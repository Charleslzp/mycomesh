// Opt-in real browser / local HTTP journey. Wallet and chain are test doubles;
// this never loads a real wallet extension, profile, key or public RPC.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { secp256k1 } from '@noble/curves/secp256k1';
import { NativeConsumerState, createConsumerServer, paymentKeyAddress, walletMessageDigest } from '../../src/consumer-runtime.mjs';

test('real browser: connect OKX-shaped wallet → one access authorization → usable API credentials → logout', {
  skip: !process.env.MYCOMESH_TEST_BROWSER_BIN, timeout: 45000,
}, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'myco-browser-journey-'));
  const state = new NativeConsumerState({ env: {}, dataDir: join(directory, 'data'), historyDir: join(directory, 'history') });
  const privateKey = Buffer.alloc(32, 19);
  const wallet = paymentKeyAddress(`myco_sk_${privateKey.toString('base64url')}`);
  let grant = { owner: `0x${'0'.repeat(40)}`, max_per_request: 100000, valid_until: 0, active: false };
  state.keyGrant = async () => grant;
  state.accountBalance = async () => '10000000';
  state.rpcValue = async () => '0x0';
  const edge = createConsumerServer(state, { port: 0 });
  const address = await edge.listen();
  state.baseUrl = `http://127.0.0.1:${address.port}/v1`;
  let chrome, socket;
  t.after(async () => {
    socket?.close();
    if (chrome && chrome.exitCode === null && chrome.signalCode === null) {
      await new Promise((resolve) => { chrome.once('exit', resolve); chrome.kill('SIGTERM'); });
    }
    await edge.close();
    await rm(directory, { recursive: true, force: true });
  });
  chrome = spawn(process.env.MYCOMESH_TEST_BROWSER_BIN, [
    '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${join(directory, 'browser')}`,
    '--no-first-run', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('isolated browser did not start')), 10000);
    chrome.stderr.on('data', (chunk) => {
      output += chunk;
      const match = output.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
    chrome.once('error', (error) => { clearTimeout(timer); reject(error); });
    chrome.once('exit', () => { clearTimeout(timer); reject(new Error('isolated browser exited before CDP')); });
  });
  socket = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  let sequence = 0, sessionId;
  const pending = new Map(), requests = [], errors = [];
  const cdp = (method, params = {}, session = sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timed out: ${method}`)); }, 8000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, ...(session ? { sessionId: session } : {}) }));
  });
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const item = pending.get(message.id); if (!item) return;
      pending.delete(message.id); clearTimeout(item.timer);
      if (message.error) item.reject(new Error(message.error.message)); else item.resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
    if (message.method === 'Runtime.bindingCalled') {
      void (async () => {
        const { id, request } = JSON.parse(message.params.payload);
        requests.push(request.method);
        let result;
        if (request.method === 'eth_requestAccounts') result = [wallet];
        else if (request.method === 'eth_chainId') result = `0x${state.network.chain_id.toString(16)}`;
        else if (request.method === 'personal_sign') {
          assert.equal(request.params[1], wallet);
          const text = Buffer.from(request.params[0].slice(2), 'hex').toString('utf8');
          const signature = secp256k1.sign(walletMessageDigest(text), privateKey, { lowS: true, prehash: false });
          result = `0x${Buffer.concat([Buffer.from(signature.toCompactRawBytes()), Buffer.from([27 + signature.recovery])]).toString('hex')}`;
        } else if (request.method === 'eth_sendTransaction') {
          const plan = await state.transactionPlan({ action: 'register_key', wallet });
          assert.deepEqual(request.params[0], { from: wallet, to: plan.transactions[0].to, data: plan.transactions[0].data });
          grant = { ...grant, owner: wallet, active: true };
          result = `0x${'ab'.repeat(32)}`;
        } else if (request.method === 'eth_getTransactionReceipt') result = { status: '0x1' };
        else throw new Error(`unexpected fixture wallet method ${request.method}`);
        await cdp('Runtime.evaluate', { expression: `window.__walletReplies.get(${id})(${JSON.stringify(result)});window.__walletReplies.delete(${id});` });
      })().catch((error) => errors.push(error.message));
    }
  });
  const target = await cdp('Target.createTarget', { url: 'about:blank' }, null);
  const attached = await cdp('Target.attachToTarget', { targetId: target.targetId, flatten: true }, null);
  sessionId = attached.sessionId;
  await cdp('Runtime.enable');
  await cdp('Page.enable');
  await cdp('Runtime.addBinding', { name: '__fixtureWalletRequest' });
  await cdp('Page.addScriptToEvaluateOnNewDocument', { source: `
    window.__walletReplies=new Map();let seq=0;
    window.ethereum={request(){throw new Error('wrong wallet chosen')}};
    window.okxwallet={request(request){return new Promise(resolve=>{const id=++seq;window.__walletReplies.set(id,resolve);window.__fixtureWalletRequest(JSON.stringify({id,request}))})},on(){}};
  ` });
  await cdp('Page.navigate', { url: `http://127.0.0.1:${address.port}/` });
  const evaluate = async (expression) => (await cdp('Runtime.evaluate', { expression, returnByValue: true })).result.value;
  const until = async (expression) => {
    for (let n = 0; n < 100; n++) {
      assert.deepEqual(errors, []);
      if (await evaluate(expression)) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`browser condition not met: ${expression}`);
  };
  await until("document.getElementById('login') && document.getElementById('lockedKey').textContent !== '读取中...'");
  assert.equal((await fetch(`${state.baseUrl.replace('/v1', '')}/credentials`)).status, 423);
  await evaluate("document.getElementById('login').click()");
  await until("!document.getElementById('app').hidden && !document.getElementById('setupAccess').disabled");
  assert.equal(await evaluate("document.getElementById('credentials').hidden"), true);
  await evaluate("document.getElementById('setupAccess').click()");
  await until("!document.getElementById('credentials').hidden && !document.getElementById('walletButton').disabled");
  assert.equal(await evaluate("document.getElementById('url').textContent"), state.baseUrl);
  assert.equal(await evaluate("document.getElementById('key').textContent"), state.paymentKey);
  assert.equal(requests.filter((method) => method === 'eth_sendTransaction').length, 1);
  assert.equal(state.authorizeBearer(`Bearer ${state.paymentKey}`), true);
  // Rerendering/refresh must not resubmit the one-time authorization.
  await evaluate("document.getElementById('refresh').click()");
  await until("!document.getElementById('walletButton').disabled");
  assert.equal(requests.filter((method) => method === 'eth_sendTransaction').length, 1);
  await evaluate("document.getElementById('walletButton').click()");
  await until("!document.getElementById('locked').hidden");
  assert.equal(state.authorizeBearer(`Bearer ${state.paymentKey}`), false);
  assert.deepEqual(errors, []);
});
