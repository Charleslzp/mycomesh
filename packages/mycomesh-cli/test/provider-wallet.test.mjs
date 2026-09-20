import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const script = readFileSync(new URL('../../../gateway/provider_onboarding_wallet.js', import.meta.url), 'utf8');
const account = `0x${'11'.repeat(20)}`;
const other = `0x${'22'.repeat(20)}`;
const contract = `0x${'33'.repeat(20)}`;
const calldata = `0x12345678${'0'.repeat(24)}${'44'.repeat(20)}`;

function fixture(options = {}) {
  const handlers = {};
  const calls = [];
  const storage = options.storage ?? new Map();
  let submitted = false;
  let saved = 0;
  let chain = options.chain ?? '0xaa36a7';
  const pin = { chainId: '0xaa36a7', contract, data: calldata, persistent: options.persistent !== false };
  const elements = {
    '#authorize-wallet': { disabled: false, addEventListener(name, handler) { handlers[name] = handler; } },
    '#setup': { requestSubmit() { saved += 1; } },
    '#authorization-message': { textContent: '' },
    '#payout_address': { value: options.address ?? '' },
    '#authorization-pin': { textContent: JSON.stringify(pin) },
  };
  const wallet = { async request(request) {
    calls.push(request);
    switch (request.method) {
      case 'eth_requestAccounts': return [account];
      case 'eth_accounts': return [options.changedAccount ? other : account];
      case 'eth_chainId': return chain;
      case 'wallet_switchEthereumChain': if (!options.stuckChain) chain = pin.chainId; return null;
      case 'eth_sendTransaction':
        if (options.sendError) throw options.sendError;
        submitted = true;
        return options.badHash ? 'invalid' : `0x${'ab'.repeat(32)}`;
      default: throw new Error('unexpected wallet method');
    }
  } };
  const context = {
    document: { querySelector(selector) { return elements[selector]; } },
    window: {
      ...(options.noWallet ? {} : options.okx ? { okxwallet: wallet, ethereum: { request() { throw new Error('wrong wallet'); } } } : { ethereum: wallet }),
      localStorage: {
        getItem(key) { return storage.get(key); },
        setItem(key, value) { storage.set(key, value); },
        removeItem(key) { storage.delete(key); },
      },
    },
    FormData: class { entries() { return [['token', 'fixture-token'], ['payout_address', elements['#payout_address'].value]]; } },
    async fetch(url, request) {
      assert.ok(['/api/provider-authorization', '/api/provider-authorization-intent'].includes(url));
      const body = JSON.parse(request.body);
      assert.equal(body.token, 'fixture-token');
      return { async json() {
        const authorized = !!options.alreadyAuthorized || (submitted && !options.pending);
        const intent = 'ab'.repeat(24);
        if (authorized) storage.clear();
        if (body.action === 'reserve' && !authorized) {
          if (storage.size) return { ok: false, error: 'Authorization pending; no duplicate send allowed' };
          storage.set(intent, 'reserved');
        }
        if (body.action === 'rejected') storage.delete(body.intent_id);
        if (body.action === 'submitted' && !authorized) storage.set(intent, body.tx_hash);
        return { ok: true, authorized, pending: storage.size > 0, intent_id: body.action === 'reserve' ? intent : null,
          plan: { transaction: { chainId: pin.chainId, from: account, to: contract, data: calldata, value: '0x0', ...options.plan } } };
      } };
    },
    setTimeout(callback) { queueMicrotask(callback); },
  };
  vm.runInNewContext(script, context);
  return {
    click: () => handlers.click(), calls, storage,
    sent: () => calls.filter((request) => request.method === 'eth_sendTransaction'),
    message: () => elements['#authorization-message'].textContent,
    saved: () => saved,
  };
}

test('first setup persists the identity before any authorization transaction', async () => {
  const ui = fixture({ persistent: false });
  await ui.click();
  assert.equal(ui.sent().length, 0);
  assert.equal(ui.saved(), 1);
});

test('OKX sends only the exact pinned transaction after account and chain checks', async () => {
  const ui = fixture({ okx: true, chain: '0x1' });
  await ui.click();
  assert.equal(ui.sent().length, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(ui.sent()[0].params[0])), {
    chainId: '0xaa36a7', from: account, to: contract, data: calldata, value: '0x0',
  });
  assert.equal(ui.saved(), 1);
  assert.match(ui.message(), /authorization verified/);
  assert.equal(ui.storage.size, 0);
});

test('already-authorized wallet does not pay another authorization gas fee', async () => {
  const ui = fixture({ alreadyAuthorized: true });
  await ui.click();
  assert.equal(ui.sent().length, 0);
  assert.equal(ui.saved(), 1);
});

for (const [name, options] of [
  ['missing extension', { noWallet: true }],
  ['wrong payout wallet', { address: other }],
  ['wallet changed account', { changedAccount: true }],
  ['wallet refused network change', { chain: '0x1', stuckChain: true }],
  ['swapped contract', { plan: { to: other } }],
  ['swapped calldata', { plan: { data: '0x1234' } }],
  ['unexpected transfer value', { plan: { value: '0x1' } }],
  ['swapped chain', { plan: { chainId: '0x1' } }],
]) {
  test(`${name} cannot send or claim setup completed`, async () => {
    const ui = fixture(options);
    await ui.click();
    assert.equal(ui.sent().length, 0);
    assert.equal(ui.saved(), 0);
  });
}

test('wallet rejection is retryable without falsely reporting authorization', async () => {
  const ui = fixture({ sendError: Object.assign(new Error('User rejected'), { code: 4001 }) });
  await ui.click();
  assert.equal(ui.storage.size, 0);
  assert.equal(ui.saved(), 0);
  assert.match(ui.message(), /User rejected/);
});

for (const [name, options] of [
  ['unknown wallet failure', { sendError: new Error('wallet connection lost') }],
  ['malformed wallet result', { badHash: true, pending: true }],
  ['authorization remains pending', { pending: true }],
]) {
  test(`${name} prevents duplicate automatic sends`, async () => {
    const ui = fixture(options);
    await ui.click();
    await ui.click();
    assert.equal(ui.sent().length, 1);
    assert.equal(ui.saved(), 0);
    assert.equal(ui.storage.size, 1);
    assert.match(ui.message(), /pending|duplicate/);
  });
}

test('a later verified authorization clears uncertainty without resending', async () => {
  const ui = fixture({ badHash: true });
  await ui.click();
  assert.equal(ui.saved(), 0);
  await ui.click();
  assert.equal(ui.sent().length, 1);
  assert.equal(ui.saved(), 1);
  assert.equal(ui.storage.size, 0);
});

test('a fresh browser origin still sees the server-side pending send fence', async () => {
  const storage = new Map();
  const first = fixture({ storage, pending: true });
  await first.click();
  const reopened = fixture({ storage, pending: true });
  await reopened.click();
  assert.equal(first.sent().length, 1);
  assert.equal(reopened.sent().length, 0);
  assert.match(reopened.message(), /pending/);
});

test('parallel tabs cannot both reserve a wallet transaction', async () => {
  const storage = new Map();
  const first = fixture({ storage, pending: true });
  const second = fixture({ storage, pending: true });
  await Promise.all([first.click(), second.click()]);
  assert.equal(first.sent().length + second.sent().length, 1);
});
