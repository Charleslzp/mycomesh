import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createContext, runInContext } from 'node:vm';
import test from 'node:test';
import { secp256k1 } from '@noble/curves/secp256k1';
import { NativeConsumerState, createConsumerServer, paymentKeyAddress, walletMessageDigest } from '../src/consumer-runtime.mjs';

const zero = '0x' + '0'.repeat(40);
const ownerKey = Buffer.alloc(32, 19);
const otherKey = Buffer.alloc(32, 23);
const address = key => paymentKeyAddress(`myco_sk_${key.toString('base64url')}`);
const owner = address(ownerKey), other = address(otherKey);
const grant = (account = owner, active = true) => ({ owner: account, active, max_per_request: 100000, valid_until: 0 });
function signedLogin(state, key) {
  const wallet = address(key), challenge = state.createWalletChallenge(wallet);
  const signature = secp256k1.sign(walletMessageDigest(challenge.message), key, { lowS: true, prehash: false });
  return { wallet, signature: `0x${Buffer.concat([Buffer.from(signature.toCompactRawBytes()), Buffer.from([27 + signature.recovery])]).toString('hex')}` };
}
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'myco-wallet-ownership-'));
  const state = new NativeConsumerState({ dataDir: directory, historyDir: join(directory, 'history'), env: {} });
  state.keyGrant = async () => grant();
  state.capacityChannels = async () => [];
  const edge = createConsumerServer(state, { port: 0 });
  const { port } = await edge.listen();
  const base = `http://127.0.0.1:${port}`;
  t.after(async () => { await edge.close(); await rm(directory, { recursive: true, force: true }); });
  return { state, directory, base };
}

// Exercise the HTTP boundary as well as state: public diagnostics must never
// expose credentials, even when a valid session already exists in the process.
test('wrong-owner login returns actionable public fields without unlocking or mutating the payment key', async t => {
  const { state, directory, base } = await fixture(t);
  const before = await readFile(join(directory, 'payment-key'), 'utf8');
  const body = signedLogin(state, otherKey);
  const response = await fetch(`${base}/v1/mycomesh/local/wallet/authenticate`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  assert.equal(response.status, 401);
  const value = await response.json();
  assert.deepEqual(Object.keys(value).sort(), ['ok', 'error', 'code', 'selected_wallet', 'expected_owner', 'payment_key_address'].sort());
  assert.equal(value.code, 'payment_key_owner_mismatch');
  assert.equal(value.selected_wallet, other);
  assert.equal(value.expected_owner, owner);
  assert.equal(value.payment_key_address, state.paymentAddress);
  assert.match(value.error, /different wallet.*separate Consumer data directory/);
  assert.ok(!JSON.stringify(value).includes(state.paymentKey));
  assert.equal(state.paymentUnlocked, false);
  assert.equal(state.managementToken, null);
  assert.equal(state.unlockedWallet, null);
  assert.equal(state.authorizeBearer(`Bearer ${state.paymentKey}`), false);
  assert.equal(await readFile(join(directory, 'payment-key'), 'utf8'), before);
  assert.equal((await fetch(`${base}/credentials`)).status, 423);
});

test('failed wrong-wallet login preserves an already authenticated owner session', async t => {
  const { state } = await fixture(t);
  const loggedIn = await state.authenticateWallet(signedLogin(state, ownerKey));
  await assert.rejects(state.authenticateWallet(signedLogin(state, otherKey)), { code: 'payment_key_owner_mismatch' });
  assert.equal(state.managementToken, loggedIn.token);
  assert.equal(state.unlockedWallet, owner);
  assert.equal(state.paymentUnlocked, true);
  assert.equal(state.authorizeManagement(`Bearer ${loggedIn.token}`), true);
});

test('a chain ownership failure is fail-closed and does not leak RPC diagnostic data', async t => {
  const { state, base } = await fixture(t);
  state.keyGrant = async () => { throw new Error(`RPC url contains credential ${state.paymentKey}`); };
  const response = await fetch(`${base}/v1/mycomesh/local/wallet/authenticate`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(signedLogin(state, ownerKey)),
  });
  assert.equal(response.status, 503);
  const value = await response.json();
  assert.equal(value.code, 'wallet_verification_unavailable');
  assert.ok(!JSON.stringify(value).includes(state.paymentKey));
  assert.equal(value.expected_owner, undefined);
  assert.equal(state.managementToken, null);
  assert.equal(state.unlockedWallet, null);
  assert.equal(state.paymentUnlocked, false);
});

test('V10 channel lookup failure neither creates a partial session nor replaces a valid one', async t => {
  const { state } = await fixture(t);
  state.network.protocol_version = 10;
  state.keyGrant = async () => grant(owner, false);
  state.capacityChannels = async () => { throw new Error('RPC down'); };
  await assert.rejects(state.authenticateWallet(signedLogin(state, ownerKey)), { code: 'wallet_verification_unavailable' });
  assert.equal(state.managementToken, null);
  assert.equal(state.unlockedWallet, null);
  assert.equal(state.paymentUnlocked, false);

  state.keyGrant = async () => grant();
  const loggedIn = await state.authenticateWallet(signedLogin(state, ownerKey));
  state.keyGrant = async () => grant(owner, false);
  await assert.rejects(state.authenticateWallet(signedLogin(state, ownerKey)), { code: 'wallet_verification_unavailable' });
  assert.equal(state.managementToken, loggedIn.token);
  assert.equal(state.unlockedWallet, owner);
  assert.equal(state.paymentUnlocked, true);
});

test('an unregistered local key accepts a new wallet login without enabling inference', async t => {
  const { state } = await fixture(t);
  state.network.protocol_version = 10;
  state.keyGrant = async () => grant(zero, false);
  const result = await state.authenticateWallet(signedLogin(state, otherKey));
  assert.equal(result.auth.authenticated, true);
  assert.equal(result.auth.wallet, other);
  assert.equal(result.auth.key_ready, false);
  assert.equal(state.authorizeBearer(`Bearer ${state.paymentKey}`), false);
});

async function browserFixture(base, dashboard, selectedWallet) {
  const html = await (await fetch(`${base}/`)).text();
  const script = html.slice(html.indexOf('<script>') + 8, html.indexOf('</script>'));
  const nodes = new Map(), walletCalls = [], apiCalls = [];
  const document = {
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, { hidden: false, textContent: '', className: '' }); return nodes.get(id); },
    querySelectorAll() { return []; }, addEventListener() {},
  };
  const context = createContext({
    document, Headers, TextEncoder, clearTimeout() {}, setTimeout() {}, setInterval() {},
    window: { ethereum: { request: async value => { walletCalls.push(value.method); return [selectedWallet]; }, on() {} } },
    fetch: async path => {
      apiCalls.push(path);
      assert.equal(path, '/v1/mycomesh/local/dashboard', 'no login challenge or authenticate request before ownership matches');
      return { ok: true, json: async () => dashboard };
    },
  });
  runInContext(script, context);
  await runInContext('load()', context);
  return { context, nodes, walletCalls, apiCalls };
}

test('login page displays known ownership and blocks mismatched wallet before signing', async t => {
  const { state, base } = await fixture(t);
  const dashboard = await state.dashboardPayload(false);
  assert.equal(dashboard.key.grant.owner, owner);
  assert.equal(dashboard.credentials, null);
  const browser = await browserFixture(base, dashboard, other);
  assert.match(browser.nodes.get('loginOwnerHint').textContent, new RegExp(owner));
  await runInContext('run(login)', browser.context);
  assert.deepEqual(browser.walletCalls, ['eth_requestAccounts']);
  assert.equal(browser.nodes.get('loginError').hidden, false);
  const message = browser.nodes.get('loginError').textContent;
  for (const item of [owner, other, state.paymentAddress, '独立 Consumer 配置目录']) assert.ok(message.includes(item));
  assert.equal(runInContext('managementToken', browser.context), null);
  assert.equal(runInContext('wallet', browser.context), null);
  assert.ok(!message.includes(state.paymentKey));
});

test('login page refuses signing when ownership could not be read', async t => {
  const { state, base } = await fixture(t);
  state.keyGrant = async () => { throw new Error('offline'); };
  const browser = await browserFixture(base, await state.dashboardPayload(false), owner);
  await runInContext('run(login)', browser.context);
  assert.deepEqual(browser.walletCalls, []);
  assert.match(browser.nodes.get('loginError').textContent, /尚未请求签名/);
  assert.equal(runInContext('managementToken', browser.context), null);
});
