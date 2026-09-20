import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createContext, runInContext } from 'node:vm';
import test from 'node:test';
import { NativeConsumerState, createConsumerServer } from '../src/consumer-runtime.mjs';

const owner = '0x' + '11'.repeat(20), other = '0x' + '22'.repeat(20), zero = '0x' + '00'.repeat(20);
const exactGrant = { owner, active: true, max_per_request: 100000, valid_until: 0 };
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'myco-onboarding-state-'));
  const state = new NativeConsumerState({ dataDir: directory, historyDir: join(directory, 'history'), env: {} });
  state.network.protocol_version = 10;
  state.network.capacity_channel_ids = [];
  state.unlockedWallet = owner;
  state.managementToken = 'test-local-session';
  state.keyGrant = async () => ({ ...exactGrant });
  state.capacityChannels = async () => [];
  state.accountBalance = async address => { assert.equal(address, owner); return '5250001'; };
  state.rpcValue = async () => '0x0';
  state.refreshReceiptStatuses = async () => {};
  state.chooseRelay = async () => { throw Object.assign(new Error('no test budget'), { code: 'budget_unavailable' }); };
  t.after(async () => { await state.dispatcher.close(); await rm(directory, { recursive: true, force: true }); });
  return { state, directory };
}

test('already matching on-chain registration produces no transaction and still needs local activation', async t => {
  const { state } = await fixture(t);
  let queried;
  state.keyGrant = async address => { queried = address; return { ...exactGrant }; };
  const plan = await state.transactionPlan({ action: 'register_key', wallet: owner });
  assert.equal(queried, state.paymentAddress);
  assert.deepEqual(plan, { action: 'register_key', key_address: state.paymentAddress, transactions: [] });
  assert.equal(state.paymentUnlocked, false);
  await state.activateCurrentPaymentKey();
  assert.equal(state.paymentUnlocked, true);
});

for (const [name, change] of [
  ['different owner', { owner: other }], ['unregistered key', { owner: zero, active: false }],
  ['revoked key', { active: false }], ['different maximum', { max_per_request: 100001 }],
  ['finite expiry', { valid_until: 2000000000 }],
]) {
  test(`${name} does not skip the existing registration path`, async t => {
    const { state } = await fixture(t);
    state.keyGrant = async () => ({ ...exactGrant, ...change });
    const plan = await state.transactionPlan({ action: 'register_key', wallet: owner });
    assert.equal(plan.transactions.length, 1);
    const transaction = plan.transactions[0];
    assert.equal(transaction.to, state.network.settlement_contract);
    assert.equal(transaction.data.slice(0, 10), '0x1d28910e');
    assert.equal(`0x${transaction.data.slice(34, 74)}`, state.paymentAddress);
    assert.equal(BigInt(`0x${transaction.data.slice(74, 138)}`), 100000n);
    assert.equal(BigInt(`0x${transaction.data.slice(138, 202)}`), 0n);
    assert.equal(state.paymentUnlocked, false);
    if (change.owner === other) await assert.rejects(state.activateCurrentPaymentKey(), /not active for this wallet/);
  });
}

test('rotation checks the pending Key grant and preserves the current credential', async t => {
  const { state, directory } = await fixture(t);
  const previous = await readFile(join(directory, 'payment-key'), 'utf8');
  const pending = state.preparePaymentKey();
  const queried = [];
  let pendingActive = false;
  state.keyGrant = async address => {
    queried.push(address);
    return address === pending.payment_key_address && !pendingActive
      ? { ...exactGrant, owner: zero, active: false } : { ...exactGrant };
  };
  assert.equal((await state.transactionPlan({ action: 'register_key', wallet: owner })).transactions.length, 1);
  pendingActive = true;
  assert.deepEqual((await state.transactionPlan({ action: 'register_key', wallet: owner })).transactions, []);
  assert.deepEqual(queried, [pending.payment_key_address, pending.payment_key_address]);
  assert.equal(await readFile(join(directory, 'payment-key'), 'utf8'), previous);
  assert.equal(state.paymentUnlocked, false);
});

test('registration optimization does not bypass the authenticated wallet or failed chain read', async t => {
  const { state } = await fixture(t);
  await assert.rejects(state.transactionPlan({ action: 'register_key', wallet: other }), /sign in/);
  state.keyGrant = async () => { throw new Error('chain unavailable'); };
  await assert.rejects(state.transactionPlan({ action: 'register_key', wallet: owner }), /chain unavailable/);
  assert.equal(state.paymentUnlocked, false);
});

test('V10 unallocated deposits belong only to the authenticated wallet, including before Key registration', async t => {
  const { state } = await fixture(t);
  for (const grantOwner of [owner, zero]) {
    state.keyGrant = async () => ({ ...exactGrant, owner: grantOwner, active: grantOwner !== zero });
    const dashboard = await state.dashboardPayload(true);
    assert.deepEqual(dashboard.account, { owner, available_balance_units: '5250001' });
    assert.equal(dashboard.budget_available_units, '0');
    assert.equal((await state.dashboardPayload(false)).account, undefined);
  }
  state.keyGrant = async () => ({ ...exactGrant, owner: other });
  state.accountBalance = async () => { throw new Error('must not read another owner account'); };
  assert.equal((await state.dashboardPayload(true)).account, undefined);
});

async function browserFixture(t, state) {
  const server = createConsumerServer(state, { port: 0 });
  const { port } = await server.listen();
  t.after(() => server.close());
  const html = await (await fetch(`http://127.0.0.1:${port}/`)).text();
  const script = html.slice(html.indexOf('<script>') + 8, html.indexOf('</script>')).split("document.querySelectorAll('.tab')")[0];
  const nodes = new Map(), walletCalls = [], requests = [];
  const document = {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, { hidden: false, textContent: '', className: '', replaceChildren() {} });
      return nodes.get(id);
    },
  };
  const dashboard = { protocol_version: 10, auth: { authenticated: true, wallet: owner, key_ready: false },
    key: { address: state.paymentAddress, max_fee_units: 100000, grant: { ...exactGrant } },
    settlement: { chain_id: 11155111, stablecoin_decimals: 6, stablecoin_symbol: 'tUSDC' },
    account: { owner, available_balance_units: '5250001' }, capacity_channels: [], budget_available_units: '0' };
  const context = createContext({ document, Headers, TextEncoder, setTimeout() {}, clearTimeout() {},
    __dashboard: dashboard,
    window: { ethereum: { request: async value => {
      walletCalls.push(value.method);
      throw new Error('matching grant must not query, switch, or send through the wallet');
    } } },
    fetch: async (path, options) => {
      requests.push(path);
      if (path.endsWith('/transactions')) return { ok: true, json: () => state.transactionPlan(JSON.parse(options.body)) };
      assert.equal(path, '/v1/mycomesh/local/wallet/activate');
      return { ok: true, json: () => state.activateCurrentPaymentKey() };
    },
  });
  runInContext(script, context);
  runInContext("state=__dashboard; wallet=state.auth.wallet; managementToken='test'; load=async()=>{};", context);
  return { context, nodes, dashboard, requests, walletCalls, html };
}

test('already registered Key shows local activation and performs no wallet transaction', async t => {
  const { state } = await fixture(t);
  const browser = await browserFixture(t, state);
  runInContext('renderActivation()', browser.context);
  assert.equal(browser.nodes.get('activate').textContent, '启用本地访问');
  assert.equal(browser.nodes.get('setupAccess').textContent, '启用本地访问');
  assert.match(browser.nodes.get('activationNotice').textContent, /链上授权已生效/);
  await runInContext('activateCurrent()', browser.context);
  assert.deepEqual(browser.requests, ['/v1/mycomesh/local/transactions', '/v1/mycomesh/local/wallet/activate']);
  assert.deepEqual(browser.walletCalls, []);
  assert.equal(state.paymentUnlocked, true);
  browser.context.window.ethereum = undefined;
  state.paymentUnlocked = false;
  await runInContext('activateCurrent()', browser.context);
  assert.equal(state.paymentUnlocked, true);
  for (const change of [{ owner: other }, { active: false }]) {
    browser.dashboard.key.grant = { ...exactGrant, ...change };
    runInContext('renderActivation()', browser.context);
    assert.equal(browser.nodes.get('activate').textContent, '激活 Key');
  }
  browser.dashboard.key.grant = { ...exactGrant };
  browser.dashboard.key.pending = { payment_key_address: other };
  runInContext('renderActivation()', browser.context);
  assert.equal(browser.nodes.get('activate').textContent, '激活 Key');
});

test('budget panel distinguishes unallocated deposits from usable budget and hides another owner balance', async t => {
  const { state } = await fixture(t);
  const browser = await browserFixture(t, state);
  runInContext('renderBudget()', browser.context);
  assert.equal(browser.nodes.get('budgetUnallocated').textContent, '已充值、尚未分配预算：5.250001 tUSDC');
  assert.match(browser.html, /充值余额需开通固定预算后才能调用；充值不等于已有可调用预算/);
  assert.equal(browser.dashboard.budget_available_units, '0');
  browser.dashboard.account.owner = other;
  runInContext('renderBudget()', browser.context);
  assert.equal(browser.nodes.get('budgetUnallocated').textContent, '已充值、尚未分配预算：--');
});
