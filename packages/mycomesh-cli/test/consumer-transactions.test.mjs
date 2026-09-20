import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NativeConsumerState } from '../src/consumer-runtime.mjs';

const wallet = '0x' + '11'.repeat(20);
const token = '0x' + '22'.repeat(20);
const settlement = '0x' + '33'.repeat(20);
const word = (data, index) => data.slice(10 + index * 64, 10 + (index + 1) * 64);

async function fixture(t, allowance) {
  const directory = await mkdtemp(join(tmpdir(), 'myco-consumer-topup-'));
  const state = new NativeConsumerState({ dataDir: directory, historyDir: join(directory, 'history'), env: {} });
  state.network.stablecoin = token;
  state.network.settlement_contract = settlement;
  state.unlockedWallet = wallet;
  state.managementToken = 'test-local-session';
  state.rpcValue = operation => operation('mock-rpc');
  let allowanceReads = 0;
  state.contractCall = async (rpc, target, signature, args) => {
    assert.equal(rpc, 'mock-rpc');
    assert.equal(target, token);
    assert.equal(signature, 'allowance(address,address)');
    assert.deepEqual(args, [wallet, settlement]);
    allowanceReads++;
    return `0x${allowance.toString(16)}`;
  };
  t.after(async () => {
    await state.dispatcher.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { state, allowanceReads: () => allowanceReads };
}

for (const allowance of [0n, 1_000_000n]) {
  test(`top-up with ${allowance} allowance approves only the full requested amount before deposit`, async t => {
    const context = await fixture(t, allowance);
    const plan = await context.state.transactionPlan({ action: 'top_up', wallet, amount_usdc: '5.250001' });
    assert.equal(plan.amount_units, '5250001');
    assert.equal(context.allowanceReads(), 1);
    assert.equal(plan.transactions.length, 2);
    const [approval, deposit] = plan.transactions;
    assert.equal(approval.to, token);
    assert.equal(approval.data.slice(0, 10), '0x095ea7b3'); // ERC20 approve(address,uint256).
    assert.equal(approval.data.length, 138);
    assert.equal(`0x${word(approval.data, 0).slice(24)}`, settlement);
    // ERC20 approval replaces the allowance: use the amount, not its shortfall.
    assert.equal(BigInt(`0x${word(approval.data, 1)}`), 5_250_001n);
    assert.equal(deposit.to, settlement);
    assert.equal(deposit.data.slice(0, 10), '0xb6b55f25'); // deposit(uint256).
    assert.equal(deposit.data.length, 74);
    assert.equal(BigInt(`0x${word(deposit.data, 0)}`), 5_250_001n);
  });
}

for (const allowance of [5_000_000n, (1n << 256n) - 1n]) {
  test(`top-up with sufficient allowance ${allowance} needs only the deposit`, async t => {
    const context = await fixture(t, allowance);
    const plan = await context.state.transactionPlan({ action: 'top_up', wallet, amount_usdc: '5' });
    assert.equal(plan.amount_units, '5000000');
    assert.equal(context.allowanceReads(), 1);
    assert.equal(plan.transactions.length, 1);
    const [deposit] = plan.transactions;
    assert.equal(deposit.to, settlement);
    assert.equal(deposit.data.slice(0, 10), '0xb6b55f25');
    assert.equal(BigInt(`0x${word(deposit.data, 0)}`), 5_000_000n);
  });
}
