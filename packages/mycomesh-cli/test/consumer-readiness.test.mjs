import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { NativeConsumerState, createConsumerServer } from "../src/consumer-runtime.mjs";

const OWNER = `0x${"11".repeat(20)}`;
const PROVIDER = `0x${"22".repeat(20)}`;

async function fixture(t, { budget = false, wallet = true } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-consumer-readiness-"));
  const state = new NativeConsumerState({ dataDir: directory, relayUrls: "https://relay.example", env: {} });
  state.network.protocol_version = 10;
  state.network.capacity_channel_ids = [`0x${"33".repeat(32)}`];
  state.unlockedWallet = wallet ? OWNER : null;
  state.managementToken = wallet ? "fixture-management-token" : null;
  state.paymentUnlocked = wallet;
  let budgetAvailable = budget;
  const channel = {
    channel_id: state.network.capacity_channel_ids[0],
    consumer_owner: OWNER,
    consumer_key: state.paymentAddress,
    provider_signer: PROVIDER,
    credit_remaining: 1_000_000,
    admit_until: Math.floor(Date.now() / 1000) + 3600,
    claim_until: Math.floor(Date.now() / 1000) + 7200,
    closed: false,
  };
  const selected = { relayUrl: "https://relay.example", health: { v10: { model: "fixture-model" } } };
  state.settlementNetworkReady = async () => true;
  state.keyGrant = async () => ({ owner: OWNER, active: true, max_per_request: state.maxFeeUnits, valid_until: 0 });
  state.capacityChannels = async () => [channel];
  state.capacityBudget = () => ({
    ready: budgetAvailable,
    reason: budgetAvailable ? "available" : "capacity_exhausted",
    remaining_units: budgetAvailable ? "1000000" : "0",
    estimated_requests: budgetAvailable ? "10" : "0",
  });
  state.chooseRelay = async (_exclude, options = {}) => {
    if (options.checkCapacity === false || budgetAvailable) return selected;
    throw Object.assign(new Error("no active fixed budget covers this route"), { code: "budget_unavailable" });
  };
  state.accountBalance = async () => "9000000";
  state.walletSnapshot = async () => ({ address: OWNER, token_balance_units: "9000000", allowance_units: "0" });
  state.refreshReceiptStatuses = async () => {};
  const runtime = createConsumerServer(state, { port: 0 });
  const { port } = await runtime.listen();
  t.after(async () => {
    await runtime.close();
    await state.dispatcher.close();
    await rm(directory, { recursive: true, force: true });
  });
  return {
    state,
    base: `http://127.0.0.1:${port}`,
    setBudget(value) { budgetAvailable = value; },
    lockWallet() {
      state.unlockedWallet = null;
      state.managementToken = null;
      state.paymentUnlocked = false;
    },
  };
}

test("liveness stays online while V10 paid readiness reports unavailable budget", async (t) => {
  const runtime = await fixture(t, { budget: false });
  const readyResponse = await fetch(`${runtime.base}/ready`);
  const ready = await readyResponse.json();
  assert.equal(readyResponse.status, 200);
  assert.equal(ready.liveness_ready, true);
  assert.equal(ready.paid_ready, null);
  assert.equal(ready.paid_readiness_checked, false);

  const paidResponse = await fetch(`${runtime.base}/paid-ready`);
  const paid = await paidResponse.json();
  assert.equal(paidResponse.status, 402);
  assert.equal(paid.liveness_ready, true);
  assert.equal(paid.paid_readiness_checked, true);
  assert.equal(paid.paid_ready, false);
  assert.equal(paid.wallet_ready, true);
  assert.equal(paid.network_ready, true);
  assert.equal(paid.budget_ready, false);
  assert.equal(paid.models_ready, true);
  assert.equal(paid.code, "budget_unavailable");
});

test("paid readiness reports a locked wallet without exposing credentials", async (t) => {
  const runtime = await fixture(t, { budget: true });
  runtime.lockWallet();
  const response = await fetch(`${runtime.base}/paid-ready`);
  const payload = await response.json();
  assert.equal(response.status, 423);
  assert.equal(payload.paid_ready, false);
  assert.equal(payload.wallet_ready, false);
  assert.equal(payload.code, "wallet_locked");
  assert.doesNotMatch(JSON.stringify(payload), /myco_sk_/);
});

test("fully ready V10 status is shared by paid endpoint, dashboard, and first screen", async (t) => {
  const runtime = await fixture(t, { budget: true });
  const response = await fetch(`${runtime.base}/paid-ready`);
  const paid = await response.json();
  assert.equal(response.status, 200);
  assert.equal(paid.paid_ready, true);
  for (const field of ["wallet_ready", "network_ready", "budget_ready", "models_ready"]) {
    assert.equal(paid[field], true, field);
  }

  const dashboard = await runtime.state.dashboardPayload(true);
  assert.equal(dashboard.paid_readiness_checked, true);
  assert.equal(dashboard.paid_ready, true);
  for (const field of ["wallet_ready", "network_ready", "budget_ready", "models_ready"]) {
    assert.equal(dashboard[field], true, field);
  }
  assert.equal(dashboard.budget_available_units, "1000000");
  assert.equal(dashboard.account.available_balance_units, "9000000");

  const html = await (await fetch(`${runtime.base}/`)).text();
  for (const label of ["钱包与 Key", "网络与 RPC", "固定预算", "可用模型"]) assert.match(html, new RegExp(label));
  assert.match(html, /充值余额不等于可调用预算/);
});

test("dashboard does not infer network readiness from a successful key grant", async (t) => {
  const runtime = await fixture(t, { budget: true });
  runtime.state.settlementNetworkReady = async () => {
    throw Object.assign(new Error("wrong chain"), { code: "network_mismatch" });
  };
  const dashboard = await runtime.state.dashboardPayload(true);
  assert.equal(dashboard.wallet_ready, true);
  assert.equal(dashboard.network_ready, false);
  assert.equal(dashboard.paid_ready, false);
  assert.equal(dashboard.inference_code, "network_unavailable");
  assert.match(dashboard.chain_error, /wrong chain/);
});

test("dashboard treats an unreadable V10 channel as network state, not empty budget", async (t) => {
  const runtime = await fixture(t, { budget: true });
  runtime.state.capacityChannels = async () => {
    throw Object.assign(new Error("capacity RPC failed"), { code: "rpc_unavailable" });
  };
  const dashboard = await runtime.state.dashboardPayload(true);
  assert.equal(dashboard.wallet_ready, true);
  assert.equal(dashboard.network_ready, false);
  assert.equal(dashboard.budget_ready, false);
  assert.equal(dashboard.paid_ready, false);
  assert.equal(dashboard.inference_code, "network_unavailable");
  assert.match(dashboard.chain_error, /capacity RPC failed/);
});

test("paid readiness keeps a verified network distinct from a failed key-grant read", async (t) => {
  const runtime = await fixture(t, { budget: true });
  runtime.state.keyGrant = async () => { throw new Error("invalid key grant response"); };
  runtime.state.capacityChannels = async () => [];
  const response = await fetch(`${runtime.base}/paid-ready`);
  const payload = await response.json();
  assert.equal(response.status, 423);
  assert.equal(payload.network_ready, true);
  assert.equal(payload.wallet_ready, false);
  assert.equal(payload.paid_ready, false);
  assert.equal(payload.code, "payment_key_not_ready");
});

test("Relay deployment identity is mandatory even without an address pin", async (t) => {
  const runtime = await fixture(t, { budget: true });
  runtime.state.network.relay_pins = {};
  assert.throws(() => runtime.state.verifyRelayIdentity("https://custom-relay.example", {
    v10: {
      chain_id: runtime.state.network.chain_id + 1,
      settlement_contract: runtime.state.network.settlement_contract,
    },
  }), /deployment does not match/);
  assert.throws(() => runtime.state.verifyRelayIdentity("https://custom-relay.example", {
    v10: {
      chain_id: runtime.state.network.chain_id,
      settlement_contract: `0x${"99".repeat(20)}`,
    },
  }), /deployment does not match/);
});
