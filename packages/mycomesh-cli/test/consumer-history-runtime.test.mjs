import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { keccak_256 } from "@noble/hashes/sha3";
import { NativeConsumerState, createConsumerServer } from "../src/consumer-runtime.mjs";

const OWNER = `0x${"ab".repeat(20)}`;
const PROVIDER = `0x${"cd".repeat(20)}`;
const REQUEST = `0x${"12".repeat(32)}`;
const OTHER_REQUEST = `0x${"34".repeat(32)}`;
const fakeKey = (byte) => `myco_sk_${Buffer.alloc(32, byte).toString("base64url")}`;
const word = (value) => Buffer.from(value.slice(2).padStart(64, "0"), "hex");
const hash = (value) => `0x${Buffer.from(keccak_256(value)).toString("hex")}`;

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-history-runtime-"));
  const runtimes = [];
  t.after(async () => {
    await Promise.all(runtimes.map((runtime) => runtime.close()));
    await rm(directory, { recursive: true, force: true });
  });
  function state(name, key = fakeKey(1)) {
    const result = new NativeConsumerState({
      dataDir: join(directory, name), historyDir: join(directory, "shared"),
      env: key === null ? {} : { MYCOMESH_V8_PAYMENT_KEY: key },
    });
    result.keyGrant = async () => ({ owner: OWNER, active: true, max_per_request: 100000, valid_until: 0 });
    result.accountBalance = async () => "1000000";
    result.rpcValue = async (callback) => callback("http://rpc.invalid");
    result.contractCall = async () => "0x0";
    return result;
  }
  return { state, runtimes };
}

function record(state, requestId = REQUEST, status = "pending", accepted = true) {
  state.recordReceipt("https://relay.example", "/v1/responses", "test-model", {
    accepted, status, settlement_key: `v8:${state.paymentAddress}:${requestId}`,
    signed_receipt: {
      authorization: { authorization: { request_id: requestId } },
      receipt: { provider: OWNER, provider_signer: PROVIDER, input_tokens: 12, output_tokens: 7, actual_fee: 2000 },
    },
  }, "test-route-model", "test-session");
}

// These fixtures are isolated in temporary directories: no live wallet or
// credentials are read, no real RPC calls or inference requests are made.
function authenticatedFixture(state) {
  state.unlockedWallet = OWNER;
  state.managementToken = "test-management-token";
  state.paymentUnlocked = true;
}

test("runtime instances share same-key history across data directories and deduplicate", async (t) => {
  const { state } = await fixture(t);
  const first = state("first"), second = state("second");
  record(first);
  assert.equal(second.history(0).length, 1);
  record(second, REQUEST, "confirmed");
  assert.equal(second.history(0)[0].status, "pending", "an unsigned Relay label is not chain confirmation");
  second.historyLedger.append({ ...second.history(0)[0], status: "confirmed", source: "chain-settled" });
  record(first, REQUEST, "pending");
  for (const consumer of [first, second]) {
    const history = consumer.history(0);
    assert.equal(history.length, 1);
    assert.equal(history[0].status, "confirmed");
    assert.equal(history[0].actual_fee_units, 2000);
    assert.equal(history[0].provider_signer, PROVIDER);
    assert.equal(history[0].session_id, "test-session");
    assert.equal(history[0].key_address, first.paymentAddress);
  }
});

test("runtime does not show another key's local or shared history", async (t) => {
  const { state } = await fixture(t);
  record(state("first"));
  assert.deepEqual(state("second", fakeKey(2)).history(0), []);
  assert.deepEqual(state("first", fakeKey(2)).history(0), []);
});

test("dashboard route hides history and usage without management authorization", async (t) => {
  const { state, runtimes } = await fixture(t);
  const consumer = state("dashboard");
  authenticatedFixture(consumer);
  record(consumer);
  const runtime = createConsumerServer(consumer, { port: 0 });
  runtimes.push(runtime);
  const { port } = await runtime.listen();
  const url = `http://127.0.0.1:${port}/v1/mycomesh/local/dashboard`;
  for (const headers of [{}, { authorization: "Bearer wrong-token" }]) {
    const response = await fetch(url, { headers });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.deepEqual(payload.history, []);
    assert.equal(payload.usage.request_count, 0);
    assert.equal(payload.usage.total_spent_units, 0);
    assert.equal(payload.credentials, null);
    assert.equal(payload.auth.authenticated, false);
    assert.equal(payload.history_sync, null);
  }
  assert.equal(consumer.historySyncAt, 0, "unauthorized dashboard must not initiate chain synchronization");
  const response = await fetch(url, { headers: { authorization: `Bearer ${consumer.managementToken}` } });
  const payload = await response.json();
  assert.equal(payload.history.length, 1);
  assert.equal(payload.usage.request_count, 1);
  assert.equal(payload.usage.total_spent_units, 2000);
  if (consumer.historySync) await consumer.historySync;
});

test("wallet snapshot reads balance and allowance concurrently", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("wallet-snapshot");
  let active = 0;
  let peak = 0;
  consumer.rpcValue = async (callback) => {
    active += 1;
    peak = Math.max(peak, active);
    try {
      await new Promise((resolve) => setTimeout(resolve, 15));
      return await callback("http://rpc.invalid");
    } finally {
      active -= 1;
    }
  };
  consumer.contractCall = async (_rpc, _contract, signature) => signature.startsWith("balanceOf") ? "0x64" : "0x32";
  assert.deepEqual(await consumer.walletSnapshot(OWNER), {
    address: OWNER,
    token_balance_units: "100",
    allowance_units: "50",
  });
  assert.equal(peak, 2, "balance and allowance should overlap");
});

test("manual history synchronization is wallet-gated and bypasses the polling throttle", async (t) => {
  const { state, runtimes } = await fixture(t);
  const consumer = state("manual-sync");
  authenticatedFixture(consumer);
  const calls = [];
  consumer.refreshReceiptStatuses = async (force) => { calls.push(force); };
  const runtime = createConsumerServer(consumer, { port: 0 });
  runtimes.push(runtime);
  const { port } = await runtime.listen();
  const url = `http://127.0.0.1:${port}/v1/mycomesh/local/history/sync`;
  assert.equal((await fetch(url, { method: "POST" })).status, 401);
  const response = await fetch(url, { method: "POST", headers: { authorization: `Bearer ${consumer.managementToken}` } });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true, history_sync: { running: false, last_checked_at: 0, error: null } });
  assert.deepEqual(calls, [true]);
});

test("dashboard asynchronously confirms history with correct settled(bytes32) ABI", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("sync");
  authenticatedFixture(consumer);
  record(consumer);
  let settle;
  const pending = new Promise((resolve) => { settle = resolve; });
  const calls = [];
  const selector = hash(Buffer.from("settled(bytes32)")).slice(2, 10);
  const settlementKey = hash(Buffer.concat([word(OWNER), word(consumer.paymentAddress), word(REQUEST)]));
  consumer.contractCall = NativeConsumerState.prototype.contractCall;
  consumer.callRpc = async (rpc, method, parameters) => {
    if (parameters[0]?.data?.startsWith(`0x${selector}`)) {
      calls.push({ rpc, method, parameters });
      return pending;
    }
    return "0x0";
  };
  const payload = await consumer.dashboardPayload(true);
  assert.equal(payload.history[0].status, "pending");
  assert.equal(payload.history_sync.running, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "eth_call");
  assert.deepEqual(calls[0].parameters, [{
    to: consumer.network.settlement_contract,
    data: `0x${selector}${settlementKey.slice(2)}`,
  }, "latest"]);
  const running = consumer.historySync;
  settle("0x1");
  await running;
  await consumer.refreshReceiptStatuses();
  const history = consumer.history(0);
  assert.equal(history.length, 1);
  assert.equal(history[0].status, "confirmed");
  assert.equal(history[0].owner, OWNER);
  assert.ok(history[0].confirmed_at > 0);
  assert.equal(history[0].input_tokens, 12);
  assert.equal(history[0].output_tokens, 7);
  assert.equal(calls.length, 1, "refresh is throttled and confirmed entries are not rechecked");
});

test("chain synchronization preserves auth gate and only checks accepted pending entries", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("gates");
  record(consumer);
  let count = 0;
  consumer.contractCall = async () => { count += 1; return "0x0"; };
  await consumer.refreshReceiptStatuses();
  assert.equal(count, 0);
  consumer.unlockedWallet = OWNER;
  await consumer.refreshReceiptStatuses();
  assert.equal(count, 0);
  authenticatedFixture(consumer);
  record(consumer, OTHER_REQUEST, "rejected", false);
  await consumer.refreshReceiptStatuses();
  assert.equal(count, 1);
  assert.equal(consumer.history(0).find((item) => item.request_id === REQUEST).status, "pending");
});

test("RPC failure leaves accepted receipt visible without claiming confirmation", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("failure");
  authenticatedFixture(consumer);
  record(consumer);
  consumer.contractCall = async () => { throw new Error("offline"); };
  await consumer.refreshReceiptStatuses();
  assert.equal(consumer.history(0)[0].status, "pending");
  assert.ok(consumer.historySyncError);
  assert.equal(consumer.historySync, null);
});

test("activating a new payment key isolates old history without erasing it", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("rotation", null);
  const oldPeer = state("old-peer", consumer.paymentKey);
  authenticatedFixture(consumer);
  record(consumer);
  const before = consumer.paymentAddress;
  const pending = consumer.preparePaymentKey();
  const rotated = await consumer.activatePendingPaymentKey(OWNER);
  assert.equal(rotated.previous_key_address, before);
  assert.equal(rotated.payment_key_address, pending.payment_key_address);
  assert.notEqual(consumer.paymentAddress, before);
  assert.deepEqual(consumer.history(0), []);
  assert.equal(oldPeer.history(0).length, 1);
  record(consumer, OTHER_REQUEST);
  assert.deepEqual(consumer.history(0).map((entry) => entry.request_id), [OTHER_REQUEST]);
  assert.deepEqual(oldPeer.history(0).map((entry) => entry.request_id), [REQUEST]);
});

for (const remoteStatus of ["failed", "confirmed", "broadcast_unknown"]) {
  test(`Relay status ${remoteStatus} cannot fabricate independent chain confirmation`, async (t) => {
    const { state } = await fixture(t);
    const consumer = state("remote-" + remoteStatus);
    authenticatedFixture(consumer);
    record(consumer);
    consumer.queryReceiptStatus = async () => ({ status: remoteStatus, error_code: remoteStatus === "failed" ? "authorization_expired" : "broadcast_unknown", authorization_deadline: 123 });
    await consumer.refreshReceiptStatuses();
    const entry = consumer.history(0)[0];
    assert.equal(entry.status, remoteStatus === "confirmed" ? "pending" : remoteStatus);
    const dashboard = await consumer.dashboardPayload(true);
    assert.equal(dashboard.usage.settled_units, 0);
    assert.equal(dashboard.usage.failed_units, remoteStatus === "failed" ? 2000 : 0);
    assert.equal(dashboard.usage.pending_units, remoteStatus === "failed" ? 0 : 2000);
    if (remoteStatus === "failed") {
      assert.equal(entry.error_code, "authorization_expired");
      assert.equal(entry.authorization_deadline, 123);
    }
  });
}

test("more than twenty newer failed receipts cannot starve an older pending settlement", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("failed-do-not-starve");
  authenticatedFixture(consumer);
  consumer.historyLedger.append({ request_id: REQUEST, timestamp: 1, accepted: true,
    status: "pending", actual_fee_units: 2000 });
  for (let index = 0; index < 26; index += 1) {
    consumer.historyLedger.append({ request_id: `0x${(100 + index).toString(16).padStart(64, "0")}`,
      timestamp: 100 + index, accepted: true, status: "failed", error_code: "authorization_expired" });
  }
  const target = hash(Buffer.concat([word(OWNER), word(consumer.paymentAddress), word(REQUEST)]));
  const checked = [];
  consumer.contractCall = async (_rpc, _contract, method, parameters) => {
    assert.equal(method, "settled(bytes32)");
    checked.push(parameters[0]);
    return parameters[0] === target ? "0x1" : "0x0";
  };
  consumer.queryReceiptStatus = async (entry) => ({ status: entry.status, error_code: entry.error_code });
  await consumer.refreshReceiptStatuses();
  assert.ok(checked.includes(target), "the older pending entry gets a chain check in the first bounded batch");
  assert.ok(checked.length <= 20);
  assert.equal(consumer.history(0).find((entry) => entry.request_id === REQUEST).status, "confirmed");
});

test("status synchronization rotates across more than twenty live receipts", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("live-status-rotation");
  authenticatedFixture(consumer);
  const requests = Array.from({ length: 47 }, (_, index) => `0x${(200 + index).toString(16).padStart(64, "0")}`);
  for (const [index, requestId] of requests.entries()) {
    consumer.historyLedger.append({ request_id: requestId, timestamp: 100 + index,
      accepted: true, status: "pending" });
  }
  const checked = [];
  consumer.queryReceiptStatus = async (entry) => {
    checked.push(entry.request_id);
    return { status: "pending" };
  };
  for (let cycle = 0; cycle < 3; cycle += 1) {
    const before = checked.length;
    consumer.historySyncAt = 0;
    await consumer.refreshReceiptStatuses();
    assert.ok(checked.length - before <= 20, "each synchronization remains bounded");
  }
  assert.equal(new Set(checked).size, requests.length, "older live entries are reached without requiring newer entries to settle");
});

test("unchanged pending and terminal public statuses never append redundant ledger rows", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("unchanged-public-status");
  authenticatedFixture(consumer);
  for (const [index, status] of ["pending", "submitted", "broadcast_unknown", "failed"].entries()) {
    consumer.historyLedger.append({ request_id: `0x${(300 + index).toString(16).padStart(64, "0")}`,
      accepted: true, status, timestamp: 100 + index,
      ...(status === "failed" ? { error_code: "authorization_expired", authorization_deadline: 123 } : {}) });
  }
  const before = consumer.history(0);
  let appends = 0;
  const append = consumer.historyLedger.append.bind(consumer.historyLedger);
  consumer.historyLedger.append = (entry) => { appends += 1; return append(entry); };
  consumer.queryReceiptStatus = async (entry) => ({
    request_id: entry.request_id, status: entry.status,
    // The real public endpoint emits JSON null for absent database fields;
    // ledger normalization omits them, so null and absent must compare equal.
    error_code: entry.error_code ?? null, tx_hash: entry.tx_hash ?? null,
    authorization_deadline: entry.authorization_deadline ?? null,
    updated_at: Math.floor(Date.now() / 1000),
  });
  for (let cycle = 0; cycle < 3; cycle += 1) {
    consumer.historySyncAt = 0;
    await consumer.refreshReceiptStatuses();
  }
  assert.equal(appends, 0, "changing only the polling timestamp must not grow either journal");
  assert.deepEqual(consumer.history(0), before);
});

test("acknowledged broadcast clears the old unknown error once without claiming chain confirmation", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("clear-broadcast-unknown");
  authenticatedFixture(consumer);
  const txHash = `0x${"56".repeat(32)}`;
  consumer.historyLedger.append({ request_id: REQUEST, accepted: true, status: "submitted",
    error_code: "broadcast_unknown", tx_hash: txHash, actual_fee_units: 2000 });
  consumer.queryReceiptStatus = async () => ({ request_id: REQUEST, status: "submitted",
    error_code: null, tx_hash: txHash, authorization_deadline: null });
  let appends = 0;
  const append = consumer.historyLedger.append.bind(consumer.historyLedger);
  consumer.historyLedger.append = (entry) => { appends += 1; return append(entry); };
  await consumer.refreshReceiptStatuses();
  let entry = consumer.history(0)[0];
  assert.equal(entry.status, "submitted", "Relay acknowledgement is not independent chain confirmation");
  assert.equal(entry.error_code, "", "an explicit tombstone must override the older journal error");
  assert.equal(entry.tx_hash, txHash);
  assert.equal(appends, 1);
  consumer.historySyncAt = 0;
  await consumer.refreshReceiptStatuses();
  entry = consumer.history(0)[0];
  assert.equal(entry.error_code, "");
  assert.equal(appends, 1, "an already cleared error does not create another journal row");
  const dashboard = await consumer.dashboardPayload(true);
  assert.equal(dashboard.usage.pending_units, 2000);
  assert.equal(dashboard.usage.failed_units, 0);
  assert.equal(dashboard.usage.settled_units, 0);
});

test("unknown execution exposes an unverified fee count and authorization ceiling, never a zero charge", async (t) => {
  const { state } = await fixture(t);
  const consumer = state("unknown-fee");
  consumer.historyLedger.append({ request_id: REQUEST, key_address: consumer.paymentAddress,
    status: "outcome_unknown", accepted: false, max_fee_units: 100000 });
  authenticatedFixture(consumer);
  consumer.refreshReceiptStatuses = async () => {};
  const view = await consumer.dashboardPayload(true);
  assert.equal(view.usage.unknown_fee_count, 1);
  assert.equal(view.usage.unknown_fee_authorized_maximum_units, 100000);
  assert.equal(view.history[0].actual_fee_units, undefined);
  assert.equal(view.usage.settled_units, 0);
  const locked = await consumer.dashboardPayload(false);
  assert.equal(locked.usage.unknown_fee_count, 0);
  assert.equal(locked.usage.unknown_fee_authorized_maximum_units, 0);
});
