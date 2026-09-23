import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ed25519 } from "@noble/curves/ed25519";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { NativeConsumerState, createConsumerServer } from "../src/consumer-runtime.mjs";
import { reservedSettlementKey } from "../src/consumer-reserved.mjs";

const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const hash = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const OWNER = address(11);
const OTHER = address(12);
const PROVIDER = address(13);
const PROVIDER_SIGNER = address(14);
const RELAY = address(15);
const RELAY_SIGNER = address(16);
const POOL = address(17);
const TREASURY = address(18);
const REGISTRY = address(19);
const REQUEST_ID = hash(21);
const REQUEST_HASH = hash(22);
const RESPONSE_HASH = hash(23);
const CHANNEL_ID = hash(24);
const EVIDENCE_HASH = hash(25);
const AUTHORIZATION_HASH = hash(26);
const BOND = 100n;
const BLOCK_TIME = 1_800_000_000;
const RELEASE_AT = BLOCK_TIME + 300;
const JURY_PRIVATE_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const JURY_PUBLIC_KEY = Buffer.from(ed25519.getPublicKey(JURY_PRIVATE_KEY)).toString("hex");

const word = (value) => {
  if (typeof value === "string" && /^0x[0-9a-f]{40}$/i.test(value)) return value.slice(2).padStart(64, "0");
  if (typeof value === "string" && /^0x[0-9a-f]{64}$/i.test(value)) return value.slice(2);
  return BigInt(value).toString(16).padStart(64, "0");
};
const abi = (values) => `0x${values.map(word).join("")}`;
const selector = (signature) => `0x${Buffer.from(keccak_256(Buffer.from(signature))).subarray(0, 4).toString("hex")}`;
const reportId = (key, reporter, evidence) => `0x${Buffer.from(keccak_256(Buffer.concat([
  Buffer.from(key.slice(2), "hex"), Buffer.alloc(12), Buffer.from(reporter.slice(2), "hex"),
  Buffer.from(evidence.slice(2), "hex"),
]))).toString("hex")}`;

function stableStringify(value) {
  if (value === null) return "null";
  if (["string", "boolean", "number"].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

function signedReference({ contract, settlementKey, reporter = OWNER, evidenceHash = EVIDENCE_HASH,
  predictedReportId = reportId(settlementKey, reporter, evidenceHash), requestHash = REQUEST_HASH } = {}) {
  const schema = "mycomesh.v10.provider-jury-evidence-reference.v1";
  const body = {
    schema, network: "eip155:11155111", chain_id: 11155111,
    settlement_contract: contract, settlement_key: settlementKey,
    request_id: REQUEST_ID, request_hash: requestHash, evidence_hash: evidenceHash,
    predicted_report_id: predictedReportId, reporter,
    origin_relay_public_key: JURY_PUBLIC_KEY,
  };
  const metadata = {
    nonce: evidenceHash.slice(2, 34), public_key: JURY_PUBLIC_KEY, purpose: schema,
    timestamp: 1_799_999_000,
    audience: `${schema}:eip155:11155111:${contract}:${reporter}`,
  };
  const message = Buffer.from(stableStringify({ document: body, signature: metadata }));
  return { ...body, signature: { ...metadata,
    signature: Buffer.from(ed25519.sign(message, JURY_PRIVATE_KEY)).toString("hex") } };
}

function settlementRecord(state, status = 1, overrides = {}) {
  const values = [OWNER, state.paymentAddress, PROVIDER, PROVIDER_SIGNER, RELAY, RELAY_SIGNER,
    POOL, TREASURY, REQUEST_ID, REQUEST_HASH, AUTHORIZATION_HASH, RESPONSE_HASH,
    2_000, 1_700, 60, 40, 200, BLOCK_TIME - 10, RELEASE_AT, status];
  const fields = { owner: 0, key: 1, request_id: 8, request_hash: 9, response_hash: 11,
    release_at: 18, status: 19 };
  for (const [name, value] of Object.entries(overrides)) values[fields[name]] = value;
  return abi(values);
}

function policy(reporterBond = BOND) {
  return abi([300, 600, 300, reporterBond, 5000, 10000, 2000, 1000, 0, 0, 0, 0, TREASURY]);
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-dispute-"));
  const state = new NativeConsumerState({ dataDir: join(directory, "data"), historyDir: join(directory, "history"), env: {} });
  state.network = {
    ...state.network,
    protocol_version: 10,
    committee_mode: "dynamic_provider_ai_v1",
    jury_registry: REGISTRY,
    jury_relay_public_keys: [JURY_PUBLIC_KEY],
    reporter_bond_units: BOND.toString(),
  };
  state.unlockedWallet = OWNER;
  state.managementToken = "test-management-token";
  state.paymentUnlocked = true;
  const settlementKey = reservedSettlementKey(CHANNEL_ID, REQUEST_ID);
  const reference = signedReference({ contract: state.network.settlement_contract, settlementKey,
    ...(options.reference || {}) });
  state.historyLedger.append({
    request_id: REQUEST_ID, request_hash: REQUEST_HASH, response_hash: RESPONSE_HASH,
    capacity_channel_id: CHANNEL_ID, settlement_key: settlementKey,
    timestamp: 100, status: "escrowed", accepted: true, owner: options.owner || OWNER,
    provider: PROVIDER, provider_signer: PROVIDER_SIGNER,
    jury_evidence_hash: reference.evidence_hash,
    jury_report_id: reference.predicted_report_id,
    jury_reporter: reference.reporter,
    jury_origin_relay_public_key: reference.origin_relay_public_key,
    jury_reference_signature: options.badSignature ? "00".repeat(64) : reference.signature.signature,
    jury_reference_timestamp: reference.signature.timestamp,
    settlement_release_at: RELEASE_AT,
  });
  state.rpcValue = (operation) => operation("mock-rpc");
  state.callRpc = async (_rpc, method) => {
    if (method === "eth_chainId") return "0xaa36a7";
    if (method === "eth_getBlockByNumber") return { hash: hash(31), number: "0x10", timestamp: `0x${BLOCK_TIME.toString(16)}` };
    throw new Error(`unexpected RPC method ${method}`);
  };
  state.contractCall = async (_rpc, target, signature) => {
    if (signature === "settlementInfo(bytes32)") return settlementRecord(state, options.status ?? 1, options.record || {});
    if (signature === "policy()") return policy(options.bond ?? BOND);
    if (signature === "allowance(address,address)") return abi([options.allowance ?? 0]);
    if (signature === "balanceOf(address)") return abi([options.balance ?? 1_000]);
    if (signature === "juryRegistry()") return abi([REGISTRY]);
    throw new Error(`unexpected contract call ${target} ${signature}`);
  };
  t.after(async () => { await state.dispatcher.close(); await rm(directory, { recursive: true, force: true }); });
  return { state, directory, settlementKey, reference };
}

const request = { action: "open_dispute", wallet: OWNER, request_id: REQUEST_ID, channel_id: CHANNEL_ID };

test("open_dispute derives evidence only from signed local history and plans exact bond approval", async (t) => {
  const { state, settlementKey } = await fixture(t);
  const plan = await state.transactionPlan(request);
  assert.equal(plan.settlement_key, settlementKey);
  assert.equal(plan.evidence_hash, EVIDENCE_HASH);
  assert.equal(plan.bond_units, BOND.toString());
  assert.equal(plan.transactions.length, 2);
  assert.equal(plan.transactions[0].kind, "approval");
  assert.equal(plan.transactions[0].data.slice(0, 10), selector("approve(address,uint256)"));
  assert.equal(BigInt(`0x${plan.transactions[0].data.slice(-64)}`), BOND);
  assert.equal(plan.transactions[1].kind, "open_dispute");
  assert.equal(plan.transactions[1].data.slice(0, 10), selector("openDispute(bytes32,bytes32)"));
  assert.equal(`0x${plan.transactions[1].data.slice(-64)}`, EVIDENCE_HASH);
  assert.equal(state.history(0)[0].dispute_stage, "planned");
  await assert.rejects(() => state.transactionPlan({ ...request, evidence_hash: hash(99) }), /accepts only/);
});

test("sufficient allowance omits approval but insufficient token balance fails", async (t) => {
  const ready = await fixture(t, { allowance: BOND });
  assert.deepEqual((await ready.state.transactionPlan(request)).transactions.map((item) => item.kind), ["open_dispute"]);
  const poor = await fixture(t, { balance: BOND - 1n });
  await assert.rejects(() => poor.state.transactionPlan(request), /balance/);
});

for (const [name, options, pattern] of [
  ["bad history signature", { badSignature: true }, /signature/],
  ["non-owner history", { owner: OTHER }, /authenticated settlement owner/],
  ["expired settlement", { record: { release_at: BLOCK_TIME } }, /window has closed/],
  ["wrong status", { status: 2 }, /not pending/],
  ["wrong request hash", { record: { request_hash: hash(90) } }, /differs/],
  ["wrong response hash", { record: { response_hash: hash(91) } }, /differs/],
  ["wrong reporter bond", { bond: BOND + 1n }, /reporter bond differs/],
  ["noncanonical report id", { reference: { predictedReportId: hash(92) } }, /report ID/],
]) {
  test(`open_dispute rejects ${name}`, async (t) => {
    const { state } = await fixture(t, options);
    await assert.rejects(() => state.transactionPlan(request), pattern);
  });
}

test("submitted dispute is persistent, blocks duplicates, and restart reconcile confirms bound report", async (t) => {
  const first = await fixture(t, { allowance: BOND });
  const plan = await first.state.transactionPlan(request);
  const txHash = hash(70);
  first.state.recordDisputeProgress({ ...request, stage: "wallet_prompted", transaction_kind: "open_dispute" });
  first.state.recordDisputeProgress({ ...request, stage: "submitted", transaction_kind: "open_dispute", tx_hash: txHash });
  await assert.rejects(() => first.state.transactionPlan(request), /already awaiting/);

  const state = new NativeConsumerState({ dataDir: join(first.directory, "restart"),
    historyDir: join(first.directory, "history"), env: { MYCOMESH_V8_PAYMENT_KEY: first.state.paymentKey } });
  state.network = { ...first.state.network };
  state.unlockedWallet = OWNER; state.managementToken = "restart-token"; state.paymentUnlocked = true;
  state.rpcValue = (operation) => operation("mock-rpc");
  let head = "0x24";
  state.callRpc = async (_rpc, method) => {
    if (method === "eth_getTransactionReceipt") return { transactionHash: txHash, blockHash: hash(71), blockNumber: "0x20",
      from: OWNER, to: state.network.settlement_contract, status: "0x1" };
    if (method === "eth_getTransactionByHash") return { hash: txHash, blockHash: hash(71), blockNumber: "0x20",
      from: OWNER, to: state.network.settlement_contract, input: plan.transactions[0].data };
    if (method === "eth_getBlockByHash") return { hash: hash(71), number: "0x20", timestamp: `0x${(BLOCK_TIME + 1).toString(16)}` };
    if (method === "eth_getBlockByNumber") return { hash: hash(71), number: "0x20", timestamp: `0x${(BLOCK_TIME + 1).toString(16)}` };
    if (method === "eth_blockNumber") return head;
    throw new Error(`unexpected ${method}`);
  };
  state.contractCall = async (_rpc, _target, signature) => {
    if (signature === "settlementInfo(bytes32)") return settlementRecord(state, 2);
    if (signature === "reports(bytes32,bytes32)") return abi([OWNER, EVIDENCE_HASH, 0]);
    throw new Error(signature);
  };
  t.after(() => state.dispatcher.close());
  await state.refreshDisputeTransactions(true);
  assert.equal(state.history(0)[0].dispute_stage, "submitted");
  head = "0x25";
  await state.refreshDisputeTransactions(true);
  const [entry] = state.history(0);
  assert.equal(entry.dispute_stage, "confirmed");
  assert.equal(entry.status, "disputed");
  assert.equal(entry.dispute_tx_hash, txHash);
});

test("reconcile distinguishes reverted and unknown submitted transactions", async (t) => {
  for (const [label, rpc, expected] of [
    ["reverted", async (_rpc, method) => method === "eth_getTransactionReceipt"
      ? { transactionHash: hash(80), blockHash: hash(81), blockNumber: "0x21", from: OWNER,
        to: null, status: "0x0" }
      : method === "eth_getTransactionByHash"
        ? null : { hash: hash(81), number: "0x21", timestamp: `0x${BLOCK_TIME.toString(16)}` }, "failed"],
    ["unknown", async () => { throw new Error("RPC offline"); }, "uncertain"],
  ]) {
    const context = await fixture(t, { allowance: BOND });
    const plan = await context.state.transactionPlan(request);
    const txHash = label === "reverted" ? hash(80) : hash(82);
    context.state.recordDisputeProgress({ ...request, stage: "wallet_prompted", transaction_kind: "open_dispute" });
    context.state.recordDisputeProgress({ ...request, stage: "submitted", transaction_kind: "open_dispute", tx_hash: txHash });
    if (label === "reverted") {
      context.state.callRpc = async (_rpc, method) => {
        if (method === "eth_getTransactionReceipt") return { transactionHash: txHash, blockHash: hash(81), blockNumber: "0x21",
          from: OWNER, to: context.state.network.settlement_contract, status: "0x0" };
        if (method === "eth_getTransactionByHash") return { hash: txHash, blockHash: hash(81), blockNumber: "0x21",
          from: OWNER, to: context.state.network.settlement_contract, input: plan.transactions[0].data };
        if (method === "eth_getBlockByHash") return { hash: hash(81), number: "0x21", timestamp: `0x${BLOCK_TIME.toString(16)}` };
        if (method === "eth_getBlockByNumber") return { hash: hash(81), number: "0x21", timestamp: `0x${BLOCK_TIME.toString(16)}` };
        if (method === "eth_blockNumber") return "0x26";
        throw new Error(method);
      };
    } else context.state.callRpc = rpc;
    await context.state.refreshDisputeTransactions(true);
    assert.equal(context.state.history(0)[0].dispute_stage, expected);
  }
});

test("dashboard exposes the dispute action copy without embedding evidence documents", async (t) => {
  const { state } = await fixture(t);
  const runtime = createConsumerServer(state, { port: 0 });
  await runtime.listen();
  try {
    const { port } = runtime.server.address();
    const html = await (await fetch(`http://127.0.0.1:${port}/`)).text();
    assert.match(html, /发起申诉/);
    assert.match(html, /客观欺诈或服务未交付/);
    assert.match(html, /evidence_hash/);
    assert.doesNotMatch(html, /provider_response|evidence_document/);
  } finally { await runtime.close(); }
});
