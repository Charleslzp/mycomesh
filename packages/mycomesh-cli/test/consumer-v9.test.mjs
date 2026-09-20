import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { keccak_256 } from "@noble/hashes/sha3";
import { NativeConsumerState, createConsumerServer, verifySignedReceipt, RESPONSE_PROOF_SCHEMA } from "../src/consumer-runtime.mjs";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const addr = (n) => `0x${n.toString(16).padStart(40, "0")}`;
const hash = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const KEY = hash(1), OWNER = addr(80), PROVIDER = addr(81), CONTRACT = addr(3);
const PROVIDER_SIGNER = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf";
const RELAY_SIGNER = "0x6813eb9362372eef6200f3b1dbc3f819671cba69";
const word = (v) => typeof v === "string" && v.startsWith("0x") ? v.slice(2).padStart(64, "0") : BigInt(v).toString(16).padStart(64, "0");
const abi = (values) => `0x${values.map(word).join("")}`;
const selector = (signature) => Buffer.from(keccak_256(Buffer.from(signature))).subarray(0, 4).toString("hex");

function manifest() {
  return { protocol_version: 9, chain_id: 31337, deployer: addr(1), stablecoin: addr(2), settlement: CONTRACT,
    treasury: addr(4), governance: addr(5), channel: "codex", channel_hash: hash(6), pricing_version: 1, pricing_hash: hash(7),
    reward_token: addr(8), eip712_name: "MycoMesh Settlement", eip712_version: "9", network_id: "local-fixture",
    channel_id: "codex", backend_policy: "test-only", independence_attested: true,
    policy: { dispute_window: 60, arbitration_timeout: 120, consumer_withdrawal_delay: 60, reporter_bond: 100,
      slash_bps: 5000, slash_cap: 10000, reporter_bounty_bps: 2000, stable_bounty_cap: 1000, token_reward: 10,
      token_reward_cap: 1000, token_minimum_exposure: 100, token_minimum_penalty: 10, bond_penalty_recipient: addr(9) },
    adjudicators: [addr(10), addr(11), addr(12)], adjudication_threshold: 2,
    adjudicator_operators: { [addr(10)]: "operator-a", [addr(11)]: "operator-b", [addr(12)]: "operator-c" } };
}

function pythonReceipt(payment) {
  const program = `import json,sys
from gateway.chain_v9 import build_provider_receipt,finalize_relay_receipt,settlement_key_for
from gateway import chain_v8,chain_v9
from gateway.relay_integrity import provider_response_hash,provider_response_proof
p=json.load(sys.stdin)
protocol=chain_v9 if p['schema']==chain_v9.AUTH_SCHEMA else chain_v8
body={'peer':{'peer_id':'fixture-peer','public_key':'fixture-key'},'request_id':p['authorization']['request_id'],'endpoint':'responses','model':'fixture-model','output_text':'fixture','usage':{'input_tokens':12,'output_tokens':7},'raw':{'id':'resp_fixture','object':'response','model':'fixture-model','output':[],'output_text':'fixture','usage':{'input_tokens':12,'output_tokens':7}}}
r=protocol.build_provider_receipt(provider='${PROVIDER}',provider_private_key='${hash(2)}',authorization_payload=p,response_hash=provider_response_hash(body),relay=p['authorization']['relay'],input_tokens=12,output_tokens=7,actual_fee=2000)
s=protocol.finalize_relay_receipt(r,relay_private_key='${hash(3)}')
print(json.dumps({'accepted':True,'status':'pending','settlement_key':settlement_key_for('${OWNER}',p['authorization']['key'],p['authorization']['request_id']),'signed_receipt':s,'fixture_proof':provider_response_proof(body)}))`;
  const result = spawnSync("python3", ["-B", "-c", program], { cwd: ROOT, input: JSON.stringify(payment), encoding: "utf8", timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-v9-consumer-"));
  const context = { posts: [], rpcCalls: [], chainStatus: 0, remoteStatus: "confirmed", signed: null };
  const relay = createServer(async (request, response) => {
    try {
      response.setHeader("content-type", "application/json");
      if (request.url === "/relay/health") {
        const version = options.healthVersion || options.version || 9;
        response.end(JSON.stringify({ ok: true, [`v${version}`]: { enabled: true, providers: 1, chain_id: 31337,
          settlement_contract: options.healthContract || CONTRACT, relay_payment_address: addr(82), relay_signer_address: RELAY_SIGNER,
          channel_hash: hash(6), pricing_version: 1, pricing_hash: hash(7), models: ["fixture-model"], model: "fixture-model",
          response_proof: options.legacyRelay ? undefined : RESPONSE_PROOF_SCHEMA,
          scheduler: { session_affinity: true }, provider_signers: [PROVIDER_SIGNER] } }));
        return;
      }
      let raw = "";
      for await (const chunk of request) raw += chunk;
      if (request.url === "/rpc") {
        const rpc = JSON.parse(raw);
        context.rpcCalls.push(rpc);
        let result = "0x0";
        if (rpc.method === "eth_chainId") result = "0x7a69";
        else if (rpc.method === "eth_getBlockByNumber") result = options.noSafeBlock ? null : { number: "0x9", hash: hash(100), timestamp: `0x${Math.floor(Date.now() / 1000).toString(16)}` };
        else if (rpc.params[0]?.data?.slice(2, 10) === selector("MAX_AUTHORIZATION_TTL()")) result = abi([options.rpcMaxTtl ?? 10800]);
        else if (rpc.params[0]?.data?.slice(2, 10) === selector("settlementInfo(bytes32)")) {
          const auth = context.signed?.authorization.authorization || context.posts[0]?.payment.authorization;
          let values = [OWNER, context.state.paymentAddress, PROVIDER, PROVIDER_SIGNER, addr(82), RELAY_SIGNER, addr(0), addr(4),
            auth?.request_id || hash(1), auth?.request_hash || hash(2), context.signed?.receipt.authorization_hash || hash(3), context.signed?.receipt.response_hash || hash(90),
            2000, 1700, 60, 40, 200, 1000, 1060, context.chainStatus];
          if (options.mutateWords) values = options.mutateWords(values);
          result = abi(values) + (options.trailingGarbage ? "ff" : "");
        } else if (rpc.params[0]?.data?.slice(2, 10) === selector("keyGrants(address)")) result = abi([OWNER, 1000000000, options.validUntil ?? 0, 1]);
        response.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
        return;
      }
      if (request.url === "/v1/mycomesh/receipts/status") {
        const query = JSON.parse(raw);
        response.end(JSON.stringify({ request_id: query.request_id, status: context.remoteStatus }));
        return;
      }
      if (request.url === "/v1/responses") {
        const payment = JSON.parse(Buffer.from(request.headers["payment-signature"], "base64url").toString());
        context.posts.push({ payment, body: JSON.parse(raw) });
        if (!options.noReceipt) {
          const envelope = pythonReceipt(payment);
          context.proof = envelope.fixture_proof;
          delete envelope.fixture_proof;
          context.signed = structuredClone(envelope.signed_receipt);
          if (options.status) envelope.status = options.status;
          if (options.accepted === false) envelope.accepted = false;
          if (options.mutateReceipt) options.mutateReceipt(envelope.signed_receipt);
          response.setHeader("PAYMENT-RESPONSE", Buffer.from(JSON.stringify(envelope)).toString("base64url"));
        }
        assert.equal(request.headers["x-mycomesh-response-proof"], RESPONSE_PROOF_SCHEMA);
        if (options.mutateProof) options.mutateProof(context.proof);
        if (options.responseStatus) response.statusCode = options.responseStatus;
        if (options.malformedBody) { response.end(options.malformedBody); return; }
        response.end(JSON.stringify(options.noProof || !context.proof ? { output_text: "unverified fixture" } : context.proof));
        return;
      }
      response.statusCode = 404;
      response.end("{}");
    } catch (error) { response.statusCode = 500; response.end(JSON.stringify({ error: { message: error.stack } })); }
  });
  await new Promise((resolve) => relay.listen(0, "127.0.0.1", resolve));
  const relayUrl = `http://127.0.0.1:${relay.address().port}`;
  const networkPath = join(directory, "network.json");
  await writeFile(networkPath, JSON.stringify({ ...manifest(), protocol_version: options.version || 9,
    ...(options.longWindow ? { max_authorization_ttl_seconds: 10800, authorization_deadline_seconds: 9000 } : {}),
    ...(options.requireProof !== undefined ? { require_response_proof: options.requireProof } : {}), settlement_rpc_url: `${relayUrl}/rpc` }));
  const state = new NativeConsumerState({ dataDir: join(directory, "data"), historyDir: join(directory, "shared"), networkConfig: networkPath, relayUrls: relayUrl,
    env: { MYCOMESH_V8_PAYMENT_KEY: KEY }, healthTimeoutMs: 1000, timeoutMs: 5000 });
  state.unlockedWallet = OWNER;
  state.managementToken = "fixture-only-management-token";
  state.paymentUnlocked = true;
  context.state = state;
  const edge = createConsumerServer(state, { port: 0 });
  const endpoint = await edge.listen();
  t.after(async () => { await edge.close(); await new Promise((resolve) => { relay.closeAllConnections(); relay.close(resolve); }); await rm(directory, { recursive: true, force: true }); });
  context.infer = async () => {
    const response = await fetch(`http://127.0.0.1:${endpoint.port}/v1/responses`, { method: "POST",
      headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" }, body: JSON.stringify({ model: "fixture-model", input: "local protocol fixture" }) });
    return { status: response.status, body: await response.json(), headers: response.headers };
  };
  context.refresh = async () => { state.historySyncAt = 0; await state.refreshReceiptStatuses(); };
  return context;
}

test("V9 localhost HTTP Consumer sends v3 authorization, verifies Python receipt and records history", async (t) => {
  const f = await fixture(t);
  const response = await f.infer();
  assert.equal(response.status, 200);
  assert.equal(response.body.output_text, "fixture");
  assert.equal(response.headers.get("x-mycomesh-content-verification"), "provider-signed");
  assert.equal(f.posts.length, 1);
  assert.equal(f.posts[0].payment.schema, "mycomesh.x402.myco-credit-v3");
  assert.equal(f.posts[0].payment.settlement_contract, CONTRACT);
  assert.equal(f.signed.schema, "mycomesh.settlement.v9.signed.v1");
  assert.equal(verifySignedReceipt(f.signed, { protocolVersion: 9 }).receipt.actual_fee, 2000);
  assert.equal(f.state.history(0).length, 1);
  assert.equal(f.state.history(0)[0].status, "pending");
  assert.equal(f.state.history(0)[0].response_hash, f.signed.receipt.response_hash);
});

for (const options of [{ healthVersion: 8 }, { healthContract: addr(99) }, { legacyRelay: true }]) {
  test(`V9 rejects incompatible Relay health before sending payment: ${JSON.stringify(options)}`, async (t) => {
    const f = await fixture(t, options);
    assert.equal((await f.infer()).status, 503);
    assert.equal(f.posts.length, 0);
  });
}

for (const options of [
  { noProof: true },
  { noProof: true, accepted: false },
  { malformedBody: '{broken json' },
  { malformedBody: '[]' },
  { responseStatus: 503 },
  { mutateProof: (proof) => { const value = JSON.parse(Buffer.from(proof.commitment_b64, "base64")); value.raw.output_text = "forged by relay"; proof.commitment_b64 = Buffer.from(JSON.stringify(value)).toString("base64"); } },
]) {
  test(`Consumer retains valid receipt on failed content without replay: ${options.noProof ? "missing" : options.malformedBody || options.responseStatus || "tampered"}`, async (t) => {
    const f = await fixture(t, options);
    const response = await f.infer();
    assert.equal(response.status, 502);
    assert.equal(f.posts.length, 1);
    assert.equal(f.state.history(0).length, 1, "valid payment evidence must survive delivery failure");
    assert.equal(f.state.history(0)[0].content_verification, "failed");
    assert.equal(f.state.history(0)[0].status, "pending");
    assert.equal(f.state.history(0)[0].accepted, true, "unsigned false cannot hide a payable receipt from chain sync");
    assert.ok(response.headers.get("PAYMENT-RESPONSE"));
    assert.equal(response.headers.get("x-mycomesh-content-verification"), "failed");
    assert.notEqual(response.body.output_text, "forged by relay");
  });
}

test('unsigned error sibling cannot replace the authenticated Provider result', async (t) => {
  const f = await fixture(t, { mutateProof: (proof) => { proof.error = { message: 'unsigned decoy' }; } });
  const response = await f.infer();
  assert.equal(response.status, 200);
  assert.equal(response.body.output_text, 'fixture');
  assert.equal(response.body.error, undefined);
});

test('existing V8 can opt into exact content proofs without a new contract', async (t) => {
  const f = await fixture(t, { version: 8, requireProof: true });
  const response = await f.infer();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-mycomesh-content-verification'), 'provider-signed');
  assert.equal(f.signed.schema, 'mycomesh.settlement.v8.signed.v1');
});

test('V8 pinned content-proof requirement cannot be downgraded by Relay health', async (t) => {
  const f = await fixture(t, { version: 8, requireProof: true, legacyRelay: true });
  assert.equal((await f.infer()).status, 503);
  assert.equal(f.posts.length, 0);
});

for (const [name, options] of [
  ["missing signed receipt", { noReceipt: true }],
  ["V8 labelled receipt", { mutateReceipt: (receipt) => { receipt.schema = "mycomesh.settlement.v8.signed.v1"; } }],
  ["outer chain mismatch", { mutateReceipt: (receipt) => { receipt.chain_id = 1; } }],
  ["outer contract mismatch", { mutateReceipt: (receipt) => { receipt.settlement_contract = addr(99); } }],
  ["authorization tampering", { mutateReceipt: (receipt) => { receipt.authorization.authorization.request_hash = hash(99); } }],
]) {
  test(`V9 fails closed without replay on ${name}`, async (t) => {
    const f = await fixture(t, options);
    assert.equal((await f.infer()).status, 502);
    assert.equal(f.posts.length, 1);
    const tracked = f.state.history(0);
    assert.equal(tracked.length, 1);
    assert.equal(tracked[0].status, "outcome_unknown");
    assert.equal(tracked[0].accepted, false);
    assert.equal(tracked[0].actual_fee_units, undefined);
    assert.equal(tracked[0].request_id, f.posts[0].payment.authorization.request_id);
  });
}

for (const status of ["confirmed", "escrowed", "released", "refunded", "dismissed", "timed_out"]) {
  test(`Relay unsigned status ${status} cannot fabricate V9 chain outcome`, async (t) => {
    const f = await fixture(t, { status });
    assert.equal((await f.infer()).status, 200);
    assert.equal(f.state.history(0)[0].status, "pending");
    await f.refresh();
    assert.equal(f.state.history(0)[0].status, "pending");
    const dashboard = await f.state.dashboardPayload(true);
    assert.equal(dashboard.usage.settled_units, 0);
    assert.equal(dashboard.usage.refunded_units, 0);
  });
}

test("V9 canonical safe-block escrow→dispute→refund never counts as paid income", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.infer()).status, 200);
  for (const [number, status] of [[1, "escrowed"], [2, "disputed"], [4, "refunded"]]) {
    f.chainStatus = number;
    await f.refresh();
    assert.equal(f.state.history(0)[0].status, status);
    const dashboard = await f.state.dashboardPayload(true);
    assert.equal(dashboard.usage.settled_units, 0);
    assert.equal(dashboard.usage.refunded_units, number === 4 ? 2000 : 0);
  }
  const calls = f.rpcCalls.filter((call) => call.method === "eth_call" && call.params[0].data.slice(2, 10) === selector("settlementInfo(bytes32)"));
  assert.equal(calls.length, 3);
  assert.ok(calls.every((call) => call.params[1].blockHash === hash(100) && call.params[1].requireCanonical === true));
  assert.ok(f.rpcCalls.filter((call) => call.method === "eth_getBlockByNumber").every((call) => call.params[0] === "safe"));
});

for (const [name, options] of [
  ["trailing ABI bytes", { trailingGarbage: true }],
  ["unknown status", { mutateWords: (values) => { values[19] = 7; return values; } }],
  ["noncanonical address padding", { mutateWords: (values) => { values[0] = `0x${"1".repeat(24)}${OWNER.slice(2)}`; return values; } }],
  ["different Provider", { mutateWords: (values) => { values[2] = addr(99); return values; } }],
  ["different committed response", { mutateWords: (values) => { values[11] = hash(99); return values; } }],
  ["unavailable safe block", { noSafeBlock: true }],
]) {
  test(`V9 safe-state validation preserves pending on ${name}`, async (t) => {
    const f = await fixture(t, options);
    assert.equal((await f.infer()).status, 200);
    f.chainStatus = 4;
    await f.refresh();
    assert.equal(f.state.history(0)[0].status, "pending");
    assert.ok(f.state.historySyncError);
  });
}

test("explicit malformed V9 manifests never fall back to V8 or fixture committee defaults", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-v9-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "network.json");
  const create = () => new NativeConsumerState({ dataDir: join(directory, "data"), historyDir: join(directory, "shared"), networkConfig: path, env: { MYCOMESH_V8_PAYMENT_KEY: KEY } });
  assert.throws(create, /missing/);
  await writeFile(path, "{invalid");
  assert.throws(create, /Invalid configured/);
  for (const name of ["policy", "adjudicators", "adjudicator_operators", "independence_attested", "reward_token", "eip712_version"]) {
    const value = manifest(); delete value[name];
    await writeFile(path, JSON.stringify(value));
    assert.throws(create, /V9/, name);
  }
  for (const changes of [{ deployment: "missing.json" }, { independence_attested: false }, { adjudication_threshold: 1 },
    { adjudicator_operators: { [addr(10)]: "same", [addr(11)]: "same", [addr(12)]: "other" } },
    { governance: addr(10) }, { reward_token: addr(2) }, { chain_id: 31337.5 }]) {
    await writeFile(path, JSON.stringify({ ...manifest(), ...changes }));
    assert.throws(create, /V9|missing/, JSON.stringify(changes));
  }
});

test("long V9 settlement window verifies actual contract limit and full key lifetime", async (t) => {
  const f = await fixture(t, { longWindow: true });
  const response = await f.infer();
  assert.equal(response.status, 200, JSON.stringify(response.body));
  const auth = f.posts[0].payment.authorization;
  assert.equal(auth.deadline - auth.issued_at, 9300);
  const reads = f.rpcCalls.filter((call) => call.method === "eth_call");
  assert.ok(reads.length >= 2);
  assert.deepEqual(reads[0].params[1], { blockHash: hash(100), requireCanonical: true });
  assert.deepEqual(reads[1].params[1], reads[0].params[1]);
});

for (const options of [{ rpcMaxTtl: 3600 }, { validUntil: Math.floor(Date.now() / 1000) + 4000 }]) {
  test(`long V9 authorization refuses incompatible chain or short key: ${JSON.stringify(options)}`, async (t) => {
    const f = await fixture(t, { longWindow: true, ...options });
    assert.ok((await f.infer()).status >= 400);
    assert.equal(f.posts.length, 0);
  });
}

for (const wrongHash of [false, true]) {
  test(`unknown execution reconciles only its matching safe-block escrow: wrong hash=${wrongHash}`, async (t) => {
    const f = await fixture(t, { noReceipt: true,
      ...(wrongHash ? { mutateWords: (words) => { words[9] = hash(999); return words; } } : {}),
    });
    assert.equal((await f.infer()).status, 502);
    assert.equal(f.state.history()[0].status, "outcome_unknown");
    f.chainStatus = 1;
    await f.refresh();
    const row = f.state.history()[0];
    if (wrongHash) {
      assert.equal(row.status, "outcome_unknown");
      assert.equal(row.actual_fee_units, undefined);
      assert.ok(f.state.historySyncError);
    } else {
      assert.equal(row.status, "escrowed");
      assert.equal(row.actual_fee_units, 2000);
      assert.equal(row.accepted, true);
    }
    assert.equal(f.posts.length, 1);
  });
}
