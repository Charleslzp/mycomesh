import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { CHANNEL_FIELDS, capacityChannelId } from "../src/consumer-reserved.mjs";
import { NativeConsumerState, paymentKeyAddress, RESPONSE_PROOF_SCHEMA } from "../src/consumer-runtime.mjs";

const h = (n) => "0x" + n.toString(16).padStart(64, "0");
const a = (n) => "0x" + n.toString(16).padStart(40, "0");
const abi = (values) => "0x" + values.map((value) =>
  (typeof value === "string" && value.startsWith("0x") ? value.slice(2) : BigInt(value).toString(16)).padStart(64, "0")).join("");
const selector = (signature) => "0x" + Buffer.from(keccak_256(Buffer.from(signature)).slice(0, 4)).toString("hex");
const ttlSelector = selector("MAX_AUTHORIZATION_TTL()");
const channelSelector = selector("channelInfo(bytes32)");
const key = h(1), provider = paymentKeyAddress(h(2)), relay = paymentKeyAddress(h(3)), contract = a(50);

async function fixture(t, { healthTimeoutMs = 300, timeoutMs = 5000, rpcCount = 2, channelOverrides = {} } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const channel = {
    consumer_owner: a(80), consumer_key: paymentKeyAddress(key), provider_owner: a(81), provider_signer: provider,
    relay: a(82), relay_signer: relay, pool: a(0), channel: h(6), pricing_version: 1, pricing_hash: h(7),
    capacity: 1000000, max_fee_per_request: 100000, valid_from: now - 600, admit_until: now + 18000,
    claim_until: now + 27000, consumer_nonce: 0, provider_nonce: 0, permit_deadline: now - 500,
    settled_max_fee: 0, credit_remaining: 1000000, stake_remaining: 1000000, closed: false,
    ...channelOverrides,
  };
  channel.channel_id = capacityChannelId(channel, 31337, contract);
  const directory = await mkdtemp(join(tmpdir(), "myco-rpc-resilience-"));
  const nodes = Array.from({ length: rpcCount }, (_, i) => ({ mode: "ok", calls: [], blockHash: h(200 + i), confirmedReads: 0 }));
  const posts = [], serverErrors = [];
  let relayReady = true;
  const respond = (response, payload, status = 200) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(payload));
  };
  const server = createServer(async (request, response) => {
    try {
      if (request.url === "/relay/health") {
        respond(response, { ok: true, v10: { enabled: true, providers: relayReady ? 1 : 0,
          chain_id: 31337, settlement_contract: contract, relay_payment_address: channel.relay,
          relay_signer_address: relay, channel_hash: channel.channel, pricing_version: 1,
          pricing_hash: channel.pricing_hash, model: "fixture-model", models: ["fixture-model"],
          reservation_mode: "provider_bound_channel", response_proof: RESPONSE_PROOF_SCHEMA, scheduler: { session_affinity: true },
          provider_signers: [provider], provider_routes: [{ provider_signer: provider, provider: channel.provider_owner, models: ["fixture-model"] }],
        } });
        return;
      }
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      if (request.url === "/v1/responses") {
        posts.push({ body, payment: JSON.parse(Buffer.from(request.headers["payment-signature"], "base64url")) });
        respond(response, { error: { message: "fixture lost execution result" } }, 503);
        return;
      }
      const node = nodes[Number(request.url.match(/^\/rpc\/(\d+)$/)?.[1])];
      assert.ok(node, `unexpected fixture path ${request.url}`);
      node.calls.push(body);
      const mode = node.onCall?.(body, node) || node.mode;
      if (mode === "down") { respond(response, { error: { message: "fixture RPC unavailable" } }, 503); return; }
      if (mode === "disconnect") { request.socket.destroy(); return; }
      if (mode === "hang") return;
      if (mode === "hang-body") { response.writeHead(200); response.write('{"jsonrpc":"2.0",'); return; }
      if (mode === "rate-limit") { respond(response, { jsonrpc: "2.0", id: body.id, error: { code: -32005, message: "fixture rate limit" } }); return; }
      let result;
      if (body.method === "eth_chainId") result = mode === "wrong-chain" ? "0x1" : "0x7a69";
      else if (body.method === "eth_getBlockByNumber") {
        const latest = body.params[0] === "latest";
        if (!latest) node.confirmedReads += 1;
        result = { number: latest ? "0x64" : "0x5e", timestamp: "0x" + now.toString(16),
          hash: latest ? h(100) : mode === "reorg" && node.confirmedReads % 2 === 0 ? h(999) : node.blockHash };
      } else if (body.method === "eth_call") {
        assert.deepEqual(body.params[1], { blockHash: node.blockHash, requireCanonical: true });
        const data = body.params[0].data;
        if (data.startsWith(ttlSelector)) result = abi([mode === "wrong-ttl" ? 3600 : 10800]);
        else {
          assert.equal(data, channelSelector + channel.channel_id.slice(2));
          result = abi([...CHANNEL_FIELDS.map(([name]) => channel[name]), channel.settled_max_fee,
            channel.credit_remaining, channel.stake_remaining, Number(channel.closed)]);
        }
      } else assert.fail(`unexpected RPC method ${body.method}`);
      respond(response, { jsonrpc: "2.0", id: body.id, result });
    } catch (error) { serverErrors.push(error); if (!response.headersSent) respond(response, { error: { message: error.message } }, 500); else response.end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  const rpcUrls = nodes.map((_, i) => `${url}/rpc/${i}`);
  const manifest = {
    protocol_version: 10, eip712_name: "MycoMesh Settlement", eip712_version: "10", reservation_mode: "provider_bound_channel",
    chain_domain: "10", max_authorization_ttl_seconds: 10800, authorization_deadline_seconds: 9000,
    chain_id: 31337, deployer: a(1), stablecoin: a(2), settlement: contract, treasury: a(4), governance: a(5),
    channel: "codex", channel_hash: h(6), pricing_version: 1, pricing_hash: h(7), reward_token: a(0),
    network_id: "fixture-controlled-test", channel_id: "codex", backend_policy: "fixture", committee_mode: "controlled_test", independence_attested: false,
    adjudicators: [a(10), a(11), a(12)], adjudication_threshold: 2,
    adjudicator_operators: { [a(10)]: "test-operator", [a(11)]: "test-operator", [a(12)]: "test-operator" },
    policy: { dispute_window: 60, arbitration_timeout: 120, consumer_withdrawal_delay: 60, reporter_bond: 100,
      slash_bps: 5000, slash_cap: 10000, reporter_bounty_bps: 2000, stable_bounty_cap: 1000,
      token_reward: 0, token_reward_cap: 0, token_minimum_exposure: 0, token_minimum_penalty: 0, bond_penalty_recipient: a(9) },
    capacity_channel_ids: [channel.channel_id], settlement_rpc_urls: rpcUrls,
  };
  const networkConfig = join(directory, "network.json");
  await writeFile(networkConfig, JSON.stringify(manifest));
  const state = new NativeConsumerState({ env: { MYCOMESH_V8_PAYMENT_KEY: key }, networkConfig, allowControlledTest: true,
    dataDir: join(directory, "data"), historyDir: join(directory, "history"), relayUrls: url, timeoutMs, healthTimeoutMs });
  state.unlockedWallet = channel.consumer_owner;
  state.paymentUnlocked = true;
  t.after(async () => {
    await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
    await rm(directory, { recursive: true, force: true });
    assert.deepEqual(serverErrors, []);
  });
  return { state, channel, nodes, posts, rpcUrls, relayReady: (ready) => { relayReady = ready; },
    infer: (id) => state.relayInference("/v1/responses", { model: "fixture-model", input: "local RPC fixture" },
      id ? { "idempotency-key": id } : {}) };
}

test("concurrent capacity readers share one verified snapshot and later reads see closure", async (t) => {
  const { state, channel, nodes } = await fixture(t);
  const values = await Promise.all(Array.from({ length: 12 }, () => state.capacityChannels()));
  assert.ok(values.every((value) => value[0].channel_id === channel.channel_id && !value[0].closed));
  assert.equal(nodes[0].calls.length, 6);
  assert.equal(nodes[1].calls.length, 0);
  channel.closed = true;
  channel.credit_remaining = 0;
  const next = await state.capacityChannels();
  assert.equal(next[0].closed, true);
  assert.equal(next[0].credit_remaining, 0);
  assert.equal(nodes[0].calls.length, 12);
});

test("a funded future channel reports its start time without blaming the healthy Relay", async (t) => {
  const validFrom = Math.floor(Date.now() / 1000) + 600;
  const { state, posts, infer } = await fixture(t, { channelOverrides: { valid_from: validFrom } });
  await assert.rejects(state.chooseRelay(new Set(), { model: "fixture-model" }), (error) => {
    assert.equal(error.code, "budget_not_started");
    assert.equal(error.availableAt, validFrom);
    assert.doesNotMatch(error.message, /no healthy/i);
    return true;
  });
  const result = await infer("future-budget");
  assert.equal(result.status, 402);
  assert.equal(result.payload.error.code, "budget_not_started");
  assert.equal(result.payload.error.execution_status, "not_dispatched");
  assert.equal(posts.length, 0);
});

test("an exhausted budget is reported before dispatch", async (t) => {
  const { posts, infer } = await fixture(t, { channelOverrides: { settled_max_fee: 1000000, credit_remaining: 0 } });
  const result = await infer("empty-budget");
  assert.equal(result.status, 402);
  assert.equal(result.payload.error.code, "budget_unavailable");
  assert.equal(result.payload.error.execution_status, "not_dispatched");
  assert.equal(posts.length, 0);
});

test("a successful RPC becomes preferred and a recovered backup can replace it", async (t) => {
  const { state, nodes, rpcUrls } = await fixture(t);
  nodes[0].mode = "down";
  await state.capacityChannels();
  assert.equal(nodes[0].calls.length, 1);
  assert.equal(nodes[1].calls.length, 6);
  assert.equal(state.preferredRpcUrl, rpcUrls[1]);
  await state.capacityChannels();
  assert.equal(nodes[0].calls.length, 1);
  assert.equal(nodes[1].calls.length, 12);
  nodes[0].mode = "ok";
  nodes[1].mode = "down";
  await state.capacityChannels();
  assert.equal(nodes[0].calls.length, 7);
  assert.equal(nodes[1].calls.length, 13);
  assert.equal(state.preferredRpcUrl, rpcUrls[0]);
});

test("mid-snapshot transient failure restarts all verification and pins the new canonical block", async (t) => {
  const { state, nodes } = await fixture(t, { rpcCount: 1 });
  let failed = false;
  nodes[0].onCall = (body, node) => {
    if (!failed && body.method === "eth_call") {
      failed = true;
      node.blockHash = h(350);
      return "rate-limit";
    }
  };
  await state.capacityChannels();
  assert.equal(nodes[0].calls.length, 10);
  assert.equal(nodes[0].calls.filter((call) => call.method === "eth_chainId").length, 2);
  const reads = nodes[0].calls.filter((call) => call.method === "eth_call");
  assert.equal(reads[0].params[1].blockHash, h(200));
  assert.ok(reads.slice(1).every((call) => call.params[1].blockHash === h(350)));
});

test("RPC failover restarts the complete snapshot on one endpoint", async (t) => {
  const { state, nodes } = await fixture(t);
  nodes[0].onCall = (body) => body.method === "eth_call" ? "disconnect" : undefined;
  await state.capacityChannels();
  assert.equal(nodes[0].calls.length, 4);
  assert.equal(nodes[1].calls.length, 6);
  assert.equal(nodes[1].calls[0].method, "eth_chainId");
  assert.ok(nodes[1].calls.filter((call) => call.method === "eth_call")
    .every((call) => call.params[1].blockHash === h(201)));
});

test("failed concurrent snapshots use bounded attempts and are cleared for recovery", async (t) => {
  const { state, nodes } = await fixture(t);
  nodes.forEach((node) => { node.mode = "down"; });
  const outcomes = await Promise.allSettled(Array.from({ length: 10 }, () => state.capacityChannels()));
  assert.ok(outcomes.every((outcome) => outcome.status === "rejected" && outcome.reason.code === "rpc_unavailable"));
  assert.deepEqual(nodes.map((node) => node.calls.length), [2, 2]);
  nodes[0].mode = "ok";
  assert.equal((await state.capacityChannels()).length, 1);
  assert.deepEqual(nodes.map((node) => node.calls.length), [8, 2]);
});

for (const [mode, count, reason] of [["wrong-chain", 1, "chain mismatch"], ["wrong-ttl", 4, "lifetime mismatch"], ["reorg", 6, "reorged"]]) {
  test(`deterministic ${mode} validation failure is not retried or cached`, async (t) => {
    const { state, nodes } = await fixture(t, { rpcCount: 1 });
    nodes[0].mode = mode;
    await assert.rejects(state.capacityChannels(), (error) => error.code === "rpc_unavailable" && error.message.includes(reason));
    assert.equal(nodes[0].calls.length, count);
    nodes[0].mode = "ok";
    assert.equal((await state.capacityChannels()).length, 1);
    assert.equal(nodes[0].calls.length, count + 6);
  });
}

for (const mode of ["hang", "hang-body"]) {
  test(`${mode} RPC has a bounded deadline through the complete HTTP body`, async (t) => {
    const { state, nodes } = await fixture(t, { rpcCount: 1, healthTimeoutMs: 50 });
    nodes[0].mode = mode;
    const start = performance.now();
    await assert.rejects(state.capacityChannels(), (error) => error.code === "rpc_unavailable");
    assert.equal(nodes[0].calls.length, 2);
    assert.ok(performance.now() - start < 1500);
  });
}

function assertNotDispatched(result, code) {
  assert.equal(result.status, 503, JSON.stringify(result.payload));
  assert.equal(result.payload.error.code, code);
  assert.equal(result.payload.error.execution_status, "not_dispatched");
  assert.match(result.headers["x-mycomesh-request-id"], /^0x[0-9a-f]{64}$/);
  assert.equal(result.payload.error.request_id, result.headers["x-mycomesh-request-id"]);
}

test("predispatch RPC failure keeps a stable request ID and recovery never replays inference", async (t) => {
  const { state, nodes, posts, infer } = await fixture(t);
  nodes.forEach((node) => { node.mode = "down"; });
  const failure = await infer("rpc-down");
  assertNotDispatched(failure, "rpc_unavailable");
  assert.equal(posts.length, 0);
  assert.deepEqual(state.history(0), []);
  assert.equal(state.relayFailures.size, 0);
  nodes[0].mode = "ok";
  assert.deepEqual(await infer("rpc-down"), failure);
  assert.equal(posts.length, 0);
  const unknown = await infer("rpc-recovered");
  assert.equal(unknown.status, 422, JSON.stringify(unknown.payload));
  assert.equal(unknown.payload.error.execution_status, "unknown");
  assert.equal(unknown.headers["x-should-retry"], "false");
  assert.equal(posts.length, 1);
  assert.equal(posts[0].payment.authorization.request_id, unknown.headers["x-mycomesh-request-id"]);
  const repeated = await infer("rpc-recovered");
  assert.equal(repeated.payload.error.code, "idempotency_outcome_unknown");
  assert.equal(repeated.headers["x-mycomesh-request-id"], unknown.headers["x-mycomesh-request-id"]);
  assert.equal(posts.length, 1);
});

test("RPC failure during final authorization retains request identity without any POST", async (t) => {
  const { state, nodes, posts, infer } = await fixture(t, { rpcCount: 1 });
  let snapshots = 0;
  nodes[0].onCall = (body) => {
    if (body.method === "eth_chainId") snapshots += 1;
    if (snapshots > 1) return "down";
  };
  assertNotDispatched(await infer(), "rpc_unavailable");
  assert.equal(posts.length, 0);
  assert.deepEqual(state.history(0), []);
  assert.equal(state.relayFailures.size, 0);
  assert.equal([...state.relayInFlight.values()].reduce((sum, n) => sum + n, 0), 0);
});

test("Relay health failure stays distinct from RPC failure", async (t) => {
  const { nodes, posts, infer, relayReady } = await fixture(t);
  relayReady(false);
  assertNotDispatched(await infer(), "relay_unavailable");
  assert.equal(posts.length, 0);
  assert.equal(nodes.reduce((sum, node) => sum + node.calls.length, 0), 0);
});
