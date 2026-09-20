import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { NativeConsumerState, createReceiptStatusQuery, verifyAuthorization, walletMessageDigest } from "../src/consumer-runtime.mjs";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";

const signer = "0x" + "ab".repeat(20);
async function fixture(t, timeoutMs = 150) {
  const directory = await mkdtemp(join(tmpdir(), "myco-resilience-"));
  const nodes = [{ mode: "ok", ready: true, signers: [], healthCalls: 0 }, { mode: "ok", ready: true, signers: [], healthCalls: 0 }];
  const calls = [], servers = [], urls = [];
  for (const [index, node] of nodes.entries()) {
    const server = createServer(async (request, response) => {
      try {
        if (request.url === "/relay/health") {
          node.healthCalls += 1;
          if (node.mode === "dead-health") { response.writeHead(503); response.end("{}"); return; }
          response.writeHead(200, { "content-type": "application/json" });
          response.end(JSON.stringify({ ok: true, v8: { enabled: true, providers: 1, model: "gpt-5.5", models: ["gpt-5.5"],
            settlement_ready: node.ready, inference_ready: true, provider_signers: node.signers,
            scheduler: { session_affinity: true, total_slots: 1, outstanding_jobs: 0 }, chain_id: 31337,
            settlement_contract: "0x" + "11".repeat(20), relay_payment_address: "0x" + "44".repeat(20),
            relay_signer_address: "0x" + "55".repeat(20), channel_hash: "0x" + "66".repeat(32),
            pricing_version: 1, pricing_hash: "0x" + "77".repeat(32), maxOutputTokens: 64 } }));
          return;
        }
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const payment = JSON.parse(Buffer.from(request.headers["payment-signature"], "base64url").toString());
        verifyAuthorization(payment);
        calls.push({ relay: index, body, budget: Number(request.headers["x-mycomesh-request-timeout-ms"]), request_id: payment.authorization.request_id });
        if (node.mode === "slow-reject") await new Promise((r) => setTimeout(r, 70));
        if (["slow-reject", "unknown-error"].includes(node.mode)) {
          response.writeHead(503, { "content-type": "application/json" });
          response.end(JSON.stringify({ error: { message: "test unavailable", ...(node.mode === "slow-reject" ? { execution_status: "not_dispatched" } : {}) } }));
          return;
        }
        response.writeHead(200, { "content-type": "application/json" });
        if (node.mode === "slow-body") { response.flushHeaders(); response.write('{"id":'); return; }
        response.end(JSON.stringify({ id: "response-" + calls.length, object: "response", output: [], status: "completed" }));
      } catch {
        if (!response.headersSent) response.writeHead(500);
        response.end();
      }
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    servers.push(server);
    urls.push(`http://127.0.0.1:${server.address().port}`);
  }
  const networkConfig = join(directory, "fixture-network.json");
  await writeFile(networkConfig, JSON.stringify({ protocol_version: 8, chain_id: 31337,
    settlement: "0x" + "11".repeat(20), stablecoin: "0x" + "22".repeat(20) }));
  const state = new NativeConsumerState({ env: {}, networkConfig, dataDir: directory, historyDir: join(directory, "history"), relayUrls: urls.join(","), timeoutMs, healthTimeoutMs: 50 });
  t.after(async () => {
    await Promise.all(servers.map((server) => new Promise((r) => { server.close(r); server.closeAllConnections(); })));
    await rm(directory, { recursive: true, force: true });
  });
  const infer = (session) => state.relayInference("/v1/responses", { model: "gpt-5.5", input: "local fixture", max_output_tokens: 10 },
    session ? { "x-session-id": session } : {});
  return { state, nodes, urls, calls, infer };
}

test("native response body is covered by the original deadline and is never replayed", async (t) => {
  const { nodes, calls, state, infer } = await fixture(t);
  nodes[0].mode = "slow-body";
  const began = performance.now();
  const result = await infer();
  assert.equal(result.status, 502);
  assert.equal(calls.length, 1);
  assert.ok(performance.now() - began < 1000);
  assert.equal(state.activeInferenceRequests, 0);
  assert.equal([...state.relayInFlight.values()].reduce((a, b) => a + b, 0), 0);
});

test("retries share the remaining budget instead of restarting the request timeout", async (t) => {
  // Leave enough headroom for a busy CI host to complete the first 70 ms
  // response and still exercise the second route before the deadline.
  const { nodes, calls, state, urls, infer } = await fixture(t, 500);
  await Promise.all(urls.map((url) => state.relayHealth(url)));
  nodes[0].mode = "slow-reject";
  nodes[1].mode = "slow-body";
  const result = await infer();
  // Under host contention the final deadline can expire while selecting the
  // second route, which is surfaced as 504; both outcomes preserve the
  // single request identity and prove the retry budget was not restarted.
  assert.ok([502, 504].includes(result.status));
  assert.equal(calls.length, 2);
  assert.ok(calls[1].budget < calls[0].budget - 50);
  assert.equal(calls[0].request_id, calls[1].request_id);
});

test("a 503 without proof of non-dispatch does not trigger a second inference", async (t) => {
  const { nodes, calls, infer } = await fixture(t);
  nodes[0].mode = "unknown-error";
  assert.equal((await infer()).status, 503);
  assert.equal(calls.length, 1);
});

test("settlement-unready Relay is skipped even when HTTP health and Providers are healthy", async (t) => {
  const { nodes, calls, infer } = await fixture(t);
  nodes[0].ready = false;
  assert.equal((await infer()).status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].relay, 1);
});

test("failure cooldown skips the bad Relay across requests and permits a later probe", async (t) => {
  const { nodes, calls, state, urls, infer } = await fixture(t);
  nodes[0].mode = "unknown-error";
  assert.equal((await infer()).status, 503);
  assert.equal((await infer()).status, 200);
  assert.deepEqual(calls.map((r) => r.relay), [0, 1]);
  const healthCalls = nodes[0].healthCalls;
  await assert.rejects(state.relayHealth(urls[0]), /cooling down/);
  assert.equal(nodes[0].healthCalls, healthCalls);
  state.relayFailures.get(urls[0]).until = Date.now() - 1;
  nodes[0].mode = "ok";
  assert.equal((await state.relayHealth(urls[0])).ok, true);
  assert.ok(nodes[0].healthCalls > healthCalls);
});

test("an unreachable Relay cannot be selected from stale previously healthy data", async (t) => {
  const { nodes, state, urls } = await fixture(t, 1000);
  await state.relayHealth(urls[0]);
  nodes[0].mode = "dead-health";
  await assert.rejects(state.relayHealth(urls[0], true), /health is invalid/);
  assert.equal(state.healthCache.has(urls[0]), false);
});

test("selection deadline never leaks a reservation after late health completion", async (t) => {
  const { state, urls, calls, infer } = await fixture(t, 40);
  const health = await state.relayHealth(urls[0]);
  let resume;
  const held = new Promise((r) => { resume = r; });
  state.relayHealth = async () => { await held; return health; };
  const result = await infer("deadline-session");
  assert.equal(result.status, 504);
  resume();
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(calls.length, 0);
  assert.equal(state.sessionSelections.size, 0);
  assert.equal(state.sessionRoutes.size, 0);
  assert.equal([...state.relayReservations.values()].reduce((a, b) => a + b, 0), 0);
});

for (const matching of [false, true]) {
  test(`session recovery ${matching ? "uses only the same Provider on a new Relay" : "refuses an alternate account"}`, async (t) => {
    const { nodes, state, urls, calls, infer } = await fixture(t, 1000);
    nodes[0].ready = false;
    nodes[1].signers = [matching ? signer : "0x" + "cd".repeat(20)];
    state.history = () => [{ accepted: true, session_id: "restore", relay_url: urls[0], provider_signer: signer }];
    const result = await infer("restore");
    assert.equal(result.status, matching ? 200 : 503);
    assert.equal(calls.length, matching ? 1 : 0);
    if (matching) {
      assert.equal(calls[0].relay, 1);
      assert.equal(calls[0].body.metadata.mycomesh_provider_signer, signer);
      assert.equal(state.sessionRoutes.get("restore").providerSigner, signer);
    }
  });
}

test("receipt status uses a domain-separated payment-key proof, not a payable authorization", () => {
  const key = "myco_sk_" + Buffer.alloc(32, 1).toString("base64url");
  const query = createReceiptStatusQuery(key, { chainId: 11155111, contract: "0x" + "11".repeat(20), requestId: "0x" + "22".repeat(32), issuedAt: 1789456000 });
  const message = `MycoMesh receipt status v1\nchain_id:${query.chain_id}\nsettlement_contract:${query.settlement_contract}\nkey:${query.key}\nrequest_id:${query.request_id}\nissued_at:${query.issued_at}`;
  const raw = Buffer.from(query.signature.slice(2), "hex");
  const pub = secp256k1.Signature.fromCompact(raw.subarray(0, 64)).addRecoveryBit(raw[64] - 27).recoverPublicKey(walletMessageDigest(message)).toRawBytes(false);
  assert.equal("0x" + Buffer.from(keccak_256(pub.subarray(1)).slice(-20)).toString("hex"), query.key);
  assert.equal(query.max_fee, undefined);
  assert.equal(query.signature.length, 132);
});

test("receipt status message verifies the Python Relay signature vector", () => {
  const key = "myco_sk_" + Buffer.alloc(32, 0x11).toString("base64url");
  const query = createReceiptStatusQuery(key, { chainId: 11155111, contract: "0x" + "11".repeat(20), requestId: "0x" + "77".repeat(32), issuedAt: 1789458000 });
  assert.equal(query.key, "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a");
  const message = `MycoMesh receipt status v1\nchain_id:${query.chain_id}\nsettlement_contract:${query.settlement_contract}\nkey:${query.key}\nrequest_id:${query.request_id}\nissued_at:${query.issued_at}`;
  const raw = Buffer.from("347969adb7f109ada5007c38bc8b73414143c63d0b14a8f47732d1639041909975cc8d567ff76e18ef70253b2e7187b2b41a327353fb82f68216a0fdd3ccde301c", "hex");
  const pub = secp256k1.Signature.fromCompact(raw.subarray(0, 64)).addRecoveryBit(raw[64] - 27).recoverPublicKey(walletMessageDigest(message)).toRawBytes(false);
  assert.equal("0x" + Buffer.from(keccak_256(pub.subarray(1)).slice(-20)).toString("hex"), query.key);
});
