import { ConsumerHistoryLedger } from "../src/consumer-history.mjs";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { NativeConsumerState, verifyAuthorization } from "../src/consumer-runtime.mjs";

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-routing-"));
  const calls = [];
  const modes = ["ok", "ok"];
  const servers = [];
  const urls = [];
  for (let index = 0; index < 2; index += 1) {
    const server = createServer(async (request, response) => {
      try {
        if (request.url === "/relay/health") {
          response.writeHead(200, { "content-type": "application/json" });
          response.end(JSON.stringify({ ok: true, v8: {
            enabled: true, providers: 1, model: "gpt-5.5", models: ["gpt-5.5"],
            scheduler: { session_affinity: true, total_slots: 1, outstanding_jobs: 0 },
            chain_id: 31337, settlement_contract: "0x" + "11".repeat(20),
            relay_payment_address: "0x" + (index === 0 ? "44" : "88").repeat(20),
            relay_signer_address: "0x" + "55".repeat(20), channel_hash: "0x" + "66".repeat(32),
            pricing_version: 1, pricing_hash: "0x" + "77".repeat(32), maxOutputTokens: 100,
          } }));
          return;
        }
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        const payment = JSON.parse(Buffer.from(request.headers["payment-signature"], "base64url").toString("utf8"));
        verifyAuthorization(payment); // Entirely local signature verification, no RPC.
        const id = `resp_${index}_${calls.length}`;
        calls.push({ relay: index, body, requestId: payment.authorization.request_id, id });
        if (modes[index] === "disconnect") { request.socket.destroy(); return; }
        if (modes[index] === "503") {
          response.writeHead(503, { "content-type": "application/json" });
          response.end(JSON.stringify({ error: { message: "mock relay unavailable", execution_status: "not_dispatched" } }));
          return;
        }
        response.writeHead(200, {
          "content-type": "application/json",
          ...(modes[index] === "bad-receipt" ? { "PAYMENT-RESPONSE": "invalid" } : {}),
        });
        if (modes[index] === "bad-json") { response.end("not json"); return; }
        response.end(JSON.stringify({ id, object: "response", status: "completed", model: "gpt-5.5", output_text: "mock", output: [] }));
      } catch {
        response.writeHead(500, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { message: "mock request rejected" } }));
      }
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    servers.push(server);
    urls.push(`http://127.0.0.1:${server.address().port}`);
  }
  const state = new NativeConsumerState({ env: {}, dataDir: directory, relayUrls: urls.join(","), healthTimeoutMs: 100, timeoutMs: 1000 });
  state.network = { ...state.network, chain_id: 31337, settlement_contract: "0x" + "11".repeat(20) };
  state.historyLedger = new ConsumerHistoryLedger({ localPath: state.historyPath, sharedDir: join(directory, "history"), chainId: state.network.chain_id, contract: state.network.settlement_contract, keyAddress: state.paymentAddress });
  t.after(async () => {
    await Promise.all(servers.map((server) => new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    })));
    await rm(directory, { recursive: true, force: true });
  });
  return { state, calls, modes, urls };
}

function infer(state, input = "same prompt", session, extra = {}) {
  return state.relayInference("/v1/responses", { model: "gpt-5.5", input, max_output_tokens: 20, ...extra },
    session ? { "x-mycomesh-session-id": session } : {});
}

function assertReleased(state) {
  assert.equal(state.sessionSelections.size, 0);
  assert.equal([...state.relayReservations.values()].reduce((a, b) => a + b, 0), 0);
  assert.equal([...state.relayInFlight.values()].reduce((a, b) => a + b, 0), 0);
  assert.equal([...state.sessionRoutes.values()].reduce((a, entry) => a + entry.inFlight, 0), 0);
  assert.equal(state.activeInferenceRequests, 0);
}

test("explicit sessions A/B spread across Relays while changed prompt A stays pinned", async (t) => {
  const { state, calls } = await fixture(t);
  assert.equal((await infer(state, "first", "A")).status, 200);
  assert.equal((await infer(state, "first", "B")).status, 200);
  assert.equal((await infer(state, "a completely different next prompt", "A")).status, 200);
  assert.notEqual(calls[0].relay, calls[1].relay);
  assert.equal(calls[0].relay, calls[2].relay);
  assert.equal(calls[2].body.metadata.mycomesh_session_id, "A");
  assert.equal(new Set(calls.map((call) => call.requestId)).size, 3);
  assertReleased(state);
});

test("concurrent first turns in one explicit session never fork its Relay binding", async (t) => {
  const { state, calls } = await fixture(t);
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => infer(state, `turn ${i}`, "shared")));
  assert.ok(results.every((result) => result.status === 200));
  assert.equal(calls.length, 8);
  assert.equal(new Set(calls.map((call) => call.relay)).size, 1);
  assert.equal(new Set(calls.map((call) => call.requestId)).size, 8);
  assertReleased(state);
});

test("concurrent identical prompts without explicit sessions spread independently", async (t) => {
  const { state, calls } = await fixture(t);
  const results = await Promise.all(Array.from({ length: 8 }, () => infer(state)));
  assert.ok(results.every((result) => result.status === 200));
  assert.equal(calls.filter((call) => call.relay === 0).length, 4);
  assert.equal(calls.filter((call) => call.relay === 1).length, 4);
  assert.equal(new Set(calls.map((call) => call.body.metadata.mycomesh_session_id)).size, 8);
  assertReleased(state);
});

test("unknown continuations fail locally without sending any Relay inference", async (t) => {
  const { state, calls } = await fixture(t);
  const response = await infer(state, "next", undefined, { previous_response_id: "unknown" });
  assert.equal(response.status, 409);
  assert.equal(calls.length, 0);
  assertReleased(state);
});

test("known previous_response_id uses its first Relay and a fresh payment request id", async (t) => {
  const { state, calls } = await fixture(t);
  const first = await infer(state);
  const next = await infer(state, "next", undefined, { previous_response_id: first.payload.id });
  assert.equal(next.status, 200);
  assert.equal(calls[0].relay, calls[1].relay);
  assert.equal(calls[0].body.metadata.mycomesh_session_id, calls[1].body.metadata.mycomesh_session_id);
  assert.notEqual(calls[0].requestId, calls[1].requestId);
  assertReleased(state);
});

test("a remembered continuation whose route is missing is not reassigned", async (t) => {
  const { state, calls } = await fixture(t);
  const first = await infer(state);
  state.sessionRoutes.clear();
  const next = await infer(state, "next", undefined, { previous_response_id: first.payload.id });
  assert.equal(next.status, 409);
  assert.equal(calls.length, 1);
  assertReleased(state);
});

test("conflicting shared history routes reject restoration instead of picking the newest account", async (t) => {
  const { state, calls, urls } = await fixture(t);
  state.history = () => urls.map((relay_url, index) => ({
    accepted: true, session_id: "conflict", relay_url,
    provider_signer: "0x" + (index ? "aa" : "bb").repeat(20),
  }));
  const result = await infer(state, "continue", "conflict");
  assert.equal(result.status, 409);
  assert.match(result.payload.error.message, /conflicting/);
  assert.equal(calls.length, 0);
  assert.equal(state.sessionRoutes.has("conflict"), false);
  assertReleased(state);
});

test("a failed bound Relay never migrates the session to the healthy alternate", async (t) => {
  const { state, calls, modes } = await fixture(t);
  assert.equal((await infer(state, "first", "bound")).status, 200);
  modes[calls[0].relay] = "503";
  assert.equal((await infer(state, "next", "bound")).status, 503);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].relay, calls[1].relay);
  assertReleased(state);
});

test("an initial independent request may fail over after an explicit rejection without changing payment request id", async (t) => {
  const { state, calls, modes } = await fixture(t);
  modes[0] = "503";
  const result = await infer(state);
  assert.equal(result.status, 200);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((call) => call.relay), [0, 1]);
  assert.equal(calls[0].requestId, calls[1].requestId);
  assertReleased(state);
});

for (const mode of ["bad-json", "bad-receipt"]) {
  test(`HTTP success followed by ${mode} must not execute again on a second Relay`, async (t) => {
    const { state, calls, modes } = await fixture(t);
    modes[0] = mode;
    const result = await infer(state);
    assert.ok(result.status >= 400);
    assert.equal(calls.length, 1);
    assertReleased(state);
  });
}

test("connection loss after POST leaves an unknown outcome and never replays inference", async (t) => {
  const { state, calls, modes } = await fixture(t);
  modes[0] = "disconnect";
  const result = await infer(state);
  assert.equal(result.status, 502);
  assert.equal(result.payload.error.type, "relay_outcome_unknown");
  assert.equal(calls.length, 1);
  assertReleased(state);
});

test("payment construction errors release all reserved and active counts", async (t) => {
  const { state, calls } = await fixture(t);
  state.buildRelayPayment = () => { throw new Error("mock invalid payment input"); };
  assert.ok((await infer(state, "first", "bound")).status >= 400);
  assert.equal(calls.length, 0);
  assertReleased(state);
});

test("active inference accounting covers pinned health waits before Relay execution", async (t) => {
  const { state } = await fixture(t);
  assert.equal((await infer(state, "first", "bound")).status, 200);
  const originalHealth = state.relayHealth.bind(state);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let began;
  const started = new Promise((resolve) => { began = resolve; });
  state.relayHealth = async (url) => { began(); await gate; return originalHealth(url); };
  const pending = infer(state, "next", "bound");
  await started;
  try {
    assert.equal(state.activeInferenceRequests, 1);
    assert.equal([...state.relayInFlight.values()].reduce((a, b) => a + b, 0), 0);
  } finally { release(); }
  assert.equal((await pending).status, 200);
  assertReleased(state);
});

test("capacity pressure evicts idle independent routes without blocking new work", async (t) => {
  const { state, calls, urls } = await fixture(t);
  const now = Date.now();
  for (let i = 0; i < 4096; i += 1) {
    state.sessionRoutes.set(`old-${i}`, { relayUrl: urls[0], lastUsed: now, inFlight: 0, explicit: false });
  }
  assert.equal((await infer(state)).status, 200);
  assert.equal(calls.length, 1);
  assert.ok(state.sessionRoutes.size <= 4096);
  assertReleased(state);
});

test("capacity pressure does not discard explicit session bindings", async (t) => {
  const { state, calls, urls } = await fixture(t);
  const now = Date.now();
  for (let i = 0; i < 4096; i += 1) {
    state.sessionRoutes.set(`explicit-${i}`, { relayUrl: urls[0], lastUsed: now, inFlight: 0, explicit: true });
  }
  assert.equal((await infer(state, "new", "cannot-fit")).status, 503);
  assert.equal(calls.length, 0);
  assert.equal(state.sessionRoutes.size, 4096);
  assertReleased(state);
});

for (const explicit of [false, true]) {
  test(`history route restoration respects capacity with ${explicit ? "explicit" : "independent"} existing routes`, async (t) => {
    const { state, calls, urls } = await fixture(t);
    const now = Date.now();
    for (let i = 0; i < 4096; i += 1) {
      state.sessionRoutes.set(`old-${i}`, { relayUrl: urls[0], lastUsed: now, inFlight: 0, explicit });
    }
    state.history = () => [{ accepted: true, session_id: "restore", relay_url: urls[1], provider_signer: "0x" + "99".repeat(20) }];
    const response = await infer(state, "restored turn", "restore");
    assert.equal(response.status, explicit ? 503 : 200);
    assert.equal(calls.length, explicit ? 0 : 1);
    assert.equal(state.sessionRoutes.size, 4096);
    assert.equal(state.sessionRoutes.has("restore"), !explicit);
    if (!explicit) {
      assert.equal(calls[0].relay, 1);
      assert.equal(calls[0].body.metadata.mycomesh_provider_signer, "0x" + "99".repeat(20));
    }
    assertReleased(state);
  });
}

test("a selected implicit route cannot be evicted before its await caller resumes", async (t) => {
  const { state, urls } = await fixture(t);
  const now = Date.now();
  for (let index = 0; index < 4095; index += 1) {
    state.sessionRoutes.set(`explicit-${index}`, { relayUrl: urls[0], lastUsed: now, inFlight: 0, explicit: true });
  }
  state.history = () => [];
  state.chooseRelay = async () => ({ relayUrl: urls[0], health: { v8: { scheduler: { session_affinity: true } } } });
  let firstRoute;
  let competing;
  const first = (async () => {
    await state.chooseSessionRelay({ id: "first-implicit", explicit: false, requiresOriginalRoute: false }, new Set(), "gpt-5.5");
    firstRoute = state.sessionRoutes.get("first-implicit");
    if (firstRoute) {
      firstRoute.inFlight += 1;
      firstRoute.dispatchPending = false;
    }
  })();
  // Selection inserts the route, then its finally releases sessionSelections.
  // This competing microtask runs before the first await caller takes ownership.
  queueMicrotask(() => queueMicrotask(() => {
    competing = state.chooseSessionRelay({ id: "competing-implicit", explicit: false, requiresOriginalRoute: false }, new Set(), "gpt-5.5")
      .then(() => null, (error) => error);
  }));
  await first;
  const refused = await competing;
  assert.ok(firstRoute, "a dispatch-pending route must survive capacity reclamation");
  assert.match(refused?.message || "", /capacity/);
  assert.equal(state.sessionRoutes.has("competing-implicit"), false);
  assert.equal(state.sessionRoutes.size, 4096);
  firstRoute.inFlight -= 1;
  assertReleased(state);
});

test("native concurrent inference at capacity retains the first route through POST and continuation", async (t) => {
  const { state, calls, urls } = await fixture(t);
  const health = await state.relayHealth(urls[0]);
  const now = Date.now();
  for (let index = 0; index < 4095; index += 1) {
    state.sessionRoutes.set(`explicit-${index}`, { relayUrl: urls[0], lastUsed: now, inFlight: 0, explicit: true });
  }
  state.chooseRelay = async () => ({ relayUrl: urls[0], health });
  let competing;
  const first = infer(state, "first implicit request");
  queueMicrotask(() => queueMicrotask(() => { competing = infer(state, "competing implicit request"); }));
  const firstResult = await first;
  const competingResult = await competing;
  assert.equal(firstResult.status, 200);
  assert.equal(competingResult.status, 503);
  assert.equal(calls.length, 1, "capacity rejection must not send an extra Relay inference");
  const id = firstResult.headers["x-mycomesh-session-id"];
  assert.ok(state.sessionRoutes.has(id));
  assert.equal(state.sessionRoutes.get(id).dispatchPending, false);
  assert.equal(state.sessionRoutes.size, 4096);
  assertReleased(state);
  const continuation = await infer(state, "next turn", undefined, { previous_response_id: firstResult.payload.id });
  assert.equal(continuation.status, 200);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].body.metadata.mycomesh_session_id, id);
  assert.equal(calls[1].relay, calls[0].relay);
  assertReleased(state);
});

test("native concurrent requests never exceed remaining route capacity or leak dispatch reservations", async (t) => {
  const { state, calls, urls } = await fixture(t);
  const now = Date.now();
  for (let index = 0; index < 4092; index += 1) {
    state.sessionRoutes.set(`explicit-${index}`, { relayUrl: urls[0], lastUsed: now, inFlight: 0, explicit: true });
  }
  const results = await Promise.all(Array.from({ length: 8 }, (_, index) => infer(state, `capacity request ${index}`)));
  assert.equal(results.filter((result) => result.status === 200).length, 4);
  assert.equal(results.filter((result) => result.status === 503).length, 4);
  assert.equal(calls.length, 4);
  assert.equal(state.sessionRoutes.size, 4096);
  for (const result of results.filter((item) => item.status === 200)) {
    const route = state.sessionRoutes.get(result.headers["x-mycomesh-session-id"]);
    assert.ok(route);
    assert.equal(route.dispatchPending, false);
  }
  assertReleased(state);
});

test("lost execution is durably tracked without prompt or payment secret", async (t) => {
  const { state, calls, modes } = await fixture(t);
  modes[0] = "disconnect";
  const result = await infer(state, "private fixture prompt");
  const rows = state.history(0);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].status, "outcome_unknown");
  assert.equal(rows[0].accepted, false);
  assert.equal(rows[0].request_id, calls[0].requestId);
  assert.equal(result.headers["x-mycomesh-request-id"], calls[0].requestId);
  assert.match(rows[0].request_hash, /^0x[0-9a-f]{64}$/);
  assert.equal(rows[0].max_fee_units, state.maxFeeUnits);
  assert.ok(!JSON.stringify(rows).includes("private fixture prompt"));
  assert.ok(!JSON.stringify(rows).includes(state.paymentKey));
  const reopened = new ConsumerHistoryLedger({ localPath: state.historyPath, sharedDir: state.historyLedger.sharedDir,
    chainId: state.network.chain_id, contract: state.network.settlement_contract, keyAddress: state.paymentAddress });
  assert.equal(reopened.history()[0].request_id, calls[0].requestId);
});

test("journal failure prevents dispatch instead of losing request identity", async (t) => {
  const { state, calls } = await fixture(t);
  state.historyLedger.append = () => { throw new Error("fixture disk full"); };
  const result = await infer(state);
  assert.equal(result.status, 503);
  assert.equal(result.payload.error.type, "request_tracking_unavailable");
  assert.equal(calls.length, 0);
  assertReleased(state);
});

test("catalog is a stable union of all ready same-network Relays", async (t) => {
  const { state, urls } = await fixture(t);
  const original = state.relayHealth.bind(state);
  state.relayHealth = async (url) => {
    const health = await original(url);
    return { ...health, v8: { ...health.v8, models: url === urls[0] ? ["gpt-5.5", "gpt-5.6-sol"] : ["gpt-5.5"] } };
  };
  const first = await state.modelCatalog(), second = await state.modelCatalog();
  assert.deepEqual(first, second);
  assert.deepEqual(first.map((model) => [model.id, model.route_count]), [["gpt-5.5", 2], ["gpt-5.6-sol", 1]]);
  assert.equal(first.find((model) => model.id === "gpt-5.5").redundancy, "redundant");
  assert.equal(first.find((model) => model.id === "gpt-5.6-sol").redundancy, "single_relay");
  assert.match(first.find((model) => model.id === "gpt-5.6-sol").route_warning, /failover unavailable/);
  state.relayHealth = async (url) => {
    if (url === urls[0]) throw new Error("fixture gas unavailable");
    return original(url);
  };
  assert.deepEqual((await state.modelCatalog()).map((model) => model.id), ["gpt-5.5"]);
});

test("deadline exhausted by journal persistence is marked not dispatched", async (t) => {
  const { state, calls } = await fixture(t);
  state.timeoutMs = 60;
  const append = state.historyLedger.append.bind(state.historyLedger);
  let first = true;
  state.historyLedger.append = (entry) => {
    append(entry);
    if (first) { first = false; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 80); }
  };
  const result = await infer(state);
  assert.equal(result.status, 504);
  assert.equal(calls.length, 0);
  assert.equal(state.history()[0].status, "not_dispatched");
  assertReleased(state);
});
