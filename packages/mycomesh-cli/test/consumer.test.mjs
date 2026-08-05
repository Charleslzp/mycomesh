import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { tmpdir } from "node:os";
import { Script } from "node:vm";
import { join } from "node:path";
import test from "node:test";

import {
  CONSUMER_HELP,
  CONSUMER_RELEASE_VERSION,
  isApiInvocation,
  main,
  parseArguments,
} from "../src/consumer.mjs";
import {
  NativeConsumerState,
  buildAuthorization,
  chatCompletionSse,
  createConsumerServer,
  derivePromptCacheKey,
  inferenceRequestHash,
  paymentKeyAddress,
  verifyAuthorization,
} from "../src/consumer-runtime.mjs";

function capture() {
  let value = "";
  return { stream: { write(chunk) { value += String(chunk); } }, value: () => value };
}

test("native launcher defaults do not mention or require Docker", () => {
  const parsed = parseArguments([], { HOME: "/tmp" });
  assert.equal(parsed.host, "127.0.0.1");
  assert.equal(parsed.port, 8110);
  assert.equal(parsed.baseUrl, "http://127.0.0.1:8110/v1");
  assert.equal(parsed.noCodex, true);
  assert.equal(parsed.dataDir, "/tmp/.mycomesh/consumer");
  assert.equal(isApiInvocation([]), false);
  assert.equal(isApiInvocation(["health"]), true);
  assert.equal(isApiInvocation(["responses", "hello"]), true);
  assert.match(CONSUMER_HELP, /without Docker/);
  assert.doesNotMatch(CONSUMER_HELP, /Compose|container image|Docker Desktop/);
});

test("launcher options select local data, relay failover, and port", () => {
  const parsed = parseArguments([
    "--data-dir", "/tmp/myco-consumer",
    "--relay", "https://relay-a.example,https://relay-b.example",
    "--host", "127.0.0.1",
    "--port", "9123",
    "--ready-timeout", "60",
    "--max-fee", "200000",
    "--no-browser",
    "--no-codex",
  ], {});
  assert.deepEqual(parsed.relayUrls, "https://relay-a.example,https://relay-b.example");
  assert.equal(parsed.port, 9123);
  assert.equal(parsed.readyTimeout, 60);
  assert.equal(parsed.maxFeeUnits, 200000);
  assert.equal(parsed.noCodex, true);
  assert.equal(parsed.noBrowser, true);
});

test("Codex is opt-in and a custom port updates the default API URL", () => {
  const parsed = parseArguments(["--codex", "--port", "9123"], { HOME: "/tmp" });
  assert.equal(parsed.noCodex, false);
  assert.equal(parsed.baseUrl, "http://127.0.0.1:9123/v1");
});

test("help and version do not start a runtime", async () => {
  for (const [args, expected] of [
    [["--help"], /without Docker/],
    [["--version"], new RegExp(CONSUMER_RELEASE_VERSION.replaceAll(".", "\\."))],
  ]) {
    const stdout = capture();
    let started = false;
    const code = await main(args, {
      env: {},
      stdout: stdout.stream,
      spawn() { started = true; throw new Error("must not spawn"); },
    });
    assert.equal(code, 0);
    assert.equal(started, false);
    assert.match(stdout.value(), expected);
  }
});

test("native state persists a payment key and emits only the local export", async () => {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-"));
  try {
    const first = new NativeConsumerState({ dataDir: directory, relayUrls: "https://relay.example" });
    const second = new NativeConsumerState({ dataDir: directory, relayUrls: "https://relay.example" });
    assert.equal(second.paymentKey, first.paymentKey);
    assert.equal(second.paymentAddress, paymentKeyAddress(first.paymentKey));
    assert.match(first.credentialsText(), /^export OPENAI_BASE_URL='http:\/\/127\.0\.0\.1:8110\/v1'\nexport OPENAI_API_KEY='myco_sk_/);
    assert.doesNotMatch(first.credentialsText().toLowerCase(), /session/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("consumer dashboard inline script remains valid JavaScript", async () => {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-ui-"));
  const state = new NativeConsumerState({ dataDir: directory, relayUrls: "https://relay.example" });
  const edge = createConsumerServer(state, { port: 0 });
  await edge.listen();
  try {
    const address = edge.server.address();
    const html = await (await fetch(`http://127.0.0.1:${address.port}/`)).text();
    const start = html.indexOf("<script>") + "<script>".length;
    const end = html.indexOf("</script>");
    assert.doesNotThrow(() => new Script(html.slice(start, end)));
  } finally {
    await edge.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Node V8 authorization verifies with its own recovery path", () => {
  const paymentKey = "myco_sk_" + Buffer.alloc(32, 7).toString("base64url");
  const payment = buildAuthorization({
    paymentKey,
    chainId: 31337,
    settlementContract: "0x" + "11".repeat(20),
    requestId: "0x" + "22".repeat(32),
    requestHash: "0x" + "33".repeat(32),
    relay: "0x" + "44".repeat(20),
    relaySigner: "0x" + "55".repeat(20),
    channelHash: "0x" + "66".repeat(32),
    pricingVersion: 1,
    pricingHash: "0x" + "77".repeat(32),
    maxFee: 100000,
    issuedAt: Math.floor(Date.now() / 1000) - 300,
    deadline: Math.floor(Date.now() / 1000) + 900,
  });
  const verified = verifyAuthorization(payment);
  assert.equal(verified.authorization.key, paymentKeyAddress(paymentKey));
  assert.equal(verified.authorization.request_id, payment.authorization.request_id);
});

test("inference request hashing is deterministic and excludes transport metadata", () => {
  const first = inferenceRequestHash({ endpoint: "responses", model: "m", input: "hello", maxOutputTokens: 20, options: { stream: true, temperature: 0.2 } });
  const second = inferenceRequestHash({ endpoint: "responses", model: "m", input: "hello", maxOutputTokens: 20, options: { temperature: 0.2, stream: false } });
  assert.equal(first, second);
  assert.match(first, /^0x[0-9a-f]{64}$/);
  const chat = { endpoint: "chat", model: "m", messages: [{ role: "user", content: "hello" }], maxOutputTokens: 20 };
  assert.equal(inferenceRequestHash(chat), inferenceRequestHash({ ...chat, options: { stream: false } }));
  assert.notEqual(inferenceRequestHash(chat), inferenceRequestHash({ ...chat, options: { temperature: 0.2 } }));
});

test("prompt cache key stays stable when only later turns change", () => {
  const first = {
    endpoint: "chat",
    model: "gpt-test",
    messages: [
      { role: "system", content: "be concise" },
      { role: "user", content: "start" },
    ],
  };
  const later = {
    ...first,
    messages: [...first.messages, { role: "assistant", content: "ready" }, { role: "user", content: "continue" }],
  };
  assert.equal(derivePromptCacheKey(first), derivePromptCacheKey(later));
  assert.notEqual(derivePromptCacheKey(first), derivePromptCacheKey({ ...first, messages: [{ role: "user", content: "other" }] }));
});

test("native HTTP edge selects a live Relay and sends a V8 payment header", async () => {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-http-"));
  let healthRequests = 0;
  const relay = createServer(async (request, response) => {
    if (request.url === "/relay/health") {
      healthRequests += 1;
      if (healthRequests > 1) {
        response.writeHead(502, { "content-type": "application/json" });
        response.end(JSON.stringify({ ok: false }));
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, v8: { enabled: true, providers: 1, model: "test-model", chain_id: 31337, settlement_contract: "0x" + "11".repeat(20), relay_payment_address: "0x" + "44".repeat(20), relay_signer_address: "0x" + "55".repeat(20), channel_hash: "0x" + "66".repeat(32), pricing_version: 1, pricing_hash: "0x" + "77".repeat(32), maxOutputTokens: 100 } }));
      return;
    }
    assert.equal(request.url, "/v1/responses");
    assert.ok(request.headers["payment-signature"]);
    const payment = JSON.parse(Buffer.from(request.headers["payment-signature"], "base64url").toString("utf8"));
    assert.equal(payment.schema, "mycomesh.x402.myco-credit-v2");
    verifyAuthorization(payment);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ id: "resp_test", object: "response", status: "completed", model: "test-model", output_text: "ok", output: [] }));
  });
  await new Promise((resolve) => relay.listen(0, "127.0.0.1", resolve));
  const address = relay.address();
  const state = new NativeConsumerState({ dataDir: directory, relayUrls: `http://127.0.0.1:${address.port}` });
  const edge = createConsumerServer(state, { port: 0 });
  await edge.listen();
  const edgeAddress = edge.server.address();
  try {
    const response = await fetch(`http://127.0.0.1:${edgeAddress.port}/v1/responses`, { method: "POST", headers: { authorization: `Bearer ${state.paymentKey}`, "content-type": "application/json" }, body: JSON.stringify({ input: "hello", max_output_tokens: 20 }) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).output_text, "ok");
    assert.equal((await state.relayHealth(`http://127.0.0.1:${address.port}`, true)).v8.model, "test-model");
    assert.equal(healthRequests, 3);
  } finally {
    await edge.close();
    await new Promise((resolve) => relay.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test("Relay health retries a transient failure before selecting the Relay", async () => {
  const relay = createServer((_request, response) => {
    relay.healthRequests += 1;
    if (relay.healthRequests === 1) {
      response.writeHead(503, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: false }));
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true, v8: { enabled: true, providers: 1, model: "test-model" } }));
  });
  relay.healthRequests = 0;
  await new Promise((resolve) => relay.listen(0, "127.0.0.1", resolve));
  const address = relay.address();
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-health-"));
  const state = new NativeConsumerState({ dataDir: directory, relayUrls: `http://127.0.0.1:${address.port}`, healthTimeoutMs: 100 });
  try {
    const selected = await state.chooseRelay();
    assert.equal(selected.health.v8.model, "test-model");
    assert.equal(relay.healthRequests, 2);
  } finally {
    await new Promise((resolve) => relay.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test("Consumer restores the requested model and tool argument schema order", async () => {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-semantics-"));
  let relayModel;
  let relayBody;
  const relay = createServer(async (request, response) => {
    if (request.url === "/relay/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, v8: { enabled: true, providers: 1, model: "settlement-model", chain_id: 31337, settlement_contract: "0x" + "11".repeat(20), relay_payment_address: "0x" + "44".repeat(20), relay_signer_address: "0x" + "55".repeat(20), channel_hash: "0x" + "66".repeat(32), pricing_version: 1, pricing_hash: "0x" + "77".repeat(32) } }));
      return;
    }
    const requestBody = JSON.parse(await new Promise((resolve) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    }));
    relayModel = requestBody.model;
    relayBody = requestBody;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      id: "chatcmpl_test",
      object: "chat.completion",
      model: "settlement-model",
      choices: [{ index: 0, finish_reason: "tool_calls", message: { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "submit_validation_record", arguments: '{"context":{"nonce":"n","sequence":1},"flags":{"ascending":true},"payload":{"checksum":9,"values":[3,6]}}' } }] } }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }));
  });
  await new Promise((resolve) => relay.listen(0, "127.0.0.1", resolve));
  const address = relay.address();
  const state = new NativeConsumerState({ dataDir: directory, relayUrls: `http://127.0.0.1:${address.port}` });
  try {
    const result = await state.relayInference("/v1/chat/completions", {
      model: "gpt-5.5",
      messages: [{ role: "user", content: "call the tool" }],
      max_tokens: 100,
      tool_choice: "required",
      tools: [{ type: "function", function: { name: "submit_validation_record", parameters: { type: "object", properties: {
        context: { type: "object", properties: { nonce: { type: "string" }, sequence: { type: "integer" } } },
        payload: { type: "object", properties: { values: { type: "array", items: { type: "integer" } }, checksum: { type: "integer" } } },
        flags: { type: "object", properties: { ascending: { type: "boolean" } } },
      } } } }],
    });
    assert.equal(relayModel, "settlement-model");
    assert.match(relayBody.prompt_cache_key, /^myco_csp_[0-9a-f]{64}$/);
    assert.equal(result.payload.model, "gpt-5.5");
    const argumentsText = result.payload.choices[0].message.tool_calls[0].function.arguments;
    assert.equal(argumentsText, '{"context":{"nonce":"n","sequence":1},"payload":{"values":[3,6],"checksum":9},"flags":{"ascending":true}}');
  } finally {
    await new Promise((resolve) => relay.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test("Chat streaming preserves function tool calls", () => {
  const chunks = chatCompletionSse({
    id: "chatcmpl_test",
    model: "gpt-5.5",
    choices: [{ index: 0, finish_reason: "tool_calls", message: {
      role: "assistant",
      content: null,
      tool_calls: [{ id: "call_1", type: "function", function: { name: "submit_validation_record", arguments: '{"value":42}' } }],
    } }],
  });
  const events = chunks
    .filter((chunk) => chunk.startsWith("data: {") && !chunk.includes('"finish_reason":"tool_calls"'))
    .map((chunk) => JSON.parse(chunk.slice(6)));
  assert.deepEqual(events[1].choices[0].delta.tool_calls, [{
    index: 0,
    id: "call_1",
    type: "function",
    function: { name: "submit_validation_record", arguments: '{"value":42}' },
  }]);
});

test("temporary share exposes only the inference surface and revokes in memory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-share-"));
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.exitCode = null;
  let killed = false;
  let spawnCount = 0;
  const failedChild = new EventEmitter();
  failedChild.stdout = new PassThrough();
  failedChild.stderr = new PassThrough();
  failedChild.exitCode = null;
  failedChild.signalCode = null;
  let failedChildKilled = false;
  failedChild.kill = () => {
    failedChildKilled = true;
    failedChild.signalCode = "SIGTERM";
    queueMicrotask(() => failedChild.emit("exit", null, "SIGTERM"));
    return true;
  };
  child.kill = () => { killed = true; setTimeout(() => { child.exitCode = 0; child.emit("exit", 0); }, 25); return true; };
  let tunnelArgs;
  const state = new NativeConsumerState({
    dataDir: directory,
    relayUrls: "https://relay.example",
    tunnelSpawn(_command, args) {
      spawnCount += 1;
      tunnelArgs = args;
      if (spawnCount === 1) {
        queueMicrotask(() => failedChild.emit("error", new Error("context deadline exceeded")));
        return failedChild;
      }
      queueMicrotask(() => child.stderr.write("Tunnel ready at https://unit-test.trycloudflare.com\nRegistered tunnel connection"));
      return child;
    },
  });
  state.chooseRelay = async () => ({ relayUrl: "https://relay.example", health: { v8: { model: "test-model" } } });
  let relayPath;
  state.relayInference = async (path) => {
    relayPath = path;
    return { status: 200, payload: { id: "chatcmpl_test", choices: [] }, headers: {} };
  };
  try {
    const share = await state.startShare(10);
    const address = state.share.runtime.server.address();
    const publicUrl = `http://127.0.0.1:${address.port}`;
    assert.equal(spawnCount, 2);
    assert.equal(failedChildKilled, true);
    assert.equal(share.base_url, "https://unit-test.trycloudflare.com/v1");
    assert.match(share.api_key, /^myco_share_[A-Za-z0-9_-]+$/);
    assert.deepEqual(tunnelArgs.slice(0, 5), ["tunnel", "--no-autoupdate", "--protocol", "http2", "--url"]);
    assert.match(tunnelArgs.at(-1), /^http:\/\/127\.0\.0\.1:\d+$/);

    const coreKey = await fetch(`${publicUrl}/v1/models`, { headers: { authorization: `Bearer ${state.paymentKey}` } });
    assert.equal(coreKey.status, 401);
    const health = await fetch(`${publicUrl}/v1/health`, { headers: { authorization: `Bearer ${share.api_key}` } });
    assert.equal(health.status, 200);
    const models = await fetch(`${publicUrl}/v1/models`, { headers: { authorization: `Bearer ${share.api_key}` } });
    assert.equal(models.status, 200);
    assert.equal((await models.json()).data[0].id, "test-model");
    const chat = await fetch(`${publicUrl}/v1/v1/chat/completions`, { method: "POST", headers: { authorization: `Bearer ${share.api_key}`, "content-type": "application/json" }, body: "{}" });
    assert.equal(chat.status, 200);
    assert.equal(relayPath, "/v1/chat/completions");
    const dashboard = await fetch(`${publicUrl}/v1/mycomesh/local/dashboard`, { headers: { authorization: `Bearer ${share.api_key}` } });
    assert.equal(dashboard.status, 404);

    await state.stopShare();
    assert.equal(state.authorizeBearer(`Bearer ${share.api_key}`, { shareOnly: true }), false);
    assert.equal(killed, true);
    assert.equal(child.exitCode, 0);
  } finally {
    await state.stopShare();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Codex alpha/search is carried statelessly to the Provider and restored", async () => {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-search-"));
  let relayBody;
  const relay = createServer(async (request, response) => {
    if (request.url === "/relay/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, v8: { enabled: true, providers: 1, web_search_providers: 1, model: "test-model", chain_id: 31337, settlement_contract: "0x" + "11".repeat(20), relay_payment_address: "0x" + "44".repeat(20), relay_signer_address: "0x" + "55".repeat(20), channel_hash: "0x" + "66".repeat(32), pricing_version: 1, pricing_hash: "0x" + "77".repeat(32) } }));
      return;
    }
    assert.equal(request.url, "/v1/responses");
    relayBody = await new Promise((resolve, reject) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))));
      request.on("error", reject);
    });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      object: "response",
      status: "completed",
      output_text: "metered search",
      output: [],
      usage: { input_tokens: 8, output_tokens: 4, total_tokens: 12 },
      mycomesh_alpha_search_response: { output: "BTC is current", results: [{ type: "text_result", ref_id: "turn0search0", url: "https://example.com/btc", title: "BTC" }] },
    }));
  });
  await new Promise((resolve) => relay.listen(0, "127.0.0.1", resolve));
  const address = relay.address();
  const state = new NativeConsumerState({ dataDir: directory, relayUrls: `http://127.0.0.1:${address.port}` });
  const edge = createConsumerServer(state, { port: 0 });
  await edge.listen();
  const edgeAddress = edge.server.address();
  try {
    const response = await fetch(`http://127.0.0.1:${edgeAddress.port}/backend-api/codex/alpha/search?feature=standalone`, {
      method: "POST",
      headers: { authorization: `Bearer ${state.paymentKey}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-5.5", commands: { search_query: [{ q: "BTC price" }] } }),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { output: "BTC is current", results: [{ type: "text_result", ref_id: "turn0search0", url: "https://example.com/btc", title: "BTC" }] });
    assert.equal(relayBody.model, "test-model");
    assert.equal(relayBody.input[0].type, "mycomesh_alpha_search_request");
    assert.equal(relayBody.input[0].request.commands.search_query[0].q, "BTC price");
    assert.deepEqual(relayBody.input[0].query, { feature: "standalone" });
  } finally {
    await edge.close();
    await new Promise((resolve) => relay.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Relay scheduling preserves the request id across failover", async () => {
  const directory = await mkdtemp(join(tmpdir(), "myco-consumer-failover-"));
  const requestIds = [];
  const relay = createServer(async (request, response) => {
    const healthy = request.url.startsWith("/b/") || request.url === "/b/health";
    if (request.url.endsWith("/health")) {
      response.writeHead(healthy ? 200 : 503, { "content-type": "application/json" });
      response.end(JSON.stringify(healthy ? { ok: true, v8: { enabled: true, providers: 1, model: "test-model", chain_id: 31337, settlement_contract: "0x" + "11".repeat(20), relay_payment_address: "0x" + "44".repeat(20), relay_signer_address: "0x" + "55".repeat(20), channel_hash: "0x" + "66".repeat(32), pricing_version: 1, pricing_hash: "0x" + "77".repeat(32) } } : { ok: false }));
      return;
    }
    if (!healthy) {
      response.writeHead(503, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { message: "temporary relay failure" } }));
      return;
    }
    const payment = JSON.parse(Buffer.from(request.headers["payment-signature"], "base64url").toString("utf8"));
    requestIds.push(payment.authorization.request_id);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ id: "resp_failover", object: "response", status: "completed", output: [] }));
  });
  await new Promise((resolve) => relay.listen(0, "127.0.0.1", resolve));
  const address = relay.address();
  const state = new NativeConsumerState({ dataDir: directory, relayUrls: `http://127.0.0.1:${address.port}/a,http://127.0.0.1:${address.port}/b` });
  const result = await state.relayInference("/v1/responses", { input: "hello", max_output_tokens: 10 });
  assert.equal(result.status, 200);
  assert.equal(requestIds.length, 1);
  assert.match(requestIds[0], /^0x[0-9a-f]{64}$/);
  await new Promise((resolve) => relay.close(resolve));
  await rm(directory, { recursive: true, force: true });
});

test("package release metadata matches the native runtime", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const packageText = await readFile(new URL("../package.json", import.meta.url), "utf8");
  const runtime = await readFile(new URL("../src/consumer-runtime.mjs", import.meta.url), "utf8");
  assert.equal(CONSUMER_RELEASE_VERSION, packageJson.version);
  assert.equal(packageJson.dependencies["@noble/curves"], "1.9.1");
  assert.equal(packageJson.dependencies["@noble/hashes"], "1.8.0");
  assert.equal(packageJson.dependencies["@openai/codex"], undefined);
  assert.match(packageText, /"src\/consumer-runtime\.mjs"/);
  assert.doesNotMatch(runtime, /docker compose|Docker Desktop|ghcr\.io/i);
});
