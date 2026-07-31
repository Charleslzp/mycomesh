import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import test from "node:test";

const cliPath = fileURLToPath(new URL("../bin/mycomesh.mjs", import.meta.url));

test("health accepts a root base URL and pretty-prints JSON", async () => {
  await withServer(
    (request, response) => {
      assert.equal(request.method, "GET");
      assert.equal(request.url, "/health");
      assert.equal(request.headers.authorization, undefined);
      json(response, 200, { ok: true, service: "mycomesh" });
    },
    async (baseUrl) => {
      const result = await invoke(["health", "--base-url", baseUrl]);
      assert.equal(result.code, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), {
        ok: true,
        service: "mycomesh",
      });
      assert.equal(result.stderr, "");
    },
  );
});

test("models accepts a /v1 base URL and sends the environment API key", async () => {
  await withServer(
    (request, response) => {
      assert.equal(request.url, "/v1/models");
      assert.equal(request.headers.authorization, "Bearer test-model-key");
      json(response, 200, { object: "list", data: [{ id: "myco-model" }] });
    },
    async (baseUrl) => {
      const result = await invoke(["models"], {
        env: {
          MYCOMESH_BASE_URL: `${baseUrl}/v1`,
          MYCOMESH_API_KEY: "test-model-key",
        },
      });
      assert.equal(result.code, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).data[0].id, "myco-model");
    },
  );
});

test("responses merges --json with explicit common options", async () => {
  await withServer(
    async (request, response) => {
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/v1/responses");
      assert.equal(request.headers["content-type"], "application/json");
      assert.equal(request.headers.authorization, "Bearer flag-key");
      const body = JSON.parse(await requestText(request));
      assert.deepEqual(body, {
        input: "new input",
        metadata: { source: "test" },
        model: "myco-model",
        max_output_tokens: 25,
      });
      json(response, 200, { id: "resp_123", object: "response" });
    },
    async (baseUrl) => {
      const result = await invoke([
        "responses",
        "--base-url",
        baseUrl,
        "--api-key",
        "flag-key",
        "--json",
        '{"input":"old input","metadata":{"source":"test"}}',
        "--input",
        "new input",
        "--model",
        "myco-model",
        "--max-output-tokens",
        "25",
      ]);
      assert.equal(result.code, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).id, "resp_123");
    },
  );
});

test("responses attaches an already-opened V5 Session id", async () => {
  const sessionId = `0x${"ab".repeat(32)}`;
  await withServer(
    async (request, response) => {
      assert.deepEqual(JSON.parse(await requestText(request)), {
        input: "session request",
        mycomesh_session: { session_id: sessionId },
      });
      json(response, 200, { ok: true });
    },
    async (baseUrl) => {
      const result = await invoke([
        "responses",
        "session request",
        "--base-url",
        baseUrl,
        "--session-id",
        sessionId.toUpperCase().replace("0X", "0x"),
      ]);
      assert.equal(result.code, 0, result.stderr);
    },
  );
});

test("inference accepts MYCOMESH_SESSION_ID and validates it", async () => {
  const sessionId = `0x${"12".repeat(32)}`;
  await withServer(
    async (request, response) => {
      const body = JSON.parse(await requestText(request));
      assert.deepEqual(body.mycomesh_session, { session_id: sessionId });
      json(response, 200, { ok: true });
    },
    async (baseUrl) => {
      const result = await invoke(["chat", "hello", "--base-url", baseUrl], {
        env: { MYCOMESH_SESSION_ID: sessionId },
      });
      assert.equal(result.code, 0, result.stderr);
    },
  );

  const invalid = await invoke([
    "responses",
    "hello",
    "--session-id",
    "0x1234",
  ]);
  assert.equal(invalid.code, 2);
  assert.match(invalid.stderr, /must be a 32-byte/);
});

test("responses reads a JSON object from piped stdin", async () => {
  await withServer(
    async (request, response) => {
      assert.deepEqual(JSON.parse(await requestText(request)), {
        model: "stdin-model",
        input: [{ role: "user", content: "from stdin" }],
      });
      json(response, 200, { ok: true });
    },
    async (baseUrl) => {
      const result = await invoke(["responses", "--base-url", baseUrl], {
        input: JSON.stringify({
          model: "stdin-model",
          input: [{ role: "user", content: "from stdin" }],
        }),
      });
      assert.equal(result.code, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).ok, true);
    },
  );
});

test("chat builds messages from common arguments", async () => {
  await withServer(
    async (request, response) => {
      assert.equal(request.url, "/v1/chat/completions");
      assert.deepEqual(JSON.parse(await requestText(request)), {
        model: "chat-model",
        messages: [
          { role: "system", content: "Be concise." },
          { role: "user", content: "hello world" },
        ],
        max_tokens: 42,
      });
      json(response, 200, { choices: [{ message: { content: "hello" } }] });
    },
    async (baseUrl) => {
      const result = await invoke([
        "chat",
        "hello",
        "world",
        "--base-url",
        baseUrl,
        "--model",
        "chat-model",
        "--system",
        "Be concise.",
        "--max-tokens",
        "42",
      ]);
      assert.equal(result.code, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).choices[0].message.content, "hello");
    },
  );
});

test("chat preserves SSE event framing on stdout", async () => {
  const expected =
    'data: {"type":"response.output_text.delta","delta":"hi"}\n\n' +
    "data: [DONE]\n\n";
  await withServer(
    async (request, response) => {
      const body = JSON.parse(await requestText(request));
      assert.equal(body.stream, true);
      assert.match(request.headers.accept, /text\/event-stream/);
      response.writeHead(200, { "content-type": "text/event-stream; charset=utf-8" });
      response.write(expected.slice(0, 24));
      setImmediate(() => response.end(expected.slice(24)));
    },
    async (baseUrl) => {
      const result = await invoke([
        "chat",
        "hello",
        "--base-url",
        baseUrl,
        "--model",
        "chat-model",
        "--stream",
      ]);
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.stdout, expected);
      assert.equal(result.stderr, "");
    },
  );
});

test("HTTP failures are nonzero and redact the API key", async () => {
  const apiKey = "sensitive-test-key";
  await withServer(
    (_request, response) => {
      json(response, 401, {
        error: `Authorization: Bearer ${apiKey}`,
        received_key: apiKey,
      });
    },
    async (baseUrl) => {
      const result = await invoke(["models", "--base-url", baseUrl], {
        env: { MYCOMESH_API_KEY: apiKey },
      });
      assert.equal(result.code, 1);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /HTTP 401 Unauthorized/);
      assert.match(result.stderr, /\[REDACTED\]/);
      assert.doesNotMatch(result.stderr, new RegExp(apiKey));
    },
  );
});

test("invalid stdin JSON fails before sending a request", async () => {
  const result = await invoke(["responses"], { input: "{not-json" });
  assert.equal(result.code, 2);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /invalid JSON from stdin/);
});

test("remote API keys require HTTPS unless cleartext is explicitly allowed", async () => {
  for (const baseUrl of [
    "http://gateway.example",
    "http://127.attacker.example",
  ]) {
    const rejected = await invoke([
      "models",
      "--base-url",
      baseUrl,
      "--api-key",
      "test-key",
    ]);
    assert.equal(rejected.code, 2);
    assert.match(rejected.stderr, /remote base URLs must use HTTPS/);
    assert.doesNotMatch(rejected.stderr, /test-key/);
  }

  let requestedUrl;
  const { main } = await import("../src/cli.mjs");
  const exitCode = await main(
    [
      "models",
      "--base-url",
      "http://gateway.example",
      "--allow-insecure-http",
    ],
    {
      env: {},
      stdin: { isTTY: true },
      stdout: { write() { return true; } },
      stderr: { write() { return true; } },
      fetch: async (url) => {
        requestedUrl = String(url);
        return new Response(JSON.stringify({ object: "list", data: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    },
  );
  assert.equal(exitCode, 0);
  assert.equal(requestedUrl, "http://gateway.example/v1/models");
});

test("request timeout is configurable and passed to fetch", async () => {
  let observedSignal;
  const { main } = await import("../src/cli.mjs");
  const exitCode = await main(
    ["health", "--timeout", "7"],
    {
      env: {},
      stdin: { isTTY: true },
      stdout: { write() { return true; } },
      stderr: { write() { return true; } },
      fetch: async (_url, options) => {
        observedSignal = options.signal;
        return new Response('{"ok":true}', {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    },
  );
  assert.equal(exitCode, 0);
  assert.ok(observedSignal instanceof AbortSignal);
  assert.equal(observedSignal.aborted, false);

  const invalid = await invoke(["health", "--timeout", "0"]);
  assert.equal(invalid.code, 2);
  assert.match(invalid.stderr, /--timeout must be a positive integer/);
});

test("successful JSON responses have a hard size limit", async () => {
  let stderr = "";
  const { main } = await import("../src/cli.mjs");
  const exitCode = await main(
    ["health"],
    {
      env: {},
      stdin: { isTTY: true },
      stdout: { write() { return true; } },
      stderr: { write(chunk) { stderr += chunk; return true; } },
      maxJsonResponseBytes: 8,
      fetch: async () => new Response('{"ok":true}', {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    },
  );
  assert.equal(exitCode, 1);
  assert.match(stderr, /JSON response exceeds 8 bytes/);
});

test("request deadline aborts a stalled response body", async () => {
  await withServer(
    (_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.write('{"ok":');
    },
    async (baseUrl) => {
      const result = await invoke([
        "health",
        "--base-url",
        baseUrl,
        "--timeout",
        "1",
      ]);
      assert.equal(result.code, 1);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /request timed out after 1 seconds/);
    },
  );
});

async function withServer(handler, callback) {
  const server = createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch((error) => {
      response.destroy(error);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    server.close();
    await once(server, "close");
  }
}

function invoke(args, { env: additions = {}, input = "" } = {}) {
  const env = { ...process.env, ...additions };
  if (!("MYCOMESH_BASE_URL" in additions)) {
    delete env.MYCOMESH_BASE_URL;
  }
  if (!("MYCOMESH_API_KEY" in additions)) {
    delete env.MYCOMESH_API_KEY;
  }
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
    child.stdin.end(input);
  });
}

async function requestText(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}
