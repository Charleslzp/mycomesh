import { once } from "node:events";
import { readFile } from "node:fs/promises";

const CLI_VERSION = "0.1.0";
// The npm client is local-first. A public Gateway is an explicit override;
// the default remains the loopback Consumer edge so a blocked domain cannot
// strand the Codex client.
const DEFAULT_BASE_URL = "http://127.0.0.1:8110/v1";
const DEFAULT_TIMEOUT_SECONDS = 300;
const MAX_TIMEOUT_SECONDS = 3600;
const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MAX_ERROR_BYTES = 64 * 1024;
const MAX_JSON_RESPONSE_BYTES = 32 * 1024 * 1024;
const COMMANDS = new Set(["health", "models", "responses", "chat"]);

const HELP = `Usage: mycomesh <command> [options] [input]

Consumer commands:
  health                 Check gateway health
  models                 List available models
  responses [input]      Create a Responses API request
  chat [message]         Create a Chat Completions API request

Connection options:
  --base-url <url>        Consumer root or /v1 URL (default: local loopback)
                         (env: MYCOMESH_BASE_URL)
  --api-key <key>         Bearer API key (env: MYCOMESH_API_KEY)
  --timeout <seconds>     Request deadline, up to 3600 seconds
                         (env: MYCOMESH_TIMEOUT_SECONDS; default: 300)
  --allow-insecure-http   Allow cleartext HTTP to a non-loopback test gateway

Session options:
  --session-id <bytes32>  Use an already-opened V5 Session
                         (env: MYCOMESH_SESSION_ID)

Request body options:
  --json <json|@file|->   JSON object, JSON file, or JSON from stdin
  --model <model>         Set the request model
  --stream                Request an SSE response
  --no-stream             Disable streaming from a JSON base body

Responses options:
  --input <text>          Set the Responses API input
  --max-output-tokens <n> Set max_output_tokens

Chat options:
  --message <text>        Set the user message
  --system <text>         Prepend a system message
  --max-tokens <n>        Set max_tokens
  --max-completion-tokens <n>
                         Set max_completion_tokens

Other options:
  -h, --help              Show this help
  -v, --version           Show the CLI version

When --json is omitted, piped stdin is read as a JSON request object. Explicit
request options override fields loaded from JSON.`;

class CliError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.name = "CliError";
    this.exitCode = exitCode;
  }
}

class HttpError extends CliError {
  constructor(status, statusText, body) {
    const label = [status, statusText].filter(Boolean).join(" ");
    super(`HTTP ${label}${body ? `\n${body}` : ""}`);
    this.name = "HttpError";
  }
}

export async function main(argv, dependencies = {}) {
  const env = dependencies.env ?? process.env;
  const stdin = dependencies.stdin ?? process.stdin;
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  const fetchImpl = dependencies.fetch ?? globalThis.fetch;
  const maxJsonResponseBytes =
    dependencies.maxJsonResponseBytes ?? MAX_JSON_RESPONSE_BYTES;
  let apiKey = env.MYCOMESH_API_KEY || "";
  let requestTimeout;

  try {
    const parsed = parseArguments(argv, env);
    apiKey = parsed.apiKey;

    if (parsed.help) {
      stdout.write(`${HELP}\n`);
      return 0;
    }
    if (parsed.version) {
      stdout.write(`${CLI_VERSION}\n`);
      return 0;
    }
    if (typeof fetchImpl !== "function") {
      throw new CliError("Node.js 20 or newer is required");
    }

    const request = await buildRequest(parsed, stdin);
    requestTimeout = createRequestTimeout(parsed.timeoutSeconds);
    const response = await sendRequest(
      request,
      fetchImpl,
      requestTimeout.signal,
      parsed.timeoutSeconds,
    );
    if (!response.ok) {
      const errorBody = await readLimitedText(response.body, MAX_ERROR_BYTES);
      throw new HttpError(response.status, response.statusText, errorBody.trim());
    }

    await writeResponse(response, stdout, maxJsonResponseBytes);
    return 0;
  } catch (error) {
    const exitCode = error instanceof CliError ? error.exitCode : 1;
    const message = requestTimeout?.signal.aborted
      ? `request timed out after ${requestTimeout.timeoutSeconds} seconds`
      : error instanceof Error
        ? error.message
        : String(error);
    stderr.write(`mycomesh: ${redact(message, apiKey)}\n`);
    return exitCode;
  } finally {
    requestTimeout?.cancel();
  }
}

export function parseArguments(argv, env = process.env) {
  const parsed = {
    command: undefined,
    baseUrl: env.MYCOMESH_BASE_URL || DEFAULT_BASE_URL,
    apiKey: env.MYCOMESH_API_KEY || "",
    timeoutSeconds: requestTimeoutSeconds(
      env.MYCOMESH_TIMEOUT_SECONDS || String(DEFAULT_TIMEOUT_SECONDS),
      "MYCOMESH_TIMEOUT_SECONDS",
    ),
    allowInsecureHttp: false,
    sessionId: env.MYCOMESH_SESSION_ID || "",
    sessionIdExplicit: false,
    jsonSource: undefined,
    model: undefined,
    input: undefined,
    message: undefined,
    system: undefined,
    stream: undefined,
    maxOutputTokens: undefined,
    maxTokens: undefined,
    maxCompletionTokens: undefined,
    positionals: [],
    help: false,
    version: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") {
      parsed.positionals.push(...argv.slice(index + 1));
      break;
    }
    if (token === "-h" || token === "--help") {
      parsed.help = true;
      continue;
    }
    if (token === "-v" || token === "--version") {
      parsed.version = true;
      continue;
    }
    if (token === "--stream") {
      parsed.stream = true;
      continue;
    }
    if (token === "--no-stream") {
      parsed.stream = false;
      continue;
    }
    if (token === "--allow-insecure-http") {
      parsed.allowInsecureHttp = true;
      continue;
    }
    if (token.startsWith("--")) {
      const separator = token.indexOf("=");
      const name = separator === -1 ? token : token.slice(0, separator);
      let value = separator === -1 ? undefined : token.slice(separator + 1);
      if (value === undefined) {
        index += 1;
        value = argv[index];
      }
      if (value === undefined) {
        throw new CliError(`${name} requires a value`, 2);
      }
      switch (name) {
        case "--base-url":
          parsed.baseUrl = value;
          break;
        case "--api-key":
          parsed.apiKey = value;
          break;
        case "--timeout":
          parsed.timeoutSeconds = requestTimeoutSeconds(value, name);
          break;
        case "--session-id":
          parsed.sessionId = value;
          parsed.sessionIdExplicit = true;
          break;
        case "--json":
          parsed.jsonSource = value;
          break;
        case "--model":
          parsed.model = value;
          break;
        case "--input":
          parsed.input = value;
          break;
        case "--message":
          parsed.message = value;
          break;
        case "--system":
          parsed.system = value;
          break;
        case "--max-output-tokens":
          parsed.maxOutputTokens = positiveInteger(value, name);
          break;
        case "--max-tokens":
          parsed.maxTokens = positiveInteger(value, name);
          break;
        case "--max-completion-tokens":
          parsed.maxCompletionTokens = positiveInteger(value, name);
          break;
        default:
          throw new CliError(`unknown option: ${name}`, 2);
      }
      continue;
    }
    if (token.startsWith("-") && token !== "-") {
      throw new CliError(`unknown option: ${token}`, 2);
    }
    if (parsed.command === undefined) {
      parsed.command = token;
    } else {
      parsed.positionals.push(token);
    }
  }

  if (!parsed.command && !parsed.help && !parsed.version) {
    throw new CliError("a command is required; run mycomesh --help", 2);
  }
  if (parsed.command && !COMMANDS.has(parsed.command)) {
    throw new CliError(`unknown command: ${parsed.command}`, 2);
  }
  if (
    parsed.sessionId &&
    (parsed.command === "responses" || parsed.command === "chat")
  ) {
    parsed.sessionId = sessionId(parsed.sessionId, "--session-id");
  }
  validateCommandOptions(parsed);
  return parsed;
}

async function buildRequest(parsed, stdin) {
  const url = endpointUrl(
    parsed.baseUrl,
    parsed.command,
    parsed.allowInsecureHttp,
  );
  const headers = {
    accept: "application/json",
    "user-agent": `mycomesh-cli/${CLI_VERSION}`,
  };
  if (parsed.apiKey) {
    headers.authorization = `Bearer ${parsed.apiKey}`;
  }

  if (parsed.command === "health" || parsed.command === "models") {
    return { url, method: "GET", headers };
  }

  const body = await requestBody(parsed, stdin);
  headers["content-type"] = "application/json";
  if (body.stream === true) {
    headers.accept = "text/event-stream, application/json";
  }
  return {
    url,
    method: "POST",
    headers,
    body: JSON.stringify(body),
  };
}

async function requestBody(parsed, stdin) {
  let body = {};
  if (parsed.jsonSource !== undefined) {
    body = await parseJsonSource(parsed.jsonSource, stdin);
  } else if (stdin && stdin.isTTY !== true) {
    const piped = await readLimitedText(stdin, MAX_INPUT_BYTES);
    if (piped.trim()) {
      body = parseJsonObject(piped, "stdin");
    }
  }

  if (parsed.model !== undefined) {
    body.model = parsed.model;
  }
  if (parsed.stream !== undefined) {
    body.stream = parsed.stream;
  }
  if (parsed.sessionId) {
    body.mycomesh_session = { session_id: parsed.sessionId };
  }

  const positionalInput = parsed.positionals.length
    ? parsed.positionals.join(" ")
    : undefined;
  if (parsed.command === "responses") {
    const input = parsed.input ?? positionalInput;
    if (input !== undefined) {
      body.input = input;
    }
    if (parsed.maxOutputTokens !== undefined) {
      body.max_output_tokens = parsed.maxOutputTokens;
    }
    if (body.input === undefined) {
      throw new CliError(
        "responses requires input in JSON, --input, or a positional argument",
        2,
      );
    }
  } else {
    const message = parsed.message ?? positionalInput;
    if (message !== undefined) {
      const messages = [];
      if (parsed.system !== undefined) {
        messages.push({ role: "system", content: parsed.system });
      }
      messages.push({ role: "user", content: message });
      body.messages = messages;
    } else if (parsed.system !== undefined) {
      const messages = Array.isArray(body.messages) ? body.messages : [];
      body.messages = [
        { role: "system", content: parsed.system },
        ...messages,
      ];
    }
    if (parsed.maxTokens !== undefined) {
      body.max_tokens = parsed.maxTokens;
    }
    if (parsed.maxCompletionTokens !== undefined) {
      body.max_completion_tokens = parsed.maxCompletionTokens;
    }
    if (!Array.isArray(body.messages) || body.messages.length === 0) {
      throw new CliError(
        "chat requires messages in JSON, --message, or a positional argument",
        2,
      );
    }
  }
  return body;
}

async function parseJsonSource(source, stdin) {
  if (source === "-") {
    const text = await readLimitedText(stdin, MAX_INPUT_BYTES);
    return parseJsonObject(text, "stdin");
  }
  if (source.startsWith("@")) {
    const path = source.slice(1);
    if (!path) {
      throw new CliError("--json @file requires a file path", 2);
    }
    let contents;
    try {
      contents = await readFile(path);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new CliError(`could not read JSON file: ${detail}`, 2);
    }
    if (contents.byteLength > MAX_INPUT_BYTES) {
      throw new CliError(`JSON input exceeds ${MAX_INPUT_BYTES} bytes`, 2);
    }
    return parseJsonObject(contents.toString("utf8"), path);
  }
  if (Buffer.byteLength(source, "utf8") > MAX_INPUT_BYTES) {
    throw new CliError(`JSON input exceeds ${MAX_INPUT_BYTES} bytes`, 2);
  }
  return parseJsonObject(source, "--json");
}

function parseJsonObject(text, source) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new CliError(`invalid JSON from ${source}: ${detail}`, 2);
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new CliError(`JSON from ${source} must be an object`, 2);
  }
  return { ...value };
}

function endpointUrl(baseUrl, command, allowInsecureHttp = false) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new CliError("base URL must be an absolute HTTP or HTTPS URL", 2);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new CliError("base URL must use HTTP or HTTPS", 2);
  }
  if (url.username || url.password) {
    throw new CliError("base URL must not contain credentials", 2);
  }
  if (
    url.protocol === "http:" &&
    !allowInsecureHttp &&
    !isLoopbackHostname(url.hostname)
  ) {
    throw new CliError(
      "remote base URLs must use HTTPS; use --allow-insecure-http only for testing",
      2,
    );
  }
  if (url.search || url.hash) {
    throw new CliError("base URL must not contain a query string or fragment", 2);
  }

  let path = url.pathname.replace(/\/+$/, "");
  if (command === "health") {
    path = path.replace(/\/v1$/, "");
    url.pathname = `${path}/health`;
  } else {
    if (!path.endsWith("/v1")) {
      path = `${path}/v1`;
    }
    const resource = command === "chat" ? "chat/completions" : command;
    url.pathname = `${path}/${resource}`;
  }
  return url;
}

function isLoopbackHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  if (normalized === "localhost" || normalized === "[::1]") {
    return true;
  }
  if (!/^127(?:\.[0-9]{1,3}){3}$/.test(normalized)) {
    return false;
  }
  return normalized.split(".").every((part) => Number(part) <= 255);
}

async function sendRequest(request, fetchImpl, signal, timeoutSeconds) {
  try {
    return await fetchImpl(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "error",
      signal,
    });
  } catch (error) {
    if (signal.aborted) {
      throw new CliError(`request timed out after ${timeoutSeconds} seconds`);
    }
    const detail = error instanceof Error ? error.message : String(error);
    throw new CliError(`request failed: ${detail}`);
  }
}

async function writeResponse(response, output, maxJsonResponseBytes) {
  const contentType = (response.headers.get("content-type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();

  if (contentType === "text/event-stream") {
    await pipeBody(response.body, output);
    return;
  }
  if (contentType === "application/json" || contentType.endsWith("+json")) {
    const text = await readLimitedText(response.body, maxJsonResponseBytes, {
      rejectOnLimit: true,
      label: "JSON response",
    });
    if (!text.trim()) {
      return;
    }
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new CliError("server returned malformed JSON");
    }
    output.write(`${JSON.stringify(value, null, 2)}\n`);
    return;
  }
  await pipeBody(response.body, output);
}

async function pipeBody(body, output) {
  if (!body) {
    return;
  }
  for await (const chunk of body) {
    if (!output.write(chunk)) {
      await once(output, "drain");
    }
  }
}

async function readLimitedText(
  stream,
  limit,
  { rejectOnLimit = false, label = "response" } = {},
) {
  if (!stream) {
    return "";
  }
  const chunks = [];
  let size = 0;
  let truncated = false;
  for await (const rawChunk of stream) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
    const remaining = limit - size;
    if (chunk.byteLength > remaining) {
      if (remaining > 0) {
        chunks.push(chunk.subarray(0, remaining));
      }
      truncated = true;
      break;
    }
    chunks.push(chunk);
    size += chunk.byteLength;
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (truncated && rejectOnLimit) {
    throw new CliError(`${label} exceeds ${limit} bytes`);
  }
  return truncated ? `${text}\n[response truncated]` : text;
}

function createRequestTimeout(timeoutSeconds) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutSeconds * 1000);
  timer.unref?.();
  return {
    signal: controller.signal,
    timeoutSeconds,
    cancel() {
      clearTimeout(timer);
    },
  };
}

function requestTimeoutSeconds(value, option) {
  const timeout = positiveInteger(String(value), option);
  if (timeout > MAX_TIMEOUT_SECONDS) {
    throw new CliError(
      `${option} must not exceed ${MAX_TIMEOUT_SECONDS} seconds`,
      2,
    );
  }
  return timeout;
}

function positiveInteger(value, option) {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new CliError(`${option} must be a positive integer`, 2);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    throw new CliError(`${option} is too large`, 2);
  }
  return number;
}

function sessionId(value, option) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new CliError(`${option} must be a 32-byte 0x-prefixed hex value`, 2);
  }
  return value.toLowerCase();
}

function validateCommandOptions(parsed) {
  if (parsed.help || parsed.version || !parsed.command) {
    return;
  }
  const hasBodyOptions =
    parsed.jsonSource !== undefined ||
    parsed.model !== undefined ||
    parsed.stream !== undefined ||
    parsed.input !== undefined ||
    parsed.message !== undefined ||
    parsed.system !== undefined ||
    parsed.maxOutputTokens !== undefined ||
    parsed.maxTokens !== undefined ||
    parsed.maxCompletionTokens !== undefined ||
    parsed.positionals.length > 0;
  if ((parsed.command === "health" || parsed.command === "models") && hasBodyOptions) {
    throw new CliError(`${parsed.command} does not accept request body options`, 2);
  }
  if (
    (parsed.command === "health" || parsed.command === "models") &&
    parsed.sessionIdExplicit
  ) {
    throw new CliError(`${parsed.command} does not accept --session-id`, 2);
  }
  if (
    parsed.command === "responses" &&
    (parsed.message !== undefined ||
      parsed.system !== undefined ||
      parsed.maxTokens !== undefined ||
      parsed.maxCompletionTokens !== undefined)
  ) {
    throw new CliError("chat options cannot be used with responses", 2);
  }
  if (
    parsed.command === "chat" &&
    (parsed.input !== undefined || parsed.maxOutputTokens !== undefined)
  ) {
    throw new CliError("responses options cannot be used with chat", 2);
  }
  if (parsed.input !== undefined && parsed.positionals.length > 0) {
    throw new CliError("use either --input or positional input, not both", 2);
  }
  if (parsed.message !== undefined && parsed.positionals.length > 0) {
    throw new CliError("use either --message or a positional message, not both", 2);
  }
}

function redact(value, secret) {
  let text = String(value);
  if (!secret) {
    return text;
  }
  const variants = new Set([
    secret,
    encodeURIComponent(secret),
    JSON.stringify(secret).slice(1, -1),
  ]);
  for (const variant of variants) {
    if (variant) {
      text = text.split(variant).join("[REDACTED]");
    }
  }
  return text;
}
