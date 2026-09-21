import { spawn as defaultSpawn } from "node:child_process";
import { existsSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as readline from "node:readline/promises";
import { CONSUMER_RELEASE_VERSION } from "./release.mjs";
export { CONSUMER_RELEASE_VERSION } from "./release.mjs";

import {
  DEFAULT_BASE_URL,
  DEFAULT_MAX_FEE_UNITS,
  DEFAULT_RELAY_URL,
  NativeConsumerState,
  createConsumerServer,
  parseNetworkConfig,
  paymentKeyAddress,
} from "./consumer-runtime.mjs";

// V10 is a controlled committee testnet. Keep its manifest in the package,
// but make selecting it an explicit opt-in so the legacy V8 default remains
// safe for existing installs.
export const V10_CONTROLLED_TEST_NETWORK = fileURLToPath(
  new URL("../networks/v10-controlled-test.json", import.meta.url),
);
export const API_COMMANDS = new Set(["health", "models", "responses", "chat"]);
const API_VALUE_OPTIONS = new Set([
  "--base-url",
  "--api-key",
  "--timeout",
  "--session-id",
  "--json",
  "--model",
  "--input",
  "--message",
  "--system",
  "--max-output-tokens",
  "--max-tokens",
  "--max-completion-tokens",
]);

export const CONSUMER_HELP = `Usage: mycomesh-consumer [options] [-- codex-options]

Start the local MycoMesh Consumer without Docker, Python, or a public Gateway.
The process manages a persisted access key, selects healthy Relays, and
exposes an OpenAI-compatible loopback API.

Options:
  --no-browser          Print the local credentials URL without opening it
  --codex               Start an optional Codex client after Relay readiness
  --no-codex            Keep only the Consumer API running (default)
  --stop                Stop a previously started native Consumer
  --reset-local         Confirm and delete the local Consumer data directory
  --codex-command PATH  Codex executable for --codex (default: codex on PATH)
  --ready-timeout SEC   Relay readiness timeout (default: 1800)
  --data-dir DIR        Payment key and history directory
  --relay URLS          Comma-separated Relay URLs for automatic failover
  --network-config FILE Use a trusted network manifest and its backup Relays
  --ca-file FILE       Private CA PEM for an explicit controlled-test network
  --controlled-test     Explicitly opt into a controlled test committee
  --v10-controlled-test Select the bundled V10 fixed-budget controlled testnet
  --proxy URL           Optional outbound HTTP proxy
  --host HOST           Listen address (default: 127.0.0.1)
  --port PORT           Listen port (default: 8110)
  --max-fee UNITS       Maximum fee per request (default: 100000)
  --dry-run             Print the native startup plan
  --doctor              Check local Consumer configuration without starting or paying
  --doctor-json         Emit the same check as stable JSON for automation
  -h, --help            Show this help
  -v, --version         Show the package version

Each Consumer process starts locked. Connect your browser wallet on the setup
page. For first use, choose Enable API access and confirm the wallet request;
returning users reuse the existing authorization. Copy the API URL and key (or
the combined export) into your client. Never enter a wallet private key.
The page has no browser conversation state.`;

class ConsumerCliError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.name = "ConsumerCliError";
    this.exitCode = exitCode;
  }
}

export async function main(argv, dependencies = {}) {
  const env = dependencies.env ?? process.env;
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  try {
    const parsed = parseArguments(argv, env);
    if (parsed.help) {
      stdout.write(`${CONSUMER_HELP}\n`);
      return 0;
    }
    if (parsed.version) {
      stdout.write(`${CONSUMER_RELEASE_VERSION}\n`);
      return 0;
    }
    if (parsed.doctor || parsed.doctorJson) {
      return await consumerDoctor({ parsed, env, stdout, fetch: dependencies.fetch, json: parsed.doctorJson });
    }
    if (parsed.dryRun) {
      stdout.write(`Native Consumer: ${parsed.host}:${parsed.port}\n`);
      stdout.write(`Data directory: ${parsed.dataDir}\n`);
      stdout.write(`Relays: ${!parsed.relayUrlsExplicit && parsed.networkConfig ? "from selected network manifest (legacy default if absent)" : parsed.relayUrls}\n`);
      stdout.write("Docker: disabled\n");
      return 0;
    }
    if (parsed.stop) return stopConsumer(parsed, stdout, stderr);
    if (parsed.resetLocal) return await resetConsumer(parsed, env, stdout, stderr);

    const state = dependencies.createState
      ? dependencies.createState(parsed, env)
      : new NativeConsumerState({
          env: { ...env, MYCOMESH_CONSUMER_DATA_DIR: parsed.dataDir },
          dataDir: parsed.dataDir,
          relayUrls: parsed.relayUrlsExplicit ? parsed.relayUrls : undefined,
          networkConfig: parsed.networkConfig,
          caFile: parsed.caFile,
          allowControlledTest: parsed.allowControlledTest,
          proxy: parsed.proxy,
          baseUrl: parsed.baseUrl,
          maxFeeUnits: parsed.maxFeeUnits,
        });
    const runtime = dependencies.createServer
      ? dependencies.createServer(state, parsed)
      : createConsumerServer(state, { host: parsed.host, port: parsed.port });
    await runtime.listen();
    const rootUrl = `${parsed.scheme}://${parsed.hostForUrl}:${parsed.port}`;
    const credentialsUrl = `${rootUrl}/`;
    writePid(parsed.dataDir);
    stdout.write(`MycoMesh Consumer setup: ${credentialsUrl}\n`);
    stdout.write(`OpenAI API: ${state.baseUrl}\n`);
    if (!parsed.noBrowser) openBrowser(credentialsUrl, stderr);

    const shutdown = async () => {
      clearPid(parsed.dataDir);
      await state.stopShare?.();
      await runtime.close();
    };
    if (parsed.noCodex) {
      await waitForSignal(shutdown);
      return 0;
    }
    await waitUntilReady(state, parsed.readyTimeout, stdout);
    await waitUntilUnlocked(state, parsed.readyTimeout, stdout);
    const code = await runCodex(parsed, state, dependencies.spawn ?? defaultSpawn, stdout, stderr);
    await shutdown();
    return code;
  } catch (error) {
    const exitCode = error instanceof ConsumerCliError ? error.exitCode : 1;
    const message = error?.code === "EADDRINUSE"
      ? `port ${error.port || "requested"} is already in use; stop the old Consumer or choose --port with a matching --base-url`
      : error instanceof Error ? error.message : String(error);
    stderr.write(`mycomesh consumer: ${message}\n`);
    return exitCode;
  }
}

export function parseArguments(argv, env = process.env) {
  const parsed = {
    baseUrl: env.MYCOMESH_CONSUMER_PUBLIC_BASE_URL || DEFAULT_BASE_URL,
    baseUrlExplicit: Boolean(env.MYCOMESH_CONSUMER_PUBLIC_BASE_URL),
    dataDir: env.MYCOMESH_CONSUMER_DATA_DIR || join(env.HOME || process.cwd(), ".mycomesh", "consumer"),
    relayUrls: env.MYCOMESH_V8_RELAY_URLS || env.MYCOMESH_CONSUMER_RELAY_URL || DEFAULT_RELAY_URL,
    relayUrlsExplicit: Boolean(env.MYCOMESH_V8_RELAY_URLS || env.MYCOMESH_CONSUMER_RELAY_URL),
    networkConfig: env.MYCOMESH_CONSUMER_NETWORK_CONFIG || undefined,
    caFile: env.MYCOMESH_CONSUMER_CA_FILE || undefined,
    proxy: env.MYCOMESH_CONSUMER_PROXY || "",
    codexCommand: env.MYCOMESH_CODEX_COMMAND || "codex",
    readyTimeout: parsePositive(env.MYCOMESH_CONSUMER_READY_TIMEOUT_SECONDS || "1800", "ready timeout", 86400),
    maxFeeUnits: parsePositive(env.MYCOMESH_V8_MAX_FEE_UNITS || String(DEFAULT_MAX_FEE_UNITS), "max fee"),
    host: env.MYCOMESH_CONSUMER_HOST || "127.0.0.1",
    hostForUrl: env.MYCOMESH_CONSUMER_HOST || "127.0.0.1",
    port: parsePositive(env.MYCOMESH_CONSUMER_PORT || "8110", "port", 65535),
    scheme: "http",
    allowControlledTest: false,
    v10ControlledTest: false,
    noBrowser: false,
    noCodex: env.MYCOMESH_CONSUMER_START_CODEX !== "1",
    stop: false,
    resetLocal: false,
    dryRun: false,
    doctor: false,
    doctorJson: false,
    help: false,
    version: false,
    codexArgs: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") { parsed.codexArgs = argv.slice(index + 1); break; }
    if (token === "-h" || token === "--help") { parsed.help = true; continue; }
    if (token === "-v" || token === "--version") { parsed.version = true; continue; }
    if (token === "--controlled-test") { parsed.allowControlledTest = true; continue; }
    if (token === "--v10-controlled-test") {
      parsed.v10ControlledTest = true;
      parsed.allowControlledTest = true;
      continue;
    }
    if (token === "--no-browser") { parsed.noBrowser = true; continue; }
    if (token === "--codex") { parsed.noCodex = false; continue; }
    if (token === "--no-codex") { parsed.noCodex = true; continue; }
    if (token === "--stop") { parsed.stop = true; continue; }
    if (token === "--reset-local") { parsed.resetLocal = true; continue; }
    if (token === "--dry-run") { parsed.dryRun = true; continue; }
    if (token === "--doctor") { parsed.doctor = true; continue; }
    if (token === "--doctor-json") { parsed.doctorJson = true; continue; }
    const separator = token.indexOf("=");
    const name = separator === -1 ? token : token.slice(0, separator);
    let value = separator === -1 ? undefined : token.slice(separator + 1);
    const options = new Set(["--base-url", "--data-dir", "--relay", "--network-config", "--ca-file", "--proxy", "--codex-command", "--ready-timeout", "--host", "--port", "--max-fee"]);
    if (!options.has(name)) throw new ConsumerCliError(`unknown option: ${token}`, 2);
    if (value === undefined) { index += 1; value = argv[index]; }
    if (!value) throw new ConsumerCliError(`${name} requires a value`, 2);
    if (name === "--base-url") { parsed.baseUrl = value; parsed.baseUrlExplicit = true; }
    if (name === "--data-dir") parsed.dataDir = value;
    if (name === "--relay") { parsed.relayUrls = value; parsed.relayUrlsExplicit = true; }
    if (name === "--network-config") parsed.networkConfig = value;
    if (name === "--ca-file") parsed.caFile = value;
    if (name === "--proxy") parsed.proxy = value;
    if (name === "--codex-command") parsed.codexCommand = value;
    if (name === "--ready-timeout") parsed.readyTimeout = parsePositive(value, name, 86400);
    if (name === "--host") { parsed.host = value; parsed.hostForUrl = value.includes(":") ? `[${value}]` : value; }
    if (name === "--port") parsed.port = parsePositive(value, name, 65535);
    if (name === "--max-fee") parsed.maxFeeUnits = parsePositive(value, name);
  }
  if (parsed.v10ControlledTest && !parsed.networkConfig) {
    parsed.networkConfig = env.MYCOMESH_V10_NETWORK_CONFIG || V10_CONTROLLED_TEST_NETWORK;
  }
  if (!parsed.baseUrlExplicit) parsed.baseUrl = `http://${parsed.hostForUrl}:${parsed.port}/v1`;
  try { new URL(parsed.baseUrl); } catch { throw new ConsumerCliError("--base-url must be an absolute URL", 2); }
  return parsed;
}

// Read-only preflight. This deliberately does not construct NativeConsumerState:
// its constructor creates a payment key on first run. A doctor command must be
// safe to run from installers, CI and support scripts without changing state.
async function consumerDoctor({ parsed, env, stdout, fetch: injectedFetch, json }) {
  const checks = [];
  const add = (id, status, message, details = undefined) => {
    const check = { id, status, message };
    if (details !== undefined) check.details = details;
    checks.push(check);
  };
  const dataDir = parsed.dataDir;
  if (existsSync(dataDir)) add("data_dir", "ready", "Consumer data directory exists", { path: dataDir });
  else add("data_dir", "setup_required", "Consumer data directory has not been created", { path: dataDir });

  const keyPath = join(dataDir, "payment-key");
  const configuredKey = String(env.MYCOMESH_V8_PAYMENT_KEY || "").trim();
  let paymentAddress;
  try {
    if (configuredKey) paymentAddress = paymentKeyAddress(configuredKey);
    else if (existsSync(keyPath)) paymentAddress = paymentKeyAddress(readFileSync(keyPath, "utf8").trim());
    else throw Object.assign(new Error("payment key is not initialized"), { code: "setup_required" });
    add("payment_key", "ready", "Payment key is present and valid", {
      source: configuredKey ? "environment" : "data_dir",
      address: paymentAddress,
    });
  } catch (error) {
    add("payment_key", error.code === "setup_required" ? "setup_required" : "blocked", error.message);
  }

  let network;
  try {
    network = parseNetworkConfig(parsed.networkConfig, { allowControlledTest: parsed.allowControlledTest });
    add("network_manifest", "ready", parsed.networkConfig ? "Settlement network manifest is valid" : "Using built-in settlement network", {
      path: parsed.networkConfig || null,
      protocol_version: network.protocol_version,
      chain_id: network.chain_id,
      settlement_contract: network.settlement_contract,
    });
  } catch (error) {
    add("network_manifest", "blocked", error.message, { path: parsed.networkConfig || null });
  }

  const relayUrls = network?.relay_urls?.length ? network.relay_urls : String(parsed.relayUrls || "")
    .split(",").map((value) => value.trim()).filter(Boolean);
  const validRelays = [];
  for (const value of relayUrls) {
    try {
      const url = new URL(value);
      if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("URL must be an HTTPS origin without credentials or query");
      validRelays.push(url.href.replace(/\/+$/, ""));
    } catch (error) {
      add("relay_urls", "blocked", `Invalid Relay URL: ${error.message}`, { url: value });
    }
  }
  if (validRelays.length) add("relay_urls", "ready", `${validRelays.length} Relay URL${validRelays.length === 1 ? "" : "s"} configured`, { urls: validRelays });
  else if (!checks.some((check) => check.id === "relay_urls")) add("relay_urls", "blocked", "No usable Relay URL is configured");

  const pidPath = join(dataDir, "consumer.pid");
  if (!existsSync(pidPath)) add("local_process", "ready", "No stale Consumer pid file found", { running: false });
  else {
    const pid = Number(readFileSync(pidPath, "utf8").trim());
    let running = false;
    try { if (Number.isInteger(pid) && pid > 1) { process.kill(pid, 0); running = true; } } catch (error) { if (error.code !== "ESRCH") running = true; }
    add("local_process", running ? "ready" : "blocked", running ? "Consumer process is running" : "Consumer pid file is stale", { pid, running });
  }

  const fetchImpl = injectedFetch || ((url, options) => consumerDoctorFetch(url, options, parsed));
  const health = [];
  if (validRelays.length && typeof fetchImpl === "function") {
    await Promise.all(validRelays.map(async (relay) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1500);
      try {
        const response = await fetchImpl(`${relay}/health`, { method: "GET", redirect: "error", signal: controller.signal });
        health.push({ url: relay, status: response.ok ? "ready" : "blocked", http_status: response.status });
        await response.body?.cancel?.();
      } catch (error) { health.push({ url: relay, status: "blocked", error: error.message }); }
      finally { clearTimeout(timer); }
    }));
    const healthy = health.filter((item) => item.status === "ready").length;
    const relayStatus = healthy === 0 ? "blocked" : healthy < health.length ? "degraded" : "ready";
    add("relay_health", relayStatus, healthy ? `${healthy}/${health.length} Relay health checks passed` : "All Relay health checks failed", { relays: health });
  } else add("relay_health", "setup_required", "Relay health was not checked because no usable Relay URL is configured");

  const hasBlocked = checks.some((check) => check.status === "blocked");
  const hasSetup = checks.some((check) => check.status === "setup_required");
  const hasDegraded = checks.some((check) => check.status === "degraded");
  const report = {
    schema: "mycomesh.consumer.doctor.v1",
    status: hasBlocked ? "blocked" : hasSetup ? "setup_required" : hasDegraded ? "degraded" : "ready",
    release: { version: CONSUMER_RELEASE_VERSION },
    config: { data_dir: dataDir, host: parsed.host, port: parsed.port, base_url: parsed.baseUrl },
    checks,
  };
  if (json) stdout.write(`${JSON.stringify(report)}\n`);
  else {
    stdout.write(`Consumer doctor: ${report.status}\n`);
    for (const check of checks) stdout.write(`${check.status === "ready" ? "✓" : check.status === "setup_required" ? "!" : check.status === "degraded" ? "~" : "✗"} ${check.id}: ${check.message}\n`);
  }
  return report.status === "blocked" ? 1 : 0;
}

function consumerDoctorFetch(url, options = {}, parsed) {
  const target = new URL(url);
  if (target.protocol !== "https:" || !parsed.caFile) return globalThis.fetch(url, options);
  const ca = readFileSync(resolve(parsed.caFile));
  return new Promise((resolvePromise, reject) => {
    const request = httpsRequest({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      method: options.method || "GET",
      ca,
      rejectUnauthorized: true,
    }, (response) => {
      response.resume();
      resolvePromise({
        ok: (response.statusCode || 0) >= 200 && (response.statusCode || 0) < 300,
        status: response.statusCode || 0,
        body: { cancel: async () => {} },
      });
    });
    const abort = () => request.destroy(options.signal?.reason || new Error("request aborted"));
    options.signal?.addEventListener("abort", abort, { once: true });
    request.setTimeout(1500, () => request.destroy(new Error("request timed out")));
    request.once("error", reject);
    request.once("close", () => options.signal?.removeEventListener("abort", abort));
    request.end();
  });
}

function parsePositive(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  if (!/^[1-9][0-9]*$/.test(String(value))) throw new ConsumerCliError(`${label} must be a positive integer`, 2);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) throw new ConsumerCliError(`${label} is too large`, 2);
  return parsed;
}

export function isApiInvocation(argv) {
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") return false;
    if (token.startsWith("--")) {
      const name = token.split("=", 1)[0];
      if (!token.includes("=") && API_VALUE_OPTIONS.has(name)) index += 1;
      continue;
    }
    if (token.startsWith("-")) continue;
    return API_COMMANDS.has(token);
  }
  return false;
}

async function waitUntilReady(state, timeoutSeconds, stdout) {
  const started = Date.now();
  stdout.write(`Waiting for a healthy Settlement V${state.network?.protocol_version || 8} Relay...\n`);
  while (true) {
    try { await state.chooseRelay(); return; } catch (error) {
      if (Date.now() - started >= timeoutSeconds * 1000) throw new ConsumerCliError(`timed out waiting for a healthy Relay: ${error.message}`);
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
}

async function waitUntilUnlocked(state, timeoutSeconds, stdout) {
  const started = Date.now();
  stdout.write("Waiting for wallet verification in the local Consumer page...\n");
  while (!state.paymentUnlocked) {
    if (Date.now() - started >= timeoutSeconds * 1000) {
      throw new ConsumerCliError("timed out waiting for the payment-key owner wallet to unlock Consumer");
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

function runCodex(parsed, state, spawn, stdout, stderr) {
  return new Promise((resolve) => {
    const args = [
      "-c", 'model="gpt-5.5"',
      "-c", 'model_provider="mycomesh"',
      "-c", 'model_providers.mycomesh.name="MycoMesh"',
      "-c", `model_providers.mycomesh.base_url="${state.baseUrl}"`,
      "-c", 'model_providers.mycomesh.env_key="OPENAI_API_KEY"',
      "-c", 'model_providers.mycomesh.wire_api="responses"',
      ...parsed.codexArgs,
    ];
    const env = { ...process.env, OPENAI_BASE_URL: state.baseUrl, OPENAI_API_KEY: state.paymentKey };
    let child;
    try { child = spawn(parsed.codexCommand, args, { env, stdio: "inherit" }); }
    catch (error) { stderr.write(`mycomesh consumer: could not start Codex: ${error.message}\n`); resolve(127); return; }
    stdout.write("Opening Codex through the native MycoMesh Consumer.\n");
    child.once("error", (error) => { stderr.write(`mycomesh consumer: Codex failed: ${error.message}\n`); resolve(127); });
    child.once("exit", (code, signal) => resolve(typeof code === "number" ? code : 128 + ({ SIGINT: 2, SIGTERM: 15 }[signal] || 1)));
  });
}

function writePid(dataDir) {
  try { writeFileSync(join(dataDir, "consumer.pid"), `${process.pid}\n`, { mode: 0o600 }); } catch {}
}

function clearPid(dataDir) {
  try { unlinkSync(join(dataDir, "consumer.pid")); } catch {}
}

function stopConsumer(parsed, stdout, stderr) {
  const pidPath = join(parsed.dataDir, "consumer.pid");
  if (!existsSync(pidPath)) { stdout.write("No native Consumer is running.\n"); return 0; }
  const pid = Number(readFileSync(pidPath, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 1) { clearPid(parsed.dataDir); stderr.write("Removed an invalid Consumer pid file.\n"); return 0; }
  try { process.kill(pid, "SIGTERM"); stdout.write(`Stopped native Consumer process ${pid}.\n`); }
  catch (error) { if (error.code !== "ESRCH") throw error; stdout.write("Native Consumer was already stopped.\n"); }
  clearPid(parsed.dataDir);
  return 0;
}

async function resetConsumer(parsed, env, stdout, stderr) {
  const confirmed = env.MYCOMESH_CONFIRM_RESET === "RESET";
  if (!confirmed && process.stdin.isTTY) {
    const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await prompt.question("This removes the local payment key and history. Type RESET to continue: ");
    prompt.close();
    if (answer !== "RESET") throw new ConsumerCliError("local Consumer reset cancelled", 2);
  } else if (!confirmed) {
    throw new ConsumerCliError("set MYCOMESH_CONFIRM_RESET=RESET to reset a non-interactive Consumer", 2);
  }
  clearPid(parsed.dataDir);
  rmSync(parsed.dataDir, { recursive: true, force: true });
  stdout.write("Native Consumer local state removed.\n");
  return 0;
}

function openBrowser(url, stderr) {
  const platform = process.platform;
  let command;
  let args;
  if (platform === "darwin") { command = "open"; args = [url]; }
  else if (platform === "win32") { command = "cmd"; args = ["/c", "start", "", url]; }
  else { command = "xdg-open"; args = [url]; }
  try {
    const child = defaultSpawn(command, args, { stdio: "ignore", detached: true });
    child.unref?.();
  } catch { stderr.write(`Open ${url} in a browser.\n`); }
}

function waitForSignal(shutdown) {
  return new Promise((resolve) => {
    let closed = false;
    const finish = async () => { if (closed) return; closed = true; process.removeListener("SIGINT", finish); process.removeListener("SIGTERM", finish); await shutdown(); resolve(); };
    process.once("SIGINT", finish);
    process.once("SIGTERM", finish);
  });
}
