import { spawn as defaultSpawn } from "node:child_process";
import { existsSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as readline from "node:readline/promises";

import {
  DEFAULT_BASE_URL,
  DEFAULT_MAX_FEE_UNITS,
  DEFAULT_RELAY_URL,
  NativeConsumerState,
  createConsumerServer,
} from "./consumer-runtime.mjs";

export const CONSUMER_RELEASE_VERSION = "0.1.50";
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
The process owns one persisted V8 payment key, selects healthy Relays, and
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
  --proxy URL           Optional outbound HTTP proxy
  --host HOST           Listen address (default: 127.0.0.1)
  --port PORT           Listen port (default: 8110)
  --max-fee UNITS       Maximum fee per request (default: 100000)
  --dry-run             Print the native startup plan
  -h, --help            Show this help
  -v, --version         Show the package version

The browser page displays only the export URL/key, prepaid balance, key
operations, and local consumption history. No browser conversation state is
created.`;

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
    if (parsed.dryRun) {
      stdout.write(`Native Consumer: ${parsed.host}:${parsed.port}\n`);
      stdout.write(`Data directory: ${parsed.dataDir}\n`);
      stdout.write(`Relays: ${parsed.relayUrls}\n`);
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
          relayUrls: parsed.relayUrls,
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
    stdout.write(`MycoMesh Consumer credentials: ${credentialsUrl}\n`);
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
    proxy: env.MYCOMESH_CONSUMER_PROXY || "",
    codexCommand: env.MYCOMESH_CODEX_COMMAND || "codex",
    readyTimeout: parsePositive(env.MYCOMESH_CONSUMER_READY_TIMEOUT_SECONDS || "1800", "ready timeout", 86400),
    maxFeeUnits: parsePositive(env.MYCOMESH_V8_MAX_FEE_UNITS || String(DEFAULT_MAX_FEE_UNITS), "max fee"),
    host: env.MYCOMESH_CONSUMER_HOST || "127.0.0.1",
    hostForUrl: env.MYCOMESH_CONSUMER_HOST || "127.0.0.1",
    port: parsePositive(env.MYCOMESH_CONSUMER_PORT || "8110", "port", 65535),
    scheme: "http",
    noBrowser: false,
    noCodex: env.MYCOMESH_CONSUMER_START_CODEX !== "1",
    stop: false,
    resetLocal: false,
    dryRun: false,
    help: false,
    version: false,
    codexArgs: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") { parsed.codexArgs = argv.slice(index + 1); break; }
    if (token === "-h" || token === "--help") { parsed.help = true; continue; }
    if (token === "-v" || token === "--version") { parsed.version = true; continue; }
    if (token === "--no-browser") { parsed.noBrowser = true; continue; }
    if (token === "--codex") { parsed.noCodex = false; continue; }
    if (token === "--no-codex") { parsed.noCodex = true; continue; }
    if (token === "--stop") { parsed.stop = true; continue; }
    if (token === "--reset-local") { parsed.resetLocal = true; continue; }
    if (token === "--dry-run") { parsed.dryRun = true; continue; }
    const separator = token.indexOf("=");
    const name = separator === -1 ? token : token.slice(0, separator);
    let value = separator === -1 ? undefined : token.slice(separator + 1);
    const options = new Set(["--base-url", "--data-dir", "--relay", "--proxy", "--codex-command", "--ready-timeout", "--host", "--port", "--max-fee"]);
    if (!options.has(name)) throw new ConsumerCliError(`unknown option: ${token}`, 2);
    if (value === undefined) { index += 1; value = argv[index]; }
    if (!value) throw new ConsumerCliError(`${name} requires a value`, 2);
    if (name === "--base-url") { parsed.baseUrl = value; parsed.baseUrlExplicit = true; }
    if (name === "--data-dir") parsed.dataDir = value;
    if (name === "--relay") parsed.relayUrls = value;
    if (name === "--proxy") parsed.proxy = value;
    if (name === "--codex-command") parsed.codexCommand = value;
    if (name === "--ready-timeout") parsed.readyTimeout = parsePositive(value, name, 86400);
    if (name === "--host") { parsed.host = value; parsed.hostForUrl = value.includes(":") ? `[${value}]` : value; }
    if (name === "--port") parsed.port = parsePositive(value, name, 65535);
    if (name === "--max-fee") parsed.maxFeeUnits = parsePositive(value, name);
  }
  if (!parsed.baseUrlExplicit) parsed.baseUrl = `http://${parsed.hostForUrl}:${parsed.port}/v1`;
  try { new URL(parsed.baseUrl); } catch { throw new ConsumerCliError("--base-url must be an absolute URL", 2); }
  return parsed;
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
  stdout.write("Waiting for a healthy Settlement V8 Relay...\n");
  while (true) {
    try { await state.chooseRelay(); return; } catch (error) {
      if (Date.now() - started >= timeoutSeconds * 1000) throw new ConsumerCliError(`timed out waiting for a healthy Relay: ${error.message}`);
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
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
