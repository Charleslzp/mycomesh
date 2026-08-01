import { spawn as defaultSpawn } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const CONSUMER_RELEASE_VERSION = "0.1.5";
const DEFAULT_NODE_IMAGE =
  "ghcr.io/charleslzp/mycomesh-node@sha256:86c44b7807057904446f74528e4e4ed7c863edcbd833c3688975d6d4ca8c480d";
const API_COMMANDS = new Set(["health", "models", "responses", "chat"]);
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

const HELP = `Usage: mycomesh-consumer [options] [-- codex-options]

Start the local MycoMesh Consumer. No options are needed.

The default command starts the pinned Docker runtime, opens the local wallet
and funding page, waits for an activated V5 Session, then opens Codex through
the loopback Consumer at http://127.0.0.1:8110/v1.

Options:
  --no-browser          Print the onboarding URL without opening it
  --no-codex            Start the Consumer and browser without opening Codex
  --stop                Stop the Consumer without deleting its wallet state
  --codex-command PATH  Codex executable (default: codex)
  --ready-timeout SEC   Wallet onboarding timeout (default: 1800)
  --proxy URL           Optional proxy for Consumer network traffic
  --node-image IMAGE    Advanced: override the pinned Consumer image
  --dry-run             Print the planned Docker operations
  -h, --help            Show this help
  -v, --version         Show the package version

Existing API commands remain available:
  mycomesh-consumer health
  mycomesh-consumer models
  mycomesh-consumer responses "hello"
  mycomesh-consumer chat "hello"

Docker Desktop/Engine is required. The package installs official Codex and
wallet keys remain in the browser wallet; local Consumer credentials and
Sessions remain in a protected Docker volume.`;

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
      stdout.write(`${HELP}\n`);
      return 0;
    }
    if (parsed.version) {
      stdout.write(`${CONSUMER_RELEASE_VERSION}\n`);
      return 0;
    }
    const script = dependencies.scriptPath
      ?? fileURLToPath(new URL("../scripts/start-consumer.sh", import.meta.url));
    return await runScript(script, toScriptArgs(parsed), {
      env,
      spawn: dependencies.spawn ?? defaultSpawn,
    });
  } catch (error) {
    const exitCode = error instanceof ConsumerCliError ? error.exitCode : 1;
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`mycomesh consumer: ${message}\n`);
    return exitCode;
  }
}

export function parseArguments(argv, env = process.env) {
  const parsed = {
    nodeImage: env.MYCOMESH_NODE_IMAGE || DEFAULT_NODE_IMAGE,
    codexCommand: env.MYCOMESH_CODEX_COMMAND || bundledCodexCommand(),
    readyTimeout: env.MYCOMESH_CONSUMER_READY_TIMEOUT_SECONDS || undefined,
    proxy: env.MYCOMESH_CONSUMER_PROXY || undefined,
    noBrowser: false,
    noCodex: false,
    stop: false,
    dryRun: false,
    help: false,
    version: false,
    codexArgs: [],
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") {
      parsed.codexArgs = argv.slice(index + 1);
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
    if (token === "--no-browser") {
      parsed.noBrowser = true;
      continue;
    }
    if (token === "--no-codex") {
      parsed.noCodex = true;
      continue;
    }
    if (token === "--stop") {
      parsed.stop = true;
      continue;
    }
    if (token === "--dry-run") {
      parsed.dryRun = true;
      continue;
    }
    const separator = token.indexOf("=");
    const name = separator === -1 ? token : token.slice(0, separator);
    let value = separator === -1 ? undefined : token.slice(separator + 1);
    if (!["--node-image", "--codex-command", "--ready-timeout", "--proxy"].includes(name)) {
      throw new ConsumerCliError(`unknown option: ${token}`, 2);
    }
    if (value === undefined) {
      index += 1;
      value = argv[index];
    }
    if (!value) throw new ConsumerCliError(`${name} requires a value`, 2);
    if (name === "--node-image") parsed.nodeImage = value;
    if (name === "--codex-command") parsed.codexCommand = value;
    if (name === "--ready-timeout") parsed.readyTimeout = value;
    if (name === "--proxy") parsed.proxy = value;
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:[a-f0-9]{64}$/.test(parsed.nodeImage)) {
    throw new ConsumerCliError("Consumer image must be pinned by digest", 2);
  }
  if (parsed.readyTimeout && !/^[1-9][0-9]*$/.test(parsed.readyTimeout)) {
    throw new ConsumerCliError("--ready-timeout must be a positive integer", 2);
  }
  return parsed;
}

function bundledCodexCommand() {
  try {
    return createRequire(import.meta.url).resolve("@openai/codex/bin/codex.js");
  } catch {
    return "codex";
  }
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

export function toScriptArgs(parsed) {
  const args = ["--node-image", parsed.nodeImage];
  if (parsed.codexCommand) args.push("--codex-command", parsed.codexCommand);
  if (parsed.readyTimeout) args.push("--ready-timeout", parsed.readyTimeout);
  if (parsed.proxy) args.push("--proxy", parsed.proxy);
  if (parsed.noBrowser) args.push("--no-browser");
  if (parsed.noCodex) args.push("--no-codex");
  if (parsed.stop) args.push("--stop");
  if (parsed.dryRun) args.push("--dry-run");
  if (parsed.codexArgs.length) args.push("--", ...parsed.codexArgs);
  return args;
}

function runScript(script, args, { env, spawn }) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn("bash", [script, ...args], { env: { ...env }, stdio: "inherit" });
    } catch (error) {
      reject(new ConsumerCliError(`could not start bash: ${error.message}`));
      return;
    }
    child.once("error", (error) => reject(new ConsumerCliError(`could not start bash: ${error.message}`)));
    child.once("exit", (code, signal) => {
      resolve(typeof code === "number" ? code : 128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 }[signal] ?? 1));
    });
  });
}

export { CONSUMER_RELEASE_VERSION, DEFAULT_NODE_IMAGE, HELP as CONSUMER_HELP };
