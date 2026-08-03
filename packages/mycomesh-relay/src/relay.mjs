import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn as defaultSpawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DEFAULT_REPOSITORY_URL = "https://github.com/Charleslzp/mycomesh";
const DEFAULT_REF = "ee4ef09f3b606a52dbdd2ba93dc1fce7fef44fdb";
const DEFAULT_BOOTSTRAP_REPOSITORY = "https://raw.githubusercontent.com/Charleslzp/mycomesh";
const MAX_BOOTSTRAP_BYTES = 256 * 1024;

const HELP = `Usage: mycomesh-relay [options]

Start the MycoMesh Relay through the Docker-backed bootstrap installer.
The first run opens a loopback browser wizard for public Relay settings.

Options:
  --ref REF              Git branch, tag, or commit (default: V7 release commit)
  --repo-url URL         HTTPS repository URL for the Relay checkout
  --source-dir PATH      Persistent checkout directory (default: ./mycomesh)
  --wizard-port PORT     Loopback onboarding port (default: 8766)
  --no-browser           Print the wizard URL without opening a browser
  --no-start             Prepare the checkout without starting Relay
  --dry-run              Print the planned operations only
  -h, --help             Show this help

The wizard accepts only a public payout address, concurrency and usage limit.
Settlement transaction credentials stay in the Relay operator environment;
this launcher never accepts or stores a private key. Docker Compose V2 and
GNU Make are required on the Relay machine.

Example:
  npm install --global mycomesh-relay
  mycomesh-relay --ref <reviewed-commit> --no-browser`;

class RelayCliError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.name = "RelayCliError";
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

    const fetchImpl = dependencies.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new RelayCliError("Node.js 20 or newer is required");
    }

    const bootstrap = await downloadBootstrap(parsed, fetchImpl);
    try {
      return await runBootstrap(
        bootstrap.path,
        toBootstrapArgs(parsed),
        {
          env,
          spawn: dependencies.spawn ?? defaultSpawn,
        },
      );
    } finally {
      await rm(bootstrap.directory, { recursive: true, force: true });
    }
  } catch (error) {
    const exitCode = error instanceof RelayCliError ? error.exitCode : 1;
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`mycomesh relay: ${message}\n`);
    return exitCode;
  }
}

export function parseArguments(argv, env = process.env) {
  const parsed = {
    ref: env.MYCOMESH_REF || DEFAULT_REF,
    repositoryUrl: env.MYCOMESH_REPOSITORY_URL || DEFAULT_REPOSITORY_URL,
    sourceDir: env.MYCOMESH_SOURCE_DIR || undefined,
    wizardPort: env.MYCOMESH_RELAY_WIZARD_PORT || "8766",
    noBrowser: false,
    noStart: false,
    dryRun: false,
    help: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "-h" || token === "--help") {
      parsed.help = true;
      continue;
    }
    if (token === "--no-browser") {
      parsed.noBrowser = true;
      continue;
    }
    if (token === "--no-start") {
      parsed.noStart = true;
      continue;
    }
    if (token === "--dry-run") {
      parsed.dryRun = true;
      continue;
    }
    if (!token.startsWith("--")) {
      throw new RelayCliError(`unexpected argument: ${token}`, 2);
    }

    const separator = token.indexOf("=");
    const name = separator === -1 ? token : token.slice(0, separator);
    let value = separator === -1 ? undefined : token.slice(separator + 1);
    if (value === undefined) {
      index += 1;
      value = argv[index];
    }
    if (value === undefined || value === "") {
      throw new RelayCliError(`${name} requires a value`, 2);
    }

    switch (name) {
      case "--ref":
        parsed.ref = value;
        break;
      case "--repo-url":
        parsed.repositoryUrl = value;
        break;
      case "--source-dir":
        parsed.sourceDir = value;
        break;
      case "--wizard-port":
        parsed.wizardPort = value;
        break;
      default:
        throw new RelayCliError(`unknown option: ${name}`, 2);
    }
  }

  validateRef(parsed.ref);
  validateRepositoryUrl(parsed.repositoryUrl);
  validatePort(parsed.wizardPort);
  return parsed;
}

function validateRef(ref) {
  if (
    typeof ref !== "string" ||
    !/^[A-Za-z0-9._/-]{1,160}$/.test(ref) ||
    ref.includes("..") ||
    ref.startsWith("/")
  ) {
    throw new RelayCliError("invalid repository ref", 2);
  }
}

function validateRepositoryUrl(repositoryUrl) {
  let parsed;
  try {
    parsed = new URL(repositoryUrl);
  } catch {
    throw new RelayCliError("--repo-url must be an HTTPS URL", 2);
  }
  if (parsed.protocol !== "https:") {
    throw new RelayCliError("--repo-url must be an HTTPS URL", 2);
  }
}

function validatePort(port) {
  if (!/^\d+$/.test(String(port))) {
    throw new RelayCliError("--wizard-port must be an integer", 2);
  }
  const value = Number(port);
  if (!Number.isSafeInteger(value) || value < 1 || value > 65535) {
    throw new RelayCliError("--wizard-port is out of range", 2);
  }
}

function bootstrapUrl(ref) {
  return `${DEFAULT_BOOTSTRAP_REPOSITORY}/${ref}/scripts/bootstrap-relay.sh`;
}

async function downloadBootstrap(parsed, fetchImpl) {
  const response = await fetchImpl(bootstrapUrl(parsed.ref), {
    headers: { accept: "text/plain" },
  });
  if (!response?.ok) {
    const status = response ? `${response.status} ${response.statusText || ""}`.trim() : "unknown response";
    throw new RelayCliError(`could not download Relay bootstrap (${status})`);
  }
  const script = await response.text();
  if (Buffer.byteLength(script, "utf8") > MAX_BOOTSTRAP_BYTES) {
    throw new RelayCliError("Relay bootstrap script is unexpectedly large");
  }
  if (!script.startsWith("#!/usr/bin/env bash")) {
    throw new RelayCliError("downloaded Relay bootstrap is not a Bash script");
  }

  const directory = await mkdtemp(join(tmpdir(), "mycomesh-relay-"));
  const path = join(directory, "bootstrap-relay.sh");
  await writeFile(path, script, { encoding: "utf8", mode: 0o700 });
  return { directory, path };
}

function toBootstrapArgs(parsed) {
  const args = [
    "--ref",
    parsed.ref,
    "--repo-url",
    parsed.repositoryUrl,
    "--wizard-port",
    String(parsed.wizardPort),
  ];
  if (parsed.sourceDir) args.push("--source-dir", parsed.sourceDir);
  if (parsed.noBrowser) args.push("--no-browser");
  if (parsed.noStart) args.push("--no-start");
  if (parsed.dryRun) args.push("--dry-run");
  return args;
}

function runBootstrap(scriptPath, args, { env, spawn }) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn("bash", [scriptPath, ...args], {
        env: { ...env },
        stdio: "inherit",
      });
    } catch (error) {
      reject(new RelayCliError(`could not start bash: ${error.message}`));
      return;
    }
    child.once("error", (error) => {
      reject(new RelayCliError(`could not start bash: ${error.message}`));
    });
    child.once("exit", (code, signal) => {
      if (typeof code === "number") {
        resolve(code);
      } else {
        resolve(128 + signalNumber(signal));
      }
    });
  });
}

function signalNumber(signal) {
  const signals = { SIGINT: 2, SIGTERM: 15, SIGHUP: 1 };
  return signals[signal] || 1;
}

export { toBootstrapArgs };
