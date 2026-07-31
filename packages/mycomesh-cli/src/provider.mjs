import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn as defaultSpawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DEFAULT_REPOSITORY_URL = "https://github.com/Charleslzp/mycomesh";
const DEFAULT_REF = "main";
const DEFAULT_IMAGE_TAG = "latest";
const DEFAULT_BOOTSTRAP_REPOSITORY = "https://raw.githubusercontent.com/Charleslzp/mycomesh";
const MAX_BOOTSTRAP_BYTES = 256 * 1024;

const HELP = `Usage: mycomesh provider [options]

Start a MycoMesh Codex Provider through the Docker-backed bootstrap installer.
The first run opens local Provider settings and performs the official
interactive Codex device login.

Bootstrap options:
  --ref REF              Git branch, tag, or commit (default: main)
  --repo-url URL         HTTPS repository URL for the Provider checkout
  --source-dir PATH      Persistent checkout directory (default: ./mycomesh)

Image and login options:
  --image-tag TAG        Published image tag (default: latest)
  --provider-image IMAGE Complete image tag or digest
  --ghcr-username NAME   Username for an interactive GHCR login
  --ghcr-login           Run an interactive GHCR login
  --skip-codex-login     Reuse the existing Codex Docker volume
  --skip-provider-config Keep persisted settings/defaults without opening wizard
  --no-browser           Print the settings URL without opening a browser
  --no-start              Prepare and authenticate without starting
  --dry-run               Print the planned operations only
  -h, --help              Show this help

Proxy environment:
  MYCOMESH_PROVIDER_HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY
  http_proxy / https_proxy / all_proxy / no_proxy (uppercase also supported)

Loopback proxy hosts are translated to host.docker.internal for the isolated
Codex sidecar. Proxy values are inherited by login and long-running traffic.

Examples:
  npx --yes --package=github:Charleslzp/mycomesh#main mycomesh provider
  mycomesh-provider --ref e9468df --image-tag sha-e9468df

The npm command is only a launcher. Docker Compose is still required on the
Provider machine, and the launcher never accepts or stores wallet private keys
or Codex credentials.`;

class ProviderCliError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.name = "ProviderCliError";
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
      throw new ProviderCliError("Node.js 20 or newer is required");
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
    const exitCode = error instanceof ProviderCliError ? error.exitCode : 1;
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`mycomesh provider: ${message}\n`);
    return exitCode;
  }
}

export function parseArguments(argv, env = process.env) {
  const parsed = {
    ref: env.MYCOMESH_REF || DEFAULT_REF,
    repositoryUrl: env.MYCOMESH_REPOSITORY_URL || DEFAULT_REPOSITORY_URL,
    sourceDir: env.MYCOMESH_SOURCE_DIR || undefined,
    imageTag: env.MYCOMESH_IMAGE_TAG || undefined,
    providerImage: env.MYCOMESH_PROVIDER_IMAGE || undefined,
    ghcrUsername: env.GHCR_USERNAME || undefined,
    ghcrLogin: false,
    skipCodexLogin: false,
    skipProviderConfig: false,
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
    if (token === "--ghcr-login") {
      parsed.ghcrLogin = true;
      continue;
    }
    if (token === "--skip-codex-login") {
      parsed.skipCodexLogin = true;
      continue;
    }
    if (token === "--skip-provider-config") {
      parsed.skipProviderConfig = true;
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
      throw new ProviderCliError(`unexpected argument: ${token}`, 2);
    }

    const separator = token.indexOf("=");
    const name = separator === -1 ? token : token.slice(0, separator);
    let value = separator === -1 ? undefined : token.slice(separator + 1);
    if (value === undefined) {
      index += 1;
      value = argv[index];
    }
    if (value === undefined || value === "") {
      throw new ProviderCliError(`${name} requires a value`, 2);
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
      case "--image-tag":
        parsed.imageTag = value;
        break;
      case "--provider-image":
        parsed.providerImage = value;
        break;
      case "--ghcr-username":
        parsed.ghcrUsername = value;
        break;
      default:
        throw new ProviderCliError(`unknown option: ${name}`, 2);
    }
  }

  if (parsed.imageTag && parsed.providerImage) {
    throw new ProviderCliError("use either --image-tag or --provider-image, not both", 2);
  }
  validateRef(parsed.ref);
  validateRepositoryUrl(parsed.repositoryUrl);
  return parsed;
}

function validateRef(ref) {
  if (
    typeof ref !== "string" ||
    !/^[A-Za-z0-9._/-]{1,160}$/.test(ref) ||
    ref.includes("..") ||
    ref.startsWith("/")
  ) {
    throw new ProviderCliError("invalid repository ref", 2);
  }
}

function validateRepositoryUrl(repositoryUrl) {
  let parsed;
  try {
    parsed = new URL(repositoryUrl);
  } catch {
    throw new ProviderCliError("--repo-url must be an HTTPS URL", 2);
  }
  if (parsed.protocol !== "https:") {
    throw new ProviderCliError("--repo-url must be an HTTPS URL", 2);
  }
}

function bootstrapUrl(ref) {
  return `${DEFAULT_BOOTSTRAP_REPOSITORY}/${ref}/scripts/bootstrap-provider.sh`;
}

async function downloadBootstrap(parsed, fetchImpl) {
  const response = await fetchImpl(bootstrapUrl(parsed.ref), {
    headers: { accept: "text/plain" },
  });
  if (!response?.ok) {
    const status = response ? `${response.status} ${response.statusText || ""}`.trim() : "unknown response";
    throw new ProviderCliError(`could not download Provider bootstrap (${status})`);
  }
  const script = await response.text();
  if (Buffer.byteLength(script, "utf8") > MAX_BOOTSTRAP_BYTES) {
    throw new ProviderCliError("Provider bootstrap script is unexpectedly large");
  }
  if (!script.startsWith("#!/usr/bin/env bash")) {
    throw new ProviderCliError("downloaded Provider bootstrap is not a Bash script");
  }

  const directory = await mkdtemp(join(tmpdir(), "mycomesh-provider-"));
  const path = join(directory, "bootstrap-provider.sh");
  await writeFile(path, script, { encoding: "utf8", mode: 0o700 });
  return { directory, path };
}

function toBootstrapArgs(parsed) {
  const args = ["--ref", parsed.ref, "--repo-url", parsed.repositoryUrl];
  if (parsed.sourceDir) args.push("--source-dir", parsed.sourceDir);
  if (parsed.providerImage) {
    args.push("--provider-image", parsed.providerImage);
  } else if (parsed.imageTag) {
    args.push("--image-tag", parsed.imageTag);
  } else {
    args.push("--image-tag", DEFAULT_IMAGE_TAG);
  }
  if (parsed.ghcrUsername) args.push("--ghcr-username", parsed.ghcrUsername);
  if (parsed.ghcrLogin) args.push("--ghcr-login");
  if (parsed.skipCodexLogin) args.push("--skip-codex-login");
  if (parsed.skipProviderConfig) args.push("--skip-provider-config");
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
      reject(new ProviderCliError(`could not start bash: ${error.message}`));
      return;
    }
    child.once("error", (error) => {
      reject(new ProviderCliError(`could not start bash: ${error.message}`));
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
  return { SIGHUP: 1, SIGINT: 2, SIGTERM: 15 }[signal] ?? 1;
}

export { HELP as PROVIDER_HELP, toBootstrapArgs };
