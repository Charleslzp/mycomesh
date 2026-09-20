import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn as defaultSpawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PROVIDER_RELEASE_VERSION } from "./release.mjs";

const DEFAULT_REPOSITORY_URL = "https://github.com/Charleslzp/mycomesh";
// Pin bootstrap to the last validated node release. The launcher itself can
// evolve independently while the runtime remains reproducible and auditable.
const DEFAULT_REF = "9d6840193dc705d98c4eb23c18e8dcf0ee1701f1";
const DEFAULT_PROVIDER_IMAGE =
  "ghcr.io/charleslzp/mycomesh-provider-codex@sha256:db13f8f9c1525d0f4826454d52b8a4db7cc4879de92dc473f76e3ea25046de09";
const MAX_BOOTSTRAP_BYTES = 256 * 1024;

const HELP = `Usage: mycomesh-provider [options]

Run a MycoMesh Codex Provider. No options are needed.

The first start opens and prints a local settings page. Later starts reuse
validated saved settings. Codex device login is shown only when needed; the
Provider then connects to the MycoMesh network and verifies health.

Common option:
  --configure            Reopen settings, then restart the Provider

Advanced bootstrap options:
  --ref REF              Git branch, tag, or commit
  --repo-url URL         HTTPS repository URL for the Provider checkout
  --source-dir PATH      Persistent checkout directory

Advanced image and login options:
  --image-tag TAG        Published image tag
  --provider-image IMAGE Complete image tag or digest
  --ghcr-username NAME   Username for an interactive GHCR login
  --ghcr-login           Run an interactive GHCR login
  --skip-codex-login     Require an existing Codex login without opening sign-in
  --reauthenticate       Back up the existing Codex login and sign in again
  --skip-provider-config Keep persisted settings/defaults without opening wizard
  --no-browser           Print the settings URL without opening a browser
  --no-start              Prepare and authenticate without starting
  --dry-run               Print the planned operations only
  --doctor                Check local prerequisites without downloading or starting anything
  -v, --version           Show the launcher version
  -h, --help              Show this help

Proxy environment:
  MYCOMESH_PROVIDER_HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY
  http_proxy / https_proxy / all_proxy / no_proxy (uppercase also supported)

The launcher uses these values for its pinned bootstrap download. Loopback
proxy hosts are then translated to host.docker.internal for the isolated Codex
sidecar, covering both login and long-running traffic.

Provider settlement signing is generated and kept inside the protected
runtime volume. The setup page asks only for the public payout address and
capacity limits; it never displays or requests a signing private key.

Examples:
  mycomesh-provider
  mycomesh-provider --configure

Runtime files default to ~/.mycomesh/provider. Docker Compose is still required
on the Provider machine; host Python and pip are not required.`;

class ProviderCliError extends Error {
  constructor(message, exitCode = 1, options = undefined) {
    super(message, options);
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
    if (parsed.version) {
      stdout.write(`${PROVIDER_RELEASE_VERSION}\n`);
      return 0;
    }
    if (parsed.doctor) return await providerDoctor({ env, stdout, run: dependencies.doctorRun });

    const fetchContext = dependencies.fetch
      ? { fetch: dependencies.fetch, close: async () => {} }
      : await createProviderFetch(env, dependencies.loadUndici);
    let bootstrap;
    try {
      bootstrap = await downloadBootstrap(parsed, fetchContext.fetch);
    } finally {
      await fetchContext.close();
    }
    try {
      const bootstrapEnv = { ...env };
      if (!bootstrapEnv.MYCOMESH_PROVIDER_OPERATOR_CONFIG) {
        bootstrapEnv.MYCOMESH_PROVIDER_OPERATOR_CONFIG = parsed.operatorConfig;
      }
      return await runBootstrap(
        bootstrap.path,
        toBootstrapArgs(parsed),
        {
          env: bootstrapEnv,
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
  const defaultHome = env.HOME || env.USERPROFILE || homedir();
  const providerHome = resolve(defaultHome, ".mycomesh", "provider");
  const parsed = {
    ref: env.MYCOMESH_REF || DEFAULT_REF,
    repositoryUrl: env.MYCOMESH_REPOSITORY_URL || DEFAULT_REPOSITORY_URL,
    sourceDir: env.MYCOMESH_SOURCE_DIR || undefined,
    operatorConfig:
      env.MYCOMESH_PROVIDER_OPERATOR_CONFIG || join(providerHome, "settings.json"),
    imageTag: env.MYCOMESH_IMAGE_TAG || undefined,
    providerImage: env.MYCOMESH_PROVIDER_IMAGE || undefined,
    ghcrUsername: env.GHCR_USERNAME || undefined,
    ghcrLogin: false,
    skipCodexLogin: false,
    reauthenticate: false,
    skipProviderConfig: false,
    configure: false,
    noBrowser: false,
    noStart: false,
    dryRun: false,
    doctor: false,
    help: false,
    version: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--doctor") { parsed.doctor = true; continue; }
    if (token === "-h" || token === "--help") {
      parsed.help = true;
      continue;
    }
    if (token === "-v" || token === "--version") {
      parsed.version = true;
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
    if (token === "--reauthenticate") {
      parsed.reauthenticate = true;
      continue;
    }
    if (token === "--skip-provider-config") {
      parsed.skipProviderConfig = true;
      continue;
    }
    if (token === "--configure") {
      parsed.configure = true;
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
  if (parsed.configure && parsed.skipProviderConfig) {
    throw new ProviderCliError("use either --configure or --skip-provider-config, not both", 2);
  }
  if (parsed.reauthenticate && parsed.skipCodexLogin) {
    throw new ProviderCliError("use either --reauthenticate or --skip-codex-login, not both", 2);
  }
  validateRef(parsed.ref);
  validateRepositoryUrl(parsed.repositoryUrl);
  if (!parsed.sourceDir) {
    const isPackagedRelease =
      parsed.ref === DEFAULT_REF && parsed.repositoryUrl === DEFAULT_REPOSITORY_URL;
    const releaseDirectory = isPackagedRelease
      ? PROVIDER_RELEASE_VERSION
      : `${PROVIDER_RELEASE_VERSION}-${createHash("sha256")
          .update(`${parsed.repositoryUrl}\0${parsed.ref}`)
          .digest("hex")
          .slice(0, 12)}`;
    parsed.sourceDir = join(providerHome, "releases", releaseDirectory);
  }
  return parsed;
}

export async function providerDoctor({ env = process.env, stdout = process.stdout, run } = {}) {
  const execute = run || ((command, args) => promisify(execFile)(command, args, { env, timeout: 8000, maxBuffer: 64 * 1024 }));
  const docker = env.MYCOMESH_DOCKER_CLI || "docker";
  const providerHome = resolve(env.HOME || env.USERPROFILE || homedir(), ".mycomesh", "provider");
  const settingsPath = env.MYCOMESH_PROVIDER_OPERATOR_CONFIG || join(providerHome, "settings.json");
  const checks = [
    ["Docker CLI", docker, ["--version"], "Install Docker Desktop or Docker Engine and add docker to PATH."],
    ["Docker Compose", docker, ["compose", "version"], "Install the Docker Compose v2 plugin."],
    ["Docker daemon", docker, ["info", "--format", "{{.ServerVersion}}"], "Start Docker Desktop or the Docker Engine service, then retry."],
    ["GNU Make", env.MAKE_BIN || "make", ["--version"], "Install GNU Make (macOS: xcode-select --install; Debian/Ubuntu: sudo apt-get install make)."],
  ];
  let failed = false;
  for (const [label, command, args, remedy] of checks) {
    try {
      if (label === "GNU Make") {
        let found = false;
        for (const candidate of env.MAKE_BIN ? [env.MAKE_BIN] : ["make", "gmake"]) {
          try { found = /GNU Make/i.test((await execute(candidate, args)).stdout || ""); } catch {}
          if (found) break;
        }
        if (!found) throw new Error("GNU Make required");
      } else await execute(command, args);
      stdout.write(`OK   ${label}\n`);
    } catch {
      failed = true;
      stdout.write(`FAIL ${label}: ${remedy}\n`);
    }
  }
  const settings = await readProviderSettings(settingsPath);
  if (settings.kind === "missing") {
    stdout.write(`INFO Provider settings: first-run setup required (${settingsPath})\n`);
  } else if (settings.kind === "invalid") {
    failed = true;
    stdout.write(`FAIL Provider settings: ${settings.message} (${settingsPath})\n`);
  } else {
    const protocol = Number.isInteger(settings.value.settlement_version)
      ? `V${settings.value.settlement_version}`
      : "protocol pending";
    const reusable = settings.value.settings_reusable === true ? "ready to reuse" : "setup confirmation required";
    stdout.write(`OK   Provider settings: ${reusable}; ${protocol}\n`);
  }
  stdout.write(`Release: provider launcher ${PROVIDER_RELEASE_VERSION}; default ref ${DEFAULT_REF}\n`);
  stdout.write("This checks local prerequisites and saved setup state only. Login, model access, network admission, network-funded capacity and any personal stake are verified during setup.\n");
  return failed ? 1 : 0;
}

async function readProviderSettings(path) {
  try {
    const raw = await readFile(path, "utf8");
    let value;
    try {
      value = JSON.parse(raw);
    } catch {
      return { kind: "invalid", message: "not valid JSON" };
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { kind: "invalid", message: "expected a JSON object" };
    }
    return { kind: "ok", value };
  } catch (error) {
    if (error?.code === "ENOENT") return { kind: "missing" };
    return { kind: "invalid", message: error instanceof Error ? error.message : String(error) };
  }
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
  const segments = parsed.pathname.replace(/\.git$/, "").split("/").filter(Boolean);
  if (parsed.hostname.toLowerCase() !== "github.com" || segments.length !== 2) {
    throw new ProviderCliError("--repo-url must identify a github.com owner/repository", 2);
  }
}

function bootstrapUrl(ref, repositoryUrl) {
  const parsed = new URL(repositoryUrl);
  const segments = parsed.pathname.replace(/\.git$/, "").split("/").filter(Boolean);
  if (parsed.hostname.toLowerCase() !== "github.com" || segments.length !== 2) {
    throw new ProviderCliError("--repo-url must identify an HTTPS github.com owner/repository", 2);
  }
  const [owner, repository] = segments.map(encodeURIComponent);
  return `https://raw.githubusercontent.com/${owner}/${repository}/${encodeURIComponent(ref)}/scripts/bootstrap-provider.sh`;
}

async function downloadBootstrap(parsed, fetchImpl) {
  const url = bootstrapUrl(parsed.ref, parsed.repositoryUrl);
  let response;
  try {
    response = await fetchImpl(url, {
      headers: { accept: "text/plain" },
    });
  } catch (error) {
    throw new ProviderCliError(
      `could not download Provider bootstrap from ${url} (${networkFailureDetail(error)})`,
      1,
      { cause: error },
    );
  }
  if (!response?.ok) {
    const status = response ? `${response.status} ${response.statusText || ""}`.trim() : "unknown response";
    throw new ProviderCliError(`could not download Provider bootstrap from ${url} (${status})`);
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

async function createProviderFetch(env, loadUndici = () => import("undici")) {
  const proxy = providerProxyOptions(env);
  if (!proxy.httpProxy && !proxy.httpsProxy) {
    if (typeof globalThis.fetch !== "function") {
      throw new ProviderCliError("Node.js 20 or newer is required");
    }
    return { fetch: globalThis.fetch, close: async () => {} };
  }

  let undici;
  try {
    undici = await loadUndici();
  } catch (error) {
    throw new ProviderCliError("could not load the Provider proxy transport", 1, {
      cause: error,
    });
  }
  const dispatchers = new Map();
  const dispatcherFor = (url) => {
    if (providerProxyBypassed(url, proxy.noProxy)) return undefined;
    const protocol = new URL(url).protocol;
    const proxyUrl = protocol === "https:"
      ? proxy.httpsProxy || proxy.httpProxy
      : proxy.httpProxy;
    if (!proxyUrl) return undefined;
    if (!dispatchers.has(proxyUrl)) {
      dispatchers.set(proxyUrl, new undici.ProxyAgent({ uri: proxyUrl }));
    }
    return dispatchers.get(proxyUrl);
  };
  return {
    fetch: (url, options) => {
      const dispatcher = dispatcherFor(url);
      return undici.fetch(
        url,
        dispatcher ? { ...options, dispatcher } : options,
      );
    },
    close: async () => {
      await Promise.all([...dispatchers.values()].map((dispatcher) => dispatcher.close()));
    },
  };
}

function providerProxyOptions(env = process.env) {
  const allProxy = firstProxyValue(
    env.MYCOMESH_PROVIDER_ALL_PROXY,
    env.all_proxy,
    env.ALL_PROXY,
  );
  const httpProxy = firstProxyValue(
    env.MYCOMESH_PROVIDER_HTTP_PROXY,
    env.http_proxy,
    env.HTTP_PROXY,
    allProxy,
  );
  const httpsProxy = firstProxyValue(
    env.MYCOMESH_PROVIDER_HTTPS_PROXY,
    env.https_proxy,
    env.HTTPS_PROXY,
    allProxy,
  );
  const noProxy = firstProxyValue(
    env.MYCOMESH_PROVIDER_NO_PROXY,
    env.no_proxy,
    env.NO_PROXY,
  );
  return {
    httpProxy: validatedProxyValue(httpProxy),
    httpsProxy: validatedProxyValue(httpsProxy),
    noProxy: validatedProxyValue(noProxy),
  };
}

function firstProxyValue(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0) ?? "";
}

function validatedProxyValue(value) {
  if (value.includes("\n") || value.includes("\r")) {
    throw new ProviderCliError("Provider proxy values must be single-line", 2);
  }
  return value;
}

function providerProxyBypassed(urlValue, noProxy) {
  if (!noProxy) return false;
  const target = new URL(urlValue);
  const hostname = target.hostname.toLowerCase();
  const port = Number.parseInt(target.port, 10)
    || (target.protocol === "https:" ? 443 : target.protocol === "http:" ? 80 : 0);
  for (const rawEntry of noProxy.split(/[,\s]+/)) {
    if (!rawEntry) continue;
    if (rawEntry === "*") return true;
    const match = rawEntry.match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
    const entryHostname = (match ? match[1] : rawEntry).toLowerCase();
    const entryPort = match ? Number.parseInt(match[2], 10) : 0;
    if (entryPort && entryPort !== port) continue;
    if (/^[.*]/.test(entryHostname)) {
      if (hostname.endsWith(entryHostname.replace(/^\*/, ""))) return true;
    } else if (hostname === entryHostname) {
      return true;
    }
  }
  return false;
}

function networkFailureDetail(error) {
  const visited = new Set();
  let current = error;
  let fallback = "network request failed";
  while (current && typeof current === "object" && !visited.has(current)) {
    visited.add(current);
    const code = typeof current.code === "string" ? current.code : "";
    const hostname = typeof current.hostname === "string" ? current.hostname : "";
    if (code || hostname) {
      return [code, hostname].filter(Boolean).join(" ");
    }
    if (typeof current.message === "string" && current.message && current.message !== "fetch failed") {
      fallback = current.message;
    }
    current = current.cause;
  }
  return fallback;
}

function toBootstrapArgs(parsed) {
  const args = ["--ref", parsed.ref, "--repo-url", parsed.repositoryUrl];
  if (parsed.sourceDir) args.push("--source-dir", parsed.sourceDir);
  if (parsed.providerImage) {
    args.push("--provider-image", parsed.providerImage);
  } else if (parsed.imageTag) {
    args.push("--image-tag", parsed.imageTag);
  } else {
    args.push("--provider-image", DEFAULT_PROVIDER_IMAGE);
  }
  if (parsed.ghcrUsername) args.push("--ghcr-username", parsed.ghcrUsername);
  if (parsed.ghcrLogin) args.push("--ghcr-login");
  if (parsed.skipCodexLogin) args.push("--skip-codex-login");
  if (parsed.reauthenticate) args.push("--reauthenticate");
  if (parsed.skipProviderConfig) args.push("--skip-provider-config");
  if (parsed.configure) args.push("--configure");
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

export {
  HELP as PROVIDER_HELP,
  networkFailureDetail,
  providerProxyBypassed,
  providerProxyOptions,
  PROVIDER_RELEASE_VERSION,
  toBootstrapArgs,
};
