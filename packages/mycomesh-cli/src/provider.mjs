import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn as defaultSpawn } from "node:child_process";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const DEFAULT_REPOSITORY_URL = "https://github.com/Charleslzp/mycomesh";
const PROVIDER_RELEASE_VERSION = "0.1.19";
const DEFAULT_REF = "3a41cb73005d61e842ec8ab2e15a06ba749e3687";
const DEFAULT_PROVIDER_IMAGE =
  "ghcr.io/charleslzp/mycomesh-provider-codex@sha256:445108a8fc30d9b22bb2d6005b11c262f1df5f9eaa9f9b0912a13f02642594e6";
const MAX_BOOTSTRAP_BYTES = 256 * 1024;

const HELP = `Usage: mycomesh-provider [options]

Run a MycoMesh Codex Provider. No options are needed.

The default start opens and prints a local settings page, performs the official
Codex device login when needed, connects to the MycoMesh network, and verifies
health. Use --skip-provider-config for unattended restarts.

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
  --skip-provider-config Keep persisted settings/defaults without opening wizard
  --no-browser           Print the settings URL without opening a browser
  --no-start              Prepare and authenticate without starting
  --dry-run               Print the planned operations only
  -h, --help              Show this help

Proxy environment:
  MYCOMESH_PROVIDER_HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY
  http_proxy / https_proxy / all_proxy / no_proxy (uppercase also supported)

The launcher uses these values for its pinned bootstrap download. Loopback
proxy hosts are then translated to host.docker.internal for the isolated Codex
sidecar, covering both login and long-running traffic.

Examples:
  mycomesh-provider
  mycomesh-provider --configure

Runtime files default to ~/.mycomesh/provider. Docker Compose is still required
on the Provider machine; host Python and pip are not required. The loopback-only
wizard displays a new or not-yet-backed-up Provider key until its backup is
verified, then later settings pages show only its address.`;

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
    skipProviderConfig: false,
    configure: false,
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
