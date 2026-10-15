// mycomesh-provider (V11): run a MycoMesh Provider in Docker with one command per step.
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { request as httpsRequest } from "node:https";

export const IMAGE = "ghcr.io/charleslzp/mycomesh:latest";
export const CONTAINER = "mycomesh-provider";
const NETWORKS = join(dirname(fileURLToPath(import.meta.url)), "../networks");
const NETWORK_FILE = "mycomesh-v11-sepolia.json";

const USAGE = `Usage: mycomesh-provider <command> [options]

  init                       create the Provider signer key (no stake is needed)
  login                      sign in to ChatGPT for Codex (device code, one time)
  wallet                     create the owner wallet here (encrypted with MYCOMESH_KEY_PASSWORD); it receives payouts
  faucet                     testnet: gas ETH for the owner wallet
  register [--owner-key-file F] [--operator-id ID]
                             bind the signer on-chain and join the jury registry (default owner: the local wallet;
                             on testnets gas comes from the faucet)
  start                      run the Provider (restarts automatically)
  status | logs | stop       inspect or stop it
  earnings                   deposit, claimable payouts, holdback, escrow and jury reputation
  claim [--owner-key-file F] pay out everything claimable (matured holdback included) to the owner
  dashboard [--port 8120]    local web dashboard on http://127.0.0.1:8120
  address                    print the signer address
  backends                   list the model backends: built in, and plugins in <home>/plugins

Options: --home DIR (default ~/.mycomesh/provider), --model ID (repeatable; default: every model of its tier the backend offers),
  --backend NAME (codex, openai, anthropic, exec, or a plugin in <home>/plugins; \`backends\` lists them),
  --capacity N (concurrent requests, default 30), --backend-option KEY=VALUE (repeatable; VALUE env:NAME passes that environment variable), --api-key-env NAME, --tier N (default: the manifest tier listing --model), --base-url URL (any OpenAI-compatible server,
  e.g. vLLM or Ollama for open-weight models),
  --codex-home DIR (reuse an existing Codex login), --image REF, --network FILE`;

function docker(args, { capture = false, stdio } = {}) {
  const result = spawnSync("docker", args, { encoding: "utf8", stdio: stdio ?? (capture ? "pipe" : "inherit") });
  if (result.error) throw new Error(`docker is required: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(capture ? (result.stderr || result.stdout || "docker failed").trim().slice(-600) : `docker ${args[0]} failed`);
  }
  return capture ? result.stdout.trim() : "";
}

function user() {
  // Files the container writes stay owned by the operator on Linux.
  return typeof process.getuid === "function" ? ["--user", `${process.getuid()}:${process.getgid()}`, "-e", "HOME=/tmp"] : [];
}

function layout(values) {
  const home = resolve(values.home || process.env.MYCOMESH_PROVIDER_HOME || join(homedir(), ".mycomesh", "provider"));
  const configPath = join(home, "provider.json");
  const config = existsSync(configPath) ? JSON.parse(readFileSync(configPath, "utf8")) : {};
  const paths = { home, keys: join(home, "keys"), data: join(home, "data"), plugins: join(home, "plugins"), config: configPath,
    codex: resolve(values["codex-home"] || config.codex_home || join(home, "codex")) };
  for (const dir of [home, paths.keys, paths.data, paths.plugins, paths.codex]) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return { paths, config };
}

function saveConfig(paths, config) {
  writeFileSync(paths.config, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

/** Mount the manifest's directory (it names its CA file relatively) and return the in-container path. */
function networkMount(values) {
  const file = resolve(values.network || join(NETWORKS, NETWORK_FILE));
  const network = JSON.parse(readFileSync(file, "utf8"));
  if (network.schema !== "mycomesh.v11.network.v1") throw new Error(`${file} is not a MycoMesh V11 network manifest`);
  return { mount: ["-v", `${dirname(file)}:/config:ro`], file: `/config/${file.split("/").pop()}` };
}

/**
 * The pricing tier whose models (in the network manifest) cover every model served. A Claude Provider
 * must not land in the OpenAI tier by default: the tier sets its price, its jury and its capability probes.
 */
export function tierFor(models, values) {
  if (values.tier) return values.tier;
  const file = resolve(values.network || join(NETWORKS, NETWORK_FILE));
  const manifest = JSON.parse(readFileSync(file, "utf8"));
  const tiers = manifest.tiers || {};
  // The model catalog names each model's tier; older manifests only list models under their tier.
  const catalogTiers = new Set(models.map((model) => manifest.models?.[model]?.tier).filter(Boolean));
  if (catalogTiers.size === 1 && models.every((model) => manifest.models?.[model])) return String([...catalogTiers][0]);
  const match = Object.entries(tiers).find(([, tier]) => models.every((model) => (tier.models || []).includes(model)));
  if (!match) {
    throw new Error(`no network tier lists ${models.join(", ")}; pass --tier N (tiers: ${Object.entries(tiers)
      .map(([n, t]) => `${n} = ${t.name}: ${(t.models || []).join("/")}`).join("; ")})`);
  }
  return match[0];
}

const withNetwork = (args, file) => args.map((arg) => (arg === "@network" ? file : arg));

// An encrypted owner key is unlocked inside the container; the password travels by environment, never argv.
const secret = () => (process.env.MYCOMESH_KEY_PASSWORD ? ["-e", "MYCOMESH_KEY_PASSWORD"] : []);

function mycomesh(values, paths, args, extra = []) {
  const network = networkMount(values);
  return docker(["run", "--rm", ...user(), ...secret(), ...network.mount, "-v", `${paths.keys}:/keys`, ...extra,
    values.image || IMAGE, ...withNetwork(args, network.file)], { capture: true });
}

/** Ask the network's testnet faucet for gas; returns the HTTP status, or null without a faucet. */
function faucet(values, address) {
  const file = resolve(values.network || join(NETWORKS, NETWORK_FILE));
  const manifest = JSON.parse(readFileSync(file, "utf8"));
  if (!manifest.faucet_url) return Promise.resolve(null);
  const ca = manifest.tls_ca_file ? readFileSync(join(dirname(file), manifest.tls_ca_file), "utf8") : undefined;
  const body = JSON.stringify({ address });
  return new Promise((resolvePromise) => {
    const req = httpsRequest(new URL(`${manifest.faucet_url}/v11/faucet`), { method: "POST", ca,
      headers: { "content-type": "application/json", "content-length": body.length } }, (res) => {
      res.resume();
      res.on("end", () => resolvePromise(res.statusCode));
    });
    req.setTimeout(300_000, () => req.destroy());
    req.on("error", () => resolvePromise(null));
    req.end(body);
  });
}

/** The owner wallet's ETH, from the manifest's RPCs (null when none answers). */
async function ethBalance(values, address) {
  const manifest = JSON.parse(readFileSync(resolve(values.network || join(NETWORKS, NETWORK_FILE)), "utf8"));
  for (const url of manifest.rpc_urls || []) {
    try {
      const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(10_000),
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBalance", params: [address, "latest"] }) });
      const body = await response.json();
      if (body.result) return Number(BigInt(body.result)) / 1e18;
    } catch {}
  }
  return null;
}

/** What went wrong, in words an operator can act on (the raw message stays at the end). */
export function explain(message) {
  const text = String(message);
  const hints = [
    [/no ETH for gas|insufficient funds/i, "The owner wallet has no ETH for gas. On testnets run `mycomesh-provider faucet`; elsewhere send it a little ETH."],
    [/wrong (key|wallet) password|MAC mismatch|could not decrypt/i, "Wrong wallet password (the one set when the owner wallet was created)."],
    [/no network tier lists/i, "That model is in no tier of this network; pick a model the network lists (see `--help`)."],
    [/Cannot connect to the Docker daemon|docker is required/i, "Docker is not running: start Docker Desktop (or the docker service) and try again."],
    [/execution reverted/i, "The chain refused the transaction; the signer may already be bound to another owner."],
  ];
  const hint = hints.find(([pattern]) => pattern.test(text));
  return hint ? `${hint[1]}\n  (${text.split("\n").pop().slice(0, 300)})` : text;
}

/** The Provider container's state and its own report (data/status.json), when that report is fresh. */
export function liveStatus(paths) {
  const inspect = spawnSync("docker", ["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}}", CONTAINER], { encoding: "utf8" });
  const [state = "absent", exitCode = "0", restarts = "0"] = inspect.status === 0 ? inspect.stdout.trim().split(" ") : [];
  let report = null;
  try { report = JSON.parse(readFileSync(join(paths.data, "status.json"), "utf8")); } catch {}
  const fresh = report && Date.now() / 1000 - report.updated_at < 30;
  const relays = fresh ? report.relays : [];
  return {
    container: state, exit_code: Number(exitCode), restarts: Number(restarts),
    relays_connected: relays.filter((r) => r.connected).length, relays_total: relays.length, relays,
    jobs: fresh ? report.jobs : null, live: state === "running" && relays.some((r) => r.connected),
  };
}

/** Wait for the container to link to a Relay (or to stop), up to `seconds`. */
export async function waitLive(paths, seconds, { now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const until = now() + seconds * 1000;
  for (;;) {
    const live = liveStatus(paths);
    if (live.live || (live.container !== "running" && live.container !== "restarting" && live.container !== "created") || now() >= until) return live;
    await sleep(2000);
  }
}

const ago = (seconds) => seconds < 90 ? `${Math.round(seconds)} s ago` : seconds < 5400 ? `${Math.round(seconds / 60)} min ago` : `${(seconds / 3600).toFixed(1)} h ago`;

export function describeLive(live) {
  if (live.container === "absent") return "not started (mycomesh-provider start)";
  if (live.container !== "running") return `stopped: the container is ${live.container} (exit ${live.exit_code}); see mycomesh-provider logs`;
  const lines = [live.live ? `live: linked to ${live.relays_connected} of ${live.relays_total} Relays` : "running, but not linked to any Relay yet"];
  for (const relay of live.relays) if (!relay.connected && relay.last_error) lines.push(`  ${relay.relay}: ${relay.last_error}`);
  const jobs = live.jobs;
  if (jobs) {
    lines.push(`today: ${jobs.served_today || 0} answered, ${jobs.refused_today || 0} refused, ${jobs.failed_today || 0} failed`
      + (jobs.last_served_at ? `; last answer ${ago(Date.now() / 1000 - jobs.last_served_at)}` : ""));
    if (jobs.last_error && Date.now() / 1000 - jobs.last_error_at < 3600) lines.push(`last backend error: ${jobs.last_error}`);
  }
  if (live.restarts) lines.push(`restarted ${live.restarts} times`);
  return lines.join("\n");
}

const tusdc = (units) => `${(Number(units) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 6 })} tUSDC`;
const myco = (wei) => `${(Number(BigInt(wei || 0) / 10n ** 14n) / 1e4).toLocaleString("en-US", { maximumFractionDigits: 4 })} MYCO`;
const when = (seconds) => seconds ? new Date(seconds * 1000).toLocaleString() : "—";

/** Earnings for people: what can be claimed now, and when the rest becomes claimable. */
export function describeEarnings(e) {
  const s = e.schedule || {};
  const lines = [`claimable now      ${tusdc(e.claimable)}${s.holdback_matured ? ` (+ ${tusdc(s.holdback_matured)} matured holdback, moved on claim)` : ""}`];
  lines.push(`in escrow          ${tusdc(e.in_escrow)}${s.escrow_next_release_at ? `  next released after ${when(s.escrow_next_release_at)}, all by ${when(s.escrow_all_released_by)}` : ""}`);
  const next = (s.holdback_maturing || [])[0];
  lines.push(`held back          ${tusdc(e.holdback)}${next ? `  next ${tusdc(next.amount)} matures ${when(next.at)}` : ""}`);
  const provider = e.myco?.roles?.provider;
  if (provider) lines.push(`MYCO claimable     ${myco(provider.claimable_wei)}${provider.blocks_waiting ? `  ${provider.blocks_waiting} more hours unlock from ${when(provider.next_unlock_at)}` : ""}`);
  lines.push(`owner wallet gas   ${(Number(e.eth_wei) / 1e18).toFixed(5)} ETH${Number(e.eth_wei) < 3e14 ? "  (too little to claim: mycomesh-provider faucet on testnets)" : ""}`);
  return lines.join("\n");
}

export function describeClaim(result) {
  const hours = Object.values(result.myco_claimed || {}).reduce((a, b) => a + b, 0);
  if (!Number(result.claimed) && !hours) return "nothing to claim yet (see mycomesh-provider earnings for when)";
  return `claimed ${tusdc(result.claimed)}${hours ? ` and ${hours} hours of MYCO` : ""} to ${result.owner}`;
}

/**
 * The container's serve command. Backends are plugins: the built-in ones (codex, openai, anthropic,
 * exec) and any *.py in <home>/plugins, mounted read-only at /plugins.
 */
export function serveArgs(values, config) {
  // No --model: the node serves every model of its tier that its backend offers (see `provider serve`).
  const models = values.model?.length ? values.model : config.models || [];
  const backend = values.backend || config.backend || "codex";
  const options = values["backend-option"]?.length ? values["backend-option"] : config.backend_options || [];
  const args = ["provider", "serve", "--network", "@network", "--signer-key", "/keys/signer.key",
    "--identity", "/keys/identity.json", "--data-dir", "/data", "--backend", backend, "--plugin-dir", "/plugins",
    "--capacity", String(values.capacity || config.capacity || 30),
    "--price-input", "20", "--price-output", "2000", "--price-min", "1000"];
  if (backend === "codex") args.push("--codex-home", "/codex");
  const apiKeyEnv = values["api-key-env"] || config.api_key_env;
  const baseUrl = values["base-url"] || config.base_url;
  if (backend === "openai" || backend === "anthropic") {
    // A local open-weight server usually needs no key; hosted APIs do.
    if (!apiKeyEnv && !baseUrl) throw new Error(`--backend ${backend} needs --api-key-env NAME or --base-url URL`);
  }
  if (backend !== "codex") {
    if (apiKeyEnv) args.push("--api-key-env", apiKeyEnv);
    if (baseUrl) args.push("--base-url", baseUrl);
  }
  for (const option of options) {
    if (!/^[A-Za-z0-9_]+=/.test(option)) throw new Error(`--backend-option needs KEY=VALUE, got ${option}`);
    args.push("--backend-option", option);
  }
  for (const model of models) args.push("--model", model);
  // Secrets reach the container by environment name only: the API key and every option's env:NAME.
  const envNames = [...new Set([apiKeyEnv, ...options.map((o) => o.split("=").slice(1).join("=")).filter((v) => v.startsWith("env:"))
    .map((v) => v.slice(4))].filter(Boolean))];
  return { args, models, backend, apiKeyEnv, baseUrl, options, envNames };
}

export async function main(argv = process.argv.slice(2), { stdout = process.stdout } = {}) {
  const { values, positionals } = parseArgs({
    args: argv, allowPositionals: true,
    options: {
      home: { type: "string" }, image: { type: "string" }, network: { type: "string" },
      "owner-key-file": { type: "string" }, "operator-id": { type: "string" }, model: { type: "string", multiple: true },
      backend: { type: "string" }, "api-key-env": { type: "string" }, "codex-home": { type: "string" },
      "base-url": { type: "string" }, owner: { type: "string" }, port: { type: "string", default: "8120" },
      "no-browser": { type: "boolean" }, tier: { type: "string" }, "daily-capacity": { type: "string" },
      capacity: { type: "string" }, wait: { type: "string" },
      "backend-option": { type: "string", multiple: true },
      help: { type: "boolean" }, version: { type: "boolean" }, json: { type: "boolean" },
    },
  });
  // With no command, open the local dashboard: every step can be done from the browser.
  const [command = "dashboard"] = positionals;
  if (values.version) {
    stdout.write(`${JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version}\n`);
    return 0;
  }
  if (values.help || command === "help") { stdout.write(`${USAGE}\n`); return 0; }
  const { paths, config } = layout(values);
  const signer = join(paths.keys, "signer.key");
  if (command === "dashboard") {
    const { serveDashboard } = await import("./dashboard.mjs");
    await serveDashboard(main, { home: values.home, port: Number(values.port) });
    const url = `http://127.0.0.1:${values.port}/`;
    stdout.write(`MycoMesh Provider dashboard: ${url}\n`);
    if (process.stdout.isTTY && !process.env.CI && !values["no-browser"]) {
      const opener = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
      spawn(opener[0], opener[1], { stdio: "ignore", detached: true }).on("error", () => {}).unref();
    }
    return new Promise(() => {});
  }
  if (command === "config") {
    // What the dashboard shows; the signer address is cached after its first lookup.
    let address = config.signer;
    if (!address && existsSync(signer)) {
      address = mycomesh(values, paths, ["key", "address", "/keys/signer.key"]);
      saveConfig(paths, { ...config, signer: address });
    }
    const models = config.models || ["gpt-6.1-sol"];
    let plan = null;
    try {
      const tier = tierFor(models, values);
      const manifest = JSON.parse(readFileSync(resolve(values.network || join(NETWORKS, NETWORK_FILE)), "utf8"));
      plan = { models, tier: Number(tier), tier_name: manifest.tiers?.[tier]?.name || null,
        daily_capacity: Number(values["daily-capacity"] || config.daily_capacity || 10_000_000) };
    } catch {}
    stdout.write(`${JSON.stringify({ home: paths.home, initialized: existsSync(signer), registered: existsSync(join(paths.keys, "identity.json")),
      codex_login: existsSync(join(paths.codex, "auth.json")), wallet: existsSync(join(paths.keys, "owner.json")),
      codex_home: paths.codex, ...config, signer: address, plan, live: liveStatus(paths) })}\n`);
    return 0;
  }

  if (command === "init") {
    if (!existsSync(signer)) mycomesh(values, paths, ["key", "new", "/keys/signer.key"]);
    chmodSync(signer, 0o600);
    stdout.write(`Provider signer ${mycomesh(values, paths, ["key", "address", "/keys/signer.key"])}\n`);
    stdout.write(`keys in ${paths.keys}; next: mycomesh-provider login, then register\n`);
    return 0;
  }
  if (!existsSync(signer) && command !== "dashboard") throw new Error("no signer key; run `mycomesh-provider init` first");
  if (command === "address") {
    stdout.write(`${mycomesh(values, paths, ["key", "address", "/keys/signer.key"])}\n`);
    return 0;
  }
  if (command === "login") {
    docker(["run", "--rm", "-it", ...user(), "-e", "CODEX_HOME=/codex", "-v", `${paths.codex}:/codex`,
      "--entrypoint", "codex", values.image || IMAGE, "login", "--device-auth"]);
    return 0;
  }
  const wallet = join(paths.keys, "owner.json");
  const ownerMount = () => {
    if (values["owner-key-file"]) return ["-v", `${resolve(values["owner-key-file"])}:/owner.key:ro`];
    if (!existsSync(wallet)) throw new Error("no owner wallet: run `mycomesh-provider wallet` or pass --owner-key-file");
    if (!process.env.MYCOMESH_KEY_PASSWORD) throw new Error("set MYCOMESH_KEY_PASSWORD to unlock the owner wallet");
    return ["-v", `${wallet}:/owner.key:ro`];
  };
  if (command === "wallet") {
    if (!existsSync(wallet)) {
      if (!process.env.MYCOMESH_KEY_PASSWORD) throw new Error("set MYCOMESH_KEY_PASSWORD (at least 8 characters) to encrypt the wallet");
      mycomesh(values, paths, ["key", "new", "/keys/owner.json", "--keystore"]);
    }
    const owner = mycomesh(values, paths, ["key", "address", "/keys/owner.json"]).toLowerCase();
    saveConfig(paths, { ...config, owner });
    stdout.write(`owner wallet ${owner} (${wallet})\n`);
    return 0;
  }
  if (command === "faucet") {
    const owner = values.owner || config.owner;
    if (!owner) throw new Error("create the owner wallet first");
    const status = await faucet(values, owner);
    stdout.write(`${status === 200 ? "funded" : `faucet answered ${status ?? "nothing"}`} ${owner}\n`);
    return status === 200 ? 0 : 2;
  }
  if (command === "register") {
    const mount = ownerMount();
    const operator = values["operator-id"] || config.operator_id || `${hostname()}/${randomBytes(4).toString("hex")}`;
    // The models only pick the tier here; which ones are served is decided when the node starts.
    const models = values.model?.length ? values.model : config.models || ["gpt-6.1-sol"];
    const tier = tierFor(models, values);
    const capacity = values["daily-capacity"] || String(config.daily_capacity || 10_000_000);
    stdout.write(`registering ${models.join(", ")} in tier ${tier}, daily capacity ${Number(capacity) / 1e6} tUSDC, operator ${operator}\n`);
    if (!values["owner-key-file"] && config.owner) {
      stdout.write("1/2 gas for the registration transactions...\n");
      const status = await faucet(values, config.owner); // at most once a day
      const eth = await ethBalance(values, config.owner);
      if (eth !== null && eth < 0.0005) {
        throw new Error(`the owner wallet ${config.owner} has ${eth.toFixed(5)} ETH, not enough for gas`
          + (status === null ? "" : ` (the testnet faucet answered ${status}; it gives once a day per address and IP)`)
          + "; send it a little Sepolia ETH and run register again");
      }
    }
    stdout.write("2/2 binding the signer, joining the registry and the pricing tier (about a minute)...\n");
    const output = mycomesh(values, paths, ["provider", "register", "--network", "@network", "--owner-key", "/owner.key",
      "--signer-key", "/keys/signer.key", "--identity", "/keys/identity.json", "--operator-id", operator,
      ...models.flatMap((model) => ["--model", model]), "--tier", tier, "--daily-capacity", capacity], mount);
    const ownerMatch = output.match(/provider owner (0x[0-9a-fA-F]{40})/);
    saveConfig(paths, { ...config, operator_id: operator, ...(values.model?.length ? { models } : {}), daily_capacity: Number(capacity),
      ...(ownerMatch ? { owner: ownerMatch[1].toLowerCase() } : {}) });
    stdout.write(`${output.split("\n").pop()}\noperator ${operator}; next: mycomesh-provider start\n`);
    return 0;
  }
  if (command === "start") {
    const { args, models, backend, apiKeyEnv, baseUrl, options, envNames } = serveArgs(values, config);
    for (const name of envNames) if (!(name in process.env)) throw new Error(`${name} is not set in this shell`);
    if (!existsSync(join(paths.keys, "identity.json"))) throw new Error("not registered; run `mycomesh-provider register` first");
    if (backend === "codex" && !existsSync(join(paths.codex, "auth.json"))) {
      throw new Error(`no Codex login in ${paths.codex}; run \`mycomesh-provider login\` (or pass --codex-home)`);
    }
    spawnSync("docker", ["rm", "-f", CONTAINER], { stdio: "ignore" });
    const network = networkMount(values);
    docker(["run", "-d", "--init", "--name", CONTAINER, "--restart", "unless-stopped", ...user(), ...network.mount,
      "-v", `${paths.keys}:/keys:ro`, "-v", `${paths.data}:/data`, "-v", `${paths.codex}:/codex`,
      "-v", `${paths.plugins}:/plugins:ro`, ...envNames.flatMap((name) => ["-e", name]),
      "--log-opt", "max-size=20m", "--log-opt", "max-file=3",
      values.image || IMAGE, ...withNetwork(args, network.file)], { capture: true });
    saveConfig(paths, { ...config, models, backend, ...(apiKeyEnv ? { api_key_env: apiKeyEnv } : {}),
      ...(baseUrl ? { base_url: baseUrl } : {}), backend_options: options,
      ...(values["codex-home"] ? { codex_home: paths.codex } : {}) });
    stdout.write(`started ${CONTAINER} (${backend}: ${models.length ? models.join(", ") : "every model of its tier the backend offers"}); waiting until it links to the Relays...\n`);
    const live = await waitLive(paths, Number(values["wait"] ?? 90));
    stdout.write(`${describeLive(live)}\n`);
    if (live.container !== "running") {
      stdout.write(`${spawnSync("docker", ["logs", "--tail", "20", CONTAINER], { encoding: "utf8" }).stderr || ""}\n`);
      return 1;
    }
    return 0;
  }
  if (command === "backends") {
    stdout.write(`${mycomesh(values, paths, ["provider", "backends", "--network", "@network", "--plugin-dir", "/plugins"],
      ["-v", `${paths.plugins}:/plugins:ro`])}\n`);
    return 0;
  }
  if (command === "status") {
    const live = liveStatus(paths);
    stdout.write(values.json ? `${JSON.stringify(live)}\n` : `${describeLive(live)}\n`);
    return live.live ? 0 : 2;
  }
  if (command === "earnings") {
    const owner = values.owner || config.owner;
    if (!owner) throw new Error("--owner ADDRESS is required (it is remembered after register)");
    const raw = mycomesh(values, paths, ["provider", "earnings", "--network", "@network", "--owner", owner,
      ...(existsSync(signer) ? ["--signer-key", "/keys/signer.key"] : [])]);
    stdout.write(values.json || !process.stdout.isTTY || stdout !== process.stdout ? `${raw}\n` : `${describeEarnings(JSON.parse(raw))}\n`);
    return 0;
  }
  if (command === "claim") {
    const run = () => mycomesh(values, paths, ["provider", "claim", "--network", "@network", "--owner-key", "/owner.key"], ownerMount());
    let raw;
    try { raw = run(); } catch (error) {
      // An owner wallet without gas on a testnet: ask the faucet once, then claim again.
      if (!/no ETH for gas/.test(error.message) || !config.owner || (await faucet(values, config.owner)) !== 200) throw new Error(explain(error.message));
      raw = run();
    }
    const result = JSON.parse(raw.split("\n").pop());
    stdout.write(values.json || stdout !== process.stdout || !process.stdout.isTTY ? `${JSON.stringify(result)}\n` : `${describeClaim(result)}\n`);
    return 0;
  }
  if (command === "logs") { docker(["logs", "-f", "--tail", "100", CONTAINER]); return 0; }
  if (command === "stop") { docker(["rm", "-f", CONTAINER], { capture: true }); stdout.write("stopped\n"); return 0; }
  throw new Error(`unknown command ${command}\n${USAGE}`);
}
