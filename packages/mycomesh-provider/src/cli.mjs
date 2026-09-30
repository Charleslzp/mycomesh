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

Options: --home DIR (default ~/.mycomesh/provider), --model ID (repeatable, default gpt-5.5),
  --backend codex|openai|anthropic, --api-key-env NAME, --base-url URL (any OpenAI-compatible server,
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
  const paths = { home, keys: join(home, "keys"), data: join(home, "data"), config: configPath,
    codex: resolve(values["codex-home"] || config.codex_home || join(home, "codex")) };
  for (const dir of [home, paths.keys, paths.data, paths.codex]) mkdirSync(dir, { recursive: true, mode: 0o700 });
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

export function serveArgs(values, config) {
  const models = values.model?.length ? values.model : config.models || ["gpt-5.5"];
  const backend = values.backend || config.backend || "codex";
  const args = ["provider", "serve", "--network", "@network", "--signer-key", "/keys/signer.key",
    "--identity", "/keys/identity.json", "--data-dir", "/data", "--backend", backend,
    "--price-input", "20", "--price-output", "2000", "--price-min", "1000"];
  if (backend === "codex") args.push("--codex-home", "/codex");
  const apiKeyEnv = values["api-key-env"] || config.api_key_env;
  const baseUrl = values["base-url"] || config.base_url;
  if (backend !== "codex") {
    // A local open-weight server usually needs no key; hosted APIs do.
    if (!apiKeyEnv && !baseUrl) throw new Error(`--backend ${backend} needs --api-key-env NAME or --base-url URL`);
    if (apiKeyEnv) args.push("--api-key-env", apiKeyEnv);
    if (baseUrl) args.push("--base-url", baseUrl);
  }
  for (const model of models) args.push("--model", model);
  return { args, models, backend, apiKeyEnv, baseUrl };
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
      help: { type: "boolean" }, version: { type: "boolean" },
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
    stdout.write(`${JSON.stringify({ home: paths.home, initialized: existsSync(signer), registered: existsSync(join(paths.keys, "identity.json")),
      codex_login: existsSync(join(paths.codex, "auth.json")), wallet: existsSync(join(paths.keys, "owner.json")),
      codex_home: paths.codex, ...config, signer: address })}\n`);
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
    if (!values["owner-key-file"] && config.owner) await faucet(values, config.owner); // at most once a day; errors are fine
    const operator = values["operator-id"] || config.operator_id || `${hostname()}/${randomBytes(4).toString("hex")}`;
    const models = values.model?.length ? values.model : config.models || ["gpt-5.5"];
    const output = mycomesh(values, paths, ["provider", "register", "--network", "@network", "--owner-key", "/owner.key",
      "--signer-key", "/keys/signer.key", "--identity", "/keys/identity.json", "--operator-id", operator,
      ...models.flatMap((model) => ["--model", model]), "--tier", values.tier || String(config.tier || 1),
      "--daily-capacity", values["daily-capacity"] || String(config.daily_capacity || 10_000_000)], mount);
    const ownerMatch = output.match(/provider owner (0x[0-9a-fA-F]{40})/);
    saveConfig(paths, { ...config, operator_id: operator, models, ...(ownerMatch ? { owner: ownerMatch[1].toLowerCase() } : {}) });
    stdout.write(`${output.split("\n").pop()}\noperator ${operator}; next: mycomesh-provider start\n`);
    return 0;
  }
  if (command === "start") {
    const { args, models, backend, apiKeyEnv, baseUrl } = serveArgs(values, config);
    if (!existsSync(join(paths.keys, "identity.json"))) throw new Error("not registered; run `mycomesh-provider register` first");
    if (backend === "codex" && !existsSync(join(paths.codex, "auth.json"))) {
      throw new Error(`no Codex login in ${paths.codex}; run \`mycomesh-provider login\` (or pass --codex-home)`);
    }
    spawnSync("docker", ["rm", "-f", CONTAINER], { stdio: "ignore" });
    const network = networkMount(values);
    docker(["run", "-d", "--name", CONTAINER, "--restart", "unless-stopped", ...user(), ...network.mount,
      "-v", `${paths.keys}:/keys:ro`, "-v", `${paths.data}:/data`, "-v", `${paths.codex}:/codex`,
      ...(apiKeyEnv ? ["-e", apiKeyEnv] : []), "--log-opt", "max-size=20m", "--log-opt", "max-file=3",
      values.image || IMAGE, ...withNetwork(args, network.file)], { capture: true });
    saveConfig(paths, { ...config, models, backend, ...(apiKeyEnv ? { api_key_env: apiKeyEnv } : {}),
      ...(baseUrl ? { base_url: baseUrl } : {}),
      ...(values["codex-home"] ? { codex_home: paths.codex } : {}) });
    stdout.write(`started ${CONTAINER} (${backend}: ${models.join(", ")}); check with mycomesh-provider status\n`);
    return 0;
  }
  if (command === "status") {
    stdout.write(`${docker(["ps", "-a", "--filter", `name=^${CONTAINER}$`, "--format", "{{.Status}}"], { capture: true }) || "not running"}\n`);
    stdout.write(`${docker(["logs", "--tail", "5", CONTAINER], { capture: true, stdio: "pipe" })}\n`);
    return 0;
  }
  if (command === "earnings") {
    const owner = values.owner || config.owner;
    if (!owner) throw new Error("--owner ADDRESS is required (it is remembered after register)");
    stdout.write(`${mycomesh(values, paths, ["provider", "earnings", "--network", "@network", "--owner", owner,
      ...(existsSync(signer) ? ["--signer-key", "/keys/signer.key"] : [])])}\n`);
    return 0;
  }
  if (command === "claim") {
    stdout.write(`${mycomesh(values, paths, ["provider", "claim", "--network", "@network", "--owner-key", "/owner.key"],
      ownerMount()).split("\n").pop()}\n`);
    return 0;
  }
  if (command === "logs") { docker(["logs", "-f", "--tail", "100", CONTAINER]); return 0; }
  if (command === "stop") { docker(["rm", "-f", CONTAINER], { capture: true }); stdout.write("stopped\n"); return 0; }
  throw new Error(`unknown command ${command}\n${USAGE}`);
}
