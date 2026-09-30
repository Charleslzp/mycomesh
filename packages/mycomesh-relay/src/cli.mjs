// mycomesh-relay (V11): run an independent MycoMesh Relay (and optionally a keeper) in Docker.
// No domain name and no certificate authority: the Relay's self-signed certificate is pinned on-chain.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const IMAGE = "ghcr.io/charleslzp/mycomesh:latest";
export const RELAY = "mycomesh-relay";
export const KEEPER = "mycomesh-keeper";
const NETWORKS = join(dirname(fileURLToPath(import.meta.url)), "../networks");
const NETWORK_FILE = "mycomesh-v11-sepolia.json";

const USAGE = `Usage: mycomesh-relay <command> [options]

  init [--public-ip IP]      create the owner and signer keys and a self-signed TLS certificate
  register [--deposit UNITS] bind the signer on-chain, fund probes, and announce the Relay (with its
                             certificate pin) in the on-chain Relay directory; testnet gas comes from the faucet
  start [--with-keeper]      run the Relay on ports 10443 (HTTPS) and 10991 (Provider links)
  status | logs | stop       inspect or stop it
  earnings | claim           the Relay's share of fees and paying it out
  address                    print the owner address (fund it with a little ETH on mainnets)

Options: --home DIR (default ~/.mycomesh/relay), --image REF, --network FILE,
  --http-port 10443, --link-port 10991`;

function docker(args, { capture = true } = {}) {
  const result = spawnSync("docker", args, { encoding: "utf8", stdio: capture ? "pipe" : "inherit" });
  if (result.error) throw new Error(`docker is required: ${result.error.message}`);
  if (result.status !== 0) throw new Error((result.stderr || result.stdout || `docker ${args[0]} failed`).trim().slice(-600));
  return capture ? result.stdout.trim() : "";
}

const user = () => (typeof process.getuid === "function" ? ["--user", `${process.getuid()}:${process.getgid()}`, "-e", "HOME=/tmp"] : []);

function layout(values) {
  const home = resolve(values.home || process.env.MYCOMESH_RELAY_HOME || join(homedir(), ".mycomesh", "relay"));
  const paths = { home, keys: join(home, "keys"), data: join(home, "data"), config: join(home, "relay.json") };
  for (const dir of [home, paths.keys, paths.data]) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const config = existsSync(paths.config) ? JSON.parse(readFileSync(paths.config, "utf8")) : {};
  return { paths, config };
}

const save = (paths, config) => writeFileSync(paths.config, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });

function network(values) {
  const file = resolve(values.network || join(NETWORKS, NETWORK_FILE));
  const manifest = JSON.parse(readFileSync(file, "utf8"));
  if (manifest.schema !== "mycomesh.v11.network.v1") throw new Error(`${file} is not a MycoMesh V11 network manifest`);
  return { file, manifest, mount: ["-v", `${dirname(file)}:/config:ro`], inside: `/config/${file.split("/").pop()}` };
}

function mycomesh(values, paths, args, extra = []) {
  const net = network(values);
  return docker(["run", "--rm", ...user(), ...net.mount, "-v", `${paths.keys}:/keys`, "-v", `${paths.data}:/data`, ...extra,
    values.image || IMAGE, ...args.map((arg) => (arg === "@network" ? net.inside : arg))]);
}

function publicIp() {
  return new Promise((resolvePromise, reject) => {
    request("https://api.ipify.org", (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => (/^[0-9a-f.:]+$/i.test(body.trim()) ? resolvePromise(body.trim()) : reject(new Error("cannot detect the public IP; pass --public-ip"))));
    }).on("error", () => reject(new Error("cannot detect the public IP; pass --public-ip"))).end();
  });
}

function faucet(net, address) {
  const { manifest, file } = net;
  if (!manifest.faucet_url) return Promise.resolve(null);
  const target = new URL(`${manifest.faucet_url}/v11/faucet`);
  const ca = manifest.tls_ca_file ? readFileSync(join(dirname(file), manifest.tls_ca_file), "utf8") : undefined;
  const body = JSON.stringify({ address });
  return new Promise((resolvePromise) => {
    const req = request(target, { method: "POST", ca, headers: { "content-type": "application/json", "content-length": body.length } }, (res) => {
      res.resume();
      res.on("end", () => resolvePromise(res.statusCode));
    });
    req.on("error", () => resolvePromise(null));
    req.end(body);
  });
}

export async function main(argv = process.argv.slice(2), { stdout = process.stdout } = {}) {
  const { values, positionals } = parseArgs({
    args: argv, allowPositionals: true,
    options: {
      home: { type: "string" }, image: { type: "string" }, network: { type: "string" }, "public-ip": { type: "string" },
      deposit: { type: "string", default: "20000000" }, "http-port": { type: "string", default: "10443" },
      "link-port": { type: "string", default: "10991" }, "with-keeper": { type: "boolean" }, help: { type: "boolean" },
      version: { type: "boolean" },
    },
  });
  const [command = "help"] = positionals;
  if (values.version) {
    stdout.write(`${JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version}\n`);
    return 0;
  }
  if (values.help || command === "help") { stdout.write(`${USAGE}\n`); return 0; }
  const { paths, config } = layout(values);
  const has = (name) => existsSync(join(paths.keys, name));

  if (command === "init") {
    const ip = values["public-ip"] || config.public_ip || await publicIp();
    for (const name of ["owner.key", "signer.key"]) if (!has(name)) mycomesh(values, paths, ["key", "new", `/keys/${name}`]);
    if (!has("relay.crt")) {
      mycomesh(values, paths, ["relay", "cert", "--network", "@network", "--public-host", ip,
        "--tls-cert", "/keys/relay.crt", "--tls-key", "/keys/relay.key"]);
    }
    const owner = mycomesh(values, paths, ["key", "address", "/keys/owner.key"]);
    save(paths, { ...config, public_ip: ip, owner });
    stdout.write(`Relay owner ${owner}\npublic endpoint https://${ip}:${values["http-port"]} (self-signed, pinned on-chain at register)\n`);
    return 0;
  }
  if (!has("owner.key")) throw new Error("run `mycomesh-relay init` first");
  if (command === "address") { stdout.write(`${config.owner}\n`); return 0; }
  if (command === "register") {
    const net = network(values);
    const status = await faucet(net, config.owner);
    if (status === 200) stdout.write("funded the owner from the testnet faucet\n");
    const output = mycomesh(values, paths, ["relay", "register", "--network", "@network", "--owner-key", "/keys/owner.key",
      "--signer-key", "/keys/signer.key", "--deposit", values.deposit, "--tls-cert", "/keys/relay.crt",
      "--public-host", config.public_ip, "--public-http-port", values["http-port"], "--public-link-port", values["link-port"]]);
    save(paths, { ...config, registered: true, http_port: values["http-port"], link_port: values["link-port"] });
    stdout.write(`${output.split("\n").filter((line) => !line.startsWith("  0x")).join("\n")}\nnext: mycomesh-relay start\n`);
    return 0;
  }
  if (command === "start") {
    if (!config.registered) throw new Error("run `mycomesh-relay register` first");
    const net = network(values);
    const http = config.http_port || values["http-port"];
    const link = config.link_port || values["link-port"];
    spawnSync("docker", ["rm", "-f", RELAY], { stdio: "ignore" });
    docker(["run", "-d", "--name", RELAY, "--restart", "unless-stopped", ...user(), ...net.mount,
      "-v", `${paths.keys}:/keys:ro`, "-v", `${paths.data}:/data`, "-p", `${http}:${http}`, "-p", `${link}:${link}`,
      "--log-opt", "max-size=20m", "--log-opt", "max-file=3", values.image || IMAGE,
      "relay", "serve", "--network", net.inside, "--owner-key", "/keys/owner.key", "--signer-key", "/keys/signer.key",
      "--data-dir", "/data/relay", "--http", `0.0.0.0:${http}`, "--link", `0.0.0.0:${link}`,
      "--tls-cert", "/keys/relay.crt", "--tls-key", "/keys/relay.key"]);
    if (values["with-keeper"]) {
      spawnSync("docker", ["rm", "-f", KEEPER], { stdio: "ignore" });
      docker(["run", "-d", "--name", KEEPER, "--restart", "unless-stopped", ...user(), ...net.mount,
        "-v", `${paths.keys}:/keys:ro`, "-v", `${paths.data}:/data`, values.image || IMAGE,
        "keeper", "serve", "--network", net.inside, "--key", "/keys/owner.key", "--data-dir", "/data/keeper"]);
    }
    stdout.write(`started ${RELAY}${values["with-keeper"] ? ` and ${KEEPER}` : ""} on https://${config.public_ip}:${http}\n`);
    return 0;
  }
  if (command === "status") {
    for (const name of [RELAY, KEEPER]) {
      const state = spawnSync("docker", ["ps", "-a", "--filter", `name=^${name}$`, "--format", "{{.Status}}"], { encoding: "utf8" }).stdout.trim();
      if (state) stdout.write(`${name}: ${state}\n`);
    }
    stdout.write(`${spawnSync("docker", ["logs", "--tail", "5", RELAY], { encoding: "utf8" }).stdout || ""}`);
    return 0;
  }
  if (command === "logs") { docker(["logs", "-f", "--tail", "100", RELAY], { capture: false }); return 0; }
  if (command === "stop") {
    for (const name of [RELAY, KEEPER]) spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" });
    stdout.write("stopped\n");
    return 0;
  }
  if (command === "earnings") {
    stdout.write(`${mycomesh(values, paths, ["relay", "earnings", "--network", "@network", "--owner", config.owner])}\n`);
    return 0;
  }
  if (command === "claim") {
    stdout.write(`${mycomesh(values, paths, ["relay", "claim", "--network", "@network", "--owner-key", "/keys/owner.key"]).split("\n").pop()}\n`);
    return 0;
  }
  throw new Error(`unknown command ${command}\n${USAGE}`);
}
