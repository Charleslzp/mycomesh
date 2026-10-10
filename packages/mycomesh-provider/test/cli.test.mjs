// The launcher drives Docker; a fake docker on PATH records every invocation.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const BIN = new URL("../bin/mycomesh-provider.mjs", import.meta.url).pathname;
const ADDRESS = "0x" + "ab".repeat(20);

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), "mycomesh-provider-"));
  const log = join(dir, "docker.log");
  const fake = join(dir, "docker");
  // Emulates `mycomesh key new/address` and `provider register` by acting on the /keys mount.
  writeFileSync(fake, `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify(args) + "\\n");
const keys = args[args.findIndex((a, i) => args[i - 1] === "-v" && a.endsWith(":/keys"))]?.split(":")[0];
if (args.includes("address") && args.includes("/keys/owner.json")) { console.log("0x" + "cd".repeat(20)); process.exit(0); }
if (args.includes("key") && args.includes("new")) fs.writeFileSync(keys + "/signer.key", "0x" + "11".repeat(32) + "\\n");
if (args.includes("key") && args.includes("address")) console.log(${JSON.stringify(ADDRESS)});
if (args.includes("earnings")) console.log(JSON.stringify({ claimable: 1620, in_escrow: 5412, holdback: 180, clean_volume: 2000,
  exposure_cap: 50000000, provider: { registered_at: 1 }, reputation: { counterparties: 1, counted_volume: 2000, jury_eligible: false },
  jury_rules: { min_counted_volume: 1000000, min_counterparties: 5, min_age: 604800, fraud_cooldown: 2592000, per_counterparty_cap: 10000000, jury_size: 5, threshold: 3 } }, null, 2));
if (args.includes("claim")) console.log(JSON.stringify({ owner: "0x1", claimed: 1620 }));
if (args[0] === "ps") console.log("Up 3 minutes");
if (args[0] === "logs" && args.includes("mycomesh-provider-login")) console.log("\u001b[94mOpen https://auth.openai.com/codex/device\u001b[0m and enter ABCD-12345");
else if (args[0] === "logs") console.log("INFO mycomesh provider linking");
if (args.includes("--keystore")) { if (!process.env.MYCOMESH_KEY_PASSWORD) process.exit(3); fs.writeFileSync(keys + "/owner.json", JSON.stringify({ address: "cd".repeat(20) })); }
if (args.includes("register") && args.includes("MYCOMESH_KEY_PASSWORD") && !process.env.MYCOMESH_KEY_PASSWORD) process.exit(4);
if (args.includes("register")) { fs.writeFileSync(keys + "/identity.json", "{}"); console.log("provider owner 0x0000000000000000000000000000000000000001 signer ${ADDRESS} peer p"); }
`);
  chmodSync(fake, 0o755);
  const home = join(dir, "home");
  const run = (...args) => spawnSync(process.execPath, [BIN, ...args, "--home", home],
    { encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH}` } });
  const calls = () => existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").map((line) => JSON.parse(line)) : [];
  const env = { ...process.env, PATH: `${dir}:${process.env.PATH}` };
  return { dir, home, run, calls, env };
}

test("init, register and start drive the V11 image with the bundled network", () => {
  const { dir, home, run, calls } = sandbox();
  assert.match(run("start").stderr, /run `mycomesh-provider init`/);
  const init = run("init");
  assert.equal(init.status, 0, init.stderr);
  assert.match(init.stdout, new RegExp(ADDRESS));
  assert.equal(readFileSync(join(home, "keys/signer.key"), "utf8").length, 67);

  assert.match(run("start").stderr, /not registered/);
  const owner = join(dir, "owner.key");
  writeFileSync(owner, "0x" + "22".repeat(32));
  const register = run("register", "--owner-key-file", owner, "--operator-id", "me/1");
  assert.equal(register.status, 0, register.stderr);
  const registerCall = calls().at(-1);
  assert.ok(registerCall.includes(`${owner}:/owner.key:ro`));
  assert.deepEqual(registerCall.slice(registerCall.indexOf("provider")), ["provider", "register", "--network",
    "/config/mycomesh-v11-sepolia.json", "--owner-key", "/owner.key", "--signer-key", "/keys/signer.key",
    "--identity", "/keys/identity.json", "--operator-id", "me/1", "--model", "gpt-5.5", "--tier", "1", "--daily-capacity", "10000000"]);

  assert.match(run("start").stderr, /no Codex login/);
  writeFileSync(join(home, "codex/auth.json"), "{}");
  const start = run("start");
  assert.equal(start.status, 0, start.stderr);
  const serve = calls().at(-1);
  assert.equal(serve[0], "run");
  assert.ok(serve.includes("--restart") && serve.includes("mycomesh-provider"));
  assert.ok(serve.includes(`${join(home, "codex")}:/codex`));
  assert.ok(serve.includes("ghcr.io/charleslzp/mycomesh:latest"));
  assert.deepEqual(serve.slice(serve.indexOf("provider"), serve.indexOf("provider") + 4),
    ["provider", "serve", "--network", "/config/mycomesh-v11-sepolia.json"]);
  assert.ok(serve.includes("--codex-home"));
  assert.equal(JSON.parse(readFileSync(join(home, "provider.json"), "utf8")).operator_id, "me/1");
});

test("API-key backends pass the key by environment name only", () => {
  const { home, run, calls } = sandbox();
  run("init");
  writeFileSync(join(home, "keys/identity.json"), "{}");
  assert.match(run("start", "--backend", "anthropic").stderr, /--api-key-env/);
  assert.match(run("start", "--backend", "anthropic", "--api-key-env", "ANTHROPIC_API_KEY").stderr, /ANTHROPIC_API_KEY is not set/);
  process.env.ANTHROPIC_API_KEY = "sk-test";
  let start;
  try {
    start = run("start", "--backend", "anthropic", "--api-key-env", "ANTHROPIC_API_KEY", "--model", "claude-sonnet-4-6");
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
  }
  assert.equal(start.status, 0, start.stderr);
  const serve = calls().at(-1);
  assert.equal(serve[serve.indexOf("-e", serve.indexOf("HOME=/tmp") + 1) + 1], "ANTHROPIC_API_KEY");
  assert.ok(!serve.includes("--codex-home"));
  assert.deepEqual(serve.slice(-4), ["--api-key-env", "ANTHROPIC_API_KEY", "--model", "claude-sonnet-4-6"]);
});

test("open-weight servers need only a base URL; earnings and claim reuse the registered owner", () => {
  const { dir, home, run, calls } = sandbox();
  run("init");
  const owner = join(dir, "owner.key");
  writeFileSync(owner, "0x" + "22".repeat(32));
  run("register", "--owner-key-file", owner);
  const start = run("start", "--backend", "openai", "--base-url", "http://10.0.0.5:11434/v1", "--model", "llama-3.3-70b");
  assert.equal(start.status, 0, start.stderr);
  assert.deepEqual(calls().at(-1).slice(-4), ["--base-url", "http://10.0.0.5:11434/v1", "--model", "llama-3.3-70b"]);
  const earnings = run("earnings");
  assert.equal(earnings.status, 0, earnings.stderr);
  assert.deepEqual(calls().at(-1).slice(-8, -2), ["provider", "earnings", "--network", "/config/mycomesh-v11-sepolia.json", "--owner", "0x0000000000000000000000000000000000000001"]);
  assert.match(run("claim").stderr, /--owner-key-file/);
  const claim = run("claim", "--owner-key-file", owner);
  assert.equal(claim.status, 0, claim.stderr);
  assert.ok(calls().at(-1).includes(`${owner}:/owner.key:ro`));
});

test("the local dashboard shows status, earnings and jury progress, and only this machine may use it", async () => {
  const { dir, home, run, env } = sandbox();
  run("init");
  const owner = join(dir, "owner.key");
  writeFileSync(owner, "0x" + "22".repeat(32));
  run("register", "--owner-key-file", owner, "--operator-id", "me/1");
  const port = 18000 + Math.floor(Math.random() * 2000);
  const child = spawn(process.execPath, [BIN, "dashboard", "--port", String(port), "--home", home], { env });
  try {
    await new Promise((resolve) => child.stdout.once("data", resolve));
    const base = `http://127.0.0.1:${port}`;
    const page = await fetch(`${base}/`).then((r) => r.text());
    assert.match(page, /MycoMesh Provider/);
    const status = await fetch(`${base}/api/status`).then((r) => r.json());
    assert.equal(status.container, "Up 3 minutes");
    assert.equal(status.operator_id, "me/1");
    assert.equal(status.signer, ADDRESS);
    const earnings = await fetch(`${base}/api/earnings`).then((r) => r.json());
    assert.equal(earnings.claimable, 1620);
    assert.equal(earnings.jury_rules.min_counterparties, 5);
    const claim = await fetch(`${base}/api/claim`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_key_file: owner }) }).then((r) => r.json());
    assert.equal(claim.claimed, 1620);
    const forbidden = await fetch(`${base}/api/claim`, { method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example" }, body: "{}" });
    assert.equal(forbidden.status, 403);
  } finally {
    child.kill();
  }
});

test("the dashboard onboards a Provider end to end: key, Codex login, wallet, registration", async () => {
  const { home, env, calls } = sandbox();
  const network = join(home, "..", "network.json");
  const manifest = JSON.parse(readFileSync(new URL("../networks/mycomesh-v11-sepolia.json", import.meta.url), "utf8"));
  delete manifest.faucet_url;
  writeFileSync(network, JSON.stringify(manifest));
  const port = 18000 + Math.floor(Math.random() * 2000);
  const child = spawn(process.execPath, [BIN, "--port", String(port), "--home", home, "--network", network], { env });
  try {
    await new Promise((resolve) => child.stdout.once("data", resolve));
    const base = `http://127.0.0.1:${port}`;
    const post = (path, body = {}) => fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, body: await r.json() }));
    assert.equal((await fetch(`${base}/api/status`).then((r) => r.json())).initialized, false);
    assert.equal((await post("/api/init")).status, 200);
    assert.equal((await post("/api/login")).status, 200);
    const login = await fetch(`${base}/api/login`).then((r) => r.json());
    assert.deepEqual([login.url, login.code, login.done], ["https://auth.openai.com/codex/device", "ABCD-12345", false]);
    assert.equal((await post("/api/wallet", { password: "provider wallet pw" })).status, 200);
    const status = await fetch(`${base}/api/status`).then((r) => r.json());
    assert.equal(status.wallet, true);
    assert.equal(status.owner, "0x" + "cd".repeat(20));
    const register = await post("/api/register", { password: "provider wallet pw" });
    assert.equal(register.status, 200, JSON.stringify(register.body));
    const registerCall = calls().filter((c) => c.includes("register")).at(-1);
    assert.ok(registerCall.includes("MYCOMESH_KEY_PASSWORD") && !registerCall.includes("provider wallet pw"), "password must not be in argv");
    assert.ok(registerCall.some((a) => a.endsWith("/keys/owner.json:/owner.key:ro")));
    assert.equal((await fetch(`${base}/api/status`).then((r) => r.json())).registered, true);
  } finally {
    child.kill();
  }
});

test("the bundled manifest matches the published deployment", () => {
  const bundled = new URL("../networks/mycomesh-v11-sepolia.json", import.meta.url);
  const source = new URL("../../../deployments/mycomesh-v11-sepolia.network.json", import.meta.url);
  if (existsSync(source)) assert.deepEqual(JSON.parse(readFileSync(bundled)), JSON.parse(readFileSync(source)));
});

test("any backend plugin: options and their secrets reach the container, plugins are mounted", () => {
  const { home, run, calls } = sandbox();
  run("init");
  writeFileSync(join(home, "keys/identity.json"), "{}");
  assert.match(run("start", "--backend", "myplugin", "--backend-option", "token=env:MY_PLUGIN_TOKEN").stderr, /MY_PLUGIN_TOKEN is not set/);
  process.env.MY_PLUGIN_TOKEN = "secret";
  try {
    const start = run("start", "--backend", "myplugin", "--backend-option", "token=env:MY_PLUGIN_TOKEN",
      "--backend-option", "endpoint=http://10.0.0.9:9000", "--model", "my-model");
    assert.equal(start.status, 0, start.stderr);
  } finally {
    delete process.env.MY_PLUGIN_TOKEN;
  }
  const serve = calls().at(-1);
  assert.ok(serve.includes(`${join(home, "plugins")}:/plugins:ro`));
  assert.equal(serve[serve.indexOf("MY_PLUGIN_TOKEN") - 1], "-e");
  assert.ok(!serve.join(" ").includes("secret"), "the secret itself never appears in the command");
  assert.deepEqual(serve.slice(serve.indexOf("--backend"), serve.indexOf("--backend") + 4), ["--backend", "myplugin", "--plugin-dir", "/plugins"]);
  assert.deepEqual(serve.slice(-6), ["--backend-option", "token=env:MY_PLUGIN_TOKEN", "--backend-option", "endpoint=http://10.0.0.9:9000",
    "--model", "my-model"]);
  // Remembered for the next start.
  const again = run("start");
  assert.equal(again.status, 1);
  assert.match(again.stderr, /MY_PLUGIN_TOKEN is not set/);
});

