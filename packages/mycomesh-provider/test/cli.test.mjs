// The launcher drives Docker; a fake docker on PATH records every invocation.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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
if (args.includes("key") && args.includes("new")) fs.writeFileSync(keys + "/signer.key", "0x" + "11".repeat(32) + "\\n");
if (args.includes("key") && args.includes("address")) console.log(${JSON.stringify(ADDRESS)});
if (args.includes("register")) { fs.writeFileSync(keys + "/identity.json", "{}"); console.log("provider owner 0x1 signer ${ADDRESS} peer p"); }
`);
  chmodSync(fake, 0o755);
  const home = join(dir, "home");
  const run = (...args) => spawnSync(process.execPath, [BIN, ...args, "--home", home],
    { encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH}` } });
  const calls = () => existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").map((line) => JSON.parse(line)) : [];
  return { dir, home, run, calls };
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
    "--identity", "/keys/identity.json", "--operator-id", "me/1", "--model", "gpt-5.5"]);

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
  const start = run("start", "--backend", "anthropic", "--api-key-env", "ANTHROPIC_API_KEY", "--model", "claude-sonnet-4-6");
  assert.equal(start.status, 0, start.stderr);
  const serve = calls().at(-1);
  assert.equal(serve[serve.indexOf("-e", serve.indexOf("HOME=/tmp") + 1) + 1], "ANTHROPIC_API_KEY");
  assert.ok(!serve.includes("--codex-home"));
  assert.deepEqual(serve.slice(-4), ["--api-key-env", "ANTHROPIC_API_KEY", "--model", "claude-sonnet-4-6"]);
});

test("the bundled manifest matches the published deployment", () => {
  const bundled = new URL("../networks/mycomesh-v11-sepolia.json", import.meta.url);
  const source = new URL("../../../deployments/mycomesh-v11-sepolia.network.json", import.meta.url);
  if (existsSync(source)) assert.deepEqual(JSON.parse(readFileSync(bundled)), JSON.parse(readFileSync(source)));
});
