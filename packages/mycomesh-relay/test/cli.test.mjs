// The Relay launcher drives Docker; a fake docker on PATH records every invocation.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const BIN = new URL("../bin/mycomesh-relay.mjs", import.meta.url).pathname;
const OWNER = "0x" + "ab".repeat(20);

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), "mycomesh-relay-"));
  const log = join(dir, "docker.log");
  const fake = join(dir, "docker");
  writeFileSync(fake, `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify(args) + "\\n");
const keys = args[args.findIndex((a, i) => args[i - 1] === "-v" && /:\\/keys(:ro)?$/.test(a))]?.split(":")[0];
if (args.includes("key") && args.includes("new")) fs.writeFileSync(keys + "/" + args.at(-1).split("/").pop(), "0x" + "11".repeat(32));
if (args.includes("key") && args.includes("address")) console.log(${JSON.stringify(OWNER)});
if (args.includes("cert")) { fs.writeFileSync(keys + "/relay.crt", "cert"); console.log("f".repeat(64)); }
if (args.includes("register")) console.log("  0xabc\\nrelay owner ${OWNER} signer 0x1\\nannounced https://203.0.113.7:10443#sha256=" + "f".repeat(64));
`);
  chmodSync(fake, 0o755);
  const network = join(dir, "network.json");
  const manifest = JSON.parse(readFileSync(new URL("../networks/mycomesh-v11-sepolia.json", import.meta.url), "utf8"));
  delete manifest.faucet_url;
  writeFileSync(network, JSON.stringify(manifest));
  const home = join(dir, "home");
  const run = (...args) => spawnSync(process.execPath, [BIN, ...args, "--home", home, "--network", network],
    { encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH}` } });
  const calls = () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").map((line) => JSON.parse(line)) : []);
  return { home, run, calls };
}

test("init, register and start announce a pinned, CA-free Relay", () => {
  const { home, run, calls } = sandbox();
  assert.match(run("start").stderr, /init/);
  const init = run("init", "--public-ip", "203.0.113.7");
  assert.equal(init.status, 0, init.stderr);
  assert.match(init.stdout, new RegExp(OWNER));
  assert.ok(existsSync(join(home, "keys/owner.key")) && existsSync(join(home, "keys/signer.key")) && existsSync(join(home, "keys/relay.crt")));
  assert.ok(calls().some((c) => c.includes("cert") && c.includes("203.0.113.7")));
  assert.match(run("start").stderr, /register/);
  const register = run("register");
  assert.equal(register.status, 0, register.stderr);
  assert.match(register.stdout, /#sha256=/);
  const registerCall = calls().at(-1);
  assert.deepEqual(registerCall.slice(registerCall.indexOf("--public-host"), registerCall.indexOf("--public-host") + 2), ["--public-host", "203.0.113.7"]);
  assert.ok(registerCall.includes("/keys/relay.crt"));
  const start = run("start", "--with-keeper");
  assert.equal(start.status, 0, start.stderr);
  const [keeper, relay] = [calls().at(-1), calls().at(-3)];
  assert.ok(relay.includes("10443:10443") && relay.includes("10991:10991"));
  assert.ok(relay.includes("0.0.0.0:10443") && relay.includes("/keys/relay.key"));
  assert.ok(keeper.includes("keeper") && keeper.includes("/keys/owner.key"));
});

test("the bundled manifest matches the published deployment", () => {
  const bundled = new URL("../networks/mycomesh-v11-sepolia.json", import.meta.url);
  const source = new URL("../../../deployments/mycomesh-v11-sepolia.network.json", import.meta.url);
  if (existsSync(source)) assert.deepEqual(JSON.parse(readFileSync(bundled)), JSON.parse(readFileSync(source)));
});
