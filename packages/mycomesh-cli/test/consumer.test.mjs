import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CONSUMER_RELEASE_VERSION,
  DEFAULT_NODE_IMAGE,
  isApiInvocation,
  main,
  parseArguments,
  toScriptArgs,
} from "../src/consumer.mjs";

function capture() {
  let value = "";
  return {
    stream: { write(chunk) { value += String(chunk); } },
    value: () => value,
  };
}

test("zero arguments use the immutable Consumer runtime", () => {
  const parsed = parseArguments([], { MYCOMESH_CODEX_COMMAND: "codex" });
  assert.match(DEFAULT_NODE_IMAGE, /^ghcr\.io\/charleslzp\/mycomesh-node@sha256:[a-f0-9]{64}$/);
  assert.deepEqual(toScriptArgs(parsed), [
    "--node-image",
    DEFAULT_NODE_IMAGE,
    "--codex-command",
    "codex",
  ]);
});

test("launcher options and Codex arguments are forwarded", () => {
  const parsed = parseArguments([
    "--no-browser",
    "--no-codex",
    "--ready-timeout",
    "60",
    "--proxy",
    "http://127.0.0.1:10792",
    "--",
    "--full-auto",
  ], { MYCOMESH_CODEX_COMMAND: "codex" });
  assert.deepEqual(toScriptArgs(parsed), [
    "--node-image",
    DEFAULT_NODE_IMAGE,
    "--codex-command",
    "codex",
    "--ready-timeout",
    "60",
    "--proxy",
    "http://127.0.0.1:10792",
    "--no-browser",
    "--no-codex",
    "--",
    "--full-auto",
  ]);
});

test("mutable image overrides are rejected", () => {
  assert.throws(() => parseArguments(["--node-image", "example/consumer:latest"], {}), /pinned by digest/);
  assert.throws(() => parseArguments(["--node-image", "example/consumer@sha256:abc"], {}), /pinned by digest/);
  assert.throws(() => parseArguments(["--ready-timeout", "0"], {}), /positive integer/);
});

test("request subcommands remain stateless CLI invocations", () => {
  assert.equal(isApiInvocation([]), false);
  assert.equal(isApiInvocation(["health"]), true);
  assert.equal(isApiInvocation(["--base-url", "https://example.test/v1", "models"]), true);
  assert.equal(isApiInvocation(["responses", "hello"]), true);
  assert.equal(isApiInvocation(["--no-browser"]), false);
});

test("help and version do not start bash", async () => {
  for (const [args, expected] of [
    [["--help"], /No options are needed/],
    [["--version"], new RegExp(CONSUMER_RELEASE_VERSION.replaceAll(".", "\\."))],
  ]) {
    const stdout = capture();
    let spawned = false;
    const code = await main(args, {
      env: {},
      stdout: stdout.stream,
      spawn() { spawned = true; throw new Error("must not spawn"); },
    });
    assert.equal(code, 0);
    assert.equal(spawned, false);
    assert.match(stdout.value(), expected);
  }
});

test("launcher starts the bundled script and preserves the environment", async () => {
  const calls = [];
  const code = await main(["--no-browser", "--dry-run"], {
    env: { TEST_CONSUMER_ENV: "present", MYCOMESH_CODEX_COMMAND: "codex" },
    scriptPath: "/package/start-consumer.sh",
    spawn(command, args, options) {
      calls.push({ command, args, options });
      const child = new EventEmitter();
      queueMicrotask(() => child.emit("exit", 0, null));
      return child;
    },
  });

  assert.equal(code, 0);
  assert.equal(calls[0].command, "bash");
  assert.deepEqual(calls[0].args, [
    "/package/start-consumer.sh",
    "--node-image",
    DEFAULT_NODE_IMAGE,
    "--codex-command",
    "codex",
    "--no-browser",
    "--dry-run",
  ]);
  assert.equal(calls[0].options.env.TEST_CONSUMER_ENV, "present");
});

test("release constant matches the npm package", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const requestCli = await readFile(new URL("../src/cli.mjs", import.meta.url), "utf8");
  const startupScript = await readFile(new URL("../scripts/start-consumer.sh", import.meta.url), "utf8");
  const repositoryScript = await readFile(new URL("../../../scripts/run-consumer-codex.sh", import.meta.url), "utf8");
  assert.equal(CONSUMER_RELEASE_VERSION, packageJson.version);
  assert.match(requestCli, new RegExp(`const CLI_VERSION = "${packageJson.version.replaceAll(".", "\\.")}"`));
  assert.equal(packageJson.dependencies["@openai/codex"], "0.146.0");
  assert.match(startupScript, /export NO_PROXY="\$MYCOMESH_CONSUMER_NO_PROXY"/);
  assert.match(startupScript, /export no_proxy="\$MYCOMESH_CONSUMER_NO_PROXY"/);
  assert.doesNotMatch(startupScript, /\$\{http_proxy:-|\$\{HTTP_PROXY:-|\$\{all_proxy:-|\$\{ALL_PROXY:-/);
  for (const script of [startupScript, repositoryScript]) {
    assert.match(script, /model="gpt-5\.5"/);
    assert.match(script, /if ! codex_env=/);
    assert.doesNotMatch(script, /eval "\$\([^\n]*consumer-codex-env/);
  }
});
