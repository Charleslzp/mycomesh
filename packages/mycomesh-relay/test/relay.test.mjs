import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { main, parseArguments, toBootstrapArgs } from "../src/relay.mjs";

function capture() {
  let value = "";
  return {
    stream: { write(chunk) { value += String(chunk); } },
    value: () => value,
  };
}

test("Relay parser validates onboarding options", () => {
  const parsed = parseArguments([
    "--ref", "e9468df",
    "--source-dir", "/srv/mycomesh",
    "--wizard-port", "9000",
    "--no-browser",
    "--no-start",
    "--dry-run",
  ]);
  assert.equal(parsed.ref, "e9468df");
  assert.equal(parsed.wizardPort, "9000");
  assert.deepEqual(toBootstrapArgs(parsed), [
    "--ref", "e9468df",
    "--repo-url", "https://github.com/Charleslzp/mycomesh",
    "--wizard-port", "9000",
    "--source-dir", "/srv/mycomesh",
    "--no-browser",
    "--no-start",
    "--dry-run",
  ]);
  assert.throws(() => parseArguments(["--wizard-port", "0"]), /out of range/);
  assert.throws(() => parseArguments(["--ref", "../main"]), /invalid repository ref/);
});

test("Relay help does not contact the network", async () => {
  const stdout = capture();
  const stderr = capture();
  let fetchCalled = false;
  const code = await main(["--help"], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    fetch: async () => {
      fetchCalled = true;
      throw new Error("network should not be used");
    },
  });
  assert.equal(code, 0);
  assert.equal(fetchCalled, false);
  assert.match(stdout.value(), /Usage: mycomesh-relay/);
  assert.equal(stderr.value(), "");
});

test("Relay launcher downloads the pinned script and starts bash", async () => {
  const stderr = capture();
  const calls = [];
  const script = "#!/usr/bin/env bash\nexit 0\n";
  const code = await main(["--ref", "e9468df", "--wizard-port", "9000", "--dry-run"], {
    stderr: stderr.stream,
    env: { TEST_RELAY_ENV: "present" },
    fetch: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, text: async () => script };
    },
    spawn(command, args, options) {
      calls.push({ command, args, options });
      const child = new EventEmitter();
      queueMicrotask(() => child.emit("exit", 0, null));
      return child;
    },
  });
  assert.equal(code, 0);
  assert.equal(stderr.value(), "");
  assert.equal(calls[0].url, "https://raw.githubusercontent.com/Charleslzp/mycomesh/e9468df/scripts/bootstrap-relay.sh");
  assert.equal(calls[1].command, "bash");
  assert.deepEqual(calls[1].args.slice(1), [
    "--ref", "e9468df",
    "--repo-url", "https://github.com/Charleslzp/mycomesh",
    "--wizard-port", "9000",
    "--dry-run",
  ]);
  assert.equal(calls[1].options.env.TEST_RELAY_ENV, "present");
});
