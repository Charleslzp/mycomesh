import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { main, parseArguments, toBootstrapArgs } from "../src/provider.mjs";

function capture() {
  let value = "";
  return {
    stream: {
      write(chunk) {
        value += String(chunk);
      },
    },
    value: () => value,
  };
}

test("provider parser applies environment defaults and forwards installer options", () => {
  const parsed = parseArguments(
    [
      "--ref",
      "e9468df",
      "--source-dir",
      "/srv/mycomesh",
      "--provider-image",
      "ghcr.io/example/provider@sha256:abc",
      "--ghcr-login",
      "--skip-codex-login",
      "--skip-provider-config",
      "--no-browser",
      "--no-start",
      "--dry-run",
    ],
    { MYCOMESH_REPOSITORY_URL: "https://github.com/example/mycomesh" },
  );

  assert.equal(parsed.ref, "e9468df");
  assert.equal(parsed.repositoryUrl, "https://github.com/example/mycomesh");
  assert.deepEqual(toBootstrapArgs(parsed), [
    "--ref",
    "e9468df",
    "--repo-url",
    "https://github.com/example/mycomesh",
    "--source-dir",
    "/srv/mycomesh",
    "--provider-image",
    "ghcr.io/example/provider@sha256:abc",
    "--ghcr-login",
    "--skip-codex-login",
    "--skip-provider-config",
    "--no-browser",
    "--no-start",
    "--dry-run",
  ]);
});

test("provider parser rejects mutable option conflicts and unsafe refs", () => {
  assert.throws(
    () => parseArguments(["--image-tag", "latest", "--provider-image", "image"]),
    /either --image-tag or --provider-image/,
  );
  assert.throws(() => parseArguments(["--ref", "../main"]), /invalid repository ref/);
  assert.throws(() => parseArguments(["--repo-url", "http://example.com/repo"]), /HTTPS/);
});

test("provider help does not contact the network", async () => {
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
  assert.match(stdout.value(), /Usage: mycomesh provider/);
  assert.equal(stderr.value(), "");
});

test("provider launcher downloads the pinned script and starts bash", async () => {
  const stdout = capture();
  const stderr = capture();
  const calls = [];
  const script = "#!/usr/bin/env bash\nexit 0\n";
  const code = await main(["--ref", "e9468df", "--image-tag", "sha-e9468df", "--dry-run"], {
    env: { TEST_PROVIDER_ENV: "present" },
    stdout: stdout.stream,
    stderr: stderr.stream,
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
  assert.equal(calls[0].url, "https://raw.githubusercontent.com/Charleslzp/mycomesh/e9468df/scripts/bootstrap-provider.sh");
  assert.equal(calls[0].options.headers.accept, "text/plain");
  assert.equal(calls[1].command, "bash");
  assert.deepEqual(calls[1].args.slice(1), [
    "--ref",
    "e9468df",
    "--repo-url",
    "https://github.com/Charleslzp/mycomesh",
    "--image-tag",
    "sha-e9468df",
    "--dry-run",
  ]);
  assert.equal(calls[1].options.env.TEST_PROVIDER_ENV, "present");
});

test("provider launcher reports bootstrap download failures", async () => {
  const stderr = capture();
  const code = await main(["--dry-run"], {
    stderr: stderr.stream,
    fetch: async () => ({ ok: false, status: 404, statusText: "Not Found" }),
  });

  assert.equal(code, 1);
  assert.match(stderr.value(), /could not download Provider bootstrap/);
});
