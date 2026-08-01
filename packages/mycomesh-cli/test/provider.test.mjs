import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  main,
  parseArguments,
  PROVIDER_RELEASE_VERSION,
  toBootstrapArgs,
} from "../src/provider.mjs";

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
  assert.throws(
    () => parseArguments(["--repo-url", "https://example.com/owner/repo"]),
    /github\.com owner\/repository/,
  );
  assert.throws(
    () => parseArguments(["--configure", "--skip-provider-config"]),
    /either --configure or --skip-provider-config/,
  );
});

test("provider zero-argument defaults are release-pinned and independent of cwd", () => {
  const parsed = parseArguments([], { HOME: "/Users/provider" });

  assert.equal(PROVIDER_RELEASE_VERSION, "0.1.8");
  assert.equal(parsed.ref, "dc8e8bdd4f63e74ee4571c94db31f11fb8c40c7d");
  assert.equal(parsed.sourceDir, "/Users/provider/.mycomesh/provider/releases/0.1.8");
  assert.equal(parsed.operatorConfig, "/Users/provider/.mycomesh/provider/settings.json");
  assert.deepEqual(toBootstrapArgs(parsed), [
    "--ref",
    "dc8e8bdd4f63e74ee4571c94db31f11fb8c40c7d",
    "--repo-url",
    "https://github.com/Charleslzp/mycomesh",
    "--source-dir",
    "/Users/provider/.mycomesh/provider/releases/0.1.8",
    "--provider-image",
    "ghcr.io/charleslzp/mycomesh-provider-codex@sha256:b8af036eae0174a3c98bcf39c12115bb88795a19a96c3dd5d2e731006a7cfeec",
  ]);

  const configure = parseArguments(["--configure"], { HOME: "/Users/provider" });
  assert.equal(toBootstrapArgs(configure).at(-1), "--configure");
});

test("provider release pin matches the published package version", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../../package.json", import.meta.url), "utf8"),
  );
  assert.equal(PROVIDER_RELEASE_VERSION, packageJson.version);
});

test("provider custom refs use an isolated checkout cache", () => {
  const first = parseArguments(["--ref", "review/a"], { HOME: "/Users/provider" });
  const second = parseArguments(["--ref", "review/b"], { HOME: "/Users/provider" });

  assert.notEqual(first.sourceDir, second.sourceDir);
  assert.match(first.sourceDir, /^\/Users\/provider\/\.mycomesh\/provider\/releases\/0\.1\.8-[a-f0-9]{12}$/);
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
  assert.match(stdout.value(), /Usage: mycomesh-provider/);
  assert.match(stdout.value(), /No options are needed/);
  assert.equal(stderr.value(), "");
});

test("provider launcher downloads the pinned script and starts bash", async () => {
  const stdout = capture();
  const stderr = capture();
  const calls = [];
  const script = "#!/usr/bin/env bash\nexit 0\n";
  const code = await main([
    "--ref",
    "e9468df",
    "--source-dir",
    "/tmp/provider-home/provider",
    "--image-tag",
    "sha-e9468df",
    "--dry-run",
  ], {
    env: { TEST_PROVIDER_ENV: "present", HOME: "/tmp/provider-home" },
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
    "--source-dir",
    "/tmp/provider-home/provider",
    "--image-tag",
    "sha-e9468df",
    "--dry-run",
  ]);
  assert.equal(calls[1].options.env.TEST_PROVIDER_ENV, "present");
  assert.equal(
    calls[1].options.env.MYCOMESH_PROVIDER_OPERATOR_CONFIG,
    "/tmp/provider-home/.mycomesh/provider/settings.json",
  );
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
