import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  main,
  networkFailureDetail,
  parseArguments,
  providerProxyBypassed,
  providerProxyOptions,
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

test("provider bootstrap proxy uses explicit and lowercase environment precedence", () => {
  assert.deepEqual(
    providerProxyOptions({
      HTTP_PROXY: "http://upper.example:8080",
      http_proxy: "http://127.0.0.1:10792",
      HTTPS_PROXY: "http://upper-secure.example:8080",
      https_proxy: "http://127.0.0.1:10793",
      no_proxy: "localhost,127.0.0.1",
    }),
    {
      httpProxy: "http://127.0.0.1:10792",
      httpsProxy: "http://127.0.0.1:10793",
      noProxy: "localhost,127.0.0.1",
    },
  );
  assert.equal(
    providerProxyOptions({
      MYCOMESH_PROVIDER_HTTPS_PROXY: "http://provider-proxy.example:9443",
      https_proxy: "http://lower.example:8080",
    }).httpsProxy,
    "http://provider-proxy.example:9443",
  );
  assert.throws(
    () => providerProxyOptions({ https_proxy: "http://proxy.example\nINJECTED=1" }),
    /single-line/,
  );
  assert.equal(
    providerProxyBypassed(
      "https://raw.githubusercontent.com/owner/repository/main/bootstrap.sh",
      ".githubusercontent.com,localhost",
    ),
    true,
  );
  assert.equal(
    providerProxyBypassed("https://raw.githubusercontent.com/", "raw.githubusercontent.com:8443"),
    false,
  );
});

test("provider network errors retain the underlying code and hostname", async () => {
  const cause = Object.assign(new Error("getaddrinfo ENOTFOUND raw.githubusercontent.com"), {
    code: "ENOTFOUND",
    hostname: "raw.githubusercontent.com",
  });
  assert.equal(
    networkFailureDetail(new TypeError("fetch failed", { cause })),
    "ENOTFOUND raw.githubusercontent.com",
  );

  const stderr = capture();
  const code = await main([], {
    env: { HOME: "/Users/provider" },
    stderr: stderr.stream,
    fetch: async () => {
      throw new TypeError("fetch failed", { cause });
    },
  });
  assert.equal(code, 1);
  assert.match(stderr.value(), /ENOTFOUND raw\.githubusercontent\.com/);
});

test("provider bootstrap download uses and closes the configured Undici proxy", async () => {
  const stdout = capture();
  const stderr = capture();
  const calls = [];
  let dispatcher;

  class FakeProxyAgent {
    constructor(options) {
      this.options = options;
      this.closed = false;
      dispatcher = this;
    }

    async close() {
      this.closed = true;
    }
  }

  const code = await main([
    "--ref",
    "e9468df",
    "--source-dir",
    "/tmp/provider-proxy-test",
    "--image-tag",
    "sha-e9468df",
    "--dry-run",
  ], {
    env: {
      HOME: "/tmp/provider-home",
      http_proxy: "http://127.0.0.1:10792",
      https_proxy: "http://127.0.0.1:10793",
      no_proxy: "localhost,127.0.0.1",
    },
    stdout: stdout.stream,
    stderr: stderr.stream,
    loadUndici: async () => ({
      ProxyAgent: FakeProxyAgent,
      fetch: async (url, options) => {
        calls.push({ url, options });
        return {
          ok: true,
          text: async () => "#!/usr/bin/env bash\nexit 0\n",
        };
      },
    }),
    spawn(command, args, options) {
      calls.push({ command, args, options });
      const child = new EventEmitter();
      queueMicrotask(() => child.emit("exit", 0, null));
      return child;
    },
  });

  assert.equal(code, 0, stderr.value());
  assert.deepEqual(dispatcher.options, { uri: "http://127.0.0.1:10793" });
  assert.equal(calls[0].options.dispatcher, dispatcher);
  assert.equal(dispatcher.closed, true);
});

test("provider zero-argument defaults are release-pinned and independent of cwd", () => {
  const parsed = parseArguments([], { HOME: "/Users/provider" });

  assert.equal(PROVIDER_RELEASE_VERSION, "0.1.19");
  assert.equal(parsed.ref, "a8da4e38a4f77b8377df2b40c3256dc204f8fd2b");
  assert.equal(parsed.sourceDir, "/Users/provider/.mycomesh/provider/releases/0.1.19");
  assert.equal(parsed.operatorConfig, "/Users/provider/.mycomesh/provider/settings.json");
  assert.deepEqual(toBootstrapArgs(parsed), [
    "--ref",
    "a8da4e38a4f77b8377df2b40c3256dc204f8fd2b",
    "--repo-url",
    "https://github.com/Charleslzp/mycomesh",
    "--source-dir",
    "/Users/provider/.mycomesh/provider/releases/0.1.19",
    "--provider-image",
    "ghcr.io/charleslzp/mycomesh-provider-codex@sha256:374fae2fb3f6bcecabc21a483e614cd64af2672799bbffb46b88d05d02eec23a",
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
  assert.match(first.sourceDir, /^\/Users\/provider\/\.mycomesh\/provider\/releases\/0\.1\.19-[a-f0-9]{12}$/);
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
