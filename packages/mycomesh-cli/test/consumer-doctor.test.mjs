import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { main } from "../src/consumer.mjs";

function capture() {
  let value = "";
  return { stream: { write(chunk) { value += String(chunk); } }, value: () => value };
}

test("consumer doctor json is read-only and reports first-run setup", async () => {
  const root = await mkdtemp(join(tmpdir(), "myco-consumer-doctor-"));
  const output = capture();
  try {
    const code = await main(["--doctor-json", "--data-dir", join(root, "consumer"), "--relay", "https://relay.example"], {
      env: { HOME: root }, stdout: output.stream, stderr: output.stream,
      fetch: async () => ({ ok: true, status: 200, body: { cancel: async () => {} } }),
    });
    assert.equal(code, 0);
    const report = JSON.parse(output.value());
    assert.equal(report.schema, "mycomesh.consumer.doctor.v1");
    assert.equal(report.status, "setup_required");
    assert.equal(report.checks.find((check) => check.id === "payment_key").status, "setup_required");
    assert.equal(report.checks.find((check) => check.id === "relay_health").status, "ready");
    assert.deepEqual(await readdir(root), []);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("consumer doctor detects an invalid persisted key without exposing it", async () => {
  const root = await mkdtemp(join(tmpdir(), "myco-consumer-doctor-invalid-"));
  const dataDir = join(root, "consumer");
  await mkdir(dataDir);
  await writeFile(join(dataDir, "payment-key"), "secret-invalid-key\n", { mode: 0o600 });
  const output = capture();
  try {
    const code = await main(["--doctor-json", "--data-dir", dataDir, "--relay", "https://relay.example"], {
      env: { HOME: root }, stdout: output.stream, stderr: output.stream,
      fetch: async () => ({ ok: false, status: 503, body: { cancel: async () => {} } }),
    });
    assert.equal(code, 1);
    const report = JSON.parse(output.value());
    assert.equal(report.status, "blocked");
    assert.equal(report.checks.find((check) => check.id === "payment_key").status, "blocked");
    assert.doesNotMatch(output.value(), /secret-invalid-key/);
    assert.equal((await readFile(join(dataDir, "payment-key"), "utf8")), "secret-invalid-key\n");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("consumer doctor distinguishes partial Relay health as degraded", async () => {
  const root = await mkdtemp(join(tmpdir(), "myco-consumer-doctor-degraded-"));
  const dataDir = join(root, "consumer");
  await mkdir(dataDir);
  const output = capture();
  try {
    const code = await main([
      "--doctor-json",
      "--data-dir", dataDir,
      "--relay", "https://relay-a.example,https://relay-b.example",
    ], {
      env: { HOME: root, MYCOMESH_V8_PAYMENT_KEY: `0x${"11".repeat(32)}` },
      stdout: output.stream,
      stderr: output.stream,
      fetch: async (url) => url.includes("relay-a")
        ? { ok: true, status: 200, body: { cancel: async () => {} } }
        : { ok: false, status: 503, body: { cancel: async () => {} } },
    });
    assert.equal(code, 0);
    const report = JSON.parse(output.value());
    assert.equal(report.status, "degraded");
    assert.equal(report.checks.find((check) => check.id === "relay_health").status, "degraded");
  } finally { await rm(root, { recursive: true, force: true }); }
});
