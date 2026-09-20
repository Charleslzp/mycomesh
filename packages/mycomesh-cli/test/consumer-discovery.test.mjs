import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { ConsumerRelayDiscovery, discoveryCanonical, discoveryDigest, discoveryUrl, isPublicDiscoveryAddress,
  parseDiscoveryConfig, RELAY_ADMISSION_SCHEMA, RELAY_ANNOUNCEMENT_SCHEMA, RELAY_DIRECTORY_SCHEMA,
  verifyRelayAnnouncement } from "../src/consumer-discovery.mjs";
import { NativeConsumerState, verifyAuthorization } from "../src/consumer-runtime.mjs";

const fixtureKeys = [1, 2, 3, 4].map((index) => Buffer.from(index.toString(16).padStart(64, "0"), "hex"));
const account = (key) => `0x${Buffer.from(keccak_256(secp256k1.getPublicKey(key, false).subarray(1)).subarray(-20)).toString("hex")}`;
const authorities = fixtureKeys.slice(0, 3).map(account);
const relaySigner = account(fixtureKeys[3]);
const settlement = `0x${"11".repeat(20)}`;
const payout = `0x${"22".repeat(20)}`;
const now = 1790000000;
const config = { authorities, threshold: 2, refreshMs: 1000, timeoutMs: 1000, local: false,
  bridgeUrls: ["https://bridge.example"], network_id: "fixture-network", channel_id: "codex",
  chain_id: 31337, settlement_contract: settlement, protocol_version: 8 };

function signed(schema, unsigned, key) {
  const signature = secp256k1.sign(discoveryDigest(schema, unsigned), key, { lowS: true, prehash: false });
  return `0x${Buffer.concat([Buffer.from(signature.toCompactRawBytes()), Buffer.from([signature.recovery + 27])]).toString("hex")}`;
}

function announcement(changes = {}, { timestamp = now, key = fixtureKeys[3], binding = {}, admissionChanges = {}, signers = fixtureKeys.slice(0, 2) } = {}) {
  const fields = { network_id: config.network_id, channel_id: config.channel_id, chain_id: config.chain_id,
    settlement_contract: settlement, protocol_version: 8, host: "8.8.8.8", provider_port: 9901,
    public_url: "https://8.8.8.8", provider_tls: true, payment_address: payout, attestation_address: account(key), ...binding };
  const admitted = { ...fields, schema: RELAY_ADMISSION_SCHEMA, expires_at: timestamp + 3600, ...admissionChanges };
  const admission = { ...admitted, signatures: signers.map((signer) => ({ signer: account(signer), signature: signed(RELAY_ADMISSION_SCHEMA, admitted, signer) })) };
  const value = { ...fields, schema: RELAY_ANNOUNCEMENT_SCHEMA, sequence: 1, issued_at: timestamp,
    expires_at: timestamp + 240, admission, ...changes };
  return { ...value, signature: signed(RELAY_ANNOUNCEMENT_SCHEMA, value, key) };
}

test("discovered endpoints reject private, mapped, reserved, and transition IP addresses", () => {
  for (const address of ["127.0.0.1", "10.0.0.1", "100.100.100.200", "169.254.169.254", "172.16.1.2",
    "192.168.1.2", "192.0.2.1", "198.18.1.1", "255.255.255.255", "::1", "fc00::1", "fe80::1",
    "::ffff:127.0.0.1", "::ffff:8.8.8.8", "2002:0808:0808::1", "2001:db8::1", "64:ff9b::808:808"]) {
    assert.equal(isPublicDiscoveryAddress(address), false, address);
  }
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) {
    assert.equal(isPublicDiscoveryAddress(address), true, address);
  }
});

test("discovery URLs cannot supply userinfo, paths, fragments, local names, or plain HTTP", () => {
  for (const url of ["http://relay.example", "https://user@relay.example", "https://relay.example/path",
    "https://relay.example/?query=value", "https://relay.example/#fragment", "https://localhost",
    "https://host.local", "https://host.internal", "https://127.0.0.1", "https://2130706433",
    "https://[::ffff:127.0.0.1]"]) assert.throws(() => discoveryUrl(url), /Discovery|Invalid/);
  assert.throws(() => discoveryUrl("https://relay.example"), /not public/);
  assert.throws(() => discoveryUrl("https://8.8.8.8:443"), /Noncanonical/);
  assert.throws(() => discoveryUrl("https://relay.example:443", { bridge: true }), /Noncanonical/);
  assert.equal(discoveryUrl("http://127.0.0.1:8000", { local: true }), "http://127.0.0.1:8000");
});

test("local profile does not expand discovery to arbitrary private networks", () => {
  for (const url of ["http://10.0.0.1", "https://192.168.0.1", "https://169.254.169.254"]) {
    assert.throws(() => discoveryUrl(url, { local: true }), /Discovery/);
  }
});

test("signed announcements validate the independent authority quorum and exact deployment", () => {
  const record = announcement();
  assert.deepEqual(verifyRelayAnnouncement(record, config, { now }), record);
  assert.throws(() => verifyRelayAnnouncement(record, { ...config, chain_id: 1 }, { now }), /chain_id mismatch/);
  assert.throws(() => verifyRelayAnnouncement({ ...record, payment_address: authorities[0] }, config, { now }), /binding mismatch/);
  assert.throws(() => verifyRelayAnnouncement(announcement({}, { signers: fixtureKeys.slice(0, 1) }), config, { now }), /threshold/);
  assert.throws(() => verifyRelayAnnouncement(announcement({}, { signers: [fixtureKeys[0], fixtureKeys[0]] }), config, { now }), /untrusted/);
  assert.throws(() => verifyRelayAnnouncement(announcement({}, { signers: [fixtureKeys[0], fixtureKeys[3]] }), config, { now }), /untrusted/);
});

test("Python and native Node verify each other's deterministic signed announcements and digest bytes", () => {
  const record = announcement();
  const { signature, ...unsigned } = record;
  const result = JSON.parse(execFileSync(process.env.MYCOMESH_TEST_PYTHON || "python3", ["-B", "-c", [
    "import json, sys",
    "from gateway.relay_discovery import verify_announcement, sign_record, signed_digest, canonical_json, ANNOUNCEMENT_SCHEMA",
    "value = json.load(sys.stdin)",
    "record = verify_announcement(value['record'], policy=value['policy'], context=value['context'], now=value['now'])",
    "unsigned = {k: v for k, v in record.items() if k != 'signature'}",
    "record['signature'] = sign_record(ANNOUNCEMENT_SCHEMA, unsigned, '0x' + '0' * 63 + '4')",
    "print(json.dumps({'record': record, 'digest': signed_digest(ANNOUNCEMENT_SCHEMA, unsigned).hex(), 'canonical': canonical_json(unsigned).decode('ascii')}))",
  ].join("\n")], { cwd: fileURLToPath(new URL("../../..", import.meta.url)), encoding: "utf8",
    input: JSON.stringify({ record, now, policy: { authorities, threshold: 2 }, context: {
      network_id: config.network_id, channel_id: config.channel_id, chain_id: config.chain_id,
      settlement_contract: settlement, protocol_version: 8, network_profile: "testnet" } }) }));
  assert.equal(result.canonical, discoveryCanonical(unsigned));
  assert.equal(result.digest, Buffer.from(discoveryDigest(RELAY_ANNOUNCEMENT_SCHEMA, unsigned)).toString("hex"));
  assert.deepEqual(verifyRelayAnnouncement(result.record, config, { now }), result.record);
});

test("announcements reject expired, future, oversized lifetime, malformed field, and high-s signature data", () => {
  const original = announcement();
  for (const record of [announcement({ expires_at: now }), announcement({ issued_at: now + 31 }),
    announcement({ expires_at: now + 301 }), { ...original, unsigned_extra: "field" },
    { ...original, sequence: 1.5 }, announcement({}, { admissionChanges: { expires_at: now + 367 * 86400 } })]) {
    assert.throws(() => verifyRelayAnnouncement(record, config, { now }));
  }
  const bytes = Buffer.from(original.signature.slice(2), "hex");
  const high = secp256k1.CURVE.n - BigInt(`0x${bytes.subarray(32, 64).toString("hex")}`);
  Buffer.from(high.toString(16).padStart(64, "0"), "hex").copy(bytes, 32);
  bytes[64] = bytes[64] === 27 ? 28 : 27;
  assert.throws(() => verifyRelayAnnouncement({ ...original, signature: `0x${bytes.toString("hex")}` }, config, { now }), /low-s/);
  assert.throws(() => verifyRelayAnnouncement({ ...original, signature: original.signature.slice(0, -2) + "00" }, config, { now }), /recovery/);
});

test("even authority-signed DNS or private endpoints cannot enter the dynamic directory", () => {
  for (const host of ["relay.example", "127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1"]) {
    assert.throws(() => verifyRelayAnnouncement(announcement({}, { binding: { host, public_url: `https://${host}` } }), config, { now }), /not public/);
  }
  assert.throws(() => verifyRelayAnnouncement(announcement({}, { binding: { host: "1.1.1.1" } }), config, { now }), /must match/);
  assert.throws(() => verifyRelayAnnouncement(announcement({}, { binding: { provider_tls: false } }), config, { now }), /requires TLS/);
});

test("discovery requires explicit trust roots and bounded local manifest policy", () => {
  const manifest = { network_id: config.network_id, channel_id: config.channel_id, network_profile: "testnet",
    bridge_urls: config.bridgeUrls, relay_discovery: { authorities, threshold: 2 } };
  assert.equal(parseDiscoveryConfig({}, config), null);
  assert.deepEqual(parseDiscoveryConfig(manifest, config), { ...config, refreshMs: 30000, timeoutMs: 3000 });
  for (const changes of [{ threshold: 1 }, { authorities: [authorities[0], authorities[0]] }, { unknown: true },
    { refresh_seconds: 0 }, { timeout_seconds: 31 }, { authorities: [] }]) {
    assert.throws(() => parseDiscoveryConfig({ ...manifest, relay_discovery: { ...manifest.relay_discovery, ...changes } }, config));
  }
  assert.throws(() => parseDiscoveryConfig({ ...manifest, bridge_urls: Array(9).fill(config.bridgeUrls[0]) }, config));
});

async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), "myco-relay-discovery-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  return directory;
}

test("persistent high-water marks prevent rollback after expiry and restart; duplicates never renew expiry", async (t) => {
  const directory = await temporary(t);
  const cachePath = join(directory, "discovery.json");
  let timestamp = now;
  const cache = new ConsumerRelayDiscovery({ config, cachePath, now: () => timestamp });
  const current = announcement({ sequence: 20, expires_at: now + 5 });
  cache.accept(current);
  cache.accept(current);
  assert.equal(cache.active()[0].expires_at, now + 5);
  timestamp = now + 6;
  assert.equal(cache.active().length, 0);
  const restarted = new ConsumerRelayDiscovery({ config, cachePath, now: () => timestamp });
  assert.equal(restarted.active().length, 0);
  assert.throws(() => restarted.accept(announcement({ sequence: 19 })), /rollback/);
  assert.throws(() => restarted.accept(announcement({ sequence: 20 })), /equivocation/);
  restarted.accept(announcement({ sequence: 21 }));
  assert.equal(restarted.active().length, 1);
  assert.equal(JSON.parse(await readFile(cachePath, "utf8")).records.length, 1);
});

test("corrupt durable anti-replay state disables discovery instead of reopening an empty cache", async (t) => {
  const directory = await temporary(t);
  const cachePath = join(directory, "discovery.json");
  await writeFile(cachePath, "{broken");
  const cache = new ConsumerRelayDiscovery({ config, cachePath, now: () => now });
  assert.equal(cache.blocked, true);
  assert.throws(() => cache.accept(announcement()), /cache rejected/);
  assert.deepEqual(await cache.refresh(), []);
});

test("two cache writers cannot overwrite a newer durable sequence from a stale in-memory snapshot", async (t) => {
  const directory = await temporary(t);
  const cachePath = join(directory, "discovery.json");
  const first = new ConsumerRelayDiscovery({ config, cachePath, now: () => now });
  const second = new ConsumerRelayDiscovery({ config, cachePath, now: () => now });
  first.accept(announcement({ sequence: 20 }));
  assert.throws(() => second.accept(announcement({ sequence: 19 })), /rollback/);
  assert.equal(new ConsumerRelayDiscovery({ config, cachePath, now: () => now }).active()[0].sequence, 20);
  second.accept(announcement({ sequence: 21 }));
  assert.throws(() => first.accept(announcement({ sequence: 20 })), /rollback/);
});

test("a leftover cache write lock is never stolen or silently cleared after an uncertain write", async (t) => {
  const directory = await temporary(t);
  const cachePath = join(directory, "discovery.json");
  const cache = new ConsumerRelayDiscovery({ config, cachePath, now: () => now });
  cache.accept(announcement());
  await writeFile(`${cachePath}.lock`, "fixture-interrupted-writer");
  const restarted = new ConsumerRelayDiscovery({ config, cachePath, now: () => now });
  assert.equal(restarted.active().length, 1);
  assert.throws(() => restarted.accept(announcement({ sequence: 2 })), /locked/);
  assert.equal(await readFile(`${cachePath}.lock`, "utf8"), "fixture-interrupted-writer");
});

test("remembered identities are bounded and cannot be evicted by an admitted record flood", () => {
  const cache = new ConsumerRelayDiscovery({ config, now: () => now });
  for (let index = 1; index <= 64; index += 1) {
    const key = Buffer.from((1000 + index).toString(16).padStart(64, "0"), "hex");
    cache.accept(announcement({}, { key }));
  }
  assert.equal(cache.records.size, 64);
  assert.throws(() => cache.accept(announcement()), /capacity/);
  assert.equal(cache.records.size, 64);
});

async function server(t, handler) {
  const value = createServer(handler);
  await new Promise((resolve) => value.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => { value.close(resolve); value.closeAllConnections(); }));
  return `http://127.0.0.1:${value.address().port}`;
}
function json(response, value, status = 200) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

test("multi-Bridge discovery isolates malformed entries, forbids redirects, and coalesces refresh", async (t) => {
  const directory = await temporary(t);
  const record = announcement();
  let calls = 0, redirected = 0;
  const target = await server(t, (_, response) => { redirected += 1; json(response, {}); });
  const bad = await server(t, (_, response) => { response.writeHead(302, { location: target }); response.end(); });
  const good = await server(t, (_, response) => { calls += 1; json(response, { schema: RELAY_DIRECTORY_SCHEMA, relays: [{ ...record, signature: "bad" }, record] }); });
  const cache = new ConsumerRelayDiscovery({ config: { ...config, local: true, bridgeUrls: [bad, good] },
    cachePath: join(directory, "discovery.json"), now: () => now });
  await Promise.all([cache.refresh(), cache.refresh(), cache.refresh()]);
  assert.equal(cache.active().length, 1);
  assert.equal(calls, 1);
  assert.equal(redirected, 0);
});

test("Bridge outages preserve unexpired cached candidates and bound response-body stalls", async (t) => {
  const stalled = await server(t, (_, response) => { response.writeHead(200); response.write('{"schema":'); });
  const cache = new ConsumerRelayDiscovery({ config: { ...config, local: true, bridgeUrls: [stalled], timeoutMs: 75 }, now: () => now });
  cache.accept(announcement());
  const start = performance.now();
  await cache.refresh();
  assert.ok(performance.now() - start < 750);
  assert.equal(cache.active().length, 1);
  assert.match(cache.lastError, /Bridge discovery queries failed/);
});

test("directory oversized responses are not parsed or admitted", async (t) => {
  const huge = await server(t, (_, response) => { response.writeHead(200, { "content-length": String(1024 * 1024 + 1) }); response.end(); });
  const cache = new ConsumerRelayDiscovery({ config: { ...config, local: true, bridgeUrls: [huge] }, now: () => now });
  await cache.refresh();
  assert.equal(cache.records.size, 0);
});

async function runtimeFixture(t, { bridgeStall = false, healthMismatch = false, sessionSigner = `0x${"aa".repeat(20)}`, timeoutMs = 2000 } = {}) {
  const directory = await temporary(t);
  const calls = [];
  let record;
  const dynamic = await server(t, async (request, response) => {
    if (request.url === "/relay-announcement") { json(response, record); return; }
    if (request.url === "/relay/health") {
      json(response, { ok: true, v8: { enabled: true, providers: 1, models: ["gpt-5.5"], model: "gpt-5.5",
        chain_id: config.chain_id, settlement_contract: settlement, relay_payment_address: healthMismatch ? authorities[0] : payout,
        relay_signer_address: relaySigner, channel_hash: `0x${"66".repeat(32)}`, pricing_hash: `0x${"77".repeat(32)}`, pricing_version: 1,
        scheduler: { session_affinity: true, total_slots: 2 }, provider_signers: [sessionSigner] } });
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const payment = JSON.parse(Buffer.from(request.headers["payment-signature"], "base64url").toString());
    verifyAuthorization(payment);
    calls.push({ body: JSON.parse(Buffer.concat(chunks)), payment });
    json(response, { error: { message: "fixture execution outcome unknown" } }, 503);
  });
  record = announcement({}, { timestamp: Math.floor(Date.now() / 1000), binding: {
    host: "127.0.0.1", public_url: dynamic, provider_port: new URL(dynamic).port * 1, provider_tls: false } });
  const failed = await server(t, (_, response) => json(response, { error: "offline" }, 503));
  const bridge = await server(t, (_, response) => {
    if (bridgeStall) { response.writeHead(200); response.write('{"schema":'); return; }
    json(response, { schema: RELAY_DIRECTORY_SCHEMA, relays: [record] });
  });
  const path = join(directory, "network.json");
  await writeFile(path, JSON.stringify({ protocol_version: 8, chain_id: config.chain_id, settlement,
    stablecoin: payout, network_id: config.network_id, channel_id: config.channel_id, network_profile: "local",
    relay: { public_url: failed }, bridge_urls: [bridge], relay_discovery: { authorities, threshold: 2, timeout_seconds: 1 } }));
  const state = new NativeConsumerState({ env: {}, networkConfig: path, dataDir: directory,
    historyDir: join(directory, "history"), healthTimeoutMs: 100, timeoutMs });
  return { state, calls, dynamic, failed, record, setRecord: (value) => { record = value; } };
}

test("native Consumer finds an unconfigured Relay, probes identity, signs a real request, and never replays an unknown outcome", async (t) => {
  const { state, calls, dynamic } = await runtimeFixture(t);
  assert.equal(state.relayUrls.includes(dynamic), false);
  const result = await state.relayInference("/v1/responses", { model: "gpt-5.5", input: "fixture", max_output_tokens: 8 });
  assert.equal(result.status, 503);
  assert.equal(calls.length, 1);
  assert.ok(state.relayUrls.includes(dynamic));
  assert.equal(calls[0].payment.authorization.relay, payout);
  assert.equal(calls[0].payment.authorization.relay_signer, relaySigner);
});

test("health cannot substitute a payment identity authorized by no discovery certificate", async (t) => {
  const { state, calls } = await runtimeFixture(t, { healthMismatch: true });
  await assert.rejects(state.chooseRelay(), /identity differs/);
  assert.equal(calls.length, 0);
});

test("endpoint probe cannot return an older signed announcement than the Bridge candidate", async (t) => {
  const { state, record, setRecord, dynamic } = await runtimeFixture(t);
  await state.refreshRelayDiscovery();
  state.relayDiscovery.accept(announcement({ sequence: 5 }, { timestamp: record.issued_at,
    binding: { host: record.host, public_url: record.public_url, provider_port: record.provider_port, provider_tls: false } }));
  setRecord(record);
  await assert.rejects(state.relayHealth(dynamic), /does not match/);
});

for (const matches of [true, false]) {
  test(`dynamic Relay recovery ${matches ? "preserves" : "rejects a change to"} the original Provider`, async (t) => {
    const signer = `0x${"aa".repeat(20)}`;
    const { state, calls, failed } = await runtimeFixture(t, { sessionSigner: matches ? signer : `0x${"bb".repeat(20)}` });
    state.history = () => [{ accepted: true, session_id: "existing-session", relay_url: failed, provider_signer: signer }];
    await state.relayInference("/v1/responses", { model: "gpt-5.5", input: "fixture", max_output_tokens: 8 }, { "x-session-id": "existing-session" });
    assert.equal(calls.length, matches ? 1 : 0);
    if (matches) assert.equal(calls[0].body.metadata.mycomesh_provider_signer, signer);
  });
}

test("discovery stalls do not extend the caller's request deadline", async (t) => {
  const { state, calls } = await runtimeFixture(t, { bridgeStall: true, timeoutMs: 60 });
  const start = performance.now();
  const result = await state.relayInference("/v1/responses", { model: "gpt-5.5", input: "fixture" });
  assert.equal(result.status, 504);
  assert.ok(performance.now() - start < 500);
  assert.equal(calls.length, 0);
  await state.relayDiscovery.refresh();
});

test("healthy static routing does not wait for an unavailable discovery directory", async (t) => {
  const { state, dynamic } = await runtimeFixture(t, { bridgeStall: true });
  state.staticRelayUrls = [dynamic];
  state.relayUrls = [dynamic];
  const start = performance.now();
  assert.equal((await state.chooseRelay()).relayUrl, dynamic);
  assert.ok(performance.now() - start < 400);
  await state.relayDiscovery.refresh();
});

test("an announcement expiring between route selection and POST cannot authorize a new dispatch", async (t) => {
  const { state, calls, record } = await runtimeFixture(t);
  const payment = state.buildRelayPayment.bind(state);
  state.buildRelayPayment = (...args) => {
    const result = payment(...args);
    state.relayDiscovery.now = () => record.expires_at;
    return result;
  };
  const result = await state.relayInference("/v1/responses", { model: "gpt-5.5", input: "fixture" });
  assert.equal(result.status, 503);
  assert.equal(calls.length, 0);
});
