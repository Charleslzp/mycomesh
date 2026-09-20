import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ConsumerHistoryLedger } from "../src/consumer-history.mjs";

const KEY = `0x${"11".repeat(20)}`;
const OTHER_KEY = `0x${"22".repeat(20)}`;
const CONTRACT = `0x${"33".repeat(20)}`;
const OWNER = `0x${"44".repeat(20)}`;
const ID = `0x${"aa".repeat(32)}`;
const ID2 = `0x${"bb".repeat(32)}`;
const TX = `0x${"cc".repeat(32)}`;

function setup(t) {
  const directory = mkdtempSync(join(tmpdir(), "myco-history-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const options = { localPath: join(directory, "local.jsonl"), sharedDir: join(directory, "shared"), chainId: 11155111, contract: CONTRACT, keyAddress: KEY };
  const ledger = new ConsumerHistoryLedger(options);
  return { directory, options, ledger };
}

function entry(overrides = {}) {
  return { request_id: ID, timestamp: 100, status: "pending", accepted: true, provider: OWNER, input_tokens: 7, output_tokens: 2, actual_fee_units: 2000, ...overrides };
}

test("shares one scoped ledger across separate Consumer data directories", (t) => {
  const { directory, options, ledger } = setup(t);
  const second = new ConsumerHistoryLedger({ ...options, localPath: join(directory, "second", "history.jsonl") });
  ledger.append(entry());
  second.append(entry({ request_id: ID2, timestamp: 101 }));
  assert.equal(ledger.history(0).length, 2);
  assert.equal(second.history(0).length, 2);
  assert.deepEqual(ledger.history(1).map((item) => item.request_id), [ID2]);
  assert.equal(ledger.history(0)[0].key_address, KEY);
  assert.equal(ledger.history(0)[0].chain_id, 11155111);
});

test("chain, settlement contract and payment key each isolate history", (t) => {
  const { directory, options, ledger } = setup(t);
  ledger.append(entry());
  const variants = [{ keyAddress: OTHER_KEY }, { chainId: 1 }, { contract: OWNER }];
  variants.forEach((scope, index) => {
    const other = new ConsumerHistoryLedger({ ...options, ...scope, localPath: join(directory, `other-${index}.jsonl`) });
    assert.deepEqual(other.history(0), []);
    assert.notEqual(other.sharedPath, ledger.sharedPath);
  });
});

test("imports only current local legacy entries whose key is explicitly identifiable", (t) => {
  const { options, ledger } = setup(t);
  const own = entry({ settlement_key: `v8:${KEY}:${ID}` });
  const wrong = entry({ request_id: ID2, settlement_key: `v8:${OTHER_KEY}:${ID2}` });
  writeFileSync(options.localPath, [own, wrong, entry({ request_id: `0x${"dd".repeat(32)}` })].map(JSON.stringify).join("\n") + "\n");
  assert.equal(ledger.history(0).length, 1);
  assert.equal(ledger.lastDiagnostics.importedEntries, 1);
  assert.equal(ledger.lastDiagnostics.skippedLocalLines, 2);
  const snapshot = readFileSync(ledger.sharedPath, "utf8");
  ledger.history(0);
  assert.equal(ledger.lastDiagnostics.importedEntries, 0);
  assert.equal(readFileSync(ledger.sharedPath, "utf8"), snapshot);
});

test("legacy record with an explicit current key can be imported without v8 string", (t) => {
  const { options, ledger } = setup(t);
  writeFileSync(options.localPath, JSON.stringify(entry({ key_address: KEY })) + "\n");
  assert.equal(ledger.history(0).length, 1);
});

test("does not scan sibling instance histories during migration", (t) => {
  const { directory, ledger } = setup(t);
  writeFileSync(join(directory, "unrelated.jsonl"), JSON.stringify(entry({ settlement_key: `v8:${KEY}:${ID}` })) + "\n");
  assert.deepEqual(ledger.history(0), []);
});

test("rejects mismatching explicit scope even when the v8 key prefix matches", (t) => {
  const { options, ledger } = setup(t);
  assert.throws(() => ledger.append(entry({ key_address: OTHER_KEY })), /conflicting scope/);
  assert.throws(() => ledger.append(entry({ chain_id: 1 })), /conflicting scope/);
  assert.throws(() => ledger.append(entry({ settlement_contract: OWNER })), /conflicting scope/);
  assert.throws(() => ledger.append(entry({ settlement_key: `v8:${KEY}:${ID2}` })), /conflicting scope/);
  writeFileSync(options.localPath, JSON.stringify(entry({ key_address: OTHER_KEY, settlement_key: `v8:${KEY}:${ID}` })) + "\n");
  assert.deepEqual(ledger.history(0), []);
});

test("confirmed upgrades never regress when a newer pending record is appended", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry({ owner: OWNER, provider_signer: CONTRACT, session_id: "conversation-1", relay_url: "https://136.0.3.126" }));
  ledger.append(entry({ status: "confirmed", timestamp: 105, updated_at: 110, actual_fee_units: 1999, tx_hash: TX, block_number: 123, confirmations: 6, source: "chain-sync" }));
  ledger.append(entry({ timestamp: 120, actual_fee_units: 9999 }));
  const records = ledger.history(0);
  assert.equal(records.length, 1);
  assert.equal(records[0].status, "confirmed");
  assert.equal(records[0].tx_hash, TX);
  assert.equal(records[0].actual_fee_units, 1999);
  assert.equal(records[0].owner, OWNER);
  assert.equal(records[0].session_id, "conversation-1");
  assert.equal(records[0].timestamp, 100);
  assert.equal(records[0].source, "chain-sync");
});

test("a sparse chain confirmation preserves local token detail", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry());
  ledger.append({ request_id: ID, status: "confirmed", tx_hash: TX, input_tokens: null, output_tokens: null });
  const [record] = ledger.history(0);
  assert.equal(record.input_tokens, 7);
  assert.equal(record.output_tokens, 2);
  assert.equal(record.actual_fee_units, 2000);
});

test("drops secrets, prompts, payloads and raw signatures while preserving public receipt fields", (t) => {
  const { ledger } = setup(t);
  const secret = `myco_sk_${"Q".repeat(43)}`;
  ledger.append(entry({ owner: OWNER, provider_signer: CONTRACT, session_id: "session-safe", tx_hash: TX, private_key: "do-not-store", api_key: secret, authorization: { value: secret }, signed_receipt: { signature: "do-not-store" }, prompt: "private text", model: secret, relay_url: `https://user:${secret}@example.test`, source: "Bearer sensitive-token" }));
  const record = ledger.history(0)[0];
  assert.equal(record.owner, OWNER);
  assert.equal(record.provider_signer, CONTRACT);
  assert.equal(record.tx_hash, TX);
  for (const path of [ledger.localPath, ledger.sharedPath]) {
    const contents = readFileSync(path, "utf8");
    assert.doesNotMatch(contents, /do-not-store|myco_sk_|private text|sensitive-token|signed_receipt|authorization|api_key|private_key/);
  }
  assert.equal(record.model, undefined);
  assert.equal(record.relay_url, undefined);
});

test("corrupt and oversized lines are ignored; appending repairs a truncated last line", (t) => {
  const { options, ledger } = setup(t);
  writeFileSync(options.localPath, `{broken}\n${"x".repeat(17000)}\n{partial`);
  ledger.append(entry());
  assert.equal(ledger.history(0).length, 1);
  assert.equal(ledger.lastDiagnostics.skippedLocalLines, 3);
});

test("duplicate entries in both journals count once", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry());
  ledger.append(entry());
  ledger.append(entry());
  assert.equal(ledger.history(0).length, 1);
});

test("protects shared directories and journal permissions", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry());
  assert.equal(statSync(ledger.sharedDir).mode & 0o777, 0o700);
  assert.equal(statSync(ledger.scopeDirectory).mode & 0o777, 0o700);
  assert.equal(statSync(ledger.sharedPath).mode & 0o777, 0o600);
  assert.equal(statSync(ledger.localPath).mode & 0o777, 0o600);
});

test("refuses symlink journals without overwriting their targets", (t) => {
  const { directory, ledger } = setup(t);
  const destination = join(directory, "target");
  writeFileSync(destination, "preserve");
  symlinkSync(destination, ledger.localPath);
  assert.throws(() => ledger.append(entry()));
  assert.throws(() => ledger.history());
  assert.equal(readFileSync(destination, "utf8"), "preserve");
});

test("unscoped entries inserted directly into shared journal are not trusted", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry());
  writeFileSync(ledger.sharedPath, JSON.stringify(entry({ settlement_key: `v8:${KEY}:${ID2}`, request_id: ID2 })) + "\n");
  const rows = ledger.history(0);
  assert.deepEqual(rows.map((row) => row.request_id), [ID]);
  assert.equal(ledger.lastDiagnostics.skippedSharedLines, 1);
});

test("retains confirmed_at and chain-settled provenance", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry());
  ledger.append({ request_id: ID, status: "confirmed", confirmed_at: 222, source: "chain-settled" });
  const [record] = ledger.history(0);
  assert.equal(record.confirmed_at, 222);
  assert.equal(record.source, "chain-settled");
});

test("never chmods an existing arbitrary local history parent directory", (t) => {
  const { directory, ledger } = setup(t);
  chmodSync(directory, 0o755);
  ledger.append(entry());
  assert.equal(statSync(directory).mode & 0o777, 0o755);
  assert.equal(statSync(ledger.localPath).mode & 0o777, 0o600);
});

test("failed receipts retain terminal reason and deadline until independent chain confirmation", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry());
  ledger.append(entry({ status: "failed", error_code: "authorization_expired", authorization_deadline: 110, updated_at: 120 }));
  ledger.append(entry({ status: "pending", updated_at: 130 }));
  assert.equal(ledger.history(0)[0].status, "failed");
  assert.equal(ledger.history(0)[0].error_code, "authorization_expired");
  assert.equal(ledger.history(0)[0].authorization_deadline, 110);
  ledger.append(entry({ status: "confirmed", updated_at: 140 }));
  assert.equal(ledger.history(0)[0].status, "confirmed");
});

test("unknown broadcast remains distinct from final failure", (t) => {
  const { ledger } = setup(t);
  ledger.append(entry({ status: "broadcast_unknown", error_code: "broadcast_unknown" }));
  assert.equal(ledger.history(0)[0].status, "broadcast_unknown");
});
