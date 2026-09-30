// The Node Consumer must agree byte-for-byte with the Python reference (mycomesh/).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { settlementKey, verifySignedReceipt } from "../src/eip712.mjs";
import { buildEvidence, evidenceHash, reportId } from "../src/disputes.mjs";
import { loadNetwork } from "../src/consumer.mjs";

const vectors = JSON.parse(readFileSync(new URL("./v11-vectors.json", import.meta.url)));

test("Python-signed receipts verify in Node", () => {
  verifySignedReceipt(vectors.signed_receipt, vectors.deployment);
  const { key, request_id: requestId } = vectors.signed_receipt.authorization;
  assert.equal(settlementKey(key, requestId), vectors.settlement_key);
});

test("tampered receipts are rejected", () => {
  const tampered = structuredClone(vectors.signed_receipt);
  tampered.receipt.actual_fee += 1;
  assert.throws(() => verifySignedReceipt(tampered, vectors.deployment));
});

test("dispute evidence hashes match the Python jury", () => {
  const { evidence } = vectors;
  const rebuilt = buildEvidence({ settlement_key: evidence.settlement_key, signed_receipt: evidence.signed_receipt,
    request: evidence.request, response: evidence.response },
  { reasonCode: evidence.allegation.reason_code, statement: evidence.allegation.statement });
  assert.deepEqual(rebuilt, evidence);
  assert.equal(evidenceHash(evidence), vectors.evidence_hash);
  assert.equal(reportId(evidence.settlement_key, `0x${"44".repeat(20)}`, vectors.evidence_hash), vectors.report_id);
});

test("the bundled Sepolia manifest is a V11 network", () => {
  const network = loadNetwork(new URL("../networks/mycomesh-v11-sepolia.json", import.meta.url).pathname);
  assert.equal(network.chain_id, 11155111);
  assert.ok(network.relays.length >= 2);
  assert.match(network.tls_ca, /BEGIN CERTIFICATE/);
});

test("probe tasks and answers match the Python Relay exactly", async () => {
  const { buildTask } = await import("../src/probes.mjs");
  for (const expected of vectors.tasks) {
    const task = buildTask(expected.kind, expected.params);
    assert.equal(task.question, expected.question, expected.kind);
    assert.equal(task.reference, expected.reference, expected.kind);
  }
});

test("probe verdicts re-grade identically and forged verdicts are caught", async () => {
  const { verifyProbeEvidence } = await import("../src/probes.mjs");
  assert.equal(verifyProbeEvidence(vectors.probe_evidence.pass, vectors.deployment).verdict, "pass");
  assert.equal(verifyProbeEvidence(vectors.probe_evidence.wrong, vectors.deployment).verdict, "wrong");
  const framed = structuredClone(vectors.probe_evidence.pass);
  framed.verdict = "wrong"; // a Relay cannot claim a correct, Provider-signed answer was wrong
  assert.throws(() => verifyProbeEvidence(framed, vectors.deployment));
  const edited = structuredClone(vectors.probe_evidence.wrong);
  edited.response = Buffer.from("{}").toString("base64"); // nor swap in an answer the Provider never signed
  assert.throws(() => verifyProbeEvidence(edited, vectors.deployment));
});

test("capability probes rebuild and grade exactly like the Python Relay", async () => {
  const { buildTask, grade } = await import("../src/probes.mjs");
  for (const expected of vectors.capability_tasks) {
    const task = buildTask(expected.kind, expected.params);
    assert.equal(task.question, expected.question, expected.kind);
    assert.equal(task.reference, expected.reference, expected.kind);
    for (const [answer, verdict] of expected.grades) assert.equal(grade(task, answer), verdict, `${expected.kind}: ${answer}`);
  }
});

test("a Provider is flagged only with 99% confidence that it misses the floor", async () => {
  const { capabilityFlagged } = await import("../src/probes.mjs");
  assert.equal(capabilityFlagged(3, 9, 0.6), false);   // too few probes to judge
  assert.equal(capabilityFlagged(5, 20, 0.75), true);  // 25% against a 75% floor
  assert.equal(capabilityFlagged(14, 20, 0.75), false); // 70%: could be an honest model's bad day
});
