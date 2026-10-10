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
  assert.equal(capabilityFlagged(3, 19, 0.6), false);  // too few probes to judge
  assert.equal(capabilityFlagged(5, 20, 0.75), true);  // 25% against a 75% floor
  assert.equal(capabilityFlagged(14, 20, 0.75), false); // 70%: could be an honest model's bad day
});

test("hunters' custom questions grade exactly like the Python Relay", async () => {
  const { buildTask, grade } = await import("../src/probes.mjs");
  for (const expected of vectors.custom_tasks) {
    const task = buildTask("custom", expected.params);
    assert.equal(task.question, expected.question);
    for (const [answer, verdict] of expected.grades) assert.equal(grade(task, answer), verdict, answer);
  }
  assert.throws(() => buildTask("custom", { question: "q", reference: "maybe", grader: "number" }));
});

test("the model catalog and the tiers agree", () => {
  const network = loadNetwork(new URL("../networks/mycomesh-v11-sepolia.json", import.meta.url).pathname);
  const listed = Object.entries(network.tiers).flatMap(([tier, t]) => t.models.map((model) => [model, Number(tier)]));
  assert.deepEqual(Object.keys(network.models).sort(), listed.map(([model]) => model).sort());
  for (const [model, tier] of listed) {
    assert.equal(network.models[model].tier, tier, model);
    assert.equal(network.models[model].capabilities.tools, false, "the network does not carry tool calls yet");
  }
});

test("Anthropic and Gemini requests translate to chat, and answers back with the receipt's usage", async () => {
  const d = await import("../src/dialects.mjs");
  const ask = d.fromAnthropic({ model: "claude-sonnet-4-6", max_tokens: 300, system: [{ type: "text", text: "be brief" }],
    messages: [{ role: "user", content: "hi" }, { role: "assistant", content: [{ type: "text", text: "hello" }] },
      { role: "user", content: "again" }], temperature: 0.2, stream: true });
  assert.deepEqual(ask.messages, [{ role: "system", content: "be brief" }, { role: "user", content: "hi" },
    { role: "assistant", content: "hello" }, { role: "user", content: "again" }]);
  assert.equal(ask.maxOutputTokens, 300);
  assert.deepEqual(ask.options, { temperature: 0.2 });
  assert.equal(ask.stream, true);
  assert.throws(() => d.fromAnthropic({ model: "m", messages: [], tools: [{ name: "x" }] }), /tool use/);
  assert.throws(() => d.fromAnthropic({ model: "m", messages: [{ role: "user", content: [{ type: "image" }] }] }), /only text/);
  const receipt = { input_tokens: 12, output_tokens: 3 };
  const message = d.toAnthropic("claude-sonnet-4-6", "ok", receipt);
  assert.deepEqual([message.type, message.content, message.usage], ["message", [{ type: "text", text: "ok" }],
    { input_tokens: 12, output_tokens: 3 }]);

  assert.deepEqual(d.geminiRoute("/v1beta/models/gpt-5.5:streamGenerateContent"), { model: "gpt-5.5", stream: true });
  assert.equal(d.geminiRoute("/v1/chat/completions"), null);
  const gem = d.fromGemini({ systemInstruction: { parts: [{ text: "be brief" }] }, contents: [{ role: "user", parts: [{ text: "hi" }] },
    { role: "model", parts: [{ text: "yo" }] }], generationConfig: { maxOutputTokens: 64, temperature: 0 } }, "gpt-5.5");
  assert.deepEqual(gem.messages.map((m) => m.role), ["system", "user", "assistant"]);
  assert.deepEqual([gem.maxOutputTokens, gem.options], [64, { temperature: 0 }]);
  const answer = d.toGemini("gpt-5.5", "ok", receipt);
  assert.deepEqual([answer.candidates[0].content.parts[0].text, answer.candidates[0].finishReason, answer.usageMetadata.totalTokenCount],
    ["ok", "STOP", 15]);
});

test("dialect streams follow each vendor's event sequence", async () => {
  const d = await import("../src/dialects.mjs");
  let out = "";
  const anthropic = d.anthropicStream((chunk) => { out += chunk; }, "claude-sonnet-4-6");
  anthropic.delta("he"); anthropic.delta("llo");
  anthropic.finish("hello", { input_tokens: 4, output_tokens: 2 }, true);
  const events = [...out.matchAll(/^event: (\S+)$/gm)].map((m) => m[1]);
  assert.deepEqual(events, ["message_start", "content_block_start", "content_block_delta", "content_block_delta",
    "content_block_stop", "message_delta", "message_stop"]);
  assert.match(out, /"output_tokens":2/);
  out = "";
  const gemini = d.geminiStream((chunk) => { out += chunk; }, "gpt-5.5");
  gemini.finish("whole answer", { input_tokens: 1, output_tokens: 2 }, false); // nothing streamed: the answer arrives at once
  const chunks = out.trim().split("\n\n").map((line) => JSON.parse(line.slice(6)));
  assert.deepEqual([chunks.length, chunks[0].candidates[0].content.parts[0].text, chunks[0].candidates[0].finishReason], [1, "whole answer", "STOP"]);
});
