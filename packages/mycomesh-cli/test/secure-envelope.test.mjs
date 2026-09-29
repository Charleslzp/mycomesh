import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalJson, generateIdentity, generateTransportKey, openFrame, sealJsonFrame, verifyTransportKeyBinding,
} from "../src/secure-envelope.mjs";

const PURPOSE = "mycomesh.test.envelope.v1";

test("canonical JSON matches Python sort_keys, compact, ensure_ascii=False", () => {
  assert.equal(canonicalJson({ b: 1, a: ["é", { d: null, c: true }] }), '{"a":["é",{"c":true,"d":null}],"b":1}');
});

test("sealed frames open once, only for their recipient and purpose", () => {
  const sender = generateIdentity();
  const recipient = generateIdentity();
  const key = generateTransportKey(recipient, { lifetimeSeconds: 600 });
  assert.equal(verifyTransportKeyBinding(key.binding).peerId, recipient.peerId);
  const frame = sealJsonFrame({ secret: "prompt" }, { sender, recipientBinding: key.binding, purpose: PURPOSE });
  assert.ok(!frame.toString("utf8").includes("prompt"), "plaintext must not appear in the frame");
  assert.throws(() => openFrame(frame, { recipientKey: key, expectedPurpose: "other.purpose", replaySet: new Set() }), /purpose mismatch/);
  const other = generateTransportKey(generateIdentity(), { lifetimeSeconds: 600 });
  assert.throws(() => openFrame(frame, { recipientKey: other, expectedPurpose: PURPOSE, replaySet: new Set() }), /audience|key_id/);
  const replaySet = new Set();
  const opened = openFrame(frame, { recipientKey: key, expectedPurpose: PURPOSE, replaySet, expectedSenderPeerId: sender.peerId });
  assert.deepEqual(JSON.parse(opened.payload.toString("utf8")), { secret: "prompt" });
  assert.throws(() => openFrame(frame, { recipientKey: key, expectedPurpose: PURPOSE, replaySet }), /already accepted/);
});

test("expired transport keys are refused before sealing", () => {
  const recipient = generateIdentity();
  const key = generateTransportKey(recipient, { lifetimeSeconds: 60, now: 1_000 });
  assert.throws(() => sealJsonFrame({}, { sender: generateIdentity(), recipientBinding: key.binding, purpose: PURPOSE, now: 2_000 }), /expired/);
});
