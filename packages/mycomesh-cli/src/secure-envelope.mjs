// Byte-compatible port of gateway/secure_transport.py for the Consumer.
//
// A Consumer seals V10 request content directly to the Provider's transport
// key so a Relay only forwards ciphertext, and opens the Provider's sealed
// response with its own short-lived transport key. The formats, canonical
// JSON, signatures, key ids and KDF match the Python implementation exactly;
// tests/test_secure_envelope_interop.py checks both directions.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";

export const SECURE_ENVELOPE_VERSION = "mycomesh-secure-envelope-v1";
export const TRANSPORT_KEY_VERSION = "mycomesh-transport-key-v1";
export const TRANSPORT_KEY_PURPOSE = "mycomesh.transport.key_binding.v1";
export const ENVELOPE_SIGNATURE_PURPOSE = "mycomesh.transport.envelope.v1";
export const TRANSPORT_KEY_ALGORITHM = "X25519";
export const ENVELOPE_ALGORITHM = "X25519-HKDF-SHA256-CHACHA20POLY1305";

const MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;
const MAX_SECURE_FRAME_BYTES = 12 * 1024 * 1024;
const MAX_ENVELOPE_TTL_SECONDS = 5 * 60;
const MAX_TRANSPORT_KEY_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KDF_INFO = Buffer.concat([Buffer.from("mycomesh-secure-envelope-v1", "utf8"), Buffer.from([0]), Buffer.from("X25519-HKDF-SHA256-CHACHA20POLY1305", "utf8")]);
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const HEX_NONCE = /^[0-9a-f]{24}$/;
const SIGNATURE = /^[0-9a-f]{128}$/;
const KEY_ID = /^x25519_[0-9a-f]{64}$/;
const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const BINDING_FIELDS = ["version", "algorithm", "peer_id", "identity_public_key", "encryption_public_key",
  "key_id", "not_before", "expires_at", "signature"];
const ENVELOPE_FIELDS = ["version", "algorithm", "message_id", "purpose", "sender_peer_id", "sender_public_key",
  "recipient_peer_id", "recipient_public_key", "recipient_key_id", "ephemeral_public_key", "nonce",
  "issued_at", "expires_at", "ciphertext", "signature"];
const BINDING_SIGNATURE_FIELDS = ["nonce", "public_key", "purpose", "timestamp", "signature"];
const ENVELOPE_SIGNATURE_FIELDS = [...BINDING_SIGNATURE_FIELDS, "audience"];

export class SecureEnvelopeError extends Error {}

// Python: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new SecureEnvelopeError("canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const nowSeconds = (now) => (now === undefined ? Math.floor(Date.now() / 1000) : now);
const base64url = (bytes) => Buffer.from(bytes).toString("base64url");

function fail(message) { throw new SecureEnvelopeError(message); }

function exactFields(value, fields, label) {
  const keys = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) fail(`${label} fields are invalid`);
}

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${label} must be a non-negative integer`);
  return value;
}

export function peerIdFromPublicKey(publicKeyHex) {
  if (!HEX32.test(publicKeyHex)) fail("public key must be 32 bytes of lowercase hex");
  return `peer_${createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 24)}`;
}

export function generateIdentity() {
  const privateKey = randomBytes(32);
  const publicKey = hex(ed25519.getPublicKey(privateKey));
  return { privateKey: privateKey.toString("hex"), publicKey, peerId: peerIdFromPublicKey(publicKey) };
}

function signatureMessage(document, signaturePayload) {
  return Buffer.from(canonicalJson({ document, signature: signaturePayload }), "utf8");
}

export function signDocument(document, privateKeyHex, { purpose, timestamp, nonce, audience } = {}) {
  if (Object.hasOwn(document, "signature")) fail("document is already signed");
  const publicKey = hex(ed25519.getPublicKey(Buffer.from(privateKeyHex, "hex")));
  const payload = { nonce: nonce || randomBytes(16).toString("hex"), public_key: publicKey, purpose, timestamp: nowSeconds(timestamp) };
  if (audience) payload.audience = String(audience);
  const signature = hex(ed25519.sign(signatureMessage(document, payload), Buffer.from(privateKeyHex, "hex")));
  return { ...document, signature: { ...payload, signature } };
}

function verifyDocumentSignature(document, { purpose, audience }) {
  const signature = document.signature;
  if (!signature || typeof signature !== "object") fail("missing signature");
  if (signature.purpose !== purpose) fail("bad signature purpose");
  if (audience !== undefined && signature.audience !== audience) fail("bad signature audience");
  const { signature: _unused, ...unsigned } = document;
  const { signature: signatureHex, ...payload } = signature;
  let valid = false;
  try {
    valid = ed25519.verify(Buffer.from(signatureHex, "hex"), signatureMessage(unsigned, payload), Buffer.from(signature.public_key, "hex"));
  } catch { valid = false; }
  if (!valid) fail("bad signature");
  return unsigned;
}

function validateSignatureShape(signature, { fields, purpose, audience }) {
  if (!signature || typeof signature !== "object") fail("missing secure transport signature");
  exactFields(signature, fields, "secure transport signature");
  if (typeof signature.nonce !== "string" || !HEX16.test(signature.nonce)) fail("secure transport signature nonce must be 16 bytes of lowercase hex");
  if (typeof signature.public_key !== "string" || !HEX32.test(signature.public_key)) fail("secure transport signer public key is invalid");
  if (signature.purpose !== purpose) fail("secure transport signature purpose mismatch");
  integer(signature.timestamp, "secure transport signature timestamp");
  if (audience !== undefined && signature.audience !== audience) fail("secure transport signature audience mismatch");
  if (typeof signature.signature !== "string" || !SIGNATURE.test(signature.signature)) fail("secure transport signature must be 64 bytes of lowercase hex");
}

export function transportKeyId(publicKeyBytes) {
  const digest = createHash("sha256").update(Buffer.concat([Buffer.from("mycomesh-transport-key-v1", "utf8"), Buffer.from([0]), Buffer.from(publicKeyBytes)])).digest("hex");
  return `x25519_${digest}`;
}

export function generateTransportKey(identity, { lifetimeSeconds = 24 * 60 * 60, now } = {}) {
  const current = nowSeconds(now);
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > MAX_TRANSPORT_KEY_LIFETIME_SECONDS) {
    fail("transport key lifetime is invalid");
  }
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  const document = {
    version: TRANSPORT_KEY_VERSION,
    algorithm: TRANSPORT_KEY_ALGORITHM,
    peer_id: identity.peerId,
    identity_public_key: identity.publicKey,
    encryption_public_key: hex(publicKey),
    key_id: transportKeyId(publicKey),
    not_before: current,
    expires_at: current + lifetimeSeconds,
  };
  const binding = signDocument(document, identity.privateKey, { purpose: TRANSPORT_KEY_PURPOSE, timestamp: current });
  return { binding, privateKey: privateKey.toString("hex") };
}

export function verifyTransportKeyBinding(binding, { expectedPeerId, expectedIdentityPublicKey, now } = {}) {
  const current = nowSeconds(now);
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) fail("transport key binding must be an object");
  exactFields(binding, BINDING_FIELDS, "transport key binding");
  if (binding.version !== TRANSPORT_KEY_VERSION) fail("unsupported transport key binding version");
  if (binding.algorithm !== TRANSPORT_KEY_ALGORITHM) fail("unsupported transport key algorithm");
  const { peer_id: peerId, identity_public_key: identityPublicKey, encryption_public_key: encryptionPublicKey, key_id: keyId } = binding;
  if (typeof peerId !== "string" || !peerId || peerId.length > 160) fail("transport peer_id is invalid");
  if (typeof identityPublicKey !== "string" || !HEX32.test(identityPublicKey)) fail("transport identity public key is invalid");
  if (typeof encryptionPublicKey !== "string" || !HEX32.test(encryptionPublicKey)) fail("transport encryption public key is invalid");
  if (typeof keyId !== "string" || !KEY_ID.test(keyId)) fail("transport key_id is malformed");
  if (keyId !== transportKeyId(Buffer.from(encryptionPublicKey, "hex"))) fail("transport key_id does not match encryption public key");
  if (peerId !== peerIdFromPublicKey(identityPublicKey)) fail("transport peer_id does not match identity public key");
  if (expectedPeerId !== undefined && peerId !== String(expectedPeerId)) fail("transport key binding peer_id mismatch");
  if (expectedIdentityPublicKey !== undefined && identityPublicKey !== String(expectedIdentityPublicKey).toLowerCase()) {
    fail("transport key binding identity public key mismatch");
  }
  const notBefore = integer(binding.not_before, "transport key not_before");
  const expiresAt = integer(binding.expires_at, "transport key expires_at");
  if (expiresAt <= notBefore) fail("transport key expiry must follow not_before");
  if (expiresAt - notBefore > MAX_TRANSPORT_KEY_LIFETIME_SECONDS) fail("transport key lifetime exceeds the maximum");
  const signature = binding.signature;
  validateSignatureShape(signature, { fields: BINDING_SIGNATURE_FIELDS, purpose: TRANSPORT_KEY_PURPOSE });
  if (signature.timestamp < notBefore - MAX_CLOCK_SKEW_SECONDS) fail("transport key was signed too early");
  if (signature.timestamp > notBefore + MAX_CLOCK_SKEW_SECONDS) fail("transport key signature timestamp does not match not_before");
  if (signature.timestamp > current + MAX_CLOCK_SKEW_SECONDS) fail("transport key signature timestamp is in the future");
  if (notBefore > current + MAX_CLOCK_SKEW_SECONDS) fail("transport key is not active yet");
  if (expiresAt <= current) fail("transport key has expired");
  if (signature.public_key !== identityPublicKey) fail("transport key signer does not match identity public key");
  verifyDocumentSignature(binding, { purpose: TRANSPORT_KEY_PURPOSE });
  return { peerId, identityPublicKey, encryptionPublicKey, keyId, notBefore, expiresAt };
}

function contentKey(sharedSecret, aad) {
  return Buffer.from(hkdf(sha256, sharedSecret, sha256(aad), KDF_INFO, 32));
}

function encodeFrame(envelope) {
  const raw = Buffer.from(canonicalJson(envelope), "utf8");
  if (raw.length + 4 > MAX_SECURE_FRAME_BYTES) fail(`secure frame exceeds ${MAX_SECURE_FRAME_BYTES} bytes`);
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(raw.length);
  return Buffer.concat([prefix, raw]);
}

function decodeFrame(frame) {
  if (!Buffer.isBuffer(frame)) fail("secure frame must be bytes");
  if (frame.length < 4) fail("secure frame is truncated");
  if (frame.length > MAX_SECURE_FRAME_BYTES) fail(`secure frame exceeds ${MAX_SECURE_FRAME_BYTES} bytes`);
  const declared = frame.readUInt32BE(0);
  if (declared === 0) fail("secure frame payload is empty");
  if (declared !== frame.length - 4) fail("secure frame length mismatch");
  const raw = frame.subarray(4);
  let value;
  try { value = JSON.parse(raw.toString("utf8")); } catch { fail("secure frame is not JSON"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("secure frame payload must be an object");
  if (!raw.equals(Buffer.from(canonicalJson(value), "utf8"))) fail("secure frame JSON is not canonical");
  return value;
}

export function sealFrame(payload, { sender, recipientBinding, expectedRecipientPeerId, expectedRecipientPublicKey,
  purpose, ttlSeconds = 60, now } = {}) {
  const current = nowSeconds(now);
  if (!Buffer.isBuffer(payload)) fail("secure envelope payload must be bytes");
  if (payload.length > MAX_PLAINTEXT_BYTES) fail(`secure envelope plaintext exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
  if (typeof purpose !== "string" || !PURPOSE.test(purpose)) fail("secure envelope purpose is invalid");
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_ENVELOPE_TTL_SECONDS) fail("secure envelope TTL is invalid");
  const recipient = verifyTransportKeyBinding(recipientBinding, {
    expectedPeerId: expectedRecipientPeerId, expectedIdentityPublicKey: expectedRecipientPublicKey, now: current,
  });
  const expiresAt = current + ttlSeconds;
  if (expiresAt > recipient.expiresAt) fail("secure envelope outlives the recipient transport key");
  const ephemeralPrivate = randomBytes(32);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
  const messageId = randomBytes(16).toString("hex");
  const nonce = randomBytes(NONCE_BYTES);
  const header = {
    version: SECURE_ENVELOPE_VERSION,
    algorithm: ENVELOPE_ALGORITHM,
    message_id: messageId,
    purpose,
    sender_peer_id: sender.peerId,
    sender_public_key: sender.publicKey,
    recipient_peer_id: recipient.peerId,
    recipient_public_key: recipient.identityPublicKey,
    recipient_key_id: recipient.keyId,
    ephemeral_public_key: hex(ephemeralPublic),
    nonce: nonce.toString("hex"),
    issued_at: current,
    expires_at: expiresAt,
  };
  const aad = Buffer.from(canonicalJson(header), "utf8");
  const shared = x25519.getSharedSecret(ephemeralPrivate, Buffer.from(recipient.encryptionPublicKey, "hex"));
  const cipher = createCipheriv("chacha20-poly1305", contentKey(shared, aad), nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad, { plaintextLength: payload.length });
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
  const envelope = { ...header, ciphertext: base64url(ciphertext) };
  const signed = signDocument(envelope, sender.privateKey, {
    purpose: ENVELOPE_SIGNATURE_PURPOSE, timestamp: current, nonce: messageId, audience: recipient.identityPublicKey,
  });
  return encodeFrame(signed);
}

export function sealJsonFrame(document, options) {
  if (!document || typeof document !== "object" || Array.isArray(document)) fail("secure envelope JSON document must be an object");
  return sealFrame(Buffer.from(canonicalJson(document), "utf8"), options);
}

// replaySet: an in-process Set; a Consumer opens each response frame once.
export function openFrame(frame, { recipientKey, expectedPurpose, replaySet, expectedSenderPeerId, expectedSenderPublicKey, now } = {}) {
  const current = nowSeconds(now);
  if (!(replaySet instanceof Set)) fail("a replay set is required");
  const recipient = verifyTransportKeyBinding(recipientKey?.binding, { now: current });
  if (hex(x25519.getPublicKey(Buffer.from(recipientKey.privateKey, "hex"))) !== recipient.encryptionPublicKey) {
    fail("recipient private key does not match its binding");
  }
  const envelope = decodeFrame(frame);
  exactFields(envelope, ENVELOPE_FIELDS, "secure envelope");
  if (envelope.version !== SECURE_ENVELOPE_VERSION) fail("unsupported secure envelope version");
  if (envelope.algorithm !== ENVELOPE_ALGORITHM) fail("unsupported secure envelope algorithm");
  if (typeof envelope.message_id !== "string" || !HEX16.test(envelope.message_id)) fail("secure envelope message_id is invalid");
  if (envelope.purpose !== expectedPurpose) fail("secure envelope purpose mismatch");
  if (typeof envelope.sender_public_key !== "string" || !HEX32.test(envelope.sender_public_key)) fail("secure envelope sender public key is invalid");
  if (envelope.sender_peer_id !== peerIdFromPublicKey(envelope.sender_public_key)) fail("secure envelope sender peer_id does not match public key");
  if (expectedSenderPeerId !== undefined && envelope.sender_peer_id !== expectedSenderPeerId) fail("secure envelope sender peer_id mismatch");
  if (expectedSenderPublicKey !== undefined && envelope.sender_public_key !== String(expectedSenderPublicKey).toLowerCase()) {
    fail("secure envelope sender public key mismatch");
  }
  if (envelope.recipient_peer_id !== recipient.peerId) fail("secure envelope audience peer_id mismatch");
  if (envelope.recipient_public_key !== recipient.identityPublicKey) fail("secure envelope audience public key mismatch");
  if (envelope.recipient_key_id !== recipient.keyId) fail("secure envelope recipient key_id mismatch");
  if (typeof envelope.ephemeral_public_key !== "string" || !HEX32.test(envelope.ephemeral_public_key)) fail("secure envelope ephemeral public key is invalid");
  if (typeof envelope.nonce !== "string" || !HEX_NONCE.test(envelope.nonce)) fail("secure envelope nonce is invalid");
  const issuedAt = integer(envelope.issued_at, "secure envelope issued_at");
  const expiresAt = integer(envelope.expires_at, "secure envelope expires_at");
  if (expiresAt <= issuedAt) fail("secure envelope expiry must follow issued_at");
  if (expiresAt - issuedAt > MAX_ENVELOPE_TTL_SECONDS) fail("secure envelope TTL exceeds the maximum");
  if (issuedAt > current + MAX_CLOCK_SKEW_SECONDS) fail("secure envelope was issued in the future");
  if (expiresAt <= current) fail("secure envelope has expired");
  if (issuedAt < recipient.notBefore - MAX_CLOCK_SKEW_SECONDS) fail("secure envelope predates the recipient transport key");
  if (expiresAt > recipient.expiresAt) fail("secure envelope outlives the recipient transport key");
  const signature = envelope.signature;
  validateSignatureShape(signature, { fields: ENVELOPE_SIGNATURE_FIELDS, purpose: ENVELOPE_SIGNATURE_PURPOSE, audience: recipient.identityPublicKey });
  if (signature.public_key !== envelope.sender_public_key) fail("secure envelope signer does not match sender public key");
  if (signature.nonce !== envelope.message_id) fail("secure envelope signature nonce does not match message_id");
  if (signature.timestamp !== issuedAt) fail("secure envelope signature timestamp does not match issued_at");
  verifyDocumentSignature(envelope, { purpose: ENVELOPE_SIGNATURE_PURPOSE, audience: recipient.identityPublicKey });
  if (typeof envelope.ciphertext !== "string" || !BASE64URL.test(envelope.ciphertext)) fail("secure envelope ciphertext must be canonical base64url");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64url");
  if (base64url(ciphertext) !== envelope.ciphertext) fail("secure envelope ciphertext is not canonical base64url");
  if (ciphertext.length < TAG_BYTES) fail("secure envelope ciphertext is too short");
  if (ciphertext.length > MAX_PLAINTEXT_BYTES + TAG_BYTES) fail(`secure envelope plaintext exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
  const header = Object.fromEntries(ENVELOPE_FIELDS.filter((key) => key !== "ciphertext" && key !== "signature").map((key) => [key, envelope[key]]));
  const aad = Buffer.from(canonicalJson(header), "utf8");
  let plaintext;
  try {
    const shared = x25519.getSharedSecret(Buffer.from(recipientKey.privateKey, "hex"), Buffer.from(envelope.ephemeral_public_key, "hex"));
    const decipher = createDecipheriv("chacha20-poly1305", contentKey(shared, aad), Buffer.from(envelope.nonce, "hex"), { authTagLength: TAG_BYTES });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length - TAG_BYTES });
    decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG_BYTES));
    plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - TAG_BYTES)), decipher.final()]);
  } catch {
    fail("secure envelope authentication failed");
  }
  const replayKey = `${envelope.sender_public_key}:${recipient.keyId}:${envelope.message_id}`;
  if (replaySet.has(replayKey)) fail("secure envelope was already accepted");
  replaySet.add(replayKey);
  return {
    payload: plaintext,
    messageId: envelope.message_id,
    purpose: envelope.purpose,
    senderPeerId: envelope.sender_peer_id,
    senderPublicKey: envelope.sender_public_key,
    issuedAt,
    expiresAt,
  };
}
