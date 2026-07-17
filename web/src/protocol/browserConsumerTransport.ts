import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import {
  assertBrowserConsumerIdentity,
  assertBrowserSoftwareConsumerIdentity,
  browserBytesEqual,
  browserBytesToHex,
  type BrowserConsumerIdentity,
  type BrowserDocumentSigningIdentity,
  type BrowserSoftwareConsumerIdentity,
  BrowserConsumerProtocolError,
  browserHexToBytes,
  browserIsPlainObject,
  browserPeerIdFromPublicKey,
  type BrowserRandomBytes,
  browserSha256Hex,
  browserUtf8,
  canonicalBrowserJson,
  protocolTimestamp,
  requireBrowserLowerHex,
  secureBrowserRandomBytes,
  signBrowserDocument,
  signBrowserDocumentAsync,
  verifyBrowserDocument,
} from "./browserConsumerIdentity";

export const SECURE_ENVELOPE_VERSION = "mycomesh-secure-envelope-v1";
export const TRANSPORT_KEY_VERSION = "mycomesh-transport-key-v1";
export const TRANSPORT_KEY_PURPOSE = "mycomesh.transport.key_binding.v1";
export const ENVELOPE_SIGNATURE_PURPOSE = "mycomesh.transport.envelope.v1";
export const TRANSPORT_KEY_ALGORITHM = "X25519";
export const ENVELOPE_ALGORITHM = "X25519-HKDF-SHA256-CHACHA20POLY1305";
export const SECURE_ENVELOPE_REPLAY_SCOPE = "mycomesh.transport.envelope.v1";
export const P2P_SECURE_REQUEST_PURPOSE = "mycomesh.p2p.request.v1";
export const P2P_SECURE_RESPONSE_PURPOSE = "mycomesh.p2p.response.v1";

export const MAX_BROWSER_PLAINTEXT_BYTES = 8 * 1024 * 1024;
export const MAX_BROWSER_SECURE_FRAME_BYTES = 12 * 1024 * 1024;
export const MAX_BROWSER_ENVELOPE_TTL_SECONDS = 5 * 60;
export const MAX_BROWSER_TRANSPORT_KEY_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
export const MAX_BROWSER_CLOCK_SKEW_SECONDS = 30;
export const MAX_BROWSER_REPLAY_ENTRIES = 100_000;

const FRAME_PREFIX_BYTES = 4;
const AEAD_NONCE_BYTES = 12;
const AEAD_TAG_BYTES = 16;
const HEX_16_PATTERN = /^[0-9a-f]{32}$/;
const HEX_NONCE_PATTERN = /^[0-9a-f]{24}$/;
const KEY_ID_PATTERN = /^x25519_[0-9a-f]{64}$/;
const PURPOSE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const KDF_INFO = browserUtf8(`${SECURE_ENVELOPE_VERSION}\0${ENVELOPE_ALGORITHM}`);
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const KEY_BINDING_FIELDS = [
  "version",
  "algorithm",
  "peer_id",
  "identity_public_key",
  "encryption_public_key",
  "key_id",
  "not_before",
  "expires_at",
  "signature",
] as const;
const ENVELOPE_FIELDS = [
  "version",
  "algorithm",
  "message_id",
  "purpose",
  "sender_peer_id",
  "sender_public_key",
  "recipient_peer_id",
  "recipient_public_key",
  "recipient_key_id",
  "ephemeral_public_key",
  "nonce",
  "issued_at",
  "expires_at",
  "ciphertext",
  "signature",
] as const;
const BINDING_SIGNATURE_FIELDS = ["nonce", "public_key", "purpose", "timestamp", "signature"] as const;
const ENVELOPE_SIGNATURE_FIELDS = [
  "nonce",
  "public_key",
  "purpose",
  "timestamp",
  "audience",
  "signature",
] as const;

export interface BrowserTransportKeyBinding {
  version: typeof TRANSPORT_KEY_VERSION;
  algorithm: typeof TRANSPORT_KEY_ALGORITHM;
  peer_id: string;
  identity_public_key: string;
  encryption_public_key: string;
  key_id: string;
  not_before: number;
  expires_at: number;
  signature: {
    nonce: string;
    public_key: string;
    purpose: typeof TRANSPORT_KEY_PURPOSE;
    timestamp: number;
    signature: string;
  };
}

export interface BrowserTransportKeyPair {
  binding: BrowserTransportKeyBinding;
  privateKey: string;
}

export interface VerifiedBrowserTransportKey {
  peerId: string;
  identityPublicKey: string;
  encryptionPublicKey: string;
  keyId: string;
  notBefore: number;
  expiresAt: number;
}

export interface GenerateBrowserTransportKeyOptions {
  lifetimeSeconds?: number;
  now?: number;
  randomBytes?: BrowserRandomBytes;
}

export interface VerifyBrowserTransportKeyOptions {
  expectedPeerId?: string;
  expectedIdentityPublicKey?: string;
  now?: number;
}

interface SealBrowserFrameBaseOptions {
  sender: BrowserConsumerIdentity;
  recipientBinding: unknown;
  expectedRecipientPeerId: string;
  expectedRecipientPublicKey?: string;
  purpose: string;
  ttlSeconds?: number;
  now?: number;
  maximumPlaintextBytes?: number;
  randomBytes?: BrowserRandomBytes;
}

export interface SealBrowserFrameOptions extends SealBrowserFrameBaseOptions {
  sender: BrowserSoftwareConsumerIdentity;
}

export interface SealBrowserFrameAsyncOptions extends SealBrowserFrameBaseOptions {
  sender: BrowserDocumentSigningIdentity;
}

export interface BrowserReplayStoreLike {
  remember(scope: string, replayKey: string, ttlSeconds: number, now?: number): void;
}

export interface OpenBrowserFrameOptions {
  recipientKey: BrowserTransportKeyPair;
  expectedPurpose: string;
  replayStore: BrowserReplayStoreLike;
  expectedSenderPeerId?: string;
  expectedSenderPublicKey?: string;
  now?: number;
  maximumPlaintextBytes?: number;
  maximumFrameBytes?: number;
}

export interface OpenedBrowserEnvelope {
  payload: Uint8Array;
  messageId: string;
  purpose: string;
  senderPeerId: string;
  senderPublicKey: string;
  recipientPeerId: string;
  recipientPublicKey: string;
  recipientKeyId: string;
  issuedAt: number;
  expiresAt: number;
}

export interface OpenedBrowserJsonEnvelope<T extends Record<string, unknown> = Record<string, unknown>>
  extends OpenedBrowserEnvelope {
  jsonPayload: T;
}

export class BrowserTransportError extends BrowserConsumerProtocolError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BrowserTransportError";
  }
}

export class BrowserEnvelopeReplayError extends BrowserTransportError {
  constructor(message = "secure envelope was already accepted") {
    super(message);
    this.name = "BrowserEnvelopeReplayError";
  }
}

export class BrowserMemoryReplayStore implements BrowserReplayStoreLike {
  readonly maximumEntries: number;
  readonly #entries = new Map<string, number>();

  constructor(maximumEntries = MAX_BROWSER_REPLAY_ENTRIES) {
    this.maximumEntries = positiveInteger(maximumEntries, "maximum replay entries", MAX_BROWSER_REPLAY_ENTRIES);
  }

  remember(scope: string, replayKey: string, ttlSeconds: number, now?: number): void {
    const resolvedScope = nonemptyText(scope, "replay scope", 512).trim();
    const resolvedKey = nonemptyText(replayKey, "replay key", 1024).trim();
    if (!resolvedScope || !resolvedKey) throw new BrowserTransportError("replay scope and key are required");
    const currentTime = transportTimestamp(now, "replay time");
    const ttl = positiveInteger(ttlSeconds, "replay TTL", MAX_BROWSER_ENVELOPE_TTL_SECONDS);
    for (const [key, expiresAt] of this.#entries) {
      if (expiresAt < currentTime) this.#entries.delete(key);
    }
    const entryKey = `${resolvedScope}\0${resolvedKey}`;
    if ((this.#entries.get(entryKey) ?? -1) >= currentTime) throw new BrowserEnvelopeReplayError();
    if (this.#entries.size >= this.maximumEntries) {
      throw new BrowserTransportError("replay store capacity exceeded");
    }
    this.#entries.set(entryKey, currentTime + ttl);
  }
}

export function browserTransportKeyId(encryptionPublicKey: string | Uint8Array): string {
  const publicBytes = typeof encryptionPublicKey === "string"
    ? browserHexToBytes(requireBrowserLowerHex(encryptionPublicKey, 32, "X25519 public key"), 32)
    : encryptionPublicKey;
  if (!isUint8Array(publicBytes) || publicBytes.length !== 32) {
    throw new BrowserTransportError("X25519 public key must be 32 bytes");
  }
  const prefix = browserUtf8(`${TRANSPORT_KEY_VERSION}\0`);
  const input = new Uint8Array(prefix.length + publicBytes.length);
  input.set(prefix);
  input.set(publicBytes, prefix.length);
  return `x25519_${browserSha256Hex(input)}`;
}

export function generateBrowserTransportKey(
  identity: BrowserSoftwareConsumerIdentity,
  options: GenerateBrowserTransportKeyOptions = {},
): BrowserTransportKeyPair {
  assertBrowserSoftwareConsumerIdentity(identity);
  const prepared = prepareBrowserTransportKey(identity, options);
  const binding = signBrowserDocument(prepared.document, identity, {
    purpose: TRANSPORT_KEY_PURPOSE,
    timestamp: prepared.currentTime,
    randomBytes: prepared.randomBytes,
  });
  return {
    binding: binding as unknown as BrowserTransportKeyBinding,
    privateKey: browserBytesToHex(prepared.privateBytes),
  };
}

export async function generateBrowserTransportKeyAsync(
  identity: BrowserDocumentSigningIdentity,
  options: GenerateBrowserTransportKeyOptions = {},
): Promise<BrowserTransportKeyPair> {
  assertBrowserConsumerIdentity(identity);
  const prepared = prepareBrowserTransportKey(identity, options);
  const binding = await signBrowserDocumentAsync(prepared.document, identity, {
    purpose: TRANSPORT_KEY_PURPOSE,
    timestamp: prepared.currentTime,
    randomBytes: prepared.randomBytes,
  });
  return {
    binding: binding as unknown as BrowserTransportKeyBinding,
    privateKey: browserBytesToHex(prepared.privateBytes),
  };
}

function prepareBrowserTransportKey(
  identity: BrowserConsumerIdentity,
  options: GenerateBrowserTransportKeyOptions,
): {
  document: Record<string, unknown>;
  privateBytes: Uint8Array;
  currentTime: number;
  randomBytes: BrowserRandomBytes;
} {
  assertBrowserConsumerIdentity(identity);
  const currentTime = transportTimestamp(options.now, "current time");
  const lifetime = positiveInteger(
    options.lifetimeSeconds ?? 24 * 60 * 60,
    "transport key lifetime",
    MAX_BROWSER_TRANSPORT_KEY_LIFETIME_SECONDS,
  );
  const randomBytes = options.randomBytes ?? secureBrowserRandomBytes;
  const privateBytes = exactRandomBytes(randomBytes, 32);
  const publicBytes = x25519.getPublicKey(privateBytes);
  return {
    document: {
      version: TRANSPORT_KEY_VERSION,
      algorithm: TRANSPORT_KEY_ALGORITHM,
      peer_id: identity.peerId,
      identity_public_key: identity.publicKey,
      encryption_public_key: browserBytesToHex(publicBytes),
      key_id: browserTransportKeyId(publicBytes),
      not_before: currentTime,
      expires_at: currentTime + lifetime,
    },
    privateBytes,
    currentTime,
    randomBytes,
  };
}

export function verifyBrowserTransportKeyBinding(
  binding: unknown,
  options: VerifyBrowserTransportKeyOptions = {},
): VerifiedBrowserTransportKey {
  const currentTime = transportTimestamp(options.now, "current time");
  const value = exactObject(binding, KEY_BINDING_FIELDS, "transport key binding");
  if (value.version !== TRANSPORT_KEY_VERSION) throw new BrowserTransportError("unsupported transport key binding version");
  if (value.algorithm !== TRANSPORT_KEY_ALGORITHM) throw new BrowserTransportError("unsupported transport key algorithm");

  const peerId = nonemptyText(value.peer_id, "transport peer_id", 160);
  const identityPublicKey = lowerHex(value.identity_public_key, 32, "transport identity public key");
  const encryptionPublicKey = lowerHex(value.encryption_public_key, 32, "transport encryption public key");
  const keyId = nonemptyText(value.key_id, "transport key_id", 80);
  if (!KEY_ID_PATTERN.test(keyId)) throw new BrowserTransportError("transport key_id is malformed");
  if (keyId !== browserTransportKeyId(encryptionPublicKey)) {
    throw new BrowserTransportError("transport key_id does not match encryption public key");
  }
  if (peerId !== browserPeerIdFromPublicKey(identityPublicKey)) {
    throw new BrowserTransportError("transport peer_id does not match identity public key");
  }
  if (options.expectedPeerId !== undefined && peerId !== String(options.expectedPeerId)) {
    throw new BrowserTransportError("transport key binding peer_id mismatch");
  }
  if (
    options.expectedIdentityPublicKey !== undefined
    && identityPublicKey !== String(options.expectedIdentityPublicKey).toLowerCase()
  ) {
    throw new BrowserTransportError("transport key binding identity public key mismatch");
  }

  const notBefore = transportInteger(value.not_before, "transport key not_before");
  const expiresAt = transportInteger(value.expires_at, "transport key expires_at");
  if (expiresAt <= notBefore) throw new BrowserTransportError("transport key expiry must follow not_before");
  if (expiresAt - notBefore > MAX_BROWSER_TRANSPORT_KEY_LIFETIME_SECONDS) {
    throw new BrowserTransportError("transport key lifetime exceeds the maximum");
  }
  const signature = validateTransportSignature(
    value.signature,
    BINDING_SIGNATURE_FIELDS,
    TRANSPORT_KEY_PURPOSE,
  );
  const signatureTimestamp = transportInteger(signature.timestamp, "transport key signature timestamp");
  if (signatureTimestamp < notBefore - MAX_BROWSER_CLOCK_SKEW_SECONDS) {
    throw new BrowserTransportError("transport key was signed too early");
  }
  if (signatureTimestamp > notBefore + MAX_BROWSER_CLOCK_SKEW_SECONDS) {
    throw new BrowserTransportError("transport key signature timestamp does not match not_before");
  }
  if (signatureTimestamp > currentTime + MAX_BROWSER_CLOCK_SKEW_SECONDS) {
    throw new BrowserTransportError("transport key signature timestamp is in the future");
  }
  if (notBefore > currentTime + MAX_BROWSER_CLOCK_SKEW_SECONDS) {
    throw new BrowserTransportError("transport key is not active yet");
  }
  if (expiresAt <= currentTime) throw new BrowserTransportError("transport key has expired");
  if (signature.public_key !== identityPublicKey) {
    throw new BrowserTransportError("transport key signer does not match identity public key");
  }
  try {
    verifyBrowserDocument(value, { purpose: TRANSPORT_KEY_PURPOSE, maxAgeSeconds: 0, now: currentTime });
  } catch (error) {
    throw new BrowserTransportError("invalid transport key binding signature", { cause: error });
  }
  return {
    peerId,
    identityPublicKey,
    encryptionPublicKey,
    keyId,
    notBefore,
    expiresAt,
  };
}

export const verifyBrowserProviderTransportKey = verifyBrowserTransportKeyBinding;

export function sealBrowserFrame(payload: Uint8Array, options: SealBrowserFrameOptions): Uint8Array {
  assertBrowserSoftwareConsumerIdentity(options.sender);
  const prepared = prepareBrowserSealedEnvelope(payload, options);
  const signed = signBrowserDocument(prepared.envelope, options.sender, {
    purpose: ENVELOPE_SIGNATURE_PURPOSE,
    timestamp: prepared.currentTime,
    nonce: prepared.messageId,
    audience: prepared.recipientIdentityPublicKey,
  });
  return encodeFrame(signed);
}

export async function sealBrowserFrameAsync(
  payload: Uint8Array,
  options: SealBrowserFrameAsyncOptions,
): Promise<Uint8Array> {
  assertBrowserConsumerIdentity(options.sender);
  const prepared = prepareBrowserSealedEnvelope(payload, options);
  const signed = await signBrowserDocumentAsync(prepared.envelope, options.sender, {
    purpose: ENVELOPE_SIGNATURE_PURPOSE,
    timestamp: prepared.currentTime,
    nonce: prepared.messageId,
    audience: prepared.recipientIdentityPublicKey,
  });
  return encodeFrame(signed);
}

function prepareBrowserSealedEnvelope(
  payload: Uint8Array,
  options: SealBrowserFrameBaseOptions,
): {
  envelope: Record<string, unknown>;
  currentTime: number;
  messageId: string;
  recipientIdentityPublicKey: string;
} {
  if (!isUint8Array(payload)) throw new BrowserTransportError("secure envelope payload must be bytes");
  const currentTime = transportTimestamp(options.now, "current time");
  const ttl = positiveInteger(
    options.ttlSeconds ?? 60,
    "secure envelope TTL",
    MAX_BROWSER_ENVELOPE_TTL_SECONDS,
  );
  const maximumPlaintext = positiveInteger(
    options.maximumPlaintextBytes ?? MAX_BROWSER_PLAINTEXT_BYTES,
    "maximum plaintext size",
    MAX_BROWSER_PLAINTEXT_BYTES,
  );
  if (payload.length > maximumPlaintext) {
    throw new BrowserTransportError(`secure envelope plaintext exceeds ${maximumPlaintext} bytes`);
  }
  const purpose = transportPurpose(options.purpose);
  assertBrowserConsumerIdentity(options.sender);
  const recipient = verifyBrowserTransportKeyBinding(options.recipientBinding, {
    expectedPeerId: options.expectedRecipientPeerId,
    expectedIdentityPublicKey: options.expectedRecipientPublicKey,
    now: currentTime,
  });
  const expiresAt = currentTime + ttl;
  if (expiresAt > recipient.expiresAt) {
    throw new BrowserTransportError("secure envelope outlives the recipient transport key");
  }
  const randomBytes = options.randomBytes ?? secureBrowserRandomBytes;
  const ephemeralPrivate = exactRandomBytes(randomBytes, 32);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
  const messageId = browserBytesToHex(exactRandomBytes(randomBytes, 16));
  const nonce = exactRandomBytes(randomBytes, AEAD_NONCE_BYTES);
  const header = {
    version: SECURE_ENVELOPE_VERSION,
    algorithm: ENVELOPE_ALGORITHM,
    message_id: messageId,
    purpose,
    sender_peer_id: options.sender.peerId,
    sender_public_key: options.sender.publicKey,
    recipient_peer_id: recipient.peerId,
    recipient_public_key: recipient.identityPublicKey,
    recipient_key_id: recipient.keyId,
    ephemeral_public_key: browserBytesToHex(ephemeralPublic),
    nonce: browserBytesToHex(nonce),
    issued_at: currentTime,
    expires_at: expiresAt,
  };
  const aad = browserUtf8(canonicalBrowserJson(header));
  let sharedSecret: Uint8Array;
  try {
    sharedSecret = x25519.getSharedSecret(
      ephemeralPrivate,
      browserHexToBytes(recipient.encryptionPublicKey, 32),
    );
    assertSharedSecret(sharedSecret);
  } catch (error) {
    throw new BrowserTransportError("recipient transport public key is invalid", { cause: error });
  }
  const contentKey = deriveContentKey(sharedSecret, aad);
  const ciphertext = chacha20poly1305(contentKey, nonce, aad).encrypt(payload);
  const envelope = { ...header, ciphertext: browserBase64UrlEncode(ciphertext) };
  return {
    envelope,
    currentTime,
    messageId,
    recipientIdentityPublicKey: recipient.identityPublicKey,
  };
}

export function sealBrowserJsonFrame(
  document: Record<string, unknown>,
  options: SealBrowserFrameOptions,
): Uint8Array {
  if (!browserIsPlainObject(document)) {
    throw new BrowserTransportError("secure envelope JSON document must be an object");
  }
  return sealBrowserFrame(browserUtf8(canonicalBrowserJson(document)), options);
}

export async function sealBrowserJsonFrameAsync(
  document: Record<string, unknown>,
  options: SealBrowserFrameAsyncOptions,
): Promise<Uint8Array> {
  if (!browserIsPlainObject(document)) {
    throw new BrowserTransportError("secure envelope JSON document must be an object");
  }
  return sealBrowserFrameAsync(browserUtf8(canonicalBrowserJson(document)), options);
}

export function openBrowserFrame(frame: Uint8Array, options: OpenBrowserFrameOptions): OpenedBrowserEnvelope {
  const currentTime = transportTimestamp(options.now, "current time");
  const maximumPlaintext = positiveInteger(
    options.maximumPlaintextBytes ?? MAX_BROWSER_PLAINTEXT_BYTES,
    "maximum plaintext size",
    MAX_BROWSER_PLAINTEXT_BYTES,
  );
  const maximumFrame = positiveInteger(
    options.maximumFrameBytes ?? MAX_BROWSER_SECURE_FRAME_BYTES,
    "maximum secure frame size",
    MAX_BROWSER_SECURE_FRAME_BYTES,
  );
  const purposeExpected = transportPurpose(options.expectedPurpose);
  if (!options.replayStore || typeof options.replayStore.remember !== "function") {
    throw new BrowserTransportError("an atomic replay store is required");
  }
  const recipient = verifiedPrivateTransportKey(options.recipientKey, currentTime);
  const envelope = exactObject(decodeFrame(frame, maximumFrame), ENVELOPE_FIELDS, "secure envelope");
  if (envelope.version !== SECURE_ENVELOPE_VERSION) {
    throw new BrowserTransportError("unsupported secure envelope version");
  }
  if (envelope.algorithm !== ENVELOPE_ALGORITHM) {
    throw new BrowserTransportError("unsupported secure envelope algorithm");
  }
  const messageId = nonemptyText(envelope.message_id, "secure envelope message_id", 32);
  if (!HEX_16_PATTERN.test(messageId)) {
    throw new BrowserTransportError("secure envelope message_id must be 16 bytes of lowercase hex");
  }
  const purpose = transportPurpose(envelope.purpose);
  if (purpose !== purposeExpected) throw new BrowserTransportError("secure envelope purpose mismatch");
  const senderPeerId = nonemptyText(envelope.sender_peer_id, "secure envelope sender peer_id", 160);
  const senderPublicKey = lowerHex(envelope.sender_public_key, 32, "secure envelope sender public key");
  if (browserPeerIdFromPublicKey(senderPublicKey) !== senderPeerId) {
    throw new BrowserTransportError("secure envelope sender peer_id does not match public key");
  }
  if (options.expectedSenderPeerId !== undefined && senderPeerId !== String(options.expectedSenderPeerId)) {
    throw new BrowserTransportError("secure envelope sender peer_id mismatch");
  }
  if (
    options.expectedSenderPublicKey !== undefined
    && senderPublicKey !== String(options.expectedSenderPublicKey).toLowerCase()
  ) {
    throw new BrowserTransportError("secure envelope sender public key mismatch");
  }
  if (envelope.recipient_peer_id !== recipient.peerId) {
    throw new BrowserTransportError("secure envelope audience peer_id mismatch");
  }
  if (envelope.recipient_public_key !== recipient.identityPublicKey) {
    throw new BrowserTransportError("secure envelope audience public key mismatch");
  }
  if (envelope.recipient_key_id !== recipient.keyId) {
    throw new BrowserTransportError("secure envelope recipient key_id mismatch");
  }
  const ephemeralPublicKey = lowerHex(
    envelope.ephemeral_public_key,
    32,
    "secure envelope ephemeral public key",
  );
  const nonceHex = nonemptyText(envelope.nonce, "secure envelope nonce", 24);
  if (!HEX_NONCE_PATTERN.test(nonceHex)) {
    throw new BrowserTransportError("secure envelope nonce must be 12 bytes of lowercase hex");
  }
  const issuedAt = transportInteger(envelope.issued_at, "secure envelope issued_at");
  const expiresAt = transportInteger(envelope.expires_at, "secure envelope expires_at");
  if (expiresAt <= issuedAt) throw new BrowserTransportError("secure envelope expiry must follow issued_at");
  if (expiresAt - issuedAt > MAX_BROWSER_ENVELOPE_TTL_SECONDS) {
    throw new BrowserTransportError("secure envelope TTL exceeds the maximum");
  }
  if (issuedAt > currentTime + MAX_BROWSER_CLOCK_SKEW_SECONDS) {
    throw new BrowserTransportError("secure envelope was issued in the future");
  }
  if (expiresAt <= currentTime) throw new BrowserTransportError("secure envelope has expired");
  if (issuedAt < recipient.notBefore - MAX_BROWSER_CLOCK_SKEW_SECONDS) {
    throw new BrowserTransportError("secure envelope predates the recipient transport key");
  }
  if (expiresAt > recipient.expiresAt) {
    throw new BrowserTransportError("secure envelope outlives the recipient transport key");
  }
  const signature = validateTransportSignature(
    envelope.signature,
    ENVELOPE_SIGNATURE_FIELDS,
    ENVELOPE_SIGNATURE_PURPOSE,
    recipient.identityPublicKey,
  );
  if (signature.public_key !== senderPublicKey) {
    throw new BrowserTransportError("secure envelope signer does not match sender public key");
  }
  if (signature.nonce !== messageId) {
    throw new BrowserTransportError("secure envelope signature nonce does not match message_id");
  }
  if (signature.timestamp !== issuedAt) {
    throw new BrowserTransportError("secure envelope signature timestamp does not match issued_at");
  }
  try {
    verifyBrowserDocument(envelope, {
      purpose: ENVELOPE_SIGNATURE_PURPOSE,
      audience: recipient.identityPublicKey,
      maxAgeSeconds: 0,
      now: currentTime,
    });
  } catch (error) {
    throw new BrowserTransportError("invalid secure envelope signature", { cause: error });
  }
  const ciphertext = browserBase64UrlDecode(envelope.ciphertext, "secure envelope ciphertext");
  if (ciphertext.length < AEAD_TAG_BYTES) {
    throw new BrowserTransportError("secure envelope ciphertext is too short");
  }
  if (ciphertext.length > maximumPlaintext + AEAD_TAG_BYTES) {
    throw new BrowserTransportError(`secure envelope plaintext exceeds ${maximumPlaintext} bytes`);
  }
  const header = Object.fromEntries(
    ENVELOPE_FIELDS
      .filter((field) => field !== "ciphertext" && field !== "signature")
      .map((field) => [field, envelope[field]]),
  );
  const aad = browserUtf8(canonicalBrowserJson(header));
  let plaintext: Uint8Array;
  try {
    const sharedSecret = x25519.getSharedSecret(
      browserHexToBytes(options.recipientKey.privateKey, 32),
      browserHexToBytes(ephemeralPublicKey, 32),
    );
    assertSharedSecret(sharedSecret);
    plaintext = chacha20poly1305(
      deriveContentKey(sharedSecret, aad),
      browserHexToBytes(nonceHex, AEAD_NONCE_BYTES),
      aad,
    ).decrypt(ciphertext);
  } catch (error) {
    throw new BrowserTransportError("secure envelope authentication failed", { cause: error });
  }
  if (plaintext.length > maximumPlaintext) {
    throw new BrowserTransportError(`secure envelope plaintext exceeds ${maximumPlaintext} bytes`);
  }
  const replayKey = `${senderPublicKey}:${recipient.keyId}:${messageId}`;
  const replayTtl = Math.max(1, expiresAt - currentTime);
  try {
    options.replayStore.remember(SECURE_ENVELOPE_REPLAY_SCOPE, replayKey, replayTtl, currentTime);
  } catch (error) {
    if (error instanceof BrowserEnvelopeReplayError) throw error;
    throw new BrowserTransportError("failed to persist secure envelope replay claim", { cause: error });
  }
  return {
    payload: Uint8Array.from(plaintext),
    messageId,
    purpose,
    senderPeerId,
    senderPublicKey,
    recipientPeerId: recipient.peerId,
    recipientPublicKey: recipient.identityPublicKey,
    recipientKeyId: recipient.keyId,
    issuedAt,
    expiresAt,
  };
}

export function openBrowserJsonFrame<T extends Record<string, unknown> = Record<string, unknown>>(
  frame: Uint8Array,
  options: OpenBrowserFrameOptions,
): OpenedBrowserJsonEnvelope<T> {
  const opened = openBrowserFrame(frame, options);
  let text: string;
  let value: unknown;
  try {
    text = textDecoder.decode(opened.payload);
    value = JSON.parse(text);
  } catch (error) {
    throw new BrowserTransportError("secure envelope payload is not valid strict JSON", { cause: error });
  }
  if (!browserIsPlainObject(value)) {
    throw new BrowserTransportError("secure envelope JSON payload must be an object");
  }
  if (canonicalBrowserJson(value) !== text) {
    throw new BrowserTransportError("secure envelope JSON payload is not canonical");
  }
  return { ...opened, jsonPayload: value as T };
}

function verifiedPrivateTransportKey(
  keyPair: BrowserTransportKeyPair,
  now: number,
): VerifiedBrowserTransportKey {
  if (!keyPair || typeof keyPair !== "object") {
    throw new BrowserTransportError("recipient transport key pair is required");
  }
  const privateKey = lowerHex(keyPair.privateKey, 32, "transport private key");
  const verified = verifyBrowserTransportKeyBinding(keyPair.binding, { now });
  let publicBytes: Uint8Array;
  try {
    publicBytes = x25519.getPublicKey(browserHexToBytes(privateKey, 32));
  } catch (error) {
    throw new BrowserTransportError("transport private key is invalid", { cause: error });
  }
  if (browserBytesToHex(publicBytes) !== verified.encryptionPublicKey) {
    throw new BrowserTransportError("transport private key does not match its signed binding");
  }
  return verified;
}

function deriveContentKey(sharedSecret: Uint8Array, aad: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, sha256(aad), KDF_INFO, 32);
}

function encodeFrame(envelope: Record<string, unknown>): Uint8Array {
  const raw = browserUtf8(canonicalBrowserJson(envelope));
  if (raw.length + FRAME_PREFIX_BYTES > MAX_BROWSER_SECURE_FRAME_BYTES) {
    throw new BrowserTransportError(`secure frame exceeds ${MAX_BROWSER_SECURE_FRAME_BYTES} bytes`);
  }
  const frame = new Uint8Array(FRAME_PREFIX_BYTES + raw.length);
  new DataView(frame.buffer).setUint32(0, raw.length, false);
  frame.set(raw, FRAME_PREFIX_BYTES);
  return frame;
}

function decodeFrame(frame: Uint8Array, maximumFrameBytes: number): Record<string, unknown> {
  if (!isUint8Array(frame)) throw new BrowserTransportError("secure frame must be bytes");
  if (frame.length < FRAME_PREFIX_BYTES) throw new BrowserTransportError("secure frame is truncated");
  if (frame.length > maximumFrameBytes) {
    throw new BrowserTransportError(`secure frame exceeds ${maximumFrameBytes} bytes`);
  }
  const declaredLength = new DataView(frame.buffer, frame.byteOffset, FRAME_PREFIX_BYTES).getUint32(0, false);
  if (declaredLength === 0) throw new BrowserTransportError("secure frame payload is empty");
  if (declaredLength !== frame.length - FRAME_PREFIX_BYTES) {
    throw new BrowserTransportError("secure frame length mismatch");
  }
  const raw = frame.subarray(FRAME_PREFIX_BYTES);
  let text: string;
  let value: unknown;
  try {
    text = textDecoder.decode(raw);
    value = JSON.parse(text);
  } catch (error) {
    throw new BrowserTransportError("secure frame is not valid strict JSON", { cause: error });
  }
  if (!browserIsPlainObject(value)) throw new BrowserTransportError("secure frame payload must be an object");
  if (canonicalBrowserJson(value) !== text) {
    throw new BrowserTransportError("secure frame JSON is not canonical");
  }
  return value;
}

function validateTransportSignature(
  value: unknown,
  fields: readonly string[],
  purpose: string,
  audience?: string,
): Record<string, unknown> {
  const signature = exactObject(value, fields, "secure transport signature");
  if (typeof signature.nonce !== "string" || !HEX_16_PATTERN.test(signature.nonce)) {
    throw new BrowserTransportError("secure transport signature nonce must be 16 bytes of lowercase hex");
  }
  lowerHex(signature.public_key, 32, "secure transport signer public key");
  if (signature.purpose !== purpose) throw new BrowserTransportError("secure transport signature purpose mismatch");
  transportInteger(signature.timestamp, "secure transport signature timestamp");
  if (audience !== undefined && signature.audience !== audience) {
    throw new BrowserTransportError("secure transport signature audience mismatch");
  }
  lowerHex(signature.signature, 64, "secure transport signature");
  return signature;
}

function exactObject(value: unknown, fields: readonly string[], label: string): Record<string, unknown> {
  if (!browserIsPlainObject(value)) throw new BrowserTransportError(`${label} must be an object`);
  const expected = new Set(fields);
  const missing = fields.filter((field) => !Object.hasOwn(value, field));
  const unknown = Object.keys(value).filter((field) => !expected.has(field));
  if (missing.length > 0) throw new BrowserTransportError(`${label} is missing fields: ${missing.sort().join(", ")}`);
  if (unknown.length > 0) throw new BrowserTransportError(`${label} contains unsupported fields: ${unknown.sort().join(", ")}`);
  return value;
}

function transportTimestamp(value: unknown, label: string): number {
  try {
    return protocolTimestamp(value, label);
  } catch (error) {
    throw new BrowserTransportError(`${label} must be an integer`, { cause: error });
  }
}

function transportInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new BrowserTransportError(`${label} must be an integer`);
  }
  return value as number;
}

function positiveInteger(value: unknown, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new BrowserTransportError(`${label} must be a positive integer`);
  }
  if ((value as number) > maximum) throw new BrowserTransportError(`${label} must not exceed ${maximum}`);
  return value as number;
}

function nonemptyText(value: unknown, label: string, maximumBytes: number): string {
  if (typeof value !== "string" || value.length === 0 || browserUtf8(value).length > maximumBytes) {
    throw new BrowserTransportError(`${label} must be non-empty text no longer than ${maximumBytes} bytes`);
  }
  return value;
}

function lowerHex(value: unknown, bytes: number, label: string): string {
  try {
    return requireBrowserLowerHex(value, bytes, label);
  } catch (error) {
    throw new BrowserTransportError(`${label} must be ${bytes} bytes of lowercase hex`, { cause: error });
  }
}

function transportPurpose(value: unknown): string {
  if (typeof value !== "string" || !PURPOSE_PATTERN.test(value)) {
    throw new BrowserTransportError("secure envelope purpose is malformed");
  }
  return value;
}

function exactRandomBytes(randomBytes: BrowserRandomBytes, length: number): Uint8Array {
  const value = randomBytes(length);
  if (!isUint8Array(value) || value.length !== length) {
    throw new BrowserTransportError(`random source must return exactly ${length} bytes`);
  }
  return Uint8Array.from(value);
}

function isUint8Array(value: unknown): value is Uint8Array {
  return Object.prototype.toString.call(value) === "[object Uint8Array]";
}

function assertSharedSecret(value: Uint8Array): void {
  const zeros = new Uint8Array(value.length);
  if (value.length !== 32 || browserBytesEqual(value, zeros)) {
    throw new BrowserTransportError("X25519 shared secret is invalid");
  }
}

export function browserBase64UrlEncode(value: Uint8Array): string {
  if (!isUint8Array(value)) throw new BrowserTransportError("base64url input must be bytes");
  let binary = "";
  const chunkSize = 32_768;
  for (let offset = 0; offset < value.length; offset += chunkSize) {
    binary += String.fromCharCode(...value.subarray(offset, Math.min(offset + chunkSize, value.length)));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function browserBase64UrlDecode(
  value: unknown,
  label = "base64url value",
  maximumBytes = MAX_BROWSER_SECURE_FRAME_BYTES,
): Uint8Array {
  if (typeof value !== "string" || !BASE64URL_PATTERN.test(value) || value.includes("=")) {
    throw new BrowserTransportError(`${label} must be canonical base64url without padding`);
  }
  const maximum = positiveInteger(maximumBytes, "maximum base64url decoded size", MAX_BROWSER_SECURE_FRAME_BYTES);
  if (Math.floor(value.length * 3 / 4) > maximum) {
    throw new BrowserTransportError(`${label} exceeds ${maximum} decoded bytes`);
  }
  let binary: string;
  try {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
    binary = atob(padded);
  } catch (error) {
    throw new BrowserTransportError(`${label} is invalid base64url`, { cause: error });
  }
  const result = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) result[index] = binary.charCodeAt(index);
  if (browserBase64UrlEncode(result) !== value) throw new BrowserTransportError(`${label} is not canonical base64url`);
  return result;
}
