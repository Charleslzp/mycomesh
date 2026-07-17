import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";

export const BROWSER_SIGNATURE_MAX_AGE_SECONDS = 300;

const HEX_16_PATTERN = /^[0-9a-f]{32}$/;
const HEX_32_PATTERN = /^[0-9a-f]{64}$/;
const HEX_64_PATTERN = /^[0-9a-f]{128}$/;
const textEncoder = new TextEncoder();

export type BrowserJsonValue =
  | null
  | boolean
  | number
  | string
  | BrowserJsonValue[]
  | { [key: string]: BrowserJsonValue };

export type BrowserJsonObject = { [key: string]: BrowserJsonValue };

export interface BrowserConsumerIdentity {
  publicKey: string;
  peerId: string;
}

export interface BrowserDocumentSigner {
  readonly kind: "webcrypto-ed25519";
  readonly publicKey: string;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface BrowserConsumerSigningIdentity extends BrowserConsumerIdentity {
  readonly signer: BrowserDocumentSigner;
}

/** Software identities exist only for deterministic cross-language protocol vectors. */
export interface BrowserSoftwareConsumerIdentity extends BrowserConsumerIdentity {
  readonly privateKey: string;
}

export type BrowserDocumentSigningIdentity =
  | BrowserConsumerSigningIdentity
  | BrowserSoftwareConsumerIdentity;

export interface BrowserDocumentSignature {
  nonce: string;
  public_key: string;
  purpose: string;
  timestamp: number;
  audience?: string;
  signature: string;
}

export type BrowserSignedDocument<T extends Record<string, unknown> = BrowserJsonObject> = T & {
  signature: BrowserDocumentSignature;
};

export interface BrowserSignDocumentOptions {
  purpose: string;
  timestamp?: number;
  nonce?: string;
  audience?: string;
  randomBytes?: BrowserRandomBytes;
}

export interface BrowserVerifyDocumentOptions {
  purpose: string;
  audience?: string;
  maxAgeSeconds?: number;
  now?: number;
}

export type BrowserRandomBytes = (length: number) => Uint8Array;

export class BrowserConsumerProtocolError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BrowserConsumerProtocolError";
  }
}

export function canonicalBrowserJson(value: unknown): string {
  return canonicalize(value, new Set<object>());
}

export function browserUtf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function browserBytesToHex(value: Uint8Array): string {
  let result = "";
  for (const byte of value) result += byte.toString(16).padStart(2, "0");
  return result;
}

export function browserHexToBytes(value: string, length?: number, label = "hex value"): Uint8Array {
  if (typeof value !== "string" || !/^[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) {
    throw new BrowserConsumerProtocolError(`${label} must be hexadecimal`);
  }
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  if (length !== undefined && result.length !== length) {
    throw new BrowserConsumerProtocolError(`${label} must be ${length} bytes of hex`);
  }
  return result;
}

export function secureBrowserRandomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new BrowserConsumerProtocolError("random byte length must be a positive integer");
  }
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new BrowserConsumerProtocolError("secure browser randomness is unavailable");
  }
  const result = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65_536) {
    cryptoApi.getRandomValues(result.subarray(offset, Math.min(offset + 65_536, length)));
  }
  return result;
}

export function browserPublicKeyFromPrivateKey(privateKey: string): string {
  const privateBytes = lowerHexBytes(privateKey, 32, "Ed25519 private key");
  return browserBytesToHex(ed25519.getPublicKey(privateBytes));
}

export function browserPeerIdFromPublicKey(publicKey: string): string {
  const publicBytes = browserHexToBytes(publicKey, 32, "Ed25519 public key");
  return `peer_${browserBytesToHex(sha256(publicBytes)).slice(0, 24)}`;
}

export function browserSoftwareConsumerIdentityFromPrivateKeyForTest(
  privateKey: string,
): BrowserSoftwareConsumerIdentity {
  const normalizedPrivateKey = browserBytesToHex(lowerHexBytes(privateKey, 32, "Ed25519 private key"));
  const publicKey = browserPublicKeyFromPrivateKey(normalizedPrivateKey);
  return {
    privateKey: normalizedPrivateKey,
    publicKey,
    peerId: browserPeerIdFromPublicKey(publicKey),
  };
}

export function generateBrowserSoftwareConsumerIdentityForTest(
  randomBytes: BrowserRandomBytes = secureBrowserRandomBytes,
): BrowserSoftwareConsumerIdentity {
  return browserSoftwareConsumerIdentityFromPrivateKeyForTest(
    browserBytesToHex(requireRandomBytes(randomBytes, 32)),
  );
}

export function assertBrowserConsumerIdentity(identity: BrowserConsumerIdentity): void {
  if (!identity || typeof identity !== "object") {
    throw new BrowserConsumerProtocolError("browser Consumer identity is required");
  }
  const publicKey = requireBrowserLowerHex(identity.publicKey, 32, "browser Consumer public key");
  if (identity.peerId !== browserPeerIdFromPublicKey(publicKey)) {
    throw new BrowserConsumerProtocolError("browser Consumer peer ID does not match its public key");
  }
}

export function assertBrowserSoftwareConsumerIdentity(
  identity: BrowserSoftwareConsumerIdentity,
): void {
  assertBrowserConsumerIdentity(identity);
  const privateKey = requireBrowserLowerHex(identity.privateKey, 32, "Ed25519 private key");
  if (browserPublicKeyFromPrivateKey(privateKey) !== identity.publicKey) {
    throw new BrowserConsumerProtocolError("software Consumer identity fields do not match its private key");
  }
}

export async function browserConsumerIdentityFromWebCryptoKey(
  signingKey: CryptoKey,
  publicKey: string,
): Promise<BrowserConsumerSigningIdentity> {
  assertNonExtractableEd25519SigningKey(signingKey);
  const normalizedPublicKey = requireBrowserLowerHex(
    publicKey,
    32,
    "browser Consumer public key",
  );
  const signer = webCryptoDocumentSigner(signingKey, normalizedPublicKey);
  const probe = browserUtf8(`mycomesh.browser-consumer.key-check.v1\0${normalizedPublicKey}`);
  const signature = await signer.sign(probe);
  if (!verifyEd25519Signature(signature, probe, normalizedPublicKey)) {
    throw new BrowserConsumerProtocolError(
      "stored browser Consumer signing key does not match its public key",
    );
  }
  return Object.freeze({
    publicKey: normalizedPublicKey,
    peerId: browserPeerIdFromPublicKey(normalizedPublicKey),
    signer,
  });
}

export async function generateBrowserWebCryptoConsumerIdentity(): Promise<{
  identity: BrowserConsumerSigningIdentity;
  signingKey: CryptoKey;
}> {
  const subtle = requiredSubtleCrypto();
  let generated: CryptoKeyPair;
  try {
    generated = await subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"],
    ) as CryptoKeyPair;
  } catch (error) {
    throw new BrowserConsumerProtocolError(
      "non-extractable WebCrypto Ed25519 keys are unavailable",
      { cause: error },
    );
  }
  assertNonExtractableEd25519SigningKey(generated.privateKey);
  let publicBytes: ArrayBuffer;
  try {
    publicBytes = await subtle.exportKey("raw", generated.publicKey);
  } catch (error) {
    throw new BrowserConsumerProtocolError("failed to export the public Consumer key", {
      cause: error,
    });
  }
  const publicKey = browserBytesToHex(new Uint8Array(publicBytes));
  const identity = await browserConsumerIdentityFromWebCryptoKey(generated.privateKey, publicKey);
  return { identity, signingKey: generated.privateKey };
}

export function signBrowserDocument<T extends Record<string, unknown>>(
  document: T,
  identityOrPrivateKey: BrowserSoftwareConsumerIdentity | string,
  options: BrowserSignDocumentOptions,
): BrowserSignedDocument<T> {
  const privateKey = typeof identityOrPrivateKey === "string"
    ? browserBytesToHex(lowerHexBytes(identityOrPrivateKey, 32, "Ed25519 private key"))
    : validatedSoftwareIdentity(identityOrPrivateKey).privateKey;
  const publicKey = browserPublicKeyFromPrivateKey(privateKey);
  const prepared = prepareDocumentSignature(document, publicKey, options);
  const signature: BrowserDocumentSignature = {
    ...prepared.metadata,
    signature: browserBytesToHex(
      ed25519.sign(prepared.message, browserHexToBytes(privateKey, 32)),
    ),
  };
  return { ...document, signature } as BrowserSignedDocument<T>;
}

export async function signBrowserDocumentAsync<T extends Record<string, unknown>>(
  document: T,
  identity: BrowserDocumentSigningIdentity,
  options: BrowserSignDocumentOptions,
): Promise<BrowserSignedDocument<T>> {
  assertBrowserConsumerIdentity(identity);
  const prepared = prepareDocumentSignature(document, identity.publicKey, options);
  let signatureBytes: Uint8Array;
  if (isBrowserSoftwareConsumerIdentity(identity)) {
    assertBrowserSoftwareConsumerIdentity(identity);
    signatureBytes = ed25519.sign(
      prepared.message,
      browserHexToBytes(identity.privateKey, 32),
    );
  } else {
    if (
      !identity.signer
      || identity.signer.kind !== "webcrypto-ed25519"
      || identity.signer.publicKey !== identity.publicKey
      || typeof identity.signer.sign !== "function"
    ) {
      throw new BrowserConsumerProtocolError("browser Consumer signer is invalid");
    }
    try {
      signatureBytes = await identity.signer.sign(Uint8Array.from(prepared.message));
    } catch (error) {
      if (error instanceof BrowserConsumerProtocolError) throw error;
      throw new BrowserConsumerProtocolError("browser Consumer signing failed", { cause: error });
    }
  }
  if (!verifyEd25519Signature(signatureBytes, prepared.message, identity.publicKey)) {
    throw new BrowserConsumerProtocolError("browser Consumer signer returned an invalid signature");
  }
  return {
    ...document,
    signature: {
      ...prepared.metadata,
      signature: browserBytesToHex(signatureBytes),
    },
  } as BrowserSignedDocument<T>;
}

export function verifyBrowserDocument<T extends Record<string, unknown> = BrowserJsonObject>(
  document: unknown,
  options: BrowserVerifyDocumentOptions,
): T {
  if (!isPlainObject(document)) {
    throw new BrowserConsumerProtocolError("signed document must be a plain JSON object");
  }
  const signature = document.signature;
  if (!isPlainObject(signature)) {
    throw new BrowserConsumerProtocolError("missing signature");
  }
  if (signature.purpose !== options.purpose) {
    throw new BrowserConsumerProtocolError("bad signature purpose");
  }
  if (options.audience !== undefined && signature.audience !== String(options.audience)) {
    throw new BrowserConsumerProtocolError("bad signature audience");
  }
  if (signature.timestamp === undefined) {
    throw new BrowserConsumerProtocolError("bad signature timestamp");
  }
  const timestamp = protocolTimestamp(signature.timestamp, "signature timestamp");
  const now = protocolTimestamp(options.now, "current time");
  const maxAgeSeconds = options.maxAgeSeconds ?? BROWSER_SIGNATURE_MAX_AGE_SECONDS;
  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 0) {
    throw new BrowserConsumerProtocolError("signature maximum age must be a non-negative integer");
  }
  if (maxAgeSeconds > 0 && timestamp > now + 30) {
    throw new BrowserConsumerProtocolError("signature timestamp is in the future");
  }
  if (maxAgeSeconds > 0 && now - timestamp > maxAgeSeconds) {
    throw new BrowserConsumerProtocolError("signature expired");
  }
  const publicKey = requiredText(signature.public_key, "signature public key");
  const signatureHex = requiredText(signature.signature, "signature");
  const publicBytes = browserHexToBytes(publicKey, 32, "signature public key");
  const signatureBytes = browserHexToBytes(signatureHex, 64, "signature");
  const unsigned = withoutField(document, "signature");
  const signatureMetadata = withoutField(signature, "signature");
  const message = signatureMessage(unsigned, signatureMetadata);
  let valid = false;
  try {
    valid = ed25519.verify(signatureBytes, message, publicBytes, { zip215: false });
  } catch {
    valid = false;
  }
  if (!valid) throw new BrowserConsumerProtocolError("bad signature");
  return unsigned as T;
}

export function browserSha256Hex(value: Uint8Array): string {
  return browserBytesToHex(sha256(value));
}

export function browserBytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

export function browserIsPlainObject(value: unknown): value is Record<string, unknown> {
  return isPlainObject(value);
}

export function requireBrowserLowerHex(value: unknown, bytes: number, label: string): string {
  const pattern = bytes === 16 ? HEX_16_PATTERN : bytes === 32 ? HEX_32_PATTERN : bytes === 64 ? HEX_64_PATTERN : null;
  if (typeof value !== "string" || (pattern ? !pattern.test(value) : !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value))) {
    throw new BrowserConsumerProtocolError(`${label} must be ${bytes} bytes of lowercase hex`);
  }
  return value;
}

export function protocolTimestamp(value: unknown, label: string): number {
  const resolved = value === undefined ? Math.floor(Date.now() / 1000) : value;
  if (!Number.isSafeInteger(resolved) || (resolved as number) < 0) {
    throw new BrowserConsumerProtocolError(`${label} must be a non-negative safe integer`);
  }
  return resolved as number;
}

function signatureMessage(document: unknown, signature: unknown): Uint8Array {
  return browserUtf8(canonicalBrowserJson({ document, signature }));
}

function prepareDocumentSignature<T extends Record<string, unknown>>(
  document: T,
  publicKey: string,
  options: BrowserSignDocumentOptions,
): {
  metadata: Omit<BrowserDocumentSignature, "signature">;
  message: Uint8Array;
} {
  if (!isPlainObject(document)) {
    throw new BrowserConsumerProtocolError("signed document must be a plain JSON object");
  }
  if (Object.hasOwn(document, "signature")) {
    throw new BrowserConsumerProtocolError("document is already signed");
  }
  const normalizedPublicKey = requireBrowserLowerHex(
    publicKey,
    32,
    "signature public key",
  );
  const purpose = requiredText(options?.purpose, "signature purpose");
  const timestamp = protocolTimestamp(options.timestamp, "signature timestamp");
  const nonce = options.nonce ?? browserBytesToHex(
    requireRandomBytes(options.randomBytes ?? secureBrowserRandomBytes, 16),
  );
  if (!HEX_16_PATTERN.test(nonce)) {
    throw new BrowserConsumerProtocolError("signature nonce must be 16 bytes of lowercase hex");
  }
  const metadata: Omit<BrowserDocumentSignature, "signature"> = {
    nonce,
    public_key: normalizedPublicKey,
    purpose,
    timestamp,
  };
  if (options.audience) metadata.audience = String(options.audience);
  return { metadata, message: signatureMessage(document, metadata) };
}

function canonicalize(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    assertUnicodeScalarString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new BrowserConsumerProtocolError("canonical JSON numbers must be safe integers");
    }
    return String(value);
  }
  if (typeof value !== "object" || value === undefined) {
    throw new BrowserConsumerProtocolError("value is not canonical JSON data");
  }
  if (ancestors.has(value)) {
    throw new BrowserConsumerProtocolError("canonical JSON cannot contain circular references");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => canonicalize(item, ancestors)).join(",")}]`;
    }
    if (!isPlainObject(value)) {
      throw new BrowserConsumerProtocolError("canonical JSON objects must use a plain prototype");
    }
    const keys = Object.keys(value).sort(compareUnicodeCodePoints);
    return `{${keys.map((key) => {
      assertUnicodeScalarString(key);
      return `${JSON.stringify(key)}:${canonicalize(value[key], ancestors)}`;
    }).join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function compareUnicodeCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (char) => char.codePointAt(0)!);
  const rightPoints = Array.from(right, (char) => char.codePointAt(0)!);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

function assertUnicodeScalarString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new BrowserConsumerProtocolError("canonical JSON strings cannot contain lone surrogates");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new BrowserConsumerProtocolError("canonical JSON strings cannot contain lone surrogates");
    }
  }
}

function lowerHexBytes(value: unknown, bytes: number, label: string): Uint8Array {
  const normalized = requireBrowserLowerHex(value, bytes, label);
  return browserHexToBytes(normalized, bytes, label);
}

function requireRandomBytes(randomBytes: BrowserRandomBytes, length: number): Uint8Array {
  const value = randomBytes(length);
  if (Object.prototype.toString.call(value) !== "[object Uint8Array]" || value.length !== length) {
    throw new BrowserConsumerProtocolError(`random source must return exactly ${length} bytes`);
  }
  return Uint8Array.from(value);
}

function requiredText(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new BrowserConsumerProtocolError(`${label} must be non-empty text`);
  }
  return value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function withoutField(value: Record<string, unknown>, field: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

function validatedSoftwareIdentity(
  identity: BrowserSoftwareConsumerIdentity,
): BrowserSoftwareConsumerIdentity {
  assertBrowserSoftwareConsumerIdentity(identity);
  return identity;
}

function isBrowserSoftwareConsumerIdentity(
  identity: BrowserDocumentSigningIdentity,
): identity is BrowserSoftwareConsumerIdentity {
  return Object.hasOwn(identity, "privateKey");
}

function requiredSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new BrowserConsumerProtocolError("WebCrypto is unavailable");
  }
  return subtle;
}

function assertNonExtractableEd25519SigningKey(value: CryptoKey): void {
  if (
    !value
    || typeof value !== "object"
    || value.type !== "private"
    || value.extractable !== false
    || value.algorithm?.name !== "Ed25519"
    || value.usages.length !== 1
    || value.usages[0] !== "sign"
  ) {
    throw new BrowserConsumerProtocolError(
      "browser Consumer signing key must be a non-extractable Ed25519 private CryptoKey",
    );
  }
}

function webCryptoDocumentSigner(
  signingKey: CryptoKey,
  publicKey: string,
): BrowserDocumentSigner {
  const signer: BrowserDocumentSigner = {
    kind: "webcrypto-ed25519",
    publicKey,
    async sign(message: Uint8Array): Promise<Uint8Array> {
      if (Object.prototype.toString.call(message) !== "[object Uint8Array]") {
        throw new BrowserConsumerProtocolError("browser Consumer signature input must be bytes");
      }
      let signature: ArrayBuffer;
      try {
        signature = await requiredSubtleCrypto().sign(
          { name: "Ed25519" },
          signingKey,
          Uint8Array.from(message),
        );
      } catch (error) {
        throw new BrowserConsumerProtocolError("WebCrypto Ed25519 signing failed", {
          cause: error,
        });
      }
      const bytes = new Uint8Array(signature);
      if (bytes.length !== 64) {
        throw new BrowserConsumerProtocolError("WebCrypto returned an invalid Ed25519 signature");
      }
      return bytes;
    },
  };
  return Object.freeze(signer);
}

function verifyEd25519Signature(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: string,
): boolean {
  if (
    Object.prototype.toString.call(signature) !== "[object Uint8Array]"
    || signature.length !== 64
  ) {
    return false;
  }
  try {
    return ed25519.verify(
      signature,
      message,
      browserHexToBytes(publicKey, 32),
      { zip215: false },
    );
  } catch {
    return false;
  }
}
