import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn as defaultSpawn } from "node:child_process";
import { createServer } from "node:http";
import { rootCertificates } from "node:tls";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { Agent, ProxyAgent } from "undici";
import { RESERVED_AUTH_SCHEMA, RESERVED_SIGNED_SCHEMA, buildReservedAuthorization, verifyReservedAuthorization, verifyReservedReceipt, decodeCapacityChannel, reservedSettlementKey } from "./consumer-reserved.mjs";
import { ConsumerSessions } from "./consumer-sessions.mjs";
import { ConsumerHistoryLedger } from "./consumer-history.mjs";
import { ConsumerRequestJournal, requestPayloadHash } from "./consumer-request-journal.mjs";
import { ConsumerRelayDiscovery, parseDiscoveryConfig } from "./consumer-discovery.mjs";

export const DEFAULT_BASE_URL = "http://127.0.0.1:8110/v1";
export const DEFAULT_RELAY_URL = "https://bridge.mycomesh.xyz";
export const DEFAULT_MAX_FEE_UNITS = 100000;
// Public API model slug; `codex-standard-v1` is only the settlement channel.
export const DEFAULT_MODEL = "gpt-5.5";
export const DEFAULT_CHAIN_ID = 11155111;
export const DEFAULT_SETTLEMENT = "0x6b543a0ff6fae02172c6f205759b1b9de8a6d218";
export const DEFAULT_CHANNEL_HASH =
  "0xdedf8b58276b80863f354409c963cbaddf4ca7d5b866d528ff1386d74b339104";
export const DEFAULT_PRICING_HASH =
  "0x365dfdf311ab90468009d2a665803ca4321c50ab9ed0809ac2c6dc4a73ac9734";
export const DEFAULT_RELAY_PAYMENT_ADDRESS =
  "0x27bd63aef83554700042685c2862da6f6a9197e8";
export const DEFAULT_RELAY_SIGNER_ADDRESS =
  "0x36390747ae29f5f8ae55ddd7daace89ad57644cf";
export const DEFAULT_STABLECOIN = "0xeb487c6e778248e16361dc313e4223c20d4c23b5";
export const DEFAULT_RPC_URLS = [
  "https://ethereum-sepolia-rpc.publicnode.com",
  "https://sepolia.drpc.org",
  "https://rpc.sepolia.ethpandaops.io",
  "https://sepolia.gateway.tenderly.co",
];

const ZERO_ADDRESS = "0x" + "0".repeat(40);
const AUTH_SCHEMA = "mycomesh.x402.myco-credit-v2";
const SIGNED_SCHEMA = "mycomesh.settlement.v8.signed.v1";
const V9_AUTH_SCHEMA = "mycomesh.x402.myco-credit-v3";
const V9_SIGNED_SCHEMA = "mycomesh.settlement.v9.signed.v1";
export const RESPONSE_PROOF_SCHEMA = "mycomesh.provider-response-proof.v1";
function protocolVersion(value = 8) {
  if (value !== 8 && value !== 9 && value !== 10) throw new Error("unsupported settlement protocol version");
  return value;
}
function authorizationVersion(value) {
  if (value?.schema === AUTH_SCHEMA) return 8;
  if (value?.schema === V9_AUTH_SCHEMA) return 9;
  throw new Error("unsupported payment authorization schema");
}
const DOMAIN_TYPE =
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const AUTHORIZATION_TYPE =
  "PaymentAuthorization(bytes32 requestId,bytes32 requestHash,address key,address relay,address relaySigner,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,uint256 maxFee,uint64 issuedAt,uint64 deadline)";
const RECEIPT_TYPE =
  "UsageReceipt(bytes32 authorizationHash,bytes32 responseHash,address provider,address providerSigner,address relay,address pool,uint256 inputTokens,uint256 outputTokens,uint256 actualFee)";
const RETRYABLE_RELAY_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const MAX_AUTHORIZATION_TTL = 3600;
const V9_MAX_AUTHORIZATION_TTL = 10800;
const MAX_BODY_BYTES = 32 * 1024 * 1024;
const AUTHORIZATION_CLOCK_SKEW_SECONDS = 300;
const RESPONSES_REQUEST_OPTION_FIELDS = new Set([
  "background",
  "client_metadata",
  "context_management",
  "conversation",
  "include",
  "instructions",
  "metadata",
  "max_tool_calls",
  "moderation",
  "parallel_tool_calls",
  "previous_response_id",
  "prompt",
  "prompt_cache_key",
  "prompt_cache_options",
  "prompt_cache_retention",
  "reasoning",
  "safety_identifier",
  "service_tier",
  "store",
  "temperature",
  "text",
  "tool_choice",
  "tools",
  "top_logprobs",
  "top_p",
  "truncation",
  "user",
]);
const RESPONSES_LOCAL_OPTION_FIELDS = new Set(["stream", "stream_options"]);
const MAX_SHARE_MINUTES = 24 * 60;
const TUNNEL_START_TIMEOUT_MS = 30_000;
const TUNNEL_STOP_TIMEOUT_MS = 2_000;
const RELAY_HEALTH_CACHE_MS = 5_000;
const RELAY_HEALTH_RETRY_DELAY_MS = 250;
// Readiness is a liveness probe for local tooling and the dashboard. Keep it
// bounded even when an RPC provider stalls; inference keeps its own deadline.
const READINESS_TIMEOUT_MS = 5_000;
const WALLET_CHALLENGE_TTL_MS = 5 * 60_000;

const DEFAULT_NETWORK = Object.freeze({
  protocol_version: 8,
  chain_id: DEFAULT_CHAIN_ID,
  network_name: "Sepolia testnet",
  settlement_contract: DEFAULT_SETTLEMENT,
  stablecoin: DEFAULT_STABLECOIN,
  stablecoin_symbol: "tUSDC",
  stablecoin_decimals: 6,
  rpc_urls: DEFAULT_RPC_URLS,
  explorer_url: "https://sepolia.etherscan.io",
});

function bytesToHex(value) {
  return Buffer.from(value).toString("hex");
}

function hexToBytes(value, label = "hex value") {
  const text = String(value || "");
  if (!/^0x[0-9a-fA-F]*$/.test(text) || text.length % 2 !== 0) {
    throw new Error(`${label} must be hexadecimal`);
  }
  return Uint8Array.from(Buffer.from(text.slice(2), "hex"));
}

function normalizeBytes32(value, label = "bytes32") {
  const text = String(value || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(text)) {
    throw new Error(`${label} must be a 32-byte 0x-prefixed hex value`);
  }
  return text;
}

export function normalizeAddress(value, label = "address") {
  const text = String(value || "").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(text)) {
    throw new Error(`${label} must be a 20-byte 0x-prefixed hex value`);
  }
  return text;
}

function nonzeroAddress(value, label) {
  const address = normalizeAddress(value, label);
  if (address === ZERO_ADDRESS) throw new Error(`${label} cannot be zero`);
  return address;
}

function positiveBigInt(value, label) {
  if (typeof value === "boolean" || value === undefined || value === null || value === "") {
    throw new Error(`${label} must be an integer`);
  }
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label} must be an integer`);
  }
  if (parsed <= 0n) throw new Error(`${label} must be positive`);
  return parsed;
}

function uintBigInt(value, label) {
  if (typeof value === "boolean" || value === undefined || value === null || value === "") {
    throw new Error(`${label} must be an integer`);
  }
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label} must be an integer`);
  }
  if (parsed < 0n) throw new Error(`${label} cannot be negative`);
  return parsed;
}

function jsonInteger(value) {
  const parsed = typeof value === "bigint" ? value : BigInt(value);
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function decodeBase64Url(value) {
  return Uint8Array.from(Buffer.from(String(value), "base64url"));
}

function stableStringify(value) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("request must contain canonical JSON data");
    return JSON.stringify(value);
  }
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }
  throw new Error("request must contain canonical JSON data");
}

function abiWord(value) {
  if (typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value)) {
    return Buffer.concat([Buffer.alloc(12), Buffer.from(value.slice(2), "hex")]);
  }
  if (typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value)) {
    return Buffer.from(value.slice(2), "hex");
  }
  const parsed = uintBigInt(value, "ABI uint");
  const output = Buffer.alloc(32);
  let remaining = parsed;
  for (let index = 31; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error("ABI uint is too large");
  return output;
}

function hashText(value) {
  return Uint8Array.from(keccak_256(Buffer.from(value, "utf8")));
}

function keccakHex(value) {
  return `0x${bytesToHex(keccak_256(value))}`;
}

function paymentPrivateKey(value) {
  const text = String(value || "").trim();
  let raw;
  if (text.startsWith("myco_sk_")) {
    raw = decodeBase64Url(text.slice("myco_sk_".length));
  } else {
    raw = hexToBytes(text.startsWith("0x") ? text : `0x${text}`, "payment key");
  }
  if (raw.length !== 32) throw new Error("payment key must be 32 bytes");
  const scalar = BigInt(`0x${bytesToHex(raw)}`);
  if (scalar <= 0n || scalar >= secp256k1.CURVE.n) {
    throw new Error("payment key is outside secp256k1 range");
  }
  return raw;
}

export function generatePaymentKey() {
  while (true) {
    const raw = randomBytes(32);
    try {
      paymentPrivateKey(raw.toString("hex"));
      return `myco_sk_${raw.toString("base64url")}`;
    } catch {
      // A uniformly random 32-byte scalar is almost always valid.
    }
  }
}

export function paymentKeyAddress(value) {
  const publicKey = secp256k1.getPublicKey(paymentPrivateKey(value), false).slice(1);
  return `0x${bytesToHex(keccak_256(publicKey).slice(-20))}`;
}

function signDigest(privateKeyValue, digest) {
  const signature = secp256k1.sign(digest, paymentPrivateKey(privateKeyValue), {
    lowS: true,
    prehash: false,
  });
  const raw = Buffer.concat([
    Buffer.from(signature.toCompactRawBytes()),
    Buffer.from([27 + signature.recovery]),
  ]);
  return `0x${raw.toString("hex")}`;
}

function recoverAddress(digest, signatureValue) {
  const raw = hexToBytes(signatureValue, "signature");
  if (raw.length !== 65) throw new Error("signature must be 65 bytes");
  const recovery = raw[64] >= 27 ? raw[64] - 27 : raw[64];
  if (recovery < 0 || recovery > 3) throw new Error("signature recovery id is invalid");
  const signature = secp256k1.Signature.fromCompact(raw.slice(0, 64)).addRecoveryBit(recovery);
  const publicKey = signature.recoverPublicKey(digest).toRawBytes(false).slice(1);
  return `0x${bytesToHex(keccak_256(publicKey).slice(-20))}`;
}

export function walletMessageDigest(message) {
  const body = Buffer.from(String(message), "utf8");
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${body.length}`, "utf8");
  return Uint8Array.from(keccak_256(Buffer.concat([prefix, body])));
}

export function createReceiptStatusQuery(privateKey, { chainId, contract, requestId, channelId, issuedAt = Math.floor(Date.now() / 1000) }) {
  const query = { chain_id: Number(chainId), settlement_contract: normalizeAddress(contract),
    key: paymentKeyAddress(privateKey), request_id: normalizeBytes32(requestId, "request_id"), issued_at: Number(issuedAt) };
  if (!Number.isSafeInteger(query.chain_id) || query.chain_id <= 0 || !Number.isSafeInteger(query.issued_at) || query.issued_at <= 0) {
    throw new Error("invalid receipt status query scope");
  }
  if (channelId !== undefined) query.channel_id = normalizeBytes32(channelId, "channel_id");
  const message = `MycoMesh receipt status v${channelId === undefined ? 1 : 2}\nchain_id:${query.chain_id}\nsettlement_contract:${query.settlement_contract}\nkey:${query.key}${channelId === undefined ? "" : `\nchannel_id:${query.channel_id}`}\nrequest_id:${query.request_id}\nissued_at:${query.issued_at}`;
  return { ...query, signature: signDigest(privateKey, walletMessageDigest(message)) };
}

function typedDigest(structHash, chainId, contract, version = 8) {
  const domain = keccak_256(
    Buffer.concat([
      Buffer.from(hashText(DOMAIN_TYPE)),
      Buffer.from(hashText("MycoMesh Settlement")),
      Buffer.from(hashText(String(protocolVersion(version)))),
      abiWord(chainId),
      abiWord(normalizeAddress(contract)),
    ]),
  );
  return Uint8Array.from(
    keccak_256(Buffer.concat([Buffer.from([0x19, 0x01]), Buffer.from(domain), Buffer.from(hexToBytes(structHash))])),
  );
}

function authorizationStructHash(authorization) {
  const encoded = Buffer.concat([
    Buffer.from(hashText(AUTHORIZATION_TYPE)),
    abiWord(authorization.request_id),
    abiWord(authorization.request_hash),
    abiWord(authorization.key),
    abiWord(authorization.relay),
    abiWord(authorization.relay_signer),
    abiWord(authorization.channel),
    abiWord(authorization.pricing_version),
    abiWord(authorization.pricing_hash),
    abiWord(authorization.max_fee),
    abiWord(authorization.issued_at),
    abiWord(authorization.deadline),
  ]);
  return keccakHex(encoded);
}

function receiptStructHash(receipt) {
  const encoded = Buffer.concat([
    Buffer.from(hashText(RECEIPT_TYPE)),
    abiWord(receipt.authorization_hash),
    abiWord(receipt.response_hash),
    abiWord(receipt.provider),
    abiWord(receipt.provider_signer),
    abiWord(receipt.relay),
    abiWord(receipt.pool || ZERO_ADDRESS),
    abiWord(receipt.input_tokens),
    abiWord(receipt.output_tokens),
    abiWord(receipt.actual_fee),
  ]);
  return keccakHex(encoded);
}

export function inferenceRequestHash({
  endpoint,
  model,
  input,
  messages,
  maxOutputTokens,
  options,
}) {
  const normalizedEndpoint = String(endpoint || "").trim().toLowerCase();
  if (!["responses", "chat"].includes(normalizedEndpoint)) {
    throw new Error("inference request endpoint must be responses or chat");
  }
  const normalizedModel = String(model || "");
  if (!normalizedModel) throw new Error("inference request model is required");
  const outputLimit = positiveBigInt(maxOutputTokens, "max_output_tokens");
  const requestOptions = normalizeInferenceOptions(normalizedEndpoint, options);
  const envelope = {
    request_hash_version: requestOptions
      ? "mycomesh.inference.request.v3"
      : "mycomesh.inference.request.v2",
    endpoint: normalizedEndpoint,
    model: normalizedModel,
    [normalizedEndpoint === "chat" ? "messages" : "input"]:
      normalizedEndpoint === "chat"
        ? messages ?? [{ role: "user", content: String(input || "") }]
        : input ?? "",
    max_output_tokens: jsonInteger(outputLimit),
  };
  if (requestOptions) envelope.options = requestOptions;
  return `0x${createHash("sha256").update(stableStringify(envelope), "utf8").digest("hex")}`;
}

export function derivePromptCacheKey({ endpoint, model, input, messages, options }) {
  const explicit = options && typeof options === "object" ? options.prompt_cache_key : undefined;
  if (typeof explicit === "string" && explicit.trim()) return explicit.trim();
  const normalizedEndpoint = String(endpoint || "").trim().toLowerCase();
  if (!["responses", "chat"].includes(normalizedEndpoint)) return null;
  const seed = { model: String(model || "") };
  for (const field of ["reasoning", "tool_choice", "tools", "functions", "instructions"]) {
    const value = options && typeof options === "object" ? options[field] : undefined;
    if (value !== undefined && value !== null && value !== "" && !(Array.isArray(value) && value.length === 0)) {
      seed[field] = value;
    }
  }
  const source = normalizedEndpoint === "chat" ? (messages ?? [{ role: "user", content: String(input || "") }]) : (input ?? "");
  let firstUser;
  const system = [];
  if (Array.isArray(source)) {
    for (const item of source) {
      if (!item || typeof item !== "object") continue;
      const role = String(item.role || "").trim().toLowerCase();
      if (role === "system" || role === "developer") system.push(item.content);
      if (firstUser === undefined && role === "user") firstUser = item.content;
      if (firstUser === undefined && item.type === "input_text") firstUser = item.text;
    }
  } else if (typeof source === "string" && source.trim()) {
    firstUser = source;
  }
  if (system.length) seed.system = system;
  if (firstUser === undefined || firstUser === null || firstUser === "" || (Array.isArray(firstUser) && !firstUser.length)) return null;
  seed.first_user = firstUser;
  return `myco_csp_${createHash("sha256").update(stableStringify(seed), "utf8").digest("hex")}`;
}

function normalizeInferenceOptions(endpoint, options) {
  if (options === undefined || options === null) return null;
  if (typeof options !== "object" || Array.isArray(options)) {
    throw new Error("inference request options must be a JSON object");
  }
  const requestOptions = Object.fromEntries(
    Object.entries(options).filter(([key]) => !RESPONSES_LOCAL_OPTION_FIELDS.has(key)),
  );
  if (endpoint !== "responses") {
    const unknown = Object.keys(requestOptions).filter((key) => !RESPONSES_REQUEST_OPTION_FIELDS.has(key)).sort();
    if (unknown.length) throw new Error(`unsupported Chat request options: ${unknown.join(", ")}`);
    return Object.keys(requestOptions).length ? requestOptions : null;
  }
  const allowed = new Set([...RESPONSES_REQUEST_OPTION_FIELDS, ...RESPONSES_LOCAL_OPTION_FIELDS]);
  const unknown = Object.keys(options).filter((key) => !allowed.has(key)).sort();
  if (unknown.length) throw new Error(`unsupported Responses request options: ${unknown.join(", ")}`);
  const normalized = {};
  for (const key of [...RESPONSES_REQUEST_OPTION_FIELDS].sort()) {
    if (Object.prototype.hasOwnProperty.call(requestOptions, key)) normalized[key] = requestOptions[key];
  }
  return Object.keys(normalized).length ? normalized : null;
}

export function buildAuthorization({
  protocolVersion: requestedVersion = 8,
  paymentKey,
  chainId,
  settlementContract,
  requestId,
  requestHash,
  relay,
  relaySigner,
  channelHash,
  pricingVersion,
  pricingHash,
  maxFee,
  issuedAt = Math.floor(Date.now() / 1000),
  deadline = issuedAt + 900,
  maxAuthorizationTtlSeconds = MAX_AUTHORIZATION_TTL,
}) {
  const version = protocolVersion(requestedVersion);
  const key = paymentKeyAddress(paymentKey);
  const authorization = {
    request_id: normalizeBytes32(requestId, "request_id"),
    request_hash: normalizeBytes32(requestHash, "request_hash"),
    key,
    relay: nonzeroAddress(relay, "relay"),
    relay_signer: nonzeroAddress(relaySigner, "relay_signer"),
    channel: normalizeBytes32(channelHash, "channel"),
    pricing_version: jsonInteger(positiveBigInt(pricingVersion, "pricing_version")),
    pricing_hash: normalizeBytes32(pricingHash, "pricing_hash"),
    max_fee: jsonInteger(positiveBigInt(maxFee, "max_fee")),
    issued_at: jsonInteger(positiveBigInt(issuedAt, "issued_at")),
    deadline: jsonInteger(positiveBigInt(deadline, "deadline")),
  };
  if (authorization.request_id === `0x${"0".repeat(64)}`) throw new Error("V8 request_id cannot be zero");
  if (authorization.request_hash === `0x${"0".repeat(64)}`) throw new Error("V8 request_hash cannot be zero");
  if (authorization.channel === `0x${"0".repeat(64)}`) throw new Error("V8 channel cannot be zero");
  if (authorization.pricing_hash === `0x${"0".repeat(64)}`) throw new Error("V8 pricing_hash cannot be zero");
  const issued = BigInt(authorization.issued_at);
  const expires = BigInt(authorization.deadline);
  if (![3600, ...(version === 9 ? [V9_MAX_AUTHORIZATION_TTL] : [])].includes(maxAuthorizationTtlSeconds)
      || expires <= issued || expires - issued > BigInt(maxAuthorizationTtlSeconds)) {
    throw new Error(`V${version} authorization exceeds the verified contract lifetime`);
  }
  const authorizationHash = authorizationStructHash(authorization);
  const digest = typedDigest(authorizationHash, chainId, settlementContract, version);
  return {
    schema: version === 9 ? V9_AUTH_SCHEMA : AUTH_SCHEMA,
    chain_id: jsonInteger(positiveBigInt(chainId, "chain_id")),
    settlement_contract: nonzeroAddress(settlementContract, "settlement_contract"),
    authorization,
    authorization_hash: authorizationHash,
    authorization_digest: `0x${bytesToHex(digest)}`,
    key_signature: signDigest(paymentKey, digest),
  };
}

function verifyAuthorization(value, expected = {}) {
  if (value?.schema === RESERVED_AUTH_SCHEMA) return verifyReservedAuthorization(value, expected);
  const version = authorizationVersion(value);
  if (!value.authorization) throw new Error("payment authorization is missing");
  if (expected.protocolVersion !== undefined && version !== protocolVersion(expected.protocolVersion)) throw new Error("settlement protocol version mismatch");
  const authorization = value.authorization;
  const chainId = uintBigInt(value.chain_id, "chain_id");
  const contract = nonzeroAddress(value.settlement_contract, "settlement_contract");
  const normalized = {
    request_id: normalizeBytes32(authorization.request_id, "request_id"),
    request_hash: normalizeBytes32(authorization.request_hash, "request_hash"),
    key: nonzeroAddress(authorization.key, "key"),
    relay: nonzeroAddress(authorization.relay, "relay"),
    relay_signer: nonzeroAddress(authorization.relay_signer, "relay_signer"),
    channel: normalizeBytes32(authorization.channel, "channel"),
    pricing_version: jsonInteger(positiveBigInt(authorization.pricing_version, "pricing_version")),
    pricing_hash: normalizeBytes32(authorization.pricing_hash, "pricing_hash"),
    max_fee: jsonInteger(positiveBigInt(authorization.max_fee, "max_fee")),
    issued_at: jsonInteger(positiveBigInt(authorization.issued_at, "issued_at")),
    deadline: jsonInteger(positiveBigInt(authorization.deadline, "deadline")),
  };
  if (expected.chainId !== undefined && chainId !== BigInt(expected.chainId)) throw new Error("V8 chain_id mismatch");
  if (expected.contract && contract !== normalizeAddress(expected.contract)) throw new Error("V8 settlement_contract mismatch");
  if (expected.relay && normalized.relay !== normalizeAddress(expected.relay)) throw new Error("V8 relay mismatch");
  if (expected.relaySigner && normalized.relay_signer !== normalizeAddress(expected.relaySigner)) throw new Error("V8 relay_signer mismatch");
  if (expected.requestId && normalized.request_id !== normalizeBytes32(expected.requestId)) throw new Error("V8 request_id mismatch");
  if (expected.requestHash && normalized.request_hash !== normalizeBytes32(expected.requestHash)) throw new Error("V8 request_hash mismatch");
  const now = Math.floor(Date.now() / 1000);
  const issued = BigInt(normalized.issued_at);
  const deadline = BigInt(normalized.deadline);
  if (issued > BigInt(now + 30) || deadline < BigInt(now)) throw new Error("V8 payment authorization is outside its time window");
  if (deadline <= issued || deadline - issued > BigInt(version === 9 ? V9_MAX_AUTHORIZATION_TTL : MAX_AUTHORIZATION_TTL)) throw new Error(`V${version} payment authorization lifetime is invalid`);
  const structHash = authorizationStructHash(normalized);
  if (normalizeBytes32(value.authorization_hash, "authorization_hash") !== structHash) throw new Error("V8 authorization hash mismatch");
  const digest = typedDigest(structHash, chainId, contract, version);
  if (normalizeBytes32(value.authorization_digest, "authorization_digest") !== `0x${bytesToHex(digest)}`) throw new Error("V8 authorization digest mismatch");
  if (recoverAddress(digest, value.key_signature) !== normalized.key) throw new Error("V8 payment key signature mismatch");
  return { ...value, chain_id: jsonInteger(chainId), settlement_contract: contract, authorization: normalized };
}

function verifySignedReceipt(value, expected = {}) {
  if (value?.schema === RESERVED_SIGNED_SCHEMA) return verifyReservedReceipt(value, expected);
  const version = value?.schema === V9_SIGNED_SCHEMA ? 9 : value?.schema === SIGNED_SCHEMA ? 8 : null;
  if (version === null) throw new Error("unsupported signed receipt schema");
  if (expected.protocolVersion !== undefined && expected.protocolVersion !== version) throw new Error("settlement protocol version mismatch");
  const authorization = verifyAuthorization(value.authorization, { ...expected, protocolVersion: version });
  if (version === 9 && (uintBigInt(value.chain_id, "chain_id") !== BigInt(authorization.chain_id)
      || nonzeroAddress(value.settlement_contract, "settlement_contract") !== authorization.settlement_contract)) {
    throw new Error("V9 signed receipt deployment mismatch");
  }
  const receipt = value.receipt;
  if (!receipt || typeof receipt !== "object") throw new Error("V8 signed receipt is missing");
  const normalizedReceipt = {
    authorization_hash: normalizeBytes32(receipt.authorization_hash, "authorization_hash"),
    response_hash: normalizeBytes32(receipt.response_hash, "response_hash"),
    provider: nonzeroAddress(receipt.provider, "provider"),
    provider_signer: nonzeroAddress(receipt.provider_signer, "provider_signer"),
    relay: nonzeroAddress(receipt.relay, "relay"),
    pool: normalizeAddress(receipt.pool || ZERO_ADDRESS, "pool"),
    input_tokens: jsonInteger(uintBigInt(receipt.input_tokens, "input_tokens")),
    output_tokens: jsonInteger(uintBigInt(receipt.output_tokens, "output_tokens")),
    actual_fee: jsonInteger(positiveBigInt(receipt.actual_fee, "actual_fee")),
  };
  if (normalizedReceipt.authorization_hash !== authorization.authorization_hash) throw new Error("V8 signed receipt authorization mismatch");
  if (normalizedReceipt.relay !== authorization.authorization.relay) throw new Error("V8 signed receipt Relay payout mismatch");
  if (value.key_signature !== authorization.key_signature) throw new Error("V8 signed receipt payment signature mismatch");
  if (BigInt(normalizedReceipt.actual_fee) > BigInt(authorization.authorization.max_fee)) throw new Error("receipt exceeds authorized max fee");
  const digest = typedDigest(receiptStructHash(normalizedReceipt), authorization.chain_id, authorization.settlement_contract, version);
  if (recoverAddress(digest, value.provider_signature) !== normalizedReceipt.provider_signer) throw new Error("V8 Provider signature mismatch");
  if (recoverAddress(digest, value.relay_signature) !== authorization.authorization.relay_signer) throw new Error("V8 Relay signature mismatch");
  return { authorization, receipt: normalizedReceipt };
}

const responseControls = new WeakMap();

function deadlineError() {
  const error = new Error("request deadline exceeded");
  error.name = "TimeoutError";
  error.statusCode = 504;
  return error;
}

function remainingMs(deadline) {
  if (!Number.isFinite(deadline)) return Infinity;
  const left = deadline - performance.now();
  if (left <= 0) throw deadlineError();
  return Math.max(1, Math.ceil(left));
}

async function withinDeadline(promise, deadline) {
  if (!Number.isFinite(deadline)) return promise;
  let timer;
  try {
    const milliseconds = remainingMs(deadline);
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(deadlineError()), milliseconds);
      timer.unref?.();
    })]);
  } finally { clearTimeout(timer); }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(deadlineError()), timeoutMs);
  timer.unref?.();
  const external = options.signal;
  const abort = () => controller.abort(external.reason);
  external?.addEventListener("abort", abort, { once: true });
  if (external?.aborted) abort();
  const cleanup = () => { clearTimeout(timer); external?.removeEventListener("abort", abort); };
  try {
    const response = await fetch(url, { redirect: "error", ...options, signal: controller.signal });
    // Keep the same deadline alive until the complete body is consumed.
    responseControls.set(response, { controller, cleanup });
    return response;
  } catch (error) { cleanup(); throw error; }
}

async function readJsonResponse(response) {
  const control = responseControls.get(response);
  let text;
  try {
    const reader = response.body?.getReader();
    if (!reader) text = "";
    else {
      let size = 0;
      const chunks = [];
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_BODY_BYTES) {
            const error = new Error("Relay response body exceeds the size limit");
            control?.controller.abort(error);
            await reader.cancel().catch(() => {});
            throw error;
          }
          chunks.push(Buffer.from(value));
        }
        text = Buffer.concat(chunks, size).toString("utf8");
      } finally { reader.releaseLock(); }
    }
  } finally { control?.cleanup(); responseControls.delete(response); }
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return { error: { message: text.slice(0, 1000), type: "relay_error" } };
  }
}

function openaiError(message, type = "server_error", code = type) {
  return { error: { message: String(message), type, param: null, code } };
}

function parseNetworkConfig(path, { allowControlledTest = false } = {}) {
  if (!path) return { ...DEFAULT_NETWORK };
  if (!existsSync(path)) throw new Error("Configured settlement network manifest is missing");
  try {
    const network = JSON.parse(readFileSync(path, "utf8"));
    const deploymentPath = network.deployment ? join(dirname(path), network.deployment) : path;
    if (network.deployment && !existsSync(deploymentPath)) throw new Error("referenced deployment manifest is missing");
    const deployment = network.deployment ? JSON.parse(readFileSync(deploymentPath, "utf8")) : network;
    if (network.relay_discovery !== undefined && ["network_id", "channel_id"].some((name) => deployment[name] !== network[name])) {
      throw new Error("Discovery manifest and deployment disagree");
    }
    const version = protocolVersion(deployment.protocol_version);
    if (version >= 9 && (deployment.eip712_name !== "MycoMesh Settlement" || deployment.eip712_version !== String(version))) throw new Error(`V${version} deployment domain is not explicit`);
    if (version >= 9) validateV9Deployment(deployment, { allowControlledTest });
    if (version === 10 && (deployment.reservation_mode !== "provider_bound_channel" || String(deployment.chain_domain) !== "10" || deployment.max_authorization_ttl_seconds !== 10800)) throw new Error("V10 requires explicit fixed-budget channel policy");
    const capacityIds = network.capacity_channel_ids ?? deployment.capacity_channel_ids ?? [];
    if (!Array.isArray(capacityIds) || capacityIds.length > 32 || new Set(capacityIds.map(id => normalizeBytes32(id))).size !== capacityIds.length) throw new Error("invalid capacity channels");
    if (network !== deployment && network.capacity_channel_ids !== undefined && deployment.capacity_channel_ids !== undefined
        && JSON.stringify([...network.capacity_channel_ids].sort()) !== JSON.stringify([...deployment.capacity_channel_ids].sort())) throw new Error("network and deployment capacity channels disagree");
    if (network.require_response_proof !== undefined && typeof network.require_response_proof !== "boolean") throw new Error("require_response_proof must be boolean");
    const tlsCaFile = resolveTlsCaFile(network.tls_ca_file ?? deployment.tls_ca_file, path, { allowControlledTest });
    if (network.relay_fallbacks !== undefined && (!Array.isArray(network.relay_fallbacks) || network.relay_fallbacks.length > 3)) throw new Error("relay_fallbacks must contain at most three pinned Relays");
    const relayEntries = [network.relay, ...(network.relay_fallbacks || [])].filter((entry) => entry !== undefined);
    const relayUrls = [...new Set(relayEntries.map((entry) => {
      if (!entry || typeof entry.public_url !== "string") throw new Error("Relay manifest entry requires public_url");
      const url = new URL(entry.public_url);
      if ((url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)))
          || url.username || url.password || url.search || url.hash) throw new Error("Relay manifest URLs require HTTPS without credentials/query/fragment");
      return url.href.replace(/\/+$/, "");
    }))];
    const relayPins = {};
    for (const entry of relayEntries) {
      if (entry.payment_address === undefined && entry.attestation_address === undefined) continue;
      const url = new URL(entry.public_url).href.replace(/\/+$/, "");
      const pin = { payment_address: nonzeroAddress(entry.payment_address, "Relay payment address"),
        attestation_address: nonzeroAddress(entry.attestation_address, "Relay attestation address") };
      if (relayPins[url] && (relayPins[url].payment_address !== pin.payment_address
          || relayPins[url].attestation_address !== pin.attestation_address)) throw new Error("conflicting Relay identity pins");
      relayPins[url] = pin;
    }
    const parsed = {
      protocol_version: version,
      max_authorization_ttl_seconds: version >= 9 ? (deployment.max_authorization_ttl_seconds ?? 3600) : 3600,
      authorization_deadline_seconds: version >= 9 ? (deployment.authorization_deadline_seconds ?? 900) : 900,
      require_response_proof: version >= 9 || network.require_response_proof === true,
      capacity_channel_ids: capacityIds.map(id => normalizeBytes32(id, "capacity channel ID")),
      reservation_mode: version === 10 ? "provider_bound_channel" : undefined,
      committee_mode: deployment.committee_mode,
      independence_attested: deployment.independence_attested,
      relay_urls: relayUrls,
      relay_pins: relayPins,
      tls_ca_file: tlsCaFile,
      chain_id: Number(deployment.chain_id),
      network_name: Number(deployment.chain_id) === DEFAULT_CHAIN_ID ? "Sepolia testnet" : "EVM network",
      settlement_contract: normalizeAddress(deployment.settlement),
      stablecoin: normalizeAddress(deployment.stablecoin),
      stablecoin_symbol: "tUSDC",
      stablecoin_decimals: 6,
      rpc_urls: (network.settlement_rpc_urls || [network.settlement_rpc_url]).filter(Boolean),
      explorer_url: Number(deployment.chain_id) === DEFAULT_CHAIN_ID ? "https://sepolia.etherscan.io" : "",
    };
    parsed.relay_discovery = parseDiscoveryConfig(network, parsed);
    return parsed;
  } catch (error) {
    throw new Error(`Invalid configured settlement network: ${error.message}`);
  }
}

function validateV9Deployment(value, { allowControlledTest = false } = {}) {
  const maxTtl = value.max_authorization_ttl_seconds ?? 3600;
  const deadlineSeconds = value.authorization_deadline_seconds ?? 900;
  if (![3600, 10800].includes(maxTtl) || !Number.isSafeInteger(deadlineSeconds) || deadlineSeconds <= 0
      || deadlineSeconds + AUTHORIZATION_CLOCK_SKEW_SECONDS > maxTtl) throw new Error("invalid V9 authorization timing policy");
  const required = ["chain_id", "deployer", "stablecoin", "settlement", "treasury", "governance", "channel", "channel_hash", "pricing_version", "pricing_hash", "reward_token", "policy", "adjudicators", "adjudication_threshold", "adjudicator_operators", "independence_attested", "network_id", "channel_id", "backend_policy"];
  if (required.some((name) => value[name] === undefined)) throw new Error("V9 deployment requires explicit policy and independent committee fields");
  const uint = (item, name, bits = 256) => {
    if (!(typeof item === "number" && Number.isSafeInteger(item)) && !(typeof item === "string" && /^[0-9]+$/.test(item))) throw new Error(`invalid V9 ${name}`);
    const result = BigInt(item);
    if (result < 0n || result >= (1n << BigInt(bits))) throw new Error(`invalid V9 ${name}`);
    return result;
  };
  if (!Number.isSafeInteger(value.chain_id) || value.chain_id <= 0 || uint(value.pricing_version, "pricing_version", 64) === 0n) throw new Error("invalid V9 chain/pricing version");
  for (const name of ["deployer", "stablecoin", "settlement", "treasury", "governance"]) nonzeroAddress(value[name], name);
  for (const name of ["channel_hash", "pricing_hash"]) if (normalizeBytes32(value[name], name) === `0x${"0".repeat(64)}`) throw new Error(`zero V9 ${name}`);
  for (const name of ["channel", "network_id", "channel_id", "backend_policy"]) if (typeof value[name] !== "string" || !value[name].trim()) throw new Error(`missing V9 ${name}`);
  const fields = ["dispute_window", "arbitration_timeout", "consumer_withdrawal_delay", "reporter_bond", "slash_bps", "slash_cap", "reporter_bounty_bps", "stable_bounty_cap", "token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty", "bond_penalty_recipient"];
  if (!value.policy || typeof value.policy !== "object" || Array.isArray(value.policy)
      || Object.keys(value.policy).length !== fields.length || fields.some((name) => value.policy[name] === undefined)) throw new Error("V9 complete dispute policy required");
  const policy = Object.fromEntries(fields.slice(0, -1).map((name) => [name, uint(value.policy[name], name)]));
  const penalty = nonzeroAddress(value.policy.bond_penalty_recipient, "bond_penalty_recipient");
  for (const name of fields.slice(0, 3)) if (policy[name] === 0n || policy[name] > 2592000n) throw new Error(`invalid V9 ${name}`);
  if (policy.reporter_bond === 0n || policy.slash_bps === 0n || policy.slash_bps > 10000n || policy.slash_cap === 0n
      || policy.reporter_bounty_bps === 0n || policy.reporter_bounty_bps >= 10000n || policy.stable_bounty_cap === 0n || policy.stable_bounty_cap > policy.slash_cap) throw new Error("invalid V9 slash/bounty policy");
  const reward = normalizeAddress(value.reward_token);
  if (reward === ZERO_ADDRESS) {
    if (["token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty"].some((name) => policy[name] !== 0n)) throw new Error("V9 disabled reward policy allocates tokens");
  } else if (reward === normalizeAddress(value.stablecoin) || policy.token_reward === 0n || policy.token_reward > policy.token_reward_cap
      || policy.token_minimum_exposure === 0n || policy.token_minimum_penalty === 0n || policy.token_minimum_penalty > policy.slash_cap) throw new Error("invalid V9 token reward policy");
  if (!Array.isArray(value.adjudicators) || value.adjudicators.length < 2 || value.adjudicators.length > 16) throw new Error("V9 explicit independent committee required");
  const judges = value.adjudicators.map((judge) => nonzeroAddress(judge, "adjudicator"));
  const threshold = uint(value.adjudication_threshold, "adjudication_threshold", 16);
  if (new Set(judges).size !== judges.length || threshold < 2n || threshold <= BigInt(Math.floor(judges.length / 2)) || threshold > BigInt(judges.length)) throw new Error("V9 invalid committee quorum");
  const authorities = [value.settlement, value.governance, value.treasury].map((item) => normalizeAddress(item)).concat(penalty);
  if (normalizeAddress(value.settlement) === penalty || normalizeAddress(value.settlement) === normalizeAddress(value.treasury) || judges.some((judge) => authorities.includes(judge))) throw new Error("V9 committee conflicts with settlement authorities");
  const operators = value.adjudicator_operators;
  const controlled = value.committee_mode === "controlled_test";
  if (controlled && !(allowControlledTest === true && [11155111,31337,1337].includes(value.chain_id) && value.network_id.endsWith("-controlled-test") && value.independence_attested === false && reward === ZERO_ADDRESS)) throw new Error("controlled test requires explicit --controlled-test opt-in, test chain and disabled rewards");
  if (value.committee_mode !== undefined && !["controlled_test", "independent_users"].includes(value.committee_mode)) throw new Error("unknown committee mode");
  if (!operators || typeof operators !== "object" || Array.isArray(operators) || (!controlled && value.independence_attested !== true)) throw new Error("V9 independent operator attestation required");
  const entries = Object.entries(operators).map(([judge, operator]) => [nonzeroAddress(judge, "adjudicator operator"), operator]);
  if (entries.length !== judges.length || new Set(entries.map(([judge]) => judge)).size !== judges.length
      || entries.some(([judge, operator]) => !judges.includes(judge) || typeof operator !== "string" || !operator.trim())
      || new Set(entries.map(([, operator]) => operator.trim().toLowerCase())).size !== (controlled ? 1 : judges.length)) throw new Error("V9 distinct operator identities required");
}

function defaultDataDir() {
  return join(homedir(), ".mycomesh", "consumer");
}

function resolveBaseUrl(value) {
  const base = String(value || DEFAULT_BASE_URL).replace(/\/+$/, "");
  return base.endsWith("/v1") ? base : `${base}/v1`;
}

function rootBaseUrl(baseUrl) {
  return baseUrl.replace(/\/v1\/?$/, "");
}

function parseRelayUrls(env, explicit) {
  const raw = explicit || env.MYCOMESH_V8_RELAY_URLS || env.MYCOMESH_CONSUMER_RELAY_URL || DEFAULT_RELAY_URL;
  const urls = String(raw).split(",").map((item) => item.trim().replace(/\/+$/, "")).filter(Boolean);
  if (!urls.length) throw new Error("at least one Relay URL is required");
  for (const url of urls) {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) throw new Error("Relay URLs must use HTTP or HTTPS");
  }
  return urls;
}

function resolveTlsCaFile(configured, manifestPath, { allowControlledTest = false } = {}) {
  if (configured === undefined || configured === null || configured === "") return null;
  if (!allowControlledTest) {
    throw new Error("custom Relay TLS CA is only allowed for an explicit controlled test (--controlled-test)");
  }
  if (typeof configured !== "string" || configured.length > 1024 || configured.includes("\0")) {
    throw new Error("tls_ca_file must be a valid path");
  }
  const resolved = configured.startsWith("/") ? configured : join(dirname(manifestPath), configured);
  if (!existsSync(resolved)) throw new Error("configured Relay TLS CA file is missing");
  let certificate;
  try { certificate = readFileSync(resolved); } catch { throw new Error("configured Relay TLS CA file is unreadable"); }
  if (!certificate.toString("ascii").includes("BEGIN CERTIFICATE")) {
    throw new Error("configured Relay TLS CA file does not contain a PEM certificate");
  }
  return resolved;
}

function sameSecret(first, second) {
  const a = Buffer.from(String(first || ""));
  const b = Buffer.from(String(second || ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

export class NativeConsumerState {
  constructor(options = {}) {
    const env = options.env || process.env;
    this.dataDir = options.dataDir || env.MYCOMESH_CONSUMER_DATA_DIR || defaultDataDir();
    mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDir, 0o700); } catch {}
    this.baseUrl = resolveBaseUrl(options.baseUrl || env.MYCOMESH_CONSUMER_PUBLIC_BASE_URL || DEFAULT_BASE_URL);
    this.maxFeeUnits = options.maxFeeUnits || Number(env.MYCOMESH_V8_MAX_FEE_UNITS || DEFAULT_MAX_FEE_UNITS);
    if (!Number.isSafeInteger(this.maxFeeUnits) || this.maxFeeUnits <= 0) throw new Error("max fee must be a positive integer");
    this.timeoutMs = options.timeoutMs ?? Number(env.MYCOMESH_V8_REQUEST_TIMEOUT_SECONDS || 300) * 1000;
    this.healthTimeoutMs = options.healthTimeoutMs ?? Number(env.MYCOMESH_V8_HEALTH_TIMEOUT_SECONDS || 10) * 1000;
    this.network = parseNetworkConfig(options.networkConfig || env.MYCOMESH_CONSUMER_NETWORK_CONFIG, { allowControlledTest: options.allowControlledTest === true });
    this.relayUrls = parseRelayUrls(env, options.relayUrls || env.MYCOMESH_V8_RELAY_URLS
      || env.MYCOMESH_CONSUMER_RELAY_URL || this.network.relay_urls?.join(","));
    this.staticRelayUrls = [...this.relayUrls];
    if (env.MYCOMESH_CONSUMER_SETTLEMENT_RPC_URLS) {
      this.network.rpc_urls = String(env.MYCOMESH_CONSUMER_SETTLEMENT_RPC_URLS).split(",").map((item) => item.trim()).filter(Boolean);
    }
    // A controlled IP testnet may use a private CA. The manifest path is
    // already trusted and resolves relative CA paths; an explicit env/option
    // is supported for generated manifests whose CA is staged separately.
    const caFile = options.caFile || env.MYCOMESH_CONSUMER_CA_FILE || this.network.tls_ca_file;
    if (caFile && options.allowControlledTest !== true) {
      throw new Error("custom Relay TLS CA is only allowed for an explicit controlled test (--controlled-test)");
    }
    this.tlsCaFile = caFile ? (String(caFile).startsWith("/") ? String(caFile) : caFile) : null;
    this.tlsCa = null;
    this.tlsCaBundle = rootCertificates;
    if (this.tlsCaFile) {
      if (!existsSync(this.tlsCaFile)) throw new Error("configured Relay TLS CA file is missing");
      try { this.tlsCa = readFileSync(this.tlsCaFile); } catch { throw new Error("configured Relay TLS CA file is unreadable"); }
      if (!this.tlsCa.toString("ascii").includes("BEGIN CERTIFICATE")) throw new Error("configured Relay TLS CA file does not contain a PEM certificate");
      // `ca` replaces (rather than augments) Node's defaults. Preserve public
      // trust roots so a manifest may safely mix private test Relays and
      // publicly certified fallback Relays.
      this.tlsCaBundle = [...rootCertificates, this.tlsCa.toString("utf8")];
    }
    this.proxy = options.proxy || env.MYCOMESH_CONSUMER_PROXY || "";
    // Public testnet routes can need more than Undici's 10-second handshake
    // default. Each operation still has its own, often shorter, total deadline.
    this.dispatcher = this.proxy
      ? new ProxyAgent({ uri: this.proxy, proxyTls: { timeout: 30000 }, requestTls: { timeout: 30000, ...(this.tlsCa ? { ca: this.tlsCaBundle } : {}) } })
      : new Agent({ connect: { timeout: 30000, ...(this.tlsCa ? { ca: this.tlsCaBundle } : {}) } });
    this.relayDiscovery = this.network.relay_discovery ? new ConsumerRelayDiscovery({
      config: this.network.relay_discovery, cachePath: join(this.dataDir, "relay-discovery-cache.json"), dispatcher: this.dispatcher,
    }) : null;
    this.syncDiscoveredRelays();
    this.healthCache = new Map();
    this.healthRequests = new Map();
    // `/ready` is an advisory probe used by local tooling and dashboards. A
    // short cache prevents every browser refresh from repeating the full
    // chain-backed capacity snapshot while inference still performs its own
    // fresh capacity check before dispatch.
    this.readinessCache = null;
    this.readinessRequest = null;
    this.preferredRpcUrl = null;
    this.capacityChannelsRequest = null;
    this.relayFailures = new Map();
    this.sessions = new ConsumerSessions();
    this.sessionRoutes = new Map();
    this.sessionSelections = new Map();
    this.relayInFlight = new Map();
    this.relayReservations = new Map();
    this.relaySelectionCursor = 0;
    this.activeInferenceRequests = 0;
    this.historyPath = join(this.dataDir, "receipt-history.jsonl");
    this.pendingKeyPath = join(this.dataDir, "pending-payment-key");
    this.paymentKeyFromEnv = Boolean(String(env.MYCOMESH_V8_PAYMENT_KEY || "").trim());
    this.paymentKey = this.loadPaymentKey(env.MYCOMESH_V8_PAYMENT_KEY);
    this.paymentAddress = paymentKeyAddress(this.paymentKey);
    this.historyDir = options.historyDir || env.MYCOMESH_CONSUMER_HISTORY_DIR;
    this.historyLedger = new ConsumerHistoryLedger({
      localPath: this.historyPath,
      sharedDir: this.historyDir,
      chainId: this.network.chain_id,
      contract: this.network.settlement_contract,
      keyAddress: this.paymentAddress,
    });
    this.historySync = null;
    this.historySyncAt = 0;
    this.historySyncError = null;
    this.tunnelCommand = options.tunnelCommand || env.MYCOMESH_CONSUMER_TUNNEL_COMMAND || "cloudflared";
    this.tunnelSpawn = options.tunnelSpawn || defaultSpawn;
    this.share = null;
    this.walletChallenge = null;
    this.managementToken = null;
    this.unlockedWallet = null;
    this.paymentUnlocked = false;
  }

  loadPaymentKey(configured) {
    const value = String(configured || "").trim();
    const path = join(this.dataDir, "payment-key");
    if (value) {
      paymentPrivateKey(value);
      return value;
    }
    if (existsSync(path)) {
      const stored = readFileSync(path, "utf8").trim();
      paymentPrivateKey(stored);
      return stored;
    }
    const generated = generatePaymentKey();
    writeFileSync(path, `${generated}\n`, { mode: 0o600, flag: "wx" });
    try { chmodSync(path, 0o600); } catch {}
    return generated;
  }

  credentialsText() {
    return `export OPENAI_BASE_URL=${shellQuote(this.baseUrl)}\nexport OPENAI_API_KEY=${shellQuote(this.paymentKey)}`;
  }

  capabilities(health) {
    const version = protocolVersion(this.network.protocol_version);
    const capabilities = health?.[`v${version}`];
    if (!capabilities || typeof capabilities !== "object") throw new Error(`Relay has no Settlement V${version} capabilities`);
    return capabilities;
  }

  healthPayload() {
    this.syncDiscoveredRelays();
    return {
      ok: true,
      protocol: `mycomesh-consumer/v${this.network.protocol_version}`,
      runtime: "node-native",
      docker: false,
      browser_app_ready: true,
      gateway_dependency: false,
      routing_mode: `relay-scheduled-payment-key-v${this.network.protocol_version}`,
      relay_urls: this.relayUrls,
      relay_discovery: this.relayDiscovery ? { enabled: true, active: this.relayDiscovery.active().length,
        error: this.relayDiscovery.lastError } : { enabled: false },
      payment_key_address: this.paymentAddress,
      payment_key_persisted: !this.paymentKeyFromEnv,
      wallet_unlocked: this.paymentUnlocked,
      // This reports trust configuration only; server-certificate verification
      // is completed on each HTTPS request and is never claimed in advance.
      relay_tls: { mode: this.tlsCa ? "controlled_test_ca" : "system_trust_store", configured: Boolean(this.tlsCa) },
      responses_transports: ["http", "sse"],
    };
  }

  walletAuthPayload() {
    return {
      authenticated: Boolean(this.managementToken && this.unlockedWallet),
      wallet: this.unlockedWallet,
      key_ready: this.paymentUnlocked,
    };
  }

  createWalletChallenge(walletValue) {
    const wallet = normalizeAddress(walletValue, "wallet");
    const issuedAt = Date.now();
    const expiresAt = issuedAt + WALLET_CHALLENGE_TTL_MS;
    const nonce = randomBytes(24).toString("base64url");
    const message = [
      "MycoMesh Consumer wallet login",
      `Wallet: ${wallet}`,
      `Payment key: ${this.paymentAddress}`,
      `Nonce: ${nonce}`,
      `Issued at: ${new Date(issuedAt).toISOString()}`,
      "This signature unlocks this local Consumer process only.",
    ].join("\n");
    this.walletChallenge = { wallet, message, expiresAt };
    return { wallet, key_address: this.paymentAddress, message, expires_at: Math.floor(expiresAt / 1000) };
  }

  async authenticateWallet(raw) {
    const wallet = normalizeAddress(raw?.wallet, "wallet");
    const challenge = this.walletChallenge;
    if (!challenge || challenge.wallet !== wallet || challenge.expiresAt < Date.now()) {
      this.walletChallenge = null;
      throw new Error("wallet login challenge is missing or expired");
    }
    this.walletChallenge = null;
    const recovered = recoverAddress(walletMessageDigest(challenge.message), raw?.signature);
    if (recovered !== wallet) throw new Error("wallet signature does not match the selected account");
    let grant;
    try { grant = await this.keyGrant(this.paymentAddress); }
    catch {
      throw Object.assign(new Error("Cannot verify payment-key ownership on-chain. Please retry when the connection recovers."), {
        code: "wallet_verification_unavailable", selected_wallet: wallet, payment_key_address: this.paymentAddress,
      });
    }
    if (grant.owner !== ZERO_ADDRESS && grant.owner !== wallet) {
      throw Object.assign(new Error(`This local payment key belongs to a different wallet. Select ${grant.owner} in your wallet extension, or use a separate Consumer data directory for ${wallet}. Keep the existing key and billing history.`), {
        code: "payment_key_owner_mismatch", selected_wallet: wallet, expected_owner: grant.owner, payment_key_address: this.paymentAddress,
      });
    }
    let paymentUnlocked = grant.active && grant.owner === wallet;
    if (this.network.protocol_version === 10 && !paymentUnlocked) {
      // Revocation prevents new channels; existing owner-approved snapshots
      // keep their bounded authorization until their original expiry.
      try {
        paymentUnlocked = (await this.capacityChannels()).some(c => !c.closed && c.consumer_owner === wallet
          && c.consumer_key === this.paymentAddress && Number(c.admit_until) >= Math.floor(Date.now()/1000));
      } catch {
        throw Object.assign(new Error("Cannot verify existing payment channels on-chain. Please retry when the connection recovers."), {
          code: "wallet_verification_unavailable", selected_wallet: wallet, payment_key_address: this.paymentAddress,
        });
      }
    }
    // Commit the session only after every chain check succeeds. A failed login
    // must neither create a partial session nor replace an existing owner session.
    this.unlockedWallet = wallet;
    this.managementToken = `myco_local_${randomBytes(32).toString("base64url")}`;
    this.paymentUnlocked = paymentUnlocked;
    return { ok: true, token: this.managementToken, auth: this.walletAuthPayload(), grant };
  }

  authorizeManagement(authorization) {
    return Boolean(this.managementToken && sameSecret(authorization, `Bearer ${this.managementToken}`));
  }

  assertUnlockedWallet(walletValue = this.unlockedWallet) {
    const wallet = normalizeAddress(walletValue, "wallet");
    if (!this.managementToken || wallet !== this.unlockedWallet) {
      throw new Error("sign in with the payment-key owner wallet first");
    }
    return wallet;
  }

  async activateCurrentPaymentKey() {
    const wallet = this.assertUnlockedWallet();
    const grant = await this.keyGrant(this.paymentAddress);
    if (!grant.active || grant.owner !== wallet) {
      throw new Error("the payment key is not active for this wallet on-chain");
    }
    this.paymentUnlocked = true;
    return { ok: true, auth: this.walletAuthPayload(), grant };
  }

  async lockWallet() {
    this.walletChallenge = null;
    this.managementToken = null;
    this.unlockedWallet = null;
    this.paymentUnlocked = false;
    await this.stopShare();
    return { ok: true, auth: this.walletAuthPayload() };
  }

  history(limit = 100) {
    return this.historyLedger.history(limit);
  }

  recordDispatch(relayUrl, endpoint, payment, sessionId, status = "dispatching") {
    const auth = payment.payment.authorization;
    this.historyLedger.append({
      timestamp: Math.floor(Date.now() / 1000), updated_at: Math.floor(Date.now() / 1000),
      request_id: auth.request_id, request_hash: auth.request_hash,
      key_address: this.paymentAddress, owner: this.unlockedWallet || undefined,
      chain_id: this.network.chain_id, settlement_contract: this.network.settlement_contract,
      relay_url: relayUrl, relay: payment.channel?.relay || auth.relay, capacity_channel_id: auth.channel_id, endpoint, model: payment.model,
      route_model: payment.model, session_id: sessionId, source: "local-dispatch",
      max_fee_units: Number(auth.max_fee), authorization_deadline: Number(auth.deadline),
      accepted: false, status,
    });
  }

  recordReceipt(relayUrl, endpoint, model, settlement, routeModel = model, sessionId = null, contentVerification = "receipt-only") {
    const signed = settlement?.signed_receipt;
    const receipt = signed?.receipt;
    const auth = signed?.authorization?.authorization;
    if (!receipt || !auth) return;
    const entry = {
      timestamp: Math.floor(Date.now() / 1000),
      request_id: String(auth.request_id || ""),
      request_hash: auth.request_hash, capacity_channel_id: auth.channel_id, max_fee_units: Number(auth.max_fee),
      settlement_key: String(settlement.settlement_key || ""),
      // The unsigned Relay envelope cannot assert escrow, payout or refund.
      status: ["queued", "pending", "submitted", "broadcast_unknown", "failed", "rejected"].includes(settlement.status) ? settlement.status : "pending",
      accepted: Boolean(settlement.accepted),
      endpoint,
      model,
      route_model: routeModel,
      relay_url: relayUrl,
      provider: String(receipt.provider || ""),
      provider_signer: String(receipt.provider_signer || ""),
      response_hash: String(receipt.response_hash || ""),
      content_verification: contentVerification,
      owner: String(this.unlockedWallet || ""),
      key_address: this.paymentAddress,
      chain_id: this.network.chain_id,
      settlement_contract: this.network.settlement_contract,
      source: "local-receipt",
      session_id: sessionId,
      input_tokens: Number(receipt.input_tokens || 0),
      output_tokens: Number(receipt.output_tokens || 0),
      actual_fee_units: Number(receipt.actual_fee || 0),
      authorization_deadline: Number(auth.deadline || 0),
    };
    this.historyLedger.append(entry);
  }

  async rpcValue(callback) {
    const errors = [];
    let candidates = [...new Set(this.network.rpc_urls)];
    if (candidates.includes(this.preferredRpcUrl)) {
      candidates = [this.preferredRpcUrl, ...candidates.filter((url) => url !== this.preferredRpcUrl)];
    }
    // Each callback is a complete read against one endpoint. Restart the whole
    // verification on failover; retry transient read failures at most once.
    for (let attempt = 0; attempt < 2 && candidates.length; attempt += 1) {
      const retry = [];
      for (const rpcUrl of candidates) {
        try {
          const value = await callback(rpcUrl);
          this.preferredRpcUrl = rpcUrl;
          return value;
        } catch (error) {
          errors.push(error.message);
          if (error.rpcRetryable === true) retry.push(rpcUrl);
        }
      }
      candidates = retry;
    }
    const error = new Error(`all configured Settlement V${this.network.protocol_version} RPC endpoints failed: ${errors.join("; ")}`);
    error.code = "rpc_unavailable";
    error.statusCode = 503;
    throw error;
  }

  async callRpc(rpcUrl, method, params) {
    try {
      const response = await fetchWithTimeout(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        dispatcher: this.dispatcher,
      }, this.healthTimeoutMs);
      const payload = await readJsonResponse(response);
      if (!response.ok || payload.error) {
        const error = new Error(payload.error?.message || `RPC ${response.status}`);
        error.rpcRetryable = [408, 429, 500, 502, 503, 504].includes(response.status)
          || [-32002, -32005].includes(payload.error?.code);
        throw error;
      }
      return payload.result;
    } catch (error) {
      if (error.name === "TimeoutError" || error.name === "AbortError"
          || (error instanceof TypeError && ["fetch failed", "terminated"].includes(error.message))) {
        error.rpcRetryable = true;
      }
      throw error;
    }
  }

  async contractCall(rpcUrl, contract, signature, args, blockTag = "latest") {
    const data = `0x${bytesToHex(keccak_256(Buffer.from(signature, "ascii")).slice(0, 4))}${args.map((arg) => abiWord(arg).toString("hex")).join("")}`;
    return this.callRpc(rpcUrl, "eth_call", [{ to: normalizeAddress(contract), data }, blockTag]);
  }

  async keyGrant(address) {
    const output = await this.rpcValue((rpc) => this.contractCall(rpc, this.network.settlement_contract, "keyGrants(address)", [normalizeAddress(address)]));
    const words = String(output || "").replace(/^0x/, "").match(/.{64}/g) || [];
    if (words.length < 4) throw new Error("invalid key grant response");
    return {
      owner: `0x${words[0].slice(-40)}`,
      max_per_request: Number(BigInt(`0x${words[1]}`)),
      valid_until: Number(BigInt(`0x${words[2]}`)),
      active: BigInt(`0x${words[3]}`) !== 0n,
    };
  }

  async accountBalance(owner) {
    const output = await this.rpcValue((rpc) => this.contractCall(rpc, this.network.settlement_contract, "availableBalance(address)", [normalizeAddress(owner)]));
    return BigInt(output || "0x0").toString();
  }

  // These two reads are independent. Keep them in one helper so the local
  // dashboard can fetch the wallet snapshot in one RPC round instead of
  // serialising the token balance behind the allowance read. Both calls are
  // read-only and still use rpcValue's endpoint failover independently.
  async walletSnapshot(owner) {
    const [token, allowance] = await Promise.all([
      this.rpcValue((rpc) => this.contractCall(rpc, this.network.stablecoin, "balanceOf(address)", [normalizeAddress(owner)])),
      this.rpcValue((rpc) => this.contractCall(rpc, this.network.stablecoin, "allowance(address,address)", [normalizeAddress(owner), this.network.settlement_contract])),
    ]);
    return {
      address: owner,
      token_balance_units: BigInt(token || "0x0").toString(),
      allowance_units: BigInt(allowance || "0x0").toString(),
    };
  }

  async dashboardPayload(managementAuthorized = false) {
    const authenticated = managementAuthorized && Boolean(this.unlockedWallet);
    if (authenticated) void this.refreshReceiptStatuses().catch(() => { this.historySyncError = "暂时无法同步账单状态"; });
    const allHistory = this.history(0);
    const unknownFees = authenticated ? allHistory.filter((item) => item.actual_fee_units == null
      && !["not_dispatched", "failed", "rejected"].includes(item.status)) : [];
    const pending = authenticated ? this.pendingPaymentKey() : null;
    const payload = {
      ok: true,
      protocol_version: this.network.protocol_version,
      runtime: "node-native",
      auth: authenticated ? this.walletAuthPayload() : { authenticated: false, wallet: null, key_ready: false },
      credentials: authenticated && this.paymentUnlocked
        ? { base_url: this.baseUrl, api_key: this.paymentKey, export: this.credentialsText() }
        : null,
      key: {
        address: this.paymentAddress,
        max_fee_units: this.maxFeeUnits,
        pending: pending ? { payment_key_address: pending.payment_key_address } : null,
      },
      settlement: this.network,
      history: authenticated ? allHistory.slice(0, 100) : [],
      history_scope: "current-payment-key-on-this-device",
      history_sync: authenticated ? { running: Boolean(this.historySync), last_checked_at: this.historySyncAt, error: this.historySyncError } : null,
      usage: {
        request_count: authenticated ? allHistory.length : 0,
        total_spent_units: authenticated ? allHistory.reduce((total, item) => total + Number(item.actual_fee_units || 0), 0) : 0,
        settled_units: authenticated ? allHistory.filter((item) => ["confirmed", "released", "dismissed", "timed_out"].includes(item.status)).reduce((sum, item) => sum + Number(item.actual_fee_units || 0), 0) : 0,
        pending_units: authenticated ? allHistory.filter((item) => !["confirmed", "released", "refunded", "dismissed", "timed_out", "failed", "rejected"].includes(item.status)).reduce((sum, item) => sum + Number(item.actual_fee_units || 0), 0) : 0,
        unknown_fee_count: unknownFees.length,
        unknown_fee_authorized_maximum_units: unknownFees.reduce((sum, item) => sum + Number(item.max_fee_units || 0), 0),
        refunded_units: authenticated ? allHistory.filter((item) => item.status === "refunded").reduce((sum, item) => sum + Number(item.actual_fee_units || 0), 0) : 0,
        failed_units: authenticated ? allHistory.filter((item) => ["failed", "rejected"].includes(item.status)).reduce((sum, item) => sum + Number(item.actual_fee_units || 0), 0) : 0,
        input_tokens: authenticated ? allHistory.reduce((total, item) => total + Number(item.input_tokens || 0), 0) : 0,
        output_tokens: authenticated ? allHistory.reduce((total, item) => total + Number(item.output_tokens || 0), 0) : 0,
      },
      share: authenticated ? this.sharePayload() : { active: false },
    };
    try {
      // Key ownership and fixed-budget channel state are independent reads.
      // Start them together so the dashboard does not make the user wait for
      // two full RPC snapshots in sequence.
      const [grant, channelSnapshot] = await Promise.all([
        this.keyGrant(this.paymentAddress),
        authenticated && this.network.protocol_version === 10 ? this.capacityChannels() : Promise.resolve(null),
      ]);
      payload.key.grant = grant;
      if (authenticated && this.network.protocol_version === 10 && channelSnapshot) {
        const now = Math.floor(Date.now()/1000);
        payload.capacity_channels = channelSnapshot.filter(c => c.consumer_owner === this.unlockedWallet)
          .map(c => ({ ...c, budget: this.capacityBudget(c, allHistory, now) }));
        payload.budget_locked_units = payload.capacity_channels.filter(c=>!c.closed).reduce((n,c)=>n+BigInt(c.credit_remaining),0n).toString();
        payload.budget_available_units = payload.capacity_channels.filter(c => c.budget.ready)
          .reduce((total,c) => total+BigInt(c.budget.remaining_units),0n).toString();
        payload.budget_note = "固定预算在结算窗口结束前不会撤回；每次请求只占用授权上限。结算按 2 小时或 100 笔先到触发。撤销 Key 只会停止新请求，不会改变已有账单。";
      }
      if (authenticated && (grant.owner === this.unlockedWallet
          || (this.network.protocol_version === 10 && grant.owner === ZERO_ADDRESS))) {
        payload.account = { owner: this.unlockedWallet, available_balance_units: await this.accountBalance(this.unlockedWallet) };
      }
    } catch (error) {
      payload.chain_error = error.message;
    }
    if (authenticated) {
      try {
        const address = this.unlockedWallet;
        payload.wallet = await this.walletSnapshot(address);
      } catch (error) {
        payload.wallet_error = error.message;
      }
      try {
        // The budget panel has already taken a canonical channel snapshot.
        // Reusing its readiness result avoids a second chain snapshot during
        // every dashboard refresh; inference itself still performs a fresh
        // capacity check before dispatch.
        const channels = payload.capacity_channels || [];
        if (this.network.protocol_version === 10 && channels.length) {
          const ready = channels.filter((channel) => channel.budget?.ready);
          if (!ready.length) {
            const availableAt = channels.map((channel) => channel.budget?.available_at).filter(Number.isFinite).sort((a, b) => a - b)[0];
            const error = new Error(availableAt
              ? `Fixed budget becomes available at ${new Date(availableAt * 1000).toISOString()}`
              : "No active funded channel covers this model and Provider; renew the fixed budget");
            error.code = availableAt ? "budget_not_started" : "budget_unavailable";
            if (availableAt) error.availableAt = availableAt;
            throw error;
          }
          const route = await this.chooseRelay(new Set(), { checkCapacity: false });
          payload.inference_ready = Boolean(route);
        } else {
          const route = await this.chooseRelay();
          payload.inference_ready = Boolean(route);
        }
      } catch (error) {
        payload.inference_ready = false;
        payload.inference_error = error.message;
        payload.inference_code = error.code || null;
        if (error.availableAt) payload.budget_available_at = error.availableAt;
      }
    }
    return payload;
  }

  async queryReceiptStatus(entry, privateKey = this.paymentKey) {
    if (!this.relayUrls.includes(entry.relay_url)) return null;
    const query = createReceiptStatusQuery(privateKey, { chainId: this.network.chain_id,
      contract: this.network.settlement_contract, requestId: entry.request_id, channelId: entry.capacity_channel_id });
    const response = await fetchWithTimeout(`${entry.relay_url}/v1/mycomesh/receipts/status`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(query), dispatcher: this.dispatcher,
    }, 5000);
    const value = await readJsonResponse(response);
    if (response.status === 404) return null; // Old Relay or an unknown receipt; never assume settled/failed.
    if (!response.ok || value.request_id !== entry.request_id || (entry.capacity_channel_id && value.channel_id !== entry.capacity_channel_id)) throw new Error("invalid Relay receipt status response");
    if (!["pending", "submitted", "broadcast_unknown", "confirmed", "escrowed", "failed"].includes(value.status)) throw new Error("invalid receipt state");
    return value;
  }

  async refreshReceiptStatuses(force = false) {
    if (!this.unlockedWallet || !this.managementToken) return;
    if (this.historySync) return this.historySync;
    if (!force && Date.now() - this.historySyncAt < 30_000) return;
    this.historySyncAt = Date.now();
    const owner = this.unlockedWallet, key = this.paymentAddress, privateKey = this.paymentKey, ledger = this.historyLedger;
    const candidates = ledger.history(0).filter((entry) => (entry.accepted || ["dispatching", "outcome_unknown"].includes(entry.status)) && !["confirmed", "released", "refunded", "dismissed", "timed_out"].includes(entry.status)
      && /^0x[0-9a-f]{64}$/i.test(entry.request_id));
    const live = candidates.filter((entry) => !["failed", "rejected"].includes(entry.status));
    const terminal = candidates.filter((entry) => ["failed", "rejected"].includes(entry.status));
    this.historySyncCursors ||= { live: 0, terminal: 0 };
    const take = (rows, count, group) => {
      if (!rows.length) return [];
      const start = this.historySyncCursors[group] % rows.length;
      const selected = Array.from({ length: Math.min(count, rows.length) }, (_, index) => rows[(start + index) % rows.length]);
      this.historySyncCursors[group] = (start + selected.length) % rows.length;
      return selected;
    };
    // Reserve a small share for rechecking failed records while rotating all
    // live work. Old pending receipts cannot be hidden by recent failures.
    const pending = take(live, terminal.length ? 16 : 20, "live");
    pending.push(...take(terminal, 20 - pending.length, "terminal"));
    this.historySyncError = null;
    const check = async () => {
      while (pending.length) {
        const entry = pending.shift();
        try {
          const settlementKey = this.network.protocol_version === 10 ? reservedSettlementKey(entry.capacity_channel_id, entry.request_id) : keccakHex(Buffer.concat([abiWord(owner), abiWord(key), abiWord(entry.request_id)]));
          if (this.network.protocol_version >= 9) {
            const result = await this.rpcValue(async (rpc) => {
              const block = await this.callRpc(rpc, "eth_getBlockByNumber", ["safe", false]);
              if (!block || !/^0x[0-9a-f]{64}$/i.test(block.hash) || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(block.number)) throw new Error("safe V9 block unavailable");
              return this.contractCall(rpc, this.network.settlement_contract, "settlementInfo(bytes32)", [settlementKey],
                { blockHash: block.hash, requireCanonical: true });
            });
            if (typeof result !== "string" || !/^0x[0-9a-f]{1280}$/i.test(result)) throw new Error("invalid V9 settlement record");
            const words = result.slice(2).match(/.{64}/g);
            if (words.slice(0, 8).some((word) => !/^0{24}/.test(word)) || BigInt(`0x${words[19]}`) > 6n
                || BigInt(`0x${words[17]}`) >= (1n << 64n) || BigInt(`0x${words[18]}`) >= (1n << 64n)) throw new Error("noncanonical V9 settlement record");
            const status = [null, "escrowed", "disputed", "released", "refunded", "dismissed", "timed_out"][Number(BigInt(`0x${words[19]}`))];
            if (status) {
              if (`0x${words[0].slice(-40)}` !== owner.toLowerCase() || `0x${words[1].slice(-40)}` !== key.toLowerCase() || `0x${words[8]}` !== entry.request_id.toLowerCase()
                  || (entry.request_hash && `0x${words[9]}` !== entry.request_hash.toLowerCase())
                  || (entry.actual_fee_units != null && BigInt(`0x${words[12]}`) !== BigInt(entry.actual_fee_units))
                  || (entry.provider && `0x${words[2].slice(-40)}` !== entry.provider.toLowerCase())
                  || (entry.provider_signer && `0x${words[3].slice(-40)}` !== entry.provider_signer.toLowerCase())
                  || (entry.response_hash && `0x${words[11]}` !== entry.response_hash.toLowerCase())) throw new Error("V9 escrow scope mismatch");
              if (entry.status !== status) ledger.append({ ...entry, owner, status, accepted: true, actual_fee_units: jsonInteger(BigInt(`0x${words[12]}`)), updated_at: Math.floor(Date.now() / 1000) });
              continue;
            }
            // No safe-block escrow: a Relay cannot declare escrow or release.
            const remote = await this.queryReceiptStatus(entry, privateKey);
            if (remote && ["pending", "submitted", "broadcast_unknown", "failed"].includes(remote.status) && remote.status !== entry.status) ledger.append({ ...entry, accepted: true, status: remote.status, updated_at: Math.floor(Date.now() / 1000) });
            continue;
          }
          const result = await this.rpcValue((rpc) => this.contractCall(rpc, this.network.settlement_contract,
            "settled(bytes32)", [settlementKey]));
          if (BigInt(result || "0x0") === 1n) {
            ledger.append({ ...entry, owner, status: "confirmed", confirmed_at: Math.floor(Date.now() / 1000) });
          } else {
            const remote = await this.queryReceiptStatus(entry, privateKey);
            if (remote && remote.status !== "confirmed") {
              // A Relay cannot claim a final on-chain success without the RPC
              // check above. Its scoped authenticated status can report failure.
              const update = { status: remote.status, error_code: remote.error_code ?? (entry.error_code ? "" : undefined),
                tx_hash: remote.tx_hash, authorization_deadline: remote.authorization_deadline || entry.authorization_deadline };
              if (Object.entries(update).some(([field, value]) => value != null && value !== entry[field])) {
                ledger.append({ ...entry, ...update, accepted: true, updated_at: Math.floor(Date.now() / 1000) });
              }
            }
          }
        } catch {
          this.historySyncError = "暂时无法同步链上结算状态，已保留本地账单";
          pending.length = 0;
        }
      }
    };
    this.historySync = Promise.all([check(), check(), check()]);
    try { await this.historySync; } finally { this.historySync = null; }
  }

  sharePayload() {
    const share = this.activeShare();
    return share ? {
      active: true,
      base_url: share.baseUrl,
      api_key: share.apiKey,
      expires_at: share.expiresAt,
    } : { active: false };
  }

  activeShare() {
    if (this.share && this.share.expiresAt <= Math.floor(Date.now() / 1000)) {
      void this.stopShare();
      return null;
    }
    return this.share;
  }

  authorizeBearer(authorization, { shareOnly = false } = {}) {
    if (!shareOnly && this.paymentUnlocked && sameSecret(authorization, `Bearer ${this.paymentKey}`)) return true;
    const share = this.activeShare();
    return Boolean(share && sameSecret(authorization, `Bearer ${share.apiKey}`));
  }

  async startShare(minutesValue) {
    if (!this.paymentUnlocked) throw new Error("sign in and activate the payment key before sharing");
    const minutes = Number(minutesValue);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > MAX_SHARE_MINUTES) {
      throw new Error(`share duration must be between 1 and ${MAX_SHARE_MINUTES} minutes`);
    }
    await this.stopShare();
    const runtime = createConsumerServer(this, { host: "127.0.0.1", port: 0, publicOnly: true });
    const address = await runtime.listen();
    const apiKey = `myco_share_${randomBytes(24).toString("base64url")}`;
    const share = {
      apiKey,
      baseUrl: "",
      expiresAt: Math.floor(Date.now() / 1000) + minutes * 60,
      process: null,
      runtime,
      timer: null,
    };
    this.share = share;
    try {
      let publicUrl;
      let lastError;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const child = this.tunnelSpawn(
          this.tunnelCommand,
          ["tunnel", "--no-autoupdate", "--protocol", "http2", "--url", `http://127.0.0.1:${address.port}`],
          { stdio: ["ignore", "pipe", "pipe"] },
        );
        share.process = child;
        try {
          publicUrl = await waitForTunnelUrl(child);
          break;
        } catch (error) {
          lastError = error;
          await stopTunnelProcess(child);
          if (share.process === child) share.process = null;
          if (this.share !== share || attempt === 1) throw error;
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }
      if (!publicUrl) throw lastError || new Error("cloudflared did not publish a URL");
      if (this.share !== share) throw new Error("temporary share was cancelled");
      share.baseUrl = `${publicUrl.replace(/\/+$/, "")}/v1`;
      share.timer = setTimeout(() => { void this.stopShare(); }, minutes * 60 * 1000);
      share.timer.unref?.();
      share.process?.once("exit", () => { if (this.share === share) void this.stopShare(); });
      return this.sharePayload();
    } catch (error) {
      await this.stopShare();
      throw error;
    }
  }

  async stopShare() {
    const share = this.share;
    this.share = null;
    if (!share) return { active: false };
    if (share.timer) clearTimeout(share.timer);
    await stopTunnelProcess(share.process);
    await share.runtime?.close();
    return { active: false };
  }

  pendingPaymentKey() {
    if (!existsSync(this.pendingKeyPath)) return null;
    const value = readFileSync(this.pendingKeyPath, "utf8").trim();
    paymentPrivateKey(value);
    return { payment_key: value, payment_key_address: paymentKeyAddress(value) };
  }

  preparePaymentKey() {
    if (this.paymentKeyFromEnv) throw new Error("payment-key rotation is disabled while MYCOMESH_V8_PAYMENT_KEY is set");
    const pending = this.pendingPaymentKey();
    if (pending) return pending;
    const value = generatePaymentKey();
    writeFileSync(this.pendingKeyPath, `${value}\n`, { mode: 0o600, flag: "wx" });
    return { payment_key: value, payment_key_address: paymentKeyAddress(value) };
  }

  async activatePendingPaymentKey(wallet) {
    const owner = this.assertUnlockedWallet(wallet);
    const pending = this.pendingPaymentKey();
    if (!pending) throw new Error("no pending payment key exists");
    const grant = await this.keyGrant(pending.payment_key_address);
    if (!grant.active || grant.owner !== owner) throw new Error("the pending payment key is not active for this wallet on-chain");
    if (this.activeInferenceRequests > 0) {
      throw new Error("wait for active inference requests before rotating the payment key");
    }
    const previous = this.paymentAddress;
    const destination = join(this.dataDir, "payment-key");
    writeFileSync(destination, `${pending.payment_key}\n`, { mode: 0o600 });
    chmodSync(destination, 0o600);
    unlinkSync(this.pendingKeyPath);
    this.paymentKey = pending.payment_key;
    this.paymentAddress = pending.payment_key_address;
    this.sessions = new ConsumerSessions();
    this.sessionRoutes.clear();
    this.historyLedger = new ConsumerHistoryLedger({ localPath: this.historyPath, sharedDir: this.historyDir,
      chainId: this.network.chain_id, contract: this.network.settlement_contract, keyAddress: this.paymentAddress });
    this.historySyncAt = 0;
    this.paymentUnlocked = true;
    return { payment_key_address: this.paymentAddress, previous_key_address: previous };
  }

  async transactionPlan(raw) {
    const action = String(raw?.action || "");
    const wallet = this.assertUnlockedWallet(raw?.wallet);
    const settlement = this.network.settlement_contract;
    const token = this.network.stablecoin;
    if (action === "top_up") {
      const amount = parseUsdc(raw.amount_usdc);
      const allowance = BigInt(await this.rpcValue((rpc) => this.contractCall(rpc, token, "allowance(address,address)", [wallet, settlement])) || "0x0");
      const transactions = [];
      if (allowance < amount) transactions.push({ label: "Approve stablecoin", to: token, data: contractData("approve(address,uint256)", [settlement, amount]) });
      transactions.push({ label: "Deposit prepaid balance", to: settlement, data: contractData("deposit(uint256)", [amount]) });
      return { action, amount_units: amount.toString(), transactions };
    }
    if (action === "register_key") {
      const pending = this.pendingPaymentKey();
      const keyAddress = pending?.payment_key_address || this.paymentAddress;
      const grant = await this.keyGrant(keyAddress);
      if (grant.owner === wallet && grant.active === true
          && grant.max_per_request === this.maxFeeUnits && grant.valid_until === 0) {
        return { action, key_address: keyAddress, transactions: [] };
      }
      return { action, key_address: keyAddress, transactions: [{ label: "Register payment key", to: settlement, data: contractData("registerKey(address,uint256,uint64)", [keyAddress, this.maxFeeUnits, 0]) }] };
    }
    if (action === "revoke_key") {
      const keyAddress = normalizeAddress(raw.key_address, "key_address");
      return { action, key_address: keyAddress, transactions: [{ label: "Revoke previous payment key", to: settlement, data: contractData("revokeKey(address)", [keyAddress]) }] };
    }
    if (action === "close_capacity_channel" && this.network.protocol_version === 10) {
      const id = normalizeBytes32(raw.channel_id, "channel_id");
      const channel = (await this.capacityChannels()).find(c => c.channel_id === id && c.consumer_owner === wallet);
      if (!channel || channel.closed || Math.floor(Date.now()/1000) <= Number(channel.claim_until)) throw new Error("该预算尚未到可释放时间");
      return { action, channel_id: id, transactions: [{ label: "释放已到期的剩余预算", to: settlement, data: contractData("closeExpiredChannel(bytes32)", [id]) }] };
    }
    throw new Error("unsupported transaction action");
  }

  noteRelayFailure(relayUrl, retryAfter) {
    this.readinessCache = null;
    this.healthCache.delete(relayUrl);
    const count = Math.min(6, (this.relayFailures.get(relayUrl)?.count || 0) + 1);
    const seconds = Number(retryAfter);
    const cooldown = Math.max(Math.min(30_000, 1000 * 2 ** (count - 1)),
      Number.isFinite(seconds) && seconds > 0 ? Math.min(30_000, seconds * 1000) : 0);
    this.relayFailures.set(relayUrl, { count, until: Date.now() + cooldown });
  }

  async relayHealth(relayUrl, refresh = false) {
    const failed = this.relayFailures.get(relayUrl);
    if (failed && failed.until > Date.now()) throw new Error("Relay is cooling down after a failure");
    const running = this.healthRequests.get(relayUrl);
    if (running) return running;
    const pending = this.loadRelayHealth(relayUrl, refresh).catch((error) => {
      this.noteRelayFailure(relayUrl);
      throw error;
    });
    this.healthRequests.set(relayUrl, pending);
    try { return await pending; } finally { this.healthRequests.delete(relayUrl); }
  }

  async loadRelayHealth(relayUrl, refresh = false) {
    const cached = this.healthCache.get(relayUrl);
    const cacheAge = cached ? Date.now() - cached.at : Infinity;
    if (cached && !refresh && cacheAge < RELAY_HEALTH_CACHE_MS) {
      this.verifyRelayIdentity(relayUrl, cached.payload);
      return cached.payload;
    }
    const request = { dispatcher: this.dispatcher, headers: { accept: "application/json" } };
    if (this.relayDiscovery && !this.staticRelayUrls.includes(relayUrl)) await this.relayDiscovery.probe(relayUrl);
    let payload;
    let lastError;
    for (let attempt = 0; attempt < 2 && !payload; attempt += 1) {
      try {
        const response = await fetchWithTimeout(`${relayUrl}/relay/health`, request, this.healthTimeoutMs);
        payload = await readJsonResponse(response);
        if (!response.ok || payload?.ok !== true) throw new Error(`Relay health is invalid for ${relayUrl}`);
      } catch (error) {
        // Never fall back to an insecure transport when a private CA or host
        // certificate is wrong. Keep the route eligible for retry, but expose
        // an actionable error so operators can install the manifest CA or fix
        // the Relay certificate/SAN.
        const tlsCode = String(error?.code || error?.cause?.code || "");
        const tlsMessage = String(error?.message || error?.cause?.message || "");
        if (/CERT|TLS|SSL|UNABLE_TO_VERIFY|ERR_TLS/i.test(`${tlsCode} ${tlsMessage}`)) {
          lastError = Object.assign(new Error(`Relay TLS verification failed for ${relayUrl}; install the network manifest CA or use a publicly trusted certificate`), {
            code: "relay_tls_untrusted", cause: error,
          });
        } else {
          lastError = error;
        }
        payload = undefined;
        if (attempt === 0) await new Promise((resolve) => setTimeout(resolve, RELAY_HEALTH_RETRY_DELAY_MS));
      }
    }
    if (!payload) {
      throw lastError || new Error(`Relay health is unavailable for ${relayUrl}`);
    }
    const v8 = this.capabilities(payload);
    this.verifyRelayIdentity(relayUrl, payload);
    if (!v8 || v8.enabled !== true || Number(v8.providers || 0) <= 0) throw new Error(`Relay has no live Settlement V${this.network.protocol_version} Provider: ${relayUrl}`);
    if (payload.inference_ready === false || payload.settlement_ready === false || v8.inference_ready === false || v8.settlement_ready === false
        || payload.settlement_submitter?.ready === false || payload.settlement_submitter?.admission_ready === false) {
      throw new Error("Relay is not ready for paid inference or settlement");
    }
    this.healthCache.set(relayUrl, { at: Date.now(), payload });
    return payload;
  }

  verifyRelayIdentity(relayUrl, health) {
    const capabilities = this.capabilities(health);
    const announcement = this.relayDiscovery?.recordFor(relayUrl);
    if (this.relayDiscovery && !this.staticRelayUrls.includes(relayUrl) && !announcement) {
      throw new Error("Relay discovery announcement expired or unavailable");
    }
    const pins = [this.network.relay_pins?.[relayUrl], announcement].filter(Boolean);
    if (pins.length && (Number(capabilities.chain_id) !== this.network.chain_id
        || normalizeAddress(capabilities.settlement_contract) !== this.network.settlement_contract)) {
      throw new Error("Relay deployment does not match the pinned Consumer network");
    }
    for (const pin of pins) {
      if (normalizeAddress(capabilities.relay_payment_address) !== pin.payment_address
          || normalizeAddress(capabilities.relay_signer_address) !== pin.attestation_address) {
        throw new Error("Relay health identity differs from its pinned announcement");
      }
    }
  }

  syncDiscoveredRelays() {
    if (!this.relayDiscovery) return;
    this.relayUrls = [...new Set([...this.staticRelayUrls, ...this.relayDiscovery.active().map((record) => record.public_url)])];
    const current = new Set(this.relayUrls);
    for (const map of [this.healthCache, this.relayFailures]) {
      for (const url of map?.keys() || []) if (!current.has(url)) map.delete(url);
    }
    for (const map of [this.relayInFlight, this.relayReservations]) {
      for (const [url, count] of map?.entries() || []) if (!current.has(url) && !count) map.delete(url);
    }
  }

  async refreshRelayDiscovery() {
    if (!this.relayDiscovery) return;
    this.syncDiscoveredRelays();
    await this.relayDiscovery.refresh();
    this.syncDiscoveredRelays();
  }

  async modelCatalog() {
    await this.refreshRelayDiscovery();
    const catalog = new Map();
    await Promise.allSettled(this.relayUrls.map(async (relayUrl) => {
      const health = await this.relayHealth(relayUrl);
      const capabilities = this.capabilities(health);
      if (Number(capabilities.chain_id) !== this.network.chain_id
          || normalizeAddress(capabilities.settlement_contract) !== this.network.settlement_contract) return;
      const models = Array.isArray(capabilities.models) && capabilities.models.length
        ? capabilities.models : [capabilities.model || DEFAULT_MODEL];
      for (const id of models) {
        if (typeof id !== "string" || !id.trim() || id.length > 256) continue;
        if (!catalog.has(id)) catalog.set(id, new Set());
        catalog.get(id).add(relayUrl);
      }
    }));
    if (!catalog.size) throw new Error("No ready Relay advertises models for this network");
    return [...catalog.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([id, urls]) => ({
      id, object: "model", owned_by: "mycomesh", relays: [...urls].sort(), route_count: urls.size,
      // Keep model-specific redundancy visible to clients. A healthy Relay
      // list alone is misleading when (for example) gpt-5.6-sol is served by
      // only one route and has no automatic failover path.
      redundancy: urls.size > 1 ? "redundant" : "single_relay",
      route_warning: urls.size > 1 ? undefined : "single Relay route; failover unavailable for this model",
    }));
  }

  async readinessPayload() {
    const now = Date.now();
    if (this.readinessCache && now - this.readinessCache.at < 2_000) return this.readinessCache.payload;
    if (this.readinessRequest) return this.readinessRequest;
    this.readinessRequest = (async () => {
      const deadline = performance.now() + READINESS_TIMEOUT_MS;
      // `/ready` is a fast liveness probe. V10 capacity is checked by the
      // dashboard and immediately before inference; repeating that chain RPC
      // here makes a cold probe time out even when both Relays are healthy.
      const selected = await this.chooseRelay(new Set(), { deadline, checkCapacity: false });
      const payload = { ok: true, relay: selected.relayUrl, model: this.capabilities(selected.health).model || DEFAULT_MODEL };
      this.readinessCache = { at: Date.now(), payload };
      return payload;
    })();
    try { return await this.readinessRequest; }
    finally { this.readinessRequest = null; }
  }

  async chooseRelay(exclude = new Set(), { model, requireSessions = false, reserve = false, deadline = Infinity, providerSigner, discoveryRetry = true, checkCapacity = true } = {}) {
    const refresh = this.refreshRelayDiscovery();
    const candidates = [...this.relayUrls];
    const errors = [];
    let timedOut = false;
    let rpcFailure;
    let budgetFailure;
    let modelUnavailable = false;
    const available = [];
    const checkRelay = async (relayUrl) => {
      try {
        const health = await withinDeadline(this.relayHealth(relayUrl), deadline);
        const models = this.capabilities(health).models;
        if (model && Array.isArray(models) && !models.includes(model)) {
          modelUnavailable = true;
          throw new Error("requested model is unavailable");
        }
        if (requireSessions && this.capabilities(health).scheduler?.session_affinity !== true) throw new Error("Relay upgrade required for session routing");
        if (providerSigner && !this.capabilities(health).provider_signers?.some((signer) => String(signer).toLowerCase() === providerSigner.toLowerCase())) {
          throw new Error("original Provider is not available on this Relay");
        }
        if (checkCapacity && this.network.protocol_version === 10) await withinDeadline(this.selectCapacityChannel(health, model, providerSigner), deadline);
        const item = { relayUrl, health };
        available.push(item);
        return item;
      } catch (error) {
        timedOut ||= error.statusCode === 504;
        if (error.code === "rpc_unavailable") rpcFailure = error;
        if (error.code === "budget_not_started" || error.code === "budget_unavailable") {
          if (!budgetFailure || (error.availableAt && (!budgetFailure.availableAt || error.availableAt < budgetFailure.availableAt))) budgetFailure = error;
        }
        errors.push(`${relayUrl}: ${error.message}`);
        throw error;
      }
    };
    const checks = candidates.filter((url) => !exclude.has(url)).map(checkRelay);
    if (this.relayDiscovery && discoveryRetry) {
      checks.push(withinDeadline(refresh, deadline).then(() => {
        remainingMs(deadline);
        return Promise.any(this.relayUrls.filter((url) => !candidates.includes(url) && !exclude.has(url)).map(checkRelay));
      }));
    }
    if (checks.length) {
      const all = Promise.allSettled(checks);
      try {
        await Promise.any(checks);
        // Give other healthy replies a small comparison window, without making
        // a healthy route wait for an unreachable backup's full health timeout.
        await withinDeadline(Promise.race([all, new Promise((resolve) => setTimeout(resolve, 30))]), deadline);
      } catch {}
    }
    if (available.length) {
      remainingMs(deadline);
      const offset = this.relaySelectionCursor++ % this.relayUrls.length;
      const score = ({ relayUrl, health }) => {
        const scheduling = this.capabilities(health).scheduler;
        const slots = Math.max(1, Number(scheduling?.total_slots || this.capabilities(health).providers || 1));
        const localLoad = (this.relayInFlight.get(relayUrl) || 0) + (this.relayReservations.get(relayUrl) || 0);
        const outstanding = Math.max(Number(scheduling?.outstanding_jobs || 0), localLoad);
        const assigned = [...this.sessionRoutes.values()].filter((entry) => entry.relayUrl === relayUrl).length;
        return [outstanding / slots, assigned / slots, (this.relayUrls.indexOf(relayUrl) - offset + this.relayUrls.length) % this.relayUrls.length];
      };
      available.sort((a, b) => {
        const left = score(a), right = score(b);
        return left[0] - right[0] || left[1] - right[1] || left[2] - right[2];
      });
      const selected = available[0];
      if (reserve) {
        this.relayReservations.set(selected.relayUrl, (this.relayReservations.get(selected.relayUrl) || 0) + 1);
        selected.reserved = true;
      }
      return selected;
    }
    if (timedOut) throw deadlineError();
    remainingMs(deadline);
    if (rpcFailure) throw rpcFailure;
    if (budgetFailure) throw budgetFailure;
    if (modelUnavailable && model) {
      throw Object.assign(new Error(`model ${model} has no healthy Relay route; inspect /models for redundancy and configure a backup Provider`), {
        code: "model_route_unavailable", model,
      });
    }
    throw new Error(`no healthy Settlement V${this.network.protocol_version} Relay is available: ${errors.join("; ") || "all relays excluded"}`);
  }

  ensureSessionRouteCapacity() {
    if (this.sessionRoutes.size + this.sessionSelections.size >= 4096) {
      const idle = [...this.sessionRoutes].filter(([id, entry]) => !entry.inFlight && !entry.dispatchPending && !entry.explicit && !this.sessionSelections.has(id))
        .sort((a, b) => a[1].lastUsed - b[1].lastUsed);
      for (const [id] of idle) {
        this.sessionRoutes.delete(id);
        if (this.sessionRoutes.size + this.sessionSelections.size < 4096) break;
      }
    }
    if (this.sessionRoutes.size + this.sessionSelections.size >= 4096) throw new Error("session routing capacity reached; retry later");
  }

  async chooseSessionRelay(session, exclude, model, deadline = Infinity) {
    void this.refreshRelayDiscovery();
    const now = Date.now();
    for (const [id, entry] of this.sessionRoutes) {
      if (!entry.inFlight && !entry.dispatchPending && now - entry.lastUsed > 24 * 60 * 60_000) this.sessionRoutes.delete(id);
    }
    if (this.sessionSelections.has(session.id)) return withinDeadline(this.sessionSelections.get(session.id), deadline);
    let pinned = this.sessionRoutes.get(session.id);
    if (!pinned) {
      const savedRoutes = this.history(0).filter((entry) => entry.accepted && entry.session_id === session.id
        && entry.relay_url && /^0x[0-9a-f]{40}$/i.test(entry.provider_signer || ""));
      if (new Set(savedRoutes.map((entry) => entry.provider_signer.toLowerCase())).size > 1) {
        const error = new Error("session history contains conflicting Provider routes; automatic migration is disabled");
        error.statusCode = 409;
        throw error;
      }
      const saved = savedRoutes[0];
      if (saved) {
        this.ensureSessionRouteCapacity();
        pinned = { relayUrl: saved.relay_url, providerSigner: saved.provider_signer, explicit: true, lastUsed: now, inFlight: 0 };
        this.sessionRoutes.set(session.id, pinned);
      }
    }
    if (pinned) {
      pinned.lastUsed = now;
      pinned.explicit ||= session.explicit || session.requiresOriginalRoute;
      try {
        if (exclude.has(pinned.relayUrl) || !this.relayUrls.includes(pinned.relayUrl)) throw new Error("original session Relay is unavailable");
        const health = await withinDeadline(this.relayHealth(pinned.relayUrl), deadline);
        if (this.capabilities(health).scheduler?.session_affinity !== true) throw new Error("Relay upgrade required to continue this session");
        if (pinned.providerSigner && Array.isArray(this.capabilities(health).provider_signers)
            && !this.capabilities(health).provider_signers.some((signer) => String(signer).toLowerCase() === pinned.providerSigner.toLowerCase())) {
          throw new Error("original Provider has disconnected from this Relay");
        }
        return { relayUrl: pinned.relayUrl, health };
      } catch (error) {
        if (error.statusCode === 504 || !pinned.providerSigner || pinned.inFlight || pinned.dispatchPending) throw error;
        if (this.sessionSelections.has(session.id)) return withinDeadline(this.sessionSelections.get(session.id), deadline);
        // A Relay may change only when the SAME verified Provider identity is
        // advertised at another configured route. Never replay unknown work.
        const recovery = (async () => {
          const selected = await this.chooseRelay(new Set([...exclude, pinned.relayUrl]), {
            model, requireSessions: true, reserve: true, deadline, providerSigner: pinned.providerSigner,
          });
          pinned.relayUrl = selected.relayUrl;
          pinned.lastUsed = Date.now();
          pinned.dispatchPending = true;
          return selected;
        })();
        this.sessionSelections.set(session.id, recovery);
        try { return await recovery; } finally { this.sessionSelections.delete(session.id); }
      }
    }
    if (session.requiresOriginalRoute) {
      const error = new Error("original session route expired or is unavailable; automatic migration is disabled");
      error.statusCode = 409;
      throw error;
    }
    this.ensureSessionRouteCapacity();
    const selection = (async () => {
      const selected = await this.chooseRelay(exclude, { model, requireSessions: session.explicit, reserve: true, deadline });
      // Keep the route leased across promise resolution until runRelayInference
      // synchronously transfers this reservation into its in-flight count.
      this.sessionRoutes.set(session.id, { relayUrl: selected.relayUrl, lastUsed: Date.now(), inFlight: 0, explicit: session.explicit, dispatchPending: true });
      return selected;
    })();
    this.sessionSelections.set(session.id, selection);
    try { return await selection; } finally { this.sessionSelections.delete(session.id); }
  }

  async capacityChannels() {
    if (this.network.protocol_version !== 10) return [];
    if (!this.network.capacity_channel_ids.length) return [];
    if (this.capacityChannelsRequest) return this.capacityChannelsRequest;
    // Share only an in-flight canonical snapshot. A later call always rereads
    // the chain, including after errors or a channel's expiry/closure.
    this.capacityChannelsRequest = this.rpcValue(async rpc => {
      if (BigInt(await this.callRpc(rpc, "eth_chainId", [])) !== BigInt(this.network.chain_id)) throw new Error("capacity RPC chain mismatch");
      const block = await this.callRpc(rpc, "eth_getBlockByNumber", ["latest", false]);
      const now = Math.floor(Date.now() / 1000);
      if (!block || !/^0x[0-9a-f]{64}$/i.test(block.hash) || !/^0x[0-9a-f]+$/i.test(block.timestamp || "")
          || Math.abs(Number(BigInt(block.timestamp)) - now) > 300) throw new Error("capacity RPC clock mismatch");
      const height = BigInt(block.number);
      if (height < 6n) throw new Error("capacity RPC confirmation depth unavailable");
      const confirmed = await this.callRpc(rpc, "eth_getBlockByNumber", ['0x'+(height-6n).toString(16), false]);
      if (!confirmed || !/^0x[0-9a-f]{64}$/i.test(confirmed.hash)) throw new Error("confirmed capacity block unavailable");
      const tag = { blockHash: confirmed.hash, requireCanonical: true };
      const ttl = await this.contractCall(rpc, this.network.settlement_contract, "MAX_AUTHORIZATION_TTL()", [], tag);
      if (!/^0x[0-9a-f]{64}$/i.test(ttl) || BigInt(ttl) !== 10800n) throw new Error("capacity contract lifetime mismatch");
      const channels = await Promise.all(this.network.capacity_channel_ids.map(async id => decodeCapacityChannel(
        await this.contractCall(rpc, this.network.settlement_contract, "channelInfo(bytes32)", [id], tag),
        id, this.network.chain_id, this.network.settlement_contract)));
      const canonical = await this.callRpc(rpc, "eth_getBlockByNumber", [confirmed.number, false]);
      if (!canonical || canonical.hash !== confirmed.hash) throw new Error("capacity block reorged during verification");
      return channels;
    });
    try { return await this.capacityChannelsRequest; }
    finally { this.capacityChannelsRequest = null; }
  }

  capacityBudget(channel, history = this.history(0), now = Math.floor(Date.now()/1000)) {
    const maximum = BigInt(this.maxFeeUnits);
    // Local unknown requests retain their full authorization. Another device's
    // unsettled reservations still require the Provider's authoritative check.
    const local = history.filter(r => r.capacity_channel_id === channel.channel_id && r.status !== "not_dispatched")
      .reduce((sum,r) => sum+BigInt(r.max_fee_units ?? channel.max_fee_per_request),0n);
    const settled = BigInt(channel.settled_max_fee), used = local > settled ? local : settled;
    const capacity = BigInt(channel.capacity)-used;
    const remaining = [capacity, BigInt(channel.credit_remaining), BigInt(channel.stake_remaining)]
      .reduce((a,b) => a < b ? a : b);
    const remainingUnits = remaining > 0n ? remaining : 0n;
    let reason = "available";
    if (channel.closed) reason = "closed";
    else if (now > Number(channel.claim_until)) reason = "releasable";
    else if (channel.consumer_key !== this.paymentAddress) reason = "previous_key";
    else if (this.unlockedWallet && channel.consumer_owner !== this.unlockedWallet) reason = "different_owner";
    else if (now >= Number(channel.admit_until)) reason = "admission_closed";
    else if (now + Math.ceil(this.timeoutMs/1000) + 60 > Number(channel.admit_until)) reason = "admission_window_short";
    else if (now + this.network.authorization_deadline_seconds > Number(channel.claim_until)) reason = "claim_window_short";
    else if (BigInt(channel.max_fee_per_request) < maximum) reason = "request_limit";
    else if (capacity < maximum) reason = "capacity_exhausted";
    else if (BigInt(channel.credit_remaining) < maximum) reason = "credit_insufficient";
    else if (BigInt(channel.stake_remaining) < maximum) reason = "stake_insufficient";
    else if (Number(channel.valid_from) > now) reason = "not_started";
    return { ready: reason === "available", reason, remaining_units: remainingUnits.toString(),
      request_maximum_units: maximum.toString(), estimated_requests: reason === "available" && maximum > 0n ? (remainingUnits/maximum).toString() : "0",
      ...(reason === "not_started" ? { available_at: Number(channel.valid_from) } : {}) };
  }

  async selectCapacityChannel(health, model, providerSigner) {
    const capability = this.capabilities(health);
    if (capability.reservation_mode !== "provider_bound_channel") throw new Error("Relay does not support fixed-budget channels");
    const now = Math.floor(Date.now()/1000), history = this.history(0);
    const channels = await this.capacityChannels();
    const routed = channels.filter(c => c.relay === String(capability.relay_payment_address).toLowerCase() && c.relay_signer === String(capability.relay_signer_address).toLowerCase()
      && c.channel === capability.channel_hash && String(c.pricing_version) === String(capability.pricing_version) && c.pricing_hash === capability.pricing_hash
      && (!providerSigner || c.provider_signer === providerSigner.toLowerCase())
      && capability.provider_routes?.some(p => p.provider_signer === c.provider_signer && p.provider === c.provider_owner && (!model || p.models?.includes(model))));
    let availableAt;
    for (const channel of routed) {
      const budget = this.capacityBudget(channel, history, now);
      if (budget.ready) return channel;
      if (budget.reason === "not_started") availableAt = Math.min(availableAt ?? Infinity, budget.available_at);
    }
    const error = new Error(availableAt
      ? `Fixed budget becomes available at ${new Date(availableAt * 1000).toISOString()}`
      : "No active funded channel covers this model and Provider; renew the fixed budget");
    error.code = availableAt ? "budget_not_started" : "budget_unavailable";
    if (availableAt) error.availableAt = availableAt;
    throw error;
  }

  async authorizationTiming(health, body) {
    if (this.network.protocol_version === 10) {
      const channel = await this.selectCapacityChannel(health, body?.model, body?.metadata?.mycomesh_provider_signer);
      return { now: Math.floor(Date.now()/1000), seconds: this.network.authorization_deadline_seconds, maxTtl: 10800, channel };
    }
    const seconds = this.network.authorization_deadline_seconds ?? 900;
    const maxTtl = this.network.max_authorization_ttl_seconds ?? 3600;
    if (this.network.protocol_version !== 9 || seconds <= 900) return { now: Math.floor(Date.now() / 1000), seconds, maxTtl: 3600 };
    return await this.rpcValue(async (rpc) => {
      const chain = await this.callRpc(rpc, "eth_chainId", []);
      if (BigInt(chain) !== BigInt(this.network.chain_id)) throw new Error("authorization RPC chain mismatch");
      const block = await this.callRpc(rpc, "eth_getBlockByNumber", ["latest", false]);
      const now = Math.floor(Date.now() / 1000);
      if (!block || !/^0x[0-9a-f]{64}$/i.test(block.hash) || !/^0x[0-9a-f]+$/i.test(block.timestamp || "")
          || Math.abs(Number(BigInt(block.timestamp)) - now) > AUTHORIZATION_CLOCK_SKEW_SECONDS) throw new Error("authorization RPC clock mismatch");
      const tag = { blockHash: block.hash, requireCanonical: true };
      const limit = await this.contractCall(rpc, this.network.settlement_contract, "MAX_AUTHORIZATION_TTL()", [], tag);
      if (!/^0x[0-9a-f]{64}$/i.test(limit) || BigInt(limit) !== BigInt(maxTtl)) throw new Error("contract authorization lifetime differs from manifest");
      const grant = await this.contractCall(rpc, this.network.settlement_contract, "keyGrants(address)", [this.paymentAddress], tag);
      if (!/^0x[0-9a-f]{256}$/i.test(grant)) throw new Error("invalid authorization key grant");
      const words = grant.slice(2).match(/.{64}/g);
      const validUntil = BigInt(`0x${words[2]}`);
      if (!/^0{24}/.test(words[0]) || BigInt(`0x${words[0]}`) === 0n || BigInt(`0x${words[3]}`) !== 1n
          || BigInt(`0x${words[1]}`) < BigInt(this.maxFeeUnits)
          || (validUntil !== 0n && validUntil < BigInt(now + seconds))) throw new Error("payment key does not cover the full settlement window");
      return { now, seconds, maxTtl };
    });
  }

  buildRelayPayment(path, body, health, requestId, timing) {
    const endpoint = path.endsWith("/chat/completions") ? "chat" : "responses";
    const v8 = this.capabilities(health);
    if (!v8) throw new Error("Relay health has no V8 payment requirements");
    if (Number(v8.chain_id) !== this.network.chain_id || normalizeAddress(v8.settlement_contract) !== this.network.settlement_contract) {
      throw new Error("Relay deployment does not match the pinned Consumer network");
    }
    if ((this.network.protocol_version >= 9 || this.network.require_response_proof)
        && v8.response_proof !== RESPONSE_PROOF_SCHEMA) throw new Error("Relay upgrade required for independently verified response content");
    const hasCatalog = Array.isArray(v8.models) && v8.models.length > 0;
    const advertised = hasCatalog ? v8.models.map(String) : [String(v8.model || DEFAULT_MODEL)];
    const requested = String(body.model || "").trim();
    const model = hasCatalog
      ? (requested || String(v8.model || advertised[0] || DEFAULT_MODEL))
      : String(v8.model || requested || DEFAULT_MODEL);
    if (hasCatalog && !advertised.includes(model)) throw new Error(`model is not advertised by the selected Relay: ${model}`);
    const maxOutput = body.max_output_tokens ?? body.max_tokens ?? v8.maxOutputTokens ?? 2000;
    const options = {};
    for (const field of [...RESPONSES_REQUEST_OPTION_FIELDS, ...RESPONSES_LOCAL_OPTION_FIELDS]) {
      if (Object.prototype.hasOwnProperty.call(body, field)) options[field] = body[field];
    }
    const normalizedOptions = normalizeInferenceOptions(endpoint, options);
    const requestHash = inferenceRequestHash({
      endpoint,
      model,
      input: body.input,
      messages: body.messages,
      maxOutputTokens: maxOutput,
      options: normalizedOptions || undefined,
    });
    if ((this.network.authorization_deadline_seconds ?? 900) > 900 && !timing) throw new Error("long authorization requires verified on-chain timing");
    const now = timing?.now ?? Math.floor(Date.now() / 1000);
    if (this.network.protocol_version === 10) {
      if (!timing?.channel) throw new Error("verified capacity channel required before dispatch");
      const channel = timing.channel;
      return { payment: buildReservedAuthorization({ paymentKey: this.paymentKey, chainId: this.network.chain_id,
        settlementContract: this.network.settlement_contract, channelId: channel.channel_id, requestId, requestHash,
        maxFee: this.maxFeeUnits, issuedAt: Math.max(Number(channel.valid_from), now-300),
        executeBy: now+Math.ceil(this.timeoutMs/1000)+60, deadline: now+timing.seconds }), channel, request_id: requestId, model };
    }
    const payment = buildAuthorization({
      protocolVersion: this.network.protocol_version,
      paymentKey: this.paymentKey,
      chainId: Number(v8.chain_id),
      settlementContract: v8.settlement_contract,
      requestId,
      requestHash,
      relay: v8.relay_payment_address,
      relaySigner: v8.relay_signer_address,
      channelHash: v8.channel_hash,
      pricingVersion: v8.pricing_version,
      pricingHash: v8.pricing_hash,
      maxFee: this.maxFeeUnits,
      issuedAt: now - AUTHORIZATION_CLOCK_SKEW_SECONDS,
      deadline: now + (timing?.seconds ?? 900),
      maxAuthorizationTtlSeconds: timing?.maxTtl ?? 3600,
    });
    return { payment, request_id: requestId, model };
  }

  async relayInference(path, body, requestHeaders = {}) {
    this.activeInferenceRequests += 1;
    let journal, claim;
    try {
      if (this.network.protocol_version === 10) {
        const headers = Object.fromEntries(Object.entries(requestHeaders).map(([k,v]) => [k.toLowerCase(),v]));
        const idempotencyKey = headers["idempotency-key"];
        if (!idempotencyKey && Number(headers["x-stainless-retry-count"] || 0) > 0) {
          return { status: 422, headers: { "x-should-retry": "false" },
            payload: { error: { message: "Automatic retry has no stable Idempotency-Key. Check the original request before submitting again.",
              type: "idempotency_key_required", code: "idempotency_key_required", retryable: false } } };
        }
        if (idempotencyKey !== undefined) {
          journal = new ConsumerRequestJournal({ directory: join(this.dataDir, "request-journal"), chainId: this.network.chain_id,
            contract: this.network.settlement_contract, paymentKeyAddress: this.paymentAddress });
          claim = journal.claim({ idempotencyKey, payloadHash: requestPayloadHash({ path, body,
            session: headers["x-mycomesh-session-id"] || "" }) });
          if (claim.action === "replay") return claim.result;
        }
      }
      const result = await this.runRelayInference(path, body, requestHeaders, claim?.requestId);
      if (claim && journal) {
        if (result.payload?.error?.execution_status === "unknown") journal.markOutcomeUnknown(claim);
        else {
          try { return journal.complete(claim, result); }
          catch {
            journal.markOutcomeUnknown(claim);
            result.headers = { ...result.headers, "x-should-retry": "false", "x-mycomesh-history-status": "response-cache-unavailable" };
          }
        }
      }
      return result;
    } catch (error) {
      if (claim?.action === "execute") { try { journal.markOutcomeUnknown(claim); } catch {} }
      if (this.network.protocol_version === 10) return { status: 422, headers: { "x-should-retry": "false",
        ...(error.requestId || claim?.requestId ? { "x-mycomesh-request-id": error.requestId || claim.requestId } : {}) },
        payload: { error: { message: error.message, type: error.code || "request_tracking_unavailable", code: error.code || "request_tracking_unavailable", retryable: false } } };
      throw error;
    }
    finally { this.activeInferenceRequests -= 1; }
  }

  async runRelayInference(path, body, requestHeaders = {}, stableRequestId) {
    const deadline = performance.now() + this.timeoutMs;
    let session;
    try { session = this.sessions.resolve(body, requestHeaders); }
    catch (error) { return { payload: openaiError(error.message, "invalid_session"), status: error.statusCode || 400, headers: {} }; }
    const clientBody = body;
    body = session.body;
    const keepSession = session.explicit || session.requiresOriginalRoute || this.sessionRoutes.has(session.id);
    const requestId = stableRequestId || `0x${bytesToHex(randomBytes(32))}`;
    const preDispatchFailure = (message, type, status = 503) => ({
      payload: { error: { ...openaiError(message, type).error, execution_status: "not_dispatched", request_id: requestId } },
      status,
      headers: { "Retry-After": "2", "x-mycomesh-session-id": session.id, "x-mycomesh-request-id": requestId },
    });
    const used = new Set();
    let lastError = "no Relay accepted the request";
    let lastResponse;
    while (used.size < this.relayUrls.length) {
      let selected;
      try { selected = await this.chooseSessionRelay(session, used, body.model, deadline); }
      catch (error) {
        lastError = error.message;
        if (error.code === "rpc_unavailable") lastResponse = preDispatchFailure(lastError, "rpc_unavailable");
        if (error.code === "budget_not_started" || error.code === "budget_unavailable") lastResponse = preDispatchFailure(lastError, error.code, 402);
        if (error.statusCode === 409) lastResponse = preDispatchFailure(lastError, "session_continuation_unavailable", 409);
        if (error.statusCode === 504) lastResponse = preDispatchFailure(lastError, "request_timeout", 504);
        break;
      }
      used.add(selected.relayUrl);
      if (selected.reserved) {
        this.relayReservations.set(selected.relayUrl, Math.max(0, (this.relayReservations.get(selected.relayUrl) || 1) - 1));
        selected.reserved = false;
      }
      const route = this.sessionRoutes.get(session.id);
      if (route) { route.inFlight += 1; route.dispatchPending = false; }
      this.relayInFlight.set(selected.relayUrl, (this.relayInFlight.get(selected.relayUrl) || 0) + 1);
      let successfulHttpResponse = false;
      let postStarted = false;
      let dispatchPayment;
      try {
        const requestBody = {
          ...body,
          model: Array.isArray(this.capabilities(selected.health).models) && this.capabilities(selected.health).models.length
            ? (body.model || this.capabilities(selected.health).model || DEFAULT_MODEL)
            : (this.capabilities(selected.health).model || body.model || DEFAULT_MODEL),
        };
        if (route?.providerSigner) {
          const supplied = requestBody.metadata?.mycomesh_provider_signer;
          if (supplied && String(supplied).toLowerCase() !== route.providerSigner.toLowerCase()) {
            return { payload: openaiError("Provider hint conflicts with the original session", "invalid_session"), status: 409, headers: {} };
          }
          requestBody.metadata = { ...requestBody.metadata, mycomesh_provider_signer: route.providerSigner };
        }
        if (!String(requestBody.prompt_cache_key || "").trim()) {
          const cacheKey = derivePromptCacheKey({
            endpoint: path.endsWith("/chat/completions") ? "chat" : "responses",
            model: requestBody.model,
            input: requestBody.input,
            messages: requestBody.messages,
            options: requestBody,
          });
          if (cacheKey) requestBody.prompt_cache_key = cacheKey;
        }
        const timing = await withinDeadline(this.authorizationTiming(selected.health, requestBody), deadline);
        if (timing.channel) requestBody.metadata = { ...requestBody.metadata, mycomesh_provider_signer: timing.channel.provider_signer };
        const payment = this.buildRelayPayment(path, requestBody, selected.health, requestId, timing);
        const proofRequired = this.network.protocol_version >= 9 || this.network.require_response_proof
          || this.capabilities(selected.health).response_proof === RESPONSE_PROOF_SCHEMA;
        requestBody.model = payment.model;
        const encodedPayment = base64Url(Buffer.from(stableStringify(payment.payment), "utf8"));
        let milliseconds = remainingMs(deadline);
        this.verifyRelayIdentity(selected.relayUrl, selected.health);
        // Persist the request identity before any execution can occur. A crash
        // or lost response must leave a scoped record that can be reconciled.
        dispatchPayment = payment;
        try { this.recordDispatch(selected.relayUrl, path, payment, session.id); }
        catch { return { payload: openaiError("Cannot save request tracking; request was not dispatched", "request_tracking_unavailable"), status: 503, headers: { "x-mycomesh-request-id": requestId } }; }
        milliseconds = remainingMs(deadline);
        postStarted = true;
        const response = await fetchWithTimeout(`${selected.relayUrl}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json", "PAYMENT-SIGNATURE": encodedPayment,
            ...(proofRequired ? { "X-MycoMesh-Response-Proof": RESPONSE_PROOF_SCHEMA } : {}),
            "X-MycoMesh-Request-Timeout-Ms": String(milliseconds) },
          body: JSON.stringify(requestBody),
          dispatcher: this.dispatcher,
        }, milliseconds);
        successfulHttpResponse = response.status >= 200 && response.status < 300;
        const paymentResponse = response.headers.get("PAYMENT-RESPONSE");
        let payload, bodyError = null;
        try { payload = await readJsonResponse(response); } catch (error) { bodyError = error; }
        if (!bodyError && successfulHttpResponse && (!payload || typeof payload !== "object" || Array.isArray(payload)
            || (payload.error && !(proofRequired && payload.schema === RESPONSE_PROOF_SCHEMA)))) {
          bodyError = new Error("Relay returned an invalid response body; request was not replayed");
        }
        if (bodyError && !paymentResponse) throw bodyError;
        const retryAfter = response.headers.get("retry-after");
        const headers = { "x-mycomesh-session-id": session.id, "x-mycomesh-request-id": requestId, ...(retryAfter ? { "Retry-After": retryAfter } : {}) };
        if (this.network.protocol_version === 10 && !paymentResponse && response.status >= 400) {
          try { this.recordDispatch(selected.relayUrl, path, payment, session.id, "outcome_unknown"); } catch {}
          const error = openaiError("The request reached the Relay; execution and payment status must be reconciled before retrying. "
            + String(payload?.error?.message || ""), "relay_outcome_unknown");
          Object.assign(error.error, { execution_status: "unknown", retryable: false, request_id: requestId });
          return { payload: error, status: 422, headers: { ...headers, "x-should-retry": "false" } };
        }
        if (this.network.protocol_version !== 10 && !paymentResponse && payload?.error?.execution_status === "not_dispatched") {
          try { this.recordDispatch(selected.relayUrl, path, payment, session.id, "not_dispatched"); } catch {}
        }
        if (!paymentResponse && RETRYABLE_RELAY_STATUS.has(response.status)) {
          this.noteRelayFailure(selected.relayUrl, retryAfter);
          lastError = payload?.error?.message || `Relay returned HTTP ${response.status}`;
          lastResponse = { payload, status: response.status, headers };
          if (this.network.protocol_version === 10 || keepSession || payload?.error?.execution_status !== "not_dispatched") break;
          this.sessionRoutes.delete(session.id);
          continue;
        }
        if (!paymentResponse && response.status >= 400) return { payload: normalizeOpenAiError(payload, "relay_error"), status: response.status, headers };
        this.relayFailures.delete(selected.relayUrl);
        if (!paymentResponse && proofRequired) throw new Error("Relay success is missing its signed payment receipt");
        if (paymentResponse) {
          const settlement = decodePaymentResponse(paymentResponse, {
            protocolVersion: this.network.protocol_version,
            chainId: this.network.chain_id, contract: this.network.settlement_contract,
            requestId, requestHash: payment.payment.authorization.request_hash,
            relay: payment.payment.authorization.relay, relaySigner: payment.payment.authorization.relay_signer,
            channel: payment.channel,
          });
          const returnedAuthorization = settlement.signed_receipt.authorization;
          if (returnedAuthorization.authorization_hash !== payment.payment.authorization_hash || returnedAuthorization.key_signature !== payment.payment.key_signature) {
            throw new Error("Relay receipt changed the dispatched payment authorization");
          }
          const receipt = settlement.signed_receipt.receipt;
          const authorization = settlement.signed_receipt.authorization.authorization;
          if (authorization.request_id !== requestId || authorization.key.toLowerCase() !== this.paymentAddress
              || (route?.providerSigner && receipt.provider_signer.toLowerCase() !== route.providerSigner.toLowerCase())) {
            throw new Error("Relay receipt does not match this request or its pinned Provider");
          }
          // A fully signed, request-bound receipt may settle regardless of an
          // unsigned Relay accepted=false label; keep it eligible for RPC sync.
          settlement.accepted = true;
          let contentError = bodyError || (!successfulHttpResponse ? new Error("Relay returned a payment receipt with an HTTP error") : null);
          headers["x-mycomesh-content-verification"] = contentError ? "failed" : "receipt-only";
          if (proofRequired && !contentError) {
            try {
              payload = verifyResponseProof(payload, receipt, { requestId,
                endpoint: path.endsWith("/chat/completions") ? "chat" : "responses", model: payment.model });
              headers["x-mycomesh-content-verification"] = "provider-signed";
            } catch (error) {
              contentError = error;
              headers["x-mycomesh-content-verification"] = "failed";
            }
          }
          if (route) route.providerSigner = receipt.provider_signer;
          try {
            this.recordReceipt(selected.relayUrl, path, String(body.model || payment.model), settlement, payment.model, session.id,
              headers["x-mycomesh-content-verification"]);
          } catch {
            // A persistence failure must never replay a completed, billed inference.
            this.historySyncError = "付款回执已收到，但账单保存失败；请保留本次响应回执";
            headers["x-mycomesh-history-status"] = "persistence-error";
          }
          headers["PAYMENT-RESPONSE"] = paymentResponse;
          if (contentError) {
            this.noteRelayFailure(selected.relayUrl);
            const result = { payload: openaiError("Response content verification failed; a valid payment receipt was received and may settle. Request was not replayed.", "content_verification_failed"), status: 502, headers };
            if (this.network.protocol_version === 10) {
              result.status = 422; result.headers["x-should-retry"] = "false";
              Object.assign(result.payload.error, { execution_status: "executed", retryable: false, request_id: requestId });
            }
            return result;
          }
        }
        this.sessions.remember(payload, session.id);
        return { payload: restoreClientResponse(payload, clientBody), status: 200, headers };
      } catch (error) {
        lastError = error.message;
        if (!postStarted && dispatchPayment) {
          try { this.recordDispatch(selected.relayUrl, path, dispatchPayment, session.id, "not_dispatched"); } catch {}
        }
        if (postStarted && dispatchPayment) {
          try { this.recordDispatch(selected.relayUrl, path, dispatchPayment, session.id, "outcome_unknown"); } catch {}
        }
        if (postStarted) this.noteRelayFailure(selected.relayUrl);
        if (postStarted && this.network.protocol_version === 10) {
          const payload = openaiError("Execution or payment status is unknown; this request was not replayed. Check its request ID before retrying.", "relay_outcome_unknown");
          Object.assign(payload.error, { execution_status: "unknown", retryable: false, request_id: requestId });
          const transportCode = error?.cause?.code ?? error?.code;
          if (["UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "UND_ERR_SOCKET", "ECONNRESET", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"].includes(transportCode)) {
            payload.error.transport_code = transportCode;
          }
          return { payload, status: 422, headers: { "x-should-retry": "false", "x-mycomesh-session-id": session.id, "x-mycomesh-request-id": requestId } };
        }
        if (!postStarted && error.code === "rpc_unavailable") {
          lastResponse = preDispatchFailure(lastError, "rpc_unavailable");
          break;
        }
        if (!postStarted && error.statusCode === 504) {
          lastResponse = preDispatchFailure(lastError, "request_timeout", 504);
          break;
        }
        if (successfulHttpResponse) {
          lastResponse = { payload: openaiError(lastError, "invalid_relay_response"), status: 502,
            headers: { "x-mycomesh-session-id": session.id, "x-mycomesh-request-id": requestId } };
          break;
        }
        if (postStarted) {
          // A lost connection is not proof that a billed inference did not run.
          lastResponse = { payload: openaiError("Relay outcome is unknown; request was not replayed", "relay_outcome_unknown"), status: 502,
            headers: { "x-mycomesh-session-id": session.id, "x-mycomesh-request-id": requestId } };
          break;
        }
        if (keepSession) break;
        this.sessionRoutes.delete(session.id);
      } finally {
        this.relayInFlight.set(selected.relayUrl, Math.max(0, (this.relayInFlight.get(selected.relayUrl) || 1) - 1));
        if (route) { route.inFlight = Math.max(0, route.inFlight - 1); route.lastUsed = Date.now(); }
      }
    }
    if (lastResponse) return lastResponse;
    return preDispatchFailure(lastError, keepSession ? "session_unavailable" : "relay_unavailable");
  }
}

function decodePaymentResponse(value, expected = {}) {
  let payload;
  try { payload = JSON.parse(Buffer.from(String(value), "base64url").toString("utf8")); } catch { throw new Error("Relay returned an invalid PAYMENT-RESPONSE"); }
  if (!payload || typeof payload !== "object" || !payload.signed_receipt) throw new Error("Relay PAYMENT-RESPONSE is missing its signed receipt");
  try { const verified = verifySignedReceipt(payload.signed_receipt, expected);
    if (expected.protocolVersion === 10) payload.signed_receipt = { ...payload.signed_receipt, receipt: verified.receipt }; } catch (error) { throw new Error(`Relay returned an invalid signed receipt: ${error.message}`); }
  return payload;
}

export function verifyResponseProof(proof, receipt, { requestId, endpoint, model }) {
  if (!proof || proof.schema !== RESPONSE_PROOF_SCHEMA || typeof proof.commitment_b64 !== "string"
      || proof.commitment_b64.length > MAX_BODY_BYTES) throw new Error("Relay response is missing its Provider content proof");
  const bytes = Buffer.from(proof.commitment_b64, "base64");
  if (bytes.toString("base64") !== proof.commitment_b64) throw new Error("Invalid Provider content proof encoding");
  if (`0x${createHash("sha256").update(bytes).digest("hex")}` !== receipt.response_hash) {
    throw new Error("Response content differs from its Provider-signed commitment");
  }
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!value || value.schema !== "mycomesh.provider-response-commitment.v1"
      || value.request_id !== requestId || value.endpoint !== endpoint || value.model !== model
      || !value.raw || typeof value.raw !== "object" || Array.isArray(value.raw)) {
    throw new Error("Provider content proof does not match this request");
  }
  // Only authenticated bytes supply the API result. Ignore unauthenticated
  // sibling fields; verify before model/schema restoration or SSE generation.
  return value.raw;
}

function normalizeOpenAiError(value, fallbackType) {
  if (!value || typeof value !== "object") return openaiError(String(value || fallbackType), fallbackType);
  if (!value.error || typeof value.error !== "object") return openaiError(value.detail || value.message || fallbackType, fallbackType);
  return { ...value, error: { ...value.error, message: String(value.error.message || fallbackType), type: String(value.error.type || fallbackType), param: value.error.param ?? null, code: value.error.code || value.error.type || fallbackType } };
}

function clientToolSchema(tools, name) {
  if (!Array.isArray(tools)) return undefined;
  for (const tool of tools) {
    if (!tool || typeof tool !== "object") continue;
    const definition = tool.function && typeof tool.function === "object" ? tool.function : tool;
    if (definition.name === name && definition.parameters && typeof definition.parameters === "object") return definition.parameters;
  }
  return undefined;
}

function orderBySchema(value, schema) {
  if (Array.isArray(value)) return value.map((item) => orderBySchema(item, schema?.items));
  if (!value || typeof value !== "object" || Array.isArray(schema)) return value;
  const properties = schema?.properties;
  if (!properties || typeof properties !== "object") return value;
  const ordered = {};
  for (const key of Object.keys(properties)) {
    if (Object.prototype.hasOwnProperty.call(value, key)) ordered[key] = orderBySchema(value[key], properties[key]);
  }
  for (const key of Object.keys(value)) {
    if (!Object.prototype.hasOwnProperty.call(ordered, key)) ordered[key] = value[key];
  }
  return ordered;
}

function restoreClientResponse(payload, body) {
  if (!payload || typeof payload !== "object") return payload;
  if (typeof body.model === "string" && body.model) payload.model = body.model;
  const calls = [];
  for (const choice of Array.isArray(payload.choices) ? payload.choices : []) {
    calls.push(...(Array.isArray(choice?.message?.tool_calls) ? choice.message.tool_calls : []));
  }
  calls.push(...(Array.isArray(payload.output) ? payload.output.filter((item) => item?.type === "function_call") : []));
  for (const call of calls) {
    const fn = call?.function && typeof call.function === "object" ? call.function : call;
    if (typeof fn?.name !== "string" || typeof fn.arguments !== "string") continue;
    const schema = clientToolSchema(body.tools, fn.name);
    if (!schema) continue;
    try { fn.arguments = JSON.stringify(orderBySchema(JSON.parse(fn.arguments), schema)); } catch {}
  }
  return payload;
}

function decodeRequestBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("request body must be an object");
        resolve(value);
      } catch (error) { reject(error); }
    });
    request.on("error", reject);
  });
}

function writeJson(response, status, value, headers = {}) {
  const body = JSON.stringify(value);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  response.end(body);
}

function waitForTunnelUrl(child) {
  return new Promise((resolve, reject) => {
    let output = "";
    let publicUrl = "";
    let connected = false;
    const diagnostics = () => output.trim().replace(/\s+/g, " ").slice(-1000);
    const finish = (error, url) => {
      clearTimeout(timer);
      child.removeListener("error", onError);
      child.removeListener("exit", onExit);
      child.stdout?.removeListener("data", onData);
      child.stderr?.removeListener("data", onData);
      if (error) reject(error); else resolve(url);
    };
    const onData = (chunk) => {
      output = `${output}${String(chunk)}`.slice(-16_384);
      const match = output.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
      if (match) publicUrl = match[0];
      if (/Registered tunnel connection/i.test(output)) connected = true;
      if (publicUrl && connected) finish(null, publicUrl);
    };
    const onError = (error) => finish(new Error(`could not start cloudflared: ${error.message}`));
    const onExit = (code) => {
      const detail = diagnostics();
      finish(new Error(`cloudflared exited before publishing a URL (${code ?? "signal"})${detail ? `: ${detail}` : ""}`));
    };
    const timer = setTimeout(
      () => {
        const detail = diagnostics();
        finish(new Error(`timed out waiting for the temporary HTTPS URL${detail ? `: ${detail}` : ""}`));
      },
      TUNNEL_START_TIMEOUT_MS,
    );
    child.once("error", onError);
    child.once("exit", onExit);
    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);
  });
}

async function stopTunnelProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode != null) return;
  await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener("exit", finish);
      resolve();
    };
    const timer = setTimeout(finish, TUNNEL_STOP_TIMEOUT_MS);
    child.once("exit", finish);
    try { child.kill("SIGTERM"); } catch { finish(); }
  });
}

async function handleInference(state, request, response, path, alphaSearchQuery, shareOnly = false) {
  const authorization = String(request.headers.authorization || "");
  if (!state.authorizeBearer(authorization, { shareOnly })) {
    writeJson(response, 401, openaiError("invalid MycoMesh access key", "invalid_api_key"));
    return;
  }
  let body;
  try { body = await decodeRequestBody(request); } catch (error) {
    writeJson(response, 400, openaiError(error.message, "invalid_request_error"));
    return;
  }
  const alphaSearch = alphaSearchQuery !== undefined;
  if (alphaSearch) {
    body = {
      model: body.model,
      ...(body.metadata !== undefined ? { metadata: body.metadata } : {}),
      ...(body.conversation !== undefined ? { conversation: body.conversation } : {}),
      input: [{ type: "mycomesh_alpha_search_request", request: body, query: alphaSearchQuery }],
      max_output_tokens: body.max_output_tokens ?? 2000,
    };
    path = "/v1/responses";
  }
  if (path.endsWith("/responses/compact") && !hasCompactionTrigger(body.input)) {
    const items = Array.isArray(body.input) ? [...body.input] : [];
    if (body.input !== undefined && body.input !== "" && !Array.isArray(body.input)) {
      items.push(typeof body.input === "string" ? { type: "message", role: "user", content: body.input } : body.input);
    }
    items.push({ type: "compaction_trigger" });
    body.input = items;
  }
  try {
    const result = await state.relayInference(path, body, request.headers);
    if (result.status >= 400) {
      writeJson(response, result.status, result.payload, result.headers);
      return;
    }
    for (const [name, value] of Object.entries(result.headers || {})) response.setHeader(name, value);
    if (alphaSearch) {
      const payload = result.payload?.mycomesh_alpha_search_response;
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        writeJson(response, 502, openaiError("Provider returned an invalid alpha/search response", "mycomesh_provider_error"));
        return;
      }
      writeJson(response, 200, payload, result.headers);
      return;
    }
    if (body.stream === true) {
      response.writeHead(200, { ...result.headers, "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache", connection: "keep-alive", "x-mycomesh-streaming-mode": "buffered" });
      const events = path.endsWith("/chat/completions")
        ? chatCompletionSse(result.payload, body.stream_options?.include_usage === true)
        : responseSse(result.payload, path.endsWith("/responses/compact") || hasCompactionTrigger(body.input));
      for (const chunk of events) response.write(chunk);
      response.end();
      return;
    }
    writeJson(response, 200, result.payload, result.headers);
  } catch (error) {
    writeJson(response, 502, openaiError(error.message, "mycomesh_relay_error"));
  }
}

export function createConsumerServer(state, { host = "127.0.0.1", port = 8110, publicOnly = false } = {}) {
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", `http://${request.headers.host || "127.0.0.1"}`);
      const path = url.pathname.startsWith("/v1/v1/") ? url.pathname.slice(3) : url.pathname;
      if (publicOnly) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-MycoMesh-Session-Id, X-Session-Id, session_id");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        response.setHeader("Access-Control-Expose-Headers", "PAYMENT-RESPONSE, Retry-After, X-MycoMesh-Session-Id, X-MycoMesh-History-Status, X-MycoMesh-Content-Verification");
        if (request.method === "OPTIONS") { response.writeHead(204); response.end(); return; }
        if (request.method === "GET" && (path === "/health" || path === "/v1/health")) {
          if (!state.authorizeBearer(String(request.headers.authorization || ""), { shareOnly: true })) { writeJson(response, 401, openaiError("invalid temporary access key", "invalid_api_key")); return; }
          writeJson(response, 200, { ok: true, protocol: "mycomesh-temporary-share/v1", expires_at: state.activeShare()?.expiresAt });
          return;
        }
        if (request.method === "GET" && (path === "/models" || path === "/v1/models" || path === "/backend-api/codex/models")) {
          if (!state.authorizeBearer(String(request.headers.authorization || ""), { shareOnly: true })) { writeJson(response, 401, openaiError("invalid temporary access key", "invalid_api_key")); return; }
          try { const selected = await state.chooseRelay(); const models = Array.isArray(state.capabilities(selected.health).models) ? state.capabilities(selected.health).models : [state.capabilities(selected.health).model || DEFAULT_MODEL]; writeJson(response, 200, { object: "list", data: models.map((id) => ({ id: String(id), object: "model", owned_by: "mycomesh", relay: selected.relayUrl })) }); }
          catch (error) { writeJson(response, 503, openaiError(error.message, "relay_unavailable")); }
          return;
        }
        if (request.method === "POST" && ["/responses", "/v1/responses", "/v1/v1/responses", "/backend-api/codex/responses", "/responses/compact", "/v1/responses/compact", "/v1/v1/responses/compact", "/backend-api/codex/responses/compact", "/chat/completions", "/v1/chat/completions"].includes(path)) {
          const relayPath = path.endsWith("/chat/completions") ? "/v1/chat/completions" : path.endsWith("/responses/compact") ? "/v1/responses/compact" : "/v1/responses";
          await handleInference(state, request, response, relayPath, undefined, true); return;
        }
        if (request.method === "POST" && ["/alpha/search", "/v1/alpha/search", "/backend-api/codex/alpha/search"].includes(path)) {
          await handleInference(state, request, response, "/v1/responses", Object.fromEntries(url.searchParams), true); return;
        }
        writeJson(response, 404, openaiError("route not found", "invalid_request_error"));
        return;
      }
      if (path === "/" || path === "/credentials" || path === "/codex-env" || path.startsWith("/v1/mycomesh/local/")) {
        const remote = request.socket.remoteAddress || "";
        const authority = String(request.headers.host || "").toLowerCase();
        const localPort = server.address()?.port;
        const localAuthority = new Set([`127.0.0.1:${localPort}`, `localhost:${localPort}`, `[::1]:${localPort}`]);
        const origin = request.headers.origin;
        if (!(remote === "::1" || /^(?:::ffff:)?127\.\d+\.\d+\.\d+$/.test(remote))
            || !localAuthority.has(authority)
            || (origin !== undefined && origin !== `http://${authority}`)
            || request.headers["sec-fetch-site"] === "cross-site") {
          writeJson(response, 403, { ok: false, error: "local management requires a same-origin loopback connection" });
          return;
        }
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("X-Content-Type-Options", "nosniff");
      }
      if (request.method === "GET" && path === "/") {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(consumerHtml());
        return;
      }
      if (request.method === "GET" && path === "/health") { writeJson(response, 200, state.healthPayload()); return; }
      if (request.method === "GET" && path === "/ready") {
        try {
          writeJson(response, 200, await state.readinessPayload());
        }
        catch (error) {
          const timedOut = error?.statusCode === 504;
          const payload = { ok: false, error: timedOut ? "readiness check timed out; retry shortly" : error.message,
            code: timedOut ? "readiness_timeout" : (error.code || "relay_unavailable") };
          if (error.availableAt) payload.available_at = error.availableAt;
          writeJson(response, 503, payload, timedOut
            ? { "retry-after": "2" }
            : error.code === "budget_not_started" && error.availableAt
              ? { "retry-after": String(Math.max(1, Math.ceil(error.availableAt - Date.now() / 1000))) } : {});
        }
        return;
      }
      if (request.method === "GET" && (path === "/credentials" || path === "/codex-env")) {
        if (!state.paymentUnlocked) { writeJson(response, 423, { ok: false, error: "sign in with the payment-key owner wallet first" }); return; }
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }); response.end(`${state.credentialsText()}\n`); return;
      }
      if (request.method === "GET" && (path === "/models" || path === "/v1/models" || path === "/backend-api/codex/models")) {
        try { writeJson(response, 200, { object: "list", data: await state.modelCatalog() }); }
        catch (error) { writeJson(response, 503, openaiError(error.message, "relay_unavailable")); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/wallet/challenge") {
        try { const value = await decodeRequestBody(request); writeJson(response, 200, state.createWalletChallenge(value.wallet)); }
        catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/wallet/authenticate") {
        try { writeJson(response, 200, await state.authenticateWallet(await decodeRequestBody(request))); }
        catch (error) {
          const payload = { ok: false, error: error.message };
          // Keep the legacy error string, and expose only explicit public fields.
          if (["payment_key_owner_mismatch", "wallet_verification_unavailable"].includes(error.code)) {
            payload.code = error.code;
            payload.selected_wallet = error.selected_wallet;
            payload.payment_key_address = error.payment_key_address;
            if (error.expected_owner) payload.expected_owner = error.expected_owner;
          }
          writeJson(response, error.code === "wallet_verification_unavailable" ? 503 : 401, payload);
        }
        return;
      }
      if (request.method === "GET" && path === "/v1/mycomesh/local/dashboard") {
        writeJson(response, 200, await state.dashboardPayload(state.authorizeManagement(String(request.headers.authorization || "")))); return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/history/sync") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        await state.refreshReceiptStatuses(true);
        writeJson(response, 200, { ok: true, history_sync: {
          running: Boolean(state.historySync), last_checked_at: state.historySyncAt, error: state.historySyncError,
        } }); return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/wallet/activate") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        try { writeJson(response, 200, await state.activateCurrentPaymentKey()); }
        catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/wallet/lock") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        writeJson(response, 200, await state.lockWallet()); return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/transactions") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        try { writeJson(response, 200, await state.transactionPlan(await decodeRequestBody(request))); }
        catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/key/prepare") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        try { writeJson(response, 200, state.preparePaymentKey()); } catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/key/activate") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        try { const value = await decodeRequestBody(request); writeJson(response, 200, await state.activatePendingPaymentKey(value.wallet)); }
        catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/share/start") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        try { const value = await decodeRequestBody(request); writeJson(response, 200, { ok: true, share: await state.startShare(value.minutes) }); }
        catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/share/stop") {
        if (!state.authorizeManagement(String(request.headers.authorization || ""))) { writeJson(response, 401, { ok: false, error: "wallet login required" }); return; }
        writeJson(response, 200, { ok: true, share: await state.stopShare() });
        return;
      }
      if (request.method === "POST" && ["/responses", "/v1/responses", "/v1/v1/responses", "/backend-api/codex/responses", "/responses/compact", "/v1/responses/compact", "/v1/v1/responses/compact", "/backend-api/codex/responses/compact", "/chat/completions", "/v1/chat/completions"].includes(path)) {
        const relayPath = path.endsWith("/chat/completions")
          ? "/v1/chat/completions"
          : path.endsWith("/responses/compact")
            ? "/v1/responses/compact"
            : "/v1/responses";
        await handleInference(state, request, response, relayPath); return;
      }
      if (request.method === "POST" && ["/alpha/search", "/v1/alpha/search", "/backend-api/codex/alpha/search"].includes(path)) {
        await handleInference(state, request, response, "/v1/responses", Object.fromEntries(url.searchParams)); return;
      }
      writeJson(response, 404, openaiError("route not found", "invalid_request_error"));
    } catch (error) {
      if (!response.headersSent) writeJson(response, 500, openaiError(error.message)); else response.destroy();
    }
  });
  return { server, host, port, listen: () => new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => resolve(server.address())); }), close: () => new Promise((resolve) => server.close(() => resolve())) };
}

function hasCompactionTrigger(value) {
  return Array.isArray(value) && value.some((item) => item && typeof item === "object" && item.type === "compaction_trigger");
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function parseUsdc(value) {
  const text = String(value || "").trim();
  if (!/^\d+(?:\.\d{1,6})?$/.test(text)) throw new Error("enter a valid positive top-up amount");
  const [whole, fraction = ""] = text.split(".");
  const amount = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, "0"));
  if (amount <= 0n) throw new Error("enter a valid positive top-up amount");
  return amount;
}

function contractData(signature, args) {
  return `0x${bytesToHex(keccak_256(Buffer.from(signature, "ascii")).slice(0, 4))}${args.map((arg) => abiWord(arg).toString("hex")).join("")}`;
}

function normalizedResponse(payload) {
  const response = JSON.parse(JSON.stringify(payload || {}));
  response.id = String(response.id || response.request_id || `resp_${bytesToHex(randomBytes(16))}`);
  response.object ||= "response";
  response.created_at ||= Math.floor(Date.now() / 1000);
  response.status = ["completed", "failed", "incomplete", "cancelled"].includes(String(response.status || "completed")) ? String(response.status || "completed") : "completed";
  response.output = Array.isArray(response.output) ? response.output.filter((item) => item && typeof item === "object").map(normalizedItem) : [];
  response.error ??= null;
  response.incomplete_details ??= null;
  if (typeof response.output_text !== "string") response.output_text = response.output.filter((item) => item.type === "message").flatMap((item) => item.content || []).filter((part) => part.type === "output_text").map((part) => String(part.text || "")).join("");
  return response;
}

function normalizedItem(raw) {
  const item = JSON.parse(JSON.stringify(raw));
  item.type = String(item.type || "unknown");
  const prefix = { message: "msg", reasoning: "rs", function_call: "fc", custom_tool_call: "ct", web_search_call: "ws", file_search_call: "fs", code_interpreter_call: "ci", mcp_call: "mcp", mcp_tool_call: "mcp" }[item.type] || "item";
  item.id = String(item.id || `${prefix}_${bytesToHex(randomBytes(16))}`);
  if (item.type === "message") { item.role = String(item.role || "assistant"); item.content = Array.isArray(item.content) ? item.content.map((part) => ({ ...part, type: String(part.type || "output_text"), ...(part.type === "output_text" ? { text: String(part.text || ""), annotations: part.annotations || [], logprobs: part.logprobs || [] } : {}) })) : []; item.status ||= "completed"; }
  if (item.type === "reasoning") { item.summary = Array.isArray(item.summary) ? item.summary : []; item.status ||= "completed"; }
  if (item.type === "function_call") { item.call_id = String(item.call_id || ""); item.name = String(item.name || ""); item.arguments = String(item.arguments || ""); item.status ||= "completed"; }
  return item;
}

function responseEvents(payload, compact = false) {
  const final = normalizedResponse(payload);
  let sequence = 0;
  const events = [];
  const event = (type, fields = {}) => events.push({ type, sequence_number: sequence++, ...fields });
  if (compact) { final.output.forEach((item, index) => event("response.output_item.done", { output_index: index, item })); event(terminalEvent(final), { response: final }); return events; }
  const created = { ...final, status: "in_progress", output: [], output_text: "", error: null, incomplete_details: null, usage: null };
  event("response.created", { response: created }); event("response.in_progress", { response: created });
  final.output.forEach((item, outputIndex) => {
    const added = { ...item, status: "in_progress" }; if (item.type === "message") added.content = []; if (item.type === "function_call") added.arguments = "";
    event("response.output_item.added", { output_index: outputIndex, item: added });
    if (item.type === "message") {
      (item.content || []).forEach((part, contentIndex) => {
        const partAdded = { ...part }; if (partAdded.type === "output_text") partAdded.text = "";
        event("response.content_part.added", { item_id: item.id, output_index: outputIndex, content_index: contentIndex, part: partAdded });
        if (part.type === "output_text") { const text = String(part.text || ""); if (text) event("response.output_text.delta", { item_id: item.id, output_index: outputIndex, content_index: contentIndex, delta: text, logprobs: part.logprobs || [] }); event("response.output_text.done", { item_id: item.id, output_index: outputIndex, content_index: contentIndex, text, logprobs: part.logprobs || [] }); }
        if (part.type === "refusal") { const refusal = String(part.refusal || ""); if (refusal) event("response.refusal.delta", { item_id: item.id, output_index: outputIndex, content_index: contentIndex, delta: refusal }); event("response.refusal.done", { item_id: item.id, output_index: outputIndex, content_index: contentIndex, refusal }); }
        event("response.content_part.done", { item_id: item.id, output_index: outputIndex, content_index: contentIndex, part });
      });
    } else if (item.type === "reasoning") {
      (item.summary || []).forEach((part, summaryIndex) => { const text = String(part.text || ""); event("response.reasoning_summary_part.added", { item_id: item.id, output_index: outputIndex, summary_index: summaryIndex, part: { ...part, type: "summary_text", text: "" } }); if (text) event("response.reasoning_summary_text.delta", { item_id: item.id, output_index: outputIndex, summary_index: summaryIndex, delta: text }); event("response.reasoning_summary_text.done", { item_id: item.id, output_index: outputIndex, summary_index: summaryIndex, text }); event("response.reasoning_summary_part.done", { item_id: item.id, output_index: outputIndex, summary_index: summaryIndex, part }); });
    } else if (item.type === "function_call") {
      if (item.arguments) event("response.function_call_arguments.delta", { item_id: item.id, output_index: outputIndex, delta: item.arguments });
      event("response.function_call_arguments.done", { item_id: item.id, output_index: outputIndex, call_id: item.call_id, name: item.name, arguments: item.arguments });
    }
    event("response.output_item.done", { output_index: outputIndex, item });
  });
  event(terminalEvent(final), { response: final });
  return events;
}

function terminalEvent(response) {
  return { completed: "response.completed", failed: "response.failed", incomplete: "response.incomplete", cancelled: "response.incomplete" }[response.status] || "response.completed";
}

export function responseSse(payload, compact = false) {
  return responseEvents(payload, compact).map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
}

export function chatCompletionSse(payload, includeUsage = false) {
  const id = String(payload?.id || `chatcmpl_${bytesToHex(randomBytes(16))}`); const model = String(payload?.model || ""); const created = Number(payload?.created || Math.floor(Date.now() / 1000)); const chunks = [];
  const chunk = (index, delta, finishReason = null) => chunks.push(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created, model, choices: [{ index, delta, finish_reason: finishReason }] })}\n\n`);
  (Array.isArray(payload?.choices) ? payload.choices : []).forEach((choice, fallbackIndex) => {
    const index = Number.isInteger(choice.index) ? choice.index : fallbackIndex;
    const message = choice.message || {};
    chunk(index, { role: String(message.role || "assistant") });
    if (message.content) chunk(index, { content: String(message.content) });
    (Array.isArray(message.tool_calls) ? message.tool_calls : []).forEach((call, toolIndex) => {
      chunk(index, { tool_calls: [{ index: toolIndex, id: call.id, type: call.type || "function", function: { name: call.function?.name, arguments: String(call.function?.arguments || "") } }] });
    });
    chunk(index, {}, choice.finish_reason || "stop");
  });
  if (includeUsage && payload?.usage) chunks.push(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created, model, choices: [], usage: payload.usage })}\n\n`);
  chunks.push("data: [DONE]\n\n"); return chunks;
}

function consumerHtml() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light">
<title>Consumer | MycoMesh</title>
<style>
:root{--ink:#17211d;--muted:#68736e;--line:#d8dfdb;--soft:#f2f5f3;--paper:#fff;--green:#147553;--green-dark:#0d5b40;--amber:#9a6413;--red:#ae3d38;--blue:#365d86}*{box-sizing:border-box}[hidden]{display:none!important}html{background:#edf1ee}body{min-width:320px;margin:0;color:var(--ink);background:#edf1ee;font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}button,input,select{font:inherit;letter-spacing:0}button{cursor:pointer}.shell{min-height:100vh}.topbar{position:sticky;z-index:10;top:0;display:flex;min-height:60px;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);background:rgba(255,255,255,.97);padding:0 max(18px,env(safe-area-inset-left))}.brand{display:flex;align-items:center;gap:10px;font-weight:780}.mark{display:grid;width:30px;height:30px;place-items:center;border-radius:6px;background:var(--ink);color:#fff;font-size:12px}.network{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px}.dot{width:7px;height:7px;border-radius:50%;background:#9ba49f}.dot.ok{background:var(--green)}.workspace{width:min(760px,100%);margin:0 auto;background:var(--paper);min-height:calc(100vh - 60px)}.locked{display:grid;min-height:calc(100vh - 60px);align-content:center;padding:42px 24px 88px}.locked-inner{width:min(420px,100%);margin:0 auto}.locked-badge{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:5px 10px;color:var(--muted);font-size:12px}.locked h1{margin:20px 0 9px;font-size:30px;line-height:1.16}.locked p{margin:0 0 26px;color:var(--muted)}.key-preview{border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:14px 0;margin:0 0 22px}.label{display:block;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.key-preview .mono{display:block;margin-top:5px;font-size:12px}.button{display:inline-flex;min-height:42px;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:6px;background:var(--paper);padding:0 15px;color:var(--ink);font-weight:700}.button:hover{border-color:#95a39b;background:#f8faf9}.button.primary{border-color:var(--green);background:var(--green);color:#fff}.button.primary:hover{background:var(--green-dark)}.button.danger{border-color:#e5b6b3;color:var(--red)}.button.small{min-height:34px;padding:0 11px;font-size:12px}.button:disabled{cursor:not-allowed;opacity:.52}.locked .button{width:100%;min-height:48px}.app-head{padding:24px 20px 17px}.app-head-row{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.app-head h1{margin:0;font-size:22px}.wallet-button{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.balance{margin-top:22px}.balance strong{display:block;margin-top:4px;font-size:31px;font-weight:760}.balance-meta{display:flex;gap:16px;margin-top:8px;color:var(--muted);font-size:12px}.tabs{position:sticky;z-index:8;top:60px;display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:rgba(255,255,255,.97);padding:0 12px}.tab{min-width:0;border:0;border-bottom:2px solid transparent;background:transparent;padding:12px 4px;color:var(--muted);font-weight:650}.tab.active{border-color:var(--green);color:var(--ink)}.view{padding:2px 20px 84px}.band{border-top:1px solid var(--line);padding:23px 0}.band:first-child{border-top:0}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.section-head h2{margin:0;font-size:16px}.section-head p{margin:3px 0 0;color:var(--muted);font-size:12px}.status{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:11px;white-space:nowrap}.status:before{width:6px;height:6px;border-radius:50%;background:var(--amber);content:""}.status.ok:before{background:var(--green)}.field+.field{margin-top:13px}.field-row{display:flex;align-items:stretch;gap:7px;margin-top:6px}.value{min-width:0;flex:1;border:1px solid var(--line);border-radius:5px;background:var(--soft);padding:10px 11px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.value.exports{min-height:76px;white-space:pre-wrap}.metrics{display:grid;grid-template-columns:repeat(3,1fr);border:1px solid var(--line);border-radius:6px;overflow:hidden}.metric{min-width:0;padding:14px 10px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span{display:block;color:var(--muted);font-size:11px}.metric strong{display:block;overflow:hidden;margin-top:4px;font-size:17px;text-overflow:ellipsis}.list{margin:0}.list div{display:grid;grid-template-columns:104px minmax(0,1fr);gap:12px;border-bottom:1px solid var(--line);padding:12px 0}.list div:last-child{border-bottom:0}.list dt{color:var(--muted)}.list dd{overflow:hidden;margin:0;text-align:right;text-overflow:ellipsis;white-space:nowrap}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.topup{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}.input,.select{width:100%;min-height:42px;border:1px solid var(--line);border-radius:5px;background:#fff;padding:8px 10px;color:var(--ink)}.input:focus,.select:focus{border-color:var(--green);outline:2px solid rgba(20,117,83,.13)}.share-output{margin-top:16px}.empty{padding:34px 0;color:var(--muted);text-align:center}.table-wrap{overflow-x:auto;border-top:1px solid var(--line)}table{width:100%;min-width:620px;border-collapse:collapse}th,td{padding:11px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:12px}th{color:var(--muted);font-weight:650}.notice{border-left:3px solid var(--amber);background:#fff8e9;padding:10px 12px;color:#76511c;font-size:12px}.notice.error{border-color:var(--red);background:#fff3f2;color:#892f2b}.recovery{display:flex;align-items:center;justify-content:space-between;gap:12px}.recovery span{flex:1}.toast{position:fixed;z-index:30;right:16px;bottom:calc(18px + env(safe-area-inset-bottom));left:16px;max-width:520px;margin:auto;border-radius:6px;background:var(--ink);padding:11px 14px;color:#fff;box-shadow:0 10px 30px rgba(23,33,29,.2);text-align:center}.toast.error{background:#7e2925}@media(min-width:761px){body{padding:22px}.shell{border:1px solid var(--line);border-radius:8px;overflow:hidden;box-shadow:0 18px 50px rgba(23,33,29,.08)}.workspace{min-height:calc(100vh - 106px)}.topbar{position:relative}.tabs{top:0}.view,.app-head{padding-right:28px;padding-left:28px}.toast{bottom:28px}}@media(max-width:420px){.balance strong{font-size:27px}.metrics{grid-template-columns:1fr}.metric{display:flex;align-items:center;justify-content:space-between;border-right:0;border-bottom:1px solid var(--line)}.metric:last-child{border-bottom:0}.metric strong{margin:0}.field-row{flex-direction:column}.field-row .button{width:100%}.topup{grid-template-columns:1fr}.topup .button{width:100%}}
</style></head><body>
<div class="shell"><header class="topbar"><div class="brand"><span class="mark">M</span><span>MycoMesh</span></div><div class="network"><span id="networkDot" class="dot"></span><span id="networkName">MycoMesh</span></div></header><main class="workspace">
<div id="locked" class="locked"><div class="locked-inner"><span class="locked-badge">MycoMesh API</span><h1>连接钱包以继续</h1><p>连接钱包后获取 API 地址和访问密钥。无需填写钱包私钥。</p><p>请在已安装钱包扩展的浏览器中打开此本机地址；未安装钱包时可先安装，再刷新连接。</p><p id="loginOwnerHint" class="notice mono" aria-live="polite">正在核对本机付款 Key 的归属…</p><details class="key-preview"><summary>设备访问凭证详情</summary><span id="lockedKey" class="mono">读取中...</span></details><button id="login" class="button primary" type="button">连接钱包并签名</button><p id="loginError" class="notice error mono" role="alert" hidden></p></div></div>
<div id="app" hidden><div class="app-head"><div class="app-head-row"><div><span class="label">预付账户</span><h1>Consumer</h1></div><button id="walletButton" class="button small wallet-button" type="button">退出</button></div><div class="balance"><span id="balanceLabel" class="label">可用余额</span><strong id="balance">--</strong><div class="balance-meta"><span id="keyStatus">Key 状态 --</span><span id="requestCount">0 次请求</span></div></div></div>
<nav class="tabs" aria-label="Consumer navigation"><button class="tab active" data-view="overview" type="button">概览</button><button class="tab" data-view="wallet" type="button">钱包</button><button class="tab" data-view="activity" type="button">记录</button><button class="tab" data-view="share" type="button">分享</button></nav>
<div id="view-overview" class="view"><div class="band"><div class="section-head"><div><h2>访问凭证</h2><p id="credentialState">等待 Key 激活</p></div><span id="credentialBadge" class="status">锁定</span></div><div id="credentials" hidden><div class="field"><span class="label">API URL</span><div class="field-row"><div id="url" class="value"></div><button class="button small copy" data-copy="url" type="button">复制</button></div></div><div class="field"><span class="label">Key</span><div class="field-row"><div id="key" class="value"></div><button class="button small copy" data-copy="key" type="button">复制</button></div></div><div class="field"><span class="label">Export</span><div class="field-row"><div id="export" class="value exports"></div><button class="button small copy" data-copy="export" type="button">复制</button></div></div></div><div id="inactiveKey" class="notice"><span id="activationNotice">首次使用需在钱包中确认一次访问授权。</span><div class="actions"><button id="setupAccess" class="button primary" type="button">启用 API 访问</button></div></div></div><div class="band"><div class="section-head"><div><h2>网络与模型</h2><p>只显示通过部署校验的可用 Relay 路由</p></div><span id="modelStatus" class="status">读取中</span></div><dl id="modelList" class="list"><div><dt>模型目录</dt><dd>正在读取…</dd></div></dl><p id="modelError" class="notice error" hidden></p></div><div class="band"><div class="section-head"><h2>本地用量</h2></div><div class="metrics"><div class="metric"><span>累计消费</span><strong id="spent">--</strong></div><div class="metric"><span>输入 Tokens</span><strong id="inputTokens">0</strong></div><div class="metric"><span>输出 Tokens</span><strong id="outputTokens">0</strong></div></div></div></div>
<div id="view-wallet" class="view" hidden><div id="budgetPanel" class="band" hidden><div class="section-head"><h2>固定预算</h2><span id="budgetLocked" class="status"></span></div><p id="budgetNote" class="notice"></p><p id="budgetUnallocated" class="notice"></p><p class="notice">充值余额需开通固定预算后才能调用；充值不等于已有可调用预算。</p><p id="budgetReadiness" class="notice"></p><div id="budgetChannels"></div></div><div class="band"><div class="section-head"><h2>钱包与 Key</h2><span id="chainStatus" class="status">读取中</span></div><dl class="list"><div><dt>钱包</dt><dd id="walletAddress" class="mono"></dd></div><div><dt>Key 地址</dt><dd id="keyAddress" class="mono"></dd></div><div><dt>单次上限</dt><dd id="keyLimit"></dd></div><div><dt>有效期</dt><dd id="keyValidity"></dd></div></dl><p id="chainError" class="notice error" hidden></p><div class="actions"><button id="activate" class="button primary" type="button">激活 Key</button><button id="rotate" class="button danger" type="button" hidden>更换 Key</button></div></div><div class="band"><div class="section-head"><div><h2>充值</h2><p id="walletBalance">钱包余额 --</p></div></div><div class="topup"><input id="amount" class="input" type="number" min="0.000001" step="0.000001" inputmode="decimal" autocomplete="off" placeholder="10.00 USDC" aria-label="充值金额（USDC）"><button id="topup" class="button primary" type="button">充值</button></div></div></div>
<div id="view-activity" class="view" hidden><div class="band"><div class="section-head"><div><h2>消费记录</h2><p>当前 Key 在本机各 Consumer 的账单，按请求去重</p></div><button id="refresh" class="button small" type="button">刷新</button></div><p id="historySync" class="notice" hidden></p><div id="historyRecovery" class="notice error recovery" hidden><span id="historyRecoveryText"></span><button id="historyRecoveryButton" class="button small" type="button">立即核验</button></div><div id="historyEmpty" class="empty">暂无消费记录</div><div id="historyTable" class="table-wrap" hidden><table><thead><tr><th>时间</th><th>模型</th><th>Tokens</th><th>费用</th><th>Provider</th><th>状态</th><th>会话</th></tr></thead><tbody id="history"></tbody></table></div></div></div>
<div id="view-share" class="view" hidden><div class="band"><div class="section-head"><div><h2>临时分享</h2><p>到期后自动关闭</p></div><span id="shareStatus" class="status">未启用</span></div><div class="topup"><select id="shareMinutes" class="select"><option value="10">10 分钟</option><option value="30" selected>30 分钟</option><option value="60">1 小时</option><option value="360">6 小时</option></select><button id="shareStart" class="button primary" type="button">开始分享</button></div><div id="shareOutput" class="share-output" hidden><div class="field"><span class="label">API URL</span><div class="field-row"><div id="shareUrl" class="value"></div><button class="button small copy" data-copy="shareUrl" type="button">复制</button></div></div><div class="field"><span class="label">临时 Key</span><div class="field-row"><div id="shareKey" class="value"></div><button class="button small copy" data-copy="shareKey" type="button">复制</button></div></div><p id="shareExpiry" class="notice"></p><div class="actions"><button id="shareStop" class="button danger" type="button">停止分享</button></div></div></div></div></div>
</main></div><div id="toast" class="toast" hidden></div>
<script>
let state=null,wallet=null,managementToken=null,busy=false,loading=null;const $=id=>document.getElementById(id);const short=value=>value?value.slice(0,6)+'...'+value.slice(-4):'--';
function units(value,decimals=6){const raw=BigInt(value||0),base=10n**BigInt(decimals),whole=raw/base,fraction=(raw%base).toString().padStart(decimals,'0').replace(/0+$/,'');return whole.toLocaleString()+(fraction?'.'+fraction.slice(0,Math.max(6,Math.min(decimals,8))):'')}
function authHeaders(headers={}){const next=new Headers(headers);if(managementToken)next.set('authorization','Bearer '+managementToken);return next}
async function api(path,options={}){const response=await fetch(path,{...options,headers:authHeaders(options.headers)}),data=await response.json();if(!response.ok){const error=new Error(typeof data.error==='string'?data.error:(data.error?.message||'请求失败'));for(const field of ['code','selected_wallet','expected_owner','payment_key_address'])if(typeof data[field]==='string')error[field]=data[field];if(error.code==='payment_key_owner_mismatch')error.message=ownerMismatchMessage(error);if(error.code==='wallet_verification_unavailable')error.message='暂时无法核验链上钱包归属或预算，请稍后重试。现有 Key、账单和已登录会话保持不变。';throw error}return data}
function toast(message,error=false){const node=$('toast');node.textContent=message;node.className='toast'+(error?' error':'');node.hidden=false;clearTimeout(toast.timer);toast.timer=setTimeout(()=>node.hidden=true,3200)}
function setBusy(value){busy=value;for(const button of document.querySelectorAll('button'))button.disabled=value}
async function run(task){if(busy)return;setBusy(true);try{await task()}catch(error){const message=error?.message||String(error);if(!managementToken){$('loginError').textContent=message;$('loginError').hidden=false}toast(message,true)}finally{setBusy(false)}}
async function load(){if(loading)return loading;loading=(async()=>{state=await api('/v1/mycomesh/local/dashboard');render()})();try{await loading}finally{loading=null}}
function render(){const authenticated=Boolean(managementToken&&state.auth?.authenticated),ready=authenticated&&state.auth.key_ready,grant=state.key.grant||{},decimals=state.settlement?.stablecoin_decimals||6,symbol=state.settlement?.stablecoin_symbol||'USDC';$('networkName').textContent=state.chain_error?'链上不可用':(state.settlement?.network_name||'MycoMesh');$('networkDot').className='dot'+(state.inference_ready===true&&!state.chain_error?' ok':'');$('lockedKey').textContent=state.key.address;renderLoginOwner();$('locked').hidden=authenticated;$('app').hidden=!authenticated;if(!authenticated)return;$('walletButton').textContent=short(state.auth.wallet);$('walletAddress').textContent=state.auth.wallet;$('keyAddress').textContent=state.key.address;$('balanceLabel').textContent=state.protocol_version===10?'可用请求预算':'可用余额';$('balance').textContent=state.protocol_version===10?units(state.budget_available_units||0,decimals)+' '+symbol:(state.account?units(state.account.available_balance_units,decimals)+' '+symbol:'--');$('requestCount').textContent=state.usage.request_count+' 次请求';$('keyStatus').textContent=ready?'Key 已激活':'Key 待激活';$('credentialBadge').className='status'+(ready?' ok':'');$('credentialBadge').textContent=ready?'可用':'待激活';$('credentialState').textContent=ready?'仅在本机显示':'链上确认后显示';$('credentials').hidden=!ready;$('inactiveKey').hidden=ready;if(ready){$('url').textContent=state.credentials.base_url;$('key').textContent=state.credentials.api_key;$('export').textContent=state.credentials.export}$('spent').textContent=units(state.usage.total_spent_units,decimals)+' '+symbol;$('inputTokens').textContent=Number(state.usage.input_tokens||0).toLocaleString();$('outputTokens').textContent=Number(state.usage.output_tokens||0).toLocaleString();$('keyLimit').textContent=grant.max_per_request?units(grant.max_per_request,decimals)+' '+symbol:'--';$('keyValidity').textContent=grant.valid_until?new Date(grant.valid_until*1000).toLocaleString():'长期有效';$('chainStatus').className='status'+(grant.active?' ok':'');$('chainStatus').textContent=grant.active?'链上有效':'等待激活';$('activate').hidden=ready;$('rotate').hidden=!ready;$('chainError').hidden=!state.chain_error;$('chainError').textContent=state.chain_error||'';$('walletBalance').textContent=state.wallet?'钱包余额 '+units(state.wallet.token_balance_units,decimals)+' '+symbol:'钱包余额 --';renderActivation();renderHistory();renderShare();renderBudget()}
function renderActivation(){
  const grant=state.key.grant||{},ownedActive=grant.active===true&&grant.owner===state.auth?.wallet&&!state.key.pending;
  const exact=ownedActive&&grant.max_per_request===state.key.max_fee_units&&grant.valid_until===0;
  $('activate').textContent=ownedActive?'启用本地访问':'激活 Key';
  $('setupAccess').textContent=ownedActive?'启用本地访问':'启用 API 访问';
  $('activationNotice').textContent=exact?'链上授权已生效。启用此设备的本地访问后即可显示 API 凭证；可调用额度以账户预算为准。':ownedActive?'链上 Key 已生效，启用时将同步访问权限设置。':'首次使用需在钱包中确认一次访问授权。';
}
function renderBudget(){
  const panel=$('budgetPanel');panel.hidden=state.protocol_version!==10;if(panel.hidden)return;
  const decimals=state.settlement?.stablecoin_decimals||6,symbol=state.settlement?.stablecoin_symbol||'TestUSDC',now=Math.floor(Date.now()/1000);
  $('budgetLocked').textContent='可用 '+units(state.budget_available_units||0,decimals)+' '+symbol+' · 预算池 '+units(state.budget_locked_units||0,decimals)+' '+symbol;
  $('budgetNote').textContent=state.budget_note||'预算在结算窗口结束前不会撤回；结算按 2 小时或 100 笔先到触发。';
  const ownAccount=state.account&&state.account.owner===state.auth?.wallet;
  $('budgetUnallocated').textContent='已充值、尚未分配预算：'+(ownAccount?units(state.account.available_balance_units,decimals)+' '+symbol:'--');
  $('budgetReadiness').textContent=state.inference_ready?'预算与线路就绪 · 满 2 小时或 100 笔批量结算':state.inference_code==='budget_not_started'?'预算等待启用 · '+new Date(state.budget_available_at*1000).toLocaleString()+'；启用前不会派发或扣费':state.inference_code==='budget_unavailable'?'当前没有可用固定预算，无法派发请求；不会扣费。请联系运营方续期开通预算后刷新本页':(state.inference_error||'正在确认预算和可用线路');
  const list=$('budgetChannels');list.replaceChildren();
  const channels=state.capacity_channels||[];
  if(!channels.length){list.textContent='尚未开通固定预算。受控测试期间，由运营方与 Provider 确认预算后开通。';return}
  for(const c of channels){
    const box=document.createElement('div');box.className='band';
    const title=document.createElement('strong');title.textContent='Provider '+short(c.provider_signer);box.appendChild(title);
    const info=document.createElement('p');const budget=c.budget||{};
    const phase=({closed:'已释放',releasable:'可释放余额',previous_key:'此前 Key 的预算',different_owner:'属于其他钱包',admission_closed:'已停止新请求，等待结算',admission_window_short:'剩余接单时间不足',claim_window_short:'剩余结算时间不足',request_limit:'单次请求上限超过预算限制',capacity_exhausted:'请求额度已用完',credit_insufficient:'预算余额不足',stake_insufficient:'Provider 线路暂不可用',not_started:'等待启用，约 '+Math.max(0,Math.ceil((c.valid_from-now)/60))+' 分钟',available:'预算可用'})[budget.reason]||'预算待核验';
    info.textContent=phase+' · 当前可用 '+units(budget.remaining_units||0,decimals)+' '+symbol+(budget.ready?' · 预计还可请求 '+budget.estimated_requests+' 次':'')+' · 最早释放 '+new Date(c.claim_until*1000).toLocaleString();box.appendChild(info);
    if(!c.closed&&now>c.claim_until){const button=document.createElement('button');button.className='button';button.textContent='释放剩余预算';button.onclick=()=>run(async()=>{const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'close_capacity_channel',wallet,channel_id:c.channel_id})});await sendPlan(plan);await load();toast('预算释放交易已确认')});box.appendChild(button)}
    list.appendChild(box)
  }
}
function renderHistory(){
  const body=$('history'),items=state.history||[],decimals=state.settlement?.stablecoin_decimals||6,symbol=state.settlement?.stablecoin_symbol||'USDC';
  body.replaceChildren();$('historyEmpty').hidden=items.length>0;$('historyTable').hidden=items.length===0;
  $('spent').previousElementSibling.textContent='已结算消费';$('spent').textContent=units(state.usage.settled_units||0,decimals)+' '+symbol;
  const sync=state.history_sync||{},summary='已结算 '+units(state.usage.settled_units||0,decimals)+' · 已知待结算 '+units(state.usage.pending_units||0,decimals)+' · 结算失败 '+units(state.usage.failed_units||0,decimals)+' '+symbol+(state.usage.unknown_fee_count?' · 费用待核实 '+state.usage.unknown_fee_count+' 笔，授权上限 '+units(state.usage.unknown_fee_authorized_maximum_units,decimals)+' '+symbol:'');
  $('historySync').hidden=false;$('historySync').textContent=summary+(sync.error?' — '+sync.error:(sync.running?' — 正在同步结算状态…':''));
  const unknown=items.filter(item=>['dispatching','outcome_unknown','broadcast_unknown'].includes(item.status)||['broadcast_unknown','confirmation_timeout'].includes(item.error_code));
  const recovery=$('historyRecovery');recovery.hidden=unknown.length===0&&!sync.error;
  if(unknown.length){const ids=unknown.slice(0,3).map(item=>short(item.request_id)).join('、');$('historyRecoveryText').textContent='有 '+unknown.length+' 笔请求的执行或付款状态尚未核实（'+ids+(unknown.length>3?' 等':'')+'）。请勿重复提交相同请求；先核验状态，系统只会在链上或 Relay 返回可验证结果后更新账单。'}
  else if(sync.error)$('historyRecoveryText').textContent='账单状态暂时无法核验，原记录已保留。请重试“立即核验”；在状态明确前不要重复提交相同请求。';
  for(const item of items){
    const row=document.createElement('tr'),status=({dispatching:'已发送，结果待核实',outcome_unknown:'结果待核实，请勿重复提交',not_dispatched:'未执行',escrowed:'已托管，争议期内',disputed:'裁决中',released:'已释放',refunded:'已退回余额',dismissed:'举报驳回，已释放',timed_out:'裁决超时，已释放'})[item.status]||(item.status==='confirmed'?'已结算':item.status==='failed'?(item.error_code==='authorization_expired'?'授权过期，未结算':'结算失败'):item.status==='rejected'?'未接受':(item.status==='broadcast_unknown'||item.error_code==='broadcast_unknown'||item.error_code==='confirmation_timeout')?'结果待核实':item.status==='submitted'?'已提交，待确认':'待结算');
    for(const value of [new Date(item.timestamp*1000).toLocaleString(),item.model||'--',(item.input_tokens??'--')+' / '+(item.output_tokens??'--'),item.actual_fee_units==null?'--':units(item.actual_fee_units,decimals),short(item.provider_signer||item.provider),(item.content_verification==='failed'?'正文核验失败；':'')+status,short(item.session_id)]){
      const cell=document.createElement('td');cell.textContent=value;row.appendChild(cell)
    }
    body.appendChild(row)
  }
}
function renderShare(){const share=state.share||{};$('shareStatus').className='status'+(share.active?' ok':'');$('shareStatus').textContent=share.active?'分享中':'未启用';$('shareOutput').hidden=!share.active;if(share.active){$('shareUrl').textContent=share.base_url;$('shareKey').textContent=share.api_key;$('shareExpiry').textContent='到期时间 '+new Date(share.expires_at*1000).toLocaleString()}}
function renderModels(items){const list=$('modelList'),status=$('modelStatus'),error=$('modelError');list.replaceChildren();error.hidden=true;if(!Array.isArray(items)||!items.length){status.className='status';status.textContent='暂无可用模型';list.innerHTML='<div><dt>模型目录</dt><dd>暂无通过校验的 Relay 路由</dd></div>';return}const single=items.filter(item=>Number(item.route_count||0)<2);status.className='status'+(single.length?'':' ok');status.textContent=single.length?(items.length+' 个模型 · '+single.length+' 个单 Relay'):(items.length+' 个模型 · 已冗余');for(const item of items){const row=document.createElement('div'),name=document.createElement('dt'),value=document.createElement('dd');name.textContent=String(item.id||'未知模型');value.textContent=Number(item.route_count||0)>1?('双 Relay · '+item.route_count+' 条路由'):'单 Relay · 无自动故障切换';row.append(name,value);list.appendChild(row)}}
async function loadModels(){try{const response=await fetch('/v1/models',{cache:'no-store'}),data=await response.json();if(!response.ok)throw new Error(data?.error?.message||'模型目录暂时不可用');renderModels(data.data)}catch(error){$('modelStatus').className='status';$('modelStatus').textContent='读取失败';$('modelError').hidden=false;$('modelError').textContent=error?.message||'模型目录暂时不可用'}}
async function syncHistoryNow(){await api('/v1/mycomesh/local/history/sync',{method:'POST'});await load();const sync=state.history_sync||{};toast(sync.error?'暂时无法完成状态核验，原记录已保留':'已完成状态核验')}
function walletMessage(value){return '0x'+Array.from(new TextEncoder().encode(value),byte=>byte.toString(16).padStart(2,'0')).join('')}
function walletProvider(){return window.okxwallet?.ethereum||window.okxwallet||window.ethereum?.providers?.find(p=>p.isOkxWallet||p.isOKExWallet)||window.ethereum}
function ownerMismatchMessage(value){return '当前选择的钱包：'+value.selected_wallet+'。本机付款 Key（'+value.payment_key_address+'）已绑定钱包：'+value.expected_owner+'。请在钱包扩展中切换到该归属钱包后重试；若要使用当前钱包，请另建独立 Consumer 配置目录。不要删除或更换现有 Key，原账单和预算仍属于原钱包。'}
function renderLoginOwner(){const owner=state?.key?.grant?.owner,hint=$('loginOwnerHint');hint.textContent=!owner?'暂时无法核验本机付款 Key 的归属，请稍后重试连接。':owner.toLowerCase()==='0x'+'0'.repeat(40)?'本机付款 Key 尚未绑定钱包，可连接你的钱包完成登录，再激活访问。':'本机付款 Key 已绑定钱包：'+owner+'。请在钱包扩展中选择该账户。若要使用其他钱包，请另建独立 Consumer 配置目录，保留原 Key 和账单。'}
async function login(){
  $('loginError').hidden=true;
  const provider=walletProvider();if(!provider)throw new Error('未检测到浏览器钱包，请安装钱包扩展后刷新，或在已安装钱包的浏览器中打开此本机地址');
  await load();
  const owner=state?.key?.grant?.owner?.toLowerCase();
  if(!owner)throw new Error('暂时无法核验本机付款 Key 的链上归属，请稍后重试；本次尚未请求签名。');
  const accounts=await provider.request({method:'eth_requestAccounts'}),selectedWallet=String(accounts[0]||'').toLowerCase();
  if(!selectedWallet)throw new Error('钱包未连接');
  if(owner!=='0x'+'0'.repeat(40)&&owner!==selectedWallet)throw Object.assign(new Error(ownerMismatchMessage({selected_wallet:selectedWallet,expected_owner:owner,payment_key_address:state.key.address})),{code:'payment_key_owner_mismatch'});
  const challenge=await api('/v1/mycomesh/local/wallet/challenge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({wallet:selectedWallet})});
  const signature=await provider.request({method:'personal_sign',params:[walletMessage(challenge.message),selectedWallet]});
  const result=await api('/v1/mycomesh/local/wallet/authenticate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({wallet:selectedWallet,signature})});
  managementToken=result.token;wallet=selectedWallet;await load();toast(state.auth.key_ready?'钱包验证完成':'首次使用：点击“启用 API 访问”，并在钱包中确认');
}
async function ensureChain(){const provider=walletProvider();if(!provider)throw new Error('未检测到浏览器钱包，请安装钱包扩展后刷新，或在已安装钱包的浏览器中打开此本机地址');const expected='0x'+Number(state.settlement.chain_id).toString(16),current=await provider.request({method:'eth_chainId'});if(current.toLowerCase()!==expected.toLowerCase())await provider.request({method:'wallet_switchEthereumChain',params:[{chainId:expected}]})}
async function waitReceipt(hash){const provider=walletProvider();if(!provider)throw new Error('未检测到浏览器钱包，请安装钱包扩展后刷新，或在已安装钱包的浏览器中打开此本机地址');for(let count=0;count<120;count++){const receipt=await provider.request({method:'eth_getTransactionReceipt',params:[hash]});if(receipt){if(receipt.status!=='0x1')throw new Error('链上交易失败');return receipt}await new Promise(resolve=>setTimeout(resolve,1500))}throw new Error('等待链上确认超时')}
async function sendPlan(plan){if(Array.isArray(plan.transactions)&&plan.transactions.length===0)return;const provider=walletProvider();if(!provider)throw new Error('未检测到浏览器钱包，请安装钱包扩展后刷新，或在已安装钱包的浏览器中打开此本机地址');await ensureChain();for(const transaction of plan.transactions){toast(transaction.label+'：请在钱包中确认');const hash=await provider.request({method:'eth_sendTransaction',params:[{from:wallet,to:transaction.to,data:transaction.data}]});toast(transaction.label+'：交易已提交，等待链上确认…');await waitReceipt(hash);toast(transaction.label+'：已确认')}}
async function activateCurrent(){const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'register_key',wallet})});await sendPlan(plan);for(let count=0;count<10;count++){try{await api('/v1/mycomesh/local/wallet/activate',{method:'POST'});await load();toast('Key 已激活');return}catch(error){if(count===9)throw error;await new Promise(resolve=>setTimeout(resolve,1600))}}}
async function rotateKey(){const oldAddress=state.key.address;await api('/v1/mycomesh/local/key/prepare',{method:'POST'});const register=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'register_key',wallet})});await sendPlan(register);for(let count=0;count<10;count++){try{await api('/v1/mycomesh/local/key/activate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({wallet})});break}catch(error){if(count===9)throw error;await new Promise(resolve=>setTimeout(resolve,1600))}}const revoke=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'revoke_key',wallet,key_address:oldAddress})});await sendPlan(revoke);await load();toast(state.protocol_version===10?'新 Key 已启用；旧通道预算到期后才能释放，新 Key 需另开预算':'新 Key 已启用，旧 Key 已撤销')}
document.querySelectorAll('.tab').forEach(tab=>tab.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(item=>item.classList.toggle('active',item===tab));document.querySelectorAll('.view').forEach(view=>view.hidden=view.id!=='view-'+tab.dataset.view);if(tab.dataset.view==='activity'&&managementToken&&!busy)load().catch(error=>toast(error.message,true))}));
setInterval(()=>{if(managementToken&&!busy&&!document.hidden)load().catch(()=>{})},15000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&managementToken&&!busy)load().catch(()=>{})});
document.addEventListener('click',event=>{const button=event.target.closest('.copy');if(button)navigator.clipboard.writeText($(button.dataset.copy).textContent).then(()=>toast('已复制')).catch(()=>toast('复制失败',true))});
$('setupAccess').onclick=()=>run(activateCurrent);$('login').onclick=()=>run(login);$('activate').onclick=()=>run(activateCurrent);$('rotate').onclick=()=>run(rotateKey);$('refresh').onclick=()=>run(load);$('historyRecoveryButton').onclick=()=>run(syncHistoryNow);
function readTopupAmount(){const value=$('amount').value.trim();if(!/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(value)||Number(value)<=0)throw new Error('请输入大于 0 且最多 6 位小数的 USDC 金额');return value}
$('topup').onclick=()=>run(async()=>{const amount=readTopupAmount();const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'top_up',wallet,amount_usdc:amount})});await sendPlan(plan);$('amount').value='';await load();toast('充值已确认')});
$('shareStart').onclick=()=>run(async()=>{const value=await api('/v1/mycomesh/local/share/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({minutes:Number($('shareMinutes').value)})});state.share=value.share;renderShare();toast('临时分享已开启')});
$('shareStop').onclick=()=>run(async()=>{const value=await api('/v1/mycomesh/local/share/stop',{method:'POST'});state.share=value.share;renderShare();toast('临时分享已停止')});
$('walletButton').onclick=()=>run(async()=>{await api('/v1/mycomesh/local/wallet/lock',{method:'POST'});managementToken=null;wallet=null;await load()});
walletProvider()?.on?.('accountsChanged',()=>{if(managementToken)api('/v1/mycomesh/local/wallet/lock',{method:'POST'}).catch(()=>{}).finally(()=>{managementToken=null;wallet=null;load().catch(error=>toast(error.message,true))})});
load().catch(error=>{$('loginError').hidden=false;$('loginError').textContent=error.message});
loadModels();
</script></body></html>`;
}

export { authorizationStructHash, receiptStructHash, verifyAuthorization, verifySignedReceipt };
