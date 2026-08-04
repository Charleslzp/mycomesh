import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { ProxyAgent } from "undici";

export const DEFAULT_BASE_URL = "http://127.0.0.1:8110/v1";
export const DEFAULT_RELAY_URL = "https://bridge.mycomesh.xyz";
export const DEFAULT_MAX_FEE_UNITS = 100000;
export const DEFAULT_MODEL = "mycomesh-codex-standard-v1";
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
const DOMAIN_TYPE =
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const AUTHORIZATION_TYPE =
  "PaymentAuthorization(bytes32 requestId,bytes32 requestHash,address key,address relay,address relaySigner,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,uint256 maxFee,uint64 issuedAt,uint64 deadline)";
const RECEIPT_TYPE =
  "UsageReceipt(bytes32 authorizationHash,bytes32 responseHash,address provider,address providerSigner,address relay,address pool,uint256 inputTokens,uint256 outputTokens,uint256 actualFee)";
const RETRYABLE_RELAY_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const MAX_AUTHORIZATION_TTL = 3600;
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

const DEFAULT_NETWORK = Object.freeze({
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

function typedDigest(structHash, chainId, contract) {
  const domain = keccak_256(
    Buffer.concat([
      Buffer.from(hashText(DOMAIN_TYPE)),
      Buffer.from(hashText("MycoMesh Settlement")),
      Buffer.from(hashText("8")),
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

function normalizeInferenceOptions(endpoint, options) {
  if (options === undefined || options === null) return null;
  if (typeof options !== "object" || Array.isArray(options)) {
    throw new Error("inference request options must be a JSON object");
  }
  if (endpoint !== "responses") {
    if (Object.keys(options).length) {
      throw new Error("inference request options are supported only for responses");
    }
    return null;
  }
  const allowed = new Set([...RESPONSES_REQUEST_OPTION_FIELDS, ...RESPONSES_LOCAL_OPTION_FIELDS]);
  const unknown = Object.keys(options).filter((key) => !allowed.has(key)).sort();
  if (unknown.length) throw new Error(`unsupported Responses request options: ${unknown.join(", ")}`);
  const normalized = {};
  for (const key of [...RESPONSES_REQUEST_OPTION_FIELDS].sort()) {
    if (Object.prototype.hasOwnProperty.call(options, key)) normalized[key] = options[key];
  }
  return Object.keys(normalized).length ? normalized : null;
}

export function buildAuthorization({
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
}) {
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
  if (expires <= issued || expires - issued > BigInt(MAX_AUTHORIZATION_TTL)) {
    throw new Error("V8 authorization lifetime must be between 1 and 3600 seconds");
  }
  const authorizationHash = authorizationStructHash(authorization);
  const digest = typedDigest(authorizationHash, chainId, settlementContract);
  return {
    schema: AUTH_SCHEMA,
    chain_id: jsonInteger(positiveBigInt(chainId, "chain_id")),
    settlement_contract: nonzeroAddress(settlementContract, "settlement_contract"),
    authorization,
    authorization_hash: authorizationHash,
    authorization_digest: `0x${bytesToHex(digest)}`,
    key_signature: signDigest(paymentKey, digest),
  };
}

function verifyAuthorization(value, expected = {}) {
  if (!value || value.schema !== AUTH_SCHEMA || !value.authorization) {
    throw new Error("unsupported V8 payment authorization");
  }
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
  if (deadline <= issued || deadline - issued > BigInt(MAX_AUTHORIZATION_TTL)) throw new Error("V8 payment authorization lifetime is invalid");
  const structHash = authorizationStructHash(normalized);
  if (normalizeBytes32(value.authorization_hash, "authorization_hash") !== structHash) throw new Error("V8 authorization hash mismatch");
  const digest = typedDigest(structHash, chainId, contract);
  if (normalizeBytes32(value.authorization_digest, "authorization_digest") !== `0x${bytesToHex(digest)}`) throw new Error("V8 authorization digest mismatch");
  if (recoverAddress(digest, value.key_signature) !== normalized.key) throw new Error("V8 payment key signature mismatch");
  return { ...value, chain_id: jsonInteger(chainId), settlement_contract: contract, authorization: normalized };
}

function verifySignedReceipt(value) {
  if (!value || value.schema !== SIGNED_SCHEMA) throw new Error("unsupported signed V8 receipt");
  const authorization = verifyAuthorization(value.authorization);
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
  const digest = typedDigest(receiptStructHash(normalizedReceipt), authorization.chain_id, authorization.settlement_contract);
  if (recoverAddress(digest, value.provider_signature) !== normalizedReceipt.provider_signer) throw new Error("V8 Provider signature mismatch");
  if (recoverAddress(digest, value.relay_signature) !== authorization.authorization.relay_signer) throw new Error("V8 Relay signature mismatch");
  return { authorization, receipt: normalizedReceipt };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  try {
    return await fetch(url, { redirect: "error", ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function readJsonResponse(response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return { error: { message: text.slice(0, 1000), type: "relay_error" } };
  }
}

function openaiError(message, type = "server_error", code = type) {
  return { error: { message: String(message), type, param: null, code } };
}

function parseNetworkConfig(path) {
  if (!path || !existsSync(path)) return { ...DEFAULT_NETWORK };
  try {
    const network = JSON.parse(readFileSync(path, "utf8"));
    const deploymentPath = network.deployment ? join(dirname(path), network.deployment) : path;
    const deployment = network.deployment && existsSync(deploymentPath)
      ? JSON.parse(readFileSync(deploymentPath, "utf8"))
      : network;
    if (Number(deployment.protocol_version || 0) !== 8) return { ...DEFAULT_NETWORK };
    return {
      chain_id: Number(deployment.chain_id),
      network_name: Number(deployment.chain_id) === DEFAULT_CHAIN_ID ? "Sepolia testnet" : "EVM network",
      settlement_contract: normalizeAddress(deployment.settlement),
      stablecoin: normalizeAddress(deployment.stablecoin),
      stablecoin_symbol: "tUSDC",
      stablecoin_decimals: 6,
      rpc_urls: (network.settlement_rpc_urls || [network.settlement_rpc_url]).filter(Boolean),
      explorer_url: Number(deployment.chain_id) === DEFAULT_CHAIN_ID ? "https://sepolia.etherscan.io" : "",
    };
  } catch {
    return { ...DEFAULT_NETWORK };
  }
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
    this.relayUrls = parseRelayUrls(env, options.relayUrls);
    this.maxFeeUnits = options.maxFeeUnits || Number(env.MYCOMESH_V8_MAX_FEE_UNITS || DEFAULT_MAX_FEE_UNITS);
    if (!Number.isSafeInteger(this.maxFeeUnits) || this.maxFeeUnits <= 0) throw new Error("max fee must be a positive integer");
    this.timeoutMs = options.timeoutMs ?? Number(env.MYCOMESH_V8_REQUEST_TIMEOUT_SECONDS || 300) * 1000;
    this.healthTimeoutMs = options.healthTimeoutMs ?? Number(env.MYCOMESH_V8_HEALTH_TIMEOUT_SECONDS || 5) * 1000;
    this.network = parseNetworkConfig(options.networkConfig || env.MYCOMESH_CONSUMER_NETWORK_CONFIG);
    if (env.MYCOMESH_CONSUMER_SETTLEMENT_RPC_URLS) {
      this.network.rpc_urls = String(env.MYCOMESH_CONSUMER_SETTLEMENT_RPC_URLS).split(",").map((item) => item.trim()).filter(Boolean);
    }
    this.proxy = options.proxy || env.MYCOMESH_CONSUMER_PROXY || "";
    this.dispatcher = this.proxy ? new ProxyAgent(this.proxy) : undefined;
    this.healthCache = new Map();
    this.historyPath = join(this.dataDir, "receipt-history.jsonl");
    this.pendingKeyPath = join(this.dataDir, "pending-payment-key");
    this.paymentKeyFromEnv = Boolean(String(env.MYCOMESH_V8_PAYMENT_KEY || "").trim());
    this.paymentKey = this.loadPaymentKey(env.MYCOMESH_V8_PAYMENT_KEY);
    this.paymentAddress = paymentKeyAddress(this.paymentKey);
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

  healthPayload() {
    return {
      ok: true,
      protocol: "mycomesh-consumer/v8",
      runtime: "node-native",
      docker: false,
      browser_app_ready: true,
      gateway_dependency: false,
      routing_mode: "relay-scheduled-payment-key-v8",
      relay_urls: this.relayUrls,
      payment_key_address: this.paymentAddress,
      payment_key_persisted: !this.paymentKeyFromEnv,
      responses_transports: ["http", "sse"],
    };
  }

  history(limit = 100) {
    if (!existsSync(this.historyPath)) return [];
    const lines = readFileSync(this.historyPath, "utf8").split("\n").filter(Boolean);
    const selected = limit <= 0 ? lines : lines.slice(-Math.min(Math.max(limit, 1), 500));
    return selected.map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter((value) => value && typeof value === "object").reverse();
  }

  recordReceipt(relayUrl, endpoint, model, settlement) {
    const signed = settlement?.signed_receipt;
    const receipt = signed?.receipt;
    const auth = signed?.authorization?.authorization;
    if (!receipt || !auth) return;
    const entry = {
      timestamp: Math.floor(Date.now() / 1000),
      request_id: String(auth.request_id || ""),
      settlement_key: String(settlement.settlement_key || ""),
      status: String(settlement.status || "queued"),
      accepted: Boolean(settlement.accepted),
      endpoint,
      model,
      relay_url: relayUrl,
      provider: String(receipt.provider || ""),
      input_tokens: Number(receipt.input_tokens || 0),
      output_tokens: Number(receipt.output_tokens || 0),
      actual_fee_units: Number(receipt.actual_fee || 0),
    };
    appendFileSync(this.historyPath, `${stableStringify(entry)}\n`, { mode: 0o600 });
    try { chmodSync(this.historyPath, 0o600); } catch {}
  }

  async rpcValue(callback) {
    const errors = [];
    for (const rpcUrl of this.network.rpc_urls) {
      try { return await callback(rpcUrl); } catch (error) { errors.push(error.message); }
    }
    throw new Error(`all configured Settlement V8 RPC endpoints failed: ${errors.join("; ")}`);
  }

  async callRpc(rpcUrl, method, params) {
    const response = await fetchWithTimeout(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      dispatcher: this.dispatcher,
    }, this.healthTimeoutMs);
    const payload = await readJsonResponse(response);
    if (!response.ok || payload.error) throw new Error(payload.error?.message || `RPC ${response.status}`);
    return payload.result;
  }

  async contractCall(rpcUrl, contract, signature, args) {
    const data = `0x${bytesToHex(keccak_256(Buffer.from(signature, "ascii")).slice(0, 4))}${args.map((arg) => abiWord(arg).toString("hex")).join("")}`;
    return this.callRpc(rpcUrl, "eth_call", [{ to: normalizeAddress(contract), data }, "latest"]);
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

  async dashboardPayload(wallet) {
    const allHistory = this.history(0);
    const payload = {
      ok: true,
      protocol_version: 8,
      runtime: "node-native",
      credentials: { base_url: this.baseUrl, api_key: this.paymentKey, export: this.credentialsText() },
      key: { address: this.paymentAddress, max_fee_units: this.maxFeeUnits, pending: this.pendingPaymentKey() },
      settlement: this.network,
      history: allHistory.slice(0, 100),
      usage: {
        request_count: allHistory.length,
        total_spent_units: allHistory.reduce((total, item) => total + Number(item.actual_fee_units || 0), 0),
        input_tokens: allHistory.reduce((total, item) => total + Number(item.input_tokens || 0), 0),
        output_tokens: allHistory.reduce((total, item) => total + Number(item.output_tokens || 0), 0),
      },
    };
    try {
      const grant = await this.keyGrant(this.paymentAddress);
      payload.key.grant = grant;
      if (grant.owner !== ZERO_ADDRESS) {
        payload.account = { owner: grant.owner, available_balance_units: await this.accountBalance(grant.owner) };
      }
    } catch (error) {
      payload.chain_error = error.message;
    }
    if (wallet) {
      try {
        const address = normalizeAddress(wallet);
        const token = await this.rpcValue((rpc) => this.contractCall(rpc, this.network.stablecoin, "balanceOf(address)", [address]));
        const allowance = await this.rpcValue((rpc) => this.contractCall(rpc, this.network.stablecoin, "allowance(address,address)", [address, this.network.settlement_contract]));
        payload.wallet = { address, token_balance_units: BigInt(token || "0x0").toString(), allowance_units: BigInt(allowance || "0x0").toString() };
      } catch (error) {
        payload.wallet_error = error.message;
      }
    }
    return payload;
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
    const owner = normalizeAddress(wallet);
    const pending = this.pendingPaymentKey();
    if (!pending) throw new Error("no pending payment key exists");
    const grant = await this.keyGrant(pending.payment_key_address);
    if (!grant.active || grant.owner !== owner) throw new Error("the pending payment key is not active for this wallet on-chain");
    const previous = this.paymentAddress;
    const destination = join(this.dataDir, "payment-key");
    writeFileSync(destination, `${pending.payment_key}\n`, { mode: 0o600 });
    chmodSync(destination, 0o600);
    unlinkSync(this.pendingKeyPath);
    this.paymentKey = pending.payment_key;
    this.paymentAddress = pending.payment_key_address;
    return { payment_key: this.paymentKey, payment_key_address: this.paymentAddress, previous_key_address: previous };
  }

  async transactionPlan(raw) {
    const action = String(raw?.action || "");
    const wallet = normalizeAddress(raw?.wallet, "wallet");
    const settlement = this.network.settlement_contract;
    const token = this.network.stablecoin;
    if (action === "top_up") {
      const amount = parseUsdc(raw.amount_usdc);
      const allowance = BigInt(await this.rpcValue((rpc) => this.contractCall(rpc, token, "allowance(address,address)", [wallet, settlement])) || "0x0");
      const transactions = [];
      if (allowance < amount) transactions.push({ label: "Approve stablecoin", to: token, data: contractData("approve(address,uint256)", [settlement, (1n << 256n) - 1n]) });
      transactions.push({ label: "Deposit prepaid balance", to: settlement, data: contractData("deposit(uint256)", [amount]) });
      return { action, amount_units: amount.toString(), transactions };
    }
    if (action === "register_key") {
      const pending = this.pendingPaymentKey();
      const keyAddress = pending?.payment_key_address || this.paymentAddress;
      return { action, key_address: keyAddress, transactions: [{ label: "Register payment key", to: settlement, data: contractData("registerKey(address,uint256,uint64)", [keyAddress, this.maxFeeUnits, 0]) }] };
    }
    if (action === "revoke_key") {
      const keyAddress = normalizeAddress(raw.key_address, "key_address");
      return { action, key_address: keyAddress, transactions: [{ label: "Revoke previous payment key", to: settlement, data: contractData("revokeKey(address)", [keyAddress]) }] };
    }
    throw new Error("unsupported transaction action");
  }

  async relayHealth(relayUrl, refresh = false) {
    const cached = this.healthCache.get(relayUrl);
    if (cached && !refresh && Date.now() - cached.at < 5000) return cached.payload;
    const request = { dispatcher: this.dispatcher, headers: { accept: "application/json" } };
    let response = await fetchWithTimeout(`${relayUrl}/health`, request, this.healthTimeoutMs);
    let payload = await readJsonResponse(response);
    if (!response.ok || !payload?.v8) {
      response = await fetchWithTimeout(`${relayUrl}/relay/health`, request, this.healthTimeoutMs);
      payload = await readJsonResponse(response);
    }
    if (!response.ok || payload?.ok !== true) throw new Error(`Relay health is invalid for ${relayUrl}`);
    const v8 = payload.v8;
    if (!v8 || v8.enabled !== true || Number(v8.providers || 0) <= 0) throw new Error(`Relay has no live Settlement V8 Provider: ${relayUrl}`);
    this.healthCache.set(relayUrl, { at: Date.now(), payload });
    return payload;
  }

  async chooseRelay(exclude = new Set()) {
    const errors = [];
    for (const relayUrl of this.relayUrls) {
      if (exclude.has(relayUrl)) continue;
      try { return { relayUrl, health: await this.relayHealth(relayUrl) }; } catch (error) { errors.push(error.message); }
    }
    throw new Error(`no healthy Settlement V8 Relay is available: ${errors.join("; ") || "all relays excluded"}`);
  }

  buildRelayPayment(path, body, health, requestId) {
    const endpoint = path.endsWith("/chat/completions") ? "chat" : "responses";
    const v8 = health?.v8;
    if (!v8) throw new Error("Relay health has no V8 payment requirements");
    const model = String(v8.model || body.model || DEFAULT_MODEL);
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
    const now = Math.floor(Date.now() / 1000);
    const payment = buildAuthorization({
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
      deadline: now + 900,
    });
    return { payment, request_id: requestId, model };
  }

  async relayInference(path, body) {
    const requestId = `0x${bytesToHex(randomBytes(32))}`;
    const used = new Set();
    let lastError = "no Relay accepted the request";
    let lastResponse;
    while (used.size < this.relayUrls.length) {
      let selected;
      try { selected = await this.chooseRelay(used); } catch (error) { lastError = error.message; break; }
      used.add(selected.relayUrl);
      try {
        const payment = this.buildRelayPayment(path, body, selected.health, requestId);
        const requestBody = { ...body, model: payment.model };
        const encodedPayment = base64Url(Buffer.from(stableStringify(payment.payment), "utf8"));
        const response = await fetchWithTimeout(`${selected.relayUrl}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json", "PAYMENT-SIGNATURE": encodedPayment },
          body: JSON.stringify(requestBody),
          dispatcher: this.dispatcher,
        }, this.timeoutMs);
        const payload = await readJsonResponse(response);
        const retryAfter = response.headers.get("retry-after");
        const headers = retryAfter ? { "Retry-After": retryAfter } : {};
        if (RETRYABLE_RELAY_STATUS.has(response.status)) {
          lastError = payload?.error?.message || `Relay returned HTTP ${response.status}`;
          lastResponse = { payload, status: response.status, headers };
          continue;
        }
        if (response.status >= 400) return { payload: normalizeOpenAiError(payload, "relay_error"), status: response.status, headers };
        const paymentResponse = response.headers.get("PAYMENT-RESPONSE");
        if (paymentResponse) {
          const settlement = decodePaymentResponse(paymentResponse);
          this.recordReceipt(selected.relayUrl, path, payment.model, settlement);
          headers["PAYMENT-RESPONSE"] = paymentResponse;
        }
        return { payload, status: 200, headers };
      } catch (error) {
        lastError = error.message;
      }
    }
    if (lastResponse) return lastResponse;
    return { payload: openaiError(lastError, "relay_unavailable"), status: 503, headers: { "Retry-After": "2" } };
  }
}

function decodePaymentResponse(value) {
  let payload;
  try { payload = JSON.parse(Buffer.from(String(value), "base64url").toString("utf8")); } catch { throw new Error("Relay returned an invalid PAYMENT-RESPONSE"); }
  if (!payload || typeof payload !== "object" || !payload.signed_receipt) throw new Error("Relay PAYMENT-RESPONSE is missing its signed receipt");
  try { verifySignedReceipt(payload.signed_receipt); } catch (error) { throw new Error(`Relay returned an invalid signed receipt: ${error.message}`); }
  return payload;
}

function normalizeOpenAiError(value, fallbackType) {
  if (!value || typeof value !== "object") return openaiError(String(value || fallbackType), fallbackType);
  if (!value.error || typeof value.error !== "object") return openaiError(value.detail || value.message || fallbackType, fallbackType);
  return { ...value, error: { ...value.error, message: String(value.error.message || fallbackType), type: String(value.error.type || fallbackType), param: value.error.param ?? null, code: value.error.code || value.error.type || fallbackType } };
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

async function handleInference(state, request, response, path) {
  const authorization = String(request.headers.authorization || "");
  if (!sameSecret(authorization, `Bearer ${state.paymentKey}`)) {
    writeJson(response, 401, openaiError("invalid MycoMesh payment key", "invalid_api_key"));
    return;
  }
  let body;
  try { body = await decodeRequestBody(request); } catch (error) {
    writeJson(response, 400, openaiError(error.message, "invalid_request_error"));
    return;
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
    const result = await state.relayInference(path, body);
    if (result.status >= 400) {
      writeJson(response, result.status, result.payload, result.headers);
      return;
    }
    for (const [name, value] of Object.entries(result.headers || {})) response.setHeader(name, value);
    if (body.stream === true) {
      response.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache", connection: "keep-alive", "x-mycomesh-streaming-mode": "buffered" });
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

export function createConsumerServer(state, { host = "127.0.0.1", port = 8110 } = {}) {
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", `http://${request.headers.host || "127.0.0.1"}`);
      const path = url.pathname;
      if (request.method === "GET" && path === "/") {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(consumerHtml());
        return;
      }
      if (request.method === "GET" && path === "/health") { writeJson(response, 200, state.healthPayload()); return; }
      if (request.method === "GET" && path === "/ready") {
        try { const selected = await state.chooseRelay(); writeJson(response, 200, { ok: true, relay: selected.relayUrl, model: selected.health.v8.model || DEFAULT_MODEL }); }
        catch (error) { writeJson(response, 503, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "GET" && (path === "/credentials" || path === "/codex-env")) {
        response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }); response.end(`${state.credentialsText()}\n`); return;
      }
      if (request.method === "GET" && (path === "/models" || path === "/v1/models" || path === "/backend-api/codex/models")) {
        try { const selected = await state.chooseRelay(); writeJson(response, 200, { object: "list", data: [{ id: selected.health.v8.model || DEFAULT_MODEL, object: "model", owned_by: "mycomesh", relay: selected.relayUrl }] }); }
        catch (error) { writeJson(response, 503, openaiError(error.message, "relay_unavailable")); }
        return;
      }
      if (request.method === "GET" && path === "/v1/mycomesh/local/dashboard") { writeJson(response, 200, await state.dashboardPayload(url.searchParams.get("wallet"))); return; }
      if (request.method === "POST" && path === "/v1/mycomesh/local/transactions") {
        try { writeJson(response, 200, await state.transactionPlan(await decodeRequestBody(request))); }
        catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/key/prepare") {
        if (!sameSecret(String(request.headers.authorization || ""), `Bearer ${state.paymentKey}`)) { writeJson(response, 401, { ok: false, error: "invalid local payment key" }); return; }
        try { writeJson(response, 200, state.preparePaymentKey()); } catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "POST" && path === "/v1/mycomesh/local/key/activate") {
        if (!sameSecret(String(request.headers.authorization || ""), `Bearer ${state.paymentKey}`)) { writeJson(response, 401, { ok: false, error: "invalid local payment key" }); return; }
        try { const value = await decodeRequestBody(request); writeJson(response, 200, await state.activatePendingPaymentKey(value.wallet)); }
        catch (error) { writeJson(response, 400, { ok: false, error: error.message }); }
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
  (Array.isArray(payload?.choices) ? payload.choices : []).forEach((choice, fallbackIndex) => { const index = Number.isInteger(choice.index) ? choice.index : fallbackIndex; const message = choice.message || {}; chunk(index, { role: String(message.role || "assistant") }); if (message.content) chunk(index, { content: String(message.content) }); chunk(index, {}, choice.finish_reason || "stop"); });
  if (includeUsage && payload?.usage) chunks.push(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created, model, choices: [], usage: payload.usage })}\n\n`);
  chunks.push("data: [DONE]\n\n"); return chunks;
}

function consumerHtml() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MycoMesh Consumer</title>
<style>
body{font:15px system-ui;max-width:960px;margin:32px auto;padding:0 18px;color:#17211d;background:#f5f7f5}
h1{margin-bottom:4px}.muted{color:#68736e}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}
.panel{background:white;border:1px solid #d9e0dc;border-radius:6px;padding:18px;margin:14px 0}.value{word-break:break-all;background:#f1f4f2;padding:10px;border-radius:4px;font:12px monospace;white-space:pre-wrap}
button{padding:9px 12px;border:1px solid #177b57;border-radius:4px;background:#177b57;color:#fff;cursor:pointer}input{padding:9px;border:1px solid #c7d0ca;border-radius:4px}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #e1e7e3;text-align:left;font-size:13px}
</style></head><body>
<h1>MycoMesh Consumer V8</h1><p class="muted">Native Node runtime. This page manages credentials, prepaid balance, payment keys, and local consumption history.</p>
<div class="grid"><section class="panel"><h2>Credentials</h2><p>API URL</p><div id="url" class="value">Loading...</div><p>Payment key</p><div id="key" class="value"></div><p>Shell export</p><div id="export" class="value"></div><button id="copy" type="button">Copy export</button></section>
<section class="panel"><h2>Usage</h2><p id="usage">Loading...</p><p id="balance"></p><p>Key address</p><div id="address" class="value"></div><div class="row"><button id="register" type="button">Register key</button><button id="rotate" type="button">Rotate key</button></div></section></div>
<section class="panel"><h2>Prepaid top-up</h2><div class="row"><button id="connect" type="button">Connect wallet</button><input id="wallet" placeholder="Wallet address"><input id="amount" placeholder="10.00"><button id="topup" type="button">Top up</button></div><pre id="plan" class="value"></pre></section>
<section class="panel"><h2>Consumption history</h2><table><thead><tr><th>Time</th><th>Model</th><th>Tokens</th><th>Fee</th><th>Relay</th></tr></thead><tbody id="history"></tbody></table></section>
<script>
let state;let wallet;const $=id=>document.getElementById(id);
async function api(path,options={}){const r=await fetch(path,options);const v=await r.json();if(!r.ok)throw Error(v.error||'request failed');return v}
function render(){
  $('url').textContent=state.credentials.base_url;$('key').textContent=state.credentials.api_key;$('export').textContent=state.credentials.export;$('address').textContent=state.key.address;
  $('usage').textContent=state.usage.request_count+' requests, '+state.usage.total_spent_units+' units';$('balance').textContent='Available balance: '+(state.account?.available_balance_units||'unknown');
  $('history').innerHTML=(state.history||[]).map(x=>'<tr><td>'+new Date(x.timestamp*1000).toLocaleString()+'</td><td>'+x.model+'</td><td>'+x.input_tokens+' / '+x.output_tokens+'</td><td>'+x.actual_fee_units+'</td><td>'+x.relay_url+'</td></tr>').join('')||'<tr><td colspan="5">No consumption recorded.</td></tr>';
}
async function load(){state=await api('/v1/mycomesh/local/dashboard');render()}
async function connectWallet(){if(!window.ethereum)throw Error('No injected wallet found');const accounts=await window.ethereum.request({method:'eth_requestAccounts'});wallet=accounts[0];if(!wallet)throw Error('Wallet was not connected');$('wallet').value=wallet;$('connect').textContent=wallet.slice(0,6)+'...'+wallet.slice(-4)}
async function requireWallet(){if(!wallet)await connectWallet();return wallet}
async function waitReceipt(hash){for(let i=0;i<120;i++){const receipt=await window.ethereum.request({method:'eth_getTransactionReceipt',params:[hash]});if(receipt){if(receipt.status!=='0x1')throw Error('Chain transaction failed');return}await new Promise(resolve=>setTimeout(resolve,1500))}throw Error('Timed out waiting for chain confirmation')}
async function sendPlan(plan){for(const transaction of plan.transactions){const hash=await window.ethereum.request({method:'eth_sendTransaction',params:[{from:wallet,to:transaction.to,data:transaction.data}]});await waitReceipt(hash)}return plan}
async function showPlan(action,send=false){try{await requireWallet();const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action,wallet,key_address:state.key.address,amount_usdc:$('amount').value})});$('plan').textContent=JSON.stringify(plan,null,2);if(send){await sendPlan(plan);await load();$('plan').textContent='Transactions confirmed. '+JSON.stringify(plan,null,2)}}catch(error){$('plan').textContent=error.message}}
$('copy').onclick=()=>navigator.clipboard?.writeText($('export').textContent);
$('connect').onclick=()=>connectWallet().catch(error=>$('plan').textContent=error.message);
$('register').onclick=()=>showPlan('register_key',true);$('topup').onclick=()=>showPlan('top_up',true);
$('rotate').onclick=async()=>{try{await requireWallet();const oldAddress=state.key.address;const pending=await api('/v1/mycomesh/local/key/prepare',{method:'POST',headers:{authorization:'Bearer '+state.credentials.api_key}});const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'register_key',wallet})});await sendPlan(plan);let activated;for(let i=0;i<8&&!activated;i++){try{activated=await api('/v1/mycomesh/local/key/activate',{method:'POST',headers:{authorization:'Bearer '+state.credentials.api_key,'content-type':'application/json'},body:JSON.stringify({wallet})})}catch(error){if(i===7)throw error;await new Promise(resolve=>setTimeout(resolve,1800))}}const revoke=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'revoke_key',wallet,key_address:oldAddress})});await sendPlan(revoke);$('plan').textContent=JSON.stringify({pending,activated,revoke},null,2);await load()}catch(error){$('plan').textContent=error.message}};
load().catch(error=>$('plan').textContent=error.message);
</script></body></html>`;
}

export { authorizationStructHash, receiptStructHash, verifyAuthorization, verifySignedReceipt };
