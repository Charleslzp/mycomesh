import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn as defaultSpawn } from "node:child_process";
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
const MAX_SHARE_MINUTES = 24 * 60;
const TUNNEL_START_TIMEOUT_MS = 30_000;
const TUNNEL_STOP_TIMEOUT_MS = 2_000;
const RELAY_HEALTH_CACHE_MS = 30_000;
const RELAY_HEALTH_STALE_MS = 10 * 60_000;
const RELAY_HEALTH_RETRY_DELAY_MS = 250;
const WALLET_CHALLENGE_TTL_MS = 5 * 60_000;

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

export function walletMessageDigest(message) {
  const body = Buffer.from(String(message), "utf8");
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${body.length}`, "utf8");
  return Uint8Array.from(keccak_256(Buffer.concat([prefix, body])));
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
    this.healthTimeoutMs = options.healthTimeoutMs ?? Number(env.MYCOMESH_V8_HEALTH_TIMEOUT_SECONDS || 10) * 1000;
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
      wallet_unlocked: this.paymentUnlocked,
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
    const grant = await this.keyGrant(this.paymentAddress);
    if (grant.owner !== ZERO_ADDRESS && grant.owner !== wallet) {
      throw new Error("this local payment key belongs to a different wallet");
    }
    this.unlockedWallet = wallet;
    this.managementToken = `myco_local_${randomBytes(32).toString("base64url")}`;
    this.paymentUnlocked = grant.active && grant.owner === wallet;
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
    if (!existsSync(this.historyPath)) return [];
    const lines = readFileSync(this.historyPath, "utf8").split("\n").filter(Boolean);
    const selected = limit <= 0 ? lines : lines.slice(-Math.min(Math.max(limit, 1), 500));
    return selected.map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter((value) => value && typeof value === "object").reverse();
  }

  recordReceipt(relayUrl, endpoint, model, settlement, routeModel = model) {
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
      route_model: routeModel,
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

  async dashboardPayload(managementAuthorized = false) {
    const authenticated = managementAuthorized && Boolean(this.unlockedWallet);
    const allHistory = this.history(0);
    const pending = authenticated ? this.pendingPaymentKey() : null;
    const payload = {
      ok: true,
      protocol_version: 8,
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
      usage: {
        request_count: authenticated ? allHistory.length : 0,
        total_spent_units: authenticated ? allHistory.reduce((total, item) => total + Number(item.actual_fee_units || 0), 0) : 0,
        input_tokens: authenticated ? allHistory.reduce((total, item) => total + Number(item.input_tokens || 0), 0) : 0,
        output_tokens: authenticated ? allHistory.reduce((total, item) => total + Number(item.output_tokens || 0), 0) : 0,
      },
      share: authenticated ? this.sharePayload() : { active: false },
    };
    try {
      const grant = await this.keyGrant(this.paymentAddress);
      payload.key.grant = grant;
      if (authenticated && grant.owner !== ZERO_ADDRESS) {
        payload.account = { owner: grant.owner, available_balance_units: await this.accountBalance(grant.owner) };
      }
    } catch (error) {
      payload.chain_error = error.message;
    }
    if (authenticated) {
      try {
        const address = this.unlockedWallet;
        const token = await this.rpcValue((rpc) => this.contractCall(rpc, this.network.stablecoin, "balanceOf(address)", [address]));
        const allowance = await this.rpcValue((rpc) => this.contractCall(rpc, this.network.stablecoin, "allowance(address,address)", [address, this.network.settlement_contract]));
        payload.wallet = { address, token_balance_units: BigInt(token || "0x0").toString(), allowance_units: BigInt(allowance || "0x0").toString() };
      } catch (error) {
        payload.wallet_error = error.message;
      }
    }
    return payload;
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
    const previous = this.paymentAddress;
    const destination = join(this.dataDir, "payment-key");
    writeFileSync(destination, `${pending.payment_key}\n`, { mode: 0o600 });
    chmodSync(destination, 0o600);
    unlinkSync(this.pendingKeyPath);
    this.paymentKey = pending.payment_key;
    this.paymentAddress = pending.payment_key_address;
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
    const cacheAge = cached ? Date.now() - cached.at : Infinity;
    if (cached && !refresh && cacheAge < RELAY_HEALTH_CACHE_MS) return cached.payload;
    const request = { dispatcher: this.dispatcher, headers: { accept: "application/json" } };
    let payload;
    let lastError;
    for (let attempt = 0; attempt < 2 && !payload; attempt += 1) {
      try {
        const response = await fetchWithTimeout(`${relayUrl}/relay/health`, request, this.healthTimeoutMs);
        payload = await readJsonResponse(response);
        if (!response.ok || payload?.ok !== true) throw new Error(`Relay health is invalid for ${relayUrl}`);
      } catch (error) {
        lastError = error;
        payload = undefined;
        if (attempt === 0) await new Promise((resolve) => setTimeout(resolve, RELAY_HEALTH_RETRY_DELAY_MS));
      }
    }
    if (!payload) {
      if (cached && cacheAge < RELAY_HEALTH_STALE_MS) return cached.payload;
      throw lastError || new Error(`Relay health is unavailable for ${relayUrl}`);
    }
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
        const requestBody = {
          ...body,
          model: selected.health.v8.model || body.model,
        };
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
        const payment = this.buildRelayPayment(path, requestBody, selected.health, requestId);
        requestBody.model = payment.model;
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
          this.recordReceipt(
            selected.relayUrl,
            path,
            String(body.model || payment.model),
            settlement,
            payment.model,
          );
          headers["PAYMENT-RESPONSE"] = paymentResponse;
        }
        return { payload: restoreClientResponse(payload, body), status: 200, headers };
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
    const result = await state.relayInference(path, body);
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

export function createConsumerServer(state, { host = "127.0.0.1", port = 8110, publicOnly = false } = {}) {
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", `http://${request.headers.host || "127.0.0.1"}`);
      const path = url.pathname.startsWith("/v1/v1/") ? url.pathname.slice(3) : url.pathname;
      if (publicOnly) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        response.setHeader("Access-Control-Expose-Headers", "PAYMENT-RESPONSE, Retry-After");
        if (request.method === "OPTIONS") { response.writeHead(204); response.end(); return; }
        if (request.method === "GET" && (path === "/health" || path === "/v1/health")) {
          if (!state.authorizeBearer(String(request.headers.authorization || ""), { shareOnly: true })) { writeJson(response, 401, openaiError("invalid temporary access key", "invalid_api_key")); return; }
          writeJson(response, 200, { ok: true, protocol: "mycomesh-temporary-share/v1", expires_at: state.activeShare()?.expiresAt });
          return;
        }
        if (request.method === "GET" && (path === "/models" || path === "/v1/models" || path === "/backend-api/codex/models")) {
          if (!state.authorizeBearer(String(request.headers.authorization || ""), { shareOnly: true })) { writeJson(response, 401, openaiError("invalid temporary access key", "invalid_api_key")); return; }
          try { const selected = await state.chooseRelay(); writeJson(response, 200, { object: "list", data: [{ id: selected.health.v8.model || DEFAULT_MODEL, object: "model", owned_by: "mycomesh", relay: selected.relayUrl }] }); }
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
        if (!state.paymentUnlocked) { writeJson(response, 423, { ok: false, error: "sign in with the payment-key owner wallet first" }); return; }
        response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }); response.end(`${state.credentialsText()}\n`); return;
      }
      if (request.method === "GET" && (path === "/models" || path === "/v1/models" || path === "/backend-api/codex/models")) {
        try { const selected = await state.chooseRelay(); writeJson(response, 200, { object: "list", data: [{ id: selected.health.v8.model || DEFAULT_MODEL, object: "model", owned_by: "mycomesh", relay: selected.relayUrl }] }); }
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
        catch (error) { writeJson(response, 401, { ok: false, error: error.message }); }
        return;
      }
      if (request.method === "GET" && path === "/v1/mycomesh/local/dashboard") {
        writeJson(response, 200, await state.dashboardPayload(state.authorizeManagement(String(request.headers.authorization || "")))); return;
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
:root{--ink:#17211d;--muted:#68736e;--line:#d8dfdb;--soft:#f2f5f3;--paper:#fff;--green:#147553;--green-dark:#0d5b40;--amber:#9a6413;--red:#ae3d38;--blue:#365d86}*{box-sizing:border-box}[hidden]{display:none!important}html{background:#edf1ee}body{min-width:320px;margin:0;color:var(--ink);background:#edf1ee;font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}button,input,select{font:inherit;letter-spacing:0}button{cursor:pointer}.shell{min-height:100vh}.topbar{position:sticky;z-index:10;top:0;display:flex;min-height:60px;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);background:rgba(255,255,255,.97);padding:0 max(18px,env(safe-area-inset-left))}.brand{display:flex;align-items:center;gap:10px;font-weight:780}.mark{display:grid;width:30px;height:30px;place-items:center;border-radius:6px;background:var(--ink);color:#fff;font-size:12px}.network{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px}.dot{width:7px;height:7px;border-radius:50%;background:#9ba49f}.dot.ok{background:var(--green)}.workspace{width:min(760px,100%);margin:0 auto;background:var(--paper);min-height:calc(100vh - 60px)}.locked{display:grid;min-height:calc(100vh - 60px);align-content:center;padding:42px 24px 88px}.locked-inner{width:min(420px,100%);margin:0 auto}.locked-badge{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:5px 10px;color:var(--muted);font-size:12px}.locked h1{margin:20px 0 9px;font-size:30px;line-height:1.16}.locked p{margin:0 0 26px;color:var(--muted)}.key-preview{border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:14px 0;margin:0 0 22px}.label{display:block;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.key-preview .mono{display:block;margin-top:5px;font-size:12px}.button{display:inline-flex;min-height:42px;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:6px;background:var(--paper);padding:0 15px;color:var(--ink);font-weight:700}.button:hover{border-color:#95a39b;background:#f8faf9}.button.primary{border-color:var(--green);background:var(--green);color:#fff}.button.primary:hover{background:var(--green-dark)}.button.danger{border-color:#e5b6b3;color:var(--red)}.button.small{min-height:34px;padding:0 11px;font-size:12px}.button:disabled{cursor:not-allowed;opacity:.52}.locked .button{width:100%;min-height:48px}.app-head{padding:24px 20px 17px}.app-head-row{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.app-head h1{margin:0;font-size:22px}.wallet-button{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.balance{margin-top:22px}.balance strong{display:block;margin-top:4px;font-size:31px;font-weight:760}.balance-meta{display:flex;gap:16px;margin-top:8px;color:var(--muted);font-size:12px}.tabs{position:sticky;z-index:8;top:60px;display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:rgba(255,255,255,.97);padding:0 12px}.tab{min-width:0;border:0;border-bottom:2px solid transparent;background:transparent;padding:12px 4px;color:var(--muted);font-weight:650}.tab.active{border-color:var(--green);color:var(--ink)}.view{padding:2px 20px 84px}.band{border-top:1px solid var(--line);padding:23px 0}.band:first-child{border-top:0}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.section-head h2{margin:0;font-size:16px}.section-head p{margin:3px 0 0;color:var(--muted);font-size:12px}.status{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:11px;white-space:nowrap}.status:before{width:6px;height:6px;border-radius:50%;background:var(--amber);content:""}.status.ok:before{background:var(--green)}.field+.field{margin-top:13px}.field-row{display:flex;align-items:stretch;gap:7px;margin-top:6px}.value{min-width:0;flex:1;border:1px solid var(--line);border-radius:5px;background:var(--soft);padding:10px 11px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.value.exports{min-height:76px;white-space:pre-wrap}.metrics{display:grid;grid-template-columns:repeat(3,1fr);border:1px solid var(--line);border-radius:6px;overflow:hidden}.metric{min-width:0;padding:14px 10px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span{display:block;color:var(--muted);font-size:11px}.metric strong{display:block;overflow:hidden;margin-top:4px;font-size:17px;text-overflow:ellipsis}.list{margin:0}.list div{display:grid;grid-template-columns:104px minmax(0,1fr);gap:12px;border-bottom:1px solid var(--line);padding:12px 0}.list div:last-child{border-bottom:0}.list dt{color:var(--muted)}.list dd{overflow:hidden;margin:0;text-align:right;text-overflow:ellipsis;white-space:nowrap}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.topup{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}.input,.select{width:100%;min-height:42px;border:1px solid var(--line);border-radius:5px;background:#fff;padding:8px 10px;color:var(--ink)}.input:focus,.select:focus{border-color:var(--green);outline:2px solid rgba(20,117,83,.13)}.share-output{margin-top:16px}.empty{padding:34px 0;color:var(--muted);text-align:center}.table-wrap{overflow-x:auto;border-top:1px solid var(--line)}table{width:100%;min-width:620px;border-collapse:collapse}th,td{padding:11px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:12px}th{color:var(--muted);font-weight:650}.notice{border-left:3px solid var(--amber);background:#fff8e9;padding:10px 12px;color:#76511c;font-size:12px}.notice.error{border-color:var(--red);background:#fff3f2;color:#892f2b}.toast{position:fixed;z-index:30;right:16px;bottom:calc(18px + env(safe-area-inset-bottom));left:16px;max-width:520px;margin:auto;border-radius:6px;background:var(--ink);padding:11px 14px;color:#fff;box-shadow:0 10px 30px rgba(23,33,29,.2);text-align:center}.toast.error{background:#7e2925}@media(min-width:761px){body{padding:22px}.shell{border:1px solid var(--line);border-radius:8px;overflow:hidden;box-shadow:0 18px 50px rgba(23,33,29,.08)}.workspace{min-height:calc(100vh - 106px)}.topbar{position:relative}.tabs{top:0}.view,.app-head{padding-right:28px;padding-left:28px}.toast{bottom:28px}}@media(max-width:420px){.balance strong{font-size:27px}.metrics{grid-template-columns:1fr}.metric{display:flex;align-items:center;justify-content:space-between;border-right:0;border-bottom:1px solid var(--line)}.metric:last-child{border-bottom:0}.metric strong{margin:0}.field-row{flex-direction:column}.field-row .button{width:100%}.topup{grid-template-columns:1fr}.topup .button{width:100%}}
</style></head><body>
<div class="shell"><header class="topbar"><div class="brand"><span class="mark">M</span><span>MycoMesh</span></div><div class="network"><span id="networkDot" class="dot"></span><span id="networkName">V8 Consumer</span></div></header><main class="workspace">
<div id="locked" class="locked"><div class="locked-inner"><span class="locked-badge">Consumer V8</span><h1>连接钱包以继续</h1><p>签名后读取并核对当前 Key 的链上归属。</p><div class="key-preview"><span class="label">本地 Key 地址</span><span id="lockedKey" class="mono">读取中...</span></div><button id="login" class="button primary" type="button">连接钱包并签名</button><p id="loginError" class="notice error" hidden></p></div></div>
<div id="app" hidden><div class="app-head"><div class="app-head-row"><div><span class="label">预付账户</span><h1>Consumer</h1></div><button id="walletButton" class="button small wallet-button" type="button">退出</button></div><div class="balance"><span class="label">可用余额</span><strong id="balance">--</strong><div class="balance-meta"><span id="keyStatus">Key 状态 --</span><span id="requestCount">0 次请求</span></div></div></div>
<nav class="tabs" aria-label="Consumer navigation"><button class="tab active" data-view="overview" type="button">概览</button><button class="tab" data-view="wallet" type="button">钱包</button><button class="tab" data-view="activity" type="button">记录</button><button class="tab" data-view="share" type="button">分享</button></nav>
<div id="view-overview" class="view"><div class="band"><div class="section-head"><div><h2>访问凭证</h2><p id="credentialState">等待 Key 激活</p></div><span id="credentialBadge" class="status">锁定</span></div><div id="credentials" hidden><div class="field"><span class="label">API URL</span><div class="field-row"><div id="url" class="value"></div><button class="button small copy" data-copy="url" type="button">复制</button></div></div><div class="field"><span class="label">Key</span><div class="field-row"><div id="key" class="value"></div><button class="button small copy" data-copy="key" type="button">复制</button></div></div><div class="field"><span class="label">Export</span><div class="field-row"><div id="export" class="value exports"></div><button class="button small copy" data-copy="export" type="button">复制</button></div></div></div><div id="inactiveKey" class="notice">当前 Key 尚未在链上激活。</div></div><div class="band"><div class="section-head"><h2>本地用量</h2></div><div class="metrics"><div class="metric"><span>累计消费</span><strong id="spent">--</strong></div><div class="metric"><span>输入 Tokens</span><strong id="inputTokens">0</strong></div><div class="metric"><span>输出 Tokens</span><strong id="outputTokens">0</strong></div></div></div></div>
<div id="view-wallet" class="view" hidden><div class="band"><div class="section-head"><h2>钱包与 Key</h2><span id="chainStatus" class="status">读取中</span></div><dl class="list"><div><dt>钱包</dt><dd id="walletAddress" class="mono"></dd></div><div><dt>Key 地址</dt><dd id="keyAddress" class="mono"></dd></div><div><dt>单次上限</dt><dd id="keyLimit"></dd></div><div><dt>有效期</dt><dd id="keyValidity"></dd></div></dl><p id="chainError" class="notice error" hidden></p><div class="actions"><button id="activate" class="button primary" type="button">激活 Key</button><button id="rotate" class="button danger" type="button" hidden>更换 Key</button></div></div><div class="band"><div class="section-head"><div><h2>充值</h2><p id="walletBalance">钱包余额 --</p></div></div><div class="topup"><input id="amount" class="input" inputmode="decimal" placeholder="10.00 USDC"><button id="topup" class="button primary" type="button">充值</button></div></div></div>
<div id="view-activity" class="view" hidden><div class="band"><div class="section-head"><div><h2>消费记录</h2><p>当前设备已确认的推理账单</p></div><button id="refresh" class="button small" type="button">刷新</button></div><div id="historyEmpty" class="empty">暂无消费记录</div><div id="historyTable" class="table-wrap" hidden><table><thead><tr><th>时间</th><th>模型</th><th>Tokens</th><th>费用</th><th>Provider</th></tr></thead><tbody id="history"></tbody></table></div></div></div>
<div id="view-share" class="view" hidden><div class="band"><div class="section-head"><div><h2>临时分享</h2><p>到期后自动关闭</p></div><span id="shareStatus" class="status">未启用</span></div><div class="topup"><select id="shareMinutes" class="select"><option value="10">10 分钟</option><option value="30" selected>30 分钟</option><option value="60">1 小时</option><option value="360">6 小时</option></select><button id="shareStart" class="button primary" type="button">开始分享</button></div><div id="shareOutput" class="share-output" hidden><div class="field"><span class="label">API URL</span><div class="field-row"><div id="shareUrl" class="value"></div><button class="button small copy" data-copy="shareUrl" type="button">复制</button></div></div><div class="field"><span class="label">临时 Key</span><div class="field-row"><div id="shareKey" class="value"></div><button class="button small copy" data-copy="shareKey" type="button">复制</button></div></div><p id="shareExpiry" class="notice"></p><div class="actions"><button id="shareStop" class="button danger" type="button">停止分享</button></div></div></div></div></div>
</main></div><div id="toast" class="toast" hidden></div>
<script>
let state=null,wallet=null,managementToken=null,busy=false;const $=id=>document.getElementById(id);const short=value=>value?value.slice(0,6)+'...'+value.slice(-4):'--';
function units(value,decimals=6){const raw=BigInt(value||0),base=10n**BigInt(decimals),whole=raw/base,fraction=(raw%base).toString().padStart(decimals,'0').replace(/0+$/,'');return whole.toLocaleString()+(fraction?'.'+fraction.slice(0,4):'')}
function authHeaders(headers={}){const next=new Headers(headers);if(managementToken)next.set('authorization','Bearer '+managementToken);return next}
async function api(path,options={}){const response=await fetch(path,{...options,headers:authHeaders(options.headers)}),data=await response.json();if(!response.ok)throw new Error(typeof data.error==='string'?data.error:(data.error?.message||'请求失败'));return data}
function toast(message,error=false){const node=$('toast');node.textContent=message;node.className='toast'+(error?' error':'');node.hidden=false;clearTimeout(toast.timer);toast.timer=setTimeout(()=>node.hidden=true,3200)}
function setBusy(value){busy=value;for(const button of document.querySelectorAll('button'))button.disabled=value}
async function run(task){if(busy)return;setBusy(true);try{await task()}catch(error){toast(error?.message||String(error),true)}finally{setBusy(false)}}
async function load(){state=await api('/v1/mycomesh/local/dashboard');render()}
function render(){const authenticated=Boolean(managementToken&&state.auth?.authenticated),ready=authenticated&&state.auth.key_ready,grant=state.key.grant||{},decimals=state.settlement?.stablecoin_decimals||6,symbol=state.settlement?.stablecoin_symbol||'USDC';$('networkName').textContent=state.chain_error?'链上不可用':(state.settlement?.network_name||'V8 Consumer');$('networkDot').className='dot'+(state.chain_error?'':' ok');$('lockedKey').textContent=state.key.address;$('locked').hidden=authenticated;$('app').hidden=!authenticated;if(!authenticated)return;$('walletButton').textContent=short(state.auth.wallet);$('walletAddress').textContent=state.auth.wallet;$('keyAddress').textContent=state.key.address;$('balance').textContent=state.account?units(state.account.available_balance_units,decimals)+' '+symbol:'--';$('requestCount').textContent=state.usage.request_count+' 次请求';$('keyStatus').textContent=ready?'Key 已激活':'Key 待激活';$('credentialBadge').className='status'+(ready?' ok':'');$('credentialBadge').textContent=ready?'可用':'待激活';$('credentialState').textContent=ready?'仅在本机显示':'链上确认后显示';$('credentials').hidden=!ready;$('inactiveKey').hidden=ready;if(ready){$('url').textContent=state.credentials.base_url;$('key').textContent=state.credentials.api_key;$('export').textContent=state.credentials.export}$('spent').textContent=units(state.usage.total_spent_units,decimals)+' '+symbol;$('inputTokens').textContent=Number(state.usage.input_tokens||0).toLocaleString();$('outputTokens').textContent=Number(state.usage.output_tokens||0).toLocaleString();$('keyLimit').textContent=grant.max_per_request?units(grant.max_per_request,decimals)+' '+symbol:'--';$('keyValidity').textContent=grant.valid_until?new Date(grant.valid_until*1000).toLocaleString():'长期有效';$('chainStatus').className='status'+(grant.active?' ok':'');$('chainStatus').textContent=grant.active?'链上有效':'等待激活';$('activate').hidden=ready;$('rotate').hidden=!ready;$('chainError').hidden=!state.chain_error;$('chainError').textContent=state.chain_error||'';$('walletBalance').textContent=state.wallet?'钱包余额 '+units(state.wallet.token_balance_units,decimals)+' '+symbol:'钱包余额 --';renderHistory();renderShare()}
function renderHistory(){const body=$('history'),items=state.history||[];body.replaceChildren();$('historyEmpty').hidden=items.length>0;$('historyTable').hidden=items.length===0;for(const item of items){const row=document.createElement('tr');for(const value of [new Date(item.timestamp*1000).toLocaleString(),item.model,(item.input_tokens||0)+' / '+(item.output_tokens||0),units(item.actual_fee_units,state.settlement?.stablecoin_decimals||6),short(item.provider)]){const cell=document.createElement('td');cell.textContent=value;row.appendChild(cell)}body.appendChild(row)}}
function renderShare(){const share=state.share||{};$('shareStatus').className='status'+(share.active?' ok':'');$('shareStatus').textContent=share.active?'分享中':'未启用';$('shareOutput').hidden=!share.active;if(share.active){$('shareUrl').textContent=share.base_url;$('shareKey').textContent=share.api_key;$('shareExpiry').textContent='到期时间 '+new Date(share.expires_at*1000).toLocaleString()}}
function walletMessage(value){return '0x'+Array.from(new TextEncoder().encode(value),byte=>byte.toString(16).padStart(2,'0')).join('')}
async function login(){if(!window.ethereum)throw new Error('未检测到浏览器钱包');const accounts=await window.ethereum.request({method:'eth_requestAccounts'});wallet=String(accounts[0]||'').toLowerCase();if(!wallet)throw new Error('钱包未连接');const challenge=await api('/v1/mycomesh/local/wallet/challenge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({wallet})});const signature=await window.ethereum.request({method:'personal_sign',params:[walletMessage(challenge.message),wallet]});const result=await api('/v1/mycomesh/local/wallet/authenticate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({wallet,signature})});managementToken=result.token;await load();toast(state.auth.key_ready?'钱包验证完成':'钱包验证完成，请激活 Key')}
async function ensureChain(){const expected='0x'+Number(state.settlement.chain_id).toString(16),current=await window.ethereum.request({method:'eth_chainId'});if(current.toLowerCase()!==expected.toLowerCase())await window.ethereum.request({method:'wallet_switchEthereumChain',params:[{chainId:expected}]})}
async function waitReceipt(hash){for(let count=0;count<120;count++){const receipt=await window.ethereum.request({method:'eth_getTransactionReceipt',params:[hash]});if(receipt){if(receipt.status!=='0x1')throw new Error('链上交易失败');return receipt}await new Promise(resolve=>setTimeout(resolve,1500))}throw new Error('等待链上确认超时')}
async function sendPlan(plan){await ensureChain();for(const transaction of plan.transactions){toast(transaction.label);const hash=await window.ethereum.request({method:'eth_sendTransaction',params:[{from:wallet,to:transaction.to,data:transaction.data}]});await waitReceipt(hash)}}
async function activateCurrent(){const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'register_key',wallet})});await sendPlan(plan);for(let count=0;count<10;count++){try{await api('/v1/mycomesh/local/wallet/activate',{method:'POST'});await load();toast('Key 已激活');return}catch(error){if(count===9)throw error;await new Promise(resolve=>setTimeout(resolve,1600))}}}
async function rotateKey(){const oldAddress=state.key.address;await api('/v1/mycomesh/local/key/prepare',{method:'POST'});const register=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'register_key',wallet})});await sendPlan(register);for(let count=0;count<10;count++){try{await api('/v1/mycomesh/local/key/activate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({wallet})});break}catch(error){if(count===9)throw error;await new Promise(resolve=>setTimeout(resolve,1600))}}const revoke=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'revoke_key',wallet,key_address:oldAddress})});await sendPlan(revoke);await load();toast('新 Key 已启用，旧 Key 已撤销')}
document.querySelectorAll('.tab').forEach(tab=>tab.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(item=>item.classList.toggle('active',item===tab));document.querySelectorAll('.view').forEach(view=>view.hidden=view.id!=='view-'+tab.dataset.view)}));
document.addEventListener('click',event=>{const button=event.target.closest('.copy');if(button)navigator.clipboard.writeText($(button.dataset.copy).textContent).then(()=>toast('已复制')).catch(()=>toast('复制失败',true))});
$('login').onclick=()=>run(login);$('activate').onclick=()=>run(activateCurrent);$('rotate').onclick=()=>run(rotateKey);$('refresh').onclick=()=>run(load);
$('topup').onclick=()=>run(async()=>{const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'top_up',wallet,amount_usdc:$('amount').value.trim()})});await sendPlan(plan);$('amount').value='';await load();toast('充值已确认')});
$('shareStart').onclick=()=>run(async()=>{const value=await api('/v1/mycomesh/local/share/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({minutes:Number($('shareMinutes').value)})});state.share=value.share;renderShare();toast('临时分享已开启')});
$('shareStop').onclick=()=>run(async()=>{const value=await api('/v1/mycomesh/local/share/stop',{method:'POST'});state.share=value.share;renderShare();toast('临时分享已停止')});
$('walletButton').onclick=()=>run(async()=>{await api('/v1/mycomesh/local/wallet/lock',{method:'POST'});managementToken=null;wallet=null;await load()});
window.ethereum?.on?.('accountsChanged',()=>{if(managementToken)api('/v1/mycomesh/local/wallet/lock',{method:'POST'}).catch(()=>{}).finally(()=>{managementToken=null;wallet=null;load().catch(error=>toast(error.message,true))})});
load().catch(error=>{$('loginError').hidden=false;$('loginError').textContent=error.message});
</script></body></html>`;
}

export { authorizationStructHash, receiptStructHash, verifyAuthorization, verifySignedReceipt };
