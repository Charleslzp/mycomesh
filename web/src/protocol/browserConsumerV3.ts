import type { ConsumerV3Authorization, ConsumerV3Plan } from "./api";
import { keccak256, stringToHex } from "viem";
import {
  assertBrowserConsumerIdentity,
  assertBrowserSoftwareConsumerIdentity,
  type BrowserConsumerIdentity,
  type BrowserDocumentSigningIdentity,
  type BrowserSoftwareConsumerIdentity,
  BrowserConsumerProtocolError,
  browserIsPlainObject,
  browserSha256Hex,
  browserUtf8,
  canonicalBrowserJson,
  protocolTimestamp,
  signBrowserDocument,
  signBrowserDocumentAsync,
  verifyBrowserDocument,
} from "./browserConsumerIdentity";

export const INFERENCE_REQUEST_HASH_VERSION = "mycomesh.inference.request.v2";
export const PAYMENT_RESERVATION_PURPOSE = "mycomesh.payment.reservation.v1";
export const INFERENCE_REQUEST_PURPOSE = "mycomesh.inference.request.v1";
export const PROVIDER_RESPONSE_PURPOSE = "mycomesh.inference.provider_response.v1";
export const EVM_SESSION_AUTHORIZATION_VERSION = "mycomesh.evm.session.v1";
export const SETTLEMENT_V3_RESERVATION_VERSION = "mycomesh-reservation-v2";
export const MYCOMESH_TESTNET_NETWORK_ID = "mycomesh-testnet";
export const CODEX_CHANNEL_ID = "codex";
export const CODEX_SETTLEMENT_CHANNEL = "codex-standard-v1";
export const CODEX_BACKEND_POLICY = "codex-app-server-postvalidated-v1";

const MAX_RESERVATION_TTL_SECONDS = 30 * 24 * 60 * 60;
const MAX_EVM_WALLET_SIGNATURE_BYTES = 16 * 1024;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const BYTES32_PATTERN = /^0x[0-9a-f]{64}$/;
const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;
const WALLET_SIGNATURE_PATTERN = /^0x[0-9a-f]+$/;

const AUTHORIZATION_FIELDS = [
  "authorization_version",
  "chain_id",
  "settlement_contract",
  "onchain_reservation_id",
  "consumer_payment_address",
  "provider_id",
  "provider_payment_address",
  "channel",
  "pricing_hash",
  "pricing_version",
  "request_hash",
  "max_fee_units",
  "expires_at",
  "settlement_deadline",
  "provider_fallback_allowed",
  "nonce",
  "session_public_key",
  "wallet_signature",
] as const;

export interface BrowserV3InferenceInput {
  endpoint: "responses" | "chat";
  model: string;
  input?: unknown;
  messages?: unknown;
  maxOutputTokens: number;
}

export interface BrowserV3ChannelBinding {
  network_id: string;
  channel_id: string;
  channel: string;
  backend_policy: string;
}

export type BrowserBoundConsumerV3Plan = ConsumerV3Plan & BrowserV3ChannelBinding;

interface BuildBrowserV3InferenceRequestBaseOptions extends BrowserV3InferenceInput {
  identity: BrowserConsumerIdentity;
  plan: BrowserBoundConsumerV3Plan;
  authorization: ConsumerV3Authorization;
  requestId: string;
  consumerId?: string;
  now?: number;
  reservationNonce?: string;
  requestNonce?: string;
}

export interface BuildBrowserV3InferenceRequestOptions
  extends Omit<BuildBrowserV3InferenceRequestBaseOptions, "identity"> {
  identity: BrowserSoftwareConsumerIdentity;
}

export interface BuildBrowserV3InferenceRequestAsyncOptions
  extends Omit<BuildBrowserV3InferenceRequestBaseOptions, "identity"> {
  identity: BrowserDocumentSigningIdentity;
}

export interface BuiltBrowserV3InferenceRequest {
  requestHash: `0x${string}`;
  paymentReservation: Record<string, unknown>;
  message: Record<string, unknown>;
}

export interface VerifyBrowserProviderResponseOptions {
  consumerPublicKey: string;
  providerPublicKey: string;
  channelBinding: BrowserV3ChannelBinding;
  requestId?: string;
  requestHash?: string;
  model?: string;
  endpoint?: "responses" | "chat";
  now?: number;
}

export class BrowserV3ProtocolError extends BrowserConsumerProtocolError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BrowserV3ProtocolError";
  }
}

export function browserV3InferenceRequestHash(input: BrowserV3InferenceInput): `0x${string}` {
  const endpoint = normalizedEndpoint(input.endpoint);
  const model = nonemptyString(input.model, "inference model");
  const maxOutputTokens = positiveSafeInteger(input.maxOutputTokens, "max_output_tokens");
  const request = normalizedInferencePayload({ ...input, endpoint, model, maxOutputTokens });
  const envelope: Record<string, unknown> = {
    request_hash_version: INFERENCE_REQUEST_HASH_VERSION,
    endpoint,
    model,
    [request.field]: request.value,
    max_output_tokens: maxOutputTokens,
  };
  return `0x${browserSha256Hex(browserUtf8(canonicalBrowserJson(envelope)))}`;
}

export function browserV3AuthorizationMessage(authorization: ConsumerV3Authorization): string {
  const normalized = normalizeAuthorization(
    authorization,
    browserIsPlainObject(authorization) && Object.hasOwn(authorization, "wallet_signature"),
  );
  delete normalized.wallet_signature;
  // All authorization text is printable ASCII, so Python's ensure_ascii=True output is identical.
  return canonicalBrowserJson(normalized);
}

export function buildBrowserV3InferenceRequest(
  options: BuildBrowserV3InferenceRequestOptions,
): BuiltBrowserV3InferenceRequest {
  assertBrowserSoftwareConsumerIdentity(options.identity);
  const prepared = prepareBrowserV3InferenceRequest(options);
  const paymentReservation = signBrowserDocument(
    prepared.reservationDocument,
    options.identity,
    {
      purpose: PAYMENT_RESERVATION_PURPOSE,
      timestamp: prepared.currentTime,
      nonce: options.reservationNonce,
    },
  ) as unknown as Record<string, unknown>;
  const message = signBrowserDocument(
    prepared.messageDocument(paymentReservation),
    options.identity,
    {
      purpose: INFERENCE_REQUEST_PURPOSE,
      audience: options.plan.provider_id,
      timestamp: prepared.currentTime,
      nonce: options.requestNonce,
    },
  ) as unknown as Record<string, unknown>;
  return { requestHash: prepared.requestHash, paymentReservation, message };
}

export async function buildBrowserV3InferenceRequestAsync(
  options: BuildBrowserV3InferenceRequestAsyncOptions,
): Promise<BuiltBrowserV3InferenceRequest> {
  assertBrowserConsumerIdentity(options.identity);
  const prepared = prepareBrowserV3InferenceRequest(options);
  const paymentReservation = await signBrowserDocumentAsync(
    prepared.reservationDocument,
    options.identity,
    {
      purpose: PAYMENT_RESERVATION_PURPOSE,
      timestamp: prepared.currentTime,
      nonce: options.reservationNonce,
    },
  ) as unknown as Record<string, unknown>;
  const message = await signBrowserDocumentAsync(
    prepared.messageDocument(paymentReservation),
    options.identity,
    {
      purpose: INFERENCE_REQUEST_PURPOSE,
      audience: options.plan.provider_id,
      timestamp: prepared.currentTime,
      nonce: options.requestNonce,
    },
  ) as unknown as Record<string, unknown>;
  return { requestHash: prepared.requestHash, paymentReservation, message };
}

function prepareBrowserV3InferenceRequest(
  options: BuildBrowserV3InferenceRequestBaseOptions,
): {
  currentTime: number;
  requestHash: `0x${string}`;
  reservationDocument: Record<string, unknown>;
  messageDocument: (paymentReservation: Record<string, unknown>) => Record<string, unknown>;
} {
  const currentTime = protocolTime(options.now, "current time");
  const requestId = canonicalRequestId(options.requestId);
  const endpoint = normalizedEndpoint(options.endpoint);
  const model = nonemptyString(options.model, "inference model");
  const maxOutputTokens = positiveSafeInteger(options.maxOutputTokens, "max_output_tokens");
  const requestPayload = normalizedInferencePayload({ ...options, endpoint, model, maxOutputTokens });
  assertBrowserConsumerIdentity(options.identity);
  const requestHash = browserV3InferenceRequestHash({
    endpoint,
    model,
    input: options.input,
    messages: options.messages,
    maxOutputTokens,
  });
  const inputSizeBytes = browserUtf8(canonicalBrowserJson(requestPayload.value)).length;
  const plan = validatePlan(options.plan, requestHash, inputSizeBytes, maxOutputTokens);
  const authorization = normalizeAuthorization(options.authorization, true);
  validateAuthorizationBindings(authorization, plan, options.identity.publicKey, currentTime);

  const unsignedPlanAuthorization = normalizeAuthorization(plan.authorization, false);
  delete unsignedPlanAuthorization.wallet_signature;
  const unsignedAuthorization = { ...authorization };
  delete unsignedAuthorization.wallet_signature;
  if (canonicalBrowserJson(unsignedPlanAuthorization) !== canonicalBrowserJson(unsignedAuthorization)) {
    throw new BrowserV3ProtocolError("signed wallet authorization does not match the prepared Consumer V3 plan");
  }
  const authorizationMessage = canonicalBrowserJson(unsignedAuthorization);
  if (plan.authorization_message !== authorizationMessage) {
    throw new BrowserV3ProtocolError("Consumer V3 authorization_message does not match its authorization fields");
  }

  const consumerId = options.consumerId ?? options.identity.peerId;
  if (typeof consumerId !== "string" || consumerId.length === 0) {
    throw new BrowserV3ProtocolError("consumer_id is required");
  }
  const reservationDocument: Record<string, unknown> = {
    reservation_version: SETTLEMENT_V3_RESERVATION_VERSION,
    settlement_version: 3,
    request_id: requestId,
    consumer_id: consumerId,
    consumer_public_key: options.identity.publicKey,
    consumer_payment_address: authorization.consumer_payment_address,
    provider_id: plan.provider_id,
    provider_payment_address: plan.provider_payment_address.toLowerCase(),
    channel: plan.channel,
    pricing_hash: plan.pricing_hash.toLowerCase(),
    max_fee_units: plan.max_fee_units,
    expires_at: plan.expires_at,
    settlement_chain_id: plan.chain_id,
    settlement_contract: plan.settlement_contract.toLowerCase(),
    pricing_version: plan.pricing_version,
    onchain_reservation_id: plan.onchain_reservation_id.toLowerCase(),
    request_hash: requestHash,
    settlement_deadline: plan.settlement_deadline,
    provider_fallback_allowed: false,
    evm_session_authorization: authorization,
  };
  return {
    currentTime,
    requestHash,
    reservationDocument,
    messageDocument: (paymentReservation) => ({
      type: "infer",
      request_id: requestId,
      channel: plan.channel,
      network_id: plan.network_id,
      channel_id: plan.channel_id,
      backend_policy: plan.backend_policy,
      endpoint,
      model,
      [requestPayload.field]: requestPayload.value,
      max_output_tokens: maxOutputTokens,
      payment_reservation: paymentReservation,
    }),
  };
}

export function verifyBrowserProviderResponse<T extends Record<string, unknown> = Record<string, unknown>>(
  response: unknown,
  options: VerifyBrowserProviderResponseOptions,
): T {
  if (!browserIsPlainObject(response) || !browserIsPlainObject(response.signature)) {
    throw new BrowserV3ProtocolError("Provider response is missing its identity signature");
  }
  if (response.signature.public_key !== options.providerPublicKey.toLowerCase()) {
    throw new BrowserV3ProtocolError("Provider response signer does not match the selected Provider");
  }
  let unsigned: Record<string, unknown>;
  try {
    unsigned = verifyBrowserDocument(response, {
      purpose: PROVIDER_RESPONSE_PURPOSE,
      audience: canonicalPublicKey(options.consumerPublicKey, "Consumer public key"),
      now: options.now,
    });
  } catch (error) {
    throw new BrowserV3ProtocolError("Provider response signature is invalid", { cause: error });
  }
  if (options.requestId !== undefined && unsigned.request_id !== options.requestId) {
    throw new BrowserV3ProtocolError("Provider response request_id mismatch");
  }
  const binding = validateChannelBinding(options.channelBinding, "expected Provider response");
  for (const [field, expected] of Object.entries(binding)) {
    if (unsigned[field] !== expected) {
      throw new BrowserV3ProtocolError(`Provider response ${field} mismatch`);
    }
  }
  if (options.model !== undefined && unsigned.model !== options.model) {
    throw new BrowserV3ProtocolError("Provider response model mismatch");
  }
  if (options.endpoint !== undefined && unsigned.endpoint !== options.endpoint) {
    throw new BrowserV3ProtocolError("Provider response endpoint mismatch");
  }
  if (options.requestHash !== undefined) {
    const quality = browserIsPlainObject(unsigned.quality) ? unsigned.quality : null;
    if (quality?.request_hash !== options.requestHash) {
      throw new BrowserV3ProtocolError("Provider response request hash mismatch");
    }
  }
  return unsigned as T;
}

function validatePlan(
  plan: BrowserBoundConsumerV3Plan,
  requestHash: string,
  inputSizeBytes: number,
  maxOutputTokens: number,
): BrowserBoundConsumerV3Plan {
  if (!browserIsPlainObject(plan)) throw new BrowserV3ProtocolError("Consumer V3 plan must be an object");
  if (plan.schema !== "mycomesh.consumer.v3.plan.v1") {
    throw new BrowserV3ProtocolError("unsupported Consumer V3 plan schema");
  }
  printableAscii(plan.provider_id, "Provider ID", 256);
  validateChannelBinding(plan, "Consumer V3 plan");
  canonicalAddress(plan.provider_payment_address, "Provider payment address");
  canonicalAddress(plan.settlement_contract, "settlement contract");
  canonicalBytes32(plan.pricing_hash, "pricing hash");
  canonicalBytes32(plan.onchain_reservation_id, "reservation ID");
  canonicalBytes32(plan.request_hash, "plan request hash");
  canonicalBytes32(plan.reservation_salt, "reservation salt");
  const channelHash = canonicalBytes32(plan.channel_hash, "channel hash");
  if (channelHash !== keccak256(stringToHex(plan.channel)).toLowerCase()) {
    throw new BrowserV3ProtocolError("Consumer V3 channel_hash does not match the channel");
  }
  positiveSafeInteger(plan.chain_id, "chain_id");
  positiveSafeInteger(plan.pricing_version, "pricing_version");
  positiveSafeInteger(plan.max_fee_units, "max_fee_units");
  positiveSafeInteger(plan.expires_at, "expires_at");
  positiveSafeInteger(plan.settlement_deadline, "settlement_deadline");
  positiveSafeInteger(plan.required_confirmations, "required_confirmations");
  const declaredInputSize = positiveSafeInteger(plan.input_size_bytes, "input_size_bytes");
  const reserveInputBytes = positiveSafeInteger(plan.reserve_input_bytes, "reserve_input_bytes");
  const reserveOutputTokens = positiveSafeInteger(plan.reserve_output_tokens, "reserve_output_tokens");
  if (declaredInputSize !== inputSizeBytes) {
    throw new BrowserV3ProtocolError("Consumer V3 plan input_size_bytes does not match the inference request");
  }
  if (declaredInputSize > reserveInputBytes) {
    throw new BrowserV3ProtocolError("Consumer V3 input size exceeds the Provider reserve");
  }
  if (maxOutputTokens > reserveOutputTokens) {
    throw new BrowserV3ProtocolError("Consumer V3 output limit exceeds the Provider reserve");
  }
  if (
    !Array.isArray(plan.provider_addresses)
    || plan.provider_addresses.length === 0
    || plan.provider_addresses.some((address) => typeof address !== "string" || !address.trim())
  ) {
    throw new BrowserV3ProtocolError("Consumer V3 provider_addresses must be a non-empty string list");
  }
  if (plan.provider_fallback_allowed !== false) {
    throw new BrowserV3ProtocolError("Consumer V3 plan must disable Provider fallback");
  }
  if (plan.request_hash.toLowerCase() !== requestHash) {
    throw new BrowserV3ProtocolError("Consumer V3 plan request_hash does not match the inference request");
  }
  return plan;
}

function validateChannelBinding(value: BrowserV3ChannelBinding, label: string): BrowserV3ChannelBinding {
  if (!browserIsPlainObject(value)) throw new BrowserV3ProtocolError(`${label} channel binding is required`);
  const actual: BrowserV3ChannelBinding = {
    network_id: printableAscii(value.network_id, `${label} network_id`, 256),
    channel_id: printableAscii(value.channel_id, `${label} channel_id`, 256),
    channel: printableAscii(value.channel, `${label} channel`, 256),
    backend_policy: printableAscii(value.backend_policy, `${label} backend_policy`, 256),
  };
  const enabled: BrowserV3ChannelBinding = {
    network_id: MYCOMESH_TESTNET_NETWORK_ID,
    channel_id: CODEX_CHANNEL_ID,
    channel: CODEX_SETTLEMENT_CHANNEL,
    backend_policy: CODEX_BACKEND_POLICY,
  };
  for (const field of Object.keys(enabled) as Array<keyof BrowserV3ChannelBinding>) {
    if (actual[field] !== enabled[field]) {
      throw new BrowserV3ProtocolError(`${label} ${field} does not match the enabled Codex channel binding`);
    }
  }
  return actual;
}

function normalizeAuthorization(value: unknown, signed: boolean): Record<string, unknown> {
  if (!browserIsPlainObject(value)) {
    throw new BrowserV3ProtocolError("EVM session authorization must be an object");
  }
  const expectedFields = signed ? AUTHORIZATION_FIELDS : AUTHORIZATION_FIELDS.filter((field) => field !== "wallet_signature");
  const expected = new Set<string>(expectedFields);
  const missing = expectedFields.filter((field) => !Object.hasOwn(value, field));
  const unknown = Object.keys(value).filter((field) => !expected.has(field));
  if (missing.length > 0 || unknown.length > 0) {
    const details = [
      missing.length > 0 ? `missing ${missing.sort().join(", ")}` : "",
      unknown.length > 0 ? `unexpected ${unknown.sort().join(", ")}` : "",
    ].filter(Boolean).join("; ");
    throw new BrowserV3ProtocolError(`invalid EVM session authorization fields: ${details}`);
  }
  if (value.authorization_version !== EVM_SESSION_AUTHORIZATION_VERSION) {
    throw new BrowserV3ProtocolError("unsupported EVM session authorization version");
  }
  const normalized: Record<string, unknown> = {
    authorization_version: EVM_SESSION_AUTHORIZATION_VERSION,
    chain_id: positiveSafeInteger(value.chain_id, "authorization chain_id"),
    settlement_contract: canonicalAddress(value.settlement_contract, "authorization settlement_contract"),
    onchain_reservation_id: canonicalBytes32(value.onchain_reservation_id, "authorization reservation ID"),
    consumer_payment_address: canonicalAddress(value.consumer_payment_address, "authorization Consumer address"),
    provider_id: printableAscii(value.provider_id, "authorization Provider ID", 256),
    provider_payment_address: canonicalAddress(value.provider_payment_address, "authorization Provider address"),
    channel: printableAscii(value.channel, "authorization channel", 256),
    pricing_hash: canonicalBytes32(value.pricing_hash, "authorization pricing hash"),
    pricing_version: positiveSafeInteger(value.pricing_version, "authorization pricing_version"),
    request_hash: canonicalBytes32(value.request_hash, "authorization request hash"),
    max_fee_units: positiveSafeInteger(value.max_fee_units, "authorization max_fee_units"),
    expires_at: positiveSafeInteger(value.expires_at, "authorization expires_at"),
    settlement_deadline: positiveSafeInteger(value.settlement_deadline, "authorization settlement_deadline"),
    provider_fallback_allowed: value.provider_fallback_allowed,
    nonce: canonicalBytes32(value.nonce, "authorization nonce"),
    session_public_key: canonicalPublicKey(value.session_public_key, "authorization session public key"),
  };
  if (typeof normalized.provider_fallback_allowed !== "boolean") {
    throw new BrowserV3ProtocolError("authorization provider_fallback_allowed must be a boolean");
  }
  if ((normalized.settlement_deadline as number) > (normalized.expires_at as number)) {
    throw new BrowserV3ProtocolError("authorization settlement deadline exceeds expiry");
  }
  if (signed) normalized.wallet_signature = canonicalWalletSignature(value.wallet_signature);
  return normalized;
}

function validateAuthorizationBindings(
  authorization: Record<string, unknown>,
  plan: ConsumerV3Plan,
  identityPublicKey: string,
  now: number,
): void {
  const expected: Array<[string, unknown, unknown]> = [
    ["chain_id", authorization.chain_id, plan.chain_id],
    ["settlement_contract", authorization.settlement_contract, plan.settlement_contract.toLowerCase()],
    ["onchain_reservation_id", authorization.onchain_reservation_id, plan.onchain_reservation_id.toLowerCase()],
    ["provider_id", authorization.provider_id, plan.provider_id],
    ["provider_payment_address", authorization.provider_payment_address, plan.provider_payment_address.toLowerCase()],
    ["channel", authorization.channel, plan.channel],
    ["pricing_hash", authorization.pricing_hash, plan.pricing_hash.toLowerCase()],
    ["pricing_version", authorization.pricing_version, plan.pricing_version],
    ["request_hash", authorization.request_hash, plan.request_hash.toLowerCase()],
    ["max_fee_units", authorization.max_fee_units, plan.max_fee_units],
    ["expires_at", authorization.expires_at, plan.expires_at],
    ["settlement_deadline", authorization.settlement_deadline, plan.settlement_deadline],
    ["provider_fallback_allowed", authorization.provider_fallback_allowed, false],
    ["session_public_key", authorization.session_public_key, identityPublicKey],
  ];
  for (const [field, actual, wanted] of expected) {
    if (actual !== wanted) throw new BrowserV3ProtocolError(`EVM session authorization ${field} mismatch`);
  }
  const expiresAt = authorization.expires_at as number;
  const deadline = authorization.settlement_deadline as number;
  if (expiresAt <= now || expiresAt > now + MAX_RESERVATION_TTL_SECONDS) {
    throw new BrowserV3ProtocolError("authorization expires_at must be within the next 30 days");
  }
  if (deadline <= now || deadline > expiresAt) {
    throw new BrowserV3ProtocolError("authorization settlement deadline must be active and no later than expires_at");
  }
}

function normalizedInferencePayload(
  input: BrowserV3InferenceInput,
): { field: "input" | "messages"; value: unknown } {
  if (input.endpoint === "chat") {
    if (input.messages !== undefined) return canonicalPayload("messages", input.messages);
    const fallback = typeof input.input === "string" ? input.input : input.input == null ? "" : null;
    if (fallback === null) {
      throw new BrowserV3ProtocolError("chat input must be text when messages are omitted");
    }
    return canonicalPayload("messages", [{ role: "user", content: fallback }]);
  }
  return canonicalPayload("input", input.input === undefined ? "" : input.input);
}

function canonicalPayload(field: "input" | "messages", value: unknown): { field: "input" | "messages"; value: unknown } {
  try {
    canonicalBrowserJson(value);
  } catch (error) {
    throw new BrowserV3ProtocolError(`inference ${field} must contain canonical JSON data`, { cause: error });
  }
  return { field, value };
}

function normalizedEndpoint(value: unknown): "responses" | "chat" {
  if (value !== "responses" && value !== "chat") {
    throw new BrowserV3ProtocolError("inference endpoint must be responses or chat");
  }
  return value;
}

function canonicalRequestId(value: unknown): string {
  if (typeof value !== "string" || !REQUEST_ID_PATTERN.test(value)) {
    throw new BrowserV3ProtocolError("request_id is malformed");
  }
  return value;
}

function protocolTime(value: unknown, label: string): number {
  try {
    return protocolTimestamp(value, label);
  } catch (error) {
    throw new BrowserV3ProtocolError(`${label} must be a non-negative integer`, { cause: error });
  }
}

function positiveSafeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new BrowserV3ProtocolError(`${label} must be a positive safe integer`);
  }
  return value as number;
}

function nonemptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new BrowserV3ProtocolError(`${label} must be non-empty text`);
  }
  return value;
}

function printableAscii(value: unknown, label: string, maximum: number): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maximum
    || !/^[\x21-\x7e]+$/.test(value)
  ) {
    throw new BrowserV3ProtocolError(`${label} must use printable ASCII without whitespace`);
  }
  return value;
}

function canonicalAddress(value: unknown, label: string): string {
  if (typeof value !== "string" || !ADDRESS_PATTERN.test(value) || /^0x0+$/.test(value)) {
    throw new BrowserV3ProtocolError(`${label} must be a non-zero canonical lowercase EVM address`);
  }
  return value;
}

function canonicalBytes32(value: unknown, label: string): string {
  if (typeof value !== "string" || !BYTES32_PATTERN.test(value) || /^0x0+$/.test(value)) {
    throw new BrowserV3ProtocolError(`${label} must be a non-zero canonical lowercase bytes32 value`);
  }
  return value;
}

function canonicalPublicKey(value: unknown, label: string): string {
  if (typeof value !== "string" || !PUBLIC_KEY_PATTERN.test(value)) {
    throw new BrowserV3ProtocolError(`${label} must be a canonical Ed25519 public key`);
  }
  return value;
}

function canonicalWalletSignature(value: unknown): string {
  if (
    typeof value !== "string"
    || !WALLET_SIGNATURE_PATTERN.test(value)
    || value.length % 2 !== 0
    || (value.length - 2) / 2 < 1
    || (value.length - 2) / 2 > MAX_EVM_WALLET_SIGNATURE_BYTES
  ) {
    throw new BrowserV3ProtocolError("wallet_signature must be canonical lowercase 0x-prefixed hex");
  }
  return value;
}
