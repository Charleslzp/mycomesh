import {
  encodeAbiParameters,
  getAddress,
  hashTypedData,
  isAddressEqual,
  keccak256,
  recoverTypedDataAddress,
  sha256,
  stringToHex,
  type Address,
  type Hex,
} from "viem";
import type {
  ConsumerV3Authorization,
  ConsumerV3Plan,
  InferenceResult,
  ProviderV3Receipt,
  ProviderV3Settlement,
} from "./api";

const SETTLEMENT_SCHEMA = "mycomesh.settlement.v3.provider.v1";
const PLAN_SCHEMA = "mycomesh.consumer.v3.plan.v1";
const AUTHORIZATION_VERSION = "mycomesh.evm.session.v1";
const REQUEST_HASH_VERSION = "mycomesh.inference.request.v2";
const EIP712_NAME = "MycoMesh Settlement";
const EIP712_VERSION = "3";
const ZERO_BYTES32 = "0x" + "0".repeat(64);
const ZERO_ADDRESS = "0x" + "0".repeat(40);
const SECP256K1_HALF_ORDER =
  0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
const RECEIPT_COMMITMENT_TYPE =
  "MycoMeshV3ReceiptCommitment(bytes32 reservationId,bytes32 requestHash,bytes32 responseHash,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,address consumer,address provider,address relay,address pool,uint256 inputTokens,uint256 outputTokens,uint256 deadline)";
const ACCEPTANCE_COMMITMENT_TYPE =
  "MycoMeshV3ConsumerAcceptance(bytes32 receiptHash,bytes32 reservationId,address consumer,address provider)";

const settlementFields = [
  "schema",
  "chain_id",
  "settlement_contract",
  "receipt",
  "receipt_digest",
  "provider_signature",
] as const;

const receiptFields = [
  "receipt_hash",
  "accepted_hash",
  "reservation_id",
  "request_hash",
  "response_hash",
  "channel",
  "pricing_version",
  "pricing_hash",
  "consumer",
  "provider",
  "relay",
  "pool",
  "input_tokens",
  "output_tokens",
  "deadline",
] as const;

const planFields = [
  "schema",
  "provider_id",
  "provider_payment_address",
  "provider_addresses",
  "chain_id",
  "settlement_contract",
  "channel",
  "channel_hash",
  "pricing_version",
  "pricing_hash",
  "request_hash",
  "input_size_bytes",
  "reserve_input_bytes",
  "reserve_output_tokens",
  "max_fee_units",
  "expires_at",
  "settlement_deadline",
  "provider_fallback_allowed",
  "reservation_salt",
  "onchain_reservation_id",
  "required_confirmations",
  "authorization",
  "authorization_message",
] as const;

const authorizationFields = [
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
] as const;

export const v3ReceiptTypes = {
  Receipt: [
    { name: "receiptHash", type: "bytes32" },
    { name: "acceptedHash", type: "bytes32" },
    { name: "reservationId", type: "bytes32" },
    { name: "requestHash", type: "bytes32" },
    { name: "responseHash", type: "bytes32" },
    { name: "channel", type: "bytes32" },
    { name: "pricingVersion", type: "uint64" },
    { name: "pricingHash", type: "bytes32" },
    { name: "consumer", type: "address" },
    { name: "provider", type: "address" },
    { name: "relay", type: "address" },
    { name: "pool", type: "address" },
    { name: "inputTokens", type: "uint256" },
    { name: "outputTokens", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

export interface ConsumerV3PlanExpectations {
  chainId: number;
  settlementContract: Address;
  consumer: Address;
  providerId: string;
  providerPaymentAddress: Address;
  inputSizeBytes?: number;
  maxOutputTokens?: number;
  reserveInputBytes?: number;
  reserveOutputTokens?: number;
  requestHash?: Hex;
  channel?: string;
}

export interface V3SettlementExpectations extends ConsumerV3PlanExpectations {
  plan: ConsumerV3Plan;
  response: InferenceResult;
  providerFallbackAllowed: boolean;
  now?: number;
}

export interface V3ContractReceipt {
  receiptHash: Hex;
  acceptedHash: Hex;
  reservationId: Hex;
  requestHash: Hex;
  responseHash: Hex;
  channel: Hex;
  pricingVersion: bigint;
  pricingHash: Hex;
  consumer: Address;
  provider: Address;
  relay: Address;
  pool: Address;
  inputTokens: bigint;
  outputTokens: bigint;
  deadline: bigint;
}

export interface ValidatedV3Settlement {
  payload: ProviderV3Settlement;
  contractReceipt: V3ContractReceipt;
  providerSignature: Hex;
  typedData: ReturnType<typeof buildV3ReceiptTypedData>;
}

export function assertConsumerV3Plan(
  value: unknown,
  expected: ConsumerV3PlanExpectations,
): asserts value is ConsumerV3Plan {
  const plan = exactObject(value, planFields, "Consumer V3 plan");
  const authorization = exactObject(
    plan.authorization,
    authorizationFields,
    "Consumer V3 authorization",
  );

  if (plan.schema !== PLAN_SCHEMA) {
    throw new Error("Unsupported Consumer V3 plan schema.");
  }
  if (authorization.authorization_version !== AUTHORIZATION_VERSION) {
    throw new Error("Unsupported Consumer V3 authorization version.");
  }

  const chainId = positiveUint(plan.chain_id, "Consumer V3 chain_id");
  const authorizationChainId = positiveUint(
    authorization.chain_id,
    "Consumer V3 authorization chain_id",
  );
  if (chainId !== expected.chainId || authorizationChainId !== expected.chainId) {
    throw new Error("The Consumer V3 plan does not match the configured chain.");
  }

  const settlementContract = address(
    plan.settlement_contract,
    "Consumer V3 settlement_contract",
    false,
  );
  const authorizationContract = address(
    authorization.settlement_contract,
    "Consumer V3 authorization settlement_contract",
    false,
  );
  if (
    !isAddressEqual(settlementContract, expected.settlementContract) ||
    !isAddressEqual(authorizationContract, expected.settlementContract)
  ) {
    throw new Error("The Consumer V3 plan does not match the configured settlement contract.");
  }

  if (
    plan.provider_fallback_allowed !== false ||
    authorization.provider_fallback_allowed !== false
  ) {
    throw new Error("Consumer V3 provider fallback must remain disabled.");
  }
  if (
    text(plan.provider_id, "Consumer V3 provider_id") !== expected.providerId ||
    text(authorization.provider_id, "Consumer V3 authorization provider_id") !==
      expected.providerId
  ) {
    throw new Error("The Consumer V3 plan selected a different Provider.");
  }

  const provider = address(
    plan.provider_payment_address,
    "Consumer V3 provider_payment_address",
    false,
  );
  const authorizationProvider = address(
    authorization.provider_payment_address,
    "Consumer V3 authorization provider_payment_address",
    false,
  );
  if (
    !isAddressEqual(provider, expected.providerPaymentAddress) ||
    !isAddressEqual(authorizationProvider, expected.providerPaymentAddress)
  ) {
    throw new Error("The Consumer V3 plan Provider payment address does not match discovery.");
  }

  const consumer = address(
    authorization.consumer_payment_address,
    "Consumer V3 consumer_payment_address",
    false,
  );
  if (!isAddressEqual(consumer, expected.consumer)) {
    throw new Error("The Consumer V3 plan belongs to a different Consumer wallet.");
  }

  const providerAddresses = plan.provider_addresses;
  if (
    !Array.isArray(providerAddresses) ||
    providerAddresses.length === 0 ||
    providerAddresses.some((item) => typeof item !== "string" || !item.trim())
  ) {
    throw new Error("Consumer V3 provider_addresses must be a non-empty string list.");
  }

  const inputSizeBytes = positiveUint(
    plan.input_size_bytes,
    "Consumer V3 input_size_bytes",
  );
  const reserveInputBytes = positiveUint(
    plan.reserve_input_bytes,
    "Consumer V3 reserve_input_bytes",
  );
  const reserveOutputTokens = positiveUint(
    plan.reserve_output_tokens,
    "Consumer V3 reserve_output_tokens",
  );
  if (inputSizeBytes > reserveInputBytes) {
    throw new Error("Consumer V3 input size exceeds the Provider reserve.");
  }
  if (expected.inputSizeBytes !== undefined && inputSizeBytes !== expected.inputSizeBytes) {
    throw new Error("Consumer V3 input size does not match this request.");
  }
  if (
    expected.maxOutputTokens !== undefined &&
    positiveUint(expected.maxOutputTokens, "requested maximum output tokens") >
      reserveOutputTokens
  ) {
    throw new Error("Consumer V3 output limit exceeds the Provider reserve.");
  }
  if (
    expected.reserveInputBytes !== undefined &&
    reserveInputBytes !== expected.reserveInputBytes
  ) {
    throw new Error("Consumer V3 input reserve does not match the published network limit.");
  }
  if (
    expected.reserveOutputTokens !== undefined &&
    reserveOutputTokens !== expected.reserveOutputTokens
  ) {
    throw new Error("Consumer V3 output reserve does not match the published network limit.");
  }

  const pairs: Array<[unknown, unknown, string]> = [
    [plan.onchain_reservation_id, authorization.onchain_reservation_id, "reservation ID"],
    [plan.request_hash, authorization.request_hash, "request hash"],
    [plan.pricing_hash, authorization.pricing_hash, "pricing hash"],
  ];
  for (const [left, right, label] of pairs) {
    if (bytes32(left, "Consumer V3 " + label) !== bytes32(right, "authorization " + label)) {
      throw new Error("Consumer V3 " + label + " mismatch.");
    }
  }
  if (
    expected.requestHash !== undefined &&
    bytes32(plan.request_hash, "Consumer V3 request hash") !==
      bytes32(expected.requestHash, "expected request hash")
  ) {
    throw new Error("Consumer V3 request hash does not match this request.");
  }

  const numericPairs: Array<[unknown, unknown, string, boolean]> = [
    [plan.pricing_version, authorization.pricing_version, "pricing version", true],
    [plan.max_fee_units, authorization.max_fee_units, "maximum fee", true],
    [plan.expires_at, authorization.expires_at, "expiry", true],
    [plan.settlement_deadline, authorization.settlement_deadline, "settlement deadline", true],
  ];
  for (const [left, right, label, positive] of numericPairs) {
    const leftValue = positive
      ? positiveUint(left, "Consumer V3 " + label)
      : uint(left, "Consumer V3 " + label);
    const rightValue = positive
      ? positiveUint(right, "authorization " + label)
      : uint(right, "authorization " + label);
    if (leftValue !== rightValue) {
      throw new Error("Consumer V3 " + label + " mismatch.");
    }
  }

  if (positiveUint(plan.settlement_deadline, "Consumer V3 settlement deadline") > positiveUint(plan.expires_at, "Consumer V3 expiry")) {
    throw new Error("Consumer V3 settlement deadline exceeds the reservation expiry.");
  }
  positiveUint(plan.required_confirmations, "Consumer V3 required_confirmations");
  const channel = text(plan.channel, "Consumer V3 channel");
  const channelHash = bytes32(plan.channel_hash, "Consumer V3 channel_hash");
  if (channelHash !== keccak256(stringToHex(channel)).toLowerCase()) {
    throw new Error("Consumer V3 channel_hash does not match the channel.");
  }
  if (expected.channel !== undefined && channel !== expected.channel) {
    throw new Error("Consumer V3 channel does not match Provider discovery.");
  }
  bytes32(plan.reservation_salt, "Consumer V3 reservation_salt");
  bytes32(authorization.nonce, "Consumer V3 authorization nonce");
  if (!/^[0-9a-fA-F]{64}$/.test(text(authorization.session_public_key, "session_public_key"))) {
    throw new Error("Consumer V3 session_public_key must be a 32-byte hex key.");
  }
  if (channel !== text(authorization.channel, "authorization channel")) {
    throw new Error("Consumer V3 channel mismatch.");
  }
  if (
    text(plan.authorization_message, "Consumer V3 authorization_message") !==
    consumerV3AuthorizationMessage(authorization as unknown as ConsumerV3Authorization)
  ) {
    throw new Error("Consumer V3 authorization_message does not match its authorization fields.");
  }
}

export function consumerV3RequestHash(
  input: string,
  model: string,
  maxOutputTokens: number,
): Hex {
  positiveUint(maxOutputTokens, "maximum output tokens");
  if (!model) throw new Error("Consumer V3 request model must be non-empty.");
  return sha256(
    stringToHex(
      compactStableJson({
        request_hash_version: REQUEST_HASH_VERSION,
        endpoint: "responses",
        model,
        input,
        max_output_tokens: maxOutputTokens,
      }),
    ),
  );
}

export function consumerV3AuthorizationMessage(
  authorization: ConsumerV3Authorization,
): string {
  const normalized: Record<string, unknown> = {};
  const lowercaseFields = new Set([
    "settlement_contract",
    "onchain_reservation_id",
    "consumer_payment_address",
    "provider_payment_address",
    "pricing_hash",
    "request_hash",
    "nonce",
    "session_public_key",
  ]);
  for (const field of authorizationFields) {
    const value = authorization[field as keyof ConsumerV3Authorization];
    normalized[field] =
      lowercaseFields.has(field) && typeof value === "string"
        ? value.toLowerCase()
        : value;
  }
  return compactStableJson(normalized, true);
}

export async function validateV3Settlement(
  value: unknown,
  expected: V3SettlementExpectations,
): Promise<ValidatedV3Settlement> {
  if (expected.providerFallbackAllowed !== false || expected.plan.provider_fallback_allowed !== false) {
    throw new Error("Settlement is blocked because Provider fallback is enabled.");
  }
  assertConsumerV3Plan(expected.plan, expected);

  const raw = exactObject(value, settlementFields, "Provider V3 settlement");
  if (raw.schema !== SETTLEMENT_SCHEMA) {
    throw new Error("Unsupported Provider V3 settlement schema.");
  }
  const chainId = positiveUint(raw.chain_id, "Provider V3 chain_id");
  if (chainId !== expected.chainId) {
    throw new Error("Provider V3 settlement chain does not match the connected wallet.");
  }

  const settlementContract = address(
    raw.settlement_contract,
    "Provider V3 settlement_contract",
    false,
  );
  if (!isAddressEqual(settlementContract, expected.settlementContract)) {
    throw new Error("Provider V3 settlement contract does not match this deployment.");
  }

  const receiptValue = exactObject(raw.receipt, receiptFields, "Provider V3 receipt");
  const receipt: ProviderV3Receipt = {
    receipt_hash: nonzeroBytes32(receiptValue.receipt_hash, "receipt_hash"),
    accepted_hash: nonzeroBytes32(receiptValue.accepted_hash, "accepted_hash"),
    reservation_id: nonzeroBytes32(receiptValue.reservation_id, "reservation_id"),
    request_hash: nonzeroBytes32(receiptValue.request_hash, "request_hash"),
    response_hash: nonzeroBytes32(receiptValue.response_hash, "response_hash"),
    channel: nonzeroBytes32(receiptValue.channel, "channel"),
    pricing_version: positiveUint(receiptValue.pricing_version, "pricing_version"),
    pricing_hash: nonzeroBytes32(receiptValue.pricing_hash, "pricing_hash"),
    consumer: address(receiptValue.consumer, "consumer", false),
    provider: address(receiptValue.provider, "provider", false),
    relay: address(receiptValue.relay, "relay", true),
    pool: address(receiptValue.pool, "pool", true),
    input_tokens: uint(receiptValue.input_tokens, "input_tokens"),
    output_tokens: uint(receiptValue.output_tokens, "output_tokens"),
    deadline: positiveUint(receiptValue.deadline, "deadline"),
  };

  const usage = expected.response.usage;
  const inputTokens = usage?.input_tokens;
  const outputTokens = usage?.output_tokens;
  if (
    !usage ||
    typeof inputTokens !== "number" ||
    typeof outputTokens !== "number" ||
    !Number.isSafeInteger(inputTokens) ||
    !Number.isSafeInteger(outputTokens) ||
    inputTokens < 0 ||
    outputTokens < 0
  ) {
    throw new Error("Inference usage is required to validate the V3 Receipt.");
  }
  if (receipt.input_tokens !== inputTokens || receipt.output_tokens !== outputTokens) {
    throw new Error("Provider V3 Receipt usage does not match the returned inference usage.");
  }
  const reserveInputBytes = positiveUint(
    expected.plan.reserve_input_bytes,
    "Consumer V3 reserve_input_bytes",
  );
  const reserveOutputTokens = positiveUint(
    expected.plan.reserve_output_tokens,
    "Consumer V3 reserve_output_tokens",
  );
  if (receipt.input_tokens > reserveInputBytes) {
    throw new Error("Provider V3 Receipt input usage exceeds the Provider reserve.");
  }
  if (receipt.output_tokens > reserveOutputTokens) {
    throw new Error("Provider V3 Receipt output usage exceeds the Provider reserve.");
  }
  if (
    expected.maxOutputTokens !== undefined &&
    receipt.output_tokens > expected.maxOutputTokens
  ) {
    throw new Error("Provider V3 Receipt output usage exceeds the Consumer request cap.");
  }
  if (receipt.relay.toLowerCase() !== ZERO_ADDRESS || receipt.pool.toLowerCase() !== ZERO_ADDRESS) {
    throw new Error("Provider V3 Receipt contains an unexpected relay or pool payee.");
  }

  if (isAddressEqual(receipt.consumer, receipt.provider)) {
    throw new Error("Provider V3 receipt Consumer and Provider must differ.");
  }
  if (!isAddressEqual(receipt.consumer, expected.consumer)) {
    throw new Error("Provider V3 receipt belongs to a different Consumer wallet.");
  }
  if (!isAddressEqual(receipt.provider, expected.providerPaymentAddress)) {
    throw new Error("Provider V3 receipt was signed for a different Provider.");
  }

  const bindings: Array<[Hex, unknown, string]> = [
    [receipt.reservation_id, expected.plan.onchain_reservation_id, "reservation_id"],
    [receipt.request_hash, expected.plan.request_hash, "request_hash"],
    [receipt.channel, expected.plan.channel_hash, "channel"],
    [receipt.pricing_hash, expected.plan.pricing_hash, "pricing_hash"],
  ];
  for (const [actual, planned, label] of bindings) {
    if (actual.toLowerCase() !== bytes32(planned, "plan " + label).toLowerCase()) {
      throw new Error("Provider V3 receipt " + label + " does not match the reservation.");
    }
  }
  if (receipt.pricing_version !== expected.plan.pricing_version) {
    throw new Error("Provider V3 receipt pricing_version does not match the reservation.");
  }
  if (receipt.deadline !== expected.plan.settlement_deadline) {
    throw new Error("Provider V3 receipt deadline does not match the reservation.");
  }
  const now = Math.floor(expected.now ?? Date.now() / 1000);
  if (receipt.deadline <= now) {
    throw new Error("Provider V3 receipt has expired.");
  }

  const responseHash = settlementResponseHash(expected.response);
  if (receipt.response_hash.toLowerCase() !== responseHash.toLowerCase()) {
    throw new Error("Provider V3 receipt is not bound to the returned inference output.");
  }

  const commitments = computeV3ReceiptCommitments(receipt);
  if (receipt.receipt_hash.toLowerCase() !== commitments.receiptHash.toLowerCase()) {
    throw new Error("Provider V3 receipt_hash commitment is invalid.");
  }
  if (receipt.accepted_hash.toLowerCase() !== commitments.acceptedHash.toLowerCase()) {
    throw new Error("Provider V3 accepted_hash commitment is invalid.");
  }

  const payload: ProviderV3Settlement = {
    schema: SETTLEMENT_SCHEMA,
    chain_id: chainId,
    settlement_contract: settlementContract,
    receipt,
    receipt_digest: nonzeroBytes32(raw.receipt_digest, "receipt_digest"),
    provider_signature: providerSignature(raw.provider_signature),
  };
  const typedData = buildV3ReceiptTypedData(payload);
  const digest = hashTypedData(typedData);
  if (payload.receipt_digest.toLowerCase() !== digest.toLowerCase()) {
    throw new Error("Provider V3 receipt_digest does not match the EIP-712 receipt.");
  }

  let recoveredProvider: Address;
  try {
    recoveredProvider = await recoverTypedDataAddress({
      ...typedData,
      signature: payload.provider_signature,
    });
  } catch {
    throw new Error("Provider V3 signature is invalid.");
  }
  if (!isAddressEqual(recoveredProvider, receipt.provider)) {
    throw new Error("Provider V3 signature does not recover the receipt Provider.");
  }

  return {
    payload,
    contractReceipt: toContractReceipt(receipt),
    providerSignature: payload.provider_signature,
    typedData,
  };
}

export function buildV3ReceiptTypedData(payload: ProviderV3Settlement) {
  const receipt = payload.receipt;
  return {
    domain: {
      name: EIP712_NAME,
      version: EIP712_VERSION,
      chainId: payload.chain_id,
      verifyingContract: payload.settlement_contract as Address,
    },
    types: v3ReceiptTypes,
    primaryType: "Receipt" as const,
    message: {
      receiptHash: receipt.receipt_hash,
      acceptedHash: receipt.accepted_hash,
      reservationId: receipt.reservation_id,
      requestHash: receipt.request_hash,
      responseHash: receipt.response_hash,
      channel: receipt.channel,
      pricingVersion: BigInt(receipt.pricing_version),
      pricingHash: receipt.pricing_hash,
      consumer: receipt.consumer as Address,
      provider: receipt.provider as Address,
      relay: receipt.relay as Address,
      pool: receipt.pool as Address,
      inputTokens: BigInt(receipt.input_tokens),
      outputTokens: BigInt(receipt.output_tokens),
      deadline: BigInt(receipt.deadline),
    },
  } as const;
}

export function computeV3ReceiptCommitments(receipt: ProviderV3Receipt): {
  receiptHash: Hex;
  acceptedHash: Hex;
} {
  const receiptHash = keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint64" },
        { type: "bytes32" },
        { type: "address" },
        { type: "address" },
        { type: "address" },
        { type: "address" },
        { type: "uint256" },
        { type: "uint256" },
        { type: "uint256" },
      ],
      [
        keccak256(stringToHex(RECEIPT_COMMITMENT_TYPE)),
        receipt.reservation_id,
        receipt.request_hash,
        receipt.response_hash,
        receipt.channel,
        BigInt(receipt.pricing_version),
        receipt.pricing_hash,
        receipt.consumer,
        receipt.provider,
        receipt.relay,
        receipt.pool,
        BigInt(receipt.input_tokens),
        BigInt(receipt.output_tokens),
        BigInt(receipt.deadline),
      ],
    ),
  );
  const acceptedHash = keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "address" },
        { type: "address" },
      ],
      [
        keccak256(stringToHex(ACCEPTANCE_COMMITMENT_TYPE)),
        receiptHash,
        receipt.reservation_id,
        receipt.consumer,
        receipt.provider,
      ],
    ),
  );
  return { receiptHash, acceptedHash };
}

export function settlementResponseHash(response: InferenceResult): Hex {
  const value =
    typeof response.output_text === "string" && response.output_text.length > 0
      ? response.output_text
      : response.raw;
  if (value === undefined) {
    throw new Error("Inference response has no output value to bind to settlement.");
  }
  return sha256(stringToHex(pythonStableJson(value)));
}

function toContractReceipt(receipt: ProviderV3Receipt): V3ContractReceipt {
  return {
    receiptHash: receipt.receipt_hash,
    acceptedHash: receipt.accepted_hash,
    reservationId: receipt.reservation_id,
    requestHash: receipt.request_hash,
    responseHash: receipt.response_hash,
    channel: receipt.channel,
    pricingVersion: BigInt(receipt.pricing_version),
    pricingHash: receipt.pricing_hash,
    consumer: receipt.consumer as Address,
    provider: receipt.provider as Address,
    relay: receipt.relay as Address,
    pool: receipt.pool as Address,
    inputTokens: BigInt(receipt.input_tokens),
    outputTokens: BigInt(receipt.output_tokens),
    deadline: BigInt(receipt.deadline),
  };
}

function exactObject<const fields extends readonly string[]>(
  value: unknown,
  fields: fields,
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(label + " must be a JSON object.");
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const required = [...fields].sort();
  if (
    actual.length !== required.length ||
    actual.some((field, index) => field !== required[index])
  ) {
    throw new Error(label + " fields are invalid.");
  }
  return record;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(label + " must be non-empty text.");
  }
  return value.trim();
}

function bytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(label + " must be a 32-byte hex value.");
  }
  return value.toLowerCase() as Hex;
}

function nonzeroBytes32(value: unknown, label: string): Hex {
  const normalized = bytes32(value, label);
  if (normalized === ZERO_BYTES32) {
    throw new Error(label + " must be non-zero.");
  }
  return normalized;
}

function address(value: unknown, label: string, allowZero: boolean): Address {
  if (typeof value !== "string") {
    throw new Error(label + " must be an address.");
  }
  let normalized: Address;
  try {
    normalized = getAddress(value);
  } catch {
    throw new Error(label + " must be a valid address.");
  }
  if (!allowZero && /^0x0{40}$/i.test(normalized)) {
    throw new Error(label + " must be non-zero.");
  }
  return normalized;
}

function uint(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(label + " must be a non-negative safe integer.");
  }
  return Number(value);
}

function positiveUint(value: unknown, label: string): number {
  const normalized = uint(value, label);
  if (normalized === 0) {
    throw new Error(label + " must be positive.");
  }
  return normalized;
}

function providerSignature(value: unknown): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(value)) {
    throw new Error("provider_signature must be a 65-byte hex signature.");
  }
  const r = BigInt("0x" + value.slice(2, 66));
  const s = BigInt("0x" + value.slice(66, 130));
  const v = value.slice(130, 132).toLowerCase();
  if (r === 0n || s === 0n || s > SECP256K1_HALF_ORDER || !["00", "01", "1b", "1c"].includes(v)) {
    throw new Error("provider_signature is not canonical.");
  }
  return value.toLowerCase() as Hex;
}

function compactStableJson(value: unknown, ensureAscii = false): string {
  if (value === null) return "null";
  if (typeof value === "string") {
    const encoded = JSON.stringify(value);
    return ensureAscii
      ? encoded.replace(/[\u007f-\uffff]/g, (character) =>
          "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"),
        )
      : encoded;
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Canonical JSON contains a number outside the safe integer range.");
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => compactStableJson(item, ensureAscii)).join(",") + "]";
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(record)
        .sort()
        .map(
          (key) =>
            compactStableJson(key, ensureAscii) +
            ":" +
            compactStableJson(record[key], ensureAscii),
        )
        .join(",") +
      "}"
    );
  }
  throw new Error("Canonical JSON contains an unsupported value.");
}

function pythonStableJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Inference raw output contains a number that cannot be hashed safely.");
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => pythonStableJson(item)).join(", ") + "]";
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(record)
        .sort()
        .map((key) => JSON.stringify(key) + ": " + pythonStableJson(record[key]))
        .join(", ") +
      "}"
    );
  }
  throw new Error("Inference output contains a value that cannot be hashed safely.");
}
