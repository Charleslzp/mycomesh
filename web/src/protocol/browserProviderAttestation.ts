import { recoverTypedDataAddress } from "viem";
import type {
  ConsumerV3Authorization,
  ConsumerV3Plan,
  InferenceResult,
} from "./api";
import type { VerifiedBrowserProvider } from "./browserConsumerDiscovery";
import {
  browserIsPlainObject,
  browserPeerIdFromPublicKey,
  BrowserConsumerProtocolError,
  verifyBrowserDocument,
} from "./browserConsumerIdentity";
import {
  CODEX_BACKEND_POLICY,
  CODEX_CHANNEL_ID,
  CODEX_SETTLEMENT_CHANNEL,
  MYCOMESH_TESTNET_NETWORK_ID,
} from "./browserConsumerV3";
import {
  settlementResponseHash,
  type ValidatedV3Settlement,
} from "./settlementV3";

export const PROVIDER_SETTLEMENT_ATTESTATION_VERSION = "mycomesh-provider-attestation-v1";
export const PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE =
  "mycomesh.settlement.provider_attestation.v1";

const ATTESTATION_FIELDS = [
  "attestation_version",
  "request_id",
  "request_hash",
  "response_hash",
  "channel",
  "model",
  "endpoint",
  "input_tokens",
  "output_tokens",
  "gross_fee_units",
  "consumer_id",
  "consumer_public_key",
  "consumer_payment_address",
  "provider_id",
  "provider_payment_address",
  "pricing_hash",
  "settlement_version",
  "pricing_version",
  "onchain_reservation_id",
  "settlement_deadline",
  "network_id",
  "channel_id",
  "backend_policy",
  "signature",
] as const;

const SIGNATURE_FIELDS = [
  "nonce",
  "public_key",
  "purpose",
  "timestamp",
  "audience",
  "signature",
] as const;

const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;
const NONCE_PATTERN = /^[0-9a-f]{32}$/;
const SIGNATURE_PATTERN = /^[0-9a-f]{128}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^(?:0x)?[0-9a-f]{64}$/;
const MAX_ATTESTATION_TEXT_BYTES = 512;

export interface BrowserProviderSettlementAttestation {
  attestation_version: typeof PROVIDER_SETTLEMENT_ATTESTATION_VERSION;
  request_id: string;
  request_hash: string;
  response_hash: string;
  channel: string;
  model: string;
  endpoint: string;
  input_tokens: number;
  output_tokens: number;
  gross_fee_units: number;
  consumer_id: string;
  consumer_public_key: string;
  consumer_payment_address: string;
  provider_id: string;
  provider_payment_address: string;
  pricing_hash: string;
  settlement_version: 3;
  pricing_version: number;
  onchain_reservation_id: string;
  settlement_deadline: number;
  network_id: string;
  channel_id: string;
  backend_policy: string;
  signature: {
    nonce: string;
    public_key: string;
    purpose: typeof PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE;
    timestamp: number;
    audience: string;
    signature: string;
  };
}

export interface VerifyBrowserProviderSettlementAttestationOptions {
  response: InferenceResult;
  provider: VerifiedBrowserProvider;
  plan: ConsumerV3Plan;
  authorization: ConsumerV3Authorization;
  consumerPublicKey: string;
  consumerId: string;
  requestId: string;
  requestHash: string;
  model: string;
  endpoint: "responses" | "chat";
  validatedSettlement: ValidatedV3Settlement;
  now?: number;
}

export class BrowserProviderSettlementAttestationError extends BrowserConsumerProtocolError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BrowserProviderSettlementAttestationError";
  }
}

/**
 * Verify the Provider's Ed25519 settlement evidence after the EIP-712 receipt
 * has been validated. The two signatures intentionally remain independent:
 * this check binds the transport identity to the wallet that signed the receipt.
 */
export async function verifyBrowserProviderSettlementAttestation(
  value: unknown,
  options: VerifyBrowserProviderSettlementAttestationOptions,
): Promise<BrowserProviderSettlementAttestation> {
  try {
    return await verifyAttestation(value, options);
  } catch (error) {
    if (error instanceof BrowserProviderSettlementAttestationError) throw error;
    throw new BrowserProviderSettlementAttestationError(
      error instanceof Error ? error.message : "Provider settlement attestation is invalid",
      { cause: error },
    );
  }
}

async function verifyAttestation(
  value: unknown,
  options: VerifyBrowserProviderSettlementAttestationOptions,
): Promise<BrowserProviderSettlementAttestation> {
  const attestation = exactObject(value, ATTESTATION_FIELDS, "Provider settlement attestation");
  const signature = exactObject(attestation.signature, SIGNATURE_FIELDS, "Provider attestation signature");
  const providerPublicKey = publicKey(options.provider.publicKey, "Provider public key");
  const consumerPublicKey = publicKey(options.consumerPublicKey, "Consumer public key");

  if (signature.public_key !== providerPublicKey) {
    throw new BrowserProviderSettlementAttestationError(
      "Provider attestation signer does not match the selected Provider",
    );
  }
  if (signature.audience !== consumerPublicKey) {
    throw new BrowserProviderSettlementAttestationError(
      "Provider attestation audience does not match the Consumer",
    );
  }
  if (signature.nonce.length !== 32 || !NONCE_PATTERN.test(signature.nonce)) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation nonce is malformed");
  }
  if (signature.signature.length !== 128 || !SIGNATURE_PATTERN.test(signature.signature)) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation signature is malformed");
  }
  if (signature.purpose !== PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation purpose is invalid");
  }
  const signatureTimestamp = safeInteger(signature.timestamp, "Provider attestation timestamp");
  const now = safeNow(options.now);
  if (signatureTimestamp > now + 30) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation timestamp is in the future");
  }

  let unsigned: Record<string, unknown>;
  try {
    unsigned = verifyBrowserDocument(attestation, {
      purpose: PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE,
      audience: consumerPublicKey,
      // Python permits an attestation to be older than the generic 5-minute
      // document window; the response envelope and reservation prevent reuse.
      maxAgeSeconds: 0,
      now,
    });
  } catch (error) {
    throw new BrowserProviderSettlementAttestationError(
      "Provider settlement attestation signature is invalid",
      { cause: error },
    );
  }

  const expectedBinding = {
    network_id: MYCOMESH_TESTNET_NETWORK_ID,
    channel_id: CODEX_CHANNEL_ID,
    channel: CODEX_SETTLEMENT_CHANNEL,
    backend_policy: CODEX_BACKEND_POLICY,
  };
  for (const [field, expected] of Object.entries(expectedBinding)) {
    if (unsigned[field] !== expected || options.plan[field as keyof ConsumerV3Plan] !== expected) {
      throw new BrowserProviderSettlementAttestationError(
        `Provider attestation ${field} is not bound to the enabled Codex channel`,
      );
    }
  }

  const requestId = text(unsigned.request_id, "Provider attestation request_id");
  if (requestId !== options.requestId) throw new BrowserProviderSettlementAttestationError("Provider attestation request_id mismatch");
  const requestHash = digest(unsigned.request_hash, "Provider attestation request_hash");
  if (requestHash !== digest(options.requestHash, "expected request_hash")) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation request_hash mismatch");
  }
  const responseHash = digest(unsigned.response_hash, "Provider attestation response_hash");
  if (responseHash !== digest(settlementResponseHash(options.response), "expected response_hash")) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation response_hash mismatch");
  }
  if (text(unsigned.model, "Provider attestation model") !== options.model) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation model mismatch");
  }
  if (text(unsigned.endpoint, "Provider attestation endpoint") !== options.endpoint) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation endpoint mismatch");
  }

  const consumerId = text(unsigned.consumer_id, "Provider attestation consumer_id");
  if (consumerId !== options.consumerId) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation consumer_id mismatch");
  }
  if (unsigned.consumer_public_key !== consumerPublicKey) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation consumer public key mismatch");
  }
  const expectedProviderId = browserPeerIdFromPublicKey(providerPublicKey);
  if (unsigned.provider_id !== expectedProviderId || unsigned.provider_id !== options.provider.peerId) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation provider_id mismatch");
  }

  const consumerPaymentAddress = address(unsigned.consumer_payment_address, "Provider attestation Consumer address");
  const providerPaymentAddress = address(unsigned.provider_payment_address, "Provider attestation Provider address");
  const expectedConsumerAddress = address(options.authorization.consumer_payment_address, "Consumer payment address");
  const expectedProviderAddress = address(options.provider.paymentAddress, "Provider payment address");
  if (consumerPaymentAddress !== expectedConsumerAddress) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation Consumer payment address mismatch");
  }
  if (
    providerPaymentAddress !== expectedProviderAddress
    || providerPaymentAddress !== address(options.authorization.provider_payment_address, "authorization Provider address")
  ) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation Provider payment address mismatch");
  }

  const pricingHash = digest(unsigned.pricing_hash, "Provider attestation pricing_hash");
  if (
    pricingHash !== digest(options.plan.pricing_hash, "plan pricing_hash")
    || pricingHash !== digest(options.authorization.pricing_hash, "authorization pricing_hash")
  ) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation pricing_hash mismatch");
  }
  const pricingVersion = positiveInteger(unsigned.pricing_version, "Provider attestation pricing_version");
  if (pricingVersion !== options.plan.pricing_version || pricingVersion !== options.authorization.pricing_version) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation pricing_version mismatch");
  }
  if (safeInteger(unsigned.settlement_version, "Provider attestation settlement_version") !== 3) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation settlement_version must be 3");
  }
  const reservationId = digest(unsigned.onchain_reservation_id, "Provider attestation reservation ID");
  if (
    reservationId !== digest(options.plan.onchain_reservation_id, "plan reservation ID")
    || reservationId !== digest(options.authorization.onchain_reservation_id, "authorization reservation ID")
  ) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation reservation ID mismatch");
  }

  const inputTokens = nonnegativeInteger(unsigned.input_tokens, "Provider attestation input_tokens");
  const outputTokens = nonnegativeInteger(unsigned.output_tokens, "Provider attestation output_tokens");
  const usage = options.response.usage;
  if (
    !browserIsPlainObject(usage)
    || typeof usage.input_tokens !== "number"
    || typeof usage.output_tokens !== "number"
  ) {
    throw new BrowserProviderSettlementAttestationError("Provider response usage is required for settlement attestation");
  }
  if (
    inputTokens !== nonnegativeInteger(usage.input_tokens, "response input_tokens")
    || outputTokens !== nonnegativeInteger(usage.output_tokens, "response output_tokens")
  ) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation usage mismatch");
  }
  const grossFeeUnits = nonnegativeInteger(unsigned.gross_fee_units, "Provider attestation gross_fee_units");
  if (grossFeeUnits > positiveInteger(options.authorization.max_fee_units, "authorization max_fee_units")) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation fee exceeds the authorized maximum");
  }

  const deadline = positiveInteger(unsigned.settlement_deadline, "Provider attestation settlement_deadline");
  if (
    deadline !== options.plan.settlement_deadline
    || deadline !== options.authorization.settlement_deadline
    || deadline <= now
  ) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation settlement deadline mismatch or expiry");
  }
  if (signatureTimestamp > deadline) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation was signed after its settlement deadline");
  }

  const receipt = options.validatedSettlement.contractReceipt;
  const payload = options.validatedSettlement.payload;
  if (payload.chain_id !== options.plan.chain_id) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation EVM chain mismatch");
  }
  if (payload.settlement_contract.toLowerCase() !== options.plan.settlement_contract.toLowerCase()) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation EVM contract mismatch");
  }
  compareHex(receipt.reservationId, reservationId, "reservation ID");
  compareHex(receipt.requestHash, requestHash, "request hash");
  compareHex(receipt.responseHash, responseHash, "response hash");
  compareHex(receipt.pricingHash, pricingHash, "pricing hash");
  compareBigInt(receipt.pricingVersion, BigInt(pricingVersion), "pricing version");
  compareBigInt(receipt.inputTokens, BigInt(inputTokens), "input usage");
  compareBigInt(receipt.outputTokens, BigInt(outputTokens), "output usage");
  compareBigInt(receipt.deadline, BigInt(deadline), "settlement deadline");
  if (receipt.consumer.toLowerCase() !== consumerPaymentAddress) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation EVM Consumer mismatch");
  }
  if (receipt.provider.toLowerCase() !== providerPaymentAddress) {
    throw new BrowserProviderSettlementAttestationError("Provider attestation EVM Provider mismatch");
  }

  // `validateV3Settlement` already checks the receipt commitment and EIP-712
  // signature. Recover once more here so this binding cannot be bypassed by a
  // caller constructing a forged ValidatedV3Settlement object.
  let recoveredProvider: string;
  try {
    recoveredProvider = (await recoverTypedDataAddress({
      ...options.validatedSettlement.typedData,
      signature: options.validatedSettlement.providerSignature,
    })).toLowerCase();
  } catch (error) {
    throw new BrowserProviderSettlementAttestationError("Provider EVM settlement signature is invalid", { cause: error });
  }
  if (recoveredProvider !== providerPaymentAddress) {
    throw new BrowserProviderSettlementAttestationError("Provider EVM settlement signer mismatch");
  }

  return unsigned as unknown as BrowserProviderSettlementAttestation;
}

function exactObject(
  value: unknown,
  fields: readonly string[],
  label: string,
): Record<string, any> {
  if (!browserIsPlainObject(value)) {
    throw new BrowserProviderSettlementAttestationError(`${label} must be an object`);
  }
  const expected = new Set(fields);
  const actual = Object.keys(value);
  const missing = fields.filter((field) => !Object.hasOwn(value, field));
  const unknown = actual.filter((field) => !expected.has(field));
  if (missing.length || unknown.length) {
    throw new BrowserProviderSettlementAttestationError(
      `${label} fields are invalid${missing.length ? `; missing ${missing.join(", ")}` : ""}${unknown.length ? `; unknown ${unknown.join(", ")}` : ""}`,
    );
  }
  return value;
}

function text(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value !== value.trim()
    || new TextEncoder().encode(value).length > MAX_ATTESTATION_TEXT_BYTES
  ) {
    throw new BrowserProviderSettlementAttestationError(`${label} is malformed`);
  }
  return value;
}

function publicKey(value: unknown, label: string): string {
  if (typeof value !== "string" || !PUBLIC_KEY_PATTERN.test(value)) {
    throw new BrowserProviderSettlementAttestationError(`${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function address(value: unknown, label: string): string {
  if (typeof value !== "string" || !ADDRESS_PATTERN.test(value) || /^0x0+$/.test(value)) {
    throw new BrowserProviderSettlementAttestationError(`${label} must be a non-zero lowercase address`);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value) || /^0x0+$/.test(value)) {
    throw new BrowserProviderSettlementAttestationError(`${label} must be a non-zero 32-byte digest`);
  }
  return value.slice(0, 2) === "0x" ? value.slice(2) : value;
}

function safeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new BrowserProviderSettlementAttestationError(`${label} must be a non-negative safe integer`);
  }
  return value as number;
}

function nonnegativeInteger(value: unknown, label: string): number {
  return safeInteger(value, label);
}

function positiveInteger(value: unknown, label: string): number {
  const result = safeInteger(value, label);
  if (result <= 0) throw new BrowserProviderSettlementAttestationError(`${label} must be positive`);
  return result;
}

function safeNow(value: unknown): number {
  const result = value === undefined ? Math.floor(Date.now() / 1000) : value;
  return safeInteger(result, "current time");
}

function compareBigInt(value: bigint, expectedDigest: string, label: string): void;
function compareBigInt(value: bigint, expected: bigint, label: string): void;
function compareBigInt(value: bigint, expected: string | bigint, label: string): void {
  const normalized = typeof expected === "bigint"
    ? expected
    : BigInt(`0x${expected}`);
  if (value !== normalized) {
    throw new BrowserProviderSettlementAttestationError(`Provider attestation EVM ${label} mismatch`);
  }
}

function compareHex(value: string, expected: string, label: string): void {
  if (value.toLowerCase().replace(/^0x/, "") !== expected.toLowerCase().replace(/^0x/, "")) {
    throw new BrowserProviderSettlementAttestationError(`Provider attestation EVM ${label} mismatch`);
  }
}
