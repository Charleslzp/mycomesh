import { getAddress, keccak256, stringToHex, zeroAddress } from "viem";
import type { ConsumerV3Authorization, ConsumerV3Plan } from "./api";
import type { VerifiedBrowserProvider } from "./browserConsumerDiscovery";
import {
  type BrowserConsumerIdentity,
  type BrowserRandomBytes,
  browserBytesToHex,
  secureBrowserRandomBytes,
} from "./browserConsumerIdentity";
import {
  browserV3AuthorizationMessage,
  browserV3InferenceRequestHash,
} from "./browserConsumerV3";

const DEFAULT_RESERVATION_TTL_SECONDS = 15 * 60;
const MIN_RESERVATION_TTL_SECONDS = 5 * 60;
const MAX_RESERVATION_TTL_SECONDS = 60 * 60;

export interface BrowserV3PlanChainReader {
  quote(args: {
    settlementContract: `0x${string}`;
    channelHash: `0x${string}`;
    pricingVersion: number;
    reserveInputBytes: number;
    maxOutputTokens: number;
  }): Promise<bigint>;
  reservationIdFor(args: {
    settlementContract: `0x${string}`;
    consumer: `0x${string}`;
    reservationSalt: `0x${string}`;
  }): Promise<`0x${string}`>;
  latestChannelVersion(args: {
    settlementContract: `0x${string}`;
    channelHash: `0x${string}`;
  }): Promise<bigint>;
  channelPricingHash(args: {
    settlementContract: `0x${string}`;
    channelHash: `0x${string}`;
    pricingVersion: number;
  }): Promise<`0x${string}`>;
}

export interface PrepareBrowserV3PlanOptions {
  identity: BrowserConsumerIdentity;
  provider: VerifiedBrowserProvider;
  chainId: number;
  settlementContract: `0x${string}`;
  consumer: `0x${string}`;
  input: string;
  inputSizeBytes: number;
  model: string;
  maxOutputTokens: number;
  requiredConfirmations?: number;
  ttlSeconds?: number;
  now?: number;
  randomBytes?: BrowserRandomBytes;
  reader: BrowserV3PlanChainReader;
}

export class BrowserConsumerPlanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowserConsumerPlanError";
  }
}

export async function prepareBrowserV3Plan(
  options: PrepareBrowserV3PlanOptions,
): Promise<ConsumerV3Plan> {
  const now = nonnegativeInteger(
    options.now ?? Math.floor(Date.now() / 1000),
    "current time",
  );
  const ttlSeconds = boundedInteger(
    options.ttlSeconds ?? DEFAULT_RESERVATION_TTL_SECONDS,
    MIN_RESERVATION_TTL_SECONDS,
    MAX_RESERVATION_TTL_SECONDS,
    "reservation TTL",
  );
  const requiredConfirmations = positiveInteger(
    options.requiredConfirmations ?? 6,
    "required confirmations",
  );
  const inputSizeBytes = nonnegativeInteger(options.inputSizeBytes, "input size");
  const maxOutputTokens = positiveInteger(options.maxOutputTokens, "max output tokens");
  if (inputSizeBytes > options.provider.reserveInputBytes) {
    throw new BrowserConsumerPlanError("Inference input exceeds the selected Provider reserve");
  }
  if (maxOutputTokens > options.provider.reserveOutputTokens) {
    throw new BrowserConsumerPlanError("Inference output cap exceeds the selected Provider reserve");
  }
  if (options.model !== options.provider.model) {
    throw new BrowserConsumerPlanError("Inference model does not match the selected Provider");
  }
  if (options.chainId <= 0 || !Number.isSafeInteger(options.chainId)) {
    throw new BrowserConsumerPlanError("chain ID must be a positive safe integer");
  }
  const settlementContract = getAddress(options.settlementContract).toLowerCase() as `0x${string}`;
  if (
    settlementContract === zeroAddress
    || settlementContract !== options.provider.settlementContract.toLowerCase()
  ) {
    throw new BrowserConsumerPlanError("Selected Provider uses a different Settlement V3 contract");
  }
  const consumer = getAddress(options.consumer).toLowerCase() as `0x${string}`;
  if (consumer === zeroAddress) throw new BrowserConsumerPlanError("Consumer address must be non-zero");

  const randomBytes = options.randomBytes ?? secureBrowserRandomBytes;
  const reservationSalt = randomBytes32(randomBytes, "reservation salt");
  const authorizationNonce = randomBytes32(randomBytes, "authorization nonce");
  const requestHash = browserV3InferenceRequestHash({
    endpoint: "responses",
    model: options.model,
    input: options.input,
    maxOutputTokens,
  });
  const channelHash = keccak256(stringToHex(options.provider.channel)).toLowerCase() as `0x${string}`;
  const [quotedFee, reservationId, latestPricingVersion, onchainPricingHash] = await Promise.all([
    options.reader.quote({
      settlementContract,
      channelHash,
      pricingVersion: options.provider.pricingVersion,
      reserveInputBytes: options.provider.reserveInputBytes,
      maxOutputTokens,
    }),
    options.reader.reservationIdFor({
      settlementContract,
      consumer,
      reservationSalt,
    }),
    options.reader.latestChannelVersion({ settlementContract, channelHash }),
    options.reader.channelPricingHash({
      settlementContract,
      channelHash,
      pricingVersion: options.provider.pricingVersion,
    }),
  ]);
  const maxFeeUnits = safeBigIntNumber(quotedFee, "Settlement V3 quote");
  if (maxFeeUnits <= 0) throw new BrowserConsumerPlanError("Settlement V3 quote must be positive");
  if (latestPricingVersion !== BigInt(options.provider.pricingVersion)) {
    throw new BrowserConsumerPlanError("Provider does not advertise the latest channel pricing version");
  }
  if (onchainPricingHash.toLowerCase() !== options.provider.pricingHash.toLowerCase()) {
    throw new BrowserConsumerPlanError("Provider pricing hash does not match Settlement V3");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(reservationId)) {
    throw new BrowserConsumerPlanError("Settlement V3 returned an invalid reservation ID");
  }

  const expiresAt = now + ttlSeconds;
  const authorization: ConsumerV3Authorization = {
    authorization_version: "mycomesh.evm.session.v1",
    chain_id: options.chainId,
    settlement_contract: settlementContract,
    onchain_reservation_id: reservationId.toLowerCase() as `0x${string}`,
    consumer_payment_address: consumer,
    provider_id: options.provider.peerId,
    provider_payment_address:
      options.provider.paymentAddress.toLowerCase() as `0x${string}`,
    channel: options.provider.channel,
    pricing_hash: options.provider.pricingHash,
    pricing_version: options.provider.pricingVersion,
    request_hash: requestHash,
    max_fee_units: maxFeeUnits,
    expires_at: expiresAt,
    settlement_deadline: expiresAt,
    provider_fallback_allowed: false,
    nonce: authorizationNonce,
    session_public_key: options.identity.publicKey,
  };
  return {
    schema: "mycomesh.consumer.v3.plan.v1",
    network_id: options.provider.networkId,
    channel_id: options.provider.channelId,
    backend_policy: options.provider.backendPolicy,
    provider_id: options.provider.peerId,
    provider_payment_address:
      options.provider.paymentAddress.toLowerCase() as `0x${string}`,
    provider_addresses: [options.provider.relayAddress],
    chain_id: options.chainId,
    settlement_contract: settlementContract,
    channel: options.provider.channel,
    channel_hash: channelHash,
    pricing_version: options.provider.pricingVersion,
    pricing_hash: options.provider.pricingHash,
    request_hash: requestHash,
    input_size_bytes: inputSizeBytes,
    reserve_input_bytes: options.provider.reserveInputBytes,
    reserve_output_tokens: options.provider.reserveOutputTokens,
    max_fee_units: maxFeeUnits,
    expires_at: expiresAt,
    settlement_deadline: expiresAt,
    provider_fallback_allowed: false,
    reservation_salt: reservationSalt,
    onchain_reservation_id: reservationId.toLowerCase() as `0x${string}`,
    required_confirmations: requiredConfirmations,
    authorization,
    authorization_message: browserV3AuthorizationMessage(authorization),
  };
}

function randomBytes32(randomBytes: BrowserRandomBytes, label: string): `0x${string}` {
  const value = randomBytes(32);
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new BrowserConsumerPlanError(`${label} source must return exactly 32 bytes`);
  }
  return `0x${browserBytesToHex(value)}`;
}

function safeBigIntNumber(value: bigint, label: string): number {
  if (typeof value !== "bigint" || value > BigInt(Number.MAX_SAFE_INTEGER) || value < 0n) {
    throw new BrowserConsumerPlanError(`${label} exceeds the browser protocol integer range`);
  }
  return Number(value);
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new BrowserConsumerPlanError(`${label} must be a positive safe integer`);
  }
  return value as number;
}

function nonnegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new BrowserConsumerPlanError(`${label} must be a non-negative safe integer`);
  }
  return value as number;
}

function boundedInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  const resolved = positiveInteger(value, label);
  if (resolved < minimum || resolved > maximum) {
    throw new BrowserConsumerPlanError(`${label} must be between ${minimum} and ${maximum} seconds`);
  }
  return resolved;
}
