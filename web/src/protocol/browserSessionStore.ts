import { getAddress, isAddress, keccak256, stringToBytes, zeroAddress, type Address } from "viem";
import type { ConsumerSessionEnvelope, ConsumerSessionPlan } from "./api";

const STORAGE_KEY = "mycomesh.consumer.session.v5";
const SCHEMA_V5 = "mycomesh.consumer.v5.session.v1";
const SCHEMA_V6 = "mycomesh.consumer.v6.session.v1";
type BrowserSessionSchema = typeof SCHEMA_V5 | typeof SCHEMA_V6;
const PENDING_REQUEST_STORAGE_KEY = "mycomesh.consumer.session.v5.pending-request";
const PENDING_REQUEST_SCHEMA = "mycomesh.consumer.v5.pending-request.v1";

export interface BrowserSessionRecord {
  schema: BrowserSessionSchema;
  protocolVersion: 5 | 6;
  chainId: number;
  settlement: Address;
  consumer: Address;
  providerId: string;
  providerPaymentAddress: Address;
  relayPaymentAddress: Address;
  relayAttestationAddress: Address;
  relayEpoch: number;
  poolPaymentAddress: Address;
  channel: string;
  channelHash: `0x${string}`;
  pricingVersion: number;
  pricingHash: `0x${string}`;
  sessionSalt: `0x${string}`;
  sessionId: `0x${string}`;
  sessionKey: Address;
  maxAmountUnits: string;
  expiresAt: number;
  requestDeadline: number;
  nextSequence: number;
  cumulativeSpendUnits: string;
  model: string;
  activatedAt: number;
  /** Unsigned document supplied by the Gateway, if one was returned. */
  authorization?: Record<string, unknown>;
}

export type BrowserPendingSessionEnvelope = ConsumerSessionEnvelope & {
  session_id: `0x${string}`;
  request_id: string;
  max_fee_units: string;
  deadline: number;
};

export interface BrowserPendingSessionRequest {
  schema: typeof PENDING_REQUEST_SCHEMA;
  chainId: number;
  settlement: Address;
  sessionId: `0x${string}`;
  providerPaymentAddress: Address;
  relayPaymentAddress: Address;
  relayAttestationAddress: Address;
  poolPaymentAddress: Address;
  sequence: number;
  input: string;
  model: string;
  maxOutputTokens: number;
  envelope: BrowserPendingSessionEnvelope;
  startedAt: number;
}

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

function pendingRequestStorage(): Storage | null {
  try {
    // The prompt survives a reload in this tab, but is not retained after the
    // browser session ends and is never mixed with durable session metadata.
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

function validHex(value: unknown, bytes: number): value is `0x${string}` {
  return typeof value === "string" && new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value);
}

function validAddress(value: unknown): value is Address {
  return typeof value === "string" && isAddress(value, { strict: false });
}

function normalizeAddress(value: string): Address {
  return getAddress(value);
}

function parseRecord(value: unknown): BrowserSessionRecord | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  if (raw.schema !== SCHEMA_V5 && raw.schema !== SCHEMA_V6) return null;
  const protocolVersion = raw.protocolVersion === undefined
    ? (raw.schema === SCHEMA_V6 ? 6 : 5)
    : Number(raw.protocolVersion);
  if (protocolVersion !== 5 && protocolVersion !== 6) return null;
  if (!Number.isSafeInteger(raw.chainId) || Number(raw.chainId) <= 0) return null;
  if (!validAddress(raw.settlement) || !validAddress(raw.consumer)) return null;
  if (!validAddress(raw.providerPaymentAddress) || !validAddress(raw.sessionKey)) return null;
  if (!validAddress(raw.relayPaymentAddress) || !validAddress(raw.relayAttestationAddress)) return null;
  if (!validAddress(raw.poolPaymentAddress)) return null;
  if (
    (raw.relayPaymentAddress.toLowerCase() === zeroAddress)
    !== (raw.relayAttestationAddress.toLowerCase() === zeroAddress)
  ) return null;
  if (typeof raw.providerId !== "string" || !raw.providerId.trim()) return null;
  if (typeof raw.channel !== "string" || !raw.channel.trim()) return null;
  if (!validHex(raw.channelHash, 32) || !validHex(raw.pricingHash, 32)) return null;
  if (!validHex(raw.sessionSalt, 32) || !validHex(raw.sessionId, 32)) return null;
  if (!Number.isSafeInteger(raw.pricingVersion) || Number(raw.pricingVersion) <= 0) return null;
  if (!Number.isSafeInteger(raw.expiresAt) || Number(raw.expiresAt) <= 0) return null;
  if (!Number.isSafeInteger(raw.requestDeadline) || Number(raw.requestDeadline) <= 0) return null;
  if (!Number.isSafeInteger(raw.nextSequence) || Number(raw.nextSequence) < 0) return null;
  const relayEpoch = raw.relayEpoch === undefined ? 0 : Number(raw.relayEpoch);
  if (!Number.isSafeInteger(relayEpoch) || relayEpoch < 0 || relayEpoch >= 2 ** 64) return null;
  if (typeof raw.maxAmountUnits !== "string" || !/^\d+$/.test(raw.maxAmountUnits) || BigInt(raw.maxAmountUnits) <= 0n) return null;
  if (typeof raw.cumulativeSpendUnits !== "string" || !/^\d+$/.test(raw.cumulativeSpendUnits)) return null;
  if (typeof raw.model !== "string" || !raw.model.trim()) return null;
  if (!Number.isSafeInteger(raw.activatedAt) || Number(raw.activatedAt) <= 0) return null;
  return {
    schema: protocolVersion === 6 ? SCHEMA_V6 : SCHEMA_V5,
    protocolVersion,
    chainId: Number(raw.chainId),
    settlement: normalizeAddress(raw.settlement),
    consumer: normalizeAddress(raw.consumer),
    providerId: raw.providerId,
    providerPaymentAddress: normalizeAddress(raw.providerPaymentAddress),
    relayPaymentAddress: normalizeAddress(raw.relayPaymentAddress),
    relayAttestationAddress: normalizeAddress(raw.relayAttestationAddress),
    relayEpoch,
    poolPaymentAddress: normalizeAddress(raw.poolPaymentAddress),
    channel: raw.channel,
    channelHash: raw.channelHash,
    pricingVersion: Number(raw.pricingVersion),
    pricingHash: raw.pricingHash,
    sessionSalt: raw.sessionSalt,
    sessionId: raw.sessionId,
    sessionKey: normalizeAddress(raw.sessionKey),
    maxAmountUnits: raw.maxAmountUnits,
    expiresAt: Number(raw.expiresAt),
    requestDeadline: Number(raw.requestDeadline),
    nextSequence: Number(raw.nextSequence),
    cumulativeSpendUnits: raw.cumulativeSpendUnits,
    model: raw.model,
    activatedAt: Number(raw.activatedAt),
    ...(raw.authorization && typeof raw.authorization === "object"
      ? { authorization: raw.authorization as Record<string, unknown> }
      : {}),
  };
}

function parsePendingRequest(value: unknown): BrowserPendingSessionRequest | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  if (raw.schema !== PENDING_REQUEST_SCHEMA) return null;
  if (!Number.isSafeInteger(raw.chainId) || Number(raw.chainId) <= 0) return null;
  if (!validAddress(raw.settlement) || !validHex(raw.sessionId, 32)) return null;
  if (!validAddress(raw.providerPaymentAddress)) return null;
  if (!validAddress(raw.relayPaymentAddress) || !validAddress(raw.relayAttestationAddress)) return null;
  if (!validAddress(raw.poolPaymentAddress)) return null;
  if (
    (raw.relayPaymentAddress.toLowerCase() === zeroAddress)
    !== (raw.relayAttestationAddress.toLowerCase() === zeroAddress)
  ) return null;
  if (!Number.isSafeInteger(raw.sequence) || Number(raw.sequence) < 0) return null;
  if (typeof raw.input !== "string" || !raw.input.trim()) return null;
  if (typeof raw.model !== "string" || !raw.model.trim()) return null;
  if (!Number.isSafeInteger(raw.maxOutputTokens) || Number(raw.maxOutputTokens) <= 0) return null;
  if (!Number.isSafeInteger(raw.startedAt) || Number(raw.startedAt) <= 0) return null;
  if (!raw.envelope || typeof raw.envelope !== "object") return null;
  const envelope = raw.envelope as Record<string, unknown>;
  if (!validHex(envelope.session_id, 32) || envelope.session_id.toLowerCase() !== raw.sessionId.toLowerCase()) return null;
  if (typeof envelope.request_id !== "string" || !/^[0-9a-fA-F]{64}$/.test(envelope.request_id)) return null;
  if (typeof envelope.max_fee_units !== "string" || !/^\d+$/.test(envelope.max_fee_units) || BigInt(envelope.max_fee_units) <= 0n) return null;
  if (!Number.isSafeInteger(envelope.deadline) || Number(envelope.deadline) <= 0) return null;
  const requestHash = sessionRequestHash({
    sessionId: raw.sessionId,
    sequence: Number(raw.sequence),
    model: raw.model,
    input: raw.input,
    maxOutputTokens: Number(raw.maxOutputTokens),
  });
  if (envelope.request_id.toLowerCase() !== requestHash.slice(2).toLowerCase()) return null;
  return {
    schema: PENDING_REQUEST_SCHEMA,
    chainId: Number(raw.chainId),
    settlement: normalizeAddress(raw.settlement),
    sessionId: raw.sessionId,
    providerPaymentAddress: normalizeAddress(raw.providerPaymentAddress),
    relayPaymentAddress: normalizeAddress(raw.relayPaymentAddress),
    relayAttestationAddress: normalizeAddress(raw.relayAttestationAddress),
    poolPaymentAddress: normalizeAddress(raw.poolPaymentAddress),
    sequence: Number(raw.sequence),
    input: raw.input,
    model: raw.model,
    maxOutputTokens: Number(raw.maxOutputTokens),
    envelope: {
      session_id: envelope.session_id,
      request_id: envelope.request_id.toLowerCase(),
      max_fee_units: envelope.max_fee_units,
      deadline: Number(envelope.deadline),
    },
    startedAt: Number(raw.startedAt),
  };
}

export function getBrowserSession(options: {
  chainId: number;
  settlement: string;
  consumer: string;
  model?: string;
}): BrowserSessionRecord | null {
  const store = storage();
  if (!store) return null;
  try {
    const raw = store.getItem(STORAGE_KEY);
    if (!raw) return null;
    const record = parseRecord(JSON.parse(raw));
    if (!record) return null;
    if (record.chainId !== options.chainId) return null;
    if (record.settlement.toLowerCase() !== options.settlement.toLowerCase()) return null;
    if (record.consumer.toLowerCase() !== options.consumer.toLowerCase()) return null;
    if (options.model && record.model !== options.model) return null;
    return record;
  } catch {
    return null;
  }
}

/**
 * Recover a session when the wallet is disconnected. The record contains only
 * public session metadata; no session private key is ever written by this
 * module. A connected wallet is still checked by the caller before use.
 */
export function getStoredBrowserSessionForSettlement(options: {
  chainId: number;
  settlement: string;
}): BrowserSessionRecord | null {
  const store = storage();
  if (!store) return null;
  try {
    const raw = store.getItem(STORAGE_KEY);
    if (!raw) return null;
    const record = parseRecord(JSON.parse(raw));
    if (!record) return null;
    if (record.chainId !== options.chainId) return null;
    if (record.settlement.toLowerCase() !== options.settlement.toLowerCase()) return null;
    // Do not return optional provider-supplied documents from this recovery
    // accessor. The Gateway reconstructs and authenticates those documents.
    const { authorization: _authorization, ...metadata } = record;
    return metadata;
  } catch {
    return null;
  }
}

export function saveBrowserSession(record: BrowserSessionRecord): BrowserSessionRecord {
  const store = storage();
  if (store) {
    try {
      store.setItem(STORAGE_KEY, JSON.stringify(record));
    } catch {
      // Private browsing or a full quota should not prevent an active session
      // from being used for the current page lifetime.
    }
  }
  return record;
}

export function removeBrowserSession(): void {
  const store = storage();
  try {
    store?.removeItem(STORAGE_KEY);
  } catch {
    // Ignore storage failures.
  }
}

export function getPendingBrowserSessionRequest(options: {
  chainId: number;
  settlement: string;
}): BrowserPendingSessionRequest | null {
  const store = pendingRequestStorage();
  if (!store) return null;
  try {
    const raw = store.getItem(PENDING_REQUEST_STORAGE_KEY);
    if (!raw) return null;
    const record = parsePendingRequest(JSON.parse(raw));
    if (!record) return null;
    if (record.chainId !== options.chainId) return null;
    if (record.settlement.toLowerCase() !== options.settlement.toLowerCase()) return null;
    return record;
  } catch {
    return null;
  }
}

export function savePendingBrowserSessionRequest(
  value: Omit<BrowserPendingSessionRequest, "schema">,
): BrowserPendingSessionRequest {
  const record = parsePendingRequest({ ...value, schema: PENDING_REQUEST_SCHEMA });
  if (!record) throw new Error("The pending session request is invalid.");
  const store = pendingRequestStorage();
  if (store) {
    try {
      store.setItem(PENDING_REQUEST_STORAGE_KEY, JSON.stringify(record));
    } catch {
      // The active request can still finish when session storage is blocked.
    }
  }
  return record;
}

export function removePendingBrowserSessionRequest(): void {
  const store = pendingRequestStorage();
  try {
    store?.removeItem(PENDING_REQUEST_STORAGE_KEY);
  } catch {
    // Ignore storage failures.
  }
}

export function pendingSessionRequestMatchesSession(
  pending: BrowserPendingSessionRequest,
  session: BrowserSessionRecord,
): boolean {
  return (
    pending.chainId === session.chainId
    && pending.settlement.toLowerCase() === session.settlement.toLowerCase()
    && pending.sessionId.toLowerCase() === session.sessionId.toLowerCase()
    && pending.providerPaymentAddress.toLowerCase() === session.providerPaymentAddress.toLowerCase()
    && pending.relayPaymentAddress.toLowerCase() === session.relayPaymentAddress.toLowerCase()
    && pending.relayAttestationAddress.toLowerCase() === session.relayAttestationAddress.toLowerCase()
    && pending.poolPaymentAddress.toLowerCase() === session.poolPaymentAddress.toLowerCase()
  );
}

export interface SessionRouteBindings {
  providerPaymentAddress: Address;
  relayPaymentAddress: Address;
  relayAttestationAddress: Address;
  poolPaymentAddress: Address;
}

export interface BrowserOnchainSessionInfo extends SessionRouteBindings {
  consumer: Address;
  sessionKey: Address;
  channel: `0x${string}`;
  pricingVersion: bigint;
  pricingHash: `0x${string}`;
  openedAt: number;
  expiresAt: number;
  closeRequestedAt: number;
  maxAmount: bigint;
  spent: bigint;
  nextSequence: bigint;
  relayEpoch: bigint;
  closed: boolean;
}

function onchainSessionField(
  record: Record<string | number, unknown>,
  name: string,
  index: number,
): unknown {
  return record[name] ?? record[index];
}

function onchainSessionAddress(value: unknown, label: string): Address {
  if (!validAddress(value)) throw new Error(`The restored session has an invalid ${label} address.`);
  return normalizeAddress(value);
}

function onchainSessionUint(value: unknown, label: string): bigint {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  throw new Error(`The restored session has an invalid ${label}.`);
}

function onchainSessionTimestamp(value: unknown, label: string): number {
  const parsed = onchainSessionUint(value, label);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`The restored session has an invalid ${label}.`);
  }
  return Number(parsed);
}

export function parseV5SessionInfo(value: unknown): BrowserOnchainSessionInfo {
  if (!value || typeof value !== "object") {
    throw new Error("Settlement V5 returned invalid Session state.");
  }
  const record = value as Record<string | number, unknown>;
  const channel = onchainSessionField(record, "channel", 6);
  const pricingHash = onchainSessionField(record, "pricingHash", 8);
  const closed = onchainSessionField(record, "closed", 15);
  if (!validHex(channel, 32)) throw new Error("The restored session has an invalid channel.");
  if (!validHex(pricingHash, 32)) throw new Error("The restored session has an invalid pricing hash.");
  if (typeof closed !== "boolean") throw new Error("The restored session has an invalid closed state.");
  return {
    consumer: onchainSessionAddress(onchainSessionField(record, "consumer", 0), "Consumer"),
    providerPaymentAddress: onchainSessionAddress(onchainSessionField(record, "provider", 1), "Provider"),
    relayPaymentAddress: onchainSessionAddress(onchainSessionField(record, "relay", 2), "Relay payment"),
    relayAttestationAddress: onchainSessionAddress(onchainSessionField(record, "relaySigner", 3), "Relay attestation"),
    poolPaymentAddress: onchainSessionAddress(onchainSessionField(record, "pool", 4), "Pool payment"),
    sessionKey: onchainSessionAddress(onchainSessionField(record, "sessionKey", 5), "session key"),
    channel,
    pricingVersion: onchainSessionUint(onchainSessionField(record, "pricingVersion", 7), "pricing version"),
    pricingHash,
    openedAt: onchainSessionTimestamp(onchainSessionField(record, "openedAt", 9), "open time"),
    expiresAt: onchainSessionTimestamp(onchainSessionField(record, "expiresAt", 10), "expiry"),
    closeRequestedAt: onchainSessionTimestamp(onchainSessionField(record, "closeRequestedAt", 11), "close request time"),
    maxAmount: onchainSessionUint(onchainSessionField(record, "maxAmount", 12), "escrow cap"),
    spent: onchainSessionUint(onchainSessionField(record, "spent", 13), "spent amount"),
    nextSequence: onchainSessionUint(onchainSessionField(record, "nextSequence", 14), "next sequence"),
    relayEpoch: 0n,
    closed,
  };
}

/** Decode the V6 Session tuple, whose current route epoch precedes `closed`. */
export function parseV6SessionInfo(value: unknown): BrowserOnchainSessionInfo {
  if (!value || typeof value !== "object") {
    throw new Error("Settlement V6 returned invalid Session state.");
  }
  const record = value as Record<string | number, unknown>;
  const channel = onchainSessionField(record, "channel", 6);
  const pricingHash = onchainSessionField(record, "pricingHash", 8);
  const relayEpoch = onchainSessionUint(onchainSessionField(record, "relayEpoch", 15), "Relay epoch");
  const closed = onchainSessionField(record, "closed", 16);
  if (!validHex(channel, 32)) throw new Error("The restored session has an invalid channel.");
  if (!validHex(pricingHash, 32)) throw new Error("The restored session has an invalid pricing hash.");
  if (typeof closed !== "boolean") throw new Error("The restored session has an invalid closed state.");
  return {
    consumer: onchainSessionAddress(onchainSessionField(record, "consumer", 0), "Consumer"),
    providerPaymentAddress: onchainSessionAddress(onchainSessionField(record, "provider", 1), "Provider"),
    relayPaymentAddress: onchainSessionAddress(onchainSessionField(record, "relay", 2), "Relay payment"),
    relayAttestationAddress: onchainSessionAddress(onchainSessionField(record, "relaySigner", 3), "Relay attestation"),
    poolPaymentAddress: onchainSessionAddress(onchainSessionField(record, "pool", 4), "Pool payment"),
    sessionKey: onchainSessionAddress(onchainSessionField(record, "sessionKey", 5), "session key"),
    channel,
    pricingVersion: onchainSessionUint(onchainSessionField(record, "pricingVersion", 7), "pricing version"),
    pricingHash,
    openedAt: onchainSessionTimestamp(onchainSessionField(record, "openedAt", 9), "open time"),
    expiresAt: onchainSessionTimestamp(onchainSessionField(record, "expiresAt", 10), "expiry"),
    closeRequestedAt: onchainSessionTimestamp(onchainSessionField(record, "closeRequestedAt", 11), "close request time"),
    maxAmount: onchainSessionUint(onchainSessionField(record, "maxAmount", 12), "escrow cap"),
    spent: onchainSessionUint(onchainSessionField(record, "spent", 13), "spent amount"),
    nextSequence: onchainSessionUint(onchainSessionField(record, "nextSequence", 14), "next sequence"),
    relayEpoch,
    closed,
  };
}

export function assertSessionInfoRoutesMatchRecord(
  info: BrowserOnchainSessionInfo,
  record: BrowserSessionRecord,
): void {
  const checks: ReadonlyArray<[Address, Address, string]> = [
    [info.consumer, record.consumer, "Consumer wallet"],
    [info.providerPaymentAddress, record.providerPaymentAddress, "Provider"],
    [info.relayPaymentAddress, record.relayPaymentAddress, "Relay payment"],
    [info.relayAttestationAddress, record.relayAttestationAddress, "Relay attestation"],
    [info.poolPaymentAddress, record.poolPaymentAddress, "Pool"],
    [info.sessionKey, record.sessionKey, "session key"],
  ];
  for (const [actual, expected, label] of checks) {
    if (actual.toLowerCase() !== expected.toLowerCase()) {
      throw new Error(`The restored session ${label} binding does not match the Gateway plan.`);
    }
  }
  if (record.protocolVersion === 6 && info.relayEpoch !== BigInt(record.relayEpoch)) {
    throw new Error("The restored session Relay epoch does not match the Gateway plan.");
  }
}

export function sessionRouteBindingsFromPlan(
  plan: ConsumerSessionPlan,
): SessionRouteBindings {
  if (plan.schema !== "mycomesh.consumer.v5.plan.v1" && plan.schema !== "mycomesh.consumer.v6.plan.v1") {
    throw new Error("The Gateway returned an unsupported session plan schema.");
  }
  const protocolVersion = Number(plan.protocol_version ?? plan.settlement_version ?? (plan.schema === "mycomesh.consumer.v6.plan.v1" ? 6 : 5));
  if (protocolVersion !== 5 && protocolVersion !== 6) {
    throw new Error("The Gateway session plan does not target Settlement V5 or V6.");
  }
  if (!validAddress(plan.provider_payment_address) || plan.provider_payment_address.toLowerCase() === zeroAddress) {
    throw new Error("The session plan has an invalid Provider payment address.");
  }
  if (!validAddress(plan.relay_payment_address)) {
    throw new Error("The session plan has an invalid Relay payment address.");
  }
  if (!validAddress(plan.relay_attestation_address)) {
    throw new Error("The session plan has an invalid Relay attestation address.");
  }
  if (!validAddress(plan.pool_payment_address)) {
    throw new Error("The session plan has an invalid Pool payment address.");
  }
  if (
    (plan.relay_payment_address.toLowerCase() === zeroAddress)
    !== (plan.relay_attestation_address.toLowerCase() === zeroAddress)
  ) {
    throw new Error("The session plan must bind both Relay addresses or neither of them.");
  }
  return {
    providerPaymentAddress: normalizeAddress(plan.provider_payment_address),
    relayPaymentAddress: normalizeAddress(plan.relay_payment_address),
    relayAttestationAddress: normalizeAddress(plan.relay_attestation_address),
    poolPaymentAddress: normalizeAddress(plan.pool_payment_address),
  };
}

export function sessionRecordFromPlan(
  plan: ConsumerSessionPlan,
  consumer: string,
  model: string,
): BrowserSessionRecord {
  const routes = sessionRouteBindingsFromPlan(plan);
  const protocolVersion = Number(plan.protocol_version ?? plan.settlement_version ?? (plan.schema === "mycomesh.consumer.v6.plan.v1" ? 6 : 5)) as 5 | 6;
  if (!validAddress(consumer)) throw new Error("The session plan has an invalid consumer address.");
  if (!validAddress(plan.consumer_payment_address)) throw new Error("The session plan has an invalid Consumer payment address.");
  if (normalizeAddress(plan.consumer_payment_address) !== normalizeAddress(consumer)) {
    throw new Error("The session plan is bound to a different Consumer payment address.");
  }
  if (!validAddress(plan.settlement_contract)) throw new Error("The session plan has an invalid Settlement V5/V6 address.");
  if (!validAddress(plan.session_key) || plan.session_key.toLowerCase() === zeroAddress) {
    throw new Error("The session plan has an invalid session key address.");
  }
  if (!validHex(plan.session_salt, 32) || !validHex(plan.session_id, 32)) throw new Error("The session plan has an invalid session identifier.");
  if (!validHex(plan.channel_hash, 32) || !validHex(plan.pricing_hash, 32)) throw new Error("The session plan has an invalid pricing hash.");
  const maxAmountUnits = String(plan.max_amount_units);
  if (!/^\d+$/.test(maxAmountUnits) || BigInt(maxAmountUnits) <= 0n) throw new Error("The session plan has an invalid escrow cap.");
  const nextSequence = plan.next_sequence ?? 0;
  if (!Number.isSafeInteger(nextSequence) || nextSequence < 0) throw new Error("The session plan has an invalid sequence.");
  const cumulativeSpendUnits = String(plan.cumulative_spend_units ?? "0");
  if (!/^\d+$/.test(cumulativeSpendUnits)) throw new Error("The session plan has an invalid cumulative spend.");
  const relayEpoch = Number(plan.relay_epoch ?? 0);
  if (!Number.isSafeInteger(relayEpoch) || relayEpoch < 0 || relayEpoch >= 2 ** 64) {
    throw new Error("The session plan has an invalid Relay epoch.");
  }
  return {
    schema: protocolVersion === 6 ? SCHEMA_V6 : SCHEMA_V5,
    protocolVersion,
    chainId: plan.chain_id,
    settlement: normalizeAddress(plan.settlement_contract),
    consumer: normalizeAddress(consumer),
    providerId: plan.provider_id,
    ...routes,
    relayEpoch,
    channel: plan.channel,
    channelHash: plan.channel_hash,
    pricingVersion: plan.pricing_version,
    pricingHash: plan.pricing_hash,
    sessionSalt: plan.session_salt,
    sessionId: plan.session_id,
    sessionKey: normalizeAddress(plan.session_key),
    maxAmountUnits,
    expiresAt: plan.expires_at,
    requestDeadline: plan.request_deadline ?? plan.expires_at,
    nextSequence,
    cumulativeSpendUnits,
    model,
    activatedAt: Math.floor(Date.now() / 1000),
    ...(plan.authorization ? { authorization: plan.authorization } : {}),
  };
}

/** Missing is treated as required for compatibility with pre-recovery Gateways. */
export function sessionActivationRequired(plan: ConsumerSessionPlan): boolean {
  return plan.activation_required !== false;
}

/**
 * Deterministic request identity used for retries. It is intentionally
 * independent of the wallet and does not expose prompt content on-chain.
 */
export function sessionRequestHash(args: {
  sessionId: string;
  sequence: number;
  model: string;
  input: string;
  maxOutputTokens: number;
}): `0x${string}` {
  const canonical = JSON.stringify({
    input: args.input,
    max_output_tokens: args.maxOutputTokens,
    model: args.model,
    sequence: args.sequence,
    session_id: args.sessionId,
  });
  return keccak256(stringToBytes(canonical));
}

export function sessionRecordMatchesPlan(
  record: BrowserSessionRecord,
  plan: ConsumerSessionPlan,
): boolean {
  return (
    record.sessionId.toLowerCase() === plan.session_id.toLowerCase()
    && record.sessionKey.toLowerCase() === plan.session_key.toLowerCase()
    && record.providerPaymentAddress.toLowerCase() === plan.provider_payment_address.toLowerCase()
    && record.relayPaymentAddress.toLowerCase() === plan.relay_payment_address.toLowerCase()
    && record.relayAttestationAddress.toLowerCase() === plan.relay_attestation_address.toLowerCase()
    && record.poolPaymentAddress.toLowerCase() === plan.pool_payment_address.toLowerCase()
    && (plan.relay_epoch === undefined || record.relayEpoch === Number(plan.relay_epoch))
    && record.pricingHash.toLowerCase() === plan.pricing_hash.toLowerCase()
    && record.channelHash.toLowerCase() === plan.channel_hash.toLowerCase()
  );
}
