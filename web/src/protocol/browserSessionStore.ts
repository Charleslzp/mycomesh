import { getAddress, isAddress, keccak256, stringToBytes, type Address } from "viem";
import type { ConsumerV4Plan } from "./api";

const STORAGE_KEY = "mycomesh.consumer.session.v4";
const SCHEMA = "mycomesh.consumer.v4.session.v1";

export interface BrowserSessionRecord {
  schema: typeof SCHEMA;
  chainId: number;
  settlement: Address;
  consumer: Address;
  providerId: string;
  providerPaymentAddress: Address;
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

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
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
  if (raw.schema !== SCHEMA) return null;
  if (!Number.isSafeInteger(raw.chainId) || Number(raw.chainId) <= 0) return null;
  if (!validAddress(raw.settlement) || !validAddress(raw.consumer)) return null;
  if (!validAddress(raw.providerPaymentAddress) || !validAddress(raw.sessionKey)) return null;
  if (typeof raw.providerId !== "string" || !raw.providerId.trim()) return null;
  if (typeof raw.channel !== "string" || !raw.channel.trim()) return null;
  if (!validHex(raw.channelHash, 32) || !validHex(raw.pricingHash, 32)) return null;
  if (!validHex(raw.sessionSalt, 32) || !validHex(raw.sessionId, 32)) return null;
  if (!Number.isSafeInteger(raw.pricingVersion) || Number(raw.pricingVersion) <= 0) return null;
  if (!Number.isSafeInteger(raw.expiresAt) || Number(raw.expiresAt) <= 0) return null;
  if (!Number.isSafeInteger(raw.requestDeadline) || Number(raw.requestDeadline) <= 0) return null;
  if (!Number.isSafeInteger(raw.nextSequence) || Number(raw.nextSequence) < 0) return null;
  if (typeof raw.maxAmountUnits !== "string" || !/^\d+$/.test(raw.maxAmountUnits) || BigInt(raw.maxAmountUnits) <= 0n) return null;
  if (typeof raw.cumulativeSpendUnits !== "string" || !/^\d+$/.test(raw.cumulativeSpendUnits)) return null;
  if (typeof raw.model !== "string" || !raw.model.trim()) return null;
  if (!Number.isSafeInteger(raw.activatedAt) || Number(raw.activatedAt) <= 0) return null;
  return {
    schema: SCHEMA,
    chainId: Number(raw.chainId),
    settlement: normalizeAddress(raw.settlement),
    consumer: normalizeAddress(raw.consumer),
    providerId: raw.providerId,
    providerPaymentAddress: normalizeAddress(raw.providerPaymentAddress),
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

export function sessionRecordFromPlan(
  plan: ConsumerV4Plan,
  consumer: string,
  model: string,
): BrowserSessionRecord {
  if (!validAddress(consumer)) throw new Error("The session plan has an invalid consumer address.");
  if (!validAddress(plan.settlement_contract)) throw new Error("The session plan has an invalid Settlement V4 address.");
  if (!validAddress(plan.provider_payment_address)) throw new Error("The session plan has an invalid Provider payment address.");
  if (!validAddress(plan.session_key)) throw new Error("The session plan has an invalid session key address.");
  if (!validHex(plan.session_salt, 32) || !validHex(plan.session_id, 32)) throw new Error("The session plan has an invalid session identifier.");
  if (!validHex(plan.channel_hash, 32) || !validHex(plan.pricing_hash, 32)) throw new Error("The session plan has an invalid pricing hash.");
  const maxAmountUnits = String(plan.max_amount_units);
  if (!/^\d+$/.test(maxAmountUnits) || BigInt(maxAmountUnits) <= 0n) throw new Error("The session plan has an invalid escrow cap.");
  const nextSequence = plan.next_sequence ?? 0;
  if (!Number.isSafeInteger(nextSequence) || nextSequence < 0) throw new Error("The session plan has an invalid sequence.");
  const cumulativeSpendUnits = String(plan.cumulative_spend_units ?? "0");
  if (!/^\d+$/.test(cumulativeSpendUnits)) throw new Error("The session plan has an invalid cumulative spend.");
  return {
    schema: SCHEMA,
    chainId: plan.chain_id,
    settlement: normalizeAddress(plan.settlement_contract),
    consumer: normalizeAddress(consumer),
    providerId: plan.provider_id,
    providerPaymentAddress: normalizeAddress(plan.provider_payment_address),
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
export function sessionActivationRequired(plan: ConsumerV4Plan): boolean {
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
  plan: ConsumerV4Plan,
): boolean {
  return (
    record.sessionId.toLowerCase() === plan.session_id.toLowerCase()
    && record.sessionKey.toLowerCase() === plan.session_key.toLowerCase()
    && record.providerPaymentAddress.toLowerCase() === plan.provider_payment_address.toLowerCase()
    && record.pricingHash.toLowerCase() === plan.pricing_hash.toLowerCase()
    && record.channelHash.toLowerCase() === plan.channel_hash.toLowerCase()
  );
}
