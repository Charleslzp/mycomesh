import { getAddress, isAddress, zeroAddress } from "viem";
import type { ProviderPeer } from "./api";
import {
  browserIsPlainObject,
  browserPeerIdFromPublicKey,
  canonicalBrowserJson,
  verifyBrowserDocument,
} from "./browserConsumerIdentity";
import {
  type BrowserTransportKeyBinding,
  verifyBrowserProviderTransportKey,
} from "./browserConsumerTransport";

export const POOL_REGISTRATION_PURPOSE = "mycomesh.pool.registration.v1";
const MAX_PROVIDER_TTL_SECONDS = 300;
const PROVIDER_CLOCK_SKEW_SECONDS = 30;
const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;
const BYTES32_PATTERN = /^0x[0-9a-f]{64}$/;

export interface BrowserProviderExpectations {
  bridgeAudienceUrl: string;
  networkId: string;
  channelId: string;
  backendPolicy: string;
  channel: string;
  chainId: number;
  settlementContract: `0x${string}`;
  reserveInputBytes: number;
  reserveOutputTokens: number;
  now?: number;
}

export interface VerifiedBrowserProvider {
  peerId: string;
  publicKey: string;
  paymentAddress: `0x${string}`;
  networkId: string;
  channelId: string;
  backendPolicy: string;
  channel: string;
  model: string;
  relayAddress: string;
  relayBaseUrl: string;
  transportKey: BrowserTransportKeyBinding;
  reserveInputBytes: number;
  reserveOutputTokens: number;
  pricingVersion: number;
  pricingHash: `0x${string}`;
  settlementContract: `0x${string}`;
  descriptor: Record<string, unknown>;
  source: ProviderPeer;
}

export class BrowserProviderDiscoveryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BrowserProviderDiscoveryError";
  }
}

export function verifyBrowserProvider(
  peer: ProviderPeer,
  expected: BrowserProviderExpectations,
): VerifiedBrowserProvider {
  const descriptor = peer?.descriptor;
  if (!browserIsPlainObject(descriptor)) {
    throw new BrowserProviderDiscoveryError("Bridge Provider is missing its signed descriptor");
  }
  const bridgeAudienceUrl = canonicalBridgeAudience(expected.bridgeAudienceUrl);
  const now = protocolTime(expected.now);
  let verified: Record<string, unknown>;
  try {
    verified = verifyBrowserDocument(descriptor, {
      purpose: POOL_REGISTRATION_PURPOSE,
      audience: bridgeAudienceUrl,
      maxAgeSeconds: MAX_PROVIDER_TTL_SECONDS + PROVIDER_CLOCK_SKEW_SECONDS,
      now,
    });
  } catch (error) {
    throw new BrowserProviderDiscoveryError("Provider descriptor signature is invalid", { cause: error });
  }

  const signature = descriptor.signature;
  const signaturePublicKey = browserIsPlainObject(signature)
    ? canonicalPublicKey(signature.public_key, "Provider signature public key")
    : "";
  const publicKey = canonicalPublicKey(verified.public_key, "Provider public key");
  if (signaturePublicKey !== publicKey) {
    throw new BrowserProviderDiscoveryError("Provider descriptor signer does not match public_key");
  }
  const peerId = requiredText(verified.peer_id, "Provider peer_id");
  if (browserPeerIdFromPublicKey(publicKey) !== peerId) {
    throw new BrowserProviderDiscoveryError("Provider peer_id does not match public_key");
  }

  const ttlSeconds = positiveInteger(verified.ttl_seconds, "Provider ttl_seconds");
  if (ttlSeconds > MAX_PROVIDER_TTL_SECONDS) {
    throw new BrowserProviderDiscoveryError("Provider ttl_seconds exceeds the network maximum");
  }
  const signedLastSeen = nonnegativeInteger(verified.last_seen, "Provider last_seen");
  if (signedLastSeen > now + PROVIDER_CLOCK_SKEW_SECONDS) {
    throw new BrowserProviderDiscoveryError("Provider descriptor is dated in the future");
  }
  if (signedLastSeen + ttlSeconds + PROVIDER_CLOCK_SKEW_SECONDS <= now) {
    throw new BrowserProviderDiscoveryError("Provider descriptor has expired");
  }
  const expiresAt = positiveInteger(peer.expires_at, "Bridge Provider expires_at");
  if (expiresAt <= now || expiresAt > now + MAX_PROVIDER_TTL_SECONDS + PROVIDER_CLOCK_SKEW_SECONDS) {
    throw new BrowserProviderDiscoveryError("Bridge Provider lease is not active");
  }

  for (const field of [
    "peer_id",
    "public_key",
    "network_id",
    "channel_id",
    "backend_policy",
    "channel",
    "model",
    "addresses",
    "capacity",
    "payment_address",
    "transport_key",
    "settlement",
  ] as const) {
    if (canonicalBrowserJson(peer[field] ?? null) !== canonicalBrowserJson(verified[field] ?? null)) {
      throw new BrowserProviderDiscoveryError(`Bridge Provider ${field} does not match its signed descriptor`);
    }
  }

  const networkId = boundText(verified.network_id, expected.networkId, "network_id");
  const channelId = boundText(verified.channel_id, expected.channelId, "channel_id");
  const backendPolicy = boundText(verified.backend_policy, expected.backendPolicy, "backend_policy");
  const channel = boundText(verified.channel, expected.channel, "channel");
  const model = requiredText(verified.model, "Provider model");
  const paymentAddress = canonicalAddress(verified.payment_address, "Provider payment address");

  const capacity = requiredObject(verified.capacity, "Provider capacity");
  const reserveInputBytes = positiveInteger(capacity.reserve_input_bytes, "Provider reserve_input_bytes");
  const reserveOutputTokens = positiveInteger(capacity.reserve_output_tokens, "Provider reserve_output_tokens");
  if (
    reserveInputBytes !== expected.reserveInputBytes
    || reserveOutputTokens !== expected.reserveOutputTokens
  ) {
    throw new BrowserProviderDiscoveryError("Provider reserves do not match this Codex channel build");
  }

  const settlement = requiredObject(verified.settlement, "Provider Settlement V3 capability");
  if (positiveInteger(settlement.version, "Provider settlement version") !== 3) {
    throw new BrowserProviderDiscoveryError("Provider does not advertise Settlement V3");
  }
  if (positiveInteger(settlement.chain_id, "Provider settlement chain_id") !== expected.chainId) {
    throw new BrowserProviderDiscoveryError("Provider settlement chain does not match this application");
  }
  const settlementContract = canonicalAddress(settlement.contract, "Provider settlement contract");
  if (settlementContract.toLowerCase() !== expected.settlementContract.toLowerCase()) {
    throw new BrowserProviderDiscoveryError("Provider settlement contract does not match this application");
  }
  const pricingVersion = positiveInteger(settlement.pricing_version, "Provider pricing_version");
  const pricingHash = canonicalBytes32(settlement.pricing_hash, "Provider pricing_hash");

  let transportKey: BrowserTransportKeyBinding;
  try {
    verifyBrowserProviderTransportKey(verified.transport_key, {
      expectedPeerId: peerId,
      expectedIdentityPublicKey: publicKey,
      now,
    });
    transportKey = verified.transport_key as unknown as BrowserTransportKeyBinding;
  } catch (error) {
    throw new BrowserProviderDiscoveryError("Provider transport key is invalid", { cause: error });
  }

  const { relayAddress, relayBaseUrl } = browserRelayEndpoint(
    verified.addresses,
    peerId,
    new URL(bridgeAudienceUrl).protocol === "https:",
  );
  return {
    peerId,
    publicKey,
    paymentAddress,
    networkId,
    channelId,
    backendPolicy,
    channel,
    model,
    relayAddress,
    relayBaseUrl,
    transportKey,
    reserveInputBytes,
    reserveOutputTokens,
    pricingVersion,
    pricingHash,
    settlementContract,
    descriptor: { ...descriptor },
    source: peer,
  };
}

function browserRelayEndpoint(
  value: unknown,
  peerId: string,
  requireTls: boolean,
): { relayAddress: string; relayBaseUrl: string } {
  if (!Array.isArray(value) || value.length === 0) {
    throw new BrowserProviderDiscoveryError("Provider has no signed Relay address");
  }
  for (const item of value) {
    if (typeof item !== "string") continue;
    try {
      const parsed = new URL(item);
      if (parsed.protocol !== "myco+relays:" && (!isLocalRelay(parsed) || parsed.protocol !== "myco+relay:")) {
        continue;
      }
      if (requireTls && parsed.protocol !== "myco+relays:") continue;
      if (parsed.username || parsed.password || parsed.search || parsed.hash || !parsed.port) continue;
      const targetPeer = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
      if (!targetPeer || targetPeer !== peerId || targetPeer.includes("/")) continue;
      const scheme = parsed.protocol === "myco+relays:" ? "https:" : "http:";
      return { relayAddress: item, relayBaseUrl: `${scheme}//${parsed.host}` };
    } catch {
      // Continue until a signed browser-compatible Relay address is found.
    }
  }
  throw new BrowserProviderDiscoveryError("Provider has no browser-compatible signed Relay address");
}

function isLocalRelay(value: URL): boolean {
  return value.hostname === "localhost" || value.hostname === "127.0.0.1" || value.hostname === "[::1]";
}

function canonicalBridgeAudience(value: string): string {
  try {
    const url = new URL(value);
    const local = url.protocol === "http:" && isLocalRelay(url);
    if ((!local && url.protocol !== "https:") || url.username || url.password || url.search || url.hash) {
      throw new Error("invalid Bridge URL");
    }
    if (url.pathname !== "/" && url.pathname !== "") throw new Error("invalid Bridge path");
    return url.origin;
  } catch (error) {
    throw new BrowserProviderDiscoveryError("Bridge signature audience is not a canonical public origin", { cause: error });
  }
}

function requiredObject(value: unknown, label: string): Record<string, unknown> {
  if (!browserIsPlainObject(value)) throw new BrowserProviderDiscoveryError(`${label} is required`);
  return value;
}

function requiredText(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim() || value !== value.trim()) {
    throw new BrowserProviderDiscoveryError(`${label} must be non-empty text`);
  }
  return value;
}

function boundText(value: unknown, expected: string, field: string): string {
  const normalized = requiredText(value, `Provider ${field}`);
  if (normalized !== expected) {
    throw new BrowserProviderDiscoveryError(`Provider ${field} does not match this application`);
  }
  return normalized;
}

function canonicalPublicKey(value: unknown, label: string): string {
  if (typeof value !== "string" || !PUBLIC_KEY_PATTERN.test(value)) {
    throw new BrowserProviderDiscoveryError(`${label} must be 32 bytes of lowercase hex`);
  }
  return value;
}

function canonicalBytes32(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !BYTES32_PATTERN.test(value)) {
    throw new BrowserProviderDiscoveryError(`${label} must be bytes32 lowercase hex`);
  }
  return value as `0x${string}`;
}

function canonicalAddress(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !isAddress(value, { strict: false })) {
    throw new BrowserProviderDiscoveryError(`${label} must be an Ethereum address`);
  }
  const address = getAddress(value);
  if (address === zeroAddress) throw new BrowserProviderDiscoveryError(`${label} must be non-zero`);
  return address;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new BrowserProviderDiscoveryError(`${label} must be a positive safe integer`);
  }
  return value as number;
}

function nonnegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new BrowserProviderDiscoveryError(`${label} must be a non-negative safe integer`);
  }
  return value as number;
}

function protocolTime(value: unknown): number {
  const resolved = value === undefined ? Math.floor(Date.now() / 1000) : value;
  return nonnegativeInteger(resolved, "current time");
}
