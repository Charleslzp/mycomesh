import { getAddress, isAddress, type Address, type Hex } from "viem";
import {
  protocolApi,
  type DiscoveryResponse,
  type KeyChallenge,
  type KeyRegistrationResult,
} from "./api";
import {
  normalizeProtocolOrigin,
  validateChallenge,
  type ChallengeExpectations,
} from "./challenge";
import { generateApiKey, sha256Hex } from "./crypto";

export type KeyRegistrationStage =
  | "generating"
  | "requesting_challenge"
  | "awaiting_signature"
  | "registering";

export interface RegisterBrowserApiKeyOptions {
  wallet: string;
  signMessage: (message: string) => Promise<Hex | string>;
  rotate?: boolean;
  audience: CompleteChallengeExpectations;
  onStage?: (stage: KeyRegistrationStage) => void;
}

export type CompleteChallengeExpectations = ChallengeExpectations & {
  chainId: number;
  origin: string;
  networkId: string;
  settlement: string;
};

export interface BrowserApiKeyRegistration {
  apiKey: string;
  keyHash: string;
  baseUrl: string;
  challenge: KeyChallenge;
  account: KeyRegistrationResult;
}

export function canonicalGatewayBaseUrl(value: string | undefined, expectedOrigin: string): string {
  if (!value) throw new Error("Gateway did not return an API base URL.");
  try {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash) {
      throw new Error("Gateway returned an ambiguous API base URL.");
    }
    const origin = normalizeProtocolOrigin(url.origin);
    if (!origin || origin !== normalizeProtocolOrigin(expectedOrigin)) {
      throw new Error("Gateway API base URL does not match the signed credential origin.");
    }
    const path = url.pathname.replace(/\/+$/, "");
    if (path.includes("//")) throw new Error("Gateway returned an invalid API base URL path.");
    return path ? `${origin}${path}` : origin;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Gateway ")) throw error;
    throw new Error("Gateway returned an invalid API base URL.");
  }
}

function normalizeWallet(wallet: string): Address {
  if (!isAddress(wallet, { strict: false })) throw new Error("Connect a valid EVM wallet.");
  return getAddress(wallet);
}

function assertRegistrationMatchesChallenge(
  account: KeyRegistrationResult,
  challenge: KeyChallenge,
): void {
  if (account.account_id.toLowerCase() !== challenge.wallet.toLowerCase()) {
    throw new Error("Gateway registered the API key to a different account.");
  }
  if (account.wallet && account.wallet.toLowerCase() !== challenge.wallet.toLowerCase()) {
    throw new Error("Gateway registration wallet does not match the signed challenge.");
  }
  if (account.credential_chain_id !== undefined && account.credential_chain_id !== challenge.chain_id) {
    throw new Error("Gateway returned a different credential chain.");
  }
  if (
    account.credential_network_id !== undefined &&
    account.credential_network_id !== challenge.network_id
  ) {
    throw new Error("Gateway returned a different credential network.");
  }
  if (
    account.credential_settlement !== undefined &&
    account.credential_settlement.toLowerCase() !== challenge.settlement.toLowerCase()
  ) {
    throw new Error("Gateway returned a different credential settlement contract.");
  }
  if (
    account.credential_audience !== undefined &&
    account.credential_audience !== challenge.origin
  ) {
    throw new Error("Gateway returned a different credential origin.");
  }
  if (account.api_key_returned === true) {
    throw new Error("Gateway unexpectedly returned server-generated API key material.");
  }
  if (account.key_fingerprint?.toLowerCase() !== challenge.key_fingerprint.toLowerCase()) {
    throw new Error("Gateway registered a different API key fingerprint.");
  }
}

export function challengeAudienceFromDiscovery(
  discovery: DiscoveryResponse | undefined,
): CompleteChallengeExpectations {
  if (!discovery) throw new Error("Gateway discovery is required before signing an API key challenge.");
  const chainId = discovery.chain_id;
  if (!Number.isSafeInteger(chainId) || (chainId ?? 0) <= 0) {
    throw new Error("Gateway discovery does not contain a valid chain ID.");
  }
  const networkId = discovery.network?.trim();
  if (!networkId) throw new Error("Gateway discovery does not contain a network ID.");
  const settlement = discovery.settlement?.trim();
  if (!settlement || !isAddress(settlement, { strict: false }) || /^0x0{40}$/i.test(settlement)) {
    throw new Error("Gateway discovery does not contain a valid settlement contract.");
  }

  const gateway = discovery.recommended_gateway;
  if (gateway?.chain_id !== undefined && gateway.chain_id !== chainId) {
    throw new Error("Gateway discovery contains conflicting chain IDs.");
  }
  if (gateway?.network_id && gateway.network_id !== networkId) {
    throw new Error("Gateway discovery contains conflicting network IDs.");
  }
  if (gateway?.settlement && getAddress(gateway.settlement) !== getAddress(settlement)) {
    throw new Error("Gateway discovery contains conflicting settlement contracts.");
  }

  const originCandidates: string[] = [];
  if (gateway?.credential_audience) originCandidates.push(gateway.credential_audience);
  for (const baseUrl of [discovery.recommended_base_url, gateway?.public_url]) {
    if (!baseUrl) continue;
    try {
      originCandidates.push(new URL(baseUrl).origin);
    } catch {
      throw new Error("Gateway discovery contains an invalid public URL.");
    }
  }
  const origins = originCandidates.map((value) => normalizeProtocolOrigin(value));
  if (origins.length === 0 || origins.some((value) => !value)) {
    throw new Error("Gateway discovery does not contain a valid credential origin.");
  }
  const origin = origins[0] as string;
  if (origins.some((value) => value !== origin)) {
    throw new Error("Gateway discovery contains conflicting credential origins.");
  }

  return {
    chainId: chainId as number,
    networkId,
    settlement: getAddress(settlement),
    origin,
  };
}

export async function registerBrowserApiKey(
  options: RegisterBrowserApiKeyOptions,
): Promise<BrowserApiKeyRegistration> {
  const wallet = normalizeWallet(options.wallet);
  options.onStage?.("generating");
  const apiKey = generateApiKey();
  const keyHash = await sha256Hex(apiKey);

  options.onStage?.("requesting_challenge");
  const challenge = await protocolApi.challenge(wallet, keyHash);
  validateChallenge(challenge, wallet, keyHash, options.audience);

  options.onStage?.("awaiting_signature");
  const signature = await options.signMessage(challenge.message);
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(signature)) {
    throw new Error("Wallet returned an invalid signature payload.");
  }

  options.onStage?.("registering");
  const account = await protocolApi.register(challenge, signature, options.rotate);
  assertRegistrationMatchesChallenge(account, challenge);
  const baseUrl = canonicalGatewayBaseUrl(account.base_url, challenge.origin);
  return { apiKey, keyHash, baseUrl, challenge, account };
}
