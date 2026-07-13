import { isAddress } from "viem";
import type { KeyChallenge } from "./api";
import { runtimeConfig } from "./config";

export type ChallengeValidationCode =
  | "signature_type"
  | "wallet"
  | "key_hash"
  | "chain"
  | "audience"
  | "expiry"
  | "message";

export class ChallengeValidationError extends Error {
  readonly code: ChallengeValidationCode;

  constructor(code: ChallengeValidationCode, message: string) {
    super(message);
    this.name = "ChallengeValidationError";
    this.code = code;
  }
}

export interface ChallengeExpectations {
  chainId?: number;
  origin?: string;
  networkId?: string;
  settlement?: string;
  nowMs?: number;
  maxFutureSeconds?: number;
}

export function formatKeyRegistrationMessage(challenge: KeyChallenge): string {
  return [
    "MycoMesh API key registration",
    `Origin: ${challenge.origin}`,
    `Network ID: ${challenge.network_id}`,
    `Wallet: ${challenge.wallet}`,
    `Key Hash: ${challenge.key_hash}`,
    `Chain ID: ${challenge.chain_id}`,
    `Settlement: ${challenge.settlement}`,
    `Nonce: ${challenge.nonce}`,
    `Expires At: ${challenge.expires_at}`,
  ].join("\n");
}

export function normalizeProtocolOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash) return null;
    if (url.pathname !== "/") return null;
    const localHttp =
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
    if (url.protocol !== "https:" && !localHttp) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function sameAddress(left: string, right: string): boolean {
  return isAddress(left, { strict: false }) && isAddress(right, { strict: false }) && left.toLowerCase() === right.toLowerCase();
}

function validSettlement(value: string): boolean {
  return isAddress(value, { strict: false }) && !/^0x0{40}$/i.test(value);
}

export function validateChallenge(
  challenge: KeyChallenge,
  expectedWallet: string,
  expectedKeyHash: string,
  expectations: ChallengeExpectations = {},
): void {
  if (challenge.signature_type !== "personal_sign") {
    throw new ChallengeValidationError("signature_type", "Unsupported signature type.");
  }
  if (!sameAddress(challenge.wallet, expectedWallet) || !sameAddress(challenge.account_id, expectedWallet)) {
    throw new ChallengeValidationError(
      "wallet",
      "Gateway challenge wallet does not match the connected wallet.",
    );
  }
  if (!/^[0-9a-f]{64}$/i.test(expectedKeyHash) || challenge.key_hash.toLowerCase() !== expectedKeyHash.toLowerCase()) {
    throw new ChallengeValidationError(
      "key_hash",
      "Gateway challenge does not bind the generated API key.",
    );
  }
  if (challenge.key_fingerprint.toLowerCase() !== expectedKeyHash.slice(0, 12).toLowerCase()) {
    throw new ChallengeValidationError("key_hash", "Gateway challenge key fingerprint is inconsistent.");
  }

  const expectedChainId = expectations.chainId ?? runtimeConfig.chainId;
  if (!Number.isSafeInteger(challenge.chain_id) || challenge.chain_id !== expectedChainId) {
    throw new ChallengeValidationError("chain", "Gateway challenge is for a different chain.");
  }

  const origin = normalizeProtocolOrigin(challenge.origin);
  if (!origin || !challenge.network_id.trim() || !validSettlement(challenge.settlement)) {
    throw new ChallengeValidationError("audience", "Gateway challenge has an invalid protocol audience.");
  }
  if (!challenge.nonce.trim() || challenge.nonce.length > 256) {
    throw new ChallengeValidationError("audience", "Gateway challenge nonce is invalid.");
  }
  if (expectations.origin && origin !== normalizeProtocolOrigin(expectations.origin)) {
    throw new ChallengeValidationError("audience", "Gateway challenge origin does not match discovery.");
  }
  if (expectations.networkId && challenge.network_id !== expectations.networkId) {
    throw new ChallengeValidationError("audience", "Gateway challenge network does not match discovery.");
  }
  if (expectations.settlement && !sameAddress(challenge.settlement, expectations.settlement)) {
    throw new ChallengeValidationError("audience", "Gateway challenge settlement does not match discovery.");
  }

  const nowMs = expectations.nowMs ?? Date.now();
  const expiresAtMs = challenge.expires_at * 1000;
  const maxFutureMs = (expectations.maxFutureSeconds ?? 930) * 1000;
  if (!Number.isSafeInteger(challenge.expires_at) || expiresAtMs <= nowMs) {
    throw new ChallengeValidationError("expiry", "Gateway challenge has expired.");
  }
  if (expiresAtMs > nowMs + maxFutureMs) {
    throw new ChallengeValidationError("expiry", "Gateway challenge expiry exceeds the allowed lifetime.");
  }
  if (challenge.message !== formatKeyRegistrationMessage(challenge)) {
    throw new ChallengeValidationError(
      "message",
      "Gateway challenge signing message does not match its bound fields.",
    );
  }
}
