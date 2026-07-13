import { describe, expect, it } from "vitest";
import type { KeyChallenge } from "./api";
import {
  ChallengeValidationError,
  formatKeyRegistrationMessage,
  validateChallenge,
} from "./challenge";

const wallet = "0x00000000000000000000000000000000000000aA";
const keyHash = "ab".repeat(32);
const nowMs = 1_700_000_000_000;

function fixture(overrides: Partial<KeyChallenge> = {}): KeyChallenge {
  const challenge: KeyChallenge = {
    wallet,
    account_id: wallet,
    key_hash: keyHash,
    key_fingerprint: keyHash.slice(0, 12),
    chain_id: 11155111,
    network_id: "mycomesh-testnet",
    origin: "https://api.mycomesh.xyz",
    settlement: "0x0000000000000000000000000000000000000001",
    nonce: "test-registration-nonce",
    expires_at: Math.floor(nowMs / 1000) + 300,
    message: "",
    signature_type: "personal_sign",
    ...overrides,
  };
  if (!overrides.message) challenge.message = formatKeyRegistrationMessage(challenge);
  return challenge;
}

const audience = {
  nowMs,
  chainId: 11155111,
  networkId: "mycomesh-testnet",
  origin: "https://api.mycomesh.xyz",
  settlement: "0x0000000000000000000000000000000000000001",
};

describe("key registration challenge validation", () => {
  it("accepts a canonical challenge bound to discovery and the generated key", () => {
    expect(() => validateChallenge(fixture(), wallet, keyHash, audience)).not.toThrow();
  });

  it("rejects a signing message that differs from the response fields", () => {
    const challenge = fixture({ message: "MycoMesh API key registration\nWallet: attacker" });
    expect(() => validateChallenge(challenge, wallet, keyHash, audience)).toThrowError(
      expect.objectContaining<Partial<ChallengeValidationError>>({ code: "message" }),
    );
  });

  it("rejects an audience that does not match discovery", () => {
    const challenge = fixture({ network_id: "other-network" });
    expect(() => validateChallenge(challenge, wallet, keyHash, audience)).toThrowError(
      expect.objectContaining<Partial<ChallengeValidationError>>({ code: "audience" }),
    );
  });

  it("rejects insecure public origins and zero settlement addresses", () => {
    const insecure = fixture({ origin: "http://api.mycomesh.xyz" });
    expect(() => validateChallenge(insecure, wallet, keyHash, { ...audience, origin: undefined })).toThrow();

    const zeroSettlement = fixture({
      settlement: "0x0000000000000000000000000000000000000000",
    });
    expect(() => validateChallenge(zeroSettlement, wallet, keyHash, { ...audience, settlement: undefined })).toThrow();
  });

  it("rejects expired and unexpectedly long-lived challenges", () => {
    expect(() =>
      validateChallenge(fixture({ expires_at: Math.floor(nowMs / 1000) }), wallet, keyHash, audience),
    ).toThrowError(expect.objectContaining<Partial<ChallengeValidationError>>({ code: "expiry" }));

    expect(() =>
      validateChallenge(
        fixture({ expires_at: Math.floor(nowMs / 1000) + 3600 }),
        wallet,
        keyHash,
        audience,
      ),
    ).toThrowError(expect.objectContaining<Partial<ChallengeValidationError>>({ code: "expiry" }));
  });
});
