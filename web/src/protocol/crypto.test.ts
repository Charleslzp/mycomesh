import { describe, expect, it } from "vitest";
import { generateApiKey, isGeneratedApiKey, redactApiKey, sha256Hex } from "./crypto";

describe("browser API key crypto", () => {
  it("generates 256-bit base64url secrets with the testnet prefix", () => {
    const first = generateApiKey();
    const second = generateApiKey();

    expect(first).not.toBe(second);
    expect(isGeneratedApiKey(first)).toBe(true);
    expect(first).not.toMatch(/[+/=]/);
  });

  it("hashes the secret with SHA-256 before registration", async () => {
    await expect(sha256Hex("abc")).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("redacts secrets without returning the original value", () => {
    const secret = generateApiKey();
    const redacted = redactApiKey(secret);
    expect(redacted).not.toBe(secret);
    expect(redacted).toContain("...");
    expect(redacted.endsWith(secret.slice(-4))).toBe(true);
    expect(isGeneratedApiKey("myco_test_not-enough-entropy")).toBe(false);
  });
});
