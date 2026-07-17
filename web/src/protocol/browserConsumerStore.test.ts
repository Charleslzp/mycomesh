import { describe, expect, it } from "vitest";
import {
  signBrowserDocumentAsync,
  verifyBrowserDocument,
} from "./browserConsumerIdentity";
import { getOrCreateBrowserConsumerIdentityWithStorageForTest } from "./browserConsumerStore";

describe("browser Consumer non-extractable identity storage", () => {
  it("persists only a non-extractable CryptoKey and restores the same signer", async () => {
    let stored: unknown;
    const storage = memoryStorage(() => stored, (value) => { stored = value; });

    const first = await getOrCreateBrowserConsumerIdentityWithStorageForTest(storage);
    expect(first).not.toHaveProperty("privateKey");
    expect(Object.keys(first).sort()).toEqual(["peerId", "publicKey", "signer"]);

    const record = stored as Record<string, unknown>;
    expect(Object.keys(record).sort()).toEqual([
      "peer_id",
      "public_key",
      "schema",
      "signing_key",
    ]);
    expect(record).not.toHaveProperty("privateKey");
    expect(record).not.toHaveProperty("private_key");
    expect(record.signing_key).toMatchObject({
      extractable: false,
      type: "private",
      usages: ["sign"],
    });

    const restored = await getOrCreateBrowserConsumerIdentityWithStorageForTest(storage);
    expect(restored.publicKey).toBe(first.publicKey);
    expect(restored.peerId).toBe(first.peerId);
    const signed = await signBrowserDocumentAsync(
      { request_id: "stored-key-check" },
      restored,
      {
        purpose: "mycomesh.browser-consumer.storage-test.v1",
        timestamp: 1_800_000_000,
        nonce: "11".repeat(16),
      },
    );
    expect(verifyBrowserDocument(signed, {
      purpose: "mycomesh.browser-consumer.storage-test.v1",
      now: 1_800_000_000,
    })).toEqual({ request_id: "stored-key-check" });
  });

  it("deletes a legacy plaintext identity before creating the v2 record", async () => {
    let stored: unknown = {
      privateKey: "11".repeat(32),
      publicKey: "22".repeat(32),
      peerId: "peer_legacy",
    };
    let deletes = 0;
    const storage = {
      read: async () => stored,
      add: async (value: unknown) => { stored = value; },
      delete: async () => {
        deletes += 1;
        stored = undefined;
      },
    };

    const identity = await getOrCreateBrowserConsumerIdentityWithStorageForTest(storage);

    expect(deletes).toBe(1);
    expect(identity).not.toHaveProperty("privateKey");
    expect(stored).not.toHaveProperty("privateKey");
    expect(stored).toMatchObject({
      schema: "mycomesh.browser-consumer.identity.v2",
      public_key: identity.publicKey,
      peer_id: identity.peerId,
    });
  });
});

function memoryStorage(
  readValue: () => unknown,
  writeValue: (value: unknown) => void,
) {
  return {
    read: async () => readValue(),
    add: async (value: unknown) => writeValue(value),
    delete: async () => writeValue(undefined),
  };
}
