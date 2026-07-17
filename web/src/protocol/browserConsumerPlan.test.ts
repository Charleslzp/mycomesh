import { describe, expect, it, vi } from "vitest";
import type { VerifiedBrowserProvider } from "./browserConsumerDiscovery";
import { browserSoftwareConsumerIdentityFromPrivateKeyForTest } from "./browserConsumerIdentity";
import {
  prepareBrowserV3Plan,
  type BrowserV3PlanChainReader,
} from "./browserConsumerPlan";

const identity = browserSoftwareConsumerIdentityFromPrivateKeyForTest("11".repeat(32));
const provider = {
  peerId: "peer_provider",
  publicKey: "22".repeat(32),
  paymentAddress: "0x3333333333333333333333333333333333333333",
  networkId: "mycomesh-testnet",
  channelId: "codex",
  backendPolicy: "codex-app-server-postvalidated-v1",
  channel: "codex-standard-v1",
  model: "mycomesh-codex-standard-v1",
  relayAddress: "myco+relays://bridge.mycomesh.xyz:443/peer_provider",
  relayBaseUrl: "https://bridge.mycomesh.xyz:443",
  transportKey: {} as never,
  reserveInputBytes: 8000,
  reserveOutputTokens: 2000,
  pricingVersion: 1,
  pricingHash: `0x${"44".repeat(32)}`,
  settlementContract: "0x5555555555555555555555555555555555555555",
  descriptor: {},
  source: { peer_id: "peer_provider" },
} satisfies VerifiedBrowserProvider;

function reader(overrides: Partial<BrowserV3PlanChainReader> = {}): BrowserV3PlanChainReader {
  return {
    quote: vi.fn(async () => 25_000n),
    reservationIdFor: vi.fn(async () => `0x${"66".repeat(32)}` as const),
    latestChannelVersion: vi.fn(async () => 1n),
    channelPricingHash: vi.fn(async () => provider.pricingHash),
    ...overrides,
  };
}

describe("browser Consumer V3 plan", () => {
  it("builds a wallet authorization from signed discovery and live chain reads", async () => {
    let seed = 0;
    const plan = await prepareBrowserV3Plan({
      identity,
      provider,
      chainId: 11155111,
      settlementContract: provider.settlementContract,
      consumer: "0x7777777777777777777777777777777777777777",
      input: "hello",
      inputSizeBytes: 7,
      model: provider.model,
      maxOutputTokens: 256,
      now: 1_800_000_000,
      randomBytes: (length) => new Uint8Array(length).fill(++seed),
      reader: reader(),
    });

    expect(plan.network_id).toBe("mycomesh-testnet");
    expect(plan.channel_id).toBe("codex");
    expect(plan.backend_policy).toBe("codex-app-server-postvalidated-v1");
    expect(plan.max_fee_units).toBe(25_000);
    expect(plan.expires_at).toBe(1_800_000_900);
    expect(plan.authorization.session_public_key).toBe(identity.publicKey);
    expect(plan.authorization_message).not.toContain("wallet_signature");
  });

  it("fails closed when discovery pricing is not latest on chain", async () => {
    await expect(prepareBrowserV3Plan({
      identity,
      provider,
      chainId: 11155111,
      settlementContract: provider.settlementContract,
      consumer: "0x7777777777777777777777777777777777777777",
      input: "hello",
      inputSizeBytes: 7,
      model: provider.model,
      maxOutputTokens: 256,
      now: 1_800_000_000,
      randomBytes: (length) => new Uint8Array(length).fill(1),
      reader: reader({ latestChannelVersion: async () => 2n }),
    })).rejects.toThrow(/latest channel pricing/);
  });
});
