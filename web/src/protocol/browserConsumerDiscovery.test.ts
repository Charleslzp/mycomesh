import { describe, expect, it } from "vitest";
import type { ProviderPeer } from "./api";
import {
  POOL_REGISTRATION_PURPOSE,
  verifyBrowserProvider,
} from "./browserConsumerDiscovery";
import {
  browserSoftwareConsumerIdentityFromPrivateKeyForTest,
  signBrowserDocument,
} from "./browserConsumerIdentity";
import { generateBrowserTransportKey } from "./browserConsumerTransport";

const now = 1_800_000_000;
const provider = browserSoftwareConsumerIdentityFromPrivateKeyForTest("11".repeat(32));
const transport = generateBrowserTransportKey(provider, {
  now,
  lifetimeSeconds: 3600,
  randomBytes: (length) => new Uint8Array(length).fill(7),
});
const settlement = "0x3333333333333333333333333333333333333333" as const;

function providerPeer(overrides: Record<string, unknown> = {}): ProviderPeer {
  const unsigned = {
    peer_id: provider.peerId,
    protocol: "mycomesh-p2p/0.2",
    address: `myco+relays://bridge.mycomesh.xyz:443/${provider.peerId}`,
    addresses: [`myco+relays://bridge.mycomesh.xyz:443/${provider.peerId}`],
    network_id: "mycomesh-testnet",
    channel_id: "codex",
    backend_policy: "codex-app-server-postvalidated-v1",
    channel: "codex-standard-v1",
    agent_id: "coder",
    model: "mycomesh-codex-standard-v1",
    last_seen: now,
    ttl_seconds: 30,
    capacity: {
      max_concurrency: 1,
      transport: "relay",
      reserve_input_bytes: 8000,
      reserve_output_tokens: 2000,
    },
    public_key: provider.publicKey,
    payment_address: "0x2222222222222222222222222222222222222222",
    transport_key: transport.binding,
    settlement: {
      version: 3,
      chain_id: 11155111,
      contract: settlement,
      pricing_version: 1,
      pricing_hash: `0x${"44".repeat(32)}`,
    },
    ...overrides,
  };
  const descriptor = signBrowserDocument(unsigned, provider, {
    purpose: POOL_REGISTRATION_PURPOSE,
    audience: "https://bridge.mycomesh.xyz",
    timestamp: now,
    nonce: "55".repeat(16),
  });
  return {
    ...(descriptor as unknown as ProviderPeer),
    status: "online",
    last_seen: now,
    expires_at: now + 30,
    descriptor,
  };
}

const expected = {
  bridgeAudienceUrl: "https://bridge.mycomesh.xyz",
  networkId: "mycomesh-testnet",
  channelId: "codex",
  backendPolicy: "codex-app-server-postvalidated-v1",
  channel: "codex-standard-v1",
  chainId: 11155111,
  settlementContract: settlement,
  reserveInputBytes: 8000,
  reserveOutputTokens: 2000,
  now,
};

describe("browser Provider discovery", () => {
  it("accepts a signed Provider bound to the Codex channel and secure Relay", () => {
    const verified = verifyBrowserProvider(providerPeer(), expected);

    expect(verified.peerId).toBe(provider.peerId);
    expect(verified.relayBaseUrl).toBe("https://bridge.mycomesh.xyz:443");
    expect(verified.pricingVersion).toBe(1);
  });

  it("keeps a same-origin fetch proxy separate from the signature audience", () => {
    const verified = verifyBrowserProvider(providerPeer(), {
      ...expected,
      bridgeAudienceUrl: "https://bridge.mycomesh.xyz",
    });

    expect(verified.peerId).toBe(provider.peerId);
  });

  it("rejects Bridge fields that differ from the signed descriptor", () => {
    const peer = providerPeer();
    peer.payment_address = "0x9999999999999999999999999999999999999999";

    expect(() => verifyBrowserProvider(peer, expected)).toThrow(/payment_address.*signed descriptor/);
  });

  it("rejects cross-channel Providers", () => {
    expect(() => verifyBrowserProvider(
      providerPeer({ channel_id: "claude" }),
      expected,
    )).toThrow(/channel_id does not match/);
  });

  it("rejects plaintext public Relay transport", () => {
    const address = `myco+relay://bridge.mycomesh.xyz:80/${provider.peerId}`;
    expect(() => verifyBrowserProvider(
      providerPeer({ address, addresses: [address] }),
      expected,
    )).toThrow(/browser-compatible signed Relay/);
  });
});
