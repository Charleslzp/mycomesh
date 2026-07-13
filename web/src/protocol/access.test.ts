import { describe, expect, it } from "vitest";
import { challengeAudienceFromDiscovery } from "./access";

const completeDiscovery = {
  chain_id: 11155111,
  network: "mycomesh-testnet",
  settlement: "0x0000000000000000000000000000000000000001",
  recommended_base_url: "https://gateway.mycomesh.xyz/v1",
  recommended_gateway: {
    chain_id: 11155111,
    network_id: "mycomesh-testnet",
    settlement: "0x0000000000000000000000000000000000000001",
    credential_audience: "https://gateway.mycomesh.xyz",
  },
};

describe("discovery-bound API key registration", () => {
  it("returns a complete canonical challenge audience", () => {
    expect(challengeAudienceFromDiscovery(completeDiscovery)).toEqual({
      chainId: 11155111,
      networkId: "mycomesh-testnet",
      settlement: "0x0000000000000000000000000000000000000001",
      origin: "https://gateway.mycomesh.xyz",
    });
  });

  it("fails closed when any signed audience field is absent", () => {
    expect(() => challengeAudienceFromDiscovery(undefined)).toThrow(/discovery is required/i);
    expect(() => challengeAudienceFromDiscovery({ ...completeDiscovery, network: undefined })).toThrow(/network ID/i);
    expect(() => challengeAudienceFromDiscovery({ ...completeDiscovery, settlement: undefined })).toThrow(/settlement/i);
    expect(() => challengeAudienceFromDiscovery({ ...completeDiscovery, recommended_base_url: undefined, recommended_gateway: undefined })).toThrow(/origin/i);
  });

  it("rejects internally inconsistent gateway discovery", () => {
    expect(() => challengeAudienceFromDiscovery({
      ...completeDiscovery,
      recommended_gateway: { ...completeDiscovery.recommended_gateway, chain_id: 1 },
    })).toThrow(/conflicting chain/i);
    expect(() => challengeAudienceFromDiscovery({
      ...completeDiscovery,
      recommended_gateway: {
        ...completeDiscovery.recommended_gateway,
        credential_audience: "https://attacker.example",
      },
    })).toThrow(/conflicting credential origins/i);
  });
});
