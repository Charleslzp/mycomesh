import { describe, expect, it } from "vitest";
import {
  appRouteUrl,
  createRuntimeConfig,
  getV3ConfigurationIssues,
  hasCompleteV3Deployment,
  getV4ConfigurationIssues,
  hasCompleteV4Deployment,
  isAppHostname,
  type PublicRuntimeEnv,
} from "./config";
import { getV3ReadGate, getV3WriteGate } from "./features";

const completeV3Env: PublicRuntimeEnv = {
  VITE_PROTOCOL_VERSION: "3",
  VITE_CHAIN_ID: "11155111",
  VITE_SETTLEMENT_ADDRESS: "0x0000000000000000000000000000000000000001",
  VITE_STABLECOIN_ADDRESS: "0x0000000000000000000000000000000000000002",
  VITE_TOKEN_ADDRESS: "0x0000000000000000000000000000000000000003",
  VITE_TREASURY_ADDRESS: "0x0000000000000000000000000000000000000004",
  VITE_GOVERNANCE_ADDRESS: "0x0000000000000000000000000000000000000005",
  VITE_DEPLOYMENT_BLOCK: "8123456",
};

const completeV4Env: PublicRuntimeEnv = {
  VITE_SESSION_PROTOCOL_VERSION: "4",
  VITE_SESSION_SETTLEMENT_ADDRESS: "0x0000000000000000000000000000000000000011",
  VITE_STABLECOIN_ADDRESS: "0x0000000000000000000000000000000000000002",
};

describe("runtime config", () => {
  it("uses browser-safe defaults and strips trailing base URL slashes", () => {
    const config = createRuntimeConfig({
      VITE_API_BASE_URL: "https://api.mycomesh.xyz/",
      VITE_CHAIN_ID: "not-a-number",
    }, "https://app.example");

    expect(config.apiBaseUrl).toBe("https://api.mycomesh.xyz");
    expect(config.bridgeBaseUrl).toBe("/bridge-api");
    expect(config.bridgeAudienceUrl).toBe("https://app.example");
    expect(config.chainId).toBe(11155111);
    expect(config.rpcUrls).toEqual([]);
    expect(config.maxInputBytes).toBe(8000);
    expect(config.maxOutputTokens).toBe(2000);
    expect(hasCompleteV3Deployment(config)).toBe(false);
  });

  it("separates the Bridge fetch base from its signed descriptor audience", () => {
    const proxied = createRuntimeConfig({
      VITE_BRIDGE_BASE_URL: "/bridge-api",
      VITE_BRIDGE_AUDIENCE_URL: "https://bridge.example",
    }, "https://app.example");
    const direct = createRuntimeConfig({
      VITE_BRIDGE_BASE_URL: "https://bridge.example/path/",
    }, "https://app.example");

    expect(proxied.bridgeBaseUrl).toBe("/bridge-api");
    expect(proxied.bridgeAudienceUrl).toBe("https://bridge.example");
    expect(direct.bridgeAudienceUrl).toBe("https://bridge.example");
  });

  it("reads the public Provider request limits", () => {
    const config = createRuntimeConfig({
      VITE_MAX_INPUT_BYTES: "4096",
      VITE_MAX_OUTPUT_TOKENS: "1024",
    });

    expect(config.maxInputBytes).toBe(4096);
    expect(config.maxOutputTokens).toBe(1024);
  });

  it("normalizes and deduplicates public RPC fallback URLs", () => {
    const config = createRuntimeConfig({
      VITE_RPC_URL: "https://legacy.example",
      VITE_RPC_URLS: "https://primary.example, https://secondary.example/,https://primary.example/",
    });

    expect(config.rpcUrl).toBe("https://primary.example/");
    expect(config.rpcUrls).toEqual([
      "https://primary.example/",
      "https://secondary.example/",
    ]);
  });

  it("enables V3 only with the exact version and every manifest field", () => {
    const config = createRuntimeConfig(completeV3Env);
    expect(getV3ConfigurationIssues(config)).toEqual([]);
    expect(hasCompleteV3Deployment(config)).toBe(true);
    expect(getV3ReadGate(config).enabled).toBe(true);
  });

  it("enables the separate V4 session manifest without weakening V3 checks", () => {
    const config = createRuntimeConfig(completeV4Env);
    expect(getV4ConfigurationIssues(config)).toEqual([]);
    expect(hasCompleteV4Deployment(config)).toBe(true);
    expect(config.sessionDeployment.protocolVersion).toBe(4);
    expect(config.sessionDeployment.settlementAddress).toBe("0x0000000000000000000000000000000000000011");
    expect(hasCompleteV3Deployment(config)).toBe(false);
  });

  it("rejects an address unless the V4 protocol version is explicit", () => {
    const config = createRuntimeConfig({ VITE_SESSION_SETTLEMENT_ADDRESS: completeV4Env.VITE_SESSION_SETTLEMENT_ADDRESS });
    expect(hasCompleteV4Deployment(config)).toBe(false);
    expect(getV4ConfigurationIssues(config)).toContain("VITE_SESSION_PROTOCOL_VERSION must be exactly 4");
  });

  it("fails closed for a legacy deployment even when all addresses exist", () => {
    const config = createRuntimeConfig({ ...completeV3Env, VITE_PROTOCOL_VERSION: "2" });
    const gate = getV3ReadGate(config);
    expect(gate.enabled).toBe(false);
    expect(gate.code).toBe("manifest_incomplete");
    expect(gate.issues).toContain("VITE_PROTOCOL_VERSION must be exactly 3");
  });

  it("requires a wallet on the configured chain before writes", () => {
    const config = createRuntimeConfig(completeV3Env);
    expect(getV3WriteGate({ connected: false }, config).code).toBe("wallet_disconnected");
    expect(getV3WriteGate({ connected: true, chainId: 1 }, config).code).toBe("wrong_chain");
    expect(getV3WriteGate({ connected: true, chainId: 11155111 }, config).enabled).toBe(true);
  });

  it("recognizes the canonical and preview app hostnames", () => {
    expect(isAppHostname("app.mycomesh.xyz")).toBe(true);
    expect(isAppHostname("app.preview.mycomesh.xyz")).toBe(true);
    expect(isAppHostname("mycomesh.xyz")).toBe(false);
  });

  it("builds dApp deep links for path and dedicated-host configurations", () => {
    expect(appRouteUrl("access", "/app")).toBe("/app/access");
    expect(appRouteUrl("contracts", "https://app.mycomesh.xyz")).toBe(
      "https://app.mycomesh.xyz/app/contracts",
    );
    expect(appRouteUrl("funds", "https://preview.example/app/")).toBe(
      "https://preview.example/app/funds",
    );
  });
});
