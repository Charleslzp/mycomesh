import { describe, expect, it } from "vitest";
import {
  appRouteUrl,
  createRuntimeConfig,
  getSessionConfigurationIssues,
  getV3ConfigurationIssues,
  hasCompleteSessionDeployment,
  hasCompleteV3Deployment,
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

const completeV5Env: PublicRuntimeEnv = {
  VITE_SESSION_PROTOCOL_VERSION: "5",
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

  it("forces a loopback-served bundle onto the local Consumer edge", () => {
    const config = createRuntimeConfig({
      VITE_API_BASE_URL: "https://gateway.example/v1",
      VITE_BRIDGE_BASE_URL: "https://bridge.example",
    }, "http://127.0.0.1:8110");

    expect(config.apiBaseUrl).toBe("/");
    expect(config.bridgeBaseUrl).toBe("/v1/mycomesh/local");
    expect(config.bridgeAudienceUrl).toBe("http://127.0.0.1:8110");
  });

  it("keeps WalletConnect optional and browser-visible", () => {
    const config = createRuntimeConfig({ VITE_WALLETCONNECT_PROJECT_ID: "public-project-id" });
    expect(config.walletConnectProjectId).toBe("public-project-id");
    expect(createRuntimeConfig({}).walletConnectProjectId).toBeNull();
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

  it("enables the separate V5 session manifest without weakening V3 checks", () => {
    const config = createRuntimeConfig(completeV5Env);
    expect(getSessionConfigurationIssues(config)).toEqual([]);
    expect(hasCompleteSessionDeployment(config)).toBe(true);
    expect(config.sessionDeployment.protocolVersion).toBe(5);
    expect(config.sessionDeployment.settlementAddress).toBe("0x0000000000000000000000000000000000000011");
    expect(hasCompleteV3Deployment(config)).toBe(false);
  });

  it("rejects an address unless protocol V5 is explicit", () => {
    const missing = createRuntimeConfig({ VITE_SESSION_SETTLEMENT_ADDRESS: completeV5Env.VITE_SESSION_SETTLEMENT_ADDRESS });
    const legacy = createRuntimeConfig({ ...completeV5Env, VITE_SESSION_PROTOCOL_VERSION: "4" });
    expect(hasCompleteSessionDeployment(missing)).toBe(false);
    expect(hasCompleteSessionDeployment(legacy)).toBe(false);
    expect(getSessionConfigurationIssues(legacy)).toContain("VITE_SESSION_PROTOCOL_VERSION must be exactly 5");
  });

  it("accepts the V5 address aliases while preferring generic Session variables", () => {
    const aliased = createRuntimeConfig({
      ...completeV5Env,
      VITE_SESSION_SETTLEMENT_ADDRESS: undefined,
      VITE_V5_SETTLEMENT_ADDRESS: "0x0000000000000000000000000000000000000012",
      VITE_V5_DEPLOYMENT_BLOCK: "8123457",
    });
    expect(aliased.sessionDeployment.settlementAddress).toBe("0x0000000000000000000000000000000000000012");
    expect(aliased.sessionDeployment.deploymentBlock).toBe(8123457);
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
