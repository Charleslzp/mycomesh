import { describe, expect, it } from "vitest";
import { createRuntimeConfig } from "./config";
import { evaluateV3Deployment, evaluateV4Deployment, type V3DeploymentEvidence, type V4DeploymentEvidence } from "./deployment";

const config = createRuntimeConfig({
  VITE_PROTOCOL_VERSION: "3",
  VITE_CHAIN_ID: "11155111",
  VITE_SETTLEMENT_ADDRESS: "0x0000000000000000000000000000000000000001",
  VITE_STABLECOIN_ADDRESS: "0x0000000000000000000000000000000000000002",
  VITE_TOKEN_ADDRESS: "0x0000000000000000000000000000000000000003",
  VITE_TREASURY_ADDRESS: "0x0000000000000000000000000000000000000004",
  VITE_GOVERNANCE_ADDRESS: "0x0000000000000000000000000000000000000005",
  VITE_DEPLOYMENT_BLOCK: "8123456",
  VITE_STABLECOIN_SYMBOL: "tUSDC",
  VITE_STABLECOIN_DECIMALS: "6",
});

const validEvidence: V3DeploymentEvidence = {
  latestBlock: 8_200_000n,
  settlementCode: "0x6000",
  stablecoinCode: "0x6001",
  tokenCode: "0x6002",
  bindings: [
    config.deployment.stablecoinAddress,
    config.deployment.tokenAddress,
    config.deployment.treasuryAddress,
    config.deployment.governanceAddress,
    config.deployment.settlementAddress,
    6,
    "tUSDC",
  ],
};

describe("V3 on-chain deployment verification", () => {
  it("accepts bytecode and bindings that exactly match the manifest", () => {
    expect(evaluateV3Deployment(validEvidence, config)).toMatchObject({
      status: "verified",
      verified: true,
      issues: [],
    });
  });

  it("fails closed for an address binding mismatch", () => {
    const result = evaluateV3Deployment({
      ...validEvidence,
      bindings: [
        "0x00000000000000000000000000000000000000aa",
        ...validEvidence.bindings!.slice(1),
      ],
    }, config);
    expect(result).toMatchObject({ status: "invalid", verified: false });
    expect(result.issues).toContain("Settlement stablecoin does not match the manifest.");
  });

  it("fails closed when contract code or RPC verification is unavailable", () => {
    expect(evaluateV3Deployment({ ...validEvidence, tokenCode: "0x" }, config)).toMatchObject({
      status: "invalid",
      verified: false,
    });
    expect(evaluateV3Deployment({ errors: [new Error("RPC offline")] }, config)).toMatchObject({
      status: "unavailable",
      verified: false,
    });
  });
});

describe("V4 session deployment verification", () => {
  const v4Config = createRuntimeConfig({
    ...{
      VITE_PROTOCOL_VERSION: "3",
      VITE_CHAIN_ID: "11155111",
      VITE_SETTLEMENT_ADDRESS: "0x0000000000000000000000000000000000000001",
      VITE_STABLECOIN_ADDRESS: "0x0000000000000000000000000000000000000002",
      VITE_TOKEN_ADDRESS: "0x0000000000000000000000000000000000000003",
      VITE_TREASURY_ADDRESS: "0x0000000000000000000000000000000000000004",
      VITE_GOVERNANCE_ADDRESS: "0x0000000000000000000000000000000000000005",
      VITE_DEPLOYMENT_BLOCK: "8123456",
      VITE_STABLECOIN_SYMBOL: "tUSDC",
      VITE_STABLECOIN_DECIMALS: "6",
    },
    VITE_SESSION_PROTOCOL_VERSION: "4",
    VITE_SESSION_SETTLEMENT_ADDRESS: "0x0000000000000000000000000000000000000011",
    VITE_SESSION_DEPLOYMENT_BLOCK: "8123457",
  });
  const validEvidence: V4DeploymentEvidence = {
    latestBlock: 8_200_000n,
    settlementCode: "0x6000",
    stablecoinCode: "0x6001",
    stablecoinBinding: v4Config.deployment.stablecoinAddress,
  };

  it("accepts a deployed V4 escrow and its stablecoin binding", () => {
    expect(evaluateV4Deployment(validEvidence, v4Config)).toMatchObject({
      status: "verified",
      verified: true,
      issues: [],
    });
  });

  it("fails closed when the V4 stablecoin binding is wrong", () => {
    const result = evaluateV4Deployment({
      ...validEvidence,
      stablecoinBinding: "0x00000000000000000000000000000000000000aa",
    }, v4Config);
    expect(result).toMatchObject({ status: "invalid", verified: false });
    expect(result.issues).toContain("Settlement V4 stablecoin does not match the manifest.");
  });
});
