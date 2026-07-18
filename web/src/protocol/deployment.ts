import { getAddress, zeroAddress } from "viem";
import { useBlockNumber, useBytecode, useReadContracts } from "wagmi";
import { erc20Abi, rewardTokenV2Abi, settlementV3Abi, settlementV4Abi } from "./abis";
import {
  getV3ConfigurationIssues,
  getV4ConfigurationIssues,
  isV3Configured,
  isV4Configured,
  runtimeConfig,
  type RuntimeConfig,
} from "./config";

export type V3VerificationStatus =
  | "manifest_missing"
  | "checking"
  | "verified"
  | "invalid"
  | "unavailable";

export interface V3DeploymentEvidence {
  pending?: boolean;
  errors?: readonly unknown[];
  latestBlock?: bigint;
  settlementCode?: string;
  stablecoinCode?: string;
  tokenCode?: string;
  bindings?: readonly unknown[];
}

export interface V3DeploymentVerification {
  status: V3VerificationStatus;
  verified: boolean;
  message: string;
  issues: readonly string[];
}

export type V4VerificationStatus =
  | "manifest_missing"
  | "checking"
  | "verified"
  | "invalid"
  | "unavailable";

export interface V4DeploymentEvidence {
  pending?: boolean;
  errors?: readonly unknown[];
  latestBlock?: bigint;
  settlementCode?: string;
  stablecoinCode?: string;
  stablecoinBinding?: unknown;
}

export interface V4DeploymentVerification {
  status: V4VerificationStatus;
  verified: boolean;
  message: string;
  issues: readonly string[];
}

function deployedCode(value: string | undefined): boolean {
  return Boolean(value && value !== "0x" && value.length > 2);
}

function sameAddress(actual: unknown, expected: string): boolean {
  if (typeof actual !== "string") return false;
  try {
    return getAddress(actual) === getAddress(expected);
  } catch {
    return false;
  }
}

export function evaluateV3Deployment(
  evidence: V3DeploymentEvidence,
  config: RuntimeConfig = runtimeConfig,
): V3DeploymentVerification {
  const manifestIssues = getV3ConfigurationIssues(config);
  if (manifestIssues.length > 0) {
    return {
      status: "manifest_missing",
      verified: false,
      message: "A complete V3 deployment manifest is not configured.",
      issues: manifestIssues,
    };
  }
  if (evidence.pending) {
    return {
      status: "checking",
      verified: false,
      message: "Verifying the V3 deployment against the configured chain.",
      issues: [],
    };
  }
  if (evidence.errors?.some(Boolean)) {
    return {
      status: "unavailable",
      verified: false,
      message: "The configured RPC could not verify the V3 deployment.",
      issues: ["On-chain verification failed. Contract writes remain locked."],
    };
  }

  const deployment = config.deployment;
  const issues: string[] = [];
  if (!deployedCode(evidence.settlementCode)) issues.push("Settlement V3 has no deployed bytecode.");
  if (!deployedCode(evidence.stablecoinCode)) issues.push("Stablecoin has no deployed bytecode.");
  if (!deployedCode(evidence.tokenCode)) issues.push("Reward token has no deployed bytecode.");
  if (evidence.latestBlock === undefined) {
    issues.push("The latest chain block could not be verified.");
  } else if (evidence.latestBlock < BigInt(deployment.deploymentBlock!)) {
    issues.push("The deployment block is ahead of the configured chain.");
  }

  const bindings = evidence.bindings;
  if (!bindings || bindings.length !== 7) {
    issues.push("Settlement and token bindings could not be read.");
  } else {
    if (!sameAddress(bindings[0], deployment.stablecoinAddress!)) {
      issues.push("Settlement stablecoin does not match the manifest.");
    }
    if (!sameAddress(bindings[1], deployment.tokenAddress!)) {
      issues.push("Settlement reward token does not match the manifest.");
    }
    if (!sameAddress(bindings[2], deployment.treasuryAddress!)) {
      issues.push("Settlement treasury does not match the manifest.");
    }
    if (!sameAddress(bindings[3], deployment.governanceAddress!)) {
      issues.push("Settlement governance does not match the manifest.");
    }
    if (!sameAddress(bindings[4], deployment.settlementAddress!)) {
      issues.push("Reward token mint authority is not Settlement V3.");
    }
    if (Number(bindings[5]) !== config.stablecoinDecimals) {
      issues.push("Stablecoin decimals do not match the manifest.");
    }
    if (bindings[6] !== config.stablecoinSymbol) {
      issues.push("Stablecoin symbol does not match the manifest.");
    }
  }

  if (issues.length > 0) {
    return {
      status: "invalid",
      verified: false,
      message: "The on-chain V3 deployment does not match this application build.",
      issues,
    };
  }
  return {
    status: "verified",
    verified: true,
    message: "V3 bytecode and protocol bindings match the deployment manifest.",
    issues: [],
  };
}

export function evaluateV4Deployment(
  evidence: V4DeploymentEvidence,
  config: RuntimeConfig = runtimeConfig,
): V4DeploymentVerification {
  const manifestIssues = getV4ConfigurationIssues(config);
  if (manifestIssues.length > 0) {
    return {
      status: "manifest_missing",
      verified: false,
      message: "A complete V4 session deployment manifest is not configured.",
      issues: manifestIssues,
    };
  }
  if (evidence.pending) {
    return {
      status: "checking",
      verified: false,
      message: "Verifying the V4 session escrow against the configured chain.",
      issues: [],
    };
  }
  if (evidence.errors?.some(Boolean)) {
    return {
      status: "unavailable",
      verified: false,
      message: "The configured RPC could not verify Settlement V4.",
      issues: ["On-chain V4 verification failed. Contract writes remain locked."],
    };
  }
  const deployment = config.sessionDeployment;
  const issues: string[] = [];
  if (!deployedCode(evidence.settlementCode)) issues.push("Settlement V4 has no deployed bytecode.");
  if (!deployedCode(evidence.stablecoinCode)) issues.push("The configured stablecoin has no deployed bytecode.");
  if (evidence.stablecoinBinding === undefined) {
    issues.push("Settlement V4 stablecoin binding could not be read.");
  } else if (!sameAddress(evidence.stablecoinBinding, config.deployment.stablecoinAddress ?? "")) {
    issues.push("Settlement V4 stablecoin does not match the manifest.");
  }
  if (deployment.deploymentBlock) {
    if (evidence.latestBlock === undefined) {
      issues.push("The latest chain block could not be verified for Settlement V4.");
    } else if (evidence.latestBlock < BigInt(deployment.deploymentBlock)) {
      issues.push("The V4 deployment block is ahead of the configured chain.");
    }
  }
  if (issues.length > 0) {
    return {
      status: "invalid",
      verified: false,
      message: "The on-chain V4 session deployment does not match this application build.",
      issues,
    };
  }
  return {
    status: "verified",
    verified: true,
    message: "Settlement V4 bytecode and stablecoin binding match the deployment manifest.",
    issues: [],
  };
}

export function useV3DeploymentVerification() {
  const enabled = isV3Configured;
  const chainId = runtimeConfig.chainId;
  const settlement = runtimeConfig.deployment.settlementAddress ?? zeroAddress;
  const stablecoin = runtimeConfig.deployment.stablecoinAddress ?? zeroAddress;
  const token = runtimeConfig.deployment.tokenAddress ?? zeroAddress;
  const query = { enabled, retry: 1, staleTime: 60_000 } as const;

  const settlementCode = useBytecode({ address: settlement, chainId, query });
  const stablecoinCode = useBytecode({ address: stablecoin, chainId, query });
  const tokenCode = useBytecode({ address: token, chainId, query });
  const latestBlock = useBlockNumber({ chainId, query });
  const bindings = useReadContracts({
    allowFailure: false,
    contracts: [
      { address: settlement, abi: settlementV3Abi, functionName: "stablecoin", chainId },
      { address: settlement, abi: settlementV3Abi, functionName: "rewardToken", chainId },
      { address: settlement, abi: settlementV3Abi, functionName: "treasury", chainId },
      { address: settlement, abi: settlementV3Abi, functionName: "governance", chainId },
      { address: token, abi: rewardTokenV2Abi, functionName: "mintAuthority", chainId },
      { address: stablecoin, abi: erc20Abi, functionName: "decimals", chainId },
      { address: stablecoin, abi: erc20Abi, functionName: "symbol", chainId },
    ] as const,
    query,
  });

  function snapshot() {
    return evaluateV3Deployment({
      settlementCode: settlementCode.data,
      stablecoinCode: stablecoinCode.data,
      tokenCode: tokenCode.data,
      latestBlock: latestBlock.data,
      bindings: bindings.data,
      errors: [
        settlementCode.error,
        stablecoinCode.error,
        tokenCode.error,
        latestBlock.error,
        bindings.error,
      ],
      pending: [
        settlementCode,
        stablecoinCode,
        tokenCode,
        latestBlock,
        bindings,
      ].some((item) => item.isPending),
    });
  }

  async function verifyNow(): Promise<V3DeploymentVerification> {
    if (!enabled) return evaluateV3Deployment({}, runtimeConfig);
    const results = await Promise.all([
      settlementCode.refetch(),
      stablecoinCode.refetch(),
      tokenCode.refetch(),
      latestBlock.refetch(),
      bindings.refetch(),
    ]);
    return evaluateV3Deployment({
      settlementCode: results[0].data,
      stablecoinCode: results[1].data,
      tokenCode: results[2].data,
      latestBlock: results[3].data,
      bindings: results[4].data,
      errors: results.map((result) => result.error),
      pending: false,
    }, runtimeConfig);
  }

  return { ...snapshot(), verifyNow };
}

export function useV4DeploymentVerification() {
  const enabled = isV4Configured;
  const chainId = runtimeConfig.chainId;
  const settlement = runtimeConfig.sessionDeployment.settlementAddress ?? zeroAddress;
  const stablecoin = runtimeConfig.deployment.stablecoinAddress ?? zeroAddress;
  const query = { enabled, retry: 1, staleTime: 60_000 } as const;
  const settlementCode = useBytecode({ address: settlement, chainId, query });
  const stablecoinCode = useBytecode({ address: stablecoin, chainId, query });
  const latestBlock = useBlockNumber({ chainId, query });
  const bindings = useReadContracts({
    allowFailure: false,
    contracts: [
      { address: settlement, abi: settlementV4Abi, functionName: "stablecoin", chainId },
    ] as const,
    query,
  });

  function snapshot() {
    return evaluateV4Deployment({
      settlementCode: settlementCode.data,
      stablecoinCode: stablecoinCode.data,
      latestBlock: latestBlock.data,
      stablecoinBinding: bindings.data?.[0],
      errors: [settlementCode.error, stablecoinCode.error, latestBlock.error, bindings.error],
      pending: [settlementCode, stablecoinCode, latestBlock, bindings].some((item) => item.isPending),
    });
  }

  async function verifyNow(): Promise<V4DeploymentVerification> {
    if (!enabled) return evaluateV4Deployment({}, runtimeConfig);
    const results = await Promise.all([
      settlementCode.refetch(),
      stablecoinCode.refetch(),
      latestBlock.refetch(),
      bindings.refetch(),
    ]);
    return evaluateV4Deployment({
      settlementCode: results[0].data,
      stablecoinCode: results[1].data,
      latestBlock: results[2].data,
      stablecoinBinding: results[3].data?.[0],
      errors: results.map((result) => result.error),
      pending: false,
    }, runtimeConfig);
  }

  return { ...snapshot(), verifyNow };
}
