import { getAddress, isAddress } from "viem";

export type HexAddress = `0x${string}`;

export type PublicRuntimeEnv = Partial<
  Record<
    | "VITE_API_BASE_URL"
    | "VITE_BRIDGE_BASE_URL"
    | "VITE_SITE_URL"
    | "VITE_APP_URL"
    | "VITE_DOCS_URL"
    | "VITE_GITHUB_URL"
    | "VITE_NETWORK_NAME"
    | "VITE_CHAIN_ID"
    | "VITE_RPC_URL"
    | "VITE_EXPLORER_URL"
    | "VITE_STABLECOIN_SYMBOL"
    | "VITE_STABLECOIN_DECIMALS"
    | "VITE_PROTOCOL_VERSION"
    | "VITE_SETTLEMENT_ADDRESS"
    | "VITE_STABLECOIN_ADDRESS"
    | "VITE_TOKEN_ADDRESS"
    | "VITE_TREASURY_ADDRESS"
    | "VITE_GOVERNANCE_ADDRESS"
    | "VITE_DEPLOYMENT_BLOCK",
    string | undefined
  >
>;

export interface V3DeploymentConfig {
  protocolVersion: number;
  settlementAddress: HexAddress | null;
  stablecoinAddress: HexAddress | null;
  tokenAddress: HexAddress | null;
  treasuryAddress: HexAddress | null;
  governanceAddress: HexAddress | null;
  deploymentBlock: number | null;
}

export interface RuntimeConfig {
  apiBaseUrl: string;
  bridgeBaseUrl: string;
  siteUrl: string;
  appUrl: string;
  docsUrl: string;
  githubUrl: string;
  networkName: string;
  chainId: number;
  rpcUrl: string | undefined;
  explorerUrl: string;
  stablecoinSymbol: string;
  stablecoinDecimals: number;
  deployment: V3DeploymentConfig;
}

function positiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function optionalAddress(value: string | undefined): HexAddress | null {
  const candidate = value?.trim();
  if (!candidate || !isAddress(candidate, { strict: false })) return null;
  try {
    return getAddress(candidate);
  } catch {
    return null;
  }
}

function normalizedBaseUrl(value: string | undefined, fallback: string): string {
  const candidate = value?.trim() || fallback;
  const normalized = candidate.replace(/\/+$/, "");
  return normalized || "/";
}

export function createRuntimeConfig(env: PublicRuntimeEnv): RuntimeConfig {
  const protocolVersion = Number(env.VITE_PROTOCOL_VERSION || 0);
  const deploymentBlock = Number(env.VITE_DEPLOYMENT_BLOCK || 0);

  return {
    apiBaseUrl: normalizedBaseUrl(env.VITE_API_BASE_URL, "/proxy-api"),
    bridgeBaseUrl: normalizedBaseUrl(env.VITE_BRIDGE_BASE_URL, "/bridge-api"),
    siteUrl: env.VITE_SITE_URL?.trim() || "/",
    appUrl: env.VITE_APP_URL?.trim() || "/app",
    docsUrl: env.VITE_DOCS_URL?.trim() || "/#developers",
    githubUrl: env.VITE_GITHUB_URL?.trim() || "https://github.com/mycomesh",
    networkName: env.VITE_NETWORK_NAME?.trim() || "Sepolia testnet",
    chainId: positiveInteger(env.VITE_CHAIN_ID, 11155111),
    rpcUrl: env.VITE_RPC_URL?.trim() || undefined,
    explorerUrl: normalizedBaseUrl(env.VITE_EXPLORER_URL, "https://sepolia.etherscan.io"),
    stablecoinSymbol: env.VITE_STABLECOIN_SYMBOL?.trim() || "tUSDC",
    stablecoinDecimals: positiveInteger(env.VITE_STABLECOIN_DECIMALS, 6),
    deployment: {
      protocolVersion: Number.isSafeInteger(protocolVersion) ? protocolVersion : 0,
      settlementAddress: optionalAddress(env.VITE_SETTLEMENT_ADDRESS),
      stablecoinAddress: optionalAddress(env.VITE_STABLECOIN_ADDRESS),
      tokenAddress: optionalAddress(env.VITE_TOKEN_ADDRESS),
      treasuryAddress: optionalAddress(env.VITE_TREASURY_ADDRESS),
      governanceAddress: optionalAddress(env.VITE_GOVERNANCE_ADDRESS),
      deploymentBlock:
        Number.isSafeInteger(deploymentBlock) && deploymentBlock > 0 ? deploymentBlock : null,
    },
  };
}

export function getV3ConfigurationIssues(config: RuntimeConfig): string[] {
  const issues: string[] = [];
  const deployment = config.deployment;
  if (deployment.protocolVersion !== 3) issues.push("VITE_PROTOCOL_VERSION must be exactly 3");
  if (!deployment.settlementAddress) issues.push("VITE_SETTLEMENT_ADDRESS is missing or invalid");
  if (!deployment.stablecoinAddress) issues.push("VITE_STABLECOIN_ADDRESS is missing or invalid");
  if (!deployment.tokenAddress) issues.push("VITE_TOKEN_ADDRESS is missing or invalid");
  if (!deployment.treasuryAddress) issues.push("VITE_TREASURY_ADDRESS is missing or invalid");
  if (!deployment.governanceAddress) issues.push("VITE_GOVERNANCE_ADDRESS is missing or invalid");
  if (!deployment.deploymentBlock) issues.push("VITE_DEPLOYMENT_BLOCK is missing or invalid");
  return issues;
}

export function hasCompleteV3Deployment(config: RuntimeConfig): boolean {
  return getV3ConfigurationIssues(config).length === 0;
}

export const runtimeConfig = createRuntimeConfig(import.meta.env);

// Contract reads and writes must both fail closed until a complete V3 manifest is supplied.
export const isV3Configured = hasCompleteV3Deployment(runtimeConfig);

export function appRouteUrl(route = "", appUrl = runtimeConfig.appUrl): string {
  const segment = route.trim().replace(/^\/+|\/+$/g, "");
  if (!segment) return appUrl;

  try {
    const url = new URL(appUrl);
    const basePath = url.pathname.replace(/\/+$/, "");
    url.pathname = `${basePath && basePath !== "/" ? basePath : "/app"}/${segment}`;
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    const basePath = appUrl.replace(/\/+$/, "") || "/app";
    return `${basePath}/${segment}`;
  }
}

export function isAppHostname(hostname?: string): boolean {
  const candidate = hostname ?? (typeof window === "undefined" ? "" : window.location.hostname);
  return candidate === "app.mycomesh.xyz" || candidate.startsWith("app.");
}
