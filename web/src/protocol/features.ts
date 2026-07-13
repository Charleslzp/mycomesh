import {
  getV3ConfigurationIssues,
  hasCompleteV3Deployment,
  runtimeConfig,
  type RuntimeConfig,
} from "./config";

export type V3GateCode =
  | "ready"
  | "manifest_incomplete"
  | "wallet_disconnected"
  | "wrong_chain";

export interface V3FeatureGate {
  enabled: boolean;
  code: V3GateCode;
  message: string;
  issues: readonly string[];
}

export interface V3WalletState {
  connected: boolean;
  chainId?: number;
}

export function getV3ReadGate(config: RuntimeConfig = runtimeConfig): V3FeatureGate {
  const issues = getV3ConfigurationIssues(config);
  if (!hasCompleteV3Deployment(config)) {
    return {
      enabled: false,
      code: "manifest_incomplete",
      message: "Settlement V3 is unavailable until a complete deployment manifest is configured.",
      issues,
    };
  }
  return { enabled: true, code: "ready", message: "Settlement V3 is available.", issues: [] };
}

export function getV3WriteGate(
  wallet: V3WalletState,
  config: RuntimeConfig = runtimeConfig,
): V3FeatureGate {
  const readGate = getV3ReadGate(config);
  if (!readGate.enabled) return readGate;
  if (!wallet.connected) {
    return {
      enabled: false,
      code: "wallet_disconnected",
      message: "Connect a wallet before submitting a settlement transaction.",
      issues: [],
    };
  }
  if (wallet.chainId !== config.chainId) {
    return {
      enabled: false,
      code: "wrong_chain",
      message: `Switch the connected wallet to ${config.networkName} (chain ${config.chainId}).`,
      issues: [],
    };
  }
  return { enabled: true, code: "ready", message: "Settlement transaction is ready.", issues: [] };
}
