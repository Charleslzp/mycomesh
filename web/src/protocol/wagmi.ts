import { fallback, http } from "viem";
import { createConfig } from "wagmi";
import { injected, walletConnect } from "wagmi/connectors";
import { defineChain } from "viem";
import { sepolia } from "viem/chains";
import { runtimeConfig } from "./config";

export const configuredChain =
  runtimeConfig.chainId === sepolia.id
    ? sepolia
    : defineChain({
        id: runtimeConfig.chainId,
        name: runtimeConfig.networkName,
        nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
        rpcUrls: {
          default: { http: runtimeConfig.rpcUrls.length ? [...runtimeConfig.rpcUrls] : ["http://127.0.0.1:8545"] },
        },
        blockExplorers: {
          default: { name: "Explorer", url: runtimeConfig.explorerUrl },
        },
        testnet: true,
      });

const connectors = [injected()];
if (runtimeConfig.walletConnectProjectId) {
  connectors.push(walletConnect({ projectId: runtimeConfig.walletConnectProjectId }));
}

export const wagmiConfig = createConfig({
  chains: [configuredChain],
  connectors,
  transports: {
    [configuredChain.id]: runtimeConfig.rpcUrls.length
      ? fallback(runtimeConfig.rpcUrls.map((url) => http(url)))
      : http(),
  },
});
