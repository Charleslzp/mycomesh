import { createConfig, http } from "wagmi";
import { injected } from "wagmi/connectors";
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
          default: { http: [runtimeConfig.rpcUrl || "http://127.0.0.1:8545"] },
        },
        blockExplorers: {
          default: { name: "Explorer", url: runtimeConfig.explorerUrl },
        },
        testnet: true,
      });

export const wagmiConfig = createConfig({
  chains: [configuredChain],
  connectors: [injected()],
  transports: {
    [configuredChain.id]: http(runtimeConfig.rpcUrl),
  },
});
