import { ChevronDown, CircleAlert, LogOut, Wallet } from "lucide-react";
import { useAccount, useConnect, useDisconnect, useSwitchChain } from "wagmi";
import { configuredChain } from "../protocol/wagmi";

function shortAddress(address: string) {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function WalletButton() {
  const { address, chainId, isConnected } = useAccount();
  const { connectors, connect, isPending: isConnecting } = useConnect();
  const { disconnect } = useDisconnect();
  const { switchChain, isPending: isSwitching } = useSwitchChain();
  const wrongNetwork = isConnected && chainId !== configuredChain.id;

  if (!isConnected) {
    return (
      <button
        className="wallet-button"
        type="button"
        onClick={() => connectors[0] && connect({ connector: connectors[0] })}
        disabled={isConnecting || connectors.length === 0}
      >
        <Wallet size={17} aria-hidden="true" />
        <span>{isConnecting ? "Connecting…" : connectors.length ? "Connect wallet" : "Wallet unavailable"}</span>
      </button>
    );
  }

  if (wrongNetwork) {
    return (
      <button
        className="wallet-button wallet-button--warning"
        type="button"
        onClick={() => switchChain({ chainId: configuredChain.id })}
        disabled={isSwitching}
      >
        <CircleAlert size={17} aria-hidden="true" />
        <span>{isSwitching ? "Switching…" : `Switch to ${configuredChain.name}`}</span>
      </button>
    );
  }

  return (
    <details className="wallet-menu">
      <summary className="wallet-button" aria-label={`Connected wallet ${address}`}>
        <span className="status-dot status-dot--online" aria-hidden="true" />
        <span>{address ? shortAddress(address) : "Connected"}</span>
        <ChevronDown size={15} aria-hidden="true" />
      </summary>
      <div className="wallet-menu__panel">
        <p>Connected to {configuredChain.name}</p>
        <button type="button" onClick={() => disconnect()}>
          <LogOut size={16} aria-hidden="true" />
          Disconnect
        </button>
      </div>
    </details>
  );
}
