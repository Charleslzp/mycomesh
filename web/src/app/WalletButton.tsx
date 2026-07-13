import { ChevronDown, LogOut, Wallet } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useAccount, useConnect, useDisconnect, useSwitchChain } from "wagmi";
import { runtimeConfig } from "../protocol/config";
import { truncateMiddle } from "./ui";

export function WalletButton() {
  const [open, setOpen] = useState(false);
  const controlRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const disconnectRef = useRef<HTMLButtonElement>(null);
  const { address, chainId, isConnected } = useAccount();
  const { connectors, connect, error: connectError, isPending } = useConnect();
  const { disconnect } = useDisconnect();
  const { switchChain, isPending: isSwitching } = useSwitchChain();
  const wrongChain = isConnected && chainId !== runtimeConfig.chainId;

  useEffect(() => {
    if (!open) return;
    disconnectRef.current?.focus();
    function closeOnOutsidePointer(event: PointerEvent) {
      if (!controlRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      setOpen(false);
      triggerRef.current?.focus();
    }
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  if (!isConnected) {
    return (
      <div className="wallet-control">
        <button
          className="button button--primary wallet-control__connect"
          disabled={isPending || connectors.length === 0}
          onClick={() => connectors[0] && connect({ connector: connectors[0] })}
          type="button"
        >
          <Wallet aria-hidden="true" size={17} />
          {isPending ? "Connecting" : "Connect wallet"}
        </button>
        {connectError ? <span className="wallet-control__error">{connectError.message}</span> : null}
      </div>
    );
  }

  if (wrongChain) {
    return (
      <button
        className="button button--warning"
        disabled={isSwitching}
        onClick={() => switchChain({ chainId: runtimeConfig.chainId })}
        type="button"
      >
        {isSwitching ? "Switching" : `Switch to ${runtimeConfig.networkName}`}
      </button>
    );
  }

  return (
    <div ref={controlRef} className="wallet-control wallet-control--connected">
      <button
        ref={triggerRef}
        aria-expanded={open}
        aria-controls="wallet-control-menu"
        aria-haspopup="menu"
        className="button button--wallet"
        onClick={() => setOpen((value) => !value)}
        type="button"
      >
        <span className="wallet-control__indicator" aria-hidden="true" />
        {truncateMiddle(address || "")}
        <ChevronDown aria-hidden="true" size={15} />
      </button>
      {open ? (
        <div className="wallet-control__menu" id="wallet-control-menu" role="menu">
          <span role="presentation">{runtimeConfig.networkName}</span>
          <button
            ref={disconnectRef}
            role="menuitem"
            onClick={() => {
              disconnect();
              setOpen(false);
            }}
            type="button"
          >
            <LogOut aria-hidden="true" size={15} />
            Disconnect
          </button>
        </div>
      ) : null}
    </div>
  );
}
