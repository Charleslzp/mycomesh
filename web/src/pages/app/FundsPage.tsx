import { CircleAlert, ExternalLink, LoaderCircle, LockKeyhole, ShieldCheck, WalletCards } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { formatUnits, parseUnits, zeroAddress } from "viem";
import {
  useAccount,
  useReadContract,
  useWaitForTransactionReceipt,
  useWriteContract,
} from "wagmi";
import { FieldError, Metric, Notice, PageHeader, Panel, Status, truncateMiddle } from "../../app/ui";
import { erc20Abi, settlementV3Abi } from "../../protocol/abis";
import { isV3Configured, runtimeConfig } from "../../protocol/config";
import { useV3DeploymentVerification } from "../../protocol/deployment";
import { errorMessage, formatTokenAmount } from "./helpers";

type FundsAction = "approve" | "deposit" | "withdraw";

export function FundsPage() {
  const { address, chainId, isConnected } = useAccount();
  const [mode, setMode] = useState<"deposit" | "withdraw">("deposit");
  const [amount, setAmount] = useState("");
  const [action, setAction] = useState<FundsAction | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const settlement = runtimeConfig.deployment.settlementAddress ?? zeroAddress;
  const stablecoin = runtimeConfig.deployment.stablecoinAddress ?? zeroAddress;
  const deploymentVerification = useV3DeploymentVerification();
  const readEnabled = deploymentVerification.verified && Boolean(address) && chainId === runtimeConfig.chainId;
  const readAddress = address ?? zeroAddress;

  const tokenBalance = useReadContract({
    address: stablecoin,
    abi: erc20Abi,
    chainId: runtimeConfig.chainId,
    functionName: "balanceOf",
    args: [readAddress],
    query: { enabled: readEnabled },
  });
  const allowance = useReadContract({
    address: stablecoin,
    abi: erc20Abi,
    chainId: runtimeConfig.chainId,
    functionName: "allowance",
    args: [readAddress, settlement],
    query: { enabled: readEnabled },
  });
  const available = useReadContract({
    address: settlement,
    abi: settlementV3Abi,
    chainId: runtimeConfig.chainId,
    functionName: "availableBalance",
    args: [readAddress],
    query: { enabled: readEnabled },
  });
  const locked = useReadContract({
    address: settlement,
    abi: settlementV3Abi,
    chainId: runtimeConfig.chainId,
    functionName: "lockedBalance",
    args: [readAddress],
    query: { enabled: readEnabled },
  });
  const prepaid = useReadContract({
    address: settlement,
    abi: settlementV3Abi,
    chainId: runtimeConfig.chainId,
    functionName: "prepaidBalance",
    args: [readAddress],
    query: { enabled: readEnabled },
  });
  const { data: transactionHash, error: writeError, isPending: isWriting, writeContractAsync } = useWriteContract();
  const transaction = useWaitForTransactionReceipt({ hash: transactionHash, chainId: runtimeConfig.chainId });
  const wrongChain = isConnected && chainId !== runtimeConfig.chainId;
  const decimals = runtimeConfig.stablecoinDecimals;

  const parsedAmount = useMemo(() => {
    try {
      if (!amount.trim() || Number(amount) <= 0) return null;
      return parseUnits(amount, decimals);
    } catch {
      return null;
    }
  }, [amount, decimals]);
  const needsApproval = mode === "deposit" && parsedAmount !== null && (allowance.data ?? 0n) < parsedAmount;
  const insufficientBalance = mode === "deposit" && parsedAmount !== null && (tokenBalance.data ?? 0n) < parsedAmount;
  const insufficientAvailable = mode === "withdraw" && parsedAmount !== null && (available.data ?? 0n) < parsedAmount;
  const pending = isWriting || transaction.isLoading;

  useEffect(() => {
    if (!transaction.isSuccess) return;
    void Promise.all([
      tokenBalance.refetch(),
      allowance.refetch(),
      available.refetch(),
      locked.refetch(),
      prepaid.refetch(),
    ]);
    if (action !== "approve") setAmount("");
  }, [transaction.isSuccess]); // Refetch only when a submitted transaction reaches a receipt.

  async function submit(nextAction: FundsAction) {
    setLocalError(null);
    if (!isV3Configured || !address || chainId !== runtimeConfig.chainId) {
      setLocalError("Wallet, chain, or complete V3 deployment configuration is missing.");
      return;
    }
    if (!parsedAmount) {
      setLocalError("Enter a valid amount greater than zero.");
      return;
    }
    if (nextAction === "deposit" && (tokenBalance.data ?? 0n) < parsedAmount) {
      setLocalError(`The wallet does not hold enough ${runtimeConfig.stablecoinSymbol}.`);
      return;
    }
    if (nextAction === "deposit" && (allowance.data ?? 0n) < parsedAmount) {
      setLocalError("Approve this exact amount before depositing it.");
      return;
    }
    if (nextAction === "withdraw" && (available.data ?? 0n) < parsedAmount) {
      setLocalError("The settlement contract does not report enough available balance.");
      return;
    }

    const currentVerification = await deploymentVerification.verifyNow();
    if (!currentVerification.verified) {
      setLocalError(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
      return;
    }

    setAction(nextAction);
    try {
      if (nextAction === "approve") {
        await writeContractAsync({
          address: stablecoin,
          abi: erc20Abi,
          chainId: runtimeConfig.chainId,
          functionName: "approve",
          args: [settlement, parsedAmount],
        });
      } else {
        await writeContractAsync({
          address: settlement,
          abi: settlementV3Abi,
          chainId: runtimeConfig.chainId,
          functionName: nextAction,
          args: [parsedAmount],
        });
      }
    } catch (submissionError) {
      setLocalError(errorMessage(submissionError));
    }
  }

  const actionLabel = action === "approve" ? "Approval" : action === "deposit" ? "Deposit" : "Withdrawal";

  return (
    <div className="app-page app-page--funds">
      <PageHeader
        eyebrow="Settlement"
        title="Funds"
        description="Manage the stablecoin balance available to V3 request reservations."
        actions={
          <Status tone={deploymentVerification.verified ? "positive" : "warning"}>
            {deploymentVerification.verified
              ? "V3 verified on-chain"
              : deploymentVerification.status === "checking"
                ? "Verifying V3"
                : "V3 locked"}
          </Status>
        }
      />

      {!isV3Configured ? (
        <Notice icon={LockKeyhole} title="Chain writes are locked" tone="warning">
          This build does not contain a complete V3 deployment manifest. No legacy V2 address will be used as a
          fallback, and no approval or settlement transaction can be constructed.
        </Notice>
      ) : !deploymentVerification.verified ? (
        <Notice icon={LockKeyhole} title="On-chain verification required" tone="warning">
          {deploymentVerification.message} {deploymentVerification.issues[0] ?? "No contract transaction can be constructed yet."}
        </Notice>
      ) : !isConnected ? (
        <Notice icon={WalletCards} title="Connect a wallet" tone="neutral">Balances and settlement actions are scoped to the connected consumer address.</Notice>
      ) : wrongChain ? (
        <Notice icon={CircleAlert} title={`Switch to ${runtimeConfig.networkName}`} tone="warning">Settlement writes are disabled while the wallet is connected to chain ID {chainId}.</Notice>
      ) : null}

      <section className="app-metric-grid" aria-label="Settlement balances">
        <Metric label="Wallet" value={formatTokenAmount(tokenBalance.data, decimals)} detail={runtimeConfig.stablecoinSymbol} />
        <Metric label="Available" value={formatTokenAmount(available.data, decimals)} detail="Can be withdrawn or reserved" />
        <Metric label="Locked" value={formatTokenAmount(locked.data, decimals)} detail="Held by active reservations" />
        <Metric label="Prepaid" value={formatTokenAmount(prepaid.data, decimals)} detail="Reported by V3 settlement" />
      </section>

      <div className="app-two-column app-funds-layout">
        <Panel title="Move funds" description="Token approval and settlement deposit are separate Ethereum transactions.">
          <div className="app-segmented-control" aria-label="Funds action">
            <button aria-pressed={mode === "deposit"} onClick={() => { setMode("deposit"); setLocalError(null); }} type="button">Deposit</button>
            <button aria-pressed={mode === "withdraw"} onClick={() => { setMode("withdraw"); setLocalError(null); }} type="button">Withdraw</button>
          </div>
          <div className="app-funds-form">
            <label htmlFor="funds-amount">Amount</label>
            <div className="app-token-input">
              <input
                disabled={!readEnabled || pending}
                id="funds-amount"
                inputMode="decimal"
                onChange={(event) => setAmount(event.target.value)}
                placeholder="0.00"
                value={amount}
              />
              <span>{runtimeConfig.stablecoinSymbol}</span>
            </div>
            {amount && parsedAmount === null ? <FieldError>Enter a valid positive token amount.</FieldError> : null}
            {insufficientBalance ? <FieldError>Wallet balance is too low for this deposit.</FieldError> : null}
            {insufficientAvailable ? <FieldError>Available settlement balance is too low for this withdrawal.</FieldError> : null}

            {mode === "deposit" && needsApproval ? (
              <button className="button button--secondary" disabled={!readEnabled || pending || insufficientBalance} onClick={() => submit("approve")} type="button">
                {pending && action === "approve" ? <LoaderCircle className="is-spinning" aria-hidden="true" size={17} /> : <ShieldCheck aria-hidden="true" size={17} />}
                Approve exact amount
              </button>
            ) : (
              <button
                className="button button--primary"
                disabled={!readEnabled || pending || !parsedAmount || insufficientBalance || insufficientAvailable}
                onClick={() => submit(mode)}
                type="button"
              >
                {pending ? <LoaderCircle className="is-spinning" aria-hidden="true" size={17} /> : <WalletCards aria-hidden="true" size={17} />}
                {mode === "deposit" ? "Deposit funds" : "Withdraw available"}
              </button>
            )}
            <FieldError>{localError || (writeError ? errorMessage(writeError) : null) || (transaction.isError ? errorMessage(transaction.error) : null)}</FieldError>
            {transactionHash ? (
              <a className="app-transaction-link" href={`${runtimeConfig.explorerUrl}/tx/${transactionHash}`} target="_blank" rel="noreferrer">
                {transaction.isSuccess ? `${actionLabel} confirmed` : `${actionLabel} submitted`}
                <span>{truncateMiddle(transactionHash, 10, 8)}</span>
                <ExternalLink aria-hidden="true" size={15} />
              </a>
            ) : null}
          </div>
        </Panel>

        <Panel title="Authorization" description="The console never requests an unlimited ERC-20 allowance.">
          <dl className="app-definition-list">
            <div><dt>Approved</dt><dd>{formatTokenAmount(allowance.data, decimals)} {runtimeConfig.stablecoinSymbol}</dd></div>
            <div><dt>Stablecoin</dt><dd>{isV3Configured ? truncateMiddle(stablecoin) : "Unavailable"}</dd></div>
            <div><dt>Spender</dt><dd>{isV3Configured ? truncateMiddle(settlement) : "Unavailable"}</dd></div>
            <div><dt>Chain</dt><dd>{runtimeConfig.networkName}</dd></div>
          </dl>
          <p className="app-panel-note">
            {runtimeConfig.stablecoinSymbol} is a test token with no monetary value. MycoMesh does not present it as production USDC.
          </p>
          {parsedAmount ? <p className="app-panel-note">Current amount in base units: {formatUnits(parsedAmount, 0)}</p> : null}
        </Panel>
      </div>
    </div>
  );
}
