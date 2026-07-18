import { CircleAlert, ExternalLink, FlaskConical, LoaderCircle, LockKeyhole, ShieldCheck, WalletCards } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { formatUnits, parseUnits, zeroAddress } from "viem";
import {
  useAccount,
  useReadContract,
  useWaitForTransactionReceipt,
  useWriteContract,
} from "wagmi";
import { FieldError, Metric, Notice, PageHeader, Panel, Status, truncateMiddle } from "../../app/ui";
import { erc20Abi, settlementV3Abi, settlementV4Abi, testUsdcAbi } from "../../protocol/abis";
import { isV3Configured, isV4Configured, runtimeConfig } from "../../protocol/config";
import { useV3DeploymentVerification, useV4DeploymentVerification } from "../../protocol/deployment";
import { errorMessage, formatTokenAmount } from "./helpers";

type FundsAction = "approve" | "deposit" | "withdraw" | "mint";

export function FundsPage() {
  const { address, chainId, isConnected } = useAccount();
  const [mode, setMode] = useState<"deposit" | "withdraw">("deposit");
  const [amount, setAmount] = useState("");
  const [action, setAction] = useState<FundsAction | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const sessionSettlement = runtimeConfig.sessionDeployment.settlementAddress ?? zeroAddress;
  const legacySettlement = runtimeConfig.deployment.settlementAddress ?? zeroAddress;
  // V4 is the public funds target. V3 remains selectable only by builds that
  // have not yet published the session deployment manifest.
  const useSessionSettlement = isV4Configured;
  const settlement = useSessionSettlement ? sessionSettlement : legacySettlement;
  const stablecoin = runtimeConfig.deployment.stablecoinAddress ?? zeroAddress;
  const deploymentVerification = useV3DeploymentVerification();
  const sessionDeploymentVerification = useV4DeploymentVerification();
  const readEnabled = (useSessionSettlement ? sessionDeploymentVerification.verified : deploymentVerification.verified)
    && Boolean(address) && chainId === runtimeConfig.chainId;
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
    address: legacySettlement,
    abi: settlementV3Abi,
    chainId: runtimeConfig.chainId,
    functionName: "availableBalance",
    args: [readAddress],
    query: { enabled: readEnabled && !useSessionSettlement },
  });
  const locked = useReadContract({
    address: legacySettlement,
    abi: settlementV3Abi,
    chainId: runtimeConfig.chainId,
    functionName: "lockedBalance",
    args: [readAddress],
    query: { enabled: readEnabled && !useSessionSettlement },
  });
  const prepaid = useReadContract({
    address: legacySettlement,
    abi: settlementV3Abi,
    chainId: runtimeConfig.chainId,
    functionName: "prepaidBalance",
    args: [readAddress],
    query: { enabled: readEnabled && !useSessionSettlement },
  });
  const sessionAvailable = useReadContract({
    address: sessionSettlement,
    abi: settlementV4Abi,
    chainId: runtimeConfig.chainId,
    functionName: "availableBalance",
    args: [readAddress],
    query: { enabled: readEnabled && useSessionSettlement },
  });
  const sessionLocked = useReadContract({
    address: sessionSettlement,
    abi: settlementV4Abi,
    chainId: runtimeConfig.chainId,
    functionName: "lockedBalance",
    args: [readAddress],
    query: { enabled: readEnabled && useSessionSettlement },
  });
  const sessionPrepaid = useReadContract({
    address: sessionSettlement,
    abi: settlementV4Abi,
    chainId: runtimeConfig.chainId,
    functionName: "prepaidBalance",
    args: [readAddress],
    query: { enabled: readEnabled && useSessionSettlement },
  });
  const { data: transactionHash, error: writeError, isPending: isWriting, writeContractAsync } = useWriteContract();
  const transaction = useWaitForTransactionReceipt({ hash: transactionHash, chainId: runtimeConfig.chainId });
  const wrongChain = isConnected && chainId !== runtimeConfig.chainId;
  const decimals = runtimeConfig.stablecoinDecimals;
  const availableData = useSessionSettlement ? sessionAvailable.data : available.data;
  const lockedData = useSessionSettlement ? sessionLocked.data : locked.data;
  const prepaidData = useSessionSettlement ? sessionPrepaid.data : prepaid.data;

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
  const insufficientAvailable = mode === "withdraw" && parsedAmount !== null && (availableData ?? 0n) < parsedAmount;
  const pending = isWriting || transaction.isLoading;
  const testnetFaucetEnabled = runtimeConfig.chainId === 11155111;

  useEffect(() => {
    if (!transaction.isSuccess) return;
    void Promise.all([
      tokenBalance.refetch(),
      allowance.refetch(),
      available.refetch(),
      locked.refetch(),
      prepaid.refetch(),
      sessionAvailable.refetch(),
      sessionLocked.refetch(),
      sessionPrepaid.refetch(),
    ]);
    if (action !== "approve") setAmount("");
  }, [transaction.isSuccess]); // Refetch only when a submitted transaction reaches a receipt.

  async function submit(nextAction: Exclude<FundsAction, "mint">) {
    setLocalError(null);
    if ((!useSessionSettlement && !isV3Configured) || (useSessionSettlement && !isV4Configured) || !address || chainId !== runtimeConfig.chainId) {
      setLocalError(`Wallet, chain, or complete Settlement ${useSessionSettlement ? "V4" : "V3"} deployment configuration is missing.`);
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
    if (nextAction === "withdraw" && (availableData ?? 0n) < parsedAmount) {
      setLocalError("The settlement contract does not report enough available balance.");
      return;
    }

    if (!useSessionSettlement) {
      const currentVerification = await deploymentVerification.verifyNow();
      if (!currentVerification.verified) {
        setLocalError(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
        return;
      }
    } else {
      const currentVerification = await sessionDeploymentVerification.verifyNow();
      if (!currentVerification.verified) {
        setLocalError(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
        return;
      }
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
          abi: useSessionSettlement ? settlementV4Abi : settlementV3Abi,
          chainId: runtimeConfig.chainId,
          functionName: nextAction,
          args: [parsedAmount],
        });
      }
    } catch (submissionError) {
      setLocalError(errorMessage(submissionError));
    }
  }

  async function mintTestTokens() {
    setLocalError(null);
    if (!testnetFaucetEnabled || (!useSessionSettlement && !isV3Configured) || (useSessionSettlement && !isV4Configured) || !address || chainId !== runtimeConfig.chainId) {
      setLocalError("The Sepolia test-token faucet is unavailable.");
      return;
    }
    if (!useSessionSettlement) {
      const currentVerification = await deploymentVerification.verifyNow();
      if (!currentVerification.verified) {
        setLocalError(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
        return;
      }
    } else {
      const currentVerification = await sessionDeploymentVerification.verifyNow();
      if (!currentVerification.verified) {
        setLocalError(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
        return;
      }
    }
    setAction("mint");
    try {
      await writeContractAsync({
        address: stablecoin,
        abi: testUsdcAbi,
        chainId: runtimeConfig.chainId,
        functionName: "mint",
        args: [address, parseUnits("100", decimals)],
      });
    } catch (submissionError) {
      setLocalError(errorMessage(submissionError));
    }
  }

  const actionLabel = action === "approve" ? "Approval" : action === "deposit" ? "Deposit" : action === "mint" ? "Test mint" : "Withdrawal";

  return (
    <div className="app-page app-page--funds">
      <PageHeader
        eyebrow="Settlement"
        title="Funds"
        description={useSessionSettlement
          ? "Manage the bounded prepaid balance used by API-like V4 inference sessions."
          : "Manage the stablecoin balance available to V3 request reservations."}
        actions={
          <Status tone={useSessionSettlement ? sessionDeploymentVerification.verified ? "positive" : "warning" : deploymentVerification.verified ? "positive" : "warning"}>
            {useSessionSettlement
              ? "V4 session escrow"
              : deploymentVerification.verified
                ? "V3 verified on-chain"
              : deploymentVerification.status === "checking"
                ? "Verifying V3"
                : "V3 locked"}
          </Status>
        }
      />

      {useSessionSettlement && !sessionDeploymentVerification.verified ? (
        <Notice icon={LockKeyhole} title="Settlement V4 writes are locked" tone="warning">
          {sessionDeploymentVerification.message} {sessionDeploymentVerification.issues[0] ?? "On-chain verification is still pending."}
        </Notice>
      ) : !useSessionSettlement && !isV3Configured ? (
        <Notice icon={LockKeyhole} title="Chain writes are locked" tone="warning">
          This build does not contain a complete V3 deployment manifest. No legacy V2 address will be used as a
          fallback, and no approval or settlement transaction can be constructed.
        </Notice>
      ) : !useSessionSettlement && !deploymentVerification.verified ? (
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
        <Metric label="Available" value={formatTokenAmount(availableData, decimals)} detail="Can be withdrawn or used for sessions" />
        <Metric label="Locked" value={formatTokenAmount(lockedData, decimals)} detail={useSessionSettlement ? "Held by active sessions" : "Held by active reservations"} />
        <Metric label="Prepaid" value={formatTokenAmount(prepaidData, decimals)} detail={useSessionSettlement ? "Reported by V4 settlement" : "Reported by V3 settlement"} />
      </section>

      <div className="app-two-column app-funds-layout">
        <Panel title="Move funds" description={useSessionSettlement ? "Deposit once into the V4 session escrow; requests are then relayed without wallet prompts." : "Token approval and settlement deposit are separate Ethereum transactions."}>
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
          {testnetFaucetEnabled ? (
            <div className="app-funds-form">
              <p className="app-panel-note">Sepolia only: mint 100 public test tokens with no monetary value.</p>
              <button
                className="button button--secondary"
                disabled={!readEnabled || pending}
                onClick={mintTestTokens}
                type="button"
              >
                {pending && action === "mint" ? <LoaderCircle className="is-spinning" aria-hidden="true" size={17} /> : <FlaskConical aria-hidden="true" size={17} />}
                Mint 100 test tUSDC
              </button>
            </div>
          ) : null}
          <dl className="app-definition-list">
            <div><dt>Approved</dt><dd>{formatTokenAmount(allowance.data, decimals)} {runtimeConfig.stablecoinSymbol}</dd></div>
            <div><dt>Stablecoin</dt><dd>{(useSessionSettlement || isV3Configured) ? truncateMiddle(stablecoin) : "Unavailable"}</dd></div>
            <div><dt>Spender</dt><dd>{(useSessionSettlement || isV3Configured) ? truncateMiddle(settlement) : "Unavailable"}</dd></div>
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
