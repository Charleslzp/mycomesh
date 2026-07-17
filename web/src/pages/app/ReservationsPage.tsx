import { ArchiveX, Boxes, Clock3, ExternalLink, LoaderCircle, LockKeyhole } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { isHex, zeroAddress } from "viem";
import { useAccount, useReadContract, useWaitForTransactionReceipt, useWriteContract } from "wagmi";
import { EmptyState, FieldError, Metric, Notice, PageHeader, Panel, Status, formatTime, truncateMiddle } from "../../app/ui";
import { settlementV3Abi } from "../../protocol/abis";
import { isV3Configured, runtimeConfig } from "../../protocol/config";
import { useV3DeploymentVerification } from "../../protocol/deployment";
import {
  findReservationRecovery,
  removeReservationRecovery,
  reservationIdFromQuery,
  type ReservationRecoveryRecord,
} from "../../protocol/reservationRecovery";
import { errorMessage, formatTokenAmount } from "./helpers";

export function ReservationsPage() {
  const { address, chainId, isConnected } = useAccount();
  const [searchParams, setSearchParams] = useSearchParams();
  const [reservationId, setReservationId] = useState("");
  const [recoveredReservation, setRecoveredReservation] = useState<ReservationRecoveryRecord | null>(null);
  const [releaseSubmission, setReleaseSubmission] = useState<{
    reservationId: `0x${string}`;
    transactionHash: `0x${string}`;
    consumer: `0x${string}`;
  } | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const settlement = runtimeConfig.deployment.settlementAddress ?? zeroAddress;
  const deploymentVerification = useV3DeploymentVerification();
  const readEnabled = deploymentVerification.verified && Boolean(address) && chainId === runtimeConfig.chainId;
  const locked = useReadContract({
    address: settlement,
    abi: settlementV3Abi,
    chainId: runtimeConfig.chainId,
    functionName: "lockedBalance",
    args: [address ?? zeroAddress],
    query: { enabled: readEnabled },
  });
  const { data: transactionHash, error: writeError, isPending: isWriting, writeContractAsync } = useWriteContract();
  const transaction = useWaitForTransactionReceipt({ hash: transactionHash, chainId: runtimeConfig.chainId });
  const validId = isHex(reservationId, { strict: true }) && reservationId.length === 66;
  const recoveryQuery = reservationIdFromQuery(searchParams);

  useEffect(() => {
    const queryValue = recoveryQuery.trim();
    const queryValid = isHex(queryValue, { strict: true }) && queryValue.length === 66;
    if (queryValue && !queryValid) {
      setRecoveredReservation(null);
      setReservationId(queryValue);
      return;
    }
    if (!address || chainId !== runtimeConfig.chainId || settlement === zeroAddress) {
      setRecoveredReservation(null);
      if (queryValue) setReservationId(queryValue);
      return;
    }
    const recovered = findReservationRecovery(
      {
        chainId: runtimeConfig.chainId,
        settlement,
        consumer: address,
        ...(queryValid ? { reservationId: queryValue } : {}),
      },
      { requireTransaction: !queryValid },
    );
    setRecoveredReservation(recovered);
    setReservationId(queryValue || recovered?.reservationId || "");
  }, [address, chainId, recoveryQuery, settlement]);

  useEffect(() => {
    if (
      !transaction.isSuccess ||
      !transactionHash ||
      !releaseSubmission ||
      transactionHash.toLowerCase() !== releaseSubmission.transactionHash.toLowerCase()
    ) return;
    removeReservationRecovery({
      chainId: runtimeConfig.chainId,
      settlement,
      consumer: releaseSubmission.consumer,
      reservationId: releaseSubmission.reservationId,
    });
    setRecoveredReservation(null);
    setReservationId("");
    const nextSearch = new URLSearchParams(searchParams);
    nextSearch.delete("reservation_id");
    nextSearch.delete("reservation");
    setSearchParams(nextSearch, { replace: true });
    void locked.refetch();
  }, [transaction.isSuccess, transactionHash, releaseSubmission]);

  function updateReservationId(value: string) {
    const next = value.trim();
    setReservationId(next);
    if (!address || chainId !== runtimeConfig.chainId || settlement === zeroAddress) {
      setRecoveredReservation(null);
      return;
    }
    setRecoveredReservation(findReservationRecovery({
      chainId: runtimeConfig.chainId,
      settlement,
      consumer: address,
      reservationId: next,
    }));
  }

  async function releaseExpired() {
    setLocalError(null);
    if (!isV3Configured || !address || chainId !== runtimeConfig.chainId || !validId) {
      setLocalError("A connected wallet, complete V3 deployment, and 32-byte reservation ID are required.");
      return;
    }
    const currentVerification = await deploymentVerification.verifyNow();
    if (!currentVerification.verified) {
      setLocalError(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
      return;
    }
    try {
      const submittedReservationId = reservationId as `0x${string}`;
      const hash = await writeContractAsync({
        address: settlement,
        abi: settlementV3Abi,
        chainId: runtimeConfig.chainId,
        functionName: "releaseExpiredReservation",
        args: [submittedReservationId],
      });
      setReleaseSubmission({
        reservationId: submittedReservationId,
        transactionHash: hash,
        consumer: address,
      });
    } catch (releaseError) {
      setLocalError(errorMessage(releaseError));
    }
  }

  return (
    <div className="app-page app-page--reservations">
      <PageHeader
        eyebrow="Request funding"
        title="Reservations"
        description="Inspect the connected wallet's aggregate lock and release a known reservation after its on-chain expiry."
        actions={<Status tone={deploymentVerification.verified ? "positive" : "warning"}>{deploymentVerification.verified ? `${runtimeConfig.networkName} verified` : "V3 unavailable"}</Status>}
      />

      {!isV3Configured ? (
        <Notice icon={LockKeyhole} title="Reservation actions are locked" tone="warning">A complete V3 deployment manifest is required before this page can read balances or construct release transactions.</Notice>
      ) : !deploymentVerification.verified ? (
        <Notice icon={LockKeyhole} title="Reservation actions are locked" tone="warning">{deploymentVerification.message} {deploymentVerification.issues[0] ?? "On-chain verification is still pending."}</Notice>
      ) : null}

      <section className="app-metric-grid app-metric-grid--compact" aria-label="Reservation aggregate">
        <Metric label="Consumer" value={address ? truncateMiddle(address) : "Wallet not connected"} />
        <Metric label="Locked balance" value={formatTokenAmount(locked.data, runtimeConfig.stablecoinDecimals)} detail={runtimeConfig.stablecoinSymbol} />
      </section>

      <div className="app-two-column app-reservations-layout">
        <Panel title="Release expired reservation" description="The contract verifies expiry. A non-expired or unknown identifier will revert.">
          <div className="app-release-form">
            {recoveredReservation ? (
              <div className="app-reservation-recovery" role="status">
                <div className="app-reservation-recovery__heading">
                  <Clock3 aria-hidden="true" size={17} />
                  <strong>Recovered reservation</strong>
                </div>
                <dl className="app-definition-list">
                  <div><dt>Expires</dt><dd>{formatTime(recoveredReservation.expiresAt)}</dd></div>
                  <div><dt>Created</dt><dd>{formatTime(recoveredReservation.createdAt)}</dd></div>
                </dl>
                {recoveredReservation.transactionHash ? (
                  <a className="app-transaction-link" href={`${runtimeConfig.explorerUrl}/tx/${recoveredReservation.transactionHash}`} target="_blank" rel="noreferrer">
                    Reservation transaction
                    <span>{truncateMiddle(recoveredReservation.transactionHash, 10, 8)}</span>
                    <ExternalLink aria-hidden="true" size={15} />
                  </a>
                ) : null}
              </div>
            ) : null}
            <label htmlFor="reservation-id">Reservation ID</label>
            <input id="reservation-id" onChange={(event) => updateReservationId(event.target.value)} placeholder="0x... (32 bytes)" value={reservationId} />
            {reservationId && !validId ? <FieldError>Reservation ID must be exactly 32 bytes of hexadecimal data.</FieldError> : null}
            <button className="button button--secondary" disabled={!readEnabled || !validId || isWriting || transaction.isLoading} onClick={releaseExpired} type="button">
              {isWriting || transaction.isLoading ? <LoaderCircle className="is-spinning" aria-hidden="true" size={17} /> : <ArchiveX aria-hidden="true" size={17} />}
              Release after expiry
            </button>
            <FieldError>{localError || (writeError ? errorMessage(writeError) : null) || (transaction.isError ? errorMessage(transaction.error) : null)}</FieldError>
            {transactionHash ? <a className="app-transaction-link" href={`${runtimeConfig.explorerUrl}/tx/${transactionHash}`} target="_blank" rel="noreferrer">{transaction.isSuccess ? "Release confirmed" : "Release submitted"}<span>{truncateMiddle(transactionHash, 10, 8)}</span><ExternalLink aria-hidden="true" size={15} /></a> : null}
          </div>
        </Panel>

        <Panel title="Reservation records" description="ReservationCreated and ReservationReleased are canonical contract events.">
          <EmptyState icon={Boxes} title="No public indexer configured">
            <p>The current API does not expose a wallet reservation list. The console will not reconstruct an incomplete history from a limited RPC window.</p>
            {isV3Configured ? <a href={`${runtimeConfig.explorerUrl}/address/${settlement}#events`} target="_blank" rel="noreferrer">Inspect settlement events <ExternalLink aria-hidden="true" size={14} /></a> : null}
          </EmptyState>
        </Panel>
      </div>
    </div>
  );
}
