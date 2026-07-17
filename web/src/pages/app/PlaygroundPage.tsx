import { useQuery } from "@tanstack/react-query";
import { Braces, CircleAlert, CircleCheck, Clock3, ExternalLink, KeyRound, LoaderCircle, RefreshCw, Send, ShieldCheck, Sparkles, WalletCards } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAccount, usePublicClient, useSignMessage, useSignTypedData, useWriteContract } from "wagmi";
import { useApiKey } from "../../state/ApiKeyContext";
import { FieldError, Metric, Notice, PageHeader, Panel, Status, formatTime, truncateMiddle } from "../../app/ui";
import { inferencePeerId, protocolApi, type ConsumerV3Authorization, type InferenceResult } from "../../protocol/api";
import { settlementV3Abi } from "../../protocol/abis";
import { isV3Configured, runtimeConfig } from "../../protocol/config";
import { useV3DeploymentVerification } from "../../protocol/deployment";
import { canonicalInferenceInputBytes } from "../../protocol/inputLimits";
import {
  findReservationRecovery,
  removeReservationRecovery,
  saveReservationRecovery,
  type ReservationRecoveryRecord,
} from "../../protocol/reservationRecovery";
import { assertConsumerV3Plan, consumerV3RequestHash, validateV3Settlement, type ValidatedV3Settlement } from "../../protocol/settlementV3";
import { errorMessage } from "./helpers";

type SettlementStatus =
  | "idle"
  | "validating"
  | "signing"
  | "submitting"
  | "confirming"
  | "settled"
  | "pending"
  | "failed";

interface SettlementContext {
  validated: ValidatedV3Settlement;
  confirmations: number;
}

function settlementTone(status: SettlementStatus): "positive" | "warning" | "negative" | "neutral" {
  if (status === "settled") return "positive";
  if (status === "failed") return "negative";
  if (status === "idle") return "neutral";
  return "warning";
}

function settlementTitle(status: SettlementStatus): string {
  if (status === "settled") return "Settlement confirmed";
  if (status === "failed") return "Settlement failed";
  if (status === "pending") return "Settlement pending";
  if (status === "signing") return "Settlement signing";
  if (status === "submitting") return "Settlement submitting";
  if (status === "confirming") return "Settlement confirming";
  if (status === "validating") return "Settlement validating";
  return "Settlement";
}

export function PlaygroundPage() {
  const { apiKey } = useApiKey();
  const { address, chainId, isConnected } = useAccount();
  const publicClient = usePublicClient({ chainId: runtimeConfig.chainId });
  const { signMessageAsync } = useSignMessage();
  const { signTypedDataAsync } = useSignTypedData();
  const { writeContractAsync } = useWriteContract();
  const deploymentVerification = useV3DeploymentVerification();
  const models = useQuery({ queryKey: ["models"], queryFn: protocolApi.models, retry: 1 });
  const peers = useQuery({ queryKey: ["provider-peers"], queryFn: protocolApi.peers, retry: 1, refetchInterval: 15_000 });
  const [model, setModel] = useState("");
  const [input, setInput] = useState("Explain how request-bound settlement protects an AI inference consumer in three concise points.");
  const [maxOutputTokens, setMaxOutputTokens] = useState(256);
  const [result, setResult] = useState<InferenceResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState("");
  const [phase, setPhase] = useState("Ready");
  const [reservationTransactionHash, setReservationTransactionHash] = useState<`0x${string}` | null>(null);
  const [settlementStatus, setSettlementStatus] = useState<SettlementStatus>("idle");
  const [settlementError, setSettlementError] = useState<string | null>(null);
  const [settlementTransactionHash, setSettlementTransactionHash] = useState<`0x${string}` | null>(null);
  const [settlementContext, setSettlementContext] = useState<SettlementContext | null>(null);
  const [reservationRecovery, setReservationRecovery] = useState<ReservationRecoveryRecord | null>(null);
  const settlementAddress = runtimeConfig.deployment.settlementAddress;
  const eligiblePeers = useMemo(
    () => (peers.data ?? []).filter((peer) => peer.model === model && peer.settlement?.version === 3),
    [model, peers.data],
  );
  const selectedPeer = useMemo(
    () => eligiblePeers.find((peer) => peer.peer_id === selectedProvider),
    [eligiblePeers, selectedProvider],
  );
  const requestInput = input.trim();
  const inputBytes = canonicalInferenceInputBytes(requestInput);
  const inputTooLarge = inputBytes > runtimeConfig.maxInputBytes;
  const settlementBusy = ["validating", "signing", "submitting", "confirming"].includes(settlementStatus);

  useEffect(() => {
    if (!model && models.data?.[0]) setModel(models.data[0].id);
  }, [model, models.data]);

  useEffect(() => {
    if (!eligiblePeers.some((peer) => peer.peer_id === selectedProvider)) {
      setSelectedProvider(eligiblePeers[0]?.peer_id ?? "");
    }
  }, [eligiblePeers, selectedProvider]);

  useEffect(() => {
    if (!address || chainId !== runtimeConfig.chainId || !settlementAddress) {
      setReservationRecovery(null);
      return;
    }
    const recovered = findReservationRecovery({
      chainId: runtimeConfig.chainId,
      settlement: settlementAddress,
      consumer: address,
    });
    setReservationRecovery(recovered);
    setReservationTransactionHash(recovered?.transactionHash ?? null);
  }, [address, chainId, settlementAddress]);

  function clearRecoveredReservation(reservationId: string, consumer: string) {
    if (!settlementAddress) return;
    removeReservationRecovery({
      chainId: runtimeConfig.chainId,
      settlement: settlementAddress,
      consumer,
      reservationId,
    });
    setReservationRecovery((current) =>
      current?.reservationId.toLowerCase() === reservationId.toLowerCase() ? null : current,
    );
    setReservationTransactionHash(null);
  }

  async function settleValidated(
    validated: ValidatedV3Settlement,
    confirmations: number,
  ): Promise<boolean> {
    if (
      !address ||
      chainId !== runtimeConfig.chainId ||
      !publicClient ||
      address.toLowerCase() !== validated.payload.receipt.consumer.toLowerCase()
    ) {
      setSettlementStatus("pending");
      setSettlementError("Reconnect the Consumer wallet used for this reservation before settling.");
      return false;
    }

    setSettlementStatus("signing");
    setPhase("Sign settlement Receipt");
    let consumerSignature: `0x${string}`;
    try {
      consumerSignature = await signTypedDataAsync(validated.typedData);
    } catch {
      setSettlementStatus("pending");
      setSettlementError("Consumer signature was declined. The inference output is preserved.");
      setPhase("Complete");
      return false;
    }

    setSettlementStatus("submitting");
    setSettlementError(null);
    setPhase("Submit settlement");
    let transactionHash: `0x${string}`;
    try {
      transactionHash = await writeContractAsync({
        address: validated.payload.settlement_contract,
        abi: settlementV3Abi,
        chainId: runtimeConfig.chainId,
        functionName: "settleSignedReceipt",
        args: [
          [
            [
              validated.contractReceipt.receiptHash, validated.contractReceipt.acceptedHash, validated.contractReceipt.reservationId, validated.contractReceipt.requestHash, validated.contractReceipt.responseHash, validated.contractReceipt.channel, validated.contractReceipt.pricingVersion, validated.contractReceipt.pricingHash, validated.contractReceipt.consumer, validated.contractReceipt.provider, validated.contractReceipt.relay, validated.contractReceipt.pool, validated.contractReceipt.inputTokens, validated.contractReceipt.outputTokens, validated.contractReceipt.deadline,
            ],
            consumerSignature,
            validated.providerSignature,
          ],
        ],
      });
    } catch (submissionError) {
      setSettlementStatus("failed");
      setSettlementError(errorMessage(submissionError));
      setPhase("Complete");
      return false;
    }

    setSettlementTransactionHash(transactionHash);
    setSettlementStatus("confirming");
    setPhase("Confirm settlement");
    try {
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: transactionHash,
        confirmations: Math.max(1, confirmations),
      });
      if (receipt.status !== "success") {
        throw new Error("The Settlement V3 transaction reverted.");
      }
    } catch (confirmationError) {
      setSettlementStatus("failed");
      setSettlementError(errorMessage(confirmationError));
      setPhase("Complete");
      return false;
    }

    setSettlementStatus("settled");
    setSettlementError(null);
    setPhase("Complete");
    return true;
  }

  async function retrySettlement() {
    if (!settlementContext) return;
    if (settlementTransactionHash && publicClient) {
      setSettlementStatus("confirming");
      setSettlementError(null);
      setPhase("Confirm settlement");
      try {
        const receipt = await publicClient.waitForTransactionReceipt({
          hash: settlementTransactionHash,
          confirmations: Math.max(1, settlementContext.confirmations),
        });
        if (receipt.status !== "success") {
          throw new Error("The Settlement V3 transaction reverted.");
        }
        setSettlementStatus("settled");
        setPhase("Complete");
        clearRecoveredReservation(
          settlementContext.validated.contractReceipt.reservationId,
          settlementContext.validated.payload.receipt.consumer,
        );
      } catch (confirmationError) {
        setSettlementStatus("failed");
        setSettlementError(errorMessage(confirmationError));
        setPhase("Complete");
      }
      return;
    }
    const settled = await settleValidated(settlementContext.validated, settlementContext.confirmations);
    if (settled) {
      clearRecoveredReservation(
        settlementContext.validated.contractReceipt.reservationId,
        settlementContext.validated.payload.receipt.consumer,
      );
    }
  }

  async function runInference() {
    if (inputTooLarge) {
      setError(`Input is ${inputBytes.toLocaleString()} bytes; the Provider limit is ${runtimeConfig.maxInputBytes.toLocaleString()} bytes.`);
      setPhase("Ready");
      return;
    }
    if (
      !apiKey ||
      !model ||
      !requestInput ||
      !selectedProvider ||
      !address ||
      chainId !== runtimeConfig.chainId ||
      !publicClient
    ) return;
    setRunning(true);
    setError(null);
    setResult(null);
    setReservationTransactionHash(null);
    setSettlementStatus("idle");
    setSettlementError(null);
    setSettlementTransactionHash(null);
    setSettlementContext(null);
    try {
      setPhase("Verifying V3");
      const currentVerification = await deploymentVerification.verifyNow();
      if (!currentVerification.verified) {
        throw new Error(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
      }
      setPhase("Preparing reservation");
      const plan = await protocolApi.prepareV3(
        apiKey,
        requestInput,
        model,
        maxOutputTokens,
        selectedProvider,
      );
      const settlementContract = runtimeConfig.deployment.settlementAddress;
      const providerPaymentAddress = selectedPeer?.payment_address;
      const providerChannel = selectedPeer?.channel;
      if (!settlementContract || !providerPaymentAddress || !providerChannel) {
        throw new Error("The selected V3 Provider has no verified payment address.");
      }
      const requestHash = consumerV3RequestHash(requestInput, model, maxOutputTokens);
      assertConsumerV3Plan(plan, {
        chainId: runtimeConfig.chainId,
        settlementContract,
        consumer: address,
        providerId: selectedProvider,
        providerPaymentAddress: providerPaymentAddress as `0x${string}`,
        inputSizeBytes: inputBytes,
        maxOutputTokens,
        reserveInputBytes: runtimeConfig.maxInputBytes,
        reserveOutputTokens: runtimeConfig.maxOutputTokens,
        requestHash,
        channel: providerChannel,
      });
      const [quotedMaximumFee, reservationId, latestPricingVersion, pricingHash] =
        await Promise.all([
          publicClient.readContract({
            address: plan.settlement_contract,
            abi: settlementV3Abi,
            functionName: "quote",
            args: [
              plan.channel_hash,
              BigInt(plan.pricing_version),
              BigInt(plan.reserve_input_bytes),
              BigInt(maxOutputTokens),
            ],
          }),
          publicClient.readContract({
            address: plan.settlement_contract,
            abi: settlementV3Abi,
            functionName: "reservationIdFor",
            args: [address, plan.reservation_salt],
          }),
          publicClient.readContract({
            address: plan.settlement_contract,
            abi: settlementV3Abi,
            functionName: "latestChannelVersion",
            args: [plan.channel_hash],
          }),
          publicClient.readContract({
            address: plan.settlement_contract,
            abi: settlementV3Abi,
            functionName: "channelPricingHash",
            args: [plan.channel_hash, BigInt(plan.pricing_version)],
          }),
        ]);
      if (quotedMaximumFee !== BigInt(plan.max_fee_units)) {
        throw new Error("The reservation amount does not match the confirmed on-chain quote.");
      }
      if (reservationId.toLowerCase() !== plan.onchain_reservation_id.toLowerCase()) {
        throw new Error("The reservation ID does not match the connected Consumer wallet.");
      }
      if (latestPricingVersion !== BigInt(plan.pricing_version)) {
        throw new Error("The Provider plan does not use the latest channel pricing version.");
      }
      if (pricingHash.toLowerCase() !== plan.pricing_hash.toLowerCase()) {
        throw new Error("The Provider plan pricing hash does not match Settlement V3.");
      }
      const requiredConfirmations = Math.max(1, plan.required_confirmations);
      const reservationConfirmations = requiredConfirmations + 1;
      const preparedRecovery = saveReservationRecovery({
        schema: "mycomesh.reservation.recovery.v1",
        chainId: runtimeConfig.chainId,
        settlement: plan.settlement_contract,
        consumer: address,
        reservationId: plan.onchain_reservation_id,
        expiresAt: plan.expires_at,
        transactionHash: null,
        createdAt: Date.now(),
      });
      setReservationRecovery(preparedRecovery);
      setReservationTransactionHash(null);
      setPhase("Confirm reservation");
      const transactionHash = await writeContractAsync({
        address: plan.settlement_contract,
        abi: settlementV3Abi,
        chainId: runtimeConfig.chainId,
        functionName: "createReservation",
        args: [
          plan.reservation_salt,
          plan.provider_payment_address,
          plan.channel_hash,
          plan.request_hash,
          BigInt(plan.pricing_version),
          BigInt(plan.max_fee_units),
          BigInt(plan.expires_at),
          false,
        ],
      });
      const submittedRecovery = saveReservationRecovery({
        ...preparedRecovery,
        transactionHash,
      });
      setReservationRecovery(submittedRecovery);
      setReservationTransactionHash(transactionHash);
      setPhase(`Waiting for ${reservationConfirmations} confirmations`);
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: transactionHash,
        confirmations: reservationConfirmations,
      });
      if (receipt.status !== "success") throw new Error("The V3 reservation transaction reverted.");
      setPhase("Authorize request");
      const walletSignature = await signMessageAsync({ message: plan.authorization_message });
      const authorization: ConsumerV3Authorization = {
        ...plan.authorization,
        wallet_signature: walletSignature,
      };
      setPhase("Routing request");
      const inferenceResult = await protocolApi.infer(apiKey, requestInput, model, maxOutputTokens, {
        provider_id: plan.provider_id,
        authorization,
        reservation_transaction_hash: transactionHash,
      });
      setResult(inferenceResult);
      if (inferenceResult.error || inferenceResult.ok === false) {
        throw new Error(inferenceResult.error || "Provider did not return a successful inference.");
      }

      setPhase("Validating settlement");
      setSettlementStatus("validating");
      try {
        const validated = await validateV3Settlement(inferenceResult.mycomesh_v3_settlement, {
          chainId: runtimeConfig.chainId,
          settlementContract,
          consumer: address,
          providerId: plan.provider_id,
          providerPaymentAddress: providerPaymentAddress as `0x${string}`,
          plan,
          response: inferenceResult,
          providerFallbackAllowed: plan.provider_fallback_allowed,
          inputSizeBytes: inputBytes,
          maxOutputTokens,
          reserveInputBytes: runtimeConfig.maxInputBytes,
          reserveOutputTokens: runtimeConfig.maxOutputTokens,
          requestHash,
          channel: providerChannel,
        });
        setSettlementContext({
          validated,
          confirmations: requiredConfirmations,
        });
        const settled = await settleValidated(validated, requiredConfirmations);
        if (settled) {
          clearRecoveredReservation(plan.onchain_reservation_id, address);
        }
      } catch (settlementValidationError) {
        setSettlementStatus("failed");
        setSettlementError(errorMessage(settlementValidationError));
      }
      setPhase("Complete");
    } catch (inferenceError) {
      setError(errorMessage(inferenceError));
      setPhase("Failed");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="app-page app-page--playground">
      <PageHeader
        eyebrow="Inference"
        title="Playground"
        description="Send one request through the consumer proxy and inspect its returned output, usage, price, and receipt envelope."
        actions={<Status tone={apiKey ? "positive" : "warning"}>{apiKey ? "Credential ready" : "API key required"}</Status>}
      />

      {!apiKey ? (
        <Notice icon={KeyRound} title="Establish consumer access first" tone="warning">
          <Link to="/app/access">Create a wallet-bound API key</Link> before making a billed inference request.
        </Notice>
      ) : null}

      {apiKey && (!isConnected || chainId !== runtimeConfig.chainId) ? (
        <Notice icon={WalletCards} title={isConnected ? `Switch to ${runtimeConfig.networkName}` : "Connect the consumer wallet"} tone="warning">
          The wallet that owns this API key must create and authorize the request reservation.
        </Notice>
      ) : apiKey && (!isV3Configured || !deploymentVerification.verified) ? (
        <Notice icon={CircleAlert} title="Settlement V3 is not ready" tone="warning">
          {deploymentVerification.message}
        </Notice>
      ) : null}

      <div className="app-playground-layout">
        <Panel title="Request" description="This form calls POST /v1/responses. Responses are currently returned after completion, not token-streamed.">
          <form className="app-request-form" onSubmit={(event) => { event.preventDefault(); runInference(); }}>
            <label htmlFor="model">Model</label>
            <select id="model" disabled={models.isLoading || models.isError || running} onChange={(event) => setModel(event.target.value)} value={model}>
              {models.data?.map((record) => <option key={record.id} value={record.id}>{record.id}</option>)}
              {!models.data?.length ? <option value="">{models.isLoading ? "Loading models" : "No model advertised"}</option> : null}
            </select>

            <label htmlFor="provider">Provider</label>
            <select
              id="provider"
              disabled={peers.isLoading || peers.isError || running}
              onChange={(event) => setSelectedProvider(event.target.value)}
              value={selectedProvider}
            >
              {eligiblePeers.map((peer) => (
                <option key={peer.peer_id} value={peer.peer_id}>
                  {truncateMiddle(peer.peer_id, 12, 8)} - {peer.capacity?.max_concurrency ?? 1} slot
                </option>
              ))}
              {!eligiblePeers.length ? <option value="">{peers.isLoading ? "Discovering providers" : "No verified V3 provider"}</option> : null}
            </select>

            <label htmlFor="prompt">Input</label>
            <textarea id="prompt" maxLength={12_000} onChange={(event) => setInput(event.target.value)} rows={9} value={input} />
            <div className="app-form-meta">
              <span>{inputBytes.toLocaleString()} / {runtimeConfig.maxInputBytes.toLocaleString()} canonical UTF-8 bytes</span>
            </div>
            <FieldError>{inputTooLarge ? `Reduce the input by at least ${(inputBytes - runtimeConfig.maxInputBytes).toLocaleString()} bytes before reserving funds.` : null}</FieldError>

            <label htmlFor="max-output-tokens">Maximum output tokens</label>
            <div className="app-number-control">
              <input
                id="max-output-tokens"
                max={runtimeConfig.maxOutputTokens}
                min={16}
                onChange={(event) => setMaxOutputTokens(Math.max(16, Math.min(runtimeConfig.maxOutputTokens, Number(event.target.value) || 16)))}
                step={16}
                type="number"
                value={maxOutputTokens}
              />
            </div>

            <button className="button button--primary" disabled={!apiKey || !isConnected || chainId !== runtimeConfig.chainId || !publicClient || !deploymentVerification.verified || !selectedProvider || !model || !requestInput || inputTooLarge || running} type="submit">
              {running ? <LoaderCircle className="is-spinning" aria-hidden="true" size={17} /> : <Send aria-hidden="true" size={17} />}
              {running ? phase : "Run inference"}
            </button>
            <FieldError>{error}</FieldError>
            {reservationRecovery ? (
              <div className="app-reservation-recovery" role="status">
                <div className="app-reservation-recovery__heading">
                  <Clock3 aria-hidden="true" size={17} />
                  <strong>{reservationRecovery.transactionHash ? "Reservation submitted" : "Reservation prepared"}</strong>
                </div>
                <dl className="app-definition-list">
                  <div>
                    <dt>Reservation ID</dt>
                    <dd title={reservationRecovery.reservationId}>{truncateMiddle(reservationRecovery.reservationId, 10, 8)}</dd>
                  </div>
                  <div>
                    <dt>Expires</dt>
                    <dd><time dateTime={new Date(reservationRecovery.expiresAt * 1000).toISOString()}>{formatTime(reservationRecovery.expiresAt)}</time></dd>
                  </div>
                </dl>
                {reservationRecovery.transactionHash ? (
                  <a
                    className="app-transaction-link"
                    href={`${runtimeConfig.explorerUrl}/tx/${reservationRecovery.transactionHash}`}
                    rel="noreferrer"
                    target="_blank"
                  >
                    Reservation transaction
                    <span>{truncateMiddle(reservationRecovery.transactionHash, 10, 8)}</span>
                    <ExternalLink aria-hidden="true" size={15} />
                  </a>
                ) : (
                  <p className="app-panel-note">No reservation transaction hash has been returned.</p>
                )}
                <Link
                  className="app-transaction-link"
                  to={`/app/reservations?reservation_id=${encodeURIComponent(reservationRecovery.reservationId)}`}
                >
                  Open reservation recovery
                  <RefreshCw aria-hidden="true" size={15} />
                </Link>
              </div>
            ) : reservationTransactionHash ? (
              <a
                className="app-transaction-link"
                href={`${runtimeConfig.explorerUrl}/tx/${reservationTransactionHash}`}
                rel="noreferrer"
                target="_blank"
              >
                Reservation transaction
                <span>{truncateMiddle(reservationTransactionHash, 10, 8)}</span>
                <ExternalLink aria-hidden="true" size={15} />
              </a>
            ) : null}
          </form>
        </Panel>

        <Panel title="Response" description={result?.request_id ? `Request ${result.request_id}` : "The provider output will appear here."}>
          {result ? (
            <div className="app-response-result">
              {result.error ? <Notice icon={CircleAlert} title="Provider returned an error" tone="negative">{result.error}</Notice> : null}
              <div className="app-response-result__output">
                <Sparkles aria-hidden="true" size={18} />
                <p>{result.output_text || "No output text was returned."}</p>
              </div>
              {settlementStatus !== "idle" ? (
                <Notice
                  icon={settlementStatus === "settled" ? CircleCheck : settlementStatus === "failed" ? CircleAlert : ShieldCheck}
                  title={settlementTitle(settlementStatus)}
                  tone={settlementTone(settlementStatus)}
                >
                  <span>{settlementError || (settlementStatus === "settled" ? "Receipt settled on-chain." : "Settlement is still in progress.")}</span>
                  {settlementTransactionHash ? (
                    <a
                      className="app-transaction-link"
                      href={`${runtimeConfig.explorerUrl}/tx/${settlementTransactionHash}`}
                      rel="noreferrer"
                      target="_blank"
                    >
                      Settlement transaction
                      <span>{truncateMiddle(settlementTransactionHash, 10, 8)}</span>
                      <ExternalLink aria-hidden="true" size={15} />
                    </a>
                  ) : null}
                  {(settlementStatus === "pending" || settlementStatus === "failed") && settlementContext ? (
                    <button className="button button--secondary" onClick={() => void retrySettlement()} type="button">
                      <RefreshCw aria-hidden="true" size={15} />
                      Retry settlement
                    </button>
                  ) : null}
                </Notice>
              ) : null}
              <section className="app-metric-grid app-metric-grid--compact" aria-label="Response metrics">
                <Metric label="Model" value={result.model || model} />
                <Metric label="Provider" value={inferencePeerId(result.peer) || "Unavailable"} />
                <Metric label="Latency" value={result.elapsed_ms !== undefined ? `${result.elapsed_ms} ms` : "Unavailable"} />
                <Metric label="Tokens" value={result.usage?.total_tokens ?? "Unavailable"} />
              </section>
              <details className="app-json-details">
                <summary><Braces aria-hidden="true" size={16} /> Price and receipt envelope</summary>
                <pre>{JSON.stringify({ price: result.mycomesh_price ?? null, receipt: result.mycomesh_receipt ?? null, settlement: result.mycomesh_v3_settlement ?? null, usage: result.usage ?? null }, null, 2)}</pre>
              </details>
            </div>
          ) : running ? (
            <div className="app-response-waiting"><LoaderCircle className="is-spinning" aria-hidden="true" size={24} /><strong>{phase}</strong><p>The gateway buffers the current response until completion.</p></div>
          ) : (
            <div className="app-empty-response"><Clock3 aria-hidden="true" size={24} /><p>No inference has been run in this session.</p></div>
          )}
        </Panel>
      </div>
    </div>
  );
}
