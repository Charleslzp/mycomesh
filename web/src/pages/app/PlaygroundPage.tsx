import { useQuery } from "@tanstack/react-query";
import { getAccount } from "@wagmi/core";
import { Braces, CircleAlert, CircleCheck, Clock3, ExternalLink, KeyRound, LoaderCircle, RefreshCw, Send, ShieldCheck, Sparkles, WalletCards } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { formatUnits, isAddressEqual, type Address } from "viem";
import { useAccount, usePublicClient, useSignMessage, useSignTypedData, useWriteContract } from "wagmi";
import { useApiKey } from "../../state/ApiKeyContext";
import { FieldError, Metric, Notice, PageHeader, Panel, Status, formatTime, truncateMiddle } from "../../app/ui";
import {
  inferencePeerId,
  protocolApi,
  type ConsumerV3Authorization,
  type ConsumerV4Envelope,
  type ConsumerV4Plan,
  type InferenceResult,
  type ProviderPeer,
} from "../../protocol/api";
import { settlementV3Abi, settlementV4Abi } from "../../protocol/abis";
import { inferThroughBrowserConsumer } from "../../protocol/browserConsumerDirect";
import { verifyBrowserProvider, type VerifiedBrowserProvider } from "../../protocol/browserConsumerDiscovery";
import { prepareBrowserV3Plan, type BrowserV3PlanChainReader } from "../../protocol/browserConsumerPlan";
import { getOrCreateBrowserConsumerIdentity } from "../../protocol/browserConsumerStore";
import { isV4Configured, runtimeConfig } from "../../protocol/config";
import { useV3DeploymentVerification, useV4DeploymentVerification } from "../../protocol/deployment";
import { canonicalInferenceInputBytes } from "../../protocol/inputLimits";
import {
  findReservationRecovery,
  removeReservationRecovery,
  saveReservationRecovery,
  type ReservationRecoveryRecord,
} from "../../protocol/reservationRecovery";
import { assertConsumerV3Plan, consumerV3RequestHash, validateV3Settlement, type ValidatedV3Settlement } from "../../protocol/settlementV3";
import {
  getBrowserSession,
  getStoredBrowserSessionForSettlement,
  removeBrowserSession,
  saveBrowserSession,
  sessionActivationRequired,
  sessionRecordFromPlan,
  sessionRequestHash,
  type BrowserSessionRecord,
} from "../../protocol/browserSessionStore";
import { errorMessage } from "./helpers";
import { wagmiConfig } from "../../protocol/wagmi";

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

// The network-facing ID is deliberately stable; a Provider maps it to its
// configured Codex runtime model internally and must not receive that secret
// implementation detail from the Consumer.
const PUBLIC_MODEL_LABELS: Record<string, string> = {
  "mycomesh-codex-standard-v1": "Codex Standard (network)",
};

function modelLabel(modelId: string): string {
  return PUBLIC_MODEL_LABELS[modelId] ?? modelId;
}

function inferenceErrorMessage(error: unknown): string {
  const message = errorMessage(error);
  if (
    /provider [^\n]*(timed out|deadline exceeded)/i.test(message)
    || /provider route timed out/i.test(message)
    || /relay inference deadline exceeded/i.test(message)
  ) {
    return `${message}. The Provider did not return before the Relay deadline; no Provider receipt was accepted. Check reservation recovery before retrying.`;
  }
  return message;
}

function assertActiveConsumerWallet(expectedAddress: Address): void {
  const current = getAccount(wagmiConfig);
  if (
    !current.isConnected
    || !current.address
    || !isAddressEqual(current.address, expectedAddress)
    || current.chainId !== runtimeConfig.chainId
  ) {
    throw new Error("The connected Consumer wallet or chain changed during this operation.");
  }
}

function verifyConfiguredProvider(
  peer: ProviderPeer,
  settlementAddress: Address,
  now = Math.floor(Date.now() / 1000),
): VerifiedBrowserProvider {
  return verifyBrowserProvider(peer, {
    bridgeAudienceUrl: runtimeConfig.bridgeAudienceUrl,
    networkId: runtimeConfig.networkId,
    channelId: runtimeConfig.channelId,
    backendPolicy: runtimeConfig.backendPolicy,
    channel: runtimeConfig.channel,
    chainId: runtimeConfig.chainId,
    settlementContract: settlementAddress,
    reserveInputBytes: runtimeConfig.maxInputBytes,
    reserveOutputTokens: runtimeConfig.maxOutputTokens,
    now,
  });
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

function positiveSessionUnits(value: unknown): bigint | null {
  if (typeof value === "bigint") return value > 0n ? value : null;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return BigInt(value);
  if (typeof value === "string" && /^\d+$/.test(value) && value !== "0") {
    try {
      return BigInt(value);
    } catch {
      return null;
    }
  }
  return null;
}

function sessionEnvelope(
  record: BrowserSessionRecord,
  input: string,
  model: string,
  maxOutputTokens: number,
): ConsumerV4Envelope {
  const now = Math.floor(Date.now() / 1000);
  if (record.expiresAt <= now + 2) throw new Error("The prepaid session has expired; activate a new session.");
  // The Provider receipt is signed with this deadline. Keep it stable across
  // retries and long-lived sessions so a delayed transport retry does not
  // create an expired or semantically different settlement receipt. The
  // Gateway still applies its own short HTTP/Relay execution timeout.
  const deadline = Math.min(record.requestDeadline, record.expiresAt - 1);
  if (deadline <= now) throw new Error("The prepaid session request deadline has passed; activate a new session.");
  const requestHash = sessionRequestHash({
    sessionId: record.sessionId,
    sequence: record.nextSequence,
    model,
    input,
    maxOutputTokens,
  });
  // The Gateway owns the managed session key and builds the canonical signed
  // authorization/request documents. Keep the browser envelope deliberately
  // small: this is also the replay-safe shape accepted by older V4 Gateways.
  return {
    session_id: record.sessionId,
    request_id: requestHash.slice(2),
    max_fee_units: record.maxAmountUnits,
    deadline,
  };
}

function sessionSpendFromResult(result: InferenceResult): bigint | null {
  const update = result.mycomesh_session;
  const explicit = positiveSessionUnits(update?.cumulative_spend_units);
  if (explicit !== null) return explicit;
  const receipt = result.mycomesh_receipt;
  if (receipt && typeof receipt === "object") {
    const record = receipt as Record<string, unknown>;
    for (const key of ["cumulative_spend_units", "gross_fee_units", "amount_units", "quoted_fee", "gross_fee"]) {
      const candidate = positiveSessionUnits(record[key]);
      if (candidate !== null) return candidate;
    }
  }
  const price = result.mycomesh_price;
  if (price && typeof price === "object") {
    const record = price as Record<string, unknown>;
    for (const key of ["cumulative_spend_units", "gross_fee_units", "amount_units", "quoted_fee", "gross_fee"]) {
      const candidate = positiveSessionUnits(record[key]);
      if (candidate !== null) return candidate;
    }
  }
  return null;
}

export function PlaygroundPage() {
  const { apiKey } = useApiKey();
  const { address, chainId, isConnected } = useAccount();
  const publicClient = usePublicClient({ chainId: runtimeConfig.chainId });
  const { signMessageAsync } = useSignMessage();
  const { signTypedDataAsync } = useSignTypedData();
  const { writeContractAsync } = useWriteContract();
  const deploymentVerification = useV3DeploymentVerification();
  const sessionDeploymentVerification = useV4DeploymentVerification();
  const settlementAddress = runtimeConfig.deployment.settlementAddress;
  const sessionSettlementAddress = runtimeConfig.sessionDeployment.settlementAddress;
  const diagnosticsEnabled = typeof window !== "undefined"
    && new URLSearchParams(window.location.search).get("diagnostics") === "1";
  // The public app uses the Consumer Gateway as the default route.  Direct
  // browser-to-Relay transport remains available for operators who explicitly
  // need it, but it should not force every consumer to pick a peer.
  const [routeMode, setRouteMode] = useState<"direct" | "gateway">("gateway");
  const models = useQuery({
    queryKey: ["models"],
    queryFn: protocolApi.models,
    retry: 1,
    enabled: routeMode === "gateway",
  });
  const peers = useQuery({
    queryKey: ["provider-peers"],
    queryFn: protocolApi.peers,
    retry: 1,
    refetchInterval: 15_000,
    enabled: routeMode === "direct",
  });
  const browserIdentity = useQuery({
    queryKey: ["browser-consumer-identity"],
    queryFn: getOrCreateBrowserConsumerIdentity,
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
    enabled: routeMode === "direct",
  });
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
  const [browserSession, setBrowserSession] = useState<BrowserSessionRecord | null>(null);
  const [sessionActivationHash, setSessionActivationHash] = useState<`0x${string}` | null>(null);
  const [providerClock, setProviderClock] = useState(() => Math.floor(Date.now() / 1000));
  const providerDiscovery = useMemo(() => {
    const accepted: VerifiedBrowserProvider[] = [];
    const errors: string[] = [];
    if (!settlementAddress) return { accepted, errors };
    for (const peer of peers.data ?? []) {
      try {
        accepted.push(verifyConfiguredProvider(peer, settlementAddress, providerClock));
      } catch (providerError) {
        errors.push(errorMessage(providerError));
      }
    }
    return { accepted, errors };
  }, [peers.data, providerClock, settlementAddress]);
  const modelOptions = useMemo(
    () => routeMode === "direct"
      ? [...new Set(providerDiscovery.accepted.map((peer) => peer.model))]
      : (models.data ?? []).map((record) => record.id),
    [models.data, providerDiscovery.accepted, routeMode],
  );
  const directEligibleProviders = useMemo(
    () => providerDiscovery.accepted.filter((peer) => peer.model === model),
    [model, providerDiscovery.accepted],
  );
  const eligiblePeers = useMemo(
    () => routeMode === "direct" ? directEligibleProviders.map((peer) => peer.source) : [],
    [directEligibleProviders, routeMode],
  );
  const selectedDirectProvider = useMemo(
    () => directEligibleProviders.find((peer) => peer.peerId === selectedProvider),
    [directEligibleProviders, selectedProvider],
  );
  const requestInput = input.trim();
  const inputBytes = canonicalInferenceInputBytes(requestInput);
  const inputTooLarge = inputBytes > runtimeConfig.maxInputBytes;
  const credentialReady = routeMode === "direct" ? Boolean(browserIdentity.data) : Boolean(apiKey);
  const sessionGateway = routeMode === "gateway" && isV4Configured;
  const sessionHasLocalActivation = sessionGateway
    && Boolean(browserSession)
    && browserSession!.expiresAt > Math.floor(Date.now() / 1000) + 2;
  const connectedSessionWalletMismatch = sessionHasLocalActivation
    && isConnected
    && (!address || chainId !== runtimeConfig.chainId || !isAddressEqual(address, browserSession!.consumer));
  const sessionNeedsWallet = sessionGateway && !sessionHasLocalActivation;
  const requiresConnectedWallet = routeMode !== "gateway" || !sessionGateway || sessionNeedsWallet;
  const deploymentReady = sessionGateway
    ? sessionHasLocalActivation || sessionDeploymentVerification.verified
    : deploymentVerification.verified;
  const modelLoading = routeMode === "direct" ? peers.isLoading : models.isLoading;
  const modelError = routeMode === "direct" ? peers.isError || peers.isRefetchError : models.isError;
  const runDisabled =
    !credentialReady
    || (requiresConnectedWallet && !isConnected)
    || (requiresConnectedWallet && chainId !== runtimeConfig.chainId)
    || (requiresConnectedWallet && !publicClient)
    || connectedSessionWalletMismatch
    || !deploymentReady
    || (routeMode === "direct" && (peers.isError || peers.isRefetchError))
    || (routeMode === "direct" && !selectedProvider)
    || !model
    || !requestInput
    || inputTooLarge
    || running;
  const showWalletNotice = credentialReady && (
    connectedSessionWalletMismatch
    || (requiresConnectedWallet && (!isConnected || chainId !== runtimeConfig.chainId))
  );

  useEffect(() => {
    if (!modelOptions.includes(model)) setModel(modelOptions[0] ?? "");
  }, [model, modelOptions]);

  useEffect(() => {
    const timer = window.setInterval(
      () => setProviderClock(Math.floor(Date.now() / 1000)),
      5_000,
    );
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (routeMode === "direct" && !eligiblePeers.some((peer) => peer.peer_id === selectedProvider)) {
      setSelectedProvider(eligiblePeers[0]?.peer_id ?? "");
    }
    if (routeMode === "gateway" && selectedProvider) setSelectedProvider("");
  }, [eligiblePeers, routeMode, selectedProvider]);

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

  useEffect(() => {
    if (!sessionSettlementAddress) {
      setBrowserSession(null);
      return;
    }
    // A funded session can be used after the wallet is disconnected. When a
    // wallet is connected, retain a mismatched record only to show a blocking
    // reconnect state; the request path never uses it with the other wallet.
    if (address && chainId === runtimeConfig.chainId) {
      const owned = getBrowserSession({
        chainId: runtimeConfig.chainId,
        settlement: sessionSettlementAddress,
        consumer: address,
      });
      const stored = getStoredBrowserSessionForSettlement({
        chainId: runtimeConfig.chainId,
        settlement: sessionSettlementAddress,
      });
      setBrowserSession(owned ?? stored);
      return;
    }
    setBrowserSession(getStoredBrowserSessionForSettlement({
      chainId: runtimeConfig.chainId,
      settlement: sessionSettlementAddress,
    }));
  }, [address, chainId, sessionSettlementAddress]);

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
    const settlementConsumer = validated.payload.receipt.consumer as Address;
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
      assertActiveConsumerWallet(settlementConsumer);
      consumerSignature = await signTypedDataAsync({
        ...validated.typedData,
        account: settlementConsumer,
      });
      assertActiveConsumerWallet(settlementConsumer);
    } catch (signingError) {
      setSettlementStatus("pending");
      setSettlementError(errorMessage(signingError));
      setPhase("Complete");
      return false;
    }

    setSettlementStatus("submitting");
    setSettlementError(null);
    setPhase("Submit settlement");
    let transactionHash: `0x${string}`;
    try {
      transactionHash = await writeContractAsync({
        account: settlementConsumer,
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
      assertActiveConsumerWallet(settlementConsumer);
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

  async function refreshDirectProvider(peerId: string): Promise<VerifiedBrowserProvider> {
    if (!settlementAddress) throw new Error("Settlement V3 is not configured.");
    const refreshed = await peers.refetch({ cancelRefetch: true });
    if (refreshed.error || !refreshed.data) {
      throw new Error("Bridge discovery is unavailable; no funds were reserved.");
    }
    const source = refreshed.data.find((peer) => peer.peer_id === peerId);
    if (!source) throw new Error("The selected Provider is no longer registered with the Bridge.");
    return verifyConfiguredProvider(source, settlementAddress);
  }

  async function activateSession(
    plan: ConsumerV4Plan,
    consumer: Address,
    activeModel: string,
  ): Promise<BrowserSessionRecord> {
    if (!publicClient || !sessionSettlementAddress) {
      throw new Error("Settlement V4 is not configured for this app build.");
    }
    if (plan.chain_id !== runtimeConfig.chainId) {
      throw new Error("The Gateway session plan targets a different chain.");
    }
    if (plan.network_id !== runtimeConfig.networkId || plan.channel_id !== runtimeConfig.channelId || plan.backend_policy !== runtimeConfig.backendPolicy) {
      throw new Error("The Gateway session plan does not match this network build.");
    }
    if (plan.channel !== runtimeConfig.channel) {
      throw new Error("The Gateway session plan targets a different inference channel.");
    }
    if (plan.settlement_contract.toLowerCase() !== sessionSettlementAddress.toLowerCase()) {
      throw new Error("The Gateway session plan targets an untrusted Settlement V4 contract.");
    }
    if (plan.consumer_payment_address.toLowerCase() !== consumer.toLowerCase()) {
      throw new Error("The Gateway session plan is bound to a different consumer wallet.");
    }
    if (isAddressEqual(plan.provider_payment_address, consumer)) {
      throw new Error("The Gateway session plan cannot pay the consumer wallet as Provider.");
    }
    if (isAddressEqual(plan.session_key, plan.provider_payment_address) || isAddressEqual(plan.session_key, consumer)) {
      throw new Error("The Gateway returned an invalid session key binding.");
    }
    const now = Math.floor(Date.now() / 1000);
    if (plan.expires_at <= now + 30 || plan.expires_at > now + 30 * 24 * 60 * 60) {
      throw new Error("The Gateway returned a session plan outside the Settlement V4 lifetime.");
    }
    const maxAmount = positiveSessionUnits(plan.max_amount_units);
    if (maxAmount === null || maxAmount >= (1n << 256n)) throw new Error("The Gateway returned an invalid session escrow cap.");
    const code = await publicClient.getBytecode({ address: plan.settlement_contract });
    if (!code || code === "0x") throw new Error("Settlement V4 has no deployed bytecode at the configured address.");

    const [derivedSessionId, latestPricingVersion, pricingHash] = await Promise.all([
      publicClient.readContract({
        address: plan.settlement_contract,
        abi: settlementV4Abi,
        functionName: "sessionIdFor",
        args: [consumer, plan.session_salt],
      }),
      publicClient.readContract({
        address: plan.settlement_contract,
        abi: settlementV4Abi,
        functionName: "latestChannelVersion",
        args: [plan.channel_hash],
      }),
      publicClient.readContract({
        address: plan.settlement_contract,
        abi: settlementV4Abi,
        functionName: "channelPricingHash",
        args: [plan.channel_hash, BigInt(plan.pricing_version)],
      }),
    ]);
    if (String(derivedSessionId).toLowerCase() !== plan.session_id.toLowerCase()) {
      throw new Error("The Gateway session ID does not match Settlement V4.");
    }
    if (BigInt(latestPricingVersion as bigint) !== BigInt(plan.pricing_version)) {
      throw new Error("The session plan does not use the current channel pricing version.");
    }
    if (String(pricingHash).toLowerCase() !== plan.pricing_hash.toLowerCase()) {
      throw new Error("The session plan pricing hash does not match Settlement V4.");
    }

    if (!sessionActivationRequired(plan)) {
      setPhase("Restore prepaid session");
      const info = await publicClient.readContract({
        address: plan.settlement_contract,
        abi: settlementV4Abi,
        functionName: "sessionInfo",
        args: [plan.session_id],
      });
      const record = info as unknown as Record<string | number, unknown>;
      const value = (name: string, index: number) => record[name] ?? record[index];
      if (String(value("consumer", 0)).toLowerCase() !== consumer.toLowerCase()) {
        throw new Error("The restored session is bound to a different consumer wallet.");
      }
      if (String(value("provider", 1)).toLowerCase() !== plan.provider_payment_address.toLowerCase()) {
        throw new Error("The restored session Provider binding does not match the Gateway plan.");
      }
      if (String(value("sessionKey", 2)).toLowerCase() !== plan.session_key.toLowerCase()) {
        throw new Error("The restored session key binding does not match the Gateway plan.");
      }
      if (String(value("channel", 3)).toLowerCase() !== plan.channel_hash.toLowerCase()) {
        throw new Error("The restored session channel does not match the Gateway plan.");
      }
      if (BigInt(value("pricingVersion", 4) as bigint) !== BigInt(plan.pricing_version)) {
        throw new Error("The restored session pricing version does not match the Gateway plan.");
      }
      if (String(value("pricingHash", 5)).toLowerCase() !== plan.pricing_hash.toLowerCase()) {
        throw new Error("The restored session pricing hash does not match the Gateway plan.");
      }
      if (BigInt(value("maxAmount", 9) as bigint) !== maxAmount) {
        throw new Error("The restored session escrow cap does not match the Gateway plan.");
      }
      if (Boolean(value("closed", 12))) throw new Error("The restored prepaid session is closed.");
      const restoredExpiry = Number(value("expiresAt", 7));
      if (!Number.isSafeInteger(restoredExpiry) || restoredExpiry <= now) {
        throw new Error("The restored prepaid session has expired.");
      }
      if (restoredExpiry !== plan.expires_at) {
        throw new Error("The restored session expiry does not match the Gateway plan.");
      }
      const recordFromPlan = sessionRecordFromPlan(plan, consumer, activeModel);
      const restoredRecord: BrowserSessionRecord = {
        ...recordFromPlan,
        expiresAt: restoredExpiry,
        nextSequence: Number.isSafeInteger(plan.next_sequence) && (plan.next_sequence ?? 0) >= 0
          ? plan.next_sequence ?? 0
          : recordFromPlan.nextSequence,
      };
      saveBrowserSession(restoredRecord);
      setBrowserSession(restoredRecord);
      return restoredRecord;
    }

    const available = await publicClient.readContract({
      address: plan.settlement_contract,
      abi: settlementV4Abi,
      functionName: "availableBalance",
      args: [consumer],
    });
    if (BigInt(available as bigint) < maxAmount) {
      throw new Error(`Deposit at least ${formatUnits(maxAmount, runtimeConfig.stablecoinDecimals)} ${runtimeConfig.stablecoinSymbol} before activating a session.`);
    }

    assertActiveConsumerWallet(consumer);
    setPhase("Activate prepaid session");
    const transactionHash = await writeContractAsync({
      account: consumer,
      address: plan.settlement_contract,
      abi: settlementV4Abi,
      chainId: runtimeConfig.chainId,
      functionName: "openSession",
      args: [
        plan.session_salt,
        plan.provider_payment_address,
        plan.session_key,
        plan.channel_hash,
        BigInt(plan.pricing_version),
        maxAmount,
        BigInt(plan.expires_at),
      ],
    });
    setSessionActivationHash(transactionHash);
    assertActiveConsumerWallet(consumer);
    const requestedConfirmations = Number(plan.required_activation_confirmations ?? 1);
    if (!Number.isSafeInteger(requestedConfirmations) || requestedConfirmations < 1) {
      throw new Error("The Gateway returned an invalid session confirmation requirement.");
    }
    // Session activation is the only chain wait in the API-like path. Keep a
    // hostile or stale plan from turning it back into the old seven-block UX.
    const confirmations = Math.min(2, requestedConfirmations);
    setPhase(confirmations > 1 ? `Confirming session (${confirmations} blocks)` : "Confirming session");
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: transactionHash,
      confirmations,
    });
    if (receipt.status !== "success") throw new Error("The prepaid session activation transaction reverted.");
    assertActiveConsumerWallet(consumer);
    const record = sessionRecordFromPlan(plan, consumer, activeModel);
    saveBrowserSession(record);
    setBrowserSession(record);
    return record;
  }

  async function runSessionInference(): Promise<void> {
    if (
      !apiKey
      || !sessionSettlementAddress
      || !model
      || !requestInput
    ) return;
    const storedSession = browserSession ?? getStoredBrowserSessionForSettlement({
      chainId: runtimeConfig.chainId,
      settlement: sessionSettlementAddress,
    });
    const storedSessionActive = Boolean(storedSession && storedSession.expiresAt > Math.floor(Date.now() / 1000) + 2);
    if (
      storedSessionActive
      && isConnected
      && (!address || chainId !== runtimeConfig.chainId || !isAddressEqual(address, storedSession!.consumer))
    ) {
      setError("Disconnect the other wallet or reconnect the wallet bound to this prepaid session.");
      return;
    }
    const walletForActivation = address && chainId === runtimeConfig.chainId ? address : null;
    if (!storedSessionActive && (!walletForActivation || !publicClient)) return;
    const runAddress = storedSessionActive ? storedSession!.consumer : walletForActivation!;
    setRunning(true);
    setError(null);
    setResult(null);
    setSettlementStatus("idle");
    setSettlementError(null);
    setSettlementTransactionHash(null);
    setSettlementContext(null);
    try {
      if (!storedSessionActive) assertActiveConsumerWallet(runAddress);
      let activeSession = storedSession;
      let activatedDuringRun = false;
      const now = Math.floor(Date.now() / 1000);
      if (activeSession && activeSession.expiresAt <= now + 2) {
        removeBrowserSession();
        activeSession = null;
        setBrowserSession(null);
      }
      if (!activeSession) {
        setPhase("Preparing prepaid session");
        const plan = await protocolApi.prepareSession(apiKey, requestInput, model, maxOutputTokens);
        if (plan.enabled === false) throw new Error("Session settlement is not enabled by the Gateway yet.");
        activeSession = await activateSession(plan, runAddress, model);
        activatedDuringRun = true;
      }
      if (activatedDuringRun) assertActiveConsumerWallet(runAddress);
      const envelope = sessionEnvelope(activeSession, requestInput, model, maxOutputTokens);
      setPhase("Routing request");
      const inferenceResult = await protocolApi.infer(
        apiKey,
        requestInput,
        model,
        maxOutputTokens,
        undefined,
        envelope,
      );
      setResult(inferenceResult);
      if (inferenceResult.error || inferenceResult.ok === false) {
        throw new Error(inferenceResult.error || "Provider did not return a successful inference.");
      }

      // The Gateway may return authoritative sequence/spend state after it
      // queues a receipt. Prefer that state; otherwise advance the local
      // sequence while leaving cumulative spend unchanged until a receipt
      // amount is supplied.
      const update = inferenceResult.mycomesh_session;
      const explicitNext = update?.next_sequence ?? update?.sequence;
      const nextSequence = typeof explicitNext === "number" && Number.isSafeInteger(explicitNext) && explicitNext >= 0
        ? explicitNext
        : activeSession.nextSequence + 1;
      let cumulativeSpendUnits = activeSession.cumulativeSpendUnits;
      const explicitSpend = update?.cumulative_spend_units;
      if (explicitSpend !== undefined && /^\d+$/.test(String(explicitSpend))) {
        cumulativeSpendUnits = String(explicitSpend);
      } else {
        const receiptSpend = sessionSpendFromResult(inferenceResult);
        if (receiptSpend !== null) {
          cumulativeSpendUnits = (BigInt(activeSession.cumulativeSpendUnits) + receiptSpend).toString();
        }
      }
      const updatedSession: BrowserSessionRecord = {
        ...activeSession,
        model,
        nextSequence,
        cumulativeSpendUnits,
      };
      saveBrowserSession(updatedSession);
      setBrowserSession(updatedSession);
      setPhase("Complete");
    } catch (inferenceError) {
      setError(inferenceErrorMessage(inferenceError));
      setPhase("Failed");
    } finally {
      setRunning(false);
    }
  }

  async function runInference() {
    if (inputTooLarge) {
      setError(`Input is ${inputBytes.toLocaleString()} bytes; the Provider limit is ${runtimeConfig.maxInputBytes.toLocaleString()} bytes.`);
      setPhase("Ready");
      return;
    }
    if (routeMode === "gateway" && isV4Configured) {
      if (!model || !requestInput || !apiKey) return;
      await runSessionInference();
      return;
    }
    if (
      !model ||
      !requestInput ||
      (routeMode === "direct" && !selectedProvider) ||
      !address ||
      chainId !== runtimeConfig.chainId ||
      !publicClient ||
      (routeMode === "gateway" && !apiKey) ||
      (routeMode === "direct" && (!browserIdentity.data || !selectedDirectProvider))
    ) return;
    const runAddress = address;
    let activeDirectProvider = routeMode === "direct" ? selectedDirectProvider : null;
    setRunning(true);
    setError(null);
    setResult(null);
    setReservationTransactionHash(null);
    setSettlementStatus("idle");
    setSettlementError(null);
    setSettlementTransactionHash(null);
    setSettlementContext(null);
    try {
      assertActiveConsumerWallet(runAddress);
      setPhase("Verifying V3");
      const currentVerification = await deploymentVerification.verifyNow();
      if (!currentVerification.verified) {
        throw new Error(`${currentVerification.message} ${currentVerification.issues[0] ?? ""}`.trim());
      }
      assertActiveConsumerWallet(runAddress);
      if (routeMode === "direct") {
        setPhase("Refreshing Provider lease");
        activeDirectProvider = await refreshDirectProvider(selectedProvider);
        assertActiveConsumerWallet(runAddress);
      }
      setPhase("Preparing reservation");
      const reader: BrowserV3PlanChainReader = {
        quote: async (args) => publicClient.readContract({
          address: args.settlementContract,
          abi: settlementV3Abi,
          functionName: "quote",
          args: [
            args.channelHash,
            BigInt(args.pricingVersion),
            BigInt(args.reserveInputBytes),
            BigInt(args.maxOutputTokens),
          ],
        }),
        reservationIdFor: async (args) => publicClient.readContract({
          address: args.settlementContract,
          abi: settlementV3Abi,
          functionName: "reservationIdFor",
          args: [args.consumer, args.reservationSalt],
        }),
        latestChannelVersion: async (args) => publicClient.readContract({
          address: args.settlementContract,
          abi: settlementV3Abi,
          functionName: "latestChannelVersion",
          args: [args.channelHash],
        }),
        channelPricingHash: async (args) => publicClient.readContract({
          address: args.settlementContract,
          abi: settlementV3Abi,
          functionName: "channelPricingHash",
          args: [args.channelHash, BigInt(args.pricingVersion)],
        }),
      };
      const plan = routeMode === "direct"
        ? await prepareBrowserV3Plan({
          identity: browserIdentity.data!,
          provider: activeDirectProvider!,
          chainId: runtimeConfig.chainId,
          settlementContract: settlementAddress!,
          consumer: runAddress,
          input: requestInput,
          inputSizeBytes: inputBytes,
          model,
          maxOutputTokens,
          requiredConfirmations: 6,
          reader,
        })
        : await protocolApi.prepareV3(apiKey!, requestInput, model, maxOutputTokens);
      const settlementContract = runtimeConfig.deployment.settlementAddress;
      const providerPaymentAddress = routeMode === "direct"
        ? activeDirectProvider?.paymentAddress
        : plan.provider_payment_address;
      const providerChannel = routeMode === "direct"
        ? activeDirectProvider?.channel
        : plan.channel;
      if (!settlementContract || !providerPaymentAddress || !providerChannel) {
        throw new Error("The Gateway returned an incomplete V3 Provider binding.");
      }
      const requestHash = consumerV3RequestHash(requestInput, model, maxOutputTokens);
      assertConsumerV3Plan(plan, {
        chainId: runtimeConfig.chainId,
        settlementContract,
        consumer: runAddress,
        providerId: plan.provider_id,
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
            args: [runAddress, plan.reservation_salt],
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
      assertActiveConsumerWallet(runAddress);
      const requiredConfirmations = Math.max(1, plan.required_confirmations);
      // The backend's confirmation depth is measured as `latest - confirmed`.
      // viem counts the inclusion block as confirmation one, so add one to
      // wait for the same number of blocks after inclusion before Relay
      // admission can read the reservation at its confirmed block.
      const reservationConfirmations = requiredConfirmations + 1;
      const preparedRecovery = saveReservationRecovery({
        schema: "mycomesh.reservation.recovery.v1",
        chainId: runtimeConfig.chainId,
        settlement: plan.settlement_contract,
        consumer: runAddress,
        reservationId: plan.onchain_reservation_id,
        expiresAt: plan.expires_at,
        transactionHash: null,
        createdAt: Date.now(),
      });
      setReservationRecovery(preparedRecovery);
      setReservationTransactionHash(null);
      setPhase("Confirm reservation");
      const transactionHash = await writeContractAsync({
        account: runAddress,
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
      assertActiveConsumerWallet(runAddress);
      const submittedRecovery = saveReservationRecovery({
        ...preparedRecovery,
        transactionHash,
      });
      setReservationRecovery(submittedRecovery);
      setReservationTransactionHash(transactionHash);
      setPhase(
        `Waiting for ${requiredConfirmations} blocks after inclusion (${reservationConfirmations} total confirmations)`,
      );
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: transactionHash,
        confirmations: reservationConfirmations,
      });
      if (receipt.status !== "success") throw new Error("The V3 reservation transaction reverted.");
      assertActiveConsumerWallet(runAddress);
      if (routeMode === "direct") {
        setPhase("Rechecking Provider lease");
        const refreshedProvider = await refreshDirectProvider(plan.provider_id);
        if (
          refreshedProvider.paymentAddress.toLowerCase() !== plan.provider_payment_address.toLowerCase()
          || refreshedProvider.pricingVersion !== plan.pricing_version
          || refreshedProvider.pricingHash.toLowerCase() !== plan.pricing_hash.toLowerCase()
          || refreshedProvider.channel !== plan.channel
          || refreshedProvider.model !== model
        ) {
          throw new Error("The selected Provider changed its signed V3 binding after reservation.");
        }
        activeDirectProvider = refreshedProvider;
        assertActiveConsumerWallet(runAddress);
      }
      setPhase("Authorize request");
      const walletSignature = await signMessageAsync({
        account: runAddress,
        message: plan.authorization_message,
      });
      assertActiveConsumerWallet(runAddress);
      const authorization: ConsumerV3Authorization = {
        ...plan.authorization,
        wallet_signature: walletSignature,
      };
      setPhase(routeMode === "direct" ? "Encrypting Provider request" : "Routing request");
      const inferenceResult = routeMode === "direct"
        ? await inferThroughBrowserConsumer({
          identity: browserIdentity.data!,
          provider: activeDirectProvider!,
          plan,
          authorization,
          input: requestInput,
          model,
          maxOutputTokens,
        })
        : await protocolApi.infer(apiKey!, requestInput, model, maxOutputTokens, {
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
          consumer: runAddress,
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
          clearRecoveredReservation(plan.onchain_reservation_id, runAddress);
        }
      } catch (settlementValidationError) {
        setSettlementStatus("failed");
        setSettlementError(errorMessage(settlementValidationError));
      }
      setPhase("Complete");
    } catch (inferenceError) {
      setError(inferenceErrorMessage(inferenceError));
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
        description={routeMode === "direct"
          ? "Create a wallet-bound reservation, send an encrypted request to a selected Provider, and settle its signed receipt."
          : sessionGateway
            ? "Activate one bounded prepaid session, then use the Gateway like a normal API without wallet prompts per request."
            : "Create a wallet-bound reservation, let the Gateway choose a verified Provider, and settle its signed receipt."}
        actions={
          <Status tone={credentialReady ? "positive" : "warning"}>
            {routeMode === "direct"
              ? browserIdentity.isLoading
                ? "Starting local Consumer"
                : credentialReady
                  ? "Local Consumer ready"
                  : "Local Consumer unavailable"
              : apiKey
                ? sessionGateway
                  ? browserSession
                    ? "Prepaid session active"
                    : "One-time session activation"
                  : "Gateway credential ready"
                : "Gateway API key required"}
          </Status>
        }
      />

      {diagnosticsEnabled ? <div className="app-segmented-control" aria-label="Consumer route">
        <button
          aria-pressed={routeMode === "gateway"}
          disabled={running}
          onClick={() => setRouteMode("gateway")}
          type="button"
        >
          Automatic Gateway
        </button>
        <button
          aria-pressed={routeMode === "direct"}
          disabled={running}
          onClick={() => setRouteMode("direct")}
          type="button"
        >
          Direct diagnostics
        </button>
      </div> : null}

      {routeMode === "gateway" && !apiKey ? (
        <Notice icon={KeyRound} title="Establish consumer access first" tone="warning">
          <Link to="/app/access">Create a wallet-bound API key</Link> before making a billed inference request.
        </Notice>
      ) : null}

      {routeMode === "direct" && browserIdentity.error ? (
        <Notice icon={CircleAlert} title="Local Consumer identity is unavailable" tone="negative">
          {errorMessage(browserIdentity.error)}
        </Notice>
      ) : null}

      {routeMode === "direct"
      && !peers.isLoading
      && providerDiscovery.accepted.length === 0
      && providerDiscovery.errors.length > 0 ? (
        <Notice icon={CircleAlert} title="No valid Codex Provider is online" tone="warning">
          Provider discovery rejected {providerDiscovery.errors.length} descriptor{providerDiscovery.errors.length === 1 ? "" : "s"} that did not match this network build.
        </Notice>
      ) : null}

      {showWalletNotice ? (
        <Notice icon={WalletCards} title={connectedSessionWalletMismatch ? "Reconnect the session wallet" : isConnected ? `Switch to ${runtimeConfig.networkName}` : "Connect the consumer wallet"} tone="warning">
          {sessionGateway
            ? "Connect the wallet bound to this session only when activating or recovering it. An active local session can run without a wallet connection."
            : "This wallet creates the request reservation and authorizes the local Consumer session."}
        </Notice>
      ) : credentialReady && !deploymentReady ? (
        <Notice icon={CircleAlert} title={sessionGateway ? "Settlement V4 is not ready" : "Settlement V3 is not ready"} tone="warning">
          {sessionGateway ? sessionDeploymentVerification.message : deploymentVerification.message}
        </Notice>
      ) : null}

      <div className="app-playground-layout">
        <Panel
          title="Request"
          description={routeMode === "direct"
            ? "Browser Consumer to Relay to Provider, with end-to-end encrypted request and response frames."
            : sessionGateway
              ? "The Gateway selects a verified Provider. Your wallet is used only to activate the bounded prepaid session."
              : "The Gateway selects a verified Provider and forwards the request."}
        >
          {sessionGateway && browserSession ? (
            <div className="app-form-meta" role="status">
              <span>Session active · {browserSession.nextSequence.toLocaleString()} requests sent · {browserSession.expiresAt > Math.floor(Date.now() / 1000) ? `expires ${formatTime(browserSession.expiresAt)}` : "expired"}</span>
              {sessionActivationHash ? (
                <a className="app-transaction-link" href={`${runtimeConfig.explorerUrl}/tx/${sessionActivationHash}`} rel="noreferrer" target="_blank">
                  Activation transaction <span>{truncateMiddle(sessionActivationHash, 10, 8)}</span><ExternalLink aria-hidden="true" size={15} />
                </a>
              ) : null}
            </div>
          ) : null}
          <form className="app-request-form" onSubmit={(event) => { event.preventDefault(); runInference(); }}>
            <label htmlFor="model">Model</label>
            <select id="model" disabled={modelLoading || modelError || running} onChange={(event) => setModel(event.target.value)} value={model}>
              {modelOptions.map((modelId) => <option key={modelId} value={modelId}>{modelLabel(modelId)}</option>)}
              {!modelOptions.length ? <option value="">{modelLoading ? "Loading models" : "No model advertised"}</option> : null}
            </select>

            {routeMode === "direct" ? (
              <>
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
              </>
            ) : (
              <div className="app-form-meta" role="status">
                <span>Provider: selected automatically by the Gateway</span>
              </div>
            )}

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

            <button className="button button--primary" disabled={runDisabled} type="submit">
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
              {sessionGateway && result.mycomesh_session ? (
                <Notice icon={ShieldCheck} title="Receipt queued by Gateway" tone="positive">
                  This response was accepted against the bounded session. No wallet transaction or confirmation wait is required for the next request.
                </Notice>
              ) : null}
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
                <Metric label="Model" value={modelLabel(result.model || model)} />
                <Metric label="Provider" value={inferencePeerId(result.peer) || "Unavailable"} />
                <Metric label="Latency" value={result.elapsed_ms !== undefined ? `${result.elapsed_ms} ms` : "Unavailable"} />
                <Metric label="Tokens" value={result.usage?.total_tokens ?? "Unavailable"} />
              </section>
              <details className="app-json-details">
                <summary><Braces aria-hidden="true" size={16} /> Price and receipt envelope</summary>
                <pre>{JSON.stringify({ price: result.mycomesh_price ?? null, receipt: result.mycomesh_receipt ?? null, settlement: result.mycomesh_v4_settlement ?? result.mycomesh_v3_settlement ?? null, session: result.mycomesh_session ?? null, usage: result.usage ?? null }, null, 2)}</pre>
              </details>
            </div>
          ) : running ? (
            <div className="app-response-waiting"><LoaderCircle className="is-spinning" aria-hidden="true" size={24} /><strong>{phase}</strong><p>{routeMode === "direct" ? "Waiting for the selected Provider response." : "The Gateway buffers the current response until completion."}</p></div>
          ) : (
            <div className="app-empty-response"><Clock3 aria-hidden="true" size={24} /><p>No inference has been run in this session.</p></div>
          )}
        </Panel>
      </div>
    </div>
  );
}
