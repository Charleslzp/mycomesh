import type {
  ConsumerV3Authorization,
  ConsumerV3Plan,
  InferenceResult,
} from "./api";
import { fetchProtocolJson } from "./api";
import type { VerifiedBrowserProvider } from "./browserConsumerDiscovery";
import {
  type BrowserDocumentSigningIdentity,
  browserBytesToHex,
  browserIsPlainObject,
  secureBrowserRandomBytes,
} from "./browserConsumerIdentity";
import {
  BrowserMemoryReplayStore,
  P2P_SECURE_REQUEST_PURPOSE,
  P2P_SECURE_RESPONSE_PURPOSE,
  browserBase64UrlDecode,
  browserBase64UrlEncode,
  generateBrowserTransportKeyAsync,
  openBrowserJsonFrame,
  sealBrowserJsonFrameAsync,
} from "./browserConsumerTransport";
import {
  buildBrowserV3InferenceRequestAsync,
  verifyBrowserProviderResponse,
} from "./browserConsumerV3";
import { verifyBrowserProviderSettlementAttestation } from "./browserProviderAttestation";
import { validateV3Settlement } from "./settlementV3";

export const RELAY_V3_ADMISSION_SCHEMA = "mycomesh.relay.consumer-admission.v1";
const DEFAULT_DIRECT_TIMEOUT_MS = 180_000;
const responseReplayStore = new BrowserMemoryReplayStore();

export interface BrowserDirectInferenceOptions {
  identity: BrowserDocumentSigningIdentity;
  provider: VerifiedBrowserProvider;
  plan: ConsumerV3Plan;
  authorization: ConsumerV3Authorization;
  input: string;
  model: string;
  maxOutputTokens: number;
  timeoutMs?: number;
  now?: number;
}

export class BrowserDirectInferenceError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BrowserDirectInferenceError";
  }
}

export async function inferThroughBrowserConsumer(
  options: BrowserDirectInferenceOptions,
): Promise<InferenceResult> {
  const timeoutMs = boundedTimeout(options.timeoutMs ?? DEFAULT_DIRECT_TIMEOUT_MS);
  const timeoutSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const requestId = browserBytesToHex(secureBrowserRandomBytes(16));
  const built = await buildBrowserV3InferenceRequestAsync({
    identity: options.identity,
    plan: options.plan,
    authorization: options.authorization,
    requestId,
    endpoint: "responses",
    model: options.model,
    input: options.input,
    maxOutputTokens: options.maxOutputTokens,
    now,
  });
  const replyKey = await generateBrowserTransportKeyAsync(options.identity, {
    lifetimeSeconds: 10 * 60,
    now,
  });
  let requestFrame: Uint8Array;
  try {
    requestFrame = await sealBrowserJsonFrameAsync(
      {
        message: built.message,
        reply_transport_key: replyKey.binding,
      },
      {
        sender: options.identity,
        recipientBinding: options.provider.transportKey,
        expectedRecipientPeerId: options.provider.peerId,
        expectedRecipientPublicKey: options.provider.publicKey,
        purpose: P2P_SECURE_REQUEST_PURPOSE,
        ttlSeconds: Math.min(300, Math.max(30, timeoutSeconds + 5)),
        now,
      },
    );
  } catch (error) {
    throw new BrowserDirectInferenceError("Failed to encrypt the Provider request", { cause: error });
  }

  const relayResponse = await fetchProtocolJson<Record<string, unknown>>(
    options.provider.relayBaseUrl,
    `/infer/${encodeURIComponent(options.provider.peerId)}`,
    {
      method: "POST",
      body: JSON.stringify({
        secure_frame: browserBase64UrlEncode(requestFrame),
        admission: {
          schema: RELAY_V3_ADMISSION_SCHEMA,
          authorization: options.authorization,
        },
        timeout: timeoutSeconds,
      }),
    },
    timeoutMs + 5_000,
  );
  if (typeof relayResponse.secure_frame !== "string") {
    throw new BrowserDirectInferenceError("Relay response is missing its encrypted Provider frame");
  }

  let wrapper: Record<string, unknown>;
  try {
    wrapper = openBrowserJsonFrame(
      browserBase64UrlDecode(relayResponse.secure_frame, "Relay secure_frame"),
      {
        recipientKey: replyKey,
        expectedPurpose: P2P_SECURE_RESPONSE_PURPOSE,
        expectedSenderPeerId: options.provider.peerId,
        expectedSenderPublicKey: options.provider.publicKey,
        replayStore: responseReplayStore,
        now,
      },
    ).jsonPayload;
  } catch (error) {
    throw new BrowserDirectInferenceError("Provider response encryption or identity is invalid", {
      cause: error,
    });
  }
  if (
    Object.keys(wrapper).length !== 1
    || !browserIsPlainObject(wrapper.response)
  ) {
    throw new BrowserDirectInferenceError("Encrypted Provider response wrapper is invalid");
  }
  if (wrapper.response.ok === false) {
    const detail = typeof wrapper.response.error === "string"
      ? wrapper.response.error.trim().slice(0, 500)
      : "Provider rejected the inference request";
    throw new BrowserDirectInferenceError(detail || "Provider rejected the inference request");
  }

  let verifiedResponse: InferenceResult;
  try {
    verifiedResponse = verifyBrowserProviderResponse<InferenceResult>(wrapper.response, {
      consumerPublicKey: options.identity.publicKey,
      providerPublicKey: options.provider.publicKey,
      channelBinding: {
        network_id: options.plan.network_id,
        channel_id: options.plan.channel_id,
        channel: options.plan.channel,
        backend_policy: options.plan.backend_policy,
      },
      requestId,
      requestHash: built.requestHash,
      model: options.model,
      endpoint: "responses",
    });
  } catch (error) {
    throw new BrowserDirectInferenceError("Provider response signature or request binding is invalid", {
      cause: error,
    });
  }

  try {
    const settlement = await validateV3Settlement(verifiedResponse.mycomesh_v3_settlement, {
      chainId: options.plan.chain_id,
      settlementContract: options.plan.settlement_contract,
      consumer: options.authorization.consumer_payment_address,
      providerId: options.provider.peerId,
      providerPaymentAddress: options.provider.paymentAddress,
      plan: options.plan,
      response: verifiedResponse,
      providerFallbackAllowed: false,
      maxOutputTokens: options.maxOutputTokens,
      now,
    });
    await verifyBrowserProviderSettlementAttestation(
      verifiedResponse.provider_settlement_attestation,
      {
        response: verifiedResponse,
        provider: options.provider,
        plan: options.plan,
        authorization: options.authorization,
        consumerPublicKey: options.identity.publicKey,
        consumerId: options.identity.peerId,
        requestId,
        requestHash: built.requestHash,
        model: options.model,
        endpoint: "responses",
        validatedSettlement: settlement,
        now,
      },
    );
  } catch (error) {
    throw new BrowserDirectInferenceError("Provider Settlement V3 evidence is invalid", {
      cause: error,
    });
  }
  return verifiedResponse;
}

function boundedTimeout(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1_000 || (value as number) > 300_000) {
    throw new BrowserDirectInferenceError("Direct inference timeout must be between 1 and 300 seconds");
  }
  return value as number;
}
