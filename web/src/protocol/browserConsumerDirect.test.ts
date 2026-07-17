import { afterEach, describe, expect, it, vi } from "vitest";
import {
  hashTypedData,
  keccak256,
  stringToHex,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type {
  ConsumerV3Authorization,
  ConsumerV3Plan,
  InferenceResult,
  ProviderV3Receipt,
} from "./api";
import { inferThroughBrowserConsumer } from "./browserConsumerDirect";
import type { VerifiedBrowserProvider } from "./browserConsumerDiscovery";
import {
  browserIsPlainObject,
  browserSoftwareConsumerIdentityFromPrivateKeyForTest,
  generateBrowserWebCryptoConsumerIdentity,
  signBrowserDocument,
} from "./browserConsumerIdentity";
import {
  BrowserMemoryReplayStore,
  P2P_SECURE_REQUEST_PURPOSE,
  P2P_SECURE_RESPONSE_PURPOSE,
  browserBase64UrlDecode,
  browserBase64UrlEncode,
  generateBrowserTransportKey,
  openBrowserJsonFrame,
  sealBrowserJsonFrame,
} from "./browserConsumerTransport";
import {
  PROVIDER_RESPONSE_PURPOSE,
  browserV3AuthorizationMessage,
  browserV3InferenceRequestHash,
} from "./browserConsumerV3";
import {
  PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE,
  PROVIDER_SETTLEMENT_ATTESTATION_VERSION,
} from "./browserProviderAttestation";
import {
  buildV3ReceiptTypedData,
  computeV3ReceiptCommitments,
  settlementResponseHash,
} from "./settlementV3";

afterEach(() => vi.unstubAllGlobals());

describe("direct browser Consumer", () => {
  it("sends an opaque Relay frame and authenticates the encrypted Provider response", async () => {
    const now = Math.floor(Date.now() / 1000);
    const generatedConsumer = await generateBrowserWebCryptoConsumerIdentity();
    const consumerIdentity = generatedConsumer.identity;
    const providerIdentity = browserSoftwareConsumerIdentityFromPrivateKeyForTest("22".repeat(32));
    const providerEvm = privateKeyToAccount(("0x" + "11".repeat(32)) as Hex);
    const consumerEvm = privateKeyToAccount(("0x" + "33".repeat(32)) as Hex);
    const providerPaymentAddress = providerEvm.address.toLowerCase() as `0x${string}`;
    const consumerPaymentAddress = consumerEvm.address.toLowerCase() as `0x${string}`;
    expect(generatedConsumer.signingKey.extractable).toBe(false);
    expect(consumerIdentity).not.toHaveProperty("privateKey");
    const providerTransport = generateBrowserTransportKey(providerIdentity, {
      now,
      lifetimeSeconds: 3600,
      randomBytes: fixedRandom(3),
    });
    const channel = "codex-standard-v1";
    const model = "mycomesh-codex-standard-v1";
    const input = "hello";
    const requestHash = browserV3InferenceRequestHash({
      endpoint: "responses",
      model,
      input,
      maxOutputTokens: 64,
    });
    const authorization: ConsumerV3Authorization = {
      authorization_version: "mycomesh.evm.session.v1",
      chain_id: 11155111,
      settlement_contract: "0x3333333333333333333333333333333333333333",
      onchain_reservation_id: `0x${"44".repeat(32)}`,
      consumer_payment_address: consumerPaymentAddress,
      provider_id: providerIdentity.peerId,
      provider_payment_address: providerPaymentAddress,
      channel,
      pricing_hash: `0x${"77".repeat(32)}`,
      pricing_version: 1,
      request_hash: requestHash,
      max_fee_units: 25_000,
      expires_at: now + 900,
      settlement_deadline: now + 900,
      provider_fallback_allowed: false,
      nonce: `0x${"88".repeat(32)}`,
      session_public_key: consumerIdentity.publicKey,
    };
    const plan: ConsumerV3Plan = {
      schema: "mycomesh.consumer.v3.plan.v1",
      network_id: "mycomesh-testnet",
      channel_id: "codex",
      backend_policy: "codex-app-server-postvalidated-v1",
      provider_id: providerIdentity.peerId,
      provider_payment_address: authorization.provider_payment_address,
      provider_addresses: [`myco+relays://bridge.mycomesh.xyz:443/${providerIdentity.peerId}`],
      chain_id: 11155111,
      settlement_contract: authorization.settlement_contract,
      channel,
      channel_hash: keccak256(stringToHex(channel)),
      pricing_version: 1,
      pricing_hash: authorization.pricing_hash,
      request_hash: requestHash,
      input_size_bytes: 7,
      reserve_input_bytes: 8000,
      reserve_output_tokens: 2000,
      max_fee_units: 25_000,
      expires_at: now + 900,
      settlement_deadline: now + 900,
      provider_fallback_allowed: false,
      reservation_salt: `0x${"99".repeat(32)}`,
      onchain_reservation_id: authorization.onchain_reservation_id,
      required_confirmations: 6,
      authorization,
      authorization_message: browserV3AuthorizationMessage(authorization),
    };
    const provider: VerifiedBrowserProvider = {
      peerId: providerIdentity.peerId,
      publicKey: providerIdentity.publicKey,
      paymentAddress: authorization.provider_payment_address,
      networkId: plan.network_id,
      channelId: plan.channel_id,
      backendPolicy: plan.backend_policy,
      channel,
      model,
      relayAddress: plan.provider_addresses[0],
      relayBaseUrl: "https://bridge.mycomesh.xyz:443",
      transportKey: providerTransport.binding,
      reserveInputBytes: 8000,
      reserveOutputTokens: 2000,
      pricingVersion: 1,
      pricingHash: authorization.pricing_hash,
      settlementContract: authorization.settlement_contract,
      descriptor: {},
      source: { peer_id: providerIdentity.peerId },
    };

    vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe(
        `https://bridge.mycomesh.xyz:443/infer/${encodeURIComponent(providerIdentity.peerId)}`,
      );
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.admission).toEqual({
        schema: "mycomesh.relay.consumer-admission.v1",
        authorization: { ...authorization, wallet_signature: "0x11" },
      });
      const requestWrapper = openBrowserJsonFrame(
        browserBase64UrlDecode(body.secure_frame, "request secure_frame"),
        {
          recipientKey: providerTransport,
          expectedPurpose: P2P_SECURE_REQUEST_PURPOSE,
          expectedSenderPeerId: consumerIdentity.peerId,
          expectedSenderPublicKey: consumerIdentity.publicKey,
          replayStore: new BrowserMemoryReplayStore(),
          now,
        },
      ).jsonPayload;
      expect(browserIsPlainObject(requestWrapper.message)).toBe(true);
      expect(browserIsPlainObject(requestWrapper.reply_transport_key)).toBe(true);
      const requestMessage = requestWrapper.message as Record<string, unknown>;
      const responseBody: InferenceResult = {
        ok: true,
        request_id: String(requestMessage.request_id),
        network_id: plan.network_id,
        channel_id: plan.channel_id,
        channel: plan.channel,
        backend_policy: plan.backend_policy,
        endpoint: "responses",
        model,
        output_text: "direct result",
        usage: { input_tokens: 5, output_tokens: 7, total_tokens: 12 },
        quality: { request_hash: requestHash },
      };
      const responseHash = settlementResponseHash(responseBody);
      const receiptBase: ProviderV3Receipt = {
        receipt_hash: `0x${"00".repeat(32)}` as Hex,
        accepted_hash: `0x${"00".repeat(32)}` as Hex,
        reservation_id: authorization.onchain_reservation_id,
        request_hash: requestHash,
        response_hash: responseHash,
        channel: plan.channel_hash,
        pricing_version: plan.pricing_version,
        pricing_hash: plan.pricing_hash,
        consumer: authorization.consumer_payment_address,
        provider: providerPaymentAddress,
        relay: `0x${"00".repeat(20)}` as Hex,
        pool: `0x${"00".repeat(20)}` as Hex,
        input_tokens: 5,
        output_tokens: 7,
        deadline: plan.settlement_deadline,
      };
      const commitments = computeV3ReceiptCommitments(receiptBase);
      const receipt: ProviderV3Receipt = {
        ...receiptBase,
        receipt_hash: commitments.receiptHash,
        accepted_hash: commitments.acceptedHash,
      };
      const typedData = buildV3ReceiptTypedData({
        schema: "mycomesh.settlement.v3.provider.v1",
        chain_id: plan.chain_id,
        settlement_contract: plan.settlement_contract,
        receipt,
        receipt_digest: `0x${"00".repeat(32)}` as Hex,
        provider_signature: `0x${"00".repeat(65)}` as Hex,
      });
      const settlementPayload = {
        schema: "mycomesh.settlement.v3.provider.v1" as const,
        chain_id: plan.chain_id,
        settlement_contract: plan.settlement_contract,
        receipt,
        receipt_digest: hashTypedData(typedData),
        provider_signature: await providerEvm.signTypedData(typedData),
      };
      const providerAttestation = signBrowserDocument(
        {
          attestation_version: PROVIDER_SETTLEMENT_ATTESTATION_VERSION,
          request_id: String(requestMessage.request_id),
          request_hash: requestHash,
          response_hash: responseHash.slice(2),
          channel: plan.channel,
          model,
          endpoint: "responses",
          input_tokens: 5,
          output_tokens: 7,
          gross_fee_units: 1_200,
          consumer_id: consumerIdentity.peerId,
          consumer_public_key: consumerIdentity.publicKey,
          consumer_payment_address: authorization.consumer_payment_address,
          provider_id: providerIdentity.peerId,
          provider_payment_address: providerPaymentAddress,
          pricing_hash: plan.pricing_hash,
          settlement_version: 3,
          pricing_version: plan.pricing_version,
          onchain_reservation_id: authorization.onchain_reservation_id,
          settlement_deadline: plan.settlement_deadline,
          network_id: plan.network_id,
          channel_id: plan.channel_id,
          backend_policy: plan.backend_policy,
        },
        providerIdentity,
        {
          purpose: PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE,
          audience: consumerIdentity.publicKey,
          timestamp: now,
          nonce: "bb".repeat(16),
        },
      );
      const providerResponse = signBrowserDocument(
        {
          ...responseBody,
          mycomesh_v3_settlement: settlementPayload,
          provider_settlement_attestation: providerAttestation,
        },
        providerIdentity,
        {
          purpose: PROVIDER_RESPONSE_PURPOSE,
          audience: consumerIdentity.publicKey,
          timestamp: now,
          nonce: "aa".repeat(16),
        },
      );
      const responseFrame = sealBrowserJsonFrame(
        { response: providerResponse },
        {
          sender: providerIdentity,
          recipientBinding: requestWrapper.reply_transport_key,
          expectedRecipientPeerId: consumerIdentity.peerId,
          expectedRecipientPublicKey: consumerIdentity.publicKey,
          purpose: P2P_SECURE_RESPONSE_PURPOSE,
          ttlSeconds: 60,
          now,
          randomBytes: fixedRandom(9),
        },
      );
      return new Response(JSON.stringify({ secure_frame: browserBase64UrlEncode(responseFrame) }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }));

    const result = await inferThroughBrowserConsumer({
      identity: consumerIdentity,
      provider,
      plan,
      authorization: { ...authorization, wallet_signature: "0x11" },
      input,
      model,
      maxOutputTokens: 64,
      now,
    });

    expect(result.output_text).toBe("direct result");
    expect(result.network_id).toBe("mycomesh-testnet");
  });
});

function fixedRandom(seed: number): (length: number) => Uint8Array {
  let counter = seed;
  return (length) => new Uint8Array(length).fill((counter++ % 250) + 1);
}
