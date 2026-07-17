import { describe, expect, it } from "vitest";
import { hashTypedData, keccak256, stringToHex, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type {
  ConsumerV3Authorization,
  ConsumerV3Plan,
  InferenceResult,
  ProviderV3Receipt,
} from "./api";
import type { VerifiedBrowserProvider } from "./browserConsumerDiscovery";
import {
  browserSoftwareConsumerIdentityFromPrivateKeyForTest,
  signBrowserDocument,
} from "./browserConsumerIdentity";
import {
  PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE,
  PROVIDER_SETTLEMENT_ATTESTATION_VERSION,
  verifyBrowserProviderSettlementAttestation,
} from "./browserProviderAttestation";
import {
  buildV3ReceiptTypedData,
  computeV3ReceiptCommitments,
  settlementResponseHash,
  validateV3Settlement,
  type ValidatedV3Settlement,
} from "./settlementV3";
import { browserV3AuthorizationMessage, browserV3InferenceRequestHash } from "./browserConsumerV3";

const NOW = 1_800_000_000;
const CHAIN_ID = 11155111;
const SETTLEMENT = "0x3333333333333333333333333333333333333333" as const;

async function fixture() {
  const consumerIdentity = browserSoftwareConsumerIdentityFromPrivateKeyTest("22".repeat(32));
  const providerIdentity = browserSoftwareConsumerIdentityFromPrivateKeyTest("44".repeat(32));
  const providerEvm = privateKeyToAccount(("0x" + "11".repeat(32)) as Hex);
  const consumerEvm = privateKeyToAccount(("0x" + "33".repeat(32)) as Hex);
  const providerPaymentAddress = providerEvm.address.toLowerCase() as `0x${string}`;
  const consumerPaymentAddress = consumerEvm.address.toLowerCase() as `0x${string}`;
  const model = "mycomesh-codex-standard-v1";
  const input = "attestation fixture";
  const maxOutputTokens = 64;
  const requestHash = browserV3InferenceRequestHash({
    endpoint: "responses",
    model,
    input,
    maxOutputTokens,
  });
  const channel = "codex-standard-v1";
  const pricingHash = `0x${"77".repeat(32)}` as `0x${string}`;
  const reservationId = `0x${"88".repeat(32)}` as `0x${string}`;
  const authorization: ConsumerV3Authorization = {
    authorization_version: "mycomesh.evm.session.v1",
    chain_id: CHAIN_ID,
    settlement_contract: SETTLEMENT,
    onchain_reservation_id: reservationId,
    consumer_payment_address: consumerPaymentAddress,
    provider_id: providerIdentity.peerId,
    provider_payment_address: providerPaymentAddress,
    channel,
    pricing_hash: pricingHash,
    pricing_version: 1,
    request_hash: requestHash,
    max_fee_units: 25_000,
    expires_at: NOW + 900,
    settlement_deadline: NOW + 900,
    provider_fallback_allowed: false,
    nonce: `0x${"99".repeat(32)}`,
    session_public_key: consumerIdentity.publicKey,
  };
  const plan: ConsumerV3Plan = {
    schema: "mycomesh.consumer.v3.plan.v1",
    network_id: "mycomesh-testnet",
    channel_id: "codex",
    backend_policy: "codex-app-server-postvalidated-v1",
    provider_id: providerIdentity.peerId,
    provider_payment_address: providerPaymentAddress,
    provider_addresses: [`myco+relays://bridge.mycomesh.xyz:443/${providerIdentity.peerId}`],
    chain_id: CHAIN_ID,
    settlement_contract: SETTLEMENT,
    channel,
    channel_hash: keccak256(stringToHex(channel)),
    pricing_version: 1,
    pricing_hash: pricingHash,
    request_hash: requestHash,
    input_size_bytes: new TextEncoder().encode(input).length,
    reserve_input_bytes: 8000,
    reserve_output_tokens: 2000,
    max_fee_units: 25_000,
    expires_at: NOW + 900,
    settlement_deadline: NOW + 900,
    provider_fallback_allowed: false,
    reservation_salt: `0x${"aa".repeat(32)}`,
    onchain_reservation_id: reservationId,
    required_confirmations: 6,
    authorization,
    authorization_message: browserV3AuthorizationMessage(authorization),
  };
  const provider: VerifiedBrowserProvider = {
    peerId: providerIdentity.peerId,
    publicKey: providerIdentity.publicKey,
    paymentAddress: providerPaymentAddress,
    networkId: plan.network_id,
    channelId: plan.channel_id,
    backendPolicy: plan.backend_policy,
    channel,
    model,
    relayAddress: plan.provider_addresses[0],
    relayBaseUrl: "https://bridge.mycomesh.xyz:443",
    transportKey: {} as never,
    reserveInputBytes: 8000,
    reserveOutputTokens: 2000,
    pricingVersion: 1,
    pricingHash,
    settlementContract: SETTLEMENT,
    descriptor: {},
    source: { peer_id: providerIdentity.peerId },
  };
  const response: InferenceResult = {
    ok: true,
    request_id: "request-attestation-1",
    network_id: plan.network_id,
    channel_id: plan.channel_id,
    channel,
    backend_policy: plan.backend_policy,
    endpoint: "responses",
    model,
    output_text: "attestation result",
    usage: { input_tokens: 12, output_tokens: 34, total_tokens: 46 },
    quality: { request_hash: requestHash },
  };
  const responseHash = settlementResponseHash(response);
  const receiptBase: ProviderV3Receipt = {
    receipt_hash: `0x${"00".repeat(32)}` as Hex,
    accepted_hash: `0x${"00".repeat(32)}` as Hex,
    reservation_id: reservationId,
    request_hash: requestHash,
    response_hash: responseHash,
    channel: plan.channel_hash,
    pricing_version: 1,
    pricing_hash: pricingHash,
    consumer: consumerPaymentAddress,
    provider: providerPaymentAddress,
    relay: `0x${"00".repeat(20)}` as Hex,
    pool: `0x${"00".repeat(20)}` as Hex,
    input_tokens: 12,
    output_tokens: 34,
    deadline: NOW + 900,
  };
  const commitments = computeV3ReceiptCommitments(receiptBase);
  const receipt = {
    ...receiptBase,
    receipt_hash: commitments.receiptHash,
    accepted_hash: commitments.acceptedHash,
  } satisfies ProviderV3Receipt;
  const typedData = buildV3ReceiptTypedData({
    schema: "mycomesh.settlement.v3.provider.v1",
    chain_id: CHAIN_ID,
    settlement_contract: SETTLEMENT,
    receipt,
    receipt_digest: `0x${"00".repeat(32)}` as Hex,
    provider_signature: `0x${"00".repeat(65)}` as Hex,
  });
  const settlement = {
    schema: "mycomesh.settlement.v3.provider.v1" as const,
    chain_id: CHAIN_ID,
    settlement_contract: SETTLEMENT,
    receipt,
    receipt_digest: hashTypedData(typedData),
    provider_signature: await providerEvm.signTypedData(typedData),
  };
  response.mycomesh_v3_settlement = settlement;
  const attestation = signBrowserDocument(
    {
      attestation_version: PROVIDER_SETTLEMENT_ATTESTATION_VERSION,
      request_id: response.request_id,
      request_hash: requestHash,
      response_hash: responseHash.slice(2),
      channel,
      model,
      endpoint: "responses",
      input_tokens: 12,
      output_tokens: 34,
      gross_fee_units: 1200,
      consumer_id: consumerIdentity.peerId,
      consumer_public_key: consumerIdentity.publicKey,
      consumer_payment_address: consumerPaymentAddress,
      provider_id: providerIdentity.peerId,
      provider_payment_address: providerPaymentAddress,
      pricing_hash: pricingHash,
      settlement_version: 3,
      pricing_version: 1,
      onchain_reservation_id: reservationId,
      settlement_deadline: NOW + 900,
      network_id: plan.network_id,
      channel_id: plan.channel_id,
      backend_policy: plan.backend_policy,
    },
    providerIdentity,
    {
      purpose: PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE,
      audience: consumerIdentity.publicKey,
      timestamp: NOW,
      nonce: "bb".repeat(16),
    },
  );
  response.provider_settlement_attestation = attestation;
  const validatedSettlement = await validateV3Settlement(settlement, {
    chainId: CHAIN_ID,
    settlementContract: SETTLEMENT,
    consumer: consumerPaymentAddress,
    providerId: providerIdentity.peerId,
    providerPaymentAddress: providerPaymentAddress,
    plan,
    response,
    providerFallbackAllowed: false,
    maxOutputTokens,
    now: NOW,
  });
  return {
    consumerIdentity,
    providerIdentity,
    provider,
    plan,
    authorization,
    response,
    attestation,
    validatedSettlement,
    requestHash,
    providerEvm,
  };
}

function browserSoftwareConsumerIdentityFromPrivateKeyTest(value: string) {
  return browserSoftwareConsumerIdentityFromPrivateKeyForTest(value);
}

function optionsFor(value: Awaited<ReturnType<typeof fixture>>) {
  return {
    response: value.response,
    provider: value.provider,
    plan: value.plan,
    authorization: value.authorization,
    consumerPublicKey: value.consumerIdentity.publicKey,
    consumerId: value.consumerIdentity.peerId,
    requestId: value.response.request_id as string,
    requestHash: value.requestHash,
    model: value.provider.model,
    endpoint: "responses" as const,
    validatedSettlement: value.validatedSettlement,
    now: NOW,
  };
}

function resign(
  value: Awaited<ReturnType<typeof fixture>>,
  changes: Record<string, unknown>,
) {
  const unsigned = { ...value.attestation } as Record<string, unknown>;
  delete unsigned.signature;
  Object.assign(unsigned, changes);
  return signBrowserDocument(unsigned, value.providerIdentity, {
    purpose: PROVIDER_SETTLEMENT_ATTESTATION_PURPOSE,
    audience: value.consumerIdentity.publicKey,
    timestamp: NOW,
    nonce: "cc".repeat(16),
  });
}

describe("browser Provider settlement attestation", () => {
  it("accepts a fully bound Ed25519 attestation and EIP-712 receipt", async () => {
    const value = await fixture();
    await expect(
      verifyBrowserProviderSettlementAttestation(value.attestation, optionsFor(value)),
    ).resolves.toMatchObject({
      attestation_version: PROVIDER_SETTLEMENT_ATTESTATION_VERSION,
      provider_id: value.providerIdentity.peerId,
    });
  });

  it.each([
    ["request", { request_hash: `0x${"12".repeat(32)}` }],
    ["provider", { provider_id: "peer_other" }],
    ["consumer", { consumer_public_key: "33".repeat(32) }],
    ["payment", { provider_payment_address: "0x" + "99".repeat(20) }],
    ["pricing", { pricing_hash: `0x${"13".repeat(32)}` }],
    ["reservation", { onchain_reservation_id: `0x${"14".repeat(32)}` }],
    ["usage", { output_tokens: 35 }],
    ["deadline", { settlement_deadline: NOW + 901 }],
    ["channel", { channel_id: "claude" }],
  ])("rejects a re-signed %s field tamper", async (_label, changes) => {
    const value = await fixture();
    const tampered = resign(value, changes);
    await expect(
      verifyBrowserProviderSettlementAttestation(tampered, optionsFor(value)),
    ).rejects.toThrow();
  });

  it("rejects an audience tamper even when the attestation is not re-signed", async () => {
    const value = await fixture();
    const tampered = {
      ...value.attestation,
      signature: { ...value.attestation.signature, audience: "00".repeat(32) },
    };
    await expect(
      verifyBrowserProviderSettlementAttestation(tampered, optionsFor(value)),
    ).rejects.toThrow(/audience|signature/);
  });

  it("rejects an EVM provider signature that is not the receipt Provider", async () => {
    const value = await fixture();
    const other = privateKeyToAccount(("0x" + "55".repeat(32)) as Hex);
    const forged: ValidatedV3Settlement = {
      ...value.validatedSettlement,
      providerSignature: await other.signTypedData(value.validatedSettlement.typedData),
    };
    await expect(
      verifyBrowserProviderSettlementAttestation(value.attestation, {
        ...optionsFor(value),
        validatedSettlement: forged,
      }),
    ).rejects.toThrow(/signer|signature/);
  });
});
