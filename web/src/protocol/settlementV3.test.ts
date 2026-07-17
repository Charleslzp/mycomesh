import { describe, expect, it } from "vitest";
import {
  encodeFunctionData,
  hashTypedData,
  keccak256,
  stringToHex,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { settlementV3Abi } from "./abis";
import type { ConsumerV3Authorization, ConsumerV3Plan, InferenceResult, ProviderV3Receipt } from "./api";
import {
  assertConsumerV3Plan,
  buildV3ReceiptTypedData,
  computeV3ReceiptCommitments,
  consumerV3AuthorizationMessage,
  consumerV3RequestHash,
  settlementResponseHash,
  validateV3Settlement,
} from "./settlementV3";

const chainId = 11155111;
const settlement = "0x3333333333333333333333333333333333333333" as const;
const provider = privateKeyToAccount(("0x" + "11".repeat(32)) as Hex);
const consumer = privateKeyToAccount(("0x" + "22".repeat(32)) as Hex);
const response: InferenceResult = { ok: true, output_text: "settled output", model: "model-v3", usage: { input_tokens: 12, output_tokens: 34, total_tokens: 46 } };

function fixture() {
  const now = Math.floor(Date.now() / 1000);
  const base: ProviderV3Receipt = {
    receipt_hash: ("0x" + "00".repeat(32)) as Hex,
    accepted_hash: ("0x" + "00".repeat(32)) as Hex,
    reservation_id: ("0x" + "03".repeat(32)) as Hex,
    request_hash: ("0x" + "04".repeat(32)) as Hex,
    response_hash: settlementResponseHash(response),
    channel: keccak256(stringToHex("codex-standard-v1")),
    pricing_version: 1,
    pricing_hash: ("0x" + "07".repeat(32)) as Hex,
    consumer: consumer.address,
    provider: provider.address,
    relay: ("0x" + "00".repeat(20)) as Hex,
    pool: ("0x" + "00".repeat(20)) as Hex,
    input_tokens: 12,
    output_tokens: 34,
    deadline: now + 1800,
  };
  const commitments = computeV3ReceiptCommitments(base);
  const receipt: ProviderV3Receipt = {
    ...base,
    receipt_hash: commitments.receiptHash,
    accepted_hash: commitments.acceptedHash,
  };
  const typedData = buildV3ReceiptTypedData({
    schema: "mycomesh.settlement.v3.provider.v1",
    chain_id: chainId,
    settlement_contract: settlement,
    receipt,
    receipt_digest: "0x" as Hex,
    provider_signature: "0x" as Hex,
  });
  const authorization: ConsumerV3Authorization = {
    authorization_version: "mycomesh.evm.session.v1",
    chain_id: chainId,
    settlement_contract: settlement,
    onchain_reservation_id: receipt.reservation_id,
    consumer_payment_address: consumer.address,
    provider_id: "peer-provider",
    provider_payment_address: provider.address,
    channel: "codex-standard-v1",
    pricing_hash: receipt.pricing_hash,
    pricing_version: receipt.pricing_version,
    request_hash: receipt.request_hash,
    max_fee_units: 1000,
    expires_at: now + 3600,
    settlement_deadline: receipt.deadline,
    provider_fallback_allowed: false,
    nonce: ("0x" + "08".repeat(32)) as Hex,
    session_public_key: "09".repeat(32),
  };
  const plan = {
    schema: "mycomesh.consumer.v3.plan.v1",
    provider_id: "peer-provider",
    provider_payment_address: provider.address,
    provider_addresses: ["myco+relays://bridge.mycomesh.xyz:443/peer-provider"],
    chain_id: chainId,
    settlement_contract: settlement,
    channel: "codex-standard-v1",
    channel_hash: receipt.channel,
    pricing_version: receipt.pricing_version,
    pricing_hash: receipt.pricing_hash,
    request_hash: receipt.request_hash,
    input_size_bytes: 42,
    reserve_input_bytes: 8000,
    reserve_output_tokens: 2000,
    max_fee_units: 1000,
    expires_at: now + 3600,
    settlement_deadline: receipt.deadline,
    provider_fallback_allowed: false,
    reservation_salt: ("0x" + "05".repeat(32)) as Hex,
    onchain_reservation_id: receipt.reservation_id,
    required_confirmations: 1,
    authorization,
    authorization_message: consumerV3AuthorizationMessage(authorization),
  } as unknown as ConsumerV3Plan;
  return { receipt, plan, typedData, now };
}

async function signedPayload() {
  const { receipt, plan, typedData, now } = fixture();
  return {
    receipt,
    plan,
    now,
    payload: {
      schema: "mycomesh.settlement.v3.provider.v1" as const,
      chain_id: chainId,
      settlement_contract: settlement,
      receipt,
      receipt_digest: hashTypedData(typedData),
      provider_signature: await provider.signTypedData(typedData),
    },
  };
}

describe("Settlement V3 browser validation", () => {
  it("binds the plan to the exact request and published Provider limits", () => {
    const { plan } = fixture();
    const expected = {
      chainId,
      settlementContract: settlement,
      consumer: consumer.address,
      providerId: "peer-provider",
      providerPaymentAddress: provider.address,
      inputSizeBytes: 42,
      maxOutputTokens: 256,
      reserveInputBytes: 8000,
      reserveOutputTokens: 2000,
    };

    expect(() => assertConsumerV3Plan(plan, expected)).not.toThrow();
    expect(() =>
      assertConsumerV3Plan(
        { ...plan, reserve_output_tokens: 128 },
        expected,
      ),
    ).toThrow(/output limit|output reserve/);
    expect(() =>
      assertConsumerV3Plan(
        { ...plan, input_size_bytes: 43 },
        expected,
      ),
    ).toThrow(/input size/);
  });

  it("matches the backend canonical request hash", () => {
    expect(consumerV3RequestHash("hello", "model-v3", 256)).toBe(
      "0xa63d765a1ea3a94587e5b60edd628a8950a5ddb06570746bbded9d26f7898eff",
    );
  });

  it("builds the contract Receipt tuple and validates a Provider-signed payload", async () => {
    const { receipt, plan, payload, now } = await signedPayload();
    const validated = await validateV3Settlement(payload, {
      chainId,
      settlementContract: settlement,
      consumer: consumer.address,
      providerId: "peer-provider",
      providerPaymentAddress: provider.address,
      plan,
      response,
      providerFallbackAllowed: false,
      now,
    });

    expect(validated.payload.receipt_digest).toBe(payload.receipt_digest);
    expect(validated.contractReceipt.pricingVersion).toBe(1n);
    const callData = encodeFunctionData({
      abi: settlementV3Abi,
      functionName: "settleSignedReceipt",
      args: [[
        [
          receipt.receipt_hash,
          receipt.accepted_hash,
          receipt.reservation_id,
          receipt.request_hash,
          receipt.response_hash,
          receipt.channel,
          BigInt(receipt.pricing_version),
          receipt.pricing_hash,
          receipt.consumer,
          receipt.provider,
          receipt.relay,
          receipt.pool,
          BigInt(receipt.input_tokens),
          BigInt(receipt.output_tokens),
          BigInt(receipt.deadline),
        ],
        payload.provider_signature,
        payload.provider_signature,
      ]],
    });
    expect(callData).toMatch(/^0x[0-9a-f]{8}/);
  });

  it("rejects a changed output, unknown fields, and mismatched chain or Consumer", async () => {
    const { payload, plan, now } = await signedPayload();
    await expect(
      validateV3Settlement({ ...payload, extra: true }, {
        chainId,
        settlementContract: settlement,
        consumer: consumer.address,
        providerId: "peer-provider",
        providerPaymentAddress: provider.address,
        plan,
        response: { ...response, output_text: "tampered" },
        providerFallbackAllowed: false,
        now,
      }),
    ).rejects.toThrow(/fields|output/);

    await expect(
      validateV3Settlement({ ...payload, chain_id: 1 }, {
        chainId,
        settlementContract: settlement,
        consumer: consumer.address,
        providerId: "peer-provider",
        providerPaymentAddress: provider.address,
        plan,
        response,
        providerFallbackAllowed: false,
        now,
      }),
    ).rejects.toThrow(/chain/);

    await expect(
      validateV3Settlement(payload, {
        chainId,
        settlementContract: settlement,
        consumer: provider.address,
        providerId: "peer-provider",
        providerPaymentAddress: provider.address,
        plan,
        response,
        providerFallbackAllowed: false,
        now,
      }),
    ).rejects.toThrow(/Consumer/);
  });

  it("rejects Provider usage above the Consumer cap or advertised reserve", async () => {
    const { payload, plan, now } = await signedPayload();
    const expectations = {
      chainId,
      settlementContract: settlement,
      consumer: consumer.address,
      providerId: "peer-provider",
      providerPaymentAddress: provider.address,
      plan,
      providerFallbackAllowed: false,
      maxOutputTokens: 256,
      now,
    };
    await expect(
      validateV3Settlement(
        { ...payload, receipt: { ...payload.receipt, output_tokens: 300 } },
        {
          ...expectations,
          response: {
            ...response,
            usage: { input_tokens: 12, output_tokens: 300, total_tokens: 312 },
          },
        },
      ),
    ).rejects.toThrow(/Consumer request cap/);
    await expect(
      validateV3Settlement(
        { ...payload, receipt: { ...payload.receipt, input_tokens: 8001 } },
        {
          ...expectations,
          response: {
            ...response,
            usage: { input_tokens: 8001, output_tokens: 34, total_tokens: 8035 },
          },
        },
      ),
    ).rejects.toThrow(/Provider reserve/);
  });

  it("rejects fallback-enabled plans and invalid Provider signatures", async () => {
    const { payload, plan, now } = await signedPayload();
    const fallbackPlan = { ...plan, provider_fallback_allowed: true } as unknown as ConsumerV3Plan;
    await expect(
      validateV3Settlement(payload, {
        chainId,
        settlementContract: settlement,
        consumer: consumer.address,
        providerId: "peer-provider",
        providerPaymentAddress: provider.address,
        plan: fallbackPlan,
        response,
        providerFallbackAllowed: true,
        now,
      }),
    ).rejects.toThrow(/fallback/);

    await expect(
      validateV3Settlement({ ...payload, provider_signature: ("0x" + "aa".repeat(65)) as Hex }, {
        chainId,
        settlementContract: settlement,
        consumer: consumer.address,
        providerId: "peer-provider",
        providerPaymentAddress: provider.address,
        plan,
        response,
        providerFallbackAllowed: false,
        now,
      }),
    ).rejects.toThrow(/signature|canonical/);
  });
  it("rejects tampered receipt hashes, usage, and route payees", async () => {
    const { payload, plan, now } = await signedPayload();
    const expectations = {
      chainId,
      settlementContract: settlement,
      consumer: consumer.address,
      providerId: "peer-provider",
      providerPaymentAddress: provider.address,
      plan,
      response,
      providerFallbackAllowed: false,
      now,
    };
    await expect(
      validateV3Settlement(
        { ...payload, receipt: { ...payload.receipt, receipt_hash: ("0x" + "aa".repeat(32)) as Hex } },
        expectations,
      ),
    ).rejects.toThrow(/commitment|digest|signature/);
    await expect(
      validateV3Settlement(
        { ...payload, receipt: { ...payload.receipt, input_tokens: 99 } },
        expectations,
      ),
    ).rejects.toThrow(/usage|commitment|digest/);
    await expect(
      validateV3Settlement(
        { ...payload, receipt: { ...payload.receipt, relay: consumer.address } },
        expectations,
      ),
    ).rejects.toThrow(/relay|payee|commitment/);
  });
});
