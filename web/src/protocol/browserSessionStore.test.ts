import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getAddress } from "viem";
import {
  assertSessionInfoRoutesMatchRecord,
  getBrowserSession,
  getPendingBrowserSessionRequest,
  getStoredBrowserSessionForSettlement,
  pendingSessionRequestMatchesSession,
  parseV6SessionInfo,
  parseV5SessionInfo,
  removeBrowserSession,
  removePendingBrowserSessionRequest,
  saveBrowserSession,
  savePendingBrowserSessionRequest,
  sessionActivationRequired,
  sessionRecordFromPlan,
  sessionRecordMatchesPlan,
  sessionRequestHash,
} from "./browserSessionStore";
import type { ConsumerSessionPlan } from "./api";

const consumer = "0x00000000000000000000000000000000000000aa" as const;
const plan: ConsumerSessionPlan = {
  schema: "mycomesh.consumer.v5.plan.v1",
  settlement_version: 5,
  network_id: "mycomesh-testnet",
  channel_id: "codex",
  backend_policy: "codex-backend",
  provider_id: "peer-provider",
  provider_payment_address: "0x00000000000000000000000000000000000000bb",
  relay_payment_address: "0x00000000000000000000000000000000000000e1",
  relay_attestation_address: "0x00000000000000000000000000000000000000e2",
  pool_payment_address: "0x00000000000000000000000000000000000000e3",
  chain_id: 11155111,
  settlement_contract: "0x00000000000000000000000000000000000000cc",
  channel: "codex-standard-v1",
  channel_hash: `0x${"11".repeat(32)}`,
  pricing_version: 1,
  pricing_hash: `0x${"22".repeat(32)}`,
  session_salt: `0x${"33".repeat(32)}`,
  session_id: `0x${"44".repeat(32)}`,
  session_key: "0x00000000000000000000000000000000000000dd",
  max_amount_units: "1000000",
  expires_at: 2_000_000_000,
  activation_required: false,
  next_sequence: 7,
  cumulative_spend_units: "42000",
  request_deadline: 1_999_999_000,
  required_activation_confirmations: 1,
  consumer_payment_address: consumer,
};

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
});

afterEach(() => {
  removeBrowserSession();
  removePendingBrowserSessionRequest();
});

describe("browser V5 session persistence", () => {
  it("opens only when the Gateway has not confirmed activation", () => {
    expect(sessionActivationRequired(plan)).toBe(false);
    expect(sessionActivationRequired({ ...plan, activation_required: true })).toBe(true);
    expect(sessionActivationRequired({ ...plan, activation_required: undefined })).toBe(true);
  });

  it("round-trips a session only for its bound wallet and deployment", () => {
    const record = sessionRecordFromPlan(plan, consumer, "model-a");
    record.authorization = { session_signature: "should-not-leave-recovery" };
    saveBrowserSession(record);
    expect(getBrowserSession({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
      consumer,
    })).toMatchObject({
      sessionId: plan.session_id,
      sessionKey: plan.session_key,
      relayPaymentAddress: getAddress(plan.relay_payment_address),
      relayAttestationAddress: getAddress(plan.relay_attestation_address),
      poolPaymentAddress: getAddress(plan.pool_payment_address),
      nextSequence: 7,
      cumulativeSpendUnits: "42000",
    });
    expect(getBrowserSession({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
      consumer: "0x00000000000000000000000000000000000000ee",
    })).toBeNull();
    expect(getStoredBrowserSessionForSettlement({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
    })).not.toHaveProperty("authorization");
  });

  it("requires and compares every V5 payout route", () => {
    const session = sessionRecordFromPlan(plan, consumer, "model-a");
    expect(sessionRecordMatchesPlan(session, plan)).toBe(true);
    expect(sessionRecordMatchesPlan(session, {
      ...plan,
      relay_payment_address: "0x00000000000000000000000000000000000000f1",
    })).toBe(false);
    expect(sessionRecordMatchesPlan(session, {
      ...plan,
      relay_attestation_address: "0x00000000000000000000000000000000000000f2",
    })).toBe(false);
    expect(sessionRecordMatchesPlan(session, {
      ...plan,
      pool_payment_address: "0x00000000000000000000000000000000000000f3",
    })).toBe(false);
    expect(() => sessionRecordFromPlan({
      ...plan,
      relay_attestation_address: "0x0000000000000000000000000000000000000000",
    }, consumer, "model-a")).toThrow("both Relay addresses");
  });

  it("parses the V5 Session layout and rejects every changed on-chain route", () => {
    const record = sessionRecordFromPlan(plan, consumer, "model-a");
    const values: unknown[] = [
      consumer,
      plan.provider_payment_address,
      plan.relay_payment_address,
      plan.relay_attestation_address,
      plan.pool_payment_address,
      plan.session_key,
      plan.channel_hash,
      1n,
      plan.pricing_hash,
      1_750_000_000n,
      BigInt(plan.expires_at),
      0n,
      1_000_000n,
      42_000n,
      7n,
      false,
    ];
    const restored = parseV5SessionInfo(values);
    expect(restored).toMatchObject({
      expiresAt: plan.expires_at,
      maxAmount: 1_000_000n,
      nextSequence: 7n,
    });
    expect(() => assertSessionInfoRoutesMatchRecord(restored, record)).not.toThrow();

    for (const key of [
      "providerPaymentAddress",
      "relayPaymentAddress",
      "relayAttestationAddress",
      "poolPaymentAddress",
      "sessionKey",
    ] as const) {
      expect(() => assertSessionInfoRoutesMatchRecord({
        ...restored,
        [key]: "0x00000000000000000000000000000000000000f1",
      }, record)).toThrow("does not match the Gateway plan");
    }
  });

  it("parses the V6 Session layout and binds the active Relay epoch", () => {
    const v6Plan: ConsumerSessionPlan = {
      ...plan,
      schema: "mycomesh.consumer.v6.plan.v1",
      settlement_version: 6,
      protocol_version: 6,
      relay_epoch: 3,
    };
    const record = sessionRecordFromPlan(v6Plan, consumer, "model-a");
    const values: unknown[] = [
      consumer,
      v6Plan.provider_payment_address,
      v6Plan.relay_payment_address,
      v6Plan.relay_attestation_address,
      v6Plan.pool_payment_address,
      v6Plan.session_key,
      v6Plan.channel_hash,
      1n,
      v6Plan.pricing_hash,
      1_750_000_000n,
      BigInt(v6Plan.expires_at),
      0n,
      1_000_000n,
      42_000n,
      7n,
      3n,
      false,
    ];
    const restored = parseV6SessionInfo(values);
    expect(restored.relayEpoch).toBe(3n);
    expect(() => assertSessionInfoRoutesMatchRecord(restored, record)).not.toThrow();
    expect(() => assertSessionInfoRoutesMatchRecord({ ...restored, relayEpoch: 4n }, record))
      .toThrow("Relay epoch");
  });

  it("creates deterministic request identities while changing sequence", () => {
    const first = sessionRequestHash({ sessionId: plan.session_id, sequence: 0, model: "model-a", input: "hello", maxOutputTokens: 128 });
    const retry = sessionRequestHash({ sessionId: plan.session_id, sequence: 0, model: "model-a", input: "hello", maxOutputTokens: 128 });
    const next = sessionRequestHash({ sessionId: plan.session_id, sequence: 1, model: "model-a", input: "hello", maxOutputTokens: 128 });
    expect(first).toBe(retry);
    expect(next).not.toBe(first);
  });

  it("round-trips the exact pending request in session storage", () => {
    const session = sessionRecordFromPlan(plan, consumer, "model-a");
    const requestHash = sessionRequestHash({
      sessionId: session.sessionId,
      sequence: session.nextSequence,
      model: "model-a",
      input: "unfinished prompt",
      maxOutputTokens: 128,
    });
    const pending = savePendingBrowserSessionRequest({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
      sessionId: session.sessionId,
      providerPaymentAddress: session.providerPaymentAddress,
      relayPaymentAddress: session.relayPaymentAddress,
      relayAttestationAddress: session.relayAttestationAddress,
      poolPaymentAddress: session.poolPaymentAddress,
      sequence: session.nextSequence,
      input: "unfinished prompt",
      model: "model-a",
      maxOutputTokens: 128,
      envelope: {
        session_id: session.sessionId,
        request_id: requestHash.slice(2),
        max_fee_units: session.maxAmountUnits,
        deadline: session.requestDeadline,
      },
      startedAt: 1_750_000_000,
    });

    expect(getPendingBrowserSessionRequest({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
    })).toEqual(pending);
    expect(pendingSessionRequestMatchesSession(pending, session)).toBe(true);
    expect(pendingSessionRequestMatchesSession(pending, { ...session, nextSequence: session.nextSequence + 1 })).toBe(true);
    expect(pendingSessionRequestMatchesSession(pending, {
      ...session,
      relayPaymentAddress: "0x00000000000000000000000000000000000000f1",
    })).toBe(false);
    expect(window.sessionStorage.length).toBe(1);
    expect(window.localStorage.length).toBe(0);
  });

  it("rejects a pending request whose stored identity does not match its input", () => {
    const session = sessionRecordFromPlan(plan, consumer, "model-a");
    expect(() => savePendingBrowserSessionRequest({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
      sessionId: session.sessionId,
      providerPaymentAddress: session.providerPaymentAddress,
      relayPaymentAddress: session.relayPaymentAddress,
      relayAttestationAddress: session.relayAttestationAddress,
      poolPaymentAddress: session.poolPaymentAddress,
      sequence: session.nextSequence,
      input: "unfinished prompt",
      model: "model-a",
      maxOutputTokens: 128,
      envelope: {
        session_id: session.sessionId,
        request_id: "55".repeat(32),
        max_fee_units: session.maxAmountUnits,
        deadline: session.requestDeadline,
      },
      startedAt: 1_750_000_000,
    })).toThrow("pending session request is invalid");
    expect(window.sessionStorage.length).toBe(0);
  });

  it("stores only the retry fields and filters by deployment", () => {
    const session = sessionRecordFromPlan(plan, consumer, "model-a");
    const input = "private prompt for this browser tab";
    const requestHash = sessionRequestHash({
      sessionId: session.sessionId,
      sequence: session.nextSequence,
      model: "model-a",
      input,
      maxOutputTokens: 128,
    });
    savePendingBrowserSessionRequest({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
      sessionId: session.sessionId,
      providerPaymentAddress: session.providerPaymentAddress,
      relayPaymentAddress: session.relayPaymentAddress,
      relayAttestationAddress: session.relayAttestationAddress,
      poolPaymentAddress: session.poolPaymentAddress,
      sequence: session.nextSequence,
      input,
      model: "model-a",
      maxOutputTokens: 128,
      envelope: {
        session_id: session.sessionId,
        request_id: requestHash.slice(2),
        max_fee_units: session.maxAmountUnits,
        deadline: session.requestDeadline,
        authorization: { session_signature: "must-not-be-stored" },
      },
      startedAt: 1_750_000_000,
      apiKey: "must-not-be-stored",
    } as Parameters<typeof savePendingBrowserSessionRequest>[0] & { apiKey: string });

    const serialized = window.sessionStorage.getItem(window.sessionStorage.key(0)!);
    expect(serialized).toContain(input);
    expect(serialized).not.toContain("must-not-be-stored");
    expect(getPendingBrowserSessionRequest({
      chainId: plan.chain_id + 1,
      settlement: plan.settlement_contract,
    })).toBeNull();
    expect(getPendingBrowserSessionRequest({
      chainId: plan.chain_id,
      settlement: "0x00000000000000000000000000000000000000ee",
    })).toBeNull();
  });
});
