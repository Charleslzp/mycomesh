import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  getBrowserSession,
  getPendingBrowserSessionRequest,
  getStoredBrowserSessionForSettlement,
  pendingSessionRequestMatchesSession,
  removeBrowserSession,
  removePendingBrowserSessionRequest,
  saveBrowserSession,
  savePendingBrowserSessionRequest,
  sessionActivationRequired,
  sessionRecordFromPlan,
  sessionRequestHash,
} from "./browserSessionStore";
import type { ConsumerV4Plan } from "./api";

const consumer = "0x00000000000000000000000000000000000000aa" as const;
const plan: ConsumerV4Plan = {
  schema: "mycomesh.consumer.v4.plan.v1",
  network_id: "mycomesh-testnet",
  channel_id: "codex",
  backend_policy: "codex-backend",
  provider_id: "peer-provider",
  provider_payment_address: "0x00000000000000000000000000000000000000bb",
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

describe("browser V4 session persistence", () => {
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
    expect(window.sessionStorage.length).toBe(1);
    expect(window.localStorage.length).toBe(0);
  });

  it("rejects a pending request whose stored identity does not match its input", () => {
    const session = sessionRecordFromPlan(plan, consumer, "model-a");
    expect(() => savePendingBrowserSessionRequest({
      chainId: plan.chain_id,
      settlement: plan.settlement_contract,
      sessionId: session.sessionId,
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
