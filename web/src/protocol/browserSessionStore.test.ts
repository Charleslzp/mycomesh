import { afterEach, describe, expect, it } from "vitest";
import {
  getBrowserSession,
  getStoredBrowserSessionForSettlement,
  removeBrowserSession,
  saveBrowserSession,
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

afterEach(() => {
  removeBrowserSession();
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
});
