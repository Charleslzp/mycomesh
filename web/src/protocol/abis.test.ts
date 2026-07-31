import { describe, expect, it } from "vitest";
import { settlementV5Abi } from "./abis";

describe("Settlement V5 ABI", () => {
  it("binds every route when opening a Session", () => {
    const openSession = settlementV5Abi.find(
      (item) => item.type === "function" && item.name === "openSession",
    );
    expect(openSession?.type).toBe("function");
    if (!openSession || openSession.type !== "function") return;
    expect(openSession.inputs.map((input) => input.name)).toEqual([
      "sessionSalt",
      "provider",
      "relay",
      "relaySigner",
      "pool",
      "sessionKey",
      "channel",
      "pricingVersion",
      "maxAmount",
      "expiresAt",
    ]);
  });

  it("decodes Session route fields before the signing and pricing state", () => {
    const sessionInfo = settlementV5Abi.find(
      (item) => item.type === "function" && item.name === "sessionInfo",
    );
    expect(sessionInfo?.type).toBe("function");
    if (!sessionInfo || sessionInfo.type !== "function") return;
    const session = sessionInfo.outputs[0];
    expect(session.type).toBe("tuple");
    if (session.type !== "tuple") return;
    expect(session.components.map((component) => component.name)).toEqual([
      "consumer",
      "provider",
      "relay",
      "relaySigner",
      "pool",
      "sessionKey",
      "channel",
      "pricingVersion",
      "pricingHash",
      "openedAt",
      "expiresAt",
      "closeRequestedAt",
      "maxAmount",
      "spent",
      "nextSequence",
      "closed",
    ]);
  });
});
