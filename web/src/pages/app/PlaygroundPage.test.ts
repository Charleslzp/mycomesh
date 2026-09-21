import { describe, expect, it } from "vitest";
import { isRetryableInferenceError } from "./PlaygroundPage";

describe("Consumer inference recovery guidance", () => {
  it("offers retry for transient transport and route failures", () => {
    expect(isRetryableInferenceError("Settlement RPC is temporarily unavailable. Retry in a moment; no request was dispatched.")).toBe(true);
    expect(isRetryableInferenceError("The request is taking longer than expected. Retry it to continue without creating a second charge.")).toBe(true);
    expect(isRetryableInferenceError("This model has no healthy Relay route right now.")).toBe(true);
  });

  it("does not offer retry for setup and authorization failures", () => {
    expect(isRetryableInferenceError("No active fixed-budget channel covers this model yet.")).toBe(false);
    expect(isRetryableInferenceError("Prepaid access needs attention. Refresh prepaid access, then retry the request.")).toBe(false);
    expect(isRetryableInferenceError(null)).toBe(false);
  });
});
