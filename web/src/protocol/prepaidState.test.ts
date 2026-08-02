import { describe, expect, it, vi } from "vitest";
import { waitForMinimumValue } from "./prepaidState";

describe("prepaid state visibility", () => {
  it("waits for a lagging RPC to expose the confirmed value", async () => {
    const read = vi.fn()
      .mockResolvedValueOnce(0n)
      .mockResolvedValueOnce(4n)
      .mockResolvedValueOnce(10n);

    await expect(waitForMinimumValue(read, 10n, { attempts: 3, intervalMs: 0 })).resolves.toBe(true);
    expect(read).toHaveBeenCalledTimes(3);
  });

  it("reports when the required value never becomes visible", async () => {
    const read = vi.fn().mockResolvedValue(9n);

    await expect(waitForMinimumValue(read, 10n, { attempts: 2, intervalMs: 0 })).resolves.toBe(false);
    expect(read).toHaveBeenCalledTimes(2);
  });
});
