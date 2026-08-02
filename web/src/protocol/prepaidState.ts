interface WaitForMinimumValueOptions {
  attempts?: number;
  intervalMs?: number;
}

export async function waitForMinimumValue(
  read: () => Promise<bigint>,
  minimum: bigint,
  options: WaitForMinimumValueOptions = {},
): Promise<boolean> {
  const attempts = options.attempts ?? 10;
  const intervalMs = options.intervalMs ?? 1_000;
  if (!Number.isSafeInteger(attempts) || attempts < 1 || intervalMs < 0) {
    throw new Error("Invalid prepaid state wait options.");
  }
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await read() >= minimum) return true;
    if (attempt + 1 < attempts && intervalMs > 0) {
      await new Promise((resolve) => globalThis.setTimeout(resolve, intervalMs));
    }
  }
  return false;
}
