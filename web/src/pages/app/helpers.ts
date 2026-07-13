import { ApiError } from "../../protocol/api";

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.detail;
  if (error instanceof Error) return error.message;
  return "The operation could not be completed.";
}

export function formatTokenAmount(value: bigint | undefined, decimals: number, maximumFractionDigits = 2) {
  if (value === undefined) return "Unavailable";
  const divisor = 10n ** BigInt(decimals);
  const whole = value / divisor;
  const fraction = value % divisor;
  if (maximumFractionDigits === 0) return whole.toLocaleString();
  const padded = fraction.toString().padStart(decimals, "0").slice(0, maximumFractionDigits);
  const trimmed = padded.replace(/0+$/, "");
  return trimmed ? `${whole.toLocaleString()}.${trimmed}` : whole.toLocaleString();
}
