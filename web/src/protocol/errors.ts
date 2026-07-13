import { ApiError } from "./api";

export type ProtocolErrorCode =
  | "bad_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "timeout"
  | "conflict"
  | "rate_limited"
  | "service_unavailable"
  | "network"
  | "wallet_rejected"
  | "unknown";

export interface ProtocolErrorInfo {
  code: ProtocolErrorCode;
  title: string;
  message: string;
  retryable: boolean;
  status?: number;
}

function walletRejected(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const record = error as { code?: unknown; name?: unknown; message?: unknown };
  return (
    record.code === 4001 ||
    record.code === "ACTION_REJECTED" ||
    record.name === "UserRejectedRequestError" ||
    /user rejected|user denied/i.test(String(record.message || ""))
  );
}

export function toProtocolError(error: unknown): ProtocolErrorInfo {
  if (walletRejected(error)) {
    return {
      code: "wallet_rejected",
      title: "Signature cancelled",
      message: "The wallet did not approve the request. No API key was registered.",
      retryable: true,
    };
  }
  if (!(error instanceof ApiError)) {
    return {
      code: "unknown",
      title: "Request failed",
      message: error instanceof Error ? error.message : "An unexpected error occurred.",
      retryable: false,
    };
  }

  const detail = error.detail;
  if (error.status === 0) {
    return {
      code: "network",
      title: "Gateway unreachable",
      message: detail,
      retryable: true,
      status: error.status,
    };
  }
  if (error.status === 400 || error.status === 422) {
    return { code: "bad_request", title: "Request rejected", message: detail, retryable: false, status: error.status };
  }
  if (error.status === 401) {
    return { code: "unauthorized", title: "API key required", message: detail, retryable: false, status: error.status };
  }
  if (error.status === 403) {
    return { code: "forbidden", title: "Access denied", message: detail, retryable: false, status: error.status };
  }
  if (error.status === 404) {
    return { code: "not_found", title: "Resource not found", message: detail, retryable: false, status: error.status };
  }
  if (error.status === 408) {
    return { code: "timeout", title: "Gateway timed out", message: detail, retryable: true, status: error.status };
  }
  if (error.status === 409) {
    return { code: "conflict", title: "Request already in progress", message: detail, retryable: true, status: error.status };
  }
  if (error.status === 429) {
    return { code: "rate_limited", title: "Rate limit reached", message: detail, retryable: true, status: error.status };
  }
  if (error.status >= 500) {
    return {
      code: "service_unavailable",
      title: "Service unavailable",
      message: detail,
      retryable: true,
      status: error.status,
    };
  }
  return { code: "unknown", title: "Request failed", message: detail, retryable: false, status: error.status };
}
