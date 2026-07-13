import { runtimeConfig } from "./config";

export interface ProxyHealth {
  ok: boolean;
  service: string;
  billing_mode?: string;
  [key: string]: unknown;
}

export interface GatewayDescriptor {
  node_id?: string;
  public_url?: string;
  network_id?: string;
  chain_id?: number;
  settlement?: string;
  credential_audience?: string;
  credential_scope?: string;
  role?: string;
  status?: string;
  capacity?: number;
  expires_at?: number;
  public_key?: string;
}

export interface DiscoveryResponse {
  network?: string;
  chain_id?: number;
  settlement?: string;
  recommended_base_url?: string;
  recommended_gateway?: GatewayDescriptor;
  gateways?: GatewayDescriptor[];
  key_registration?: {
    enabled?: boolean;
    challenge_url?: string;
    register_url?: string;
    secret_storage?: string;
    credential_scope?: string;
  };
  updated_at?: number;
}

export interface ProviderPeer {
  peer_id: string;
  status?: string;
  channel?: string;
  model?: string;
  payment_address?: string;
  addresses?: string[];
  address?: string;
  capacity?: { max_concurrency?: number; transport?: string };
  reputation?: { score?: number; successes?: number; failures?: number };
  expires_at?: number;
  transport_key?: { key_id?: string; expires_at?: number };
}

export interface BridgePeersResponse {
  ok: boolean;
  protocol?: string;
  peers: ProviderPeer[];
}

export interface ModelRecord {
  id: string;
  object: string;
  created?: number;
  owned_by?: string;
}

export interface AccountRecord {
  account_id: string;
  status: string;
  balance_usdc: string;
  payment_address?: string | null;
  key_fingerprint?: string;
  billing_mode?: string;
  parent_account_id?: string | null;
  discount_bps?: number;
  reseller_margin_bps?: number;
  monthly_quota_usdc?: string;
  monthly_used_usdc?: string;
  usage_tier?: string;
  credential_audience?: string;
  credential_network_id?: string;
  credential_chain_id?: number;
  credential_settlement?: string;
}

export interface KeyChallenge {
  wallet: string;
  account_id: string;
  key_hash: string;
  key_fingerprint: string;
  chain_id: number;
  network_id: string;
  origin: string;
  settlement: string;
  nonce: string;
  expires_at: number;
  message: string;
  signature_type: "personal_sign";
}

export interface KeyRegistrationResult extends AccountRecord {
  wallet?: string;
  base_url?: string;
  credential_scope?: string;
  api_key_material?: "client_generated" | string;
  api_key_returned?: boolean;
}

export interface InferenceResult {
  ok?: boolean;
  id?: string;
  object?: string;
  request_id?: string;
  peer?: string;
  model?: string;
  output_text?: string;
  output?: unknown[];
  usage?: { input_tokens?: number; output_tokens?: number; total_tokens?: number };
  elapsed_ms?: number;
  mycomesh_price?: Record<string, unknown>;
  mycomesh_receipt?: Record<string, unknown>;
  error?: string;
  [key: string]: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly retryAfterMs?: number;

  constructor(status: number, detail: string, retryAfterMs?: number) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.retryAfterMs = retryAfterMs;
  }
}

function requestUrl(baseUrl: string, path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  if (baseUrl === "/") return normalizedPath;
  return `${baseUrl.replace(/\/+$/, "")}${normalizedPath}`;
}

function errorDetail(payload: unknown, status: number): string {
  if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>;
    const detail = record.detail ?? record.error ?? record.message;
    if (typeof detail === "string" && detail.trim()) return detail.trim();
    if (detail !== undefined) {
      try {
        return JSON.stringify(detail);
      } catch {
        // Fall through to the status message.
      }
    }
  }
  if (typeof payload === "string" && payload.trim()) return payload.trim().slice(0, 500);
  return `Request failed with status ${status}.`;
}

function retryAfterMs(headers: Headers): number | undefined {
  const raw = headers.get("retry-after");
  if (!raw) return undefined;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const at = Date.parse(raw);
  return Number.isFinite(at) ? Math.max(0, at - Date.now()) : undefined;
}

async function readPayload(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

export async function fetchProtocolJson<T>(
  baseUrl: string,
  path: string,
  init: RequestInit = {},
  timeoutMs = 10_000,
): Promise<T> {
  const controller = new AbortController();
  const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  try {
    const response = await fetch(requestUrl(baseUrl, path), {
      ...init,
      credentials: "omit",
      redirect: "error",
      headers,
      signal: controller.signal,
    });
    const payload = await readPayload(response);
    if (!response.ok) {
      throw new ApiError(response.status, errorDetail(payload, response.status), retryAfterMs(response.headers));
    }
    return payload as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted || (error instanceof DOMException && error.name === "AbortError")) {
      throw new ApiError(408, "The service did not respond before the deadline.");
    }
    if (error instanceof TypeError) {
      throw new ApiError(
        0,
        "The gateway could not be reached. Check its URL, availability, and browser CORS configuration.",
      );
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timer);
  }
}

function authorization(apiKey: string): HeadersInit {
  const secret = apiKey.trim();
  if (!secret) throw new ApiError(401, "An API key is required.");
  return { Authorization: `Bearer ${secret}` };
}

export const protocolApi = {
  health: () => fetchProtocolJson<ProxyHealth>(runtimeConfig.apiBaseUrl, "/health"),
  discovery: () =>
    fetchProtocolJson<DiscoveryResponse>(runtimeConfig.apiBaseUrl, "/.well-known/mycomesh.json"),
  gateways: () =>
    fetchProtocolJson<DiscoveryResponse>(runtimeConfig.apiBaseUrl, "/v1/mycomesh/gateways"),
  models: async () => {
    const payload = await fetchProtocolJson<{ data?: ModelRecord[] }>(
      runtimeConfig.apiBaseUrl,
      "/v1/models",
    );
    return Array.isArray(payload.data) ? payload.data : [];
  },
  peers: async () => {
    const payload = await fetchProtocolJson<BridgePeersResponse>(
      runtimeConfig.bridgeBaseUrl,
      "/peers",
    );
    return Array.isArray(payload.peers) ? payload.peers : [];
  },
  challenge: (wallet: string, keyHash: string) =>
    fetchProtocolJson<KeyChallenge>(runtimeConfig.apiBaseUrl, "/v1/mycomesh/keys/challenge", {
      method: "POST",
      body: JSON.stringify({ wallet, key_hash: keyHash, chain_id: runtimeConfig.chainId }),
    }),
  register: (challenge: KeyChallenge, signature: string, rotate = false) =>
    fetchProtocolJson<KeyRegistrationResult>(
      runtimeConfig.apiBaseUrl,
      rotate ? "/v1/mycomesh/keys/rotate" : "/v1/mycomesh/keys/register",
      {
        method: "POST",
        body: JSON.stringify({
          wallet: challenge.wallet,
          key_hash: challenge.key_hash,
          chain_id: challenge.chain_id,
          nonce: challenge.nonce,
          signature,
        }),
      },
    ),
  account: (apiKey: string) =>
    fetchProtocolJson<AccountRecord>(runtimeConfig.apiBaseUrl, "/account", {
      headers: authorization(apiKey),
    }),
  infer: (apiKey: string, input: string, model: string, maxOutputTokens: number) =>
    fetchProtocolJson<InferenceResult>(
      runtimeConfig.apiBaseUrl,
      "/v1/responses",
      {
        method: "POST",
        headers: authorization(apiKey),
        body: JSON.stringify({ model, input, max_output_tokens: maxOutputTokens }),
      },
      180_000,
    ),
};
