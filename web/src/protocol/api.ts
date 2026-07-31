import { runtimeConfig } from "./config";

export const MAX_PROTOCOL_JSON_RESPONSE_BYTES = 8 * 1024 * 1024;

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
    rotate_url?: string;
    revoke_url?: string;
    secret_storage?: string;
    credential_scope?: string;
  };
  updated_at?: number;
}

export interface ProviderPeer {
  peer_id: string;
  status?: string;
  protocol?: string;
  public_key?: string;
  network_id?: string;
  channel_id?: string;
  backend_policy?: string;
  channel?: string;
  model?: string;
  payment_address?: string;
  addresses?: string[];
  address?: string;
  capacity?: {
    max_concurrency?: number;
    transport?: string;
    reserve_input_bytes?: number;
    reserve_output_tokens?: number;
  };
  reputation?: { score?: number; successes?: number; failures?: number };
  last_seen?: number;
  ttl_seconds?: number;
  expires_at?: number;
  transport_key?: Record<string, unknown> & { key_id?: string; expires_at?: number };
  settlement?: { version?: number; chain_id?: number; contract?: string; pricing_version?: number; pricing_hash?: string };
  descriptor?: Record<string, unknown>;
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

export interface KeyRevocationResult {
  account_id: string;
  key_fingerprint?: string | null;
  revoked: boolean;
}

export interface ConsumerV3Authorization {
  authorization_version: string;
  chain_id: number;
  settlement_contract: `0x${string}`;
  onchain_reservation_id: `0x${string}`;
  consumer_payment_address: `0x${string}`;
  provider_id: string;
  provider_payment_address: `0x${string}`;
  channel: string;
  pricing_hash: `0x${string}`;
  pricing_version: number;
  request_hash: `0x${string}`;
  max_fee_units: number;
  expires_at: number;
  settlement_deadline: number;
  provider_fallback_allowed: boolean;
  nonce: `0x${string}`;
  session_public_key: string;
  wallet_signature?: `0x${string}`;
}

export interface ConsumerV3Plan {
  schema: "mycomesh.consumer.v3.plan.v1";
  network_id: string;
  channel_id: string;
  backend_policy: string;
  provider_id: string;
  provider_payment_address: `0x${string}`;
  provider_addresses: string[];
  chain_id: number;
  settlement_contract: `0x${string}`;
  channel: string;
  channel_hash: `0x${string}`;
  pricing_version: number;
  pricing_hash: `0x${string}`;
  request_hash: `0x${string}`;
  input_size_bytes: number;
  reserve_input_bytes: number;
  reserve_output_tokens: number;
  max_fee_units: number;
  expires_at: number;
  settlement_deadline: number;
  provider_fallback_allowed: false;
  reservation_salt: `0x${string}`;
  onchain_reservation_id: `0x${string}`;
  required_confirmations: number;
  authorization: ConsumerV3Authorization;
  authorization_message: string;
}

export interface ConsumerV3Envelope {
  provider_id: string;
  authorization: ConsumerV3Authorization;
  reservation_transaction_hash: `0x${string}`;
}

export interface ProviderV3Receipt {
  receipt_hash: `0x${string}`;
  accepted_hash: `0x${string}`;
  reservation_id: `0x${string}`;
  request_hash: `0x${string}`;
  response_hash: `0x${string}`;
  channel: `0x${string}`;
  pricing_version: number;
  pricing_hash: `0x${string}`;
  consumer: `0x${string}`;
  provider: `0x${string}`;
  relay: `0x${string}`;
  pool: `0x${string}`;
  input_tokens: number;
  output_tokens: number;
  deadline: number;
}

export interface ProviderV3Settlement {
  schema: "mycomesh.settlement.v3.provider.v1";
  chain_id: number;
  settlement_contract: `0x${string}`;
  receipt: ProviderV3Receipt;
  receipt_digest: `0x${string}`;
  provider_signature: `0x${string}`;
}

export type JsonObject = Record<string, unknown>;

/** Plan returned once when a consumer activates a route-bound V5 session. */
export interface ConsumerSessionPlan {
  schema: "mycomesh.consumer.v5.plan.v1";
  enabled?: boolean;
  settlement_version?: 5;
  network_id: string;
  channel_id: string;
  backend_policy: string;
  provider_id: string;
  provider_payment_address: `0x${string}`;
  provider_addresses?: string[];
  relay_payment_address: `0x${string}`;
  relay_attestation_address: `0x${string}`;
  pool_payment_address: `0x${string}`;
  chain_id: number;
  settlement_contract: `0x${string}`;
  channel: string;
  channel_hash: `0x${string}`;
  pricing_version: number;
  pricing_hash: `0x${string}`;
  session_salt: `0x${string}`;
  session_id: `0x${string}`;
  session_key: `0x${string}`;
  max_amount_units: number | string;
  expires_at: number;
  /** false means the Gateway verified this session on-chain and it can be restored without a wallet write. */
  activation_required?: boolean;
  next_sequence?: number;
  cumulative_spend_units?: number | string;
  request_deadline?: number;
  required_activation_confirmations?: number;
  consumer_payment_address: `0x${string}`;
  /** Optional unsigned authorization document for the Gateway session. */
  authorization?: JsonObject;
  /** A backend may return an already-normalized request template. */
  request?: JsonObject;
}

export type ConsumerV5Plan = ConsumerSessionPlan;
/** @deprecated Session preparation now returns a V5 plan. */
export type ConsumerV4Plan = ConsumerSessionPlan;

export interface ConsumerSessionAuthorization extends JsonObject {
  schema?: string;
  authorization_version?: string;
  chain_id?: number;
  settlement_contract?: `0x${string}`;
  session_id?: `0x${string}`;
  session_key?: `0x${string}`;
  consumer_payment_address?: `0x${string}`;
  provider_id?: string;
  provider_payment_address?: `0x${string}`;
  relay_payment_address?: `0x${string}`;
  relay_attestation_address?: `0x${string}`;
  pool_payment_address?: `0x${string}`;
  channel?: string;
  channel_hash?: `0x${string}`;
  pricing_version?: number;
  pricing_hash?: `0x${string}`;
  max_amount_units?: number | string;
  max_fee_units?: number | string;
  expires_at?: number;
  deadline?: number;
  [key: string]: unknown;
}

export type ConsumerV5Authorization = ConsumerSessionAuthorization;
/** @deprecated Session authorization now targets V5. */
export type ConsumerV4Authorization = ConsumerSessionAuthorization;

export interface ConsumerSessionRequest extends JsonObject {
  schema?: string;
  request_hash: `0x${string}`;
  session_id: `0x${string}`;
  sequence: number;
  cumulative_spend_units: number | string;
  max_fee_units: number | string;
  deadline: number;
  model: string;
  input: string;
  max_output_tokens: number;
  [key: string]: unknown;
}

export type ConsumerV5Request = ConsumerSessionRequest;
/** @deprecated Session requests now target V5. */
export type ConsumerV4Request = ConsumerSessionRequest;

export interface ConsumerSessionEnvelope {
  session_id: `0x${string}`;
  sequence?: number;
  cumulative_spend_units?: number | string;
  authorization?: ConsumerSessionAuthorization;
  request?: ConsumerSessionRequest;
  /** Compatibility fields accepted by older Gateway builds. */
  session_key?: `0x${string}`;
  provider_id?: string;
  [key: string]: unknown;
}

export type ConsumerV5Envelope = ConsumerSessionEnvelope;
/** @deprecated Session envelopes now target V5. */
export type ConsumerV4Envelope = ConsumerSessionEnvelope;

export interface ProviderV5Settlement {
  schema: "mycomesh.settlement.v5.provider.v1" | string;
  chain_id: number;
  settlement_contract: `0x${string}`;
  receipt: JsonObject;
  receipt_digest: `0x${string}`;
  provider_signature: `0x${string}`;
  session_key_signature?: `0x${string}`;
  relay_signature?: `0x${string}`;
}

/** @deprecated Provider settlement payloads now target V5. */
export type ProviderV4Settlement = ProviderV5Settlement;

export interface InferenceResult {
  ok?: boolean;
  id?: string;
  object?: string;
  request_id?: string;
  peer?: string | ProviderPeer;
  model?: string;
  output_text?: string;
  output?: unknown[];
  usage?: { input_tokens?: number; output_tokens?: number; total_tokens?: number };
  elapsed_ms?: number;
  mycomesh_price?: Record<string, unknown>;
  mycomesh_receipt?: Record<string, unknown>;
  mycomesh_v3_settlement?: ProviderV3Settlement;
  mycomesh_v5_settlement?: ProviderV5Settlement;
  mycomesh_v4_settlement?: ProviderV4Settlement;
  mycomesh_session?: {
    session_id?: `0x${string}`;
    sequence?: number;
    cumulative_spend_units?: number | string;
    next_sequence?: number;
    remaining_units?: number | string;
    [key: string]: unknown;
  };
  error?: string;
  [key: string]: unknown;
}

export function inferencePeerId(peer: InferenceResult["peer"]): string | undefined {
  if (typeof peer === "string") return peer.trim() || undefined;
  if (peer && typeof peer.peer_id === "string") return peer.peer_id.trim() || undefined;
  return undefined;
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
  const text = await readBoundedResponseText(response);
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

async function readBoundedResponseText(response: Response): Promise<string> {
  const contentLength = declaredContentLength(response.headers);
  if (contentLength !== undefined && contentLength > MAX_PROTOCOL_JSON_RESPONSE_BYTES) {
    await cancelResponseBody(response.body);
    throw oversizedJsonResponseError();
  }

  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_PROTOCOL_JSON_RESPONSE_BYTES) {
      throw oversizedJsonResponseError();
    }
    return text;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const parts: string[] = [];
  let receivedBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      receivedBytes += value.byteLength;
      if (receivedBytes > MAX_PROTOCOL_JSON_RESPONSE_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The response is already rejected; cancellation is best-effort cleanup.
        }
        throw oversizedJsonResponseError();
      }
      parts.push(decoder.decode(value, { stream: true }));
    }
    parts.push(decoder.decode());
    return parts.join("");
  } finally {
    reader.releaseLock();
  }
}

function declaredContentLength(headers: Headers): number | undefined {
  const raw = headers.get("content-length");
  if (!raw || !/^\d+$/.test(raw)) return undefined;
  const length = Number(raw);
  return Number.isSafeInteger(length) ? length : Number.POSITIVE_INFINITY;
}

async function cancelResponseBody(body: ReadableStream<Uint8Array> | null): Promise<void> {
  if (!body) return;
  try {
    await body.cancel();
  } catch {
    // The size violation is authoritative even if transport cleanup fails.
  }
}

function oversizedJsonResponseError(): ApiError {
  return new ApiError(
    502,
    `The service JSON response exceeds the ${MAX_PROTOCOL_JSON_RESPONSE_BYTES}-byte limit.`,
  );
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
  revokeCurrentKey: (apiKey: string) =>
    fetchProtocolJson<KeyRevocationResult>(
      runtimeConfig.apiBaseUrl,
      "/v1/mycomesh/keys/current",
      {
        method: "DELETE",
        headers: authorization(apiKey),
      },
    ),
  prepareV3: (
    apiKey: string,
    input: string,
    model: string,
    maxOutputTokens: number,
    providerId?: string,
  ) =>
    fetchProtocolJson<ConsumerV3Plan>(
      runtimeConfig.apiBaseUrl,
      "/v1/mycomesh/v3/prepare",
      {
        method: "POST",
        headers: authorization(apiKey),
        body: JSON.stringify({
          endpoint: "responses",
          model,
          input,
          max_output_tokens: maxOutputTokens,
          ...(providerId ? { provider_id: providerId } : {}),
        }),
      },
      // V3 preparation may perform several finalized-chain RPCs plus Provider
      // discovery before the reservation plan is returned.
      90_000,
    ),
  prepareSession: (
    apiKey: string,
    input: string,
    model: string,
    maxOutputTokens: number,
    providerId?: string,
    sessionId?: string,
  ) =>
    fetchProtocolJson<ConsumerSessionPlan>(
      runtimeConfig.apiBaseUrl,
      "/v1/mycomesh/session/prepare",
      {
        method: "POST",
        headers: authorization(apiKey),
        body: JSON.stringify({
          endpoint: "responses",
          model,
          input,
          max_output_tokens: maxOutputTokens,
          ...(providerId ? { provider_id: providerId } : {}),
          ...(sessionId ? { session_id: sessionId } : {}),
        }),
      },
      90_000,
    ),
  infer: (
    apiKey: string,
    input: string,
    model: string,
    maxOutputTokens: number,
    consumerV3?: ConsumerV3Envelope,
    consumerSession?: ConsumerSessionEnvelope,
  ) =>
    fetchProtocolJson<InferenceResult>(
      runtimeConfig.apiBaseUrl,
      "/v1/responses",
      {
        method: "POST",
        headers: authorization(apiKey),
        body: JSON.stringify({
          model,
          input,
          max_output_tokens: maxOutputTokens,
          ...(consumerV3 ? { mycomesh_v3: consumerV3 } : {}),
          ...(consumerSession ? { mycomesh_session: consumerSession } : {}),
        }),
      },
      // The production Proxy allows up to 300s for V3 admission, Provider
      // execution, and receipt validation; leave a small client-side buffer.
      305_000,
    ),
};
