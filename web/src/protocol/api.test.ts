import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchProtocolJson, inferencePeerId, protocolApi } from "./api";

function mockResponse(
  payload: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(extraHeaders),
    text: vi.fn().mockResolvedValue(
      typeof payload === "string" ? payload : JSON.stringify(payload),
    ),
  } as unknown as Response;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("protocol API transport", () => {
  it("extracts the Provider id from an inference descriptor", () => {
    expect(inferencePeerId("peer-a")).toBe("peer-a");
    expect(inferencePeerId({ peer_id: "peer-b", model: "model-a" })).toBe("peer-b");
    expect(inferencePeerId({ peer_id: "" })).toBeUndefined();
  });

  it("sends JSON requests without cookies or redirect following", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await fetchProtocolJson("https://api.mycomesh.xyz/", "/health");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.mycomesh.xyz/health");
    expect(init.credentials).toBe("omit");
    expect(init.redirect).toBe("error");
    expect(new Headers(init.headers).get("accept")).toBe("application/json");
  });

  it("keeps the API key in the Authorization header and uses the receipt-bearing endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse({ output_text: "ok" }));
    vi.stubGlobal("fetch", fetchMock);

    await protocolApi.infer("myco_test_secret", "hello", "mycomesh-model", 128);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/proxy-api/v1/responses");
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer myco_test_secret");
    expect(JSON.parse(String(init.body))).toEqual({
      model: "mycomesh-model",
      input: "hello",
      max_output_tokens: 128,
    });
  });

  it("prepares and submits the wallet-signed V3 envelope without moving the API key into JSON", async () => {
    const authorization = {
      authorization_version: "mycomesh.evm.session.v1",
      chain_id: 11155111,
      settlement_contract: ("0x" + "11".repeat(20)) as `0x${string}`,
      onchain_reservation_id: ("0x" + "22".repeat(32)) as `0x${string}`,
      consumer_payment_address: ("0x" + "33".repeat(20)) as `0x${string}`,
      provider_id: "peer-provider",
      provider_payment_address: ("0x" + "44".repeat(20)) as `0x${string}`,
      channel: "codex-standard-v1",
      pricing_hash: ("0x" + "55".repeat(32)) as `0x${string}`,
      pricing_version: 1,
      request_hash: ("0x" + "66".repeat(32)) as `0x${string}`,
      max_fee_units: 1000,
      expires_at: 2_000_000_000,
      settlement_deadline: 2_000_000_000,
      provider_fallback_allowed: false,
      nonce: ("0x" + "77".repeat(32)) as `0x${string}`,
      session_public_key: "88".repeat(32),
      wallet_signature: ("0x" + "99".repeat(65)) as `0x${string}`,
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(mockResponse({ provider_id: "peer-provider" }))
      .mockResolvedValueOnce(mockResponse({ output_text: "ok" }));
    vi.stubGlobal("fetch", fetchMock);

    await protocolApi.prepareV3("myco_test_secret", "hello", "model-a", 128, "peer-provider");
    await protocolApi.infer("myco_test_secret", "hello", "model-a", 128, {
      provider_id: "peer-provider",
      authorization,
      reservation_transaction_hash: ("0x" + "aa".repeat(32)) as `0x${string}`,
    });

    const [prepareUrl, prepareInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(prepareUrl).toBe("/proxy-api/v1/mycomesh/v3/prepare");
    expect(new Headers(prepareInit.headers).get("authorization")).toBe("Bearer myco_test_secret");
    expect(JSON.parse(String(prepareInit.body))).toMatchObject({
      endpoint: "responses",
      provider_id: "peer-provider",
      input: "hello",
      max_output_tokens: 128,
    });
    const [, inferInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    const inferBody = JSON.parse(String(inferInit.body));
    expect(inferBody.mycomesh_v3.authorization.wallet_signature).toBe(authorization.wallet_signature);
    expect(inferBody).not.toHaveProperty("api_key");
  });

  it("revokes only the bearer credential currently held by the browser", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse({ revoked: true, account_id: "acct-a" }));
    vi.stubGlobal("fetch", fetchMock);

    await protocolApi.revokeCurrentKey("myco_test_secret");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/proxy-api/v1/mycomesh/keys/current");
    expect(init.method).toBe("DELETE");
    expect(init.body).toBeUndefined();
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer myco_test_secret");
    expect(init.credentials).toBe("omit");
  });

  it("turns HTTP failures into structured errors and honors Retry-After", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockResponse({ detail: "capacity reached" }, 429, { "retry-after": "2" })),
    );

    const error = await fetchProtocolJson("/proxy-api", "/health").catch((value) => value);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 429, detail: "capacity reached", retryAfterMs: 2000 });
  });

  it("maps browser network failures to a CORS-aware gateway error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(fetchProtocolJson("/proxy-api", "/health")).rejects.toMatchObject({
      status: 0,
      detail: expect.stringContaining("CORS"),
    });
  });

  it("aborts requests at the configured deadline", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError")),
          );
        }),
      ),
    );

    const request = fetchProtocolJson("/proxy-api", "/health", {}, 100);
    const assertion = expect(request).rejects.toMatchObject({ status: 408 });
    await vi.advanceTimersByTimeAsync(101);
    await assertion;
  });
});
