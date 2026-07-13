import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchProtocolJson, protocolApi } from "./api";

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
