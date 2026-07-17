import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import {
  ApiKeyProvider,
  SESSION_API_KEY_STORAGE_KEY,
  useApiKey,
} from "./ApiKeyContext";

function Harness() {
  const { apiKey, credential, setApiKey, clearApiKey, persistence } = useApiKey();
  return (
    <>
      <output>{apiKey ?? "none"}</output>
      <span>{persistence}</span>
      <span>{credential?.baseUrl ?? "no-url"}</span>
      <button
        type="button"
        onClick={() => setApiKey("myco_test_session-only-secret", { baseUrl: "https://gateway.mycomesh.xyz/v1" })}
      >Set</button>
      <button type="button" onClick={clearApiKey}>Clear</button>
    </>
  );
}

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});

describe("ApiKeyProvider", () => {
  it("persists only in sessionStorage and clears explicitly", () => {
    render(
      <ApiKeyProvider>
        <Harness />
      </ApiKeyProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Set" }));
    expect(screen.getByText("myco_test_session-only-secret")).toBeInTheDocument();
    expect(sessionStorage.getItem(SESSION_API_KEY_STORAGE_KEY)).toContain(
      "myco_test_session-only-secret",
    );
    expect(screen.getByText("https://gateway.mycomesh.xyz/v1")).toBeInTheDocument();
    expect(localStorage.length).toBe(0);

    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(screen.getByText("none")).toBeInTheDocument();
    expect(sessionStorage.getItem(SESSION_API_KEY_STORAGE_KEY)).toBeNull();
  });
});
