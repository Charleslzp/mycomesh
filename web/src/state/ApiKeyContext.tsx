import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type PropsWithChildren,
} from "react";

export const SESSION_API_KEY_STORAGE_KEY = "mycomesh.session-api-key.v1";

export interface SessionApiCredential {
  apiKey: string;
  wallet?: string;
  fingerprint?: string;
  baseUrl?: string;
  createdAt: number;
}

export type ApiKeyPersistence = "session" | "memory";

export interface ApiKeyContextValue {
  apiKey: string | null;
  credential: SessionApiCredential | null;
  hasApiKey: boolean;
  persistence: ApiKeyPersistence;
  setApiKey: (
    apiKey: string,
    metadata?: Omit<Partial<SessionApiCredential>, "apiKey" | "createdAt">,
  ) => void;
  setCredential: (credential: SessionApiCredential) => void;
  clearApiKey: () => void;
}

const ApiKeyContext = createContext<ApiKeyContextValue | null>(null);

function browserSessionStorage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function validCredential(value: unknown): value is SessionApiCredential {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<SessionApiCredential>;
  return (
    typeof record.apiKey === "string" &&
    record.apiKey.trim().length >= 16 &&
    record.apiKey.length <= 512 &&
    Number.isSafeInteger(record.createdAt) &&
    Number(record.createdAt) > 0 &&
    (record.wallet === undefined || typeof record.wallet === "string") &&
    (record.fingerprint === undefined || typeof record.fingerprint === "string") &&
    (record.baseUrl === undefined || typeof record.baseUrl === "string")
  );
}

export function readSessionApiCredential(): SessionApiCredential | null {
  const storage = browserSessionStorage();
  if (!storage) return null;
  try {
    const raw = storage.getItem(SESSION_API_KEY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;
    if (validCredential(parsed)) return parsed;
    storage.removeItem(SESSION_API_KEY_STORAGE_KEY);
  } catch {
    // A blocked or corrupt session store falls back to memory for this tab.
  }
  return null;
}

function persistCredential(credential: SessionApiCredential | null): boolean {
  const storage = browserSessionStorage();
  if (!storage) return false;
  try {
    if (credential) storage.setItem(SESSION_API_KEY_STORAGE_KEY, JSON.stringify(credential));
    else storage.removeItem(SESSION_API_KEY_STORAGE_KEY);
    return true;
  } catch {
    return false;
  }
}

export function ApiKeyProvider({ children }: PropsWithChildren) {
  const [credential, setCredentialState] = useState<SessionApiCredential | null>(() =>
    readSessionApiCredential(),
  );
  const [persistence, setPersistence] = useState<ApiKeyPersistence>(() =>
    browserSessionStorage() ? "session" : "memory",
  );

  const setCredential = useCallback((next: SessionApiCredential) => {
    if (!validCredential(next)) throw new Error("Invalid session API credential.");
    setPersistence(persistCredential(next) ? "session" : "memory");
    setCredentialState(next);
  }, []);

  const setApiKey = useCallback<ApiKeyContextValue["setApiKey"]>(
    (apiKey, metadata = {}) => {
      const next: SessionApiCredential = {
        apiKey: apiKey.trim(),
        ...metadata,
        createdAt: Date.now(),
      };
      if (!validCredential(next)) throw new Error("API key is empty or invalid.");
      setPersistence(persistCredential(next) ? "session" : "memory");
      setCredentialState(next);
    },
    [],
  );

  const clearApiKey = useCallback(() => {
    setPersistence(persistCredential(null) ? "session" : "memory");
    setCredentialState(null);
  }, []);

  const value = useMemo<ApiKeyContextValue>(
    () => ({
      apiKey: credential?.apiKey ?? null,
      credential,
      hasApiKey: Boolean(credential),
      persistence,
      setApiKey,
      setCredential,
      clearApiKey,
    }),
    [credential, persistence, setApiKey, setCredential, clearApiKey],
  );

  return <ApiKeyContext.Provider value={value}>{children}</ApiKeyContext.Provider>;
}

export function useApiKey(): ApiKeyContextValue {
  const context = useContext(ApiKeyContext);
  if (!context) throw new Error("useApiKey must be used inside ApiKeyProvider.");
  return context;
}
