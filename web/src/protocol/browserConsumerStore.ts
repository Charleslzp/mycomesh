import {
  browserConsumerIdentityFromWebCryptoKey,
  type BrowserConsumerSigningIdentity,
  generateBrowserWebCryptoConsumerIdentity,
} from "./browserConsumerIdentity";

const DATABASE_NAME = "mycomesh-browser-consumer-v1";
const DATABASE_VERSION = 2;
const STORE_NAME = "identity";
const ACTIVE_IDENTITY_KEY = "active";
const STORED_IDENTITY_SCHEMA = "mycomesh.browser-consumer.identity.v2";

interface StoredBrowserConsumerIdentity {
  schema: typeof STORED_IDENTITY_SCHEMA;
  public_key: string;
  peer_id: string;
  signing_key: CryptoKey;
}

interface BrowserConsumerIdentityStorage {
  read(): Promise<unknown>;
  add(value: StoredBrowserConsumerIdentity): Promise<void>;
  delete(): Promise<void>;
}

export class BrowserConsumerStoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BrowserConsumerStoreError";
  }
}

export async function getOrCreateBrowserConsumerIdentity(): Promise<BrowserConsumerSigningIdentity> {
  const database = await openIdentityDatabase();
  try {
    return await getOrCreateWithStorage(indexedDbStorage(database));
  } finally {
    database.close();
  }
}

export async function deleteBrowserConsumerIdentity(): Promise<void> {
  const database = await openIdentityDatabase();
  try {
    await indexedDbStorage(database).delete();
  } finally {
    database.close();
  }
}

/** Test hook for exercising persistence without replacing the browser IndexedDB implementation. */
export async function getOrCreateBrowserConsumerIdentityWithStorageForTest(
  storage: BrowserConsumerIdentityStorage,
): Promise<BrowserConsumerSigningIdentity> {
  return getOrCreateWithStorage(storage);
}

async function getOrCreateWithStorage(
  storage: BrowserConsumerIdentityStorage,
): Promise<BrowserConsumerSigningIdentity> {
  const stored = await storage.read();
  if (stored !== undefined) {
    try {
      return await identityFromStoredRecord(stored);
    } catch {
      try {
        await storage.delete();
      } catch (deleteError) {
        throw new BrowserConsumerStoreError(
          "Stored browser Consumer identity is invalid and could not be removed",
          { cause: deleteError },
        );
      }
    }
  }

  let generated: Awaited<ReturnType<typeof generateBrowserWebCryptoConsumerIdentity>>;
  try {
    generated = await generateBrowserWebCryptoConsumerIdentity();
  } catch (error) {
    throw new BrowserConsumerStoreError(
      "Failed to create a non-extractable browser Consumer identity",
      { cause: error },
    );
  }
  const record: StoredBrowserConsumerIdentity = {
    schema: STORED_IDENTITY_SCHEMA,
    public_key: generated.identity.publicKey,
    peer_id: generated.identity.peerId,
    signing_key: generated.signingKey,
  };
  try {
    await storage.add(record);
    return generated.identity;
  } catch (error) {
    if (!isConstraintError(error)) {
      throw new BrowserConsumerStoreError(
        "Failed to persist the non-extractable browser Consumer identity",
        { cause: error },
      );
    }
  }

  // Another tab won the add-only race. Its key is canonical for this origin.
  const winner = await storage.read();
  if (winner === undefined) {
    throw new BrowserConsumerStoreError(
      "Browser Consumer identity creation raced but no stored identity remains",
    );
  }
  return identityFromStoredRecord(winner);
}

async function identityFromStoredRecord(value: unknown): Promise<BrowserConsumerSigningIdentity> {
  if (!isPlainObject(value)) {
    throw new BrowserConsumerStoreError("Stored browser Consumer identity is malformed");
  }
  const expectedFields = new Set(["schema", "public_key", "peer_id", "signing_key"]);
  if (
    value.schema !== STORED_IDENTITY_SCHEMA
    || Object.keys(value).some((field) => !expectedFields.has(field))
    || Object.keys(value).length !== expectedFields.size
    || typeof value.public_key !== "string"
    || typeof value.peer_id !== "string"
  ) {
    throw new BrowserConsumerStoreError(
      "Stored browser Consumer identity does not use the non-extractable key schema",
    );
  }
  let identity: BrowserConsumerSigningIdentity;
  try {
    identity = await browserConsumerIdentityFromWebCryptoKey(
      value.signing_key as CryptoKey,
      value.public_key,
    );
  } catch (error) {
    throw new BrowserConsumerStoreError(
      "Stored browser Consumer identity failed its non-extractable key consistency check",
      { cause: error },
    );
  }
  if (identity.peerId !== value.peer_id) {
    throw new BrowserConsumerStoreError(
      "Stored browser Consumer peer ID does not match its public key",
    );
  }
  return identity;
}

function indexedDbStorage(database: IDBDatabase): BrowserConsumerIdentityStorage {
  return {
    read: () => new Promise<unknown>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(ACTIVE_IDENTITY_KEY);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new BrowserConsumerStoreError(
        "Failed to read the browser Consumer identity",
        { cause: request.error },
      ));
      transaction.onabort = () => reject(new BrowserConsumerStoreError(
        "Browser Consumer identity read was aborted",
        { cause: transaction.error },
      ));
    }),
    add: (value) => new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).add(value, ACTIVE_IDENTITY_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(
        transaction.error ?? new BrowserConsumerStoreError(
          "Browser Consumer identity write failed",
        ),
      );
      transaction.onabort = transaction.onerror;
    }),
    delete: () => new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).delete(ACTIVE_IDENTITY_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new BrowserConsumerStoreError(
        "Failed to delete the browser Consumer identity",
        { cause: transaction.error },
      ));
      transaction.onabort = transaction.onerror;
    }),
  };
}

function openIdentityDatabase(): Promise<IDBDatabase> {
  if (!globalThis.indexedDB) {
    return Promise.reject(
      new BrowserConsumerStoreError(
        "IndexedDB is unavailable; local Consumer identity cannot be persisted",
      ),
    );
  }
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = globalThis.indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    let blocked = false;
    request.onupgradeneeded = (event) => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME);
      } else if ((event as IDBVersionChangeEvent).oldVersion < DATABASE_VERSION) {
        // Version 1 stored an extractable private-key string. It must never survive migration.
        request.transaction?.objectStore(STORE_NAME).clear();
      }
    };
    request.onsuccess = () => {
      const database = request.result;
      if (blocked) {
        database.close();
        return;
      }
      database.onversionchange = () => database.close();
      resolve(database);
    };
    request.onerror = () => reject(
      new BrowserConsumerStoreError("Failed to open local Consumer identity storage", {
        cause: request.error,
      }),
    );
    request.onblocked = () => {
      blocked = true;
      reject(new BrowserConsumerStoreError(
        "Local Consumer identity migration is blocked by another tab; reload the other tab",
      ));
    };
  });
}

function isConstraintError(value: unknown): boolean {
  return value instanceof DOMException
    ? value.name === "ConstraintError"
    : isPlainObject(value) && value.name === "ConstraintError";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
