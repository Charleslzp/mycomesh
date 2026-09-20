import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const SCHEMA = "mycomesh.consumer.history.v1";
const MAX_LINE_BYTES = 16 * 1024;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const BYTES32 = /^0x[0-9a-f]{64}$/i;
const SECRET = /myco_(?:sk|local|share)_[a-z0-9_-]+|\bbearer\s+\S+|0x[0-9a-f]{128,}/i;
const V9_TERMINAL = new Set(["released", "refunded", "dismissed", "timed_out"]);
const STATUSES = new Set(["dispatching", "outcome_unknown", "not_dispatched", "queued", "pending", "submitted", "broadcast_unknown", "confirmed", "failed", "rejected", "escrowed", "disputed", ...V9_TERMINAL]);
const NUMERIC_FIELDS = ["input_tokens", "output_tokens", "actual_fee_units", "updated_at", "confirmed_at", "block_number", "confirmations", "authorization_deadline"];

function address(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)) throw new TypeError(`invalid ${label}`);
  return value.toLowerCase();
}

function number(value) {
  if (typeof value === "boolean" || value === null || value === "" || value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function text(value, maximum = 256) {
  if (typeof value !== "string" || value.length > maximum || SECRET.test(value) || /[\u0000-\u001f]/.test(value)) return undefined;
  return value;
}

function publicUrl(value) {
  const raw = text(value, 2048);
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.search || url.hash) return undefined;
    return raw;
  } catch {
    return undefined;
  }
}

const recordKey = record => `${record.capacity_channel_id || ""}:${record.request_id}`;

function stable(record) {
  return JSON.stringify(Object.fromEntries(Object.keys(record).sort().map((key) => [key, record[key]])));
}

function privateDirectory(path) {
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error("history directory must not be a symbolic link");
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function appendPrivate(path, entry) {
  const directory = dirname(path);
  if (!existsSync(directory)) privateDirectory(directory);
  else if (!lstatSync(directory).isDirectory()) throw new Error("history parent must be a regular non-symlink directory");
  // A single O_APPEND write keeps concurrent writers from sharing a seek offset.
  // Readers also deduplicate: repeated imports by two processes are harmless.
  const fd = openSync(path, constants.O_RDWR | constants.O_CREAT | constants.O_APPEND | (constants.O_NOFOLLOW || 0), 0o600);
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new Error("history must be a regular file");
    fchmodSync(fd, 0o600);
    let prefix = "";
    if (info.size) {
      const last = Buffer.alloc(1);
      readSync(fd, last, 0, 1, info.size - 1);
      if (last[0] !== 10) prefix = "\n";
    }
    const line = Buffer.from(`${prefix}${JSON.stringify(entry)}\n`, "utf8");
    if (writeSync(fd, line) !== line.length) throw new Error("incomplete history append");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function merge(previous, next) {
  if (!previous) return next;
  let winner;
  if (V9_TERMINAL.has(previous.status) && !V9_TERMINAL.has(next.status)) winner = previous;
  else if (V9_TERMINAL.has(next.status) && !V9_TERMINAL.has(previous.status)) winner = next;
  else if (["escrowed", "disputed"].includes(previous.status) && ["dispatching", "outcome_unknown", "not_dispatched", "queued", "pending", "submitted", "broadcast_unknown", "failed", "rejected"].includes(next.status)) winner = previous;
  else if (["escrowed", "disputed"].includes(next.status) && ["dispatching", "outcome_unknown", "not_dispatched", "queued", "pending", "submitted", "broadcast_unknown", "failed", "rejected"].includes(previous.status)) winner = next;
  else if (previous.status === "confirmed" && next.status !== "confirmed") winner = previous;
  else if (next.status === "confirmed" && previous.status !== "confirmed") winner = next;
  else if (["failed", "rejected"].includes(previous.status) && !["failed", "rejected"].includes(next.status)) winner = previous;
  else if (["failed", "rejected"].includes(next.status) && !["failed", "rejected"].includes(previous.status)) winner = next;
  else {
    const previousTime = previous.updated_at ?? previous.timestamp;
    const nextTime = next.updated_at ?? next.timestamp;
    winner = nextTime >= previousTime ? next : previous;
  }
  const other = winner === next ? previous : next;
  const result = { ...other, ...winner, accepted: previous.accepted || next.accepted || winner.status === "confirmed" };
  // Never discard locally verified token detail merely because a chain-only
  // status update has no token enrichment yet.
  for (const name of ["input_tokens", "output_tokens"]) {
    if (result[name] == null && other[name] != null) result[name] = other[name];
  }
  const timestamps = [previous.timestamp, next.timestamp].filter((value) => value > 0);
  if (timestamps.length) result.timestamp = Math.min(...timestamps);
  if (previous.confirmations !== undefined || next.confirmations !== undefined) {
    result.confirmations = Math.max(previous.confirmations || 0, next.confirmations || 0);
  }
  return result;
}

/**
 * Same-device metadata journal, partitioned by chain + contract + payment key.
 * This class never grants API or dashboard access: the caller's wallet gate
 * must still guard history presentation and any chain-confirmation sync.
 * Only localPath and this exact shared scope are read; no directory scanning.
 */
export class ConsumerHistoryLedger {
  constructor({ localPath, sharedDir, chainId, contract, keyAddress }) {
    if (typeof localPath !== "string" || !localPath) throw new TypeError("localPath is required");
    this.chainId = number(chainId);
    if (!this.chainId) throw new TypeError("invalid chainId");
    this.contract = address(contract, "contract");
    this.keyAddress = address(keyAddress, "keyAddress");
    this.localPath = resolve(localPath);
    this.sharedDir = resolve(sharedDir || process.env.MYCOMESH_CONSUMER_HISTORY_DIR || join(homedir(), ".mycomesh", "consumer-history"));
    this.scopeDirectory = join(this.sharedDir, String(this.chainId), this.contract, this.keyAddress);
    this.sharedPath = join(this.scopeDirectory, "receipts.jsonl");
    this.lastDiagnostics = { skippedLocalLines: 0, skippedSharedLines: 0, importedEntries: 0 };
  }

  normalize(raw, origin) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
    const requestId = typeof raw.request_id === "string" ? raw.request_id.toLowerCase() : "";
    if (!BYTES32.test(requestId)) return null;
    const claims = [raw.key_address, raw.payment_key_address, raw.key].filter((value) => value !== undefined);
    if (claims.some((value) => typeof value !== "string" || !ADDRESS.test(value) || value.toLowerCase() !== this.keyAddress)) return null;
    if (raw.chain_id !== undefined && number(raw.chain_id) !== this.chainId) return null;
    for (const claimed of [raw.settlement_contract, raw.contract]) {
      if (claimed !== undefined && (typeof claimed !== "string" || !ADDRESS.test(claimed) || claimed.toLowerCase() !== this.contract)) return null;
    }
    const settlementKey = typeof raw.settlement_key === "string" ? raw.settlement_key.toLowerCase() : "";
    const legacyScope = /^v[89]:(0x[0-9a-f]{40}):(0x[0-9a-f]{64})$/.exec(settlementKey);
    if (legacyScope && (legacyScope[1] !== this.keyAddress || legacyScope[2] !== requestId)) return null;
    if (settlementKey && !legacyScope && !BYTES32.test(settlementKey)) return null;
    if (origin === "local" && !claims.length && !legacyScope) return null;
    if (origin === "shared" && (!claims.length || raw.chain_id === undefined || raw.settlement_contract === undefined)) return null;
    if (raw.capacity_channel_id !== undefined && (typeof raw.capacity_channel_id !== "string" || !BYTES32.test(raw.capacity_channel_id))) return null;
    const status = STATUSES.has(raw.status) ? raw.status : "pending";
    const record = {
      schema: SCHEMA,
      chain_id: this.chainId,
      settlement_contract: this.contract,
      key_address: this.keyAddress,
      request_id: requestId,
      settlement_key: settlementKey || `v8:${this.keyAddress}:${requestId}`,
      timestamp: number(raw.timestamp) ?? (origin === "append" ? Math.floor(Date.now() / 1000) : 0),
      status,
      accepted: raw.accepted === true || status === "confirmed",
      source: text(raw.source, 80) || (origin === "local" && raw.schema !== SCHEMA ? "legacy-local" : "consumer"),
    };
    if (raw.capacity_channel_id) record.capacity_channel_id = raw.capacity_channel_id.toLowerCase();
    if (["provider-signed", "receipt-only", "failed"].includes(raw.content_verification)) record.content_verification = raw.content_verification;
    for (const name of ["owner", "provider", "provider_signer", "relay"]) {
      if (typeof raw[name] === "string" && ADDRESS.test(raw[name])) record[name] = raw[name].toLowerCase();
    }
    if (typeof raw.response_hash === "string" && BYTES32.test(raw.response_hash)) record.response_hash = raw.response_hash.toLowerCase();
    if (typeof raw.request_hash === "string" && BYTES32.test(raw.request_hash)) record.request_hash = raw.request_hash.toLowerCase();
    if (number(raw.max_fee_units) !== undefined) record.max_fee_units = number(raw.max_fee_units);
    for (const name of ["endpoint", "model", "route_model", "session_id", "error_code"]) {
      const value = text(raw[name]);
      if (value !== undefined) record[name] = value;
    }
    const relayUrl = publicUrl(raw.relay_url);
    if (relayUrl) record.relay_url = relayUrl;
    const txHash = raw.tx_hash ?? raw.transaction_hash;
    if (typeof txHash === "string" && BYTES32.test(txHash)) record.tx_hash = txHash.toLowerCase();
    for (const name of NUMERIC_FIELDS) {
      const value = number(raw[name]);
      if (value !== undefined) record[name] = value;
    }
    if (record.actual_fee_units === undefined && number(raw.actual_fee) !== undefined) record.actual_fee_units = number(raw.actual_fee);
    // All unknown fields (including prompts, payloads, private keys, API keys,
    // signatures and nested authorizations) are deliberately not copied.
    return record;
  }

  read(path, origin) {
    if (!existsSync(path)) return [];
    if (!lstatSync(path).isFile()) throw new Error("history must be a regular non-symlink file");
    const rows = [];
    for (const line of readFileSync(path, "utf8").split("\n")) {
      if (!line.trim()) continue;
      let record;
      try {
        record = Buffer.byteLength(line, "utf8") <= MAX_LINE_BYTES ? this.normalize(JSON.parse(line), origin) : null;
      } catch {
        record = null;
      }
      if (record) rows.push(record);
      else this.lastDiagnostics[origin === "local" ? "skippedLocalLines" : "skippedSharedLines"] += 1;
    }
    return rows;
  }

  prepareShared() {
    privateDirectory(this.sharedDir);
    privateDirectory(join(this.sharedDir, String(this.chainId)));
    privateDirectory(join(this.sharedDir, String(this.chainId), this.contract));
    privateDirectory(this.scopeDirectory);
  }

  history(limit = 100) {
    if (!Number.isSafeInteger(limit)) throw new TypeError("history limit must be an integer");
    this.lastDiagnostics = { skippedLocalLines: 0, skippedSharedLines: 0, importedEntries: 0 };
    const shared = new Map();
    for (const record of this.read(this.sharedPath, "shared")) shared.set(recordKey(record), merge(shared.get(recordKey(record)), record));
    const local = new Map();
    for (const record of this.read(this.localPath, "local")) local.set(recordKey(record), merge(local.get(recordKey(record)), record));
    const merged = new Map(shared);
    for (const record of local.values()) {
      const next = merge(shared.get(recordKey(record)), record);
      merged.set(recordKey(record), next);
      if (!shared.has(recordKey(record)) || stable(next) !== stable(shared.get(recordKey(record)))) {
        this.prepareShared();
        appendPrivate(this.sharedPath, next);
        this.lastDiagnostics.importedEntries += 1;
      }
    }
    const rows = [...merged.values()].sort((left, right) => right.timestamp - left.timestamp || left.request_id.localeCompare(right.request_id));
    return limit <= 0 ? rows : rows.slice(0, Math.min(limit, 500));
  }

  append(entry) {
    const record = this.normalize(entry, "append");
    if (!record) throw new TypeError("history entry has an invalid request ID or conflicting scope");
    const bytes = Buffer.byteLength(JSON.stringify(record), "utf8");
    if (bytes > MAX_LINE_BYTES) throw new TypeError("history entry is too large");
    this.prepareShared();
    appendPrivate(this.localPath, record);
    if (this.sharedPath !== this.localPath) appendPrivate(this.sharedPath, record);
    return record;
  }
}

export { ConsumerHistoryLedger as ConsumerHistory };
