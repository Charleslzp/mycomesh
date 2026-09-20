import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, constants, existsSync, fchmodSync, fsyncSync, fstatSync, lstatSync, mkdirSync,
  openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const SCHEMA = 'mycomesh.consumer.request-journal.v1';
const HASH = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const MAX_REQUEST_BYTES = 16 * 1024 * 1024;
const SAFE_HEADERS = new Set(['content-type', 'x-request-id', 'x-mycomesh-request-id', 'x-mycomesh-session-id',
  'x-mycomesh-content-verification', 'x-mycomesh-history-status', 'x-should-retry']);
const PAYMENT_FIELDS = new Set(['payment-response', 'payment_response', 'payment_v7', 'payment_v8', 'payment_v9', 'payment_v10',
  'mycomesh_v7_settlement', 'mycomesh_v8_settlement', 'mycomesh_v9_settlement', 'mycomesh_v10_settlement', 'settlement_v10',
  'signed_receipt', 'relay_dispatch', 'key_signature', 'provider_signature', 'relay_signature', 'authorization',
  'api_key', 'payment_key', 'private_key', 'signature']);
const SECRET_VALUE = /myco_(?:sk|local|share)_[a-z0-9_-]+|\bbearer\s+\S+/i;
const sha256 = value => createHash('sha256').update(value).digest('hex');

export class RequestJournalError extends Error {
  constructor(code, message, requestId) {
    super(message); this.name = 'RequestJournalError'; this.code = code; this.statusCode = 422;
    this.requestId = requestId; this.retryable = false;
  }
}

function canonical(value, ancestors = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (!value || typeof value !== 'object' || ancestors.has(value)) throw new TypeError('journal input must be finite canonical JSON');
  if (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('journal input must be plain JSON');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) return '[' + Array.from(value, item => canonical(item, ancestors)).join(',') + ']';
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key], ancestors)).join(',') + '}';
  } finally { ancestors.delete(value); }
}

/** Hash only; the original request (including its prompt) is never persisted. */
export function requestPayloadHash(value) {
  const encoded = canonical(value);
  if (Buffer.byteLength(encoded) > MAX_REQUEST_BYTES) throw new RequestJournalError('request_too_large', 'Request exceeds the idempotency journal size bound');
  return '0x' + sha256(encoded);
}

function syncDirectory(path) {
  const fd = openSync(path, constants.O_RDONLY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function privateDirectory(path) {
  if (existsSync(path) && !lstatSync(path).isDirectory()) throw new Error('request journal must use regular directories');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  if (!lstatSync(path).isDirectory()) throw new Error('request journal directory changed');
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try { fchmodSync(fd, 0o700); } finally { closeSync(fd); }
}
function writeAll(fd, bytes) {
  fchmodSync(fd, 0o600);
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (!written) throw new Error('incomplete request journal write');
    offset += written;
  }
  fsyncSync(fd);
}
function cleanValue(value) {
  if (typeof value === 'string') {
    if (SECRET_VALUE.test(value)) throw new RequestJournalError('unsafe_cached_response', 'Response contains credential-like text; it cannot be cached');
    return value;
  }
  if (Array.isArray(value)) return value.map(cleanValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !PAYMENT_FIELDS.has(key.toLowerCase())).map(([key, item]) => [key, cleanValue(item)]));
  return value;
}
/** Cache API output only, excluding payment proofs and top-level echoed input. */
export function protectedCachedResult(result) {
  if (!result || !Number.isInteger(result.status) || result.status < 100 || result.status > 599) throw new TypeError('invalid cached HTTP status');
  canonical(result.payload); // Validate before traversing; rejects cycles/non-JSON.
  const payload = cleanValue(result.payload);
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    for (const key of ['input', 'messages', 'prompt', 'instructions', 'system_prompt', 'metadata']) delete payload[key];
  }
  const headers = Object.fromEntries(Object.entries(result.headers || {}).flatMap(([key, value]) => {
    const name = key.toLowerCase();
    if (!SAFE_HEADERS.has(name)) return [];
    if (typeof value !== 'string' || value.length > 2048 || /[\r\n]/.test(value) || SECRET_VALUE.test(value)) throw new TypeError('invalid cached response header');
    return [[name, value]];
  }));
  return { status: result.status, headers, payload };
}

/**
 * A permanent per-key O_EXCL claim is the execution fence. No TTL or stale-lock
 * recovery ever removes a claim. Missing/corrupt state fails closed. Filesystem
 * loss is outside this guarantee: retain this directory across restarts.
 */
export class ConsumerRequestJournal {
  constructor({ directory, chainId, contract, paymentKeyAddress, maxResponseBytes = 8 * 1024 * 1024 }) {
    if (!directory || !Number.isSafeInteger(chainId) || chainId <= 0 || !ADDRESS.test(contract || '') || !ADDRESS.test(paymentKeyAddress || '')) throw new TypeError('invalid request journal scope');
    if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 16 * 1024 * 1024) throw new TypeError('invalid response size bound');
    this.scopeHash = sha256(canonical({ chainId, contract: contract.toLowerCase(), paymentKeyAddress: paymentKeyAddress.toLowerCase() }));
    this.root = resolve(directory); this.directory = join(this.root, this.scopeHash); this.maxResponseBytes = maxResponseBytes;
    privateDirectory(this.root); privateDirectory(this.directory); syncDirectory(this.root); syncDirectory(dirname(this.root));
  }

  _path(entryKey) {
    if (typeof entryKey !== 'string' || !/^[0-9a-f]{64}$/.test(entryKey)) throw new TypeError('invalid journal entry key');
    return join(this.directory, entryKey + '.json');
  }
  _read(entryKey) {
    let fd;
    try {
      fd = openSync(this._path(entryKey), constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
      const info = fstatSync(fd);
      if (!info.isFile() || info.size > this.maxResponseBytes + 16384 || (info.mode & 0o077)) throw new Error('invalid journal file');
      const value = JSON.parse(readFileSync(fd, 'utf8'));
      if (value.schema !== SCHEMA || value.scope_hash !== this.scopeHash || value.key_hash !== entryKey
          || !HASH.test(value.request_id || '') || !HASH.test(value.payload_hash || '') || !/^[0-9a-f]{64}$/.test(value.owner_hash || '')
          || !['in_progress', 'complete', 'outcome_unknown'].includes(value.phase)) throw new Error('invalid journal record');
      if (value.phase === 'complete' && (!value.result || value.result_hash !== sha256(canonical(value.result)))) throw new Error('invalid cached result');
      return value;
    } catch {
      throw new RequestJournalError('idempotency_state_unknown', 'Existing idempotency state is unavailable or incomplete; do not execute again');
    } finally { if (fd !== undefined) closeSync(fd); }
  }

  claim({ idempotencyKey, payloadHash }) {
    if (typeof idempotencyKey !== 'string' || !idempotencyKey.trim() || Buffer.byteLength(idempotencyKey) > 1024 || /[\u0000-\u001f\u007f]/.test(idempotencyKey)) throw new RequestJournalError('invalid_idempotency_key', 'Idempotency-Key must be nonempty and at most 1024 bytes');
    if (!HASH.test(payloadHash || '')) throw new TypeError('payloadHash must be a canonical SHA-256 value');
    const entryKey = sha256(idempotencyKey), path = this._path(entryKey);
    const requestId = '0x' + randomBytes(32).toString('hex'), claimToken = randomBytes(32).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    const record = { schema: SCHEMA, scope_hash: this.scopeHash, key_hash: entryKey, payload_hash: payloadHash,
      request_id: requestId, owner_hash: sha256(claimToken), phase: 'in_progress', created_at: now, updated_at: now };
    let fd;
    try {
      fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const existing = this._read(entryKey);
      if (existing.payload_hash !== payloadHash) throw new RequestJournalError('idempotency_conflict', 'Idempotency-Key was already bound to different request content', existing.request_id);
      if (existing.phase === 'complete') return { action: 'replay', requestId: existing.request_id, result: existing.result };
      throw new RequestJournalError('idempotency_outcome_unknown', 'This request is in progress or has an unknown outcome; automatic execution is forbidden', existing.request_id);
    }
    try {
      writeAll(fd, Buffer.from(canonical(record))); syncDirectory(this.directory);
    } finally { closeSync(fd); } // Never remove an incomplete exclusive claim.
    return { action: 'execute', requestId, claimToken, entryKey };
  }

  _update(claim, update) {
    if (!claim || !/^[0-9a-f]{64}$/.test(claim.claimToken || '') || !HASH.test(claim.requestId || '')) throw new TypeError('invalid execution claim');
    const path = this._path(claim.entryKey), lockPath = path + '.update-lock';
    let lock;
    try { lock = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600); }
    catch { throw new RequestJournalError('idempotency_update_locked', 'Request journal update is unavailable; retain the original execution fence', claim.requestId); }
    let temporary;
    try {
      const record = this._read(claim.entryKey);
      if (record.request_id !== claim.requestId || !timingSafeEqual(Buffer.from(record.owner_hash, 'hex'), Buffer.from(sha256(claim.claimToken), 'hex'))) throw new RequestJournalError('idempotency_claim_mismatch', 'This process does not own the execution claim', record.request_id);
      const next = update(record);
      if (next === record) return;
      temporary = path + '.' + randomBytes(12).toString('hex') + '.tmp';
      const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
      try { writeAll(fd, Buffer.from(canonical(next))); } finally { closeSync(fd); }
      renameSync(temporary, path); temporary = null; syncDirectory(this.directory);
    } finally {
      if (temporary) { try { unlinkSync(temporary); } catch {} }
      closeSync(lock); unlinkSync(lockPath); syncDirectory(this.directory);
    }
  }

  complete(claim, result) {
    const cleaned = protectedCachedResult(result), encoded = canonical(cleaned);
    if (Buffer.byteLength(encoded) > this.maxResponseBytes) throw new RequestJournalError('cached_response_too_large', 'Response exceeds the protected cache bound; the execution remains fenced', claim?.requestId);
    this._update(claim, record => {
      if (record.phase === 'complete') {
        if (record.result_hash !== sha256(encoded)) throw new RequestJournalError('idempotency_completion_conflict', 'A completed response cannot be replaced', record.request_id);
        return record;
      }
      return { ...record, phase: 'complete', updated_at: Math.floor(Date.now() / 1000), result: cleaned, result_hash: sha256(encoded) };
    });
    return cleaned;
  }
  markOutcomeUnknown(claim) {
    this._update(claim, record => record.phase === 'complete' ? record : { ...record, phase: 'outcome_unknown', updated_at: Math.floor(Date.now() / 1000) });
  }
}
