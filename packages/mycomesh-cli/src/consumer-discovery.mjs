import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { BlockList, isIP } from "node:net";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";

export const RELAY_ADMISSION_SCHEMA = "mycomesh.relay-admission.v1";
export const RELAY_ANNOUNCEMENT_SCHEMA = "mycomesh.relay-announcement.v1";
export const RELAY_DIRECTORY_SCHEMA = "mycomesh.relay-directory.v1";
const CACHE_SCHEMA = "mycomesh.relay-discovery-cache.v1";
const MAX_RECORDS = 64;
const MAX_DIRECTORY_BYTES = 1024 * 1024;
const MAX_ANNOUNCEMENT_BYTES = 16 * 1024;
const BINDINGS = ["network_id", "channel_id", "chain_id", "settlement_contract", "protocol_version",
  "host", "provider_port", "public_url", "provider_tls", "payment_address", "attestation_address"];
const fileRevision = (stat) => `${stat.dev}:${stat.ino}:${stat.mtimeNs}:${stat.size}`;

const privateAddresses = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["192.88.99.0", 24], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 3],
]) privateAddresses.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [["2001::", 23], ["2001:db8::", 32], ["2002::", 16],
  ["3fff::", 20], ["3ffe::", 16]]) privateAddresses.addSubnet(address, prefix, "ipv6");
const publicV6 = new BlockList();
publicV6.addSubnet("2000::", 3, "ipv6");

export function isPublicDiscoveryAddress(address) {
  const family = isIP(address);
  return family === 4 ? !privateAddresses.check(address, "ipv4")
    : family === 6 && publicV6.check(address, "ipv6") && !privateAddresses.check(address, "ipv6");
}

function loopback(address) {
  return address === "::1" || (isIP(address) === 4 && address.startsWith("127."));
}

export function discoveryUrl(value, { local = false, bridge = false } = {}) {
  if (typeof value !== "string" || value.length > 512 || /[^\x21-\x7e]|\\/.test(value)) throw new Error("Invalid discovery URL");
  const match = /^(https?):\/\/(\[[^\]]+\]|[^/:]+)(?::([0-9]+))?$/.exec(value);
  if (!match) throw new Error("Invalid discovery URL origin");
  const url = new URL(value);
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if ((url.protocol !== "https:" && !(local && loopback(hostname) && url.protocol === "http:"))
      || url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) {
    throw new Error("Discovery requires HTTPS origin URLs without credentials, query, or fragment");
  }
  if ((isIP(hostname) && (!(isPublicDiscoveryAddress(hostname) || (local && loopback(hostname)))
      || match[2] !== url.hostname)) || (!bridge && !isIP(hostname))) {
    throw new Error("Discovery endpoint is not public");
  }
  if (bridge && !isIP(hostname) && !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(match[2])) throw new Error("Invalid bootstrap hostname");
  if (url.port === "0") throw new Error("Invalid discovery port");
  if (value !== url.origin) throw new Error("Noncanonical discovery URL");
  return value;
}

function exactFields(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) {
    throw new Error(`Invalid ${label} fields`);
  }
}

function address(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{40}$/.test(value) || /^0x0{40}$/.test(value)) {
    throw new Error(`Invalid ${label}`);
  }
  return value;
}

function integer(value, label, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`Invalid ${label}`);
  return value;
}

export function discoveryCanonical(value, depth = 0) {
  if (depth > 12) throw new Error("Discovery JSON is too deeply nested");
  if (typeof value === "string") {
    if (/[^\x20-\x7e]/.test(value)) throw new Error("Discovery strings must be printable ASCII");
    return JSON.stringify(value);
  }
  if (typeof value === "number") return String(integer(value, "discovery integer"));
  if (typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => discoveryCanonical(item, depth + 1)).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort()
    .map((key) => `${discoveryCanonical(key, depth + 1)}:${discoveryCanonical(value[key], depth + 1)}`).join(",")}}`;
  throw new Error("Invalid discovery value");
}

export function discoveryDigest(schema, unsigned) {
  return keccak_256(Buffer.from(`${schema}\n${discoveryCanonical(unsigned)}`, "utf8"));
}

function recoverSigner(digest, value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{130}$/.test(value)) throw new Error("Invalid discovery signature encoding");
  const bytes = Buffer.from(value.slice(2), "hex");
  if (bytes[64] !== 27 && bytes[64] !== 28) throw new Error("Invalid discovery signature recovery");
  const signature = secp256k1.Signature.fromCompact(bytes.subarray(0, 64)).addRecoveryBit(bytes[64] - 27);
  if (signature.hasHighS()) throw new Error("Discovery signature must be low-s");
  const publicKey = signature.recoverPublicKey(digest).toRawBytes(false).subarray(1);
  return `0x${Buffer.from(keccak_256(publicKey).subarray(-20)).toString("hex")}`;
}

export function parseDiscoveryConfig(manifest, network) {
  if (manifest.relay_discovery === undefined) return null;
  const value = manifest.relay_discovery;
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).some((key) => !["authorities", "threshold", "refresh_seconds", "timeout_seconds"].includes(key))) {
    throw new Error("Invalid relay_discovery policy");
  }
  if (!Array.isArray(value.authorities) || !value.authorities.length || value.authorities.length > 16) throw new Error("Discovery authorities required");
  const authorities = value.authorities.map((item) => address(item, "discovery authority"));
  if (new Set(authorities).size !== authorities.length) throw new Error("Duplicate discovery authorities");
  const threshold = integer(value.threshold, "discovery threshold", Math.floor(authorities.length / 2) + 1, authorities.length);
  const refreshSeconds = integer(value.refresh_seconds ?? 30, "discovery refresh", 1, 120);
  const timeoutSeconds = integer(value.timeout_seconds ?? 3, "discovery timeout", 1, 10);
  for (const name of ["network_id", "channel_id"]) {
    if (typeof manifest[name] !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(manifest[name])) throw new Error(`Discovery requires ${name}`);
  }
  if (!["local", "testnet", "open"].includes(manifest.network_profile)) throw new Error("Invalid discovery network profile");
  const local = manifest.network_profile === "local";
  if (!Array.isArray(manifest.bridge_urls) || !manifest.bridge_urls.length || manifest.bridge_urls.length > 8) throw new Error("Discovery requires one to eight trusted Bridges");
  const bridgeUrls = manifest.bridge_urls.map((url) => discoveryUrl(url, { local, bridge: true }));
  if (new Set(bridgeUrls).size !== bridgeUrls.length) throw new Error("Duplicate discovery bootstrap Bridge");
  return { authorities, threshold, refreshMs: refreshSeconds * 1000, timeoutMs: timeoutSeconds * 1000,
    local, bridgeUrls, network_id: manifest.network_id, channel_id: manifest.channel_id,
    chain_id: integer(network.chain_id, "discovery chain", 1),
    settlement_contract: address(network.settlement_contract, "discovery settlement"),
    protocol_version: integer(network.protocol_version, "discovery protocol", 8, 10) };
}

function verifyBinding(record, config) {
  for (const key of ["network_id", "channel_id", "chain_id", "settlement_contract", "protocol_version"]) {
    if (record[key] !== config[key]) throw new Error(`Discovery ${key} mismatch`);
  }
  address(record.payment_address, "Relay payment address");
  address(record.attestation_address, "Relay attestation address");
  integer(record.provider_port, "Relay provider port", 1, 65535);
  if (typeof record.provider_tls !== "boolean" || (!config.local && !record.provider_tls)) throw new Error("Discovery Provider transport requires TLS");
  if (discoveryUrl(record.public_url, { local: config.local }) !== record.public_url) throw new Error("Noncanonical discovery URL");
  const host = new URL(record.public_url).hostname.replace(/^\[|\]$/g, "");
  if (record.host !== host) throw new Error("Relay host must match its public URL IP");
}

export function verifyRelayAnnouncement(record, config, { now = Math.floor(Date.now() / 1000), allowExpired = false } = {}) {
  exactFields(record, [...BINDINGS, "schema", "sequence", "issued_at", "expires_at", "admission", "signature"], "Relay announcement");
  if (record.schema !== RELAY_ANNOUNCEMENT_SCHEMA || Buffer.byteLength(discoveryCanonical(record)) > MAX_ANNOUNCEMENT_BYTES) throw new Error("Invalid Relay announcement schema or size");
  verifyBinding(record, config);
  integer(record.sequence, "Relay sequence", 1);
  integer(record.issued_at, "Relay issued_at");
  integer(record.expires_at, "Relay expires_at", 1);
  if (record.issued_at > now + 30 || record.expires_at <= record.issued_at || record.expires_at - record.issued_at > 300
      || (!allowExpired && record.expires_at <= now)) throw new Error("Relay announcement expired or invalid lifetime");
  const admission = record.admission;
  exactFields(admission, [...BINDINGS, "schema", "expires_at", "signatures"], "Relay admission");
  if (admission.schema !== RELAY_ADMISSION_SCHEMA) throw new Error("Invalid Relay admission schema");
  for (const key of BINDINGS) if (admission[key] !== record[key]) throw new Error("Relay admission binding mismatch");
  integer(admission.expires_at, "admission expiry", 1);
  if (admission.expires_at < record.expires_at || admission.expires_at > now + 366 * 86400
      || (!allowExpired && admission.expires_at <= now)) throw new Error("Relay admission expired or invalid lifetime");
  if (!Array.isArray(admission.signatures) || !admission.signatures.length || admission.signatures.length > 16) throw new Error("Invalid admission signatures");
  const { signatures, ...unsignedAdmission } = admission;
  const admissionDigest = discoveryDigest(RELAY_ADMISSION_SCHEMA, unsignedAdmission);
  const signers = new Set();
  for (const signed of signatures) {
    exactFields(signed, ["signer", "signature"], "admission signature");
    const signer = address(signed.signer, "admission signer");
    if (!config.authorities.includes(signer) || signers.has(signer)
        || recoverSigner(admissionDigest, signed.signature) !== signer) throw new Error("Invalid or untrusted admission signature");
    signers.add(signer);
  }
  if (signers.size < config.threshold) throw new Error("Relay admission threshold not met");
  const { signature, ...unsigned } = record;
  if (recoverSigner(discoveryDigest(RELAY_ANNOUNCEMENT_SCHEMA, unsigned), signature) !== record.attestation_address) {
    throw new Error("Relay announcement signature mismatch");
  }
  return JSON.parse(JSON.stringify(record));
}

async function fetchDiscoveryJson(url, { dispatcher, timeoutMs, maxBytes }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  try {
    const response = await fetch(url, { redirect: "error", headers: { accept: "application/json" }, dispatcher, signal: controller.signal });
    if (!response.ok) { await response.body?.cancel(); throw new Error(`Discovery HTTP ${response.status}`); }
    if (Number(response.headers.get("content-length")) > maxBytes) { await response.body?.cancel(); throw new Error("Discovery response exceeds size limit"); }
    let length = 0;
    const chunks = [];
    for await (const chunk of response.body || []) {
      length += chunk.byteLength;
      if (length > maxBytes) { controller.abort(); throw new Error("Discovery response exceeds size limit"); }
      chunks.push(Buffer.from(chunk));
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, length)));
  } finally { clearTimeout(timer); }
}

export class ConsumerRelayDiscovery {
  constructor({ config, cachePath, dispatcher, now = () => Math.floor(Date.now() / 1000) }) {
    this.config = config;
    this.cachePath = cachePath;
    this.dispatcher = dispatcher;
    this.now = now;
    this.records = new Map();
    this.refreshing = null;
    this.lastRefresh = -Infinity;
    this.lastError = null;
    if (cachePath && existsSync(cachePath)) {
      try {
        this.records = this.readCache();
      } catch (error) {
        // Corrupt or incompatible persistent anti-replay state cannot silently
        // become an empty cache and admit older signed announcements again.
        this.records.clear();
        this.lastError = `Discovery cache rejected: ${error.message}`;
        this.blocked = true;
      }
    }
  }

  readCache() {
    const records = new Map();
    if (!this.cachePath || !existsSync(this.cachePath)) return records;
    const descriptor = openSync(this.cachePath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    let cached, revision;
    try {
      const stat = fstatSync(descriptor, { bigint: true });
      if (!stat.isFile() || stat.size > BigInt(MAX_DIRECTORY_BYTES)) throw new Error("Invalid discovery cache file");
      revision = fileRevision(stat);
      cached = JSON.parse(readFileSync(descriptor, "utf8"));
    } finally { closeSync(descriptor); }
    exactFields(cached, ["schema", "records"], "discovery cache");
    if (cached.schema !== CACHE_SCHEMA || !Array.isArray(cached.records) || cached.records.length > MAX_RECORDS) throw new Error("Invalid discovery cache");
    for (const candidate of cached.records) {
      const record = verifyRelayAnnouncement(candidate, this.config, { now: this.now(), allowExpired: true });
      if (records.has(record.attestation_address)) throw new Error("Duplicate discovery cache identity");
      records.set(record.attestation_address, record);
    }
    this.cacheRevision = revision;
    return records;
  }

  persist() {
    if (!this.cachePath) return;
    const temporary = `${this.cachePath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      writeFileSync(temporary, JSON.stringify({ schema: CACHE_SCHEMA, records: [...this.records.values()] }), { flag: "wx", mode: 0o600 });
      const descriptor = openSync(temporary, "r");
      try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
      renameSync(temporary, this.cachePath);
      chmodSync(this.cachePath, 0o600);
      if (process.platform !== "win32") {
        const directory = openSync(dirname(this.cachePath), "r");
        try { fsyncSync(directory); } finally { closeSync(directory); }
      }
      this.cacheRevision = fileRevision(lstatSync(this.cachePath, { bigint: true }));
    } finally { try { unlinkSync(temporary); } catch {} }
  }

  accept(candidate) {
    if (this.blocked) throw new Error(this.lastError);
    const record = verifyRelayAnnouncement(candidate, this.config, { now: this.now() });
    let lock;
    if (this.cachePath) {
      try {
        lock = openSync(`${this.cachePath}.lock`, "wx", 0o600);
        writeFileSync(lock, String(process.pid));
      } catch (error) {
        if (lock !== undefined) { closeSync(lock); try { unlinkSync(`${this.cachePath}.lock`); } catch {} }
        throw new Error("Discovery cache is locked; cached routes and static fallbacks remain available");
      }
    }
    try {
      if (this.cachePath && existsSync(this.cachePath)
          && fileRevision(lstatSync(this.cachePath, { bigint: true })) !== this.cacheRevision) {
        const persisted = this.readCache();
        const merged = new Map(this.records);
        for (const [identity, latest] of persisted) {
          const previous = merged.get(identity);
          if (!previous || previous.sequence < latest.sequence) merged.set(identity, latest);
          else if (previous.sequence === latest.sequence && discoveryCanonical(previous) !== discoveryCanonical(latest)) throw new Error("Conflicting discovery cache identity");
        }
        if (merged.size > MAX_RECORDS) throw new Error("Relay discovery identity capacity reached");
        this.records = merged;
      }
      return this.acceptVerified(record);
    } finally {
      if (lock !== undefined) { closeSync(lock); unlinkSync(`${this.cachePath}.lock`); }
    }
  }

  acceptVerified(record) {
    const identity = record.attestation_address;
    const previous = this.records.get(identity);
    if (previous && (record.sequence < previous.sequence || (record.sequence === previous.sequence
        && discoveryCanonical(record) !== discoveryCanonical(previous)))) throw new Error("Relay announcement sequence rollback or equivocation");
    if (previous?.sequence === record.sequence) return previous;
    if (!previous && this.records.size >= MAX_RECORDS) throw new Error("Relay discovery identity capacity reached");
    this.records.set(identity, record);
    try { this.persist(); }
    catch (error) { if (previous) this.records.set(identity, previous); else this.records.delete(identity); throw error; }
    return record;
  }

  active() {
    const now = this.now();
    return [...this.records.values()].filter((record) => record.expires_at > now && record.admission.expires_at > now);
  }

  recordFor(url) {
    const matches = this.active().filter((record) => record.public_url === url);
    if (matches.length > 1) throw new Error("Conflicting Relay identities share one discovery endpoint");
    return matches[0] || null;
  }

  async refresh({ force = false } = {}) {
    if (this.blocked) return this.active();
    if (this.refreshing) return this.refreshing;
    if (!force && Date.now() - this.lastRefresh < this.config.refreshMs) return this.active();
    this.lastRefresh = Date.now();
    this.lastError = null;
    this.refreshing = (async () => {
      const results = await Promise.allSettled(this.config.bridgeUrls.map(async (url) => {
        const directory = await fetchDiscoveryJson(`${url}/relays`, { dispatcher: this.dispatcher,
          timeoutMs: this.config.timeoutMs, maxBytes: MAX_DIRECTORY_BYTES });
        if (directory?.schema !== RELAY_DIRECTORY_SCHEMA || !Array.isArray(directory.relays) || directory.relays.length > MAX_RECORDS) throw new Error("Invalid Relay directory");
        let accepted = 0;
        for (const candidate of directory.relays) {
          try { this.accept(candidate); accepted += 1; } catch (error) { this.lastError = error.message; }
        }
        return accepted;
      }));
      if (results.every((result) => result.status === "rejected")) this.lastError = "All Bridge discovery queries failed; retained unexpired cached routes";
      return this.active();
    })();
    try { return await this.refreshing; } finally { this.refreshing = null; }
  }

  async probe(url) {
    const candidate = this.recordFor(url);
    if (!candidate) throw new Error("Relay discovery announcement expired or unavailable");
    const payload = await fetchDiscoveryJson(`${url}/relay-announcement`, { dispatcher: this.dispatcher,
      timeoutMs: this.config.timeoutMs, maxBytes: MAX_ANNOUNCEMENT_BYTES });
    const record = verifyRelayAnnouncement(payload, this.config, { now: this.now() });
    if (BINDINGS.some((field) => record[field] !== candidate[field]) || record.sequence < candidate.sequence) {
      throw new Error("Relay endpoint proof does not match its discovered announcement");
    }
    return this.accept(record);
  }
}
