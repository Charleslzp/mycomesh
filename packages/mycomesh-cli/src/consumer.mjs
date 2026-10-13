// V11 Consumer runtime: one custodied deposit, any Provider, relay-blind requests.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Agent as HttpAgent, createServer, request as httpRequest } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { dirname, resolve } from "node:path";
import { rootCertificates } from "node:tls";
import { addressOf, encodeCall } from "./eip712.mjs";
import { rpcCall } from "./chain.mjs";
import { openDelta, openResponse, outputText, planRequest, prepareRequest, verifiedProvider } from "./protocol.mjs";
import { recordRequest } from "./disputes.mjs";
import { chatStream, responseStream } from "./sse.mjs";
import { consoleRoutes, localRequestAllowed } from "./console.mjs";
import { pinnedOptions, splitPin } from "./tlspin.mjs";
import { compareRank, rankKey, reputation } from "./reputation.mjs";
import { hashApiKey } from "./tenants.mjs";
import { anthropicError, anthropicStream, countAnthropicTokens, countGeminiTokens, fromAnthropic, fromGemini, fromResponses,
  geminiError, geminiRoute, geminiStream, responsesUsesTools, toAnthropic, toGemini, toResponses } from "./dialects.mjs";

// Discovery is served from cache and refreshed in the background once it is older than its fresh period; only
// data older than its usable period (or none yet) makes a request wait for it.
const PROVIDER_CACHE_MS = [30_000, 300_000];
const RELAY_CACHE_MS = [300_000, 3_600_000];
const REPUTATION_CACHE_MS = [600_000, 3_600_000];
const REPUTATION_WAIT_MS = 3_000; // a first request ranks without reputation rather than wait longer for it
const WARM_EVERY_MS = 20_000; // serve: keep discovery fresh and a connection to every Relay open

/** A value loaded once at a time, served stale while it is refreshed. */
class Cached {
  constructor(load, [freshMs, usableMs]) { Object.assign(this, { load, freshMs, usableMs, at: 0, value: undefined, pending: null }); }

  get() {
    const age = Date.now() - this.at;
    if (this.value !== undefined && age < this.freshMs) return Promise.resolve(this.value);
    if (this.value !== undefined && age < this.usableMs) { this.refresh().catch(() => {}); return Promise.resolve(this.value); }
    return this.refresh();
  }

  refresh() {
    this.pending ||= this.load().then((value) => { Object.assign(this, { value, at: Date.now() }); return value; })
      .finally(() => { this.pending = null; });
    return this.pending;
  }
}

// Session affinity: a conversation goes back to the Provider that answered its last turn, whose upstream
// account holds the conversation's prompt cache (measured: a new Codex thread with the same 10k-token prefix
// read 9,728 tokens from cache on the same account, none on another).
const SESSION_LIMIT = 10_000;
const SESSION_IDLE_MS = 3_600_000;

/**
 * The conversation a request continues: the client's own session id when it sends one (a `session_id` header,
 * OpenAI `prompt_cache_key`, Anthropic `metadata.user_id`), else the conversation's opening (instructions,
 * system messages and the first user message), which every later turn sends again unchanged.
 */
export function sessionKey({ endpoint, model, content, options = {}, session }) {
  const explicit = session || options.prompt_cache_key;
  if (explicit) return `session:${model}:${explicit}`;
  const messages = Array.isArray(content) ? content : [{ role: "user", content }];
  const head = [];
  for (const message of messages) {
    head.push(message);
    if (message?.role === "user" || typeof message === "string") break;
  }
  return `head:${createHash("sha256").update(JSON.stringify([endpoint, model, options.instructions ?? null, head])).digest("hex")}`;
}

// Consumers of one network (a node and its tenants) share what they discover.
const DISCOVERY = new WeakMap();
const VERIFIED = new WeakMap(); // descriptor -> the times its verification holds
const MAX_BODY = 16 * 1024 * 1024;

export function loadNetwork(path) {
  const network = JSON.parse(readFileSync(path, "utf8"));
  if (network.schema !== "mycomesh.v11.network.v1") throw new Error("not a MycoMesh V11 network manifest");
  if (network.tls_ca_file) network.tls_ca = readFileSync(resolve(dirname(path), network.tls_ca_file), "utf8");
  return network;
}

/**
 * Kept-alive connections, one agent per Relay origin (and pin): a request to a Relay this Consumer talked to in
 * the last half minute skips the TCP and TLS handshakes (several round trips across the world). Idle sockets
 * are dropped after `keepAlive.idleMs`, well inside the Relay edge's own keep-alive (nginx: 75 s), and a request
 * whose reused socket turns out to have been closed by the Relay before any reply is sent again on a fresh
 * one: a closed idle connection never carried it, and the Relay and Provider refuse a settlement key twice
 * anyway. (Only an agent's own createConnection is honoured, hence the pinned one here.)
 */
export const keepAlive = { idleMs: 30_000 };
const AGENTS = new Map();

function tlsOptions(target, ca, pin) {
  const key = `${target.protocol}//${target.host}#${pin || ""}#${ca ? "ca" : ""}`;
  let options = AGENTS.get(key);
  if (!options) {
    const settings = { keepAlive: true, timeout: keepAlive.idleMs, scheduling: "lifo" };
    if (target.protocol !== "https:") options = { agent: new HttpAgent(settings) };
    else {
      const agent = new HttpsAgent(settings);
      if (pin) agent.createConnection = pinnedOptions(target.href, pin).createConnection;
      options = pin || !ca ? { agent } : { agent, ca: [...rootCertificates, ca] };
    }
    AGENTS.set(key, options);
  }
  return options;
}

/** Drop every kept-alive connection (tests, shutdown). */
export function closeConnections() {
  for (const { agent } of AGENTS.values()) agent.destroy();
  AGENTS.clear();
}

const STALE = new Set(["ECONNRESET", "EPIPE", "ECONNABORTED"]);

/** Send once; again if a reused connection was already closed by the Relay before anything came back. */
function withFreshRetry(send) {
  return new Promise((resolvePromise, reject) => {
    const attempt = (tries) => send((error, req, answered) => {
      if (error && req?.reusedSocket && !answered && STALE.has(error.code) && tries < 3) return attempt(tries + 1);
      return error ? reject(error) : undefined;
    }, resolvePromise);
    attempt(0);
  });
}

export async function httpJson(url, { method = "GET", body, ca, pin, timeoutMs = 330_000 } = {}) {
  const target = new URL(url);
  const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const tls = tlsOptions(target, ca, pin);
  return withFreshRetry((fail, resolvePromise) => {
    let answered = false;
    const req = send(target, {
      method, headers: { accept: "application/json", ...(data ? { "content-type": "application/json", "content-length": data.length } : {}) },
      ...tls,
    }, (res) => {
      answered = true;
      const chunks = [];
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY) { req.destroy(new Error("response too large")); return; }
        chunks.push(chunk);
      });
      res.on("end", () => {
        try { resolvePromise({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") }); }
        catch (error) { fail(error, req, true); }
      });
    });
    // A wall-clock deadline, not a socket idle timeout: keep-alive sockets are reused, and an idle timeout
    // left on one by an earlier short request (a 10 s /providers call) would later cut a long answer.
    const timer = setTimeout(() => req.destroy(new Error(`request to ${target.host}${target.pathname} timed out after ${timeoutMs / 1000} s`)), timeoutMs);
    req.on("close", () => clearTimeout(timer));
    req.on("error", (error) => fail(error, req, answered));
    if (data) req.write(data);
    req.end();
  });
}

/** POST expecting NDJSON; each line goes to onLine. Non-streamed replies resolve as JSON. */
export async function httpNdjson(url, { body, ca, pin, timeoutMs = 340_000, onLine }) {
  const target = new URL(url);
  const data = Buffer.from(JSON.stringify(body));
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const tls = tlsOptions(target, ca, pin);
  return withFreshRetry((fail, resolvePromise) => {
    let answered = false;
    const req = send(target, {
      method: "POST",
      headers: { accept: "application/x-ndjson", "content-type": "application/json", "content-length": data.length },
      ...tls,
    }, (res) => {
      answered = true;
      const streaming = res.statusCode === 200 && String(res.headers["content-type"] || "").includes("ndjson");
      let buffered = "";
      const chunks = [];
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        if (!streaming) { chunks.push(chunk); return; }
        buffered += chunk;
        let index;
        while ((index = buffered.indexOf("\n")) >= 0) {
          const line = buffered.slice(0, index);
          buffered = buffered.slice(index + 1);
          if (line.trim()) {
            try { onLine(JSON.parse(line)); } catch (error) { req.destroy(error); return; }
          }
        }
      });
      res.on("end", () => {
        if (streaming) return resolvePromise({ status: 200, streamed: true });
        try { resolvePromise({ status: res.statusCode, body: JSON.parse(chunks.join("") || "{}") }); } catch (error) { fail(error, req, true); }
      });
    });
    // A wall-clock deadline, not a socket idle timeout: keep-alive sockets are reused, and an idle timeout
    // left on one by an earlier short request (a 10 s /providers call) would later cut a long answer.
    const timer = setTimeout(() => req.destroy(new Error(`request to ${target.host}${target.pathname} timed out after ${timeoutMs / 1000} s`)), timeoutMs);
    req.on("close", () => clearTimeout(timer));
    req.on("error", (error) => fail(error, req, answered));
    req.end(data);
  });
}

function decodeString(raw, offset) {
  const length = Number(BigInt(`0x${raw.slice(offset * 2, offset * 2 + 64)}`));
  return Buffer.from(raw.slice(offset * 2 + 64, offset * 2 + 64 + length * 2), "hex").toString("utf8");
}

/** Active Relays announced in the on-chain RelayDirectoryV11. */
export async function directoryRelays(network) {
  if (!network.relay_directory) return [];
  const count = Number(BigInt(await rpcCall(network.rpc_urls, "eth_call", [{ to: network.relay_directory, data: encodeCall("relayCount()", []) }, "latest"])));
  const relays = [];
  for (let index = 0; index < count; index += 1) {
    const raw = (await rpcCall(network.rpc_urls, "eth_call", [{ to: network.relay_directory,
      data: encodeCall("relayAt(uint256)", [["uint", BigInt(index)]]) }, "latest"])).slice(2);
    const base = Number(BigInt(`0x${raw.slice(0, 64)}`));
    if (!Number(BigInt(`0x${raw.slice(64, 128)}`))) continue;
    const entry = raw.slice(base * 2);
    const [url, pin] = splitPin(decodeString(entry, Number(BigInt(`0x${entry.slice(128, 192)}`))));
    relays.push({ owner: `0x${entry.slice(24, 64)}`.toLowerCase(), signer: `0x${entry.slice(64 + 24, 128)}`.toLowerCase(),
      url: url.replace(/\/+$/, ""), pin });
  }
  return relays;
}

export class Consumer {
  constructor({ network, keyPrivate, maxFee, journalDir, fetchJson = httpJson, streamJson = httpNdjson, now = () => Math.floor(Date.now() / 1000) }) {
    this.streamJson = streamJson;
    this.journalDir = journalDir;
    this.inFlight = new Map(); // Provider signer -> requests this Consumer has with it now
    this.sessions = new Map(); // session key -> { provider, at }, least recently used first
    this.network = network;
    this.keyPrivate = keyPrivate;
    this.key = addressOf(keyPrivate);
    this.maxFee = maxFee;
    this.fetchJson = fetchJson;
    this.now = now;
    this.deployment = { chainId: network.chain_id, settlement: network.settlement.toLowerCase() };
    const shared = DISCOVERY.get(network) || new Map();
    DISCOVERY.set(network, shared);
    if (!shared.has(fetchJson)) {
      shared.set(fetchJson, { relays: new Cached(() => this.loadRelays(), RELAY_CACHE_MS), providers: new Map(),
        reputations: new Cached(() => this.loadReputations(), REPUTATION_CACHE_MS) });
    }
    this.discovery = shared.get(fetchJson);
  }

  /** On-chain reputation and verified probe verdicts for every Provider in view, cached. */
  reputations({ waitMs = Infinity } = {}) {
    const value = this.discovery.reputations.get();
    if (!Number.isFinite(waitMs)) return value;
    return Promise.race([value, new Promise((resolve) => setTimeout(resolve, waitMs, {}).unref())]);
  }

  async loadReputations() {
    const descriptors = new Map();
    const relaysByOwner = {};
    await Promise.all((await this.relays()).map(async (relay) => {
      try {
        const owner = relay.owner || `0x${(await rpcCall(this.network.rpc_urls, "eth_call", [{ to: this.network.settlement,
          data: encodeCall("relaySignerOwner(address)", [["address", relay.signer]]) }, "latest"])).slice(26)}`;
        relaysByOwner[owner.toLowerCase()] = relay;
      } catch {}
      try { for (const descriptor of await this.providers(relay)) descriptors.set(descriptor.provider_signer, descriptor); } catch {}
    }));
    let value = {};
    try { value = await reputation(this, [...descriptors.values()], relaysByOwner); } catch {}
    return value;
  }

  /** Discover now what the first request would otherwise wait for; with `everyMs`, keep it fresh (serve). */
  warm({ everyMs } = {}) {
    const once = async () => {
      try { await Promise.all((await this.relays()).map((relay) => this.providers(relay).catch(() => {}))); } catch {}
      await this.reputations().catch(() => {});
    };
    const first = once();
    if (everyMs) setInterval(once, everyMs).unref();
    return first;
  }

  /** Manifest Relays first, then directory Relays whose /health proves the announced signer. */
  relays() {
    return this.discovery.relays.get();
  }

  async loadRelays() {
    const relays = this.network.relays.map((relay) => ({ ...relay }));
    const known = new Set(relays.map((relay) => relay.signer.toLowerCase()));
    try {
      for (const relay of await directoryRelays(this.network)) {
        if (known.has(relay.signer)) {
          // A manifest Relay that pinned its certificate on-chain is checked by the pin, not the CA.
          const listed = relays.find((entry) => entry.signer.toLowerCase() === relay.signer);
          listed.pin = relay.pin || listed.pin;
          listed.owner = relay.owner;
          continue;
        }
        try {
          const { status, body } = await this.fetchJson(`${relay.url}/health`, { ca: this.network.tls_ca, pin: relay.pin, timeoutMs: 5_000 });
          if (status === 200 && String(body.relay_signer).toLowerCase() === relay.signer
              && String(body.settlement).toLowerCase() === this.deployment.settlement) {
            relays.push(relay);
            known.add(relay.signer);
          }
        } catch {}
      }
    } catch {}
    return relays;
  }

  /** A Relay's Providers whose signed descriptors verify now (a cached list is checked again on every use). */
  async providers(relay) {
    let entry = this.discovery.providers.get(relay.url);
    if (!entry) {
      entry = new Cached(async () => {
        const { status, body } = await this.fetchJson(`${relay.url}/providers`, { ca: this.network.tls_ca, pin: relay.pin, timeoutMs: 10_000 });
        if (status !== 200) throw new Error(`Relay ${relay.url} /providers returned ${status}`);
        return body.providers || [];
      }, PROVIDER_CACHE_MS);
      this.discovery.providers.set(relay.url, entry);
    }
    const now = this.now();
    return (await entry.get()).filter((descriptor) => {
      // Signatures do not change: once verified, a descriptor stays good until its key or attestation expires.
      const known = VERIFIED.get(descriptor);
      if (known && known.from <= now && now < known.until) return true;
      try { verifiedProvider(descriptor, this.deployment, now); } catch { return false; }
      VERIFIED.set(descriptor, { from: now, until: Math.min(Number(descriptor.transport_key?.expires_at),
        Number(descriptor.transport_attestation?.expires_at)) });
      return true;
    });
  }

  /** The network's model catalog (manifest "models"): vendor, tier, capabilities. */
  catalog() {
    return this.network.models || {};
  }

  async models() {
    const names = new Set();
    for (const relay of await this.relays()) {
      try { for (const provider of await this.providers(relay)) for (const model of provider.models || []) names.add(model); } catch {}
    }
    return [...names].sort();
  }

  /**
   * Try Relays and Providers in order; fail over only while the request provably was not dispatched. When
   * every Provider is busy, wait and try again (a short queue) rather than failing a burst of requests.
   */
  async request(args) {
    const deadline = Date.now() + (this.queueMs ?? 120_000);
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await this.attempt(args);
      } catch (error) {
        const busy = error.dispatched === false && [502, 503].includes(error.status);
        if (!busy || Date.now() > deadline) throw error;
        await new Promise((resolve) => setTimeout(resolve, Math.min(4_000, 500 * 2 ** attempt) * (0.5 + Math.random())));
      }
    }
  }

  /**
   * What the chain proves ranks first (recent fraud, a suspected downgrade, verified probe failures); then
   * Providers this Consumer is not already keeping busy; then the Provider holding this conversation's cache;
   * then reputation in coarse bands, shuffled within a band so that many Consumers spread over the network
   * instead of all queueing at its single best Provider.
   */
  rank(candidates, records, preferred) {
    const key = (descriptor) => {
      const [fraud, downgrade, failure, volume] = rankKey(descriptor, records[descriptor.provider_signer]);
      const busy = (this.inFlight.get(descriptor.provider_signer) || 0) >= Math.max(1, Number(descriptor.capacity) || 1) ? 1 : 0;
      const sticky = descriptor.provider_signer === preferred ? 0 : 1;
      return [fraud, downgrade, busy, sticky, failure, -Math.floor(Math.log10(1 - volume)), Math.random()];
    };
    const keyed = candidates.map((descriptor) => [key(descriptor), descriptor]);
    keyed.sort((a, b) => compareRank(a[0], b[0]));
    return keyed.map(([, descriptor]) => descriptor);
  }

  /** The Provider that answered this conversation last, if recently. */
  stickyProvider(session) {
    const entry = this.sessions.get(session);
    return entry && Date.now() - entry.at < SESSION_IDLE_MS ? entry.provider : undefined;
  }

  remember(session, provider) {
    this.sessions.delete(session);
    this.sessions.set(session, { provider, at: Date.now() });
    if (this.sessions.size > SESSION_LIMIT) this.sessions.delete(this.sessions.keys().next().value);
  }

  async attempt({ endpoint, model, content, maxOutputTokens = 4096, options = {}, provider, session, onDelta }) {
    let lastError;
    let raisedFee = 0;
    const conversation = sessionKey({ endpoint, model, content, options, session });
    const preferred = this.stickyProvider(conversation);
    for (const relay of await this.relays()) {
      let candidates;
      try {
        candidates = (await this.providers(relay)).filter((descriptor) => (descriptor.models || []).includes(model)
          && (!provider || descriptor.provider_signer === provider.toLowerCase()));
      }
      catch (error) { lastError = error; continue; }
      const records = await this.reputations({ waitMs: REPUTATION_WAIT_MS }).catch(() => ({}));
      candidates = this.rank(candidates, records, preferred);
      let retried = false;
      for (let index = 0; index < candidates.length; index += 1) {
        const descriptor = candidates[index];
        // Authorize what this request can really cost, not the Consumer's whole per-request cap.
        const plan = planRequest(descriptor, endpoint, content, maxOutputTokens, this.maxFee, options.tools);
        const maxFee = Math.min(Number(this.maxFee), Math.max(raisedFee || 0, plan.maxFee));
        const prepared = prepareRequest({
          descriptor, deployment: this.deployment, keyPrivate: this.keyPrivate, relaySigner: relay.signer,
          endpoint, model, content, maxOutputTokens: plan.maxOutputTokens, maxFee, options, now: this.now(),
        });
        let reply;
        const streamed = [];
        let final = null;
        const signer = descriptor.provider_signer;
        this.inFlight.set(signer, (this.inFlight.get(signer) || 0) + 1);
        try {
          reply = onDelta
            ? await this.streamJson(`${relay.url}/v11/requests`, { body: prepared.payload, ca: this.network.tls_ca, pin: relay.pin, onLine: (line) => {
              if (line.type === "delta") {
                streamed.push(openDelta(prepared, line.sealed, streamed.length, this.now()));
                onDelta(streamed.at(-1));
              } else {
                final = line;
              }
            } })
            : await this.fetchJson(`${relay.url}/v11/requests`, { method: "POST", body: prepared.payload, ca: this.network.tls_ca, pin: relay.pin });
        } catch (error) {
          // The request may have reached the Relay: never replay it elsewhere.
          throw Object.assign(new Error(`request outcome unknown: ${error.message}`), { code: "outcome_unknown", requestId: prepared.authorization.request_id });
        } finally {
          this.inFlight.set(signer, (this.inFlight.get(signer) || 1) - 1);
        }
        if (reply.streamed) {
          if (!final) throw Object.assign(new Error("stream ended without a result"), { code: "outcome_unknown" });
          // Part of an answer already reached the client and cannot be taken back: never start it again, here
          // or at another Provider, or the client would read half an answer followed by another one.
          if (final.type === "error" && streamed.length) {
            throw Object.assign(new Error(`the answer was cut off: ${final.error}`), { status: 502, dispatched: true });
          }
          // An error before dispatch (a busy Provider, say) is safe to fail over, exactly as without streaming.
          reply = final.type === "error"
            ? { status: final.status || 502, body: { error: final.error, dispatched: final.dispatched } }
            : { status: 200, body: final };
        }
        if (reply.status === 200) {
          const opened = openResponse(prepared, reply.body, this.deployment, this.now());
          if (streamed.length && streamed.join("") !== outputText(opened.response.output)) {
            throw new Error("streamed text differs from the receipted response");
          }
          // Only this machine can ever reveal the plaintexts, so keep them for the dispute window.
          if (this.journalDir) recordRequest(this.journalDir, prepared, opened, relay.url);
          this.remember(conversation, signer);
          return opened;
        }
        lastError = Object.assign(new Error(reply.body?.error || `Relay returned ${reply.status}`),
          { status: reply.status, dispatched: reply.body?.dispatched });
        // A Provider that found the max fee too low for this request says what it needs; ask again with that.
        const needed = /worst-case price (\d+)/.exec(String(reply.body?.error || ""));
        if (needed && reply.body?.dispatched === false) {
          const required = Number(needed[1]);
          if (required > Number(this.maxFee)) {
            throw Object.assign(new Error(`this request may cost up to ${required}, above the per-request limit ${this.maxFee}`), { status: 402 });
          }
          raisedFee = Math.ceil(required * 1.2);
          if (!retried) { retried = true; index -= 1; } // the same Provider, once, with the fee it asked for
          continue;
        }
        if (reply.body?.dispatched !== false || ![502, 503].includes(reply.status)) throw lastError;
      }
    }
    throw lastError || new Error(`no Provider serves model ${model}`);
  }
}

function openaiError(message, code = "mycomesh_error") {
  return { error: { message, type: "mycomesh_error", code } };
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

/** Anthropic Messages and Gemini generateContent: translated to a chat request, answered in the client's dialect. */
async function dialectRequest(req, res, active, path, setWriter) {
  const body = await readJson(req);
  const gemini = geminiRoute(path);
  // Token counting (Claude Code and the Gemini CLI ask before long requests): an estimate, no request is sent.
  const json = (value) => { res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); return res.end(JSON.stringify(value)); };
  if (path === "/v1/messages/count_tokens") return json(countAnthropicTokens(body));
  if (gemini?.count) return json(countGeminiTokens(body, gemini.model));
  const ask = gemini ? fromGemini(body, gemini.model) : fromAnthropic(body);
  const stream = gemini ? gemini.stream : ask.stream;
  const request = { endpoint: "chat", model: ask.model, content: ask.messages, maxOutputTokens: ask.maxOutputTokens, options: ask.options,
    session: ask.session || req.headers["x-claude-code-session-id"] || req.headers["session_id"] || req.headers["x-session-id"] || undefined };
  if (!stream) {
    const { response, receipt } = await active.request(request);
    const out = gemini ? toGemini(ask.model, response.output, receipt.receipt) : toAnthropic(ask.model, response.output, receipt.receipt);
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify(out));
  }
  const write = (chunk) => {
    if (!res.headersSent) res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
    res.write(chunk);
  };
  const writer = gemini ? geminiStream(write, ask.model) : anthropicStream(write, ask.model);
  setWriter(writer);
  let streamedAny = false;
  const { response, receipt } = await active.request({ ...request, onDelta: (piece) => { streamedAny ||= Boolean(piece); writer.delta(piece); } });
  writer.finish(response.output, receipt.receipt, streamedAny);
  return res.end();
}

/**
 * Responses with tools (Codex CLI and other agents): translated to the network's chat shape and back, so the
 * Provider sees one way of calling tools; the client gets function_call / custom_tool_call items to run.
 */
async function responsesWithTools(res, active, body, session, setWriter) {
  const { model, stream } = body;
  const { messages, options, custom } = fromResponses(body);
  const maxOutputTokens = body.max_output_tokens ?? 4096;
  const request = { endpoint: "chat", model, content: messages, maxOutputTokens, options, session };
  if (!stream) {
    const { response, receipt } = await active.request(request);
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify(toResponses(model, response.output, receipt.receipt, custom)));
  }
  const write = (text) => {
    if (!res.headersSent) res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
    res.write(text);
  };
  const writer = responseStream(write, { model });
  setWriter(writer);
  const { response, receipt } = await active.request({ ...request, onDelta: (text) => writer.delta(text) });
  writer.finish(toResponses(model, response.output, receipt.receipt, custom));
  return res.end();
}

/** Local OpenAI-compatible endpoint (plus the Anthropic and Gemini dialects); nothing leaves this machine unsealed except pricing and routing. */
export function serveConsumer(consumer, { host = "127.0.0.1", port = 8110, apiKey, dataDir, tenants = () => ({}) } = {}) {
  consumer.warm({ everyMs: WARM_EVERY_MS }).catch(() => {}); // tenants share it
  const routes = dataDir ? consoleRoutes({ consumer, dataDir }) : {};
  // Every dialect's way of presenting a key: OpenAI Bearer, Anthropic x-api-key, Gemini x-goog-api-key or ?key=.
  const bearer = (req) => /^Bearer (.+)$/.exec(String(req.headers.authorization || ""))?.[1]
    || req.headers["x-api-key"] || req.headers["x-goog-api-key"] || new URL(req.url, "http://localhost").searchParams.get("key") || undefined;
  const server = createServer(async (req, res) => {
    let writer = null;
    let dialect = "openai";
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
      res.end(type === "application/json" ? JSON.stringify(body) : body);
    };
    try {
      const path = new URL(req.url, "http://localhost").pathname.replace(/^\/v1\/v1\//, "/v1/");
      dialect = path === "/v1/messages" || path === "/v1/messages/count_tokens" ? "anthropic" : geminiRoute(path) ? "gemini" : "openai";
      // A tenant's API key selects its own payment key and budget; tenants may call from anywhere.
      const tenant = /^\/v1(beta|alpha)?\//.test(path) && bearer(req) ? tenants()[hashApiKey(bearer(req))] : undefined;
      if (!tenant && !localRequestAllowed(req, server.address().port)) {
        return send(403, openaiError("only this machine may use the local node", "forbidden"));
      }
      const active = tenant || consumer;
      const route = routes[`${req.method} ${path}`];
      if (route) {
        if (req.method === "POST" && !String(req.headers["content-type"] || "").startsWith("application/json")) {
          return send(415, { error: "JSON body required" });
        }
        const result = await route(req.method === "POST" ? await readJson(req) : {});
        return result?.type ? send(200, result.body, result.type) : send(200, result);
      }
      // Without a configured key the local node trusts this machine (Host and Origin are checked above), so
      // clients that insist on sending some key (Claude Code, the Gemini CLI) still work.
      if (!tenant && apiKey && bearer(req) !== apiKey) return send(401, openaiError("invalid API key", "unauthorized"));
      if (req.method === "GET" && path === "/v1/models") {
        const catalog = active.catalog?.() || {};
        return send(200, { object: "list", data: (await active.models()).map((model) => ({
          id: model, object: "model", owned_by: "mycomesh", ...(catalog[model] ? { mycomesh: catalog[model] } : {}) })) });
      }
      if (req.method === "POST" && dialect !== "openai") return await dialectRequest(req, res, active, path, (w) => { writer = w; });
      if (req.method === "GET" && path === "/health") return send(200, { ok: true, protocol: 11, key: consumer.key });
      if (req.method !== "POST" || !["/v1/responses", "/v1/chat/completions", "/responses", "/chat/completions"].includes(path)) {
        return send(404, openaiError("not found", "not_found"));
      }
      const body = await readJson(req);
      const chat = path.endsWith("/chat/completions");
      const session = req.headers["session_id"] || req.headers["x-session-id"] || undefined;
      if (!chat && responsesUsesTools(body)) return await responsesWithTools(res, active, body, body.prompt_cache_key || session, (w) => { writer = w; });
      const { model, stream, stream_options: streamOptions, ...rest } = body;
      const content = chat ? rest.messages : rest.input;
      delete rest.messages;
      delete rest.input;
      const maxOutputTokens = rest.max_output_tokens ?? rest.max_tokens ?? rest.max_completion_tokens ?? 4096;
      delete rest.max_output_tokens;
      delete rest.max_tokens;
      delete rest.max_completion_tokens;
      if (!stream) {
        const { response } = await active.request({ endpoint: chat ? "chat" : "responses", model, content, maxOutputTokens, options: rest, session });
        return send(200, response.output);
      }
      // Headers go out with the first delta, so a request that fails before dispatch still gets an HTTP error.
      const write = (text) => {
        if (!res.headersSent) res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
        res.write(text);
      };
      writer = chat ? chatStream(write, { model }, { includeUsage: streamOptions?.include_usage === true }) : responseStream(write, { model });
      const { response } = await active.request({ endpoint: chat ? "chat" : "responses", model, content, maxOutputTokens,
        options: rest, session, onDelta: (text) => writer.delta(text) });
      writer.finish(response.output);
      return res.end();
    } catch (error) {
      if (res.headersSent) { writer?.fail(error.message); return res.end(); }
      if (error.message === "wrong wallet password") return send(401, { error: error.message });
      if (error.status && error.status < 500 && !error.dispatched && routes[`${req.method} ${new URL(req.url, "http://x").pathname}`]) {
        return send(error.status, { error: error.message });
      }
      const status = error.code === "outcome_unknown" ? 504 : (error.status && error.status < 500 ? error.status : 502);
      if (dialect === "anthropic") return send(status, anthropicError(error.message, status));
      if (dialect === "gemini") return send(status, geminiError(error.message, status));
      return send(status, openaiError(error.message, error.code || "request_failed"));
    }
  });
  return new Promise((resolvePromise) => server.listen(port, host, () => resolvePromise(server)));
}
