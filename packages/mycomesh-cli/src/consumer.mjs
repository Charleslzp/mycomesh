// V11 Consumer runtime: one custodied deposit, any Provider, relay-blind requests.
import { readFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { dirname, resolve } from "node:path";
import { rootCertificates } from "node:tls";
import { addressOf, encodeCall } from "./eip712.mjs";
import { rpcCall } from "./chain.mjs";
import { openDelta, openResponse, outputText, prepareRequest, verifiedProvider } from "./protocol.mjs";
import { recordRequest } from "./disputes.mjs";
import { chatStream, responseStream } from "./sse.mjs";
import { consoleRoutes, localRequestAllowed } from "./console.mjs";
import { pinnedOptions, splitPin } from "./tlspin.mjs";
import { compareRank, rankKey, reputation } from "./reputation.mjs";
import { hashApiKey } from "./tenants.mjs";

const PROVIDER_CACHE_MS = 30_000;
const RELAY_CACHE_MS = 300_000;
const REPUTATION_CACHE_MS = 600_000;
const MAX_BODY = 16 * 1024 * 1024;

export function loadNetwork(path) {
  const network = JSON.parse(readFileSync(path, "utf8"));
  if (network.schema !== "mycomesh.v11.network.v1") throw new Error("not a MycoMesh V11 network manifest");
  if (network.tls_ca_file) network.tls_ca = readFileSync(resolve(dirname(path), network.tls_ca_file), "utf8");
  return network;
}

async function tlsOptions(target, ca, pin) {
  if (target.protocol !== "https:") return {};
  if (pin) return pinnedOptions(target.href, pin);
  return ca ? { ca: [...rootCertificates, ca] } : {};
}

export async function httpJson(url, { method = "GET", body, ca, pin, timeoutMs = 330_000 } = {}) {
  const target = new URL(url);
  const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const tls = await tlsOptions(target, ca, pin);
  return new Promise((resolvePromise, reject) => {
    const req = send(target, {
      method, headers: { accept: "application/json", ...(data ? { "content-type": "application/json", "content-length": data.length } : {}) },
      ...tls,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY) { req.destroy(new Error("response too large")); return; }
        chunks.push(chunk);
      });
      res.on("end", () => {
        try { resolvePromise({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") }); }
        catch (error) { reject(error); }
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error("request timed out")));
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

/** POST expecting NDJSON; each line goes to onLine. Non-streamed replies resolve as JSON. */
export async function httpNdjson(url, { body, ca, pin, timeoutMs = 340_000, onLine }) {
  const target = new URL(url);
  const data = Buffer.from(JSON.stringify(body));
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const tls = await tlsOptions(target, ca, pin);
  return new Promise((resolvePromise, reject) => {
    const req = send(target, {
      method: "POST",
      headers: { accept: "application/x-ndjson", "content-type": "application/json", "content-length": data.length },
      ...tls,
    }, (res) => {
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
        try { resolvePromise({ status: res.statusCode, body: JSON.parse(chunks.join("") || "{}") }); } catch (error) { reject(error); }
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error("request timed out")));
    req.on("error", reject);
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
    this.network = network;
    this.keyPrivate = keyPrivate;
    this.key = addressOf(keyPrivate);
    this.maxFee = maxFee;
    this.fetchJson = fetchJson;
    this.now = now;
    this.deployment = { chainId: network.chain_id, settlement: network.settlement.toLowerCase() };
    this.cache = new Map();
    this.relayCache = null;
  }

  /** On-chain reputation and verified probe verdicts for every Provider in view, cached. */
  async reputations() {
    if (this.reputationCache && Date.now() - this.reputationCache.at < REPUTATION_CACHE_MS) return this.reputationCache.value;
    const descriptors = new Map();
    const relaysByOwner = {};
    for (const relay of await this.relays()) {
      try {
        const owner = relay.owner || `0x${(await rpcCall(this.network.rpc_urls, "eth_call", [{ to: this.network.settlement,
          data: encodeCall("relaySignerOwner(address)", [["address", relay.signer]]) }, "latest"])).slice(26)}`;
        relaysByOwner[owner.toLowerCase()] = relay;
      } catch {}
      try { for (const descriptor of await this.providers(relay)) descriptors.set(descriptor.provider_signer, descriptor); } catch {}
    }
    let value = {};
    try { value = await reputation(this, [...descriptors.values()], relaysByOwner); } catch {}
    this.reputationCache = { at: Date.now(), value };
    return value;
  }

  /** Manifest Relays first, then directory Relays whose /health proves the announced signer. */
  async relays() {
    if (this.relayCache && Date.now() - this.relayCache.at < RELAY_CACHE_MS) return this.relayCache.relays;
    const relays = [...this.network.relays];
    const known = new Set(relays.map((relay) => relay.signer.toLowerCase()));
    try {
      for (const relay of await directoryRelays(this.network)) {
        if (known.has(relay.signer)) continue;
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
    this.relayCache = { at: Date.now(), relays };
    return relays;
  }

  async providers(relay) {
    const cached = this.cache.get(relay.url);
    if (cached && Date.now() - cached.at < PROVIDER_CACHE_MS) return cached.providers;
    const { status, body } = await this.fetchJson(`${relay.url}/providers`, { ca: this.network.tls_ca, pin: relay.pin, timeoutMs: 10_000 });
    if (status !== 200) throw new Error(`Relay ${relay.url} /providers returned ${status}`);
    const now = this.now();
    const providers = (body.providers || []).filter((descriptor) => {
      try { verifiedProvider(descriptor, this.deployment, now); return true; } catch { return false; }
    });
    this.cache.set(relay.url, { at: Date.now(), providers });
    return providers;
  }

  async models() {
    const names = new Set();
    for (const relay of await this.relays()) {
      try { for (const provider of await this.providers(relay)) for (const model of provider.models || []) names.add(model); } catch {}
    }
    return [...names].sort();
  }

  /** Try Relays in order; fail over only while the request provably was not dispatched. */
  async request({ endpoint, model, content, maxOutputTokens = 4096, options = {}, provider, onDelta }) {
    let lastError;
    for (const relay of await this.relays()) {
      let candidates;
      try {
        candidates = (await this.providers(relay)).filter((descriptor) => (descriptor.models || []).includes(model)
          && (!provider || descriptor.provider_signer === provider.toLowerCase()));
      }
      catch (error) { lastError = error; continue; }
      // What the chain proves ranks first: recent fraud, verified probe failures, reputation; then price.
      const records = await this.reputations().catch(() => ({}));
      candidates.sort((a, b) => compareRank(rankKey(a, records[a.provider_signer]), rankKey(b, records[b.provider_signer])));
      for (const descriptor of candidates) {
        const prepared = prepareRequest({
          descriptor, deployment: this.deployment, keyPrivate: this.keyPrivate, relaySigner: relay.signer,
          endpoint, model, content, maxOutputTokens, maxFee: this.maxFee, options, now: this.now(),
        });
        let reply;
        const streamed = [];
        let final = null;
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
        }
        if (reply.streamed) {
          if (!final) throw Object.assign(new Error("stream ended without a result"), { code: "outcome_unknown" });
          if (final.type === "error") throw Object.assign(new Error(final.error), { status: final.status, dispatched: final.dispatched });
          reply = { status: 200, body: final };
        }
        if (reply.status === 200) {
          const opened = openResponse(prepared, reply.body, this.deployment, this.now());
          if (streamed.length && streamed.join("") !== outputText(opened.response.output)) {
            throw new Error("streamed text differs from the receipted response");
          }
          // Only this machine can ever reveal the plaintexts, so keep them for the dispute window.
          if (this.journalDir) recordRequest(this.journalDir, prepared, opened, relay.url);
          return opened;
        }
        lastError = Object.assign(new Error(reply.body?.error || `Relay returned ${reply.status}`), { status: reply.status });
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

/** Local OpenAI-compatible endpoint; nothing leaves this machine unsealed except pricing and routing. */
export function serveConsumer(consumer, { host = "127.0.0.1", port = 8110, apiKey, dataDir, tenants = () => ({}) } = {}) {
  const routes = dataDir ? consoleRoutes({ consumer, dataDir }) : {};
  const bearer = (req) => /^Bearer (.+)$/.exec(String(req.headers.authorization || ""))?.[1];
  const server = createServer(async (req, res) => {
    let writer = null;
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
      res.end(type === "application/json" ? JSON.stringify(body) : body);
    };
    try {
      const path = new URL(req.url, "http://localhost").pathname.replace(/^\/v1\/v1\//, "/v1/");
      // A tenant's API key selects its own payment key and budget; tenants may call from anywhere.
      const tenant = path.startsWith("/v1/") && bearer(req) ? tenants()[hashApiKey(bearer(req))] : undefined;
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
      if (!tenant && bearer(req) && bearer(req) !== apiKey) return send(401, openaiError("invalid API key", "unauthorized"));
      if (!tenant && apiKey && bearer(req) !== apiKey) return send(401, openaiError("invalid API key", "unauthorized"));
      if (req.method === "GET" && path === "/health") return send(200, { ok: true, protocol: 11, key: consumer.key });
      if (req.method === "GET" && path === "/v1/models") {
        return send(200, { object: "list", data: (await active.models()).map((id) => ({ id, object: "model", owned_by: "mycomesh" })) });
      }
      if (req.method !== "POST" || !["/v1/responses", "/v1/chat/completions", "/responses", "/chat/completions"].includes(path)) {
        return send(404, openaiError("not found", "not_found"));
      }
      const body = await readJson(req);
      const chat = path.endsWith("/chat/completions");
      const { model, stream, stream_options: streamOptions, ...rest } = body;
      const content = chat ? rest.messages : rest.input;
      delete rest.messages;
      delete rest.input;
      const maxOutputTokens = rest.max_output_tokens ?? rest.max_tokens ?? rest.max_completion_tokens ?? 4096;
      delete rest.max_output_tokens;
      delete rest.max_tokens;
      delete rest.max_completion_tokens;
      if (!stream) {
        const { response } = await active.request({ endpoint: chat ? "chat" : "responses", model, content, maxOutputTokens, options: rest });
        return send(200, response.output);
      }
      // Headers go out with the first delta, so a request that fails before dispatch still gets an HTTP error.
      const write = (text) => {
        if (!res.headersSent) res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
        res.write(text);
      };
      writer = chat ? chatStream(write, { model }, { includeUsage: streamOptions?.include_usage === true }) : responseStream(write, { model });
      const { response } = await active.request({ endpoint: chat ? "chat" : "responses", model, content, maxOutputTokens,
        options: rest, onDelta: (text) => writer.delta(text) });
      writer.finish(response.output);
      return res.end();
    } catch (error) {
      if (res.headersSent) { writer?.fail(error.message); return res.end(); }
      if (error.message === "wrong wallet password") return send(401, { error: error.message });
      if (error.status && error.status < 500 && !error.dispatched && routes[`${req.method} ${new URL(req.url, "http://x").pathname}`]) {
        return send(error.status, { error: error.message });
      }
      const status = error.code === "outcome_unknown" ? 504 : (error.status && error.status < 500 ? error.status : 502);
      return send(status, openaiError(error.message, error.code || "request_failed"));
    }
  });
  return new Promise((resolvePromise) => server.listen(port, host, () => resolvePromise(server)));
}
