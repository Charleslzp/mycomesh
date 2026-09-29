// V11 Consumer runtime: one custodied deposit, any Provider, relay-blind requests.
import { readFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { dirname, resolve } from "node:path";
import { rootCertificates } from "node:tls";
import { addressOf } from "./eip712.mjs";
import { openResponse, prepareRequest, verifiedProvider } from "./protocol.mjs";
import { chatSse, responseSse } from "./sse.mjs";

const PROVIDER_CACHE_MS = 30_000;
const MAX_BODY = 16 * 1024 * 1024;

export function loadNetwork(path) {
  const network = JSON.parse(readFileSync(path, "utf8"));
  if (network.schema !== "mycomesh.v11.network.v1") throw new Error("not a MycoMesh V11 network manifest");
  if (network.tls_ca_file) network.tls_ca = readFileSync(resolve(dirname(path), network.tls_ca_file), "utf8");
  return network;
}

export function httpJson(url, { method = "GET", body, ca, timeoutMs = 330_000 } = {}) {
  const target = new URL(url);
  const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolvePromise, reject) => {
    const req = send(target, {
      method, headers: { accept: "application/json", ...(data ? { "content-type": "application/json", "content-length": data.length } : {}) },
      ...(target.protocol === "https:" && ca ? { ca: [...rootCertificates, ca] } : {}),
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

export class Consumer {
  constructor({ network, keyPrivate, maxFee, fetchJson = httpJson, now = () => Math.floor(Date.now() / 1000) }) {
    this.network = network;
    this.keyPrivate = keyPrivate;
    this.key = addressOf(keyPrivate);
    this.maxFee = maxFee;
    this.fetchJson = fetchJson;
    this.now = now;
    this.deployment = { chainId: network.chain_id, settlement: network.settlement.toLowerCase() };
    this.cache = new Map();
  }

  async providers(relay) {
    const cached = this.cache.get(relay.url);
    if (cached && Date.now() - cached.at < PROVIDER_CACHE_MS) return cached.providers;
    const { status, body } = await this.fetchJson(`${relay.url}/providers`, { ca: this.network.tls_ca, timeoutMs: 10_000 });
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
    for (const relay of this.network.relays) {
      try { for (const provider of await this.providers(relay)) for (const model of provider.models || []) names.add(model); } catch {}
    }
    return [...names].sort();
  }

  /** Try Relays in order; fail over only while the request provably was not dispatched. */
  async request({ endpoint, model, content, maxOutputTokens = 4096, options = {} }) {
    let lastError;
    for (const relay of this.network.relays) {
      let candidates;
      try { candidates = (await this.providers(relay)).filter((provider) => (provider.models || []).includes(model)); }
      catch (error) { lastError = error; continue; }
      candidates.sort((a, b) => (a.prices.output_per_1k - b.prices.output_per_1k) || (a.prices.input_per_1k - b.prices.input_per_1k));
      for (const descriptor of candidates) {
        const prepared = prepareRequest({
          descriptor, deployment: this.deployment, keyPrivate: this.keyPrivate, relaySigner: relay.signer,
          endpoint, model, content, maxOutputTokens, maxFee: this.maxFee, options, now: this.now(),
        });
        let reply;
        try {
          reply = await this.fetchJson(`${relay.url}/v11/requests`, { method: "POST", body: prepared.payload, ca: this.network.tls_ca });
        } catch (error) {
          // The request may have reached the Relay: never replay it elsewhere.
          throw Object.assign(new Error(`request outcome unknown: ${error.message}`), { code: "outcome_unknown", requestId: prepared.authorization.request_id });
        }
        if (reply.status === 200) return openResponse(prepared, reply.body, this.deployment, this.now());
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
export function serveConsumer(consumer, { host = "127.0.0.1", port = 8110, apiKey } = {}) {
  const server = createServer(async (req, res) => {
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
      res.end(type === "application/json" ? JSON.stringify(body) : body);
    };
    try {
      if (apiKey && req.headers.authorization !== `Bearer ${apiKey}`) return send(401, openaiError("invalid API key", "unauthorized"));
      const path = new URL(req.url, "http://localhost").pathname.replace(/^\/v1\/v1\//, "/v1/");
      if (req.method === "GET" && path === "/health") return send(200, { ok: true, protocol: 11, key: consumer.key });
      if (req.method === "GET" && path === "/v1/models") {
        return send(200, { object: "list", data: (await consumer.models()).map((id) => ({ id, object: "model", owned_by: "mycomesh" })) });
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
      const { response } = await consumer.request({ endpoint: chat ? "chat" : "responses", model, content, maxOutputTokens, options: rest });
      const output = response.output;
      if (stream) return send(200, chat ? chatSse(output, { includeUsage: streamOptions?.include_usage === true }) : responseSse(output), "text/event-stream");
      return send(200, output);
    } catch (error) {
      const status = error.code === "outcome_unknown" ? 504 : (error.status && error.status < 500 ? error.status : 502);
      return send(status, openaiError(error.message, error.code || "request_failed"));
    }
  });
  return new Promise((resolvePromise) => server.listen(port, host, () => resolvePromise(server)));
}
