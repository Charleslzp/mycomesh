// V11 Consumer disputes: keep each request's plaintexts locally, reveal them as evidence on demand.
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "./secure-envelope.mjs";
import { encodeCall, encodeWords, hex, keccak, settlementKey } from "./eip712.mjs";

export const EVIDENCE_SCHEMA = "mycomesh.v11.evidence.v1";
const JOURNAL_RETENTION_MS = 3 * 24 * 3600 * 1000; // the dispute window is 24 hours

const journal = (dir) => join(dir, "requests");

export function recordRequest(dir, prepared, opened, relayUrl) {
  const folder = journal(dir);
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  const key = settlementKey(prepared.authorization.key, prepared.authorization.request_id);
  const path = join(folder, `${key}.json`);
  writeFileSync(path, JSON.stringify({
    settlement_key: key, relay_url: relayUrl, recorded_at: Math.floor(Date.now() / 1000),
    signed_receipt: opened.receipt, request: Buffer.from(prepared.requestPlaintext).toString("base64"),
    response: Buffer.from(opened.responsePlaintext).toString("base64"),
  }), { mode: 0o600 });
  chmodSync(path, 0o600);
  for (const name of readdirSync(folder)) {
    const file = join(folder, name);
    if (Date.now() - statSync(file).mtimeMs > JOURNAL_RETENTION_MS) unlinkSync(file);
  }
  return key;
}

export function loadRequest(dir, which) {
  const folder = journal(dir);
  let name = `${String(which).toLowerCase()}.json`;
  if (which === "last") {
    const files = readdirSync(folder).filter((file) => file.endsWith(".json"));
    if (!files.length) throw new Error("no recorded requests");
    name = files.sort((a, b) => statSync(join(folder, b)).mtimeMs - statSync(join(folder, a)).mtimeMs)[0];
  }
  return JSON.parse(readFileSync(join(folder, name), "utf8"));
}

export function buildEvidence(record, { reasonCode, statement }) {
  return {
    schema: EVIDENCE_SCHEMA, settlement_key: record.settlement_key, signed_receipt: record.signed_receipt,
    request: record.request, response: record.response,
    allegation: { reason_code: String(reasonCode).slice(0, 64), statement: String(statement).slice(0, 4000) },
  };
}

export const evidenceHash = (evidence) => hex(keccak(Buffer.from(canonicalJson(evidence), "utf8")));

export const reportId = (key, reporter, digest) =>
  hex(keccak(encodeWords([["bytes32", key], ["address", reporter], ["bytes32", digest]])));

export const openDisputeCall = (key, digest) => encodeCall("openDispute(bytes32,bytes32)", [["bytes32", key], ["bytes32", digest]]);

function preview(document) {
  const content = document.endpoint === "chat" ? (document.messages || []).filter((m) => m.role === "user").at(-1)?.content : document.input;
  const text = typeof content === "string" ? content : Array.isArray(content)
    ? content.map((part) => (typeof part === "string" ? part : part?.text ?? part?.content ?? "")).join(" ") : JSON.stringify(content ?? "");
  return String(text).slice(0, 400);
}

/** Recorded requests, newest first, with short previews (the plaintexts never leave this machine). */
export function listRequests(dir, outputText, limit = 100) {
  const folder = journal(dir);
  if (!existsSync(folder)) return [];
  return readdirSync(folder).filter((name) => name.endsWith(".json"))
    .map((name) => JSON.parse(readFileSync(join(folder, name), "utf8")))
    .sort((a, b) => b.recorded_at - a.recorded_at).slice(0, limit)
    .map((record) => {
      let request = {}; let response = {};
      try { request = JSON.parse(Buffer.from(record.request, "base64").toString("utf8")); } catch {}
      try { response = JSON.parse(Buffer.from(record.response, "base64").toString("utf8")); } catch {}
      const { authorization, receipt } = record.signed_receipt;
      return {
        settlement_key: record.settlement_key, recorded_at: record.recorded_at, relay_url: record.relay_url,
        model: request.model, endpoint: request.endpoint, prompt: preview(request),
        answer: String(outputText(response.output)).slice(0, 600), fee: String(receipt.actual_fee),
        input_tokens: receipt.input_tokens, output_tokens: receipt.output_tokens, provider: authorization.provider_signer,
      };
    });
}
