// Client dialects for the local endpoint: Anthropic Messages and Gemini generateContent, translated to and
// from the network's chat requests (OpenAI shape), streaming included. Token counts come from the
// Provider-signed receipt, so every client sees what it was charged for.
import { randomUUID } from "node:crypto";

const id = (prefix) => `${prefix}${randomUUID().replace(/-/g, "")}`;

export class DialectError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

/** Text of Anthropic or Gemini content: a string or text blocks/parts. Other block kinds are refused. */
function text(content, where) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) throw new DialectError(`${where}: content must be text`);
  return content.map((part) => {
    if (typeof part === "string") return part;
    if (part && typeof part.text === "string" && (part.type === undefined || part.type === "text")) return part.text;
    if (part?.type === "thinking" || part?.type === "redacted_thinking" || part?.thought) return "";
    throw new DialectError(`${where}: only text content is supported (got ${part?.type || Object.keys(part || {})[0] || "unknown"})`);
  }).join("");
}

const unsupportedTools = (present) => {
  if (present) throw new DialectError("tool use is not supported on this network yet; send text-only requests");
};

// ---------------- Anthropic Messages ----------------

/** POST /v1/messages body -> { model, messages, maxOutputTokens, options, stream } */
export function fromAnthropic(body) {
  if (typeof body.model !== "string" || !Array.isArray(body.messages)) throw new DialectError("model and messages are required");
  unsupportedTools(body.tools?.length || body.tool_choice);
  const messages = [];
  if (body.system !== undefined) messages.push({ role: "system", content: text(body.system, "system") });
  for (const message of body.messages) {
    if (!["user", "assistant"].includes(message?.role)) throw new DialectError("messages alternate user and assistant");
    messages.push({ role: message.role, content: text(message.content, `${message.role} message`) });
  }
  const options = {};
  for (const key of ["temperature", "top_p"]) if (body[key] !== undefined) options[key] = body[key];
  if (body.stop_sequences) options.stop = body.stop_sequences;
  return { model: body.model, messages, maxOutputTokens: body.max_tokens ?? 4096, options, stream: body.stream === true };
}

export function toAnthropic(model, answer, receipt) {
  return {
    id: id("msg_"), type: "message", role: "assistant", model,
    content: [{ type: "text", text: answer }], stop_reason: "end_turn", stop_sequence: null,
    usage: { input_tokens: Number(receipt.input_tokens), output_tokens: Number(receipt.output_tokens) },
  };
}

/** Anthropic's SSE event sequence, fed with text as it arrives. */
export function anthropicStream(write, model) {
  const event = (type, data) => write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
  let started = false;
  const start = () => {
    if (started) return;
    started = true;
    event("message_start", { message: { id: id("msg_"), type: "message", role: "assistant", model, content: [],
      stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } });
    event("content_block_start", { index: 0, content_block: { type: "text", text: "" } });
  };
  return {
    delta(piece) { start(); if (piece) event("content_block_delta", { index: 0, delta: { type: "text_delta", text: piece } }); },
    finish(answer, receipt, streamedAny) {
      start();
      if (!streamedAny && answer) event("content_block_delta", { index: 0, delta: { type: "text_delta", text: answer } });
      event("content_block_stop", { index: 0 });
      event("message_delta", { delta: { stop_reason: "end_turn", stop_sequence: null },
        usage: { input_tokens: Number(receipt.input_tokens), output_tokens: Number(receipt.output_tokens) } });
      event("message_stop", {});
    },
    fail(message) { event("error", { error: { type: "api_error", message } }); },
  };
}

export const anthropicError = (message, status) => ({ type: "error", error: {
  type: status === 401 || status === 403 ? "authentication_error" : status === 404 ? "not_found_error"
    : status === 402 ? "billing_error" : status >= 500 ? "api_error" : "invalid_request_error", message } });

// ---------------- Gemini generateContent ----------------

const GEMINI_PATH = /^\/(?:v1|v1beta|v1alpha)\/models\/([^/:]+):(generateContent|streamGenerateContent)$/;

/** The model and whether it streams, for a Gemini path; null for any other path. */
export function geminiRoute(path) {
  const match = GEMINI_PATH.exec(path);
  return match ? { model: decodeURIComponent(match[1]), stream: match[2] === "streamGenerateContent" } : null;
}

export function fromGemini(body, model) {
  if (!Array.isArray(body.contents)) throw new DialectError("contents are required");
  unsupportedTools(body.tools?.length);
  const messages = [];
  const system = body.systemInstruction || body.system_instruction;
  if (system) messages.push({ role: "system", content: text(system.parts ?? system, "systemInstruction") });
  for (const item of body.contents) {
    const role = item.role === "model" ? "assistant" : "user";
    messages.push({ role, content: text(item.parts, `${item.role || "user"} content`) });
  }
  const config = body.generationConfig || body.generation_config || {};
  const options = {};
  if (config.temperature !== undefined) options.temperature = config.temperature;
  if (config.topP !== undefined) options.top_p = config.topP;
  if (config.stopSequences) options.stop = config.stopSequences;
  return { model, messages, maxOutputTokens: config.maxOutputTokens ?? 4096, options };
}

function geminiChunk(model, piece, receipt) {
  const chunk = { candidates: [{ content: { role: "model", parts: [{ text: piece }] }, index: 0 }], modelVersion: model };
  if (receipt) {
    chunk.candidates[0].finishReason = "STOP";
    const input = Number(receipt.input_tokens); const output = Number(receipt.output_tokens);
    chunk.usageMetadata = { promptTokenCount: input, candidatesTokenCount: output, totalTokenCount: input + output };
  }
  return chunk;
}

export const toGemini = (model, answer, receipt) => geminiChunk(model, answer, receipt);

/** streamGenerateContent with alt=sse: one JSON chunk per event; the last carries finishReason and usage. */
export function geminiStream(write, model) {
  const chunk = (value) => write(`data: ${JSON.stringify(value)}\n\n`);
  return {
    delta(piece) { if (piece) chunk(geminiChunk(model, piece)); },
    finish(answer, receipt, streamedAny) { chunk(geminiChunk(model, streamedAny ? "" : answer, receipt)); },
    fail(message) { chunk({ error: { code: 500, message, status: "INTERNAL" } }); },
  };
}

export const geminiError = (message, status) => ({ error: { code: status, message,
  status: status === 400 ? "INVALID_ARGUMENT" : status === 401 || status === 403 ? "PERMISSION_DENIED"
    : status === 404 ? "NOT_FOUND" : status === 402 ? "RESOURCE_EXHAUSTED" : "INTERNAL" } });
