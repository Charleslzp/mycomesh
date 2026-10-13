// Client dialects for the local endpoint: Anthropic Messages, Gemini generateContent and OpenAI Responses with
// tools, translated to and from the network's one shape (OpenAI Chat Completions: tools, assistant tool_calls,
// role "tool" results), streaming included. The Consumer's own client runs the tools; the network only carries
// the calls and their results. Token counts come from the Provider-signed receipt.
import { randomUUID } from "node:crypto";

const id = (prefix) => `${prefix}${randomUUID().replace(/-/g, "")}`;

export class DialectError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

/**
 * Content in the network's parts (OpenAI Chat): a string when it is all text, else text, image_url (a data: or
 * https URL) and file (a data: URL and its filename) parts. Anthropic blocks, Responses inputs and Gemini parts
 * all land here.
 */
export function parts(content, where) {
  if (typeof content === "string" || content === undefined || content === null) return content ?? "";
  if (!Array.isArray(content)) throw new DialectError(`${where}: content must be text`);
  const out = [];
  for (const part of content) {
    const media = mediaPart(part);
    if (media) out.push(media);
    else { const words = text([part], where); if (words) out.push({ type: "text", text: words }); }
  }
  return out.every((p) => p.type === "text") ? out.map((p) => p.text).join("") : out;
}

const dataUrl = (mime, data) => `data:${mime || "application/octet-stream"};base64,${data}`;

/** An image or document block of any dialect as a network part; null for text and the rest. */
function mediaPart(part) {
  if (!part || typeof part !== "object") return null;
  if (part.type === "image" && part.source) {  // Anthropic
    const url = part.source.type === "base64" ? dataUrl(part.source.media_type, part.source.data) : part.source.url;
    return url ? { type: "image_url", image_url: { url } } : null;
  }
  if (part.type === "document" && part.source?.type === "base64") {
    return { type: "file", file: { filename: part.title || "document.pdf", file_data: dataUrl(part.source.media_type, part.source.data) } };
  }
  if (part.type === "input_image" && (part.image_url || part.url)) return { type: "image_url", image_url: { url: part.image_url || part.url } };  // Responses
  if (part.type === "input_file" && part.file_data) {
    return { type: "file", file: { filename: part.filename || "file", file_data: part.file_data.startsWith("data:") ? part.file_data : dataUrl("application/pdf", part.file_data) } };
  }
  if (part.type === "image_url" && part.image_url) return { type: "image_url", image_url: { url: part.image_url.url || part.image_url } };  // Chat
  if (part.type === "file" && part.file) return { type: "file", file: part.file };
  if (part.inlineData?.data) {  // Gemini
    const url = dataUrl(part.inlineData.mimeType, part.inlineData.data);
    return part.inlineData.mimeType?.startsWith("image/") ? { type: "image_url", image_url: { url } }
      : { type: "file", file: { filename: "file", file_data: url } };
  }
  return null;
}

/** The text of content (images and documents become a note): for places that can hold only text. */
function text(content, where) {
  if (typeof content === "string") return content;
  if (content === undefined || content === null) return "";
  if (!Array.isArray(content)) throw new DialectError(`${where}: content must be text`);
  return content.map((part) => {
    if (typeof part === "string") return part;
    if (part && typeof part.text === "string" && (part.type === undefined || part.type === "text")) return part.text;
    if (part?.type === "thinking" || part?.type === "redacted_thinking" || part?.thought) return "";
    if (part?.type === "image" || part?.inlineData || part?.type === "input_image" || part?.type === "image_url") return "[image]";
    if (part?.type === "document") return part.source?.type === "text" ? String(part.source.data ?? "") : "[document]";
    if (part?.type === "input_file" || part?.type === "file") return "[file]";
    if (part?.type === "input_text" || part?.type === "output_text") return String(part.text ?? "");
    throw new DialectError(`${where}: unsupported content (${part?.type || Object.keys(part || {})[0] || "unknown"})`);
  }).join("");
}

const parseArguments = (value) => {
  if (value && typeof value === "object") return value;
  try { return JSON.parse(value || "{}"); } catch { return { input: String(value) }; }
};

/** The answer and tool calls of a network response (a chat completion). */
export function answerOf(output) {
  const choice = output?.choices?.[0] || {};
  const message = choice.message || {};
  return { text: typeof message.content === "string" ? message.content : "", calls: Array.isArray(message.tool_calls) ? message.tool_calls : [],
    finish: choice.finish_reason || "stop" };
}

// ---------------- Anthropic Messages ----------------

/** POST /v1/messages body -> { model, messages, maxOutputTokens, options, stream, session } */
export function fromAnthropic(body) {
  if (typeof body.model !== "string" || !Array.isArray(body.messages)) throw new DialectError("model and messages are required");
  const messages = [];
  if (body.system !== undefined) messages.push({ role: "system", content: text(body.system, "system") });
  for (const message of body.messages) {
    if (message?.role === "system") { messages.push({ role: "system", content: text(message.content, "system message") }); continue; }
    if (!["user", "assistant"].includes(message?.role)) throw new DialectError(`unsupported message role ${message?.role}`);
    const blocks = typeof message.content === "string" ? [{ type: "text", text: message.content }] : message.content || [];
    if (message.role === "assistant") {
      const calls = blocks.filter((b) => b?.type === "tool_use").map((b) => ({ id: b.id, type: "function",
        function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) } }));
      const words = text(blocks.filter((b) => b?.type !== "tool_use"), "assistant message");
      messages.push({ role: "assistant", content: words || (calls.length ? null : ""), ...(calls.length ? { tool_calls: calls } : {}) });
      continue;
    }
    // A user turn: tool results answer the previous assistant's calls; the rest is what the user said. A tool
    // result can only be text, so images it returned (a screenshot Read) follow in a user message.
    const shown = [];
    for (const block of blocks.filter((b) => b?.type === "tool_result")) {
      const content = Array.isArray(block.content) ? block.content : [{ type: "text", text: String(block.content ?? "") }];
      const media = content.map(mediaPart).filter(Boolean);
      const result = text(content.filter((b) => !mediaPart(b)), "tool_result") + (media.length ? `\n[${media.length} attachment(s) follow]` : "");
      messages.push({ role: "tool", tool_call_id: block.tool_use_id, content: block.is_error ? `Error: ${result}` : result });
      if (media.length) shown.push({ type: "text", text: `Attachments returned by tool call ${block.tool_use_id}:` }, ...media);
    }
    const rest = blocks.filter((b) => b?.type !== "tool_result");
    const said = rest.length ? parts(rest, "user message") : "";
    if (shown.length) messages.push({ role: "user", content: [...shown, ...(typeof said === "string" ? (said ? [{ type: "text", text: said }] : []) : said)] });
    else if (rest.length || !blocks.length) messages.push({ role: "user", content: said });
  }
  const options = {};
  for (const key of ["temperature", "top_p"]) if (body[key] !== undefined) options[key] = body[key];
  if (body.stop_sequences) options.stop = body.stop_sequences;
  // The effort the user chose in the client (Claude Code: output_config.effort) is the model's reasoning effort.
  const effort = body.output_config?.effort;
  if (["minimal", "low", "medium", "high"].includes(effort)) options.reasoning_effort = effort;
  const tools = (body.tools || []).filter((t) => t?.name && (t.type === undefined || t.type === "custom" || t.input_schema));
  if (tools.length) {
    options.tools = tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description || "",
      parameters: t.input_schema || { type: "object", properties: {} } } }));
    const choice = body.tool_choice;
    if (choice?.type === "any") options.tool_choice = "required";
    else if (choice?.type === "tool" && choice.name) options.tool_choice = { type: "function", function: { name: choice.name } };
    else if (choice?.type === "none") options.tool_choice = "none";
  }
  // Claude Code puts its session in metadata.user_id (a JSON string with session_id): a conversation's turns share it.
  let session = typeof body.metadata?.user_id === "string" ? body.metadata.user_id : undefined;
  try { session = JSON.parse(session).session_id || session; } catch {}
  return { model: body.model, messages, maxOutputTokens: body.max_tokens ?? 4096, options, stream: body.stream === true, session };
}

const anthropicStop = (answer) => answer.calls.length ? "tool_use" : answer.finish === "length" ? "max_tokens" : "end_turn";

export function toAnthropic(model, output, receipt) {
  const answer = answerOf(output);
  const content = answer.text ? [{ type: "text", text: answer.text }] : [];
  for (const call of answer.calls) content.push({ type: "tool_use", id: call.id, name: call.function?.name, input: parseArguments(call.function?.arguments) });
  return {
    id: id("msg_"), type: "message", role: "assistant", model, content: content.length ? content : [{ type: "text", text: "" }],
    stop_reason: anthropicStop(answer), stop_sequence: null,
    usage: { input_tokens: Number(receipt.input_tokens), output_tokens: Number(receipt.output_tokens) },
  };
}

/** Anthropic's SSE event sequence: text as it arrives, then tool_use blocks when the verified answer is in. */
export function anthropicStream(write, model) {
  const event = (type, data) => write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
  let started = false;
  let textOpen = false;
  let index = 0;
  const start = () => {
    if (started) return;
    started = true;
    event("message_start", { message: { id: id("msg_"), type: "message", role: "assistant", model, content: [],
      stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } });
  };
  const openText = () => {
    if (textOpen) return;
    textOpen = true;
    event("content_block_start", { index, content_block: { type: "text", text: "" } });
  };
  return {
    delta(piece) {
      start();
      if (!piece) return;
      openText();
      event("content_block_delta", { index, delta: { type: "text_delta", text: piece } });
    },
    finish(output, receipt, streamedAny) {
      start();
      const answer = answerOf(output);
      if (!streamedAny && answer.text) { openText(); event("content_block_delta", { index, delta: { type: "text_delta", text: answer.text } }); }
      if (!textOpen && !answer.calls.length) openText();
      if (textOpen) { event("content_block_stop", { index }); index += 1; }
      for (const call of answer.calls) {
        event("content_block_start", { index, content_block: { type: "tool_use", id: call.id, name: call.function?.name, input: {} } });
        event("content_block_delta", { index, delta: { type: "input_json_delta", partial_json: JSON.stringify(parseArguments(call.function?.arguments)) } });
        event("content_block_stop", { index });
        index += 1;
      }
      event("message_delta", { delta: { stop_reason: anthropicStop(answer), stop_sequence: null },
        usage: { input_tokens: Number(receipt.input_tokens), output_tokens: Number(receipt.output_tokens) } });
      event("message_stop", {});
    },
    fail(message) { start(); event("error", { error: { type: "api_error", message } }); },
  };
}

/** /v1/messages/count_tokens: an upper-bound estimate (UTF-8 bytes / 3, as prices are authorized). */
export function countAnthropicTokens(body) {
  const ask = fromAnthropic({ max_tokens: 1, ...body });
  const bytes = Buffer.byteLength(JSON.stringify(ask.messages), "utf8") + Buffer.byteLength(JSON.stringify(ask.options.tools || []), "utf8");
  return { input_tokens: Math.ceil(bytes / 3) };
}

export const anthropicError = (message, status) => ({ type: "error", error: {
  type: status === 401 || status === 403 ? "authentication_error" : status === 404 ? "not_found_error"
    : status === 402 ? "billing_error" : status >= 500 ? "api_error" : "invalid_request_error", message } });

// ---------------- OpenAI Responses (with tools) ----------------

/** Whether a Responses request needs the tool translation (tools, or tool calls and results in its input). */
export function responsesUsesTools(body) {
  return (Array.isArray(body.tools) && body.tools.length > 0)
    || (Array.isArray(body.input) && body.input.some((item) => /^(function_call|custom_tool_call)/.test(item?.type || "")));
}

/** POST /v1/responses body with tools -> { messages, options, custom } (custom: names of freeform tools). */
export function fromResponses(body) {
  const messages = [];
  if (body.instructions) messages.push({ role: "system", content: String(body.instructions) });
  const custom = new Set();
  const tools = [];
  for (const tool of body.tools || []) {
    if (tool?.type === "function" && tool.name) {
      tools.push({ type: "function", function: { name: tool.name, description: tool.description || "", parameters: tool.parameters || { type: "object", properties: {} } } });
    } else if (tool?.type === "custom" && tool.name) {
      // A freeform tool (Codex's apply_patch): one string argument carries its whole input.
      custom.add(tool.name);
      tools.push({ type: "function", function: { name: tool.name, description: `${tool.description || ""}\nPut the tool's complete raw input in the "input" string.`,
        parameters: { type: "object", properties: { input: { type: "string" } }, required: ["input"] } } });
    } // hosted tools (web search, file search, ...) cannot run on this network: they are left out
  }
  const input = typeof body.input === "string" ? [{ role: "user", content: body.input }] : body.input || [];
  const assistant = () => {
    const last = messages.at(-1);
    if (last?.role === "assistant") return last;
    const fresh = { role: "assistant", content: null, tool_calls: [] };
    messages.push(fresh);
    return fresh;
  };
  for (const item of input) {
    const type = item?.type || (item?.role ? "message" : "");
    if (type === "message") {
      const role = item.role === "developer" ? "system" : item.role;
      if (role === "assistant") { const a = assistant(); a.content = (a.content || "") + text(item.content, "assistant message"); }
      else messages.push({ role, content: role === "user" ? parts(item.content, "user message") : text(item.content, `${role} message`) });
    } else if (type === "function_call" || type === "custom_tool_call") {
      const a = assistant();
      (a.tool_calls ||= []).push({ id: item.call_id, type: "function", function: { name: item.name,
        arguments: type === "custom_tool_call" ? JSON.stringify({ input: item.input ?? "" }) : (item.arguments ?? "{}") } });
    } else if (type === "function_call_output" || type === "custom_tool_call_output") {
      const media = Array.isArray(item.output) ? item.output.map(mediaPart).filter(Boolean) : [];
      const output = typeof item.output === "string" ? item.output : text(item.output.filter((b) => !mediaPart(b)), "tool output");
      messages.push({ role: "tool", tool_call_id: item.call_id, content: output });
      if (media.length) messages.push({ role: "user", content: [{ type: "text", text: `Attachments returned by tool call ${item.call_id}:` }, ...media] });
    } // reasoning items and the like stay with the client
  }
  for (const message of messages) if (message.role === "assistant" && !message.tool_calls?.length) delete message.tool_calls;
  const options = {};
  for (const key of ["temperature", "top_p", "reasoning", "parallel_tool_calls"]) if (body[key] !== undefined) options[key] = body[key];
  if (tools.length) options.tools = tools;
  const choice = body.tool_choice;
  if (choice === "none" || choice === "required" || choice === "auto") options.tool_choice = choice;
  else if (choice?.name) options.tool_choice = { type: "function", function: { name: choice.name } };
  return { messages, options, custom };
}

/** A network answer (chat completion) as a Responses object, freeform tools as custom_tool_call items. */
export function toResponses(model, output, receipt, custom = new Set()) {
  const answer = answerOf(output);
  const items = [];
  if (answer.text || !answer.calls.length) {
    items.push({ type: "message", id: id("msg_"), role: "assistant", status: "completed",
      content: [{ type: "output_text", text: answer.text, annotations: [] }] });
  }
  for (const call of answer.calls) {
    const name = call.function?.name;
    items.push(custom.has(name)
      ? { type: "custom_tool_call", id: id("ctc_"), call_id: call.id, name, input: String(parseArguments(call.function?.arguments).input ?? ""), status: "completed" }
      : { type: "function_call", id: id("fc_"), call_id: call.id, name, arguments: call.function?.arguments || "{}", status: "completed" });
  }
  const input = Number(receipt?.input_tokens ?? output?.usage?.prompt_tokens ?? 0);
  const out = Number(receipt?.output_tokens ?? output?.usage?.completion_tokens ?? 0);
  return { id: id("resp_"), object: "response", created_at: Math.floor(Date.now() / 1000), model, status: "completed",
    output: items, output_text: answer.text, usage: { input_tokens: input, output_tokens: out, total_tokens: input + out } };
}

// ---------------- Gemini generateContent ----------------

const GEMINI_PATH = /^\/(?:v1|v1beta|v1alpha)\/models\/([^/:]+):(generateContent|streamGenerateContent|countTokens)$/;

/** The model and whether it streams, for a Gemini path; null for any other path. */
export function geminiRoute(path) {
  const match = GEMINI_PATH.exec(path);
  return match ? { model: decodeURIComponent(match[1]), stream: match[2] === "streamGenerateContent", count: match[2] === "countTokens" } : null;
}

const partsOf = (value, where) => parts(value, where);

export function fromGemini(body, model) {
  if (!Array.isArray(body.contents)) throw new DialectError("contents are required");
  const messages = [];
  const system = body.systemInstruction || body.system_instruction;
  if (system) messages.push({ role: "system", content: text(system.parts ?? system, "systemInstruction") });
  // Gemini answers a call by the function's name; the network by an id. Pair each response with the
  // earliest unanswered call of that name.
  const open = [];
  let counter = 0;
  for (const item of body.contents) {
    const parts = item.parts || [];
    const calls = parts.filter((p) => p.functionCall);
    const results = parts.filter((p) => p.functionResponse);
    const said = parts.filter((p) => !p.functionCall && !p.functionResponse);
    const words = item.role === "model" ? text(said, "model content") : partsOf(said, "user content");
    if (item.role === "model") {
      const toolCalls = calls.map((p) => {
        const call = { id: p.functionCall.id || `call_${counter++}`, type: "function",
          function: { name: p.functionCall.name, arguments: JSON.stringify(p.functionCall.args ?? {}) } };
        open.push(call);
        return call;
      });
      messages.push({ role: "assistant", content: words || (toolCalls.length ? null : ""), ...(toolCalls.length ? { tool_calls: toolCalls } : {}) });
      continue;
    }
    for (const part of results) {  // results first: they answer the calls the model just made
      const index = open.findIndex((call) => call.function.name === part.functionResponse.name);
      const call = index >= 0 ? open.splice(index, 1)[0] : null;
      messages.push({ role: "tool", tool_call_id: part.functionResponse.id || call?.id || `call_${counter++}`,
        content: JSON.stringify(part.functionResponse.response ?? {}) });
    }
    if ((typeof words === "string" ? words : words.length) || !results.length) messages.push({ role: "user", content: words });
  }
  const config = body.generationConfig || body.generation_config || {};
  const options = {};
  if (config.temperature !== undefined) options.temperature = config.temperature;
  if (config.topP !== undefined) options.top_p = config.topP;
  if (config.stopSequences) options.stop = config.stopSequences;
  const declarations = (body.tools || []).flatMap((t) => t.functionDeclarations || t.function_declarations || []);
  if (declarations.length) {
    options.tools = declarations.map((d) => ({ type: "function", function: { name: d.name, description: d.description || "",
      parameters: d.parametersJsonSchema || d.parameters || { type: "object", properties: {} } } }));
    const mode = body.toolConfig?.functionCallingConfig?.mode;
    if (mode === "NONE") options.tool_choice = "none";
    else if (mode === "ANY") options.tool_choice = "required";
  }
  return { model, messages, maxOutputTokens: config.maxOutputTokens ?? 4096, options };
}

function geminiParts(piece, calls = []) {
  const parts = piece ? [{ text: piece }] : [];
  for (const call of calls) parts.push({ functionCall: { name: call.function?.name, args: parseArguments(call.function?.arguments) } });
  return parts.length ? parts : [{ text: "" }];
}

function geminiChunk(model, parts, receipt) {
  const chunk = { candidates: [{ content: { role: "model", parts }, index: 0 }], modelVersion: model };
  if (receipt) {
    chunk.candidates[0].finishReason = "STOP";
    const input = Number(receipt.input_tokens); const output = Number(receipt.output_tokens);
    chunk.usageMetadata = { promptTokenCount: input, candidatesTokenCount: output, totalTokenCount: input + output };
  }
  return chunk;
}

export const toGemini = (model, output, receipt) => {
  const answer = answerOf(output);
  return geminiChunk(model, geminiParts(answer.text, answer.calls), receipt);
};

/** countTokens: an upper-bound estimate (UTF-8 bytes / 3, as prices are authorized). */
export function countGeminiTokens(body, model) {
  const ask = fromGemini({ contents: [], ...body }, model);
  const bytes = Buffer.byteLength(JSON.stringify(ask.messages), "utf8") + Buffer.byteLength(JSON.stringify(ask.options.tools || []), "utf8");
  return { totalTokens: Math.ceil(bytes / 3) };
}

/** streamGenerateContent with alt=sse: one JSON chunk per event; the last carries calls, finishReason and usage. */
export function geminiStream(write, model) {
  const chunk = (value) => write(`data: ${JSON.stringify(value)}\n\n`);
  return {
    delta(piece) { if (piece) chunk(geminiChunk(model, [{ text: piece }])); },
    finish(output, receipt, streamedAny) {
      const answer = answerOf(output);
      chunk(geminiChunk(model, geminiParts(streamedAny ? "" : answer.text, answer.calls), receipt));
    },
    fail(message) { chunk({ error: { code: 500, message, status: "INTERNAL" } }); },
  };
}

export const geminiError = (message, status) => ({ error: { code: status, message,
  status: status === 400 ? "INVALID_ARGUMENT" : status === 401 || status === 403 ? "PERMISSION_DENIED"
    : status === 404 ? "NOT_FOUND" : status === 402 ? "RESOURCE_EXHAUSTED" : "INTERNAL" } });
