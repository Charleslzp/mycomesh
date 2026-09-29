// Buffered SSE for OpenAI clients (Codex needs the Responses event sequence).
// Port of the event order in the former gateway/openai_protocol.py.
import { randomUUID } from "node:crypto";

const TERMINAL = { completed: "response.completed", incomplete: "response.incomplete", failed: "response.failed" };
const PREFIX = { message: "msg", reasoning: "rs", function_call: "fc", custom_tool_call: "ct" };

const sse = (event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;

function normalize(payload) {
  const response = structuredClone(payload || {});
  response.id ||= `resp_${randomUUID().replace(/-/g, "")}`;
  response.object ||= "response";
  response.created_at ||= Math.floor(Date.now() / 1000);
  response.status = TERMINAL[response.status] ? response.status : "completed";
  response.output = (Array.isArray(response.output) ? response.output : []).filter((item) => item && typeof item === "object")
    .map((item) => ({ ...item, type: item.type || "unknown", id: item.id || `${PREFIX[item.type] || "item"}_${randomUUID().replace(/-/g, "")}` }));
  response.error ??= null;
  response.incomplete_details ??= null;
  if (typeof response.output_text !== "string") {
    response.output_text = response.output.filter((item) => item.type === "message")
      .flatMap((item) => item.content || []).filter((part) => part.type === "output_text").map((part) => part.text || "").join("");
  }
  return response;
}

function added(item) {
  const copy = structuredClone(item);
  copy.status = "in_progress";
  if (copy.type === "message") copy.content = [];
  if (copy.type === "reasoning") { copy.summary = []; if ("content" in copy) copy.content = []; }
  if (copy.type === "function_call") copy.arguments = "";
  if (copy.type === "custom_tool_call") copy.input = "";
  return copy;
}

export function responseSse(payload) {
  const final = normalize(payload);
  const out = [];
  let sequence = 0;
  const emit = (type, fields) => out.push(sse({ type, sequence_number: sequence++, ...fields }));
  const created = { ...structuredClone(final), status: "in_progress", output: [], output_text: "", usage: null };
  emit("response.created", { response: created });
  emit("response.in_progress", { response: created });
  final.output.forEach((item, output_index) => {
    const item_id = item.id;
    emit("response.output_item.added", { output_index, item: added(item) });
    if (item.type === "message") {
      (item.content || []).forEach((part, content_index) => {
        emit("response.content_part.added", { item_id, output_index, content_index, part: { ...part, text: part.type === "output_text" ? "" : part.text } });
        if (part.type === "output_text") {
          if (part.text) emit("response.output_text.delta", { item_id, output_index, content_index, delta: part.text, logprobs: [] });
          emit("response.output_text.done", { item_id, output_index, content_index, text: part.text || "", logprobs: [] });
        }
        emit("response.content_part.done", { item_id, output_index, content_index, part });
      });
    } else if (item.type === "reasoning") {
      (item.summary || []).forEach((part, summary_index) => {
        emit("response.reasoning_summary_part.added", { item_id, output_index, summary_index, part: { ...part, type: "summary_text", text: "" } });
        if (part.text) emit("response.reasoning_summary_text.delta", { item_id, output_index, summary_index, delta: part.text });
        emit("response.reasoning_summary_text.done", { item_id, output_index, summary_index, text: part.text || "" });
        emit("response.reasoning_summary_part.done", { item_id, output_index, summary_index, part });
      });
    } else if (item.type === "function_call") {
      if (item.arguments) emit("response.function_call_arguments.delta", { item_id, output_index, delta: item.arguments });
      emit("response.function_call_arguments.done", { item_id, output_index, call_id: item.call_id || "", name: item.name || "", arguments: item.arguments || "" });
    } else if (item.type === "custom_tool_call") {
      if (item.input) emit("response.custom_tool_call_input.delta", { item_id, output_index, delta: item.input });
      emit("response.custom_tool_call_input.done", { item_id, output_index, call_id: item.call_id || "", name: item.name || "", input: item.input || "" });
    }
    emit("response.output_item.done", { output_index, item });
  });
  emit(TERMINAL[final.status], { response: final });
  return out.join("");
}

export function chatSse(payload, { includeUsage = false } = {}) {
  const id = payload.id || `chatcmpl_${randomUUID().replace(/-/g, "")}`;
  const model = payload.model || "";
  const created = payload.created || Math.floor(Date.now() / 1000);
  const chunk = (index, delta, finish_reason) =>
    `data: ${JSON.stringify({ id, object: "chat.completion.chunk", created, model, choices: [{ index, delta, finish_reason }] })}\n\n`;
  const out = [];
  (payload.choices || []).forEach((choice, fallback) => {
    const index = Number.isInteger(choice.index) ? choice.index : fallback;
    const message = choice.message || {};
    out.push(chunk(index, { role: message.role || "assistant" }, null));
    if (typeof message.content === "string" && message.content) out.push(chunk(index, { content: message.content }, null));
    const tools = Array.isArray(message.tool_calls) ? message.tool_calls : [];
    tools.forEach((tool, toolIndex) => out.push(chunk(index, { tool_calls: [{
      index: toolIndex, id: tool.id || `call_${randomUUID().slice(0, 24)}`, type: tool.type || "function",
      function: { name: tool.function?.name || "", arguments: tool.function?.arguments || "" },
    }] }, null)));
    out.push(chunk(index, {}, choice.finish_reason || (tools.length ? "tool_calls" : "stop")));
  });
  if (includeUsage && payload.usage) {
    out.push(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created, model, choices: [], usage: payload.usage })}\n\n`);
  }
  out.push("data: [DONE]\n\n");
  return out.join("");
}
