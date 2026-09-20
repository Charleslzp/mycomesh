import { randomUUID } from "node:crypto";

// Routing-only hints: never forward these as Gateway stateful-history headers.
export const CONSUMER_SESSION_HEADERS = Object.freeze([
  "x-mycomesh-session-id",
  "x-session-id",
  "session_id",
]);

const TOOL_CALL_TYPES = new Set([
  "tool_call", "function_call", "local_shell_call", "tool_search_call",
  "custom_tool_call", "mcp_tool_call",
]);
const TOOL_OUTPUT_TYPES = new Set([
  "function_call_output", "tool_search_output", "custom_tool_call_output",
  "mcp_tool_call_output",
]);

export class ConsumerSessionError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = "ConsumerSessionError";
    this.statusCode = statusCode;
    this.status = statusCode;
    this.code = statusCode === 409 ? "session_continuation_unavailable" : "invalid_session";
  }
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validIdentifier(value, limit) {
  return typeof value === "string" && value.length > 0 && value.length <= limit
    && /^[\x21-\x7e]+$/.test(value) && !value.includes(",");
}

function sessionIdentifier(value) {
  if (!validIdentifier(value, 128)) {
    throw new ConsumerSessionError("Session id must be 1–128 printable ASCII characters without whitespace or commas");
  }
  return value;
}

function headerSignals(headers) {
  const values = [];
  const entries = typeof headers?.entries === "function"
    ? headers.entries() : Object.entries(headers || {});
  for (const [name, value] of entries) {
    if (!CONSUMER_SESSION_HEADERS.includes(name.toLowerCase())) continue;
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      if (value.length !== 1) throw new ConsumerSessionError("Duplicate session headers are not allowed");
      values.push(sessionIdentifier(value[0]));
    } else {
      values.push(sessionIdentifier(value));
    }
  }
  return values;
}

function toolReferences(body) {
  const context = new Set();
  const outputs = [];
  for (const item of Array.isArray(body.input) ? body.input : []) {
    if (!object(item)) continue;
    if (TOOL_CALL_TYPES.has(item.type) && validIdentifier(item.call_id, 256)) context.add(item.call_id);
    if (TOOL_OUTPUT_TYPES.has(item.type)) outputs.push(item.call_id);
  }
  for (const message of Array.isArray(body.messages) ? body.messages : []) {
    if (!object(message)) continue;
    if (message.role === "assistant" && Array.isArray(message.tool_calls)) {
      for (const call of message.tool_calls) {
        if (object(call) && validIdentifier(call.id, 256)) context.add(call.id);
      }
    }
    if (message.role === "tool") outputs.push(message.tool_call_id);
  }
  return { context, outputs };
}

/**
 * One instance belongs to one authenticated Consumer routing namespace.
 * No prompt, cache key, wallet, or payment request id is treated as a session.
 * Continuation mappings are process-local, bounded, and expire after inactivity.
 */
export class ConsumerSessions {
  constructor({ ttlMs = 30 * 60_000, maxEntries = 10_000, now = Date.now, generateId = randomUUID } = {}) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || !Number.isSafeInteger(maxEntries) || maxEntries <= 0) {
      throw new TypeError("Session TTL and capacity must be positive safe integers");
    }
    if (typeof now !== "function" || typeof generateId !== "function") {
      throw new TypeError("Session clock and id generator must be functions");
    }
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.now = now;
    this.generateId = generateId;
    this.entries = new Map();
  }

  get size() {
    this.prune(this.now());
    return this.entries.size;
  }

  prune(now) {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }

  resolve(body, headers = {}) {
    if (!object(body)) throw new ConsumerSessionError("Request body must be a JSON object");
    if (body.metadata != null && !object(body.metadata)) {
      throw new ConsumerSessionError("Request metadata must be a JSON object");
    }
    const signals = headerSignals(headers);
    if (Object.hasOwn(body.metadata || {}, "mycomesh_session_id")) {
      signals.push(sessionIdentifier(body.metadata.mycomesh_session_id));
    }
    if (body.conversation != null) {
      const value = object(body.conversation) ? body.conversation.id : body.conversation;
      signals.push(sessionIdentifier(value));
    }
    if (new Set(signals).size > 1) throw new ConsumerSessionError("Explicit session identifiers disagree");

    const now = this.now();
    this.prune(now);
    const continuationSessions = new Set();
    const matchedKeys = new Set();
    const resolveReference = (kind, value, selfContained = false) => {
      if (!validIdentifier(value, 256)) {
        throw new ConsumerSessionError("Continuation reference must be a nonempty ASCII identifier", 409);
      }
      const key = `${kind}:${value}`;
      const entry = this.entries.get(key);
      // Full-history SDK/Codex requests may include old call+output pairs and
      // are already supported statelessly by the Provider backend. An explicit
      // new session may fork that history without inheriting its old route.
      if (selfContained && signals.length) return;
      if (!entry && selfContained) return;
      if (!entry || !entry.sessionId) {
        throw new ConsumerSessionError("Continuation is unknown, expired, or ambiguous; its original route is unavailable", 409);
      }
      continuationSessions.add(entry.sessionId);
      matchedKeys.add(key);
    };
    if (body.previous_response_id != null) resolveReference("response", body.previous_response_id);
    const { context, outputs } = toolReferences(body);
    for (const callId of outputs) resolveReference("call", callId, context.has(callId));
    if (continuationSessions.size > 1) {
      throw new ConsumerSessionError("Continuation references belong to different sessions", 409);
    }
    const previousSession = continuationSessions.values().next().value;
    if (previousSession && signals.length && previousSession !== signals[0]) {
      throw new ConsumerSessionError("Explicit session does not match the continuation's original session", 409);
    }
    const id = signals[0] || previousSession || sessionIdentifier(this.generateId());
    for (const key of matchedKeys) {
      const entry = this.entries.get(key);
      this.entries.delete(key);
      this.entries.set(key, { ...entry, expiresAt: now + this.ttlMs });
    }
    return {
      id,
      body: { ...body, metadata: { ...body.metadata, mycomesh_session_id: id } },
      explicit: signals.length > 0,
      requiresOriginalRoute: matchedKeys.size > 0,
    };
  }

  // Accept either a raw OpenAI response or relayInference's {status, payload}.
  // Call only after the actual request succeeded on the selected route.
  remember(result, sessionId) {
    sessionIdentifier(sessionId);
    if (!object(result) || (typeof result.status === "number" && (result.status < 200 || result.status >= 300))) return 0;
    const payload = object(result.payload) ? result.payload : result;
    if (payload.error) return 0;
    const now = this.now();
    this.prune(now);
    let remembered = 0;
    const save = (kind, value) => {
      if (!validIdentifier(value, 256)) return;
      const key = `${kind}:${value}`;
      const previous = this.entries.get(key);
      // A reused upstream id must not silently transfer a continuation route.
      const resolvedSession = previous && previous.sessionId !== sessionId ? null : sessionId;
      this.entries.delete(key);
      this.entries.set(key, { sessionId: resolvedSession, expiresAt: now + this.ttlMs });
      while (this.entries.size > this.maxEntries) this.entries.delete(this.entries.keys().next().value);
      remembered += 1;
    };
    save("response", payload.id);
    for (const item of Array.isArray(payload.output) ? payload.output : []) {
      if (object(item) && TOOL_CALL_TYPES.has(item.type)) save("call", item.call_id);
    }
    for (const choice of Array.isArray(payload.choices) ? payload.choices : []) {
      for (const call of Array.isArray(choice?.message?.tool_calls) ? choice.message.tool_calls : []) {
        if (object(call)) save("call", call.id);
      }
    }
    return remembered;
  }
}
