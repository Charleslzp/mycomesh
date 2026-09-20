import assert from "node:assert/strict";
import test from "node:test";
import { ConsumerSessions } from "../src/consumer-sessions.mjs";

const fails = (statusCode) => (error) => error.statusCode === statusCode;

test("independent equal prompts/cache keys never become one session", () => {
  const sessions = new ConsumerSessions();
  const body = { input: "same prompt", prompt_cache_key: "same-cache", user: "same-user", request_id: "payment-id" };
  const first = sessions.resolve(body);
  const second = sessions.resolve(body);
  assert.notEqual(first.id, second.id);
  assert.equal(first.explicit, false);
  assert.equal(first.requiresOriginalRoute, false);
  assert.equal(second.explicit, false);
  assert.equal(first.body.prompt_cache_key, "same-cache");
  assert.equal(first.body.request_id, "payment-id");
  assert.equal(first.body.metadata.mycomesh_session_id, first.id);
  assert.equal(body.metadata, undefined);
});

test("explicit headers and Responses metadata/conversation work without mutating input", () => {
  const sessions = new ConsumerSessions();
  const variants = [
    [{ input: "a" }, { "X-MycoMesh-Session-ID": "session-a" }],
    [{ input: "b" }, { "x-session-id": ["session-a"] }],
    [{ input: "c" }, { session_id: "session-a" }],
    [{ metadata: { mycomesh_session_id: "session-a", kept: "value" } }, {}],
    [{ conversation: "session-a" }, {}],
    [{ conversation: { id: "session-a" } }, new Headers({ "x-session-id": "session-a" })],
  ];
  for (const [body, headers] of variants) {
    const original = JSON.stringify(body);
    const result = sessions.resolve(body, headers);
    assert.equal(result.id, "session-a");
    assert.equal(result.explicit, true);
    assert.equal(JSON.stringify(body), original);
    assert.notEqual(result.body.metadata, body.metadata);
    if (body.metadata?.kept) assert.equal(result.body.metadata.kept, "value");
  }
});

test("payment sessions, generic session_id and unverified Codex turn headers are not inferred", () => {
  const sessions = new ConsumerSessions({ generateId: () => "fresh" });
  const result = sessions.resolve({
    session_id: "legacy", mycomesh_session: { session_id: "escrow" },
    client_metadata: { session_id: "unverified" },
  }, { turn_id: "turn", "x-codex-turn-metadata": "opaque" });
  assert.equal(result.id, "fresh");
  assert.equal(result.explicit, false);
});

test("conflicting explicit hints and malformed identifiers fail before forwarding", () => {
  const sessions = new ConsumerSessions();
  assert.throws(() => sessions.resolve({ conversation: "a" }, { "x-session-id": "b" }), fails(400));
  assert.throws(() => sessions.resolve({}, { session_id: "a", "x-session-id": "b" }), fails(400));
  assert.throws(() => sessions.resolve({}, { "x-session-id": ["a", "a"] }), fails(400));
  assert.throws(() => sessions.resolve({}, { "x-session-id": "a, b" }), fails(400));
  for (const value of ["", "a\nb", "has space", "中文", "x".repeat(129), 1, true, null, {}]) {
    assert.throws(() => sessions.resolve({ metadata: { mycomesh_session_id: value } }), fails(400));
  }
  for (const body of [null, [], { metadata: "bad" }, { metadata: [] }, { conversation: {} }]) {
    assert.throws(() => sessions.resolve(body), fails(400));
  }
  assert.equal(sessions.resolve({ metadata: { mycomesh_session_id: "x".repeat(128) } }).id.length, 128);
});

test("previous_response_id continues the actual remembered session but never replaces billing ids", () => {
  const sessions = new ConsumerSessions();
  sessions.remember({ status: 200, payload: { id: "resp-a", output: [] } }, "session-a");
  const result = sessions.resolve({ previous_response_id: "resp-a", input: "next", request_id: "new-payment" });
  assert.equal(result.id, "session-a");
  assert.equal(result.explicit, false);
  assert.equal(result.body.previous_response_id, "resp-a");
  assert.equal(result.requiresOriginalRoute, true);
  assert.equal(result.body.request_id, "new-payment");
  assert.throws(() => sessions.resolve({ previous_response_id: "missing" }, { "x-session-id": "a" }), fails(409));
  assert.throws(() => sessions.resolve({ previous_response_id: "resp-a", conversation: "b" }), fails(409));
  assert.throws(() => sessions.resolve({ previous_response_id: "" }), fails(409));
});

test("Responses and Chat tool outputs use remembered call IDs", () => {
  const sessions = new ConsumerSessions();
  sessions.remember({ id: "resp-a", output: [{ type: "function_call", call_id: "call-a" }] }, "session-a");
  sessions.remember({ id: "chat-a", choices: [{ message: { tool_calls: [{ id: "call-chat" }] } }] }, "session-a");
  for (const body of [
    { input: [{ type: "function_call_output", call_id: "call-a", output: "done" }] },
    { input: [{ type: "custom_tool_call_output", call_id: "call-a", output: "done" }] },
    { messages: [{ role: "tool", tool_call_id: "call-chat", content: "done" }] },
  ]) assert.equal(sessions.resolve(body).id, "session-a");
  assert.throws(() => sessions.resolve({ input: [{ type: "function_call_output", call_id: "missing" }] }), fails(409));
  assert.throws(() => sessions.resolve({ messages: [{ role: "tool", content: "missing id" }] }), fails(409));
});

test("self-contained SDK/Codex tool history remains statelessly usable after restart", () => {
  const sessions = new ConsumerSessions({ generateId: () => "fresh" });
  const body = { input: [
    { type: "function_call", call_id: "old-call", name: "tool", arguments: "{}" },
    { type: "function_call_output", call_id: "old-call", output: "old result" },
    { role: "user", content: "next" },
  ] };
  assert.equal(sessions.resolve(body).id, "fresh");
  assert.equal(sessions.resolve(body, { "x-session-id": "resume" }).id, "resume");
  assert.equal(sessions.resolve({ messages: [
    { role: "assistant", tool_calls: [{ id: "old-chat-call" }] },
    { role: "tool", tool_call_id: "old-chat-call", content: "old result" },
  ] }).id, "fresh");
  // Without an explicit fork, a known route is reused; full history can fork.
  sessions.remember({ output: [{ type: "function_call", call_id: "old-call" }] }, "original");
  assert.equal(sessions.resolve(body).id, "original");
  assert.equal(sessions.resolve(body).requiresOriginalRoute, true);
  assert.equal(sessions.resolve(body, { "x-session-id": "other" }).id, "other");
  assert.equal(sessions.resolve(body, { "x-session-id": "other" }).requiresOriginalRoute, false);
  sessions.remember({ id: "previous", output: [{ type: "function_call", call_id: "pending" }] }, "original");
  assert.throws(() => sessions.resolve({ ...body, previous_response_id: "previous" }, { session_id: "fork" }), fails(409));
  assert.throws(() => sessions.resolve({ input: [...body.input,
    { type: "function_call_output", call_id: "pending", output: "done" },
  ] }, { session_id: "fork" }), fails(409));
});

test("Chat full-history tool pairs also support explicit forks", () => {
  const sessions = new ConsumerSessions();
  sessions.remember({ choices: [{ message: { tool_calls: [{ id: "call-chat" }] } }] }, "original");
  const body = { messages: [
    { role: "assistant", tool_calls: [{ id: "call-chat" }] },
    { role: "tool", tool_call_id: "call-chat", content: "old result" },
  ] };
  assert.equal(sessions.resolve(body).id, "original");
  assert.equal(sessions.resolve(body, { session_id: "fork" }).id, "fork");
  assert.throws(() => sessions.resolve({ messages: [body.messages[1]] }, { session_id: "fork" }), fails(409));
});

test("mixed continuation sessions and reused upstream identifiers cannot merge routes", () => {
  const sessions = new ConsumerSessions();
  sessions.remember({ id: "resp-a", output: [{ type: "function_call", call_id: "call-a" }] }, "a");
  sessions.remember({ id: "resp-b", output: [{ type: "function_call", call_id: "call-b" }] }, "b");
  assert.throws(() => sessions.resolve({ previous_response_id: "resp-a", input: [{ type: "function_call_output", call_id: "call-b" }] }), fails(409));
  sessions.remember({ id: "resp-a" }, "b");
  sessions.remember({ id: "resp-a" }, "a");
  assert.throws(() => sessions.resolve({ previous_response_id: "resp-a" }), fails(409));
});

test("mappings expire, refresh on valid continuation, and have bounded capacity", () => {
  let now = 0;
  const sessions = new ConsumerSessions({ ttlMs: 100, maxEntries: 2, now: () => now });
  sessions.remember({ id: "a" }, "session-a");
  sessions.remember({ id: "b" }, "session-b");
  now = 50;
  sessions.resolve({ previous_response_id: "a" });
  sessions.remember({ id: "c" }, "session-c");
  assert.equal(sessions.size, 2);
  assert.throws(() => sessions.resolve({ previous_response_id: "b" }), fails(409));
  now = 149;
  assert.equal(sessions.resolve({ previous_response_id: "a" }).id, "session-a");
  now = 150;
  assert.throws(() => sessions.resolve({ previous_response_id: "c" }), fails(409));
  now = 249;
  assert.throws(() => sessions.resolve({ previous_response_id: "a" }), fails(409));
  assert.equal(sessions.size, 0);
});

test("errors are not remembered and separate instances cannot recover each other's routes", () => {
  const sessions = new ConsumerSessions();
  for (const response of [null, { status: 503, payload: { id: "failed" } }, { error: { message: "bad" }, id: "failed" }]) {
    assert.equal(sessions.remember(response, "a"), 0);
  }
  assert.throws(() => sessions.resolve({ previous_response_id: "failed" }), fails(409));
  sessions.remember({ id: "only-first" }, "a");
  assert.throws(() => new ConsumerSessions().resolve({ previous_response_id: "only-first" }), fails(409));
});

test("invalid capacity and clock dependencies are rejected", () => {
  for (const options of [{ ttlMs: 0 }, { maxEntries: -1 }, { maxEntries: 1.5 }, { now: null }, { generateId: null }]) {
    assert.throws(() => new ConsumerSessions(options), TypeError);
  }
});
