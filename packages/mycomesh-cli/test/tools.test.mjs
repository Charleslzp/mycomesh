// Tool calling through every dialect: the client's tools and results go out in the network's one shape (OpenAI
// Chat), and the model's calls come back in the client's own shape, streamed or not.
import assert from "node:assert/strict";
import test from "node:test";
import { anthropicStream, countAnthropicTokens, fromAnthropic, fromGemini, fromResponses, responsesUsesTools, toAnthropic,
  toGemini, toResponses } from "../src/dialects.mjs";
import { planRequest } from "../src/protocol.mjs";
import { chatStream } from "../src/sse.mjs";

const call = (id, name, args) => ({ id, type: "function", function: { name, arguments: JSON.stringify(args) } });
const completion = (content, calls = []) => ({ choices: [{ index: 0, message: { role: "assistant", content, ...(calls.length ? { tool_calls: calls } : {}) },
  finish_reason: calls.length ? "tool_calls" : "stop" }], usage: { prompt_tokens: 10, completion_tokens: 5 } });
const receipt = { input_tokens: 10, output_tokens: 5 };

test("Anthropic: tools, tool_use and tool_result go out as chat; calls come back as tool_use blocks", () => {
  const ask = fromAnthropic({ model: "gpt-5.5", max_tokens: 1000, system: [{ type: "text", text: "Be brief.", cache_control: { type: "ephemeral" } }],
    tools: [{ name: "Bash", description: "run a command", input_schema: { type: "object", properties: { command: { type: "string" } } } }],
    tool_choice: { type: "auto" },
    messages: [
      { role: "user", content: "list files" },
      { role: "assistant", content: [{ type: "text", text: "Listing." }, { type: "tool_use", id: "toolu_1", name: "Bash", input: { command: "ls" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: [{ type: "text", text: "a.txt\nb.txt" }] }] },
    ] });
  assert.deepEqual(ask.messages, [
    { role: "system", content: "Be brief." },
    { role: "user", content: "list files" },
    { role: "assistant", content: "Listing.", tool_calls: [call("toolu_1", "Bash", { command: "ls" })] },
    { role: "tool", tool_call_id: "toolu_1", content: "a.txt\nb.txt" },
  ]);
  assert.deepEqual(ask.options.tools, [{ type: "function", function: { name: "Bash", description: "run a command",
    parameters: { type: "object", properties: { command: { type: "string" } } } } }]);
  const out = toAnthropic("gpt-5.5", completion(null, [call("call_9", "Bash", { command: "cat a.txt" })]), receipt);
  assert.equal(out.stop_reason, "tool_use");
  assert.deepEqual(out.content, [{ type: "tool_use", id: "call_9", name: "Bash", input: { command: "cat a.txt" } }]);
  assert.ok(countAnthropicTokens({ model: "m", messages: [{ role: "user", content: "hi" }] }).input_tokens > 0);
});

test("Anthropic streaming: text first, then each tool_use block with its input", () => {
  let wire = "";
  const writer = anthropicStream((chunk) => { wire += chunk; }, "gpt-5.5");
  writer.delta("Let me look.");
  writer.finish(completion("Let me look.", [call("call_1", "Read", { path: "a.txt" }), call("call_2", "Read", { path: "b.txt" })]), receipt, true);
  const events = wire.trim().split("\n\n").map((block) => JSON.parse(block.split("\n")[1].slice(6)));
  assert.deepEqual(events.map((e) => e.type), ["message_start", "content_block_start", "content_block_delta", "content_block_stop",
    "content_block_start", "content_block_delta", "content_block_stop", "content_block_start", "content_block_delta", "content_block_stop",
    "message_delta", "message_stop"]);
  assert.deepEqual(events[4].content_block, { type: "tool_use", id: "call_1", name: "Read", input: {} });
  assert.equal(events[5].delta.partial_json, '{"path":"a.txt"}');
  assert.equal(events[7].index, 2);
  assert.equal(events.at(-2).delta.stop_reason, "tool_use");
});

test("Responses: function and freeform tools, calls and outputs; calls come back as items", () => {
  const body = { model: "gpt-5.5", instructions: "You are Codex.",
    tools: [{ type: "function", name: "shell", parameters: { type: "object", properties: { command: { type: "array" } } } },
      { type: "custom", name: "apply_patch", description: "Patch files" }, { type: "web_search" }],
    input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "fix it" }] },
      { type: "reasoning", summary: [] },
      { type: "function_call", call_id: "c1", name: "shell", arguments: '{"command":["ls"]}' },
      { type: "function_call_output", call_id: "c1", output: "main.py" },
      { type: "custom_tool_call", call_id: "c2", name: "apply_patch", input: "*** Begin Patch" },
      { type: "custom_tool_call_output", call_id: "c2", output: "done" }] };
  assert.ok(responsesUsesTools(body));
  const { messages, options, custom } = fromResponses(body);
  assert.deepEqual(messages, [
    { role: "system", content: "You are Codex." }, { role: "user", content: "fix it" },
    { role: "assistant", content: null, tool_calls: [call("c1", "shell", { command: ["ls"] })] },
    { role: "tool", tool_call_id: "c1", content: "main.py" },
    { role: "assistant", content: null, tool_calls: [{ id: "c2", type: "function", function: { name: "apply_patch", arguments: '{"input":"*** Begin Patch"}' } }] },
    { role: "tool", tool_call_id: "c2", content: "done" }]);
  assert.deepEqual(options.tools.map((t) => t.function.name), ["shell", "apply_patch"]); // hosted web_search left out
  const out = toResponses("gpt-5.5", completion("", [call("c3", "apply_patch", { input: "*** Begin Patch\n+x" }), call("c4", "shell", { command: ["pytest"] })]), receipt, custom);
  assert.deepEqual(out.output.map((i) => [i.type, i.call_id, i.input ?? i.arguments]),
    [["custom_tool_call", "c3", "*** Begin Patch\n+x"], ["function_call", "c4", '{"command":["pytest"]}']]);
  assert.equal(responsesUsesTools({ input: "hi" }), false);
});

test("Gemini: function responses are paired with their calls by name; calls come back as functionCall parts", () => {
  const ask = fromGemini({ tools: [{ functionDeclarations: [{ name: "read_file", parametersJsonSchema: { type: "object" } }] }],
    contents: [{ role: "user", parts: [{ text: "read a" }] },
      { role: "model", parts: [{ functionCall: { name: "read_file", args: { path: "a" } } }] },
      { role: "user", parts: [{ functionResponse: { name: "read_file", response: { content: "AAA" } } }] }] }, "gpt-5.5");
  assert.equal(ask.messages[1].tool_calls[0].function.name, "read_file");
  assert.equal(ask.messages[2].role, "tool");
  assert.equal(ask.messages[2].tool_call_id, ask.messages[1].tool_calls[0].id);
  assert.equal(ask.options.tools[0].function.name, "read_file");
  const out = toGemini("gpt-5.5", completion(null, [call("x", "read_file", { path: "b" })]), receipt);
  assert.deepEqual(out.candidates[0].content.parts, [{ functionCall: { name: "read_file", args: { path: "b" } } }]);
});

test("chat streaming ends with the tool calls; the price authorized counts the tool definitions", () => {
  let wire = "";
  const writer = chatStream((chunk) => { wire += chunk; }, { model: "gpt-5.5" });
  writer.finish(completion(null, [call("c1", "shell", { command: "ls" })]));
  const chunks = wire.split("\n\n").filter((l) => l.startsWith("data: {")).map((l) => JSON.parse(l.slice(6)));
  assert.equal(chunks.at(-2).choices[0].delta.tool_calls[0].function.name, "shell");
  assert.equal(chunks.at(-1).choices[0].finish_reason, "tool_calls");
  const descriptor = { input_overhead_tokens: 0, prices: { input_per_1k: 7, output_per_1k: 628, minimum_fee: 1 } };
  const tools = [{ type: "function", function: { name: "t", description: "x".repeat(30_000), parameters: {} } }];
  const bare = planRequest(descriptor, "chat", [{ role: "user", content: "hi" }], 100, 1_000_000).maxFee;
  const withTools = planRequest(descriptor, "chat", [{ role: "user", content: "hi" }], 100, 1_000_000, tools).maxFee;
  assert.ok(withTools > bare + 100, `${withTools} vs ${bare}`);
});
