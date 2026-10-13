// Images and documents in every dialect become the network's parts; Providers get them only if they read them.
import assert from "node:assert/strict";
import test from "node:test";
import { inputKinds } from "../src/consumer.mjs";
import { fromAnthropic, fromGemini, fromResponses, parts } from "../src/dialects.mjs";

const PNG = "iVBORw0KGgo=";

test("Anthropic images and documents, and images a tool returned", () => {
  const ask = fromAnthropic({ model: "m", max_tokens: 10, messages: [
    { role: "user", content: [{ type: "text", text: "what is this?" }, { type: "image", source: { type: "base64", media_type: "image/png", data: PNG } },
      { type: "document", title: "spec.pdf", source: { type: "base64", media_type: "application/pdf", data: "JVBERi0=" } }] },
    { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Read", input: { file_path: "shot.png" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: PNG } }] }] },
  ] });
  assert.deepEqual(ask.messages[0].content, [{ type: "text", text: "what is this?" }, { type: "image_url", image_url: { url: `data:image/png;base64,${PNG}` } },
    { type: "file", file: { filename: "spec.pdf", file_data: "data:application/pdf;base64,JVBERi0=" } }]);
  assert.deepEqual(ask.messages[2], { role: "tool", tool_call_id: "t1", content: "\n[1 attachment(s) follow]" });
  assert.deepEqual(ask.messages[3], { role: "user", content: [{ type: "text", text: "Attachments returned by tool call t1:" },
    { type: "image_url", image_url: { url: `data:image/png;base64,${PNG}` } }] });
  assert.deepEqual(inputKinds(ask.messages), ["file", "image"]);
  assert.equal(parts([{ type: "text", text: "only " }, { type: "text", text: "words" }], "x"), "only words"); // text stays a string
});

test("Responses input_image / input_file and Gemini inlineData", () => {
  const { messages } = fromResponses({ input: [{ role: "user", content: [{ type: "input_text", text: "look" },
    { type: "input_image", image_url: "https://example.com/a.png" }, { type: "input_file", filename: "a.pdf", file_data: "data:application/pdf;base64,JVBE" }] }] });
  assert.deepEqual(messages[0].content.map((p) => p.type), ["text", "image_url", "file"]);
  const gem = fromGemini({ contents: [{ role: "user", parts: [{ text: "see" }, { inlineData: { mimeType: "image/jpeg", data: "/9j/" } },
    { inlineData: { mimeType: "application/pdf", data: "JVBE" } }] }] }, "m");
  assert.deepEqual(gem.messages[0].content, [{ type: "text", text: "see" }, { type: "image_url", image_url: { url: "data:image/jpeg;base64,/9j/" } },
    { type: "file", file: { filename: "file", file_data: "data:application/pdf;base64,JVBE" } }]);
  assert.deepEqual(inputKinds([{ role: "user", content: "plain" }]), []);
});
