from __future__ import annotations

import json
import unittest

from gateway.openai_protocol import (
    chat_completion_sse,
    normalize_openai_error,
    response_stream_events,
)
from gateway.codex_app_backend import _function_call_outputs, _structured_tool_output


class ResponsesProtocolTests(unittest.TestCase):
    def test_all_codex_tool_output_types_are_continuations(self) -> None:
        items = [
            {"type": "function_call_output", "call_id": "call_1", "output": "one"},
            {"type": "tool_search_output", "call_id": "call_2", "tools": [{"name": "shell"}]},
            {"type": "custom_tool_call_output", "call_id": "call_3", "output": "three"},
            {"type": "mcp_tool_call_output", "call_id": "call_4", "output": {"ok": True}},
            {"type": "message", "role": "user", "content": "ignore"},
        ]

        outputs = _function_call_outputs(items)
        self.assertEqual([item["call_id"] for item in outputs], ["call_1", "call_2", "call_3", "call_4"])
        self.assertEqual(
            json.loads(_structured_tool_output(outputs[1])["output"]),
            [{"name": "shell"}],
        )

    def test_message_stream_has_strict_indices_arrays_and_sequence_numbers(self) -> None:
        events = list(
            response_stream_events(
                {
                    "id": "resp_1",
                    "status": "completed",
                    "model": "gpt-test",
                    "output": [
                        {
                            "id": "msg_1",
                            "type": "message",
                            "role": "assistant",
                            "status": "completed",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": "hello",
                                    "annotations": [{"type": "url_citation", "url": "https://example.com"}],
                                },
                                {"type": "refusal", "refusal": "no"},
                            ],
                        }
                    ],
                }
            )
        )

        self.assertEqual([event["sequence_number"] for event in events], list(range(len(events))))
        added = next(event for event in events if event["type"] == "response.output_item.added")
        self.assertEqual(added["output_index"], 0)
        self.assertEqual(added["item"]["content"], [])
        delta = next(event for event in events if event["type"] == "response.output_text.delta")
        self.assertEqual(delta["content_index"], 0)
        self.assertEqual(delta["logprobs"], [])
        done = next(event for event in events if event["type"] == "response.output_text.done")
        self.assertEqual(done["logprobs"], [])
        refusal = next(event for event in events if event["type"] == "response.refusal.done")
        self.assertEqual(refusal["content_index"], 1)

    def test_function_custom_reasoning_and_unknown_items_are_not_dropped(self) -> None:
        events = list(
            response_stream_events(
                {
                    "id": "resp_tools",
                    "output": [
                        {
                            "id": "fc_1",
                            "type": "function_call",
                            "call_id": "call_1",
                            "name": "shell",
                            "arguments": '{"cmd":"pwd"}',
                        },
                        {
                            "id": "ct_1",
                            "type": "custom_tool_call",
                            "call_id": "call_2",
                            "name": "apply_patch",
                            "input": "patch",
                        },
                        {
                            "id": "rs_1",
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "summary"}],
                            "content": [{"type": "reasoning_text", "text": "reason"}],
                        },
                        {"id": "future_1", "type": "future_tool_call", "payload": {"x": 1}},
                    ],
                }
            )
        )

        function_added = next(
            event
            for event in events
            if event["type"] == "response.output_item.added" and event["output_index"] == 0
        )
        self.assertEqual(function_added["item"]["arguments"], "")
        function_done = next(
            event for event in events if event["type"] == "response.function_call_arguments.done"
        )
        self.assertEqual(function_done["name"], "shell")
        self.assertEqual(function_done["arguments"], '{"cmd":"pwd"}')
        event_types = {event["type"] for event in events}
        self.assertIn("response.custom_tool_call_input.done", event_types)
        self.assertIn("response.reasoning_summary_text.done", event_types)
        self.assertIn("response.reasoning_text.done", event_types)
        future_done = next(
            event
            for event in events
            if event["type"] == "response.output_item.done" and event["output_index"] == 3
        )
        self.assertEqual(future_done["item"]["payload"], {"x": 1})

    def test_tool_search_arguments_are_an_object_and_compact_wire_is_minimal(self) -> None:
        payload = {
            "id": "resp_compact",
            "status": "completed",
            "output": [
                {
                    "id": "ts_1",
                    "type": "tool_search_call",
                    "call_id": None,
                    "arguments": {"query": "shell"},
                },
                {
                    "id": "cmp_1",
                    "type": "compaction",
                    "encrypted_content": "ciphertext",
                },
            ],
        }
        events = list(response_stream_events(payload))
        added = next(event for event in events if event["type"] == "response.output_item.added")
        self.assertEqual(added["item"]["execution"], "client")
        self.assertEqual(added["item"]["arguments"], {"query": "shell"})

        compact_events = list(response_stream_events(payload, compact=True))
        self.assertEqual(
            [event["type"] for event in compact_events],
            ["response.output_item.done", "response.output_item.done", "response.completed"],
        )
        self.assertEqual([event["sequence_number"] for event in compact_events], [0, 1, 2])
        self.assertEqual(compact_events[1]["item"]["encrypted_content"], "ciphertext")

    def test_terminal_failure_and_error_envelope(self) -> None:
        events = list(
            response_stream_events(
                {
                    "id": "resp_failed",
                    "status": "failed",
                    "error": {"type": "server_error", "message": "boom"},
                    "output": [],
                }
            )
        )
        self.assertEqual(events[-1]["type"], "response.failed")
        error = normalize_openai_error({"detail": "bad"}, fallback_type="relay_error")
        self.assertEqual(error["error"]["message"], "bad")
        self.assertEqual(error["error"]["code"], "relay_error")


class ChatProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_chat_stream_uses_chunks_tools_usage_and_done(self) -> None:
        payload = {
            "id": "chatcmpl_1",
            "model": "gpt-test",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "shell", "arguments": '{"cmd":"pwd"}'},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        }
        chunks = [chunk async for chunk in chat_completion_sse(payload, include_usage=True)]
        self.assertEqual(chunks[-1], b"data: [DONE]\n\n")
        decoded = [json.loads(chunk.decode().removeprefix("data: ").strip()) for chunk in chunks[:-1]]
        self.assertTrue(all(item["object"] == "chat.completion.chunk" for item in decoded))
        self.assertEqual(decoded[1]["choices"][0]["delta"]["tool_calls"][0]["index"], 0)
        self.assertEqual(decoded[-1]["choices"], [])
        self.assertEqual(decoded[-1]["usage"]["total_tokens"], 3)
