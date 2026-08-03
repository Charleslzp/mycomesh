from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import httpx

from gateway.codex_oauth_backend import (
    CodexOAuthBackendError,
    CodexOAuthResponsesBackend,
)


class CodexOAuthResponsesBackendTests(unittest.IsolatedAsyncioTestCase):
    def _backend(self, handler) -> tuple[CodexOAuthResponsesBackend, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name)
        (home / "auth.json").write_text(
            json.dumps(
                {
                    "auth_mode": "chatgpt",
                    "tokens": {
                        "access_token": "secret-access-token",
                        "account_id": "account-1",
                        "refresh_token": "secret-refresh-token",
                    },
                }
            ),
            encoding="utf-8",
        )
        return (
            CodexOAuthResponsesBackend(
                codex_home=str(home),
                timeout_seconds=5,
                internal_model="gpt-5.6",
                base_url="https://chatgpt.test/backend-api/codex",
                transport=httpx.MockTransport(handler),
            ),
            home,
        )

    async def test_compact_uses_codex_oauth_headers_and_compact_schema(self) -> None:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["request"] = request
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "id": "resp_compact",
                    "object": "response",
                    "status": "completed",
                    "model": "gpt-5.6",
                    "output": [{"type": "compaction", "encrypted_content": "ciphertext"}],
                    "usage": {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
                },
            )

        backend, _ = self._backend(handler)
        result = await backend.response(
            {
                "model": "public-model",
                "input": [{"type": "compaction_trigger"}],
                "instructions": "compact",
                "stream": True,
                "prompt_cache_key": "local-cache",
                "max_output_tokens": 2000,
                "reasoning": {"effort": "max"},
                "mycomesh_p2p_request_hash": "0x" + "11" * 32,
            },
            compact=True,
            public_model="public-model",
        )

        request = captured["request"]
        self.assertEqual(request.url.path, "/backend-api/codex/responses/compact")
        self.assertEqual(request.headers["authorization"], "Bearer secret-access-token")
        self.assertEqual(request.headers["chatgpt-account-id"], "account-1")
        self.assertEqual(request.headers["originator"], "codex_cli_rs")
        self.assertEqual(request.headers["openai-beta"], "responses=experimental")
        self.assertEqual(
            captured["body"],
            {
                "model": "gpt-5.6",
                "input": [{"type": "compaction_trigger"}],
                "instructions": "compact",
                "reasoning": {"effort": "xhigh"},
            },
        )
        self.assertEqual(result["model"], "public-model")

    async def test_native_followup_uses_codex_sse_and_strips_unsupported_fields(self) -> None:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["request"] = request
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=(
                    b'event: response.created\ndata: {"type":"response.created","response":{"id":"resp_1"}}\n\n'
                    b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_1","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n'
                ),
            )

        backend, _ = self._backend(handler)
        await backend.response(
            {
                "model": "public-model",
                "input": "continue from compacted context",
                "stream": False,
                "store": True,
                "metadata": {"trace": "kept"},
                "max_output_tokens": 123,
                "reasoning": {"effort": "high"},
                "mycomesh_p2p_request_hash": "0x" + "22" * 32,
            },
            compact=False,
            public_model="public-model",
        )

        self.assertEqual(captured["body"]["model"], "gpt-5.6")
        self.assertIs(captured["body"]["stream"], True)
        self.assertIs(captured["body"]["store"], False)
        self.assertEqual(captured["request"].headers["accept"], "text/event-stream")
        self.assertEqual(
            captured["body"]["input"],
            [{"type": "message", "role": "user", "content": "continue from compacted context"}],
        )
        self.assertEqual(captured["body"]["include"], ["reasoning.encrypted_content"])
        self.assertNotIn("metadata", captured["body"])
        self.assertNotIn("max_output_tokens", captured["body"])
        self.assertNotIn("mycomesh_p2p_request_hash", captured["body"])

    async def test_native_followup_rejects_sse_without_terminal_response(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b'event: response.created\ndata: {"type":"response.created","response":{"id":"resp_1"}}\n\n',
            )

        backend, _ = self._backend(handler)
        with self.assertRaisesRegex(CodexOAuthBackendError, "without a terminal response"):
            await backend.response(
                {"model": "public-model", "input": [{"type": "item_reference", "id": "item_1"}]},
                compact=False,
                public_model="public-model",
            )

    async def test_upstream_error_preserves_protocol_payload_without_token(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429,
                json={"error": {"type": "rate_limit_error", "message": "quota reached"}},
            )

        backend, _ = self._backend(handler)
        with self.assertRaises(CodexOAuthBackendError) as raised:
            await backend.response(
                {"model": "public-model", "input": "hello"},
                compact=False,
                public_model="public-model",
            )
        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(raised.exception.payload["error"]["type"], "rate_limit_error")
        self.assertNotIn("secret-access-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
