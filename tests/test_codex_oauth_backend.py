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

    async def test_native_followup_is_unary_and_strips_mycomesh_fields(self) -> None:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "id": "resp_1",
                    "status": "completed",
                    "output": [],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                },
            )

        backend, _ = self._backend(handler)
        await backend.response(
            {
                "model": "public-model",
                "input": [{"type": "compaction", "encrypted_content": "ciphertext"}],
                "stream": True,
                "metadata": {"trace": "kept"},
                "mycomesh_p2p_request_hash": "0x" + "22" * 32,
            },
            compact=False,
            public_model="public-model",
        )

        self.assertEqual(captured["body"]["model"], "gpt-5.6")
        self.assertIs(captured["body"]["stream"], False)
        self.assertEqual(captured["body"]["metadata"], {"trace": "kept"})
        self.assertNotIn("mycomesh_p2p_request_hash", captured["body"])

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
