from __future__ import annotations

import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from gateway.codex_app_backend import CodexAppServerBackend, _JsonRpcClient
from gateway.codex_backend import CodexCliBackend


def _backend_kwargs() -> dict[str, object]:
    return {
        "command": "codex",
        "codex_home": ".",
        "workdir": ".",
        "sandbox": "workspace-write",
        "timeout_seconds": 1,
    }


def _usage_breakdown(
    *,
    input_tokens: int,
    output_tokens: int,
    cached_input_tokens: int = 0,
    reasoning_output_tokens: int = 0,
) -> dict[str, int]:
    return {
        "cachedInputTokens": cached_input_tokens,
        "inputTokens": input_tokens,
        "outputTokens": output_tokens,
        "reasoningOutputTokens": reasoning_output_tokens,
        "totalTokens": input_tokens + output_tokens,
    }


def _rpc_client(*messages: dict[str, object]) -> _JsonRpcClient:
    stdout = asyncio.StreamReader()
    for message in messages:
        stdout.feed_data((json.dumps(message) + "\n").encode("utf-8"))
    stdout.feed_eof()
    return _JsonRpcClient(
        SimpleNamespace(stdin=None, stdout=stdout, stderr=None, returncode=0)
    )


class CodexMeteringTest(unittest.TestCase):
    def test_production_capabilities_do_not_claim_an_output_cap(self) -> None:
        cli = CodexCliBackend(**_backend_kwargs())
        app_local = CodexAppServerBackend(**_backend_kwargs())
        app_strict = CodexAppServerBackend(
            **_backend_kwargs(),
            production_strict=True,
        )

        self.assertFalse(cli.production_capabilities["native_output_token_cap"])
        self.assertFalse(cli.production_capabilities["trusted_native_usage"])
        self.assertFalse(cli.production_capabilities["production_ready"])
        self.assertFalse(app_local.production_capabilities["native_output_token_cap"])
        self.assertTrue(app_local.production_capabilities["native_usage_events"])
        self.assertFalse(app_local.production_capabilities["trusted_native_usage"])
        self.assertTrue(app_strict.production_capabilities["trusted_native_usage"])
        self.assertFalse(app_strict.production_capabilities["production_ready"])

    def test_cli_production_strict_fails_before_spawning(self) -> None:
        async def scenario() -> None:
            backend = CodexCliBackend(
                **_backend_kwargs(),
                production_strict=True,
            )
            with patch.object(backend, "_exec", new=AsyncMock()) as execute:
                with self.assertRaisesRegex(RuntimeError, "not production-capable"):
                    await backend.response(
                        {
                            "model": "gpt-5.5",
                            "input": "hello",
                            "max_output_tokens": 64,
                        }
                    )
            execute.assert_not_awaited()

        asyncio.run(scenario())

    def test_app_server_strict_rejects_unsupported_output_cap_before_spawning(self) -> None:
        async def scenario() -> None:
            backend = CodexAppServerBackend(
                **_backend_kwargs(),
                production_strict=True,
            )
            with patch.object(backend, "_run_turn", new=AsyncMock()) as run_turn:
                with self.assertRaisesRegex(RuntimeError, "does not expose a native output-token cap"):
                    await backend.chat_completion(
                        {
                            "model": "gpt-5.5",
                            "messages": [{"role": "user", "content": "hello"}],
                            "max_completion_tokens": 64,
                        }
                    )
            run_turn.assert_not_awaited()

        asyncio.run(scenario())

    def test_app_server_uses_validated_native_total_usage(self) -> None:
        async def scenario() -> None:
            client = _rpc_client(
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "tokenUsage": {
                            "last": _usage_breakdown(
                                input_tokens=2,
                                output_tokens=1,
                                cached_input_tokens=1,
                            ),
                            "total": _usage_breakdown(
                                input_tokens=8,
                                output_tokens=5,
                                cached_input_tokens=3,
                                reasoning_output_tokens=2,
                            ),
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "turn/completed",
                    "params": {"threadId": "thread-1", "turn": {"id": "turn-1"}},
                },
            )
            result = await client.read_turn_until_stop(
                thread_id="thread-1",
                turn_id="turn-1",
                require_trusted_usage=True,
            )
            self.assertEqual(
                result.response_usage(),
                {"input_tokens": 8, "output_tokens": 5, "total_tokens": 13},
            )

        asyncio.run(scenario())

    def test_malformed_native_usage_is_always_rejected(self) -> None:
        async def scenario() -> None:
            malformed_total = _usage_breakdown(input_tokens=2, output_tokens=1)
            malformed_total["totalTokens"] = 99
            client = _rpc_client(
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "tokenUsage": {
                            "last": _usage_breakdown(input_tokens=1, output_tokens=1),
                            "total": malformed_total,
                        },
                    },
                }
            )
            with self.assertRaisesRegex(RuntimeError, "totalTokens is inconsistent"):
                await client.read_turn_until_stop(
                    thread_id="thread-1",
                    turn_id="turn-1",
                )

        asyncio.run(scenario())

    def test_strict_mode_fails_closed_when_usage_event_is_missing(self) -> None:
        completed = {
            "jsonrpc": "2.0",
            "method": "turn/completed",
            "params": {"threadId": "thread-1", "turn": {"id": "turn-1"}},
        }

        async def strict_scenario() -> None:
            client = _rpc_client(completed)
            with self.assertRaisesRegex(RuntimeError, "without trusted native token usage"):
                await client.read_turn_until_stop(
                    thread_id="thread-1",
                    turn_id="turn-1",
                    require_trusted_usage=True,
                )

        async def local_scenario() -> None:
            client = _rpc_client(completed)
            result = await client.read_turn_until_stop(
                thread_id="thread-1",
                turn_id="turn-1",
            )
            self.assertEqual(
                result.response_usage(),
                {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            )

        asyncio.run(strict_scenario())
        asyncio.run(local_scenario())


if __name__ == "__main__":
    unittest.main()
