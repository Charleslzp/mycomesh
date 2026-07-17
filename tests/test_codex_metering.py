from __future__ import annotations

import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from gateway.codex_app_backend import (
    AppTurnResult,
    CodexAppServerBackend,
    _codex_subprocess_env,
    _JsonRpcClient,
)
from gateway.codex_backend import CodexCliBackend, CodexProcessLimiter


def _backend_kwargs() -> dict[str, object]:
    return {
        "command": "codex",
        "codex_home": ".",
        "workdir": ".",
        "sandbox": "workspace-write",
        "timeout_seconds": 1,
    }


def _testnet_backend(**overrides: object) -> CodexAppServerBackend:
    values = {
        **_backend_kwargs(),
        "sandbox": "read-only",
        "process_limiter": CodexProcessLimiter(maximum=1),
        "production_strict": True,
        "testnet_metering": True,
        "testnet_max_output_token_cap": 64,
        **overrides,
    }
    return CodexAppServerBackend(**values)


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

        app_testnet = _testnet_backend()
        capabilities = app_testnet.production_capabilities
        self.assertTrue(capabilities["production_ready"])
        self.assertFalse(capabilities["native_output_token_cap"])
        self.assertFalse(capabilities["runtime_metering_proof"])
        self.assertTrue(capabilities["post_execution_output_cap_validation"])

    def test_testnet_mode_requires_strict_read_only_single_process(self) -> None:
        with self.assertRaisesRegex(ValueError, "production_strict"):
            CodexAppServerBackend(
                **{**_backend_kwargs(), "sandbox": "read-only"},
                process_limiter=CodexProcessLimiter(maximum=1),
                testnet_metering=True,
            )
        with self.assertRaisesRegex(ValueError, "CODEX_MAX_CONCURRENT_PROCESSES=1"):
            CodexAppServerBackend(
                **{**_backend_kwargs(), "sandbox": "read-only"},
                process_limiter=CodexProcessLimiter(maximum=2),
                production_strict=True,
                testnet_metering=True,
            )
        with self.assertRaisesRegex(ValueError, "CODEX_SANDBOX=read-only"):
            CodexAppServerBackend(
                **_backend_kwargs(),
                process_limiter=CodexProcessLimiter(maximum=1),
                production_strict=True,
                testnet_metering=True,
            )

    def test_testnet_thread_disables_provider_side_tools(self) -> None:
        backend = _testnet_backend()
        params = backend._thread_start_params(model="gpt-5.5", tools=None)

        self.assertEqual(params["sandbox"], "read-only")
        self.assertTrue(params["ephemeral"])
        self.assertIsNone(params["dynamicTools"])
        config = params["config"]
        self.assertEqual(config["web_search"], "disabled")
        self.assertEqual(config["mcp_servers"], {})
        self.assertEqual(config["plugins"], {})
        for feature in (
            "shell_tool",
            "unified_exec",
            "shell_snapshot",
            "hooks",
            "code_mode",
            "code_mode_host",
            "multi_agent",
            "apps",
            "plugins",
            "in_app_browser",
            "browser_use",
            "browser_use_full_cdp_access",
            "browser_use_external",
            "computer_use",
            "remote_plugin",
            "plugin_sharing",
            "image_generation",
            "skill_mcp_dependency_install",
            "tool_suggest",
            "tool_call_mcp_elicitation",
            "auth_elicitation",
            "workspace_dependencies",
        ):
            self.assertIs(config["features"][feature], False)

    def test_testnet_subprocess_environment_strips_api_credentials(self) -> None:
        sensitive_names = (
            "OPENAI_API_KEY",
            "OPENAI_API_TOKEN",
            "OPENAI_ACCESS_TOKEN",
            "CODEX_API_KEY",
            "CODEX_ACCESS_TOKEN",
            "CHATGPT_ACCESS_TOKEN",
        )
        with patch.dict(
            "os.environ",
            {
                **{name: "sensitive" for name in sensitive_names},
                "PATH": "/usr/bin",
                "LANG": "C.UTF-8",
                "AGENT_KEYS": "must-not-reach-codex",
                "MYCOMESH_ADMIN_TOKEN": "must-not-reach-codex",
                "MYCOMESH_REPLAY_DB": "must-not-reach-codex",
            },
            clear=True,
        ):
            env = _codex_subprocess_env(
                "/isolated/codex-home",
                strip_api_credentials=True,
            )

        self.assertEqual(env["CODEX_HOME"], "/isolated/codex-home")
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["LANG"], "C.UTF-8")
        for name in sensitive_names:
            self.assertNotIn(name, env)
        self.assertNotIn("AGENT_KEYS", env)
        self.assertNotIn("MYCOMESH_ADMIN_TOKEN", env)
        self.assertNotIn("MYCOMESH_REPLAY_DB", env)

    def test_testnet_rejects_tools_streaming_and_continuations_before_spawning(self) -> None:
        async def scenario() -> None:
            backend = _testnet_backend()
            requests = (
                ({"stream": True}, "streaming"),
                ({"tools": [{"type": "function", "name": "run"}]}, "tools"),
                ({"tool_choice": "auto"}, "tool_choice"),
                ({"previous_response_id": "resp_1"}, "previous_response_id"),
                (
                    {
                        "input": [
                            {
                                "type": "function_call_output",
                                "call_id": "call_1",
                                "output": "done",
                            }
                        ]
                    },
                    "function_call_output",
                ),
            )
            for extra, expected in requests:
                body = {
                    "model": "gpt-5.5",
                    "input": "hello",
                    "max_output_tokens": 10,
                    **extra,
                }
                with self.subTest(expected=expected), patch.object(
                    backend,
                    "_run_turn",
                    new=AsyncMock(),
                ) as run_turn:
                    with self.assertRaisesRegex(RuntimeError, expected):
                        await backend.response(body)
                    run_turn.assert_not_awaited()

        asyncio.run(scenario())

    def test_testnet_postvalidates_native_usage_and_output_cap(self) -> None:
        async def scenario() -> None:
            backend = _testnet_backend()
            body = {
                "model": "gpt-5.5",
                "input": "hello",
                "max_output_tokens": 10,
            }
            usage = _usage_breakdown(input_tokens=7, output_tokens=5)
            result = AppTurnResult("thread-1", "turn-1", "OK", usage, [])
            with patch.object(backend, "_run_turn", new=AsyncMock(return_value=result)):
                payload = await backend.response(body)
            self.assertEqual(
                payload["usage"],
                {"input_tokens": 7, "output_tokens": 5, "total_tokens": 12},
            )

            over_cap = AppTurnResult(
                "thread-2",
                "turn-2",
                "too long",
                _usage_breakdown(input_tokens=7, output_tokens=11),
                [],
            )
            with patch.object(backend, "_run_turn", new=AsyncMock(return_value=over_cap)):
                with self.assertRaisesRegex(RuntimeError, "exceeded"):
                    await backend.response(body)

            malformed_usage = _usage_breakdown(input_tokens=7, output_tokens=5)
            malformed_usage["totalTokens"] = 99
            malformed = AppTurnResult(
                "thread-3",
                "turn-3",
                "bad usage",
                malformed_usage,
                [],
            )
            with patch.object(backend, "_run_turn", new=AsyncMock(return_value=malformed)):
                with self.assertRaisesRegex(RuntimeError, "totalTokens is inconsistent"):
                    await backend.response(body)

        asyncio.run(scenario())

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
