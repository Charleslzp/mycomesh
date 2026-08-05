from __future__ import annotations

import asyncio
import json
import os
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
    def test_alpha_search_is_executed_by_provider_as_hosted_web_search(self) -> None:
        async def scenario() -> None:
            with patch.dict(
                os.environ,
                {"MYCOMESH_CODEX_TESTNET_WEB_SEARCH": "true"},
            ):
                backend = _testnet_backend()
            result = AppTurnResult(
                "thread-search",
                "turn-search",
                "Current answer with sources",
                _usage_breakdown(input_tokens=8, output_tokens=5),
                [],
                response_items=[
                    {
                        "id": "ws_real",
                        "type": "web_search_call",
                        "status": "completed",
                        "action": {"type": "search", "query": "current BTC price"},
                    }
                ],
            )
            with patch.object(
                backend,
                "_run_turn",
                new=AsyncMock(return_value=result),
            ) as run_turn:
                payload = await backend.response(
                    {
                        "model": "gpt-5.5",
                        "input": [
                            {
                                "type": "mycomesh_alpha_search_request",
                                "request": {
                                    "model": "gpt-5.5",
                                    "commands": {
                                        "search_query": [{"q": "current BTC price"}]
                                    },
                                    "settings": {"search_context_size": "high"},
                                },
                            }
                        ],
                        "max_output_tokens": 10,
                    }
                )

            self.assertEqual(
                payload["mycomesh_alpha_search_response"],
                {"output": "Current answer with sources"},
            )
            self.assertEqual(
                payload["usage"],
                {"input_tokens": 8, "output_tokens": 5, "total_tokens": 13},
            )
            self.assertEqual(run_turn.await_args.kwargs["tools"], [{"type": "web_search", "search_context_size": "high"}])
            self.assertIn("current BTC price", run_turn.await_args.kwargs["prompt"])

        asyncio.run(scenario())

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

    def test_testnet_thread_allows_dynamic_tools_but_disables_provider_side_tools(self) -> None:
        backend = _testnet_backend()
        params = backend._thread_start_params(
            model="gpt-5.5",
            instructions="Use client-provided functions only.",
            tools=[
                {
                    "type": "function",
                    "name": "lookup",
                    "description": "Lookup data.",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    },
                },
                {
                    "type": "custom",
                    "name": "apply_patch",
                    "description": "Apply a patch.",
                    "format": {"type": "grammar"},
                },
                {"type": "web_search"},
                {"type": "mcp", "server_label": "hosted"},
            ],
        )

        self.assertEqual(params["sandbox"], "read-only")
        self.assertTrue(params["ephemeral"])
        self.assertNotIn("baseInstructions", params)
        self.assertEqual(
            params["developerInstructions"],
            "Use client-provided functions only.",
        )
        self.assertEqual(
            params["dynamicTools"],
            [
                {
                    "type": "function",
                    "name": "lookup",
                    "description": "Lookup data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    },
                },
                {
                    "type": "function",
                    "name": "mycomesh_client_apply_patch",
                    "description": "Apply a patch.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"input": {"type": "string"}},
                        "required": ["input"],
                        "additionalProperties": False,
                    },
                },
            ],
        )
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

    def test_testnet_web_search_can_be_enabled_explicitly(self) -> None:
        with patch.dict(os.environ, {"MYCOMESH_CODEX_TESTNET_WEB_SEARCH": "true"}):
            backend = _testnet_backend()
            params = backend._thread_start_params(
                model="gpt-5.5",
                tools=[{"type": "web_search", "search_context_size": "low"}],
            )

        self.assertEqual(params["config"]["web_search"], "live")
        self.assertEqual(
            params["config"]["tools"],
            {"web_search": {"context_size": "low"}},
        )
        self.assertTrue(params["experimentalRawEvents"])

        turn_params = backend._turn_start_params(
            thread_id="thread-1",
            prompt="Use lookup.",
            model="gpt-5.5",
            output_schema=None,
            reasoning={"effort": "high", "summary": "concise", "ignored": True},
        )
        self.assertEqual(
            turn_params["input"],
            [{"type": "text", "text": "Use lookup.", "text_elements": []}],
        )
        self.assertEqual(turn_params["effort"], "high")
        self.assertEqual(turn_params["summary"], "concise")

        invalid_reasoning = backend._turn_start_params(
            thread_id="thread-2",
            prompt="hello",
            model="gpt-5.5",
            output_schema=None,
            reasoning={"effort": "", "summary": "verbose"},
        )
        self.assertNotIn("effort", invalid_reasoning)
        self.assertNotIn("summary", invalid_reasoning)

    def test_testnet_subprocess_environment_strips_api_credentials(self) -> None:
        sensitive_names = (
            "OPENAI_API_KEY",
            "OPENAI_API_TOKEN",
            "OPENAI_ACCESS_TOKEN",
            "CODEX_API_KEY",
            "CODEX_ACCESS_TOKEN",
            "CHATGPT_ACCESS_TOKEN",
        )
        proxy_values = {
            "HTTP_PROXY": "http://upper-http.example:8080",
            "HTTPS_PROXY": "http://upper-https.example:8081",
            "ALL_PROXY": "socks5://upper-all.example:1080",
            "NO_PROXY": "localhost,provider-sidecar",
            "http_proxy": "http://lower-http.example:9080",
            "https_proxy": "http://lower-https.example:9081",
            "all_proxy": "socks5://lower-all.example:1081",
            "no_proxy": "127.0.0.1,provider-sidecar",
        }
        with patch.dict(
            "os.environ",
            {
                **{name: "sensitive" for name in sensitive_names},
                **proxy_values,
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
        for name, value in proxy_values.items():
            self.assertEqual(env[name], value)
        for name in sensitive_names:
            self.assertNotIn(name, env)
        self.assertNotIn("AGENT_KEYS", env)
        self.assertNotIn("MYCOMESH_ADMIN_TOKEN", env)
        self.assertNotIn("MYCOMESH_REPLAY_DB", env)

    def test_testnet_rejects_streaming_before_spawning(self) -> None:
        async def scenario() -> None:
            backend = _testnet_backend()
            body = {
                "model": "gpt-5.5",
                "input": "hello",
                "max_output_tokens": 10,
                "stream": True,
                "tools": [{"type": "function", "name": "run"}],
                "tool_choice": "auto",
            }
            with patch.object(backend, "_run_turn", new=AsyncMock()) as run_turn:
                with self.assertRaisesRegex(RuntimeError, "streaming"):
                    await backend.response(body)
                run_turn.assert_not_awaited()

        asyncio.run(scenario())

    def test_testnet_bridges_dynamic_function_call_and_continuation(self) -> None:
        class PendingClient:
            def __init__(self) -> None:
                self.responses: list[dict[str, object]] = []
                self.require_trusted_usage: bool | None = None
                self.closed = False

            async def respond(self, request_id: int | str, result: dict[str, object]) -> None:
                self.responses.append({"request_id": request_id, "result": result})

            async def read_turn_until_stop(
                self,
                thread_id: str,
                turn_id: str,
                *,
                require_trusted_usage: bool = False,
            ) -> AppTurnResult:
                self.require_trusted_usage = require_trusted_usage
                return AppTurnResult(
                    thread_id,
                    turn_id,
                    "Final answer after lookup",
                    _usage_breakdown(input_tokens=8, output_tokens=5),
                    [],
                )

            async def close(self) -> None:
                self.closed = True

        async def scenario() -> None:
            backend = _testnet_backend()
            client = PendingClient()
            initial = AppTurnResult(
                "thread-1",
                "turn-1",
                "",
                _usage_breakdown(input_tokens=4, output_tokens=1),
                [],
                client=client,
                pending_tool_request_id=99,
                pending_tool_call={
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": "call_patch",
                    "tool": "mycomesh_client_apply_patch",
                    "arguments": {"input": "*** Begin Patch\n*** End Patch"},
                },
            )
            tools = [
                {
                    "type": "custom",
                    "name": "apply_patch",
                    "description": "Apply a patch.",
                    "format": {"type": "grammar"},
                }
            ]
            with patch.object(
                backend,
                "_validate_testnet_metering_result",
                wraps=backend._validate_testnet_metering_result,
            ) as validate_metering:
                with patch.object(
                    backend,
                    "_run_turn",
                    new=AsyncMock(return_value=initial),
                ) as run_turn:
                    first = await backend.response(
                        {
                            "model": "gpt-5.5",
                            "input": "Apply the patch.",
                            "max_output_tokens": 10,
                            "instructions": "Use client-provided functions only.",
                            "reasoning": {
                                "effort": "high",
                                "summary": "concise",
                                "ignored": True,
                            },
                            "tools": tools,
                            "tool_choice": "auto",
                        }
                    )
                    second = await backend.response(
                        {
                            "model": "gpt-5.5",
                            "input": [
                                {
                                    "type": "custom_tool_call_output",
                                    "call_id": "call_old",
                                    "output": "Stale output",
                                },
                                first["output"][0],
                                {
                                    "type": "custom_tool_call_output",
                                    "call_id": "call_patch",
                                    "output": "Done!",
                                }
                            ],
                        }
                    )

            self.assertEqual(first["output"][0]["type"], "custom_tool_call")
            self.assertEqual(first["output"][0]["name"], "apply_patch")
            self.assertEqual(first["output"][0]["call_id"], "call_patch")
            self.assertEqual(first["output"][0]["input"], "*** Begin Patch\n*** End Patch")
            self.assertEqual(first["tool_choice"], "auto")
            self.assertEqual(first["tools"], tools)
            self.assertIs(first["parallel_tool_calls"], False)
            self.assertEqual(
                first["usage"],
                {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
            )
            self.assertEqual(
                second["usage"],
                {"input_tokens": 4, "output_tokens": 4, "total_tokens": 8},
            )
            with self.assertRaisesRegex(RuntimeError, "cumulative token usage decreased"):
                initial.response_usage(
                    previous=_usage_breakdown(input_tokens=5, output_tokens=1)
                )
            run_turn.assert_awaited_once()
            self.assertEqual(validate_metering.call_count, 2)
            self.assertEqual(run_turn.await_args.kwargs["tools"], tools)
            self.assertEqual(
                run_turn.await_args.kwargs["instructions"],
                "Use client-provided functions only.",
            )
            self.assertEqual(
                run_turn.await_args.kwargs["reasoning"],
                {"effort": "high", "summary": "concise"},
            )
            self.assertEqual(second["output_text"], "Final answer after lookup")
            self.assertEqual(
                client.responses,
                [
                    {
                        "request_id": 99,
                        "result": {
                            "success": True,
                            "contentItems": [{"type": "inputText", "text": "Done!"}],
                        },
                    }
                ],
            )
            self.assertIs(client.require_trusted_usage, True)
            self.assertTrue(client.closed)
            self.assertEqual(backend._pending, {})

        asyncio.run(scenario())

    def test_testnet_continues_a_metered_deferred_tool_call_in_a_new_turn(self) -> None:
        class PendingClient:
            def __init__(self) -> None:
                self.requests: list[tuple[str, dict[str, object]]] = []
                self.require_trusted_usage: bool | None = None
                self.closed = False

            async def request(
                self, method: str, params: dict[str, object]
            ) -> dict[str, object]:
                self.requests.append((method, params))
                return {"turn": {"id": "turn-2"}}

            async def read_turn_until_stop(
                self,
                thread_id: str,
                turn_id: str,
                *,
                require_trusted_usage: bool = False,
            ) -> AppTurnResult:
                self.require_trusted_usage = require_trusted_usage
                return AppTurnResult(
                    thread_id,
                    turn_id,
                    "Final answer after patch",
                    _usage_breakdown(input_tokens=8, output_tokens=5),
                    [],
                )

            async def close(self) -> None:
                self.closed = True

        async def scenario() -> None:
            backend = _testnet_backend()
            client = PendingClient()
            initial = AppTurnResult(
                "thread-1",
                "turn-1",
                "",
                _usage_breakdown(input_tokens=4, output_tokens=1),
                [],
                client=client,
                pending_tool_request_id=None,
                pending_tool_call={
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": "call_patch",
                    "tool": "mycomesh_client_apply_patch",
                    "arguments": {"input": "*** Begin Patch\n*** End Patch"},
                },
            )
            with patch.object(
                backend,
                "_run_turn",
                new=AsyncMock(return_value=initial),
            ):
                first = await backend.response(
                    {
                        "model": "gpt-5.5",
                        "input": "Apply the patch.",
                        "max_output_tokens": 10,
                        "reasoning": {"effort": "high"},
                        "tools": [{"type": "custom", "name": "apply_patch"}],
                    }
                )
                second = await backend.response(
                    {
                        "model": "gpt-5.5",
                        "previous_response_id": first["id"],
                        "input": [
                            {
                                "type": "custom_tool_call_output",
                                "call_id": "call_patch",
                                "output": "Done!",
                            }
                        ],
                    }
                )

            self.assertEqual(second["output_text"], "Final answer after patch")
            self.assertEqual(
                second["usage"],
                {"input_tokens": 4, "output_tokens": 4, "total_tokens": 8},
            )
            self.assertEqual(len(client.requests), 2)
            method, params = client.requests[0]
            self.assertEqual(method, "thread/inject_items")
            self.assertEqual(
                params,
                {
                    "threadId": "thread-1",
                    "items": [
                        {
                            "type": "custom_tool_call_output",
                            "call_id": "call_patch",
                            "output": "Done!",
                        }
                    ],
                },
            )
            method, params = client.requests[1]
            self.assertEqual(method, "turn/start")
            self.assertEqual(params["threadId"], "thread-1")
            self.assertEqual(params["model"], "gpt-5.5")
            self.assertEqual(params["effort"], "high")
            self.assertEqual(
                params["input"][0]["text"],
                "Continue the original task using the external tool result.",
            )
            self.assertIs(client.require_trusted_usage, True)
            self.assertTrue(client.closed)

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

            cumulative = AppTurnResult(
                "thread-4",
                "turn-4",
                "incremental",
                _usage_breakdown(input_tokens=100, output_tokens=15),
                [],
            )
            backend._validate_testnet_metering_result(
                body,
                cumulative,
                previous_usage=_usage_breakdown(input_tokens=93, output_tokens=5),
            )

        asyncio.run(scenario())

    def test_testnet_closes_unregistered_tool_turn_when_metering_rejects_it(self) -> None:
        async def scenario() -> None:
            backend = _testnet_backend()
            client = SimpleNamespace(close=AsyncMock())
            result = AppTurnResult(
                "thread-1",
                "turn-1",
                "",
                _usage_breakdown(input_tokens=7, output_tokens=11),
                [],
                client=client,
                pending_tool_call={
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": "call_patch",
                    "tool": "mycomesh_client_apply_patch",
                    "arguments": {"input": "TEST_PATCH"},
                },
            )
            with patch.object(backend, "_run_turn", new=AsyncMock(return_value=result)):
                with self.assertRaisesRegex(RuntimeError, "exceeded"):
                    await backend.response(
                        {
                            "model": "gpt-5.5",
                            "input": "Apply the patch.",
                            "max_output_tokens": 10,
                            "tools": [{"type": "custom", "name": "apply_patch"}],
                        }
                    )

            client.close.assert_awaited_once()
            self.assertEqual(backend._pending, {})

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
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": "turn-1", "status": "completed"},
                    },
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

    def test_strict_tool_call_waits_for_native_usage_before_returning(self) -> None:
        async def scenario() -> None:
            tool_call = {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "call_patch",
                "tool": "mycomesh_client_apply_patch",
                "arguments": {"input": "TEST_PATCH"},
            }
            client = _rpc_client(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "item/tool/call",
                    "params": tool_call,
                },
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "tokenUsage": {
                            "last": _usage_breakdown(input_tokens=4, output_tokens=1),
                            "total": _usage_breakdown(input_tokens=4, output_tokens=1),
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": "turn-1", "status": "interrupted"},
                    },
                },
                {"jsonrpc": "2.0", "id": 4, "result": {}},
            )
            client.respond = AsyncMock()
            client.send_request = AsyncMock(return_value=4)

            result = await client.read_turn_until_stop(
                thread_id="thread-1",
                turn_id="turn-1",
                require_trusted_usage=True,
            )

            self.assertEqual(result.pending_tool_call, tool_call)
            self.assertIsNone(result.pending_tool_request_id)
            self.assertIs(result.client, client)
            self.assertEqual(
                result.response_usage(),
                {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
            )
            client.respond.assert_awaited_once()
            client.send_request.assert_awaited_once_with(
                "turn/interrupt",
                {"threadId": "thread-1", "turnId": "turn-1"},
            )

        asyncio.run(scenario())

    def test_strict_tool_call_uses_native_continuation_when_usage_arrives_first(self) -> None:
        async def scenario() -> None:
            client = _rpc_client(
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "tokenUsage": {
                            "last": _usage_breakdown(input_tokens=2, output_tokens=1),
                            "total": _usage_breakdown(input_tokens=2, output_tokens=1),
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "item/tool/call",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "callId": "call_patch",
                        "tool": "mycomesh_client_apply_patch",
                        "arguments": {"input": "TEST_PATCH"},
                    },
                },
            )
            client._write = AsyncMock()

            result = await client.read_turn_until_stop(
                "thread-1", "turn-1", require_trusted_usage=True
            )

            self.assertEqual(result.usage["totalTokens"], 3)
            self.assertEqual(result.pending_tool_request_id, 99)
            client._write.assert_not_awaited()

        asyncio.run(scenario())

    def test_strict_usage_is_bound_and_cannot_decrease(self) -> None:
        async def scenario() -> None:
            client = _rpc_client(
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "old-turn",
                        "tokenUsage": {
                            "last": _usage_breakdown(input_tokens=1, output_tokens=1),
                            "total": _usage_breakdown(input_tokens=100, output_tokens=10),
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "tokenUsage": {
                            "last": _usage_breakdown(input_tokens=2, output_tokens=1),
                            "total": _usage_breakdown(input_tokens=8, output_tokens=4),
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "tokenUsage": {
                            "last": _usage_breakdown(input_tokens=1, output_tokens=1),
                            "total": _usage_breakdown(input_tokens=7, output_tokens=4),
                        },
                    },
                },
            )

            with self.assertRaisesRegex(RuntimeError, "cumulative token usage decreased"):
                await client.read_turn_until_stop(
                    "thread-1", "turn-1", require_trusted_usage=True
                )

        asyncio.run(scenario())

    def test_strict_interrupt_rejects_a_malformed_ack(self) -> None:
        async def scenario() -> None:
            client = _rpc_client(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "item/tool/call",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "callId": "call-1",
                        "tool": "lookup",
                        "arguments": {},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "tokenUsage": {
                            "last": _usage_breakdown(input_tokens=2, output_tokens=1),
                            "total": _usage_breakdown(input_tokens=2, output_tokens=1),
                        },
                    },
                },
                {"jsonrpc": "2.0", "id": 1},
            )
            client._write = AsyncMock()

            with self.assertRaisesRegex(RuntimeError, "malformed turn/interrupt"):
                await client.read_turn_until_stop(
                    "thread-1", "turn-1", require_trusted_usage=True
                )

        asyncio.run(scenario())

    def test_request_preserves_early_turn_notification(self) -> None:
        async def scenario() -> None:
            tool_call = {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "call_lookup",
                "tool": "lookup",
                "arguments": {"query": "weather"},
            }
            client = _rpc_client(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "item/tool/call",
                    "params": tool_call,
                },
                {"jsonrpc": "2.0", "id": 1, "result": {"turn": {"id": "turn-1"}}},
            )
            client._write = AsyncMock()

            response = await client.request("turn/start", {"threadId": "thread-1"})
            result = await client.read_turn_until_stop("thread-1", "turn-1")

            self.assertEqual(response["turn"]["id"], "turn-1")
            self.assertEqual(result.pending_tool_call, tool_call)

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
            "params": {
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "completed"},
            },
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
