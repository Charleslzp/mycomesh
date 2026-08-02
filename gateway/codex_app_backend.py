from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .channel_policy import CODEX_BACKEND_POLICY

from .codex_backend import (
    CodexProcessLimiter,
    MAX_CODEX_TIMEOUT_SECONDS,
    _CodexProcessPermit,
    _create_codex_subprocess,
    _positive_limit,
    _requested_max_output_tokens,
    _stop_process,
    _subprocess_group_kwargs,
    chat_completion_payload,
    response_payload,
    response_tool_call_payload,
    tool_call_payload,
)
from .netio import bounded_timeout
from .schema_output import coerce_to_schema, json_schema_content

APP_SERVER_STREAM_LIMIT = 8 * 1024 * 1024
DEFAULT_APP_SERVER_STDOUT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_APP_SERVER_STDERR_RETAIN_BYTES = 1024 * 1024
DEFAULT_APP_SERVER_MAX_MESSAGES = 100_000
DEFAULT_APP_SERVER_MAX_PENDING_TURNS = 8
DEFAULT_APP_SERVER_PENDING_TTL_SECONDS = 300.0
MAX_APP_SERVER_STDOUT_BYTES = 256 * 1024 * 1024
MAX_APP_SERVER_STDERR_RETAIN_BYTES = 16 * 1024 * 1024
MAX_APP_SERVER_MESSAGES = 1_000_000
MAX_APP_SERVER_PENDING_TURNS = 64
MAX_APP_SERVER_PENDING_TTL_SECONDS = 3600.0

_NATIVE_USAGE_FIELDS = (
    "cachedInputTokens",
    "inputTokens",
    "outputTokens",
    "reasoningOutputTokens",
    "totalTokens",
)
_APP_SERVER_OUTPUT_CAP_LIMITATION = (
    "Codex app-server v2 turn/start does not expose a native output-token cap"
)
CODEX_TESTNET_METERING_MODE = CODEX_BACKEND_POLICY
MAX_CODEX_TESTNET_OUTPUT_TOKEN_CAP = 1_000_000
_CODEX_TESTNET_DISABLED_FEATURES = (
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
)
_CODEX_BUILTIN_DYNAMIC_TOOL_NAMES = frozenset(
    {"apply_patch", "request_user_input", "update_plan", "view_image"}
)
_CLIENT_DYNAMIC_TOOL_PREFIX = "mycomesh_client_"
_CODEX_API_CREDENTIAL_ENV = (
    "OPENAI_API_KEY",
    "OPENAI_API_TOKEN",
    "OPENAI_ACCESS_TOKEN",
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "CHATGPT_ACCESS_TOKEN",
)
_CODEX_PROXY_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)
_CODEX_TESTNET_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    *_CODEX_PROXY_ENV,
)


class CodexAppServerBackend:
    def __init__(
        self,
        command: str,
        codex_home: str,
        workdir: str,
        sandbox: str,
        timeout_seconds: float,
        process_limiter: CodexProcessLimiter | None = None,
        production_strict: bool = False,
        testnet_metering: bool = False,
        testnet_max_output_token_cap: int = 2000,
    ) -> None:
        self.command = command
        self.codex_home = codex_home
        self.workdir = workdir
        self.sandbox = sandbox
        self.timeout_seconds = bounded_timeout(
            timeout_seconds,
            maximum=MAX_CODEX_TIMEOUT_SECONDS,
            label="Codex app-server timeout",
        )
        self.stdout_max_bytes = _positive_limit(
            os.getenv("CODEX_APP_SERVER_STDOUT_MAX_BYTES"),
            DEFAULT_APP_SERVER_STDOUT_MAX_BYTES,
            "CODEX_APP_SERVER_STDOUT_MAX_BYTES",
            maximum=MAX_APP_SERVER_STDOUT_BYTES,
        )
        self.stderr_retain_bytes = _positive_limit(
            os.getenv("CODEX_APP_SERVER_STDERR_RETAIN_BYTES"),
            DEFAULT_APP_SERVER_STDERR_RETAIN_BYTES,
            "CODEX_APP_SERVER_STDERR_RETAIN_BYTES",
            maximum=MAX_APP_SERVER_STDERR_RETAIN_BYTES,
        )
        self.max_messages = _positive_limit(
            os.getenv("CODEX_APP_SERVER_MAX_MESSAGES"),
            DEFAULT_APP_SERVER_MAX_MESSAGES,
            "CODEX_APP_SERVER_MAX_MESSAGES",
            maximum=MAX_APP_SERVER_MESSAGES,
        )
        self.max_pending_turns = _positive_limit(
            os.getenv("CODEX_APP_SERVER_MAX_PENDING_TURNS"),
            DEFAULT_APP_SERVER_MAX_PENDING_TURNS,
            "CODEX_APP_SERVER_MAX_PENDING_TURNS",
            maximum=MAX_APP_SERVER_PENDING_TURNS,
        )
        self.pending_ttl_seconds = bounded_timeout(
            os.getenv(
                "CODEX_APP_SERVER_PENDING_TTL_SECONDS",
                str(DEFAULT_APP_SERVER_PENDING_TTL_SECONDS),
            ),
            maximum=MAX_APP_SERVER_PENDING_TTL_SECONDS,
            label="Codex app-server pending turn TTL",
        )
        self.process_limiter = process_limiter or CodexProcessLimiter()
        self.production_strict = production_strict
        self.testnet_metering = bool(testnet_metering)
        if self.testnet_metering and not self.production_strict:
            raise ValueError("Codex testnet metering requires production_strict")
        if self.testnet_metering and self.process_limiter.maximum != 1:
            raise ValueError(
                "Codex testnet metering requires CODEX_MAX_CONCURRENT_PROCESSES=1"
            )
        if self.testnet_metering and self.sandbox != "read-only":
            raise ValueError("Codex testnet metering requires CODEX_SANDBOX=read-only")
        if (
            type(testnet_max_output_token_cap) is not int
            or testnet_max_output_token_cap <= 0
            or testnet_max_output_token_cap > MAX_CODEX_TESTNET_OUTPUT_TOKEN_CAP
        ):
            raise ValueError(
                "Codex testnet maximum output-token cap must be between 1 and "
                f"{MAX_CODEX_TESTNET_OUTPUT_TOKEN_CAP}"
            )
        self.testnet_max_output_token_cap = testnet_max_output_token_cap
        self._pending: dict[str, PendingToolTurn] = {}

    @property
    def production_capabilities(self) -> dict[str, Any]:
        testnet_ready = self.production_strict and self.testnet_metering
        return {
            "schema": "mycomesh.inference.capabilities.v1",
            "backend": "codex_app_server",
            "native_output_token_cap": False,
            "native_usage_events": True,
            "trusted_native_usage": self.production_strict,
            "runtime_metering_proof": False,
            "post_execution_output_cap_validation": testnet_ready,
            "metering_mode": CODEX_TESTNET_METERING_MODE if testnet_ready else None,
            "maximum_output_token_cap": (
                self.testnet_max_output_token_cap if testnet_ready else None
            ),
            "supports_streaming": False,
            "production_strict": self.production_strict,
            "production_ready": testnet_ready,
            "limitation": None if testnet_ready else _APP_SERVER_OUTPUT_CAP_LIMITATION,
        }

    async def chat_completion(
        self,
        body: dict[str, Any],
        public_model: str | None = None,
    ) -> dict[str, Any]:
        self._assert_production_request(body)
        model = body.get("model") or "codex-cli"
        result = await self._run_turn(
            prompt=_messages_to_prompt(body.get("messages", [])),
            model=model,
            output_schema=_chat_output_schema(body),
        )
        self._validate_testnet_metering_result(body, result)
        response_model = public_model or model
        if _should_return_tool_call(body):
            return tool_call_payload(model=response_model, body=body, content=result.text or "ok")
        content = result.text or ""
        if _wants_json(body):
            content = _json_content(content, body)
        payload = chat_completion_payload(model=response_model, content=content)
        payload["usage"] = result.chat_usage()
        payload["codex_thread_id"] = result.thread_id
        payload["codex_turn_id"] = result.turn_id
        return payload

    async def response(
        self,
        body: dict[str, Any],
        public_model: str | None = None,
    ) -> dict[str, Any]:
        self._assert_production_request(body)
        model = body.get("model") or "codex-cli"
        response_model = public_model or model
        tool_outputs = _function_call_outputs(body.get("input"))
        if tool_outputs:
            return await self._continue_pending_tool_turn(
                body=body,
                public_model=response_model,
                tool_outputs=tool_outputs,
            )

        run_turn_kwargs: dict[str, Any] = {
            "prompt": _response_input_to_prompt(body.get("input", "")),
            "model": model,
            "output_schema": _response_output_schema(body),
            "tools": body.get("tools"),
        }
        if isinstance(body.get("instructions"), str):
            run_turn_kwargs["instructions"] = body["instructions"]
        reasoning = _reasoning_overrides(body.get("reasoning"))
        if reasoning:
            run_turn_kwargs["reasoning"] = reasoning
        result = await self._run_turn(**run_turn_kwargs)
        try:
            self._validate_testnet_metering_result(body, result)
        except BaseException:
            if result.client is not None:
                await result.client.close()
            raise
        if result.pending_tool_call:
            try:
                payload = response_function_call_payload(
                    model=response_model,
                    body=body,
                    tool_call=result.pending_tool_call,
                )
                await self._register_pending(payload["id"], PendingToolTurn(
                    client=result.client,
                    thread_id=result.thread_id,
                    turn_id=result.turn_id,
                    request_id=result.pending_tool_request_id,
                    body=dict(body),
                    public_model=response_model,
                    usage=result.usage,
                    call_id=str(payload["output"][0]["call_id"]),
                ))
            except BaseException:
                if result.client is not None:
                    await result.client.close()
                raise
            payload["usage"] = result.response_usage()
            payload["codex_thread_id"] = result.thread_id
            payload["codex_turn_id"] = result.turn_id
            return payload
        if _should_return_tool_call(body):
            payload = response_tool_call_payload(model=response_model, body=body, content=result.text or "ok")
        else:
            content = result.text or ""
            if _wants_json(body):
                content = _json_content(content, body)
            payload = response_payload(
                model=response_model,
                content=content,
                body=body,
                output_items=result.response_items,
            )
        payload["usage"] = result.response_usage()
        payload["codex_thread_id"] = result.thread_id
        payload["codex_turn_id"] = result.turn_id
        return payload

    def _assert_production_request(self, body: dict[str, Any]) -> None:
        requested_limit = _requested_max_output_tokens(body)
        if self.production_strict and self.testnet_metering:
            self._assert_testnet_request(body)
            if requested_limit is not None or not _function_call_outputs(body.get("input")):
                self._testnet_requested_output_cap(body)
            return
        if self.production_strict and requested_limit is not None:
            raise RuntimeError(
                f"{_APP_SERVER_OUTPUT_CAP_LIMITATION}; requested max output tokens="
                f"{requested_limit!r} cannot be enforced"
            )

    def _testnet_requested_output_cap(self, body: dict[str, Any]) -> int:
        requested_limit = _requested_max_output_tokens(body)
        if requested_limit is None:
            raise RuntimeError(
                "Codex testnet metering requires an explicit output-token cap"
            )
        if (
            isinstance(requested_limit, bool)
            or not isinstance(requested_limit, int)
            or requested_limit <= 0
        ):
            raise RuntimeError(
                "Codex testnet output-token cap must be a positive integer"
            )
        if requested_limit > self.testnet_max_output_token_cap:
            raise RuntimeError(
                "Codex testnet output-token cap exceeds the configured maximum: "
                f"{requested_limit} > {self.testnet_max_output_token_cap}"
            )
        return requested_limit

    def _validate_testnet_metering_result(
        self,
        body: dict[str, Any],
        result: "AppTurnResult",
        *,
        previous_usage: dict[str, Any] | None = None,
    ) -> None:
        if not (self.production_strict and self.testnet_metering):
            return
        output_token_cap = self._testnet_requested_output_cap(body)
        usage = result.usage
        if set(usage) != set(_NATIVE_USAGE_FIELDS):
            raise RuntimeError(
                "Codex app-server testnet metering returned an invalid native usage shape"
            )
        for field in _NATIVE_USAGE_FIELDS:
            count = usage.get(field)
            if type(count) is not int or count < 0:
                raise RuntimeError(
                    "Codex app-server testnet metering returned invalid native usage field "
                    f"{field}"
                )
        if usage["cachedInputTokens"] > usage["inputTokens"]:
            raise RuntimeError(
                "Codex app-server testnet metering cachedInputTokens exceeds inputTokens"
            )
        if usage["reasoningOutputTokens"] > usage["outputTokens"]:
            raise RuntimeError(
                "Codex app-server testnet metering reasoningOutputTokens exceeds outputTokens"
            )
        if usage["totalTokens"] != usage["inputTokens"] + usage["outputTokens"]:
            raise RuntimeError(
                "Codex app-server testnet metering totalTokens is inconsistent"
            )
        measured_usage = (
            _native_usage_delta(usage, previous_usage)
            if previous_usage is not None
            else usage
        )
        if measured_usage["cachedInputTokens"] > measured_usage["inputTokens"]:
            raise RuntimeError(
                "Codex app-server testnet metering incremental cachedInputTokens "
                "exceeds inputTokens"
            )
        if measured_usage["reasoningOutputTokens"] > measured_usage["outputTokens"]:
            raise RuntimeError(
                "Codex app-server testnet metering incremental reasoningOutputTokens "
                "exceeds outputTokens"
            )
        if (
            measured_usage["totalTokens"]
            != measured_usage["inputTokens"] + measured_usage["outputTokens"]
        ):
            raise RuntimeError(
                "Codex app-server testnet metering incremental totalTokens is inconsistent"
            )
        output_tokens = measured_usage["outputTokens"]
        if output_tokens > output_token_cap:
            raise RuntimeError(
                "Codex app-server output usage exceeded the authorized post-execution cap: "
                f"{output_tokens} > {output_token_cap}"
            )

    @staticmethod
    def _assert_testnet_request(body: dict[str, Any]) -> None:
        if body.get("stream") not in (None, False):
            raise RuntimeError("Codex testnet metering does not allow streaming")

    def _thread_start_params(
        self,
        *,
        model: str,
        tools: Any,
        instructions: Any = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": model,
            "cwd": self.workdir,
            "approvalPolicy": "never",
            "sandbox": _sandbox_mode(self.sandbox),
            "ephemeral": True,
            "dynamicTools": _dynamic_tools(tools),
        }
        if isinstance(instructions, str):
            params["developerInstructions"] = instructions
        hosted_tools_config = _hosted_tools_config(tools)
        if self.testnet_metering:
            params["config"] = {
                "web_search": "disabled",
                "mcp_servers": {},
                "plugins": {},
                "features": {
                    feature: False for feature in _CODEX_TESTNET_DISABLED_FEATURES
                },
            }
        elif hosted_tools_config:
            params["config"] = hosted_tools_config
            params["experimentalRawEvents"] = True
        return params

    def _turn_start_params(
        self,
        *,
        thread_id: str,
        prompt: str,
        model: str,
        output_schema: dict[str, Any] | None,
        reasoning: Any = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": prompt, "text_elements": []}],
            "cwd": self.workdir,
            "approvalPolicy": "never",
            "model": model,
        }
        if output_schema:
            params["outputSchema"] = output_schema
        params.update(_reasoning_overrides(reasoning))
        return params

    async def _continue_pending_tool_turn(
        self,
        body: dict[str, Any],
        public_model: str,
        tool_outputs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        previous_response_id = body.get("previous_response_id")
        if not isinstance(previous_response_id, str) or not previous_response_id:
            matches = [
                response_id
                for response_id, candidate in self._pending.items()
                if candidate.call_id
                and any(
                    str(output.get("call_id") or "") == candidate.call_id
                    for output in tool_outputs
                )
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    "function_call_output requires previous_response_id or a unique call_id"
                )
            previous_response_id = matches[0]
        pending = self._pending.get(previous_response_id)
        if pending is None:
            raise RuntimeError(f"unknown or expired previous_response_id: {previous_response_id}")
        matching_outputs = [
            output
            for output in tool_outputs
            if not pending.call_id
            or str(output.get("call_id") or "") == pending.call_id
        ]
        if len(matching_outputs) != 1:
            raise RuntimeError(
                "exactly one function_call_output must match the pending tool"
            )
        output = matching_outputs[0]
        self._pending.pop(previous_response_id, None)
        keep_client_open = False
        try:
            await self._cancel_pending_expiry(pending)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.timeout_seconds

            def remaining_timeout() -> float:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                return remaining

            combined_body = {**pending.body, **body}
            if pending.request_id is None:
                await asyncio.wait_for(
                    pending.client.request(
                        "thread/inject_items",
                        {
                            "threadId": pending.thread_id,
                            "items": [_structured_tool_output(output)],
                        },
                    ),
                    timeout=remaining_timeout(),
                )
                turn_response = await asyncio.wait_for(
                    pending.client.request(
                        "turn/start",
                        self._turn_start_params(
                            thread_id=pending.thread_id,
                            prompt="Continue the original task using the external tool result.",
                            model=str(pending.body.get("model") or "codex-cli"),
                            output_schema=_response_output_schema(combined_body),
                            reasoning=pending.body.get("reasoning"),
                        ),
                    ),
                    timeout=remaining_timeout(),
                )
                turn_id = turn_response["turn"]["id"]
            else:
                await asyncio.wait_for(
                    pending.client.respond(
                        pending.request_id,
                        {
                            "success": True,
                            "contentItems": _dynamic_tool_output_content(
                                output.get("output", "")
                            ),
                        },
                    ),
                    timeout=remaining_timeout(),
                )
                turn_id = pending.turn_id
            read_turn = pending.client.read_turn_until_stop(
                thread_id=pending.thread_id,
                turn_id=turn_id,
                **(
                    {"require_trusted_usage": True}
                    if self.production_strict
                    else {}
                ),
            )
            result = await asyncio.wait_for(read_turn, timeout=remaining_timeout())
            self._validate_testnet_metering_result(
                pending.body,
                result,
                previous_usage=pending.usage,
            )

            if result.pending_tool_call:
                incremental_usage = result.response_usage(previous=pending.usage)
                payload = response_function_call_payload(
                    model=public_model,
                    body={**pending.body, **body},
                    tool_call=result.pending_tool_call,
                )
                await self._register_pending(payload["id"], PendingToolTurn(
                    client=result.client or pending.client,
                    thread_id=result.thread_id,
                    turn_id=result.turn_id,
                    request_id=result.pending_tool_request_id,
                    body=combined_body,
                    public_model=public_model,
                    usage=result.usage,
                    call_id=str(payload["output"][0]["call_id"]),
                ))
                keep_client_open = True
                payload["usage"] = incremental_usage
                payload["codex_thread_id"] = result.thread_id
                payload["codex_turn_id"] = result.turn_id
                return payload

            content = result.text or ""
            if _wants_json(pending.body):
                content = _json_content(content, pending.body)
            payload = response_payload(
                model=public_model,
                content=content,
                body={**pending.body, **body},
                output_items=result.response_items,
            )
            payload["usage"] = result.response_usage(previous=pending.usage)
            payload["codex_thread_id"] = result.thread_id
            payload["codex_turn_id"] = result.turn_id
            return payload
        finally:
            if not keep_client_open:
                await pending.client.close()

    async def _register_pending(self, response_id: str, pending: "PendingToolTurn") -> None:
        if pending.client is None:
            raise RuntimeError("Codex app-server returned a tool call without an active client")
        if len(self._pending) >= self.max_pending_turns:
            await pending.client.close()
            raise RuntimeError(
                f"Codex app-server has reached {self.max_pending_turns} pending tool turns"
            )
        self._pending[response_id] = pending
        pending.expiry_task = asyncio.create_task(self._expire_pending(response_id, pending))

    async def _expire_pending(self, response_id: str, pending: "PendingToolTurn") -> None:
        try:
            await asyncio.sleep(self.pending_ttl_seconds)
            if self._pending.get(response_id) is pending:
                self._pending.pop(response_id, None)
                try:
                    await pending.client.close()
                except Exception:
                    pass
        except asyncio.CancelledError:
            return

    @staticmethod
    async def _cancel_pending_expiry(pending: "PendingToolTurn") -> None:
        task = pending.expiry_task
        if task is None:
            return
        pending.expiry_task = None
        if task.done():
            return
        task_loop = task.get_loop()
        if task_loop.is_closed():
            return
        current_loop = asyncio.get_running_loop()
        if task_loop is not current_loop:
            task_loop.call_soon_threadsafe(task.cancel)
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def close(self) -> None:
        pending_turns = list(self._pending.values())
        self._pending.clear()
        for pending in pending_turns:
            await self._cancel_pending_expiry(pending)
            try:
                await pending.client.close()
            except Exception:
                pass

    async def _run_turn(
        self,
        prompt: str,
        model: str,
        output_schema: dict[str, Any] | None = None,
        tools: Any = None,
        instructions: Any = None,
        reasoning: Any = None,
    ) -> "AppTurnResult":
        deadline = asyncio.get_running_loop().time() + self.timeout_seconds

        def remaining_timeout(limit: float) -> float:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            return min(float(limit), remaining)

        Path(self.codex_home).mkdir(parents=True, exist_ok=True)
        permit = self.process_limiter.acquire()
        try:
            process = await _create_codex_subprocess(
                self.command,
                "app-server",
                "--stdio",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=APP_SERVER_STREAM_LIMIT,
                env=_codex_subprocess_env(
                    self.codex_home,
                    strip_api_credentials=self.testnet_metering,
                ),
                **_subprocess_group_kwargs(),
            )
        except FileNotFoundError as exc:
            permit.release()
            raise RuntimeError(f"Codex command not found: {self.command}") from exc
        except BaseException:
            permit.release()
            raise
        client = _JsonRpcClient(
            process,
            stdout_max_bytes=self.stdout_max_bytes,
            stderr_retain_bytes=self.stderr_retain_bytes,
            max_messages=self.max_messages,
            process_permit=permit,
        )
        keep_client_open = False
        try:
            await asyncio.wait_for(
                client.request(
                    "initialize",
                    {
                        "clientInfo": {"name": "codex-gateway", "version": "0.1"},
                        "capabilities": {"experimentalApi": True},
                    },
                ),
                timeout=remaining_timeout(15),
            )
            thread_params = self._thread_start_params(
                model=model,
                tools=tools,
                instructions=instructions,
            )
            thread_response = await asyncio.wait_for(
                client.request("thread/start", thread_params),
                timeout=remaining_timeout(30),
            )
            thread_id = thread_response["thread"]["id"]
            turn_params = self._turn_start_params(
                thread_id=thread_id,
                prompt=prompt,
                model=model,
                output_schema=output_schema,
                reasoning=reasoning,
            )
            turn_response = await asyncio.wait_for(
                client.request("turn/start", turn_params),
                timeout=remaining_timeout(30),
            )
            turn_id = turn_response["turn"]["id"]
            result = await asyncio.wait_for(
                client.read_turn_until_stop(
                    thread_id=thread_id,
                    turn_id=turn_id,
                    require_trusted_usage=self.production_strict,
                ),
                timeout=remaining_timeout(self.timeout_seconds),
            )
            if result.pending_tool_call:
                keep_client_open = True
                return result
            return result
        finally:
            if not keep_client_open:
                await client.close()


@dataclass
class PendingToolTurn:
    client: "_JsonRpcClient"
    thread_id: str
    turn_id: str
    request_id: int | str | None
    body: dict[str, Any]
    public_model: str
    usage: dict[str, Any]
    call_id: str = ""
    expiry_task: asyncio.Task[None] | None = None


class AppTurnResult:
    def __init__(
        self,
        thread_id: str,
        turn_id: str,
        text: str,
        usage: dict[str, Any] | None,
        items: list[dict[str, Any]],
        client: "_JsonRpcClient | None" = None,
        pending_tool_request_id: int | str | None = None,
        pending_tool_call: dict[str, Any] | None = None,
        response_items: list[dict[str, Any]] | None = None,
    ) -> None:
        self.thread_id = thread_id
        self.turn_id = turn_id
        self.text = text
        self.usage = usage or {}
        self.items = items
        self.client = client
        self.pending_tool_request_id = pending_tool_request_id
        self.pending_tool_call = pending_tool_call
        self.response_items = response_items or []

    def chat_usage(self) -> dict[str, int]:
        return {
            "prompt_tokens": _usage_int(self.usage, "inputTokens"),
            "completion_tokens": _usage_int(self.usage, "outputTokens"),
            "total_tokens": _usage_int(self.usage, "totalTokens"),
        }

    def response_usage(self, *, previous: dict[str, Any] | None = None) -> dict[str, int]:
        usage = _native_usage_delta(self.usage, previous) if previous is not None else self.usage
        return {
            "input_tokens": _usage_int(usage, "inputTokens"),
            "output_tokens": _usage_int(usage, "outputTokens"),
            "total_tokens": _usage_int(usage, "totalTokens"),
        }


class _JsonRpcClient:
    def __init__(
        self,
        process: asyncio.subprocess.Process,
        *,
        stdout_max_bytes: int = DEFAULT_APP_SERVER_STDOUT_MAX_BYTES,
        stderr_retain_bytes: int = DEFAULT_APP_SERVER_STDERR_RETAIN_BYTES,
        max_messages: int = DEFAULT_APP_SERVER_MAX_MESSAGES,
        process_permit: _CodexProcessPermit | None = None,
    ) -> None:
        self.process = process
        self._next_id = 1
        self._stdout_max_bytes = stdout_max_bytes
        self._stderr_retain_bytes = stderr_retain_bytes
        self._max_messages = max_messages
        self._stdout_bytes = 0
        self._message_count = 0
        self._stderr = bytearray()
        self._stderr_truncated = False
        self._backlog: deque[dict[str, Any]] = deque()
        self._closed = False
        self._process_permit = process_permit
        self._close_task: asyncio.Task[None] | None = None
        self._stderr_task = (
            asyncio.create_task(self._drain_stderr())
            if self.process.stderr is not None
            else None
        )

    async def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        request_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = params
        await self._write(message)
        skipped: list[dict[str, Any]] = []
        try:
            while True:
                response = await self._next_message()
                if response.get("id") == request_id and "method" not in response:
                    if ("result" in response) == ("error" in response):
                        raise RuntimeError(
                            f"Codex app-server returned a malformed {method} response"
                        )
                    if "error" in response:
                        error = response["error"]
                        message = error.get("message") if isinstance(error, dict) else error
                        raise RuntimeError(str(message or f"{method} failed"))
                    return response.get("result")
                if response.get("method") == "item/tool/call":
                    skipped.append(response)
                    continue
                if await self._reject_unknown_server_request(response):
                    continue
                skipped.append(response)
        finally:
            for response in reversed(skipped):
                self._backlog.appendleft(response)

    async def respond(self, request_id: int | str, result: dict[str, Any]) -> None:
        await self._write({"jsonrpc": "2.0", "id": request_id, "result": result})

    async def send_request(self, method: str, params: dict[str, Any]) -> int:
        request_id = self._next_id
        self._next_id += 1
        await self._write(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        return request_id

    async def read_turn_until_stop(
        self,
        thread_id: str,
        turn_id: str,
        *,
        require_trusted_usage: bool = False,
    ) -> AppTurnResult:
        text_parts: list[str] = []
        completed_text: str | None = None
        items: list[dict[str, Any]] = []
        response_items: list[dict[str, Any]] = []
        usage: dict[str, Any] | None = None
        usage_version = 0
        deferred_tool_call: dict[str, Any] | None = None
        deferred_usage_version: int | None = None
        interrupt_request_id: int | None = None
        interrupt_acknowledged = False
        terminal_seen = False

        def result() -> AppTurnResult:
            _require_native_usage(usage, required=require_trusted_usage)
            text = completed_text if completed_text is not None else "".join(text_parts)
            return AppTurnResult(
                thread_id=thread_id,
                turn_id=turn_id,
                text=text,
                usage=usage,
                items=items,
                client=self if deferred_tool_call is not None else None,
                pending_tool_request_id=None,
                pending_tool_call=deferred_tool_call,
                response_items=response_items,
            )

        async def maybe_interrupt() -> None:
            nonlocal interrupt_request_id
            if (
                deferred_tool_call is not None
                and deferred_usage_version is not None
                and usage_version > deferred_usage_version
                and interrupt_request_id is None
            ):
                interrupt_request_id = await self.send_request(
                    "turn/interrupt",
                    {"threadId": thread_id, "turnId": turn_id},
                )

        while True:
            message = await self._next_message()
            if (
                interrupt_request_id is not None
                and message.get("id") == interrupt_request_id
                and "method" not in message
            ):
                if ("result" in message) == ("error" in message):
                    raise RuntimeError(
                        "Codex app-server returned a malformed turn/interrupt response"
                    )
                if "error" in message:
                    error = message["error"]
                    detail = error.get("message") if isinstance(error, dict) else error
                    raise RuntimeError(
                        f"Codex app-server could not interrupt metered tool turn: {detail}"
                    )
                interrupt_acknowledged = True
                if terminal_seen:
                    return result()
                continue
            if message.get("method") == "item/tool/call":
                params = message.get("params") or {}
                if params.get("threadId") != thread_id or params.get("turnId") != turn_id:
                    await self.respond(
                        message["id"],
                        {"success": False, "contentItems": [{"type": "inputText", "text": "Wrong turn"}]},
                    )
                    continue
                if require_trusted_usage and usage is not None:
                    return AppTurnResult(
                        thread_id=thread_id,
                        turn_id=turn_id,
                        text=(
                            completed_text
                            if completed_text is not None
                            else "".join(text_parts)
                        ),
                        usage=usage,
                        items=items,
                        client=self,
                        pending_tool_request_id=message["id"],
                        pending_tool_call=params,
                        response_items=response_items,
                    )
                if require_trusted_usage:
                    if deferred_tool_call is None:
                        deferred_tool_call = params
                        deferred_usage_version = usage_version
                    await self.respond(
                        message["id"],
                        {
                            "success": False,
                            "contentItems": [
                                {
                                    "type": "inputText",
                                    "text": "The external client will execute this tool call.",
                                }
                            ],
                        },
                    )
                    await maybe_interrupt()
                    continue
                _require_native_usage(usage, required=require_trusted_usage)
                return AppTurnResult(
                    thread_id=thread_id,
                    turn_id=turn_id,
                    text=completed_text if completed_text is not None else "".join(text_parts),
                    usage=usage,
                    items=items,
                    client=self,
                    pending_tool_request_id=message["id"],
                    pending_tool_call=params,
                    response_items=response_items,
                )
            if await self._reject_unknown_server_request(message):
                continue
            method = message.get("method")
            params = message.get("params") or {}
            if method == "error":
                raise RuntimeError(str(params.get("message") or params))
            if method == "rawResponseItem/completed":
                raw_item = _response_output_item(params.get("item"))
                if raw_item is not None:
                    response_items.append(raw_item)
                continue
            if params.get("threadId") != thread_id:
                continue
            if params.get("turnId") not in {None, turn_id}:
                continue
            if method == "item/agentMessage/delta":
                text_parts.append(str(params.get("delta", "")))
            elif method == "item/completed":
                item = params.get("item") or {}
                items.append(item)
                if item.get("type") == "agentMessage":
                    completed_text = str(item.get("text", ""))
                elif item.get("type") == "webSearch":
                    response_items.append(_web_search_thread_item_to_response_item(item))
            elif method == "thread/tokenUsage/updated":
                if require_trusted_usage and params.get("turnId") != turn_id:
                    continue
                next_usage = _validated_native_usage(params.get("tokenUsage"))
                if usage is not None:
                    _native_usage_delta(next_usage, usage)
                usage = next_usage
                usage_version += 1
                await maybe_interrupt()
            elif method == "turn/completed":
                turn = params.get("turn")
                if not isinstance(turn, dict) or turn.get("id") != turn_id:
                    continue
                status = turn.get("status")
                if status == "failed":
                    error = turn.get("error")
                    detail = error.get("message") if isinstance(error, dict) else error
                    raise RuntimeError(str(detail or "Codex app-server turn failed"))
                if deferred_tool_call is None:
                    valid_statuses = (
                        {"completed"}
                        if require_trusted_usage
                        else {None, "completed"}
                    )
                    if status not in valid_statuses:
                        raise RuntimeError(
                            f"Codex app-server turn ended with status {status!r}"
                        )
                    return result()
                if status != "interrupted":
                    raise RuntimeError(
                        "Codex app-server metered tool turn did not stop as interrupted"
                    )
                if (
                    deferred_usage_version is None
                    or usage_version <= deferred_usage_version
                ):
                    raise RuntimeError(
                        "Codex app-server stopped a tool turn without trusted native "
                        "token usage after the tool response"
                    )
                if interrupt_request_id is None:
                    raise RuntimeError(
                        "Codex app-server stopped a metered tool turn before interrupt"
                    )
                terminal_seen = True
                if interrupt_acknowledged:
                    return result()

    async def close(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_impl())
        await asyncio.shield(self._close_task)

    async def _close_impl(self) -> None:
        self._closed = True
        try:
            if self.process.stdin:
                self.process.stdin.close()
            await _stop_process(self.process, terminate_first=True)
            if self._stderr_task is not None:
                try:
                    await asyncio.wait_for(self._stderr_task, timeout=5)
                except asyncio.TimeoutError:
                    self._stderr_task.cancel()
                    await asyncio.gather(self._stderr_task, return_exceptions=True)
        finally:
            if self._stderr_task is not None and not self._stderr_task.done():
                self._stderr_task.cancel()
            if self._process_permit is not None:
                self._process_permit.release()
                self._process_permit = None

    async def _write(self, message: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise RuntimeError("Codex app-server stdin is closed")
        self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        await self.process.stdin.drain()

    async def _reject_unknown_server_request(self, message: dict[str, Any]) -> bool:
        if "id" not in message or not isinstance(message.get("method"), str):
            return False
        await self._write(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": "Method not found"},
            }
        )
        return True

    async def _next_message(self) -> dict[str, Any]:
        if self._backlog:
            return self._backlog.popleft()
        return await self._read()

    async def _read(self) -> dict[str, Any]:
        if self.process.stdout is None:
            raise RuntimeError("Codex app-server stdout is closed")
        try:
            line = await self.process.stdout.readline()
        except (ValueError, asyncio.LimitOverrunError) as exc:
            raise RuntimeError(
                f"Codex app-server message exceeded {APP_SERVER_STREAM_LIMIT} bytes"
            ) from exc
        if not line:
            detail = self._stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(detail or "Codex app-server closed")
        self._stdout_bytes += len(line)
        if self._stdout_bytes > self._stdout_max_bytes:
            raise RuntimeError(
                "Codex app-server cumulative stdout exceeded "
                f"{self._stdout_max_bytes} bytes"
            )
        self._message_count += 1
        if self._message_count > self._max_messages:
            raise RuntimeError(
                f"Codex app-server exceeded {self._max_messages} messages"
            )
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Codex app-server returned invalid JSON") from exc
        if not isinstance(message, dict):
            raise RuntimeError("Codex app-server returned a non-object JSON-RPC message")
        return message

    async def _drain_stderr(self) -> None:
        stream = self.process.stderr
        if stream is None:
            return
        while True:
            chunk = await stream.read(64 * 1024)
            if not chunk:
                return
            remaining = self._stderr_retain_bytes - len(self._stderr)
            if remaining > 0:
                self._stderr.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self._stderr_truncated = True


def _messages_to_prompt(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for message in messages:
        role = message.get("role", "unknown")
        content = _content_to_text(message.get("content", ""))
        if content:
            parts.append(f"{role.upper()}:\n{content}")
    return "\n\n".join(parts).strip()


def _response_input_to_prompt(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                role = item.get("role", "user")
                content = _content_to_text(item.get("content", ""))
                if content:
                    parts.append(f"{role.upper()}:\n{content}")
            else:
                parts.append(str(item))
        return "\n\n".join(parts).strip()
    return str(value)


def _function_call_outputs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value
        if isinstance(item, dict)
        and item.get("type") in {"function_call_output", "custom_tool_call_output"}
    ]


def _dynamic_tool_output_content(output: Any) -> list[dict[str, str]]:
    if isinstance(output, str):
        return [{"type": "inputText", "text": output}]
    return [{"type": "inputText", "text": json.dumps(output, ensure_ascii=False)}]


def _structured_tool_output(output: dict[str, Any]) -> dict[str, Any]:
    value = output.get("output", "")
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    return {
        "type": output["type"],
        "call_id": str(output.get("call_id") or ""),
        "output": value,
    }


def _reasoning_overrides(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    overrides: dict[str, str] = {}
    effort = value.get("effort")
    if isinstance(effort, str) and effort:
        overrides["effort"] = effort
    summary = value.get("summary")
    if summary in {"auto", "concise", "detailed", "none"}:
        overrides["summary"] = summary
    return overrides


def _dynamic_tools(tools: Any) -> list[dict[str, Any]] | None:
    if not isinstance(tools, list):
        return None
    dynamic_tools: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_type = tool.get("type")
        if tool_type == "custom":
            name = tool.get("name")
            if name:
                name = _dynamic_tool_name(str(name))
                dynamic_tools.append(
                    {
                        "type": "function",
                        "name": name,
                        "description": str(tool.get("description") or f"Call {name}."),
                        "inputSchema": {
                            "type": "object",
                            "properties": {"input": {"type": "string"}},
                            "required": ["input"],
                            "additionalProperties": False,
                        },
                    }
                )
            continue
        if tool_type != "function" and "function" not in tool:
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = function.get("name")
        if not name:
            continue
        name = _dynamic_tool_name(str(name))
        parameters = function.get("parameters")
        dynamic_tools.append(
            {
                "type": "function",
                "name": name,
                "description": str(function.get("description") or f"Call {name}."),
                "inputSchema": parameters if isinstance(parameters, dict) else {"type": "object", "properties": {}},
            }
        )
    return dynamic_tools or None


def _dynamic_tool_name(name: str) -> str:
    if name in _CODEX_BUILTIN_DYNAMIC_TOOL_NAMES:
        return f"{_CLIENT_DYNAMIC_TOOL_PREFIX}{name}"
    return name


def _client_tool_name(name: str, tools: Any) -> str:
    if not name.startswith(_CLIENT_DYNAMIC_TOOL_PREFIX) or not isinstance(tools, list):
        return name
    original = name[len(_CLIENT_DYNAMIC_TOOL_PREFIX) :]
    if original not in _CODEX_BUILTIN_DYNAMIC_TOOL_NAMES:
        return name
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function")
        candidate = function.get("name") if isinstance(function, dict) else tool.get("name")
        if candidate == original:
            return original
    return name


def _hosted_tools_config(tools: Any) -> dict[str, Any] | None:
    web_search_tool = _hosted_web_search_tool(tools)
    if web_search_tool is None:
        return None

    web_search_config: dict[str, Any] = {}
    context_size = web_search_tool.get("search_context_size") or web_search_tool.get("context_size")
    if context_size in {"low", "medium", "high"}:
        web_search_config["context_size"] = context_size

    allowed_domains = web_search_tool.get("allowed_domains")
    if isinstance(allowed_domains, list) and all(isinstance(domain, str) for domain in allowed_domains):
        web_search_config["allowed_domains"] = allowed_domains

    location = _web_search_location(web_search_tool.get("user_location") or web_search_tool.get("location"))
    if location:
        web_search_config["location"] = location

    return {"web_search": "live", "tools": {"web_search": web_search_config}}


def _hosted_web_search_tool(tools: Any) -> dict[str, Any] | None:
    if not isinstance(tools, list):
        return None
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_type = tool.get("type")
        if isinstance(tool_type, str) and (tool_type == "web_search" or tool_type.startswith("web_search_preview")):
            return tool
    return None


def _web_search_location(location: Any) -> dict[str, str] | None:
    if not isinstance(location, dict):
        return None
    normalized = {
        key: value
        for key in ("city", "country", "region", "timezone")
        if isinstance((value := location.get(key)), str) and value
    }
    return normalized or None


def _response_output_item(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    if item.get("type") != "web_search_call":
        return None
    response_item = {
        key: value
        for key, value in item.items()
        if not str(key).startswith("internal_")
    }
    response_item["id"] = str(response_item.get("id") or f"ws_{uuid.uuid4().hex}")
    response_item["status"] = response_item.get("status") or "completed"
    return response_item


def _web_search_thread_item_to_response_item(item: dict[str, Any]) -> dict[str, Any]:
    response_item: dict[str, Any] = {
        "id": str(item.get("id") or f"ws_{uuid.uuid4().hex}"),
        "type": "web_search_call",
        "status": "completed",
    }
    action = item.get("action")
    if isinstance(action, dict):
        response_item["action"] = action
    return response_item


def response_function_call_payload(
    model: str,
    body: dict[str, Any],
    tool_call: dict[str, Any],
) -> dict[str, Any]:
    response_id = f"resp_{uuid.uuid4().hex}"
    arguments = tool_call.get("arguments")
    if not isinstance(arguments, str):
        arguments = json.dumps(arguments if arguments is not None else {}, ensure_ascii=False)
    call_id = str(tool_call.get("callId") or f"call_{uuid.uuid4().hex[:24]}")
    name = _client_tool_name(
        str(tool_call.get("tool") or "tool"),
        body.get("tools"),
    )
    custom_tool = any(
        isinstance(tool, dict)
        and tool.get("type") == "custom"
        and str(tool.get("name") or "") == name
        for tool in body.get("tools", [])
    ) if isinstance(body.get("tools"), list) else False
    if custom_tool:
        try:
            parsed_arguments = json.loads(arguments)
        except (TypeError, ValueError):
            parsed_arguments = arguments
        custom_input = (
            parsed_arguments.get("input")
            if isinstance(parsed_arguments, dict)
            else parsed_arguments
        )
        output_item = {
            "id": f"ct_{uuid.uuid4().hex}",
            "type": "custom_tool_call",
            "status": "completed",
            "call_id": call_id,
            "name": name,
            "input": str(custom_input if custom_input is not None else ""),
        }
    else:
        output_item = {
            "id": f"fc_{uuid.uuid4().hex}",
            "type": "function_call",
            "status": "completed",
            "call_id": call_id,
            "name": name,
            "arguments": arguments,
        }
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "error": None,
        "incomplete_details": None,
        "instructions": body.get("instructions"),
        "max_output_tokens": body.get("max_output_tokens"),
        "metadata": body.get("metadata") or {},
        "status": "completed",
        "model": model,
        "output": [output_item],
        "output_text": "",
        "parallel_tool_calls": body.get("parallel_tool_calls", True),
        "previous_response_id": body.get("previous_response_id"),
        "reasoning": body.get("reasoning") or {"effort": None, "summary": None},
        "store": body.get("store", True),
        "temperature": body.get("temperature"),
        "text": body.get("text") or {"format": {"type": "text"}},
        "tool_choice": body.get("tool_choice", "auto"),
        "tools": body.get("tools", []),
        "top_p": body.get("top_p"),
        "truncation": body.get("truncation", "disabled"),
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
    }


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") in {"text", "input_text", "output_text"}:
                    text_parts.append(str(item.get("text", "")))
                elif "text" in item:
                    text_parts.append(str(item["text"]))
        return "\n".join(part for part in text_parts if part)
    return str(content)


def _wants_json(body: dict[str, Any]) -> bool:
    return _json_schema(body) is not None or (
        isinstance(body.get("response_format"), dict)
        and body["response_format"].get("type") == "json_object"
    )


def _json_content(content: str, body: dict[str, Any]) -> str:
    schema = _json_schema(body)
    if schema:
        return json_schema_content(content.strip() or "ok", schema)
    stripped = content.strip()
    try:
        json.loads(stripped)
        return stripped
    except json.JSONDecodeError:
        return json.dumps({"result": stripped}, ensure_ascii=False)


def _should_return_tool_call(body: dict[str, Any]) -> bool:
    tools = body.get("tools")
    if not isinstance(tools, list) or not tools:
        return False
    tool_choice = body.get("tool_choice")
    return tool_choice == "required" or isinstance(tool_choice, dict)


def _chat_output_schema(body: dict[str, Any]) -> dict[str, Any] | None:
    return _json_schema(body)


def _response_output_schema(body: dict[str, Any]) -> dict[str, Any] | None:
    return _json_schema(body)


def _json_schema(body: dict[str, Any]) -> dict[str, Any] | None:
    response_format = body.get("response_format")
    if isinstance(response_format, dict):
        if response_format.get("type") == "json_schema":
            json_schema = response_format.get("json_schema")
            if isinstance(json_schema, dict) and isinstance(json_schema.get("schema"), dict):
                return json_schema["schema"]
        if isinstance(response_format.get("schema"), dict):
            return response_format["schema"]
    text = body.get("text")
    if isinstance(text, dict):
        text_format = text.get("format")
        if isinstance(text_format, dict) and isinstance(text_format.get("schema"), dict):
            return text_format["schema"]
    return None


def _schema_value(schema: dict[str, Any], fallback: str) -> Any:
    return coerce_to_schema(fallback, schema, fallback)


def _sandbox_mode(value: str) -> str:
    if value in {"read-only", "workspace-write", "danger-full-access"}:
        return value
    return "workspace-write"


def _codex_subprocess_env(
    codex_home: str,
    *,
    strip_api_credentials: bool,
) -> dict[str, str]:
    if strip_api_credentials:
        env = {
            name: os.environ[name]
            for name in _CODEX_TESTNET_ENV_ALLOWLIST
            if name in os.environ
        }
    else:
        env = dict(os.environ)
        for name in _CODEX_API_CREDENTIAL_ENV:
            if not os.environ.get(name):
                env.pop(name, None)
    env["CODEX_HOME"] = codex_home
    return env


def _usage_int(usage: dict[str, Any], key: str) -> int:
    value = usage.get(key)
    return value if isinstance(value, int) else 0


def _native_usage_delta(
    current: dict[str, Any],
    previous: dict[str, Any],
) -> dict[str, int]:
    delta: dict[str, int] = {}
    for field in _NATIVE_USAGE_FIELDS:
        current_value = _usage_int(current, field)
        previous_value = _usage_int(previous, field)
        if current_value < previous_value:
            raise RuntimeError("Codex app-server cumulative token usage decreased")
        delta[field] = current_value - previous_value
    return delta


def _validated_native_usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise RuntimeError("Codex app-server returned malformed native token usage")
    validated: dict[str, dict[str, int]] = {}
    for scope in ("last", "total"):
        breakdown = value.get(scope)
        if not isinstance(breakdown, dict):
            raise RuntimeError(
                f"Codex app-server native token usage is missing {scope!r} breakdown"
            )
        current: dict[str, int] = {}
        for field in _NATIVE_USAGE_FIELDS:
            count = breakdown.get(field)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise RuntimeError(
                    "Codex app-server native token usage field "
                    f"{scope}.{field} must be a non-negative integer"
                )
            current[field] = count
        if current["cachedInputTokens"] > current["inputTokens"]:
            raise RuntimeError(
                f"Codex app-server native token usage {scope}.cachedInputTokens "
                "exceeds inputTokens"
            )
        if current["reasoningOutputTokens"] > current["outputTokens"]:
            raise RuntimeError(
                f"Codex app-server native token usage {scope}.reasoningOutputTokens "
                "exceeds outputTokens"
            )
        if current["totalTokens"] != current["inputTokens"] + current["outputTokens"]:
            raise RuntimeError(
                f"Codex app-server native token usage {scope}.totalTokens is inconsistent"
            )
        validated[scope] = current
    return validated["total"]


def _require_native_usage(usage: dict[str, Any] | None, *, required: bool) -> None:
    if required and usage is None:
        raise RuntimeError(
            "Codex app-server completed without trusted native token usage"
        )
