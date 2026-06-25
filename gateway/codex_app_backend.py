from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .codex_backend import (
    chat_completion_payload,
    response_payload,
    response_tool_call_payload,
    tool_call_payload,
)
from .schema_output import coerce_to_schema, json_schema_content

APP_SERVER_STREAM_LIMIT = 8 * 1024 * 1024


class CodexAppServerBackend:
    def __init__(
        self,
        command: str,
        codex_home: str,
        workdir: str,
        sandbox: str,
        timeout_seconds: float,
    ) -> None:
        self.command = command
        self.codex_home = codex_home
        self.workdir = workdir
        self.sandbox = sandbox
        self.timeout_seconds = timeout_seconds
        self._pending: dict[str, PendingToolTurn] = {}

    async def chat_completion(
        self,
        body: dict[str, Any],
        public_model: str | None = None,
    ) -> dict[str, Any]:
        model = body.get("model") or "codex-cli"
        result = await self._run_turn(
            prompt=_messages_to_prompt(body.get("messages", [])),
            model=model,
            output_schema=_chat_output_schema(body),
        )
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
        model = body.get("model") or "codex-cli"
        response_model = public_model or model
        tool_outputs = _function_call_outputs(body.get("input"))
        if tool_outputs:
            return await self._continue_pending_tool_turn(
                body=body,
                public_model=response_model,
                tool_outputs=tool_outputs,
            )

        result = await self._run_turn(
            prompt=_response_input_to_prompt(body.get("input", "")),
            model=model,
            output_schema=_response_output_schema(body),
            tools=body.get("tools"),
        )
        if result.pending_tool_call:
            payload = response_function_call_payload(
                model=response_model,
                body=body,
                tool_call=result.pending_tool_call,
            )
            self._pending[payload["id"]] = PendingToolTurn(
                client=result.client,
                thread_id=result.thread_id,
                turn_id=result.turn_id,
                request_id=result.pending_tool_request_id,
                body=dict(body),
                public_model=response_model,
                usage=result.usage,
            )
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

    async def _continue_pending_tool_turn(
        self,
        body: dict[str, Any],
        public_model: str,
        tool_outputs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        previous_response_id = body.get("previous_response_id")
        if not isinstance(previous_response_id, str) or not previous_response_id:
            raise RuntimeError("previous_response_id is required when sending function_call_output")
        pending = self._pending.pop(previous_response_id, None)
        if pending is None:
            raise RuntimeError(f"unknown or expired previous_response_id: {previous_response_id}")

        output = tool_outputs[0]
        try:
            await pending.client.respond(
                pending.request_id,
                {
                    "success": True,
                    "contentItems": _dynamic_tool_output_content(output.get("output", "")),
                },
            )
            result = await asyncio.wait_for(
                pending.client.read_turn_until_stop(thread_id=pending.thread_id, turn_id=pending.turn_id),
                timeout=self.timeout_seconds,
            )
        except Exception:
            await pending.client.close()
            raise

        if result.pending_tool_call:
            payload = response_function_call_payload(
                model=public_model,
                body={**pending.body, **body},
                tool_call=result.pending_tool_call,
            )
            self._pending[payload["id"]] = PendingToolTurn(
                client=result.client or pending.client,
                thread_id=result.thread_id,
                turn_id=result.turn_id,
                request_id=result.pending_tool_request_id,
                body={**pending.body, **body},
                public_model=public_model,
                usage=result.usage,
            )
            payload["usage"] = result.response_usage()
            payload["codex_thread_id"] = result.thread_id
            payload["codex_turn_id"] = result.turn_id
            return payload

        await pending.client.close()
        content = result.text or ""
        if _wants_json(pending.body):
            content = _json_content(content, pending.body)
        payload = response_payload(
            model=public_model,
            content=content,
            body={**pending.body, **body},
            output_items=result.response_items,
        )
        payload["usage"] = result.response_usage()
        payload["codex_thread_id"] = result.thread_id
        payload["codex_turn_id"] = result.turn_id
        return payload

    async def _run_turn(
        self,
        prompt: str,
        model: str,
        output_schema: dict[str, Any] | None = None,
        tools: Any = None,
    ) -> "AppTurnResult":
        Path(self.codex_home).mkdir(parents=True, exist_ok=True)
        process = await asyncio.create_subprocess_exec(
            self.command,
            "app-server",
            "--stdio",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=APP_SERVER_STREAM_LIMIT,
            env={**os.environ, "CODEX_HOME": self.codex_home},
        )
        client = _JsonRpcClient(process)
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
                timeout=15,
            )
            thread_params: dict[str, Any] = {
                "model": model,
                "cwd": self.workdir,
                "approvalPolicy": "never",
                "sandbox": _sandbox_mode(self.sandbox),
                "ephemeral": True,
                "dynamicTools": _dynamic_tools(tools),
            }
            hosted_tools_config = _hosted_tools_config(tools)
            if hosted_tools_config:
                thread_params["config"] = hosted_tools_config
                thread_params["experimentalRawEvents"] = True
            thread_response = await asyncio.wait_for(
                client.request("thread/start", thread_params),
                timeout=30,
            )
            thread_id = thread_response["thread"]["id"]
            turn_params: dict[str, Any] = {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt, "text_elements": []}],
                "cwd": self.workdir,
                "approvalPolicy": "never",
                "model": model,
            }
            if output_schema:
                turn_params["outputSchema"] = output_schema
            turn_response = await asyncio.wait_for(
                client.request("turn/start", turn_params),
                timeout=30,
            )
            turn_id = turn_response["turn"]["id"]
            result = await asyncio.wait_for(
                client.read_turn_until_stop(thread_id=thread_id, turn_id=turn_id),
                timeout=self.timeout_seconds,
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
    request_id: int | str
    body: dict[str, Any]
    public_model: str
    usage: dict[str, Any]


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

    def response_usage(self) -> dict[str, int]:
        return {
            "input_tokens": _usage_int(self.usage, "inputTokens"),
            "output_tokens": _usage_int(self.usage, "outputTokens"),
            "total_tokens": _usage_int(self.usage, "totalTokens"),
        }


class _JsonRpcClient:
    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process
        self._next_id = 1

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
        while True:
            response = await self._read()
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise RuntimeError(response["error"].get("message", f"{method} failed"))
            return response.get("result")

    async def respond(self, request_id: int | str, result: dict[str, Any]) -> None:
        await self._write({"jsonrpc": "2.0", "id": request_id, "result": result})

    async def read_turn_until_stop(self, thread_id: str, turn_id: str) -> AppTurnResult:
        text_parts: list[str] = []
        completed_text: str | None = None
        items: list[dict[str, Any]] = []
        response_items: list[dict[str, Any]] = []
        usage: dict[str, Any] | None = None
        while True:
            message = await self._read()
            if message.get("method") == "item/tool/call":
                params = message.get("params") or {}
                if params.get("threadId") != thread_id or params.get("turnId") != turn_id:
                    await self.respond(
                        message["id"],
                        {"success": False, "contentItems": [{"type": "inputText", "text": "Wrong turn"}]},
                    )
                    continue
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
            method = message.get("method")
            params = message.get("params") or {}
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
                token_usage = params.get("tokenUsage") or {}
                usage = token_usage.get("last") or token_usage.get("total")
            elif method == "turn/completed":
                text = completed_text if completed_text is not None else "".join(text_parts)
                return AppTurnResult(
                    thread_id=thread_id,
                    turn_id=turn_id,
                    text=text,
                    usage=usage,
                    items=items,
                    response_items=response_items,
                )
            elif method == "error":
                raise RuntimeError(str(params.get("message") or params))

    async def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self.process.stderr:
            await self.process.stderr.read()

    async def _write(self, message: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise RuntimeError("Codex app-server stdin is closed")
        self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        await self.process.stdin.drain()

    async def _read(self) -> dict[str, Any]:
        if self.process.stdout is None:
            raise RuntimeError("Codex app-server stdout is closed")
        line = await self.process.stdout.readline()
        if not line:
            raise RuntimeError("Codex app-server closed")
        return json.loads(line.decode("utf-8"))


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
        if isinstance(item, dict) and item.get("type") == "function_call_output"
    ]


def _dynamic_tool_output_content(output: Any) -> list[dict[str, str]]:
    if isinstance(output, str):
        return [{"type": "inputText", "text": output}]
    return [{"type": "inputText", "text": json.dumps(output, ensure_ascii=False)}]


def _dynamic_tools(tools: Any) -> list[dict[str, Any]] | None:
    if not isinstance(tools, list):
        return None
    dynamic_tools: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        if tool.get("type") != "function" and "function" not in tool:
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = function.get("name")
        if not name:
            continue
        parameters = function.get("parameters")
        dynamic_tools.append(
            {
                "type": "function",
                "name": str(name),
                "description": str(function.get("description") or f"Call {name}."),
                "inputSchema": parameters if isinstance(parameters, dict) else {"type": "object", "properties": {}},
            }
        )
    return dynamic_tools or None


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
    output_item = {
        "id": f"fc_{uuid.uuid4().hex}",
        "type": "function_call",
        "status": "completed",
        "call_id": call_id,
        "name": str(tool_call.get("tool") or "tool"),
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


def _usage_int(usage: dict[str, Any], key: str) -> int:
    value = usage.get(key)
    return value if isinstance(value, int) else 0
