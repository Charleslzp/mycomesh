from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from .schema_output import coerce_to_schema, json_schema_content


class CodexCliBackend:
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

    async def chat_completion(
        self,
        body: dict[str, Any],
        public_model: str | None = None,
    ) -> dict[str, Any]:
        prompt = _messages_to_prompt(body.get("messages", []))
        model = body.get("model") or "codex-cli"
        output = await self._exec(prompt=prompt, model=model)
        if _should_return_tool_call(body):
            return tool_call_payload(model=public_model or model, body=body, content=output)
        if _wants_json(body):
            output = _json_content(output, body)
        return chat_completion_payload(model=public_model or model, content=output)

    async def response(
        self,
        body: dict[str, Any],
        public_model: str | None = None,
    ) -> dict[str, Any]:
        prompt = _response_input_to_prompt(body.get("input", ""))
        model = body.get("model") or "codex-cli"
        output = await self._exec(prompt=prompt, model=model)
        if _should_return_tool_call(body):
            return response_tool_call_payload(model=public_model or model, body=body, content=output)
        if _wants_json(body):
            output = _json_content(output, body)
        return response_payload(model=public_model or model, content=output, body=body)

    async def _exec(self, prompt: str, model: str) -> str:
        Path(self.codex_home).mkdir(parents=True, exist_ok=True)
        cmd = [
            self.command,
            "exec",
            "--cd",
            self.workdir,
            "--sandbox",
            self.sandbox,
            "--skip-git-repo-check",
            "--output-last-message",
            "-",
        ]
        if model and model != "codex-cli":
            cmd.extend(["--model", model])
        cmd.append("-")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "CODEX_HOME": self.codex_home},
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"Codex command not found: {self.command}") from exc

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(prompt.encode("utf-8")),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise RuntimeError("Codex CLI timed out") from exc

        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(stderr_text or "Codex CLI failed")

        return stdout.decode("utf-8", errors="replace").strip()


def chat_completion_payload(model: str, content: str) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-codex-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": _chat_usage(),
    }


def tool_call_payload(model: str, body: dict[str, Any], content: str) -> dict[str, Any]:
    tool = _first_tool(body)
    name = tool.get("function", {}).get("name", "tool") if tool else "tool"
    arguments = _tool_arguments(tool, content)
    return {
        "id": f"chatcmpl-codex-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call_{uuid.uuid4().hex[:24]}",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": arguments,
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": _chat_usage(),
    }


def fast_chat_payload(model: str, body: dict[str, Any], fallback: str = "ok") -> dict[str, Any] | None:
    if _should_return_tool_call(body):
        return tool_call_payload(model=model, body=body, content=fallback)
    if _wants_json(body):
        return chat_completion_payload(
            model=model,
            content=_json_content(fallback, body),
        )
    return None


def chat_completion_chunk(model: str, content: str, finish: bool = False) -> dict[str, Any]:
    chunk_id = f"chatcmpl-codex-{uuid.uuid4().hex}"
    if finish:
        delta: dict[str, Any] = {}
        finish_reason = "stop"
    else:
        delta = {"role": "assistant", "content": content}
        finish_reason = None
    return {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }
        ],
    }


def response_payload(
    model: str,
    content: str,
    body: dict[str, Any] | None = None,
    output_items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    body = body or {}
    response_id = f"resp_{uuid.uuid4().hex}"
    output_id = f"msg_{uuid.uuid4().hex}"
    passthrough_items = _response_output_items(output_items)
    has_hosted_web_search_result = any(item.get("type") == "web_search_call" for item in passthrough_items)
    message_item = {
        "id": output_id,
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [
            {
                "type": "output_text",
                "text": content,
                "annotations": [],
            }
        ],
    }
    output = [*passthrough_items, message_item]
    tools = body.get("tools", [])
    if not has_hosted_web_search_result:
        tools = _without_web_search_tools(tools)
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
        "output": output,
        "output_text": content,
        "parallel_tool_calls": body.get("parallel_tool_calls", True),
        "previous_response_id": body.get("previous_response_id"),
        "reasoning": body.get("reasoning") or {"effort": None, "summary": None},
        "store": body.get("store", True),
        "temperature": body.get("temperature"),
        "text": body.get("text") or {"format": {"type": "text"}},
        "tool_choice": body.get("tool_choice", "auto"),
        "tools": tools,
        "top_p": body.get("top_p"),
        "truncation": body.get("truncation", "disabled"),
        "usage": _response_usage(body=body, content=content),
    }


def _response_output_items(items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized_items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        normalized = dict(item)
        if normalized.get("type") == "web_search_call":
            normalized["id"] = str(normalized.get("id") or f"ws_{uuid.uuid4().hex}")
            normalized["status"] = normalized.get("status") or "completed"
        item_key = (str(normalized.get("type") or ""), str(normalized.get("id") or ""))
        if item_key in seen:
            continue
        seen.add(item_key)
        normalized_items.append(normalized)
    return normalized_items


def _without_web_search_tools(tools: Any) -> Any:
    if not isinstance(tools, list):
        return tools
    return [
        tool
        for tool in tools
        if not (
            isinstance(tool, dict)
            and isinstance(tool.get("type"), str)
            and (tool["type"] == "web_search" or tool["type"].startswith("web_search_preview"))
        )
    ]


def response_tool_call_payload(model: str, body: dict[str, Any], content: str) -> dict[str, Any]:
    response_id = f"resp_{uuid.uuid4().hex}"
    call_id = f"call_{uuid.uuid4().hex[:24]}"
    tool = _first_tool(body)
    name = _tool_name(tool)
    arguments = _tool_arguments(tool, content)
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
        "output": [
            {
                "id": f"fc_{uuid.uuid4().hex}",
                "type": "function_call",
                "status": "completed",
                "call_id": call_id,
                "name": name,
                "arguments": arguments,
            }
        ],
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
        "usage": _response_usage(body=body, content=content),
    }


def fast_response_payload(model: str, body: dict[str, Any], fallback: str = "ok") -> dict[str, Any] | None:
    if _should_return_tool_call(body):
        return response_tool_call_payload(model=model, body=body, content=fallback)
    if _wants_json(body):
        return response_payload(
            model=model,
            content=_json_content(fallback, body),
            body=body,
        )
    return None


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


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    text_parts.append(str(item.get("text", "")))
                elif item.get("type") in {"input_text", "output_text"}:
                    text_parts.append(str(item.get("text", "")))
                elif "text" in item:
                    text_parts.append(str(item["text"]))
        return "\n".join(part for part in text_parts if part)
    return str(content)


def _wants_json(body: dict[str, Any]) -> bool:
    response_format = body.get("response_format")
    if isinstance(response_format, dict):
        return response_format.get("type") in {"json_object", "json_schema"}
    text = body.get("text")
    if isinstance(text, dict):
        text_format = text.get("format")
        if isinstance(text_format, dict):
            return text_format.get("type") in {"json_object", "json_schema"}
    return False


def _json_content(content: str, body: dict[str, Any] | None = None) -> str:
    stripped = content.strip()
    schema = _json_schema(body or {})
    if schema:
        return json_schema_content(stripped, schema)
    if stripped:
        try:
            json.loads(stripped)
            return stripped
        except json.JSONDecodeError:
            pass
    return json.dumps({"result": stripped}, ensure_ascii=False)


def _should_return_tool_call(body: dict[str, Any]) -> bool:
    tools = body.get("tools")
    if not isinstance(tools, list) or not tools:
        return False
    if _first_tool(body) is None:
        return False
    tool_choice = body.get("tool_choice")
    if tool_choice == "required":
        return True
    if isinstance(tool_choice, dict):
        return True
    if tool_choice in {"none", "auto"}:
        return tool_choice != "none" and _prompt_mentions_tool(body)
    return _prompt_mentions_tool(body)


def _prompt_mentions_tool(body: dict[str, Any]) -> bool:
    prompt = _body_prompt(body).lower()
    return any(marker in prompt for marker in ["tool", "function", "调用工具", "函数"])


def _first_tool(body: dict[str, Any]) -> dict[str, Any] | None:
    selected_name = _selected_tool_name(body.get("tool_choice"))
    function_tools: list[dict[str, Any]] = []
    for tool in body.get("tools", []):
        if not isinstance(tool, dict):
            continue
        if tool.get("type") == "function" or "function" in tool:
            if selected_name and _tool_name(tool) == selected_name:
                return tool
            function_tools.append(tool)
    if function_tools:
        return function_tools[0]
    return None


def _selected_tool_name(tool_choice: Any) -> str | None:
    if isinstance(tool_choice, dict):
        function = tool_choice.get("function")
        if isinstance(function, dict) and function.get("name"):
            return str(function["name"])
        if tool_choice.get("name"):
            return str(tool_choice["name"])
    return None


def _body_prompt(body: dict[str, Any]) -> str:
    if isinstance(body.get("messages"), list):
        return _messages_to_prompt(body["messages"])
    if "input" in body:
        return _response_input_to_prompt(body["input"])
    return ""


def _function_parameters(tool: dict[str, Any]) -> dict[str, Any]:
    function = tool.get("function")
    if isinstance(function, dict):
        parameters = function.get("parameters")
        if isinstance(parameters, dict):
            return parameters
    parameters = tool.get("parameters")
    if isinstance(parameters, dict):
        return parameters
    return {}


def _tool_name(tool: dict[str, Any] | None) -> str:
    if not tool:
        return "tool"
    function = tool.get("function")
    if isinstance(function, dict) and function.get("name"):
        return str(function["name"])
    if tool.get("name"):
        return str(tool["name"])
    return "tool"


def _tool_arguments(tool: dict[str, Any] | None, content: str) -> str:
    if not tool:
        return "{}"
    parameters = _function_parameters(tool)
    if isinstance(parameters, dict) and parameters.get("type") == "object":
        return json.dumps(coerce_to_schema(content, parameters, content), ensure_ascii=False)
    properties = parameters.get("properties", {}) if isinstance(parameters, dict) else {}
    args: dict[str, Any] = {}
    if isinstance(properties, dict):
        for key, schema in properties.items():
            if not isinstance(schema, dict):
                args[key] = content
                continue
            schema_type = schema.get("type")
            if schema_type == "string":
                args[key] = content
            elif schema_type in {"number", "integer"}:
                args[key] = 0
            elif schema_type == "boolean":
                args[key] = False
            elif schema_type == "array":
                args[key] = []
            elif schema_type == "object":
                args[key] = {}
            else:
                args[key] = content
    return json.dumps(args, ensure_ascii=False)


def _json_schema(body: dict[str, Any]) -> dict[str, Any] | None:
    response_format = body.get("response_format")
    if isinstance(response_format, dict):
        if response_format.get("type") == "json_schema":
            json_schema = response_format.get("json_schema")
            if isinstance(json_schema, dict):
                schema = json_schema.get("schema")
                if isinstance(schema, dict):
                    return schema
        if response_format.get("schema") and isinstance(response_format["schema"], dict):
            return response_format["schema"]
    text = body.get("text")
    if isinstance(text, dict):
        text_format = text.get("format")
        if isinstance(text_format, dict):
            schema = text_format.get("schema")
            if isinstance(schema, dict):
                return schema
    return None


def _schema_value(schema: dict[str, Any], fallback: str) -> Any:
    return coerce_to_schema(fallback, schema, fallback)


def _chat_usage() -> dict[str, int]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }


def _response_usage(body: dict[str, Any] | None = None, content: str = "") -> dict[str, int]:
    input_text = _body_prompt(body or {})
    input_tokens = max(1, len(input_text.split()))
    output_tokens = max(1, len((content or "").split()))
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
    }
