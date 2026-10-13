"""Model backends a Provider can serve: any OpenAI-compatible API (OpenAI, the
Codex sidecar) and the Anthropic Messages API."""
from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class BackendError(RuntimeError):
    pass


def _events(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float):
    """POST a streaming request and yield each server-sent event's JSON data."""
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "Accept": "text/event-stream", **headers},
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        detail = exc.read(2_000).decode("utf-8", "replace")
        exc.close()
        raise BackendError(f"backend HTTP {exc.code}: {detail[:300]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BackendError(f"backend unreachable: {exc}") from exc
    with response:
        size = 0
        for raw in response:
            size += len(raw)
            if size > MAX_RESPONSE_BYTES:
                raise BackendError("backend response too large")
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                return
            try:
                yield json.loads(data)
            except ValueError:
                continue


def _post(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(2_000).decode("utf-8", "replace")
        exc.close()
        raise BackendError(f"backend HTTP {exc.code}: {detail[:300]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BackendError(f"backend unreachable: {exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise BackendError("backend response too large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise BackendError("backend returned a non-object")
    return value


def content_parts(content: Any) -> list[dict[str, Any]]:
    """A message's content as the network's parts (OpenAI Chat): text, image_url (a data: or https URL) and file
    (a data: URL with its filename)."""
    if content is None:
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if not isinstance(content, list):
        return [{"type": "text", "text": json.dumps(content, ensure_ascii=False)}]
    parts: list[dict[str, Any]] = []
    for part in content:
        if isinstance(part, str):
            parts.append({"type": "text", "text": part})
        elif not isinstance(part, dict):
            continue
        elif part.get("type") in {"text", "input_text", "output_text"} or (part.get("type") is None and "text" in part):
            parts.append({"type": "text", "text": str(part.get("text", ""))})
        elif part.get("type") == "image_url" and (part.get("image_url") or {}).get("url"):
            parts.append({"type": "image_url", "image_url": {"url": part["image_url"]["url"]}})
        elif part.get("type") == "input_image" and part.get("image_url"):
            parts.append({"type": "image_url", "image_url": {"url": part["image_url"]}})
        elif part.get("type") == "file" and isinstance(part.get("file"), dict):
            parts.append({"type": "file", "file": {k: v for k, v in part["file"].items() if k in {"filename", "file_data"}}})
    return parts


def input_kinds(document: dict[str, Any]) -> set[str]:
    """What a request asks its backend to read besides text: "image", "file"."""
    found: set[str] = set()
    messages = document.get("messages") if document.get("endpoint") == "chat" else document.get("input")
    for message in messages if isinstance(messages, list) else []:
        for part in content_parts(message.get("content")) if isinstance(message, dict) else []:
            if part["type"] == "image_url":
                found.add("image")
            elif part["type"] == "file":
                found.add("file")
    return found


def split_data_url(url: str) -> tuple[str, str] | None:
    """(media type, base64 data) of a data: URL; None for any other URL."""
    if not isinstance(url, str) or not url.startswith("data:") or ";base64," not in url:
        return None
    head, data = url[5:].split(";base64,", 1)
    return head or "application/octet-stream", data


def tool_call(call_id: str, name: str, arguments: Any) -> dict[str, Any]:
    """A tool call in the network's one shape (OpenAI Chat Completions): the Consumer's client runs the tool."""
    return {"id": str(call_id), "type": "function",
            "function": {"name": str(name), "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments)}}


def request_tools(request: dict[str, Any]) -> list[dict[str, Any]]:
    """The request's function tools (OpenAI Chat shape), unless tool_choice turns them off."""
    options = request.get("options") or {}
    if options.get("tool_choice") == "none":
        return []
    return [tool for tool in options.get("tools") or [] if isinstance(tool, dict) and tool.get("type") == "function"
            and isinstance(tool.get("function"), dict) and tool["function"].get("name")]


def shape_output(request: dict[str, Any], text: str, input_tokens: int, output_tokens: int,
                 tool_calls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if request["endpoint"] == "chat":
        message: dict[str, Any] = {"role": "assistant", "content": text or (None if tool_calls else "")}
        if tool_calls:
            message["tool_calls"] = tool_calls
        return {"id": f"chatcmpl_{secrets.token_hex(12)}", "object": "chat.completion", "created": int(time.time()),
                "model": request["model"],
                "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if tool_calls else "stop"}],
                "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens,
                          "total_tokens": input_tokens + output_tokens}}
    output: list[dict[str, Any]] = []
    if text or not tool_calls:
        output.append({"type": "message", "id": f"msg_{secrets.token_hex(12)}", "role": "assistant", "status": "completed",
                       "content": [{"type": "output_text", "text": text, "annotations": []}]})
    output += [{"type": "function_call", "id": f"fc_{secrets.token_hex(12)}", "call_id": call["id"],
                "name": call["function"]["name"], "arguments": call["function"]["arguments"], "status": "completed"}
               for call in tool_calls or []]
    return {"id": f"resp_{secrets.token_hex(12)}", "object": "response", "created_at": int(time.time()),
            "status": "completed", "model": request["model"], "output_text": text, "output": output,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                      "total_tokens": input_tokens + output_tokens}}


@dataclass
class OpenAICompatibleBackend:
    """POSTs /responses or /chat/completions to an OpenAI-compatible base URL."""

    base_url: str
    api_key: str = ""
    timeout: float = 300.0
    streams = True
    inputs = ("text", "image", "file")  # as the server it fronts accepts them (OpenAI: all three)

    def __call__(self, request: dict[str, Any], on_delta: Any = None) -> tuple[Any, int, int]:
        base = self.base_url.rstrip("/")
        body = dict(request["options"])
        body.update(model=request["model"])
        if request["endpoint"] == "chat":
            body.update(messages=request["messages"], max_tokens=request["max_output_tokens"])
            url = f"{base}/chat/completions"
        else:
            body.update(input=request["input"], max_output_tokens=request["max_output_tokens"])
            url = f"{base}/responses"
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        if on_delta is not None:
            result = self._stream(url, body, headers, request, on_delta)
        else:
            result = _post(url, body, headers, self.timeout)
        usage = result.get("usage") or {}
        input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
        output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
        return result, input_tokens, output_tokens

    def _stream(self, url: str, body: dict[str, Any], headers: dict[str, str], request: dict[str, Any],
                on_delta: Any) -> dict[str, Any]:
        body = {**body, "stream": True}
        if request["endpoint"] == "chat":
            body["stream_options"] = {"include_usage": True}
            text, usage, meta, calls, finish = [], None, {}, {}, None
            for event in _events(url, body, headers, self.timeout):
                meta = meta or {key: event.get(key) for key in ("id", "model", "created")}
                usage = event.get("usage") or usage
                for choice in event.get("choices") or []:
                    finish = choice.get("finish_reason") or finish
                    delta = (choice.get("delta") or {}).get("content")
                    if delta:
                        text.append(delta)
                        on_delta(delta)
                    for part in (choice.get("delta") or {}).get("tool_calls") or []:  # streamed in pieces, by index
                        call = calls.setdefault(part.get("index", len(calls)), {"id": "", "name": "", "arguments": ""})
                        call["id"] = part.get("id") or call["id"]
                        call["name"] += (part.get("function") or {}).get("name") or ""
                        call["arguments"] += (part.get("function") or {}).get("arguments") or ""
            message: dict[str, Any] = {"role": "assistant", "content": "".join(text) or (None if calls else "")}
            if calls:
                message["tool_calls"] = [tool_call(c["id"] or f"call_{secrets.token_hex(8)}", c["name"], c["arguments"])
                                         for _, c in sorted(calls.items())]
            return {**meta, "object": "chat.completion",
                    "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if calls else (finish or "stop")}],
                    "usage": usage or {}}
        final = None
        for event in _events(url, body, headers, self.timeout):
            if event.get("type") == "response.output_text.delta" and event.get("delta"):
                on_delta(event["delta"])
            elif event.get("type") in {"response.completed", "response.incomplete"}:
                final = event.get("response")
            elif event.get("type") in {"response.failed", "error"}:
                raise BackendError(f"backend stream failed: {str(event)[:300]}")
        if not isinstance(final, dict):
            raise BackendError("backend stream ended without a final response")
        return final


@dataclass
class AnthropicBackend:
    """Claude via the Anthropic Messages API."""

    inputs = ("text", "image", "file")
    api_key: str
    base_url: str = "https://api.anthropic.com/v1"
    version: str = "2023-06-01"
    timeout: float = 300.0
    passthrough: tuple[str, ...] = field(default=("temperature", "top_p", "top_k", "system", "stop_sequences"))
    streams = True

    def __call__(self, request: dict[str, Any], on_delta: Any = None) -> tuple[Any, int, int]:
        if request["endpoint"] == "chat":
            messages = request["messages"]
        else:
            content = request["input"]
            messages = [{"role": "user", "content": content if isinstance(content, (str, list)) else json.dumps(content)}]
        body = {key: value for key, value in request["options"].items() if key in self.passthrough}
        system = [m["content"] for m in messages if isinstance(m, dict) and m.get("role") == "system"]
        if system:
            messages = [m for m in messages if not (isinstance(m, dict) and m.get("role") == "system")]
            body["system"] = "\n\n".join(str(part) for part in system)
        tools = request_tools(request)
        if tools:
            body["tools"] = [{"name": t["function"]["name"], "description": t["function"].get("description", ""),
                              "input_schema": t["function"].get("parameters") or {"type": "object", "properties": {}}} for t in tools]
            choice = request["options"].get("tool_choice")
            if choice == "required":
                body["tool_choice"] = {"type": "any"}
            elif isinstance(choice, dict) and (choice.get("function") or {}).get("name"):
                body["tool_choice"] = {"type": "tool", "name": choice["function"]["name"]}
        body.update(model=request["model"], max_tokens=request["max_output_tokens"], messages=anthropic_messages(messages))
        url = f"{self.base_url.rstrip('/')}/messages"
        headers = {"x-api-key": self.api_key, "anthropic-version": self.version}
        if on_delta is not None:
            result = self._stream(url, body, headers, on_delta)
        else:
            result = _post(url, body, headers, self.timeout)
        usage = result.get("usage") or {}
        input_tokens, output_tokens = int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)
        # Consumers speak the OpenAI protocols, so Claude answers in the same shapes.
        text = "".join(str(part.get("text", "")) for part in result.get("content") or [] if part.get("type", "text") == "text")
        calls = [tool_call(part.get("id"), part.get("name"), part.get("input") or {})
                 for part in result.get("content") or [] if part.get("type") == "tool_use"]
        shaped = shape_output(request, text, input_tokens, output_tokens, calls)
        if result.get("stop_reason") == "max_tokens":
            shaped.update({"status": "incomplete"} if "status" in shaped else {})
        return shaped, input_tokens, output_tokens

    def _stream(self, url: str, body: dict[str, Any], headers: dict[str, str], on_delta: Any) -> dict[str, Any]:
        message: dict[str, Any] = {}
        text: list[str] = []
        usage = {"input_tokens": 0, "output_tokens": 0}
        uses: dict[int, dict[str, Any]] = {}  # content block index -> tool_use being streamed
        for event in _events(url, {**body, "stream": True}, headers, self.timeout):
            kind = event.get("type")
            if kind == "message_start":
                message = dict(event.get("message") or {})
                usage.update({k: v for k, v in (message.get("usage") or {}).items() if k in usage and v})
            elif kind == "content_block_start" and (event.get("content_block") or {}).get("type") == "tool_use":
                block = event["content_block"]
                uses[event.get("index", len(uses))] = {"type": "tool_use", "id": block.get("id"), "name": block.get("name"), "json": ""}
            elif kind == "content_block_delta" and (event.get("delta") or {}).get("type") == "input_json_delta":
                uses.setdefault(event.get("index", 0), {"type": "tool_use", "json": ""})["json"] += event["delta"].get("partial_json", "")
            elif kind == "content_block_delta" and (event.get("delta") or {}).get("type") == "text_delta":
                text.append(event["delta"]["text"])
                on_delta(event["delta"]["text"])
            elif kind == "message_delta":
                usage.update({k: v for k, v in (event.get("usage") or {}).items() if k in usage and v})
                message["stop_reason"] = (event.get("delta") or {}).get("stop_reason")
            elif kind == "error":
                raise BackendError(f"backend stream failed: {str(event)[:300]}")
        content: list[dict[str, Any]] = [{"type": "text", "text": "".join(text)}]
        for _, use in sorted(uses.items()):
            content.append({"type": "tool_use", "id": use.get("id"), "name": use.get("name"),
                            "input": json.loads(use["json"]) if use["json"].strip() else {}})
        return {**message, "content": content, "usage": usage}


def anthropic_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """Chat messages with tool calls and tool results in the Messages API's shape: tool_use blocks on the
    assistant turn, tool_result blocks on the next user turn (consecutive results merged into one)."""
    out: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role == "tool":
            block = {"type": "tool_result", "tool_use_id": message.get("tool_call_id"), "content": str(message.get("content") or "")}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) \
                    and all(b.get("type") == "tool_result" for b in out[-1]["content"]):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        elif role == "assistant" and message.get("tool_calls"):
            blocks: list[dict[str, Any]] = [{"type": "text", "text": message["content"]}] if message.get("content") else []
            for call in message["tool_calls"]:
                arguments = (call.get("function") or {}).get("arguments") or "{}"
                try:
                    parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
                except ValueError:
                    parsed = {"input": arguments}
                blocks.append({"type": "tool_use", "id": call.get("id"), "name": (call.get("function") or {}).get("name"), "input": parsed})
            out.append({"role": "assistant", "content": blocks})
        else:
            content = message.get("content")
            out.append({"role": role, "content": anthropic_content(content) if isinstance(content, list) else (content or "")})
    return out


def anthropic_content(content: list[Any]) -> list[dict[str, Any]]:
    """Network content parts as Messages API blocks: text, image (base64 or URL), document (PDF)."""
    blocks: list[dict[str, Any]] = []
    for part in content_parts(content):
        if part["type"] == "text":
            blocks.append({"type": "text", "text": part["text"]})
        elif part["type"] == "image_url":
            url = part["image_url"]["url"]
            data = split_data_url(url)
            blocks.append({"type": "image", "source": {"type": "base64", "media_type": data[0], "data": data[1]} if data
                           else {"type": "url", "url": url}})
        elif part["type"] == "file":
            data = split_data_url(part["file"].get("file_data", ""))
            if data:
                blocks.append({"type": "document", "source": {"type": "base64", "media_type": data[0], "data": data[1]},
                               **({"title": part["file"]["filename"]} if part["file"].get("filename") else {})})
    return blocks
