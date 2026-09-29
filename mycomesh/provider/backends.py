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


def shape_output(request: dict[str, Any], text: str, input_tokens: int, output_tokens: int) -> dict[str, Any]:
    if request["endpoint"] == "chat":
        return {"id": f"chatcmpl_{secrets.token_hex(12)}", "object": "chat.completion", "created": int(time.time()),
                "model": request["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens,
                          "total_tokens": input_tokens + output_tokens}}
    return {"id": f"resp_{secrets.token_hex(12)}", "object": "response", "created_at": int(time.time()),
            "status": "completed", "model": request["model"], "output_text": text,
            "output": [{"type": "message", "id": f"msg_{secrets.token_hex(12)}", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": text, "annotations": []}]}],
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                      "total_tokens": input_tokens + output_tokens}}


@dataclass
class OpenAICompatibleBackend:
    """POSTs /responses or /chat/completions to an OpenAI-compatible base URL."""

    base_url: str
    api_key: str = ""
    timeout: float = 300.0
    streams = True

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
            text, usage, meta = [], None, {}
            for event in _events(url, body, headers, self.timeout):
                meta = meta or {key: event.get(key) for key in ("id", "model", "created")}
                usage = event.get("usage") or usage
                for choice in event.get("choices") or []:
                    delta = (choice.get("delta") or {}).get("content")
                    if delta:
                        text.append(delta)
                        on_delta(delta)
            return {**meta, "object": "chat.completion",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "".join(text)},
                                 "finish_reason": "stop"}], "usage": usage or {}}
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
        body.update(model=request["model"], max_tokens=request["max_output_tokens"], messages=messages)
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
        shaped = shape_output(request, text, input_tokens, output_tokens)
        if result.get("stop_reason") == "max_tokens":
            shaped.update({"status": "incomplete"} if "status" in shaped else {})
        return shaped, input_tokens, output_tokens

    def _stream(self, url: str, body: dict[str, Any], headers: dict[str, str], on_delta: Any) -> dict[str, Any]:
        message: dict[str, Any] = {}
        text: list[str] = []
        usage = {"input_tokens": 0, "output_tokens": 0}
        for event in _events(url, {**body, "stream": True}, headers, self.timeout):
            kind = event.get("type")
            if kind == "message_start":
                message = dict(event.get("message") or {})
                usage.update({k: v for k, v in (message.get("usage") or {}).items() if k in usage and v})
            elif kind == "content_block_delta" and (event.get("delta") or {}).get("type") == "text_delta":
                text.append(event["delta"]["text"])
                on_delta(event["delta"]["text"])
            elif kind == "message_delta":
                usage.update({k: v for k, v in (event.get("usage") or {}).items() if k in usage and v})
                message["stop_reason"] = (event.get("delta") or {}).get("stop_reason")
            elif kind == "error":
                raise BackendError(f"backend stream failed: {str(event)[:300]}")
        return {**message, "content": [{"type": "text", "text": "".join(text)}], "usage": usage}
