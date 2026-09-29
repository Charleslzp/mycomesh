"""Model backends a Provider can serve: any OpenAI-compatible API (OpenAI, the
Codex sidecar) and the Anthropic Messages API."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class BackendError(RuntimeError):
    pass


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


@dataclass
class OpenAICompatibleBackend:
    """POSTs /responses or /chat/completions to an OpenAI-compatible base URL."""

    base_url: str
    api_key: str = ""
    timeout: float = 300.0

    def __call__(self, request: dict[str, Any]) -> tuple[Any, int, int]:
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
        result = _post(url, body, headers, self.timeout)
        usage = result.get("usage") or {}
        input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
        output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
        return result, input_tokens, output_tokens


@dataclass
class AnthropicBackend:
    """Claude via the Anthropic Messages API."""

    api_key: str
    base_url: str = "https://api.anthropic.com/v1"
    version: str = "2023-06-01"
    timeout: float = 300.0
    passthrough: tuple[str, ...] = field(default=("temperature", "top_p", "top_k", "system", "stop_sequences"))

    def __call__(self, request: dict[str, Any]) -> tuple[Any, int, int]:
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
        result = _post(f"{self.base_url.rstrip('/')}/messages", body,
                       {"x-api-key": self.api_key, "anthropic-version": self.version}, self.timeout)
        usage = result.get("usage") or {}
        return result, int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)
