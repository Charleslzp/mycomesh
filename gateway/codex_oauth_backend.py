from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx


CHATGPT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
CODEX_VERSION = "0.146.0"
CODEX_USER_AGENT = f"codex_cli_rs/{CODEX_VERSION} (Linux; x86_64) xterm-256color"
_COMPACT_FIELDS = (
    "model",
    "input",
    "instructions",
    "tools",
    "parallel_tool_calls",
    "reasoning",
    "text",
    "previous_response_id",
)
_CHATGPT_UNSUPPORTED_FIELDS = {
    "frequency_penalty",
    "max_completion_tokens",
    "max_output_tokens",
    "metadata",
    "presence_penalty",
    "prompt_cache_retention",
    "safety_identifier",
    "stream_options",
    "temperature",
    "top_p",
    "user",
}
_TERMINAL_RESPONSE_EVENTS = {
    "response.completed",
    "response.failed",
    "response.incomplete",
}


class CodexOAuthBackendError(RuntimeError):
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = int(status_code)
        self.payload = payload
        message = _error_message(payload) or f"Codex Responses upstream returned HTTP {status_code}"
        super().__init__(message)


class CodexOAuthResponsesBackend:
    """Small native Responses client backed by the official Codex login."""

    def __init__(
        self,
        *,
        codex_home: str,
        timeout_seconds: float,
        internal_model: str,
        base_url: str = CHATGPT_CODEX_BASE_URL,
        transport: httpx.AsyncBaseTransport | None = None,
        max_response_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        self.auth_path = Path(codex_home) / "auth.json"
        self.timeout_seconds = float(timeout_seconds)
        self.internal_model = str(internal_model)
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.max_response_bytes = int(max_response_bytes)

    async def response(
        self,
        body: Mapping[str, Any],
        *,
        compact: bool,
        public_model: str,
    ) -> dict[str, Any]:
        access_token, account_id = self._credentials()
        payload = self._request_payload(body, compact=compact)
        headers = {
            "authorization": f"Bearer {access_token}",
            "chatgpt-account-id": account_id,
            "content-type": "application/json",
            "accept": "application/json" if compact else "text/event-stream",
            "openai-beta": "responses=experimental",
            "originator": "codex_cli_rs",
            "user-agent": CODEX_USER_AGENT,
            "version": CODEX_VERSION,
        }
        path = "/responses/compact" if compact else "/responses"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
                trust_env=self.transport is None,
            ) as client:
                response = await client.post(self.base_url + path, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise CodexOAuthBackendError(
                502,
                {"error": {"type": "upstream_error", "message": str(exc)}},
            ) from exc
        content = response.content
        if len(content) > self.max_response_bytes:
            raise CodexOAuthBackendError(
                502,
                {"error": {"type": "upstream_error", "message": "Codex Responses upstream body is too large"}},
            )
        if response.status_code >= 400:
            result = _decode_error_payload(content, response.status_code)
            raise CodexOAuthBackendError(response.status_code, result)
        try:
            result = _decode_json_object(content) if compact else _decode_responses_sse(content)
        except (TypeError, ValueError) as exc:
            raise CodexOAuthBackendError(
                502,
                {"error": {"type": "upstream_error", "message": str(exc)}},
            ) from exc
        result["model"] = public_model
        return result

    def _credentials(self) -> tuple[str, str]:
        try:
            raw = self.auth_path.read_bytes()
            if len(raw) > 1024 * 1024:
                raise ValueError("auth.json is too large")
            value = json.loads(raw)
            tokens = value.get("tokens") if isinstance(value, dict) else None
            access_token = tokens.get("access_token") if isinstance(tokens, dict) else None
            account_id = tokens.get("account_id") if isinstance(tokens, dict) else None
        except (OSError, ValueError, TypeError) as exc:
            raise CodexOAuthBackendError(
                503,
                {"error": {"type": "authentication_error", "message": "Codex OAuth credentials are unavailable"}},
            ) from exc
        if not isinstance(access_token, str) or not access_token.strip():
            raise CodexOAuthBackendError(
                503,
                {"error": {"type": "authentication_error", "message": "Codex OAuth access token is unavailable"}},
            )
        if not isinstance(account_id, str) or not account_id.strip():
            raise CodexOAuthBackendError(
                503,
                {"error": {"type": "authentication_error", "message": "Codex OAuth account id is unavailable"}},
            )
        return access_token.strip(), account_id.strip()

    def _request_payload(self, body: Mapping[str, Any], *, compact: bool) -> dict[str, Any]:
        if compact:
            payload = {field: body[field] for field in _COMPACT_FIELDS if field in body}
            reasoning = payload.get("reasoning")
            if (
                self.internal_model.startswith("gpt-5.6")
                and isinstance(reasoning, Mapping)
                and reasoning.get("effort") == "max"
            ):
                payload["reasoning"] = {**reasoning, "effort": "xhigh"}
        else:
            payload = {
                key: value
                for key, value in body.items()
                if not key.startswith("gateway_") and not key.startswith("mycomesh_")
            }
            for field in _CHATGPT_UNSUPPORTED_FIELDS:
                payload.pop(field, None)
            payload["store"] = False
            payload["stream"] = True
            input_value = payload.get("input")
            if isinstance(input_value, str):
                payload["input"] = (
                    [{"type": "message", "role": "user", "content": input_value}]
                    if input_value.strip()
                    else []
                )
            reasoning = payload.get("reasoning")
            if isinstance(reasoning, Mapping):
                include = payload.get("include")
                include_values = list(include) if isinstance(include, list) else []
                if "reasoning.encrypted_content" not in include_values:
                    include_values.append("reasoning.encrypted_content")
                payload["include"] = include_values
        payload["model"] = self.internal_model
        return payload


def _error_message(payload: Mapping[str, Any]) -> str:
    error = payload.get("error")
    if isinstance(error, Mapping):
        return str(error.get("message") or "")
    return str(payload.get("detail") or payload.get("message") or "")


def _decode_json_object(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Codex Responses upstream returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise TypeError("Codex Responses upstream returned a non-object response")
    return value


def _decode_error_payload(content: bytes, status_code: int) -> dict[str, Any]:
    try:
        return _decode_json_object(content)
    except (TypeError, ValueError):
        return {
            "error": {
                "type": "upstream_error",
                "message": f"Codex Responses upstream returned HTTP {status_code}",
            }
        }


def _decode_responses_sse(content: bytes) -> dict[str, Any]:
    terminal: dict[str, Any] | None = None
    normalized = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    for block in normalized.split(b"\n\n"):
        data_lines = []
        for line in block.splitlines():
            if line.startswith(b"data:"):
                data_lines.append(line[5:].lstrip())
        if not data_lines:
            continue
        data = b"\n".join(data_lines)
        if data == b"[DONE]":
            continue
        try:
            event = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Codex Responses upstream returned invalid SSE JSON") from exc
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "")
        if event_type == "error":
            error = event.get("error")
            payload = error if isinstance(error, dict) else event
            raise ValueError(_error_message({"error": payload}) or "Codex Responses upstream returned an error event")
        if event_type in _TERMINAL_RESPONSE_EVENTS:
            response = event.get("response")
            if isinstance(response, dict):
                terminal = response
    if terminal is None:
        raise ValueError("Codex Responses upstream stream ended without a terminal response")
    return terminal
