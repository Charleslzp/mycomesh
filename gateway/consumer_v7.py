from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shlex
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import httpx
import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .chain import ChainError
from .chain_v7 import build_authorization, generate_payment_key, payment_key_address, payment_private_key
from .reservation import RESPONSES_LOCAL_OPTION_FIELDS, RESPONSES_REQUEST_OPTION_FIELDS, inference_request_hash, normalize_inference_request_options


DEFAULT_BASE_URL = "http://127.0.0.1:8110/v1"
DEFAULT_MAX_FEE_UNITS = 100_000
# Public RPCs can lag the local clock by more than a few seconds. Keep the
# signed window below the contract's one-hour TTL while leaving settlement room.
AUTHORIZATION_CLOCK_SKEW_SECONDS = 300
RETRYABLE_RELAY_STATUS = {408, 429, 500, 502, 503, 504}


class ConsumerV7Error(RuntimeError):
    pass


@dataclass(frozen=True)
class ConsumerV7Config:
    data_dir: Path
    base_url: str = DEFAULT_BASE_URL
    relay_urls: tuple[str, ...] = ()
    max_fee_units: int = DEFAULT_MAX_FEE_UNITS
    timeout_seconds: float = 300.0
    health_timeout_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "ConsumerV7Config":
        data_dir = Path(os.getenv("MYCOMESH_CONSUMER_DATA_DIR", "/data"))
        raw_relays = os.getenv("MYCOMESH_V7_RELAY_URLS") or os.getenv("MYCOMESH_CONSUMER_RELAY_URL") or "https://bridge.mycomesh.xyz"
        relays = tuple(item.rstrip("/") for item in raw_relays.split(",") if item.strip())
        if not relays:
            raise ConsumerV7Error("MYCOMESH_V7_RELAY_URLS must contain at least one Relay URL")
        try:
            max_fee = int(os.getenv("MYCOMESH_V7_MAX_FEE_UNITS", str(DEFAULT_MAX_FEE_UNITS)))
        except ValueError as exc:
            raise ConsumerV7Error("MYCOMESH_V7_MAX_FEE_UNITS must be an integer") from exc
        if max_fee <= 0:
            raise ConsumerV7Error("MYCOMESH_V7_MAX_FEE_UNITS must be positive")
        return cls(
            data_dir=data_dir,
            base_url=os.getenv("MYCOMESH_CONSUMER_PUBLIC_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            relay_urls=relays,
            max_fee_units=max_fee,
            timeout_seconds=float(os.getenv("MYCOMESH_V7_REQUEST_TIMEOUT_SECONDS", "300")),
            health_timeout_seconds=float(os.getenv("MYCOMESH_V7_HEALTH_TIMEOUT_SECONDS", "5")),
        )


class ConsumerV7State:
    def __init__(self, config: ConsumerV7Config | None = None) -> None:
        self.config = config or ConsumerV7Config.from_env()
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.config.data_dir.chmod(0o700)
        except OSError:
            pass
        self.payment_key = self._load_payment_key()
        self.payment_address = payment_key_address(self.payment_key)
        self._health_cache: dict[str, tuple[float, dict[str, Any]]] = {}

    def _load_payment_key(self) -> str:
        configured = os.getenv("MYCOMESH_V7_PAYMENT_KEY", "").strip()
        path = self.config.data_dir / "payment-key"
        if configured:
            payment_private_key(configured)
            return configured
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            payment_private_key(value)
            return value
        value = generate_payment_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(value + "\n")
        except BaseException:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return value

    def credentials_text(self) -> str:
        return "\n".join(
            (
                f"export OPENAI_BASE_URL={shlex.quote(self.config.base_url)}",
                f"export OPENAI_API_KEY={shlex.quote(self.payment_key)}",
            )
        )

    def health_payload(self) -> dict[str, Any]:
        return {
            "ok": True,
            "protocol": "mycomesh-consumer/v7",
            "browser_app_ready": True,
            "gateway_dependency": False,
            "routing_mode": "relay-scheduled-payment-key-v7",
            "relay_urls": list(self.config.relay_urls),
            "payment_key_address": self.payment_address,
            "payment_key_persisted": True,
        }

    async def relay_health(self, relay_url: str, *, refresh: bool = False) -> dict[str, Any]:
        cached = self._health_cache.get(relay_url)
        if cached and not refresh and time.monotonic() - cached[0] < 5:
            return cached[1]
        try:
            async with httpx.AsyncClient(timeout=self.config.health_timeout_seconds, follow_redirects=False) as client:
                response = await client.get(relay_url.rstrip("/") + "/health")
                response.raise_for_status()
                payload = response.json()
                if isinstance(payload, dict) and not isinstance(payload.get("v7"), dict):
                    response = await client.get(relay_url.rstrip("/") + "/relay/health")
                    response.raise_for_status()
                    payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConsumerV7Error(f"Relay health failed for {relay_url}: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise ConsumerV7Error(f"Relay health is invalid for {relay_url}")
        v7 = payload.get("v7")
        if not isinstance(v7, dict) or v7.get("enabled") is not True or int(v7.get("providers") or 0) <= 0:
            raise ConsumerV7Error(f"Relay has no live Settlement V7 Provider: {relay_url}")
        self._health_cache[relay_url] = (time.monotonic(), payload)
        return payload

    async def choose_relay(self, *, exclude: set[str] | None = None) -> tuple[str, dict[str, Any]]:
        excluded = exclude or set()
        errors: list[str] = []
        for relay_url in self.config.relay_urls:
            if relay_url in excluded:
                continue
            try:
                return relay_url, await self.relay_health(relay_url)
            except ConsumerV7Error as exc:
                errors.append(str(exc))
        raise ConsumerV7Error("no healthy Settlement V7 Relay is available: " + "; ".join(errors))


def create_app(state: ConsumerV7State | None = None) -> FastAPI:
    local = state or ConsumerV7State()
    app = FastAPI(title="MycoMesh Consumer V7", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.consumer_v7 = local
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.get("/", response_class=HTMLResponse)
    async def browser_credentials() -> str:
        exports = local.credentials_text()
        escaped = exports.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>MycoMesh</title>"
            "<style>body{font:14px ui-monospace,SFMono-Regular,Menlo,monospace;margin:40px;line-height:1.7}"
            "pre{white-space:pre-wrap;word-break:break-word}</style></head>"
            f"<body><pre>{escaped}</pre></body></html>"
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return local.health_payload()

    @app.get("/ready")
    async def ready() -> dict[str, Any]:
        try:
            relay, payload = await local.choose_relay()
        except ConsumerV7Error as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)
        return {"ok": True, "relay": relay, "model": payload["v7"].get("model")}

    @app.get("/credentials")
    async def credentials() -> str:
        return local.credentials_text() + "\n"

    @app.get("/codex-env")
    async def codex_env() -> str:
        return local.credentials_text() + "\n"

    @app.get("/v1/models")
    async def models() -> dict[str, Any]:
        relay, payload = await local.choose_relay()
        model = str(payload["v7"].get("model") or "mycomesh-codex-standard-v1")
        return {"object": "list", "data": [{"id": model, "object": "model", "owned_by": "mycomesh", "relay": relay}]}

    @app.post("/v1/responses")
    async def responses(request: Request, authorization: str | None = Header(default=None)) -> Any:
        return await _proxy_inference(local, "/v1/responses", request, authorization)

    @app.post("/v1/chat/completions")
    async def chat(request: Request, authorization: str | None = Header(default=None)) -> Any:
        return await _proxy_inference(local, "/v1/chat/completions", request, authorization)

    return app


async def _proxy_inference(
    state: ConsumerV7State,
    path: str,
    request: Request,
    authorization: str | None,
) -> Any:
    if authorization != f"Bearer {state.payment_key}":
        return JSONResponse({"error": {"type": "invalid_api_key", "message": "invalid MycoMesh payment key"}}, status_code=401)
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError) as exc:
        return JSONResponse({"error": {"type": "invalid_request", "message": "request body must be JSON"}}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": {"type": "invalid_request", "message": "request body must be an object"}}, status_code=422)
    # Keep one settlement id across Relay failover. The authorization remains
    # Relay-specific, while the on-chain settlement key prevents double charge.
    request_id = "0x" + secrets.token_hex(32)
    used: set[str] = set()
    last_error: str | None = None
    for _ in state.config.relay_urls:
        try:
            relay_url, health = await state.choose_relay(exclude=used)
        except ConsumerV7Error as exc:
            last_error = str(exc)
            break
        used.add(relay_url)
        try:
            payload = _build_relay_payment(state, path, body, health, request_id=request_id)
            relay_path = relay_url.rstrip("/") + path
            encoded = base64.urlsafe_b64encode(
                json.dumps(payload["payment"], sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            request_body = dict(body)
            model = str(health["v7"].get("model") or request_body.get("model") or "")
            request_body["model"] = model
            async with httpx.AsyncClient(timeout=state.config.timeout_seconds, follow_redirects=False) as client:
                response = await client.post(
                    relay_path,
                    json=request_body,
                    headers={"PAYMENT-SIGNATURE": encoded, "content-type": "application/json"},
                )
            if response.status_code in RETRYABLE_RELAY_STATUS:
                last_error = response.text[:500]
                continue
            if response.status_code >= 400:
                return JSONResponse(_decode_error(response), status_code=response.status_code)
            result = response.json()
            if not isinstance(result, dict):
                raise ConsumerV7Error("Relay returned a non-object response")
            if body.get("stream") is True:
                return _stream_response(path, result)
            return JSONResponse(result)
        except (httpx.HTTPError, ValueError, ConsumerV7Error) as exc:
            last_error = str(exc)
            continue
    return JSONResponse(
        {"error": {"type": "relay_unavailable", "message": last_error or "no Relay accepted the request"}},
        status_code=503,
        headers={"Retry-After": "2"},
    )


def _build_relay_payment(
    state: ConsumerV7State,
    path: str,
    body: Mapping[str, Any],
    health: Mapping[str, Any],
    *,
    request_id: str | None = None,
) -> dict[str, Any]:
    endpoint = "chat" if path.endswith("/chat/completions") else "responses"
    v7 = health.get("v7")
    if not isinstance(v7, Mapping):
        raise ConsumerV7Error("Relay health has no V7 payment requirements")
    request_body = dict(body)
    model = str(v7.get("model") or request_body.get("model") or "")
    max_output = request_body.get("max_output_tokens")
    if max_output is None:
        max_output = request_body.get("max_tokens")
    max_output_tokens = int(max_output or int(v7.get("maxOutputTokens") or 2000))
    options = {
        field: request_body[field]
        for field in RESPONSES_REQUEST_OPTION_FIELDS | RESPONSES_LOCAL_OPTION_FIELDS
        if field in request_body
    }
    normalized_options = normalize_inference_request_options(endpoint, options)
    request_id = request_id or ("0x" + secrets.token_hex(32))
    request_hash = "0x" + inference_request_hash(
        endpoint=endpoint,
        model=model,
        input_value=request_body.get("input"),
        messages=request_body.get("messages"),
        max_output_tokens=max_output_tokens,
        options=normalized_options,
    )
    now = int(time.time())
    payment = build_authorization(
        payment_key=state.payment_key,
        chain_id=int(v7["chain_id"]),
        settlement_contract=str(v7["settlement_contract"]),
        request_id=request_id,
        request_hash=request_hash,
        relay=str(v7["relay_payment_address"]),
        relay_signer=str(v7["relay_signer_address"]),
        channel_hash=str(v7["channel_hash"]),
        pricing_version=int(v7["pricing_version"]),
        pricing_hash=str(v7["pricing_hash"]),
        max_fee=state.config.max_fee_units,
        issued_at=now - AUTHORIZATION_CLOCK_SKEW_SECONDS,
        deadline=now + 900,
    )
    return {"payment": payment, "request_id": request_id}


def _decode_error(response: httpx.Response) -> dict[str, Any]:
    try:
        value = response.json()
    except ValueError:
        value = None
    if isinstance(value, dict):
        return value
    return {"error": {"type": "relay_error", "message": response.text[:1000]}}


def _sse_event(event: str, payload: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


async def _responses_sse(payload: dict[str, Any]):
    response_id = str(payload.get("id") or payload.get("request_id") or f"resp_{uuid.uuid4().hex}")
    completed = dict(payload)
    completed.setdefault("id", response_id)
    completed.setdefault("object", "response")
    completed["status"] = "completed"
    created = {
        "id": response_id,
        "object": "response",
        "status": "in_progress",
        "model": payload.get("model"),
        "output": [],
        "output_text": "",
        "error": None,
        "incomplete_details": None,
    }
    yield _sse_event("response.created", {"type": "response.created", "response": created})
    yield _sse_event("response.in_progress", {"type": "response.in_progress", "response": created})

    text = str(payload.get("output_text") or "")
    output = payload.get("output") if isinstance(payload.get("output"), list) else []
    message_index = next(
        (
            index
            for index, item in enumerate(output)
            if isinstance(item, dict) and item.get("type") == "message"
        ),
        len(output),
    )
    message_item = output[message_index] if message_index < len(output) else None
    if message_item is None and text:
        message_item = {
            "id": f"msg_{uuid.uuid4().hex}",
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }
    for index, item in enumerate(output):
        if index == message_index or not isinstance(item, dict):
            continue
        item_type = item.get("type")
        item_id = str(item.get("id") or f"item_{uuid.uuid4().hex}")
        added_item = {**item, "id": item_id, "status": "in_progress"}
        if item_type == "function_call":
            added_item["arguments"] = ""
        elif item_type == "custom_tool_call":
            added_item["input"] = ""
        yield _sse_event(
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "output_index": index,
                "item": added_item,
            },
        )
        if item_type == "function_call":
            arguments = str(item.get("arguments") or "")
            if arguments:
                yield _sse_event(
                    "response.function_call_arguments.delta",
                    {
                        "type": "response.function_call_arguments.delta",
                        "item_id": item_id,
                        "output_index": index,
                        "delta": arguments,
                    },
                )
            yield _sse_event(
                "response.function_call_arguments.done",
                {
                    "type": "response.function_call_arguments.done",
                    "item_id": item_id,
                    "output_index": index,
                    "name": str(item.get("name") or ""),
                    "arguments": arguments,
                },
            )
        elif item_type == "custom_tool_call":
            tool_input = str(item.get("input") or "")
            if tool_input:
                yield _sse_event(
                    "response.custom_tool_call_input.delta",
                    {
                        "type": "response.custom_tool_call_input.delta",
                        "item_id": item_id,
                        "output_index": index,
                        "delta": tool_input,
                    },
                )
            yield _sse_event(
                "response.custom_tool_call_input.done",
                {
                    "type": "response.custom_tool_call_input.done",
                    "item_id": item_id,
                    "output_index": index,
                    "input": tool_input,
                },
            )
        yield _sse_event(
            "response.output_item.done",
            {"type": "response.output_item.done", "output_index": index, "item": item},
        )

    if message_item is None:
        yield _sse_event("response.completed", {"type": "response.completed", "response": completed})
        return

    message_id = str(message_item.get("id") or f"msg_{uuid.uuid4().hex}")
    content = message_item.get("content") if isinstance(message_item.get("content"), list) else []
    text_index = next(
        (
            index
            for index, part in enumerate(content)
            if isinstance(part, dict) and part.get("type") == "output_text"
        ),
        0,
    )
    text_part = (
        content[text_index]
        if text_index < len(content) and isinstance(content[text_index], dict)
        else {"type": "output_text", "text": text, "annotations": []}
    )
    annotations = text_part.get("annotations") if isinstance(text_part.get("annotations"), list) else []
    yield _sse_event(
        "response.output_item.added",
        {
            "type": "response.output_item.added",
            "output_index": message_index,
            "item": {**message_item, "status": "in_progress", "content": []},
        },
    )
    yield _sse_event(
        "response.content_part.added",
        {
            "type": "response.content_part.added",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_index,
            "part": {"type": "output_text", "text": "", "annotations": annotations},
        },
    )
    if text:
        yield _sse_event(
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "item_id": message_id,
                "output_index": message_index,
                "content_index": text_index,
                "delta": text,
            },
        )
    yield _sse_event(
        "response.output_text.done",
        {
            "type": "response.output_text.done",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_index,
            "text": text,
        },
    )
    yield _sse_event(
        "response.content_part.done",
        {
            "type": "response.content_part.done",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_index,
            "part": {"type": "output_text", "text": text, "annotations": annotations},
        },
    )
    yield _sse_event(
        "response.output_item.done",
        {"type": "response.output_item.done", "output_index": message_index, "item": message_item},
    )
    yield _sse_event("response.completed", {"type": "response.completed", "response": completed})


def _stream_response(path: str, payload: dict[str, Any]) -> StreamingResponse:
    if path.endswith("/chat/completions"):
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        content = f"data: {data}\n\ndata: [DONE]\n\n"
        return StreamingResponse(iter((content.encode("utf-8"),)), media_type="text/event-stream")
    return StreamingResponse(_responses_sse(payload), media_type="text/event-stream")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the MycoMesh V7 payment-key Consumer edge.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8110)
    subparsers.add_parser("credentials")
    subparsers.add_parser("codex-env")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state = ConsumerV7State()
    if args.command == "credentials":
        print(state.credentials_text())
        return 0
    if args.command == "codex-env":
        print(state.credentials_text())
        return 0
    uvicorn.run(create_app(state), host=args.host, port=args.port, access_log=False, server_header=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
