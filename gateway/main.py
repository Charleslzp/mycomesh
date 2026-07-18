from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .auth_store import AuthStore
from .codex_app_backend import CodexAppServerBackend
from .codex_backend import (
    CodexCliBackend,
    CodexProcessLimiter,
    chat_completion_chunk,
    chat_completion_payload,
    fast_chat_payload,
    fast_response_payload,
    response_payload,
)
from .config import AgentConfig, GatewayConfig, load_config
from .native_metering import (
    NativeMeteredBackend,
    NativeMeteringError,
    NativeMeteringRequestError,
)
from .orchestration import (
    OrchestrationDecision,
    agent_result_prompt,
    orchestrator_prompt,
    parse_decision,
    strip_for_orchestration,
)
from .request_limits import BoundedRequestBodyMiddleware
from .server_limits import (
    DEFAULT_GATEWAY_MAX_CONCURRENT_REQUESTS,
    BoundedASGIConcurrencyMiddleware,
    bounded_connection_count,
)
from .session_store import SessionStore, make_session_key
from .upstream import UpstreamClient, UpstreamError

GATEWAY_FIELDS = {
    "gateway_agent_id",
    "gateway_user_id",
    "gateway_workspace_id",
    "gateway_task_id",
    "gateway_session_id",
    "gateway_stateful",
    "gateway_clear_session",
    "gateway_metadata",
}
INTERNAL_FIELDS: set[str] = set()
STATEFUL_HEADER_VALUES = {"1", "true", "yes", "stateful"}
P2P_NATIVE_INFERENCE_SCHEMA = "mycomesh.gateway.p2p-native.v1"

config: GatewayConfig = load_config()
gateway_max_concurrent_requests = bounded_connection_count(
    os.getenv(
        "GATEWAY_MAX_CONCURRENT_REQUESTS",
        str(DEFAULT_GATEWAY_MAX_CONCURRENT_REQUESTS),
    ),
    label="gateway max concurrent requests",
)
store = SessionStore(config.session_db)
auth_store = AuthStore(config.session_db, config.auth_token_ttl_seconds)
upstream = UpstreamClient(
    config.upstream_base_url,
    config.upstream_api_key,
    timeout_seconds=config.upstream_timeout_seconds,
    max_response_bytes=config.upstream_max_response_bytes,
    max_stream_bytes=config.upstream_max_stream_bytes,
)
codex_process_limiter = CodexProcessLimiter()
codex_backend = CodexCliBackend(
    command=config.codex_command,
    codex_home=config.codex_home,
    workdir=config.codex_workdir,
    sandbox=config.codex_sandbox,
    timeout_seconds=config.codex_timeout_seconds,
    process_limiter=codex_process_limiter,
    production_strict=config.production_strict,
)
codex_app_backend = CodexAppServerBackend(
    command=config.codex_command,
    codex_home=config.codex_home,
    workdir=config.codex_workdir,
    sandbox=config.codex_sandbox,
    timeout_seconds=config.codex_timeout_seconds,
    process_limiter=codex_process_limiter,
    production_strict=config.production_strict,
    testnet_metering=config.codex_testnet_metering,
    testnet_max_output_token_cap=config.codex_testnet_max_output_tokens,
)
native_metered_backend = (
    NativeMeteredBackend(
        base_url=config.upstream_base_url,
        api_key=config.upstream_api_key,
        expected_model=config.center_model or "",
        expected_model_revision=config.upstream_expected_model_revision or "",
        metering_public_key=config.upstream_metering_public_key or "",
        capabilities_sha256=config.upstream_capabilities_sha256 or "",
        audience=config.upstream_metering_audience or "",
        default_output_token_cap=config.upstream_default_max_output_tokens,
    )
    if config.backend == "native_metered_http"
    else None
)


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    try:
        if native_metered_backend is not None:
            await native_metered_backend.ensure_ready(upstream)
        _assert_production_backend_ready()
        yield
    finally:
        await codex_app_backend.close()


app = FastAPI(title="Multi-Agent OpenAI-Compatible Gateway", lifespan=_lifespan)
app.add_middleware(
    BoundedRequestBodyMiddleware,
    limit=lambda: config.max_request_bytes,
    timeout_seconds=lambda: float(os.getenv("GATEWAY_REQUEST_BODY_TIMEOUT_SECONDS", "30")),
)
app.add_middleware(
    BoundedASGIConcurrencyMiddleware,
    maximum=gateway_max_concurrent_requests,
)


@app.exception_handler(UpstreamError)
async def _upstream_error_handler(_request: Request, exc: UpstreamError) -> JSONResponse:
    return JSONResponse(
        status_code=502,
        content={"detail": str(exc)},
    )


@dataclass(frozen=True)
class RequestContext:
    user_id: str
    workspace_id: str
    task_id: str
    agent_id: str
    session_id: str
    session_key: str
    stateful: bool
    metadata: dict[str, Any]


@app.get("/health")
async def health() -> dict[str, Any]:
    return _gateway_health_payload()


@app.get("/ready")
async def readiness() -> Response:
    if native_metered_backend is not None:
        try:
            await native_metered_backend.ensure_ready(upstream)
        except (NativeMeteringError, UpstreamError):
            pass
    payload = _gateway_health_payload()
    if payload["settlement_ready"] is True:
        return JSONResponse(payload)
    return JSONResponse(status_code=503, content=payload)


def _gateway_health_payload() -> dict[str, Any]:
    capabilities = _active_inference_capabilities()
    return {
        "ok": True,
        "backend": config.backend,
        "network_profile": config.network_profile,
        "production_strict": config.production_strict,
        "inference_capabilities": capabilities,
        "settlement_ready": bool(capabilities.get("production_ready")),
        "center_model": config.center_model,
        "public_model_id": _public_model_id(),
        "codex_internal_model": config.codex_internal_model if _is_codex_backend() else None,
        "codex_home": config.codex_home if _is_codex_backend() else None,
        "codex_workdir": config.codex_workdir if _is_codex_backend() else None,
        "default_user_id": config.default_user_id,
        "default_workspace_id": config.default_workspace_id,
        "require_user_auth": config.require_user_auth,
        "agents": sorted(config.agents.keys()),
    }


@app.post("/auth/register")
async def register(payload: dict[str, Any]) -> dict[str, Any]:
    if not config.allow_public_user_registration:
        raise HTTPException(status_code=403, detail="public user registration is disabled")
    try:
        user = auth_store.create_user(
            username=str(payload.get("username", "")),
            password=str(payload.get("password", "")),
            user_id=payload.get("user_id"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"user": user}


@app.post("/auth/login")
async def login(payload: dict[str, Any]) -> dict[str, Any]:
    result = auth_store.authenticate(
        username=str(payload.get("username", "")),
        password=str(payload.get("password", "")),
    )
    if result is None:
        raise HTTPException(status_code=401, detail="invalid username or password")
    return result


@app.get("/auth/me")
async def me(x_user_token: str | None = Header(default=None)) -> dict[str, Any]:
    return {"user": _user_from_token(x_user_token)}


@app.post("/auth/logout")
async def logout(x_user_token: str | None = Header(default=None)) -> dict[str, Any]:
    if not x_user_token:
        raise HTTPException(status_code=401, detail="X-User-Token is required")
    return {"revoked": auth_store.revoke_token(x_user_token)}


@app.get("/gateway/sessions")
async def list_sessions(
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None),
    x_user_token: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_workspace_id: str | None = Header(default=None),
    x_task_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _resolve_agent(authorization, x_agent_id, None)
    user_id = _resolve_user_id(
        body=None,
        x_user_token=x_user_token,
        x_user_id=x_user_id,
        body_user=None,
    )
    return {
        "data": store.list_sessions(
            user_id=user_id,
            workspace_id=x_workspace_id,
            task_id=x_task_id,
        )
    }


@app.delete("/gateway/sessions/{session_id}")
async def clear_session(
    session_id: str,
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None),
    x_user_token: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_workspace_id: str | None = Header(default=None),
    x_task_id: str | None = Header(default=None),
) -> dict[str, Any]:
    agent_id, _ = _resolve_agent(authorization, x_agent_id, None)
    user_id = _resolve_user_id(
        body=None,
        x_user_token=x_user_token,
        x_user_id=x_user_id,
        body_user=None,
    )
    workspace_id = x_workspace_id or config.default_workspace_id
    task_id = x_task_id or session_id
    session_key = make_session_key(user_id, workspace_id, task_id, agent_id, session_id)
    deleted = store.clear_session_key(session_key)
    return {
        "deleted": deleted,
        "user_id": user_id,
        "workspace_id": workspace_id,
        "task_id": task_id,
        "agent_id": agent_id,
        "session_id": session_id,
    }


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    model_ids = [_public_model_id()] if _public_model_id() else []
    if not _is_codex_backend():
        model_ids.extend(agent.model for agent in config.agents.values() if agent.model)
    unique_model_ids = sorted({model_id for model_id in model_ids if model_id})
    return {
        "object": "list",
        "data": [
            {
                "id": model_id,
                "object": "model",
                "created": 0,
                "owned_by": "gateway",
            }
            for model_id in unique_model_ids
        ],
    }


@app.post("/mycomesh/p2p-infer")
async def p2p_native_infer(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None),
) -> Response:
    _resolve_agent(authorization, x_agent_id, None)
    codex_testnet = (
        config.backend == "codex_app_server"
        and config.network_profile == "testnet"
        and config.codex_testnet_metering
    )
    if config.backend != "native_metered_http" and not codex_testnet:
        raise HTTPException(status_code=503, detail="settlement metering is not configured")
    wrapper = await _bounded_request_json(request)
    if set(wrapper) != {"schema", "endpoint", "request"}:
        raise HTTPException(status_code=422, detail="invalid P2P native inference wrapper")
    if wrapper.get("schema") != P2P_NATIVE_INFERENCE_SCHEMA:
        raise HTTPException(status_code=422, detail="invalid P2P native inference schema")
    endpoint = wrapper.get("endpoint")
    native_body = wrapper.get("request")
    if endpoint not in {"chat", "responses"} or not isinstance(native_body, dict):
        raise HTTPException(status_code=422, detail="invalid P2P native inference request")
    if codex_testnet:
        codex_body = _codex_body(native_body)
        if endpoint == "chat":
            payload = await codex_app_backend.chat_completion(
                codex_body,
                public_model=_public_model_id(),
            )
        else:
            payload = await codex_app_backend.response(
                codex_body,
                public_model=_public_model_id(),
            )
        return JSONResponse(payload)

    await _ensure_native_metered_backend_ready()
    try:
        prepared = _native_metered_backend().prepare_request(endpoint, native_body)
    except NativeMeteringRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response = await upstream.post_json("/mycomesh/infer", prepared.envelope)
    content_type = response.headers.get("content-type", "application/json")
    if response.status_code >= 400:
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=content_type,
        )
    try:
        payload = _native_metered_backend().parse_and_verify_result(prepared, response.content)
    except NativeMeteringError as exc:
        raise UpstreamError(f"native metering verification failed: {exc}") from exc
    return JSONResponse(payload)


@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None),
    x_user_token: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_workspace_id: str | None = Header(default=None),
    x_task_id: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
    x_gateway_stateful: str | None = Header(default=None),
) -> Response:
    body = await _bounded_request_json(request)
    context, agent_config = _request_context(
        authorization=authorization,
        x_agent_id=x_agent_id,
        x_user_token=x_user_token,
        x_user_id=x_user_id,
        x_workspace_id=x_workspace_id,
        x_task_id=x_task_id,
        x_session_id=x_session_id,
        x_gateway_stateful=x_gateway_stateful,
        body=body,
    )

    if body.get("gateway_clear_session"):
        store.clear_session_key(context.session_key)

    upstream_body = _strip_gateway_fields(body)
    _apply_model(upstream_body, agent_config)
    if config.backend == "native_metered_http":
        if context.stateful:
            raise HTTPException(
                status_code=422,
                detail="stateful sessions are disabled for settlement-backed native metering",
            )
        upstream_body["messages"] = body.get("messages", [])
    else:
        upstream_body["messages"] = _build_messages(
            context=context,
            agent_config=agent_config,
            incoming_messages=body.get("messages", []),
        )

    if not upstream_body.get("model"):
        raise HTTPException(
            status_code=400,
            detail="model is required unless CENTER_MODEL or the agent config provides one",
        )

    if config.backend == "native_metered_http" and upstream_body.get("stream"):
        raise HTTPException(
            status_code=422,
            detail="streaming is disabled for settlement-backed native metering",
        )

    if upstream_body.get("stream"):
        if _is_codex_backend():
            stream = _stream_codex_chat_completion(
                context=context,
                incoming_messages=body.get("messages", []),
                upstream_body=upstream_body,
            )
            return StreamingResponse(stream, media_type="text/event-stream")
        stream = _stream_chat_completion(
            context=context,
            incoming_messages=body.get("messages", []),
            upstream_body=upstream_body,
        )
        return StreamingResponse(stream, media_type="text/event-stream")

    if _is_codex_backend():
        try:
            if _fast_probe_reply_from_chat(upstream_body) is not None:
                payload = chat_completion_payload(
                    model=_public_model_for_response(body),
                    content=_fast_probe_reply_from_chat(upstream_body) or "ok",
                )
            elif _should_fast_protocol_shim(upstream_body):
                payload = fast_chat_payload(
                    model=_public_model_for_response(body),
                    body=upstream_body,
                )
                if payload is None:
                    payload = await _codex_backend().chat_completion(
                        _codex_body(upstream_body),
                        public_model=_public_model_for_response(body),
                    )
            elif _should_orchestrate(agent_config, upstream_body):
                payload = await _run_codex_orchestration(
                    context=context,
                    orchestrator_config=agent_config,
                    incoming_messages=body.get("messages", []),
                    base_body=upstream_body,
                    public_model=_public_model_for_response(body),
                    include_trace=_should_include_orchestration_trace(body),
                )
            else:
                payload = await _codex_backend().chat_completion(
                    _codex_body(upstream_body),
                    public_model=_public_model_for_response(body),
                )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise HTTPException(
                status_code=504,
                detail=f"Codex app-server exceeded its total {config.codex_timeout_seconds:.0f}s deadline",
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    elif config.backend == "openai_http":
        response = await upstream.post_json("/chat/completions", upstream_body)
        content_type = response.headers.get("content-type", "application/json")
        if response.status_code >= 400:
            return Response(
                content=response.content,
                status_code=response.status_code,
                media_type=content_type,
            )
        payload = response.json()
    elif config.backend == "native_metered_http":
        await _ensure_native_metered_backend_ready()
        try:
            prepared = _native_metered_backend().prepare_request("chat", upstream_body)
        except NativeMeteringRequestError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        response = await upstream.post_json("/mycomesh/infer", prepared.envelope)
        content_type = response.headers.get("content-type", "application/json")
        if response.status_code >= 400:
            return Response(
                content=response.content,
                status_code=response.status_code,
                media_type=content_type,
            )
        try:
            payload = _native_metered_backend().parse_and_verify_result(
                prepared, response.content
            )
        except NativeMeteringError as exc:
            raise UpstreamError(f"native metering verification failed: {exc}") from exc
    else:
        raise HTTPException(status_code=500, detail=f"unknown backend: {config.backend}")

    _persist_chat_turn(
        context=context,
        incoming_messages=body.get("messages", []),
        assistant_message=_extract_assistant_message(payload),
    )
    return JSONResponse(payload)


@app.post("/responses")
@app.post("/responses/compact")
@app.post("/v1/responses")
@app.post("/v1/v1/responses")
@app.post("/v1/responses/compact")
@app.post("/v1/v1/responses/compact")
async def responses(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None),
    x_user_token: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_workspace_id: str | None = Header(default=None),
    x_task_id: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
    x_gateway_stateful: str | None = Header(default=None),
) -> Response:
    if (
        config.backend == "native_metered_http"
        and request.url.path.rstrip("/").endswith("/compact")
    ):
        raise HTTPException(status_code=422, detail="compact responses are not supported")
    body = await _bounded_request_json(request)
    context, agent_config = _request_context(
        authorization=authorization,
        x_agent_id=x_agent_id,
        x_user_token=x_user_token,
        x_user_id=x_user_id,
        x_workspace_id=x_workspace_id,
        x_task_id=x_task_id,
        x_session_id=x_session_id,
        x_gateway_stateful=x_gateway_stateful,
        body=body,
    )

    if config.backend == "native_metered_http" and context.stateful:
        raise HTTPException(
            status_code=422,
            detail="stateful sessions are disabled for settlement-backed native metering",
        )

    upstream_body = _strip_gateway_fields(body)
    _apply_model(upstream_body, agent_config)
    if not upstream_body.get("model"):
        raise HTTPException(
            status_code=400,
            detail="model is required unless CENTER_MODEL or the agent config provides one",
        )

    if _is_codex_backend():
        fast_reply = _fast_probe_reply_from_response(upstream_body)
        if _contains_response_function_call_output(body.get("input")):
            upstream_body["input"] = body.get("input")
        else:
            upstream_body["input"] = _normalize_response_input_files(upstream_body.get("input"))
            upstream_body["input"] = _build_response_input(
                context=context,
                agent_config=agent_config,
                body={**body, "input": upstream_body["input"]},
            )
        if upstream_body.get("stream"):
            stream = _stream_codex_response(context, body.get("input", []), upstream_body)
            return StreamingResponse(stream, media_type="text/event-stream")
        try:
            if fast_reply is not None:
                payload = response_payload(
                    model=_public_model_for_response(body),
                    content=fast_reply,
                    body=upstream_body,
                )
            elif _should_codex_app_protocol_bridge(upstream_body):
                payload = await _codex_backend().response(
                    _codex_body(upstream_body),
                    public_model=_public_model_for_response(body),
                )
            elif _should_fast_protocol_shim(upstream_body):
                payload = fast_response_payload(
                    model=_public_model_for_response(body),
                    body=upstream_body,
                )
                if payload is None:
                    payload = await _codex_backend().response(
                        _codex_body(upstream_body),
                        public_model=_public_model_for_response(body),
                    )
            else:
                payload = await _codex_backend().response(
                    _codex_body(upstream_body),
                    public_model=_public_model_for_response(body),
                )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise HTTPException(
                status_code=504,
                detail=f"Codex app-server exceeded its total {config.codex_timeout_seconds:.0f}s deadline",
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        _persist_response_turn(context, body.get("input"), payload.get("output_text"))
        return JSONResponse(payload)

    if config.backend == "native_metered_http":
        await _ensure_native_metered_backend_ready()
        if upstream_body.get("stream"):
            raise HTTPException(
                status_code=422,
                detail="streaming is disabled for settlement-backed native metering",
            )
        try:
            prepared = _native_metered_backend().prepare_request("responses", upstream_body)
        except NativeMeteringRequestError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        response = await upstream.post_json("/mycomesh/infer", prepared.envelope)
        content_type = response.headers.get("content-type", "application/json")
        if response.status_code >= 400:
            return Response(
                content=response.content,
                status_code=response.status_code,
                media_type=content_type,
            )
        try:
            return JSONResponse(
                _native_metered_backend().parse_and_verify_result(
                    prepared, response.content
                )
            )
        except NativeMeteringError as exc:
            raise UpstreamError(f"native metering verification failed: {exc}") from exc

    response = await upstream.post_json("/responses", upstream_body)
    content_type = response.headers.get("content-type", "application/json")
    if response.status_code >= 400:
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=content_type,
        )
    return JSONResponse(response.json())


@app.post("/v1/embeddings")
async def embeddings(request: Request) -> Response:
    if _is_restricted_inference_backend():
        return _unsupported("embeddings", f"{config.backend} does not provide embeddings")
    return await _proxy_request("embeddings", request)


@app.api_route("/v1/files{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def files(request: Request, path: str = "") -> Response:
    if _is_restricted_inference_backend():
        return _unsupported("files", f"{config.backend} backend does not expose OpenAI Files API")
    return await _proxy_request(f"files{path}", request)


@app.api_route("/v1/audio{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def audio(request: Request, path: str = "") -> Response:
    if _is_restricted_inference_backend():
        return _unsupported("audio", f"{config.backend} backend does not expose audio APIs")
    return await _proxy_request(f"audio{path}", request)


@app.api_route("/v1/images{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def images(request: Request, path: str = "") -> Response:
    if _is_restricted_inference_backend():
        return _unsupported("images", f"{config.backend} backend does not expose image APIs")
    return await _proxy_request(f"images{path}", request)


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_v1(path: str, request: Request) -> Response:
    if _is_restricted_inference_backend():
        return _unsupported(path, f"{config.backend} backend does not support /v1/{path}")
    return await _proxy_request(path, request)


async def _proxy_request(path: str, request: Request) -> Response:
    _resolve_agent(
        request.headers.get("authorization"),
        request.headers.get("x-agent-id"),
        None,
    )
    body = await _bounded_request_body(request)
    response = await upstream.proxy(
        method=request.method,
        path=f"/{path}",
        headers=dict(request.headers),
        body=body,
        query=request.url.query,
    )
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=_response_headers(response.headers),
    )


def _resolve_agent(
    authorization: str | None,
    x_agent_id: str | None,
    body_agent_id: str | None,
) -> tuple[str, AgentConfig]:
    token = _bearer_token(authorization)
    if config.key_to_agent:
        if not token or token not in config.key_to_agent:
            raise HTTPException(status_code=401, detail="unknown agent key")
        agent_id = config.key_to_agent[token]
    elif config.allow_anonymous_gateway:
        agent_id = body_agent_id or x_agent_id or "default"
    else:
        raise HTTPException(
            status_code=503,
            detail="gateway has no agent keys configured; set AGENT_KEYS or explicitly enable ALLOW_ANONYMOUS_GATEWAY",
        )

    agent_config = config.agents.get(agent_id, AgentConfig(agent_id=agent_id))
    return agent_id, agent_config


async def _bounded_request_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > config.max_request_bytes:
                raise HTTPException(status_code=413, detail="request body is too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from exc
    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > config.max_request_bytes - len(body):
            raise HTTPException(status_code=413, detail="request body is too large")
        body.extend(chunk)
    return bytes(body)


async def _bounded_request_json(request: Request) -> dict[str, Any]:
    body = await _bounded_request_body(request)
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="request body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    return payload


def _request_context(
    authorization: str | None,
    x_agent_id: str | None,
    x_user_token: str | None,
    x_user_id: str | None,
    x_workspace_id: str | None,
    x_task_id: str | None,
    x_session_id: str | None,
    x_gateway_stateful: str | None,
    body: dict[str, Any],
) -> tuple[RequestContext, AgentConfig]:
    agent_id, agent_config = _resolve_agent(
        authorization,
        x_agent_id,
        body.get("gateway_agent_id"),
    )
    context = _build_context(
        agent_id=agent_id,
        agent_config=agent_config,
        body=body,
        x_user_token=x_user_token,
        x_user_id=x_user_id,
        x_workspace_id=x_workspace_id,
        x_task_id=x_task_id,
        x_session_id=x_session_id,
        x_gateway_stateful=x_gateway_stateful,
    )
    _validate_agent_access(agent_config, context)
    return context, agent_config


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="authorization must use Bearer token")
    return token


def _resolve_session_id(x_session_id: str | None, body: dict[str, Any]) -> str | None:
    return (
        body.get("gateway_session_id")
        or x_session_id
        or body.get("user")
    )


def _build_context(
    agent_id: str,
    agent_config: AgentConfig,
    body: dict[str, Any],
    x_user_token: str | None,
    x_user_id: str | None,
    x_workspace_id: str | None,
    x_task_id: str | None,
    x_session_id: str | None,
    x_gateway_stateful: str | None,
) -> RequestContext:
    user_id = _resolve_user_id(
        body=body,
        x_user_token=x_user_token,
        x_user_id=x_user_id,
        body_user=body.get("user"),
    )
    workspace_id = (
        body.get("gateway_workspace_id")
        or x_workspace_id
        or config.default_workspace_id
    )
    raw_session_id = _resolve_session_id(x_session_id, body)
    task_id = (
        body.get("gateway_task_id")
        or x_task_id
        or raw_session_id
        or "default-task"
    )
    session_id = raw_session_id or f"{task_id}:{agent_id}"
    metadata = _context_metadata(body)
    stateful = _is_stateful(session_id, x_gateway_stateful, body)
    session_key = make_session_key(user_id, workspace_id, task_id, agent_id, session_id)
    return RequestContext(
        user_id=str(user_id),
        workspace_id=str(workspace_id),
        task_id=str(task_id),
        agent_id=agent_id,
        session_id=str(session_id),
        session_key=session_key,
        stateful=stateful,
        metadata={
            "agent_role": agent_config.role,
            **metadata,
        },
    )


def _resolve_user_id(
    body: dict[str, Any] | None,
    x_user_token: str | None,
    x_user_id: str | None,
    body_user: Any,
) -> str:
    if x_user_token:
        return _user_from_token(x_user_token)["user_id"]
    if config.require_user_auth:
        raise HTTPException(status_code=401, detail="X-User-Token is required")
    if body is not None and body.get("gateway_user_id"):
        return str(body["gateway_user_id"])
    if x_user_id:
        return x_user_id
    if body_user:
        return str(body_user)
    return config.default_user_id


def _user_from_token(token: str | None) -> dict[str, Any]:
    if not token:
        raise HTTPException(status_code=401, detail="X-User-Token is required")
    user = auth_store.user_for_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid or expired user token")
    return user


def _context_metadata(body: dict[str, Any]) -> dict[str, Any]:
    raw_metadata = body.get("gateway_metadata")
    if isinstance(raw_metadata, dict):
        return raw_metadata
    return {}


def _validate_agent_access(agent_config: AgentConfig, context: RequestContext) -> None:
    if agent_config.allowed_users and context.user_id not in agent_config.allowed_users:
        raise HTTPException(status_code=403, detail="agent is not allowed for this user")
    if agent_config.workspace_ids and context.workspace_id not in agent_config.workspace_ids:
        raise HTTPException(status_code=403, detail="agent is not allowed for this workspace")


def _is_stateful(
    session_id: str | None,
    x_gateway_stateful: str | None,
    body: dict[str, Any],
) -> bool:
    if body.get("gateway_stateful") is not None:
        return bool(body["gateway_stateful"])
    if x_gateway_stateful is not None:
        return x_gateway_stateful.strip().lower() in STATEFUL_HEADER_VALUES
    return bool(session_id)


def _strip_gateway_fields(body: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in body.items() if key not in GATEWAY_FIELDS}


def _apply_model(body: dict[str, Any], agent_config: AgentConfig) -> None:
    if config.center_model:
        body["model"] = config.center_model
    elif agent_config.model:
        body["model"] = agent_config.model


def _public_model_id() -> str | None:
    return config.public_model_id or config.center_model


def _public_model_for_response(body: dict[str, Any]) -> str:
    requested_model = body.get("model")
    if isinstance(requested_model, str) and requested_model:
        return requested_model
    return _public_model_id() or "codex-cli"


def _codex_body(body: dict[str, Any]) -> dict[str, Any]:
    codex_body = dict(body)
    codex_body["model"] = config.codex_internal_model or "codex-cli"
    return codex_body


def _is_codex_backend() -> bool:
    return config.backend in {"codex_cli", "codex_app_server"}


def _is_restricted_inference_backend() -> bool:
    return _is_codex_backend() or config.backend == "native_metered_http"


def _native_metered_backend() -> NativeMeteredBackend:
    if native_metered_backend is None:
        raise RuntimeError("native-metered backend is not configured")
    return native_metered_backend


async def _ensure_native_metered_backend_ready() -> None:
    try:
        await _native_metered_backend().ensure_ready(upstream)
    except (NativeMeteringError, UpstreamError) as exc:
        raise UpstreamError(f"native metering capability refresh failed: {exc}") from exc


def _codex_backend() -> Any:
    if config.backend == "codex_app_server":
        return codex_app_backend
    return codex_backend


def _active_inference_capabilities() -> dict[str, Any]:
    if _is_codex_backend():
        return dict(_codex_backend().production_capabilities)
    if config.backend == "native_metered_http":
        return dict(_native_metered_backend().capabilities)
    if config.backend == "openai_http":
        return {
            "backend": "openai_http",
            "native_output_token_cap": False,
            "native_usage_events": False,
            "trusted_native_usage": False,
            "production_strict": config.production_strict,
            "production_ready": False,
            "limitation": (
                "generic OpenAI-compatible upstreams are not pinned to a native output-cap "
                "and trusted-usage contract"
            ),
        }
    return {
        "backend": config.backend,
        "native_output_token_cap": False,
        "native_usage_events": False,
        "trusted_native_usage": False,
        "production_strict": config.production_strict,
        "production_ready": False,
        "limitation": "unknown inference backend",
    }


def _assert_production_backend_ready() -> None:
    if not config.production_strict:
        return
    capabilities = _active_inference_capabilities()
    if capabilities.get("production_ready") is True:
        return
    limitation = str(capabilities.get("limitation") or "required production capabilities are unavailable")
    raise RuntimeError(
        f"{config.network_profile} gateway refuses non-settleable backend {config.backend!r}: {limitation}"
    )


def _fast_probe_reply_from_chat(body: dict[str, Any]) -> str | None:
    if not _can_fast_probe(body):
        return None
    messages = body.get("messages")
    if not isinstance(messages, list):
        return None
    user_messages = [
        message
        for message in messages
        if isinstance(message, dict) and message.get("role") == "user"
    ]
    if len(user_messages) != 1:
        return None
    return _fast_probe_reply(_message_text(user_messages[0]))


def _fast_probe_reply_from_response(body: dict[str, Any]) -> str | None:
    if not _can_fast_probe(body):
        return None
    return _fast_probe_reply(_response_input_text(body.get("input")))


def _can_fast_probe(body: dict[str, Any]) -> bool:
    if config.production_strict:
        return False
    return not any(
        body.get(key)
        for key in (
            "stream",
            "tools",
            "tool_choice",
            "response_format",
            "text",
            "parallel_tool_calls",
        )
    )


def _message_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)
    return ""


def _response_input_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return _message_text(value[0])
    return ""


def _fast_probe_reply(text: str) -> str | None:
    normalized = text.strip().lower()
    normalized = normalized.strip(" \t\r\n.!?。！？'\"`")
    normalized = " ".join(normalized.split())
    if normalized in {"hi", "hello", "hey", "ping", "test", "你好", "您好"}:
        return "hi" if normalized in {"hi", "hello", "hey", "你好", "您好"} else "ok"
    if normalized in {"say hi", "say hello", "reply hi", "respond hi"}:
        return "hi"
    if normalized in {
        "say ok",
        "reply ok",
        "respond ok",
        "just say ok",
        "只回复 ok",
        "只回复ok",
    }:
        return "ok"
    return None


def _should_orchestrate(agent_config: AgentConfig, body: dict[str, Any]) -> bool:
    return bool(
        _is_codex_backend()
        and not config.production_strict
        and agent_config.orchestrates
        and not body.get("stream")
        and not _has_protocol_feature_request(body)
    )


def _should_include_orchestration_trace(body: dict[str, Any]) -> bool:
    metadata = body.get("gateway_metadata")
    return isinstance(metadata, dict) and bool(metadata.get("include_orchestration_trace"))


def _should_fast_protocol_shim(body: dict[str, Any]) -> bool:
    return bool(
        not config.production_strict
        and (body.get("tools") or body.get("tool_choice") or body.get("response_format") or body.get("text"))
    )


def _should_codex_app_protocol_bridge(body: dict[str, Any]) -> bool:
    return bool(
        config.backend == "codex_app_server"
        and (
            body.get("tools")
            or body.get("tool_choice")
            or body.get("response_format")
            or body.get("text")
        )
    )


def _has_protocol_feature_request(body: dict[str, Any]) -> bool:
    if body.get("tools") or body.get("tool_choice"):
        return True
    if body.get("response_format") or body.get("text"):
        return True
    if _contains_typed_content(body.get("messages"), {"file", "input_file", "image_url", "input_image"}):
        return True
    if _contains_typed_content(body.get("input"), {"file", "input_file", "image_url", "input_image"}):
        return True
    return False


def _contains_typed_content(value: Any, content_types: set[str]) -> bool:
    if isinstance(value, dict):
        item_type = value.get("type")
        if isinstance(item_type, str) and item_type in content_types:
            return True
        return any(_contains_typed_content(item, content_types) for item in value.values())
    if isinstance(value, list):
        return any(_contains_typed_content(item, content_types) for item in value)
    return False


def _contains_response_function_call_output(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    return any(
        isinstance(item, dict) and item.get("type") == "function_call_output"
        for item in value
    )


async def _run_codex_orchestration(
    context: RequestContext,
    orchestrator_config: AgentConfig,
    incoming_messages: list[dict[str, Any]],
    base_body: dict[str, Any],
    public_model: str,
    include_trace: bool,
) -> dict[str, Any]:
    orchestrator_context = _child_context(
        context=context,
        agent_id=orchestrator_config.agent_id,
        session_id=f"{context.session_id}:orchestrator",
    )
    messages = _build_messages(
        context=orchestrator_context,
        agent_config=AgentConfig(
            agent_id=orchestrator_config.agent_id,
            role="orchestrator",
            description=orchestrator_config.description,
            system_prompt=orchestrator_prompt(config.agents),
        ),
        incoming_messages=incoming_messages,
    )
    clean_body = strip_for_orchestration(base_body)
    clean_body["messages"] = messages

    trace: list[dict[str, Any]] = []
    last_payload: dict[str, Any] | None = None
    for step in range(max(config.orchestration_max_steps, 1)):
        payload = await _codex_backend().chat_completion(
            _codex_body(clean_body),
            public_model=public_model,
        )
        last_payload = payload
        content = _assistant_content(payload)
        decision = parse_decision(content)
        if decision is None:
            trace.append({"step": step + 1, "action": "fallback_final"})
            return _with_orchestration_metadata(payload, trace, include_trace)

        trace.append(_decision_trace(step + 1, decision))
        if decision.action == "final":
            final = decision.final if decision.final is not None else content
            return _with_orchestration_metadata(
                _replace_chat_content(payload, final),
                trace,
                include_trace,
            )

        if not decision.target_agent or decision.target_agent not in config.agents:
            final = f"Orchestration failed: unknown target_agent {decision.target_agent!r}."
            return _with_orchestration_metadata(
                _replace_chat_content(payload, final),
                trace,
                include_trace,
            )

        agent_payload = await _call_codex_child_agent(
            context=context,
            agent_id=decision.target_agent,
            agent_input=decision.input or "",
            session_id=decision.session_id or f"{context.session_id}:{decision.target_agent}",
            base_body=base_body,
            public_model=public_model,
        )
        agent_content = _assistant_content(agent_payload)
        trace.append(
            {
                "step": step + 1,
                "action": "agent_result",
                "target_agent": decision.target_agent,
            }
        )
        clean_body["messages"].append(
            {
                "role": "assistant",
                "content": json.dumps(
                    {
                        "action": "call_agent",
                        "target_agent": decision.target_agent,
                        "input": decision.input or "",
                    },
                    ensure_ascii=False,
                ),
            }
        )
        clean_body["messages"].append(
            {
                "role": "user",
                "content": agent_result_prompt(decision.target_agent, agent_content),
            }
        )

    fallback = _assistant_content(last_payload) if last_payload else "Orchestration did not produce a final answer."
    payload = last_payload or await _codex_backend().chat_completion(
        _codex_body(clean_body),
        public_model=public_model,
    )
    return _with_orchestration_metadata(_replace_chat_content(payload, fallback), trace, include_trace)


async def _call_codex_child_agent(
    context: RequestContext,
    agent_id: str,
    agent_input: str,
    session_id: str,
    base_body: dict[str, Any],
    public_model: str,
) -> dict[str, Any]:
    agent_config = config.agents[agent_id]
    child_context = _child_context(
        context=context,
        agent_id=agent_id,
        session_id=session_id,
    )
    child_body = strip_for_orchestration(base_body)
    child_body["messages"] = _build_messages(
        context=child_context,
        agent_config=agent_config,
        incoming_messages=[{"role": "user", "content": agent_input}],
    )
    payload = await _codex_backend().chat_completion(
        _codex_body(child_body),
        public_model=public_model,
    )
    _persist_chat_turn(
        context=child_context,
        incoming_messages=[{"role": "user", "content": agent_input}],
        assistant_message=_extract_assistant_message(payload),
    )
    return payload


def _child_context(context: RequestContext, agent_id: str, session_id: str) -> RequestContext:
    return RequestContext(
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        task_id=context.task_id,
        agent_id=agent_id,
        session_id=session_id,
        session_key=make_session_key(
            context.user_id,
            context.workspace_id,
            context.task_id,
            agent_id,
            session_id,
        ),
        stateful=context.stateful,
        metadata={**context.metadata, "routed_by": context.agent_id},
    )


def _assistant_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices") or []
    if choices:
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return ""


def _replace_chat_content(payload: dict[str, Any], content: str) -> dict[str, Any]:
    replaced = dict(payload)
    choices = list(replaced.get("choices") or [])
    if not choices:
        return replaced
    first_choice = dict(choices[0])
    message = dict(first_choice.get("message") or {})
    message["role"] = message.get("role") or "assistant"
    message["content"] = content
    message.pop("tool_calls", None)
    first_choice["message"] = message
    first_choice["finish_reason"] = "stop"
    choices[0] = first_choice
    replaced["choices"] = choices
    return replaced


def _with_orchestration_metadata(
    payload: dict[str, Any],
    trace: list[dict[str, Any]],
    include_trace: bool,
) -> dict[str, Any]:
    if not include_trace:
        return payload
    with_metadata = dict(payload)
    with_metadata["gateway_orchestration"] = {
        "enabled": True,
        "trace": trace,
    }
    return with_metadata


def _decision_trace(step: int, decision: OrchestrationDecision) -> dict[str, Any]:
    trace: dict[str, Any] = {
        "step": step,
        "action": decision.action,
    }
    if decision.target_agent:
        trace["target_agent"] = decision.target_agent
    if decision.session_id:
        trace["session_id"] = decision.session_id
    if decision.reason:
        trace["reason"] = decision.reason
    return trace


def _build_messages(
    context: RequestContext,
    agent_config: AgentConfig,
    incoming_messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(incoming_messages, list):
        raise HTTPException(status_code=400, detail="messages must be a list")

    messages: list[dict[str, Any]] = []
    if agent_config.system_prompt:
        messages.append({"role": "system", "content": agent_config.system_prompt})
    messages.append({"role": "system", "content": _routing_prompt(context, agent_config)})

    messages.extend(message for message in incoming_messages if message.get("role") == "system")

    if context.stateful:
        messages.extend(store.history_for_session_key(context.session_key, config.history_limit))

    messages.extend(message for message in incoming_messages if message.get("role") != "system")
    return messages


def _build_response_input(
    context: RequestContext,
    agent_config: AgentConfig,
    body: dict[str, Any],
) -> list[dict[str, Any]]:
    incoming = _response_input_to_messages(body.get("input", []))
    return _build_messages(
        context=context,
        agent_config=agent_config,
        incoming_messages=incoming,
    )


def _response_input_to_messages(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        return [{"role": "user", "content": value}]
    if isinstance(value, list):
        messages: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict) and item.get("role"):
                messages.append(
                    {
                        "role": item.get("role", "user"),
                        "content": item.get("content", ""),
                    }
                )
            else:
                messages.append({"role": "user", "content": str(item)})
        return messages
    return [{"role": "user", "content": str(value)}]


def _normalize_response_input_files(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_response_input_files(item) for item in value]
    if isinstance(value, dict):
        if value.get("type") == "input_file":
            return {"type": "input_text", "text": _input_file_text(value)}
        normalized = dict(value)
        if "content" in normalized:
            normalized["content"] = _normalize_response_input_files(normalized["content"])
        return normalized
    return value


def _input_file_text(item: dict[str, Any]) -> str:
    filename = str(item.get("filename") or item.get("name") or "uploaded file")
    file_data = item.get("file_data")
    if _is_inline_pdf_data_uri(file_data):
        raise HTTPException(
            status_code=422,
            detail=(
                "inline PDF extraction is disabled; extract the document in a bounded sandbox "
                "and submit the exact text as input_text"
            ),
        )
    if item.get("file_id"):
        return f"[File input: {filename}; file_id={item['file_id']}]"
    return f"[File input: {filename}]"


def _is_inline_pdf_data_uri(value: Any) -> bool:
    if not isinstance(value, str) or value[:5].lower() != "data:":
        return False
    metadata, separator, _payload = value[5:].partition(",")
    if not separator:
        return False
    media_type = metadata.split(";", 1)[0].strip().lower()
    return media_type == "application/pdf"

def _persist_chat_turn(
    context: RequestContext,
    incoming_messages: list[dict[str, Any]],
    assistant_message: dict[str, Any] | None,
) -> None:
    if not context.stateful:
        return

    new_messages = [
        message
        for message in incoming_messages
        if message.get("role") != "system"
    ]
    if assistant_message:
        new_messages.append(assistant_message)
    store.append_turn(
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        task_id=context.task_id,
        agent_id=context.agent_id,
        session_id=context.session_id,
        messages=new_messages,
        metadata=context.metadata,
    )


def _persist_response_turn(
    context: RequestContext,
    incoming_input: Any,
    output_text: str | None,
) -> None:
    incoming_messages = _response_input_to_messages(incoming_input)
    assistant_message = None
    if output_text:
        assistant_message = {"role": "assistant", "content": output_text}
    _persist_chat_turn(
        context=context,
        incoming_messages=incoming_messages,
        assistant_message=assistant_message,
    )


def _extract_assistant_message(payload: dict[str, Any]) -> dict[str, Any] | None:
    choices = payload.get("choices") or []
    if not choices:
        return None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None
    return message


async def _stream_chat_completion(
    context: RequestContext,
    incoming_messages: list[dict[str, Any]],
    upstream_body: dict[str, Any],
) -> AsyncIterator[bytes]:
    content_parts: list[str] = []
    role = "assistant"

    async for chunk in upstream.stream_post("/chat/completions", upstream_body):
        _collect_stream_content(chunk, content_parts)
        yield chunk

    assistant_message = None
    if content_parts:
        assistant_message = {"role": role, "content": "".join(content_parts)}

    _persist_chat_turn(
        context=context,
        incoming_messages=incoming_messages,
        assistant_message=assistant_message,
    )


async def _stream_codex_chat_completion(
    context: RequestContext,
    incoming_messages: list[dict[str, Any]],
    upstream_body: dict[str, Any],
) -> AsyncIterator[bytes]:
    try:
        payload = await _codex_backend().chat_completion(
            _codex_body(upstream_body),
            public_model=_public_model_for_response(upstream_body),
        )
    except (asyncio.TimeoutError, TimeoutError) as exc:
        yield _sse({"error": _error_payload("timeout", f"Codex app-server exceeded its total {config.codex_timeout_seconds:.0f}s deadline", "timeout")})
        yield b"data: [DONE]\n\n"
        return
    except RuntimeError as exc:
        yield _sse({"error": _error_payload("server_error", str(exc), "server_error")})
        yield b"data: [DONE]\n\n"
        return

    assistant_message = _extract_assistant_message(payload)
    content = ""
    if assistant_message and isinstance(assistant_message.get("content"), str):
        content = assistant_message["content"]

    if content:
        yield _sse(chat_completion_chunk(model=payload["model"], content=content))
    yield _sse(chat_completion_chunk(model=payload["model"], content="", finish=True))
    yield b"data: [DONE]\n\n"

    _persist_chat_turn(
        context=context,
        incoming_messages=incoming_messages,
        assistant_message=assistant_message,
    )


async def _stream_codex_response(
    context: RequestContext,
    incoming_input: Any,
    upstream_body: dict[str, Any],
) -> AsyncIterator[bytes]:
    response_id = f"resp_{uuid.uuid4().hex}"
    created_at = int(time.time())
    created = {
        "id": response_id,
        "object": "response",
        "created_at": created_at,
        "status": "in_progress",
        "model": _public_model_for_response(upstream_body),
        "output": [],
        "output_text": "",
        "error": None,
        "incomplete_details": None,
    }
    yield _sse_event("response.created", {"type": "response.created", "response": created})
    yield _sse_event("response.in_progress", {"type": "response.in_progress", "response": created})
    try:
        payload = await _codex_backend().response(
            _codex_body(upstream_body),
            public_model=_public_model_for_response(upstream_body),
        )
    except (asyncio.TimeoutError, TimeoutError) as exc:
        yield _sse_event(
            "response.failed",
            {
                "type": "response.failed",
                "response": {
                    **created,
                    "status": "failed",
                    "error": _error_payload(
                        "timeout",
                        f"Codex app-server exceeded its total {config.codex_timeout_seconds:.0f}s deadline",
                        "timeout",
                    ),
                },
            },
        )
        return
    except RuntimeError as exc:
        yield _sse_event(
            "response.failed",
            {
                "type": "response.failed",
                "response": {
                    **created,
                    "status": "failed",
                    "error": _error_payload("server_error", str(exc), "server_error"),
                },
            },
        )
        return

    payload["id"] = response_id
    content = payload.get("output_text", "")
    output = payload.get("output") if isinstance(payload.get("output"), list) else []
    message_index = next(
        (
            index
            for index, item in enumerate(output)
            if isinstance(item, dict) and item.get("type") == "message"
        ),
        len(output),
    )
    message_item = (
        output[message_index]
        if message_index < len(output) and isinstance(output[message_index], dict)
        else {
            "id": f"msg_{uuid.uuid4().hex}",
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": content, "annotations": []}],
        }
    )
    message_id = str(message_item.get("id") or f"msg_{uuid.uuid4().hex}")
    message_content = message_item.get("content") if isinstance(message_item.get("content"), list) else []
    text_part_index = next(
        (
            index
            for index, part in enumerate(message_content)
            if isinstance(part, dict) and part.get("type") == "output_text"
        ),
        0,
    )
    text_part = (
        message_content[text_part_index]
        if text_part_index < len(message_content) and isinstance(message_content[text_part_index], dict)
        else {"type": "output_text", "text": content, "annotations": []}
    )
    annotations = text_part.get("annotations") if isinstance(text_part.get("annotations"), list) else []

    for index, item in enumerate(output):
        if index == message_index or not isinstance(item, dict):
            continue
        yield _sse_event(
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "output_index": index,
                "item": {**item, "status": "in_progress"},
            },
        )
        yield _sse_event(
            "response.output_item.done",
            {"type": "response.output_item.done", "output_index": index, "item": item},
        )

    added_message_item = {**message_item, "status": "in_progress", "content": []}
    yield _sse_event(
        "response.output_item.added",
        {
            "type": "response.output_item.added",
            "output_index": message_index,
            "item": added_message_item,
        },
    )
    yield _sse_event(
        "response.content_part.added",
        {
            "type": "response.content_part.added",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_part_index,
            "part": {"type": "output_text", "text": "", "annotations": annotations},
        },
    )
    if content:
        yield _sse_event(
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "item_id": message_id,
                "output_index": message_index,
                "content_index": text_part_index,
                "delta": content,
            },
        )
    yield _sse_event(
        "response.output_text.done",
        {
            "type": "response.output_text.done",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_part_index,
            "text": content,
        },
    )
    yield _sse_event(
        "response.content_part.done",
        {
            "type": "response.content_part.done",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_part_index,
            "part": {"type": "output_text", "text": content, "annotations": annotations},
        },
    )
    yield _sse_event(
        "response.output_item.done",
        {
            "type": "response.output_item.done",
            "output_index": message_index,
            "item": message_item,
        },
    )
    yield _sse_event("response.completed", {"type": "response.completed", "response": payload})
    _persist_response_turn(context, incoming_input, content)


def _routing_prompt(context: RequestContext, agent_config: AgentConfig) -> str:
    lines = [
        "Gateway routing context:",
        f"- user_id: {context.user_id}",
        f"- workspace_id: {context.workspace_id}",
        f"- task_id: {context.task_id}",
        f"- agent_id: {context.agent_id}",
        f"- agent_role: {agent_config.role}",
        f"- session_id: {context.session_id}",
        "",
        "You are a child code agent behind an OpenAI-compatible gateway.",
        "Treat the current request as part of this routed code task.",
        "Do not claim to have changed files unless the caller provided tools or instructions that actually let you do so.",
    ]
    if agent_config.description:
        lines.append(f"Agent description: {agent_config.description}")
    return "\n".join(lines)


def _collect_stream_content(chunk: bytes, content_parts: list[str]) -> None:
    for raw_line in chunk.splitlines():
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if not line.startswith("data: "):
            continue
        data = line.removeprefix("data: ").strip()
        if not data or data == "[DONE]":
            continue
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            continue
        choices = payload.get("choices") or []
        if not choices:
            continue
        delta = choices[0].get("delta") or {}
        content = delta.get("content")
        if isinstance(content, str):
            content_parts.append(content)


def _response_headers(headers: dict[str, str]) -> dict[str, str]:
    excluded = {
        "content-encoding",
        "content-length",
        "connection",
        "transfer-encoding",
    }
    return {key: value for key, value in headers.items() if key.lower() not in excluded}


def _unsupported(param: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": _error_payload(param=param, message=message, code="unsupported")},
    )


def _error_payload(param: str, message: str, code: str) -> dict[str, Any]:
    return {
        "message": message,
        "type": "invalid_request_error",
        "param": param,
        "code": code,
    }


def _sse(payload: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _sse_event(event: str, payload: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")
