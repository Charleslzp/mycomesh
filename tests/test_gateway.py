from __future__ import annotations

import base64
import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient

from gateway.codex_backend import (
    CodexCliBackend,
    CodexProcessLimiter,
    _ProcessOutputLimitError,
    _read_bounded_stream,
    chat_completion_payload,
    response_payload,
    tool_call_payload,
)
from gateway.codex_app_backend import (
    AppTurnResult,
    CodexAppServerBackend,
    PendingToolTurn,
    _JsonRpcClient,
    _dynamic_tools,
    _hosted_tools_config,
)
from gateway.server_limits import (
    MAX_SERVER_CONNECTIONS,
    BoundedASGIConcurrencyMiddleware,
    uvicorn_limit_args,
)
from gateway.request_limits import BoundedRequestBodyMiddleware
from gateway.upstream import normalize_upstream_base_url


class FakeUpstream:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    async def post_json(self, path: str, body: dict[str, Any]):
        self.requests.append({"path": path, "body": body})
        return FakeResponse(
            {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 0,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    async def proxy(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        query: str,
    ) -> "FakeResponse":
        self.requests.append(
            {
                "method": method,
                "path": path,
                "headers": headers,
                "body": body,
                "query": query,
            }
        )
        return FakeResponse({"ok": True})


class FakeResponse:
    status_code = 200
    headers = {"content-type": "application/json"}

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.content = json.dumps(payload).encode("utf-8")

    def json(self) -> dict[str, Any]:
        return self._payload


class FakeCodexBackend:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    async def chat_completion(self, body: dict[str, Any], public_model: str | None = None):
        self.requests.append(body)
        return {
            "id": "chatcmpl-codex-test",
            "object": "chat.completion",
            "created": 0,
            "model": public_model or body["model"],
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "codex ok"},
                    "finish_reason": "stop",
                }
            ],
        }

    async def response(self, body: dict[str, Any], public_model: str | None = None):
        self.requests.append(body)
        return {
            "id": "resp-codex-test",
            "object": "response",
            "created_at": 0,
            "status": "completed",
            "model": public_model or body["model"],
            "output": [
                {
                    "id": "msg-test",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "response ok",
                            "annotations": [],
                        }
                    ],
                }
            ],
            "output_text": "response ok",
            "usage": None,
        }


class SequencedCodexBackend:
    def __init__(self, outputs: list[str]) -> None:
        self.outputs = outputs
        self.requests: list[dict[str, Any]] = []

    async def chat_completion(self, body: dict[str, Any], public_model: str | None = None):
        self.requests.append(body)
        index = len(self.requests) - 1
        content = self.outputs[index] if index < len(self.outputs) else self.outputs[-1]
        return {
            "id": f"chatcmpl-codex-test-{index}",
            "object": "chat.completion",
            "created": 0,
            "model": public_model or body["model"],
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    async def response(self, body: dict[str, Any], public_model: str | None = None):
        raise AssertionError("response should not be called in orchestration tests")


class PendingToolCodexAppBackend(CodexAppServerBackend):
    def __init__(self) -> None:
        super().__init__(
            command="codex",
            codex_home=".",
            workdir=".",
            sandbox="workspace-write",
            timeout_seconds=1,
        )
        self.requests: list[dict[str, Any]] = []
        self.fake_client = FakePendingToolClient()

    async def _run_turn(
        self,
        prompt: str,
        model: str,
        output_schema: dict[str, Any] | None = None,
        tools: Any = None,
    ) -> AppTurnResult:
        self.requests.append(
            {
                "prompt": prompt,
                "model": model,
                "output_schema": output_schema,
                "tools": tools,
            }
        )
        return AppTurnResult(
            thread_id="thread-1",
            turn_id="turn-1",
            text="",
            usage={"inputTokens": 1, "outputTokens": 0, "totalTokens": 1},
            items=[],
            client=self.fake_client,
            pending_tool_request_id=99,
            pending_tool_call={
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "call_lookup",
                "tool": "lookup",
                "arguments": {"query": "weather"},
            },
        )


class HostedSearchCodexAppBackend(CodexAppServerBackend):
    def __init__(self) -> None:
        super().__init__(
            command="codex",
            codex_home=".",
            workdir=".",
            sandbox="workspace-write",
            timeout_seconds=1,
        )
        self.requests: list[dict[str, Any]] = []

    async def _run_turn(
        self,
        prompt: str,
        model: str,
        output_schema: dict[str, Any] | None = None,
        tools: Any = None,
    ) -> AppTurnResult:
        self.requests.append(
            {
                "prompt": prompt,
                "model": model,
                "output_schema": output_schema,
                "tools": tools,
            }
        )
        return AppTurnResult(
            thread_id="thread-search",
            turn_id="turn-search",
            text="Search result",
            usage={"inputTokens": 2, "outputTokens": 3, "totalTokens": 5},
            items=[],
            response_items=[
                {
                    "id": "ws_real",
                    "type": "web_search_call",
                    "status": "completed",
                    "action": {"type": "search", "query": "search the web"},
                }
            ],
        )


class FakePendingToolClient:
    def __init__(self) -> None:
        self.responses: list[dict[str, Any]] = []
        self.closed = False

    async def respond(self, request_id: int | str, result: dict[str, Any]) -> None:
        self.responses.append({"request_id": request_id, "result": result})

    async def read_turn_until_stop(self, thread_id: str, turn_id: str) -> AppTurnResult:
        return AppTurnResult(
            thread_id=thread_id,
            turn_id=turn_id,
            text="Final answer after lookup",
            usage={"inputTokens": 2, "outputTokens": 3, "totalTokens": 5},
            items=[],
        )

    async def close(self) -> None:
        self.closed = True


class GatewayTest(unittest.TestCase):
    def test_upstream_base_url_is_structurally_validated(self) -> None:
        self.assertEqual(
            normalize_upstream_base_url("HTTPS://API.OpenAI.com:443/v1/"),
            "https://api.openai.com/v1",
        )
        self.assertEqual(
            normalize_upstream_base_url("http://127.0.0.1:8080/v1"),
            "http://127.0.0.1:8080/v1",
        )
        for invalid in (
            "ftp://api.example/v1",
            "https://user:secret@api.example/v1",
            "https://api.example/v1?token=secret",
            "https://api.example/v1#fragment",
            "https://api.example/v1;params",
            " https://api.example/v1",
            "https://api.example\\@evil.example/v1",
            "https://-api.example/v1",
            "https://api-.example/v1",
            "https://api_name.example/v1",
            "https://999.999.999.999/v1",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_upstream_base_url(invalid)

    def test_public_health_does_not_disclose_upstream_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                **os.environ,
                "AGENTS_FILE": str(Path(tmp) / "missing-agents.json"),
                "SESSION_DB": str(Path(tmp) / "sessions.sqlite3"),
                "UPSTREAM_BASE_URL": "https://api.example/v1",
            }
            with patch.dict(os.environ, env, clear=True):
                main = importlib.reload(importlib.import_module("gateway.main"))
                response = TestClient(main.app).get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("upstream_base_url", response.json())
        self.assertEqual(response.json()["network_profile"], "local")
        self.assertFalse(response.json()["settlement_ready"])

    def test_nonlocal_gateway_profile_forces_fail_closed_production_gate(self) -> None:
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "AGENTS_FILE": str(Path(tmp) / "missing-agents.json"),
                "SESSION_DB": str(Path(tmp) / "sessions.sqlite3"),
                "GATEWAY_BACKEND": "codex_app_server",
                "MYCOMESH_NETWORK_PROFILE": "testnet",
                "CODEX_PRODUCTION_STRICT": "false",
            }
            with patch.dict(os.environ, env, clear=True):
                main = importlib.reload(importlib.import_module("gateway.main"))
            self.addCleanup(importlib.reload, main)

        self.assertTrue(main.config.production_strict)
        self.assertTrue(main.codex_app_backend.production_strict)
        with patch.object(
            main,
            "config",
            replace(main.config, network_profile="testnet", production_strict=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "refuses non-settleable backend"):
                main._assert_production_backend_ready()
            capabilities = main._active_inference_capabilities()
        self.assertFalse(capabilities["native_output_token_cap"])
        self.assertFalse(capabilities["production_ready"])

    def test_unknown_gateway_network_profile_is_rejected(self) -> None:
        from gateway.config import load_config

        with patch.dict(os.environ, {"MYCOMESH_NETWORK_PROFILE": "mainnet"}, clear=True):
            with self.assertRaisesRegex(ValueError, "unknown MycoMesh network profile"):
                load_config()

    def test_chat_completion_is_stateful_and_agent_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents_file = tmp_path / "agents.json"
            agents_file.write_text(
                """
                {
                  "agents": {
                    "planner": {
                      "keys": ["planner-key"],
                      "role": "planner",
                      "system_prompt": "Planner prompt",
                      "model": "central-test-model"
                    }
                  }
                }
                """,
                encoding="utf-8",
            )

            env = {
                **os.environ,
                "AGENTS_FILE": str(agents_file),
                "SESSION_DB": str(tmp_path / "sessions.sqlite3"),
                "GATEWAY_BACKEND": "openai_http",
                "CENTER_MODEL": "",
            }

            with patch.dict(os.environ, env, clear=True):
                main = importlib.import_module("gateway.main")
                main = importlib.reload(main)
                fake_upstream = FakeUpstream()
                main.upstream = fake_upstream

                client = TestClient(main.app)
                headers = {"Authorization": "Bearer planner-key"}

                first = client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "child-model",
                        "gateway_user_id": "user-a",
                        "gateway_workspace_id": "repo-a",
                        "gateway_task_id": "task-1",
                        "gateway_session_id": "planning",
                        "messages": [{"role": "user", "content": "first"}],
                    },
                )
                self.assertEqual(first.status_code, 200)

                second = client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "child-model",
                        "gateway_user_id": "user-a",
                        "gateway_workspace_id": "repo-a",
                        "gateway_task_id": "task-1",
                        "gateway_session_id": "planning",
                        "messages": [{"role": "user", "content": "second"}],
                    },
                )
                self.assertEqual(second.status_code, 200)

            first_body = fake_upstream.requests[0]["body"]
            self.assertEqual(first_body["model"], "central-test-model")
            self.assertEqual(
                first_body["messages"][0],
                {"role": "system", "content": "Planner prompt"},
            )
            self.assertIn("user_id: user-a", first_body["messages"][1]["content"])
            self.assertIn("workspace_id: repo-a", first_body["messages"][1]["content"])
            self.assertIn("task_id: task-1", first_body["messages"][1]["content"])
            self.assertEqual(first_body["messages"][2], {"role": "user", "content": "first"})

            second_body = fake_upstream.requests[1]["body"]
            self.assertEqual(
                second_body["messages"],
                [
                    {"role": "system", "content": "Planner prompt"},
                    second_body["messages"][1],
                    {"role": "user", "content": "first"},
                    {"role": "assistant", "content": "ok"},
                    {"role": "user", "content": "second"},
                ],
            )

            sessions = client.get(
                "/gateway/sessions",
                headers={
                    "Authorization": "Bearer planner-key",
                    "X-User-Id": "user-a",
                },
            ).json()["data"]
            self.assertEqual(sessions[0]["user_id"], "user-a")
            self.assertEqual(sessions[0]["workspace_id"], "repo-a")
            self.assertEqual(sessions[0]["task_id"], "task-1")
            self.assertEqual(sessions[0]["agent_id"], "planner")
            self.assertEqual(sessions[0]["session_id"], "planning")

            unauthenticated = client.post(
                "/v1/embeddings",
                json={"model": "embedding-model", "input": "secret"},
            )
            self.assertEqual(unauthenticated.status_code, 401)

            authenticated = client.post(
                "/v1/embeddings",
                headers={"Authorization": "Bearer planner-key"},
                json={"model": "embedding-model", "input": "secret"},
            )
            self.assertEqual(authenticated.status_code, 200)
            self.assertEqual(fake_upstream.requests[-1]["path"], "/embeddings")

    def test_local_user_login_token_can_scope_gateway_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents_file = tmp_path / "agents.json"
            agents_file.write_text(
                """
                {
                  "agents": {
                    "coder": {
                      "keys": ["coder-key"],
                      "role": "coder",
                      "model": "central-test-model"
                    }
                  }
                }
                """,
                encoding="utf-8",
            )
            env = {
                **os.environ,
                "AGENTS_FILE": str(agents_file),
                "SESSION_DB": str(tmp_path / "sessions.sqlite3"),
                "REQUIRE_USER_AUTH": "true",
                "ALLOW_PUBLIC_USER_REGISTRATION": "true",
                "GATEWAY_BACKEND": "openai_http",
                "CENTER_MODEL": "",
            }

            with patch.dict(os.environ, env, clear=True):
                main = importlib.import_module("gateway.main")
                main = importlib.reload(main)
                fake_upstream = FakeUpstream()
                main.upstream = fake_upstream
                client = TestClient(main.app)

                created = client.post(
                    "/auth/register",
                    json={
                        "username": "alice",
                        "password": "password123",
                        "user_id": "user-alice",
                    },
                )
                self.assertEqual(created.status_code, 200)

                login = client.post(
                    "/auth/login",
                    json={"username": "alice", "password": "password123"},
                )
                self.assertEqual(login.status_code, 200)
                token = login.json()["access_token"]

                response = client.post(
                    "/v1/chat/completions",
                    headers={
                        "Authorization": "Bearer coder-key",
                        "X-User-Token": token,
                    },
                    json={
                        "model": "child-model",
                        "gateway_workspace_id": "repo-a",
                        "gateway_task_id": "task-1",
                        "gateway_session_id": "coding",
                        "messages": [{"role": "user", "content": "change code"}],
                    },
                )
                self.assertEqual(response.status_code, 200)

            body = fake_upstream.requests[0]["body"]
            routing_prompt = body["messages"][0]["content"]
            self.assertIn("user_id: user-alice", routing_prompt)

    def test_codex_backend_uses_openai_compatible_response_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents_file = tmp_path / "agents.json"
            agents_file.write_text(
                """
                {
                  "agents": {
                    "coder": {
                      "keys": ["coder-key"],
                      "role": "coder"
                    }
                  }
                }
                """,
                encoding="utf-8",
            )
            env = {
                **os.environ,
                "AGENTS_FILE": str(agents_file),
                "SESSION_DB": str(tmp_path / "sessions.sqlite3"),
                "GATEWAY_BACKEND": "codex_cli",
                "CENTER_MODEL": "",
                "PUBLIC_MODEL_ID": "gpt-5.5",
                "CODEX_INTERNAL_MODEL": "gpt-5.5",
            }

            with patch.dict(os.environ, env, clear=True):
                main = importlib.import_module("gateway.main")
                main = importlib.reload(main)
                fake_codex = FakeCodexBackend()
                main.codex_backend = fake_codex
                client = TestClient(main.app)

                response = client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer coder-key"},
                    json={
                        "model": "gpt-5.5",
                        "gateway_user_id": "user-a",
                        "gateway_workspace_id": "repo-a",
                        "gateway_task_id": "task-1",
                        "gateway_session_id": "coding",
                        "messages": [{"role": "user", "content": "change code"}],
                    },
                )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["choices"][0]["message"]["content"], "codex ok")
            self.assertEqual(payload["model"], "gpt-5.5")
            self.assertEqual(fake_codex.requests[0]["model"], "gpt-5.5")

    def test_responses_api_is_bridged_for_codex_backend(self) -> None:
        client, fake_codex = self._codex_client()
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "task-1",
                "gateway_session_id": "responses",
                "input": "summarize this task",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["object"], "response")
        self.assertEqual(payload["output_text"], "response ok")
        self.assertEqual(payload["model"], "gpt-5.5")
        self.assertEqual(fake_codex.requests[0]["model"], "gpt-5.5")

    def test_responses_route_aliases_and_compact_are_supported(self) -> None:
        for route in ("/responses", "/v1/v1/responses", "/v1/responses/compact"):
            client, _ = self._codex_client()
            response = client.post(
                route,
                headers={"Authorization": "Bearer coder-key"},
                json={
                    "model": "gpt-5.5",
                    "gateway_stateful": False,
                    "input": "ping",
                },
            )
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["object"], "response")
            self.assertTrue(payload["id"].startswith("resp_"))
            self.assertGreater(payload["usage"]["total_tokens"], 0)

    def test_codex_response_stream_emits_responses_sse_events(self) -> None:
        client, _ = self._codex_client()
        with client.stream(
            "POST",
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_stateful": False,
                "stream": True,
                "input": "ping",
            },
        ) as response:
            text = response.read().decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("event: response.created", text)
        self.assertIn('"type": "response.created"', text)
        self.assertIn("event: response.output_item.added", text)
        self.assertIn("event: response.content_part.added", text)
        self.assertIn("event: response.output_text.delta", text)
        self.assertIn("event: response.output_text.done", text)
        self.assertIn("event: response.content_part.done", text)
        self.assertIn("event: response.output_item.done", text)
        self.assertIn("event: response.completed", text)

    def test_responses_json_schema_text_format_returns_strict_json(self) -> None:
        client, _ = self._codex_client(
            backend="codex_app_server",
            codex_backend=StaticCodexBackend("structured"),
        )
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_stateful": False,
                "input": "return structured output",
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "result",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "status": {"type": "string"},
                                "count": {"type": "integer"},
                            },
                            "required": ["status", "count"],
                        },
                    }
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(json.loads(payload["output_text"]), {"status": "structured", "count": 0})

    def test_responses_json_schema_text_format_coerces_boolean_true_and_strips_extra_fields(self) -> None:
        client, _ = self._codex_client(
            backend="codex_app_server",
            codex_backend=StaticCodexBackend('{"code":"DIDI-TEST-STRUCT","ok":false,"extra":"drop"}'),
        )
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_stateful": False,
                "input": "return strict structured output",
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "result",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string", "const": "DIDI-TEST-STRUCT"},
                                "ok": {"type": "boolean", "const": True},
                            },
                            "required": ["code", "ok"],
                            "additionalProperties": False,
                        },
                    }
                },
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(json.loads(payload["output_text"]), {"code": "DIDI-TEST-STRUCT", "ok": True})

    def test_responses_rejects_inline_pdf_before_backend(self) -> None:
        client, fake_codex = self._codex_client()
        pdf_data = base64.b64encode(b"%PDF-1.4\nnot a real pdf").decode("ascii")
        for prefix in (
            "data:application/pdf;base64,",
            "data:APPLICATION/PDF;name=sample.pdf;base64,",
            "data:application/pdf,",
        ):
            with self.subTest(prefix=prefix):
                response = client.post(
                    "/v1/responses",
                    headers={"Authorization": "Bearer coder-key"},
                    json={
                        "model": "gpt-5.5",
                        "gateway_stateful": False,
                        "input": [
                            {
                                "role": "user",
                                "content": [
                                    {"type": "input_text", "text": "summarize"},
                                    {
                                        "type": "input_file",
                                        "filename": "sample.pdf",
                                        "file_data": prefix + pdf_data,
                                    },
                                ],
                            }
                        ],
                    },
                )
                self.assertEqual(response.status_code, 422)
                self.assertIn("inline PDF extraction is disabled", response.json()["detail"])
        self.assertEqual(fake_codex.requests, [])

    def test_codex_stream_returns_sse_chunks(self) -> None:
        client, _ = self._codex_client()
        with client.stream(
            "POST",
            "/v1/chat/completions",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "child-model",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "task-1",
                "gateway_session_id": "stream",
                "stream": True,
                "messages": [{"role": "user", "content": "say ok"}],
            },
        ) as response:
            text = response.read().decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("chat.completion.chunk", text)
        self.assertIn("codex ok", text)
        self.assertIn("[DONE]", text)

    def test_unsupported_codex_endpoints_return_openai_style_error(self) -> None:
        client, _ = self._codex_client()
        response = client.post(
            "/v1/embeddings",
            headers={"Authorization": "Bearer coder-key"},
            json={"model": "text-embedding-3-small", "input": "hello"},
        )
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertEqual(payload["error"]["type"], "invalid_request_error")
        self.assertEqual(payload["error"]["code"], "unsupported")

    def test_models_returns_public_model_id_for_codex_backend(self) -> None:
        client, _ = self._codex_client()
        response = client.get("/v1/models")
        self.assertEqual(response.status_code, 200)
        model_ids = [item["id"] for item in response.json()["data"]]
        self.assertEqual(model_ids, ["gpt-5.5"])

    def test_codex_app_server_backend_is_selected(self) -> None:
        client, fake_codex = self._codex_client(backend="codex_app_server")
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "task-1",
                "gateway_session_id": "app-server",
                "messages": [{"role": "user", "content": "change code"}],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["choices"][0]["message"]["content"], "codex ok")
        self.assertEqual(payload["model"], "gpt-5.5")
        self.assertEqual(fake_codex.requests[0]["model"], "gpt-5.5")

    def test_codex_app_server_uses_large_stdout_limit(self) -> None:
        with patch("gateway.codex_app_backend.asyncio.create_subprocess_exec") as create_process:
            create_process.side_effect = RuntimeError("stop before process IO")
            backend = CodexAppServerBackend(
                command="codex",
                codex_home=".",
                workdir=".",
                sandbox="workspace-write",
                timeout_seconds=1,
            )
            with self.assertRaises(RuntimeError):
                self._run(backend._run_turn(prompt="hello", model="gpt-5.5"))

        self.assertEqual(create_process.call_args.kwargs["limit"], 8 * 1024 * 1024)

    def test_codex_cli_reader_rejects_oversized_output(self) -> None:
        async def scenario() -> None:
            import asyncio

            reader = asyncio.StreamReader()
            reader.feed_data(b"12345")
            reader.feed_eof()
            with self.assertRaisesRegex(_ProcessOutputLimitError, "stdout exceeded 4 bytes"):
                await _read_bounded_stream(reader, 4, "stdout")

        self._run(scenario())

    def test_codex_process_limiter_is_shared_and_fails_fast(self) -> None:
        limiter = CodexProcessLimiter(maximum=1)
        cli_backend = CodexCliBackend(
            command="codex",
            codex_home=".",
            workdir=".",
            sandbox="workspace-write",
            timeout_seconds=1,
            process_limiter=limiter,
        )
        app_backend = CodexAppServerBackend(
            command="codex",
            codex_home=".",
            workdir=".",
            sandbox="workspace-write",
            timeout_seconds=1,
            process_limiter=limiter,
        )
        self.assertIs(cli_backend.process_limiter, app_backend.process_limiter)

        permit = limiter.acquire()
        self.assertEqual(limiter.active, 1)
        with self.assertRaisesRegex(RuntimeError, "concurrency limit reached"):
            app_backend.process_limiter.acquire()
        permit.release()
        permit.release()
        self.assertEqual(limiter.active, 0)

    def test_codex_cli_cancellation_stops_process_and_releases_slot(self) -> None:
        async def scenario() -> None:
            import asyncio

            class FakeStdin:
                def write(self, _data: bytes) -> None:
                    pass

                async def drain(self) -> None:
                    pass

                def close(self) -> None:
                    pass

            class FakeProcess:
                def __init__(self) -> None:
                    self.pid = None
                    self.returncode = None
                    self.stdin = FakeStdin()
                    self.stdout = asyncio.StreamReader()
                    self.stderr = asyncio.StreamReader()
                    self.killed = False
                    self._finished = asyncio.Event()

                def kill(self) -> None:
                    if self.returncode is not None:
                        return
                    self.killed = True
                    self.returncode = -9
                    self.stdout.feed_eof()
                    self.stderr.feed_eof()
                    self._finished.set()

                def terminate(self) -> None:
                    self.kill()

                async def wait(self) -> int:
                    await self._finished.wait()
                    return self.returncode

            limiter = CodexProcessLimiter(maximum=1)
            backend = CodexCliBackend(
                command="codex",
                codex_home=".",
                workdir=".",
                sandbox="workspace-write",
                timeout_seconds=10,
                process_limiter=limiter,
            )
            process = FakeProcess()
            with patch(
                "gateway.codex_backend.asyncio.create_subprocess_exec",
                return_value=process,
            ) as create_process:
                task = asyncio.create_task(backend._exec(prompt="hello", model="codex-cli"))
                for _ in range(20):
                    if create_process.await_count:
                        break
                    await asyncio.sleep(0)
                self.assertEqual(limiter.active, 1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

            self.assertTrue(process.killed)
            self.assertEqual(limiter.active, 0)
            if os.name == "posix":
                self.assertTrue(create_process.call_args.kwargs["start_new_session"])

        self._run(scenario())

    def test_codex_app_server_close_survives_caller_cancellation(self) -> None:
        async def scenario() -> None:
            import asyncio

            class FakeProcess:
                def __init__(self) -> None:
                    self.pid = None
                    self.returncode = None
                    self.stdin = None
                    self.stdout = None
                    self.stderr = None
                    self.terminate_called = asyncio.Event()
                    self._finished = asyncio.Event()

                def terminate(self) -> None:
                    self.terminate_called.set()

                def kill(self) -> None:
                    self.returncode = -9
                    self._finished.set()

                async def wait(self) -> int:
                    await self._finished.wait()
                    return self.returncode

                def finish(self) -> None:
                    self.returncode = -15
                    self._finished.set()

            limiter = CodexProcessLimiter(maximum=1)
            permit = limiter.acquire()
            process = FakeProcess()
            client = _JsonRpcClient(process, process_permit=permit)
            close_task = asyncio.create_task(client.close())
            await process.terminate_called.wait()
            close_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await close_task
            process.finish()
            for _ in range(20):
                if limiter.active == 0:
                    break
                await asyncio.sleep(0)

            self.assertEqual(limiter.active, 0)
            self.assertTrue(client._closed)

        self._run(scenario())

    def test_codex_cancellation_during_spawn_tracks_and_stops_late_process(self) -> None:
        async def scenario() -> None:
            import asyncio

            class FakeProcess:
                def __init__(self) -> None:
                    self.pid = None
                    self.returncode = None
                    self.killed = False
                    self._finished = asyncio.Event()

                def kill(self) -> None:
                    self.killed = True
                    self.returncode = -9
                    self._finished.set()

                def terminate(self) -> None:
                    self.kill()

                async def wait(self) -> int:
                    await self._finished.wait()
                    return self.returncode

            spawn_started = asyncio.Event()
            release_spawn = asyncio.Event()
            process = FakeProcess()

            async def slow_spawn(*_args: Any, **_kwargs: Any) -> FakeProcess:
                spawn_started.set()
                await release_spawn.wait()
                return process

            limiter = CodexProcessLimiter(maximum=1)
            backend = CodexCliBackend(
                command="codex",
                codex_home=".",
                workdir=".",
                sandbox="workspace-write",
                timeout_seconds=10,
                process_limiter=limiter,
            )
            with patch(
                "gateway.codex_backend.asyncio.create_subprocess_exec",
                side_effect=slow_spawn,
            ):
                task = asyncio.create_task(backend._exec(prompt="hello", model="codex-cli"))
                await spawn_started.wait()
                task.cancel()
                await asyncio.sleep(0)
                self.assertEqual(limiter.active, 1)
                self.assertFalse(process.killed)
                release_spawn.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task

            self.assertTrue(process.killed)
            self.assertEqual(limiter.active, 0)

        self._run(scenario())

    def test_codex_pending_turn_cancellation_closes_client(self) -> None:
        async def scenario() -> None:
            import asyncio

            class BlockingPendingClient(FakePendingToolClient):
                def __init__(self) -> None:
                    super().__init__()
                    self.read_started = asyncio.Event()
                    self._never = asyncio.Event()

                async def read_turn_until_stop(
                    self,
                    thread_id: str,
                    turn_id: str,
                ) -> AppTurnResult:
                    self.read_started.set()
                    await self._never.wait()
                    raise AssertionError("unreachable")

            backend = CodexAppServerBackend(
                command="codex",
                codex_home=".",
                workdir=".",
                sandbox="workspace-write",
                timeout_seconds=10,
            )
            client = BlockingPendingClient()
            backend._pending["response-1"] = PendingToolTurn(
                client,
                "thread-1",
                "turn-1",
                1,
                {},
                "model",
                {},
            )
            task = asyncio.create_task(backend._continue_pending_tool_turn(
                body={"previous_response_id": "response-1"},
                public_model="model",
                tool_outputs=[{"output": "done"}],
            ))
            await client.read_started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            self.assertTrue(client.closed)
            self.assertNotIn("response-1", backend._pending)

        self._run(scenario())

    def test_codex_app_server_bounds_cumulative_events_and_stderr_retention(self) -> None:
        async def scenario() -> None:
            import asyncio
            from types import SimpleNamespace

            first = b'{"jsonrpc":"2.0","id":1,"result":{}}\n'
            second = b'{"jsonrpc":"2.0","id":2,"result":{}}\n'
            stdout = asyncio.StreamReader()
            stderr = asyncio.StreamReader()
            stdout.feed_data(first + second)
            stdout.feed_eof()
            stderr.feed_data(b"diagnostic")
            stderr.feed_eof()
            process = SimpleNamespace(
                stdin=None,
                stdout=stdout,
                stderr=stderr,
                returncode=0,
            )
            client = _JsonRpcClient(
                process,
                stdout_max_bytes=len(first),
                stderr_retain_bytes=4,
                max_messages=10,
            )
            self.assertEqual((await client._read())["id"], 1)
            with self.assertRaisesRegex(RuntimeError, "cumulative stdout exceeded"):
                await client._read()
            await client.close()
            self.assertEqual(bytes(client._stderr), b"diag")
            self.assertTrue(client._stderr_truncated)

            stdout = asyncio.StreamReader()
            stdout.feed_data(first + second)
            stdout.feed_eof()
            process = SimpleNamespace(
                stdin=None,
                stdout=stdout,
                stderr=None,
                returncode=0,
            )
            client = _JsonRpcClient(
                process,
                stdout_max_bytes=len(first + second),
                stderr_retain_bytes=4,
                max_messages=1,
            )
            await client._read()
            with self.assertRaisesRegex(RuntimeError, "exceeded 1 messages"):
                await client._read()
            await client.close()

        self._run(scenario())

    def test_codex_app_server_bounds_pending_tool_processes(self) -> None:
        async def scenario() -> None:
            backend = CodexAppServerBackend(
                command="codex",
                codex_home=".",
                workdir=".",
                sandbox="workspace-write",
                timeout_seconds=1,
            )
            backend.max_pending_turns = 1
            backend.pending_ttl_seconds = 60
            first_client = FakePendingToolClient()
            first = PendingToolTurn(first_client, "thread-1", "turn-1", 1, {}, "model", {})
            await backend._register_pending("response-1", first)

            second_client = FakePendingToolClient()
            second = PendingToolTurn(second_client, "thread-2", "turn-2", 2, {}, "model", {})
            with self.assertRaisesRegex(RuntimeError, "reached 1 pending tool turns"):
                await backend._register_pending("response-2", second)

            self.assertTrue(second_client.closed)
            self.assertFalse(first_client.closed)
            self.assertEqual(list(backend._pending), ["response-1"])
            backend._pending.pop("response-1")
            await backend._cancel_pending_expiry(first)
            await first_client.close()

        self._run(scenario())

    def test_codex_app_server_expires_abandoned_tool_process(self) -> None:
        async def scenario() -> None:
            import asyncio

            backend = CodexAppServerBackend(
                command="codex",
                codex_home=".",
                workdir=".",
                sandbox="workspace-write",
                timeout_seconds=1,
            )
            backend.pending_ttl_seconds = 0.01
            client = FakePendingToolClient()
            pending = PendingToolTurn(client, "thread-1", "turn-1", 1, {}, "model", {})
            await backend._register_pending("response-1", pending)
            for _ in range(20):
                if client.closed:
                    break
                await asyncio.sleep(0.01)

            self.assertTrue(client.closed)
            self.assertNotIn("response-1", backend._pending)

        self._run(scenario())

    def test_codex_process_limits_have_hard_configuration_caps(self) -> None:
        with patch.dict(
            os.environ,
            {"CODEX_MAX_CONCURRENT_PROCESSES": "65"},
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "must not exceed 64"):
                CodexProcessLimiter()

        with patch.dict(
            os.environ,
            {"CODEX_APP_SERVER_MAX_PENDING_TURNS": "65"},
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "must not exceed 64"):
                CodexAppServerBackend(
                    command="codex",
                    codex_home=".",
                    workdir=".",
                    sandbox="workspace-write",
                    timeout_seconds=1,
                )

        with self.assertRaisesRegex(ValueError, "must not exceed 3600"):
            CodexCliBackend(
                command="codex",
                codex_home=".",
                workdir=".",
                sandbox="workspace-write",
                timeout_seconds=3601,
            )

    def test_codex_app_server_bridges_responses_function_tool_turn(self) -> None:
        fake_codex = PendingToolCodexAppBackend()
        client, _ = self._codex_client(
            backend="codex_app_server",
            codex_backend=fake_codex,
        )

        first = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_stateful": False,
                "input": "Use lookup for the weather.",
                "tools": [
                    {
                        "type": "function",
                        "name": "lookup",
                        "description": "Lookup data.",
                        "parameters": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                            "required": ["query"],
                        },
                    }
                ],
            },
        )

        self.assertEqual(first.status_code, 200)
        first_payload = first.json()
        self.assertEqual(first_payload["output"][0]["type"], "function_call")
        self.assertEqual(first_payload["output"][0]["name"], "lookup")
        self.assertEqual(first_payload["output"][0]["call_id"], "call_lookup")
        self.assertEqual(
            json.loads(first_payload["output"][0]["arguments"]),
            {"query": "weather"},
        )
        self.assertEqual(fake_codex.requests[0]["tools"][0]["name"], "lookup")

        second = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_stateful": False,
                "previous_response_id": first_payload["id"],
                "input": [
                    {
                        "type": "function_call_output",
                        "call_id": "call_lookup",
                        "output": "sunny",
                    }
                ],
            },
        )

        self.assertEqual(second.status_code, 200)
        second_payload = second.json()
        self.assertEqual(second_payload["output_text"], "Final answer after lookup")
        self.assertEqual(fake_codex.fake_client.responses[0]["request_id"], 99)
        self.assertEqual(
            fake_codex.fake_client.responses[0]["result"]["contentItems"],
            [{"type": "inputText", "text": "sunny"}],
        )
        self.assertEqual(fake_codex.fake_client.closed, True)

    def test_codex_orchestrator_routes_to_child_agent_and_returns_final(self) -> None:
        client, fake_codex = self._codex_client(
            orchestrates=True,
            codex_backend=SequencedCodexBackend(
                [
                    json.dumps(
                        {
                            "action": "call_agent",
                            "target_agent": "planner",
                            "input": "Plan the login change.",
                            "session_id": "plan-1",
                        }
                    ),
                    "Planner result",
                    json.dumps(
                        {
                            "action": "final",
                            "final": "Use the planner result.",
                        }
                    ),
                ]
            ),
        )
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "task-1",
                "gateway_session_id": "orchestrate",
                "gateway_metadata": {"include_orchestration_trace": True},
                "messages": [{"role": "user", "content": "Add login rate limits"}],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["choices"][0]["message"]["content"], "Use the planner result.")
        self.assertEqual(payload["gateway_orchestration"]["enabled"], True)
        self.assertEqual(payload["gateway_orchestration"]["trace"][0]["target_agent"], "planner")
        self.assertEqual(len(fake_codex.requests), 3)
        self.assertIn("center Codex orchestrator", fake_codex.requests[0]["messages"][0]["content"])
        self.assertIn("Planner prompt", fake_codex.requests[1]["messages"][0]["content"])
        self.assertIn("Child agent result received", fake_codex.requests[2]["messages"][-1]["content"])

    def test_codex_orchestrator_falls_back_to_raw_answer_on_invalid_json(self) -> None:
        client, _ = self._codex_client(
            orchestrates=True,
            codex_backend=SequencedCodexBackend(["plain answer"]),
        )
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "task-1",
                "gateway_session_id": "orchestrate",
                "gateway_metadata": {"include_orchestration_trace": True},
                "messages": [{"role": "user", "content": "Explain this task"}],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["choices"][0]["message"]["content"], "plain answer")
        self.assertEqual(payload["gateway_orchestration"]["trace"][0]["action"], "fallback_final")

    def test_codex_fast_probe_skips_codex_for_minimal_chat(self) -> None:
        client, fake_codex = self._codex_client(
            orchestrates=True,
            codex_backend=SequencedCodexBackend(["should not be used"]),
        )
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "connectivity",
                "gateway_session_id": "probe",
                "gateway_stateful": False,
                "messages": [{"role": "user", "content": "hi"}],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["choices"][0]["message"]["content"], "hi")
        self.assertEqual(payload["model"], "gpt-5.5")
        self.assertEqual(fake_codex.requests, [])

    def test_codex_fast_probe_skips_codex_for_minimal_response(self) -> None:
        client, fake_codex = self._codex_client(
            orchestrates=True,
            codex_backend=SequencedCodexBackend(["should not be used"]),
        )
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "connectivity",
                "gateway_session_id": "probe",
                "gateway_stateful": False,
                "input": "ping",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["output_text"], "ok")
        self.assertEqual(payload["model"], "gpt-5.5")
        self.assertEqual(fake_codex.requests, [])

    def test_codex_orchestrator_bypasses_for_tool_probe(self) -> None:
        client, fake_codex = self._codex_client(
            orchestrates=True,
            codex_backend=StaticCodexBackend("lookup value"),
        )
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "tool-probe",
                "gateway_session_id": "tool-probe",
                "gateway_stateful": False,
                "messages": [{"role": "user", "content": "use the tool"}],
                "tool_choice": "required",
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "parameters": {
                                "type": "object",
                                "properties": {"query": {"type": "string"}},
                                "required": ["query"],
                            },
                        },
                    }
                ],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("gateway_orchestration", payload)
        self.assertEqual(payload["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(
            payload["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "lookup",
        )
        self.assertEqual(fake_codex.requests, [])

    def test_codex_orchestrator_bypasses_for_json_schema_probe(self) -> None:
        client, fake_codex = self._codex_client(
            orchestrates=True,
            codex_backend=StaticCodexBackend("done"),
        )
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_user_id": "user-a",
                "gateway_workspace_id": "repo-a",
                "gateway_task_id": "json-probe",
                "gateway_session_id": "json-probe",
                "gateway_stateful": False,
                "messages": [{"role": "user", "content": "return json"}],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "result",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "status": {"type": "string"},
                                "count": {"type": "integer"},
                            },
                            "required": ["status", "count"],
                        },
                    },
                },
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("gateway_orchestration", payload)
        self.assertEqual(
            json.loads(payload["choices"][0]["message"]["content"]),
            {"status": "ok", "count": 0},
        )
        self.assertEqual(fake_codex.requests, [])

    def test_tool_call_payload_is_openai_compatible(self) -> None:
        payload = tool_call_payload(
            model="gpt-5.5",
            body={
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "parameters": {
                                "type": "object",
                                "properties": {"query": {"type": "string"}},
                            },
                        },
                    }
                ]
            },
            content="weather",
        )
        message = payload["choices"][0]["message"]
        self.assertEqual(payload["model"], "gpt-5.5")
        self.assertEqual(payload["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(message["tool_calls"][0]["function"]["name"], "lookup")

    def test_chat_tool_choice_required_returns_function_call(self) -> None:
        backend = StaticCodexBackend("run lookup")
        response = self._run(
            backend.chat_completion(
                {
                    "model": "gpt-5.5",
                    "messages": [{"role": "user", "content": "hello"}],
                    "tool_choice": "required",
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": "lookup",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"query": {"type": "string"}},
                                    "required": ["query"],
                                },
                            },
                        }
                    ],
                }
            )
        )

        message = response["choices"][0]["message"]
        self.assertEqual(response["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(message["tool_calls"][0]["function"]["name"], "lookup")
        self.assertEqual(
            json.loads(message["tool_calls"][0]["function"]["arguments"]),
            {"query": "run lookup"},
        )

    def test_chat_json_schema_response_format_returns_schema_json(self) -> None:
        backend = StaticCodexBackend("done")
        response = self._run(
            backend.chat_completion(
                {
                    "model": "gpt-5.5",
                    "messages": [{"role": "user", "content": "return json"}],
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "result",
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {"type": "string"},
                                    "count": {"type": "integer"},
                                    "ok": {"type": "boolean"},
                                },
                                "required": ["status", "count", "ok"],
                            },
                        },
                    },
                }
            )
        )

        content = response["choices"][0]["message"]["content"]
        self.assertEqual(
            json.loads(content),
            {"status": "done", "count": 0, "ok": True},
        )

    def test_chat_json_schema_response_format_respects_const_and_additional_properties(self) -> None:
        backend = StaticCodexBackend('{"code":"wrong","ok":false,"extra":"drop"}')
        response = self._run(
            backend.chat_completion(
                {
                    "model": "gpt-5.5",
                    "messages": [{"role": "user", "content": "return strict json"}],
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "result",
                            "strict": True,
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "code": {"type": "string", "const": "DIDI-TEST-STRUCT"},
                                    "ok": {"type": "boolean", "const": True},
                                },
                                "required": ["code", "ok"],
                                "additionalProperties": False,
                            },
                        },
                    },
                }
            )
        )

        content = response["choices"][0]["message"]["content"]
        self.assertEqual(json.loads(content), {"code": "DIDI-TEST-STRUCT", "ok": True})

    def test_response_tool_choice_uses_selected_function(self) -> None:
        backend = StaticCodexBackend("forecast")
        response = self._run(
            backend.response(
                {
                    "model": "gpt-5.5",
                    "input": "call weather",
                    "tool_choice": {
                        "type": "function",
                        "function": {"name": "weather"},
                    },
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": "search",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"query": {"type": "string"}},
                                },
                            },
                        },
                        {
                            "type": "function",
                            "function": {
                                "name": "weather",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"location": {"type": "string"}},
                                    "required": ["location"],
                                },
                            },
                        },
                    ],
                }
            )
        )

        output = response["output"][0]
        self.assertEqual(output["type"], "function_call")
        self.assertEqual(output["name"], "weather")
        self.assertEqual(json.loads(output["arguments"]), {"location": "forecast"})

    def test_response_payload_includes_responses_api_fields(self) -> None:
        payload = response_payload(
            model="gpt-5.5",
            content="ok",
            body={
                "tools": [{"type": "function", "function": {"name": "lookup"}}],
                "tool_choice": "auto",
                "text": {"format": {"type": "text"}},
                "metadata": {"task": "test"},
            },
        )
        self.assertEqual(payload["object"], "response")
        self.assertEqual(payload["output_text"], "ok")
        self.assertGreater(payload["usage"]["total_tokens"], 0)
        self.assertEqual(payload["tools"][0]["function"]["name"], "lookup")
        self.assertEqual(payload["tool_choice"], "auto")
        self.assertEqual(payload["metadata"], {"task": "test"})

    def test_response_payload_does_not_synthesize_web_search_call(self) -> None:
        payload = response_payload(
            model="gpt-5.5",
            content="Result source: https://example.com/result",
            body={"tools": [{"type": "web_search"}]},
        )

        self.assertEqual(payload["output"][0]["type"], "message")
        self.assertEqual(payload["output"][0]["content"][0]["annotations"], [])
        self.assertEqual(payload["tools"], [])

    def test_response_payload_passes_through_real_web_search_call(self) -> None:
        payload = response_payload(
            model="gpt-5.5",
            content="Search result",
            body={"tools": [{"type": "web_search"}]},
            output_items=[
                {
                    "id": "ws_real",
                    "type": "web_search_call",
                    "status": "completed",
                    "action": {"type": "search", "query": "BTC price"},
                }
            ],
        )

        self.assertEqual(payload["output"][0]["type"], "web_search_call")
        self.assertEqual(payload["output"][0]["id"], "ws_real")
        self.assertEqual(payload["output"][1]["type"], "message")
        self.assertEqual(payload["tools"], [{"type": "web_search"}])

    def test_response_payload_skips_web_search_call_for_plain_chat(self) -> None:
        payload = response_payload(
            model="gpt-5.5",
            content="你好。",
            body={"input": "你好", "tools": [{"type": "web_search_preview"}]},
        )

        self.assertEqual(payload["output"][0]["type"], "message")
        self.assertEqual(payload["output_text"], "你好。")
        self.assertEqual(payload["tools"], [])

    def test_response_payload_does_not_infer_web_search_from_original_input(self) -> None:
        payload = response_payload(
            model="gpt-5.5",
            content="你好。",
            body={
                "input": [
                    {"role": "system", "content": "Gateway supports web search."},
                    {"role": "user", "content": "search the web for old context"},
                    {"role": "user", "content": "你好"},
                ],
                "tools": [{"type": "web_search_preview"}],
            },
        )

        self.assertEqual(payload["output"][0]["type"], "message")
        self.assertEqual(payload["tools"], [])

    def test_responses_web_search_preview_tool_is_not_synthesized_by_cli_backend(self) -> None:
        client, _ = self._codex_client(codex_backend=StaticCodexBackend("Search result"))
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_stateful": False,
                "input": "search the web",
                "tools": [{"type": "web_search_preview"}],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["output"][0]["type"], "message")
        self.assertEqual(payload["tools"], [])
        self.assertEqual(payload["output_text"], "Search result")

    def test_codex_app_server_web_search_preview_tool_passes_through_real_search_call(self) -> None:
        fake_codex = HostedSearchCodexAppBackend()
        client, _ = self._codex_client(
            backend="codex_app_server",
            codex_backend=fake_codex,
        )
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer coder-key"},
            json={
                "model": "gpt-5.5",
                "gateway_stateful": False,
                "input": "search the web",
                "tools": [{"type": "web_search_preview"}],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["output"][0]["type"], "web_search_call")
        self.assertEqual(payload["output"][0]["id"], "ws_real")
        self.assertEqual(payload["output"][0]["action"], {"type": "search", "query": "search the web"})
        self.assertEqual(payload["output_text"], "Search result")

    def test_codex_app_server_maps_hosted_web_search_to_thread_config(self) -> None:
        config = _hosted_tools_config(
            [
                {
                    "type": "web_search_preview",
                    "search_context_size": "high",
                    "allowed_domains": ["example.com"],
                    "user_location": {
                        "city": "New York",
                        "country": "US",
                        "ignored": "drop",
                    },
                }
            ]
        )

        self.assertEqual(
            config,
            {
                "web_search": "live",
                "tools": {
                    "web_search": {
                        "context_size": "high",
                        "allowed_domains": ["example.com"],
                        "location": {"city": "New York", "country": "US"},
                    }
                },
            },
        )

    def test_codex_app_server_dynamic_tools_ignore_hosted_web_search(self) -> None:
        dynamic_tools = _dynamic_tools(
            [
                {"type": "web_search"},
                {
                    "type": "function",
                    "name": "lookup",
                    "parameters": {"type": "object", "properties": {}},
                },
            ]
        )

        self.assertEqual(len(dynamic_tools or []), 1)
        self.assertEqual(dynamic_tools[0]["name"], "lookup")

    def test_chat_payload_uses_public_model(self) -> None:
        payload = chat_completion_payload(model="gpt-5.5", content="ok")
        self.assertEqual(payload["model"], "gpt-5.5")

    def test_gateway_request_concurrency_limit_rejects_before_dispatch(self) -> None:
        async def scenario() -> None:
            import asyncio

            started = asyncio.Event()
            release = asyncio.Event()
            dispatched = 0

            async def downstream(scope: Any, receive: Any, send: Any) -> None:
                nonlocal dispatched
                dispatched += 1
                started.set()
                await release.wait()
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"ok"})

            middleware = BoundedASGIConcurrencyMiddleware(downstream, maximum=1)
            scope = {"type": "http", "method": "GET", "path": "/health", "headers": []}

            async def receive() -> dict[str, Any]:
                return {"type": "http.request", "body": b"", "more_body": False}

            first_messages: list[dict[str, Any]] = []
            rejected_messages: list[dict[str, Any]] = []

            async def send_first(message: dict[str, Any]) -> None:
                first_messages.append(message)

            async def send_rejected(message: dict[str, Any]) -> None:
                rejected_messages.append(message)

            first = asyncio.create_task(middleware(scope, receive, send_first))
            await started.wait()
            await middleware(scope, receive, send_rejected)

            self.assertEqual(dispatched, 1)
            self.assertEqual(rejected_messages[0]["status"], 503)
            self.assertIn(b"concurrency limit reached", rejected_messages[1]["body"])

            release.set()
            await first
            self.assertEqual(first_messages[0]["status"], 200)

        self._run(scenario())

        with self.assertRaisesRegex(ValueError, "between 1 and 4096"):
            BoundedASGIConcurrencyMiddleware(
                object(),
                maximum=MAX_SERVER_CONNECTIONS + 1,
            )

    def test_gateway_concurrency_limit_wraps_request_body_buffer(self) -> None:
        self._codex_client()
        main = importlib.import_module("gateway.main")
        self.assertIs(
            main.app.user_middleware[0].cls,
            BoundedASGIConcurrencyMiddleware,
        )

    def test_request_body_deadline_rejects_slow_clients(self) -> None:
        async def scenario() -> None:
            import asyncio

            async def downstream(_scope: Any, _receive: Any, _send: Any) -> None:
                raise AssertionError("slow request must not reach downstream")

            async def receive() -> dict[str, Any]:
                await asyncio.Event().wait()
                raise AssertionError("unreachable")

            messages: list[dict[str, Any]] = []

            async def send(message: dict[str, Any]) -> None:
                messages.append(message)

            middleware = BoundedRequestBodyMiddleware(
                downstream,
                limit=1024,
                timeout_seconds=0.01,
            )
            await middleware(
                {"type": "http", "method": "POST", "path": "/", "headers": []},
                receive,
                send,
            )
            self.assertEqual(messages[0]["status"], 408)
            self.assertIn(b"deadline exceeded", messages[1]["body"])

        self._run(scenario())

    def test_uvicorn_runtime_limits_are_bounded(self) -> None:
        env = {
            "TEST_UVICORN_LIMIT_CONCURRENCY": "32",
            "TEST_UVICORN_KEEP_ALIVE_SECONDS": "7",
            "TEST_UVICORN_H11_MAX_INCOMPLETE_EVENT_BYTES": "32768",
        }
        with patch.dict(os.environ, env, clear=True):
            args = uvicorn_limit_args(env_prefix="TEST", default_concurrency=128)
        self.assertEqual(
            args,
            [
                "--limit-concurrency",
                "32",
                "--timeout-keep-alive",
                "7",
                "--h11-max-incomplete-event-size",
                "32768",
            ],
        )
        with patch.dict(os.environ, {"TEST_UVICORN_KEEP_ALIVE_SECONDS": "301"}, clear=True):
            with self.assertRaisesRegex(ValueError, "between 1 and 300"):
                uvicorn_limit_args(env_prefix="TEST", default_concurrency=128)

    def test_primary_inference_routes_enforce_bounded_object_json(self) -> None:
        from dataclasses import replace

        client, backend = self._codex_client()
        main = importlib.import_module("gateway.main")
        headers = {"Authorization": "Bearer coder-key", "Content-Type": "application/json"}
        with patch.object(main, "config", replace(main.config, max_request_bytes=64)):
            for path in ("/v1/chat/completions", "/v1/responses"):
                with self.subTest(path=path, case="oversized"):
                    response = client.post(path, headers=headers, content=json.dumps({"input": "x" * 128}))
                    self.assertEqual(response.status_code, 413)
                with self.subTest(path=path, case="malformed"):
                    response = client.post(path, headers=headers, content=b"{not-json")
                    self.assertEqual(response.status_code, 400)
                    self.assertIn("valid JSON", response.json()["detail"])
                with self.subTest(path=path, case="non-object"):
                    response = client.post(path, headers=headers, content=b"[]")
                    self.assertEqual(response.status_code, 400)
                    self.assertIn("JSON object", response.json()["detail"])
        self.assertEqual(backend.requests, [])

    def test_global_body_limit_covers_auto_parsed_and_chunked_routes(self) -> None:
        from dataclasses import replace

        client, _ = self._codex_client()
        main = importlib.import_module("gateway.main")
        with patch.object(main, "config", replace(main.config, max_request_bytes=64)):
            auto_parsed = client.post(
                "/auth/login",
                headers={"Content-Type": "application/json"},
                content=json.dumps({"username": "x" * 128, "password": "p"}),
            )
            self.assertEqual(auto_parsed.status_code, 413)

            def chunks():
                yield b'{"username":"'
                yield b"x" * 128
                yield b'","password":"p"}'

            chunked = client.post(
                "/auth/login",
                headers={"Content-Type": "application/json"},
                content=chunks(),
            )
            self.assertEqual(chunked.status_code, 413)

            invalid_length = client.post(
                "/auth/login",
                headers={"Content-Type": "application/json", "Content-Length": "-1"},
                content=b"{}",
            )
            self.assertEqual(invalid_length.status_code, 400)

        with patch.object(main, "config", replace(main.config, max_request_bytes=256 * 1024 * 1024 + 1)):
            invalid_limit = client.post(
                "/auth/login",
                headers={"Content-Type": "application/json"},
                content=b"{}",
            )
            self.assertEqual(invalid_limit.status_code, 503)

    def _run(self, awaitable):
        import asyncio

        return asyncio.run(awaitable)

    def _codex_client(
        self,
        orchestrates: bool = False,
        codex_backend: Any | None = None,
        backend: str = "codex_cli",
    ):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tmp_path = Path(tmp.name)
        coder_agent: dict[str, Any] = {
            "keys": ["coder-key"],
            "role": "coder",
            "description": "Center coder agent.",
        }
        if orchestrates:
            coder_agent["orchestrates"] = True
        agents_file = tmp_path / "agents.json"
        agents_file.write_text(
            json.dumps(
                {
                    "agents": {
                        "planner": {
                            "keys": ["planner-key"],
                            "role": "planner",
                            "description": "Plan code tasks.",
                            "system_prompt": "Planner prompt",
                        },
                        "coder": coder_agent,
                    }
                }
            ),
            encoding="utf-8",
        )
        env = {
            **os.environ,
            "AGENTS_FILE": str(agents_file),
            "SESSION_DB": str(tmp_path / "sessions.sqlite3"),
            "GATEWAY_BACKEND": backend,
            "CENTER_MODEL": "",
            "PUBLIC_MODEL_ID": "gpt-5.5",
            "CODEX_INTERNAL_MODEL": "gpt-5.5",
        }
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        main = importlib.import_module("gateway.main")
        main = importlib.reload(main)
        fake_codex = codex_backend or FakeCodexBackend()
        if backend == "codex_app_server":
            main.codex_app_backend = fake_codex
        else:
            main.codex_backend = fake_codex
        return TestClient(main.app), fake_codex


class StaticCodexBackend(CodexCliBackend):
    def __init__(self, output: str) -> None:
        super().__init__(
            command="codex",
            codex_home=".",
            workdir=".",
            sandbox="workspace-write",
            timeout_seconds=1,
        )
        self.output = output
        self.requests: list[dict[str, Any]] = []

    async def _exec(self, prompt: str, model: str) -> str:
        self.requests.append({"prompt": prompt, "model": model})
        return self.output


if __name__ == "__main__":
    unittest.main()
