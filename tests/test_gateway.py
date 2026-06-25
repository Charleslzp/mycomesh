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
    chat_completion_payload,
    response_payload,
    tool_call_payload,
)
from gateway.codex_app_backend import (
    AppTurnResult,
    CodexAppServerBackend,
    _dynamic_tools,
    _hosted_tools_config,
)


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


class FakeResponse:
    status_code = 200
    headers = {"content-type": "application/json"}

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.content = b""

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

            sessions = client.get("/gateway/sessions").json()["data"]
            self.assertEqual(sessions[0]["user_id"], "user-a")
            self.assertEqual(sessions[0]["workspace_id"], "repo-a")
            self.assertEqual(sessions[0]["task_id"], "task-1")
            self.assertEqual(sessions[0]["agent_id"], "planner")
            self.assertEqual(sessions[0]["session_id"], "planning")

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

    def test_responses_input_file_pdf_is_normalized_before_backend(self) -> None:
        client, fake_codex = self._codex_client()
        pdf_data = base64.b64encode(b"%PDF-1.4\nnot a real pdf").decode("ascii")
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
                                "file_data": f"data:application/pdf;base64,{pdf_data}",
                            },
                        ],
                    }
                ],
            },
        )
        self.assertEqual(response.status_code, 200)
        backend_input = fake_codex.requests[0]["input"][1]["content"]
        self.assertIn("PDF file: sample.pdf", json.dumps(backend_input))
        self.assertNotIn("input_file", json.dumps(backend_input))

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
