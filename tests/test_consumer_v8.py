from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from gateway.consumer_v8 import (
    ConsumerV8Config,
    ConsumerV8State,
    _build_relay_payment,
    _consumer_html_page,
    _proxy_inference,
    _relay_inference_result,
    _stream_response,
    create_app,
)
from gateway.relay import RelayError, RelayState, _v7_normalize_request, _v7_payment_header


class ConsumerV8Tests(unittest.TestCase):
    def test_codex_protocol_aliases_are_registered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("https://relay.example",))
            )
            app = create_app(state)

        http_routes = {
            (route.path, method)
            for route in app.routes
            for method in (getattr(route, "methods", None) or set())
        }
        websocket_routes = {
            route.path for route in app.routes if route.__class__.__name__ == "APIWebSocketRoute"
        }
        for path in (
            "/responses",
            "/v1/responses",
            "/backend-api/codex/responses",
            "/responses/compact",
            "/v1/responses/compact",
            "/backend-api/codex/responses/compact",
        ):
            self.assertIn((path, "POST"), http_routes)
        for path in ("/chat/completions", "/v1/chat/completions"):
            self.assertIn((path, "POST"), http_routes)
        for path in ("/models", "/v1/models", "/backend-api/codex/models"):
            self.assertIn((path, "GET"), http_routes)
        for path in ("/responses", "/v1/responses", "/backend-api/codex/responses"):
            self.assertIn(path, websocket_routes)
        for path in (
            "/v1/mycomesh/local/dashboard",
            "/v1/mycomesh/local/transactions",
            "/v1/mycomesh/local/key/prepare",
            "/v1/mycomesh/local/key/activate",
        ):
            self.assertTrue(any(route.path == path for route in app.routes))

    def test_responses_websocket_bridges_response_create_without_consumer_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(
                    data_dir=Path(directory),
                    relay_urls=("https://relay.example",),
                )
            )
            payload = {
                "id": "resp_ws",
                "object": "response",
                "status": "completed",
                "model": "gpt-test",
                "output": [
                    {
                        "id": "msg_ws",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "done", "annotations": []}],
                    }
                ],
                "output_text": "done",
            }
            relay = AsyncMock(return_value=(payload, 200, {}))
            with patch("gateway.consumer_v8._relay_inference_result", relay):
                client = TestClient(create_app(state), base_url="http://localhost")
                with client.websocket_connect(
                    "/v1/responses",
                    headers={"authorization": f"Bearer {state.payment_key}", "host": "localhost"},
                ) as websocket:
                    websocket.send_json(
                        {
                            "type": "response.create",
                            "generate": True,
                            "model": "gpt-test",
                            "input": "hello",
                            "previous_response_id": "resp_previous",
                        }
                    )
                    events = []
                    while not events or events[-1]["type"] != "response.completed":
                        events.append(websocket.receive_json())
                    websocket.send_json({"type": "unknown"})
                    protocol_error = websocket.receive_json()

        self.assertEqual([event["sequence_number"] for event in events], list(range(len(events))))
        self.assertEqual(events[-1]["response"]["output_text"], "done")
        self.assertEqual(protocol_error["type"], "error")
        forwarded = relay.await_args.args[2]
        self.assertNotIn("type", forwarded)
        self.assertNotIn("generate", forwarded)
        self.assertEqual(forwarded["previous_response_id"], "resp_previous")
        self.assertNotIn("session", json.dumps(forwarded).lower())

    def test_responses_websocket_bridges_remote_compaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("https://relay.example",))
            )
            relay = AsyncMock(
                return_value=(
                    {
                        "id": "resp_compact",
                        "status": "completed",
                        "output": [
                            {
                                "id": "cmp_1",
                                "type": "compaction",
                                "encrypted_content": "ciphertext",
                            }
                        ],
                    },
                    200,
                    {},
                )
            )
            with patch("gateway.consumer_v8._relay_inference_result", relay):
                client = TestClient(create_app(state), base_url="http://localhost")
                with client.websocket_connect(
                    "/v1/responses",
                    headers={"authorization": f"Bearer {state.payment_key}", "host": "localhost"},
                ) as websocket:
                    websocket.send_json(
                        {
                            "type": "response.create",
                            "input": [{"type": "compaction_trigger"}],
                        }
                    )
                    events = [websocket.receive_json(), websocket.receive_json()]

        self.assertEqual(
            [event["type"] for event in events],
            ["response.output_item.done", "response.completed"],
        )
        self.assertEqual(events[0]["item"]["encrypted_content"], "ciphertext")
        relay.assert_awaited_once()

    def test_credentials_are_only_export_url_and_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(
                    data_dir=Path(directory),
                    relay_urls=("http://relay-a",),
                )
            )
            text = state.credentials_text()
            self.assertIn("OPENAI_BASE_URL=", text)
            self.assertIn("OPENAI_API_KEY=", text)
            self.assertNotIn("session", text.lower())
            self.assertNotIn("session", json.dumps(state.health_payload()).lower())

    def test_consumer_page_exposes_v7_account_controls_without_sessions(self) -> None:
        page = _consumer_html_page()
        self.assertIn("充值预付", page)
        self.assertIn("消费记录", page)
        self.assertIn("更换 Key", page)
        self.assertIn("Export", page)
        self.assertNotIn("session", page.lower())

    def test_key_prepare_endpoint_requires_the_current_local_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("http://relay-a",))
            )
            client = TestClient(create_app(state), base_url="http://localhost")
            denied = client.post("/v1/mycomesh/local/key/prepare")
            prepared = client.post(
                "/v1/mycomesh/local/key/prepare",
                headers={"authorization": f"Bearer {state.payment_key}"},
            )

        self.assertEqual(denied.status_code, 401)
        self.assertEqual(prepared.status_code, 200)
        self.assertNotEqual(prepared.json()["payment_key_address"], state.payment_address)

    def test_transaction_plan_registers_pending_key_and_builds_top_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("http://relay-a",))
            )
            state._settlement = {
                "settlement_contract": "0x" + "11" * 20,
                "stablecoin": "0x" + "22" * 20,
                "rpc_urls": ["http://rpc"],
            }
            pending = state.prepare_payment_key()
            state._rpc_value = lambda _callback: 0
            register = state.transaction_plan(
                {"action": "register_key", "wallet": "0x" + "33" * 20}
            )
            top_up = state.transaction_plan(
                {
                    "action": "top_up",
                    "wallet": "0x" + "33" * 20,
                    "amount_usdc": "2.5",
                }
            )

        self.assertEqual(register["key_address"], pending["payment_key_address"])
        self.assertEqual(len(register["transactions"]), 1)
        self.assertEqual(top_up["amount_units"], 2_500_000)
        self.assertEqual(len(top_up["transactions"]), 2)
        self.assertTrue(all(item["data"].startswith("0x") for item in top_up["transactions"]))

    def test_pending_key_activates_only_after_owner_grant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("http://relay-a",))
            )
            owner = "0x" + "44" * 20
            previous = state.payment_address
            pending = state.prepare_payment_key()
            state._grant_for = lambda _address: {
                "owner": owner,
                "max_per_request": 100_000,
                "valid_until": 0,
                "active": True,
            }
            activated = state.activate_pending_payment_key(owner)

            self.assertEqual(activated["previous_key_address"], previous)
            self.assertEqual(state.payment_address, pending["payment_key_address"])
            self.assertFalse((Path(directory) / "pending-payment-key").exists())
            self.assertEqual(
                (Path(directory) / "payment-key").read_text(encoding="utf-8").strip(),
                pending["payment_key"],
            )

    def test_signed_receipt_summary_is_persisted_without_response_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("http://relay-a",))
            )
            state.record_receipt(
                relay_url="https://relay.example",
                endpoint="/v1/responses",
                model="test-model",
                settlement={
                    "settlement_key": "0x" + "55" * 32,
                    "status": "queued",
                    "accepted": True,
                    "signed_receipt": {
                        "authorization": {
                            "authorization": {"request_id": "0x" + "66" * 32}
                        },
                        "receipt": {
                            "provider": "0x" + "77" * 20,
                            "input_tokens": 12,
                            "output_tokens": 3,
                            "actual_fee": 2_100,
                        },
                    },
                },
            )
            history = state.history()

        self.assertEqual(history[0]["actual_fee_units"], 2_100)
        self.assertEqual(history[0]["input_tokens"], 12)
        self.assertNotIn("output_text", history[0])

    def test_request_id_survives_relay_failover(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(
                    data_dir=Path(directory),
                    relay_urls=("http://relay-a",),
                )
            )
            health = {
                "v8": {
                    "chain_id": 31337,
                    "settlement_contract": "0x" + "11" * 20,
                    "relay_payment_address": "0x" + "22" * 20,
                    "relay_signer_address": "0x" + "33" * 20,
                    "channel_hash": "0x" + "44" * 32,
                    "pricing_version": 1,
                    "pricing_hash": "0x" + "55" * 32,
                    "model": "test-model",
                    "maxOutputTokens": 2000,
                }
            }
            first = _build_relay_payment(
                state,
                "/v1/responses",
                {"input": "hello", "max_output_tokens": 4},
                health,
                request_id="0x" + "66" * 32,
            )
            second = _build_relay_payment(
                state,
                "/v1/responses",
                {"input": "hello", "max_output_tokens": 4},
                health,
                request_id="0x" + "66" * 32,
            )
            self.assertEqual(
                first["payment"]["authorization"]["request_id"],
                second["payment"]["authorization"]["request_id"],
            )

    def test_authorization_tolerates_chain_clock_lag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("http://relay-a",))
            )
            health = {
                "v8": {
                    "chain_id": 31337,
                    "settlement_contract": "0x" + "11" * 20,
                    "relay_payment_address": "0x" + "22" * 20,
                    "relay_signer_address": "0x" + "33" * 20,
                    "channel_hash": "0x" + "44" * 32,
                    "pricing_version": 1,
                    "pricing_hash": "0x" + "55" * 32,
                    "model": "test-model",
                }
            }
            with patch("gateway.consumer_v8.time.time", return_value=1_000):
                result = _build_relay_payment(
                    state,
                    "/v1/responses",
                    {"input": "hello", "max_output_tokens": 4},
                    health,
                )

        authorization = result["payment"]["authorization"]
        self.assertEqual(authorization["issued_at"], 700)
        self.assertEqual(authorization["deadline"], 1_900)

    def test_x402_payload_wrapper_is_accepted(self) -> None:
        payload = {"schema": "mycomesh.x402.myco-credit-v1", "authorization": {}}
        header = base64.urlsafe_b64encode(
            json.dumps({"x402Version": 2, "payload": payload}).encode()
        ).decode()

        class Headers(dict):
            pass

        decoded = _v7_payment_header(Headers({"PAYMENT-SIGNATURE": header}))
        self.assertEqual(decoded, payload)

    def test_v7_relay_requires_both_public_identities(self) -> None:
        with self.assertRaisesRegex(RelayError, "payout address"):
            RelayState(settlement_version=7)

    def test_v7_responses_request_omits_messages_field(self) -> None:
        peer = {
            "model": "test-model",
            "channel": "codex-standard-v1",
            "settlement": {
                "chain_id": 31337,
                "contract": "0x" + "11" * 20,
                "pricing_version": 1,
                "pricing_hash": "0x" + "22" * 32,
            },
        }
        state = SimpleNamespace(
            settlement_version=7,
            settlement_chain_id=31337,
            settlement_contract="0x" + "11" * 20,
        )
        with patch("gateway.relay._v7_provider_candidates", return_value=[SimpleNamespace(peer=peer)]):
            request = _v7_normalize_request(
                state,
                "/v1/responses",
                {"model": "test-model", "input": "hello", "max_output_tokens": 4},
                payment=None,
            )
        self.assertEqual(request["input"], "hello")
        self.assertNotIn("messages", request)


class ConsumerV8AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_relay_failover_preserves_last_openai_error(self) -> None:
        error = {
            "error": {
                "type": "usage_limit_reached",
                "message": "The usage limit has been reached",
            }
        }
        responses = [
            httpx.Response(
                429,
                json=error,
                headers={"Retry-After": value},
                request=httpx.Request("POST", f"https://relay-{value}/v1/responses"),
            )
            for value in ("3", "7")
        ]

        class Client:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def __aenter__(self) -> "Client":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def post(self, *_args: object, **_kwargs: object) -> httpx.Response:
                return responses.pop(0)

        state = SimpleNamespace(
            config=SimpleNamespace(
                relay_urls=("https://relay-a", "https://relay-b"),
                timeout_seconds=1,
            ),
            choose_relay=AsyncMock(
                side_effect=[
                    ("https://relay-a", {"v8": {"model": "test-model"}}),
                    ("https://relay-b", {"v8": {"model": "test-model"}}),
                ]
            ),
        )
        with (
            patch("gateway.consumer_v8._build_relay_payment", return_value={"payment": {}}),
            patch("gateway.consumer_v8.httpx.AsyncClient", Client),
        ):
            payload, status, headers = await _relay_inference_result(
                state,
                "/v1/responses",
                {"input": "hello"},
            )

        self.assertEqual(state.choose_relay.await_count, 2)
        self.assertEqual(status, 429)
        self.assertEqual(payload["error"]["type"], "usage_limit_reached")
        self.assertEqual(payload["error"]["message"], "The usage limit has been reached")
        self.assertIsNone(payload["error"]["param"])
        self.assertEqual(payload["error"]["code"], "usage_limit_reached")
        self.assertEqual(headers, {"Retry-After": "7"})

    async def test_http_remote_compaction_is_forwarded_to_relay(self) -> None:
        request = SimpleNamespace(
            json=AsyncMock(return_value={"input": [{"type": "compaction_trigger"}]})
        )
        state = SimpleNamespace(payment_key="secret")
        with patch(
            "gateway.consumer_v8._relay_inference_result",
            AsyncMock(return_value=({"id": "resp_compact", "output": []}, 200, {})),
        ) as relay:
            response = await _proxy_inference(
                state,
                "/v1/responses",
                request,
                "Bearer secret",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)["id"], "resp_compact")
        relay.assert_awaited_once()

    async def test_explicit_compact_route_adds_protocol_trigger(self) -> None:
        request = SimpleNamespace(json=AsyncMock(return_value={"input": "compact this"}))
        state = SimpleNamespace(payment_key="secret")
        relay = AsyncMock(return_value=({"id": "resp_compact", "output": []}, 200, {}))
        with patch("gateway.consumer_v8._relay_inference_result", relay):
            response = await _proxy_inference(
                state,
                "/v1/responses/compact",
                request,
                "Bearer secret",
            )

        self.assertEqual(response.status_code, 200)
        forwarded = relay.await_args.args[2]
        self.assertEqual(forwarded["input"][-1], {"type": "compaction_trigger"})

    async def test_responses_stream_has_codex_lifecycle(self) -> None:
        response = _stream_response(
            "/v1/responses",
            {
                "id": "resp_test",
                "object": "response",
                "model": "mycomesh-codex-standard-v1",
                "output_text": "done",
                "output": [
                    {
                        "id": "msg_test",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "done", "annotations": []}],
                    }
                ],
            },
        )
        text = b"".join([chunk async for chunk in response.body_iterator]).decode()
        self.assertEqual(response.headers["x-mycomesh-streaming-mode"], "buffered")
        for event in (
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ):
            self.assertIn(f"event: {event}", text)
        self.assertLess(text.index("event: response.created"), text.index("event: response.completed"))

    async def test_responses_stream_emits_function_call_arguments(self) -> None:
        response = _stream_response(
            "/v1/responses",
            {
                "id": "resp_tool",
                "object": "response",
                "model": "mycomesh-codex-standard-v1",
                "output_text": "",
                "output": [
                    {
                        "id": "fc_tool",
                        "type": "function_call",
                        "status": "completed",
                        "call_id": "call_tool",
                        "name": "exec_command",
                        "arguments": '{"cmd":"pwd"}',
                    }
                ],
            },
        )
        text = b"".join([chunk async for chunk in response.body_iterator]).decode()

        self.assertIn("event: response.function_call_arguments.delta", text)
        self.assertIn("event: response.function_call_arguments.done", text)
        events = [
            json.loads(line.removeprefix("data: "))
            for line in text.splitlines()
            if line.startswith("data: {")
        ]
        done = next(event for event in events if event["type"] == "response.function_call_arguments.done")
        self.assertEqual(done["arguments"], '{"cmd":"pwd"}')
        self.assertNotIn("event: response.content_part.added", text)
        self.assertLess(
            text.index("event: response.function_call_arguments.done"),
            text.index("event: response.output_item.done"),
        )

    async def test_responses_stream_emits_custom_tool_input(self) -> None:
        response = _stream_response(
            "/v1/responses",
            {
                "id": "resp_custom_tool",
                "object": "response",
                "model": "mycomesh-codex-standard-v1",
                "output_text": "",
                "output": [
                    {
                        "id": "ct_tool",
                        "type": "custom_tool_call",
                        "status": "completed",
                        "call_id": "call_tool",
                        "name": "apply_patch",
                        "input": "*** Begin Patch",
                    }
                ],
            },
        )
        text = b"".join([chunk async for chunk in response.body_iterator]).decode()

        self.assertIn("event: response.custom_tool_call_input.delta", text)
        self.assertIn("event: response.custom_tool_call_input.done", text)
        events = [
            json.loads(line.removeprefix("data: "))
            for line in text.splitlines()
            if line.startswith("data: {")
        ]
        done = next(event for event in events if event["type"] == "response.custom_tool_call_input.done")
        self.assertEqual(done["input"], "*** Begin Patch")
        self.assertNotIn("event: response.content_part.added", text)

    async def test_bridge_health_falls_back_to_relay_health(self) -> None:
        seen: list[str] = []

        class Client:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def __aenter__(self) -> "Client":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def get(self, url: str) -> httpx.Response:
                seen.append(url)
                payload = (
                    {"ok": True, "protocol": "mycomesh-pool/0.2"}
                    if url.endswith("/health") and not url.endswith("/relay/health")
                    else {"ok": True, "v8": {"enabled": True, "providers": 1}}
                )
                return httpx.Response(200, json=payload, request=httpx.Request("GET", url))

        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV8State(
                ConsumerV8Config(data_dir=Path(directory), relay_urls=("https://relay.example",))
            )
            with patch("gateway.consumer_v8.httpx.AsyncClient", Client):
                payload = await state.relay_health("https://relay.example")

        self.assertEqual(payload["v8"]["providers"], 1)
        self.assertEqual(
            seen,
            ["https://relay.example/health", "https://relay.example/relay/health"],
        )


if __name__ == "__main__":
    unittest.main()
