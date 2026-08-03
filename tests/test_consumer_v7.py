from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from gateway.consumer_v7 import (
    ConsumerV7Config,
    ConsumerV7State,
    _build_relay_payment,
    _stream_response,
)
from gateway.relay import RelayError, RelayState, _v7_normalize_request, _v7_payment_header


class ConsumerV7Tests(unittest.TestCase):
    def test_credentials_are_only_export_url_and_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV7State(
                ConsumerV7Config(
                    data_dir=Path(directory),
                    relay_urls=("http://relay-a",),
                )
            )
            text = state.credentials_text()
            self.assertIn("OPENAI_BASE_URL=", text)
            self.assertIn("OPENAI_API_KEY=", text)
            self.assertNotIn("session", text.lower())
            self.assertNotIn("session", json.dumps(state.health_payload()).lower())

    def test_request_id_survives_relay_failover(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV7State(
                ConsumerV7Config(
                    data_dir=Path(directory),
                    relay_urls=("http://relay-a",),
                )
            )
            health = {
                "v7": {
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
            state = ConsumerV7State(
                ConsumerV7Config(data_dir=Path(directory), relay_urls=("http://relay-a",))
            )
            health = {
                "v7": {
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
            with patch("gateway.consumer_v7.time.time", return_value=1_000):
                result = _build_relay_payment(
                    state,
                    "/v1/responses",
                    {"input": "hello", "max_output_tokens": 4},
                    health,
                )

        authorization = result["payment"]["authorization"]
        self.assertEqual(authorization["issued_at"], 970)
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


class ConsumerV7AsyncTests(unittest.IsolatedAsyncioTestCase):
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
                    else {"ok": True, "v7": {"enabled": True, "providers": 1}}
                )
                return httpx.Response(200, json=payload, request=httpx.Request("GET", url))

        with tempfile.TemporaryDirectory() as directory:
            state = ConsumerV7State(
                ConsumerV7Config(data_dir=Path(directory), relay_urls=("https://relay.example",))
            )
            with patch("gateway.consumer_v7.httpx.AsyncClient", Client):
                payload = await state.relay_health("https://relay.example")

        self.assertEqual(payload["v7"]["providers"], 1)
        self.assertEqual(
            seen,
            ["https://relay.example/health", "https://relay.example/relay/health"],
        )


if __name__ == "__main__":
    unittest.main()
