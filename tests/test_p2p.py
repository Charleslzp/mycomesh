from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import gateway.p2p
from gateway.identity import create_identity, sign_document
from gateway.p2p import (
    DEFAULT_CHANNEL,
    INFERENCE_REQUEST_PURPOSE,
    ProviderConfig,
    build_gateway_request_body,
    handle_message,
    parse_peer_address,
)
from gateway.pricing import DEFAULT_PRICING
from gateway.reservation import build_payment_reservation


class P2PProtocolTest(unittest.TestCase):
    def test_parse_peer_address_accepts_tcp_uri_and_host_port(self) -> None:
        first = parse_peer_address("tcp://127.0.0.1:9700")
        second = parse_peer_address("localhost:9701")

        self.assertEqual(first.host, "127.0.0.1")
        self.assertEqual(first.port, 9700)
        self.assertEqual(second.uri, "tcp://localhost:9701")

    def test_provider_config_normalizes_payment_address(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            payment_address="0x00000000000000000000000000000000000000A2",
        )

        self.assertEqual(config.payment_address, "0x00000000000000000000000000000000000000a2")

    def test_build_gateway_request_body_for_responses(self) -> None:
        body = build_gateway_request_body(
            endpoint="responses",
            model="gpt-5.5",
            input_value="hello",
            metadata={"task_id": "task-1"},
        )

        self.assertEqual(body["model"], "gpt-5.5")
        self.assertEqual(body["input"], "hello")
        self.assertFalse(body["gateway_stateful"])
        self.assertEqual(body["metadata"], {"task_id": "task-1"})
        limited = build_gateway_request_body(endpoint="responses", model="gpt-5.5", input_value="hello", max_output_tokens=128)
        self.assertEqual(limited["max_output_tokens"], 128)

    def test_build_gateway_request_body_for_chat(self) -> None:
        body = build_gateway_request_body(
            endpoint="chat",
            model="gpt-5.5",
            input_value="hello",
        )

        self.assertEqual(
            body["messages"],
            [{"role": "user", "content": "hello"}],
        )
        self.assertFalse(body["gateway_stateful"])
        limited = build_gateway_request_body(endpoint="chat", model="gpt-5.5", input_value="hello", max_output_tokens=64)
        self.assertEqual(limited["max_tokens"], 64)

    def test_handle_infer_calls_local_gateway(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        calls: list[dict[str, Any]] = []

        def fake_call_gateway(**kwargs: Any) -> dict[str, Any]:
            calls.append(kwargs)
            return {
                "id": "resp-test",
                "object": "response",
                "output_text": "provider ok",
                "usage": {"total_tokens": 2},
            }

        with patch.object(gateway.p2p, "call_gateway", side_effect=fake_call_gateway):
            response = handle_message(
                config,
                _signed_infer(
                    consumer_identity,
                    config,
                    request_id="req-1",
                    endpoint="responses",
                    model="gpt-5.5",
                    input_value="Say OK",
                ),
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["request_id"], "req-1")
        self.assertEqual(response["output_text"], "provider ok")
        self.assertEqual(calls[0]["gateway_url"], "http://127.0.0.1:8000/v1")
        self.assertEqual(calls[0]["agent_key"], "coder-key")
        self.assertEqual(calls[0]["endpoint"], "responses")
        self.assertEqual(calls[0]["body"]["input"], "Say OK")

    def test_handle_infer_forwards_max_output_tokens(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        calls: list[dict[str, Any]] = []

        def fake_call_gateway(**kwargs: Any) -> dict[str, Any]:
            calls.append(kwargs)
            return {"output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}}

        message = _signed_infer(consumer_identity, config, request_id="req-limited", max_output_tokens=77)
        with patch.object(gateway.p2p, "call_gateway", side_effect=fake_call_gateway):
            response = handle_message(config, message)

        self.assertTrue(response["ok"])
        self.assertEqual(calls[0]["body"]["max_output_tokens"], 77)

    def test_handle_infer_rejects_wrong_channel(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:1/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        response = handle_message(
            config,
            _signed_infer(
                consumer_identity,
                config,
                request_id="req-1",
                channel="other-channel",
                input_value="Say OK",
            ),
        )

        self.assertFalse(response["ok"])
        self.assertIn("channel mismatch", response["error"])

    def test_handle_infer_rejects_unsigned_request_by_default(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:1/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
        )

        response = handle_message(
            config,
            {
                "type": "infer",
                "request_id": "req-1",
                "channel": DEFAULT_CHANNEL,
                "input": "Say OK",
            },
        )

        self.assertFalse(response["ok"])
        self.assertIn("signature", response["error"])

    def test_handle_infer_rejects_signed_request_without_consumer_policy(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:1/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
        )

        response = handle_message(
            config,
            sign_document(
                {
                    "type": "infer",
                    "request_id": "req-1",
                    "channel": DEFAULT_CHANNEL,
                    "input": "Say OK",
                },
                consumer_identity.private_key,
                purpose=INFERENCE_REQUEST_PURPOSE,
                audience=config.peer_id,
            ),
        )

        self.assertFalse(response["ok"])
        self.assertIn("allowlist", response["error"])

    def test_handle_infer_rejects_duplicate_signed_request(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        message = _signed_infer(
            consumer_identity,
            config,
            request_id="req-1",
            endpoint="responses",
            model="gpt-5.5",
            input_value="Say OK",
        )

        with patch.object(gateway.p2p, "call_gateway", return_value={"output_text": "ok", "usage": {}}):
            first = handle_message(config, message)
            second = handle_message(config, message)

        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])
        self.assertIn("duplicate", second["error"])

    def test_handle_infer_rejects_missing_payment_reservation(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        response = handle_message(
            config,
            sign_document(
                {
                    "type": "infer",
                    "request_id": "req-no-reservation",
                    "channel": DEFAULT_CHANNEL,
                    "endpoint": "responses",
                    "model": "gpt-5.5",
                    "input": "Say OK",
                },
                consumer_identity.private_key,
                purpose=INFERENCE_REQUEST_PURPOSE,
                audience=config.peer_id,
            ),
        )

        self.assertFalse(response["ok"])
        self.assertIn("payment reservation", response["error"])

    def test_handle_infer_rejects_wrong_audience(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        response = handle_message(
            config,
            sign_document(
                {
                    "type": "infer",
                    "request_id": "req-wrong-audience",
                    "channel": DEFAULT_CHANNEL,
                    "endpoint": "responses",
                    "model": "gpt-5.5",
                    "input": "Say OK",
                },
                consumer_identity.private_key,
                purpose=INFERENCE_REQUEST_PURPOSE,
                audience="other-peer",
            ),
        )

        self.assertFalse(response["ok"])
        self.assertIn("audience", response["error"])

    def test_handle_infer_rejects_under_reserved_payment(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        response = handle_message(
            config,
            _signed_infer(
                consumer_identity,
                config,
                request_id="req-low-reservation",
                max_fee_units=1,
            ),
        )

        self.assertFalse(response["ok"])
        self.assertIn("max_fee_units", response["error"])

    def test_handle_infer_rejects_response_cost_above_reservation(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
            reserve_input_tokens=1,
            reserve_output_tokens=1,
        )
        message = _signed_infer(consumer_identity, config, request_id="req-over-cost", max_fee_units=10_000)

        with patch.object(
            gateway.p2p,
            "call_gateway",
            return_value={"output_text": "too much", "usage": {"input_tokens": 10_000, "output_tokens": 10_000}},
        ):
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("exceeded payment reservation", response["error"])

    def test_persistent_replay_store_rejects_duplicate_after_restart(self) -> None:
        consumer_identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            replay_db = str(Path(tmp) / "replay.sqlite3")
            first_config = ProviderConfig(
                peer_id="peer-test",
                channel=DEFAULT_CHANNEL,
                agent_id="coder",
                agent_key="coder-key",
                gateway_url="http://127.0.0.1:8000/v1",
                model="gpt-5.5",
                advertise_host="127.0.0.1",
                advertise_port=9700,
                authorized_consumers={consumer_identity.public_key},
                replay_store_path=replay_db,
            )
            second_config = ProviderConfig(
                peer_id="peer-test",
                channel=DEFAULT_CHANNEL,
                agent_id="coder",
                agent_key="coder-key",
                gateway_url="http://127.0.0.1:8000/v1",
                model="gpt-5.5",
                advertise_host="127.0.0.1",
                advertise_port=9700,
                authorized_consumers={consumer_identity.public_key},
                replay_store_path=replay_db,
            )
            message = _signed_infer(consumer_identity, first_config, request_id="req-persistent")

            with patch.object(gateway.p2p, "call_gateway", return_value={"output_text": "ok", "usage": {}}):
                first = handle_message(first_config, message)
                second = handle_message(second_config, message)

        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])
        self.assertIn("duplicate", second["error"])

def _signed_infer(
    identity: Any,
    config: ProviderConfig,
    *,
    request_id: str,
    channel: str = DEFAULT_CHANNEL,
    endpoint: str = "responses",
    model: str = "gpt-5.5",
    input_value: str = "Say OK",
    max_fee_units: int = 100000,
    max_output_tokens: int | None = None,
) -> dict[str, Any]:
    message = {
        "type": "infer",
        "request_id": request_id,
        "channel": channel,
        "endpoint": endpoint,
        "model": model,
        "input": input_value,
        "payment_reservation": build_payment_reservation(
            request_id=request_id,
            consumer_id="test-consumer",
            consumer_payment_address=None,
            provider_id=config.peer_id,
            provider_payment_address=config.payment_address,
            channel=channel,
            pricing_hash=DEFAULT_PRICING[DEFAULT_CHANNEL].config_hash(),
            max_fee_units=max_fee_units,
            signer=identity,
        ),
    }
    if max_output_tokens is not None:
        message["max_output_tokens"] = max_output_tokens
    return sign_document(message, identity.private_key, purpose=INFERENCE_REQUEST_PURPOSE, audience=config.peer_id)


if __name__ == "__main__":
    unittest.main()
