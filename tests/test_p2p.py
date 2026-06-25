from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

import gateway.p2p
from gateway.p2p import (
    DEFAULT_CHANNEL,
    ProviderConfig,
    build_gateway_request_body,
    handle_message,
    parse_peer_address,
)


class P2PProtocolTest(unittest.TestCase):
    def test_parse_peer_address_accepts_tcp_uri_and_host_port(self) -> None:
        first = parse_peer_address("tcp://127.0.0.1:9700")
        second = parse_peer_address("localhost:9701")

        self.assertEqual(first.host, "127.0.0.1")
        self.assertEqual(first.port, 9700)
        self.assertEqual(second.uri, "tcp://localhost:9701")

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

    def test_handle_infer_calls_local_gateway(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
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
                {
                    "type": "infer",
                    "request_id": "req-1",
                    "channel": DEFAULT_CHANNEL,
                    "endpoint": "responses",
                    "model": "gpt-5.5",
                    "input": "Say OK",
                },
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["request_id"], "req-1")
        self.assertEqual(response["output_text"], "provider ok")
        self.assertEqual(calls[0]["gateway_url"], "http://127.0.0.1:8000/v1")
        self.assertEqual(calls[0]["agent_key"], "coder-key")
        self.assertEqual(calls[0]["endpoint"], "responses")
        self.assertEqual(calls[0]["body"]["input"], "Say OK")

    def test_handle_infer_rejects_wrong_channel(self) -> None:
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
                "channel": "other-channel",
                "input": "Say OK",
            },
        )

        self.assertFalse(response["ok"])
        self.assertIn("channel mismatch", response["error"])


if __name__ == "__main__":
    unittest.main()
