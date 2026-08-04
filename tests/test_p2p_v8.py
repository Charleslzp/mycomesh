from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.chain import DEFAULT_CHANNEL_HASH, parse_private_key, private_key_to_address
from gateway.chain_v8 import build_authorization, verify_provider_receipt
from gateway.identity import create_identity, sign_document
from gateway.p2p import (
    GatewayHTTPError,
    INFERENCE_REQUEST_PURPOSE,
    P2PError,
    ProviderConfig,
    _inference_request_hash,
    _preverify_inference_request,
    handle_infer,
)


class ProviderV8Test(unittest.TestCase):
    def setUp(self) -> None:
        self.provider_identity = create_identity()
        self.relay_identity = create_identity()
        self.payment_key = "0x" + "11" * 32
        self.provider_key = "0x" + "22" * 32
        self.relay_signer_key = "0x" + "33" * 32
        self.provider_signer = private_key_to_address(parse_private_key(self.provider_key))
        self.provider_address = "0x" + "99" * 20
        self.relay_signer = private_key_to_address(parse_private_key(self.relay_signer_key))
        self.relay_payout = "0x" + "44" * 20
        self.contract = "0x" + "55" * 20
        self.pricing_hash = "0x" + "66" * 32
        self.now = int(time.time())

    def config(self, directory: str) -> ProviderConfig:
        identity_path = Path(directory) / "provider-evm.json"
        identity_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "private_key": self.provider_key,
                    "address": self.provider_signer,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(identity_path, 0o600)
        return ProviderConfig(
            peer_id=self.provider_identity.peer_id,
            channel="codex-standard-v1",
            agent_id="provider",
            agent_key="agent-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="test-model",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=self.provider_identity,
            payment_address=self.provider_address,
            relay_payment_address=self.relay_payout,
            relay_attestation_address=self.relay_signer,
            network_profile="local",
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract=self.contract,
            settlement_chain_id=11155111,
            settlement_version=8,
            pricing_version=1,
            pricing_hash=self.pricing_hash,
            replay_store_path=str(Path(directory) / "replay.sqlite3"),
            evm_identity_path=str(identity_path),
        )

    def message(self, config: ProviderConfig) -> dict[str, object]:
        request_id = "0x" + "77" * 32
        unsigned: dict[str, object] = {
            "type": "infer",
            "request_id": request_id,
            "channel": config.channel,
            "endpoint": "responses",
            "model": config.model,
            "input": "hello",
            "max_output_tokens": 4,
        }
        request_hash = "0x" + _inference_request_hash(config, unsigned, 4)
        unsigned["payment_v8"] = build_authorization(
            payment_key=self.payment_key,
            chain_id=int(config.settlement_chain_id or 0),
            settlement_contract=str(config.settlement_contract),
            request_id=request_id,
            request_hash=request_hash,
            relay=self.relay_payout,
            relay_signer=self.relay_signer,
            channel_hash=DEFAULT_CHANNEL_HASH,
            pricing_version=1,
            pricing_hash=self.pricing_hash,
            max_fee=100_000,
            issued_at=self.now,
            deadline=self.now + 900,
        )
        return sign_document(
            unsigned,
            self.relay_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=config.peer_id,
            timestamp=self.now,
        )

    def test_preverify_has_no_session_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checked = _preverify_inference_request(self.config(directory), self.message(self.config(directory)))
            reservation = checked["reservation"]
            self.assertEqual(reservation["settlement_version"], 8)
            self.assertIn("payment_authorization", reservation)
            self.assertNotIn("session_id", reservation)
            self.assertNotIn("sequence", reservation)
            self.assertTrue(checked["request_key"].startswith("v8:"))

    def test_v8_replay_key_is_independent_of_relay_scheduler_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            first = _preverify_inference_request(config, self.message(config))
            second_message = self.message(config)
            second_message["signature"] = sign_document(
                {key: value for key, value in second_message.items() if key != "signature"},
                create_identity().private_key,
                purpose=INFERENCE_REQUEST_PURPOSE,
                audience=config.peer_id,
                timestamp=self.now,
            )["signature"]
            second = _preverify_inference_request(config, second_message)
            self.assertEqual(first["request_key"], second["request_key"])

    def test_inference_returns_independent_provider_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            with (
                patch("gateway.p2p.ensure_gateway_readiness"),
                patch(
                    "gateway.p2p.call_gateway",
                    return_value={
                        "output_text": "world",
                        "usage": {"input_tokens": 5, "output_tokens": 3},
                    },
                ),
            ):
                response = handle_infer(config, self.message(config))
            self.assertTrue(response["ok"])
            self.assertNotIn("provider_settlement_attestation", response)
            authorization, receipt, _, _, _ = verify_provider_receipt(response["mycomesh_v8_settlement"])
            self.assertEqual(receipt.provider, self.provider_address)
            self.assertEqual(receipt.relay, self.relay_payout)
            self.assertEqual(receipt.actual_fee, 2000)
            self.assertEqual(authorization["authorization"]["relay_signer"], self.relay_signer)

    def test_same_v8_request_replays_cached_result_without_second_upstream_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            message = self.message(config)
            with (
                patch("gateway.p2p.ensure_gateway_readiness"),
                patch(
                    "gateway.p2p.call_gateway",
                    return_value={
                        "output_text": "world",
                        "usage": {"input_tokens": 5, "output_tokens": 3},
                    },
                ) as upstream,
            ):
                first = handle_infer(config, message)
                second = handle_infer(config, message)
            self.assertTrue(first["ok"])
            self.assertTrue(second["ok"])
            self.assertEqual(second["request_id"], first["request_id"])
            self.assertEqual(second["raw"], first["raw"])
            self.assertEqual(second["usage"], first["usage"])
            self.assertEqual(upstream.call_count, 1)

    def test_same_request_can_refresh_cached_receipt_for_a_new_relay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            first_message = self.message(config)
            with (
                patch("gateway.p2p.ensure_gateway_readiness"),
                patch(
                    "gateway.p2p.call_gateway",
                    return_value={
                        "output_text": "world",
                        "usage": {"input_tokens": 5, "output_tokens": 3},
                    },
                ) as upstream,
            ):
                first = handle_infer(config, first_message)
                next_relay = "0x" + "88" * 20
                next_signer_key = "0x" + "99" * 32
                next_signer = private_key_to_address(parse_private_key(next_signer_key))
                config.relay_payment_address = next_relay
                config.relay_attestation_address = next_signer
                unsigned = {key: value for key, value in first_message.items() if key != "signature"}
                raw_payment = unsigned["payment_v8"]["authorization"]
                unsigned["payment_v8"] = build_authorization(
                    payment_key=self.payment_key,
                    chain_id=int(config.settlement_chain_id or 0),
                    settlement_contract=str(config.settlement_contract),
                    request_id=str(raw_payment["request_id"]),
                    request_hash=str(raw_payment["request_hash"]),
                    relay=next_relay,
                    relay_signer=next_signer,
                    channel_hash=DEFAULT_CHANNEL_HASH,
                    pricing_version=1,
                    pricing_hash=self.pricing_hash,
                    max_fee=100_000,
                    issued_at=self.now,
                    deadline=self.now + 900,
                )
                second_message = sign_document(
                    unsigned,
                    create_identity().private_key,
                    purpose=INFERENCE_REQUEST_PURPOSE,
                    audience=config.peer_id,
                    timestamp=self.now,
                )
                second = handle_infer(config, second_message)
            self.assertTrue(first["ok"])
            self.assertTrue(second["ok"])
            _, receipt, _, _, _ = verify_provider_receipt(second["mycomesh_v8_settlement"])
            self.assertEqual(receipt.relay, next_relay)
            self.assertEqual(upstream.call_count, 1)

    def test_explicit_upstream_rejection_releases_v8_execution_fence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            message = self.message(config)
            with (
                patch("gateway.p2p.ensure_gateway_readiness"),
                patch(
                    "gateway.p2p.call_gateway",
                    side_effect=P2PError("gateway returned HTTP 403: rejected"),
                ) as upstream,
            ):
                first = handle_infer(config, message)
                second = handle_infer(config, message)
            self.assertFalse(first["ok"])
            self.assertFalse(first["retryable"])
            self.assertFalse(second["ok"])
            self.assertFalse(second["retryable"])
            self.assertEqual(upstream.call_count, 2)

    def test_upstream_http_error_preserves_status_and_openai_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            message = self.message(config)
            payload = {
                "error": {
                    "type": "rate_limit_error",
                    "message": "quota reached",
                    "code": "rate_limit_exceeded",
                }
            }
            with (
                patch("gateway.p2p.ensure_gateway_readiness"),
                patch(
                    "gateway.p2p.call_gateway",
                    side_effect=GatewayHTTPError(
                        429,
                        payload,
                        'gateway returned HTTP 429: {"error":{"type":"rate_limit_error"}}',
                    ),
                ),
            ):
                response = handle_infer(config, message)

        self.assertFalse(response["ok"])
        self.assertFalse(response["retryable"])
        self.assertEqual(response["upstream_status"], 429)
        self.assertEqual(response["upstream_error"], payload)


if __name__ == "__main__":
    unittest.main()
