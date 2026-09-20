"""Local-only Consumer V9 routing and payment boundary regressions."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from gateway import chain_v9
from gateway.consumer_v8 import (ConsumerV8Config, ConsumerV8Error, ConsumerV8State,
                                _build_relay_payment, _decode_payment_response, _relay_inference_result)
from tests.test_chain_v9 import address, deployment_manifest, digest, key, signer
from gateway.relay_integrity import RESPONSE_PROOF_SCHEMA, provider_response_hash, provider_response_proof


class ConsumerV9Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        (root / "deployment.json").write_text(json.dumps(deployment_manifest()))
        self.manifest = root / "network.json"
        self.manifest.write_text(json.dumps({"deployment": "deployment.json", "settlement_rpc_urls": ["http://127.0.0.1:8545"]}))
        self.state = ConsumerV8State(ConsumerV8Config(data_dir=root / "state", network_config_path=self.manifest,
                                                   relay_urls=("http://127.0.0.1:9900",)))
        self.health = {"v9": {"enabled": True, "providers": 1, "model": "test-model", "models": ["test-model"],
                              "response_proof": RESPONSE_PROOF_SCHEMA,
                              "chain_id": 31337, "settlement_contract": address(3),
                              "relay_payment_address": address(4), "relay_signer_address": signer(3),
                              "channel_hash": digest(6), "pricing_version": 1, "pricing_hash": digest(7)}}

    def payment(self):
        return _build_relay_payment(self.state, "/v1/responses", {"input": "test", "max_output_tokens": 20}, self.health)["payment"]

    def test_explicit_v9_manifest_builds_domain_nine_authorization(self):
        self.assertEqual(self.state.settlement_version, 9)
        payment = self.payment()
        self.assertEqual(payment["schema"], chain_v9.AUTH_SCHEMA)
        chain_v9.verify_authorization(payment)
        self.assertEqual(self.state.health_payload()["protocol"], "mycomesh-consumer/v9")

    def test_v8_health_and_changed_deployment_cannot_receive_v9_payment(self):
        with self.assertRaises(ConsumerV8Error):
            _build_relay_payment(self.state, "/v1/responses", {"input": "test"}, {"v8": self.health["v9"]})
        self.health["v9"]["settlement_contract"] = address(100)
        with self.assertRaisesRegex(ConsumerV8Error, "pinned V9"):
            self.payment()

    def test_malformed_or_missing_explicit_manifest_never_falls_back_to_v8(self):
        self.manifest.write_text(json.dumps({"deployment": "missing.json"}))
        with self.assertRaisesRegex(ConsumerV8Error, "Invalid configured"):
            self.state._load_settlement_config()
        self.manifest.unlink()
        with self.assertRaisesRegex(ConsumerV8Error, "missing"):
            self.state._load_settlement_config()

    def test_malformed_response_proof_requirement_does_not_silently_disable_it(self):
        self.manifest.write_text(json.dumps({"deployment": "deployment.json", "require_response_proof": "true",
                                            "settlement_rpc_url": "http://127.0.0.1:8545"}))
        with self.assertRaisesRegex(ConsumerV8Error, "must be boolean"):
            self.state._load_settlement_config()

    def test_signed_v9_receipt_is_bound_to_the_original_payment(self):
        payment = self.payment()
        provider = chain_v9.build_provider_receipt(provider=address(8), provider_private_key=key(2),
            authorization_payload=payment, response_hash=digest(10), relay=address(4),
            input_tokens=1, output_tokens=1, actual_fee=10)
        signed = chain_v9.finalize_relay_receipt(provider, relay_private_key=key(3))
        payload = {"signed_receipt": signed, "status": "confirmed", "accepted": True}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        self.assertEqual(_decode_payment_response(encoded, expected_version=9, expected_payment=payment), payload)
        with self.assertRaises(ConsumerV8Error):
            _decode_payment_response(encoded, expected_version=8)
        with self.assertRaisesRegex(ConsumerV8Error, "dispatched payment"):
            _decode_payment_response(encoded, expected_version=9, expected_payment=self.payment())
        self.state.record_receipt(relay_url="http://127.0.0.1:9900", endpoint="responses", model="test-model", settlement=payload)
        self.assertEqual(self.state.history()[0]["status"], "pending", "Relay cannot assert a chain terminal state")


class ConsumerV9AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_valid_receipt_survives_failed_or_malformed_body(self):
        for mode in ("valid", "tampered", "bad_json", "array", "http_error"):
            with self.subTest(mode=mode):
                fixture = ConsumerV9Tests()
                fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                state = fixture.state
                state.choose_relay = AsyncMock(return_value=("http://127.0.0.1:9900", fixture.health))
                class Client:
                    def __init__(self, **kwargs): pass
                    async def __aenter__(self): return self
                    async def __aexit__(self, *args): pass
                    async def post(self, *args, **kwargs):
                        payment = json.loads(base64.urlsafe_b64decode(kwargs["headers"]["PAYMENT-SIGNATURE"] + "=="))
                        body = {"peer": {}, "request_id": payment["authorization"]["request_id"],
                                "endpoint": "responses", "model": "test-model", "output_text": "fixture",
                                "usage": {"input_tokens": 1, "output_tokens": 1}, "raw": {"output_text": "fixture"}}
                        receipt = chain_v9.build_provider_receipt(provider=address(8), provider_private_key=key(2),
                            authorization_payload=payment, response_hash=provider_response_hash(body), relay=address(4),
                            input_tokens=1, output_tokens=1, actual_fee=10)
                        envelope = {"accepted": True, "status": "pending", "signed_receipt": chain_v9.finalize_relay_receipt(receipt, relay_private_key=key(3))}
                        headers = {"PAYMENT-RESPONSE": base64.urlsafe_b64encode(json.dumps(envelope).encode()).decode()}
                        if mode == "tampered": body["raw"]["output_text"] = "forgery"
                        proof = provider_response_proof(body)
                        content = "{bad" if mode == "bad_json" else "[]" if mode == "array" else json.dumps(proof)
                        return httpx.Response(503 if mode == "http_error" else 200, content=content, headers=headers)
                with patch("gateway.consumer_v8.httpx.AsyncClient", Client):
                    result, status, headers = await _relay_inference_result(state, "/v1/responses", {"input": "fixture"})
                self.assertEqual(status, 200 if mode == "valid" else 502)
                self.assertEqual(state.choose_relay.await_count, 1)
                self.assertEqual(len(state.history()), 1)
                self.assertEqual(state.history()[0]["content_verification"], "provider-signed" if mode == "valid" else "failed")
                self.assertIn("PAYMENT-RESPONSE", headers)
                if mode != "valid": self.assertNotIn("output_text", result)

    async def test_unknown_post_result_is_not_replayed_on_another_relay(self):
        for mode in ("timeout", "missing_receipt", "unscoped_503"):
            with self.subTest(mode=mode):
                state = SimpleNamespace(settlement_version=9,
                    config=SimpleNamespace(relay_urls=("http://relay-a", "http://relay-b"), timeout_seconds=1),
                    capabilities=lambda health: health["v9"],
                    choose_relay=AsyncMock(return_value=("http://relay-a", {"v9": {"model": "test"}})))
                class Client:
                    def __init__(self, **kwargs): pass
                    async def __aenter__(self): return self
                    async def __aexit__(self, *args): pass
                    async def post(self, *args, **kwargs):
                        if mode == "timeout": raise httpx.ReadTimeout("fixture timeout")
                        return httpx.Response(503 if mode == "unscoped_503" else 200,
                            json={"error": {"message": "unknown"}} if mode == "unscoped_503" else {"output_text": "test"})
                with patch("gateway.consumer_v8.httpx.AsyncClient", Client), patch("gateway.consumer_v8._build_relay_payment", return_value={"payment": {}}):
                    _, status, _ = await _relay_inference_result(state, "/v1/responses", {"input": "test"})
                self.assertEqual(status, 503)
                self.assertEqual(state.choose_relay.await_count, 1)
