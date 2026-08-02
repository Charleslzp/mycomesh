from __future__ import annotations

import json
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from gateway.local_consumer import (
    LocalConsumerConfig,
    LocalConsumerAPIError,
    LocalConsumerError,
    _session_v5_claim_should_be_retained,
    _session_claim_requires_recovery,
    _provider_route_refresh_required,
    _credentials_payload,
    bootstrap_local_consumer,
    create_app,
)
from gateway.identity import peer_id_from_public_key
from gateway.identity import create_identity
from gateway.session_service import SessionClaim, SessionServiceError


ROOT = Path(__file__).resolve().parents[1]
NETWORK_CONFIG = ROOT / "deployments" / "sepolia-provider-network.json"


def _config(data_dir: Path) -> LocalConsumerConfig:
    return LocalConsumerConfig(
        data_dir=data_dir,
        network_config_path=NETWORK_CONFIG,
        public_base_url="http://127.0.0.1:8110/v1",
    )


class LocalConsumerPersistenceTest(unittest.TestCase):
    def test_bootstrap_generates_and_persists_local_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp) / "consumer")
            first = bootstrap_local_consumer(config)
            second = bootstrap_local_consumer(config)

            self.assertEqual(first.api_key, second.api_key)
            self.assertEqual(first.identity, second.identity)
            self.assertRegex(first.api_key, r"^sk-myco-local-[A-Za-z0-9_-]{43}$")
            self.assertRegex(first.identity.public_key, r"^[0-9a-f]{64}$")
            self.assertEqual(stat.S_IMODE(config.data_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(config.api_key_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(config.identity_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(config.session_secret_path.stat().st_mode), 0o600)
            self.assertTrue(config.session_db_path.is_file())

            credentials = _credentials_payload(first)
            self.assertEqual(credentials["base_url"], "http://127.0.0.1:8110/v1")
            self.assertEqual(credentials["api_key"], first.api_key)
            self.assertEqual(credentials["model"], "mycomesh-codex-standard-v1")

    def test_tampered_identity_and_secret_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp) / "consumer")
            bootstrap_local_consumer(config)
            identity = json.loads(config.identity_path.read_text(encoding="utf-8"))
            identity["public_key"] = "00" * 32
            identity["peer_id"] = peer_id_from_public_key(identity["public_key"])
            config.identity_path.write_text(json.dumps(identity), encoding="utf-8")
            with self.assertRaisesRegex(LocalConsumerError, "does not match private key"):
                bootstrap_local_consumer(config)

        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp) / "consumer")
            config.data_dir.mkdir(mode=0o700)
            target = Path(tmp) / "outside-key"
            target.write_text("sk-myco-local-" + "A" * 43, encoding="utf-8")
            config.api_key_path.symlink_to(target)
            with self.assertRaisesRegex(LocalConsumerError, "symbolic link"):
                bootstrap_local_consumer(config)

    def test_external_wallet_is_public_only_and_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp) / "consumer")
            state = bootstrap_local_consumer(config)
            wallet = state.configure_external_wallet("0x" + "11" * 20)
            self.assertEqual(wallet.address, "0x" + "11" * 20)
            payload = json.loads(config.wallet_path.read_text(encoding="utf-8"))
            self.assertEqual(set(payload), {"schema", "address", "signing_mode"})
            self.assertNotIn("private_key", payload)
            self.assertEqual(stat.S_IMODE(config.wallet_path.stat().st_mode), 0o600)

            reloaded = bootstrap_local_consumer(config)
            self.assertEqual(reloaded.wallet, wallet)
            with self.assertRaisesRegex(LocalConsumerError, "different wallet"):
                reloaded.configure_external_wallet("0x" + "22" * 20)

    def test_verified_provider_cache_survives_discovery_outage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp) / "consumer")
            state = bootstrap_local_consumer(config)
            state.configure_external_wallet("0x" + "11" * 20)
            provider = create_identity()
            peer = {
                "peer_id": provider.peer_id,
                "public_key": provider.public_key,
                "model": state.network.public_model_id,
                "network_id": state.network.network_id,
                "channel_id": state.network.channel_id,
                "backend_policy": state.network.backend_policy,
                "payment_address": "0x" + "22" * 20,
                "addresses": ["myco+relay://bridge.mycomesh.xyz/provider/9901"],
                "session_settlement": {
                    "version": 5,
                    "chain_id": state.session_deployment.chain_id,
                    "contract": state.session_deployment.contract,
                    "pricing_version": state.session_deployment.pricing_version,
                    "pricing_hash": state.session_deployment.pricing_hash,
                },
                "ttl_seconds": 900,
            }
            with patch("gateway.local_consumer.discover_peers_from_pools", return_value=[peer]):
                self.assertEqual(state.discover_peers()[0]["peer_id"], provider.peer_id)
            self.assertTrue(config.peer_cache_path.is_file())

            reloaded = bootstrap_local_consumer(config)
            with patch(
                "gateway.local_consumer.discover_peers_from_pools",
                side_effect=OSError("all discovery seeds are blocked"),
            ):
                cached = reloaded.discover_peers()
            self.assertEqual(cached[0]["peer_id"], provider.peer_id)

    def test_provider_route_refreshes_before_transport_key_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = bootstrap_local_consumer(_config(Path(tmp) / "consumer"))
            self.assertTrue(
                state._provider_route_requires_refresh(
                    {"transport_key": {"expires_at": int(time.time()) + 30}}
                )
            )
            self.assertFalse(
                state._provider_route_requires_refresh(
                    {"transport_key": {"expires_at": int(time.time()) + 120}}
                )
            )

    def test_relay_transport_key_rejection_requires_route_refresh(self) -> None:
        self.assertTrue(
            _provider_route_refresh_required(
                LocalConsumerError(
                    "all Provider routes failed: relay returned HTTP 400: "
                    '{"ok": false, "error": "secure relay request targets an '
                    'unregistered provider transport key"}'
                )
            )
        )
        self.assertFalse(_provider_route_refresh_required(LocalConsumerError("provider timed out")))


class LocalConsumerAPITest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.config = _config(Path(self.temp.name) / "consumer")
        self.state = bootstrap_local_consumer(self.config)
        self.client = TestClient(
            create_app(state=self.state),
            base_url="http://127.0.0.1:8110",
        )
        self.headers = {"Authorization": f"Bearer {self.state.api_key}"}

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def test_health_is_live_but_readiness_is_fail_closed(self) -> None:
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.json()["ok"])
        self.assertFalse(health.json()["inference_ready"])
        self.assertFalse(health.json()["gateway_dependency"])

        ready = self.client.get("/ready")
        self.assertEqual(ready.status_code, 503)
        self.assertEqual(ready.json()["state"], "needs_wallet")

    def test_openai_routes_require_the_volume_local_key(self) -> None:
        for path in (
            "/v1/mycomesh/local/status",
            "/v1/responses",
            "/v1/chat/completions",
        ):
            with self.subTest(path=path):
                response = self.client.request(
                    "GET" if path.endswith("models") or path.endswith("status") else "POST",
                    path,
                    json={} if not path.endswith("models") and not path.endswith("status") else None,
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["error"]["code"], "invalid_api_key")
                self.assertEqual(response.headers["www-authenticate"], "Bearer")

        models = self.client.get("/v1/models")
        self.assertEqual(models.status_code, 200)
        self.assertEqual(models.json()["data"][0]["id"], "mycomesh-codex-standard-v1")

    def test_non_loopback_host_is_rejected_before_serving_app_or_api(self) -> None:
        for path in ("/health", "/app/playground", "/v1/models"):
            with self.subTest(path=path):
                response = self.client.get(path, headers={"Host": "attacker.example"})
                self.assertEqual(response.status_code, 400)

    def test_status_exposes_identity_and_topology_but_never_the_api_key(self) -> None:
        response = self.client.get(
            "/v1/mycomesh/local/status",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["state"], "needs_wallet")
        self.assertFalse(payload["gateway_dependency"])
        self.assertEqual(payload["network"]["bridge_urls"], ["https://bridge.mycomesh.xyz"])
        self.assertEqual(payload["identity"]["public_key"], self.state.identity.public_key)
        self.assertNotIn(self.state.api_key, json.dumps(payload))

    def test_loopback_credentials_bootstrap_is_not_cacheable(self) -> None:
        response = self.client.get("/v1/mycomesh/local/credentials")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.json()["api_key"], self.state.api_key)

        blocked = self.client.get(
            "/v1/mycomesh/local/credentials",
            headers={"Host": "attacker.example"},
        )
        self.assertEqual(blocked.status_code, 400)

    def test_wallet_endpoint_rejects_private_key_material(self) -> None:
        rejected = self.client.put(
            "/v1/mycomesh/local/wallet",
            headers=self.headers,
            json={
                "address": "0x" + "11" * 20,
                "signing_mode": "external",
                "private_key": "0x" + "22" * 32,
            },
        )
        self.assertEqual(rejected.status_code, 422)
        self.assertFalse(self.config.wallet_path.exists())

        accepted = self.client.put(
            "/v1/mycomesh/local/wallet",
            headers=self.headers,
            json={"address": "0x" + "11" * 20, "signing_mode": "external"},
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["status"]["state"], "needs_session")
        self.assertFalse(accepted.json()["wallet"]["private_key_stored"])

    def test_session_prepare_accepts_a_bounded_prepaid_limit(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        provider = create_identity()
        peer = {
            "peer_id": provider.peer_id,
            "public_key": provider.public_key,
            "model": self.state.network.public_model_id,
            "network_id": self.state.network.network_id,
            "channel_id": self.state.network.channel_id,
            "backend_policy": self.state.network.backend_policy,
            "payment_address": "0x" + "22" * 20,
            "addresses": ["myco+relay://bridge.mycomesh.xyz/provider/9901"],
            "session_settlement": {
                "version": 5,
                "chain_id": self.state.session_deployment.chain_id,
                "contract": self.state.session_deployment.contract,
                "pricing_version": self.state.session_deployment.pricing_version,
                "pricing_hash": self.state.session_deployment.pricing_hash,
            },
            "ttl_seconds": 900,
        }
        with patch("gateway.local_consumer.discover_peers_from_pools", return_value=[peer]):
            response = self.client.post(
                "/v1/mycomesh/session/prepare",
                headers=self.headers,
                json={
                    "model": self.state.network.public_model_id,
                    "max_output_tokens": 256,
                    "max_amount_units": 123456,
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["max_amount_units"], 123456)
        self.assertEqual(response.json()["settlement_version"], 5)
        persisted = self.state.session_store.plan(response.json()["session_id"])
        self.assertEqual(persisted["provider"]["peer_id"], provider.peer_id)
        self.assertEqual(persisted["provider"]["addresses"], peer["addresses"])

    def test_inference_is_an_explicit_openai_compatible_not_ready_error(self) -> None:
        for path in ("/v1/responses", "/v1/chat/completions"):
            with self.subTest(path=path):
                response = self.client.post(path, headers=self.headers, json={})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["error"]["code"], "consumer_not_ready")
                self.assertIn("v3_execution_not_enabled", response.json()["mycomesh"]["blockers"])
                self.assertEqual(response.headers["retry-after"], "30")

    def test_standard_openai_request_uses_the_active_local_session(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        active_session = {
            "session_id": "0x" + "12" * 32,
            "activated_at": 1,
        }
        with (
            patch.object(self.state.session_store, "latest_active", return_value=active_session),
            patch.object(
                self.state,
                "infer",
                return_value={"id": "resp_local", "object": "response", "output": []},
            ) as infer,
        ):
            body = {
                "model": "gpt-5.5",
                "instructions": "Use the supplied tools.",
                "input": [{"role": "user", "content": "hello"}],
                "tools": [{"type": "function", "name": "shell", "parameters": {}}],
                "tool_choice": "auto",
                "parallel_tool_calls": True,
                "reasoning": {"effort": "high", "summary": "auto"},
                "store": False,
                "include": ["reasoning.encrypted_content"],
                "prompt_cache_key": "thread-1",
                "client_metadata": {"turn_id": "turn-1"},
            }
            response = self.client.post("/v1/responses", headers=self.headers, json=body)
            compact = self.client.post("/v1/responses/compact", headers=self.headers, json=body)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(compact.status_code, 200)
        first, second = (call.kwargs for call in infer.call_args_list)
        self.assertEqual(first["model"], self.state.network.public_model_id)
        self.assertEqual(first["request_options"]["instructions"], body["instructions"])
        self.assertEqual(first["request_options"]["tools"], body["tools"])
        self.assertEqual(first["request_options"]["reasoning"], body["reasoning"])
        self.assertEqual(first["envelope"]["session_id"], active_session["session_id"])
        self.assertRegex(first["envelope"]["request_id"], r"^codex_[0-9a-f]{64}$")
        self.assertEqual(first["envelope"]["request_id"], second["envelope"]["request_id"])

    def test_responses_stream_has_codex_item_lifecycle_and_tool_output(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        active_session = {"session_id": "0x" + "12" * 32, "activated_at": 1}
        raw = {
            "id": "resp_local",
            "object": "response",
            "model": self.state.network.public_model_id,
            "output": [
                {
                    "id": "fc_1",
                    "type": "function_call",
                    "status": "completed",
                    "call_id": "call_1",
                    "name": "shell",
                    "arguments": "{}",
                },
                {
                    "id": "msg_1",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "done", "annotations": []}],
                },
            ],
            "output_text": "done",
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        }
        payload = {
            "type": "infer_result",
            "ok": True,
            "request_id": "request_1",
            "output_text": "done",
            "raw": raw,
            "mycomesh_session": {"session_id": active_session["session_id"]},
        }
        with (
            patch.object(self.state.session_store, "latest_active", return_value=active_session),
            patch.object(self.state, "infer", return_value=payload),
        ):
            response = self.client.post(
                "/v1/responses",
                headers=self.headers,
                json={"model": "gpt-5.5", "input": "hello", "stream": True},
            )

        self.assertEqual(response.status_code, 200)
        text = response.text
        self.assertLess(
            text.index("event: response.output_item.added"),
            text.index("event: response.content_part.added"),
        )
        self.assertLess(
            text.index("event: response.content_part.added"),
            text.index("event: response.output_text.delta"),
        )
        for event in (
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ):
            self.assertIn(f"event: {event}", text)
        self.assertIn('"type": "function_call"', text)
        self.assertIn('"delta": "done"', text)
        self.assertIn('"mycomesh_session"', text)
        self.assertNotIn('"raw"', text)

    def test_completed_codex_retry_is_returned_without_a_second_claim(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        plan = {"consumer_payment_address": wallet.address}
        cached = {"id": "resp_cached", "object": "response", "output": []}
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state.session_store, "completed_response", return_value=cached),
            patch.object(self.state.session_store, "claim_request") as claim,
        ):
            result = self.state.infer(
                endpoint="responses",
                model=self.state.network.public_model_id,
                input_value="hello",
                max_output_tokens=32,
                envelope={"session_id": "0x" + "12" * 32, "request_id": "codex_retry"},
            )

        self.assertEqual(result, cached)
        claim.assert_not_called()

    def test_consumed_sequence_error_keeps_the_local_claim(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        peer = {
            "peer_id": "provider-a",
            "payment_address": "0x" + "22" * 20,
            "addresses": ["myco+relays://bridge.example:443/provider-a"],
        }
        plan = {
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 100_000,
            "expires_at": int(time.time()) + 3_600,
            "provider": peer,
            "provider_id": peer["peer_id"],
            "provider_payment_address": peer["payment_address"],
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={
                "request_id": "codex-retry",
                "channel": self.state.session_deployment.channel,
                "network_id": self.state.network.network_id,
                "channel_id": self.state.network.channel_id,
                "backend_policy": self.state.network.backend_policy,
                "pricing_version": self.state.session_deployment.pricing_version,
                "max_fee_units": 100,
                "sequence": 1,
            },
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state.session_store, "completed_response", return_value=None),
            patch.object(self.state.session_store, "claim_request", return_value=claim),
            patch.object(self.state, "_validate_peer_binding"),
            patch.object(self.state, "_provider_route_requires_refresh", return_value=False),
            patch.object(
                self.state,
                "_send_session_request",
                side_effect=LocalConsumerError(
                    "all Provider routes failed: Settlement V4 session request or sequence has already been consumed"
                ),
            ),
            patch.object(self.state.session_store, "rollback") as rollback,
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state.infer(
                    endpoint="responses",
                    model=self.state.network.public_model_id,
                    input_value="hello",
                    max_output_tokens=32,
                    envelope={"session_id": session_id, "request_id": "codex-retry"},
                )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(raised.exception.code, "session_sequence_conflict")
        rollback.assert_not_called()

    def test_in_flight_session_request_is_retryable(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        plan = {
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 100_000,
            "expires_at": int(time.time()) + 3_600,
        }
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state.session_store, "completed_response", return_value=None),
            patch.object(
                self.state.session_store,
                "claim_request",
                side_effect=SessionServiceError("another request is already in flight for this session"),
            ),
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state.infer(
                    endpoint="responses",
                    model=self.state.network.public_model_id,
                    input_value="hello",
                    max_output_tokens=32,
                    envelope={"session_id": session_id, "request_id": "codex-concurrent"},
                )

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.code, "session_request_in_flight")
        self.assertEqual(raised.exception.headers, {"Retry-After": "5"})

    def test_stale_session_claim_requires_a_new_session(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        plan = {
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 100_000,
            "expires_at": int(time.time()) + 3_600,
        }
        stale_error = SessionServiceError("stale V4 request claim requires operator recovery")
        self.assertTrue(_session_claim_requires_recovery(stale_error))
        self.assertFalse(_session_claim_requires_recovery(SessionServiceError("another request is already in flight for this session")))
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state.session_store, "completed_response", return_value=None),
            patch.object(self.state.session_store, "claim_request", side_effect=stale_error),
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state.infer(
                    endpoint="responses",
                    model=self.state.network.public_model_id,
                    input_value="hello",
                    max_output_tokens=32,
                    envelope={"session_id": session_id, "request_id": "codex-stale"},
                )

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.code, "session_recovery_required")
        self.assertIn("activate a new v5/v6 session", raised.exception.message.lower())

    def test_stale_relay_transport_route_is_refreshed_before_retry(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        peer = {
            "peer_id": "provider-a",
            "payment_address": "0x" + "22" * 20,
            "addresses": ["myco+relays://bridge.example:443/provider-a"],
        }
        plan = {
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 100_000,
            "expires_at": int(time.time()) + 3_600,
            "provider": peer,
            "provider_id": peer["peer_id"],
            "provider_payment_address": peer["payment_address"],
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={
                "request_id": "codex-route-refresh",
                "channel": self.state.session_deployment.channel,
                "network_id": self.state.network.network_id,
                "channel_id": self.state.network.channel_id,
                "backend_policy": self.state.network.backend_policy,
                "pricing_version": self.state.session_deployment.pricing_version,
                "max_fee_units": 100,
                "sequence": 1,
            },
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        stale_route_error = LocalConsumerError(
            "all Provider routes failed: relay returned HTTP 400: "
            '{"ok": false, "error": "secure relay request targets an '
            'unregistered provider transport key"}'
        )
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state.session_store, "completed_response", return_value=None),
            patch.object(self.state.session_store, "claim_request", return_value=claim),
            patch.object(self.state, "_validate_peer_binding"),
            patch.object(self.state, "_provider_route_requires_refresh", return_value=False),
            patch.object(self.state, "_refresh_session_provider", return_value=peer) as refresh,
            patch.object(
                self.state,
                "_send_session_request",
                side_effect=[
                    stale_route_error,
                    LocalConsumerError(
                        "all Provider routes failed: Settlement V4 session request or sequence has already been consumed"
                    ),
                ],
            ),
            patch.object(self.state.session_store, "rollback") as rollback,
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state.infer(
                    endpoint="responses",
                    model=self.state.network.public_model_id,
                    input_value="hello",
                    max_output_tokens=32,
                    envelope={"session_id": session_id, "request_id": "codex-route-refresh"},
                )

        self.assertEqual(raised.exception.code, "session_sequence_conflict")
        refresh.assert_called_once_with(
            session_id=session_id,
            provider_id="provider-a",
            provider_payment_address="0x" + "22" * 20,
            model=self.state.network.public_model_id,
        )
        rollback.assert_not_called()

    def test_v5_claim_retention_distinguishes_pre_dispatch_failures(self) -> None:
        self.assertTrue(_session_v5_claim_should_be_retained(LocalConsumerError("provider timed out")))
        self.assertTrue(_session_v5_claim_should_be_retained(LocalConsumerError("sequence has already been consumed")))
        self.assertFalse(_session_v5_claim_should_be_retained(LocalConsumerError("provider is not connected")))
        self.assertFalse(_session_v5_claim_should_be_retained(ValueError("invalid request")))

    def test_explicit_session_is_not_replaced_by_the_local_default(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        explicit = {"session_id": "0x" + "34" * 32}
        with patch.object(
            self.state,
            "infer",
            return_value={"id": "resp_local", "object": "response", "output": []},
        ) as infer:
            response = self.client.post(
                "/v1/responses",
                headers=self.headers,
                json={"input": "hello", "mycomesh_session": explicit},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(infer.call_args.kwargs["envelope"], explicit)

    def test_bundled_browser_consumer_is_served_without_exposing_credentials(self) -> None:
        web = Path(self.temp.name) / "web"
        assets = web / "assets"
        assets.mkdir(parents=True)
        (web / "index.html").write_text("<div id='root'></div>", encoding="utf-8")
        (assets / "app.js").write_text("console.log('ok')", encoding="utf-8")
        config = LocalConsumerConfig(
            data_dir=self.config.data_dir,
            network_config_path=self.config.network_config_path,
            public_base_url=self.config.public_base_url,
            web_dist_dir=web,
        )
        state = bootstrap_local_consumer(config)
        with TestClient(
            create_app(state=state),
            base_url="http://127.0.0.1:8110",
        ) as client:
            health = client.get("/health")
            self.assertTrue(health.json()["browser_app_ready"])
            page = client.get("/app/playground")
            self.assertEqual(page.status_code, 200)
            self.assertIn("default-src 'none'", page.headers["content-security-policy"])
            self.assertNotIn(state.api_key, page.text)
            asset = client.get("/assets/app.js")
            self.assertEqual(asset.status_code, 200)
            self.assertIn("immutable", asset.headers["cache-control"])


class LocalConsumerComposeTest(unittest.TestCase):
    def test_consumer_profile_is_loopback_only_and_secret_is_volume_local(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        start = compose.index("  consumer:\n")
        end = compose.index("\n  proxy:\n", start)
        service = compose[start:end]
        self.assertIn('profiles: ["consumer"]', service)
        self.assertIn('user: "10001:10001"', service)
        self.assertIn("read_only: true", service)
        self.assertIn("cap_drop:\n      - ALL", service)
        self.assertIn('"127.0.0.1:8110:8110"', service)
        self.assertNotIn("MYCOMESH_CONSUMER_PORT", service)
        self.assertIn("mycomesh-consumer-data:/data", service)
        self.assertNotIn("PRIVATE_KEY", service)
        self.assertNotIn("MYCOMESH_PUBLIC_GATEWAY_URL", service)


if __name__ == "__main__":
    unittest.main()
