from __future__ import annotations

import json
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from gateway.local_consumer import (
    LocalConsumerConfig,
    LocalConsumerAPIError,
    LocalConsumerError,
    _session_v5_claim_should_be_retained,
    _session_claim_requires_recovery,
    _session_execution_requires_recovery,
    _provider_route_refresh_required,
    _codex_request_id,
    _codex_env_script,
    _credentials_payload,
    bootstrap_local_consumer,
    create_app,
)
from gateway.identity import peer_id_from_public_key
from gateway.identity import create_identity
from gateway.relay import RelayError
from gateway.session_service import SessionClaim, SessionServiceError


ROOT = Path(__file__).resolve().parents[1]
NETWORK_CONFIG = ROOT / "deployments" / "sepolia-provider-network.json"
NETWORK_CONFIG_V6 = ROOT / "deployments" / "sepolia-provider-network-v6.json"


def _config(data_dir: Path, network_config_path: Path = NETWORK_CONFIG) -> LocalConsumerConfig:
    return LocalConsumerConfig(
        data_dir=data_dir,
        network_config_path=network_config_path,
        public_base_url="http://127.0.0.1:8110/v1",
    )


class LocalConsumerPersistenceTest(unittest.TestCase):
    def test_status_reports_configured_settlement_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = bootstrap_local_consumer(_config(Path(tmp) / "consumer", NETWORK_CONFIG_V6))
            status = state.status_payload()
            self.assertEqual(status["routing_mode"], "local-p2p-bridge-relay-settlement-v6")
            self.assertEqual(status["settlement"]["version"], 6)

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
        self.state.stop_settlement_worker()
        self.client.close()
        self.temp.cleanup()

    def _persist_relay_outbox(
        self,
        *,
        request_id: str,
        relay: bool = True,
        provider_addresses: list[str] | None = None,
        response_payload: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        wallet = self.state.wallet or self.state.configure_external_wallet("0x" + "11" * 20)
        peer = {
            "peer_id": f"provider-{request_id}",
            "payment_address": "0x" + "22" * 20,
            "addresses": provider_addresses
            or [f"myco+relays://bridge.example:443/provider-{request_id}"],
        }
        plan = self.state.session_store.create_plan(
            account_id=wallet.address,
            consumer=wallet.address,
            provider_id=str(peer["peer_id"]),
            provider_payment_address=str(peer["payment_address"]),
            provider_route=peer,
            deployment=self.state.session_deployment,
            max_amount_units=1_000,
            expires_at=int(time.time()) + 3_600,
        )
        claim = self.state.session_store.claim_request(
            session_id=str(plan["session_id"]),
            account_id=wallet.address,
            request_id=request_id,
            request_hash="0x" + "44" * 32,
            max_fee_units=100,
            deadline=int(time.time()) + 300,
            signer=self.state.identity,
        )
        settlement = {"receipt": request_id}
        submission = {
            "schema": "mycomesh.relay.settlement.v1",
            "protocol_version": 5,
            "chain_id": 1,
            "settlement_contract": "0x" + "33" * 20,
            "provider_settlement": settlement,
            "session_signature": "0x01",
            "relay_attestation": {"signature": "0x02"},
        }
        self.state.session_store.finalize(
            str(plan["session_id"]),
            sequence=int(claim.request["sequence"]),
            expected_request_id=str(claim.request["request_id"]),
            amount_units=1,
            request_hash="0x" + "44" * 32,
            response_payload=response_payload or {"id": f"resp-{request_id}"},
            settlement_payload=settlement,
            relay_route_address=(str(peer["addresses"][0]) if relay else None),
            relay_submission=(submission if relay else None),
        )
        return plan, submission

    def _outbox_row(self, plan: dict[str, object], request_id: str) -> dict[str, object]:
        with sqlite3.connect(self.config.session_db_path) as db:
            db.row_factory = sqlite3.Row
            row = db.execute(
                """
                SELECT settlement_status, settlement_attempted_at,
                       relay_route_address, relay_submission_json
                FROM session_v4_results
                WHERE session_id=? AND request_id=?
                """,
                (str(plan["session_id"]), request_id),
            ).fetchone()
        self.assertIsNotNone(row)
        return dict(row)

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

    def test_codex_env_exposes_only_stable_local_edge_credentials(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        with patch.object(
            self.state.session_store,
            "latest_active",
            return_value={"session_id": "0x" + "12" * 32, "activated_at": 1},
        ):
            rendered = _codex_env_script(self.state)
        self.assertIn("OPENAI_BASE_URL=http://127.0.0.1:8110/v1", rendered)
        self.assertIn("MYCOMESH_API_KEY=", rendered)
        self.assertNotIn("MYCOMESH_SESSION_ID", rendered)
        self.assertNotIn("0x" + "12" * 32, rendered)

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
                self.assertNotIn("mycomesh", response.json())
                self.assertEqual(response.headers["retry-after"], "30")

    def test_standard_openai_request_uses_the_active_local_session(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        active_session = {
            "session_id": "0x" + "12" * 32,
            "activated_at": 1,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
        }
        with (
            patch.object(self.state.session_store, "latest_active", return_value=active_session),
            patch.object(self.state.session_store, "request_claim_state", return_value=None),
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

    def test_standard_openai_request_uses_fallback_only_for_a_different_stale_claim(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        blocked = {
            "session_id": "0x" + "12" * 32,
            "activated_at": 1,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
        }
        available = {
            "session_id": "0x" + "34" * 32,
            "activated_at": 1,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
        }
        with (
            patch.object(
                self.state.session_store,
                "latest_active",
                side_effect=[blocked, available],
            ) as latest,
            patch.object(
                self.state.session_store,
                "request_claim_state",
                return_value={
                    "request_id": "another-turn",
                    "stale": True,
                    "fallback_safe": True,
                },
            ),
            patch.object(
                self.state,
                "infer",
                return_value={"id": "resp_local", "object": "response", "output": []},
            ) as infer,
        ):
            response = self.client.post(
                "/v1/responses",
                headers=self.headers,
                json={
                    "model": "gpt-5.5",
                    "input": "hello",
                    "client_metadata": {"turn_id": "new-turn"},
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(latest.call_count, 2)
        self.assertEqual(
            latest.call_args_list[0].kwargs,
            {
                "account_id": self.state.wallet.address,
                "settlement_contract": self.state.session_deployment.contract,
            },
        )
        self.assertTrue(latest.call_args_list[1].kwargs["require_unclaimed"])
        self.assertGreater(latest.call_args_list[1].kwargs["minimum_fee_units"], 0)
        self.assertEqual(infer.call_args.kwargs["envelope"]["session_id"], available["session_id"])

    def test_standard_openai_retry_never_routes_around_a_fresh_claim(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        claimed = {
            "session_id": "0x" + "12" * 32,
            "activated_at": 1,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
        }
        with (
            patch.object(self.state.session_store, "latest_active", return_value=claimed) as latest,
            patch.object(
                self.state.session_store,
                "request_claim_state",
                return_value={
                    "request_id": "another-turn",
                    "stale": False,
                    "fallback_safe": False,
                },
            ),
            patch.object(
                self.state,
                "infer",
                return_value={"id": "resp_local", "object": "response", "output": []},
            ) as infer,
        ):
            response = self.client.post(
                "/v1/responses",
                headers=self.headers,
                json={
                    "model": "gpt-5.5",
                    "input": "hello",
                    "client_metadata": {"turn_id": "retry-turn"},
                },
            )

        self.assertEqual(response.status_code, 200)
        latest.assert_called_once_with(
            account_id=self.state.wallet.address,
            settlement_contract=self.state.session_deployment.contract,
        )
        self.assertEqual(infer.call_args.kwargs["envelope"]["session_id"], claimed["session_id"])

    def test_standard_openai_exact_retry_keeps_its_expired_claim(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        claimed = {
            "session_id": "0x" + "12" * 32,
            "activated_at": 1,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
        }
        body = {
            "model": "gpt-5.5",
            "input": "hello",
            "client_metadata": {"turn_id": "same-turn"},
        }
        request_id = _codex_request_id(body, claimed["session_id"])
        with (
            patch.object(self.state.session_store, "latest_active", return_value=claimed) as latest,
            patch.object(
                self.state.session_store,
                "request_claim_state",
                return_value={
                    "request_id": request_id,
                    "stale": True,
                    "fallback_safe": True,
                },
            ),
            patch.object(
                self.state,
                "infer",
                return_value={"id": "resp_local", "object": "response", "output": []},
            ) as infer,
        ):
            response = self.client.post("/v1/responses", headers=self.headers, json=body)

        self.assertEqual(response.status_code, 200)
        latest.assert_called_once_with(
            account_id=self.state.wallet.address,
            settlement_contract=self.state.session_deployment.contract,
        )
        self.assertEqual(infer.call_args.kwargs["envelope"]["request_id"], request_id)

    def test_standard_openai_retry_keeps_recovered_internal_claim_for_same_turn(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        claimed = {
            "session_id": "0x" + "12" * 32,
            "activated_at": 1,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
        }
        with (
            patch.object(self.state.session_store, "latest_active", return_value=claimed) as latest,
            patch.object(
                self.state.session_store,
                "request_claim_state",
                return_value={
                    "request_id": "recover_deadbeef",
                    "client_request_id": "codex_A",
                    "stale": True,
                    "fallback_safe": True,
                },
            ),
            patch("gateway.local_consumer._codex_request_id", return_value="codex_A"),
            patch.object(
                self.state,
                "infer",
                return_value={"id": "resp_local", "object": "response", "output": []},
            ) as infer,
        ):
            response = self.client.post(
                "/v1/responses",
                headers=self.headers,
                json={
                    "model": "gpt-5.5",
                    "input": "hello",
                    "client_metadata": {"turn_id": "same-turn"},
                },
            )

        self.assertEqual(response.status_code, 200)
        latest.assert_called_once_with(
            account_id=self.state.wallet.address,
            settlement_contract=self.state.session_deployment.contract,
        )
        self.assertEqual(infer.call_args.kwargs["envelope"]["session_id"], claimed["session_id"])
        self.assertEqual(infer.call_args.kwargs["envelope"]["request_id"], "codex_A")

    def test_responses_stream_has_codex_item_lifecycle_and_tool_output(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        active_session = {
            "session_id": "0x" + "12" * 32,
            "activated_at": 1,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
        }
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
            patch.object(self.state.session_store, "request_claim_state", return_value=None),
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
            patch.object(self.state, "_wake_settlement_drain") as wake,
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
        wake.assert_called_once()

    def test_activated_session_does_not_repeat_chain_rpc(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        plan = {
            "consumer_payment_address": wallet.address,
            "activated_at": int(time.time()),
        }
        cached = {"id": "resp_activated", "object": "response", "output": []}
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(
                self.state,
                "_verify_local_session",
                side_effect=AssertionError("activated Session must not repeat eth_call"),
            ) as verify,
            patch.object(self.state.session_store, "completed_response", return_value=cached),
        ):
            result = self.state.infer(
                endpoint="responses",
                model=self.state.network.public_model_id,
                input_value="hello",
                max_output_tokens=32,
                envelope={"session_id": session_id, "request_id": "codex-activated"},
            )

        self.assertEqual(result, cached)
        verify.assert_not_called()

    def test_relay_outbox_retries_after_restart_and_accepts_duplicate_ack(self) -> None:
        plan, submission = self._persist_relay_outbox(request_id="relay-restart")
        settlement_key = "0xsession:0xreceipt"
        with (
            patch.object(self.state, "_relay_settlement_key", return_value=settlement_key),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                side_effect=RelayError("acknowledgement lost"),
            ),
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 0)
        self.assertEqual(
            len(self.state.session_store.pending_settlements(relay_only=True)),
            1,
        )

        restarted = bootstrap_local_consumer(self.config)
        acknowledgement = {
            "ok": True,
            "schema": "mycomesh.relay.settlement.accepted.v1",
            "settlement_key": settlement_key,
            "status": "pending",
            "accepted": False,
        }
        with (
            patch.object(restarted, "_relay_settlement_key", return_value=settlement_key),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                return_value=acknowledgement,
            ) as submit,
        ):
            self.assertEqual(restarted._drain_pending_settlements(), 1)

        self.assertEqual(submit.call_args.args[1], submission)
        self.assertEqual(
            restarted.session_store.pending_settlements(relay_only=True),
            [],
        )
        self.assertEqual(
            restarted.session_store.completed_response(
                session_id=str(plan["session_id"]),
                request_id="relay-restart",
                account_id=restarted.wallet.address,
                request_hash="0x" + "44" * 32,
            )["id"],
            "resp-relay-restart",
        )

    def test_wrong_relay_ack_stays_pending(self) -> None:
        self._persist_relay_outbox(request_id="relay-wrong-ack")
        with (
            patch.object(self.state, "_relay_settlement_key", return_value="expected-key"),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                return_value={
                    "ok": True,
                    "schema": "mycomesh.relay.settlement.accepted.v1",
                    "settlement_key": "wrong-key",
                    "status": "pending",
                    "accepted": True,
                },
            ),
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 0)
        self.assertEqual(
            len(self.state.session_store.pending_settlements(relay_only=True)),
            1,
        )

    def test_terminal_relay_ack_stops_outbox_retries(self) -> None:
        plan, _ = self._persist_relay_outbox(request_id="relay-terminal-ack")
        acknowledgement = {
            "ok": True,
            "schema": "mycomesh.relay.settlement.accepted.v1",
            "settlement_key": "expected-key",
            "status": "failed",
            "accepted": False,
        }
        with (
            patch.object(self.state, "_relay_settlement_key", return_value="expected-key"),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                return_value=acknowledgement,
            ) as submit,
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 0)
            self.assertEqual(self.state._drain_pending_settlements(), 0)

        submit.assert_called_once()
        self.assertEqual(
            self._outbox_row(plan, "relay-terminal-ack")["settlement_status"],
            "failed",
        )

    def test_expired_relay_attestation_stops_outbox_retries(self) -> None:
        plan, _ = self._persist_relay_outbox(request_id="relay-expired-attestation")
        with (
            patch.object(self.state, "_relay_settlement_key", return_value="expected-key"),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                side_effect=RelayError("Relay V6 attestation deadline has elapsed"),
            ) as submit,
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 0)
            self.assertEqual(self.state._drain_pending_settlements(), 0)

        submit.assert_called_once()
        self.assertEqual(
            self._outbox_row(plan, "relay-expired-attestation")["settlement_status"],
            "failed",
        )

    def test_relay_bound_receipt_without_attestation_is_rejected_before_finalize(self) -> None:
        response = {
            "mycomesh_session": {"protocol_version": 5},
            "mycomesh_v5_settlement": {
                "chain_id": 1,
                "settlement_contract": "0x" + "33" * 20,
            },
        }
        receipt = SimpleNamespace(relay="0x" + "44" * 20)
        with patch(
            "gateway.local_consumer.verify_provider_settlement_payload_v5",
            return_value=receipt,
        ):
            with self.assertRaisesRegex(LocalConsumerError, "missing its Relay attestation"):
                self.state._build_relay_settlement_submission(
                    route_address="myco+relays://bridge.example:443/provider-a",
                    response=response,
                    session_private_key="0x" + "55" * 32,
                )

    def test_legacy_outbox_rows_do_not_starve_deliverable_sessions(self) -> None:
        legacy: list[tuple[dict[str, object], str]] = []
        for index in range(9):
            request_id = f"legacy-{index}"
            plan, _ = self._persist_relay_outbox(
                request_id=request_id,
                relay=False,
                provider_addresses=[f"tcp://127.0.0.1:{9700 + index}"],
            )
            legacy.append((plan, request_id))
        deliverable, _submission = self._persist_relay_outbox(request_id="deliverable")

        with patch.object(
            self.state,
            "_submit_settlement_to_relay",
            side_effect=lambda **kwargs: str(kwargs["session_id"])
            == str(deliverable["session_id"]),
        ) as submit:
            self.assertEqual(self.state._drain_pending_settlements(limit=8), 1)

        submit.assert_called_once()
        for plan, request_id in legacy:
            row = self._outbox_row(plan, request_id)
            self.assertIsNotNone(row["settlement_attempted_at"])
            self.assertIsNone(row["relay_route_address"])
            self.assertIsNone(row["relay_submission_json"])

    def test_legacy_outbox_tries_persisted_relay_routes_until_one_accepts(self) -> None:
        wrong = "myco+relays://wrong.example:443/provider-legacy-routes"
        correct = "myco+relays://correct.example:443/provider-legacy-routes"
        plan, submission = self._persist_relay_outbox(
            request_id="legacy-routes",
            relay=False,
            provider_addresses=[wrong, "tcp://127.0.0.1:9700", correct],
        )
        settlement_key = "legacy-session:legacy-receipt"
        acknowledgement = {
            "ok": True,
            "schema": "mycomesh.relay.settlement.accepted.v1",
            "settlement_key": settlement_key,
            "status": "pending",
            "accepted": True,
        }
        with (
            patch.object(
                self.state,
                "_build_relay_settlement_submission",
                return_value=submission,
            ) as build,
            patch.object(self.state, "_relay_settlement_key", return_value=settlement_key),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                side_effect=[RelayError("wrong Relay"), acknowledgement],
            ) as submit,
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 1)

        self.assertEqual(
            [call.kwargs["route_address"] for call in build.call_args_list],
            [wrong, correct],
        )
        self.assertEqual(submit.call_count, 2)
        row = self._outbox_row(plan, "legacy-routes")
        self.assertEqual(row["settlement_status"], "delivered")
        self.assertEqual(row["relay_route_address"], correct)
        self.assertEqual(json.loads(str(row["relay_submission_json"])), submission)

    def test_legacy_missing_attestation_is_fail_closed_without_starving_other_session(self) -> None:
        blocked, _ = self._persist_relay_outbox(
            request_id="legacy-no-attestation",
            relay=False,
            provider_addresses=[
                "myco+relays://bridge.example:443/provider-legacy-no-attestation"
            ],
        )
        healthy, _ = self._persist_relay_outbox(request_id="healthy-after-attestation")
        with (
            patch.object(
                self.state,
                "_build_relay_settlement_submission",
                side_effect=LocalConsumerError(
                    "Relay-bound Provider settlement is missing its Relay attestation"
                ),
            ),
            patch.object(
                self.state,
                "_submit_settlement_to_relay",
                side_effect=lambda **kwargs: str(kwargs["session_id"])
                == str(healthy["session_id"]),
            ) as submit,
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 1)

        submit.assert_called_once()
        row = self._outbox_row(blocked, "legacy-no-attestation")
        self.assertEqual(row["settlement_status"], "pending")
        self.assertIsNotNone(row["settlement_attempted_at"])
        self.assertIsNone(row["relay_route_address"])
        self.assertIsNone(row["relay_submission_json"])

    def test_legacy_ack_loss_keeps_rehydration_null_until_restart(self) -> None:
        route = "myco+relays://bridge.example:443/provider-legacy-ack-loss"
        plan, submission = self._persist_relay_outbox(
            request_id="legacy-ack-loss",
            relay=False,
            provider_addresses=[route],
        )
        settlement_key = "legacy-ack-session:legacy-ack-receipt"
        with (
            patch.object(
                self.state,
                "_build_relay_settlement_submission",
                return_value=submission,
            ),
            patch.object(self.state, "_relay_settlement_key", return_value=settlement_key),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                side_effect=RelayError("acknowledgement lost"),
            ),
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 0)

        row = self._outbox_row(plan, "legacy-ack-loss")
        self.assertEqual(row["settlement_status"], "pending")
        self.assertIsNone(row["relay_route_address"])
        self.assertIsNone(row["relay_submission_json"])

        restarted = bootstrap_local_consumer(self.config)
        acknowledgement = {
            "ok": True,
            "schema": "mycomesh.relay.settlement.accepted.v1",
            "settlement_key": settlement_key,
            "status": "pending",
            "accepted": False,
        }
        with (
            patch.object(
                restarted,
                "_build_relay_settlement_submission",
                return_value=submission,
            ) as build,
            patch.object(restarted, "_relay_settlement_key", return_value=settlement_key),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                return_value=acknowledgement,
            ),
        ):
            self.assertEqual(restarted._drain_pending_settlements(), 1)

        self.assertEqual(
            build.call_args.kwargs["session_private_key"],
            restarted.session_store.derive_private_key(str(plan["session_id"])),
        )
        row = self._outbox_row(plan, "legacy-ack-loss")
        self.assertEqual(row["settlement_status"], "delivered")
        self.assertEqual(row["relay_route_address"], route)
        self.assertEqual(json.loads(str(row["relay_submission_json"])), submission)

    def test_rehydrated_legacy_head_releases_next_session_sequence(self) -> None:
        route = "myco+relays://bridge.example:443/provider-legacy-sequence"
        plan, first_submission = self._persist_relay_outbox(
            request_id="legacy-sequence-head",
            relay=False,
            provider_addresses=[route],
        )
        second_claim = self.state.session_store.claim_request(
            session_id=str(plan["session_id"]),
            account_id=self.state.wallet.address,
            request_id="legacy-sequence-next",
            request_hash="0x" + "55" * 32,
            max_fee_units=100,
            deadline=int(time.time()) + 300,
            signer=self.state.identity,
        )
        second_submission = {"sequence": 2, "exact": True}
        self.state.session_store.finalize(
            str(plan["session_id"]),
            sequence=int(second_claim.request["sequence"]),
            expected_request_id=str(second_claim.request["request_id"]),
            amount_units=1,
            request_hash="0x" + "55" * 32,
            response_payload={"id": "legacy-sequence-next-response"},
            settlement_payload={"sequence": 2},
            relay_route_address=route,
            relay_submission=second_submission,
        )
        pending = self.state.session_store.pending_settlements(relay_only=True)
        self.assertEqual([item["sequence"] for item in pending], [1])

        settlement_key = "legacy-sequence:receipt-one"
        acknowledgement = {
            "ok": True,
            "schema": "mycomesh.relay.settlement.accepted.v1",
            "settlement_key": settlement_key,
            "status": "pending",
            "accepted": True,
        }
        with (
            patch.object(
                self.state,
                "_build_relay_settlement_submission",
                return_value=first_submission,
            ),
            patch.object(self.state, "_relay_settlement_key", return_value=settlement_key),
            patch(
                "gateway.local_consumer.submit_relay_settlement",
                return_value=acknowledgement,
            ),
        ):
            self.assertEqual(self.state._drain_pending_settlements(), 1)

        pending = self.state.session_store.pending_settlements(relay_only=True)
        self.assertEqual([item["sequence"] for item in pending], [2])
        self.assertEqual(pending[0]["relay_submission"], second_submission)

    def test_failed_relay_heads_do_not_starve_other_sessions(self) -> None:
        plans = [
            self._persist_relay_outbox(request_id=f"fair-{index}")[0]
            for index in range(9)
        ]
        first = self.state.session_store.pending_settlements(
            limit=8,
            relay_only=True,
        )
        self.assertEqual(len(first), 8)
        for item in first:
            self.state.session_store.mark_settlement_failed(
                session_id=str(item["session_id"]),
                request_id=str(item["request_id"]),
                error="temporary Relay failure",
                retryable=True,
            )

        second = self.state.session_store.pending_settlements(
            limit=8,
            relay_only=True,
        )
        attempted = {str(item["session_id"]) for item in first}
        untouched = {
            str(plan["session_id"])
            for plan in plans
            if str(plan["session_id"]) not in attempted
        }
        self.assertEqual({str(second[0]["session_id"])}, untouched)

    def test_failed_session_head_does_not_block_another_session_in_one_drain(self) -> None:
        first, _ = self._persist_relay_outbox(request_id="blocked-head")
        second, _ = self._persist_relay_outbox(request_id="healthy-head")

        def submit(**kwargs: object) -> bool:
            return str(kwargs["session_id"]) == str(second["session_id"])

        with patch.object(
            self.state,
            "_submit_settlement_to_relay",
            side_effect=submit,
        ) as deliver:
            self.assertEqual(self.state._drain_pending_settlements(), 1)

        self.assertEqual(deliver.call_count, 2)
        self.assertNotEqual(first["session_id"], second["session_id"])

    def test_settlement_worker_drains_immediately_and_stops(self) -> None:
        drained = threading.Event()
        with patch.object(
            self.state,
            "_drain_pending_settlements",
            side_effect=lambda: drained.set(),
        ) as drain:
            self.state.start_settlement_worker()
            self.assertTrue(drained.wait(2.0))
            self.state.stop_settlement_worker()

        drain.assert_called()
        self.assertIsNone(self.state._settlement_thread)

    def test_concurrent_outbox_drains_send_each_item_once_per_process(self) -> None:
        self._persist_relay_outbox(request_id="concurrent-drain")
        started = threading.Event()
        release = threading.Event()

        def submit(**_kwargs: object) -> bool:
            started.set()
            self.assertTrue(release.wait(2.0))
            return False

        with patch.object(
            self.state,
            "_submit_settlement_to_relay",
            side_effect=submit,
        ) as deliver:
            worker = threading.Thread(target=self.state._drain_pending_settlements)
            worker.start()
            self.assertTrue(started.wait(2.0))
            self.assertEqual(self.state._drain_pending_settlements(), 0)
            release.set()
            worker.join(2.0)

        self.assertFalse(worker.is_alive())
        deliver.assert_called_once()

    def test_finalize_race_returns_cache_without_provider_execution(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        plan = {
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 10_000_000,
            "expires_at": int(time.time()) + 3_600,
        }
        cached = {"id": "resp-race-winner", "object": "response", "output": []}
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch.object(
                self.state.session_store,
                "completed_response",
                side_effect=[None, cached],
            ) as completed,
            patch.object(
                self.state.session_store,
                "claim_request",
                side_effect=SessionServiceError(
                    "V4 client_request_id is already completed"
                ),
            ),
            patch.object(self.state, "_send_session_request") as execute,
        ):
            result = self.state.infer(
                endpoint="responses",
                model=self.state.network.public_model_id,
                input_value="hello",
                max_output_tokens=32,
                envelope={"session_id": session_id, "request_id": "codex-race"},
            )

        self.assertEqual(result, cached)
        self.assertEqual(completed.call_count, 2)
        execute.assert_not_called()

    def test_consumed_sequence_pending_status_keeps_the_local_claim(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        peer = {
            "peer_id": "provider-a",
            "payment_address": "0x" + "22" * 20,
            "addresses": ["myco+relays://bridge.example:443/provider-a"],
        }
        plan = {
            "session_id": session_id,
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 10_000_000,
            "expires_at": int(time.time()) + 3_600,
            "provider": peer,
            "provider_id": peer["peer_id"],
            "provider_payment_address": peer["payment_address"],
            "protocol_version": 5,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={
                "request_id": "codex-retry",
                "request_hash": "0x" + "44" * 32,
                "channel": self.state.session_deployment.channel,
                "network_id": self.state.network.network_id,
                "channel_id": self.state.network.channel_id,
                "backend_policy": self.state.network.backend_policy,
                "pricing_version": self.state.session_deployment.pricing_version,
                "max_fee_units": 1_000_000,
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
            ) as execute,
            patch.object(
                self.state,
                "_send_session_status",
                return_value=({"status": "pending"}, "relay://example"),
            ) as status,
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

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.code, "consumer_request_in_flight")
        self.assertEqual(execute.call_count, 1)
        status.assert_called_once()
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
        self.assertEqual(raised.exception.code, "consumer_request_in_flight")
        self.assertEqual(raised.exception.message, "The local Consumer is finishing another request. Please wait a moment.")
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
        self.assertTrue(_session_execution_requires_recovery(LocalConsumerError("Settlement V4 request execution is already in progress or uncertain; retry with the same request_id")))
        self.assertFalse(_session_execution_requires_recovery(LocalConsumerError("provider timed out")))
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state.session_store, "completed_response", return_value=None),
            patch.object(self.state.session_store, "claim_request", side_effect=stale_error),
            patch.object(
                self.state.session_store,
                "request_claim_state",
                return_value={"request_id": "old", "stale": False, "fallback_safe": False},
            ),
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state.infer(
                    endpoint="responses",
                    model=self.state.network.public_model_id,
                    input_value="hello",
                    max_output_tokens=32,
                    envelope={"session_id": session_id, "request_id": "codex-stale"},
                )

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.code, "consumer_request_in_flight")
        self.assertEqual(raised.exception.message, "The local Consumer is finishing another request. Please wait a moment.")

    def test_stale_session_claim_is_recovered_before_the_new_request(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        peer = {"peer_id": "provider-a"}
        plan = {
            "session_id": session_id,
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 1_000_000,
            "expires_at": int(time.time()) + 3_600,
            "protocol_version": 5,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={
                "request_id": "codex-new",
                "request_hash": "0x" + "44" * 32,
                "channel": self.state.session_deployment.channel,
                "network_id": self.state.network.network_id,
                "channel_id": self.state.network.channel_id,
                "backend_policy": self.state.network.backend_policy,
                "pricing_version": self.state.session_deployment.pricing_version,
                "max_fee_units": 100_000,
                "sequence": 2,
            },
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=2_000,
        )
        stale_error = SessionServiceError("stale V4 request claim requires operator recovery")
        response = {
            "ok": True,
            "request_id": "codex-new",
            "model": self.state.network.public_model_id,
            "endpoint": "responses",
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "mycomesh_v5_settlement": {},
        }
        with (
            patch.object(self.state.session_store, "get", side_effect=[plan, plan]),
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state.session_store, "completed_response", return_value=None),
            patch.object(
                self.state.session_store,
                "claim_request",
                side_effect=[stale_error, claim],
            ),
            patch.object(
                self.state.session_store,
                "request_claim_state",
                return_value={
                    "request_id": "codex-old",
                    "request_hash": "0x" + "22" * 32,
                    "max_fee_units": 100_000,
                    "stale": True,
                    "fallback_safe": True,
                },
            ),
            patch.object(self.state, "_recover_stale_session_claim") as recover,
            patch.object(self.state, "_session_provider", return_value=peer),
            patch.object(self.state, "_send_session_request", return_value=(response, "relay://example")),
            patch("gateway.local_consumer.verify_provider_response"),
            patch.object(self.state.session_store, "finalize"),
            patch.object(self.state, "_submit_settlement_to_relay"),
        ):
            output = self.state.infer(
                endpoint="responses",
                model=self.state.network.public_model_id,
                input_value="hello",
                max_output_tokens=32,
                envelope={"session_id": session_id, "request_id": "codex-new"},
            )

        recover.assert_called_once_with(
            plan=plan,
            claim_state={
                "request_id": "codex-old",
                "request_hash": "0x" + "22" * 32,
                "max_fee_units": 100_000,
                "stale": True,
                "fallback_safe": True,
            },
            model=self.state.network.public_model_id,
        )
        self.assertEqual(output["mycomesh_session"]["sequence"], 2)

    def test_stale_status_refreshes_bound_provider_route_and_retries_once(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        payment_address = "0x" + "22" * 20
        plan = {
            "session_id": session_id,
            "expires_at": int(time.time()) + 3_600,
            "provider_id": "provider-a",
            "provider_payment_address": payment_address,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={"request_id": "old-request", "sequence": 1},
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        old_peer = {"peer_id": "provider-a", "payment_address": payment_address, "route": "old"}
        wrong_peer = {
            "peer_id": "provider-a",
            "payment_address": "0x" + "44" * 20,
            "route": "wrong-wallet",
        }
        refreshed_peer = {
            "peer_id": "provider-a",
            "payment_address": payment_address,
            "route": "refreshed",
        }
        rotated_key = LocalConsumerError(
            "all Provider status routes failed: secure relay request targets an "
            "unregistered provider transport key"
        )
        with (
            patch.object(self.state.session_store, "claim_request", return_value=claim),
            patch.object(self.state, "_session_provider", return_value=old_peer),
            patch.object(
                self.state,
                "discover_peers",
                return_value=[wrong_peer, refreshed_peer],
            ) as discover,
            patch.object(self.state.session_store, "set_provider_route") as persist,
            patch.object(self.state, "_validate_peer_binding") as validate,
            patch.object(
                self.state,
                "_send_session_status",
                side_effect=[rotated_key, ({"status": "aborted"}, "relay://refreshed")],
            ) as status,
            patch.object(self.state.session_store, "rollback") as rollback,
        ):
            recovered = self.state._recover_stale_session_claim(
                plan=plan,
                claim_state={
                    "request_id": "old-request",
                    "request_hash": "0x" + "55" * 32,
                    "max_fee_units": 100,
                },
                model=self.state.network.public_model_id,
            )

        self.assertIsNone(recovered)
        discover.assert_called_once_with(
            model=self.state.network.public_model_id,
            allow_cached=False,
        )
        persist.assert_called_once_with(session_id, refreshed_peer)
        validate.assert_called_once_with(refreshed_peer)
        self.assertEqual(
            [item.kwargs["peer"] for item in status.call_args_list],
            [old_peer, refreshed_peer],
        )
        rollback.assert_called_once_with(
            session_id,
            sequence=1,
            expected_request_id="old-request",
        )

    def test_stale_status_refresh_failure_is_not_retried_again(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        payment_address = "0x" + "22" * 20
        plan = {
            "session_id": session_id,
            "expires_at": int(time.time()) + 3_600,
            "provider_id": "provider-a",
            "provider_payment_address": payment_address,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={"request_id": "old-request", "sequence": 1},
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        old_peer = {"peer_id": "provider-a", "payment_address": payment_address, "route": "old"}
        refreshed_peer = {
            "peer_id": "provider-a",
            "payment_address": payment_address,
            "route": "refreshed",
        }
        rotated_key = LocalConsumerError(
            "all Provider status routes failed: secure relay request targets an "
            "unregistered provider transport key"
        )
        with (
            patch.object(self.state.session_store, "claim_request", return_value=claim),
            patch.object(self.state, "_session_provider", return_value=old_peer),
            patch.object(
                self.state,
                "_refresh_session_provider",
                return_value=refreshed_peer,
            ) as refresh,
            patch.object(self.state, "_validate_peer_binding"),
            patch.object(
                self.state,
                "_send_session_status",
                side_effect=[rotated_key, LocalConsumerError("provider status timed out")],
            ) as status,
            patch.object(self.state.session_store, "rollback") as rollback,
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state._recover_stale_session_claim(
                    plan=plan,
                    claim_state={
                        "request_id": "old-request",
                        "request_hash": "0x" + "55" * 32,
                        "max_fee_units": 100,
                    },
                    model=self.state.network.public_model_id,
                )

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.code, "provider_unavailable")
        refresh.assert_called_once_with(
            session_id=session_id,
            provider_id="provider-a",
            provider_payment_address=payment_address,
            model=self.state.network.public_model_id,
        )
        self.assertEqual(status.call_count, 2)
        rollback.assert_not_called()

    def test_absent_provider_status_does_not_release_the_local_claim(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        plan = {
            "session_id": session_id,
            "expires_at": int(time.time()) + 3_600,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={"request_id": "old-request", "sequence": 1},
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        with (
            patch.object(self.state.session_store, "claim_request", return_value=claim),
            patch.object(self.state, "_session_provider", return_value={"peer_id": "provider-a"}),
            patch.object(
                self.state,
                "_send_session_status",
                return_value=({"status": "absent"}, "relay://example"),
            ),
            patch.object(self.state.session_store, "rollback") as rollback,
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state._recover_stale_session_claim(
                    plan=plan,
                    claim_state={
                        "request_id": "old-request",
                        "request_hash": "0x" + "55" * 32,
                        "max_fee_units": 100,
                    },
                    model=self.state.network.public_model_id,
                )

        self.assertEqual(raised.exception.code, "consumer_request_in_flight")
        rollback.assert_not_called()

    def test_old_status_recovery_cannot_target_a_replaced_provider_attempt(self) -> None:
        self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        plan = {"session_id": session_id, "expires_at": int(time.time()) + 3_600}
        replaced = SessionClaim(
            plan=plan,
            authorization={},
            request={"request_id": "recover_winner", "sequence": 1},
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        with (
            patch.object(self.state.session_store, "claim_request", return_value=replaced),
            patch.object(self.state, "_send_session_status") as status,
            patch.object(self.state.session_store, "rollback") as rollback,
        ):
            with self.assertRaises(LocalConsumerAPIError) as raised:
                self.state._recover_stale_session_claim(
                    plan=plan,
                    claim_state={
                        "request_id": "old-request",
                        "client_request_id": "codex-turn",
                        "request_hash": "0x" + "55" * 32,
                        "max_fee_units": 100,
                    },
                    model=self.state.network.public_model_id,
                )

        self.assertEqual(raised.exception.code, "consumer_request_in_flight")
        status.assert_not_called()
        rollback.assert_not_called()

    def test_retry_without_client_metadata_returns_recovered_request_once(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        request_hash = "0x" + "22" * 32
        plan = {
            "session_id": session_id,
            "activated_at": 1,
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 10_000_000,
            "cumulative_spend_units": 0,
            "expires_at": int(time.time()) + 3_600,
            "protocol_version": 5,
        }
        stale_claim = {
            "request_id": "old-request",
            "request_hash": request_hash,
            "max_fee_units": 1_000_000,
            "stale": True,
            "fallback_safe": True,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={
                "request_id": "old-request",
                "request_hash": request_hash,
                "channel": self.state.session_deployment.channel,
                "network_id": self.state.network.network_id,
                "channel_id": self.state.network.channel_id,
                "backend_policy": self.state.network.backend_policy,
                "pricing_version": self.state.session_deployment.pricing_version,
                "max_fee_units": 1_000_000,
                "sequence": 1,
            },
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        recovered = {
            "id": "resp_recovered",
            "object": "response",
            "ok": True,
            "request_id": "old-request",
            "model": self.state.network.public_model_id,
            "endpoint": "responses",
            "output": [],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "mycomesh_v5_settlement": {},
        }
        stale_error = SessionServiceError("stale V4 request claim requires operator recovery")
        with (
            patch.object(self.state.session_store, "latest_active", return_value=plan),
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch("gateway.local_consumer.inference_request_hash", return_value="22" * 32),
            patch.object(self.state.session_store, "completed_response", return_value=None),
            patch.object(
                self.state.session_store,
                "claim_request",
                side_effect=[stale_error, claim],
            ) as claim_request,
            patch.object(
                self.state.session_store,
                "request_claim_state",
                return_value=stale_claim,
            ),
            patch.object(self.state, "_session_provider", return_value={"peer_id": "provider-a"}),
            patch.object(
                self.state,
                "_send_session_status",
                return_value=({"status": "completed", "response": recovered}, "relay://example"),
            ) as status,
            patch.object(self.state, "_send_session_request") as execute,
            patch("gateway.local_consumer.verify_provider_response"),
            patch.object(self.state.session_store, "finalize") as finalize,
            patch.object(
                self.state,
                "_build_relay_settlement_submission",
                return_value={"stored": "submission"},
            ),
            patch.object(self.state, "_submit_settlement_to_relay") as settle,
            patch.object(self.state, "_wake_settlement_drain") as wake,
        ):
            response = self.client.post(
                "/v1/responses",
                headers=self.headers,
                json={"model": "gpt-5.5", "input": "hello", "max_output_tokens": 32},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], "resp_recovered")
        self.assertEqual(claim_request.call_count, 2)
        self.assertNotEqual(
            claim_request.call_args_list[0].kwargs["request_id"],
            claim_request.call_args_list[1].kwargs["request_id"],
        )
        status.assert_called_once()
        finalize.assert_called_once()
        settle.assert_not_called()
        wake.assert_called_once()
        execute.assert_not_called()

    def test_aborted_provider_execution_retries_once_with_a_fresh_provider_id(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        peer = {
            "peer_id": "provider-a",
            "payment_address": "0x" + "22" * 20,
            "addresses": ["myco+relays://bridge.example:443/provider-a"],
        }
        plan = self.state.session_store.create_plan(
            account_id=wallet.address,
            consumer=wallet.address,
            provider_id=peer["peer_id"],
            provider_payment_address=peer["payment_address"],
            provider_route=peer,
            deployment=self.state.session_deployment,
            max_amount_units=10_000_000,
            expires_at=int(time.time()) + 3_600,
        )
        session_id = str(plan["session_id"])
        provider_request_ids: list[str] = []
        provider_request_deadlines: list[int] = []

        def execute_request(**kwargs: object) -> tuple[dict[str, object], str]:
            claim = kwargs["claim"]
            assert isinstance(claim, SessionClaim)
            provider_request_ids.append(str(claim.request["request_id"]))
            provider_request_deadlines.append(int(claim.request["deadline"]))
            if len(provider_request_ids) == 1:
                raise LocalConsumerError(
                    "all Provider routes failed: Settlement V4 request execution is already in progress or uncertain; retry with the same request_id"
                )
            return {
                "ok": True,
                "request_id": provider_request_ids[-1],
                "model": self.state.network.public_model_id,
                "endpoint": "responses",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                "mycomesh_v5_settlement": {},
            }, "relay://example"

        with (
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state, "_session_provider", return_value=peer),
            patch.object(
                self.state,
                "_send_session_request",
                side_effect=execute_request,
            ) as execute,
            patch.object(
                self.state,
                "_send_session_status",
                return_value=({"status": "aborted"}, "relay://example"),
            ) as status,
            patch("gateway.local_consumer.verify_provider_response") as verify,
            patch.object(
                self.state,
                "_build_relay_settlement_submission",
                return_value={"stored": "submission"},
            ),
            patch.object(self.state, "_submit_settlement_to_relay") as settle,
            patch.object(self.state, "_wake_settlement_drain") as wake,
        ):
            request = {
                "endpoint": "responses",
                "model": self.state.network.public_model_id,
                "input_value": "hello",
                "max_output_tokens": 32,
                "envelope": {"session_id": session_id, "request_id": "codex-uncertain"},
            }
            result = self.state.infer(**request)
            cached = self.state.infer(**request)

        self.assertEqual(result["mycomesh_session"]["sequence"], 1)
        self.assertEqual(cached, result)
        self.assertEqual(execute.call_count, 2)
        status.assert_called_once()
        self.assertEqual(provider_request_ids[0], "codex-uncertain")
        self.assertRegex(provider_request_ids[1], r"^recover_[0-9a-f]{32}$")
        self.assertEqual(provider_request_deadlines, [int(plan["expires_at"])] * 2)
        self.assertEqual(
            verify.call_args.kwargs["expected_request_id"],
            provider_request_ids[1],
        )
        settle.assert_not_called()
        self.assertGreaterEqual(wake.call_count, 1)

    def test_lost_aborted_status_response_recovers_after_consumer_restart(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        peer = {
            "peer_id": "provider-a",
            "payment_address": "0x" + "22" * 20,
            "addresses": ["myco+relays://bridge.example:443/provider-a"],
        }
        plan = self.state.session_store.create_plan(
            account_id=wallet.address,
            consumer=wallet.address,
            provider_id=peer["peer_id"],
            provider_payment_address=peer["payment_address"],
            provider_route=peer,
            deployment=self.state.session_deployment,
            max_amount_units=10_000_000,
            expires_at=int(time.time()) + 3_600,
        )
        request = {
            "endpoint": "responses",
            "model": self.state.network.public_model_id,
            "input_value": "hello",
            "max_output_tokens": 32,
            "envelope": {
                "session_id": str(plan["session_id"]),
                "request_id": "codex-lost-abort-status",
            },
        }

        with (
            patch.object(self.state, "_verify_local_session"),
            patch.object(self.state, "_session_provider", return_value=peer),
            patch.object(
                self.state,
                "_send_session_request",
                side_effect=LocalConsumerError(
                    "Settlement V4 request execution is already in progress or uncertain"
                ),
            ),
            patch.object(
                self.state,
                "_send_session_status",
                side_effect=KeyboardInterrupt("crash after Provider persisted aborted status"),
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.state.infer(**request)

        persisted = self.state.session_store.request_claim_state(str(plan["session_id"]))
        self.assertEqual(persisted["request_id"], "codex-lost-abort-status")
        restarted = bootstrap_local_consumer(self.config)
        provider_request_ids: list[str] = []

        def execute_after_restart(**kwargs: object) -> tuple[dict[str, object], str]:
            claim = kwargs["claim"]
            assert isinstance(claim, SessionClaim)
            provider_request_ids.append(str(claim.request["request_id"]))
            if len(provider_request_ids) == 1:
                raise LocalConsumerError(
                    "Settlement V4 request execution was aborted; "
                    "query signed session status before retrying"
                )
            return {
                "ok": True,
                "request_id": provider_request_ids[-1],
                "model": restarted.network.public_model_id,
                "endpoint": "responses",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                "mycomesh_v5_settlement": {},
            }, "relay://example"

        with (
            patch.object(restarted, "_verify_local_session"),
            patch.object(restarted, "_session_provider", return_value=peer),
            patch.object(
                restarted,
                "_send_session_request",
                side_effect=execute_after_restart,
            ) as execute,
            patch.object(
                restarted,
                "_send_session_status",
                return_value=({"status": "aborted"}, "relay://example"),
            ) as status,
            patch("gateway.local_consumer.verify_provider_response"),
            patch.object(restarted, "_submit_settlement_to_relay"),
        ):
            result = restarted.infer(**request)
            cached = restarted.infer(**request)

        self.assertEqual(cached, result)
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(provider_request_ids[0], "codex-lost-abort-status")
        self.assertRegex(provider_request_ids[1], r"^recover_[0-9a-f]{32}$")
        status.assert_called_once()
        self.assertIsNone(restarted.session_store.request_claim_state(str(plan["session_id"])))

    def test_recovery_cas_loser_returns_concurrent_completed_result(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        peer = {"peer_id": "provider-a"}
        plan = {
            "session_id": session_id,
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 10_000_000,
            "expires_at": int(time.time()) + 3_600,
            "provider_id": "provider-a",
            "provider_payment_address": "0x" + "22" * 20,
            "protocol_version": 5,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={
                "request_id": "codex-cas-race",
                "request_hash": "0x" + "44" * 32,
                "channel": self.state.session_deployment.channel,
                "network_id": self.state.network.network_id,
                "channel_id": self.state.network.channel_id,
                "backend_policy": self.state.network.backend_policy,
                "pricing_version": self.state.session_deployment.pricing_version,
                "max_fee_units": 1_000_000,
                "sequence": 1,
            },
            private_key="0x" + "33" * 32,
            previous_cumulative_spend_units=0,
        )
        cached = {"id": "resp-cas-winner", "object": "response", "output": []}
        with (
            patch.object(self.state.session_store, "get", return_value=plan),
            patch.object(self.state, "_verify_local_session"),
            patch("gateway.local_consumer.inference_request_hash", return_value="44" * 32),
            patch.object(
                self.state.session_store,
                "completed_response",
                side_effect=[None, cached],
            ) as completed,
            patch.object(self.state.session_store, "claim_request", return_value=claim),
            patch.object(self.state, "_session_provider", return_value=peer),
            patch.object(
                self.state,
                "_send_session_request",
                side_effect=LocalConsumerError(
                    "Settlement V4 request execution is already in progress or uncertain"
                ),
            ) as execute,
            patch.object(
                self.state,
                "_send_session_status",
                return_value=({"status": "aborted"}, "relay://example"),
            ),
            patch.object(
                self.state.session_store,
                "replace_claim_attempt",
                side_effect=SessionServiceError("V4 request claim changed during recovery"),
            ),
        ):
            result = self.state.infer(
                endpoint="responses",
                model=self.state.network.public_model_id,
                input_value="hello",
                max_output_tokens=32,
                envelope={"session_id": session_id, "request_id": "codex-cas-race"},
            )

        self.assertEqual(result, cached)
        self.assertEqual(completed.call_count, 2)
        self.assertEqual(execute.call_count, 1)

    def test_stale_relay_transport_route_is_refreshed_before_retry(self) -> None:
        wallet = self.state.configure_external_wallet("0x" + "11" * 20)
        session_id = "0x" + "12" * 32
        peer = {
            "peer_id": "provider-a",
            "payment_address": "0x" + "22" * 20,
            "addresses": ["myco+relays://bridge.example:443/provider-a"],
        }
        plan = {
            "session_id": session_id,
            "consumer_payment_address": wallet.address,
            "channel": self.state.session_deployment.channel,
            "max_amount_units": 100_000,
            "expires_at": int(time.time()) + 3_600,
            "provider": peer,
            "provider_id": peer["peer_id"],
            "provider_payment_address": peer["payment_address"],
            "protocol_version": 5,
        }
        claim = SessionClaim(
            plan=plan,
            authorization={},
            request={
                "request_id": "codex-route-refresh",
                "request_hash": "0x" + "44" * 32,
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
            patch.object(
                self.state,
                "_send_session_status",
                return_value=({"status": "pending"}, "relay://example"),
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

        self.assertEqual(raised.exception.code, "consumer_request_in_flight")
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
