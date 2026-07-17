from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.local_consumer import (
    LocalConsumerConfig,
    LocalConsumerError,
    _credentials_payload,
    bootstrap_local_consumer,
    create_app,
)
from gateway.identity import peer_id_from_public_key


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
            "/v1/models",
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

        models = self.client.get("/v1/models", headers=self.headers)
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
        self.assertEqual(accepted.json()["status"]["state"], "needs_signer")
        self.assertFalse(accepted.json()["wallet"]["private_key_stored"])

    def test_inference_is_an_explicit_openai_compatible_not_ready_error(self) -> None:
        for path in ("/v1/responses", "/v1/chat/completions"):
            with self.subTest(path=path):
                response = self.client.post(path, headers=self.headers, json={})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["error"]["code"], "consumer_not_ready")
                self.assertIn("v3_execution_not_enabled", response.json()["mycomesh"]["blockers"])
                self.assertEqual(response.headers["retry-after"], "30")

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
