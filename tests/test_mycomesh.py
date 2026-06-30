from __future__ import annotations

import importlib
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from gateway.billing import usdc_to_units
from gateway.chain import parse_private_key, private_key_to_address, sign_evm_digest
from gateway.identity import create_identity, sign_document
from gateway.gateway_registry import GATEWAY_REGISTRATION_PURPOSE


ADMIN_HEADERS = {"Authorization": "Bearer admin-token"}


class MycoMeshProxyTest(unittest.TestCase):
    def test_sync_balance_rejects_incomplete_chain_metadata_without_mutating_balance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="onchain-prepaid")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                mycomesh.store.create_account("acct-a")
                client = TestClient(mycomesh.app)

                response = client.post(
                    "/accounts/acct-a/sync-balance",
                    headers=ADMIN_HEADERS,
                    json={"balance_usdc": "5", "chain_id": 11155111},
                )
                account = mycomesh.store.get_by_account("acct-a")

        self.assertEqual(response.status_code, 400)
        self.assertIsNotNone(account)
        self.assertEqual(account.balance_usdc, "0.000000")

    def test_sync_balance_records_chain_freshness_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="onchain-prepaid")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                mycomesh.store.create_account("acct-a")
                client = TestClient(mycomesh.app)

                response = client.post(
                    "/accounts/acct-a/sync-balance",
                    headers=ADMIN_HEADERS,
                    json={
                        "balance_usdc": "5",
                        "chain_id": 11155111,
                        "settlement": "0x0000000000000000000000000000000000000002",
                        "latest_block": 120,
                        "synced_block": 114,
                        "confirmations": 6,
                        "source": "test-indexer",
                    },
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["balance_usdc"], "5.000000")
        self.assertEqual(body["chain_sync"]["chain_id"], 11155111)
        self.assertEqual(body["chain_sync"]["settlement"], "0x0000000000000000000000000000000000000002")
        self.assertEqual(body["chain_sync"]["synced_block"], 114)

    def test_rotate_key_response_preserves_account_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                mycomesh.store.configure_account(
                    account.account_id,
                    parent_account_id="acct-parent",
                    discount_bps=500,
                    reseller_margin_bps=1000,
                    monthly_quota_usdc="20",
                    usage_tier="reseller",
                )
                client = TestClient(mycomesh.app)

                response = client.post("/accounts/acct-a/keys/rotate", headers=ADMIN_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["api_key"].startswith("msk_"))
        self.assertEqual(body["parent_account_id"], "acct-parent")
        self.assertEqual(body["discount_bps"], 500)
        self.assertEqual(body["reseller_margin_bps"], 1000)
        self.assertEqual(body["monthly_quota_usdc"], "20.000000")
        self.assertEqual(usdc_to_units(body["monthly_quota_usdc"]), usdc_to_units("20"))
        self.assertEqual(body["usage_tier"], "reseller")

    def test_health_is_minimal_and_admin_health_is_detailed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)

                public = client.get("/health")
                admin = client.get("/admin/health", headers=ADMIN_HEADERS)

        self.assertEqual(public.status_code, 200)
        self.assertNotIn("consumer_public_key", public.json())
        self.assertEqual(admin.status_code, 200)
        self.assertIn("consumer_public_key", admin.json())

    def test_account_status_endpoint_suspends_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                client = TestClient(mycomesh.app)

                updated = client.post(
                    "/accounts/acct-a/status",
                    headers=ADMIN_HEADERS,
                    json={"status": "suspended"},
                )
                denied = client.get("/account", headers={"Authorization": f"Bearer {account.api_key}"})

        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["status"], "suspended")
        self.assertEqual(denied.status_code, 403)

    def test_wallet_registers_client_generated_key_hash(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        api_key = "msk_client_generated_secret"
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)

                challenge_response = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash, "chain_id": 11155111},
                )
                challenge = challenge_response.json()
                signature = sign_evm_digest(private_key, mycomesh._personal_sign_digest(challenge["message"].encode("utf-8")))
                register_response = client.post(
                    "/v1/mycomesh/keys/register",
                    json={
                        "wallet": wallet,
                        "key_hash": key_hash,
                        "chain_id": 11155111,
                        "nonce": challenge["nonce"],
                        "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
                    },
                )
                account_response = client.get("/account", headers={"Authorization": f"Bearer {api_key}"})
                stored = mycomesh.store.get_by_account(wallet)

        self.assertEqual(challenge_response.status_code, 200)
        self.assertEqual(register_response.status_code, 200)
        self.assertFalse(register_response.json()["api_key_returned"])
        self.assertEqual(account_response.status_code, 200)
        self.assertIsNotNone(stored)
        self.assertIsNone(stored.api_key)
        self.assertEqual(stored.payment_address, wallet)

    def test_wallet_key_rotation_replaces_previous_client_key(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        first_key = "msk_first_client_secret"
        second_key = "msk_second_client_secret"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)

                self._register_client_key(client, mycomesh, private_key, wallet, first_key)
                first_account = client.get("/account", headers={"Authorization": f"Bearer {first_key}"})
                self._register_client_key(client, mycomesh, private_key, wallet, second_key)
                old_key = client.get("/account", headers={"Authorization": f"Bearer {first_key}"})
                new_key = client.get("/account", headers={"Authorization": f"Bearer {second_key}"})

        self.assertEqual(first_account.status_code, 200)
        self.assertEqual(old_key.status_code, 401)
        self.assertEqual(new_key.status_code, 200)
        self.assertEqual(new_key.json()["account_id"], wallet)

    def test_gateway_registry_discovery_outputs_public_node_urls(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                registration = sign_document(
                    {
                        "node_id": identity.peer_id,
                        "public_key": identity.public_key,
                        "public_url": "https://gw-a.operator.example/v1",
                        "weight": 10,
                        "capacity": 100,
                        "latency_ms": 50,
                    },
                    identity.private_key,
                    purpose=GATEWAY_REGISTRATION_PURPOSE,
                )

                registered = client.post("/gateways", json=registration)
                discovery = client.get("/v1/mycomesh/gateways")

        self.assertEqual(registered.status_code, 200)
        self.assertEqual(registered.json()["public_url"], "https://gw-a.operator.example/v1")
        self.assertEqual(discovery.status_code, 200)
        self.assertEqual(discovery.json()["recommended_base_url"], "https://gw-a.operator.example/v1")
        self.assertIn("https://gw-a.operator.example/v1", discovery.json()["base_urls"])

    def _register_client_key(self, client: TestClient, mycomesh: object, private_key: str, wallet: str, api_key: str) -> None:
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        challenge = client.post(
            "/v1/mycomesh/keys/challenge",
            json={"wallet": wallet, "key_hash": key_hash, "chain_id": 11155111},
        ).json()
        signature = sign_evm_digest(private_key, mycomesh._personal_sign_digest(challenge["message"].encode("utf-8")))
        response = client.post(
            "/v1/mycomesh/keys/register",
            json={
                "wallet": wallet,
                "key_hash": key_hash,
                "chain_id": 11155111,
                "nonce": challenge["nonce"],
                "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
            },
        )
        self.assertEqual(response.status_code, 200)

    def _env(self, tmp_path: Path, *, billing_mode: str) -> dict[str, str]:
        return {
            **os.environ,
            "MYCOMESH_ADMIN_TOKEN": "admin-token",
            "MYCOMESH_BILLING_DB": str(tmp_path / "billing.sqlite3"),
            "MYCOMESH_GATEWAY_REGISTRY_DB": str(tmp_path / "gateways.sqlite3"),
            "MYCOMESH_BILLING_MODE": billing_mode,
            "MYCOMESH_REQUEST_IDENTITY": str(tmp_path / "request-identity.json"),
        }


if __name__ == "__main__":
    unittest.main()
