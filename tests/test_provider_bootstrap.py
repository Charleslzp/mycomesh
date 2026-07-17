from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from gateway.identity import load_or_create_identity

from gateway.provider_bootstrap import (
    ProviderBootstrapError,
    apply_provider_network_config,
    load_or_create_provider_evm_identity,
    load_provider_network_config,
    require_provider_bridge_lease,
)


ROOT = Path(__file__).resolve().parents[1]
NETWORK_CONFIG = ROOT / "deployments" / "sepolia-provider-network.json"


class ProviderEvmIdentityTest(unittest.TestCase):
    def test_identity_is_generated_once_with_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state" / "provider-evm-identity.json"
            first = load_or_create_provider_evm_identity(path)
            second = load_or_create_provider_evm_identity(path)

            self.assertEqual(first, second)
            self.assertRegex(first.private_key, r"^0x[0-9a-f]{64}$")
            self.assertRegex(first.address, r"^0x[0-9a-f]{40}$")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_tampered_address_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "provider.json"
            identity = load_or_create_provider_evm_identity(path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["address"] = "0x" + "00" * 20
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ProviderBootstrapError, "does not match"):
                load_or_create_provider_evm_identity(path)

            path.unlink()
            target = Path(tmp) / "target.json"
            target.write_text(identity.private_key, encoding="utf-8")
            path.symlink_to(target)
            with self.assertRaisesRegex(ProviderBootstrapError, "symbolic link"):
                load_or_create_provider_evm_identity(path)


class ProviderNetworkConfigTest(unittest.TestCase):
    def test_repository_network_config_is_complete_and_v3_backed(self) -> None:
        config = load_provider_network_config(NETWORK_CONFIG)

        self.assertEqual(config.network_id, "mycomesh-testnet")
        self.assertEqual(config.deployment.protocol_version, 3)
        self.assertEqual(config.deployment.chain_id, 11155111)
        self.assertEqual(config.bridge_urls, ("https://bridge.mycomesh.xyz",))
        self.assertEqual(len(config.settlement_rpc_urls), 3)
        self.assertEqual(config.settlement_rpc_urls[0], "https://sepolia.drpc.org")
        self.assertEqual(config.settlement_rpc_url, ",".join(config.settlement_rpc_urls))
        self.assertEqual(config.public_model_id, "mycomesh-codex-standard-v1")
        self.assertEqual(config.reserve_input_bytes, 8000)
        self.assertEqual(config.reserve_output_tokens, 2000)
        self.assertEqual(config.provider_transport, "relay")
        self.assertTrue(config.relay_provider_tls)

    def test_hydration_uses_public_config_and_private_local_payout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(
                network_profile="testnet",
                settlement_version=3,
                settlement_rpc_url=None,
                pool=None,
                consumer_public_key=[],
                transport=None,
                relay_host=None,
                relay_port=None,
                relay_public_url=None,
                relay_provider_tls=None,
                payment_address=None,
            )
            env: dict[str, str] = {}
            config = apply_provider_network_config(
                args,
                NETWORK_CONFIG,
                evm_identity_path=Path(tmp) / "provider-evm.json",
                env=env,
            )

            self.assertEqual(args.pool, "https://bridge.mycomesh.xyz")
            self.assertEqual(args.consumer_public_key, list(config.consumer_public_keys))
            self.assertEqual(args.transport, "relay")
            self.assertEqual(args.relay_host, "bridge.mycomesh.xyz")
            self.assertEqual(args.relay_port, 9901)
            self.assertEqual(args.relay_public_url, "https://bridge.mycomesh.xyz")
            self.assertTrue(args.relay_provider_tls)
            self.assertRegex(args.payment_address, r"^0x[0-9a-f]{40}$")
            self.assertEqual(args.settlement_rpc_url, config.settlement_rpc_url)
            self.assertEqual(args.model, config.public_model_id)
            self.assertEqual(args.reserve_input_tokens, config.reserve_input_bytes)
            self.assertEqual(args.reserve_output_tokens, config.reserve_output_tokens)
            self.assertEqual(env["PUBLIC_MODEL_ID"], config.public_model_id)
            self.assertEqual(env["MYCOMESH_NETWORK_ID"], config.network_id)
            self.assertEqual(Path(env["MYCO_DEPLOYMENT"]), config.deployment_path)

    def test_hydration_rejects_payout_and_public_route_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            identity_path = Path(tmp) / "provider-evm.json"
            identity = load_or_create_provider_evm_identity(identity_path)
            base = dict(
                network_profile="testnet",
                settlement_version=3,
                settlement_rpc_url=None,
                consumer_public_key=[],
                transport=None,
                relay_host=None,
                relay_port=None,
                relay_public_url=None,
                relay_provider_tls=None,
            )
            args = SimpleNamespace(
                **base,
                pool="https://attacker.example",
                payment_address=identity.address,
            )
            with self.assertRaisesRegex(ProviderBootstrapError, "Bridge override"):
                apply_provider_network_config(
                    args,
                    NETWORK_CONFIG,
                    evm_identity_path=identity_path,
                    env={},
                )

            args = SimpleNamespace(
                **base,
                pool=None,
                payment_address="0x" + "11" * 20,
            )
            with self.assertRaisesRegex(ProviderBootstrapError, "local EVM signing identity"):
                apply_provider_network_config(
                    args,
                    NETWORK_CONFIG,
                    evm_identity_path=identity_path,
                    env={},
                )


    def test_bridge_lease_requires_this_provider_in_signed_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            node_path = Path(tmp) / "node-identity.json"
            identity = load_or_create_identity(node_path)
            with patch(
                "gateway.provider_bootstrap.discover_peers",
                return_value=[{"peer_id": identity.peer_id}],
            ) as discover:
                require_provider_bridge_lease(NETWORK_CONFIG, node_path)
            discover.assert_called_once_with(
                "https://bridge.mycomesh.xyz",
                channel="codex-standard-v1",
                timeout=5.0,
            )

            with patch("gateway.provider_bootstrap.discover_peers", return_value=[]):
                with self.assertRaisesRegex(ProviderBootstrapError, "no live lease"):
                    require_provider_bridge_lease(NETWORK_CONFIG, node_path)

if __name__ == "__main__":
    unittest.main()
