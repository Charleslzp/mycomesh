from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from gateway import provider_jury
from gateway.client import _build_parser, _cmd_relay_serve
from gateway.identity import create_identity, save_identity
from tests.test_chain_v9 import address


class RelayJuryCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = create_identity()
        self.identity_path = self.root / "relay-jury-identity.json"
        save_identity(self.identity_path, self.identity)
        self.contract = address(50)
        self.network_path = self.root / "network.json"
        self.policy_hash = provider_jury.decision_policy_hash(
            model="judge-model",
            system_prompt="Apply the pinned fraud policy.",
            max_output_tokens=512,
            task_ttl_seconds=300,
        )

    def arguments(self):
        return _build_parser().parse_args([
            "relay", "serve",
            "--network-profile", "testnet",
            "--payment-address", address(40),
            "--attestation-identity", str(self.root / "attestation.json"),
            "--network-config", str(self.network_path),
            "--relay-admission", str(self.root / "relay-admission.json"),
            "--discovery-cache", str(self.root / "discovery.sqlite3"),
            "--settlement-version", "10",
            "--settlement-chain-id", "31337",
            "--settlement-contract", self.contract,
            "--jury-identity", str(self.identity_path),
            "--jury-expected-public-key", self.identity.public_key,
        ])

    def provider_network(self, *, committee_mode="dynamic_provider_ai_v1"):
        return SimpleNamespace(
            deployment=SimpleNamespace(
                protocol_version=10,
                committee_mode=committee_mode,
                chain_id=31337,
                settlement=self.contract,
            ),
            jury_relay_public_keys=(self.identity.public_key,),
            jury_decision_policy_hash=self.policy_hash,
        )

    def discovery_config(self):
        return {
            "context": {
                "network_profile": "testnet",
                "chain_id": 31337,
                "settlement_contract": self.contract,
                "protocol_version": 10,
            },
            "policy": {"authorities": [address(60)], "threshold": 1},
            "bridge_urls": ["https://bridge.example"],
        }

    def test_parser_exposes_explicit_opt_in_environment(self) -> None:
        with patch.dict(os.environ, {
            "MYCOMESH_RELAY_JURY_IDENTITY": str(self.identity_path),
            "MYCOMESH_RELAY_JURY_PUBLIC_KEY": self.identity.public_key,
        }, clear=True):
            args = _build_parser().parse_args(["relay", "serve"])
        self.assertEqual(args.jury_identity, str(self.identity_path))
        self.assertEqual(args.jury_expected_public_key, self.identity.public_key)
        self.assertFalse(args.provider_jury_runtime_enabled)
        self.assertFalse(args.provider_jury_execution_enabled)

    def test_dynamic_v10_jury_identity_is_wired_to_serve_relay(self) -> None:
        publisher = Mock()
        with patch(
            "gateway.client.load_provider_network_config",
            return_value=self.provider_network(),
        ), patch(
            "gateway.relay_discovery.load_discovery_config",
            return_value=self.discovery_config(),
        ), patch(
            "gateway.relay_discovery_runtime.RelayDiscoveryPublisher.from_file",
            return_value=publisher,
        ), patch("gateway.client.serve_relay") as serve, patch("sys.stdout", new=io.StringIO()):
            result = _cmd_relay_serve(self.arguments())

        self.assertEqual(result, 0)
        self.assertTrue(serve.call_args.kwargs["provider_ai_jury_dynamic_configured"])
        self.assertEqual(
            serve.call_args.kwargs["jury_identity_path"], str(self.identity_path),
        )
        self.assertEqual(
            serve.call_args.kwargs["jury_expected_public_key"], self.identity.public_key,
        )
        publisher.close.assert_called_once()

    def test_static_or_non_v10_network_cannot_load_jury_identity(self) -> None:
        errors = io.StringIO()
        with patch(
            "gateway.client.load_provider_network_config",
            return_value=self.provider_network(committee_mode="independent_committee_v1"),
        ), patch("gateway.client.serve_relay") as serve, patch("sys.stderr", new=errors):
            result = _cmd_relay_serve(self.arguments())

        self.assertEqual(result, 2)
        self.assertIn("dynamic V10 jury deployment", errors.getvalue())
        serve.assert_not_called()

    def test_execution_gate_cannot_be_enabled_without_runtime(self) -> None:
        args = self.arguments()
        args.provider_jury_execution_enabled = True
        errors = io.StringIO()
        with patch(
            "gateway.client.load_provider_network_config",
            return_value=self.provider_network(),
        ), patch("gateway.client.serve_relay") as serve, patch("sys.stderr", new=errors):
            result = _cmd_relay_serve(args)
        self.assertEqual(result, 2)
        self.assertIn("execution requires --provider-jury-runtime-enabled", errors.getvalue())
        serve.assert_not_called()

    def test_runtime_factories_are_composed_and_wired_only_after_full_group(self) -> None:
        args = self.arguments()
        args.provider_jury_runtime_enabled = True
        args.provider_jury_rpc_url = "https://rpc.example"
        args.provider_jury_policy = str(self.root / "policy.json")
        args.provider_jury_worker_db = str(self.root / "worker.sqlite3")
        args.provider_jury_transaction_db = str(self.root / "transaction.sqlite3")
        args.provider_jury_intake_db = str(self.root / "intake.sqlite3")
        runtime_factory = Mock()
        intake_factory = Mock()
        factories = SimpleNamespace(
            runtime_factory=runtime_factory,
            intake_factory=intake_factory,
        )
        publisher = Mock()
        with patch(
            "gateway.client.load_provider_network_config",
            return_value=self.provider_network(),
        ), patch(
            "gateway.provider_jury_service.load_provider_jury_service_config",
            return_value=object(),
        ) as load_service, patch(
            "gateway.provider_jury_service.ProviderJuryServiceFactories",
            return_value=factories,
        ), patch(
            "gateway.relay_discovery.load_discovery_config",
            return_value=self.discovery_config(),
        ), patch(
            "gateway.relay_discovery_runtime.RelayDiscoveryPublisher.from_file",
            return_value=publisher,
        ), patch("gateway.client.serve_relay") as serve, patch(
            "sys.stdout", new=io.StringIO(),
        ):
            result = _cmd_relay_serve(args)

        self.assertEqual(result, 0)
        load_service.assert_called_once()
        self.assertIs(serve.call_args.kwargs["provider_jury_runtime_factory"], runtime_factory)
        self.assertIs(serve.call_args.kwargs["provider_jury_intake_factory"], intake_factory)
        publisher.close.assert_called_once()

    def test_runtime_group_missing_durable_intake_fails_before_server(self) -> None:
        args = self.arguments()
        args.provider_jury_runtime_enabled = True
        args.provider_jury_rpc_url = "https://rpc.example"
        args.provider_jury_policy = str(self.root / "policy.json")
        args.provider_jury_worker_db = str(self.root / "worker.sqlite3")
        args.provider_jury_transaction_db = str(self.root / "transaction.sqlite3")
        args.provider_jury_intake_db = None
        errors = io.StringIO()
        with patch(
            "gateway.client.load_provider_network_config",
            return_value=self.provider_network(),
        ), patch("gateway.client.serve_relay") as serve, patch("sys.stderr", new=errors):
            result = _cmd_relay_serve(args)
        self.assertEqual(result, 2)
        self.assertIn("--provider-jury-intake-db", errors.getvalue())
        serve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
