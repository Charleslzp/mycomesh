"""Explicit local V9 manifests: never imply that a deployment exists online."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway.chain import ChainError, load_active_myco_deployment
from gateway.client import _build_parser
from gateway.operator_setup import _html_page, normalize_operator_config, shell_env
from gateway.pool import normalize_settlement_capability
from gateway.provider_bootstrap import ProviderBootstrapError, apply_provider_network_config, load_provider_network_config
from tests.test_chain_v9 import deployment_manifest
from tests import test_ip_mesh_deploy


ROOT = Path(__file__).resolve().parents[1]


def fixture_manifest():
    network = json.loads((ROOT / "deployments/sepolia-provider-network-v8.json").read_text())
    deployment = deployment_manifest()
    deployment.update(chain_id=11155111, network_id=network["network_id"], channel_id=network["channel_id"],
                      backend_policy=network["backend_policy"], channel="codex-standard-v1")
    network["deployment"] = "fixture-v9.json"
    return network, deployment


class V9NetworkConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.network, self.deployment = fixture_manifest()
        self.path = self.root / "network.json"
        self.path.write_text(json.dumps(self.network))
        (self.root / self.network["deployment"]).write_text(json.dumps(self.deployment))

    def test_bootstrap_selects_v9_with_independent_receipt_identity(self):
        config = load_provider_network_config(self.path)
        self.assertEqual(config.deployment.protocol_version, 9)
        args, env = SimpleNamespace(), {"MYCOMESH_PROVIDER_PAYOUT_ADDRESS": "0x" + "ef" * 20}
        apply_provider_network_config(args, self.path, evm_identity_path=self.root / "identity.json", env=env)
        self.assertEqual(args.settlement_version, 9)
        self.assertEqual(args.payment_address, env["MYCOMESH_PROVIDER_PAYOUT_ADDRESS"])
        self.assertEqual(env["MYCO_DEPLOYMENT"], str(self.root / "fixture-v9.json"))

    def test_v9_policy_and_payout_are_not_invented(self):
        with self.assertRaisesRegex(ProviderBootstrapError, "explicit Provider payout"):
            apply_provider_network_config(SimpleNamespace(), self.path, evm_identity_path=self.root / "identity.json", env={})
        self.deployment.pop("policy")
        (self.root / self.network["deployment"]).write_text(json.dumps(self.deployment))
        with self.assertRaises(ProviderBootstrapError):
            load_provider_network_config(self.path)

    def test_active_v9_loader_requires_explicit_matching_manifest(self):
        with self.assertRaisesRegex(ChainError, "explicit deployment"):
            load_active_myco_deployment(settlement_version=9, env={})
        path = self.root / "fixture-v9.json"
        self.assertEqual(load_active_myco_deployment(path, settlement_version=9, env={}).protocol_version, 9)
        with self.assertRaises(ChainError):
            load_active_myco_deployment(path, settlement_version=9,
                                        env={"MYCOMESH_SETTLEMENT_CONTRACT": "0x" + "f0" * 20})

    def test_relay_cli_supports_explicit_v9_without_changing_legacy_default(self):
        with patch.dict("os.environ", {}, clear=True):
            parser = _build_parser()
            self.assertEqual(parser.parse_args(["relay", "serve", "--settlement-version", "9"]).settlement_version, 9)
            self.assertEqual(parser.parse_args(["relay", "serve"]).settlement_version, 6)

    def test_bridge_accepts_v9_only_as_explicit_exact_deployment(self):
        capability = {"version": 9, "chain_id": 11155111, "contract": self.deployment["settlement"],
                      "pricing_version": 1, "pricing_hash": self.deployment["pricing_hash"]}
        self.assertEqual(normalize_settlement_capability(capability, label="fixture"), capability)

    def test_onboarding_keeps_signer_separate_and_warns_about_escrow(self):
        config = normalize_operator_config({"settlement_version": 9, "payout_address": "0x" + "ef" * 20,
                                            "provider_signer_address": "0x" + "ab" * 20}, role="provider")
        self.assertIn("MYCOMESH_SETTLEMENT_VERSION=9", shell_env(config, role="provider"))
        page = _html_page(role="provider", token="test-only-token", current=config, settlement_version=9).decode()
        self.assertIn("escrow", page)
        self.assertIn('name="payout_address"', page)


class V9IPMeshPreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_ip_mesh_deploy.IPMeshProviderPrepareTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        network, deployment = fixture_manifest()
        network.update(relay=self.fixture.manifest["relay"], public_model_ids=["gpt-5.5"])
        self.fixture.network.write_text(json.dumps(network))
        self.path = self.fixture.root / "app/deployments/fixture-v9.json"
        self.path.write_text(json.dumps(deployment))

    def test_prepare_uses_explicit_v9_without_overwriting_v8_or_starting_services(self):
        old = self.fixture.root / "app/deployments/sepolia-myco-v8.json"
        before = old.read_bytes()
        result = test_ip_mesh_deploy.provider.prepare(self.fixture.args)
        self.assertFalse(result["started"])
        self.assertEqual(old.read_bytes(), before)
        env = (self.fixture.root / "mesh.env").read_text()
        self.assertIn("MYCOMESH_PROVIDER_SETTLEMENT_VERSION=9", env)
        self.assertIn("/app/deployments/fixture-v9.json", env)
        loaded = load_provider_network_config(self.fixture.root / "app/deployments/sepolia-provider-network-v9.json")
        self.assertEqual(loaded.deployment.protocol_version, 9)

    def test_missing_v9_policy_rejected_before_environment_is_written(self):
        deployment = json.loads(self.path.read_text())
        deployment.pop("adjudicators")
        self.path.write_text(json.dumps(deployment))
        with self.assertRaises(ValueError):
            test_ip_mesh_deploy.provider.prepare(self.fixture.args)
        self.assertFalse((self.fixture.root / "mesh.env").exists())


if __name__ == "__main__":
    unittest.main()
