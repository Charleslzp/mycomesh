"""A labeled single-operator test committee must never become the default."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gateway import chain, chain_v9
from gateway import v9_deployment as deploy
from gateway.channel_policy import CODEX_CHANNEL_BINDING, require_enabled_channel_binding
from gateway.provider_bootstrap import load_provider_network_config, ProviderBootstrapError
from gateway.consumer_v8 import ConsumerV8State, ConsumerV8Error
from gateway.relay_adjudication_v9 import V9AdjudicationError
from tests.test_chain_v9 import deployment_manifest
from tests.test_relay_adjudication_v9 import V9Fixture
from tests.test_v9_deployment import FakeRPC, artifact_fixture, policy_fixture


def controlled(value):
    value = copy.deepcopy(value)
    value.update(committee_mode="controlled_test", independence_attested=False,
                 network_id="mycomesh-v9-controlled-test", reward_token=chain.ZERO_ADDRESS,
                 adjudicator_operators={address: "mycomesh-controlled-test-operator"
                                       for address in value["adjudicators"]})
    for field in ("token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty"):
        value["policy"][field] = 0
    return value


class ControlledManifestTests(unittest.TestCase):
    def test_independent_canonical_manifest_is_unchanged(self):
        original = deployment_manifest()
        saved = chain_v9.validate_deployment(original).to_dict()
        self.assertNotIn("committee_mode", saved)
        self.assertEqual(saved, {**original, "adjudicators": tuple(original["adjudicators"]),
                                "tx_hash": None, "deployment_block": None})

    def test_controlled_requires_separate_local_opt_in(self):
        value = controlled(deployment_manifest())
        for opt_in in (False, 1, "1", None):
            with self.subTest(opt_in=opt_in), self.assertRaises(chain.ChainError):
                chain_v9.validate_deployment(value, allow_controlled_test=opt_in)
        saved = chain_v9.validate_deployment(value, allow_controlled_test=True).to_dict()
        self.assertEqual(saved["committee_mode"], "controlled_test")
        self.assertFalse(saved["independence_attested"])
        self.assertEqual(chain_v9.validate_deployment(saved, allow_controlled_test=True).to_dict(), saved)

    def test_controlled_mode_cannot_claim_independence_or_use_mainnet(self):
        base = controlled(deployment_manifest())
        changes = ({"independence_attested": True}, {"network_id": "mycomesh-public"},
                   {"chain_id": 1}, {"chain_id": 8453}, {"committee_mode": "whatever"},
                   {"committee_mode": "independent_users"},
                   {"adjudicator_operators": deployment_manifest()["adjudicator_operators"]})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(chain.ChainError):
                chain_v9.validate_deployment({**base, **change}, allow_controlled_test=True)

    def test_controlled_retains_majority_address_conflicts_and_zero_rewards(self):
        base = controlled(deployment_manifest())
        changes = ({"adjudication_threshold": 1}, {"adjudicators": [base["adjudicators"][0]] * 3},
                   {"governance": base["adjudicators"][0]}, {"reward_token": deployment_manifest()["reward_token"]},
                   {"policy": {**base["policy"], "token_reward": 1}})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(chain.ChainError):
                chain_v9.validate_deployment({**base, **change}, allow_controlled_test=True)

    def test_public_independent_mode_does_not_gain_an_exception(self):
        base = deployment_manifest()
        for change in ({"independence_attested": False},
                       {"adjudicator_operators": controlled(base)["adjudicator_operators"]}):
            with self.subTest(change=change), self.assertRaises(chain.ChainError):
                chain_v9.validate_deployment({**base, **change}, allow_controlled_test=True)

    def test_save_load_and_runtime_entrypoint_all_require_opt_in(self):
        value = chain_v9.validate_deployment(controlled(deployment_manifest()), allow_controlled_test=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controlled.json"
            with self.assertRaises(chain.ChainError):
                chain_v9.save_deployment(path, value)
            self.assertFalse(path.exists())
            chain_v9.save_deployment(path, value, allow_controlled_test=True)
            with self.assertRaises(chain.ChainError):
                chain_v9.load_deployment(path)
            self.assertEqual(chain_v9.load_deployment(path, allow_controlled_test=True), value)
            env = {"MYCOMESH_SETTLEMENT_VERSION": "9", "MYCO_DEPLOYMENT": str(path)}
            for option in (None, "true", "0"):
                candidate = dict(env)
                if option is not None:
                    candidate["MYCOMESH_ALLOW_CONTROLLED_V9_TEST"] = option
                with self.subTest(option=option), self.assertRaises(chain.ChainError):
                    chain.load_active_myco_deployment(env=candidate)
            env["MYCOMESH_ALLOW_CONTROLLED_V9_TEST"] = "1"
            self.assertEqual(chain.load_active_myco_deployment(env=env), value)


class ControlledDeploymentTests(unittest.TestCase):
    def test_tooling_rejects_controlled_policy_before_rpc_without_opt_in(self):
        policy = controlled(policy_fixture())
        client = FakeRPC()
        with self.assertRaises(chain.ChainError):
            client.plan(policy, artifact_fixture())
        self.assertEqual(client.calls, [])
        with self.assertRaises(chain.ChainError):
            deploy.constructor_data(policy)

    def test_opted_in_plan_retains_honest_mode_and_normal_constructor(self):
        policy = controlled(policy_fixture())
        client = FakeRPC()
        client.allow_controlled_test = True
        plan = client.plan(policy, artifact_fixture())
        self.assertEqual(plan["policy"]["committee_mode"], "controlled_test")
        self.assertFalse(plan["manifest_candidate"]["independence_attested"])
        self.assertEqual(deploy.constructor_data(policy, allow_controlled_test=True),
                         deploy.constructor_data(policy_fixture()))
        self.assertEqual(client.refresh(plan)["transaction"], plan["transaction"])
        client.allow_controlled_test = False
        client.calls.clear()
        with self.assertRaises(chain.ChainError):
            client.refresh(plan)
        self.assertEqual(client.calls, [])
        with self.assertRaises(chain.ChainError):
            client.check_network(policy)
        self.assertEqual(client.calls, [])

    def test_existing_independent_policy_roundtrips_without_new_fields(self):
        policy = policy_fixture()
        self.assertEqual(deploy.validate_policy(policy), policy)
        self.assertNotIn("committee_mode", FakeRPC().plan(policy, artifact_fixture())["manifest_candidate"])


class ControlledChannelTests(unittest.TestCase):
    def test_binding_default_rejects_and_only_explicit_process_can_accept(self):
        normal = CODEX_CHANNEL_BINDING.to_dict()
        test = {**normal, "network_id": "mycomesh-v9-controlled-test"}
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                require_enabled_channel_binding(**test)
            self.assertEqual(require_enabled_channel_binding(**normal), CODEX_CHANNEL_BINDING)
        with patch.dict("os.environ", {"MYCOMESH_ALLOW_CONTROLLED_V9_TEST": "1"}):
            self.assertEqual(require_enabled_channel_binding(**test).to_dict(), test)
            self.assertEqual(require_enabled_channel_binding(**normal), CODEX_CHANNEL_BINDING)
            with self.assertRaises(ValueError):
                require_enabled_channel_binding(**test, allow_controlled_test=False)
            for changes in ({"network_id": "another-controlled-test"}, {"channel_id": "claude"},
                            {"backend_policy": "unvalidated"}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    require_enabled_channel_binding(**{**test, **changes})

    def test_provider_bootstrap_requires_process_opt_in_for_controlled_manifest(self):
        source = Path(__file__).resolve().parents[1] / "deployments" / "sepolia-provider-network-v8.json"
        network = json.loads(source.read_text())
        manifest = controlled(deployment_manifest())
        manifest.update(channel=CODEX_CHANNEL_BINDING.channel, backend_policy=CODEX_CHANNEL_BINDING.backend_policy)
        network.update(deployment="controlled.json", network_id=manifest["network_id"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / network["deployment"]).write_text(json.dumps(manifest))
            path = root / "network.json"
            path.write_text(json.dumps(network))
            with patch.dict("os.environ", {}, clear=True), self.assertRaises(ProviderBootstrapError):
                load_provider_network_config(path)
            with patch.dict("os.environ", {"MYCOMESH_ALLOW_CONTROLLED_V9_TEST": "1"}):
                loaded = load_provider_network_config(path)
                # The ordinary consumer does not inherit the node's test opt-in.
                consumer = object.__new__(ConsumerV8State)
                consumer.config = SimpleNamespace(network_config_path=path)
                with self.assertRaises(ConsumerV8Error):
                    consumer._load_settlement_config()
            self.assertEqual(loaded.network_id, "mycomesh-v9-controlled-test")
            self.assertEqual(loaded.deployment.committee_mode, "controlled_test")


class ControlledOperatorTests(V9Fixture, unittest.TestCase):
    def settings(self):
        return dict(committee_mode="controlled_test", allow_controlled_test=True,
                    independence_attested=False,
                    adjudicator_operators={address: "mycomesh-controlled-test-operator"
                                           for address in self.config.adjudicators})

    def test_controlled_operator_requires_explicit_honest_configuration(self):
        options = self.settings()
        valid = replace(self.config, **options)
        self.assertEqual(valid.domain["committee_mode"], "controlled_test")
        self.assertNotIn("committee_mode", self.config.domain)
        for change in ({"allow_controlled_test": False}, {"allow_controlled_test": 1},
                       {"independence_attested": True}, {"chain_id": 1},
                       {"committee_mode": "independent_users"},
                       {"adjudicator_operators": self.config.adjudicator_operators}):
            with self.subTest(change=change), self.assertRaises(V9AdjudicationError):
                replace(self.config, **{**options, **change})

    def test_operator_still_rejects_reporter_and_weak_quorum(self):
        for change in ({"reporter_address": self.config.adjudicators[0]}, {"threshold": 1}):
            with self.subTest(change=change), self.assertRaises(V9AdjudicationError):
                replace(self.config, **{**self.settings(), **change})


if __name__ == "__main__":
    unittest.main()
