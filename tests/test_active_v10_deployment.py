from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gateway.chain import ChainError, load_active_myco_deployment
from gateway.chain_v10 import V10Deployment
from tests.test_chain_v9 import address, deployment_manifest, digest


class ActiveV10DeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'deployment.json'
        self.manifest = {**deployment_manifest(), 'protocol_version': 10,
            'eip712_version': '10', 'chain_domain': '10',
            'reservation_mode': 'provider_bound_channel',
            'max_authorization_ttl_seconds': 10800, 'authorization_deadline_seconds': 9000,
            'capacity_channel_ids': [digest(101), digest(102), digest(103)]}
        self.path.write_text(json.dumps(self.manifest))
        self.env = {'MYCOMESH_SETTLEMENT_VERSION': '10', 'MYCO_DEPLOYMENT': str(self.path)}

    def test_environment_dispatches_to_real_v10_loader(self):
        with patch.dict(os.environ, self.env, clear=True):
            actual = load_active_myco_deployment()
        self.assertIsInstance(actual, V10Deployment)
        self.assertEqual(actual.protocol_version, 10)
        self.assertEqual(actual.eip712_version, '10')
        self.assertEqual(actual.capacity_channel_ids, tuple(self.manifest['capacity_channel_ids']))

    def test_explicit_version_and_path_use_same_loader(self):
        actual = load_active_myco_deployment(self.path, settlement_version=10, env={})
        self.assertIsInstance(actual, V10Deployment)

    def test_no_implicit_v10_manifest(self):
        with self.assertRaisesRegex(ChainError, 'explicit deployment manifest'):
            load_active_myco_deployment(env={'MYCOMESH_SETTLEMENT_VERSION': '10'})

    def test_v9_manifest_is_rejected_by_v10_dispatch(self):
        self.path.write_text(json.dumps(deployment_manifest()))
        with self.assertRaises(ChainError):
            load_active_myco_deployment(env=self.env)

    def test_configured_contract_and_chain_are_pinned(self):
        for overrides in ({'MYCOMESH_SETTLEMENT_CONTRACT': address(99)},
                          {'MYCOMESH_SESSION_SETTLEMENT_CONTRACT': address(99)},
                          {'MYCOMESH_SETTLEMENT_CHAIN_ID': '1'},
                          {'MYCOMESH_SESSION_CHAIN_ID': '1'}):
            with self.subTest(overrides=overrides), self.assertRaises(ChainError):
                load_active_myco_deployment(env={**self.env, **overrides})

    def test_v10_optin_is_separate_from_v9(self):
        controlled = {**self.manifest, 'committee_mode': 'controlled_test',
            'independence_attested': False,
            'network_id': 'mycomesh-v10-fixed-budget-controlled-test',
            'reward_token': address(0),
            'policy': {**self.manifest['policy'], 'token_reward': 0, 'token_reward_cap': 0,
                       'token_minimum_exposure': 0, 'token_minimum_penalty': 0},
            'adjudicator_operators': {a: 'same-test-operator' for a in self.manifest['adjudicators']}}
        self.path.write_text(json.dumps(controlled))
        for switches in ({}, {'MYCOMESH_ALLOW_CONTROLLED_V9_TEST': '1'}):
            with self.subTest(switches=switches), self.assertRaises(ChainError):
                load_active_myco_deployment(env={**self.env, **switches})
        actual = load_active_myco_deployment(env={**self.env, 'MYCOMESH_ALLOW_CONTROLLED_V10_TEST': '1'})
        self.assertEqual(actual.committee_mode, 'controlled_test')

    def test_v9_dispatch_remains_v9(self):
        self.path.write_text(json.dumps(deployment_manifest()))
        actual = load_active_myco_deployment(env={**self.env, 'MYCOMESH_SETTLEMENT_VERSION': '9'})
        self.assertEqual(actual.protocol_version, 9)
        self.assertNotIsInstance(actual, V10Deployment)


if __name__ == '__main__':
    unittest.main()
