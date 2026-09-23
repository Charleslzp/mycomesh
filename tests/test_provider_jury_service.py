from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from gateway import chain, chain_v10, provider_jury
from gateway.identity import create_identity
from gateway.provider_bootstrap import ProviderNetworkConfig
from gateway.provider_jury_service import (
    ProviderJuryServiceError,
    ProviderJuryServiceFactories,
    load_provider_jury_service_config,
    resolve_provider_descriptor,
)
from tests.test_chain_v9 import address, digest, key, signer


class ProviderJuryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = create_identity()
        self.policy = {
            "schema": provider_jury.POLICY_SCHEMA,
            "model": "judge-model",
            "system_prompt": "Apply the pinned fraud policy.",
            "max_output_tokens": 512,
            "task_ttl_seconds": 300,
        }
        self.policy_hash = provider_jury.decision_policy_hash(
            model=self.policy["model"],
            system_prompt=self.policy["system_prompt"],
            max_output_tokens=self.policy["max_output_tokens"],
            task_ttl_seconds=self.policy["task_ttl_seconds"],
        )
        self.policy_path = self.root / "jury-policy.json"
        self.policy_path.write_text(json.dumps(self.policy))
        self.policy_path.chmod(0o600)
        self.sender = signer(90)
        self.network_path = self.root / "network.json"
        self.deployment_path = self.root / "deployment.json"
        self.network_path.write_text(json.dumps({
            "network_id": "fixture",
            "deployment": "deployment.json",
            "settlement_rpc_url": "https://rpc.example",
            "settlement_rpc_urls": [
                "https://rpc.example", "https://rpc-backup.example",
            ],
            "jury_relay_public_keys": [self.identity.public_key],
            "jury_transaction_senders": {
                self.identity.public_key: self.sender,
            },
            "jury_decision_policy_hash": self.policy_hash,
        }))
        self.deployment_path.write_text(json.dumps({
            "protocol_version": 10,
            "committee_mode": chain_v10.DYNAMIC_PROVIDER_JURY,
            "chain_id": 31337,
            "settlement": address(50),
            "jury_registry": address(51),
            "jury_decision_policy_hash": self.policy_hash,
            "deployment_block": 10,
            "genesis_hash": digest(100),
            "settlement_runtime_code_keccak256": digest(101),
            "jury_registry_runtime_code_keccak256": digest(102),
            "confirmations": 3,
        }))
        deployment = SimpleNamespace(
            protocol_version=10,
            committee_mode=chain_v10.DYNAMIC_PROVIDER_JURY,
            chain_id=31337,
            deployment_block=10,
            settlement=address(50),
            jury_registry=address(51),
            jury_registry_governance=address(52),
            reputation_authority=address(53),
            treasury=address(55),
            policy={"bond_penalty_recipient": address(54)},
            minimum_provider_reputation=80,
            jury_size=3,
            adjudication_threshold=2,
            jury_selection_delay_blocks=2,
            jury_decision_policy_hash=self.policy_hash,
        )
        self.network = ProviderNetworkConfig(
            path=self.network_path,
            network_id="fixture",
            channel_id="codex",
            backend_policy="fixture",
            deployment_path=self.deployment_path,
            deployment=deployment,
            settlement_rpc_url="https://rpc.example",
            settlement_rpc_urls=(
                "https://rpc.example", "https://rpc-backup.example",
            ),
            public_model_id="judge-model",
            public_model_ids=("judge-model",),
            reserve_input_bytes=1000,
            reserve_output_tokens=100,
            bridge_urls=("https://bridge.example",),
            consumer_public_keys=(),
            provider_transport="relay",
            relay_host="relay.example",
            relay_port=443,
            relay_public_url="https://relay.example",
            relay_provider_tls=True,
            relay_payment_address=address(60),
            relay_attestation_address=address(61),
            jury_relay_public_keys=(self.identity.public_key,),
            jury_transaction_senders={self.identity.public_key: self.sender},
            jury_decision_policy_hash=self.policy_hash,
        )

    def paths(self) -> dict:
        return {
            "policy_path": self.policy_path,
            "worker_db_path": self.root / "worker.sqlite3",
            "transaction_db_path": self.root / "transactions.sqlite3",
            "intake_db_path": self.root / "intake.sqlite3",
        }

    def config(self, **changes):
        values = {
            "jury_relay_public_key": self.identity.public_key,
            "rpc_url": "https://rpc.example",
            **self.paths(),
            "execution_enabled": False,
        }
        values.update(changes)
        return load_provider_jury_service_config(self.network, **values)

    def test_manifest_pins_build_all_chain_and_intake_inputs(self) -> None:
        configured = self.config()
        chain_config = configured.chain_config()
        self.assertEqual(chain_config.genesis_hash, digest(100))
        self.assertEqual(chain_config.settlement_runtime_code_hash, digest(101))
        self.assertEqual(chain_config.registry_runtime_code_hash, digest(102))
        self.assertEqual(
            chain_config.rpc_urls,
            ("https://rpc.example", "https://rpc-backup.example"),
        )
        self.assertEqual(configured.transaction_sender, self.sender)
        self.assertEqual(configured.confirmations, 3)
        self.assertEqual(configured.deployment_block, 10)

    def test_missing_manifest_pin_and_unpinned_rpc_fail_closed(self) -> None:
        value = json.loads(self.deployment_path.read_text())
        value.pop("jury_registry_runtime_code_keccak256")
        self.deployment_path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ProviderJuryServiceError, "missing jury runtime pins"):
            self.config()
        self.deployment_path.write_text(json.dumps({
            **value, "jury_registry_runtime_code_keccak256": digest(102),
        }))
        with self.assertRaisesRegex(ProviderJuryServiceError, "one RPC pinned"):
            self.config(rpc_url="https://other.example")

    def test_service_rejects_single_endpoint_manifest_for_runtime_reads(self) -> None:
        self.network = replace(
            self.network, settlement_rpc_urls=("https://rpc.example",),
        )
        payload = json.loads(self.network_path.read_text())
        payload["settlement_rpc_urls"] = ["https://rpc.example"]
        self.network_path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ProviderJuryServiceError, "multi-RPC"):
            self.config()

    def test_execution_requires_protected_matching_key_and_all_caps(self) -> None:
        key_path = self.root / "jury.key"
        key_path.write_text(key(90))
        key_path.chmod(0o600)
        with self.assertRaisesRegex(ProviderJuryServiceError, "all three positive gas caps"):
            self.config(execution_enabled=True, transaction_key_file=key_path)
        configured = self.config(
            execution_enabled=True,
            transaction_key_file=key_path,
            max_gas_price_wei=10,
            max_gas_units=500_000,
            max_total_gas_cost_wei=5_000_000,
        )
        self.assertTrue(configured.execution_enabled)
        with self.assertRaisesRegex(ProviderJuryServiceError, "explicit execution"):
            self.config(max_gas_price_wei=10)

    def test_each_relay_identity_selects_its_own_dedicated_sender(self) -> None:
        other_identity = create_identity()
        other_sender = signer(91)
        senders = {
            self.identity.public_key: self.sender,
            other_identity.public_key: other_sender,
        }
        keys = (self.identity.public_key, other_identity.public_key)
        self.network = replace(
            self.network,
            jury_relay_public_keys=keys,
            jury_transaction_senders=senders,
        )
        payload = json.loads(self.network_path.read_text())
        payload["jury_relay_public_keys"] = list(keys)
        payload["jury_transaction_senders"] = senders
        self.network_path.write_text(json.dumps(payload))
        configured = self.config(jury_relay_public_key=other_identity.public_key)
        self.assertEqual(configured.transaction_sender, other_sender)
        with self.assertRaisesRegex(ProviderJuryServiceError, "not pinned"):
            self.config(jury_relay_public_key=create_identity().public_key)

    def provider_session(self):
        provider_identity = create_identity()
        owner, vote_signer = address(70), address(71)
        capability = {
            "schema": provider_jury.CAPABILITY_SCHEMA,
            "models": ["judge-model"],
            "max_output_tokens": 512,
            "supports_structured_verdict": True,
            "decision_policy_hash": self.policy_hash,
        }
        operator_id = "operator-a"
        descriptor = {
            "schema": "mycomesh.provider-jury.descriptor.v1",
            "provider_owner": owner,
            "vote_signer": vote_signer,
            "operator_id": operator_id,
            "operator_id_hash": provider_jury._keccak_text(operator_id),
            "peer_id_hash": provider_jury._keccak_text(provider_identity.peer_id),
            "capability": capability,
            "capability_hash": provider_jury.capability_hash(capability),
        }
        session = SimpleNamespace(
            authenticated_signer=vote_signer,
            peer={
                "peer_id": provider_identity.peer_id,
                "public_key": provider_identity.public_key,
                "network_id": "fixture",
                "payment_address": owner,
                "secure_transport_required": True,
                "transport_key": {"key": "fixture"},
                "settlement": {
                    "version": 10,
                    "chain_id": 31337,
                    "contract": address(50),
                    "provider_signer": vote_signer,
                },
                "provider_jury": descriptor,
            },
        )
        snapshot = {
            "owner": owner,
            "vote_signer": vote_signer,
            "operator_id_hash": descriptor["operator_id_hash"],
            "peer_id_hash": descriptor["peer_id_hash"],
            "capability_hash": descriptor["capability_hash"],
            "reputation": 95,
        }
        return provider_identity.peer_id, session, snapshot

    def test_resolver_uses_authenticated_relay_descriptor(self) -> None:
        configured = self.config()
        peer_id, session, snapshot = self.provider_session()
        state = SimpleNamespace(
            lock=__import__("threading").RLock(), providers={peer_id: session},
        )
        with patch("gateway.relay._require_provider_admissible") as admissible:
            selected = resolve_provider_descriptor(state, snapshot, configured)
        self.assertEqual(selected["peer_id"], peer_id)
        self.assertEqual(selected["reputation"], 95)
        admissible.assert_called_once_with(state, session)
        session.authenticated_signer = address(99)
        with self.assertRaisesRegex(ProviderJuryServiceError, "unavailable"):
            resolve_provider_descriptor(state, snapshot, configured)

    def test_factories_bind_state_and_verify_chain_before_runtime(self) -> None:
        configured = self.config()
        state = SimpleNamespace(
            _jury_identity=self.identity,
            _provider_jury_intake=SimpleNamespace(ready=lambda: True),
            provider_jury_case_intake_health=lambda: True,
            payment_address=address(60),
            attestation_address=address(61),
            settlement_private_key=None,
            lock=__import__("threading").RLock(),
            providers={},
        )
        adapter = Mock()
        adapter.confirmed_context.return_value = {"block_number": 10}
        adapter.config = configured.chain_config()
        adapter.execution_enabled = False
        worker = Mock()
        worker.network_id = "fixture"
        worker.chain_id = 31337
        worker.settlement_contract = address(50)
        worker.jury_registry = address(51)
        worker.minimum_reputation = 80
        worker.jury_size = 3
        worker.adjudication_threshold = 2
        worker.required_confirmations = 3
        worker.decision_policy_hash = self.policy_hash
        worker.execution_enabled = False
        runtime = Mock()
        factories = ProviderJuryServiceFactories(
            configured, evidence_resolver=lambda _snapshot: {},
        )
        with patch(
            "gateway.provider_jury_service.ProviderJuryChainAdapter",
            return_value=adapter,
        ) as adapter_type, patch(
            "gateway.provider_jury_service.ProviderJuryRelayWorker",
            return_value=worker,
        ), patch(
            "gateway.provider_jury_service.ProviderJuryRuntime",
            return_value=runtime,
        ) as runtime_type:
            self.assertIs(factories.runtime_factory(state), runtime)
        adapter.confirmed_context.assert_called_once()
        chain_args, chain_kwargs = adapter_type.call_args
        self.assertEqual(
            chain_args[0].rpc_urls,
            ("https://rpc.example", "https://rpc-backup.example"),
        )
        self.assertNotIn("rpc", chain_kwargs)
        self.assertNotIn("allow_test_rpc_override", chain_kwargs)
        kwargs = runtime_type.call_args.kwargs
        self.assertTrue(callable(kwargs["invoke_provider"]))
        self.assertTrue(kwargs["case_intake_health"]())


if __name__ == "__main__":
    unittest.main()
