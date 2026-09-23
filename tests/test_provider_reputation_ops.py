from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from gateway import chain, pool
from gateway.identity import create_identity, save_identity
from gateway.provider_reputation_ops import (
    DYNAMIC_JURY_MODE,
    OPS_POLICY_SCHEMA,
    ProviderReputationOpsError,
    authority_action_status,
    build_signed_pool_snapshot,
    execute_authority_action,
    load_ops_context,
    propose_authority_action,
    reconcile_authority_action,
)
from gateway.provider_reputation_sync import ProviderReputationOutbox
from gateway.provider_reputation_sync import HISTORY_IMPORT_SCHEMA
from gateway.relay_incidents import evidence_hash
from gateway.v10_reputation import FEEDBACK_SCHEMA, reputation_event_id


def address(number: int) -> str:
    return "0x" + f"{number:040x}"


def digest(number: int) -> str:
    return "0x" + f"{number:064x}"


def write_json(path: Path, value: object, *, mode: int = 0o644) -> bytes:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(raw)
    os.chmod(path, mode)
    return raw


class FakeOutbox:
    def __init__(self, action_hash: str) -> None:
        self.action_hash = action_hash

    def get(self, value: str):
        if value != self.action_hash:
            return None
        return {"action_hash": value, "state": "proposed"}


class FakeSync:
    instances: list["FakeSync"] = []
    action_hash = digest(900)

    def __init__(self, config, **kwargs) -> None:
        self.config = config
        self.kwargs = kwargs
        self.closed = False
        self.outbox = FakeOutbox(self.action_hash)
        self.__class__.instances.append(self)

    def propose(self, snapshot, descriptor):
        return {
            "state": "proposed", "action_hash": self.action_hash,
            "sender": self.kwargs["sender"],
            "action": {
                "provider": {"owner": address(15)},
                "source": {"peer_id": "peer_test", "sequence": 1},
            },
        }

    def execute(self, action_hash):
        return {
            "state": "submitted", "action_hash": action_hash,
            "tx_hash": digest(901), "sender": self.kwargs["sender"],
        }

    def reconcile(self, action_hash):
        return {
            "status": "submitted", "action_hash": action_hash,
            "tx_hash": digest(901), "sender": self.kwargs["sender"],
        }

    def close(self):
        self.closed = True


class ProviderReputationOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = create_identity()
        self.provider_identity = create_identity()
        self.network_id = "mycomesh-dynamic-jury-controlled-test"
        self.registry = address(11)
        self.settlement = address(12)
        self.governance = address(13)
        self.authority = address(14)
        self.runtime_hash = digest(101)
        self.settlement_runtime_hash = digest(108)
        self.settlement_deployment_block = 80
        self.settlement_deployment_block_hash = digest(109)
        self.policy_hash = digest(102)
        self.genesis_hash = digest(103)
        self.rpc_url = "https://rpc.example.test"
        self.deployment_path = self.root / "deployment.json"
        self.network_path = self.root / "network.json"
        self.policy_path = self.root / "ops-policy.json"
        self.history_path = self.root / "reputation-history.json"
        history_event = {
            "schema": FEEDBACK_SCHEMA,
            "network_id": "mycomesh-v9-history",
            "chain_id": 31337,
            "settlement_contract": address(112),
            "settlement_key": digest(201),
            "request_id": digest(202),
            "provider_owner": address(113),
            "provider_signer": address(16),
            "peer_id": self.provider_identity.peer_id,
            "tx_hash": digest(203),
            "log_index": 0,
            "block_number": 100,
            "block_hash": digest(204),
            "terminal_status": "released",
            "outcome": "positive",
        }
        self.history_artifact = {
            "schema": HISTORY_IMPORT_SCHEMA,
            "source": {
                "network_id": "mycomesh-v9-history",
                "protocol_version": 9,
                "chain_id": 31337,
                "genesis_hash": self.genesis_hash,
                "settlement_contract": address(112),
                "runtime_code_hash": digest(105),
                "confirmations": 6,
                "source_deployment_block": 90,
                "source_deployment_block_hash": digest(106),
                "source_history_through_block": 120,
                "source_history_through_block_hash": digest(107),
            },
            "entries": [{
                "peer_id": self.provider_identity.peer_id,
                "provider_signer": address(16),
                "events": [history_event],
            }],
        }
        history_raw = write_json(self.history_path, self.history_artifact)
        self.history_lineage = {
            "schema": HISTORY_IMPORT_SCHEMA,
            "source_network_id": "mycomesh-v9-history",
            "source_protocol_version": 9,
            "source_chain_id": 31337,
            "source_genesis_hash": self.genesis_hash,
            "source_settlement_contract": address(112),
            "source_runtime_code_hash": digest(105),
            "confirmations": 6,
            "source_deployment_block": 90,
            "source_deployment_block_hash": digest(106),
            "source_history_through_block": 120,
            "source_history_through_block_hash": digest(107),
            "artifact_sha256": hashlib.sha256(history_raw).hexdigest(),
            "artifact_root": evidence_hash(self.history_artifact),
        }
        self.deployment = {
            "protocol_version": 10,
            "deployment_class": "controlled_test",
            "network_id": self.network_id,
            "chain_id": 31337,
            "genesis_hash": self.genesis_hash,
            "settlement": self.settlement,
            "settlement_runtime_code_keccak256": self.settlement_runtime_hash,
            "deployment_block": self.settlement_deployment_block,
            "deployment_block_hash": self.settlement_deployment_block_hash,
            "governance": self.governance,
            "committee_mode": DYNAMIC_JURY_MODE,
            "jury_randomness": "future_blockhash_v1",
            "jury_registry": self.registry,
            "jury_registry_governance": self.governance,
            "reputation_authority": self.authority,
            "minimum_provider_reputation": 80,
            "jury_decision_policy_hash": self.policy_hash,
            "jury_registry_runtime_code_hash": self.runtime_hash,
            "reputation_history_import": dict(self.history_lineage),
        }
        self.network = {
            "protocol_version": 10,
            "network_id": self.network_id,
            "deployment": self.deployment_path.name,
            "settlement_rpc_url": self.rpc_url,
            "settlement_rpc_urls": [self.rpc_url, "https://rpc2.example.test"],
            "reputation_history_import": dict(self.history_lineage),
        }
        self._rewrite_configs()
        self.context = self.load()
        FakeSync.instances.clear()

    def _rewrite_configs(self) -> None:
        deployment_raw = write_json(self.deployment_path, self.deployment)
        network_raw = write_json(self.network_path, self.network)
        self.ops_policy = {
            "schema": OPS_POLICY_SCHEMA,
            "deployment_class": "controlled_test",
            "deployment_sha256": hashlib.sha256(deployment_raw).hexdigest(),
            "network_sha256": hashlib.sha256(network_raw).hexdigest(),
            "network_id": self.network_id,
            "chain_id": 31337,
            "genesis_hash": self.genesis_hash,
            "settlement_contract": self.settlement,
            "jury_registry": self.registry,
            "registry_runtime_code_hash": self.runtime_hash,
            "reputation_authority": self.authority,
            "minimum_reputation": 80,
            "decision_policy_hash": self.policy_hash,
            "pool_snapshot_public_key": self.identity.public_key,
            "snapshot_audience": self.registry,
            "descriptor_audience": "https://pool.example.test",
            "rpc_url": self.rpc_url,
            "confirmations": 3,
            "max_snapshot_age_seconds": 300,
            "max_descriptor_age_seconds": 300,
            "reputation_history_import": {
                "filename": self.history_path.name,
                "artifact_sha256": self.history_lineage["artifact_sha256"],
                "artifact_root": self.history_lineage["artifact_root"],
            },
        }
        write_json(self.policy_path, self.ops_policy)

    def load(self):
        return load_ops_context(
            self.policy_path, self.network_path, self.deployment_path,
        )

    def reputation_event(self, number: int) -> dict:
        return {
            "schema": FEEDBACK_SCHEMA,
            "network_id": self.network_id,
            "chain_id": 31337,
            "settlement_contract": self.settlement,
            "settlement_key": digest(1_000 + number),
            "request_id": digest(2_000 + number),
            "provider_owner": address(15),
            "provider_signer": address(16),
            "peer_id": self.provider_identity.peer_id,
            "tx_hash": digest(3_000 + number),
            "log_index": 0,
            "block_number": number,
            "block_hash": digest(4_000 + number),
            "terminal_status": "released",
            "outcome": "positive",
        }

    def test_loads_exact_dynamic_policy_with_pinned_history(self) -> None:
        context = self.context
        self.assertEqual(context.authority_sender, self.authority)
        self.assertEqual(context.config.jury_registry, self.registry)
        self.assertEqual(
            context.config.settlement_runtime_code_hash,
            self.settlement_runtime_hash,
        )
        self.assertEqual(
            context.config.settlement_deployment_block,
            self.settlement_deployment_block,
        )
        self.assertEqual(
            context.config.settlement_deployment_block_hash,
            self.settlement_deployment_block_hash,
        )
        self.assertEqual(context.config.minimum_reputation, 80)
        self.assertEqual(
            context.config.pool_snapshot_public_keys,
            (self.identity.public_key,),
        )
        self.assertEqual(
            context.config.history_import.lineage(), self.history_lineage,
        )

    def test_history_import_is_required_and_exactly_bound(self) -> None:
        self._rewrite_configs()
        policy = dict(self.ops_policy)
        policy.pop("reputation_history_import")
        write_json(self.policy_path, policy)
        with self.assertRaisesRegex(ProviderReputationOpsError, "unknown or missing"):
            self.load()

        self.network["reputation_history_import"] = {
            **self.history_lineage, "artifact_root": digest(999),
        }
        self._rewrite_configs()
        with self.assertRaisesRegex(ProviderReputationOpsError, "lineage differs"):
            self.load()

    def test_rejects_static_manifest_even_when_file_hash_is_rebound(self) -> None:
        self.deployment["committee_mode"] = "controlled_test"
        self.deployment["adjudicators"] = [address(55)]
        self._rewrite_configs()
        with self.assertRaisesRegex(ProviderReputationOpsError, "dynamic Provider-AI"):
            self.load()

    def test_rejects_policy_authority_runtime_and_decision_hash_drift(self) -> None:
        cases = (
            ("reputation_authority", address(99), "independent authority"),
            ("registry_runtime_code_hash", digest(999), "runtime code hash differs"),
            ("decision_policy_hash", digest(998), "decision policy hash differs"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                self._rewrite_configs()
                policy = dict(self.ops_policy)
                policy[field] = value
                write_json(self.policy_path, policy)
                with self.assertRaisesRegex(ProviderReputationOpsError, message):
                    self.load()

    def test_target_settlement_boundary_is_required_from_deployment(self) -> None:
        for field in (
            "settlement_runtime_code_keccak256",
            "deployment_block",
            "deployment_block_hash",
        ):
            with self.subTest(field=field):
                self.deployment.pop(field)
                self._rewrite_configs()
                with self.assertRaises(ProviderReputationOpsError):
                    self.load()
                self.deployment.update({
                    "settlement_runtime_code_keccak256": self.settlement_runtime_hash,
                    "deployment_block": self.settlement_deployment_block,
                    "deployment_block_hash": self.settlement_deployment_block_hash,
                })

    def test_snapshot_uses_existing_identity_store_and_incrementing_sequence(self) -> None:
        identity_path = self.root / "pool-identity.json"
        save_identity(identity_path, self.identity)
        reputation_path = self.root / "pool-reputation.json"
        config = pool.PoolConfig(reputation_path=str(reputation_path))
        proofs = [self.reputation_event(201), self.reputation_event(202)]
        config.reputation[self.provider_identity.peer_id] = {
            "successes": 2, "settlements": 2,
        }
        config.reputation_events[self.provider_identity.peer_id] = {
            reputation_event_id(event) for event in proofs
        }
        config.reputation_proofs[self.provider_identity.peer_id] = {
            reputation_event_id(event): event for event in proofs
        }
        pool.save_pool_reputation(config)
        sequence_path = self.root / "snapshot-sequences.sqlite3"
        now = 2_000_000_000
        first = build_signed_pool_snapshot(
            self.context,
            identity_path=identity_path,
            reputation_store_path=reputation_path,
            sequence_store_path=sequence_path,
            peer_id=self.provider_identity.peer_id,
            sequence=1,
            now=now,
        )
        self.assertEqual(first["sequence"], 1)
        self.assertEqual(first["signature"]["public_key"], self.identity.public_key)
        repeated = build_signed_pool_snapshot(
            self.context,
            identity_path=identity_path,
            reputation_store_path=reputation_path,
            sequence_store_path=sequence_path,
            peer_id=self.provider_identity.peer_id,
            sequence=1,
            now=now,
        )
        self.assertEqual(repeated, first)
        with self.assertRaisesRegex(ProviderReputationOpsError, "increment"):
            build_signed_pool_snapshot(
                self.context,
                identity_path=identity_path,
                reputation_store_path=reputation_path,
                sequence_store_path=sequence_path,
                peer_id=self.provider_identity.peer_id,
                sequence=3,
                now=now,
            )

        rogue_path = self.root / "rogue-identity.json"
        save_identity(rogue_path, create_identity())
        with self.assertRaisesRegex(ProviderReputationOpsError, "pinned"):
            build_signed_pool_snapshot(
                self.context,
                identity_path=rogue_path,
                reputation_store_path=reputation_path,
                sequence_store_path=self.root / "rogue-sequence.sqlite3",
                peer_id=self.provider_identity.peer_id,
                sequence=1,
                now=now,
            )

    def test_snapshot_can_bootstrap_from_history_with_empty_live_store(self) -> None:
        identity_path = self.root / "history-pool-identity.json"
        save_identity(identity_path, self.identity)
        reputation_path = self.root / "empty-pool-reputation.json"
        write_json(
            reputation_path,
            {"schema": pool.POOL_REPUTATION_STORE_SCHEMA, "proofs": {}},
        )
        snapshot = build_signed_pool_snapshot(
            self.context,
            identity_path=identity_path,
            reputation_store_path=reputation_path,
            sequence_store_path=self.root / "history-sequences.sqlite3",
            peer_id=self.provider_identity.peer_id,
            sequence=1,
            now=2_000_000_000,
        )
        self.assertEqual(snapshot["receipt_count"], 1)
        self.assertEqual(snapshot["history_import"], self.history_lineage)

    def test_propose_is_no_send_and_closes_runtime(self) -> None:
        snapshot_path = self.root / "snapshot.json"
        descriptor_path = self.root / "descriptor.json"
        write_json(snapshot_path, {"signed": "snapshot"})
        write_json(descriptor_path, {"signed": "descriptor"})
        row = propose_authority_action(
            self.context,
            outbox_path=self.root / "outbox.sqlite3",
            snapshot_path=snapshot_path,
            descriptor_path=descriptor_path,
            sync_factory=FakeSync,
        )
        self.assertEqual(row["state"], "proposed")
        instance = FakeSync.instances[-1]
        self.assertFalse(instance.kwargs["execution_enabled"])
        self.assertFalse(instance.kwargs["dedicated_sender"])
        self.assertTrue(instance.closed)

    def test_execute_requires_send_exact_hash_key_and_gas_caps(self) -> None:
        key_path = self.root / "authority.key"
        key_path.write_text("11" * 32 + "\n", encoding="ascii")
        os.chmod(key_path, 0o600)
        with self.assertRaisesRegex(ProviderReputationOpsError, "--send"):
            execute_authority_action(
                self.context,
                outbox_path=self.root / "outbox.sqlite3",
                action_hash=FakeSync.action_hash,
                send=False,
                key_file=key_path,
                max_gas_price_wei=10,
                max_gas_units=200_000,
                max_total_gas_cost_wei=2_000_000,
                sync_factory=FakeSync,
            )
        with self.assertRaisesRegex(ProviderReputationOpsError, "canonical action hash"):
            execute_authority_action(
                self.context,
                outbox_path=self.root / "outbox.sqlite3",
                action_hash="not-a-hash",
                send=True,
                key_file=key_path,
                max_gas_price_wei=10,
                max_gas_units=200_000,
                max_total_gas_cost_wei=2_000_000,
                sync_factory=FakeSync,
            )
        result = execute_authority_action(
            self.context,
            outbox_path=self.root / "outbox.sqlite3",
            action_hash=FakeSync.action_hash,
            send=True,
            key_file=key_path,
            max_gas_price_wei=10,
            max_gas_units=200_000,
            max_total_gas_cost_wei=2_000_000,
            sync_factory=FakeSync,
        )
        self.assertEqual(result["state"], "submitted")
        instance = FakeSync.instances[-1]
        self.assertTrue(instance.kwargs["execution_enabled"])
        self.assertTrue(instance.kwargs["dedicated_sender"])
        self.assertEqual(instance.kwargs["max_gas_units"], 200_000)
        self.assertTrue(instance.closed)

    def test_reconcile_and_status_are_bound_to_dynamic_deployment(self) -> None:
        reconciled = reconcile_authority_action(
            self.context,
            outbox_path=self.root / "fake.sqlite3",
            action_hash=FakeSync.action_hash,
            sync_factory=FakeSync,
        )
        self.assertEqual(reconciled["status"], "submitted")
        self.assertTrue(FakeSync.instances[-1].closed)

        outbox_path = self.root / "status.sqlite3"
        outbox = ProviderReputationOutbox(outbox_path)
        body = {
            "schema": "mycomesh.v10.provider-reputation-action.v1",
            "network_id": self.network_id,
            "chain_id": 31337,
            "genesis_hash": self.genesis_hash,
            "scope": f"{self.genesis_hash}:31337",
            "sender": self.authority,
            "target": self.registry,
            "source": {
                "pool_public_key": self.identity.public_key,
                "peer_id": self.provider_identity.peer_id,
                "sequence": 1,
                "snapshot_hash": digest(301),
                "source_digest": digest(302),
                "descriptor_hash": digest(303),
                "snapshot_observed_at": 1,
                "descriptor_timestamp": 1,
                "receipt_count": 0,
            },
            "provider": {"owner": address(77)},
            "calldata": "0x1234",
        }
        action = {**body, "action_hash": evidence_hash(body)}
        saved = outbox.propose(action)
        outbox.close()
        status = authority_action_status(
            self.context, outbox_path=outbox_path,
            action_hash=saved["action_hash"],
        )
        self.assertEqual(status["state"], "proposed")
        self.assertEqual(status["action_hash"], saved["action_hash"])

    def test_secret_files_must_not_be_group_readable(self) -> None:
        identity_path = self.root / "pool-identity.json"
        save_identity(identity_path, self.identity)
        os.chmod(identity_path, 0o640)
        reputation_path = self.root / "pool-reputation.json"
        write_json(
            reputation_path,
            {
                "schema": pool.POOL_REPUTATION_STORE_SCHEMA,
                "proofs": {
                    self.provider_identity.peer_id: [self.reputation_event(1)]
                },
            },
            mode=0o600,
        )
        with self.assertRaisesRegex(ProviderReputationOpsError, "0600"):
            build_signed_pool_snapshot(
                self.context,
                identity_path=identity_path,
                reputation_store_path=reputation_path,
                sequence_store_path=self.root / "sequences.sqlite3",
                peer_id=self.provider_identity.peer_id,
                sequence=1,
            )


if __name__ == "__main__":
    unittest.main()
