from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from gateway import provider_jury
from gateway.identity import create_identity
from gateway.provider_jury_runtime import ProviderJuryRuntime
from gateway.provider_jury_worker import ASSIGNMENT_SCHEMA, ProviderJuryRelayWorker
from gateway.relay_incidents import evidence_hash
from tests.test_chain_v9 import address, digest, key, signer


class _FixtureChain:
    """Read-only assignment + receipt fixture; no RPC or wallet is used."""

    def __init__(self, *, assignment: dict, contract: str, registry: str,
                 settlement_key: str, sender: str) -> None:
        self.config = SimpleNamespace(
            network_id="controlled-fixture",
            chain_id=31337,
            settlement_contract=contract,
            jury_registry=registry,
            minimum_reputation=80,
            jury_size=3,
            adjudication_threshold=2,
            confirmations=2,
        )
        self.execution_enabled = True
        self.assignment = assignment
        self.contract = contract
        self.registry = registry
        self.settlement_key = settlement_key
        self.sender = sender
        self.calls: list[str] = []
        self.broadcasted: list[dict] = []
        self.inspect_count = 0
        self.last_plan: dict | None = None

    def fetch_assignment(self, binding):
        self.calls.append("fetch")
        self.assert_binding(binding)
        return {
            "schema": ASSIGNMENT_SCHEMA,
            "status": "pending",
            "network_id": binding["network_id"],
            "chain_id": binding["chain_id"],
            "settlement_contract": binding["settlement_contract"],
            "jury_registry": binding["jury_registry"],
            "settlement_key": binding["settlement_key"],
        }

    def finalize_assignment(self, binding, pending):
        self.calls.append("finalize")
        self.assert_binding(binding)
        assert pending["status"] == "pending"
        return dict(self.assignment)

    def preflight(self, plan):
        self.calls.append("preflight")
        self.last_plan = dict(plan)
        vote = plan["evm_vote"]
        self.assert_equal(vote["settlement_key"], self.settlement_key)
        self.assert_equal(vote["settlement_contract"], self.contract)
        self.assert_equal(vote["to"], self.contract)
        self.assert_equal(vote["value"], "0x0")
        self.assert_true(vote["data"].startswith("0x"))
        self.assert_equal(len(vote["votes"]), 2)
        self.assert_equal(len(vote["vote_permits"]), 2)
        self.assert_equal(
            {permit["decision_hash"] for permit in vote["vote_permits"]},
            {vote["decision_hash"]},
        )

    def broadcast(self, plan):
        self.calls.append("broadcast")
        self.last_plan = dict(plan)
        self.broadcasted.append(dict(plan))
        vote = plan["evm_vote"]
        return {
            "status": "submitted",
            "tx_hash": digest(500),
            "plan_hash": plan["plan_hash"],
            "chain_id": vote["chain_id"],
            "settlement_contract": vote["settlement_contract"],
            "sender": self.sender,
            "nonce": 7,
        }

    def inspect(self, plan, current):
        self.calls.append("inspect")
        self.assert_equal(current["result"]["tx_hash"], digest(500))
        self.inspect_count += 1
        if self.inspect_count == 1:
            return {
                "status": "uncertain",
                "tx_hash": digest(500),
                "plan_hash": plan["plan_hash"],
                "chain_id": plan["evm_vote"]["chain_id"],
                "settlement_contract": plan["evm_vote"]["settlement_contract"],
                "sender": self.sender,
                "nonce": 7,
            }
        return self.confirmed(plan)

    def confirmed(self, plan):
        vote = plan["evm_vote"]
        block_hash = digest(501)
        events = [
            {
                "event": "DisputeVote",
                "address": self.contract,
                "adjudicator": item["judge"],
                "transaction_hash": digest(500),
                "block_hash": block_hash,
                "block_number": 900,
                "log_index": index,
                "removed": False,
                "settlement_key": vote["settlement_key"],
                "confirmed": vote["confirmed"],
                "report_id": vote["report_id"],
                "decision_hash": vote["decision_hash"],
            }
            for index, item in enumerate(vote["votes"])
        ]
        return {
            "status": "confirmed",
            "tx_hash": digest(500),
            "plan_hash": plan["plan_hash"],
            "chain_id": vote["chain_id"],
            "settlement_contract": vote["settlement_contract"],
            "sender": self.sender,
            "nonce": 7,
            "confirmations": 2,
            "receipt": {
                "transaction_hash": digest(500),
                "block_number": 900,
                "block_hash": block_hash,
                "status": 1,
                "from": self.sender,
                "to": self.contract,
            },
            "vote_events": events,
            "resolution_event": {
                "event": "DisputeResolved",
                "address": self.contract,
                "transaction_hash": digest(500),
                "block_hash": block_hash,
                "block_number": 900,
                "log_index": len(events),
                "removed": False,
                "settlement_key": vote["settlement_key"],
                "status": 4,
                "slash_amount": 10,
                "stable_bounty": 2,
            },
            "settlement_outcome": {
                "status": "confirmed",
                "status_code": 4,
                "winning_report_id": vote["report_id"],
                "dismiss_votes": 0,
                "report_count": 1,
                "total_bond": 5,
                "slash_amount": 10,
                "stable_bounty": 2,
                "report_bond_forfeited": False,
            },
        }

    def broadcast_recorded(self, _plan):
        return False

    def expire_assignment(self, _binding):
        return {"status": "failed"}

    def retry_assignment(self, _binding):
        return {"status": "pending"}

    def confirmed_context(self):
        return {"block_number": 900, "block_hash": digest(501)}

    def storage_health(self):
        return {
            "schema": "mycomesh.v10.provider-jury-chain-storage-health.v1",
            "ready": True,
            "quick_check": True,
            "writable": True,
            "backlog_count": 0,
            "uncertain_count": 0,
        }

    def close(self):
        pass

    def assert_binding(self, binding):
        self.assert_equal(binding["network_id"], self.config.network_id)
        self.assert_equal(binding["chain_id"], self.config.chain_id)
        self.assert_equal(binding["settlement_contract"], self.contract)
        self.assert_equal(binding["jury_registry"], self.registry)
        self.assert_equal(binding["settlement_key"], self.settlement_key)

    def assert_true(self, value):
        if not value:
            raise AssertionError(f"fixture expected truthy value, got {value!r}")

    def assert_equal(self, left, right):
        if left != right:
            raise AssertionError(f"fixture mismatch: {left!r} != {right!r}")


class ProviderJuryRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.relay = create_identity()
        self.providers = [create_identity() for _ in range(3)]
        self.contract = address(50)
        self.registry = address(51)
        self.sender = signer(90)
        self.settlement_key = digest(1)
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
        self.policy_path = Path(self.temporary.name) / "jury-policy.json"
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        self.policy_path.chmod(0o600)
        self.document = {
            "schema": "fixture.evidence.v1",
            "finding": "signed response mismatch",
        }
        self.evidence = {
            "report_id": digest(10),
            "evidence_hash": evidence_hash(self.document),
            "request_hash": digest(11),
            "response_hash": digest(12),
        }

    def selected(self, index: int) -> dict:
        identity = self.providers[index]
        operator = f"operator-{index}"
        capability = {
            "schema": provider_jury.CAPABILITY_SCHEMA,
            "models": ["judge-model"],
            "max_output_tokens": 1024,
            "supports_structured_verdict": True,
            "decision_policy_hash": self.policy_hash,
        }
        return {
            "owner": address(100 + index),
            "vote_signer": signer(20 + index),
            "operator_id": operator,
            "operator_id_hash": provider_jury._keccak_text(operator),
            "peer_id": identity.peer_id,
            "peer_id_hash": provider_jury._keccak_text(identity.peer_id),
            "capability": capability,
            "capability_hash": provider_jury.capability_hash(capability),
            "reputation": 90 + index,
        }

    def test_dynamic_ai_quorum_to_durable_receipt_reconcile(self):
        assignment = {
            "schema": ASSIGNMENT_SCHEMA,
            "status": "finalized",
            "network_id": "controlled-fixture",
            "chain_id": 31337,
            "settlement_contract": self.contract,
            "jury_registry": self.registry,
            "settlement_key": self.settlement_key,
            "assignment_hash": digest(2),
            "threshold": 2,
            "selected_providers": [self.selected(index) for index in range(3)],
            "block_number": 123,
            "block_hash": digest(3),
        }
        chain = _FixtureChain(
            assignment=assignment, contract=self.contract,
            registry=self.registry, settlement_key=self.settlement_key,
            sender=self.sender,
        )
        worker = ProviderJuryRelayWorker(
            Path(self.temporary.name) / "jury.sqlite3",
            relay_identity=self.relay,
            network_id="controlled-fixture",
            chain_id=31337,
            settlement_contract=self.contract,
            jury_registry=self.registry,
            minimum_reputation=80,
            jury_size=3,
            adjudication_threshold=2,
            decision_policy_hash=self.policy_hash,
            execution_enabled=True,
            lease_seconds=5,
            required_confirmations=2,
        )
        calls: list[str] = []

        def invoke(task):
            calls.append(task["selected_provider"]["peer_id"])
            selected = task["selected_provider"]
            index = next(
                index for index, identity in enumerate(self.providers)
                if identity.peer_id == selected["peer_id"]
            )
            return provider_jury.build_provider_verdict(
                task=task,
                model_output={
                    "confirmed": True,
                    "confidence_bps": 9000,
                    "reason_code": "fraud",
                    "reasoning": f"independent reasoning {index}",
                },
                provider_identity=self.providers[index],
                evm_private_key=key(20 + index),
                vote_nonce=0,
                vote_deadline=task["deadline"],
            )

        runtime = ProviderJuryRuntime(
            worker=worker,
            chain_adapter=chain,
            invoke_provider=invoke,
            policy_path=self.policy_path,
            deployment_decision_policy_hash=self.policy_hash,
            execution_enabled=True,
            transport_health=lambda: True,
            case_intake_health=lambda: True,
        )
        self.addCleanup(runtime.close)

        submitted = runtime.process_case(
            self.settlement_key, self.evidence, self.document,
        )
        self.assertEqual(submitted["status"], "submitted")
        self.assertEqual(len(calls), 3)
        self.assertEqual(chain.calls[:4], ["fetch", "finalize", "preflight", "broadcast"])
        plan = worker.get_plan(self.settlement_key)
        self.assertIsNotNone(plan)
        vote = plan["evm_vote"]
        self.assertEqual(len(plan["quorum_verdicts"]), 2)
        self.assertEqual(len(vote["votes"]), 2)
        self.assertEqual(vote["decision_hash"], plan["quorum_verdicts"][0]["decision_hash"])
        self.assertEqual(
            vote["data"],
            provider_jury.chain_v10.encode_dispute_vote_by_sig(
                self.settlement_key, vote["vote_permits"],
            ),
        )
        self.assertEqual(worker.get(self.settlement_key)["status"], "submitted")

        uncertain = runtime.process_case(
            self.settlement_key, self.evidence, self.document,
        )
        self.assertEqual(uncertain["status"], "uncertain")
        self.assertEqual(worker.get(self.settlement_key)["status"], "uncertain")

        confirmed = runtime.process_case(
            self.settlement_key, self.evidence, self.document,
        )
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(worker.get(self.settlement_key)["status"], "confirmed")
        self.assertEqual(chain.inspect_count, 2)
        self.assertEqual(len(chain.broadcasted), 1)
        self.assertEqual(chain.calls[-2:], ["inspect", "inspect"])
        self.assertEqual(runtime.health()["monetary_ready"], True)


if __name__ == "__main__":
    unittest.main()
