from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from gateway import provider_jury
from gateway.identity import create_identity
from gateway.provider_jury_chain import (
    ProviderJuryChainAdapter,
    ProviderJuryChainConfig,
)
from gateway.provider_jury_runtime import ProviderJuryRuntime
from gateway.provider_jury_worker import (
    ASSIGNMENT_SCHEMA,
    ProviderJuryRelayWorker,
    ProviderJuryWorkerError,
)
from gateway.relay_incidents import evidence_hash
from tests.test_chain_v9 import address, digest, key, signer


class ProviderJuryControlledCanaryTests(unittest.TestCase):
    """Run the dynamic Provider-AI lifecycle without a funded RPC broadcast.

    The worker and chain adapter are real durable components.  Only their
    chain reads and final send/inspect callbacks are replaced by deterministic
    local observations, so this canary exercises the same state fences used by
    the Relay while proving that no ``eth_sendRawTransaction`` is reachable.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.relay_identity = create_identity()
        self.provider_identities = [create_identity() for _ in range(3)]
        self.network_id = "mycomesh-v10-dynamic-provider-ai-controlled-test"
        self.chain_id = 31337
        self.contract = address(50)
        self.registry = address(51)
        self.genesis_hash = digest(100)
        self.settlement_key = digest(1)
        self.assignment_hash = digest(2)
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
        self.policy_path = root / "provider-jury-policy.json"
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        self.policy_path.chmod(0o600)
        self.sender = signer(90)
        self.key_path = root / "jury-sender.key"
        self.key_path.write_text(key(90), encoding="ascii")
        self.key_path.chmod(0o600)
        self.config = ProviderJuryChainConfig(
            network_id=self.network_id,
            rpc_urls=("https://rpc-a.invalid", "https://rpc-b.invalid"),
            chain_id=self.chain_id,
            genesis_hash=self.genesis_hash,
            settlement_contract=self.contract,
            settlement_runtime_code_hash=digest(101),
            jury_registry=self.registry,
            registry_runtime_code_hash=digest(102),
            jury_registry_governance=address(52),
            reputation_authority=address(53),
            bond_penalty_recipient=address(54),
            minimum_reputation=80,
            jury_size=3,
            adjudication_threshold=2,
            selection_delay_blocks=2,
            confirmations=2,
        )
        self.capability = {
            "schema": provider_jury.CAPABILITY_SCHEMA,
            "models": ["judge-model"],
            "max_output_tokens": 1024,
            "supports_structured_verdict": True,
            "decision_policy_hash": self.policy_hash,
        }
        self.document = {
            "schema": "fixture.evidence.v1",
            "finding": "controlled canary evidence",
        }
        self.evidence = {
            "report_id": digest(10),
            "evidence_hash": evidence_hash(self.document),
            "request_hash": digest(11),
            "response_hash": digest(12),
        }

    def selected_provider(self, index: int, *, reputation: int = 90) -> dict:
        identity = self.provider_identities[index]
        operator_id = f"operator-{index}"
        return {
            "owner": address(100 + index),
            "vote_signer": signer(20 + index),
            "operator_id": operator_id,
            "operator_id_hash": provider_jury._keccak_text(operator_id),
            "peer_id": identity.peer_id,
            "peer_id_hash": provider_jury._keccak_text(identity.peer_id),
            "capability": self.capability,
            "capability_hash": provider_jury.capability_hash(self.capability),
            "reputation": reputation,
        }

    def assignment(self, *, providers: list[dict] | None = None) -> dict:
        return {
            "schema": ASSIGNMENT_SCHEMA,
            "status": "finalized",
            "network_id": self.network_id,
            "chain_id": self.chain_id,
            "settlement_contract": self.contract,
            "jury_registry": self.registry,
            "settlement_key": self.settlement_key,
            "assignment_hash": self.assignment_hash,
            "threshold": 2,
            "selected_providers": providers or [self.selected_provider(i) for i in range(3)],
            "block_number": 123,
            "block_hash": digest(3),
        }

    def make_worker(self, name: str = "worker.sqlite3") -> ProviderJuryRelayWorker:
        return ProviderJuryRelayWorker(
            Path(self.temporary.name) / name,
            relay_identity=self.relay_identity,
            network_id=self.network_id,
            chain_id=self.chain_id,
            settlement_contract=self.contract,
            jury_registry=self.registry,
            minimum_reputation=80,
            jury_size=3,
            adjudication_threshold=2,
            decision_policy_hash=self.policy_hash,
            execution_enabled=True,
            lease_seconds=30,
            required_confirmations=2,
        )

    def make_adapter(self, name: str = "chain.sqlite3") -> ProviderJuryChainAdapter:
        return ProviderJuryChainAdapter(
            self.config,
            outbox_path=Path(self.temporary.name) / name,
            resolve_provider=lambda _snapshot: {},
            sender=self.sender,
            execution_enabled=True,
            dedicated_sender=True,
            key_file=self.key_path,
            max_gas_price_wei=10**9,
            max_gas_units=1_000_000,
            max_total_gas_cost_wei=10**18,
        )

    def invoke_provider(self, task: dict) -> dict:
        selected = task["selected_provider"]
        index = next(
            i for i, identity in enumerate(self.provider_identities)
            if identity.peer_id == selected["peer_id"]
        )
        return provider_jury.build_provider_verdict(
            task=task,
            model_output={
                "confirmed": True,
                "confidence_bps": 9_000,
                "reason_code": "controlled_canary",
                "reasoning": f"deterministic canary verdict {index}",
            },
            provider_identity=self.provider_identities[index],
            evm_private_key=key(20 + index),
            vote_nonce=0,
            vote_deadline=task["deadline"],
            now=task["issued_at"],
        )

    def test_dynamic_registry_state_and_durable_lifecycle_without_broadcast(self) -> None:
        worker = self.make_worker()
        adapter = self.make_adapter()
        self.addCleanup(worker.close)
        self.addCleanup(adapter.close)

        # This is the same guard used for a Registry assignment snapshot.  A
        # low-reputation member must be rejected before any Provider call.
        with self.assertRaisesRegex(ProviderJuryWorkerError, "low-reputation"):
            worker._assignment(
                self.assignment(providers=[
                    self.selected_provider(0, reputation=79),
                    self.selected_provider(1),
                    self.selected_provider(2),
                ]),
                binding=worker._binding(self.settlement_key),
            )

        # Use the real adapter config and durable outbox, while replacing only
        # network callbacks with local observations.
        assignment = self.assignment()
        adapter.fetch_assignment = lambda _binding: dict(assignment)
        adapter.finalize_assignment = lambda _binding, _pending: dict(assignment)
        adapter.preflight = lambda _plan: {"action_hash": digest(81)}
        adapter.broadcast_recorded = lambda _plan: False
        adapter.confirmed_context = lambda: {
            "block_number": 123,
            "block_hash": digest(83),
        }
        broadcast_states: list[str] = []
        broadcast_calls = 0

        def safe_broadcast(plan: dict) -> dict:
            nonlocal broadcast_calls
            broadcast_calls += 1
            current = worker.get(self.settlement_key)
            self.assertIsNotNone(current)
            broadcast_states.append(current["status"])
            # Deliberately do not call adapter._submit, _rpc, or eth_sendRawTransaction.
            return {
                "status": "submitted",
                "tx_hash": digest(80),
                "plan_hash": plan["plan_hash"],
                "chain_id": self.chain_id,
                "settlement_contract": self.contract,
                "sender": self.sender,
                "nonce": 7,
            }

        adapter.broadcast = safe_broadcast
        inspection_mode = {"value": "uncertain"}

        def inspect(plan: dict, _current: dict) -> dict:
            vote = plan["evm_vote"]
            base = {
                "tx_hash": digest(80),
                "plan_hash": plan["plan_hash"],
                "chain_id": self.chain_id,
                "settlement_contract": self.contract,
                "sender": self.sender,
                "nonce": 7,
            }
            if inspection_mode["value"] == "uncertain":
                return {**base, "status": "uncertain"}
            block_hash = digest(84)
            events = [
                {
                    "event": "DisputeVote",
                    "address": self.contract,
                    "adjudicator": vote_item["judge"],
                    "transaction_hash": digest(80),
                    "block_hash": block_hash,
                    "block_number": 321,
                    "log_index": index,
                    "removed": False,
                    "settlement_key": vote["settlement_key"],
                    "confirmed": vote["confirmed"],
                    "report_id": vote["report_id"],
                    "decision_hash": (
                        digest(999)
                        if inspection_mode["value"] == "bad_decision_hash"
                        else vote["decision_hash"]
                    ),
                }
                for index, vote_item in enumerate(vote["votes"])
            ]
            return {
                **base,
                "status": "confirmed",
                "confirmations": 2,
                "receipt": {
                    "transaction_hash": digest(80),
                    "block_number": 321,
                    "block_hash": block_hash,
                    "status": 1,
                    "from": self.sender,
                    "to": self.contract,
                },
                "vote_events": events,
                "resolution_event": {
                    "event": "DisputeResolved",
                    "address": self.contract,
                    "transaction_hash": digest(80),
                    "block_hash": block_hash,
                    "block_number": 321,
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

        adapter.inspect = inspect

        # First admission is explicitly execution-disabled: the plan is
        # durable, but no preflight or broadcast is reachable.
        admitted_runtime = ProviderJuryRuntime(
            worker=worker,
            chain_adapter=adapter,
            invoke_provider=self.invoke_provider,
            policy_path=self.policy_path,
            deployment_decision_policy_hash=self.policy_hash,
            execution_enabled=False,
        )
        admitted = admitted_runtime.process_case(
            self.settlement_key, self.evidence, self.document,
        )
        self.assertEqual(admitted["status"], "admitted")
        self.assertEqual(adapter.outbox.storage_health()["backlog_count"], 0)

        # Enabling only the local canary coordinator exercises the real worker
        # lease.  The safe broadcaster observes the intermediate executing row.
        runtime = ProviderJuryRuntime(
            worker=worker,
            chain_adapter=adapter,
            invoke_provider=self.invoke_provider,
            policy_path=self.policy_path,
            deployment_decision_policy_hash=self.policy_hash,
            execution_enabled=True,
            transport_health=lambda: True,
            case_intake_health=lambda: True,
        )
        submitted = runtime.process_case(self.settlement_key, self.evidence, self.document)
        self.assertEqual(submitted["status"], "submitted")
        self.assertEqual(broadcast_states, ["executing"])
        self.assertEqual(broadcast_calls, 1)
        self.assertEqual(adapter.outbox.storage_health()["backlog_count"], 0)

        uncertain = runtime.process_case(self.settlement_key, self.evidence, self.document)
        self.assertEqual(uncertain["status"], "uncertain")
        self.assertEqual(broadcast_calls, 1)

        # A mismatched decisionHash is rejected during reconciliation and the
        # durable case remains uncertain rather than being relabeled confirmed.
        inspection_mode["value"] = "bad_decision_hash"
        with self.assertRaisesRegex(ProviderJuryWorkerError, "invalid jury transaction observation"):
            runtime.process_case(self.settlement_key, self.evidence, self.document)
        self.assertEqual(worker.get(self.settlement_key)["status"], "uncertain")

        inspection_mode["value"] = "confirmed"
        confirmed = runtime.process_case(self.settlement_key, self.evidence, self.document)
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["result"]["confirmations"], 2)
        self.assertEqual(worker.get(self.settlement_key)["status"], "confirmed")
        self.assertEqual(adapter.outbox.storage_health()["backlog_count"], 0)
        runtime.close()
        admitted_runtime.close()


if __name__ == "__main__":
    unittest.main()
