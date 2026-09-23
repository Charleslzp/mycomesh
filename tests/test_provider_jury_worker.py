from __future__ import annotations

import copy
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from gateway import provider_jury
from gateway.identity import create_identity
from gateway.provider_jury_worker import (
    ASSIGNMENT_SCHEMA,
    ProviderJuryRelayWorker,
    ProviderJuryWorkerError,
)
from tests.test_chain_v9 import address, digest, key, signer


class ProviderJuryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.relay = create_identity()
        self.providers = [create_identity(), create_identity(), create_identity()]
        self.settlement_key = digest(1)
        self.assignment_hash = digest(2)
        self.contract = address(50)
        self.registry = address(51)
        self.capability = {
            "schema": provider_jury.CAPABILITY_SCHEMA,
            "models": ["judge-model"],
            "max_output_tokens": 1024,
            "supports_structured_verdict": True,
            "decision_policy_hash": provider_jury.decision_policy_hash(
                model="judge-model",
                system_prompt="Apply the pinned fraud policy.",
                max_output_tokens=512,
                task_ttl_seconds=300,
            ),
        }
        self.evidence_document = {
            "schema": "fixture.evidence.v1",
            "finding": "signed response mismatch",
            "artifacts": [digest(13), digest(14)],
        }
        self.evidence = {
            "report_id": digest(11),
            "evidence_hash": provider_jury.evidence_hash(self.evidence_document),
            "request_hash": digest(13),
            "response_hash": digest(14),
        }
        self.inference = {
            "model": "judge-model",
            "system_prompt": "Apply the pinned fraud policy.",
            "evidence_document": self.evidence_document,
            "max_output_tokens": 512,
        }
        self.worker = self.make_worker()
        self.addCleanup(self.worker.close)

    def make_worker(self, *, name="jury.sqlite3", enabled=True, policy_ttl=300):
        return ProviderJuryRelayWorker(
            Path(self.temporary.name) / name,
            relay_identity=self.relay,
            network_id="fixture",
            chain_id=31337,
            settlement_contract=self.contract,
            jury_registry=self.registry,
            minimum_reputation=80,
            jury_size=3,
            adjudication_threshold=2,
            decision_policy_hash=provider_jury.decision_policy_hash(
                model="judge-model",
                system_prompt="Apply the pinned fraud policy.",
                max_output_tokens=512,
                task_ttl_seconds=policy_ttl,
            ),
            execution_enabled=enabled,
            lease_seconds=5,
            required_confirmations=2,
        )

    def test_execution_store_rejects_symbolic_link(self):
        target = Path(self.temporary.name) / "target.sqlite3"
        target.write_bytes(b"")
        link = Path(self.temporary.name) / "linked.sqlite3"
        link.symlink_to(target)
        with self.assertRaisesRegex(ProviderJuryWorkerError, "opened safely"):
            self.make_worker(name="linked.sqlite3")

    def selected(self, index, *, reputation=None, operator=None):
        identity = self.providers[index]
        operator_id = operator or f"operator-{index}"
        return {
            "owner": address(100 + index),
            "vote_signer": signer(20 + index),
            "operator_id": operator_id,
            "operator_id_hash": provider_jury._keccak_text(operator_id),
            "peer_id": identity.peer_id,
            "peer_id_hash": provider_jury._keccak_text(identity.peer_id),
            "capability": self.capability,
            "capability_hash": provider_jury.capability_hash(self.capability),
            "reputation": 90 + index if reputation is None else reputation,
        }

    def assignment(self, **changes):
        value = {
            "schema": ASSIGNMENT_SCHEMA,
            "status": "finalized",
            "network_id": "fixture",
            "chain_id": 31337,
            "settlement_contract": self.contract,
            "jury_registry": self.registry,
            "settlement_key": self.settlement_key,
            "assignment_hash": self.assignment_hash,
            "threshold": 2,
            "selected_providers": [self.selected(index) for index in range(3)],
            "block_number": 123,
            "block_hash": digest(3),
        }
        value.update(changes)
        return value

    def invoke(self, task, *, outcomes=None):
        provider = task["selected_provider"]
        index = next(index for index in range(3)
                     if provider["peer_id"] == self.providers[index].peer_id)
        outcome = True if outcomes is None else outcomes[index]
        return provider_jury.build_provider_verdict(
            task=task,
            model_output={
                "confirmed": outcome,
                "confidence_bps": 9000,
                "reason_code": "fraud" if outcome else "not_proven",
                "reasoning": f"independent reasoning {index}",
            },
            provider_identity=self.providers[index],
            evm_private_key=key(20 + index),
            vote_nonce=0,
            vote_deadline=self.now + 240,
            now=self.now,
        )

    def admit(self, **changes):
        arguments = {
            "settlement_key": self.settlement_key,
            "evidence": self.evidence,
            "inference_request": self.inference,
            "fetch_assignment": lambda _binding: self.assignment(),
            "invoke_provider": self.invoke,
            "now": self.now,
        }
        arguments.update(changes)
        return self.worker.collect_and_admit(**arguments)

    @staticmethod
    def submitted(plan):
        return {
            "status": "submitted",
            "tx_hash": digest(80),
            "plan_hash": plan["plan_hash"],
            "chain_id": plan["evm_vote"]["chain_id"],
            "settlement_contract": plan["evm_vote"]["settlement_contract"],
            "sender": address(90),
            "nonce": 7,
        }

    @classmethod
    def confirmed(cls, plan):
        submitted = cls.submitted(plan)
        block_hash = digest(81)
        block_number = 321
        vote = plan["evm_vote"]
        events = []
        for index, planned in enumerate(vote["votes"]):
            events.append({
                "event": "DisputeVote",
                "address": vote["settlement_contract"],
                "adjudicator": planned["judge"],
                "transaction_hash": submitted["tx_hash"],
                "block_hash": block_hash,
                "block_number": block_number,
                "log_index": index,
                "removed": False,
                "settlement_key": vote["settlement_key"],
                "confirmed": vote["confirmed"],
                "report_id": vote["report_id"],
                "decision_hash": vote["decision_hash"],
            })
        status_code = 4 if vote["confirmed"] else 5
        slash_amount = 10 if vote["confirmed"] else 0
        stable_bounty = 2 if vote["confirmed"] else 0
        return {
            **submitted,
            "status": "confirmed",
            "confirmations": 2,
            "receipt": {
                "transaction_hash": submitted["tx_hash"],
                "block_number": block_number,
                "block_hash": block_hash,
                "status": 1,
                "from": submitted["sender"],
                "to": vote["settlement_contract"],
            },
            "vote_events": events,
            "resolution_event": {
                "event": "DisputeResolved",
                "address": vote["settlement_contract"],
                "transaction_hash": submitted["tx_hash"],
                "block_hash": block_hash,
                "block_number": block_number,
                "log_index": len(events),
                "removed": False,
                "settlement_key": vote["settlement_key"],
                "status": status_code,
                "slash_amount": slash_amount,
                "stable_bounty": stable_bounty,
            },
            "settlement_outcome": {
                "status": "confirmed" if vote["confirmed"] else "dismissed",
                "status_code": status_code,
                "winning_report_id": (
                    vote["report_id"] if vote["confirmed"]
                    else provider_jury.ZERO_BYTES32
                ),
                "dismiss_votes": 0 if vote["confirmed"] else len(events),
                "report_count": 1,
                "total_bond": 5,
                "slash_amount": slash_amount,
                "stable_bounty": stable_bounty,
                "report_bond_forfeited": not vote["confirmed"],
            },
        }

    def test_collect_execute_and_receipt_reconcile(self):
        calls = []
        state = self.admit(invoke_provider=lambda task: (calls.append(task), self.invoke(task))[1])
        self.assertEqual(state["status"], "admitted")
        self.assertEqual(len(calls), 3)
        plan = self.worker.get_plan(self.settlement_key)
        self.assertIsNotNone(plan)
        self.assertEqual(len(plan["quorum_verdicts"]), 2)
        self.assertEqual(len(plan["evm_vote"]["votes"]), 2)
        self.assertTrue(plan["evm_vote"]["data"].startswith("0x"))

        broadcasts = []
        submitted = self.worker.execute(
            self.settlement_key,
            broadcast=lambda value: (broadcasts.append(value), self.submitted(value))[1],
            now=self.now + 1,
        )
        self.assertEqual(submitted["status"], "submitted")
        # A submitted action is returned as-is; the keeper is not called again.
        again = self.worker.execute(
            self.settlement_key,
            broadcast=lambda _value: self.fail("submitted transaction was resent"),
            now=self.now + 2,
        )
        self.assertEqual(again["status"], "submitted")
        self.assertEqual(len(broadcasts), 1)

        final = self.worker.reconcile(
            self.settlement_key,
            inspect=lambda value, current: self.confirmed(value),
        )
        self.assertEqual(final["status"], "confirmed")
        self.assertEqual(final["result"]["confirmations"], 2)

        advanced = self.confirmed(plan)
        advanced["confirmations"] = 3
        refreshed = self.worker.reconcile(
            self.settlement_key,
            inspect=lambda _value, _current: advanced,
        )
        self.assertEqual(refreshed["status"], "confirmed")
        self.assertEqual(refreshed["result"]["confirmations"], 3)

        reorged = self.worker.reconcile(
            self.settlement_key,
            inspect=lambda value, _current: {
                **self.submitted(value), "status": "uncertain",
            },
        )
        self.assertEqual(reorged["status"], "uncertain")
        self.assertEqual(reorged["result"]["tx_hash"], submitted["result"]["tx_hash"])

    def test_storage_health_checks_integrity_write_lock_and_closed_store(self):
        health = self.worker.storage_health()
        self.assertTrue(health["ready"])
        self.assertTrue(health["quick_check"])
        self.assertTrue(health["writable"])
        self.assertEqual(health["backlog_count"], 0)
        self.assertEqual(health["uncertain_count"], 0)

        self.admit()
        self.worker._db.execute(
            "UPDATE provider_jury_executions SET status='uncertain'"
        )
        pending = self.worker.storage_health()
        self.assertTrue(pending["ready"])
        self.assertEqual(pending["backlog_count"], 1)
        self.assertEqual(pending["uncertain_count"], 1)

        self.worker._db.execute("PRAGMA query_only=ON")
        readonly = self.worker.storage_health()
        self.assertFalse(readonly["ready"])
        self.assertTrue(readonly["quick_check"])
        self.assertFalse(readonly["writable"])
        self.worker._db.execute("PRAGMA query_only=OFF")

        self.worker.close()
        closed = self.worker.storage_health()
        self.assertFalse(closed["ready"])
        self.assertFalse(closed["quick_check"])
        self.assertFalse(closed["writable"])

        corrupt = self.make_worker(name="corrupt.sqlite3")
        corrupt._db.close()
        Path(corrupt.path).write_bytes(b"not-a-sqlite-database")
        corrupt._db = sqlite3.connect(
            corrupt.path, timeout=30, isolation_level=None, check_same_thread=False,
        )
        damaged = corrupt.storage_health()
        self.assertFalse(damaged["ready"])
        self.assertFalse(damaged["quick_check"])
        corrupt.close()

    def test_pending_assignment_is_finalized_before_provider_calls(self):
        order = []

        def fetch(_binding):
            order.append("fetch")
            return {"status": "pending", "request_block": 100}

        def finalize(binding, pending):
            order.append("finalize")
            self.assertEqual(binding["settlement_key"], self.settlement_key)
            self.assertEqual(pending["request_block"], 100)
            return self.assignment()

        self.admit(
            fetch_assignment=fetch,
            finalize_assignment=finalize,
            invoke_provider=lambda task: (order.append("invoke"), self.invoke(task))[1],
        )
        self.assertEqual(order[:2], ["fetch", "finalize"])
        self.assertEqual(order.count("invoke"), 3)

    def test_selected_provider_ai_calls_run_concurrently(self):
        barrier = threading.Barrier(3, timeout=2)

        def invoke(task):
            barrier.wait()
            return self.invoke(task)

        state = self.admit(invoke_provider=invoke)
        self.assertEqual(state["status"], "admitted")

    def test_partial_collection_retry_reuses_exact_durable_tasks(self):
        first_tasks = {}

        def partial(task):
            index = next(index for index, identity in enumerate(self.providers)
                         if task["selected_provider"]["peer_id"] == identity.peer_id)
            first_tasks[index] = copy.deepcopy(task)
            if index:
                raise TimeoutError("selected Provider temporarily unavailable")
            return self.invoke(task)

        with self.assertRaisesRegex(ProviderJuryWorkerError, "strict-majority quorum"):
            self.admit(invoke_provider=partial)
        self.assertEqual(set(first_tasks), {0, 1, 2})
        self.assertIsNone(self.worker.get(self.settlement_key))

        retried = []

        def retry(task):
            index = next(index for index, identity in enumerate(self.providers)
                         if task["selected_provider"]["peer_id"] == identity.peer_id)
            self.assertEqual(task, first_tasks[index])
            retried.append(index)
            return self.invoke(task)

        state = self.worker.collect_and_admit(
            settlement_key=self.settlement_key,
            evidence=self.evidence,
            inference_request=self.inference,
            # Confirmed snapshot metadata may advance, but the immutable
            # assignment and its signed tasks must remain identical.
            fetch_assignment=lambda _binding: self.assignment(
                block_number=124, block_hash=digest(4),
            ),
            invoke_provider=retry,
            now=self.now + 10,
        )
        self.assertEqual(state["status"], "admitted")
        self.assertEqual(set(retried), {0, 1, 2})

    def test_expired_partial_collection_never_mints_replacement_tasks(self):
        self.worker.close()
        self.capability["decision_policy_hash"] = provider_jury.decision_policy_hash(
            model="judge-model",
            system_prompt="Apply the pinned fraud policy.",
            max_output_tokens=512,
            task_ttl_seconds=5,
        )
        self.worker = self.make_worker(name="jury-short-ttl.sqlite3", policy_ttl=5)
        self.addCleanup(self.worker.close)
        with self.assertRaisesRegex(ProviderJuryWorkerError, "strict-majority quorum"):
            self.admit(
                invoke_provider=lambda _task: (_ for _ in ()).throw(
                    TimeoutError("no verdict")
                ),
                task_ttl_seconds=5,
            )
        with self.assertRaisesRegex(ProviderJuryWorkerError, "expired"):
            self.worker.collect_and_admit(
                settlement_key=self.settlement_key,
                evidence=self.evidence,
                inference_request=self.inference,
                fetch_assignment=lambda _binding: self.assignment(),
                invoke_provider=lambda _task: self.fail(
                    "expired collection invoked a Provider"
                ),
                task_ttl_seconds=5,
                now=self.now + 6,
            )

    def test_conflicting_or_invalid_ai_outputs_do_not_admit(self):
        outcomes = [True, False, True]

        def invoke(task):
            index = next(index for index, identity in enumerate(self.providers)
                         if task["selected_provider"]["peer_id"] == identity.peer_id)
            if index == 2:
                return {"malformed": True}
            return self.invoke(task, outcomes=outcomes)

        with self.assertRaisesRegex(ProviderJuryWorkerError, "strict-majority quorum"):
            self.admit(invoke_provider=invoke)
        self.assertIsNone(self.worker.get(self.settlement_key))

    def test_inference_policy_must_match_deployment_pin(self):
        changed = dict(self.inference)
        changed["system_prompt"] = "Apply an attacker-selected policy."
        with self.assertRaisesRegex(ProviderJuryWorkerError, "differs from deployment"):
            self.admit(inference_request=changed)
        self.assertIsNone(self.worker.get(self.settlement_key))

    def test_assignment_must_be_pinned_independent_and_high_reputation(self):
        low = [self.selected(0), self.selected(1, reputation=79), self.selected(2)]
        with self.assertRaisesRegex(ProviderJuryWorkerError, "low-reputation"):
            self.admit(fetch_assignment=lambda _binding: self.assignment(selected_providers=low))
        duplicated = [self.selected(0), self.selected(1, operator="operator-0"), self.selected(2)]
        with self.assertRaisesRegex(ProviderJuryWorkerError, "not independent"):
            self.admit(fetch_assignment=lambda _binding: self.assignment(selected_providers=duplicated))
        aliased = [self.selected(0), self.selected(1), self.selected(2)]
        aliased[1]["owner"] = aliased[0]["vote_signer"]
        with self.assertRaisesRegex(ProviderJuryWorkerError, "separate every Provider owner"):
            self.admit(fetch_assignment=lambda _binding: self.assignment(selected_providers=aliased))
        with self.assertRaisesRegex(ProviderJuryWorkerError, "another deployment"):
            self.admit(fetch_assignment=lambda _binding: self.assignment(chain_id=1))

    def test_hard_crash_lease_recovers_to_uncertain_without_retry(self):
        self.admit()

        def crash(_plan):
            raise SystemExit("hard crash")

        with self.assertRaises(SystemExit):
            self.worker.execute(self.settlement_key, broadcast=crash, now=self.now + 1)
        self.assertEqual(self.worker.get(self.settlement_key)["status"], "executing")
        self.assertEqual(self.worker.recover_expired_leases(now=self.now + 6), 1)
        self.assertEqual(self.worker.get(self.settlement_key)["status"], "uncertain")
        returned = self.worker.execute(
            self.settlement_key,
            broadcast=lambda _plan: self.fail("uncertain transaction was resent"),
            now=self.now + 7,
        )
        self.assertEqual(returned["status"], "uncertain")

    def test_pre_outbox_hard_crash_can_be_proven_not_sent_and_retried(self):
        self.admit()

        def crash(_plan):
            raise SystemExit("hard crash before durable adapter reservation")

        with self.assertRaises(SystemExit):
            self.worker.execute(self.settlement_key, broadcast=crash, now=self.now + 1)
        self.assertEqual(self.worker.recover_expired_leases(
            now=self.now + 6, broadcast_recorded=lambda _plan: False,
        ), 1)
        recovered = self.worker.get(self.settlement_key)
        self.assertEqual(recovered["status"], "admitted")
        self.assertEqual(recovered["attempts"], 0)
        sent = self.worker.execute(
            self.settlement_key,
            broadcast=lambda plan: self.submitted(plan),
            now=self.now + 7,
        )
        self.assertEqual(sent["status"], "submitted")

    def test_restart_preserves_executing_until_outbox_aware_recovery(self):
        crashed = self.make_worker(name="restart.sqlite3")
        crashed.collect_and_admit(
            settlement_key=self.settlement_key,
            evidence=self.evidence,
            inference_request=self.inference,
            fetch_assignment=lambda _binding: self.assignment(),
            invoke_provider=self.invoke,
            now=self.now,
        )
        with self.assertRaises(SystemExit):
            crashed.execute(
                self.settlement_key,
                broadcast=lambda _plan: (_ for _ in ()).throw(
                    SystemExit("hard crash before durable adapter reservation")
                ),
                now=self.now + 1,
            )
        crashed.close()

        restarted = self.make_worker(name="restart.sqlite3")
        self.addCleanup(restarted.close)
        self.assertEqual(restarted.get(self.settlement_key)["status"], "executing")
        self.assertEqual(restarted.recover_expired_leases(
            now=self.now + 6, broadcast_recorded=lambda _plan: False,
        ), 1)
        self.assertEqual(restarted.get(self.settlement_key)["status"], "admitted")
        sent = restarted.execute(
            self.settlement_key,
            broadcast=lambda plan: self.submitted(plan),
            now=self.now + 7,
        )
        self.assertEqual(sent["status"], "submitted")

    def test_callback_failure_is_uncertain_and_cannot_be_blindly_retried(self):
        self.admit()

        def fail(_plan):
            raise TimeoutError("RPC response lost after submission")

        with self.assertRaisesRegex(ProviderJuryWorkerError, "uncertain"):
            self.worker.execute(self.settlement_key, broadcast=fail, now=self.now + 1)
        current = self.worker.get(self.settlement_key)
        self.assertEqual(current["status"], "uncertain")
        self.assertEqual(current["attempts"], 1)
        returned = self.worker.execute(
            self.settlement_key,
            broadcast=lambda _plan: self.fail("uncertain transaction was resent"),
            now=self.now + 2,
        )
        self.assertEqual(returned["status"], "uncertain")

    def test_definitely_not_sent_failure_returns_case_to_admitted(self):
        self.admit()

        class NotSentError(RuntimeError):
            definitely_not_sent = True

        with self.assertRaisesRegex(ProviderJuryWorkerError, "definitely not sent"):
            self.worker.execute(
                self.settlement_key,
                broadcast=lambda _plan: (_ for _ in ()).throw(NotSentError()),
                now=self.now + 1,
            )
        current = self.worker.get(self.settlement_key)
        self.assertEqual(current["status"], "admitted")
        self.assertEqual(current["attempts"], 0)
        submitted = self.worker.execute(
            self.settlement_key,
            broadcast=lambda plan: self.submitted(plan),
            now=self.now + 2,
        )
        self.assertEqual(submitted["status"], "submitted")

    def test_expired_vote_permit_is_fenced_before_broadcast(self):
        self.admit()
        returned = self.worker.execute(
            self.settlement_key,
            broadcast=lambda _plan: self.fail("expired vote permit was broadcast"),
            now=self.now + 241,
        )
        self.assertEqual(returned["status"], "uncertain")
        self.assertEqual(returned["error_code"], "vote_permit_expired")
        self.assertEqual(returned["attempts"], 0)

    def test_negative_quorum_executes_and_confirms_dismissal_with_bond_forfeiture(self):
        admitted = self.admit(
            invoke_provider=lambda task: self.invoke(
                task, outcomes=[False, False, False],
            ),
        )
        self.assertEqual(admitted["status"], "admitted")
        plan = self.worker.get_plan(self.settlement_key)
        self.assertIsNotNone(plan)
        self.assertTrue(plan["automatic_execution_allowed"])
        self.assertFalse(plan["evm_vote"]["confirmed"])
        self.assertEqual(plan["evm_vote"]["report_id"], provider_jury.ZERO_BYTES32)
        self.assertEqual(len(plan["evm_vote"]["vote_permits"]), 2)
        submitted = self.worker.execute(
            self.settlement_key,
            broadcast=lambda value: self.submitted(value),
            now=self.now + 1,
        )
        self.assertEqual(submitted["status"], "submitted")
        final = self.worker.reconcile(
            self.settlement_key,
            inspect=lambda value, _current: self.confirmed(value),
        )
        self.assertEqual(final["status"], "confirmed")
        self.assertEqual(final["result"]["settlement_outcome"]["status"], "dismissed")
        self.assertTrue(
            final["result"]["settlement_outcome"]["report_bond_forfeited"]
        )

    def test_low_confidence_negative_cannot_form_or_execute_a_quorum(self):
        def low_confidence(task):
            provider = task["selected_provider"]
            index = next(index for index in range(3)
                         if provider["peer_id"] == self.providers[index].peer_id)
            return provider_jury.build_provider_verdict(
                task=task,
                model_output={
                    "confirmed": False,
                    "confidence_bps": provider_jury.MIN_AUTOMATIC_CONFIDENCE_BPS - 1,
                    "reason_code": "insufficient_evidence",
                    "reasoning": "The evidence is ambiguous and cannot authorize dismissal.",
                },
                provider_identity=self.providers[index],
                evm_private_key=key(20 + index),
                vote_nonce=0,
                vote_deadline=self.now + 240,
                now=self.now,
            )

        with self.assertRaisesRegex(
            ProviderJuryWorkerError, "did not form one strict-majority quorum",
        ):
            self.admit(invoke_provider=low_confidence)
        self.assertIsNone(self.worker.get_plan(self.settlement_key))

    def test_invalid_receipt_or_event_cannot_be_confirmed(self):
        self.admit()
        self.worker.execute(
            self.settlement_key,
            broadcast=lambda plan: self.submitted(plan),
            now=self.now + 1,
        )
        plan = self.worker.get_plan(self.settlement_key)
        wrong = self.confirmed(plan)
        wrong["vote_events"][0]["decision_hash"] = digest(99)
        with self.assertRaisesRegex(ProviderJuryWorkerError, "vote events"):
            self.worker.record_result(self.settlement_key, wrong)
        self.assertEqual(self.worker.get(self.settlement_key)["status"], "submitted")

    def test_repeated_admission_is_idempotent_but_changed_evidence_is_rejected(self):
        self.admit()
        state = self.worker.collect_and_admit(
            settlement_key=self.settlement_key,
            evidence=self.evidence,
            inference_request=self.inference,
            fetch_assignment=lambda _binding: self.fail("assignment was fetched twice"),
            invoke_provider=lambda _task: self.fail("Provider was invoked twice"),
            now=self.now + 1,
        )
        self.assertEqual(state["status"], "admitted")
        changed = copy.deepcopy(self.evidence)
        changed["response_hash"] = digest(99)
        with self.assertRaisesRegex(ProviderJuryWorkerError, "different evidence"):
            self.worker.collect_and_admit(
                settlement_key=self.settlement_key,
                evidence=changed,
                inference_request=self.inference,
                fetch_assignment=lambda _binding: self.assignment(),
                invoke_provider=self.invoke,
                now=self.now + 1,
            )


if __name__ == "__main__":
    unittest.main()
