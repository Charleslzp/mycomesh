import json
import sqlite3
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from gateway.identity import create_identity, sign_document
from gateway.relay_incidents import evidence_hash
from gateway import chain_v10
from gateway.v10_enforcement import (
    V10EnforcementError, V10MonetaryExecutionStore, V10MonetaryPolicy,
    build_evm_vote_plan,
    monetary_policy_from_deployment, verify_monetary_action,
)
from tests.test_chain_v9 import key, signer


class V10EnforcementTests(unittest.TestCase):
    def monetary_policy(self, users, judge_keys, contract="0x" + "55" * 20,
                        reputations=None, *, independence_attested=True,
                        required_votes=2, required_reputation=80):
        addresses = [signer(judge_key) for judge_key in judge_keys]
        operators = [f"independent-operator-{index}"
                     for index in range(len(addresses))]
        if reputations is None:
            reputations = [99] * len(users)
        deployment = {
            "protocol_version": 10, "network_id": "test-v10", "chain_id": 31337,
            "settlement": contract, "adjudication_threshold": required_votes,
            "independence_attested": independence_attested,
            "adjudicators": addresses,
            "adjudicator_operators": dict(zip(addresses, operators)),
            "monetary_policy": {
                "schema": "mycomesh.v10.monetary-policy.v1",
                "network_id": "test-v10", "chain_id": 31337,
                "settlement_contract": contract, "required_reputation": required_reputation,
                "required_votes": required_votes,
                "signers": [
                    {"public_key": user.public_key, "evm_address": address,
                     "operator_id": operator, "reputation": reputation}
                    for user, address, operator, reputation
                    in zip(users, addresses, operators, reputations)
                ],
            },
        }
        return monetary_policy_from_deployment(deployment)

    def monetary_fixture(self, action_id="case-state-machine"):
        users = [create_identity(), create_identity()]
        evidence = {"probe_receipt": "0x" + "88" * 32, "passed": False}
        contract = "0x" + "55" * 20
        settlement_key = "0x" + "66" * 32
        policy = self.monetary_policy(users, (10, 11), contract)
        action = {
            "schema": "mycomesh.v10.monetary-action.v1", "action_id": action_id, "nonce": 0,
            "operation": "confirm", "evidence_hash": evidence_hash(evidence),
            "policy_hash": policy.policy_hash,
            "execution": {"schema": "mycomesh.v10.evm-vote.v1", "chain_id": 31337,
                          "settlement_contract": contract, "settlement_key": settlement_key,
                          "confirmed": True, "report_id": "0x" + "77" * 32,
                          "decision_hash": "0x" + "00" * 32, "vote_permits": []},
        }
        from gateway.v10_enforcement import _decision_hash
        action["decision_hash"] = _decision_hash(action)
        action["execution"]["decision_hash"] = action["decision_hash"]
        permits = []
        for user, judge_key in zip(users, (10, 11)):
            permit = chain_v10.build_dispute_vote(
                settlement_key=settlement_key, confirmed=True,
                report_id=action["execution"]["report_id"], decision_hash=action["decision_hash"],
                nonce=0, deadline=int(time.time()) + 1000, judge_private_key=key(judge_key),
                chain_id=31337, settlement_contract=contract,
            )
            permit["public_key"] = user.public_key
            permits.append(permit)
        action["execution"]["vote_permits"] = permits
        approval_hash = evidence_hash(action)
        action["user_signatures"] = [
            sign_document({"action_hash": approval_hash, "evm_address": signer(judge_key)},
                          user.private_key, purpose="mycomesh.v10.monetary-approval.v1", timestamp=100)
            for user, judge_key in zip(users, (10, 11))
        ]
        return action, evidence, {
            "policy": policy, "now": 100,
        }

    def test_requires_evidence_reputation_and_statutory_votes(self):
        users = [create_identity(), create_identity()]
        evidence = {"probe_receipt": "0x" + "11" * 32, "passed": False}
        policy = self.monetary_policy(users, (10, 11))
        base = {"schema": "mycomesh.v10.monetary-action.v1", "evidence_hash": evidence_hash(evidence),
                "policy_hash": policy.policy_hash, "amount": 3}
        approvals = []
        action_hash = evidence_hash(base)
        for user in users:
            approvals.append(sign_document({"action_hash": action_hash}, user.private_key,
                                           purpose="mycomesh.v10.monetary-approval.v1", timestamp=100))
        result = verify_monetary_action({**base, "user_signatures": approvals}, evidence=evidence,
                                        policy=policy, now=100)
        self.assertFalse(result["payable"])

    def test_policy_rejects_single_vote_or_nonindependent_committee(self):
        users = [create_identity(), create_identity()]
        with self.assertRaisesRegex(V10EnforcementError, "at least two"):
            self.monetary_policy(users[:1], (10,), required_votes=1)
        with self.assertRaisesRegex(V10EnforcementError, "attested operator independence"):
            self.monetary_policy(users, (10, 11), independence_attested=False)
        with self.assertRaisesRegex(V10EnforcementError, "at least 80"):
            self.monetary_policy(users, (10, 11), required_reputation=1)
        larger = [create_identity() for _ in range(4)]
        with self.assertRaisesRegex(V10EnforcementError, "roster"):
            self.monetary_policy(larger, (10, 11, 12, 13), required_votes=2)

    def test_policy_and_execution_flags_cannot_bypass_validated_configuration(self):
        with self.assertRaisesRegex(V10EnforcementError, "validated deployment manifest"):
            V10MonetaryPolicy(
                network_id="fake", chain_id=1, settlement_contract="0x" + "11" * 20,
                required_reputation=1, required_votes=1, signers=(),
                policy_hash="0x" + "00" * 32, _deployment_json="{}",
                _validation_token=None,
            )
        users = [create_identity(), create_identity()]
        valid = self.monetary_policy(users, (10, 11))
        forged = replace(valid, required_votes=1, required_reputation=0)
        action, evidence, _ = self.monetary_fixture("case-copied-policy")
        with self.assertRaisesRegex(V10EnforcementError, "differs from"):
            verify_monetary_action(action, evidence=evidence, policy=forged, now=100)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actions.sqlite3"
            with self.assertRaisesRegex(V10EnforcementError, "explicit boolean"):
                V10MonetaryExecutionStore(path, enabled="false")
            with self.assertRaisesRegex(V10EnforcementError, "2 to 256"):
                V10MonetaryExecutionStore(path, required_confirmations=1)

    def test_action_must_commit_the_exact_active_policy(self):
        action, evidence, options = self.monetary_fixture("case-policy-binding")
        action["policy_hash"] = "0x" + "ff" * 32
        with self.assertRaisesRegex(V10EnforcementError, "active policy"):
            verify_monetary_action(action, evidence=evidence, **options)

    def test_repository_controlled_test_manifest_cannot_enable_automatic_policy(self):
        deployment = json.loads(
            (Path(__file__).parents[1] / "deployments" / "sepolia-myco-v10.json")
            .read_text(encoding="utf-8")
        )
        with self.assertRaisesRegex(V10EnforcementError, "attested operator independence"):
            monetary_policy_from_deployment(deployment)

    def test_rejects_low_reputation_and_under_vote(self):
        users = [create_identity(), create_identity(), create_identity()]
        user = users[0]
        policy = self.monetary_policy(users, (10, 11, 12), reputations=(79, 99, 99))
        evidence = {"x": 1}
        base = {"schema": "mycomesh.v10.monetary-action.v1", "evidence_hash": evidence_hash(evidence),
                "policy_hash": policy.policy_hash, "amount": 1}
        approval = sign_document({"action_hash": evidence_hash(base)}, user.private_key,
                                 purpose="mycomesh.v10.monetary-approval.v1", timestamp=100)
        with self.assertRaises(V10EnforcementError):
            verify_monetary_action({**base, "user_signatures": [approval]}, evidence=evidence,
                                   policy=policy, now=100)

    def test_rejects_duplicate_approval_from_the_same_user(self):
        users = [create_identity(), create_identity()]
        user = users[0]
        policy = self.monetary_policy(users, (10, 11))
        evidence = {"probe_receipt": "0x" + "22" * 32, "passed": False}
        base = {"schema": "mycomesh.v10.monetary-action.v1",
                "evidence_hash": evidence_hash(evidence), "policy_hash": policy.policy_hash,
                "amount": 1}
        approval = sign_document({"action_hash": evidence_hash(base)}, user.private_key,
                                 purpose="mycomesh.v10.monetary-approval.v1", timestamp=100)
        with self.assertRaises(V10EnforcementError):
            verify_monetary_action({**base, "user_signatures": [approval, approval]},
                                   evidence=evidence, policy=policy, now=100)

    def test_rejects_action_without_independent_user_approval(self):
        evidence = {"probe_receipt": "0x" + "33" * 32, "passed": False}
        users = [create_identity(), create_identity()]
        policy = self.monetary_policy(users, (10, 11))
        base = {"schema": "mycomesh.v10.monetary-action.v1",
                "evidence_hash": evidence_hash(evidence), "policy_hash": policy.policy_hash,
                "amount": 1}
        with self.assertRaises(V10EnforcementError):
            verify_monetary_action({**base, "user_signatures": []}, evidence=evidence,
                                   policy=policy, now=100)

    def test_builds_relayable_quorum_plan_from_user_and_evm_approvals(self):
        users = [create_identity(), create_identity()]
        evidence = {"probe_receipt": "0x" + "44" * 32, "passed": False}
        contract = "0x" + "55" * 20
        settlement_key = "0x" + "66" * 32
        policy = self.monetary_policy(users, (10, 11), contract)
        base = {
            "schema": "mycomesh.v10.monetary-action.v1", "action_id": "case-1", "nonce": 0,
            "operation": "confirm", "evidence_hash": evidence_hash(evidence),
            "policy_hash": policy.policy_hash,
            "execution": {"schema": "mycomesh.v10.evm-vote.v1", "chain_id": 31337,
                           "settlement_contract": contract, "settlement_key": settlement_key,
                           "confirmed": True, "report_id": "0x" + "77" * 32,
                           "decision_hash": "0x" + "00" * 32, "vote_permits": []},
        }
        from gateway.v10_enforcement import _decision_hash
        base["decision_hash"] = _decision_hash(base)
        base["execution"]["decision_hash"] = base["decision_hash"]
        permits = []
        for user, judge_key in zip(users, (10, 11)):
            permit = chain_v10.build_dispute_vote(
                settlement_key=settlement_key, confirmed=True,
                report_id=base["execution"]["report_id"], decision_hash=base["decision_hash"],
                nonce=0, deadline=int(time.time()) + 100, judge_private_key=key(judge_key),
                chain_id=31337, settlement_contract=contract,
            )
            permit["public_key"] = user.public_key
            permits.append(permit)
        base["execution"]["vote_permits"] = permits
        action_hash = evidence_hash(base)
        approvals = [sign_document({"action_hash": action_hash, "evm_address": signer(k)}, user.private_key,
                                    purpose="mycomesh.v10.monetary-approval.v1", timestamp=100)
                      for user, k in zip(users, (10, 11))]
        action = {**base, "user_signatures": approvals}
        admission = verify_monetary_action(
            action, evidence=evidence, policy=policy, now=100,
        )
        plan = build_evm_vote_plan(
            action, approved_by=admission["approved_by"], policy=policy,
        )
        self.assertTrue(plan["data"].startswith("0x"))
        self.assertEqual(len(plan["votes"]), 2)
        with tempfile.TemporaryDirectory() as directory:
            store = V10MonetaryExecutionStore(Path(directory) / "actions.sqlite3", enabled=True)
            self.addCleanup(store.close)
            calls = []
            with self.assertRaises(V10EnforcementError):
                store.admit_and_execute(
                    action, evidence=evidence, policy=policy,
                    execute=lambda _plan: (_ for _ in ()).throw(RuntimeError("rpc uncertain")), now=100,
                )
            self.assertEqual(store.get(admission["action_hash"])["status"], "uncertain")
            saved = store.admit_and_execute(
                action, evidence=evidence, policy=policy,
                execute=lambda _plan: calls.append(True), now=100,
            )
            self.assertEqual(saved["status"], "uncertain")
            self.assertEqual(calls, [])

    def test_execution_store_never_retries_uncertain_broadcast(self):
        action, evidence, options = self.monetary_fixture("case-invalid-approval")
        action["user_signatures"] = []
        with tempfile.TemporaryDirectory() as directory:
            store = V10MonetaryExecutionStore(Path(directory) / "actions.sqlite3")
            self.addCleanup(store.close)
            with self.assertRaises(V10EnforcementError):
                store.admit_and_execute(
                    action, evidence=evidence, policy=options["policy"],
                    execute=lambda _plan: {"tx": "0x"}, now=100,
                )

    def test_execution_store_distinguishes_submitted_and_confirmed(self):
        action, evidence, options = self.monetary_fixture("case-submitted-confirmed")
        sender = signer(20)
        with tempfile.TemporaryDirectory() as directory:
            store = V10MonetaryExecutionStore(
                Path(directory) / "actions.sqlite3", enabled=True, required_confirmations=2,
            )
            self.addCleanup(store.close)

            def submit(plan):
                return {
                    "status": "submitted", "tx_hash": "0x" + "aa" * 32,
                    "plan_hash": plan["plan_hash"],
                    "chain_id": plan["evm_vote"]["chain_id"],
                    "settlement_contract": plan["evm_vote"]["settlement_contract"],
                    "sender": sender, "nonce": 7,
                }

            submitted = store.admit_and_execute(
                action, evidence=evidence, execute=submit, **options,
            )
            self.assertEqual(submitted["status"], "submitted")
            self.assertEqual(submitted["attempts"], 1)
            plan = store.get_plan(submitted["action_hash"])
            self.assertIsNotNone(plan)
            result = dict(submitted["result"], status="confirmed", confirmations=2)
            result["receipt"] = {
                "transaction_hash": result["tx_hash"], "block_number": 123,
                "block_hash": "0x" + "bb" * 32, "status": "0x1",
                "from": sender, "to": plan["evm_vote"]["settlement_contract"],
            }
            result["vote_events"] = [
                {"event": "DisputeVote", "address": plan["evm_vote"]["settlement_contract"],
                 "adjudicator": vote["judge"],
                 "transaction_hash": result["tx_hash"],
                 "block_hash": result["receipt"]["block_hash"], "block_number": 123,
                 "log_index": index, "removed": False,
                 "settlement_key": plan["evm_vote"]["settlement_key"],
                 "confirmed": plan["evm_vote"]["confirmed"],
                 "report_id": plan["evm_vote"]["report_id"],
                 "decision_hash": plan["evm_vote"]["decision_hash"]}
                for index, vote in enumerate(plan["evm_vote"]["votes"])
            ]
            boolean_status = {
                **result,
                "receipt": {**result["receipt"], "status": True},
            }
            with self.assertRaisesRegex(V10EnforcementError, "receipt does not prove"):
                store.record_result(submitted["action_hash"], boolean_status)
            confirmed = store.record_result(submitted["action_hash"], result)
            self.assertEqual(confirmed["status"], "confirmed")
            self.assertEqual(store.record_result(submitted["action_hash"], result), confirmed)

    def test_confirmed_result_rejects_wrong_vote_event(self):
        action, evidence, options = self.monetary_fixture("case-wrong-event")
        sender = signer(20)
        with tempfile.TemporaryDirectory() as directory:
            store = V10MonetaryExecutionStore(Path(directory) / "actions.sqlite3", enabled=True)
            self.addCleanup(store.close)
            submitted = store.admit_and_execute(
                action, evidence=evidence, **options,
                execute=lambda plan: {
                    "status": "submitted", "tx_hash": "0x" + "aa" * 32,
                    "plan_hash": plan["plan_hash"], "chain_id": 31337,
                    "settlement_contract": plan["evm_vote"]["settlement_contract"],
                    "sender": sender, "nonce": 8,
                },
            )
            plan = store.get_plan(submitted["action_hash"])
            result = dict(submitted["result"], status="confirmed", confirmations=2)
            result["receipt"] = {
                "transaction_hash": result["tx_hash"], "block_number": 123,
                "block_hash": "0x" + "bb" * 32, "status": 1,
                "from": sender, "to": plan["evm_vote"]["settlement_contract"],
            }
            result["vote_events"] = [{
                "event": "DisputeVote", "address": plan["evm_vote"]["settlement_contract"],
                "adjudicator": signer(99), "transaction_hash": result["tx_hash"],
                "block_hash": result["receipt"]["block_hash"], "block_number": 123,
                "log_index": 0, "removed": False,
                "settlement_key": plan["evm_vote"]["settlement_key"],
                "confirmed": True, "report_id": plan["evm_vote"]["report_id"],
                "decision_hash": plan["evm_vote"]["decision_hash"],
            }] * 2
            with self.assertRaises(V10EnforcementError):
                store.record_result(submitted["action_hash"], result)
            self.assertEqual(store.get(submitted["action_hash"])["status"], "submitted")

    def test_hard_crash_lease_expires_to_uncertain_without_retry(self):
        action, evidence, options = self.monetary_fixture("case-hard-crash")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actions.sqlite3"
            store = V10MonetaryExecutionStore(path, enabled=True, lease_seconds=5)
            with self.assertRaises(KeyboardInterrupt):
                store.admit_and_execute(
                    action, evidence=evidence, **options,
                    execute=lambda _plan: (_ for _ in ()).throw(KeyboardInterrupt()),
                )
            from gateway.v10_enforcement import _action_hash
            executing = store.get(_action_hash(action))
            self.assertEqual(executing["status"], "executing")
            expiry = executing["lease_expires_at"]
            store.close()

            reopened = V10MonetaryExecutionStore(path, enabled=True, lease_seconds=5)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.recover_expired_leases(now=expiry - 1), 0)
            self.assertEqual(reopened.recover_expired_leases(now=expiry), 1)
            calls = []
            saved = reopened.admit_and_execute(
                action, evidence=evidence, **options,
                execute=lambda _plan: calls.append(True),
            )
            self.assertEqual(saved["status"], "uncertain")
            self.assertEqual(saved["error_code"], "execution_lease_expired")
            self.assertEqual(calls, [])

    def test_legacy_executing_row_is_fenced_for_manual_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            database = sqlite3.connect(path)
            database.execute("""CREATE TABLE v10_monetary_actions (
                action_hash TEXT PRIMARY KEY, action_id TEXT NOT NULL UNIQUE,
                nonce TEXT NOT NULL, plan_json TEXT NOT NULL,
                status TEXT NOT NULL, result_json TEXT, error_code TEXT,
                created_at INTEGER NOT NULL)""")
            database.execute(
                "INSERT INTO v10_monetary_actions VALUES (?,?,?,?,?,?,?,?)",
                ("0x" + "aa" * 32, "legacy-case", "0",
                 json.dumps({"plan_hash": "0x" + "bb" * 32}),
                 "executing", None, None, 100),
            )
            database.commit()
            database.close()

            store = V10MonetaryExecutionStore(path, enabled=True)
            self.addCleanup(store.close)
            saved = store.get("0x" + "aa" * 32)
            self.assertEqual(saved["status"], "uncertain")
            self.assertEqual(
                saved["error_code"], "legacy_execution_requires_reconciliation",
            )


if __name__ == "__main__":
    unittest.main()
