import tempfile
import time
import unittest
from pathlib import Path

from gateway.identity import create_identity, sign_document
from gateway.relay_incidents import evidence_hash
from gateway import chain_v10
from gateway.v10_enforcement import (
    V10EnforcementError, V10MonetaryExecutionStore, build_evm_vote_plan,
    verify_monetary_action,
)
from tests.test_chain_v9 import key, signer


class V10EnforcementTests(unittest.TestCase):
    def test_requires_evidence_reputation_and_statutory_votes(self):
        users = [create_identity(), create_identity()]
        evidence = {"probe_receipt": "0x" + "11" * 32, "passed": False}
        base = {"schema": "mycomesh.v10.monetary-action.v1", "evidence_hash": evidence_hash(evidence), "amount": 3}
        approvals = []
        action_hash = evidence_hash(base)
        for user in users:
            approvals.append(sign_document({"action_hash": action_hash}, user.private_key,
                                           purpose="mycomesh.v10.monetary-approval.v1", timestamp=100))
        result = verify_monetary_action({**base, "user_signatures": approvals}, evidence=evidence,
                                        high_reputation_users={u.public_key: 99 for u in users},
                                        required_reputation=80, statutory_votes=2, required_votes=2, now=100)
        self.assertFalse(result["payable"])

    def test_rejects_low_reputation_and_under_vote(self):
        user = create_identity()
        evidence = {"x": 1}
        base = {"schema": "mycomesh.v10.monetary-action.v1", "evidence_hash": evidence_hash(evidence), "amount": 1}
        approval = sign_document({"action_hash": evidence_hash(base)}, user.private_key,
                                 purpose="mycomesh.v10.monetary-approval.v1", timestamp=100)
        with self.assertRaises(V10EnforcementError):
            verify_monetary_action({**base, "user_signatures": [approval]}, evidence=evidence,
                                   high_reputation_users={user.public_key: 79}, required_reputation=80,
                                   statutory_votes=1, required_votes=1, now=100)

    def test_rejects_duplicate_approval_from_the_same_user(self):
        user = create_identity()
        evidence = {"probe_receipt": "0x" + "22" * 32, "passed": False}
        base = {"schema": "mycomesh.v10.monetary-action.v1",
                "evidence_hash": evidence_hash(evidence), "amount": 1}
        approval = sign_document({"action_hash": evidence_hash(base)}, user.private_key,
                                 purpose="mycomesh.v10.monetary-approval.v1", timestamp=100)
        with self.assertRaises(V10EnforcementError):
            verify_monetary_action({**base, "user_signatures": [approval, approval]},
                                   evidence=evidence,
                                   high_reputation_users={user.public_key: 99},
                                   required_reputation=80, statutory_votes=2,
                                   required_votes=2, now=100)

    def test_rejects_action_without_independent_user_approval(self):
        evidence = {"probe_receipt": "0x" + "33" * 32, "passed": False}
        base = {"schema": "mycomesh.v10.monetary-action.v1",
                "evidence_hash": evidence_hash(evidence), "amount": 1}
        with self.assertRaises(V10EnforcementError):
            verify_monetary_action({**base, "user_signatures": []}, evidence=evidence,
                                   high_reputation_users={}, required_reputation=80,
                                   statutory_votes=2, required_votes=2, now=100)

    def test_builds_relayable_quorum_plan_from_user_and_evm_approvals(self):
        users = [create_identity(), create_identity()]
        evidence = {"probe_receipt": "0x" + "44" * 32, "passed": False}
        contract = "0x" + "55" * 20
        settlement_key = "0x" + "66" * 32
        base = {
            "schema": "mycomesh.v10.monetary-action.v1", "action_id": "case-1", "nonce": 0,
            "operation": "confirm", "evidence_hash": evidence_hash(evidence),
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
            action, evidence=evidence,
            high_reputation_users={u.public_key: 99 for u in users},
            required_reputation=80, statutory_votes=2, required_votes=2, now=100,
        )
        plan = build_evm_vote_plan(
            action, approved_by=admission["approved_by"],
            evm_addresses={u.public_key: signer(k) for u, k in zip(users, (10, 11))},
        )
        self.assertTrue(plan["data"].startswith("0x"))
        self.assertEqual(len(plan["votes"]), 2)
        with tempfile.TemporaryDirectory() as directory:
            store = V10MonetaryExecutionStore(Path(directory) / "actions.sqlite3", enabled=True)
            self.addCleanup(store.close)
            calls = []
            with self.assertRaises(V10EnforcementError):
                store.admit_and_execute(
                    action, evidence=evidence,
                    high_reputation_users={u.public_key: 99 for u in users},
                    required_reputation=80, statutory_votes=2, required_votes=2,
                    evm_addresses={u.public_key: signer(k) for u, k in zip(users, (10, 11))},
                    execute=lambda _plan: (_ for _ in ()).throw(RuntimeError("rpc uncertain")), now=100,
                )
            self.assertEqual(store.get(admission["action_hash"])["status"], "uncertain")
            saved = store.admit_and_execute(
                action, evidence=evidence,
                high_reputation_users={u.public_key: 99 for u in users},
                required_reputation=80, statutory_votes=2, required_votes=2,
                evm_addresses={u.public_key: signer(k) for u, k in zip(users, (10, 11))},
                execute=lambda _plan: calls.append(True), now=100,
            )
            self.assertEqual(saved["status"], "uncertain")
            self.assertEqual(calls, [])

    def test_execution_store_never_retries_uncertain_broadcast(self):
        with tempfile.TemporaryDirectory() as directory:
            store = V10MonetaryExecutionStore(Path(directory) / "actions.sqlite3")
            self.addCleanup(store.close)
            with self.assertRaises(V10EnforcementError):
                store.admit_and_execute(
                    {"schema": "mycomesh.v10.monetary-action.v1", "action_id": "case-2", "nonce": 0,
                     "evidence_hash": evidence_hash({"x": 1}), "user_signatures": []},
                    evidence={"x": 1}, high_reputation_users={}, required_reputation=80,
                    statutory_votes=0, required_votes=1, evm_addresses={},
                    execute=lambda _plan: {"tx": "0x"}, now=100,
                )


if __name__ == "__main__":
    unittest.main()
