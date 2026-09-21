import unittest

from gateway.identity import create_identity, sign_document
from gateway.relay_incidents import evidence_hash
from gateway.v10_enforcement import V10EnforcementError, verify_monetary_action


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


if __name__ == "__main__":
    unittest.main()
