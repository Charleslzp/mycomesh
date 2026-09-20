"""User jury policy with real signed evidence; only chain reads are mocked."""
import copy
import json
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from gateway import chain, chain_v9
from gateway.adjudication_agent_model import AdvisorError
from gateway.identity import create_identity, sign_document
from gateway.relay import RelaySchedulingError
from gateway.relay_adjudication_v9 import V9AdjudicationClient, V9AdjudicationError, V9OperatorConfig
from gateway.relay_incidents import evidence_hash
from gateway.user_jury_agent import (JuryError, ROSTER_PURPOSE, UserJuryAgent, read_json,
                                     review_incident, verify_user_roster, write_private_json)
from tests import test_relay_v9_runtime
from tests.test_relay_adjudication_v9 import address, digest


class UserJuryAgentTests(unittest.TestCase):
    def setUp(self):
        self.rig = test_relay_v9_runtime.RelayV9SecurityTests()
        self.rig.setUp()
        self.addCleanup(self.rig.doCleanups)
        self.rig.mode = "usage_mismatch"
        with self.assertRaises(RelaySchedulingError):
            self.rig.run_request()
        self.incident = self.rig.incident()
        self.now = int(time.time())
        self.source = "synthetic-authenticated-observation-ledger:1"
        self.policy = {"reporter_bond": 500, "bond_penalty_recipient": address(80)}
        self.config = V9OperatorConfig(
            rpc_url="http://127.0.0.1:18545", chain_id=11155111,
            settlement_contract=self.rig.contract, runtime_code_hash=digest(801),
            genesis_hash=digest(802), policy_hash=evidence_hash(self.policy),
            adjudicators=tuple(address(n) for n in (10, 11, 12)),
            adjudicator_operators={address(n): f"synthetic-user-{n}" for n in (10, 11, 12)},
            independence_attested=True, threshold=2,
            observer_public_key=self.rig.state._scheduler_identity.public_key,
            reporter_address=address(9), confirmations=1)
        self.client = V9AdjudicationClient(self.config)
        self.authority = create_identity()
        self.agent = UserJuryAgent(self.client, reputation_public_key=self.authority.public_key, minimum_score=100)
        receipt = self.incident["evidence"]["provider_response"]["mycomesh_v9_settlement"]["receipt"]
        auth = self.rig.payment["authorization"]
        self.settlement_key = chain_v9.settlement_key_for(address(7), auth["key"], auth["request_id"])
        self.snap = {"domain": self.config.domain, "block_number": 99, "block_hash": digest(99),
            "timestamp": self.now, "actor": address(9), "policy": self.policy,
            "adjudicators": list(self.config.adjudicators), "threshold": 2,
            "settlement_key": self.settlement_key, "report_id": chain.ZERO_BYTES32,
            "settlement": {"owner": address(7), "key": auth["key"], "provider": self.rig.provider_payout,
                "provider_signer": self.rig.provider_signer, "relay": self.rig.relay_payout,
                "relay_signer": self.rig.relay_signer, "pool": chain.ZERO_ADDRESS,
                "treasury": address(8), "request_id": auth["request_id"], "request_hash": auth["request_hash"],
                "authorization_hash": receipt["authorization_hash"], "response_hash": receipt["response_hash"],
                "gross_fee": receipt["actual_fee"], "settled_at": self.now-10,
                "release_at": self.now, "status": 2},
            "dispute": {"resolve_at": self.now+200}, "report": {"reporter": address(9),
                "evidence_hash": self.incident["record_hash"], "bond_claimed": False},
            "has_reported": False, "actor_vote": 0, "claimable": 0, "token_claimable": 0}
        self.voted = set()
        p = patch.object(self.client, "snapshot", side_effect=self.snapshot)
        p.start()
        self.addCleanup(p.stop)
        self.roster = {"schema": ROSTER_PURPOSE, "domain": self.config.domain,
            "issued_at": self.now, "expires_at": self.now+150, "users": [
                {"address": address(n), "operator_id": f"synthetic-user-{n}",
                 "score": score, "score_source_hash": digest(n+900), "affiliated_addresses": [], "opt_in": True}
                for n, score in ((10, 300), (11, 500), (12, 200))]}
        self.sign_roster()

    def snapshot(self, settlement_key, actor, report_id=chain.ZERO_BYTES32):
        result = copy.deepcopy(self.snap)
        result.update(settlement_key=settlement_key, actor=actor, report_id=report_id)
        if actor in self.voted:
            result["actor_vote"] = 1
        return result

    def sign_roster(self):
        self.signed = sign_document(self.roster, self.authority.private_key, ROSTER_PURPOSE,
                                    audience=evidence_hash(self.config.domain), timestamp=self.roster["issued_at"])

    def assign(self):
        return self.agent.assign(incident=self.incident, observed_at=self.now, observation_source_ref=self.source,
                                 settlement_key=self.settlement_key, signed_roster=self.signed)

    def review(self, task, **kwargs):
        return self.agent.review(task, reviewer=task["reviewer"], observed_at=self.now,
                                 observation_source_ref=self.source, **kwargs)

    def approval(self, task, outcome="confirmed"):
        return {"task_hash": task["task_hash"], "reviewer": task["reviewer"],
            "incident_record_hash": task["incident"]["record_hash"], "outcome": outcome,
            "reason": "I independently replayed the exact signed evidence and checked its chain binding."}

    def plan(self, task, approval=None):
        return self.agent.plan_user_vote(task, reviewer=task["reviewer"], observed_at=self.now,
            observation_source_ref=self.source, approved_review=approval if approval is not None else self.approval(task))

    @staticmethod
    def rehash(task):
        task["task_hash"] = evidence_hash({k: v for k, v in task.items() if k != "task_hash"})

    @staticmethod
    def advice():
        return {"recommendation": "review_violation", "summary": "Review the verified evidence before making your own decision.",
                "fact_ids": ["F03", "F05"], "uncertainties": ["This suggestion does not establish a monetary verdict."]}

    def test_real_evidence_user_ranking_and_unsigned_vote(self):
        tasks = self.assign()
        self.assertEqual([t["reviewer"] for t in tasks], [address(11), address(10), address(12)])
        task = tasks[0]
        report = self.review(task)
        self.assertEqual(report["facts"][2]["value"], "protocol_contradiction")
        self.assertTrue(report["eligible_for_confirming_vote_review"])
        self.assertFalse(report["monetary_verdict"])
        self.assertFalse(report["transaction_authorized"])
        plan = self.plan(task)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["transaction"]["from"], address(11))
        self.assertEqual(plan["inputs"]["review"]["outcome"], "confirmed")

    def test_model_receives_only_closed_enums_and_cannot_authorize(self):
        task = self.assign()[0]
        advisor = Mock()
        advisor.advise.return_value = self.advice()
        report = self.review(task, advisor=advisor)
        facts = advisor.advise.call_args.args[0]
        self.assertEqual(len(facts), 8)
        self.assertTrue(all(set(f) == {"id", "name", "value"} for f in facts))
        self.assertNotIn(self.incident["record_hash"], json.dumps(facts))
        self.assertEqual(report["codex_status"], "suggestion_only")
        self.assertFalse(report["transaction_authorized"])
        with self.assertRaisesRegex(JuryError, "explicit user review"):
            self.plan(task, report["codex_advice"])

    def test_model_outage_does_not_change_verified_facts(self):
        task = self.assign()[0]
        before = self.review(task)
        report = self.review(task, advisor=Mock(advise=Mock(side_effect=AdvisorError("unavailable"))))
        self.assertEqual(before["facts"], report["facts"])
        self.assertEqual(report["codex_status"], "unavailable_or_invalid")
        self.assertIsNone(report["codex_advice"])

    def test_model_cannot_upgrade_receipt_mismatch(self):
        task = self.assign()[0]
        self.snap["settlement"]["gross_fee"] += 1
        report = self.review(task, advisor=Mock(advise=Mock(return_value=self.advice())))
        self.assertEqual(report["facts"][4]["value"], "mismatched")
        self.assertEqual(report["codex_status"], "unsupported_suggestion")
        self.assertIsNone(report["codex_advice"])
        with self.assertRaises(V9AdjudicationError):
            self.plan(task)

    def test_corrupt_or_unverifiable_evidence_is_not_automatic_guilt_or_innocence(self):
        incident = copy.deepcopy(self.incident)
        incident["evidence"]["code"] = "fabricated"
        report = review_incident(incident, observer_public_key=self.config.observer_public_key,
                                observed_at=self.now, observation_source_ref=self.source)
        self.assertEqual(report["recommendation"], "insufficient_evidence")
        self.assertEqual(report["facts"][2]["value"], "unverifiable")
        self.assertFalse(report["monetary_verdict"])

    def test_observer_must_be_independently_pinned(self):
        report = review_incident(self.incident, observer_public_key=create_identity().public_key,
                                observed_at=self.now, observation_source_ref=self.source)
        self.assertEqual(report["facts"][1]["value"], "unverified")

    def test_recomputed_task_hash_cannot_forge_observation_time_or_source(self):
        for field, value in (("observed_at", self.now-60), ("observation_source_ref", "attacker-ledger")):
            task = self.assign()[0]
            task[field] = value
            self.rehash(task)
            with self.subTest(field=field), self.assertRaisesRegex(JuryError, "trusted provenance"):
                self.review(task)
            with self.subTest(field=field), self.assertRaisesRegex(JuryError, "trusted provenance"):
                self.plan(task)

    def test_recomputed_task_hash_cannot_change_local_pins(self):
        for field, value in (("minimum_score", 1), ("roster_authority", create_identity().public_key),
                             ("domain", {}), ("transaction_authorized", True)):
            task = self.assign()[0]
            task[field] = value
            self.rehash(task)
            with self.subTest(field=field), self.assertRaises(JuryError):
                self.review(task)

    def test_task_recipient_and_integrity_are_enforced(self):
        task = self.assign()[0]
        task["reviewer"] = address(10)
        with self.assertRaisesRegex(JuryError, "content changed"):
            self.review(task)
        task = self.assign()[0]
        with self.assertRaises(JuryError):
            self.agent.review(task, reviewer=address(10), observed_at=self.now, observation_source_ref=self.source)

    def test_task_cannot_extend_roster_expiry(self):
        task = self.assign()[0]
        task["expires_at"] += 1
        self.rehash(task)
        with self.assertRaisesRegex(JuryError, "expiry"):
            self.review(task)

    def test_expired_roster_and_task_fail(self):
        task = self.assign()[0]
        with patch("gateway.user_jury_agent.time.time", return_value=self.now+151):
            with self.assertRaises(JuryError):
                self.review(task)
            with self.assertRaises(JuryError):
                self.assign()

    def test_tampered_wrong_authority_or_wrong_domain_roster_fail(self):
        self.signed["users"][0]["score"] += 1
        with self.assertRaisesRegex(JuryError, "signature"):
            self.assign()
        self.sign_roster()
        self.signed["signature"]["public_key"] = create_identity().public_key
        with self.assertRaisesRegex(JuryError, "authority"):
            self.assign()
        self.roster["domain"] = {}
        self.sign_roster()
        with self.assertRaisesRegex(JuryError, "deployment"):
            self.assign()

    def test_roster_requires_unique_users_and_reputation_source(self):
        for modification in (lambda r: r["users"].append(copy.deepcopy(r["users"][0])),
                             lambda r: r["users"][0].update(score=True),
                             lambda r: r["users"][0].update(score_source_hash=chain.ZERO_BYTES32)):
            original = copy.deepcopy(self.roster)
            modification(self.roster)
            self.sign_roster()
            with self.assertRaises(JuryError):
                self.assign()
            self.roster = original

    def test_threshold_opt_in_operator_and_affiliations_enforced(self):
        changes = [{"opt_in": False}, {"score": 99}, {"operator_id": "other-controller"},
                   {"affiliated_addresses": [self.rig.provider_payout]}]
        for change in changes:
            original = copy.deepcopy(self.roster)
            self.roster["users"][0].update(change)
            self.sign_roster()
            with self.subTest(change=change):
                tasks = self.assign()
                self.assertNotIn(address(10), [t["reviewer"] for t in tasks])
                self.assertEqual(len(tasks), 2)
            self.roster = original
        self.roster["users"][0]["opt_in"] = False
        self.roster["users"][1]["opt_in"] = False
        self.sign_roster()
        with self.assertRaisesRegex(JuryError, "not enough"):
            self.assign()

    def test_actual_transaction_parties_are_excluded(self):
        for field in ("owner", "key", "provider", "provider_signer", "relay", "relay_signer", "pool", "treasury"):
            original = self.snap["settlement"][field]
            self.snap["settlement"][field] = address(10)
            with self.subTest(field=field):
                self.assertNotIn(address(10), [t["reviewer"] for t in self.assign()])
            self.snap["settlement"][field] = original

    def test_prior_vote_is_excluded_without_starving_remaining_users(self):
        tasks = self.assign()
        self.voted.add(tasks[0]["reviewer"])
        remaining = self.assign()
        self.assertEqual(len(remaining), 2)
        self.assertNotIn(tasks[0]["reviewer"], [t["reviewer"] for t in remaining])
        self.review(tasks[1])
        with self.assertRaisesRegex(JuryError, "already voted"):
            self.review(tasks[0])

    def test_closed_case_or_changed_actual_report_fails_before_model(self):
        task = self.assign()[0]
        advisor = Mock()
        for field, value in (("status", 4), ("release_at", self.now+10)):
            original = self.snap["settlement"][field]
            self.snap["settlement"][field] = value
            with self.assertRaisesRegex(JuryError, "voting window"):
                self.review(task, advisor=advisor)
            self.snap["settlement"][field] = original
        self.snap["report"]["evidence_hash"] = digest(999)
        with self.assertRaisesRegex(JuryError, "actual onchain report"):
            self.review(task, advisor=advisor)
        advisor.advise.assert_not_called()

    def test_human_approval_must_bind_exact_task_and_explicit_outcome(self):
        task = self.assign()[0]
        for field, value in (("task_hash", digest(999)), ("reviewer", address(12)),
                             ("incident_record_hash", digest(999)), ("outcome", "abstain")):
            approval = self.approval(task)
            approval[field] = value
            with self.subTest(field=field), self.assertRaises(JuryError):
                self.plan(task, approval)
        dismissed = self.plan(task, self.approval(task, "dismissed"))
        self.assertFalse(dismissed["inputs"]["confirmed"])

    def test_model_extra_execution_fields_rejected(self):
        advice = self.advice()
        advice["execute"] = True
        report = self.review(self.assign()[0], advisor=Mock(advise=Mock(return_value=advice)))
        self.assertEqual(report["codex_status"], "unavailable_or_invalid")
        self.assertIsNone(report["codex_advice"])


class PrivateJuryFileTests(unittest.TestCase):
    def test_private_files_are_exclusive_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "task.json"
            write_private_json(path, {"private": "evidence"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(read_json(path), {"private": "evidence"})
            with self.assertRaises(FileExistsError):
                write_private_json(path, {})
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                read_json(link)

    def test_duplicate_fields_nonfinite_and_nonobjects_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "task.json"
            for raw in ('{"a":1,"a":2}', '{"a":NaN}', '[]'):
                path.write_text(raw)
                with self.subTest(raw=raw), self.assertRaises(JuryError):
                    read_json(path)


if __name__ == "__main__":
    unittest.main()
