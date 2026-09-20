from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import threading
import unittest

from gateway.identity import create_identity, sign_document
from gateway.relay_adjudication import (
    ADJUDICATION_PURPOSE, AdjudicationError, AdjudicationPolicy, AdjudicationStore,
    EconomicExposure, build_decision_document, verify_adjudication,
)
from gateway.relay_incidents import RelayIncidentStore


class RelayAdjudicationTests(unittest.TestCase):
    def setUp(self):
        self.authorities = [create_identity() for _ in range(3)]
        self.reporter = create_identity()
        self.provider = create_identity()
        self.policy = AdjudicationPolicy(
            network_id="test-network", chain_id=123, settlement_contract="0x" + "11" * 20,
            authority_public_keys=tuple(identity.public_key for identity in self.authorities), threshold=2,
            max_refund_units=1_000, token_reward_units=10, max_token_reward_units=20,
            stable_reward_bps=2_000, max_stable_reward_units=50,
        )
        self.exposure = EconomicExposure(consumer_paid_units=100, recoverable_provider_units=300)
        with RelayIncidentStore(":memory:") as incidents:
            incident = incidents.record_incident(
                provider_id=self.provider.peer_id, provider_signer=None, request_id="request-a", request_hash="hash-a",
                kind="protocol:invalid_response", severity="high", evidence={
                    "observer_public_key": self.reporter.public_key,
                    "provider_registration": {"public_key": self.provider.public_key},
                    "provider_response": {"signed_artifact": "independently reviewed elsewhere"},
                },
            )
            self.incident = incidents.get_incident(incident["incident_id"])
        self.verification = dict(expected_incident=self.incident, reporter_public_key=self.reporter.public_key,
                                 policy=self.policy, exposure=self.exposure, now=1_010)

    def document(self, **overrides):
        arguments = {key: value for key, value in self.verification.items() if key != "now"}
        return build_decision_document(**{**arguments, "outcome": "confirmed", "issued_at": 1_000,
                                         "expires_at": 1_100, "nonce": "decision-1", **overrides})

    def votes(self, document=None, identities=None, *, purpose=ADJUDICATION_PURPOSE, audience=None, timestamp=1_001):
        if document is None:
            document = self.document()
        return [sign_document(document, identity.private_key, purpose=purpose,
                              audience=self.policy.audience if audience is None else audience, timestamp=timestamp)
                for identity in (self.authorities[:2] if identities is None else identities)]

    def test_valid_distinct_quorum_returns_only_nonpayable_plan(self):
        result = verify_adjudication(self.votes(), **self.verification)
        self.assertEqual(result["decision"]["outcome"], "confirmed")
        self.assertEqual(result["decision"]["amounts"], {
            "refund_units": 100, "unfunded_refund_units": 0, "token_reward_units": 10, "stable_reward_units": 40,
        })
        self.assertFalse(result["payable"])
        self.assertFalse(result["onchain_linked"])
        self.assertEqual(len(result["authority_public_keys"]), 2)

    def test_threshold_and_policy_limits_are_strict(self):
        for change in ({"threshold": 1}, {"threshold": True}, {"threshold": 4},
                       {"authority_public_keys": (self.authorities[0].public_key,) * 3},
                       {"stable_reward_bps": 10_001}, {"max_stable_reward_units": -1},
                       {"token_reward_units": 21}, {"token_reward_units": 1.0}, {"chain_id": 0}):
            with self.subTest(change=change), self.assertRaises(AdjudicationError):
                replace(self.policy, **change)

    def test_exposure_requires_exact_nonnegative_units(self):
        for value in (-1, True, "1", 0.5, 2**63):
            with self.subTest(value=value), self.assertRaises(AdjudicationError):
                EconomicExposure(value, 100)
        with self.assertRaises(AdjudicationError):
            self.document(exposure=EconomicExposure(1_001, 2_000))

    def test_insufficient_duplicate_and_unpinned_votes_rejected(self):
        cases = (self.votes(identities=self.authorities[:1]),
                 self.votes(identities=[self.authorities[0], self.authorities[0]]),
                 self.votes(identities=[self.authorities[0], create_identity()]))
        for votes in cases:
            with self.subTest(votes=len(votes)), self.assertRaises(AdjudicationError):
                verify_adjudication(votes, **self.verification)

    def test_reporter_cannot_join_quorum_even_if_allowlisted(self):
        policy = replace(self.policy, authority_public_keys=(self.reporter.public_key, self.authorities[0].public_key))
        document = self.document(policy=policy)
        votes = self.votes(document, identities=[self.reporter, self.authorities[0]], audience=policy.audience)
        with self.assertRaisesRegex(AdjudicationError, "reporter is excluded"):
            verify_adjudication(votes, **{**self.verification, "policy": policy})

    def test_reporter_alias_cannot_bypass_exclusion(self):
        with self.assertRaisesRegex(AdjudicationError, "incident observer"):
            self.document(reporter_public_key=create_identity().public_key)

    def test_accused_provider_cannot_join_quorum(self):
        policy = replace(self.policy, authority_public_keys=(self.provider.public_key, self.authorities[0].public_key))
        document = self.document(policy=policy)
        votes = self.votes(document, identities=[self.provider, self.authorities[0]], audience=policy.audience)
        with self.assertRaisesRegex(AdjudicationError, "accused provider"):
            verify_adjudication(votes, **{**self.verification, "policy": policy})

    def test_signature_purpose_audience_and_signature_tampering_rejected(self):
        bad_signature = self.votes()
        bad_signature[0]["signature"]["signature"] = "00" * 64
        for votes in (bad_signature, self.votes(purpose="wrong-purpose"), self.votes(audience="wrong-domain")):
            with self.assertRaisesRegex(AdjudicationError, "invalid adjudicator signature"):
                verify_adjudication(votes, **self.verification)

    def test_cross_network_contract_policy_replays_rejected(self):
        votes = self.votes()
        for change in ({"network_id": "different-network"}, {"chain_id": 124},
                       {"settlement_contract": "0x" + "22" * 20}, {"max_token_reward_units": 100}):
            with self.subTest(change=change), self.assertRaises(AdjudicationError):
                verify_adjudication(votes, **{**self.verification, "policy": replace(self.policy, **change)})

    def test_incident_metadata_artifacts_and_hash_tampering_rejected(self):
        for change in ({"request_id": "wrong"}, {"provider_id": "wrong"}, {"severity": "low"},
                       {"evidence": {"different": "artifact"}}, {"record_hash": "0x" + "00" * 32}):
            with self.subTest(change=change), self.assertRaises(AdjudicationError):
                verify_adjudication(self.votes(), **{**self.verification, "expected_incident": {**self.incident, **change}})

    def test_requester_cannot_supply_arbitrary_amounts_or_extra_fields(self):
        for change in ({"amounts": {"refund_units": 0, "token_reward_units": 999}},
                       {"payable": True}, {"economic_context": {"consumer_paid_units": 0, "recoverable_provider_units": 9999}}):
            document = {**self.document(), **change}
            with self.subTest(change=change), self.assertRaisesRegex(AdjudicationError, "does not match expected"):
                verify_adjudication(self.votes(document), **self.verification)

    def test_refund_priority_and_shortfall_prevent_bounty(self):
        exposure = EconomicExposure(consumer_paid_units=100, recoverable_provider_units=60)
        document = self.document(exposure=exposure)
        result = verify_adjudication(self.votes(document), **{**self.verification, "exposure": exposure})
        self.assertEqual(result["decision"]["amounts"], {
            "refund_units": 60, "unfunded_refund_units": 40, "token_reward_units": 0, "stable_reward_units": 0,
        })

    def test_stable_bounty_capped_and_never_takes_consumer_refund(self):
        document = self.document(exposure=EconomicExposure(100, 100_000))
        self.assertEqual(document["amounts"]["refund_units"], 100)
        self.assertEqual(document["amounts"]["stable_reward_units"], 50)
        document = self.document(exposure=EconomicExposure(100, 100))
        self.assertEqual(document["amounts"]["stable_reward_units"], 0)

    def test_dismissed_outcome_produces_no_awards(self):
        result = verify_adjudication(self.votes(self.document(outcome="dismissed")), **self.verification)
        self.assertEqual(set(result["decision"]["amounts"].values()), {0})

    def test_quorum_must_agree_exact_document_not_just_outcome(self):
        votes = [self.votes()[0], self.votes(self.document(nonce="different"))[1]]
        with self.assertRaisesRegex(AdjudicationError, "conflicting decisions"):
            verify_adjudication(votes, **self.verification)

    def test_expiry_future_and_signature_window_rejected(self):
        for now in (900, 1_100, 2_000):
            with self.subTest(now=now), self.assertRaises(AdjudicationError):
                verify_adjudication(self.votes(), **{**self.verification, "now": now})
        for timestamp in (999, 1_100):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(AdjudicationError, "validity window"):
                verify_adjudication(self.votes(timestamp=timestamp), **self.verification)
        with self.assertRaises(AdjudicationError):
            self.document(expires_at=1_000 + 86_401)

    def test_terminal_decision_is_idempotent_and_persists_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "adjudications.sqlite3")
            votes = self.votes()
            with AdjudicationStore(path) as store:
                first = store.submit(votes, **self.verification)
                self.assertEqual(first, store.submit(votes, **self.verification))
                with self.assertRaisesRegex(AdjudicationError, "conflicting terminal"):
                    store.submit(self.votes(self.document(outcome="dismissed")), **self.verification)
            with AdjudicationStore(path) as restarted:
                self.assertEqual(first, restarted.get(self.incident["incident_id"]))
                self.assertEqual(first, restarted.submit(votes, **self.verification))
                self.assertFalse(restarted.get(self.incident["incident_id"])["payable"])

    def test_terminal_replay_with_other_quorum_cannot_change_existing_certificate(self):
        document = self.document()
        with AdjudicationStore(":memory:") as store:
            first = store.submit(self.votes(document), **self.verification)
            second = store.submit(self.votes(document, identities=self.authorities[1:]), **self.verification)
            self.assertEqual(first, second)

    def test_expired_certificate_cannot_initiate_record(self):
        with AdjudicationStore(":memory:") as store:
            with self.assertRaises(AdjudicationError):
                store.submit(self.votes(), **{**self.verification, "now": 2_000})
            self.assertIsNone(store.get(self.incident["incident_id"]))

    def test_two_connections_conflicting_terminal_decisions_only_one_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "adjudications.sqlite3")
            barrier = threading.Barrier(2)
            with AdjudicationStore(path) as first, AdjudicationStore(path) as second:
                def submit(store, outcome):
                    votes = self.votes(self.document(outcome=outcome))
                    barrier.wait(timeout=5)
                    try:
                        return store.submit(votes, **self.verification)["decision"]["outcome"]
                    except AdjudicationError as exc:
                        self.assertIn("conflicting terminal", str(exc))
                        return "conflict"
                with ThreadPoolExecutor(max_workers=2) as workers:
                    futures = [workers.submit(submit, first, "confirmed"), workers.submit(submit, second, "dismissed")]
                    results = [future.result(timeout=10) for future in futures]
                self.assertEqual(results.count("conflict"), 1)
                self.assertEqual(first.get(self.incident["incident_id"]), second.get(self.incident["incident_id"]))

    def test_memory_lifecycle_and_private_database_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "adjudications.sqlite3"
            with AdjudicationStore(str(path)) as store:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                stored = store.submit(self.votes(), **self.verification)
                self.assertEqual(json.loads(json.dumps(stored)), store.get(self.incident["incident_id"]))
            with self.assertRaisesRegex(RuntimeError, "closed"):
                store.get(self.incident["incident_id"])


if __name__ == "__main__":
    unittest.main()
