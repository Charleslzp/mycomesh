from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from gateway import chain_v10, provider_jury
from gateway.relay_incidents import (
    PROVIDER_JURY_EVIDENCE_KIND,
    RelayIncidentStore,
    evidence_hash,
)
from tests.test_chain_v9 import address, digest


def incident_fields(**overrides):
    return {
        "provider_id": "peer-a", "provider_signer": "0x" + "11" * 20,
        "request_id": "0x" + "22" * 32, "request_hash": "0x" + "33" * 32,
        "kind": "protocol_receipt_mismatch", "severity": "high",
        "evidence": {"field": "request_id", "expected": "a", "actual": "b"},
        **overrides,
    }


class RelayIncidentStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "incidents.sqlite3")
        self.store = RelayIncidentStore(self.path)
        self.addCleanup(self.store.close)

    def test_incidents_and_bounty_intents_are_idempotent(self):
        first = self.store.record_incident(**incident_fields())
        second = self.store.record_incident(**incident_fields())
        self.assertEqual(first, second)
        fields = dict(incident_id=first["incident_id"], claimant_id="relay-a", token_units=10, refund_units=20)
        intent = self.store.enqueue_bounty(**fields)
        self.assertEqual(intent, self.store.enqueue_bounty(**fields))
        self.assertEqual(intent["status"], "pending")
        with self.assertRaisesRegex(ValueError, "conflicting bounty"):
            self.store.enqueue_bounty(**{**fields, "token_units": 999})

    def test_missing_and_empty_request_ids_are_idempotent(self):
        first = self.store.record_incident(**incident_fields(request_id=None))
        self.assertEqual(first, self.store.record_incident(**incident_fields(request_id=None)))
        self.assertEqual(first, self.store.record_incident(**incident_fields(request_id="")))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)

    def test_conflicting_metadata_or_evidence_is_rejected(self):
        self.store.record_incident(**incident_fields())
        for change in ({"provider_signer": "different-signer"}, {"request_hash": "different-hash"},
                       {"severity": "low"}, {"evidence": {"actual": "different-body"}}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "conflicting incident"):
                self.store.record_incident(**incident_fields(**change))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)

    def test_signed_artifacts_and_metadata_can_be_retrieved_unchanged(self):
        fields = incident_fields(evidence={"expected_authorization": {"signature": "consumer-sig"},
                                          "actual_receipt": {"signature": "provider-sig"}, "response": "body"})
        summary = self.store.record_incident(**fields)
        fields["evidence"]["response"] = "mutated-after-recording"
        stored = self.store.get_incident(summary["incident_id"])
        self.assertEqual(stored["evidence"]["response"], "body")
        committed = {name: stored[name] for name in incident_fields()}
        self.assertEqual(evidence_hash(committed), stored["record_hash"])
        self.assertEqual(stored["record_hash"], summary["record_hash"])
        self.assertEqual(evidence_hash(stored["evidence"]), summary["evidence_hash"])
        self.assertIsNone(self.store.get_incident("missing"))

    def test_private_incident_store_resolves_committed_v10_jury_evidence(self):
        settlement_key = digest(80)
        request_id = digest(81)
        request_hash = digest(82)
        response_hash = digest(83)
        reporter = address(84)
        provider_signer = address(85)
        document = {
            "schema": provider_jury.EVIDENCE_DOCUMENT_SCHEMA,
            "settlement_key": settlement_key,
            "reporter": reporter,
            "origin_relay_public_key": "11" * 32,
            "allegation": {"code": "mismatch", "summary": "review"},
            "request": {
                "request_id": request_id,
                "endpoint": "responses",
                "model": "judge-model",
                "input": "hello",
                "messages": None,
                "max_output_tokens": 32,
                "options": {},
            },
            "provider_response": {
                "settlement_v10": {
                    "provider_signer": provider_signer,
                    "authorization": {"authorization": {
                        "issued_at": 100,
                    }},
                },
            },
        }
        committed = evidence_hash(document)
        report_id = chain_v10.report_id_for(
            settlement_key, reporter, committed,
        )
        self.store.record_incident(
            provider_id="peer-jury",
            provider_signer=provider_signer,
            request_id=request_id,
            request_hash=request_hash,
            kind=PROVIDER_JURY_EVIDENCE_KIND,
            severity="high",
            evidence=document,
        )
        snapshot = {
            "settlement_key": settlement_key,
            "evidence": {"payload": {
                "report_id": report_id,
                "evidence_hash": committed,
                "reporter": reporter,
            }},
        }
        authorization = {"authorization": {
            "request_id": request_id,
            "request_hash": request_hash,
            "channel_id": digest(86),
        }}
        receipt = SimpleNamespace(
            provider_signer=provider_signer,
            response_hash=response_hash,
        )
        with patch(
            "gateway.provider_jury._v10_evidence_document",
            return_value=document,
        ), patch(
            "gateway.reservation.normalize_inference_request_options",
            return_value={},
        ), patch(
            "gateway.reservation.inference_request_hash",
            return_value=request_hash[2:],
        ), patch(
            "gateway.chain_v10.verify_signed_receipt",
            return_value=(authorization, receipt, ()),
        ), patch(
            "gateway.chain_v10.settlement_key_for",
            return_value=settlement_key,
        ):
            resolved = self.store.resolve_provider_jury_evidence(snapshot)
        self.assertEqual(resolved["evidence"], {
            "report_id": report_id,
            "evidence_hash": committed,
            "request_hash": request_hash,
            "response_hash": response_hash,
        })
        self.assertEqual(resolved["evidence_document"], document)

    def test_jury_evidence_resolver_rejects_missing_or_ambiguous_local_data(self):
        settlement_key, reporter, committed = digest(90), address(91), digest(92)
        snapshot = {
            "settlement_key": settlement_key,
            "evidence": {"payload": {
                "report_id": chain_v10.report_id_for(
                    settlement_key, reporter, committed,
                ),
                "evidence_hash": committed,
                "reporter": reporter,
            }},
        }
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            self.store.resolve_provider_jury_evidence(snapshot)

    def test_invalid_incident_fields_and_nonfinite_json_rejected(self):
        for fields in (incident_fields(provider_id=""), incident_fields(kind=" "),
                       incident_fields(evidence={"x": float("nan")}), incident_fields(evidence=[])):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.store.record_incident(**fields)

    def test_protocol_violation_quarantines_and_is_idempotent(self):
        args = dict(provider_id="peer-a", evidence_id="evidence-1", passed=False, hard_violation=True)
        first = self.store.record_observation(**args)
        duplicate = self.store.record_observation(**args)
        self.assertEqual(first, duplicate)
        self.assertEqual(first["status"], "quarantined")
        self.assertEqual(duplicate["evidence_count"], 1)
        self.assertTrue(self.store.is_quarantined("peer-a"))

    def test_soft_failures_never_quarantine_and_can_recover(self):
        for index in range(40):
            risk = self.store.record_observation(provider_id="peer-a", evidence_id=f"soft-{index}", passed=False)
            self.assertNotEqual(risk["status"], "quarantined")
        self.assertEqual(risk["status"], "suspect")
        for index in range(20):
            risk = self.store.record_observation(provider_id="peer-a", evidence_id=f"pass-{index}", passed=True)
        self.assertEqual(risk["status"], "healthy")

    def test_quarantine_stays_sticky_after_success(self):
        self.store.record_observation(provider_id="peer-a", evidence_id="bad", passed=False, hard_violation=True)
        for index in range(20):
            self.store.record_observation(provider_id="peer-a", evidence_id=f"pass-{index}", passed=True)
        self.assertTrue(self.store.is_quarantined("peer-a"))

    def test_conflicting_risk_observation_cannot_change_verdict(self):
        self.store.record_observation(provider_id="peer-a", evidence_id="same", passed=False)
        for change in ({"passed": True}, {"passed": False, "hard_violation": True}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "conflicting risk"):
                self.store.record_observation(provider_id="peer-a", evidence_id="same", **change)
        self.assertEqual(self.store.risk_snapshot("peer-a")["evidence_count"], 1)
        self.assertFalse(self.store.is_quarantined("peer-a"))

    def test_observations_require_exact_booleans_and_nonempty_ids(self):
        for changes in ({"passed": 1}, {"passed": "false"}, {"hard_violation": "false"},
                        {"passed": True, "hard_violation": True}, {"provider_id": ""}, {"evidence_id": ""}):
            args = dict(provider_id="peer-a", evidence_id="test", passed=False)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.record_observation(**{**args, **changes})
        self.assertEqual(self.store.risk_snapshot("peer-a")["evidence_count"], 0)

    def test_atomic_protocol_incident_quarantines_peer_and_trusted_signer(self):
        fields = incident_fields()
        summary = self.store.record_protocol_incident(**fields, risk_provider_ids=["signer:chain:contract:a"])
        self.assertTrue(self.store.is_quarantined("peer-a"))
        self.assertTrue(self.store.is_quarantined("signer:chain:contract:a"))
        self.assertEqual(summary, self.store.record_protocol_incident(**fields, risk_provider_ids=["signer:chain:contract:a"]))
        self.assertEqual(self.store.risk_snapshot("peer-a")["evidence_count"], 1)

    def test_atomic_protocol_incident_rolls_back_all_risk_updates_on_conflict(self):
        summary = self.store.record_incident(**incident_fields())
        self.store.record_observation(provider_id="zz-alias", evidence_id=summary["incident_id"], passed=True)
        with self.assertRaisesRegex(ValueError, "conflicting risk"):
            self.store.record_protocol_incident(**incident_fields(), risk_provider_ids=["zz-alias"])
        self.assertEqual(self.store.risk_snapshot("peer-a")["evidence_count"], 0)
        self.assertFalse(self.store.is_quarantined("zz-alias"))

    def test_operator_clear_is_audited_idempotent_and_does_not_clear_later_evidence(self):
        self.store.record_observation(provider_id="peer-a", evidence_id="bad", passed=False, hard_violation=True)
        action = dict(provider_id="peer-a", operator_id="operator-a", reason="reviewed signed counterevidence", action_id="review-1")
        self.assertEqual(self.store.clear_quarantine(**action)["status"], "healthy")
        self.assertFalse(self.store.is_quarantined("peer-a"))
        # Replayed old evidence does not reverse an explicit reviewed clear.
        self.store.record_observation(provider_id="peer-a", evidence_id="bad", passed=False, hard_violation=True)
        self.assertFalse(self.store.is_quarantined("peer-a"))
        self.store.record_observation(provider_id="peer-a", evidence_id="new-bad", passed=False, hard_violation=True)
        self.assertEqual(self.store.clear_quarantine(**action)["status"], "quarantined")
        actions = self.store.risk_actions("peer-a")
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["operator_id"], "operator-a")
        self.assertEqual(json.loads(actions[0]["previous_state_json"])["status"], "quarantined")
        with self.assertRaisesRegex(ValueError, "conflicting operator"):
            self.store.clear_quarantine(**{**action, "reason": "different"})

    def test_invalid_or_unaudited_clear_is_rejected(self):
        action = dict(provider_id="peer-a", operator_id="operator-a", reason="review", action_id="review-1")
        with self.assertRaisesRegex(ValueError, "not quarantined"):
            self.store.clear_quarantine(**action)
        self.store.record_observation(provider_id="peer-a", evidence_id="bad", passed=False, hard_violation=True)
        for field in action:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.store.clear_quarantine(**{**action, field: ""})
        self.assertTrue(self.store.is_quarantined("peer-a"))

    def test_bounty_requires_existing_incident_and_nonempty_claimant(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.store.enqueue_bounty(incident_id="unknown", claimant_id="relay-a")
        incident = self.store.record_incident(**incident_fields())
        with self.assertRaises(ValueError):
            self.store.enqueue_bounty(incident_id=incident["incident_id"], claimant_id="")

    def test_bounty_requires_exact_nonnegative_integer_units(self):
        incident = self.store.record_incident(**incident_fields())
        for value in (-1, True, "1", 1.0, 0.1, float("nan"), 2**63):
            for field in ("token_units", "refund_units"):
                with self.subTest(value=value, field=field), self.assertRaises(ValueError):
                    self.store.enqueue_bounty(incident_id=incident["incident_id"], claimant_id="relay-a", **{field: value})

    def test_memory_database_keeps_schema_and_data_until_closed(self):
        with RelayIncidentStore(":memory:") as store:
            incident = store.record_protocol_incident(**incident_fields())
            self.assertIsNotNone(store.get_incident(incident["incident_id"]))
            self.assertTrue(store.is_quarantined("peer-a"))
            self.assertEqual(store.enqueue_bounty(incident_id=incident["incident_id"], claimant_id="relay")["status"], "pending")
        with self.assertRaisesRegex(RuntimeError, "closed"):
            store.risk_snapshot("peer-a")
        store.close()

    def test_restart_preserves_evidence_quarantine_and_idempotency(self):
        summary = self.store.record_protocol_incident(**incident_fields())
        self.store.close()
        with RelayIncidentStore(self.path) as restarted:
            self.assertEqual(summary, restarted.record_protocol_incident(**incident_fields()))
            self.assertTrue(restarted.is_quarantined("peer-a"))
            self.assertEqual(restarted.risk_snapshot("peer-a")["evidence_count"], 1)

    def test_private_file_and_new_parent_permissions(self):
        path = Path(self.directory.name) / "private" / "ledger.sqlite3"
        with RelayIncidentStore(str(path)) as store:
            store.record_incident(**incident_fields())
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(path.parent).st_mode & 0o777, 0o700)
            for suffix in ("-wal", "-shm"):
                if Path(str(path) + suffix).exists():
                    self.assertEqual(os.stat(str(path) + suffix).st_mode & 0o777, 0o600)

    def test_incident_store_rejects_symlink_and_hardlink_database_targets(self):
        parent = Path(self.directory.name) / "link-tests"
        parent.mkdir(mode=0o700)
        target = parent / "target.sqlite3"
        target.write_bytes(b"do-not-touch")
        symlink = parent / "symlink.sqlite3"
        symlink.symlink_to(target)
        with self.assertRaises(OSError):
            RelayIncidentStore(str(symlink))
        self.assertEqual(target.read_bytes(), b"do-not-touch")

        hardlink = parent / "hardlink.sqlite3"
        os.link(target, hardlink)
        with self.assertRaisesRegex(OSError, "multiple hard links"):
            RelayIncidentStore(str(hardlink))

    def test_incident_store_rejects_foreign_ownership(self):
        path = Path(self.directory.name) / "foreign" / "ledger.sqlite3"
        with patch("gateway.relay_incidents.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(OSError, "foreign ownership"):
                RelayIncidentStore(str(path))

    def test_memory_store_is_explicitly_not_durable(self):
        with RelayIncidentStore(":memory:") as store:
            self.assertFalse(store.durable)
        self.assertFalse(store.durable)

    def test_same_instance_threads_deduplicate_incident_and_risk(self):
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(lambda _: self.store.record_protocol_incident(**incident_fields(request_id=None)), range(40)))
        self.assertEqual(len({result["incident_id"] for result in results}), 1)
        self.assertEqual(self.store.risk_snapshot("peer-a")["evidence_count"], 1)

    def test_two_connections_concurrent_conflicting_evidence_one_wins(self):
        with RelayIncidentStore(self.path) as other:
            barrier = threading.Barrier(2)
            def attempt(store, actual):
                barrier.wait(timeout=5)
                try:
                    return store.record_protocol_incident(**incident_fields(evidence={"actual": actual}))["incident_id"]
                except ValueError as exc:
                    self.assertIn("conflicting incident", str(exc))
                    return "conflict"
            with ThreadPoolExecutor(max_workers=2) as workers:
                futures = [workers.submit(attempt, self.store, "a"), workers.submit(attempt, other, "b")]
                results = [future.result(timeout=10) for future in futures]
            self.assertEqual(results.count("conflict"), 1)
            self.assertEqual(self.store.risk_snapshot("peer-a")["evidence_count"], 1)

    def test_two_connections_concurrent_conflicting_risk_one_wins(self):
        with RelayIncidentStore(self.path) as other:
            barrier = threading.Barrier(2)
            def attempt(store, passed):
                barrier.wait(timeout=5)
                try:
                    return store.record_observation(provider_id="peer-a", evidence_id="same", passed=passed)
                except ValueError:
                    return None
            with ThreadPoolExecutor(max_workers=2) as workers:
                futures = [workers.submit(attempt, self.store, True), workers.submit(attempt, other, False)]
                results = [future.result(timeout=10) for future in futures]
            self.assertEqual(sum(result is None for result in results), 1)
            self.assertEqual(self.store.risk_snapshot("peer-a")["evidence_count"], 1)

    def _legacy_database(self, rows):
        path = str(Path(self.directory.name) / "legacy.sqlite3")
        with sqlite3.connect(path) as db:
            db.execute("""CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, provider_signer TEXT,
                request_id TEXT, request_hash TEXT, evidence_hash TEXT NOT NULL, kind TEXT NOT NULL,
                severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', evidence_json TEXT NOT NULL,
                created_at INTEGER NOT NULL, UNIQUE(provider_id, request_id, evidence_hash, kind))""")
            for identity, fields in rows:
                db.execute("INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 1)",
                           (identity, fields["provider_id"], fields["provider_signer"], fields["request_id"],
                            fields["request_hash"], evidence_hash(fields["evidence"]), fields["kind"],
                            fields["severity"], json.dumps(fields["evidence"])))
        return path

    def test_legacy_null_duplicates_are_preserved_but_deduplicated_on_reuse(self):
        fields = incident_fields(request_id=None)
        path = self._legacy_database([("legacy-first", fields), ("legacy-second", fields)])
        with RelayIncidentStore(path) as migrated:
            self.assertEqual(migrated.record_incident(**fields)["incident_id"], "legacy-first")
            self.assertIsNotNone(migrated.get_incident("legacy-second"))
            self.assertEqual(migrated.audit_health()["legacy_conflicts"], 0)
        with RelayIncidentStore(path) as restarted:
            self.assertEqual(restarted.record_incident(**fields)["incident_id"], "legacy-first")

    def test_legacy_conflicts_are_preserved_and_fail_closed_on_reuse(self):
        fields = incident_fields(request_id=None)
        path = self._legacy_database([("legacy-first", fields), ("legacy-second", {**fields, "severity": "low"})])
        with RelayIncidentStore(path) as migrated:
            with self.assertRaisesRegex(ValueError, "conflicting incident"):
                migrated.record_incident(**fields)
            self.assertIsNotNone(migrated.get_incident("legacy-first"))
            self.assertIsNotNone(migrated.get_incident("legacy-second"))
            self.assertEqual(migrated.audit_health()["legacy_conflicts"], 1)
            self.assertFalse(migrated.audit_health()["payments_enabled"])


if __name__ == "__main__":
    unittest.main()
