"""Local scheduler tests only: synthetic receipts, no RPC, signing or transfers."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.session_relayer import (
    PreparedRelaySettlement, RelaySettlementError, RelaySettlementOutbox,
    RelaySettlementSubmitter,
)


class SettlementBatchScheduleTests(unittest.TestCase):
    now = 1_800_000_000
    contract = "0x" + "b" * 40
    key_address = "0x" + "a" * 40

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "outbox.sqlite3"
        clock = patch("gateway.session_relayer.time.time", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        no_rpc = patch("gateway.session_relayer.rpc_call", side_effect=AssertionError("scheduler must not perform RPC"))
        self.rpc = no_rpc.start()
        self.addCleanup(no_rpc.stop)
        self.outbox = RelaySettlementOutbox(self.path)
        self.worker = self.submitter()

    def submitter(self, **options):
        return RelaySettlementSubmitter(outbox=self.outbox, rpc_url="http://fixture.invalid",
            private_key="0x" + "4" * 64, expected_chain_id=11155111,
            expected_contract=self.contract, settlement_version=9, **options)

    def prepared(self, index, *, deadline=None, receipt_deadline=None):
        # Longer-lived synthetic envelopes exercise the time threshold. They
        # are deliberately never verified/signed: deployed V9 TTL is <=1 hour.
        request_id = "0x" + f"{index:064x}"
        receipt = {"actual_fee": 100}
        if receipt_deadline is not None:
            receipt["deadline"] = receipt_deadline
        return PreparedRelaySettlement(key=f"v9:fixture:{index}", session_id=request_id,
            receipt_hash="0x" + "c" * 64, sequence=0, chain_id=11155111,
            settlement_contract=self.contract, calldata="0x1234",
            payload={"protocol_version": 9, "tuple_data": "0x1234", "signed_receipt": {
                "authorization": {"authorization": {"key": self.key_address,
                    "deadline": self.now + 20000 if deadline is None else deadline}},
                "receipt": receipt}})

    def add(self, index, **options):
        prepared = self.prepared(index, **options)
        self.outbox.enqueue(prepared)
        return prepared

    def schedule(self):
        return self.worker.snapshot()["batching"]

    def test_empty_queue_never_triggers_or_creates_transaction(self):
        self.assertEqual(self.worker._next_scheduled_batch(), [])
        status = self.schedule()
        self.assertEqual(status["pending_count"], 0)
        self.assertEqual(status["next_trigger_reason"], "empty")
        self.assertIsNone(status["next_trigger_at"])
        self.rpc.assert_not_called()

    def test_first_receipt_waits_at_most_interval_and_restart_does_not_reset(self):
        self.add(1)
        enqueued = self.now
        self.assertEqual(self.schedule()["next_trigger_at"], enqueued + 7200)
        self.now += 7199
        self.assertEqual(self.worker._next_scheduled_batch(), [])
        self.outbox = RelaySettlementOutbox(self.path)
        self.worker = self.submitter()
        self.assertEqual(self.schedule()["oldest_pending_age_seconds"], 7199)
        self.now += 1
        self.assertEqual(len(self.worker._next_scheduled_batch()), 1)
        self.assertEqual(self.schedule()["next_trigger_reason"], "interval")

    def test_timer_uses_last_successful_settlement_even_after_idle_period(self):
        old = self.add(1)
        self.outbox.mark_confirmed(old.key)
        settled = self.now
        self.now += 1000
        self.add(2)
        self.assertEqual(self.schedule()["next_trigger_at"], settled + 7200)
        self.now = settled + 7200
        self.assertEqual(len(self.worker._next_scheduled_batch()), 1)
        self.outbox.mark_confirmed("v9:fixture:2")
        self.now += 8000
        self.assertEqual(self.worker._next_scheduled_batch(), [])
        self.add(3)
        self.assertEqual(len(self.worker._next_scheduled_batch()), 1)

    def test_count_trigger_drains_all_100_in_contract_sized_chunks_across_restart(self):
        self.worker = self.submitter(batch_size=32)
        for index in range(1, 100):
            self.add(index)
        self.assertEqual(self.worker._next_scheduled_batch(), [])
        # Duplicate intake is neither a new receipt nor a new timer anchor.
        self.outbox.enqueue(self.prepared(99))
        self.assertEqual(self.schedule()["pending_count"], 99)
        self.add(100)
        batch = self.worker._next_scheduled_batch()
        lengths = [len(batch)]
        self.assertEqual(self.schedule()["next_trigger_reason"], "count")
        self.add(101)  # A later receipt does not join the already claimed cohort.
        self.outbox.mark_confirmed_many([item["settlement_key"] for item in batch])
        self.outbox = RelaySettlementOutbox(self.path)
        self.worker = self.submitter(batch_size=32)
        while batch := self.worker._next_scheduled_batch():
            lengths.append(len(batch))
            self.assertNotIn("v9:fixture:101", [item["settlement_key"] for item in batch])
            self.outbox.mark_confirmed_many([item["settlement_key"] for item in batch])
        self.assertEqual(lengths, [32, 32, 32, 4])
        self.assertEqual(self.schedule()["pending_count"], 1)
        self.assertEqual(self.schedule()["next_trigger_at"], self.now + 7200)
        self.assertFalse(self.schedule()["flush_active"])

    def test_deadline_priority_cannot_skip_session_head_outside_query_window(self):
        # Keep the first receipt's deadline far away and make the following 299
        # receipts urgent.  A deadline-ordered LIMIT 256 query does not contain
        # sequence zero; the scheduler must still pull that head before any
        # later sequence is submitted.
        session_id = "0x" + "d" * 64
        for sequence in range(300):
            deadline = self.now + (100_000 if sequence == 0 else 100)
            self.outbox.enqueue(PreparedRelaySettlement(
                key=f"v9:ordered:{sequence}", session_id=session_id,
                receipt_hash="0x" + f"{sequence:064x}", sequence=sequence,
                chain_id=11155111, settlement_contract=self.contract,
                calldata="0x1234", payload={
                    "protocol_version": 9, "tuple_data": "0x1234",
                    "signed_receipt": {"authorization": {"authorization": {
                        "key": self.key_address, "deadline": deadline}},
                        "receipt": {}},
                }))
        batch = self.outbox.next_batch(8, prioritize_deadlines=True)
        self.assertEqual([int(item["sequence"]) for item in batch], list(range(8)))

    def test_short_signed_deadline_flushes_early_without_extending_authorization(self):
        deadline = self.now + 900
        prepared = self.add(1, deadline=deadline)
        self.assertEqual(self.schedule()["next_trigger_at"], deadline - 300)
        self.assertEqual(self.schedule()["next_trigger_reason"], "authorization_deadline")
        self.now += 599
        self.assertEqual(self.worker._next_scheduled_batch(), [])
        self.now += 1
        batch = self.worker._next_scheduled_batch()
        self.assertEqual(len(batch), 1)
        self.assertEqual(json.loads(batch[0]["payload_json"]), prepared.payload)

    def test_earliest_receipt_deadline_wins_and_urgent_receipt_is_first(self):
        self.add(1)
        self.add(2, receipt_deadline=self.now + 301)
        self.assertEqual(self.schedule()["next_trigger_at"], self.now + 1)
        self.now += 1
        batch = self.worker._next_scheduled_batch()
        self.assertEqual(batch[0]["settlement_key"], "v9:fixture:2")

    def test_urgent_new_receipt_can_join_active_flush_without_resetting_its_timer(self):
        self.worker = self.submitter(settlement_count_threshold=2, batch_size=1)
        self.add(1)
        self.add(2)
        first = self.worker._next_scheduled_batch()
        trigger = self.schedule()["next_trigger_at"]
        self.outbox.mark_confirmed(first[0]["settlement_key"])
        self.now += 1
        self.add(3, deadline=self.now + 100)
        batch = self.worker._next_scheduled_batch()
        self.assertEqual(batch[0]["settlement_key"], "v9:fixture:3")
        self.assertEqual(self.schedule()["next_trigger_at"], trigger)
        self.assertEqual(self.schedule()["next_trigger_reason"], "authorization_deadline")

    def test_retry_bypasses_interval_and_keeps_original_queue_age(self):
        prepared = self.add(1)
        enqueued = self.now
        self.now += 60
        self.outbox.mark_failed(prepared.key, "rpc_unavailable", retryable=True)
        self.outbox = RelaySettlementOutbox(self.path)
        self.worker = self.submitter()
        self.assertEqual(self.schedule()["oldest_pending_at"], enqueued)
        self.assertEqual(self.schedule()["next_trigger_reason"], "retry")
        self.assertEqual(len(self.worker._next_scheduled_batch()), 1)

    def test_submitted_batch_recovery_bypasses_wait_and_does_not_get_split(self):
        keys = [self.add(index).key for index in (1, 2)]
        self.outbox.mark_submitted_many(keys, "0x" + "1" * 64)
        self.worker = self.submitter(batch_size=1)
        self.assertEqual(self.schedule()["next_trigger_reason"], "recovery")
        self.assertEqual(len(self.worker._next_scheduled_batch()), 2)
        self.rpc.assert_not_called()

    def test_legacy_unknown_broadcast_fences_new_transactions(self):
        self.add(1)
        self.add(2)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE relay_settlement_outbox SET status='broadcast_unknown',error='broadcast_unknown' WHERE settlement_key='v9:fixture:1'")
        self.now += 7200
        self.assertEqual(self.worker._next_scheduled_batch(), [])
        self.assertEqual(self.outbox.next_batch(), [])
        self.assertEqual(self.schedule()["next_trigger_reason"], "broadcast_unknown")
        self.assertIsNone(self.schedule()["next_trigger_at"])

    def test_expiry_sweep_does_not_resurrect_or_send_expired_cohort(self):
        self.add(1, deadline=self.now + 20)
        self.assertEqual(len(self.worker._next_scheduled_batch()), 1)
        self.now += 21
        self.assertEqual(self.outbox.expire_pending(), 1)
        self.assertEqual(self.worker._next_scheduled_batch(), [])
        self.assertEqual(self.schedule()["next_trigger_reason"], "empty")

    def test_health_exposes_policy_and_age_without_signatures_or_private_cohort_ids(self):
        self.add(1)
        self.now += 5
        status = self.schedule()
        self.assertEqual((status["interval_seconds"], status["count_threshold"]), (7200, 100))
        self.assertEqual(status["oldest_pending_age_seconds"], 5)
        self.assertNotIn("_pending_rowid_ceiling", status)
        self.assertNotIn("signed_receipt", json.dumps(status))

    def test_policy_validation_and_minimum_deadline_margin(self):
        for options in ({"settlement_count_threshold": 0}, {"settlement_count_threshold": True},
                        {"settlement_interval_seconds": float("nan")},
                        {"settlement_deadline_margin_seconds": -1}):
            with self.subTest(options=options), self.assertRaises(RelaySettlementError):
                self.submitter(**options)
        worker = self.submitter(settlement_deadline_margin_seconds=1)
        self.assertGreaterEqual(worker.settlement_deadline_margin_seconds,
            worker.poll_seconds + worker.tx_timeout_seconds + worker.receipt_timeout_seconds)

    def test_legacy_schema_migration_preserves_pending_deadline_and_last_success(self):
        legacy_path = self.path.with_name("legacy.sqlite3")
        prepared = self.prepared(1, deadline=self.now + 900)
        with sqlite3.connect(legacy_path) as db:
            db.execute("CREATE TABLE relay_settlement_outbox (settlement_key TEXT PRIMARY KEY,session_id TEXT NOT NULL,receipt_hash TEXT NOT NULL,sequence INTEGER NOT NULL,chain_id INTEGER NOT NULL,settlement_contract TEXT NOT NULL,calldata TEXT NOT NULL,payload_json TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',tx_hash TEXT,error TEXT,attempts INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)")
            values = (prepared.key, prepared.session_id, prepared.receipt_hash, 0,
                prepared.chain_id, prepared.settlement_contract, prepared.calldata,
                json.dumps(prepared.payload), "pending", self.now - 60, self.now - 60)
            db.execute("INSERT INTO relay_settlement_outbox(settlement_key,session_id,receipt_hash,sequence,chain_id,settlement_contract,calldata,payload_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", values)
            db.execute("INSERT INTO relay_settlement_outbox(settlement_key,session_id,receipt_hash,sequence,chain_id,settlement_contract,calldata,payload_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("old-success", *values[1:8], "escrowed", self.now - 400, self.now - 300))
        self.outbox = RelaySettlementOutbox(legacy_path)
        self.worker = self.submitter()
        status = self.schedule()
        self.assertEqual(status["oldest_pending_age_seconds"], 60)
        self.assertEqual(status["last_settlement_at"], self.now - 300)
        self.assertEqual(status["earliest_authorization_deadline"], self.now + 900)
        self.assertEqual(status["next_trigger_at"], self.now + 600)


if __name__ == "__main__":
    unittest.main()
