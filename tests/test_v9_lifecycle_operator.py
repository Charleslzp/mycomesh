"""Escrow maintenance uses synthetic roles and mocked local RPC only."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from gateway import chain, chain_v9
from gateway.relay_adjudication_v9 import V9AdjudicationError, V9TransactionOutbox, main
from tests.test_relay_adjudication_v9 import V9Fixture, address, digest, key


class V9LifecyclePlanTests(V9Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.snap["settlement"]["release_at"] = self.now
        self.snapshot_mock = patch.object(self.client, "snapshot", side_effect=self.snapshot)
        self.snapshot_mock.start()
        self.addCleanup(self.snapshot_mock.stop)

    def plan(self, action="release"):
        return getattr(self.client, "plan_" + action)(actor=address(9), settlement_key=self.settlement_key)

    def test_release_at_exact_deadline_is_read_only_and_not_a_payout(self):
        with patch.object(self.client, "rpc") as rpc:
            plan = self.plan()
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["monetary_verdict"])
        self.assertEqual(plan["amounts"], {"escrow_fee_units": 100})
        self.assertEqual(plan["transaction"]["data"], chain_v9.encode_release(self.settlement_key))
        rpc.assert_not_called()

    def test_release_rejects_early_missing_disputed_or_terminal_records(self):
        original = copy.deepcopy(self.snap)
        for status, release_at in ((0, self.now), (1, self.now + 1), (2, self.now),
                                   (3, self.now), (4, self.now), (5, self.now), (6, self.now)):
            self.snap = copy.deepcopy(original)
            self.snap["settlement"].update(status=status, release_at=release_at)
            with self.subTest(status=status, release_at=release_at), self.assertRaises(V9AdjudicationError):
                self.plan()

    def test_timeout_requires_disputed_record_and_full_arbitration_window(self):
        self.snap["settlement"].update(status=2, release_at=self.now - 100)
        self.snap["dispute"]["resolve_at"] = self.now + 1
        with self.assertRaisesRegex(V9AdjudicationError, "not due"):
            self.plan("timeout")
        self.snap["dispute"]["resolve_at"] = self.now
        plan = self.plan("timeout")
        self.assertEqual(plan["transaction"]["data"], chain_v9.encode_resolve_timed_out_dispute(self.settlement_key))
        self.assertFalse(plan["monetary_verdict"])
        for status in (0, 1, 3, 4, 5, 6):
            self.snap["settlement"]["status"] = status
            with self.subTest(status=status), self.assertRaises(V9AdjudicationError):
                self.plan("timeout")

    def test_zero_actor_and_mismatched_settlement_identity_are_rejected(self):
        with self.assertRaises(V9AdjudicationError):
            self.client.plan_release(actor=chain.ZERO_ADDRESS, settlement_key=self.settlement_key)
        self.snap["settlement"]["request_id"] = digest(1000)
        with self.assertRaisesRegex(V9AdjudicationError, "matching"):
            self.plan()

    def test_plan_refresh_rechecks_maturity_and_concurrent_resolution(self):
        plan = self.plan()
        self.client.refresh(plan)
        for status in (2, 3):
            self.snap["settlement"]["status"] = status
            with self.subTest(status=status), self.assertRaises(V9AdjudicationError):
                self.client.refresh(plan)

    def test_final_state_requires_matching_confirmed_snapshot_after_transaction(self):
        plan = self.plan()
        with self.assertRaisesRegex(V9AdjudicationError, "outcome"):
            self.client.verify_lifecycle(plan, minimum_block_number=99)
        self.snap["settlement"]["status"] = 3
        result = self.client.verify_lifecycle(plan, minimum_block_number=99)
        self.assertEqual(result["status"], "released")
        self.assertTrue(result["verified"])
        self.assertFalse(result["wallet_payout_verified"])
        with self.assertRaisesRegex(V9AdjudicationError, "predates"):
            self.client.verify_lifecycle(plan, minimum_block_number=100)
        self.snap["settlement"]["response_hash"] = digest(999)
        with self.assertRaisesRegex(V9AdjudicationError, "differs"):
            self.client.verify_lifecycle(plan, minimum_block_number=99)

    def test_timeout_verification_rejects_other_terminal_outcomes(self):
        self.snap["settlement"].update(status=2, release_at=self.now - 100)
        self.snap["dispute"]["resolve_at"] = self.now
        plan = self.plan("timeout")
        for status in (3, 4, 5):
            self.snap["settlement"]["status"] = status
            with self.subTest(status=status), self.assertRaisesRegex(V9AdjudicationError, "outcome"):
                self.client.verify_lifecycle(plan, minimum_block_number=99)
        self.snap["settlement"]["status"] = 6
        self.assertEqual(self.client.verify_lifecycle(plan, minimum_block_number=99)["status"], "timed_out")

    def test_final_state_verification_rejects_tampered_plan_or_network(self):
        plan = self.plan()
        self.snap["settlement"]["status"] = 3
        for field in ("inputs", "domain"):
            altered = copy.deepcopy(plan)
            altered[field]["settlement_key"] = digest(999)
            with self.subTest(field=field), self.assertRaisesRegex(V9AdjudicationError, "hash"):
                self.client.verify_lifecycle(altered, minimum_block_number=99)

    def test_cli_exposes_both_exact_key_plans_without_execution(self):
        for action in ("release", "timeout"):
            self.snap["settlement"].update(status=1 if action == "release" else 2, release_at=self.now - 100)
            self.snap["dispute"]["resolve_at"] = self.now
            output = io.StringIO()
            with patch("gateway.relay_adjudication_v9.V9OperatorConfig.load", return_value=self.config), \
                    patch("gateway.relay_adjudication_v9.V9AdjudicationClient", return_value=self.client), \
                    patch("sys.stdout", output):
                result = main(["--config", "unused-fixture.json", "plan-" + action,
                               "--actor", address(9), "--settlement-key", self.settlement_key])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["action"], action)


class V9LifecycleOutboxTests(V9Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.snap["settlement"]["release_at"] = self.now
        snapshot_patch = patch.object(self.client, "snapshot", side_effect=self.snapshot)
        snapshot_patch.start()
        self.addCleanup(snapshot_patch.stop)
        self.plan = self.client.plan_release(actor=address(9), settlement_key=self.settlement_key)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "outbox.sqlite3"
        self.key_file = Path(self.directory.name) / "fixture-key"
        self.key_file.write_text(key(9))
        self.key_file.chmod(0o600)
        self.outbox = V9TransactionOutbox(self.path)
        self.addCleanup(self.outbox.close)
        self.receipt = None
        self.send_count = 0
        self.raise_send = False
        self.block_hash = digest(99)
        rpc_patch = patch.object(self.client, "rpc", side_effect=self.rpc)
        rpc_patch.start()
        self.addCleanup(rpc_patch.stop)

    def rpc(self, method, params):
        if method == "eth_getTransactionCount": return "0x0"
        if method == "eth_gasPrice": return "0x1"
        if method == "eth_estimateGas": return hex(50000)
        if method == "eth_sendRawTransaction":
            self.send_count += 1
            if self.raise_send: raise TimeoutError("fixture RPC lost response")
            return "0x" + chain.keccak256(bytes.fromhex(params[0][2:])).hex()
        if method == "eth_getTransactionReceipt": return self.receipt
        if method == "eth_chainId": return hex(31337)
        if method == "eth_getBlockByNumber": return {"hash": digest(10) if params[0] == "0x0" else self.block_hash}
        if method == "eth_blockNumber": return hex(100)
        raise AssertionError(method)

    def execute(self, outbox=None, plan=None):
        plan = plan or self.plan
        return (outbox or self.outbox).execute(self.client, plan, allow_send=True,
            approved_plan_hash=plan["plan_hash"], key_file=self.key_file,
            max_gas_price_wei=10, max_gas_units=100000, max_total_gas_cost_wei=1000000)

    def confirmed_receipt(self, result):
        self.receipt = {"transactionHash": result["tx_hash"], "blockNumber": hex(99),
                        "blockHash": digest(99), "status": "0x1"}

    def test_lifecycle_default_dry_run_never_reads_key_or_broadcasts(self):
        self.assertEqual(self.outbox.execute(self.client, self.plan)["sent"], False)
        self.client.rpc.assert_not_called()

    def test_success_is_independently_verified_and_survives_restart(self):
        first = self.execute()
        self.confirmed_receipt(first)
        self.snap["settlement"]["status"] = 3
        result = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(result["state"], "confirmed")
        self.assertEqual(result["settlement_outcome"]["status"], "released")
        reopened = V9TransactionOutbox(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(self.execute(reopened), result)
        self.assertEqual(self.send_count, 1)

    def test_successful_transaction_without_business_outcome_locks_sender(self):
        self.confirmed_receipt(self.execute())
        with self.assertRaisesRegex(V9AdjudicationError, "outcome"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(self.outbox.get(self.plan["plan_hash"])["state"], "uncertain")
        self.snap["block_number"] += 1
        another = self.client.plan_release(actor=address(9), settlement_key=self.settlement_key)
        with self.assertRaisesRegex(V9AdjudicationError, "unresolved"):
            self.execute(plan=another)
        self.assertEqual(self.send_count, 1)

    def test_uncertain_broadcast_survives_restart_without_new_nonce(self):
        self.raise_send = True
        first = self.execute()
        reopened = V9TransactionOutbox(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(self.execute(reopened)["tx_hash"], first["tx_hash"])
        self.snap["block_number"] += 1
        another = self.client.plan_release(actor=address(9), settlement_key=self.settlement_key)
        with self.assertRaisesRegex(V9AdjudicationError, "unresolved"):
            self.execute(reopened, another)
        self.assertEqual(self.send_count, 1)

    def test_reorg_removes_previously_verified_outcome(self):
        self.confirmed_receipt(self.execute())
        self.snap["settlement"]["status"] = 3
        self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.block_hash = digest(100)
        result = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(result["state"], "uncertain")
        self.assertNotIn("settlement_outcome", result)

    def test_reorg_during_business_verification_keeps_sender_uncertain(self):
        self.confirmed_receipt(self.execute())
        self.snap["settlement"]["status"] = 3
        original = self.client.verify_lifecycle
        def verify(*args, **kwargs):
            result = original(*args, **kwargs)
            self.block_hash = digest(100)
            return result
        with patch.object(self.client, "verify_lifecycle", side_effect=verify), \
                self.assertRaisesRegex(V9AdjudicationError, "reorganized"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(self.outbox.get(self.plan["plan_hash"])["state"], "uncertain")

    def test_old_outbox_schema_preserves_pending_transaction(self):
        first = self.execute()
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE v9_operator_outcomes")
        reopened = V9TransactionOutbox(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(self.execute(reopened)["tx_hash"], first["tx_hash"])
        self.assertEqual(self.send_count, 1)


if __name__ == "__main__":
    unittest.main()
