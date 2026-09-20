from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway.chain import ChainError, keccak256
from gateway.session_relayer import (
    PreparedRelaySettlement,
    RelaySettlementError,
    RelaySettlementOutbox,
    RelaySettlementSubmitter,
)


class SessionRelayerSubmissionTest(unittest.TestCase):
    chain_id = 11155111
    key_address = "0x" + "a" * 40
    contract = "0x" + "b" * 40
    gas_price = 2_000_000_000
    receipt_budget = 250_000 * gas_price * 15_000 // 10_000
    fake_raw_transaction = b"unit-test-transaction-with-no-real-signature"

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.outbox = RelaySettlementOutbox(Path(directory.name) / "outbox.sqlite3")
        self.balance = self.receipt_budget * 3
        self.tx_hash = "0x" + keccak256(self.fake_raw_transaction).hex()
        self.broadcast_error: Exception | None = None
        self.estimate_error: Exception | None = None
        self.receipt = {
            "status": "0x1",
            "gasUsed": hex(100_000),
            "effectiveGasPrice": hex(self.gas_price),
        }
        self.broadcast_observations = []
        rpc_patch = patch("gateway.session_relayer.rpc_call", side_effect=self._rpc)
        self.rpc = rpc_patch.start()
        self.addCleanup(rpc_patch.stop)
        sign_patch = patch(
            "gateway.session_relayer.sign_legacy_transaction",
            return_value=self.fake_raw_transaction,
        )
        self.sign = sign_patch.start()
        self.addCleanup(sign_patch.stop)

    def _rpc(self, rpc_url: str, method: str, params: list, timeout: float):
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getTransactionCount":
            return "0x7"
        if method == "eth_gasPrice":
            return hex(self.gas_price)
        if method == "eth_getBlockByNumber":
            return {"baseFeePerGas": "0x0"}
        if method == "eth_estimateGas":
            if self.estimate_error is not None:
                raise self.estimate_error
            return hex(100_000)
        if method == "eth_getBalance":
            return hex(self.balance)
        if method == "eth_sendRawTransaction":
            # A separate SQLite connection observes committed state before
            # the fake broadcast accepts or rejects the transaction.
            with sqlite3.connect(self.outbox.path) as db:
                rows = db.execute(
                    "SELECT status,tx_hash FROM relay_settlement_outbox ORDER BY settlement_key"
                ).fetchall()
                raw_transactions = db.execute("SELECT raw_transaction FROM relay_settlement_outbox").fetchall()
            self.broadcast_observations.append(rows)
            self.assertTrue(rows)
            self.assertTrue(all(row == ("submitted", self.tx_hash) for row in rows))
            self.assertTrue(all(row[0] == params[0] for row in raw_transactions))
            if self.broadcast_error is not None:
                raise self.broadcast_error
            return self.tx_hash
        if method == "eth_getTransactionReceipt":
            self.assertEqual(params, [self.tx_hash])
            return self.receipt
        raise AssertionError(f"unexpected RPC method: {method}")

    def _submitter(self, outbox: RelaySettlementOutbox | None = None):
        submitter = RelaySettlementSubmitter(
            outbox=self.outbox if outbox is None else outbox,
            rpc_url="http://unit-test.invalid",
            private_key="0x" + "4" * 64,
            expected_chain_id=self.chain_id,
            health_timeout_seconds=1.0,
        )
        submitter._thread = SimpleNamespace(is_alive=lambda: True)
        submitter._worker_heartbeat = time.monotonic()
        return submitter

    def _prepared(
        self,
        index: int = 1,
        *,
        deadline: int | None = None,
        receipt_deadline: int | None = None,
    ) -> PreparedRelaySettlement:
        request_id = "0x" + f"{index:064x}"
        receipt = {"request_id": request_id}
        if receipt_deadline is not None:
            receipt["deadline"] = receipt_deadline
        return PreparedRelaySettlement(
            key=f"v8:{self.key_address}:{request_id}",
            session_id=request_id,
            receipt_hash="0x" + "c" * 64,
            sequence=0,
            chain_id=self.chain_id,
            settlement_contract=self.contract,
            calldata="0x1234",
            payload={
                "schema": "mycomesh.relay.settlement.v8",
                "protocol_version": 8,
                "tuple_data": "0x1234",
                "signed_receipt": {
                    "receipt": receipt,
                    "provider_signature": "fake-provider-signature",
                    "authorization": {
                        "authorization": {
                            "request_id": request_id,
                            "key": self.key_address,
                            "deadline": int(time.time()) + 900 if deadline is None else deadline,
                        },
                        "signature": "fake-authorization-signature",
                    },
                },
            },
        )

    def _methods(self) -> list[str]:
        return [call.args[1] for call in self.rpc.call_args_list]

    def _status(self, prepared: PreparedRelaySettlement) -> dict:
        return self.outbox.public_status(prepared.session_id, key_address=self.key_address)

    def test_expired_authorization_fails_without_sending(self) -> None:
        prepared = self._prepared(deadline=int(time.time()) - 1)
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        with patch.object(submitter, "_send_transaction") as send:
            submitter._process(self.outbox.next_batch())
        send.assert_not_called()
        self.rpc.assert_not_called()
        self.sign.assert_not_called()
        self.assertEqual(self._status(prepared)["status"], "failed")
        self.assertEqual(self._status(prepared)["error_code"], "authorization_expired")
        self.assertEqual(self.outbox.next_batch(), [])

    def test_earlier_receipt_deadline_prevents_sending(self) -> None:
        prepared = self._prepared(receipt_deadline=int(time.time()) - 1)
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        with patch.object(submitter, "_send_transaction") as send:
            submitter._process(self.outbox.next_batch())
        send.assert_not_called()
        self.sign.assert_not_called()
        self.assertEqual(self._status(prepared)["status"], "failed")

    def test_mixed_batch_sends_only_unexpired_receipt(self) -> None:
        expired = self._prepared(1, deadline=int(time.time()) - 1)
        valid = self._prepared(2)
        self.outbox.enqueue(expired)
        self.outbox.enqueue(valid)
        submitter = self._submitter()
        with (
            patch.object(submitter, "_send_transaction", return_value=self.tx_hash) as send,
            patch.object(submitter, "_wait_for_receipt") as wait,
        ):
            submitter._process(self.outbox.next_batch())
        send.assert_called_once()
        sent_items, calldata = send.call_args.args
        self.assertEqual([item["settlement_key"] for item in sent_items], [valid.key])
        self.assertEqual(calldata, valid.calldata)
        wait.assert_called_once_with([valid.key], self.tx_hash)
        self.assertEqual(self.outbox.status(expired.key), "failed")
        self.sign.assert_not_called()

    def test_preflight_authorization_expiry_is_permanent(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.estimate_error = ChainError("execution reverted: authorization expired")
        submitter = self._submitter()
        submitter._process(self.outbox.next_batch())
        self.assertEqual(self._status(prepared)["status"], "failed")
        self.assertEqual(self._status(prepared)["error_code"], "authorization_expired")
        self.assertEqual(self.outbox.next_batch(), [])
        self.sign.assert_not_called()
        self.assertNotIn("eth_sendRawTransaction", self._methods())

    def test_preflight_batch_expiry_isolates_receipts_without_requeueing_expired(self) -> None:
        expired_at_contract = self._prepared(1)
        valid = self._prepared(2)
        self.outbox.enqueue(expired_at_contract)
        self.outbox.enqueue(valid)
        submitter = self._submitter()

        def send(items, calldata):
            keys = [item["settlement_key"] for item in items]
            if expired_at_contract.key in keys:
                raise RelaySettlementError("authorization expired", error_code="authorization_expired")
            self.outbox.mark_submitted_many(keys, self.tx_hash)
            return self.tx_hash

        with (
            patch.object(submitter, "_send_transaction", side_effect=send) as sending,
            patch.object(submitter, "_wait_for_receipt") as wait,
        ):
            submitter._process(self.outbox.next_batch())
        self.assertEqual(sending.call_count, 3)
        self.assertEqual(self.outbox.status(expired_at_contract.key), "failed")
        self.assertEqual(self.outbox.status(valid.key), "submitted")
        self.assertEqual(submitter.batch_size, 8)
        wait.assert_called_once_with([valid.key], self.tx_hash)

    def test_unknown_broadcast_is_durable_and_next_attempt_only_polls_same_hash(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        self.broadcast_error = TimeoutError("RPC broadcast timed out")
        with self.assertRaises(RelaySettlementError) as raised:
            submitter._process(self.outbox.next_batch())
        self.assertEqual(raised.exception.error_code, "broadcast_unknown")
        self.assertEqual(self.broadcast_observations, [[("submitted", self.tx_hash)]])
        self.assertEqual(self._status(prepared)["status"], "submitted")
        self.assertEqual(self._status(prepared)["tx_hash"], self.tx_hash)
        self.assertEqual(self._status(prepared)["error_code"], "broadcast_unknown")
        self.assertEqual(self._methods().count("eth_getTransactionCount"), 1)
        self.assertEqual(self._methods().count("eth_sendRawTransaction"), 1)
        self.sign.assert_called_once()

        self.rpc.reset_mock()
        submitter._process(self.outbox.next_batch())
        self.assertEqual(self._methods(), ["eth_getTransactionReceipt"])
        self.assertEqual(self._status(prepared)["status"], "confirmed")
        self.assertEqual(self._status(prepared)["tx_hash"], self.tx_hash)
        self.sign.assert_called_once()

    def test_unknown_broadcast_still_blocks_admission_after_submitter_restart(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        self.broadcast_error = TimeoutError("RPC broadcast timed out")
        with self.assertRaises(RelaySettlementError):
            submitter._process(self.outbox.next_batch())

        reopened = RelaySettlementOutbox(self.outbox.path)
        restarted = self._submitter(reopened)
        restarted.refresh_health()
        status = restarted.snapshot()
        self.assertIs(status["worker_alive"], True)
        self.assertGreater(status["gas_capacity_remaining"], 0)
        self.assertIs(status["ready"], False)
        self.assertEqual(status["error_code"], "broadcast_unknown")
        with self.assertRaises(RelaySettlementError) as raised:
            restarted.reserve_admission()
        self.assertEqual(raised.exception.error_code, "broadcast_unknown")
        self.rpc.reset_mock()
        restarted._process(reopened.next_batch())
        self.assertEqual(self._methods(), ["eth_getTransactionReceipt"])
        self.assertIs(restarted.snapshot()["ready"], True)
        self.sign.assert_called_once()

    def test_failed_hash_persistence_prevents_broadcast(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        with patch.object(
            self.outbox, "mark_submitted_many", side_effect=sqlite3.OperationalError("disk full")
        ):
            with self.assertRaises(sqlite3.OperationalError):
                submitter._send_transaction(self.outbox.next_batch(), prepared.calldata)
        self.assertNotIn("eth_sendRawTransaction", self._methods())
        self.assertEqual(self._status(prepared)["status"], "pending")
        self.assertIsNone(self._status(prepared)["tx_hash"])
        self.sign.assert_called_once()

    def test_submitted_reverted_receipt_fails_without_rebroadcasting(self) -> None:
        prepared = self._prepared(deadline=int(time.time()) - 1)
        self.outbox.enqueue(prepared)
        self.outbox.mark_submitted(prepared.key, self.tx_hash)
        self.receipt["status"] = "0x0"
        submitter = self._submitter()
        submitter._process(self.outbox.next_batch())
        self.assertEqual(self._methods(), ["eth_getTransactionReceipt"])
        self.assertEqual(self._status(prepared)["status"], "failed")
        self.assertEqual(self._status(prepared)["error_code"], "transaction_reverted")
        self.assertEqual(self._status(prepared)["tx_hash"], self.tx_hash)
        self.assertEqual(self.outbox.next_batch(), [])
        self.sign.assert_not_called()

    def test_definitive_insufficient_funds_clears_hash_but_retains_pending_budget(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        submitter.refresh_health()
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 2)
        self.broadcast_error = ChainError("insufficient funds for gas * price + value")
        with self.assertRaises(RelaySettlementError) as raised:
            submitter._process(self.outbox.next_batch())
        self.assertEqual(raised.exception.error_code, "low_gas")
        self.assertEqual(self._status(prepared)["status"], "pending")
        self.assertIsNone(self._status(prepared)["tx_hash"])
        self.assertEqual(self._status(prepared)["error_code"], "low_gas")
        self.assertIsNone(self.outbox.blocking_error())
        self.assertEqual(self._methods().count("eth_sendRawTransaction"), 1)

        after_pause = time.monotonic() + submitter.poll_seconds + 1
        with patch("gateway.session_relayer.time.monotonic", return_value=after_pause):
            submitter.refresh_health()
            self.assertIs(submitter.snapshot()["ready"], True)
            self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 2)
            submitter.reserve_admission()
            submitter.reserve_admission()
            with self.assertRaises(RelaySettlementError):
                submitter.reserve_admission()
        self.assertEqual(self.outbox.snapshot(), {"pending": 1})

    def test_broadcast_uses_fallback_that_passed_read_only_preflight_not_a_403_primary(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        primary, backup = "http://primary.invalid", "http://backup.invalid"
        submitter.rpc_url = f"{primary},{backup}"
        def answer(url, method, params, timeout):
            if method == "eth_getTransactionReceipt":
                return self._rpc(url, method, params, timeout)
            if url == primary:
                raise ChainError("RPC request failed: HTTP 403")
            self.assertEqual(url, backup)
            return self._rpc(url, method, params, timeout)
        self.rpc.side_effect = answer
        submitter._process(self.outbox.next_batch())
        broadcasts = [call.args[0] for call in self.rpc.call_args_list if call.args[1] == "eth_sendRawTransaction"]
        self.assertEqual(broadcasts, [backup])
        self.assertEqual(self.outbox.status(prepared.key), "confirmed")
        self.sign.assert_called_once()

    def test_broadcast_timeout_never_falls_back_or_signs_another_nonce(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        submitter = self._submitter()
        primary, backup = "http://primary.invalid", "http://backup.invalid"
        submitter.rpc_url = f"{primary},{backup}"
        self.broadcast_error = TimeoutError("broadcast response lost")
        with self.assertRaises(RelaySettlementError):
            submitter._process(self.outbox.next_batch())
        self.assertEqual(self._methods().count("eth_sendRawTransaction"), 1)
        self.assertEqual(self._methods().count("eth_getTransactionCount"), 1)
        self.assertTrue(all(call.args[0] == primary for call in self.rpc.call_args_list))
        self.assertEqual(self._status(prepared)["error_code"], "broadcast_unknown")
        self.assertEqual(self._status(prepared)["tx_hash"], self.tx_hash)
        self.sign.assert_called_once()

    def test_restart_rebroadcasts_identical_bytes_to_chain_checked_fallback(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.broadcast_error = TimeoutError("initial broadcast response lost")
        with self.assertRaises(RelaySettlementError):
            self._submitter()._process(self.outbox.next_batch())
        reopened = RelaySettlementOutbox(self.outbox.path)
        restarted = self._submitter(reopened)
        primary, backup = "http://primary.invalid", "http://backup.invalid"
        restarted.rpc_url = f"{primary},{backup}"
        confirmed_receipt = self.receipt
        self.receipt = None
        raw_payloads = []

        def answer(url, method, params, timeout):
            if method == "eth_sendRawTransaction":
                raw_payloads.append((url, params[0]))
                if url == primary:
                    raise TimeoutError("response lost")
                self.broadcast_error = None
                self.receipt = confirmed_receipt
            return self._rpc(url, method, params, timeout)

        self.rpc.reset_mock()
        self.rpc.side_effect = answer
        restarted.refresh_health()
        self.assertFalse(restarted.snapshot()["ready"])
        with patch.object(restarted._stop, "wait"):
            restarted._process(reopened.next_batch())
        self.assertEqual(raw_payloads, [(primary, "0x" + self.fake_raw_transaction.hex()),
                                       (backup, "0x" + self.fake_raw_transaction.hex())])
        self.assertNotIn("eth_getTransactionCount", self._methods())
        self.sign.assert_called_once()
        self.assertEqual(self._status(prepared)["status"], "confirmed")
        self.assertTrue(restarted.snapshot()["ready"])
        self.assertNotIn("raw_transaction", self._status(prepared))

    def test_crash_after_durable_signature_before_first_broadcast_recovers(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        original_rpc = self._rpc

        def crash(url, method, params, timeout):
            if method == "eth_sendRawTransaction":
                raise SystemExit("simulated process death")
            return original_rpc(url, method, params, timeout)

        self.rpc.side_effect = crash
        with self.assertRaises(SystemExit):
            self._submitter()._process(self.outbox.next_batch())
        reopened = RelaySettlementOutbox(self.outbox.path)
        self.assertEqual(reopened.status(prepared.key), "submitted")
        self.assertEqual(reopened.signed_transaction([prepared.key], self.tx_hash),
                         (self.chain_id, "0x" + self.fake_raw_transaction.hex()))
        confirmed_receipt = self.receipt
        self.receipt = None

        def recovered(url, method, params, timeout):
            result = original_rpc(url, method, params, timeout)
            if method == "eth_sendRawTransaction":
                self.receipt = confirmed_receipt
            return result

        self.rpc.reset_mock()
        self.rpc.side_effect = recovered
        restarted = self._submitter(reopened)
        with patch.object(restarted._stop, "wait"):
            restarted._process(reopened.next_batch())
        self.assertEqual(self._status(prepared)["status"], "confirmed")
        self.assertEqual(self._methods().count("eth_sendRawTransaction"), 1)
        self.assertNotIn("eth_getTransactionCount", self._methods())
        self.sign.assert_called_once()

    def test_recovery_rejection_cannot_recycle_a_previously_broadcast_nonce(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_submitted_many([prepared.key], self.tx_hash,
                                        raw_transaction="0x" + self.fake_raw_transaction.hex())
        self.receipt = None
        self.broadcast_error = ChainError("insufficient funds for gas * price + value")
        with self.assertRaises(RelaySettlementError) as raised:
            self._submitter()._process(self.outbox.next_batch())
        self.assertEqual(raised.exception.error_code, "broadcast_unknown")
        self.assertEqual(self._status(prepared)["status"], "submitted")
        self.assertEqual(self._status(prepared)["tx_hash"], self.tx_hash)
        self.assertIsNotNone(self.outbox.signed_transaction([prepared.key], self.tx_hash))
        self.assertNotIn("eth_getTransactionCount", self._methods())
        self.sign.assert_not_called()

    def test_corrupt_durable_signature_blocks_rebroadcast(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_submitted_many([prepared.key], self.tx_hash,
                                        raw_transaction="0x" + self.fake_raw_transaction.hex())
        with sqlite3.connect(self.outbox.path) as db:
            db.execute("UPDATE relay_settlement_outbox SET raw_transaction='0x1234'")
        self.receipt = None
        with self.assertRaises(RelaySettlementError) as raised:
            self._submitter()._process(self.outbox.next_batch())
        self.assertEqual(raised.exception.error_code, "broadcast_unknown")
        self.assertEqual(self._status(prepared)["status"], "submitted")
        self.assertNotIn("eth_sendRawTransaction", self._methods())
        self.sign.assert_not_called()

    def test_receipt_lookup_checks_backup_when_primary_has_no_transaction(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_submitted_many([prepared.key], self.tx_hash,
                                        raw_transaction="0x" + self.fake_raw_transaction.hex())
        submitter = self._submitter()
        primary, backup = "http://primary.invalid", "http://backup.invalid"
        submitter.rpc_url = f"{primary},{backup}"

        def answer(url, method, params, timeout):
            if url == primary and method == "eth_getTransactionReceipt":
                return None
            return self._rpc(url, method, params, timeout)

        self.rpc.side_effect = answer
        submitter._process(self.outbox.next_batch())
        self.assertEqual(self._status(prepared)["status"], "confirmed")
        self.assertEqual(self._methods().count("eth_getTransactionReceipt"), 2)
        self.assertNotIn("eth_sendRawTransaction", self._methods())
        self.sign.assert_not_called()

    def test_rebroadcast_skips_wrong_chain_and_already_known_clears_block(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_submitted_many([prepared.key], self.tx_hash,
                                        raw_transaction="0x" + self.fake_raw_transaction.hex())
        submitter = self._submitter()
        primary, backup = "http://primary.invalid", "http://backup.invalid"
        submitter.rpc_url = f"{primary},{backup}"
        submitter._submission_error("broadcast_unknown")

        def answer(url, method, params, timeout):
            if url == primary:
                self.assertEqual(method, "eth_chainId")
                return "0x1"
            if method == "eth_sendRawTransaction":
                raise ChainError("already known")
            return self._rpc(url, method, params, timeout)

        self.rpc.side_effect = answer
        submitter._rebroadcast_submitted([prepared.key], self.tx_hash)
        self.assertIsNone(self.outbox.blocking_error())
        self.assertIsNone(submitter._submission_error_code)
        self.assertEqual(submitter._submission_block_until, 0.0)
        self.assertEqual(self._status(prepared)["status"], "submitted")
        self.assertNotIn("eth_getTransactionCount", self._methods())
        self.sign.assert_not_called()

    def test_persisted_submission_cannot_be_overwritten_by_a_new_signature(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        raw = "0x" + self.fake_raw_transaction.hex()
        self.outbox.mark_submitted_many([prepared.key], self.tx_hash, raw_transaction=raw)
        other_raw = b"different transaction"
        with self.assertRaises(RelaySettlementError):
            self.outbox.mark_submitted_many([prepared.key], "0x" + keccak256(other_raw).hex(),
                                            raw_transaction="0x" + other_raw.hex())
        self.assertEqual(self.outbox.signed_transaction([prepared.key], self.tx_hash), (self.chain_id, raw))

    def test_low_gas_before_any_acceptance_clears_recoverable_bytes_with_hash(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.broadcast_error = ChainError("insufficient funds for gas * price + value")
        with self.assertRaises(RelaySettlementError):
            self._submitter()._process(self.outbox.next_batch())
        with sqlite3.connect(self.outbox.path) as db:
            row = db.execute("SELECT status,tx_hash,raw_transaction FROM relay_settlement_outbox").fetchone()
        self.assertEqual(row, ("pending", None, None))

    def test_schema_migration_preserves_legacy_ambiguous_submission(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        legacy_path = self.outbox.path.with_name("legacy.sqlite3")
        with sqlite3.connect(legacy_path) as db:
            db.execute("""CREATE TABLE relay_settlement_outbox (
                settlement_key TEXT PRIMARY KEY, session_id TEXT NOT NULL,
                receipt_hash TEXT NOT NULL, sequence INTEGER NOT NULL,
                chain_id INTEGER NOT NULL, settlement_contract TEXT NOT NULL,
                calldata TEXT NOT NULL, payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', tx_hash TEXT, error TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
            db.execute("ATTACH DATABASE ? AS current_outbox", (str(self.outbox.path),))
            db.execute("""INSERT INTO relay_settlement_outbox
                SELECT settlement_key,session_id,receipt_hash,sequence,chain_id,
                settlement_contract,calldata,payload_json,'submitted',?,
                'broadcast_unknown',1,created_at,updated_at
                FROM current_outbox.relay_settlement_outbox""", (self.tx_hash,))
        legacy = RelaySettlementOutbox(legacy_path)
        self.assertEqual(legacy.status(prepared.key), "submitted")
        self.assertEqual(legacy.blocking_error(), "broadcast_unknown")
        self.assertIsNone(legacy.signed_transaction([prepared.key], self.tx_hash))
        self.assertEqual(legacy.next_batch()[0]["attempts"], 1)
        self._submitter(legacy)._process(legacy.next_batch())
        self.assertEqual(legacy.status(prepared.key), "confirmed")
        self.assertEqual(self._methods(), ["eth_getTransactionReceipt"])

    def test_batch_signature_persistence_is_atomic_if_any_row_is_missing(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        with self.assertRaises(RelaySettlementError):
            self.outbox.mark_submitted_many([prepared.key, "missing"], self.tx_hash,
                                            raw_transaction="0x" + self.fake_raw_transaction.hex())
        self.assertEqual(self._status(prepared)["status"], "pending")
        self.assertIsNone(self._status(prepared)["tx_hash"])
        with sqlite3.connect(self.outbox.path) as db:
            self.assertIsNone(db.execute("SELECT raw_transaction FROM relay_settlement_outbox").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
