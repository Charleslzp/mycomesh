from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway.chain import ChainError
from gateway.session_relayer import (
    PreparedRelaySettlement,
    RelaySettlementError,
    RelaySettlementOutbox,
    RelaySettlementSubmitter,
)


class SessionRelayerHealthTest(unittest.TestCase):
    chain_id = 11155111
    gas_price = 2_000_000_000
    gas_per_receipt = 250_000
    gas_safety_bps = 15_000
    key_address = "0x" + "a" * 40
    contract = "0x" + "b" * 40

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.outbox = RelaySettlementOutbox(Path(directory.name) / "relay.sqlite3")
        self.receipt_budget = (
            self.gas_price * self.gas_per_receipt * self.gas_safety_bps // 10_000
        )
        self.balance = self.receipt_budget * 3
        self.rpc_chain_id = self.chain_id
        self.rpc_failure: Exception | None = None
        rpc_patch = patch("gateway.session_relayer.rpc_call", side_effect=self._rpc)
        self.rpc = rpc_patch.start()
        self.addCleanup(rpc_patch.stop)
        send_patch = patch.object(
            RelaySettlementSubmitter,
            "_send_transaction",
            side_effect=AssertionError("unit tests must not submit transactions"),
            create=True,
        )
        self.send = send_patch.start()
        self.addCleanup(send_patch.stop)

    def _rpc(self, rpc_url: str, method: str, params: list, timeout: float):
        if self.rpc_failure is not None:
            raise self.rpc_failure
        if method == "eth_chainId":
            return hex(self.rpc_chain_id)
        if method == "eth_getBalance":
            return hex(self.balance)
        if method == "eth_gasPrice":
            return hex(self.gas_price)
        if method == "eth_getBlockByNumber":
            return {"baseFeePerGas": "0x0", "timestamp": hex(int(time.time()))}
        raise AssertionError(f"unexpected RPC method: {method}")

    def _submitter(self, *, alive: bool = True) -> RelaySettlementSubmitter:
        submitter = RelaySettlementSubmitter(
            outbox=self.outbox,
            rpc_url="http://unit-test.invalid",
            private_key="0x" + "4" * 64,
            expected_chain_id=self.chain_id,
            gas_per_receipt=self.gas_per_receipt,
            gas_safety_bps=self.gas_safety_bps,
            health_timeout_seconds=1.0,
        )
        submitter._thread = SimpleNamespace(is_alive=lambda: alive)
        submitter._worker_heartbeat = time.monotonic()
        return submitter

    def _prepared(self, index: int = 1, *, deadline: int | None = None):
        request_id = "0x" + f"{index:064x}"
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
                    "receipt": {"request_id": request_id},
                    "provider_signature": "test-provider-signature",
                    "authorization": {
                        "authorization": {
                            "request_id": request_id,
                            "key": self.key_address,
                            "deadline": int(time.time()) + 900 if deadline is None else deadline,
                        },
                        "signature": "test-authorization-signature",
                    },
                },
            },
        )

    def _assert_not_ready(self, submitter: RelaySettlementSubmitter) -> dict:
        status = submitter.snapshot()
        self.assertIs(status["ready"], False)
        self.assertIs(status["settlement_ready"], False)
        self.assertTrue(status["error_code"])
        with self.assertRaises(RelaySettlementError) as raised:
            submitter.reserve_admission()
        self.assertTrue(raised.exception.error_code)
        return status

    def test_snapshot_is_cached_and_health_uses_only_read_only_rpc(self) -> None:
        submitter = self._submitter()
        submitter.refresh_health()
        call_count = self.rpc.call_count
        for _ in range(3):
            status = submitter.snapshot()
            self.assertIs(status["ready"], True)
            self.assertIs(status["settlement_ready"], True)
            self.assertIs(status["worker_alive"], True)
            self.assertFalse(status["error_code"])
            self.assertEqual(status["gas_capacity_remaining"], 3)
        self.assertEqual(self.rpc.call_count, call_count)
        methods = {call.args[1] for call in self.rpc.call_args_list}
        self.assertEqual(
            methods,
            {"eth_chainId", "eth_getBalance", "eth_gasPrice", "eth_getBlockByNumber"},
        )
        self.send.assert_not_called()

    def test_gas_exhaustion_and_top_up_refresh_readiness(self) -> None:
        submitter = self._submitter()
        self.balance = self.receipt_budget - 1
        submitter.refresh_health()
        status = self._assert_not_ready(submitter)
        self.assertEqual(status["gas_capacity_remaining"], 0)

        self.balance = self.receipt_budget * 2
        submitter.refresh_health()
        self.assertIs(submitter.snapshot()["ready"], True)
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 2)

        self.balance = 0
        submitter.refresh_health()
        self._assert_not_ready(submitter)

    def test_rpc_failure_invalidates_previous_ready_state_and_can_recover(self) -> None:
        submitter = self._submitter()
        submitter.refresh_health()
        self.assertIs(submitter.snapshot()["ready"], True)
        self.rpc_failure = ChainError("RPC unavailable")
        submitter.refresh_health()
        self._assert_not_ready(submitter)
        self.rpc_failure = None
        submitter.refresh_health()
        self.assertIs(submitter.snapshot()["ready"], True)
        self.assertFalse(submitter.snapshot()["error_code"])

    def test_wrong_chain_does_not_admit_settlement(self) -> None:
        submitter = self._submitter()
        self.rpc_chain_id += 1
        submitter.refresh_health()
        status = self._assert_not_ready(submitter)
        self.assertEqual(status["error_code"], "wrong_chain")
        self.assertIsNone(submitter._health_rpc_endpoint)

    def test_healthy_backup_is_pinned_after_bad_primary_and_reused_for_complete_probes(self) -> None:
        submitter = self._submitter()
        primary, backup = "http://bad.invalid", "http://healthy.invalid"
        submitter.rpc_url = f"{primary},{backup}"
        def read(endpoint, method, params, timeout):
            if endpoint == primary:
                raise ChainError("primary HTTP 403")
            self.assertEqual(endpoint, backup)
            return self._rpc(endpoint, method, params, timeout)
        self.rpc.side_effect = read
        for _ in range(4):
            self.assertTrue(submitter.refresh_health()["ready"])
        primary_calls = [call for call in self.rpc.call_args_list if call.args[0] == primary]
        self.assertEqual(len(primary_calls), 1, "successful backup remains preferred after primary cooldown expires")
        self.assertEqual(submitter._health_rpc_endpoint, backup)
        backup_methods = [call.args[1] for call in self.rpc.call_args_list if call.args[0] == backup]
        self.assertEqual(backup_methods, ["eth_chainId", "eth_getBalance", "eth_gasPrice", "eth_getBlockByNumber"] * 4)

    def test_partial_primary_probe_never_mixes_values_with_backup(self) -> None:
        submitter = self._submitter()
        primary, backup = "http://partial.invalid", "http://complete.invalid"
        submitter.rpc_url = f"{primary},{backup}"
        def read(endpoint, method, params, timeout):
            if endpoint == primary:
                if method == "eth_getBalance":
                    return hex(self.receipt_budget * 100)
                if method == "eth_gasPrice":
                    raise ChainError("gas RPC timed out")
            return self._rpc(endpoint, method, params, timeout)
        self.rpc.side_effect = read
        status = submitter.refresh_health()
        self.assertTrue(status["ready"])
        self.assertEqual(status["gas_capacity_remaining"], 3)
        self.assertEqual(submitter._health_rpc_endpoint, backup)
        self.assertEqual([call.args[1] for call in self.rpc.call_args_list if call.args[0] == backup],
                         ["eth_chainId", "eth_getBalance", "eth_gasPrice", "eth_getBlockByNumber"])

    def test_wrong_chain_backup_is_rejected_before_reading_gas(self) -> None:
        submitter = self._submitter()
        primary, backup = "http://offline.invalid", "http://wrong-chain.invalid"
        submitter.rpc_url = f"{primary},{backup}"
        def read(endpoint, method, params, timeout):
            if endpoint == primary:
                raise ChainError("offline")
            self.assertEqual(method, "eth_chainId")
            return hex(self.chain_id + 1)
        self.rpc.side_effect = read
        status = submitter.refresh_health()
        self.assertEqual(self._assert_not_ready(submitter)["error_code"], "wrong_chain")
        self.assertEqual(status["gas_capacity_remaining"], 0)
        self.assertIsNone(submitter._health_rpc_endpoint)

    def test_failed_preferred_endpoint_can_recover_through_another_complete_bundle(self) -> None:
        submitter = self._submitter()
        primary, backup = "http://primary.invalid", "http://backup.invalid"
        submitter.rpc_url = f"{primary},{backup}"
        self.assertTrue(submitter.refresh_health()["ready"])
        self.assertEqual(submitter._health_rpc_endpoint, primary)
        def read(endpoint, method, params, timeout):
            if endpoint == primary:
                raise ChainError("primary is now offline")
            return self._rpc(endpoint, method, params, timeout)
        self.rpc.side_effect = read
        self.assertTrue(submitter.refresh_health()["ready"])
        self.assertEqual(submitter._health_rpc_endpoint, backup)
        self.rpc_failure = ChainError("all endpoints offline")
        self.assertFalse(submitter.refresh_health()["ready"])
        self.assertEqual(self._assert_not_ready(submitter)["error_code"], "rpc_unavailable")

    def test_health_fallback_total_budget_never_exceeds_eight_seconds(self) -> None:
        submitter = self._submitter()
        submitter.health_timeout_seconds = 3.0
        submitter.rpc_url = ",".join(f"http://slow-{index}.invalid" for index in range(4))
        clock = [time.monotonic()]
        began = clock[0]
        def read(endpoint, method, params, timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 3.0)
            clock[0] += timeout
            raise ChainError("timed out")
        self.rpc.side_effect = read
        with patch("gateway.session_relayer.time.monotonic", side_effect=lambda: clock[0]):
            self.assertFalse(submitter.refresh_health()["ready"])
        self.assertLessEqual(clock[0] - began, 8.0)
        self.assertEqual([call.args[3] for call in self.rpc.call_args_list], [3.0, 3.0, 2.0])

    def test_dead_worker_overrides_cached_healthy_rpc(self) -> None:
        submitter = self._submitter()
        submitter.refresh_health()
        self.assertIs(submitter.snapshot()["ready"], True)
        submitter._thread = SimpleNamespace(is_alive=lambda: False)
        status = self._assert_not_ready(submitter)
        self.assertIs(status["worker_alive"], False)

    def test_worker_must_exist_before_admission(self) -> None:
        submitter = self._submitter()
        submitter._thread = None
        submitter.refresh_health()
        status = self._assert_not_ready(submitter)
        self.assertIs(status["worker_alive"], False)

    def test_twenty_threads_cannot_reserve_more_than_three_receipts(self) -> None:
        submitter = self._submitter()
        submitter.refresh_health()
        barrier = threading.Barrier(20, timeout=5)

        def reserve():
            barrier.wait()
            try:
                return submitter.reserve_admission(), None
            except RelaySettlementError as exc:
                return None, exc.error_code

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(lambda _: reserve(), range(20)))
        leases = [lease for lease, _ in results if lease is not None]
        rejected = [error for lease, error in results if lease is None]
        self.assertEqual(len(leases), 3)
        self.assertEqual(len(set(leases)), 3)
        self.assertTrue(all(isinstance(lease, str) and lease for lease in leases))
        self.assertEqual(len(rejected), 17)
        self.assertTrue(all(rejected))
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 0)
        self._assert_not_ready(submitter)
        for lease in leases:
            submitter.release_admission(lease)
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 3)
        self.assertIs(submitter.snapshot()["ready"], True)

    def test_release_is_idempotent_without_creating_extra_capacity(self) -> None:
        self.balance = self.receipt_budget
        submitter = self._submitter()
        submitter.refresh_health()
        lease = submitter.reserve_admission()
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 0)
        submitter.release_admission(lease)
        submitter.release_admission(lease)
        submitter.release_admission("unknown-lease")
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 1)
        replacement = submitter.reserve_admission()
        self._assert_not_ready(submitter)
        submitter.release_admission(replacement)

    def test_enqueue_transfers_reserved_budget_to_durable_pending_receipt(self) -> None:
        self.balance = self.receipt_budget * 2
        submitter = self._submitter()
        submitter.refresh_health()
        prepared = self._prepared()
        lease = submitter.reserve_admission()
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 1)
        self.assertEqual(submitter.enqueue(prepared, reservation=lease), ("pending", True))
        self.assertEqual(self.outbox.status(prepared.key), "pending")
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 1)
        submitter.release_admission(lease)
        submitter.release_admission(lease)
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 1)
        reopened = RelaySettlementOutbox(self.outbox.path)
        self.assertEqual(reopened.status(prepared.key), "pending")

        duplicate_lease = submitter.reserve_admission()
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 0)
        self.assertEqual(
            submitter.enqueue(prepared, reservation=duplicate_lease), ("pending", False)
        )
        submitter.release_admission(duplicate_lease)
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 1)
        self.assertEqual(self.outbox.snapshot(), {"pending": 1})

    def test_failed_durable_write_does_not_silently_consume_reservation(self) -> None:
        self.balance = self.receipt_budget
        submitter = self._submitter()
        submitter.refresh_health()
        lease = submitter.reserve_admission()
        prepared = self._prepared()
        with patch.object(self.outbox, "enqueue", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises((sqlite3.OperationalError, RelaySettlementError)):
                submitter.enqueue(prepared, reservation=lease)
        self.assertIsNone(self.outbox.status(prepared.key))
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 0)
        submitter.release_admission(lease)
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 1)

    def test_public_status_exposes_only_status_fields_for_matching_key(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        tx_hash = "0x" + "d" * 64
        self.outbox.mark_submitted(prepared.key, tx_hash)
        status = self.outbox.public_status(prepared.session_id, key_address=self.key_address)
        self.assertEqual(
            set(status),
            {"request_id", "status", "error_code", "tx_hash", "updated_at", "authorization_deadline"},
        )
        self.assertEqual(status["request_id"], prepared.session_id)
        self.assertEqual(status["status"], "submitted")
        self.assertEqual(status["tx_hash"], tx_hash)
        encoded = json.dumps(status)
        self.assertNotIn("signature", encoded)
        self.assertNotIn("payload", encoded)
        self.assertNotIn("test-authorization-signature", encoded)
        self.assertNotIn("calldata", encoded)
        self.assertIsInstance(status["updated_at"], int)
        self.assertEqual(
            status["authorization_deadline"],
            prepared.payload["signed_receipt"]["authorization"]["authorization"]["deadline"],
        )
        self.assertIsNone(
            self.outbox.public_status(prepared.session_id, key_address="0x" + "e" * 40)
        )

    def test_public_failed_status_does_not_disclose_raw_error_secrets(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_failed(
            prepared.key,
            "execution reverted; authorization=test-authorization-secret; signature=test-signature-secret",
            retryable=False,
        )
        status = self.outbox.public_status(prepared.session_id, key_address=self.key_address)
        self.assertEqual(
            set(status),
            {"request_id", "status", "error_code", "tx_hash", "updated_at", "authorization_deadline"},
        )
        self.assertEqual(status["status"], "failed")
        self.assertTrue(status["error_code"])
        self.assertNotIn("test-authorization-secret", json.dumps(status))
        self.assertNotIn("test-signature-secret", json.dumps(status))

    def test_public_status_checks_original_authorization_key(self) -> None:
        prepared = self._prepared()
        prepared.payload["signed_receipt"]["authorization"]["authorization"]["key"] = (
            "0x" + "e" * 40
        )
        self.outbox.enqueue(prepared)
        self.assertIsNone(
            self.outbox.public_status(prepared.session_id, key_address=self.key_address)
        )

    def test_duplicate_failed_receipt_never_returns_to_pending(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_failed(prepared.key, "receipt expired", retryable=False)
        self.assertEqual(self.outbox.enqueue(prepared), ("failed", False))
        self.assertEqual(self.outbox.enqueue(prepared), ("failed", False))
        self.assertEqual(self.outbox.status(prepared.key), "failed")
        self.assertEqual(self.outbox.next_batch(), [])
        self.assertEqual(self.outbox.snapshot(), {"failed": 1})

    def test_confirmation_does_not_recycle_stale_cached_gas_balance(self) -> None:
        self.balance = self.receipt_budget
        submitter = self._submitter()
        submitter.refresh_health()
        prepared = self._prepared()
        lease = submitter.reserve_admission()
        submitter.enqueue(prepared, reservation=lease)
        tx_hash = "0x" + "d" * 64
        self.outbox.mark_submitted(prepared.key, tx_hash)
        with patch("gateway.session_relayer.rpc_call", return_value={"status": "0x1", "gasUsed": hex(self.gas_per_receipt), "effectiveGasPrice": hex(self.gas_price)}):
            submitter._wait_for_receipt([prepared.key], tx_hash)
        self.assertEqual(self.outbox.status(prepared.key), "confirmed")
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 0)
        self._assert_not_ready(submitter)
        self.balance -= self.gas_per_receipt * self.gas_price
        submitter.refresh_health()
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 0)

    def test_health_sweep_expires_pending_behind_an_unresolved_submitted_transaction(self) -> None:
        submitter = self._submitter()
        submitted = self._prepared(1)
        expired = self._prepared(2, deadline=int(time.time()) - 10)
        self.outbox.enqueue(submitted)
        self.outbox.mark_submitted(submitted.key, "0x" + "d" * 64)
        self.outbox.enqueue(expired)
        submitter.refresh_health()
        self.assertEqual(self.outbox.status(submitted.key), "submitted")
        self.assertEqual(self.outbox.status(expired.key), "failed")
        status = submitter.public_status(expired.session_id, key_address=self.key_address)
        self.assertEqual(status["error_code"], "authorization_expired")
        self.send.assert_not_called()

    def test_stale_health_cache_rejects_admission_without_synchronous_rpc(self) -> None:
        submitter = self._submitter()
        submitter.refresh_health()
        calls = self.rpc.call_count
        submitter._health["checked_monotonic"] -= submitter.health_max_age_seconds + 1
        self._assert_not_ready(submitter)
        self.assertEqual(self.rpc.call_count, calls)

    def test_legacy_ambiguous_broadcast_is_quarantined_without_allocating_a_new_nonce(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_failed(prepared.key, "RPC request failed for eth_sendRawTransaction: connection failed", retryable=True)
        reopened = RelaySettlementOutbox(self.outbox.path)
        self.assertEqual(reopened.status(prepared.key), "broadcast_unknown")
        self.assertEqual(reopened.enqueue(prepared), ("broadcast_unknown", False))
        self.assertEqual(reopened.next_batch(), [])
        self.assertEqual(reopened.blocking_error(), "broadcast_unknown")

    def test_submitted_transaction_group_is_not_truncated_by_a_smaller_batch_configuration(self) -> None:
        first, second = self._prepared(1), self._prepared(2)
        self.outbox.enqueue(first)
        self.outbox.enqueue(second)
        self.outbox.mark_submitted_many([first.key, second.key], "0x" + "d" * 64)
        self.assertEqual(len(self.outbox.next_batch(1)), 2)

    def test_malformed_rpc_receipt_never_marks_a_submitted_transaction_failed(self) -> None:
        prepared = self._prepared()
        self.outbox.enqueue(prepared)
        self.outbox.mark_submitted(prepared.key, "0x" + "d" * 64)
        submitter = self._submitter()
        with patch("gateway.session_relayer.rpc_call", return_value={}):
            with self.assertRaises(RelaySettlementError):
                submitter._process(self.outbox.next_batch())
        self.assertEqual(self.outbox.status(prepared.key), "submitted")
        self.assertEqual(self.outbox.blocking_error(), "broadcast_unknown")
        self.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
