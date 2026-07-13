from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from gateway.billing import (
    BillingError,
    BillingStore,
    ChainBalanceUnavailable,
    ChainSyncSuperseded,
    KeyChallengeVerificationInProgress,
    KeyChallengeVerificationLimitExceeded,
    usdc_to_units,
)
from gateway.ledger import receipt_hash


@contextmanager
def patch_time(value: int):
    with patch("gateway.billing.time.time", return_value=value):
        yield


class BillingTest(unittest.TestCase):
    def test_create_deposit_and_debit_account(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            credited = store.deposit(account.account_id, "1.25")
            debited = store.debit(account.account_id, usdc_to_units("0.25"), "event-1")
            fetched_by_key = store.get_by_key(account.api_key or "")
            fetched_by_account = store.get_by_account(account.account_id)
            with store._connect() as conn:
                row = conn.execute("SELECT api_key, api_key_hash, key_fingerprint FROM accounts WHERE account_id = ?", (account.account_id,)).fetchone()

        self.assertTrue(account.api_key.startswith("msk_"))
        self.assertIsNotNone(fetched_by_key)
        self.assertIsNotNone(fetched_by_account)
        self.assertIsNone(fetched_by_account.api_key)
        self.assertIsNone(row["api_key"])
        self.assertIsNotNone(row["api_key_hash"])
        self.assertEqual(row["key_fingerprint"], account.key_fingerprint)
        self.assertEqual(credited.balance_usdc, "1.250000")
        self.assertEqual(debited.balance_usdc, "1.000000")

    def test_debit_rejects_insufficient_balance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")

            with self.assertRaisesRegex(BillingError, "insufficient"):
                store.debit(account.account_id, usdc_to_units("0.01"), "event-1")

    def test_payment_address_cannot_back_multiple_billing_accounts(self) -> None:
        payment_address = "0x00000000000000000000000000000000000000a1"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            store.create_account("acct-a", payment_address=payment_address)
            with self.assertRaisesRegex(BillingError, "already registered"):
                store.create_account("acct-b", payment_address=payment_address.upper().replace("0X", "0x"))
            store.create_account("acct-b")
            with self.assertRaisesRegex(BillingError, "already registered"):
                store.set_payment_address("acct-b", payment_address)
            with self.assertRaisesRegex(BillingError, "already registered"):
                store.register_key_hash("acct-b", "11" * 32, payment_address=payment_address)

    def test_reserve_capture_and_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")

            reserved = store.reserve(account.account_id, usdc_to_units("0.40"), "res-1")
            captured = store.capture("res-1", usdc_to_units("0.25"), "event-1")
            store.reserve(account.account_id, usdc_to_units("0.10"), "res-2")
            released = store.release("res-2")

        self.assertEqual(reserved.balance_usdc, "0.600000")
        self.assertEqual(captured.balance_usdc, "0.750000")
        self.assertIsNotNone(released)
        self.assertEqual(released.balance_usdc, "0.750000")

    def test_capture_rejects_amount_above_reserved_max_fee(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")
            store.reserve(account.account_id, usdc_to_units("0.25"), "res-1")

            with self.assertRaisesRegex(BillingError, "reserved max_fee"):
                store.capture("res-1", usdc_to_units("0.26"), "event-1")

    def test_reserve_rejects_monthly_quota_before_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "10.00")
            store.configure_account(account.account_id, monthly_quota_usdc="1.00")

            with self.assertRaisesRegex(BillingError, "monthly quota"):
                store.reserve(account.account_id, usdc_to_units("1.01"), "res-1")

    def test_monthly_quota_counts_open_reservations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "10.00")
            store.configure_account(account.account_id, monthly_quota_usdc="1.00")

            store.reserve(account.account_id, usdc_to_units("0.60"), "res-1")
            with self.assertRaisesRegex(BillingError, "monthly quota"):
                store.reserve(account.account_id, usdc_to_units("0.50"), "res-2")

    def test_monthly_quota_resets_on_new_usage_period(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "10.00")
            store.configure_account(account.account_id, monthly_quota_usdc="1.00")
            with store._connect() as conn:
                conn.execute(
                    "UPDATE accounts SET monthly_used_units = ?, usage_period = ? WHERE account_id = ?",
                    (usdc_to_units("1.00"), "2000-01", account.account_id),
                )

            reserved = store.reserve(account.account_id, usdc_to_units("0.50"), "res-1")

        self.assertEqual(reserved.balance_usdc, "9.500000")

    def test_capture_records_receipt_outbox_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")
            store.reserve(account.account_id, usdc_to_units("0.25"), "res-1")

            store.capture("res-1", usdc_to_units("0.25"), "event-1", outbox_payload={"job_id": "event-1"})
            pending = store.pending_receipts()
            marked = store.mark_receipt_exported("event-1")
            stale_mark = store.mark_receipt_exported("event-1")
            exported = store.pending_receipts()

        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["receipt_id"], "event-1")
        self.assertTrue(marked)
        self.assertFalse(stale_mark)
        self.assertEqual(exported, [])

    def test_receipt_outbox_claim_is_transactional_and_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")
            store.reserve(account.account_id, usdc_to_units("0.25"), "res-1")
            store.capture("res-1", usdc_to_units("0.25"), "event-1", outbox_payload={"job_id": "event-1"})

            first_claim = store.pending_receipts()
            concurrent_claim = BillingStore(store.path).pending_receipts()
            token = str(first_claim[0]["claim_token"])
            wrong_release = store.release_receipt_claim("event-1", "wrong-token")
            released = store.release_receipt_claim("event-1", token)
            second_claim = BillingStore(store.path).pending_receipts()
            wrong_mark = store.mark_receipt_exported("event-1", claim_token="wrong-token")
            marked = store.mark_receipt_exported(
                "event-1",
                claim_token=str(second_claim[0]["claim_token"]),
            )

        self.assertEqual(len(first_claim), 1)
        self.assertEqual(concurrent_claim, [])
        self.assertFalse(wrong_release)
        self.assertTrue(released)
        self.assertFalse(wrong_mark)
        self.assertTrue(marked)
        self.assertEqual(second_claim[0]["attempt_count"], 2)

    def test_stale_receipt_outbox_claim_is_recovered_after_worker_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")
            store.reserve(account.account_id, usdc_to_units("0.25"), "res-1")
            store.capture("res-1", usdc_to_units("0.25"), "event-1", outbox_payload={"job_id": "event-1"})

            with patch_time(1_000):
                abandoned = store.pending_receipts(claim_timeout_seconds=300)
            with patch_time(1_299):
                still_leased = BillingStore(store.path).pending_receipts(claim_timeout_seconds=300)
            with patch_time(1_300):
                recovered = BillingStore(store.path).pending_receipts(claim_timeout_seconds=300)

        self.assertEqual(len(abandoned), 1)
        self.assertEqual(still_leased, [])
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["receipt_id"], "event-1")
        self.assertEqual(recovered[0]["attempt_count"], 2)

    def test_chain_sync_state_requires_matching_fresh_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement="0x0000000000000000000000000000000000000002",
                latest_block=100,
                synced_block=95,
                confirmations=5,
                source="events",
                synced_at=1_000,
                synced_block_hash="0x" + "aa" * 32,
            )
            with patch_time(1_030):
                state = store.require_fresh_chain_sync(
                    chain_id=11155111,
                    settlement="0x0000000000000000000000000000000000000002",
                    max_age_seconds=60,
                    max_block_lag=10,
                )
            with patch_time(1_100):
                with self.assertRaisesRegex(BillingError, "stale"):
                    store.require_fresh_chain_sync(
                        chain_id=11155111,
                        settlement="0x0000000000000000000000000000000000000002",
                        max_age_seconds=60,
                        max_block_lag=10,
                    )

        self.assertEqual(state["synced_block"], 95)

    def test_chain_guard_rechecks_freshness_inside_reservation_transaction(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account(
                "acct-a", payment_address="0x0000000000000000000000000000000000000001"
            )
            store.sync_chain_balance(
                account.account_id,
                1_000_000,
                chain_id=11155111,
                settlement=settlement,
                latest_block=106,
                synced_block=100,
                confirmations=6,
                source="events",
                synced_at=1_000,
                synced_block_hash="0x" + "aa" * 32,
            )
            with patch_time(1_010):
                with self.assertRaisesRegex(BillingError, "global.*never"):
                    store.require_fresh_chain_sync(
                        chain_id=11155111,
                        settlement=settlement,
                        max_age_seconds=60,
                        max_block_lag=10,
                    )
                with self.assertRaisesRegex(BillingError, "global.*never"):
                    store.require_fresh_chain_sync(
                        chain_id=11155111,
                        settlement=settlement,
                        max_age_seconds=60,
                        max_block_lag=10,
                        account_id=account.account_id,
                    )
                with self.assertRaisesRegex(ChainBalanceUnavailable, "global.*never"):
                    store.reserve_with_chain_guard(
                        account.account_id,
                        100_000,
                        "res-missing-global",
                        chain_id=11155111,
                        settlement=settlement,
                        max_age_seconds=60,
                        max_block_lag=10,
                    )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=106,
                synced_block=100,
                confirmations=6,
                source="events",
                synced_at=1_000,
                synced_block_hash="0x" + "aa" * 32,
            )
            with patch_time(1_010):
                store.require_fresh_chain_sync(
                    chain_id=11155111,
                    settlement=settlement,
                    max_age_seconds=60,
                    max_block_lag=10,
                    min_confirmations=6,
                    account_id=account.account_id,
                )
                store.invalidate_chain_accounts([account.account_id])
                with self.assertRaisesRegex(ChainBalanceUnavailable, "stale"):
                    store.reserve_with_chain_guard(
                        account.account_id,
                        400_000,
                        "res-stale",
                        chain_id=11155111,
                        settlement=settlement,
                        max_age_seconds=60,
                        max_block_lag=10,
                        min_confirmations=6,
                    )
            unchanged = store.get_by_account(account.account_id)

        self.assertEqual(unchanged.balance_units, 1_000_000)

    def test_chain_guard_compares_account_cursor_to_global_latest_block(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            store.create_account(
                "acct-a", payment_address="0x0000000000000000000000000000000000000001"
            )
            store.create_account(
                "acct-b", payment_address="0x0000000000000000000000000000000000000002"
            )
            store.publish_direct_chain_balance(
                "acct-a",
                "1",
                expected_state=None,
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                synced_block_hash="0x" + "aa" * 32,
                synced_at=1_000,
            )
            store.publish_direct_chain_balance(
                "acct-b",
                "1",
                expected_state=store.get_chain_sync_state(),
                chain_id=11155111,
                settlement=settlement,
                latest_block=200,
                synced_block=200,
                confirmations=0,
                synced_block_hash="0x" + "bb" * 32,
                synced_at=1_000,
            )

            with patch_time(1_010):
                with self.assertRaisesRegex(BillingError, "block lag exceeded"):
                    store.require_fresh_chain_sync(
                        chain_id=11155111,
                        settlement=settlement,
                        max_age_seconds=60,
                        max_block_lag=10,
                        account_id="acct-a",
                    )
                with self.assertRaisesRegex(ChainBalanceUnavailable, "block lag exceeded"):
                    store.reserve_with_chain_guard(
                        "acct-a",
                        400_000,
                        "res-global-lag",
                        chain_id=11155111,
                        settlement=settlement,
                        max_age_seconds=60,
                        max_block_lag=10,
                    )
            unchanged = store.get_by_account("acct-a")

        self.assertEqual(unchanged.balance_units, 1_000_000)

    def test_obsolete_chain_publication_and_invalidation_are_fenced(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        canonical_log = {
            "transactionHash": "0x" + "11" * 32,
            "logIndex": "0x0",
            "blockNumber": "0x65",
            "blockHash": "0x" + "bb" * 32,
            "topics": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address=consumer)
            store.sync_chain_balance(
                account.account_id,
                1_000_000,
                chain_id=11155111,
                settlement=settlement,
                latest_block=99,
                synced_block=99,
                confirmations=0,
                source="events",
                synced_block_hash="0x" + "99" * 32,
            )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=99,
                synced_block=99,
                confirmations=0,
                source="events",
                synced_block_hash="0x" + "99" * 32,
            )
            store.debit(account.account_id, 250_000, "event-1", receipt=receipt)
            obsolete = store.get_chain_sync_state()
            store.publish_canonical_chain_balances(
                [(account.account_id, consumer, 750_000)],
                expected_state=obsolete,
                chain_id=11155111,
                settlement=settlement,
                latest_block=101,
                synced_block=101,
                confirmations=0,
                source="events",
                synced_block_hash="0x" + "bb" * 32,
                canonical_logs=[canonical_log],
                settled_receipts=[(receipt_hash(receipt), consumer, 101, None)],
                reconcile_from_block=100,
                reconcile_to_block=101,
            )
            with self.assertRaises(ChainSyncSuperseded):
                store.publish_canonical_chain_balances(
                    [(account.account_id, consumer, 1_000_000)],
                    expected_state=obsolete,
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=100,
                    synced_block=100,
                    confirmations=0,
                    source="events",
                    synced_block_hash="0x" + "aa" * 32,
                    canonical_logs=[],
                    settled_receipts=[],
                    reconcile_from_block=100,
                    reconcile_to_block=100,
                )
            with self.assertRaises(ChainSyncSuperseded):
                store.invalidate_chain_accounts_if_current(
                    [account.account_id],
                    chain_id=11155111,
                    settlement=settlement,
                    expected_state=obsolete,
                )
            state = store.get_chain_sync_state()
            account_state = store.get_chain_sync_state(account.account_id)
            updated = store.get_by_account(account.account_id)
            with store._connect() as conn:
                usage = conn.execute(
                    "SELECT chain_settled_block FROM usage_events WHERE event_id = 'event-1'"
                ).fetchone()

        self.assertEqual(state["synced_block"], 101)
        self.assertEqual(account_state["synced_block"], 101)
        self.assertGreater(account_state["synced_at"], 0)
        self.assertEqual(updated.balance_units, 750_000)
        self.assertEqual(usage["chain_settled_block"], 101)

    def test_v3_receipt_confirmation_requires_matching_reservation_id(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        reservation_id = "0x" + "11" * 32
        other_reservation_id = "0x" + "22" * 32
        receipt = {
            "job_id": "event-v3",
            "amount": "0.25",
            "onchain_reservation_id": reservation_id,
        }
        hashed = receipt_hash(receipt)
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address=consumer)
            store.sync_chain_balance(
                account.account_id,
                1_000_000,
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                source="events",
                synced_block_hash="0x" + "aa" * 32,
            )
            store.debit(account.account_id, 250_000, "event-v3", receipt=receipt)
            wrong = store.confirm_chain_receipts(
                [hashed],
                chain_id=11155111,
                settlement=settlement,
                settled_block=101,
                consumer_addresses={hashed: consumer},
                onchain_reservation_ids={hashed: other_reservation_id},
            )
            right = store.confirm_chain_receipts(
                [hashed],
                chain_id=11155111,
                settlement=settlement,
                settled_block=101,
                consumer_addresses={hashed: consumer},
                onchain_reservation_ids={hashed: reservation_id},
            )
            repeated = store.confirm_chain_receipts(
                [hashed],
                chain_id=11155111,
                settlement=settlement,
                settled_block=101,
                consumer_addresses={hashed: consumer},
                onchain_reservation_ids={hashed: reservation_id},
            )
            state = store.get_chain_sync_state(account.account_id)

        self.assertEqual((wrong, right, repeated), (0, 1, 0))
        self.assertEqual(state["pending_spend_units"], 0)

    def test_direct_balance_publication_updates_balance_and_cursor_atomically(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            store.create_account(
                "acct-a",
                payment_address="0x0000000000000000000000000000000000000001",
            )
            account = store.publish_direct_chain_balance(
                "acct-a",
                "5",
                expected_state=None,
                chain_id=11155111,
                settlement=settlement,
                latest_block=120,
                synced_block=114,
                confirmations=6,
                synced_block_hash="0x" + "aa" * 32,
                synced_at=1_000,
            )
            global_state = store.get_chain_sync_state()
            account_state = store.get_chain_sync_state("acct-a")

        self.assertEqual(account.balance_units, 5_000_000)
        self.assertEqual(global_state["source"], "direct")
        self.assertEqual(global_state["synced_block"], 114)
        self.assertEqual(account_state["source"], "direct")
        self.assertEqual(account_state["synced_block"], 114)

    def test_event_indexed_state_cannot_be_downgraded_to_direct_balance(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            store.create_account(
                "acct-a",
                payment_address="0x0000000000000000000000000000000000000001",
            )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=120,
                synced_block=114,
                confirmations=6,
                source="events",
                synced_block_hash="0x" + "aa" * 32,
                synced_at=1_000,
            )
            expected = store.get_chain_sync_state()

            with self.assertRaisesRegex(BillingError, "cannot be downgraded"):
                store.publish_direct_chain_balance(
                    "acct-a",
                    "5",
                    expected_state=expected,
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=121,
                    synced_block=115,
                    confirmations=6,
                    synced_block_hash="0x" + "bb" * 32,
                    synced_at=1_001,
                )
            account = store.get_by_account("acct-a")
            state = store.get_chain_sync_state()

        self.assertEqual(account.balance_units, 0)
        self.assertEqual(state["source"], "events")
        self.assertEqual(state["synced_block"], 114)

    def test_chain_settlement_entry_points_reject_zero_address(self) -> None:
        zero_address = "0x" + "00" * 20
        block_hash = "0x" + "aa" * 32
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account(
                "acct-a",
                payment_address="0x0000000000000000000000000000000000000001",
            )
            calls = {
                "sync_chain_balance": lambda: store.sync_chain_balance(
                    account.account_id,
                    1,
                    chain_id=11155111,
                    settlement=zero_address,
                    latest_block=100,
                    synced_block=95,
                    confirmations=5,
                    source="events",
                    synced_block_hash=block_hash,
                ),
                "publish_canonical_chain_balances": lambda: store.publish_canonical_chain_balances(
                    [],
                    expected_state=None,
                    chain_id=11155111,
                    settlement=zero_address,
                    latest_block=100,
                    synced_block=95,
                    confirmations=5,
                    source="events",
                    synced_block_hash=block_hash,
                ),
                "accounts_with_chain_settled_receipts": lambda: store.accounts_with_chain_settled_receipts(
                    chain_id=11155111,
                    settlement=zero_address,
                    from_block=90,
                    to_block=100,
                ),
                "set_chain_sync_state": lambda: store.set_chain_sync_state(
                    chain_id=11155111,
                    settlement=zero_address,
                    latest_block=100,
                    synced_block=95,
                    confirmations=5,
                    source="events",
                    synced_block_hash=block_hash,
                ),
                "require_fresh_chain_sync": lambda: store.require_fresh_chain_sync(
                    chain_id=11155111,
                    settlement=zero_address,
                    max_age_seconds=60,
                    max_block_lag=10,
                ),
                "advance_chain_account_freshness": lambda: store.advance_chain_account_freshness(
                    chain_id=11155111,
                    settlement=zero_address,
                    latest_block=100,
                    synced_block=95,
                    confirmations=5,
                    source="events",
                    synced_block_hash=block_hash,
                ),
                "mark_chain_reorg": lambda: store.mark_chain_reorg(
                    chain_id=11155111,
                    settlement=zero_address,
                ),
                "record_chain_events": lambda: store.record_chain_events(
                    chain_id=11155111,
                    settlement=zero_address,
                    logs=[],
                ),
                "confirm_chain_receipts": lambda: store.confirm_chain_receipts(
                    [],
                    chain_id=11155111,
                    settlement=zero_address,
                    settled_block=95,
                ),
            }

            for name, call in calls.items():
                with self.subTest(entry_point=name):
                    with self.assertRaisesRegex(BillingError, "settlement must be a non-zero EVM address"):
                        call()

    def test_chain_balance_sync_preserves_open_and_captured_liabilities_across_restart(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        block_hash = "0x" + "ab" * 32
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "billing.sqlite3"
            store = BillingStore(path)
            account = store.create_account(
                "acct-a",
                payment_address="0x0000000000000000000000000000000000000001",
            )
            store.sync_chain_balance(
                account.account_id,
                usdc_to_units("1.00"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=95,
                confirmations=5,
                source="events",
                synced_at=1_000,
                synced_block_hash=block_hash,
            )
            reserved = store.reserve(account.account_id, usdc_to_units("0.40"), "res-1")
            resynced_open = store.sync_chain_balance(
                account.account_id,
                usdc_to_units("1.00"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=101,
                synced_block=96,
                confirmations=5,
                source="events",
                synced_at=1_001,
                synced_block_hash="0x" + "bc" * 32,
            )

            store = BillingStore(path)
            captured = store.capture(
                "res-1",
                usdc_to_units("0.25"),
                "event-1",
                receipt={"job_id": "event-1", "amount": "0.25"},
            )
            resynced_captured = store.sync_chain_balance(
                account.account_id,
                usdc_to_units("1.00"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=102,
                synced_block=97,
                confirmations=5,
                source="events",
                synced_at=1_002,
                synced_block_hash="0x" + "cd" * 32,
            )
            chain_state = store.get_chain_sync_state(account.account_id)

        self.assertEqual(reserved.balance_usdc, "0.600000")
        self.assertEqual(resynced_open.balance_usdc, "0.600000")
        self.assertEqual(captured.balance_usdc, "0.750000")
        self.assertEqual(resynced_captured.balance_usdc, "0.750000")
        self.assertEqual(chain_state["pending_spend_units"], usdc_to_units("0.25"))

    def test_confirmed_receipt_releases_pending_liability_only_once(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account(
                "acct-a",
                payment_address="0x0000000000000000000000000000000000000001",
            )
            store.sync_chain_balance(
                account.account_id,
                usdc_to_units("1.00"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=95,
                confirmations=5,
                source="events",
                synced_block_hash="0x" + "ab" * 32,
            )
            store.debit(account.account_id, usdc_to_units("0.25"), "event-1", receipt=receipt)

            first = store.confirm_chain_receipts(
                [receipt_hash(receipt)],
                chain_id=11155111,
                settlement=settlement,
                settled_block=101,
            )
            second = store.confirm_chain_receipts(
                [receipt_hash(receipt)],
                chain_id=11155111,
                settlement=settlement,
                settled_block=101,
            )
            synced = store.sync_chain_balance(
                account.account_id,
                usdc_to_units("0.75"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=106,
                synced_block=101,
                confirmations=5,
                source="events",
                synced_block_hash="0x" + "bc" * 32,
            )

        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(synced.balance_usdc, "0.750000")

    def test_reorg_rewinds_settled_receipt_and_requires_canonical_recovery(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        payment_address = "0x0000000000000000000000000000000000000001"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        block_hash = "0x" + "ab" * 32
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address=payment_address)
            store.sync_chain_balance(
                account.account_id,
                usdc_to_units("1.00"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=106,
                synced_block=100,
                confirmations=6,
                source="events",
                synced_block_hash=block_hash,
            )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=106,
                synced_block=100,
                confirmations=6,
                source="events",
                synced_block_hash=block_hash,
            )
            store.debit(account.account_id, usdc_to_units("0.25"), "event-1", receipt=receipt)
            store.confirm_chain_receipts(
                [receipt_hash(receipt)],
                chain_id=11155111,
                settlement=settlement,
                settled_block=100,
            )
            store.sync_chain_balance(
                account.account_id,
                usdc_to_units("0.75"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=106,
                synced_block=100,
                confirmations=6,
                source="events",
                synced_block_hash=block_hash,
            )

            store.mark_chain_reorg(chain_id=11155111, settlement=settlement)
            store.mark_chain_reorg(chain_id=11155111, settlement=settlement)
            rewound = store.get_chain_sync_state(account.account_id)
            rewound_account = store.get_by_account(account.account_id)
            with store._connect() as conn:
                usage = conn.execute(
                    "SELECT chain_settled_at, chain_settled_block FROM usage_events WHERE event_id = 'event-1'"
                ).fetchone()

            ordinary_sync = store.sync_chain_balance(
                account.account_id,
                usdc_to_units("1.00"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=107,
                synced_block=101,
                confirmations=6,
                source="events",
                synced_block_hash="0x" + "bc" * 32,
            )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=107,
                synced_block=101,
                confirmations=6,
                source="events",
                synced_block_hash="0x" + "bc" * 32,
            )
            sticky_account_state = store.get_chain_sync_state(account.account_id)
            sticky_global_state = store.get_chain_sync_state()

            recovered = store.publish_canonical_chain_balances(
                [(account.account_id, payment_address, usdc_to_units("1.00"))],
                expected_state=store.get_chain_sync_state(),
                chain_id=11155111,
                settlement=settlement,
                latest_block=108,
                synced_block=102,
                confirmations=6,
                source="events",
                synced_block_hash="0x" + "cd" * 32,
                canonical_logs=[],
                settled_receipts=[],
                reconcile_from_block=102,
                reconcile_to_block=102,
                reorg_recovery=True,
            )[0]
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=108,
                synced_block=102,
                confirmations=6,
                source="events",
                synced_block_hash="0x" + "cd" * 32,
                clear_reorg=True,
            )
            recovered_account_state = store.get_chain_sync_state(account.account_id)
            recovered_global_state = store.get_chain_sync_state()

        self.assertEqual(rewound["pending_spend_units"], usdc_to_units("0.25"))
        self.assertEqual(rewound["reorg_detected"], 1)
        self.assertEqual(rewound_account.balance_units, 0)
        self.assertIsNone(usage["chain_settled_at"])
        self.assertIsNone(usage["chain_settled_block"])
        self.assertEqual(ordinary_sync.balance_units, 0)
        self.assertEqual(sticky_account_state["reorg_detected"], 1)
        self.assertEqual(sticky_global_state["reorg_detected"], 1)
        self.assertEqual(recovered.balance_usdc, "0.750000")
        self.assertEqual(recovered_account_state["reorg_detected"], 0)
        self.assertEqual(recovered_global_state["reorg_detected"], 0)

    def test_reorg_sticky_balance_is_not_restored_by_reservation_refunds(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            accounts = [
                store.create_account(f"acct-{index}", payment_address=f"0x{index:040x}")
                for index in (1, 2, 3)
            ]
            for account in accounts:
                store.sync_chain_balance(
                    account.account_id,
                    1_000_000,
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=100,
                    synced_block=100,
                    confirmations=0,
                    source="events",
                    synced_block_hash="0x" + "aa" * 32,
                )
                store.reserve(account.account_id, 400_000, f"res-{account.account_id}")
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                source="events",
                synced_block_hash="0x" + "aa" * 32,
            )
            store.mark_chain_reorg(chain_id=11155111, settlement=settlement)

            store.capture("res-acct-1", 250_000, "event-captured")
            store.release("res-acct-2")
            with store._connect() as conn:
                conn.execute("UPDATE reservations SET created_at = 0 WHERE reservation_id = 'res-acct-3'")
            released = store.release_expired_reservations(max_age_seconds=1)
            balances = [store.get_by_account(account.account_id).balance_units for account in accounts]
            states = [store.get_chain_sync_state(account.account_id) for account in accounts]

        self.assertEqual(released, 1)
        self.assertEqual(balances, [0, 0, 0])
        self.assertTrue(all(state["reorg_detected"] == 1 for state in states))
        self.assertEqual(states[0]["pending_spend_units"], 250_000)

    def test_chain_freshness_is_scoped_to_each_account(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            first = store.create_account(
                "acct-a", payment_address="0x0000000000000000000000000000000000000001"
            )
            store.create_account(
                "acct-b", payment_address="0x0000000000000000000000000000000000000002"
            )
            store.sync_chain_balance(
                first.account_id,
                usdc_to_units("1.00"),
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=95,
                confirmations=5,
                source="events",
                synced_at=1_000,
                synced_block_hash="0x" + "ab" * 32,
            )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=95,
                confirmations=5,
                source="events",
                synced_at=1_000,
                synced_block_hash="0x" + "aa" * 32,
            )
            with patch_time(1_010):
                first_state = store.require_fresh_chain_sync(
                    chain_id=11155111,
                    settlement=settlement,
                    max_age_seconds=60,
                    max_block_lag=10,
                    account_id="acct-a",
                )
                with self.assertRaisesRegex(BillingError, "acct-b"):
                    store.require_fresh_chain_sync(
                        chain_id=11155111,
                        settlement=settlement,
                        max_age_seconds=60,
                        max_block_lag=10,
                    )

        self.assertEqual(first_state["account_id"], "acct-a")

    def test_event_cursor_cannot_promote_a_direct_balance_without_resync(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account(
                "acct-a", payment_address="0x0000000000000000000000000000000000000001"
            )
            store.sync_chain_balance(
                account.account_id,
                1_000_000,
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                source="direct",
                synced_block_hash="0x" + "aa" * 32,
            )

            advanced = store.advance_chain_account_freshness(
                chain_id=11155111,
                settlement=settlement,
                latest_block=106,
                synced_block=100,
                confirmations=6,
                source="events",
                synced_block_hash="0x" + "bb" * 32,
            )
            state = store.get_chain_sync_state(account.account_id)

        self.assertEqual(advanced, 0)
        self.assertEqual(state["source"], "direct")
        self.assertEqual(state["confirmations"], 0)

    def test_conflicting_chain_event_marks_cache_reorged(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        base_log = {
            "transactionHash": "0x" + "11" * 32,
            "logIndex": "0x0",
            "blockNumber": "0x64",
            "blockHash": "0x" + "aa" * 32,
            "topics": ["0x" + "22" * 32],
        }
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account(
                "acct-a", payment_address="0x0000000000000000000000000000000000000001"
            )
            store.sync_chain_balance(
                account.account_id,
                1_000_000,
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                source="events",
                synced_block_hash=str(base_log["blockHash"]),
            )
            inserted = store.record_chain_events(chain_id=11155111, settlement=settlement, logs=[base_log])
            conflicting = {**base_log, "blockHash": "0x" + "bb" * 32}
            with self.assertRaisesRegex(BillingError, "conflicting block hashes"):
                store.record_chain_events(chain_id=11155111, settlement=settlement, logs=[conflicting])
            state = store.get_chain_sync_state(account.account_id)

        self.assertEqual(inserted, 1)
        self.assertEqual(state["reorg_detected"], 1)

    def test_rotate_key_and_delete_account(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.configure_account(
                account.account_id,
                parent_account_id="acct-parent",
                discount_bps=500,
                reseller_margin_bps=1200,
                monthly_quota_usdc="25.00",
                usage_tier="reseller",
            )
            rotated = store.rotate_key(account.account_id)
            deleted = store.delete_account(account.account_id)

        self.assertNotEqual(rotated.api_key, account.api_key)
        self.assertEqual(rotated.parent_account_id, "acct-parent")
        self.assertEqual(rotated.discount_bps, 500)
        self.assertEqual(rotated.reseller_margin_bps, 1200)
        self.assertEqual(rotated.monthly_quota_units, usdc_to_units("25.00"))
        self.assertEqual(rotated.usage_tier, "reseller")
        self.assertTrue(deleted)

    def test_account_payment_address_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address="0x0000000000000000000000000000000000000001")
            updated = store.set_payment_address(account.account_id, "0x00000000000000000000000000000000000000A2")
            by_payment_address = store.accounts_by_payment_address()

        self.assertEqual(account.payment_address, "0x0000000000000000000000000000000000000001")
        self.assertEqual(updated.payment_address, "0x00000000000000000000000000000000000000a2")
        self.assertEqual(by_payment_address["0x00000000000000000000000000000000000000a2"].account_id, "acct-a")

    def test_rejects_invalid_payment_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")

            with self.assertRaisesRegex(BillingError, "payment_address"):
                store.create_account("acct-a", payment_address="not-an-address")

    def test_register_client_generated_key_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            wallet = "0x00000000000000000000000000000000000000a1"
            key_hash = "a" * 64

            account = store.register_key_hash(wallet, key_hash, payment_address=wallet)
            fetched_by_hash = store.get_by_key_hash(key_hash)
            with store._connect() as conn:
                row = conn.execute("SELECT api_key, api_key_hash FROM accounts WHERE account_id = ?", (wallet,)).fetchone()

        self.assertEqual(account.account_id, wallet)
        self.assertIsNone(account.api_key)
        self.assertEqual(account.payment_address, wallet)
        self.assertIsNotNone(fetched_by_hash)
        self.assertEqual(fetched_by_hash.account_id, wallet)
        self.assertIsNone(row["api_key"])
        self.assertEqual(row["api_key_hash"], key_hash)

    def test_scoped_key_requires_exact_gateway_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            wallet = "0x00000000000000000000000000000000000000a1"
            settlement = "0x00000000000000000000000000000000000000b2"
            api_key = "msk_origin_bound_secret"
            account = store.register_key_hash(
                wallet,
                hashlib.sha256(api_key.encode("utf-8")).hexdigest(),
                payment_address=wallet,
                credential_origin="https://gateway.example",
                credential_network_id="mycomesh-testnet",
                credential_chain_id=11155111,
                credential_settlement=settlement,
            )

            missing_context = store.get_by_key(api_key)
            matching = store.get_by_key(
                api_key,
                credential_origin="https://gateway.example",
                credential_network_id="mycomesh-testnet",
                credential_chain_id=11155111,
                credential_settlement=settlement,
            )
            wrong_origin = store.get_by_key(
                api_key,
                credential_origin="https://other.example",
                credential_network_id="mycomesh-testnet",
                credential_chain_id=11155111,
                credential_settlement=settlement,
            )
            wrong_chain = store.get_by_key(
                api_key,
                credential_origin="https://gateway.example",
                credential_network_id="mycomesh-testnet",
                credential_chain_id=1,
                credential_settlement=settlement,
            )

        self.assertEqual(account.credential_origin, "https://gateway.example")
        self.assertEqual(account.credential_network_id, "mycomesh-testnet")
        self.assertEqual(account.credential_chain_id, 11155111)
        self.assertEqual(account.credential_settlement, settlement)
        self.assertIsNone(missing_context)
        self.assertIsNotNone(matching)
        self.assertIsNone(wrong_origin)
        self.assertIsNone(wrong_chain)

    def test_key_challenge_is_single_use(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            challenge = store.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=60,
                nonce="challenge-1",
                now=100,
            )

            consumed = store.consume_key_challenge(
                wallet=str(challenge["wallet"]),
                key_hash=str(challenge["key_hash"]),
                chain_id=int(challenge["chain_id"]),
                nonce=str(challenge["nonce"]),
                now=120,
            )

            with self.assertRaisesRegex(BillingError, "already been consumed"):
                store.consume_key_challenge(
                    wallet=str(challenge["wallet"]),
                    key_hash=str(challenge["key_hash"]),
                    chain_id=int(challenge["chain_id"]),
                    nonce=str(challenge["nonce"]),
                    now=121,
                )

        self.assertEqual(consumed["nonce"], "challenge-1")

    def test_key_challenge_expiry_boundary_is_invalid_and_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            challenge = store.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=60,
                nonce="expires-at-boundary",
                now=100,
            )

            with self.assertRaisesRegex(BillingError, "challenge expired"):
                store.consume_key_challenge(
                    wallet=str(challenge["wallet"]),
                    key_hash=str(challenge["key_hash"]),
                    chain_id=int(challenge["chain_id"]),
                    nonce=str(challenge["nonce"]),
                    now=160,
                )

            store.create_key_challenge(
                wallet=str(challenge["wallet"]),
                key_hash=str(challenge["key_hash"]),
                chain_id=int(challenge["chain_id"]),
                nonce="replacement-at-boundary",
                now=160,
            )
            expired = store.get_key_challenge(str(challenge["nonce"]))

        self.assertIsNone(expired)

    def test_key_challenge_claim_rechecks_expiry_after_waiting_for_write_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "billing.sqlite3"
            store = BillingStore(path)
            challenge = store.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=60,
                nonce="expires-while-claim-waits",
                now=100,
            )
            blocker = sqlite3.connect(path)
            blocker.execute("BEGIN IMMEDIATE")
            started = threading.Event()
            clock_read = threading.Event()
            clock = [120]
            failures: list[Exception] = []

            def current_time() -> int:
                clock_read.set()
                return clock[0]

            def claim() -> None:
                started.set()
                try:
                    store.claim_key_challenge_verification(
                        wallet=str(challenge["wallet"]),
                        key_hash=str(challenge["key_hash"]),
                        chain_id=int(challenge["chain_id"]),
                        nonce=str(challenge["nonce"]),
                    )
                except Exception as exc:
                    failures.append(exc)

            with patch("gateway.billing.time.time", side_effect=current_time):
                worker = threading.Thread(target=claim)
                worker.start()
                self.assertTrue(started.wait(timeout=1))
                read_before_lock_release = clock_read.wait(timeout=0.1)
                clock[0] = 160
                blocker.rollback()
                worker.join(timeout=5)
            blocker.close()
            stored = store.get_key_challenge(str(challenge["nonce"]))

        self.assertFalse(read_before_lock_release)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], BillingError)
        self.assertIn("expired", str(failures[0]))
        self.assertEqual(stored["verification_attempts"], 0)
        self.assertIsNone(stored["verification_token"])

    def test_atomic_key_registration_rechecks_expiry_after_waiting_for_write_lock(self) -> None:
        wallet = "0x00000000000000000000000000000000000000a1"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "billing.sqlite3"
            store = BillingStore(path)
            challenge = store.create_key_challenge(
                wallet=wallet,
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=60,
                nonce="expires-while-registration-waits",
                now=100,
            )
            claim = store.claim_key_challenge_verification(
                wallet=wallet,
                key_hash=str(challenge["key_hash"]),
                chain_id=11155111,
                nonce=str(challenge["nonce"]),
                now=110,
            )
            blocker = sqlite3.connect(path)
            blocker.execute("BEGIN IMMEDIATE")
            started = threading.Event()
            clock_read = threading.Event()
            clock = [120]
            failures: list[Exception] = []

            def current_time() -> int:
                clock_read.set()
                return clock[0]

            def register() -> None:
                started.set()
                try:
                    store.consume_key_challenge_and_register_key_hash(
                        account_id=wallet,
                        wallet=wallet,
                        key_hash=str(challenge["key_hash"]),
                        chain_id=11155111,
                        nonce=str(challenge["nonce"]),
                        verification_token=str(claim["verification_token"]),
                        payment_address=wallet,
                    )
                except Exception as exc:
                    failures.append(exc)

            with patch("gateway.billing.time.time", side_effect=current_time):
                worker = threading.Thread(target=register)
                worker.start()
                self.assertTrue(started.wait(timeout=1))
                read_before_lock_release = clock_read.wait(timeout=0.1)
                clock[0] = 160
                blocker.rollback()
                worker.join(timeout=5)
            blocker.close()
            stored = store.get_key_challenge(str(challenge["nonce"]))
            account = store.get_by_account(wallet)

        self.assertFalse(read_before_lock_release)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], BillingError)
        self.assertIn("expired", str(failures[0]))
        self.assertIsNone(stored["consumed_at"])
        self.assertIsNone(account)

    def test_key_challenge_consume_is_atomic_across_connections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "billing.sqlite3"
            issuer = BillingStore(path)
            challenge = issuer.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=60,
                nonce="concurrent-consume",
                now=100,
            )
            stores = [BillingStore(path), BillingStore(path)]
            barrier = threading.Barrier(2)
            lock = threading.Lock()
            successes: list[dict[str, object]] = []
            failures: list[Exception] = []

            def consume(store: BillingStore) -> None:
                try:
                    barrier.wait(timeout=5)
                    result = store.consume_key_challenge(
                        wallet=str(challenge["wallet"]),
                        key_hash=str(challenge["key_hash"]),
                        chain_id=int(challenge["chain_id"]),
                        nonce=str(challenge["nonce"]),
                        now=120,
                    )
                    with lock:
                        successes.append(result)
                except Exception as exc:
                    with lock:
                        failures.append(exc)

            threads = [threading.Thread(target=consume, args=(store,)) for store in stores]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

            stored = issuer.get_key_challenge(str(challenge["nonce"]))

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], BillingError)
        self.assertRegex(str(failures[0]), "already been consumed")
        self.assertEqual(stored["consumed_at"], 120)

    def test_key_challenge_verification_claim_is_atomic_across_connections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "billing.sqlite3"
            issuer = BillingStore(path)
            challenge = issuer.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=300,
                nonce="concurrent-verification",
                now=100,
            )
            stores = [BillingStore(path), BillingStore(path)]
            barrier = threading.Barrier(2)
            lock = threading.Lock()
            claims: list[dict[str, object]] = []
            failures: list[Exception] = []

            def claim(store: BillingStore) -> None:
                try:
                    barrier.wait(timeout=5)
                    result = store.claim_key_challenge_verification(
                        wallet=str(challenge["wallet"]),
                        key_hash=str(challenge["key_hash"]),
                        chain_id=int(challenge["chain_id"]),
                        nonce=str(challenge["nonce"]),
                        now=120,
                    )
                    with lock:
                        claims.append(result)
                except Exception as exc:
                    with lock:
                        failures.append(exc)

            threads = [threading.Thread(target=claim, args=(candidate,)) for candidate in stores]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(claims), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], KeyChallengeVerificationInProgress)
        self.assertEqual(claims[0]["verification_attempts"], 1)

    def test_verification_claim_cannot_be_taken_over_before_challenge_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "billing.sqlite3"
            owner = BillingStore(path)
            contender = BillingStore(path)
            challenge = owner.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=300,
                nonce="persistent-verification-owner",
                now=100,
            )
            common = {
                "wallet": str(challenge["wallet"]),
                "key_hash": str(challenge["key_hash"]),
                "chain_id": int(challenge["chain_id"]),
                "nonce": str(challenge["nonce"]),
            }
            first = owner.claim_key_challenge_verification(**common, now=110)
            with self.assertRaises(KeyChallengeVerificationInProgress):
                contender.claim_key_challenge_verification(**common, now=399)
            still_owned = contender.get_key_challenge(str(challenge["nonce"]))
            released = owner.release_key_challenge_verification(
                str(challenge["nonce"]),
                str(first["verification_token"]),
            )
            second = contender.claim_key_challenge_verification(**common, now=399)

        self.assertEqual(still_owned["verification_token"], first["verification_token"])
        self.assertEqual(still_owned["verification_attempts"], 1)
        self.assertTrue(released)
        self.assertNotEqual(first["verification_token"], second["verification_token"])
        self.assertEqual(second["verification_attempts"], 2)

    def test_key_challenge_verification_attempts_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            challenge = store.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=300,
                nonce="bounded-verification",
                now=100,
            )
            common = {
                "wallet": str(challenge["wallet"]),
                "key_hash": str(challenge["key_hash"]),
                "chain_id": int(challenge["chain_id"]),
                "nonce": str(challenge["nonce"]),
            }
            for timestamp in (110, 111):
                claim = store.claim_key_challenge_verification(
                    **common,
                    now=timestamp,
                    max_attempts=2,
                )
                self.assertTrue(
                    store.release_key_challenge_verification(
                        str(challenge["nonce"]), str(claim["verification_token"])
                    )
                )

            with self.assertRaises(KeyChallengeVerificationLimitExceeded):
                store.claim_key_challenge_verification(**common, now=112, max_attempts=2)

    def test_unsubmitted_verification_claim_can_refund_its_attempt_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            challenge = store.create_key_challenge(
                wallet="0x00000000000000000000000000000000000000a1",
                key_hash="a" * 64,
                chain_id=11155111,
                ttl_seconds=300,
                nonce="unsubmitted-verification",
                now=100,
            )
            common = {
                "wallet": str(challenge["wallet"]),
                "key_hash": str(challenge["key_hash"]),
                "chain_id": int(challenge["chain_id"]),
                "nonce": str(challenge["nonce"]),
            }
            first = store.claim_key_challenge_verification(
                **common,
                now=110,
                max_attempts=1,
            )
            rolled_back = store.rollback_key_challenge_verification_claim(
                str(challenge["nonce"]),
                str(first["verification_token"]),
            )
            repeated = store.rollback_key_challenge_verification_claim(
                str(challenge["nonce"]),
                str(first["verification_token"]),
            )
            after_rollback = store.get_key_challenge(str(challenge["nonce"]))
            retry = store.claim_key_challenge_verification(
                **common,
                now=111,
                max_attempts=1,
            )

        self.assertTrue(rolled_back)
        self.assertFalse(repeated)
        self.assertIsNone(after_rollback["verification_token"])
        self.assertEqual(after_rollback["verification_attempts"], 0)
        self.assertEqual(retry["verification_attempts"], 1)

    def test_challenge_consumption_rolls_back_when_key_registration_fails(self) -> None:
        wallet = "0x00000000000000000000000000000000000000a1"
        key_hash = "ab" * 32
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            store.register_key_hash(
                "acct-b",
                key_hash,
                payment_address="0x00000000000000000000000000000000000000b1",
            )
            challenge = store.create_key_challenge(
                wallet=wallet,
                key_hash=key_hash,
                chain_id=11155111,
                nonce="atomic-consume-register",
                now=100,
            )
            claim = store.claim_key_challenge_verification(
                wallet=wallet,
                key_hash=key_hash,
                chain_id=11155111,
                nonce=str(challenge["nonce"]),
                now=101,
                max_attempts=2,
            )

            with self.assertRaisesRegex(BillingError, "another account"):
                store.consume_key_challenge_and_register_key_hash(
                    account_id=wallet,
                    wallet=wallet,
                    key_hash=key_hash,
                    chain_id=11155111,
                    nonce=str(challenge["nonce"]),
                    verification_token=str(claim["verification_token"]),
                    payment_address=wallet,
                    now=102,
                )
            stored = store.get_key_challenge(str(challenge["nonce"]))
            released = store.release_key_challenge_verification(
                str(challenge["nonce"]), str(claim["verification_token"])
            )
            retry = store.claim_key_challenge_verification(
                wallet=wallet,
                key_hash=key_hash,
                chain_id=11155111,
                nonce=str(challenge["nonce"]),
                now=103,
                max_attempts=2,
            )

        self.assertIsNone(stored["consumed_at"])
        self.assertEqual(stored["verification_token"], claim["verification_token"])
        self.assertTrue(released)
        self.assertEqual(retry["verification_attempts"], 2)

    def test_concurrent_initializers_serialize_schema_migrations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "billing.sqlite3"
            with sqlite3.connect(path) as conn:
                conn.execute(
                    """
                    CREATE TABLE key_challenges (
                        nonce TEXT PRIMARY KEY,
                        wallet TEXT NOT NULL,
                        key_hash TEXT NOT NULL,
                        chain_id INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER,
                        created_at INTEGER NOT NULL
                    )
                    """
                )
            barrier = threading.Barrier(3)
            errors: list[BaseException] = []

            def initialize() -> None:
                barrier.wait()
                try:
                    BillingStore(path)
                except BaseException as exc:
                    errors.append(exc)

            workers = [threading.Thread(target=initialize) for _ in range(2)]
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join(timeout=5)
            with sqlite3.connect(path) as conn:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(key_challenges)")}

        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertTrue({"verification_token", "verification_started_at", "verification_attempts"} <= columns)

    def test_key_challenge_prunes_rows_and_enforces_atomic_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            common = {
                "wallet": "0x00000000000000000000000000000000000000a1",
                "key_hash": "a" * 64,
                "chain_id": 11155111,
                "ttl_seconds": 60,
                "capacity": 2,
                "rate_per_minute": 10,
            }
            first = store.create_key_challenge(**common, nonce="bounded-1", now=100)
            store.create_key_challenge(**common, nonce="bounded-2", now=100)
            with self.assertRaisesRegex(BillingError, "capacity exceeded"):
                store.create_key_challenge(**common, nonce="bounded-3", now=100)

            store.consume_key_challenge(
                wallet=str(first["wallet"]),
                key_hash=str(first["key_hash"]),
                chain_id=int(first["chain_id"]),
                nonce=str(first["nonce"]),
                now=101,
            )
            store.create_key_challenge(**common, nonce="bounded-3", now=101)
            with store._connect() as conn:
                rows_after_consumed_prune = int(conn.execute("SELECT COUNT(*) FROM key_challenges").fetchone()[0])

            store.create_key_challenge(**common, nonce="bounded-4", now=162)
            with store._connect() as conn:
                rows_after_expiry_prune = int(conn.execute("SELECT COUNT(*) FROM key_challenges").fetchone()[0])

        self.assertEqual(rows_after_consumed_prune, 3)
        self.assertEqual(rows_after_expiry_prune, 1)

    def test_key_challenge_rate_limit_is_independent_of_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            common = {
                "wallet": "0x00000000000000000000000000000000000000a1",
                "key_hash": "b" * 64,
                "chain_id": 11155111,
                "ttl_seconds": 300,
                "capacity": 10,
                "rate_per_minute": 2,
            }
            store.create_key_challenge(**common, nonce="rate-one", now=100)
            store.create_key_challenge(**common, nonce="rate-two", now=100)
            with self.assertRaisesRegex(BillingError, "rate limit exceeded"):
                store.create_key_challenge(**common, nonce="rate-three", now=100)

    def test_set_balance_replaces_cached_balance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")
            synced = store.set_balance(account.account_id, "0.42")

        self.assertEqual(synced.balance_usdc, "0.420000")

    def test_release_expired_reservations_refunds_balance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")
            store.reserve(account.account_id, usdc_to_units("0.25"), "res-expired")
            with store._connect() as conn:
                conn.execute("UPDATE reservations SET created_at = 0 WHERE reservation_id = 'res-expired'")
            released = store.release_expired_reservations(max_age_seconds=1)
            released_again = store.release_expired_reservations(max_age_seconds=1)
            updated = store.get_by_account(account.account_id)

        self.assertEqual(released, 1)
        self.assertEqual(released_again, 0)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.balance_usdc, "1.000000")

    def test_suspended_account_cannot_reserve_or_debit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")
            suspended = store.set_account_status(account.account_id, "suspended")

            with self.assertRaisesRegex(BillingError, "suspended"):
                store.reserve(account.account_id, usdc_to_units("0.10"), "res-1")
            with self.assertRaisesRegex(BillingError, "suspended"):
                store.debit(account.account_id, usdc_to_units("0.10"), "event-1")

        self.assertEqual(suspended.status, "suspended")

    def test_reserve_and_capture_are_idempotent_for_same_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a")
            store.deposit(account.account_id, "1.00")

            first = store.reserve(account.account_id, usdc_to_units("0.25"), "res-1")
            second = store.reserve(account.account_id, usdc_to_units("0.25"), "res-1")
            captured = store.capture("res-1", usdc_to_units("0.10"), "event-1")
            captured_again = store.capture("res-1", usdc_to_units("0.10"), "event-1")

        self.assertEqual(first.balance_usdc, "0.750000")
        self.assertEqual(second.balance_usdc, "0.750000")
        self.assertEqual(captured.balance_usdc, "0.900000")
        self.assertEqual(captured_again.balance_usdc, "0.900000")

    def test_usdc_amount_rejects_extra_precision(self) -> None:
        with self.assertRaisesRegex(BillingError, "6 decimal"):
            usdc_to_units("0.0000001")


if __name__ == "__main__":
    unittest.main()
