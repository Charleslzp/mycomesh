from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from gateway.billing import BillingError, BillingStore, usdc_to_units


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
            store.mark_receipt_exported("event-1")
            exported = store.pending_receipts()

        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["receipt_id"], "event-1")
        self.assertEqual(exported, [])

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
            updated = store.get_by_account(account.account_id)

        self.assertEqual(released, 1)
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
