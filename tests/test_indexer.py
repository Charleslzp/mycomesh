from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.billing import BillingError, BillingStore, usdc_to_units
from gateway.chain import ChainError
from gateway.indexer import (
    DEPOSITED_TOPIC,
    RECEIPT_SETTLED_TOPIC,
    RECEIPT_SETTLED_V3_TOPIC,
    sync_prepaid_balances,
    sync_prepaid_balances_from_events,
    _settled_receipt_events,
    _settled_receipts,
)
from gateway.ledger import receipt_hash


class IndexerTest(unittest.TestCase):
    def test_v3_settlement_parser_preserves_reservation_identity(self) -> None:
        receipt = "0x" + "11" * 32
        consumer = "0x" + "01" * 20
        logs = [
            {
                "blockNumber": "0x64",
                "topics": [
                    RECEIPT_SETTLED_V3_TOPIC,
                    receipt,
                    "0x" + reservation_byte * 64,
                    "0x" + "0" * 24 + consumer[2:],
                ],
            }
            for reservation_byte in ("a", "b")
        ]

        events = _settled_receipt_events(logs)

        self.assertEqual(len(events), 2)
        self.assertEqual({event[3] for event in events}, {"0x" + "a" * 64, "0x" + "b" * 64})

    def test_same_receipt_hash_for_distinct_reservations_does_not_halt_indexing(self) -> None:
        receipt = "0x" + "11" * 32
        first_consumer = "0x" + "01" * 20
        second_consumer = "0x" + "02" * 20
        logs = [
            {
                "topics": [
                    RECEIPT_SETTLED_V3_TOPIC,
                    receipt,
                    "0x" + reservation_byte * 64,
                    "0x" + "0" * 24 + consumer[2:],
                ]
            }
            for reservation_byte, consumer in (("a", first_consumer), ("b", second_consumer))
        ]

        self.assertEqual(
            _settled_receipts(logs),
            [(receipt, first_consumer), (receipt, second_consumer)],
        )

    def test_sync_prepaid_balances_updates_local_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address="0x0000000000000000000000000000000000000001")
            state = Path(tmp) / "indexer.json"
            with (
                patch("gateway.indexer.prepaid_balance", return_value=420_000) as balance_mock,
                patch("gateway.indexer._rpc_block_number", return_value=100),
                patch("gateway.indexer._rpc_block_hash", return_value="0x" + "aa" * 32),
            ):
                result = sync_prepaid_balances(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement="0x0000000000000000000000000000000000000002",
                    accounts=[account.account_id],
                    chain_id=11155111,
                    state_path=state,
                )
            updated = store.get_by_account(account.account_id)
            sync_state = store.get_chain_sync_state()
            state_exists = state.exists()

        self.assertEqual(balance_mock.call_args.kwargs["block_tag"], 100)
        self.assertEqual(result.accounts[0].balance_usdc, "0.420000")
        self.assertEqual(result.chain_id, 11155111)
        self.assertIsNotNone(updated)
        self.assertIsNotNone(sync_state)
        self.assertEqual(sync_state["synced_block"], 100)
        self.assertEqual(updated.balance_usdc, "0.420000")
        self.assertTrue(state_exists)

    def test_sync_prepaid_balances_from_events_uses_confirmed_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address="0x0000000000000000000000000000000000000001")
            state = Path(tmp) / "indexer.json"

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x64"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "aa" * 32}
                if method == "eth_getLogs":
                    self.assertEqual(params[0]["fromBlock"], "0x5b")
                    self.assertEqual(params[0]["toBlock"], "0x5f")
                    return [
                        {
                            "topics": [
                                DEPOSITED_TOPIC,
                                "0x" + "0" * 24 + "0000000000000000000000000000000000000001",
                            ]
                        }
                    ]
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call), patch(
                "gateway.indexer.prepaid_balance", return_value=1_250_000
            ) as balance_mock:
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement="0x0000000000000000000000000000000000000002",
                    chain_id=11155111,
                    confirmations=5,
                    lookback_blocks=5,
                    state_path=state,
                )
            updated = store.get_by_account(account.account_id)

        self.assertEqual(balance_mock.call_args.kwargs["block_tag"], 95)
        self.assertEqual(result.from_block, 91)
        self.assertEqual(result.to_block, 95)
        self.assertEqual(result.logs_seen, 1)
        self.assertEqual(result.accounts[0].account_id, "acct-a")
        self.assertIsNotNone(updated)
        self.assertEqual(updated.balance_usdc, "1.250000")

    def test_event_sync_resets_cursor_when_settlement_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            state = Path(tmp) / "indexer.json"
            state.write_text(
                '{"chain_id":11155111,"settlement":"0x0000000000000000000000000000000000000099","last_block":100}\n',
                encoding="utf-8",
            )

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x6e"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "bb" * 32}
                if method == "eth_getLogs":
                    self.assertEqual(params[0]["fromBlock"], "0x6a")
                    self.assertEqual(params[0]["toBlock"], "0x6e")
                    return []
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement="0x0000000000000000000000000000000000000002",
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=5,
                    state_path=state,
                )

        self.assertEqual(result.from_block, 106)

    def test_event_sync_rejects_confirmed_head_behind_direct_cursor(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            state = Path(tmp) / "indexer.json"
            state.write_text(
                (
                    '{"chain_id":11155111,"settlement":"%s","to_block":100,'
                    '"synced_block_hash":"0x%s","source":"direct"}\n'
                )
                % (settlement, "aa" * 32),
                encoding="utf-8",
            )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                source="direct",
                synced_block_hash="0x" + "aa" * 32,
            )

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x64"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "aa" * 32}
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call):
                with self.assertRaisesRegex(ChainError, "confirmed chain head moved behind"):
                    sync_prepaid_balances_from_events(
                        store=store,
                        rpc_url="http://rpc.local",
                        settlement=settlement,
                        chain_id=11155111,
                        confirmations=6,
                        lookback_blocks=5,
                        state_path=state,
                    )
            database_state = store.get_chain_sync_state()

        self.assertEqual(database_state["reorg_detected"], 1)

    def test_event_sync_establishes_all_accounts_from_direct_cursor(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            for suffix in ("1", "2"):
                store.create_account(
                    f"acct-{suffix}",
                    payment_address="0x" + "0" * 39 + suffix,
                )
                store.publish_direct_chain_balance(
                    f"acct-{suffix}",
                    "1",
                    expected_state=store.get_chain_sync_state(),
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=100,
                    synced_block=100,
                    confirmations=0,
                    synced_block_hash="0x" + "aa" * 32,
                )

            def block_hash(_rpc_url: str, block_number: int, *, timeout: float) -> str:
                del timeout
                return "0x" + ("aa" if block_number == 100 else "bb") * 32

            with (
                patch("gateway.indexer._rpc_block_number", return_value=107),
                patch("gateway.indexer._rpc_block_hash", side_effect=block_hash),
                patch("gateway.indexer._rpc_get_logs", return_value=[]),
                patch("gateway.indexer.prepaid_balance", side_effect=[2_000_000, 3_000_000]),
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    chain_id=11155111,
                    confirmations=6,
                    state_path=Path(tmp) / "indexer.json",
                )
            global_state = store.get_chain_sync_state()
            first = store.get_by_account("acct-1")
            second = store.get_by_account("acct-2")
            first_state = store.get_chain_sync_state("acct-1")
            second_state = store.get_chain_sync_state("acct-2")

        self.assertEqual((result.from_block, result.to_block), (101, 101))
        self.assertEqual(global_state["source"], "events")
        self.assertEqual((first.balance_units, second.balance_units), (2_000_000, 3_000_000))
        self.assertEqual((first_state["source"], second_state["source"]), ("events", "events"))


    def test_event_sync_refreshes_explicit_new_account_without_new_block(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        block_hash = "0x" + "aa" * 32
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=94,
                confirmations=6,
                source="events",
                synced_block_hash=block_hash,
            )
            account = store.create_account(
                "acct-new",
                payment_address="0x0000000000000000000000000000000000000001",
            )
            with (
                patch("gateway.indexer._rpc_block_number", return_value=100),
                patch("gateway.indexer._rpc_block_hash", return_value=block_hash),
                patch("gateway.indexer._rpc_get_logs") as logs_mock,
                patch("gateway.indexer.prepaid_balance", return_value=2_500_000) as balance_mock,
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    accounts=[account.account_id],
                    chain_id=11155111,
                    confirmations=6,
                    state_path=Path(tmp) / "indexer.json",
                )
            refreshed = store.get_by_account(account.account_id)
            account_state = store.get_chain_sync_state(account.account_id)

        logs_mock.assert_not_called()
        self.assertEqual(balance_mock.call_args.kwargs["block_tag"], 94)
        self.assertEqual(result.accounts[0].account_id, account.account_id)
        self.assertEqual(refreshed.balance_units, 2_500_000)
        self.assertEqual(account_state["synced_block"], 94)
        self.assertEqual(account_state["confirmations"], 6)
    def test_event_sync_chunks_get_logs_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            ranges: list[tuple[str, str]] = []

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x0a"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "cc" * 32}
                if method == "eth_getLogs":
                    ranges.append((params[0]["fromBlock"], params[0]["toBlock"]))
                    return []
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call):
                sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement="0x0000000000000000000000000000000000000002",
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=10,
                    chunk_blocks=4,
                    state_path=Path(tmp) / "indexer.json",
                )

        self.assertEqual(ranges, [("0x1", "0x4"), ("0x5", "0x8"), ("0x9", "0xa")])

    def test_direct_resync_does_not_recredit_open_or_captured_spend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account(
                "acct-a", payment_address="0x0000000000000000000000000000000000000001"
            )
            common = {
                "store": store,
                "rpc_url": "http://rpc.local",
                "settlement": "0x0000000000000000000000000000000000000002",
                "accounts": [account.account_id],
                "chain_id": 11155111,
                "state_path": Path(tmp) / "indexer.json",
            }
            with (
                patch("gateway.indexer.prepaid_balance", return_value=1_000_000),
                patch("gateway.indexer._rpc_block_number", return_value=100),
                patch("gateway.indexer._rpc_block_hash", return_value="0x" + "aa" * 32),
            ):
                sync_prepaid_balances(**common)
                store.reserve(account.account_id, usdc_to_units("0.40"), "res-1")
                open_result = sync_prepaid_balances(**common)
                store.capture("res-1", usdc_to_units("0.25"), "event-1")
                captured_result = sync_prepaid_balances(**common)

        self.assertEqual(open_result.accounts[0].balance_usdc, "0.600000")
        self.assertEqual(captured_result.accounts[0].balance_usdc, "0.750000")

    def test_direct_sync_detects_reorg_during_balance_fetch(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account(
                "acct-a", payment_address="0x0000000000000000000000000000000000000001"
            )
            with (
                patch("gateway.indexer.prepaid_balance", return_value=1_000_000),
                patch("gateway.indexer._rpc_block_number", return_value=100),
                patch(
                    "gateway.indexer._rpc_block_hash",
                    side_effect=["0x" + "aa" * 32, "0x" + "bb" * 32],
                ),
                patch.object(
                    store,
                    "publish_canonical_chain_balances",
                    wraps=store.publish_canonical_chain_balances,
                ) as publish_mock,
            ):
                with self.assertRaisesRegex(ChainError, "reorganization"):
                    sync_prepaid_balances(
                        store=store,
                        rpc_url="http://rpc.local",
                        settlement=settlement,
                        accounts=[account.account_id],
                        chain_id=11155111,
                        state_path=Path(tmp) / "indexer.json",
                    )
            state = store.get_chain_sync_state(account.account_id)
            updated = store.get_by_account(account.account_id)

        self.assertEqual(state["reorg_detected"], 1)
        self.assertEqual(updated.balance_units, 0)
        publish_mock.assert_not_called()

    def test_event_reorg_after_balance_fetch_rewinds_receipt_before_any_publication(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        canonical_hash = "0x" + "aa" * 32
        log = {
            "transactionHash": "0x" + "11" * 32,
            "logIndex": "0x0",
            "blockNumber": "0x64",
            "blockHash": canonical_hash,
            "topics": [
                RECEIPT_SETTLED_TOPIC,
                receipt_hash(receipt),
                "0x" + "22" * 32,
                "0x" + "0" * 24 + consumer[2:],
            ],
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
            store.debit(account.account_id, 250_000, "event-1", receipt=receipt)
            with (
                patch("gateway.indexer._rpc_block_number", return_value=100),
                patch(
                    "gateway.indexer._rpc_block_hash",
                    side_effect=[canonical_hash, "0x" + "bb" * 32],
                ),
                patch("gateway.indexer._rpc_get_logs", return_value=[log]),
                patch("gateway.indexer.prepaid_balance", return_value=750_000),
                patch.object(
                    store,
                    "publish_canonical_chain_balances",
                    wraps=store.publish_canonical_chain_balances,
                ) as publish_mock,
            ):
                with self.assertRaisesRegex(ChainError, "reorganization"):
                    sync_prepaid_balances_from_events(
                        store=store,
                        rpc_url="http://rpc.local",
                        settlement=settlement,
                        accounts=[account.account_id],
                        chain_id=11155111,
                        confirmations=0,
                        lookback_blocks=1,
                        state_path=Path(tmp) / "indexer.json",
                    )
            state = store.get_chain_sync_state(account.account_id)
            updated = store.get_by_account(account.account_id)
            with store._connect() as conn:
                usage = conn.execute(
                    "SELECT chain_settled_at, chain_settled_block FROM usage_events WHERE event_id = 'event-1'"
                ).fetchone()

        publish_mock.assert_not_called()
        self.assertEqual(state["reorg_detected"], 1)
        self.assertEqual(state["pending_spend_units"], 250_000)
        self.assertEqual(updated.balance_units, 0)
        self.assertIsNone(usage["chain_settled_at"])
        self.assertIsNone(usage["chain_settled_block"])

    def test_event_sync_recovers_sticky_reorg_by_resyncing_all_accounts(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        old_hash = "0x" + "aa" * 32
        new_hash = "0x" + "bb" * 32
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            accounts = [
                store.create_account(
                    f"acct-{index}",
                    payment_address=f"0x{index:040x}",
                )
                for index in (1, 2)
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
                    synced_block_hash=old_hash,
                )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                source="events",
                synced_block_hash=old_hash,
            )
            store.mark_chain_reorg(chain_id=11155111, settlement=settlement)
            state_path = Path(tmp) / "indexer.json"
            state_path.write_text(
                (
                    '{"chain_id":11155111,"settlement":"%s","source":"events",'
                    '"last_block":100,"last_block_hash":"%s"}\n'
                )
                % (settlement, old_hash),
                encoding="utf-8",
            )

            with (
                patch("gateway.indexer._rpc_block_number", return_value=101),
                patch("gateway.indexer._rpc_block_hash", return_value=new_hash),
                patch("gateway.indexer._rpc_get_logs", return_value=[]),
                patch("gateway.indexer.prepaid_balance", return_value=1_000_000) as balance_mock,
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=2,
                    state_path=state_path,
                )
            account_states = [store.get_chain_sync_state(account.account_id) for account in accounts]
            global_state = store.get_chain_sync_state()

        self.assertEqual(result.from_block, 100)
        self.assertEqual(len(result.accounts), 2)
        self.assertEqual(balance_mock.call_count, 2)
        self.assertTrue(all(state["reorg_detected"] == 0 for state in account_states))
        self.assertEqual(global_state["reorg_detected"], 0)
        self.assertEqual(global_state["synced_block_hash"], new_hash)

    def test_event_sync_reconciles_orphaned_receipt_from_interrupted_run(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        orphan_log = {
            "transactionHash": "0x" + "11" * 32,
            "logIndex": "0x0",
            "blockNumber": "0x64",
            "blockHash": "0x" + "aa" * 32,
            "topics": [
                RECEIPT_SETTLED_TOPIC,
                receipt_hash(receipt),
                "0x" + "22" * 32,
                "0x" + "0" * 24 + consumer[2:],
            ],
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
            store.debit(account.account_id, 250_000, "event-1", receipt=receipt)
            store.confirm_chain_receipts(
                [receipt_hash(receipt)],
                chain_id=11155111,
                settlement=settlement,
                settled_block=100,
                consumer_addresses={receipt_hash(receipt): consumer},
            )
            store.record_chain_events(chain_id=11155111, settlement=settlement, logs=[orphan_log])
            state_path = Path(tmp) / "indexer.json"
            state_path.write_text(
                (
                    '{"chain_id":11155111,"settlement":"%s","source":"events",'
                    '"last_block":99,"last_block_hash":"0x%s"}\n'
                )
                % (settlement, "99" * 32),
                encoding="utf-8",
            )

            def block_hash(_rpc_url: str, block_number: int, timeout: float) -> str:
                del timeout
                return "0x" + ("99" if block_number == 99 else "bb") * 32

            with (
                patch("gateway.indexer._rpc_block_number", return_value=100),
                patch("gateway.indexer._rpc_block_hash", side_effect=block_hash),
                patch("gateway.indexer._rpc_get_logs", return_value=[]),
                patch("gateway.indexer.prepaid_balance", return_value=1_000_000),
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=1,
                    state_path=state_path,
                )
            account_state = store.get_chain_sync_state(account.account_id)
            updated = store.get_by_account(account.account_id)
            with store._connect() as conn:
                usage = conn.execute(
                    "SELECT chain_settled_at FROM usage_events WHERE event_id = 'event-1'"
                ).fetchone()
                event_count = conn.execute("SELECT COUNT(*) AS count FROM chain_events").fetchone()["count"]

        self.assertEqual(result.accounts[0].balance_usdc, "0.750000")
        self.assertEqual(updated.balance_usdc, "0.750000")
        self.assertEqual(account_state["pending_spend_units"], 250_000)
        self.assertIsNone(usage["chain_settled_at"])
        self.assertEqual(event_count, 0)

    def test_receipt_settlement_event_clears_matching_pending_spend(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        log = {
            "transactionHash": "0x" + "11" * 32,
            "logIndex": "0x0",
            "blockNumber": "0x64",
            "blockHash": "0x" + "aa" * 32,
            "topics": [
                RECEIPT_SETTLED_TOPIC,
                receipt_hash(receipt),
                "0x" + "22" * 32,
                "0x" + "0" * 24 + consumer[2:],
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address=consumer)
            store.sync_chain_balance(
                account.account_id,
                1_000_000,
                chain_id=11155111,
                settlement=settlement,
                latest_block=95,
                synced_block=95,
                confirmations=0,
                source="events",
                synced_at=1_000,
                synced_block_hash="0x" + "99" * 32,
            )
            store.debit(account.account_id, 250_000, "event-1", receipt=receipt)

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x64"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "aa" * 32}
                if method == "eth_getLogs":
                    return [log]
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call), patch(
                "gateway.indexer.prepaid_balance", return_value=750_000
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    accounts=[account.account_id],
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=1,
                    state_path=Path(tmp) / "indexer.json",
                )
            state = store.get_chain_sync_state(account.account_id)

        self.assertEqual(result.accounts[0].balance_usdc, "0.750000")
        self.assertEqual(state["pending_spend_units"], 0)

    def test_unidentified_receipt_settlement_log_cannot_clear_pending_spend(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        untrusted_log = {
            "topics": [
                RECEIPT_SETTLED_TOPIC,
                receipt_hash(receipt),
                "0x" + "22" * 32,
                "0x" + "0" * 24 + consumer[2:],
            ]
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
            store.debit(account.account_id, 250_000, "event-1", receipt=receipt)

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x64"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "aa" * 32}
                if method == "eth_getLogs":
                    return [untrusted_log]
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call), patch(
                "gateway.indexer.prepaid_balance", return_value=1_000_000
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    accounts=[account.account_id],
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=1,
                    state_path=Path(tmp) / "indexer.json",
                )
            state = store.get_chain_sync_state(account.account_id)

        self.assertEqual(result.accounts[0].balance_usdc, "0.750000")
        self.assertEqual(state["pending_spend_units"], 250_000)

    def test_v3_receipt_settlement_event_clears_matching_pending_spend(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        reservation_id = "0x" + "32" * 32
        receipt = {
            "job_id": "event-v3",
            "amount": "0.25",
            "onchain_reservation_id": reservation_id,
        }
        log = {
            "transactionHash": "0x" + "31" * 32,
            "logIndex": "0x0",
            "blockNumber": "0x64",
            "blockHash": "0x" + "aa" * 32,
            "topics": [
                RECEIPT_SETTLED_V3_TOPIC,
                receipt_hash(receipt),
                reservation_id,
                "0x" + "0" * 24 + consumer[2:],
            ],
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
            store.debit(account.account_id, 250_000, "event-v3", receipt=receipt)

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x64"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "aa" * 32}
                if method == "eth_getLogs":
                    self.assertIn(RECEIPT_SETTLED_V3_TOPIC, params[0]["topics"][0])
                    return [log]
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call), patch(
                "gateway.indexer.prepaid_balance", return_value=750_000
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    accounts=[account.account_id],
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=1,
                    state_path=Path(tmp) / "indexer.json",
                )
            state = store.get_chain_sync_state(account.account_id)

        self.assertEqual(result.accounts[0].balance_usdc, "0.750000")
        self.assertEqual(state["pending_spend_units"], 0)

    def test_receipt_settlement_for_another_consumer_cannot_clear_pending_spend(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        consumer = "0x0000000000000000000000000000000000000001"
        other_consumer = "0x0000000000000000000000000000000000000003"
        receipt = {"job_id": "event-1", "amount": "0.25"}
        log = {
            "transactionHash": "0x" + "41" * 32,
            "logIndex": "0x0",
            "blockNumber": "0x64",
            "blockHash": "0x" + "aa" * 32,
            "topics": [
                RECEIPT_SETTLED_TOPIC,
                receipt_hash(receipt),
                "0x" + "42" * 32,
                "0x" + "0" * 24 + other_consumer[2:],
            ],
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
            store.debit(account.account_id, 250_000, "event-1", receipt=receipt)

            def fake_rpc_call(_rpc_url: str, method: str, _params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x64"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "aa" * 32}
                if method == "eth_getLogs":
                    return [log]
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call), patch(
                "gateway.indexer.prepaid_balance", return_value=1_000_000
            ):
                result = sync_prepaid_balances_from_events(
                    store=store,
                    rpc_url="http://rpc.local",
                    settlement=settlement,
                    accounts=[account.account_id],
                    chain_id=11155111,
                    confirmations=0,
                    lookback_blocks=1,
                    state_path=Path(tmp) / "indexer.json",
                )
            state = store.get_chain_sync_state(account.account_id)

        self.assertEqual(result.accounts[0].balance_usdc, "0.750000")
        self.assertEqual(state["pending_spend_units"], 250_000)

    def test_cursor_block_hash_mismatch_fails_closed(self) -> None:
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
                source="events",
                synced_block_hash="0x" + "aa" * 32,
            )
            store.set_chain_sync_state(
                chain_id=11155111,
                settlement=settlement,
                latest_block=100,
                synced_block=100,
                confirmations=0,
                source="events",
                synced_block_hash="0x" + "aa" * 32,
            )
            state = Path(tmp) / "indexer.json"
            state.write_text(
                (
                    '{"chain_id":11155111,"settlement":"%s","last_block":100,'
                    '"last_block_hash":"0x%s"}\n'
                )
                % (settlement, "aa" * 32),
                encoding="utf-8",
            )

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x65"
                if method == "eth_getBlockByNumber":
                    return {"hash": "0x" + "bb" * 32}
                raise AssertionError(method)

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call):
                with self.assertRaisesRegex(ChainError, "reorganization"):
                    sync_prepaid_balances_from_events(
                        store=store,
                        rpc_url="http://rpc.local",
                        settlement=settlement,
                        chain_id=11155111,
                        confirmations=0,
                        state_path=state,
                    )
            reorged = store.get_chain_sync_state(account.account_id)
            with self.assertRaisesRegex(BillingError, "reorganization"):
                store.require_fresh_chain_sync(
                    chain_id=11155111,
                    settlement=settlement,
                    max_age_seconds=10_000_000_000,
                    max_block_lag=10,
                    account_id=account.account_id,
                )

        self.assertEqual(reorged["reorg_detected"], 1)


if __name__ == "__main__":
    unittest.main()
