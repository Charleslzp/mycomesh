from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.billing import BillingStore
from gateway.indexer import DEPOSITED_TOPIC, sync_prepaid_balances, sync_prepaid_balances_from_events


class IndexerTest(unittest.TestCase):
    def test_sync_prepaid_balances_updates_local_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            account = store.create_account("acct-a", payment_address="0x0000000000000000000000000000000000000001")
            state = Path(tmp) / "indexer.json"
            with patch("gateway.indexer.prepaid_balance", return_value=420_000), patch("gateway.indexer._rpc_block_number", return_value=100):
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

            with patch("gateway.indexer.rpc_call", side_effect=fake_rpc_call), patch("gateway.indexer.prepaid_balance", return_value=1_250_000):
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

    def test_event_sync_chunks_get_logs_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BillingStore(Path(tmp) / "billing.sqlite3")
            ranges: list[tuple[str, str]] = []

            def fake_rpc_call(_rpc_url: str, method: str, params: list[object], _timeout: float) -> object:
                if method == "eth_blockNumber":
                    return "0x0a"
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


if __name__ == "__main__":
    unittest.main()
