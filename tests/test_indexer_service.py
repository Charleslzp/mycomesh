from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from gateway.indexer_service import IndexerServiceError, load_config


class IndexerServiceConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = {
            "MYCOMESH_NETWORK_PROFILE": "testnet",
            "MYCOMESH_SETTLEMENT_VERSION": "3",
            "MYCOMESH_BILLING_MODE": "onchain-prepaid",
            "MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE": "1",
            "MYCO_DEPLOYMENT": "/app/deployments/sepolia-myco-v3.json",
            "ETH_RPC_URL": "https://rpc.example",
            "ETH_CHAIN_ID": "11155111",
            "MYCOMESH_BILLING_DB": "postgresql://mycomesh:secret@postgres:5432/mycomesh",
        }
        self.deployment = SimpleNamespace(
            chain_id=11155111,
            settlement="0x0000000000000000000000000000000000000002",
        )

    def _load(self, **overrides: str):
        values = {**self.env, **overrides}
        with patch(
            "gateway.indexer_service.load_active_myco_deployment",
            return_value=self.deployment,
        ):
            return load_config(values)

    def test_production_defaults_are_bounded(self) -> None:
        config = self._load()

        self.assertEqual(config.confirmations, 6)
        self.assertEqual(config.max_age_seconds, 120)
        self.assertEqual(config.max_block_lag, 12)
        self.assertEqual(config.lookback_blocks, 100)
        self.assertEqual(config.chunk_blocks, 100)

    def test_testnet_confirmations_have_hard_minimum_and_maximum(self) -> None:
        for value in ("5", "65"):
            with self.subTest(value=value), self.assertRaisesRegex(
                IndexerServiceError, "must be between 6 and 64"
            ):
                self._load(MYCOMESH_CHAIN_SYNC_MIN_CONFIRMATIONS=value)

    def test_freshness_window_covers_two_cycles_and_is_capped(self) -> None:
        with self.assertRaisesRegex(IndexerServiceError, "two sync intervals"):
            self._load(
                MYCOMESH_INDEXER_SYNC_INTERVAL_SECONDS="30",
                MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS="59",
            )
        with self.assertRaisesRegex(IndexerServiceError, "must not exceed 300"):
            self._load(MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS="301")

    def test_block_lag_is_bounded_and_covers_confirmations(self) -> None:
        with self.assertRaisesRegex(IndexerServiceError, "at least the confirmation"):
            self._load(MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG="5")
        with self.assertRaisesRegex(IndexerServiceError, "must not exceed 64"):
            self._load(MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG="65")


if __name__ == "__main__":
    unittest.main()
