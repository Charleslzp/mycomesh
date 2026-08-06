from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.v8_indexer_service import (
    RECEIPT_EVENT_TOPIC,
    IndexedReceipt,
    IndexerConfig,
    IndexerCursor,
    ReceiptStore,
    create_app,
    decode_receipt_log,
)


CHAIN_ID = 11155111
SETTLEMENT = "0x" + "11" * 20
OWNER = "0x" + "22" * 20
PROVIDER = "0x" + "33" * 20
PROVIDER_SIGNER = "0x" + "44" * 20
RELAY = "0x" + "55" * 20


def _word_address(address: str) -> str:
    return "0" * 24 + address[2:]


def _receipt(index: int, *, owner: str = OWNER) -> IndexedReceipt:
    return IndexedReceipt(
        settlement_key="0x" + f"{index:064x}",
        request_id="0x" + f"{index + 100:064x}",
        owner=owner,
        provider=PROVIDER,
        provider_signer=PROVIDER_SIGNER,
        relay=RELAY,
        actual_fee_units=str(index * 100),
        input_tokens=index * 10,
        output_tokens=index,
        block_number=100 + index,
        block_hash="0x" + f"{index + 200:064x}",
        transaction_hash="0x" + f"{index + 300:064x}",
        transaction_index=0,
        log_index=index,
        block_timestamp=1_800_000_000 + index,
    )


class V8ReceiptIndexerTest(unittest.TestCase):
    def test_decodes_receipt_settled_log(self) -> None:
        value = decode_receipt_log(
            {
                "address": SETTLEMENT,
                "topics": [
                    RECEIPT_EVENT_TOPIC,
                    "0x" + "66" * 32,
                    "0x" + "77" * 32,
                    "0x" + _word_address(OWNER),
                ],
                "data": "0x"
                + _word_address(PROVIDER)
                + _word_address(PROVIDER_SIGNER)
                + _word_address(RELAY)
                + f"{2000:064x}",
                "blockNumber": "0x64",
                "blockHash": "0x" + "88" * 32,
                "transactionHash": "0x" + "99" * 32,
                "transactionIndex": "0x2",
                "logIndex": "0x3",
            },
            expected_contract=SETTLEMENT,
        )

        self.assertEqual(value.owner, OWNER)
        self.assertEqual(value.provider, PROVIDER)
        self.assertEqual(value.provider_signer, PROVIDER_SIGNER)
        self.assertEqual(value.relay, RELAY)
        self.assertEqual(value.actual_fee_units, "2000")
        self.assertEqual(value.block_number, 100)
        self.assertEqual(value.log_index, 3)

    def test_wallet_history_is_filtered_summarized_and_paginated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ReceiptStore(Path(directory) / "index.sqlite3", chain_id=CHAIN_ID, settlement=SETTLEMENT)
            store.apply_chunk(
                [_receipt(1), _receipt(2), _receipt(3), _receipt(4, owner="0x" + "aa" * 20)],
                IndexerCursor(104, "0x" + "bb" * 32, 1_800_000_100),
            )

            first, cursor, summary = store.list_receipts(OWNER, limit=2)
            self.assertEqual([item["block_number"] for item in first], [103, 102])
            self.assertEqual(cursor, "102:2")
            self.assertEqual(summary["receipt_count"], 3)
            self.assertEqual(summary["actual_fee_units"], "600")
            self.assertEqual(summary["input_tokens"], 60)

            second, cursor, _ = store.list_receipts(OWNER, limit=2, before=(102, 2))
            self.assertEqual([item["block_number"] for item in second], [101])
            self.assertIsNone(cursor)

    def test_public_api_requires_a_valid_wallet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = IndexerConfig(
                rpc_url="https://rpc.example",
                chain_id=CHAIN_ID,
                settlement=SETTLEMENT,
                deployment_block=1,
                database=str(Path(directory) / "index.sqlite3"),
                outbox_database="",
            )
            store = ReceiptStore(config.database, chain_id=CHAIN_ID, settlement=SETTLEMENT)
            store.apply_chunk(
                [_receipt(1)],
                IndexerCursor(101, "0x" + "cc" * 32, 1_800_000_000),
            )
            with TestClient(create_app(config, store=store, start_runtime=False)) as client:
                response = client.get("/v1/receipts", params={"owner": OWNER})
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertEqual(payload["owner"], OWNER)
                self.assertEqual(payload["summary"]["actual_fee_units"], "100")
                self.assertEqual(len(payload["receipts"]), 1)

                invalid = client.get("/v1/receipts", params={"owner": "not-an-address"})
                self.assertEqual(invalid.status_code, 400)


if __name__ == "__main__":
    unittest.main()
