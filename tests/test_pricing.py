from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from gateway import ledger as ledger_module
from gateway.identity import create_identity
from gateway.ledger import (
    append_receipt,
    append_receipt_payload,
    append_receipt_payload_once,
    build_receipt,
    receipt_hash,
    sign_acceptance,
    verify_acceptance,
    verify_receipt_signature,
)
from gateway.p2p import DEFAULT_CHANNEL
from gateway.pricing import ChannelPricing, quote_usage


class PricingTest(unittest.TestCase):
    def test_quote_usage_applies_minimum_fee_and_splits(self) -> None:
        quote = quote_usage(
            DEFAULT_CHANNEL,
            {
                "input_tokens": 100,
                "output_tokens": 20,
            },
        )

        self.assertEqual(quote.to_dict()["gross_fee"], "0.002000")
        self.assertEqual(quote.to_dict()["provider_amount"], "0.001700")
        self.assertEqual(quote.to_dict()["relay_amount"], "0.000060")
        self.assertEqual(quote.to_dict()["pool_amount"], "0.000040")
        self.assertEqual(quote.to_dict()["treasury_amount"], "0.000200")

    def test_quote_usage_prices_input_and_output_tokens(self) -> None:
        quote = quote_usage(
            DEFAULT_CHANNEL,
            {
                "input_tokens": 2000,
                "output_tokens": 1000,
            },
        )

        self.assertEqual(quote.to_dict()["gross_fee"], "0.006000")
        self.assertEqual(quote.input_tokens, 2000)
        self.assertEqual(quote.output_tokens, 1000)

    def test_quote_uses_solidity_integer_flooring(self) -> None:
        pricing = ChannelPricing(
            channel="flooring-test",
            input_per_1k=Decimal("0.001500"),
            output_per_1k=Decimal("0"),
            minimum_fee=Decimal("0"),
        )

        quote = quote_usage("flooring-test", {"input_tokens": 1}, pricing=pricing)

        self.assertEqual(quote.to_dict()["gross_fee"], "0.000001")
        self.assertEqual(quote.to_dict()["provider_amount"], "0.000000")
        self.assertEqual(quote.to_dict()["treasury_amount"], "0.000001")

    def test_rejects_uncommitted_dynamic_multiplier(self) -> None:
        with self.assertRaisesRegex(ValueError, "not supported by the settlement contract"):
            ChannelPricing(channel="dynamic-test", base_multiplier=Decimal("1.1"))

    def test_rejects_amounts_or_shares_not_representable_on_chain(self) -> None:
        with self.assertRaisesRegex(ValueError, "more precision"):
            ChannelPricing(channel="precision-test", input_per_1k=Decimal("0.0000001"))
        with self.assertRaisesRegex(ValueError, "shares must sum to 1"):
            ChannelPricing(channel="split-test", provider_share=Decimal("0.84"))

    def test_append_receipt_writes_jsonl(self) -> None:
        identity = create_identity()
        quote = quote_usage(DEFAULT_CHANNEL, {"input_tokens": 1000, "output_tokens": 100})
        receipt = build_receipt(
            consumer_id="consumer-a",
            provider_id="provider-a",
            relay_id="relay-a",
            pool_url="http://pool",
            selected_address="relay://relay-a/provider-a",
            channel=DEFAULT_CHANNEL,
            model="gpt-5.5",
            endpoint="responses",
            input_value="hello",
            response={
                "request_id": "job-a",
                "output_text": "world",
                "usage": {"input_tokens": 1000, "output_tokens": 100},
            },
            quote=quote,
            started_at=100.0,
            finished_at=101.5,
            provider_payment_address="0x0000000000000000000000000000000000000002",
            signer=identity,
            request_hash="ab" * 32,
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipts.jsonl"
            append_receipt(path, receipt)
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["job_id"], "job-a")
        self.assertEqual(payload["consumer_id"], "consumer-a")
        self.assertEqual(payload["pricing"]["stablecoin"], "USDC")
        self.assertEqual(payload["provider_payment_address"], "0x0000000000000000000000000000000000000002")
        self.assertEqual(payload["request_hash"], "ab" * 32)
        self.assertEqual(payload["elapsed_ms"], 1500)
        self.assertEqual(verify_receipt_signature(payload)["job_id"], "job-a")

        accepted = sign_acceptance(payload, identity, accepted_by="consumer-a")
        acceptance = verify_acceptance(accepted)
        self.assertEqual(acceptance["receipt_hash"], receipt_hash(payload))
        self.assertEqual(acceptance["status"], "accepted")
        self.assertEqual(verify_receipt_signature(accepted)["job_id"], "job-a")

    def test_outbox_append_is_durable_idempotent_and_repairs_partial_tail(self) -> None:
        payload = {"job_id": "job-once", "value": 1}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipts.jsonl"
            path.write_bytes(b'{"job_id":"complete"}\n{"job_id":"partial"')
            first = append_receipt_payload_once(path, "job-once", payload)
            second = append_receipt_payload_once(path, "job-once", payload)
            lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual([item["job_id"] for item in lines], ["complete", "job-once"])

    def test_outbox_index_rejects_conflicting_payload_for_existing_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipts.jsonl"
            append_receipt_payload_once(path, "job-a", {"job_id": "job-a", "value": 1})

            with self.assertRaisesRegex(ValueError, "conflicting payload"):
                append_receipt_payload_once(path, "job-a", {"job_id": "job-a", "value": 2})

            payloads = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(payloads, [{"job_id": "job-a", "value": 1}])

    def test_all_append_apis_share_lock_and_job_id_uniqueness(self) -> None:
        payload = {"job_id": "shared-job", "value": "x" * 4096}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipts.jsonl"

            def append(index: int) -> bool:
                if index % 2:
                    append_receipt_payload(path, payload)
                    return False
                return append_receipt_payload_once(path, "shared-job", payload)

            with ThreadPoolExecutor(max_workers=16) as executor:
                results = list(executor.map(append, range(64)))
            lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            with sqlite3.connect(ledger_module._ledger_index_path(path)) as conn:
                indexed = conn.execute(
                    "SELECT job_id, payload_hash FROM receipt_jobs"
                ).fetchall()

        self.assertLessEqual(sum(results), 1)
        self.assertEqual(lines, [payload])
        self.assertEqual(len(indexed), 1)
        self.assertEqual(indexed[0][0], "shared-job")

    def test_persistent_index_bootstraps_once_then_growth_does_not_rescan_history(self) -> None:
        existing = [{"job_id": f"legacy-{index}", "value": index} for index in range(200)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipts.jsonl"
            path.write_text(
                "".join(json.dumps(payload, sort_keys=True) + "\n" for payload in existing),
                encoding="utf-8",
            )
            with patch.object(
                ledger_module,
                "_scan_ledger_records",
                wraps=ledger_module._scan_ledger_records,
            ) as scan:
                self.assertTrue(
                    append_receipt_payload_once(path, "new-0", {"job_id": "new-0", "value": 0})
                )
                for index in range(1, 21):
                    append_receipt_payload(path, {"job_id": f"new-{index}", "value": index})
                self.assertFalse(
                    append_receipt_payload_once(path, "new-0", {"job_id": "new-0", "value": 0})
                )
            with sqlite3.connect(ledger_module._ledger_index_path(path)) as conn:
                indexed_count = conn.execute("SELECT COUNT(*) FROM receipt_jobs").fetchone()[0]
                indexed_size = conn.execute(
                    "SELECT indexed_size FROM ledger_index_metadata WHERE singleton = 1"
                ).fetchone()[0]
            ledger_size = path.stat().st_size

        self.assertEqual(scan.call_count, 1)
        self.assertEqual(indexed_count, 221)
        self.assertEqual(indexed_size, ledger_size)


if __name__ == "__main__":
    unittest.main()
