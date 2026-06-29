from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gateway.identity import create_identity
from gateway.ledger import append_receipt, build_receipt, receipt_hash, sign_acceptance, verify_acceptance, verify_receipt_signature
from gateway.p2p import DEFAULT_CHANNEL
from gateway.pricing import quote_usage


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
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipts.jsonl"
            append_receipt(path, receipt)
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["job_id"], "job-a")
        self.assertEqual(payload["consumer_id"], "consumer-a")
        self.assertEqual(payload["pricing"]["stablecoin"], "USDC")
        self.assertEqual(payload["provider_payment_address"], "0x0000000000000000000000000000000000000002")
        self.assertEqual(payload["elapsed_ms"], 1500)
        self.assertEqual(verify_receipt_signature(payload)["job_id"], "job-a")

        accepted = sign_acceptance(payload, identity, accepted_by="consumer-a")
        acceptance = verify_acceptance(accepted)
        self.assertEqual(acceptance["receipt_hash"], receipt_hash(payload))
        self.assertEqual(acceptance["status"], "accepted")
        self.assertEqual(verify_receipt_signature(accepted)["job_id"], "job-a")


if __name__ == "__main__":
    unittest.main()
