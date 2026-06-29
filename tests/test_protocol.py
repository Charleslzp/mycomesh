from __future__ import annotations

import unittest

from gateway.identity import create_identity, sign_document
from gateway.ledger import build_receipt, sign_acceptance
from gateway.p2p import DEFAULT_CHANNEL, PROVIDER_RESPONSE_PURPOSE
from gateway.pricing import quote_usage
from gateway.protocol import ProtocolValidationError, validate_settlement_receipt, verify_provider_response


class ProtocolValidationTest(unittest.TestCase):
    def test_verify_provider_response_matches_peer_descriptor(self) -> None:
        provider = create_identity()
        response = sign_document(
            {"ok": True, "request_id": "job-1", "output_text": "ok", "usage": {}},
            provider.private_key,
            purpose=PROVIDER_RESPONSE_PURPOSE,
        )

        verified = verify_provider_response(response, {"peer_id": provider.peer_id, "public_key": provider.public_key})

        self.assertEqual(verified["request_id"], "job-1")

    def test_verify_provider_response_rejects_wrong_peer(self) -> None:
        provider = create_identity()
        other = create_identity()
        response = sign_document(
            {"ok": True, "request_id": "job-1", "output_text": "ok", "usage": {}},
            provider.private_key,
            purpose=PROVIDER_RESPONSE_PURPOSE,
        )

        with self.assertRaisesRegex(ProtocolValidationError, "public_key"):
            verify_provider_response(response, {"peer_id": other.peer_id, "public_key": other.public_key})

    def test_validate_settlement_receipt_requires_signed_acceptance(self) -> None:
        consumer = create_identity()
        provider = create_identity()
        quote = quote_usage(DEFAULT_CHANNEL, {"input_tokens": 1, "output_tokens": 1})
        receipt = build_receipt(
            consumer_id="acct-a",
            provider_id=provider.peer_id,
            relay_id=None,
            pool_url="http://pool",
            selected_address="tcp://provider:9700",
            channel=DEFAULT_CHANNEL,
            model="gpt-5.5",
            endpoint="responses",
            input_value="hi",
            response={"request_id": "job-1", "output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}},
            quote=quote,
            started_at=100.0,
            finished_at=101.0,
            consumer_public_key=consumer.public_key,
            provider_public_key=provider.public_key,
            consumer_payment_address="0x0000000000000000000000000000000000000001",
            provider_payment_address="0x0000000000000000000000000000000000000002",
            signer=consumer,
        ).to_dict()
        accepted = sign_acceptance(receipt, consumer, accepted_by="acct-a")

        result = validate_settlement_receipt(
            accepted,
            consumer_address="0x0000000000000000000000000000000000000001",
            provider_address="0x0000000000000000000000000000000000000002",
            consumer_public_key=consumer.public_key,
            provider_public_key=provider.public_key,
        )

        self.assertEqual(result["acceptance"]["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
