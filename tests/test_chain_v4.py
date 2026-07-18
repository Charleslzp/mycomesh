from __future__ import annotations

from copy import deepcopy
import unittest

from gateway.chain import parse_private_key, private_key_to_address
from gateway.chain_v4 import build_provider_settlement_payload
from gateway.session_service import SessionClaim
import gateway.mycomesh as mycomesh


class V4SettlementQueueTest(unittest.TestCase):
    def test_runtime_receipt_deadline_may_be_earlier_but_not_later(self) -> None:
        self.assertEqual(
            mycomesh._validate_runtime_v4_receipt_deadline(
                1_000,
                1_100,
                now=900,
            ),
            1_000,
        )
        with self.assertRaisesRegex(
            mycomesh.P2PError,
            "exceeds the signed request deadline",
        ):
            mycomesh._validate_runtime_v4_receipt_deadline(1_200, 1_100, now=900)
        with self.assertRaisesRegex(
            mycomesh.P2PError,
            "deadline has elapsed",
        ):
            mycomesh._validate_runtime_v4_receipt_deadline(900, 1_100, now=900)

    def test_queue_canonicalizes_bare_bytes32_receipt_fields(self) -> None:
        provider_private_key = "0x" + "33" * 32
        session_private_key = "0x" + "11" * 32
        consumer = private_key_to_address(parse_private_key("0x" + "22" * 32))
        provider = private_key_to_address(parse_private_key(provider_private_key))
        payload = build_provider_settlement_payload(
            provider_private_key=provider_private_key,
            chain_id=11155111,
            settlement_contract="0x" + "44" * 20,
            session_id="0x" + "88" * 32,
            request_hash="0x" + "99" * 32,
            response_hash="0x" + "aa" * 32,
            channel_hash="0x" + "bb" * 32,
            pricing_version=1,
            pricing_hash="0x" + "cc" * 32,
            consumer=consumer,
            provider=provider,
            input_tokens=1,
            output_tokens=2,
            sequence=0,
            quoted_fee=3,
            deadline=9_999_999_999,
        )
        wire_payload = deepcopy(payload)
        for field in (
            "receipt_hash",
            "accepted_hash",
            "session_id",
            "request_hash",
            "response_hash",
            "channel",
            "pricing_hash",
        ):
            wire_payload["receipt"][field] = wire_payload["receipt"][field][2:]

        queued = mycomesh._queue_v4_settlement(
            session=SessionClaim(
                plan={},
                authorization={},
                request={},
                private_key=session_private_key,
                previous_cumulative_spend_units=0,
            ),
            settlement_payload=wire_payload,
        )

        self.assertEqual(queued["receipt"]["response_hash"], "0x" + "aa" * 32)
        self.assertTrue(queued["receipt_digest"].startswith("0x"))
        self.assertTrue(queued["calldata"].startswith("0x"))


if __name__ == "__main__":
    unittest.main()
