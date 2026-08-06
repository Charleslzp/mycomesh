from __future__ import annotations

import unittest
import time
from unittest.mock import patch

from gateway.chain import ChainError, parse_private_key, private_key_to_address
from gateway.chain_v8 import (
    SIGNED_SCHEMA,
    build_authorization,
    build_provider_receipt,
    claim_payout,
    encode_signed_batch,
    encode_signed_receipt,
    finalize_relay_receipt,
    generate_payment_key,
    payment_key_address,
    payment_private_key,
    verify_authorization,
    verify_provider_receipt,
    verify_signed_receipt,
)


CHAIN_ID = 11155111
CONTRACT = "0x" + "11" * 20
RELAY_PAYOUT = "0x" + "22" * 20
PAYMENT_KEY = "0x" + "01".rjust(64, "0")
PROVIDER_KEY = "0x" + "02".rjust(64, "0")
PROVIDER_PAYOUT = "0x" + "99" * 20
RELAY_SIGNER_KEY = "0x" + "03".rjust(64, "0")
REQUEST_ID = "0x" + "44" * 32
REQUEST_HASH = "0x" + "55" * 32
RESPONSE_HASH = "0x" + "66" * 32
CHANNEL = "0x" + "77" * 32
PRICING_HASH = "0x" + "88" * 32
NOW = int(time.time())


def address(private_key: str) -> str:
    return private_key_to_address(parse_private_key(private_key))


class ChainV8Tests(unittest.TestCase):
    def authorization(self) -> dict[str, object]:
        return build_authorization(
            payment_key=PAYMENT_KEY,
            chain_id=CHAIN_ID,
            settlement_contract=CONTRACT,
            request_id=REQUEST_ID,
            request_hash=REQUEST_HASH,
            relay=RELAY_PAYOUT,
            relay_signer=address(RELAY_SIGNER_KEY),
            channel_hash=CHANNEL,
            pricing_version=1,
            pricing_hash=PRICING_HASH,
            max_fee=50_000,
            issued_at=NOW,
            deadline=NOW + 300,
        )

    def test_payment_key_round_trip(self) -> None:
        exported = generate_payment_key()
        self.assertTrue(exported.startswith("myco_sk_"))
        self.assertEqual(payment_key_address(exported), address(payment_private_key(exported)))

    def test_payout_claim_uses_external_wallet_transaction(self) -> None:
        with patch(
            "gateway.chain_v8.send_contract_transaction",
            return_value="0x" + "ab" * 32,
        ) as send:
            tx_hash = claim_payout(
                rpc_url="https://rpc.example",
                payout_private_key=PAYMENT_KEY,
                settlement=CONTRACT,
                chain_id=CHAIN_ID,
            )
        self.assertEqual(tx_hash, "0x" + "ab" * 32)
        self.assertEqual(send.call_args.kwargs["signature"], "claim()")
        self.assertEqual(send.call_args.kwargs["args"], [])
        self.assertEqual(send.call_args.kwargs["private_key"], PAYMENT_KEY)

    def test_authorization_binds_request_and_separate_relay_signer(self) -> None:
        verified = verify_authorization(
            self.authorization(),
            expected_chain_id=CHAIN_ID,
            expected_contract=CONTRACT,
            expected_relay=RELAY_PAYOUT,
            expected_relay_signer=address(RELAY_SIGNER_KEY),
            expected_request_id=REQUEST_ID,
            expected_request_hash=REQUEST_HASH,
            now=NOW + 1,
        )
        self.assertEqual(verified["authorization"]["key"], address(PAYMENT_KEY))

        tampered = self.authorization()
        tampered["authorization"] = {**tampered["authorization"], "request_hash": "0x" + "99" * 32}
        with self.assertRaisesRegex(ChainError, "hash mismatch"):
            verify_authorization(tampered, now=NOW + 1)

    def test_authorization_rejects_zero_bound_fields(self) -> None:
        for field in ("request_id", "request_hash", "channel", "pricing_hash"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ChainError, field):
                    build_authorization(
                        payment_key=PAYMENT_KEY,
                        chain_id=CHAIN_ID,
                        settlement_contract=CONTRACT,
                        request_id="0x" + "0" * 64 if field == "request_id" else REQUEST_ID,
                        request_hash="0x" + "0" * 64 if field == "request_hash" else REQUEST_HASH,
                        relay=RELAY_PAYOUT,
                        relay_signer=address(RELAY_SIGNER_KEY),
                        channel_hash="0x" + "0" * 64 if field == "channel" else CHANNEL,
                        pricing_version=1,
                        pricing_hash="0x" + "0" * 64 if field == "pricing_hash" else PRICING_HASH,
                        max_fee=50_000,
                        issued_at=NOW,
                        deadline=NOW + 300,
                    )

    def test_provider_and_relay_receipt_signatures_and_calldata(self) -> None:
        provider = build_provider_receipt(
            provider=PROVIDER_PAYOUT,
            provider_private_key=PROVIDER_KEY,
            authorization_payload=self.authorization(),
            response_hash=RESPONSE_HASH,
            relay=RELAY_PAYOUT,
            input_tokens=1200,
            output_tokens=300,
            actual_fee=2400,
        )
        _, receipt, _, _, _ = verify_provider_receipt(provider)
        self.assertEqual(receipt.provider, PROVIDER_PAYOUT)
        self.assertEqual(receipt.provider_signer, address(PROVIDER_KEY))
        self.assertEqual(receipt.relay, RELAY_PAYOUT)

        signed = finalize_relay_receipt(provider, relay_private_key=RELAY_SIGNER_KEY)
        self.assertEqual(signed["schema"], SIGNED_SCHEMA)
        verify_signed_receipt(signed, now=NOW + 1)
        with self.assertRaisesRegex(ChainError, "outside its time window"):
            verify_signed_receipt(signed, now=NOW + 1_000)
        self.assertGreater(len(encode_signed_receipt(signed)), 10)
        self.assertGreater(len(encode_signed_batch([signed, signed])), len(encode_signed_receipt(signed)))

        with self.assertRaisesRegex(ChainError, "relay signer"):
            finalize_relay_receipt(provider, relay_private_key="0x" + "04".rjust(64, "0"))


if __name__ == "__main__":
    unittest.main()
