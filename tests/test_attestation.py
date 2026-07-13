from __future__ import annotations

import time
import unittest

from gateway.attestation import (
    AttestationError,
    PROVIDER_SETTLEMENT_PURPOSE,
    build_provider_settlement_attestation,
    verify_provider_settlement_attestation,
)
from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import create_identity, sign_document
from gateway.ledger import stable_hash
from gateway.pricing import DEFAULT_CHANNEL, quote_usage
from gateway.reservation import build_payment_reservation, verify_payment_reservation


class ProviderSettlementAttestationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.consumer = create_identity()
        self.provider = create_identity()
        self.now = int(time.time())
        self.response = {
            "request_id": "req-1",
            "output_text": "answer",
            "usage": {"input_tokens": 1000, "output_tokens": 100},
        }
        signed_reservation = build_payment_reservation(
            request_id="req-1",
            consumer_id="consumer-1",
            consumer_payment_address="0x" + "1" * 40,
            provider_id=self.provider.peer_id,
            provider_payment_address="0x" + "2" * 40,
            channel=DEFAULT_CHANNEL,
            pricing_hash="0x" + "a" * 64,
            max_fee_units=10_000,
            signer=self.consumer,
            expires_at=self.now + 60,
        )
        self.reservation = verify_payment_reservation(
            signed_reservation,
            request_id="req-1",
            channel=DEFAULT_CHANNEL,
            now=self.now,
        )
        self.quote = quote_usage(DEFAULT_CHANNEL, self.response["usage"])

    def test_provider_attestation_binds_usage_price_and_parties(self) -> None:
        attestation = self._attestation()

        verified = verify_provider_settlement_attestation(
            attestation,
            provider_public_key=self.provider.public_key,
            consumer_public_key=self.consumer.public_key,
            expected={
                "request_id": "req-1",
                "input_tokens": 1000,
                "output_tokens": 100,
                "gross_fee_units": 2000,
                "pricing_hash": "0x" + "a" * 64,
            },
            now=self.now,
        )

        self.assertEqual(verified["provider_id"], self.provider.peer_id)

    def test_attestation_tampering_is_rejected(self) -> None:
        attestation = self._attestation()
        attestation["output_tokens"] = 1

        with self.assertRaisesRegex(AttestationError, "invalid provider settlement attestation"):
            verify_provider_settlement_attestation(
                attestation,
                provider_public_key=self.provider.public_key,
                consumer_public_key=self.consumer.public_key,
                now=self.now,
            )

    def test_attestation_cannot_be_relabelled_as_another_provider(self) -> None:
        attestation = self._attestation()

        with self.assertRaisesRegex(AttestationError, "public_key mismatch"):
            verify_provider_settlement_attestation(
                attestation,
                provider_public_key=create_identity().public_key,
                consumer_public_key=self.consumer.public_key,
                now=self.now,
            )

    def test_builder_rejects_malformed_request_hash(self) -> None:
        with self.assertRaisesRegex(AttestationError, "request_hash"):
            self._attestation(request_hash="request-hash")

    def test_signed_malformed_integer_is_an_attestation_error(self) -> None:
        attestation = self._resign(self._attestation(), gross_fee_units="1.2")

        with self.assertRaisesRegex(AttestationError, "must be an integer"):
            verify_provider_settlement_attestation(
                attestation,
                provider_public_key=self.provider.public_key,
                consumer_public_key=self.consumer.public_key,
                now=self.now,
            )

    def test_signed_malformed_payment_address_is_rejected(self) -> None:
        attestation = self._resign(self._attestation(), provider_payment_address="https://provider.example")

        with self.assertRaisesRegex(AttestationError, "provider_payment_address"):
            verify_provider_settlement_attestation(
                attestation,
                provider_public_key=self.provider.public_key,
                consumer_public_key=self.consumer.public_key,
                now=self.now,
            )

    def test_v2_attestation_rejects_v3_only_fields(self) -> None:
        attestation = self._resign(
            self._attestation(),
            pricing_version=1,
            onchain_reservation_id="0x" + "3" * 64,
        )

        with self.assertRaisesRegex(AttestationError, "cannot contain V3"):
            verify_provider_settlement_attestation(
                attestation,
                provider_public_key=self.provider.public_key,
                consumer_public_key=self.consumer.public_key,
                now=self.now,
            )

    def test_attestation_consumer_key_is_bound_to_audience(self) -> None:
        other_consumer = create_identity()
        attestation = self._resign(self._attestation(), consumer_public_key=other_consumer.public_key)

        with self.assertRaisesRegex(AttestationError, "consumer_public_key mismatch"):
            verify_provider_settlement_attestation(
                attestation,
                provider_public_key=self.provider.public_key,
                consumer_public_key=self.consumer.public_key,
                now=self.now,
            )

    def test_v3_attestation_rejects_request_not_bound_by_reservation(self) -> None:
        wallet_private_key = "0x" + "11" * 32
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        settlement_contract = "0x" + "3" * 40
        signed = build_payment_reservation(
            request_id="req-v3",
            consumer_id="consumer-1",
            consumer_payment_address=consumer_address,
            provider_id=self.provider.peer_id,
            provider_payment_address="0x" + "2" * 40,
            channel=DEFAULT_CHANNEL,
            pricing_hash="0x" + "a" * 64,
            max_fee_units=10_000,
            signer=self.consumer,
            expires_at=self.now + 60,
            settlement_version=3,
            pricing_version=7,
            onchain_reservation_id="0x" + "b" * 64,
            request_hash="0x" + "c" * 64,
            settlement_deadline=self.now + 50,
            settlement_chain_id=11155111,
            settlement_contract=settlement_contract,
            consumer_wallet_private_key=wallet_private_key,
        )
        reservation = verify_payment_reservation(
            signed,
            request_id="req-v3",
            channel=DEFAULT_CHANNEL,
            settlement_version=3,
            settlement_chain_id=11155111,
            settlement_contract=settlement_contract,
            now=self.now,
        )

        with self.assertRaisesRegex(AttestationError, "does not match"):
            build_provider_settlement_attestation(
                request_id="req-v3",
                request_hash="0x" + "d" * 64,
                response=self.response,
                channel=DEFAULT_CHANNEL,
                model="gpt-5.5",
                endpoint="responses",
                reservation=reservation,
                quote=self.quote,
                provider_id=self.provider.peer_id,
                provider_payment_address="0x" + "2" * 40,
                signer=self.provider,
            )

    def _attestation(self, *, request_hash: str | None = None) -> dict[str, object]:
        return build_provider_settlement_attestation(
            request_id="req-1",
            request_hash=request_hash or stable_hash("request"),
            response=self.response,
            channel=DEFAULT_CHANNEL,
            model="model",
            endpoint="responses",
            reservation=self.reservation,
            quote=self.quote,
            provider_id=self.provider.peer_id,
            provider_payment_address="0x" + "2" * 40,
            signer=self.provider,
        )

    def _resign(self, attestation: dict[str, object], **changes: object) -> dict[str, object]:
        unsigned = {key: value for key, value in attestation.items() if key != "signature"}
        unsigned.update(changes)
        return sign_document(
            unsigned,
            self.provider.private_key,
            purpose=PROVIDER_SETTLEMENT_PURPOSE,
            audience=self.consumer.public_key,
            timestamp=self.now,
        )


if __name__ == "__main__":
    unittest.main()
