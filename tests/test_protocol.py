from __future__ import annotations

import time
import unittest

from gateway.attestation import build_provider_settlement_attestation
from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import NodeIdentity, create_identity, sign_document
from gateway.ledger import (
    ACCEPTANCE_PURPOSE,
    LEGACY_RECEIPT_VERSION,
    acceptance_hash,
    build_receipt,
    sign_acceptance,
    sign_receipt,
    stable_hash,
)
from gateway.p2p import DEFAULT_CHANNEL, PROVIDER_RESPONSE_PURPOSE
from gateway.pricing import quote_usage
from gateway.protocol import ProtocolValidationError, validate_settlement_receipt, verify_provider_response
from gateway.reservation import build_payment_reservation, verify_payment_reservation


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

    def test_acceptance_version_is_not_ignored(self) -> None:
        receipt, consumer, _ = self._accepted_receipt()
        receipt = self._resign_acceptance(receipt, consumer, acceptance_version="mycomesh-acceptance-v0")

        with self.assertRaisesRegex(ProtocolValidationError, "acceptance version"):
            validate_settlement_receipt(receipt)

    def test_acceptance_job_id_must_match_receipt(self) -> None:
        receipt, consumer, _ = self._accepted_receipt()
        receipt = self._resign_acceptance(receipt, consumer, job_id="another-job")

        with self.assertRaisesRegex(ProtocolValidationError, "job_id mismatch"):
            validate_settlement_receipt(receipt)

    def test_strict_mode_rejects_legacy_receipt(self) -> None:
        receipt, _, _ = self._accepted_receipt()

        with self.assertRaisesRegex(ProtocolValidationError, "legacy settlement receipts are disabled"):
            validate_settlement_receipt(receipt, allow_legacy_receipts=False)

    def test_attested_v2_receipt_passes_strict_mode(self) -> None:
        receipt, _, _ = self._accepted_receipt(with_attestation=True)

        result = validate_settlement_receipt(
            receipt,
            allow_legacy_receipts=False,
            required_settlement_version=2,
        )

        self.assertEqual(result["receipt"]["receipt_version"], "mycomesh-receipt-v2")

    def test_v3_receipt_cannot_be_downgraded_to_legacy(self) -> None:
        receipt, consumer, _ = self._accepted_receipt(settlement_version=3, with_attestation=True)
        unsigned = self._without_acceptance(receipt)
        unsigned["receipt_version"] = LEGACY_RECEIPT_VERSION
        unsigned["provider_settlement_attestation"] = None
        downgraded = sign_acceptance(sign_receipt(unsigned, consumer), consumer, accepted_by="acct-a")

        with self.assertRaisesRegex(ProtocolValidationError, "Settlement V3 requires"):
            validate_settlement_receipt(downgraded)

    def test_signed_malformed_hash_is_rejected_by_shape_validation(self) -> None:
        receipt, consumer, _ = self._accepted_receipt()
        unsigned = self._without_acceptance(receipt)
        unsigned["request_hash"] = "not-a-digest"
        malformed = sign_acceptance(sign_receipt(unsigned, consumer), consumer, accepted_by="acct-a")

        with self.assertRaisesRegex(ProtocolValidationError, "request_hash"):
            validate_settlement_receipt(malformed)

    def test_malformed_pricing_value_is_wrapped_as_protocol_error(self) -> None:
        receipt, consumer, _ = self._accepted_receipt(with_attestation=True)
        unsigned = self._without_acceptance(receipt)
        unsigned["pricing"] = {**unsigned["pricing"], "input_tokens": "1.5"}
        malformed = sign_acceptance(sign_receipt(unsigned, consumer), consumer, accepted_by="acct-a")

        with self.assertRaisesRegex(ProtocolValidationError, "pricing input_tokens must be an integer"):
            validate_settlement_receipt(malformed)

    def _accepted_receipt(
        self,
        *,
        settlement_version: int = 2,
        with_attestation: bool = False,
    ) -> tuple[dict[str, object], NodeIdentity, NodeIdentity]:
        consumer = create_identity()
        provider = create_identity()
        now = int(time.time())
        consumer_wallet_private_key = "0x" + "11" * 32
        consumer_address = (
            private_key_to_address(parse_private_key(consumer_wallet_private_key))
            if settlement_version == 3
            else "0x" + "1" * 40
        )
        provider_address = "0x" + "2" * 40
        pricing_hash = "0x" + "a" * 64
        response: dict[str, object] = {
            "request_id": "job-1",
            "output_text": "ok",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        quote = quote_usage(DEFAULT_CHANNEL, response["usage"])
        reservation_kwargs: dict[str, object] = {}
        if settlement_version == 3:
            reservation_kwargs = {
                "pricing_version": 7,
                "onchain_reservation_id": "0x" + "b" * 64,
                "request_hash": stable_hash("hi"),
                "settlement_deadline": now + 90,
                "settlement_chain_id": 31_337,
                "settlement_contract": "0x" + "3" * 40,
                "consumer_wallet_private_key": consumer_wallet_private_key,
            }
        signed_reservation = build_payment_reservation(
            request_id="job-1",
            consumer_id="acct-a",
            consumer_payment_address=consumer_address,
            provider_id=provider.peer_id,
            provider_payment_address=provider_address,
            channel=DEFAULT_CHANNEL,
            pricing_hash=pricing_hash,
            max_fee_units=10_000,
            signer=consumer,
            expires_at=now + 120,
            settlement_version=settlement_version,
            **reservation_kwargs,
        )
        reservation = verify_payment_reservation(
            signed_reservation,
            request_id="job-1",
            channel=DEFAULT_CHANNEL,
            settlement_version=settlement_version,
            settlement_chain_id=(31_337 if settlement_version == 3 else None),
            settlement_contract=("0x" + "3" * 40 if settlement_version == 3 else None),
            now=now,
        )
        if with_attestation:
            response["provider_settlement_attestation"] = build_provider_settlement_attestation(
                request_id="job-1",
                request_hash=stable_hash("hi"),
                response=response,
                channel=DEFAULT_CHANNEL,
                model="gpt-5.5",
                endpoint="responses",
                reservation=reservation,
                quote=quote,
                provider_id=provider.peer_id,
                provider_payment_address=provider_address,
                signer=provider,
            )
        receipt = build_receipt(
            consumer_id="acct-a",
            provider_id=provider.peer_id,
            relay_id=None,
            pool_url="https://pool.example",
            selected_address="provider.example:9700",
            channel=DEFAULT_CHANNEL,
            model="gpt-5.5",
            endpoint="responses",
            input_value="hi",
            response=response,
            quote=quote,
            started_at=now,
            finished_at=now + 1,
            consumer_public_key=consumer.public_key,
            provider_public_key=provider.public_key,
            consumer_payment_address=consumer_address,
            provider_payment_address=provider_address,
            channel_pricing_hash=pricing_hash,
            settlement_version=settlement_version,
            pricing_version=7 if settlement_version == 3 else None,
            onchain_reservation_id="0x" + "b" * 64 if settlement_version == 3 else None,
            settlement_deadline=now + 90 if settlement_version == 3 else 0,
            signer=consumer,
        ).to_dict()
        return sign_acceptance(receipt, consumer, accepted_by="acct-a"), consumer, provider

    @staticmethod
    def _without_acceptance(receipt: dict[str, object]) -> dict[str, object]:
        return {
            key: value
            for key, value in receipt.items()
            if key not in {"acceptance", "acceptance_signature", "accepted_hash"}
        }

    def _resign_acceptance(
        self,
        receipt: dict[str, object],
        consumer: NodeIdentity,
        **changes: object,
    ) -> dict[str, object]:
        acceptance = dict(receipt["acceptance"])
        acceptance.update(changes)
        signed = sign_document(acceptance, consumer.private_key, purpose=ACCEPTANCE_PURPOSE)
        updated = dict(receipt)
        updated["acceptance"] = {key: value for key, value in signed.items() if key != "signature"}
        updated["acceptance_signature"] = signed["signature"]
        updated["accepted_hash"] = acceptance_hash(updated["acceptance"])
        return updated


if __name__ == "__main__":
    unittest.main()
