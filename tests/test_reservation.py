from __future__ import annotations

import copy
import time
import unittest

from gateway.chain import SECP256K1_N, parse_private_key, private_key_to_address
from gateway.identity import create_identity
from gateway.reservation import (
    EVM_SESSION_AUTHORIZATION_VERSION,
    INFERENCE_REQUEST_HASH_VERSION,
    MAX_RESERVATION_TTL_SECONDS,
    ReservationError,
    build_evm_session_authorization,
    build_payment_reservation,
    evm_session_authorization_digest,
    evm_session_authorization_message,
    inference_request_hash,
    validate_evm_session_authorization,
    verify_eoa_session_authorization,
    verify_payment_reservation,
)


class PaymentReservationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = create_identity()
        self.now = int(time.time())
        self.wallet_private_key = "0x" + "1".zfill(64)
        self.consumer_address = private_key_to_address(parse_private_key(self.wallet_private_key))
        self.provider_address = "0x" + "2" * 40
        self.settlement_contract = "0x" + "3" * 40
        self.chain_id = 11155111
        self.pricing_hash = "0x" + "a" * 64
        self.reservation_id = "0x" + "b" * 64
        self.request_hash = "0x" + "c" * 64

    def test_inference_request_hash_binds_billable_envelope(self) -> None:
        baseline = inference_request_hash(
            endpoint="responses",
            model="gpt-5.5",
            input_value={"prompt": "hello"},
            max_output_tokens=2000,
        )
        self.assertEqual(len(baseline), 64)
        self.assertEqual(INFERENCE_REQUEST_HASH_VERSION, "mycomesh.inference.request.v2")
        self.assertNotEqual(
            baseline,
            inference_request_hash(
                endpoint="responses",
                model="gpt-5.5-mini",
                input_value={"prompt": "hello"},
                max_output_tokens=2000,
            ),
        )
        self.assertNotEqual(
            baseline,
            inference_request_hash(
                endpoint="responses",
                model="gpt-5.5",
                input_value={"prompt": "hello"},
                max_output_tokens=2001,
            ),
        )

    def test_inference_request_hash_uses_canonical_chat_messages(self) -> None:
        from_input = inference_request_hash(
            endpoint="chat",
            model="gpt-5.5",
            input_value="hello",
            max_output_tokens="128",
        )
        from_messages = inference_request_hash(
            endpoint="chat",
            model="gpt-5.5",
            messages=[{"content": "hello", "role": "user"}],
            max_output_tokens=128,
        )
        self.assertEqual(from_input, from_messages)

    def test_inference_request_hash_rejects_ambiguous_values(self) -> None:
        with self.assertRaisesRegex(ReservationError, "endpoint"):
            inference_request_hash(endpoint="images", model="gpt-5.5", input_value="hello", max_output_tokens=1)
        with self.assertRaisesRegex(ReservationError, "max_output_tokens"):
            inference_request_hash(endpoint="responses", model="gpt-5.5", input_value="hello", max_output_tokens=True)
        with self.assertRaisesRegex(ReservationError, "max_output_tokens"):
            inference_request_hash(endpoint="responses", model="gpt-5.5", input_value="hello", max_output_tokens=1.5)
        with self.assertRaisesRegex(ReservationError, "canonical JSON"):
            inference_request_hash(
                endpoint="responses",
                model="gpt-5.5",
                input_value={"temperature": float("nan")},
                max_output_tokens=1,
            )

    def test_v2_reservation_remains_explicit_and_verifiable(self) -> None:
        reservation = build_payment_reservation(
            request_id="req-v2",
            consumer_id="consumer",
            consumer_payment_address=self.consumer_address,
            provider_id="provider",
            provider_payment_address=self.provider_address,
            channel="channel",
            pricing_hash=self.pricing_hash,
            max_fee_units=100,
            signer=self.identity,
            expires_at=self.now + 60,
        )

        verified = verify_payment_reservation(
            reservation,
            request_id="req-v2",
            channel="channel",
            provider_id="provider",
            consumer_public_key=self.identity.public_key,
            pricing_hash=self.pricing_hash,
            settlement_version=2,
            now=self.now,
        )

        self.assertEqual(verified["settlement_version"], 2)

    def test_v3_binds_pricing_and_onchain_reservation(self) -> None:
        reservation = self._v3_reservation()

        verified = verify_payment_reservation(
            reservation,
            request_id="req-v3",
            channel="channel",
            provider_id="provider",
            provider_payment_address=self.provider_address,
            consumer_public_key=self.identity.public_key,
            pricing_hash=self.pricing_hash,
            settlement_version=3,
            pricing_version=7,
            onchain_reservation_id=self.reservation_id,
            request_hash=self.request_hash,
            settlement_chain_id=self.chain_id,
            settlement_contract=self.settlement_contract,
            now=self.now,
        )

        self.assertEqual(verified["pricing_version"], 7)
        self.assertEqual(verified["onchain_reservation_id"], self.reservation_id)
        self.assertEqual(verified["request_hash"], self.request_hash)
        self.assertFalse(verified["provider_fallback_allowed"])
        authorization = verify_eoa_session_authorization(
            verified["evm_session_authorization"],
            consumer_payment_address=self.consumer_address,
            session_public_key=self.identity.public_key,
            now=self.now,
        )
        self.assertEqual(authorization["authorization_version"], EVM_SESSION_AUTHORIZATION_VERSION)
        self.assertEqual(authorization["onchain_reservation_id"], self.reservation_id)

    def test_v3_fallback_authorization_is_explicit_and_verified(self) -> None:
        reservation = self._v3_reservation(provider_fallback_allowed=True)

        verified = verify_payment_reservation(
            reservation,
            request_id="req-v3",
            channel="channel",
            settlement_version=3,
            provider_fallback_allowed=True,
            now=self.now,
        )

        self.assertTrue(verified["provider_fallback_allowed"])
        with self.assertRaisesRegex(ReservationError, "provider_fallback_allowed mismatch"):
            verify_payment_reservation(
                reservation,
                request_id="req-v3",
                channel="channel",
                settlement_version=3,
                provider_fallback_allowed=False,
                now=self.now,
            )

    def test_v3_rejects_missing_chain_fields(self) -> None:
        with self.assertRaisesRegex(ReservationError, "onchain_reservation_id"):
            build_payment_reservation(
                request_id="req-v3",
                consumer_id="consumer",
                consumer_payment_address=self.consumer_address,
                provider_id="provider",
                provider_payment_address=self.provider_address,
                channel="channel",
                pricing_hash=self.pricing_hash,
                max_fee_units=100,
                signer=self.identity,
                expires_at=self.now + 60,
                settlement_version=3,
                pricing_version=7,
                settlement_chain_id=self.chain_id,
                settlement_contract=self.settlement_contract,
                consumer_wallet_private_key=self.wallet_private_key,
            )

    def test_v3_requires_wallet_authorization(self) -> None:
        with self.assertRaisesRegex(ReservationError, "exactly one"):
            build_payment_reservation(
                request_id="req-v3",
                consumer_id="consumer",
                consumer_payment_address=self.consumer_address,
                provider_id="provider",
                provider_payment_address=self.provider_address,
                channel="channel",
                pricing_hash=self.pricing_hash,
                max_fee_units=100,
                signer=self.identity,
                expires_at=self.now + 60,
                settlement_version=3,
                pricing_version=7,
                onchain_reservation_id=self.reservation_id,
                request_hash=self.request_hash,
                settlement_chain_id=self.chain_id,
                settlement_contract=self.settlement_contract,
            )

    def test_eip191_authorization_binds_every_security_field(self) -> None:
        authorization = self._v3_reservation()["evm_session_authorization"]
        message = evm_session_authorization_message(authorization)
        self.assertNotIn(b"wallet_signature", message)
        self.assertEqual(len(evm_session_authorization_digest(authorization)), 32)
        mutations = {
            "chain_id": self.chain_id + 1,
            "settlement_contract": "0x" + "4" * 40,
            "onchain_reservation_id": "0x" + "d" * 64,
            "consumer_payment_address": "0x" + "4" * 40,
            "provider_id": "other-provider",
            "provider_payment_address": "0x" + "4" * 40,
            "channel": "other-channel",
            "pricing_hash": "0x" + "d" * 64,
            "pricing_version": 8,
            "request_hash": "0x" + "d" * 64,
            "max_fee_units": 101,
            "expires_at": self.now + 61,
            "settlement_deadline": self.now + 49,
            "provider_fallback_allowed": True,
            "nonce": "0x" + "d" * 64,
            "session_public_key": "d" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                tampered = copy.deepcopy(authorization)
                tampered[field] = value
                with self.assertRaises(ReservationError):
                    verify_eoa_session_authorization(tampered, now=self.now)

    def test_session_authorization_rejects_unknown_missing_and_malformed_signature_fields(self) -> None:
        authorization = self._v3_reservation()["evm_session_authorization"]
        missing = copy.deepcopy(authorization)
        missing.pop("nonce")
        with self.assertRaisesRegex(ReservationError, "missing nonce"):
            validate_evm_session_authorization(missing, now=self.now)
        unknown = copy.deepcopy(authorization)
        unknown["extra"] = True
        with self.assertRaisesRegex(ReservationError, "unexpected extra"):
            validate_evm_session_authorization(unknown, now=self.now)

        short_signature = copy.deepcopy(authorization)
        short_signature["wallet_signature"] = "0x" + "11" * 64
        with self.assertRaisesRegex(ReservationError, "exactly 65 bytes"):
            verify_eoa_session_authorization(short_signature, now=self.now)
        bad_v = copy.deepcopy(authorization)
        bad_v["wallet_signature"] = authorization["wallet_signature"][:-2] + "1d"
        with self.assertRaisesRegex(ReservationError, "signature v"):
            verify_eoa_session_authorization(bad_v, now=self.now)
        high_s = copy.deepcopy(authorization)
        signature = bytes.fromhex(authorization["wallet_signature"][2:])
        high_s["wallet_signature"] = (
            "0x"
            + signature[:32].hex()
            + (SECP256K1_N - 1).to_bytes(32, "big").hex()
            + signature[64:].hex()
        )
        with self.assertRaisesRegex(ReservationError, "low-s"):
            verify_eoa_session_authorization(high_s, now=self.now)

    def test_v3_time_window_is_shared_by_local_external_and_full_authorizations(self) -> None:
        common = {
            "chain_id": self.chain_id,
            "settlement_contract": self.settlement_contract,
            "onchain_reservation_id": self.reservation_id,
            "consumer_payment_address": self.consumer_address,
            "provider_id": "provider",
            "provider_payment_address": self.provider_address,
            "channel": "channel",
            "pricing_hash": self.pricing_hash,
            "pricing_version": 7,
            "request_hash": self.request_hash,
            "max_fee_units": 100,
            "provider_fallback_allowed": False,
            "session_public_key": self.identity.public_key,
        }
        signing_sources = (
            {"wallet_private_key": self.wallet_private_key},
            {
                "wallet_signature": "0x1234",
                "nonce": "0x" + "d" * 64,
            },
        )
        for source in signing_sources:
            with self.subTest(source=next(iter(source))):
                with self.assertRaisesRegex(ReservationError, "within the next 30 days"):
                    build_evm_session_authorization(
                        **common,
                        **source,
                        expires_at=self.now + MAX_RESERVATION_TTL_SECONDS + 1,
                        settlement_deadline=self.now + 50,
                        now=self.now,
                    )
                with self.assertRaisesRegex(ReservationError, "deadline must be active"):
                    build_evm_session_authorization(
                        **common,
                        **source,
                        expires_at=self.now + 60,
                        settlement_deadline=self.now,
                        now=self.now,
                    )

        authorization = self._v3_reservation()["evm_session_authorization"]
        too_far = copy.deepcopy(authorization)
        too_far["expires_at"] = self.now + MAX_RESERVATION_TTL_SECONDS + 1
        with self.assertRaisesRegex(ReservationError, "within the next 30 days"):
            validate_evm_session_authorization(too_far, now=self.now)
        inactive_deadline = copy.deepcopy(authorization)
        inactive_deadline["settlement_deadline"] = self.now
        with self.assertRaisesRegex(ReservationError, "deadline must be active"):
            validate_evm_session_authorization(inactive_deadline, now=self.now)

    def test_v3_rejects_wallet_key_for_another_consumer(self) -> None:
        with self.assertRaisesRegex(ReservationError, "does not match consumer_payment_address"):
            self._v3_reservation(consumer_wallet_private_key="0x" + "2".zfill(64))

    def test_v3_rejects_wrong_expected_version_or_reservation(self) -> None:
        reservation = self._v3_reservation()
        with self.assertRaisesRegex(ReservationError, "pricing_version mismatch"):
            verify_payment_reservation(
                reservation,
                request_id="req-v3",
                channel="channel",
                settlement_version=3,
                pricing_version=8,
                now=self.now,
            )
        with self.assertRaisesRegex(ReservationError, "onchain_reservation_id mismatch"):
            verify_payment_reservation(
                reservation,
                request_id="req-v3",
                channel="channel",
                settlement_version=3,
                pricing_version=7,
                onchain_reservation_id="0x" + "c" * 64,
                now=self.now,
            )

    def _v3_reservation(
        self,
        *,
        provider_fallback_allowed: bool = False,
        consumer_wallet_private_key: str | None = None,
    ) -> dict[str, object]:
        return build_payment_reservation(
            request_id="req-v3",
            consumer_id="consumer",
            consumer_payment_address=self.consumer_address,
            provider_id="provider",
            provider_payment_address=self.provider_address,
            channel="channel",
            pricing_hash=self.pricing_hash,
            max_fee_units=100,
            signer=self.identity,
            expires_at=self.now + 60,
            settlement_version=3,
            pricing_version=7,
            onchain_reservation_id=self.reservation_id,
            request_hash=self.request_hash,
            settlement_deadline=self.now + 50,
            provider_fallback_allowed=provider_fallback_allowed,
            settlement_chain_id=self.chain_id,
            settlement_contract=self.settlement_contract,
            consumer_wallet_private_key=consumer_wallet_private_key or self.wallet_private_key,
        )


if __name__ == "__main__":
    unittest.main()
