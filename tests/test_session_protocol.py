from __future__ import annotations

import copy
import time
import unittest

from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import create_identity
from gateway.session_protocol import (
    SESSION_V4_AUTHORIZATION_SCHEMA,
    SessionProtocolError,
    SessionSignatureError,
    build_session_authorization,
    build_session_receipt,
    build_session_request,
    normalize_session_authorization,
    session_authorization_hash,
    verify_session_authorization,
    verify_session_evm_signature,
    verify_session_receipt,
    verify_session_request,
)


class SessionProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.consumer = create_identity()
        self.provider = create_identity()
        self.consumer_private_key = "0x" + "1".zfill(64)
        self.session_private_key = "0x" + "3".zfill(64)
        self.provider_private_key = "0x" + "2".zfill(64)
        self.consumer_address = private_key_to_address(
            parse_private_key(self.consumer_private_key)
        )
        self.session_address = private_key_to_address(
            parse_private_key(self.session_private_key)
        )
        self.provider_address = private_key_to_address(
            parse_private_key(self.provider_private_key)
        )
        self.auth = build_session_authorization(
            session_id="0x" + "a" * 64,
            session_key=self.session_address,
            consumer_payment_address=self.consumer_address,
            provider_id=self.provider.peer_id,
            provider_payment_address=self.provider_address,
            channel="codex-standard-v1",
            pricing_version=1,
            pricing_hash="0x" + "b" * 64,
            max_amount_units=1_000,
            max_fee_units=250,
            expires_at=self.now + 900,
            deadline=self.now + 600,
            signer=self.consumer,
            now=self.now,
        )

    def _request(self, *, sequence: int = 1, previous: int = 0, fee: int = 100):
        return build_session_request(
            authorization=self.auth,
            request_id=f"request-{sequence}",
            request_hash="0x" + str(sequence) * 64,
            max_fee_units=fee,
            deadline=self.now + 300,
            sequence=sequence,
            previous_cumulative_spend_units=previous,
            signer=self.consumer,
            now=self.now,
        )

    def test_authorization_and_request_are_ed25519_bound(self) -> None:
        verified_auth = verify_session_authorization(
            self.auth,
            provider_id=self.provider.peer_id,
            expected_channel="codex-standard-v1",
            now=self.now,
        )
        self.assertEqual(verified_auth["schema"], SESSION_V4_AUTHORIZATION_SCHEMA)
        request = self._request()
        verified_request = verify_session_request(
            request,
            self.auth,
            now=self.now,
        )
        self.assertEqual(verified_request["sequence"], 1)
        self.assertEqual(verified_request["cumulative_spend_units"], 100)
        self.assertEqual(
            verified_request["authorization_hash"], session_authorization_hash(self.auth)
        )

    def test_payout_addresses_are_bound_across_authorization_request_and_receipt(self) -> None:
        relay = "0x" + "4" * 40
        pool = "0x" + "5" * 40
        auth = build_session_authorization(
            session_id="0x" + "d" * 64,
            session_key=self.session_address,
            consumer_payment_address=self.consumer_address,
            provider_id=self.provider.peer_id,
            provider_payment_address=self.provider_address,
            relay_payment_address=relay,
            pool_payment_address=pool,
            channel="codex-standard-v1",
            pricing_version=1,
            pricing_hash="0x" + "e" * 64,
            max_amount_units=500,
            expires_at=self.now + 900,
            signer=self.consumer,
            now=self.now,
        )
        request = build_session_request(
            authorization=auth,
            request_id="payout-bound",
            request_hash="0x" + "f" * 64,
            max_fee_units=100,
            deadline=self.now + 300,
            signer=self.consumer,
            now=self.now,
        )
        self.assertEqual(request["relay_payment_address"], relay)
        self.assertEqual(request["pool_payment_address"], pool)
        receipt = build_session_receipt(
            request=request,
            response_hash="0x" + "1" * 64,
            amount_units=75,
            signer=self.provider,
            provider_public_key=self.provider.public_key,
            now=self.now,
        )
        verified = verify_session_receipt(receipt, auth, request, now=self.now)
        self.assertEqual(verified["relay_payment_address"], relay)
        self.assertEqual(verified["pool_payment_address"], pool)

        tampered = copy.deepcopy(request)
        tampered["relay_payment_address"] = "0x" + "6" * 40
        with self.assertRaisesRegex(SessionProtocolError, "relay_payment_address"):
            verify_session_request(tampered, auth, now=self.now)

    def test_legacy_omitted_payout_fields_default_to_zero_address(self) -> None:
        legacy = copy.deepcopy(self.auth)
        legacy.pop("relay_payment_address")
        legacy.pop("pool_payment_address")
        normalized = normalize_session_authorization(legacy, require_canonical=True)
        self.assertEqual(normalized["relay_payment_address"], "0x" + "0" * 40)
        self.assertEqual(normalized["pool_payment_address"], "0x" + "0" * 40)

        request = build_session_request(
            authorization=legacy,
            request_id="legacy-payout-default",
            request_hash="0x" + "2" * 64,
            max_fee_units=100,
            deadline=self.now + 300,
            signer=self.consumer,
            now=self.now,
        )
        verified = verify_session_request(request, legacy, now=self.now, require_outer_signature=False)
        self.assertEqual(verified["authorization_hash"], session_authorization_hash(legacy))

    def test_sequence_and_cumulative_spend_must_be_monotonic(self) -> None:
        first = self._request()
        second = self._request(sequence=2, previous=100)
        verify_session_request(first, self.auth, now=self.now)
        verify_session_request(
            second,
            self.auth,
            previous_sequence=1,
            previous_cumulative_spend_units=100,
            now=self.now,
        )
        with self.assertRaisesRegex(SessionProtocolError, "increase exactly by one"):
            verify_session_request(
                second,
                self.auth,
                previous_sequence=0,
                previous_cumulative_spend_units=0,
                now=self.now,
            )
        tampered = copy.deepcopy(second)
        tampered["cumulative_spend_units"] = 999
        # The outer signature covers the spend value, so this is rejected
        # before a provider could account the inflated cumulative amount.
        with self.assertRaises(SessionProtocolError):
            verify_session_request(
                tampered,
                self.auth,
                previous_sequence=1,
                previous_cumulative_spend_units=100,
                now=self.now,
            )

    def test_receipt_accounts_actual_spend_and_cannot_exceed_request(self) -> None:
        request = self._request(fee=100)
        receipt = build_session_receipt(
            request=request,
            response_hash="0x" + "c" * 64,
            amount_units=75,
            signer=self.provider,
            provider_public_key=self.provider.public_key,
            now=self.now,
        )
        verified = verify_session_receipt(
            receipt,
            self.auth,
            request,
            previous_cumulative_spend_units=0,
            now=self.now,
        )
        self.assertEqual(verified["amount_units"], 75)
        self.assertEqual(verified["cumulative_spend_units"], 75)
        too_large = copy.deepcopy(receipt)
        too_large["amount_units"] = 101
        with self.assertRaises(SessionProtocolError):
            verify_session_receipt(
                too_large,
                self.auth,
                request,
                previous_cumulative_spend_units=0,
                now=self.now,
            )

    def test_evm_signature_is_independent_from_outer_signature(self) -> None:
        auth = build_session_authorization(
            session_id="0x" + "d" * 64,
            session_key=self.session_address,
            consumer_payment_address=self.consumer_address,
            provider_id=self.provider.peer_id,
            provider_payment_address=self.provider_address,
            channel="codex-standard-v1",
            pricing_version=1,
            pricing_hash="0x" + "e" * 64,
            max_amount_units=500,
            expires_at=self.now + 900,
            signer=self.consumer,
            session_private_key=self.session_private_key,
            now=self.now,
        )
        verified = verify_session_authorization(
            auth,
            provider_id=self.provider.peer_id,
            now=self.now,
            require_evm_signature=True,
        )
        self.assertEqual(verify_session_evm_signature(verified), self.session_address)
        tampered = copy.deepcopy(auth)
        tampered["session_signature"]["v"] = 29
        with self.assertRaises(SessionSignatureError):
            verify_session_authorization(tampered, now=self.now, require_outer_signature=False)

    def test_unknown_fields_and_noncanonical_signed_fields_are_rejected(self) -> None:
        unknown = copy.deepcopy(self.auth)
        unknown["unexpected"] = True
        with self.assertRaisesRegex(SessionProtocolError, "unknown fields"):
            verify_session_authorization(unknown, now=self.now)
        noncanonical = copy.deepcopy(self.auth)
        noncanonical["pricing_hash"] = noncanonical["pricing_hash"].upper()
        with self.assertRaises(SessionProtocolError):
            verify_session_authorization(noncanonical, now=self.now)


if __name__ == "__main__":
    unittest.main()
