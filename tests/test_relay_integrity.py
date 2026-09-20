from __future__ import annotations

import copy
import time
import unittest
from unittest.mock import patch

from gateway.attestation import settlement_response_hash
from gateway.chain import DEFAULT_CHANNEL_HASH, parse_private_key, private_key_to_address
from gateway.chain_v8 import build_authorization, build_provider_receipt
from gateway.identity import create_identity, sign_document
from gateway.pricing import ChannelPricing, quote_usage, usage_tokens
from gateway.relay_integrity import (
    PROVIDER_RESPONSE_PURPOSE, RelayIntegrityError, provider_response_hash,
    validate_authorization_binding, validate_provider_response,
)


class RelayIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider_key = "0x" + "02".rjust(64, "0")
        self.relay_key = "0x" + "03".rjust(64, "0")
        self.provider_signer = private_key_to_address(parse_private_key(self.provider_key))
        self.relay_signer = private_key_to_address(parse_private_key(self.relay_key))
        self.provider = "0x" + "ab" * 20
        self.relay = "0x" + "cd" * 20
        self.provider_identity = create_identity()
        self.audience = create_identity().public_key
        self.pricing = ChannelPricing(channel="codex-standard-v1")
        self.request = {
            "chain_id": 11155111, "contract": "0x" + "ef" * 20,
            "request_id": "0x" + "12" * 32, "request_hash": "0x" + "34" * 32,
            "endpoint": "responses", "model": "test-model", "max_output_tokens": 500,
            "channel": self.pricing.channel,
        }
        now = int(time.time())
        self.payment = build_authorization(
            payment_key="0x" + "01".rjust(64, "0"), chain_id=self.request["chain_id"],
            settlement_contract=self.request["contract"],
            request_id=self.request["request_id"], request_hash=self.request["request_hash"],
            relay=self.relay, relay_signer=self.relay_signer,
            channel_hash=DEFAULT_CHANNEL_HASH, pricing_version=1,
            pricing_hash="0x" + "56" * 32, max_fee=10000,
            issued_at=now, deadline=now + 900,
        )
        self.response = {
            "type": "infer_result", "ok": True,
            "peer": {"peer_id": self.provider_identity.peer_id, "public_key": self.provider_identity.public_key},
            "request_id": self.request["request_id"], "endpoint": "responses", "model": "test-model",
            "output_text": "answer", "usage": {"input_tokens": 1000, "output_tokens": 300},
            "raw": {
                "output_text": "answer", "usage": {"input_tokens": 1000, "output_tokens": 300},
                "output": [{"type": "function_call", "arguments": '{"amount":1}'}],
            },
        }

    def seal(self, response=None, *, payment=None, receipt_fields=None, legacy_hash=False):
        result = copy.deepcopy(self.response if response is None else response)
        usage = result["usage"]
        input_tokens, output_tokens = usage_tokens(usage)
        args = dict(
            provider=self.provider, provider_private_key=self.provider_key,
            authorization_payload=payment or self.payment,
            response_hash=("0x" + settlement_response_hash(result)) if legacy_hash else provider_response_hash(result),
            relay=self.relay, input_tokens=input_tokens, output_tokens=output_tokens,
            actual_fee=int(quote_usage(self.pricing.channel, usage, pricing=self.pricing).gross_fee * 1000000),
        )
        args.update(receipt_fields or {})
        result["mycomesh_v8_settlement"] = build_provider_receipt(**args)
        return sign_document(result, self.provider_identity.private_key, PROVIDER_RESPONSE_PURPOSE, audience=self.audience)

    def check(self, response, **overrides):
        options = dict(
            settlement_version=8, request=self.request, expected_provider=self.provider,
            expected_provider_signer=self.provider_signer,
            expected_relay=self.relay, expected_relay_signer=self.relay_signer,
            expected_provider_public_key=self.provider_identity.public_key,
            expected_response_audience=self.audience, pricing=self.pricing,
        )
        options.update(overrides)
        return validate_provider_response(response, self.payment, **options)

    def resign_outer(self, response):
        return sign_document(
            {key: value for key, value in response.items() if key != "signature"},
            self.provider_identity.private_key, PROVIDER_RESPONSE_PURPOSE, audience=self.audience,
        )

    def test_real_signed_provider_response_is_accepted(self):
        result = self.check(self.seal())
        self.assertTrue(result.response_signature_verified)
        self.assertTrue(result.signer_identity_bound)
        self.assertEqual(result.receipt["input_tokens"], 1000)

    def test_structured_body_tamper_rejected_with_identical_text(self):
        result = self.seal()
        result["raw"]["output"][0]["arguments"] = '{"amount":1000000}'
        with self.assertRaisesRegex(RelayIntegrityError, "response_hash") as caught:
            self.check(self.resign_outer(result))
        self.assertTrue(caught.exception.response_signature_verified)
        self.assertIsNone(caught.exception.verified_provider_signer)
        self.assertFalse(caught.exception.signer_identity_bound)

    def test_transport_tamper_is_not_an_authenticated_provider_observation(self):
        result = self.seal()
        result["raw"]["output_text"] = "tampered"
        with self.assertRaises(RelayIntegrityError) as caught:
            self.check(result)
        self.assertFalse(caught.exception.response_signature_verified)

    def test_legacy_text_only_commitment_has_no_silent_downgrade(self):
        with self.assertRaisesRegex(RelayIntegrityError, "response_hash"):
            self.check(self.seal(legacy_hash=True))

    def test_usage_mismatch_rejected_even_with_valid_signatures(self):
        with self.assertRaisesRegex(RelayIntegrityError, "usage conflicts") as caught:
            self.check(self.seal(receipt_fields={"input_tokens": 1}))
        self.assertEqual(caught.exception.verified_provider_signer, self.provider_signer)
        self.assertTrue(caught.exception.signer_identity_bound)

    def test_cached_tokens_use_same_billable_units_as_provider(self):
        self.response["usage"]["input_tokens_details"] = {"cached_tokens": 900}
        self.response["raw"]["usage"] = copy.deepcopy(self.response["usage"])
        result = self.check(self.seal())
        self.assertEqual(result.receipt["input_tokens"], 100)

    def test_raw_usage_and_output_conflicts_rejected(self):
        for field, value, error in (("output_text", "different", "raw output"), ("usage", {"input_tokens": 1}, "raw usage")):
            with self.subTest(field=field):
                response = copy.deepcopy(self.response)
                response["raw"][field] = value
                with self.assertRaisesRegex(RelayIntegrityError, error):
                    self.check(self.seal(response))

    def test_signed_other_authorization_is_rejected(self):
        payment = copy.deepcopy(self.payment)
        # Generate another cryptographically valid authorization, not merely a
        # mutated invalid signature: this is the original replay/binding bug.
        fields = dict(payment["authorization"])
        fields.pop("key")
        fields["channel_hash"] = fields.pop("channel")
        fields["request_id"] = "0x" + "98" * 32
        other = build_authorization(
            payment_key="0x" + "01".rjust(64, "0"), chain_id=payment["chain_id"],
            settlement_contract=payment["settlement_contract"], **fields,
        )
        with self.assertRaisesRegex(RelayIntegrityError, "request_id"):
            self.check(self.seal(payment=other))

    def test_incomplete_authorization_never_bypasses_binding(self):
        with self.assertRaises(RelayIntegrityError):
            validate_authorization_binding({}, self.payment["authorization"])

    def test_payout_and_signer_are_bound_separately(self):
        with self.assertRaisesRegex(RelayIntegrityError, "payout"):
            self.check(self.seal(receipt_fields={"provider": "0x" + "78" * 20}))
        with self.assertRaisesRegex(RelayIntegrityError, "signer"):
            self.check(self.seal(), expected_provider_signer="0x" + "78" * 20)

    def test_fee_cannot_exceed_authorized_maximum(self):
        with self.assertRaisesRegex(RelayIntegrityError, "max_fee"):
            self.check(self.seal(receipt_fields={"actual_fee": 10001}))

    def test_fee_must_match_trusted_quote_when_configured(self):
        with self.assertRaisesRegex(RelayIntegrityError, "usage quote"):
            self.check(self.seal(receipt_fields={"actual_fee": 2201}))

    def test_provider_cannot_redirect_the_configured_pool_share(self):
        with self.assertRaisesRegex(RelayIntegrityError, "pool payout"):
            self.check(self.seal(receipt_fields={"pool": "0x" + "77" * 20}),
                       expected_pool="0x" + "00" * 20)

    def test_output_token_limit_is_enforced(self):
        with self.assertRaisesRegex(RelayIntegrityError, "output token limit"):
            self.check(self.seal(), request={**self.request, "max_output_tokens": 200})

    def test_boolean_and_conflicting_token_aliases_rejected(self):
        for usage in (
            {"input_tokens": True, "output_tokens": 300},
            {"input_tokens": 1000, "prompt_tokens": 1, "output_tokens": 300},
            {"input_tokens": 1000, "output_tokens": 300, "total_tokens": 1},
        ):
            with self.subTest(usage=usage):
                response = copy.deepcopy(self.response)
                response["usage"] = response["raw"]["usage"] = usage
                with self.assertRaises(RelayIntegrityError):
                    self.check(self.seal(response))

    def test_wrong_outer_audience_is_rejected(self):
        with self.assertRaisesRegex(RelayIntegrityError, "audience"):
            self.check(self.seal(), expected_response_audience="wrong-relay")

    def test_invalid_provider_signature_has_no_attributed_signer(self):
        result = self.seal()
        result["mycomesh_v8_settlement"]["provider_signature"] = "0x" + "00" * 65
        with self.assertRaises(RelayIntegrityError) as caught:
            self.check(self.resign_outer(result))
        self.assertIsNone(caught.exception.verified_provider_signer)
        self.assertTrue(caught.exception.response_signature_verified)

    def test_commitment_ignores_only_transport_metadata(self):
        altered = {**self.response, "elapsed_ms": 99, "signature": {"temporary": True}, "peer": {**self.response["peer"], "last_seen": 999}}
        self.assertEqual(provider_response_hash(self.response), provider_response_hash(altered))
        altered["model"] = "another-model"
        self.assertNotEqual(provider_response_hash(self.response), provider_response_hash(altered))

    def test_stolen_receipt_cannot_frame_its_evm_signer(self):
        response = self.seal()
        attacker = create_identity()
        response["peer"] = {"peer_id": attacker.peer_id, "public_key": attacker.public_key}
        response = sign_document(
            {key: value for key, value in response.items() if key != "signature"},
            attacker.private_key, PROVIDER_RESPONSE_PURPOSE, audience=self.audience,
        )
        with self.assertRaisesRegex(RelayIntegrityError, "response_hash") as caught:
            self.check(response, expected_provider_public_key=attacker.public_key)
        self.assertTrue(caught.exception.response_signature_verified)
        self.assertFalse(caught.exception.signer_identity_bound)
        self.assertIsNone(caught.exception.verified_provider_signer)

    def test_response_peer_identity_cannot_disagree_with_outer_signer(self):
        response = copy.deepcopy(self.response)
        response["peer"]["peer_id"] = create_identity().peer_id
        with self.assertRaisesRegex(RelayIntegrityError, "peer identity") as caught:
            self.check(self.seal(response))
        self.assertFalse(caught.exception.signer_identity_bound)

    def test_payment_expiry_is_not_classified_as_a_hard_contradiction(self):
        response = self.seal()
        later = int(time.time()) + 1000
        with patch("gateway.chain_v8.time.time", return_value=later):
            with self.assertRaises(RelayIntegrityError) as caught:
                self.check(response)
        self.assertEqual(caught.exception.code, "receipt_time_window")

    def test_bad_local_admission_context_is_not_provider_misconduct(self):
        with self.assertRaises(RelayIntegrityError) as caught:
            self.check(self.seal(), request={**self.request, "request_hash": "0x" + "ff" * 32})
        self.assertEqual(caught.exception.code, "admission_context_invalid")

    def test_chat_response_normalization(self):
        self.request["endpoint"] = "chat"
        self.response["endpoint"] = "chat"
        self.response["raw"] = {
            "choices": [{"message": {"content": "answer", "tool_calls": [{"arguments": "safe"}]}}],
            "usage": self.response["usage"],
        }
        self.check(self.seal())
        altered = self.seal()
        altered["raw"]["choices"][0]["message"]["tool_calls"][0]["arguments"] = "changed"
        with self.assertRaisesRegex(RelayIntegrityError, "response_hash"):
            self.check(self.resign_outer(altered))

    def test_v7_has_the_same_full_response_integrity_checks(self):
        from gateway.chain_v7 import build_authorization as build_v7_authorization
        from gateway.chain_v7 import build_provider_receipt as build_v7_receipt

        fields = dict(self.payment["authorization"])
        fields.pop("key")
        fields["channel_hash"] = fields.pop("channel")
        payment = build_v7_authorization(
            payment_key="0x" + "01".rjust(64, "0"), chain_id=self.request["chain_id"],
            settlement_contract=self.request["contract"], **fields,
        )
        response = copy.deepcopy(self.response)
        response["mycomesh_v7_settlement"] = build_v7_receipt(
            provider_private_key=self.provider_key, authorization_payload=payment,
            response_hash=provider_response_hash(response), relay=self.relay,
            input_tokens=1000, output_tokens=300, actual_fee=2200,
        )
        response = self.resign_outer(response)
        self.payment = payment
        result = self.check(response, settlement_version=7, expected_provider=self.provider_signer)
        self.assertTrue(result.signer_identity_bound)


if __name__ == "__main__":
    unittest.main()
