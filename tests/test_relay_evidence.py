from __future__ import annotations

import copy
import time
import unittest
from unittest.mock import patch

import tests.test_relay_security_integration as fixtures
from gateway.chain import ChainError
from gateway.chain_v8 import verify_provider_receipt
from gateway.identity import sign_document
from gateway.relay import RelaySchedulingError
from gateway.relay_evidence import OBSERVATION_PURPOSE, RelayEvidenceError, verify_relay_incident
from gateway.relay_incidents import evidence_hash


class RelayEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.rig = fixtures.RelaySecurityIntegrationTests()
        self.rig.setUp()
        self.addCleanup(self.rig.doCleanups)
        self.rig.mode = "usage_mismatch"
        self.observed_at = int(time.time())
        with self.assertRaises(RelaySchedulingError):
            self.rig.run_request()
        self.incident = self.rig.incident()

    def verify(self, incident=None, *, observed_at=None):
        return verify_relay_incident(
            incident or self.incident,
            expected_observer_public_key=self.rig.state._scheduler_identity.public_key,
            observed_at=self.observed_at if observed_at is None else observed_at,
        )

    def rehash(self, incident):
        incident["evidence_hash"] = evidence_hash(incident["evidence"])
        incident["record_hash"] = evidence_hash({key: incident[key] for key in (
            "provider_id", "provider_signer", "request_id", "request_hash", "kind", "severity", "evidence",
        )})
        return incident

    def observer_resign(self, incident):
        evidence = {key: value for key, value in incident["evidence"].items() if key != "signature"}
        incident["evidence"] = sign_document(
            evidence, self.rig.state._scheduler_identity.private_key, OBSERVATION_PURPOSE,
            audience=f'11155111:{self.rig.contract}',
            timestamp=evidence["expected_authorization"]["authorization"]["issued_at"],
            nonce=evidence_hash(evidence)[2:34],
        )
        return self.rehash(incident)

    def test_actual_stored_incident_reproduces_protocol_contradiction(self):
        verified = self.verify()
        self.assertEqual(verified["code"], "usage_receipt_mismatch")
        self.assertEqual(verified["classification"], "protocol_contradiction")
        self.assertEqual(verified["provider_signer"], self.rig.provider_signer)
        self.assertEqual(verified["reporter_authentication"], "ed25519_observer_signature")
        self.assertIs(verified["monetary_verdict"], False)
        self.assertIs(verified["model_identity_proven"], False)

    def test_historical_evidence_survives_authorization_expiry_without_changing_live_checks(self):
        later = self.observed_at + 10000
        receipt = self.rig.last_response["mycomesh_v8_settlement"]
        with patch("gateway.chain_v8.time.time", return_value=later):
            with self.assertRaisesRegex(ChainError, "outside its time window"):
                verify_provider_receipt(receipt)
            historical = verify_provider_receipt(receipt, now=self.observed_at)
            self.assertEqual(historical[1].input_tokens, 1)
            self.assertEqual(self.verify()["code"], "usage_receipt_mismatch")
        with self.assertRaises(RelayEvidenceError):
            self.verify(observed_at=later)

    def test_corrupted_evidence_and_rehashed_tampering_are_rejected(self):
        for rehash in (False, True):
            with self.subTest(rehash=rehash):
                incident = copy.deepcopy(self.incident)
                incident["evidence"]["provider_response"]["output_text"] = "fabricated"
                if rehash:
                    self.rehash(incident)
                with self.assertRaises(RelayEvidenceError):
                    self.verify(incident)

    def test_forged_victim_economic_alias_is_rejected_even_with_rehashed_record(self):
        incident = copy.deepcopy(self.incident)
        incident["provider_signer"] = "0x" + "98" * 20
        self.rehash(incident)
        with self.assertRaisesRegex(RelayEvidenceError, "economic alias"):
            self.verify(incident)

    def test_reporter_cannot_forge_provider_registration(self):
        incident = copy.deepcopy(self.incident)
        incident["evidence"]["provider_registration"]["settlement"]["provider_signer"] = "0x" + "98" * 20
        self.observer_resign(incident)
        with self.assertRaises(RelayEvidenceError):
            self.verify(incident)

    def test_legacy_unsigned_registration_is_unverifiable(self):
        incident = copy.deepcopy(self.incident)
        incident["evidence"]["provider_registration"].pop("signature")
        self.observer_resign(incident)
        with self.assertRaisesRegex(RelayEvidenceError, "signed Provider registration"):
            self.verify(incident)

    def test_claimed_error_must_match_reproduced_error(self):
        incident = copy.deepcopy(self.incident)
        incident["evidence"]["code"] = "fee_limit"
        incident["kind"] = "protocol:fee_limit"
        self.observer_resign(incident)
        with self.assertRaisesRegex(RelayEvidenceError, "did not reproduce"):
            self.verify(incident)

    def test_untrusted_created_at_is_not_used_as_the_verification_clock(self):
        incident = copy.deepcopy(self.incident)
        incident["created_at"] = 0
        self.assertEqual(self.verify(incident)["observed_at"], self.observed_at)
        with self.assertRaises(TypeError):
            verify_relay_incident(incident, expected_observer_public_key=self.rig.state._scheduler_identity.public_key)

    def test_wrong_pinned_observer_and_invalid_trusted_time_are_rejected(self):
        with self.assertRaisesRegex(RelayEvidenceError, "pinned observer"):
            verify_relay_incident(self.incident, expected_observer_public_key="a" * 64, observed_at=self.observed_at)
        for value in (True, -1, str(self.observed_at)):
            with self.subTest(value=value), self.assertRaises(RelayEvidenceError):
                self.verify(observed_at=value)

    def test_different_dispatched_authorization_remains_a_contextual_allegation(self):
        rig = fixtures.RelaySecurityIntegrationTests()
        rig.setUp()
        self.addCleanup(rig.doCleanups)
        rig.mode = "other_authorization"
        observed_at = int(time.time())
        with self.assertRaises(RelaySchedulingError):
            rig.run_request()
        verified = verify_relay_incident(
            rig.incident(), expected_observer_public_key=rig.state._scheduler_identity.public_key,
            observed_at=observed_at,
        )
        self.assertEqual(verified["classification"], "contextual_allegation")
        self.assertIs(verified["monetary_verdict"], False)

    def test_valid_decimal_string_issued_at_replays_using_verified_canonical_anchor(self):
        rig = fixtures.RelaySecurityIntegrationTests()
        rig.setUp()
        self.addCleanup(rig.doCleanups)
        rig.mode = "usage_mismatch"
        rig.payment["authorization"]["issued_at"] = str(rig.payment["authorization"]["issued_at"])
        observed_at = int(time.time())
        with self.assertRaisesRegex(RelaySchedulingError, "usage conflicts"):
            rig.run_request()
        incident = rig.incident()
        self.assertIsInstance(incident["evidence"]["expected_authorization"]["authorization"]["issued_at"], str)
        self.assertIsInstance(incident["evidence"]["signature"]["timestamp"], int)
        verified = verify_relay_incident(
            incident, expected_observer_public_key=rig.state._scheduler_identity.public_key,
            observed_at=observed_at,
        )
        self.assertEqual(verified["code"], "usage_receipt_mismatch")
        self.assertEqual(verified["classification"], "protocol_contradiction")
