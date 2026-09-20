"""Real cryptographic Relay path; only RPC, outbox I/O and transport are fakes."""
from __future__ import annotations

import copy
import json
import queue
import sqlite3
import time
import unittest
from unittest.mock import Mock, patch

from gateway.chain import DEFAULT_CHANNEL_HASH, ZERO_ADDRESS, parse_private_key, private_key_to_address
from gateway import chain_v8
from gateway.identity import create_identity, sign_document, verify_document
from gateway.p2p import INFERENCE_REQUEST_PURPOSE
from gateway.provider_identity_binding import build_provider_identity_binding, verify_provider_identity_binding
from gateway.relay import (
    RelayError, RelayJob, RelayNotDispatchedError, RelayProviderSession, RelaySchedulingError, RelayState,
    _reserve_provider_load_locked, _signer_risk_key, _start_relay_job,
    _transition_provider_load, _v7_provider_candidates, relay_infer, relay_v7_openai,
)
from gateway.relay_integrity import (PROVIDER_RESPONSE_PURPOSE, provider_response_hash,
                                   RESPONSE_PROOF_SCHEMA, verify_response_proof, RelayIntegrityError)
from gateway.reservation import inference_request_hash


class RelaySecurityIntegrationTests(unittest.TestCase):
    version = 8
    protocol = chain_v8

    def setUp(self):
        self.provider_private = "0x" + "12".rjust(64, "0")
        self.relay_private = "0x" + "13".rjust(64, "0")
        self.key_private = "0x" + "14".rjust(64, "0")
        self.provider_signer = private_key_to_address(parse_private_key(self.provider_private))
        self.relay_signer = private_key_to_address(parse_private_key(self.relay_private))
        self.key_address = private_key_to_address(parse_private_key(self.key_private))
        self.provider_payout, self.relay_payout = "0x" + "ab" * 20, "0x" + "cd" * 20
        self.contract, self.pricing_hash = "0x" + "ef" * 20, "0x" + "56" * 32
        self.state = RelayState(
            settlement_version=self.version, payment_address=self.relay_payout,
            attestation_address=self.relay_signer,
            attestation_private_keys={self.relay_signer: self.relay_private},
            incident_store_path=":memory:",
        )
        self.addCleanup(self.state._incident_store.close)
        self.identity = create_identity()
        self.session = self.add_session(self.identity)
        self.body = {"model": "test-model", "input": "test prompt", "max_output_tokens": 500}
        request_hash = "0x" + inference_request_hash(
            endpoint="responses", model="test-model", input_value=self.body["input"],
            max_output_tokens=500, options={},
        )
        now = int(time.time())
        self.payment = self.protocol.build_authorization(
            payment_key=self.key_private, chain_id=11155111, settlement_contract=self.contract,
            request_id="0x" + "12" * 32, request_hash=request_hash,
            relay=self.relay_payout, relay_signer=self.relay_signer,
            channel_hash=DEFAULT_CHANNEL_HASH, pricing_version=1, pricing_hash=self.pricing_hash,
            max_fee=10000, issued_at=now, deadline=now + 900,
        )
        self.submitter = Mock(spec=["reserve_admission", "release_admission", "enqueue"])
        self.submitter.reserve_admission.return_value = "lease"
        self.submitter.enqueue.return_value = ("pending", True)
        self.state._settlement_submitter = self.submitter
        self.mode = "valid"
        self.last_response = None

    def add_session(self, identity):
        peer = {
            "peer_id": identity.peer_id, "public_key": identity.public_key,
            "model": "test-model", "models": ["test-model"], "channel": "codex-standard-v1",
            "payment_address": self.provider_payout, "challenge": "registration-challenge",
            "settlement": {"version": self.version, "chain_id": 11155111, "contract": self.contract,
                           "pricing_version": 1, "pricing_hash": self.pricing_hash,
                           "provider_signer": self.provider_signer},
        }
        audience = "test-relay:9801"
        peer["settlement_identity_binding"] = build_provider_identity_binding(
            peer, audience=audience, private_key=self.provider_private,
        )
        session = RelayProviderSession(
            peer_id=identity.peer_id, peer=peer,
            authenticated_signer=verify_provider_identity_binding(peer, audience=audience),
            registration_document=sign_document(
                peer, identity.private_key, "mycomesh.relay.provider.v1", audience=audience,
            ),
        )
        self.state.providers[session.peer_id] = session
        return session

    def transport(self, state, peer_id, message, **_kwargs):
        # Relay request signing, response verification, co-signing, calldata
        # encoding, and risk/evidence persistence are all real production code.
        verify_document(message, purpose=INFERENCE_REQUEST_PURPOSE, audience=peer_id)
        usage = {"input_tokens": 1000, "output_tokens": 300}
        response = {
            "type": "infer_result", "ok": True, "peer": copy.deepcopy(self.session.peer),
            "request_id": message["request_id"], "endpoint": message["endpoint"], "model": message["model"],
            "output_text": "answer", "usage": usage,
            "raw": {"output_text": "answer", "usage": copy.deepcopy(usage),
                    "output": [{"type": "function_call", "arguments": '{"amount":1}'}]},
        }
        payment = message[f"payment_v{self.version}"]
        if self.mode == "other_authorization":
            fields = dict(payment["authorization"])
            fields.pop("key")
            fields["channel_hash"] = fields.pop("channel")
            fields["request_id"] = "0x" + "99" * 32
            payment = self.protocol.build_authorization(
                payment_key=self.key_private, chain_id=11155111, settlement_contract=self.contract, **fields,
            )
        response[f"mycomesh_v{self.version}_settlement"] = self.protocol.build_provider_receipt(
            provider=self.provider_payout, provider_private_key=self.provider_private,
            authorization_payload=payment, response_hash=provider_response_hash(response),
            relay=self.relay_payout, input_tokens=1 if self.mode == "usage_mismatch" else 1000,
            output_tokens=300, actual_fee=2200,
        )
        if self.mode == "body_mismatch":
            response["raw"]["output"][0]["arguments"] = '{"amount":1000000}'
        response = sign_document(
            response, self.identity.private_key, PROVIDER_RESPONSE_PURPOSE,
            audience=state._scheduler_identity.public_key,
        )
        if self.mode == "transport_tamper":
            response["raw"]["output_text"] = "unsigned transport tamper"
        self.last_response = copy.deepcopy(response)
        return response

    def run_request(self, **kwargs):
        with (
            patch("gateway.relay.v8_key_grant" if self.version == 8 else "gateway.chain_v9.key_grant", return_value={"active": True, "owner": self.key_address, "max_per_request": 10000, "valid_until": 0}),
            patch("gateway.relay.v8_account_balance" if self.version == 8 else "gateway.chain_v9.account_balance", return_value=100000),
            patch("gateway.chain_v9.provider_stake_status", return_value={"stake": 100000, "locked": 0, "available": 100000}),
            patch("gateway.relay.relay_infer", side_effect=self.transport) as transport,
            patch("gateway.relay.finalize_v8_relay_receipt" if self.version == 8 else "gateway.chain_v9.finalize_relay_receipt", wraps=self.protocol.finalize_relay_receipt) as finalize,
        ):
            self.transport_mock, self.finalize_mock = transport, finalize
            return relay_v7_openai(self.state, "/v1/responses", self.body, self.payment, **kwargs)

    def incident(self):
        row = self.state._incident_store._db.execute("SELECT incident_id FROM incidents").fetchone()
        self.assertIsNotNone(row)
        return self.state._incident_store.get_incident(row["incident_id"])

    def assert_rejected_without_signing_or_queueing(self):
        self.finalize_mock.assert_not_called()
        self.submitter.enqueue.assert_not_called()
        self.submitter.release_admission.assert_called_once_with("lease")
        self.assertEqual(self.session.reserved_jobs + self.session.active_jobs + self.session.queued_jobs, 0)

    def test_valid_full_request_is_verified_signed_and_enqueued(self):
        output, envelope = self.run_request()
        self.assertTrue(envelope["accepted"])
        self.protocol.verify_signed_receipt(envelope["signed_receipt"])
        self.assertEqual(output, self.last_response["raw"], "Relay must not mutate the committed API body after validation")
        self.finalize_mock.assert_called_once()
        self.submitter.enqueue.assert_called_once()
        self.assertFalse(self.state._incident_store.is_quarantined(self.session.peer_id))

    def test_requested_content_proof_preserves_committed_body_and_not_header_payload(self):
        output, envelope = self.run_request(response_proof=True)
        self.protocol.verify_signed_receipt(envelope["signed_receipt"])
        self.assertEqual(output["schema"], RESPONSE_PROOF_SCHEMA)
        verified = verify_response_proof(output, envelope["signed_receipt"]["receipt"],
            request_id=self.payment["authorization"]["request_id"], endpoint="responses", model=self.body["model"])
        self.assertEqual(verified, self.last_response["raw"])
        self.assertNotIn("commitment_b64", json.dumps(envelope))

    def test_relay_cannot_substitute_body_under_an_unchanged_valid_receipt(self):
        output, envelope = self.run_request(response_proof=True)
        import base64
        value = json.loads(base64.b64decode(output["commitment_b64"]))
        value["raw"]["output"][0]["arguments"] = '{"amount":1000000}'
        output["commitment_b64"] = base64.b64encode(json.dumps(value).encode()).decode()
        self.protocol.verify_signed_receipt(envelope["signed_receipt"])
        with self.assertRaisesRegex(RelayIntegrityError, "signed commitment"):
            verify_response_proof(output, envelope["signed_receipt"]["receipt"],
                request_id=self.payment["authorization"]["request_id"], endpoint="responses", model=self.body["model"])

    def test_provider_signed_structured_body_mismatch_is_blocked_before_cosigning(self):
        self.mode = "body_mismatch"
        with self.assertRaisesRegex(RelaySchedulingError, "response_hash"):
            self.run_request()
        self.assert_rejected_without_signing_or_queueing()
        incident = self.incident()
        self.assertEqual(incident["evidence"]["provider_response"], self.last_response)
        self.assertEqual(incident["evidence"]["expected_authorization"], self.payment)
        self.assertFalse(incident["evidence"]["monetary_verdict"])
        self.assertTrue(self.state._incident_store.is_quarantined(self.session.peer_id))
        risk_key = _signer_risk_key(11155111, self.contract, self.provider_signer)
        self.assertTrue(self.state._incident_store.is_quarantined(risk_key))

    def test_valid_crypto_usage_contradiction_is_not_queued(self):
        self.mode = "usage_mismatch"
        with self.assertRaisesRegex(RelaySchedulingError, "usage conflicts"):
            self.run_request()
        self.assert_rejected_without_signing_or_queueing()

    def test_another_valid_consumer_authorization_is_not_queued(self):
        self.mode = "other_authorization"
        with self.assertRaisesRegex(RelaySchedulingError, "request_id"):
            self.run_request()
        self.assert_rejected_without_signing_or_queueing()

    def test_rotated_peer_with_same_authenticated_signer_stays_quarantined(self):
        self.mode = "usage_mismatch"
        with self.assertRaises(RelaySchedulingError):
            self.run_request()
        self.state.providers.clear()
        rotated = self.add_session(create_identity())
        self.assertNotEqual(rotated.peer_id, self.session.peer_id)
        self.assertEqual(_v7_provider_candidates(self.state), [])
        with self.assertRaisesRegex(RelayNotDispatchedError, "quarantined"):
            relay_infer(self.state, rotated.peer_id, {}, timeout=0.1)
        self.assertTrue(rotated.jobs.empty())

    def test_queued_job_is_rechecked_at_dispatch_callback(self):
        with self.state.lock:
            reservation = _reserve_provider_load_locked(self.state, self.session)
        _transition_provider_load(reservation, "queued")
        job = RelayJob("queued", {}, queue.Queue(), reservation)
        self.state._incident_store.record_observation(
            provider_id=self.session.peer_id, evidence_id="confirmed-before-dispatch", passed=False, hard_violation=True,
        )
        self.assertFalse(_start_relay_job(self.state, self.session, job))
        self.assertIsInstance(job.response_queue.get_nowait(), RelayNotDispatchedError)
        self.assertEqual(reservation.phase, "released")
        self.assertFalse(reservation.dispatched)

    def test_signature_tampering_does_not_poison_economic_identity(self):
        self.mode = "transport_tamper"
        with self.assertRaises(RelaySchedulingError):
            self.run_request()
        self.assert_rejected_without_signing_or_queueing()
        risk_key = _signer_risk_key(11155111, self.contract, self.provider_signer)
        self.assertFalse(self.state._incident_store.is_quarantined(risk_key))
        self.assertFalse(self.incident()["evidence"]["economic_identity_verified"])

    def test_evidence_write_failure_does_not_allow_another_dispatch(self):
        self.mode = "usage_mismatch"
        with patch.object(self.state._incident_store, "record_protocol_incident", side_effect=sqlite3.OperationalError("test disk unavailable")):
            with self.assertLogs("gateway.relay", level="ERROR"):
                with self.assertRaises(RelaySchedulingError):
                    self.run_request()
        self.assertTrue(self.state._risk_storage_failed)
        with self.assertRaisesRegex(RelayNotDispatchedError, "risk store"):
            relay_infer(self.state, self.session.peer_id, {}, timeout=0.1)

    def test_provider_cannot_choose_a_different_configured_settlement_deployment(self):
        # Model a configured deployment without starting its live worker.
        self.state.settlement_chain_id = 11155111
        self.state.settlement_contract = self.contract
        self.session.peer["settlement"]["contract"] = "0x" + "de" * 20
        self.assertEqual(_v7_provider_candidates(self.state), [])
        with self.assertRaises(RelayError):
            self.run_request()
        self.transport_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
