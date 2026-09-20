import queue
import sqlite3
import unittest
from unittest.mock import Mock, patch

from gateway.identity import create_identity, sign_document
from gateway.provider_identity_binding import build_provider_identity_binding, verify_provider_identity_binding
from gateway.relay import (RELAY_PROVIDER_REGISTRATION_PURPOSE, RelayError,
                           RelayJob, RelayNotDispatchedError, RelayProviderSession,
                           _provider_risk_keys, _signer_risk_key, _start_relay_job,
                           _v7_provider_candidates, relay_infer, serve_relay, verify_relay_provider_peer)
from gateway.relay_incidents import RelayIncidentStore
from tests.test_relay_scheduler import make_state, make_request, assign, CONTRACT, SIGNERS
from tests.test_chain_v8 import PROVIDER_KEY, address


class RelayQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.state = make_state()
        self.store = RelayIncidentStore(":memory:")
        self.state._incident_store = self.store

    def tearDown(self):
        self.store.close()

    def quarantine(self, key="peer-a"):
        self.store.record_observation(provider_id=key, evidence_id="hard-proof", passed=False, hard_violation=True)

    def test_direct_peer_inference_rejected_before_enqueue(self):
        self.quarantine()
        with self.assertRaises(RelayNotDispatchedError):
            relay_infer(self.state, "peer-a", {}, 0.1)
        self.assertTrue(self.state.providers["peer-a"].jobs.empty())

    def test_queued_job_rechecks_risk_and_releases_load(self):
        reservation = assign(self.state, make_request())
        job = RelayJob("job", {}, queue.Queue(), reservation)
        self.quarantine(reservation.provider.peer_id)
        self.assertFalse(_start_relay_job(self.state, reservation.provider, job))
        self.assertEqual(reservation.phase, "released")
        self.assertIsInstance(job.response_queue.get_nowait(), RelayNotDispatchedError)

    def test_rotating_peer_does_not_escape_verified_signer_risk(self):
        key = _signer_risk_key(11155111, CONTRACT, SIGNERS["peer-a"])
        self.quarantine(key)
        original = self.state.providers["peer-a"]
        self.state.providers["rotated"] = RelayProviderSession(
            "rotated", {**original.peer, "peer_id": "rotated"})
        self.assertEqual([p.peer_id for p in _v7_provider_candidates(self.state)], ["peer-b"])

    def test_database_failure_blocks_new_dispatch(self):
        self.state._incident_store = Mock()
        self.state._incident_store.is_quarantined.side_effect = sqlite3.OperationalError("unavailable")
        with self.assertLogs("gateway.relay", level="ERROR"):
            with self.assertRaises(RelayNotDispatchedError):
                relay_infer(self.state, "peer-a", {}, 0.1)
        self.assertTrue(self.state._risk_storage_failed)
        self.assertTrue(self.state.providers["peer-a"].jobs.empty())

    def test_v7_payout_signer_and_authenticated_signer_remain_risk_scopes(self):
        original = self.state.providers["peer-a"]
        signer = SIGNERS["peer-a"]
        peer = {**original.peer, "payment_address": signer,
                "settlement": {"version": 7, "chain_id": 11155111, "contract": CONTRACT}}
        session = RelayProviderSession("rotated", peer)
        alias = _signer_risk_key(11155111, CONTRACT, signer)
        self.assertIn(alias, _provider_risk_keys(session))
        session.authenticated_signer = signer
        session.peer = {**peer, "payment_address": SIGNERS["peer-b"]}
        self.assertIn(alias, _provider_risk_keys(session))

    def test_changed_deployment_cannot_hide_signer_quarantine_from_direct_inference(self):
        signer = SIGNERS["peer-a"]
        self.quarantine(_signer_risk_key(11155111, CONTRACT, signer))
        original = self.state.providers["peer-a"]
        peer = {**original.peer, "peer_id": "rotated",
                "settlement": {**original.peer["settlement"], "chain_id": 1, "contract": "0x" + "ab" * 20}}
        session = RelayProviderSession("rotated", peer, authenticated_signer=signer)
        self.state.providers["rotated"] = session
        with self.assertRaises(RelayNotDispatchedError):
            relay_infer(self.state, "rotated", {}, 0.1)
        self.assertTrue(session.jobs.empty())

    def test_soft_suspect_remains_schedulable(self):
        for n in range(10):
            self.store.record_observation(provider_id="peer-a", evidence_id=str(n), passed=False)
        self.assertEqual(self.store.risk_snapshot("peer-a")["status"], "suspect")
        self.assertIn("peer-a", [p.peer_id for p in _v7_provider_candidates(self.state)])

    def test_identity_proof_binds_peer_challenge_and_domain(self):
        identity = create_identity()
        peer = {"peer_id": identity.peer_id, "public_key": identity.public_key,
                "challenge": "fresh-registration-challenge", "payment_address": "0x" + "99" * 20,
                "settlement": {"version": 8, "chain_id": 11155111, "contract": CONTRACT,
                               "provider_signer": address(PROVIDER_KEY)}}
        peer["settlement_identity_binding"] = build_provider_identity_binding(
            peer, audience="relay-a", private_key=PROVIDER_KEY)
        self.assertEqual(verify_provider_identity_binding(peer, audience="relay-a"), address(PROVIDER_KEY))
        for changed in ({**peer, "challenge": "other"},
                        {**peer, "settlement": {**peer["settlement"], "chain_id": 1}}):
            with self.assertRaises(ValueError):
                verify_provider_identity_binding(changed, audience="relay-a")
        with self.assertRaises(ValueError):
            verify_provider_identity_binding(peer, audience="relay-b")

    def test_registration_cannot_claim_another_transport_public_key(self):
        attacker, victim = create_identity(), create_identity()
        registration = sign_document(
            {"peer_id": victim.peer_id, "public_key": victim.public_key},
            attacker.private_key, purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE,
            audience="relay-a")
        with self.assertRaisesRegex(RelayError, "does not match registration signer"):
            verify_relay_provider_peer(registration, audience="relay-a")

    def test_relay_shutdown_drains_probes_before_stopping_settlement(self):
        events = []
        runtime = Mock()
        runtime.coordinator.timeout_seconds = 20.0
        runtime.stop.side_effect = lambda: events.append("probe_stop")
        runtime.drain.side_effect = lambda **kwargs: events.append("probe_drain") or True
        runtime.close.side_effect = lambda: events.append("probe_close")
        self.state._settlement_submitter = Mock()
        self.state._settlement_submitter.stop.side_effect = lambda: events.append("submitter_stop")
        with patch("gateway.relay.RelayState", return_value=self.state), \
                patch("gateway.relay.RelayProviderTCPServer"), \
                patch("gateway.relay.RelayControlHTTPServer") as control, \
                patch("gateway.relay.threading.Thread"), \
                patch("gateway.relay_probe_runtime.create_relay_probe_runtime", return_value=runtime):
            control.return_value.serve_forever.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                serve_relay("127.0.0.1")
        self.assertEqual(events, ["probe_stop", "probe_drain", "probe_close", "submitter_stop"])
        runtime.drain.assert_called_once_with(timeout_seconds=21.0)


if __name__ == "__main__":
    unittest.main()
