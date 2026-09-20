from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gateway import relay
from gateway import chain_v8
from gateway.chain_v8 import payment_key_address
from gateway.identity import create_identity, sign_document
from gateway.relay_incidents import RelayIncidentStore
from gateway.relay_integrity import PROVIDER_RESPONSE_PURPOSE, provider_response_hash
from gateway.relay_probe import RelayProbeError, RelayProbeStore, VerifiedProbeResponse, probe_digest
from gateway.relay_probe_runtime import (
    ProbeBudgetStore, RelayProbeRuntimeError, create_relay_probe_runtime,
)


SPONSOR = "0x" + "01".rjust(64, "0")
PROVIDER = "0x" + "02".rjust(64, "0")
RELAY = "0x" + "03".rjust(64, "0")
RELAYER = "0x" + "04".rjust(64, "0")


class RelayProbeRuntimeTests(unittest.TestCase):
    version = 8
    protocol = chain_v8

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.key_file = root / "probe-key"
        self.key_file.write_text(SPONSOR, encoding="ascii")
        self.key_file.chmod(0o600)
        self.provider_identity, self.relay_identity = create_identity(), create_identity()
        peer = {
            "peer_id": self.provider_identity.peer_id, "public_key": self.provider_identity.public_key,
            "payment_address": "0x" + "99" * 20, "model": "gpt-5.4", "models": ["gpt-5.4"], "channel": "codex",
            "settlement": {"version": self.version, "chain_id": 123, "contract": "0x" + "11" * 20,
                           "pricing_version": 1, "pricing_hash": "0x" + "88" * 32,
                           "provider_signer": payment_key_address(PROVIDER)},
        }
        self.session = relay.RelayProviderSession(peer_id=self.provider_identity.peer_id, peer=peer)
        incidents = RelayIncidentStore(str(root / "incidents.sqlite3"))
        probes = RelayProbeStore(str(root / "probes.sqlite3"))
        self.addCleanup(incidents.close)
        self.addCleanup(probes.close)
        self.state = SimpleNamespace(
            settlement_version=self.version, settlement_chain_id=123, settlement_contract="0x" + "11" * 20,
            _settlement_submitter=SimpleNamespace(address=payment_key_address(RELAYER)),
            settlement_private_key=None, payment_address="0x" + "55" * 20,
            attestation_address=payment_key_address(RELAY), attestation_private_keys={payment_key_address(RELAY): RELAY},
            _probe_store=probes, _incident_store=incidents, _scheduler_identity=self.relay_identity,
            providers={self.session.peer_id: self.session}, lock=threading.RLock(),
            _risk_lock=threading.RLock(), _risk_storage_failed=False, _emergency_quarantine=set(), _provider_affinity={},
        )
        self.env = {
            "MYCOMESH_RELAY_PROBES_ENABLED": "true", "MYCOMESH_RELAY_PROBE_SPONSOR_KEY_FILE": str(self.key_file),
            "MYCOMESH_RELAY_PROBE_MAX_FEE_UNITS": "100", "MYCOMESH_RELAY_PROBE_DAILY_BUDGET_UNITS": "200",
        }

    def runtime(self, **environment):
        worker = create_relay_probe_runtime(self.state, {**self.env, **environment})
        self.addCleanup(worker.close)
        return worker

    def envelope(self, nonce="a" * 48):
        return {"probe_class": "json_arithmetic_v1", "nonce": nonce, "input": "Return JSON only " + nonce,
                "max_output_tokens": 96}

    def normal_response(self, state, path, body, payment, **kwargs):
        request = relay._v7_normalize_request(state, path, body, payment=payment)
        prompt = body["input"]
        match = re.search(r'"nonce" equal to "([0-9a-f]+)" and "sum" equal to (\d+) \+ (\d+)', prompt)
        output_text = json.dumps({"nonce": match[1], "sum": int(match[2]) + int(match[3])}) if match else '{"test":true}'
        usage = {"input_tokens": 4, "output_tokens": 4}
        raw = {"output_text": output_text, "usage": usage}
        response = {
            "ok": True, "request_id": request["request_id"], "model": request["model"], "endpoint": "responses",
            "peer": {"peer_id": self.provider_identity.peer_id, "public_key": self.provider_identity.public_key},
            "output_text": output_text, "usage": usage, "raw": raw,
        }
        provider = self.protocol.build_provider_receipt(
            provider=self.session.peer["payment_address"], provider_private_key=PROVIDER,
            authorization_payload=payment, response_hash=provider_response_hash(response), relay=state.payment_address,
            input_tokens=4, output_tokens=4, actual_fee=1,
        )
        response[f"mycomesh_v{self.version}_settlement"] = provider
        response = sign_document(response, self.provider_identity.private_key, purpose=PROVIDER_RESPONSE_PURPOSE,
                                 audience=self.relay_identity.public_key)
        receipt = self.protocol.finalize_relay_receipt(provider, relay_private_key=RELAY)
        return raw, {"signed_receipt": receipt, "audit_provider_response": response,
                     "audit_provider_id": kwargs["audit_provider_id"]}

    def test_disabled_never_reads_sponsor_or_touches_state(self):
        with patch("gateway.relay_probe_runtime.os.open", side_effect=AssertionError("must not open")):
            self.assertIsNone(create_relay_probe_runtime(object(), {}))
            self.assertIsNone(create_relay_probe_runtime(object(), {"MYCOMESH_RELAY_PROBES_ENABLED": "false"}))

    def test_configuration_requires_v8_durable_stores_submitter_and_explicit_budgets(self):
        for field, value in (("settlement_version", 7), ("_settlement_submitter", None),
                             ("_incident_store", SimpleNamespace(path=":memory:")), ("_probe_store", None)):
            with self.subTest(field=field), patch.object(self.state, field, value), self.assertRaises(RelayProbeRuntimeError):
                create_relay_probe_runtime(self.state, self.env)
        for change in ({"MYCOMESH_RELAY_PROBE_MAX_FEE_UNITS": "0"}, {"MYCOMESH_RELAY_PROBE_DAILY_BUDGET_UNITS": "99"},
                       {"MYCOMESH_RELAY_PROBE_MAX_FEE_UNITS": "1.0"}, {"MYCOMESH_RELAY_PROBE_MAX_FEE_UNITS": ""}):
            with self.subTest(change=change), self.assertRaises(RelayProbeRuntimeError):
                create_relay_probe_runtime(self.state, {**self.env, **change})

    def test_key_file_permissions_and_symlinks_rejected(self):
        self.key_file.chmod(0o644)
        with self.assertRaises(RelayProbeRuntimeError):
            create_relay_probe_runtime(self.state, self.env)
        self.key_file.chmod(0o600)
        link = self.key_file.with_name("linked-key")
        link.symlink_to(self.key_file)
        with self.assertRaises(RelayProbeRuntimeError):
            create_relay_probe_runtime(self.state, {**self.env, "MYCOMESH_RELAY_PROBE_SPONSOR_KEY_FILE": str(link)})

    def test_payout_attestation_or_relayer_key_reuse_is_rejected(self):
        for key in (RELAY, RELAYER):
            self.key_file.write_text(key, encoding="ascii")
            with self.subTest(key=payment_key_address(key)), self.assertRaisesRegex(RelayProbeRuntimeError, "must not reuse"):
                create_relay_probe_runtime(self.state, self.env)
        self.key_file.write_text(SPONSOR, encoding="ascii")
        with patch.object(self.state, "payment_address", payment_key_address(SPONSOR)), self.assertRaises(RelayProbeRuntimeError):
            create_relay_probe_runtime(self.state, self.env)

    def test_constructor_makes_no_chain_or_provider_calls(self):
        with patch("gateway.relay.relay_v7_openai", side_effect=AssertionError("no inference")), \
                patch("gateway.relay.v8_key_grant", side_effect=AssertionError("no RPC")):
            worker = self.runtime()
            self.assertEqual(worker.budget.reserved_units(worker.scope), 0)

    def test_dispatch_uses_real_normal_path_selected_peer_and_max_fee_reservation(self):
        worker = self.runtime()
        def execute(*args, **kwargs):
            self.assertEqual(worker.budget.reserved_units(worker.scope), 100)
            self.assertEqual(kwargs["audit_provider_id"], self.session.peer_id)
            self.assertEqual(args[3]["authorization"]["max_fee"], 100)
            self.assertEqual(args[3]["authorization"]["key"], payment_key_address(SPONSOR))
            self.assertEqual(args[2]["metadata"]["mycomesh_provider_signer"], payment_key_address(PROVIDER))
            return self.normal_response(*args, **kwargs)
        with patch("gateway.relay.relay_v7_openai", side_effect=execute) as dispatch:
            result = worker.dispatch(self.session.peer_id, self.envelope(), 10)
        self.assertIsInstance(result, VerifiedProbeResponse)
        self.assertEqual(result.output_text, '{"test":true}')
        self.assertEqual(dispatch.call_count, 1)
        stored = worker.budget.get_receipt(result.receipt_hash)
        self.assertEqual(stored["provider_id"], self.session.peer_id)
        self.assertIn("signature", stored["provider_response"])
        self.assertIn("signed_receipt", stored)
        self.assertNotIn(SPONSOR, json.dumps(stored))

    def test_duplicate_request_cannot_dispatch_again_even_after_restart(self):
        worker = self.runtime()
        with patch("gateway.relay.relay_v7_openai", side_effect=self.normal_response) as dispatch:
            worker.dispatch(self.session.peer_id, self.envelope(), 10)
            worker.close()
            restarted = self.runtime()
            with self.assertRaisesRegex(RelayProbeRuntimeError, "already reserved"):
                restarted.dispatch(self.session.peer_id, self.envelope(), 10)
            self.assertEqual(dispatch.call_count, 1)
            self.assertEqual(restarted.budget.reserved_units(restarted.scope), 100)

    def test_uncertain_failure_retains_full_budget_and_next_request_hits_cap(self):
        worker = self.runtime(MYCOMESH_RELAY_PROBE_DAILY_BUDGET_UNITS="100")
        with patch("gateway.relay.relay_v7_openai", side_effect=TimeoutError("uncertain")) as dispatch:
            with self.assertRaises(TimeoutError):
                worker.dispatch(self.session.peer_id, self.envelope("first"), 10)
            with self.assertRaisesRegex(RelayProbeRuntimeError, "budget exhausted"):
                worker.dispatch(self.session.peer_id, self.envelope("second"), 10)
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(worker.budget.reserved_units(worker.scope), 100)
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["evidence_count"], 0)

    def test_missing_or_wrong_selected_peer_proof_is_inconclusive(self):
        worker = self.runtime()
        with patch("gateway.relay.relay_v7_openai", return_value=({}, {})):
            with self.assertRaisesRegex(RelayProbeRuntimeError, "selected Provider proof"):
                worker.dispatch(self.session.peer_id, self.envelope(), 10)
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["evidence_count"], 0)

    def test_signed_body_tampering_cannot_create_verified_probe_response(self):
        worker = self.runtime()
        def altered(*args, **kwargs):
            raw, receipt = self.normal_response(*args, **kwargs)
            receipt["audit_provider_response"]["output_text"] = "tampered"
            return raw, receipt
        with patch("gateway.relay.relay_v7_openai", side_effect=altered), self.assertRaises(ValueError):
            worker.dispatch(self.session.peer_id, self.envelope(), 10)

    def test_risk_callbacks_only_use_verified_pass_or_capability_mismatch(self):
        worker = self.runtime(MYCOMESH_RELAY_PROBE_DAILY_BUDGET_UNITS="1000")
        for outcome in ("timeout", "dispatch_error", "unverified_response", "result_not_persisted"):
            worker.observe({"provider_id": self.session.peer_id, "outcome": outcome, "passed": False})
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["evidence_count"], 0)
        for index in range(8):
            envelope = self.envelope(f"{index:048x}")
            with patch("gateway.relay.relay_v7_openai", side_effect=self.normal_response):
                response = worker.dispatch(self.session.peer_id, envelope, 10)
            probe = self.state._probe_store.issue(provider_id=self.session.peer_id, probe_class="json_arithmetic_v1",
                request_hash=probe_digest(envelope), nonce=envelope["nonce"], request=envelope)
            evidence = {"receipt_hash": response.receipt_hash, "outcome": "capability_mismatch"}
            digest = probe_digest(evidence)
            self.state._probe_store.record_result(probe_id=probe["probe_id"], nonce=probe["nonce"],
                provider_id=self.session.peer_id, passed=False, result_hash=digest, evidence=evidence)
            observation = {"probe_id": probe["probe_id"], "provider_id": self.session.peer_id,
                           "outcome": "capability_mismatch", "passed": False, "result_hash": digest, "evidence": evidence}
            worker.observe(observation)
            worker.observe(observation)  # Exact replay cannot add a second failure.
            with self.assertRaises(RelayProbeRuntimeError):
                worker.observe({**observation, "result_hash": "alternate-replay"})
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["status"], "suspect")
        alias = relay._signer_risk_key(123, self.state.settlement_contract, payment_key_address(PROVIDER))
        self.assertEqual(self.state._incident_store.risk_snapshot(alias)["status"], "suspect")
        self.assertFalse(self.state._incident_store.is_quarantined(self.session.peer_id))

    def test_forged_or_inconsistent_observation_has_no_risk_effect(self):
        worker = self.runtime()
        for observation in ({"outcome": "passed", "passed": False},
                            {"outcome": "passed", "passed": True, "provider_id": self.session.peer_id,
                             "result_hash": "fake", "evidence": {"receipt_hash": "unknown"}}):
            with self.assertRaises(RelayProbeError):
                worker.observe(observation)
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["evidence_count"], 0)

    def test_supplier_has_no_rpc_and_quarantined_peer_cannot_dispatch(self):
        worker = self.runtime()
        with patch("gateway.relay.v8_key_grant", side_effect=AssertionError("no RPC")):
            self.assertEqual(worker.provider_ids(), [self.session.peer_id])
            self.state._incident_store.record_observation(provider_id=self.session.peer_id, evidence_id="hard",
                                                         passed=False, hard_violation=True)
            self.assertEqual(worker.provider_ids(), [])
        with patch("gateway.relay.relay_v7_openai") as dispatch, self.assertRaises(RelayProbeRuntimeError):
            worker.dispatch(self.session.peer_id, self.envelope(), 10)
        dispatch.assert_not_called()

    def test_stop_prevents_dispatch_and_worker_returns(self):
        worker = self.runtime()
        worker.stop()
        worker.run()
        with patch("gateway.relay.relay_v7_openai") as dispatch, self.assertRaisesRegex(RelayProbeRuntimeError, "stopped"):
            worker.dispatch(self.session.peer_id, self.envelope(), 10)
        dispatch.assert_not_called()

    def test_coordinator_to_normal_path_to_verified_receipt_and_soft_observation(self):
        worker = self.runtime()
        with patch("gateway.relay.relay_v7_openai", side_effect=self.normal_response) as dispatch:
            worker.coordinator.tick(worker.provider_ids())
            task = next(iter(worker.coordinator._tasks.values()))
            completed = task.finished.get(timeout=5)
            task.finished.put_nowait(completed)
            observations = worker.coordinator.tick([])
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(observations[0]["outcome"], "passed")
        self.assertTrue(observations[0]["observation_delivered"])
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["evidence_count"], 1)
        self.assertEqual(worker.budget.reserved_units(worker.scope), 100)

    def test_stop_then_drain_finishes_existing_probe_without_starting_another(self):
        worker = self.runtime()
        started, release = threading.Event(), threading.Event()

        def delayed(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(timeout=5))
            return self.normal_response(*args, **kwargs)

        with patch("gateway.relay.relay_v7_openai", side_effect=delayed) as dispatch:
            worker.coordinator.tick(worker.provider_ids())
            self.assertTrue(started.wait(timeout=2))
            worker.stop()
            release.set()
            self.assertTrue(worker.drain(timeout_seconds=2))
            self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(worker.coordinator.inflight_count, 0)
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["evidence_count"], 1)
        self.assertEqual(worker.budget.reserved_units(worker.scope), 100)

    def test_hung_dispatch_drain_is_bounded_and_does_not_close_budget(self):
        worker = self.runtime()
        started, release = threading.Event(), threading.Event()

        def delayed(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(timeout=5))
            return self.normal_response(*args, **kwargs)

        with patch("gateway.relay.relay_v7_openai", side_effect=delayed) as dispatch:
            worker.coordinator.tick(worker.provider_ids())
            self.assertTrue(started.wait(timeout=2))
            worker.stop()
            before = time.monotonic()
            try:
                self.assertFalse(worker.drain(timeout_seconds=0.03))
                self.assertLess(time.monotonic() - before, 0.3)
                self.assertEqual(dispatch.call_count, 1)
                self.assertEqual(worker.budget.reserved_units(worker.scope), 100)
                with self.assertRaisesRegex(RelayProbeRuntimeError, "in flight"):
                    worker.close()
            finally:
                release.set()
                if worker._drain_thread is not None:
                    worker._drain_thread.join(timeout=1)
            self.assertTrue(worker.drain(timeout_seconds=2))
            self.assertEqual(dispatch.call_count, 1)

    def test_blocked_result_persistence_does_not_break_drain_deadline(self):
        worker = self.runtime()
        worker.stop()
        entered, release = threading.Event(), threading.Event()
        original_tick = worker.coordinator.tick

        def blocked_tick(providers):
            self.assertEqual(tuple(providers), ())
            entered.set()
            self.assertTrue(release.wait(timeout=5))
            return original_tick(providers)

        with patch.object(worker.coordinator, "tick", side_effect=blocked_tick) as tick:
            before = time.monotonic()
            try:
                self.assertFalse(worker.drain(timeout_seconds=0.03))
                self.assertTrue(entered.is_set())
                self.assertLess(time.monotonic() - before, 0.3)
                first_poller = worker._drain_thread
                self.assertFalse(worker.drain(timeout_seconds=0.03))
                self.assertIs(worker._drain_thread, first_poller)
                self.assertEqual(tick.call_count, 1)
                with self.assertRaisesRegex(RelayProbeRuntimeError, "result collection"):
                    worker.close()
            finally:
                release.set()
                worker._drain_thread.join(timeout=2)
        self.assertTrue(worker.drain(timeout_seconds=1))
        self.assertEqual(worker.budget.reserved_units(worker.scope), 0)

    def test_drain_requires_stop_and_a_finite_positive_timeout(self):
        worker = self.runtime()
        with self.assertRaisesRegex(RelayProbeRuntimeError, "before draining"):
            worker.drain(1)
        worker.stop()
        for timeout in (0, -1, True, float("nan"), float("inf"), "1"):
            with self.subTest(timeout=timeout), self.assertRaises(RelayProbeRuntimeError):
                worker.drain(timeout)
        with patch("gateway.relay.relay_v7_openai") as dispatch:
            self.assertTrue(worker.drain(1))
        dispatch.assert_not_called()

    def test_stop_does_not_wait_for_tick_lock_during_result_persistence(self):
        worker = self.runtime()
        entered, release = threading.Event(), threading.Event()
        original_record = worker.coordinator.store.record_result

        def blocked_record(**kwargs):
            entered.set()
            self.assertTrue(release.wait(timeout=5))
            return original_record(**kwargs)

        with patch("gateway.relay.relay_v7_openai", side_effect=self.normal_response) as dispatch:
            worker.coordinator.tick(worker.provider_ids())
            task = next(iter(worker.coordinator._tasks.values()))
            task.finished.put_nowait(task.finished.get(timeout=5))
            with patch.object(worker.coordinator.store, "record_result", side_effect=blocked_record):
                finisher = threading.Thread(target=worker.coordinator.tick, args=((),), daemon=True)
                finisher.start()
                self.assertTrue(entered.wait(timeout=2))
                try:
                    before = time.monotonic()
                    worker.stop()
                    self.assertLess(time.monotonic() - before, 0.3)
                    self.assertFalse(worker.drain(0.03))
                    self.assertEqual(dispatch.call_count, 1)
                finally:
                    release.set()
                    finisher.join(timeout=2)
                    if worker._drain_thread is not None:
                        worker._drain_thread.join(timeout=2)
            self.assertTrue(worker.drain(1))
            self.assertEqual(dispatch.call_count, 1)

    def test_stop_during_challenge_write_does_not_start_dispatch(self):
        worker = self.runtime()
        entered, release = threading.Event(), threading.Event()
        original_issue = worker.coordinator.store.issue

        def blocked_issue(**kwargs):
            entered.set()
            self.assertTrue(release.wait(timeout=5))
            return original_issue(**kwargs)

        with patch.object(worker.coordinator.store, "issue", side_effect=blocked_issue), \
                patch("gateway.relay.relay_v7_openai") as dispatch:
            starter = threading.Thread(target=worker.coordinator.tick, args=([self.session.peer_id],), daemon=True)
            starter.start()
            self.assertTrue(entered.wait(timeout=2))
            try:
                before = time.monotonic()
                worker.stop()
                self.assertLess(time.monotonic() - before, 0.3)
            finally:
                release.set()
                starter.join(timeout=2)
            self.assertTrue(worker.drain(1))
        dispatch.assert_not_called()
        self.assertEqual(worker.budget.reserved_units(worker.scope), 0)
        self.assertEqual(self.state._incident_store.risk_snapshot(self.session.peer_id)["evidence_count"], 0)


class ProbeBudgetStoreTests(unittest.TestCase):
    def test_persistence_scope_and_utc_day_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "budget.sqlite3")
            store = ProbeBudgetStore(path)
            store.reserve(scope="a:1:contract", request_hash="first", max_fee_units=60, daily_budget_units=100, now=100)
            store.close()
            store = ProbeBudgetStore(path)
            self.addCleanup(store.close)
            with self.assertRaisesRegex(RelayProbeRuntimeError, "exhausted"):
                store.reserve(scope="a:1:contract", request_hash="second", max_fee_units=60, daily_budget_units=100, now=101)
            store.reserve(scope="different:1:contract", request_hash="second", max_fee_units=60, daily_budget_units=100, now=101)
            store.reserve(scope="a:1:contract", request_hash="third", max_fee_units=60, daily_budget_units=100, now=86_401)
            with self.assertRaisesRegex(RelayProbeRuntimeError, "already reserved"):
                store.reserve(scope="a:1:contract", request_hash="first", max_fee_units=60, daily_budget_units=100, now=86_401)

    def test_concurrent_connections_cannot_overreserve(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "budget.sqlite3")
            first, second = ProbeBudgetStore(path), ProbeBudgetStore(path)
            self.addCleanup(first.close)
            self.addCleanup(second.close)
            barrier = threading.Barrier(2)
            def reserve(store, request_hash):
                barrier.wait(timeout=5)
                try:
                    store.reserve(scope="same", request_hash=request_hash, max_fee_units=60, daily_budget_units=100, now=100)
                    return True
                except RelayProbeRuntimeError:
                    return False
            with ThreadPoolExecutor(max_workers=2) as workers:
                futures = [workers.submit(reserve, first, "first"), workers.submit(reserve, second, "second")]
                self.assertEqual(sum(future.result(timeout=10) for future in futures), 1)
            self.assertEqual(first.reserved_units("same", now=100), 60)

    def test_receipt_requires_reservation_and_conflicts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProbeBudgetStore(str(Path(directory) / "budget.sqlite3"))
            self.addCleanup(store.close)
            with self.assertRaises(RelayProbeRuntimeError):
                store.record_receipt(scope="a", request_hash="first", evidence={"proof": 1})
            store.reserve(scope="a", request_hash="first", max_fee_units=60, daily_budget_units=100)
            digest = store.record_receipt(scope="a", request_hash="first", evidence={"proof": 1})
            self.assertEqual(digest, store.record_receipt(scope="a", request_hash="first", evidence={"proof": 1}))
            with self.assertRaisesRegex(RelayProbeRuntimeError, "conflicting"):
                store.record_receipt(scope="a", request_hash="first", evidence={"proof": 2})


if __name__ == "__main__":
    unittest.main()
