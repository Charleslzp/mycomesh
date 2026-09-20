from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import queue
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from gateway.chain import parse_private_key, private_key_to_address
from gateway.relay import (
    RelayError, RelayJob, RelayNotDispatchedError, RelayOutcomeUnknownError,
    RelayProviderSession, RelaySchedulingError, RelaySettlementUnavailableError, RelayState,
    V7ProviderRejected, _assign_v7_provider, _disconnect_relay_provider,
    _provider_affinity_key, _release_provider_load, _routing_provider_signer, _routing_session_id,
    _scheduler_snapshot, _transition_provider_load, _v7_normalize_request,
    relay_error_http_response, relay_infer, relay_v7_openai, v7_relay_capabilities,
)
from gateway.reservation import inference_request_hash
from gateway.session_relayer import RelaySettlementError


KEY = "0x" + "aa" * 20
CONTRACT = "0x" + "11" * 20
PRICING = "0x" + "22" * 32
SIGNERS = {"peer-a": "0x" + "ab" * 20, "peer-b": "0x" + "bc" * 20}


def make_state() -> RelayState:
    private_key = "0x" + "4".zfill(64)
    signer = private_key_to_address(parse_private_key(private_key))
    state = RelayState(settlement_version=8, payment_address="0x" + "33" * 20,
                       attestation_address=signer, attestation_private_keys={signer: private_key})
    settlement = {"version": 8, "chain_id": 11155111, "contract": CONTRACT,
                  "pricing_version": 1, "pricing_hash": PRICING}
    for name in ("peer-a", "peer-b"):
        state.providers[name] = RelayProviderSession(
            peer_id=name, last_seen=100,
            peer={"peer_id": name, "settlement": {**settlement, "provider_signer": SIGNERS[name]},
                  "model": "m", "models": ["m"], "channel": "c"},
        )
    return state


def make_request(session_id: str | None = None) -> dict:
    return {"endpoint": "responses", "model": "m", "input": "identical prompt",
            "options": {"metadata": {"mycomesh_session_id": session_id}} if session_id is not None else {},
            "chain_id": 11155111, "contract": CONTRACT, "channel": "c",
            "pricing_version": 1, "pricing_hash": PRICING, "requires_web_search": False,
            "request_id": "0x" + "55" * 32, "request_hash": "0x" + "66" * 32,
            "max_output_tokens": 128}


def assign(state, request, key=KEY):
    return _assign_v7_provider(state, request, _provider_affinity_key(key, request))


class RelaySessionSchedulerTest(unittest.TestCase):
    def test_no_session_does_not_bind_prompt_cache(self):
        state = make_state()
        request = make_request()
        request["options"]["prompt_cache_key"] = "shared-cache"
        self.assertIsNone(_provider_affinity_key(KEY, request))
        first, second = assign(state, request), assign(state, request)
        self.assertNotEqual(first.provider.peer_id, second.provider.peer_id)
        self.assertFalse(state._provider_affinity)
        _release_provider_load(first)
        _release_provider_load(second)

    def test_new_sessions_with_identical_prompt_choose_separate_idle_providers(self):
        state = make_state()
        first, second = assign(state, make_request("a")), assign(state, make_request("b"))
        self.assertNotEqual(first.provider.peer_id, second.provider.peer_id)
        self.assertEqual(len(state._provider_affinity), 2)
        _release_provider_load(first)
        _release_provider_load(second)

    def test_idle_new_sessions_tie_break_by_number_of_bindings(self):
        state = make_state()
        first = assign(state, make_request("a"))
        _release_provider_load(first)
        second = assign(state, make_request("b"))
        self.assertNotEqual(first.provider.peer_id, second.provider.peer_id)
        _release_provider_load(second)

    def test_first_turn_concurrency_binds_atomically_without_reentrant_lock(self):
        state = make_state()
        state.lock = threading.Lock()
        gate = threading.Barrier(8)

        def concurrent_assignment(_):
            gate.wait(timeout=2)
            return assign(state, make_request("same-session"))

        with ThreadPoolExecutor(max_workers=8) as pool:
            reservations = list(pool.map(concurrent_assignment, range(8)))
        self.assertEqual(len({item.provider.peer_id for item in reservations}), 1)
        self.assertEqual(reservations[0].affinity.in_flight, 8)
        for reservation in reservations:
            _release_provider_load(reservation)
        self.assertEqual(reservations[0].affinity.in_flight, 0)

    def test_session_scope_is_key_chain_contract_and_not_prompt_or_model(self):
        request = make_request("same")
        original = _provider_affinity_key(KEY, request)
        changed_prompt = {**request, "input": "different", "model": "new-model"}
        self.assertEqual(original, _provider_affinity_key(KEY, changed_prompt))
        self.assertNotEqual(original, _provider_affinity_key("0x" + "bb" * 20, request))
        self.assertNotEqual(original, _provider_affinity_key(KEY, {**request, "chain_id": 1}))
        self.assertNotEqual(original, _provider_affinity_key(KEY, {**request, "contract": "0x" + "cc" * 20}))
        state = make_state()
        first = assign(state, request)
        second = assign(state, request, "0x" + "bb" * 20)
        self.assertNotEqual(first.provider.peer_id, second.provider.peer_id)
        _release_provider_load(first)
        _release_provider_load(second)

    def test_bound_session_stays_on_busy_provider(self):
        state = make_state()
        first = assign(state, make_request("a"))
        _transition_provider_load(first, "queued")
        _transition_provider_load(first, "active")
        second = assign(state, make_request("a"))
        self.assertIs(first.provider, second.provider)
        self.assertEqual(_scheduler_snapshot(state, list(state.providers.values()))["available_slots"], 1)
        _release_provider_load(first)
        _release_provider_load(second)

    def test_disconnected_pin_is_not_migrated(self):
        state = make_state()
        request = make_request("a")
        first = assign(state, request)
        _release_provider_load(first)
        state.providers.pop(first.provider.peer_id)
        with self.assertRaises(RelaySchedulingError) as error:
            assign(state, request)
        self.assertEqual(error.exception.status_code, 503)
        self.assertEqual(state._provider_affinity[_provider_affinity_key(KEY, request)].peer_id, first.provider.peer_id)

    def test_incompatible_pin_returns_409_and_does_not_migrate(self):
        state = make_state()
        request = make_request("a")
        first = assign(state, request)
        _release_provider_load(first)
        first.provider.peer["models"] = ["other"]
        with self.assertRaises(RelaySchedulingError) as error:
            assign(state, request)
        self.assertEqual(error.exception.status_code, 409)

    def test_phase_accounting_is_disjoint_and_release_is_idempotent(self):
        state = make_state()
        reservation = assign(state, make_request("a"))
        for phase in ("reserved", "queued", "active", "received"):
            _transition_provider_load(reservation, phase)
            snapshot = _scheduler_snapshot(state, list(state.providers.values()))
            self.assertEqual(snapshot["outstanding_jobs"], 1)
            self.assertEqual(snapshot["total_slots"], 2)
            self.assertEqual(snapshot["available_slots"], 1)
            for field in ("reserved", "queued", "active"):
                self.assertEqual(snapshot[field + "_jobs"], int(field == phase))
        _release_provider_load(reservation)
        _release_provider_load(reservation)
        self.assertFalse(_transition_provider_load(reservation, "active"))
        snapshot = v7_relay_capabilities(state)["scheduler"]
        self.assertEqual(snapshot["outstanding_jobs"], 0)
        self.assertEqual(snapshot["available_slots"], 2)
        self.assertEqual(snapshot["version"], 1)
        self.assertIs(snapshot["session_affinity"], True)
        self.assertNotIn("a", snapshot)

    def test_health_when_no_providers_advertises_zero_slots(self):
        state = make_state()
        state.providers.clear()
        capabilities = v7_relay_capabilities(state)
        self.assertEqual(capabilities["providers"], 0)
        self.assertEqual(capabilities["scheduler"]["total_slots"], 0)
        self.assertEqual(capabilities["scheduler"]["outstanding_jobs"], 0)

    def test_expired_active_pin_is_never_evicted_for_a_new_session(self):
        state = make_state()
        with patch("gateway.relay.MAX_PROVIDER_AFFINITY_ENTRIES", 1):
            first = assign(state, make_request("a"))
            first.affinity.expires_at = -1
            with self.assertRaises(RelaySchedulingError):
                assign(state, make_request("b"))
            same_session = assign(state, make_request("a"))
            self.assertIs(same_session.affinity, first.affinity)
            self.assertEqual(len(state._provider_affinity), 1)
            _release_provider_load(first)
            _release_provider_load(same_session)

    def test_expired_idle_pin_can_be_reclaimed_but_live_idle_pin_is_not_evicted(self):
        state = make_state()
        with patch("gateway.relay.MAX_PROVIDER_AFFINITY_ENTRIES", 1):
            first = assign(state, make_request("a"))
            _release_provider_load(first)
            with self.assertRaises(RelaySchedulingError):
                assign(state, make_request("b"))
            first.affinity.expires_at = -1
            second = assign(state, make_request("b"))
            self.assertEqual(len(state._provider_affinity), 1)
            _release_provider_load(second)

    def test_invalid_session_ids_rejected_without_admission(self):
        for value in ("", " ", "a b", "a,b", "\na", "a\x7f", "会话", "a" * 129, None, 1, [], {}):
            with self.subTest(value=value), self.assertRaises(RelayError):
                _routing_session_id({"mycomesh_session_id": value})
        self.assertEqual(_routing_session_id({"mycomesh_session_id": "a" * 128}), "a" * 128)
        state = make_state()
        with self.assertRaises(RelayError):
            _v7_normalize_request(state, "/v1/responses", {"metadata": {"mycomesh_session_id": "a b"}}, payment=None)
        self.assertFalse(state._provider_affinity)

    def test_session_metadata_is_covered_by_existing_request_hash(self):
        common = dict(endpoint="responses", model="m", input_value="same", max_output_tokens=128)
        first = inference_request_hash(**common, options={"metadata": {"mycomesh_session_id": "a"}})
        second = inference_request_hash(**common, options={"metadata": {"mycomesh_session_id": "b"}})
        self.assertNotEqual(first, second)

    def test_signer_hint_is_signed_but_not_part_of_session_identity(self):
        request = make_request("a")
        key = _provider_affinity_key(KEY, request)
        common = dict(endpoint="responses", model="m", input_value="same", max_output_tokens=128)
        first = inference_request_hash(**common, options=request["options"])
        request["options"]["metadata"]["mycomesh_provider_signer"] = SIGNERS["peer-b"]
        self.assertEqual(key, _provider_affinity_key(KEY, request))
        self.assertNotEqual(first, inference_request_hash(**common, options=request["options"]))

    def test_expired_pin_and_restarted_relay_restore_original_signer_despite_load(self):
        for restart in (False, True):
            with self.subTest(restart=restart):
                state = make_state()
                request = make_request("returning")
                first = assign(state, request)
                _release_provider_load(first)
                original_peer = first.provider.peer_id
                request["options"]["metadata"]["mycomesh_provider_signer"] = SIGNERS[original_peer]
                first.affinity.expires_at = -1
                if restart:
                    state = make_state()
                busy = assign(state, make_request())
                self.assertEqual(busy.provider.peer_id, original_peer)
                restored = assign(state, request)
                self.assertEqual(restored.provider.peer_id, original_peer)
                self.assertEqual(restored.affinity.provider_signer, SIGNERS[original_peer])
                _release_provider_load(busy)
                _release_provider_load(restored)

    def test_hint_can_restore_same_signer_with_new_peer_identity(self):
        state = make_state()
        request = make_request("returning")
        request["options"]["metadata"]["mycomesh_provider_signer"] = SIGNERS["peer-b"]
        original = state.providers.pop("peer-b")
        replacement = RelayProviderSession(peer_id="replacement", peer=dict(original.peer))
        state.providers[replacement.peer_id] = replacement
        reservation = assign(state, request)
        self.assertIs(reservation.provider, replacement)
        _release_provider_load(reservation)

    def test_hint_conflicts_with_live_pin_even_if_original_provider_is_offline(self):
        state = make_state()
        request = make_request("a")
        first = assign(state, request)
        _release_provider_load(first)
        state.providers.pop(first.provider.peer_id)
        request["options"]["metadata"]["mycomesh_provider_signer"] = SIGNERS["peer-b"]
        with self.assertRaises(RelaySchedulingError) as error:
            assign(state, request)
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(first.affinity.provider_signer, SIGNERS["peer-a"])

    def test_hint_offline_incompatible_or_missing_advertisement_fails_closed(self):
        for mode, expected_status in (("offline", 503), ("incompatible", 409), ("legacy", 503)):
            for pinned in (False, True):
                with self.subTest(mode=mode, pinned=pinned):
                    state = make_state()
                    request = make_request("a")
                    if pinned:
                        _release_provider_load(assign(state, request))
                    request["options"]["metadata"]["mycomesh_provider_signer"] = SIGNERS["peer-a"]
                    if mode == "offline":
                        state.providers.pop("peer-a")
                    elif mode == "incompatible":
                        state.providers["peer-a"].peer["models"] = ["other"]
                    else:
                        state.providers["peer-a"].peer["settlement"].pop("provider_signer")
                        state.providers["peer-a"].peer["payment_address"] = SIGNERS["peer-a"]
                    with self.assertRaises(RelaySchedulingError) as error:
                        assign(state, request)
                    self.assertEqual(error.exception.status_code, expected_status)
                    self.assertEqual(state.providers["peer-b"].reserved_jobs, 0)

    def test_provider_cannot_change_advertised_signer_under_a_live_pin(self):
        state = make_state()
        request = make_request("a")
        first = assign(state, request)
        _release_provider_load(first)
        first.provider.peer["settlement"]["provider_signer"] = SIGNERS["peer-b"]
        with self.assertRaises(RelaySchedulingError) as error:
            assign(state, request)
        self.assertEqual(error.exception.status_code, 409)

    def test_provider_hint_exact_format_and_normalization(self):
        for value in ("", None, 1, [], {}, "0X" + "aa" * 20, "0x" + "aa" * 19,
                      "0x" + "zz" * 20, SIGNERS["peer-a"] + "\n", " " + SIGNERS["peer-a"]):
            with self.subTest(value=value), self.assertRaises(RelayError):
                _routing_provider_signer({"mycomesh_provider_signer": value})
        self.assertEqual(_routing_provider_signer({"mycomesh_provider_signer": "0x" + "AB" * 20}), SIGNERS["peer-a"])
        state = make_state()
        with self.assertRaises(RelayError):
            _v7_normalize_request(state, "/v1/responses", {"metadata": {"mycomesh_provider_signer": "bad"}}, payment=None)
        self.assertFalse(state._provider_affinity)

    def test_normalization_selects_original_signer_pricing_and_rejects_offline_hint(self):
        state = make_state()
        state.providers["peer-b"].peer["settlement"]["pricing_version"] = 7
        body = {"model": "m", "input": "hi", "metadata": {"mycomesh_session_id": "a",
                "mycomesh_provider_signer": SIGNERS["peer-b"]}}
        normalized = _v7_normalize_request(state, "/v1/responses", body, payment=None)
        self.assertEqual(normalized["pricing_version"], 7)
        state.providers.pop("peer-b")
        with self.assertRaises(RelaySchedulingError) as error:
            _v7_normalize_request(state, "/v1/responses", body, payment=None)
        self.assertEqual(error.exception.status_code, 503)

    def test_queue_full_releases_raw_admission(self):
        state = make_state()
        provider = state.providers["peer-a"]
        provider.jobs = queue.Queue(maxsize=1)
        provider.jobs.put(RelayJob("occupied", {}, queue.Queue()))
        with self.assertRaisesRegex(RelayError, "queue is full"):
            relay_infer(state, "peer-a", {}, timeout=0.1)
        self.assertEqual(provider.reserved_jobs + provider.queued_jobs + provider.active_jobs, 0)

    def test_timeout_cancels_only_queued_admission(self):
        state = make_state()
        provider = state.providers["peer-a"]
        with self.assertRaisesRegex(RelayNotDispatchedError, "timed out"):
            relay_infer(state, "peer-a", {}, timeout=0.01)
        self.assertIn("peer-a", state.providers)
        self.assertTrue(provider.jobs.empty())
        self.assertEqual(provider.reserved_jobs + provider.queued_jobs + provider.active_jobs, 0)

    def test_reserved_old_connection_cannot_enqueue_after_provider_reconnect(self):
        state = make_state()
        reservation = assign(state, make_request("a"))
        old = reservation.provider
        replacement = RelayProviderSession(peer_id=old.peer_id, peer=dict(old.peer))
        state.providers[old.peer_id] = replacement
        try:
            with self.assertRaisesRegex(RelayError, "not connected"):
                relay_infer(state, old.peer_id, {}, timeout=0.1, load_reservation=reservation)
        finally:
            _release_provider_load(reservation)
        self.assertTrue(replacement.jobs.empty())
        self.assertEqual(old.reserved_jobs, 0)

    def test_worker_phase_accounting_until_response_is_received(self):
        state = make_state()
        provider = state.providers["peer-a"]
        observed = []

        def provider_worker():
            job = provider.jobs.get(timeout=1)
            _transition_provider_load(job.load_reservation, "active")
            observed.append(v7_relay_capabilities(state)["scheduler"])
            _transition_provider_load(job.load_reservation, "received")
            job.response_queue.put({"type": "relay_job_result", "response": {"ok": True}})

        worker = threading.Thread(target=provider_worker)
        worker.start()
        self.assertEqual(relay_infer(state, provider.peer_id, {}, timeout=1), {"ok": True})
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(observed[0]["active_jobs"], 1)
        self.assertEqual(observed[0]["queued_jobs"], 0)
        self.assertEqual(observed[0]["outstanding_jobs"], 1)
        self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 0)

    def test_disconnect_releases_all_queued_jobs(self):
        state = make_state()
        provider = state.providers["peer-a"]
        errors = []

        def wait_for_result():
            try:
                relay_infer(state, "peer-a", {}, timeout=2)
            except RelayError as error:
                errors.append(str(error))

        workers = [threading.Thread(target=wait_for_result) for _ in range(2)]
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + 1
        while provider.jobs.qsize() != 2 and time.monotonic() < deadline:
            time.sleep(0.001)
        _disconnect_relay_provider(state, provider)
        for worker in workers:
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 2)
        self.assertEqual(provider.reserved_jobs + provider.queued_jobs + provider.active_jobs, 0)

    def run_openai(self, state, request, provider_call, *, submitter=None, deadline=None):
        if submitter is None:
            submitter = Mock()
            submitter.enqueue.return_value = ("pending", True)
            submitter.reserve_admission.return_value = "admission-lease"
        state._settlement_submitter = submitter
        with (
            patch("gateway.relay._v7_normalize_request", return_value=request),
            patch("gateway.relay.verify_v8_authorization", return_value={"authorization": {"key": KEY, "max_fee": 100000}}),
            patch("gateway.relay.v8_key_grant", return_value={"active": True, "owner": KEY, "max_per_request": 100000}),
            patch("gateway.relay.v8_account_balance", return_value=1000000),
            patch("gateway.relay._relay_v7_provider", side_effect=provider_call),
            # This fixture isolates scheduler routing/admission semantics.
            # Real crypto and full-body checks are exercised without this mock
            # by test_relay_integrity and test_relay_security_integration.
            patch("gateway.relay.validate_provider_response"),
            patch("gateway.relay.finalize_v8_relay_receipt", side_effect=lambda value, **kwargs: value),
            patch("gateway.relay.prepare_v8_relay_settlement", return_value=SimpleNamespace(key="settlement-key")),
        ):
            return relay_v7_openai(state, "/v1/responses", {}, {}, deadline=deadline)

    def test_independent_request_retries_another_provider_and_releases_each_assignment(self):
        state = make_state()
        attempted = []

        def provider_call(_state, session, message, *, timeout, load_reservation):
            attempted.append(session.peer_id)
            self.assertEqual(session.reserved_jobs, 1)
            if len(attempted) == 1:
                raise RelayNotDispatchedError("provider queue is full")
            return {"raw": {"output_text": "ok"},
                    "mycomesh_v8_settlement": {"receipt": {"provider_signer": SIGNERS[session.peer_id]}}}

        output, receipt = self.run_openai(state, make_request(), provider_call)
        self.assertEqual(output["output_text"], "ok")
        self.assertTrue(receipt["accepted"])
        self.assertEqual(attempted, ["peer-a", "peer-b"])
        self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 0)

    def test_explicit_session_does_not_fallback_on_busy_disconnect_or_uncertain_timeout(self):
        for error in (V7ProviderRejected("busy", retryable=True, status_code=429),
                      RelayError("provider disconnected"), RelayError("provider timed out"),
                      RelayError("provider queue is full")):
            with self.subTest(error=str(error)):
                state = make_state()
                calls = []

                def provider_call(_state, session, message, **kwargs):
                    calls.append(session.peer_id)
                    raise error

                with self.assertRaises(RelayError):
                    self.run_openai(state, make_request("pinned"), provider_call)
                self.assertEqual(calls, ["peer-a"])
                self.assertEqual(len(state._provider_affinity), 1)
                self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 0)

    def test_unexpected_error_during_request_preparation_does_not_leak_reservation(self):
        state = make_state()
        with self.assertRaisesRegex(ValueError, "preparation failed"):
            self.run_openai(state, make_request("pinned"), Mock(side_effect=ValueError("preparation failed")))
        self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 0)

    def test_mismatching_verified_receipt_is_not_enqueued_or_returned(self):
        state = make_state()
        request = make_request("pinned")
        request["options"]["metadata"]["mycomesh_provider_signer"] = SIGNERS["peer-a"]
        response = {"raw": {"output_text": "wrong account"},
                    "mycomesh_v8_settlement": {"receipt": {"provider_signer": SIGNERS["peer-b"]}}}
        with self.assertRaises(RelaySchedulingError) as error:
            self.run_openai(state, request, Mock(return_value=response))
        self.assertEqual(error.exception.status_code, 409)
        state._settlement_submitter.enqueue.assert_not_called()
        self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 0)

    def test_outstanding_reservation_includes_receipt_finalization(self):
        state = make_state()
        request = make_request("pinned")
        response = {"raw": {"output_text": "ok"},
                    "mycomesh_v8_settlement": {"receipt": {"provider_signer": SIGNERS["peer-a"]}}}

        def validate_receipt(_request, reservation, signed):
            self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 1)
            self.assertEqual(reservation.affinity.in_flight, 1)

        with patch("gateway.relay._validate_scheduled_provider_signer", side_effect=validate_receipt):
            self.run_openai(state, request, Mock(return_value=response))
        self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 0)

    def test_post_inference_finalization_failure_never_retries_another_provider(self):
        state = make_state()
        provider_call = Mock(return_value={})
        with patch("gateway.relay._finalize_scheduled_v7_response", side_effect=RelayError("outbox disconnected")):
            with self.assertRaisesRegex(RelayError, "outbox disconnected"):
                self.run_openai(state, make_request(), provider_call)
        self.assertEqual(provider_call.call_count, 1)
        self.assertEqual(v7_relay_capabilities(state)["scheduler"]["outstanding_jobs"], 0)

    def test_unknown_execution_or_provider_retryable_never_changes_provider(self):
        for error in (RelayOutcomeUnknownError("execution timed out"),
                      V7ProviderRejected("fenced execution requires recovery", retryable=True, status_code=503)):
            with self.subTest(error=error):
                state = make_state()
                provider_call = Mock(side_effect=error)
                with self.assertRaises(RelayError):
                    self.run_openai(state, make_request(), provider_call)
                self.assertEqual(provider_call.call_count, 1)
                state._settlement_submitter.release_admission.assert_called_once_with("admission-lease")

    def test_candidate_retries_share_one_deadline(self):
        state = make_state()
        budgets = []

        def provider_call(_state, session, message, *, timeout, **kwargs):
            budgets.append(timeout)
            if len(budgets) == 1:
                time.sleep(0.03)
                raise RelayNotDispatchedError("queue is full")
            return {"raw": {"output_text": "ok"},
                    "mycomesh_v8_settlement": {"receipt": {"provider_signer": SIGNERS[session.peer_id]}}}

        self.run_openai(state, make_request(), provider_call, deadline=time.monotonic() + 1)
        self.assertEqual(len(budgets), 2)
        self.assertLess(budgets[1], budgets[0] - 0.02)
        self.assertLessEqual(budgets[0], 1)

    def test_expired_total_deadline_prevents_next_candidate(self):
        state = make_state()
        calls = []

        def provider_call(_state, session, message, **kwargs):
            calls.append(session.peer_id)
            time.sleep(0.04)
            raise RelayNotDispatchedError("queue is full")

        with self.assertRaisesRegex(RelayNotDispatchedError, "total deadline"):
            self.run_openai(state, make_request(), provider_call, deadline=time.monotonic() + 0.025)
        self.assertEqual(calls, ["peer-a"])

    def test_settlement_admission_failure_prevents_paid_dispatch(self):
        state = make_state()
        submitter = Mock()
        error = RelaySettlementError("sensitive RPC detail must not be exposed")
        error.error_code = "insufficient_gas"
        submitter.reserve_admission.side_effect = error
        provider_call = Mock()
        with self.assertRaises(RelaySettlementUnavailableError) as failed:
            self.run_openai(state, make_request(), provider_call, submitter=submitter)
        self.assertEqual(failed.exception.execution_status, "not_dispatched")
        self.assertEqual(failed.exception.error_code, "insufficient_gas")
        self.assertNotIn("sensitive", str(failed.exception))
        provider_call.assert_not_called()
        submitter.enqueue.assert_not_called()
        submitter.release_admission.assert_not_called()

    def test_receipt_atomically_consumes_admission_and_finally_releases_lease(self):
        state = make_state()
        response = {"raw": {"output_text": "ok"},
                    "mycomesh_v8_settlement": {"receipt": {"provider_signer": SIGNERS["peer-a"]}}}
        self.run_openai(state, make_request(), Mock(return_value=response))
        self.assertEqual(state._settlement_submitter.enqueue.call_args.kwargs, {"reservation": "admission-lease"})
        state._settlement_submitter.release_admission.assert_called_once_with("admission-lease")

    def test_scheduling_error_mapping(self):
        self.assertEqual(relay_error_http_response(RelaySchedulingError("offline")), (503, {"Retry-After": "5"}))
        self.assertEqual(relay_error_http_response(RelaySchedulingError("incompatible", 409)), (409, {}))


if __name__ == "__main__":
    unittest.main()
