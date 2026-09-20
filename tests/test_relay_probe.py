from __future__ import annotations

import json
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from pathlib import Path
from unittest.mock import patch

from gateway.relay_probe import (
    RelayProbeCoordinator,
    RelayProbeError,
    RelayProbeStore,
    VerifiedProbeResponse,
    probe_digest,
)


DIGEST = "0x" + "11" * 32


class Clock:
    def __init__(self, value: float = 1000) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class RelayProbeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.store = RelayProbeStore(":memory:", clock=self.clock)
        self.addCleanup(self.store.close)

    def issue(self, **overrides):
        return self.store.issue(**{
            "provider_id": "peer-a", "probe_class": "json_schema", "request_hash": DIGEST, **overrides,
        })

    @staticmethod
    def result_args(challenge, **overrides):
        return {"probe_id": challenge["probe_id"], "provider_id": challenge["provider_id"],
                "nonce": challenge["nonce"], "passed": True, "result_hash": DIGEST,
                "evidence": {"receipt": "signed", "details": {"a": 1, "b": 2}}, **overrides}

    def test_nonce_provider_binding_and_idempotent_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RelayProbeStore(str(Path(directory) / "probes.sqlite3"))
            issued = store.issue(
                provider_id="peer-a",
                probe_class="json_schema",
                request_hash="0x" + "11" * 32,
                ttl_seconds=30,
            )
            completed = store.record_result(
                probe_id=issued["probe_id"],
                nonce=issued["nonce"],
                provider_id="peer-a",
                passed=True,
                result_hash="0x" + "22" * 32,
                now=issued["issued_at"] + 1,
            )
            duplicate = store.record_result(
                probe_id=issued["probe_id"],
                nonce=issued["nonce"],
                provider_id="peer-a",
                passed=True,
                result_hash="0x" + "22" * 32,
                now=issued["issued_at"] + 1,
            )
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(duplicate["probe_id"], issued["probe_id"])
            with self.assertRaises(RelayProbeError):
                store.record_result(
                    probe_id=issued["probe_id"],
                    nonce="wrong",
                    provider_id="peer-a",
                    passed=True,
                    result_hash="0x" + "22" * 32,
                    now=issued["issued_at"] + 1,
                )

    def test_expired_probe_rejects_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RelayProbeStore(str(Path(directory) / "probes.sqlite3"))
            issued = store.issue(
                provider_id="peer-a", probe_class="safety", request_hash="0x" + "33" * 32, ttl_seconds=1
            )
            with self.assertRaisesRegex(RelayProbeError, "expired"):
                store.record_result(
                    probe_id=issued["probe_id"],
                    nonce=issued["nonce"],
                    provider_id="peer-a",
                    passed=False,
                    result_hash="0x" + "44" * 32,
                    now=issued["expires_at"] + 1,
                )

    def test_memory_database_lives_until_explicit_close(self) -> None:
        challenge = self.issue()
        self.assertEqual(self.store.get(challenge["probe_id"])["nonce"], challenge["nonce"])
        self.store.record_result(**self.result_args(challenge))
        self.assertEqual(self.store.get(challenge["probe_id"])["status"], "completed")
        self.store.close()
        self.store.close()
        with self.assertRaisesRegex(RelayProbeError, "closed"):
            self.store.get(challenge["probe_id"])

    def test_result_conflict_checks_verdict_and_full_evidence(self) -> None:
        challenge = self.issue()
        recorded = self.store.record_result(**self.result_args(challenge))
        for update in ({"passed": False}, {"evidence": {"receipt": "different"}},
                       {"result_hash": "0x" + "ff" * 32}):
            with self.subTest(update=update), self.assertRaisesRegex(RelayProbeError, "conflicts"):
                self.store.record_result(**self.result_args(challenge, **update))
        duplicate = self.store.record_result(**self.result_args(
            challenge, evidence={"details": {"b": 2, "a": 1}, "receipt": "signed"},
        ))
        self.assertEqual(recorded, duplicate)

    def test_completed_retry_remains_idempotent_after_expiry(self) -> None:
        challenge = self.issue(ttl_seconds=1)
        result = self.store.record_result(**self.result_args(challenge))
        self.clock.value += 100
        self.assertEqual(result, self.store.record_result(**self.result_args(challenge)))
        self.assertEqual(self.store.expire(), 0)

    def test_expiry_at_exact_deadline_and_predated_result(self) -> None:
        challenge = self.issue(ttl_seconds=1)
        with self.assertRaisesRegex(RelayProbeError, "predates"):
            self.store.record_result(**self.result_args(challenge, now=999))
        with self.assertRaisesRegex(RelayProbeError, "expired"):
            self.store.record_result(**self.result_args(challenge, now=1001))
        self.assertEqual(self.store.expire(now=1001), 1)
        self.assertEqual(self.store.get(challenge["probe_id"])["status"], "expired")

    def test_wrong_provider_unknown_probe_and_nonce_rejected(self) -> None:
        challenge = self.issue()
        for override in ({"provider_id": "peer-b"}, {"nonce": "another"}, {"probe_id": "unknown"}):
            with self.subTest(override=override), self.assertRaises(RelayProbeError):
                self.store.record_result(**self.result_args(challenge, **override))

    def test_invalid_issue_inputs_rejected(self) -> None:
        for override in ({"provider_id": ""}, {"provider_id": " peer-a"}, {"provider_id": None},
                         {"probe_class": ""}, {"request_hash": "abc"}, {"expected_digest": ""},
                         {"ttl_seconds": 0}, {"ttl_seconds": 901}, {"ttl_seconds": True},
                         {"ttl_seconds": 1.1}, {"nonce": "123"}):
            with self.subTest(override=override), self.assertRaises(RelayProbeError):
                self.issue(**override)

    def test_invalid_results_rejected(self) -> None:
        challenge = self.issue()
        for override in ({"passed": 1}, {"passed": "false"}, {"result_hash": ""},
                         {"evidence": [1]}, {"evidence": {"nonfinite": float("nan")}},
                         {"evidence": {"huge": "a" * 33000}}, {"now": True}):
            with self.subTest(override=override), self.assertRaises(RelayProbeError):
                self.store.record_result(**self.result_args(challenge, **override))

    def test_request_nonce_and_digest_binding(self) -> None:
        nonce = "ab" * 24
        request = {"nonce": nonce, "input": "example"}
        with self.assertRaisesRegex(RelayProbeError, "hash mismatch"):
            self.issue(nonce=nonce, request=request)
        with self.assertRaisesRegex(RelayProbeError, "nonce mismatch"):
            self.issue(nonce="cd" * 24, request=request, request_hash=probe_digest(request))
        challenge = self.issue(nonce=nonce, request=request, request_hash=probe_digest(request))
        self.assertEqual(json.loads(self.store.get(challenge["probe_id"])["request_json"]), request)
        with self.assertRaisesRegex(RelayProbeError, "already exists"):
            self.issue(nonce=nonce)

    def test_parallel_conflicting_results_have_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "probes.db")
            with RelayProbeStore(path, clock=self.clock) as first, RelayProbeStore(path, clock=self.clock) as second:
                challenge = first.issue(provider_id="peer-a", probe_class="json_schema", request_hash=DIGEST)
                barrier = threading.Barrier(2)

                def submit(store, passed):
                    barrier.wait(timeout=2)
                    try:
                        return store.record_result(**self.result_args(challenge, passed=passed))["evidence_json"]
                    except RelayProbeError:
                        return "conflict"

                with ThreadPoolExecutor(max_workers=2) as workers:
                    calls = [workers.submit(submit, first, True), workers.submit(submit, second, False)]
                    results = [future.result(timeout=3) for future in calls]
                self.assertEqual(results.count("conflict"), 1)
                self.assertIn(first.get(challenge["probe_id"])["evidence_json"], results)

    def test_parallel_identical_results_all_succeed(self) -> None:
        challenge = self.issue()
        with ThreadPoolExecutor(max_workers=8) as workers:
            futures = [workers.submit(self.store.record_result, **self.result_args(challenge)) for _ in range(8)]
            results = [future.result(timeout=3) for future in futures]
        self.assertTrue(all(result == results[0] for result in results))

    def test_previous_schema_migrates_and_persists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "probes.db")
            with sqlite3.connect(path) as db:
                db.execute("""CREATE TABLE probes (probe_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
                    nonce TEXT NOT NULL UNIQUE, probe_class TEXT NOT NULL, request_hash TEXT NOT NULL,
                    expected_digest TEXT, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'issued', result_hash TEXT, evidence_json TEXT)""")
            with RelayProbeStore(path, clock=self.clock) as store:
                challenge = store.issue(provider_id="peer-a", probe_class="json_schema", request_hash=DIGEST)
                store.record_result(**self.result_args(challenge))
            with RelayProbeStore(path, clock=self.clock) as reopened:
                self.assertEqual(reopened.get(challenge["probe_id"])["status"], "completed")


class RelayProbeCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.store = RelayProbeStore(":memory:", clock=self.clock)
        self.addCleanup(self.store.close)

    @staticmethod
    def good_response(provider, request, timeout):
        numbers = re.search(r"equal to (\d+) \+ (\d+)\.", request["input"])
        assert numbers is not None
        answer = {"nonce": request["nonce"], "sum": int(numbers[1]) + int(numbers[2])}
        return VerifiedProbeResponse(provider, probe_digest(request), json.dumps(answer), DIGEST)

    def coordinator(self, dispatch=None, **kwargs):
        coordinator = RelayProbeCoordinator(
            self.store, dispatch or self.good_response,
            **{"enabled": True, "clock": self.clock, **kwargs},
        )
        self.addCleanup(coordinator.stop)
        return coordinator

    def collect(self, coordinator, count=1):
        results = []
        deadline = time.monotonic() + 2
        while len(results) < count and time.monotonic() < deadline:
            results.extend(coordinator.tick())
            if len(results) < count:
                threading.Event().wait(0.001)
        self.assertEqual(len(results), count)
        return results

    def test_disabled_by_default_dispatches_nothing(self) -> None:
        calls = []
        coordinator = RelayProbeCoordinator(self.store, lambda *args: calls.append(args))
        self.assertEqual(coordinator.tick(["peer-a"]), [])
        coordinator.run(lambda: calls.append("supplier"), threading.Event())
        self.assertEqual(calls, [])
        self.assertEqual(coordinator.inflight_count, 0)

    def test_success_is_locally_evaluated_persisted_and_observed_once(self) -> None:
        observations = []
        coordinator = self.coordinator(observation_callback=observations.append)
        coordinator.tick(["peer-a", "peer-a"])
        result = self.collect(coordinator)[0]
        self.assertTrue(result["passed"])
        self.assertFalse(result["hard_violation"])
        self.assertTrue(result["observation_delivered"])
        self.assertEqual(result["result_hash"], probe_digest(result["evidence"]))
        persisted = self.store.get(result["probe_id"])
        self.assertEqual(json.loads(persisted["evidence_json"])["evidence"], result["evidence"])
        self.assertEqual(probe_digest(json.loads(persisted["request_json"])), persisted["request_hash"])
        coordinator.tick(["peer-a"])
        self.assertEqual(len(observations), 1)
        self.assertEqual(coordinator.inflight_count, 0)

    def test_provider_cannot_supply_a_passing_verdict_or_hash(self) -> None:
        coordinator = self.coordinator(lambda *_: {"passed": True, "result_hash": DIGEST, "verified": True})
        coordinator.tick(["peer-a"])
        result = self.collect(coordinator)[0]
        self.assertFalse(result["passed"])
        self.assertEqual(result["outcome"], "unverified_response")
        self.assertNotEqual(result["result_hash"], DIGEST)

    def test_wrong_answer_nonce_duplicate_json_or_extra_fields_fail(self) -> None:
        def wrong_sum(answer):
            answer["sum"] += 1
            return json.dumps(answer)

        def wrong_nonce(answer):
            answer["nonce"] = "replayed"
            return json.dumps(answer)

        def duplicate_key(answer):
            return json.dumps(answer)[:-1] + ', "sum": ' + str(answer["sum"]) + "}"

        def float_sum(answer):
            answer["sum"] = float(answer["sum"])
            return json.dumps(answer)

        for alter in (wrong_sum, wrong_nonce, duplicate_key, float_sum,
                      lambda answer: json.dumps({**answer, "passed": True}), lambda _: "not json"):
            with self.subTest(alter=alter):
                def dispatch(provider, request, timeout):
                    good = self.good_response(provider, request, timeout)
                    return VerifiedProbeResponse(provider, good.request_hash, alter(json.loads(good.output_text)), DIGEST)

                coordinator = self.coordinator(dispatch)
                coordinator.tick(["peer-a"])
                result = self.collect(coordinator)[0]
                self.assertFalse(result["passed"])
                self.assertEqual(result["outcome"], "capability_mismatch")

    def test_wrong_binding_receipt_reference_or_oversized_output_fails(self) -> None:
        for mutate, outcome in (
            (lambda value: {**value, "provider_id": "peer-b"}, "response_binding_mismatch"),
            (lambda value: {**value, "request_hash": "0x" + "00" * 32}, "response_binding_mismatch"),
            (lambda value: {**value, "receipt_hash": "invalid"}, "invalid_receipt_reference"),
            (lambda value: {**value, "output_text": "a" * 4097}, "invalid_output"),
        ):
            with self.subTest(outcome=outcome):
                def dispatch(provider, request, timeout):
                    good = self.good_response(provider, request, timeout)
                    return VerifiedProbeResponse(**mutate(good.__dict__))

                coordinator = self.coordinator(dispatch)
                coordinator.tick(["peer-a"])
                result = self.collect(coordinator)[0]
                self.assertFalse(result["passed"])
                self.assertEqual(result["outcome"], outcome)

    def test_call_budget_and_one_probe_per_provider_per_window(self) -> None:
        calls = []

        def dispatch(*args):
            calls.append(args[0])
            return self.good_response(*args)

        coordinator = self.coordinator(dispatch, max_inflight=2, max_probes_per_interval=2)
        coordinator.tick(["peer-a", "peer-a", "peer-b", "peer-c"])
        self.collect(coordinator, count=2)
        coordinator.tick(["peer-a", "peer-b", "peer-c"])
        self.assertCountEqual(calls, ["peer-a", "peer-b"])
        self.clock.value += 60
        coordinator.tick(["peer-c"])
        self.collect(coordinator)
        self.assertCountEqual(calls, ["peer-a", "peer-b", "peer-c"])

    def test_round_robin_prevents_provider_starvation(self) -> None:
        calls = []

        def dispatch(*args):
            calls.append(args[0])
            return self.good_response(*args)

        coordinator = self.coordinator(dispatch, max_probes_per_interval=1)
        for _ in range(3):
            coordinator.tick(["peer-a", "peer-b", "peer-c"])
            self.collect(coordinator)
            self.clock.value += 60
        self.assertEqual(calls, ["peer-a", "peer-b", "peer-c"])

    def test_infinite_candidate_iterator_is_bounded(self) -> None:
        coordinator = self.coordinator()
        coordinator.tick(repeat("peer-a"))
        self.collect(coordinator)
        self.assertEqual(coordinator.tick(repeat("peer-a")), [])
        self.assertEqual(coordinator.inflight_count, 0)

    def test_thread_start_failure_releases_capacity(self) -> None:
        coordinator = self.coordinator()
        with patch("gateway.relay_probe.threading.Thread.start", side_effect=RuntimeError("no threads")):
            coordinator.tick(["peer-a"])
        result = self.collect(coordinator)[0]
        self.assertEqual(result["outcome"], "dispatch_error")
        self.assertEqual(coordinator.inflight_count, 0)

    def test_unpersistable_result_is_inconclusive_and_not_observed(self) -> None:
        observations = []
        coordinator = self.coordinator(observation_callback=observations.append)
        coordinator.tick(["peer-a"])
        with patch.object(self.store, "record_result", side_effect=sqlite3.OperationalError("read only")):
            result = self.collect(coordinator)[0]
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["outcome"], "result_not_persisted")
        self.assertEqual(observations, [])
        self.assertEqual(coordinator.inflight_count, 0)

    def test_timed_out_hung_dispatch_retains_capacity_and_is_not_reobserved(self) -> None:
        release = threading.Event()
        entered = threading.Event()
        exited = threading.Event()
        self.addCleanup(release.set)
        calls = []
        observations = []

        def blocked(provider, request, timeout):
            calls.append(provider)
            entered.set()
            release.wait(2)
            response = self.good_response(provider, request, timeout)
            exited.set()
            return response

        coordinator = self.coordinator(blocked, timeout_seconds=1, observation_callback=observations.append)
        coordinator.tick(["peer-a"])
        self.assertTrue(entered.wait(1))
        self.clock.value += 2
        result = coordinator.tick(["peer-b"])[0]
        self.assertEqual(result["outcome"], "timeout")
        self.assertEqual(coordinator.inflight_count, 1)
        self.clock.value += 60
        self.assertEqual(coordinator.tick(["peer-b"]), [])
        self.assertEqual(calls, ["peer-a"])
        release.set()
        self.assertTrue(exited.wait(1))
        deadline = time.monotonic() + 1
        while coordinator.inflight_count and time.monotonic() < deadline:
            self.assertEqual(coordinator.tick(), [])
            threading.Event().wait(0.001)
        self.assertEqual(coordinator.inflight_count, 0)
        self.assertEqual(len(observations), 1)

    def test_transport_error_is_soft_and_does_not_store_exception_secrets(self) -> None:
        def failing(*_):
            raise RuntimeError("PRIVATE_TOKEN_SHOULD_NOT_BE_STORED")

        coordinator = self.coordinator(failing)
        coordinator.tick(["peer-a"])
        result = self.collect(coordinator)[0]
        self.assertEqual(result["outcome"], "dispatch_error")
        self.assertFalse(result["hard_violation"])
        self.assertNotIn("PRIVATE_TOKEN", self.store.get(result["probe_id"])["evidence_json"])

    def test_callback_failure_keeps_result_for_replay_without_redispatch(self) -> None:
        def failing(_):
            raise RuntimeError("ledger unavailable")

        coordinator = self.coordinator(observation_callback=failing)
        coordinator.tick(["peer-a"])
        result = self.collect(coordinator)[0]
        self.assertFalse(result["observation_delivered"])
        self.assertEqual(self.store.get(result["probe_id"])["status"], "completed")
        self.assertEqual(coordinator.tick(["peer-a"]), [])
        self.assertEqual(coordinator.inflight_count, 0)

    def test_stop_prevents_new_dispatches(self) -> None:
        coordinator = self.coordinator()
        coordinator.stop()
        self.assertEqual(coordinator.tick(["peer-a"]), [])
        self.assertEqual(coordinator.inflight_count, 0)
        stop_event = threading.Event()
        stop_event.set()
        coordinator.run(lambda: self.fail("supplier called after stop"), stop_event)

    def test_invalid_configuration_rejected(self) -> None:
        for config in ({"enabled": 1}, {"max_inflight": 0}, {"max_inflight": 17},
                       {"max_probes_per_interval": True}, {"max_probes_per_interval": 101},
                       {"timeout_seconds": float("nan")}, {"timeout_seconds": 601},
                       {"interval_seconds": 0}, {"timeout_seconds": True}):
            with self.subTest(config=config), self.assertRaises(RelayProbeError):
                self.coordinator(**config)


if __name__ == "__main__":
    unittest.main()
