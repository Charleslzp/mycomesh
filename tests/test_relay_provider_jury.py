from __future__ import annotations

import copy
import io
import json
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from gateway import provider_jury
from gateway.identity import create_identity, save_identity, verify_document
from gateway.p2p import P2P_JURY_REQUEST_PURPOSE, P2P_SECURE_REQUEST_PURPOSE, P2P_SECURE_RESPONSE_PURPOSE
from gateway.relay import (
    RelayError,
    RelayControlHTTPServer,
    RelayProviderSession,
    RelayState,
    _decode_secure_frame,
    _encode_secure_frame,
    configure_relay_jury_identity,
    invoke_provider_jury,
    serve_relay,
    _ProviderJuryIntakeLoop,
    _close_provider_jury_runtime,
    _relay_provider_jury_intake_health,
    _relay_provider_jury_runtime_health,
)
from gateway.secure_transport import MemoryReplayStore, generate_transport_key, open_frame, seal_json_frame
from tests.test_chain_v9 import address, digest, key, signer


class StubProviderJuryRuntime:
    def __init__(self, health: dict | BaseException) -> None:
        self.health_result = health
        self.close_calls = 0
        self.health_calls = 0

    def health(self) -> dict:
        self.health_calls += 1
        if isinstance(self.health_result, BaseException):
            raise self.health_result
        return copy.deepcopy(self.health_result)

    def close(self) -> None:
        self.close_calls += 1


class StubProviderJuryIntake:
    def __init__(self, *, ready: bool = True, sync_error: BaseException | None = None) -> None:
        self.ready_result = ready
        self.sync_error = sync_error
        self.runtime = None
        self.close_calls = 0
        self.sync_calls = 0
        self.dispatch_calls = 0
        self.synced = threading.Event()
        self.dispatched = threading.Event()

    def bind_runtime(self, runtime) -> None:
        if self.runtime is not None and self.runtime is not runtime:
            raise RuntimeError("already bound")
        self.runtime = runtime

    def sync_once(self):
        self.sync_calls += 1
        self.synced.set()
        if self.sync_error is not None:
            raise self.sync_error
        return {"caught_up": True}

    def dispatch_once(self):
        self.dispatch_calls += 1
        self.dispatched.set()
        return None

    def ready(self) -> bool:
        return self.ready_result and self.runtime is not None

    def health(self) -> dict:
        ready = self.ready()
        result = {
            "schema": "mycomesh.v10.provider-jury-event-intake-health.v1",
            "ready": ready,
            "chain_id": 31337,
            "settlement_contract": address(50),
            "jury_registry": address(51),
            "confirmations": 2,
            "cursor": {"block_number": 100, "block_hash": digest(100)},
            "runtime_bound": self.runtime is not None,
            "chain_verified": self.ready_result,
            "caught_up": self.ready_result,
            "halted": False,
        }
        if not ready:
            result["error_code"] = "fixture_not_ready"
        return result

    def close(self) -> None:
        self.close_calls += 1


class StubIntakeLoopHealth:
    def __init__(self, *, running: bool = True, error_code: str | None = None) -> None:
        self.running = running
        self.error_code = error_code

    def health(self):
        result = {"running": self.running, "stop_requested": False}
        if self.error_code is not None:
            result["error_code"] = self.error_code
        return result


class RelayProviderJuryTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.relay_identity = create_identity()
        self.provider_identity = create_identity()
        self.provider_transport = generate_transport_key(
            self.provider_identity, lifetime_seconds=600,
        )
        self.contract = address(50)
        self.registry = address(51)
        self.vote_signer = signer(20)
        self.owner = address(100)
        self.policy_hash = provider_jury.decision_policy_hash(
            model="judge-model",
            system_prompt="Apply the pinned fraud policy.",
            max_output_tokens=512,
            task_ttl_seconds=300,
        )
        self.capability = {
            "schema": provider_jury.CAPABILITY_SCHEMA,
            "models": ["judge-model"],
            "max_output_tokens": 1024,
            "supports_structured_verdict": True,
            "decision_policy_hash": self.policy_hash,
        }
        self.selected = {
            "owner": self.owner,
            "vote_signer": self.vote_signer,
            "operator_id": "operator-a",
            "operator_id_hash": provider_jury._keccak_text("operator-a"),
            "peer_id": self.provider_identity.peer_id,
            "peer_id_hash": provider_jury._keccak_text(self.provider_identity.peer_id),
            "capability": self.capability,
            "capability_hash": provider_jury.capability_hash(self.capability),
            "reputation": 95,
        }
        evidence_document = {
            "schema": "fixture.provider-jury-evidence.v1",
            "finding": "signed response mismatch",
        }
        self.task = provider_jury.build_jury_task(
            network_id="fixture",
            chain_id=31337,
            settlement_contract=self.contract,
            jury_registry=self.registry,
            settlement_key=digest(70),
            assignment_hash=digest(71),
            selected_provider=self.selected,
            evidence={
                "report_id": digest(72),
                "evidence_hash": provider_jury.evidence_hash(evidence_document),
                "request_hash": digest(73),
                "response_hash": digest(74),
            },
            decision_policy_hash=self.policy_hash,
            inference_request={
                "model": "judge-model",
                "system_prompt": "Apply the pinned fraud policy.",
                "evidence_document": evidence_document,
                "max_output_tokens": 512,
            },
            relay_identity=self.relay_identity,
            issued_at=self.now,
            deadline=self.now + 300,
            nonce=digest(75),
        )
        self.state = RelayState()
        self.identity_path = Path(self.temporary.name) / "relay-jury-identity.json"
        save_identity(self.identity_path, self.relay_identity)
        configure_relay_jury_identity(
            self.state,
            self.identity_path,
            allowed_public_keys=[self.relay_identity.public_key],
        )
        self.session = RelayProviderSession(
            peer_id=self.provider_identity.peer_id,
            peer=self.peer_descriptor(),
            authenticated_signer=self.vote_signer,
        )
        self.state.providers[self.session.peer_id] = self.session

    def peer_descriptor(self) -> dict:
        return {
            "peer_id": self.provider_identity.peer_id,
            "public_key": self.provider_identity.public_key,
            "network_id": "fixture",
            "payment_address": self.owner,
            "secure_transport_required": True,
            "transport_key": self.provider_transport.binding,
            "settlement": {
                "version": 10,
                "chain_id": 31337,
                "contract": self.contract,
                "provider_signer": self.vote_signer,
            },
            "provider_jury": {
                "schema": "mycomesh.provider-jury.descriptor.v1",
                "provider_owner": self.owner,
                "vote_signer": self.vote_signer,
                "operator_id": self.selected["operator_id"],
                "operator_id_hash": self.selected["operator_id_hash"],
                "peer_id_hash": self.selected["peer_id_hash"],
                "capability": self.capability,
                "capability_hash": self.selected["capability_hash"],
            },
        }

    def provider_response(self, state, peer_id, message, timeout, load_reservation=None):
        self.assertIs(state, self.state)
        self.assertEqual(peer_id, self.provider_identity.peer_id)
        self.assertGreater(timeout, 0)
        self.assertIsNotNone(load_reservation)
        request_frame = _decode_secure_frame(message["secure_frame"])
        opened = open_frame(
            request_frame,
            recipient_key=self.provider_transport,
            expected_purpose=P2P_SECURE_REQUEST_PURPOSE,
            expected_sender_peer_id=self.relay_identity.peer_id,
            expected_sender_public_key=self.relay_identity.public_key,
            replay_store=MemoryReplayStore(),
        )
        wrapper = opened.json_payload()
        request = wrapper["message"]
        unsigned = verify_document(
            request,
            purpose=P2P_JURY_REQUEST_PURPOSE,
            audience=self.provider_identity.peer_id,
        )
        self.assertEqual(request["signature"]["public_key"], opened.sender_public_key)
        self.assertEqual(unsigned["jury_task"], self.task)
        verdict = provider_jury.build_provider_verdict(
            task=self.task,
            model_output={
                "confirmed": True,
                "confidence_bps": 9000,
                "reason_code": "signed_mismatch",
                "reasoning": "The canonical signed artifacts conflict.",
            },
            provider_identity=self.provider_identity,
            evm_private_key=key(20),
            vote_nonce=0,
            vote_deadline=self.now + 240,
            now=self.now,
        )
        response = {
            "type": "jury_infer_result",
            "ok": True,
            "request_id": unsigned["request_id"],
            "cached": False,
            "verdict": verdict,
        }
        response_frame = seal_json_frame(
            {"response": response},
            sender=self.provider_identity,
            recipient_binding=wrapper["reply_transport_key"],
            expected_recipient_peer_id=self.relay_identity.peer_id,
            expected_recipient_public_key=self.relay_identity.public_key,
            purpose=P2P_SECURE_RESPONSE_PURPOSE,
            ttl_seconds=60,
        )
        return {"secure_frame": _encode_secure_frame(response_frame)}

    def test_secure_assignment_bound_provider_jury_round_trip(self) -> None:
        with patch("gateway.relay.relay_infer", side_effect=self.provider_response) as relay_call:
            verdict = invoke_provider_jury(self.state, self.task, timeout=5)

        checked = provider_jury.verify_provider_verdict(verdict, task=self.task, now=self.now)
        self.assertTrue(checked["model_output"]["confirmed"])
        relay_call.assert_called_once()
        self.assertEqual(self.session.reserved_jobs, 0)

    def test_descriptor_must_match_assignment_before_dispatch(self) -> None:
        mismatched = copy.deepcopy(self.session.peer)
        mismatched["provider_jury"]["operator_id"] = "operator-b"
        self.session.peer = mismatched
        with patch("gateway.relay.relay_infer") as relay_call:
            with self.assertRaisesRegex(RelayError, "assignment snapshot"):
                invoke_provider_jury(self.state, self.task, timeout=5)
        relay_call.assert_not_called()

    def test_jury_identity_is_required_and_cannot_use_ephemeral_scheduler(self) -> None:
        self.state._jury_identity = None
        with self.assertRaisesRegex(RelayError, "identity is not configured"):
            invoke_provider_jury(self.state, self.task, timeout=5)

    def test_identity_loader_requires_file_permissions_and_deployment_pin(self) -> None:
        other_state = RelayState()
        identity_path = Path(self.temporary.name) / "another-jury-identity.json"
        save_identity(identity_path, self.relay_identity)
        with self.assertRaisesRegex(RelayError, "not in the deployment"):
            configure_relay_jury_identity(
                other_state, identity_path,
                allowed_public_keys=[create_identity().public_key],
            )
        identity_path.chmod(0o644)
        with self.assertRaisesRegex(RelayError, "group or other"):
            configure_relay_jury_identity(other_state, identity_path)

    def test_relay_state_does_not_load_jury_identity_without_dynamic_v10(self) -> None:
        with self.assertRaisesRegex(RelayError, "dynamic V10 jury deployment"):
            RelayState(
                jury_identity_path=str(self.identity_path),
                jury_expected_public_key=self.relay_identity.public_key,
            )
        with self.assertRaisesRegex(RelayError, "requires Settlement V10"):
            RelayState(
                settlement_version=9,
                provider_ai_jury_dynamic_configured=True,
            )

    def test_health_reports_transport_readiness_without_monetary_enforcement(self) -> None:
        ready = self._runtime_state()
        health = self._health(ready)
        self.assertTrue(health["provider_ai_jury_transport_ready"])
        self.assertEqual(
            health["provider_ai_jury_identity_public_key"],
            self.relay_identity.public_key,
        )
        anti_cheat = health["anti_cheat"]
        self.assertTrue(anti_cheat["provider_ai_jury_transport_ready"])
        self.assertEqual(
            anti_cheat["provider_ai_jury_identity_public_key"],
            self.relay_identity.public_key,
        )
        self.assertFalse(anti_cheat["monetary_enforcement_enabled"])
        self.assertEqual(anti_cheat["monetary_enforcement_mode"], "disabled")
        self.assertEqual(
            health["provider_ai_jury_runtime"],
            {
                "configured": False,
                "monetary_ready": False,
                "error_code": "runtime_disabled",
            },
        )
        self.assertEqual(
            health["provider_ai_jury_intake"]["schema"],
            "mycomesh.v10.provider-jury-event-intake-health.v1",
        )
        self.assertFalse(health["provider_ai_jury_intake"]["configured"])
        self.assertFalse(health["provider_ai_jury_intake"]["ready"])
        self.assertFalse(health["provider_ai_jury_intake"]["caught_up"])
        self.assertFalse(health["provider_ai_jury_intake"]["halted"])

        disabled = self._health(RelayState())
        self.assertFalse(
            disabled["anti_cheat"]["provider_ai_jury_transport_ready"]
        )
        self.assertIsNone(
            disabled["anti_cheat"]["provider_ai_jury_identity_public_key"]
        )

    def test_health_enables_monetary_mode_only_for_ready_runtime(self) -> None:
        runtime = StubProviderJuryRuntime(self._ready_runtime_health())
        state = self._runtime_state()
        state._provider_jury_runtime = runtime
        self._attach_ready_intake(state, runtime)

        health = self._health(state)

        self.assertTrue(health["provider_ai_jury_runtime"]["configured"])
        self.assertTrue(health["provider_ai_jury_runtime"]["monetary_ready"])
        self.assertTrue(health["provider_ai_jury_intake"]["ready"])
        self.assertTrue(health["provider_ai_jury_intake"]["caught_up"])
        self.assertFalse(health["provider_ai_jury_intake"]["halted"])
        anti_cheat = health["anti_cheat"]
        self.assertTrue(anti_cheat["monetary_enforcement_enabled"])
        self.assertEqual(anti_cheat["enforcement_mode"], "provider_ai_jury")
        self.assertEqual(
            anti_cheat["monetary_enforcement_mode"], "provider_ai_jury",
        )

    def test_health_keeps_monetary_mode_disabled_for_unhealthy_runtime(self) -> None:
        unhealthy = self._ready_runtime_health()
        unhealthy["chain"] = {
            **unhealthy["chain"],
            "ready": False,
            "error_code": "rpc_unavailable",
        }
        unhealthy["monetary_ready"] = False
        runtime = StubProviderJuryRuntime(unhealthy)
        state = self._runtime_state()
        state._provider_jury_runtime = runtime

        health = self._health(state)

        runtime_health = health["provider_ai_jury_runtime"]
        self.assertTrue(runtime_health["configured"])
        self.assertFalse(runtime_health["monetary_ready"])
        self.assertEqual(runtime_health["chain"]["error_code"], "rpc_unavailable")
        anti_cheat = health["anti_cheat"]
        self.assertFalse(anti_cheat["monetary_enforcement_enabled"])
        self.assertEqual(anti_cheat["enforcement_mode"], "quarantine_only")
        self.assertEqual(anti_cheat["monetary_enforcement_mode"], "disabled")

    def test_health_fails_closed_when_runtime_health_raises(self) -> None:
        state = self._runtime_state()
        state._provider_jury_runtime = StubProviderJuryRuntime(
            RuntimeError("private failure"),
        )

        health = self._health(state)

        self.assertEqual(
            health["provider_ai_jury_runtime"],
            {
                "configured": True,
                "monetary_ready": False,
                "error_code": "health_unavailable",
            },
        )
        self.assertFalse(health["anti_cheat"]["monetary_enforcement_enabled"])

    def test_health_rejects_wrong_schema_and_rederives_contradictory_state(self) -> None:
        wrong = self._ready_runtime_health()
        wrong["schema"] = "attacker.health.v1"
        state = self._runtime_state()
        state._provider_jury_runtime = StubProviderJuryRuntime(wrong)
        health = _relay_provider_jury_runtime_health(state)
        self.assertFalse(health["monetary_ready"])
        self.assertEqual(health["error_code"], "health_unavailable")

        contradictory = self._ready_runtime_health()
        contradictory["worker"]["storage"]["writable"] = False
        contradictory["monetary_ready"] = True
        state = self._runtime_state()
        state._provider_jury_runtime = StubProviderJuryRuntime(contradictory)
        health = _relay_provider_jury_runtime_health(state)
        self.assertFalse(health["worker"]["ready"])
        self.assertFalse(health["monetary_ready"])

    def test_health_chain_probe_is_single_flight_and_short_ttl_cached(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class BlockingRuntime(StubProviderJuryRuntime):
            def health(inner_self):
                inner_self.health_calls += 1
                started.set()
                release.wait(timeout=2)
                return copy.deepcopy(inner_self.health_result)

        runtime = BlockingRuntime(self._ready_runtime_health())
        state = self._runtime_state()
        state._provider_jury_runtime = runtime
        self._attach_ready_intake(state, runtime)
        state._provider_jury_health_cache_ttl_seconds = 0.02
        results: list[dict] = []
        thread = threading.Thread(
            target=lambda: results.append(_relay_provider_jury_runtime_health(state)),
        )
        thread.start()
        self.assertTrue(started.wait(timeout=1))
        concurrent = _relay_provider_jury_runtime_health(state)
        self.assertFalse(concurrent["monetary_ready"])
        self.assertEqual(concurrent["error_code"], "health_refresh_in_progress")
        self.assertEqual(runtime.health_calls, 1)
        release.set()
        thread.join(timeout=2)
        self.assertTrue(results[0]["monetary_ready"])

        cached = _relay_provider_jury_runtime_health(state)
        self.assertTrue(cached["monetary_ready"])
        self.assertEqual(runtime.health_calls, 1)
        time.sleep(0.03)
        release.clear()
        started.clear()
        # Past the refresh TTL the last probe is served without waiting while
        # exactly one background refresh runs.
        stale = _relay_provider_jury_runtime_health(state)
        self.assertTrue(stale["monetary_ready"])
        self.assertTrue(started.wait(timeout=1))
        again = _relay_provider_jury_runtime_health(state)
        self.assertTrue(again["monetary_ready"])
        self.assertEqual(runtime.health_calls, 2)
        release.set()
        deadline = time.monotonic() + 2
        while state._provider_jury_health_refreshing and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertFalse(state._provider_jury_health_refreshing)
        self.assertEqual(runtime.health_calls, 2)

    def test_health_never_serves_probe_beyond_hard_age(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class SlowRuntime(StubProviderJuryRuntime):
            def health(inner_self):
                inner_self.health_calls += 1
                if inner_self.health_calls > 1:
                    started.set()
                    release.wait(timeout=2)
                return copy.deepcopy(inner_self.health_result)

        runtime = SlowRuntime(self._ready_runtime_health())
        state = self._runtime_state()
        state._provider_jury_runtime = runtime
        self._attach_ready_intake(state, runtime)
        state._provider_jury_health_cache_ttl_seconds = 0.01
        state._provider_jury_health_max_age_seconds = 0.05
        self.assertTrue(_relay_provider_jury_runtime_health(state)["monetary_ready"])
        time.sleep(0.02)
        self.assertTrue(_relay_provider_jury_runtime_health(state)["monetary_ready"])
        self.assertTrue(started.wait(timeout=1))
        time.sleep(0.05)
        # The background refresh is still stuck on RPC and the last probe is
        # past its hard age: fail closed without starting another probe.
        expired = _relay_provider_jury_runtime_health(state)
        self.assertFalse(expired["monetary_ready"])
        self.assertEqual(expired["error_code"], "health_refresh_in_progress")
        self.assertEqual(runtime.health_calls, 2)
        release.set()

    def test_health_uses_live_intake_over_cached_case_intake_sample(self) -> None:
        sampled = self._ready_runtime_health()
        sampled["case_intake"] = {
            "ready": False,
            "mode": "trusted_internal_chain_anchored_callback",
            "error_code": "case_intake_not_ready",
        }
        sampled["monetary_ready"] = False
        runtime = StubProviderJuryRuntime(sampled)
        state = self._runtime_state()
        state._provider_jury_runtime = runtime
        intake = self._attach_ready_intake(state, runtime)
        health = _relay_provider_jury_runtime_health(state)
        self.assertTrue(health["case_intake"]["ready"])
        self.assertNotIn("error_code", health["case_intake"])
        self.assertTrue(health["monetary_ready"])

        intake.ready_result = False
        health = _relay_provider_jury_runtime_health(state)
        self.assertFalse(health["case_intake"]["ready"])
        self.assertFalse(health["monetary_ready"])
        self.assertEqual(runtime.health_calls, 1)

    def test_health_does_not_upgrade_other_case_intake_failures(self) -> None:
        for error_code in ("case_intake_not_configured", "RuntimeError"):
            with self.subTest(error_code=error_code):
                sampled = self._ready_runtime_health()
                sampled["case_intake"] = {
                    "ready": False,
                    "mode": "trusted_internal_chain_anchored_callback",
                    "error_code": error_code,
                }
                sampled["monetary_ready"] = False
                runtime = StubProviderJuryRuntime(sampled)
                state = self._runtime_state()
                state._provider_jury_runtime = runtime
                self._attach_ready_intake(state, runtime)
                health = _relay_provider_jury_runtime_health(state)
                self.assertFalse(health["case_intake"]["ready"])
                self.assertFalse(health["monetary_ready"])

    def test_serve_relay_owns_direct_or_factory_runtime_lifecycle(self) -> None:
        for injection in ("direct", "factory"):
            with self.subTest(injection=injection):
                runtime = StubProviderJuryRuntime({"monetary_ready": False})
                created_with: list[RelayState] = []

                def factory(state: RelayState) -> StubProviderJuryRuntime:
                    created_with.append(state)
                    return runtime

                runtime_options = (
                    {"provider_jury_runtime": runtime}
                    if injection == "direct"
                    else {"provider_jury_runtime_factory": factory}
                )
                with patch("gateway.relay.RelayProviderTCPServer"), patch(
                    "gateway.relay.RelayControlHTTPServer"
                ) as control_server, patch(
                    "gateway.relay_probe_runtime.create_relay_probe_runtime",
                    return_value=None,
                ):
                    control_server.return_value.serve_forever.side_effect = KeyboardInterrupt
                    with self.assertRaises(KeyboardInterrupt):
                        serve_relay(
                            "127.0.0.1",
                            settlement_version=10,
                            payment_address=address(31),
                            attestation_address=signer(30),
                            attestation_private_keys={signer(30): key(30)},
                            provider_ai_jury_dynamic_configured=True,
                            jury_identity_path=str(self.identity_path),
                            jury_expected_public_key=self.relay_identity.public_key,
                            **runtime_options,
                        )

                self.assertEqual(runtime.close_calls, 1)
                if injection == "factory":
                    self.assertEqual(len(created_with), 1)
                    self.assertIsNone(created_with[0]._provider_jury_runtime)

    def test_serve_relay_owns_and_runs_direct_or_factory_intake_lifecycle(self) -> None:
        for injection in ("direct", "factory"):
            with self.subTest(injection=injection):
                runtime = StubProviderJuryRuntime(self._ready_runtime_health())
                intake = StubProviderJuryIntake()
                created_with: list[RelayState] = []

                def intake_factory(state):
                    created_with.append(state)
                    return intake

                def runtime_factory(state):
                    self.assertIs(state._provider_jury_intake, intake)
                    self.assertFalse(state._provider_jury_intake.ready())
                    self.assertFalse(state.provider_jury_case_intake_health())
                    return runtime

                options = (
                    {
                        "provider_jury_runtime": runtime,
                        "provider_jury_intake": intake,
                    }
                    if injection == "direct"
                    else {
                        "provider_jury_runtime_factory": runtime_factory,
                        "provider_jury_intake_factory": intake_factory,
                    }
                )

                def stop_after_cycle():
                    self.assertTrue(intake.dispatched.wait(timeout=2))
                    raise KeyboardInterrupt

                with patch("gateway.relay.RelayProviderTCPServer"), patch(
                    "gateway.relay.RelayControlHTTPServer"
                ) as control_server, patch(
                    "gateway.relay_probe_runtime.create_relay_probe_runtime",
                    return_value=None,
                ):
                    control_server.return_value.serve_forever.side_effect = stop_after_cycle
                    with self.assertRaises(KeyboardInterrupt):
                        serve_relay(
                            "127.0.0.1",
                            settlement_version=10,
                            payment_address=address(31),
                            attestation_address=signer(30),
                            attestation_private_keys={signer(30): key(30)},
                            provider_ai_jury_dynamic_configured=True,
                            jury_identity_path=str(self.identity_path),
                            jury_expected_public_key=self.relay_identity.public_key,
                            provider_jury_intake_poll_seconds=0.05,
                            provider_jury_intake_join_timeout_seconds=1,
                            **options,
                        )

                self.assertIs(intake.runtime, runtime)
                self.assertGreaterEqual(intake.sync_calls, 1)
                self.assertGreaterEqual(intake.dispatch_calls, 1)
                self.assertEqual(intake.close_calls, 1)
                self.assertEqual(runtime.close_calls, 1)
                if injection == "factory":
                    self.assertEqual(len(created_with), 1)
                    self.assertIsNone(created_with[0]._provider_jury_intake)
                    self.assertIsNone(created_with[0]._provider_jury_runtime)

    def test_intake_factory_or_bind_failure_closes_every_owned_component(self) -> None:
        runtime = StubProviderJuryRuntime(self._ready_runtime_health())
        with patch(
            "gateway.relay_probe_runtime.create_relay_probe_runtime", return_value=None,
        ):
            with self.assertRaisesRegex(RuntimeError, "intake factory failed"):
                serve_relay(
                    "127.0.0.1",
                    settlement_version=10,
                    payment_address=address(31),
                    attestation_address=signer(30),
                    attestation_private_keys={signer(30): key(30)},
                    provider_ai_jury_dynamic_configured=True,
                    jury_identity_path=str(self.identity_path),
                    jury_expected_public_key=self.relay_identity.public_key,
                    provider_jury_runtime=runtime,
                    provider_jury_intake_factory=lambda _state: (_ for _ in ()).throw(
                        RuntimeError("intake factory failed")
                    ),
                )
        self.assertEqual(runtime.close_calls, 1)

        runtime = StubProviderJuryRuntime(self._ready_runtime_health())
        intake = StubProviderJuryIntake()
        intake.bind_runtime = lambda _runtime: (_ for _ in ()).throw(
            RuntimeError("bind failed")
        )
        with self.assertRaisesRegex(RuntimeError, "bind failed"):
            serve_relay(
                "127.0.0.1",
                settlement_version=10,
                payment_address=address(31),
                attestation_address=signer(30),
                attestation_private_keys={signer(30): key(30)},
                provider_ai_jury_dynamic_configured=True,
                jury_identity_path=str(self.identity_path),
                jury_expected_public_key=self.relay_identity.public_key,
                provider_jury_runtime=runtime,
                provider_jury_intake=intake,
            )
        self.assertEqual(intake.close_calls, 1)
        self.assertEqual(runtime.close_calls, 1)

    def test_intake_thread_start_failure_closes_runtime_and_intake(self) -> None:
        runtime = StubProviderJuryRuntime(self._ready_runtime_health())
        intake = StubProviderJuryIntake()
        with patch("gateway.relay.RelayProviderTCPServer"), patch(
            "gateway.relay.RelayControlHTTPServer"
        ), patch(
            "gateway.relay_probe_runtime.create_relay_probe_runtime",
            return_value=None,
        ), patch.object(
            _ProviderJuryIntakeLoop, "start",
            side_effect=RuntimeError("intake thread failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "intake thread failed"):
                serve_relay(
                    "127.0.0.1",
                    settlement_version=10,
                    payment_address=address(31),
                    attestation_address=signer(30),
                    attestation_private_keys={signer(30): key(30)},
                    provider_ai_jury_dynamic_configured=True,
                    jury_identity_path=str(self.identity_path),
                    jury_expected_public_key=self.relay_identity.public_key,
                    provider_jury_runtime=runtime,
                    provider_jury_intake=intake,
                )
        self.assertEqual(intake.close_calls, 1)
        self.assertEqual(runtime.close_calls, 1)

    def test_intake_loop_error_and_repeated_close_fail_closed(self) -> None:
        runtime = StubProviderJuryRuntime(self._ready_runtime_health())
        intake = StubProviderJuryIntake(sync_error=RuntimeError("rpc unavailable"))
        intake.bind_runtime(runtime)
        loop = _ProviderJuryIntakeLoop(intake, poll_seconds=0.05)
        state = self._runtime_state()
        state._provider_jury_runtime = runtime
        state._provider_jury_intake = intake
        state._provider_jury_intake_loop = loop
        loop.start()
        self.assertTrue(intake.synced.wait(timeout=1))
        deadline = time.monotonic() + 1
        while "error_code" not in loop.health() and time.monotonic() < deadline:
            time.sleep(0.01)
        intake_health = _relay_provider_jury_intake_health(state)
        runtime_health = _relay_provider_jury_runtime_health(state)
        self.assertFalse(intake_health["ready"])
        self.assertFalse(runtime_health["monetary_ready"])
        self.assertEqual(intake_health["error_code"], "RuntimeError")
        _close_provider_jury_runtime(state, join_timeout_seconds=1)
        _close_provider_jury_runtime(state, join_timeout_seconds=1)
        self.assertEqual(intake.close_calls, 1)
        self.assertEqual(runtime.close_calls, 1)

    def test_intake_loop_recovers_only_after_successful_sync_and_dispatch(self) -> None:
        runtime = StubProviderJuryRuntime(self._ready_runtime_health())
        intake = StubProviderJuryIntake(sync_error=RuntimeError("temporary rpc failure"))
        intake.bind_runtime(runtime)
        loop = _ProviderJuryIntakeLoop(intake, poll_seconds=0.05)
        state = self._runtime_state()
        state._provider_jury_runtime = runtime
        state._provider_jury_intake = intake
        state._provider_jury_intake_loop = loop
        loop.start()
        self.assertTrue(intake.synced.wait(timeout=1))
        deadline = time.monotonic() + 1
        while "error_code" not in loop.health() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(_relay_provider_jury_intake_health(state)["ready"])
        intake.sync_error = None
        self.assertTrue(intake.dispatched.wait(timeout=1))
        deadline = time.monotonic() + 1
        while not _relay_provider_jury_intake_health(state)["ready"] and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(_relay_provider_jury_intake_health(state)["ready"])
        _close_provider_jury_runtime(state, join_timeout_seconds=1)
        self.assertEqual(intake.close_calls, 1)
        self.assertEqual(runtime.close_calls, 1)

    def test_intake_health_schema_is_strict_and_exposed(self) -> None:
        runtime = StubProviderJuryRuntime(self._ready_runtime_health())
        state = self._runtime_state()
        state._provider_jury_runtime = runtime
        intake = self._attach_ready_intake(state, runtime)
        health = _relay_provider_jury_intake_health(state)
        self.assertEqual(
            health["schema"],
            "mycomesh.v10.provider-jury-event-intake-health.v1",
        )
        self.assertTrue(health["ready"])
        self.assertTrue(health["caught_up"])
        self.assertFalse(health["halted"])

        original_health = intake.health
        intake.health = lambda: {**original_health(), "unexpected": True}
        rejected = _relay_provider_jury_intake_health(state)
        self.assertFalse(rejected["ready"])
        self.assertEqual(rejected["error_code"], "health_unavailable")
        self.assertFalse(_relay_provider_jury_runtime_health(state)["monetary_ready"])

    def test_factory_is_not_called_before_v10_identity_preconditions(self) -> None:
        calls = []

        def factory(_state):
            calls.append(1)
            return StubProviderJuryRuntime(self._ready_runtime_health())

        with self.assertRaisesRegex(RelayError, "dynamic Settlement V10"):
            serve_relay("127.0.0.1", provider_jury_runtime_factory=factory)
        self.assertEqual(calls, [])

    def test_startup_failures_after_runtime_install_always_close_components(self) -> None:
        runtime_options = {
            "settlement_version": 10,
            "payment_address": address(31),
            "attestation_address": signer(30),
            "attestation_private_keys": {signer(30): key(30)},
            "provider_ai_jury_dynamic_configured": True,
            "jury_identity_path": str(self.identity_path),
            "jury_expected_public_key": self.relay_identity.public_key,
        }
        stages = ("probe", "discovery", "provider_bind", "control_bind")
        for stage in stages:
            with self.subTest(stage=stage):
                runtime = StubProviderJuryRuntime(self._ready_runtime_health())
                intake = StubProviderJuryIntake()
                discovery = None
                probe_side_effect = None
                provider_side_effect = None
                control_side_effect = None
                if stage == "probe":
                    probe_side_effect = RuntimeError("probe startup failed")
                elif stage == "discovery":
                    discovery = type("Discovery", (), {
                        "config": {"context": {"network_profile": "wrong"}},
                        "admission": {},
                    })()
                elif stage == "provider_bind":
                    provider_side_effect = OSError("provider bind failed")
                else:
                    control_side_effect = OSError("control bind failed")
                with patch(
                    "gateway.relay_probe_runtime.create_relay_probe_runtime",
                    side_effect=probe_side_effect,
                    return_value=None,
                ), patch(
                    "gateway.relay.RelayProviderTCPServer",
                    side_effect=provider_side_effect,
                ), patch(
                    "gateway.relay.RelayControlHTTPServer",
                    side_effect=control_side_effect,
                ):
                    with self.assertRaises((RelayError, RuntimeError, OSError)):
                        serve_relay(
                            "127.0.0.1",
                            provider_jury_runtime=runtime,
                            provider_jury_intake=intake,
                            relay_discovery=discovery,
                            **runtime_options,
                        )
                self.assertEqual(intake.close_calls, 1)
                self.assertEqual(runtime.close_calls, 1)

    def test_serve_relay_prints_loaded_jury_public_key(self) -> None:
        output = io.StringIO()
        with patch("gateway.relay.RelayProviderTCPServer") as provider_server, patch(
            "gateway.relay.RelayControlHTTPServer"
        ) as control_server, patch(
            "gateway.relay_probe_runtime.create_relay_probe_runtime", return_value=None,
        ), patch("sys.stdout", new=output):
            control_server.return_value.serve_forever.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                serve_relay(
                    "127.0.0.1",
                    settlement_version=10,
                    payment_address=address(31),
                    attestation_address=signer(30),
                    attestation_private_keys={signer(30): key(30)},
                    provider_ai_jury_dynamic_configured=True,
                    jury_identity_path=str(
                        Path(self.temporary.name) / "relay-jury-identity.json"
                    ),
                    jury_expected_public_key=self.relay_identity.public_key,
                )

        self.assertIn(
            f"provider_ai_jury_identity_public_key: {self.relay_identity.public_key}",
            output.getvalue(),
        )
        provider_server.assert_called_once()

    @staticmethod
    def _health(state: RelayState) -> dict:
        server = RelayControlHTTPServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_address[1]}/health", timeout=2,
            ) as response:
                return json.loads(response.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def _runtime_state(self) -> RelayState:
        return RelayState(
            settlement_version=10,
            payment_address=address(31),
            attestation_address=signer(30),
            attestation_private_keys={signer(30): key(30)},
            provider_ai_jury_dynamic_configured=True,
            jury_identity_path=str(self.identity_path),
            jury_expected_public_key=self.relay_identity.public_key,
        )

    @staticmethod
    def _attach_ready_intake(state: RelayState, runtime) -> StubProviderJuryIntake:
        intake = StubProviderJuryIntake()
        intake.bind_runtime(runtime)
        state._provider_jury_intake = intake
        state._provider_jury_intake_loop = StubIntakeLoopHealth()
        return intake

    def _ready_runtime_health(self) -> dict:
        return {
            "schema": "mycomesh.v10.provider-jury-runtime-health.v1",
            "policy": {
                "ready": True,
                "schema": provider_jury.POLICY_SCHEMA,
                "model": "judge-model",
                "decision_policy_hash": self.policy_hash,
            },
            "transport": {
                "ready": True,
                "mode": "case_bound_private_callback",
            },
            "chain": {
                "ready": True,
                "confirmed_block_number": 123,
                "confirmed_block_hash": digest(123),
                "storage": {
                    "schema": "mycomesh.v10.provider-jury-chain-storage-health.v1",
                    "ready": True,
                    "quick_check": True,
                    "writable": True,
                    "backlog_count": 0,
                    "uncertain_count": 0,
                },
            },
            "worker": {
                "ready": True,
                "execution_enabled": True,
                "storage": {
                    "schema": "mycomesh.v10.provider-jury-worker-storage-health.v1",
                    "ready": True,
                    "quick_check": True,
                    "writable": True,
                    "backlog_count": 0,
                    "uncertain_count": 0,
                },
            },
            "case_intake": {
                "ready": True,
                "mode": "trusted_internal_chain_anchored_callback",
            },
            "execution": {
                "enabled": True,
                "worker_enabled": True,
                "chain_enabled": True,
                "ready": True,
            },
            "monetary_ready": True,
        }


if __name__ == "__main__":
    unittest.main()
