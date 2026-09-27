from __future__ import annotations

import json
from types import SimpleNamespace
import tempfile
import threading
import time
import unittest
from pathlib import Path

from gateway import provider_jury
from gateway.provider_jury_runtime import (
    ProviderJuryRuntime,
    ProviderJuryRuntimeError,
)
from gateway.provider_jury_chain import CHAIN_STORAGE_HEALTH_SCHEMA
from gateway.provider_jury_worker import WORKER_STORAGE_HEALTH_SCHEMA
from gateway.relay_incidents import evidence_hash
from tests.test_chain_v9 import address, digest


class FakeWorker:
    def __init__(self, *, execution_enabled: bool) -> None:
        self.network_id = "fixture"
        self.chain_id = 31337
        self.settlement_contract = address(50)
        self.jury_registry = address(51)
        self.minimum_reputation = 80
        self.jury_size = 3
        self.adjudication_threshold = 2
        self.required_confirmations = 2
        self.decision_policy_hash = provider_jury.decision_policy_hash(
            model="judge-model",
            system_prompt="Apply the pinned fraud policy.",
            max_output_tokens=512,
            task_ttl_seconds=240,
        )
        self.execution_enabled = execution_enabled
        self.state = None
        self.plan = {
            "plan_hash": digest(70),
            "automatic_execution_allowed": True,
            "evm_vote": {"chain_id": 31337},
        }
        self.events: list[str] = []
        self.closed = False
        self.saved_evidence = None
        self.saved_inference = None
        self.collect_active = 0
        self.collect_max_active = 0
        self.collect_gate: threading.Event | None = None
        self.storage_ready = True

    def recover_expired_leases(self, *, broadcast_recorded=None):
        self.events.append("recover")
        return 0

    def collect_and_admit(
        self, *, settlement_key, evidence, inference_request, fetch_assignment,
        invoke_provider, finalize_assignment, task_ttl_seconds,
    ):
        self.events.append("collect")
        self.collect_active += 1
        self.collect_max_active = max(self.collect_max_active, self.collect_active)
        try:
            if self.collect_gate is not None:
                self.collect_gate.wait(timeout=2)
                time.sleep(0.02)
            if self.state is not None:
                if evidence != self.saved_evidence or inference_request != self.saved_inference:
                    raise ValueError("case input changed")
                return dict(self.state)
            binding = {
                "settlement_key": settlement_key,
                "network_id": self.network_id,
                "chain_id": self.chain_id,
                "settlement_contract": self.settlement_contract,
                "jury_registry": self.jury_registry,
            }
            fetched = fetch_assignment(binding)
            if fetched.get("status") != "finalized":
                fetched = finalize_assignment(binding, fetched)
            invoke_provider({"assignment": fetched, "settlement_key": settlement_key})
            self.saved_evidence = evidence
            self.saved_inference = inference_request
            self.state = {"status": "admitted", "settlement_key": settlement_key}
            return dict(self.state)
        finally:
            self.collect_active -= 1

    def get_plan(self, _settlement_key):
        return dict(self.plan)

    def get(self, _settlement_key):
        return dict(self.state) if self.state is not None else None

    def execute(self, settlement_key, *, broadcast):
        self.events.append("execute")
        result = broadcast(self.plan)
        self.state = {
            "status": result["status"],
            "settlement_key": settlement_key,
            "result": dict(result),
        }
        return dict(self.state)

    def reconcile(self, settlement_key, *, inspect):
        self.events.append("reconcile")
        result = inspect(self.plan, self.state)
        self.state = {
            "status": result["status"],
            "settlement_key": settlement_key,
            "result": dict(result),
        }
        return dict(self.state)

    def close(self):
        self.closed = True

    def storage_health(self):
        return {
            "schema": WORKER_STORAGE_HEALTH_SCHEMA,
            "ready": self.storage_ready,
            "quick_check": self.storage_ready,
            "writable": self.storage_ready,
            "backlog_count": 0,
            "uncertain_count": 0,
        }


class FakeChain:
    def __init__(self, worker: FakeWorker, *, execution_enabled: bool) -> None:
        self.config = SimpleNamespace(
            network_id=worker.network_id,
            chain_id=worker.chain_id,
            settlement_contract=worker.settlement_contract,
            jury_registry=worker.jury_registry,
            minimum_reputation=worker.minimum_reputation,
            jury_size=worker.jury_size,
            adjudication_threshold=worker.adjudication_threshold,
            confirmations=worker.required_confirmations,
        )
        self.execution_enabled = execution_enabled
        self.events: list[str] = []
        self.closed = False
        self.inspect_result = {"status": "confirmed", "tx_hash": digest(80)}
        self.storage_ready = True

    def fetch_assignment(self, binding):
        self.events.append("fetch")
        return {"status": "pending", "settlement_key": binding["settlement_key"]}

    def finalize_assignment(self, binding, _pending):
        self.events.append("finalize")
        return {"status": "finalized", "settlement_key": binding["settlement_key"]}

    def preflight(self, _plan):
        self.events.append("preflight")
        return {"action_hash": digest(81)}

    def broadcast(self, plan):
        self.events.append("broadcast")
        return {"status": "submitted", "plan_hash": plan["plan_hash"],
                "tx_hash": digest(82)}

    def inspect(self, _plan, _current):
        self.events.append("inspect")
        return dict(self.inspect_result)

    def broadcast_recorded(self, _plan):
        return False

    def expire_assignment(self, binding):
        self.events.append("expire")
        return {"status": "failed", "settlement_key": binding["settlement_key"]}

    def retry_assignment(self, binding):
        self.events.append("retry")
        return {"status": "pending", "settlement_key": binding["settlement_key"]}

    def confirmed_context(self):
        self.events.append("health")
        return {"block_number": 123, "block_hash": digest(83)}

    def close(self):
        self.closed = True

    def storage_health(self):
        return {
            "schema": CHAIN_STORAGE_HEALTH_SCHEMA,
            "ready": self.storage_ready,
            "quick_check": self.storage_ready,
            "writable": self.storage_ready,
            "backlog_count": 0,
            "uncertain_count": 0,
        }


class ProviderJuryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.policy_path = Path(self.temporary.name) / "jury-policy.json"
        self.policy = {
            "schema": provider_jury.POLICY_SCHEMA,
            "model": "judge-model",
            "system_prompt": "Apply the pinned fraud policy.",
            "max_output_tokens": 512,
            "task_ttl_seconds": 240,
        }
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        self.policy_path.chmod(0o600)
        self.policy_hash = provider_jury.decision_policy_hash(
            model=self.policy["model"],
            system_prompt=self.policy["system_prompt"],
            max_output_tokens=self.policy["max_output_tokens"],
            task_ttl_seconds=self.policy["task_ttl_seconds"],
        )
        self.document = {
            "schema": "fixture.evidence.v1",
            "finding": "signed response mismatch",
        }
        self.evidence = {
            "report_id": digest(10),
            "evidence_hash": evidence_hash(self.document),
            "request_hash": digest(11),
            "response_hash": digest(12),
        }
        self.settlement_key = digest(1)

    def runtime(self, *, enabled=False, worker=None, chain=None, invoke=None,
                transport_health=None, case_intake_health=None):
        worker = worker or FakeWorker(execution_enabled=enabled)
        chain = chain or FakeChain(worker, execution_enabled=enabled)
        invocations = []

        def default_invoke(task):
            invocations.append(task)
            chain.events.append("invoke")
            return {"verdict": True}

        runtime = ProviderJuryRuntime(
            worker=worker,
            chain_adapter=chain,
            invoke_provider=invoke or default_invoke,
            policy_path=self.policy_path,
            deployment_decision_policy_hash=self.policy_hash,
            execution_enabled=enabled,
            transport_health=(
                transport_health
                if transport_health is not None
                else (lambda: True) if enabled else None
            ),
            case_intake_health=case_intake_health,
        )
        self.addCleanup(runtime.close)
        return runtime, worker, chain, invocations

    def test_every_executable_policy_input_must_match_deployment_pin(self):
        worker = FakeWorker(execution_enabled=False)
        chain = FakeChain(worker, execution_enabled=False)
        changes = {
            "model": "attacker-model",
            "system_prompt": "Apply an attacker-selected policy.",
            "max_output_tokens": 513,
            "task_ttl_seconds": 241,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = {**self.policy, field: value}
                self.policy_path.write_text(json.dumps(changed), encoding="utf-8")
                self.policy_path.chmod(0o600)
                with self.assertRaisesRegex(
                    ProviderJuryRuntimeError, "executable policy hash.*deployment pin",
                ):
                    ProviderJuryRuntime(
                        worker=worker,
                        chain_adapter=chain,
                        invoke_provider=lambda _task: {},
                        policy_path=self.policy_path,
                        deployment_decision_policy_hash=self.policy_hash,
                        execution_enabled=False,
                    )

    def test_policy_file_rejects_duplicate_fields_and_unsafe_permissions(self):
        worker = FakeWorker(execution_enabled=False)
        chain = FakeChain(worker, execution_enabled=False)
        duplicate = (
            '{"schema":"mycomesh.v10.provider-jury-policy.v1",'
            '"model":"first","model":"second",'
            '"system_prompt":"Apply the pinned fraud policy.",'
            '"max_output_tokens":512,"task_ttl_seconds":240}'
        )
        self.policy_path.write_text(duplicate, encoding="utf-8")
        self.policy_path.chmod(0o600)
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "repeats field"):
            ProviderJuryRuntime(
                worker=worker, chain_adapter=chain,
                invoke_provider=lambda _task: {}, policy_path=self.policy_path,
                deployment_decision_policy_hash=self.policy_hash,
            )

        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        self.policy_path.chmod(0o666)
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "writable"):
            ProviderJuryRuntime(
                worker=worker, chain_adapter=chain,
                invoke_provider=lambda _task: {}, policy_path=self.policy_path,
                deployment_decision_policy_hash=self.policy_hash,
            )

        changed = dict(self.policy)
        changed["unknown"] = True
        self.policy_path.write_text(json.dumps(changed), encoding="utf-8")
        self.policy_path.chmod(0o600)
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "unknown or missing"):
            ProviderJuryRuntime(
                worker=worker,
                chain_adapter=chain,
                invoke_provider=lambda _task: {},
                policy_path=self.policy_path,
                deployment_decision_policy_hash=self.policy_hash,
                execution_enabled=False,
            )

    def test_disabled_execution_admits_without_preflight_or_broadcast(self):
        runtime, worker, chain, invocations = self.runtime(enabled=False)
        state = runtime.process_case(
            self.settlement_key, self.evidence, self.document,
        )
        self.assertEqual(state["status"], "admitted")
        self.assertEqual(len(invocations), 1)
        self.assertEqual(chain.events, ["fetch", "finalize", "invoke"])
        self.assertNotIn("execute", worker.events)

        health = runtime.health()
        self.assertTrue(health["transport"]["ready"])
        self.assertTrue(health["chain"]["ready"])
        self.assertTrue(health["worker"]["ready"])
        self.assertFalse(health["execution"]["enabled"])
        self.assertFalse(health["monetary_ready"])

    def test_enabled_happy_path_orders_callbacks_and_submits_once(self):
        runtime, worker, chain, invocations = self.runtime(
            enabled=True, case_intake_health=lambda: True,
        )
        state = runtime.process_case(
            self.settlement_key, self.evidence, self.document,
        )
        self.assertEqual(state["status"], "submitted")
        self.assertEqual(len(invocations), 1)
        self.assertEqual(
            chain.events,
            ["fetch", "finalize", "invoke", "preflight", "broadcast"],
        )
        self.assertEqual(worker.events, ["recover", "collect", "execute"])
        health = runtime.health()
        self.assertTrue(health["execution"]["ready"])
        self.assertTrue(health["case_intake"]["ready"])
        self.assertTrue(health["monetary_ready"])

    def test_execution_components_do_not_imply_trusted_case_intake(self):
        runtime, worker, chain, _ = self.runtime(
            enabled=True, case_intake_health=lambda: False,
        )
        health = runtime.health()
        self.assertTrue(health["execution"]["ready"])
        self.assertFalse(health["case_intake"]["ready"])
        self.assertEqual(
            health["case_intake"]["error_code"], "case_intake_not_ready",
        )
        self.assertFalse(health["monetary_ready"])
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "intake is not ready"):
            runtime.process_case(self.settlement_key, self.evidence, self.document)
        self.assertNotIn("broadcast", chain.events)
        self.assertNotIn("execute", worker.events)

    def test_enabled_runtime_requires_explicit_case_intake_gate(self):
        worker = FakeWorker(execution_enabled=True)
        chain = FakeChain(worker, execution_enabled=True)
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "case-intake"):
            ProviderJuryRuntime(
                worker=worker,
                chain_adapter=chain,
                invoke_provider=lambda _task: {},
                policy_path=self.policy_path,
                deployment_decision_policy_hash=self.policy_hash,
                execution_enabled=True,
                transport_health=lambda: True,
            )

    def test_enabled_runtime_requires_explicit_transport_gate(self):
        worker = FakeWorker(execution_enabled=True)
        chain = FakeChain(worker, execution_enabled=True)
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "transport health gate"):
            ProviderJuryRuntime(
                worker=worker,
                chain_adapter=chain,
                invoke_provider=lambda _task: {},
                policy_path=self.policy_path,
                deployment_decision_policy_hash=self.policy_hash,
                execution_enabled=True,
                case_intake_health=lambda: True,
            )

    def test_uncertain_submitted_and_confirmed_cases_only_reconcile_original_tx(self):
        for starting, observed in (
            ("uncertain", "submitted"),
            ("submitted", "confirmed"),
            ("confirmed", "confirmed"),
        ):
            with self.subTest(starting=starting):
                worker = FakeWorker(execution_enabled=True)
                chain = FakeChain(worker, execution_enabled=True)
                worker.state = {
                    "status": starting,
                    "settlement_key": self.settlement_key,
                    "result": {"tx_hash": digest(82)},
                }
                worker.saved_evidence = self.evidence
                worker.saved_inference = {
                    "model": self.policy["model"],
                    "system_prompt": self.policy["system_prompt"],
                    "evidence_document": self.document,
                    "max_output_tokens": self.policy["max_output_tokens"],
                }
                chain.inspect_result = {"status": observed, "tx_hash": digest(82)}
                runtime, _, _, invocations = self.runtime(
                    enabled=True, worker=worker, chain=chain,
                    case_intake_health=lambda: True,
                )
                result = runtime.process_case(
                    self.settlement_key, self.evidence, self.document,
                )
                self.assertEqual(result["status"], observed)
                self.assertEqual(invocations, [])
                self.assertEqual(chain.events, ["inspect"])
                self.assertNotIn("preflight", chain.events)
                self.assertNotIn("broadcast", chain.events)

    def test_reconcile_case_never_collects_or_broadcasts(self):
        runtime, worker, chain, invocations = self.runtime(
            enabled=True, case_intake_health=lambda: True,
        )
        worker.state = {
            "status": "submitted",
            "settlement_key": self.settlement_key,
            "result": {"tx_hash": digest(82)},
        }
        chain.inspect_result = {"status": "confirmed", "tx_hash": digest(82)}
        result = runtime.reconcile_case(self.settlement_key)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(worker.events, ["recover", "reconcile"])
        self.assertEqual(chain.events, ["inspect"])
        self.assertEqual(invocations, [])

    def test_evidence_document_hash_mismatch_fails_before_callbacks(self):
        runtime, worker, chain, invocations = self.runtime(
            enabled=True, case_intake_health=lambda: True,
        )
        changed = dict(self.document)
        changed["finding"] = "attacker-selected content"
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "does not match"):
            runtime.process_case(self.settlement_key, self.evidence, changed)
        self.assertEqual(worker.events, [])
        self.assertEqual(chain.events, [])
        self.assertEqual(invocations, [])

    def test_same_case_is_serialized_and_expiration_uses_execution_gate(self):
        runtime, worker, chain, _ = self.runtime(
            enabled=True, case_intake_health=lambda: True,
        )
        worker.collect_gate = threading.Event()
        results = []

        def run():
            results.append(runtime.process_case(
                self.settlement_key, self.evidence, self.document,
            ))

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        time.sleep(0.03)
        worker.collect_gate.set()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(len(results), 2)
        self.assertEqual(worker.collect_max_active, 1)
        # First call submits and the serialized second call reconciles it.
        self.assertEqual(chain.events.count("broadcast"), 1)
        self.assertEqual(chain.events.count("inspect"), 1)

        expired = runtime.expire_assignment(digest(2))
        self.assertEqual(expired["status"], "failed")
        self.assertEqual(chain.events[-1], "expire")

        retried = runtime.retry_assignment(digest(3))
        self.assertEqual(retried["status"], "pending")
        self.assertEqual(chain.events[-1], "retry")
        self.assertNotIn("finalize", chain.events[-1:])

    def test_retry_assignment_is_explicit_and_execution_gated(self):
        disabled, worker, chain, invocations = self.runtime(enabled=False)
        with self.assertRaisesRegex(ProviderJuryRuntimeError, "retry is disabled"):
            disabled.retry_assignment(self.settlement_key)
        self.assertNotIn("retry", chain.events)
        self.assertEqual(worker.events, [])
        self.assertEqual(invocations, [])

        enabled, worker, chain, invocations = self.runtime(
            enabled=True, case_intake_health=lambda: True,
        )
        result = enabled.retry_assignment(self.settlement_key)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(chain.events, ["retry"])
        self.assertEqual(worker.events, [])
        self.assertEqual(invocations, [])

    def test_health_separates_transport_failure_and_close_is_idempotent(self):
        runtime, worker, chain, _ = self.runtime(
            enabled=True, transport_health=lambda: False,
            case_intake_health=lambda: True,
        )
        health = runtime.health()
        self.assertFalse(health["transport"]["ready"])
        self.assertTrue(health["chain"]["ready"])
        self.assertFalse(health["execution"]["ready"])
        self.assertFalse(health["monetary_ready"])

        runtime.close()
        runtime.close()
        self.assertTrue(worker.closed)
        self.assertTrue(chain.closed)
        self.assertFalse(runtime.health()["monetary_ready"])

    def test_health_rederives_storage_and_policy_readiness(self):
        runtime, worker, chain, _ = self.runtime(
            enabled=True,
            transport_health=lambda: True,
            case_intake_health=lambda: True,
        )
        worker.storage_ready = False
        health = runtime.health()
        self.assertFalse(health["worker"]["ready"])
        self.assertFalse(health["monetary_ready"])

        worker.storage_ready = True
        chain.storage_ready = False
        health = runtime.health()
        self.assertFalse(health["chain"]["ready"])
        self.assertFalse(health["monetary_ready"])

        chain.storage_ready = True
        worker.decision_policy_hash = digest(999)
        health = runtime.health()
        self.assertFalse(health["policy"]["ready"])
        self.assertFalse(health["monetary_ready"])


if __name__ == "__main__":
    unittest.main()
