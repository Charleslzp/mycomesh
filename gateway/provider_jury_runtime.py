"""Internal coordinator for the dynamic Provider-AI jury pipeline.

This module intentionally has no HTTP intake and no Provider roster.  A trusted
Relay incident/report pipeline supplies an already committed settlement case
and its canonical evidence document.  The on-chain Registry assignment remains
the sole source of jury membership.

Execution is explicit and fail closed.  Once a worker case is submitted,
uncertain, or confirmed, subsequent calls only inspect the transaction already
committed by :mod:`gateway.provider_jury_chain`; they never allocate another
nonce or broadcast replacement bytes.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import threading
from typing import Any, Iterator

from . import chain, provider_jury
from .provider_jury_chain import (
    CHAIN_STORAGE_HEALTH_SCHEMA,
    ProviderJuryChainAdapter,
)
from .provider_jury_worker import (
    CASE_SCHEMA,
    WORKER_STORAGE_HEALTH_SCHEMA,
    ProviderJuryRelayWorker,
)
from .relay_incidents import evidence_hash


class ProviderJuryRuntimeError(RuntimeError):
    """The local jury policy or runtime composition is unsafe."""


RUNTIME_HEALTH_SCHEMA = "mycomesh.v10.provider-jury-runtime-health.v1"
MAX_POLICY_FILE_BYTES = 96 * 1024
_POLICY_FIELDS = {
    "schema", "model", "system_prompt", "max_output_tokens", "task_ttl_seconds",
}


def _reject_constant(value: str) -> None:
    raise ProviderJuryRuntimeError(f"jury policy contains a non-JSON constant: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ProviderJuryRuntimeError(f"jury policy repeats field {name!r}")
        result[name] = value
    return result


def _strict_json_file(path: str | os.PathLike[str]) -> Any:
    if not isinstance(path, (str, os.PathLike)) or not str(path) or "\x00" in str(path):
        raise ProviderJuryRuntimeError("a local jury policy path is required")
    target = Path(path)
    try:
        before = target.lstat()
    except OSError as exc:
        raise ProviderJuryRuntimeError("jury policy file is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProviderJuryRuntimeError("jury policy must be a local regular file, not a symlink")
    if hasattr(os, "getuid") and before.st_uid != os.getuid():
        raise ProviderJuryRuntimeError("jury policy file must be owned by the Relay account")
    if stat.S_IMODE(before.st_mode) & 0o022:
        raise ProviderJuryRuntimeError("jury policy file must not be writable by group or others")
    if before.st_size <= 0 or before.st_size > MAX_POLICY_FILE_BYTES:
        raise ProviderJuryRuntimeError("jury policy file size is invalid")

    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0))
    try:
        descriptor = os.open(target, flags)
        try:
            after = os.fstat(descriptor)
            if (not stat.S_ISREG(after.st_mode)
                    or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)):
                raise ProviderJuryRuntimeError("jury policy file changed while opening")
            chunks: list[bytes] = []
            remaining = MAX_POLICY_FILE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 16 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            final = os.fstat(descriptor)
            if (after.st_size != final.st_size
                    or after.st_mtime_ns != final.st_mtime_ns
                    or len(payload) != final.st_size):
                raise ProviderJuryRuntimeError("jury policy file changed while reading")
        finally:
            os.close(descriptor)
    except ProviderJuryRuntimeError:
        raise
    except OSError as exc:
        raise ProviderJuryRuntimeError("jury policy file cannot be read safely") from exc
    if len(payload) > MAX_POLICY_FILE_BYTES:
        raise ProviderJuryRuntimeError("jury policy file exceeds the size limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderJuryRuntimeError("jury policy must be UTF-8 JSON") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except ProviderJuryRuntimeError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderJuryRuntimeError("jury policy must be strict JSON") from exc


def _canonical_copy(value: Any, label: str) -> Any:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
        return json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderJuryRuntimeError(f"{label} must be strict JSON data") from exc


def _canonical_hash(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryRuntimeError(f"{label} must be a canonical bytes32") from exc
    if normalized != value or (nonzero and normalized == chain.ZERO_BYTES32):
        raise ProviderJuryRuntimeError(f"{label} must be lowercase canonical nonzero bytes32")
    return normalized


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or len(value) > maximum or "\x00" in value):
        raise ProviderJuryRuntimeError(f"{label} must be bounded canonical text")
    return value


@dataclass(frozen=True)
class ProviderJuryRuntimePolicy:
    schema: str
    model: str
    system_prompt: str
    max_output_tokens: int
    task_ttl_seconds: int
    decision_policy_hash: str

    @classmethod
    def load(
        cls, path: str | os.PathLike[str], *, deployment_decision_policy_hash: str,
    ) -> "ProviderJuryRuntimePolicy":
        value = _strict_json_file(path)
        if not isinstance(value, Mapping) or set(value) != _POLICY_FIELDS:
            raise ProviderJuryRuntimeError("jury policy has unknown or missing fields")
        if value.get("schema") != provider_jury.POLICY_SCHEMA:
            raise ProviderJuryRuntimeError("unsupported Provider jury policy schema")
        model = _bounded_text(value.get("model"), "jury policy model", 160)
        system_prompt = _bounded_text(
            value.get("system_prompt"), "jury policy system_prompt",
            provider_jury.MAX_PROMPT_CHARS,
        )
        maximum = value.get("max_output_tokens")
        ttl = value.get("task_ttl_seconds")
        if type(maximum) is not int or not 1 <= maximum <= 1_000_000:
            raise ProviderJuryRuntimeError("jury policy max_output_tokens is out of bounds")
        if (type(ttl) is not int
                or not 1 <= ttl <= provider_jury.MAX_TASK_TTL_SECONDS):
            raise ProviderJuryRuntimeError("jury policy task_ttl_seconds is out of bounds")
        pinned = _canonical_hash(
            deployment_decision_policy_hash, "deployment decision policy hash",
        )
        observed = provider_jury.decision_policy_hash(
            model=model,
            system_prompt=system_prompt,
            max_output_tokens=maximum,
            task_ttl_seconds=ttl,
        )
        if observed != pinned:
            raise ProviderJuryRuntimeError(
                "jury executable policy hash differs from the deployment pin"
            )
        return cls(
            schema=provider_jury.POLICY_SCHEMA,
            model=model,
            system_prompt=system_prompt,
            max_output_tokens=maximum,
            task_ttl_seconds=ttl,
            decision_policy_hash=observed,
        )


class ProviderJuryRuntime:
    """Compose assignment reads, Provider inference, and durable vote execution."""

    _RECONCILE_ONLY = frozenset({"submitted", "uncertain", "confirmed"})
    _WORKER_METHODS = (
        "collect_and_admit", "execute", "reconcile", "get", "get_plan",
        "recover_expired_leases", "storage_health", "close",
    )
    _CHAIN_METHODS = (
        "fetch_assignment", "finalize_assignment", "preflight", "broadcast",
        "inspect", "broadcast_recorded", "expire_assignment", "retry_assignment",
        "confirmed_context", "storage_health", "close",
    )

    def __init__(
        self, *, worker: ProviderJuryRelayWorker,
        chain_adapter: ProviderJuryChainAdapter,
        invoke_provider: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        policy_path: str | os.PathLike[str],
        deployment_decision_policy_hash: str,
        execution_enabled: bool = False,
        transport_health: Callable[[], bool] | None = None,
        case_intake_health: Callable[[], bool] | None = None,
    ) -> None:
        if type(execution_enabled) is not bool:
            raise ProviderJuryRuntimeError("execution_enabled must be an explicit boolean")
        if not callable(invoke_provider):
            raise ProviderJuryRuntimeError("a private Provider jury transport callback is required")
        if transport_health is not None and not callable(transport_health):
            raise ProviderJuryRuntimeError("transport_health must be callable")
        if case_intake_health is not None and not callable(case_intake_health):
            raise ProviderJuryRuntimeError("case_intake_health must be callable")
        for name in self._WORKER_METHODS:
            if not callable(getattr(worker, name, None)):
                raise ProviderJuryRuntimeError("a complete Provider jury worker is required")
        for name in self._CHAIN_METHODS:
            if not callable(getattr(chain_adapter, name, None)):
                raise ProviderJuryRuntimeError("a complete Provider jury chain adapter is required")

        pin = _canonical_hash(
            deployment_decision_policy_hash, "deployment decision policy hash",
        )
        worker_pin = getattr(worker, "decision_policy_hash", None)
        if worker_pin != pin:
            raise ProviderJuryRuntimeError(
                "jury worker decision policy differs from the deployment pin"
            )
        self.policy = ProviderJuryRuntimePolicy.load(
            policy_path, deployment_decision_policy_hash=pin,
        )
        self.worker = worker
        self.chain = chain_adapter
        self.invoke_provider = invoke_provider
        self.execution_enabled = execution_enabled
        self.transport_health = transport_health
        self.case_intake_health = case_intake_health
        self._validate_component_binding()
        if execution_enabled and (
            getattr(worker, "execution_enabled", None) is not True
            or getattr(chain_adapter, "execution_enabled", None) is not True
        ):
            raise ProviderJuryRuntimeError(
                "enabled runtime requires execution-enabled worker and chain adapter"
            )
        if execution_enabled and case_intake_health is None:
            raise ProviderJuryRuntimeError(
                "enabled runtime requires an explicit trusted case-intake health gate"
            )
        if execution_enabled and transport_health is None:
            raise ProviderJuryRuntimeError(
                "enabled runtime requires an explicit private transport health gate"
            )

        self._case_locks_guard = threading.Lock()
        self._case_locks: dict[str, tuple[threading.RLock, int]] = {}
        self._lifecycle = threading.Condition(threading.RLock())
        self._active_operations = 0
        self._closed = False

    def _validate_component_binding(self) -> None:
        config = getattr(self.chain, "config", None)
        if config is None:
            raise ProviderJuryRuntimeError("jury chain adapter has no validated deployment config")
        fields = {
            "network_id": "network_id",
            "chain_id": "chain_id",
            "settlement_contract": "settlement_contract",
            "jury_registry": "jury_registry",
            "minimum_reputation": "minimum_reputation",
            "jury_size": "jury_size",
            "adjudication_threshold": "adjudication_threshold",
            "required_confirmations": "confirmations",
        }
        for worker_name, config_name in fields.items():
            if getattr(self.worker, worker_name, None) != getattr(config, config_name, None):
                raise ProviderJuryRuntimeError(
                    f"jury worker {worker_name} differs from the chain deployment"
                )

    def __enter__(self) -> "ProviderJuryRuntime":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    @contextmanager
    def _operation(self) -> Iterator[None]:
        with self._lifecycle:
            if self._closed:
                raise ProviderJuryRuntimeError("Provider jury runtime is closed")
            self._active_operations += 1
        try:
            yield
        finally:
            with self._lifecycle:
                self._active_operations -= 1
                if self._active_operations == 0:
                    self._lifecycle.notify_all()

    @contextmanager
    def _case_lock(self, settlement_key: str) -> Iterator[None]:
        with self._case_locks_guard:
            prior = self._case_locks.get(settlement_key)
            lock, users = prior if prior is not None else (threading.RLock(), 0)
            self._case_locks[settlement_key] = (lock, users + 1)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._case_locks_guard:
                current = self._case_locks.get(settlement_key)
                if current is not None and current[0] is lock:
                    if current[1] == 1:
                        del self._case_locks[settlement_key]
                    else:
                        self._case_locks[settlement_key] = (lock, current[1] - 1)

    def _settlement_key(self, value: Any) -> str:
        return _canonical_hash(value, "settlement key")

    def _binding(self, settlement_key: str) -> dict[str, Any]:
        return {
            "schema": CASE_SCHEMA,
            "network_id": self.worker.network_id,
            "chain_id": self.worker.chain_id,
            "settlement_contract": self.worker.settlement_contract,
            "jury_registry": self.worker.jury_registry,
            "settlement_key": settlement_key,
        }

    def _case_input(
        self, evidence: Mapping[str, Any], evidence_document: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        frozen_evidence = _canonical_copy(evidence, "jury evidence")
        frozen_document = _canonical_copy(evidence_document, "jury evidence document")
        if (not isinstance(frozen_evidence, dict)
                or set(frozen_evidence) != {
                    "report_id", "evidence_hash", "request_hash", "response_hash",
                }
                or not isinstance(frozen_document, dict) or not frozen_document):
            raise ProviderJuryRuntimeError("jury evidence and its document must be objects")
        try:
            document_size = len(json.dumps(
                frozen_document, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8"))
        except (TypeError, ValueError) as exc:  # defensive after _canonical_copy
            raise ProviderJuryRuntimeError("jury evidence document is not canonical") from exc
        if document_size > provider_jury.MAX_PROMPT_CHARS:
            raise ProviderJuryRuntimeError("jury evidence document exceeds the prompt limit")
        for name in ("report_id", "evidence_hash", "request_hash", "response_hash"):
            frozen_evidence[name] = _canonical_hash(
                frozen_evidence.get(name), f"jury {name}",
            )
        committed_hash = frozen_evidence["evidence_hash"]
        if evidence_hash(frozen_document) != committed_hash:
            raise ProviderJuryRuntimeError(
                "jury evidence_hash does not match the canonical evidence document"
            )
        inference = {
            "model": self.policy.model,
            "system_prompt": self.policy.system_prompt,
            "evidence_document": frozen_document,
            "max_output_tokens": self.policy.max_output_tokens,
        }
        return frozen_evidence, frozen_document, inference

    def process_case(
        self, settlement_key: str, evidence: Mapping[str, Any],
        evidence_document: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Collect one assignment-bound AI quorum and advance its original tx.

        This method is deliberately an internal callback rather than a public
        endpoint.  The caller remains responsible for admitting only evidence
        anchored by the settlement/report ingestion pipeline.
        """
        key = self._settlement_key(settlement_key)
        frozen_evidence, _document, inference = self._case_input(
            evidence, evidence_document,
        )
        with self._operation(), self._case_lock(key):
            existing = self.worker.get(key)
            if self.execution_enabled and existing is None:
                intake_ready, intake_error = self._case_intake_ready()
                if not intake_ready:
                    raise ProviderJuryRuntimeError(
                        f"trusted case intake is not ready ({intake_error or 'unknown'})"
                    )
            self.worker.recover_expired_leases(
                broadcast_recorded=self.chain.broadcast_recorded,
            )
            state = self.worker.collect_and_admit(
                settlement_key=key,
                evidence=frozen_evidence,
                inference_request=inference,
                fetch_assignment=self.chain.fetch_assignment,
                finalize_assignment=self.chain.finalize_assignment,
                invoke_provider=self.invoke_provider,
                task_ttl_seconds=self.policy.task_ttl_seconds,
            )
            status = state.get("status") if isinstance(state, Mapping) else None
            if status in self._RECONCILE_ONLY:
                return self.worker.reconcile(key, inspect=self.chain.inspect)
            if status == "executing":
                # Another process may own a still-live lease.  Never create a
                # second send attempt; a later call will recover or reconcile.
                return dict(state)
            if status != "admitted":
                raise ProviderJuryRuntimeError("jury worker returned an unknown execution state")
            if not self.execution_enabled:
                return dict(state)
            plan = self.worker.get_plan(key)
            if not isinstance(plan, Mapping):
                raise ProviderJuryRuntimeError("admitted jury case has no durable execution plan")
            intake_ready, intake_error = self._case_intake_ready()
            if not intake_ready:
                raise ProviderJuryRuntimeError(
                    f"trusted case intake is not ready ({intake_error or 'unknown'})"
                )
            # Read-only validation happens before the worker acquires its one
            # send lease.  The adapter validates again immediately before send.
            self.chain.preflight(plan)
            return self.worker.execute(key, broadcast=self.chain.broadcast)

    def expire_assignment(self, settlement_key: str) -> dict[str, Any]:
        """Pass through the explicit, permissionless expired-assignment action."""
        key = self._settlement_key(settlement_key)
        with self._operation(), self._case_lock(key):
            if not self.execution_enabled:
                raise ProviderJuryRuntimeError(
                    "jury assignment expiration is disabled by the runtime execution gate"
                )
            result = self.chain.expire_assignment(self._binding(key))
            if not isinstance(result, Mapping):
                raise ProviderJuryRuntimeError("jury assignment expiration returned no state")
            return dict(result)

    def retry_assignment(self, settlement_key: str) -> dict[str, Any]:
        """Run the explicit failed-draw maintenance action.

        A successful retry remains ``pending`` until a separate, later call to
        the normal assignment finalizer. This API never invokes a Provider,
        creates a verdict plan, or broadcasts a Settlement vote.
        """
        key = self._settlement_key(settlement_key)
        with self._operation(), self._case_lock(key):
            if not self.execution_enabled:
                raise ProviderJuryRuntimeError(
                    "jury assignment retry is disabled by the runtime execution gate"
                )
            result = self.chain.retry_assignment(self._binding(key))
            if not isinstance(result, Mapping):
                raise ProviderJuryRuntimeError("jury assignment retry returned no state")
            status = result.get("status")
            if status not in {"failed", "pending", "finalized"}:
                raise ProviderJuryRuntimeError(
                    "jury assignment retry returned an invalid state"
                )
            return dict(result)

    def _transport_ready(self) -> tuple[bool, str | None]:
        if self.transport_health is None:
            return True, None
        try:
            ready = self.transport_health()
            if type(ready) is not bool:
                raise ProviderJuryRuntimeError("transport health callback must return a boolean")
            return ready, None if ready else "transport_not_ready"
        except Exception as exc:
            return False, type(exc).__name__

    def _case_intake_ready(self) -> tuple[bool, str | None]:
        # No public HTTP intake is safe here.  Monetary readiness requires an
        # explicitly wired internal event/evidence pipeline to attest that it
        # only supplies canonical, chain-anchored cases.
        if self.case_intake_health is None:
            return False, "case_intake_not_configured"
        try:
            ready = self.case_intake_health()
            if type(ready) is not bool:
                raise ProviderJuryRuntimeError(
                    "case intake health callback must return a boolean"
                )
            return ready, None if ready else "case_intake_not_ready"
        except Exception as exc:
            return False, type(exc).__name__

    @staticmethod
    def _storage_health(
        callback: Callable[[], Mapping[str, Any]], *, schema: str, label: str,
    ) -> dict[str, Any]:
        """Validate one durable-store probe without trusting its ready bit."""
        fallback = {
            "schema": schema,
            "ready": False,
            "quick_check": False,
            "writable": False,
            "backlog_count": 0,
            "uncertain_count": 0,
        }
        try:
            value = callback()
            if not isinstance(value, Mapping):
                raise ProviderJuryRuntimeError(f"{label} storage health is not an object")
            normalized = _canonical_copy(dict(value), f"{label} storage health")
            required = {
                "schema", "ready", "quick_check", "writable",
                "backlog_count", "uncertain_count",
            }
            if not required.issubset(normalized) or normalized.get("schema") != schema:
                raise ProviderJuryRuntimeError(f"{label} storage health schema is invalid")
            for name in ("ready", "quick_check", "writable"):
                if type(normalized.get(name)) is not bool:
                    raise ProviderJuryRuntimeError(
                        f"{label} storage health {name} must be a boolean"
                    )
            for name in ("backlog_count", "uncertain_count"):
                if type(normalized.get(name)) is not int or normalized[name] < 0:
                    raise ProviderJuryRuntimeError(
                        f"{label} storage health {name} must be nonnegative"
                    )
            if normalized["uncertain_count"] > normalized["backlog_count"]:
                raise ProviderJuryRuntimeError(
                    f"{label} storage health counts are inconsistent"
                )
            derived = normalized["quick_check"] and normalized["writable"]
            normalized["ready"] = derived
            if not derived and "error_code" not in normalized:
                normalized["error_code"] = "storage_not_ready"
            return normalized
        except Exception as exc:
            return {**fallback, "error_code": type(exc).__name__}

    def _closed_health(self) -> dict[str, Any]:
        unavailable = {"ready": False, "error_code": "runtime_closed"}
        return {
            "schema": RUNTIME_HEALTH_SCHEMA,
            "policy": {**unavailable, "schema": self.policy.schema},
            "transport": dict(unavailable),
            "chain": {
                **unavailable,
                "storage": {
                    "schema": CHAIN_STORAGE_HEALTH_SCHEMA,
                    "ready": False,
                    "quick_check": False,
                    "writable": False,
                    "backlog_count": 0,
                    "uncertain_count": 0,
                    "error_code": "runtime_closed",
                },
            },
            "worker": {
                **unavailable,
                "execution_enabled": getattr(self.worker, "execution_enabled", None) is True,
                "storage": {
                    "schema": WORKER_STORAGE_HEALTH_SCHEMA,
                    "ready": False,
                    "quick_check": False,
                    "writable": False,
                    "backlog_count": 0,
                    "uncertain_count": 0,
                    "error_code": "runtime_closed",
                },
            },
            "case_intake": dict(unavailable),
            "execution": {
                "enabled": self.execution_enabled,
                "worker_enabled": getattr(self.worker, "execution_enabled", None) is True,
                "chain_enabled": getattr(self.chain, "execution_enabled", None) is True,
                "ready": False,
            },
            "monetary_ready": False,
        }

    def health(self) -> dict[str, Any]:
        """Derive monetary readiness from every validated runtime component."""
        with self._lifecycle:
            closed = self._closed
        if closed:
            return self._closed_health()
        with self._operation():
            transport_ready, transport_error = self._transport_ready()
            intake_ready, intake_error = self._case_intake_ready()
            transport = {
                "ready": transport_ready,
                "mode": "case_bound_private_callback",
            }
            if transport_error:
                transport["error_code"] = transport_error

            policy_ready = False
            policy_health: dict[str, Any]
            try:
                self._validate_component_binding()
                if (
                    self.policy.schema != provider_jury.POLICY_SCHEMA
                    or self.policy.decision_policy_hash
                    != getattr(self.worker, "decision_policy_hash", None)
                ):
                    raise ProviderJuryRuntimeError("jury policy binding changed")
                policy_ready = True
                policy_health = {
                    "ready": True,
                    "schema": self.policy.schema,
                    "model": self.policy.model,
                    "decision_policy_hash": self.policy.decision_policy_hash,
                }
            except Exception as exc:
                policy_health = {
                    "ready": False,
                    "schema": self.policy.schema,
                    "error_code": type(exc).__name__,
                }

            worker_storage = self._storage_health(
                self.worker.storage_health,
                schema=WORKER_STORAGE_HEALTH_SCHEMA,
                label="worker",
            )
            worker_ready = worker_storage["ready"] is True

            chain_storage = self._storage_health(
                self.chain.storage_health,
                schema=CHAIN_STORAGE_HEALTH_SCHEMA,
                label="chain",
            )
            chain_ready = False
            chain_health: dict[str, Any]
            try:
                if chain_storage["ready"] is not True:
                    raise ProviderJuryRuntimeError("jury chain outbox is not ready")
                context = self.chain.confirmed_context()
                if not isinstance(context, Mapping):
                    raise ProviderJuryRuntimeError("chain health returned no confirmed context")
                block_number = context.get("block_number")
                block_hash = context.get("block_hash")
                if type(block_number) is not int or block_number < 0:
                    raise ProviderJuryRuntimeError("chain health returned an invalid block number")
                _canonical_hash(block_hash, "confirmed jury block hash")
                chain_ready = True
                chain_health = {
                    "ready": True,
                    "confirmed_block_number": block_number,
                    "confirmed_block_hash": block_hash,
                    "storage": chain_storage,
                }
            except Exception as exc:
                chain_health = {
                    "ready": False,
                    "storage": chain_storage,
                    "error_code": type(exc).__name__,
                }

            worker_execution = getattr(self.worker, "execution_enabled", None) is True
            chain_execution = getattr(self.chain, "execution_enabled", None) is True
            execution_ready = (
                self.execution_enabled and worker_execution and chain_execution
                and policy_ready and transport_ready and chain_ready and worker_ready
                and chain_storage["backlog_count"] == 0
            )
            case_intake = {
                "ready": intake_ready,
                "mode": "trusted_internal_chain_anchored_callback",
            }
            if intake_error:
                case_intake["error_code"] = intake_error
            return {
                "schema": RUNTIME_HEALTH_SCHEMA,
                "policy": policy_health,
                "transport": transport,
                "chain": chain_health,
                "worker": {
                    "ready": worker_ready,
                    "execution_enabled": worker_execution,
                    "storage": worker_storage,
                },
                "case_intake": case_intake,
                "execution": {
                    "enabled": self.execution_enabled,
                    "worker_enabled": worker_execution,
                    "chain_enabled": chain_execution,
                    "ready": execution_ready,
                },
                "monetary_ready": all((
                    policy_ready,
                    transport_ready,
                    chain_ready,
                    worker_ready,
                    intake_ready,
                    execution_ready,
                )),
            }

    def close(self) -> None:
        with self._lifecycle:
            if self._closed:
                return
            self._closed = True
            while self._active_operations:
                self._lifecycle.wait()
        failures: list[BaseException] = []
        for component in (self.worker, self.chain):
            try:
                component.close()
            except BaseException as exc:  # close both durable stores on teardown
                failures.append(exc)
        if failures:
            raise ProviderJuryRuntimeError("Provider jury runtime did not close cleanly") from failures[0]


ProviderJuryRuntimeCoordinator = ProviderJuryRuntime


__all__ = [
    "ProviderJuryRuntime", "ProviderJuryRuntimeCoordinator",
    "ProviderJuryRuntimeError", "ProviderJuryRuntimePolicy",
    "RUNTIME_HEALTH_SCHEMA",
]
