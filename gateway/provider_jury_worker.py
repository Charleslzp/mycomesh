"""Durable Relay worker for dynamically selected Provider-AI juries.

The Registry is the source of jury membership.  This worker deliberately does
not keep a local adjudicator roster: injected chain callbacks fetch and, when
needed, finalize one assignment snapshot.  The worker then issues signed,
assignment-bound inference tasks, verifies the Providers' identity and EVM
permits through :mod:`gateway.provider_jury`, and persists one atomic
``voteDisputeBySig`` plan before a funded keeper may broadcast it.

Execution is fail closed.  ``executing`` is only a lease; an exception or an
expired lease becomes ``uncertain`` and is never automatically retried.
``submitted`` transactions can advance only through receipt reconciliation.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable, Mapping
from typing import Any

from . import chain, provider_jury
from .identity import NodeIdentity
from .relay_incidents import evidence_hash
from .v10_enforcement import V10EnforcementError, _execution_result


class ProviderJuryWorkerError(ValueError):
    """A dynamic jury could not be admitted or safely executed."""


ASSIGNMENT_SCHEMA = "mycomesh.v10.provider-jury-assignment.v1"
CASE_SCHEMA = "mycomesh.v10.provider-jury-case.v1"
PLAN_SCHEMA = "mycomesh.v10.provider-jury-execution-plan.v1"
VOTE_PLAN_SCHEMA = "mycomesh.v10.provider-jury-vote-plan.v1"
WORKER_STORAGE_HEALTH_SCHEMA = "mycomesh.v10.provider-jury-worker-storage-health.v1"
ZERO_BYTES32 = "0x" + "00" * 32

AssignmentFetcher = Callable[[Mapping[str, Any]], Mapping[str, Any]]
AssignmentFinalizer = Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
ProviderInvoker = Callable[[Mapping[str, Any]], Mapping[str, Any]]
Broadcaster = Callable[[Mapping[str, Any]], Mapping[str, Any]]
Inspector = Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ProviderJuryWorkerError("jury worker data must be strict JSON") from exc


def _frozen_json(value: Any, label: str) -> Any:
    try:
        return json.loads(_canonical(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderJuryWorkerError(f"{label} must be strict JSON data") from exc


def _uint(value: Any, label: str, *, maximum: int = 2**64 - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ProviderJuryWorkerError(f"{label} must be a bounded nonnegative integer")
    return value


def _address(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryWorkerError(f"{label} must be a canonical EVM address") from exc
    if normalized != value or normalized == chain.ZERO_ADDRESS:
        raise ProviderJuryWorkerError(f"{label} must be lowercase, canonical and nonzero")
    return normalized


def _bytes32(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryWorkerError(f"{label} must be a canonical bytes32") from exc
    if normalized != value or (nonzero and normalized == ZERO_BYTES32):
        qualifier = "nonzero " if nonzero else ""
        raise ProviderJuryWorkerError(f"{label} must be lowercase, canonical and {qualifier}bytes32")
    return normalized


def _network_id(value: Any) -> str:
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or len(value) > 256 or "\x00" in value):
        raise ProviderJuryWorkerError("network_id must be bounded canonical text")
    return value


def _case_key(*, network_id: str, chain_id: int, settlement_contract: str,
              settlement_key: str) -> str:
    return evidence_hash({
        "schema": CASE_SCHEMA,
        "network_id": network_id,
        "chain_id": chain_id,
        "settlement_contract": settlement_contract,
        "settlement_key": settlement_key,
    })


class ProviderJuryRelayWorker:
    """Collect Provider-AI verdicts and hand one durable plan to a keeper.

    ``fetch_assignment`` and ``finalize_assignment`` must read a pinned chain
    and return the exact assignment schema documented by
    :meth:`collect_and_admit`.  They are intentionally injected so this module
    neither owns an RPC implementation nor a transaction signer.
    """

    STATUSES = frozenset({"admitted", "executing", "submitted", "confirmed", "uncertain"})

    def __init__(
        self, path: str | os.PathLike[str], *, relay_identity: NodeIdentity,
        network_id: str, chain_id: int, settlement_contract: str, jury_registry: str,
        minimum_reputation: int, jury_size: int, adjudication_threshold: int,
        decision_policy_hash: str,
        execution_enabled: bool = False, lease_seconds: int = 120,
        required_confirmations: int = 2,
    ) -> None:
        if str(path) == ":memory:":
            raise ProviderJuryWorkerError("Provider jury execution store must be durable")
        if not isinstance(relay_identity, NodeIdentity):
            raise ProviderJuryWorkerError("Relay identity is required for signed jury tasks")
        self.relay_identity = relay_identity
        self.network_id = _network_id(network_id)
        self.chain_id = _uint(chain_id, "chain_id", maximum=2**256 - 1)
        self.settlement_contract = _address(settlement_contract, "settlement contract")
        self.jury_registry = _address(jury_registry, "jury registry")
        self.minimum_reputation = _uint(minimum_reputation, "minimum Provider reputation")
        self.decision_policy_hash = _bytes32(decision_policy_hash, "decision policy hash")
        self.jury_size = _uint(jury_size, "jury size", maximum=7)
        self.adjudication_threshold = _uint(
            adjudication_threshold, "adjudication threshold", maximum=7,
        )
        if (self.jury_size < 3 or self.adjudication_threshold < 2
                or self.adjudication_threshold > self.jury_size
                or self.adjudication_threshold * 2 <= self.jury_size):
            raise ProviderJuryWorkerError("dynamic Provider jury requires a strict-majority quorum")
        if type(execution_enabled) is not bool:
            raise ProviderJuryWorkerError("execution_enabled must be an explicit boolean")
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 3600:
            raise ProviderJuryWorkerError("execution lease must be between 5 and 3600 seconds")
        if type(required_confirmations) is not int or not 2 <= required_confirmations <= 256:
            raise ProviderJuryWorkerError("automatic jury execution requires 2 to 256 confirmations")
        self.execution_enabled = execution_enabled
        self.lease_seconds = lease_seconds
        self.required_confirmations = required_confirmations
        self.path = str(path)
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exc:
            raise ProviderJuryWorkerError(
                "Provider jury execution store cannot be opened safely"
            ) from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise ProviderJuryWorkerError(
                    "Provider jury execution store must be an owned regular file"
                )
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self._lock = threading.RLock()
        # One process must never mint two different signed task sets for the
        # same assignment.  SQLite below provides the durable cross-restart
        # fence; this lock also avoids duplicate live calls inside a Relay.
        self._collection_lock = threading.RLock()
        self._db = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                                   check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS provider_jury_executions (
            case_key TEXT PRIMARY KEY,
            settlement_key TEXT NOT NULL,
            assignment_hash TEXT NOT NULL,
            plan_hash TEXT NOT NULL UNIQUE,
            plan_json TEXT NOT NULL,
            status TEXT NOT NULL,
            result_json TEXT,
            error_code TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            lease_owner TEXT,
            lease_expires_at INTEGER,
            attempts INTEGER NOT NULL DEFAULT 0
        )""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS provider_jury_collections (
            case_key TEXT PRIMARY KEY,
            settlement_key TEXT NOT NULL,
            assignment_hash TEXT NOT NULL,
            collection_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            deadline INTEGER NOT NULL
        )""")
        # Do not classify an expired execution lease during construction.  At
        # this point the worker has no access to the chain adapter's durable
        # outbox, so it cannot distinguish a crash before reservation from a
        # crash after broadcast.  ProviderJuryRuntime performs recovery with
        # ``broadcast_recorded`` before processing a case.

    def storage_health(self) -> dict[str, Any]:
        """Check that the execution store is intact, writable, and queryable.

        ``quick_check`` catches damaged pages while the immediate transaction
        and no-op UPDATE prove that this process can acquire the write lock.
        The transaction is always rolled back, so a health probe never changes
        durable execution state.
        """
        snapshot: dict[str, Any] = {
            "schema": WORKER_STORAGE_HEALTH_SCHEMA,
            "ready": False,
            "quick_check": False,
            "writable": False,
            "backlog_count": 0,
            "uncertain_count": 0,
        }
        try:
            with self._lock:
                rows = self._db.execute("PRAGMA quick_check(1)").fetchall()
                if len(rows) != 1 or rows[0][0] != "ok":
                    snapshot["error_code"] = "integrity_check_failed"
                    return snapshot
                snapshot["quick_check"] = True
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    # BEGIN IMMEDIATE alone can succeed on a query-only
                    # connection. A zero-row UPDATE proves write authorization
                    # without mutating durable state.
                    self._db.execute(
                        "UPDATE provider_jury_executions SET updated_at=updated_at WHERE 0"
                    )
                    snapshot["writable"] = True
                    row = self._db.execute(
                        "SELECT COUNT(*) AS backlog_count, "
                        "COALESCE(SUM(CASE WHEN status='uncertain' THEN 1 ELSE 0 END),0) "
                        "AS uncertain_count FROM provider_jury_executions "
                        "WHERE status!='confirmed'"
                    ).fetchone()
                    snapshot["backlog_count"] = int(row["backlog_count"])
                    snapshot["uncertain_count"] = int(row["uncertain_count"])
                finally:
                    self._db.rollback()
                snapshot["ready"] = True
                return snapshot
        except Exception as exc:
            snapshot["error_code"] = type(exc).__name__
            return snapshot

    def __enter__(self) -> "ProviderJuryRelayWorker":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _binding(self, settlement_key: str) -> dict[str, Any]:
        key = _bytes32(settlement_key, "settlement key")
        return {
            "schema": CASE_SCHEMA,
            "network_id": self.network_id,
            "chain_id": self.chain_id,
            "settlement_contract": self.settlement_contract,
            "jury_registry": self.jury_registry,
            "settlement_key": key,
        }

    def _key(self, settlement_key: str) -> str:
        binding = self._binding(settlement_key)
        return _case_key(
            network_id=self.network_id, chain_id=self.chain_id,
            settlement_contract=self.settlement_contract,
            settlement_key=binding["settlement_key"],
        )

    @staticmethod
    def _public_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = {
            "case_key": row["case_key"],
            "settlement_key": row["settlement_key"],
            "assignment_hash": row["assignment_hash"],
            "plan_hash": row["plan_hash"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "attempts": row["attempts"],
        }
        if row["status"] == "executing":
            value["lease_expires_at"] = row["lease_expires_at"]
        if row["result_json"]:
            value["result"] = json.loads(row["result_json"])
        if row["error_code"]:
            value["error_code"] = row["error_code"]
        return value

    def get(self, settlement_key: str) -> dict[str, Any] | None:
        case_key = self._key(settlement_key)
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM provider_jury_executions WHERE case_key=?", (case_key,),
            ).fetchone()
            return self._public_row(row)

    def get_plan(self, settlement_key: str) -> dict[str, Any] | None:
        case_key = self._key(settlement_key)
        with self._lock:
            row = self._db.execute(
                "SELECT plan_json FROM provider_jury_executions WHERE case_key=?", (case_key,),
            ).fetchone()
            return json.loads(row["plan_json"]) if row is not None else None

    def _assignment(self, value: Any, *, binding: Mapping[str, Any]) -> dict[str, Any]:
        fields = {
            "schema", "status", "network_id", "chain_id", "settlement_contract",
            "jury_registry", "settlement_key", "assignment_hash", "threshold",
            "selected_providers", "block_number", "block_hash",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ProviderJuryWorkerError("finalized jury assignment has unknown or missing fields")
        if value.get("schema") != ASSIGNMENT_SCHEMA or value.get("status") != "finalized":
            raise ProviderJuryWorkerError("Provider jury assignment is not finalized")
        normalized = {
            "schema": ASSIGNMENT_SCHEMA,
            "status": "finalized",
            "network_id": _network_id(value.get("network_id")),
            "chain_id": _uint(value.get("chain_id"), "assignment chain_id", maximum=2**256 - 1),
            "settlement_contract": _address(value.get("settlement_contract"), "assignment Settlement"),
            "jury_registry": _address(value.get("jury_registry"), "assignment Registry"),
            "settlement_key": _bytes32(value.get("settlement_key"), "assignment settlement key"),
            "assignment_hash": _bytes32(value.get("assignment_hash"), "assignment hash"),
            "threshold": _uint(value.get("threshold"), "assignment threshold", maximum=7),
            "selected_providers": _frozen_json(value.get("selected_providers"), "selected Providers"),
            "block_number": _uint(value.get("block_number"), "assignment block number"),
            "block_hash": _bytes32(value.get("block_hash"), "assignment block hash"),
        }
        for field in ("network_id", "chain_id", "settlement_contract", "jury_registry", "settlement_key"):
            if normalized[field] != binding[field]:
                raise ProviderJuryWorkerError("jury assignment belongs to another deployment or case")
        providers = normalized["selected_providers"]
        if not isinstance(providers, list) or len(providers) != self.jury_size:
            raise ProviderJuryWorkerError("jury assignment does not contain the pinned jury size")
        if normalized["threshold"] != self.adjudication_threshold:
            raise ProviderJuryWorkerError("jury assignment threshold differs from deployment policy")
        # build_jury_task performs the complete selected-Provider schema and
        # capability validation.  These checks additionally enforce the
        # independent high-reputation properties before any inference call.
        try:
            reputations = [item.get("reputation") for item in providers]
            vote_signers = [item.get("vote_signer") for item in providers]
            owners = [item.get("owner") for item in providers]
            operators = [item.get("operator_id_hash") for item in providers]
            peers = [item.get("peer_id_hash") for item in providers]
        except AttributeError as exc:
            raise ProviderJuryWorkerError("selected Provider snapshots must be objects") from exc
        if any(type(score) is not int or score < self.minimum_reputation for score in reputations):
            raise ProviderJuryWorkerError("jury assignment contains a low-reputation Provider")
        for values in (vote_signers, owners, operators, peers):
            try:
                independent = len(set(values)) == len(providers)
            except TypeError as exc:
                raise ProviderJuryWorkerError(
                    "jury assignment Provider identity fields must be scalar values"
                ) from exc
            if not independent:
                raise ProviderJuryWorkerError("jury assignment Provider identities are not independent")
        if set(owners) & set(vote_signers):
            raise ProviderJuryWorkerError(
                "jury assignment must separate every Provider owner and vote signer"
            )
        return normalized

    def collect_and_admit(
        self, *, settlement_key: str, evidence: Mapping[str, Any],
        inference_request: Mapping[str, Any], fetch_assignment: AssignmentFetcher,
        invoke_provider: ProviderInvoker,
        finalize_assignment: AssignmentFinalizer | None = None,
        task_ttl_seconds: int = 300, now: int | None = None,
    ) -> dict[str, Any]:
        """Durably prepare one task set, then collect a Provider-AI quorum.

        Tasks are committed before the first network call.  A partial failure
        or Relay restart therefore retries the exact same signed tasks; it can
        never strand a case by presenting a Provider with a second task for an
        assignment it has already executed.
        """
        with self._collection_lock:
            return self._collect_and_admit(
                settlement_key=settlement_key,
                evidence=evidence,
                inference_request=inference_request,
                fetch_assignment=fetch_assignment,
                invoke_provider=invoke_provider,
                finalize_assignment=finalize_assignment,
                task_ttl_seconds=task_ttl_seconds,
                now=now,
            )

    def _collect_and_admit(
        self, *, settlement_key: str, evidence: Mapping[str, Any],
        inference_request: Mapping[str, Any], fetch_assignment: AssignmentFetcher,
        invoke_provider: ProviderInvoker,
        finalize_assignment: AssignmentFinalizer | None = None,
        task_ttl_seconds: int = 300, now: int | None = None,
    ) -> dict[str, Any]:
        """Fetch/finalize an assignment, call its Providers, and persist a plan.

        A finalized assignment callback must return exactly::

            {schema,status,network_id,chain_id,settlement_contract,jury_registry,
             settlement_key,assignment_hash,threshold,selected_providers,
             block_number,block_hash}

        ``selected_providers`` use the signed snapshot schema accepted by
        :func:`gateway.provider_jury.build_jury_task`.  A non-finalized fetch
        result is handed to ``finalize_assignment(binding, fetched)``.
        """
        if not callable(fetch_assignment) or not callable(invoke_provider):
            raise ProviderJuryWorkerError("assignment fetch and Provider invocation callbacks are required")
        timestamp = int(time.time()) if now is None else _uint(now, "jury collection time")
        ttl = _uint(task_ttl_seconds, "jury task TTL", maximum=provider_jury.MAX_TASK_TTL_SECONDS)
        if ttl < 1:
            raise ProviderJuryWorkerError("jury task TTL must be positive")
        binding = self._binding(settlement_key)
        frozen_evidence = _frozen_json(evidence, "jury evidence")
        frozen_inference = _frozen_json(inference_request, "jury inference request")
        existing = self.get(binding["settlement_key"])
        if existing is not None:
            saved = self.get_plan(binding["settlement_key"])
            if (saved is None or saved.get("evidence") != frozen_evidence
                    or saved.get("inference_request") != frozen_inference):
                raise ProviderJuryWorkerError("case was already admitted with different evidence or policy")
            return existing

        fetched = fetch_assignment(dict(binding))
        if not isinstance(fetched, Mapping):
            raise ProviderJuryWorkerError("assignment fetch callback returned no assignment")
        if fetched.get("status") != "finalized":
            if not callable(finalize_assignment):
                raise ProviderJuryWorkerError("jury assignment requires finalization")
            fetched = finalize_assignment(dict(binding), dict(fetched))
        assignment = self._assignment(fetched, binding=binding)

        try:
            policy_hash = provider_jury.decision_policy_hash(
                model=frozen_inference.get("model"),
                system_prompt=frozen_inference.get("system_prompt"),
                max_output_tokens=frozen_inference.get("max_output_tokens"),
                task_ttl_seconds=ttl,
            )
        except provider_jury.ProviderJuryError as exc:
            raise ProviderJuryWorkerError(f"invalid Provider jury decision policy: {exc}") from exc
        if policy_hash != self.decision_policy_hash:
            raise ProviderJuryWorkerError("Provider jury inference policy differs from deployment")
        assignment, tasks = self._prepare_collection(
            binding=binding,
            assignment=assignment,
            evidence=frozen_evidence,
            inference_request=frozen_inference,
            policy_hash=policy_hash,
            timestamp=timestamp,
            ttl=ttl,
        )

        verified: list[dict[str, Any]] = []
        task_map = {evidence_hash(task): task for task in tasks}
        invocation_errors: list[dict[str, str]] = []

        def invoke_one(task: dict[str, Any]) -> dict[str, Any]:
            raw_verdict = invoke_provider(dict(task))
            verification_now = timestamp if now is not None else int(time.time())
            checked = provider_jury.verify_provider_verdict(
                raw_verdict, task=task, now=verification_now,
            )
            return {
                "raw": _frozen_json(raw_verdict, "Provider verdict"),
                "checked": checked,
            }

        # Jury members are independent services. Calling them serially turns a
        # 3–7 member quorum into N times the Provider timeout and can consume the
        # whole adjudication window. Invoke every selected Provider concurrently
        # while retaining a deterministic task/verdict audit trail below.
        with ThreadPoolExecutor(
            max_workers=len(tasks), thread_name_prefix="mycomesh-provider-jury",
        ) as executor:
            futures = {executor.submit(invoke_one, task): task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                try:
                    verified.append(future.result())
                except Exception as exc:
                    invocation_errors.append({
                        "peer_id": task["selected_provider"]["peer_id"],
                        "error_code": type(exc).__name__,
                    })

        # Parallel completion order is nondeterministic; plans and their hashes
        # must be stable for the same signed evidence.
        verified.sort(key=lambda item: item["checked"]["provider"]["vote_signer"])
        invocation_errors.sort(key=lambda item: (item["peer_id"], item["error_code"]))

        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for item in verified:
            checked = item["checked"]
            groups.setdefault((checked["context_hash"], checked["decision_hash"]), []).append(item)
        candidates = [items for items in groups.values()
                      if len(items) >= self.adjudication_threshold]
        if len(candidates) != 1:
            detail = ",".join(item["error_code"] for item in invocation_errors) \
                or "conflicting_verdicts"
            raise ProviderJuryWorkerError(
                f"selected Provider AIs did not form one strict-majority quorum ({detail})"
            )
        selected_quorum = sorted(
            candidates[0], key=lambda item: item["checked"]["provider"]["vote_signer"],
        )[: self.adjudication_threshold]
        raw_verdicts = [item["raw"] for item in selected_quorum]
        try:
            quorum_now = timestamp if now is not None else int(time.time())
            quorum = provider_jury.aggregate_quorum(
                raw_verdicts, tasks=task_map,
                threshold=self.adjudication_threshold, now=quorum_now,
            )
        except provider_jury.ProviderJuryError as exc:
            raise ProviderJuryWorkerError(f"Provider AI quorum is invalid: {exc}") from exc

        quorum_task_hashes = {item["task_hash"] for item in raw_verdicts}
        quorum_tasks = [task for task in tasks if evidence_hash(task) in quorum_task_hashes]
        votes = [{
            "judge": permit["judge"],
            "nonce": permit["nonce"],
            "deadline": permit["deadline"],
            "signature": permit["signature"],
        } for permit in quorum["vote_permits"]]
        vote_plan = {
            "schema": VOTE_PLAN_SCHEMA,
            "chain_id": self.chain_id,
            "settlement_contract": self.settlement_contract,
            "settlement_key": quorum["settlement_key"],
            "assignment_hash": quorum["assignment_hash"],
            "confirmed": quorum["confirmed"],
            "report_id": quorum["report_id"],
            "decision_hash": quorum["decision_hash"],
            "to": self.settlement_contract,
            "value": "0x0",
            "votes": votes,
            "vote_permits": quorum["vote_permits"],
            "data": quorum["calldata"],
            "broadcast": False,
        }
        case_key = self._key(binding["settlement_key"])
        body = {
            "schema": PLAN_SCHEMA,
            "case_key": case_key,
            "network_id": self.network_id,
            "policy": {
                "minimum_reputation": self.minimum_reputation,
                "jury_size": self.jury_size,
                "adjudication_threshold": self.adjudication_threshold,
                "decision_policy_hash": self.decision_policy_hash,
            },
            "assignment": assignment,
            "evidence": frozen_evidence,
            "inference_request": frozen_inference,
            "decision_policy_hash": policy_hash,
            "jury_tasks": tasks,
            "provider_verdicts": [item["raw"] for item in verified],
            "provider_failures": invocation_errors,
            "quorum_tasks": quorum_tasks,
            "quorum_verdicts": raw_verdicts,
            "evm_vote": vote_plan,
            # A strict-majority dismissal is monetary too: it releases the
            # escrow and forfeits the owner's report bond. Both outcomes carry
            # the exact on-chain permit threshold and are therefore executable.
            "automatic_execution_allowed": True,
            "broadcast": False,
        }
        plan = {**body, "plan_hash": evidence_hash(body)}
        self._admit(plan, created_at=timestamp)
        saved = self.get(binding["settlement_key"])
        assert saved is not None
        return saved

    @staticmethod
    def _immutable_assignment(value: Mapping[str, Any]) -> dict[str, Any]:
        return {name: item for name, item in value.items()
                if name not in {"block_number", "block_hash"}}

    def _prepare_collection(
        self, *, binding: Mapping[str, Any], assignment: Mapping[str, Any],
        evidence: Mapping[str, Any], inference_request: Mapping[str, Any],
        policy_hash: str, timestamp: int, ttl: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Commit or load the one immutable task set for a jury case."""
        case_key = self._key(str(binding["settlement_key"]))
        new_tasks: list[dict[str, Any]] = []
        for index, selected in enumerate(assignment["selected_providers"]):
            try:
                task = provider_jury.build_jury_task(
                    network_id=self.network_id,
                    chain_id=self.chain_id,
                    settlement_contract=self.settlement_contract,
                    jury_registry=self.jury_registry,
                    settlement_key=str(binding["settlement_key"]),
                    assignment_hash=str(assignment["assignment_hash"]),
                    selected_provider=selected,
                    evidence=evidence,
                    decision_policy_hash=policy_hash,
                    inference_request=inference_request,
                    relay_identity=self.relay_identity,
                    issued_at=timestamp,
                    deadline=timestamp + ttl,
                    nonce=evidence_hash({
                        "schema": "mycomesh.v10.provider-jury-task-nonce.v1",
                        "assignment_hash": assignment["assignment_hash"],
                        "provider_index": index,
                        "entropy": secrets.token_hex(32),
                    }),
                )
            except provider_jury.ProviderJuryError as exc:
                raise ProviderJuryWorkerError(
                    f"cannot build assignment-bound jury task: {exc}"
                ) from exc
            new_tasks.append(task)
        proposed = {
            "assignment": _frozen_json(assignment, "jury assignment"),
            "evidence": _frozen_json(evidence, "jury evidence"),
            "inference_request": _frozen_json(
                inference_request, "jury inference request"
            ),
            "decision_policy_hash": policy_hash,
            "jury_tasks": new_tasks,
        }
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM provider_jury_collections WHERE case_key=?",
                    (case_key,),
                ).fetchone()
                if row is None:
                    self._db.execute(
                        """INSERT INTO provider_jury_collections(
                               case_key,settlement_key,assignment_hash,
                               collection_json,created_at,deadline)
                           VALUES (?,?,?,?,?,?)""",
                        (case_key, binding["settlement_key"], assignment["assignment_hash"],
                         _canonical(proposed), timestamp, timestamp + ttl),
                    )
                    saved = proposed
                    deadline = timestamp + ttl
                else:
                    saved = json.loads(row["collection_json"])
                    deadline = int(row["deadline"])
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise
        saved_assignment = saved.get("assignment") if isinstance(saved, Mapping) else None
        saved_tasks = saved.get("jury_tasks") if isinstance(saved, Mapping) else None
        if (not isinstance(saved_assignment, Mapping)
                or not isinstance(saved_tasks, list)
                or len(saved_tasks) != self.jury_size
                or saved.get("evidence") != evidence
                or saved.get("inference_request") != inference_request
                or saved.get("decision_policy_hash") != policy_hash
                or self._immutable_assignment(saved_assignment)
                != self._immutable_assignment(assignment)):
            raise ProviderJuryWorkerError(
                "durable jury collection differs from the canonical case"
            )
        if timestamp > deadline:
            raise ProviderJuryWorkerError(
                "durable jury task set expired before a quorum was formed"
            )
        checked_tasks: list[dict[str, Any]] = []
        for task, selected in zip(saved_tasks, saved_assignment["selected_providers"]):
            try:
                provider_jury.verify_jury_task(
                    task,
                    expected_relay_public_key=self.relay_identity.public_key,
                    expected_assignment_hash=str(saved_assignment["assignment_hash"]),
                    expected_provider=selected,
                    now=timestamp,
                )
            except provider_jury.ProviderJuryError as exc:
                raise ProviderJuryWorkerError(
                    f"durable jury task is invalid: {exc}"
                ) from exc
            checked_tasks.append(dict(task))
        return dict(saved_assignment), checked_tasks

    def _admit(self, plan: Mapping[str, Any], *, created_at: int) -> None:
        assignment = plan["assignment"]
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT plan_hash FROM provider_jury_executions WHERE case_key=?",
                    (plan["case_key"],),
                ).fetchone()
                if existing is not None:
                    if existing["plan_hash"] != plan["plan_hash"]:
                        raise ProviderJuryWorkerError("case already has a different durable jury plan")
                    self._db.commit()
                    return
                self._db.execute(
                    """INSERT INTO provider_jury_executions(
                           case_key,settlement_key,assignment_hash,plan_hash,plan_json,status,
                           result_json,error_code,created_at,updated_at,lease_owner,
                           lease_expires_at,attempts)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (plan["case_key"], assignment["settlement_key"],
                     assignment["assignment_hash"], plan["plan_hash"], _canonical(plan),
                     "admitted", None, None, created_at, created_at, None, None, 0),
                )
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def recover_expired_leases(
        self, *, now: int | None = None,
        broadcast_recorded: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> int:
        timestamp = int(time.time()) if now is None else _uint(now, "lease recovery time")
        with self._lock:
            if broadcast_recorded is not None:
                if not callable(broadcast_recorded):
                    raise ProviderJuryWorkerError("broadcast_recorded must be callable")
                rows = self._db.execute(
                    """SELECT case_key,plan_json FROM provider_jury_executions
                       WHERE status='executing'
                             AND (lease_expires_at IS NULL OR lease_expires_at<=?)""",
                    (timestamp,),
                ).fetchall()
                recovered = 0
                for row in rows:
                    try:
                        recorded = broadcast_recorded(json.loads(row["plan_json"]))
                        if type(recorded) is not bool:
                            raise TypeError("broadcast_recorded must return a boolean")
                    except Exception:
                        # Failure to prove absence remains uncertain. Never turn
                        # an inspection outage into permission for a second send.
                        recorded = True
                    status = "uncertain" if recorded else "admitted"
                    error = "execution_lease_expired" if recorded else "lease_expired_before_outbox"
                    cursor = self._db.execute(
                        """UPDATE provider_jury_executions
                           SET status=?,error_code=?,lease_owner=NULL,lease_expires_at=NULL,
                               attempts=CASE WHEN ?=0 AND attempts>0 THEN attempts-1 ELSE attempts END,
                               updated_at=?
                           WHERE case_key=? AND status='executing'
                                 AND (lease_expires_at IS NULL OR lease_expires_at<=?)""",
                        (status, error, int(recorded), timestamp, row["case_key"], timestamp),
                    )
                    recovered += cursor.rowcount
                return recovered
            cursor = self._db.execute(
                """UPDATE provider_jury_executions
                   SET status='uncertain',error_code='execution_lease_expired',
                       lease_owner=NULL,lease_expires_at=NULL,updated_at=?
                   WHERE status='executing'
                         AND (lease_expires_at IS NULL OR lease_expires_at<=?)""",
                (timestamp, timestamp),
            )
            return cursor.rowcount

    def _validate_result(
        self, result: Mapping[str, Any], *, plan: Mapping[str, Any],
        existing: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            return _execution_result(
                result, plan=plan, existing=existing,
                required_confirmations=self.required_confirmations,
            )
        except V10EnforcementError as exc:
            raise ProviderJuryWorkerError(f"invalid jury transaction observation: {exc}") from exc

    def execute(
        self, settlement_key: str, *, broadcast: Broadcaster,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Acquire one lease and call the keeper at most once for this case."""
        if not callable(broadcast):
            raise ProviderJuryWorkerError("execution requires a broadcast callback")
        if not self.execution_enabled:
            raise ProviderJuryWorkerError("automatic Provider jury execution is disabled")
        timestamp = int(time.time()) if now is None else _uint(now, "execution time")
        self.recover_expired_leases(now=timestamp)
        case_key = self._key(settlement_key)
        lease_owner = secrets.token_hex(16)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM provider_jury_executions WHERE case_key=?", (case_key,),
                ).fetchone()
                if row is None:
                    raise ProviderJuryWorkerError("unknown Provider jury case")
                if row["status"] != "admitted":
                    saved = self._public_row(row)
                    assert saved is not None
                    self._db.commit()
                    return saved
                plan = json.loads(row["plan_json"])
                vote_plan = plan.get("evm_vote")
                if (plan.get("automatic_execution_allowed") is not True
                        or not isinstance(vote_plan, Mapping)
                        or type(vote_plan.get("confirmed")) is not bool
                        or not isinstance(vote_plan.get("data"), str)
                        or not vote_plan["data"].startswith("0x")):
                    raise ProviderJuryWorkerError(
                        "saved Provider jury plan is not automatically executable"
                    )
                votes = vote_plan.get("votes")
                permits = vote_plan.get("vote_permits")
                if (not isinstance(votes, list) or not isinstance(permits, list)
                        or len(votes) != self.adjudication_threshold
                        or len(permits) != self.adjudication_threshold
                        or any(type(vote.get("deadline")) is not int
                               for vote in votes if isinstance(vote, Mapping))
                        or any(not isinstance(vote, Mapping) for vote in votes)):
                    raise ProviderJuryWorkerError("saved Provider jury vote plan is malformed")
                if any(timestamp > vote["deadline"] for vote in votes):
                    self._db.execute(
                        """UPDATE provider_jury_executions
                           SET status='uncertain',error_code='vote_permit_expired',updated_at=?
                           WHERE case_key=? AND status='admitted'""",
                        (timestamp, case_key),
                    )
                    updated = self._db.execute(
                        "SELECT * FROM provider_jury_executions WHERE case_key=?", (case_key,),
                    ).fetchone()
                    saved = self._public_row(updated)
                    assert saved is not None
                    self._db.commit()
                    return saved
                cursor = self._db.execute(
                    """UPDATE provider_jury_executions
                       SET status='executing',lease_owner=?,lease_expires_at=?,
                           attempts=attempts+1,updated_at=?,error_code=NULL
                       WHERE case_key=? AND status='admitted'""",
                    (lease_owner, timestamp + self.lease_seconds, timestamp, case_key),
                )
                if cursor.rowcount != 1:
                    raise ProviderJuryWorkerError("could not acquire Provider jury execution lease")
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise
        try:
            raw_result = broadcast(plan)
            result = self._validate_result(raw_result, plan=plan)
        except Exception as exc:
            if getattr(exc, "definitely_not_sent", False) is True:
                with self._lock:
                    self._db.execute(
                        """UPDATE provider_jury_executions
                           SET status='admitted',
                               attempts=CASE WHEN attempts>0 THEN attempts-1 ELSE 0 END,
                               error_code=?,lease_owner=NULL,lease_expires_at=NULL,updated_at=?
                           WHERE case_key=? AND status='executing' AND lease_owner=?""",
                        (type(exc).__name__, int(time.time()), case_key, lease_owner),
                    )
                raise ProviderJuryWorkerError(
                    "Provider jury transaction was definitely not sent; case remains admitted"
                ) from exc
            with self._lock:
                self._db.execute(
                    """UPDATE provider_jury_executions
                       SET status='uncertain',error_code=?,lease_owner=NULL,
                           lease_expires_at=NULL,updated_at=?
                       WHERE case_key=? AND status='executing' AND lease_owner=?""",
                    (type(exc).__name__, int(time.time()), case_key, lease_owner),
                )
            raise ProviderJuryWorkerError(
                "Provider jury execution is uncertain; reconcile the original transaction"
            ) from exc
        with self._lock:
            cursor = self._db.execute(
                """UPDATE provider_jury_executions
                   SET status=?,result_json=?,error_code=NULL,lease_owner=NULL,
                       lease_expires_at=NULL,updated_at=?
                   WHERE case_key=? AND status='executing' AND lease_owner=?""",
                (result["status"], _canonical(result), int(time.time()), case_key, lease_owner),
            )
            if cursor.rowcount != 1:
                raise ProviderJuryWorkerError("jury execution lease was lost before persistence")
        saved = self.get(settlement_key)
        assert saved is not None
        return saved

    def record_result(self, settlement_key: str, result: Mapping[str, Any]) -> dict[str, Any]:
        """Persist a pinned-chain observation; this method never broadcasts."""
        case_key = self._key(settlement_key)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM provider_jury_executions WHERE case_key=?", (case_key,),
                ).fetchone()
                if row is None:
                    raise ProviderJuryWorkerError("unknown Provider jury case")
                if row["status"] not in {"uncertain", "submitted", "confirmed"}:
                    raise ProviderJuryWorkerError(
                        "only uncertain or submitted jury executions may be reconciled"
                    )
                plan = json.loads(row["plan_json"])
                existing = json.loads(row["result_json"]) if row["result_json"] else None
                checked = self._validate_result(result, plan=plan, existing=existing)
                self._db.execute(
                    """UPDATE provider_jury_executions
                       SET status=?,result_json=?,error_code=NULL,lease_owner=NULL,
                           lease_expires_at=NULL,updated_at=? WHERE case_key=?""",
                    (checked["status"], _canonical(checked), int(time.time()), case_key),
                )
                updated = self._db.execute(
                    "SELECT * FROM provider_jury_executions WHERE case_key=?", (case_key,),
                ).fetchone()
                saved = self._public_row(updated)
                assert saved is not None
                self._db.commit()
                return saved
            except BaseException:
                self._db.rollback()
                raise

    def reconcile(self, settlement_key: str, *, inspect: Inspector) -> dict[str, Any]:
        if not callable(inspect):
            raise ProviderJuryWorkerError("reconciliation requires a chain inspection callback")
        plan = self.get_plan(settlement_key)
        current = self.get(settlement_key)
        if plan is None or current is None:
            raise ProviderJuryWorkerError("unknown Provider jury case")
        return self.record_result(settlement_key, inspect(plan, current))


__all__ = [
    "ASSIGNMENT_SCHEMA", "CASE_SCHEMA", "PLAN_SCHEMA", "VOTE_PLAN_SCHEMA",
    "ProviderJuryRelayWorker", "ProviderJuryWorkerError",
    "WORKER_STORAGE_HEALTH_SCHEMA",
]
