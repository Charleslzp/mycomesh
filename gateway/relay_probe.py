"""Durable synthetic probes and an opt-in, bounded local probe coordinator.

These probes check a small JSON/arithmetic capability, NOT the identity of a
model, the Provider's software, or grounds for a financial penalty. A dispatch
adapter must independently verify the transport, signed receipt, response body,
and actual inference request before constructing ``VerifiedProbeResponse``.
The coordinator never signs payments, trusts Provider-supplied verdicts, or
issues rewards. No work is dispatched unless explicitly enabled.
"""

from __future__ import annotations

import hashlib
import json
import math
import queue
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping


class RelayProbeError(RuntimeError):
    pass


def _text(value: Any, name: str, limit: int = 256) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > limit or any(ord(char) < 32 for char in value)
    ):
        raise RelayProbeError(f"invalid {name}")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise RelayProbeError(f"invalid {name}; expected a 32-byte hex digest")
    return value.lower()


def _canonical(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise RelayProbeError("probe data must be finite JSON") from exc
    if len(encoded.encode("utf-8")) > 32768:
        raise RelayProbeError("probe data exceeds the size limit")
    return encoded


def probe_digest(value: Mapping[str, Any]) -> str:
    """Hash the local probe envelope; this is NOT a V8 inference request hash."""
    return "0x" + hashlib.sha256(_canonical(dict(value)).encode("utf-8")).hexdigest()


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RelayProbeError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


class RelayProbeStore:
    """One lifecycle connection per store, serialized locally and by SQLite.

    ``BEGIN IMMEDIATE`` covers read/compare/write, including across processes.
    Retrying a completed probe is permitted only for the identical full result,
    even after its original challenge expires. The caller is trusted local
    verification code: this is deliberately not a public result-submission API.
    """

    def __init__(self, path: str, *, clock: Callable[[], float] = time.time) -> None:
        self.path = _text(path, "probe database path", 4096)
        self._clock = clock
        self._lock = threading.RLock()
        self._closed = False
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        with self._transaction() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS probes (
                    probe_id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    nonce TEXT NOT NULL UNIQUE,
                    probe_class TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    expected_digest TEXT,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'issued',
                    result_hash TEXT,
                    evidence_json TEXT,
                    request_json TEXT
                )"""
            )
            # Preserve databases created by the first implementation.
            columns = {row["name"] for row in db.execute("PRAGMA table_info(probes)")}
            if "request_json" not in columns:
                db.execute("ALTER TABLE probes ADD COLUMN request_json TEXT")
            db.execute("CREATE INDEX IF NOT EXISTS probes_provider_status ON probes(provider_id, status, expires_at)")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RelayProbeError("probe store is closed")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.rollback()
                raise
            else:
                self._db.commit()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self) -> RelayProbeStore:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def issue(
        self,
        *,
        provider_id: str,
        probe_class: str,
        request_hash: str,
        expected_digest: str | None = None,
        ttl_seconds: int = 120,
        nonce: str | None = None,
        request: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        provider_id = _text(provider_id, "provider_id")
        probe_class = _text(probe_class, "probe_class", 64)
        request_hash = _digest(request_hash, "request_hash")
        expected_digest = None if expected_digest is None else _digest(expected_digest, "expected_digest")
        ttl = _integer(ttl_seconds, "probe ttl", 1, 900)
        now = _integer(int(self._clock()), "current time", 0, (1 << 63) - 901)
        nonce = secrets.token_hex(24) if nonce is None else nonce
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{48}", nonce):
            raise RelayProbeError("invalid probe nonce")
        request_json = None
        if request is not None:
            if not isinstance(request, Mapping):
                raise RelayProbeError("probe request must be a mapping")
            request_json = _canonical(dict(request))
            if probe_digest(request) != request_hash:
                raise RelayProbeError("probe request hash mismatch")
            if request.get("nonce") != nonce:
                raise RelayProbeError("probe request nonce mismatch")
        probe_id = "probe_" + uuid.uuid4().hex
        try:
            with self._transaction() as db:
                db.execute(
                    """INSERT INTO probes
                    (probe_id, provider_id, nonce, probe_class, request_hash,
                     expected_digest, issued_at, expires_at, request_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (probe_id, provider_id, nonce, probe_class, request_hash,
                     expected_digest, now, now + ttl, request_json),
                )
        except sqlite3.IntegrityError as exc:
            raise RelayProbeError("probe identifier or nonce already exists") from exc
        return {"probe_id": probe_id, "provider_id": provider_id, "nonce": nonce,
                "probe_class": probe_class, "request_hash": request_hash,
                "issued_at": now, "expires_at": now + ttl}

    def get(self, probe_id: str) -> dict[str, Any]:
        probe_id = _text(probe_id, "probe_id")
        with self._transaction() as db:
            row = db.execute("SELECT * FROM probes WHERE probe_id = ?", (probe_id,)).fetchone()
        if row is None:
            raise RelayProbeError("unknown probe")
        return dict(row)

    def record_result(
        self,
        *,
        probe_id: str,
        nonce: str,
        provider_id: str,
        passed: bool,
        result_hash: str,
        evidence: Mapping[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        probe_id = _text(probe_id, "probe_id")
        provider_id = _text(provider_id, "provider_id")
        nonce = _text(nonce, "nonce", 128)
        if type(passed) is not bool:
            raise RelayProbeError("passed must be a boolean")
        result_hash = _digest(result_hash, "result_hash")
        if evidence is not None and not isinstance(evidence, Mapping):
            raise RelayProbeError("probe evidence must be a mapping")
        current = _integer(int(self._clock()) if now is None else now, "current time", 0, (1 << 63) - 1)
        encoded = _canonical({"passed": passed, "result_hash": result_hash, "evidence": dict(evidence or {})})
        with self._transaction() as db:
            row = db.execute("SELECT * FROM probes WHERE probe_id = ?", (probe_id,)).fetchone()
            if row is None:
                raise RelayProbeError("unknown probe")
            if row["provider_id"] != provider_id or row["nonce"] != nonce:
                raise RelayProbeError("probe provider or nonce mismatch")
            if current < int(row["issued_at"]):
                raise RelayProbeError("probe result predates its challenge")
            if row["status"] == "completed":
                if row["result_hash"] != result_hash or row["evidence_json"] != encoded:
                    raise RelayProbeError("probe result conflicts with the recorded result")
                return dict(row)
            if current >= int(row["expires_at"]):
                raise RelayProbeError("probe has expired")
            if row["status"] != "issued":
                raise RelayProbeError("probe is not accepting a result")
            updated = db.execute(
                """UPDATE probes SET status='completed', result_hash=?, evidence_json=?
                WHERE probe_id=? AND status='issued'""", (result_hash, encoded, probe_id)
            )
            if updated.rowcount != 1:
                raise RelayProbeError("probe result transition conflicted")
            result = db.execute("SELECT * FROM probes WHERE probe_id = ?", (probe_id,)).fetchone()
        assert result is not None
        return dict(result)

    def expire(self, *, now: int | None = None) -> int:
        current = _integer(int(self._clock()) if now is None else now, "current time", 0, (1 << 63) - 1)
        with self._transaction() as db:
            cursor = db.execute(
                "UPDATE probes SET status='expired' WHERE status='issued' AND expires_at <= ?", (current,)
            )
            return int(cursor.rowcount)


@dataclass(frozen=True)
class VerifiedProbeResponse:
    """Trusted adapter result, never deserialize this directly from a Provider.

    ``request_hash`` binds the canonical local probe envelope. The adapter must
    also check the DIFFERENT protocol-specific request hash and signed response
    itself. ``receipt_hash`` identifies the evidence retained by that adapter;
    possession of either hash by itself is not a proof of authenticity.
    """

    provider_id: str
    request_hash: str
    output_text: str
    receipt_hash: str


@dataclass
class _ProbeTask:
    challenge: dict[str, Any]
    request: dict[str, Any]
    expected: dict[str, Any]
    deadline: float
    finished: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=1))
    reported: bool = False


class RelayProbeCoordinator:
    """Opt-in soft capability checks with explicit concurrency/rate limits.

    ``tick`` only polls/starts daemon dispatches and never waits on a Provider.
    A timed-out callback continues to consume its capacity slot until it really
    exits; repeated timeouts cannot create an unbounded number of threads.
    The trusted dispatch adapter MUST enforce its transport timeout and its own
    prepaid/sponsor budget. This module deliberately has no payment authority.
    Per-interval call limits are local process limits, not a financial budget.
    """

    def __init__(
        self,
        store: RelayProbeStore,
        dispatch: Callable[[str, Mapping[str, Any], float], VerifiedProbeResponse],
        *,
        enabled: bool = False,
        observation_callback: Callable[[Mapping[str, Any]], None] | None = None,
        interval_seconds: float = 60,
        timeout_seconds: float = 10,
        max_inflight: int = 1,
        max_probes_per_interval: int = 2,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(enabled) is not bool:
            raise RelayProbeError("enabled must be a boolean")
        for name, value in (("interval_seconds", interval_seconds), ("timeout_seconds", timeout_seconds)):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 600:
                raise RelayProbeError(f"{name} must be finite and between 0 and 600")
        self.max_inflight = _integer(max_inflight, "max_inflight", 1, 16)
        self.max_probes_per_interval = _integer(max_probes_per_interval, "max_probes_per_interval", 1, 100)
        if not callable(dispatch) or (observation_callback is not None and not callable(observation_callback)):
            raise RelayProbeError("probe dispatch and observation callback must be callable")
        self.store, self.dispatch, self.enabled = store, dispatch, enabled
        self.observation_callback = observation_callback
        self.interval_seconds, self.timeout_seconds = float(interval_seconds), float(timeout_seconds)
        self._clock = clock
        self._window_started = clock()
        self._window_count = 0
        self._window_providers: set[str] = set()
        self._candidate_cursor = 0
        self._tasks: dict[str, _ProbeTask] = {}
        self._lock = threading.RLock()
        self._stopped = threading.Event()

    @property
    def inflight_count(self) -> int:
        with self._lock:
            return len(self._tasks)

    def stop(self) -> None:
        """Cancel new work without waiting for a tick's persistence/callback lock."""
        self._stopped.set()

    def _dispatch(self, task: _ProbeTask) -> None:
        try:
            if self._stopped.is_set():
                task.finished.put_nowait((self._clock(), None, "StoppedBeforeDispatch"))
                return
            # Isolate mutable adapter inputs from the evidence/evaluator copy.
            response = self.dispatch(task.challenge["provider_id"], dict(task.request), self.timeout_seconds)
            task.finished.put_nowait((self._clock(), response, None))
        except BaseException as exc:
            # Never persist exception messages: adapters may include secrets.
            task.finished.put_nowait((self._clock(), None, type(exc).__name__))

    def _start(self, provider_id: str, now: float) -> None:
        if self._stopped.is_set():
            return
        nonce = secrets.token_hex(24)
        left, right = secrets.randbelow(999) + 1, secrets.randbelow(999) + 1
        expected = {"nonce": nonce, "sum": left + right}
        request = {
            "probe_class": "json_arithmetic_v1", "nonce": nonce,
            "input": f'Return only a JSON object with exactly two fields: "nonce" equal to "{nonce}" and "sum" equal to {left} + {right}.',
            "max_output_tokens": 96,
        }
        challenge = self.store.issue(
            provider_id=provider_id, probe_class=request["probe_class"],
            nonce=nonce, request=request, request_hash=probe_digest(request),
            expected_digest=probe_digest(expected), ttl_seconds=math.ceil(self.timeout_seconds) + 60,
        )
        task = _ProbeTask(challenge, request, expected, now + self.timeout_seconds)
        self._tasks[challenge["probe_id"]] = task
        self._window_count += 1
        self._window_providers.add(provider_id)
        if self._stopped.is_set():
            # stop may race a durable challenge write. Keep the challenge for
            # drain to finalize inconclusively, but do not call the adapter.
            task.finished.put_nowait((self._clock(), None, "StoppedBeforeDispatch"))
            return
        try:
            threading.Thread(target=self._dispatch, args=(task,), name="relay-capability-probe", daemon=True).start()
        except RuntimeError:
            # Treat local resource exhaustion as a dispatch error, not a stuck
            # in-flight call. The next tick records it without invoking Provider.
            task.finished.put_nowait((self._clock(), None, "ThreadStartError"))

    @staticmethod
    def _evaluate(task: _ProbeTask, response: Any) -> tuple[bool, str, dict[str, Any]]:
        if type(response) is not VerifiedProbeResponse:
            return False, "unverified_response", {}
        if response.provider_id != task.challenge["provider_id"] or response.request_hash != task.challenge["request_hash"]:
            return False, "response_binding_mismatch", {}
        try:
            receipt_hash = _digest(response.receipt_hash, "receipt_hash")
        except RelayProbeError:
            return False, "invalid_receipt_reference", {}
        if not isinstance(response.output_text, str) or len(response.output_text) > 4096:
            return False, "invalid_output", {"receipt_hash": receipt_hash}
        details = {"output_text": response.output_text, "receipt_hash": receipt_hash}

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        try:
            decoded = json.loads(response.output_text, object_pairs_hook=unique_object)
            passed = (type(decoded) is dict and set(decoded) == {"nonce", "sum"}
                      and type(decoded.get("sum")) is int and decoded == task.expected)
        except (ValueError, RecursionError):
            passed = False
        return passed, "passed" if passed else "capability_mismatch", details

    def _finish(self, task: _ProbeTask, response: Any = None, *, failure: str | None = None) -> dict[str, Any]:
        passed, outcome, details = (False, failure, {}) if failure else self._evaluate(task, response)
        evidence = {"schema": "mycomesh.relay.probe-observation.v1", "outcome": outcome,
                    "probe_id": task.challenge["probe_id"], "provider_id": task.challenge["provider_id"],
                    "nonce": task.challenge["nonce"], "request_hash": task.challenge["request_hash"],
                    "expected_digest": probe_digest(task.expected), "hard_violation": False, **details}
        # Hash only locally constructed evidence; never accept a Provider verdict/hash.
        result_hash = probe_digest(evidence)
        try:
            record = self.store.record_result(
                probe_id=task.challenge["probe_id"], nonce=task.challenge["nonce"],
                provider_id=task.challenge["provider_id"], passed=passed, result_hash=result_hash, evidence=evidence,
            )
        except (RelayProbeError, sqlite3.Error):
            try:
                self.store.expire()
            except (RelayProbeError, sqlite3.Error):
                pass
            # An expired/unpersistable result is inconclusive and must not affect risk.
            return {"probe_id": task.challenge["probe_id"], "provider_id": task.challenge["provider_id"],
                    "status": "inconclusive", "outcome": "result_not_persisted", "hard_violation": False}
        observation = {"probe_id": record["probe_id"], "provider_id": record["provider_id"],
                       "status": record["status"], "passed": passed, "hard_violation": False,
                       "outcome": outcome, "result_hash": result_hash, "evidence": evidence,
                       "observation_delivered": self.observation_callback is None}
        if self.observation_callback is not None:
            try:
                self.observation_callback(dict(observation))
                observation["observation_delivered"] = True
            except Exception:
                # The durable completed row can be replayed by an idempotent risk
                # consumer. A callback outage must not dispatch the same probe again.
                observation["observation_delivered"] = False
        return observation

    def tick(self, provider_ids: Iterable[str] = ()) -> list[dict[str, Any]]:
        """Poll results then start at most the configured available call budget.

        Enumerate at most 1,024 supplied candidates per tick. This also prevents
        an accidentally infinite provider iterator from blocking the scheduler.
        One provider is probed at most once in a local rate-limit window.
        """
        with self._lock:
            now = self._clock()
            results: list[dict[str, Any]] = []
            for probe_id, task in list(self._tasks.items()):
                try:
                    finished_at, response, error_type = task.finished.get_nowait()
                except queue.Empty:
                    if now >= task.deadline and not task.reported:
                        results.append(self._finish(task, failure="timeout"))
                        task.reported = True
                    continue
                if not task.reported:
                    failure = "timeout" if finished_at >= task.deadline else ("dispatch_error" if error_type else None)
                    results.append(self._finish(task, response, failure=failure))
                self._tasks.pop(probe_id)
            if not self.enabled or self._stopped.is_set():
                return results
            if now - self._window_started >= self.interval_seconds:
                self._window_started = now
                self._window_count = 0
                self._window_providers.clear()
            busy_providers = {task.challenge["provider_id"] for task in self._tasks.values()}
            # Rotate a bounded snapshot so the first providers in a stable
            # registry cannot monopolize every window's small call budget.
            candidates = list(dict.fromkeys(_text(item, "provider_id") for item in islice(provider_ids, 1024)))
            offset = self._candidate_cursor % len(candidates) if candidates else 0
            for index in range(len(candidates)):
                if (self._stopped.is_set() or len(self._tasks) >= self.max_inflight
                        or self._window_count >= self.max_probes_per_interval):
                    break
                candidate_index = (offset + index) % len(candidates)
                provider_id = candidates[candidate_index]
                if provider_id in busy_providers or provider_id in self._window_providers:
                    continue
                self._start(provider_id, now)
                self._candidate_cursor = candidate_index + 1
                busy_providers.add(provider_id)
            return results

    def run(self, provider_supplier: Callable[[], Iterable[str]], stop_event: threading.Event) -> None:
        """Optional interruptible loop; its supplier must be bounded local code."""
        if not self.enabled:
            return
        while not stop_event.is_set():
            if self._stopped.is_set():
                return
            self.tick(provider_supplier())
            stop_event.wait(min(0.25, self.timeout_seconds, self.interval_seconds))
        self.stop()
