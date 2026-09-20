"""Local evidence ledger, not an adjudicator or payment authority.

Evidence must contain artifacts needed by an independent verifier: hashing an
allegation does not prove it. Callers verify signatures before recording a hard
protocol violation. Soft/probabilistic failures never quarantine. Only a locally
authorized operator should invoke clear_quarantine; there is no public route.

Migration preserves historical IDs and reward intents. Exact legacy duplicates
resolve to their first ID; conflicting legacy observations are retained and
blocked from reuse pending review. Existing quarantines, including ones caused
by the old soft-failure rule, remain sticky until explicitly cleared. No method
establishes cross-relay consensus or makes an unfunded bounty spendable.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def evidence_hash(value: Mapping[str, Any]) -> str:
    return "0x" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a nonempty string without surrounding whitespace")
    return value


def _optional_text(value: Any, name: str) -> str | None:
    if value is None or value == "":
        return None
    return _text(value, name)


def _units(value: Any, name: str) -> int:
    if type(value) is not int or value < 0 or value > 2**63 - 1:
        raise ValueError(f"{name} must be an exact nonnegative signed-64-bit integer")
    return value


class RelayIncidentStore:
    """SQLite evidence/risk transactions with conflict-aware idempotency.

    Each instance owns one connection, including for :memory:. The instance lock
    serializes threads; BEGIN IMMEDIATE serializes other instances/processes.
    Owners should close the store when retiring it.
    """

    def __init__(self, path: str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            parent = Path(self.path).parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Create privately before sqlite opens the DB (and its WAL files).
            descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(descriptor)
            os.chmod(self.path, 0o600)
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        try:
            if self.path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(self.path + suffix)
                    if sidecar.exists():
                        sidecar.chmod(0o600)
            self._init_schema()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self) -> RelayIncidentStore:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeError("incident store is closed")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def _init_schema(self) -> None:
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
                provider_signer TEXT, request_id TEXT, request_hash TEXT,
                evidence_hash TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open', evidence_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(provider_id, request_id, evidence_hash, kind)
            );
            CREATE TABLE IF NOT EXISTS incident_keys (
                observation_key TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                record_hash TEXT NOT NULL, conflicted INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS ledger_schema (version INTEGER PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS bounty_intents (
                intent_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                claimant_id TEXT NOT NULL, token_units INTEGER NOT NULL DEFAULT 0,
                refund_units INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending',
                tx_ref TEXT, created_at INTEGER NOT NULL, UNIQUE(incident_id, claimant_id)
            );
            CREATE TABLE IF NOT EXISTS provider_risk (
                provider_id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'healthy',
                consecutive_failures INTEGER NOT NULL DEFAULT 0, rolling_score REAL NOT NULL DEFAULT 1.0,
                evidence_count INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS risk_observations (
                provider_id TEXT NOT NULL, evidence_id TEXT NOT NULL, passed INTEGER NOT NULL,
                hard_violation INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
                PRIMARY KEY(provider_id, evidence_id)
            );
            CREATE TABLE IF NOT EXISTS risk_actions (
                action_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, operator_id TEXT NOT NULL,
                reason TEXT NOT NULL, previous_state_json TEXT NOT NULL, created_at INTEGER NOT NULL
            );
            """
        )
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM ledger_schema WHERE version=1").fetchone():
                return
            for row in db.execute("SELECT * FROM incidents ORDER BY created_at, rowid").fetchall():
                record = self._record_from_row(row)
                key, digest = self._observation_key(record), evidence_hash(record)
                existing = db.execute("SELECT * FROM incident_keys WHERE observation_key=?", (key,)).fetchone()
                if existing is None:
                    db.execute("INSERT INTO incident_keys(observation_key, incident_id, record_hash) VALUES (?, ?, ?)",
                               (key, row["incident_id"], digest))
                elif existing["record_hash"] != digest:
                    db.execute("UPDATE incident_keys SET conflicted=1 WHERE observation_key=?", (key,))
            db.execute("INSERT INTO ledger_schema(version) VALUES (1)")

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "provider_id": row["provider_id"], "provider_signer": row["provider_signer"] or None,
            "request_id": row["request_id"] or None, "request_hash": row["request_hash"] or None,
            "kind": row["kind"], "severity": row["severity"], "evidence": json.loads(row["evidence_json"]),
        }

    @staticmethod
    def _observation_key(record: Mapping[str, Any]) -> str:
        # A request/kind pair identifies one immutable observation. Without a
        # request ID, the artifact digest supplies an explicit stable identity.
        return evidence_hash({
            "provider_id": record["provider_id"], "kind": record["kind"],
            "request_id": record["request_id"],
            "artifact_hash": None if record["request_id"] else evidence_hash(record["evidence"]),
        })

    def _record_incident(self, db: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        record = {
            "provider_id": _text(kwargs["provider_id"], "provider_id"),
            "provider_signer": _optional_text(kwargs["provider_signer"], "provider_signer"),
            "request_id": _optional_text(kwargs["request_id"], "request_id"),
            "request_hash": _optional_text(kwargs["request_hash"], "request_hash"),
            "kind": _text(kwargs["kind"], "kind"), "severity": _text(kwargs["severity"], "severity"),
        }
        if not isinstance(kwargs["evidence"], Mapping):
            raise ValueError("evidence must be a JSON object")
        # Roundtrip freezes mutable input and rejects non-finite JSON numbers.
        record["evidence"] = json.loads(_canonical(dict(kwargs["evidence"])))
        key, digest = self._observation_key(record), evidence_hash(record)
        existing = db.execute("SELECT * FROM incident_keys WHERE observation_key=?", (key,)).fetchone()
        if existing is not None:
            if existing["conflicted"] or existing["record_hash"] != digest:
                raise ValueError("conflicting incident observation")
            row = db.execute("SELECT * FROM incidents WHERE incident_id=?", (existing["incident_id"],)).fetchone()
            assert row is not None
            return {"incident_id": row["incident_id"], "evidence_hash": row["evidence_hash"],
                    "record_hash": digest, "status": row["status"]}
        incident_id = "inc_" + uuid.uuid4().hex
        payload_digest = evidence_hash(record["evidence"])
        db.execute(
            """INSERT INTO incidents
            (incident_id, provider_id, provider_signer, request_id, request_hash,
             evidence_hash, kind, severity, evidence_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, record["provider_id"], record["provider_signer"], record["request_id"],
             record["request_hash"], payload_digest, record["kind"], record["severity"],
             _canonical(record["evidence"]), int(time.time())),
        )
        db.execute("INSERT INTO incident_keys(observation_key, incident_id, record_hash) VALUES (?, ?, ?)",
                   (key, incident_id, digest))
        return {"incident_id": incident_id, "evidence_hash": payload_digest, "record_hash": digest, "status": "open"}

    def record_incident(
        self, *, provider_id: str, provider_signer: str | None, request_id: str | None,
        request_hash: str | None, kind: str, severity: str, evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Record immutable metadata/artifacts; conflicting retries fail closed."""
        with self._transaction() as db:
            return self._record_incident(
                db, provider_id=provider_id, provider_signer=provider_signer, request_id=request_id,
                request_hash=request_hash, kind=kind, severity=severity, evidence=evidence,
            )

    def record_protocol_incident(
        self, *, provider_id: str, provider_signer: str | None, request_id: str | None,
        request_hash: str | None, kind: str, severity: str, evidence: Mapping[str, Any],
        risk_provider_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        """Atomically persist a verified violation and quarantine trusted aliases.

        The caller supplies authenticated economic IDs (chain/contract/signer),
        not merely a claimed payout address that could poison an innocent peer.
        """
        if isinstance(risk_provider_ids, (str, bytes)):
            raise ValueError("risk_provider_ids must be a collection, not a string")
        identities = {provider_id, *(_text(value, "risk_provider_id") for value in risk_provider_ids)}
        with self._transaction() as db:
            incident = self._record_incident(
                db, provider_id=provider_id, provider_signer=provider_signer, request_id=request_id,
                request_hash=request_hash, kind=kind, severity=severity, evidence=evidence,
            )
            for identity in sorted(identities):
                self._record_observation(db, provider_id=identity, evidence_id=incident["incident_id"],
                                         passed=False, hard_violation=True)
            return incident

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._transaction() as db:
            row = db.execute("SELECT * FROM incidents WHERE incident_id=?", (_text(incident_id, "incident_id"),)).fetchone()
            if row is None:
                return None
            record = self._record_from_row(row)
            return {**record, "incident_id": row["incident_id"], "evidence_hash": row["evidence_hash"],
                    "record_hash": evidence_hash(record), "status": row["status"], "created_at": row["created_at"]}

    @staticmethod
    def _healthy(provider_id: str) -> dict[str, Any]:
        return {"provider_id": provider_id, "status": "healthy", "consecutive_failures": 0,
                "rolling_score": 1.0, "evidence_count": 0, "updated_at": 0}

    def _record_observation(
        self, db: sqlite3.Connection, *, provider_id: str, evidence_id: str,
        passed: bool, hard_violation: bool,
    ) -> dict[str, Any]:
        provider_id, evidence_id = _text(provider_id, "provider_id"), _text(evidence_id, "evidence_id")
        if type(passed) is not bool or type(hard_violation) is not bool:
            raise ValueError("passed and hard_violation must be booleans")
        if passed and hard_violation:
            raise ValueError("a passing observation cannot be a hard violation")
        existing = db.execute("SELECT * FROM risk_observations WHERE provider_id=? AND evidence_id=?",
                              (provider_id, evidence_id)).fetchone()
        row = db.execute("SELECT * FROM provider_risk WHERE provider_id=?", (provider_id,)).fetchone()
        result = dict(row) if row else self._healthy(provider_id)
        if existing is not None:
            if existing["passed"] != int(passed) or existing["hard_violation"] != int(hard_violation):
                raise ValueError("conflicting risk observation")
            return result
        now = int(time.time())
        failures = 0 if passed else result["consecutive_failures"] + 1
        score = min(1.0, result["rolling_score"] * 0.8 + 0.2) if passed else max(0.0, result["rolling_score"] * 0.8)
        status = result["status"]
        if status != "quarantined":
            status = "quarantined" if hard_violation else ("suspect" if failures >= 3 or score < 0.5 else "healthy")
        db.execute("INSERT INTO risk_observations VALUES (?, ?, ?, ?, ?)",
                   (provider_id, evidence_id, int(passed), int(hard_violation), now))
        db.execute(
            """INSERT INTO provider_risk VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id) DO UPDATE SET status=excluded.status,
            consecutive_failures=excluded.consecutive_failures, rolling_score=excluded.rolling_score,
            evidence_count=excluded.evidence_count, updated_at=excluded.updated_at""",
            (provider_id, status, failures, score, result["evidence_count"] + 1, now),
        )
        return {"provider_id": provider_id, "status": status, "consecutive_failures": failures,
                "rolling_score": score, "evidence_count": result["evidence_count"] + 1, "updated_at": now}

    def record_observation(
        self, *, provider_id: str, evidence_id: str, passed: bool, hard_violation: bool = False,
    ) -> dict[str, Any]:
        """Idempotent observation; soft failures at most suspect, quarantine sticky."""
        with self._transaction() as db:
            return self._record_observation(db, provider_id=provider_id, evidence_id=evidence_id,
                                            passed=passed, hard_violation=hard_violation)

    def risk_snapshot(self, provider_id: str) -> dict[str, Any]:
        provider_id = _text(provider_id, "provider_id")
        with self._transaction() as db:
            row = db.execute("SELECT * FROM provider_risk WHERE provider_id=?", (provider_id,)).fetchone()
            return dict(row) if row else self._healthy(provider_id)

    def is_quarantined(self, provider_id: str) -> bool:
        return self.risk_snapshot(provider_id)["status"] == "quarantined"

    def clear_quarantine(self, *, provider_id: str, operator_id: str, reason: str, action_id: str) -> dict[str, Any]:
        """Audited local operator action, not self-service or a public API.

        Resets local risk counters but preserves observations/incidents. Duplicate
        actions are no-ops even if later evidence quarantines again. Authorization
        of the human/operator belongs to the invoking application.
        """
        values = {name: _text(value, name) for name, value in (
            ("provider_id", provider_id), ("operator_id", operator_id), ("reason", reason), ("action_id", action_id))}
        with self._transaction() as db:
            previous = db.execute("SELECT * FROM risk_actions WHERE action_id=?", (action_id,)).fetchone()
            row = db.execute("SELECT * FROM provider_risk WHERE provider_id=?", (provider_id,)).fetchone()
            snapshot = dict(row) if row else self._healthy(provider_id)
            if previous is not None:
                if any(previous[name] != value for name, value in values.items()):
                    raise ValueError("conflicting operator action")
                return snapshot
            if snapshot["status"] != "quarantined":
                raise ValueError("provider is not quarantined")
            now = int(time.time())
            db.execute("INSERT INTO risk_actions VALUES (?, ?, ?, ?, ?, ?)",
                       (action_id, provider_id, operator_id, reason, _canonical(snapshot), now))
            db.execute("UPDATE provider_risk SET status='healthy', consecutive_failures=0, rolling_score=1.0, updated_at=? WHERE provider_id=?",
                       (now, provider_id))
            return {**snapshot, "status": "healthy", "consecutive_failures": 0, "rolling_score": 1.0, "updated_at": now}

    def risk_actions(self, provider_id: str) -> list[dict[str, Any]]:
        with self._transaction() as db:
            rows = db.execute("SELECT * FROM risk_actions WHERE provider_id=? ORDER BY created_at, rowid",
                              (_text(provider_id, "provider_id"),)).fetchall()
            return [dict(row) for row in rows]

    def audit_health(self) -> dict[str, Any]:
        with self._transaction() as db:
            conflicts = db.execute("SELECT COUNT(*) FROM incident_keys WHERE conflicted=1").fetchone()[0]
            return {"schema_version": 1, "legacy_conflicts": conflicts, "payments_enabled": False}

    def enqueue_bounty(
        self, *, incident_id: str, claimant_id: str, token_units: int = 0, refund_units: int = 0,
    ) -> dict[str, Any]:
        """Unfunded proposal only; no award, transfer, or authority to take a refund.

        refund_units is retained for schema compatibility. It is not permission
        to divert a consumer refund to the claimant.
        """
        incident_id, claimant_id = _text(incident_id, "incident_id"), _text(claimant_id, "claimant_id")
        token_units, refund_units = _units(token_units, "token_units"), _units(refund_units, "refund_units")
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is None:
                raise ValueError("bounty incident does not exist")
            row = db.execute("SELECT * FROM bounty_intents WHERE incident_id=? AND claimant_id=?",
                             (incident_id, claimant_id)).fetchone()
            if row is not None:
                if row["token_units"] != token_units or row["refund_units"] != refund_units:
                    raise ValueError("conflicting bounty intent")
            else:
                db.execute(
                    """INSERT INTO bounty_intents
                    (intent_id, incident_id, claimant_id, token_units, refund_units, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    ("bty_" + uuid.uuid4().hex, incident_id, claimant_id, token_units, refund_units, int(time.time())),
                )
                row = db.execute("SELECT * FROM bounty_intents WHERE incident_id=? AND claimant_id=?",
                                 (incident_id, claimant_id)).fetchone()
            assert row is not None
            return {key: row[key] for key in ("intent_id", "incident_id", "claimant_id", "token_units", "refund_units", "status")}
