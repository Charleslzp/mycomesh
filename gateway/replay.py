from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from importlib import import_module
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterator, Sequence
from urllib.parse import urlsplit


DEFAULT_REPLAY_DB = ".codex-run/mycomesh-replay.sqlite3"
MAX_SQL_INTEGER = (1 << 63) - 1

_EXECUTION_COLUMNS = (
    "scope, execution_key, state, owner, fencing_token, claimed_at, "
    "updated_at, expires_at, result_hash, result_payload"
)


class ReplayError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutionClaim:
    scope: str
    execution_key: str
    state: str
    owner: str
    fencing_token: int
    claimed_at: int
    updated_at: int
    expires_at: int
    result_hash: str | None = None
    result_payload: str | None = None
    acquired: bool = False


def _required(value: object, label: str) -> str:
    resolved = str(value or "").strip()
    if not resolved:
        raise ReplayError(f"{label} is required")
    return resolved


def _positive_token(value: object) -> int:
    try:
        token = int(value)
    except (TypeError, ValueError) as exc:
        raise ReplayError("fencing token must be a positive integer") from exc
    if token <= 0:
        raise ReplayError("fencing token must be a positive integer")
    return token


def _normalize_claims(
    claims: Sequence[tuple[str, str, int]],
    *,
    now: int,
) -> tuple[tuple[str, str, int], ...]:
    if not claims:
        raise ReplayError("at least one replay claim is required")
    normalized: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    for scope, replay_key, expires_at in claims:
        resolved_scope = _required(scope, "replay scope")
        resolved_key = _required(replay_key, "replay key")
        identity = (resolved_scope, resolved_key)
        if identity in seen:
            raise ReplayError("duplicate replay claim")
        seen.add(identity)
        try:
            resolved_expiry = int(expires_at)
        except (TypeError, ValueError) as exc:
            raise ReplayError("replay claim expiry must be an integer") from exc
        normalized.append((resolved_scope, resolved_key, max(now + 1, resolved_expiry)))
    return tuple(sorted(normalized, key=lambda claim: claim[:2]))


def _execution_from_row(row: Sequence[Any], *, acquired: bool = False) -> ExecutionClaim:
    return ExecutionClaim(
        scope=str(row[0]),
        execution_key=str(row[1]),
        state=str(row[2]),
        owner=str(row[3]),
        fencing_token=int(row[4]),
        claimed_at=int(row[5]),
        updated_at=int(row[6]),
        expires_at=int(row[7]),
        result_hash=None if row[8] is None else str(row[8]),
        result_payload=None if row[9] is None else str(row[9]),
        acquired=acquired,
    )


class _SqlReplayBackend:
    placeholder = "?"
    select_for_update = ""

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        raise NotImplementedError

    def _next_fencing_token(self, cursor: Any) -> int:
        raise NotImplementedError

    def get_session_progress(
        self,
        scope: str,
        progress_key: str,
        *,
        now: int,
    ) -> tuple[int, int] | None:
        """Read the last committed off-chain session sequence/spend."""
        marker = self.placeholder
        with self._transaction() as cursor:
            cursor.execute(
                (
                    "SELECT session_sequence, cumulative_spend_units, expires_at "
                    f"FROM session_progress WHERE scope = {marker} AND progress_key = {marker}"
                ),
                (scope, progress_key),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if int(row[2]) < now:
                cursor.execute(
                    f"DELETE FROM session_progress WHERE scope = {marker} AND progress_key = {marker}",
                    (scope, progress_key),
                )
                return None
            return int(row[0]), int(row[1])

    def set_session_progress(
        self,
        scope: str,
        progress_key: str,
        *,
        sequence: int,
        cumulative_spend_units: int,
        expires_at: int,
        now: int,
    ) -> None:
        """Persist monotonically increasing committed V4 session progress."""
        marker = self.placeholder
        with self._transaction() as cursor:
            # Expired rows may be safely replaced; active rows only move
            # forward, preventing a delayed Provider process from rewinding a
            # session after a restart.
            cursor.execute(
                f"DELETE FROM session_progress WHERE expires_at < {marker}",
                (now,),
            )
            cursor.execute(
                (
                    "INSERT INTO session_progress("
                    "scope, progress_key, session_sequence, cumulative_spend_units, expires_at, updated_at"
                    f") VALUES ({marker}, {marker}, {marker}, {marker}, {marker}, {marker}) "
                    "ON CONFLICT(scope, progress_key) DO UPDATE SET "
                    "session_sequence = excluded.session_sequence, "
                    "cumulative_spend_units = excluded.cumulative_spend_units, "
                    "expires_at = excluded.expires_at, updated_at = excluded.updated_at "
                    "WHERE (session_progress.session_sequence < excluded.session_sequence "
                    "AND session_progress.cumulative_spend_units <= excluded.cumulative_spend_units) "
                    "OR (session_progress.session_sequence = excluded.session_sequence "
                    "AND session_progress.cumulative_spend_units = excluded.cumulative_spend_units)"
                ),
                (
                    scope,
                    progress_key,
                    int(sequence),
                    int(cumulative_spend_units),
                    int(expires_at),
                    int(now),
                ),
            )
            if cursor.rowcount == 1:
                return
            cursor.execute(
                (
                    "SELECT session_sequence, cumulative_spend_units "
                    f"FROM session_progress WHERE scope = {marker} AND progress_key = {marker}"
                ),
                (scope, progress_key),
            )
            row = cursor.fetchone()
            if row is None:
                raise ReplayError("session progress disappeared during update")
            current_sequence, current_spend = int(row[0]), int(row[1])
            if current_sequence > int(sequence):
                return
            raise ReplayError("session progress conflicts with an existing sequence")

    def claim_many(self, claims: tuple[tuple[str, str, int], ...], *, now: int) -> None:
        marker = self.placeholder
        with self._transaction() as cursor:
            cursor.execute(f"DELETE FROM replay_nonces WHERE expires_at < {marker}", (now,))
            for scope, replay_key, expires_at in claims:
                cursor.execute(
                    (
                        "INSERT INTO replay_nonces(scope, replay_key, seen_at, expires_at) "
                        f"VALUES ({marker}, {marker}, {marker}, {marker}) "
                        "ON CONFLICT(scope, replay_key) DO UPDATE SET "
                        "seen_at = excluded.seen_at, expires_at = excluded.expires_at "
                        f"WHERE replay_nonces.expires_at < {marker}"
                    ),
                    (scope, replay_key, now, expires_at, now),
                )
                if cursor.rowcount != 1:
                    raise ReplayError("duplicate replay key")

    def forget_many(self, claims: tuple[tuple[str, str], ...]) -> None:
        """Atomically remove claims that never reached an externally visible result."""
        marker = self.placeholder
        with self._transaction() as cursor:
            for scope, replay_key in claims:
                cursor.execute(
                    f"DELETE FROM replay_nonces WHERE scope = {marker} AND replay_key = {marker}",
                    (scope, replay_key),
                )

    def _select_execution(self, cursor: Any, scope: str, execution_key: str) -> Sequence[Any] | None:
        marker = self.placeholder
        cursor.execute(
            (
                f"SELECT {_EXECUTION_COLUMNS} FROM execution_claims "
                f"WHERE scope = {marker} AND execution_key = {marker}{self.select_for_update}"
            ),
            (scope, execution_key),
        )
        return cursor.fetchone()

    def get_execution(self, scope: str, execution_key: str) -> ExecutionClaim | None:
        with self._transaction() as cursor:
            row = self._select_execution(cursor, scope, execution_key)
        return None if row is None else _execution_from_row(row)

    def claim_execution(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        *,
        expires_at: int,
        now: int,
    ) -> ExecutionClaim:
        marker = self.placeholder
        with self._transaction() as cursor:
            token = self._next_fencing_token(cursor)
            cursor.execute(
                (
                    "INSERT INTO execution_claims("
                    "scope, execution_key, state, owner, fencing_token, claimed_at, updated_at, expires_at"
                    f") VALUES ({marker}, {marker}, 'claimed', {marker}, {marker}, {marker}, {marker}, {marker}) "
                    "ON CONFLICT(scope, execution_key) DO UPDATE SET "
                    "state = 'claimed', owner = excluded.owner, fencing_token = excluded.fencing_token, "
                    "claimed_at = excluded.claimed_at, updated_at = excluded.updated_at, "
                    "expires_at = excluded.expires_at, result_hash = NULL, result_payload = NULL "
                    "WHERE execution_claims.state = 'claimed' "
                    f"AND execution_claims.expires_at < {marker}"
                ),
                (scope, execution_key, owner, token, now, now, expires_at, now),
            )
            row = self._select_execution(cursor, scope, execution_key)
            if row is None:  # pragma: no cover - protected by the insert/upsert
                raise ReplayError("failed to persist execution claim")
            claim = _execution_from_row(row)
            if claim.state == "completed":
                return replace(claim, acquired=False)
            if claim.state == "claimed" and claim.fencing_token == token and claim.owner == owner:
                return replace(claim, acquired=True)
            raise ReplayError(f"execution is already {claim.state}")

    def mark_execution_started(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
        *,
        expires_at: int,
        now: int,
    ) -> ExecutionClaim:
        marker = self.placeholder
        with self._transaction() as cursor:
            row = self._select_execution(cursor, scope, execution_key)
            if row is None:
                raise ReplayError("execution claim does not exist")
            claim = _execution_from_row(row)
            self._require_fence(claim, owner, fencing_token)
            if claim.state == "started":
                return claim
            if claim.state != "claimed":
                raise ReplayError(f"execution is already {claim.state}")
            if claim.expires_at < now:
                raise ReplayError("execution claim has expired")
            cursor.execute(
                (
                    "UPDATE execution_claims SET state = 'started', updated_at = "
                    f"{marker}, expires_at = {marker} WHERE scope = {marker} AND execution_key = {marker} "
                    f"AND owner = {marker} AND fencing_token = {marker} AND state = 'claimed'"
                ),
                (now, expires_at, scope, execution_key, owner, fencing_token),
            )
            if cursor.rowcount != 1:  # pragma: no cover - row is locked in PostgreSQL
                raise ReplayError("execution claim changed concurrently")
            updated = self._select_execution(cursor, scope, execution_key)
            if updated is None:  # pragma: no cover - protected by the update
                raise ReplayError("execution claim disappeared")
            return _execution_from_row(updated)

    def complete_execution(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
        *,
        result_hash: str,
        result_payload: str | None,
        now: int,
    ) -> ExecutionClaim:
        marker = self.placeholder
        with self._transaction() as cursor:
            row = self._select_execution(cursor, scope, execution_key)
            if row is None:
                raise ReplayError("execution claim does not exist")
            claim = _execution_from_row(row)
            self._require_fence(claim, owner, fencing_token)
            if claim.state == "completed":
                if claim.result_hash != result_hash or claim.result_payload != result_payload:
                    raise ReplayError("completed execution result does not match")
                return claim
            if claim.state not in {"started", "uncertain"}:
                raise ReplayError("execution has not started")
            cursor.execute(
                (
                    "UPDATE execution_claims SET state = 'completed', updated_at = "
                    f"{marker}, result_hash = {marker}, result_payload = {marker} "
                    f"WHERE scope = {marker} AND execution_key = {marker} AND owner = {marker} "
                    f"AND fencing_token = {marker} AND state IN ('started', 'uncertain')"
                ),
                (now, result_hash, result_payload, scope, execution_key, owner, fencing_token),
            )
            if cursor.rowcount != 1:  # pragma: no cover - row is locked in PostgreSQL
                raise ReplayError("execution claim changed concurrently")
            updated = self._select_execution(cursor, scope, execution_key)
            if updated is None:  # pragma: no cover - protected by the update
                raise ReplayError("execution claim disappeared")
            return _execution_from_row(updated)

    def mark_execution_uncertain(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
        *,
        now: int,
    ) -> ExecutionClaim:
        marker = self.placeholder
        with self._transaction() as cursor:
            row = self._select_execution(cursor, scope, execution_key)
            if row is None:
                raise ReplayError("execution claim does not exist")
            claim = _execution_from_row(row)
            self._require_fence(claim, owner, fencing_token)
            if claim.state == "uncertain":
                return claim
            if claim.state != "started":
                raise ReplayError("only a started execution can become uncertain")
            cursor.execute(
                (
                    "UPDATE execution_claims SET state = 'uncertain', updated_at = "
                    f"{marker} WHERE scope = {marker} AND execution_key = {marker} "
                    f"AND owner = {marker} AND fencing_token = {marker} AND state = 'started'"
                ),
                (now, scope, execution_key, owner, fencing_token),
            )
            if cursor.rowcount != 1:  # pragma: no cover - row is locked in PostgreSQL
                raise ReplayError("execution claim changed concurrently")
            updated = self._select_execution(cursor, scope, execution_key)
            if updated is None:  # pragma: no cover - protected by the update
                raise ReplayError("execution claim disappeared")
            return _execution_from_row(updated)

    def release_execution(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
    ) -> bool:
        marker = self.placeholder
        with self._transaction() as cursor:
            cursor.execute(
                (
                    f"DELETE FROM execution_claims WHERE scope = {marker} AND execution_key = {marker} "
                    f"AND owner = {marker} AND fencing_token = {marker} AND state = 'claimed'"
                ),
                (scope, execution_key, owner, fencing_token),
            )
            return cursor.rowcount == 1

    @staticmethod
    def _require_fence(claim: ExecutionClaim, owner: str, fencing_token: int) -> None:
        if claim.owner != owner or claim.fencing_token != fencing_token:
            raise ReplayError("execution fencing token is stale")


class _SQLiteReplayBackend(_SqlReplayBackend):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        conn = self._connect()
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    def _init(self) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    scope TEXT NOT NULL,
                    replay_key TEXT NOT NULL,
                    seen_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY(scope, replay_key)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS replay_nonces_expiry_idx "
                "ON replay_nonces(expires_at)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_fencing_tokens (
                    token INTEGER PRIMARY KEY AUTOINCREMENT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_claims (
                    scope TEXT NOT NULL,
                    execution_key TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('claimed', 'started', 'uncertain', 'completed')),
                    owner TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    claimed_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    result_hash TEXT,
                    result_payload TEXT,
                    PRIMARY KEY(scope, execution_key)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS execution_claims_expiry_idx "
                "ON execution_claims(state, expires_at)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_progress (
                    scope TEXT NOT NULL,
                    progress_key TEXT NOT NULL,
                    session_sequence INTEGER NOT NULL,
                    cumulative_spend_units INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(scope, progress_key)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS session_progress_expiry_idx "
                "ON session_progress(expires_at)"
            )

    def _next_fencing_token(self, cursor: sqlite3.Cursor) -> int:
        inserted = cursor.execute("INSERT INTO execution_fencing_tokens DEFAULT VALUES")
        if inserted.lastrowid is None:  # pragma: no cover - SQLite always returns it
            raise ReplayError("failed to allocate execution fencing token")
        return int(inserted.lastrowid)


class _PostgresReplayBackend(_SqlReplayBackend):
    placeholder = "%s"
    select_for_update = " FOR UPDATE"

    def __init__(self, dsn: str) -> None:
        try:
            psycopg = import_module("psycopg")
        except (ImportError, ModuleNotFoundError) as exc:
            raise ReplayError(
                "PostgreSQL replay store requires psycopg 3; install 'psycopg[binary]>=3.1,<4'"
            ) from exc
        self._connect_database = psycopg.connect
        self._dsn = dsn
        self._init()

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        conn = self._connect_database(self._dsn)
        try:
            with conn.cursor() as cursor:
                yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self) -> None:
        with self._transaction() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    scope TEXT NOT NULL,
                    replay_key TEXT NOT NULL,
                    seen_at BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    PRIMARY KEY(scope, replay_key)
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS replay_nonces_expiry_idx "
                "ON replay_nonces(expires_at)"
            )
            cursor.execute("CREATE SEQUENCE IF NOT EXISTS execution_fencing_token_seq AS BIGINT")
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_claims (
                    scope TEXT NOT NULL,
                    execution_key TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('claimed', 'started', 'uncertain', 'completed')),
                    owner TEXT NOT NULL,
                    fencing_token BIGINT NOT NULL,
                    claimed_at BIGINT NOT NULL,
                    updated_at BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    result_hash TEXT,
                    result_payload TEXT,
                    PRIMARY KEY(scope, execution_key)
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS execution_claims_expiry_idx "
                "ON execution_claims(state, expires_at)"
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS session_progress (
                    scope TEXT NOT NULL,
                    progress_key TEXT NOT NULL,
                    session_sequence BIGINT NOT NULL,
                    cumulative_spend_units BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    updated_at BIGINT NOT NULL,
                    PRIMARY KEY(scope, progress_key)
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS session_progress_expiry_idx "
                "ON session_progress(expires_at)"
            )

    def _next_fencing_token(self, cursor: Any) -> int:
        cursor.execute("SELECT nextval('execution_fencing_token_seq')")
        row = cursor.fetchone()
        if row is None:  # pragma: no cover - PostgreSQL always returns it
            raise ReplayError("failed to allocate execution fencing token")
        return int(row[0])


class ReplayStore:
    """Persistent replay and execution claims for one SQLite file or PostgreSQL cluster."""

    def __init__(self, path: str | Path = DEFAULT_REPLAY_DB) -> None:
        self.location = str(path)
        parsed = urlsplit(self.location)
        if parsed.scheme in {"postgres", "postgresql"}:
            self._path: Path | None = None
            self.backend = "postgresql"
            self._backend: _SqlReplayBackend = self._initialize_backend(
                lambda: _PostgresReplayBackend(self.location),
                "PostgreSQL",
            )
        elif "://" in self.location:
            raise ReplayError(f"unsupported replay store URL scheme: {parsed.scheme or 'unknown'}")
        else:
            self._path = Path(path)
            self.backend = "sqlite"
            self._backend = self._initialize_backend(
                lambda: _SQLiteReplayBackend(self._path),
                "SQLite",
            )

    @staticmethod
    def _initialize_backend(factory: Any, label: str) -> _SqlReplayBackend:
        try:
            return factory()
        except ReplayError:
            raise
        except Exception as exc:
            raise ReplayError(f"failed to initialize {label} replay store") from exc

    @property
    def path(self) -> Path:
        if self._path is None:
            raise ReplayError("PostgreSQL replay stores have no local path; use ReplayStore methods")
        return self._path

    def _connect(self) -> sqlite3.Connection:
        if not isinstance(self._backend, _SQLiteReplayBackend):
            raise ReplayError("direct connections are unavailable for PostgreSQL replay stores")
        return self._backend._connect()

    def remember(self, scope: str, replay_key: str, ttl_seconds: int, now: int | None = None) -> None:
        current_time = int(now if now is not None else time.time())
        ttl = max(1, int(ttl_seconds))
        self.claim_many(((scope, replay_key, current_time + ttl),), now=current_time)

    def claim_many(
        self,
        claims: Sequence[tuple[str, str, int]],
        *,
        now: int | None = None,
    ) -> None:
        current_time = int(now if now is not None else time.time())
        normalized = _normalize_claims(claims, now=current_time)
        self._run(lambda: self._backend.claim_many(normalized, now=current_time))

    def forget_many(self, claims: Sequence[tuple[str, str]]) -> None:
        normalized: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for scope, replay_key in claims:
            item = (_required(scope, "replay scope"), _required(replay_key, "replay key"))
            if item in seen:
                raise ReplayError("duplicate replay claim")
            seen.add(item)
            normalized.append(item)
        if not normalized:
            raise ReplayError("at least one replay claim is required")
        self._run(lambda: self._backend.forget_many(tuple(sorted(normalized))))

    def get_session_progress(
        self,
        scope: str,
        progress_key: str,
        *,
        now: int | None = None,
    ) -> tuple[int, int] | None:
        resolved_scope = _required(scope, "session progress scope")
        resolved_key = _required(progress_key, "session progress key")
        current_time = int(now if now is not None else time.time())
        return self._run(
            lambda: self._backend.get_session_progress(
                resolved_scope,
                resolved_key,
                now=current_time,
            )
        )

    def set_session_progress(
        self,
        scope: str,
        progress_key: str,
        sequence: int,
        cumulative_spend_units: int,
        expires_at: int,
        *,
        now: int | None = None,
    ) -> None:
        resolved_scope = _required(scope, "session progress scope")
        resolved_key = _required(progress_key, "session progress key")
        try:
            resolved_sequence = int(sequence)
            resolved_spend = int(cumulative_spend_units)
            resolved_expiry = int(expires_at)
        except (TypeError, ValueError) as exc:
            raise ReplayError("session progress values must be integers") from exc
        if (
            resolved_sequence < 0
            or resolved_sequence > MAX_SQL_INTEGER
            or resolved_spend < 0
            or resolved_spend > MAX_SQL_INTEGER
            or resolved_expiry <= 0
            or resolved_expiry > MAX_SQL_INTEGER
        ):
            raise ReplayError("session progress values are invalid")
        current_time = int(now if now is not None else time.time())
        if resolved_expiry <= current_time:
            raise ReplayError("session progress expiry must be in the future")
        self._run(
            lambda: self._backend.set_session_progress(
                resolved_scope,
                resolved_key,
                sequence=resolved_sequence,
                cumulative_spend_units=resolved_spend,
                expires_at=resolved_expiry,
                now=current_time,
            )
        )

    def get_execution(self, scope: str, execution_key: str) -> ExecutionClaim | None:
        resolved_scope = _required(scope, "execution scope")
        resolved_key = _required(execution_key, "execution key")
        return self._run(lambda: self._backend.get_execution(resolved_scope, resolved_key))

    def claim_execution(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        ttl_seconds: int,
        *,
        now: int | None = None,
    ) -> ExecutionClaim:
        resolved_scope = _required(scope, "execution scope")
        resolved_key = _required(execution_key, "execution key")
        resolved_owner = _required(owner, "execution owner")
        current_time = int(now if now is not None else time.time())
        expires_at = current_time + max(1, int(ttl_seconds))
        return self._run(
            lambda: self._backend.claim_execution(
                resolved_scope,
                resolved_key,
                resolved_owner,
                expires_at=expires_at,
                now=current_time,
            )
        )

    def mark_execution_started(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
        ttl_seconds: int,
        *,
        now: int | None = None,
    ) -> ExecutionClaim:
        resolved_scope = _required(scope, "execution scope")
        resolved_key = _required(execution_key, "execution key")
        resolved_owner = _required(owner, "execution owner")
        token = _positive_token(fencing_token)
        current_time = int(now if now is not None else time.time())
        expires_at = current_time + max(1, int(ttl_seconds))
        return self._run(
            lambda: self._backend.mark_execution_started(
                resolved_scope,
                resolved_key,
                resolved_owner,
                token,
                expires_at=expires_at,
                now=current_time,
            )
        )

    def complete_execution(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
        result_hash: str,
        result_payload: str | None = None,
        *,
        now: int | None = None,
    ) -> ExecutionClaim:
        resolved_scope = _required(scope, "execution scope")
        resolved_key = _required(execution_key, "execution key")
        resolved_owner = _required(owner, "execution owner")
        token = _positive_token(fencing_token)
        resolved_hash = _required(result_hash, "execution result hash")
        if result_payload is not None and not isinstance(result_payload, str):
            raise ReplayError("execution result payload must be a string")
        current_time = int(now if now is not None else time.time())
        return self._run(
            lambda: self._backend.complete_execution(
                resolved_scope,
                resolved_key,
                resolved_owner,
                token,
                result_hash=resolved_hash,
                result_payload=result_payload,
                now=current_time,
            )
        )

    def mark_execution_uncertain(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
        *,
        now: int | None = None,
    ) -> ExecutionClaim:
        resolved_scope = _required(scope, "execution scope")
        resolved_key = _required(execution_key, "execution key")
        resolved_owner = _required(owner, "execution owner")
        token = _positive_token(fencing_token)
        current_time = int(now if now is not None else time.time())
        return self._run(
            lambda: self._backend.mark_execution_uncertain(
                resolved_scope,
                resolved_key,
                resolved_owner,
                token,
                now=current_time,
            )
        )

    def release_execution(
        self,
        scope: str,
        execution_key: str,
        owner: str,
        fencing_token: int,
    ) -> bool:
        resolved_scope = _required(scope, "execution scope")
        resolved_key = _required(execution_key, "execution key")
        resolved_owner = _required(owner, "execution owner")
        token = _positive_token(fencing_token)
        return self._run(
            lambda: self._backend.release_execution(
                resolved_scope,
                resolved_key,
                resolved_owner,
                token,
            )
        )

    @staticmethod
    def _run(operation: Any) -> Any:
        try:
            return operation()
        except ReplayError:
            raise
        except Exception as exc:
            raise ReplayError("replay store operation failed") from exc
