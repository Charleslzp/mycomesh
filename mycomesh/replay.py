"""Replay stores for secure envelopes and request ids."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path


class ReplayError(RuntimeError):
    pass


class MemoryReplayStore:
    """Process-local replay protection with expiry (Consumer and tests)."""

    def __init__(self, maximum_entries: int = 100_000) -> None:
        self._entries: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()
        self._maximum = maximum_entries

    def remember(self, scope: str, replay_key: str, ttl_seconds: int, now: int | None = None) -> None:
        current = int(time.time() if now is None else now)
        with self._lock:
            if len(self._entries) >= self._maximum:
                self._entries = {key: expiry for key, expiry in self._entries.items() if expiry > current}
            if self._entries.get((scope, replay_key), 0) > current:
                raise ReplayError("replayed message")
            if len(self._entries) >= self._maximum:
                raise ReplayError("replay store is full")
            self._entries[(scope, replay_key)] = current + max(1, int(ttl_seconds))


class SqliteReplayStore:
    """Durable replay protection that survives restarts (Provider and Relay)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self._path, timeout=30, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS replay (scope TEXT NOT NULL, replay_key TEXT NOT NULL, "
            "expires_at INTEGER NOT NULL, PRIMARY KEY (scope, replay_key))"
        )
        self._lock = threading.Lock()

    def remember(self, scope: str, replay_key: str, ttl_seconds: int, now: int | None = None) -> None:
        current = int(time.time() if now is None else now)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("DELETE FROM replay WHERE expires_at <= ?", (current,))
                try:
                    self._db.execute(
                        "INSERT INTO replay (scope, replay_key, expires_at) VALUES (?, ?, ?)",
                        (scope, replay_key, current + max(1, int(ttl_seconds))),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ReplayError("replayed message") from exc
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def close(self) -> None:
        self._db.close()
