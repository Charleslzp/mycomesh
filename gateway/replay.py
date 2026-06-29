from __future__ import annotations

import sqlite3
import time
from pathlib import Path


DEFAULT_REPLAY_DB = ".codex-run/mycomesh-replay.sqlite3"


class ReplayError(RuntimeError):
    pass


class ReplayStore:
    def __init__(self, path: str | Path = DEFAULT_REPLAY_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
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

    def remember(self, scope: str, replay_key: str, ttl_seconds: int, now: int | None = None) -> None:
        resolved_scope = str(scope or "").strip()
        resolved_key = str(replay_key or "").strip()
        if not resolved_scope:
            raise ReplayError("replay scope is required")
        if not resolved_key:
            raise ReplayError("replay key is required")
        current_time = int(now if now is not None else time.time())
        ttl = max(1, int(ttl_seconds))
        expires_at = current_time + ttl
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM replay_nonces WHERE expires_at < ?", (current_time,))
            existing = conn.execute(
                "SELECT * FROM replay_nonces WHERE scope = ? AND replay_key = ?",
                (resolved_scope, resolved_key),
            ).fetchone()
            if existing is not None and int(existing["expires_at"]) >= current_time:
                raise ReplayError("duplicate replay key")
            conn.execute(
                (
                    "INSERT INTO replay_nonces(scope, replay_key, seen_at, expires_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(scope, replay_key) DO UPDATE SET seen_at = excluded.seen_at, expires_at = excluded.expires_at"
                ),
                (resolved_scope, resolved_key, current_time, expires_at),
            )
