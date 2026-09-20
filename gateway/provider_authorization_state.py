"""Persistent, public-data-only wallet-send fence for Provider onboarding."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time


class AuthorizationStateError(ValueError):
    pass


class ProviderAuthorizationState:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = self.path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077:
            raise AuthorizationStateError("authorization state directory must be private (0700)")
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except FileExistsError:
            pass
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise AuthorizationStateError("authorization state must be a private regular file")
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS intents (
                scope TEXT PRIMARY KEY, intent_id TEXT NOT NULL, status TEXT NOT NULL,
                tx_hash TEXT, updated_at INTEGER NOT NULL)""")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def scope(plan):
        tx = plan["transaction"]
        return hashlib.sha256(json.dumps(
            [tx["chainId"], tx["to"].lower(), tx["from"].lower(), tx["data"].lower(), tx["value"]],
            separators=(",", ":"),
        ).encode()).hexdigest()

    def pending(self, plan):
        with self._connect() as db:
            row = db.execute("SELECT * FROM intents WHERE scope=? AND status IN ('reserved','submitted')", (self.scope(plan),)).fetchone()
            return dict(row) if row else None

    def reserve(self, plan):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            scope = self.scope(plan)
            row = db.execute("SELECT status FROM intents WHERE scope=?", (scope,)).fetchone()
            if row and row["status"] in {"reserved", "submitted"}:
                raise AuthorizationStateError("An authorization may already be pending; no duplicate transaction is allowed")
            intent = secrets.token_hex(24)
            db.execute("INSERT OR REPLACE INTO intents VALUES (?,?,?,NULL,?)", (scope, intent, "reserved", int(time.time())))
        return intent

    def submitted(self, plan, intent, tx_hash):
        with self._connect() as db:
            changed = db.execute("UPDATE intents SET status='submitted',tx_hash=?,updated_at=? WHERE scope=? AND intent_id=? AND status='reserved'", (tx_hash, int(time.time()), self.scope(plan), intent)).rowcount
            if not changed:
                raise AuthorizationStateError("Authorization intent is no longer available")

    def cancel_rejected(self, plan, intent):
        with self._connect() as db:
            changed = db.execute("UPDATE intents SET status='cancelled',updated_at=? WHERE scope=? AND intent_id=? AND status='reserved'", (int(time.time()), self.scope(plan), intent)).rowcount
            if not changed:
                raise AuthorizationStateError("Only this wallet's rejected, unsent intent can be cancelled")

    def confirmed(self, plan):
        with self._connect() as db:
            db.execute("UPDATE intents SET status='confirmed',updated_at=? WHERE scope=?", (int(time.time()), self.scope(plan)))
