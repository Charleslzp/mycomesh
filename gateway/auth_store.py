from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PBKDF2_ITERATIONS = 210_000
SALT_BYTES = 16
TOKEN_BYTES = 32


class AuthStore:
    def __init__(self, db_path: str, token_ttl_seconds: int) -> None:
        self.db_path = db_path
        self.token_ttl_seconds = token_ttl_seconds
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(user_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id
                ON auth_tokens(user_id, expires_at)
                """
            )

    def create_user(
        self,
        username: str,
        password: str,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        username = _normalize_username(username)
        _validate_password(password)
        user_id = user_id or username
        now = _now()
        password_hash = _hash_password(password)
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT INTO users(user_id, username, password_hash, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (user_id, username, password_hash, now, now),
                    )
            except sqlite3.IntegrityError as exc:
                raise ValueError("username or user_id already exists") from exc
        return {"user_id": user_id, "username": username, "created_at": now}

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        username = _normalize_username(username)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT user_id, username, password_hash
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if row is None or not _verify_password(password, row["password_hash"]):
            return None

        token = secrets.token_urlsafe(TOKEN_BYTES)
        token_hash = _hash_token(token)
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        expires_at = (now_dt + timedelta(seconds=self.token_ttl_seconds)).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO auth_tokens(token_hash, user_id, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (token_hash, row["user_id"], now, expires_at),
                )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_at": expires_at,
            "user": {
                "user_id": row["user_id"],
                "username": row["username"],
            },
        }

    def user_for_token(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        token_hash = _hash_token(token)
        now = _now()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.user_id, u.username, t.expires_at
                FROM auth_tokens t
                JOIN users u ON u.user_id = t.user_id
                WHERE t.token_hash = ?
                  AND t.revoked_at IS NULL
                  AND t.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
        if row is None:
            return None
        return {
            "user_id": row["user_id"],
            "username": row["username"],
            "expires_at": row["expires_at"],
        }

    def revoke_token(self, token: str) -> bool:
        token_hash = _hash_token(token)
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    UPDATE auth_tokens
                    SET revoked_at = ?
                    WHERE token_hash = ? AND revoked_at IS NULL
                    """,
                    (_now(), token_hash),
                )
                return cursor.rowcount > 0


def _normalize_username(username: str) -> str:
    username = username.strip().lower()
    if not username:
        raise ValueError("username is required")
    if len(username) > 120:
        raise ValueError("username is too long")
    return username


def _validate_password(password: str) -> None:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")


def _hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_b64.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
