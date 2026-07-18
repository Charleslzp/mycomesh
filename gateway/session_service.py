"""Durable Consumer Session V4 state and bounded session-key management.

The browser opens a V4 escrow once.  The Gateway then owns a *bounded* EVM
session key derived from a deployment secret and signs the small, short-lived
request envelope locally.  No wallet RPC, reservation transaction, or block
confirmation is needed for an individual inference.  The key is never
returned to the browser and the escrow cap/expiry remain enforced by the
Settlement contract.

This module deliberately does not replace the V3 reservation store.  A V4
session has its own SQLite state machine so a restart cannot reset a sequence
or accidentally accept a duplicate request.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .chain import (
    BYTES32_PATTERN,
    ZERO_ADDRESS,
    abi_encode_arg,
    call_contract,
    channel_to_hash,
    keccak256,
    normalize_address,
    normalize_bytes32,
    parse_private_key,
    private_key_to_address,
)
from .identity import NodeIdentity
from .session_protocol import (
    ZERO_BYTES32,
    build_session_authorization,
    build_session_request,
)


SESSION_V4_PLAN_SCHEMA = "mycomesh.consumer.v4.plan.v1"
DEFAULT_SESSION_DB = ".codex-run/mycomesh-session-v4.sqlite3"
DEFAULT_SESSION_LIFETIME_SECONDS = 24 * 60 * 60
MAX_SESSION_LIFETIME_SECONDS = 30 * 24 * 60 * 60
DEFAULT_SESSION_MAX_AMOUNT_UNITS = 10_000_000  # 10 stablecoin units at 6 decimals
MAX_SESSION_MAX_AMOUNT_UNITS = 10**18
SESSION_CLAIM_STALE_SECONDS = 15 * 60
SESSION_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")


class SessionServiceError(ValueError):
    """Raised when a V4 session is malformed, inactive, or replayed."""


@dataclass(frozen=True)
class SessionDeployment:
    chain_id: int
    contract: str
    rpc_url: str | None
    channel: str
    channel_hash: str
    pricing_version: int
    pricing_hash: str
    network_id: str
    channel_id: str
    backend_policy: str

    def normalized(self) -> "SessionDeployment":
        chain_id = int(self.chain_id)
        if chain_id <= 0:
            raise SessionServiceError("session chain_id must be positive")
        contract = normalize_address(self.contract)
        if contract == ZERO_ADDRESS:
            raise SessionServiceError("session settlement contract cannot be zero")
        channel = str(self.channel or "").strip()
        if not channel:
            raise SessionServiceError("session channel is required")
        channel_hash = normalize_bytes32(self.channel_hash)
        pricing_hash = normalize_bytes32(self.pricing_hash)
        pricing_version = int(self.pricing_version)
        if pricing_version <= 0 or pricing_version >= 1 << 64:
            raise SessionServiceError("session pricing_version is out of range")
        return SessionDeployment(
            chain_id=chain_id,
            contract=contract,
            rpc_url=(str(self.rpc_url).strip() or None) if self.rpc_url else None,
            channel=channel,
            channel_hash=channel_hash,
            pricing_version=pricing_version,
            pricing_hash=pricing_hash,
            network_id=str(self.network_id or "").strip(),
            channel_id=str(self.channel_id or "").strip(),
            backend_policy=str(self.backend_policy or "").strip(),
        )


@dataclass(frozen=True)
class SessionClaim:
    plan: dict[str, Any]
    authorization: dict[str, Any]
    request: dict[str, Any]
    private_key: str
    previous_cumulative_spend_units: int


class SessionV4Store:
    """SQLite-backed session registry with an atomic one-in-flight claim."""

    def __init__(self, path: str | Path = DEFAULT_SESSION_DB, *, secret: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._secret = self._validate_secret(secret if secret is not None else os.getenv("MYCOMESH_SESSION_KEY_SECRET"))
        self._lock = threading.RLock()
        self._initialize()

    @staticmethod
    def _validate_secret(value: str | None) -> bytes:
        raw = str(value or "")
        if len(raw) < 32:
            raise SessionServiceError(
                "MYCOMESH_SESSION_KEY_SECRET must contain at least 32 characters"
            )
        return raw.encode("utf-8")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS session_v4 (
                    session_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    consumer TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    provider_payment_address TEXT NOT NULL,
                    session_salt TEXT NOT NULL UNIQUE,
                    session_key TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    channel_hash TEXT NOT NULL,
                    pricing_version INTEGER NOT NULL,
                    pricing_hash TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    settlement_contract TEXT NOT NULL,
                    network_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    backend_policy TEXT NOT NULL,
                    max_amount_units INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    next_sequence INTEGER NOT NULL DEFAULT 0,
                    cumulative_spend_units INTEGER NOT NULL DEFAULT 0,
                    claimed_sequence INTEGER,
                    claimed_request_id TEXT,
                    claimed_request_hash TEXT,
                    claimed_max_fee_units INTEGER,
                    claimed_deadline INTEGER,
                    claimed_previous_cumulative_units INTEGER,
                    claimed_at INTEGER,
                    activated_at INTEGER,
                    closed INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS session_v4_results (
                    session_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    amount_units INTEGER NOT NULL,
                    request_hash TEXT NOT NULL DEFAULT '0x',
                    response_json TEXT NOT NULL,
                    settlement_json TEXT,
                    settlement_status TEXT NOT NULL DEFAULT 'pending',
                    settlement_tx_hash TEXT,
                    settlement_error TEXT,
                    completed_at INTEGER NOT NULL,
                    PRIMARY KEY (session_id, request_id)
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS session_v4_account_idx ON session_v4(account_id, created_at DESC)"
            )
            # V4 was initially shipped behind a feature flag.  Keep the
            # migration explicit so an operator can enable it on an existing
            # Gateway database without dropping sessions or replay state.
            self._ensure_column(db, "session_v4", "claimed_request_hash", "TEXT")
            self._ensure_column(db, "session_v4", "claimed_deadline", "INTEGER")
            self._ensure_column(db, "session_v4_results", "request_hash", "TEXT NOT NULL DEFAULT '0x'")
            self._ensure_column(db, "session_v4_results", "settlement_json", "TEXT")
            self._ensure_column(db, "session_v4_results", "settlement_status", "TEXT NOT NULL DEFAULT 'pending'")
            self._ensure_column(db, "session_v4_results", "settlement_tx_hash", "TEXT")
            self._ensure_column(db, "session_v4_results", "settlement_error", "TEXT")

    @staticmethod
    def _ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {str(row[1]) for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def create_plan(
        self,
        *,
        account_id: str,
        consumer: str,
        provider_id: str,
        provider_payment_address: str,
        deployment: SessionDeployment,
        max_amount_units: int | None = None,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        deployment = deployment.normalized()
        current = int(time.time() if now is None else now)
        consumer_address = _nonzero_address(consumer, "consumer")
        provider_address = _nonzero_address(provider_payment_address, "provider_payment_address")
        if not provider_id or not str(provider_id).strip():
            raise SessionServiceError("provider_id is required")
        amount = int(max_amount_units or DEFAULT_SESSION_MAX_AMOUNT_UNITS)
        if amount <= 0 or amount > MAX_SESSION_MAX_AMOUNT_UNITS:
            raise SessionServiceError("session max_amount_units is out of range")
        expiry = int(expires_at or current + DEFAULT_SESSION_LIFETIME_SECONDS)
        if expiry <= current or expiry > current + MAX_SESSION_LIFETIME_SECONDS:
            raise SessionServiceError("session expires_at must be within 30 days")

        for _ in range(8):
            salt = "0x" + secrets.token_hex(32)
            session_id = session_id_for(
                contract=deployment.contract,
                chain_id=deployment.chain_id,
                consumer=consumer_address,
                session_salt=salt,
            )
            private_key = self.derive_private_key(session_id)
            session_key = private_key_to_address(parse_private_key(private_key))
            try:
                with self._lock, self._connect() as db:
                    db.execute(
                        """
                        INSERT INTO session_v4 (
                            session_id, account_id, consumer, provider_id,
                            provider_payment_address, session_salt, session_key,
                            channel, channel_hash, pricing_version, pricing_hash,
                            chain_id, settlement_contract, network_id, channel_id,
                            backend_policy, max_amount_units, expires_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            str(account_id),
                            consumer_address,
                            str(provider_id),
                            provider_address,
                            salt,
                            session_key,
                            deployment.channel,
                            deployment.channel_hash,
                            deployment.pricing_version,
                            deployment.pricing_hash,
                            deployment.chain_id,
                            deployment.contract,
                            deployment.network_id,
                            deployment.channel_id,
                            deployment.backend_policy,
                            amount,
                            expiry,
                            current,
                        ),
                    )
                return self.plan(session_id)
            except sqlite3.IntegrityError:
                continue
        raise SessionServiceError("could not allocate a unique V4 session salt")

    def plan(self, session_id: str) -> dict[str, Any]:
        row = self._row(session_id)
        if row is None:
            raise SessionServiceError("unknown V4 session")
        return _row_plan(row)

    def get(self, session_id: str) -> dict[str, Any] | None:
        row = self._row(session_id)
        return _row_plan(row) if row is not None else None

    def latest_active(
        self,
        *,
        account_id: str,
        provider_id: str | None = None,
        now: int | None = None,
    ) -> dict[str, Any] | None:
        current = int(time.time() if now is None else now)
        query = (
            "SELECT * FROM session_v4 WHERE account_id=? AND closed=0 AND expires_at>?"
            + (" AND provider_id=?" if provider_id else "")
            + " ORDER BY created_at DESC LIMIT 1"
        )
        args: tuple[Any, ...] = (
            (str(account_id), current, str(provider_id))
            if provider_id
            else (str(account_id), current)
        )
        with self._connect() as db:
            row = db.execute(query, args).fetchone()
        return _row_plan(row) if row is not None else None

    def derive_private_key(self, session_id: str) -> str:
        value = str(session_id).lower().encode("ascii")
        # Rehash with a counter until the scalar is in secp256k1's valid range.
        from .chain import SECP256K1_N

        for counter in range(32):
            digest = hmac.new(self._secret, b"mycomesh-session-v4\0" + value + bytes([counter]), hashlib.sha256).digest()
            scalar = int.from_bytes(digest, "big")
            if 0 < scalar < SECP256K1_N:
                return "0x" + digest.hex()
        raise SessionServiceError("could not derive a valid V4 session key")

    def claim_request(
        self,
        *,
        session_id: str,
        account_id: str,
        request_id: str,
        request_hash: str,
        max_fee_units: int,
        deadline: int,
        signer: NodeIdentity,
        now: int | None = None,
    ) -> SessionClaim:
        current = int(time.time() if now is None else now)
        normalized_session_id = normalize_bytes32(session_id)
        request_digest = normalize_bytes32(request_hash)
        request_text = str(request_id or "")
        if not SESSION_REQUEST_ID_PATTERN.fullmatch(request_text):
            raise SessionServiceError("V4 request_id must be 1-192 ASCII characters")
        fee = int(max_fee_units)
        if fee <= 0:
            raise SessionServiceError("session request max_fee_units must be positive")
        try:
            requested_deadline = int(deadline)
        except (TypeError, ValueError) as exc:
            raise SessionServiceError("session request deadline must be an integer") from exc
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM session_v4 WHERE session_id = ?", (normalized_session_id,)
            ).fetchone()
            if row is None:
                db.execute("ROLLBACK")
                raise SessionServiceError("unknown V4 session")
            _validate_row_owner(row, account_id)
            _validate_row_active(row, current)
            claimed_at = row["claimed_at"]
            reuse_claim = False
            if claimed_at is not None:
                if row["claimed_request_id"] == request_id:
                    claimed_hash = normalize_bytes32(str(row["claimed_request_hash"] or "0x" + "0" * 64))
                    if claimed_hash != request_digest or int(row["claimed_max_fee_units"] or 0) != fee:
                        db.execute("ROLLBACK")
                        raise SessionServiceError("V4 request_id is already bound to a different request")
                    # Reuse the exact sequence for an API retry.  This is
                    # important when a Provider reports an uncertain
                    # execution: allocating a fresh sequence would strand the
                    # original receipt and require another wallet action.
                    reuse_claim = True
                elif int(claimed_at) >= current - SESSION_CLAIM_STALE_SECONDS:
                    db.execute("ROLLBACK")
                    raise SessionServiceError("another request is already in flight for this session")
                else:
                    db.execute("ROLLBACK")
                    raise SessionServiceError("stale V4 request claim requires operator recovery")
            if reuse_claim:
                sequence = int(row["claimed_sequence"] or 0)
                previous_cumulative = int(row["claimed_previous_cumulative_units"] or 0)
                if sequence <= 0:
                    db.execute("ROLLBACK")
                    raise SessionServiceError("V4 request claim sequence is missing")
                # A Provider receipt commits this exact deadline.  Retries may
                # carry a freshly computed browser deadline, but the Gateway
                # must reproduce the original signed request for verification
                # and settlement to remain deterministic.
                claimed_deadline = row["claimed_deadline"]
                resolved_deadline = (
                    requested_deadline if claimed_deadline is None else int(claimed_deadline)
                )
                if claimed_deadline is None:
                    # Backfill an in-flight claim created before this column
                    # was introduced.  Subsequent retries are then stable.
                    db.execute(
                        "UPDATE session_v4 SET claimed_deadline=? WHERE session_id=?",
                        (resolved_deadline, normalized_session_id),
                    )
            else:
                sequence = int(row["next_sequence"]) + 1
                previous_cumulative = int(row["cumulative_spend_units"])
                resolved_deadline = requested_deadline
            if fee > int(row["max_amount_units"]) - previous_cumulative:
                db.execute("ROLLBACK")
                raise SessionServiceError("session max amount would be exceeded")
            if resolved_deadline <= current or resolved_deadline > int(row["expires_at"]):
                db.execute("ROLLBACK")
                raise SessionServiceError("session request deadline is outside the session")
            if not reuse_claim:
                db.execute(
                    """
                    UPDATE session_v4
                    SET claimed_sequence=?, claimed_request_id=?, claimed_request_hash=?, claimed_max_fee_units=?,
                        claimed_deadline=?, claimed_previous_cumulative_units=?, claimed_at=?
                    WHERE session_id=?
                    """,
                    (
                        sequence,
                        request_text,
                        request_digest,
                        fee,
                        resolved_deadline,
                        previous_cumulative,
                        current,
                        normalized_session_id,
                    ),
                )
            db.execute("COMMIT")
            row = db.execute("SELECT * FROM session_v4 WHERE session_id = ?", (normalized_session_id,)).fetchone()

        assert row is not None
        plan = _row_plan(row)
        private_key = self.derive_private_key(normalized_session_id)
        authorization = build_session_authorization(
            session_id=normalized_session_id,
            session_key=str(row["session_key"]),
            consumer_payment_address=str(row["consumer"]),
            provider_id=str(row["provider_id"]),
            provider_payment_address=str(row["provider_payment_address"]),
            channel=str(row["channel"]),
            pricing_version=int(row["pricing_version"]),
            pricing_hash=str(row["pricing_hash"]),
            max_amount_units=int(row["max_amount_units"]),
            expires_at=int(row["expires_at"]),
            sequence=0,
            request_hash=ZERO_BYTES32,
            max_fee_units=int(row["max_amount_units"]),
            deadline=int(row["expires_at"]),
            cumulative_spend_units=0,
            signer=signer,
            consumer_id=str(account_id),
            consumer_public_key=signer.public_key,
            network_id=str(row["network_id"]),
            channel_id=str(row["channel_id"]),
            backend_policy=str(row["backend_policy"]),
            nonce=str(row["session_salt"]),
            settlement_chain_id=int(row["chain_id"]),
            settlement_contract=str(row["settlement_contract"]),
            session_public_key=signer.public_key,
            session_private_key=private_key,
            now=current,
        )
        request = build_session_request(
            authorization=authorization,
            request_id=str(request_id),
            request_hash=request_digest,
            max_fee_units=fee,
            deadline=resolved_deadline,
            sequence=sequence,
            previous_cumulative_spend_units=previous_cumulative,
            cumulative_spend_units=previous_cumulative + fee,
            signer=signer,
            session_private_key=private_key,
            now=current,
        )
        return SessionClaim(
            plan=plan,
            authorization=authorization,
            request=request,
            private_key=private_key,
            previous_cumulative_spend_units=previous_cumulative,
        )

    def mark_activated(self, session_id: str, *, now: int | None = None) -> None:
        """Record that the Gateway has verified the on-chain session once.

        This marker is local metadata only.  Providers still perform their
        own bounded on-chain session check, but the Gateway does not need to
        repeat the same ``eth_call`` for every API request.
        """
        current = int(time.time() if now is None else now)
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE session_v4 SET activated_at=COALESCE(activated_at, ?) WHERE session_id=?",
                (current, normalize_bytes32(session_id)),
            )

    def finalize(
        self,
        session_id: str,
        *,
        sequence: int,
        amount_units: int,
        request_hash: str,
        response_payload: Mapping[str, Any],
        settlement_payload: Mapping[str, Any] | None = None,
        now: int | None = None,
    ) -> None:
        amount = int(amount_units)
        if amount < 0:
            raise SessionServiceError("settled amount cannot be negative")
        request_digest = normalize_bytes32(request_hash)
        try:
            response_json = json.dumps(
                dict(response_payload),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise SessionServiceError("V4 response is not canonical JSON") from exc
        completed_at = int(time.time() if now is None else now)
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM session_v4 WHERE session_id = ?", (normalize_bytes32(session_id),)).fetchone()
            if row is None or row["claimed_sequence"] != int(sequence):
                db.execute("ROLLBACK")
                raise SessionServiceError("V4 session claim does not match finalization")
            claimed_hash = normalize_bytes32(str(row["claimed_request_hash"] or "0x" + "0" * 64))
            if claimed_hash != request_digest:
                db.execute("ROLLBACK")
                raise SessionServiceError("V4 request hash does not match finalization")
            previous = int(row["claimed_previous_cumulative_units"] or 0)
            if amount > int(row["claimed_max_fee_units"] or 0):
                db.execute("ROLLBACK")
                raise SessionServiceError("settled amount exceeds claimed fee")
            cumulative = previous + amount
            if cumulative > int(row["max_amount_units"]):
                db.execute("ROLLBACK")
                raise SessionServiceError("settled amount exceeds session cap")
            request_id = str(row["claimed_request_id"] or "")
            if not request_id:
                db.execute("ROLLBACK")
                raise SessionServiceError("V4 session claim request_id is missing")
            settlement_json: str | None = None
            if settlement_payload is not None:
                try:
                    settlement_json = json.dumps(
                        dict(settlement_payload),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                except (TypeError, ValueError) as exc:
                    db.execute("ROLLBACK")
                    raise SessionServiceError("V4 settlement payload is not canonical JSON") from exc
            existing = db.execute(
                "SELECT response_json, request_hash, settlement_json FROM session_v4_results WHERE session_id=? AND request_id=?",
                (normalize_bytes32(session_id), request_id),
            ).fetchone()
            if existing is not None and (
                str(existing["response_json"]) != response_json
                or normalize_bytes32(str(existing["request_hash"] or "0x" + "0" * 64)) != request_digest
            ):
                db.execute("ROLLBACK")
                raise SessionServiceError("V4 request_id already has a different result")
            db.execute(
                """
                INSERT INTO session_v4_results(
                    session_id, request_id, account_id, sequence, amount_units,
                    request_hash, response_json, settlement_json, settlement_status, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, request_id) DO NOTHING
                """,
                (
                    normalize_bytes32(session_id),
                    request_id,
                    str(row["account_id"]),
                    int(sequence),
                    amount,
                    request_digest,
                    response_json,
                    settlement_json,
                    "pending" if settlement_json is not None else "none",
                    completed_at,
                ),
            )
            db.execute(
                """
                UPDATE session_v4 SET next_sequence=?, cumulative_spend_units=?,
                    claimed_sequence=NULL, claimed_request_id=NULL, claimed_request_hash=NULL,
                    claimed_max_fee_units=NULL, claimed_deadline=NULL,
                    claimed_previous_cumulative_units=NULL, claimed_at=NULL
                WHERE session_id=?
                """,
                (int(sequence), cumulative, normalize_bytes32(session_id)),
            )
            db.execute("COMMIT")

    def completed_response(
        self,
        *,
        session_id: str,
        request_id: str,
        account_id: str,
        request_hash: str | None = None,
    ) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT response_json, request_hash FROM session_v4_results
                WHERE session_id=? AND request_id=? AND account_id=?
                """,
                (normalize_bytes32(session_id), str(request_id), str(account_id)),
            ).fetchone()
        if row is None:
            return None
        if request_hash is not None:
            expected = normalize_bytes32(request_hash)
            actual = normalize_bytes32(str(row["request_hash"] or "0x" + "0" * 64))
            if actual != expected:
                raise SessionServiceError("V4 request_id is already bound to a different request")
        value = json.loads(str(row["response_json"]))
        if not isinstance(value, dict):
            raise SessionServiceError("stored V4 response is malformed")
        return value

    def rollback(self, session_id: str, *, sequence: int) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """
                UPDATE session_v4 SET claimed_sequence=NULL, claimed_request_id=NULL, claimed_request_hash=NULL,
                    claimed_max_fee_units=NULL, claimed_deadline=NULL,
                    claimed_previous_cumulative_units=NULL, claimed_at=NULL
                WHERE session_id=? AND claimed_sequence=?
                """,
                (normalize_bytes32(session_id), int(sequence)),
            )

    def pending_settlements(self, *, limit: int = 32) -> list[dict[str, Any]]:
        """Return durable receipts that still need relayer delivery."""
        bounded = max(1, min(int(limit), 256))
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT session_id, request_id, sequence, settlement_json,
                       settlement_status, settlement_tx_hash
                FROM session_v4_results
                WHERE settlement_json IS NOT NULL
                  AND settlement_status IN ('pending', 'submitted')
                ORDER BY completed_at ASC, sequence ASC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["settlement_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise SessionServiceError("stored V4 settlement payload is malformed") from exc
            if not isinstance(payload, dict):
                raise SessionServiceError("stored V4 settlement payload is malformed")
            result.append(
                {
                    "session_id": str(row["session_id"]),
                    "request_id": str(row["request_id"]),
                    "sequence": int(row["sequence"]),
                    "payload": payload,
                    "status": str(row["settlement_status"]),
                    "tx_hash": str(row["settlement_tx_hash"] or "") or None,
                }
            )
        return result

    def mark_settlement_submitted(self, *, session_id: str, request_id: str, tx_hash: str) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """
                UPDATE session_v4_results
                SET settlement_status='submitted', settlement_tx_hash=?, settlement_error=NULL
                WHERE session_id=? AND request_id=? AND settlement_json IS NOT NULL
                """,
                (str(tx_hash), normalize_bytes32(session_id), str(request_id)),
            )

    def mark_settlement_confirmed(self, *, session_id: str, request_id: str, tx_hash: str | None = None) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """
                UPDATE session_v4_results
                SET settlement_status='confirmed', settlement_tx_hash=COALESCE(?, settlement_tx_hash), settlement_error=NULL
                WHERE session_id=? AND request_id=?
                """,
                (str(tx_hash) if tx_hash else None, normalize_bytes32(session_id), str(request_id)),
            )

    def mark_settlement_failed(
        self,
        *,
        session_id: str,
        request_id: str,
        error: str,
        retryable: bool = True,
    ) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """
                UPDATE session_v4_results
                SET settlement_status=?, settlement_error=?
                WHERE session_id=? AND request_id=?
                """,
                (
                    "pending" if retryable else "failed",
                    str(error)[:2000],
                    normalize_bytes32(session_id),
                    str(request_id),
                ),
            )

    def _row(self, session_id: str) -> sqlite3.Row | None:
        with self._connect() as db:
            return db.execute("SELECT * FROM session_v4 WHERE session_id = ?", (normalize_bytes32(session_id),)).fetchone()


def session_id_for(*, contract: str, chain_id: int, consumer: str, session_salt: str) -> str:
    return "0x" + keccak256(
        b"".join(
            [
                abi_encode_arg(normalize_address(contract)),
                abi_encode_arg(str(int(chain_id))),
                abi_encode_arg(normalize_address(consumer)),
                abi_encode_arg(normalize_bytes32(session_salt)),
            ]
        )
    ).hex()


def decode_session_info(output: str) -> dict[str, Any]:
    """Decode the fixed-size ``sessionInfo`` ABI tuple for activation checks."""
    raw = str(output or "")
    if not raw.startswith("0x") or len(raw) < 2 + 13 * 64:
        raise SessionServiceError("Settlement V4 sessionInfo returned malformed ABI data")
    words = [raw[2 + index * 64 : 2 + (index + 1) * 64] for index in range(13)]
    return {
        "consumer": "0x" + words[0][-40:],
        "provider": "0x" + words[1][-40:],
        "session_key": "0x" + words[2][-40:],
        "channel": "0x" + words[3],
        "pricing_version": int(words[4], 16),
        "pricing_hash": "0x" + words[5],
        "opened_at": int(words[6], 16),
        "expires_at": int(words[7], 16),
        "close_requested_at": int(words[8], 16),
        "max_amount_units": int(words[9], 16),
        "spent": int(words[10], 16),
        "next_sequence": int(words[11], 16),
        "closed": bool(int(words[12], 16)),
    }


def verify_opened_session(
    *,
    rpc_url: str,
    contract: str,
    plan: Mapping[str, Any],
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Read one session record after activation; no confirmation-depth wait."""
    output = call_contract(
        rpc_url,
        contract,
        "sessionInfo(bytes32)",
        [normalize_bytes32(str(plan["session_id"]))],
        timeout=timeout,
        block_tag="latest",
    )
    actual = decode_session_info(output)
    expected = {
        "consumer": normalize_address(str(plan["consumer_payment_address"])),
        "provider": normalize_address(str(plan["provider_payment_address"])),
        "session_key": normalize_address(str(plan["session_key"])),
        "channel": normalize_bytes32(str(plan["channel_hash"])),
        "pricing_version": int(plan["pricing_version"]),
        "pricing_hash": normalize_bytes32(str(plan["pricing_hash"])),
        "max_amount_units": int(plan["max_amount_units"]),
        "expires_at": int(plan["expires_at"]),
    }
    for field, value in expected.items():
        actual_value = actual[field]
        if isinstance(value, str):
            if field in {"consumer", "provider", "session_key"} and normalize_address(actual_value) == ZERO_ADDRESS:
                raise SessionServiceError("Settlement V4 session is not active yet")
            if str(actual_value).lower() != str(value).lower():
                raise SessionServiceError(f"Settlement V4 session {field} mismatch")
        elif int(actual_value) != int(value):
            raise SessionServiceError(f"Settlement V4 session {field} mismatch")
    if actual["closed"]:
        raise SessionServiceError("Settlement V4 session is closed")
    return actual


def _row_plan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "schema": SESSION_V4_PLAN_SCHEMA,
        "account_id": str(row["account_id"]),
        "consumer_payment_address": str(row["consumer"]),
        "provider_id": str(row["provider_id"]),
        "provider_payment_address": str(row["provider_payment_address"]),
        "session_salt": str(row["session_salt"]),
        "session_id": str(row["session_id"]),
        "session_key": str(row["session_key"]),
        "channel": str(row["channel"]),
        "channel_hash": str(row["channel_hash"]),
        "pricing_version": int(row["pricing_version"]),
        "pricing_hash": str(row["pricing_hash"]),
        "chain_id": int(row["chain_id"]),
        "settlement_contract": str(row["settlement_contract"]),
        "network_id": str(row["network_id"]),
        "channel_id": str(row["channel_id"]),
        "backend_policy": str(row["backend_policy"]),
        "max_amount_units": int(row["max_amount_units"]),
        "expires_at": int(row["expires_at"]),
        "next_sequence": int(row["next_sequence"]),
        "cumulative_spend_units": int(row["cumulative_spend_units"]),
        "activated_at": int(row["activated_at"] or 0),
        "activation_required": True,
        "required_activation_confirmations": 1,
    }


def _validate_row_owner(row: sqlite3.Row, account_id: str) -> None:
    if str(row["account_id"]) != str(account_id):
        raise SessionServiceError("V4 session does not belong to this API account")


def _validate_row_active(row: sqlite3.Row, now: int) -> None:
    if int(row["closed"] or 0):
        raise SessionServiceError("V4 session is closed")
    if int(row["expires_at"]) <= int(now):
        raise SessionServiceError("V4 session has expired")


def _nonzero_address(value: Any, label: str) -> str:
    normalized = normalize_address(str(value or ""))
    if normalized == ZERO_ADDRESS:
        raise SessionServiceError(f"{label} must be non-zero")
    return normalized
