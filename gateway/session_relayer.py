"""Relay-owned V5 receipt intake and transaction submission.

The Consumer keeps the session key and signs the completed receipt.  The
Relay only validates the signed envelope, persists it, and spends its own
native gas to submit the contract call.  This keeps the transaction relayer
an internal Relay component instead of exposing a fourth operator role.
"""

from __future__ import annotations

import json
import logging
import math
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence
from uuid import uuid4

from .chain import (
    ChainError,
    EvmSignature,
    ZERO_ADDRESS,
    normalize_address,
    parse_private_key,
    private_key_to_address,
    recover_evm_address,
    rpc_call,
    keccak256,
    sign_legacy_transaction,
)
from .chain_v4 import _parse_signature, _signature_bytes
from .chain_v5 import (
    encode_settle_signed_receipt,
    encode_settle_signed_receipt_tuple,
    encode_settle_signed_batch_tuples,
    session_receipt_digest,
    verify_provider_settlement_payload,
    verify_relay_attestation,
)
from .chain_v6 import (
    encode_settle_signed_receipt as encode_settle_signed_receipt_v6,
    encode_settle_signed_receipt_tuple as encode_settle_signed_receipt_tuple_v6,
    session_receipt_digest as session_receipt_digest_v6,
    verify_provider_settlement_payload as verify_provider_settlement_payload_v6,
    verify_relay_attestation as verify_relay_attestation_v6,
)


logger = logging.getLogger(__name__)

RELAY_SETTLEMENT_SCHEMA = "mycomesh.relay.settlement.v1"
DEFAULT_RELAY_SETTLEMENT_DB = "/data/relay-settlement.sqlite3"
DEFAULT_RELAY_SETTLEMENT_POLL_SECONDS = 5.0
DEFAULT_RELAY_SETTLEMENT_TIMEOUT_SECONDS = 30.0
DEFAULT_RELAY_SETTLEMENT_RECEIPT_TIMEOUT_SECONDS = 180.0
DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE = 8
MAX_RELAY_SETTLEMENT_BATCH_SIZE = 32
DEFAULT_RELAY_SETTLEMENT_INTERVAL_SECONDS = 7200
DEFAULT_RELAY_SETTLEMENT_COUNT_THRESHOLD = 100
DEFAULT_RELAY_SETTLEMENT_DEADLINE_MARGIN_SECONDS = 300


class RelaySettlementError(RuntimeError):
    """Raised when a Consumer settlement envelope cannot be accepted."""

    def __init__(self, message: str, *, error_code: str = "settlement_unavailable") -> None:
        super().__init__(message)
        self.error_code = error_code


def settlement_error_code(error: Any) -> str:
    """Public enum only: RPC exception text may contain signed transaction data."""
    value = str(error or "").lower()
    if value in {"authorization_expired", "receipt_expired", "low_gas", "broadcast_unknown", "confirmation_timeout", "invalid_receipt", "wrong_chain", "rpc_unavailable", "transaction_reverted", "already_settled", "settlement_failed"}:
        return value
    if "authorization" in value and any(part in value for part in ("expired", "deadline", "elapsed")):
        return "authorization_expired"
    if any(part in value for part in ("receipt expired", "session expired", "attestation deadline", "receipt deadline")):
        return "receipt_expired"
    if "insufficient funds" in value or "low_gas" in value:
        return "low_gas"
    if "broadcast_unknown" in value:
        return "broadcast_unknown"
    if "revert" in value:
        return "transaction_reverted"
    if any(part in value for part in ("timeout", "timed out", "connection", "rpc_unavailable")):
        return "rpc_unavailable"
    if "settled" in value:
        return "already_settled"
    return "settlement_failed" if value else ""


def _payload_metadata(payload: Mapping[str, Any]) -> tuple[str | None, int | None, str]:
    signed = payload.get("signed_receipt") or {}
    envelope = signed.get("authorization") or {} if isinstance(signed, Mapping) else {}
    authorization = envelope.get("authorization") or {} if isinstance(envelope, Mapping) else {}
    key = authorization.get("key") if isinstance(authorization, Mapping) else None
    key = key.lower() if isinstance(key, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", key) else None
    candidates = []
    mappings = [authorization, signed.get("receipt") if isinstance(signed, Mapping) else None,
                payload.get("relay_attestation"), (payload.get("provider_settlement") or {}).get("receipt")]
    for value in mappings:
        if isinstance(value, Mapping):
            deadline = value.get("deadline")
            if isinstance(deadline, (int, str)) and not isinstance(deadline, bool):
                try:
                    number = int(deadline)
                    if number > 0:
                        candidates.append(number)
                except ValueError:
                    pass
    return key, min(candidates) if candidates else None, "authorization_expired" if key else "receipt_expired"


@dataclass(frozen=True)
class PreparedRelaySettlement:
    key: str
    session_id: str
    receipt_hash: str
    sequence: int
    chain_id: int
    settlement_contract: str
    calldata: str
    payload: dict[str, Any]


def _signature(value: Any, label: str) -> tuple[EvmSignature, bytes]:
    try:
        parsed = _parse_signature(value, label)
        return parsed, _signature_bytes(parsed, label)
    except (ChainError, TypeError, ValueError) as exc:
        raise RelaySettlementError(str(exc)) from exc


def prepare_relay_settlement(
    submission: Mapping[str, Any],
    *,
    expected_chain_id: int | None,
    expected_contract: str | None,
    expected_relay: str | None,
    attestation_private_keys: Mapping[str, str],
    now: int | None = None,
) -> PreparedRelaySettlement:
    """Validate a Consumer envelope and rebuild the only accepted calldata."""

    if not isinstance(submission, Mapping):
        raise RelaySettlementError("settlement submission must be an object")
    required = {
        "schema",
        "protocol_version",
        "chain_id",
        "settlement_contract",
        "provider_settlement",
        "session_signature",
        "relay_attestation",
    }
    if set(submission) != required:
        raise RelaySettlementError("settlement submission fields are invalid")
    if submission.get("schema") != RELAY_SETTLEMENT_SCHEMA:
        raise RelaySettlementError("unsupported Relay settlement schema")
    try:
        protocol_version = int(submission.get("protocol_version"))
        chain_id = int(submission.get("chain_id"))
    except (TypeError, ValueError) as exc:
        raise RelaySettlementError("settlement protocol_version and chain_id must be integers") from exc
    if protocol_version not in {5, 6}:
        raise RelaySettlementError("Relay settlement intake only supports V5 or V6")
    if chain_id <= 0:
        raise RelaySettlementError("settlement chain_id must be positive")
    try:
        contract = normalize_address(str(submission.get("settlement_contract") or ""))
    except ChainError as exc:
        raise RelaySettlementError(f"invalid settlement contract: {exc}") from exc
    if expected_chain_id is not None and chain_id != int(expected_chain_id):
        raise RelaySettlementError("settlement chain_id does not match the Relay deployment")
    if expected_contract is not None:
        try:
            expected = normalize_address(expected_contract)
        except ChainError as exc:
            raise RelaySettlementError(f"invalid configured settlement contract: {exc}") from exc
        if contract != expected:
            raise RelaySettlementError("settlement contract does not match the Relay deployment")

    provider_payload = submission.get("provider_settlement")
    if not isinstance(provider_payload, Mapping):
        raise RelaySettlementError("provider_settlement must be an object")
    try:
        verify_payload = verify_provider_settlement_payload_v6 if protocol_version == 6 else verify_provider_settlement_payload
        receipt = verify_payload(provider_payload)
    except (ChainError, TypeError, ValueError) as exc:
        raise RelaySettlementError(f"invalid Provider settlement payload: {exc}") from exc
    try:
        provider_contract = normalize_address(str(provider_payload.get("settlement_contract") or ""))
    except ChainError as exc:
        raise RelaySettlementError(f"invalid Provider settlement contract: {exc}") from exc
    if int(provider_payload.get("chain_id") or 0) != chain_id or provider_contract != contract:
        raise RelaySettlementError("Provider settlement deployment does not match the submission")
    if expected_relay is not None:
        try:
            relay = normalize_address(expected_relay)
        except ChainError as exc:
            raise RelaySettlementError(f"invalid configured Relay payout address: {exc}") from exc
        if relay == ZERO_ADDRESS or normalize_address(receipt.relay) != relay:
            raise RelaySettlementError("receipt Relay payout does not match this Relay")
    elif normalize_address(receipt.relay) == ZERO_ADDRESS:
        raise RelaySettlementError(f"V{protocol_version} Relay settlement requires a non-zero Relay payout")

    digest_builder = session_receipt_digest_v6 if protocol_version == 6 else session_receipt_digest
    digest = digest_builder(receipt, chain_id=chain_id, verifying_contract=contract)
    session_signature, session_signature_bytes = _signature(
        submission.get("session_signature"),
        "session signature",
    )
    try:
        # Contract validation remains authoritative for the session key.  The
        # recovery check rejects malformed signatures before they enter the
        # durable queue and prevents the Relay from wasting gas on junk.
        recover_evm_address(digest, session_signature)
    except (ChainError, TypeError, ValueError) as exc:
        raise RelaySettlementError(f"invalid session signature: {exc}") from exc

    attestation_value = submission.get("relay_attestation")
    relay_attestation: dict[str, Any] | None
    relay_signature_bytes = b""
    if normalize_address(receipt.relay) == ZERO_ADDRESS:
        if attestation_value is not None:
            raise RelaySettlementError("zero Relay payout cannot include an attestation")
        relay_attestation = None
    else:
        if not isinstance(attestation_value, Mapping):
            raise RelaySettlementError(f"V{protocol_version} Relay settlement requires a Relay attestation")
        try:
            signer = normalize_address(str(attestation_value.get("signer") or ""))
        except ChainError as exc:
            raise RelaySettlementError(f"invalid Relay attestation signer: {exc}") from exc
        try:
            private_keys = {
                normalize_address(str(address)): str(private_key)
                for address, private_key in attestation_private_keys.items()
            }
        except (ChainError, TypeError, ValueError) as exc:
            raise RelaySettlementError(f"Relay attestation key set is invalid: {exc}") from exc
        if signer not in private_keys:
            raise RelaySettlementError("Relay attestation signer is not active on this Relay")
        try:
            verify_attestation = verify_relay_attestation_v6 if protocol_version == 6 else verify_relay_attestation
            relay_attestation = verify_attestation(
                dict(attestation_value),
                expected_signer=signer,
                receipt=receipt,
                expected_chain_id=chain_id,
                expected_contract=contract,
                now=now,
            )
        except (ChainError, TypeError, ValueError) as exc:
            raise RelaySettlementError(f"invalid Relay attestation: {exc}") from exc
        _, relay_signature_bytes = _signature(relay_attestation["signature"], "Relay attestation signature")

    _, provider_signature_bytes = _signature(
        provider_payload.get("provider_signature"),
        "Provider signature",
    )
    try:
        encode_receipt = encode_settle_signed_receipt_v6 if protocol_version == 6 else encode_settle_signed_receipt
        encode_tuple = encode_settle_signed_receipt_tuple_v6 if protocol_version == 6 else encode_settle_signed_receipt_tuple
        calldata = encode_receipt(
            receipt,
            relay_attestation,
            session_signature_bytes,
            provider_signature_bytes,
            relay_signature_bytes,
        )
    except (ChainError, TypeError, ValueError) as exc:
        raise RelaySettlementError(f"failed to encode V{protocol_version} settlement: {exc}") from exc

    key = f"{receipt.session_id.lower()}:{receipt.receipt_hash.lower()}"
    payload = {
        "schema": RELAY_SETTLEMENT_SCHEMA,
        "protocol_version": protocol_version,
        "chain_id": chain_id,
        "settlement_contract": contract,
        "provider_settlement": dict(provider_payload),
        "session_signature": str(submission["session_signature"]),
        "relay_attestation": relay_attestation,
        "calldata": calldata,
        "tuple_data": "0x" + encode_tuple(
            receipt,
            relay_attestation,
            session_signature_bytes,
            provider_signature_bytes,
            relay_signature_bytes,
        ).hex(),
        "receipt_digest": "0x" + digest.hex(),
    }
    return PreparedRelaySettlement(
        key=key,
        session_id=receipt.session_id,
        receipt_hash=receipt.receipt_hash,
        sequence=int(receipt.sequence),
        chain_id=chain_id,
        settlement_contract=contract,
        calldata=calldata,
        payload=payload,
    )


class RelaySettlementOutbox:
    """Small SQLite spool that survives Relay restarts and duplicate posts."""

    def __init__(self, path: str | Path = DEFAULT_RELAY_SETTLEMENT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._expiry_cursor = 0
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA busy_timeout=10000")
            # sqlite3.Connection.__exit__ commits/rolls back, but DOES NOT
            # close the handle. Explicit closure is essential for health
            # polling: GC-dependent cleanup can exhaust a long-running Relay.
            with db:
                yield db
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS relay_settlement_outbox (
                    settlement_key TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    chain_id INTEGER NOT NULL,
                    settlement_contract TEXT NOT NULL,
                    calldata TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    tx_hash TEXT,
                    raw_transaction TEXT,
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(relay_settlement_outbox)")}
            if "raw_transaction" not in columns:
                db.execute("ALTER TABLE relay_settlement_outbox ADD COLUMN raw_transaction TEXT")
            if "enqueued_at" not in columns:
                db.execute("ALTER TABLE relay_settlement_outbox ADD COLUMN enqueued_at INTEGER")
            if "authorization_deadline" not in columns:
                db.execute("ALTER TABLE relay_settlement_outbox ADD COLUMN authorization_deadline INTEGER")
            # created_at historically moves on retry. Keep a separate immutable
            # queue age so a restart or transient RPC failure cannot reset it.
            db.execute("UPDATE relay_settlement_outbox SET enqueued_at=created_at WHERE enqueued_at IS NULL")
            for row in db.execute("SELECT settlement_key,payload_json FROM relay_settlement_outbox WHERE status='pending' AND authorization_deadline IS NULL").fetchall():
                try:
                    _, expiry, _ = _payload_metadata(json.loads(row["payload_json"]))
                except (TypeError, ValueError, AttributeError):
                    expiry = None
                if expiry is not None:
                    db.execute("UPDATE relay_settlement_outbox SET authorization_deadline=? WHERE settlement_key=?", (expiry, row["settlement_key"]))
            db.execute("CREATE TABLE IF NOT EXISTS relay_settlement_schedule (id INTEGER PRIMARY KEY CHECK(id=1), last_settlement_at INTEGER, drain_through_rowid INTEGER, drain_triggered_at INTEGER, drain_reason TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS relay_v10_dispatches (chain_id INTEGER NOT NULL, contract TEXT NOT NULL, channel_id TEXT NOT NULL, request_id TEXT NOT NULL, authorization_json TEXT NOT NULL, dispatch_json TEXT NOT NULL, PRIMARY KEY(chain_id,contract,channel_id,request_id))")
            db.execute("INSERT OR IGNORE INTO relay_settlement_schedule(id,last_settlement_at) SELECT 1,MAX(updated_at) FROM relay_settlement_outbox WHERE status IN ('confirmed','escrowed')")
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_relay_settlement_status "
                "ON relay_settlement_outbox(status, created_at)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_relay_settlement_pending_session_sequence "
                "ON relay_settlement_outbox(status, session_id, sequence)"
            )
            # Older workers could put a possibly broadcast transaction back in
            # pending after an RPC error. Never allocate a fresh nonce for it.
            rows = db.execute("SELECT settlement_key,tx_hash,error FROM relay_settlement_outbox WHERE status='pending' AND error IS NOT NULL").fetchall()
            for row in rows:
                raw_error = str(row["error"] or "").lower()
                code = settlement_error_code(raw_error)
                if code in {"authorization_expired", "receipt_expired"}:
                    db.execute("UPDATE relay_settlement_outbox SET status='failed',error=? WHERE settlement_key=?", (code, row["settlement_key"]))
                elif code not in {"low_gas", "transaction_reverted"} and (row["tx_hash"] or "eth_sendrawtransaction" in raw_error):
                    state = "submitted" if re.fullmatch(r"0x[0-9a-fA-F]{64}", str(row["tx_hash"] or "")) else "broadcast_unknown"
                    db.execute("UPDATE relay_settlement_outbox SET status=?,error='broadcast_unknown' WHERE settlement_key=?", (state, row["settlement_key"]))

    def v10_dispatch(self, authorization: Mapping[str, Any], *, build: Callable | None = None) -> dict[str, Any] | None:
        """Commit exactly one signed dispatch before network/model execution.

        ECDSA signing is nondeterministic. Re-signing the same digest after a
        restart would conflict with the Provider's exact durable request fence.
        """
        raw = authorization['authorization']
        binding = (authorization['chain_id'], authorization['settlement_contract'], raw['channel_id'], raw['request_id'])
        encoded = json.dumps(dict(authorization), sort_keys=True, separators=(',', ':'))
        with self._lock, self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT authorization_json,dispatch_json FROM relay_v10_dispatches WHERE chain_id=? AND contract=? AND channel_id=? AND request_id=?', binding).fetchone()
            if existing:
                if existing['authorization_json'] != encoded:
                    raise RelaySettlementError('V10 request reused with different authorization', error_code='invalid_receipt')
                return json.loads(existing['dispatch_json'])
            if build is None:
                return None
            dispatch = build()
            db.execute('INSERT INTO relay_v10_dispatches VALUES(?,?,?,?,?,?)',
                (*binding, encoded, json.dumps(dispatch, sort_keys=True, separators=(',', ':'))))
            return dispatch

    def enqueue(self, prepared: PreparedRelaySettlement) -> tuple[str, bool]:
        now = int(time.time())
        try:
            _, expiry, _ = _payload_metadata(prepared.payload)
        except (TypeError, ValueError, AttributeError):
            expiry = None
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT status FROM relay_settlement_outbox WHERE settlement_key=?",
                (prepared.key,),
            ).fetchone()
            if existing is not None:
                status = str(existing["status"])
                # A duplicate upload must never resurrect a permanently expired
                # receipt or a reverted/ambiguous transaction.
                return status, False
            db.execute(
                """
                INSERT INTO relay_settlement_outbox(
                    settlement_key, session_id, receipt_hash, sequence, chain_id,
                    settlement_contract, calldata, payload_json, created_at, updated_at,
                    enqueued_at, authorization_deadline
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    prepared.key,
                    prepared.session_id,
                    prepared.receipt_hash,
                    prepared.sequence,
                    prepared.chain_id,
                    prepared.settlement_contract,
                    prepared.calldata,
                    json.dumps(prepared.payload, sort_keys=True, separators=(",", ":")),
                    now,
                    now,
                    now,
                    expiry,
                ),
            )
        return "pending", True

    def status(self, key: str) -> str | None:
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT status FROM relay_settlement_outbox WHERE settlement_key=?",
                (str(key),),
            ).fetchone()
        return str(row["status"]) if row is not None else None

    def public_status(self, request_id: str, *, key_address: str | None = None,
                      settlement_version: int = 8, chain_id: int | None = None,
                      settlement_contract: str | None = None, channel_id: str | None = None) -> dict[str, Any] | None:
        request_id = str(request_id).lower()
        key_address = str(key_address or "").lower()
        if settlement_version not in {7, 8, 9, 10} or not re.fullmatch(r"0x[0-9a-f]{64}", request_id) or not re.fullmatch(r"0x[0-9a-f]{40}", key_address):
            return None
        with self._lock, self._connect() as db:
            if settlement_version in {9, 10}:
                if settlement_version == 10 and not re.fullmatch(r"0x[0-9a-f]{64}", str(channel_id or "")):
                    return None
                if chain_id is None or not settlement_contract:
                    return None
                rows = db.execute("SELECT session_id,status,error,tx_hash,updated_at,payload_json FROM relay_settlement_outbox WHERE session_id=? AND chain_id=? AND settlement_contract=?",
                                  (request_id, chain_id, normalize_address(settlement_contract))).fetchall()
                matches = []
                for candidate in rows:
                    try:
                        payload = json.loads(candidate["payload_json"])
                        if (payload.get("protocol_version") == settlement_version and _payload_metadata(payload)[0] == key_address
                                and (settlement_version != 10 or payload.get("channel_id") == channel_id)):
                            matches.append(candidate)
                    except (TypeError, ValueError, AttributeError):
                        continue
                row = matches[0] if len(matches) == 1 else None
            else:
                row = db.execute("SELECT session_id,status,error,tx_hash,updated_at,payload_json FROM relay_settlement_outbox WHERE settlement_key=? AND session_id=?",
                                 (f"v{settlement_version}:{key_address}:{request_id}", request_id)).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload_json"])
            original_key, deadline, _ = _payload_metadata(payload)
        except (TypeError, ValueError, AttributeError):
            return None
        if original_key != key_address:
            return None
        tx_hash = str(row["tx_hash"] or "").lower()
        return {"request_id": request_id, "status": str(row["status"]),
                "error_code": settlement_error_code(row["error"]) or None,
                "tx_hash": tx_hash if re.fullmatch(r"0x[0-9a-f]{64}", tx_hash) else None,
                "updated_at": int(row["updated_at"]), "authorization_deadline": deadline,
                **({"onchain_settlement_key": payload.get("settlement_key"),
                    "escrow_release_at": (payload.get("escrow_event") or {}).get("release_at")}
                   if settlement_version in {9, 10} else {}),
                **({"channel_id": channel_id, "protocol_version": 10} if settlement_version == 10 else {})}

    def submission_items(self, keys: list[str]) -> list[dict[str, Any]]:
        """Read exact durable rows for receipt/event reconciliation."""
        with self._lock, self._connect() as db:
            rows = [db.execute("SELECT * FROM relay_settlement_outbox WHERE settlement_key=?", (key,)).fetchone()
                    for key in keys]
        if any(row is None for row in rows):
            raise RelaySettlementError("settlement reconciliation row missing", error_code="rpc_unavailable")
        return [dict(row) for row in rows]

    def known_statuses(self, keys: list[str]) -> dict[str, str]:
        """Bounded read for independent submitters skipping already terminal rows."""
        result = {}
        with self._lock, self._connect() as db:
            for start in range(0, len(keys), 256):
                chunk = keys[start:start+256]
                if chunk:
                    marks = ','.join('?' for _ in chunk)
                    result.update((row['settlement_key'], row['status']) for row in db.execute(
                        f'SELECT settlement_key,status FROM relay_settlement_outbox WHERE settlement_key IN ({marks})', chunk))
        return result

    def mark_escrowed_many(self, events: Mapping[str, Mapping[str, Any]], tx_hash: str) -> None:
        """V9 confirmation records escrow, never an earned or claimable fee."""
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for key, event in events.items():
                row = db.execute("SELECT payload_json FROM relay_settlement_outbox WHERE settlement_key=?", (key,)).fetchone()
                if row is None:
                    raise RelaySettlementError("escrow reconciliation row missing")
                payload = json.loads(row["payload_json"])
                payload["escrow_event"] = dict(event)
                db.execute("UPDATE relay_settlement_outbox SET status='escrowed',tx_hash=?,error=NULL,payload_json=?,updated_at=? WHERE settlement_key=?",
                           (tx_hash, json.dumps(payload, sort_keys=True, separators=(",", ":")), int(time.time()), key))
            if events:
                db.execute("UPDATE relay_settlement_schedule SET last_settlement_at=? WHERE id=1", (int(time.time()),))

    def expire_pending(self, *, now: int | None = None, limit: int = 256) -> int:
        """Bounded sweep even while the nonce worker is polling an old tx."""
        now = int(time.time()) if now is None else int(now)
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT rowid,settlement_key,payload_json FROM relay_settlement_outbox WHERE status='pending' AND rowid>? ORDER BY rowid LIMIT ?",
                              (self._expiry_cursor, max(1, min(256, int(limit))))).fetchall()
            if not rows:
                self._expiry_cursor = 0
                return 0
            self._expiry_cursor = int(rows[-1]["rowid"])
            expired = []
            for row in rows:
                try:
                    _, deadline, code = _payload_metadata(json.loads(row["payload_json"]))
                except (ValueError, TypeError, AttributeError):
                    expired.append(("invalid_receipt", now, row["settlement_key"]))
                    continue
                if deadline is not None and deadline <= now:
                    expired.append((code, now, row["settlement_key"]))
            if expired:
                db.execute("BEGIN IMMEDIATE")
                db.executemany("UPDATE relay_settlement_outbox SET status='failed',error=?,updated_at=? WHERE settlement_key=? AND status='pending'", expired)
            return len(expired)

    def batching_schedule(self, *, interval_seconds: int, count_threshold: int,
                          deadline_margin_seconds: int, now: int | None = None,
                          activate: bool = False) -> dict[str, Any]:
        """Inspect/claim a durable flush cohort, independently of tx batch size.

        A claimed cohort stays due until drained, including after restart. New
        receipts cannot reset its timer, and finishing its first small on-chain
        batch cannot send the remaining cohort back to a two-hour wait.
        """
        now = int(time.time()) if now is None else int(now)
        with self._lock, self._connect() as db:
            if activate:
                db.execute("BEGIN IMMEDIATE")
            schedule = db.execute("SELECT * FROM relay_settlement_schedule WHERE id=1").fetchone()
            pending = db.execute("SELECT COUNT(*) AS count,MIN(enqueued_at) AS oldest,MIN(authorization_deadline) AS deadline,MAX(rowid) AS newest,SUM(CASE WHEN error IS NOT NULL OR attempts>0 THEN 1 ELSE 0 END) AS retries FROM relay_settlement_outbox WHERE status='pending'").fetchone()
            submitted = db.execute("SELECT COUNT(*) FROM relay_settlement_outbox WHERE status='submitted'").fetchone()[0]
            unknown = db.execute("SELECT COUNT(*) FROM relay_settlement_outbox WHERE status='broadcast_unknown'").fetchone()[0]
            ceiling = schedule["drain_through_rowid"]
            active = bool(ceiling is not None and db.execute("SELECT 1 FROM relay_settlement_outbox WHERE rowid<=? AND status IN ('pending','submitted','broadcast_unknown') LIMIT 1", (ceiling,)).fetchone())
            if activate and ceiling is not None and not active:
                db.execute("UPDATE relay_settlement_schedule SET drain_through_rowid=NULL,drain_triggered_at=NULL,drain_reason=NULL WHERE id=1")
            last = schedule["last_settlement_at"]
            count, oldest, expiry = int(pending["count"]), pending["oldest"], pending["deadline"]
            reason, trigger_at = "empty", None
            if unknown:
                # Old journals without a recoverable tx hash require operator
                # reconciliation. Never send another nonce around this fence.
                reason = "broadcast_unknown"
            elif submitted:
                reason, trigger_at = "recovery", now
            elif active:
                reason, trigger_at = str(schedule["drain_reason"]), int(schedule["drain_triggered_at"])
                later = db.execute("SELECT MIN(authorization_deadline) AS deadline,SUM(CASE WHEN error IS NOT NULL OR attempts>0 THEN 1 ELSE 0 END) AS retries FROM relay_settlement_outbox WHERE status='pending' AND rowid>?", (ceiling,)).fetchone()
                urgent = later["deadline"] is not None and int(later["deadline"]) - deadline_margin_seconds <= now
                if urgent or later["retries"]:
                    # A short-lived receipt arriving during a long flush must
                    # not expire behind an older, later-deadline cohort.
                    ceiling = int(pending["newest"])
                    reason = "authorization_deadline" if urgent else "retry"
                    if activate:
                        db.execute("UPDATE relay_settlement_schedule SET drain_through_rowid=?,drain_reason=? WHERE id=1", (ceiling, reason))
            elif count:
                anchor = min(int(oldest), int(last)) if last is not None else int(oldest)
                trigger_at, reason = anchor + interval_seconds, "interval"
                if expiry is not None and int(expiry) - deadline_margin_seconds <= trigger_at:
                    trigger_at, reason = int(expiry) - deadline_margin_seconds, "authorization_deadline"
                if count >= count_threshold:
                    trigger_at, reason = now, "count"
                if pending["retries"]:
                    trigger_at, reason = now, "retry"
            due = trigger_at is not None and trigger_at <= now
            if activate and due and count and not submitted and not unknown and not active:
                ceiling, active = int(pending["newest"]), True
                db.execute("UPDATE relay_settlement_schedule SET drain_through_rowid=?,drain_triggered_at=?,drain_reason=? WHERE id=1", (ceiling, now, reason))
            return {"interval_seconds": interval_seconds, "count_threshold": count_threshold,
                    "deadline_margin_seconds": deadline_margin_seconds, "pending_count": count,
                    "oldest_pending_at": oldest, "oldest_pending_age_seconds": max(0, now - int(oldest)) if oldest is not None else 0,
                    "earliest_authorization_deadline": expiry, "last_settlement_at": last,
                    "next_trigger_at": trigger_at, "next_trigger_reason": reason,
                    "flush_active": active, "due": due,
                    "_pending_rowid_ceiling": ceiling if active else None}

    def next_batch(self, limit: int = DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE, *,
                   pending_rowid_ceiling: int | None = None,
                   prioritize_deadlines: bool = False) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_RELAY_SETTLEMENT_BATCH_SIZE))
        with self._lock, self._connect() as db:
            if db.execute("SELECT 1 FROM relay_settlement_outbox WHERE status='broadcast_unknown' LIMIT 1").fetchone():
                return []
            submitted = db.execute(
                "SELECT * FROM relay_settlement_outbox WHERE status='submitted' "
                "ORDER BY updated_at ASC LIMIT 1"
            ).fetchone()
            if submitted is not None:
                tx_hash = str(submitted["tx_hash"] or "")
                if tx_hash:
                    rows = db.execute(
                        "SELECT * FROM relay_settlement_outbox WHERE status='submitted' AND tx_hash=? "
                        "ORDER BY created_at ASC, session_id ASC, sequence ASC LIMIT ?",
                        (tx_hash, MAX_RELAY_SETTLEMENT_BATCH_SIZE),
                    ).fetchall()
                    return [dict(row) for row in rows]
                return [dict(submitted)]
            condition = " AND rowid<=?" if pending_rowid_ceiling is not None else ""
            order = "authorization_deadline IS NULL, authorization_deadline ASC, " if prioritize_deadlines else ""
            rows = db.execute("SELECT * FROM relay_settlement_outbox WHERE status='pending'" + condition
                              + " ORDER BY " + order + "created_at ASC, session_id ASC, sequence ASC LIMIT 256",
                              (pending_rowid_ceiling,) if pending_rowid_ceiling is not None else ()).fetchall()
            # Deadline prioritisation can put a later sequence at the front of
            # the 256-row window while its earlier sequence falls outside that
            # window.  The old in-memory check then treated the later item as
            # the head of the session and could submit receipts out of order.
            # Bring each visible session's true pending head into the bounded
            # candidate set before applying the normal contiguous-sequence
            # selection.  The rowid ceiling is part of an active drain cohort,
            # so a predecessor outside it must not be pulled into this flush.
            visible_sessions = sorted({str(row["session_id"]).lower() for row in rows})
            if visible_sessions:
                marks = ",".join("?" for _ in visible_sessions)
                params: list[Any] = list(visible_sessions)
                ceiling_sql = " AND rowid<=?" if pending_rowid_ceiling is not None else ""
                if pending_rowid_ceiling is not None:
                    params.append(pending_rowid_ceiling)
                heads = db.execute(
                    "SELECT session_id,MIN(sequence) AS sequence "
                    "FROM relay_settlement_outbox WHERE status='pending' "
                    f"AND lower(session_id) IN ({marks}){ceiling_sql} GROUP BY lower(session_id)",
                    params,
                ).fetchall()
                # Fetch the exact head row even when it is already in the
                # deadline window.  It may be ordered after a later sequence;
                # the stable reconstruction below puts the head first.
                head_rows: dict[str, Any] = {}
                for head in heads:
                    session_id = str(head["session_id"]).lower()
                    sequence = int(head["sequence"])
                    predecessor = db.execute(
                        "SELECT * FROM relay_settlement_outbox WHERE status='pending' "
                        "AND lower(session_id)=? AND sequence=?" + ceiling_sql + " LIMIT 1",
                        ([session_id, sequence] + ([pending_rowid_ceiling] if pending_rowid_ceiling is not None else [])),
                    ).fetchone()
                    if predecessor is not None:
                        head_rows[session_id] = predecessor
                if head_rows:
                    # Keep deadline/age ordering between sessions, but always
                    # emit a session head before any later receipt from that
                    # session.  Without this, an appended predecessor would be
                    # visited last and the batch would contain only sequence 0.
                    ordered_rows: list[Any] = []
                    emitted: set[str] = set()
                    for row in rows:
                        session_id = str(row["session_id"]).lower()
                        head = head_rows.get(session_id)
                        if head is not None and session_id not in emitted:
                            ordered_rows.append(head)
                            emitted.add(session_id)
                        if str(row["settlement_key"]) != str(head["settlement_key"] if head is not None else ""):
                            ordered_rows.append(row)
                    rows = ordered_rows
        candidates: list[dict[str, Any]] = []
        anchor: tuple[int, str] | None = None
        selected_sequences: dict[str, int] = {}
        for row in rows:
            item = dict(row)
            session_id = str(item["session_id"]).lower()
            sequence = int(item["sequence"])
            item_anchor = (int(item["chain_id"]), str(item["settlement_contract"]).lower())
            if anchor is not None and item_anchor != anchor:
                continue
            previous = selected_sequences.get(session_id)
            if previous is None and any(
                str(other["session_id"]).lower() == session_id
                and int(other["sequence"]) < sequence
                for other in rows
            ):
                continue
            if previous is not None and sequence != previous + 1:
                continue
            # Choose the chain/contract only after this row is eligible as a
            # session head.  A deadline-prioritised row may be blocked by a
            # predecessor from another deployment; pinning the anchor before
            # that check would hide the real head and return an empty batch.
            if anchor is None:
                anchor = item_anchor
            candidates.append(item)
            selected_sequences[session_id] = sequence
            if len(candidates) >= bounded:
                break
        return candidates

    def next_item(self) -> dict[str, Any] | None:
        batch = self.next_batch(1)
        return batch[0] if batch else None

    def mark_submitted(self, key: str, tx_hash: str) -> None:
        self.mark_submitted_many([key], tx_hash)

    def mark_submitted_many(self, keys: list[str], tx_hash: str, *, raw_transaction: str | None = None) -> None:
        if not keys:
            return
        if raw_transaction is not None:
            try:
                raw = bytes.fromhex(raw_transaction.removeprefix("0x"))
                valid = bool(raw) and raw_transaction.startswith("0x") and "0x" + keccak256(raw).hex() == tx_hash.lower()
            except (TypeError, ValueError):
                valid = False
            if not valid:
                raise RelaySettlementError("signed transaction does not match its hash", error_code="broadcast_unknown")
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if raw_transaction is not None:
                for key in keys:
                    row = db.execute("SELECT status,tx_hash FROM relay_settlement_outbox WHERE settlement_key=?", (key,)).fetchone()
                    if row is None or row["status"] != "pending" or row["tx_hash"]:
                        raise RelaySettlementError("transaction already submitted or no longer pending", error_code="broadcast_unknown")
            db.executemany(
                "UPDATE relay_settlement_outbox SET status='submitted', tx_hash=?, raw_transaction=?, attempts=attempts+1, "
                "error='broadcast_unknown', updated_at=? WHERE settlement_key=?",
                [(str(tx_hash), raw_transaction, int(time.time()), str(key)) for key in keys],
            )

    def signed_transaction(self, keys: list[str], tx_hash: str) -> tuple[int, str] | None:
        """Private recovery material, never included in public status."""
        with self._lock, self._connect() as db:
            rows = [db.execute("SELECT status,tx_hash,chain_id,raw_transaction FROM relay_settlement_outbox WHERE settlement_key=?",
                               (key,)).fetchone() for key in keys]
        if not rows or any(row is None or row["status"] != "submitted" or row["tx_hash"] != tx_hash for row in rows):
            raise RelaySettlementError("inconsistent durable transaction state", error_code="broadcast_unknown")
        raw_values = {row["raw_transaction"] for row in rows}
        chain_ids = {int(row["chain_id"]) for row in rows}
        if len(raw_values) != 1 or len(chain_ids) != 1:
            raise RelaySettlementError("inconsistent durable transaction batch", error_code="broadcast_unknown")
        raw_transaction = next(iter(raw_values))
        if raw_transaction is None:
            return None
        try:
            raw = bytes.fromhex(raw_transaction.removeprefix("0x"))
            valid = bool(raw) and raw_transaction.startswith("0x") and "0x" + keccak256(raw).hex() == tx_hash.lower()
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise RelaySettlementError("durable signed transaction hash mismatch", error_code="broadcast_unknown")
        return next(iter(chain_ids)), raw_transaction

    def mark_broadcast_acknowledged(self, keys: list[str]) -> None:
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany("UPDATE relay_settlement_outbox SET error=NULL,updated_at=? WHERE settlement_key=? AND status='submitted'",
                           [(int(time.time()), key) for key in keys])

    def mark_confirmed(self, key: str, tx_hash: str | None = None) -> None:
        self.mark_confirmed_many([key], tx_hash)

    def mark_confirmed_many(self, keys: list[str], tx_hash: str | None = None) -> None:
        if not keys:
            return
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany(
                "UPDATE relay_settlement_outbox SET status='confirmed', tx_hash=COALESCE(?, tx_hash), "
                "error=NULL, updated_at=? WHERE settlement_key=?",
                [
                    (str(tx_hash) if tx_hash else None, int(time.time()), str(key))
                    for key in keys
                ],
            )
            db.execute("UPDATE relay_settlement_schedule SET last_settlement_at=? WHERE id=1", (int(time.time()),))

    def mark_failed(self, key: str, error: str, *, retryable: bool) -> None:
        self.mark_failed_many([key], error, retryable=retryable)

    def mark_failed_many(self, keys: list[str], error: str, *, retryable: bool) -> None:
        if not keys:
            return
        now = int(time.time())
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany(
                "UPDATE relay_settlement_outbox SET status=?, error=?, created_at=CASE WHEN ? THEN ? ELSE created_at END, "
                "updated_at=? WHERE settlement_key=?",
                [
                    (
                        "pending" if retryable else "failed",
                        str(error)[:2000],
                        bool(retryable),
                        now,
                        now,
                        str(key),
                    )
                    for key in keys
                ],
            )

    def mark_submission_error(self, keys: list[str], code: str, *, definitely_rejected: bool = False) -> None:
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany(
                "UPDATE relay_settlement_outbox SET status=?,tx_hash=CASE WHEN ? THEN NULL ELSE tx_hash END,"
                "raw_transaction=CASE WHEN ? THEN NULL ELSE raw_transaction END,"
                "error=CASE WHEN error='broadcast_unknown' AND NOT ? THEN error ELSE ? END,updated_at=? WHERE settlement_key=?",
                [("pending" if definitely_rejected else "submitted", definitely_rejected, definitely_rejected, definitely_rejected, code, int(time.time()), key) for key in keys],
            )

    def blocking_error(self) -> str | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT error FROM relay_settlement_outbox WHERE status='broadcast_unknown' OR (status='submitted' AND error IN ('broadcast_unknown','confirmation_timeout')) LIMIT 1").fetchone()
        return settlement_error_code(row["error"]) or "broadcast_unknown" if row else None

    def snapshot(self) -> dict[str, int]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT status, COUNT(*) AS count FROM relay_settlement_outbox GROUP BY status"
            ).fetchall()
        return {str(row["status"]): int(row["count"]) for row in rows}


class RelaySettlementSubmitter:
    """Ordered, batched nonce-stream worker owned by one Relay process."""

    def __init__(
        self,
        *,
        outbox: RelaySettlementOutbox,
        rpc_url: str,
        private_key: str,
        poll_seconds: float = DEFAULT_RELAY_SETTLEMENT_POLL_SECONDS,
        tx_timeout_seconds: float = DEFAULT_RELAY_SETTLEMENT_TIMEOUT_SECONDS,
        receipt_timeout_seconds: float = DEFAULT_RELAY_SETTLEMENT_RECEIPT_TIMEOUT_SECONDS,
        batch_size: int = DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE,
        batch_encoder: Callable[[Sequence[bytes]], str] = encode_settle_signed_batch_tuples,
        expected_chain_id: int | None = None,
        expected_contract: str | None = None,
        settlement_version: int = 8,
        gas_per_receipt: int = 250_000,
        gas_safety_bps: int = 15_000,
        health_interval_seconds: float = 5.0,
        health_timeout_seconds: float = 2.0,
        health_max_age_seconds: float = 20.0,
        settlement_interval_seconds: int = DEFAULT_RELAY_SETTLEMENT_INTERVAL_SECONDS,
        settlement_count_threshold: int = DEFAULT_RELAY_SETTLEMENT_COUNT_THRESHOLD,
        settlement_deadline_margin_seconds: int = DEFAULT_RELAY_SETTLEMENT_DEADLINE_MARGIN_SECONDS,
    ) -> None:
        if not str(rpc_url or "").strip():
            raise RelaySettlementError("Relay settlement RPC URL is required")
        try:
            private_key_to_address(parse_private_key(private_key))
        except ChainError as exc:
            raise RelaySettlementError(f"Relay transaction identity is invalid: {exc}") from exc
        self.outbox = outbox
        self.rpc_url = str(rpc_url)
        self.private_key = str(private_key)
        for value in (poll_seconds, tx_timeout_seconds, receipt_timeout_seconds):
            if not math.isfinite(float(value)) or float(value) <= 0:
                raise RelaySettlementError("worker intervals must be finite and positive")
        self.poll_seconds = min(30.0, max(0.5, float(poll_seconds)))
        self.tx_timeout_seconds = min(60.0, max(1.0, float(tx_timeout_seconds)))
        self.receipt_timeout_seconds = min(300.0, max(5.0, float(receipt_timeout_seconds)))
        for value, name, maximum in (
            (settlement_interval_seconds, "settlement_interval_seconds", 7 * 86400),
            (settlement_count_threshold, "settlement_count_threshold", 4096),
            (settlement_deadline_margin_seconds, "settlement_deadline_margin_seconds", 86400),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise RelaySettlementError(f"{name} must be an integer between 1 and {maximum}")
        self.settlement_interval_seconds = settlement_interval_seconds
        self.settlement_count_threshold = settlement_count_threshold
        # This is an early-flush safety margin, not permission to extend any
        # signed deadline. V9 currently caps authorization TTL at one hour.
        self.settlement_deadline_margin_seconds = max(settlement_deadline_margin_seconds,
            math.ceil(self.tx_timeout_seconds + self.receipt_timeout_seconds + self.poll_seconds))
        self.batch_size = max(1, min(int(batch_size), MAX_RELAY_SETTLEMENT_BATCH_SIZE))
        self.batch_encoder = batch_encoder
        if type(settlement_version) is not int or settlement_version not in {5, 6, 7, 8, 9, 10}:
            raise RelaySettlementError("unsupported settlement worker version")
        self.settlement_version = settlement_version
        self.expected_contract = normalize_address(expected_contract) if expected_contract else None
        self.address = private_key_to_address(parse_private_key(private_key))
        self.expected_chain_id = int(expected_chain_id) if expected_chain_id is not None else None
        if self.expected_chain_id is not None and self.expected_chain_id <= 0:
            raise RelaySettlementError("expected chain ID must be positive")
        if type(gas_per_receipt) is not int or not 1 <= gas_per_receipt <= 5_000_000:
            raise RelaySettlementError("gas_per_receipt is invalid")
        if type(gas_safety_bps) is not int or not 10_000 <= gas_safety_bps <= 100_000:
            raise RelaySettlementError("gas_safety_bps is invalid")
        for value in (health_interval_seconds, health_timeout_seconds, health_max_age_seconds):
            if not math.isfinite(float(value)) or float(value) <= 0:
                raise RelaySettlementError("health intervals must be finite and positive")
        self.gas_per_receipt = gas_per_receipt
        self.gas_safety_bps = gas_safety_bps
        self.health_interval_seconds = min(10.0, max(0.5, float(health_interval_seconds)))
        self.health_timeout_seconds = min(3.0, max(0.1, float(health_timeout_seconds)))
        self.health_max_age_seconds = min(60.0, max(1.0, float(health_max_age_seconds)))
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._health_thread: threading.Thread | None = None
        self._state_lock = threading.RLock()
        self._reservations: set[str] = set()
        self._worker_heartbeat = time.monotonic()
        self._health: dict[str, Any] = {"checked_at": None, "checked_monotonic": 0.0, "error_code": "rpc_unavailable"}
        self._health_rpc_endpoint: str | None = None
        self._accounting_generation = 0
        self._spent_since_check = 0
        self._last_success_at: int | None = None
        self._last_rpc_success_at: int | None = None
        self._last_error_at: int | None = None
        self._last_error_code: str | None = None
        self._submission_error_code: str | None = None
        self._submission_block_until = 0.0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._worker_heartbeat = time.monotonic()
        self._health_thread = threading.Thread(target=self._health_run, name="mycomesh-relay-settlement-health", daemon=True)
        self._thread = threading.Thread(target=self._run, name="mycomesh-relay-settlement", daemon=True)
        self._thread.start()
        self._health_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        if self._health_thread is not None:
            self._health_thread.join(timeout=5.0)

    def enqueue(self, prepared: PreparedRelaySettlement, *, reservation: str | None = None) -> tuple[str, bool]:
        if (self.settlement_version in {9, 10} or prepared.payload.get("protocol_version") in {9, 10}) and self.settlement_version != prepared.payload.get("protocol_version"):
            raise RelaySettlementError("Settlement domain cannot share another-version submitter")
        with self._state_lock:
            if reservation is not None and reservation not in self._reservations and self.outbox.status(prepared.key) is None:
                raise RelaySettlementError("settlement admission reservation is no longer valid", error_code="admission_invalid")
            result = self.outbox.enqueue(prepared)
            if reservation is not None:
                self._reservations.discard(reservation)
        self._wake.set()
        return result

    def snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            backlog = self.outbox.snapshot()
            batching = self._batching_schedule()
            batching.pop("_pending_rowid_ceiling", None)
            alive = bool(self._thread and self._thread.is_alive() and not self._stop.is_set()
                         and time.monotonic() - self._worker_heartbeat <= max(30.0, self.tx_timeout_seconds + 5.0))
            recent = time.monotonic() - self._health.get("checked_monotonic", 0) <= self.health_max_age_seconds
            price = int(self._health.get("gas_price_wei", 0))
            per_receipt = (self.gas_per_receipt * price * self.gas_safety_bps + 9999) // 10_000
            balance = max(0, int(self._health.get("balance_wei", 0)) - self._spent_since_check)
            outstanding = sum(backlog.get(status, 0) for status in ("pending", "submitted", "broadcast_unknown"))
            available = max(0, min(4096, balance // per_receipt - outstanding - len(self._reservations))) if per_receipt else 0
            code = self._health.get("error_code")
            if not recent:
                code = "rpc_unavailable"
            if self._submission_error_code and (self._submission_error_code in {"broadcast_unknown", "confirmation_timeout"} or time.monotonic() < self._submission_block_until):
                code = self._submission_error_code
            durable_error = self.outbox.blocking_error()
            if durable_error:
                code = durable_error
            if not alive:
                code = "worker_unavailable"
            if not code and not available:
                code = "low_gas"
            return {"enabled": True, "ready": code is None, "settlement_ready": code is None, "error_code": code,
                    "worker_alive": alive, "transaction_relayer_address": self.address, "batch_size": self.batch_size,
                    "batching": batching,
                    "outbox": backlog, "checked_at": self._health.get("checked_at"), "chain_id": self._health.get("chain_id"),
                    "gas_balance_wei": str(balance), "gas_price_wei": str(price), "gas_per_receipt": self.gas_per_receipt,
                    "gas_capacity_remaining": available, "admission_reservations": len(self._reservations),
                    "last_success_at": self._last_success_at, "last_rpc_success_at": self._last_rpc_success_at,
                    "last_error_at": self._last_error_at, "last_error_code": self._last_error_code}

    def reserve_admission(self) -> str:
        with self._state_lock:
            state = self.snapshot()
            if not state["ready"]:
                code = str(state["error_code"] or "settlement_unavailable")
                raise RelaySettlementError("Relay settlement is not ready: " + code, error_code=code)
            lease = uuid4().hex
            self._reservations.add(lease)
            return lease

    def release_admission(self, reservation: str | None) -> None:
        with self._state_lock:
            self._reservations.discard(reservation)

    def public_status(self, request_id: str, *, key_address: str | None = None, channel_id: str | None = None) -> dict[str, Any] | None:
        return self.outbox.public_status(request_id, key_address=key_address, settlement_version=self.settlement_version,
                                         chain_id=self.expected_chain_id, settlement_contract=self.expected_contract, channel_id=channel_id)

    def refresh_health(self) -> dict[str, Any]:
        """Bounded RPC health probe and expiry sweep; HTTP uses snapshot()."""
        with self._state_lock:
            if self.settlement_version != 10:
                self.outbox.expire_pending()
            generation = self._accounting_generation
            started = time.monotonic()
            preferred = self._health_rpc_endpoint
        probe: dict[str, Any] = {"error_code": "rpc_unavailable"}
        deadline = started + min(8.0, 4 * self.health_timeout_seconds)
        endpoints = tuple(dict.fromkeys(value.strip() for value in self.rpc_url.split(",") if value.strip()))
        if not 1 <= len(endpoints) <= 4:
            endpoints = ()
        elif preferred in endpoints:
            endpoints = (preferred, *(value for value in endpoints if value != preferred))
        successful_endpoint: str | None = None
        endpoint = ""
        def read(method: str, parameters: list[Any]) -> Any:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RelaySettlementError("health RPC deadline elapsed", error_code="rpc_unavailable")
            # Never pass the comma-separated list here: each successful health
            # snapshot must come from one chain-checked endpoint, not four
            # independently selected fallback endpoints.
            result = rpc_call(endpoint, method, parameters, min(self.health_timeout_seconds, remaining))
            if time.monotonic() >= deadline:
                raise RelaySettlementError("health RPC deadline elapsed", error_code="rpc_unavailable")
            return result
        for endpoint in endpoints:
            if time.monotonic() >= deadline:
                break
            try:
                chain = int(read("eth_chainId", []), 16)
                if self.expected_chain_id is None or chain != self.expected_chain_id:
                    raise RelaySettlementError("settlement RPC chain does not match deployment", error_code="wrong_chain")
                balance = int(read("eth_getBalance", [self.address, "pending"]), 16)
                price = int(read("eth_gasPrice", []), 16)
                block = read("eth_getBlockByNumber", ["latest", False])
                if not isinstance(block, Mapping):
                    raise RelaySettlementError("invalid latest block", error_code="rpc_unavailable")
                base = int(block.get("baseFeePerGas", "0x0"), 16)
                price = max(price, base + max(1_000_000_000, price // 10))
                if balance < 0 or price <= 0:
                    raise RelaySettlementError("invalid gas RPC values", error_code="rpc_unavailable")
                probe = {"chain_id": chain, "balance_wei": balance, "gas_price_wei": price, "error_code": None}
                successful_endpoint = endpoint
                break
            except Exception as exc:
                probe["error_code"] = "wrong_chain" if getattr(exc, "error_code", None) == "wrong_chain" else "rpc_unavailable"
        with self._state_lock:
            if started < self._health.get("started_monotonic", 0):
                return self.snapshot()
            self._health = {**self._health, **probe, "checked_at": int(time.time()), "checked_monotonic": time.monotonic(), "started_monotonic": started}
            if not probe.get("error_code") and generation == self._accounting_generation:
                self._spent_since_check = 0
            if not probe.get("error_code"):
                self._health_rpc_endpoint = successful_endpoint
                self._last_rpc_success_at = int(time.time())
            if probe.get("error_code"):
                self._last_error_at, self._last_error_code = int(time.time()), probe["error_code"]
        return self.snapshot()

    def _health_run(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh_health()
            except Exception:
                with self._state_lock:
                    self._health["error_code"] = "rpc_unavailable"
            self._stop.wait(self.health_interval_seconds)

    def _submission_error(self, code: str) -> None:
        with self._state_lock:
            self._last_error_at = int(time.time())
            self._last_error_code = code
            if self._submission_error_code not in {"broadcast_unknown", "confirmation_timeout"}:
                self._submission_error_code = code
            self._submission_block_until = time.monotonic() + self.poll_seconds

    def _run(self) -> None:
        while not self._stop.is_set():
            self._worker_heartbeat = time.monotonic()
            try:
                if self.process_once():
                    continue
            except Exception:
                self._submission_error(self._submission_error_code or "settlement_failed")
                logger.warning("Relay settlement worker paused; code=%s", self._last_error_code)
            self._wake.wait(timeout=self.poll_seconds)
            self._wake.clear()

    def process_once(self, *, force: bool = False) -> int:
        """Process at most one bounded batch, preserving unknown-tx precedence.

        Provider independent submission uses a dedicated gas identity and its
        own durable outbox. A file lock prevents two processes using one outbox;
        sharing this identity with a different outbox is not supported.
        """
        import fcntl
        with self._state_lock:
            path = Path(str(self.outbox.path) + '.submitter.lock')
        with path.open('a') as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RelaySettlementError('settlement outbox already has a worker') from exc
            try:
                items = (self.outbox.next_batch(self.batch_size, prioritize_deadlines=True)
                         if force else self._next_scheduled_batch())
                if items:
                    self._process(items)
                return len(items)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _reconcile_v10_existing(self, item: Mapping[str, Any]) -> bool:
        """Confirm Provider-submitted escrow by (channel, request), never by request alone.

        Canonical, six-block-old storage is authoritative even when the other
        submitter's transaction hash is unavailable. This is escrow recognition,
        not a claim or payout, and never clears a locally unknown transaction.
        """
        from . import chain_v10
        self._worker_heartbeat = time.monotonic()
        payload = json.loads(item['payload_json'])
        auth = payload['signed_receipt']['authorization']['authorization']
        usage = payload['signed_receipt']['receipt']
        key = chain_v10.settlement_key_for(auth['channel_id'], auth['request_id'])
        if key != payload['settlement_key']:
            raise RelaySettlementError('V10 durable key mismatch', error_code='invalid_receipt')
        from .reserved_execution import confirmed_channel_snapshot
        cache_key = (int(item['chain_id']), item['settlement_contract'], auth['channel_id'])
        cache = getattr(self, '_v10_reconcile_channels', {})
        snapshot = cache.get(cache_key)
        if snapshot is None:
            snapshot = confirmed_channel_snapshot(self.rpc_url, item['settlement_contract'], auth['channel_id'],
                chain_id=int(item['chain_id']), confirmations=6, timeout=min(3.0, self.tx_timeout_seconds))
            cache[cache_key] = snapshot
        terms = snapshot['config']
        if terms != payload['channel']:
            raise RelaySettlementError('V10 durable channel mismatch', error_code='invalid_receipt')
        info = chain_v10.settlement_info(self.rpc_url, item['settlement_contract'], key,
            timeout=min(3.0, self.tx_timeout_seconds),
            block_tag={'blockHash': snapshot['block_hash'], 'requireCanonical': True})
        # EIP-1898 binds the storage read, then verify its anchor once more:
        # a fork during that read must not make a competing submitter terminal.
        head = int(rpc_call(self.rpc_url, 'eth_blockNumber', [], min(3.0, self.tx_timeout_seconds)), 16)
        current = rpc_call(self.rpc_url, 'eth_getBlockByNumber',
            [hex(snapshot['block_number']), False], min(3.0, self.tx_timeout_seconds))
        if (head - snapshot['block_number'] + 1 < 6 or not isinstance(current, Mapping)
                or str(current.get('hash', '')).lower() != snapshot['block_hash'].lower()
                or int(current.get('number', '-1'), 16) != snapshot['block_number']):
            raise RelaySettlementError('V10 reconciliation block changed', error_code='rpc_unavailable')
        if int(info['status']) == 0:
            # A competing submitter may have settled in the unconfirmed tail.
            # Absence becomes terminal only after the confirmed block itself
            # passes the last timestamp at which this receipt could settle.
            deadline = int(auth['deadline'])
            if deadline <= int(time.time()):
                confirmed_at = snapshot.get('block_timestamp')
                if type(confirmed_at) is not int or confirmed_at <= deadline:
                    raise RelaySettlementError('V10 expiry awaits a confirmed block beyond its deadline',
                        error_code='rpc_unavailable')
            return False
        expected = {'owner': terms['consumer_owner'], 'key': auth['key'],
            'provider': terms['provider_owner'], 'provider_signer': terms['provider_signer'],
            'relay': terms['relay'], 'relay_signer': terms['relay_signer'],
            'request_id': auth['request_id'], 'request_hash': auth['request_hash'],
            'authorization_hash': usage['authorization_hash'], 'response_hash': usage['response_hash'],
            'gross_fee': usage['actual_fee']}
        if any(info.get(name) != value for name, value in expected.items()):
            raise RelaySettlementError('V10 existing settlement conflicts with receipt', error_code='invalid_receipt')
        event = {**info, 'settlement_key': key, 'channel_id': auth['channel_id'],
            'reconciled_from_chain': True, 'confirmed_block_hash': snapshot['block_hash']}
        self.outbox.mark_escrowed_many({str(item['settlement_key']): event}, '')
        return True

    def _batching_schedule(self, *, activate: bool = False) -> dict[str, Any]:
        return self.outbox.batching_schedule(interval_seconds=self.settlement_interval_seconds,
            count_threshold=self.settlement_count_threshold,
            deadline_margin_seconds=self.settlement_deadline_margin_seconds, activate=activate)

    def _next_scheduled_batch(self) -> list[dict[str, Any]]:
        schedule = self._batching_schedule(activate=True)
        if not schedule["due"]:
            return []
        return self.outbox.next_batch(self.batch_size,
            pending_rowid_ceiling=schedule["_pending_rowid_ceiling"],
            prioritize_deadlines=self.settlement_version in {7, 8, 9, 10})

    def _process(self, items: list[Mapping[str, Any]]) -> None:
        if not items:
            return
        self._worker_heartbeat = time.monotonic()
        self._v10_reconcile_channels = {}
        active = []
        for item in items:
            try:
                protocol_version = json.loads(str(item["payload_json"])).get("protocol_version")
            except (TypeError, ValueError, AttributeError) as exc:
                raise RelaySettlementError("invalid durable settlement envelope", error_code="invalid_receipt") from exc
            if (self.settlement_version in {9, 10} or protocol_version in {9, 10}) and self.settlement_version != protocol_version:
                # Preserve mismatched durable state for operator reconciliation;
                # never encode, broadcast, or confirm it under another domain.
                self._submission_error("invalid_receipt")
                raise RelaySettlementError("Outbox protocol differs from this worker", error_code="invalid_receipt")
            if self.settlement_version == 10 and str(item["status"]) != "submitted" and self._reconcile_v10_existing(item):
                continue
            # Once broadcast, expiry must not discard a transaction that might
            # already have executed before the authorization deadline.
            if str(item["status"]) != "submitted":
                try:
                    _, deadline, code = _payload_metadata(json.loads(str(item["payload_json"])))
                except (ValueError, TypeError, AttributeError):
                    self.outbox.mark_failed(str(item["settlement_key"]), "invalid_receipt", retryable=False)
                    continue
                if deadline is not None and deadline <= int(time.time()):
                    self.outbox.mark_failed(str(item["settlement_key"]), code.replace("_", " "), retryable=False)
                    self._submission_error(code)
                    continue
            active.append(item)
        items = active
        if not items:
            return
        keys = [str(item["settlement_key"]) for item in items]
        transaction_submitted = any(str(item["status"]) == "submitted" for item in items)
        submitted_hashes = {str(item.get("tx_hash") or "") for item in items if str(item["status"]) == "submitted"}
        try:
            if submitted_hashes:
                tx_hash = next(iter(submitted_hashes))
                if len(submitted_hashes) != 1 or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
                    self._submission_error("broadcast_unknown")
                    raise RelaySettlementError("Relay settlement outbox has inconsistent submitted transaction state", error_code="broadcast_unknown")
                self._wait_for_receipt(keys, tx_hash)
                return
            if len(items) == 1:
                calldata = str(items[0]["calldata"])
            else:
                tuple_values: list[bytes] = []
                for item in items:
                    payload = json.loads(str(item["payload_json"]))
                    tuple_data = payload.get("tuple_data")
                    if not isinstance(tuple_data, str) or not tuple_data.startswith("0x"):
                        raise RelaySettlementError("Relay settlement outbox item is missing tuple data")
                    tuple_values.append(bytes.fromhex(tuple_data[2:]))
                calldata = self.batch_encoder(tuple_values)
            tx_hash = self._send_transaction(items, calldata)
            transaction_submitted = True
            self._wait_for_receipt(keys, tx_hash)
        except Exception as exc:
            code = getattr(exc, "error_code", None)
            if not code or code == "settlement_unavailable":
                code = settlement_error_code(exc)
            self._submission_error(code)
            # _send_transaction persists the hash BEFORE broadcasting. Even if
            # its RPC response is lost, this row must never get a fresh nonce.
            transaction_submitted = transaction_submitted or any(self.outbox.status(key) == "submitted" for key in keys)
            permanent = code in {"transaction_reverted", "authorization_expired", "receipt_expired", "already_settled"}
            if transaction_submitted and not permanent:
                self.outbox.mark_submission_error(keys, code)
                raise RelaySettlementError("submitted settlement awaits reconciliation", error_code=code) from None
            if not transaction_submitted and len(items) > 1 and code in {"authorization_expired", "receipt_expired"}:
                # Isolate contract-reported expiry without recycling the whole
                # expired batch as a transient failure or changing signatures.
                for item in items:
                    self._process([item])
                return
            if not transaction_submitted and len(items) > 1 and code in {"transaction_reverted", "already_settled", "low_gas"}:
                self.batch_size = max(1, len(items) // 2)
                self.outbox.mark_failed_many(keys, code, retryable=True)
                logger.warning(
                    "Relay settlement batch of %s rejected before broadcast; batch size now %s",
                    len(items),
                    self.batch_size,
                )
                self._wake.wait(timeout=self.poll_seconds)
                self._wake.clear()
                return
            if self.settlement_version == 10 and code in {"transaction_reverted", "already_settled"}:
                self._v10_reconcile_channels = {}
                remaining = []
                for item in items:
                    try:
                        if not self._reconcile_v10_existing(item):
                            remaining.append(str(item['settlement_key']))
                    except Exception:
                        remaining.append(str(item['settlement_key']))
                if not remaining:
                    return
                # Another submitter can win immediately before this broadcast.
                # Keep the unmatched rows for a confirmed-state reconciliation.
                self.outbox.mark_failed_many(remaining, 'rpc_unavailable', retryable=True)
                return
            retryable = not permanent
            self.outbox.mark_failed_many(keys, code, retryable=retryable)
            if retryable:
                raise RelaySettlementError("settlement submission deferred", error_code=code) from None
            logger.error("Relay settlement permanently failed for %s receipt(s); code=%s", len(items), code)

    def _send_transaction(self, items: list[Mapping[str, Any]], calldata: str) -> str:
        """Persist the signed transaction and hash before its first broadcast.

        Neither the raw transaction nor its signature is exposed through health
        or status. Recovery may rebroadcast only these identical bytes; it
        never reconstructs the transaction using a new nonce.
        """
        deadline = time.monotonic() + self.tx_timeout_seconds
        endpoint = ""
        def read(method: str, parameters: list[Any]) -> Any:
            self._worker_heartbeat = time.monotonic()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RelaySettlementError("transaction preparation timed out", error_code="rpc_unavailable")
            return rpc_call(endpoint, method, parameters, min(5.0, remaining))
        contract = str(items[0]["settlement_contract"])
        preparation_error = "rpc_unavailable"
        endpoints = tuple(dict.fromkeys(value.strip() for value in self.rpc_url.split(",") if value.strip()))
        if not 1 <= len(endpoints) <= 4:
            raise RelaySettlementError("settlement RPC endpoint count is invalid", error_code="rpc_unavailable")
        # Bind the first broadcast to a chain-checked, fully preflighted RPC.
        # Recovery can subsequently broadcast the same durable signed bytes.
        for endpoint in endpoints:
            try:
                chain = int(read("eth_chainId", []), 16)
                if chain != int(items[0]["chain_id"]) or (self.expected_chain_id is not None and chain != self.expected_chain_id):
                    raise RelaySettlementError("transaction RPC chain does not match deployment", error_code="wrong_chain")
                nonce = int(read("eth_getTransactionCount", [self.address, "pending"]), 16)
                price = int(read("eth_gasPrice", []), 16)
                block = read("eth_getBlockByNumber", ["latest", False])
                base = int(block.get("baseFeePerGas", "0x0"), 16)
                price = max(price, base + max(1_000_000_000, price // 10))
                estimate = int(read("eth_estimateGas", [{"from": self.address, "to": contract, "data": calldata, "value": "0x0"}]), 16)
                gas_limit = max(21_000, estimate * 12 // 10 + 10_000)
                with self._state_lock:
                    self.gas_per_receipt = max(self.gas_per_receipt, (gas_limit + len(items) - 1) // len(items))
                balance = int(read("eth_getBalance", [self.address, "pending"]), 16)
                if balance < gas_limit * price:
                    raise RelaySettlementError("insufficient funds for settlement gas", error_code="low_gas")
                break
            except Exception as exc:
                code = getattr(exc, "error_code", None) or settlement_error_code(exc)
                if code in {"authorization_expired", "receipt_expired", "transaction_reverted", "already_settled", "low_gas"}:
                    raise
                preparation_error = code if code == "wrong_chain" else "rpc_unavailable"
        else:
            raise RelaySettlementError("no configured RPC passed transaction preflight", error_code=preparation_error)
        raw = sign_legacy_transaction(private_key=parse_private_key(self.private_key), nonce=nonce, gas_price=price,
                                      gas_limit=gas_limit, to_address=contract, value=0,
                                      data=bytes.fromhex(calldata[2:]), chain_id=chain)
        tx_hash = "0x" + keccak256(raw).hex()
        keys = [str(item["settlement_key"]) for item in items]
        if time.monotonic() >= deadline:
            raise RelaySettlementError("transaction preparation timed out", error_code="rpc_unavailable")
        self.outbox.mark_submitted_many(keys, tx_hash, raw_transaction="0x" + raw.hex())
        try:
            result = read("eth_sendRawTransaction", ["0x" + raw.hex()])
            if not isinstance(result, str) or result.lower() != tx_hash:
                raise RelaySettlementError("broadcast response did not match the prepared transaction", error_code="broadcast_unknown")
            self.outbox.mark_broadcast_acknowledged(keys)
        except Exception as exc:
            lowered = str(exc).lower()
            if "already known" in lowered:
                self.outbox.mark_broadcast_acknowledged(keys)
                return tx_hash
            ambiguous = any(marker in lowered for marker in ("timeout", "timed out", "connection", "transport", "502", "503"))
            if "insufficient funds" in lowered and not ambiguous:
                self.outbox.mark_submission_error(keys, "low_gas", definitely_rejected=True)
                raise RelaySettlementError("settlement gas balance changed before broadcast", error_code="low_gas") from None
            self.outbox.mark_submission_error(keys, "broadcast_unknown")
            raise RelaySettlementError("settlement broadcast outcome is unknown", error_code="broadcast_unknown") from None
        return tx_hash

    def _rebroadcast_submitted(self, keys: list[str], tx_hash: str) -> None:
        stored = self.outbox.signed_transaction(keys, tx_hash)
        if stored is None:
            # Legacy rows have no recoverable signature. Do not guess a nonce.
            return
        chain_id, raw_transaction = stored
        if self.expected_chain_id is not None and chain_id != self.expected_chain_id:
            raise RelaySettlementError("durable transaction chain mismatch", error_code="broadcast_unknown")
        endpoints = tuple(dict.fromkeys(value.strip() for value in self.rpc_url.split(",") if value.strip()))
        if not 1 <= len(endpoints) <= 4:
            raise RelaySettlementError("settlement RPC endpoint count is invalid", error_code="broadcast_unknown")
        deadline = time.monotonic() + self.tx_timeout_seconds
        for endpoint in endpoints:
            try:
                def read(method: str, parameters: list[Any]) -> Any:
                    self._worker_heartbeat = time.monotonic()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RelaySettlementError("rebroadcast deadline elapsed", error_code="broadcast_unknown")
                    return rpc_call(endpoint, method, parameters, min(5.0, remaining))
                if int(read("eth_chainId", []), 16) != chain_id:
                    continue
                try:
                    result = read("eth_sendRawTransaction", [raw_transaction])
                    acknowledged = isinstance(result, str) and result.lower() == tx_hash.lower()
                except Exception as exc:
                    acknowledged = "already known" in str(exc).lower()
                if acknowledged:
                    self.outbox.mark_broadcast_acknowledged(keys)
                    with self._state_lock:
                        self._submission_error_code = None
                        self._submission_block_until = 0.0
                    return
            except Exception:
                pass
        # Rejection at one RPC cannot disprove earlier acceptance elsewhere.
        raise RelaySettlementError("settlement rebroadcast outcome is unknown", error_code="broadcast_unknown") from None

    def _transaction_receipt(self, tx_hash: str, deadline: float) -> Any:
        endpoints = tuple(dict.fromkeys(value.strip() for value in self.rpc_url.split(",") if value.strip()))
        if not 1 <= len(endpoints) <= 4:
            raise RelaySettlementError("settlement RPC endpoint count is invalid", error_code="rpc_unavailable")
        saw_null = False
        for endpoint in endpoints:
            try:
                def read(method: str, parameters: list[Any]) -> Any:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RelaySettlementError("receipt RPC deadline elapsed", error_code="confirmation_timeout")
                    self._worker_heartbeat = time.monotonic()
                    return rpc_call(endpoint, method, parameters, min(5.0, remaining))
                if (len(endpoints) > 1 or self.settlement_version == 10) and self.expected_chain_id is not None:
                    if int(read("eth_chainId", []), 16) != self.expected_chain_id:
                        continue
                receipt = read("eth_getTransactionReceipt", [tx_hash])
                if receipt is None:
                    saw_null = True
                    continue
                if isinstance(receipt, Mapping):
                    actual_hash = receipt.get("transactionHash")
                    if actual_hash is not None and str(actual_hash).lower() != tx_hash.lower():
                        continue
                    if self.settlement_version == 10:
                        receipt = self._confirmed_v10_receipt(receipt, tx_hash, read)
                        if receipt is None:
                            saw_null = True
                            continue
                    return receipt
            except Exception:
                continue
        if saw_null:
            return None
        raise RelaySettlementError("no RPC returned a matching transaction receipt", error_code="rpc_unavailable")

    @staticmethod
    def _confirmed_v10_receipt(receipt: Mapping[str, Any], tx_hash: str,
                               read: Callable[[str, list[Any]], Any]) -> Mapping[str, Any] | None:
        """Keep both successes and reverts submitted until six canonical confirmations.

        Every read uses the same chain-checked endpoint. An immature receipt,
        disappearance, or fork remains unresolved and can only rebroadcast the
        original durable bytes. Recheck after the receipt read before committing
        terminal state, so a reorg observed during this sequence fails closed.
        """
        block_hash = str(receipt.get('blockHash') or '').lower()
        if (str(receipt.get('transactionHash') or '').lower() != tx_hash.lower()
                or not re.fullmatch(r'0x[0-9a-f]{64}', block_hash)):
            raise RelaySettlementError('V10 receipt block binding is missing', error_code='rpc_unavailable')
        number = int(receipt['blockNumber'], 16)
        if number < 0:
            raise RelaySettlementError('V10 receipt block number is invalid', error_code='rpc_unavailable')
        if int(read('eth_blockNumber', []), 16) - number + 1 < 6:
            return None
        block = read('eth_getBlockByNumber', [hex(number), False])
        if (not isinstance(block, Mapping) or str(block.get('hash', '')).lower() != block_hash
                or int(block.get('number', '-1'), 16) != number):
            return None
        fresh = read('eth_getTransactionReceipt', [tx_hash])
        if (not isinstance(fresh, Mapping)
                or any(fresh.get(field) != receipt.get(field)
                       for field in ('transactionHash', 'blockHash', 'blockNumber', 'status', 'logs'))):
            return None
        # A changed head and canonical block can invalidate the earlier count.
        if int(read('eth_blockNumber', []), 16) - number + 1 < 6:
            return None
        current = read('eth_getBlockByNumber', [hex(number), False])
        if (not isinstance(current, Mapping) or str(current.get('hash', '')).lower() != block_hash
                or int(current.get('number', '-1'), 16) != number):
            return None
        return fresh

    def _wait_for_receipt(self, keys: list[str], tx_hash: str) -> None:
        deadline = time.monotonic() + self.receipt_timeout_seconds
        rebroadcast_attempted = False
        while not self._stop.is_set():
            self._worker_heartbeat = time.monotonic()
            receipt = self._transaction_receipt(tx_hash, deadline)
            if isinstance(receipt, Mapping):
                status = receipt.get("status")
                if status not in {"0x0", "0x00", 0, "0x1", "0x01", 1}:
                    raise RelaySettlementError("RPC receipt has no valid execution status", error_code="rpc_unavailable")
                with self._state_lock:
                    self._submission_error_code = None
                    def quantity(value: Any, fallback: int) -> int:
                        try:
                            return int(value, 16) if isinstance(value, str) else int(value)
                        except (TypeError, ValueError):
                            return fallback
                    used = quantity(receipt.get("gasUsed"), self.gas_per_receipt * len(keys))
                    price = quantity(receipt.get("effectiveGasPrice"), int(self._health.get("gas_price_wei", 0)))
                    self._spent_since_check += used * price
                    self._accounting_generation += 1
                    if status in {"0x1", "0x01", 1}:
                        if self.settlement_version in {9, 10}:
                            self.outbox.mark_escrowed_many(self._verified_v9_escrow_events(keys, tx_hash, receipt), tx_hash)
                        else:
                            self.outbox.mark_confirmed_many(keys, tx_hash)
                        self._last_success_at = int(time.time())
                        self._submission_error_code = None
                if status not in {"0x1", "0x01", 1}:
                    raise RelaySettlementError("Relay settlement transaction reverted", error_code="transaction_reverted")
                return
            if time.monotonic() >= deadline:
                raise RelaySettlementError("Relay settlement transaction confirmation timed out", error_code="confirmation_timeout")
            if not rebroadcast_attempted:
                self._rebroadcast_submitted(keys, tx_hash)
                rebroadcast_attempted = True
            self._stop.wait(2.0)

    def _verified_v9_escrow_events(self, keys: list[str], tx_hash: str,
                                  receipt: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        from .chain_v9 import parse_receipt_escrowed
        if str(receipt.get("transactionHash") or "").lower() != tx_hash.lower():
            raise RelaySettlementError("V9 receipt transaction binding is missing", error_code="rpc_unavailable")
        logs = receipt.get("logs")
        if not isinstance(logs, list):
            raise RelaySettlementError("V9 receipt escrow logs are missing", error_code="rpc_unavailable")
        result: dict[str, dict[str, Any]] = {}
        for item in self.outbox.submission_items(keys):
            payload = json.loads(item["payload_json"])
            if payload.get("protocol_version") != self.settlement_version:
                raise RelaySettlementError("V9 worker encountered a different protocol", error_code="invalid_receipt")
            signed = payload["signed_receipt"]
            usage = signed["receipt"]
            matches = []
            for log in logs:
                try:
                    event = parse_receipt_escrowed(log, expected_contract=item["settlement_contract"])
                except (ChainError, KeyError, TypeError, ValueError):
                    continue
                if event and event.get("settlement_key") == payload.get("settlement_key"):
                    matches.append(event)
            if len(matches) != 1:
                raise RelaySettlementError("V9 escrow event is missing or ambiguous", error_code="rpc_unavailable")
            event = matches[0]
            if (event.get("request_id") != item["session_id"]
                    or event.get("owner") != payload.get("owner")
                    or event.get("provider") != (payload.get("provider") if self.settlement_version == 10 else usage.get("provider"))
                    or int(event.get("gross_fee", -1)) != int(usage["actual_fee"])):
                raise RelaySettlementError("V9 escrow event conflicts with the signed receipt", error_code="rpc_unavailable")
            result[item["settlement_key"]] = event
        return result
