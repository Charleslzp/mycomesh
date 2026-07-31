"""Relay-owned V5 receipt intake and transaction submission.

The Consumer keeps the session key and signs the completed receipt.  The
Relay only validates the signed envelope, persists it, and spends its own
native gas to submit the contract call.  This keeps the transaction relayer
an internal Relay component instead of exposing a fourth operator role.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .chain import (
    ChainError,
    EvmSignature,
    ZERO_ADDRESS,
    normalize_address,
    parse_private_key,
    private_key_to_address,
    recover_evm_address,
    rpc_call,
    send_contract_data_transaction,
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


logger = logging.getLogger(__name__)

RELAY_SETTLEMENT_SCHEMA = "mycomesh.relay.settlement.v1"
DEFAULT_RELAY_SETTLEMENT_DB = "/data/relay-settlement.sqlite3"
DEFAULT_RELAY_SETTLEMENT_POLL_SECONDS = 5.0
DEFAULT_RELAY_SETTLEMENT_TIMEOUT_SECONDS = 30.0
DEFAULT_RELAY_SETTLEMENT_RECEIPT_TIMEOUT_SECONDS = 180.0
DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE = 8
MAX_RELAY_SETTLEMENT_BATCH_SIZE = 32


class RelaySettlementError(RuntimeError):
    """Raised when a Consumer settlement envelope cannot be accepted."""


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
    if protocol_version != 5:
        raise RelaySettlementError("Relay settlement intake only supports V5")
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
        receipt = verify_provider_settlement_payload(provider_payload)
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
        raise RelaySettlementError("V5 Relay settlement requires a non-zero Relay payout")

    digest = session_receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
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
            raise RelaySettlementError("V5 Relay settlement requires a Relay attestation")
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
            relay_attestation = verify_relay_attestation(
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
        calldata = encode_settle_signed_receipt(
            receipt,
            relay_attestation,
            session_signature_bytes,
            provider_signature_bytes,
            relay_signature_bytes,
        )
    except (ChainError, TypeError, ValueError) as exc:
        raise RelaySettlementError(f"failed to encode V5 settlement: {exc}") from exc

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
        "tuple_data": "0x" + encode_settle_signed_receipt_tuple(
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
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=10000")
        return db

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
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_relay_settlement_status "
                "ON relay_settlement_outbox(status, created_at)"
            )

    def enqueue(self, prepared: PreparedRelaySettlement) -> tuple[str, bool]:
        now = int(time.time())
        with self._lock, self._connect() as db:
            existing = db.execute(
                "SELECT status FROM relay_settlement_outbox WHERE settlement_key=?",
                (prepared.key,),
            ).fetchone()
            if existing is not None:
                status = str(existing["status"])
                if status == "failed":
                    db.execute(
                        "UPDATE relay_settlement_outbox SET status='pending', error=NULL, updated_at=? "
                        "WHERE settlement_key=?",
                        (now, prepared.key),
                    )
                    return "pending", True
                return status, False
            db.execute(
                """
                INSERT INTO relay_settlement_outbox(
                    settlement_key, session_id, receipt_hash, sequence, chain_id,
                    settlement_contract, calldata, payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
        return "pending", True

    def next_batch(self, limit: int = DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_RELAY_SETTLEMENT_BATCH_SIZE))
        with self._lock, self._connect() as db:
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
                        (tx_hash, bounded),
                    ).fetchall()
                    return [dict(row) for row in rows]
                return [dict(submitted)]
            rows = db.execute(
                "SELECT * FROM relay_settlement_outbox WHERE status='pending' "
                "ORDER BY created_at ASC, session_id ASC, sequence ASC LIMIT 256"
            ).fetchall()
        candidates: list[dict[str, Any]] = []
        anchor: tuple[int, str] | None = None
        selected_sequences: dict[str, int] = {}
        for row in rows:
            item = dict(row)
            session_id = str(item["session_id"]).lower()
            sequence = int(item["sequence"])
            item_anchor = (int(item["chain_id"]), str(item["settlement_contract"]).lower())
            if anchor is None:
                anchor = item_anchor
            if item_anchor != anchor:
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

    def mark_submitted_many(self, keys: list[str], tx_hash: str) -> None:
        if not keys:
            return
        with self._lock, self._connect() as db:
            db.executemany(
                "UPDATE relay_settlement_outbox SET status='submitted', tx_hash=?, attempts=attempts+1, "
                "error=NULL, updated_at=? WHERE settlement_key=?",
                [(str(tx_hash), int(time.time()), str(key)) for key in keys],
            )

    def mark_confirmed(self, key: str, tx_hash: str | None = None) -> None:
        self.mark_confirmed_many([key], tx_hash)

    def mark_confirmed_many(self, keys: list[str], tx_hash: str | None = None) -> None:
        if not keys:
            return
        with self._lock, self._connect() as db:
            db.executemany(
                "UPDATE relay_settlement_outbox SET status='confirmed', tx_hash=COALESCE(?, tx_hash), "
                "error=NULL, updated_at=? WHERE settlement_key=?",
                [
                    (str(tx_hash) if tx_hash else None, int(time.time()), str(key))
                    for key in keys
                ],
            )

    def mark_failed(self, key: str, error: str, *, retryable: bool) -> None:
        self.mark_failed_many([key], error, retryable=retryable)

    def mark_failed_many(self, keys: list[str], error: str, *, retryable: bool) -> None:
        if not keys:
            return
        now = int(time.time())
        with self._lock, self._connect() as db:
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
        self.poll_seconds = max(0.5, float(poll_seconds))
        self.tx_timeout_seconds = max(1.0, float(tx_timeout_seconds))
        self.receipt_timeout_seconds = max(5.0, float(receipt_timeout_seconds))
        self.batch_size = max(1, min(int(batch_size), MAX_RELAY_SETTLEMENT_BATCH_SIZE))
        self.address = private_key_to_address(parse_private_key(private_key))
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="mycomesh-relay-settlement", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def enqueue(self, prepared: PreparedRelaySettlement) -> tuple[str, bool]:
        result = self.outbox.enqueue(prepared)
        self._wake.set()
        return result

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "transaction_relayer_address": self.address,
            "batch_size": self.batch_size,
            "outbox": self.outbox.snapshot(),
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            items = self.outbox.next_batch(self.batch_size)
            if not items:
                self._wake.wait(timeout=self.poll_seconds)
                self._wake.clear()
                continue
            try:
                self._process(items)
            except Exception:
                logger.exception("Relay settlement worker failed")
                self._wake.wait(timeout=self.poll_seconds)
                self._wake.clear()

    def _process(self, items: list[Mapping[str, Any]]) -> None:
        if not items:
            return
        keys = [str(item["settlement_key"]) for item in items]
        transaction_submitted = any(str(item["status"]) == "submitted" for item in items)
        submitted_hashes = {str(item.get("tx_hash") or "") for item in items if str(item["status"]) == "submitted"}
        if submitted_hashes:
            tx_hash = next(iter(submitted_hashes))
            if len(submitted_hashes) != 1 or not tx_hash:
                raise RelaySettlementError("Relay settlement outbox has inconsistent submitted transaction state")
            self._wait_for_receipt(keys, tx_hash)
            return
        try:
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
                calldata = encode_settle_signed_batch_tuples(tuple_values)
            tx_hash = send_contract_data_transaction(
                rpc_url=self.rpc_url,
                private_key=self.private_key,
                chain_id=int(items[0]["chain_id"]),
                contract=str(items[0]["settlement_contract"]),
                data=calldata,
                timeout=self.tx_timeout_seconds,
            )
            self.outbox.mark_submitted_many(keys, tx_hash)
            transaction_submitted = True
            self._wait_for_receipt(keys, tx_hash)
        except Exception as exc:
            lowered = str(exc).lower()
            permanent = any(
                marker in lowered
                for marker in ("reverted", "receipt expired", "session expired", "settled")
            )
            if len(items) > 1 and permanent:
                self.batch_size = max(1, len(items) // 2)
                self.outbox.mark_failed_many(keys, str(exc), retryable=True)
                logger.warning(
                    "Relay settlement batch of %s reverted; retrying with batch size %s",
                    len(items),
                    self.batch_size,
                )
                return
            retryable = not permanent
            if transaction_submitted and retryable:
                # A submitted transaction may still be in the mempool. Keep its
                # hash so the next loop polls it instead of spending a second
                # nonce on a duplicate transaction.
                raise
            self.outbox.mark_failed_many(keys, str(exc), retryable=retryable)
            if retryable:
                raise
            logger.error("Relay settlement permanently failed for %s receipt(s): %s", len(items), exc)

    def _wait_for_receipt(self, keys: list[str], tx_hash: str) -> None:
        deadline = time.monotonic() + self.receipt_timeout_seconds
        while not self._stop.is_set():
            receipt = rpc_call(
                self.rpc_url,
                "eth_getTransactionReceipt",
                [tx_hash],
                min(20.0, max(1.0, deadline - time.monotonic())),
            )
            if isinstance(receipt, Mapping):
                status = receipt.get("status")
                if status not in {"0x1", "0x01", 1}:
                    raise RelaySettlementError(f"Relay settlement transaction reverted: {tx_hash}")
                self.outbox.mark_confirmed_many(keys, tx_hash)
                return
            if time.monotonic() >= deadline:
                raise RelaySettlementError(f"Relay settlement transaction confirmation timed out: {tx_hash}")
            time.sleep(2.0)
