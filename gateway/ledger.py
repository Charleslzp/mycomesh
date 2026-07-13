from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import fcntl

from .identity import NodeIdentity, sign_document, verify_document
from .pricing import PriceQuote


DEFAULT_LEDGER_PATH = ".codex-run/receipts.jsonl"
RECEIPT_VERSION = "mycomesh-receipt-v2"
LEGACY_RECEIPT_VERSION = "mycomesh-receipt-v1"
RECEIPT_PURPOSE = "mycomesh.receipt.v1"
ACCEPTANCE_VERSION = "mycomesh-acceptance-v1"
ACCEPTANCE_PURPOSE = "mycomesh.receipt.acceptance.v1"
MAX_LEDGER_RECORD_BYTES = 16 * 1024 * 1024
LEDGER_INDEX_SUFFIX = ".index.sqlite3"


@dataclass(frozen=True)
class InferenceReceipt:
    job_id: str
    consumer_id: str
    provider_id: str
    relay_id: str | None
    pool_url: str
    selected_address: str
    channel: str
    model: str
    endpoint: str
    request_hash: str
    response_hash: str
    started_at: int
    finished_at: int
    elapsed_ms: int
    usage: dict[str, Any] | None
    quote: PriceQuote
    pricing_config_hash: str | None = None
    channel_pricing_hash: str | None = None
    settlement_version: int = 2
    pricing_version: int | None = None
    onchain_reservation_id: str | None = None
    settlement_deadline: int = 0
    consumer_public_key: str | None = None
    provider_public_key: str | None = None
    consumer_payment_address: str | None = None
    provider_payment_address: str | None = None
    relay_payment_address: str | None = None
    pool_payment_address: str | None = None
    provider_settlement_attestation: dict[str, Any] | None = None
    bridge_usage: list[dict[str, Any]] | None = None
    quality: dict[str, Any] | None = None
    signatures: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": RECEIPT_VERSION if self.provider_settlement_attestation else LEGACY_RECEIPT_VERSION,
            "job_id": self.job_id,
            "consumer_id": self.consumer_id,
            "provider_id": self.provider_id,
            "consumer_public_key": self.consumer_public_key,
            "provider_public_key": self.provider_public_key,
            "consumer_payment_address": self.consumer_payment_address,
            "provider_payment_address": self.provider_payment_address,
            "relay_payment_address": self.relay_payment_address,
            "pool_payment_address": self.pool_payment_address,
            "bridge_usage": self.bridge_usage or [],
            "quality": self.quality or {},
            "relay_id": self.relay_id,
            "pool_url": self.pool_url,
            "selected_address": self.selected_address,
            "channel": self.channel,
            "model": self.model,
            "endpoint": self.endpoint,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ms": self.elapsed_ms,
            "usage": self.usage,
            "pricing": self.quote.to_dict(),
            "pricing_config_hash": self.pricing_config_hash,
            "channel_pricing_hash": self.channel_pricing_hash,
            "settlement_version": self.settlement_version,
            "pricing_version": self.pricing_version,
            "onchain_reservation_id": self.onchain_reservation_id,
            "settlement_deadline": self.settlement_deadline,
            "provider_settlement_attestation": self.provider_settlement_attestation,
            "signatures": self.signatures or {},
        }


def build_receipt(
    consumer_id: str,
    provider_id: str,
    relay_id: str | None,
    pool_url: str,
    selected_address: str,
    channel: str,
    model: str,
    endpoint: str,
    input_value: Any,
    response: dict[str, Any],
    quote: PriceQuote,
    started_at: float,
    finished_at: float,
    consumer_public_key: str | None = None,
    provider_public_key: str | None = None,
    consumer_payment_address: str | None = None,
    provider_payment_address: str | None = None,
    relay_payment_address: str | None = None,
    pool_payment_address: str | None = None,
    bridge_usage: list[dict[str, Any]] | None = None,
    quality: dict[str, Any] | None = None,
    channel_pricing_hash: str | None = None,
    settlement_version: int | None = None,
    pricing_version: int | None = None,
    onchain_reservation_id: str | None = None,
    settlement_deadline: int = 0,
    signer: NodeIdentity | None = None,
    request_hash: str | None = None,
) -> InferenceReceipt:
    response_signature = response.get("signature") if isinstance(response.get("signature"), dict) else None
    signatures = {"provider_response": response_signature} if response_signature else None
    provider_attestation = (
        dict(response["provider_settlement_attestation"])
        if isinstance(response.get("provider_settlement_attestation"), dict)
        else None
    )
    attested_settlement_version = _attestation_int(provider_attestation, "settlement_version")
    attested_pricing_version = _attestation_int(provider_attestation, "pricing_version")
    attested_deadline = _attestation_int(provider_attestation, "settlement_deadline")
    resolved_quality = quality or _response_quality(response)
    resolved_request_hash = _receipt_request_hash(request_hash, resolved_quality, input_value)
    receipt = InferenceReceipt(
        job_id=str(response.get("request_id") or uuid.uuid4().hex),
        consumer_id=consumer_id,
        provider_id=provider_id,
        consumer_public_key=consumer_public_key or response.get("consumer_public_key"),
        provider_public_key=provider_public_key or _response_provider_public_key(response),
        consumer_payment_address=consumer_payment_address,
        provider_payment_address=provider_payment_address or _response_provider_payment_address(response),
        relay_payment_address=relay_payment_address,
        pool_payment_address=pool_payment_address,
        provider_settlement_attestation=provider_attestation,
        bridge_usage=bridge_usage or [],
        quality=resolved_quality,
        relay_id=relay_id,
        pool_url=pool_url,
        selected_address=selected_address,
        channel=channel,
        model=model,
        endpoint=endpoint,
        request_hash=resolved_request_hash,
        response_hash=stable_hash(response.get("output_text") or response.get("raw") or response),
        started_at=int(started_at),
        finished_at=int(finished_at),
        elapsed_ms=int((finished_at - started_at) * 1000),
        usage=response.get("usage") if isinstance(response.get("usage"), dict) else None,
        quote=quote,
        pricing_config_hash=quote.to_dict().get("pricing_config_hash"),
        channel_pricing_hash=channel_pricing_hash or quote.to_dict().get("pricing_config_hash"),
        settlement_version=int(settlement_version or attested_settlement_version or 2),
        pricing_version=pricing_version if pricing_version is not None else attested_pricing_version,
        onchain_reservation_id=(
            onchain_reservation_id
            or (str(provider_attestation.get("onchain_reservation_id") or "") if provider_attestation else None)
            or None
        ),
        settlement_deadline=int(settlement_deadline or attested_deadline or 0),
        signatures=signatures,
    )
    if signer is None:
        return receipt
    signed = sign_receipt(receipt.to_dict(), signer)
    return InferenceReceipt(
        **{
            **receipt.__dict__,
            "signatures": signed.get("signatures", {}),
        }
    )


def append_receipt(path: Path, receipt: InferenceReceipt) -> None:
    append_receipt_payload(path, receipt.to_dict())


def append_receipt_payload(path: Path, receipt: dict[str, Any]) -> None:
    job_id = str(receipt.get("job_id") or "").strip() or None
    _append_receipt_payload(path, receipt, receipt_id=job_id)


def append_receipt_payload_once(path: Path, receipt_id: str, receipt: dict[str, Any]) -> bool:
    normalized_id = str(receipt_id).strip()
    if not normalized_id or str(receipt.get("job_id") or "") != normalized_id:
        raise ValueError("receipt outbox id must match receipt job_id")
    return _append_receipt_payload(path, receipt, receipt_id=normalized_id)


def _append_receipt_payload(
    path: Path,
    receipt: dict[str, Any],
    *,
    receipt_id: str | None,
) -> bool:
    encoded = json.dumps(receipt, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    if len(encoded) - 1 > MAX_LEDGER_RECORD_BYTES:
        raise ValueError(f"receipt ledger record exceeds {MAX_LEDGER_RECORD_BYTES} bytes")
    payload_hash = _ledger_payload_hash(receipt)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as file:
        fcntl.flock(file.fileno(), fcntl.LOCK_EX)
        _repair_partial_ledger_tail(file)
        index_path = _ledger_index_path(path)
        conn = _open_ledger_index(index_path)
        try:
            _synchronize_ledger_index(conn, file)
            if receipt_id is not None:
                existing = conn.execute(
                    "SELECT payload_hash FROM receipt_jobs WHERE job_id = ?",
                    (receipt_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing[0]) != payload_hash:
                        raise ValueError(f"receipt ledger already contains a conflicting payload for {receipt_id}")
                    return False

            file.seek(0, os.SEEK_END)
            file.write(encoded)
            file.flush()
            os.fsync(file.fileno())
            _fsync_directory(path.parent)
            stat = os.fstat(file.fileno())
            with conn:
                if receipt_id is not None:
                    conn.execute(
                        "INSERT INTO receipt_jobs(job_id, payload_hash) VALUES (?, ?)",
                        (receipt_id, payload_hash),
                    )
                _set_ledger_index_metadata(conn, stat)
        finally:
            conn.close()
    return True


def _ledger_index_path(path: Path) -> Path:
    return path.with_name(path.name + LEDGER_INDEX_SUFFIX)


def _open_ledger_index(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30.0)
    try:
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS receipt_jobs (
                job_id TEXT PRIMARY KEY,
                payload_hash TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger_index_metadata (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                file_device TEXT NOT NULL,
                file_inode TEXT NOT NULL,
                indexed_size INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    except Exception:
        conn.close()
        raise
    return conn


def _synchronize_ledger_index(conn: sqlite3.Connection, file: BinaryIO) -> None:
    stat = os.fstat(file.fileno())
    row = conn.execute(
        "SELECT file_device, file_inode, indexed_size FROM ledger_index_metadata WHERE singleton = 1"
    ).fetchone()
    try:
        indexed_size = int(row[2]) if row is not None else -1
    except (TypeError, ValueError):
        indexed_size = -1
    rebuild = (
        row is None
        or str(row[0]) != str(stat.st_dev)
        or str(row[1]) != str(stat.st_ino)
        or indexed_size < 0
        or indexed_size > stat.st_size
        or not _ledger_offset_is_record_boundary(file, indexed_size)
    )
    start = 0 if rebuild else indexed_size
    if not rebuild and start == stat.st_size:
        return

    with conn:
        if rebuild:
            conn.execute("DELETE FROM receipt_jobs")
        _scan_ledger_records(conn, file, start=start, end=stat.st_size)
        _set_ledger_index_metadata(conn, stat)


def _scan_ledger_records(
    conn: sqlite3.Connection,
    file: BinaryIO,
    *,
    start: int,
    end: int,
) -> None:
    file.seek(start)
    while file.tell() < end:
        line = file.readline(MAX_LEDGER_RECORD_BYTES + 2)
        if not line:
            break
        if not line.endswith(b"\n") or len(line) - 1 > MAX_LEDGER_RECORD_BYTES:
            raise ValueError(f"receipt ledger record exceeds {MAX_LEDGER_RECORD_BYTES} bytes")
        try:
            payload = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        job_id = str(payload.get("job_id") or "").strip()
        if not job_id:
            continue
        payload_hash = _ledger_payload_hash(payload)
        existing = conn.execute(
            "SELECT payload_hash FROM receipt_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != payload_hash:
                raise ValueError(f"receipt ledger contains conflicting payloads for {job_id}")
            continue
        conn.execute(
            "INSERT INTO receipt_jobs(job_id, payload_hash) VALUES (?, ?)",
            (job_id, payload_hash),
        )


def _set_ledger_index_metadata(conn: sqlite3.Connection, stat: os.stat_result) -> None:
    conn.execute(
        """
        INSERT INTO ledger_index_metadata(singleton, file_device, file_inode, indexed_size)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(singleton) DO UPDATE SET
            file_device = excluded.file_device,
            file_inode = excluded.file_inode,
            indexed_size = excluded.indexed_size
        """,
        (str(stat.st_dev), str(stat.st_ino), int(stat.st_size)),
    )


def _ledger_offset_is_record_boundary(file: BinaryIO, offset: int) -> bool:
    if offset == 0:
        return True
    file.seek(offset - 1)
    return file.read(1) == b"\n"


def _repair_partial_ledger_tail(file: BinaryIO) -> None:
    file.seek(0, os.SEEK_END)
    size = file.tell()
    if size == 0:
        return
    file.seek(size - 1)
    if file.read(1) == b"\n":
        return

    search_end = size
    complete_end = 0
    while search_end > 0:
        search_start = max(0, search_end - 64 * 1024)
        file.seek(search_start)
        chunk = file.read(search_end - search_start)
        newline = chunk.rfind(b"\n")
        if newline >= 0:
            complete_end = search_start + newline + 1
            break
        search_end = search_start
    file.seek(complete_end)
    file.truncate()
    file.flush()
    os.fsync(file.fileno())


def _ledger_payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _receipt_request_hash(explicit: str | None, quality: dict[str, Any] | None, input_value: Any) -> str:
    candidate: Any = explicit
    if candidate is None and isinstance(quality, dict):
        candidate = quality.get("request_hash")
    if candidate is None:
        return stable_hash(input_value)
    normalized = str(candidate).removeprefix("0x").lower()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("receipt request_hash must be a 32-byte hex digest")
    return normalized


def sign_receipt(receipt: dict[str, Any], signer: NodeIdentity, role: str = "operator") -> dict[str, Any]:
    unsigned = dict(receipt)
    signatures = dict(unsigned.pop("signatures", {}) or {})
    signed = sign_document(unsigned, signer.private_key, purpose=f"{RECEIPT_PURPOSE}.{role}")
    signatures[role] = signed["signature"]
    unsigned["signatures"] = signatures
    return unsigned


def build_acceptance(receipt: dict[str, Any], accepted_by: str, status: str = "accepted") -> dict[str, Any]:
    return {
        "acceptance_version": ACCEPTANCE_VERSION,
        "receipt_hash": receipt_hash(receipt),
        "job_id": str(receipt.get("job_id") or ""),
        "consumer_id": str(receipt.get("consumer_id") or ""),
        "provider_id": str(receipt.get("provider_id") or ""),
        "accepted_by": accepted_by,
        "status": status,
    }


def sign_acceptance(receipt: dict[str, Any], signer: NodeIdentity, accepted_by: str | None = None) -> dict[str, Any]:
    acceptance = build_acceptance(receipt, accepted_by=accepted_by or signer.peer_id)
    signed = sign_document(acceptance, signer.private_key, purpose=ACCEPTANCE_PURPOSE)
    receipt_with_acceptance = dict(receipt)
    receipt_with_acceptance["acceptance"] = {key: value for key, value in signed.items() if key != "signature"}
    receipt_with_acceptance["acceptance_signature"] = signed["signature"]
    receipt_with_acceptance["accepted_hash"] = acceptance_hash(receipt_with_acceptance["acceptance"])
    return receipt_with_acceptance


def verify_acceptance(receipt: dict[str, Any], expected_public_key: str | None = None) -> dict[str, Any]:
    acceptance = receipt.get("acceptance")
    signature = receipt.get("acceptance_signature")
    if not isinstance(acceptance, dict):
        raise ValueError("missing receipt acceptance")
    if not isinstance(signature, dict):
        raise ValueError("missing receipt acceptance signature")
    signed = dict(acceptance)
    signed["signature"] = signature
    verified = verify_document(signed, purpose=ACCEPTANCE_PURPOSE)
    _require_signature_public_key(signature, expected_public_key, "acceptance")
    if str(verified.get("receipt_hash") or "") != receipt_hash(_receipt_without_acceptance(receipt)):
        raise ValueError("acceptance receipt hash mismatch")
    expected_hash = acceptance_hash(verified)
    if str(receipt.get("accepted_hash") or "") not in {"", expected_hash}:
        raise ValueError("accepted_hash mismatch")
    return verified


def receipt_hash(receipt: dict[str, Any]) -> str:
    return "0x" + stable_hash(_receipt_without_acceptance(receipt))


def acceptance_hash(acceptance: dict[str, Any]) -> str:
    return "0x" + stable_hash(acceptance)


def verify_receipt_signature(
    receipt: dict[str, Any],
    role: str = "operator",
    expected_public_key: str | None = None,
) -> dict[str, Any]:
    unsigned_receipt = _receipt_without_acceptance(receipt)
    signatures = unsigned_receipt.get("signatures")
    if not isinstance(signatures, dict) or role not in signatures:
        raise ValueError(f"missing {role} receipt signature")
    signed = {key: value for key, value in unsigned_receipt.items() if key != "signatures"}
    signature = signatures[role]
    if not isinstance(signature, dict):
        raise ValueError(f"invalid {role} receipt signature")
    _require_signature_public_key(signature, expected_public_key, f"{role} receipt")
    signed["signature"] = signature
    return verify_document(signed, purpose=f"{RECEIPT_PURPOSE}.{role}")


def _require_signature_public_key(signature: dict[str, Any], expected_public_key: str | None, label: str) -> None:
    if expected_public_key is None:
        return
    actual = str(signature.get("public_key") or "")
    if not actual or actual != str(expected_public_key):
        raise ValueError(f"{label} public_key mismatch")


def _receipt_without_acceptance(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"acceptance", "acceptance_signature", "accepted_hash"}
    }


def _response_provider_public_key(response: dict[str, Any]) -> str | None:
    provider_signature = response.get("provider_signature")
    if isinstance(provider_signature, dict):
        return provider_signature.get("public_key")
    return None


def _response_provider_payment_address(response: dict[str, Any]) -> str | None:
    peer = response.get("peer")
    if isinstance(peer, dict):
        payment_address = peer.get("payment_address")
        if payment_address:
            return str(payment_address)
    return None


def _response_quality(response: dict[str, Any]) -> dict[str, Any] | None:
    quality = response.get("quality")
    if isinstance(quality, dict):
        return dict(quality)
    raw = response.get("raw")
    if isinstance(raw, dict) and isinstance(raw.get("mycomesh_quality"), dict):
        return dict(raw["mycomesh_quality"])
    return None


def _attestation_int(attestation: dict[str, Any] | None, field: str) -> int | None:
    if not attestation or attestation.get(field) is None:
        return None
    try:
        return int(attestation[field])
    except (TypeError, ValueError):
        return None
