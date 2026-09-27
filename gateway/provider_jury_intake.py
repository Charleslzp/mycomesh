"""Durable canonical event intake for the V10 Provider-AI jury runtime.

This module is deliberately not an HTTP handler.  It follows only the pinned
Settlement and ProviderJuryRegistry contracts, waits for the configured number
of confirmations, and turns a canonical on-chain dispute into an internal
``ProviderJuryRuntime.process_case`` or ``reconcile_case`` call.

The event cursor and delivery fence live in SQLite.  Events which have not yet
been delivered may be rewound and replayed after a reorganization.  A deep
reorganization of a case which may already have reached the runtime is instead
persistently halted: an off-chain inference or an on-chain vote cannot be
rolled back safely by this indexer, so automatically executing a replacement
fork would be unsafe.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any, Iterator

from . import chain, chain_v9, chain_v10, provider_jury
from .provider_jury_chain import (
    JURY_ASSIGNED_TOPIC,
    JURY_FAILED_TOPIC,
    JURY_REQUESTED_TOPIC,
    JURY_UNAVAILABLE_TOPIC,
)
from .relay_incidents import evidence_hash


class ProviderJuryIntakeError(RuntimeError):
    """The event source, durable cursor, or evidence resolver is unsafe."""


INTAKE_HEALTH_SCHEMA = "mycomesh.v10.provider-jury-event-intake-health.v1"
CASE_EVENT_SCHEMA = "mycomesh.v10.provider-jury-chain-case.v1"
DISPUTE_OPENED_TOPIC = "0x" + chain.keccak256(
    b"DisputeOpened(bytes32,uint256)"
).hex()
EVIDENCE_SUBMITTED_TOPIC = "0x" + chain.keccak256(
    b"EvidenceSubmitted(bytes32,bytes32,address,bytes32,uint256)"
).hex()
DISPUTE_RESOLVED_TOPIC = "0x" + chain.keccak256(
    b"DisputeResolved(bytes32,uint8,uint256,uint256)"
).hex()
RECEIPT_ESCROWED_TOPIC = chain_v9.RECEIPT_ESCROWED_TOPIC
SETTLEMENT_TOPICS = frozenset({
    RECEIPT_ESCROWED_TOPIC, DISPUTE_OPENED_TOPIC, EVIDENCE_SUBMITTED_TOPIC,
    DISPUTE_RESOLVED_TOPIC,
})
REGISTRY_TOPICS = frozenset({
    JURY_REQUESTED_TOPIC, JURY_ASSIGNED_TOPIC, JURY_FAILED_TOPIC,
    JURY_UNAVAILABLE_TOPIC,
})
ASSIGNMENT_EVENTS = frozenset({
    "JuryRequested", "JuryAssigned", "JuryAssignmentFailed", "JuryUnavailable",
})

RPC = Callable[[str, list[Any]], Any]
EvidenceResolver = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _json(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProviderJuryIntakeError("jury intake data must be strict JSON") from exc


def _uint(value: Any, label: str, *, maximum: int = 2**256 - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ProviderJuryIntakeError(f"{label} must be a bounded nonnegative integer")
    return value


def _rpc_uint(value: Any, label: str, *, maximum: int = 2**256 - 1) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ProviderJuryIntakeError(f"{label} must be a canonical RPC quantity")
    try:
        result = int(value[2:] or "0", 16)
    except ValueError as exc:
        raise ProviderJuryIntakeError(f"{label} must be a canonical RPC quantity") from exc
    if value != hex(result) or result > maximum:
        raise ProviderJuryIntakeError(f"{label} must be a canonical RPC quantity")
    return result


def _address(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryIntakeError(f"invalid {label}") from exc
    if normalized != value or normalized == chain.ZERO_ADDRESS:
        raise ProviderJuryIntakeError(f"{label} must be lowercase canonical and nonzero")
    return normalized


def _hash(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryIntakeError(f"invalid {label}") from exc
    if normalized != value or (nonzero and normalized == chain.ZERO_BYTES32):
        raise ProviderJuryIntakeError(f"{label} must be lowercase canonical bytes32")
    return normalized


def _raw_data(value: Any, label: str) -> bytes:
    if (not isinstance(value, str) or not value.startswith("0x")
            or len(value) % 2 or value != value.lower()
            or any(character not in "0123456789abcdef" for character in value[2:])):
        raise ProviderJuryIntakeError(f"{label} has malformed ABI data")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:  # defensive after the character check
        raise ProviderJuryIntakeError(f"{label} has malformed ABI data") from exc


def _topic_address(value: Any, label: str) -> str:
    raw = bytes.fromhex(_hash(value, label)[2:])
    if any(raw[:12]):
        raise ProviderJuryIntakeError(f"{label} is not a canonical indexed address")
    return _address("0x" + raw[12:].hex(), label)


def _word_address(word: bytes, label: str) -> str:
    if len(word) != 32 or any(word[:12]):
        raise ProviderJuryIntakeError(f"{label} is not a canonical ABI address")
    return _address("0x" + word[12:].hex(), label)


def _static_arrays(
    raw: bytes, *, offsets: list[int], head_words: int, maximum: int, label: str,
) -> list[list[bytes]]:
    cursor = head_words * 32
    result: list[list[bytes]] = []
    for offset in offsets:
        if offset != cursor or offset + 32 > len(raw):
            raise ProviderJuryIntakeError(f"{label} has noncanonical array offsets")
        count = int.from_bytes(raw[offset:offset + 32], "big")
        if count > maximum:
            raise ProviderJuryIntakeError(f"{label} has an oversized array")
        end = offset + 32 + count * 32
        if end > len(raw):
            raise ProviderJuryIntakeError(f"{label} has a truncated array")
        result.append([
            raw[offset + 32 + index * 32:offset + 64 + index * 32]
            for index in range(count)
        ])
        cursor = end
    if cursor != len(raw):
        raise ProviderJuryIntakeError(f"{label} has trailing ABI data")
    return result


@dataclass(frozen=True)
class ProviderJuryEventIntakeConfig:
    network_id: str
    rpc_url: str
    chain_id: int
    genesis_hash: str
    settlement_contract: str
    jury_registry: str
    deployment_block: int
    confirmations: int
    max_scan_blocks: int = 500
    max_logs_per_scan: int = 2_000
    rpc_timeout: int = 15

    def __post_init__(self) -> None:
        if (not isinstance(self.network_id, str) or not self.network_id.strip()
                or self.network_id != self.network_id.strip()
                or len(self.network_id) > 256 or "\x00" in self.network_id):
            raise ProviderJuryIntakeError("network_id must be bounded canonical text")
        if not isinstance(self.rpc_url, str) or not self.rpc_url:
            raise ProviderJuryIntakeError("RPC URL is required")
        _uint(self.chain_id, "chain id")
        if self.chain_id == 0:
            raise ProviderJuryIntakeError("chain id must be positive")
        _hash(self.genesis_hash, "genesis hash")
        _address(self.settlement_contract, "Settlement contract")
        _address(self.jury_registry, "Jury Registry")
        if self.settlement_contract == self.jury_registry:
            raise ProviderJuryIntakeError("Settlement and Jury Registry must be distinct")
        _uint(self.deployment_block, "deployment block")
        if not 2 <= self.confirmations <= 256:
            raise ProviderJuryIntakeError("jury event intake requires 2 to 256 confirmations")
        if not 1 <= self.max_scan_blocks <= 2_000:
            raise ProviderJuryIntakeError("jury event scan range is out of bounds")
        if not 1 <= self.max_logs_per_scan <= 10_000:
            raise ProviderJuryIntakeError("jury event log limit is out of bounds")
        if not 1 <= self.rpc_timeout <= 300:
            raise ProviderJuryIntakeError("jury event RPC timeout is out of bounds")

    @property
    def domain(self) -> dict[str, Any]:
        return {
            "network_id": self.network_id,
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "settlement_contract": self.settlement_contract,
            "jury_registry": self.jury_registry,
            "deployment_block": self.deployment_block,
            "confirmations": self.confirmations,
            "max_scan_blocks": self.max_scan_blocks,
            "max_logs_per_scan": self.max_logs_per_scan,
        }


class ProviderJuryEventIntake:
    """Follow canonical V10 case events and call one internal jury runtime.

    ``resolve_evidence`` is a local trusted resolver (for example, a Relay
    incident database), not user input.  Its output remains bound to the
    on-chain report id and evidence hash before the runtime is called.
    """

    def __init__(
        self, path: str | os.PathLike[str], *, config: ProviderJuryEventIntakeConfig,
        resolve_evidence: EvidenceResolver, runtime: Any | None = None,
        rpc: RPC | None = None,
    ) -> None:
        if str(path) == ":memory:":
            raise ProviderJuryIntakeError("jury event intake database must be durable")
        if not callable(resolve_evidence):
            raise ProviderJuryIntakeError("a trusted local evidence resolver is required")
        self.path = Path(path)
        self.config = config
        self.resolve_evidence = resolve_evidence
        self._rpc_callback = rpc
        self._runtime: Any | None = None
        self._lock = threading.RLock()
        self._closed = False
        self._chain_verified = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode)
                    or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
                raise ProviderJuryIntakeError(
                    "jury intake database must be an owned regular file"
                )
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self.db = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, check_same_thread=False,
        )
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self._create_schema()
        self._pin_config()
        # The process may have died at any point after committing the delivery
        # fence.  Retrying the same settlement is safe because ProviderJuryRuntime
        # and its worker/outbox are themselves durable and idempotent.
        self.db.execute(
            "UPDATE provider_jury_intake_jobs SET state='active' "
            "WHERE state='processing'"
        )
        if runtime is not None:
            self.bind_runtime(runtime)

    def _create_schema(self) -> None:
        self.db.execute("""CREATE TABLE IF NOT EXISTS provider_jury_intake_state (
            id INTEGER PRIMARY KEY CHECK(id=1), domain_json TEXT NOT NULL,
            cursor_number INTEGER NOT NULL, cursor_hash TEXT,
            halted_reason TEXT, last_synced_at INTEGER,
            caught_up INTEGER NOT NULL DEFAULT 0
        )""")
        columns = {
            row["name"] for row in self.db.execute(
                "PRAGMA table_info(provider_jury_intake_state)"
            ).fetchall()
        }
        if "caught_up" not in columns:
            self.db.execute(
                "ALTER TABLE provider_jury_intake_state "
                "ADD COLUMN caught_up INTEGER NOT NULL DEFAULT 0"
            )
        self.db.execute("""CREATE TABLE IF NOT EXISTS provider_jury_intake_blocks (
            block_number INTEGER PRIMARY KEY, block_hash TEXT NOT NULL UNIQUE
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS provider_jury_intake_events (
            event_id TEXT PRIMARY KEY, block_number INTEGER NOT NULL,
            block_hash TEXT NOT NULL, transaction_hash TEXT NOT NULL,
            transaction_index INTEGER NOT NULL, log_index INTEGER NOT NULL,
            address TEXT NOT NULL, topic TEXT NOT NULL, event_name TEXT NOT NULL,
            settlement_key TEXT NOT NULL, payload_json TEXT NOT NULL,
            UNIQUE(block_number, log_index)
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS provider_jury_intake_jobs (
            settlement_key TEXT PRIMARY KEY, evidence_event_id TEXT NOT NULL UNIQUE,
            report_id TEXT NOT NULL, evidence_hash TEXT NOT NULL,
            reporter TEXT NOT NULL, state TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, dispatched_at INTEGER,
            updated_at INTEGER NOT NULL, last_error TEXT,
            last_runtime_status TEXT, result_json TEXT
        )""")

    def _pin_config(self) -> None:
        domain = _json(self.config.domain)
        self.db.execute(
            "INSERT OR IGNORE INTO provider_jury_intake_state "
            "(id,domain_json,cursor_number) VALUES (1,?,?)",
            (domain, self.config.deployment_block - 1),
        )
        saved = self.db.execute(
            "SELECT domain_json FROM provider_jury_intake_state WHERE id=1"
        ).fetchone()
        if saved is None or saved["domain_json"] != domain:
            self.db.close()
            raise ProviderJuryIntakeError(
                "jury intake database belongs to another deployment or scan policy"
            )

    def bind_runtime(self, runtime: Any) -> None:
        """Bind exactly one internal runtime; no network-facing adapter is exposed."""
        if (
            not callable(getattr(runtime, "process_case", None))
            or not callable(getattr(runtime, "reconcile_case", None))
        ):
            raise ProviderJuryIntakeError(
                "Provider jury runtime lacks process_case or reconcile_case"
            )
        worker = getattr(runtime, "worker", None)
        if worker is not None:
            expected = {
                "network_id": self.config.network_id,
                "chain_id": self.config.chain_id,
                "settlement_contract": self.config.settlement_contract,
                "jury_registry": self.config.jury_registry,
                "required_confirmations": self.config.confirmations,
            }
            if any(getattr(worker, name, None) != value for name, value in expected.items()):
                raise ProviderJuryIntakeError(
                    "Provider jury runtime differs from the event intake deployment pins"
                )
        with self._lock:
            if self._runtime is not None and self._runtime is not runtime:
                raise ProviderJuryIntakeError("jury event intake runtime is already bound")
            self._runtime = runtime

    def _rpc(self, method: str, params: list[Any]) -> Any:
        try:
            if self._rpc_callback is not None:
                return self._rpc_callback(method, params)
            return chain.rpc_call(
                self.config.rpc_url, method, params, timeout=self.config.rpc_timeout,
            )
        except ProviderJuryIntakeError:
            raise
        except Exception as exc:
            raise ProviderJuryIntakeError(f"jury intake RPC {method} failed") from exc

    @contextmanager
    def _cycle_lock(self) -> Iterator[None]:
        with self._lock:
            if self._closed:
                raise ProviderJuryIntakeError("jury event intake is closed")
            lock_path = str(self.path) + ".lock"
            descriptor = os.open(
                lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode)
                        or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
                    raise ProviderJuryIntakeError(
                        "jury intake lock must be an owned regular file"
                    )
                os.fchmod(descriptor, 0o600)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ProviderJuryIntakeError(
                        "another jury event intake cycle is active"
                    ) from None
                yield
            finally:
                os.close(descriptor)

    def _block(self, number: int) -> dict[str, Any]:
        value = self._rpc("eth_getBlockByNumber", [hex(number), False])
        if value is None:
            raise ProviderJuryIntakeError(f"canonical block {number} is unavailable")
        if not isinstance(value, Mapping):
            raise ProviderJuryIntakeError(f"canonical block {number} is malformed")
        observed_number = _rpc_uint(value.get("number"), "block number")
        if observed_number != number:
            raise ProviderJuryIntakeError("RPC returned the wrong canonical block")
        return {
            "number": number,
            "hash": _hash(value.get("hash"), "block hash"),
            "timestamp": _rpc_uint(
                value.get("timestamp"), "block timestamp", maximum=2**64 - 1,
            ),
        }

    def _optional_block(self, number: int) -> dict[str, Any] | None:
        value = self._rpc("eth_getBlockByNumber", [hex(number), False])
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise ProviderJuryIntakeError(f"canonical block {number} is malformed")
        observed_number = _rpc_uint(value.get("number"), "block number")
        if observed_number != number:
            raise ProviderJuryIntakeError("RPC returned the wrong canonical block")
        return {
            "number": number,
            "hash": _hash(value.get("hash"), "block hash"),
            "timestamp": _rpc_uint(
                value.get("timestamp"), "block timestamp", maximum=2**64 - 1,
            ),
        }

    def _verify_chain(self) -> int:
        chain_id = _rpc_uint(self._rpc("eth_chainId", []), "chain id")
        if chain_id != self.config.chain_id:
            raise ProviderJuryIntakeError("RPC chain differs from the jury deployment")
        genesis = self._block(0)
        if genesis["hash"] != self.config.genesis_hash:
            raise ProviderJuryIntakeError("RPC genesis differs from the jury deployment")
        head = _rpc_uint(self._rpc("eth_blockNumber", []), "head block")
        return head

    def _state(self) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM provider_jury_intake_state WHERE id=1"
        ).fetchone()
        if row is None:  # pragma: no cover - protected by schema and pinning
            raise ProviderJuryIntakeError("jury intake state is missing")
        return row

    def _halted(self) -> str | None:
        return self._state()["halted_reason"]

    def _ensure_not_halted(self) -> None:
        reason = self._halted()
        if reason:
            raise ProviderJuryIntakeError(
                f"jury event intake is halted pending operator reconciliation ({reason})"
            )

    def _recover_reorg(self) -> bool:
        state = self._state()
        cursor = int(state["cursor_number"])
        cursor_hash = state["cursor_hash"]
        if cursor_hash is None:
            return False
        current = self._optional_block(cursor)
        if current is not None and current["hash"] == cursor_hash:
            return False

        ancestor = self.config.deployment_block - 1
        ancestor_hash: str | None = None
        checkpoints = self.db.execute(
            "SELECT block_number,block_hash FROM provider_jury_intake_blocks "
            "WHERE block_number<? ORDER BY block_number DESC",
            (cursor,),
        ).fetchall()
        for checkpoint in checkpoints:
            number = int(checkpoint["block_number"])
            canonical = self._optional_block(number)
            if canonical is not None and canonical["hash"] == checkpoint["block_hash"]:
                ancestor = number
                ancestor_hash = checkpoint["block_hash"]
                break

        affected = self.db.execute(
            "SELECT DISTINCT jobs.settlement_key FROM provider_jury_intake_jobs jobs "
            "JOIN provider_jury_intake_events events "
            "ON events.settlement_key=jobs.settlement_key "
            "WHERE events.block_number>? AND jobs.dispatched_at IS NOT NULL",
            (ancestor,),
        ).fetchall()
        now = int(time.time())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if affected:
                keys = [row["settlement_key"] for row in affected]
                self.db.executemany(
                    "UPDATE provider_jury_intake_jobs SET state='orphaned', "
                    "updated_at=?,last_error='canonical_event_reorganized' "
                    "WHERE settlement_key=?",
                    [(now, key) for key in keys],
                )
                self.db.execute(
                    "UPDATE provider_jury_intake_state SET halted_reason=? WHERE id=1",
                    ("reorg_after_runtime_delivery",),
                )
            self.db.execute(
                "DELETE FROM provider_jury_intake_jobs WHERE dispatched_at IS NULL "
                "AND settlement_key IN (SELECT DISTINCT settlement_key FROM "
                "provider_jury_intake_events WHERE block_number>?)",
                (ancestor,),
            )
            self.db.execute(
                "DELETE FROM provider_jury_intake_events WHERE block_number>?",
                (ancestor,),
            )
            self.db.execute(
                "DELETE FROM provider_jury_intake_blocks WHERE block_number>?",
                (ancestor,),
            )
            self.db.execute(
                "UPDATE provider_jury_intake_state SET cursor_number=?,cursor_hash=?,"
                "caught_up=0 "
                "WHERE id=1",
                (ancestor, ancestor_hash),
            )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        if affected:
            raise ProviderJuryIntakeError(
                "canonical events changed after runtime delivery; automatic replay is halted"
            )
        return True

    @staticmethod
    def _event_order(event: Mapping[str, Any]) -> tuple[int, int, int]:
        return (
            int(event["block_number"]), int(event["transaction_index"]),
            int(event["log_index"]),
        )

    def _decode_log(self, value: Any, *, expected_address: str) -> dict[str, Any]:
        if not isinstance(value, Mapping) or value.get("removed") not in (None, False):
            raise ProviderJuryIntakeError("jury intake received a removed or malformed event")
        address_value = _address(value.get("address"), "event address")
        if address_value != expected_address:
            raise ProviderJuryIntakeError("jury event came from an unexpected contract")
        topics = value.get("topics")
        if not isinstance(topics, list) or not topics:
            raise ProviderJuryIntakeError("jury event has malformed topics")
        topics = [_hash(topic, "event topic", nonzero=False) for topic in topics]
        topic = topics[0]
        allowed = (
            SETTLEMENT_TOPICS
            if expected_address == self.config.settlement_contract
            else REGISTRY_TOPICS
        )
        if topic not in allowed:
            raise ProviderJuryIntakeError("jury event topic is not allowed for this contract")
        block_number = _rpc_uint(value.get("blockNumber"), "event block number")
        block_hash = _hash(value.get("blockHash"), "event block hash")
        transaction_hash = _hash(value.get("transactionHash"), "event transaction hash")
        transaction_index = _rpc_uint(
            value.get("transactionIndex"), "event transaction index",
        )
        log_index = _rpc_uint(value.get("logIndex"), "event log index")
        raw = _raw_data(value.get("data"), "jury event")
        event_name: str
        settlement_key: str
        payload: dict[str, Any]

        if topic == RECEIPT_ESCROWED_TOPIC:
            if len(topics) != 4 or len(raw) != 96:
                raise ProviderJuryIntakeError("ReceiptEscrowed event has malformed ABI data")
            event_name = "ReceiptEscrowed"
            settlement_key = _hash(topics[1], "escrow settlement key")
            payload = {
                "request_id": _hash(topics[2], "escrow request id"),
                "owner": _topic_address(topics[3], "escrow owner"),
                "provider": _word_address(raw[:32], "escrow Provider"),
                "gross_fee": int.from_bytes(raw[32:64], "big"),
                "release_at": _uint(
                    int.from_bytes(raw[64:96], "big"), "escrow release time",
                    maximum=2**64 - 1,
                ),
            }
            if payload["gross_fee"] == 0:
                raise ProviderJuryIntakeError("ReceiptEscrowed event has a zero fee")
        elif topic == DISPUTE_OPENED_TOPIC:
            if len(topics) != 2 or len(raw) != 32:
                raise ProviderJuryIntakeError("DisputeOpened event has malformed ABI data")
            event_name = "DisputeOpened"
            settlement_key = _hash(topics[1], "dispute settlement key")
            payload = {"resolve_at": int.from_bytes(raw, "big")}
        elif topic == EVIDENCE_SUBMITTED_TOPIC:
            if len(topics) != 4 or len(raw) != 64:
                raise ProviderJuryIntakeError("EvidenceSubmitted event has malformed ABI data")
            event_name = "EvidenceSubmitted"
            settlement_key = _hash(topics[1], "evidence settlement key")
            payload = {
                "report_id": _hash(topics[2], "evidence report id"),
                "reporter": _topic_address(topics[3], "evidence reporter"),
                "evidence_hash": _hash("0x" + raw[:32].hex(), "evidence hash"),
                "bond": int.from_bytes(raw[32:], "big"),
            }
            if chain_v10.report_id_for(
                settlement_key, payload["reporter"], payload["evidence_hash"],
            ) != payload["report_id"]:
                raise ProviderJuryIntakeError(
                    "EvidenceSubmitted report id is not canonical"
                )
        elif topic == DISPUTE_RESOLVED_TOPIC:
            if len(topics) != 2 or len(raw) != 96:
                raise ProviderJuryIntakeError("DisputeResolved event has malformed ABI data")
            status = int.from_bytes(raw[:32], "big")
            if status not in {4, 5, 6, 7}:
                raise ProviderJuryIntakeError(
                    "DisputeResolved event has a nonterminal status"
                )
            event_name = "DisputeResolved"
            settlement_key = _hash(topics[1], "resolved settlement key")
            payload = {
                "status": status,
                "slash_amount": int.from_bytes(raw[32:64], "big"),
                "stable_bounty": int.from_bytes(raw[64:], "big"),
            }
        elif topic == JURY_REQUESTED_TOPIC:
            if len(topics) != 3 or len(raw) != 64:
                raise ProviderJuryIntakeError("JuryRequested event has malformed ABI data")
            event_name = "JuryRequested"
            settlement_key = _hash(topics[1], "jury case id")
            payload = {
                "roster_version": _uint(
                    int(topics[2], 16), "jury roster version", maximum=2**64 - 1,
                ),
                "selection_block": _uint(
                    int.from_bytes(raw[:32], "big"), "jury selection block",
                    maximum=2**64 - 1,
                ),
                "roster_commitment": _hash(
                    "0x" + raw[32:].hex(), "jury roster commitment",
                ),
            }
        elif topic == JURY_UNAVAILABLE_TOPIC:
            if len(topics) != 3 or len(raw) != 32:
                raise ProviderJuryIntakeError("JuryUnavailable event has malformed ABI data")
            event_name = "JuryUnavailable"
            settlement_key = _hash(topics[1], "jury case id")
            payload = {
                "roster_version": _uint(
                    int(topics[2], 16), "jury roster version", maximum=2**64 - 1,
                ),
                "independent_candidate_count": int.from_bytes(raw, "big"),
            }
        elif topic == JURY_FAILED_TOPIC:
            if len(topics) != 2 or len(raw) != 32:
                raise ProviderJuryIntakeError(
                    "JuryAssignmentFailed event has malformed ABI data"
                )
            event_name = "JuryAssignmentFailed"
            settlement_key = _hash(topics[1], "jury case id")
            payload = {"seed": "0x" + raw.hex()}
        elif topic == JURY_ASSIGNED_TOPIC:
            if len(topics) != 3 or len(raw) < 128:
                raise ProviderJuryIntakeError("JuryAssigned event has malformed ABI data")
            offsets = [
                int.from_bytes(raw[index * 32:(index + 1) * 32], "big")
                for index in (1, 2, 3)
            ]
            arrays = _static_arrays(
                raw, offsets=offsets, head_words=4, maximum=7, label="JuryAssigned",
            )
            if not arrays[0] or not (len(arrays[0]) == len(arrays[1]) == len(arrays[2])):
                raise ProviderJuryIntakeError("JuryAssigned arrays have inconsistent lengths")
            event_name = "JuryAssigned"
            settlement_key = _hash(topics[1], "jury case id")
            payload = {
                "assignment_hash": _hash(topics[2], "jury assignment hash"),
                "seed": _hash("0x" + raw[:32].hex(), "jury seed"),
                "owners": [_word_address(word, "jury owner") for word in arrays[0]],
                "vote_signers": [
                    _word_address(word, "jury vote signer") for word in arrays[1]
                ],
                "operator_id_hashes": [
                    _hash("0x" + word.hex(), "jury operator id hash")
                    for word in arrays[2]
                ],
            }
        else:  # pragma: no cover - allowed-topic partition is exhaustive
            raise ProviderJuryIntakeError("unsupported jury event")

        identity = {
            "chain_id": self.config.chain_id,
            "block_hash": block_hash,
            "transaction_hash": transaction_hash,
            "log_index": log_index,
            "address": address_value,
            "topic": topic,
        }
        return {
            "event_id": evidence_hash(identity),
            "block_number": block_number,
            "block_hash": block_hash,
            "transaction_hash": transaction_hash,
            "transaction_index": transaction_index,
            "log_index": log_index,
            "address": address_value,
            "topic": topic,
            "event_name": event_name,
            "settlement_key": settlement_key,
            "payload": payload,
        }

    def _fetch_logs(self, start: int, end: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for address_value, topics in (
            (self.config.settlement_contract, sorted(SETTLEMENT_TOPICS)),
            (self.config.jury_registry, sorted(REGISTRY_TOPICS)),
        ):
            raw = self._rpc("eth_getLogs", [{
                "address": address_value,
                "fromBlock": hex(start),
                "toBlock": hex(end),
                "topics": [topics],
            }])
            if not isinstance(raw, list):
                raise ProviderJuryIntakeError("RPC returned a malformed jury event list")
            if len(raw) + len(result) > self.config.max_logs_per_scan:
                raise ProviderJuryIntakeError(
                    "jury event range exceeds the configured log limit"
                )
            result.extend(
                self._decode_log(item, expected_address=address_value) for item in raw
            )
        result.sort(key=self._event_order)
        return result

    def _insert_event(self, event: Mapping[str, Any]) -> bool:
        existing = self.db.execute(
            "SELECT * FROM provider_jury_intake_events WHERE event_id=? "
            "OR (block_number=? AND log_index=?)",
            (event["event_id"], event["block_number"], event["log_index"]),
        ).fetchall()
        encoded = _json(event["payload"])
        if existing:
            expected = (
                event["event_id"], event["block_number"], event["block_hash"],
                event["transaction_hash"], event["transaction_index"],
                event["log_index"], event["address"], event["topic"],
                event["event_name"], event["settlement_key"], encoded,
            )
            for row in existing:
                observed = tuple(row[name] for name in (
                    "event_id", "block_number", "block_hash", "transaction_hash",
                    "transaction_index", "log_index", "address", "topic",
                    "event_name", "settlement_key", "payload_json",
                ))
                if observed != expected:
                    raise ProviderJuryIntakeError(
                        "jury RPC equivocated about an existing event identity"
                    )
            return False
        self.db.execute(
            "INSERT INTO provider_jury_intake_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                event["event_id"], event["block_number"], event["block_hash"],
                event["transaction_hash"], event["transaction_index"],
                event["log_index"], event["address"], event["topic"],
                event["event_name"], event["settlement_key"], encoded,
            ),
        )
        return True

    @staticmethod
    def _row_event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "event_id": row["event_id"],
            "block_number": int(row["block_number"]),
            "block_hash": row["block_hash"],
            "transaction_hash": row["transaction_hash"],
            "transaction_index": int(row["transaction_index"]),
            "log_index": int(row["log_index"]),
            "address": row["address"],
            "event_name": row["event_name"],
            "settlement_key": row["settlement_key"],
            "payload": json.loads(row["payload_json"]),
        }

    def _materialize_jobs(self) -> int:
        rows = self.db.execute(
            "SELECT * FROM provider_jury_intake_events ORDER BY "
            "block_number,transaction_index,log_index"
        ).fetchall()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            event = self._row_event(row)
            grouped.setdefault(event["settlement_key"], []).append(event)
        created = 0
        now = int(time.time())
        for settlement_key, events in grouped.items():
            by_name: dict[str, list[dict[str, Any]]] = {}
            for event in events:
                by_name.setdefault(event["event_name"], []).append(event)
            if not all(by_name.get(name) for name in (
                "ReceiptEscrowed", "DisputeOpened", "EvidenceSubmitted",
            )):
                continue
            receipts = by_name["ReceiptEscrowed"]
            disputes = by_name["DisputeOpened"]
            evidence_events = by_name["EvidenceSubmitted"]
            if len(receipts) != 1 or len(disputes) != 1 or len(evidence_events) != 1:
                raise ProviderJuryIntakeError(
                    "V10 jury case must contain exactly one escrow, dispute, and owner report"
                )
            evidence = evidence_events[0]
            payload = evidence["payload"]
            if payload["reporter"] != receipts[0]["payload"]["owner"]:
                raise ProviderJuryIntakeError(
                    "V10 evidence reporter differs from the escrow owner"
                )
            assignments = [event for event in events if event["event_name"] in ASSIGNMENT_EVENTS]
            latest_assignment = assignments[-1] if assignments else None
            existing = self.db.execute(
                "SELECT state,dispatched_at FROM provider_jury_intake_jobs "
                "WHERE settlement_key=?",
                (settlement_key,),
            ).fetchone()
            resolutions = by_name.get("DisputeResolved", [])
            if resolutions and existing is None:
                status = resolutions[-1]["payload"]["status"]
                cursor = self.db.execute(
                    "INSERT OR IGNORE INTO provider_jury_intake_jobs "
                    "(settlement_key,evidence_event_id,report_id,evidence_hash,reporter,"
                    "state,updated_at,last_runtime_status) "
                    "VALUES (?,?,?,?,?,'chain_resolved',?,?)",
                    (
                        settlement_key, evidence["event_id"], payload["report_id"],
                        payload["evidence_hash"], payload["reporter"], now,
                        f"chain_resolved_{status}",
                    ),
                )
                created += int(cursor.rowcount > 0)
                continue
            if resolutions and existing is not None and existing["dispatched_at"] is None:
                status = resolutions[-1]["payload"]["status"]
                self.db.execute(
                    "UPDATE provider_jury_intake_jobs SET state='chain_resolved',"
                    "updated_at=?,last_runtime_status=? WHERE settlement_key=?",
                    (now, f"chain_resolved_{status}", settlement_key),
                )
                continue
            if latest_assignment is None:
                continue
            if latest_assignment["event_name"] not in {"JuryRequested", "JuryAssigned"}:
                if existing is not None and existing["state"] not in {
                    "completed", "expired", "chain_resolved", "orphaned",
                }:
                    state = (
                        "assignment_unavailable"
                        if latest_assignment["event_name"] == "JuryUnavailable"
                        else "assignment_failed"
                    )
                    self.db.execute(
                        "UPDATE provider_jury_intake_jobs SET state=?,updated_at=?,"
                        "last_runtime_status=? WHERE settlement_key=?",
                        (state, now, state, settlement_key),
                    )
                continue
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO provider_jury_intake_jobs "
                "(settlement_key,evidence_event_id,report_id,evidence_hash,reporter,state,updated_at) "
                "VALUES (?,?,?,?,?,'pending',?)",
                (
                    settlement_key, evidence["event_id"], payload["report_id"],
                    payload["evidence_hash"], payload["reporter"], now,
                ),
            )
            created += int(cursor.rowcount > 0)
            self.db.execute(
                "UPDATE provider_jury_intake_jobs SET "
                "state=CASE WHEN dispatched_at IS NULL THEN 'pending' ELSE 'active' END,"
                "updated_at=?,last_error=NULL WHERE settlement_key=? "
                "AND state IN ('assignment_failed','assignment_unavailable')",
                (now, settlement_key),
            )
        return created

    def sync_once(self) -> dict[str, Any]:
        """Ingest at most one bounded confirmed range and persist its cursor."""
        with self._cycle_lock():
            self._chain_verified = False
            self._ensure_not_halted()
            head = self._verify_chain()
            self._recover_reorg()
            self._ensure_not_halted()
            confirmed_head = head - self.config.confirmations + 1
            state = self._state()
            cursor = int(state["cursor_number"])
            if (cursor >= self.config.deployment_block
                    and cursor > confirmed_head):
                raise ProviderJuryIntakeError(
                    "confirmed chain head moved behind the durable jury cursor"
                )
            start = max(self.config.deployment_block, cursor + 1)
            if confirmed_head < start:
                self.db.execute(
                    "UPDATE provider_jury_intake_state SET caught_up=1,last_synced_at=? "
                    "WHERE id=1",
                    (int(time.time()),),
                )
                self._chain_verified = True
                return {
                    "from_block": start,
                    "through_block": cursor,
                    "latest_block": head,
                    "confirmed_head": confirmed_head,
                    "events": 0,
                    "jobs": 0,
                    "caught_up": cursor >= confirmed_head,
                }
            end = min(confirmed_head, start + self.config.max_scan_blocks - 1)
            boundary = self._block(end)
            events = self._fetch_logs(start, end)
            canonical: dict[int, str] = {end: boundary["hash"]}
            for event in events:
                number = int(event["block_number"])
                if not start <= number <= end:
                    raise ProviderJuryIntakeError("jury event lies outside its requested range")
                if number not in canonical:
                    canonical[number] = self._block(number)["hash"]
                if canonical[number] != event["block_hash"]:
                    raise ProviderJuryIntakeError("jury event is not on the canonical chain")
            if self._block(end)["hash"] != boundary["hash"]:
                raise ProviderJuryIntakeError(
                    "jury event scan boundary reorganized before cursor commit"
                )

            inserted = 0
            self.db.execute("BEGIN IMMEDIATE")
            try:
                for event in events:
                    inserted += int(self._insert_event(event))
                self.db.executemany(
                    "INSERT OR REPLACE INTO provider_jury_intake_blocks VALUES (?,?)",
                    sorted(canonical.items()),
                )
                jobs = self._materialize_jobs()
                self.db.execute(
                    "UPDATE provider_jury_intake_state SET cursor_number=?,cursor_hash=?,"
                    "last_synced_at=?,caught_up=? WHERE id=1",
                    (
                        end, boundary["hash"], int(time.time()),
                        int(end == confirmed_head),
                    ),
                )
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            self._chain_verified = True
            return {
                "from_block": start,
                "through_block": end,
                "latest_block": head,
                "confirmed_head": confirmed_head,
                "events": inserted,
                "jobs": jobs,
                "caught_up": end == confirmed_head,
            }

    def _case_snapshot(self, settlement_key: str, evidence_event_id: str) -> dict[str, Any]:
        rows = self.db.execute(
            "SELECT * FROM provider_jury_intake_events WHERE settlement_key=? "
            "ORDER BY block_number,transaction_index,log_index",
            (settlement_key,),
        ).fetchall()
        events = [self._row_event(row) for row in rows]
        receipts = [event for event in events if event["event_name"] == "ReceiptEscrowed"]
        disputes = [event for event in events if event["event_name"] == "DisputeOpened"]
        evidence_events = [
            event for event in events if event["event_name"] == "EvidenceSubmitted"
        ]
        if len(receipts) != 1 or len(disputes) != 1 or len(evidence_events) != 1:
            raise ProviderJuryIntakeError(
                "V10 jury case must contain exactly one escrow, dispute, and owner report"
            )
        if evidence_events[0]["payload"]["reporter"] != receipts[0]["payload"]["owner"]:
            raise ProviderJuryIntakeError(
                "V10 evidence reporter differs from the escrow owner"
            )
        if evidence_events[0]["event_id"] != evidence_event_id:
            raise ProviderJuryIntakeError(
                "jury job is not bound to the sole canonical owner report"
            )
        selected: dict[str, Any] = {}
        assignments: list[dict[str, Any]] = []
        for event in events:
            if event["event_name"] == "ReceiptEscrowed" and "receipt" not in selected:
                selected["receipt"] = event
            elif event["event_name"] == "DisputeOpened" and "dispute" not in selected:
                selected["dispute"] = event
            elif event["event_id"] == evidence_event_id:
                selected["evidence"] = event
            if event["event_name"] in ASSIGNMENT_EVENTS:
                assignments.append(event)
        if set(selected) != {"receipt", "dispute", "evidence"} or not assignments:
            raise ProviderJuryIntakeError("jury case lost a required canonical event")
        assignment = assignments[-1]
        if assignment["event_name"] not in {"JuryRequested", "JuryAssigned"}:
            raise ProviderJuryIntakeError("jury assignment is not currently actionable")
        return {
            "schema": CASE_EVENT_SCHEMA,
            "network_id": self.config.network_id,
            "chain_id": self.config.chain_id,
            "settlement_contract": self.config.settlement_contract,
            "jury_registry": self.config.jury_registry,
            "settlement_key": settlement_key,
            "receipt": selected["receipt"],
            "dispute": selected["dispute"],
            "evidence": selected["evidence"],
            "assignment": assignment,
        }

    def _verify_snapshot_canonical(
        self, snapshot: Mapping[str, Any], *, head: int,
    ) -> int:
        confirmed_head = head - self.config.confirmations + 1
        if confirmed_head < 0:
            raise ProviderJuryIntakeError("chain has insufficient jury confirmations")
        boundary = self._block(confirmed_head)
        cache: dict[int, str] = {}
        for name in ("receipt", "dispute", "evidence", "assignment"):
            event = snapshot[name]
            number = int(event["block_number"])
            if number > confirmed_head:
                raise ProviderJuryIntakeError(
                    "jury case contains an event without enough confirmations"
                )
            if number not in cache:
                cache[number] = self._block(number)["hash"]
            if cache[number] != event["block_hash"]:
                raise ProviderJuryIntakeError(
                    "jury case event reorganized before runtime delivery"
                )
        if self._block(confirmed_head)["hash"] != boundary["hash"]:
            raise ProviderJuryIntakeError(
                "jury case confirmation boundary reorganized during verification"
            )
        return int(boundary["timestamp"])

    def _resolved_evidence(
        self, snapshot: Mapping[str, Any], job: Mapping[str, Any],
    ) -> tuple[dict[str, str], dict[str, Any]]:
        try:
            resolved = self.resolve_evidence(snapshot)
        except ProviderJuryIntakeError:
            raise
        except Exception as exc:
            raise ProviderJuryIntakeError("trusted jury evidence resolver failed") from exc
        if not isinstance(resolved, Mapping) or set(resolved) != {
            "evidence", "evidence_document",
        }:
            raise ProviderJuryIntakeError(
                "trusted resolver must return evidence and evidence_document only"
            )
        raw_evidence = resolved.get("evidence")
        document = resolved.get("evidence_document")
        if not isinstance(raw_evidence, Mapping) or set(raw_evidence) != {
            "report_id", "evidence_hash", "request_hash", "response_hash",
        } or not isinstance(document, Mapping) or not document:
            raise ProviderJuryIntakeError("trusted resolver returned malformed jury evidence")
        normalized = {
            name: _hash(raw_evidence.get(name), f"resolved {name}")
            for name in ("report_id", "evidence_hash", "request_hash", "response_hash")
        }
        if (normalized["report_id"] != job["report_id"]
                or normalized["evidence_hash"] != job["evidence_hash"]):
            raise ProviderJuryIntakeError(
                "resolved jury evidence differs from the canonical on-chain report"
            )
        try:
            frozen_document = json.loads(_json(document))
        except json.JSONDecodeError as exc:  # pragma: no cover - _json produced JSON
            raise ProviderJuryIntakeError("jury evidence document is not JSON") from exc
        if evidence_hash(frozen_document) != normalized["evidence_hash"]:
            raise ProviderJuryIntakeError(
                "resolved jury document differs from the on-chain evidence hash"
            )
        if (frozen_document.get("schema") != provider_jury.EVIDENCE_DOCUMENT_SCHEMA
                or frozen_document.get("settlement_key") != snapshot["settlement_key"]
                or frozen_document.get("reporter") != job["reporter"]):
            raise ProviderJuryIntakeError(
                "resolved jury document is not bound to the canonical case and reporter"
            )
        return normalized, frozen_document

    def dispatch_once(self) -> dict[str, Any] | None:
        """Deliver one canonical case through the runtime's idempotent API."""
        with self._cycle_lock():
            self._chain_verified = False
            self._ensure_not_halted()
            if self._runtime is None:
                raise ProviderJuryIntakeError("Provider jury runtime is not bound")
            head = self._verify_chain()
            self._recover_reorg()
            self._ensure_not_halted()
            confirmed_head = head - self.config.confirmations + 1
            state = self._state()
            cursor = int(state["cursor_number"])
            if (cursor < confirmed_head
                    or (cursor >= self.config.deployment_block
                        and cursor > confirmed_head)):
                self.db.execute(
                    "UPDATE provider_jury_intake_state SET caught_up=0 WHERE id=1"
                )
                raise ProviderJuryIntakeError(
                    "jury event cursor is not caught up to the confirmed chain head"
                )
            self._materialize_jobs()
            rows = self.db.execute(
                "SELECT * FROM provider_jury_intake_jobs "
                "WHERE state IN ('pending','active') "
                "ORDER BY updated_at,settlement_key LIMIT 100"
            ).fetchall()
            if not rows:
                self._chain_verified = True
                return None
            selected: tuple[dict[str, Any], dict[str, Any], bool] | None = None
            waiting: dict[str, Any] | None = None
            for row in rows:
                job = dict(row)
                snapshot = self._case_snapshot(
                    job["settlement_key"], job["evidence_event_id"],
                )
                chain_time = self._verify_snapshot_canonical(snapshot, head=head)
                release_at = int(snapshot["receipt"]["payload"]["release_at"])
                resolve_at = int(snapshot["dispute"]["payload"]["resolve_at"])
                if resolve_at <= release_at:
                    raise ProviderJuryIntakeError(
                        "canonical dispute window is inconsistent with its escrow"
                    )
                if chain_time < release_at:
                    if waiting is None:
                        waiting = {
                            "settlement_key": job["settlement_key"],
                            "report_id": job["report_id"],
                            "state": "waiting_evidence_window",
                            "confirmed_chain_time": chain_time,
                            "release_at": release_at,
                        }
                    continue
                if chain_time >= resolve_at:
                    # Once delivery has started, never discard the durable
                    # worker/outbox state merely because the dispute window
                    # elapsed.  A restart can land here after a broadcast;
                    # only the original transaction may be reconciled.
                    delivery_started = (
                        job["dispatched_at"] is not None
                        or job.get("state") in {"processing", "active"}
                    )
                    if not delivery_started:
                        self.db.execute(
                            "UPDATE provider_jury_intake_jobs SET state='expired',"
                            "updated_at=?,last_runtime_status='window_expired',"
                            "last_error=NULL WHERE settlement_key=?",
                            (int(time.time()), job["settlement_key"]),
                        )
                        continue
                    selected = (job, snapshot, True)
                    break
                selected = (job, snapshot, False)
                break
            if selected is None:
                self._chain_verified = True
                return waiting
            job, snapshot, reconcile_only = selected
            if reconcile_only:
                evidence = document = None
            else:
                evidence, document = self._resolved_evidence(snapshot, job)
            # ProviderJuryRuntime checks this callback again immediately before
            # every monetary action.  Mark it ready only after the chain facts
            # and the locally resolved evidence have both been revalidated.
            self._chain_verified = True

            now = int(time.time())
            self.db.execute("BEGIN IMMEDIATE")
            try:
                changed = self.db.execute(
                    "UPDATE provider_jury_intake_jobs SET state='processing',"
                    "attempts=attempts+1,dispatched_at=COALESCE(dispatched_at,?),"
                    "updated_at=?,last_error=NULL WHERE settlement_key=? "
                    "AND state IN ('pending','active')",
                    (now, now, job["settlement_key"]),
                )
                if changed.rowcount != 1:
                    raise ProviderJuryIntakeError("jury intake delivery fence was superseded")
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            try:
                if reconcile_only:
                    result = self._runtime.reconcile_case(job["settlement_key"])
                else:
                    result = self._runtime.process_case(
                        job["settlement_key"], evidence, document,
                    )
                if not isinstance(result, Mapping):
                    raise ProviderJuryIntakeError("Provider jury runtime returned no state")
                frozen_result = json.loads(_json(result))
                status = frozen_result.get("status")
                if not isinstance(status, str) or not status:
                    raise ProviderJuryIntakeError(
                        "Provider jury runtime returned an invalid state"
                    )
                # Both quorum outcomes now execute voteDisputeBySig. A case is
                # complete only after the original transaction is canonically
                # confirmed; a local negative model result is not a timeout.
                completed = status == "confirmed"
                expired_without_transaction = reconcile_only and status in {
                    "not_admitted", "pending", "admitted",
                }
                self.db.execute(
                    "UPDATE provider_jury_intake_jobs SET state=?,updated_at=?,"
                    "last_runtime_status=?,result_json=?,last_error=NULL "
                    "WHERE settlement_key=?",
                    (
                        "expired" if expired_without_transaction else (
                            "completed" if completed else "active"
                        ), int(time.time()),
                        "window_expired" if expired_without_transaction else status,
                        _json(frozen_result), job["settlement_key"],
                    ),
                )
                return {
                    "settlement_key": job["settlement_key"],
                    "report_id": job["report_id"],
                    "state": (
                        "expired" if expired_without_transaction else (
                            "completed" if completed else "active"
                        )
                    ),
                    "runtime": frozen_result,
                }
            except BaseException as exc:
                self.db.execute(
                    "UPDATE provider_jury_intake_jobs SET state='active',updated_at=?,"
                    "last_error=? WHERE settlement_key=?",
                    (int(time.time()), type(exc).__name__, job["settlement_key"]),
                )
                raise

    def health(self) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                return {
                    "schema": INTAKE_HEALTH_SCHEMA,
                    "ready": False,
                    "error_code": "intake_closed",
                }
            state = self._state()
            halted = state["halted_reason"]
            caught_up = bool(int(state["caught_up"]))
            ready = (
                self._chain_verified and caught_up
                and self._runtime is not None and not halted
            )
            result: dict[str, Any] = {
                "schema": INTAKE_HEALTH_SCHEMA,
                "ready": ready,
                "chain_id": self.config.chain_id,
                "settlement_contract": self.config.settlement_contract,
                "jury_registry": self.config.jury_registry,
                "confirmations": self.config.confirmations,
                "cursor": {
                    "block_number": int(state["cursor_number"]),
                    "block_hash": state["cursor_hash"],
                },
                "runtime_bound": self._runtime is not None,
                "chain_verified": self._chain_verified,
                "caught_up": caught_up,
                "halted": bool(halted),
            }
            if halted:
                result["error_code"] = halted
            elif not self._chain_verified:
                result["error_code"] = "chain_not_verified"
            elif not caught_up:
                result["error_code"] = "cursor_not_caught_up"
            elif self._runtime is None:
                result["error_code"] = "runtime_not_bound"
            return result

    def ready(self) -> bool:
        return bool(self.health().get("ready"))

    def job(self, settlement_key: str) -> dict[str, Any] | None:
        key = _hash(settlement_key, "settlement key")
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM provider_jury_intake_jobs WHERE settlement_key=?",
                (key,),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            if result.get("result_json"):
                result["result"] = json.loads(result.pop("result_json"))
            else:
                result.pop("result_json", None)
            return result

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self.db.close()


__all__ = [
    "CASE_EVENT_SCHEMA", "DISPUTE_OPENED_TOPIC", "DISPUTE_RESOLVED_TOPIC",
    "EVIDENCE_SUBMITTED_TOPIC",
    "INTAKE_HEALTH_SCHEMA", "ProviderJuryEventIntake",
    "ProviderJuryEventIntakeConfig", "ProviderJuryIntakeError",
    "RECEIPT_ESCROWED_TOPIC",
]
