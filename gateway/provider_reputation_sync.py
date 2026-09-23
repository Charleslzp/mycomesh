"""Fail-closed Pool reputation publisher for the dynamic Provider jury Registry.

The candidate pool is deliberately mutable.  A Pool signs one monotonically
sequenced, receipt-commitment-bound reputation snapshot for a live Provider
descriptor.  This module derives the Registry entry from those two artifacts;
it never accepts or persists a fixed adjudicator roster.

Chain writes are explicit opt-in and at-most-once.  The signed transaction is
committed to SQLite before broadcast.  A crash in ``executing`` becomes
``uncertain`` on restart, and neither ``submitted`` nor ``uncertain`` is ever
automatically re-signed or re-broadcast.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from . import chain, pool, provider_jury
from .identity import NodeIdentity, sign_document, verify_document, IdentityError
from .provider_identity_binding import verify_provider_identity_binding
from .relay_adjudication_v9 import _protected_key
from .relay_incidents import evidence_hash
from .v10_reputation import (
    DISPUTE_RESOLVED_TOPIC,
    FEEDBACK_FIELDS,
    SETTLEMENT_RELEASED_TOPIC,
    V9_DISPUTE_RESOLVED_TOPIC,
    V10ReputationError,
    V10ReputationEventVerifier,
    V10ReputationVerifierConfig,
    canonical_terminal_log_reference,
    normalize_feedback_document,
    reputation_event_id,
)


class ProviderReputationSyncError(ValueError):
    """The reputation source, Registry state, or transaction is unsafe."""


SNAPSHOT_SCHEMA = "mycomesh.pool.provider-reputation-snapshot.v3"
SNAPSHOT_PURPOSE = "mycomesh.pool.provider-reputation-snapshot.v3"
ACTION_SCHEMA = "mycomesh.v10.provider-reputation-action.v1"
RECEIPT_SET_SCHEMA = "mycomesh.pool.reputation-event-set.v2"
SOURCE_DIGEST_SCHEMA = "mycomesh.pool.provider-reputation-source.v2"
HISTORY_IMPORT_SCHEMA = "mycomesh.v10.reputation-history-import.v1"
ZERO_SHA256 = "0" * 64
SET_PROVIDER_SIGNATURE = (
    "setProvider((address,address,bytes32,bytes32,bytes32,uint64,bool),uint64,bytes32)"
)
PROVIDER_UPDATED_TOPIC = "0x" + chain.keccak256(
    b"ProviderUpdated(address,address,bytes32,uint64,bool,uint64,bytes32,uint64)"
).hex()
UINT64_MAX = 2**64 - 1
ZERO_BYTES32 = chain.ZERO_BYTES32
MAX_SNAPSHOT_TTL_SECONDS = 900
MAX_DESCRIPTOR_TTL_SECONDS = 300
_HEX_PUBLIC_KEY = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_NONCE = re.compile(r"^[0-9a-f]{32}$")
_OPERATOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]*$")


RPC = Callable[[str, list[Any]], Any]
EndpointRPC = Callable[[str, str, list[Any]], Any]
TransactionSigner = Callable[..., bytes]
KeyLoader = Callable[[str | os.PathLike[str]], bytes]
EventVerifierFactory = Callable[
    [V10ReputationVerifierConfig, RPC], V10ReputationEventVerifier,
]


def _json(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProviderReputationSyncError("reputation sync data must be strict JSON") from exc


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProviderReputationSyncError(f"{label} has unknown or missing fields")
    return value


def _uint(
    value: Any, label: str, *, bits: int = 256, positive: bool = False,
) -> int:
    if type(value) is not int or value < int(positive) or value >= 2**bits:
        raise ProviderReputationSyncError(f"{label} must be a bounded integer")
    return value


def _hex_uint(value: Any, label: str, *, bits: int = 256) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ProviderReputationSyncError(f"{label} must be canonical RPC hex")
    try:
        parsed = int(value[2:] or "0", 16)
    except ValueError as exc:
        raise ProviderReputationSyncError(f"{label} must be canonical RPC hex") from exc
    if value != hex(parsed) or parsed >= 2**bits:
        raise ProviderReputationSyncError(f"{label} must be canonical RPC hex")
    return parsed


def _address(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderReputationSyncError(f"invalid {label}") from exc
    if normalized != value or (nonzero and normalized == chain.ZERO_ADDRESS):
        raise ProviderReputationSyncError(f"{label} must be canonical and nonzero")
    return normalized


def _hash(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderReputationSyncError(f"invalid {label}") from exc
    if normalized != value or (nonzero and normalized == ZERO_BYTES32):
        raise ProviderReputationSyncError(
            f"{label} must be canonical" + (" and nonzero" if nonzero else "")
        )
    return normalized


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > maximum or "\x00" in value
    ):
        raise ProviderReputationSyncError(f"{label} must be bounded canonical text")
    return value


def _raw_result(value: Any, label: str) -> bytes:
    if (
        not isinstance(value, str) or not value.startswith("0x")
        or len(value) % 2 or any(ch not in "0123456789abcdef" for ch in value[2:])
    ):
        raise ProviderReputationSyncError(f"{label} returned malformed ABI data")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ProviderReputationSyncError(f"{label} returned malformed ABI data") from exc


def _word_address(word: bytes, label: str, *, nonzero: bool = True) -> str:
    if len(word) != 32 or any(word[:12]):
        raise ProviderReputationSyncError(f"{label} returned a malformed address")
    return _address("0x" + word[12:].hex(), label, nonzero=nonzero)


def _word_uint(word: bytes, label: str, *, bits: int = 256) -> int:
    if len(word) != 32:
        raise ProviderReputationSyncError(f"{label} returned a malformed integer")
    return _uint(int.from_bytes(word, "big"), label, bits=bits)


def _word_bool(word: bytes, label: str) -> bool:
    value = _word_uint(word, label, bits=8)
    if value not in (0, 1):
        raise ProviderReputationSyncError(f"{label} returned a malformed boolean")
    return bool(value)


def _receipt_set_hash(event_ids: list[str]) -> str:
    """Commit to one Provider's verified, chain-scoped terminal event set."""
    normalized = [_hash(item, "Pool reputation event id") for item in event_ids]
    if normalized != sorted(set(normalized)):
        raise ProviderReputationSyncError(
            "Pool reputation event ids must be unique and sorted"
        )
    return evidence_hash({"schema": RECEIPT_SET_SCHEMA, "event_ids": normalized})


@dataclass(frozen=True)
class ReputationHistoryImport:
    """One release-pinned, same-chain V9/V10 history source.

    Entries contain full terminal-event references.  The snapshot authority
    cannot add an imported event: membership is checked against this exact
    artifact and every member is reverified from the pinned source contract.
    """

    source_network_id: str
    source_protocol_version: int
    source_chain_id: int
    source_genesis_hash: str
    source_settlement_contract: str
    source_runtime_code_hash: str
    confirmations: int
    source_deployment_block: int
    source_deployment_block_hash: str
    source_history_through_block: int
    source_history_through_block_hash: str
    artifact_sha256: str
    artifact_root: str
    entries: Mapping[str, tuple[Mapping[str, Any], ...]]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "source_network_id", _text(self.source_network_id, "history source network_id"),
        )
        if self.source_protocol_version not in {9, 10}:
            raise ProviderReputationSyncError(
                "history source protocol version must be V9 or V10"
            )
        object.__setattr__(
            self, "source_chain_id",
            _uint(self.source_chain_id, "history source chain id", positive=True, bits=64),
        )
        object.__setattr__(
            self, "source_genesis_hash",
            _hash(self.source_genesis_hash, "history source genesis hash"),
        )
        object.__setattr__(
            self, "source_settlement_contract",
            _address(self.source_settlement_contract, "history source settlement"),
        )
        object.__setattr__(
            self, "source_runtime_code_hash",
            _hash(self.source_runtime_code_hash, "history source runtime code hash"),
        )
        confirmations = _uint(
            self.confirmations, "history confirmations", positive=True, bits=16,
        )
        if not 2 <= confirmations <= 256:
            raise ProviderReputationSyncError(
                "history confirmations must be between two and 256"
            )
        object.__setattr__(self, "confirmations", confirmations)
        deployment_block = _uint(
            self.source_deployment_block,
            "history source deployment block",
            positive=True,
            bits=64,
        )
        history_through = _uint(
            self.source_history_through_block,
            "history source through block",
            positive=True,
            bits=64,
        )
        if history_through < deployment_block:
            raise ProviderReputationSyncError(
                "history source cutoff predates contract deployment"
            )
        object.__setattr__(self, "source_deployment_block", deployment_block)
        object.__setattr__(
            self,
            "source_deployment_block_hash",
            _hash(
                self.source_deployment_block_hash,
                "history source deployment block hash",
            ),
        )
        object.__setattr__(self, "source_history_through_block", history_through)
        object.__setattr__(
            self,
            "source_history_through_block_hash",
            _hash(
                self.source_history_through_block_hash,
                "history source through block hash",
            ),
        )
        if not isinstance(self.artifact_sha256, str) or re.fullmatch(
            r"[0-9a-f]{64}", self.artifact_sha256,
        ) is None or self.artifact_sha256 == ZERO_SHA256:
            raise ProviderReputationSyncError("invalid history import artifact sha256")
        object.__setattr__(
            self, "artifact_root", _hash(self.artifact_root, "history import artifact root"),
        )
        if not isinstance(self.entries, Mapping) or not self.entries:
            raise ProviderReputationSyncError("history import entries are required")
        normalized: dict[str, tuple[Mapping[str, Any], ...]] = {}
        all_events: set[str] = set()
        signer_peers: dict[str, str] = {}
        for peer_id, raw_events in self.entries.items():
            peer = _text(peer_id, "history peer id", maximum=160)
            if not isinstance(raw_events, tuple) or not raw_events:
                raise ProviderReputationSyncError("history peer event set is invalid")
            events: list[Mapping[str, Any]] = []
            peer_signer: str | None = None
            for raw_event in raw_events:
                try:
                    event = pool.normalize_feedback_document(raw_event)
                    event_id = pool.reputation_event_id(event)
                except (pool.V10ReputationError, AttributeError) as exc:
                    raise ProviderReputationSyncError(
                        "history import contains an invalid terminal-event reference"
                    ) from exc
                if (
                    event["peer_id"] != peer
                    or event["network_id"] != self.source_network_id
                    or event["chain_id"] != self.source_chain_id
                    or event["settlement_contract"] != self.source_settlement_contract
                    or event_id in all_events
                ):
                    raise ProviderReputationSyncError(
                        "history import event identity or source is invalid"
                    )
                if peer_signer is None:
                    peer_signer = event["provider_signer"]
                elif peer_signer != event["provider_signer"]:
                    raise ProviderReputationSyncError(
                        "history peer entry mixes Provider signer identities"
                    )
                all_events.add(event_id)
                events.append(event)
            assert peer_signer is not None
            if peer_signer in signer_peers:
                raise ProviderReputationSyncError(
                    "historical Provider signer is assigned to multiple peers"
                )
            signer_peers[peer_signer] = peer
            normalized[peer] = tuple(events)
        object.__setattr__(self, "entries", normalized)

    def lineage(self) -> dict[str, Any]:
        return {
            "schema": HISTORY_IMPORT_SCHEMA,
            "source_network_id": self.source_network_id,
            "source_protocol_version": self.source_protocol_version,
            "source_chain_id": self.source_chain_id,
            "source_genesis_hash": self.source_genesis_hash,
            "source_settlement_contract": self.source_settlement_contract,
            "source_runtime_code_hash": self.source_runtime_code_hash,
            "confirmations": self.confirmations,
            "source_deployment_block": self.source_deployment_block,
            "source_deployment_block_hash": self.source_deployment_block_hash,
            "source_history_through_block": self.source_history_through_block,
            "source_history_through_block_hash": self.source_history_through_block_hash,
            "artifact_sha256": self.artifact_sha256,
            "artifact_root": self.artifact_root,
        }


def load_reputation_history_import(
    value: Any,
    *,
    artifact_sha256: str,
    expected_artifact_root: str,
) -> ReputationHistoryImport:
    """Validate one exact proof-carrying V9/V10 history artifact."""
    artifact = _exact(
        value, {"schema", "source", "entries"}, "reputation history import",
    )
    if artifact.get("schema") != HISTORY_IMPORT_SCHEMA:
        raise ProviderReputationSyncError(
            "unsupported reputation history import schema"
        )
    root = evidence_hash(artifact)
    if root != _hash(expected_artifact_root, "history import artifact root"):
        raise ProviderReputationSyncError(
            "reputation history import semantic root differs from its pin"
        )
    source = _exact(
        artifact.get("source"),
        {
            "network_id", "protocol_version", "chain_id", "genesis_hash",
            "settlement_contract", "runtime_code_hash", "confirmations",
            "source_deployment_block", "source_deployment_block_hash",
            "source_history_through_block", "source_history_through_block_hash",
        },
        "reputation history source",
    )
    raw_entries = artifact.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ProviderReputationSyncError(
            "reputation history import entries are required"
        )
    entries: dict[str, tuple[Mapping[str, Any], ...]] = {}
    explicit_signers: set[str] = set()
    observed_peers: list[str] = []
    for raw_entry in raw_entries:
        entry = _exact(
            raw_entry, {"peer_id", "provider_signer", "events"},
            "reputation history entry",
        )
        peer_id = _text(entry.get("peer_id"), "history peer id", maximum=160)
        observed_peers.append(peer_id)
        if peer_id in entries:
            raise ProviderReputationSyncError(
                "reputation history import contains a duplicate peer"
            )
        provider_signer = _address(
            entry.get("provider_signer"), "historical Provider signer",
        )
        if provider_signer in explicit_signers:
            raise ProviderReputationSyncError(
                "historical Provider signer is assigned to multiple peers"
            )
        raw_events = entry.get("events")
        if not isinstance(raw_events, list) or not raw_events:
            raise ProviderReputationSyncError(
                "reputation history peer has no terminal events"
            )
        events: list[Mapping[str, Any]] = []
        event_ids: list[str] = []
        for raw_event in raw_events:
            try:
                event = normalize_feedback_document(raw_event)
            except V10ReputationError as exc:
                raise ProviderReputationSyncError(
                    "reputation history entry has an invalid terminal event"
                ) from exc
            if event["peer_id"] != peer_id or event["provider_signer"] != provider_signer:
                raise ProviderReputationSyncError(
                    "history entry is not bound to its Provider signer and peer"
                )
            events.append(event)
            event_ids.append(reputation_event_id(event))
        if event_ids != sorted(event_ids):
            raise ProviderReputationSyncError(
                "reputation history events must use canonical identity order"
            )
        entries[peer_id] = tuple(events)
        explicit_signers.add(provider_signer)
    if observed_peers != sorted(observed_peers):
        raise ProviderReputationSyncError(
            "reputation history entries must use canonical peer order"
        )
    return ReputationHistoryImport(
        source_network_id=_text(source.get("network_id"), "history source network id"),
        source_protocol_version=_uint(
            source.get("protocol_version"), "history source protocol version", bits=8,
        ),
        source_chain_id=_uint(
            source.get("chain_id"), "history source chain id", bits=64, positive=True,
        ),
        source_genesis_hash=_hash(
            source.get("genesis_hash"), "history source genesis hash",
        ),
        source_settlement_contract=_address(
            source.get("settlement_contract"), "history source settlement",
        ),
        source_runtime_code_hash=_hash(
            source.get("runtime_code_hash"), "history source runtime code hash",
        ),
        confirmations=_uint(
            source.get("confirmations"), "history confirmations", bits=16, positive=True,
        ),
        source_deployment_block=_uint(
            source.get("source_deployment_block"),
            "history source deployment block",
            bits=64,
            positive=True,
        ),
        source_deployment_block_hash=_hash(
            source.get("source_deployment_block_hash"),
            "history source deployment block hash",
        ),
        source_history_through_block=_uint(
            source.get("source_history_through_block"),
            "history source through block",
            bits=64,
            positive=True,
        ),
        source_history_through_block_hash=_hash(
            source.get("source_history_through_block_hash"),
            "history source through block hash",
        ),
        artifact_sha256=artifact_sha256,
        artifact_root=root,
        entries=entries,
    )


@dataclass(frozen=True)
class ProviderReputationSyncConfig:
    network_id: str
    rpc_url: str
    chain_id: int
    genesis_hash: str
    settlement_contract: str
    settlement_runtime_code_hash: str
    settlement_deployment_block: int
    settlement_deployment_block_hash: str
    jury_registry: str
    registry_runtime_code_hash: str
    minimum_reputation: int
    decision_policy_hash: str
    pool_snapshot_public_keys: tuple[str, ...]
    snapshot_audience: str
    descriptor_audience: str
    confirmations: int = 3
    timeout_seconds: float = 10.0
    max_snapshot_age_seconds: int = 300
    max_descriptor_age_seconds: int = 300
    history_import: ReputationHistoryImport | None = None
    rpc_urls: tuple[str, ...] = ()
    allow_insecure_test_rpc: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "network_id", _text(self.network_id, "network_id"))
        object.__setattr__(self, "rpc_url", _text(self.rpc_url, "RPC URL", maximum=2048))
        if type(self.allow_insecure_test_rpc) is not bool:
            raise ProviderReputationSyncError(
                "insecure test RPC policy must be explicit"
            )
        rpc_urls = tuple(self.rpc_urls) or (self.rpc_url,)
        parsed_urls = [urlsplit(item) if isinstance(item, str) else None for item in rpc_urls]
        if (
            len(rpc_urls) != len(set(rpc_urls))
            or self.rpc_url not in rpc_urls
            or any(
                not isinstance(item, str)
                or item != item.strip()
                or "\x00" in item
                or parsed is None
                or parsed.scheme not in (
                    {"http", "https"}
                    if self.allow_insecure_test_rpc else {"https"}
                )
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or bool(parsed.query)
                or bool(parsed.fragment)
                for item, parsed in zip(rpc_urls, parsed_urls)
            )
            or len({str(parsed.hostname).lower() for parsed in parsed_urls})
            != len(parsed_urls)
        ):
            raise ProviderReputationSyncError(
                "reputation RPC endpoints must be independent credential-free pinned HTTPS URLs"
            )
        object.__setattr__(self, "rpc_urls", rpc_urls)
        object.__setattr__(self, "chain_id", _uint(self.chain_id, "chain id", positive=True))
        object.__setattr__(self, "genesis_hash", _hash(self.genesis_hash, "genesis hash"))
        object.__setattr__(
            self, "settlement_contract",
            _address(self.settlement_contract, "settlement contract"),
        )
        object.__setattr__(
            self, "settlement_runtime_code_hash",
            _hash(
                self.settlement_runtime_code_hash,
                "settlement runtime code hash",
            ),
        )
        object.__setattr__(
            self, "settlement_deployment_block",
            _uint(
                self.settlement_deployment_block,
                "settlement deployment block",
                bits=64,
                positive=True,
            ),
        )
        object.__setattr__(
            self, "settlement_deployment_block_hash",
            _hash(
                self.settlement_deployment_block_hash,
                "settlement deployment block hash",
            ),
        )
        object.__setattr__(
            self, "jury_registry", _address(self.jury_registry, "jury Registry"),
        )
        object.__setattr__(
            self, "registry_runtime_code_hash",
            _hash(self.registry_runtime_code_hash, "Registry runtime code hash"),
        )
        object.__setattr__(
            self, "minimum_reputation",
            _uint(self.minimum_reputation, "minimum reputation", bits=64, positive=True),
        )
        object.__setattr__(
            self, "decision_policy_hash",
            _hash(self.decision_policy_hash, "jury decision policy hash"),
        )
        keys = tuple(self.pool_snapshot_public_keys)
        if (
            len(keys) != 1 or len(set(keys)) != len(keys)
            or any(_HEX_PUBLIC_KEY.fullmatch(key) is None for key in keys)
        ):
            raise ProviderReputationSyncError(
                "exactly one canonical Pool snapshot authority must be pinned"
            )
        object.__setattr__(self, "pool_snapshot_public_keys", keys)
        object.__setattr__(
            self, "snapshot_audience", _text(self.snapshot_audience, "snapshot audience"),
        )
        object.__setattr__(
            self, "descriptor_audience",
            _text(self.descriptor_audience, "descriptor audience", maximum=2048),
        )
        confirmations = _uint(
            self.confirmations, "confirmations", bits=16, positive=True,
        )
        if not 2 <= confirmations <= 256:
            raise ProviderReputationSyncError(
                "reputation confirmations must be between 2 and 256"
            )
        object.__setattr__(self, "confirmations", confirmations)
        if (
            type(self.timeout_seconds) not in (int, float)
            or not 0 < float(self.timeout_seconds) <= 300
        ):
            raise ProviderReputationSyncError("RPC timeout must be bounded and positive")
        for name, maximum in (
            ("max_snapshot_age_seconds", MAX_SNAPSHOT_TTL_SECONDS),
            ("max_descriptor_age_seconds", MAX_DESCRIPTOR_TTL_SECONDS),
        ):
            value = _uint(getattr(self, name), name, bits=32, positive=True)
            if value > maximum:
                raise ProviderReputationSyncError(f"{name} exceeds the supported maximum")
        if len(rpc_urls) < 2:
            raise ProviderReputationSyncError(
                "reputation admission requires at least two pinned RPC endpoints"
            )
        history = self.history_import
        if history is not None:
            if not isinstance(history, ReputationHistoryImport):
                raise ProviderReputationSyncError(
                    "validated V10 reputation history import is required"
                )
            if (
                history.source_chain_id != self.chain_id
                or history.source_genesis_hash != self.genesis_hash
                or history.source_settlement_contract == self.settlement_contract
            ):
                raise ProviderReputationSyncError(
                    "history import must be a prior V9/V10 deployment on the pinned chain"
                )


def build_pool_reputation_snapshot(
    config: pool.PoolConfig,
    *,
    peer_id: str,
    network_id: str,
    sequence: int,
    pool_identity: NodeIdentity,
    audience: str,
    now: int | None = None,
    ttl_seconds: int = 300,
    history_import: ReputationHistoryImport | None = None,
) -> dict[str, Any]:
    """Sign a snapshot from the Pool's authenticated, replay-fenced store."""
    current = int(time.time()) if now is None else _uint(now, "snapshot time", bits=64)
    ttl = _uint(ttl_seconds, "snapshot TTL", bits=32, positive=True)
    if ttl > MAX_SNAPSHOT_TTL_SECONDS:
        raise ProviderReputationSyncError("snapshot TTL exceeds the supported maximum")
    source_peer = _text(peer_id, "snapshot peer id", maximum=160)
    with config.lock:
        current_proofs = dict(config.reputation_proofs.get(source_peer) or {})
    imported = () if history_import is None else history_import.entries.get(source_peer, ())
    proofs_by_id: dict[str, dict[str, Any]] = {}
    for raw_proof in (*imported, *current_proofs.values()):
        try:
            proof = pool.normalize_feedback_document(raw_proof)
            event_id = pool.reputation_event_id(proof)
        except (pool.V10ReputationError, AttributeError) as exc:
            raise ProviderReputationSyncError(
                "snapshot contains an invalid terminal-event proof"
            ) from exc
        if proof["peer_id"] != source_peer or event_id in proofs_by_id:
            raise ProviderReputationSyncError(
                "snapshot terminal-event proofs are duplicated or target another peer"
            )
        proofs_by_id[event_id] = proof
    if not proofs_by_id:
        raise ProviderReputationSyncError(
            "snapshot requires at least one replayable terminal-event proof"
        )
    receipts = sorted(proofs_by_id)
    proofs = [proofs_by_id[event_id] for event_id in receipts]
    stats = _stats_from_events(proofs)
    document = {
        "schema": SNAPSHOT_SCHEMA,
        "network_id": _text(network_id, "network_id"),
        "peer_id": source_peer,
        "sequence": _uint(sequence, "snapshot sequence", bits=63, positive=True),
        "stats": stats,
        "receipt_count": len(receipts),
        "receipt_set_hash": _receipt_set_hash(receipts),
        "events": proofs,
        "history_import": (
            history_import.lineage() if history_import is not None else None
        ),
        "observed_at": current,
        "expires_at": current + ttl,
    }
    return sign_document(
        document, pool_identity.private_key, SNAPSHOT_PURPOSE,
        timestamp=current, audience=_text(audience, "snapshot audience"),
    )


def _snapshot_stats(value: Any) -> dict[str, int]:
    stats = _exact(
        value,
        {"score", "successes", "failures", "settlements", "disputes"},
        "Pool reputation stats",
    )
    counters = {
        name: _uint(stats.get(name), f"Pool reputation {name}", bits=64)
        for name in ("successes", "failures", "settlements", "disputes")
    }
    expected = pool.peer_reputation_score(**counters)
    if (
        counters["successes"] != counters["settlements"]
        or counters["failures"] != counters["disputes"]
    ):
        raise ProviderReputationSyncError(
            "Pool reputation counters violate terminal-event invariants"
        )
    if type(stats.get("score")) is not int or stats.get("score") != expected:
        raise ProviderReputationSyncError(
            "Pool reputation score does not match the canonical receipt formula"
        )
    return {"score": expected, **counters}


def _stats_from_events(events: list[Mapping[str, Any]]) -> dict[str, int]:
    counters = {
        "successes": 0, "failures": 0, "settlements": 0, "disputes": 0,
    }
    for event in events:
        outcome = event.get("outcome")
        if outcome == "positive":
            counters["successes"] += 1
            counters["settlements"] += 1
        elif outcome == "negative":
            counters["failures"] += 1
            counters["disputes"] += 1
        elif outcome != "neutral":
            raise ProviderReputationSyncError(
                "snapshot terminal event has an invalid outcome"
            )
    return {
        "score": pool.peer_reputation_score(**counters),
        **counters,
    }


def verify_pool_reputation_snapshot(
    value: Any,
    *,
    config: ProviderReputationSyncConfig,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderReputationSyncError("Pool reputation snapshot must be an object")
    current = int(time.time()) if now is None else _uint(now, "current time", bits=64)
    try:
        unsigned = verify_document(
            value,
            purpose=SNAPSHOT_PURPOSE,
            audience=config.snapshot_audience,
            max_age_seconds=config.max_snapshot_age_seconds,
            now=current,
        )
    except IdentityError as exc:
        raise ProviderReputationSyncError(f"invalid Pool reputation snapshot: {exc}") from exc
    signature = value.get("signature")
    if not isinstance(signature, Mapping):
        raise ProviderReputationSyncError("Pool reputation snapshot signature is required")
    signer = str(signature.get("public_key") or "")
    if signer not in config.pool_snapshot_public_keys:
        raise ProviderReputationSyncError("Pool reputation snapshot signer is not pinned")
    if _SIGNATURE_NONCE.fullmatch(str(signature.get("nonce") or "")) is None:
        raise ProviderReputationSyncError("Pool reputation snapshot nonce is not canonical")
    document = _exact(
        unsigned,
        {
            "schema", "network_id", "peer_id", "sequence", "stats",
            "receipt_count", "receipt_set_hash", "events", "history_import",
            "observed_at", "expires_at",
        },
        "Pool reputation snapshot",
    )
    if document.get("schema") != SNAPSHOT_SCHEMA:
        raise ProviderReputationSyncError("unsupported Pool reputation snapshot schema")
    if document.get("network_id") != config.network_id:
        raise ProviderReputationSyncError("Pool reputation snapshot targets another network")
    peer_id = _text(document.get("peer_id"), "snapshot peer id", maximum=160)
    sequence = _uint(document.get("sequence"), "snapshot sequence", bits=63, positive=True)
    observed_at = _uint(document.get("observed_at"), "snapshot observed_at", bits=64)
    expires_at = _uint(document.get("expires_at"), "snapshot expires_at", bits=64)
    signature_time = _uint(signature.get("timestamp"), "snapshot signature time", bits=64)
    if signature_time != observed_at:
        raise ProviderReputationSyncError(
            "Pool reputation snapshot observation is not bound to its signature time"
        )
    if (
        not observed_at <= current < expires_at
        or expires_at > observed_at + config.max_snapshot_age_seconds
    ):
        raise ProviderReputationSyncError("Pool reputation snapshot is stale or overlong")
    receipt_count = _uint(document.get("receipt_count"), "receipt count", bits=64)
    receipt_set_hash = _hash(document.get("receipt_set_hash"), "receipt set hash")
    raw_events = document.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise ProviderReputationSyncError(
            "Pool reputation snapshot requires terminal-event proofs"
        )
    events: list[dict[str, Any]] = []
    event_ids: list[str] = []
    for raw_event in raw_events:
        try:
            event = pool.normalize_feedback_document(raw_event)
            event_id = pool.reputation_event_id(event)
        except (pool.V10ReputationError, AttributeError) as exc:
            raise ProviderReputationSyncError(
                "Pool reputation snapshot contains an invalid terminal-event proof"
            ) from exc
        if event["peer_id"] != peer_id or event_id in event_ids:
            raise ProviderReputationSyncError(
                "Pool reputation snapshot event is duplicated or targets another peer"
            )
        events.append(event)
        event_ids.append(event_id)
    if event_ids != sorted(event_ids):
        raise ProviderReputationSyncError(
            "Pool reputation snapshot events must use canonical identity order"
        )
    if receipt_count != len(events) or receipt_set_hash != _receipt_set_hash(event_ids):
        raise ProviderReputationSyncError(
            "Pool reputation snapshot event commitment is invalid"
        )
    stats = _snapshot_stats(document.get("stats"))
    if stats != _stats_from_events(events):
        raise ProviderReputationSyncError(
            "Pool reputation counters differ from their terminal-event proofs"
        )
    expected_history = (
        config.history_import.lineage() if config.history_import is not None else None
    )
    if document.get("history_import") != expected_history:
        raise ProviderReputationSyncError(
            "Pool reputation snapshot history lineage differs from the pinned import"
        )
    return {
        "schema": SNAPSHOT_SCHEMA,
        "network_id": config.network_id,
        "peer_id": peer_id,
        "sequence": sequence,
        "stats": stats,
        "receipt_count": receipt_count,
        "receipt_set_hash": receipt_set_hash,
        "events": events,
        "history_import": expected_history,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "pool_public_key": signer,
        "snapshot_hash": evidence_hash(value),
    }


def _keccak_text(value: str) -> str:
    return "0x" + chain.keccak256(value.encode("utf-8")).hex()


def verify_live_provider_descriptor(
    value: Any,
    *,
    snapshot: Mapping[str, Any],
    config: ProviderReputationSyncConfig,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderReputationSyncError("Provider descriptor must be a signed object")
    if len(_json(value).encode("utf-8")) > pool.MAX_PEER_DESCRIPTOR_BYTES:
        raise ProviderReputationSyncError("Provider descriptor is too large")
    current = int(time.time()) if now is None else _uint(now, "current time", bits=64)
    try:
        descriptor = pool.verify_peer_descriptor(
            value,
            require_signed=True,
            audience=config.descriptor_audience,
            max_signature_age_seconds=config.max_descriptor_age_seconds,
            now=current,
        )
    except pool.PoolError as exc:
        raise ProviderReputationSyncError(f"invalid live Provider descriptor: {exc}") from exc
    signature = value.get("signature")
    if not isinstance(signature, Mapping):
        raise ProviderReputationSyncError("Provider descriptor signature is required")
    descriptor_signer = str(signature.get("public_key") or "")
    if (
        _HEX_PUBLIC_KEY.fullmatch(descriptor_signer) is None
        or descriptor.get("public_key") != descriptor_signer
        or _SIGNATURE_NONCE.fullmatch(str(signature.get("nonce") or "")) is None
    ):
        raise ProviderReputationSyncError(
            "Provider descriptor signer is not bound to its peer identity"
        )
    signature_time = _uint(signature.get("timestamp"), "descriptor signature time", bits=64)
    if signature_time > current + 30:
        raise ProviderReputationSyncError("Provider descriptor signature is in the future")
    ttl = _uint(descriptor.get("ttl_seconds"), "Provider descriptor TTL", bits=32, positive=True)
    if ttl > MAX_DESCRIPTOR_TTL_SECONDS or current >= signature_time + ttl:
        raise ProviderReputationSyncError("Provider descriptor is not live")
    peer_id = _text(descriptor.get("peer_id"), "Provider peer id", maximum=160)
    if peer_id != snapshot.get("peer_id"):
        raise ProviderReputationSyncError(
            "Provider descriptor peer does not match the reputation snapshot"
        )
    if descriptor.get("network_id") != config.network_id:
        raise ProviderReputationSyncError("Provider descriptor targets another network")
    jury = _exact(
        descriptor.get("provider_jury"),
        {
            "schema", "provider_owner", "vote_signer", "operator_id",
            "operator_id_hash", "peer_id_hash", "capability", "capability_hash",
        },
        "Provider jury descriptor",
    )
    if jury.get("schema") != "mycomesh.provider-jury.descriptor.v1":
        raise ProviderReputationSyncError("unsupported Provider jury descriptor schema")
    owner = _address(jury.get("provider_owner"), "Provider owner")
    vote_signer = _address(jury.get("vote_signer"), "Provider vote signer")
    if owner == vote_signer:
        raise ProviderReputationSyncError("Provider owner and vote signer must be independent")
    if _address(descriptor.get("payment_address"), "Provider payment address") != owner:
        raise ProviderReputationSyncError("Provider owner differs from its signed payment address")
    settlement = descriptor.get("settlement")
    if not isinstance(settlement, Mapping):
        raise ProviderReputationSyncError("Provider V10 settlement descriptor is required")
    if (
        settlement.get("version") != 10
        or settlement.get("chain_id") != config.chain_id
        or settlement.get("contract") != config.settlement_contract
        or _address(settlement.get("provider_signer"), "settlement Provider signer")
        != vote_signer
    ):
        raise ProviderReputationSyncError(
            "Provider vote signer differs from its signed V10 settlement identity"
        )
    try:
        proven_signer = verify_provider_identity_binding(
            descriptor, audience=config.descriptor_audience,
        )
    except ValueError as exc:
        raise ProviderReputationSyncError(
            f"Provider descriptor lacks a valid EVM vote-signer proof: {exc}"
        ) from exc
    if proven_signer != vote_signer:
        raise ProviderReputationSyncError(
            "Provider EVM identity proof differs from its jury vote signer"
        )
    operator_id = _text(jury.get("operator_id"), "Provider operator id", maximum=160)
    if _OPERATOR_ID.fullmatch(operator_id) is None:
        raise ProviderReputationSyncError("Provider operator id is not canonical")
    operator_hash = _hash(jury.get("operator_id_hash"), "Provider operator id hash")
    peer_hash = _hash(jury.get("peer_id_hash"), "Provider peer id hash")
    capability = jury.get("capability")
    if not isinstance(capability, Mapping):
        raise ProviderReputationSyncError("Provider jury capability is required")
    try:
        computed_capability_hash = provider_jury.capability_hash(capability)
    except provider_jury.ProviderJuryError as exc:
        raise ProviderReputationSyncError(f"invalid Provider jury capability: {exc}") from exc
    capability_hash = _hash(jury.get("capability_hash"), "Provider capability hash")
    if operator_hash != _keccak_text(operator_id):
        raise ProviderReputationSyncError("Provider operator identity hash mismatch")
    if peer_hash != _keccak_text(peer_id):
        raise ProviderReputationSyncError("Provider peer identity hash mismatch")
    if capability_hash != computed_capability_hash:
        raise ProviderReputationSyncError("Provider capability hash mismatch")
    if capability.get("decision_policy_hash") != config.decision_policy_hash:
        raise ProviderReputationSyncError("Provider jury capability has another policy")
    return {
        "owner": owner,
        "vote_signer": vote_signer,
        "operator_id": operator_id,
        "operator_id_hash": operator_hash,
        "peer_id": peer_id,
        "peer_id_hash": peer_hash,
        "capability": json.loads(_json(capability)),
        "capability_hash": capability_hash,
        "descriptor_hash": evidence_hash(value),
        "descriptor_timestamp": signature_time,
        "descriptor_expires_at": signature_time + ttl,
    }


def provider_source_digest(
    snapshot: Mapping[str, Any], descriptor: Mapping[str, Any],
) -> str:
    """Commit the two authenticated artifacts that produced a Registry row."""
    return evidence_hash({
        "schema": SOURCE_DIGEST_SCHEMA,
        "pool_public_key": str(snapshot.get("pool_public_key") or ""),
        "peer_id": _text(snapshot.get("peer_id"), "source peer id", maximum=160),
        "sequence": _uint(
            snapshot.get("sequence"), "source sequence", bits=63, positive=True,
        ),
        "snapshot_hash": _hash(snapshot.get("snapshot_hash"), "snapshot hash"),
        "receipt_set_hash": _hash(
            snapshot.get("receipt_set_hash"), "receipt set hash",
        ),
        "history_import": snapshot.get("history_import"),
        "descriptor_hash": _hash(
            descriptor.get("descriptor_hash"), "descriptor hash",
        ),
    })


def encode_set_provider(
    provider: Mapping[str, Any], *, source_sequence: Any, source_digest: Any,
) -> str:
    args = [
        _address(provider.get("owner"), "Provider owner"),
        _address(provider.get("vote_signer"), "Provider vote signer"),
        _hash(provider.get("operator_id_hash"), "Provider operator id hash"),
        _hash(provider.get("peer_id_hash"), "Provider peer id hash"),
        _hash(provider.get("capability_hash"), "Provider capability hash"),
        str(_uint(provider.get("reputation"), "Provider reputation", bits=64)),
        "true" if provider.get("active") is True else "false",
        str(_uint(source_sequence, "source sequence", bits=64, positive=True)),
        _hash(source_digest, "source digest"),
    ]
    if type(provider.get("active")) is not bool:
        raise ProviderReputationSyncError("Provider active flag must be a boolean")
    try:
        return chain.encode_contract_call(SET_PROVIDER_SIGNATURE, args)
    except chain.ChainError as exc:
        raise ProviderReputationSyncError("could not encode setProvider action") from exc


def _action_snapshot_event_ids(value: Mapping[str, Any]) -> set[str]:
    """Recover the authenticated proof set retained inside a durable action."""
    artifacts = value.get("source_artifacts")
    snapshot = artifacts.get("snapshot") if isinstance(artifacts, Mapping) else None
    events = snapshot.get("events") if isinstance(snapshot, Mapping) else None
    if not isinstance(events, list) or not events:
        raise ProviderReputationSyncError(
            "durable reputation action has no replayable snapshot event set"
        )
    result: set[str] = set()
    for raw_event in events:
        try:
            event_id = reputation_event_id(normalize_feedback_document(raw_event))
        except V10ReputationError as exc:
            raise ProviderReputationSyncError(
                "durable reputation action has an invalid snapshot event"
            ) from exc
        if event_id in result:
            raise ProviderReputationSyncError(
                "durable reputation action repeats a snapshot event"
            )
        result.add(event_id)
    source = value.get("source")
    if (
        not isinstance(source, Mapping)
        or source.get("receipt_count") != len(result)
        or source.get("receipt_set_hash") != _receipt_set_hash(sorted(result))
    ):
        raise ProviderReputationSyncError(
            "durable reputation action event commitment is invalid"
        )
    return result


class ProviderReputationOutbox:
    """Durable source replay fence, execution lease, and transaction identity."""

    STATES = frozenset({
        "proposed", "executing", "submitted", "confirmed", "uncertain", "reverted",
    })

    def __init__(self, path: str | os.PathLike[str]) -> None:
        if str(path) == ":memory:":
            raise ProviderReputationSyncError("reputation outbox must be durable")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            target, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise ProviderReputationSyncError(
                    "reputation outbox must be an owned regular file"
                )
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.path = target
        self._lock = threading.RLock()
        self.db = sqlite3.connect(
            target, timeout=30, isolation_level=None, check_same_thread=False,
        )
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("""CREATE TABLE IF NOT EXISTS provider_reputation_actions (
            action_hash TEXT PRIMARY KEY,
            scope TEXT NOT NULL,
            source_signer TEXT NOT NULL,
            source_peer_id TEXT NOT NULL,
            source_sequence INTEGER NOT NULL,
            snapshot_hash TEXT NOT NULL,
            descriptor_hash TEXT NOT NULL,
            provider_owner TEXT NOT NULL,
            sender TEXT NOT NULL,
            target TEXT NOT NULL,
            calldata TEXT NOT NULL,
            action_json TEXT NOT NULL,
            state TEXT NOT NULL,
            lease_id TEXT,
            lease_expires INTEGER,
            nonce INTEGER,
            tx_hash TEXT UNIQUE,
            raw_tx TEXT,
            receipt_json TEXT,
            result_json TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(scope,sender,nonce)
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS provider_reputation_sources (
            source_signer TEXT NOT NULL,
            provider_owner TEXT NOT NULL,
            source_peer_id TEXT NOT NULL,
            source_sequence INTEGER NOT NULL,
            source_observed_at INTEGER NOT NULL,
            descriptor_timestamp INTEGER NOT NULL,
            receipt_count INTEGER NOT NULL,
            snapshot_hash TEXT NOT NULL,
            action_hash TEXT NOT NULL,
            PRIMARY KEY(source_signer,provider_owner),
            UNIQUE(source_signer,source_peer_id)
        )""")
        # A process can die after signing or broadcasting but before advancing
        # the journal.  Restart never guesses which side of that boundary won.
        recovered_at = int(time.time())
        self.db.execute(
            "UPDATE provider_reputation_actions SET state='proposed',lease_id=NULL,"
            "lease_expires=NULL,updated_at=? WHERE state='executing' AND tx_hash IS NULL",
            (recovered_at,),
        )
        self.db.execute(
            "UPDATE provider_reputation_actions SET state='uncertain',lease_id=NULL,"
            "lease_expires=NULL,updated_at=? WHERE state='executing' AND tx_hash IS NOT NULL",
            (recovered_at,),
        )
        # Repair rows produced by an older lease-recovery bug that labelled a
        # provably pre-transaction crash as uncertain.  A real send boundary
        # always has nonce, raw bytes, and a locally derived transaction hash.
        self.db.execute(
            "UPDATE provider_reputation_actions SET state='proposed',lease_id=NULL,"
            "lease_expires=NULL,updated_at=? WHERE state='uncertain' "
            "AND nonce IS NULL AND tx_hash IS NULL AND raw_tx IS NULL",
            (recovered_at,),
        )

    def close(self) -> None:
        with self._lock:
            self.db.close()

    @staticmethod
    def _public(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = {
            name: row[name]
            for name in (
                "action_hash", "scope", "source_signer", "source_peer_id",
                "source_sequence", "snapshot_hash", "descriptor_hash",
                "provider_owner", "sender", "target", "calldata", "state",
                "nonce", "tx_hash", "created_at", "updated_at",
            )
        }
        result["action"] = json.loads(row["action_json"])
        if row["receipt_json"]:
            result["receipt"] = json.loads(row["receipt_json"])
        if row["result_json"]:
            result["result"] = json.loads(row["result_json"])
        return result

    def get(self, action_hash: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM provider_reputation_actions WHERE action_hash=?",
                (_hash(action_hash, "action hash"),),
            ).fetchone()
        return self._public(row)

    def _row(self, action_hash: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM provider_reputation_actions WHERE action_hash=?",
            (_hash(action_hash, "action hash"),),
        ).fetchone()
        if row is None:
            raise ProviderReputationSyncError("unknown reputation action")
        return row

    def propose(self, action: Mapping[str, Any]) -> dict[str, Any]:
        body = json.loads(_json(action))
        action_hash = _hash(body.get("action_hash"), "action hash")
        committed = {key: value for key, value in body.items() if key != "action_hash"}
        if evidence_hash(committed) != action_hash:
            raise ProviderReputationSyncError("reputation action hash is invalid")
        source = body.get("source")
        if not isinstance(source, Mapping):
            raise ProviderReputationSyncError("reputation action source is required")
        signer = str(source.get("pool_public_key") or "")
        peer_id = _text(source.get("peer_id"), "source peer id", maximum=160)
        sequence = _uint(source.get("sequence"), "source sequence", bits=63, positive=True)
        snapshot_hash = _hash(source.get("snapshot_hash"), "snapshot hash")
        _hash(source.get("source_digest"), "source digest")
        descriptor_hash = _hash(source.get("descriptor_hash"), "descriptor hash")
        observed_at = _uint(
            source.get("snapshot_observed_at"), "snapshot observed_at", bits=63,
        )
        descriptor_timestamp = _uint(
            source.get("descriptor_timestamp"), "descriptor timestamp", bits=63,
        )
        receipt_count = _uint(source.get("receipt_count"), "receipt count", bits=63)
        owner = _address(body.get("provider", {}).get("owner"), "Provider owner")
        now = int(time.time())
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                cursor = self.db.execute(
                    "SELECT * FROM provider_reputation_sources "
                    "WHERE source_signer=? AND provider_owner=?",
                    (signer, owner),
                ).fetchone()
                peer_binding = self.db.execute(
                    "SELECT provider_owner FROM provider_reputation_sources "
                    "WHERE source_signer=? AND source_peer_id=?",
                    (signer, peer_id),
                ).fetchone()
                if peer_binding is not None and peer_binding["provider_owner"] != owner:
                    raise ProviderReputationSyncError(
                        "Pool reputation peer is already bound to another Provider owner"
                    )
                if cursor is not None:
                    if cursor["source_peer_id"] != peer_id:
                        raise ProviderReputationSyncError(
                            "Provider owner cannot inherit another Pool peer's reputation"
                        )
                    if sequence < cursor["source_sequence"]:
                        raise ProviderReputationSyncError(
                            "stale Pool reputation snapshot sequence"
                        )
                    if sequence == cursor["source_sequence"] and (
                        cursor["snapshot_hash"] != snapshot_hash
                        or cursor["action_hash"] != action_hash
                    ):
                        raise ProviderReputationSyncError(
                            "Pool reputation snapshot sequence was equivocated or rebound"
                        )
                    if sequence > cursor["source_sequence"] and (
                        observed_at < cursor["source_observed_at"]
                        or descriptor_timestamp < cursor["descriptor_timestamp"]
                        or receipt_count < cursor["receipt_count"]
                    ):
                        raise ProviderReputationSyncError(
                            "newer Pool sequence regresses its authenticated evidence"
                        )
                    if sequence > cursor["source_sequence"]:
                        previous = self.db.execute(
                            "SELECT action_json FROM provider_reputation_actions "
                            "WHERE action_hash=?",
                            (cursor["action_hash"],),
                        ).fetchone()
                        if previous is None:
                            raise ProviderReputationSyncError(
                                "prior reputation source action is unavailable"
                            )
                        try:
                            previous_body = json.loads(previous["action_json"])
                        except (TypeError, ValueError, json.JSONDecodeError) as exc:
                            raise ProviderReputationSyncError(
                                "prior reputation source action is invalid"
                            ) from exc
                        if not _action_snapshot_event_ids(previous_body).issubset(
                            _action_snapshot_event_ids(body)
                        ):
                            raise ProviderReputationSyncError(
                                "newer Pool sequence removed authenticated terminal events"
                            )
                prior = self.db.execute(
                    "SELECT * FROM provider_reputation_actions WHERE action_hash=?",
                    (action_hash,),
                ).fetchone()
                if prior is not None:
                    if prior["action_json"] != _json(body):
                        raise ProviderReputationSyncError(
                            "saved reputation action identity changed"
                        )
                    self.db.commit()
                    result = self._public(prior)
                    assert result is not None
                    return result
                self.db.execute(
                    """INSERT INTO provider_reputation_actions(
                           action_hash,scope,source_signer,source_peer_id,
                           source_sequence,snapshot_hash,descriptor_hash,
                           provider_owner,sender,target,calldata,action_json,state,
                           created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        action_hash, body["scope"], signer, peer_id, sequence,
                        snapshot_hash, descriptor_hash, owner, body["sender"],
                        body["target"], body["calldata"], _json(body),
                        "proposed", now, now,
                    ),
                )
                self.db.execute(
                    """INSERT INTO provider_reputation_sources(
                           source_signer,provider_owner,source_peer_id,source_sequence,
                           source_observed_at,descriptor_timestamp,receipt_count,
                           snapshot_hash,action_hash)
                       VALUES (?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(source_signer,provider_owner) DO UPDATE SET
                           source_peer_id=excluded.source_peer_id,
                           source_sequence=excluded.source_sequence,
                           source_observed_at=excluded.source_observed_at,
                           descriptor_timestamp=excluded.descriptor_timestamp,
                           receipt_count=excluded.receipt_count,
                           snapshot_hash=excluded.snapshot_hash,
                           action_hash=excluded.action_hash""",
                    (
                        signer, owner, peer_id, sequence, observed_at,
                        descriptor_timestamp, receipt_count, snapshot_hash, action_hash,
                    ),
                )
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        result = self.get(action_hash)
        assert result is not None
        return result

    def recover_expired_leases(self, *, now: int | None = None) -> int:
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            safe = self.db.execute(
                "UPDATE provider_reputation_actions SET state='proposed',"
                "lease_id=NULL,lease_expires=NULL,updated_at=? "
                "WHERE state='executing' AND lease_expires<=? AND tx_hash IS NULL",
                (current, current),
            )
            uncertain = self.db.execute(
                "UPDATE provider_reputation_actions SET state='uncertain',"
                "lease_id=NULL,lease_expires=NULL,updated_at=? "
                "WHERE state='executing' AND lease_expires<=? AND tx_hash IS NOT NULL",
                (current, current),
            )
        return safe.rowcount + uncertain.rowcount

    def abort_not_sent(
        self, action_hash: str, *, lease_id: str, now: int | None = None,
    ) -> dict[str, Any]:
        """Release a lease only when no transaction identity was ever attached."""
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            changed = self.db.execute(
                "UPDATE provider_reputation_actions SET state='proposed',"
                "lease_id=NULL,lease_expires=NULL,updated_at=? "
                "WHERE action_hash=? AND state='executing' AND lease_id=? "
                "AND tx_hash IS NULL AND raw_tx IS NULL",
                (current, _hash(action_hash, "action hash"), lease_id),
            )
            if changed.rowcount != 1:
                raise ProviderReputationSyncError(
                    "cannot prove the reputation transaction was not sent"
                )
        result = self.get(action_hash)
        assert result is not None
        return result

    def begin_execution(
        self, action_hash: str, *, lease_seconds: int, now: int | None = None,
    ) -> tuple[dict[str, Any], str]:
        current = int(time.time()) if now is None else int(now)
        lease = secrets.token_hex(16)
        with self._lock:
            # Commit lease recovery as its own durable transition.  If the
            # requested row already acquired a transaction identity, the
            # eligibility error below must not roll its uncertain state back
            # to a permanently executing row.
            self.db.execute("BEGIN IMMEDIATE")
            try:
                # Expiring a lease is not itself evidence that a transaction
                # exists.  Preserve the same crash-boundary distinction used
                # by startup recovery: before durable tx attachment it is safe
                # to reacquire; afterwards the outcome is uncertain forever
                # until receipt reconciliation proves it.
                self.db.execute(
                    "UPDATE provider_reputation_actions SET state='proposed',"
                    "lease_id=NULL,lease_expires=NULL,updated_at=? "
                    "WHERE state='executing' AND lease_expires<=? "
                    "AND tx_hash IS NULL AND raw_tx IS NULL",
                    (current, current),
                )
                self.db.execute(
                    "UPDATE provider_reputation_actions SET state='uncertain',"
                    "lease_id=NULL,lease_expires=NULL,updated_at=? "
                    "WHERE state='executing' AND lease_expires<=? "
                    "AND (tx_hash IS NOT NULL OR raw_tx IS NOT NULL)",
                    (current, current),
                )
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(action_hash)
                if row["state"] != "proposed":
                    raise ProviderReputationSyncError(
                        "reputation action is not eligible for first execution"
                    )
                cursor = self.db.execute(
                    "SELECT action_hash FROM provider_reputation_sources "
                    "WHERE source_signer=? AND provider_owner=?",
                    (row["source_signer"], row["provider_owner"]),
                ).fetchone()
                if cursor is None or cursor["action_hash"] != row["action_hash"]:
                    raise ProviderReputationSyncError(
                        "reputation action was superseded by a newer signed snapshot"
                    )
                blocked = self.db.execute(
                    "SELECT action_hash FROM provider_reputation_actions "
                    "WHERE scope=? AND sender=? "
                    "AND state IN ('executing','submitted','uncertain') LIMIT 1",
                    (row["scope"], row["sender"]),
                ).fetchone()
                if blocked is not None:
                    raise ProviderReputationSyncError(
                        "dedicated reputation authority has an unresolved action"
                    )
                changed = self.db.execute(
                    "UPDATE provider_reputation_actions SET state='executing',"
                    "lease_id=?,lease_expires=?,updated_at=? "
                    "WHERE action_hash=? AND state='proposed'",
                    (lease, current + lease_seconds, current, row["action_hash"]),
                )
                if changed.rowcount != 1:
                    raise ProviderReputationSyncError(
                        "reputation execution lease was acquired concurrently"
                    )
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        result = self.get(action_hash)
        assert result is not None
        return result, lease

    def attach_transaction(
        self,
        action_hash: str,
        *,
        lease_id: str,
        nonce: int,
        raw_tx: bytes,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = int(time.time()) if now is None else int(now)
        tx_hash = "0x" + chain.keccak256(raw_tx).hex()
        raw_hex = "0x" + raw_tx.hex()
        with self._lock:
            try:
                changed = self.db.execute(
                    "UPDATE provider_reputation_actions SET nonce=?,tx_hash=?,raw_tx=?,"
                    "updated_at=? WHERE action_hash=? AND state='executing' "
                    "AND lease_id=? AND nonce IS NULL AND tx_hash IS NULL",
                    (
                        _uint(nonce, "transaction nonce", bits=64), tx_hash,
                        raw_hex, current, _hash(action_hash, "action hash"), lease_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ProviderReputationSyncError(
                    "dedicated reputation authority nonce is already reserved"
                ) from exc
            if changed.rowcount != 1:
                raise ProviderReputationSyncError(
                    "reputation transaction lease or identity changed"
                )
        result = self.get(action_hash)
        assert result is not None
        return result

    def mark_submitted(
        self, action_hash: str, *, lease_id: str, now: int | None = None,
    ) -> dict[str, Any]:
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            changed = self.db.execute(
                "UPDATE provider_reputation_actions SET state='submitted',"
                "lease_id=NULL,lease_expires=NULL,updated_at=? "
                "WHERE action_hash=? AND state='executing' AND lease_id=? "
                "AND tx_hash IS NOT NULL",
                (current, _hash(action_hash, "action hash"), lease_id),
            )
            if changed.rowcount != 1:
                raise ProviderReputationSyncError(
                    "reputation transaction is not in its original execution lease"
                )
        result = self.get(action_hash)
        assert result is not None
        return result

    def mark_uncertain(
        self,
        action_hash: str,
        *,
        receipt: Mapping[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            changed = self.db.execute(
                "UPDATE provider_reputation_actions SET state='uncertain',"
                "lease_id=NULL,lease_expires=NULL,receipt_json=?,result_json=NULL,updated_at=? "
                "WHERE action_hash=? AND state IN ('executing','submitted','uncertain','confirmed')",
                (
                    _json(receipt) if receipt is not None else None,
                    current, _hash(action_hash, "action hash"),
                ),
            )
            if changed.rowcount != 1:
                raise ProviderReputationSyncError("reputation action cannot become uncertain")
        result = self.get(action_hash)
        assert result is not None
        return result

    def mark_observed_submitted(
        self,
        action_hash: str,
        *,
        receipt: Mapping[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            changed = self.db.execute(
                "UPDATE provider_reputation_actions SET state='submitted',"
                "receipt_json=?,result_json=NULL,updated_at=? WHERE action_hash=? "
                "AND state IN ('submitted','uncertain','confirmed') AND tx_hash IS NOT NULL",
                (
                    _json(receipt) if receipt is not None else None,
                    current, _hash(action_hash, "action hash"),
                ),
            )
            if changed.rowcount != 1:
                raise ProviderReputationSyncError(
                    "reputation action has no reconcilable transaction"
                )
        result = self.get(action_hash)
        assert result is not None
        return result

    def mark_confirmed(
        self,
        action_hash: str,
        *,
        receipt: Mapping[str, Any],
        result: Mapping[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            changed = self.db.execute(
                "UPDATE provider_reputation_actions SET state='confirmed',"
                "receipt_json=?,result_json=?,updated_at=? WHERE action_hash=? "
                "AND state IN ('submitted','uncertain','confirmed') AND tx_hash IS NOT NULL",
                (
                    _json(receipt), _json(result), current,
                    _hash(action_hash, "action hash"),
                ),
            )
            if changed.rowcount != 1:
                raise ProviderReputationSyncError(
                    "reputation action cannot be confirmed from its current state"
                )
        saved = self.get(action_hash)
        assert saved is not None
        return saved

    def mark_reverted(
        self,
        action_hash: str,
        *,
        receipt: Mapping[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        """Record a canonical revert as terminal for this exact transaction.

        A mined revert proves the nonce was consumed and these bytes must never
        be resent.  Unlike an ambiguous transaction it must not permanently
        fence later, independently signed reputation snapshots.
        """
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            changed = self.db.execute(
                "UPDATE provider_reputation_actions SET state='reverted',"
                "lease_id=NULL,lease_expires=NULL,receipt_json=?,result_json=NULL,updated_at=? "
                "WHERE action_hash=? AND state IN ('submitted','uncertain','confirmed') "
                "AND tx_hash IS NOT NULL",
                (
                    _json(receipt), current,
                    _hash(action_hash, "action hash"),
                ),
            )
            if changed.rowcount != 1:
                raise ProviderReputationSyncError(
                    "reputation action cannot be marked reverted"
                )
        saved = self.get(action_hash)
        assert saved is not None
        return saved

    def raw_transaction(self, action_hash: str) -> str:
        with self._lock:
            row = self._row(action_hash)
            raw = row["raw_tx"]
        if not raw:
            raise ProviderReputationSyncError(
                "reputation action has no durable transaction identity"
            )
        return str(raw)


class ProviderReputationSync:
    """Validate Pool evidence and synchronize one mutable Registry candidate."""

    def __init__(
        self,
        config: ProviderReputationSyncConfig,
        *,
        outbox_path: str | os.PathLike[str],
        sender: str,
        execution_enabled: bool = False,
        dedicated_sender: bool = False,
        key_file: str | os.PathLike[str] | None = None,
        max_gas_price_wei: int | None = None,
        max_gas_units: int | None = None,
        max_total_gas_cost_wei: int | None = None,
        lease_seconds: int = 60,
        rpc: RPC | None = None,
        endpoint_rpc: EndpointRPC | None = None,
        transaction_signer: TransactionSigner | None = None,
        key_loader: KeyLoader | None = None,
        event_verifier_factory: EventVerifierFactory | None = None,
    ) -> None:
        if not isinstance(config, ProviderReputationSyncConfig):
            raise ProviderReputationSyncError("validated reputation sync config is required")
        if type(execution_enabled) is not bool or type(dedicated_sender) is not bool:
            raise ProviderReputationSyncError("reputation execution flags must be explicit")
        self.config = config
        self.sender = _address(sender, "reputation authority sender")
        self.execution_enabled = execution_enabled
        self.dedicated_sender = dedicated_sender
        self.key_file = Path(key_file) if key_file is not None else None
        self.max_gas_price_wei = max_gas_price_wei
        self.max_gas_units = max_gas_units
        self.max_total_gas_cost_wei = max_total_gas_cost_wei
        self.lease_seconds = _uint(lease_seconds, "execution lease", bits=32, positive=True)
        if self.lease_seconds > 3600:
            raise ProviderReputationSyncError("execution lease is too long")
        self._rpc_override = rpc
        self._endpoint_rpc_override = endpoint_rpc
        if endpoint_rpc is not None and not callable(endpoint_rpc):
            raise ProviderReputationSyncError(
                "endpoint RPC override must be callable"
            )
        self._transaction_signer = transaction_signer or chain.sign_legacy_transaction
        self._key_loader = key_loader or _protected_key
        self._event_verifier_factory = event_verifier_factory or (
            lambda verifier_config, rpc_call: V10ReputationEventVerifier(
                verifier_config, rpc=rpc_call,
            )
        )
        if not callable(self._event_verifier_factory):
            raise ProviderReputationSyncError(
                "reputation event verifier factory must be callable"
            )
        self._history_completeness_cache: set[tuple[str, int, str]] = set()
        self._live_completeness_cache: dict[
            tuple[str, int, str], dict[str, frozenset[str]]
        ] = {}
        self.outbox = ProviderReputationOutbox(outbox_path)
        if execution_enabled:
            if not dedicated_sender or self.key_file is None:
                raise ProviderReputationSyncError(
                    "execution requires an explicitly dedicated authority and key file"
                )
            if not callable(self._transaction_signer) or not callable(self._key_loader):
                raise ProviderReputationSyncError(
                    "transaction signer and key loader must be callable"
                )
            for value, label in (
                (max_gas_price_wei, "gas price cap"),
                (max_gas_units, "gas unit cap"),
                (max_total_gas_cost_wei, "total gas cost cap"),
            ):
                _uint(value, label, positive=True)

    def close(self) -> None:
        self.outbox.close()

    @property
    def scope(self) -> str:
        return f"{self.config.genesis_hash}:{self.config.chain_id}"

    def _rpc(self, method: str, params: list[Any]) -> Any:
        responses: list[Any] = []
        failures: list[str] = []
        for endpoint in self.config.rpc_urls:
            try:
                responses.append(self._rpc_for_url(endpoint)(method, params))
            except Exception as exc:
                if method == "eth_sendRawTransaction":
                    failures.append(f"{endpoint}: {exc}")
                    continue
                raise ProviderReputationSyncError(
                    f"pinned RPC endpoint failed {method}: {exc}"
                ) from exc
        if method == "eth_blockNumber":
            return hex(min(
                _hex_uint(value, "chain head") for value in responses
            ))
        if method in {"eth_gasPrice", "eth_estimateGas"}:
            return hex(max(
                _hex_uint(value, method) for value in responses
            ))
        if method == "eth_sendRawTransaction":
            if failures:
                raise ProviderReputationSyncError(
                    "one or more pinned RPC broadcasts failed: "
                    + "; ".join(failures)
                )
            hashes = [_hash(value, "broadcast transaction hash") for value in responses]
            if any(value != hashes[0] for value in hashes[1:]):
                raise ProviderReputationSyncError(
                    "pinned RPC endpoints returned different transaction hashes"
                )
            return hashes[0]
        if method == "eth_getBlockByNumber":
            projections: list[dict[str, Any] | None] = []
            for value in responses:
                if value is None:
                    projections.append(None)
                    continue
                if not isinstance(value, Mapping):
                    raise ProviderReputationSyncError(
                        "pinned RPC returned a malformed block"
                    )
                projection = {
                    "number": _hex_uint(value.get("number"), "block number"),
                    "hash": _hash(value.get("hash"), "block hash"),
                }
                if "timestamp" in value:
                    projection["timestamp"] = _hex_uint(
                        value.get("timestamp"), "block timestamp",
                    )
                projections.append(projection)
            if any(value != projections[0] for value in projections[1:]):
                raise ProviderReputationSyncError(
                    "pinned RPC endpoints disagree on canonical block state"
                )
            return responses[0]
        encoded = [_json(value) for value in responses]
        if any(value != encoded[0] for value in encoded[1:]):
            raise ProviderReputationSyncError(
                f"pinned RPC endpoints disagree on {method}"
            )
        return responses[0]

    def _rpc_for_url(self, rpc_url: str) -> RPC:
        if self._endpoint_rpc_override is not None:
            return lambda method, params: self._endpoint_rpc_override(
                rpc_url, method, params,
            )
        if self._rpc_override is not None:
            return self._rpc_override
        return lambda method, params: chain.rpc_call(
            rpc_url, method, params, self.config.timeout_seconds,
        )

    def _all_rpc_block_hash(self, *, number: int, label: str) -> str:
        hashes: list[str] = []
        for endpoint in self.config.rpc_urls:
            value = self._rpc_for_url(endpoint)(
                "eth_getBlockByNumber", [hex(number), False],
            )
            if (
                not isinstance(value, Mapping)
                or _hex_uint(value.get("number"), f"{label} number") != number
            ):
                raise ProviderReputationSyncError(
                    f"reputation RPC returned an invalid {label}"
                )
            hashes.append(_hash(value.get("hash"), f"{label} hash"))
        if any(value != hashes[0] for value in hashes[1:]):
            raise ProviderReputationSyncError(
                f"pinned reputation RPC endpoints disagree on {label}"
            )
        return hashes[0]

    def _final_confirmation_fence(
        self, *, safe_end: int, confirmations: int, label: str,
    ) -> None:
        heads = [
            _hex_uint(
                self._rpc_for_url(endpoint)("eth_blockNumber", []),
                f"final {label} chain head",
            )
            for endpoint in self.config.rpc_urls
        ]
        if (
            max(heads) - min(heads) > 2
            or min(heads) - confirmations + 1 < safe_end
        ):
            raise ProviderReputationSyncError(
                f"{label} lost its confirmation-safe boundary during verification"
            )

    def _verify_history_import_completeness(self) -> None:
        """Prove the one-time import contains every canonical terminal log."""
        history = self.config.history_import
        if history is None:
            return
        heads: list[int] = []
        for endpoint in self.config.rpc_urls:
            rpc = self._rpc_for_url(endpoint)
            chain_id = _hex_uint(rpc("eth_chainId", []), "history chain id")
            genesis = rpc("eth_getBlockByNumber", ["0x0", False])
            if (
                chain_id != history.source_chain_id
                or not isinstance(genesis, Mapping)
                or _hash(genesis.get("hash"), "history genesis hash")
                != history.source_genesis_hash
            ):
                raise ProviderReputationSyncError(
                    "history RPC chain or genesis differs from its pin"
                )
            heads.append(_hex_uint(rpc("eth_blockNumber", []), "history chain head"))
        if max(heads) - min(heads) > 2:
            raise ProviderReputationSyncError(
                "pinned history RPC heads are too far apart"
            )
        safe_end = min(heads) - history.confirmations + 1
        if safe_end < history.source_history_through_block:
            raise ProviderReputationSyncError(
                "history RPC has fallen behind the release-pinned cutoff"
            )
        deployment_hash = self._all_rpc_block_hash(
            number=history.source_deployment_block,
            label="source deployment block",
        )
        through_hash = self._all_rpc_block_hash(
            number=history.source_history_through_block,
            label="release history cutoff block",
        )
        if (
            deployment_hash != history.source_deployment_block_hash
            or through_hash != history.source_history_through_block_hash
        ):
            raise ProviderReputationSyncError(
                "history import boundary block differs from its release pin"
            )
        current_boundary_hash = self._all_rpc_block_hash(
            number=safe_end, label="current safe history block",
        )
        cache_key = (history.artifact_root, safe_end, current_boundary_hash)
        if cache_key in self._history_completeness_cache:
            return
        previous_hash = self._all_rpc_block_hash(
            number=history.source_deployment_block - 1,
            label="pre-deployment block",
        )
        for endpoint in self.config.rpc_urls:
            rpc = self._rpc_for_url(endpoint)
            code_value = rpc(
                "eth_getCode",
                [history.source_settlement_contract, {
                    "blockHash": deployment_hash, "requireCanonical": True,
                }],
            )
            previous_value = rpc(
                "eth_getCode",
                [history.source_settlement_contract, {
                    "blockHash": previous_hash, "requireCanonical": True,
                }],
            )
            code = _raw_result(code_value, "history settlement runtime code")
            previous_code = _raw_result(
                previous_value, "pre-deployment settlement runtime code",
            )
            if (
                not code
                or "0x" + chain.keccak256(code).hex()
                != history.source_runtime_code_hash
                or previous_code
            ):
                raise ProviderReputationSyncError(
                    "history deployment boundary or runtime code differs from its pin"
                )
        topics = [
            SETTLEMENT_RELEASED_TOPIC,
            V9_DISPUTE_RESOLVED_TOPIC
            if history.source_protocol_version == 9
            else DISPUTE_RESOLVED_TOPIC,
        ]
        endpoint_references: list[list[dict[str, Any]]] = []
        for endpoint in self.config.rpc_urls:
            rpc = self._rpc_for_url(endpoint)
            references: list[dict[str, Any]] = []
            for start in range(history.source_deployment_block, safe_end + 1, 1_000):
                end = min(safe_end, start + 999)
                raw_logs = rpc("eth_getLogs", [{
                    "address": history.source_settlement_contract,
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [topics],
                }])
                if not isinstance(raw_logs, list):
                    raise ProviderReputationSyncError(
                        "history RPC returned malformed terminal logs"
                    )
                for raw_log in raw_logs:
                    try:
                        reference = canonical_terminal_log_reference(
                            raw_log,
                            chain_id=history.source_chain_id,
                            protocol_version=history.source_protocol_version,
                            settlement_contract=history.source_settlement_contract,
                        )
                    except V10ReputationError as exc:
                        raise ProviderReputationSyncError(
                            f"history RPC returned an invalid terminal log: {exc}"
                        ) from exc
                    if reference is not None:
                        references.append(reference)
            references.sort(key=lambda item: item["event_id"])
            if len({item["event_id"] for item in references}) != len(references):
                raise ProviderReputationSyncError(
                    "history RPC returned duplicate canonical terminal logs"
                )
            endpoint_references.append(references)
        if any(
            candidate != endpoint_references[0]
            for candidate in endpoint_references[1:]
        ):
            raise ProviderReputationSyncError(
                "pinned history RPC endpoints disagree on canonical terminal logs"
            )
        expected_ids = {
            reputation_event_id(event)
            for events in history.entries.values()
            for event in events
        }
        observed_ids = {
            item["event_id"] for item in endpoint_references[0]
        }
        if observed_ids != expected_ids:
            raise ProviderReputationSyncError(
                "history import omits or invents canonical terminal events"
            )
        if self._all_rpc_block_hash(
            number=safe_end, label="current safe history block",
        ) != current_boundary_hash:
            raise ProviderReputationSyncError(
                "history source reorganized during completeness verification"
            )
        self._final_confirmation_fence(
            safe_end=safe_end,
            confirmations=history.confirmations,
            label="history source",
        )
        self._history_completeness_cache.add(cache_key)

    def _live_settlement_identity(
        self,
        rpc: RPC,
        reference: Mapping[str, Any],
    ) -> dict[str, Any]:
        settlement_key = _hash(
            reference["topics"][1], "terminal settlement key",
        )
        raw = _raw_result(
            rpc(
                "eth_call",
                [{
                    "to": self.config.settlement_contract,
                    "data": chain.encode_contract_call(
                        "settlementInfo(bytes32)", [settlement_key],
                    ),
                }, {
                    "blockHash": reference["block_hash"],
                    "requireCanonical": True,
                }],
            ),
            "live settlementInfo",
        )
        if len(raw) != 20 * 32:
            raise ProviderReputationSyncError(
                "live settlementInfo returned the wrong ABI length"
            )
        words = [raw[index:index + 32] for index in range(0, len(raw), 32)]
        status = _word_uint(words[19], "live settlement status", bits=8)
        if status != reference["terminal_status_code"]:
            raise ProviderReputationSyncError(
                "live terminal log differs from canonical settlement state"
            )
        return {
            "settlement_key": settlement_key,
            "provider_owner": _word_address(
                words[2], "live settlement Provider owner",
            ),
            "provider_signer": _word_address(
                words[3], "live settlement Provider signer",
            ),
            "request_id": _hash(
                "0x" + words[8].hex(), "live settlement request id",
            ),
        }

    def _verify_live_reputation_completeness(
        self,
        descriptor: Mapping[str, Any],
    ) -> frozenset[str]:
        """Prove the snapshot includes every terminal event for this signer.

        Pool signatures authenticate transport but cannot choose the first
        event set admitted for a Provider.  Every pinned RPC is therefore
        rescanned from the target Settlement's exact deployment boundary to
        the current confirmation-safe head.  ``settlementInfo`` maps each
        canonical positive, negative, or neutral terminal log to its actual
        Provider signer before the snapshot is compared.
        """
        vote_signer = _address(
            descriptor.get("vote_signer"), "live Provider vote signer",
        )
        heads: list[int] = []
        for endpoint in self.config.rpc_urls:
            rpc = self._rpc_for_url(endpoint)
            chain_id = _hex_uint(rpc("eth_chainId", []), "live chain id")
            genesis = rpc("eth_getBlockByNumber", ["0x0", False])
            if (
                chain_id != self.config.chain_id
                or not isinstance(genesis, Mapping)
                or _hash(genesis.get("hash"), "live genesis hash")
                != self.config.genesis_hash
            ):
                raise ProviderReputationSyncError(
                    "live reputation RPC chain or genesis differs from its pin"
                )
            heads.append(_hex_uint(rpc("eth_blockNumber", []), "live chain head"))
        if max(heads) - min(heads) > 2:
            raise ProviderReputationSyncError(
                "pinned live reputation RPC heads are too far apart"
            )
        safe_end = min(heads) - self.config.confirmations + 1
        if safe_end < self.config.settlement_deployment_block:
            raise ProviderReputationSyncError(
                "target Settlement deployment has insufficient confirmations"
            )
        deployment_hash = self._all_rpc_block_hash(
            number=self.config.settlement_deployment_block,
            label="target Settlement deployment block",
        )
        if deployment_hash != self.config.settlement_deployment_block_hash:
            raise ProviderReputationSyncError(
                "target Settlement deployment block differs from its release pin"
            )
        boundary_hash = self._all_rpc_block_hash(
            number=safe_end, label="current safe target Settlement block",
        )
        cache_key = (
            self.config.settlement_contract, safe_end, boundary_hash,
        )
        cached = self._live_completeness_cache.get(cache_key)
        if cached is not None:
            return cached.get(vote_signer, frozenset())

        previous_hash = self._all_rpc_block_hash(
            number=self.config.settlement_deployment_block - 1,
            label="pre-target-Settlement-deployment block",
        )
        for endpoint in self.config.rpc_urls:
            rpc = self._rpc_for_url(endpoint)
            code = _raw_result(
                rpc("eth_getCode", [self.config.settlement_contract, {
                    "blockHash": deployment_hash, "requireCanonical": True,
                }]),
                "target Settlement runtime code",
            )
            previous_code = _raw_result(
                rpc("eth_getCode", [self.config.settlement_contract, {
                    "blockHash": previous_hash, "requireCanonical": True,
                }]),
                "pre-deployment target Settlement runtime code",
            )
            if (
                not code
                or "0x" + chain.keccak256(code).hex()
                != self.config.settlement_runtime_code_hash
                or previous_code
            ):
                raise ProviderReputationSyncError(
                    "target Settlement deployment boundary or runtime code differs from its pin"
                )

        endpoint_references: list[list[dict[str, Any]]] = []
        topics = [SETTLEMENT_RELEASED_TOPIC, DISPUTE_RESOLVED_TOPIC]
        for endpoint in self.config.rpc_urls:
            rpc = self._rpc_for_url(endpoint)
            references: list[dict[str, Any]] = []
            for start in range(
                self.config.settlement_deployment_block, safe_end + 1, 1_000,
            ):
                end = min(safe_end, start + 999)
                raw_logs = rpc("eth_getLogs", [{
                    "address": self.config.settlement_contract,
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [topics],
                }])
                if not isinstance(raw_logs, list):
                    raise ProviderReputationSyncError(
                        "live reputation RPC returned malformed terminal logs"
                    )
                for raw_log in raw_logs:
                    try:
                        reference = canonical_terminal_log_reference(
                            raw_log,
                            chain_id=self.config.chain_id,
                            protocol_version=10,
                            settlement_contract=self.config.settlement_contract,
                        )
                    except V10ReputationError as exc:
                        raise ProviderReputationSyncError(
                            f"live reputation RPC returned an invalid terminal log: {exc}"
                        ) from exc
                    if reference is None:
                        continue
                    if not start <= reference["block_number"] <= end:
                        raise ProviderReputationSyncError(
                            "live reputation RPC returned a log outside the requested range"
                        )
                    references.append({
                        **reference,
                        **self._live_settlement_identity(rpc, reference),
                    })
            references.sort(key=lambda item: item["event_id"])
            if len({item["event_id"] for item in references}) != len(references):
                raise ProviderReputationSyncError(
                    "live reputation RPC returned duplicate canonical terminal logs"
                )
            endpoint_references.append(references)
        if any(
            candidate != endpoint_references[0]
            for candidate in endpoint_references[1:]
        ):
            raise ProviderReputationSyncError(
                "pinned live reputation RPC endpoints disagree on canonical terminal logs"
            )
        if self._all_rpc_block_hash(
            number=safe_end, label="current safe target Settlement block",
        ) != boundary_hash:
            raise ProviderReputationSyncError(
                "target Settlement reorganized during completeness verification"
            )
        self._final_confirmation_fence(
            safe_end=safe_end,
            confirmations=self.config.confirmations,
            label="target Settlement",
        )
        grouped: dict[str, set[str]] = {}
        for reference in endpoint_references[0]:
            grouped.setdefault(reference["provider_signer"], set()).add(
                reference["event_id"],
            )
        frozen = {
            signer: frozenset(event_ids)
            for signer, event_ids in grouped.items()
        }
        self._live_completeness_cache.clear()
        self._live_completeness_cache[cache_key] = frozen
        return frozen.get(vote_signer, frozenset())

    def _verify_snapshot_event_proofs(
        self,
        snapshot: Mapping[str, Any],
        descriptor: Mapping[str, Any],
    ) -> None:
        """Re-derive every score input from canonical chain state.

        A Pool signature is transport authentication only.  It is never an
        authority to mint counters or an event root.
        """
        events = snapshot.get("events")
        if not isinstance(events, list) or not events:
            raise ProviderReputationSyncError(
                "reputation snapshot has no terminal-event proofs"
            )
        history = self.config.history_import
        self._verify_history_import_completeness()
        expected_live = self._verify_live_reputation_completeness(descriptor)
        peer_id = str(descriptor["peer_id"])
        expected_imports: dict[str, Mapping[str, Any]] = {}
        if history is not None:
            expected_imports = {
                reputation_event_id(event): event
                for event in history.entries.get(peer_id, ())
            }
        observed_imports: set[str] = set()
        observed_live: set[str] = set()
        verifiers: dict[tuple[str, str], V10ReputationEventVerifier] = {}
        for raw_event in events:
            try:
                event = normalize_feedback_document(raw_event)
                event_id = reputation_event_id(event)
            except V10ReputationError as exc:
                raise ProviderReputationSyncError(
                    "reputation snapshot contains an invalid event proof"
                ) from exc
            source_contract = event["settlement_contract"]
            if source_contract == self.config.settlement_contract:
                observed_live.add(event_id)
                source = {
                    "network_id": self.config.network_id,
                    "chain_id": self.config.chain_id,
                    "genesis_hash": self.config.genesis_hash,
                    "settlement_contract": self.config.settlement_contract,
                    "confirmations": self.config.confirmations,
                    "runtime_code_hash": self.config.settlement_runtime_code_hash,
                    "protocol_version": 10,
                    "rpc_urls": self.config.rpc_urls,
                }
            elif history is not None and source_contract == history.source_settlement_contract:
                if event_id not in expected_imports or dict(expected_imports[event_id]) != event:
                    raise ProviderReputationSyncError(
                        "historical reputation event is absent from the pinned import artifact"
                    )
                observed_imports.add(event_id)
                source = {
                    "network_id": history.source_network_id,
                    "chain_id": history.source_chain_id,
                    "genesis_hash": history.source_genesis_hash,
                    "settlement_contract": history.source_settlement_contract,
                    "confirmations": history.confirmations,
                    "runtime_code_hash": history.source_runtime_code_hash,
                    "protocol_version": history.source_protocol_version,
                    "rpc_urls": self.config.rpc_urls,
                }
            else:
                raise ProviderReputationSyncError(
                    "reputation event targets an unpinned settlement deployment"
                )
            source_peer = {
                "peer_id": peer_id,
                "network_id": source["network_id"],
                "payment_address": descriptor["owner"],
                "settlement": {
                    "version": source["protocol_version"],
                    "chain_id": source["chain_id"],
                    "contract": source["settlement_contract"],
                    "provider_signer": descriptor["vote_signer"],
                },
            }
            verified_results: list[Mapping[str, Any]] = []
            for endpoint in source["rpc_urls"]:
                verifier_key = (source_contract, str(endpoint))
                verifier = verifiers.get(verifier_key)
                if verifier is None:
                    verifier_config = V10ReputationVerifierConfig(
                        network_id=str(source["network_id"]),
                        rpc_url=str(endpoint),
                        chain_id=int(source["chain_id"]),
                        genesis_hash=str(source["genesis_hash"]),
                        settlement_contract=str(source["settlement_contract"]),
                        confirmations=int(source["confirmations"]),
                        timeout_seconds=self.config.timeout_seconds,
                        runtime_code_hash=(
                            str(source["runtime_code_hash"])
                            if source["runtime_code_hash"] is not None else None
                        ),
                        protocol_version=int(source["protocol_version"]),
                        require_provider_owner_match=(
                            source_contract == self.config.settlement_contract
                        ),
                    )
                    verifier = self._event_verifier_factory(
                        verifier_config, self._rpc_for_url(str(endpoint)),
                    )
                    if not isinstance(verifier, V10ReputationEventVerifier) and not callable(
                        getattr(verifier, "verify", None)
                    ):
                        raise ProviderReputationSyncError(
                            "reputation event verifier factory returned an invalid verifier"
                        )
                    verifiers[verifier_key] = verifier
                try:
                    verified = verifier.verify(event, peer=source_peer)
                except V10ReputationError as exc:
                    raise ProviderReputationSyncError(
                        f"terminal-event reputation proof is not canonical: {exc}"
                    ) from exc
                if (
                    not isinstance(verified, Mapping)
                    or verified.get("event_id") != event_id
                    or verified.get("outcome") != event["outcome"]
                    or any(verified.get(name) != event[name] for name in FEEDBACK_FIELDS)
                ):
                    raise ProviderReputationSyncError(
                        "terminal-event reputation verifier changed the proof identity"
                    )
                verified_results.append(verified)
            if len(verified_results) > 1 and any(
                dict(item) != dict(verified_results[0])
                for item in verified_results[1:]
            ):
                raise ProviderReputationSyncError(
                    "pinned reputation RPC endpoints disagree on terminal state"
                )
        if observed_imports != set(expected_imports):
            raise ProviderReputationSyncError(
                "snapshot omitted events from its pinned historical import entry"
            )
        if observed_live != expected_live:
            raise ProviderReputationSyncError(
                "snapshot omits or invents canonical live terminal events for its Provider signer"
            )

    def _call(
        self,
        signature: str,
        args: list[str],
        tag: Any,
        *,
        sender: str | None = None,
        target: str | None = None,
    ) -> bytes:
        transaction = {
            "to": target or self.config.jury_registry,
            "data": chain.encode_contract_call(signature, args),
        }
        if sender is not None:
            transaction["from"] = sender
        return _raw_result(self._rpc("eth_call", [transaction, tag]), signature)

    def _call_words(
        self, signature: str, args: list[str], count: int, tag: Any,
        *, target: str | None = None,
    ) -> list[bytes]:
        raw = self._call(signature, args, tag, target=target)
        if len(raw) != count * 32:
            raise ProviderReputationSyncError(
                f"{signature} returned the wrong ABI length"
            )
        return [raw[index * 32:(index + 1) * 32] for index in range(count)]

    def _chain_identity(self) -> None:
        if _hex_uint(self._rpc("eth_chainId", []), "chain id") != self.config.chain_id:
            raise ProviderReputationSyncError("RPC chain differs from the Registry deployment")
        genesis = self._rpc("eth_getBlockByNumber", ["0x0", False])
        if (
            not isinstance(genesis, Mapping)
            or _hash(str(genesis.get("hash") or ""), "genesis hash")
            != self.config.genesis_hash
        ):
            raise ProviderReputationSyncError(
                "RPC genesis differs from the Registry deployment"
            )

    def _require_registry_code(self, tag: Any) -> None:
        code = _raw_result(
            self._rpc("eth_getCode", [self.config.jury_registry, tag]),
            "Registry code",
        )
        if (
            not code
            or "0x" + chain.keccak256(code).hex()
            != self.config.registry_runtime_code_hash
        ):
            raise ProviderReputationSyncError(
                "Registry runtime differs from the release pin"
            )

    def confirmed_context(self) -> dict[str, Any]:
        self._chain_identity()
        head = _hex_uint(self._rpc("eth_blockNumber", []), "head block")
        number = head - self.config.confirmations + 1
        if number < 0:
            raise ProviderReputationSyncError(
                "chain has insufficient reputation-sync confirmations"
            )
        block = self._rpc("eth_getBlockByNumber", [hex(number), False])
        if not isinstance(block, Mapping):
            raise ProviderReputationSyncError("confirmed Registry block is unavailable")
        block_hash = _hash(str(block.get("hash") or ""), "confirmed block hash")
        if _hex_uint(block.get("number"), "confirmed block number") != number:
            raise ProviderReputationSyncError("RPC returned the wrong confirmed block")
        timestamp = _hex_uint(block.get("timestamp"), "confirmed block timestamp", bits=64)
        if not -30 <= int(time.time()) - timestamp <= self.config.max_snapshot_age_seconds:
            raise ProviderReputationSyncError("confirmed Registry snapshot is stale or future")
        tag = {"blockHash": block_hash, "requireCanonical": True}
        self._require_registry_code(tag)
        registry_settlement = _word_address(
            self._call_words("settlement()", [], 1, tag)[0],
            "Registry settlement",
        )
        settlement_registry = _word_address(
            self._call_words(
                "juryRegistry()", [], 1, tag,
                target=self.config.settlement_contract,
            )[0],
            "Settlement jury Registry",
        )
        if (
            registry_settlement != self.config.settlement_contract
            or settlement_registry != self.config.jury_registry
        ):
            raise ProviderReputationSyncError(
                "Registry and Settlement are not bound to each other"
            )
        authority = _word_address(
            self._call_words("reputationAuthority()", [], 1, tag)[0],
            "reputation authority",
        )
        minimum = _word_uint(
            self._call_words("minimumReputation()", [], 1, tag)[0],
            "minimum reputation", bits=64,
        )
        pending = _word_uint(
            self._call_words("pendingAssignments()", [], 1, tag)[0],
            "pending assignments",
        )
        if authority != self.sender:
            raise ProviderReputationSyncError(
                "configured sender is not the Registry reputationAuthority"
            )
        if minimum != self.config.minimum_reputation:
            raise ProviderReputationSyncError(
                "Registry minimum reputation differs from the deployment pin"
            )
        if pending != 0:
            raise ProviderReputationSyncError(
                "Registry updates are paused while jury assignments are pending"
            )
        latest_authority = _word_address(
            self._call_words("reputationAuthority()", [], 1, "latest")[0],
            "latest reputation authority",
        )
        latest_pending = _word_uint(
            self._call_words("pendingAssignments()", [], 1, "latest")[0],
            "latest pending assignments",
        )
        latest_registry_settlement = _word_address(
            self._call_words("settlement()", [], 1, "latest")[0],
            "latest Registry settlement",
        )
        latest_settlement_registry = _word_address(
            self._call_words(
                "juryRegistry()", [], 1, "latest",
                target=self.config.settlement_contract,
            )[0],
            "latest Settlement jury Registry",
        )
        if latest_authority != self.sender:
            raise ProviderReputationSyncError("reputationAuthority changed after confirmation")
        if latest_pending != 0:
            raise ProviderReputationSyncError(
                "Registry updates are paused while jury assignments are pending"
            )
        if (
            latest_registry_settlement != self.config.settlement_contract
            or latest_settlement_registry != self.config.jury_registry
        ):
            raise ProviderReputationSyncError(
                "Registry or Settlement binding changed after confirmation"
            )
        boundary = self._rpc("eth_getBlockByNumber", [hex(number), False])
        if (
            not isinstance(boundary, Mapping)
            or str(boundary.get("hash") or "").lower() != block_hash
        ):
            raise ProviderReputationSyncError(
                "confirmed Registry snapshot reorganized during reads"
            )
        return {
            "head": head,
            "block_number": number,
            "block_hash": block_hash,
            "timestamp": timestamp,
            "tag": tag,
            "reputation_authority": authority,
            "minimum_reputation": minimum,
            "pending_assignments": 0,
            "settlement_contract": registry_settlement,
            "jury_registry": settlement_registry,
        }

    def _preflight(self, action: Mapping[str, Any], tag: Any) -> None:
        transaction = {
            "from": self.sender,
            "to": self.config.jury_registry,
            "data": action["calldata"],
        }
        result = self._rpc("eth_call", [transaction, tag])
        if result != "0x":
            raise ProviderReputationSyncError(
                "setProvider preflight returned unexpected data"
            )

    def propose(
        self,
        snapshot_value: Any,
        signed_descriptor: Any,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        snapshot = verify_pool_reputation_snapshot(
            snapshot_value, config=self.config, now=now,
        )
        descriptor = verify_live_provider_descriptor(
            signed_descriptor, snapshot=snapshot, config=self.config, now=now,
        )
        self._verify_snapshot_event_proofs(snapshot, descriptor)
        context = self.confirmed_context()
        reputation = min(snapshot["stats"]["score"], UINT64_MAX)
        provider = {
            "owner": descriptor["owner"],
            "vote_signer": descriptor["vote_signer"],
            "operator_id_hash": descriptor["operator_id_hash"],
            "peer_id_hash": descriptor["peer_id_hash"],
            "capability_hash": descriptor["capability_hash"],
            "reputation": reputation,
            "active": reputation >= self.config.minimum_reputation,
        }
        source = {
            "pool_public_key": snapshot["pool_public_key"],
            "peer_id": snapshot["peer_id"],
            "sequence": snapshot["sequence"],
            "snapshot_hash": snapshot["snapshot_hash"],
            "descriptor_hash": descriptor["descriptor_hash"],
            "descriptor_timestamp": descriptor["descriptor_timestamp"],
            "descriptor_expires_at": descriptor["descriptor_expires_at"],
            "snapshot_expires_at": snapshot["expires_at"],
            "snapshot_observed_at": snapshot["observed_at"],
            "receipt_count": snapshot["receipt_count"],
            "receipt_set_hash": snapshot["receipt_set_hash"],
            "history_import": snapshot["history_import"],
            "score": snapshot["stats"]["score"],
        }
        source["source_digest"] = provider_source_digest(snapshot, descriptor)
        body = {
            "schema": ACTION_SCHEMA,
            "network_id": self.config.network_id,
            "chain_id": self.config.chain_id,
            "genesis_hash": self.config.genesis_hash,
            "scope": self.scope,
            "sender": self.sender,
            "target": self.config.jury_registry,
            "source": source,
            "source_artifacts": {
                "snapshot": json.loads(_json(snapshot_value)),
                "provider_descriptor": json.loads(_json(signed_descriptor)),
            },
            "provider": provider,
            "calldata": encode_set_provider(
                provider,
                source_sequence=source["sequence"],
                source_digest=source["source_digest"],
            ),
        }
        action = {**body, "action_hash": evidence_hash(body)}
        self._preflight(action, context["tag"])
        return self.outbox.propose(action)

    def _require_execution_key(self) -> bytes:
        if (
            not self.execution_enabled or not self.dedicated_sender
            or self.key_file is None
        ):
            raise ProviderReputationSyncError(
                "automatic reputation execution is disabled"
            )
        try:
            key = self._key_loader(self.key_file)
        except Exception as exc:
            raise ProviderReputationSyncError(
                "could not load the protected reputation authority key"
            ) from exc
        if chain.private_key_to_address(key) != self.sender:
            raise ProviderReputationSyncError(
                "protected key does not match the reputationAuthority sender"
            )
        return key

    def _validate_saved_action_sources(
        self, action: Mapping[str, Any], *, now: int,
    ) -> None:
        expected_binding = {
            "schema": ACTION_SCHEMA,
            "network_id": self.config.network_id,
            "chain_id": self.config.chain_id,
            "genesis_hash": self.config.genesis_hash,
            "scope": self.scope,
            "sender": self.sender,
            "target": self.config.jury_registry,
        }
        if any(action.get(name) != value for name, value in expected_binding.items()):
            raise ProviderReputationSyncError(
                "reputation action execution binding differs from its configured deployment"
            )
        artifacts = _exact(
            action.get("source_artifacts"),
            {"snapshot", "provider_descriptor"},
            "reputation source artifacts",
        )
        snapshot = verify_pool_reputation_snapshot(
            artifacts["snapshot"], config=self.config, now=now,
        )
        descriptor = verify_live_provider_descriptor(
            artifacts["provider_descriptor"],
            snapshot=snapshot, config=self.config, now=now,
        )
        self._verify_snapshot_event_proofs(snapshot, descriptor)
        source = action.get("source")
        if not isinstance(source, Mapping):
            raise ProviderReputationSyncError("reputation action source is missing")
        expected_source = {
            "pool_public_key": snapshot["pool_public_key"],
            "peer_id": snapshot["peer_id"],
            "sequence": snapshot["sequence"],
            "snapshot_hash": snapshot["snapshot_hash"],
            "descriptor_hash": descriptor["descriptor_hash"],
            "descriptor_timestamp": descriptor["descriptor_timestamp"],
            "descriptor_expires_at": descriptor["descriptor_expires_at"],
            "snapshot_expires_at": snapshot["expires_at"],
            "snapshot_observed_at": snapshot["observed_at"],
            "receipt_count": snapshot["receipt_count"],
            "receipt_set_hash": snapshot["receipt_set_hash"],
            "history_import": snapshot["history_import"],
            "score": snapshot["stats"]["score"],
        }
        expected_source["source_digest"] = provider_source_digest(snapshot, descriptor)
        if source != expected_source:
            raise ProviderReputationSyncError(
                "reputation action source differs from its signed artifacts"
            )
        reputation = min(snapshot["stats"]["score"], UINT64_MAX)
        expected_provider = {
            "owner": descriptor["owner"],
            "vote_signer": descriptor["vote_signer"],
            "operator_id_hash": descriptor["operator_id_hash"],
            "peer_id_hash": descriptor["peer_id_hash"],
            "capability_hash": descriptor["capability_hash"],
            "reputation": reputation,
            "active": reputation >= self.config.minimum_reputation,
        }
        if (
            action.get("provider") != expected_provider
            or action.get("calldata") != encode_set_provider(
                expected_provider,
                source_sequence=expected_source["sequence"],
                source_digest=expected_source["source_digest"],
            )
        ):
            raise ProviderReputationSyncError(
                "reputation action differs from its signed Provider evidence"
            )

    def execute(self, action_hash: str) -> dict[str, Any]:
        action_hash = _hash(action_hash, "action hash")
        saved = self.outbox.get(action_hash)
        if saved is None:
            raise ProviderReputationSyncError("unknown reputation action")
        if saved["state"] != "proposed":
            raise ProviderReputationSyncError(
                "submitted or uncertain reputation actions must only be reconciled"
            )
        key = self._require_execution_key()
        action = saved["action"]
        current = int(time.time())
        self._validate_saved_action_sources(action, now=current)
        self.confirmed_context()
        self._preflight(action, "latest")
        latest_nonce = _hex_uint(
            self._rpc("eth_getTransactionCount", [self.sender, "latest"]),
            "latest authority nonce",
        )
        pending_nonce = _hex_uint(
            self._rpc("eth_getTransactionCount", [self.sender, "pending"]),
            "pending authority nonce",
        )
        if latest_nonce != pending_nonce:
            raise ProviderReputationSyncError(
                "dedicated reputationAuthority has an external pending transaction"
            )
        gas_price = _hex_uint(self._rpc("eth_gasPrice", []), "gas price")
        estimate = _hex_uint(
            self._rpc(
                "eth_estimateGas",
                [{
                    "from": self.sender,
                    "to": self.config.jury_registry,
                    "value": "0x0",
                    "data": action["calldata"],
                }],
            ),
            "setProvider gas estimate",
        )
        gas = estimate * 12 // 10 + 10_000
        assert self.max_gas_price_wei is not None
        assert self.max_gas_units is not None
        assert self.max_total_gas_cost_wei is not None
        if (
            gas_price > self.max_gas_price_wei
            or gas > self.max_gas_units
            or gas * gas_price > self.max_total_gas_cost_wei
        ):
            raise ProviderReputationSyncError(
                "reputation transaction exceeds explicit gas caps"
            )
        try:
            raw = self._transaction_signer(
                private_key=key,
                nonce=latest_nonce,
                gas_price=gas_price,
                gas_limit=gas,
                to_address=self.config.jury_registry,
                value=0,
                data=bytes.fromhex(action["calldata"][2:]),
                chain_id=self.config.chain_id,
            )
            if not isinstance(raw, bytes) or not raw:
                raise ProviderReputationSyncError(
                    "transaction signer returned invalid signed bytes"
                )
        except ProviderReputationSyncError:
            raise
        except Exception as exc:
            raise ProviderReputationSyncError(
                "reputation transaction signing failed before any send attempt"
            ) from exc
        _leased, lease_id = self.outbox.begin_execution(
            action_hash, lease_seconds=self.lease_seconds,
        )
        try:
            attached = self.outbox.attach_transaction(
                action_hash, lease_id=lease_id, nonce=latest_nonce, raw_tx=raw,
            )
        except BaseException:
            self.outbox.abort_not_sent(action_hash, lease_id=lease_id)
            raise
        try:
            returned = _hash(
                self._rpc("eth_sendRawTransaction", ["0x" + raw.hex()]),
                "broadcast transaction hash",
            )
            if returned != attached["tx_hash"]:
                raise ProviderReputationSyncError(
                    "RPC returned another reputation transaction hash"
                )
            return self.outbox.mark_submitted(action_hash, lease_id=lease_id)
        except BaseException as exc:
            try:
                self.outbox.mark_uncertain(action_hash)
            except ProviderReputationSyncError:
                pass
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(exc, ProviderReputationSyncError):
                raise ProviderReputationSyncError(
                    "reputation broadcast is uncertain; reconcile the durable hash: "
                    f"{exc}"
                ) from exc
            raise ProviderReputationSyncError(
                "reputation broadcast is uncertain; reconcile the durable hash"
            ) from exc

    def _transaction(self, row: Mapping[str, Any]) -> Mapping[str, Any] | None:
        transaction = self._rpc("eth_getTransactionByHash", [row["tx_hash"]])
        if transaction is None:
            return None
        if not isinstance(transaction, Mapping):
            raise ProviderReputationSyncError(
                "RPC returned a malformed reputation transaction"
            )
        data = transaction.get("input", transaction.get("data"))
        if (
            _hash(str(transaction.get("hash") or ""), "transaction hash")
            != row["tx_hash"]
            or _address(str(transaction.get("from") or ""), "transaction sender")
            != self.sender
            or _address(str(transaction.get("to") or ""), "transaction target")
            != self.config.jury_registry
            or _hex_uint(transaction.get("nonce"), "transaction nonce") != row["nonce"]
            or _hex_uint(transaction.get("value"), "transaction value") != 0
            or data != row["calldata"]
        ):
            raise ProviderReputationSyncError(
                "on-chain reputation transaction differs from the outbox"
            )
        chain_id = transaction.get("chainId")
        if chain_id is not None and _hex_uint(
            chain_id, "transaction chain id",
        ) != self.config.chain_id:
            raise ProviderReputationSyncError(
                "on-chain reputation transaction targets another chain"
            )
        return transaction

    @staticmethod
    def _topic_address(value: Any, label: str) -> str:
        raw = bytes.fromhex(_hash(value, label, nonzero=False)[2:])
        return _word_address(raw, label)

    def _provider_updated_event(
        self,
        logs: Any,
        *,
        receipt: Mapping[str, Any],
        provider: Mapping[str, Any],
        source: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(logs, list):
            raise ProviderReputationSyncError(
                "confirmed reputation receipt has no canonical logs"
            )
        matching: list[dict[str, Any]] = []
        for log in logs:
            if not isinstance(log, Mapping):
                raise ProviderReputationSyncError("receipt contains a malformed event")
            topics = log.get("topics")
            if not isinstance(topics, list) or not topics or topics[0] != PROVIDER_UPDATED_TOPIC:
                continue
            if (
                log.get("removed") not in (None, False)
                or _address(str(log.get("address") or ""), "event address")
                != self.config.jury_registry
                or _hash(str(log.get("transactionHash") or ""), "event transaction hash")
                != receipt["transaction_hash"]
                or _hash(str(log.get("blockHash") or ""), "event block hash")
                != receipt["block_hash"]
                or _hex_uint(log.get("blockNumber"), "event block number")
                != receipt["block_number"]
                or len(topics) != 4
            ):
                raise ProviderReputationSyncError(
                    "ProviderUpdated is not bound to the canonical receipt"
                )
            data = _raw_result(log.get("data"), "ProviderUpdated")
            if len(data) != 160:
                raise ProviderReputationSyncError("ProviderUpdated has malformed data")
            event = {
                "event": "ProviderUpdated",
                "owner": self._topic_address(topics[1], "event Provider owner"),
                "vote_signer": self._topic_address(
                    topics[2], "event Provider vote signer",
                ),
                "operator_id_hash": _hash(topics[3], "event operator id hash"),
                "reputation": _word_uint(data[:32], "event reputation", bits=64),
                "active": _word_bool(data[32:64], "event active"),
                "source_sequence": _word_uint(
                    data[64:96], "event source sequence", bits=64,
                ),
                "source_digest": _hash(
                    "0x" + data[96:128].hex(), "event source digest",
                ),
                "roster_version": _word_uint(
                    data[128:160], "event roster version", bits=64,
                ),
                "log_index": _hex_uint(log.get("logIndex"), "event log index"),
            }
            expected = {
                "owner": provider["owner"],
                "vote_signer": provider["vote_signer"],
                "operator_id_hash": provider["operator_id_hash"],
                "reputation": provider["reputation"],
                "active": provider["active"],
                "source_sequence": source["sequence"],
                "source_digest": source["source_digest"],
            }
            if any(event[name] != value for name, value in expected.items()):
                raise ProviderReputationSyncError(
                    "ProviderUpdated differs from the durable reputation action"
                )
            if event["roster_version"] == 0:
                raise ProviderReputationSyncError(
                    "ProviderUpdated emitted an invalid roster version"
                )
            matching.append(event)
        if len(matching) != 1:
            raise ProviderReputationSyncError(
                "confirmed setProvider transaction must emit exactly one ProviderUpdated"
            )
        return matching[0]

    def _provider_state(self, owner: str, tag: Any) -> dict[str, Any]:
        words = self._call_words("providerForOwner(address)", [owner], 7, tag)
        return {
            "owner": _word_address(words[0], "registered Provider owner"),
            "vote_signer": _word_address(words[1], "registered Provider vote signer"),
            "operator_id_hash": "0x" + words[2].hex(),
            "peer_id_hash": "0x" + words[3].hex(),
            "capability_hash": "0x" + words[4].hex(),
            "reputation": _word_uint(words[5], "registered Provider reputation", bits=64),
            "active": _word_bool(words[6], "registered Provider active"),
        }

    def _provider_source_state(self, owner: str, tag: Any) -> dict[str, Any]:
        sequence = self._call_words(
            "providerSourceSequence(address)", [owner], 1, tag,
        )[0]
        digest = self._call_words(
            "providerSourceDigest(address)", [owner], 1, tag,
        )[0]
        return {
            "sequence": _word_uint(
                sequence, "registered Provider source sequence", bits=64,
            ),
            "digest": _hash(
                "0x" + digest.hex(), "registered Provider source digest",
            ),
        }

    def reconcile(self, action_hash: str) -> dict[str, Any]:
        action_hash = _hash(action_hash, "action hash")
        self.outbox.recover_expired_leases()
        row = self.outbox.get(action_hash)
        if row is None:
            raise ProviderReputationSyncError("unknown reputation action")
        if row["state"] not in {"submitted", "uncertain", "confirmed"} or not row.get("tx_hash"):
            raise ProviderReputationSyncError(
                "reputation action has no reconcilable transaction identity"
            )
        try:
            self._chain_identity()
            transaction = self._transaction(row)
            raw_receipt = self._rpc(
                "eth_getTransactionReceipt", [row["tx_hash"]],
            )
        except ProviderReputationSyncError:
            self.outbox.mark_uncertain(action_hash)
            raise
        if raw_receipt is None:
            if transaction is None:
                self.outbox.mark_uncertain(action_hash)
                raise ProviderReputationSyncError(
                    "reputation transaction is not observable; do not resend it"
                )
            if row["state"] == "confirmed":
                self.outbox.mark_uncertain(action_hash)
                raise ProviderReputationSyncError(
                    "confirmed reputation receipt disappeared; canonicality is uncertain"
                )
            if row["state"] == "submitted":
                self.outbox.mark_observed_submitted(action_hash)
            return {
                "status": row["state"], "action_hash": action_hash,
                "tx_hash": row["tx_hash"], "sender": self.sender,
                "nonce": row["nonce"],
            }
        if not isinstance(raw_receipt, Mapping):
            raise ProviderReputationSyncError(
                "RPC returned a malformed reputation receipt"
            )
        tx_hash = _hash(
            str(raw_receipt.get("transactionHash") or ""),
            "receipt transaction hash",
        )
        block_hash = _hash(str(raw_receipt.get("blockHash") or ""), "receipt block hash")
        block_number = _hex_uint(raw_receipt.get("blockNumber"), "receipt block number")
        status = _hex_uint(raw_receipt.get("status"), "receipt status", bits=8)
        sender = _address(str(raw_receipt.get("from") or ""), "receipt sender")
        target = _address(str(raw_receipt.get("to") or ""), "receipt target")
        if (
            tx_hash != row["tx_hash"] or sender != self.sender
            or target != self.config.jury_registry or status not in (0, 1)
        ):
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "reputation receipt differs from its durable transaction"
            )
        try:
            canonical = self._rpc(
                "eth_getBlockByNumber", [hex(block_number), False],
            )
            head = _hex_uint(self._rpc("eth_blockNumber", []), "head block")
        except ProviderReputationSyncError:
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise
        if (
            not isinstance(canonical, Mapping)
            or str(canonical.get("hash") or "").lower() != block_hash
            or _hex_uint(canonical.get("number"), "canonical block number")
            != block_number
        ):
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "reputation receipt block is noncanonical; do not resend"
            )
        receipt_tag = {"blockHash": block_hash, "requireCanonical": True}
        try:
            self._require_registry_code(receipt_tag)
        except ProviderReputationSyncError:
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise
        confirmations = head - block_number + 1
        if confirmations <= 0:
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "reputation receipt is ahead of the canonical chain head"
            )
        if confirmations < self.config.confirmations:
            self.outbox.mark_observed_submitted(
                action_hash, receipt=raw_receipt,
            )
            return {
                "status": "submitted", "action_hash": action_hash,
                "tx_hash": tx_hash, "sender": sender, "nonce": row["nonce"],
                "confirmations": confirmations,
            }
        if transaction is None:
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "confirmed reputation receipt has no matching transaction body"
            )
        if (
            _hex_uint(transaction.get("blockNumber"), "transaction block number")
            != block_number
            or _hash(str(transaction.get("blockHash") or ""), "transaction block hash")
            != block_hash
        ):
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "reputation transaction body differs from its receipt block"
            )
        if status == 0:
            self.outbox.mark_reverted(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "setProvider transaction reverted and must not be resent"
            )
        normalized_receipt = {
            "transaction_hash": tx_hash,
            "block_number": block_number,
            "block_hash": block_hash,
            "status": 1,
            "from": sender,
            "to": target,
        }
        action = row["action"]
        try:
            event = self._provider_updated_event(
                raw_receipt.get("logs"),
                receipt=normalized_receipt,
                provider=action["provider"],
                source=action["source"],
            )
            provider_state = self._provider_state(
                action["provider"]["owner"], receipt_tag,
            )
            provider_source_state = self._provider_source_state(
                action["provider"]["owner"], receipt_tag,
            )
        except ProviderReputationSyncError:
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise
        if provider_state != action["provider"]:
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "confirmed Registry Provider state differs from the durable action"
            )
        if provider_source_state != {
            "sequence": action["source"]["sequence"],
            "digest": action["source"]["source_digest"],
        }:
            self.outbox.mark_uncertain(action_hash, receipt=raw_receipt)
            raise ProviderReputationSyncError(
                "confirmed Registry source identity differs from the durable action"
            )
        result = {
            "status": "confirmed",
            "action_hash": action_hash,
            "tx_hash": tx_hash,
            "chain_id": self.config.chain_id,
            "registry": self.config.jury_registry,
            "sender": sender,
            "nonce": row["nonce"],
            "confirmations": confirmations,
            "receipt": normalized_receipt,
            "event": event,
        }
        self.outbox.mark_confirmed(
            action_hash, receipt=raw_receipt, result=result,
        )
        return result


__all__ = [
    "ACTION_SCHEMA", "HISTORY_IMPORT_SCHEMA", "PROVIDER_UPDATED_TOPIC",
    "ReputationHistoryImport", "ProviderReputationOutbox",
    "ProviderReputationSync", "ProviderReputationSyncConfig",
    "ProviderReputationSyncError", "SNAPSHOT_PURPOSE", "SNAPSHOT_SCHEMA",
    "build_pool_reputation_snapshot", "encode_set_provider", "provider_source_digest",
    "load_reputation_history_import", "verify_live_provider_descriptor",
    "verify_pool_reputation_snapshot",
]
