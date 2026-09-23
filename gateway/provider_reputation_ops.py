"""Operator CLI for the dynamic Provider-AI jury reputation authority.

The deployment policy pins *how* Providers become eligible, never a fixed
Provider or adjudicator roster.  A Pool signs a monotonically sequenced
reputation snapshot for one live Provider descriptor; the dedicated
``reputationAuthority`` may then propose, explicitly broadcast, and reconcile
the corresponding ``ProviderJuryRegistryV1.setProvider`` transaction.

All commands are read-only by default.  ``execute`` is the only command that
can broadcast and it requires ``--send``, an exact durable action hash, a
protected dedicated key file, and three explicit gas caps.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from . import chain, pool
from .identity import (
    IdentityError,
    NodeIdentity,
    peer_id_from_public_key,
    public_key_from_private_key,
)
from .provider_reputation_sync import (
    ProviderReputationOutbox,
    ProviderReputationSync,
    ProviderReputationSyncConfig,
    ProviderReputationSyncError,
    build_pool_reputation_snapshot,
    load_reputation_history_import,
    verify_pool_reputation_snapshot,
)
from .relay_incidents import evidence_hash


class ProviderReputationOpsError(ValueError):
    """The local ops policy, source material, or requested action is unsafe."""


OPS_POLICY_SCHEMA = "mycomesh.v10.provider-reputation-ops-policy.v1"
DYNAMIC_JURY_MODE = "dynamic_provider_ai_v1"
DYNAMIC_JURY_RANDOMNESS = "future_blockhash_v1"
DEPLOYMENT_CLASS = "controlled_test"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_IDENTITY_BYTES = 16 * 1024
MAX_SNAPSHOT_BYTES = 256 * 1024
MAX_DESCRIPTOR_BYTES = pool.MAX_PEER_DESCRIPTOR_BYTES
ZERO_HASH = "0x" + "0" * 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_KEY = re.compile(r"^[0-9a-f]{64}$")
_ACTION_HASH = re.compile(r"^0x[0-9a-f]{64}$")
_POLICY_FIELDS = {
    "schema", "deployment_class", "deployment_sha256", "network_sha256",
    "network_id", "chain_id", "genesis_hash", "settlement_contract",
    "jury_registry", "registry_runtime_code_hash", "reputation_authority",
    "minimum_reputation", "decision_policy_hash",
    "pool_snapshot_public_key", "snapshot_audience", "descriptor_audience",
    "rpc_url", "confirmations", "max_snapshot_age_seconds",
    "max_descriptor_age_seconds", "reputation_history_import",
}
_HISTORY_POLICY_FIELD = "reputation_history_import"
_FORBIDDEN_ROSTER_FIELDS = {
    "adjudicators", "adjudicator_operators", "independence_attested",
    "jury_provider_evidence", "provider_roster",
}


def _strict_json_loads(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ProviderReputationOpsError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProviderReputationOpsError(
                    f"{label} contains a non-finite JSON number"
                )
            ),
        )
    except ProviderReputationOpsError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderReputationOpsError(f"{label} is not strict JSON") from exc


def _read_bounded_file(
    path: str | os.PathLike[str], *, maximum: int, label: str,
    secret: bool = False,
) -> bytes:
    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise ProviderReputationOpsError(f"could not open {label}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > maximum
        ):
            raise ProviderReputationOpsError(
                f"{label} must be a non-empty bounded regular file"
            )
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ProviderReputationOpsError(f"{label} must be owned by the current user")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022:
            raise ProviderReputationOpsError(f"{label} must not be group/world writable")
        if secret and mode & 0o077:
            raise ProviderReputationOpsError(f"{label} permissions must be 0600 or stricter")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > maximum:
        raise ProviderReputationOpsError(f"{label} exceeds its size limit")
    return raw


def _read_json(
    path: str | os.PathLike[str], *, maximum: int, label: str,
    secret: bool = False,
) -> Any:
    return _strict_json_loads(
        _read_bounded_file(path, maximum=maximum, label=label, secret=secret),
        label,
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProviderReputationOpsError(f"{label} has unknown or missing fields")
    return value


def _text(value: Any, label: str, *, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > maximum or "\x00" in value
    ):
        raise ProviderReputationOpsError(f"{label} must be bounded canonical text")
    return value


def _uint(
    value: Any, label: str, *, bits: int = 256, positive: bool = False,
) -> int:
    if type(value) is not int or value < int(positive) or value >= 2**bits:
        raise ProviderReputationOpsError(f"{label} must be a bounded integer")
    return value


def _address(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderReputationOpsError(f"invalid {label}") from exc
    if normalized != value or normalized == chain.ZERO_ADDRESS:
        raise ProviderReputationOpsError(f"{label} must be canonical and nonzero")
    return normalized


def _hash(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderReputationOpsError(f"invalid {label}") from exc
    if normalized != value or normalized == ZERO_HASH:
        raise ProviderReputationOpsError(f"{label} must be canonical and nonzero")
    return normalized


def _https_rpc(value: Any) -> str:
    result = _text(value, "RPC URL")
    parsed = urlsplit(result)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment
    ):
        raise ProviderReputationOpsError(
            "RPC URL must be credential-free HTTPS without query or fragment"
        )
    return result


@dataclass(frozen=True)
class ProviderReputationOpsContext:
    config: ProviderReputationSyncConfig
    authority_sender: str
    deployment_sha256: str
    network_sha256: str
    deployment_path: Path
    network_path: Path
    pool_snapshot_public_key: str


def load_ops_context(
    policy_path: str | os.PathLike[str],
    network_path: str | os.PathLike[str],
    deployment_path: str | os.PathLike[str],
) -> ProviderReputationOpsContext:
    """Load one exact ops policy bound to dynamic V10 manifest bytes."""
    policy_raw = _read_bounded_file(
        policy_path, maximum=MAX_CONFIG_BYTES, label="reputation ops policy",
    )
    network_raw = _read_bounded_file(
        network_path, maximum=MAX_CONFIG_BYTES, label="Provider network config",
    )
    deployment_raw = _read_bounded_file(
        deployment_path, maximum=MAX_CONFIG_BYTES, label="V10 deployment manifest",
    )
    policy_value = _strict_json_loads(policy_raw, "reputation ops policy")
    network = _strict_json_loads(network_raw, "Provider network config")
    deployment = _strict_json_loads(deployment_raw, "V10 deployment manifest")
    if not isinstance(policy_value, Mapping) or set(policy_value) != _POLICY_FIELDS:
        raise ProviderReputationOpsError(
            "reputation ops policy has unknown or missing fields"
        )
    if not isinstance(network, Mapping) or not isinstance(deployment, Mapping):
        raise ProviderReputationOpsError("network and deployment configs must be objects")
    if policy_value.get("schema") != OPS_POLICY_SCHEMA:
        raise ProviderReputationOpsError("unsupported reputation ops policy schema")
    if policy_value.get("deployment_class") != DEPLOYMENT_CLASS:
        raise ProviderReputationOpsError(
            "future-blockhash Provider jury ops must be controlled_test"
        )
    for field, raw in (
        ("deployment_sha256", deployment_raw), ("network_sha256", network_raw),
    ):
        expected = policy_value.get(field)
        if not isinstance(expected, str) or _SHA256.fullmatch(expected) is None:
            raise ProviderReputationOpsError(f"invalid {field}")
        if expected != _sha256(raw):
            raise ProviderReputationOpsError(f"{field} does not match the pinned file")

    if deployment.get("committee_mode") != DYNAMIC_JURY_MODE:
        raise ProviderReputationOpsError(
            "deployment is not a dynamic Provider-AI jury"
        )
    if deployment.get("jury_randomness") != DYNAMIC_JURY_RANDOMNESS:
        raise ProviderReputationOpsError("deployment uses an unsupported jury randomness mode")
    forbidden = sorted(_FORBIDDEN_ROSTER_FIELDS & set(deployment))
    if forbidden:
        raise ProviderReputationOpsError(
            "dynamic deployment must not pin a static adjudicator roster"
        )
    if _FORBIDDEN_ROSTER_FIELDS & set(network):
        raise ProviderReputationOpsError(
            "dynamic network config must not pin a static adjudicator roster"
        )
    if deployment.get("protocol_version") != 10 or network.get("protocol_version") != 10:
        raise ProviderReputationOpsError("reputation ops require protocol version 10")
    if (
        "deployment_class" in deployment
        and deployment.get("deployment_class") != DEPLOYMENT_CLASS
    ):
        raise ProviderReputationOpsError("deployment class differs from the ops policy")

    declared_name = network.get("deployment")
    deployment_target = Path(deployment_path).resolve()
    if (
        not isinstance(declared_name, str) or not declared_name
        or Path(declared_name).name != declared_name
        or (Path(network_path).resolve().parent / declared_name).resolve()
        != deployment_target
    ):
        raise ProviderReputationOpsError(
            "network config does not reference the exact deployment manifest"
        )

    network_id = _text(policy_value.get("network_id"), "network id", maximum=256)
    if (
        network_id != deployment.get("network_id")
        or network_id != network.get("network_id")
        or not network_id.endswith("-controlled-test")
    ):
        raise ProviderReputationOpsError("network id is not the pinned controlled test")
    chain_id = _uint(policy_value.get("chain_id"), "chain id", bits=64, positive=True)
    if chain_id != deployment.get("chain_id"):
        raise ProviderReputationOpsError("chain id differs from the deployment")
    genesis_hash = _hash(policy_value.get("genesis_hash"), "genesis hash")
    if genesis_hash != deployment.get("genesis_hash"):
        raise ProviderReputationOpsError("genesis hash differs from the deployment")
    settlement = _address(
        policy_value.get("settlement_contract"), "settlement contract",
    )
    settlement_runtime_hash = _hash(
        deployment.get("settlement_runtime_code_keccak256"),
        "Settlement runtime code hash",
    )
    settlement_deployment_block = _uint(
        deployment.get("deployment_block"),
        "Settlement deployment block",
        bits=64,
        positive=True,
    )
    settlement_deployment_block_hash = _hash(
        deployment.get("deployment_block_hash"),
        "Settlement deployment block hash",
    )
    registry = _address(policy_value.get("jury_registry"), "jury Registry")
    authority = _address(
        policy_value.get("reputation_authority"), "reputation authority",
    )
    governance = _address(deployment.get("governance"), "deployment governance")
    registry_governance = _address(
        deployment.get("jury_registry_governance"), "jury Registry governance",
    )
    if (
        settlement != deployment.get("settlement")
        or registry != deployment.get("jury_registry")
        or authority != deployment.get("reputation_authority")
        or governance != registry_governance
        or authority in {governance, settlement, registry}
        or len({settlement, registry, authority, governance}) != 4
    ):
        raise ProviderReputationOpsError(
            "settlement, Registry, governance, or independent authority pin differs"
        )
    minimum = _uint(
        policy_value.get("minimum_reputation"), "minimum reputation",
        bits=64, positive=True,
    )
    if minimum != deployment.get("minimum_provider_reputation"):
        raise ProviderReputationOpsError("minimum reputation differs from the deployment")
    decision_hash = _hash(
        policy_value.get("decision_policy_hash"), "jury decision policy hash",
    )
    if decision_hash != deployment.get("jury_decision_policy_hash"):
        raise ProviderReputationOpsError(
            "jury decision policy hash differs from the deployment"
        )
    runtime_hash = _hash(
        policy_value.get("registry_runtime_code_hash"),
        "Registry runtime code hash",
    )
    manifest_runtime_hash = deployment.get("jury_registry_runtime_code_hash")
    if manifest_runtime_hash is not None and manifest_runtime_hash != runtime_hash:
        raise ProviderReputationOpsError(
            "Registry runtime code hash differs from the deployment"
        )
    public_key = policy_value.get("pool_snapshot_public_key")
    if not isinstance(public_key, str) or _PUBLIC_KEY.fullmatch(public_key) is None:
        raise ProviderReputationOpsError(
            "exactly one canonical Pool snapshot public key must be pinned"
        )
    rpc_url = _https_rpc(policy_value.get("rpc_url"))
    rpc_urls = network.get("settlement_rpc_urls")
    if (
        network.get("settlement_rpc_url") != rpc_url
        or not isinstance(rpc_urls, list) or not rpc_urls
        or rpc_url not in rpc_urls or len(rpc_urls) != len(set(rpc_urls))
        or any(_https_rpc(item) != item for item in rpc_urls)
    ):
        raise ProviderReputationOpsError("RPC URL is not pinned by the network config")
    history_import = None
    history_pin = policy_value.get(_HISTORY_POLICY_FIELD)
    deployment_history = deployment.get(_HISTORY_POLICY_FIELD)
    network_history = network.get(_HISTORY_POLICY_FIELD)
    if history_pin is not None:
        history_pin = _exact(
            history_pin, {"filename", "artifact_sha256", "artifact_root"},
            "reputation history import pin",
        )
        filename = history_pin.get("filename")
        if (
            not isinstance(filename, str) or not filename
            or Path(filename).name != filename
        ):
            raise ProviderReputationOpsError(
                "reputation history import filename must be a local basename"
            )
        history_path = (Path(policy_path).resolve().parent / filename).resolve()
        history_raw = _read_bounded_file(
            history_path, maximum=MAX_CONFIG_BYTES,
            label="reputation history import artifact",
        )
        expected_sha = history_pin.get("artifact_sha256")
        if (
            not isinstance(expected_sha, str)
            or _SHA256.fullmatch(expected_sha) is None
            or _sha256(history_raw) != expected_sha
        ):
            raise ProviderReputationOpsError(
                "reputation history import sha256 differs from its pin"
            )
        try:
            history_import = load_reputation_history_import(
                _strict_json_loads(history_raw, "reputation history import artifact"),
                artifact_sha256=expected_sha,
                expected_artifact_root=_hash(
                    history_pin.get("artifact_root"),
                    "reputation history import root",
                ),
            )
        except ProviderReputationSyncError as exc:
            raise ProviderReputationOpsError(str(exc)) from exc
        if (
            deployment_history != history_import.lineage()
            or network_history != history_import.lineage()
        ):
            raise ProviderReputationOpsError(
                "deployment or network reputation history lineage differs from its artifact"
            )
    else:
        raise ProviderReputationOpsError(
            "dynamic V10 reputation ops require a pinned history import"
        )
    confirmations = _uint(
        policy_value.get("confirmations"), "confirmations", bits=16, positive=True,
    )
    max_snapshot_age = _uint(
        policy_value.get("max_snapshot_age_seconds"),
        "maximum snapshot age", bits=32, positive=True,
    )
    max_descriptor_age = _uint(
        policy_value.get("max_descriptor_age_seconds"),
        "maximum descriptor age", bits=32, positive=True,
    )
    snapshot_audience = _text(
        policy_value.get("snapshot_audience"), "snapshot audience", maximum=256,
    )
    descriptor_audience = _text(
        policy_value.get("descriptor_audience"), "descriptor audience",
    )
    if snapshot_audience != registry:
        raise ProviderReputationOpsError(
            "snapshot audience must be the exact jury Registry address"
        )
    config = ProviderReputationSyncConfig(
        network_id=network_id,
        rpc_url=rpc_url,
        chain_id=chain_id,
        genesis_hash=genesis_hash,
        settlement_contract=settlement,
        settlement_runtime_code_hash=settlement_runtime_hash,
        settlement_deployment_block=settlement_deployment_block,
        settlement_deployment_block_hash=settlement_deployment_block_hash,
        jury_registry=registry,
        registry_runtime_code_hash=runtime_hash,
        minimum_reputation=minimum,
        decision_policy_hash=decision_hash,
        pool_snapshot_public_keys=(public_key,),
        snapshot_audience=snapshot_audience,
        descriptor_audience=descriptor_audience,
        confirmations=confirmations,
        max_snapshot_age_seconds=max_snapshot_age,
        max_descriptor_age_seconds=max_descriptor_age,
        history_import=history_import,
        rpc_urls=tuple(rpc_urls),
    )
    return ProviderReputationOpsContext(
        config=config,
        authority_sender=authority,
        deployment_sha256=_sha256(deployment_raw),
        network_sha256=_sha256(network_raw),
        deployment_path=deployment_target,
        network_path=Path(network_path).resolve(),
        pool_snapshot_public_key=public_key,
    )


class PoolSnapshotSequenceStore:
    """Fail-closed reservation journal for Pool-signed snapshot sequences."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        if str(path) == ":memory:":
            raise ProviderReputationOpsError("snapshot sequence store must be durable")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                target,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exc:
            raise ProviderReputationOpsError(
                "could not open snapshot sequence store"
            ) from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise ProviderReputationOpsError(
                    "snapshot sequence store must be an owned regular file"
                )
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self.path = target
        self.db = sqlite3.connect(target, timeout=30, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("""CREATE TABLE IF NOT EXISTS pool_snapshot_sequences (
            scope TEXT NOT NULL,
            signer TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            state TEXT NOT NULL,
            snapshot_hash TEXT,
            snapshot_json TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(scope,signer,peer_id,sequence)
        )""")

    def close(self) -> None:
        self.db.close()

    def reserve(
        self, *, scope: str, signer: str, peer_id: str, sequence: int,
    ) -> dict[str, Any] | None:
        now = int(time.time())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute(
                "SELECT state,snapshot_json FROM pool_snapshot_sequences "
                "WHERE scope=? AND signer=? AND peer_id=? AND sequence=?",
                (scope, signer, peer_id, sequence),
            ).fetchone()
            if existing is not None:
                if existing[0] == "finalized" and existing[1]:
                    self.db.commit()
                    return _strict_json_loads(
                        existing[1].encode("utf-8"), "saved Pool snapshot",
                    )
                raise ProviderReputationOpsError(
                    "snapshot sequence has an incomplete reservation; operator recovery is required"
                )
            row = self.db.execute(
                "SELECT MAX(sequence) FROM pool_snapshot_sequences "
                "WHERE scope=? AND signer=? AND peer_id=?",
                (scope, signer, peer_id),
            ).fetchone()
            previous = int(row[0] or 0)
            if sequence != previous + 1:
                raise ProviderReputationOpsError(
                    f"snapshot sequence must explicitly increment from {previous} to {previous + 1}"
                )
            self.db.execute(
                "INSERT INTO pool_snapshot_sequences VALUES (?,?,?,?,?,?,?,?,?)",
                (scope, signer, peer_id, sequence, "reserved", None, None, now, now),
            )
            self.db.commit()
            return None
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise

    def finalize(
        self, *, scope: str, signer: str, peer_id: str, sequence: int,
        snapshot: Mapping[str, Any],
    ) -> dict[str, Any]:
        encoded = json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
        snapshot_hash = evidence_hash(snapshot)
        now = int(time.time())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.db.execute(
                "UPDATE pool_snapshot_sequences SET state='finalized',"
                "snapshot_hash=?,snapshot_json=?,updated_at=? "
                "WHERE scope=? AND signer=? AND peer_id=? AND sequence=? "
                "AND state='reserved' AND snapshot_json IS NULL",
                (
                    snapshot_hash, encoded, now, scope, signer, peer_id, sequence,
                ),
            )
            if cursor.rowcount != 1:
                raise ProviderReputationOpsError(
                    "snapshot sequence reservation changed before finalization"
                )
            self.db.commit()
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise
        return json.loads(encoded)


def _load_existing_pool_identity(
    path: str | os.PathLike[str], *, expected_public_key: str,
) -> NodeIdentity:
    raw = _read_bounded_file(
        path, maximum=MAX_IDENTITY_BYTES, label="Pool identity", secret=True,
    )
    try:
        payload = _strict_json_loads(raw, "Pool identity")
        payload = _exact(
            payload, {"private_key", "public_key", "peer_id"}, "Pool identity",
        )
        private_key = str(payload["private_key"])
        public_key = str(payload["public_key"])
        peer_id = str(payload["peer_id"])
        derived_public_key = public_key_from_private_key(private_key)
        derived_peer_id = peer_id_from_public_key(public_key)
    except (IdentityError, ValueError) as exc:
        raise ProviderReputationOpsError("could not load the existing Pool identity") from exc
    if public_key != derived_public_key or peer_id != derived_peer_id:
        raise ProviderReputationOpsError(
            "Pool identity private key, public key, and peer id do not match"
        )
    if public_key != expected_public_key:
        raise ProviderReputationOpsError(
            "Pool identity does not match the pinned snapshot public key"
        )
    return NodeIdentity(
        private_key=private_key, public_key=public_key, peer_id=peer_id,
    )


def build_signed_pool_snapshot(
    context: ProviderReputationOpsContext,
    *,
    identity_path: str | os.PathLike[str],
    reputation_store_path: str | os.PathLike[str],
    sequence_store_path: str | os.PathLike[str],
    peer_id: str,
    sequence: int,
    ttl_seconds: int = 300,
    now: int | None = None,
) -> dict[str, Any]:
    """Sign one replay-fenced snapshot from existing Pool state and identity."""
    identity = _load_existing_pool_identity(
        identity_path, expected_public_key=context.pool_snapshot_public_key,
    )
    reputation_value = _read_json(
        reputation_store_path, maximum=pool.MAX_REPUTATION_STORE_BYTES,
        label="Pool reputation store",
    )
    _exact(
        reputation_value, {"schema", "proofs"},
        "Pool reputation store",
    )
    if reputation_value.get("schema") != pool.POOL_REPUTATION_STORE_SCHEMA:
        raise ProviderReputationOpsError(
            "Pool reputation store must use the proof-carrying durable v4 schema"
        )
    peer = _text(peer_id, "Provider peer id", maximum=160)
    proofs = reputation_value.get("proofs")
    imported = (
        context.config.history_import is not None
        and peer in context.config.history_import.entries
    )
    if not isinstance(proofs, Mapping) or (peer not in proofs and not imported):
        raise ProviderReputationOpsError(
            "Provider peer is absent from both the Pool store and pinned history import"
        )
    sequence = _uint(sequence, "snapshot sequence", bits=63, positive=True)
    ttl = _uint(ttl_seconds, "snapshot TTL", bits=32, positive=True)
    if ttl > context.config.max_snapshot_age_seconds:
        raise ProviderReputationOpsError(
            "snapshot TTL exceeds the pinned maximum snapshot age"
        )
    config = pool.PoolConfig(reputation_path=str(reputation_store_path))
    try:
        pool.load_pool_reputation(config)
    except pool.PoolError as exc:
        raise ProviderReputationOpsError("could not load durable Pool reputation") from exc
    scope = (
        f"{context.config.genesis_hash}:{context.config.chain_id}:"
        f"{context.config.network_id}"
    )
    store = PoolSnapshotSequenceStore(sequence_store_path)
    try:
        existing = store.reserve(
            scope=scope, signer=identity.public_key, peer_id=peer, sequence=sequence,
        )
        if existing is not None:
            verify_pool_reputation_snapshot(
                existing, config=context.config, now=now,
            )
            return existing
        snapshot = build_pool_reputation_snapshot(
            config,
            peer_id=peer,
            network_id=context.config.network_id,
            sequence=sequence,
            pool_identity=identity,
            audience=context.config.snapshot_audience,
            now=now,
            ttl_seconds=ttl,
            history_import=context.config.history_import,
        )
        verify_pool_reputation_snapshot(snapshot, config=context.config, now=now)
        return store.finalize(
            scope=scope, signer=identity.public_key, peer_id=peer,
            sequence=sequence, snapshot=snapshot,
        )
    finally:
        store.close()


def _read_snapshot(path: str | os.PathLike[str]) -> Mapping[str, Any]:
    value = _read_json(path, maximum=MAX_SNAPSHOT_BYTES, label="Pool reputation snapshot")
    if not isinstance(value, Mapping):
        raise ProviderReputationOpsError("Pool reputation snapshot must be an object")
    return value


def _read_descriptor(path: str | os.PathLike[str]) -> Mapping[str, Any]:
    value = _read_json(path, maximum=MAX_DESCRIPTOR_BYTES, label="Provider descriptor")
    if not isinstance(value, Mapping):
        raise ProviderReputationOpsError("Provider descriptor must be an object")
    return value


SyncFactory = Callable[..., ProviderReputationSync]


def propose_authority_action(
    context: ProviderReputationOpsContext,
    *, outbox_path: str | os.PathLike[str], snapshot_path: str | os.PathLike[str],
    descriptor_path: str | os.PathLike[str],
    sync_factory: SyncFactory = ProviderReputationSync,
) -> dict[str, Any]:
    sync = sync_factory(
        context.config, outbox_path=outbox_path,
        sender=context.authority_sender, execution_enabled=False,
        dedicated_sender=False,
    )
    try:
        return sync.propose(
            _read_snapshot(snapshot_path), _read_descriptor(descriptor_path),
        )
    finally:
        sync.close()


def execute_authority_action(
    context: ProviderReputationOpsContext,
    *, outbox_path: str | os.PathLike[str], action_hash: str, send: bool,
    key_file: str | os.PathLike[str], max_gas_price_wei: int,
    max_gas_units: int, max_total_gas_cost_wei: int,
    sync_factory: SyncFactory = ProviderReputationSync,
) -> dict[str, Any]:
    if send is not True:
        raise ProviderReputationOpsError(
            "broadcast is disabled; execute requires an explicit --send"
        )
    if not isinstance(action_hash, str) or _ACTION_HASH.fullmatch(action_hash) is None:
        raise ProviderReputationOpsError("an exact canonical action hash is required")
    _read_bounded_file(
        key_file, maximum=MAX_IDENTITY_BYTES,
        label="reputation authority key", secret=True,
    )
    gas_price = _uint(max_gas_price_wei, "gas price cap", positive=True)
    gas_units = _uint(max_gas_units, "gas unit cap", bits=64, positive=True)
    total = _uint(max_total_gas_cost_wei, "total gas cost cap", positive=True)
    sync = sync_factory(
        context.config, outbox_path=outbox_path,
        sender=context.authority_sender, execution_enabled=True,
        dedicated_sender=True, key_file=key_file,
        max_gas_price_wei=gas_price, max_gas_units=gas_units,
        max_total_gas_cost_wei=total,
    )
    try:
        saved = sync.outbox.get(action_hash)
        if saved is None or saved.get("action_hash") != action_hash:
            raise ProviderReputationOpsError(
                "exact action hash is not present in the durable outbox"
            )
        return sync.execute(action_hash)
    finally:
        sync.close()


def reconcile_authority_action(
    context: ProviderReputationOpsContext,
    *, outbox_path: str | os.PathLike[str], action_hash: str,
    sync_factory: SyncFactory = ProviderReputationSync,
) -> dict[str, Any]:
    if not isinstance(action_hash, str) or _ACTION_HASH.fullmatch(action_hash) is None:
        raise ProviderReputationOpsError("an exact canonical action hash is required")
    sync = sync_factory(
        context.config, outbox_path=outbox_path,
        sender=context.authority_sender, execution_enabled=False,
        dedicated_sender=False,
    )
    try:
        return sync.reconcile(action_hash)
    finally:
        sync.close()


def authority_action_status(
    context: ProviderReputationOpsContext,
    *, outbox_path: str | os.PathLike[str], action_hash: str,
) -> dict[str, Any]:
    if not isinstance(action_hash, str) or _ACTION_HASH.fullmatch(action_hash) is None:
        raise ProviderReputationOpsError("an exact canonical action hash is required")
    outbox = ProviderReputationOutbox(outbox_path)
    try:
        row = outbox.get(action_hash)
    finally:
        outbox.close()
    if row is None:
        raise ProviderReputationOpsError("unknown reputation action")
    action = row.get("action")
    expected = {
        "network_id": context.config.network_id,
        "chain_id": context.config.chain_id,
        "genesis_hash": context.config.genesis_hash,
        "sender": context.authority_sender,
        "target": context.config.jury_registry,
    }
    if not isinstance(action, Mapping) or any(
        action.get(name) != value for name, value in expected.items()
    ):
        raise ProviderReputationOpsError(
            "saved action differs from the pinned dynamic V10 deployment"
        )
    return row


def _public_result(value: Mapping[str, Any]) -> dict[str, Any]:
    action = value.get("action") if isinstance(value.get("action"), Mapping) else {}
    source = action.get("source") if isinstance(action.get("source"), Mapping) else {}
    provider = action.get("provider") if isinstance(action.get("provider"), Mapping) else {}
    result = {
        "state": value.get("state", value.get("status")),
        "action_hash": value.get("action_hash"),
        "tx_hash": value.get("tx_hash"),
        "sender": value.get("sender"),
        "nonce": value.get("nonce"),
        "provider_owner": value.get("provider_owner", provider.get("owner")),
        "source_peer_id": value.get("source_peer_id", source.get("peer_id")),
        "source_sequence": value.get("source_sequence", source.get("sequence")),
    }
    if isinstance(value.get("confirmations"), int):
        result["confirmations"] = value["confirmations"]
    return {key: item for key, item in result.items() if item is not None}


def _write_json_output(path: str | os.PathLike[str], value: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if target.exists():
        existing = _read_bounded_file(
            target, maximum=MAX_SNAPSHOT_BYTES, label="snapshot output",
        )
        if existing != encoded:
            raise ProviderReputationOpsError(
                "snapshot output already exists with different content"
            )
        return
    try:
        descriptor = os.open(
            target,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as exc:
        raise ProviderReputationOpsError("snapshot output already exists") from exc
    except OSError as exc:
        raise ProviderReputationOpsError("could not write snapshot output") from exc


def _positive(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive base-10 integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive base-10 integer")
    return parsed


def _add_context_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", required=True, help="exact ops policy JSON")
    parser.add_argument("--network", required=True, help="Provider network JSON")
    parser.add_argument("--deployment", required=True, help="dynamic V10 deployment JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m gateway.provider_reputation_ops",
        description="Dynamic Provider-AI jury reputation authority operations",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot", help="sign a Pool reputation snapshot")
    _add_context_arguments(snapshot)
    snapshot.add_argument("--identity", required=True)
    snapshot.add_argument("--reputation-store", required=True)
    snapshot.add_argument("--sequence-store", required=True)
    snapshot.add_argument("--peer-id", required=True)
    snapshot.add_argument("--sequence", required=True, type=_positive)
    snapshot.add_argument("--ttl-seconds", type=_positive, default=300)
    snapshot.add_argument("--output", required=True)

    propose = commands.add_parser("propose", help="validate evidence and save an action")
    _add_context_arguments(propose)
    propose.add_argument("--outbox", required=True)
    propose.add_argument("--snapshot", required=True)
    propose.add_argument("--descriptor", required=True)

    execute = commands.add_parser("execute", help="explicitly broadcast one saved action")
    _add_context_arguments(execute)
    execute.add_argument("--outbox", required=True)
    execute.add_argument("--action-hash", required=True)
    execute.add_argument("--send", action="store_true")
    execute.add_argument("--key-file", required=True)
    execute.add_argument("--max-gas-price-wei", required=True, type=_positive)
    execute.add_argument("--max-gas-units", required=True, type=_positive)
    execute.add_argument("--max-total-gas-cost-wei", required=True, type=_positive)

    reconcile = commands.add_parser("reconcile", help="reconcile a durable transaction")
    _add_context_arguments(reconcile)
    reconcile.add_argument("--outbox", required=True)
    reconcile.add_argument("--action-hash", required=True)

    status = commands.add_parser("status", help="read one durable action without RPC")
    _add_context_arguments(status)
    status.add_argument("--outbox", required=True)
    status.add_argument("--action-hash", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        context = load_ops_context(args.policy, args.network, args.deployment)
        if args.command == "snapshot":
            snapshot = build_signed_pool_snapshot(
                context,
                identity_path=args.identity,
                reputation_store_path=args.reputation_store,
                sequence_store_path=args.sequence_store,
                peer_id=args.peer_id,
                sequence=args.sequence,
                ttl_seconds=args.ttl_seconds,
            )
            _write_json_output(args.output, snapshot)
            response = {
                "status": "signed",
                "snapshot_path": str(Path(args.output).resolve()),
                "snapshot_hash": evidence_hash(snapshot),
                "peer_id": snapshot.get("peer_id"),
                "sequence": snapshot.get("sequence"),
                "pool_public_key": snapshot.get("signature", {}).get("public_key"),
            }
        elif args.command == "propose":
            response = _public_result(propose_authority_action(
                context, outbox_path=args.outbox,
                snapshot_path=args.snapshot, descriptor_path=args.descriptor,
            ))
        elif args.command == "execute":
            response = _public_result(execute_authority_action(
                context, outbox_path=args.outbox,
                action_hash=args.action_hash, send=args.send,
                key_file=args.key_file,
                max_gas_price_wei=args.max_gas_price_wei,
                max_gas_units=args.max_gas_units,
                max_total_gas_cost_wei=args.max_total_gas_cost_wei,
            ))
        elif args.command == "reconcile":
            response = _public_result(reconcile_authority_action(
                context, outbox_path=args.outbox, action_hash=args.action_hash,
            ))
        else:
            response = _public_result(authority_action_status(
                context, outbox_path=args.outbox, action_hash=args.action_hash,
            ))
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        ProviderReputationOpsError, ProviderReputationSyncError,
        pool.PoolError, IdentityError, OSError, sqlite3.Error, ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DYNAMIC_JURY_MODE", "OPS_POLICY_SCHEMA", "PoolSnapshotSequenceStore",
    "ProviderReputationOpsContext", "ProviderReputationOpsError",
    "authority_action_status", "build_parser", "build_signed_pool_snapshot",
    "execute_authority_action", "load_ops_context", "main",
    "propose_authority_action", "reconcile_authority_action",
]
