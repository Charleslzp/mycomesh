from __future__ import annotations

import ipaddress
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .identity import (
    SIGNATURE_MAX_AGE_SECONDS,
    IdentityError,
    peer_id_from_public_key,
    verify_document,
)
from .netio import is_legacy_ipv4_hostname


DEFAULT_GATEWAY_REGISTRY_DB = ".codex-run/mycomesh-gateways.sqlite3"
GATEWAY_REGISTRATION_PURPOSE = "mycomesh.gateway.register"
DEFAULT_GATEWAY_TTL_SECONDS = 300
MIN_GATEWAY_TTL_SECONDS = 30
MAX_GATEWAY_TTL_SECONDS = 3600
MAX_GATEWAY_WEIGHT = 100
MAX_GATEWAY_CAPACITY = 1_000_000
MAX_GATEWAY_LIST_LIMIT = 100
GATEWAY_SIGNATURE_FUTURE_TOLERANCE_SECONDS = 30
REQUIRED_SIGNED_GATEWAY_FIELDS = frozenset(
    {
        "node_id",
        "public_key",
        "public_url",
        "network_id",
        "chain_id",
        "settlement",
        "sequence",
        "expires_at",
        "status",
        "weight",
        "capacity",
        "role",
    }
)


class GatewayRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayRecord:
    node_id: str
    public_key: str
    public_url: str
    network_id: str
    chain_id: int
    settlement: str
    sequence: int
    status: str
    weight: int
    capacity: int
    latency_ms: int | None
    success_rate: float | None
    stake: str | None
    role: str
    last_seen: int
    expires_at: int
    signature: dict[str, Any] | None = None
    descriptor: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "public_key": self.public_key,
            "public_url": self.public_url,
            "network_id": self.network_id,
            "chain_id": self.chain_id,
            "settlement": self.settlement,
            "sequence": self.sequence,
            "status": self.status,
            "weight": self.weight,
            "capacity": self.capacity,
            "latency_ms": self.latency_ms,
            "success_rate": self.success_rate,
            "stake": self.stake,
            "role": self.role,
            "last_seen": self.last_seen,
            "expires_at": self.expires_at,
            "signature": self.signature or {},
            "descriptor": self.descriptor or {},
        }


class GatewayRegistry:
    def __init__(self, path: str | Path = DEFAULT_GATEWAY_REGISTRY_DB) -> None:
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
                CREATE TABLE IF NOT EXISTS gateways (
                    node_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    public_url TEXT NOT NULL,
                    network_id TEXT NOT NULL DEFAULT '',
                    chain_id INTEGER NOT NULL DEFAULT 0,
                    settlement TEXT NOT NULL DEFAULT '',
                    sequence INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    weight INTEGER NOT NULL DEFAULT 1,
                    capacity INTEGER NOT NULL DEFAULT 0,
                    latency_ms INTEGER,
                    success_rate REAL,
                    stake TEXT,
                    role TEXT NOT NULL DEFAULT 'gateway_bridge',
                    signature_json TEXT,
                    descriptor_json TEXT,
                    last_seen INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(gateways)").fetchall()}
            if "network_id" not in columns:
                conn.execute("ALTER TABLE gateways ADD COLUMN network_id TEXT NOT NULL DEFAULT ''")
            if "chain_id" not in columns:
                conn.execute("ALTER TABLE gateways ADD COLUMN chain_id INTEGER NOT NULL DEFAULT 0")
            if "settlement" not in columns:
                conn.execute("ALTER TABLE gateways ADD COLUMN settlement TEXT NOT NULL DEFAULT ''")
            if "sequence" not in columns:
                conn.execute("ALTER TABLE gateways ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0")
            if "descriptor_json" not in columns:
                conn.execute("ALTER TABLE gateways ADD COLUMN descriptor_json TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_sequences (
                    node_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS local_gateway_descriptors (
                    node_id TEXT PRIMARY KEY,
                    cache_key TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )

    def next_sequence(self, node_id: str, *, minimum: int | None = None) -> int:
        normalized_node_id = str(node_id).strip()
        if not normalized_node_id:
            raise GatewayRegistryError("gateway sequence node_id is required")
        floor = _bounded_int(
            minimum if minimum is not None else int(time.time()),
            "sequence minimum",
            minimum=1,
            maximum=2**63 - 1,
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT sequence FROM gateway_sequences WHERE node_id = ?",
                (normalized_node_id,),
            ).fetchone()
            sequence = floor if row is None else max(floor, int(row["sequence"]) + 1)
            if sequence > 2**63 - 1:
                raise GatewayRegistryError("gateway descriptor sequence is exhausted")
            conn.execute(
                (
                    "INSERT INTO gateway_sequences(node_id, sequence) VALUES (?, ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET sequence = excluded.sequence"
                ),
                (normalized_node_id, sequence),
            )
        return sequence

    def get_or_issue_local_descriptor(
        self,
        node_id: str,
        *,
        cache_key: str,
        now: int,
        refresh_before_seconds: int,
        factory: Callable[[int], dict[str, Any]],
    ) -> dict[str, Any]:
        normalized_node_id = str(node_id).strip()
        if not normalized_node_id:
            raise GatewayRegistryError("local gateway descriptor node_id is required")
        current_time = _bounded_int(now, "descriptor time", minimum=1, maximum=2**63 - 1)
        refresh_before = _bounded_int(
            refresh_before_seconds,
            "descriptor refresh window",
            minimum=0,
            maximum=MAX_GATEWAY_TTL_SECONDS,
        )
        normalized_cache_key = str(cache_key)

        with self._connect() as conn:
            cached = _cached_local_descriptor(
                conn.execute(
                    "SELECT * FROM local_gateway_descriptors WHERE node_id = ?",
                    (normalized_node_id,),
                ).fetchone(),
                cache_key=normalized_cache_key,
                now=current_time,
                refresh_before=refresh_before,
            )
        if cached is not None:
            return cached

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cached = _cached_local_descriptor(
                conn.execute(
                    "SELECT * FROM local_gateway_descriptors WHERE node_id = ?",
                    (normalized_node_id,),
                ).fetchone(),
                cache_key=normalized_cache_key,
                now=current_time,
                refresh_before=refresh_before,
            )
            if cached is not None:
                return cached

            sequence_row = conn.execute(
                "SELECT sequence FROM gateway_sequences WHERE node_id = ?",
                (normalized_node_id,),
            ).fetchone()
            sequence = (
                current_time
                if sequence_row is None
                else max(current_time, int(sequence_row["sequence"]) + 1)
            )
            if sequence > 2**63 - 1:
                raise GatewayRegistryError("gateway descriptor sequence is exhausted")

            payload = factory(sequence)
            if not isinstance(payload, dict):
                raise GatewayRegistryError("local gateway descriptor factory must return an object")
            if str(payload.get("node_id") or "") != normalized_node_id:
                raise GatewayRegistryError("local gateway descriptor node_id mismatch")
            if payload.get("sequence") != sequence:
                raise GatewayRegistryError("local gateway descriptor sequence mismatch")
            expires_at = _bounded_int(
                payload.get("expires_at"),
                "local gateway descriptor expires_at",
                minimum=current_time + refresh_before + 1,
                maximum=current_time + MAX_GATEWAY_TTL_SECONDS,
            )
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            conn.execute(
                (
                    "INSERT INTO gateway_sequences(node_id, sequence) VALUES (?, ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET sequence = excluded.sequence"
                ),
                (normalized_node_id, sequence),
            )
            conn.execute(
                """
                INSERT INTO local_gateway_descriptors(
                    node_id, cache_key, sequence, expires_at, payload_json
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    cache_key = excluded.cache_key,
                    sequence = excluded.sequence,
                    expires_at = excluded.expires_at,
                    payload_json = excluded.payload_json
                """,
                (normalized_node_id, normalized_cache_key, sequence, expires_at, encoded),
            )
        return payload

    def register(
        self,
        payload: dict[str, Any],
        *,
        ttl_seconds: int = DEFAULT_GATEWAY_TTL_SECONDS,
        require_signed: bool = True,
        expected_network_id: str | None = None,
        expected_chain_id: int | None = None,
        expected_settlement: str | None = None,
        local_compat: bool = False,
    ) -> GatewayRecord:
        now = int(time.time())
        if not require_signed and not local_compat:
            raise GatewayRegistryError("gateway descriptors must be node-signed outside the local profile")
        unsigned = (
            verify_gateway_registration(
                payload,
                expected_network_id=expected_network_id,
                expected_chain_id=expected_chain_id,
                expected_settlement=expected_settlement,
                allow_localhost=local_compat,
                now=now,
            )
            if require_signed
            else dict(payload)
        )
        public_key = _registration_public_key(payload, unsigned)
        node_id = str(unsigned.get("node_id") or peer_id_from_public_key(public_key))
        if node_id != peer_id_from_public_key(public_key):
            raise GatewayRegistryError("gateway node_id does not match public_key")
        public_url = normalize_gateway_url(str(unsigned.get("public_url") or ""), allow_localhost=local_compat)
        network_id = _descriptor_network_id(unsigned, expected_network_id, local_compat=local_compat)
        chain_id = _descriptor_chain_id(unsigned, expected_chain_id, local_compat=local_compat)
        settlement = _descriptor_settlement(
            unsigned,
            expected_settlement,
            local_compat=local_compat,
        )
        sequence = _descriptor_sequence(unsigned, local_compat=local_compat, now=now)
        status = _gateway_status(unsigned.get("status") or "active")
        weight = _bounded_int(unsigned.get("weight", 1), "weight", minimum=1, maximum=MAX_GATEWAY_WEIGHT)
        capacity = _bounded_int(unsigned.get("capacity", 0), "capacity", minimum=0, maximum=MAX_GATEWAY_CAPACITY)
        latency_ms = _optional_non_negative_int(unsigned.get("latency_ms"), "latency_ms")
        success_rate = _optional_success_rate(unsigned.get("success_rate"))
        stake = str(unsigned.get("stake")) if unsigned.get("stake") is not None else None
        role = str(unsigned.get("role") or "gateway_bridge")
        expires_at = _descriptor_expiry(unsigned, default_ttl=ttl_seconds, local_compat=local_compat, now=now)
        signature = payload.get("signature") if isinstance(payload.get("signature"), dict) else None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM gateways WHERE node_id = ?", (node_id,)).fetchone()
            if existing is not None:
                existing_sequence = int(existing["sequence"])
                if sequence < existing_sequence:
                    raise GatewayRegistryError("gateway descriptor sequence is older than the registered descriptor")
                if sequence == existing_sequence:
                    if _same_descriptor(
                        existing,
                        public_key=public_key,
                        public_url=public_url,
                        network_id=network_id,
                        chain_id=chain_id,
                        settlement=settlement,
                        expires_at=expires_at,
                        status=status,
                        weight=weight,
                        capacity=capacity,
                        latency_ms=latency_ms,
                        success_rate=success_rate,
                        stake=stake,
                        role=role,
                    ):
                        return _record_from_row(existing)
                    raise GatewayRegistryError("gateway descriptor sequence must increase when descriptor fields change")
            conn.execute(
                (
                    "INSERT INTO gateways(node_id, public_key, public_url, network_id, chain_id, settlement, sequence, status, weight, capacity, "
                    "latency_ms, success_rate, stake, role, signature_json, descriptor_json, last_seen, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET public_key = excluded.public_key, public_url = excluded.public_url, "
                    "network_id = excluded.network_id, chain_id = excluded.chain_id, settlement = excluded.settlement, "
                    "sequence = excluded.sequence, "
                    "status = excluded.status, weight = excluded.weight, capacity = excluded.capacity, latency_ms = excluded.latency_ms, "
                    "success_rate = excluded.success_rate, stake = excluded.stake, role = excluded.role, signature_json = excluded.signature_json, "
                    "descriptor_json = excluded.descriptor_json, "
                    "last_seen = excluded.last_seen, expires_at = excluded.expires_at"
                ),
                (
                    node_id,
                    public_key,
                    public_url,
                    network_id,
                    chain_id,
                    settlement,
                    sequence,
                    status,
                    weight,
                    capacity,
                    latency_ms,
                    success_rate,
                    stake,
                    role,
                    _json_signature(signature),
                    _json_document(payload),
                    now,
                    expires_at,
                ),
            )
        return GatewayRecord(
            node_id=node_id,
            public_key=public_key,
            public_url=public_url,
            network_id=network_id,
            chain_id=chain_id,
            settlement=settlement,
            sequence=sequence,
            status=status,
            weight=weight,
            capacity=capacity,
            latency_ms=latency_ms,
            success_rate=success_rate,
            stake=stake,
            role=role,
            last_seen=now,
            expires_at=expires_at,
            signature=signature,
            descriptor=dict(payload),
        )

    def list_gateways(self, *, include_inactive: bool = False, now: int | None = None, limit: int = 20) -> list[GatewayRecord]:
        current_time = int(now if now is not None else time.time())
        query = "SELECT * FROM gateways"
        params: list[object] = []
        if not include_inactive:
            query += " WHERE status = 'active' AND expires_at > ?"
            params.append(current_time)
        # Registration metadata is self-reported. It must never determine the
        # consumer recommendation order until an independent monitor owns it.
        query += " ORDER BY last_seen DESC, node_id ASC LIMIT ?"
        params.append(min(MAX_GATEWAY_LIST_LIMIT, max(1, int(limit))))
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_record_from_row(row) for row in rows]

    def set_status(self, node_id: str, status: str) -> GatewayRecord:
        normalized = _gateway_status(status)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            result = conn.execute("UPDATE gateways SET status = ? WHERE node_id = ?", (normalized, node_id))
            if int(result.rowcount or 0) != 1:
                raise GatewayRegistryError(f"gateway not found: {node_id}")
            row = conn.execute("SELECT * FROM gateways WHERE node_id = ?", (node_id,)).fetchone()
        return _record_from_row(row)


def verify_gateway_registration(
    payload: dict[str, Any],
    *,
    expected_network_id: str | None = None,
    expected_chain_id: int | None = None,
    expected_settlement: str | None = None,
    expected_node_id: str | None = None,
    expected_public_key: str | None = None,
    allow_localhost: bool = False,
    now: int | None = None,
) -> dict[str, Any]:
    return verify_gateway_descriptor(
        payload,
        expected_network_id=expected_network_id,
        expected_chain_id=expected_chain_id,
        expected_settlement=expected_settlement,
        expected_node_id=expected_node_id,
        expected_public_key=expected_public_key,
        allow_localhost=allow_localhost,
        require_fresh_signature=True,
        now=now,
    )


def verify_gateway_descriptor(
    payload: dict[str, Any],
    *,
    expected_network_id: str | None = None,
    expected_chain_id: int | None = None,
    expected_settlement: str | None = None,
    expected_node_id: str | None = None,
    expected_public_key: str | None = None,
    allow_localhost: bool = False,
    require_fresh_signature: bool = False,
    now: int | None = None,
) -> dict[str, Any]:
    current_time = int(now if now is not None else time.time())
    try:
        unsigned = verify_document(
            payload,
            purpose=GATEWAY_REGISTRATION_PURPOSE,
            max_age_seconds=SIGNATURE_MAX_AGE_SECONDS if require_fresh_signature else 0,
            now=current_time,
        )
    except IdentityError as exc:
        raise GatewayRegistryError(f"invalid gateway signature: {exc}") from exc

    missing = sorted(REQUIRED_SIGNED_GATEWAY_FIELDS - set(unsigned))
    if missing:
        raise GatewayRegistryError(
            f"signed gateway descriptor is missing required fields: {', '.join(missing)}"
        )

    public_key = _registration_public_key(payload, unsigned)
    node_id = str(unsigned.get("node_id") or "")
    if node_id != peer_id_from_public_key(public_key):
        raise GatewayRegistryError("gateway node_id does not match public_key")
    if expected_node_id is not None and node_id != str(expected_node_id):
        raise GatewayRegistryError("gateway node_id does not match the pinned trust anchor")
    if expected_public_key is not None and public_key != str(expected_public_key):
        raise GatewayRegistryError("gateway public_key does not match the pinned trust anchor")

    declared_url = unsigned.get("public_url")
    if not isinstance(declared_url, str):
        raise GatewayRegistryError("signed gateway descriptor public_url must be a string")
    canonical_url = normalize_gateway_url(declared_url, allow_localhost=allow_localhost)
    if declared_url != canonical_url:
        raise GatewayRegistryError(
            f"signed gateway descriptor public_url must already be canonical: {canonical_url}"
        )

    _descriptor_network_id(unsigned, expected_network_id, local_compat=False)
    _descriptor_chain_id(unsigned, expected_chain_id, local_compat=False)
    _descriptor_settlement(unsigned, expected_settlement, local_compat=False)
    _descriptor_sequence(unsigned, local_compat=False, now=current_time)
    _gateway_status(unsigned.get("status"))
    _bounded_int(unsigned.get("weight"), "weight", minimum=1, maximum=MAX_GATEWAY_WEIGHT)
    _bounded_int(unsigned.get("capacity"), "capacity", minimum=0, maximum=MAX_GATEWAY_CAPACITY)
    if not str(unsigned.get("role") or "").strip():
        raise GatewayRegistryError("gateway descriptor role must not be empty")

    signature_timestamp = _gateway_signature_timestamp(payload)
    if signature_timestamp > current_time + GATEWAY_SIGNATURE_FUTURE_TOLERANCE_SECONDS:
        raise GatewayRegistryError("gateway descriptor signature timestamp is in the future")
    expires_at = _gateway_descriptor_expiry_value(unsigned)
    if expires_at <= current_time:
        raise GatewayRegistryError("gateway descriptor has expired")
    lifetime = expires_at - signature_timestamp
    if lifetime <= 0 or lifetime > MAX_GATEWAY_TTL_SECONDS:
        raise GatewayRegistryError(
            f"gateway descriptor signed lifetime must be between 1 and {MAX_GATEWAY_TTL_SECONDS} seconds"
        )
    return unsigned


def normalize_gateway_url(public_url: str, *, allow_localhost: bool = False) -> str:
    value = str(public_url or "")
    if (
        not value
        or value != value.strip()
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GatewayRegistryError(
            "gateway public_url must not contain surrounding whitespace, control characters, or backslashes"
        )
    try:
        parsed = urlparse(value)
        hostname = str(parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError as exc:
        raise GatewayRegistryError("gateway public_url is invalid") from exc
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise GatewayRegistryError("gateway public_url must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise GatewayRegistryError("gateway public_url must not contain userinfo")
    if parsed.query or parsed.fragment or parsed.params:
        raise GatewayRegistryError("gateway public_url must not contain params, query, or fragment")
    if not hostname or "%" in hostname:
        raise GatewayRegistryError("gateway public_url hostname is invalid")
    local = _is_localhost(hostname)
    if local and not allow_localhost:
        raise GatewayRegistryError("localhost gateway URLs are allowed only in the local profile")
    if parsed.scheme != "https" and not (allow_localhost and local):
        raise GatewayRegistryError("gateway public_url must use https outside the local profile")
    _validate_public_hostname(hostname, allow_localhost=allow_localhost)
    path = parsed.path.rstrip("/")
    if path and path != "/v1":
        raise GatewayRegistryError("gateway public_url path must be empty or /v1")
    canonical_host = _canonical_url_host(hostname)
    default_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port <= 0:
        raise GatewayRegistryError("gateway public_url port is invalid")
    authority = canonical_host if port is None or port == default_port else f"{canonical_host}:{port}"
    return f"{parsed.scheme}://{authority}/v1"


def _registration_public_key(payload: dict[str, Any], unsigned: dict[str, Any]) -> str:
    signature = payload.get("signature")
    signature_public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    declared_public_key = str(unsigned.get("public_key") or "")
    public_key = signature_public_key or declared_public_key
    if not public_key:
        raise GatewayRegistryError("gateway public_key is required")
    if signature_public_key and declared_public_key and signature_public_key != declared_public_key:
        raise GatewayRegistryError("gateway public_key does not match signature public_key")
    return public_key


def _record_from_row(row: sqlite3.Row) -> GatewayRecord:
    return GatewayRecord(
        node_id=str(row["node_id"]),
        public_key=str(row["public_key"]),
        public_url=str(row["public_url"]),
        network_id=str(row["network_id"]),
        chain_id=int(row["chain_id"]),
        settlement=str(row["settlement"]),
        sequence=int(row["sequence"]),
        status=str(row["status"]),
        weight=int(row["weight"]),
        capacity=int(row["capacity"]),
        latency_ms=int(row["latency_ms"]) if row["latency_ms"] is not None else None,
        success_rate=float(row["success_rate"]) if row["success_rate"] is not None else None,
        stake=str(row["stake"]) if row["stake"] else None,
        role=str(row["role"]),
        last_seen=int(row["last_seen"]),
        expires_at=int(row["expires_at"]),
        signature=_json_object(row["signature_json"]),
        descriptor=_json_object(row["descriptor_json"]),
    )


def _gateway_status(status: Any) -> str:
    normalized = str(status or "").strip().lower()
    if normalized not in {"active", "draining", "suspended"}:
        raise GatewayRegistryError("gateway status must be active, draining, or suspended")
    return normalized


def _optional_non_negative_int(value: Any, label: str) -> int | None:
    if value is None or value == "":
        return None
    parsed = int(value)
    if parsed < 0:
        raise GatewayRegistryError(f"{label} must be non-negative")
    return parsed


def _optional_success_rate(value: Any) -> float | None:
    if value is None or value == "":
        return None
    parsed = float(value)
    if parsed < 0 or parsed > 1:
        raise GatewayRegistryError("success_rate must be between 0 and 1")
    return parsed


def _is_localhost(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_public_hostname(hostname: str, *, allow_localhost: bool) -> None:
    if allow_localhost and _is_localhost(hostname):
        return
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if hostname.endswith((".local", ".internal", ".lan", ".home")) or "." not in hostname:
            raise GatewayRegistryError("gateway public_url must use a public DNS hostname")
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise GatewayRegistryError("gateway public_url hostname is invalid") from exc
        labels = ascii_hostname.split(".")
        if (
            len(ascii_hostname) > 253
            or is_legacy_ipv4_hostname(ascii_hostname)
            or all(character.isdigit() or character == "." for character in ascii_hostname)
            or any(
                not label
                or len(label) > 63
                or not label[0].isalnum()
                or not label[-1].isalnum()
                or any(not character.isalnum() and character != "-" for character in label)
                for label in labels
            )
        ):
            raise GatewayRegistryError("gateway public_url hostname is invalid")
        return
    if not address.is_global:
        raise GatewayRegistryError("gateway public_url must not use a private, loopback, link-local, or reserved address")


def _canonical_url_host(hostname: str) -> str:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname.encode("idna").decode("ascii").lower()
    if address.version == 6:
        return f"[{address.compressed}]"
    return address.compressed


def _bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise GatewayRegistryError(f"{label} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise GatewayRegistryError(f"{label} must be between {minimum} and {maximum}")
    return parsed


def _cached_local_descriptor(
    row: sqlite3.Row | None,
    *,
    cache_key: str,
    now: int,
    refresh_before: int,
) -> dict[str, Any] | None:
    if (
        row is None
        or str(row["cache_key"]) != cache_key
        or int(row["expires_at"]) <= now + refresh_before
    ):
        return None
    try:
        payload = json.loads(str(row["payload_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, dict)
        or str(payload.get("node_id") or "") != str(row["node_id"])
        or payload.get("sequence") != int(row["sequence"])
        or payload.get("expires_at") != int(row["expires_at"])
    ):
        return None
    return payload


def _descriptor_network_id(unsigned: dict[str, Any], expected: str | None, *, local_compat: bool) -> str:
    value = str(unsigned.get("network_id") or (expected if local_compat else "")).strip()
    if not value:
        raise GatewayRegistryError("gateway descriptor network_id is required")
    if expected is not None and value != str(expected):
        raise GatewayRegistryError("gateway descriptor network_id does not match this network")
    return value


def _descriptor_chain_id(unsigned: dict[str, Any], expected: int | None, *, local_compat: bool) -> int:
    raw = unsigned.get("chain_id")
    if raw is None and local_compat:
        raw = expected if expected is not None else 0
    if raw is None:
        raise GatewayRegistryError("gateway descriptor chain_id is required")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise GatewayRegistryError("gateway descriptor chain_id must be an integer") from exc
    if value < 0:
        raise GatewayRegistryError("gateway descriptor chain_id must be non-negative")
    if expected is not None and value != int(expected):
        raise GatewayRegistryError("gateway descriptor chain_id does not match this network")
    return value


def _descriptor_settlement(
    unsigned: dict[str, Any],
    expected: str | None,
    *,
    local_compat: bool,
) -> str:
    raw = unsigned.get("settlement")
    if raw is None and local_compat:
        raw = expected
    if not isinstance(raw, str):
        raise GatewayRegistryError("gateway descriptor settlement is required")
    value = raw.strip()
    if (
        len(value) != 42
        or not value.startswith(("0x", "0X"))
        or any(character not in "0123456789abcdefABCDEF" for character in value[2:])
        or int(value[2:], 16) == 0
    ):
        raise GatewayRegistryError("gateway descriptor settlement must be a non-zero EVM address")
    normalized = "0x" + value[2:].lower()
    if not local_compat and value != normalized:
        raise GatewayRegistryError("gateway descriptor settlement must already be canonical")
    if expected is not None:
        expected_value = str(expected).strip()
        if (
            len(expected_value) != 42
            or not expected_value.startswith(("0x", "0X"))
            or any(
                character not in "0123456789abcdefABCDEF"
                for character in expected_value[2:]
            )
            or int(expected_value[2:], 16) == 0
        ):
            raise GatewayRegistryError("expected gateway settlement must be a non-zero EVM address")
        if normalized != "0x" + expected_value[2:].lower():
            raise GatewayRegistryError("gateway descriptor settlement does not match this network")
    return normalized


def _descriptor_sequence(unsigned: dict[str, Any], *, local_compat: bool, now: int) -> int:
    raw = unsigned.get("sequence")
    if raw is None and local_compat:
        raw = now
    if raw is None:
        raise GatewayRegistryError("gateway descriptor sequence is required")
    return _bounded_int(raw, "sequence", minimum=1, maximum=2**63 - 1)


def _descriptor_expiry(unsigned: dict[str, Any], *, default_ttl: int, local_compat: bool, now: int) -> int:
    configured_ttl = _bounded_int(
        unsigned.get("ttl_seconds", default_ttl),
        "ttl_seconds",
        minimum=MIN_GATEWAY_TTL_SECONDS,
        maximum=MAX_GATEWAY_TTL_SECONDS,
    )
    raw_expiry = unsigned.get("expires_at")
    if raw_expiry is None and local_compat:
        raw_expiry = now + configured_ttl
    if raw_expiry is None:
        raise GatewayRegistryError("gateway descriptor expires_at is required")
    expires_at = _coerce_gateway_descriptor_expiry(raw_expiry)
    remaining = expires_at - now
    if remaining < MIN_GATEWAY_TTL_SECONDS or remaining > MAX_GATEWAY_TTL_SECONDS:
        raise GatewayRegistryError(
            f"gateway descriptor expires_at must be between {MIN_GATEWAY_TTL_SECONDS} and {MAX_GATEWAY_TTL_SECONDS} seconds from now"
        )
    return expires_at


def _gateway_descriptor_expiry_value(unsigned: dict[str, Any]) -> int:
    return _coerce_gateway_descriptor_expiry(unsigned.get("expires_at"))


def _coerce_gateway_descriptor_expiry(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise GatewayRegistryError("gateway descriptor expires_at must be an integer") from exc


def _gateway_signature_timestamp(payload: dict[str, Any]) -> int:
    signature = payload.get("signature")
    if not isinstance(signature, dict):
        raise GatewayRegistryError("gateway descriptor signature is required")
    try:
        return int(signature.get("timestamp"))
    except (TypeError, ValueError) as exc:
        raise GatewayRegistryError("gateway descriptor signature timestamp must be an integer") from exc


def _same_descriptor(
    row: sqlite3.Row,
    *,
    public_key: str,
    public_url: str,
    network_id: str,
    chain_id: int,
    settlement: str,
    expires_at: int,
    status: str,
    weight: int,
    capacity: int,
    latency_ms: int | None,
    success_rate: float | None,
    stake: str | None,
    role: str,
) -> bool:
    return (
        str(row["public_key"]) == public_key
        and str(row["public_url"]) == public_url
        and str(row["network_id"]) == network_id
        and int(row["chain_id"]) == chain_id
        and str(row["settlement"]) == settlement
        and int(row["expires_at"]) == expires_at
        and str(row["status"]) == status
        and int(row["weight"]) == weight
        and int(row["capacity"]) == capacity
        and (int(row["latency_ms"]) if row["latency_ms"] is not None else None) == latency_ms
        and (float(row["success_rate"]) if row["success_rate"] is not None else None) == success_rate
        and (str(row["stake"]) if row["stake"] is not None else None) == stake
        and str(row["role"]) == role
    )


def _json_signature(signature: dict[str, Any] | None) -> str | None:
    if not signature:
        return None
    return json.dumps(signature, ensure_ascii=False, sort_keys=True)


def _json_document(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, sort_keys=True)


def _json_object(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    try:
        payload = json.loads(str(value))
    except (TypeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}
