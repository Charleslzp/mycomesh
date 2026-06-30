from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .identity import IdentityError, peer_id_from_public_key, verify_document


DEFAULT_GATEWAY_REGISTRY_DB = ".codex-run/mycomesh-gateways.sqlite3"
GATEWAY_REGISTRATION_PURPOSE = "mycomesh.gateway.register"


class GatewayRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayRecord:
    node_id: str
    public_key: str
    public_url: str
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "public_key": self.public_key,
            "public_url": self.public_url,
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
                    status TEXT NOT NULL,
                    weight INTEGER NOT NULL DEFAULT 1,
                    capacity INTEGER NOT NULL DEFAULT 0,
                    latency_ms INTEGER,
                    success_rate REAL,
                    stake TEXT,
                    role TEXT NOT NULL DEFAULT 'gateway_bridge',
                    signature_json TEXT,
                    last_seen INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )

    def register(self, payload: dict[str, Any], *, ttl_seconds: int = 300, require_signed: bool = True) -> GatewayRecord:
        now = int(time.time())
        unsigned = verify_gateway_registration(payload) if require_signed else dict(payload)
        public_key = _registration_public_key(payload, unsigned)
        node_id = str(unsigned.get("node_id") or peer_id_from_public_key(public_key))
        if node_id != peer_id_from_public_key(public_key):
            raise GatewayRegistryError("gateway node_id does not match public_key")
        public_url = normalize_gateway_url(str(unsigned.get("public_url") or ""))
        status = _gateway_status(unsigned.get("status") or "active")
        weight = max(1, int(unsigned.get("weight") or 1))
        capacity = max(0, int(unsigned.get("capacity") or 0))
        latency_ms = _optional_non_negative_int(unsigned.get("latency_ms"), "latency_ms")
        success_rate = _optional_success_rate(unsigned.get("success_rate"))
        stake = str(unsigned.get("stake")) if unsigned.get("stake") is not None else None
        role = str(unsigned.get("role") or "gateway_bridge")
        expires_at = now + max(1, int(unsigned.get("ttl_seconds") or ttl_seconds))
        signature = payload.get("signature") if isinstance(payload.get("signature"), dict) else None
        with self._connect() as conn:
            conn.execute(
                (
                    "INSERT INTO gateways(node_id, public_key, public_url, status, weight, capacity, latency_ms, success_rate, stake, role, "
                    "signature_json, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET public_key = excluded.public_key, public_url = excluded.public_url, "
                    "status = excluded.status, weight = excluded.weight, capacity = excluded.capacity, latency_ms = excluded.latency_ms, "
                    "success_rate = excluded.success_rate, stake = excluded.stake, role = excluded.role, signature_json = excluded.signature_json, "
                    "last_seen = excluded.last_seen, expires_at = excluded.expires_at"
                ),
                (
                    node_id,
                    public_key,
                    public_url,
                    status,
                    weight,
                    capacity,
                    latency_ms,
                    success_rate,
                    stake,
                    role,
                    _json_signature(signature),
                    now,
                    expires_at,
                ),
            )
        return GatewayRecord(
            node_id=node_id,
            public_key=public_key,
            public_url=public_url,
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
        )

    def list_gateways(self, *, include_inactive: bool = False, now: int | None = None, limit: int = 20) -> list[GatewayRecord]:
        current_time = int(now if now is not None else time.time())
        query = "SELECT * FROM gateways"
        params: list[object] = []
        if not include_inactive:
            query += " WHERE status = 'active' AND expires_at >= ?"
            params.append(current_time)
        query += " ORDER BY weight DESC, COALESCE(success_rate, 1.0) DESC, COALESCE(latency_ms, 2147483647) ASC, last_seen DESC LIMIT ?"
        params.append(max(1, int(limit)))
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


def verify_gateway_registration(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return verify_document(payload, purpose=GATEWAY_REGISTRATION_PURPOSE)
    except IdentityError as exc:
        raise GatewayRegistryError(f"invalid gateway signature: {exc}") from exc


def normalize_gateway_url(public_url: str) -> str:
    value = str(public_url or "").strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise GatewayRegistryError("gateway public_url must be an http(s) URL")
    if parsed.scheme != "https" and not _is_localhost(parsed.hostname or ""):
        raise GatewayRegistryError("gateway public_url must use https outside localhost")
    path = parsed.path.rstrip("/")
    if path and path != "/v1":
        raise GatewayRegistryError("gateway public_url path must be empty or /v1")
    return value + ("" if path == "/v1" else "/v1")


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
        status=str(row["status"]),
        weight=int(row["weight"]),
        capacity=int(row["capacity"]),
        latency_ms=int(row["latency_ms"]) if row["latency_ms"] is not None else None,
        success_rate=float(row["success_rate"]) if row["success_rate"] is not None else None,
        stake=str(row["stake"]) if row["stake"] else None,
        role=str(row["role"]),
        last_seen=int(row["last_seen"]),
        expires_at=int(row["expires_at"]),
        signature={},
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
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _json_signature(signature: dict[str, Any] | None) -> str | None:
    if not signature:
        return None
    import json

    return json.dumps(signature, ensure_ascii=False, sort_keys=True)
