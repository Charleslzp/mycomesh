from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None


DEFAULT_ROUTE_STATE_PATH = ".codex-run/route-state.json"


@dataclass
class RouteState:
    peers: dict[str, dict[str, Any]] = field(default_factory=dict)
    leases: dict[str, dict[str, Any]] = field(default_factory=dict)


def load_route_state(path: str | Path = DEFAULT_ROUTE_STATE_PATH) -> RouteState:
    resolved = Path(path)
    with _route_state_lock(resolved, exclusive=False):
        if not resolved.exists():
            return RouteState()
        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return RouteState()
    peers = payload.get("peers") if isinstance(payload, dict) else None
    leases = payload.get("leases") if isinstance(payload, dict) else None
    return RouteState(
        peers=peers if isinstance(peers, dict) else {},
        leases=leases if isinstance(leases, dict) else {},
    )


def save_route_state(state: RouteState, path: str | Path = DEFAULT_ROUTE_STATE_PATH) -> None:
    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with _route_state_lock(resolved, exclusive=True):
        if resolved.exists():
            try:
                existing = json.loads(resolved.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = {}
            if isinstance(existing, dict):
                state = _merge_route_state(
                    RouteState(
                        peers=existing.get("peers") if isinstance(existing.get("peers"), dict) else {},
                        leases=existing.get("leases") if isinstance(existing.get("leases"), dict) else {},
                    ),
                    state,
                )
        _prune_leases(state)
        payload = json.dumps({"peers": state.peers, "leases": state.leases}, indent=2, sort_keys=True) + "\n"
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(resolved.parent),
            prefix=f".{resolved.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temp_name = file.name
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_name, resolved)


def rank_peers(peers: list[dict[str, Any]], state: RouteState | None = None) -> list[dict[str, Any]]:
    route_state = state or RouteState()

    def score(peer: dict[str, Any]) -> tuple[float, int]:
        peer_id = str(peer.get("peer_id") or "")
        stats = route_state.peers.get(peer_id, {})
        failures = int(stats.get("failures") or 0)
        successes = int(stats.get("successes") or 0)
        accepted = int(stats.get("accepted") or 0)
        settled = int(stats.get("settled") or 0)
        disputed = int(stats.get("disputed") or 0)
        latency_ms = float(stats.get("latency_ms") or 0)
        capacity = _capacity(peer)
        active = active_leases(route_state, peer_id)
        available = max(0, capacity - active)
        value = (
            (successes * 20.0)
            + (accepted * 30.0)
            + (settled * 50.0)
            + (available * 2.0)
            - (failures * 75.0)
            - (disputed * 150.0)
            - (latency_ms / 1000.0)
        )
        return value, int(peer.get("last_seen") or 0)

    return sorted((dict(peer) for peer in peers), key=score, reverse=True)


def record_route_success(state: RouteState, peer_id: str, latency_ms: int) -> None:
    stats = _stats(state, peer_id)
    stats["successes"] = int(stats.get("successes") or 0) + 1
    stats["latency_ms"] = latency_ms
    stats["last_success_at"] = int(time.time())


def record_route_failure(state: RouteState, peer_id: str, error: Exception | str) -> None:
    stats = _stats(state, peer_id)
    stats["failures"] = int(stats.get("failures") or 0) + 1
    stats["last_error"] = str(error)
    stats["last_failure_at"] = int(time.time())


def record_route_acceptance(state: RouteState, peer_id: str) -> None:
    stats = _stats(state, peer_id)
    stats["accepted"] = int(stats.get("accepted") or 0) + 1
    stats["last_accepted_at"] = int(time.time())


def record_route_settlement(state: RouteState, peer_id: str) -> None:
    stats = _stats(state, peer_id)
    stats["settled"] = int(stats.get("settled") or 0) + 1
    stats["last_settled_at"] = int(time.time())


def record_route_dispute(state: RouteState, peer_id: str, reason: Exception | str) -> None:
    stats = _stats(state, peer_id)
    stats["disputed"] = int(stats.get("disputed") or 0) + 1
    stats["last_dispute"] = str(reason)
    stats["last_disputed_at"] = int(time.time())


def reserve_peer(state: RouteState, peer: dict[str, Any], ttl_seconds: int = 180) -> str:
    peer_id = str(peer.get("peer_id") or "")
    if not peer_id:
        raise ValueError("peer_id is required")
    _prune_leases(state)
    capacity = _capacity(peer)
    if active_leases(state, peer_id) >= capacity:
        raise ValueError(f"peer capacity is exhausted: {peer_id}")
    lease_id = f"lease_{peer_id}_{secrets.token_hex(8)}"
    state.leases[lease_id] = {
        "peer_id": peer_id,
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + max(1, ttl_seconds),
    }
    return lease_id


def release_peer(state: RouteState, lease_id: str | None) -> None:
    if lease_id:
        state.leases.pop(lease_id, None)


def active_leases(state: RouteState, peer_id: str) -> int:
    _prune_leases(state)
    return sum(1 for lease in state.leases.values() if str(lease.get("peer_id") or "") == peer_id)


def _stats(state: RouteState, peer_id: str) -> dict[str, Any]:
    return state.peers.setdefault(peer_id, {})


def _prune_leases(state: RouteState) -> None:
    now = int(time.time())
    expired = [lease_id for lease_id, lease in state.leases.items() if int(lease.get("expires_at") or 0) <= now]
    for lease_id in expired:
        state.leases.pop(lease_id, None)


def _capacity(peer: dict[str, Any]) -> int:
    capacity = peer.get("capacity")
    if isinstance(capacity, dict):
        try:
            value = int(capacity.get("max_concurrency") or capacity.get("value") or 1)
        except (TypeError, ValueError):
            value = 1
        return max(1, value)
    return 1


def _merge_route_state(base: RouteState, overlay: RouteState) -> RouteState:
    peers = dict(base.peers)
    for peer_id, stats in overlay.peers.items():
        current = peers.get(peer_id)
        if not isinstance(current, dict):
            peers[peer_id] = dict(stats) if isinstance(stats, dict) else {}
            continue
        if not isinstance(stats, dict):
            continue
        merged = dict(current)
        for key, value in stats.items():
            if key in {"successes", "failures", "accepted", "settled", "disputed"}:
                merged[key] = max(int(current.get(key) or 0), int(value or 0))
            elif key.startswith("last_") or key == "latency_ms":
                merged[key] = value
            else:
                merged.setdefault(key, value)
        peers[peer_id] = merged
    leases = dict(base.leases)
    leases.update(overlay.leases)
    return RouteState(peers=peers, leases=leases)


class _route_state_lock:
    def __init__(self, path: Path, exclusive: bool) -> None:
        self.path = path
        self.exclusive = exclusive
        self.file: Any = None

    def __enter__(self) -> None:
        if fcntl is None:
            return None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = (self.path.with_suffix(self.path.suffix + ".lock")).open("a+", encoding="utf-8")
        operation = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
        fcntl.flock(self.file.fileno(), operation)
        return None

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.file is None or fcntl is None:
            return None
        try:
            fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        finally:
            self.file.close()
        return None
