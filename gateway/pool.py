from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .billing import BillingError, normalize_payment_address
from .identity import IdentityError, peer_id_from_public_key, verify_document
from .p2p import P2PError, parse_peer_address, send_message


POOL_PROTOCOL_VERSION = "mycomesh-pool/0.2"
DEFAULT_POOL_PORT = 9800
DEFAULT_POOL_URL = f"http://127.0.0.1:{DEFAULT_POOL_PORT}"
DEFAULT_NODE_TTL_SECONDS = 30
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 10
MAX_HTTP_BODY_BYTES = 1024 * 1024
POOL_REGISTRATION_PURPOSE = "mycomesh.pool.registration.v1"
POOL_LEAVE_PURPOSE = "mycomesh.pool.leave.v1"
POOL_REPUTATION_PURPOSE = "mycomesh.pool.reputation.v1"
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMIT_MAX_REQUESTS = 120
DEFAULT_POOL_REPUTATION_PATH = ".codex-run/pool-reputation.json"
DEFAULT_HTTP_READ_TIMEOUT_SECONDS = 10
NETWORK_PROFILE_LOCAL = "local"
NETWORK_PROFILE_TESTNET = "testnet"
NETWORK_PROFILE_OPEN = "open"
NETWORK_PROFILES = {NETWORK_PROFILE_LOCAL, NETWORK_PROFILE_TESTNET, NETWORK_PROFILE_OPEN}


class PoolError(RuntimeError):
    pass


@dataclass
class PoolConfig:
    peers: dict[str, dict[str, Any]] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.RLock)
    require_signed_peers: bool = True
    verify_direct_addresses: bool = True
    rate_limits: dict[str, list[float]] = field(default_factory=dict)
    rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS
    rate_limit_max_requests: int = DEFAULT_RATE_LIMIT_MAX_REQUESTS
    bootstrap_pools: list[str] = field(default_factory=list)
    public_url: str | None = None
    reputation: dict[str, dict[str, int]] = field(default_factory=dict)
    reputation_path: str | None = DEFAULT_POOL_REPUTATION_PATH
    http_read_timeout_seconds: float = DEFAULT_HTTP_READ_TIMEOUT_SECONDS
    authorized_reputation_signers: set[str] = field(default_factory=set)
    allow_any_reputation_signer: bool = False
    network_profile: str = NETWORK_PROFILE_TESTNET
    authorized_provider_public_keys: set[str] = field(default_factory=set)
    require_provider_payment_address: bool | None = None

    def __post_init__(self) -> None:
        self.network_profile = normalize_network_profile(self.network_profile)


@dataclass
class PoolHeartbeat:
    stop_event: threading.Event
    thread: threading.Thread

    def stop(self, timeout: float = 2.0) -> None:
        self.stop_event.set()
        self.thread.join(timeout=timeout)


class PoolHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        config: PoolConfig,
    ) -> None:
        super().__init__(server_address, PoolRequestHandler)
        self.config = config


class PoolRequestHandler(BaseHTTPRequestHandler):
    server: PoolHTTPServer

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/health":
            self._write(200, pool_health_payload(self.server.config))
            return
        if parsed.path == "/peers":
            channel = _first_query_value(query, "channel")
            self._write(
                200,
                {
                    "ok": True,
                    "protocol": POOL_PROTOCOL_VERSION,
                    "peers": list_live_peers(self.server.config, channel=channel),
                },
            )
            return
        self._write(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        self.connection.settimeout(float(self.server.config.http_read_timeout_seconds))
        parsed = urllib.parse.urlparse(self.path)
        try:
            self._rate_limit()
            body = self._read_json()
            if parsed.path in {"/join", "/heartbeat"}:
                peer = body.get("peer")
                ttl_seconds = _coerce_positive_int(
                    body.get("ttl_seconds", body.get("ttl")),
                    DEFAULT_NODE_TTL_SECONDS,
                )
                registered = register_peer(
                    self.server.config,
                    peer=peer,
                    ttl_seconds=ttl_seconds,
                    capacity=body.get("capacity"),
                )
                self._write(
                    200,
                    {
                        "ok": True,
                        "protocol": POOL_PROTOCOL_VERSION,
                        "peer": registered,
                        "peers": list_live_peers(self.server.config),
                    },
                )
                return
            if parsed.path == "/reputation":
                feedback = verify_reputation_feedback(
                    body.get("feedback"),
                    audience=self.server.config.public_url,
                    authorized_signers=self.server.config.authorized_reputation_signers,
                    allow_any_signer=self.server.config.allow_any_reputation_signer,
                )
                updated = record_peer_reputation(
                    self.server.config,
                    str(feedback.get("peer_id") or ""),
                    success=bool(feedback.get("success")),
                    failure=bool(feedback.get("failure")),
                    settled=bool(feedback.get("settled")),
                    disputed=bool(feedback.get("disputed")),
                )
                self._write(200, {"ok": True, "peer_id": feedback.get("peer_id"), "reputation": updated})
                return
            if parsed.path == "/leave":
                peer_id = verify_leave_descriptor(body.get("leave"), audience=self.server.config.public_url)
                removed = remove_peer(self.server.config, peer_id)
                self._write(200, {"ok": True, "removed": removed})
                return
        except Exception as exc:
            self._write(400, {"ok": False, "error": str(exc)})
            return
        self._write(404, {"ok": False, "error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _rate_limit(self) -> None:
        client = self.client_address[0] if self.client_address else "unknown"
        now = time.time()
        with self.server.config.lock:
            recent = [
                timestamp
                for timestamp in self.server.config.rate_limits.get(client, [])
                if now - timestamp < self.server.config.rate_limit_window_seconds
            ]
            if len(recent) >= self.server.config.rate_limit_max_requests:
                raise PoolError("rate limit exceeded")
            recent.append(now)
            self.server.config.rate_limits[client] = recent

    def _read_json(self) -> dict[str, Any]:
        content_length = int(self.headers.get("content-length") or "0")
        if content_length > MAX_HTTP_BODY_BYTES:
            raise PoolError("request body too large")
        if content_length <= 0:
            return {}
        payload = self.rfile.read(content_length).decode("utf-8")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise PoolError("request body must be a JSON object")
        return value

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def serve_pool(listen_host: str, listen_port: int, config: PoolConfig | None = None) -> None:
    resolved = config or PoolConfig()
    if resolved.public_url is None:
        resolved.public_url = f"http://{listen_host}:{listen_port}"
    validate_pool_launch_config(resolved)
    load_pool_reputation(resolved)
    with PoolHTTPServer((listen_host, listen_port), resolved) as server:
        server.serve_forever()


def normalize_network_profile(value: str | None) -> str:
    profile = str(value or NETWORK_PROFILE_TESTNET).strip().lower()
    if profile not in NETWORK_PROFILES:
        raise PoolError(f"unknown network profile: {value}")
    return profile


def validate_pool_launch_config(config: PoolConfig) -> None:
    profile = normalize_network_profile(config.network_profile)
    if profile == NETWORK_PROFILE_LOCAL:
        return
    if profile == NETWORK_PROFILE_OPEN:
        raise PoolError("open network profile is reserved until staking, slashing, and disputes are implemented")
    if not config.require_signed_peers:
        raise PoolError(f"{profile} pool requires signed provider descriptors")
    if not config.verify_direct_addresses:
        raise PoolError(f"{profile} pool requires direct address verification")
    if not _requires_provider_payment_address(config):
        raise PoolError(f"{profile} pool requires provider payment addresses")
    if config.allow_any_reputation_signer:
        raise PoolError(f"{profile} pool requires an explicit reputation signer allowlist")
    if not config.authorized_reputation_signers:
        raise PoolError(f"{profile} pool requires --reputation-signer-public-key")
    if profile == NETWORK_PROFILE_TESTNET and not config.authorized_provider_public_keys:
        raise PoolError("testnet pool requires --provider-public-key")


def register_peer(
    config: PoolConfig,
    peer: Any,
    ttl_seconds: int = DEFAULT_NODE_TTL_SECONDS,
    capacity: Any = None,
    now: float | None = None,
    allow_unsigned: bool = False,
) -> dict[str, Any]:
    if not isinstance(peer, dict):
        raise PoolError("peer must be a JSON object")
    peer = verify_peer_descriptor(
        peer,
        require_signed=config.require_signed_peers and not allow_unsigned,
        audience=config.public_url,
    )
    peer_id = str(peer.get("peer_id") or "")
    addresses = normalize_peer_addresses(peer)
    if not peer_id:
        raise PoolError("peer.peer_id is required")
    if not addresses:
        raise PoolError("peer.address or peer.addresses is required")
    payment_address = normalize_pool_payment_address(peer.get("payment_address"))
    validate_provider_admission(config, peer, payment_address)
    if config.verify_direct_addresses:
        verify_peer_addresses(peer_id, addresses)

    current_time = int(now if now is not None else time.time())
    ttl = max(1, int(ttl_seconds))
    normalized = dict(peer)
    normalized["peer_id"] = peer_id
    normalized["address"] = addresses[0]
    normalized["addresses"] = addresses
    normalized["status"] = "online"
    normalized["last_seen"] = current_time
    normalized["ttl_seconds"] = ttl
    normalized["expires_at"] = current_time + ttl
    if payment_address:
        normalized["payment_address"] = payment_address
    if capacity is not None:
        normalized["capacity"] = capacity if isinstance(capacity, dict) else {"value": capacity}
    else:
        normalized.setdefault("capacity", {})

    with config.lock:
        config.peers[peer_id] = normalized
    return dict(normalized)


def validate_provider_admission(config: PoolConfig, peer: dict[str, Any], payment_address: str | None) -> None:
    profile = normalize_network_profile(config.network_profile)
    public_key = str(peer.get("public_key") or "")
    if profile != NETWORK_PROFILE_LOCAL and not config.verify_direct_addresses:
        raise PoolError(f"{profile} pool requires direct address verification")
    if _requires_provider_payment_address(config) and not payment_address:
        raise PoolError(f"peer.payment_address is required for {profile} pool")
    if profile == NETWORK_PROFILE_LOCAL:
        return
    if not public_key:
        raise PoolError("peer.public_key is required")
    if profile == NETWORK_PROFILE_OPEN:
        raise PoolError("open network profile is reserved until staking, slashing, and disputes are implemented")
    allowed = config.authorized_provider_public_keys
    if not allowed:
        raise PoolError("provider public_key allowlist is required for testnet pool")
    if public_key not in allowed:
        raise PoolError("provider public_key is not authorized")


def _requires_provider_payment_address(config: PoolConfig) -> bool:
    if config.require_provider_payment_address is not None:
        return bool(config.require_provider_payment_address)
    return normalize_network_profile(config.network_profile) != NETWORK_PROFILE_LOCAL


def normalize_pool_payment_address(value: Any) -> str | None:
    try:
        return normalize_payment_address(str(value) if value is not None else None)
    except BillingError as exc:
        raise PoolError(str(exc)) from exc


def verify_peer_descriptor(peer: dict[str, Any], require_signed: bool = True, audience: str | None = None) -> dict[str, Any]:
    if not require_signed:
        return dict(peer)
    try:
        unsigned = verify_document(peer, purpose=POOL_REGISTRATION_PURPOSE, audience=audience)
    except IdentityError as exc:
        raise PoolError(f"invalid peer signature: {exc}") from exc
    public_key = str(peer.get("public_key") or unsigned.get("public_key") or "")
    if not public_key:
        signature = peer.get("signature")
        if isinstance(signature, dict):
            public_key = str(signature.get("public_key") or "")
    if not public_key:
        raise PoolError("peer.public_key is required")
    expected_peer_id = peer_id_from_public_key(public_key)
    peer_id = str(unsigned.get("peer_id") or "")
    if peer_id != expected_peer_id:
        raise PoolError("peer_id does not match public_key")
    normalized = dict(unsigned)
    normalized["public_key"] = public_key
    normalized["signature"] = peer["signature"]
    return normalized


def verify_leave_descriptor(leave: Any, audience: str | None = None) -> str:
    if not isinstance(leave, dict):
        raise PoolError("leave must be a signed JSON object")
    try:
        unsigned = verify_document(leave, purpose=POOL_LEAVE_PURPOSE, audience=audience)
    except IdentityError as exc:
        raise PoolError(f"invalid leave signature: {exc}") from exc
    signature = leave.get("signature")
    public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if not public_key:
        raise PoolError("leave public_key is required")
    peer_id = str(unsigned.get("peer_id") or "")
    if not peer_id:
        raise PoolError("leave.peer_id is required")
    if peer_id != peer_id_from_public_key(public_key):
        raise PoolError("leave peer_id does not match public_key")
    return peer_id


def remove_peer(config: PoolConfig, peer_id: str) -> bool:
    if not peer_id:
        return False
    with config.lock:
        return config.peers.pop(peer_id, None) is not None


def list_live_peers(
    config: PoolConfig,
    channel: str | None = None,
    now: float | None = None,
) -> list[dict[str, Any]]:
    current_time = int(now if now is not None else time.time())
    with config.lock:
        _prune_expired_peers(config, current_time)
        peers = []
        for peer in config.peers.values():
            if channel and str(peer.get("channel") or "") != channel:
                continue
            peer_copy = dict(peer)
            peer_copy["reputation"] = peer_reputation_payload(config, str(peer.get("peer_id") or ""))
            peers.append(peer_copy)
    peers.sort(
        key=lambda item: (
            int((item.get("reputation") or {}).get("score") or 0),
            int(item.get("last_seen") or 0),
            str(item.get("peer_id") or ""),
        ),
        reverse=True,
    )
    return peers


def record_peer_reputation(
    config: PoolConfig,
    peer_id: str,
    *,
    success: bool = False,
    failure: bool = False,
    settled: bool = False,
    disputed: bool = False,
) -> dict[str, int]:
    if not peer_id:
        raise PoolError("peer_id is required")
    with config.lock:
        stats = dict(config.reputation.get(peer_id) or {})
        for key, enabled in (
            ("successes", success),
            ("failures", failure),
            ("settlements", settled),
            ("disputes", disputed),
        ):
            if enabled:
                stats[key] = int(stats.get(key) or 0) + 1
        config.reputation[peer_id] = stats
        payload = peer_reputation_payload(config, peer_id)
        save_pool_reputation(config)
        return payload


def peer_reputation_payload(config: PoolConfig, peer_id: str) -> dict[str, int]:
    stats = dict(config.reputation.get(peer_id) or {})
    successes = int(stats.get("successes") or 0)
    failures = int(stats.get("failures") or 0)
    settlements = int(stats.get("settlements") or 0)
    disputes = int(stats.get("disputes") or 0)
    score = (settlements * 20) + (successes * 5) - (failures * 10) - (disputes * 50)
    return {
        "score": max(0, score),
        "successes": successes,
        "failures": failures,
        "settlements": settlements,
        "disputes": disputes,
    }


def verify_peer_addresses(peer_id: str, addresses: list[str], timeout: float = 2.0) -> None:
    direct_addresses = [address for address in addresses if address.startswith("tcp://")]
    if not direct_addresses:
        return
    last_error: Exception | None = None
    for address in direct_addresses:
        try:
            response = send_message(
                parse_peer_address(address),
                {"type": "ping", "request_id": f"pool-probe-{int(time.time())}"},
                timeout=timeout,
            )
        except (P2PError, ValueError) as exc:
            last_error = exc
            continue
        peer = response.get("peer") if isinstance(response, dict) else None
        if isinstance(peer, dict) and str(peer.get("peer_id") or "") == peer_id:
            return
        last_error = PoolError("direct address returned a different peer_id")
    raise PoolError(f"could not verify any direct provider address: {last_error}")


def verify_reputation_feedback(
    feedback: Any,
    audience: str | None = None,
    *,
    authorized_signers: set[str] | None = None,
    allow_any_signer: bool = False,
) -> dict[str, Any]:
    if not isinstance(feedback, dict):
        raise PoolError("feedback must be a signed JSON object")
    try:
        unsigned = verify_document(feedback, purpose=POOL_REPUTATION_PURPOSE, audience=audience)
    except IdentityError as exc:
        raise PoolError(f"invalid reputation signature: {exc}") from exc
    signature = feedback.get("signature")
    signer = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    signers = authorized_signers or set()
    if not signer:
        raise PoolError("reputation signer public_key is required")
    if signers and signer not in signers:
        raise PoolError("reputation signer is not authorized")
    if not signers and not allow_any_signer:
        raise PoolError("reputation signer allowlist is required")
    if not str(unsigned.get("peer_id") or ""):
        raise PoolError("feedback.peer_id is required")
    if not str(unsigned.get("receipt_hash") or ""):
        raise PoolError("feedback.receipt_hash is required")
    if not any(bool(unsigned.get(key)) for key in ("success", "failure", "settled", "disputed")):
        raise PoolError("feedback must include a reputation outcome")
    result = dict(unsigned)
    result["signer_public_key"] = signer
    return result


def load_pool_reputation(config: PoolConfig) -> None:
    if not config.reputation_path:
        return
    path = Path(config.reputation_path)
    if not path.exists():
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if isinstance(payload, dict):
        with config.lock:
            config.reputation = {
                str(peer_id): {str(key): int(value) for key, value in stats.items() if isinstance(value, int)}
                for peer_id, stats in payload.items()
                if isinstance(stats, dict)
            }


def save_pool_reputation(config: PoolConfig) -> None:
    if not config.reputation_path:
        return
    path = Path(config.reputation_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config.reputation, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def pool_health_payload(config: PoolConfig) -> dict[str, Any]:
    peers = list_live_peers(config)
    return {
        "ok": True,
        "protocol": POOL_PROTOCOL_VERSION,
        "network_profile": normalize_network_profile(config.network_profile),
        "live_peers": len(peers),
        "channels": sorted({str(peer.get("channel") or "") for peer in peers if peer.get("channel")}),
        "bootstrap_pools": list(config.bootstrap_pools),
        "authorized_provider_count": len(config.authorized_provider_public_keys),
        "authorized_reputation_signer_count": len(config.authorized_reputation_signers),
    }


def join_pool(
    pool_url: str,
    peer: dict[str, Any],
    ttl_seconds: int = DEFAULT_NODE_TTL_SECONDS,
    capacity: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    return _post_json(
        _pool_endpoint(pool_url, "/join"),
        {
            "peer": peer,
            "ttl_seconds": ttl_seconds,
            "capacity": capacity or {},
        },
        timeout=timeout,
    )


def heartbeat_pool(
    pool_url: str,
    peer: dict[str, Any],
    ttl_seconds: int = DEFAULT_NODE_TTL_SECONDS,
    capacity: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    return _post_json(
        _pool_endpoint(pool_url, "/heartbeat"),
        {
            "peer": peer,
            "ttl_seconds": ttl_seconds,
            "capacity": capacity or {},
        },
        timeout=timeout,
    )


def discover_peers(
    pool_url: str,
    channel: str | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    query = ""
    if channel:
        query = "?" + urllib.parse.urlencode({"channel": channel})
    payload = _get_json(_pool_endpoint(pool_url, "/peers") + query, timeout=timeout)
    peers = payload.get("peers") if isinstance(payload, dict) else None
    if not isinstance(peers, list):
        raise PoolError("pool response did not contain peers")
    return [dict(peer) for peer in peers if isinstance(peer, dict)]


def get_pool_health(pool_url: str, timeout: float = 5.0) -> dict[str, Any]:
    return _get_json(_pool_endpoint(pool_url, "/health"), timeout=timeout)


def start_pool_heartbeat(
    pool_url: str,
    peer_factory: Callable[[], dict[str, Any]],
    ttl_seconds: int = DEFAULT_NODE_TTL_SECONDS,
    interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
    capacity: dict[str, Any] | None = None,
    timeout: float = 5.0,
    initial_delay: float = 0.0,
    on_error: Callable[[Exception], None] | None = None,
) -> PoolHeartbeat:
    stop_event = threading.Event()

    def run() -> None:
        if initial_delay > 0:
            stop_event.wait(initial_delay)
        while not stop_event.is_set():
            try:
                heartbeat_pool(
                    pool_url=pool_url,
                    peer=peer_factory(),
                    ttl_seconds=ttl_seconds,
                    capacity=capacity,
                    timeout=timeout,
                )
            except Exception as exc:
                if on_error is not None:
                    on_error(exc)
            stop_event.wait(max(1.0, interval_seconds))

    thread = threading.Thread(target=run, name="mycomesh-pool-heartbeat", daemon=True)
    thread.start()
    return PoolHeartbeat(stop_event=stop_event, thread=thread)


def _prune_expired_peers(config: PoolConfig, now: int) -> None:
    expired = [
        peer_id
        for peer_id, peer in config.peers.items()
        if int(peer.get("expires_at") or 0) <= now
    ]
    for peer_id in expired:
        config.peers.pop(peer_id, None)


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    return _open_json(request, timeout)


def _get_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    return _open_json(request, timeout)


def _open_json(request: urllib.request.Request, timeout: float) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise PoolError(f"pool returned HTTP {exc.code}: {payload}") from exc
    except urllib.error.URLError as exc:
        raise PoolError(f"failed to reach pool: {exc}") from exc
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise PoolError("pool response must be a JSON object")
    if value.get("ok") is False:
        raise PoolError(str(value.get("error") or "pool request failed"))
    return value


def _pool_endpoint(pool_url: str, path: str) -> str:
    return pool_url.rstrip("/") + path


def _first_query_value(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    value = values[0].strip()
    return value or None


def _coerce_positive_int(value: Any, default: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return result if result > 0 else default


def normalize_peer_addresses(peer: dict[str, Any]) -> list[str]:
    addresses: list[str] = []
    raw_addresses = peer.get("addresses")
    if isinstance(raw_addresses, list):
        addresses.extend(str(item).strip() for item in raw_addresses if str(item).strip())
    address = str(peer.get("address") or "").strip()
    if address:
        addresses.insert(0, address)
    return list(dict.fromkeys(addresses))
