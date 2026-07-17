from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
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
from .browser_cors import parse_allowed_origins
from .chain import ChainError, normalize_address, normalize_bytes32
from .gateway_registry import GatewayRegistryError, normalize_gateway_url
from .identity import IdentityError, create_identity, peer_id_from_public_key, verify_document
from .netio import NetworkIOError, bounded_timeout, read_bounded, text_preview
from .p2p import (
    ADDRESS_PROOF_PURPOSE,
    P2PError,
    parse_peer_address,
    send_message,
    send_secure_message,
)
from .relay import RelayError, parse_relay_address, send_secure_relay_message
from .secure_transport import SecureTransportError, verify_transport_key_binding
from .server_limits import BoundedThreadingMixIn, arm_socket_deadline, bounded_connection_count


POOL_PROTOCOL_VERSION = "mycomesh-pool/0.2"
DEFAULT_POOL_PORT = 9800
DEFAULT_POOL_URL = f"http://127.0.0.1:{DEFAULT_POOL_PORT}"
DEFAULT_NODE_TTL_SECONDS = 30
MAX_NODE_TTL_SECONDS = 300
MAX_PROVIDER_CAPACITY = 1024
MAX_PEER_ADDRESSES = 8
MAX_PEER_ADDRESS_LENGTH = 512
MAX_PEER_DESCRIPTOR_BYTES = 64 * 1024
MAX_PERMISSIONLESS_PEER_DESCRIPTOR_BYTES = 16 * 1024
DEFAULT_POOL_PEER_LIST_LIMIT = 256
MAX_POOL_PEER_LIST_LIMIT = 256
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 10
MAX_HTTP_BODY_BYTES = 1024 * 1024
MAX_POOL_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_POOL_TIMEOUT_SECONDS = 60.0
POOL_REGISTRATION_PURPOSE = "mycomesh.pool.registration.v1"
POOL_LEAVE_PURPOSE = "mycomesh.pool.leave.v1"
POOL_REPUTATION_PURPOSE = "mycomesh.pool.reputation.v1"
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMIT_MAX_REQUESTS = 120
MAX_RATE_LIMIT_WINDOW_SECONDS = 3600
MAX_RATE_LIMIT_REQUESTS = 10_000
DEFAULT_POOL_MAX_RATE_LIMIT_CLIENTS = 4096
MAX_POOL_RATE_LIMIT_CLIENTS = 65_536
DEFAULT_POOL_MAX_PEERS = 1024
MAX_POOL_PEERS = 16_384
DEFAULT_POOL_MAX_ADDRESS_VERIFICATIONS = 8
MAX_POOL_ADDRESS_VERIFICATIONS = 128
DEFAULT_REGISTRATION_NONCE_TTL_SECONDS = 300
MAX_REGISTRATION_NONCE_TTL_SECONDS = 3600
DEFAULT_POOL_MAX_REGISTRATION_NONCES = 65_536
MAX_POOL_REGISTRATION_NONCES = 262_144
RATE_LIMIT_CLEANUP_INTERVAL_SECONDS = 1.0
RATE_LIMIT_PATHS = frozenset(
    {"/join", "/heartbeat", "/reputation", "/leave", "/observed-ip"}
)
DEFAULT_POOL_REPUTATION_PATH = ".codex-run/pool-reputation.json"
DEFAULT_HTTP_READ_TIMEOUT_SECONDS = 10
DEFAULT_POOL_MAX_CONNECTIONS = 128
DEFAULT_POOL_REQUEST_READ_DEADLINE_SECONDS = 15.0
MAX_POOL_REQUEST_READ_DEADLINE_SECONDS = 60.0
NETWORK_PROFILE_LOCAL = "local"
NETWORK_PROFILE_TESTNET = "testnet"
NETWORK_PROFILE_OPEN = "open"
NETWORK_PROFILES = {NETWORK_PROFILE_LOCAL, NETWORK_PROFILE_TESTNET, NETWORK_PROFILE_OPEN}
SETTLEMENT_CAPABILITY_FIELDS = (
    "version",
    "chain_id",
    "contract",
    "pricing_version",
    "pricing_hash",
)


class PoolError(RuntimeError):
    pass


@dataclass
class PoolConfig:
    peers: dict[str, dict[str, Any]] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.RLock)
    require_signed_peers: bool = True
    verify_direct_addresses: bool = True
    rate_limits: dict[str, list[float]] = field(default_factory=dict)
    rate_limit_last_cleanup: float = 0.0
    rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS
    rate_limit_max_requests: int = DEFAULT_RATE_LIMIT_MAX_REQUESTS
    max_rate_limit_clients: int = DEFAULT_POOL_MAX_RATE_LIMIT_CLIENTS
    trust_proxy_headers: bool = False
    max_peers: int = DEFAULT_POOL_MAX_PEERS
    registration_nonces: dict[str, float] = field(default_factory=dict)
    registration_nonce_ttl_seconds: int = DEFAULT_REGISTRATION_NONCE_TTL_SECONDS
    max_registration_nonces: int = DEFAULT_POOL_MAX_REGISTRATION_NONCES
    bootstrap_pools: list[str] = field(default_factory=list)
    public_url: str | None = None
    reputation: dict[str, dict[str, int]] = field(default_factory=dict)
    reputation_path: str | None = DEFAULT_POOL_REPUTATION_PATH
    http_read_timeout_seconds: float = DEFAULT_HTTP_READ_TIMEOUT_SECONDS
    max_connections: int = DEFAULT_POOL_MAX_CONNECTIONS
    max_concurrent_address_verifications: int = DEFAULT_POOL_MAX_ADDRESS_VERIFICATIONS
    request_read_deadline_seconds: float = DEFAULT_POOL_REQUEST_READ_DEADLINE_SECONDS
    _address_verification_slots: Any = field(init=False, repr=False)
    authorized_reputation_signers: set[str] = field(default_factory=set)
    allow_any_reputation_signer: bool = False
    network_profile: str = NETWORK_PROFILE_TESTNET
    authorized_provider_public_keys: set[str] = field(default_factory=set)
    allow_any_signed_provider: bool = False
    trusted_relay_origins: set[str] = field(default_factory=set)
    require_provider_payment_address: bool | None = None
    expected_settlement: dict[str, Any] | None = None
    expected_channel: str | None = None
    cors_allowed_origins: tuple[str, ...] = field(
        default_factory=lambda: parse_allowed_origins(
            os.getenv("MYCOMESH_POOL_CORS_ALLOWED_ORIGINS"),
            setting="MYCOMESH_POOL_CORS_ALLOWED_ORIGINS",
        )
    )

    def __post_init__(self) -> None:
        self.network_profile = normalize_network_profile(self.network_profile)
        self.trusted_relay_origins = {
            normalize_trusted_relay_origin(value)
            for value in self.trusted_relay_origins
        }
        if self.expected_settlement is not None:
            self.expected_settlement = normalize_settlement_capability(
                self.expected_settlement,
                label="PoolConfig.expected_settlement",
            )
        if self.expected_channel is not None:
            self.expected_channel = str(self.expected_channel).strip()
            if not self.expected_channel:
                raise PoolError("PoolConfig.expected_channel must not be empty")
        self.cors_allowed_origins = parse_allowed_origins(
            self.cors_allowed_origins,
            setting="PoolConfig.cors_allowed_origins",
        )
        try:
            self.http_read_timeout_seconds = bounded_timeout(
                self.http_read_timeout_seconds,
                maximum=MAX_POOL_TIMEOUT_SECONDS,
                label="pool HTTP read timeout",
            )
            self.request_read_deadline_seconds = bounded_timeout(
                self.request_read_deadline_seconds,
                maximum=MAX_POOL_REQUEST_READ_DEADLINE_SECONDS,
                label="pool request read deadline",
            )
        except NetworkIOError as exc:
            raise PoolError(str(exc)) from exc
        try:
            self.max_connections = bounded_connection_count(
                self.max_connections,
                label="pool max connections",
            )
            self.max_concurrent_address_verifications = bounded_connection_count(
                self.max_concurrent_address_verifications,
                label="pool concurrent address verifications",
                maximum=MAX_POOL_ADDRESS_VERIFICATIONS,
            )
            self.rate_limit_window_seconds = bounded_connection_count(
                self.rate_limit_window_seconds,
                label="pool rate limit window seconds",
                maximum=MAX_RATE_LIMIT_WINDOW_SECONDS,
            )
            self.rate_limit_max_requests = bounded_connection_count(
                self.rate_limit_max_requests,
                label="pool rate limit max requests",
                maximum=MAX_RATE_LIMIT_REQUESTS,
            )
            self.max_rate_limit_clients = bounded_connection_count(
                self.max_rate_limit_clients,
                label="pool max rate limit clients",
                maximum=MAX_POOL_RATE_LIMIT_CLIENTS,
            )
            self.max_peers = bounded_connection_count(
                self.max_peers,
                label="pool max peers",
                maximum=MAX_POOL_PEERS,
            )
            self.registration_nonce_ttl_seconds = bounded_connection_count(
                self.registration_nonce_ttl_seconds,
                label="pool registration nonce TTL seconds",
                maximum=MAX_REGISTRATION_NONCE_TTL_SECONDS,
            )
            self.max_registration_nonces = bounded_connection_count(
                self.max_registration_nonces,
                label="pool max registration nonces",
                maximum=MAX_POOL_REGISTRATION_NONCES,
            )
        except ValueError as exc:
            raise PoolError(str(exc)) from exc
        if len(self.peers) > self.max_peers:
            raise PoolError("initial pool peer registry exceeds max_peers")
        if len(self.rate_limits) > self.max_rate_limit_clients:
            raise PoolError("initial pool rate limit registry exceeds max_rate_limit_clients")
        if len(self.registration_nonces) > self.max_registration_nonces:
            raise PoolError("initial registration nonce cache exceeds max_registration_nonces")
        self._address_verification_slots = threading.BoundedSemaphore(
            self.max_concurrent_address_verifications
        )


@dataclass
class PoolHeartbeat:
    stop_event: threading.Event
    thread: threading.Thread
    on_success: Callable[[str, dict[str, Any]], None] | None = None

    def stop(self, timeout: float = 2.0) -> None:
        self.stop_event.set()
        self.thread.join(timeout=timeout)


class PoolHTTPServer(BoundedThreadingMixIn, ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        config: PoolConfig,
    ) -> None:
        super().__init__(server_address, PoolRequestHandler)
        self.config = config
        self.configure_connection_limit(config.max_connections)


class PoolRequestHandler(BaseHTTPRequestHandler):
    server: PoolHTTPServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(float(self.server.config.http_read_timeout_seconds))
        self._read_deadline = arm_socket_deadline(
            self.connection,
            float(self.server.config.request_read_deadline_seconds),
        )

    def finish(self) -> None:
        self._cancel_read_deadline()
        super().finish()

    def do_GET(self) -> None:
        self._cancel_read_deadline()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/observed-ip":
            try:
                observed_ipv4 = self._observed_ipv4()
                _enforce_pool_rate_limit(
                    self.server.config,
                    observed_ipv4,
                    path=parsed.path,
                )
            except PoolError as exc:
                self._write(
                    400,
                    {"ok": False, "error": str(exc)},
                    headers={"Cache-Control": "no-store"},
                )
                return
            self._write(
                200,
                {"ok": True, "observed_ipv4": observed_ipv4},
                headers={"Cache-Control": "no-store"},
            )
            return
        cors_headers = self._browser_cors_headers()
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/health":
            self._write(200, pool_health_payload(self.server.config), headers=cors_headers)
            return
        if parsed.path == "/peers":
            channel = _first_query_value(query, "channel")
            limit = min(
                _coerce_positive_int(
                    _first_query_value(query, "limit"),
                    DEFAULT_POOL_PEER_LIST_LIMIT,
                ),
                MAX_POOL_PEER_LIST_LIMIT,
            )
            self._write(
                200,
                {
                    "ok": True,
                    "protocol": POOL_PROTOCOL_VERSION,
                    "peers": list_live_peers(
                        self.server.config,
                        channel=channel,
                        limit=limit,
                    ),
                },
                headers=cors_headers,
            )
            return
        self._write(404, {"ok": False, "error": "not found"}, headers=cors_headers)

    def do_OPTIONS(self) -> None:
        self._cancel_read_deadline()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/observed-ip":
            self._write(404, {"ok": False, "error": "not found"})
            return
        cors_headers = self._browser_cors_headers()
        if parsed.path not in {"/health", "/peers"}:
            self._write(404, {"ok": False, "error": "not found"}, headers=cors_headers)
            return
        origin = str(self.headers.get("origin") or "")
        if origin not in self.server.config.cors_allowed_origins:
            self._write(403, {"ok": False, "error": "CORS origin is not allowed"}, headers=cors_headers)
            return
        requested_method = str(self.headers.get("access-control-request-method") or "").upper()
        if requested_method != "GET":
            self._write(405, {"ok": False, "error": "CORS method is not allowed"}, headers=cors_headers)
            return
        if str(self.headers.get("access-control-request-headers") or "").strip():
            self._write(400, {"ok": False, "error": "CORS request headers are not allowed"}, headers=cors_headers)
            return
        self._write_empty(
            204,
            headers={
                **cors_headers,
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Max-Age": "600",
            },
        )

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            self._rate_limit(parsed.path)
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

    def _rate_limit(self, path: str) -> None:
        socket_client = self.client_address[0] if self.client_address else ""
        real_ip_headers = self.headers.get_all("X-Real-IP") or []
        client = _resolve_rate_limit_client_ip(
            self.server.config,
            socket_client,
            real_ip_headers,
        )
        _enforce_pool_rate_limit(self.server.config, client, path=path)

    def _observed_ipv4(self) -> str:
        socket_client = self.client_address[0] if self.client_address else ""
        real_ip_headers = self.headers.get_all("X-Real-IP") or []
        return _resolve_observed_ipv4(
            self.server.config,
            socket_client,
            real_ip_headers,
        )

    def _read_json(self) -> dict[str, Any]:
        try:
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
        finally:
            self._cancel_read_deadline()

    def _cancel_read_deadline(self) -> None:
        timer = getattr(self, "_read_deadline", None)
        if timer is not None:
            timer.cancel()
            self._read_deadline = None

    def _browser_cors_headers(self) -> dict[str, str]:
        allowed_origins = self.server.config.cors_allowed_origins
        if not allowed_origins:
            return {}
        headers = {"Vary": "Origin"}
        origin = str(self.headers.get("origin") or "")
        if origin in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
        return headers

    def _write(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(data) > MAX_POOL_RESPONSE_BYTES:
            status = 503
            data = json.dumps(
                {"ok": False, "error": "pool response exceeds maximum size"}
            ).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _write_empty(self, status: int, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("content-length", "0")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()


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
    if config.expected_settlement is None or config.expected_channel is None:
        raise PoolError(f"{profile} pool requires a canonical V3 deployment manifest")
    public_url = str(config.public_url or "")
    try:
        canonical_gateway = normalize_gateway_url(
            public_url,
            allow_localhost=False,
        )
    except GatewayRegistryError as exc:
        raise PoolError(f"{profile} pool public_url must be a canonical HTTPS origin") from exc
    if public_url != canonical_gateway[: -len("/v1")]:
        raise PoolError(f"{profile} pool public_url must be a canonical HTTPS origin")
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
    if (
        profile == NETWORK_PROFILE_TESTNET
        and not config.authorized_provider_public_keys
        and not config.allow_any_signed_provider
    ):
        raise PoolError("testnet pool requires --provider-public-key or --allow-any-signed-provider")


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
    peer_size = _json_size(peer)
    if peer_size > MAX_PEER_DESCRIPTOR_BYTES:
        raise PoolError("peer descriptor is too large")
    if (
        config.network_profile == NETWORK_PROFILE_TESTNET
        and config.allow_any_signed_provider
        and peer_size > MAX_PERMISSIONLESS_PEER_DESCRIPTOR_BYTES
    ):
        raise PoolError("permissionless provider descriptor is too large")
    signed_descriptor = dict(peer) if isinstance(peer.get("signature"), dict) else None
    profile = normalize_network_profile(config.network_profile)
    peer = verify_peer_descriptor(
        peer,
        require_signed=profile != NETWORK_PROFILE_LOCAL or (config.require_signed_peers and not allow_unsigned),
        audience=config.public_url,
    )
    validate_peer_settlement_capability(config, peer)
    peer_id = str(peer.get("peer_id") or "")
    addresses = normalize_peer_addresses(peer)
    if not peer_id:
        raise PoolError("peer.peer_id is required")
    if not addresses:
        raise PoolError("peer.address or peer.addresses is required")
    payment_address = normalize_pool_payment_address(peer.get("payment_address"))
    validate_provider_admission(config, peer, payment_address)
    if profile == NETWORK_PROFILE_TESTNET:
        validate_testnet_direct_provider_addresses(addresses)
    if profile == NETWORK_PROFILE_TESTNET and config.allow_any_signed_provider:
        validate_permissionless_provider_addresses(
            addresses,
            trusted_relay_origins=config.trusted_relay_origins,
        )
    if profile == NETWORK_PROFILE_LOCAL:
        ttl = normalize_peer_ttl(ttl_seconds)
        normalized_capacity = normalize_peer_capacity(capacity, required=False)
    else:
        if "ttl_seconds" not in peer:
            raise PoolError("non-local peer descriptor must sign ttl_seconds")
        if "capacity" not in peer:
            raise PoolError("non-local peer descriptor must sign capacity")
        ttl = normalize_peer_ttl(peer.get("ttl_seconds"))
        normalized_capacity = normalize_peer_capacity(peer.get("capacity"), required=True)

    current_time = int(now if now is not None else time.time())
    with config.lock:
        _prune_expired_peers(config, current_time)
        _require_peer_registry_capacity_locked(config, peer_id)

    if profile != NETWORK_PROFILE_LOCAL:
        validate_public_peer_addresses(addresses)
        validate_secure_peer_transports(addresses, profile=profile)
        binding = peer.get("transport_key")
        if not isinstance(binding, dict):
            raise PoolError("non-local peer descriptor must sign transport_key")
        try:
            verify_transport_key_binding(
                binding,
                expected_peer_id=peer_id,
                expected_identity_public_key=str(peer.get("public_key") or ""),
            )
        except SecureTransportError as exc:
            raise PoolError(f"invalid peer transport_key: {exc}") from exc
    if profile == NETWORK_PROFILE_TESTNET and config.allow_any_signed_provider:
        _claim_permissionless_registration_nonce(
            config,
            signed_descriptor,
            now=current_time,
        )
    relay_only = bool(addresses) and all(
        urllib.parse.urlsplit(address).scheme in {"myco+relay", "myco+relays"}
        for address in addresses
    )
    if profile == NETWORK_PROFILE_TESTNET and relay_only:
        validate_trusted_relay_addresses(addresses, config.trusted_relay_origins)
    if config.verify_direct_addresses:
        if not config._address_verification_slots.acquire(blocking=False):
            raise PoolError("pool address verification capacity reached")
        try:
            verification_kwargs = {
                "public_key": str(peer.get("public_key") or "") or None,
                "transport_key": peer.get("transport_key") if isinstance(peer.get("transport_key"), dict) else None,
                "audience": config.public_url,
                "require_signed": profile != NETWORK_PROFILE_LOCAL or bool(peer.get("signature")),
            }
            if relay_only and profile != NETWORK_PROFILE_LOCAL:
                verify_peer_relay_addresses(
                    peer_id,
                    addresses,
                    trusted_relay_origins=config.trusted_relay_origins,
                    **verification_kwargs,
                )
            else:
                verify_peer_addresses(peer_id, addresses, **verification_kwargs)
        finally:
            config._address_verification_slots.release()

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
    normalized["capacity"] = normalized_capacity
    if signed_descriptor is not None:
        normalized["descriptor"] = signed_descriptor

    with config.lock:
        _prune_expired_peers(config, current_time)
        _require_peer_registry_capacity_locked(config, peer_id)
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
    if config.allow_any_signed_provider:
        return
    allowed = config.authorized_provider_public_keys
    if not allowed:
        raise PoolError("provider public_key allowlist is required for testnet pool")
    if public_key not in allowed:
        raise PoolError("provider public_key is not authorized")


def normalize_settlement_capability(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PoolError(f"{label} must be a JSON object")
    missing = [field for field in SETTLEMENT_CAPABILITY_FIELDS if field not in value]
    if missing:
        raise PoolError(f"{label} is missing required fields: {', '.join(missing)}")

    normalized: dict[str, Any] = {}
    for field in ("version", "chain_id", "pricing_version"):
        field_value = value[field]
        if type(field_value) is not int:
            raise PoolError(f"{label}.{field} must be an integer")
        if field_value <= 0:
            raise PoolError(f"{label}.{field} must be positive")
        normalized[field] = field_value
    if normalized["version"] != 3:
        raise PoolError(f"{label}.version must be 3")
    try:
        normalized["contract"] = normalize_address(value["contract"])
        normalized["pricing_hash"] = normalize_bytes32(value["pricing_hash"])
    except ChainError as exc:
        raise PoolError(f"invalid {label}: {exc}") from exc
    return normalized


def validate_peer_settlement_capability(config: PoolConfig, peer: dict[str, Any]) -> None:
    expected = config.expected_settlement
    if expected is None:
        return
    actual = normalize_settlement_capability(
        peer.get("settlement"),
        label="peer.settlement",
    )
    for field in SETTLEMENT_CAPABILITY_FIELDS:
        if actual[field] != expected[field]:
            raise PoolError(
                f"peer.settlement.{field} does not match the Bridge V3 deployment manifest"
            )
    expected_channel = config.expected_channel
    if expected_channel is not None and peer.get("channel") != expected_channel:
        raise PoolError(
            "peer.channel does not match the Bridge V3 deployment manifest"
        )


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
    limit: int | None = None,
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
    if limit is None:
        return peers
    return peers[: max(0, int(limit))]


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


def verify_peer_addresses(
    peer_id: str,
    addresses: list[str],
    timeout: float = 2.0,
    *,
    public_key: str | None = None,
    transport_key: dict[str, Any] | None = None,
    audience: str | None = None,
    require_signed: bool | None = None,
) -> None:
    direct_addresses = [
        address
        for address in addresses
        if urllib.parse.urlsplit(address).scheme in {"tcp", "myco+tcp"}
    ]
    if not direct_addresses:
        return
    signed_proof_required = bool(public_key) if require_signed is None else bool(require_signed)
    if signed_proof_required and not public_key:
        raise PoolError("provider public_key is required for signed address proof")
    last_error: Exception | None = None
    for address in direct_addresses:
        request_id = f"pool-probe-{secrets.token_hex(16)}"
        try:
            parsed_address = parse_peer_address(address)
            probe = {"type": "ping", "request_id": request_id, "audience": audience}
            if parsed_address.secure:
                if not public_key or not isinstance(transport_key, dict):
                    raise PoolError("secure provider address requires public_key and transport_key")
                response = send_secure_message(
                    parsed_address,
                    probe,
                    timeout=timeout,
                    sender=create_identity(),
                    recipient_binding=transport_key,
                    expected_recipient_peer_id=peer_id,
                    expected_recipient_public_key=public_key,
                )
            else:
                response = send_message(parsed_address, probe, timeout=timeout)
        except (P2PError, PoolError, ValueError) as exc:
            last_error = exc
            continue
        if str(response.get("request_id") or "") != request_id:
            last_error = PoolError("direct address proof returned a different request_id")
            continue
        verified_response = response
        if signed_proof_required:
            try:
                verified_response = verify_document(
                    response,
                    purpose=ADDRESS_PROOF_PURPOSE,
                    audience=audience,
                )
            except IdentityError as exc:
                last_error = PoolError(f"invalid signed address proof: {exc}")
                continue
            signature = response.get("signature")
            signer = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
            if signer != public_key:
                last_error = PoolError("address proof was signed by a different provider key")
                continue
            try:
                signer_peer_id = peer_id_from_public_key(signer)
            except IdentityError as exc:
                last_error = PoolError(f"invalid address proof public_key: {exc}")
                continue
            if signer_peer_id != peer_id:
                last_error = PoolError("address proof key does not match peer_id")
                continue
        response_peer = verified_response.get("peer") if isinstance(verified_response, dict) else None
        if (
            isinstance(response_peer, dict)
            and str(response_peer.get("peer_id") or "") == peer_id
            and (not public_key or str(response_peer.get("public_key") or "") == public_key)
        ):
            return
        last_error = PoolError("direct address returned a different peer_id")
    raise PoolError(f"could not verify any direct provider address: {last_error}")


def validate_testnet_direct_provider_addresses(addresses: list[str]) -> None:
    for address in addresses:
        parsed = urllib.parse.urlsplit(address)
        if parsed.scheme not in {"tcp", "myco+tcp"}:
            continue
        hostname = str(parsed.hostname or "").split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise PoolError(
                "testnet direct provider DNS names are not allowed; use literal public IPs"
            ) from exc
        if not _is_public_unicast_ip(ip):
            raise PoolError(
                "testnet direct provider address is non-public; use a literal public IP"
            )



def validate_permissionless_provider_addresses(
    addresses: list[str],
    *,
    trusted_relay_origins: set[str] | None = None,
) -> None:
    schemes = {urllib.parse.urlsplit(address).scheme for address in addresses}
    if schemes == {"myco+relays"}:
        validate_trusted_relay_addresses(addresses, trusted_relay_origins or set())
        return
    if schemes != {"myco+tcp"}:
        raise PoolError(
            "permissionless testnet provider must use only myco+tcp:// direct addresses "
            "or only trusted myco+relays:// addresses"
        )
    for address in addresses:
        parsed = urllib.parse.urlsplit(address)
        hostname = str(parsed.hostname or "").split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise PoolError(
                "permissionless testnet direct provider addresses must use literal IPs; DNS names are not allowed"
            ) from exc
        if not _is_public_unicast_ip(ip):
            raise PoolError(
                "permissionless testnet direct provider requires myco+tcp:// literal public IP addresses"
            )


def normalize_trusted_relay_origin(value: str) -> str:
    raw = str(value or "").strip()
    try:
        canonical = normalize_gateway_url(raw, allow_localhost=False)[: -len("/v1")]
    except GatewayRegistryError as exc:
        raise PoolError("trusted Relay origin must be a canonical HTTPS origin") from exc
    if raw != canonical:
        raise PoolError("trusted Relay origin must be a canonical HTTPS origin")
    return canonical


def relay_address_origin(address: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(address)
        port = parsed.port
    except ValueError as exc:
        raise PoolError(f"invalid Relay address: {exc}") from exc
    if parsed.scheme != "myco+relays" or not parsed.hostname or port is None:
        raise PoolError("testnet relay-only providers require myco+relays:// addresses")
    hostname = str(parsed.hostname).rstrip(".").lower()
    authority = hostname if port == 443 else f"{hostname}:{port}"
    return normalize_trusted_relay_origin(f"https://{authority}")


def validate_trusted_relay_addresses(addresses: list[str], trusted_relay_origins: set[str]) -> None:
    if not trusted_relay_origins:
        raise PoolError("testnet relay-only providers require a trusted Relay origin allowlist")
    for address in addresses:
        origin = relay_address_origin(address)
        if origin not in trusted_relay_origins:
            raise PoolError(f"Relay origin is not trusted: {origin}")


def verify_peer_relay_addresses(
    peer_id: str,
    addresses: list[str],
    timeout: float = 5.0,
    *,
    public_key: str | None,
    transport_key: dict[str, Any] | None,
    audience: str | None,
    trusted_relay_origins: set[str] | None,
    require_signed: bool = True,
) -> None:
    if not public_key or not isinstance(transport_key, dict):
        raise PoolError("secure Relay address proof requires public_key and transport_key")
    if trusted_relay_origins is not None:
        validate_trusted_relay_addresses(addresses, trusted_relay_origins)
    probe_identity = create_identity()
    last_error: Exception | None = None
    for value in addresses:
        request_id = f"pool-relay-probe-{secrets.token_hex(16)}"
        try:
            address = parse_relay_address(value)
            if address.peer_id != peer_id:
                raise PoolError("Relay address path does not match peer_id")
            response = send_secure_relay_message(
                address,
                {"type": "ping", "request_id": request_id, "audience": audience},
                timeout=timeout,
                sender=probe_identity,
                recipient_binding=transport_key,
                expected_recipient_public_key=public_key,
            )
            if response.get("type") != "pong" or response.get("ok") is not True:
                raise PoolError("Relay address proof did not return a successful pong")
            if str(response.get("request_id") or "") != request_id:
                raise PoolError("Relay address proof returned a different request_id")
            verified = (
                verify_document(response, purpose=ADDRESS_PROOF_PURPOSE, audience=audience)
                if require_signed
                else response
            )
            signature = response.get("signature")
            signer = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
            if signer != public_key or peer_id_from_public_key(signer) != peer_id:
                raise PoolError("Relay address proof was signed by a different provider key")
            response_peer = verified.get("peer") if isinstance(verified, dict) else None
            if not isinstance(response_peer, dict):
                raise PoolError("Relay address proof is missing its provider descriptor")
            if str(response_peer.get("peer_id") or "") != peer_id:
                raise PoolError("Relay address proof returned a different peer_id")
            if str(response_peer.get("public_key") or "") != public_key:
                raise PoolError("Relay address proof returned a different provider key")
            proof_binding = response_peer.get("transport_key")
            if not isinstance(proof_binding, dict):
                raise PoolError("Relay address proof is missing its transport_key")
            verify_transport_key_binding(
                proof_binding,
                expected_peer_id=peer_id,
                expected_identity_public_key=public_key,
            )
            return
        except (IdentityError, P2PError, PoolError, RelayError, SecureTransportError, ValueError) as exc:
            last_error = exc
    raise PoolError(f"could not verify any Relay provider address: {last_error}")


def validate_public_peer_addresses(addresses: list[str]) -> None:
    for address in addresses:
        if len(address) > MAX_PEER_ADDRESS_LENGTH:
            raise PoolError("peer address is too long")
        try:
            parsed = urllib.parse.urlsplit(address)
            port = parsed.port
        except ValueError as exc:
            raise PoolError(f"invalid peer address: {exc}") from exc
        if parsed.scheme not in {
            "tcp",
            "relay",
            "relays",
            "myco+tcp",
            "myco+relay",
            "myco+relays",
        }:
            raise PoolError("non-local peer addresses must use an explicit supported transport scheme")
        hostname = str(parsed.hostname or "").rstrip(".").lower()
        if not hostname or port is None:
            raise PoolError("peer address must include a host and port")
        if parsed.username is not None or parsed.password is not None:
            raise PoolError("peer address must not include userinfo")
        if parsed.query or parsed.fragment:
            raise PoolError("peer address must not include a query or fragment")
        if parsed.scheme in {"tcp", "myco+tcp"} and parsed.path not in {"", "/"}:
            raise PoolError("direct peer address must not include a path")
        if _is_metadata_hostname(hostname):
            raise PoolError("peer address targets a cloud metadata host")
        try:
            answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise PoolError(f"peer address host could not be resolved: {exc}") from exc
        resolved = {str(answer[4][0]).split("%", 1)[0] for answer in answers if answer[4]}
        if not resolved:
            raise PoolError("peer address host did not resolve to an address")
        for value in resolved:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError as exc:
                raise PoolError("peer address resolved to an invalid IP address") from exc
            if not _is_public_unicast_ip(ip):
                raise PoolError(f"non-local peer address resolved to non-public IP {ip}")


def validate_secure_peer_transports(addresses: list[str], *, profile: str) -> None:
    insecure = [
        address
        for address in addresses
        if urllib.parse.urlsplit(address).scheme in {"tcp", "relay", "relays"}
    ]
    if insecure:
        raise PoolError(
            f"{profile} registration rejects plaintext tcp:// and relay:// transports; "
            "use myco+tcp://, myco+relay://, or myco+relays://"
        )
    unsupported = [
        address
        for address in addresses
        if urllib.parse.urlsplit(address).scheme not in {"myco+tcp", "myco+relay", "myco+relays"}
    ]
    if unsupported:
        raise PoolError(f"{profile} registration requires a secure Myco transport scheme")


def normalize_peer_ttl(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PoolError("peer ttl_seconds must be an integer")
    ttl = value
    if ttl < 1 or ttl > MAX_NODE_TTL_SECONDS:
        raise PoolError(f"peer ttl_seconds must be between 1 and {MAX_NODE_TTL_SECONDS}")
    return ttl


def normalize_peer_capacity(value: Any, *, required: bool) -> dict[str, Any]:
    if value is None or value == {}:
        if required:
            raise PoolError("peer capacity.max_concurrency is required")
        return {}
    if not isinstance(value, dict):
        raise PoolError("peer capacity must be a JSON object")
    max_concurrency = value.get("max_concurrency")
    if not isinstance(max_concurrency, int) or isinstance(max_concurrency, bool):
        raise PoolError("peer capacity.max_concurrency must be an integer")
    if max_concurrency < 1 or max_concurrency > MAX_PROVIDER_CAPACITY:
        raise PoolError(f"peer capacity.max_concurrency must be between 1 and {MAX_PROVIDER_CAPACITY}")
    normalized = dict(value)
    normalized["max_concurrency"] = max_concurrency
    return normalized


def _is_metadata_hostname(hostname: str) -> bool:
    return hostname in {
        "metadata",
        "metadata.google.internal",
        "instance-data",
    } or hostname.endswith(".metadata.google.internal")


def _is_public_unicast_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_global
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def _json_size(value: Any) -> int:
    try:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PoolError("peer descriptor must be JSON serializable") from exc
    return len(payload)


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
    profile = normalize_network_profile(config.network_profile)
    if profile == NETWORK_PROFILE_LOCAL:
        admission_mode = "local"
    elif profile == NETWORK_PROFILE_TESTNET and config.allow_any_signed_provider:
        admission_mode = "any_signed"
    else:
        admission_mode = "allowlist"
    return {
        "ok": True,
        "protocol": POOL_PROTOCOL_VERSION,
        "network_profile": profile,
        "provider_admission_mode": admission_mode,
        "allow_any_signed_provider": bool(config.allow_any_signed_provider),
        "max_peers": config.max_peers,
        "live_peers": len(peers),
        "channels": sorted({str(peer.get("channel") or "") for peer in peers if peer.get("channel")}),
        "bootstrap_pools": list(config.bootstrap_pools),
        "authorized_provider_count": len(config.authorized_provider_public_keys),
        "trusted_relay_origins": sorted(config.trusted_relay_origins),
        "authorized_reputation_signer_count": len(config.authorized_reputation_signers),
        "expected_channel": config.expected_channel,
        "settlement": (
            dict(config.expected_settlement)
            if config.expected_settlement is not None
            else None
        ),
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
    require_signed: bool | None = None,
) -> list[dict[str, Any]]:
    query = ""
    if channel:
        query = "?" + urllib.parse.urlencode({"channel": channel})
    payload = _get_json(_pool_endpoint(pool_url, "/peers") + query, timeout=timeout)
    peers = payload.get("peers") if isinstance(payload, dict) else None
    if not isinstance(peers, list):
        raise PoolError("pool response did not contain peers")
    signed_required = not is_loopback_pool_url(pool_url) if require_signed is None else bool(require_signed)
    return [
        verify_discovered_peer(peer, pool_url=pool_url, require_signed=signed_required)
        for peer in peers
        if isinstance(peer, dict)
    ]


def verify_discovered_peer(
    peer: dict[str, Any],
    *,
    pool_url: str,
    require_signed: bool = True,
) -> dict[str, Any]:
    descriptor = peer.get("descriptor")
    if not isinstance(descriptor, dict):
        if isinstance(peer.get("signature"), dict):
            descriptor = peer
        elif require_signed:
            raise PoolError("pool returned a peer without a signed descriptor")
        else:
            return dict(peer)
    verified = verify_peer_descriptor(descriptor, require_signed=True, audience=pool_url)
    if str(peer.get("peer_id") or "") != str(verified.get("peer_id") or ""):
        raise PoolError("pool peer_id does not match its signed descriptor")
    if normalize_peer_addresses(peer) != normalize_peer_addresses(verified):
        raise PoolError("pool peer addresses do not match the signed descriptor")
    if require_signed and ("ttl_seconds" not in verified or "capacity" not in verified):
        raise PoolError("signed peer descriptor must bind ttl_seconds and capacity")
    if require_signed:
        addresses = normalize_peer_addresses(verified)
        validate_secure_peer_transports(addresses, profile="remote")
        transport_key = verified.get("transport_key")
        if not isinstance(transport_key, dict):
            raise PoolError("signed remote peer descriptor must bind transport_key")
        try:
            verify_transport_key_binding(
                transport_key,
                expected_peer_id=str(verified.get("peer_id") or ""),
                expected_identity_public_key=str(verified.get("public_key") or ""),
            )
        except SecureTransportError as exc:
            raise PoolError(f"invalid remote peer transport_key: {exc}") from exc
    for field_name in ("channel", "model", "public_key", "transport_key", "ttl_seconds", "capacity"):
        if field_name in verified and peer.get(field_name) != verified.get(field_name):
            raise PoolError(f"pool peer {field_name} does not match the signed descriptor")
    if "payment_address" in verified:
        signed_payment_address = normalize_pool_payment_address(verified.get("payment_address"))
        returned_payment_address = normalize_pool_payment_address(peer.get("payment_address"))
        if returned_payment_address != signed_payment_address:
            raise PoolError("pool peer payment_address does not match the signed descriptor")
        verified["payment_address"] = signed_payment_address

    normalized = dict(verified)
    runtime_fields = ["status", "last_seen", "expires_at", "reputation"]
    if not require_signed:
        runtime_fields.extend(["ttl_seconds", "capacity"])
    for field_name in runtime_fields:
        if field_name in peer:
            normalized[field_name] = peer[field_name]
    normalized["descriptor"] = dict(descriptor)
    return normalized


def is_loopback_pool_url(pool_url: str) -> bool:
    try:
        hostname = urllib.parse.urlsplit(pool_url).hostname
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname.rstrip(".").lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def get_pool_health(pool_url: str, timeout: float = 5.0) -> dict[str, Any]:
    return _get_json(_pool_endpoint(pool_url, "/health"), timeout=timeout)


def get_pool_observed_ip(pool_url: str, timeout: float = 5.0) -> str:
    parsed = urllib.parse.urlsplit(str(pool_url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PoolError("pool URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise PoolError("pool URL must not include userinfo")
    if parsed.query or parsed.fragment:
        raise PoolError("pool URL must not include a query or fragment")
    if parsed.path not in {"", "/"}:
        raise PoolError("pool URL must be a canonical origin")
    if not is_loopback_pool_url(pool_url) and parsed.scheme != "https":
        raise PoolError("remote pool observation requires canonical HTTPS")
    payload = _get_json_no_redirect(
        _pool_endpoint(pool_url, "/observed-ip"), timeout=timeout
    )
    return _require_global_ipv4(payload.get("observed_ipv4"), "pool observed_ipv4")

def start_pool_heartbeat(
    pool_url: str,
    peer_factory: Callable[[], dict[str, Any]],
    ttl_seconds: int = DEFAULT_NODE_TTL_SECONDS,
    interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
    capacity: dict[str, Any] | None = None,
    timeout: float = 5.0,
    initial_delay: float = 0.0,
    on_error: Callable[[Exception], None] | None = None,
    on_success: Callable[[str, dict[str, Any]], None] | None = None,
) -> PoolHeartbeat:
    stop_event = threading.Event()

    def report_error(exc: Exception) -> None:
        if on_error is None:
            return
        try:
            on_error(exc)
        except Exception:
            # A diagnostic callback must not terminate the heartbeat worker.
            pass

    def run() -> None:
        if initial_delay > 0:
            stop_event.wait(initial_delay)
        while not stop_event.is_set():
            try:
                response = heartbeat_pool(
                    pool_url=pool_url,
                    peer=peer_factory(),
                    ttl_seconds=ttl_seconds,
                    capacity=capacity,
                    timeout=timeout,
                )
            except Exception as exc:
                report_error(exc)
            else:
                if on_success is not None:
                    try:
                        on_success(pool_url, response)
                    except Exception as exc:
                        report_error(exc)
            stop_event.wait(max(1.0, interval_seconds))

    thread = threading.Thread(target=run, name="mycomesh-pool-heartbeat", daemon=True)
    thread.start()
    return PoolHeartbeat(stop_event=stop_event, thread=thread, on_success=on_success)


def _claim_permissionless_registration_nonce(
    config: PoolConfig,
    signed_descriptor: dict[str, Any] | None,
    *,
    now: int,
) -> None:
    signature = signed_descriptor.get("signature") if isinstance(signed_descriptor, dict) else None
    if not isinstance(signature, dict):
        raise PoolError("permissionless provider descriptor signature is required")
    signer = str(signature.get("public_key") or "").lower()
    nonce = str(signature.get("nonce") or "")
    try:
        nonce_bytes = bytes.fromhex(nonce)
    except ValueError as exc:
        raise PoolError("provider descriptor signature nonce must be 16 bytes hex") from exc
    if not signer or len(nonce) != 32 or len(nonce_bytes) != 16:
        raise PoolError("provider descriptor signature nonce must be 16 bytes hex")
    cache_key = f"{signer}:{nonce.lower()}"
    with config.lock:
        expired = [
            key
            for key, expires_at in config.registration_nonces.items()
            if float(expires_at) <= now
        ]
        for key in expired:
            config.registration_nonces.pop(key, None)
        if cache_key in config.registration_nonces:
            raise PoolError("provider descriptor signature nonce was already used")
        if len(config.registration_nonces) >= config.max_registration_nonces:
            raise PoolError("registration nonce cache capacity reached")
        config.registration_nonces[cache_key] = now + config.registration_nonce_ttl_seconds


def _require_peer_registry_capacity_locked(config: PoolConfig, peer_id: str) -> None:
    if peer_id not in config.peers and len(config.peers) >= config.max_peers:
        raise PoolError("pool peer registry capacity reached")


def _prune_expired_peers(config: PoolConfig, now: int) -> None:
    expired = [
        peer_id
        for peer_id, peer in config.peers.items()
        if int(peer.get("expires_at") or 0) <= now
    ]
    for peer_id in expired:
        config.peers.pop(peer_id, None)


def _resolve_rate_limit_client_ip(
    config: PoolConfig,
    socket_client: str,
    real_ip_headers: list[str],
) -> str:
    try:
        socket_ip = ipaddress.ip_address(str(socket_client).split("%", 1)[0])
    except ValueError as exc:
        raise PoolError("socket client address is not a valid IP") from exc
    if not config.trust_proxy_headers or not (socket_ip.is_loopback or socket_ip.is_private):
        return str(socket_ip)
    if len(real_ip_headers) != 1:
        raise PoolError("trusted proxy request requires exactly one X-Real-IP header")
    candidate = str(real_ip_headers[0]).strip()
    if not candidate or "," in candidate or "%" in candidate:
        raise PoolError("X-Real-IP must contain exactly one valid IP address")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise PoolError("X-Real-IP must contain exactly one valid IP address") from exc


def _resolve_observed_ipv4(
    config: PoolConfig,
    socket_client: str,
    real_ip_headers: list[str],
) -> str:
    try:
        socket_ip = ipaddress.ip_address(str(socket_client).split("%", 1)[0])
    except ValueError as exc:
        raise PoolError("socket client address is not a valid IP") from exc
    candidate: Any = socket_ip
    if config.trust_proxy_headers and (socket_ip.is_loopback or socket_ip.is_private):
        if len(real_ip_headers) != 1:
            raise PoolError("trusted loopback proxy requires exactly one X-Real-IP header")
        raw_candidate = str(real_ip_headers[0]).strip()
        if not raw_candidate or "," in raw_candidate or "%" in raw_candidate:
            raise PoolError("X-Real-IP must contain exactly one global IPv4 address")
        candidate = raw_candidate
    return _require_global_ipv4(candidate, "observed client IP")


def _require_global_ipv4(value: Any, label: str) -> str:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise PoolError(f"{label} must be a valid global IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not _is_public_unicast_ip(address):
        raise PoolError(f"{label} must be a global IPv4 address")
    return str(address)

def _enforce_pool_rate_limit(
    config: PoolConfig,
    client: str,
    *,
    path: str = "/join",
    now: float | None = None,
) -> None:
    current_time = float(now if now is not None else time.time())
    bucket = path if path in RATE_LIMIT_PATHS else "/other"
    client_key = f"{bucket}|{client}"
    with config.lock:
        cleanup_interval = min(
            RATE_LIMIT_CLEANUP_INTERVAL_SECONDS,
            float(config.rate_limit_window_seconds),
        )
        if current_time - config.rate_limit_last_cleanup >= cleanup_interval:
            expired_clients = [
                known_client
                for known_client, timestamps in config.rate_limits.items()
                if not timestamps
                or current_time - max(timestamps) >= config.rate_limit_window_seconds
            ]
            for known_client in expired_clients:
                config.rate_limits.pop(known_client, None)
            config.rate_limit_last_cleanup = current_time

        recent = [
            timestamp
            for timestamp in config.rate_limits.get(client_key, [])
            if current_time - timestamp < config.rate_limit_window_seconds
        ]
        if len(recent) >= config.rate_limit_max_requests:
            raise PoolError("rate limit exceeded")
        if client_key not in config.rate_limits and len(config.rate_limits) >= config.max_rate_limit_clients:
            raise PoolError("rate limit client registry capacity reached")
        recent.append(current_time)
        config.rate_limits[client_key] = recent


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    return _open_json(request, timeout, opener=_POOL_NO_REDIRECT_OPENER)


def _get_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    return _open_json(request, timeout, opener=_POOL_NO_REDIRECT_OPENER)


class _NoPoolRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_POOL_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoPoolRedirectHandler())


def _get_json_no_redirect(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    return _open_json(request, timeout, opener=_POOL_NO_REDIRECT_OPENER)


def _open_json(
    request: urllib.request.Request, timeout: float, opener: Any | None = None
) -> dict[str, Any]:
    try:
        resolved_timeout = bounded_timeout(timeout, maximum=MAX_POOL_TIMEOUT_SECONDS, label="pool timeout")
    except NetworkIOError as exc:
        raise PoolError(str(exc)) from exc
    deadline = time.monotonic() + resolved_timeout
    open_request = urllib.request.urlopen if opener is None else opener.open
    try:
        with open_request(request, timeout=resolved_timeout) as response:
            payload = read_bounded(
                response,
                maximum=MAX_POOL_RESPONSE_BYTES,
                label="pool response",
                deadline=deadline,
            ).decode(
                "utf-8", errors="replace"
            )
    except urllib.error.HTTPError as exc:
        try:
            payload = read_bounded(
                exc,
                maximum=MAX_POOL_RESPONSE_BYTES,
                label="pool error response",
                deadline=deadline,
            ).decode(
                "utf-8", errors="replace"
            )
        except NetworkIOError as limit_exc:
            raise PoolError(str(limit_exc)) from exc
        finally:
            exc.close()
        raise PoolError(f"pool returned HTTP {exc.code}: {text_preview(payload)}") from exc
    except NetworkIOError as exc:
        raise PoolError(str(exc)) from exc
    except urllib.error.URLError as exc:
        raise PoolError(f"failed to reach pool: {exc}") from exc
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise PoolError("pool response must be a JSON object")
    if value.get("ok") is False:
        raise PoolError(text_preview(str(value.get("error") or "pool request failed")))
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
    normalized = list(dict.fromkeys(addresses))
    if len(normalized) > MAX_PEER_ADDRESSES:
        raise PoolError(f"peer may advertise at most {MAX_PEER_ADDRESSES} addresses")
    if any(len(item) > MAX_PEER_ADDRESS_LENGTH for item in normalized):
        raise PoolError("peer address is too long")
    return normalized
