from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import socketserver
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .attestation import AttestationError, build_provider_settlement_attestation, settlement_response_hash
from .codex_app_backend import CODEX_TESTNET_METERING_MODE
from .channel_policy import (
    CODEX_BACKEND_POLICY,
    CODEX_CHANNEL_ID,
    MYCOMESH_TESTNET_NETWORK_ID,
    require_enabled_channel_binding,
)
from .identity import (
    IdentityError,
    NodeIdentity,
    peer_id_from_public_key,
    sign_document,
    verify_document,
)
from .pricing import DEFAULT_CHANNEL, ChannelPricing, load_pricing_config, quote_usage
from .native_metering import (
    CanonicalNativeRequest,
    NativeMeteringError,
    NativeMeteringRequestError,
    canonicalize_native_request,
    native_inference_request_hash,
    validate_metered_result_shape,
)
from .pricing_source import channel_pricing_snapshot
from .reservation import (
    ReservationError,
    evm_session_authorization_digest,
    inference_request_hash,
    verify_eoa_session_authorization,
    verify_payment_reservation,
)
from .billing import normalize_payment_address, usdc_to_units
from .session_protocol import (
    SessionProtocolError,
    verify_session_authorization,
    verify_session_request,
)
from .netio import NetworkIOError, bounded_timeout, read_bounded, text_preview
from .replay import DEFAULT_REPLAY_DB, MAX_SQL_INTEGER, ReplayError, ReplayStore
from .secure_transport import (
    MAX_SECURE_FRAME_BYTES,
    MemoryReplayStore,
    ReplayStoreLike,
    SecureTransportError,
    TransportKeyPair,
    VerifiedEnvelopeMetadata,
    generate_transport_key,
    open_frame,
    read_secure_frame,
    seal_json_frame,
    verify_frame_metadata,
    verify_transport_key_binding,
)
from .server_limits import BoundedThreadingMixIn, arm_socket_deadline, bounded_connection_count


PROTOCOL_VERSION = "mycomesh-p2p/0.2"
DEFAULT_P2P_PORT = 9700
DEFAULT_PUBLIC_MODEL_ID = "mycomesh-codex-standard-v1"
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_GATEWAY_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_GATEWAY_ERROR_RESPONSE_BYTES = 64 * 1024
MAX_GATEWAY_HEALTH_RESPONSE_BYTES = 64 * 1024
GATEWAY_READINESS_LEASE_SECONDS = 2.0
MAX_P2P_NETWORK_TIMEOUT_SECONDS = 300.0
DEFAULT_P2P_MAX_CONNECTIONS = 128
DEFAULT_P2P_REQUEST_READ_DEADLINE_SECONDS = 15.0
MAX_P2P_REQUEST_READ_DEADLINE_SECONDS = 60.0
INFERENCE_REQUEST_PURPOSE = "mycomesh.inference.request.v1"
PROVIDER_RESPONSE_PURPOSE = "mycomesh.inference.provider_response.v1"
ADDRESS_PROOF_PURPOSE = "mycomesh.provider.address_proof.v1"
P2P_SECURE_REQUEST_PURPOSE = "mycomesh.p2p.request.v1"
# Address probes are intentionally distinct from inference requests.  Relays
# may permit this narrowly-scoped purpose without granting a consumer access
# to the paid inference path.
P2P_ADDRESS_PROBE_PURPOSE = "mycomesh.p2p.address_probe.v1"
P2P_SECURE_RESPONSE_PURPOSE = "mycomesh.p2p.response.v1"
DEFAULT_MAX_PEER_BOOK_SIZE = 256
MAX_PEER_BOOK_SIZE = 1024
MAX_PEER_DESCRIPTOR_BYTES = 16 * 1024
MAX_RESERVE_INPUT_TOKENS = 1_000_000
MAX_RESERVE_OUTPUT_TOKENS = 1_000_000
SETTLEMENT_INCLUSION_BUFFER_SECONDS = 60
MAX_REQUEST_ID_BYTES = 128
CANONICAL_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CANONICAL_SIGNATURE_NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")
P2P_NATIVE_INFERENCE_SCHEMA = "mycomesh.gateway.p2p-native.v1"
P2P_NATIVE_EXECUTION_SCHEMA = "mycomesh.p2p.native-execution.v1"
# V4 inference is an off-chain execution path.  Keep a durable result claim
# separate from the authorization replay keys so a lost transport response can
# be replayed byte-for-byte without running the model a second time.
V4_EXECUTION_SCOPE = "p2p.v4.inference.execution"
V4_EXECUTION_RESULT_SCHEMA = "mycomesh.p2p.v4-execution-result.v1"
# Version two makes the short-lived request deadline transport-mutable.  Keep
# the version in the durable envelope so a Provider restart can distinguish a
# legacy cache from a result written by the current replay contract.
V4_SESSION_REQUEST_HASH_VERSION = 2
V4_LEGACY_SESSION_REQUEST_HASH_VERSION = 1
V4_SESSION_PROGRESS_SCOPE = "p2p.v4.session.progress"
# Refresh a cached outer response before the normal 300-second transport
# signature window expires, leaving room for Relay/Consumer clock skew.
V4_RESPONSE_REFRESH_SIGNATURE_AGE_SECONDS = 240


class P2PError(RuntimeError):
    pass


class P2PRetryableError(P2PError):
    """Transient Provider infrastructure error safe for the same request retry."""

    pass


def _verify_secure_request_metadata(
    config: "ProviderConfig", frame: bytes
) -> VerifiedEnvelopeMetadata:
    """Verify routing metadata for either supported secure request purpose."""
    last_error: SecureTransportError | None = None
    for purpose in (P2P_SECURE_REQUEST_PURPOSE, P2P_ADDRESS_PROBE_PURPOSE):
        try:
            return verify_frame_metadata(
                frame,
                expected_purpose=purpose,
                expected_recipient_peer_id=config.peer_id,
                expected_recipient_public_key=(
                    config.identity.public_key if config.identity is not None else None
                ),
            )
        except SecureTransportError as exc:
            last_error = exc
    raise P2PError(f"invalid secure P2P request: {last_error}")


@dataclass(frozen=True)
class PeerAddress:
    host: str
    port: int
    scheme: str = "tcp"

    @property
    def value(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def uri(self) -> str:
        return f"{self.scheme}://{self.value}"

    @property
    def secure(self) -> bool:
        return self.scheme == "myco+tcp"


@dataclass
class ProviderConfig:
    peer_id: str
    channel: str
    agent_id: str
    agent_key: str
    gateway_url: str
    model: str
    advertise_host: str
    advertise_port: int
    network_id: str | None = MYCOMESH_TESTNET_NETWORK_ID
    channel_id: str | None = CODEX_CHANNEL_ID
    backend_policy: str | None = CODEX_BACKEND_POLICY
    timeout_seconds: float = 120.0
    peer_book: dict[str, dict[str, Any]] = field(default_factory=dict)
    identity: NodeIdentity | None = None
    require_signed_requests: bool = True
    allow_any_signed_consumer: bool = False
    authorized_consumers: set[str] = field(default_factory=set)
    payment_address: str | None = None
    seen_requests: dict[str, float] = field(default_factory=dict)
    require_payment_reservation: bool = True
    pricing_config_path: str | None = None
    pricing_hash: str | None = None
    reserve_input_tokens: int = 8000
    reserve_output_tokens: int = 2000
    replay_store_path: str | None = None
    replay_ttl_seconds: int = 600
    max_concurrency: int = 1
    socket_timeout_seconds: float = 10.0
    max_connections: int = DEFAULT_P2P_MAX_CONNECTIONS
    request_read_deadline_seconds: float = DEFAULT_P2P_REQUEST_READ_DEADLINE_SECONDS
    allow_remote_gateway_https: bool = False
    max_peer_book_size: int = DEFAULT_MAX_PEER_BOOK_SIZE
    network_profile: str = "local"
    settlement_rpc_url: str | None = None
    settlement_contract: str | None = None
    settlement_chain_id: int | None = None
    settlement_version: int = 2
    session_v4_enabled: bool = False
    session_v4_verify_onchain: bool = True
    session_v4_cache_seconds: int = 30
    pricing_version: int | None = None
    settlement_confirmations: int = 6
    settlement_rpc_timeout_seconds: float = 20.0
    evm_identity_path: str | None = None
    transport_key_lifetime_seconds: int = 24 * 60 * 60
    _seen_lock: threading.Lock = field(init=False, repr=False)
    _peer_book_lock: threading.Lock = field(init=False, repr=False)
    _semaphore: threading.BoundedSemaphore = field(init=False, repr=False)
    _replay_store: ReplayStore | None = field(default=None, init=False, repr=False)
    _transport_key: TransportKeyPair | None = field(default=None, init=False, repr=False)
    _transport_keys: dict[str, TransportKeyPair] = field(default_factory=dict, init=False, repr=False)
    _transport_key_lock: Any = field(init=False, repr=False)
    _transport_replay_store: ReplayStoreLike | None = field(default=None, init=False, repr=False)
    _gateway_readiness_lock: threading.Lock = field(init=False, repr=False)
    _gateway_readiness_until: float = field(default=0.0, init=False, repr=False)
    _gateway_readiness_max_output_token_cap: int = field(default=0, init=False, repr=False)
    _bridge_registration_lock: threading.Lock = field(init=False, repr=False)
    _bridge_registration_required: bool = field(default=False, init=False, repr=False)
    _bridge_registration_valid_until: dict[str, float] = field(default_factory=dict, init=False, repr=False)
    _session_v4_lock: threading.Lock = field(init=False, repr=False)
    _session_v4_cache: dict[str, dict[str, Any]] = field(default_factory=dict, init=False, repr=False)
    _session_v4_progress: dict[str, tuple[int, int]] = field(default_factory=dict, init=False, repr=False)
    _execution_owner: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._transport_key_lock = threading.RLock()
        # A process-unique owner prevents two Provider processes sharing a
        # replay database from ever completing each other's execution claim.
        self._execution_owner = f"{self.peer_id}:{uuid.uuid4().hex}"
        self.payment_address = normalize_payment_address(self.payment_address)
        if self.evm_identity_path is not None:
            self.evm_identity_path = str(self.evm_identity_path).strip() or None
        if self.evm_identity_path is not None and "\x00" in self.evm_identity_path:
            raise P2PError("evm_identity_path contains a NUL byte")
        self.reserve_input_tokens = _bounded_config_int(
            self.reserve_input_tokens,
            "reserve_input_tokens",
            MAX_RESERVE_INPUT_TOKENS,
        )
        self.reserve_output_tokens = _bounded_config_int(
            self.reserve_output_tokens,
            "reserve_output_tokens",
            MAX_RESERVE_OUTPUT_TOKENS,
        )
        try:
            self.timeout_seconds = bounded_timeout(
                self.timeout_seconds,
                maximum=MAX_P2P_NETWORK_TIMEOUT_SECONDS,
                label="timeout_seconds",
            )
            self.socket_timeout_seconds = bounded_timeout(
                self.socket_timeout_seconds,
                maximum=MAX_P2P_NETWORK_TIMEOUT_SECONDS,
                label="socket_timeout_seconds",
            )
            self.settlement_rpc_timeout_seconds = bounded_timeout(
                self.settlement_rpc_timeout_seconds,
                maximum=MAX_P2P_NETWORK_TIMEOUT_SECONDS,
                label="settlement_rpc_timeout_seconds",
            )
            self.request_read_deadline_seconds = bounded_timeout(
                self.request_read_deadline_seconds,
                maximum=MAX_P2P_REQUEST_READ_DEADLINE_SECONDS,
                label="request_read_deadline_seconds",
            )
        except NetworkIOError as exc:
            raise P2PError(str(exc)) from exc
        try:
            self.max_connections = bounded_connection_count(
                self.max_connections,
                label="max_connections",
            )
        except ValueError as exc:
            raise P2PError(str(exc)) from exc
        self.max_concurrency = max(1, int(self.max_concurrency))
        self.max_peer_book_size = int(self.max_peer_book_size)
        if self.max_peer_book_size < 1 or self.max_peer_book_size > MAX_PEER_BOOK_SIZE:
            raise P2PError(f"max_peer_book_size must be between 1 and {MAX_PEER_BOOK_SIZE}")
        if not isinstance(self.peer_book, dict):
            raise P2PError("peer_book must be a mapping")
        if any(not isinstance(peer, dict) for peer in self.peer_book.values()):
            raise P2PError("peer_book entries must be JSON objects")
        if any(_json_size(peer) > MAX_PEER_DESCRIPTOR_BYTES for peer in self.peer_book.values()):
            raise P2PError("peer_book entry is too large")
        if len(self.peer_book) > self.max_peer_book_size:
            retained = sorted(
                self.peer_book.items(),
                key=lambda item: (int(item[1].get("last_seen") or 0), item[0]),
                reverse=True,
            )[: self.max_peer_book_size]
            self.peer_book = dict(retained)
        self._semaphore = threading.BoundedSemaphore(self.max_concurrency)
        self._seen_lock = threading.Lock()
        self._peer_book_lock = threading.Lock()
        self._gateway_readiness_lock = threading.Lock()
        self._bridge_registration_lock = threading.Lock()
        self._session_v4_lock = threading.Lock()
        validate_gateway_url(
            self.gateway_url,
            allow_remote_https=self.allow_remote_gateway_https,
        )
        if self.identity is not None and self.peer_id != self.identity.peer_id:
            raise P2PError("provider peer_id must match the configured identity public key")
        profile = str(self.network_profile or "").strip().lower()
        if profile not in {"local", "testnet", "open"}:
            raise P2PError(f"unknown network profile: {self.network_profile}")
        self.network_profile = profile
        if bool(self.settlement_rpc_url) != bool(self.settlement_contract):
            raise P2PError("settlement_rpc_url and settlement_contract must be configured together")
        self.settlement_version = int(self.settlement_version)
        if self.settlement_version not in {2, 3, 4}:
            raise P2PError("settlement_version must be 2, 3, or 4")
        self.session_v4_enabled = bool(self.session_v4_enabled or self.settlement_version == 4)
        if isinstance(self.session_v4_cache_seconds, bool):
            raise P2PError("session_v4_cache_seconds must be an integer")
        self.session_v4_cache_seconds = int(self.session_v4_cache_seconds)
        if self.session_v4_cache_seconds < 0 or self.session_v4_cache_seconds > 24 * 60 * 60:
            raise P2PError("session_v4_cache_seconds must be between 0 and 86400")
        if self.pricing_version is not None:
            self.pricing_version = int(self.pricing_version)
            if self.pricing_version <= 0 or self.pricing_version > (1 << 64) - 1:
                raise P2PError("pricing_version must be a positive uint64")
        if self.settlement_chain_id is not None and int(self.settlement_chain_id) <= 0:
            raise P2PError("settlement_chain_id must be positive")
        if self.settlement_chain_id is not None:
            self.settlement_chain_id = int(self.settlement_chain_id)
        self.settlement_confirmations = int(self.settlement_confirmations)
        if self.settlement_confirmations < 0 or self.settlement_confirmations > 10_000:
            raise P2PError("settlement_confirmations must be between 0 and 10000")
        if self.settlement_version in {3, 4} and (not self.settlement_rpc_url or not self.settlement_contract):
            raise P2PError(f"Settlement V{self.settlement_version} requires settlement_rpc_url and settlement_contract")
        if self.settlement_version in {3, 4} and self.settlement_chain_id is None:
            raise P2PError(f"Settlement V{self.settlement_version} requires settlement_chain_id")
        if self.settlement_version in {3, 4} and not self.require_signed_requests:
            raise P2PError(f"Settlement V{self.settlement_version} requires signed inference requests")
        if self.settlement_version == 3 and not self.require_payment_reservation:
            raise P2PError("Settlement V3 requires payment reservations")
        if self.settlement_version in {3, 4} and self.identity is None:
            raise P2PError(f"Settlement V{self.settlement_version} requires a provider identity")
        if self.settlement_version in {3, 4} and not self.payment_address:
            raise P2PError(f"Settlement V{self.settlement_version} requires a provider payment_address")
        if profile != "local" and self.identity is None:
            raise P2PError(f"{profile} secure provider transport requires a provider identity")
        if profile != "local" and not self.require_signed_requests:
            raise P2PError(f"{profile} secure provider transport requires signed requests")
        if profile != "local" and self.settlement_version not in {3, 4}:
            raise P2PError(f"{profile} Provider requires Settlement V3 or V4")
        if profile != "local" and self.settlement_version == 3 and self.settlement_confirmations < 6:
            raise P2PError(f"{profile} Provider requires at least 6 settlement confirmations")
        if profile != "local" and (
            not isinstance(self.pricing_hash, str) or not self.pricing_hash.strip()
        ):
            raise P2PError(f"{profile} Provider requires an explicit pricing_hash")
        if profile != "local":
            try:
                from .chain import ChainError, normalize_bytes32

                self.pricing_hash = normalize_bytes32(self.pricing_hash)
            except (ChainError, ValueError) as exc:
                raise P2PError(
                    f"{profile} Provider pricing_hash must be a valid bytes32"
                ) from exc
            try:
                require_enabled_channel_binding(
                    network_id=self.network_id,
                    channel_id=self.channel_id,
                    channel=self.channel,
                    backend_policy=self.backend_policy,
                    label=f"{profile} Provider",
                )
            except ValueError as exc:
                raise P2PError(str(exc)) from exc
        self._bridge_registration_required = profile != "local"
        if (self.settlement_version in {3, 4} or profile != "local") and not self.replay_store_path:
            self.replay_store_path = DEFAULT_REPLAY_DB
        if self.replay_store_path:
            self._replay_store = ReplayStore(self.replay_store_path)
        if isinstance(self.transport_key_lifetime_seconds, bool):
            raise P2PError("transport_key_lifetime_seconds must be an integer")
        self.transport_key_lifetime_seconds = int(self.transport_key_lifetime_seconds)
        if self.transport_key_lifetime_seconds < 300 or self.transport_key_lifetime_seconds > 30 * 24 * 60 * 60:
            raise P2PError("transport_key_lifetime_seconds must be between 300 and 2592000")
        if self.identity is not None:
            try:
                self.ensure_transport_key(force=True)
            except SecureTransportError as exc:
                raise P2PError(f"failed to initialize secure provider transport: {exc}") from exc
            self._transport_replay_store = self._replay_store or MemoryReplayStore()

    def ensure_transport_key(
        self,
        *,
        rotate: bool = True,
        force: bool = False,
    ) -> TransportKeyPair | None:
        if self.identity is None:
            return None
        now = int(time.time())
        with self._transport_key_lock:
            self._transport_keys = {
                key_id: key
                for key_id, key in self._transport_keys.items()
                if int(key.binding.get("expires_at") or 0) > now
            }
            current = self._transport_key
            remaining = int(current.binding.get("expires_at") or 0) - now if current is not None else 0
            rotation_window = min(3600, max(60, self.transport_key_lifetime_seconds // 5))
            if force or current is None or (rotate and remaining <= rotation_window):
                current = generate_transport_key(
                    self.identity,
                    lifetime_seconds=self.transport_key_lifetime_seconds,
                )
                self._transport_key = current
                self._transport_keys[str(current.binding["key_id"])] = current
            elif str(current.binding.get("key_id") or "") not in self._transport_keys:
                self._transport_keys[str(current.binding["key_id"])] = current
            return current

    def accepted_transport_bindings(self, *, rotate: bool = True) -> list[dict[str, Any]]:
        current = self.ensure_transport_key(rotate=rotate)
        if current is None:
            return []
        with self._transport_key_lock:
            current_key_id = str(current.binding.get("key_id") or "")
            keys = sorted(
                self._transport_keys.values(),
                key=lambda item: str(item.binding.get("key_id") or "") != current_key_id,
            )
            return [dict(item.binding) for item in keys]

    def transport_key_for_frame(
        self,
        frame: bytes,
        *,
        metadata: VerifiedEnvelopeMetadata | None = None,
    ) -> TransportKeyPair:
        if self.identity is None:
            raise P2PError("secure provider transport is not configured")
        if metadata is None:
            metadata = _verify_secure_request_metadata(self, frame)
        with self._transport_key_lock:
            key = self._transport_keys.get(metadata.recipient_key_id)
        if key is None:
            raise P2PError("secure P2P request targets an unknown or expired transport key")
        return key


class ProviderTCPServer(
    BoundedThreadingMixIn,
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        config: ProviderConfig,
    ) -> None:
        super().__init__(server_address, P2PRequestHandler)
        self.config = config
        self.configure_connection_limit(config.max_connections)
        if self.config.advertise_port == 0:
            self.config.advertise_port = int(self.server_address[1])


class P2PRequestHandler(socketserver.StreamRequestHandler):
    server: ProviderTCPServer

    def handle(self) -> None:
        self.connection.settimeout(float(self.server.config.socket_timeout_seconds))
        read_deadline = arm_socket_deadline(
            self.connection,
            float(self.server.config.request_read_deadline_seconds),
        )
        secure_request = False
        try:
            first = self.rfile.peek(1)[:1]
            secure_request = first != b"{"
            if secure_request:
                frame = read_secure_frame(self.rfile)
            else:
                raw = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
        except Exception:
            return
        finally:
            read_deadline.cancel()
        if secure_request:
            try:
                self.wfile.write(handle_secure_frame(self.server.config, frame))
                self.wfile.flush()
            except Exception:
                # Before decryption there is no authenticated reply key, so fail closed.
                return
            return
        if len(raw) > MAX_MESSAGE_BYTES:
            self._write({"type": "error", "ok": False, "error": "message too large"})
            return
        try:
            message = json.loads(raw.decode("utf-8"))
            if self.server.config.network_profile != "local" and message.get("type") != "ping":
                raise P2PError("plaintext requests are disabled; use myco+tcp://")
            response = handle_message(self.server.config, message)
        except Exception as exc:
            response = {"type": "error", "ok": False, "error": str(exc)}
        self._write(response)

    def _write(self, response: dict[str, Any]) -> None:
        payload = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
        if len(payload) > MAX_MESSAGE_BYTES:
            payload = json.dumps(
                {"type": "error", "ok": False, "error": "response too large"}
            ).encode("utf-8") + b"\n"
        self.wfile.write(payload)


def serve_provider(
    listen_host: str,
    listen_port: int,
    config: ProviderConfig,
    bootstrap_peers: list[PeerAddress] | None = None,
    on_started: Callable[[ProviderConfig], None] | None = None,
) -> None:
    with ProviderTCPServer((listen_host, listen_port), config) as server:
        serving = threading.Thread(
            target=server.serve_forever,
            name="mycomesh-provider-server",
            daemon=True,
        )
        serving.start()
        try:
            if on_started is not None:
                on_started(config)
            for peer in bootstrap_peers or []:
                try:
                    announce_to_peer(config, peer, timeout=5)
                except P2PError:
                    pass
            serving.join()
        finally:
            server.shutdown()
            serving.join(timeout=2.0)


def configure_bridge_registrations(
    config: ProviderConfig,
    pool_urls: list[str],
) -> None:
    required = config.network_profile != "local"
    if required:
        normalized = {_canonical_bridge_origin(url) for url in pool_urls}
    else:
        normalized = {str(url).strip() for url in pool_urls if str(url).strip()}
    if required and not normalized:
        raise P2PError("non-local Provider requires at least one Bridge registration")
    with config._bridge_registration_lock:
        config._bridge_registration_required = required
        config._bridge_registration_valid_until = {url: 0.0 for url in normalized}


def _canonical_bridge_origin(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise P2PError("non-local Bridge URL must be a canonical HTTPS origin")
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise P2PError("non-local Bridge URL must be a canonical HTTPS origin") from exc
    canonical = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or canonical != value
    ):
        raise P2PError("non-local Bridge URL must be a canonical HTTPS origin")
    return value


def record_bridge_registration(
    config: ProviderConfig,
    pool_url: str,
    response: Any,
    *,
    ttl_seconds: int,
    now: float | None = None,
    monotonic_now: float | None = None,
) -> bool:
    if (
        not isinstance(response, dict)
        or response.get("ok") is not True
        or response.get("protocol") != "mycomesh-pool/0.2"
    ):
        return False
    peer = response.get("peer")
    if (
        not isinstance(peer, dict)
        or peer.get("peer_id") != config.peer_id
        or peer.get("status") != "online"
    ):
        return False
    expires_at = peer.get("expires_at")
    if type(expires_at) is not int:
        return False
    wall_now = time.time() if now is None else float(now)
    remaining = expires_at - wall_now
    try:
        ttl = int(ttl_seconds)
    except (TypeError, ValueError):
        return False
    if ttl <= 0 or remaining <= 0:
        return False
    valid_for = min(float(ttl), float(remaining))
    current_monotonic = time.monotonic() if monotonic_now is None else float(monotonic_now)
    normalized_url = str(pool_url).strip()
    with config._bridge_registration_lock:
        if config._bridge_registration_required and normalized_url not in config._bridge_registration_valid_until:
            return False
        config._bridge_registration_valid_until[normalized_url] = current_monotonic + valid_for
    return True


def bridge_registration_ready(
    config: ProviderConfig,
    *,
    monotonic_now: float | None = None,
) -> bool:
    if config.network_profile == "local":
        return True
    current = time.monotonic() if monotonic_now is None else float(monotonic_now)
    with config._bridge_registration_lock:
        if not config._bridge_registration_required:
            return False
        return any(valid_until > current for valid_until in config._bridge_registration_valid_until.values())


def handle_message(config: ProviderConfig, message: dict[str, Any]) -> dict[str, Any]:
    message_type = str(message.get("type") or "")
    request_id = str(message.get("request_id") or uuid.uuid4().hex)
    if message_type == "ping":
        response = {
            "type": "pong",
            "ok": True,
            "request_id": request_id,
            "bridge_ready": bridge_registration_ready(config),
            "peer": provider_descriptor(config),
        }
        if config.identity is not None:
            response = sign_document(
                response,
                config.identity.private_key,
                purpose=ADDRESS_PROOF_PURPOSE,
                audience=str(message.get("audience") or "") or None,
            )
        return response
    if message_type == "hello":
        return {
            "type": "hello_result",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
            "peers": peer_book_snapshot(config),
        }
    if message_type == "peers":
        return {
            "type": "peers_result",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
            "peers": peer_book_snapshot(config),
        }
    if message_type == "announce":
        peer = message.get("peer")
        if isinstance(peer, dict):
            remember_peer(config, peer)
        return {
            "type": "announce_result",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
            "peers": peer_book_snapshot(config),
        }
    if message_type == "infer":
        return handle_infer(config, message)
    raise P2PError(f"unsupported p2p message type: {message_type}")


def handle_infer(config: ProviderConfig, message: dict[str, Any]) -> dict[str, Any]:
    raw_request_id = message.get("request_id")
    request_id = raw_request_id if isinstance(raw_request_id, str) else ""
    execution_key: str | None = None
    execution_claim: Any | None = None
    execution_started = False
    try:
        preverified = _preverify_inference_request(
            config,
            message,
            allow_v4_replay=True,
        )
        request_id = str(preverified["request_id"])
    except P2PError as exc:
        error_response = {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id if _is_canonical_request_id(request_id) else "",
            "error": str(exc),
        }
        if isinstance(exc, P2PRetryableError):
            error_response["retryable"] = True
        return error_response
    preverified_reservation = preverified.get("reservation")
    is_v4_request = (
        isinstance(preverified_reservation, dict)
        and int(preverified_reservation.get("settlement_version") or 0) == 4
    )
    # Completed results are returned before Bridge/Gateway readiness checks: a
    # transport retry must remain available even while the upstream is down.
    if is_v4_request:
        try:
            cached_response = _lookup_v4_cached_response(config, preverified)
        except P2PError as exc:
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": str(exc),
                "retryable": isinstance(exc, P2PRetryableError),
            }
        if cached_response is not None:
            return cached_response
    if not bridge_registration_ready(config):
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": "Provider has no live Bridge registration",
            "retryable": True,
        }
    channel = str(preverified["unsigned"].get("channel") or config.channel)
    if channel != config.channel:
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": f"channel mismatch: provider={config.channel} request={channel}",
        }
    native_request: CanonicalNativeRequest | None = None
    if config.network_profile != "local":
        try:
            native_request = _prepare_p2p_native_request(config, preverified)
        except P2PError as exc:
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": str(exc),
            }
    pricing_table = load_pricing_config(config.pricing_config_path)
    if is_v4_request:
        try:
            execution_key, execution_claim, cached_response = _claim_v4_execution(
                config,
                preverified,
            )
        except P2PError as exc:
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": str(exc),
                "retryable": True,
            }
        if cached_response is not None:
            return cached_response
    if not config._semaphore.acquire(blocking=False):
        try:
            _release_v4_execution_claim(config, execution_key, execution_claim)
        except P2PError:
            # Preserve the capacity error; the durable claim remains visible
            # and cannot be mistaken for a successful execution.
            pass
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": "provider concurrency exceeded",
            "retryable": True,
        }
    try:
        ensure_gateway_readiness(
            config,
            output_token_cap=(native_request.output_token_cap if native_request is not None else preverified["execution_limits"]["output_token_cap"]),
        )
    except P2PError as exc:
        config._semaphore.release()
        if is_v4_request:
            try:
                _release_v4_execution_claim(config, execution_key, execution_claim)
            except P2PError as release_error:
                exc = P2PError(f"{exc}; {release_error}")
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": str(exc),
            "retryable": True,
        }
    try:
        verified = verify_inference_request(
            config,
            message,
            pricing_table=pricing_table,
            preverified=preverified,
        )
    except P2PError as exc:
        config._semaphore.release()
        if is_v4_request:
            try:
                _release_v4_execution_claim(config, execution_key, execution_claim)
            except P2PError as release_error:
                exc = P2PError(f"{exc}; {release_error}")
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": str(exc),
        }
    except BaseException:
        config._semaphore.release()
        raise

    endpoint = native_request.endpoint if native_request is not None else str(message.get("endpoint") or "responses")
    model = native_request.model if native_request is not None else str(message.get("model") or config.model)
    reservation = verified.get("reservation")
    consumed_v3 = isinstance(reservation, dict) and int(reservation.get("settlement_version") or 2) == 3
    consumed_v4 = isinstance(reservation, dict) and int(reservation.get("settlement_version") or 2) == 4
    if consumed_v4:
        try:
            _mark_v4_execution_started(config, execution_key, execution_claim)
            execution_started = True
        except P2PError as exc:
            try:
                _release_v4_authorization(config, reservation)
            except P2PError as release_error:
                exc = P2PError(f"{exc}; {release_error}")
            try:
                _release_v4_execution_claim(config, execution_key, execution_claim)
            except P2PError as release_error:
                exc = P2PError(f"{exc}; {release_error}")
            config._semaphore.release()
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": str(exc),
                "retryable": True,
            }
    started_at = time.time()
    try:
        if native_request is not None:
            raw = call_native_gateway(
                gateway_url=config.gateway_url,
                agent_key=config.agent_key,
                native_request=native_request,
                timeout=config.timeout_seconds,
                allow_remote_gateway_https=config.allow_remote_gateway_https,
            )
            verified_usage = verify_gateway_metering(
                config,
                raw,
                native_request=native_request,
            )
        else:
            body = build_gateway_request_body(
                endpoint=endpoint,
                model=model,
                input_value=message.get("input"),
                messages=message.get("messages"),
                metadata=message.get("metadata"),
                max_output_tokens=verified["output_token_cap"],
            )
            raw = call_gateway(
                gateway_url=config.gateway_url,
                agent_key=config.agent_key,
                endpoint=endpoint,
                body=body,
                timeout=config.timeout_seconds,
                allow_remote_gateway_https=config.allow_remote_gateway_https,
            )
            verified_usage = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}
        raw = {**raw, "usage": verified_usage}
    except Exception as exc:
        invalidate_gateway_readiness(config)
        if consumed_v4 and execution_started:
            try:
                # Once the upstream request has been sent, a timeout or
                # connection reset cannot prove that inference did not run.
                # Preserve the sequence and fence retries behind an uncertain
                # execution instead of charging the model twice.
                _mark_v4_execution_uncertain(config, execution_key, execution_claim)
            except (P2PError, ReplayError) as uncertain_error:
                exc = P2PError(f"{exc}; {uncertain_error}")
        error_response = {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": str(exc),
        }
        if consumed_v3:
            error_response["retryable"] = False
        elif consumed_v4:
            error_response["retryable"] = True
        return error_response
    finally:
        config._semaphore.release()

    try:
        request_hash = str(verified["request_hash"])
        response = {
            "type": "infer_result",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
            "channel": config.channel,
            "endpoint": endpoint,
            "model": model,
            "output_text": extract_output_text(endpoint, raw),
            "usage": raw.get("usage"),
            "provider_signature": verified.get("provider_signature"),
            "consumer_public_key": verified.get("consumer_public_key"),
            "elapsed_ms": int((time.time() - started_at) * 1000),
            "quality": {
                "mode": "provider-attested",
                "request_hash": request_hash,
                "canary": bool(message.get("metadata", {}).get("canary")) if isinstance(message.get("metadata"), dict) else False,
            },
            "raw": raw,
        }
    except Exception as exc:
        if consumed_v4 and execution_started:
            try:
                _mark_v4_execution_uncertain(config, execution_key, execution_claim)
            except P2PError as uncertain_error:
                exc = P2PError(f"{exc}; {uncertain_error}")
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": f"failed to build provider response: {exc}",
            "retryable": bool(consumed_v4),
        }
    if config.network_profile != "local":
        response.update(
            {
                "network_id": config.network_id,
                "channel_id": config.channel_id,
                "backend_policy": config.backend_policy,
            }
        )
    try:
        quote = quote_usage(
            config.channel,
            raw.get("usage") if isinstance(raw, dict) else None,
            pricing_table=pricing_table,
        )
        amount_units = usdc_to_units(quote.to_dict()["gross_fee"])
    except Exception as exc:
        if consumed_v4 and execution_started:
            try:
                _mark_v4_execution_uncertain(config, execution_key, execution_claim)
            except P2PError as uncertain_error:
                exc = P2PError(f"{exc}; {uncertain_error}")
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": f"failed to quote provider usage: {exc}",
            "retryable": bool(consumed_v4),
        }
    if consumed_v3:
        try:
            onchain_amount_units = v3_onchain_quote(
                config,
                config.channel,
                int(reservation.get("pricing_version") or 0),
                quote.input_tokens,
                quote.output_tokens,
                block_tag=int(verified["confirmed_block"]),
            )
        except (KeyError, P2PError, TypeError, ValueError) as exc:
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": f"failed to verify Settlement V3 usage quote: {exc}",
                "retryable": False,
            }
        if onchain_amount_units != amount_units:
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": "local pricing does not match the confirmed Settlement V3 on-chain quote",
                "retryable": False,
            }
        amount_units = onchain_amount_units
    max_fee_units = int(verified.get("max_fee_units") or 0)
    if max_fee_units > 0 and amount_units > max_fee_units:
        if consumed_v4:
            try:
                _mark_v4_execution_uncertain(config, execution_key, execution_claim)
            except P2PError as uncertain_error:
                return {
                    "type": "infer_result",
                    "ok": False,
                    "request_id": request_id,
                    "error": f"inference cost exceeded payment reservation; {uncertain_error}",
                    "retryable": True,
                }
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": "inference cost exceeded payment reservation",
            "retryable": False,
        }
    if consumed_v3:
        try:
            response["mycomesh_v3_settlement"] = _build_v3_provider_settlement(
                config=config,
                response=response,
                reservation=reservation,
                quote=quote,
            )
        except P2PError as exc:
            if consumed_v4 and execution_started:
                try:
                    _mark_v4_execution_uncertain(config, execution_key, execution_claim)
                except P2PError as uncertain_error:
                    exc = P2PError(f"{exc}; {uncertain_error}")
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": f"failed to sign Settlement V3 receipt: {exc}",
                "retryable": False,
            }
    if consumed_v4:
        try:
            response["mycomesh_v4_settlement"] = _build_v4_provider_settlement(
                config=config,
                response=response,
                reservation=reservation,
                quote=quote,
            )
        except P2PError as exc:
            if execution_started:
                try:
                    _mark_v4_execution_uncertain(config, execution_key, execution_claim)
                except P2PError as uncertain_error:
                    exc = P2PError(f"{exc}; {uncertain_error}")
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": f"failed to sign Settlement V4 receipt: {exc}",
                "retryable": False,
            }
    if config.identity is not None and isinstance(reservation, dict) and reservation:
        try:
            response["provider_settlement_attestation"] = build_provider_settlement_attestation(
                request_id=request_id,
                request_hash=request_hash,
                response=response,
                channel=config.channel,
                network_id=config.network_id,
                channel_id=config.channel_id,
                backend_policy=config.backend_policy,
                model=model,
                endpoint=endpoint,
                reservation=reservation,
                quote=quote,
                provider_id=config.peer_id,
                provider_payment_address=config.payment_address,
                signer=config.identity,
            )
        except (AttestationError, IdentityError, TypeError, ValueError) as exc:
            if consumed_v4 and execution_started:
                try:
                    _mark_v4_execution_uncertain(config, execution_key, execution_claim)
                except P2PError as uncertain_error:
                    exc = P2PError(f"{exc}; {uncertain_error}")
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": f"failed to build provider settlement evidence: {exc}",
                "retryable": False,
            }
    if config.identity is not None:
        try:
            response = sign_document(
                response,
                config.identity.private_key,
                purpose=PROVIDER_RESPONSE_PURPOSE,
                audience=verified.get("consumer_public_key"),
            )
        except (IdentityError, TypeError, ValueError) as exc:
            if consumed_v4 and execution_started:
                try:
                    _mark_v4_execution_uncertain(config, execution_key, execution_claim)
                except P2PError as uncertain_error:
                    exc = P2PError(f"{exc}; {uncertain_error}")
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": f"failed to sign provider response: {exc}",
                "retryable": bool(consumed_v4),
            }
    if consumed_v4 and execution_started:
        try:
            previous_progress = reservation.get("_v4_previous_progress")
            previous_spend = (
                int(previous_progress[1])
                if isinstance(previous_progress, tuple) and len(previous_progress) == 2
                else int(reservation.get("cumulative_spend_units") or 0)
                - int(reservation.get("max_fee_units") or 0)
            )
            committed_cumulative_spend = previous_spend + int(amount_units)
            _complete_v4_execution(
                config,
                preverified,
                response,
                execution_key,
                execution_claim,
                committed_cumulative_spend_units=committed_cumulative_spend,
            )
            _commit_v4_session_progress(
                config,
                reservation,
                cumulative_spend_units=committed_cumulative_spend,
            )
        except P2PError as exc:
            # A completed execution remains replayable even if progress
            # persistence is temporarily unavailable.  Do not roll it back
            # or execute the model again; surface a retryable infrastructure
            # error so the next identical request can repair the progress row.
            try:
                claim_state = config._replay_store.get_execution(
                    V4_EXECUTION_SCOPE,
                    execution_key or "",
                ) if config._replay_store is not None and execution_key else None
            except (P2PError, ReplayError) as uncertain_error:
                claim_state = None
                exc = P2PError(f"{exc}; {uncertain_error}")
            if str(getattr(claim_state, "state", "")) != "completed":
                try:
                    _mark_v4_execution_uncertain(config, execution_key, execution_claim)
                except P2PError as uncertain_error:
                    exc = P2PError(f"{exc}; {uncertain_error}")
            return {
                "type": "infer_result",
                "ok": False,
                "request_id": request_id,
                "error": str(exc),
                "retryable": True,
            }
    return response



def _build_v3_provider_settlement(
    *,
    config: ProviderConfig,
    response: dict[str, Any],
    reservation: dict[str, Any],
    quote: Any,
) -> dict[str, Any]:
    if not config.evm_identity_path:
        raise P2PError("Provider EVM identity path is required")
    try:
        from .chain import ZERO_ADDRESS, ChainError, channel_to_hash
        from .chain_v3 import build_provider_settlement_payload
        from .provider_bootstrap import ProviderBootstrapError, load_provider_evm_identity

        signer = load_provider_evm_identity(config.evm_identity_path)
        if signer.address != normalize_payment_address(config.payment_address):
            raise P2PError("Provider EVM identity does not match payment_address")
        if config.settlement_chain_id is None or not config.settlement_contract:
            raise P2PError("Settlement V3 chain configuration is incomplete")
        return build_provider_settlement_payload(
            provider_private_key=signer.private_key,
            chain_id=config.settlement_chain_id,
            settlement_contract=config.settlement_contract,
            reservation_id=str(reservation.get("onchain_reservation_id") or ""),
            request_hash=str(reservation.get("request_hash") or ""),
            response_hash="0x" + settlement_response_hash(response),
            channel_hash=channel_to_hash(config.channel),
            pricing_version=int(reservation.get("pricing_version") or 0),
            pricing_hash=str(reservation.get("pricing_hash") or ""),
            consumer=str(reservation.get("consumer_payment_address") or ""),
            provider=str(config.payment_address or ""),
            relay=ZERO_ADDRESS,
            pool=ZERO_ADDRESS,
            input_tokens=int(quote.input_tokens),
            output_tokens=int(quote.output_tokens),
            deadline=int(reservation.get("settlement_deadline") or 0),
        )
    except P2PError:
        raise
    except (ChainError, ProviderBootstrapError, TypeError, ValueError) as exc:
        raise P2PError(str(exc)) from exc


def _build_v4_provider_settlement(
    *,
    config: ProviderConfig,
    response: dict[str, Any],
    reservation: dict[str, Any],
    quote: Any,
) -> dict[str, Any]:
    """Build the provider's EIP-712 V4 receipt without an on-chain request.

    The provider signs the receipt immediately after inference.  A Gateway (or
    another funded relayer) can later add the session-key signature and submit
    it in a batch.  No transaction or confirmation is required on this path.
    """
    if not config.evm_identity_path:
        raise P2PError("Provider EVM identity path is required for Settlement V4")
    try:
        from .chain import ZERO_ADDRESS, ChainError, channel_to_hash
        from .chain_v4 import build_provider_settlement_payload
        from .provider_bootstrap import ProviderBootstrapError, load_provider_evm_identity

        signer = load_provider_evm_identity(config.evm_identity_path)
        configured_provider = normalize_payment_address(config.payment_address)
        if signer.address != configured_provider:
            raise P2PError("Provider EVM identity does not match payment_address")
        chain_id = int(reservation.get("settlement_chain_id") or config.settlement_chain_id or 0)
        contract = str(reservation.get("settlement_contract") or config.settlement_contract or "")
        if chain_id <= 0 or not contract:
            raise P2PError("Settlement V4 chain configuration is incomplete")
        return build_provider_settlement_payload(
            provider_private_key=signer.private_key,
            chain_id=chain_id,
            settlement_contract=contract,
            session_id=str(reservation.get("session_id") or ""),
            request_hash=str(reservation.get("request_hash") or ""),
            response_hash="0x" + settlement_response_hash(response),
            channel_hash=channel_to_hash(config.channel),
            pricing_version=int(reservation.get("pricing_version") or config.pricing_version or 0),
            pricing_hash=str(reservation.get("pricing_hash") or config.pricing_hash or ""),
            consumer=str(reservation.get("consumer_payment_address") or ""),
            provider=str(config.payment_address or ""),
            relay=ZERO_ADDRESS,
            pool=ZERO_ADDRESS,
            input_tokens=int(quote.input_tokens),
            output_tokens=int(quote.output_tokens),
            # Session protocol numbers requests from 1; the V4 contract
            # numbers the corresponding receipts from its initial
            # ``nextSequence == 0``.
            sequence=max(0, int(reservation.get("sequence") or 0) - 1),
            quoted_fee=int(usdc_to_units(quote.to_dict()["gross_fee"])),
            deadline=int(reservation.get("settlement_deadline") or reservation.get("expires_at") or 0),
        )
    except P2PError:
        raise
    except (ChainError, ProviderBootstrapError, TypeError, ValueError) as exc:
        raise P2PError(str(exc)) from exc

def verify_inference_request(
    config: ProviderConfig,
    message: dict[str, Any],
    *,
    pricing_table: dict[str, ChannelPricing] | None = None,
    preverified: dict[str, Any] | None = None,
) -> dict[str, Any]:
    checked = preverified or _preverify_inference_request(config, message)
    if not config.require_signed_requests:
        return {
            **checked["execution_limits"],
            "request_hash": checked["request_hash_digest"],
        }
    unsigned = checked["unsigned"]
    request_id = str(checked["request_id"])
    consumer_public_key = str(checked["consumer_public_key"])
    request_key = str(checked["request_key"])
    execution_limits = checked["execution_limits"]
    request_hash_digest = str(checked["request_hash_digest"])
    request_hash = str(checked["request_hash"])
    confirmed_block: int | None = None
    checked_reservation = checked.get("reservation")
    is_v4 = isinstance(checked_reservation, dict) and int(checked_reservation.get("settlement_version") or 2) == 4
    if config.require_payment_reservation and not is_v4:
        try:
            pricing_table = pricing_table or load_pricing_config(config.pricing_config_path)
            confirmed_block = _confirmed_settlement_block(config) if config.settlement_version == 3 else None
            snapshot = channel_pricing_snapshot(
                pricing_table,
                str(message.get("channel") or config.channel),
                override=config.pricing_hash if config.settlement_version != 3 else None,
                rpc_url=config.settlement_rpc_url if config.settlement_version == 3 else None,
                settlement=config.settlement_contract if config.settlement_version == 3 else None,
                pricing_version=config.pricing_version,
                settlement_version=config.settlement_version,
                timeout=float(config.settlement_rpc_timeout_seconds),
                block_tag=confirmed_block if confirmed_block is not None else "latest",
            )
            if config.settlement_version == 3 and config.pricing_hash:
                from .chain import normalize_bytes32

                if normalize_bytes32(config.pricing_hash) != normalize_bytes32(snapshot.pricing_hash):
                    raise P2PError("configured pricing_hash does not match the confirmed Settlement V3 pricing hash")
            min_fee_units = provider_min_reservation_units(
                str(message.get("channel") or config.channel),
                pricing_table,
                input_tokens=execution_limits["input_token_upper_bound"],
                output_tokens=execution_limits["output_token_cap"],
            )
            if config.settlement_version == 3:
                min_fee_units = v3_onchain_quote(
                    config,
                    str(message.get("channel") or config.channel),
                    int(snapshot.pricing_version or 0),
                    execution_limits["input_token_upper_bound"],
                    execution_limits["output_token_cap"],
                    block_tag=confirmed_block,
                )
            reservation = verify_payment_reservation(
                message.get("payment_reservation"),
                request_id=request_id,
                channel=str(message.get("channel") or config.channel),
                provider_id=config.peer_id,
                provider_payment_address=config.payment_address,
                consumer_public_key=consumer_public_key,
                min_fee_units=min_fee_units,
                pricing_hash=snapshot.pricing_hash,
                settlement_version=snapshot.settlement_version,
                pricing_version=snapshot.pricing_version,
                request_hash=request_hash,
                settlement_chain_id=config.settlement_chain_id,
                settlement_contract=config.settlement_contract,
                now=int(time.time()),
            )
        except (ReservationError, RuntimeError, ValueError) as exc:
            raise P2PError(str(exc)) from exc
        if int(reservation.get("settlement_version") or 2) == 3:
            _validate_settlement_window(config, reservation)
            verify_v3_onchain_reservation(
                config,
                reservation,
                request_hash=request_hash,
                block_tag=confirmed_block,
            )
            verify_v3_latest_reservation_state(config, reservation)
            _verify_v3_session_wallet_authorization(
                config,
                reservation,
                block_tag=confirmed_block,
                now=int(time.time()),
            )
            _validate_settlement_window(config, reservation)
    elif is_v4:
        reservation = dict(checked_reservation or {})
    else:
        reservation = {}
    now = time.time()
    replay_ttl = max(1, int(config.replay_ttl_seconds))
    is_v3 = int(reservation.get("settlement_version") or 2) == 3
    is_v4 = int(reservation.get("settlement_version") or 2) == 4
    with config._seen_lock:
        expired = [key for key, seen_at in config.seen_requests.items() if now - seen_at > replay_ttl]
        for key in expired:
            config.seen_requests.pop(key, None)
        if request_key in config.seen_requests:
            raise P2PError("duplicate request_id")
    reservation_nonce = checked.get("reservation_nonce")
    if is_v3:
        payment_nonce_key = (
            f"{consumer_public_key}:{reservation_nonce}" if isinstance(reservation_nonce, str) else None
        )
        _claim_v3_authorization(
            config,
            reservation,
            now=int(now),
            request_key=request_key,
            payment_nonce_key=payment_nonce_key,
            replay_ttl=replay_ttl,
        )
        with config._seen_lock:
            config.seen_requests[request_key] = now
    elif is_v4:
        _claim_v4_authorization(
            config,
            reservation,
            request_key=request_key,
            now=int(now),
            replay_ttl=replay_ttl,
        )
        with config._seen_lock:
            config.seen_requests[request_key] = now
    else:
        with config._seen_lock:
            config.seen_requests[request_key] = now
    if config._replay_store is not None and not is_v3 and not is_v4:
        try:
            config._replay_store.remember("p2p.infer.request", request_key, replay_ttl, now=int(now))
        except ReplayError as exc:
            raise P2PError("duplicate request_id") from exc
        except Exception as exc:
            raise P2PError(f"failed to persist request_id replay claim: {exc}") from exc
        if reservation_nonce:
            try:
                config._replay_store.remember(
                    "p2p.payment.reservation",
                    f"{consumer_public_key}:{reservation_nonce}",
                    replay_ttl,
                    now=int(now),
                )
            except ReplayError as exc:
                raise P2PError("duplicate payment reservation signature nonce") from exc
            except Exception as exc:
                raise P2PError(f"failed to persist payment reservation replay claim: {exc}") from exc
    result: dict[str, Any] = {
        "consumer_public_key": consumer_public_key,
        "max_fee_units": int(reservation.get("max_fee_units") or 0),
        "reservation": dict(reservation),
        "request_hash": request_hash_digest,
        **execution_limits,
    }
    if is_v4:
        result["session_authorization"] = dict(reservation.get("session_authorization") or {})
        result["session_request"] = dict(reservation.get("session_request") or {})
        result["session_sequence"] = int(reservation.get("sequence") or 0)
    if confirmed_block is not None:
        result["confirmed_block"] = confirmed_block
    if config.identity is not None:
        result["provider_signature"] = {
            "peer_id": config.identity.peer_id,
            "public_key": config.identity.public_key,
        }
    return result


def _v4_execution_key(consumer_public_key: Any, request_id: Any) -> str:
    """Build the stable Provider-local key used for V4 idempotency."""
    consumer = str(consumer_public_key or "").strip().lower()
    request = str(request_id or "").strip()
    if not consumer or not request:
        raise P2PError("Settlement V4 execution key is incomplete")
    return f"{consumer}:{request}"


def _v4_session_progress_key(config: ProviderConfig, session: dict[str, Any]) -> str:
    try:
        chain_id = int(session.get("settlement_chain_id") or config.settlement_chain_id or 0)
    except (TypeError, ValueError) as exc:
        raise P2PError("Settlement V4 session progress chain id is invalid") from exc
    contract = str(session.get("settlement_contract") or config.settlement_contract or "").strip().lower()
    session_id = str(session.get("session_id") or "").strip().lower()
    if chain_id <= 0 or not contract or not session_id:
        raise P2PError("Settlement V4 session progress key is incomplete")
    return f"{chain_id}:{contract}:{session_id}"


def _load_v4_session_progress(
    config: ProviderConfig,
    session: dict[str, Any],
) -> tuple[int, int] | None:
    """Load committed V4 progress and merge it into the process cache."""
    if config._replay_store is None:
        return None
    key = _v4_session_progress_key(config, session)
    try:
        durable = config._replay_store.get_session_progress(
            V4_SESSION_PROGRESS_SCOPE,
            key,
        )
    except ReplayError as exc:
        raise P2PRetryableError(
            f"failed to read Settlement V4 session progress: {exc}"
        ) from exc
    session_id = str(session.get("session_id") or "").lower()
    with config._session_v4_lock:
        current = config._session_v4_progress.get(session_id)
        if durable is not None and (
            current is None
            or int(durable[0]) > int(current[0])
            or (int(durable[0]) == int(current[0]) and int(durable[1]) > int(current[1]))
        ):
            current = (int(durable[0]), int(durable[1]))
            config._session_v4_progress[session_id] = current
        return current


def _commit_v4_session_progress(
    config: ProviderConfig,
    session: dict[str, Any],
    *,
    cumulative_spend_units: int | None = None,
) -> None:
    """Persist the sequence only after a signed response is durable."""
    if config._replay_store is None:
        return
    try:
        sequence = int(session.get("sequence") or 0)
        cumulative = int(
            session.get("cumulative_spend_units")
            if cumulative_spend_units is None
            else cumulative_spend_units
        )
        expires_at = int(session.get("expires_at") or session.get("settlement_deadline") or 0)
        if sequence <= 0 or cumulative < 0 or expires_at <= int(time.time()):
            raise ValueError("invalid committed session progress")
        key = _v4_session_progress_key(config, session)
        config._replay_store.set_session_progress(
            V4_SESSION_PROGRESS_SCOPE,
            key,
            sequence,
            cumulative,
            expires_at,
        )
    except (ReplayError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to persist Settlement V4 session progress: {exc}") from exc
    session_id = str(session.get("session_id") or "").lower()
    with config._session_v4_lock:
        current = config._session_v4_progress.get(session_id)
        if current is None or sequence >= int(current[0]):
            config._session_v4_progress[session_id] = (sequence, cumulative)


def _v4_execution_claim_for_request(
    config: ProviderConfig,
    consumer_public_key: Any,
    request_id: Any,
) -> Any | None:
    """Read a durable V4 execution claim without mutating it."""
    if config._replay_store is None:
        raise P2PError("Settlement V4 requires a persistent replay store")
    key = _v4_execution_key(consumer_public_key, request_id)
    try:
        return config._replay_store.get_execution(V4_EXECUTION_SCOPE, key)
    except ReplayError as exc:
        raise P2PRetryableError(
            f"failed to read Settlement V4 execution claim: {exc}"
        ) from exc


def _canonical_v4_execution_payload(value: dict[str, Any]) -> str:
    """Serialize a cached response deterministically for hash verification."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise P2PError("Settlement V4 execution result must be canonical JSON") from exc
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise P2PError("Settlement V4 execution result exceeds the Provider cache limit")
    return encoded.decode("utf-8")


def _v4_session_request_hash(session_request: dict[str, Any]) -> str:
    # Idempotency binds semantic request fields, while allowing a consumer to
    # refresh transport/session signatures or the short-lived request deadline
    # after a timeout.  The authorization, sequence, cumulative spend, and
    # request hash remain immutable bindings for the request id.
    semantic_request = {
        key: value
        for key, value in session_request.items()
        if key not in {"signature", "session_signature", "deadline"}
    }
    payload = _canonical_v4_execution_payload(semantic_request)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _v4_legacy_session_request_hash(session_request: dict[str, Any]) -> str:
    """Hash the V4 request format used before deadline-refresh retries.

    V4 execution claims are durable across Provider upgrades.  The original
    implementation excluded signatures but included ``deadline``.  Retaining
    this exact algorithm lets a new process validate an old completed claim
    without accepting an arbitrary request with the same request id.
    """
    semantic_request = {
        key: value
        for key, value in session_request.items()
        if key not in {"signature", "session_signature"}
    }
    payload = _canonical_v4_execution_payload(semantic_request)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _v4_legacy_deadline_from_response(response: Any) -> int | None:
    """Return the deadline committed in a legacy Provider V4 receipt.

    A legacy execution envelope did not persist the request document, but the
    cached V4 settlement payload contains the exact request deadline.  Only a
    canonical integer is accepted; malformed or missing evidence disables the
    compatibility path rather than weakening replay validation.
    """
    if not isinstance(response, dict):
        return None
    settlement = response.get("mycomesh_v4_settlement")
    if not isinstance(settlement, dict):
        return None
    receipt = settlement.get("receipt")
    if not isinstance(receipt, dict):
        return None
    deadline = receipt.get("deadline")
    if type(deadline) is not int or deadline <= 0:
        return None
    return deadline


def _v4_cached_settlement_deadline(response: Any) -> int | None:
    """Read the deadline carried by cached V4 evidence, if present."""
    deadline = _v4_legacy_deadline_from_response(response)
    if deadline is not None:
        return deadline
    if not isinstance(response, dict):
        return None
    attestation = response.get("provider_settlement_attestation")
    if not isinstance(attestation, dict):
        return None
    value = attestation.get("settlement_deadline")
    if type(value) is int and value > 0:
        return value
    return None


def _v4_cached_response_signature_stale(response: Any, *, now: int) -> bool:
    """Return whether cached transport evidence should be re-signed."""
    if not isinstance(response, dict):
        return True
    signature = response.get("signature")
    if not isinstance(signature, dict):
        return True
    timestamp = signature.get("timestamp")
    if type(timestamp) is not int:
        return True
    return timestamp > now + 30 or now - timestamp >= V4_RESPONSE_REFRESH_SIGNATURE_AGE_SECONDS


def _verify_cached_v4_provider_response(
    config: ProviderConfig,
    preverified: dict[str, Any],
    response: dict[str, Any],
) -> None:
    """Verify the cached Provider signature before rebuilding its evidence."""
    if config.identity is None:
        raise P2PError("cannot refresh V4 settlement without a Provider identity")
    signature = response.get("signature")
    if not isinstance(signature, dict):
        raise P2PError("cached V4 response is missing its Provider signature")
    if str(signature.get("public_key") or "") != str(config.identity.public_key):
        raise P2PError("cached V4 response Provider signature does not match this Provider")
    timestamp = signature.get("timestamp")
    if type(timestamp) is not int or timestamp < 0 or timestamp > int(time.time()) + 30:
        raise P2PError("cached V4 response signature timestamp is invalid")
    try:
        verify_document(
            response,
            purpose=PROVIDER_RESPONSE_PURPOSE,
            audience=str(preverified.get("consumer_public_key") or ""),
            # A response may be refreshed after the short transport signature
            # window; cryptographic validity is still checked, but age is not
            # used as an authorization signal for this already-completed job.
            max_age_seconds=0,
        )
    except IdentityError as exc:
        raise P2PError(f"cached V4 response signature is invalid: {exc}") from exc
    if response.get("ok") is not True:
        raise P2PError("cached V4 response is not successful")
    if response.get("request_id") != str(preverified.get("request_id") or ""):
        raise P2PError("cached V4 response request_id mismatch")


def _refresh_v4_cached_response(
    config: ProviderConfig,
    preverified: dict[str, Any],
    response: dict[str, Any],
    *,
    committed_cumulative_spend_units: int,
) -> dict[str, Any]:
    """Re-sign V4 evidence for a refreshed request deadline.

    The model output and usage are immutable.  Only deadline-bound settlement
    artifacts and their signatures are rebuilt.  The durable execution claim
    intentionally remains unchanged; it still anchors the original execution
    result and prevents a second Gateway call.
    """
    reservation = preverified.get("reservation")
    if not isinstance(reservation, dict):
        raise P2PError("cached V4 response reservation is missing")
    current_deadline = int(reservation.get("settlement_deadline") or 0)
    cached_deadline = _v4_cached_settlement_deadline(response)
    if cached_deadline is None:
        # Older test/minimal payloads have no inspectable deadline.  Do not
        # invent a refresh binding; the normal hash-checked replay remains the
        # strict compatibility path.
        return response
    now = int(time.time())
    if (
        cached_deadline == current_deadline
        and cached_deadline > now
        and not _v4_cached_response_signature_stale(response, now=now)
    ):
        return response

    _verify_cached_v4_provider_response(config, preverified, response)
    base_response = {
        key: value
        for key, value in response.items()
        if key not in {
            "signature",
            "mycomesh_v4_settlement",
            "provider_settlement_attestation",
        }
    }
    try:
        pricing_table = load_pricing_config(config.pricing_config_path)
        quote = quote_usage(
            config.channel,
            base_response.get("usage") if isinstance(base_response.get("usage"), dict) else None,
            pricing_table=pricing_table,
        )
        amount_units = usdc_to_units(quote.to_dict()["gross_fee"])
        max_fee_units = int(reservation.get("max_fee_units") or 0)
        if amount_units > max_fee_units:
            raise P2PError("cached V4 usage exceeds the current request reservation")
        session_request = reservation.get("session_request")
        if not isinstance(session_request, dict):
            raise P2PError("cached V4 session request is missing")
        previous_spend = int(session_request["cumulative_spend_units"]) - int(
            session_request["max_fee_units"]
        )
        if previous_spend < 0 or previous_spend + amount_units != int(
            committed_cumulative_spend_units
        ):
            raise P2PError("cached V4 usage does not match the committed spend delta")
        base_response["mycomesh_v4_settlement"] = _build_v4_provider_settlement(
            config=config,
            response=base_response,
            reservation=reservation,
            quote=quote,
        )
        base_response["provider_settlement_attestation"] = build_provider_settlement_attestation(
            request_id=str(preverified["request_id"]),
            request_hash=str(preverified["request_hash"]),
            response=base_response,
            channel=config.channel,
            network_id=config.network_id,
            channel_id=config.channel_id,
            backend_policy=config.backend_policy,
            model=str(base_response.get("model") or config.model),
            endpoint=str(base_response.get("endpoint") or "responses"),
            reservation=reservation,
            quote=quote,
            provider_id=config.peer_id,
            provider_payment_address=config.payment_address,
            signer=config.identity,
        )
        return sign_document(
            base_response,
            config.identity.private_key,
            purpose=PROVIDER_RESPONSE_PURPOSE,
            audience=str(preverified.get("consumer_public_key") or ""),
        )
    except P2PError:
        raise
    except (AttestationError, IdentityError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to refresh cached V4 settlement evidence: {exc}") from exc


def _v4_cached_request_hash_matches(
    decoded: dict[str, Any],
    session_request: dict[str, Any],
) -> bool:
    """Validate current or strictly provable legacy request fingerprints."""
    stored_hash = str(decoded.get("session_request_hash") or "").lower().removeprefix("0x")
    if not stored_hash:
        return False
    current_hash = _v4_session_request_hash(session_request)
    version = decoded.get("session_request_hash_version")
    if version is not None and type(version) is not int:
        return False
    if version == V4_SESSION_REQUEST_HASH_VERSION:
        return stored_hash == current_hash
    if version not in {None, V4_LEGACY_SESSION_REQUEST_HASH_VERSION}:
        return False
    # Pre-version and explicitly legacy envelopes are accepted only when
    # the old fingerprint can be reconstructed from the deadline in the
    # cached settlement.
    if version is None and stored_hash == current_hash:
        return True
    legacy_deadline = _v4_legacy_deadline_from_response(decoded.get("response"))
    if legacy_deadline is None:
        return False
    legacy_request = dict(session_request)
    legacy_request["deadline"] = legacy_deadline
    return stored_hash == _v4_legacy_session_request_hash(legacy_request)


def _v4_execution_envelope(
    preverified: dict[str, Any],
    response: dict[str, Any],
    *,
    provider_peer_id: str,
    committed_cumulative_spend_units: int,
) -> dict[str, Any]:
    reservation = preverified.get("reservation")
    if not isinstance(reservation, dict) or int(reservation.get("settlement_version") or 0) != 4:
        raise P2PError("Settlement V4 execution reservation is missing")
    try:
        session_id = str(reservation["session_id"]).lower()
        sequence = int(reservation["sequence"])
        session_request = reservation.get("session_request")
        if not isinstance(session_request, dict):
            raise ValueError("session_request is missing")
        session_request_hash = _v4_session_request_hash(session_request)
    except (KeyError, TypeError, ValueError) as exc:
        raise P2PError("Settlement V4 execution reservation is malformed") from exc
    return {
        "schema": V4_EXECUTION_RESULT_SCHEMA,
        "provider_peer_id": str(provider_peer_id),
        "consumer_public_key": str(preverified.get("consumer_public_key") or "").lower(),
        "request_id": str(preverified.get("request_id") or ""),
        "request_hash": str(preverified.get("request_hash") or "").lower(),
        "session_id": session_id,
        "sequence": sequence,
        "session_request_hash": session_request_hash,
        "session_request_hash_version": V4_SESSION_REQUEST_HASH_VERSION,
        "committed_cumulative_spend_units": int(committed_cumulative_spend_units),
        "response": response,
    }


def _decode_v4_execution_response(
    config: ProviderConfig,
    preverified: dict[str, Any],
    claim: Any,
) -> dict[str, Any]:
    """Validate and decode a completed V4 result before returning it."""
    payload = getattr(claim, "result_payload", None)
    result_hash = str(getattr(claim, "result_hash", "") or "").lower().removeprefix("0x")
    if not payload or not result_hash:
        raise P2PError("completed Settlement V4 execution has no cached response")
    try:
        decoded = json.loads(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise P2PError("completed Settlement V4 execution contains invalid cached JSON") from exc
    if not isinstance(decoded, dict):
        raise P2PError("completed Settlement V4 execution cache must be an object")
    canonical = _canonical_v4_execution_payload(decoded)
    actual_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if actual_hash != result_hash:
        raise P2PError("completed Settlement V4 execution cache hash mismatch")
    reservation = preverified.get("reservation")
    expected = {
        "schema": V4_EXECUTION_RESULT_SCHEMA,
        "provider_peer_id": config.peer_id,
        "consumer_public_key": str(preverified.get("consumer_public_key") or "").lower(),
        "request_id": str(preverified.get("request_id") or ""),
        "request_hash": str(preverified.get("request_hash") or "").lower(),
        "session_id": str((reservation or {}).get("session_id") or "").lower(),
        "sequence": int((reservation or {}).get("sequence") or 0),
    }
    session_request = (reservation or {}).get("session_request")
    if not isinstance(session_request, dict):
        raise P2PError("Settlement V4 retry session request is missing")
    for field_name, expected_value in expected.items():
        if decoded.get(field_name) != expected_value:
            raise P2PError(
                "completed Settlement V4 execution does not match the retried request"
            )
    if not _v4_cached_request_hash_matches(decoded, session_request):
        raise P2PError(
            "completed Settlement V4 execution does not match the retried request"
        )
    committed_cumulative = decoded.get("committed_cumulative_spend_units")
    if type(committed_cumulative) is not int or committed_cumulative < 0:
        raise P2PError("completed Settlement V4 execution has invalid committed spend")
    max_amount = int(
        ((reservation or {}).get("session_authorization") or {}).get("max_amount_units") or 0
    )
    if committed_cumulative > max_amount:
        raise P2PError("completed Settlement V4 execution exceeds the session spend cap")
    response = decoded.get("response")
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise P2PError("completed Settlement V4 execution has an invalid cached response")
    if response.get("request_id") != expected["request_id"]:
        raise P2PError("cached Settlement V4 response request_id mismatch")
    response = _refresh_v4_cached_response(
        config,
        preverified,
        response,
        committed_cumulative_spend_units=committed_cumulative,
    )
    try:
        _commit_v4_session_progress(
            config,
            reservation,
            cumulative_spend_units=committed_cumulative,
        )
    except P2PError:
        # The signed response is already durable and must remain deliverable.
        # Every idempotent retry re-attempts this repair before returning it.
        pass
    return response


def _lookup_v4_cached_response(
    config: ProviderConfig,
    preverified: dict[str, Any],
) -> dict[str, Any] | None:
    claim = _v4_execution_claim_for_request(
        config,
        preverified.get("consumer_public_key"),
        preverified.get("request_id"),
    )
    if claim is None or str(getattr(claim, "state", "")) != "completed":
        return None
    return _decode_v4_execution_response(config, preverified, claim)


def _claim_v4_execution(
    config: ProviderConfig,
    preverified: dict[str, Any],
) -> tuple[str, Any | None, dict[str, Any] | None]:
    """Atomically claim V4 execution or return its completed response."""
    if config._replay_store is None:
        raise P2PError("Settlement V4 requires a persistent replay store")
    key = _v4_execution_key(
        preverified.get("consumer_public_key"),
        preverified.get("request_id"),
    )
    try:
        claim = config._replay_store.claim_execution(
            V4_EXECUTION_SCOPE,
            key,
            config._execution_owner,
            max(1, int(config.replay_ttl_seconds)),
        )
    except ReplayError as exc:
        current = None
        try:
            current = config._replay_store.get_execution(V4_EXECUTION_SCOPE, key)
        except ReplayError:
            pass
        state = str(getattr(current, "state", "") or "")
        if state in {"claimed", "started", "uncertain"}:
            raise P2PError(
                "Settlement V4 request execution is already in progress or uncertain; "
                "retry with the same request_id"
            ) from exc
        raise P2PRetryableError(f"failed to claim Settlement V4 execution: {exc}") from exc
    if not bool(getattr(claim, "acquired", False)):
        if str(getattr(claim, "state", "")) == "completed":
            return key, None, _decode_v4_execution_response(config, preverified, claim)
        raise P2PError(
            "Settlement V4 request execution is already in progress or uncertain; "
            "retry with the same request_id"
        )
    return key, claim, None


def _release_v4_execution_claim(
    config: ProviderConfig,
    execution_key: str | None,
    claim: Any | None,
) -> None:
    """Release only a pre-start V4 execution claim."""
    if not execution_key or claim is None or config._replay_store is None:
        return
    try:
        config._replay_store.release_execution(
            V4_EXECUTION_SCOPE,
            execution_key,
            config._execution_owner,
            int(claim.fencing_token),
        )
    except ReplayError as exc:
        raise P2PError(f"failed to release Settlement V4 execution claim: {exc}") from exc


def _mark_v4_execution_started(
    config: ProviderConfig,
    execution_key: str | None,
    claim: Any | None,
) -> None:
    if not execution_key or claim is None or config._replay_store is None:
        return
    try:
        config._replay_store.mark_execution_started(
            V4_EXECUTION_SCOPE,
            execution_key,
            config._execution_owner,
            int(claim.fencing_token),
            max(1, int(config.replay_ttl_seconds)),
        )
    except ReplayError as exc:
        raise P2PError(f"failed to start Settlement V4 execution claim: {exc}") from exc


def _mark_v4_execution_uncertain(
    config: ProviderConfig,
    execution_key: str | None,
    claim: Any | None,
) -> None:
    if not execution_key or claim is None or config._replay_store is None:
        return
    try:
        config._replay_store.mark_execution_uncertain(
            V4_EXECUTION_SCOPE,
            execution_key,
            config._execution_owner,
            int(claim.fencing_token),
        )
    except ReplayError as exc:
        # A completed claim is already the strongest possible outcome.  Any
        # other failure must remain visible to the caller instead of silently
        # reopening the sequence for a second model execution.
        try:
            current = config._replay_store.get_execution(V4_EXECUTION_SCOPE, execution_key)
        except ReplayError:
            current = None
        if str(getattr(current, "state", "")) == "completed":
            return
        raise P2PError(f"failed to mark Settlement V4 execution uncertain: {exc}") from exc


def _complete_v4_execution(
    config: ProviderConfig,
    preverified: dict[str, Any],
    response: dict[str, Any],
    execution_key: str | None,
    claim: Any | None,
    *,
    committed_cumulative_spend_units: int,
) -> None:
    if not execution_key or claim is None or config._replay_store is None:
        return
    envelope = _v4_execution_envelope(
        preverified,
        response,
        provider_peer_id=config.peer_id,
        committed_cumulative_spend_units=committed_cumulative_spend_units,
    )
    payload = _canonical_v4_execution_payload(envelope)
    result_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    try:
        config._replay_store.complete_execution(
            V4_EXECUTION_SCOPE,
            execution_key,
            config._execution_owner,
            int(claim.fencing_token),
            result_hash,
            payload,
        )
    except ReplayError as exc:
        raise P2PError(f"failed to persist Settlement V4 execution result: {exc}") from exc


def _v4_execution_claim_exists(
    config: ProviderConfig,
    consumer_public_key: Any,
    request_id: Any,
) -> bool:
    """Tell admission whether a request has an existing durable execution."""
    return _v4_execution_claim_for_request(config, consumer_public_key, request_id) is not None


def _preverify_inference_request(
    config: ProviderConfig,
    message: dict[str, Any],
    *,
    allow_v4_replay: bool = False,
) -> dict[str, Any]:
    """Perform all request and reservation checks that require no shared capacity or RPC."""
    if not isinstance(message, dict):
        raise P2PError("inference request must be a JSON object")
    request_id = _canonical_request_id(message.get("request_id"))
    has_session_authorization = isinstance(message.get("session_authorization"), dict)
    has_session_request = isinstance(message.get("session_request"), dict)
    if has_session_authorization != has_session_request:
        raise P2PError("Settlement V4 requires both session_authorization and session_request")
    has_session_v4 = has_session_authorization and has_session_request
    if has_session_v4 and not config.session_v4_enabled:
        raise P2PError("Settlement V4 session requests are disabled on this provider")
    if has_session_v4 and not config.require_signed_requests:
        raise P2PError("Settlement V4 requires signed inference requests")
    if not config.require_signed_requests:
        execution_limits = _inference_execution_limits(config, message)
        request_hash_digest = _inference_request_hash(config, message, execution_limits["output_token_cap"])
        return {
            "unsigned": message,
            "request_id": request_id,
            "consumer_public_key": "",
            "request_key": "",
            "execution_limits": execution_limits,
            "request_hash_digest": request_hash_digest,
            "request_hash": "0x" + request_hash_digest,
            "reservation": {},
            "reservation_nonce": None,
            "request_signature_nonce": None,
        }

    request_signature_nonce = _canonical_signature_nonce(message, "inference request")
    verification_time = int(time.time())
    try:
        unsigned = verify_document(
            message,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=config.peer_id,
            now=verification_time,
        )
    except IdentityError as exc:
        raise P2PError(f"invalid inference request signature: {exc}") from exc
    if _canonical_request_id(unsigned.get("request_id")) != request_id:
        raise P2PError("request_id changed during signature verification")
    signature = message.get("signature")
    consumer_public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if not consumer_public_key:
        raise P2PError("consumer public key is required")
    execution_limits = _inference_execution_limits(config, unsigned)
    request_hash_digest = _inference_request_hash(config, unsigned, execution_limits["output_token_cap"])
    request_hash = "0x" + request_hash_digest

    if has_session_v4:
        return _preverify_v4_session(
            config,
            unsigned,
            request_id=request_id,
            consumer_public_key=consumer_public_key,
            execution_limits=execution_limits,
            request_hash_digest=request_hash_digest,
            request_hash=request_hash,
            request_signature_nonce=request_signature_nonce,
            allow_v4_replay=allow_v4_replay,
        )
    wallet_bound_v3_session = (
        config.settlement_version == 3
        and config.require_signed_requests
        and config.require_payment_reservation
        and bool(config.settlement_contract)
        and config.settlement_chain_id is not None
    )
    if not config.authorized_consumers and not config.allow_any_signed_consumer and not wallet_bound_v3_session:
        raise P2PError("consumer allowlist is required")
    if (
        config.authorized_consumers
        and consumer_public_key not in config.authorized_consumers
        and not wallet_bound_v3_session
    ):
        raise P2PError("consumer is not authorized for this provider")

    reservation: dict[str, Any] = {}
    reservation_nonce: str | None = None
    if config.require_payment_reservation:
        reservation_nonce = _canonical_signature_nonce(
            message.get("payment_reservation"),
            "payment reservation",
        )
        try:
            reservation = verify_payment_reservation(
                message.get("payment_reservation"),
                request_id=request_id,
                channel=str(unsigned.get("channel") or config.channel),
                provider_id=config.peer_id,
                provider_payment_address=config.payment_address,
                consumer_public_key=consumer_public_key,
                min_fee_units=0,
                pricing_hash=None,
                settlement_version=config.settlement_version,
                pricing_version=config.pricing_version,
                request_hash=request_hash,
                settlement_chain_id=config.settlement_chain_id,
                settlement_contract=config.settlement_contract,
                now=verification_time,
            )
        except (ReservationError, RuntimeError, ValueError) as exc:
            raise P2PError(str(exc)) from exc
    if config.network_profile != "local":
        try:
            require_enabled_channel_binding(
                network_id=unsigned.get("network_id"),
                channel_id=unsigned.get("channel_id"),
                channel=unsigned.get("channel"),
                backend_policy=unsigned.get("backend_policy"),
                label="inference request",
            )
        except ValueError as exc:
            raise P2PError(str(exc)) from exc
    return {
        "unsigned": unsigned,
        "request_id": request_id,
        "consumer_public_key": consumer_public_key,
        "request_key": f"{consumer_public_key}:{request_id}",
        "execution_limits": execution_limits,
        "request_hash_digest": request_hash_digest,
        "request_hash": request_hash,
        "reservation": reservation,
        "reservation_nonce": reservation_nonce,
        "request_signature_nonce": request_signature_nonce,
    }


def _preverify_v4_session(
    config: ProviderConfig,
    unsigned: dict[str, Any],
    *,
    request_id: str,
    consumer_public_key: str,
    execution_limits: dict[str, int],
    request_hash_digest: str,
    request_hash: str,
    request_signature_nonce: str,
    allow_v4_replay: bool = False,
) -> dict[str, Any]:
    """Validate the bounded V4 session envelope attached to an inference."""
    # A completed/uncertain execution may have already advanced this process's
    # in-memory sequence tracker.  Admission still verifies every signature,
    # but permits the exact signed sequence to reach the durable idempotency
    # lookup below instead of rejecting it as a fresh request.
    existing_execution = (
        _v4_execution_claim_exists(config, consumer_public_key, request_id)
        if allow_v4_replay
        else False
    )
    try:
        authorization = verify_session_authorization(
            unsigned["session_authorization"],
            provider_id=config.peer_id,
            expected_channel=str(unsigned.get("channel") or config.channel),
            expected_pricing_version=config.pricing_version,
            expected_pricing_hash=config.pricing_hash,
            expected_session_public_key=consumer_public_key,
            now=int(time.time()),
            require_outer_signature=True,
            require_evm_signature=True,
        )
        committed_progress = _load_v4_session_progress(config, authorization)
        with config._session_v4_lock:
            previous_sequence, previous_spend = config._session_v4_progress.get(
                str(authorization["session_id"]).lower(),
                committed_progress
                or (int(authorization["sequence"]), int(authorization["cumulative_spend_units"])),
            )
        # New requests must extend the Provider's committed actual spend.  A
        # consumer cannot raise its own baseline merely by signing a larger
        # cumulative value after the Provider restarts.
        request_previous_spend = int(previous_spend)
        try:
            session_request = verify_session_request(
                unsigned["session_request"],
                authorization,
                previous_sequence=previous_sequence,
                previous_cumulative_spend_units=request_previous_spend,
                now=int(time.time()),
                require_outer_signature=True,
                require_evm_signature=True,
            )
        except SessionProtocolError as exc:
            message_text = str(exc).lower()
            if not existing_execution or not any(
                marker in message_text for marker in ("sequence", "cumulative")
            ):
                raise
            # Re-validate the complete envelope and both signatures against its
            # own predecessor.  The durable cache lookup later compares the
            # resulting request hash/session/sequence before returning data.
            raw_request = unsigned["session_request"]
            replay_sequence = int(raw_request["sequence"])
            replay_spend = int(raw_request["cumulative_spend_units"]) - int(
                raw_request["max_fee_units"]
            )
            session_request = verify_session_request(
                raw_request,
                authorization,
                previous_sequence=max(0, replay_sequence - 1),
                previous_cumulative_spend_units=max(0, replay_spend),
                now=int(time.time()),
                require_outer_signature=True,
                require_evm_signature=True,
            )
    except (SessionProtocolError, KeyError, TypeError, ValueError) as exc:
        raise P2PError(f"invalid Settlement V4 session envelope: {exc}") from exc

    if (
        int(session_request["sequence"]) > MAX_SQL_INTEGER
        or int(session_request["cumulative_spend_units"]) > MAX_SQL_INTEGER
        or int(session_request["max_fee_units"]) > MAX_SQL_INTEGER
    ):
        raise P2PError("Settlement V4 session counters exceed the Provider durable range")
    if session_request["request_id"] != request_id:
        raise P2PError("Settlement V4 session request_id mismatch")
    if session_request["request_hash"].lower() != request_hash.lower():
        raise P2PError("Settlement V4 session request_hash does not match inference input")
    if session_request["session_public_key"].lower() != consumer_public_key.lower():
        raise P2PError("Settlement V4 session signer does not match inference signer")
    if session_request["provider_id"] != config.peer_id:
        raise P2PError("Settlement V4 provider_id mismatch")
    configured_provider = normalize_payment_address(config.payment_address)
    if configured_provider and session_request["provider_payment_address"].lower() != configured_provider:
        raise P2PError("Settlement V4 provider payment address mismatch")
    if session_request["channel"] != config.channel:
        raise P2PError("Settlement V4 channel mismatch")
    if config.pricing_version is not None and int(session_request["pricing_version"]) != int(config.pricing_version):
        raise P2PError("Settlement V4 pricing_version mismatch")
    if config.pricing_hash and session_request["pricing_hash"].lower() != str(config.pricing_hash).lower():
        raise P2PError("Settlement V4 pricing_hash mismatch")
    if config.settlement_chain_id is None or not config.settlement_contract:
        raise P2PError("Settlement V4 chain configuration is incomplete")
    auth_chain_id = authorization.get("settlement_chain_id")
    auth_contract = authorization.get("settlement_contract")
    if auth_chain_id is None or auth_contract is None:
        raise P2PError("Settlement V4 session authorization must include deployment binding")
    try:
        from .chain import normalize_address

        if int(auth_chain_id) != int(config.settlement_chain_id):
            raise P2PError("Settlement V4 settlement_chain_id mismatch")
        if normalize_address(str(auth_contract)) != normalize_address(str(config.settlement_contract)):
            raise P2PError("Settlement V4 settlement_contract mismatch")
    except (TypeError, ValueError) as exc:
        raise P2PError(f"invalid Settlement V4 deployment binding: {exc}") from exc
    if config.network_profile != "local":
        try:
            require_enabled_channel_binding(
                network_id=session_request.get("network_id"),
                channel_id=session_request.get("channel_id"),
                channel=session_request.get("channel"),
                backend_policy=session_request.get("backend_policy"),
                label="Settlement V4 inference request",
            )
        except ValueError as exc:
            raise P2PError(str(exc)) from exc

    reservation: dict[str, Any] = {
        "settlement_version": 4,
        "session_id": authorization["session_id"],
        "session_key": authorization["session_key"],
        "session_public_key": authorization["session_public_key"],
        "consumer_public_key": consumer_public_key,
        "consumer_id": authorization.get("consumer_id") or unsigned.get("consumer_id") or "",
        "consumer_payment_address": authorization["consumer_payment_address"],
        "provider_id": config.peer_id,
        "provider_payment_address": session_request["provider_payment_address"],
        "channel": session_request["channel"],
        "pricing_version": int(session_request["pricing_version"]),
        "pricing_hash": session_request["pricing_hash"],
        "max_fee_units": int(session_request["max_fee_units"]),
        "amount_units": int(session_request["max_fee_units"]),
        "expires_at": int(authorization["expires_at"]),
        "settlement_deadline": int(session_request["deadline"]),
        "settlement_chain_id": int(auth_chain_id),
        "settlement_contract": str(auth_contract).lower(),
        "provider_fallback_allowed": bool(authorization.get("provider_fallback_allowed", False)),
        "request_hash": session_request["request_hash"],
        "sequence": int(session_request["sequence"]),
        "cumulative_spend_units": int(session_request["cumulative_spend_units"]),
        "authorization_hash": str(session_request["authorization_hash"]),
        "session_authorization": authorization,
        "session_request": session_request,
    }
    try:
        _verify_v4_onchain_session(config, reservation, allow_replay=existing_execution)
    except P2PError as exc:
        # A durable execution claim is already bound to this fully verified
        # request.  A transient RPC outage must not prevent replaying a result
        # (or reporting an in-flight/uncertain state); immutable envelope and
        # cache hashes are checked again before any response is returned.
        if not existing_execution or not str(exc).startswith(
            "failed to verify Settlement V4 session on-chain"
        ):
            raise
    return {
        "unsigned": unsigned,
        "request_id": request_id,
        "consumer_public_key": consumer_public_key,
        "request_key": f"{consumer_public_key}:{request_id}",
        "execution_limits": execution_limits,
        "request_hash_digest": request_hash_digest,
        "request_hash": request_hash,
        "reservation": reservation,
        "reservation_nonce": None,
        "request_signature_nonce": request_signature_nonce,
    }


def _verify_v4_onchain_session(
    config: ProviderConfig,
    reservation: dict[str, Any],
    *,
    allow_replay: bool = False,
) -> None:
    """Check the V4 session binding at latest state, with a short cache.

    This deliberately does not call ``_confirmed_settlement_block``.  Session
    admission only needs a current view of the escrow; request execution stays
    off-chain and is protected by the durable sequence claim.
    """
    if not config.session_v4_verify_onchain:
        return
    session_id = str(reservation.get("session_id") or "").lower()
    now = time.time()
    with config._session_v4_lock:
        cached = config._session_v4_cache.get(session_id)
        if cached and float(cached.get("until") or 0) > now:
            _validate_cached_v4_session(reservation, cached)
            _validate_v4_session_runtime_limits(reservation, cached, allow_replay=allow_replay)
            return
    try:
        from .chain import ChainError, call_contract, channel_to_hash, normalize_address, normalize_bytes32

        output = call_contract(
            str(config.settlement_rpc_url),
            str(config.settlement_contract),
            "sessionInfo(bytes32)",
            [normalize_bytes32(session_id)],
            timeout=float(config.settlement_rpc_timeout_seconds),
            block_tag="latest",
        )
        words = _abi_words(output, 13, "Settlement V4 session getter")
        closed_word = int(words[12], 16)
        if closed_word not in {0, 1}:
            raise ValueError("session getter returned malformed closed flag")
        state = {
            "consumer": normalize_address("0x" + words[0][-40:]),
            "provider": normalize_address("0x" + words[1][-40:]),
            "session_key": normalize_address("0x" + words[2][-40:]),
            "channel": normalize_bytes32("0x" + words[3]),
            "pricing_version": int(words[4], 16),
            "pricing_hash": normalize_bytes32("0x" + words[5]),
            "opened_at": int(words[6], 16),
            "expires_at": int(words[7], 16),
            "close_requested_at": int(words[8], 16),
            "max_amount": int(words[9], 16),
            "spent": int(words[10], 16),
            "next_sequence": int(words[11], 16),
            "closed": bool(closed_word),
        }
    except (ChainError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to verify Settlement V4 session on-chain: {exc}") from exc
    _validate_cached_v4_session(reservation, state)
    _validate_v4_session_runtime_limits(reservation, state, allow_replay=allow_replay)
    state = dict(state)
    state["until"] = now + int(config.session_v4_cache_seconds)
    with config._session_v4_lock:
        config._session_v4_cache[session_id] = state


def _validate_cached_v4_session(reservation: dict[str, Any], state: dict[str, Any]) -> None:
    """Validate immutable session fields against an on-chain/cache snapshot."""
    try:
        from .chain import channel_to_hash, normalize_address, normalize_bytes32

        if normalize_address(str(reservation["consumer_payment_address"])) != state["consumer"]:
            raise P2PError("Settlement V4 session consumer mismatch")
        if normalize_address(str(reservation["provider_payment_address"])) != state["provider"]:
            raise P2PError("Settlement V4 session provider mismatch")
        if normalize_address(str(reservation["session_key"])) != state["session_key"]:
            raise P2PError("Settlement V4 session key mismatch")
        if normalize_bytes32(channel_to_hash(str(reservation["channel"]))) != state["channel"]:
            raise P2PError("Settlement V4 session channel mismatch")
        if int(reservation["pricing_version"]) != int(state["pricing_version"]):
            raise P2PError("Settlement V4 session pricing_version mismatch")
        if normalize_bytes32(str(reservation["pricing_hash"])) != state["pricing_hash"]:
            raise P2PError("Settlement V4 session pricing_hash mismatch")
    except (TypeError, ValueError) as exc:
        raise P2PError(f"invalid Settlement V4 session binding: {exc}") from exc


def _validate_v4_session_runtime_limits(
    reservation: dict[str, Any],
    state: dict[str, Any],
    *,
    allow_replay: bool = False,
) -> None:
    current = int(time.time())
    if state.get("closed") and not allow_replay:
        raise P2PError("Settlement V4 session is closed")
    if int(state.get("expires_at") or 0) <= current and not allow_replay:
        raise P2PError("Settlement V4 session is expired")
    if int(state.get("expires_at") or 0) != int(reservation["expires_at"]) and not allow_replay:
        raise P2PError("Settlement V4 session expiry mismatch")
    if allow_replay:
        return
    if int(state.get("max_amount") or 0) < int(reservation.get("max_fee_units") or 0):
        raise P2PError("Settlement V4 session remaining cap is insufficient")
    if int(state.get("spent") or 0) + int(reservation.get("max_fee_units") or 0) > int(state.get("max_amount") or 0):
        raise P2PError("Settlement V4 session remaining balance is insufficient")
    if int(state.get("next_sequence") or 0) >= int(reservation.get("sequence") or 0):
        raise P2PError("Settlement V4 session sequence has already been settled")


def _p2p_execution_commitment(
    *,
    provider_peer_id: str,
    consumer_public_key: str,
    request_id: str,
    request_signature_nonce: str | None,
    payment_reservation_nonce: str | None,
    settlement_request_hash: str,
) -> str:
    document = {
        "schema": P2P_NATIVE_EXECUTION_SCHEMA,
        "provider_peer_id": provider_peer_id,
        "consumer_public_key": consumer_public_key,
        "request_id": request_id,
        "request_signature_nonce": request_signature_nonce or "",
        "payment_reservation_nonce": payment_reservation_nonce or "",
        "settlement_request_hash": settlement_request_hash,
    }
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise P2PError("native execution commitment must be canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _prepare_p2p_native_request(
    config: ProviderConfig,
    preverified: dict[str, Any],
) -> CanonicalNativeRequest:
    unsigned = preverified["unsigned"]
    endpoint = str(unsigned.get("endpoint") or "responses")
    allowed_fields = {
        "type",
        "request_id",
        "network_id",
        "channel_id",
        "channel",
        "backend_policy",
        "endpoint",
        "model",
        "input",
        "messages",
        "max_output_tokens",
        "metadata",
        "payment_reservation",
        "session_v4",
        "session_authorization",
        "session_request",
    }
    unsupported = sorted(set(unsigned) - allowed_fields)
    if unsupported:
        raise P2PError("native P2P inference does not support fields: " + ", ".join(unsupported))
    if unsigned.get("metadata") not in (None, {}):
        raise P2PError("native P2P inference does not support metadata")
    if endpoint == "chat" and unsigned.get("messages") is not None and unsigned.get("input") not in (None, ""):
        raise P2PError("native P2P chat must provide messages or input, not both")
    if endpoint == "responses" and "messages" in unsigned:
        raise P2PError("native P2P responses does not support messages")
    execution_hash = _p2p_execution_commitment(
        provider_peer_id=config.peer_id,
        consumer_public_key=str(preverified.get("consumer_public_key") or ""),
        request_id=str(preverified["request_id"]),
        request_signature_nonce=preverified.get("request_signature_nonce"),
        payment_reservation_nonce=preverified.get("reservation_nonce"),
        settlement_request_hash=str(preverified["request_hash_digest"]),
    )
    output_token_cap = int(preverified["execution_limits"]["output_token_cap"])
    if endpoint == "chat":
        messages = unsigned.get("messages")
        if messages is None:
            messages = [{"role": "user", "content": str(unsigned.get("input") or "")}]
        body = {
            "model": config.model,
            "messages": messages,
            "max_tokens": output_token_cap,
            "mycomesh_p2p_request_hash": execution_hash,
        }
    else:
        body = {
            "model": config.model,
            "input": unsigned.get("input") if unsigned.get("input") is not None else "",
            "max_output_tokens": output_token_cap,
            "mycomesh_p2p_request_hash": execution_hash,
        }
    try:
        return canonicalize_native_request(
            endpoint,
            body,
            expected_model=config.model,
            default_output_token_cap=config.reserve_output_tokens,
        )
    except (NativeMeteringRequestError, NativeMeteringError, TypeError, ValueError) as exc:
        raise P2PError(f"invalid native P2P inference request: {exc}") from exc


def verify_v3_onchain_reservation(
    config: ProviderConfig,
    reservation: dict[str, Any],
    *,
    now: int | None = None,
    request_hash: str | None = None,
    block_tag: int | None = None,
) -> dict[str, Any]:
    if not config.settlement_rpc_url or not config.settlement_contract:
        raise P2PError(
            "Settlement V3 requires provider settlement_rpc_url and settlement_contract for on-chain reservation verification"
        )
    try:
        from .chain import ChainError, call_contract, channel_to_hash, normalize_address, normalize_bytes32

        reservation_id = normalize_bytes32(str(reservation.get("onchain_reservation_id") or ""))
        output = call_contract(
            config.settlement_rpc_url,
            config.settlement_contract,
            "reservations(bytes32)",
            [reservation_id],
            timeout=float(config.settlement_rpc_timeout_seconds),
            block_tag=(block_tag if block_tag is not None else _confirmed_settlement_block(config)),
        )
        words = _abi_words(output, 9, "reservation getter")
        closed_value = int(words[7], 16)
        fallback_allowed_value = int(words[8], 16)
        if closed_value not in {0, 1} or fallback_allowed_value not in {0, 1}:
            raise ValueError("reservation getter returned a malformed boolean")
        onchain = {
            "consumer_payment_address": normalize_address("0x" + words[0][-40:]),
            "provider_payment_address": normalize_address("0x" + words[1][-40:]),
            "channel_hash": normalize_bytes32("0x" + words[2]),
            "request_hash": normalize_bytes32("0x" + words[3]),
            "pricing_version": int(words[4], 16),
            "expires_at": int(words[5], 16),
            "amount_units": int(words[6], 16),
            "closed": bool(closed_value),
            "provider_fallback_allowed": bool(fallback_allowed_value),
        }
        expected_consumer = normalize_address(str(reservation.get("consumer_payment_address") or ""))
        expected_provider = normalize_address(str(reservation.get("provider_payment_address") or ""))
        configured_provider = normalize_address(str(config.payment_address or ""))
        expected_channel = normalize_bytes32(channel_to_hash(str(reservation.get("channel") or "")))
        expected_request_hash = normalize_bytes32(str(request_hash or reservation.get("request_hash") or ""))
    except (ChainError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to verify Settlement V3 on-chain reservation: {exc}") from exc

    zero_address = "0x" + "0" * 40
    if onchain["consumer_payment_address"] == zero_address:
        raise P2PError("Settlement V3 on-chain reservation does not exist")
    if onchain["closed"]:
        raise P2PError("Settlement V3 on-chain reservation is closed")
    if onchain["consumer_payment_address"] != expected_consumer:
        raise P2PError("Settlement V3 on-chain reservation consumer mismatch")
    if onchain["provider_payment_address"] != expected_provider or expected_provider != configured_provider:
        raise P2PError("Settlement V3 on-chain reservation provider mismatch")
    if onchain["channel_hash"] != expected_channel:
        raise P2PError("Settlement V3 on-chain reservation channel mismatch")
    if onchain["request_hash"] != expected_request_hash:
        raise P2PError("Settlement V3 on-chain reservation request_hash mismatch")
    if onchain["pricing_version"] != int(reservation.get("pricing_version") or 0):
        raise P2PError("Settlement V3 on-chain reservation pricing_version mismatch")
    expected_fallback_allowed = reservation.get("provider_fallback_allowed")
    if not isinstance(expected_fallback_allowed, bool):
        raise P2PError("Settlement V3 reservation provider_fallback_allowed must be a boolean")
    if onchain["provider_fallback_allowed"] != expected_fallback_allowed:
        raise P2PError("Settlement V3 on-chain reservation provider_fallback_allowed mismatch")
    current_time = int(now if now is not None else time.time())
    if onchain["expires_at"] <= current_time:
        raise P2PError("Settlement V3 on-chain reservation is expired")
    if onchain["expires_at"] != int(reservation.get("expires_at") or 0):
        raise P2PError("Settlement V3 on-chain reservation expiry mismatch")
    if int(reservation.get("settlement_deadline") or 0) > onchain["expires_at"]:
        raise P2PError("Settlement V3 settlement deadline exceeds on-chain reservation expiry")
    if onchain["amount_units"] < int(reservation.get("max_fee_units") or 0):
        raise P2PError("Settlement V3 on-chain reservation amount is insufficient")
    return onchain


def verify_v3_latest_reservation_state(
    config: ProviderConfig,
    reservation: dict[str, Any],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Reject a reservation that became closed or expired after the confirmed snapshot."""
    if not config.settlement_rpc_url or not config.settlement_contract:
        raise P2PError("Settlement V3 latest-state verification requires chain configuration")
    try:
        from .chain import ChainError, call_contract, normalize_bytes32

        reservation_id = normalize_bytes32(str(reservation.get("onchain_reservation_id") or ""))
        output = call_contract(
            config.settlement_rpc_url,
            config.settlement_contract,
            "reservations(bytes32)",
            [reservation_id],
            timeout=float(config.settlement_rpc_timeout_seconds),
            block_tag="latest",
        )
        words = _abi_words(output, 9, "latest reservation getter")
        closed_value = int(words[7], 16)
        if closed_value not in {0, 1}:
            raise ValueError("latest reservation getter returned a malformed closed flag")
        latest = {
            "expires_at": int(words[5], 16),
            "closed": bool(closed_value),
        }
    except (ChainError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to verify latest Settlement V3 reservation state: {exc}") from exc
    if latest["closed"]:
        raise P2PError("Settlement V3 on-chain reservation is closed at latest block")
    current_time = int(now if now is not None else time.time())
    if latest["expires_at"] <= current_time:
        raise P2PError("Settlement V3 on-chain reservation is expired at latest block")
    return latest


def _verify_v3_session_wallet_authorization(
    config: ProviderConfig,
    reservation: dict[str, Any],
    *,
    block_tag: int | None,
    now: int,
) -> None:
    if not config.settlement_rpc_url:
        raise P2PError("Settlement V3 wallet authorization requires settlement_rpc_url")
    authorization = reservation.get("evm_session_authorization")
    consumer_address = str(reservation.get("consumer_payment_address") or "")
    resolved_block_tag = hex(max(0, int(block_tag))) if block_tag is not None else "latest"
    try:
        from .chain import ChainError, normalize_address, rpc_call

        consumer_address = normalize_address(consumer_address)
        settlement_caller = normalize_address(str(config.settlement_contract or ""))
        code = rpc_call(
            config.settlement_rpc_url,
            "eth_getCode",
            [consumer_address, resolved_block_tag],
            float(config.settlement_rpc_timeout_seconds),
        )
    except (ChainError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to identify Settlement V3 consumer wallet type: {exc}") from exc
    if (
        not isinstance(code, str)
        or not code.startswith("0x")
        or len(code[2:]) % 2
        or re.fullmatch(r"[0-9a-fA-F]*", code[2:]) is None
    ):
        raise P2PError("Settlement V3 eth_getCode returned malformed hex data")
    try:
        bytecode = bytes.fromhex(code[2:])
    except ValueError as exc:
        raise P2PError("Settlement V3 eth_getCode returned malformed hex data") from exc

    if not bytecode or not any(bytecode):
        try:
            verify_eoa_session_authorization(authorization, now=now)
        except ReservationError as exc:
            raise P2PError(str(exc)) from exc
        return

    signature = str(authorization.get("wallet_signature") or "") if isinstance(authorization, dict) else ""
    try:
        signature_bytes = bytes.fromhex(signature[2:])
        digest = evm_session_authorization_digest(authorization)
        from .chain import ChainError, keccak256, rpc_call

        selector = keccak256(b"isValidSignature(bytes32,bytes)")[:4]
        padded_length = (len(signature_bytes) + 31) // 32 * 32
        calldata = (
            selector
            + digest
            + (64).to_bytes(32, "big")
            + len(signature_bytes).to_bytes(32, "big")
            + signature_bytes.ljust(padded_length, b"\0")
        )
        result = rpc_call(
            config.settlement_rpc_url,
            "eth_call",
            [
                {
                    "from": settlement_caller,
                    "to": consumer_address,
                    "data": "0x" + calldata.hex(),
                },
                resolved_block_tag,
            ],
            float(config.settlement_rpc_timeout_seconds),
        )
    except (ChainError, ReservationError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to verify EIP-1271 session authorization: {exc}") from exc
    expected_result = "0x1626ba7e" + "0" * 56
    if not isinstance(result, str) or result.lower() != expected_result:
        raise P2PError("EIP-1271 consumer wallet rejected the session authorization")


def _claim_v3_authorization(
    config: ProviderConfig,
    reservation: dict[str, Any],
    *,
    now: int,
    request_key: str | None = None,
    payment_nonce_key: str | None = None,
    replay_ttl: int | None = None,
) -> None:
    if config._replay_store is None:
        raise P2PError("Settlement V3 requires a persistent replay store")
    try:
        from .chain import normalize_address, normalize_bytes32

        chain_id = int(reservation.get("settlement_chain_id"))
        contract = normalize_address(str(reservation.get("settlement_contract") or ""))
        reservation_id = normalize_bytes32(str(reservation.get("onchain_reservation_id") or ""))
        consumer = normalize_address(str(reservation.get("consumer_payment_address") or ""))
        authorization = reservation.get("evm_session_authorization")
        if not isinstance(authorization, dict):
            raise ValueError("EVM session authorization is required")
        session_nonce = normalize_bytes32(str(authorization.get("nonce") or ""))
        expires_at = int(reservation.get("expires_at"))
    except (RuntimeError, TypeError, ValueError) as exc:
        raise P2PError(f"invalid Settlement V3 replay claim: {exc}") from exc
    reservation_key = f"{chain_id}:{contract}:{reservation_id}"
    claims: list[tuple[str, str, int]] = [
        ("p2p.v3.onchain.reservation", reservation_key, expires_at),
        (
            "p2p.v3.session.authorization",
            f"{chain_id}:{contract}:{consumer}:{session_nonce}",
            expires_at,
        ),
    ]
    if (request_key is None) != (payment_nonce_key is None):
        raise P2PError("Settlement V3 request and payment replay claims must be provided together")
    if request_key is not None and payment_nonce_key is not None:
        generic_expires_at = now + max(1, int(replay_ttl or config.replay_ttl_seconds))
        claims[0:0] = [
            ("p2p.infer.request", request_key, generic_expires_at),
            ("p2p.payment.reservation", payment_nonce_key, generic_expires_at),
        ]
    try:
        _remember_v3_claims(
            config._replay_store,
            tuple(claims),
            now=now,
        )
    except ReplayError as exc:
        raise P2PError("Settlement V3 reservation or session authorization has already been consumed") from exc
    except Exception as exc:
        raise P2PError(f"failed to persist atomic Settlement V3 authorization claim: {exc}") from exc


def _claim_v4_authorization(
    config: ProviderConfig,
    session: dict[str, Any],
    *,
    request_key: str,
    now: int,
    replay_ttl: int,
) -> None:
    """Atomically claim a V4 request and its session sequence.

    A request id alone is insufficient: an attacker could replay the same
    session sequence under a different id.  The composite sequence key is
    durable in the provider replay store and remains reserved until the
    session expires.
    """
    if config._replay_store is None:
        raise P2PError("Settlement V4 requires a persistent replay store")
    try:
        from .chain import normalize_address, normalize_bytes32

        chain_id = int(session.get("settlement_chain_id") or config.settlement_chain_id or 0)
        contract = normalize_address(str(session.get("settlement_contract") or config.settlement_contract or ""))
        session_id = normalize_bytes32(str(session.get("session_id") or ""))
        sequence = int(session.get("sequence") or 0)
        expires_at = int(session.get("expires_at") or session.get("settlement_deadline") or 0)
        if chain_id <= 0 or sequence <= 0 or expires_at <= now:
            raise ValueError("invalid V4 session replay fields")
    except (TypeError, ValueError, RuntimeError) as exc:
        raise P2PError(f"invalid Settlement V4 replay claim: {exc}") from exc
    session_key = f"{chain_id}:{contract}:{session_id}:{sequence}"
    claims = (
        ("p2p.infer.request", request_key, now + max(1, int(replay_ttl))),
        ("p2p.v4.session.sequence", session_key, expires_at),
    )
    try:
        _load_v4_session_progress(config, session)
        with config._session_v4_lock:
            previous_sequence, previous_spend = config._session_v4_progress.get(
                session_id,
                (
                    int((session.get("session_authorization") or {}).get("sequence") or 0),
                    int((session.get("session_authorization") or {}).get("cumulative_spend_units") or 0),
                ),
            )
            if sequence != previous_sequence + 1:
                raise P2PError("Settlement V4 session sequence must increase exactly by one")
            cumulative = int(session.get("cumulative_spend_units") or 0)
            amount = int(session.get("max_fee_units") or 0)
            if cumulative < amount or cumulative > int((session.get("session_authorization") or {}).get("max_amount_units") or 0):
                raise P2PError("Settlement V4 cumulative spend exceeds the session cap")
            config._replay_store.claim_many(claims, now=now)
            session["_v4_claim_keys"] = tuple((scope, key) for scope, key, _ in claims)
            session["_v4_previous_progress"] = (previous_sequence, previous_spend)
            # Session progress advances only after the signed Provider response
            # is durable.  Keeping tentative max-fee spend out of this map also
            # prevents sequence N+1 from racing sequence N before actual usage
            # is known.
    except P2PError:
        raise
    except ReplayError as exc:
        raise P2PError("Settlement V4 session request or sequence has already been consumed") from exc
    except Exception as exc:
        raise P2PError(f"failed to persist atomic Settlement V4 authorization claim: {exc}") from exc


def _release_v4_authorization(config: ProviderConfig, session: dict[str, Any] | None) -> None:
    """Release a sequence when no signed Provider response was produced."""
    if not isinstance(session, dict) or int(session.get("settlement_version") or 0) != 4:
        return
    if config._replay_store is None:
        return
    claims = session.get("_v4_claim_keys")
    previous = session.get("_v4_previous_progress")
    session_id = str(session.get("session_id") or "").lower()
    try:
        if isinstance(claims, tuple) and claims:
            config._replay_store.forget_many(claims)
            request_keys = [
                str(key)
                for scope, key in claims
                if str(scope) == "p2p.infer.request"
            ]
            if request_keys:
                with config._seen_lock:
                    for request_key in request_keys:
                        config.seen_requests.pop(request_key, None)
        if isinstance(previous, tuple) and len(previous) == 2:
            with config._session_v4_lock:
                current = config._session_v4_progress.get(session_id)
                if current and int(current[0]) == int(session.get("sequence") or 0):
                    config._session_v4_progress[session_id] = (int(previous[0]), int(previous[1]))
    except Exception as exc:
        raise P2PError(f"failed to release unused Settlement V4 sequence: {exc}") from exc


def _remember_v3_claims(
    store: ReplayStore,
    claims: tuple[tuple[str, str, int], ...],
    *,
    now: int,
) -> None:
    """Atomically reserve all V3 replay keys in the configured shared store."""
    store.claim_many(claims, now=now)


def v3_onchain_quote(
    config: ProviderConfig,
    channel: str,
    pricing_version: int,
    input_tokens: int,
    output_tokens: int,
    *,
    block_tag: int | None = None,
) -> int:
    if not config.settlement_rpc_url or not config.settlement_contract:
        raise P2PError("Settlement V3 quote requires settlement RPC and contract configuration")
    try:
        from .chain import ChainError, call_contract, channel_to_hash

        output = call_contract(
            config.settlement_rpc_url,
            config.settlement_contract,
            "quote(bytes32,uint64,uint256,uint256)",
            [
                channel_to_hash(channel),
                str(int(pricing_version)),
                str(max(0, int(input_tokens))),
                str(max(0, int(output_tokens))),
            ],
            timeout=float(config.settlement_rpc_timeout_seconds),
            block_tag=(block_tag if block_tag is not None else _confirmed_settlement_block(config)),
        )
        return int(_abi_words(output, 1, "quote")[0], 16)
    except (ChainError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to read Settlement V3 on-chain quote: {exc}") from exc


def _confirmed_settlement_block(config: ProviderConfig) -> int:
    if not config.settlement_rpc_url:
        raise P2PError("settlement_rpc_url is required")
    try:
        from .chain import ChainError, rpc_int

        timeout = float(config.settlement_rpc_timeout_seconds)
        chain_id = rpc_int(config.settlement_rpc_url, "eth_chainId", [], timeout)
        if config.settlement_chain_id is not None and chain_id != config.settlement_chain_id:
            raise P2PError(
                f"settlement RPC chain id mismatch: expected {config.settlement_chain_id}, got {chain_id}"
            )
        latest_block = rpc_int(config.settlement_rpc_url, "eth_blockNumber", [], timeout)
    except ChainError as exc:
        raise P2PError(f"failed to read confirmed settlement block: {exc}") from exc
    return max(0, latest_block - config.settlement_confirmations)


def _abi_words(output: str, count: int, label: str = "contract call") -> list[str]:
    raw = str(output or "")
    if not raw.startswith("0x") or len(raw) != 2 + count * 64:
        raise ValueError(f"{label} returned malformed ABI data")
    return [raw[2 + index * 64 : 2 + (index + 1) * 64] for index in range(count)]


def _bounded_config_int(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int:
        raise P2PError(f"{label} must be an integer")
    if value <= 0 or value > maximum:
        raise P2PError(f"{label} must be between 1 and {maximum}")
    return value


def _inference_execution_limits(config: ProviderConfig, message: dict[str, Any]) -> dict[str, int]:
    endpoint = str(message.get("endpoint") or "responses")
    requested_model = str(message.get("model") or config.model)
    if requested_model != config.model:
        raise P2PError(
            f"requested model does not match provider descriptor: {requested_model!r} != {config.model!r}"
        )
    if endpoint == "chat":
        request_value = message.get("messages")
        if request_value is None:
            request_value = [{"role": "user", "content": str(message.get("input") or "")}]
    elif endpoint == "responses":
        request_value = message.get("input") if message.get("input") is not None else ""
    else:
        raise P2PError(f"unsupported inference endpoint: {endpoint}")
    if _contains_inline_pdf_data(request_value):
        raise P2PError(
            "inline PDF file_data is unsupported; extract it in a bounded sandbox and submit exact input_text"
        )
    canonical_input = canonical_inference_input_bytes(request_value)
    input_size_bytes = len(canonical_input)
    if input_size_bytes > config.reserve_input_tokens:
        raise P2PError(
            "inference input exceeds provider reserve_input_tokens: "
            f"{input_size_bytes} > {config.reserve_input_tokens} canonical JSON UTF-8 bytes"
        )

    requested_output = message.get("max_output_tokens")
    if requested_output is None:
        output_token_cap = config.reserve_output_tokens
    else:
        output_token_cap = _strict_request_int(requested_output, "max_output_tokens")
        if output_token_cap > config.reserve_output_tokens:
            raise P2PError(
                "max_output_tokens exceeds provider reserve_output_tokens: "
                f"{output_token_cap} > {config.reserve_output_tokens}"
            )
    return {
        "input_size_bytes": input_size_bytes,
        "input_token_upper_bound": config.reserve_input_tokens,
        "output_token_cap": output_token_cap,
    }


def canonical_inference_input_bytes(request_value: Any) -> bytes:
    try:
        return json.dumps(
            request_value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise P2PError(f"inference input/messages must be canonical JSON data: {exc}") from exc


def _strict_request_int(value: Any, label: str) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        parsed = int(value)
    else:
        raise P2PError(f"{label} must be a positive integer")
    if parsed <= 0:
        raise P2PError(f"{label} must be a positive integer")
    return parsed


def _contains_inline_pdf_data(value: Any) -> bool:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if item.get("type") == "input_file":
                file_data = item.get("file_data")
                if _is_pdf_data_uri(file_data):
                    return True
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def _is_pdf_data_uri(value: Any) -> bool:
    if not isinstance(value, str) or len(value) < 5 or value[:5].lower() != "data:":
        return False
    metadata, separator, _payload = value[5:].partition(",")
    if not separator:
        return False
    media_type = metadata.split(";", 1)[0]
    return media_type.lower() == "application/pdf"


def _inference_request_hash(config: ProviderConfig, message: dict[str, Any], output_token_cap: int) -> str:
    try:
        return inference_request_hash(
            endpoint=str(message.get("endpoint") or "responses"),
            model=str(message.get("model") or config.model),
            input_value=message.get("input"),
            messages=message.get("messages"),
            max_output_tokens=output_token_cap,
        )
    except ReservationError as exc:
        raise P2PError(str(exc)) from exc


def _validate_settlement_window(config: ProviderConfig, reservation: dict[str, Any]) -> None:
    deadline = _strict_request_int(reservation.get("settlement_deadline"), "settlement_deadline")
    expiry = _strict_request_int(reservation.get("expires_at"), "expires_at")
    minimum_deadline = math.ceil(
        time.time() + float(config.timeout_seconds) + SETTLEMENT_INCLUSION_BUFFER_SECONDS
    )
    if deadline < minimum_deadline:
        raise P2PError(
            "Settlement V3 settlement_deadline is too soon; it must allow the provider timeout "
            f"plus a {SETTLEMENT_INCLUSION_BUFFER_SECONDS}-second transaction inclusion buffer"
        )
    if deadline > expiry:
        raise P2PError("Settlement V3 settlement deadline exceeds reservation expiry")


def provider_min_reservation_units(
    channel: str,
    pricing_table: dict[str, ChannelPricing] | None = None,
    *,
    input_tokens: int = 8000,
    output_tokens: int = 2000,
) -> int:
    quote = quote_usage(
        channel,
        {
            "input_tokens": max(0, int(input_tokens)),
            "output_tokens": max(0, int(output_tokens)),
        },
        pricing_table=pricing_table,
    )
    return max(1, usdc_to_units(quote.to_dict()["gross_fee"]))


def build_gateway_request_body(
    endpoint: str,
    model: str,
    input_value: Any = None,
    messages: Any = None,
    metadata: Any = None,
    max_output_tokens: Any = None,
    p2p_request_hash: str | None = None,
) -> dict[str, Any]:
    output_limit = _positive_optional_int(max_output_tokens)
    if endpoint == "chat":
        chat_messages = messages
        if chat_messages is None:
            chat_messages = [{"role": "user", "content": str(input_value or "")}]
        body = {
            "model": model,
            "messages": chat_messages,
            "gateway_stateful": False,
            "gateway_metadata": metadata or {},
        }
        if output_limit is not None:
            body["max_tokens"] = output_limit
        if p2p_request_hash:
            body["mycomesh_p2p_request_hash"] = p2p_request_hash
        return body
    if endpoint == "responses":
        body = {
            "model": model,
            "input": input_value if input_value is not None else "",
            "gateway_stateful": False,
            "metadata": metadata or {},
        }
        if output_limit is not None:
            body["max_output_tokens"] = output_limit
        if p2p_request_hash:
            body["mycomesh_p2p_request_hash"] = p2p_request_hash
        return body
    raise P2PError(f"unsupported inference endpoint: {endpoint}")


def _positive_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def ensure_gateway_readiness(
    config: ProviderConfig,
    *,
    output_token_cap: int,
) -> None:
    if config.network_profile == "local":
        return
    monotonic_now = time.monotonic()
    if (
        config._gateway_readiness_until > monotonic_now
        and config._gateway_readiness_max_output_token_cap >= output_token_cap
    ):
        return
    with config._gateway_readiness_lock:
        monotonic_now = time.monotonic()
        if (
            config._gateway_readiness_until > monotonic_now
            and config._gateway_readiness_max_output_token_cap >= output_token_cap
        ):
            return
        gateway_base = config.gateway_url.rstrip("/")
        if gateway_base.endswith("/v1"):
            gateway_base = gateway_base[:-3]
        health_url = gateway_base.rstrip("/") + "/ready"
        request = urllib.request.Request(
            health_url,
            headers={"accept": "application/json"},
            method="GET",
        )
        timeout = min(5.0, float(config.timeout_seconds))
        deadline = time.monotonic() + timeout
        try:
            with _GATEWAY_OPENER.open(request, timeout=timeout) as response:
                content = read_bounded(
                    response,
                    maximum=MAX_GATEWAY_HEALTH_RESPONSE_BYTES,
                    label="gateway health response",
                    deadline=deadline,
                )
        except urllib.error.HTTPError as exc:
            raise P2PError(f"gateway readiness returned HTTP {exc.code}") from exc
        except (NetworkIOError, OSError, urllib.error.URLError) as exc:
            raise P2PError(f"gateway readiness check failed: {exc}") from exc
        try:
            health = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise P2PError("gateway readiness response must be valid JSON") from exc
        maximum_output_token_cap = _validate_gateway_readiness_document(
            config,
            health,
            output_token_cap=output_token_cap,
        )
        config._gateway_readiness_max_output_token_cap = maximum_output_token_cap
        config._gateway_readiness_until = (
            time.monotonic() + GATEWAY_READINESS_LEASE_SECONDS
        )


def invalidate_gateway_readiness(config: ProviderConfig) -> None:
    with config._gateway_readiness_lock:
        config._gateway_readiness_until = 0.0
        config._gateway_readiness_max_output_token_cap = 0


def _validate_gateway_readiness_document(
    config: ProviderConfig,
    health: Any,
    *,
    output_token_cap: int,
) -> int:
    if not isinstance(health, dict):
        raise P2PError("gateway readiness response must be a JSON object")
    if health.get("network_profile") != config.network_profile:
        raise P2PError("gateway readiness network profile does not match the provider")
    if health.get("production_strict") is not True or health.get("settlement_ready") is not True:
        raise P2PError("gateway is not settlement-ready")
    if health.get("public_model_id") != config.model:
        raise P2PError("gateway public model does not match the provider descriptor")
    capabilities = health.get("inference_capabilities")
    if not isinstance(capabilities, dict):
        raise P2PError("gateway readiness is missing inference capabilities")
    if capabilities.get("backend") == "codex_app_server":
        return _validate_codex_testnet_readiness(
            config,
            capabilities,
            output_token_cap=output_token_cap,
        )
    expected_flags = {
        "schema": "mycomesh.inference.capabilities.v1",
        "backend": "native_metered_http",
        "native_output_token_cap": True,
        "native_usage_events": True,
        "trusted_native_usage": True,
        "runtime_metering_proof": True,
        "supports_streaming": False,
        "production_ready": True,
    }
    for field, expected in expected_flags.items():
        if capabilities.get(field) != expected:
            raise P2PError(f"gateway readiness capability {field!r} does not match")
    expected_model = _required_metering_env("CENTER_MODEL")
    expected_revision = _required_metering_env("UPSTREAM_EXPECTED_MODEL_REVISION")
    expected_digest = _normalized_metering_hex(
        _required_metering_env("UPSTREAM_CAPABILITIES_SHA256"),
        "UPSTREAM_CAPABILITIES_SHA256",
    )
    public_key = _normalized_metering_hex(
        _required_metering_env("UPSTREAM_METERING_PUBLIC_KEY"),
        "UPSTREAM_METERING_PUBLIC_KEY",
    )
    expected_fingerprint = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
    exact_fields = {
        "model": expected_model,
        "model_revision": expected_revision,
        "capabilities_sha256": expected_digest,
        "metering_key_fingerprint": expected_fingerprint,
    }
    for field, expected in exact_fields.items():
        actual = capabilities.get(field)
        if field == "capabilities_sha256" and isinstance(actual, str):
            actual = actual.lower()
        if actual != expected:
            raise P2PError(f"gateway readiness capability {field!r} is not pinned")
    maximum = capabilities.get("maximum_output_token_cap")
    if type(maximum) is not int or maximum < output_token_cap:
        raise P2PError("gateway readiness output-token cap is below the request")
    return maximum


def _validate_codex_testnet_readiness(
    config: ProviderConfig,
    capabilities: dict[str, Any],
    *,
    output_token_cap: int,
) -> int:
    if config.network_profile != "testnet" or not _codex_testnet_metering_enabled():
        raise P2PError("Codex app-server metering is allowed only by the explicit testnet policy")
    expected_flags = {
        "schema": "mycomesh.inference.capabilities.v1",
        "backend": "codex_app_server",
        "native_output_token_cap": False,
        "native_usage_events": True,
        "trusted_native_usage": True,
        "runtime_metering_proof": False,
        "post_execution_output_cap_validation": True,
        "metering_mode": CODEX_TESTNET_METERING_MODE,
        "supports_streaming": False,
        "production_ready": True,
    }
    for field, expected in expected_flags.items():
        if capabilities.get(field) != expected:
            raise P2PError(f"Codex testnet readiness capability {field!r} does not match")
    maximum = capabilities.get("maximum_output_token_cap")
    if type(maximum) is not int or maximum < output_token_cap:
        raise P2PError("Codex testnet output-token cap is below the request")
    return maximum


def verify_gateway_metering(
    config: ProviderConfig,
    raw: dict[str, Any],
    *,
    native_request: CanonicalNativeRequest,
) -> dict[str, int]:
    if config.network_profile == "local":
        usage = raw.get("usage")
        return usage if isinstance(usage, dict) else {}
    if not isinstance(native_request, CanonicalNativeRequest):
        raise P2PError("canonical native request is required for non-local metering")
    if _codex_testnet_metering_enabled():
        return _verify_codex_testnet_gateway_usage(
            config,
            raw,
            native_request=native_request,
        )

    proof = raw.get("_mycomesh_metering")
    if not isinstance(proof, dict):
        raise P2PError("non-local gateway response is missing signed native metering")
    public_key = _normalized_metering_hex(
        _required_metering_env("UPSTREAM_METERING_PUBLIC_KEY"),
        "UPSTREAM_METERING_PUBLIC_KEY",
    )
    audience = _required_metering_env("UPSTREAM_METERING_AUDIENCE")
    model = _required_metering_env("CENTER_MODEL")
    revision = _required_metering_env("UPSTREAM_EXPECTED_MODEL_REVISION")
    capabilities_sha256 = _normalized_metering_hex(
        _required_metering_env("UPSTREAM_CAPABILITIES_SHA256"),
        "UPSTREAM_CAPABILITIES_SHA256",
    )
    if config.model != model or native_request.model != model:
        raise P2PError("native metering model does not match the Provider configuration")
    try:
        unsigned = verify_document(
            proof,
            purpose="mycomesh.inference.metering.v1",
            audience=audience,
            max_age_seconds=120,
        )
    except IdentityError as exc:
        raise P2PError(f"invalid native metering proof: {exc}") from exc
    signature = proof.get("signature")
    signed_public_key = (
        str(signature.get("public_key") or "").lower()
        if isinstance(signature, dict)
        else ""
    )
    if signed_public_key != public_key:
        raise P2PError("native metering proof used an unpinned public key")

    expected_fields = {
        "schema": "mycomesh.inference.metering.v1",
        "endpoint": native_request.endpoint,
        "model": model,
        "model_revision": revision,
        "capabilities_sha256": capabilities_sha256,
        "output_token_cap": native_request.output_token_cap,
        "p2p_request_hash": native_request.p2p_request_hash,
    }
    for field, expected in expected_fields.items():
        if unsigned.get(field) != expected:
            raise P2PError(f"native metering field {field!r} does not match")
    request_id = str(unsigned.get("request_id") or "")
    if not request_id.startswith("mreq_") or len(request_id) > 128:
        raise P2PError("native metering request_id is invalid")
    nonce = _normalized_metering_hex(unsigned.get("nonce"), "native metering nonce")
    request_hash = _normalized_metering_hex(
        unsigned.get("request_hash"), "native metering request_hash"
    )
    try:
        expected_request_hash = native_inference_request_hash(
            native_request,
            request_id=request_id,
            nonce=nonce,
            audience=audience,
            model_revision=revision,
        )
    except (NativeMeteringError, NativeMeteringRequestError, TypeError, ValueError) as exc:
        raise P2PError(f"failed to reconstruct native inference envelope: {exc}") from exc
    if request_hash != expected_request_hash:
        raise P2PError("native metering request_hash does not bind the canonical provider payload")
    response_hash = _normalized_metering_hex(
        unsigned.get("response_hash"), "native metering response_hash"
    )

    allowed_internal_fields = {"_mycomesh_metering", "_mycomesh_capabilities_sha256"}
    unexpected_internal = sorted(
        key
        for key in raw
        if isinstance(key, str) and key.startswith("_mycomesh_") and key not in allowed_internal_fields
    )
    if unexpected_internal:
        raise P2PError("gateway result contains untrusted reserved fields")
    usage = raw.get("usage")
    response_document = {
        key: value
        for key, value in raw.items()
        if key != "usage" and key not in allowed_internal_fields
    }
    try:
        validate_metered_result_shape(
            native_request.endpoint,
            {**response_document, "usage": usage},
        )
        encoded_response = json.dumps(
            response_document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (NativeMeteringError, NativeMeteringRequestError, TypeError, ValueError) as exc:
        raise P2PError("gateway result must be a valid native metering response") from exc
    actual_response_hash = hashlib.sha256(encoded_response).hexdigest()
    if response_hash != actual_response_hash:
        raise P2PError("native metering response_hash does not match the gateway result")
    now = int(time.time())
    issued_at = _exact_metering_int(unsigned.get("issued_at"), "issued_at")
    expires_at = _exact_metering_int(unsigned.get("expires_at"), "expires_at")
    if issued_at > now + 30 or expires_at < now:
        raise P2PError("native metering proof is not currently valid")
    if expires_at <= issued_at or expires_at - issued_at > 120:
        raise P2PError("native metering proof lifetime exceeds the protocol maximum")
    if raw.get("model") != model:
        raise P2PError("gateway result model does not match the pinned native model")
    if str(raw.get("_mycomesh_capabilities_sha256") or "").lower() != capabilities_sha256:
        raise P2PError("gateway result capability digest does not match the pinned contract")

    input_tokens = _exact_metering_token_count(unsigned.get("input_tokens"), "input_tokens")
    output_tokens = _exact_metering_token_count(unsigned.get("output_tokens"), "output_tokens")
    total_tokens = _exact_metering_token_count(unsigned.get("total_tokens"), "total_tokens")
    if total_tokens != input_tokens + output_tokens:
        raise P2PError("native metering total_tokens is inconsistent")
    if input_tokens > config.reserve_input_tokens:
        raise P2PError("native metering input_tokens exceed the provider reservation bound")
    if output_tokens > native_request.output_token_cap:
        raise P2PError("native metering output_tokens exceed the authorized cap")
    if native_request.endpoint == "chat":
        verified_usage = {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": total_tokens,
        }
    else:
        verified_usage = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
        }
    if usage != verified_usage:
        raise P2PError("gateway usage does not match the signed native metering proof")
    if config._replay_store is None:
        raise P2PError("persistent replay protection is required for native metering")
    signature_nonce = str(signature.get("nonce") or "")
    try:
        config._replay_store.remember(
            "p2p.native_metering.proof",
            f"{request_id}:{signature_nonce}",
            ttl_seconds=max(1, expires_at - now),
            now=now,
        )
    except ReplayError as exc:
        raise P2PError("native metering proof has already been consumed") from exc
    return verified_usage


def _verify_codex_testnet_gateway_usage(
    config: ProviderConfig,
    raw: dict[str, Any],
    *,
    native_request: CanonicalNativeRequest,
) -> dict[str, int]:
    if config.network_profile != "testnet":
        raise P2PError("Codex app-server metering is restricted to testnet")
    gateway_host = urllib.parse.urlsplit(config.gateway_url).hostname or ""
    try:
        gateway_is_loopback = ipaddress.ip_address(gateway_host).is_loopback
    except ValueError:
        gateway_is_loopback = gateway_host.lower() == "localhost"
    if not gateway_is_loopback or config.allow_remote_gateway_https:
        raise P2PError("Codex testnet metering requires the managed loopback Gateway")
    if config.model != native_request.model or raw.get("model") != config.model:
        raise P2PError("Codex testnet Gateway model does not match the Provider configuration")
    if any(isinstance(key, str) and key.startswith("_mycomesh_") for key in raw):
        raise P2PError("Codex testnet Gateway result contains reserved fields")
    try:
        validate_metered_result_shape(native_request.endpoint, raw)
    except (NativeMeteringError, NativeMeteringRequestError, TypeError, ValueError) as exc:
        raise P2PError("Codex testnet Gateway result has an invalid response shape") from exc
    usage = raw.get("usage")
    if not isinstance(usage, dict):
        raise P2PError("Codex testnet Gateway result is missing native usage")
    if native_request.endpoint == "chat":
        expected_keys = {"prompt_tokens", "completion_tokens", "total_tokens"}
        input_field = "prompt_tokens"
        output_field = "completion_tokens"
    else:
        expected_keys = {"input_tokens", "output_tokens", "total_tokens"}
        input_field = "input_tokens"
        output_field = "output_tokens"
    if set(usage) != expected_keys:
        raise P2PError("Codex testnet Gateway usage has an invalid shape")
    input_tokens = _exact_metering_token_count(usage.get(input_field), input_field)
    output_tokens = _exact_metering_token_count(usage.get(output_field), output_field)
    total_tokens = _exact_metering_token_count(usage.get("total_tokens"), "total_tokens")
    if total_tokens != input_tokens + output_tokens:
        raise P2PError("Codex testnet Gateway total_tokens is inconsistent")
    if input_tokens > config.reserve_input_tokens:
        raise P2PError("Codex testnet Gateway input_tokens exceed the reservation bound")
    if output_tokens > native_request.output_token_cap:
        raise P2PError("Codex testnet Gateway output_tokens exceed the authorized cap")
    return {
        input_field: input_tokens,
        output_field: output_tokens,
        "total_tokens": total_tokens,
    }


def _codex_testnet_metering_enabled() -> bool:
    return (
        str(os.getenv("GATEWAY_BACKEND") or "").strip() == "codex_app_server"
        and str(os.getenv("MYCOMESH_CODEX_TESTNET_METERING") or "").strip().lower()
        in {"1", "true", "yes", "on"}
    )


def _required_metering_env(name: str) -> str:
    value = os.getenv(name)
    if not value or value != value.strip():
        raise P2PError(f"{name} is required to verify non-local gateway metering")
    return value


def _normalized_metering_hex(value: Any, label: str) -> str:
    normalized = str(value or "").lower()
    if len(normalized) != 64:
        raise P2PError(f"{label} must be 32-byte hex")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise P2PError(f"{label} must be 32-byte hex") from exc
    return normalized


def _exact_metering_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise P2PError(f"native metering {label} must be an exact integer")
    return value


def _exact_metering_token_count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value > (1 << 63) - 1:
        raise P2PError(f"native metering {label} must be a bounded non-negative integer")
    return value


def call_gateway(
    gateway_url: str,
    agent_key: str,
    endpoint: str,
    body: dict[str, Any],
    timeout: float,
    allow_remote_gateway_https: bool = False,
) -> dict[str, Any]:
    path = "/chat/completions" if endpoint == "chat" else "/responses"
    return _call_gateway_path(
        gateway_url=gateway_url,
        agent_key=agent_key,
        path=path,
        body=body,
        timeout=timeout,
        allow_remote_gateway_https=allow_remote_gateway_https,
    )


def call_native_gateway(
    gateway_url: str,
    agent_key: str,
    native_request: CanonicalNativeRequest,
    timeout: float,
    allow_remote_gateway_https: bool = False,
) -> dict[str, Any]:
    gateway_base = gateway_url.rstrip("/")
    if gateway_base.endswith("/v1"):
        gateway_base = gateway_base[:-3]
    payload = dict(native_request.payload)
    cap_field = "max_tokens" if native_request.endpoint == "chat" else "max_output_tokens"
    payload[cap_field] = native_request.output_token_cap
    return _call_gateway_path(
        gateway_url=gateway_base,
        agent_key=agent_key,
        path="/mycomesh/p2p-infer",
        body={
            "schema": P2P_NATIVE_INFERENCE_SCHEMA,
            "endpoint": native_request.endpoint,
            "request": payload,
        },
        timeout=timeout,
        allow_remote_gateway_https=allow_remote_gateway_https,
    )


def _call_gateway_path(
    *,
    gateway_url: str,
    agent_key: str,
    path: str,
    body: dict[str, Any],
    timeout: float,
    allow_remote_gateway_https: bool,
) -> dict[str, Any]:
    validate_gateway_url(gateway_url, allow_remote_https=allow_remote_gateway_https)
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=MAX_P2P_NETWORK_TIMEOUT_SECONDS,
            label="gateway timeout",
        )
    except NetworkIOError as exc:
        raise P2PError(str(exc)) from exc
    url = gateway_url.rstrip("/") + path
    request = urllib.request.Request(
        url,
        data=json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {agent_key}",
        },
        method="POST",
    )
    deadline = time.monotonic() + timeout
    try:
        with _GATEWAY_OPENER.open(request, timeout=timeout) as response:
            payload = read_bounded(
                response,
                maximum=MAX_GATEWAY_RESPONSE_BYTES,
                label="gateway response",
                deadline=deadline,
            ).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            payload = read_bounded(
                exc,
                maximum=MAX_GATEWAY_ERROR_RESPONSE_BYTES,
                label="gateway error response",
                deadline=deadline,
            ).decode("utf-8", errors="replace")
        except NetworkIOError as body_exc:
            raise P2PError(
                f"gateway returned HTTP {exc.code} with an oversized or invalid error response"
            ) from body_exc
        raise P2PError(
            f"gateway returned HTTP {exc.code}: {text_preview(payload)}"
        ) from exc
    except NetworkIOError as exc:
        raise P2PError(str(exc)) from exc
    except urllib.error.URLError as exc:
        raise P2PError(f"failed to reach provider gateway: {exc}") from exc
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise P2PError("gateway response must be valid JSON") from exc
    if not isinstance(result, dict):
        raise P2PError("gateway response must be a JSON object")
    return result


class _NoGatewayRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


_GATEWAY_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoGatewayRedirectHandler(),
)


def validate_gateway_url(gateway_url: str, *, allow_remote_https: bool = False) -> None:
    try:
        parsed = urllib.parse.urlsplit(str(gateway_url or ""))
        port = parsed.port
    except ValueError as exc:
        raise P2PError(f"invalid provider gateway URL: {exc}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise P2PError("provider gateway URL must use http:// or https://")
    if not parsed.hostname:
        raise P2PError("provider gateway URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise P2PError("provider gateway URL must not include userinfo")
    if parsed.query or parsed.fragment:
        raise P2PError("provider gateway URL must not include a query or fragment")

    hostname = parsed.hostname.rstrip(".").lower()
    if not allow_remote_https and hostname != "localhost":
        try:
            literal_host = ipaddress.ip_address(hostname.split("%", 1)[0])
        except ValueError as exc:
            raise P2PError("provider gateway URL must use localhost or a literal loopback IP") from exc
        if not literal_host.is_loopback:
            raise P2PError("provider gateway URL must resolve only to loopback")

    resolved_port = port or (443 if parsed.scheme == "https" else 80)
    try:
        answers = socket.getaddrinfo(hostname, resolved_port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise P2PError(f"provider gateway host could not be resolved: {exc}") from exc
    resolved_hosts = {str(answer[4][0]).split("%", 1)[0] for answer in answers if answer[4]}
    if not resolved_hosts:
        raise P2PError("provider gateway host did not resolve to an address")
    is_loopback = all(_is_loopback_ip(host) for host in resolved_hosts)
    if is_loopback:
        return
    if not allow_remote_https:
        raise P2PError(
            "provider gateway URL must resolve only to loopback; use an explicit remote HTTPS gateway configuration if required"
        )
    if parsed.scheme != "https":
        raise P2PError("remote provider gateways require https://")


def _is_loopback_ip(value: str) -> bool:
    try:
        return bool(ipaddress.ip_address(value).is_loopback)
    except ValueError:
        return False


def extract_output_text(endpoint: str, raw: dict[str, Any]) -> str:
    if endpoint == "responses":
        return str(raw.get("output_text") or "")
    try:
        return str(raw["choices"][0]["message"].get("content") or "")
    except (KeyError, IndexError, TypeError):
        return ""


def provider_descriptor(config: ProviderConfig) -> dict[str, Any]:
    transport_key = config.ensure_transport_key()
    scheme = "tcp" if config.network_profile == "local" else "myco+tcp"
    descriptor = {
        "peer_id": config.peer_id,
        "protocol": PROTOCOL_VERSION,
        "address": f"{scheme}://{config.advertise_host}:{config.advertise_port}",
        "channel": config.channel,
        "agent_id": config.agent_id,
        "model": config.model,
        "last_seen": int(time.time()),
        "capacity": {
            "max_concurrency": config.max_concurrency,
            "reserve_input_bytes": config.reserve_input_tokens,
            "reserve_output_tokens": config.reserve_output_tokens,
        },
    }
    if config.network_profile != "local":
        descriptor.update(
            {
                "network_id": config.network_id,
                "channel_id": config.channel_id,
                "backend_policy": config.backend_policy,
            }
        )
    descriptor.update(provider_runtime_capabilities(config))
    if config.identity is not None:
        descriptor["public_key"] = config.identity.public_key
    if transport_key is not None:
        descriptor["transport_key"] = transport_key.binding
    if config.payment_address:
        descriptor["payment_address"] = config.payment_address
    return descriptor


def provider_runtime_capabilities(config: ProviderConfig) -> dict[str, Any]:
    capabilities: dict[str, Any] = {}
    if config.settlement_version in {3, 4}:
        capabilities["settlement"] = {
            "version": config.settlement_version,
            "chain_id": config.settlement_chain_id,
            "contract": str(config.settlement_contract or "").lower(),
            "pricing_version": config.pricing_version,
            "pricing_hash": str(config.pricing_hash or "").lower(),
        }
    if config.session_v4_enabled:
        capabilities["session_settlement"] = {
            "schema": "mycomesh.session.v4",
            "version": 4,
            "chain_id": config.settlement_chain_id,
            "contract": str(config.settlement_contract or "").lower(),
            "pricing_version": config.pricing_version,
            "pricing_hash": str(config.pricing_hash or "").lower(),
            "per_request_chain_transaction": False,
            "provider_receipt": "mycomesh.settlement.v4.provider.v1",
        }
    if config.network_profile != "local" and _codex_testnet_metering_enabled():
        capabilities["metering"] = {
            "schema": "mycomesh.inference.capabilities.v1",
            "mode": CODEX_TESTNET_METERING_MODE,
            "model": config.model,
            "maximum_output_token_cap": config.reserve_output_tokens,
            "runtime_metering_proof": False,
            "post_execution_output_cap_validation": True,
        }
    elif config.network_profile != "local":
        public_key = _normalized_metering_hex(
            _required_metering_env("UPSTREAM_METERING_PUBLIC_KEY"),
            "UPSTREAM_METERING_PUBLIC_KEY",
        )
        capabilities["metering"] = {
            "schema": "mycomesh.inference.capabilities.v1",
            "model": _required_metering_env("CENTER_MODEL"),
            "model_revision": _required_metering_env(
                "UPSTREAM_EXPECTED_MODEL_REVISION"
            ),
            "capabilities_sha256": _normalized_metering_hex(
                _required_metering_env("UPSTREAM_CAPABILITIES_SHA256"),
                "UPSTREAM_CAPABILITIES_SHA256",
            ),
            "metering_key_fingerprint": hashlib.sha256(
                bytes.fromhex(public_key)
            ).hexdigest()[:16],
            "maximum_output_token_cap": config.reserve_output_tokens,
            "runtime_metering_proof": True,
        }
    return capabilities


def _signature_nonce(document: Any) -> str | None:
    if not isinstance(document, dict):
        return None
    signature = document.get("signature")
    if not isinstance(signature, dict):
        return None
    nonce = str(signature.get("nonce") or "")
    return nonce or None


def _canonical_request_id(value: Any) -> str:
    if not isinstance(value, str) or not _is_canonical_request_id(value):
        raise P2PError(
            "request_id must be 1-128 ASCII characters using letters, digits, '.', '_', ':', or '-'"
        )
    return value


def _is_canonical_request_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value.encode("ascii", errors="ignore")) <= MAX_REQUEST_ID_BYTES
        and CANONICAL_REQUEST_ID_PATTERN.fullmatch(value) is not None
    )


def _canonical_signature_nonce(document: Any, label: str) -> str:
    nonce = _signature_nonce(document)
    if nonce is None or CANONICAL_SIGNATURE_NONCE_PATTERN.fullmatch(nonce) is None:
        raise P2PError(f"{label} signature nonce must be exactly 32 lowercase hexadecimal characters")
    return nonce


def remember_peer(config: ProviderConfig, peer: dict[str, Any]) -> None:
    if _json_size(peer) > MAX_PEER_DESCRIPTOR_BYTES:
        raise P2PError("peer descriptor is too large")
    peer_id = str(peer.get("peer_id") or "")
    address = str(peer.get("address") or "")
    if not peer_id or not address:
        return
    if peer_id == config.peer_id:
        return
    if len(address) > 512:
        raise P2PError("peer address is too long")
    public_key = str(peer.get("public_key") or "")
    if public_key:
        try:
            expected_peer_id = peer_id_from_public_key(public_key)
        except IdentityError as exc:
            raise P2PError(f"invalid peer public_key: {exc}") from exc
        if peer_id != expected_peer_id:
            raise P2PError("peer_id does not match peer public_key")
    normalized = dict(peer)
    normalized["last_seen"] = int(time.time())
    with config._peer_book_lock:
        if peer_id not in config.peer_book and len(config.peer_book) >= config.max_peer_book_size:
            oldest_peer_id = min(
                config.peer_book,
                key=lambda key: (int(config.peer_book[key].get("last_seen") or 0), key),
            )
            config.peer_book.pop(oldest_peer_id, None)
        config.peer_book[peer_id] = normalized


def peer_book_snapshot(config: ProviderConfig) -> list[dict[str, Any]]:
    with config._peer_book_lock:
        return [dict(peer) for peer in config.peer_book.values()]


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"))


def announce_to_peer(config: ProviderConfig, peer: PeerAddress, timeout: float) -> dict[str, Any]:
    response = send_message(
        peer,
        {
            "type": "announce",
            "request_id": uuid.uuid4().hex,
            "peer": provider_descriptor(config),
        },
        timeout=timeout,
    )
    remote_peer = response.get("peer")
    if isinstance(remote_peer, dict):
        remember_peer(config, remote_peer)
    for item in response.get("peers") or []:
        if isinstance(item, dict):
            remember_peer(config, item)
    return response


def send_message(peer: PeerAddress, message: dict[str, Any], timeout: float) -> dict[str, Any]:
    if peer.secure:
        raise P2PError("myco+tcp:// requires send_secure_message and a signed provider transport key")
    payload = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(payload) > MAX_MESSAGE_BYTES:
        raise P2PError("p2p request is too large")
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=MAX_P2P_NETWORK_TIMEOUT_SECONDS,
            label="p2p timeout",
        )
    except NetworkIOError as exc:
        raise P2PError(str(exc)) from exc
    try:
        with socket.create_connection((peer.host, peer.port), timeout=timeout) as sock:
            deadline_timer = arm_socket_deadline(sock, timeout)
            try:
                sock.settimeout(timeout)
                sock.sendall(payload)
                with sock.makefile("rb") as reader:
                    raw = reader.readline(MAX_MESSAGE_BYTES + 1)
            finally:
                deadline_timer.cancel()
    except OSError as exc:
        raise P2PError(f"failed to connect to peer {peer.value}: {exc}") from exc
    if not raw:
        raise P2PError(f"peer {peer.value} returned no response")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise P2PError(f"peer {peer.value} response is too large")
    response = json.loads(raw.decode("utf-8"))
    if isinstance(response, dict) and response.get("ok") is False:
        raise P2PError(str(response.get("error") or "p2p request failed"))
    if not isinstance(response, dict):
        raise P2PError("p2p response must be a JSON object")
    return response


def send_secure_message(
    peer: PeerAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_peer_id: str,
    expected_recipient_public_key: str | None = None,
) -> dict[str, Any]:
    if not peer.secure:
        raise P2PError("secure P2P messages require a myco+tcp:// address")
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=MAX_P2P_NETWORK_TIMEOUT_SECONDS,
            label="p2p timeout",
        )
        reply_key = generate_transport_key(sender, lifetime_seconds=600)
        request_frame = seal_json_frame(
            {"message": message, "reply_transport_key": reply_key.binding},
            sender=sender,
            recipient_binding=recipient_binding,
            expected_recipient_peer_id=expected_recipient_peer_id,
            expected_recipient_public_key=expected_recipient_public_key,
            purpose=P2P_SECURE_REQUEST_PURPOSE,
            ttl_seconds=min(300, max(30, int(math.ceil(timeout)) + 5)),
        )
    except (NetworkIOError, SecureTransportError, ValueError) as exc:
        raise P2PError(f"failed to seal secure P2P request: {exc}") from exc
    try:
        with socket.create_connection((peer.host, peer.port), timeout=timeout) as sock:
            deadline_timer = arm_socket_deadline(sock, timeout)
            try:
                sock.settimeout(timeout)
                sock.sendall(request_frame)
                with sock.makefile("rb") as reader:
                    response_frame = read_secure_frame(reader)
            finally:
                deadline_timer.cancel()
    except (OSError, SecureTransportError) as exc:
        raise P2PError(f"failed to connect securely to peer {peer.value}: {exc}") from exc
    try:
        opened = open_frame(
            response_frame,
            recipient_key=reply_key,
            expected_purpose=P2P_SECURE_RESPONSE_PURPOSE,
            expected_sender_peer_id=expected_recipient_peer_id,
            expected_sender_public_key=expected_recipient_public_key,
            replay_store=MemoryReplayStore(),
        )
        wrapper = opened.json_payload()
        if set(wrapper) != {"response"} or not isinstance(wrapper.get("response"), dict):
            raise P2PError("secure P2P response wrapper is invalid")
        response = wrapper["response"]
    except SecureTransportError as exc:
        raise P2PError(f"invalid secure P2P response: {exc}") from exc
    if response.get("ok") is False:
        raise P2PError(str(response.get("error") or "p2p request failed"))
    return response


def handle_secure_frame(config: ProviderConfig, frame: bytes) -> bytes:
    if config.identity is None or config._transport_replay_store is None:
        raise P2PError("secure provider transport is not configured")
    try:
        metadata = _verify_secure_request_metadata(config, frame)
        recipient_key = config.transport_key_for_frame(frame, metadata=metadata)
        opened = open_frame(
            frame,
            recipient_key=recipient_key,
            expected_purpose=metadata.purpose,
            replay_store=config._transport_replay_store,
        )
        wrapper = opened.json_payload()
        if set(wrapper) != {"message", "reply_transport_key"}:
            raise P2PError("secure P2P request wrapper has unknown or missing fields")
        message = wrapper.get("message")
        reply_binding = wrapper.get("reply_transport_key")
        if not isinstance(message, dict) or not isinstance(reply_binding, dict):
            raise P2PError("secure P2P request wrapper is invalid")
        if opened.purpose == P2P_ADDRESS_PROBE_PURPOSE and (
            set(message) != {"type", "request_id", "audience"}
            or message.get("type") != "ping"
        ):
            raise P2PError("secure address probe must contain only a ping")
        verify_transport_key_binding(
            reply_binding,
            expected_peer_id=opened.sender_peer_id,
            expected_identity_public_key=opened.sender_public_key,
        )
        signature = message.get("signature")
        if isinstance(signature, dict) and signature.get("public_key") != opened.sender_public_key:
            raise P2PError("secure envelope sender does not match the application request signer")
        try:
            response = handle_message(config, message)
        except Exception as exc:
            response = {"type": "error", "ok": False, "error": str(exc)}
        return seal_json_frame(
            {"response": response},
            sender=config.identity,
            recipient_binding=reply_binding,
            expected_recipient_peer_id=opened.sender_peer_id,
            expected_recipient_public_key=opened.sender_public_key,
            purpose=P2P_SECURE_RESPONSE_PURPOSE,
            ttl_seconds=60,
        )
    except SecureTransportError as exc:
        raise P2PError(f"invalid secure P2P request: {exc}") from exc


def fetch_peer_transport_binding(
    peer: PeerAddress,
    expected_peer_id: str,
    timeout: float,
) -> tuple[dict[str, Any], str]:
    """Bootstrap a signed public transport key; inference still uses only sealed frames."""
    bootstrap_peer = PeerAddress(peer.host, peer.port, scheme="tcp")
    request_id = f"transport-key-{uuid.uuid4().hex}"
    response = send_message(
        bootstrap_peer,
        {"type": "ping", "request_id": request_id},
        timeout=timeout,
    )
    if str(response.get("request_id") or "") != request_id:
        raise P2PError("transport key bootstrap returned a different request_id")
    try:
        unsigned = verify_document(response, purpose=ADDRESS_PROOF_PURPOSE)
    except IdentityError as exc:
        raise P2PError(f"invalid transport key bootstrap signature: {exc}") from exc
    signature = response.get("signature")
    public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if not public_key or peer_id_from_public_key(public_key) != expected_peer_id:
        raise P2PError("transport key bootstrap signer does not match expected peer_id")
    descriptor = unsigned.get("peer")
    binding = descriptor.get("transport_key") if isinstance(descriptor, dict) else None
    if not isinstance(binding, dict):
        raise P2PError("provider did not publish a signed transport key")
    try:
        verify_transport_key_binding(
            binding,
            expected_peer_id=expected_peer_id,
            expected_identity_public_key=public_key,
        )
    except SecureTransportError as exc:
        raise P2PError(f"invalid provider transport key: {exc}") from exc
    return binding, public_key


def parse_peer_address(value: str) -> PeerAddress:
    raw = value.strip()
    scheme = "tcp"
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme not in {"tcp", "myco+tcp"}:
            raise ValueError("peer address scheme must be tcp:// or myco+tcp://")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("peer address must not include userinfo")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("direct peer address must not include a path, query, or fragment")
        host = str(parsed.hostname or "")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("peer port must be an integer") from exc
        scheme = parsed.scheme
    else:
        if ":" not in raw:
            raise ValueError("peer address must look like host:port, tcp://host:port, or myco+tcp://host:port")
        host, port_text = raw.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError("peer port must be an integer") from exc
    if not host:
        raise ValueError("peer host is required")
    if port is None:
        raise ValueError("peer port is required")
    if port <= 0 or port > 65535:
        raise ValueError("peer port must be between 1 and 65535")
    return PeerAddress(host=host, port=port, scheme=scheme)
