from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import queue
import select
import secrets
import socket
import ssl
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping

from .billing import BillingError, normalize_payment_address
from .chain import ZERO_ADDRESS, ChainError, channel_to_hash, normalize_address, parse_private_key, private_key_to_address
from .chain_v7 import (
    account_balance as v7_account_balance,
    encode_signed_batch_tuples as encode_v7_signed_batch_tuples,
    finalize_relay_receipt,
    key_grant as v7_key_grant,
    verify_authorization as verify_v7_authorization,
)
from .chain_v6 import encode_settle_signed_batch_tuples as encode_v6_signed_batch_tuples
from .chain_v5 import build_relay_attestation
from .browser_cors import parse_allowed_origins
from .channel_policy import require_enabled_channel_binding
from .consumer_admission import (
    ConsumerAdmissionError,
    RelayV3AdmissionConfig,
    verify_relay_v3_admission,
)
from .identity import IdentityError, NodeIdentity, create_identity, peer_id_from_public_key, sign_document, verify_document
from .netio import NetworkIOError, bounded_timeout, read_bounded, text_preview
from .operator_budget import OperatorBudget, OperatorBudgetError
from .p2p import (
    INFERENCE_REQUEST_PURPOSE,
    MAX_MESSAGE_BYTES,
    P2P_ADDRESS_PROBE_PURPOSE,
    P2P_SECURE_REQUEST_PURPOSE,
    P2P_SECURE_RESPONSE_PURPOSE,
    P2P_SESSION_STATUS_REQUEST_PURPOSE,
    P2PError,
    ProviderConfig,
    handle_message,
    handle_secure_frame,
    provider_runtime_capabilities,
    provider_min_reservation_units,
)
from .reservation import (
    RESPONSES_LOCAL_OPTION_FIELDS,
    RESPONSES_REQUEST_OPTION_FIELDS,
    ReservationError,
    inference_request_hash,
    normalize_inference_request_options,
)
from .replay import DEFAULT_REPLAY_DB, ReplayError, ReplayStore
from .session_protocol import (
    SessionProtocolError,
    normalize_session_request,
    verify_session_authorization,
    verify_session_request,
)
from .secure_transport import (
    MAX_SECURE_FRAME_BYTES,
    MemoryReplayStore,
    SecureTransportError,
    generate_transport_key,
    open_frame,
    seal_json_frame,
    verify_frame_metadata,
    verify_transport_key_binding,
)
from .session_relayer import (
    DEFAULT_RELAY_SETTLEMENT_DB,
    DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE,
    MAX_RELAY_SETTLEMENT_BATCH_SIZE,
    RelaySettlementError,
    RelaySettlementOutbox,
    RelaySettlementSubmitter,
    prepare_relay_settlement,
)
from .v7_relayer import prepare_v7_relay_settlement
from .server_limits import (
    BoundedThreadingMixIn,
    arm_socket_deadline,
    bounded_connection_count,
    close_socket,
)


RELAY_PROTOCOL_VERSION = "mycomesh-relay/0.2"
DEFAULT_RELAY_CONTROL_PORT = 9900
DEFAULT_RELAY_PROVIDER_PORT = 9901
DEFAULT_RELAY_URL = f"http://127.0.0.1:{DEFAULT_RELAY_CONTROL_PORT}"
RELAY_PROVIDER_REGISTRATION_PURPOSE = "mycomesh.relay.provider.v1"
DEFAULT_RELAY_RECONNECT_GRACE_SECONDS = 5
DEFAULT_RELAY_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RELAY_RATE_LIMIT_MAX_REQUESTS = 120
MAX_RELAY_RATE_LIMIT_IDENTITIES = 4096
DEFAULT_RELAY_CONSUMER_MAX_IN_FLIGHT = 32
DEFAULT_RELAY_V3_ADMISSION_MAX_IN_FLIGHT = 16
DEFAULT_RELAY_PROVIDER_QUEUE_SIZE = 64
DEFAULT_RELAY_SOCKET_TIMEOUT_SECONDS = 10
MAX_RELAY_ENCODED_FRAME_BYTES = ((MAX_SECURE_FRAME_BYTES + 2) // 3) * 4
MAX_RELAY_MESSAGE_BYTES = MAX_RELAY_ENCODED_FRAME_BYTES + 64 * 1024
MAX_RELAY_RESPONSE_BYTES = MAX_RELAY_MESSAGE_BYTES
MAX_RELAY_INFERENCE_TIMEOUT_SECONDS = 300.0
MAX_RELAY_SOCKET_TIMEOUT_SECONDS = 60.0
DEFAULT_RELAY_MAX_CONNECTIONS = 128
DEFAULT_RELAY_REQUEST_READ_DEADLINE_SECONDS = 15.0
MAX_RELAY_REQUEST_READ_DEADLINE_SECONDS = 60.0


class RelayError(RuntimeError):
    pass


class V7ProviderRejected(RelayError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


class RelayTransientError(RelayError):
    """A failed post-inference operation that is safe to retry."""


def _normalize_relay_payment_address(
    value: str | None,
    *,
    required: bool = False,
) -> str | None:
    try:
        normalized = normalize_payment_address(value)
    except BillingError as exc:
        raise RelayError(f"Relay payment address is invalid: {exc}") from exc
    if normalized is None:
        if required:
            raise RelayError("Relay payment address is required outside the local network profile")
        return None
    if int(normalized[2:], 16) == 0:
        raise RelayError("Relay payment address must be a non-zero EVM address")
    return normalized


def relay_error_http_response(error: Exception) -> tuple[int, dict[str, str]]:
    """Map transient Provider/Relay failures to retry-aware HTTP responses."""
    message = str(error).lower()
    if isinstance(error, RelayTransientError) or "timed out" in message or "deadline exceeded" in message:
        # A Provider may still be unwinding its bounded backend call when the
        # Relay deadline fires; give callers time to inspect reservation state
        # before they submit a new paid request.
        return 504, {"Retry-After": "5"}
    if any(
        marker in message
        for marker in (
            "is not connected",
            "queue is full",
            "disconnected",
            "connection reset",
            "connection refused",
        )
    ):
        return 503, {"Retry-After": "5"}
    return 400, {}


class _NoRelayRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _build_relay_http_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler(), _NoRelayRedirectHandler())


_RELAY_HTTP_OPENER = _build_relay_http_opener()


@dataclass(frozen=True)
class RelayAddress:
    host: str
    port: int
    peer_id: str
    scheme: str = "relay"

    @property
    def value(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/{self.peer_id}"

    @property
    def secure(self) -> bool:
        return self.scheme in {"myco+relay", "myco+relays"}

    @property
    def tls(self) -> bool:
        return self.scheme in {"relays", "myco+relays"}


@dataclass
class RelayJob:
    job_id: str
    message: dict[str, Any]
    response_queue: queue.Queue


@dataclass
class RelayProviderSession:
    peer_id: str
    peer: dict[str, Any]
    jobs: queue.Queue[RelayJob] = field(default_factory=lambda: queue.Queue(maxsize=DEFAULT_RELAY_PROVIDER_QUEUE_SIZE))
    connected_at: int = field(default_factory=lambda: int(time.time()))
    last_seen: int = field(default_factory=lambda: int(time.time()))
    connection: socket.socket | None = field(default=None, repr=False)


@dataclass
class RelayState:
    providers: dict[str, RelayProviderSession] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.RLock)
    require_signed_providers: bool = True
    network_profile: str = "local"
    payment_address: str | None = None
    attestation_address: str | None = None
    attestation_private_keys: dict[str, str] = field(default_factory=dict, repr=False)
    trust_proxy_headers: bool = False
    rate_limits: dict[str, list[float]] = field(default_factory=dict)
    reconnect_grace_seconds: float = DEFAULT_RELAY_RECONNECT_GRACE_SECONDS
    rate_limit_window_seconds: int = DEFAULT_RELAY_RATE_LIMIT_WINDOW_SECONDS
    rate_limit_max_requests: int = DEFAULT_RELAY_RATE_LIMIT_MAX_REQUESTS
    authorized_consumers: set[str] = field(default_factory=set)
    allow_any_signed_consumer: bool = False
    consumer_rate_limits: dict[str, list[float]] = field(default_factory=dict)
    consumer_in_flight: dict[str, int] = field(default_factory=dict)
    consumer_max_in_flight: int = field(
        default_factory=lambda: int(
            os.getenv(
                "MYCOMESH_RELAY_CONSUMER_MAX_IN_FLIGHT",
                str(DEFAULT_RELAY_CONSUMER_MAX_IN_FLIGHT),
            )
        )
    )
    provider_queue_size: int = DEFAULT_RELAY_PROVIDER_QUEUE_SIZE
    socket_timeout_seconds: float = DEFAULT_RELAY_SOCKET_TIMEOUT_SECONDS
    control_max_connections: int = field(
        default_factory=lambda: int(
            os.getenv(
                "MYCOMESH_RELAY_CONTROL_MAX_CONNECTIONS",
                str(DEFAULT_RELAY_MAX_CONNECTIONS),
            )
        )
    )
    provider_max_connections: int = DEFAULT_RELAY_MAX_CONNECTIONS
    usage_limit_units: int = field(
        default_factory=lambda: int(os.getenv("MYCOMESH_RELAY_USAGE_LIMIT_UNITS") or 0)
    )
    usage_period_seconds: int = field(
        default_factory=lambda: int(os.getenv("MYCOMESH_RELAY_USAGE_PERIOD_SECONDS") or 2_592_000)
    )
    usage_state_path: str = "/data/operator-usage.json"
    settlement_rpc_url: str | None = None
    settlement_private_key: str | None = field(default=None, repr=False)
    settlement_chain_id: int | None = None
    settlement_contract: str | None = None
    settlement_version: int = 6
    settlement_db_path: str = DEFAULT_RELAY_SETTLEMENT_DB
    settlement_batch_size: int = DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE
    request_read_deadline_seconds: float = DEFAULT_RELAY_REQUEST_READ_DEADLINE_SECONDS
    replay_store_path: str | None = None
    replay_ttl_seconds: int = 600
    v3_admission_config: RelayV3AdmissionConfig | None = None
    v3_admission_max_in_flight: int = DEFAULT_RELAY_V3_ADMISSION_MAX_IN_FLIGHT
    cors_allowed_origins: tuple[str, ...] = field(
        default_factory=lambda: parse_allowed_origins(
            os.getenv("MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS"),
            setting="MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS",
        )
    )
    _replay_store: ReplayStore | None = field(default=None, init=False, repr=False)
    _v3_admission_slots: threading.BoundedSemaphore = field(init=False, repr=False)
    _operator_budget: OperatorBudget | None = field(default=None, init=False, repr=False)
    _settlement_outbox: RelaySettlementOutbox | None = field(default=None, init=False, repr=False)
    _settlement_submitter: RelaySettlementSubmitter | None = field(default=None, init=False, repr=False)
    _scheduler_identity: NodeIdentity = field(default_factory=create_identity, init=False, repr=False)

    def __post_init__(self) -> None:
        self.network_profile = str(self.network_profile or "").strip().lower()
        if self.network_profile not in {"local", "testnet", "open"}:
            raise RelayError("Relay network_profile must be local, testnet, or open")
        self.settlement_version = int(self.settlement_version)
        if self.settlement_version not in {5, 6, 7}:
            raise RelayError("Relay settlement_version must be 5, 6, or 7")
        self.payment_address = _normalize_relay_payment_address(
            self.payment_address,
            required=self.network_profile != "local",
        )
        normalized_keys: dict[str, str] = {}
        for address, private_key in self.attestation_private_keys.items():
            try:
                derived = private_key_to_address(parse_private_key(private_key))
                supplied = normalize_address(address)
            except ChainError as exc:
                raise RelayError(f"Relay attestation identity is invalid: {exc}") from exc
            if supplied != derived:
                raise RelayError("Relay attestation key does not match its address")
            normalized_keys[derived] = private_key
        self.attestation_private_keys = normalized_keys
        if self.attestation_address:
            try:
                self.attestation_address = normalize_address(self.attestation_address)
            except ChainError as exc:
                raise RelayError(f"Relay attestation address is invalid: {exc}") from exc
            if self.attestation_address == ZERO_ADDRESS:
                raise RelayError("Relay attestation address must be non-zero")
            if self.attestation_address not in normalized_keys:
                raise RelayError("Relay current attestation address has no private key")
        elif normalized_keys:
            if len(normalized_keys) != 1:
                raise RelayError("Relay current attestation address is required when multiple keys are loaded")
            self.attestation_address = next(iter(normalized_keys))
        if self.settlement_version == 7:
            if not self.payment_address:
                raise RelayError("Settlement V7 Relay requires a payout address")
            if not self.attestation_address:
                raise RelayError("Settlement V7 Relay requires an attestation address")
        self.cors_allowed_origins = parse_allowed_origins(
            self.cors_allowed_origins,
            setting="RelayState.cors_allowed_origins",
        )
        try:
            self.socket_timeout_seconds = bounded_timeout(
                self.socket_timeout_seconds,
                maximum=MAX_RELAY_SOCKET_TIMEOUT_SECONDS,
                label="relay socket timeout",
            )
            self.request_read_deadline_seconds = bounded_timeout(
                self.request_read_deadline_seconds,
                maximum=MAX_RELAY_REQUEST_READ_DEADLINE_SECONDS,
                label="relay request read deadline",
            )
        except NetworkIOError as exc:
            raise RelayError(str(exc)) from exc
        try:
            self.control_max_connections = bounded_connection_count(
                self.control_max_connections,
                label="relay control max connections",
            )
            self.provider_max_connections = bounded_connection_count(
                self.provider_max_connections,
                label="relay provider max connections",
            )
        except ValueError as exc:
            raise RelayError(str(exc)) from exc
        if (
            type(self.consumer_max_in_flight) is not int
            or self.consumer_max_in_flight < 1
            or self.consumer_max_in_flight > self.control_max_connections
        ):
            raise RelayError(
                "Relay consumer concurrency must be positive and no greater than the control connection limit"
            )
        if self.replay_store_path:
            self._replay_store = ReplayStore(self.replay_store_path)
        try:
            self._operator_budget = OperatorBudget(
                limit_units=int(self.usage_limit_units),
                period_seconds=int(self.usage_period_seconds),
                state_path=self.usage_state_path,
            )
        except (OperatorBudgetError, TypeError, ValueError) as exc:
            raise RelayError(f"invalid Relay usage budget: {exc}") from exc
        settlement_values = (
            self.settlement_rpc_url,
            self.settlement_private_key,
            self.settlement_chain_id,
            self.settlement_contract,
        )
        if any(value not in {None, ""} for value in settlement_values):
            if not self.settlement_rpc_url or not self.settlement_private_key:
                raise RelayError(
                    "Relay settlement requires both settlement_rpc_url and settlement_private_key"
                )
            if self.payment_address is None:
                raise RelayError(
                    "Relay settlement requires a non-zero payment_address"
                )
            if self.settlement_chain_id is None or not self.settlement_contract:
                raise RelayError(
                    "Relay settlement requires settlement_chain_id and settlement_contract"
                )
            try:
                if type(self.settlement_batch_size) is not int or not 1 <= self.settlement_batch_size <= MAX_RELAY_SETTLEMENT_BATCH_SIZE:
                    raise ValueError(
                        f"settlement_batch_size must be between 1 and {MAX_RELAY_SETTLEMENT_BATCH_SIZE}"
                    )
                self.settlement_chain_id = int(self.settlement_chain_id)
                if self.settlement_chain_id <= 0:
                    raise ValueError("settlement_chain_id must be positive")
                self.settlement_contract = normalize_address(self.settlement_contract)
                self._settlement_outbox = RelaySettlementOutbox(self.settlement_db_path)
                submitter_options: dict[str, Any] = {}
                if self.settlement_version == 7:
                    if not self.attestation_address:
                        raise ValueError("Settlement V7 Relay requires an attestation identity")
                    submitter_options["batch_encoder"] = encode_v7_signed_batch_tuples
                elif self.settlement_version == 6:
                    submitter_options["batch_encoder"] = encode_v6_signed_batch_tuples
                self._settlement_submitter = RelaySettlementSubmitter(
                    outbox=self._settlement_outbox,
                    rpc_url=self.settlement_rpc_url,
                    private_key=self.settlement_private_key,
                    batch_size=self.settlement_batch_size,
                    **submitter_options,
                )
            except (ChainError, RelaySettlementError, OSError, TypeError, ValueError) as exc:
                raise RelayError(f"invalid Relay settlement configuration: {exc}") from exc
            if self.payment_address and self._settlement_submitter.address == self.payment_address:
                raise RelayError("Relay transaction relayer identity must differ from the payout address")
            if self.attestation_address and self._settlement_submitter.address == self.attestation_address:
                raise RelayError("Relay transaction relayer identity must differ from the attestation address")
        if (
            type(self.v3_admission_max_in_flight) is not int
            or self.v3_admission_max_in_flight < 1
            or self.v3_admission_max_in_flight > self.control_max_connections
        ):
            raise RelayError(
                "Relay V3 admission concurrency must be positive and no greater than the control connection limit"
            )
        self._v3_admission_slots = threading.BoundedSemaphore(
            self.v3_admission_max_in_flight
        )


class RelayProviderTCPServer(
    BoundedThreadingMixIn,
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: RelayState,
        relay_host: str,
        control_port: int,
        provider_audience_port: int | None = None,
    ) -> None:
        super().__init__(server_address, RelayProviderHandler)
        self.state = state
        self.relay_host = relay_host
        self.control_port = control_port
        self.provider_audience_port = (
            int(provider_audience_port)
            if provider_audience_port is not None
            else int(self.server_address[1])
        )
        self.configure_connection_limit(state.provider_max_connections)


class RelayProviderHandler(socketserver.StreamRequestHandler):
    server: RelayProviderTCPServer

    def handle(self) -> None:
        self.connection.settimeout(float(self.server.state.socket_timeout_seconds))
        session: RelayProviderSession | None = None
        registration_deadline = arm_socket_deadline(
            self.connection,
            float(self.server.state.request_read_deadline_seconds),
        )
        try:
            audience = f"{self.server.relay_host}:{self.server.provider_audience_port}"
            challenge = secrets.token_hex(32)
            challenge_payload: dict[str, Any] = {
                "type": "provider_challenge",
                "protocol": RELAY_PROTOCOL_VERSION,
                "challenge": challenge,
                "audience": audience,
            }
            if self.server.state.payment_address:
                challenge_payload["relay_payment_address"] = self.server.state.payment_address
            if self.server.state.attestation_address:
                challenge_payload["relay_attestation_address"] = self.server.state.attestation_address
            _write_json_line(self.wfile, challenge_payload)
            register = _read_json_line(self.rfile)
            if register.get("type") != "provider_register":
                _write_json_line(self.wfile, {"ok": False, "error": "provider_register is required"})
                return
            peer = register.get("peer")
            if not isinstance(peer, dict):
                _write_json_line(self.wfile, {"ok": False, "error": "peer must be a JSON object"})
                return
            try:
                peer = verify_relay_provider_peer(
                    peer,
                    require_signed=self.server.state.require_signed_providers,
                    audience=audience,
                    expected_challenge=challenge,
                    expected_relay_payment_address=self.server.state.payment_address,
                    expected_relay_attestation_address=self.server.state.attestation_address,
                )
            except RelayError as exc:
                _write_json_line(self.wfile, {"ok": False, "error": str(exc)})
                return
            peer_id = str(peer.get("peer_id") or "")
            if not peer_id:
                _write_json_line(self.wfile, {"ok": False, "error": "peer.peer_id is required"})
                return
            session = RelayProviderSession(
                peer_id=peer_id,
                peer=dict(peer),
                jobs=queue.Queue(maxsize=self.server.state.provider_queue_size),
                connection=self.connection,
            )
            with self.server.state.lock:
                old = self.server.state.providers.get(peer_id)
                if old is not None:
                    if time.time() - old.connected_at < self.server.state.reconnect_grace_seconds:
                        _write_json_line(self.wfile, {"ok": False, "error": "peer reconnect rate limit exceeded"})
                        return
                    try:
                        old.jobs.put_nowait(
                            RelayJob(
                                job_id="disconnect",
                                message={"type": "disconnect"},
                                response_queue=queue.Queue(),
                            )
                        )
                    except queue.Full:
                        pass
                self.server.state.providers[peer_id] = session
            registered_payload: dict[str, Any] = {
                "ok": True,
                "type": "provider_registered",
                "protocol": RELAY_PROTOCOL_VERSION,
                "peer_id": peer_id,
                "challenge": challenge,
                "relay": f"http://{self.server.relay_host}:{self.server.control_port}",
                "relay_address": f"relay://{self.server.relay_host}:{self.server.control_port}/{peer_id}",
            }
            if self.server.state.payment_address:
                registered_payload["relay_payment_address"] = self.server.state.payment_address
            if self.server.state.attestation_address:
                registered_payload["relay_attestation_address"] = self.server.state.attestation_address
            _write_json_line(self.wfile, registered_payload)
            registration_deadline.cancel()
            self.connection.settimeout(None)
            while True:
                try:
                    # A Provider can disappear without sending another frame
                    # (for example, a killed container behind NAT). Probe the
                    # idle socket so its session does not remain schedulable.
                    job = session.jobs.get(timeout=1.0)
                except queue.Empty:
                    if _provider_socket_closed(self.connection):
                        raise RelayError(f"provider {session.peer_id!r} disconnected")
                    continue
                if job.message.get("type") == "disconnect":
                    return
                session.last_seen = int(time.time())
                _write_json_line(
                    self.wfile,
                    {
                        "type": "relay_job",
                        "job_id": job.job_id,
                        "message": job.message,
                    },
                )
                response = _read_json_line(self.rfile)
                session.last_seen = int(time.time())
                job.response_queue.put(response)
        except Exception as exc:
            if session is not None:
                _fail_pending_jobs(session, exc)
        finally:
            registration_deadline.cancel()
            if session is not None:
                with self.server.state.lock:
                    if self.server.state.providers.get(session.peer_id) is session:
                        self.server.state.providers.pop(session.peer_id, None)


def _provider_socket_closed(connection: socket.socket) -> bool:
    try:
        value = connection.recv(1, socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0))
    except BlockingIOError:
        return False
    except (ConnectionResetError, BrokenPipeError, OSError):
        return True
    return value == b""


class RelayControlHTTPServer(BoundedThreadingMixIn, ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: RelayState,
    ) -> None:
        super().__init__(server_address, RelayControlHandler)
        self.state = state
        self.configure_connection_limit(state.control_max_connections)


class RelayControlHandler(BaseHTTPRequestHandler):
    server: RelayControlHTTPServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(float(self.server.state.socket_timeout_seconds))
        self._read_deadline = arm_socket_deadline(
            self.connection,
            float(self.server.state.request_read_deadline_seconds),
        )

    def finish(self) -> None:
        self._cancel_read_deadline()
        super().finish()

    def do_GET(self) -> None:
        self._cancel_read_deadline()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            providers = list_relay_providers(self.server.state)
            self._write(
                200,
                {
                    "ok": True,
                    "protocol": RELAY_PROTOCOL_VERSION,
                    "providers": len(providers),
                    "relay_payment_address": self.server.state.payment_address,
                    "relay_attestation_address": self.server.state.attestation_address,
                    "consumer_max_in_flight": self.server.state.consumer_max_in_flight,
                    "usage_budget": (
                        self.server.state._operator_budget.snapshot()
                        if self.server.state._operator_budget is not None
                        else None
                    ),
                    "settlement_submitter": (
                        self.server.state._settlement_submitter.snapshot()
                        if self.server.state._settlement_submitter is not None
                        else {"enabled": False},
                    ),
                    "v7": v7_relay_capabilities(self.server.state),
                },
            )
            return
        if parsed.path == "/providers":
            self._write(
                200,
                {
                    "ok": True,
                    "protocol": RELAY_PROTOCOL_VERSION,
                    "providers": list_relay_providers(self.server.state),
                },
            )
            return
        self._write(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        cors_headers: dict[str, str] = {}
        if parsed.path in {"/v1/responses", "/v1/responses/compact", "/v1/chat/completions"}:
            try:
                body = self._read_json()
                payment = _v7_payment_header(self.headers)
                if payment is None:
                    required = v7_payment_required(self.server.state, parsed.path, body)
                    self._write(
                        402,
                        required,
                        headers={"PAYMENT-REQUIRED": _encode_payment_header(required)},
                    )
                    return
                response, settlement = relay_v7_openai(
                    self.server.state,
                    parsed.path,
                    body,
                    payment,
                )
                self._write(
                    200,
                    response,
                    headers={"PAYMENT-RESPONSE": _encode_payment_header(settlement)},
                )
            except Exception as exc:
                status, retry_headers = relay_error_http_response(exc)
                self._write(
                    status,
                    {
                        "error": {
                            "type": "mycomesh_relay_error",
                            "message": str(exc),
                        }
                    },
                    headers=retry_headers,
                )
            return
        if parsed.path.startswith("/infer/"):
            cors_headers = self._browser_cors_headers()
            origin_headers = self.headers.get_all("Origin") or []
            if origin_headers and "Access-Control-Allow-Origin" not in cors_headers:
                self._cancel_read_deadline()
                self._write(
                    403,
                    {"ok": False, "error": "CORS origin is not allowed"},
                    headers=cors_headers,
                )
                return
            if origin_headers:
                if (self.headers.get_all("Cookie") or []) or (
                    self.headers.get_all("Authorization") or []
                ):
                    self._cancel_read_deadline()
                    self._write(
                        400,
                        {"ok": False, "error": "credentialed CORS requests are not accepted"},
                        headers=cors_headers,
                    )
                    return
                content_types = self.headers.get_all("Content-Type") or []
                if (
                    len(content_types) != 1
                    or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
                ):
                    self._cancel_read_deadline()
                    self._write(
                        415,
                        {"ok": False, "error": "CORS inference requests require application/json"},
                        headers=cors_headers,
                    )
                    return
        try:
            if parsed.path.startswith("/infer/"):
                self._rate_limit()
                request_started_at = time.monotonic()
                peer_id = urllib.parse.unquote(parsed.path.removeprefix("/infer/"))
                body = self._read_json()
                timeout = _coerce_timeout(body.get("timeout"), 180.0)
                deadline = request_started_at + timeout
                secure_frame = body.get("secure_frame")
                session_status_marker = body.get("session_status")
                if session_status_marker is not None and type(session_status_marker) is not bool:
                    raise RelayError("session_status must be a boolean")
                if session_status_marker is True and secure_frame is None:
                    raise RelayError("session_status requires a signed secure_frame")
                verified_admission: dict[str, Any] = {}
                if secure_frame is not None:
                    if not isinstance(secure_frame, str):
                        raise RelayError("secure_frame must be base64url text")
                    consumer_public_key = verify_relay_consumer_frame(
                        self.server.state,
                        secure_frame,
                        peer_id=peer_id,
                        admission=body.get("admission"),
                        address_probe=body.get("address_probe") is True,
                        session_status=session_status_marker is True,
                        verified_admission=verified_admission,
                    )
                    relay_message = {"secure_frame": secure_frame}
                else:
                    with self.server.state.lock:
                        session = self.server.state.providers.get(peer_id)
                    if session is not None and _relay_session_requires_secure(session):
                        raise RelayError("provider requires sealed relay frames; plaintext inference is disabled")
                    message = body.get("message")
                    if not isinstance(message, dict):
                        raise RelayError("message must be a JSON object")
                    consumer_public_key = verify_relay_consumer_request(
                        self.server.state, message, peer_id=peer_id
                    )
                    relay_message = message
                _reserve_consumer_slot(self.server.state, consumer_public_key)
                budget = self.server.state._operator_budget
                budget_reservation = 0
                try:
                    v5_request = verified_admission.get("v5_attestation_request")
                    session_status = verified_admission.get("session_status") is True
                    if budget is not None:
                        if session_status:
                            budget_reservation = 0
                        elif isinstance(v5_request, dict):
                            budget_reservation = int(v5_request.get("max_fee_units") or 0)
                        else:
                            budget_reservation = int(verified_admission.get("v3_max_fee_units") or 0)
                        if not budget.reserve(budget_reservation):
                            raise RelayError("Relay usage budget exhausted for the current period")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RelayError("relay inference deadline exceeded")
                    response = relay_infer(self.server.state, peer_id, relay_message, timeout=remaining)
                    if isinstance(v5_request, dict):
                        signer = normalize_address(str(v5_request["relay_attestation_address"]))
                        private_key = self.server.state.attestation_private_keys.get(signer)
                        if not private_key:
                            raise RelayError("Relay V5 session targets an unavailable attestation key")
                        response = dict(response)
                        build_attestation = build_relay_attestation
                        if int(v5_request.get("protocol_version") or 5) == 6:
                            from .chain_v6 import build_relay_attestation as build_attestation
                        response["relay_attestation"] = build_attestation(
                            private_key=private_key,
                            chain_id=int(v5_request["chain_id"]),
                            settlement_contract=str(v5_request["settlement_contract"]),
                            session_id=str(v5_request["session_id"]),
                            request_hash=str(v5_request["request_hash"]),
                            provider=str(v5_request["provider"]),
                            relay=str(v5_request["relay"]),
                            **({"relay_epoch": int(v5_request.get("relay_epoch") or 0)} if int(v5_request.get("protocol_version") or 5) == 6 else {}),
                            sequence=int(v5_request["sequence"]),
                            deadline=int(v5_request["deadline"]),
                        )
                    if budget is not None:
                        actual_units = 0 if session_status else _relay_response_fee_units(response)
                        if actual_units is None:
                            actual_units = budget_reservation
                        if not budget.settle(budget_reservation, actual_units):
                            raise RelayError("Relay usage budget exhausted for the current period")
                        budget_reservation = 0
                    self._write(200, response, headers=cors_headers)
                finally:
                    if budget is not None and budget_reservation:
                        budget.release(budget_reservation)
                    _release_consumer_slot(self.server.state, consumer_public_key)
                return
            if parsed.path in {"/v5/settlements", "/v6/settlements"}:
                submission = self._read_json()
                submitter = self.server.state._settlement_submitter
                if submitter is None:
                    raise RelayError("Relay settlement submitter is not configured")
                try:
                    prepare_kwargs = {
                        "expected_chain_id": self.server.state.settlement_chain_id,
                        "expected_contract": self.server.state.settlement_contract,
                        "expected_relay": self.server.state.payment_address,
                        "attestation_private_keys": self.server.state.attestation_private_keys,
                    }
                    try:
                        prepared = prepare_relay_settlement(submission, **prepare_kwargs)
                    except RelaySettlementError as exc:
                        if "attestation deadline has elapsed" not in str(exc):
                            raise
                        prepared = prepare_relay_settlement(submission, now=0, **prepare_kwargs)
                        status = submitter.outbox.status(prepared.key)
                        if status is None:
                            raise exc
                        accepted = False
                    else:
                        status, accepted = submitter.enqueue(prepared)
                except RelaySettlementError as exc:
                    raise RelayError(str(exc)) from exc
                self._write(
                    202,
                    {
                        "ok": True,
                        "schema": "mycomesh.relay.settlement.accepted.v1",
                        "settlement_key": prepared.key,
                        "status": status,
                        "accepted": bool(accepted),
                    },
                )
                return
        except Exception as exc:
            status, retry_headers = relay_error_http_response(exc)
            response_headers = {**cors_headers, **retry_headers}
            self._write(status, {"ok": False, "error": str(exc)}, headers=response_headers)
            return
        self._write(404, {"ok": False, "error": "not found"}, headers=cors_headers)

    def do_OPTIONS(self) -> None:
        self._cancel_read_deadline()
        parsed = urllib.parse.urlparse(self.path)
        cors_headers = self._browser_cors_headers(preflight=True)
        peer_id = parsed.path.removeprefix("/infer/")
        if not parsed.path.startswith("/infer/") or not peer_id:
            self._write(404, {"ok": False, "error": "not found"}, headers=cors_headers)
            return
        origin_headers = self.headers.get_all("Origin") or []
        if len(origin_headers) != 1 or "Access-Control-Allow-Origin" not in cors_headers:
            self._write(
                403,
                {"ok": False, "error": "CORS origin is not allowed"},
                headers=cors_headers,
            )
            return
        requested_methods = self.headers.get_all("Access-Control-Request-Method") or []
        if len(requested_methods) != 1 or requested_methods[0].strip().upper() != "POST":
            self._write(
                405,
                {"ok": False, "error": "CORS method is not allowed"},
                headers=cors_headers,
            )
            return
        requested_headers = self.headers.get_all("Access-Control-Request-Headers") or []
        header_names = [
            name.strip().lower()
            for value in requested_headers
            for name in value.split(",")
        ]
        if any(not name or name != "content-type" for name in header_names):
            self._write(
                400,
                {"ok": False, "error": "CORS request headers are not allowed"},
                headers=cors_headers,
            )
            return
        self._write_empty(
            204,
            headers={
                **cors_headers,
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Max-Age": "600",
            },
        )

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _rate_limit(self) -> None:
        socket_client = self.client_address[0] if self.client_address else ""
        real_ip_headers = self.headers.get_all("X-Real-IP") or []
        client = _resolve_relay_rate_limit_client_ip(
            self.server.state,
            socket_client,
            real_ip_headers,
        )
        _bounded_rate_limit(
            self.server.state,
            self.server.state.rate_limits,
            client,
            error="rate limit exceeded",
        )

    def _read_json(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("content-length") or "0")
            if content_length > MAX_RELAY_MESSAGE_BYTES:
                raise RelayError("request body too large")
            if content_length <= 0:
                return {}
            payload = self.rfile.read(content_length).decode("utf-8")
            value = json.loads(payload)
            if not isinstance(value, dict):
                raise RelayError("request body must be a JSON object")
            return value
        finally:
            self._cancel_read_deadline()

    def _cancel_read_deadline(self) -> None:
        timer = getattr(self, "_read_deadline", None)
        if timer is not None:
            timer.cancel()
            self._read_deadline = None

    def _browser_cors_headers(self, *, preflight: bool = False) -> dict[str, str]:
        allowed_origins = self.server.state.cors_allowed_origins
        origin_headers = self.headers.get_all("Origin") or []
        if not allowed_origins and not origin_headers:
            return {}
        headers = {
            "Vary": (
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
                if preflight
                else "Origin"
            )
        }
        if len(origin_headers) == 1 and origin_headers[0] in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin_headers[0]
        return headers

    def _write(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
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


def _resolve_relay_rate_limit_client_ip(
    state: RelayState,
    socket_client: str,
    real_ip_headers: list[str],
) -> str:
    try:
        socket_ip = ipaddress.ip_address(str(socket_client).split("%", 1)[0])
    except ValueError as exc:
        raise RelayError("socket client address is not a valid IP") from exc
    if not state.trust_proxy_headers:
        return str(socket_ip)
    if not (socket_ip.is_loopback or socket_ip.is_private):
        raise RelayError("trusted proxy mode accepts Relay control traffic only from a loopback or private proxy")
    if len(real_ip_headers) != 1:
        raise RelayError("trusted proxy request requires exactly one X-Real-IP header")
    candidate = str(real_ip_headers[0]).strip()
    if not candidate or "," in candidate or "%" in candidate:
        raise RelayError("X-Real-IP must contain exactly one global IP address")
    try:
        client_ip = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise RelayError("X-Real-IP must contain exactly one global IP address") from exc
    if not client_ip.is_global:
        raise RelayError("X-Real-IP must contain exactly one global IP address")
    return str(client_ip)


def serve_relay(
    host: str,
    control_port: int = DEFAULT_RELAY_CONTROL_PORT,
    provider_port: int = DEFAULT_RELAY_PROVIDER_PORT,
    advertise_host: str | None = None,
    advertise_control_port: int | None = None,
    advertise_provider_port: int | None = None,
    authorized_consumers: set[str] | None = None,
    allow_any_signed_consumer: bool = False,
    replay_store_path: str | None = None,
    trust_proxy_headers: bool = False,
    cors_allowed_origins: tuple[str, ...] | list[str] | None = None,
    v3_admission_config: RelayV3AdmissionConfig | None = None,
    network_profile: str = "local",
    payment_address: str | None = None,
    attestation_address: str | None = None,
    attestation_private_keys: Mapping[str, str] | None = None,
    settlement_rpc_url: str | None = None,
    settlement_private_key: str | None = None,
    settlement_chain_id: int | None = None,
    settlement_contract: str | None = None,
    settlement_version: int = 6,
    settlement_db_path: str = DEFAULT_RELAY_SETTLEMENT_DB,
    settlement_batch_size: int = DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE,
) -> None:
    state_options: dict[str, Any] = {}
    if cors_allowed_origins is not None:
        state_options["cors_allowed_origins"] = tuple(cors_allowed_origins)
    state = RelayState(
        authorized_consumers=authorized_consumers or set(),
        trust_proxy_headers=trust_proxy_headers,
        allow_any_signed_consumer=allow_any_signed_consumer,
        replay_store_path=replay_store_path,
        v3_admission_config=v3_admission_config,
        network_profile=network_profile,
        payment_address=payment_address,
        attestation_address=attestation_address,
        attestation_private_keys=dict(attestation_private_keys or {}),
        settlement_rpc_url=settlement_rpc_url,
        settlement_private_key=settlement_private_key,
        settlement_chain_id=settlement_chain_id,
        settlement_contract=settlement_contract,
        settlement_version=settlement_version,
        settlement_db_path=settlement_db_path,
        settlement_batch_size=settlement_batch_size,
        **state_options,
    )
    relay_host = advertise_host or host
    public_control_port = advertise_control_port or control_port
    public_provider_port = advertise_provider_port or provider_port
    provider_server = RelayProviderTCPServer(
        (host, provider_port),
        state,
        relay_host,
        public_control_port,
        public_provider_port,
    )
    control_server = RelayControlHTTPServer((host, control_port), state)
    if state._settlement_submitter is not None:
        state._settlement_submitter.start()
    provider_thread = threading.Thread(target=provider_server.serve_forever, name="mycomesh-relay-provider", daemon=True)
    provider_thread.start()
    try:
        control_server.serve_forever()
    finally:
        if state._settlement_submitter is not None:
            state._settlement_submitter.stop()
        control_server.shutdown()
        provider_server.shutdown()
        provider_server.server_close()
        control_server.server_close()


def _finish_relay_registration_callback(
    callback_thread: threading.Thread | None,
    active_socket: socket.socket | None,
    stop_event: threading.Event | None,
) -> bool:
    """Keep registration callbacks serialized across reconnects.

    A callback may be performing a Bridge join that depends on the current
    relay connection.  Waiting for it before reconnecting prevents a stale
    callback from starting a second heartbeat after a newer registration.
    During an explicit stop, wake the callback and use a bounded wait so a
    user-supplied callback cannot hold shutdown forever.
    """
    if callback_thread is None or not callback_thread.is_alive():
        return True
    if stop_event is not None and stop_event.is_set():
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except (AttributeError, OSError):
                pass
        callback_thread.join(timeout=DEFAULT_RELAY_RECONNECT_GRACE_SECONDS)
        return not callback_thread.is_alive()
    callback_thread.join(timeout=DEFAULT_RELAY_RECONNECT_GRACE_SECONDS)
    if callback_thread.is_alive() and stop_event is not None:
        stop_event.set()
    return not callback_thread.is_alive()


def run_relay_provider(
    relay_host: str,
    relay_port: int,
    config: ProviderConfig,
    on_registered: Callable[[dict[str, Any]], None] | None = None,
    stop_event: threading.Event | None = None,
    provider_tls: bool = False,
    tls_server_hostname: str | None = None,
) -> None:
    if (
        config.network_profile != "local"
        and int(config.settlement_version) in {4, 5, 6, 7}
        and not config.relay_payment_address
    ):
        raise RelayError(
            f"Settlement V{config.settlement_version} Relay Provider requires a pinned Relay payment address"
        )
    if (
        config.network_profile != "local"
        and int(config.settlement_version) in {5, 6, 7}
        and not config.relay_attestation_address
    ):
        raise RelayError(f"Settlement V{config.settlement_version} Relay Provider requires a pinned Relay attestation address")
    callback_thread: threading.Thread | None = None
    callback_cleanup_ok = True
    while stop_event is None or not stop_event.is_set():
        callback_thread = None
        callback_cleanup_ok = True
        active_socket: socket.socket | None = None
        retry_after_connection = False
        try:
            raw_socket = _connect_relay_provider_socket(relay_host, relay_port, timeout=10)
            try:
                if provider_tls:
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    sock = context.wrap_socket(
                        raw_socket,
                        server_hostname=tls_server_hostname or relay_host,
                    )
                else:
                    sock = raw_socket
            except Exception:
                raw_socket.close()
                raise
            active_socket = sock
            with sock:
                sock.settimeout(10)
                try:
                    # The job loop uses select() on the socket.  A buffered
                    # reader can prefetch a job while reading the ack, making
                    # those bytes invisible to the next select() call.
                    reader = sock.makefile("rb", buffering=0)
                except TypeError:
                    # Keep compatibility with small socket doubles used by
                    # embedders and tests that expose only makefile(mode).
                    reader = sock.makefile("rb")
                writer = sock.makefile("wb")
                challenge_message = _read_json_line(reader)
                expected_audience = f"{relay_host}:{relay_port}"
                challenge = str(challenge_message.get("challenge") or "")
                if (
                    challenge_message.get("type") != "provider_challenge"
                    or challenge_message.get("protocol") != RELAY_PROTOCOL_VERSION
                    or challenge_message.get("audience") != expected_audience
                    or len(challenge) != 64
                    or any(character not in "0123456789abcdef" for character in challenge)
                ):
                    raise RelayError("invalid Relay provider challenge")
                if config.relay_payment_address:
                    challenge_payment_address = _normalize_relay_payment_address(
                        str(challenge_message.get("relay_payment_address") or ""),
                        required=True,
                    )
                    if challenge_payment_address != config.relay_payment_address:
                        raise RelayError("Relay provider challenge payment address mismatch")
                if config.relay_attestation_address:
                    challenge_attestation_address = normalize_address(
                        str(challenge_message.get("relay_attestation_address") or "")
                    )
                    if challenge_attestation_address != config.relay_attestation_address:
                        raise RelayError("Relay provider challenge attestation address mismatch")
                _write_json_line(
                    writer,
                    {
                        "type": "provider_register",
                        "peer": _relay_provider_peer(
                            config,
                            audience=expected_audience,
                            challenge=challenge,
                        ),
                    },
                )
                registered = _read_json_line(reader)
                if (
                    registered.get("ok") is not True
                    or registered.get("type") != "provider_registered"
                    or registered.get("protocol") != RELAY_PROTOCOL_VERSION
                    or registered.get("peer_id") != config.peer_id
                    or registered.get("challenge") != challenge
                ):
                    raise RelayError(str(registered.get("error") or "invalid Relay registration acknowledgement"))
                if config.relay_payment_address:
                    registered_payment_address = _normalize_relay_payment_address(
                        str(registered.get("relay_payment_address") or ""),
                        required=True,
                    )
                    if registered_payment_address != config.relay_payment_address:
                        raise RelayError("Relay registration acknowledgement payment address mismatch")
                if config.relay_attestation_address:
                    registered_attestation_address = normalize_address(
                        str(registered.get("relay_attestation_address") or "")
                    )
                    if registered_attestation_address != config.relay_attestation_address:
                        raise RelayError("Relay registration acknowledgement attestation address mismatch")
                sock.settimeout(None)
                callback_errors: queue.Queue[Exception] = queue.Queue(maxsize=1)
                if on_registered is not None:
                    def run_registered_callback(
                        callback: Callable[[dict[str, Any]], None] = on_registered,
                        registration: dict[str, Any] = registered,
                        errors: queue.Queue[Exception] = callback_errors,
                        callback_socket: socket.socket = sock,
                        callback_stop_event: threading.Event | None = stop_event,
                    ) -> None:
                        if callback_stop_event is not None and callback_stop_event.is_set():
                            return
                        try:
                            callback(registration)
                        except Exception as exc:
                            try:
                                errors.put_nowait(exc)
                            except queue.Full:
                                pass
                            try:
                                callback_socket.shutdown(socket.SHUT_RDWR)
                            except (AttributeError, OSError):
                                pass

                    callback_thread = threading.Thread(
                        target=run_registered_callback,
                        name="mycomesh-relay-provider-registered",
                        daemon=True,
                    )
                    callback_thread.start()
                registered_key = config.ensure_transport_key(rotate=False)
                registered_key_id = (
                    str(registered_key.binding.get("key_id") or "")
                    if registered_key is not None
                    else ""
                )
                while stop_event is None or not stop_event.is_set():
                    try:
                        callback_error = callback_errors.get_nowait()
                    except queue.Empty:
                        callback_error = None
                    if callback_error is not None:
                        raise RelayError(
                            f"Relay provider registration callback failed: {callback_error}"
                        ) from callback_error
                    current_key = config.ensure_transport_key()
                    current_key_id = (
                        str(current_key.binding.get("key_id") or "")
                        if current_key is not None
                        else ""
                    )
                    if current_key_id != registered_key_id:
                        break
                    readable, _, _ = select.select([sock], [], [], 1.0)
                    if not readable:
                        continue
                    try:
                        callback_error = callback_errors.get_nowait()
                    except queue.Empty:
                        callback_error = None
                    if callback_error is not None:
                        raise RelayError(
                            f"Relay provider registration callback failed: {callback_error}"
                        ) from callback_error
                    envelope = _read_json_line(reader)
                    if envelope.get("type") != "relay_job":
                        continue
                    job_id = str(envelope.get("job_id") or "")
                    message = envelope.get("message")
                    if not isinstance(message, dict):
                        response = {"ok": False, "error": "relay job message must be a JSON object"}
                    elif isinstance(message.get("secure_frame"), str):
                        try:
                            request_frame = _decode_secure_frame(message["secure_frame"])
                            response = {
                                "secure_frame": _encode_secure_frame(
                                    handle_secure_frame(config, request_frame)
                                )
                            }
                        except Exception as exc:
                            response = {"ok": False, "error": str(exc)}
                    else:
                        if config.network_profile != "local":
                            response = {
                                "ok": False,
                                "error": "plaintext relay jobs are disabled for non-local providers",
                            }
                        else:
                            response = handle_message(config, message)
                    _write_json_line(
                        writer,
                        {
                            "type": "relay_job_result",
                            "job_id": job_id,
                            "response": response,
                        },
                    )
        except (OSError, RelayError, json.JSONDecodeError) as exc:
            retry_after_connection = not (stop_event is not None and stop_event.is_set())
            if retry_after_connection:
                # A Provider remains alive while it reconnects to the Relay. Keep
                # the retry loop, but expose the reason so Docker health failures
                # can be diagnosed without attaching a debugger to the container.
                print(
                    f"relay_provider_error: {exc}; retrying in 2 seconds",
                    file=sys.stderr,
                    flush=True,
                )
        finally:
            callback_cleanup_ok = _finish_relay_registration_callback(
                callback_thread,
                active_socket,
                stop_event,
            )
        if not callback_cleanup_ok:
            raise RelayError("Relay registration callback did not finish before reconnect")
        if retry_after_connection:
            time.sleep(2)


def _connect_relay_provider_socket(
    relay_host: str,
    relay_port: int,
    *,
    timeout: float,
) -> socket.socket:
    """Open the Provider's long-lived Relay socket, optionally through HTTP CONNECT.

    The sidecar's HTTP proxy settings do not affect this raw Relay connection.
    Keep the tunnel opt-in so existing direct deployments retain their current
    behavior and only providers behind a restricted egress need the extra
    setting.
    """
    proxy_url = os.getenv("MYCOMESH_PROVIDER_RELAY_PROXY", "").strip()
    if not proxy_url:
        return socket.create_connection((relay_host, relay_port), timeout=timeout)
    try:
        parsed = urllib.parse.urlsplit(proxy_url)
        proxy_port = parsed.port or (80 if parsed.scheme == "http" else 443)
    except ValueError as exc:
        raise RelayError(f"invalid MYCOMESH_PROVIDER_RELAY_PROXY: {exc}") from exc
    if parsed.scheme != "http" or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise RelayError("MYCOMESH_PROVIDER_RELAY_PROXY must be an http URL without a path")
    if not 1 <= int(proxy_port) <= 65535:
        raise RelayError("MYCOMESH_PROVIDER_RELAY_PROXY port must be between 1 and 65535")
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((parsed.hostname, int(proxy_port)), timeout=timeout)
        sock.settimeout(timeout)
        target_host = f"[{relay_host}]" if ":" in relay_host and not relay_host.startswith("[") else relay_host
        headers = [
            f"CONNECT {target_host}:{int(relay_port)} HTTP/1.1",
            f"Host: {target_host}:{int(relay_port)}",
            "Proxy-Connection: Keep-Alive",
        ]
        if parsed.username is not None:
            credentials = f"{urllib.parse.unquote(parsed.username)}:{urllib.parse.unquote(parsed.password or '')}"
            encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {encoded}")
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        reader = sock.makefile("rb", buffering=0)
        try:
            status_line = reader.readline(8192)
            parts = status_line.decode("iso-8859-1", "replace").strip().split(None, 2)
            if len(parts) < 2 or not parts[0].startswith("HTTP/"):
                raise RelayError("Relay HTTP proxy returned an invalid CONNECT response")
            try:
                status = int(parts[1])
            except ValueError as exc:
                raise RelayError("Relay HTTP proxy returned an invalid CONNECT status") from exc
            while True:
                line = reader.readline(8192)
                if not line or line in {b"\r\n", b"\n"}:
                    break
            if not 200 <= status < 300:
                raise RelayError(f"Relay HTTP proxy CONNECT failed with HTTP {status}")
        finally:
            reader.close()
        return sock
    except (OSError, RelayError):
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        raise


def relay_infer(
    state: RelayState,
    peer_id: str,
    message: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
    with state.lock:
        session = state.providers.get(peer_id)
    if session is None:
        raise RelayError(f"provider {peer_id!r} is not connected")
    if _relay_session_requires_secure(session) and not isinstance(message.get("secure_frame"), str):
        raise RelayError("provider requires sealed relay frames; plaintext inference is disabled")
    job = RelayJob(job_id=uuid.uuid4().hex, message=message, response_queue=queue.Queue(maxsize=1))
    try:
        session.jobs.put_nowait(job)
    except queue.Full as exc:
        raise RelayError(f"provider {peer_id!r} queue is full") from exc
    try:
        envelope = job.response_queue.get(timeout=timeout)
    except queue.Empty as exc:
        _disconnect_relay_provider(state, session)
        raise RelayError(f"provider {peer_id!r} timed out") from exc
    if isinstance(envelope, Exception):
        raise RelayError(str(envelope))
    if not isinstance(envelope, dict):
        raise RelayError("provider returned invalid relay response")
    if envelope.get("type") != "relay_job_result":
        raise RelayError("provider returned unexpected relay response")
    response = envelope.get("response")
    if not isinstance(response, dict):
        raise RelayError("provider result must contain a JSON response")
    if response.get("ok") is False:
        raise RelayError(str(response.get("error") or "relay inference failed"))
    return response


def v7_relay_capabilities(state: RelayState) -> dict[str, Any]:
    if state.settlement_version != 7:
        return {"enabled": False}
    candidates = _v7_provider_candidates(state)
    if not candidates:
        return {"enabled": True, "providers": 0}
    peer = candidates[0].peer
    settlement = peer.get("settlement") if isinstance(peer.get("settlement"), dict) else {}
    return {
        "enabled": True,
        "providers": len(candidates),
        "chain_id": int(settlement.get("chain_id") or state.settlement_chain_id or 0),
        "settlement_contract": str(settlement.get("contract") or state.settlement_contract or "").lower(),
        "relay_payment_address": state.payment_address,
        "relay_signer_address": state.attestation_address,
        "channel": str(peer.get("channel") or ""),
        "channel_hash": channel_to_hash(str(peer.get("channel") or "")),
        "pricing_version": int(settlement.get("pricing_version") or 0),
        "pricing_hash": str(settlement.get("pricing_hash") or "").lower(),
        "model": str(peer.get("model") or ""),
        "payment_schema": "mycomesh.x402.myco-credit-v1",
        "session_required": False,
    }


def v7_payment_required(state: RelayState, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
    request = _v7_normalize_request(state, path, body, payment=None)
    return {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": "myco-credit-v1",
                "network": f"eip155:{request['chain_id']}",
                "asset": "USDC",
                "payTo": state.payment_address,
                "maxAmountRequired": str(request["max_fee"]),
                "maxTimeoutSeconds": 900,
                "resource": path,
                "extra": {
                    "schema": "mycomesh.x402.myco-credit-v1",
                    "settlementContract": request["contract"],
                    "relaySigner": state.attestation_address,
                    "channel": request["channel"],
                    "channelHash": request["channel_hash"],
                    "pricingVersion": request["pricing_version"],
                    "pricingHash": request["pricing_hash"],
                    "model": request["model"],
                    "maxOutputTokens": request["max_output_tokens"],
                },
            }
        ],
    }


def relay_v7_openai(
    state: RelayState,
    path: str,
    body: Mapping[str, Any],
    payment: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if state._settlement_submitter is None:
        raise RelayError("Settlement V7 submitter is not configured")
    request = _v7_normalize_request(state, path, body, payment=payment)
    verified = verify_v7_authorization(
        payment,
        expected_chain_id=request["chain_id"],
        expected_contract=request["contract"],
        expected_relay=state.payment_address,
        expected_relay_signer=state.attestation_address,
        expected_request_id=request["request_id"],
        expected_request_hash=request["request_hash"],
    )
    authorization = verified["authorization"]
    grant = v7_key_grant(
        str(state.settlement_rpc_url),
        str(state.settlement_contract),
        str(authorization["key"]),
    )
    if not grant["active"] or grant["owner"] == ZERO_ADDRESS:
        raise RelayError("payment key is inactive")
    if int(authorization["max_fee"]) > int(grant["max_per_request"]):
        raise RelayError("payment key max_per_request is too small")
    if v7_account_balance(
        str(state.settlement_rpc_url),
        str(state.settlement_contract),
        str(grant["owner"]),
    ) < int(authorization["max_fee"]):
        raise RelayError("payment account has insufficient prepaid balance")
    candidates = _v7_provider_candidates(
        state,
        model=request["model"],
        chain_id=request["chain_id"],
        contract=request["contract"],
        channel=request["channel"],
        pricing_version=request["pricing_version"],
        pricing_hash=request["pricing_hash"],
    )
    if not candidates:
        raise RelayError("no compatible Settlement V7 Provider is connected")
    last_error: Exception | None = None
    for session in candidates:
        message = {
            "type": "infer",
            "request_id": request["request_id"],
            "network_id": str(session.peer.get("network_id") or "mycomesh-testnet"),
            "channel_id": str(session.peer.get("channel_id") or "codex"),
            "backend_policy": str(session.peer.get("backend_policy") or "codex-app-server-postvalidated-v1"),
            "channel": request["channel"],
            "endpoint": request["endpoint"],
            "model": request["model"],
            "max_output_tokens": request["max_output_tokens"],
            "payment_v7": dict(payment),
            **({"messages": request["messages"]} if request["endpoint"] == "chat" else {"input": request["input"]}),
            **request["options"],
        }
        try:
            response = _relay_v7_provider(state, session, message, timeout=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS)
        except V7ProviderRejected as exc:
            last_error = exc
            if exc.retryable:
                continue
            raise
        except RelayError as exc:
            last_error = exc
            if any(
                marker in str(exc).lower()
                for marker in (
                    "queue is full",
                    "not connected",
                    "connection reset",
                    "connection closed",
                    "broken pipe",
                    "disconnected",
                    "timed out",
                )
            ):
                continue
            raise
        provider_settlement = response.get("mycomesh_v7_settlement")
        if not isinstance(provider_settlement, dict):
            raise RelayError("Provider did not return a V7 UsageReceipt")
        try:
            signed = finalize_relay_receipt(
                provider_settlement,
                relay_private_key=str(state.attestation_private_keys[str(state.attestation_address)]),
            )
            prepared = prepare_v7_relay_settlement(
                signed,
                expected_chain_id=request["chain_id"],
                expected_contract=request["contract"],
                expected_relay=str(state.payment_address),
                expected_relay_signer=str(state.attestation_address),
            )
            status, accepted = state._settlement_submitter.enqueue(prepared)
        except (ChainError, RelaySettlementError, KeyError, TypeError, ValueError) as exc:
            raise RelayTransientError(f"failed to queue Settlement V7 receipt: {exc}") from exc
        raw = response.get("raw")
        output = dict(raw) if isinstance(raw, dict) else {
            "output_text": response.get("output_text") or "",
            "usage": response.get("usage") or {},
            "model": request["model"],
        }
        output.setdefault("model", request["model"])
        return output, {
            "schema": "mycomesh.x402.my-credit-receipt.v1",
            "protocol_version": 7,
            "chain_id": request["chain_id"],
            "settlement_contract": request["contract"],
            "settlement_key": prepared.key,
            "status": status,
            "accepted": bool(accepted),
            # Keep the signed receipt in the x402 response so any compatible
            # client can verify the Provider and Relay signatures without
            # querying Relay-local state.
            "signed_receipt": signed,
        }
    raise RelayError(str(last_error or "all compatible Providers rejected the request"))


def _relay_v7_provider(
    state: RelayState,
    session: RelayProviderSession,
    message: dict[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    signed = sign_document(
        message,
        state._scheduler_identity.private_key,
        purpose=INFERENCE_REQUEST_PURPOSE,
        audience=session.peer_id,
    )
    if not _relay_session_requires_secure(session):
        response = relay_infer(state, session.peer_id, signed, timeout=timeout)
    else:
        bindings = _relay_session_transport_bindings(session)
        if not bindings:
            raise RelayError("provider has no registered transport key")
        reply_key = generate_transport_key(state._scheduler_identity, lifetime_seconds=600)
        frame = seal_json_frame(
            {"message": signed, "reply_transport_key": reply_key.binding},
            sender=state._scheduler_identity,
            recipient_binding=bindings[0],
            expected_recipient_peer_id=session.peer_id,
            expected_recipient_public_key=str(session.peer.get("public_key") or "") or None,
            purpose=P2P_SECURE_REQUEST_PURPOSE,
            ttl_seconds=300,
        )
        envelope = relay_infer(
            state,
            session.peer_id,
            {"secure_frame": _encode_secure_frame(frame)},
            timeout=timeout,
        )
        encoded = envelope.get("secure_frame")
        if not isinstance(encoded, str):
            raise RelayError("Provider V7 secure response is missing its frame")
        try:
            opened = open_frame(
                _decode_secure_frame(encoded),
                recipient_key=reply_key,
                expected_purpose=P2P_SECURE_RESPONSE_PURPOSE,
                expected_sender_peer_id=session.peer_id,
                expected_sender_public_key=str(session.peer.get("public_key") or "") or None,
                replay_store=MemoryReplayStore(),
            )
            wrapper = opened.json_payload()
            response = wrapper.get("response") if isinstance(wrapper, dict) else None
        except SecureTransportError as exc:
            raise RelayError(f"invalid Provider V7 secure response: {exc}") from exc
        if not isinstance(response, dict):
            raise RelayError("Provider V7 secure response is invalid")
    if response.get("ok") is False:
        raise V7ProviderRejected(
            str(response.get("error") or "Provider rejected V7 inference"),
            retryable=response.get("retryable") is True,
        )
    return response


def _v7_provider_candidates(
    state: RelayState,
    *,
    model: str | None = None,
    chain_id: int | None = None,
    contract: str | None = None,
    channel: str | None = None,
    pricing_version: int | None = None,
    pricing_hash: str | None = None,
) -> list[RelayProviderSession]:
    expected_contract = normalize_address(contract) if contract else None
    expected_pricing_hash = str(pricing_hash or "").lower() or None
    with state.lock:
        sessions = list(state.providers.values())
    selected: list[RelayProviderSession] = []
    for session in sessions:
        peer = session.peer
        settlement = peer.get("settlement") if isinstance(peer.get("settlement"), dict) else {}
        if int(settlement.get("version") or 0) != 7:
            continue
        if model and str(peer.get("model") or "") != model:
            continue
        if channel and str(peer.get("channel") or "") != channel:
            continue
        if chain_id is not None and int(settlement.get("chain_id") or 0) != int(chain_id):
            continue
        if expected_contract and normalize_address(str(settlement.get("contract") or "")) != expected_contract:
            continue
        if pricing_version is not None and int(settlement.get("pricing_version") or 0) != int(pricing_version):
            continue
        if expected_pricing_hash and str(settlement.get("pricing_hash") or "").lower() != expected_pricing_hash:
            continue
        selected.append(session)
    selected.sort(key=lambda item: (item.jobs.qsize(), -int(item.last_seen), item.peer_id))
    return selected


def _v7_normalize_request(
    state: RelayState,
    path: str,
    body: Mapping[str, Any],
    *,
    payment: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if state.settlement_version != 7:
        raise RelayError("Settlement V7 is not enabled on this Relay")
    candidates = _v7_provider_candidates(state)
    if not candidates:
        raise RelayError("no Settlement V7 Provider is connected")
    peer = candidates[0].peer
    endpoint = "chat" if path.endswith("/chat/completions") else "responses"
    if not isinstance(body, Mapping):
        raise RelayError("inference body must be a JSON object")
    model = str(body.get("model") or peer.get("model") or "")
    if model != str(peer.get("model") or model):
        raise RelayError("model is not supported by this Relay Provider set")
    output_value = body.get("max_output_tokens")
    if output_value is None:
        output_value = body.get("max_tokens")
    max_output_tokens = int(output_value or 2000)
    if max_output_tokens <= 0:
        raise RelayError("max_output_tokens must be positive")
    input_value = body.get("input")
    messages = body.get("messages")
    if endpoint == "chat" and messages is None:
        raise RelayError("chat completions require messages")
    options = {
        field: body[field]
        for field in RESPONSES_REQUEST_OPTION_FIELDS | RESPONSES_LOCAL_OPTION_FIELDS
        if field in body
    }
    try:
        normalized_options = normalize_inference_request_options(endpoint, options)
        request_hash = "0x" + inference_request_hash(
            endpoint=endpoint,
            model=model,
            input_value=input_value,
            messages=messages,
            max_output_tokens=max_output_tokens,
            options=normalized_options,
        )
    except (ReservationError, TypeError, ValueError) as exc:
        raise RelayError(str(exc)) from exc
    settlement = peer.get("settlement") if isinstance(peer.get("settlement"), dict) else {}
    chain_id = int(settlement.get("chain_id") or state.settlement_chain_id or 0)
    contract = normalize_address(str(settlement.get("contract") or state.settlement_contract or ""))
    channel = str(peer.get("channel") or "")
    pricing_version = int(settlement.get("pricing_version") or 0)
    pricing_hash = str(settlement.get("pricing_hash") or "").lower()
    if not chain_id or not pricing_version or not pricing_hash:
        raise RelayError("Provider V7 pricing deployment is incomplete")
    request_id = ""
    if payment is not None:
        raw_auth = payment.get("authorization") if isinstance(payment, Mapping) else None
        request_id = str(raw_auth.get("request_id") or "") if isinstance(raw_auth, Mapping) else ""
    normalized = {
        "endpoint": endpoint,
        "model": model,
        "max_output_tokens": max_output_tokens,
        "options": normalized_options,
        "request_hash": request_hash,
        "request_id": request_id,
        "max_fee": int(os.getenv("MYCOMESH_V7_DEFAULT_MAX_FEE_UNITS", "100000")),
        "chain_id": chain_id,
        "contract": contract,
        "channel": channel,
        "channel_hash": channel_to_hash(channel),
        "pricing_version": pricing_version,
        "pricing_hash": pricing_hash,
    }
    normalized["messages" if endpoint == "chat" else "input"] = messages if endpoint == "chat" else input_value
    return normalized


def _v7_payment_header(headers: Any) -> dict[str, Any] | None:
    value = headers.get("PAYMENT-SIGNATURE") or headers.get("X-PAYMENT")
    if not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(str(value).encode("ascii") + b"=" * (-len(str(value)) % 4))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RelayError(f"invalid x402 PAYMENT-SIGNATURE header: {exc}") from exc
    if not isinstance(decoded, dict):
        raise RelayError("x402 PAYMENT-SIGNATURE must contain a JSON object")
    # x402 clients commonly wrap the scheme payload in `payload`; older
    # MycoMesh clients sent the payload object directly. Accept both forms so
    # the custom `myco-credit-v1` scheme remains interoperable at the HTTP edge.
    payload = decoded.get("payload")
    if isinstance(payload, dict) and "authorization" in payload:
        return payload
    payment = decoded.get("payment")
    if isinstance(payment, dict) and "authorization" in payment:
        return payment
    return decoded


def _encode_payment_header(value: Mapping[str, Any]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _disconnect_relay_provider(state: RelayState, session: RelayProviderSession) -> None:
    with state.lock:
        if state.providers.get(session.peer_id) is session:
            state.providers.pop(session.peer_id, None)
    if session.connection is not None:
        close_socket(session.connection)
    _fail_pending_jobs(session, RelayError(f"provider {session.peer_id!r} disconnected"))


def verify_relay_consumer_request(state: RelayState, message: dict[str, Any], peer_id: str | None = None) -> str:
    if not state.authorized_consumers and not state.allow_any_signed_consumer:
        raise RelayError("relay consumer allowlist is required")
    try:
        target_peer_id = str(peer_id or message.get("provider_peer_id") or "")
        declared_peer_id = str(message.get("provider_peer_id") or target_peer_id)
        if target_peer_id and declared_peer_id != target_peer_id:
            raise RelayError("relay target peer mismatch")
        audience = target_peer_id
        verify_document(message, purpose=INFERENCE_REQUEST_PURPOSE, audience=audience or None)
    except IdentityError as exc:
        raise RelayError(f"invalid relay control request signature: {exc}") from exc
    signature = message.get("signature")
    public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if public_key not in state.authorized_consumers and not state.allow_any_signed_consumer:
        raise RelayError("consumer is not authorized for this relay")
    request_id = str(message.get("request_id") or "")
    if not request_id:
        raise RelayError("request_id is required")
    if state._replay_store is not None:
        try:
            state._replay_store.remember(
                "relay.infer.request",
                f"{public_key}:{target_peer_id}:{request_id}",
                int(state.replay_ttl_seconds),
            )
        except ReplayError as exc:
            raise RelayError(str(exc).replace("replay key", "request_id")) from exc
    _consumer_rate_limit(state, public_key)
    return public_key


def verify_relay_consumer_frame(
    state: RelayState,
    encoded_frame: str,
    *,
    peer_id: str,
    admission: Any = None,
    address_probe: bool = False,
    session_status: bool = False,
    verified_admission: dict[str, Any] | None = None,
) -> str:
    is_address_probe = address_probe is True
    is_session_status = session_status is True
    if is_address_probe and is_session_status:
        raise RelayError("secure relay request cannot be both an address probe and session_status")
    if (
        not is_address_probe
        and not state.authorized_consumers
        and not state.allow_any_signed_consumer
        and state.v3_admission_config is None
        and not _is_v4_admission(admission)
    ):
        raise RelayError("relay consumer allowlist is required")
    with state.lock:
        session = state.providers.get(peer_id)
    if session is None:
        raise RelayError(f"provider {peer_id!r} is not connected")
    bindings = _relay_session_transport_bindings(session)
    if not bindings:
        raise RelayError("provider has not registered a signed transport key")
    request_frame = _decode_secure_frame(encoded_frame)
    expected_purpose = (
        P2P_ADDRESS_PROBE_PURPOSE
        if is_address_probe
        else P2P_SESSION_STATUS_REQUEST_PURPOSE
        if is_session_status
        else P2P_SECURE_REQUEST_PURPOSE
    )
    try:
        metadata = verify_frame_metadata(
            request_frame,
            expected_purpose=expected_purpose,
            expected_recipient_peer_id=peer_id,
            expected_recipient_public_key=str(session.peer.get("public_key") or "") or None,
        )
        binding = next(
            (
                item
                for item in bindings
                if str(item.get("key_id") or "") == metadata.recipient_key_id
            ),
            None,
        )
        if binding is None:
            raise RelayError("secure relay request targets an unregistered provider transport key")
        verify_frame_metadata(
            request_frame,
            expected_purpose=expected_purpose,
            expected_recipient_peer_id=peer_id,
            expected_recipient_public_key=str(session.peer.get("public_key") or "") or None,
            expected_recipient_binding=binding,
        )
    except SecureTransportError as exc:
        raise RelayError(f"invalid secure relay request: {exc}") from exc
    verified_session_status = metadata.purpose == P2P_SESSION_STATUS_REQUEST_PURPOSE
    if verified_admission is not None:
        verified_admission["session_status"] = verified_session_status
    public_key = metadata.sender_public_key
    v4_admission = _is_v4_admission(admission)
    if verified_session_status and (
        not v4_admission or str(admission.get("version") or "") not in {"5", "6"}
    ):
        raise RelayError("session_status requires Settlement V5 or V6 admission")
    requires_v3_admission = (
        not is_address_probe
        and public_key not in state.authorized_consumers
        and not state.allow_any_signed_consumer
        and not v4_admission
    )
    if requires_v3_admission:
        if state.v3_admission_config is None:
            raise RelayError("consumer is not authorized for this relay")
        if not state._v3_admission_slots.acquire(blocking=False):
            raise RelayError("Relay V3 admission capacity is exhausted")
    else:
        _consumer_rate_limit(state, public_key)
    try:
        if state._replay_store is None:
            raise RelayError("secure relay requires a persistent replay store")
        try:
            state._replay_store.remember(
                "relay.secure.envelope",
                f"{public_key}:{peer_id}:{metadata.message_id}",
                max(1, metadata.expires_at - int(time.time())),
            )
        except ReplayError as exc:
            raise RelayError("secure relay request has already been forwarded") from exc
        if v4_admission:
            try:
                verified_session = _verify_relay_v4_admission(
                    admission,
                    sender_public_key=public_key,
                    provider_peer=session.peer,
                    peer_id=peer_id,
                    expected_relay_payment_address=state.payment_address,
                    require_deployment=str(admission.get("version") or "") in {"5", "6"},
                )
                if str(admission.get("version") or "") in {"5", "6"}:
                    requested_signer = normalize_address(
                        str(admission.get("relay_attestation_address") or "")
                    )
                    if requested_signer not in state.attestation_private_keys:
                        raise SessionProtocolError(
                            f"V{admission.get('version')} Relay attestation key is not available"
                        )
                    if verified_admission is not None:
                        verified_admission["v5_attestation_request"] = {
                            "chain_id": int(verified_session["settlement_chain_id"]),
                            "settlement_contract": str(verified_session["settlement_contract"]),
                            "session_id": str(verified_session["session_id"]),
                            "request_hash": str(verified_session["request_hash"]),
                            "max_fee_units": int(verified_session["max_fee_units"]),
                            "provider": str(verified_session["provider_payment_address"]),
                            "relay": str(verified_session["relay_payment_address"]),
                            "sequence": int(verified_session["sequence"]) - 1,
                            "deadline": int(verified_session["deadline"]),
                            "relay_attestation_address": requested_signer,
                            "relay_epoch": int(verified_session.get("relay_epoch") or 0),
                            "protocol_version": int(admission.get("version") or 5),
                        }
            except (ChainError, SessionProtocolError, TypeError, ValueError) as exc:
                raise RelayError(f"consumer V4 admission was rejected: {exc}") from exc
            _consumer_rate_limit(state, public_key)
        elif requires_v3_admission:
            try:
                verified_v3 = verify_relay_v3_admission(
                    admission,
                    sender_public_key=public_key,
                    provider_peer=session.peer,
                    config=state.v3_admission_config,
                )
                if verified_admission is not None:
                    verified_admission["v3_max_fee_units"] = int(verified_v3["max_fee_units"])
            except ConsumerAdmissionError as exc:
                raise RelayError(f"consumer V3 admission was rejected: {exc}") from exc
            _consumer_rate_limit(state, public_key)
    finally:
        if requires_v3_admission:
            state._v3_admission_slots.release()
    return public_key


def _is_v4_admission(value: Any) -> bool:
    return isinstance(value, dict) and str(value.get("version") or "") in {"4", "5", "6"}


def _relay_response_fee_units(response: Any) -> int | None:
    """Read a plaintext settlement fee without opening sealed Relay frames."""

    if not isinstance(response, dict):
        return None
    for key in ("mycomesh_v6_settlement", "mycomesh_v5_settlement", "mycomesh_v4_settlement", "mycomesh_v3_settlement"):
        settlement = response.get(key)
        if not isinstance(settlement, dict):
            continue
        for field_name in ("quoted_fee", "amount_units"):
            value = settlement.get(field_name)
            try:
                if value is not None:
                    return max(0, int(value))
            except (TypeError, ValueError):
                return None
    return None


def _verify_relay_v4_admission(
    admission: Any,
    *,
    sender_public_key: str,
    provider_peer: Mapping[str, Any],
    peer_id: str,
    expected_relay_payment_address: str | None = None,
    require_deployment: bool = False,
) -> dict[str, Any]:
    """Validate a signed V4 envelope without a per-request chain read.

    The Relay authenticates only the transport admission.  Provider-side
    admission remains authoritative for the on-chain session, sequence, and
    price, so this fast path cannot mint spend or bypass Settlement checks.
    """
    if not isinstance(admission, dict):
        raise SessionProtocolError("V4 admission must be an object")
    authorization = admission.get("session_authorization")
    request = admission.get("session_request")
    if not isinstance(authorization, dict) or not isinstance(request, dict):
        raise SessionProtocolError("V4 admission must contain session_authorization and session_request")
    provider_id = str(provider_peer.get("peer_id") or peer_id)
    auth = verify_session_authorization(
        authorization,
        provider_id=provider_id,
        expected_session_public_key=sender_public_key,
        now=int(time.time()),
        require_outer_signature=True,
        require_evm_signature=True,
    )
    # The Relay deliberately does not keep the Provider's durable Session
    # progress.  Validate the request against its own predecessor so a
    # multi-request prepaid session can pass this transport admission; the
    # Provider remains authoritative for the actual cross-request sequence.
    normalized_request = normalize_session_request(
        request,
        require_signature=True,
        require_canonical=True,
    )
    previous_sequence = int(normalized_request["sequence"]) - 1
    previous_spend = int(normalized_request["cumulative_spend_units"]) - int(
        normalized_request["max_fee_units"]
    )
    if previous_sequence < 0 or previous_spend < 0:
        raise SessionProtocolError("V4 request predecessor is invalid")
    verified_request = verify_session_request(
        normalized_request,
        auth,
        previous_sequence=previous_sequence,
        previous_cumulative_spend_units=previous_spend,
        now=int(time.time()),
        require_outer_signature=True,
        require_evm_signature=True,
    )
    if str(verified_request["session_public_key"]).lower() != sender_public_key.lower():
        raise SessionProtocolError("V4 request signer does not match Relay sender")
    if expected_relay_payment_address:
        try:
            expected_payment_address = _normalize_relay_payment_address(
                expected_relay_payment_address,
                required=True,
            )
        except RelayError as exc:
            raise SessionProtocolError(str(exc)) from exc
        if verified_request["relay_payment_address"].lower() != expected_payment_address:
            raise SessionProtocolError("V4 Relay payment address mismatch")
    result = dict(verified_request)
    result["settlement_chain_id"] = auth.get("settlement_chain_id")
    result["settlement_contract"] = auth.get("settlement_contract")
    if require_deployment and (
        result["settlement_chain_id"] is None or result["settlement_contract"] is None
    ):
        raise SessionProtocolError("V5 Relay admission is missing its settlement deployment")
    return result


def _consumer_rate_limit(state: RelayState, public_key: str) -> None:
    _bounded_rate_limit(
        state,
        state.consumer_rate_limits,
        public_key,
        error="consumer rate limit exceeded",
    )


def _bounded_rate_limit(
    state: RelayState,
    entries: dict[str, list[float]],
    identity: str,
    *,
    error: str,
) -> None:
    now = time.time()
    with state.lock:
        recent = [
            timestamp
            for timestamp in entries.get(identity, [])
            if now - timestamp < state.rate_limit_window_seconds
        ]
        if identity not in entries and len(entries) >= MAX_RELAY_RATE_LIMIT_IDENTITIES:
            for candidate, timestamps in list(entries.items()):
                if not any(now - timestamp < state.rate_limit_window_seconds for timestamp in timestamps):
                    entries.pop(candidate, None)
            if len(entries) >= MAX_RELAY_RATE_LIMIT_IDENTITIES:
                raise RelayError("rate limit identity capacity reached")
        if len(recent) >= state.rate_limit_max_requests:
            raise RelayError(error)
        recent.append(now)
        entries[identity] = recent


def _reserve_consumer_slot(state: RelayState, public_key: str) -> None:
    with state.lock:
        active = int(state.consumer_in_flight.get(public_key) or 0)
        if active >= state.consumer_max_in_flight:
            raise RelayError("consumer concurrency exceeded")
        state.consumer_in_flight[public_key] = active + 1


def _release_consumer_slot(state: RelayState, public_key: str) -> None:
    with state.lock:
        active = int(state.consumer_in_flight.get(public_key) or 0)
        if active <= 1:
            state.consumer_in_flight.pop(public_key, None)
        else:
            state.consumer_in_flight[public_key] = active - 1


def send_relay_message(address: RelayAddress, message: dict[str, Any], timeout: float) -> dict[str, Any]:
    if address.secure:
        raise RelayError(
            "myco+relay(s):// requires send_secure_relay_message and a signed provider transport key"
        )
    return _post_relay_message(address, {"message": message}, timeout)


def send_secure_relay_message(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None = None,
) -> dict[str, Any]:
    return _send_secure_relay_message(
        address,
        message,
        timeout,
        sender=sender,
        recipient_binding=recipient_binding,
        expected_recipient_public_key=expected_recipient_public_key,
        purpose=P2P_SECURE_REQUEST_PURPOSE,
        address_probe=False,
        session_status=False,
    )


def send_secure_relay_status(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None = None,
) -> dict[str, Any]:
    if not isinstance(message, dict) or message.get("type") != "session_status":
        raise RelayError("secure Relay status request must be a session_status message")
    return _send_secure_relay_message(
        address,
        message,
        timeout,
        sender=sender,
        recipient_binding=recipient_binding,
        expected_recipient_public_key=expected_recipient_public_key,
        purpose=P2P_SESSION_STATUS_REQUEST_PURPOSE,
        address_probe=False,
        session_status=True,
    )


def send_secure_relay_probe(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(message, dict)
        or set(message) != {"type", "request_id", "audience"}
        or message.get("type") != "ping"
        or not isinstance(message.get("request_id"), str)
        or not message["request_id"]
    ):
        raise RelayError("secure Relay address probe must contain only a ping")
    return _send_secure_relay_message(
        address,
        message,
        timeout,
        sender=sender,
        recipient_binding=recipient_binding,
        expected_recipient_public_key=expected_recipient_public_key,
        purpose=P2P_ADDRESS_PROBE_PURPOSE,
        address_probe=True,
        session_status=False,
    )


def submit_relay_settlement(
    address: RelayAddress,
    submission: Mapping[str, Any],
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Submit a Consumer-signed V5 receipt to the Relay's durable outbox."""

    if not isinstance(submission, Mapping):
        raise RelayError("Relay settlement submission must be an object")
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=60.0,
            label="Relay settlement submission timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
    scheme = "https" if address.tls else "http"
    version = int(submission.get("protocol_version") or 5)
    if version not in {5, 6}:
        raise RelayError("Relay settlement submission protocol_version must be 5 or 6")
    url = f"{scheme}://{address.host}:{address.port}/v{version}/settlements"
    request = urllib.request.Request(
        url,
        data=json.dumps(dict(submission), separators=(",", ":")).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    deadline = time.monotonic() + timeout
    try:
        with _RELAY_HTTP_OPENER.open(request, timeout=timeout) as response:
            payload = read_bounded(
                response,
                maximum=64 * 1024,
                label="Relay settlement response",
                deadline=deadline,
            ).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            payload = read_bounded(
                exc,
                maximum=64 * 1024,
                label="Relay settlement error response",
                deadline=deadline,
            ).decode("utf-8", errors="replace")
        finally:
            exc.close()
        raise RelayError(f"Relay settlement returned HTTP {exc.code}: {text_preview(payload)}") from exc
    except (urllib.error.URLError, NetworkIOError) as exc:
        raise RelayError(f"failed to submit settlement to Relay: {exc}") from exc
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RelayError("Relay settlement response is not JSON") from exc
    if not isinstance(value, dict):
        raise RelayError("Relay settlement response must be an object")
    if value.get("ok") is not True:
        raise RelayError(text_preview(str(value.get("error") or "Relay rejected settlement")))
    return value


def _send_secure_relay_message(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None,
    purpose: str,
    address_probe: bool,
    session_status: bool,
) -> dict[str, Any]:
    if not address.secure:
        raise RelayError("secure relay messages require a myco+relay:// or myco+relays:// address")
    try:
        resolved_timeout = bounded_timeout(
            timeout,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
        reply_key = generate_transport_key(sender, lifetime_seconds=600)
        request_frame = seal_json_frame(
            {"message": message, "reply_transport_key": reply_key.binding},
            sender=sender,
            recipient_binding=recipient_binding,
            expected_recipient_peer_id=address.peer_id,
            expected_recipient_public_key=expected_recipient_public_key,
            purpose=purpose,
            ttl_seconds=min(300, max(30, int(resolved_timeout) + 5)),
        )
    except (NetworkIOError, SecureTransportError, ValueError) as exc:
        raise RelayError(f"failed to seal secure relay request: {exc}") from exc
    value = _post_relay_message(
        address,
        {
            "secure_frame": _encode_secure_frame(request_frame),
            # The Relay validates this signed admission before forwarding the
            # encrypted frame.  It never receives the request plaintext; the
            # Provider repeats the full V4 checks after decryption.
            **(
                {
                    "admission": (
                        {
                            "version": str(int(message.get("session_protocol_version") or 4)),
                            "session_authorization": message.get("session_authorization"),
                            "session_request": message.get("session_request"),
                            **(
                                {"relay_attestation_address": message.get("relay_attestation_address")}
                                if int(message.get("session_protocol_version") or 4) in {5, 6}
                                else {}
                            ),
                        }
                        if message.get("session_v4") is True
                        else message.get("payment_reservation")
                    )
                }
                if message.get("session_v4") is True or message.get("payment_reservation") is not None
                else {}
            ),
            **({"address_probe": True} if address_probe else {}),
            **({"session_status": True} if session_status else {}),
        },
        resolved_timeout,
    )
    encoded_response = value.get("secure_frame")
    if not isinstance(encoded_response, str):
        raise RelayError("secure relay response is missing its sealed frame")
    try:
        opened = open_frame(
            _decode_secure_frame(encoded_response),
            recipient_key=reply_key,
            expected_purpose=P2P_SECURE_RESPONSE_PURPOSE,
            expected_sender_peer_id=address.peer_id,
            expected_sender_public_key=expected_recipient_public_key,
            replay_store=MemoryReplayStore(),
        )
        wrapper = opened.json_payload()
        if set(wrapper) != {"response"} or not isinstance(wrapper.get("response"), dict):
            raise RelayError("secure relay response wrapper is invalid")
        response = wrapper["response"]
    except SecureTransportError as exc:
        raise RelayError(f"invalid secure relay response: {exc}") from exc
    if response.get("ok") is False:
        raise RelayError(str(response.get("error") or "relay inference failed"))
    if value.get("relay_attestation") is not None:
        response["_mycomesh_relay_attestation"] = value.get("relay_attestation")
    return response


def _post_relay_message(
    address: RelayAddress,
    body: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
    control_scheme = "https" if address.tls else "http"
    url = f"{control_scheme}://{address.host}:{address.port}/infer/{urllib.parse.quote(address.peer_id, safe='')}"
    request = urllib.request.Request(
        url,
        data=json.dumps({**body, "timeout": timeout}).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    request_timeout = timeout + 5
    deadline = time.monotonic() + request_timeout
    try:
        with _RELAY_HTTP_OPENER.open(request, timeout=request_timeout) as response:
            payload = read_bounded(
                response,
                maximum=MAX_RELAY_RESPONSE_BYTES,
                label="relay response",
                deadline=deadline,
            ).decode(
                "utf-8", errors="replace"
            )
    except urllib.error.HTTPError as exc:
        try:
            payload = read_bounded(
                exc,
                maximum=MAX_RELAY_RESPONSE_BYTES,
                label="relay error response",
                deadline=deadline,
            ).decode(
                "utf-8", errors="replace"
            )
        except NetworkIOError as limit_exc:
            raise RelayError(str(limit_exc)) from exc
        finally:
            exc.close()
        raise RelayError(f"relay returned HTTP {exc.code}: {text_preview(payload)}") from exc
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
    except urllib.error.URLError as exc:
        raise RelayError(f"failed to reach relay: {exc}") from exc
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RelayError("relay response must be a JSON object")
    if value.get("ok") is False:
        raise RelayError(text_preview(str(value.get("error") or "relay request failed")))
    return value


def list_relay_providers(state: RelayState) -> list[dict[str, Any]]:
    with state.lock:
        providers = [
            {
                **session.peer,
                "connected_at": session.connected_at,
                "last_seen": session.last_seen,
            }
            for session in state.providers.values()
        ]
    providers.sort(key=lambda item: (int(item.get("last_seen") or 0), str(item.get("peer_id") or "")), reverse=True)
    return providers


def parse_relay_address(value: str) -> RelayAddress:
    raw = value.strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"relay", "relays", "myco+relay", "myco+relays"}:
        raise ValueError(
            "relay address must use relay://, relays://, myco+relay://, or myco+relays://"
        )
    if not parsed.hostname:
        raise ValueError("relay host is required")
    if parsed.port is None:
        raise ValueError("relay port is required")
    peer_id = urllib.parse.unquote(parsed.path.lstrip("/"))
    if not peer_id:
        raise ValueError("relay peer id is required")
    return RelayAddress(host=parsed.hostname, port=parsed.port, peer_id=peer_id, scheme=parsed.scheme)


def _relay_provider_peer(
    config: ProviderConfig,
    audience: str | None = None,
    challenge: str | None = None,
) -> dict[str, Any]:
    transport_keys = config.accepted_transport_bindings()
    peer = {
        "peer_id": config.peer_id,
        "protocol": RELAY_PROTOCOL_VERSION,
        "channel": config.channel,
        "agent_id": config.agent_id,
        "model": config.model,
        "last_seen": int(time.time()),
        "network_profile": config.network_profile,
        "secure_transport_required": config.network_profile != "local",
    }
    if config.network_profile != "local":
        peer.update(
            {
                "network_id": config.network_id,
                "channel_id": config.channel_id,
                "backend_policy": config.backend_policy,
            }
        )
    peer.update(provider_runtime_capabilities(config))
    if challenge is not None:
        peer["challenge"] = challenge
    if config.identity is not None:
        peer["public_key"] = config.identity.public_key
    if transport_keys:
        peer["transport_key"] = transport_keys[0]
        peer["transport_keys"] = transport_keys
    if config.payment_address:
        peer["payment_address"] = config.payment_address
    relay_payment_address = getattr(config, "relay_payment_address", None)
    if relay_payment_address:
        peer["relay_payment_address"] = relay_payment_address
    relay_attestation_address = getattr(config, "relay_attestation_address", None)
    if relay_attestation_address:
        peer["relay_attestation_address"] = relay_attestation_address
    return sign_document(peer, config.identity.private_key, purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE, audience=audience)


def verify_relay_provider_peer(
    peer: dict[str, Any],
    require_signed: bool = True,
    audience: str | None = None,
    expected_challenge: str | None = None,
    expected_relay_payment_address: str | None = None,
    expected_relay_attestation_address: str | None = None,
) -> dict[str, Any]:
    if not require_signed:
        normalized = dict(peer)
        normalized = _normalize_provider_relay_payment_address(
            normalized,
            expected_relay_payment_address=expected_relay_payment_address,
        )
        return _normalize_provider_relay_attestation_address(
            normalized,
            expected_relay_attestation_address=expected_relay_attestation_address,
        )
    try:
        unsigned = verify_document(peer, purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE, audience=audience)
    except IdentityError as exc:
        raise RelayError(f"invalid provider signature: {exc}") from exc
    public_key = str(unsigned.get("public_key") or "")
    if not public_key:
        signature = peer.get("signature")
        if isinstance(signature, dict):
            public_key = str(signature.get("public_key") or "")
    if not public_key:
        raise RelayError("provider public_key is required")
    if str(unsigned.get("peer_id") or "") != peer_id_from_public_key(public_key):
        raise RelayError("peer_id does not match public_key")
    if expected_challenge is not None and unsigned.get("challenge") != expected_challenge:
        raise RelayError("provider registration challenge does not match this connection")
    normalized = dict(unsigned)
    normalized["public_key"] = public_key
    normalized["signature"] = peer["signature"]
    binding = normalized.get("transport_key")
    if binding is not None:
        if not isinstance(binding, dict):
            raise RelayError("provider transport_key must be an object")
        try:
            verify_transport_key_binding(
                binding,
                expected_peer_id=str(normalized.get("peer_id") or ""),
                expected_identity_public_key=public_key,
            )
        except SecureTransportError as exc:
            raise RelayError(f"invalid provider transport key: {exc}") from exc
    network_profile = str(normalized.get("network_profile") or "local").strip().lower()
    if network_profile not in {"local", "testnet", "open"}:
        raise RelayError("provider network_profile is invalid")
    secure_required = normalized.get("secure_transport_required", False)
    if type(secure_required) is not bool:
        raise RelayError("provider secure_transport_required must be a boolean")
    if network_profile != "local" and not secure_required:
        raise RelayError("non-local relay providers must require secure transport")
    if network_profile != "local":
        try:
            require_enabled_channel_binding(
                network_id=normalized.get("network_id"),
                channel_id=normalized.get("channel_id"),
                channel=normalized.get("channel"),
                backend_policy=normalized.get("backend_policy"),
                label="Relay Provider",
            )
        except ValueError as exc:
            raise RelayError(str(exc)) from exc
    if secure_required and not isinstance(binding, dict):
        raise RelayError("secure relay provider requires a signed transport key")
    raw_transport_keys = normalized.get("transport_keys", [])
    if not isinstance(raw_transport_keys, list) or len(raw_transport_keys) > 4:
        raise RelayError("provider transport_keys must be a list of at most four bindings")
    verified_key_ids: set[str] = set()
    for item in raw_transport_keys:
        if not isinstance(item, dict):
            raise RelayError("provider transport_keys entries must be objects")
        try:
            verified_key = verify_transport_key_binding(
                item,
                expected_peer_id=str(normalized.get("peer_id") or ""),
                expected_identity_public_key=public_key,
            )
        except SecureTransportError as exc:
            raise RelayError(f"invalid provider transport key: {exc}") from exc
        if verified_key.key_id in verified_key_ids:
            raise RelayError("provider transport_keys contains a duplicate key")
        verified_key_ids.add(verified_key.key_id)
    if isinstance(binding, dict) and raw_transport_keys:
        current_key_id = str(binding.get("key_id") or "")
        if current_key_id not in verified_key_ids:
            raise RelayError("provider transport_keys must include transport_key")
    try:
        payment_address = normalize_payment_address(str(normalized.get("payment_address")) if normalized.get("payment_address") else None)
    except BillingError as exc:
        raise RelayError(str(exc)) from exc
    if payment_address:
        normalized["payment_address"] = payment_address
    normalized = _normalize_provider_relay_payment_address(
        normalized,
        expected_relay_payment_address=expected_relay_payment_address,
    )
    return _normalize_provider_relay_attestation_address(
        normalized,
        expected_relay_attestation_address=expected_relay_attestation_address,
    )


def _normalize_provider_relay_payment_address(
    peer: dict[str, Any],
    *,
    expected_relay_payment_address: str | None,
) -> dict[str, Any]:
    raw_payment_address = peer.get("relay_payment_address")
    supplied_payment_address = _normalize_relay_payment_address(
        str(raw_payment_address) if raw_payment_address else None,
        required=expected_relay_payment_address is not None,
    )
    expected_payment_address = _normalize_relay_payment_address(
        expected_relay_payment_address,
        required=expected_relay_payment_address is not None,
    )
    if expected_payment_address and supplied_payment_address != expected_payment_address:
        raise RelayError("Provider registration Relay payment address mismatch")
    if supplied_payment_address:
        peer["relay_payment_address"] = supplied_payment_address
    return peer


def _normalize_provider_relay_attestation_address(
    peer: dict[str, Any],
    *,
    expected_relay_attestation_address: str | None,
) -> dict[str, Any]:
    raw = peer.get("relay_attestation_address")
    try:
        supplied = normalize_address(str(raw or ZERO_ADDRESS))
        expected = normalize_address(str(expected_relay_attestation_address or ZERO_ADDRESS))
    except ChainError as exc:
        raise RelayError(f"Provider registration Relay attestation address is invalid: {exc}") from exc
    if expected != ZERO_ADDRESS and supplied != expected:
        raise RelayError("Provider registration Relay attestation address mismatch")
    if supplied != ZERO_ADDRESS:
        peer["relay_attestation_address"] = supplied
    return peer


def _relay_session_requires_secure(session: RelayProviderSession) -> bool:
    return bool(session.peer.get("secure_transport_required"))


def _relay_session_transport_bindings(session: RelayProviderSession) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    current = session.peer.get("transport_key")
    if isinstance(current, dict):
        bindings.append(current)
    raw = session.peer.get("transport_keys")
    if isinstance(raw, list):
        bindings.extend(item for item in raw if isinstance(item, dict))
    deduplicated: dict[str, dict[str, Any]] = {}
    for binding in bindings:
        key_id = str(binding.get("key_id") or "")
        if key_id:
            deduplicated[key_id] = binding
    return list(deduplicated.values())


def _fail_pending_jobs(session: RelayProviderSession, exc: Exception) -> None:
    while True:
        try:
            job = session.jobs.get_nowait()
        except queue.Empty:
            return
        job.response_queue.put(exc)


def _write_json_line(writer: Any, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
    writer.write(data)
    writer.flush()


def _read_json_line(reader: Any) -> dict[str, Any]:
    raw = reader.readline(MAX_RELAY_MESSAGE_BYTES + 1)
    if not raw:
        raise RelayError("connection closed")
    if len(raw) > MAX_RELAY_MESSAGE_BYTES:
        raise RelayError("message too large")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RelayError("message must be a JSON object")
    return value


def _encode_secure_frame(frame: bytes) -> str:
    if not isinstance(frame, bytes) or not frame or len(frame) > MAX_SECURE_FRAME_BYTES:
        raise RelayError("secure relay frame size is invalid")
    return base64.urlsafe_b64encode(frame).decode("ascii").rstrip("=")


def _decode_secure_frame(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_RELAY_ENCODED_FRAME_BYTES:
        raise RelayError("secure relay frame size is invalid")
    padding = "=" * (-len(value) % 4)
    try:
        frame = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RelayError("secure relay frame is not valid base64url") from exc
    if not frame or len(frame) > MAX_SECURE_FRAME_BYTES:
        raise RelayError("secure relay frame size is invalid")
    return frame


def _coerce_timeout(value: Any, default: float) -> float:
    resolved = default if value is None else value
    try:
        return bounded_timeout(
            resolved,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
