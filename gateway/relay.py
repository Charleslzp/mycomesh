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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .billing import BillingError, normalize_payment_address
from .browser_cors import parse_allowed_origins
from .channel_policy import require_enabled_channel_binding
from .consumer_admission import (
    ConsumerAdmissionError,
    RelayV3AdmissionConfig,
    verify_relay_v3_admission,
)
from .identity import IdentityError, NodeIdentity, peer_id_from_public_key, sign_document, verify_document
from .netio import NetworkIOError, bounded_timeout, read_bounded, text_preview
from .p2p import (
    INFERENCE_REQUEST_PURPOSE,
    MAX_MESSAGE_BYTES,
    P2P_ADDRESS_PROBE_PURPOSE,
    P2P_SECURE_REQUEST_PURPOSE,
    P2P_SECURE_RESPONSE_PURPOSE,
    P2PError,
    ProviderConfig,
    handle_message,
    handle_secure_frame,
    provider_runtime_capabilities,
)
from .replay import DEFAULT_REPLAY_DB, ReplayError, ReplayStore
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


def relay_error_http_response(error: Exception) -> tuple[int, dict[str, str]]:
    """Map transient Provider/Relay failures to retry-aware HTTP responses."""
    message = str(error).lower()
    if "timed out" in message or "deadline exceeded" in message:
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


_RELAY_HTTP_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRelayRedirectHandler(),
)


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
    trust_proxy_headers: bool = False
    rate_limits: dict[str, list[float]] = field(default_factory=dict)
    reconnect_grace_seconds: float = DEFAULT_RELAY_RECONNECT_GRACE_SECONDS
    rate_limit_window_seconds: int = DEFAULT_RELAY_RATE_LIMIT_WINDOW_SECONDS
    rate_limit_max_requests: int = DEFAULT_RELAY_RATE_LIMIT_MAX_REQUESTS
    authorized_consumers: set[str] = field(default_factory=set)
    allow_any_signed_consumer: bool = False
    consumer_rate_limits: dict[str, list[float]] = field(default_factory=dict)
    consumer_in_flight: dict[str, int] = field(default_factory=dict)
    consumer_max_in_flight: int = DEFAULT_RELAY_CONSUMER_MAX_IN_FLIGHT
    provider_queue_size: int = DEFAULT_RELAY_PROVIDER_QUEUE_SIZE
    socket_timeout_seconds: float = DEFAULT_RELAY_SOCKET_TIMEOUT_SECONDS
    control_max_connections: int = DEFAULT_RELAY_MAX_CONNECTIONS
    provider_max_connections: int = DEFAULT_RELAY_MAX_CONNECTIONS
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

    def __post_init__(self) -> None:
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
        if self.replay_store_path:
            self._replay_store = ReplayStore(self.replay_store_path)
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
            _write_json_line(
                self.wfile,
                {
                    "type": "provider_challenge",
                    "protocol": RELAY_PROTOCOL_VERSION,
                    "challenge": challenge,
                    "audience": audience,
                },
            )
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
            _write_json_line(
                self.wfile,
                {
                    "ok": True,
                    "type": "provider_registered",
                    "protocol": RELAY_PROTOCOL_VERSION,
                    "peer_id": peer_id,
                    "challenge": challenge,
                    "relay": f"http://{self.server.relay_host}:{self.server.control_port}",
                    "relay_address": f"relay://{self.server.relay_host}:{self.server.control_port}/{peer_id}",
                },
            )
            registration_deadline.cancel()
            self.connection.settimeout(None)
            while True:
                job = session.jobs.get()
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
                peer_id = urllib.parse.unquote(parsed.path.removeprefix("/infer/"))
                body = self._read_json()
                timeout = _coerce_timeout(body.get("timeout"), 180.0)
                secure_frame = body.get("secure_frame")
                if secure_frame is not None:
                    if not isinstance(secure_frame, str):
                        raise RelayError("secure_frame must be base64url text")
                    consumer_public_key = verify_relay_consumer_frame(
                        self.server.state,
                        secure_frame,
                        peer_id=peer_id,
                        admission=body.get("admission"),
                        address_probe=body.get("address_probe") is True,
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
                try:
                    response = relay_infer(self.server.state, peer_id, relay_message, timeout=timeout)
                    self._write(200, response, headers=cors_headers)
                finally:
                    _release_consumer_slot(self.server.state, consumer_public_key)
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
    provider_thread = threading.Thread(target=provider_server.serve_forever, name="mycomesh-relay-provider", daemon=True)
    provider_thread.start()
    try:
        control_server.serve_forever()
    finally:
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
    callback_thread: threading.Thread | None = None
    callback_cleanup_ok = True
    while stop_event is None or not stop_event.is_set():
        callback_thread = None
        callback_cleanup_ok = True
        active_socket: socket.socket | None = None
        retry_after_connection = False
        try:
            raw_socket = socket.create_connection((relay_host, relay_port), timeout=10)
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
        except (OSError, RelayError, json.JSONDecodeError):
            retry_after_connection = not (stop_event is not None and stop_event.is_set())
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
) -> str:
    is_address_probe = address_probe is True
    if (
        not is_address_probe
        and not state.authorized_consumers
        and not state.allow_any_signed_consumer
        and state.v3_admission_config is None
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
    expected_purpose = P2P_ADDRESS_PROBE_PURPOSE if is_address_probe else P2P_SECURE_REQUEST_PURPOSE
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
    public_key = metadata.sender_public_key
    requires_v3_admission = (
        not is_address_probe
        and public_key not in state.authorized_consumers
        and not state.allow_any_signed_consumer
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
        if requires_v3_admission:
            try:
                verify_relay_v3_admission(
                    admission,
                    sender_public_key=public_key,
                    provider_peer=session.peer,
                    config=state.v3_admission_config,
                )
            except ConsumerAdmissionError as exc:
                raise RelayError(f"consumer V3 admission was rejected: {exc}") from exc
            _consumer_rate_limit(state, public_key)
    finally:
        if requires_v3_admission:
            state._v3_admission_slots.release()
    return public_key


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
    )


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
            **({"address_probe": True} if address_probe else {}),
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
    return sign_document(peer, config.identity.private_key, purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE, audience=audience)


def verify_relay_provider_peer(
    peer: dict[str, Any],
    require_signed: bool = True,
    audience: str | None = None,
    expected_challenge: str | None = None,
) -> dict[str, Any]:
    if not require_signed:
        return dict(peer)
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
    return normalized


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
