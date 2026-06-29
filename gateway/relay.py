from __future__ import annotations

import json
import os
import queue
import socket
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
from .identity import IdentityError, peer_id_from_public_key, sign_document, verify_document
from .p2p import INFERENCE_REQUEST_PURPOSE, MAX_MESSAGE_BYTES, P2PError, ProviderConfig, handle_message
from .replay import DEFAULT_REPLAY_DB, ReplayError, ReplayStore


RELAY_PROTOCOL_VERSION = "mycomesh-relay/0.2"
DEFAULT_RELAY_CONTROL_PORT = 9900
DEFAULT_RELAY_PROVIDER_PORT = 9901
DEFAULT_RELAY_URL = f"http://127.0.0.1:{DEFAULT_RELAY_CONTROL_PORT}"
RELAY_PROVIDER_REGISTRATION_PURPOSE = "mycomesh.relay.provider.v1"
DEFAULT_RELAY_RECONNECT_GRACE_SECONDS = 5
DEFAULT_RELAY_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RELAY_RATE_LIMIT_MAX_REQUESTS = 120
DEFAULT_RELAY_CONSUMER_MAX_IN_FLIGHT = 32
DEFAULT_RELAY_PROVIDER_QUEUE_SIZE = 64
DEFAULT_RELAY_SOCKET_TIMEOUT_SECONDS = 10


class RelayError(RuntimeError):
    pass


@dataclass(frozen=True)
class RelayAddress:
    host: str
    port: int
    peer_id: str

    @property
    def value(self) -> str:
        return f"relay://{self.host}:{self.port}/{self.peer_id}"


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


@dataclass
class RelayState:
    providers: dict[str, RelayProviderSession] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.RLock)
    require_signed_providers: bool = True
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
    replay_store_path: str | None = None
    replay_ttl_seconds: int = 600
    _replay_store: ReplayStore | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.replay_store_path:
            self._replay_store = ReplayStore(self.replay_store_path)


class RelayProviderTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: RelayState,
        relay_host: str,
        control_port: int,
    ) -> None:
        super().__init__(server_address, RelayProviderHandler)
        self.state = state
        self.relay_host = relay_host
        self.control_port = control_port


class RelayProviderHandler(socketserver.StreamRequestHandler):
    server: RelayProviderTCPServer

    def handle(self) -> None:
        self.connection.settimeout(float(self.server.state.socket_timeout_seconds))
        session: RelayProviderSession | None = None
        try:
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
                    audience=f"{self.server.relay_host}:{self.server.server_address[1]}",
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
                    "relay": f"http://{self.server.relay_host}:{self.server.control_port}",
                    "relay_address": f"relay://{self.server.relay_host}:{self.server.control_port}/{peer_id}",
                },
            )
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
            if session is not None:
                with self.server.state.lock:
                    if self.server.state.providers.get(session.peer_id) is session:
                        self.server.state.providers.pop(session.peer_id, None)


class RelayControlHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: RelayState,
    ) -> None:
        super().__init__(server_address, RelayControlHandler)
        self.state = state


class RelayControlHandler(BaseHTTPRequestHandler):
    server: RelayControlHTTPServer

    def do_GET(self) -> None:
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
        self.connection.settimeout(float(self.server.state.socket_timeout_seconds))
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path.startswith("/infer/"):
                self._rate_limit()
                peer_id = urllib.parse.unquote(parsed.path.removeprefix("/infer/"))
                body = self._read_json()
                timeout = _coerce_timeout(body.get("timeout"), 180.0)
                message = body.get("message")
                if not isinstance(message, dict):
                    raise RelayError("message must be a JSON object")
                consumer_public_key = verify_relay_consumer_request(self.server.state, message, peer_id=peer_id)
                _reserve_consumer_slot(self.server.state, consumer_public_key)
                try:
                    response = relay_infer(self.server.state, peer_id, message, timeout=timeout)
                    self._write(200, response)
                finally:
                    _release_consumer_slot(self.server.state, consumer_public_key)
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
        with self.server.state.lock:
            recent = [
                timestamp
                for timestamp in self.server.state.rate_limits.get(client, [])
                if now - timestamp < self.server.state.rate_limit_window_seconds
            ]
            if len(recent) >= self.server.state.rate_limit_max_requests:
                raise RelayError("rate limit exceeded")
            recent.append(now)
            self.server.state.rate_limits[client] = recent

    def _read_json(self) -> dict[str, Any]:
        content_length = int(self.headers.get("content-length") or "0")
        if content_length > MAX_MESSAGE_BYTES:
            raise RelayError("request body too large")
        if content_length <= 0:
            return {}
        payload = self.rfile.read(content_length).decode("utf-8")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise RelayError("request body must be a JSON object")
        return value

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def serve_relay(
    host: str,
    control_port: int = DEFAULT_RELAY_CONTROL_PORT,
    provider_port: int = DEFAULT_RELAY_PROVIDER_PORT,
    advertise_host: str | None = None,
    authorized_consumers: set[str] | None = None,
    allow_any_signed_consumer: bool = False,
    replay_store_path: str | None = None,
) -> None:
    state = RelayState(
        authorized_consumers=authorized_consumers or set(),
        allow_any_signed_consumer=allow_any_signed_consumer,
        replay_store_path=replay_store_path,
    )
    relay_host = advertise_host or host
    provider_server = RelayProviderTCPServer((host, provider_port), state, relay_host, control_port)
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


def run_relay_provider(
    relay_host: str,
    relay_port: int,
    config: ProviderConfig,
    on_registered: Callable[[dict[str, Any]], None] | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    while stop_event is None or not stop_event.is_set():
        try:
            with socket.create_connection((relay_host, relay_port), timeout=10) as sock:
                sock.settimeout(None)
                reader = sock.makefile("rb")
                writer = sock.makefile("wb")
                _write_json_line(
                    writer,
                    {
                        "type": "provider_register",
                        "peer": _relay_provider_peer(config, audience=f"{relay_host}:{relay_port}"),
                    },
                )
                registered = _read_json_line(reader)
                if registered.get("ok") is False:
                    raise RelayError(str(registered.get("error") or "relay registration failed"))
                if on_registered is not None:
                    on_registered(registered)
                while stop_event is None or not stop_event.is_set():
                    envelope = _read_json_line(reader)
                    if envelope.get("type") != "relay_job":
                        continue
                    job_id = str(envelope.get("job_id") or "")
                    message = envelope.get("message")
                    if not isinstance(message, dict):
                        response = {"ok": False, "error": "relay job message must be a JSON object"}
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
            if stop_event is not None and stop_event.is_set():
                return
            time.sleep(2)


def relay_infer(
    state: RelayState,
    peer_id: str,
    message: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    with state.lock:
        session = state.providers.get(peer_id)
    if session is None:
        raise RelayError(f"provider {peer_id!r} is not connected")
    job = RelayJob(job_id=uuid.uuid4().hex, message=message, response_queue=queue.Queue(maxsize=1))
    try:
        session.jobs.put_nowait(job)
    except queue.Full as exc:
        raise RelayError(f"provider {peer_id!r} queue is full") from exc
    try:
        envelope = job.response_queue.get(timeout=timeout)
    except queue.Empty as exc:
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
    if state.authorized_consumers and public_key not in state.authorized_consumers:
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


def _consumer_rate_limit(state: RelayState, public_key: str) -> None:
    now = time.time()
    with state.lock:
        recent = [
            timestamp
            for timestamp in state.consumer_rate_limits.get(public_key, [])
            if now - timestamp < state.rate_limit_window_seconds
        ]
        if len(recent) >= state.rate_limit_max_requests:
            raise RelayError("consumer rate limit exceeded")
        recent.append(now)
        state.consumer_rate_limits[public_key] = recent


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
    url = f"http://{address.host}:{address.port}/infer/{urllib.parse.quote(address.peer_id, safe='')}"
    request = urllib.request.Request(
        url,
        data=json.dumps({"message": message, "timeout": timeout}).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout + 5) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise RelayError(f"relay returned HTTP {exc.code}: {payload}") from exc
    except urllib.error.URLError as exc:
        raise RelayError(f"failed to reach relay: {exc}") from exc
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RelayError("relay response must be a JSON object")
    if value.get("ok") is False:
        raise RelayError(str(value.get("error") or "relay request failed"))
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
    if parsed.scheme != "relay":
        raise ValueError("relay address must look like relay://host:port/peer_id")
    if not parsed.hostname:
        raise ValueError("relay host is required")
    if parsed.port is None:
        raise ValueError("relay port is required")
    peer_id = urllib.parse.unquote(parsed.path.lstrip("/"))
    if not peer_id:
        raise ValueError("relay peer id is required")
    return RelayAddress(host=parsed.hostname, port=parsed.port, peer_id=peer_id)


def _relay_provider_peer(config: ProviderConfig, audience: str | None = None) -> dict[str, Any]:
    peer = {
        "peer_id": config.peer_id,
        "protocol": RELAY_PROTOCOL_VERSION,
        "channel": config.channel,
        "agent_id": config.agent_id,
        "model": config.model,
        "last_seen": int(time.time()),
    }
    if config.identity is not None:
        peer["public_key"] = config.identity.public_key
    if config.payment_address:
        peer["payment_address"] = config.payment_address
    return sign_document(peer, config.identity.private_key, purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE, audience=audience)


def verify_relay_provider_peer(peer: dict[str, Any], require_signed: bool = True, audience: str | None = None) -> dict[str, Any]:
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
    normalized = dict(unsigned)
    normalized["public_key"] = public_key
    normalized["signature"] = peer["signature"]
    try:
        payment_address = normalize_payment_address(str(normalized.get("payment_address")) if normalized.get("payment_address") else None)
    except BillingError as exc:
        raise RelayError(str(exc)) from exc
    if payment_address:
        normalized["payment_address"] = payment_address
    return normalized


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
    raw = reader.readline(MAX_MESSAGE_BYTES + 1)
    if not raw:
        raise RelayError("connection closed")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise RelayError("message too large")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RelayError("message must be a JSON object")
    return value


def _coerce_timeout(value: Any, default: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if result > 0 else default
