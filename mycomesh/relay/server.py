"""Relay network servers: Consumer HTTP API, Provider link server, settlement worker."""
from __future__ import annotations

import json
import logging
import secrets
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..identity import IdentityError, verify_document
from ..link import LINK_PURPOSE, FramedConnection, LinkClosed
from .core import RelayCore, RelayError
from .disputes import DisputeDesk
from .probes import ProbeRunner, probe_loop

MAX_HTTP_BODY = 16 * 1024 * 1024
JOB_TIMEOUT = 330.0
log = logging.getLogger("mycomesh.relay")


class ProviderRejected(RuntimeError):
    def __init__(self, message: str, executed: Any) -> None:
        super().__init__(message)
        self.executed = executed


class ProviderConnection:
    """One authenticated Provider link; jobs are matched to results by id."""

    def __init__(self, conn: FramedConnection) -> None:
        self.conn = conn
        self._pending: dict[str, tuple[threading.Event, list[dict[str, Any]], Any]] = {}
        self._lock = threading.Lock()

    def request(self, job: dict[str, Any], on_chunk: Any = None) -> dict[str, Any]:
        job_id = secrets.token_hex(16)
        done = threading.Event()
        slot: list[dict[str, Any]] = []
        with self._lock:
            self._pending[job_id] = (done, slot, on_chunk)
        try:
            self.conn.send({"type": "job", "job_id": job_id, "job": job})
            if not done.wait(JOB_TIMEOUT) or not slot:
                raise ProviderRejected("Provider did not answer in time", None)
        finally:
            with self._lock:
                self._pending.pop(job_id, None)
        message = slot[0]
        if message.get("ok") is not True:
            raise ProviderRejected(str(message.get("error") or "Provider rejected the job"), message.get("executed"))
        return message["result"]

    def resolve(self, message: dict[str, Any]) -> None:
        with self._lock:
            entry = self._pending.get(str(message.get("job_id")))
        if entry is not None:
            entry[1].append(message)
            entry[0].set()

    def chunk(self, message: dict[str, Any]) -> None:
        with self._lock:
            entry = self._pending.get(str(message.get("job_id")))
        if entry is not None and entry[2] is not None and isinstance(message.get("data"), str):
            try:
                entry[2](message["data"])
            except Exception:  # the Consumer went away; the job still completes and settles
                pass

    def fail_all(self) -> None:
        with self._lock:
            entries = list(self._pending.values())
        for done, _, _ in entries:
            done.set()


@dataclass
class RelayServer:
    core: RelayCore
    http_address: tuple[str, int]
    link_address: tuple[str, int]
    submitter_private: str
    rpc_url: str
    dispute_window: int
    settle_interval: float = 600.0
    settle_count: int = 32
    link_tls: ssl.SSLContext | None = None
    desk: DisputeDesk | None = None
    probes: ProbeRunner | None = None
    probe_interval: float = 3_600.0
    faucet: Any = None  # mycomesh.relay.faucet.Faucet on testnets
    dispute_interval: float = 15.0
    _threads: list[threading.Thread] = field(default_factory=list, init=False, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _servers: list[Any] = field(default_factory=list, init=False, repr=False)
    _links: set[FramedConnection] = field(default_factory=set, init=False, repr=False)
    worker_state: dict[str, Any] = field(default_factory=dict, init=False)

    def start(self) -> None:
        http = ThreadingHTTPServer(self.http_address, _http_handler(self))
        http.daemon_threads = True
        link = _LinkServer(self.link_address, self)
        self._servers = [http, link]
        self.http_address = http.server_address[:2]
        self.link_address = link.server_address[:2]
        loops = [(http.serve_forever, "relay-http"), (link.serve_forever, "relay-link"),
                 (self._settlement_loop, "relay-settlement")]
        if self.desk is not None:
            loops.append((self._dispute_loop, "relay-disputes"))
        if self.probes is not None:
            loops.append((lambda: probe_loop(self.probes, self._stop, mean_interval=self.probe_interval), "relay-probes"))
        for target, name in loops:
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for server in self._servers:
            server.shutdown()
            server.server_close()
        # Stopping the listener leaves accepted links open; close them so every
        # Provider sees the restart and reconnects.
        for conn in list(self._links):
            conn.close()

    def health(self) -> dict[str, Any]:
        return {
            "ok": True, "protocol": 11, "relay_signer": self.core.signer,
            "chain_id": self.core.deployment.chain_id, "settlement": self.core.deployment.settlement,
            "providers": len(self.core.providers), "queue": self.core.queue.counts(),
            "settlement_worker": dict(self.worker_state), "suspended": len(self.core.suspended),
            "disputes": len(self.desk.open_cases()) if self.desk is not None else None,
            "faucet": self.faucet is not None,
        }

    def _dispute_loop(self) -> None:
        while not self._stop.wait(self.dispute_interval):
            try:
                for key, action in self.desk.cycle():
                    log.info("dispute %s: %s", key, action)
            except Exception as exc:
                log.warning("dispute desk cycle failed: %s", exc)

    def _settlement_loop(self) -> None:
        last_release = 0.0
        while not self._stop.wait(5.0):
            try:
                counts = self.core.queue.counts()
                oldest = self.core.queue.oldest_queued_age()
                if counts.get("queued", 0) >= self.settle_count or (oldest is not None and oldest >= self.settle_interval):
                    settled = self.core.settle_queued(self.submitter_private, self.rpc_url)
                    self.worker_state.update(last_settled=len(settled), last_settle_at=int(time.time()))
                if time.monotonic() - last_release >= 60.0:
                    released = self.core.release_due(self.submitter_private, self.rpc_url, self.dispute_window)
                    self.worker_state.update(last_released=len(released))
                    last_release = time.monotonic()
                self.worker_state.pop("error", None)
            except Exception as exc:  # the loop must keep running; surface the reason in /health
                self.worker_state["error"] = type(exc).__name__
                log.warning("settlement worker cycle failed: %s", exc)

    def handle_link(self, sock: socket.socket) -> None:
        conn = FramedConnection(sock)
        self._links.add(conn)
        nonce = secrets.token_hex(16)
        signer = None
        provider: ProviderConnection | None = None
        try:
            conn.send({"type": "challenge", "nonce": nonce, "relay_signer": self.core.signer,
                       "chain_id": self.core.deployment.chain_id, "settlement": self.core.deployment.settlement})
            provider = ProviderConnection(conn)
            signer = self._register(conn, provider, conn.receive(), nonce)
            conn.send({"type": "registered", "provider_signer": signer})
            conn.start_pings()
            while True:
                message = conn.receive()
                kind = message.get("type")
                if kind == "result":
                    provider.resolve(message)
                elif kind == "chunk":
                    provider.chunk(message)
                elif kind == "descriptor":
                    signer = self._register(conn, provider, message, nonce)
        except (LinkClosed, RelayError, IdentityError, ValueError, KeyError) as exc:
            if not conn.closed.is_set():
                try:
                    conn.send({"type": "error", "error": str(exc)[:300]})
                except (LinkClosed, ValueError):
                    pass
        finally:
            conn.close()
            self._links.discard(conn)
            if provider is not None:
                provider.fail_all()
            if signer is not None:
                with self.core._lock:
                    session = self.core.providers.get(signer)
                    if session is not None and getattr(session.send, "__self__", None) is provider:
                        self.core.unregister_provider(signer)

    def _register(self, conn: FramedConnection, provider: ProviderConnection, message: dict[str, Any], nonce: str) -> str:
        if message.get("type") not in {"register", "descriptor"}:
            raise RelayError("expected a Provider registration")
        signed = message.get("registration")
        if not isinstance(signed, dict):
            raise RelayError("registration must be a signed document")
        document = verify_document(signed, purpose=LINK_PURPOSE, audience=self.core.signer)
        descriptor = document.get("descriptor")
        if document.get("nonce") != nonce or not isinstance(descriptor, dict):
            raise RelayError("registration does not answer this challenge")
        if signed["signature"].get("public_key") != descriptor.get("identity_public_key"):
            raise RelayError("registration is not signed by the Provider identity")
        return self.core.register_provider(descriptor, provider.request)


class _LinkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], relay: RelayServer) -> None:
        self.relay = relay
        super().__init__(address, _LinkHandler)


class _LinkHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        relay: RelayServer = self.server.relay  # type: ignore[attr-defined]
        sock = self.request
        if relay.link_tls is not None:
            try:
                sock = relay.link_tls.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, OSError):
                return
        relay.handle_link(sock)


def _http_handler(relay: RelayServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "mycomesh-relay/11"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            log.debug("%s %s", self.address_string(), format % args)

        def _write(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _stream(self, prepared: Any) -> None:
            """Admission passed: stream sealed deltas as NDJSON, then the final result or error."""
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            lock = threading.Lock()
            alive = [True]

            def line(value: dict[str, Any]) -> None:
                data = json.dumps(value, separators=(",", ":")).encode() + b"\n"
                with lock:
                    if not alive[0]:
                        return
                    try:
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                        self.wfile.flush()
                    except OSError:
                        alive[0] = False

            try:
                line({"type": "result", **relay.core.dispatch(prepared, on_chunk=lambda data: line({"type": "delta", "sealed": data}))})
            except RelayError as exc:
                line({"type": "error", "error": str(exc), "status": exc.status, "dispatched": exc.dispatched})
            with lock:
                if alive[0]:
                    try:
                        self.wfile.write(b"0\r\n\r\n")
                    except OSError:
                        pass

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._write(200, relay.health())
            elif self.path == "/providers":
                self._write(200, {"providers": relay.core.provider_descriptors()})
            elif self.path.startswith("/v11/evidence/") and relay.desk is not None:
                evidence = relay.desk.evidence(self.path.rsplit("/", 1)[1])
                self._write(200, evidence) if evidence is not None else self._write(404, {"error": "unknown evidence"})
            else:
                self._write(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            routes = {"/v11/requests": relay.core.handle_request}
            if relay.desk is not None:
                routes["/v11/evidence"] = relay.desk.submit_evidence
            if relay.faucet is not None:
                client = self.headers.get("X-Real-IP") or self.client_address[0]
                routes["/v11/faucet"] = lambda payload: relay.faucet.grant(payload, client)
            if self.path not in routes:
                self._write(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if not 0 < length <= MAX_HTTP_BODY:
                    raise RelayError("request body size is invalid", 413)
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise RelayError("request body must be an object")
                if self.path == "/v11/requests" and "application/x-ndjson" in (self.headers.get("Accept") or ""):
                    self._stream(relay.core.prepare(payload))
                    return
                self._write(200, routes[self.path](payload))
            except RelayError as exc:
                self._write(exc.status, {"error": str(exc), "dispatched": exc.dispatched})
            except ValueError:
                self._write(400, {"error": "invalid JSON", "dispatched": False})

    return Handler
