"""Provider side of the Relay link: one session per pinned Relay, all at once."""
from __future__ import annotations

import logging
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from ..identity import sign_document
from ..link import LINK_PURPOSE, FramedConnection, LinkClosed, PING_INTERVAL
from .worker import JobRejected, ProviderWorker

log = logging.getLogger("mycomesh.provider")


@dataclass(frozen=True)
class RelayEndpoint:
    host: str
    port: int
    tls: bool = False
    ca_file: str | None = None
    server_hostname: str | None = None
    signer: str | None = None  # expected Relay signer, when known from the manifest or directory
    pin: str | None = None  # SHA-256 of a self-signed certificate announced on-chain; replaces CA checks

    def connect(self, timeout: float = 10.0) -> socket.socket:
        if not self.tls:
            return socket.create_connection((self.host, self.port), timeout=timeout)
        from ..tlspin import connect

        return connect(self.server_hostname or self.host, self.port, pin=self.pin, ca_file=self.ca_file, timeout=timeout)


class ProviderLink(threading.Thread):
    """Keeps one authenticated session to one Relay, reconnecting forever."""

    def __init__(self, worker: ProviderWorker, endpoint: RelayEndpoint, stop: threading.Event) -> None:
        super().__init__(name=f"mycomesh-provider-link-{endpoint.host}:{endpoint.port}", daemon=True)
        self.worker = worker
        self.endpoint = endpoint
        self.stop = stop
        self.connected = threading.Event()
        self.last_error: str | None = None
        self._executor = ThreadPoolExecutor(max_workers=worker.capacity + 2)

    def run(self) -> None:
        backoff = 1.0
        while not self.stop.is_set():
            try:
                self._session()
                backoff = 1.0
            except (LinkClosed, OSError, ValueError, KeyError) as exc:
                self.last_error = str(exc)[:200]
            self.connected.clear()
            if self.stop.wait(backoff):
                break
            backoff = min(backoff * 2, 30.0)

    def _registration(self, nonce: str, audience: str) -> dict[str, Any]:
        return sign_document({"nonce": nonce, "descriptor": self.worker.descriptor()},
                             self.worker.identity.private_key, purpose=LINK_PURPOSE, audience=audience)

    def _session(self) -> None:
        conn = FramedConnection(self.endpoint.connect())
        try:
            challenge = conn.receive()
            deployment = self.worker.deployment
            if (challenge.get("type") != "challenge" or challenge.get("chain_id") != deployment.chain_id
                    or str(challenge.get("settlement")).lower() != deployment.settlement):
                raise ValueError("Relay is bound to a different deployment")
            nonce, relay_signer = str(challenge["nonce"]), str(challenge["relay_signer"])
            if self.endpoint.signer and relay_signer.lower() != self.endpoint.signer.lower():
                raise ValueError("Relay signer differs from the one it announced")
            conn.send({"type": "register", "registration": self._registration(nonce, relay_signer)})
            reply = conn.receive()
            if reply.get("type") != "registered":
                raise ValueError(str(reply.get("error") or "Relay refused the registration"))
            self.connected.set()
            conn.start_pings()
            announced = self.worker.current_transport_key().binding["key_id"]
            watcher = threading.Thread(target=self._watch_key_rotation,
                                       args=(conn, nonce, relay_signer, announced), daemon=True)
            watcher.start()
            while not self.stop.is_set():
                message = conn.receive()
                if message.get("type") == "job":
                    self._executor.submit(self._run_job, conn, message)
                elif message.get("type") == "error":
                    raise ValueError(str(message.get("error")))
        finally:
            conn.close()

    def _watch_key_rotation(self, conn: FramedConnection, nonce: str, relay_signer: str, announced: str) -> None:
        while not conn.closed.wait(PING_INTERVAL):
            current = self.worker.current_transport_key().binding["key_id"]
            if current != announced:
                try:
                    conn.send({"type": "descriptor", "registration": self._registration(nonce, relay_signer)})
                    announced = current
                except (LinkClosed, ValueError):
                    return

    def _run_job(self, conn: FramedConnection, message: dict[str, Any]) -> None:
        job_id = message.get("job_id")
        try:
            emit = lambda data: conn.send({"type": "chunk", "job_id": job_id, "data": data})
            reply = {"type": "result", "job_id": job_id, "ok": True,
                     "result": self.worker.handle_job(message["job"], emit=emit)}
        except JobRejected as exc:
            reply = {"type": "result", "job_id": job_id, "ok": False, "error": str(exc)[:300], "executed": False}
        except Exception as exc:  # outcome unknown once the backend may have run
            log.warning("job failed: %s: %s", type(exc).__name__, str(exc)[:200])
            reply = {"type": "result", "job_id": job_id, "ok": False, "error": "backend failed", "executed": None}
        try:
            conn.send(reply)
        except (LinkClosed, ValueError):
            pass


def run_provider(worker: ProviderWorker, endpoints: list[RelayEndpoint], stop: threading.Event) -> list[ProviderLink]:
    """Serve every pinned Relay concurrently (multi-home)."""
    links = [ProviderLink(worker, endpoint, stop) for endpoint in endpoints]
    for link in links:
        link.start()
    return links
