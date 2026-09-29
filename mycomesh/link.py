"""Framed JSON over a stream socket, shared by the Relay and Provider link ends.

Frames are newline-delimited canonical JSON with a size bound.  Both ends send
pings; a connection with no inbound frame for IDLE_TIMEOUT is closed, so a
half-open TCP connection can never strand a Provider.
"""
from __future__ import annotations

import json
import socket
import threading
from typing import Any

MAX_FRAME_BYTES = 16 * 1024 * 1024
PING_INTERVAL = 15.0
IDLE_TIMEOUT = 45.0

LINK_PURPOSE = "mycomesh.v11.provider-link"


class LinkClosed(ConnectionError):
    pass


class FramedConnection:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.sock.settimeout(IDLE_TIMEOUT)
        self._reader = sock.makefile("rb")
        self._write_lock = threading.Lock()
        self.closed = threading.Event()

    def send(self, message: dict[str, Any]) -> None:
        data = json.dumps(message, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        if len(data) > MAX_FRAME_BYTES:
            raise ValueError("frame exceeds the link limit")
        with self._write_lock:
            if self.closed.is_set():
                raise LinkClosed("link is closed")
            try:
                self.sock.sendall(data)
            except OSError as exc:
                self.close()
                raise LinkClosed(str(exc)) from exc

    def receive(self) -> dict[str, Any]:
        try:
            line = self._reader.readline(MAX_FRAME_BYTES + 1)
        except (OSError, socket.timeout) as exc:
            self.close()
            raise LinkClosed(f"link read failed: {exc}") from exc
        if not line:
            self.close()
            raise LinkClosed("peer closed the link")
        if len(line) > MAX_FRAME_BYTES:
            self.close()
            raise LinkClosed("frame exceeds the link limit")
        try:
            value = json.loads(line)
        except ValueError as exc:
            self.close()
            raise LinkClosed("invalid frame") from exc
        if not isinstance(value, dict):
            self.close()
            raise LinkClosed("frame is not an object")
        return value

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        for action in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self._reader.close, self.sock.close):
            try:
                action()
            except OSError:
                pass

    def start_pings(self) -> None:
        def loop() -> None:
            while not self.closed.wait(PING_INTERVAL):
                try:
                    self.send({"type": "ping"})
                except (LinkClosed, ValueError):
                    return

        threading.Thread(target=loop, name="mycomesh-link-ping", daemon=True).start()
