from __future__ import annotations

import socket
import threading
from typing import Any

from starlette.responses import JSONResponse


DEFAULT_GATEWAY_MAX_CONCURRENT_REQUESTS = 128
MAX_SERVER_CONNECTIONS = 4096
DEFAULT_UVICORN_KEEP_ALIVE_SECONDS = 5
DEFAULT_UVICORN_H11_MAX_INCOMPLETE_EVENT_BYTES = 64 * 1024
MAX_UVICORN_KEEP_ALIVE_SECONDS = 300
MAX_UVICORN_H11_MAX_INCOMPLETE_EVENT_BYTES = 1024 * 1024


def bounded_connection_count(
    value: Any,
    *,
    label: str,
    maximum: int = MAX_SERVER_CONNECTIONS,
) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        resolved = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer") from exc
    if resolved < 1 or resolved > maximum:
        raise ValueError(f"{label} must be between 1 and {maximum}")
    return resolved


def uvicorn_limit_args(*, env_prefix: str, default_concurrency: int) -> list[str]:
    import os

    prefix = str(env_prefix or "").strip().upper()
    if not prefix or not prefix.replace("_", "").isalnum():
        raise ValueError("uvicorn environment prefix is invalid")
    concurrency = bounded_connection_count(
        os.getenv(f"{prefix}_UVICORN_LIMIT_CONCURRENCY", str(default_concurrency)),
        label=f"{prefix} Uvicorn concurrency",
    )
    keep_alive = _bounded_int(
        os.getenv(
            f"{prefix}_UVICORN_KEEP_ALIVE_SECONDS",
            str(DEFAULT_UVICORN_KEEP_ALIVE_SECONDS),
        ),
        label=f"{prefix} Uvicorn keep-alive seconds",
        minimum=1,
        maximum=MAX_UVICORN_KEEP_ALIVE_SECONDS,
    )
    incomplete_event_bytes = _bounded_int(
        os.getenv(
            f"{prefix}_UVICORN_H11_MAX_INCOMPLETE_EVENT_BYTES",
            str(DEFAULT_UVICORN_H11_MAX_INCOMPLETE_EVENT_BYTES),
        ),
        label=f"{prefix} Uvicorn h11 incomplete event bytes",
        minimum=1024,
        maximum=MAX_UVICORN_H11_MAX_INCOMPLETE_EVENT_BYTES,
    )
    return [
        "--limit-concurrency",
        str(concurrency),
        "--timeout-keep-alive",
        str(keep_alive),
        "--h11-max-incomplete-event-size",
        str(incomplete_event_bytes),
    ]


def _bounded_int(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        resolved = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer") from exc
    if resolved < minimum or resolved > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return resolved


class BoundedThreadingMixIn:
    _connection_slots: threading.BoundedSemaphore

    def configure_connection_limit(self, maximum: int) -> None:
        self._connection_slots = threading.BoundedSemaphore(maximum)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            close_socket(request)
            return
        try:
            super().process_request(request, client_address)  # type: ignore[misc]
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)  # type: ignore[misc]
        finally:
            self._connection_slots.release()


class BoundedASGIConcurrencyMiddleware:
    def __init__(self, app: Any, *, maximum: int) -> None:
        self.app = app
        self.maximum = bounded_connection_count(
            maximum,
            label="gateway max concurrent requests",
        )
        self._request_slots = threading.BoundedSemaphore(self.maximum)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        if not self._request_slots.acquire(blocking=False):
            await JSONResponse(
                status_code=503,
                content={"detail": "gateway request concurrency limit reached"},
                headers={"Retry-After": "1"},
            )(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            self._request_slots.release()


def arm_socket_deadline(connection: socket.socket, seconds: float) -> threading.Timer:
    timer = threading.Timer(seconds, close_socket, args=(connection,))
    timer.daemon = True
    timer.start()
    return timer


def close_socket(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass
