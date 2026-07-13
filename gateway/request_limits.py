from __future__ import annotations

import asyncio
from collections.abc import Callable
import math
from typing import Any

from starlette.responses import JSONResponse


MAX_CONFIGURABLE_REQUEST_BODY_BYTES = 256 * 1024 * 1024
MAX_REQUEST_BODY_TIMEOUT_SECONDS = 300.0


class BoundedRequestBodyMiddleware:
    """Buffer an HTTP request only up to a configured limit before routing it."""

    def __init__(
        self,
        app: Any,
        *,
        limit: int | Callable[[], int],
        timeout_seconds: float | Callable[[], float] = 30.0,
    ) -> None:
        self.app = app
        self.limit = limit
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        try:
            limit = int(self.limit() if callable(self.limit) else self.limit)
        except (TypeError, ValueError):
            await self._reject(scope, receive, send, 503, "request body limit is invalid")
            return
        if limit <= 0 or limit > MAX_CONFIGURABLE_REQUEST_BODY_BYTES:
            await self._reject(scope, receive, send, 503, "request body limit is invalid")
            return
        try:
            timeout_seconds = float(
                self.timeout_seconds() if callable(self.timeout_seconds) else self.timeout_seconds
            )
        except (TypeError, ValueError):
            await self._reject(scope, receive, send, 503, "request body timeout is invalid")
            return
        if (
            not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > MAX_REQUEST_BODY_TIMEOUT_SECONDS
        ):
            await self._reject(scope, receive, send, 503, "request body timeout is invalid")
            return

        content_lengths = [
            value
            for name, value in scope.get("headers", [])
            if bytes(name).lower() == b"content-length"
        ]
        if len(content_lengths) > 1:
            await self._reject(scope, receive, send, 400, "invalid Content-Length")
            return
        if content_lengths:
            try:
                raw_length = bytes(content_lengths[0]).decode("ascii")
            except UnicodeDecodeError:
                raw_length = ""
            if not raw_length.isdigit():
                await self._reject(scope, receive, send, 400, "invalid Content-Length")
                return
            if int(raw_length) > limit:
                await self._reject(scope, receive, send, 413, "request body is too large")
                return

        body = bytearray()
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        try:
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                message = await asyncio.wait_for(receive(), timeout=remaining)
                message_type = message.get("type")
                if message_type == "http.disconnect":
                    return
                if message_type != "http.request":
                    continue
                chunk = message.get("body", b"")
                if len(chunk) > limit - len(body):
                    await self._reject(scope, receive, send, 413, "request body is too large")
                    return
                body.extend(chunk)
                if not message.get("more_body", False):
                    break
        except asyncio.TimeoutError:
            await self._reject(scope, receive, send, 408, "request body deadline exceeded")
            return

        delivered = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(
        scope: dict[str, Any],
        receive: Any,
        send: Any,
        status_code: int,
        detail: str,
    ) -> None:
        await JSONResponse(status_code=status_code, content={"detail": detail})(scope, receive, send)
