from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import ipaddress
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .netio import bounded_timeout, is_legacy_ipv4_hostname


MAX_UPSTREAM_TIMEOUT_SECONDS = 300.0
DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_CONFIGURABLE_UPSTREAM_RESPONSE_BYTES = 256 * 1024 * 1024


class UpstreamError(RuntimeError):
    pass


def normalize_upstream_base_url(value: str) -> str:
    raw = str(value)
    if not raw or raw != raw.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in raw
    ):
        raise ValueError("UPSTREAM_BASE_URL must be a non-empty URL without surrounding whitespace")
    if "\\" in raw:
        raise ValueError("UPSTREAM_BASE_URL must not contain backslashes")
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("UPSTREAM_BASE_URL must use http or https")
    if not parsed.hostname:
        raise ValueError("UPSTREAM_BASE_URL must include a hostname")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("UPSTREAM_BASE_URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("UPSTREAM_BASE_URL must not contain a query string or fragment")
    if ";" in parsed.path:
        raise ValueError("UPSTREAM_BASE_URL must not contain path parameters")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("UPSTREAM_BASE_URL has an invalid port") from exc
    hostname = parsed.hostname
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("UPSTREAM_BASE_URL has an invalid hostname") from exc
        labels = host.split(".")
        if (
            not host
            or len(host) > 253
            or is_legacy_ipv4_hostname(host)
            or all(character.isdigit() or character == "." for character in host)
            or any(
                not label
                or len(label) > 63
                or not label[0].isalnum()
                or not label[-1].isalnum()
                or any(not character.isalnum() and character != "-" for character in label)
                for label in labels
            )
        ):
            raise ValueError("UPSTREAM_BASE_URL has an invalid hostname")
    else:
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    authority = host if port is None else f"{host}:{port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((scheme, authority, path, "", ""))


class UpstreamClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        timeout_seconds: float = 180.0,
        max_response_bytes: int = DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES,
        max_stream_bytes: int = DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES,
    ) -> None:
        self.base_url = normalize_upstream_base_url(base_url)
        self.api_key = api_key
        self.total_timeout_seconds = bounded_timeout(
            timeout_seconds,
            maximum=MAX_UPSTREAM_TIMEOUT_SECONDS,
            label="upstream timeout",
        )
        self.timeout = httpx.Timeout(self.total_timeout_seconds)
        self.max_response_bytes = _bounded_byte_limit(
            max_response_bytes,
            label="upstream response limit",
        )
        self.max_stream_bytes = _bounded_byte_limit(
            max_stream_bytes,
            label="upstream stream limit",
        )

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        if extra:
            headers.update(extra)
        return headers

    async def post_json(self, path: str, body: dict[str, Any]) -> httpx.Response:
        return await self._request_bounded(
            "POST",
            f"{self.base_url}{path}",
            headers=self._headers(),
            json=body,
        )

    async def stream_post(self, path: str, body: dict[str, Any]) -> AsyncIterator[bytes]:
        try:
            async with _total_deadline(self.total_timeout_seconds):
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                    async with client.stream(
                        "POST",
                        f"{self.base_url}{path}",
                        headers=self._headers({"accept": "text/event-stream"}),
                        json=body,
                    ) as response:
                        async for chunk in _iter_bounded_response(
                            response,
                            maximum=self.max_stream_bytes,
                            label="upstream stream",
                        ):
                            yield chunk
        except TimeoutError as exc:
            raise UpstreamError("upstream stream exceeded its total deadline") from exc
        except UpstreamError:
            raise
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream stream failed: {exc}") from exc

    async def proxy(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        query: str,
    ) -> httpx.Response:
        filtered_headers = {
            key: value
            for key, value in headers.items()
            if key.lower()
            not in {
                "authorization",
                "content-length",
                "host",
            }
        }
        upstream_headers = self._headers(filtered_headers)
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{query}"

        return await self._request_bounded(
            method,
            url,
            headers=upstream_headers,
            content=body,
        )

    async def _request_bounded(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            async with _total_deadline(self.total_timeout_seconds):
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                    async with client.stream(method, url, **kwargs) as response:
                        content = await _read_bounded_response(
                            response,
                            maximum=self.max_response_bytes,
                            label="upstream response",
                        )
                        return httpx.Response(
                            status_code=response.status_code,
                            headers=response.headers,
                            content=content,
                            request=response.request,
                            extensions=response.extensions,
                        )
        except TimeoutError as exc:
            raise UpstreamError("upstream request exceeded its total deadline") from exc
        except UpstreamError:
            raise
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream request failed: {exc}") from exc


@asynccontextmanager
async def _total_deadline(seconds: float) -> AsyncIterator[None]:
    task = asyncio.current_task()
    if task is None:
        raise RuntimeError("upstream total deadline requires an asyncio task")
    expired = False

    def cancel_for_deadline() -> None:
        nonlocal expired
        expired = True
        task.cancel()

    timer = asyncio.get_running_loop().call_later(seconds, cancel_for_deadline)
    try:
        yield
    except asyncio.CancelledError as exc:
        if expired:
            raise TimeoutError("total deadline exceeded") from exc
        raise
    finally:
        timer.cancel()


async def _read_bounded_response(
    response: httpx.Response,
    *,
    maximum: int,
    label: str,
) -> bytes:
    chunks: list[bytes] = []
    async for chunk in _iter_bounded_response(response, maximum=maximum, label=label):
        chunks.append(chunk)
    return b"".join(chunks)


async def _iter_bounded_response(
    response: httpx.Response,
    *,
    maximum: int,
    label: str,
) -> AsyncIterator[bytes]:
    declared = _response_content_length(response)
    if declared is not None and declared > maximum:
        raise UpstreamError(f"{label} exceeds {maximum} bytes")
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > maximum:
            raise UpstreamError(f"{label} exceeds {maximum} bytes")
        yield chunk


def _response_content_length(response: httpx.Response) -> int | None:
    values = response.headers.get_list("content-length")
    parts = [part.strip() for value in values for part in value.split(",")]
    if not parts:
        return None
    if len(parts) != 1 or not parts[0].isdigit():
        raise UpstreamError("upstream response has an invalid Content-Length")
    return int(parts[0])


def _bounded_byte_limit(value: Any, *, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        resolved = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer") from exc
    if resolved <= 0 or resolved > MAX_CONFIGURABLE_UPSTREAM_RESPONSE_BYTES:
        raise ValueError(
            f"{label} must be between 1 and {MAX_CONFIGURABLE_UPSTREAM_RESPONSE_BYTES} bytes"
        )
    return resolved
