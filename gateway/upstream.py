from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx


class UpstreamClient:
    def __init__(self, base_url: str, api_key: str | None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        if extra:
            headers.update(extra)
        return headers

    async def post_json(self, path: str, body: dict[str, Any]) -> httpx.Response:
        async with httpx.AsyncClient(timeout=None) as client:
            return await client.post(
                f"{self.base_url}{path}",
                headers=self._headers(),
                json=body,
            )

    async def stream_post(self, path: str, body: dict[str, Any]) -> AsyncIterator[bytes]:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}{path}",
                headers=self._headers({"accept": "text/event-stream"}),
                json=body,
            ) as response:
                async for chunk in response.aiter_bytes():
                    yield chunk

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

        async with httpx.AsyncClient(timeout=None) as client:
            return await client.request(
                method,
                url,
                headers=upstream_headers,
                content=body,
            )
