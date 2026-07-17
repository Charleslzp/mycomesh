from __future__ import annotations

import io
import asyncio
import json
import time
import unittest
import urllib.error
from unittest.mock import patch

import httpx

from gateway.chain import MAX_RPC_LOG_RESPONSE_BYTES, MAX_RPC_RESPONSE_BYTES, ChainError, rpc_call
from gateway.client import MAX_CLIENT_POOL_RESPONSE_BYTES, MAX_HEALTH_RESPONSE_BYTES, _pool_post_json, fetch_health
from gateway.netio import NetworkIOError, read_bounded
from gateway.pool import MAX_POOL_RESPONSE_BYTES, PoolConfig, PoolError, _get_json
from gateway.p2p import (
    MAX_GATEWAY_RESPONSE_BYTES,
    MAX_P2P_NETWORK_TIMEOUT_SECONDS,
    P2PError,
    call_gateway,
)
from gateway.relay import (
    MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
    MAX_RELAY_RESPONSE_BYTES,
    RelayError,
    RelayState,
    _coerce_timeout,
    parse_relay_address,
    relay_infer,
    send_relay_message,
)

from gateway.upstream import (
    MAX_CONFIGURABLE_UPSTREAM_RESPONSE_BYTES,
    MAX_UPSTREAM_TIMEOUT_SECONDS,
    UpstreamClient,
    UpstreamError,
    _read_bounded_response,
    normalize_upstream_base_url,
)


class FakeResponse:
    def __init__(self, payload: bytes = b"", *, content_length: int | None = None, status: int = 200) -> None:
        self.payload = payload
        self.headers = {} if content_length is None else {"Content-Length": str(content_length)}
        self.status = status
        self.read_sizes: list[int] = []

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.payload if size < 0 else self.payload[:size]


class BoundedNetworkIOTest(unittest.TestCase):
    def test_reader_checks_unknown_length_with_max_plus_one(self) -> None:
        response = FakeResponse(b"12345")

        with self.assertRaisesRegex(NetworkIOError, "exceeds 4 bytes"):
            read_bounded(response, maximum=4, label="test response")

        self.assertEqual(response.read_sizes, [5])

    def test_reader_enforces_one_deadline_across_streamed_chunks(self) -> None:
        class SlowChunkedResponse:
            headers: dict[str, str] = {}

            def read1(self, _size: int) -> bytes:
                time.sleep(0.01)
                return b"x"

        with self.assertRaisesRegex(NetworkIOError, "deadline exceeded"):
            read_bounded(
                SlowChunkedResponse(),
                maximum=1024,
                label="slow response",
                deadline=time.monotonic() + 0.001,
            )

    def test_rpc_rejects_declared_oversize_without_reading(self) -> None:
        response = FakeResponse(content_length=MAX_RPC_LOG_RESPONSE_BYTES + 1)

        with patch("gateway.chain.urllib.request.urlopen", return_value=response), self.assertRaisesRegex(
            ChainError, "RPC response exceeds"
        ):
            rpc_call("https://rpc.example", "eth_getLogs", [], timeout=20)

        self.assertEqual(response.read_sizes, [])

    def test_rpc_reserves_the_larger_limit_for_get_logs(self) -> None:
        ordinary = FakeResponse(content_length=MAX_RPC_RESPONSE_BYTES + 1)
        with patch("gateway.chain.urllib.request.urlopen", return_value=ordinary), self.assertRaises(ChainError):
            rpc_call("https://rpc.example", "eth_chainId", [], timeout=20)

        log_response = FakeResponse(b'{"jsonrpc":"2.0","id":1,"result":[]}', content_length=MAX_RPC_RESPONSE_BYTES + 1)
        with patch("gateway.chain.urllib.request.urlopen", return_value=log_response):
            self.assertEqual(rpc_call("https://rpc.example", "eth_getLogs", [], timeout=20), [])

    def test_rpc_timeout_must_be_finite_and_bounded(self) -> None:
        for timeout in (float("nan"), float("inf"), 301.0):
            with self.subTest(timeout=timeout), self.assertRaises(ChainError), patch(
                "gateway.chain.urllib.request.urlopen"
            ) as urlopen:
                rpc_call("https://rpc.example", "eth_chainId", [], timeout=timeout)
            urlopen.assert_not_called()

        invalid_shape = FakeResponse(b"[]")
        with patch("gateway.chain.urllib.request.urlopen", return_value=invalid_shape), self.assertRaisesRegex(
            ChainError, "non-object"
        ):
            rpc_call("https://rpc.example", "eth_chainId", [], timeout=20)

    def test_rpc_fails_over_and_cools_down_rate_limited_endpoints(self) -> None:
        limited = urllib.error.HTTPError(
            "https://primary.example",
            429,
            "rate limited",
            {},
            io.BytesIO(b""),
        )
        success = FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0xaa36a7"}).encode())
        with patch.dict("gateway.chain._RPC_ENDPOINT_COOLDOWNS", {}, clear=True), patch(
            "gateway.chain.urllib.request.urlopen",
            side_effect=[limited, success, success],
        ) as urlopen:
            endpoints = "https://primary.example,https://secondary.example"
            self.assertEqual(rpc_call(endpoints, "eth_chainId", [], timeout=20), "0xaa36a7")
            self.assertEqual(rpc_call(endpoints, "eth_chainId", [], timeout=20), "0xaa36a7")

        self.assertEqual(urlopen.call_args_list[0].args[0].full_url, "https://primary.example")
        self.assertEqual(urlopen.call_args_list[1].args[0].full_url, "https://secondary.example")
        self.assertEqual(urlopen.call_args_list[2].args[0].full_url, "https://secondary.example")

    def test_rpc_does_not_hide_semantic_json_rpc_errors_with_fallback(self) -> None:
        response = FakeResponse(
            json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}).encode()
        )
        with patch.dict("gateway.chain._RPC_ENDPOINT_COOLDOWNS", {}, clear=True), patch(
            "gateway.chain.urllib.request.urlopen",
            return_value=response,
        ) as urlopen, self.assertRaisesRegex(ChainError, "execution reverted"):
            rpc_call(
                "https://primary.example,https://secondary.example",
                "eth_call",
                [],
                timeout=20,
            )
        self.assertEqual(urlopen.call_count, 1)

    def test_pool_success_and_http_error_bodies_are_bounded(self) -> None:
        response = FakeResponse(content_length=MAX_POOL_RESPONSE_BYTES + 1)
        with patch("gateway.pool._POOL_NO_REDIRECT_OPENER.open", return_value=response), self.assertRaisesRegex(
            PoolError, "pool response exceeds"
        ):
            _get_json("https://pool.example/peers", timeout=5)

        with self.assertRaisesRegex(PoolError, "read timeout"):
            PoolConfig(http_read_timeout_seconds=float("inf"))

        error = urllib.error.HTTPError(
            "https://pool.example/peers",
            500,
            "failure",
            {"Content-Length": str(MAX_POOL_RESPONSE_BYTES + 1)},
            io.BytesIO(b""),
        )
        with patch("gateway.pool._POOL_NO_REDIRECT_OPENER.open", side_effect=error), self.assertRaisesRegex(
            PoolError, "pool error response exceeds"
        ):
            _get_json("https://pool.example/peers", timeout=5)

    def test_relay_timeout_is_rejected_before_a_slot_can_wait(self) -> None:
        for timeout in (float("nan"), float("inf"), MAX_RELAY_INFERENCE_TIMEOUT_SECONDS + 1):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(RelayError, "timeout"):
                _coerce_timeout(timeout, 180.0)
            with self.subTest(timeout=timeout), self.assertRaisesRegex(RelayError, "timeout"):
                relay_infer(RelayState(), "missing", {}, timeout=timeout)

        with patch("gateway.relay.urllib.request.urlopen") as urlopen, self.assertRaisesRegex(RelayError, "timeout"):
            send_relay_message(parse_relay_address("relay://127.0.0.1:9900/peer"), {}, timeout=float("inf"))
        urlopen.assert_not_called()

        with self.assertRaisesRegex(RelayError, "socket timeout"):
            RelayState(socket_timeout_seconds=float("inf"))

    def test_relay_response_is_bounded(self) -> None:
        response = FakeResponse(content_length=MAX_RELAY_RESPONSE_BYTES + 1)
        with patch("gateway.relay._RELAY_HTTP_OPENER.open", return_value=response), self.assertRaisesRegex(
            RelayError, "relay response exceeds"
        ):
            send_relay_message(parse_relay_address("relay://127.0.0.1:9900/peer"), {}, timeout=5)

    def test_client_health_and_pool_error_responses_are_bounded(self) -> None:
        health = FakeResponse(content_length=MAX_HEALTH_RESPONSE_BYTES + 1)
        with patch("gateway.client._HEALTH_OPENER.open", return_value=health), self.assertRaisesRegex(
            urllib.error.URLError, "health response exceeds"
        ):
            fetch_health("https://gateway.example/health", timeout=5)

        error = urllib.error.HTTPError(
            "https://pool.example/leave",
            500,
            "failure",
            {"Content-Length": str(MAX_CLIENT_POOL_RESPONSE_BYTES + 1)},
            io.BytesIO(b""),
        )
        with patch("gateway.client._HEALTH_OPENER.open", side_effect=error), self.assertRaisesRegex(
            PoolError, "pool error response exceeds"
        ):
            _pool_post_json("https://pool.example", "/leave", {}, timeout=5)

    def test_upstream_timeout_is_finite_and_bounded(self) -> None:
        for timeout in (float("nan"), float("inf"), MAX_UPSTREAM_TIMEOUT_SECONDS + 1):
            with self.subTest(timeout=timeout), self.assertRaises(NetworkIOError):
                UpstreamClient("https://upstream.example", None, timeout_seconds=timeout)

    def test_upstream_timeout_is_a_total_wall_clock_deadline(self) -> None:
        class SlowClient:
            async def __aenter__(self) -> SlowClient:
                await asyncio.sleep(0.05)
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

        async def request() -> None:
            client = UpstreamClient("https://upstream.example", None, timeout_seconds=0.001)
            with patch("gateway.upstream.httpx.AsyncClient", return_value=SlowClient()):
                with self.assertRaisesRegex(UpstreamError, "total deadline"):
                    await client.post_json("/responses", {"input": "hello"})

        asyncio.run(request())

    def test_upstream_rejects_legacy_numeric_ipv4_hostnames(self) -> None:
        for value in (
            "https://0x7f.0.0.1/v1",
            "https://0x7f.1/v1",
            "https://0177.0.0x0.1/v1",
            "https://2130706433/v1",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "invalid hostname"):
                normalize_upstream_base_url(value)

    def test_upstream_decoded_response_and_configured_limit_are_bounded(self) -> None:
        async def read_oversized() -> None:
            response = httpx.Response(200, content=b"12345")
            with self.assertRaisesRegex(UpstreamError, "exceeds 4 bytes"):
                await _read_bounded_response(response, maximum=4, label="upstream response")

        asyncio.run(read_oversized())
        with self.assertRaisesRegex(ValueError, "must be between"):
            UpstreamClient(
                "https://upstream.example",
                None,
                max_response_bytes=MAX_CONFIGURABLE_UPSTREAM_RESPONSE_BYTES + 1,
            )

    def test_provider_gateway_response_and_timeout_are_bounded(self) -> None:
        response = FakeResponse(content_length=MAX_GATEWAY_RESPONSE_BYTES + 1)
        with patch("gateway.p2p._GATEWAY_OPENER.open", return_value=response), self.assertRaisesRegex(
            P2PError, "gateway response exceeds"
        ):
            call_gateway(
                "http://127.0.0.1:8000/v1",
                "agent-key",
                "responses",
                {"model": "test", "input": "hello"},
                timeout=5,
            )
        self.assertEqual(response.read_sizes, [])

        with patch("gateway.p2p._GATEWAY_OPENER.open") as opener, self.assertRaisesRegex(
            P2PError, "must not exceed"
        ):
            call_gateway(
                "http://127.0.0.1:8000/v1",
                "agent-key",
                "responses",
                {"model": "test", "input": "hello"},
                timeout=MAX_P2P_NETWORK_TIMEOUT_SECONDS + 1,
            )
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
