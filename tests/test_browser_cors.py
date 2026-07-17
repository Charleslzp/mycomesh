from __future__ import annotations

from email.message import Message
import importlib
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from gateway.browser_cors import CorsConfigurationError, parse_allowed_origins
from gateway.pool import NETWORK_PROFILE_LOCAL, PoolConfig, PoolRequestHandler


class BrowserOriginParsingTest(unittest.TestCase):
    def test_origins_are_canonical_exact_and_deduplicated(self) -> None:
        self.assertEqual(
            parse_allowed_origins(
                " HTTPS://APP.MycoMesh.xyz:443, http://127.0.0.1:3000,https://app.mycomesh.xyz ",
                setting="TEST_ORIGINS",
            ),
            ("https://app.mycomesh.xyz", "http://127.0.0.1:3000"),
        )
        self.assertEqual(
            parse_allowed_origins("http://[::1]:5173", setting="TEST_ORIGINS"),
            ("http://[::1]:5173",),
        )

    def test_unsafe_or_ambiguous_origins_fail_closed(self) -> None:
        rejected = (
            "*",
            "null",
            "http://app.mycomesh.xyz",
            "https://app.mycomesh.xyz/path",
            "https://user:secret@app.mycomesh.xyz",
            "https://app.mycomesh.xyz?redirect=evil",
            "https://127.1",
            "https://app.mycomesh.xyz,",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(CorsConfigurationError):
                parse_allowed_origins(value, setting="TEST_ORIGINS")


class ProxyCorsTest(unittest.TestCase):
    def test_proxy_allows_only_configured_origin_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), "https://app.mycomesh.xyz")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="https://api.testnet.mycomesh.xyz")

                allowed = client.options(
                    "/account",
                    headers={
                        "Origin": "https://app.mycomesh.xyz",
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "authorization",
                    },
                )
                post = client.options(
                    "/v1/mycomesh/keys/challenge",
                    headers={
                        "Origin": "https://app.mycomesh.xyz",
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "content-type",
                    },
                )
                delete = client.options(
                    "/v1/mycomesh/keys/current",
                    headers={
                        "Origin": "https://app.mycomesh.xyz",
                        "Access-Control-Request-Method": "DELETE",
                        "Access-Control-Request-Headers": "authorization",
                    },
                )
                actual = client.get("/health", headers={"Origin": "https://app.mycomesh.xyz"})
                denied = client.options(
                    "/account",
                    headers={
                        "Origin": "https://evil.example",
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "authorization",
                    },
                )

        for response in (allowed, post, delete, actual):
            self.assertEqual(response.headers["access-control-allow-origin"], "https://app.mycomesh.xyz")
            self.assertIn("Origin", response.headers["vary"])
            self.assertNotIn("access-control-allow-credentials", response.headers)
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("GET", allowed.headers["access-control-allow-methods"])
        self.assertIn("authorization", allowed.headers["access-control-allow-headers"].lower())
        self.assertEqual(post.status_code, 200)
        self.assertIn("POST", post.headers["access-control-allow-methods"])
        self.assertEqual(delete.status_code, 200)
        self.assertIn("DELETE", delete.headers["access-control-allow-methods"])
        self.assertEqual(actual.status_code, 200)
        self.assertEqual(denied.status_code, 400)
        self.assertNotIn("access-control-allow-origin", denied.headers)
        self.assertIn("Origin", denied.headers["vary"])

    def test_invalid_proxy_origin_configuration_stops_module_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            valid_env = self._env(Path(tmp), "https://app.mycomesh.xyz")
            module = importlib.import_module("gateway.mycomesh")
            with patch.dict(
                os.environ,
                {**valid_env, "MYCOMESH_CORS_ALLOWED_ORIGINS": "http://app.mycomesh.xyz"},
                clear=True,
            ):
                with self.assertRaises(CorsConfigurationError):
                    importlib.reload(module)
            with patch.dict(os.environ, valid_env, clear=True):
                importlib.reload(module)

    @staticmethod
    def _env(tmp: Path, origins: str) -> dict[str, str]:
        return {
            "MYCOMESH_ADMIN_TOKEN": "test-admin-token-32-bytes-minimum-secret",
            "MYCOMESH_BILLING_DB": str(tmp / "billing.sqlite3"),
            "MYCOMESH_GATEWAY_REGISTRY_DB": str(tmp / "gateways.sqlite3"),
            "MYCOMESH_REQUEST_IDENTITY": str(tmp / "request-identity.json"),
            "MYCOMESH_BILLING_MODE": "local",
            "MYCOMESH_NETWORK_PROFILE": "local",
            "MYCOMESH_NETWORK_ID": "mycomesh-local-test",
            "MYCOMESH_PUBLIC_GATEWAY_URL": "https://api.testnet.mycomesh.xyz/v1",
            "MYCOMESH_CORS_ALLOWED_ORIGINS": origins,
            "ETH_RPC_URL": "",
            "ETH_CHAIN_ID": "11155111",
            "MYCO_SETTLEMENT": "0x0000000000000000000000000000000000000002",
        }


class PoolCorsTest(unittest.TestCase):
    def test_bridge_get_and_preflight_use_exact_origin(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            cors_allowed_origins=("https://app.mycomesh.xyz",),
        )
        handler = self._handler(
            config,
            origin="https://app.mycomesh.xyz",
            method="GET",
        )
        self.assertEqual(
            handler._browser_cors_headers(),
            {
                "Vary": "Origin",
                "Access-Control-Allow-Origin": "https://app.mycomesh.xyz",
            },
        )
        handler._write_empty = Mock()

        handler.do_OPTIONS()

        handler._write_empty.assert_called_once()
        status = handler._write_empty.call_args.args[0]
        headers = handler._write_empty.call_args.kwargs["headers"]
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "https://app.mycomesh.xyz")
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, OPTIONS")
        self.assertEqual(headers["Vary"], "Origin")
        self.assertNotIn("Access-Control-Allow-Credentials", headers)
        self.assertNotIn("Access-Control-Allow-Headers", headers)

    def test_bridge_rejects_cross_origin_write_and_custom_headers(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            cors_allowed_origins=("https://app.mycomesh.xyz",),
        )
        for method, request_headers, expected_status in (
            ("POST", "", 405),
            ("GET", "authorization", 400),
        ):
            with self.subTest(method=method, request_headers=request_headers):
                handler = self._handler(
                    config,
                    origin="https://app.mycomesh.xyz",
                    method=method,
                    request_headers=request_headers,
                )
                handler._write = Mock()
                handler.do_OPTIONS()
                self.assertEqual(handler._write.call_args.args[0], expected_status)

    def test_bridge_omits_allow_origin_for_unlisted_origin(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            cors_allowed_origins=("https://app.mycomesh.xyz",),
        )
        handler = self._handler(config, origin="https://evil.example", method="GET")
        self.assertEqual(handler._browser_cors_headers(), {"Vary": "Origin"})
        handler._write = Mock()
        handler.do_OPTIONS()
        self.assertEqual(handler._write.call_args.args[0], 403)
        self.assertNotIn("Access-Control-Allow-Origin", handler._write.call_args.kwargs["headers"])

    def test_invalid_bridge_origin_configuration_stops_config_load(self) -> None:
        with patch.dict(
            os.environ,
            {"MYCOMESH_POOL_CORS_ALLOWED_ORIGINS": "*"},
            clear=False,
        ):
            with self.assertRaises(CorsConfigurationError):
                PoolConfig(
                    require_signed_peers=False,
                    verify_direct_addresses=False,
                    network_profile=NETWORK_PROFILE_LOCAL,
                )

    @staticmethod
    def _handler(
        config: PoolConfig,
        *,
        origin: str,
        method: str,
        request_headers: str = "",
    ) -> PoolRequestHandler:
        handler = PoolRequestHandler.__new__(PoolRequestHandler)
        handler.server = SimpleNamespace(config=config)
        handler.path = "/peers"
        handler._read_deadline = None
        headers = Message()
        headers["Origin"] = origin
        headers["Access-Control-Request-Method"] = method
        if request_headers:
            headers["Access-Control-Request-Headers"] = request_headers
        handler.headers = headers
        return handler


if __name__ == "__main__":
    unittest.main()
