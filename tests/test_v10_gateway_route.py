from __future__ import annotations

import base64
import importlib
import json
import os
import ssl
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from gateway import chain_v10
from gateway.v10_gateway_route import (
    V10GatewayRoute,
    V10GatewayRouteError,
    decode_payment_header,
    load_v10_gateway_route,
    relay_route_health,
)
from tests.test_chain_v9 import address, digest, key, signer


CHAIN_ID = 11155111
SETTLEMENT = address(50)
RELAY_PAYMENT = address(31)
RELAY_SIGNER = signer(30)
ROOT = Path(__file__).resolve().parents[1]


def encode(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def authorization(*, chain_id: int = CHAIN_ID, contract: str = SETTLEMENT) -> dict:
    now = int(time.time())
    return chain_v10.build_authorization(
        payment_key=key(1), chain_id=chain_id, settlement_contract=contract,
        channel_id=digest(7), request_id=digest(8), request_hash=digest(9),
        max_fee=1000, issued_at=now, execute_by=now + 300, deadline=now + 9000,
    )


def route(urls: tuple[str, ...] = ("https://relay-a.test", "https://relay-b.test")) -> V10GatewayRoute:
    return V10GatewayRoute(
        network_id="mycomesh-v10-test",
        chain_id=CHAIN_ID,
        settlement=SETTLEMENT,
        relay_urls=urls,
        relay_payment_address=RELAY_PAYMENT,
        relay_attestation_address=RELAY_SIGNER,
        ssl_context=ssl.create_default_context(),
    )


def relay_health(**changes) -> dict:
    payload = {
        "providers": 3,
        "inference_ready": True,
        "settlement_ready": True,
        "v10": {
            "enabled": True,
            "chain_id": CHAIN_ID,
            "settlement_contract": SETTLEMENT,
            "relay_payment_address": RELAY_PAYMENT,
            "relay_signer_address": RELAY_SIGNER,
            "scheduler": {"total_slots": 3},
        },
    }
    payload.update(changes)
    return payload


class FakeResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.status = status
        self._body = body
        self._headers = headers

    def read(self, limit: int) -> bytes:
        return self._body[:limit]

    def getheader(self, name: str):
        return self._headers.get(name)


class FakeSocket:
    def settimeout(self, value: float) -> None:
        pass


def fake_connection_factory(behaviour: dict[str, str], log: list):
    """HTTPSConnection stand-in: behaviour maps host -> connect_fail | send_fail | ok."""

    class FakeConnection:
        def __init__(self, host, port, *, timeout, context):
            self.host = host
            self.sock = FakeSocket()

        def connect(self):
            log.append(("connect", self.host))
            if behaviour[self.host] == "connect_fail":
                raise ConnectionRefusedError("refused")

        def request(self, method, path, body=None, headers=None):
            log.append(("request", self.host, path, dict(headers or {})))
            if behaviour[self.host] == "send_fail":
                raise ConnectionResetError("reset after write")

        def getresponse(self):
            return FakeResponse(200, b'{"ok":true}', {"PAYMENT-RESPONSE": "receipt", "X-Other": "hidden"})

        def close(self):
            pass

    return FakeConnection


class V10GatewayRouteUnitTest(unittest.TestCase):
    def test_decode_payment_header_accepts_bare_and_wrapped_forms(self) -> None:
        payment = authorization()
        for value in (payment, {"payload": payment}, {"payment": payment}):
            with self.subTest(keys=sorted(value)):
                self.assertEqual(decode_payment_header(encode(value)), payment)
        for bad in ("%%%", encode(["not", "object"])):
            with self.assertRaises(V10GatewayRouteError) as caught:
                decode_payment_header(bad)
            self.assertEqual(caught.exception.execution_status, "not_dispatched")

    def test_verify_payment_binds_chain_and_settlement(self) -> None:
        verified = route().verify_payment(encode(authorization()))
        self.assertEqual(verified["authorization"]["key"], chain_v10.v9.payment_key_address(
            chain_v10.v9.payment_private_key(key(1))
        ))
        for payment in (authorization(chain_id=1), authorization(contract=address(51))):
            with self.assertRaises(V10GatewayRouteError) as caught:
                route().verify_payment(encode(payment))
            self.assertEqual(caught.exception.status, 400)
        tampered = authorization()
        tampered["authorization"]["max_fee"] = 999_999
        with self.assertRaises(V10GatewayRouteError):
            route().verify_payment(encode(tampered))

    def test_forward_fails_over_only_before_the_request_is_written(self) -> None:
        log: list = []
        factory = fake_connection_factory({"relay-a.test": "connect_fail", "relay-b.test": "ok"}, log)
        with patch("gateway.v10_gateway_route.http.client.HTTPSConnection", factory):
            status, body, headers = route().forward(
                "/v1/responses", b"{}", payment_header="sig",
                response_proof="proof", timeout_seconds=10,
            )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"ok":true}')
        self.assertEqual(headers, {"PAYMENT-RESPONSE": "receipt"})
        requests = [entry for entry in log if entry[0] == "request"]
        self.assertEqual([entry[1] for entry in requests], ["relay-b.test"])
        sent = requests[0][3]
        self.assertEqual(sent["PAYMENT-SIGNATURE"], "sig")
        self.assertEqual(sent["X-MycoMesh-Response-Proof"], "proof")

        log.clear()
        factory = fake_connection_factory({"relay-a.test": "send_fail", "relay-b.test": "ok"}, log)
        with patch("gateway.v10_gateway_route.http.client.HTTPSConnection", factory):
            with self.assertRaises(V10GatewayRouteError) as caught:
                route().forward("/v1/responses", b"{}", payment_header="sig",
                                response_proof=None, timeout_seconds=10)
        self.assertEqual(caught.exception.execution_status, "unknown")
        self.assertNotIn(("connect", "relay-b.test"), log)

        factory = fake_connection_factory({"relay-a.test": "connect_fail", "relay-b.test": "connect_fail"}, [])
        with patch("gateway.v10_gateway_route.http.client.HTTPSConnection", factory):
            with self.assertRaises(V10GatewayRouteError) as caught:
                route().forward("/v1/responses", b"{}", payment_header="sig",
                                response_proof=None, timeout_seconds=10)
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(caught.exception.execution_status, "not_dispatched")

    def test_relay_health_requires_deployment_binding_and_capacity(self) -> None:
        self.assertTrue(relay_route_health(relay_health(), route())["ready"])
        wrong = relay_health()
        wrong["v10"] = {**wrong["v10"], "settlement_contract": address(52)}
        self.assertEqual(relay_route_health(wrong, route())["error_code"], "deployment_mismatch")
        for changes in ({"providers": 0}, {"settlement_ready": False}, {"inference_ready": False}):
            with self.subTest(changes=changes):
                self.assertFalse(relay_route_health(relay_health(**changes), route())["ready"])
        idle = relay_health()
        idle["v10"] = {**idle["v10"], "scheduler": {"total_slots": 0}}
        self.assertFalse(relay_route_health(idle, route())["ready"])

    def test_health_snapshot_never_blocks_and_expires(self) -> None:
        r = route(("https://relay-a.test",))
        with patch.object(V10GatewayRoute, "_probe_relay", lambda self, url: {"url": url, "ready": True, "total_slots": 1}):
            self.assertIsNone(r.health_snapshot())
            deadline = time.monotonic() + 2
            while r._health is None and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertTrue(r.health_snapshot()["relays"][0]["ready"])
        r._health_checked_at -= 3600
        with patch.object(V10GatewayRoute, "_refresh_health", lambda self: None):
            self.assertIsNone(r.health_snapshot())

    def test_loader_pins_the_checked_in_v10_manifest(self) -> None:
        self.assertIsNone(load_v10_gateway_route({}))
        network = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
        ca = ROOT / "packages/mycomesh-cli/networks/v10-dynamic-20260926.ca.crt"
        with patch.dict(os.environ, {"MYCOMESH_ALLOW_CONTROLLED_V10_TEST": "1"}):
            loaded = load_v10_gateway_route({
                "MYCOMESH_V10_PROVIDER_NETWORK_CONFIG": str(network),
                "MYCOMESH_V10_RELAY_CA_FILE": str(ca),
            })
        manifest = json.loads(network.read_text(encoding="utf-8"))
        self.assertEqual(loaded.relay_urls, (
            manifest["relay"]["public_url"],
            *[entry["public_url"] for entry in manifest["relay_fallbacks"]],
        ))
        self.assertEqual(loaded.chain_id, manifest["chain_id"])


class V10GatewayHttpTest(unittest.TestCase):
    def _gateway(self, tmp: Path, fake_route: V10GatewayRoute | None):
        env = {
            **os.environ,
            "MYCOMESH_ADMIN_TOKEN": "test-admin-token-with-enough-entropy-0123456789",
            "MYCOMESH_BILLING_DB": str(tmp / "billing.sqlite3"),
            "MYCOMESH_GATEWAY_REGISTRY_DB": str(tmp / "gateways.sqlite3"),
            "MYCOMESH_BILLING_MODE": "onchain-prepaid",
            "MYCOMESH_REQUEST_IDENTITY": str(tmp / "request-identity.json"),
            "MYCOMESH_NETWORK_PROFILE": "local",
            "MYCOMESH_NETWORK_ID": "mycomesh-v10-test",
            "MYCOMESH_PUBLIC_GATEWAY_URL": "http://localhost:8000/v1",
            "ETH_RPC_URL": "",
            "ETH_CHAIN_ID": str(CHAIN_ID),
            "MYCO_SETTLEMENT": SETTLEMENT,
        }
        patcher = patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
        route_patch = patch.object(mycomesh, "_v10_gateway_route", return_value=fake_route)
        route_patch.start()
        self.addCleanup(route_patch.stop)
        return mycomesh, TestClient(mycomesh.app)

    def test_signed_request_is_verified_and_forwarded_without_an_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = route()
            calls: list = []

            def forward(path, body, **kwargs):
                calls.append((path, body, kwargs))
                return 200, b'{"id":"resp"}', {"PAYMENT-RESPONSE": "receipt"}

            fake.forward = forward
            _, client = self._gateway(Path(tmp), fake)
            response = client.post(
                "/v1/chat/completions",
                content=b'{"model":"m","messages":[]}',
                headers={"PAYMENT-SIGNATURE": encode(authorization()), "Content-Type": "application/json"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": "resp"})
        self.assertEqual(response.headers["PAYMENT-RESPONSE"], "receipt")
        self.assertEqual(calls[0][0], "/v1/chat/completions")
        self.assertEqual(calls[0][1], b'{"model":"m","messages":[]}')

    def test_invalid_signature_is_rejected_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = route()
            fake.forward = lambda *args, **kwargs: self.fail("must not dispatch")
            _, client = self._gateway(Path(tmp), fake)
            response = client.post(
                "/v1/responses", json={"input": "hi"},
                headers={"PAYMENT-SIGNATURE": encode(authorization(contract=address(51)))},
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["execution_status"], "not_dispatched")
        self.assertEqual(response.headers["x-should-retry"], "true")

    def test_unsigned_request_gets_relay_payment_terms_and_api_keys_keep_their_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = route()
            fake.forward = lambda path, body, **kwargs: (402, b'{"accepts":[]}', {"PAYMENT-REQUIRED": "terms"})
            _, client = self._gateway(Path(tmp), fake)
            unsigned = client.post("/v1/responses", json={"input": "hi"})
            keyed = client.post(
                "/v1/responses", json={"input": "hi"},
                headers={"Authorization": "Bearer not-a-real-key"},
            )
        self.assertEqual(unsigned.status_code, 402)
        self.assertEqual(unsigned.headers["PAYMENT-REQUIRED"], "terms")
        self.assertEqual(keyed.status_code, 401)

    def test_payment_without_configured_route_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, client = self._gateway(Path(tmp), None)
            response = client.post(
                "/v1/responses", json={"input": "hi"},
                headers={"PAYMENT-SIGNATURE": encode(authorization())},
            )
        self.assertEqual(response.status_code, 400)

    def test_readiness_reports_the_v10_route_from_relay_health(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = route()
            snapshot = {"relays": [{"url": "https://relay-a.test", "ready": True, "total_slots": 3}]}
            fake.health_snapshot = lambda: snapshot
            mycomesh, client = self._gateway(Path(tmp), fake)
            deployment = type("Deployment", (), {
                "protocol_version": 10, "chain_id": CHAIN_ID,
                "settlement": SETTLEMENT, "network_id": "mycomesh-v10-test",
            })()
            with patch.object(mycomesh, "_consumer_deployment_binding", return_value=deployment):
                ready = client.get("/ready")
                snapshot["relays"][0]["ready"] = False
                not_ready = client.get("/ready")
        self.assertEqual(ready.status_code, 200, ready.json())
        self.assertTrue(ready.json()["checks"]["v10_gateway_route"])
        self.assertEqual(ready.json()["provider_capacity"], 3)
        self.assertEqual(not_ready.status_code, 503)
        self.assertFalse(not_ready.json()["checks"]["v10_gateway_route"])


if __name__ == "__main__":
    unittest.main()
