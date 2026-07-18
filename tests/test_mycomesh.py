from __future__ import annotations

import importlib
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from gateway.billing import usdc_to_units
from gateway.chain import ChainError, DEFAULT_CHANNEL_HASH, parse_private_key, private_key_to_address, sign_evm_digest
from gateway.chain_v3 import V3Deployment, save_deployment as save_v3_deployment
from gateway.identity import create_identity, sign_document
from gateway.gateway_registry import (
    GATEWAY_REGISTRATION_PURPOSE,
    MAX_GATEWAY_TTL_SECONDS,
    GatewayRegistry,
    GatewayRegistryError,
    normalize_gateway_url,
    verify_gateway_descriptor,
    verify_gateway_registration,
)
from gateway.reservation import inference_request_hash


TEST_ADMIN_TOKEN = "test-admin-token-32-bytes-minimum-secret"
ADMIN_HEADERS = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}


class MycoMeshProxyTest(unittest.TestCase):
    def test_session_context_preserves_rpc_failover_list(self) -> None:
        import gateway.mycomesh as mycomesh

        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.update(
                {
                    "MYCOMESH_SESSION_V4_ENABLED": "true",
                    "MYCOMESH_SESSION_DEPLOYMENT": str(
                        Path(__file__).resolve().parents[1] / "deployments" / "sepolia-myco-v4.json"
                    ),
                    "MYCOMESH_SESSION_RPC_URL": (
                        "https://primary.example,https://secondary.example,https://tertiary.example"
                    ),
                    "MYCOMESH_SESSION_KEY_SECRET": "test-session-secret-with-at-least-32-bytes",
                }
            )
            with patch.dict(os.environ, env, clear=True):
                context = mycomesh._consumer_v4_context()

        self.assertEqual(
            context["rpc_url"],
            "https://primary.example,https://secondary.example,https://tertiary.example",
        )

    def test_gateway_sequence_is_persistent_and_monotonic_across_clock_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gateways.sqlite3"
            first_registry = GatewayRegistry(path)
            first = first_registry.next_sequence("peer-a", minimum=100)
            after_restart = GatewayRegistry(path).next_sequence("peer-a", minimum=50)
            after_clock_advance = GatewayRegistry(path).next_sequence("peer-a", minimum=200)

        self.assertEqual(first, 100)
        self.assertEqual(after_restart, 101)
        self.assertEqual(after_clock_advance, 200)

    def test_local_descriptor_cache_is_read_only_until_refresh_or_config_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gateways.sqlite3"
            first_registry = GatewayRegistry(path)
            issued: list[int] = []

            def factory(now: int):
                def build(sequence: int) -> dict[str, object]:
                    issued.append(sequence)
                    return {
                        "node_id": "peer-a",
                        "sequence": sequence,
                        "expires_at": now + 300,
                    }

                return build

            first = first_registry.get_or_issue_local_descriptor(
                "peer-a",
                cache_key="config-a",
                now=1000,
                refresh_before_seconds=30,
                factory=factory(1000),
            )
            cached_after_restart = GatewayRegistry(path).get_or_issue_local_descriptor(
                "peer-a",
                cache_key="config-a",
                now=1100,
                refresh_before_seconds=30,
                factory=factory(1100),
            )
            refreshed = GatewayRegistry(path).get_or_issue_local_descriptor(
                "peer-a",
                cache_key="config-a",
                now=1270,
                refresh_before_seconds=30,
                factory=factory(1270),
            )
            changed = GatewayRegistry(path).get_or_issue_local_descriptor(
                "peer-a",
                cache_key="config-b",
                now=1271,
                refresh_before_seconds=30,
                factory=factory(1271),
            )

        self.assertEqual(cached_after_restart, first)
        self.assertEqual(issued, [1000, 1270, 1271])
        self.assertEqual(refreshed["sequence"], 1270)
        self.assertEqual(changed["sequence"], 1271)

    def test_global_body_limit_covers_auto_parsed_and_chunked_routes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                **self._env(Path(tmp), billing_mode="local"),
                "MYCOMESH_MAX_REQUEST_BYTES": "64",
            }
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="http://localhost:8000")

                auto_parsed = client.post(
                    "/accounts",
                    headers={**ADMIN_HEADERS, "Content-Type": "application/json"},
                    content='{"account_id":"' + ("x" * 128) + '"}',
                )
                self.assertEqual(auto_parsed.status_code, 413)

                def chunks():
                    yield b'{"wallet":"'
                    yield b"x" * 128
                    yield b'"}'

                chunked = client.post(
                    "/v1/mycomesh/keys/challenge",
                    headers={"Content-Type": "application/json"},
                    content=chunks(),
                )
                self.assertEqual(chunked.status_code, 413)

    def test_chat_commitment_binds_original_messages_array(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))

        messages = [
            {"role": "system", "content": "Be exact."},
            {"role": "user", "content": [{"type": "text", "text": "Say OK"}]},
        ]
        actual = mycomesh._public_request_hash(
            endpoint="chat",
            model="gpt-5.5",
            input_value=messages,
            max_output_tokens=64,
        )
        expected = inference_request_hash(
            endpoint="chat",
            model="gpt-5.5",
            messages=messages,
            max_output_tokens=64,
        )
        stringified = inference_request_hash(
            endpoint="chat",
            model="gpt-5.5",
            input_value=messages,
            max_output_tokens=64,
        )
        self.assertEqual(actual, expected)
        self.assertNotEqual(actual, stringified)

    def test_output_token_limit_is_strictly_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))

        self.assertEqual(mycomesh._request_max_output_tokens({"max_output_tokens": 128}), 128)
        self.assertEqual(mycomesh._request_max_output_tokens({"max_completion_tokens": 128}), 128)
        self.assertEqual(mycomesh._request_max_output_tokens({"max_tokens": 128}), 128)
        self.assertEqual(
            mycomesh._request_max_output_tokens(
                {"max_output_tokens": 128, "max_completion_tokens": 128, "max_tokens": 128}
            ),
            128,
        )
        self.assertIsNone(mycomesh._request_max_output_tokens({}))
        for key in ("max_output_tokens", "max_completion_tokens", "max_tokens"):
            for invalid in (True, 0, -1, "128", 1.5):
                with self.subTest(key=key, invalid=invalid):
                    with self.assertRaises(HTTPException) as raised:
                        mycomesh._request_max_output_tokens({key: invalid})
                    self.assertEqual(raised.exception.status_code, 422)

        with self.assertRaises(HTTPException) as conflict:
            mycomesh._request_max_output_tokens({"max_completion_tokens": 64, "max_tokens": 128})
        self.assertEqual(conflict.exception.status_code, 422)
        self.assertIn("must match", str(conflict.exception.detail))

    def test_inference_deadline_after_reserve_restores_balance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["MYCOMESH_ROUTE_STATE"] = str(Path(tmp) / "route-state.json")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                mycomesh.store.deposit(account.account_id, "100")
                before = mycomesh.store.get_by_account(account.account_id)
                peer = {
                    "peer_id": "peer-a",
                    "public_key": "provider-key",
                    "payment_address": "0x0000000000000000000000000000000000000003",
                    "address": "tcp://127.0.0.1:9700",
                    "capacity": {"max_concurrency": 1},
                }
                deadline = HTTPException(status_code=504, detail="deadline")
                with patch.object(mycomesh, "discover_peers_from_pools", return_value=[peer]), patch.object(
                    mycomesh,
                    "_remaining_inference_time",
                    side_effect=[1.0, deadline],
                ):
                    with self.assertRaises(HTTPException) as raised:
                        mycomesh._run_pool_inference(
                            account,
                            "hello",
                            "mycomesh-codex-standard-v1",
                            "responses",
                            timeout=1.0,
                        )
                after = mycomesh.store.get_by_account(account.account_id)

        self.assertEqual(raised.exception.status_code, 504)
        self.assertIsNotNone(before)
        self.assertIsNotNone(after)
        self.assertEqual(after.balance_units, before.balance_units)

    def test_inference_concurrency_limit_fails_fast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                occupied = threading.BoundedSemaphore(1)
                self.assertTrue(occupied.acquire(blocking=False))
                with patch.object(mycomesh, "_inference_slots", occupied):
                    with self.assertRaises(HTTPException) as raised:
                        asyncio.run(
                            mycomesh._run_pool_inference_async(
                                account,
                                "hello",
                                "mycomesh-codex-standard-v1",
                                "responses",
                            )
                        )
                occupied.release()

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.headers, {"Retry-After": "1"})

    def test_inference_timeout_config_rejects_non_finite_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["MYCOMESH_TIMEOUT_SECONDS"] = "inf"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                with self.assertRaises(HTTPException) as raised:
                    mycomesh._configured_inference_timeout()

        self.assertEqual(raised.exception.status_code, 503)

    def test_pool_route_timeout_is_retryable_gateway_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))

        raised = mycomesh._pool_route_failure(
            mycomesh.RelayError("provider 'peer-a' timed out")
        )
        self.assertEqual(raised.status_code, 504)
        self.assertEqual(raised.headers, {"Retry-After": "5"})
        self.assertIn("Relay deadline", str(raised.detail))

    def test_post_capture_route_state_failure_preserves_success_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            env["MYCOMESH_ROUTE_STATE"] = str(tmp_path / "route-state.json")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                mycomesh.store.deposit(account.account_id, "1")
                reservation_id = "res-post-capture"
                reservation_units = 10_000
                mycomesh.store.reserve(account.account_id, reservation_units, reservation_id)
                peer = {
                    "peer_id": "peer-a",
                    "public_key": "provider-key",
                    "payment_address": "0x0000000000000000000000000000000000000003",
                    "address": "tcp://127.0.0.1:9700",
                    "capacity": {"max_concurrency": 1},
                }
                response = {
                    "id": "response-a",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
                receipt = SimpleNamespace(job_id="job-a", to_dict=lambda: {"job_id": "job-a"})
                accepted_receipt = {"job_id": "job-a", "accepted": True}
                original_capture = mycomesh.store.capture
                captured = threading.Event()

                def capture(*args, **kwargs):
                    result = original_capture(*args, **kwargs)
                    captured.set()
                    return result

                def save_route_state(*_args, **_kwargs):
                    if captured.is_set():
                        raise OSError("route-state disk failure")

                with patch.object(
                    mycomesh,
                    "_send_infer_to_address",
                    return_value=response,
                ), patch.object(mycomesh, "verify_provider_response"), patch.object(
                    mycomesh,
                    "build_receipt",
                    return_value=receipt,
                ), patch.object(
                    mycomesh,
                    "sign_acceptance",
                    return_value=accepted_receipt,
                ), patch.object(mycomesh, "build_bridge_usage", return_value={}), patch.object(
                    mycomesh.store,
                    "capture",
                    side_effect=capture,
                ), patch.object(
                    mycomesh,
                    "save_route_state",
                    side_effect=save_route_state,
                ), patch.object(mycomesh, "_export_pending_receipts"), self.assertLogs(
                    mycomesh.logger.name,
                    level="ERROR",
                ) as logs:
                    output = mycomesh._route_reserved_inference(
                        account=account,
                        input_value="hello",
                        model="mycomesh-codex-standard-v1",
                        endpoint="responses",
                        peers=[peer],
                        pool_url="http://127.0.0.1:9800",
                        channel="codex-standard-v1",
                        deadline=time.monotonic() + 5,
                        route_state=mycomesh.load_route_state(env["MYCOMESH_ROUTE_STATE"]),
                        route_state_path=env["MYCOMESH_ROUTE_STATE"],
                        pricing_table=mycomesh.load_pricing_config(None),
                        channel_pricing_hash="0x" + "11" * 32,
                        reservation_id=reservation_id,
                        reservation_output_tokens=100,
                        reservation_units=reservation_units,
                        request_hash="0x" + "22" * 32,
                        control=mycomesh._InferenceControl(time.monotonic() + 5),
                    )
                after = mycomesh.store.get_by_account(account.account_id)

        self.assertEqual(output["id"], "response-a")
        self.assertEqual(output["mycomesh_receipt"], accepted_receipt)
        self.assertIsNotNone(after)
        self.assertEqual(after.balance_units, usdc_to_units("0.998"))
        self.assertTrue(any("capture_committed=True" in line for line in logs.output))

    def test_outer_timeout_prevents_background_reserve_after_discovery_returns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                started = threading.Event()
                unblock = threading.Event()
                finished = threading.Event()
                observed_timeouts: list[float] = []

                class Slot:
                    def acquire(self, blocking: bool = False) -> bool:
                        return True

                    def release(self) -> None:
                        finished.set()

                def discover(*_args, timeout: float, **_kwargs):
                    observed_timeouts.append(timeout)
                    started.set()
                    unblock.wait(1)
                    return [{"peer_id": "peer-a"}]

                async def scenario() -> HTTPException:
                    task = asyncio.create_task(
                        mycomesh._run_pool_inference_async(
                            account,
                            "hello",
                            "mycomesh-codex-standard-v1",
                            "responses",
                        )
                    )
                    while not started.is_set():
                        await asyncio.sleep(0.001)
                    try:
                        await task
                    except HTTPException as exc:
                        raised = exc
                    else:
                        self.fail("inference should have timed out")
                    unblock.set()
                    for _ in range(1_000):
                        if finished.is_set():
                            break
                        await asyncio.sleep(0.001)
                    return raised

                with patch.object(mycomesh, "_configured_inference_timeout", return_value=0.05), patch.object(
                    mycomesh,
                    "_inference_slots",
                    Slot(),
                ), patch.object(
                    mycomesh,
                    "discover_peers_from_pools",
                    side_effect=discover,
                ), patch.object(mycomesh.store, "reserve") as reserve, patch.object(
                    mycomesh.store,
                    "capture",
                ) as capture:
                    raised = asyncio.run(scenario())

        self.assertEqual(raised.status_code, 504)
        self.assertTrue(finished.is_set())
        self.assertEqual(len(observed_timeouts), 1)
        self.assertGreater(observed_timeouts[0], 0)
        self.assertLessEqual(observed_timeouts[0], 0.05)
        reserve.assert_not_called()
        capture.assert_not_called()

    def test_client_cancellation_prevents_capture_and_releases_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            env["MYCOMESH_ROUTE_STATE"] = str(tmp_path / "route-state.json")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                mycomesh.store.deposit(account.account_id, "1")
                before = mycomesh.store.get_by_account(account.account_id)
                send_started = threading.Event()
                unblock = threading.Event()
                finished = threading.Event()
                peer = {
                    "peer_id": "peer-a",
                    "public_key": "provider-key",
                    "payment_address": "0x0000000000000000000000000000000000000003",
                    "address": "tcp://127.0.0.1:9700",
                    "capacity": {"max_concurrency": 1},
                }

                class Slot:
                    def acquire(self, blocking: bool = False) -> bool:
                        return True

                    def release(self) -> None:
                        finished.set()

                def send(*_args, **_kwargs):
                    send_started.set()
                    unblock.wait(1)
                    return {"id": "too-late"}

                async def scenario() -> None:
                    task = asyncio.create_task(
                        mycomesh._run_pool_inference_async(
                            account,
                            "hello",
                            "mycomesh-codex-standard-v1",
                            "responses",
                        )
                    )
                    while not send_started.is_set():
                        await asyncio.sleep(0.001)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    unblock.set()
                    for _ in range(1_000):
                        if finished.is_set():
                            break
                        await asyncio.sleep(0.001)

                with patch.object(mycomesh, "_configured_inference_timeout", return_value=1.0), patch.object(
                    mycomesh,
                    "_inference_slots",
                    Slot(),
                ), patch.object(
                    mycomesh,
                    "discover_peers_from_pools",
                    return_value=[peer],
                ), patch.object(
                    mycomesh,
                    "_reservation_units",
                    return_value=10_000,
                ), patch.object(
                    mycomesh,
                    "_send_infer_to_address",
                    side_effect=send,
                ), patch.object(mycomesh, "verify_provider_response") as verify, patch.object(
                    mycomesh.store,
                    "capture",
                ) as capture:
                    asyncio.run(scenario())
                after = mycomesh.store.get_by_account(account.account_id)

        self.assertTrue(finished.is_set())
        self.assertIsNotNone(before)
        self.assertIsNotNone(after)
        self.assertEqual(after.balance_units, before.balance_units)
        verify.assert_not_called()
        capture.assert_not_called()

    def test_sync_balance_rejects_incomplete_chain_metadata_without_mutating_balance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="onchain-prepaid")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                mycomesh.store.create_account("acct-a")
                client = TestClient(mycomesh.app)

                response = client.post(
                    "/accounts/acct-a/sync-balance",
                    headers=ADMIN_HEADERS,
                    json={"balance_usdc": "5"},
                )
                account = mycomesh.store.get_by_account("acct-a")

        self.assertEqual(response.status_code, 400)
        self.assertIsNotNone(account)
        self.assertEqual(account.balance_usdc, "0.000000")

    def test_sync_balance_records_chain_freshness_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="onchain-prepaid")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                mycomesh.store.create_account(
                    "acct-a",
                    payment_address="0x0000000000000000000000000000000000000001",
                )
                mycomesh.store.create_account("acct-b")
                mycomesh.store.set_balance("acct-b", "7")
                client = TestClient(mycomesh.app)

                response = client.post(
                    "/accounts/acct-a/sync-balance",
                    headers=ADMIN_HEADERS,
                    json={
                        "balance_usdc": "5",
                        "chain_id": 11155111,
                        "settlement": "0x0000000000000000000000000000000000000002",
                        "latest_block": 120,
                        "synced_block": 114,
                        "synced_block_hash": "0x" + "aa" * 32,
                        "confirmations": 6,
                        "source": "direct",
                    },
                )
                forged_event_source = client.post(
                    "/accounts/acct-a/sync-balance",
                    headers=ADMIN_HEADERS,
                    json={
                        "balance_usdc": "9",
                        "chain_id": 11155111,
                        "settlement": "0x0000000000000000000000000000000000000002",
                        "latest_block": 121,
                        "synced_block": 115,
                        "synced_block_hash": "0x" + "bb" * 32,
                        "confirmations": 6,
                        "source": "events",
                    },
                )
                account_after = mycomesh.store.get_by_account("acct-a")
                other_state = mycomesh.store.get_chain_sync_state("acct-b")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["balance_usdc"], "5.000000")
        self.assertEqual(body["chain_sync"]["chain_id"], 11155111)
        self.assertEqual(body["chain_sync"]["settlement"], "0x0000000000000000000000000000000000000002")
        self.assertEqual(body["chain_sync"]["synced_block"], 114)
        self.assertEqual(body["chain_sync"]["source"], "direct")
        self.assertEqual(forged_event_source.status_code, 400)
        self.assertEqual(account_after.balance_usdc, "5.000000")
        self.assertEqual(other_state["chain_id"], 0)
        self.assertEqual(other_state["metadata_pending"], 1)

    def test_rotate_key_response_preserves_account_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                mycomesh.store.configure_account(
                    account.account_id,
                    parent_account_id="acct-parent",
                    discount_bps=500,
                    reseller_margin_bps=1000,
                    monthly_quota_usdc="20",
                    usage_tier="reseller",
                )
                client = TestClient(mycomesh.app)

                response = client.post("/accounts/acct-a/keys/rotate", headers=ADMIN_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["api_key"].startswith("msk_"))
        self.assertEqual(body["parent_account_id"], "acct-parent")
        self.assertEqual(body["discount_bps"], 500)
        self.assertEqual(body["reseller_margin_bps"], 1000)
        self.assertEqual(body["monthly_quota_usdc"], "20.000000")
        self.assertEqual(usdc_to_units(body["monthly_quota_usdc"]), usdc_to_units("20"))
        self.assertEqual(body["usage_tier"], "reseller")
        self.assertEqual(body["credential_audience"], "http://localhost:8000")

    def test_nonlocal_legacy_key_must_be_rotated_into_gateway_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.update(
                {
                    "MYCOMESH_NETWORK_PROFILE": "testnet",
                    "MYCOMESH_PUBLIC_GATEWAY_URL": "https://api.myco.example/v1",
                }
            )
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                legacy = mycomesh.store.create_account("acct-legacy")
                client = TestClient(mycomesh.app, base_url="https://api.myco.example")
                denied = client.get(
                    "/account",
                    headers={"Authorization": f"Bearer {legacy.api_key}"},
                )
                rotated = client.post("/accounts/acct-legacy/keys/rotate", headers=ADMIN_HEADERS)
                accepted = client.get(
                    "/account",
                    headers={"Authorization": f"Bearer {rotated.json()['api_key']}"},
                )

        self.assertEqual(denied.status_code, 403)
        self.assertIn("must be rotated", denied.json()["detail"])
        self.assertEqual(rotated.status_code, 200)
        self.assertEqual(rotated.json()["credential_audience"], "https://api.myco.example")
        self.assertEqual(accepted.status_code, 200)

    def test_health_is_minimal_and_admin_health_is_detailed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)

                public = client.get("/health")
                admin = client.get("/admin/health", headers=ADMIN_HEADERS)

        self.assertEqual(public.status_code, 200)
        self.assertNotIn("consumer_public_key", public.json())
        self.assertEqual(admin.status_code, 200)
        self.assertIn("consumer_public_key", admin.json())

    def test_nonlocal_profile_rejects_placeholder_admin_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.update(
                {
                    "MYCOMESH_NETWORK_PROFILE": "testnet",
                    "MYCOMESH_PUBLIC_GATEWAY_URL": "https://api.myco.example/v1",
                    "MYCOMESH_ADMIN_TOKEN": "change-me-admin-token",
                }
            )
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                response = TestClient(mycomesh.app).get(
                    "/admin/health",
                    headers={"Authorization": "Bearer change-me-admin-token"},
                )

        self.assertEqual(response.status_code, 503)
        self.assertIn("strong non-placeholder secret", response.json()["detail"])

    def test_account_status_endpoint_suspends_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                client = TestClient(mycomesh.app)

                updated = client.post(
                    "/accounts/acct-a/status",
                    headers=ADMIN_HEADERS,
                    json={"status": "suspended"},
                )
                denied = client.get("/account", headers={"Authorization": f"Bearer {account.api_key}"})

        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["status"], "suspended")
        self.assertEqual(denied.status_code, 403)

    def test_wallet_registers_client_generated_key_hash(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        api_key = "msk_client_generated_secret"
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="http://localhost:8000")

                challenge_response = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash, "chain_id": 11155111},
                )
                challenge = challenge_response.json()
                signature = sign_evm_digest(private_key, mycomesh._personal_sign_digest(challenge["message"].encode("utf-8")))
                register_response = client.post(
                    "/v1/mycomesh/keys/register",
                    json={
                        "wallet": wallet,
                        "key_hash": key_hash,
                        "chain_id": 11155111,
                        "nonce": challenge["nonce"],
                        "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
                    },
                )
                account_response = client.get("/account", headers={"Authorization": f"Bearer {api_key}"})
                stored = mycomesh.store.get_by_account(wallet)
                discovery = client.get("/.well-known/mycomesh.json").json()["key_registration"]

        self.assertEqual(challenge_response.status_code, 200)
        self.assertEqual(register_response.status_code, 200)
        self.assertFalse(register_response.json()["api_key_returned"])
        self.assertEqual(register_response.json()["base_url"], "http://localhost:8000/v1")
        self.assertEqual(register_response.json()["credential_scope"], "origin_network_chain_settlement")
        self.assertNotIn("base_urls", register_response.json())
        self.assertEqual(discovery["rotate_url"], "/v1/mycomesh/keys/rotate")
        self.assertEqual(discovery["revoke_url"], "/v1/mycomesh/keys/current")
        self.assertIn("Origin: http://localhost:8000", challenge["message"])
        self.assertIn("Network ID: mycomesh-local-test", challenge["message"])
        self.assertIn("Settlement: 0x0000000000000000000000000000000000000002", challenge["message"])
        self.assertEqual(account_response.status_code, 200)
        self.assertIsNotNone(stored)
        self.assertIsNone(stored.api_key)
        self.assertEqual(stored.payment_address, wallet)
        self.assertEqual(stored.credential_origin, "http://localhost:8000")
        self.assertEqual(stored.credential_network_id, "mycomesh-local-test")
        self.assertEqual(stored.credential_chain_id, 11155111)
        self.assertEqual(stored.credential_settlement, "0x0000000000000000000000000000000000000002")

    def test_v3_manifest_drives_discovery_and_wallet_key_registration(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        api_key = "msk_v3_client_generated_secret"
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            deployment = self._v3_deployment()
            env = self._v3_env(tmp_path, deployment, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="http://localhost:8000")
                discovery = client.get("/.well-known/mycomesh.json")
                challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash},
                )
                challenge_payload = challenge.json()
                signature = sign_evm_digest(
                    private_key,
                    mycomesh._personal_sign_digest(challenge_payload["message"].encode("utf-8")),
                )
                registration = client.post(
                    "/v1/mycomesh/keys/register",
                    json={
                        "wallet": wallet,
                        "key_hash": key_hash,
                        "nonce": challenge_payload["nonce"],
                        "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
                    },
                )
                stored = mycomesh.store.get_by_account(wallet)

            with patch.dict(os.environ, {**env, "ETH_CHAIN_ID": "1"}, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                rejected = TestClient(mycomesh.app).post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash},
                )

        self.assertEqual(discovery.status_code, 200)
        self.assertEqual(discovery.json()["chain_id"], deployment.chain_id)
        self.assertEqual(discovery.json()["settlement"], deployment.settlement)
        self.assertEqual(challenge.status_code, 200)
        self.assertEqual(challenge_payload["chain_id"], deployment.chain_id)
        self.assertEqual(challenge_payload["settlement"], deployment.settlement)
        self.assertEqual(registration.status_code, 200)
        self.assertEqual(stored.credential_chain_id, deployment.chain_id)
        self.assertEqual(stored.credential_settlement, deployment.settlement)
        self.assertEqual(rejected.status_code, 503)
        self.assertIn("ETH_CHAIN_ID does not match", rejected.json()["detail"])

    def test_v3_chain_cache_uses_manifest_and_rejects_conflicting_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            deployment = self._v3_deployment()
            env = self._v3_env(tmp_path, deployment, billing_mode="onchain-prepaid")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                configuration = mycomesh._chain_cache_configuration()
                os.environ["MYCO_SETTLEMENT"] = "0x" + "99" * 20
                with self.assertRaisesRegex(ChainError, "MYCO_SETTLEMENT does not match"):
                    mycomesh._chain_cache_configuration()

        self.assertEqual(configuration["chain_id"], deployment.chain_id)
        self.assertEqual(configuration["settlement"], deployment.settlement)

    def test_contract_wallet_registers_client_key_with_eip1271(self) -> None:
        wallet = "0x00000000000000000000000000000000000000aa"
        api_key = "msk_contract_wallet_secret"
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["ETH_RPC_URL"] = "https://rpc.example"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="http://localhost:8000")
                challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash, "chain_id": 11155111},
                ).json()

                with patch.object(mycomesh, "rpc_call", return_value="0x6000") as identify_rpc, patch(
                    "gateway.chain_v3.rpc_call",
                    side_effect=["0x6000", "0x1626ba7e" + "0" * 56],
                ) as wallet_rpc:
                    response = client.post(
                        "/v1/mycomesh/keys/register",
                        json={
                            "wallet": wallet,
                            "key_hash": key_hash,
                            "chain_id": 11155111,
                            "nonce": challenge["nonce"],
                            "signature": "0x1234",
                        },
                    )

        self.assertEqual(response.status_code, 200)
        identify_rpc.assert_called_once()
        self.assertEqual(
            identify_rpc.call_args.args[:3],
            ("https://rpc.example", "eth_getCode", [wallet, "latest"]),
        )
        self.assertGreater(identify_rpc.call_args.args[3], 0)
        self.assertLessEqual(identify_rpc.call_args.args[3], 20.0)
        self.assertEqual([call.args[1] for call in wallet_rpc.call_args_list], ["eth_getCode", "eth_call"])
        self.assertTrue(all(0 < call.args[3] <= 20.0 for call in wallet_rpc.call_args_list))
        contract_call = wallet_rpc.call_args_list[1].args[2][0]
        self.assertEqual(contract_call["from"], "0x0000000000000000000000000000000000000002")
        self.assertEqual(contract_call["to"], wallet)
        self.assertIn("1234", contract_call["data"])

    def test_wallet_type_rpc_keeps_eoa_path_and_bounds_contract_inputs(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        key_hash = hashlib.sha256(b"rpc-eoa-key").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["ETH_RPC_URL"] = "https://rpc.example"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash},
                ).json()
                signature = sign_evm_digest(
                    private_key,
                    mycomesh._personal_sign_digest(challenge["message"].encode("utf-8")),
                )
                registration = {
                    "wallet": wallet,
                    "key_hash": key_hash,
                    "nonce": challenge["nonce"],
                    "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
                }
                with patch.object(mycomesh, "rpc_call", return_value="0x") as identify_rpc, patch.object(
                    mycomesh, "verify_eip1271_signature"
                ) as contract_verify:
                    eoa_response = client.post("/v1/mycomesh/keys/register", json=registration)

                second_challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": "0x00000000000000000000000000000000000000bb", "key_hash": key_hash},
                ).json()
                contract_registration = {
                    "wallet": "0x00000000000000000000000000000000000000bb",
                    "key_hash": key_hash,
                    "nonce": second_challenge["nonce"],
                    "signature": "0x" + "ab" * (mycomesh.MAX_EIP1271_SIGNATURE_BYTES + 1),
                }
                with patch.object(mycomesh, "rpc_call", return_value="0x6000"), patch.object(
                    mycomesh, "verify_eip1271_signature"
                ) as oversized_verify:
                    oversized = client.post("/v1/mycomesh/keys/register", json=contract_registration)

                os.environ["MYCOMESH_KEY_REGISTRATION_RPC_TIMEOUT"] = "31"
                with patch.object(mycomesh, "rpc_call") as invalid_timeout_rpc:
                    invalid_timeout = client.post("/v1/mycomesh/keys/register", json=contract_registration)

        self.assertEqual(eoa_response.status_code, 200)
        identify_rpc.assert_called_once()
        contract_verify.assert_not_called()
        self.assertEqual(oversized.status_code, 403)
        self.assertIn("exceeds", oversized.json()["detail"])
        oversized_verify.assert_not_called()
        self.assertEqual(invalid_timeout.status_code, 503)
        self.assertIn("must not exceed 30 seconds", invalid_timeout.json()["detail"])
        invalid_timeout_rpc.assert_not_called()

    def test_contract_wallet_transport_failure_is_not_reported_as_bad_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["ETH_RPC_URL"] = "https://rpc.example"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                common = {
                    "wallet": "0x00000000000000000000000000000000000000aa",
                    "message": "challenge",
                    "signature_payload": "0x1234",
                    "caller": "0x0000000000000000000000000000000000000002",
                }
                with patch.object(mycomesh, "rpc_call", return_value="0x6000"), patch.object(
                    mycomesh,
                    "verify_eip1271_signature",
                    side_effect=ChainError("RPC timeout"),
                ):
                    with self.assertRaises(HTTPException) as unavailable:
                        mycomesh._verify_key_registration_signature(**common)
                with patch.object(mycomesh, "rpc_call", return_value="0x6000"), patch.object(
                    mycomesh,
                    "verify_eip1271_signature",
                    side_effect=mycomesh.EIP1271SignatureRejected("wrong magic value"),
                ):
                    with self.assertRaises(HTTPException) as rejected:
                        mycomesh._verify_key_registration_signature(**common)

        self.assertEqual(unavailable.exception.status_code, 503)
        self.assertIn("unavailable", str(unavailable.exception.detail))
        self.assertEqual(rejected.exception.status_code, 403)
        self.assertIn("rejected", str(rejected.exception.detail))

    def test_contract_wallet_registration_rpc_worker_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["ETH_RPC_URL"] = "https://rpc.example"
            env["MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                self.assertTrue(mycomesh._key_registration_rpc_slots.acquire(blocking=False))
                try:
                    with self.assertRaises(HTTPException) as denied, patch.object(
                        mycomesh,
                        "_verify_key_registration_signature",
                    ) as verifier, patch.object(
                        mycomesh._key_registration_rpc_executor,
                        "submit",
                    ) as submit:
                        asyncio.run(
                            mycomesh._verify_key_registration_signature_async(
                                wallet="0x00000000000000000000000000000000000000aa",
                                message="challenge",
                                signature_payload="0x1234",
                                caller="0x0000000000000000000000000000000000000002",
                            )
                        )
                finally:
                    mycomesh._key_registration_rpc_slots.release()

        self.assertEqual(denied.exception.status_code, 503)
        verifier.assert_not_called()
        submit.assert_not_called()

    def test_contract_wallet_registration_does_not_starve_default_executor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["ETH_RPC_URL"] = "https://rpc.example"
            env["MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                started = threading.Event()
                unblock = threading.Event()

                def blocking_verifier(**_kwargs: object) -> None:
                    started.set()
                    unblock.wait(2)

                async def scenario() -> str:
                    loop = asyncio.get_running_loop()
                    loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
                    registration = asyncio.create_task(
                        mycomesh._verify_key_registration_signature_async(
                            wallet="0x00000000000000000000000000000000000000aa",
                            message="challenge",
                            signature_payload="0x1234",
                            caller="0x0000000000000000000000000000000000000002",
                        )
                    )
                    try:
                        for _ in range(1_000):
                            if started.is_set():
                                break
                            await asyncio.sleep(0.001)
                        self.assertTrue(started.is_set())
                        return await asyncio.wait_for(asyncio.to_thread(lambda: "default-ok"), timeout=0.25)
                    finally:
                        unblock.set()
                        await registration

                with patch.object(
                    mycomesh,
                    "_configured_key_registration_rpc_timeout",
                    return_value=1.0,
                ), patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                    side_effect=blocking_verifier,
                ) as verifier:
                    result = asyncio.run(scenario())

        self.assertEqual(result, "default-ok")
        verifier.assert_called_once()

    def test_contract_wallet_registration_timeout_keeps_slot_until_worker_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["ETH_RPC_URL"] = "https://rpc.example"
            env["MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                started = threading.Event()
                unblock = threading.Event()
                wallet = "0x00000000000000000000000000000000000000aa"
                key_hash = "ab" * 32
                challenge = mycomesh.store.create_key_challenge(
                    wallet=wallet,
                    key_hash=key_hash,
                    chain_id=11155111,
                    nonce="kreg_timeout_test",
                )

                def blocking_verifier(**_kwargs: object) -> None:
                    started.set()
                    unblock.wait(2)

                async def scenario() -> tuple[HTTPException, float]:
                    nonce_claim = mycomesh._claim_inflight_key_registration_nonce("kreg_timeout_test")
                    verification_token = ""

                    def claim_verification():
                        nonlocal verification_token
                        claimed = mycomesh.store.claim_key_challenge_verification(
                            wallet=wallet,
                            key_hash=key_hash,
                            chain_id=11155111,
                            nonce=str(challenge["nonce"]),
                        )
                        verification_token = str(claimed["verification_token"])
                        nonce_claim.set_release_callback(
                            lambda: mycomesh.store.release_key_challenge_verification(
                                str(challenge["nonce"]),
                                verification_token,
                            )
                        )
                        return lambda: mycomesh.store.rollback_key_challenge_verification_claim(
                            str(challenge["nonce"]),
                            verification_token,
                        )

                    began = time.monotonic()
                    try:
                        await mycomesh._verify_key_registration_signature_async(
                            wallet=wallet,
                            message="challenge",
                            signature_payload="0x1234",
                            caller="0x0000000000000000000000000000000000000002",
                            nonce_claim=nonce_claim,
                            before_submit=claim_verification,
                        )
                    except HTTPException as exc:
                        raised = exc
                    else:
                        self.fail("registration RPC should have timed out")
                    elapsed = time.monotonic() - began
                    self.assertTrue(started.is_set())
                    nonce_claim.release()
                    persisted = mycomesh.store.get_key_challenge(str(challenge["nonce"]))
                    self.assertEqual(persisted["verification_token"], verification_token)
                    self.assertEqual(persisted["verification_attempts"], 1)
                    with self.assertRaises(HTTPException) as duplicate:
                        mycomesh._claim_inflight_key_registration_nonce("kreg_timeout_test")
                    self.assertEqual(duplicate.exception.status_code, 409)
                    self.assertFalse(mycomesh._key_registration_rpc_slots.acquire(blocking=False))
                    unblock.set()
                    reacquired = False
                    for _ in range(1_000):
                        if mycomesh._key_registration_rpc_slots.acquire(blocking=False):
                            reacquired = True
                            break
                        await asyncio.sleep(0.001)
                    self.assertTrue(reacquired)
                    mycomesh._key_registration_rpc_slots.release()
                    replacement_claim = None
                    for _ in range(1_000):
                        try:
                            replacement_claim = mycomesh._claim_inflight_key_registration_nonce("kreg_timeout_test")
                            break
                        except HTTPException as exc:
                            self.assertEqual(exc.status_code, 409)
                            await asyncio.sleep(0.001)
                    self.assertIsNotNone(replacement_claim)
                    replacement_claim.release()
                    cleared = None
                    for _ in range(1_000):
                        cleared = mycomesh.store.get_key_challenge(str(challenge["nonce"]))
                        if cleared["verification_token"] is None:
                            break
                        await asyncio.sleep(0.001)
                    self.assertIsNone(cleared["verification_token"])
                    self.assertEqual(cleared["verification_attempts"], 1)
                    return raised, elapsed

                with patch.object(
                    mycomesh,
                    "_configured_key_registration_rpc_timeout",
                    return_value=0.05,
                ), patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                    side_effect=blocking_verifier,
                ) as verifier:
                    raised, elapsed = asyncio.run(scenario())

        self.assertEqual(raised.status_code, 504)
        self.assertIn("deadline exceeded", str(raised.detail))
        self.assertLess(elapsed, 0.5)
        verifier.assert_called_once()

    def test_cancelled_contract_wallet_registration_releases_slot_after_worker_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["ETH_RPC_URL"] = "https://rpc.example"
            env["MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                started = threading.Event()
                unblock = threading.Event()

                def blocking_verifier(**_kwargs: object) -> None:
                    started.set()
                    unblock.wait(2)

                async def scenario() -> None:
                    nonce_claim = mycomesh._claim_inflight_key_registration_nonce("kreg_cancel_test")
                    registration = asyncio.create_task(
                        mycomesh._verify_key_registration_signature_async(
                            wallet="0x00000000000000000000000000000000000000aa",
                            message="challenge",
                            signature_payload="0x1234",
                            caller="0x0000000000000000000000000000000000000002",
                            nonce_claim=nonce_claim,
                        )
                    )
                    for _ in range(1_000):
                        if started.is_set():
                            break
                        await asyncio.sleep(0.001)
                    self.assertTrue(started.is_set())
                    registration.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await registration
                    nonce_claim.release()
                    with self.assertRaises(HTTPException) as duplicate:
                        mycomesh._claim_inflight_key_registration_nonce("kreg_cancel_test")
                    self.assertEqual(duplicate.exception.status_code, 409)
                    self.assertFalse(mycomesh._key_registration_rpc_slots.acquire(blocking=False))
                    unblock.set()
                    reacquired = False
                    for _ in range(1_000):
                        if mycomesh._key_registration_rpc_slots.acquire(blocking=False):
                            reacquired = True
                            break
                        await asyncio.sleep(0.001)
                    self.assertTrue(reacquired)
                    mycomesh._key_registration_rpc_slots.release()
                    replacement_claim = None
                    for _ in range(1_000):
                        try:
                            replacement_claim = mycomesh._claim_inflight_key_registration_nonce("kreg_cancel_test")
                            break
                        except HTTPException as exc:
                            self.assertEqual(exc.status_code, 409)
                            await asyncio.sleep(0.001)
                    self.assertIsNotNone(replacement_claim)
                    replacement_claim.release()

                with patch.object(
                    mycomesh,
                    "_configured_key_registration_rpc_timeout",
                    return_value=1.0,
                ), patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                    side_effect=blocking_verifier,
                ) as verifier:
                    asyncio.run(scenario())

        verifier.assert_called_once()

    def test_wallet_key_rotation_replaces_previous_client_key(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        first_key = "msk_first_client_secret"
        second_key = "msk_second_client_secret"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="http://localhost:8000")

                self._register_client_key(client, mycomesh, private_key, wallet, first_key)
                first_account = client.get("/account", headers={"Authorization": f"Bearer {first_key}"})
                self._register_client_key(client, mycomesh, private_key, wallet, second_key)
                old_key = client.get("/account", headers={"Authorization": f"Bearer {first_key}"})
                new_key = client.get("/account", headers={"Authorization": f"Bearer {second_key}"})

        self.assertEqual(first_account.status_code, 200)
        self.assertEqual(old_key.status_code, 401)
        self.assertEqual(new_key.status_code, 200)
        self.assertEqual(new_key.json()["account_id"], wallet)

    def test_consumer_can_revoke_only_its_current_key(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        api_key = "msk_client_revoked_secret"
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="http://localhost:8000")
                self._register_client_key(client, mycomesh, private_key, wallet, api_key)

                revoked = client.delete(
                    "/v1/mycomesh/keys/current",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                rejected = client.get(
                    "/account",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                stored = mycomesh.store.get_by_account(wallet)

        self.assertEqual(revoked.status_code, 200)
        self.assertTrue(revoked.json()["revoked"])
        self.assertEqual(revoked.json()["key_fingerprint"], hashlib.sha256(api_key.encode()).hexdigest()[:12])
        self.assertEqual(rejected.status_code, 401)
        self.assertIsNone(stored.key_fingerprint)

    def test_wallet_key_is_enforced_against_context_and_request_authority(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        api_key = "msk_exact_gateway_scope"
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, base_url="http://localhost:8000")
                auth = {"Authorization": f"Bearer {api_key}"}
                self._register_client_key(client, mycomesh, private_key, wallet, api_key)

                valid = client.get("/account", headers=auth)
                wrong_host = client.get("/account", headers={**auth, "Host": "other.localhost:8000"})
                os.environ["MYCOMESH_NETWORK_ID"] = "other-network"
                wrong_network = client.get("/account", headers=auth)
                os.environ["MYCOMESH_NETWORK_ID"] = "mycomesh-local-test"
                os.environ["MYCO_SETTLEMENT"] = "0x0000000000000000000000000000000000000003"
                wrong_settlement = client.get("/account", headers=auth)
                os.environ["MYCO_SETTLEMENT"] = "0x0000000000000000000000000000000000000002"
                os.environ["MYCOMESH_PUBLIC_GATEWAY_URL"] = "http://localhost:9000/v1"
                wrong_origin = client.get("/account", headers=auth)
                os.environ["MYCOMESH_PUBLIC_GATEWAY_URL"] = "http://localhost:8000/v1"
                restored = client.get("/account", headers=auth)

        self.assertEqual(valid.status_code, 200)
        self.assertEqual(wrong_host.status_code, 401)
        self.assertEqual(wrong_network.status_code, 401)
        self.assertEqual(wrong_settlement.status_code, 401)
        self.assertEqual(wrong_origin.status_code, 401)
        self.assertEqual(restored.status_code, 200)

    def test_public_gateway_url_is_required_even_in_local_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.pop("MYCOMESH_PUBLIC_GATEWAY_URL", None)
            env.pop("MYCOMESH_PUBLIC_URL", None)
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                discovery = client.get("/.well-known/mycomesh.json")
                challenge = client.post("/v1/mycomesh/keys/challenge", json={})

        self.assertEqual(discovery.status_code, 503)
        self.assertIn("MYCOMESH_PUBLIC_GATEWAY_URL is required", discovery.json()["detail"])
        self.assertEqual(challenge.status_code, 503)
        self.assertIn("MYCOMESH_PUBLIC_GATEWAY_URL is required", challenge.json()["detail"])

    def test_gateway_registry_discovery_outputs_public_node_urls(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._env(tmp_path, billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                registration = self._signed_gateway_descriptor(
                    identity,
                    public_url="https://gw-a.operator.example/v1",
                    sequence=1,
                    weight=10,
                )
                registered = client.post("/gateways", headers=ADMIN_HEADERS, json=registration)
                discovery = client.get("/v1/mycomesh/gateways")

        self.assertEqual(registered.status_code, 200)
        self.assertEqual(registered.json()["public_url"], "https://gw-a.operator.example/v1")
        self.assertEqual(discovery.status_code, 200)
        self.assertEqual(discovery.json()["recommended_base_url"], "http://localhost:8000/v1")
        self.assertNotIn("base_urls", discovery.json())
        self.assertEqual(discovery.json()["gateways"][0]["public_url"], "https://gw-a.operator.example/v1")
        self.assertEqual(
            discovery.json()["gateways"][0]["settlement"],
            "0x0000000000000000000000000000000000000002",
        )
        self.assertEqual(
            discovery.json()["gateways"][0]["credential_scope"],
            "origin_network_chain_settlement",
        )
        verified = verify_gateway_descriptor(
            discovery.json()["gateways"][0]["descriptor"],
            expected_network_id="mycomesh-local-test",
            expected_chain_id=11155111,
            expected_settlement="0x0000000000000000000000000000000000000002",
            expected_node_id=identity.peer_id,
            expected_public_key=identity.public_key,
        )
        self.assertEqual(verified["public_url"], "https://gw-a.operator.example/v1")
        recommended = discovery.json()["recommended_gateway"]
        recommended_verified = verify_gateway_descriptor(
            recommended["descriptor"],
            expected_network_id="mycomesh-local-test",
            expected_chain_id=11155111,
            expected_settlement="0x0000000000000000000000000000000000000002",
            allow_localhost=True,
        )
        self.assertEqual(recommended_verified["public_url"], discovery.json()["recommended_base_url"])
        self.assertEqual(recommended_verified["settlement"], discovery.json()["settlement"])

    def test_signed_gateway_registration_requires_admin_by_default(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                registration = sign_document(
                    {
                        "node_id": identity.peer_id,
                        "public_key": identity.public_key,
                        "public_url": "https://gw.operator.example/v1",
                    },
                    identity.private_key,
                    purpose=GATEWAY_REGISTRATION_PURPOSE,
                )

                response = client.post("/gateways", json=registration)

        self.assertEqual(response.status_code, 401)

    def test_public_self_registration_is_never_enabled_outside_local_profile(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.update(
                {
                    "MYCOMESH_NETWORK_PROFILE": "testnet",
                    "MYCOMESH_PUBLIC_GATEWAY_URL": "https://api.myco.example/v1",
                    "MYCOMESH_ALLOW_PUBLIC_GATEWAY_REGISTRATION": "1",
                }
            )
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                registration = self._signed_gateway_descriptor(
                    identity,
                    public_url="https://gw.operator.example/v1",
                    sequence=1,
                )

                response = client.post("/gateways", json=registration)

        self.assertEqual(response.status_code, 401)

    def test_gateway_descriptor_rejects_wrong_network_bounds_and_sequence_replay(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.update(
                {
                    "MYCOMESH_NETWORK_PROFILE": "testnet",
                    "MYCOMESH_PUBLIC_GATEWAY_URL": "https://api.myco.example/v1",
                }
            )
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                accepted = client.post(
                    "/gateways",
                    headers=ADMIN_HEADERS,
                    json=self._signed_gateway_descriptor(
                        identity,
                        public_url="https://gw-a.operator.example/v1",
                        sequence=10,
                    ),
                )
                replay_changed_url = client.post(
                    "/gateways",
                    headers=ADMIN_HEADERS,
                    json=self._signed_gateway_descriptor(
                        identity,
                        public_url="https://gw-b.operator.example/v1",
                        sequence=10,
                    ),
                )
                wrong_network = client.post(
                    "/gateways",
                    headers=ADMIN_HEADERS,
                    json=self._signed_gateway_descriptor(
                        identity,
                        public_url="https://gw-c.operator.example/v1",
                        sequence=11,
                        network_id="attacker-network",
                    ),
                )
                wrong_settlement = client.post(
                    "/gateways",
                    headers=ADMIN_HEADERS,
                    json=self._signed_gateway_descriptor(
                        identity,
                        public_url="https://gw-c.operator.example/v1",
                        sequence=11,
                        settlement="0x0000000000000000000000000000000000000003",
                    ),
                )
                oversized_weight = client.post(
                    "/gateways",
                    headers=ADMIN_HEADERS,
                    json=self._signed_gateway_descriptor(
                        identity,
                        public_url="https://gw-c.operator.example/v1",
                        sequence=11,
                        weight=101,
                    ),
                )
                listed_at_expiry = mycomesh.gateway_registry.list_gateways(
                    now=int(accepted.json()["expires_at"])
                )

        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(replay_changed_url.status_code, 400)
        self.assertIn("sequence must increase", replay_changed_url.json()["detail"])
        self.assertEqual(wrong_network.status_code, 400)
        self.assertIn("does not match", wrong_network.json()["detail"])
        self.assertEqual(wrong_settlement.status_code, 400)
        self.assertIn("settlement does not match", wrong_settlement.json()["detail"])
        self.assertEqual(oversized_weight.status_code, 400)
        self.assertIn("weight must be between", oversized_weight.json()["detail"])
        self.assertEqual(listed_at_expiry, [])

    def test_signed_gateway_descriptor_requires_complete_canonical_fields(self) -> None:
        identity = create_identity()
        now = int(time.time())
        complete = {
            "node_id": identity.peer_id,
            "public_key": identity.public_key,
            "public_url": "https://gw.example/v1",
            "network_id": "mycomesh-local-test",
            "chain_id": 11155111,
            "settlement": "0x0000000000000000000000000000000000000002",
            "sequence": 1,
            "expires_at": now + 300,
            "status": "active",
            "weight": 1,
            "capacity": 100,
            "role": "gateway_bridge",
        }
        missing_role = sign_document(
            {key: value for key, value in complete.items() if key != "role"},
            identity.private_key,
            purpose=GATEWAY_REGISTRATION_PURPOSE,
            timestamp=now,
        )
        noncanonical_url = sign_document(
            {**complete, "public_url": "HTTPS://GW.Example:443/"},
            identity.private_key,
            purpose=GATEWAY_REGISTRATION_PURPOSE,
            timestamp=now,
        )
        missing_settlement = sign_document(
            {key: value for key, value in complete.items() if key != "settlement"},
            identity.private_key,
            purpose=GATEWAY_REGISTRATION_PURPOSE,
            timestamp=now,
        )

        with self.assertRaisesRegex(GatewayRegistryError, "missing required fields: role"):
            verify_gateway_registration(missing_role, now=now)
        with self.assertRaisesRegex(GatewayRegistryError, "must already be canonical"):
            verify_gateway_registration(noncanonical_url, now=now)
        with self.assertRaisesRegex(GatewayRegistryError, "missing required fields: settlement"):
            verify_gateway_registration(missing_settlement, now=now)

    def test_gateway_descriptor_consumption_uses_expiry_with_bounded_lifetime(self) -> None:
        identity = create_identity()
        now = 2_000_000_000

        def descriptor(*, expires_at: int, timestamp: int = now) -> dict[str, object]:
            return sign_document(
                {
                    "node_id": identity.peer_id,
                    "public_key": identity.public_key,
                    "public_url": "https://gw.example/v1",
                    "network_id": "mycomesh-testnet",
                    "chain_id": 11155111,
                    "settlement": "0x0000000000000000000000000000000000000002",
                    "sequence": 1,
                    "expires_at": expires_at,
                    "status": "active",
                    "weight": 1,
                    "capacity": 100,
                    "role": "gateway_bridge",
                },
                identity.private_key,
                purpose=GATEWAY_REGISTRATION_PURPOSE,
                timestamp=timestamp,
            )

        valid = descriptor(expires_at=now + 900)
        verified = verify_gateway_descriptor(
            valid,
            expected_network_id="mycomesh-testnet",
            expected_chain_id=11155111,
            now=now + 600,
        )
        self.assertEqual(verified["public_url"], "https://gw.example/v1")
        with self.assertRaisesRegex(GatewayRegistryError, "signature expired"):
            verify_gateway_registration(valid, now=now + 600)
        with self.assertRaisesRegex(GatewayRegistryError, "has expired"):
            verify_gateway_descriptor(valid, now=now + 900)
        with self.assertRaisesRegex(GatewayRegistryError, "signed lifetime"):
            verify_gateway_descriptor(
                descriptor(expires_at=now + MAX_GATEWAY_TTL_SECONDS + 1),
                now=now,
            )
        other_identity = create_identity()
        with self.assertRaisesRegex(GatewayRegistryError, "pinned trust anchor"):
            verify_gateway_descriptor(valid, expected_node_id=other_identity.peer_id, now=now)
        with self.assertRaisesRegex(GatewayRegistryError, "pinned trust anchor"):
            verify_gateway_descriptor(valid, expected_public_key=other_identity.public_key, now=now)
        with self.assertRaisesRegex(GatewayRegistryError, "timestamp is in the future"):
            verify_gateway_descriptor(
                descriptor(expires_at=now + 300, timestamp=now + 31),
                now=now,
            )

    def test_self_reported_weight_cannot_replace_canonical_recommendation(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.update(
                {
                    "MYCOMESH_NETWORK_PROFILE": "testnet",
                    "MYCOMESH_PUBLIC_GATEWAY_URL": "https://api.myco.example/v1",
                }
            )
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                registered = client.post(
                    "/gateways",
                    headers=ADMIN_HEADERS,
                    json=self._signed_gateway_descriptor(
                        identity,
                        public_url="https://attacker.operator.example/v1",
                        sequence=1,
                        weight=100,
                    ),
                )
                discovery = client.get("/v1/mycomesh/gateways")

        self.assertEqual(registered.status_code, 200)
        self.assertEqual(discovery.status_code, 200)
        self.assertEqual(discovery.json()["recommended_base_url"], "https://api.myco.example/v1")

    def test_gateway_url_validation_rejects_credential_smuggling_and_private_addresses(self) -> None:
        rejected = (
            "https://user:secret@gw.example/v1",
            "https://gw.example/v1?next=https://evil.example",
            "https://gw.example/v1#evil",
            "https://127.0.0.1/v1",
            "https://192.168.1.20/v1",
            "https://metadata.internal/v1",
            "https://127.1/v1",
            "https://0177.0.0.1/v1",
            "https://0x7f.0.0.1/v1",
            "https://0x7f.1/v1",
            "https://0x7f000001/v1",
            "https://bad_label.example/v1",
            "https://-bad.example/v1",
            "https://good.example\\evil/v1",
            "https://good.example\nevil/v1",
            " https://good.example/v1",
            "http://gw.example/v1",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(GatewayRegistryError):
                normalize_gateway_url(value)
        self.assertEqual(normalize_gateway_url("HTTPS://GW.Example:443/"), "https://gw.example/v1")
        self.assertEqual(
            normalize_gateway_url("http://127.0.0.1:8000", allow_localhost=True),
            "http://127.0.0.1:8000/v1",
        )

    def test_invalid_configured_public_url_fails_discovery_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["MYCOMESH_PUBLIC_GATEWAY_URL"] = "http://192.168.1.10:8000/v1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                response = TestClient(mycomesh.app).get("/v1/mycomesh/gateways")

        self.assertEqual(response.status_code, 503)
        self.assertIn("invalid public gateway URL", response.json()["detail"])

    def test_key_challenge_ttl_is_bounded_and_signature_is_context_bound(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        key_hash = hashlib.sha256(b"origin-bound-key").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                excessive = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash, "chain_id": 11155111, "ttl_seconds": 901},
                )
                challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash, "chain_id": 11155111},
                ).json()
                signature = sign_evm_digest(
                    private_key,
                    mycomesh._personal_sign_digest(challenge["message"].encode("utf-8")),
                )
                replays = []
                for variable, changed_value, changed_chain_id in (
                    ("MYCOMESH_PUBLIC_GATEWAY_URL", "http://localhost:9000/v1", 11155111),
                    ("MYCOMESH_NETWORK_ID", "other-network", 11155111),
                    ("ETH_CHAIN_ID", "11155112", 11155112),
                    ("MYCO_SETTLEMENT", "0x0000000000000000000000000000000000000003", 11155111),
                ):
                    original = os.environ[variable]
                    os.environ[variable] = changed_value
                    try:
                        replays.append(
                            client.post(
                                "/v1/mycomesh/keys/register",
                                json={
                                    "wallet": wallet,
                                    "key_hash": key_hash,
                                    "chain_id": changed_chain_id,
                                    "nonce": challenge["nonce"],
                                    "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
                                },
                            )
                        )
                    finally:
                        os.environ[variable] = original

        self.assertEqual(excessive.status_code, 400)
        self.assertEqual([response.status_code for response in replays], [403, 403, 400, 403])

    def test_key_challenge_expiry_boundary_and_concurrent_registration_single_flight(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        key_hash = hashlib.sha256(b"atomic-key-registration").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)

                with patch("gateway.billing.time.time", return_value=100):
                    expiring = client.post(
                        "/v1/mycomesh/keys/challenge",
                        json={"wallet": wallet, "key_hash": key_hash, "ttl_seconds": 30},
                    ).json()
                expiring_signature = sign_evm_digest(
                    private_key,
                    mycomesh._personal_sign_digest(expiring["message"].encode("utf-8")),
                )
                with patch("gateway.billing.time.time", return_value=expiring["expires_at"]), patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                ) as expired_verifier:
                    at_expiry = client.post(
                        "/v1/mycomesh/keys/register",
                        json={
                            "wallet": wallet,
                            "key_hash": key_hash,
                            "nonce": expiring["nonce"],
                            "signature": {
                                "r": expiring_signature.r,
                                "s": expiring_signature.s,
                                "v": expiring_signature.v,
                            },
                        },
                    )

                concurrent = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash},
                ).json()
                concurrent_signature = sign_evm_digest(
                    private_key,
                    mycomesh._personal_sign_digest(concurrent["message"].encode("utf-8")),
                )
                registration = {
                    "wallet": wallet,
                    "key_hash": key_hash,
                    "nonce": concurrent["nonce"],
                    "signature": {
                        "r": concurrent_signature.r,
                        "s": concurrent_signature.s,
                        "v": concurrent_signature.v,
                    },
                }
                verifier_started = threading.Event()
                unblock_verifier = threading.Event()
                original_verify = mycomesh._verify_key_registration_signature

                def synchronized_verify(**kwargs: object) -> None:
                    verifier_started.set()
                    unblock_verifier.wait(timeout=5)
                    original_verify(**kwargs)

                responses: list[tuple[int, dict[str, object]]] = []
                response_lock = threading.Lock()

                def register_once() -> None:
                    response = TestClient(mycomesh.app).post("/v1/mycomesh/keys/register", json=registration)
                    with response_lock:
                        responses.append((response.status_code, response.json()))

                with patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                    side_effect=synchronized_verify,
                ) as verifier:
                    first = threading.Thread(target=register_once)
                    second = threading.Thread(target=register_once)
                    first.start()
                    self.assertTrue(verifier_started.wait(timeout=5))
                    second.start()
                    second.join(timeout=5)
                    self.assertFalse(second.is_alive())
                    unblock_verifier.set()
                    first.join(timeout=5)
                    self.assertFalse(first.is_alive())

        self.assertEqual(at_expiry.status_code, 400)
        expired_verifier.assert_not_called()
        self.assertIn("expired", at_expiry.json()["detail"])
        self.assertEqual(sorted(status for status, _payload in responses), [200, 409])
        self.assertEqual(len(responses), 2)
        rejected = next(payload for status, payload in responses if status == 409)
        self.assertIn("already in progress", str(rejected["detail"]))
        verifier.assert_called_once()

    def test_key_registration_verification_attempt_limit_blocks_additional_rpc(self) -> None:
        wallet = "0x00000000000000000000000000000000000000a1"
        key_hash = hashlib.sha256(b"bounded-registration-attempts").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["MYCOMESH_KEY_REGISTRATION_MAX_ATTEMPTS"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash},
                ).json()
                registration = {
                    "wallet": wallet,
                    "key_hash": key_hash,
                    "nonce": challenge["nonce"],
                    "signature": "0x1234",
                }
                with patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                    side_effect=HTTPException(status_code=403, detail="invalid signature"),
                ) as verifier:
                    first = client.post("/v1/mycomesh/keys/register", json=registration)
                    second = client.post("/v1/mycomesh/keys/register", json=registration)
                stored = mycomesh.store.get_key_challenge(challenge["nonce"])

        self.assertEqual(first.status_code, 403)
        self.assertEqual(second.status_code, 429)
        self.assertIn("attempt limit", second.json()["detail"])
        self.assertEqual(stored["verification_attempts"], 1)
        self.assertIsNone(stored["verification_token"])
        verifier.assert_called_once()

    def test_rpc_capacity_rejection_does_not_consume_verification_attempt(self) -> None:
        wallet = "0x00000000000000000000000000000000000000a1"
        key_hash = hashlib.sha256(b"capacity-does-not-burn-attempt").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["MYCOMESH_KEY_REGISTRATION_MAX_ATTEMPTS"] = "1"
            env["MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app)
                challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash},
                ).json()
                registration = {
                    "wallet": wallet,
                    "key_hash": key_hash,
                    "nonce": challenge["nonce"],
                    "signature": "0x1234",
                }
                self.assertTrue(mycomesh._key_registration_rpc_slots.acquire(blocking=False))
                try:
                    denied = client.post("/v1/mycomesh/keys/register", json=registration)
                    after_denial = mycomesh.store.get_key_challenge(challenge["nonce"])
                finally:
                    mycomesh._key_registration_rpc_slots.release()
                with patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                    side_effect=HTTPException(status_code=403, detail="invalid signature"),
                ) as verifier:
                    attempted = client.post("/v1/mycomesh/keys/register", json=registration)
                after_attempt = mycomesh.store.get_key_challenge(challenge["nonce"])

        self.assertEqual(denied.status_code, 503)
        self.assertEqual(after_denial["verification_attempts"], 0)
        self.assertIsNone(after_denial["verification_token"])
        self.assertEqual(attempted.status_code, 403)
        self.assertEqual(after_attempt["verification_attempts"], 1)
        verifier.assert_called_once()

    def test_executor_submission_failure_does_not_consume_verification_attempt(self) -> None:
        wallet = "0x00000000000000000000000000000000000000a1"
        key_hash = hashlib.sha256(b"submission-failure-does-not-burn-attempt").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env["MYCOMESH_KEY_REGISTRATION_MAX_ATTEMPTS"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                client = TestClient(mycomesh.app, raise_server_exceptions=False)
                challenge = client.post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": key_hash},
                ).json()
                registration = {
                    "wallet": wallet,
                    "key_hash": key_hash,
                    "nonce": challenge["nonce"],
                    "signature": "0x1234",
                }
                with patch.object(
                    mycomesh._key_registration_rpc_executor,
                    "submit",
                    side_effect=RuntimeError("executor unavailable"),
                ):
                    failed_submission = client.post(
                        "/v1/mycomesh/keys/register",
                        json=registration,
                    )
                after_submission_failure = mycomesh.store.get_key_challenge(challenge["nonce"])
                with patch.object(
                    mycomesh,
                    "_verify_key_registration_signature",
                    side_effect=HTTPException(status_code=403, detail="invalid signature"),
                ) as verifier:
                    attempted = client.post("/v1/mycomesh/keys/register", json=registration)
                after_attempt = mycomesh.store.get_key_challenge(challenge["nonce"])

        self.assertEqual(failed_submission.status_code, 503)
        self.assertIn("executor is unavailable", failed_submission.json()["detail"])
        self.assertEqual(after_submission_failure["verification_attempts"], 0)
        self.assertIsNone(after_submission_failure["verification_token"])
        self.assertEqual(attempted.status_code, 403)
        self.assertEqual(after_attempt["verification_attempts"], 1)
        verifier.assert_called_once()

    def test_public_key_registration_defaults_disabled_outside_local_profile(self) -> None:
        private_key = "0x" + "0" * 63 + "1"
        wallet = private_key_to_address(parse_private_key(private_key))
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            env.update(
                {
                    "MYCOMESH_NETWORK_PROFILE": "testnet",
                    "MYCOMESH_PUBLIC_GATEWAY_URL": "https://api.myco.example/v1",
                }
            )
            env.pop("MYCOMESH_PUBLIC_KEY_REGISTRATION", None)
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                response = TestClient(mycomesh.app).post(
                    "/v1/mycomesh/keys/challenge",
                    json={"wallet": wallet, "key_hash": hashlib.sha256(b"key").hexdigest()},
                )

        self.assertEqual(response.status_code, 403)

    def test_onchain_serving_checks_freshness_for_authenticated_account_only(self) -> None:
        settlement = "0x0000000000000000000000000000000000000002"
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="onchain-prepaid")
            env["MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE"] = "1"
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                first = mycomesh.store.create_account(
                    "acct-a", payment_address="0x0000000000000000000000000000000000000001"
                )
                mycomesh.store.create_account(
                    "acct-b", payment_address="0x0000000000000000000000000000000000000002"
                )
                mycomesh.store.sync_chain_balance(
                    first.account_id,
                    1_000_000,
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=100,
                    synced_block=95,
                    confirmations=5,
                    source="events",
                    synced_block_hash="0x" + "aa" * 32,
                )
                mycomesh.store.set_chain_sync_state(
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=100,
                    synced_block=95,
                    confirmations=5,
                    source="events",
                    synced_block_hash="0x" + "aa" * 32,
                )

                with self.assertRaises(HTTPException) as underconfirmed:
                    mycomesh._require_serving_billing_mode("acct-a")
                mycomesh.store.sync_chain_balance(
                    first.account_id,
                    1_000_000,
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=101,
                    synced_block=95,
                    confirmations=6,
                    source="events",
                    synced_block_hash="0x" + "aa" * 32,
                )
                mycomesh.store.set_chain_sync_state(
                    chain_id=11155111,
                    settlement=settlement,
                    latest_block=101,
                    synced_block=95,
                    confirmations=6,
                    source="events",
                    synced_block_hash="0x" + "aa" * 32,
                )
                mycomesh._require_serving_billing_mode("acct-a")
                with self.assertRaises(HTTPException) as denied:
                    mycomesh._require_serving_billing_mode("acct-b")

        self.assertIn("insufficient confirmations", str(underconfirmed.exception.detail))
        self.assertIn("acct-b", str(denied.exception.detail))

    def test_receipt_export_failure_releases_transactional_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), billing_mode="local")
            with patch.dict(os.environ, env, clear=True):
                mycomesh = importlib.reload(importlib.import_module("gateway.mycomesh"))
                account = mycomesh.store.create_account("acct-a")
                mycomesh.store.deposit(account.account_id, "1.00")
                mycomesh.store.reserve(account.account_id, 250_000, "res-1")
                mycomesh.store.capture(
                    "res-1",
                    250_000,
                    "event-1",
                    outbox_payload={"job_id": "event-1"},
                )

                with patch.object(mycomesh, "append_receipt_payload_once", side_effect=OSError("disk full")):
                    with self.assertRaisesRegex(OSError, "disk full"):
                        mycomesh._export_pending_receipts()
                reclaimed = mycomesh.store.pending_receipts()

        self.assertEqual(len(reclaimed), 1)
        self.assertEqual(reclaimed[0]["receipt_id"], "event-1")
        self.assertEqual(reclaimed[0]["attempt_count"], 2)

    def _v3_deployment(self) -> V3Deployment:
        return V3Deployment(
            protocol_version=3,
            chain_id=11155111,
            deployer="0x" + "aa" * 20,
            test_usdc="0x" + "bb" * 20,
            stablecoin="0x" + "bb" * 20,
            settlement="0x" + "22" * 20,
            token="0x" + "cc" * 20,
            treasury="0x" + "dd" * 20,
            governance="0x" + "ee" * 20,
            max_consumer_rebate_bps=1_000,
            max_supply=10**27,
            channel="codex-standard-v1",
            channel_hash=DEFAULT_CHANNEL_HASH,
            pricing_version=1,
            pricing_hash="0x" + "13" * 32,
        )

    def _v3_env(
        self,
        tmp_path: Path,
        deployment: V3Deployment,
        *,
        billing_mode: str,
    ) -> dict[str, str]:
        manifest = tmp_path / "sepolia-myco-v3.json"
        save_v3_deployment(manifest, deployment)
        env = self._env(tmp_path, billing_mode=billing_mode)
        for name in (
            "ETH_CHAIN_ID",
            "MYCOMESH_SETTLEMENT_CHAIN_ID",
            "MYCOMESH_PRICING_VERSION",
            "MYCO_DEPLOYER",
            "MYCO_TEST_USDC",
            "MYCO_STABLECOIN",
            "MYCO_SETTLEMENT",
            "MYCOMESH_SETTLEMENT_CONTRACT",
            "MYCO_TOKEN",
            "MYCO_TREASURY",
            "TREASURY",
            "MYCOMESH_GOVERNANCE",
            "GOVERNANCE",
            "MYCO_CHANNEL_HASH",
            "MYCOMESH_CHANNEL_PRICING_HASH",
            "MYCOMESH_PROVIDER_PRICING_HASH",
            "MYCO_PRICING_HASH",
        ):
            env.pop(name, None)
        env.update(
            {
                "MYCOMESH_SETTLEMENT_VERSION": "3",
                "MYCO_DEPLOYMENT": str(manifest),
            }
        )
        return env

    def _register_client_key(self, client: TestClient, mycomesh: object, private_key: str, wallet: str, api_key: str) -> None:
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        challenge = client.post(
            "/v1/mycomesh/keys/challenge",
            json={"wallet": wallet, "key_hash": key_hash, "chain_id": 11155111},
        ).json()
        signature = sign_evm_digest(private_key, mycomesh._personal_sign_digest(challenge["message"].encode("utf-8")))
        response = client.post(
            "/v1/mycomesh/keys/register",
            json={
                "wallet": wallet,
                "key_hash": key_hash,
                "chain_id": 11155111,
                "nonce": challenge["nonce"],
                "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
            },
        )
        self.assertEqual(response.status_code, 200)

    def _signed_gateway_descriptor(
        self,
        identity: object,
        *,
        public_url: str,
        sequence: int,
        network_id: str = "mycomesh-local-test",
        settlement: str = "0x0000000000000000000000000000000000000002",
        weight: int = 1,
    ) -> dict[str, object]:
        return sign_document(
            {
                "node_id": identity.peer_id,
                "public_key": identity.public_key,
                "public_url": public_url,
                "network_id": network_id,
                "chain_id": 11155111,
                "settlement": settlement,
                "sequence": sequence,
                "expires_at": int(time.time()) + 300,
                "status": "active",
                "weight": weight,
                "capacity": 100,
                "role": "gateway_bridge",
            },
            identity.private_key,
            purpose=GATEWAY_REGISTRATION_PURPOSE,
        )

    def _env(self, tmp_path: Path, *, billing_mode: str) -> dict[str, str]:
        return {
            **os.environ,
            "MYCOMESH_ADMIN_TOKEN": TEST_ADMIN_TOKEN,
            "MYCOMESH_BILLING_DB": str(tmp_path / "billing.sqlite3"),
            "MYCOMESH_GATEWAY_REGISTRY_DB": str(tmp_path / "gateways.sqlite3"),
            "MYCOMESH_BILLING_MODE": billing_mode,
            "MYCOMESH_REQUEST_IDENTITY": str(tmp_path / "request-identity.json"),
            "MYCOMESH_NETWORK_PROFILE": "local",
            "MYCOMESH_NETWORK_ID": "mycomesh-local-test",
            "MYCOMESH_PUBLIC_GATEWAY_URL": "http://localhost:8000/v1",
            "ETH_RPC_URL": "",
            "ETH_CHAIN_ID": "11155111",
            "MYCO_SETTLEMENT": "0x0000000000000000000000000000000000000002",
        }


if __name__ == "__main__":
    unittest.main()
