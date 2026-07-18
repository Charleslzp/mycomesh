from __future__ import annotations

import hashlib
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import create_identity, sign_document
from gateway.p2p import (
    DEFAULT_CHANNEL,
    INFERENCE_REQUEST_PURPOSE,
    ProviderConfig,
    _inference_request_hash,
    _preverify_inference_request,
    provider_descriptor,
    verify_inference_request,
)
import gateway.p2p as p2p
from gateway.session_protocol import (
    build_session_authorization,
    build_session_request,
    session_authorization_hash,
)
from gateway.replay import ReplayError


class ProviderSessionV4Test(unittest.TestCase):
    def setUp(self) -> None:
        self.provider_identity = create_identity()
        self.consumer_identity = create_identity()
        self.session_private_key = "0x" + "11" * 32
        self.consumer_private_key = "0x" + "22" * 32
        self.provider_private_key = "0x" + "33" * 32
        self.session_key = private_key_to_address(parse_private_key(self.session_private_key))
        self.consumer_address = private_key_to_address(parse_private_key(self.consumer_private_key))
        self.provider_address = private_key_to_address(parse_private_key(self.provider_private_key))
        self.contract = "0x" + "44" * 20
        self.pricing_hash = "0x" + "aa" * 32
        self.now = int(time.time())

    def _config(self, replay_path: str) -> ProviderConfig:
        return ProviderConfig(
            peer_id=self.provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="provider",
            agent_key="agent-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="test-model",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=self.provider_identity,
            payment_address=self.provider_address,
            network_profile="local",
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract=self.contract,
            settlement_chain_id=11155111,
            settlement_version=4,
            pricing_version=1,
            pricing_hash=self.pricing_hash,
            replay_store_path=replay_path,
            session_v4_verify_onchain=False,
        )

    def _message(
        self,
        config: ProviderConfig,
        *,
        request_id: str,
        sequence: int,
        previous_spend: int,
        auth: dict,
        max_fee_units: int = 1_000,
        deadline: int | None = None,
    ) -> dict:
        unsigned = {
            "type": "infer",
            "request_id": request_id,
            "channel": DEFAULT_CHANNEL,
            "endpoint": "responses",
            "model": "test-model",
            "input": "hello",
            "max_output_tokens": 4,
            "session_v4": True,
        }
        request_hash = "0x" + _inference_request_hash(config, unsigned, 4)
        request = build_session_request(
            authorization=auth,
            request_id=request_id,
            request_hash=request_hash,
            max_fee_units=max_fee_units,
            deadline=deadline or self.now + 300,
            sequence=sequence,
            previous_cumulative_spend_units=previous_spend,
            signer=self.consumer_identity,
            session_private_key=self.session_private_key,
            now=self.now,
        )
        unsigned.update({"session_authorization": auth, "session_request": request})
        return sign_document(
            unsigned,
            self.consumer_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=config.peer_id,
            timestamp=self.now,
        )

    def test_completed_retry_allows_refreshed_request_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            auth = self._auth(config, "0x" + "8a" * 32)
            first_message = self._message(
                config,
                request_id="v4-refreshed-deadline",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
                deadline=self.now + 300,
            )
            retry_message = self._message(
                config,
                request_id="v4-refreshed-deadline",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
                deadline=self.now + 600,
            )
            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    side_effect=lambda *, reservation, **_kwargs: {
                        "schema": "test.v4.receipt",
                        "sequence": 0,
                        "receipt": {
                            "deadline": int(reservation["settlement_deadline"]),
                        },
                    },
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "deadline-safe", "usage": {"total_tokens": 2}},
                ) as gateway_call,
            ):
                first = p2p.handle_message(config, first_message)
                retry = p2p.handle_message(config, retry_message)

            self.assertTrue(first["ok"])
            self.assertTrue(retry["ok"])
            self.assertEqual(retry["output_text"], first["output_text"])
            self.assertNotEqual(retry["signature"], first["signature"])
            self.assertEqual(
                retry["mycomesh_v4_settlement"]["receipt"]["deadline"],
                self.now + 600,
            )
            self.assertEqual(
                retry["provider_settlement_attestation"]["settlement_deadline"],
                self.now + 600,
            )
            self.assertEqual(gateway_call.call_count, 1)

    def test_completed_retry_accepts_rebuilt_authorization_signature(self) -> None:
        """Randomized authorization signatures must not invalidate a retry."""
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            session_id = "0x" + "89" * 32
            first_auth = self._auth(config, session_id)
            retry_auth = self._auth(config, session_id)
            self.assertNotEqual(
                session_authorization_hash(first_auth),
                session_authorization_hash(retry_auth),
            )
            first_message = self._message(
                config,
                request_id="v4-refreshed-authorization",
                sequence=1,
                previous_spend=0,
                auth=first_auth,
                max_fee_units=10_000,
                deadline=self.now + 600,
            )
            retry_message = self._message(
                config,
                request_id="v4-refreshed-authorization",
                sequence=1,
                previous_spend=0,
                auth=retry_auth,
                max_fee_units=10_000,
                deadline=self.now + 600,
            )
            first_checked = _preverify_inference_request(config, first_message)
            retry_checked = _preverify_inference_request(config, retry_message)
            original_authorization_hash = first_checked["reservation"]["authorization_hash"]
            response = sign_document(
                {
                    "type": "infer_result",
                    "ok": True,
                    "request_id": "v4-refreshed-authorization",
                    "mycomesh_v4_settlement": {
                        "receipt": {"deadline": self.now + 600},
                    },
                    "provider_settlement_attestation": {
                        "authorization_hash": original_authorization_hash,
                    },
                },
                config.identity.private_key,
                purpose=p2p.PROVIDER_RESPONSE_PURPOSE,
                audience=retry_checked["consumer_public_key"],
            )
            cached = p2p._v4_execution_envelope(
                first_checked,
                response,
                provider_peer_id=config.peer_id,
                committed_cumulative_spend_units=2_000,
            )
            payload = p2p._canonical_v4_execution_payload(cached)
            claim = SimpleNamespace(
                result_payload=payload,
                result_hash=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            )

            with patch.object(
                p2p,
                "_build_v4_provider_settlement",
                return_value={
                    "schema": "test.v4.receipt",
                    "receipt": {"deadline": self.now + 600},
                },
            ):
                replayed = p2p._decode_v4_execution_response(config, retry_checked, claim)

            self.assertTrue(replayed["ok"])
            self.assertEqual(
                replayed["provider_settlement_attestation"]["authorization_hash"],
                retry_checked["reservation"]["authorization_hash"],
            )

    def test_completed_retry_accepts_legacy_hash_with_cached_receipt_deadline(self) -> None:
        """A result written before the deadline-refresh fix remains replayable."""
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            session_id = "0x" + "8b" * 32
            first_auth = self._auth(config, session_id)
            retry_auth = self._auth(config, session_id)
            self.assertNotEqual(
                session_authorization_hash(first_auth),
                session_authorization_hash(retry_auth),
            )
            first_message = self._message(
                config,
                request_id="v4-legacy-hash",
                sequence=1,
                previous_spend=0,
                auth=first_auth,
                max_fee_units=10_000,
                deadline=self.now + 300,
            )
            retry_message = self._message(
                config,
                request_id="v4-legacy-hash",
                sequence=1,
                previous_spend=0,
                auth=retry_auth,
                max_fee_units=10_000,
                deadline=self.now + 600,
            )
            first_checked = _preverify_inference_request(config, first_message)
            retry_checked = _preverify_inference_request(config, retry_message)
            response = {
                "type": "infer_result",
                "ok": True,
                "request_id": "v4-legacy-hash",
                "mycomesh_v4_settlement": {
                    "receipt": {"deadline": self.now + 300},
                },
                "provider_settlement_attestation": {
                    "authorization_hash": first_checked["reservation"]["authorization_hash"],
                },
            }
            response = sign_document(
                response,
                config.identity.private_key,
                purpose=p2p.PROVIDER_RESPONSE_PURPOSE,
                audience=retry_checked["consumer_public_key"],
            )
            cached = p2p._v4_execution_envelope(
                first_checked,
                response,
                provider_peer_id=config.peer_id,
                committed_cumulative_spend_units=2_000,
            )
            cached["session_request_hash"] = p2p._v4_legacy_session_request_hash(
                first_checked["reservation"]["session_request"]
            )
            cached.pop("session_request_hash_version")
            payload = p2p._canonical_v4_execution_payload(cached)
            claim = SimpleNamespace(
                result_payload=payload,
                result_hash=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            )

            with patch.object(
                p2p,
                "_build_v4_provider_settlement",
                return_value={
                    "schema": "test.v4.receipt",
                    "receipt": {"deadline": self.now + 600},
                },
            ):
                replayed = p2p._decode_v4_execution_response(config, retry_checked, claim)

            self.assertTrue(replayed["ok"])
            self.assertEqual(
                replayed["mycomesh_v4_settlement"]["receipt"]["deadline"],
                self.now + 600,
            )

    def test_completed_retry_refreshes_expired_receipt_without_gateway_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            auth = self._auth(config, "0x" + "8d" * 32)
            message = self._message(
                config,
                request_id="v4-expired-receipt",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
                deadline=self.now + 600,
            )
            settlement_calls = 0

            def settlement_with_expiry(*, reservation, **_kwargs) -> dict:
                nonlocal settlement_calls
                settlement_calls += 1
                deadline = self.now - 1 if settlement_calls == 1 else int(
                    reservation["settlement_deadline"]
                )
                return {
                    "schema": "test.v4.receipt",
                    "sequence": 0,
                    "receipt": {"deadline": deadline},
                }

            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    side_effect=settlement_with_expiry,
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "expired-safe", "usage": {"total_tokens": 2}},
                ) as gateway_call,
            ):
                first = p2p.handle_message(config, message)
                refreshed = p2p.handle_message(config, message)

            self.assertTrue(first["ok"])
            self.assertTrue(refreshed["ok"])
            self.assertEqual(refreshed["output_text"], first["output_text"])
            self.assertEqual(
                refreshed["mycomesh_v4_settlement"]["receipt"]["deadline"],
                self.now + 600,
            )
            self.assertEqual(gateway_call.call_count, 1)
            self.assertEqual(settlement_calls, 2)

    def test_cached_receipt_refreshes_stale_outer_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            auth = self._auth(config, "0x" + "8e" * 32)
            message = self._message(
                config,
                request_id="v4-stale-signature",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
                deadline=self.now + 600,
            )
            checked = _preverify_inference_request(config, message)
            cached = {
                "type": "infer_result",
                "ok": True,
                "request_id": "v4-stale-signature",
                "channel": DEFAULT_CHANNEL,
                "endpoint": "responses",
                "model": "test-model",
                "output_text": "stale-safe",
                "usage": {"total_tokens": 2},
                "provider_signature": {
                    "peer_id": config.peer_id,
                    "public_key": config.identity.public_key,
                },
                "quality": {"request_hash": checked["request_hash"]},
                "mycomesh_v4_settlement": {
                    "receipt": {"deadline": self.now + 600},
                },
            }
            stale = sign_document(
                cached,
                config.identity.private_key,
                purpose=p2p.PROVIDER_RESPONSE_PURPOSE,
                audience=checked["consumer_public_key"],
                timestamp=self.now - 300,
            )
            with patch.object(
                p2p,
                "_build_v4_provider_settlement",
                return_value={
                    "schema": "test.v4.receipt",
                    "receipt": {"deadline": self.now + 600},
                },
            ):
                refreshed = p2p._refresh_v4_cached_response(
                    config,
                    checked,
                    stale,
                    committed_cumulative_spend_units=2_000,
                )

            self.assertGreater(
                int(refreshed["signature"]["timestamp"]),
                int(stale["signature"]["timestamp"]),
            )
            self.assertEqual(refreshed["output_text"], "stale-safe")

    def test_completed_retry_rejects_unproven_legacy_hash_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            auth = self._auth(config, "0x" + "8c" * 32)
            first_message = self._message(
                config,
                request_id="v4-legacy-hash-invalid",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
                deadline=self.now + 300,
            )
            retry_message = self._message(
                config,
                request_id="v4-legacy-hash-invalid",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
                deadline=self.now + 600,
            )
            first_checked = _preverify_inference_request(config, first_message)
            retry_checked = _preverify_inference_request(config, retry_message)
            response = {
                "type": "infer_result",
                "ok": True,
                "request_id": "v4-legacy-hash-invalid",
                "mycomesh_v4_settlement": {
                    "receipt": {"deadline": self.now + 301},
                },
            }
            cached = p2p._v4_execution_envelope(
                first_checked,
                response,
                provider_peer_id=config.peer_id,
                committed_cumulative_spend_units=2_000,
            )
            cached["session_request_hash"] = p2p._v4_legacy_session_request_hash(
                first_checked["reservation"]["session_request"]
            )
            cached.pop("session_request_hash_version")
            payload = p2p._canonical_v4_execution_payload(cached)
            claim = SimpleNamespace(
                result_payload=payload,
                result_hash=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            )

            with self.assertRaisesRegex(
                p2p.P2PError,
                "completed Settlement V4 execution does not match the retried request",
            ):
                p2p._decode_v4_execution_response(config, retry_checked, claim)

    def _auth(self, config: ProviderConfig, session_id: str) -> dict:
        return build_session_authorization(
            session_id=session_id,
            session_key=self.session_key,
            consumer_payment_address=self.consumer_address,
            provider_id=config.peer_id,
            provider_payment_address=self.provider_address,
            channel=DEFAULT_CHANNEL,
            pricing_version=1,
            pricing_hash=self.pricing_hash,
            max_amount_units=100_000,
            expires_at=self.now + 3_600,
            deadline=self.now + 3_600,
            signer=self.consumer_identity,
            settlement_chain_id=11155111,
            settlement_contract=self.contract,
            session_private_key=self.session_private_key,
            now=self.now,
        )

    def test_handle_infer_v4_replays_persisted_success_without_gateway_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            auth = self._auth(config, "0x" + "88" * 32)
            message = self._message(
                config,
                request_id="v4-idempotent-success",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    return_value={"schema": "test.v4.receipt", "sequence": 0},
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "cached answer", "usage": {"total_tokens": 2}},
                ) as gateway_call,
            ):
                first = p2p.handle_message(config, message)
                # Re-open the same durable store to model a Provider restart.
                restarted = self._config(replay_path)
                second = p2p.handle_message(restarted, message)

            self.assertTrue(first["ok"])
            self.assertEqual(second, first)
            self.assertEqual(gateway_call.call_count, 1)

    def test_handle_infer_v4_timeout_is_uncertain_and_not_reexecuted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            auth = self._auth(config, "0x" + "99" * 32)
            message = self._message(
                config,
                request_id="v4-idempotent-timeout",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            with patch.object(
                p2p,
                "call_gateway",
                side_effect=TimeoutError("provider timed out"),
            ) as gateway_call:
                first = p2p.handle_message(config, message)
                second = p2p.handle_message(config, message)

            self.assertFalse(first["ok"])
            self.assertTrue(first["retryable"])
            self.assertFalse(second["ok"])
            self.assertTrue(second["retryable"])
            self.assertEqual(gateway_call.call_count, 1)
            checked = _preverify_inference_request(config, message, allow_v4_replay=True)
            key = p2p._v4_execution_key(
                checked["consumer_public_key"],
                checked["request_id"],
            )
            claim = config._replay_store.get_execution(p2p.V4_EXECUTION_SCOPE, key)
            self.assertIsNotNone(claim)
            self.assertEqual(claim.state, "uncertain")

    def test_completed_v4_retry_survives_session_rpc_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            config.session_v4_verify_onchain = True
            auth = self._auth(config, "0x" + "ab" * 32)
            message = self._message(
                config,
                request_id="v4-cache-rpc-outage",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            with (
                patch.object(
                    p2p,
                    "_verify_v4_onchain_session",
                    side_effect=[
                        None,
                        p2p.P2PError("failed to verify Settlement V4 session on-chain: RPC down"),
                    ],
                ),
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    return_value={"schema": "test.v4.receipt", "sequence": 0},
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "rpc-safe", "usage": {"total_tokens": 2}},
                ) as gateway_call,
            ):
                first = p2p.handle_message(config, message)
                restarted = self._config(replay_path)
                restarted.session_v4_verify_onchain = True
                second = p2p.handle_message(restarted, message)

            self.assertTrue(first["ok"])
            self.assertEqual(second, first)
            self.assertEqual(gateway_call.call_count, 1)

    def test_v4_sequence_progress_survives_provider_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            auth = self._auth(config, "0x" + "bc" * 32)
            first_message = self._message(
                config,
                request_id="v4-restart-seq-1",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    return_value={"schema": "test.v4.receipt", "sequence": 0},
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "first", "usage": {"total_tokens": 2}},
                ) as gateway_call,
            ):
                first = p2p.handle_message(config, first_message)
                self.assertTrue(first["ok"])

                # The default minimum fee is 0.002 USDC = 2,000 units.
                restarted = self._config(replay_path)
                second_message = self._message(
                    restarted,
                    request_id="v4-restart-seq-2",
                    sequence=2,
                    previous_spend=2_000,
                    auth=auth,
                    max_fee_units=10_000,
                )
                gateway_call.return_value = {
                    "output_text": "second",
                    "usage": {"total_tokens": 2},
                }
                second = p2p.handle_message(restarted, second_message)

            self.assertTrue(second["ok"])
            self.assertEqual(gateway_call.call_count, 2)

    def test_cached_v4_retry_repairs_progress_after_transient_store_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            auth = self._auth(config, "0x" + "cd" * 32)
            first_message = self._message(
                config,
                request_id="v4-progress-repair-1",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            assert config._replay_store is not None
            real_set_progress = config._replay_store.set_session_progress
            progress_calls = 0

            def flaky_set_progress(*args, **kwargs) -> None:
                nonlocal progress_calls
                progress_calls += 1
                if progress_calls == 1:
                    raise ReplayError("temporary progress store failure")
                real_set_progress(*args, **kwargs)

            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    return_value={"schema": "test.v4.receipt", "sequence": 0},
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "repairable", "usage": {"total_tokens": 2}},
                ) as gateway_call,
                patch.object(
                    config._replay_store,
                    "set_session_progress",
                    side_effect=flaky_set_progress,
                ),
            ):
                first = p2p.handle_message(config, first_message)
                repaired = p2p.handle_message(config, first_message)

            self.assertFalse(first["ok"])
            self.assertTrue(first["retryable"])
            self.assertTrue(repaired["ok"])
            self.assertEqual(gateway_call.call_count, 1)
            self.assertGreaterEqual(progress_calls, 2)

            restarted = self._config(replay_path)
            second_message = self._message(
                restarted,
                request_id="v4-progress-repair-2",
                sequence=2,
                previous_spend=2_000,
                auth=auth,
                max_fee_units=10_000,
            )
            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    return_value={"schema": "test.v4.receipt", "sequence": 1},
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "next", "usage": {"total_tokens": 2}},
                ) as gateway_call,
            ):
                second = p2p.handle_message(restarted, second_message)

            self.assertTrue(second["ok"])
            self.assertEqual(gateway_call.call_count, 1)

    def test_v4_session_does_not_admit_next_sequence_before_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            first_config = self._config(replay_path)
            competing_config = self._config(replay_path)
            auth = self._auth(first_config, "0x" + "de" * 32)
            first_message = self._message(
                first_config,
                request_id="v4-serial-1",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            premature_second = self._message(
                competing_config,
                request_id="v4-serial-2-premature",
                sequence=2,
                previous_spend=10_000,
                auth=auth,
                max_fee_units=10_000,
            )
            entered_gateway = threading.Event()
            release_gateway = threading.Event()
            responses: list[dict] = []

            def blocking_gateway(**_kwargs) -> dict:
                entered_gateway.set()
                self.assertTrue(release_gateway.wait(timeout=5))
                return {"output_text": "first", "usage": {"total_tokens": 2}}

            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    return_value={"schema": "test.v4.receipt", "sequence": 0},
                ),
                patch.object(p2p, "call_gateway", side_effect=blocking_gateway) as gateway_call,
            ):
                worker = threading.Thread(
                    target=lambda: responses.append(
                        p2p.handle_message(first_config, first_message)
                    )
                )
                worker.start()
                self.assertTrue(entered_gateway.wait(timeout=5))
                rejected = p2p.handle_message(competing_config, premature_second)
                self.assertFalse(rejected["ok"])
                self.assertIn("sequence", rejected["error"])
                self.assertEqual(gateway_call.call_count, 1)
                release_gateway.set()
                worker.join(timeout=5)

            self.assertFalse(worker.is_alive())
            self.assertTrue(responses[0]["ok"])

            next_config = self._config(replay_path)
            committed_second = self._message(
                next_config,
                request_id="v4-serial-2",
                sequence=2,
                previous_spend=2_000,
                auth=auth,
                max_fee_units=10_000,
            )
            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    return_value={"schema": "test.v4.receipt", "sequence": 1},
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "second", "usage": {"total_tokens": 2}},
                ),
            ):
                accepted = p2p.handle_message(next_config, committed_second)

            self.assertTrue(accepted["ok"])

    def test_v4_admission_does_not_read_confirmed_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            auth = build_session_authorization(
                session_id="0x" + "55" * 32,
                session_key=self.session_key,
                consumer_payment_address=self.consumer_address,
                provider_id=config.peer_id,
                provider_payment_address=self.provider_address,
                channel=DEFAULT_CHANNEL,
                pricing_version=1,
                pricing_hash=self.pricing_hash,
                max_amount_units=100_000,
                expires_at=self.now + 3_600,
                deadline=self.now + 3_600,
                signer=self.consumer_identity,
                settlement_chain_id=11155111,
                settlement_contract=self.contract,
                session_private_key=self.session_private_key,
                now=self.now,
            )
            message = self._message(config, request_id="v4-1", sequence=1, previous_spend=0, auth=auth)
            with patch("gateway.p2p._confirmed_settlement_block", side_effect=AssertionError("V4 must not pin confirmations")):
                checked = _preverify_inference_request(config, message)
                verified = verify_inference_request(config, message, preverified=checked)
            self.assertEqual(verified["reservation"]["settlement_version"], 4)
            self.assertEqual(verified["session_sequence"], 1)

    def test_v4_sequence_claim_is_monotonic_and_replay_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            auth = build_session_authorization(
                session_id="0x" + "66" * 32,
                session_key=self.session_key,
                consumer_payment_address=self.consumer_address,
                provider_id=config.peer_id,
                provider_payment_address=self.provider_address,
                channel=DEFAULT_CHANNEL,
                pricing_version=1,
                pricing_hash=self.pricing_hash,
                max_amount_units=100_000,
                expires_at=self.now + 3_600,
                deadline=self.now + 3_600,
                signer=self.consumer_identity,
                settlement_chain_id=11155111,
                settlement_contract=self.contract,
                session_private_key=self.session_private_key,
                now=self.now,
            )
            first = self._message(config, request_id="v4-seq-1", sequence=1, previous_spend=0, auth=auth)
            first_checked = _preverify_inference_request(config, first)
            first_verified = verify_inference_request(config, first, preverified=first_checked)
            p2p._commit_v4_session_progress(
                config,
                first_verified["reservation"],
                cumulative_spend_units=1_000,
            )
            second = self._message(config, request_id="v4-seq-2", sequence=2, previous_spend=1_000, auth=auth)
            second_checked = _preverify_inference_request(config, second)
            verify_inference_request(config, second, preverified=second_checked)
            replay = self._message(config, request_id="v4-seq-replay", sequence=2, previous_spend=1_000, auth=auth)
            with self.assertRaisesRegex(Exception, "already been consumed|sequence"):
                replay_checked = _preverify_inference_request(config, replay)
                verify_inference_request(config, replay, preverified=replay_checked)

    def test_descriptor_advertises_session_settlement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            descriptor = provider_descriptor(config)
            self.assertEqual(descriptor["settlement"]["version"], 4)
            self.assertFalse(descriptor["session_settlement"]["per_request_chain_transaction"])

    def test_failed_v4_execution_releases_request_and_sequence_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            auth = build_session_authorization(
                session_id="0x" + "77" * 32,
                session_key=self.session_key,
                consumer_payment_address=self.consumer_address,
                provider_id=config.peer_id,
                provider_payment_address=self.provider_address,
                channel=DEFAULT_CHANNEL,
                pricing_version=1,
                pricing_hash=self.pricing_hash,
                max_amount_units=100_000,
                expires_at=self.now + 3_600,
                deadline=self.now + 3_600,
                signer=self.consumer_identity,
                settlement_chain_id=11155111,
                settlement_contract=self.contract,
                session_private_key=self.session_private_key,
                now=self.now,
            )
            message = self._message(config, request_id="v4-release", sequence=1, previous_spend=0, auth=auth)
            checked = _preverify_inference_request(config, message)
            verified = verify_inference_request(config, message, preverified=checked)
            p2p._release_v4_authorization(config, verified["reservation"])
            retry_checked = _preverify_inference_request(config, message)
            retry_verified = verify_inference_request(config, message, preverified=retry_checked)
            self.assertEqual(retry_verified["session_sequence"], 1)


if __name__ == "__main__":
    unittest.main()
