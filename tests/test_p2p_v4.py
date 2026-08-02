from __future__ import annotations

import hashlib
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway.attestation import verify_provider_settlement_attestation
from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import create_identity, sign_document, verify_document
import gateway.identity as identity
from gateway.operator_budget import OperatorBudget
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
            "session_protocol_version": config.settlement_version,
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

    def _status_message(
        self,
        config: ProviderConfig,
        inference: dict,
        *,
        request_id: str,
        deadline: int | None = None,
    ) -> dict:
        target = inference["session_request"]
        session_request = build_session_request(
            authorization=inference["session_authorization"],
            request_id=target["request_id"],
            request_hash=target["request_hash"],
            max_fee_units=target["max_fee_units"],
            deadline=deadline or inference["session_authorization"]["deadline"],
            sequence=target["sequence"],
            previous_cumulative_spend_units=(
                target["cumulative_spend_units"] - target["max_fee_units"]
            ),
            signer=self.consumer_identity,
            session_private_key=self.session_private_key,
            now=self.now,
        )
        unsigned = {
            "type": "session_status",
            "request_id": request_id,
            "target_request_id": target["request_id"],
            "channel": target["channel"],
            "network_id": target["network_id"],
            "channel_id": target["channel_id"],
            "backend_policy": target["backend_policy"],
            "relay_attestation_address": target["relay_attestation_address"],
            "session_protocol_version": config.settlement_version,
            "session_authorization": inference["session_authorization"],
            "session_request": session_request,
        }
        return sign_document(
            unsigned,
            self.consumer_identity.private_key,
            purpose=p2p.SESSION_STATUS_REQUEST_PURPOSE,
            audience=config.peer_id,
            timestamp=self.now,
        )

    def _with_uppercase_signing_key(self, document: dict) -> dict:
        unsigned = {key: value for key, value in document.items() if key != "signature"}
        signature = {
            key: value
            for key, value in document["signature"].items()
            if key != "signature"
        }
        signature["public_key"] = str(signature["public_key"]).upper()
        signature["signature"] = identity._private_key(
            self.consumer_identity.private_key
        ).sign(identity._signature_message(unsigned, signature)).hex()
        return {**unsigned, "signature": signature}

    def test_session_status_returns_signed_completed_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            auth = self._auth(config, "0x" + "71" * 32)
            inference = self._message(
                config,
                request_id="v6-status-completed",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
                deadline=self.now + 300,
            )
            status_request = self._status_message(
                config,
                inference,
                request_id="status-completed-transport",
                deadline=auth["deadline"],
            )
            with (
                patch.object(
                    p2p,
                    "_build_v4_provider_settlement",
                    side_effect=lambda *, reservation, **_kwargs: {
                        "schema": "test.v6.receipt",
                        "sequence": 0,
                        "receipt": {"deadline": int(reservation["settlement_deadline"])},
                    },
                ),
                patch.object(
                    p2p,
                    "call_gateway",
                    return_value={"output_text": "status-safe", "usage": {"total_tokens": 2}},
                ) as gateway_call,
            ):
                inference_response = p2p.handle_message(config, inference)
                with patch.object(
                    config._replay_store,
                    "abort_execution_with_claims",
                    wraps=config._replay_store.abort_execution_with_claims,
                ) as abort_execution:
                    result = p2p.handle_message(config, status_request)
                abort_execution.assert_not_called()

            self.assertTrue(inference_response["ok"])
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["request_id"], "status-completed-transport")
            self.assertEqual(result["target_request_id"], "v6-status-completed")
            self.assertEqual(result["response"]["output_text"], "status-safe")
            self.assertEqual(
                result["response"]["mycomesh_v6_settlement"]["receipt"]["deadline"],
                auth["deadline"],
            )
            verified = verify_document(
                result,
                purpose=p2p.SESSION_STATUS_RESPONSE_PURPOSE,
                audience=self.consumer_identity.public_key,
                now=self.now,
            )
            self.assertEqual(verified["status"], "completed")
            self.assertEqual(gateway_call.call_count, 1)

            with self.assertRaisesRegex(
                p2p.P2PError,
                "canonical Session authorization deadline",
            ):
                p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-noncanonical-deadline",
                        deadline=self.now + 600,
                    ),
                )

            forged_expiry = self.now + 7_200
            forged_inference = {
                **inference,
                "session_authorization": self._auth(
                    config,
                    str(auth["session_id"]),
                    expires_at=forged_expiry,
                ),
            }
            with self.assertRaisesRegex(p2p.P2PError, "durable expiry"):
                p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        forged_inference,
                        request_id="status-forged-authorization-expiry",
                    ),
                )

    def test_session_status_reports_absent_pending_and_aborts_only_stale_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6

            def status_for(
                target: str,
                claimed_at: int | None,
                state: str = "claimed",
            ) -> dict:
                auth = self._auth(config, "0x" + target[-2:] * 32)
                inference = self._message(
                    config,
                    request_id=target,
                    sequence=1,
                    previous_spend=0,
                    auth=auth,
                    max_fee_units=10_000,
                )
                if claimed_at is not None:
                    execution_key = p2p._v4_execution_key(
                        self.consumer_identity.public_key,
                        target,
                    )
                    claim = config._replay_store.claim_execution(
                        p2p.V4_EXECUTION_SCOPE,
                        execution_key,
                        config._execution_owner,
                        3_600,
                        now=claimed_at,
                    )
                    checked = _preverify_inference_request(config, inference)
                    verify_inference_request(
                        config,
                        inference,
                        preverified=checked,
                        execution_key=execution_key,
                        execution_claim=claim,
                    )
                    if state in {"started", "uncertain"}:
                        config._replay_store.mark_execution_started(
                            p2p.V4_EXECUTION_SCOPE,
                            execution_key,
                            config._execution_owner,
                            claim.fencing_token,
                            3_600,
                            now=claimed_at,
                        )
                    if state == "uncertain":
                        config._replay_store.mark_execution_uncertain(
                            p2p.V4_EXECUTION_SCOPE,
                            execution_key,
                            config._execution_owner,
                            claim.fencing_token,
                            now=claimed_at,
                        )
                with patch.object(p2p.time, "time", return_value=self.now):
                    return p2p.handle_message(
                        config,
                        self._status_message(
                            config,
                            inference,
                            request_id=f"status-{target}",
                        ),
                    )

            self.assertEqual(status_for("v6-status-72", None)["status"], "aborted")
            self.assertEqual(status_for("v6-status-73", self.now)["status"], "aborted")
            self.assertEqual(
                status_for("v6-status-77", self.now, "uncertain")["status"],
                "pending",
            )
            self.assertEqual(
                status_for(
                    "v6-status-82",
                    self.now - p2p.SESSION_STATUS_ABORT_GRACE_SECONDS,
                    "uncertain",
                )["status"],
                "pending",
            )
            self.assertEqual(
                status_for(
                    "v6-status-79",
                    self.now - p2p.SESSION_STATUS_ABORT_GRACE_SECONDS - 1,
                    "uncertain",
                )["status"],
                "aborted",
            )
            self.assertEqual(
                status_for("v6-status-78", self.now, "started")["status"],
                "pending",
            )
            self.assertEqual(
                status_for(
                    "v6-status-75",
                    self.now - p2p.SESSION_STATUS_ABORT_AFTER_SECONDS,
                    "started",
                )["status"],
                "pending",
            )
            stale = status_for(
                "v6-status-74",
                self.now - p2p.SESSION_STATUS_ABORT_AFTER_SECONDS - 1,
                "started",
            )
            self.assertEqual(stale["status"], "aborted")
            stale_claim = config._replay_store.get_execution(
                p2p.V4_EXECUTION_SCOPE,
                p2p._v4_execution_key(
                    self.consumer_identity.public_key,
                    "v6-status-74",
                ),
            )
            self.assertEqual(stale_claim.state, "aborted")

            config.timeout_seconds = 45
            dynamic_abort_after = 45 + p2p.SESSION_STATUS_ABORT_GRACE_SECONDS
            self.assertEqual(
                status_for(
                    "v6-status-80",
                    self.now - dynamic_abort_after,
                    "started",
                )["status"],
                "pending",
            )
            self.assertEqual(
                status_for(
                    "v6-status-81",
                    self.now - dynamic_abort_after - 1,
                    "started",
                )["status"],
                "aborted",
            )

    def test_absent_status_tombstones_delayed_inference_until_session_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            inference = self._message(
                config,
                request_id="v6-status-delayed-inference",
                sequence=1,
                previous_spend=0,
                auth=self._auth(config, "0x" + "83" * 32),
                max_fee_units=10_000,
            )
            with patch.object(p2p.time, "time", return_value=self.now):
                status = p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-delayed-inference",
                    ),
                )

            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-delayed-inference",
            )
            self.assertEqual(status["status"], "aborted")
            claim = config._replay_store.get_execution(p2p.V4_EXECUTION_SCOPE, execution_key)
            self.assertIsNotNone(claim)
            assert claim is not None
            self.assertEqual(claim.state, "aborted")
            self.assertEqual(claim.result_hash, p2p.ABORTED_CLAIMS_RELEASED_MARKER)
            self.assertEqual(claim.expires_at, inference["session_authorization"]["expires_at"])

            with patch.object(p2p, "call_gateway") as gateway_call:
                delayed = p2p.handle_message(config, inference)
            self.assertFalse(delayed["ok"])
            self.assertIn("execution was aborted", delayed["error"])
            gateway_call.assert_not_called()

    def test_status_treats_claim_before_nonce_insert_as_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            inference = self._message(
                config,
                request_id="v6-status-claim-race",
                sequence=1,
                previous_spend=0,
                auth=self._auth(config, "0x" + "84" * 32),
            )
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-claim-race",
            )
            config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )

            with patch.object(p2p.time, "time", return_value=self.now):
                status = p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-claim-race",
                    ),
                )

            self.assertEqual(status["status"], "pending")
            claim = config._replay_store.get_execution(p2p.V4_EXECUTION_SCOPE, execution_key)
            self.assertIsNotNone(claim)
            assert claim is not None
            self.assertEqual(claim.state, "claimed")

    def test_status_aborts_a_stale_claim_with_no_nonce_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            inference = self._message(
                config,
                request_id="v6-status-stale-claim-race",
                sequence=1,
                previous_spend=0,
                auth=self._auth(config, "0x" + "85" * 32),
            )
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-stale-claim-race",
            )
            config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now - p2p.SESSION_STATUS_ABORT_AFTER_SECONDS - 1,
            )

            with patch.object(p2p.time, "time", return_value=self.now):
                status = p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-stale-claim-race",
                    ),
                )

            self.assertEqual(status["status"], "aborted")
            claim = config._replay_store.get_execution(p2p.V4_EXECUTION_SCOPE, execution_key)
            self.assertIsNotNone(claim)
            assert claim is not None
            self.assertEqual(claim.state, "aborted")

    def test_aborted_session_status_releases_authorization_after_retryable_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            auth = self._auth(config, "0x" + "79" * 32)
            inference = self._message(
                config,
                request_id="v6-status-aborted",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-aborted",
            )
            execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            checked = _preverify_inference_request(config, inference)
            verified = verify_inference_request(
                config,
                inference,
                preverified=checked,
                execution_key=execution_key,
                execution_claim=execution_claim,
            )
            request_key = str(checked["request_key"])
            status_request = self._status_message(
                config,
                inference,
                request_id="status-aborted-transport",
            )

            with (
                patch.object(p2p.time, "time", return_value=self.now),
                patch.object(
                    config._replay_store,
                    "abort_execution_with_claims",
                    side_effect=ReplayError("store unavailable"),
                ),
            ):
                with self.assertRaisesRegex(
                    p2p.P2PRetryableError,
                    "failed to read Settlement session status",
                ):
                    p2p.handle_message(config, status_request)

            still_claimed = config._replay_store.get_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
            )
            self.assertEqual(still_claimed.state, "claimed")
            self.assertIn(request_key, config.seen_requests)

            with patch.object(p2p.time, "time", return_value=self.now):
                recovered = p2p.handle_message(config, status_request)
            self.assertEqual(recovered["status"], "aborted")
            self.assertNotIn(request_key, config.seen_requests)

            with self.assertRaises(ReplayError):
                config._replay_store.complete_execution(
                    p2p.V4_EXECUTION_SCOPE,
                    execution_key,
                    config._execution_owner,
                    execution_claim.fencing_token,
                    "result-hash",
                    "{}",
                    now=self.now,
                )

            replacement = self._message(
                config,
                request_id="v6-status-replacement",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )
            replacement_execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-replacement",
            )
            replacement_execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                replacement_execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            replacement_checked = _preverify_inference_request(config, replacement)
            replacement_verified = verify_inference_request(
                config,
                replacement,
                preverified=replacement_checked,
                execution_key=replacement_execution_key,
                execution_claim=replacement_execution_claim,
            )
            self.assertEqual(replacement_verified["session_sequence"], 1)

            with patch.object(p2p.time, "time", return_value=self.now):
                repeated = p2p.handle_message(config, status_request)
            self.assertEqual(repeated["status"], "aborted")
            p2p._release_v4_authorization(
                config,
                verified["reservation"],
                execution_key=execution_key,
                execution_claim=execution_claim,
            )
            conflicting = self._message(
                config,
                request_id="v6-status-conflicting",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )
            with self.assertRaisesRegex(p2p.P2PError, "already been consumed"):
                conflicting_checked = _preverify_inference_request(config, conflicting)
                verify_inference_request(
                    config,
                    conflicting,
                    preverified=conflicting_checked,
                )

    def test_session_status_cannot_abort_an_execution_from_another_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            original = self._message(
                config,
                request_id="v6-status-bound-execution",
                sequence=1,
                previous_spend=0,
                auth=self._auth(config, "0x" + "7b" * 32),
            )
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-bound-execution",
            )
            execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            checked = _preverify_inference_request(config, original)
            verify_inference_request(
                config,
                original,
                preverified=checked,
                execution_key=execution_key,
                execution_claim=execution_claim,
            )
            other_session = self._message(
                config,
                request_id="v6-status-bound-execution",
                sequence=1,
                previous_spend=0,
                auth=self._auth(config, "0x" + "7c" * 32),
            )

            with (
                patch.object(p2p.time, "time", return_value=self.now),
                self.assertRaisesRegex(
                    p2p.P2PError,
                    "recovery requires a new Session",
                ),
            ):
                p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        other_session,
                        request_id="status-wrong-session",
                    ),
                )

            current = config._replay_store.get_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
            )
            self.assertEqual(current.state, "claimed")
            with patch.object(p2p.time, "time", return_value=self.now):
                valid = p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        original,
                        request_id="status-correct-session",
                    ),
                )
            self.assertEqual(valid["status"], "aborted")

    def test_owned_request_claim_survives_until_stale_execution_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            inference = self._message(
                config,
                request_id="v6-status-long-running",
                sequence=1,
                previous_spend=0,
                auth=self._auth(config, "0x" + "7f" * 32),
            )
            checked = _preverify_inference_request(config, inference)
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-long-running",
            )
            execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            verified = verify_inference_request(
                config,
                inference,
                preverified=checked,
                execution_key=execution_key,
                execution_claim=execution_claim,
            )
            config._replay_store.mark_execution_started(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                execution_claim.fencing_token,
                3_600,
                now=self.now,
            )
            config._replay_store.remember(
                "test.cleanup",
                "trigger",
                60,
                now=self.now + config.replay_ttl_seconds + 1,
            )
            claim_keys = p2p._v4_authorization_claim_keys(
                config,
                verified["reservation"],
                request_key=str(checked["request_key"]),
            )
            self.assertTrue(
                config._replay_store.abort_execution_with_claims(
                    p2p.V4_EXECUTION_SCOPE,
                    execution_key,
                    claim_keys,
                    self.now,
                    states=("started",),
                    now=self.now + config.replay_ttl_seconds + 2,
                )
            )

    def test_session_status_uses_canonical_request_key_casing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            inference = self._with_uppercase_signing_key(
                self._message(
                    config,
                    request_id="v6-status-key-casing",
                    sequence=1,
                    previous_spend=0,
                    auth=self._auth(config, "0x" + "7e" * 32),
                )
            )
            checked = _preverify_inference_request(config, inference)
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-key-casing",
            )
            self.assertEqual(checked["request_key"], execution_key)
            execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            verify_inference_request(
                config,
                inference,
                preverified=checked,
                execution_key=execution_key,
                execution_claim=execution_claim,
            )

            with patch.object(p2p.time, "time", return_value=self.now):
                result = p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-key-casing",
                    ),
                )
            self.assertEqual(result["status"], "aborted")

    def test_legacy_aborted_session_without_owned_cleanup_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            auth = self._auth(config, "0x" + "7d" * 32)
            inference = self._message(
                config,
                request_id="v6-status-legacy-aborted",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-legacy-aborted",
            )
            config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            checked = _preverify_inference_request(config, inference)
            verify_inference_request(config, inference, preverified=checked)
            with (
                patch.object(p2p.time, "time", return_value=self.now),
                self.assertRaisesRegex(
                    p2p.P2PError,
                    "recovery requires a new Session",
                ),
            ):
                p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-legacy-active",
                    ),
                )
            active = config._replay_store.get_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
            )
            self.assertEqual(active.state, "claimed")
            self.assertTrue(
                config._replay_store.abort_stale_execution(
                    p2p.V4_EXECUTION_SCOPE,
                    execution_key,
                    self.now,
                    states=("claimed",),
                    now=self.now,
                )
            )

            with (
                patch.object(p2p.time, "time", return_value=self.now),
                self.assertRaisesRegex(
                    p2p.P2PError,
                    "recovery requires a new Session",
                ),
            ):
                p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-legacy-aborted",
                    ),
                )

            replacement = self._message(
                config,
                request_id="v6-status-legacy-replacement",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )
            with self.assertRaisesRegex(p2p.P2PError, "already been consumed"):
                replacement_checked = _preverify_inference_request(config, replacement)
                verify_inference_request(
                    config,
                    replacement,
                    preverified=replacement_checked,
                )

    def test_pending_session_status_preserves_authorization_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            auth = self._auth(config, "0x" + "7a" * 32)
            inference = self._message(
                config,
                request_id="v6-status-pending",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v6-status-pending",
            )
            execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            checked = _preverify_inference_request(config, inference)
            verify_inference_request(
                config,
                inference,
                preverified=checked,
                execution_key=execution_key,
                execution_claim=execution_claim,
            )
            config._replay_store.mark_execution_started(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                execution_claim.fencing_token,
                3_600,
                now=self.now,
            )

            with (
                patch.object(p2p.time, "time", return_value=self.now),
                patch.object(
                    config._replay_store,
                    "abort_execution_with_claims",
                    wraps=config._replay_store.abort_execution_with_claims,
                ) as abort_execution,
            ):
                result = p2p.handle_message(
                    config,
                    self._status_message(
                        config,
                        inference,
                        request_id="status-pending-transport",
                    ),
                )

            self.assertEqual(result["status"], "pending")
            abort_execution.assert_called_once()
            self.assertIn(str(checked["request_key"]), config.seen_requests)

    def test_session_status_requires_provider_audience_and_signed_network_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 6
            inference = self._message(
                config,
                request_id="v6-status-bound",
                sequence=1,
                previous_spend=0,
                auth=self._auth(config, "0x" + "76" * 32),
                max_fee_units=10_000,
            )
            valid = self._status_message(
                config,
                inference,
                request_id="status-bound-transport",
            )
            unsigned = {key: value for key, value in valid.items() if key != "signature"}
            wrong_audience = sign_document(
                unsigned,
                self.consumer_identity.private_key,
                purpose=p2p.SESSION_STATUS_REQUEST_PURPOSE,
                audience="peer_wrong",
                timestamp=self.now,
            )
            with self.assertRaisesRegex(p2p.P2PError, "bad signature audience"):
                p2p.handle_message(config, wrong_audience)

            unsigned["network_id"] = "wrong-network"
            wrong_network = sign_document(
                unsigned,
                self.consumer_identity.private_key,
                purpose=p2p.SESSION_STATUS_REQUEST_PURPOSE,
                audience=config.peer_id,
                timestamp=self.now,
            )
            with self.assertRaisesRegex(p2p.P2PError, "network_id binding mismatch"):
                p2p.handle_message(config, wrong_network)

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
            verified_attestation = verify_provider_settlement_attestation(
                replayed["provider_settlement_attestation"],
                provider_public_key=config.identity.public_key,
                consumer_public_key=retry_checked["consumer_public_key"],
                expected={"request_hash": retry_checked["request_hash_digest"]},
            )
            self.assertEqual(
                verified_attestation["request_hash"],
                retry_checked["request_hash_digest"],
            )
            self.assertEqual(
                replayed["provider_settlement_attestation"]["request_hash"],
                retry_checked["request_hash_digest"],
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

    def _auth(
        self,
        config: ProviderConfig,
        session_id: str,
        *,
        expires_at: int | None = None,
    ) -> dict:
        resolved_expiry = expires_at or self.now + 3_600
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
            expires_at=resolved_expiry,
            deadline=resolved_expiry,
            signer=self.consumer_identity,
            settlement_chain_id=11155111,
            settlement_contract=self.contract,
            session_protocol_version=config.settlement_version,
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

    def test_v4_execution_claim_lasts_until_session_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            auth = self._auth(config, "0x" + "8f" * 32)
            message = self._message(
                config,
                request_id="v4-long-session-claim",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            checked = _preverify_inference_request(config, message)
            with patch.object(config._replay_store, "claim_execution", wraps=config._replay_store.claim_execution) as claim:
                key, execution_claim, cached = p2p._claim_v4_execution(config, checked)

            self.assertIsNone(cached)
            self.assertIsNotNone(execution_claim)
            self.assertGreater(
                int(claim.call_args.args[3]),
                int(config.replay_ttl_seconds),
            )
            p2p._release_v4_execution_claim(config, key, execution_claim)

    def test_v4_budget_rejection_releases_the_session_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config._operator_budget = OperatorBudget(
                limit_units=1,
                period_seconds=3_600,
                state_path=Path(directory) / "budget.json",
            )
            auth = self._auth(config, "0x" + "90" * 32)
            message = self._message(
                config,
                request_id="v4-budget-rejection",
                sequence=1,
                previous_spend=0,
                auth=auth,
                max_fee_units=10_000,
            )
            with patch.object(p2p, "call_gateway") as gateway_call:
                result = p2p.handle_message(config, message)

            self.assertFalse(result["ok"])
            self.assertIn("usage budget exhausted", result["error"])
            gateway_call.assert_not_called()
            retry_checked = _preverify_inference_request(config, message)
            retry_verified = verify_inference_request(config, message, preverified=retry_checked)
            self.assertEqual(retry_verified["session_sequence"], 1)

    def test_handle_infer_v4_timeout_is_uncertain_and_not_reexecuted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay_path = str(Path(directory) / "replay.sqlite3")
            config = self._config(replay_path)
            config._operator_budget = OperatorBudget(
                limit_units=20_000,
                period_seconds=3_600,
                state_path=Path(directory) / "budget.json",
            )
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
            self.assertEqual(
                config._operator_budget.snapshot()["spent_units"],
                10_000,
            )
            self.assertEqual(config._operator_budget.snapshot()["reserved_units"], 0)

    def test_post_dispatch_failures_conservatively_spend_operator_budget(self) -> None:
        for target, session_suffix in (("extract_output_text", "91"), ("quote_usage", "92")):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                config = self._config(str(Path(directory) / "replay.sqlite3"))
                config._operator_budget = OperatorBudget(
                    limit_units=20_000,
                    period_seconds=3_600,
                    state_path=Path(directory) / "budget.json",
                )
                message = self._message(
                    config,
                    request_id=f"v4-budget-{target}",
                    sequence=1,
                    previous_spend=0,
                    auth=self._auth(config, "0x" + session_suffix * 32),
                    max_fee_units=10_000,
                )
                with (
                    patch.object(
                        p2p,
                        "call_gateway",
                        return_value={"output_text": "done", "usage": {"total_tokens": 2}},
                    ),
                    patch.object(p2p, target, side_effect=ValueError("forced failure")),
                ):
                    result = p2p.handle_message(config, message)

                self.assertFalse(result["ok"])
                self.assertEqual(config._operator_budget.snapshot()["spent_units"], 10_000)
                self.assertEqual(config._operator_budget.snapshot()["reserved_units"], 0)

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

    def test_v4_admission_rejects_unexpected_relay_payment_address(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.relay_payment_address = "0x" + "55" * 20
            auth = build_session_authorization(
                session_id="0x" + "56" * 32,
                session_key=self.session_key,
                consumer_payment_address=self.consumer_address,
                provider_id=config.peer_id,
                provider_payment_address=self.provider_address,
                relay_payment_address="0x" + "66" * 20,
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
            message = self._message(
                config,
                request_id="v4-relay-payout-mismatch",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )

            with self.assertRaisesRegex(p2p.P2PError, "relay payment address mismatch"):
                _preverify_inference_request(config, message)

    def test_v5_admission_allows_direct_provider_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(str(Path(directory) / "replay.sqlite3"))
            config.settlement_version = 5
            auth = self._auth(config, "0x" + "57" * 32)
            message = self._message(
                config,
                request_id="v5-direct-route",
                sequence=1,
                previous_spend=0,
                auth=auth,
            )

            checked = _preverify_inference_request(config, message)
            self.assertEqual(checked["reservation"]["settlement_version"], 5)
            self.assertEqual(checked["reservation"]["relay_payment_address"], "0x" + "00" * 20)

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
            config.relay_payment_address = "0x" + "77" * 20
            self.assertEqual(
                provider_descriptor(config)["relay_payment_address"],
                "0x" + "77" * 20,
            )

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
            execution_key = p2p._v4_execution_key(
                self.consumer_identity.public_key,
                "v4-release",
            )
            execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            checked = _preverify_inference_request(config, message)
            verified = verify_inference_request(
                config,
                message,
                preverified=checked,
                execution_key=execution_key,
                execution_claim=execution_claim,
            )
            p2p._release_v4_authorization(
                config,
                verified["reservation"],
                execution_key=execution_key,
                execution_claim=execution_claim,
            )
            retry_execution_claim = config._replay_store.claim_execution(
                p2p.V4_EXECUTION_SCOPE,
                execution_key,
                config._execution_owner,
                3_600,
                now=self.now,
            )
            retry_checked = _preverify_inference_request(config, message)
            retry_verified = verify_inference_request(
                config,
                message,
                preverified=retry_checked,
                execution_key=execution_key,
                execution_claim=retry_execution_claim,
            )
            self.assertEqual(retry_verified["session_sequence"], 1)


if __name__ == "__main__":
    unittest.main()
