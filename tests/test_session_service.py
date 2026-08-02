from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import create_identity
from gateway.session_service import (
    SessionDeployment,
    SessionServiceError,
    SessionV4Store,
)


class SessionServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SessionV4Store(
            Path(self.tmp.name) / "session.sqlite3",
            secret="test-session-secret-with-at-least-32-bytes",
        )
        self.consumer_key = "0x" + "1".zfill(64)
        self.provider_key = "0x" + "2".zfill(64)
        self.consumer = private_key_to_address(parse_private_key(self.consumer_key))
        self.provider = private_key_to_address(parse_private_key(self.provider_key))
        self.signer = create_identity()
        self.deployment = SessionDeployment(
            chain_id=11155111,
            contract="0x" + "a" * 40,
            rpc_url=None,
            channel="codex-standard-v1",
            channel_hash="0x" + "b" * 64,
            pricing_version=1,
            pricing_hash="0x" + "c" * 64,
            network_id="mycomesh-testnet",
            channel_id="codex",
            backend_policy="codex-app-server-postvalidated-v1",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _plan(self) -> dict[str, object]:
        return self.store.create_plan(
            account_id="acct_test",
            consumer=self.consumer,
            provider_id="peer_test",
            provider_payment_address=self.provider,
            deployment=self.deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_100,
            now=2_000_000_000,
        )

    def test_plan_can_bind_route_specific_payout_addresses(self) -> None:
        relay = "0x" + "3" * 40
        pool = "0x" + "4" * 40
        plan = self.store.create_plan(
            account_id="acct_route",
            consumer=self.consumer,
            provider_id="peer_route",
            provider_payment_address=self.provider,
            deployment=self.deployment,
            relay_payment_address=relay,
            pool_payment_address=pool,
            max_amount_units=1_000,
            expires_at=2_000_000_100,
            now=2_000_000_000,
        )

        self.assertEqual(plan["relay_payment_address"], relay)
        self.assertEqual(plan["pool_payment_address"], pool)

    def test_provider_route_is_persisted_and_bound_to_the_session(self) -> None:
        route = {
            "peer_id": "peer_route",
            "payment_address": self.provider,
            "addresses": ["myco+relays://bridge.example/peer_route"],
        }
        plan = self.store.create_plan(
            account_id="acct_route",
            consumer=self.consumer,
            provider_id="peer_route",
            provider_payment_address=self.provider,
            provider_route=route,
            deployment=self.deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_100,
            now=2_000_000_000,
        )

        self.assertEqual(self.store.plan(str(plan["session_id"]))["provider"], route)
        with self.assertRaisesRegex(SessionServiceError, "peer_id does not match"):
            self.store.set_provider_route(
                str(plan["session_id"]),
                {**route, "peer_id": "peer_other"},
            )

    def test_existing_session_database_adds_provider_route_column(self) -> None:
        with self.store._connect() as db:
            db.execute("ALTER TABLE session_v4 DROP COLUMN provider_json")

        migrated = SessionV4Store(
            self.store.path,
            secret="test-session-secret-with-at-least-32-bytes",
        )
        with migrated._connect() as db:
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(session_v4)")}

        self.assertIn("provider_json", columns)

    def test_v5_plan_binds_relay_payout_and_independent_attestation_identity(self) -> None:
        relay = "0x" + "3" * 40
        relay_signer = "0x" + "5" * 40
        deployment = SessionDeployment(
            **{
                **self.deployment.__dict__,
                "protocol_version": 5,
                "relay_payment_address": relay,
                "relay_attestation_address": relay_signer,
            }
        )
        plan = self.store.create_plan(
            account_id="acct_v5",
            consumer=self.consumer,
            provider_id="peer_v5",
            provider_payment_address=self.provider,
            deployment=deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_100,
            now=2_000_000_000,
        )

        self.assertEqual(plan["schema"], "mycomesh.consumer.v5.plan.v1")
        self.assertEqual(plan["protocol_version"], 5)
        self.assertEqual(plan["relay_payment_address"], relay)
        self.assertEqual(plan["relay_attestation_address"], relay_signer)

        with self.assertRaisesRegex(SessionServiceError, "both be set or zero"):
            SessionDeployment(
                **{
                    **self.deployment.__dict__,
                    "protocol_version": 5,
                    "relay_payment_address": relay,
                }
            ).normalized()

    def test_latest_active_ignores_a_newer_unactivated_plan(self) -> None:
        active = self.store.create_plan(
            account_id="acct_latest",
            consumer=self.consumer,
            provider_id="peer_active",
            provider_payment_address=self.provider,
            deployment=self.deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_200,
            now=2_000_000_000,
        )
        self.store.mark_activated(str(active["session_id"]), now=2_000_000_001)
        pending = self.store.create_plan(
            account_id="acct_latest",
            consumer=self.consumer,
            provider_id="peer_pending",
            provider_payment_address=self.provider,
            deployment=self.deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_200,
            now=2_000_000_002,
        )

        self.assertEqual(
            self.store.latest_active(account_id="acct_latest", now=2_000_000_003)["session_id"],
            active["session_id"],
        )
        self.assertEqual(
            self.store.latest_active(
                account_id="acct_latest",
                require_activated=False,
                now=2_000_000_003,
            )["session_id"],
            pending["session_id"],
        )

    def test_latest_active_can_require_an_unclaimed_session_with_enough_balance(self) -> None:
        funded = self.store.create_plan(
            account_id="acct_capacity",
            consumer=self.consumer,
            provider_id="peer_funded",
            provider_payment_address=self.provider,
            deployment=self.deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_200,
            now=2_000_000_000,
        )
        self.store.mark_activated(str(funded["session_id"]), now=2_000_000_001)
        small = self.store.create_plan(
            account_id="acct_capacity",
            consumer=self.consumer,
            provider_id="peer_small",
            provider_payment_address=self.provider,
            deployment=self.deployment,
            max_amount_units=50,
            expires_at=2_000_000_200,
            now=2_000_000_002,
        )
        self.store.mark_activated(str(small["session_id"]), now=2_000_000_003)

        selected = self.store.latest_active(
            account_id="acct_capacity",
            require_unclaimed=True,
            minimum_fee_units=100,
            now=2_000_000_004,
        )

        self.assertEqual(selected["session_id"], funded["session_id"])

    def test_latest_active_skips_unsettleable_sessions(self) -> None:
        account_id = "acct_settlement_health"

        def plan_with_result(
            *,
            provider_id: str,
            created_at: int,
            settlement: dict[str, object],
        ) -> dict[str, object]:
            plan = self.store.create_plan(
                account_id=account_id,
                consumer=self.consumer,
                provider_id=provider_id,
                provider_payment_address=self.provider,
                deployment=self.deployment,
                max_amount_units=1_000,
                expires_at=2_000_000_500,
                now=created_at,
            )
            self.store.mark_activated(str(plan["session_id"]), now=created_at + 1)
            claim = self.store.claim_request(
                session_id=str(plan["session_id"]),
                account_id=account_id,
                request_id=f"request-{provider_id}",
                request_hash="0x" + "d" * 64,
                max_fee_units=100,
                deadline=2_000_000_400,
                signer=self.signer,
                now=created_at + 2,
            )
            self.store.finalize(
                str(plan["session_id"]),
                sequence=int(claim.request["sequence"]),
                expected_request_id=str(claim.request["request_id"]),
                amount_units=1,
                request_hash="0x" + "d" * 64,
                response_payload={"id": f"response-{provider_id}"},
                settlement_payload=settlement,
                now=created_at + 3,
            )
            return plan

        healthy = self.store.create_plan(
            account_id=account_id,
            consumer=self.consumer,
            provider_id="peer-healthy",
            provider_payment_address=self.provider,
            deployment=self.deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_500,
            now=2_000_000_000,
        )
        self.store.mark_activated(str(healthy["session_id"]), now=2_000_000_001)
        failed = plan_with_result(
            provider_id="peer-failed",
            created_at=2_000_000_010,
            settlement={"receipt": {"deadline": 2_000_000_400}},
        )
        self.store.mark_settlement_failed(
            session_id=str(failed["session_id"]),
            request_id="request-peer-failed",
            error="terminal",
            retryable=False,
        )
        plan_with_result(
            provider_id="peer-expired",
            created_at=2_000_000_020,
            settlement={"receipt": {"deadline": 2_000_000_050}},
        )
        plan_with_result(
            provider_id="peer-malformed",
            created_at=2_000_000_030,
            settlement={"receipt": {}},
        )

        selected = self.store.latest_active(
            account_id=account_id,
            now=2_000_000_100,
        )

        self.assertEqual(selected["session_id"], healthy["session_id"])

    def test_latest_active_keeps_delivered_and_confirmed_sessions(self) -> None:
        account_id = "acct_settled"

        def settled_plan(provider_id: str, created_at: int, status: str) -> dict[str, object]:
            plan = self.store.create_plan(
                account_id=account_id,
                consumer=self.consumer,
                provider_id=provider_id,
                provider_payment_address=self.provider,
                deployment=self.deployment,
                max_amount_units=1_000,
                expires_at=2_000_000_500,
                now=created_at,
            )
            self.store.mark_activated(str(plan["session_id"]), now=created_at + 1)
            request_id = f"request-{provider_id}"
            claim = self.store.claim_request(
                session_id=str(plan["session_id"]),
                account_id=account_id,
                request_id=request_id,
                request_hash="0x" + "e" * 64,
                max_fee_units=100,
                deadline=2_000_000_400,
                signer=self.signer,
                now=created_at + 2,
            )
            self.store.finalize(
                str(plan["session_id"]),
                sequence=int(claim.request["sequence"]),
                expected_request_id=request_id,
                amount_units=1,
                request_hash="0x" + "e" * 64,
                response_payload={"id": f"response-{provider_id}"},
                settlement_payload={"malformed": True},
                now=created_at + 3,
            )
            if status == "confirmed":
                self.store.mark_settlement_confirmed(
                    session_id=str(plan["session_id"]),
                    request_id=request_id,
                )
            else:
                self.store.mark_settlement_delivered(
                    session_id=str(plan["session_id"]),
                    request_id=request_id,
                    settlement_key=f"key-{provider_id}",
                    route_address="myco+relays://bridge.example/provider",
                    submission={"provider": provider_id},
                )
            return plan

        confirmed = settled_plan("peer-confirmed", 2_000_000_010, "confirmed")
        self.assertEqual(
            self.store.latest_active(account_id=account_id, now=2_000_000_100)["session_id"],
            confirmed["session_id"],
        )
        delivered = settled_plan("peer-delivered", 2_000_000_020, "delivered")
        self.assertEqual(
            self.store.latest_active(account_id=account_id, now=2_000_000_100)["session_id"],
            delivered["session_id"],
        )

    def test_retry_returns_same_committed_response_and_durable_outbox(self) -> None:
        plan = self._plan()
        claim = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-1",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        response = {"id": "resp-1", "output": [{"text": "ok"}]}
        settlement = {"schema": "mycomesh.settlement.v4.provider.v1", "calldata": "0x1234"}
        self.store.finalize(
            str(plan["session_id"]),
            sequence=int(claim.request["sequence"]),
            expected_request_id=str(claim.request["request_id"]),
            amount_units=75,
            request_hash="0x" + "d" * 64,
            response_payload=response,
            settlement_payload=settlement,
            now=2_000_000_002,
        )
        self.assertEqual(
            self.store.completed_response(
                session_id=str(plan["session_id"]),
                request_id="req-1",
                account_id="acct_test",
                request_hash="0x" + "d" * 64,
            ),
            response,
        )
        pending = self.store.pending_settlements()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["sequence"], 1)
        self.assertEqual(pending[0]["payload"], settlement)
        self.assertEqual(self.store.plan(str(plan["session_id"]))["next_sequence"], 1)

        with self.assertRaisesRegex(SessionServiceError, "different request"):
            self.store.completed_response(
                session_id=str(plan["session_id"]),
                request_id="req-1",
                account_id="acct_test",
                request_hash="0x" + "e" * 64,
            )

    def test_finalize_atomically_persists_exact_relay_submission(self) -> None:
        plan = self._plan()
        claim = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-relay-outbox",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        response = {"id": "resp-relay-outbox", "relay_attestation": {"signature": "0x01"}}
        settlement = {"schema": "mycomesh.settlement.v5.provider.v1"}
        route = "myco+relays://bridge.example:443/provider-a"
        submission = {
            "schema": "mycomesh.relay.settlement.v1",
            "protocol_version": 5,
            "provider_settlement": settlement,
            "session_signature": "0x02",
        }

        self.store.finalize(
            str(plan["session_id"]),
            sequence=int(claim.request["sequence"]),
            expected_request_id=str(claim.request["request_id"]),
            amount_units=75,
            request_hash="0x" + "d" * 64,
            response_payload=response,
            settlement_payload=settlement,
            relay_route_address=route,
            relay_submission=submission,
            now=2_000_000_002,
        )

        pending = self.store.pending_settlements()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["response"], response)
        self.assertEqual(pending[0]["relay_route_address"], route)
        self.assertEqual(pending[0]["relay_submission"], submission)

        self.store.mark_settlement_delivered(
            session_id=str(plan["session_id"]),
            request_id=str(claim.request["request_id"]),
            settlement_key="settlement-key",
            route_address=route,
            submission=submission,
        )
        self.store.mark_settlement_failed(
            session_id=str(plan["session_id"]),
            request_id=str(claim.request["request_id"]),
            error="late worker",
            retryable=True,
        )
        self.assertEqual(self.store.pending_settlements(), [])

    def test_relay_outbox_exposes_only_each_session_head(self) -> None:
        plan = self._plan()
        for sequence in (1, 2):
            request_id = f"relay-sequence-{sequence}"
            request_hash = "0x" + str(sequence) * 64
            claim = self.store.claim_request(
                session_id=str(plan["session_id"]),
                account_id="acct_test",
                request_id=request_id,
                request_hash=request_hash,
                max_fee_units=100,
                deadline=2_000_000_050 + sequence,
                signer=self.signer,
                now=2_000_000_000 + sequence,
            )
            self.store.finalize(
                str(plan["session_id"]),
                sequence=int(claim.request["sequence"]),
                expected_request_id=request_id,
                amount_units=1,
                request_hash=request_hash,
                response_payload={"id": f"response-{sequence}"},
                settlement_payload={"sequence": sequence},
                relay_route_address="myco+relays://bridge.example:443/provider-a",
                relay_submission={"sequence": sequence},
                now=2_000_000_010 + sequence,
            )

        pending = self.store.pending_settlements(relay_only=True)
        self.assertEqual([item["sequence"] for item in pending], [1])
        self.store.mark_settlement_delivered(
            session_id=str(plan["session_id"]),
            request_id="relay-sequence-1",
            settlement_key="first",
            route_address="myco+relays://bridge.example:443/provider-a",
            submission={"sequence": 1},
        )
        pending = self.store.pending_settlements(relay_only=True)
        self.assertEqual([item["sequence"] for item in pending], [2])

    def test_legacy_relay_head_blocks_later_sequence_until_rehydrated(self) -> None:
        provider_route = {
            "peer_id": "peer_legacy",
            "payment_address": self.provider,
            "addresses": ["myco+relays://bridge.example:443/peer_legacy"],
        }
        plan = self.store.create_plan(
            account_id="acct_test",
            consumer=self.consumer,
            provider_id="peer_legacy",
            provider_payment_address=self.provider,
            provider_route=provider_route,
            deployment=self.deployment,
            max_amount_units=1_000,
            expires_at=2_000_000_100,
            now=2_000_000_000,
        )
        for sequence in (1, 2):
            request_id = f"legacy-sequence-{sequence}"
            request_hash = "0x" + str(sequence) * 64
            claim = self.store.claim_request(
                session_id=str(plan["session_id"]),
                account_id="acct_test",
                request_id=request_id,
                request_hash=request_hash,
                max_fee_units=100,
                deadline=2_000_000_050 + sequence,
                signer=self.signer,
                now=2_000_000_000 + sequence,
            )
            self.store.finalize(
                str(plan["session_id"]),
                sequence=int(claim.request["sequence"]),
                expected_request_id=request_id,
                amount_units=1,
                request_hash=request_hash,
                response_payload={"id": f"legacy-response-{sequence}"},
                settlement_payload={"sequence": sequence},
                relay_route_address=(
                    "myco+relays://bridge.example:443/peer_legacy"
                    if sequence == 2
                    else None
                ),
                relay_submission=({"sequence": sequence} if sequence == 2 else None),
                now=2_000_000_010 + sequence,
            )

        pending = self.store.pending_settlements(relay_only=True)
        self.assertEqual([item["sequence"] for item in pending], [1])
        self.assertIsNone(pending[0]["relay_route_address"])
        self.assertIsNone(pending[0]["relay_submission"])
        self.assertEqual(pending[0]["provider"], provider_route)

        rebuilt = {"sequence": 1, "rehydrated": True}
        self.store.mark_settlement_delivered(
            session_id=str(plan["session_id"]),
            request_id="legacy-sequence-1",
            settlement_key="legacy-first",
            route_address="myco+relays://bridge.example:443/peer_legacy",
            submission=rebuilt,
        )
        pending = self.store.pending_settlements(relay_only=True)
        self.assertEqual([item["sequence"] for item in pending], [2])

    def test_new_relay_outbox_delivery_cannot_change_exact_submission(self) -> None:
        plan = self._plan()
        claim = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="exact-delivery",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        route = "myco+relays://bridge.example:443/peer_test"
        submission = {"exact": True}
        self.store.finalize(
            str(plan["session_id"]),
            sequence=int(claim.request["sequence"]),
            expected_request_id=str(claim.request["request_id"]),
            amount_units=1,
            request_hash="0x" + "d" * 64,
            response_payload={"id": "exact-response"},
            settlement_payload={"receipt": True},
            relay_route_address=route,
            relay_submission=submission,
            now=2_000_000_002,
        )

        with self.assertRaisesRegex(SessionServiceError, "route changed"):
            self.store.mark_settlement_delivered(
                session_id=str(plan["session_id"]),
                request_id="exact-delivery",
                settlement_key="exact-key",
                route_address="myco+relays://other.example:443/peer_test",
                submission=submission,
            )
        self.assertEqual(len(self.store.pending_settlements(relay_only=True)), 1)

    def test_claim_request_id_is_bounded_and_hash_is_required_at_finalize(self) -> None:
        plan = self._plan()
        with self.assertRaisesRegex(SessionServiceError, "request_id"):
            self.store.claim_request(
                session_id=str(plan["session_id"]),
                account_id="acct_test",
                request_id="bad id",
                request_hash="0x" + "d" * 64,
                max_fee_units=100,
                deadline=2_000_000_050,
                signer=self.signer,
                now=2_000_000_001,
            )
        claim = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-2",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        with self.assertRaisesRegex(SessionServiceError, "request hash"):
            self.store.finalize(
                str(plan["session_id"]),
                sequence=int(claim.request["sequence"]),
                expected_request_id=str(claim.request["request_id"]),
                amount_units=1,
                request_hash="0x" + "e" * 64,
                response_payload={"ok": True},
                now=2_000_000_002,
            )

    def test_retry_refreshes_claimed_deadline_and_finalize_clears_it(self) -> None:
        plan = self._plan()
        first = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-deadline",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        retry = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-deadline",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_080,
            signer=self.signer,
            now=2_000_000_002,
        )

        self.assertEqual(retry.request["sequence"], first.request["sequence"])
        self.assertEqual(retry.request["deadline"], 2_000_000_080)

        self.store.finalize(
            str(plan["session_id"]),
            sequence=int(first.request["sequence"]),
            expected_request_id=str(first.request["request_id"]),
            amount_units=75,
            request_hash="0x" + "d" * 64,
            response_payload={"id": "resp-deadline"},
            now=2_000_000_003,
        )
        next_claim = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-after-finalize",
            request_hash="0x" + "e" * 64,
            max_fee_units=100,
            deadline=2_000_000_080,
            signer=self.signer,
            now=2_000_000_004,
        )

        self.assertEqual(next_claim.request["sequence"], 2)
        self.assertEqual(next_claim.request["deadline"], 2_000_000_080)

    def test_expired_claim_can_retry_the_exact_request_with_a_fresh_deadline(self) -> None:
        plan = self._plan()
        first = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-expired-retry",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )

        retry = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-expired-retry",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_100,
            signer=self.signer,
            now=2_000_000_051,
        )

        self.assertEqual(retry.request["sequence"], first.request["sequence"])
        self.assertEqual(retry.request["deadline"], 2_000_000_100)

    def test_expired_claim_requires_recovery_for_a_different_request(self) -> None:
        plan = self._plan()
        self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-expired",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )

        with self.assertRaisesRegex(SessionServiceError, "stale V4 request claim"):
            self.store.claim_request(
                session_id=str(plan["session_id"]),
                account_id="acct_test",
                request_id="req-new",
                request_hash="0x" + "e" * 64,
                max_fee_units=100,
                deadline=2_000_000_080,
                signer=self.signer,
                now=2_000_000_051,
            )

        self.assertIsNone(
            self.store.latest_active(
                account_id="acct_test",
                require_activated=False,
                require_unclaimed=True,
                now=2_000_000_051,
            )
        )
        self.assertEqual(
            self.store.latest_active(
                account_id="acct_test",
                require_activated=False,
                now=2_000_000_051,
            )["session_id"],
            plan["session_id"],
        )
        self.assertEqual(
            self.store.request_claim_state(str(plan["session_id"]), now=2_000_000_051),
            {
                "request_id": "req-expired",
                "client_request_id": "req-expired",
                "request_hash": "0x" + "d" * 64,
                "max_fee_units": 100,
                "deadline": 2_000_000_050,
                "claimed_at": 2_000_000_001,
                "stale": True,
                "fallback_safe": False,
            },
        )
        self.assertEqual(
            self.store.request_claim_state(str(plan["session_id"]), now=2_000_001_000),
            {
                "request_id": "req-expired",
                "client_request_id": "req-expired",
                "request_hash": "0x" + "d" * 64,
                "max_fee_units": 100,
                "deadline": 2_000_000_050,
                "claimed_at": 2_000_000_001,
                "stale": True,
                "fallback_safe": True,
            },
        )

    def test_rollback_clears_claimed_deadline(self) -> None:
        plan = self._plan()
        first = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-rollback-deadline",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        self.store.rollback(
            str(plan["session_id"]),
            sequence=int(first.request["sequence"]),
            expected_request_id=str(first.request["request_id"]),
        )
        retried = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="req-rollback-deadline",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_080,
            signer=self.signer,
            now=2_000_000_002,
        )

        self.assertEqual(retried.request["sequence"], 1)
        self.assertEqual(retried.request["deadline"], 2_000_000_080)

    def test_recovery_provider_id_keeps_durable_client_idempotency(self) -> None:
        plan = self._plan()
        original = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="codex-turn-1",
            client_request_id="codex-turn-1",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        recovered = self.store.replace_claim_attempt(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            expected_request_id="codex-turn-1",
            client_request_id="codex-turn-1",
            replacement_request_id="recover_attempt_1",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_060,
            signer=self.signer,
            now=2_000_000_002,
        )
        self.assertEqual(recovered.request["sequence"], original.request["sequence"])
        with self.assertRaisesRegex(SessionServiceError, "changed during recovery"):
            self.store.replace_claim_attempt(
                session_id=str(plan["session_id"]),
                account_id="acct_test",
                expected_request_id="codex-turn-1",
                client_request_id="codex-turn-1",
                replacement_request_id="recover_losing_attempt",
                request_hash="0x" + "d" * 64,
                max_fee_units=100,
                deadline=2_000_000_061,
                signer=self.signer,
                now=2_000_000_002,
            )

        restarted = SessionV4Store(
            self.store.path,
            secret="test-session-secret-with-at-least-32-bytes",
        )
        resumed = restarted.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="codex-turn-1",
            client_request_id="codex-turn-1",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_070,
            signer=self.signer,
            now=2_000_000_003,
        )
        self.assertEqual(resumed.request["request_id"], "recover_attempt_1")
        self.assertEqual(
            restarted.request_claim_state(str(plan["session_id"]), now=2_000_000_003)[
                "client_request_id"
            ],
            "codex-turn-1",
        )

        response = {"id": "resp-recovered", "request_id": "recover_attempt_1"}
        restarted.finalize(
            str(plan["session_id"]),
            sequence=int(resumed.request["sequence"]),
            expected_request_id=str(resumed.request["request_id"]),
            amount_units=75,
            request_hash="0x" + "d" * 64,
            response_payload=response,
            now=2_000_000_004,
        )
        for request_id in ("codex-turn-1", "recover_attempt_1"):
            self.assertEqual(
                restarted.completed_response(
                    session_id=str(plan["session_id"]),
                    request_id=request_id,
                    account_id="acct_test",
                    request_hash="0x" + "d" * 64,
                ),
                response,
            )
        with self.assertRaisesRegex(SessionServiceError, "different request"):
            restarted.completed_response(
                session_id=str(plan["session_id"]),
                request_id="codex-turn-1",
                account_id="acct_test",
                request_hash="0x" + "e" * 64,
            )

    def test_only_one_concurrent_recovery_attempt_wins(self) -> None:
        plan = self._plan()
        self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="codex-race",
            client_request_id="codex-race",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        stores = [
            SessionV4Store(
                self.store.path,
                secret="test-session-secret-with-at-least-32-bytes",
            )
            for _ in range(2)
        ]
        barrier = threading.Barrier(2)
        outcomes: list[object] = []
        outcomes_lock = threading.Lock()

        def recover(store: SessionV4Store, replacement: str) -> None:
            barrier.wait()
            try:
                outcome: object = store.replace_claim_attempt(
                    session_id=str(plan["session_id"]),
                    account_id="acct_test",
                    expected_request_id="codex-race",
                    client_request_id="codex-race",
                    replacement_request_id=replacement,
                    request_hash="0x" + "d" * 64,
                    max_fee_units=100,
                    deadline=2_000_000_060,
                    signer=self.signer,
                    now=2_000_000_002,
                )
            except SessionServiceError as exc:
                outcome = exc
            with outcomes_lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=recover, args=(store, f"recover_race_{index}"))
            for index, store in enumerate(stores)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        winners = [outcome for outcome in outcomes if not isinstance(outcome, Exception)]
        losers = [outcome for outcome in outcomes if isinstance(outcome, SessionServiceError)]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)
        self.assertEqual(
            self.store.request_claim_state(str(plan["session_id"]))["request_id"],
            winners[0].request["request_id"],
        )

    def test_recovery_attempt_is_fenced_from_old_rollback_and_finalize(self) -> None:
        plan = self._plan()
        original = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="codex-fenced",
            client_request_id="codex-fenced",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        replace_store, rollback_store = [
            SessionV4Store(
                self.store.path,
                secret="test-session-secret-with-at-least-32-bytes",
            )
            for _ in range(2)
        ]
        replaced = threading.Event()
        outcomes: dict[str, object] = {}

        def replace() -> None:
            try:
                outcomes["claim"] = replace_store.replace_claim_attempt(
                    session_id=str(plan["session_id"]),
                    account_id="acct_test",
                    expected_request_id="codex-fenced",
                    client_request_id="codex-fenced",
                    replacement_request_id="recover_fenced",
                    request_hash="0x" + "d" * 64,
                    max_fee_units=100,
                    deadline=2_000_000_060,
                    signer=self.signer,
                    now=2_000_000_002,
                )
            finally:
                replaced.set()

        def rollback_old() -> None:
            if not replaced.wait(5):
                outcomes["rollback"] = TimeoutError("replace did not complete")
                return
            outcomes["rollback"] = rollback_store.rollback(
                str(plan["session_id"]),
                sequence=int(original.request["sequence"]),
                expected_request_id="codex-fenced",
            )

        threads = [threading.Thread(target=replace), threading.Thread(target=rollback_old)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive())

        recovered = outcomes["claim"]
        self.assertFalse(outcomes["rollback"])
        with self.assertRaisesRegex(SessionServiceError, "does not match finalization"):
            self.store.finalize(
                str(plan["session_id"]),
                sequence=int(original.request["sequence"]),
                expected_request_id="codex-fenced",
                amount_units=75,
                request_hash="0x" + "d" * 64,
                response_payload={"id": "late-old-response"},
                now=2_000_000_003,
            )
        self.assertEqual(
            self.store.request_claim_state(str(plan["session_id"]))["request_id"],
            recovered.request["request_id"],
        )

    def test_rollback_winner_prevents_recovery_replacement(self) -> None:
        plan = self._plan()
        original = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="codex-rollback-wins",
            client_request_id="codex-rollback-wins",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        rollback_store, replace_store = [
            SessionV4Store(
                self.store.path,
                secret="test-session-secret-with-at-least-32-bytes",
            )
            for _ in range(2)
        ]
        rolled_back = threading.Event()
        outcomes: dict[str, object] = {}

        def rollback_first() -> None:
            try:
                outcomes["rollback"] = rollback_store.rollback(
                    str(plan["session_id"]),
                    sequence=int(original.request["sequence"]),
                    expected_request_id="codex-rollback-wins",
                )
            finally:
                rolled_back.set()

        def replace_late() -> None:
            if not rolled_back.wait(5):
                outcomes["replace"] = TimeoutError("rollback did not complete")
                return
            try:
                replace_store.replace_claim_attempt(
                    session_id=str(plan["session_id"]),
                    account_id="acct_test",
                    expected_request_id="codex-rollback-wins",
                    client_request_id="codex-rollback-wins",
                    replacement_request_id="recover_too_late",
                    request_hash="0x" + "d" * 64,
                    max_fee_units=100,
                    deadline=2_000_000_060,
                    signer=self.signer,
                    now=2_000_000_002,
                )
            except SessionServiceError as exc:
                outcomes["replace"] = exc

        threads = [threading.Thread(target=rollback_first), threading.Thread(target=replace_late)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive())

        self.assertTrue(outcomes["rollback"])
        self.assertRegex(str(outcomes["replace"]), "changed during recovery")
        self.assertIsNone(self.store.request_claim_state(str(plan["session_id"])))

    def test_late_claim_after_finalize_cannot_allocate_a_new_sequence(self) -> None:
        plan = self._plan()
        claim = self.store.claim_request(
            session_id=str(plan["session_id"]),
            account_id="acct_test",
            request_id="codex-finalize-race",
            client_request_id="codex-finalize-race",
            request_hash="0x" + "d" * 64,
            max_fee_units=100,
            deadline=2_000_000_050,
            signer=self.signer,
            now=2_000_000_001,
        )
        finalizer = SessionV4Store(
            self.store.path,
            secret="test-session-secret-with-at-least-32-bytes",
        )
        late_reader = SessionV4Store(
            self.store.path,
            secret="test-session-secret-with-at-least-32-bytes",
        )
        finalized = threading.Event()
        outcomes: list[object] = []

        def finalize() -> None:
            try:
                finalizer.finalize(
                    str(plan["session_id"]),
                    sequence=int(claim.request["sequence"]),
                    expected_request_id=str(claim.request["request_id"]),
                    amount_units=75,
                    request_hash="0x" + "d" * 64,
                    response_payload={"id": "resp-finalize-race"},
                    now=2_000_000_002,
                )
            finally:
                finalized.set()

        def claim_late() -> None:
            if not finalized.wait(5):
                outcomes.append(TimeoutError("finalize did not complete"))
                return
            try:
                late_reader.claim_request(
                    session_id=str(plan["session_id"]),
                    account_id="acct_test",
                    request_id="codex-finalize-race",
                    client_request_id="codex-finalize-race",
                    request_hash="0x" + "d" * 64,
                    max_fee_units=100,
                    deadline=2_000_000_060,
                    signer=self.signer,
                    now=2_000_000_003,
                )
            except SessionServiceError as exc:
                outcomes.append(exc)

        threads = [threading.Thread(target=finalize), threading.Thread(target=claim_late)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive())

        self.assertEqual(len(outcomes), 1)
        self.assertRegex(str(outcomes[0]), "client_request_id is already completed")
        self.assertEqual(self.store.plan(str(plan["session_id"]))["next_sequence"], 1)
        self.assertIsNone(self.store.request_claim_state(str(plan["session_id"])))

    def test_existing_database_migrates_recovery_alias_columns(self) -> None:
        path = Path(self.tmp.name) / "legacy-session.sqlite3"
        SessionV4Store(path, secret="test-session-secret-with-at-least-32-bytes")
        with sqlite3.connect(path) as db:
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(session_v4)")}
            self.assertIn("claimed_deadline", columns)
            db.execute("DROP INDEX session_v4_results_client_idx")
            db.execute("ALTER TABLE session_v4 DROP COLUMN claimed_deadline")
            db.execute("ALTER TABLE session_v4 DROP COLUMN claimed_client_request_id")
            db.execute("ALTER TABLE session_v4_results DROP COLUMN client_request_id")

        SessionV4Store(path, secret="test-session-secret-with-at-least-32-bytes")
        with sqlite3.connect(path) as db:
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(session_v4)")}
            result_columns = {
                str(row[1]) for row in db.execute("PRAGMA table_info(session_v4_results)")
            }

        self.assertIn("claimed_deadline", columns)
        self.assertIn("claimed_client_request_id", columns)
        self.assertIn("client_request_id", result_columns)
        self.assertIn("relay_route_address", result_columns)
        self.assertIn("relay_submission_json", result_columns)
        self.assertIn("settlement_attempted_at", result_columns)


if __name__ == "__main__":
    unittest.main()
