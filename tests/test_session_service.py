from __future__ import annotations

import sqlite3
import tempfile
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
        self.store.rollback(str(plan["session_id"]), sequence=int(first.request["sequence"]))
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

    def test_existing_database_migrates_claimed_deadline_column(self) -> None:
        path = Path(self.tmp.name) / "legacy-session.sqlite3"
        SessionV4Store(path, secret="test-session-secret-with-at-least-32-bytes")
        with sqlite3.connect(path) as db:
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(session_v4)")}
            self.assertIn("claimed_deadline", columns)
            db.execute("ALTER TABLE session_v4 DROP COLUMN claimed_deadline")

        SessionV4Store(path, secret="test-session-secret-with-at-least-32-bytes")
        with sqlite3.connect(path) as db:
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(session_v4)")}

        self.assertIn("claimed_deadline", columns)


if __name__ == "__main__":
    unittest.main()
