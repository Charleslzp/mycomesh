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

    def test_retry_reuses_claimed_deadline_and_finalize_clears_it(self) -> None:
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
        self.assertEqual(retry.request["deadline"], 2_000_000_050)

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
