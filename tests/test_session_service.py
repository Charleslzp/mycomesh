from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
