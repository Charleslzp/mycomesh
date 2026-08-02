from __future__ import annotations

import tempfile
import time
import unittest
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

from gateway.chain import ZERO_ADDRESS, channel_to_hash, parse_private_key, private_key_to_address, sign_evm_digest
from gateway.chain_v5 import (
    build_provider_settlement_payload,
    build_relay_attestation,
    encode_settle_signed_batch_tuples,
    encode_settle_signed_receipt_tuple,
    session_receipt_digest,
    verify_provider_settlement_payload,
)
from gateway.pricing import DEFAULT_CHANNEL
from gateway.session_relayer import (
    RELAY_SETTLEMENT_SCHEMA,
    RelaySettlementError,
    RelaySettlementOutbox,
    RelaySettlementSubmitter,
    prepare_relay_settlement,
)
from gateway.relay import RelayControlHandler, RelayError, RelayState


class SessionRelayerTest(unittest.TestCase):
    provider_key = "0x" + "1" * 64
    consumer_key = "0x" + "2" * 64
    relay_attestation_key = "0x" + "3" * 64
    contract = "0x" + "a" * 40
    chain_id = 11155111

    def _submission(
        self,
        *,
        sequence: int = 0,
        request_byte: str = "12",
        deadline: int | None = None,
    ) -> dict:
        provider = private_key_to_address(parse_private_key(self.provider_key))
        consumer = private_key_to_address(parse_private_key(self.consumer_key))
        relay = "0x" + "b" * 40
        attestation_signer = private_key_to_address(parse_private_key(self.relay_attestation_key))
        deadline = int(time.time()) + 300 if deadline is None else int(deadline)
        provider_payload = build_provider_settlement_payload(
            provider_private_key=self.provider_key,
            chain_id=self.chain_id,
            settlement_contract=self.contract,
            session_id="0x" + "11" * 32,
            request_hash="0x" + request_byte * 32,
            response_hash="0x" + f"{int(request_byte, 16) + 1:02x}" * 32,
            channel_hash=channel_to_hash(DEFAULT_CHANNEL),
            pricing_version=1,
            pricing_hash="0x" + "99" * 32,
            consumer=consumer,
            provider=provider,
            relay=relay,
            pool=ZERO_ADDRESS,
            input_tokens=10,
            output_tokens=20,
            sequence=sequence,
            quoted_fee=100,
            deadline=deadline,
        )
        receipt = verify_provider_settlement_payload(provider_payload)
        attestation = build_relay_attestation(
            private_key=self.relay_attestation_key,
            chain_id=self.chain_id,
            settlement_contract=self.contract,
            session_id=receipt.session_id,
            request_hash=receipt.request_hash,
            provider=receipt.provider,
            relay=receipt.relay,
            sequence=receipt.sequence,
            deadline=receipt.deadline,
        )
        digest = session_receipt_digest(
            receipt,
            chain_id=self.chain_id,
            verifying_contract=self.contract,
        )
        signature = sign_evm_digest(self.consumer_key, digest)
        session_signature = (
            "0x"
            + signature.r[2:]
            + signature.s[2:]
            + f"{signature.v:02x}"
        )
        return {
            "schema": RELAY_SETTLEMENT_SCHEMA,
            "protocol_version": 5,
            "chain_id": self.chain_id,
            "settlement_contract": self.contract,
            "provider_settlement": provider_payload,
            "session_signature": session_signature,
            "relay_attestation": attestation,
            "relay": relay,
            "attestation_signer": attestation_signer,
        }

    @staticmethod
    def _post_settlement(state: Any, submission: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        handler = RelayControlHandler.__new__(RelayControlHandler)
        handler.server = SimpleNamespace(state=state)
        handler.path = "/v5/settlements"
        handler._read_deadline = None
        handler.headers = Message()
        handler._read_json = Mock(return_value=submission)
        handler._write = Mock()
        handler.do_POST()
        return handler._write.call_args.args[:2]

    def test_prepare_requires_all_three_signatures(self) -> None:
        submission = self._submission()
        relay = submission.pop("relay")
        signer = submission.pop("attestation_signer")
        prepared = prepare_relay_settlement(
            submission,
            expected_chain_id=self.chain_id,
            expected_contract=self.contract,
            expected_relay=relay,
            attestation_private_keys={signer: self.relay_attestation_key},
        )
        self.assertTrue(prepared.calldata.startswith("0x"))
        self.assertEqual(prepared.sequence, 0)

        invalid = dict(submission)
        invalid["session_signature"] = "0x" + "00" * 65
        with self.assertRaises(RelaySettlementError):
            prepare_relay_settlement(
                invalid,
                expected_chain_id=self.chain_id,
                expected_contract=self.contract,
                expected_relay=relay,
                attestation_private_keys={signer: self.relay_attestation_key},
            )

    def test_outbox_deduplicates_receipt(self) -> None:
        submission = self._submission()
        relay = submission.pop("relay")
        signer = submission.pop("attestation_signer")
        prepared = prepare_relay_settlement(
            submission,
            expected_chain_id=self.chain_id,
            expected_contract=self.contract,
            expected_relay=relay,
            attestation_private_keys={signer: self.relay_attestation_key},
        )
        with tempfile.TemporaryDirectory() as directory:
            outbox = RelaySettlementOutbox(Path(directory) / "relay.sqlite3")
            self.assertEqual(outbox.enqueue(prepared), ("pending", True))
            self.assertEqual(outbox.enqueue(prepared), ("pending", False))
            item = outbox.next_item()
            self.assertIsNotNone(item)
            assert item is not None
            self.assertEqual(item["settlement_key"], prepared.key)
            self.assertEqual(outbox.snapshot(), {"pending": 1})

    def test_relay_acknowledges_only_durable_expired_settlement(self) -> None:
        submission = self._submission(deadline=int(time.time()) - 1)
        relay = submission.pop("relay")
        signer = submission.pop("attestation_signer")
        with tempfile.TemporaryDirectory() as directory:
            outbox = RelaySettlementOutbox(Path(directory) / "relay.sqlite3")
            submitter = RelaySettlementSubmitter(
                outbox=outbox,
                rpc_url="http://127.0.0.1:8545",
                private_key="0x" + "4" * 64,
            )
            state = SimpleNamespace(
                _settlement_submitter=submitter,
                settlement_chain_id=self.chain_id,
                settlement_contract=self.contract,
                payment_address=relay,
                attestation_private_keys={signer: self.relay_attestation_key},
            )
            prepared = prepare_relay_settlement(
                submission,
                expected_chain_id=self.chain_id,
                expected_contract=self.contract,
                expected_relay=relay,
                attestation_private_keys={signer: self.relay_attestation_key},
                now=0,
            )
            outbox.enqueue(prepared)

            status, response = self._post_settlement(state, submission)
            self.assertEqual(status, 202)
            self.assertEqual(
                response,
                {
                    "ok": True,
                    "schema": "mycomesh.relay.settlement.accepted.v1",
                    "settlement_key": prepared.key,
                    "status": "pending",
                    "accepted": False,
                },
            )

            outbox.mark_confirmed(prepared.key, "0x" + "ab" * 32)
            status, response = self._post_settlement(state, submission)
            self.assertEqual(status, 202)
            self.assertEqual(response["status"], "confirmed")
            self.assertIs(response["accepted"], False)

            outbox.mark_failed(prepared.key, "permanent failure", retryable=False)
            status, response = self._post_settlement(state, submission)
            self.assertEqual(status, 202)
            self.assertEqual(response["status"], "failed")
            self.assertIs(response["accepted"], False)
            self.assertEqual(outbox.snapshot(), {"failed": 1})

            tampered = {
                **submission,
                "relay_attestation": {
                    **submission["relay_attestation"],
                    "signature": "0x" + "00" * 65,
                },
            }
            status, response = self._post_settlement(state, tampered)
            self.assertEqual(status, 400)
            self.assertIn("invalid Relay attestation", response["error"])

            unknown = self._submission(
                request_byte="14",
                deadline=int(time.time()) - 1,
            )
            unknown.pop("relay")
            unknown.pop("attestation_signer")
            status, response = self._post_settlement(state, unknown)
            self.assertEqual(status, 400)
            self.assertIn("attestation deadline has elapsed", response["error"])

    def test_outbox_keeps_same_session_sequences_ordered_for_batches(self) -> None:
        submissions = [self._submission(sequence=0, request_byte="12"), self._submission(sequence=1, request_byte="14")]
        prepared: list[Any] = []
        for submission in submissions:
            relay = submission.pop("relay")
            signer = submission.pop("attestation_signer")
            prepared.append(
                prepare_relay_settlement(
                    submission,
                    expected_chain_id=self.chain_id,
                    expected_contract=self.contract,
                    expected_relay=relay,
                    attestation_private_keys={signer: self.relay_attestation_key},
                )
            )
        with tempfile.TemporaryDirectory() as directory:
            outbox = RelaySettlementOutbox(Path(directory) / "relay.sqlite3")
            outbox.enqueue(prepared[1])
            outbox.enqueue(prepared[0])
            batch = outbox.next_batch(8)
            self.assertEqual([int(item["sequence"]) for item in batch], [0, 1])
            outbox.mark_confirmed(prepared[0].key, "0x" + "01" * 32)
            batch = outbox.next_batch(8)
            self.assertEqual([int(item["sequence"]) for item in batch], [1])

    def test_batch_calldata_uses_settle_signed_batch_abi(self) -> None:
        submission = self._submission()
        relay = submission.pop("relay")
        signer = submission.pop("attestation_signer")
        prepared = prepare_relay_settlement(
            submission,
            expected_chain_id=self.chain_id,
            expected_contract=self.contract,
            expected_relay=relay,
            attestation_private_keys={signer: self.relay_attestation_key},
        )
        tuple_data = bytes.fromhex(str(prepared.payload["tuple_data"])[2:])
        calldata = encode_settle_signed_batch_tuples([tuple_data])
        self.assertTrue(calldata.startswith("0x"))
        self.assertNotEqual(calldata[:10], prepared.calldata[:10])
        self.assertEqual(
            tuple_data,
            encode_settle_signed_receipt_tuple(
                verify_provider_settlement_payload(prepared.payload["provider_settlement"]),
                prepared.payload["relay_attestation"],
                bytes.fromhex(str(prepared.payload["session_signature"])[2:]),
                bytes.fromhex(str(prepared.payload["provider_settlement"]["provider_signature"])[2:]),
                bytes.fromhex(str(prepared.payload["relay_attestation"]["signature"])[2:]),
            ),
        )

    def test_submitter_sends_one_transaction_for_an_ordered_batch(self) -> None:
        prepared: list[Any] = []
        for sequence, request_byte in ((0, "12"), (1, "14")):
            submission = self._submission(sequence=sequence, request_byte=request_byte)
            relay = submission.pop("relay")
            signer = submission.pop("attestation_signer")
            prepared.append(
                prepare_relay_settlement(
                    submission,
                    expected_chain_id=self.chain_id,
                    expected_contract=self.contract,
                    expected_relay=relay,
                    attestation_private_keys={signer: self.relay_attestation_key},
                )
            )
        with tempfile.TemporaryDirectory() as directory:
            outbox = RelaySettlementOutbox(Path(directory) / "relay.sqlite3")
            for item in prepared:
                outbox.enqueue(item)
            submitter = RelaySettlementSubmitter(
                outbox=outbox,
                rpc_url="http://127.0.0.1:8545",
                private_key=self.relay_attestation_key,
                batch_size=8,
            )
            with (
                patch("gateway.session_relayer.send_contract_data_transaction", return_value="0x" + "99" * 32) as send,
                patch("gateway.session_relayer.rpc_call", return_value={"status": "0x1"}),
            ):
                submitter._process(outbox.next_batch(8))
            send.assert_called_once()
            self.assertTrue(str(send.call_args.kwargs["data"]).startswith("0x"))
            self.assertEqual(outbox.snapshot(), {"confirmed": 2})

    def test_relay_submitter_requires_payout_and_pinned_deployment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = {
                "settlement_rpc_url": "http://127.0.0.1:8545",
                "settlement_private_key": self.relay_attestation_key,
                "settlement_db_path": Path(directory) / "relay.sqlite3",
            }
            with self.assertRaisesRegex(RelayError, "payment_address"):
                RelayState(**common)
            with self.assertRaisesRegex(RelayError, "settlement_chain_id"):
                RelayState(
                    **common,
                    payment_address="0x" + "b" * 40,
                )
            state = RelayState(
                **common,
                payment_address="0x" + "b" * 40,
                settlement_chain_id=self.chain_id,
                settlement_contract=self.contract,
            )
            self.assertTrue(state._settlement_submitter is not None)
            assert state._settlement_submitter is not None
            self.assertEqual(state._settlement_submitter.batch_size, 8)


if __name__ == "__main__":
    unittest.main()
