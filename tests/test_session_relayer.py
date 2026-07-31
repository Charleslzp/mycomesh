from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from gateway.chain import ZERO_ADDRESS, channel_to_hash, parse_private_key, private_key_to_address, sign_evm_digest
from gateway.chain_v5 import (
    build_provider_settlement_payload,
    build_relay_attestation,
    session_receipt_digest,
    verify_provider_settlement_payload,
)
from gateway.pricing import DEFAULT_CHANNEL
from gateway.session_relayer import (
    RELAY_SETTLEMENT_SCHEMA,
    RelaySettlementError,
    RelaySettlementOutbox,
    prepare_relay_settlement,
)
from gateway.relay import RelayError, RelayState


class SessionRelayerTest(unittest.TestCase):
    provider_key = "0x" + "1" * 64
    consumer_key = "0x" + "2" * 64
    relay_attestation_key = "0x" + "3" * 64
    contract = "0x" + "a" * 40
    chain_id = 11155111

    def _submission(self) -> dict:
        provider = private_key_to_address(parse_private_key(self.provider_key))
        consumer = private_key_to_address(parse_private_key(self.consumer_key))
        relay = "0x" + "b" * 40
        attestation_signer = private_key_to_address(parse_private_key(self.relay_attestation_key))
        deadline = int(time.time()) + 300
        provider_payload = build_provider_settlement_payload(
            provider_private_key=self.provider_key,
            chain_id=self.chain_id,
            settlement_contract=self.contract,
            session_id="0x" + "11" * 32,
            request_hash="0x" + "12" * 32,
            response_hash="0x" + "13" * 32,
            channel_hash=channel_to_hash(DEFAULT_CHANNEL),
            pricing_version=1,
            pricing_hash="0x" + "99" * 32,
            consumer=consumer,
            provider=provider,
            relay=relay,
            pool=ZERO_ADDRESS,
            input_tokens=10,
            output_tokens=20,
            sequence=0,
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


if __name__ == "__main__":
    unittest.main()
