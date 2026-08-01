from __future__ import annotations

import unittest

from gateway.chain import ChainError, SECP256K1_N, parse_private_key, private_key_to_address
from gateway.chain_v6 import (
    V6_SESSION_RECEIPT_SIGNATURE,
    build_provider_settlement_payload,
    build_relay_attestation,
    encode_settle_signed_receipt,
    verify_provider_settlement_payload,
    verify_relay_attestation,
)


class ChainV6Test(unittest.TestCase):
    provider_key = "0x" + "11" * 32
    relay_key = "0x" + "22" * 32
    session_key = "0x" + "33" * 32
    contract = "0x" + "44" * 20
    consumer = "0x" + "55" * 20

    def _payload(self, *, epoch: int = 0, relay: str = "0x" + "bb" * 20):
        return build_provider_settlement_payload(
            provider_private_key=self.provider_key,
            chain_id=11155111,
            settlement_contract=self.contract,
            session_id="0x" + "66" * 32,
            request_hash="0x" + "77" * 32,
            response_hash="0x" + "88" * 32,
            channel_hash="0x" + "99" * 32,
            pricing_version=1,
            pricing_hash="0x" + "aa" * 32,
            consumer=self.consumer,
            provider=private_key_to_address(parse_private_key(self.provider_key)),
            relay=relay,
            pool="0x" + "cc" * 20,
            relay_epoch=epoch,
            input_tokens=10,
            output_tokens=20,
            sequence=0,
            quoted_fee=2000,
            deadline=2_000_000_000,
        )

    def test_epoch_is_bound_by_provider_and_relay_signatures(self):
        payload = self._payload(epoch=3)
        receipt = verify_provider_settlement_payload(payload)
        attestation = build_relay_attestation(
            private_key=self.relay_key,
            chain_id=payload["chain_id"],
            settlement_contract=payload["settlement_contract"],
            session_id=receipt.session_id,
            request_hash=receipt.request_hash,
            provider=receipt.provider,
            relay=receipt.relay,
            relay_epoch=receipt.relay_epoch,
            sequence=receipt.sequence,
            deadline=receipt.deadline,
        )
        verified = verify_relay_attestation(
            attestation,
            expected_signer=private_key_to_address(parse_private_key(self.relay_key)),
            receipt=receipt,
        )
        signature = bytes.fromhex(payload["provider_signature"][2:])
        relay_signature = bytes.fromhex(verified["signature"][2:])
        calldata = encode_settle_signed_receipt(receipt, verified, signature, signature, relay_signature)
        self.assertTrue(calldata.startswith("0x"))
        self.assertIn("uint64,uint256,uint256,uint256", V6_SESSION_RECEIPT_SIGNATURE)

    def test_direct_route_uses_zero_attestation(self):
        payload = self._payload(relay="0x" + "00" * 20)
        raw = dict(payload["receipt"])
        raw["pool"] = "0x" + "00" * 20
        direct = build_provider_settlement_payload(
            provider_private_key=self.provider_key,
            chain_id=payload["chain_id"],
            settlement_contract=payload["settlement_contract"],
            session_id=raw["session_id"],
            request_hash=raw["request_hash"],
            response_hash=raw["response_hash"],
            channel_hash=raw["channel"],
            pricing_version=raw["pricing_version"],
            pricing_hash=raw["pricing_hash"],
            consumer=raw["consumer"],
            provider=raw["provider"],
            relay=raw["relay"],
            pool=raw["pool"],
            relay_epoch=raw["relay_epoch"],
            input_tokens=raw["input_tokens"],
            output_tokens=raw["output_tokens"],
            sequence=raw["sequence"],
            quoted_fee=raw["quoted_fee"],
            deadline=raw["deadline"],
        )
        receipt = verify_provider_settlement_payload(direct)
        signature = bytes.fromhex(direct["provider_signature"][2:])
        self.assertTrue(encode_settle_signed_receipt(receipt, None, signature, signature, b""))

    def test_rejects_epoch_tampering(self):
        payload = self._payload(epoch=1)
        receipt = verify_provider_settlement_payload(payload)
        attestation = build_relay_attestation(
            private_key=self.relay_key,
            chain_id=payload["chain_id"],
            settlement_contract=payload["settlement_contract"],
            session_id=receipt.session_id,
            request_hash=receipt.request_hash,
            provider=receipt.provider,
            relay=receipt.relay,
            relay_epoch=receipt.relay_epoch + 1,
            sequence=receipt.sequence,
            deadline=receipt.deadline,
        )
        with self.assertRaisesRegex(ChainError, "relay_epoch does not match"):
            verify_relay_attestation(attestation, expected_signer=attestation["signer"], receipt=receipt)

    def test_rejects_high_s_attestation(self):
        payload = self._payload()
        receipt = verify_provider_settlement_payload(payload)
        attestation = build_relay_attestation(
            private_key=self.relay_key,
            chain_id=payload["chain_id"],
            settlement_contract=payload["settlement_contract"],
            session_id=receipt.session_id,
            request_hash=receipt.request_hash,
            provider=receipt.provider,
            relay=receipt.relay,
            relay_epoch=receipt.relay_epoch,
            sequence=receipt.sequence,
            deadline=receipt.deadline,
        )
        raw = bytes.fromhex(attestation["signature"][2:])
        high_s = SECP256K1_N - int.from_bytes(raw[32:64], "big")
        mutated = dict(attestation)
        mutated["signature"] = "0x" + (raw[:32] + high_s.to_bytes(32, "big") + raw[64:]).hex()
        with self.assertRaisesRegex(ChainError, "low-s"):
            verify_relay_attestation(mutated, expected_signer=attestation["signer"], receipt=receipt)


if __name__ == "__main__":
    unittest.main()
