from __future__ import annotations

import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.attestation import build_provider_settlement_attestation
from gateway.chain import ChainError, derive_contract_address, private_key_to_address, parse_private_key, recover_evm_address
from gateway.chain_v3 import (
    EIP1271SignatureRejected,
    SETTLE_PROVIDER_FALLBACK_V3_SIGNATURE,
    SETTLE_SIGNED_V3_SIGNATURE,
    V3Deployment,
    V3ReceiptInput,
    V3SignedReceiptInput,
    build_provider_fallback_receipt_input,
    build_signed_receipt_input,
    create_reservation,
    default_pricing_hash,
    derive_v3_testnet_addresses,
    encode_settle_provider_fallback,
    encode_settle_signed_receipt,
    load_deployment,
    receipt_digest,
    reservation_id_for,
    save_deployment,
    signature_bytes,
    verify_eip1271_signature,
)
from gateway.identity import create_identity
from gateway.ledger import build_receipt, sign_acceptance, sign_receipt, stable_hash
from gateway.pricing import DEFAULT_CHANNEL, quote_usage
from gateway.reservation import build_payment_reservation, verify_payment_reservation


class ChainV3Test(unittest.TestCase):
    def setUp(self) -> None:
        self.consumer_key = "0x" + "11" * 32
        self.provider_key = "0x" + "22" * 32
        self.consumer_address = private_key_to_address(parse_private_key(self.consumer_key))
        self.provider_address = private_key_to_address(parse_private_key(self.provider_key))
        self.settlement = "0x" + "33" * 20
        self.chain_id = 31_337

    def test_reservation_id_is_namespaced_by_consumer(self) -> None:
        salt = "0x" + "44" * 32
        first = reservation_id_for(
            settlement=self.settlement,
            chain_id=self.chain_id,
            consumer=self.consumer_address,
            reservation_salt=salt,
        )
        second = reservation_id_for(
            settlement=self.settlement,
            chain_id=self.chain_id,
            consumer=self.provider_address,
            reservation_salt=salt,
        )

        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 66)

    def test_create_reservation_binds_request_hash_in_contract_call(self) -> None:
        request_hash = "0x" + "55" * 32
        with patch("gateway.chain_v3.send_contract_transaction", return_value="0x" + "66" * 32) as send:
            submission = create_reservation(
                rpc_url="https://rpc.example",
                private_key=self.consumer_key,
                settlement=self.settlement,
                reservation_salt="0x" + "44" * 32,
                provider=self.provider_address,
                channel_hash="0x" + "77" * 32,
                request_hash=request_hash,
                pricing_version=7,
                amount_usdc="1.25",
                expires_at=2_000_000_000,
                provider_fallback_allowed=True,
                chain_id=self.chain_id,
            )

        self.assertEqual(submission.request_hash, request_hash)
        self.assertEqual(
            send.call_args.kwargs["signature"],
            "createReservation(bytes32,address,bytes32,bytes32,uint64,uint256,uint64,bool)",
        )
        self.assertEqual(send.call_args.kwargs["args"][3], request_hash)
        self.assertEqual(send.call_args.kwargs["args"][-1], "true")

    def test_create_reservation_rejects_non_boolean_provider_fallback_flag(self) -> None:
        for invalid in ("false", "true", 0, 1, None):
            with self.subTest(invalid=invalid):
                with patch("gateway.chain_v3.send_contract_transaction") as send:
                    with self.assertRaisesRegex(ChainError, "provider_fallback_allowed must be a boolean"):
                        create_reservation(
                            rpc_url="https://rpc.example",
                            private_key=self.consumer_key,
                            settlement=self.settlement,
                            reservation_salt="0x" + "44" * 32,
                            provider=self.provider_address,
                            channel_hash="0x" + "77" * 32,
                            request_hash="0x" + "55" * 32,
                            pricing_version=7,
                            amount_usdc="1.25",
                            expires_at=2_000_000_000,
                            provider_fallback_allowed=invalid,  # type: ignore[arg-type]
                            chain_id=self.chain_id,
                        )
                    send.assert_not_called()

    def test_default_pricing_hash_matches_solidity_abi_commitment(self) -> None:
        self.assertEqual(
            default_pricing_hash("0x" + "11" * 20),
            "0x1f333524f0ac236d961fb534a5ec988c7e8877a44972f3359895b7b9500f12ae",
        )

    def test_atomic_deployer_children_use_fixed_create_nonces(self) -> None:
        deployer = "0x" + "ab" * 20
        addresses = derive_v3_testnet_addresses(deployer)

        self.assertEqual(addresses["test_usdc"], derive_contract_address(deployer, 1))
        self.assertEqual(addresses["settlement"], derive_contract_address(deployer, 2))
        self.assertEqual(addresses["token"], derive_contract_address(deployer, 3))

    def test_v3_deployment_record_round_trip(self) -> None:
        deployment = V3Deployment(
            protocol_version=3,
            chain_id=self.chain_id,
            deployer="0x" + "aa" * 20,
            test_usdc="0x" + "bb" * 20,
            stablecoin="0x" + "bb" * 20,
            settlement=self.settlement,
            token="0x" + "cc" * 20,
            treasury="0x" + "dd" * 20,
            governance="0x" + "ee" * 20,
            max_consumer_rebate_bps=1_000,
            max_supply=10**27,
            channel=DEFAULT_CHANNEL,
            channel_hash="0x" + "12" * 32,
            pricing_version=1,
            pricing_hash="0x" + "13" * 32,
            tx_hash="0x" + "14" * 32,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deployment.json"
            save_deployment(path, deployment)

            self.assertEqual(load_deployment(path), deployment)

    def test_digest_signatures_recover_both_parties(self) -> None:
        accepted = self._accepted_receipt()
        signed = build_signed_receipt_input(
            accepted,
            consumer_private_key=self.consumer_key,
            provider_private_key=self.provider_key,
            chain_id=self.chain_id,
            verifying_contract=self.settlement,
        )
        digest = receipt_digest(signed.receipt, chain_id=self.chain_id, verifying_contract=self.settlement)

        self.assertEqual(recover_evm_address(digest, _signature_parts(signed.consumer_signature)), self.consumer_address)
        self.assertEqual(recover_evm_address(digest, _signature_parts(signed.provider_signature)), self.provider_address)

    def test_every_receipt_field_changes_the_eip712_digest(self) -> None:
        base = self._receipt_input()
        base_digest = receipt_digest(base, chain_id=self.chain_id, verifying_contract=self.settlement)
        values = dict(base.__dict__)
        mutations = {
            "receipt_hash": "0x" + "01" * 32,
            "accepted_hash": "0x" + "02" * 32,
            "reservation_id": "0x" + "03" * 32,
            "request_hash": "0x" + "04" * 32,
            "response_hash": "0x" + "05" * 32,
            "channel_hash": "0x" + "06" * 32,
            "pricing_version": 8,
            "pricing_hash": "0x" + "07" * 32,
            "consumer": "0x" + "55" * 20,
            "provider": "0x" + "66" * 20,
            "relay": "0x" + "77" * 20,
            "pool": "0x" + "88" * 20,
            "input_tokens": 101,
            "output_tokens": 202,
            "deadline": 999_999,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                mutated = V3ReceiptInput(**{**values, field: replacement})
                self.assertNotEqual(
                    receipt_digest(mutated, chain_id=self.chain_id, verifying_contract=self.settlement),
                    base_digest,
                )

    def test_dynamic_signature_calldata_offsets_are_canonical(self) -> None:
        receipt = self._receipt_input()
        consumer_signature = bytes(range(65))
        provider_signature = bytes(reversed(range(65)))
        data = bytes.fromhex(
            encode_settle_signed_receipt(
                V3SignedReceiptInput(receipt, consumer_signature, provider_signature)
            )[2:]
        )

        self.assertEqual(data[:4].hex(), _keccak_selector(SETTLE_SIGNED_V3_SIGNATURE))
        self.assertEqual(int.from_bytes(data[4:36], "big"), 32)
        tuple_start = 36
        receipt_words = len(receipt.abi_args())
        consumer_offset = int.from_bytes(
            data[tuple_start + receipt_words * 32 : tuple_start + (receipt_words + 1) * 32], "big"
        )
        provider_offset = int.from_bytes(
            data[tuple_start + (receipt_words + 1) * 32 : tuple_start + (receipt_words + 2) * 32], "big"
        )
        self.assertEqual(consumer_offset, 17 * 32)
        self.assertEqual(provider_offset, 17 * 32 + 128)
        self.assertEqual(int.from_bytes(data[tuple_start + consumer_offset : tuple_start + consumer_offset + 32], "big"), 65)
        self.assertEqual(int.from_bytes(data[tuple_start + provider_offset : tuple_start + provider_offset + 32], "big"), 65)

    def test_provider_fallback_uses_zero_acceptance_and_canonical_calldata(self) -> None:
        receipt = self._accepted_receipt()
        for field in ("acceptance", "acceptance_signature", "accepted_hash"):
            receipt.pop(field, None)
        fallback = build_provider_fallback_receipt_input(receipt)
        provider_signature = bytes(range(65))

        data = bytes.fromhex(encode_settle_provider_fallback(fallback, provider_signature)[2:])

        self.assertEqual(fallback.accepted_hash, "0x" + "0" * 64)
        self.assertEqual(data[:4].hex(), _keccak_selector(SETTLE_PROVIDER_FALLBACK_V3_SIGNATURE))
        signature_offset_position = 4 + len(fallback.abi_args()) * 32
        signature_offset = int.from_bytes(data[signature_offset_position : signature_offset_position + 32], "big")
        self.assertEqual(signature_offset, 16 * 32)
        self.assertEqual(int.from_bytes(data[4 + signature_offset : 4 + signature_offset + 32], "big"), 65)

    def test_provider_fallback_accepts_dynamic_contract_wallet_signature(self) -> None:
        fallback = self._receipt_input()
        contract_signature = bytes(range(128))

        data = bytes.fromhex(encode_settle_provider_fallback(fallback, contract_signature)[2:])
        signature_offset = int.from_bytes(data[4 + 15 * 32 : 4 + 16 * 32], "big")

        self.assertEqual(int.from_bytes(data[4 + signature_offset : 4 + signature_offset + 32], "big"), 128)

    def test_eip1271_signature_is_checked_against_contract_at_latest_block(self) -> None:
        digest = bytes.fromhex("12" * 32)
        signature = b"safe-signature"

        with patch("gateway.chain_v3.rpc_call", side_effect=["0x60016000", "0x1626ba7e" + "0" * 56]) as rpc:
            verify_eip1271_signature(
                rpc_url="https://rpc.example",
                signer=self.provider_address,
                digest=digest,
                signature=signature,
                caller=self.settlement,
            )

        self.assertEqual(rpc.call_args_list[0].args[1], "eth_getCode")
        self.assertEqual(rpc.call_args_list[1].args[1], "eth_call")
        call = rpc.call_args_list[1].args[2][0]
        calldata = call["data"]
        self.assertEqual(calldata[:10], "0x1626ba7e")
        self.assertEqual(call["from"], self.settlement)
        self.assertEqual(call["to"], self.provider_address)

    def test_eip1271_rejects_eoa_or_wrong_magic_value(self) -> None:
        with patch("gateway.chain_v3.rpc_call", return_value="0x"):
            with self.assertRaisesRegex(EIP1271SignatureRejected, "no contract code"):
                verify_eip1271_signature(
                    rpc_url="https://rpc.example",
                    signer=self.provider_address,
                    digest=bytes(32),
                    signature=b"signature",
                    caller=self.settlement,
                )
        invalid_results = (
            "0x1626ba7e",
            "0xffffffff" + "0" * 56,
            "0x1626ba7",
            "0x" + "zz" * 32,
        )
        for result in invalid_results:
            with self.subTest(result=result):
                with patch("gateway.chain_v3.rpc_call", side_effect=["0x6000", result]):
                    with self.assertRaisesRegex(EIP1271SignatureRejected, "rejected"):
                        verify_eip1271_signature(
                            rpc_url="https://rpc.example",
                            signer=self.provider_address,
                            digest=bytes(32),
                            signature=b"signature",
                            caller=self.settlement,
                        )

    def test_eip1271_rejects_malformed_contract_code_before_eth_call(self) -> None:
        malformed_codes = (
            None,
            "6000",
            "0X6000",
            "0x0",
            "0x600",
            "0xzz",
            "0x60 00",
        )
        for code in malformed_codes:
            with self.subTest(code=code):
                with patch("gateway.chain_v3.rpc_call", return_value=code) as rpc:
                    with self.assertRaisesRegex(
                        EIP1271SignatureRejected,
                        "unexpected eth_getCode response",
                    ):
                        verify_eip1271_signature(
                            rpc_url="https://rpc.example",
                            signer=self.provider_address,
                            digest=bytes(32),
                            signature=b"signature",
                            caller=self.settlement,
                        )
                self.assertEqual(rpc.call_count, 1)

    def test_eip1271_rpc_calls_share_one_total_deadline(self) -> None:
        with patch("gateway.chain_v3.time.monotonic", side_effect=[100.0, 121.0]), patch(
            "gateway.chain_v3.rpc_call",
            return_value="0x6000",
        ) as rpc:
            with self.assertRaisesRegex(ChainError, "deadline exceeded"):
                verify_eip1271_signature(
                    rpc_url="https://rpc.example",
                    signer=self.provider_address,
                    digest=bytes(32),
                    signature=b"signature",
                    caller=self.settlement,
                    timeout=20.0,
                )

        self.assertEqual(rpc.call_count, 1)

    def _accepted_receipt(self) -> dict[str, object]:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        now = int(time.time())
        pricing_hash = "0x" + "99" * 32
        reservation_id = reservation_id_for(
            settlement=self.settlement,
            chain_id=self.chain_id,
            consumer=self.consumer_address,
            reservation_salt="0x" + "44" * 32,
        )
        response = {
            "request_id": "job-v3",
            "output_text": "answer",
            "usage": {"input_tokens": 1000, "output_tokens": 100},
        }
        quote = quote_usage(DEFAULT_CHANNEL, response["usage"])
        signed_reservation = build_payment_reservation(
            request_id="job-v3",
            consumer_id="consumer-v3",
            consumer_payment_address=self.consumer_address,
            provider_id=provider_identity.peer_id,
            provider_payment_address=self.provider_address,
            channel=DEFAULT_CHANNEL,
            pricing_hash=pricing_hash,
            max_fee_units=10_000,
            signer=consumer_identity,
            expires_at=now + 120,
            settlement_version=3,
            pricing_version=7,
            onchain_reservation_id=reservation_id,
            request_hash=stable_hash("prompt"),
            settlement_deadline=now + 90,
            settlement_chain_id=self.chain_id,
            settlement_contract=self.settlement,
            consumer_wallet_private_key=self.consumer_key,
        )
        reservation = verify_payment_reservation(
            signed_reservation,
            request_id="job-v3",
            channel=DEFAULT_CHANNEL,
            settlement_version=3,
            pricing_version=7,
            settlement_chain_id=self.chain_id,
            settlement_contract=self.settlement,
            now=now,
        )
        receipt = build_receipt(
            consumer_id="consumer-v3",
            provider_id=provider_identity.peer_id,
            relay_id=None,
            pool_url="https://pool.example",
            selected_address="provider.example:9700",
            channel=DEFAULT_CHANNEL,
            model="model-v3",
            endpoint="responses",
            input_value="prompt",
            response=response,
            quote=quote,
            started_at=now,
            finished_at=now + 1,
            consumer_public_key=consumer_identity.public_key,
            provider_public_key=provider_identity.public_key,
            consumer_payment_address=self.consumer_address,
            provider_payment_address=self.provider_address,
            channel_pricing_hash=pricing_hash,
        ).to_dict()
        attestation = build_provider_settlement_attestation(
            request_id="job-v3",
            request_hash=str(receipt["request_hash"]),
            response=response,
            channel=DEFAULT_CHANNEL,
            model="model-v3",
            endpoint="responses",
            reservation=reservation,
            quote=quote,
            provider_id=provider_identity.peer_id,
            provider_payment_address=self.provider_address,
            signer=provider_identity,
        )
        receipt.update(
            {
                "receipt_version": "mycomesh-receipt-v2",
                "settlement_version": 3,
                "pricing_version": 7,
                "onchain_reservation_id": reservation_id,
                "settlement_deadline": now + 90,
                "provider_settlement_attestation": attestation,
            }
        )
        signed_receipt = sign_receipt(receipt, consumer_identity)
        return sign_acceptance(signed_receipt, consumer_identity, accepted_by="consumer-v3")

    def _receipt_input(self) -> V3ReceiptInput:
        return V3ReceiptInput(
            receipt_hash="0x" + "10" * 32,
            accepted_hash="0x" + "20" * 32,
            reservation_id="0x" + "30" * 32,
            request_hash="0x" + "40" * 32,
            response_hash="0x" + "50" * 32,
            channel_hash="0x" + "60" * 32,
            pricing_version=7,
            pricing_hash="0x" + "70" * 32,
            consumer=self.consumer_address,
            provider=self.provider_address,
            relay="0x" + "80" * 20,
            pool="0x" + "90" * 20,
            input_tokens=100,
            output_tokens=200,
            deadline=888_888,
        )


def _signature_parts(value: bytes):
    from gateway.chain import EvmSignature

    return EvmSignature(r="0x" + value[:32].hex(), s="0x" + value[32:64].hex(), v=value[64])


def _keccak_selector(signature: str) -> str:
    from gateway.chain import keccak256

    return keccak256(signature.encode("utf-8"))[:4].hex()


if __name__ == "__main__":
    unittest.main()
