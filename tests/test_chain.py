from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gateway.identity import create_identity
from gateway.ledger import build_receipt, sign_acceptance
from gateway.pricing import quote_usage
from gateway.chain import (
    DEFAULT_CHANNEL_HASH,
    DEFAULT_MYCO_DEPLOYMENT_PATH,
    SEPOLIA_CHAIN_ID,
    ZERO_ADDRESS,
    ChainError,
    build_delegated_receipt_settlement_args,
    build_delegated_receipt_settlement_args_from_signatures,
    build_receipt_settlement_args,
    build_delegate_authorization,
    build_signed_receipt_settlement_args,
    channel_to_hash,
    derive_testnet_addresses,
    encode_settle_delegated_receipt_call,
    encode_settle_signed_receipt_call,
    encode_contract_call,
    governance_action_hash,
    load_deployment,
    load_myco_deployment,
    load_receipt,
    parse_private_key,
    private_key_to_address,
    receipt_hash,
    reward_token_amount,
    myco_receipt_struct_hash,
    myco_delegate_digest,
    recover_evm_address,
    sign_evm_digest,
    sign_legacy_transaction,
    stablecoin_amount,
)
from gateway.p2p import DEFAULT_CHANNEL


class ChainHelpersTest(unittest.TestCase):
    def test_default_channel_hash_matches_keccak(self) -> None:
        self.assertEqual(channel_to_hash(DEFAULT_CHANNEL), DEFAULT_CHANNEL_HASH)

    def test_stablecoin_amount_uses_six_decimals(self) -> None:
        self.assertEqual(stablecoin_amount("10"), 10_000_000)
        self.assertEqual(stablecoin_amount("0.002"), 2_000)
        self.assertEqual(stablecoin_amount("0.0000009"), 0)

    def test_reward_token_amount_uses_eighteen_decimals(self) -> None:
        self.assertEqual(reward_token_amount("1"), 10**18)
        self.assertEqual(reward_token_amount("0.5"), 5 * 10**17)
        self.assertEqual(reward_token_amount("0.0000000000000000009"), 0)

    def test_private_key_to_address_matches_eth_vector(self) -> None:
        address = private_key_to_address(parse_private_key("0x" + "0" * 63 + "1"))

        self.assertEqual(address, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")

    def test_encode_contract_call(self) -> None:
        call = encode_contract_call(
            "approve(address,uint256)",
            ["0x0000000000000000000000000000000000000002", "2000"],
        )

        self.assertTrue(call.startswith("0x095ea7b3"))
        self.assertEqual(len(call), 2 + 8 + 64 + 64)

    def test_encode_governance_tuple_calls(self) -> None:
        economics = encode_contract_call(
            "setEconomics((uint256,uint256,uint256,uint16))",
            [str(7 * 24 * 60 * 60), str(reward_token_amount("1000")), "210000", "2000"],
        )
        channel = encode_contract_call(
            "setChannel(bytes32,(uint256,uint256,uint256,uint16,uint16,uint16,uint16,uint16,uint16,uint256,bool))",
            [
                DEFAULT_CHANNEL_HASH,
                str(stablecoin_amount("0.001")),
                str(stablecoin_amount("0.004")),
                str(stablecoin_amount("0.002")),
                "8500",
                "300",
                "200",
                "1000",
                "9000",
                "1000",
                str(10**12),
                "true",
            ],
        )

        self.assertEqual(len(economics), 2 + 8 + 64 * 4)
        self.assertEqual(len(channel), 2 + 8 + 64 * 12)

    def test_governance_action_hashes_are_stable(self) -> None:
        delay = governance_action_hash("governance-delay", delay_seconds=86400)
        operator = governance_action_hash(
            "operator",
            operator="0x0000000000000000000000000000000000000002",
            allowed=True,
        )
        channel = governance_action_hash(
            "channel",
            channel_hash=DEFAULT_CHANNEL_HASH,
            input_per_1k_usdc="0.001",
            output_per_1k_usdc="0.004",
            minimum_fee_usdc="0.002",
            provider_bps=8500,
            relay_bps=300,
            pool_bps=200,
            treasury_bps=1000,
            provider_reward_bps=9000,
            consumer_reward_bps=1000,
            reward_per_treasury_unit=10**12,
            active=True,
        )

        self.assertRegex(delay, r"^0x[a-f0-9]{64}$")
        self.assertRegex(operator, r"^0x[a-f0-9]{64}$")
        self.assertRegex(channel, r"^0x[a-f0-9]{64}$")
        self.assertNotEqual(delay, operator)
        self.assertEqual(delay, governance_action_hash("governance-delay", delay_seconds=86400))

    def test_governance_action_hash_requires_action_parameters(self) -> None:
        with self.assertRaises(ChainError):
            governance_action_hash("economics", epoch_seconds=604800)

    def test_sign_legacy_transaction_returns_rlp_bytes(self) -> None:
        raw = sign_legacy_transaction(
            private_key=parse_private_key("0x" + "0" * 63 + "1"),
            nonce=0,
            gas_price=1_000_000_000,
            gas_limit=50_000,
            to_address="0x0000000000000000000000000000000000000002",
            value=0,
            data=bytes.fromhex("095ea7b3"),
            chain_id=SEPOLIA_CHAIN_ID,
        )

        self.assertGreater(len(raw), 0)
        self.assertGreaterEqual(raw[0], 0xF8)

    def test_sign_contract_creation_transaction_returns_rlp_bytes(self) -> None:
        raw = sign_legacy_transaction(
            private_key=parse_private_key("0x" + "0" * 63 + "1"),
            nonce=0,
            gas_price=1_000_000_000,
            gas_limit=500_000,
            to_address=None,
            value=0,
            data=b"\x60\x00",
            chain_id=SEPOLIA_CHAIN_ID,
        )

        self.assertGreater(len(raw), 0)
        self.assertGreaterEqual(raw[0], 0xF8)

    def test_derive_testnet_addresses_from_deployer(self) -> None:
        addresses = derive_testnet_addresses("0x1234567890123456789012345678901234567890")

        self.assertEqual(addresses["test_usdc"], "0x55424e77a7e34815c8ac3008e96cfbc3c98bb746")
        self.assertEqual(addresses["token"], "0xf7c49be3d09b504206a79bf68ad8eb41f6dcd541")
        self.assertEqual(addresses["settlement"], "0x72440018ed063cc7f7946110b0ff7e6de76a6d01")

    def test_build_receipt_settlement_args(self) -> None:
        receipt = {
            "job_id": "job-1",
            "channel": DEFAULT_CHANNEL,
            "pricing": {"input_tokens": 1000, "output_tokens": 500},
        }

        args = build_receipt_settlement_args(
            receipt,
            consumer="0x0000000000000000000000000000000000000001",
            provider="0x0000000000000000000000000000000000000002",
        )

        self.assertEqual(args.receipt_hash, receipt_hash(receipt))
        self.assertEqual(args.channel_hash, DEFAULT_CHANNEL_HASH)
        self.assertEqual(args.relay, ZERO_ADDRESS)
        self.assertEqual(args.pool, ZERO_ADDRESS)
        self.assertEqual(args.input_tokens, 1000)
        self.assertEqual(args.output_tokens, 500)
        self.assertEqual(args.accepted_hash, "0x" + "0" * 64)
        self.assertEqual(args.pricing_hash, "0x" + "0" * 64)
        self.assertEqual(args.deadline, 0)
        self.assertEqual(args.gross_fee_units, 3000)

    def test_build_receipt_settlement_args_uses_receipt_payment_addresses(self) -> None:
        receipt = {
            "job_id": "job-1",
            "channel": DEFAULT_CHANNEL,
            "consumer_payment_address": "0x0000000000000000000000000000000000000001",
            "provider_payment_address": "0x0000000000000000000000000000000000000002",
            "pricing": {"input_tokens": 1000, "output_tokens": 500},
        }

        args = build_receipt_settlement_args(receipt, consumer=None, provider=None)

        self.assertEqual(args.consumer, "0x0000000000000000000000000000000000000001")
        self.assertEqual(args.provider, "0x0000000000000000000000000000000000000002")

    def test_build_receipt_settlement_args_uses_pricing_hash_and_deadline(self) -> None:
        receipt = {
            "job_id": "job-1",
            "channel": DEFAULT_CHANNEL,
            "consumer_payment_address": "0x0000000000000000000000000000000000000001",
            "provider_payment_address": "0x0000000000000000000000000000000000000002",
            "accepted_hash": "0x" + "2" * 64,
            "pricing": {
                "input_tokens": 1000,
                "output_tokens": 500,
                "channel_pricing_hash": "0x" + "1" * 64,
            },
            "settlement_deadline": 123,
        }

        args = build_receipt_settlement_args(receipt, consumer=None, provider=None)

        self.assertEqual(args.pricing_hash, "0x" + "1" * 64)
        self.assertEqual(args.accepted_hash, "0x" + "2" * 64)
        self.assertEqual(args.deadline, 123)

    def test_build_signed_receipt_settlement_args(self) -> None:
        consumer_key = "0x" + "0" * 63 + "1"
        provider_key = "0x" + "0" * 63 + "2"
        receipt = self._accepted_receipt()

        args = build_signed_receipt_settlement_args(
            receipt,
            consumer_private_key=consumer_key,
            provider_private_key=provider_key,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract="0x0000000000000000000000000000000000000004",
        )
        calldata = encode_settle_signed_receipt_call(args)

        self.assertTrue(calldata.startswith("0x"))
        self.assertEqual(len(args.consumer_signature.r), 66)
        self.assertEqual(len(args.provider_signature.s), 66)
        self.assertGreater(args.consumer_signature.v, 26)
        self.assertNotEqual(myco_receipt_struct_hash(args.receipt), "0x" + "0" * 64)

    def test_build_delegated_receipt_settlement_args(self) -> None:
        consumer_key = "0x" + "0" * 63 + "1"
        provider_key = "0x" + "0" * 63 + "2"
        delegate_key = "0x" + "0" * 63 + "3"
        delegate = private_key_to_address(parse_private_key(delegate_key))
        receipt = self._accepted_receipt()

        args = build_delegated_receipt_settlement_args(
            receipt,
            consumer_delegate_private_key=consumer_key,
            provider_delegate_private_key=provider_key,
            delegate=delegate,
            max_amount=3_000,
            expires_at=12345,
            consumer_nonce=10,
            provider_nonce=11,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract="0x0000000000000000000000000000000000000004",
        )
        signed = build_signed_receipt_settlement_args(
            receipt,
            consumer_private_key=consumer_key,
            provider_private_key=provider_key,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract="0x0000000000000000000000000000000000000004",
        )
        calldata = encode_settle_delegated_receipt_call(args)

        self.assertTrue(calldata.startswith("0x"))
        self.assertGreater(len(calldata), len(encode_settle_signed_receipt_call(signed)))
        self.assertEqual(args.receipt.consumer, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
        self.assertEqual(args.receipt.provider, "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf")
        self.assertEqual(args.max_amount, 3_000)
        self.assertEqual(args.consumer_nonce, 10)
        self.assertGreaterEqual(args.consumer_delegate_signature.v, 27)

    def test_build_delegated_receipt_settlement_args_from_wallet_signatures(self) -> None:
        consumer_key = "0x" + "0" * 63 + "1"
        provider_key = "0x" + "0" * 63 + "2"
        delegate_key = "0x" + "0" * 63 + "3"
        delegate = private_key_to_address(parse_private_key(delegate_key))
        receipt = self._accepted_receipt()
        base = build_receipt_settlement_args(receipt, consumer=None, provider=None)
        verifying_contract = "0x0000000000000000000000000000000000000004"
        consumer_digest = myco_delegate_digest(
            account=base.consumer,
            delegate=delegate,
            receipt=base,
            max_amount=3_000,
            expires_at=12345,
            nonce=10,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract=verifying_contract,
        )
        provider_digest = myco_delegate_digest(
            account=base.provider,
            delegate=delegate,
            receipt=base,
            max_amount=3_000,
            expires_at=12345,
            nonce=11,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract=verifying_contract,
        )
        consumer_signature = sign_evm_digest(consumer_key, consumer_digest)
        provider_signature = sign_evm_digest(provider_key, provider_digest)

        args = build_delegated_receipt_settlement_args_from_signatures(
            receipt,
            consumer_delegate_signature=consumer_signature,
            provider_delegate_signature=provider_signature,
            delegate=delegate,
            max_amount=3_000,
            expires_at=12345,
            consumer_nonce=10,
            provider_nonce=11,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract=verifying_contract,
        )

        self.assertEqual(args.receipt.consumer, recover_evm_address(consumer_digest, consumer_signature))
        self.assertEqual(args.receipt.provider, recover_evm_address(provider_digest, provider_signature))
        self.assertEqual(args.consumer_delegate_signature.r, consumer_signature.r)

    def test_build_delegate_authorization(self) -> None:
        receipt = build_receipt_settlement_args(
            self._accepted_receipt(),
            consumer=None,
            provider=None,
        )
        authorization = build_delegate_authorization(
            account_private_key="0x" + "0" * 63 + "1",
            delegate="0x0000000000000000000000000000000000000004",
            receipt=receipt,
            max_amount=1_000_000,
            expires_at=12345,
            nonce=7,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract="0x0000000000000000000000000000000000000005",
        )
        digest = myco_delegate_digest(
            account=authorization.account,
            delegate=authorization.delegate,
            receipt=authorization.receipt,
            max_amount=authorization.max_amount,
            expires_at=authorization.expires_at,
            nonce=authorization.nonce,
            chain_id=SEPOLIA_CHAIN_ID,
            verifying_contract="0x0000000000000000000000000000000000000005",
        )

        self.assertEqual(authorization.account, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
        self.assertEqual(len(digest), 32)
        self.assertEqual(len(authorization.signature.r), 66)
        self.assertGreaterEqual(authorization.signature.v, 27)

    def test_load_deployment_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sepolia.json"
            path.write_text(
                json.dumps(
                    {
                        "chain_id": SEPOLIA_CHAIN_ID,
                        "deployer": "0x0000000000000000000000000000000000000001",
                        "test_usdc": "0x0000000000000000000000000000000000000002",
                        "token": "0x0000000000000000000000000000000000000003",
                        "settlement": "0x0000000000000000000000000000000000000004",
                        "treasury": "0x0000000000000000000000000000000000000005",
                    }
                ),
                encoding="utf-8",
            )

            deployment = load_deployment(path)

        self.assertEqual(deployment.settlement, "0x0000000000000000000000000000000000000004")
        self.assertEqual(deployment.channel_hash, DEFAULT_CHANNEL_HASH)

    def test_load_myco_deployment_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / DEFAULT_MYCO_DEPLOYMENT_PATH
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps(
                    {
                        "chain_id": SEPOLIA_CHAIN_ID,
                        "deployer": "0x0000000000000000000000000000000000000001",
                        "test_usdc": "0x0000000000000000000000000000000000000002",
                        "token": "0x0000000000000000000000000000000000000003",
                        "settlement": "0x0000000000000000000000000000000000000004",
                        "treasury": "0x0000000000000000000000000000000000000005",
                    }
                ),
                encoding="utf-8",
            )

            deployment = load_myco_deployment(path)

        self.assertEqual(deployment.settlement, "0x0000000000000000000000000000000000000004")
        self.assertEqual(deployment.channel_hash, DEFAULT_CHANNEL_HASH)

    def test_load_receipt_supports_jsonl_latest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipts.jsonl"
            path.write_text(
                json.dumps({"job_id": "old"}) + "\n" + json.dumps({"job_id": "new"}) + "\n",
                encoding="utf-8",
            )

            receipt = load_receipt(path)

        self.assertEqual(receipt["job_id"], "new")

    def _accepted_receipt(self) -> dict[str, object]:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        quote = quote_usage(DEFAULT_CHANNEL, {"input_tokens": 1000, "output_tokens": 500})
        receipt = build_receipt(
            consumer_id="acct-a",
            provider_id=provider_identity.peer_id,
            relay_id=None,
            pool_url="http://pool",
            selected_address="tcp://provider:9700",
            channel=DEFAULT_CHANNEL,
            model="gpt-5.5",
            endpoint="responses",
            input_value="Say OK",
            response={
                "request_id": "job-1",
                "output_text": "ok",
                "usage": {"input_tokens": 1000, "output_tokens": 500},
            },
            quote=quote,
            started_at=100.0,
            finished_at=101.0,
            consumer_public_key=consumer_identity.public_key,
            provider_public_key=provider_identity.public_key,
            consumer_payment_address="0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
            provider_payment_address="0x2b5ad5c4795c026514f8317c7a215e218dccd6cf",
            channel_pricing_hash="0x" + "4" * 64,
            signer=consumer_identity,
        ).to_dict()
        return sign_acceptance(receipt, consumer_identity, accepted_by="acct-a")


if __name__ == "__main__":
    unittest.main()
