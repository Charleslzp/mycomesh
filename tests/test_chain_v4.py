from __future__ import annotations

from copy import deepcopy
import unittest

from gateway.chain import ChainError, parse_private_key, private_key_to_address
from gateway.chain_v4 import (
    V4_CLAIM_PAYOUT_SIGNATURE,
    build_provider_settlement_payload,
    encode_claim_payout,
    keccak256,
    load_deployment,
    validate_pull_payment_artifact,
)
from gateway.session_service import SessionClaim
import gateway.mycomesh as mycomesh


class V4SettlementQueueTest(unittest.TestCase):
    def test_claim_payout_calldata_uses_expected_selector(self) -> None:
        calldata = encode_claim_payout()
        selector = keccak256(V4_CLAIM_PAYOUT_SIGNATURE.encode("ascii"))[:4].hex()
        self.assertEqual(calldata, "0x" + selector)

    def test_v4_deployment_parser_exposes_redeploy_command(self) -> None:
        from gateway.client import _build_parser

        args = _build_parser().parse_args(["chain", "deploy-myco-v4-testnet", "--stablecoin", "0x" + "11" * 20, "--reward-token", "0x" + "22" * 20])
        self.assertEqual(args.func.__name__, "_cmd_chain_deploy_myco_v4_testnet")
        self.assertEqual(args.deployment, "deployments/sepolia-myco-v4.json")

    def test_v4_claim_parser_uses_pull_payment_command(self) -> None:
        from gateway.client import _build_parser

        args = _build_parser().parse_args(
            ["chain", "v4-claim-payout", "--identity", "/data/provider-evm-identity.json"]
        )
        self.assertEqual(args.func.__name__, "_cmd_chain_v4_claim_payout")
        self.assertEqual(args.deployment, "deployments/sepolia-myco-v4.json")
        self.assertEqual(args.identity, "/data/provider-evm-identity.json")

    def test_existing_manifest_advertises_pull_payment_support(self) -> None:
        deployment = load_deployment()
        self.assertTrue(deployment.pull_payments_enabled)

    def test_pull_payment_manifest_flag_rejects_non_boolean_values(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        payload = json.loads(Path("deployments/sepolia-myco-v4.json").read_text(encoding="utf-8"))
        payload["pull_payments_enabled"] = "true"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deployment.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ChainError, "pull_payments_enabled must be a boolean"):
                load_deployment(path)

    def test_stale_v4_artifact_is_rejected_before_deploy(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        stale = {
            "abi": [],
            "bytecode": {"object": "0x6000"},
            "deployedBytecode": {"object": "0x6000"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stale.json"
            path.write_text(json.dumps(stale), encoding="utf-8")
            with self.assertRaisesRegex(ChainError, "missing pull-payment functions"):
                validate_pull_payment_artifact(path)

    def test_runtime_receipt_deadline_may_be_earlier_but_not_later(self) -> None:
        self.assertEqual(
            mycomesh._validate_runtime_v4_receipt_deadline(
                1_000,
                1_100,
                now=900,
            ),
            1_000,
        )
        with self.assertRaisesRegex(
            mycomesh.P2PError,
            "exceeds the signed request deadline",
        ):
            mycomesh._validate_runtime_v4_receipt_deadline(1_200, 1_100, now=900)
        with self.assertRaisesRegex(
            mycomesh.P2PError,
            "deadline has elapsed",
        ):
            mycomesh._validate_runtime_v4_receipt_deadline(900, 1_100, now=900)

    def test_queue_canonicalizes_bare_bytes32_receipt_fields(self) -> None:
        provider_private_key = "0x" + "33" * 32
        session_private_key = "0x" + "11" * 32
        consumer = private_key_to_address(parse_private_key("0x" + "22" * 32))
        provider = private_key_to_address(parse_private_key(provider_private_key))
        payload = build_provider_settlement_payload(
            provider_private_key=provider_private_key,
            chain_id=11155111,
            settlement_contract="0x" + "44" * 20,
            session_id="0x" + "88" * 32,
            request_hash="0x" + "99" * 32,
            response_hash="0x" + "aa" * 32,
            channel_hash="0x" + "bb" * 32,
            pricing_version=1,
            pricing_hash="0x" + "cc" * 32,
            consumer=consumer,
            provider=provider,
            input_tokens=1,
            output_tokens=2,
            sequence=0,
            quoted_fee=3,
            deadline=9_999_999_999,
        )
        wire_payload = deepcopy(payload)
        for field in (
            "receipt_hash",
            "accepted_hash",
            "session_id",
            "request_hash",
            "response_hash",
            "channel",
            "pricing_hash",
        ):
            wire_payload["receipt"][field] = wire_payload["receipt"][field][2:]

        queued = mycomesh._queue_v4_settlement(
            session=SessionClaim(
                plan={},
                authorization={},
                request={},
                private_key=session_private_key,
                previous_cumulative_spend_units=0,
            ),
            settlement_payload=wire_payload,
        )

        self.assertEqual(queued["receipt"]["response_hash"], "0x" + "aa" * 32)
        self.assertTrue(queued["receipt_digest"].startswith("0x"))
        self.assertTrue(queued["calldata"].startswith("0x"))


if __name__ == "__main__":
    unittest.main()
