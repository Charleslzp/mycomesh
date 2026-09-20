from __future__ import annotations

import copy
import time
import unittest
from unittest.mock import patch

from gateway import chain_v8 as v8, chain_v9 as v9
from gateway.chain import ChainError, SECP256K1_N, abi_encode_arg, keccak256, parse_private_key, private_key_to_address
from gateway.session_relayer import RelaySettlementError
from gateway.v9_relayer import prepare_v9_relay_settlement


def address(number: int) -> str:
    return "0x" + f"{number:040x}"


def digest(number: int) -> str:
    return "0x" + f"{number:064x}"


def key(number: int) -> str:
    return "0x" + f"{number:064x}"


def signer(number: int) -> str:
    return private_key_to_address(parse_private_key(key(number)))


def abi(*values: object) -> str:
    return "0x" + b"".join(abi_encode_arg(str(item)) for item in values).hex()


def deployment_manifest() -> dict:
    return {
        "protocol_version": 9, "chain_id": 31337, "deployer": address(1), "stablecoin": address(2),
        "settlement": address(3), "treasury": address(4), "governance": address(5), "channel": "codex",
        "channel_hash": digest(6), "pricing_version": 1, "pricing_hash": digest(7), "reward_token": address(8),
        "policy": {"dispute_window": 60, "arbitration_timeout": 120, "consumer_withdrawal_delay": 60,
                   "reporter_bond": 100, "slash_bps": 5000, "slash_cap": 10000, "reporter_bounty_bps": 2000,
                   "stable_bounty_cap": 1000, "token_reward": 10, "token_reward_cap": 1000,
                   "token_minimum_exposure": 100, "token_minimum_penalty": 10, "bond_penalty_recipient": address(9)},
        "adjudicators": [address(10), address(11), address(12)], "adjudication_threshold": 2,
        "adjudicator_operators": {address(10): "operator-a", address(11): "operator-b", address(12): "operator-c"},
        "independence_attested": True, "network_id": "local-test", "channel_id": "codex",
        "backend_policy": "test-only", "eip712_name": "MycoMesh Settlement", "eip712_version": "9",
    }


class ChainV9Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.params = dict(payment_key=key(1), chain_id=31337, settlement_contract=address(21),
                           request_id=digest(2), request_hash=digest(3), relay=address(4), relay_signer=signer(3),
                           channel_hash=digest(5), pricing_version=1, pricing_hash=digest(6), max_fee=5000,
                           issued_at=self.now, deadline=self.now + 300)

    def provider(self, module=v9):
        return module.build_provider_receipt(
            provider=address(7), provider_private_key=key(2), authorization_payload=module.build_authorization(**self.params),
            response_hash=digest(8), relay=address(4), input_tokens=100, output_tokens=200, actual_fee=1000)

    def signed(self, module=v9):
        return module.finalize_relay_receipt(self.provider(module), relay_private_key=key(3))

    def test_v9_round_trip_and_compatible_calldata_shape(self):
        provider = self.provider()
        auth, receipt, _, chain, contract = v9.verify_provider_receipt(provider, now=self.now + 1)
        self.assertEqual(chain, 31337)
        self.assertEqual(contract, address(21))
        self.assertEqual(receipt.provider_signer, signer(2))
        signed = self.signed()
        v9.verify_signed_receipt(signed, now=self.now + 1)
        self.assertEqual(signed["schema"], v9.SIGNED_SCHEMA)
        single = v9.encode_signed_receipt(signed)
        self.assertTrue(single.startswith("0x" + keccak256(v9.SETTLE_SIGNATURE.encode())[:4].hex()))
        self.assertEqual(v9.encode_signed_batch([signed]), v9.encode_signed_batch_tuples([v9.encode_signed_receipt_tuple(signed)]))

    def test_v8_v9_authorizations_are_not_interchangeable(self):
        a8, a9 = v8.build_authorization(**self.params), v9.build_authorization(**self.params)
        self.assertNotEqual(a8["authorization_digest"], a9["authorization_digest"])
        self.assertEqual(a8["authorization_hash"], a9["authorization_hash"])
        for module, auth in ((v9, a8), (v8, a9)):
            with self.assertRaises(ChainError):
                module.verify_authorization(auth)
        forged = copy.deepcopy(a8)
        forged["schema"] = v9.AUTH_SCHEMA
        with self.assertRaisesRegex(ChainError, "digest mismatch"):
            v9.verify_authorization(forged)
        forged["authorization_digest"] = a9["authorization_digest"]
        with self.assertRaisesRegex(ChainError, "signature mismatch"):
            v9.verify_authorization(forged)

    def test_v8_receipts_rejected_even_with_relabelled_schemas(self):
        signed8 = self.signed(v8)
        with self.assertRaises(ChainError):
            v9.verify_signed_receipt(signed8)
        signed8["schema"] = v9.SIGNED_SCHEMA
        signed8["authorization"]["schema"] = v9.AUTH_SCHEMA
        with self.assertRaises(ChainError):
            v9.verify_signed_receipt(signed8)
        signed8["authorization"] = v9.build_authorization(**self.params)
        signed8["key_signature"] = signed8["authorization"]["key_signature"]
        with self.assertRaisesRegex(ChainError, "Provider signature mismatch"):
            v9.verify_signed_receipt(signed8)

    def test_domain_chain_contract_all_bound(self):
        auth = v9.build_authorization(**self.params)
        for name, value in (("chain_id", 1), ("settlement_contract", address(22))):
            forged = copy.deepcopy(auth)
            forged[name] = value
            with self.subTest(name=name), self.assertRaises(ChainError):
                v9.verify_authorization(forged)

    def test_outer_provider_and_signed_deployment_must_match(self):
        for builder, verify in ((self.provider, v9.verify_provider_receipt), (self.signed, v9.verify_signed_receipt)):
            for field, value in (("chain_id", 1), ("chain_id", 31337.5), ("settlement_contract", address(22))):
                forged = builder()
                forged[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ChainError):
                    verify(forged)

    def test_strict_uint_and_lifetime(self):
        for value in (True, -1, 1.5, "1.5", "-1", 1 << 256):
            with self.subTest(value=value), self.assertRaises(ChainError):
                v9.build_authorization(**{**self.params, "max_fee": value})
        for field in ("issued_at", "deadline"):
            with self.assertRaises(ChainError):
                v9.build_authorization(**{**self.params, field: self.now + 0.5})
        for expires in (self.now, self.now + 3601):
            with self.assertRaises(ChainError):
                v9.build_authorization(**{**self.params, "deadline": expires})
        auth = v9.build_authorization(**self.params)
        for when in (self.now - 1, self.now + 301):
            with self.assertRaisesRegex(ChainError, "time window"):
                v9.verify_authorization(auth, now=when)
        v9.verify_authorization(auth, now=self.now + 300)

    def test_historical_verification_explicit_only(self):
        provider, signed = self.provider(), self.signed()
        with patch("gateway.chain_v9.time.time", return_value=self.now + 500):
            for verify, value in ((v9.verify_provider_receipt, provider), (v9.verify_signed_receipt, signed)):
                with self.assertRaises(ChainError):
                    verify(value)
                verify(value, now=self.now + 1)

    def test_noncanonical_signatures_rejected(self):
        authorization = v9.build_authorization(**self.params)
        raw = bytes.fromhex(authorization["key_signature"][2:])
        high_s = SECP256K1_N - int.from_bytes(raw[32:64], "big")
        v = 55 - raw[64] if raw[64] >= 27 else raw[64] ^ 1
        authorization["key_signature"] = "0x" + (raw[:32] + high_s.to_bytes(32, "big") + bytes([v])).hex()
        with self.assertRaisesRegex(ChainError, "low s"):
            v9.verify_authorization(authorization)

    def test_max_fee_zero_response_and_contract_payees_rejected(self):
        params = dict(provider=address(7), provider_private_key=key(2), authorization_payload=v9.build_authorization(**self.params),
                      response_hash=digest(8), relay=address(4), input_tokens=100, output_tokens=200, actual_fee=1000)
        for changes in ({"actual_fee": 5001}, {"response_hash": digest(0)}, {"provider": address(21)}, {"pool": address(21)}):
            with self.subTest(changes=changes), self.assertRaises(ChainError):
                v9.build_provider_receipt(**{**params, **changes})

    def test_wrong_relay_signer_and_tampered_usage_rejected(self):
        with self.assertRaises(ChainError):
            v9.finalize_relay_receipt(self.provider(), relay_private_key=key(4))
        signed = self.signed()
        signed["receipt"]["output_tokens"] += 1
        with self.assertRaises(ChainError):
            v9.verify_signed_receipt(signed)

    def test_batch_limits(self):
        for values in ([], [b"a"] * 33):
            with self.assertRaises(ChainError):
                v9.encode_signed_batch_tuples(values)

    def test_prepare_requires_trusted_owner_and_matches_onchain_key(self):
        signed = self.signed()
        kwargs = dict(owner=address(90), expected_chain_id=31337, expected_contract=address(21),
                      expected_relay=address(4), expected_relay_signer=signer(3))
        prepared = prepare_v9_relay_settlement(signed, **kwargs)
        expected = v9.settlement_key_for(address(90), signer(1), digest(2))
        self.assertEqual(prepared.payload["settlement_key"], expected)
        self.assertEqual(prepared.payload["protocol_version"], 9)
        self.assertIn(expected, prepared.key)
        for field, value in (("owner", address(0)), ("expected_chain_id", 1), ("expected_contract", address(22)),
                             ("expected_relay", address(55)), ("expected_relay_signer", signer(4))):
            with self.subTest(field=field), self.assertRaises(RelaySettlementError):
                prepare_v9_relay_settlement(signed, **{**kwargs, field: value})


class V9ReadAndCalldataTests(unittest.TestCase):
    def test_pinned_block_all_stake_reads_and_inconsistent_snapshot(self):
        block = {"blockHash": digest(99), "requireCanonical": True}
        with patch("gateway.chain_v9.rpc_call", side_effect=[abi(1000), abi(300)]) as rpc:
            self.assertEqual(v9.provider_stake_status("unused", address(3), address(7), block_tag=block),
                             {"stake": 1000, "locked": 300, "available": 700})
        self.assertTrue(all(call.args[2][1] == block for call in rpc.call_args_list))
        with patch("gateway.chain_v9.rpc_call", side_effect=[abi(1), abi(2)]), self.assertRaises(ChainError):
            v9.provider_stake_status("unused", address(3), address(7), block_tag="0x1")

    def test_default_stake_reads_pin_latest_block_hash(self):
        with patch("gateway.chain_v9.rpc_call", side_effect=[{"hash": digest(44)}, abi(1000), abi(100)]) as rpc:
            self.assertEqual(v9.provider_stake_status("unused", address(3), address(7))["available"], 900)
        self.assertEqual(rpc.call_args_list[0].args[1], "eth_getBlockByNumber")
        for call in rpc.call_args_list[1:]:
            self.assertEqual(call.args[2][1], {"blockHash": digest(44), "requireCanonical": True})

    def test_reads_reject_noncanonical_abi_and_pending_unpinned_state(self):
        for result in ("0x", "0xzz", abi(1) + "00", abi(2)):
            with self.subTest(result=result), patch("gateway.chain_v9.rpc_call", return_value=result), self.assertRaises(ChainError):
                v9.is_adjudicator("unused", address(3), address(10))
        with patch("gateway.chain_v9.rpc_call") as rpc, self.assertRaises(ChainError):
            v9.is_adjudicator("unused", address(3), address(10), block_tag="pending")
        rpc.assert_not_called()

    def test_all_information_queries(self):
        with patch("gateway.chain_v9.rpc_call", return_value=abi(address(1), 100, 200, True)):
            self.assertEqual(v9.key_grant("unused", address(3), address(4))["owner"], address(1))
        settlement = [address(i) for i in range(1, 9)] + [digest(i) for i in range(9, 13)] + [100, 85, 3, 2, 10, 1000, 1060, 1]
        with patch("gateway.chain_v9.rpc_call", return_value=abi(*settlement)):
            self.assertEqual(v9.settlement_info("unused", address(3), digest(1))["status_name"], "pending")
        with patch("gateway.chain_v9.rpc_call", return_value=abi(1, 2, 0, 1, 100, digest(0), 0, 0, 0)):
            self.assertEqual(v9.dispute_info("unused", address(3), digest(1))["total_bond"], 100)
        with patch("gateway.chain_v9.rpc_call", return_value=abi(address(7), digest(9), False)):
            self.assertFalse(v9.report_info("unused", address(3), digest(1), digest(2))["bond_claimed"])
        with patch("gateway.chain_v9.rpc_call", return_value=abi(32, 3, address(10), address(11), address(12))):
            self.assertEqual(v9.adjudicators("unused", address(3)), [address(10), address(11), address(12)])

    def test_policy_matches_contract_field_order(self):
        manifest = deployment_manifest()
        values = [manifest["policy"][name] for name in v9.POLICY_FIELDS]
        with patch("gateway.chain_v9.rpc_call", side_effect=[abi(*values), abi(2), abi(address(8)), abi(address(2))]):
            policy = v9.dispute_policy("unused", address(3), block_tag="0x1")
        self.assertEqual({name: policy[name] for name in v9.POLICY_FIELDS}, manifest["policy"])
        self.assertEqual(policy["adjudication_threshold"], 2)

    def test_calldata_selectors_and_strict_boundaries(self):
        cases = ((v9.encode_open_dispute(digest(1), digest(2)), "openDispute(bytes32,bytes32)"),
                 (v9.encode_submit_evidence(digest(1), digest(2)), "submitEvidence(bytes32,bytes32)"),
                 (v9.encode_release(digest(1)), "release(bytes32)"),
                 (v9.encode_resolve_timed_out_dispute(digest(1)), "resolveTimedOutDispute(bytes32)"),
                 (v9.encode_claim_dispute_bond(digest(1), digest(2)), "claimDisputeBond(bytes32,bytes32)"),
                 (v9.encode_claim_token_reward(), "claimTokenReward()"),
                 (v9.encode_claim_payout(), "claim()"),
                 (v9.encode_deposit_stake(100), "depositStake(uint256)"),
                 (v9.encode_fund_token_rewards(100), "fundTokenRewards(uint256)"))
        for encoded, signature in cases:
            self.assertEqual(encoded[:10], "0x" + keccak256(signature.encode())[:4].hex())
        for amount in (0, -1, True, 1.1, "1.1", 1 << 256):
            with self.subTest(amount=amount), self.assertRaises(ChainError):
                v9.encode_deposit_stake(amount)
        for confirmed, report in ((True, digest(0)), (False, digest(2)), (1, digest(2))):
            with self.assertRaises(ChainError):
                v9.encode_vote_dispute(digest(1), confirmed=confirmed, report_id=report, decision_hash=digest(3))
        vote = v9.encode_vote_dispute(digest(1), confirmed=True, report_id=digest(2), decision_hash=digest(3))
        self.assertEqual(len(vote), 10 + 4 * 64)

    def test_report_hash_and_settlement_hash_are_static_abi_not_packed(self):
        expected = "0x" + keccak256(bytes.fromhex(abi(digest(1), address(2), digest(3))[2:])).hex()
        self.assertEqual(v9.report_id_for(digest(1), address(2), digest(3)), expected)

    def test_receipt_escrowed_requires_correct_contract_topic_and_canonical_fields(self):
        log = {"address": address(3), "topics": [v9.RECEIPT_ESCROWED_TOPIC, digest(1), digest(2), abi(address(4))],
               "data": abi(address(7), 1000, 1200), "removed": False}
        parsed = v9.parse_receipt_escrowed(log, expected_contract=address(3))
        self.assertEqual(parsed["owner"], address(4))
        self.assertEqual(parsed["gross_fee"], 1000)
        for changes in ({"address": address(9)}, {"removed": True}, {"topics": [digest(0)]}, {"data": "0x"}):
            with self.subTest(changes=changes), self.assertRaises(ChainError):
                v9.parse_receipt_escrowed({**log, **changes}, expected_contract=address(3))


class V9DeploymentTests(unittest.TestCase):
    def test_explicit_manifest_accepts_and_roundtrips(self):
        value = v9.validate_deployment(deployment_manifest())
        self.assertEqual(value.protocol_version, 9)
        self.assertEqual(value.eip712_version, "9")
        self.assertEqual(v9.validate_deployment(value.to_dict()), value)

    def test_missing_policy_or_independence_never_defaulted(self):
        for name in ("policy", "adjudicators", "adjudication_threshold", "adjudicator_operators", "independence_attested", "reward_token", "eip712_version"):
            value = deployment_manifest()
            del value[name]
            with self.subTest(name=name), self.assertRaises(ChainError):
                v9.validate_deployment(value)

    def test_monetary_boundaries_and_authority_conflicts(self):
        cases = (("reporter_bond", 0), ("slash_bps", 10001), ("reporter_bounty_bps", 10000),
                 ("stable_bounty_cap", 10001), ("token_minimum_penalty", 0), ("dispute_window", 2592001),
                 ("arbitration_timeout", True), ("token_reward", 1001), ("slash_cap", 1.5),
                 ("bond_penalty_recipient", address(10)))
        for field, item in cases:
            value = deployment_manifest()
            value["policy"][field] = item
            with self.subTest(field=field), self.assertRaises(ChainError):
                v9.validate_deployment(value)

    def test_quorum_and_declared_operator_separation(self):
        for changes in ({"adjudication_threshold": 1}, {"adjudication_threshold": 4}, {"independence_attested": False},
                        {"adjudicators": [address(10), address(10), address(12)]},
                        {"adjudicator_operators": {address(10): "same", address(11): "SAME", address(12): "other"}},
                        {"governance": address(10)}, {"reward_token": address(2)}, {"protocol_version": 8},
                        {"eip712_version": "8"}):
            with self.subTest(changes=changes), self.assertRaises(ChainError):
                v9.validate_deployment({**deployment_manifest(), **changes})

    def test_reward_can_only_be_explicitly_disabled(self):
        value = deployment_manifest()
        value["reward_token"] = address(0)
        with self.assertRaises(ChainError):
            v9.validate_deployment(value)
        for name in ("token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty"):
            value["policy"][name] = 0
        self.assertEqual(v9.validate_deployment(value).reward_token, address(0))


if __name__ == "__main__":
    unittest.main()
