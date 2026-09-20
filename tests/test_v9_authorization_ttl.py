"""No external RPC: compatibility boundaries for the inactive 3-hour candidate."""
import time
import unittest
from unittest.mock import patch

from gateway import chain_v9 as v9
from gateway.chain import ChainError
from tests.test_chain_v9 import address, deployment_manifest, digest, abi
from tests import test_chain_v9, test_consumer_v9


class AuthorizationTTLTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.options = dict(rpc_url="http://fixture.invalid", chain_id=31337, settlement=address(3),
                            key=address(1), now=self.now, deadline_seconds=9000,
                            expected_max_ttl=10800, max_fee=100)

    def verify(self, *, limit=10800, valid_until=0, active=True, max_fee=100,
               chain_id=31337, head_offset=0):
        calls = []
        def rpc(url, method, params, timeout):
            calls.append((method, params))
            if method == "eth_chainId": return hex(chain_id)
            if method == "eth_getBlockByNumber":
                return {"hash": digest(90), "timestamp": hex(self.now + head_offset)}
            self.assertEqual(method, "eth_call")
            self.assertEqual(params[1], {"blockHash": digest(90), "requireCanonical": True})
            if params[0]["data"] == v9._calldata("MAX_AUTHORIZATION_TTL()", []): return abi(limit)
            if params[0]["data"] == v9._calldata("keyGrants(address)", [address(1)]):
                return abi(address(7), max_fee, valid_until, str(active).lower())
            raise AssertionError(params)
        with patch("gateway.chain_v9.rpc_call", side_effect=rpc):
            result = v9.verified_authorization_window(**self.options)
        self.assertEqual(len(calls), 4)
        return result

    def test_long_window_uses_one_canonical_snapshot_and_clock_allowance(self):
        result = self.verify(valid_until=self.now + 9000)
        self.assertEqual(result["issued_at"], self.now - 300)
        self.assertEqual(result["deadline"], self.now + 9000)
        self.assertEqual(result["max_authorization_ttl"], 10800)

    def test_long_manifest_against_legacy_contract_fails_closed(self):
        with self.assertRaisesRegex(ChainError, "differs from the pinned"):
            self.verify(limit=3600)

    def test_key_must_remain_active_and_valid_for_entire_requested_window(self):
        for options in ({"valid_until": self.now + 8999}, {"active": False}, {"max_fee": 99}):
            with self.subTest(options=options), self.assertRaises(ChainError):
                self.verify(**options)

    def test_wrong_chain_and_stale_or_future_clock_fail_closed(self):
        for options in ({"chain_id": 1}, {"head_offset": -301}, {"head_offset": 301}):
            with self.subTest(options=options), self.assertRaises(ChainError):
                self.verify(**options)

    def test_legacy_manifest_keeps_canonical_fields_and_short_default(self):
        raw = deployment_manifest()
        parsed = v9.validate_deployment(raw)
        self.assertEqual(parsed.max_authorization_ttl_seconds, 3600)
        self.assertEqual(parsed.authorization_deadline_seconds, 900)
        self.assertNotIn("max_authorization_ttl_seconds", parsed.to_dict())
        self.assertNotIn("authorization_deadline_seconds", parsed.to_dict())

    def test_manifest_rejects_overlong_bool_and_ambiguous_numeric_policy(self):
        for maximum, deadline in ((3600, 9000), (10800, 10501), (True, 900), (10800, "9000"), (10800, 0)):
            with self.subTest(maximum=maximum, deadline=deadline), self.assertRaises(ChainError):
                v9.validate_deployment({**deployment_manifest(), "max_authorization_ttl_seconds": maximum,
                                        "authorization_deadline_seconds": deadline})

    def test_signer_requires_explicit_verified_limit_for_long_window(self):
        fixture = test_chain_v9.ChainV9Tests()
        fixture.setUp()
        params = {**fixture.params, "deadline": fixture.now + 9300}
        with self.assertRaises(ChainError): v9.build_authorization(**params)
        signed = v9.build_authorization(**params, max_authorization_ttl=10800)
        v9.verify_authorization(signed)
        with self.assertRaises(ChainError):
            v9.build_authorization(**{**params, "deadline": fixture.now + 10801}, max_authorization_ttl=10800)

    def test_consumer_legacy_does_not_add_a_new_rpc_dependency(self):
        fixture = test_consumer_v9.ConsumerV9Tests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with patch("gateway.chain_v9.verified_authorization_window") as verify:
            payment = fixture.payment()
        verify.assert_not_called()
        window = payment["authorization"]
        self.assertEqual(window["deadline"] - window["issued_at"], 1200)

    def test_consumer_long_authorization_uses_readback_and_never_shortens_after_failure(self):
        fixture = test_consumer_v9.ConsumerV9Tests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.state._settlement.update(max_authorization_ttl_seconds=10800, authorization_deadline_seconds=9000)
        with patch("gateway.chain_v9.verified_authorization_window", return_value={
            "issued_at": self.now - 300, "deadline": self.now + 9000, "max_authorization_ttl": 10800,
        }) as verified:
            payment = fixture.payment()
        self.assertEqual(payment["authorization"]["deadline"], self.now + 9000)
        self.assertEqual(verified.call_args.kwargs["expected_max_ttl"], 10800)
        with patch("gateway.chain_v9.verified_authorization_window", side_effect=ChainError("old contract")):
            with self.assertRaisesRegex(Exception, "old contract"):
                fixture.payment()


if __name__ == "__main__":
    unittest.main()
