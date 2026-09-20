from __future__ import annotations

import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gateway import chain, p2p
from tests import test_p2p_v10 as fixtures

REAL_ONCHAIN_QUOTE = p2p.v3_onchain_quote
HASH = '0x' + 'ab' * 32
TAG = {'blockHash': HASH, 'requireCanonical': True}
CONTRACT = '0x' + '12' * 20


class ContractBlockIdentifierTests(unittest.TestCase):
    def test_hash_object_reaches_rpc_as_json_object_without_mutation(self):
        tag = {'blockHash': '0x' + 'AB' * 32, 'requireCanonical': True}
        with patch('gateway.chain.rpc_call', return_value='0x' + f'{2000:064x}') as rpc:
            self.assertEqual(chain.call_uint256('rpc', CONTRACT, 'value()', [], block_tag=tag), 2000)
        actual = rpc.call_args.args[2][1]
        self.assertEqual(json.loads(json.dumps(actual)), TAG)
        self.assertEqual(tag['blockHash'], '0x' + 'AB' * 32)

    def test_old_numeric_and_named_selectors_remain_compatible(self):
        for value, expected in ((95, '0x5f'), (0, '0x0'), (-1, '0x0'), ('latest', 'latest'),
                                ('pending', 'pending'), ('safe', 'safe'), ('0x5f', '0x5f')):
            with self.subTest(value=value), patch('gateway.chain.rpc_call', return_value='0x') as rpc:
                chain.call_contract('rpc', CONTRACT, 'value()', [], block_tag=value)
                self.assertEqual(rpc.call_args.args[2][1], expected)

    def test_malformed_hash_objects_fail_before_rpc(self):
        invalid = [None, [], {}, {'blockHash': HASH}, {'blockNumber': '0x1'},
            {**TAG, 'blockNumber': '0x1'}, {**TAG, 'other': 1},
            *[{**TAG, 'requireCanonical': v} for v in (False, 1, 'true', None)],
            *[{**TAG, 'blockHash': v} for v in ('0x' + '00' * 32, 'latest', HASH + '\n', HASH[:-1], 123)]]
        for value in invalid:
            with self.subTest(value=value), patch('gateway.chain.rpc_call') as rpc:
                with self.assertRaises(chain.ChainError):
                    chain.call_contract('rpc', CONTRACT, 'value()', [], block_tag=value)
                rpc.assert_not_called()

    def test_real_p2p_quote_helper_preserves_snapshot_at_rpc_boundary(self):
        config = SimpleNamespace(settlement_rpc_url='rpc', settlement_contract=CONTRACT,
                                 settlement_rpc_timeout_seconds=5)
        with patch('gateway.chain.rpc_call', return_value='0x' + f'{9000:064x}') as rpc:
            self.assertEqual(REAL_ONCHAIN_QUOTE(config, 'codex-standard-v1', 1, 1000, 2000, block_tag=TAG), 9000)
        self.assertEqual(rpc.call_args.args[1], 'eth_call')
        self.assertEqual(rpc.call_args.args[2][1], TAG)
        self.assertEqual(rpc.call_args.args[2][0]['data'], chain.encode_contract_call(
            'quote(bytes32,uint64,uint256,uint256)', [chain.DEFAULT_CHANNEL_HASH, '1', '1000', '2000']))


class ProviderV10QuoteBoundaryTests(unittest.TestCase):
    setUp = fixtures.ProviderV10Test.setUp
    tearDown = fixtures.ProviderV10Test.tearDown
    message = fixtures.ProviderV10Test.message
    sign = fixtures.ProviderV10Test.sign

    def test_full_provider_inference_uses_real_quote_helper_for_both_reads(self):
        calls = []
        def rpc(url, method, params, timeout):
            self.assertEqual(method, 'eth_call')
            self.assertEqual(params[1], {'blockHash': self.snapshot['block_hash'], 'requireCanonical': True})
            # Return the fixture's minimum tariff at the JSON-RPC boundary;
            # both v3_onchain_quote and chain.call_contract execute unchanged.
            words = params[0]['data'][10:]
            inputs, outputs = int(words[128:192], 16), int(words[192:256], 16)
            amount = p2p.provider_min_reservation_units(self.config.channel, input_tokens=inputs, output_tokens=outputs)
            calls.append((inputs, outputs))
            return '0x' + f'{amount:064x}'
        with patch('gateway.p2p.v3_onchain_quote', new=REAL_ONCHAIN_QUOTE), \
             patch('gateway.chain.rpc_call', side_effect=rpc):
            response = p2p.handle_infer(self.config, self.message())
        self.assertTrue(response['ok'], response)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[-1], (5, 3))
        self.assertEqual(self.gateway.call_count, 1)
        self.assertEqual(len(self.config._reserved_ledger.outbox()), 1)


if __name__ == '__main__':
    unittest.main()
