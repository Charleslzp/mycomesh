import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from gateway.provider_settlement_fallback import fallback_decision,run

class ProviderFallbackTests(unittest.TestCase):
    def rows(self,deadline):return [{'signed_receipt':{'authorization':{'authorization':{'deadline':deadline}}}}]
    def test_disabled_never_opens_private_identity_or_rpc(self):
        self.assertEqual(run({})['reason'],'local_operator_switch_disabled')
    def test_healthy_relay_does_not_compete_during_normal_batch_window(self):
        d=fallback_decision(self.rows(10000),relay_ready=True,now=1000)
        self.assertFalse(d['attempt']);self.assertFalse(d['force'])
    def test_down_relay_uses_normal_schedule(self):
        d=fallback_decision(self.rows(10000),relay_ready=False,now=1000)
        self.assertTrue(d['attempt']);self.assertFalse(d['force'])
    def test_deadline_protection_even_if_relay_health_is_green(self):
        d=fallback_decision(self.rows(1800),relay_ready=True,now=1000)
        self.assertTrue(d['attempt']);self.assertTrue(d['force'])
    def test_empty_and_expired_do_not_trigger_force(self):
        self.assertFalse(fallback_decision([],relay_ready=False,now=1000)['attempt'])
        self.assertFalse(fallback_decision(self.rows(500),relay_ready=False,now=1000)['force'])
    def test_large_backlog_starts_protection_before_fixed_fifteen_minutes(self):
        rows=self.rows(2800)*200
        d=fallback_decision(rows,relay_ready=True,now=1000,batch_size=16)
        self.assertEqual(d['pending_count'],200)
        self.assertEqual(d['protection_window_seconds'],1860)
        self.assertTrue(d['force'])
    def test_normal_hundred_receipts_still_defer_to_healthy_relay(self):
        d=fallback_decision(self.rows(10000)*100,relay_ready=True,now=1000,batch_size=16)
        self.assertFalse(d['attempt']);self.assertEqual(d['protection_window_seconds'],1140)
    def test_expired_history_does_not_inflate_live_backlog_window(self):
        d=fallback_decision(self.rows(500)*1000+self.rows(10000),relay_ready=True,now=1000,batch_size=16)
        self.assertEqual(d['pending_count'],1);self.assertEqual(d['protection_window_seconds'],900)

    def test_enabled_wrapper_keeps_healthy_relay_schedule_and_skips_signed_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);contract='0x'+'12'*20;signer='0x'+'34'*20
            network={'relay':{'public_url':'https://relay.invalid'},'settlement_rpc_url':'https://rpc.invalid'}
            (root/'network.json').write_text(json.dumps(network))
            env={'MYCOMESH_PROVIDER_INDEPENDENT_SUBMIT_ENABLED':'1','MYCOMESH_ALLOW_CONTROLLED_V10_TEST':'1',
                'MYCOMESH_PROVIDER_NETWORK_CONFIG':str(root/'network.json'),
                'MYCOMESH_PROVIDER_SUBMISSION_OUTBOX':str(root/'outbox.sqlite3')}
            row={'contract':contract,'channel_id':'0x'+'56'*32,'request_id':'0x'+'78'*32,
                'signed_receipt':{'chain_id':11155111,'authorization':{'authorization':{'deadline':int(time.time())+9000}}}}
            with patch('gateway.chain_v10.load_deployment',return_value=SimpleNamespace(settlement=contract,chain_id=11155111)), \
                 patch('gateway.provider_bootstrap.load_provider_evm_identity',return_value=SimpleNamespace(address=signer)), \
                 patch('gateway.reserved_execution.read_execution_outbox',return_value=[row]) as read, \
                 patch('gateway.provider_settlement_fallback.relay_ready',return_value=True), \
                 patch('gateway.reserved_execution.submit_execution_outbox') as submit:
                result=run(env)
            self.assertFalse(result['broadcast']);submit.assert_not_called()
            self.assertGreater(read.call_args.kwargs['unexpired_at'],0)

    def test_recovering_unknown_runs_even_with_no_live_authorizations(self):
        from gateway.chain import keccak256
        from gateway.session_relayer import RelaySettlementOutbox,PreparedRelaySettlement
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);contract='0x'+'12'*20;signer='0x'+'34'*20
            (root/'network.json').write_text(json.dumps({'relay':{'public_url':'https://relay.invalid'},'settlement_rpc_url':'https://rpc.invalid'}))
            outbox=RelaySettlementOutbox(root/'outbox.sqlite3')
            item=PreparedRelaySettlement('durable','0x'+'78'*32,'0x'+'56'*32,0,11155111,contract,'0x00',{'protocol_version':10})
            outbox.enqueue(item);outbox.mark_submitted_many([item.key],'0x'+keccak256(b'raw').hex(),raw_transaction='0x'+b'raw'.hex())
            env={'MYCOMESH_PROVIDER_INDEPENDENT_SUBMIT_ENABLED':'1','MYCOMESH_ALLOW_CONTROLLED_V10_TEST':'1',
                'MYCOMESH_PROVIDER_NETWORK_CONFIG':str(root/'network.json'),
                'MYCOMESH_PROVIDER_SUBMISSION_OUTBOX':str(outbox.path)}
            with patch('gateway.chain_v10.load_deployment',return_value=SimpleNamespace(settlement=contract,chain_id=11155111)), \
                 patch('gateway.provider_bootstrap.load_provider_evm_identity',return_value=SimpleNamespace(address=signer)), \
                 patch('gateway.reserved_execution.read_execution_outbox',return_value=[]), \
                 patch('gateway.provider_settlement_fallback.relay_ready',return_value=True), \
                 patch('gateway.reserved_execution.submit_execution_outbox',return_value={'processed':1,'submission_attempted':True,'submission_status':{'submitted':1}}) as submit:
                result=run(env)
            self.assertTrue(result['recovering']);submit.assert_called_once()
            self.assertFalse(submit.call_args.kwargs['force']);self.assertEqual(submit.call_args.kwargs['batch_size'],16)
            self.assertNotIn('transactions',result)

    def test_expired_pending_is_reconciled_when_live_export_is_empty(self):
        from gateway.session_relayer import RelaySettlementOutbox,PreparedRelaySettlement
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);contract='0x'+'12'*20;signer='0x'+'34'*20
            (root/'network.json').write_text(json.dumps({'relay':{'public_url':'https://relay.invalid'},
                'settlement_rpc_url':'https://rpc.invalid'}))
            outbox=RelaySettlementOutbox(root/'outbox.sqlite3')
            item=PreparedRelaySettlement('expired','0x'+'78'*32,'0x'+'56'*32,0,11155111,contract,
                '0x00',{'protocol_version':10,'signed_receipt':{'authorization':{'authorization':{
                    'key':signer,'deadline':int(time.time())-1}}}})
            outbox.enqueue(item)
            env={'MYCOMESH_PROVIDER_INDEPENDENT_SUBMIT_ENABLED':'1','MYCOMESH_ALLOW_CONTROLLED_V10_TEST':'1',
                'MYCOMESH_PROVIDER_NETWORK_CONFIG':str(root/'network.json'),
                'MYCOMESH_PROVIDER_SUBMISSION_OUTBOX':str(outbox.path)}
            with patch('gateway.chain_v10.load_deployment',return_value=SimpleNamespace(settlement=contract,chain_id=11155111)), \
                 patch('gateway.provider_bootstrap.load_provider_evm_identity',return_value=SimpleNamespace(address=signer)), \
                 patch('gateway.reserved_execution.read_execution_outbox',return_value=[]) as read, \
                 patch('gateway.provider_settlement_fallback.relay_ready',return_value=True), \
                 patch('gateway.reserved_execution.submit_execution_outbox',return_value={'processed':1,
                     'submission_attempted':True,'submission_status':{'escrowed':1}}) as submit:
                result=run(env)
            self.assertTrue(result['recovering']);submit.assert_called_once()
            self.assertFalse(submit.call_args.kwargs['force'])
            self.assertEqual(read.call_args.kwargs['submission_outbox'],str(outbox.path))

if __name__=='__main__':unittest.main()
