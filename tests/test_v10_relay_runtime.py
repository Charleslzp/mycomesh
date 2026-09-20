from __future__ import annotations
import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from gateway import chain_v10 as v, relay
from gateway.chain import channel_to_hash, keccak256, sign_evm_digest
from gateway.chain_v4 import _signature_bytes
from gateway.relay_integrity import provider_response_hash, RelayIntegrityError
from gateway.reserved_execution import ReservedExecutionError
from gateway.session_relayer import RelaySettlementOutbox, RelaySettlementSubmitter, RelaySettlementError
from gateway.v10_relayer import prepare_v10_relay_settlement, validate_v10_response
from tests.test_chain_v10 import config
from tests.test_chain_v9 import key, signer, address, digest


class V10RelayRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.now = int(time.time()); self.contract = address(50)
        c = config(self.now); c['channel'] = channel_to_hash('c')
        self.cid = v.channel_id_for(c, chain_id=31337, settlement_contract=self.contract)
        self.channel = {**c, 'config': c, 'channel_id': self.cid, 'closed': False,
            'credit_remaining': 20000, 'stake_remaining': 20000, 'settled_max_fee': 0,
            'block_hash': digest(99), 'block_number': 500, 'head_timestamp': self.now}
        self.body = {'input': 'hello', 'model': 'm', 'max_output_tokens': 128,
            'metadata': {'mycomesh_provider_signer': signer(2)}}
        self.state = relay.RelayState(settlement_version=10, payment_address=signer(3),
            attestation_address=signer(3), attestation_private_keys={signer(3): key(3)})
        self.state.settlement_chain_id=31337; self.state.settlement_contract=self.contract
        self.state.settlement_rpc_url = 'https://unit.invalid'
        for name, provider_signer in [('first', signer(2)), ('other', signer(4))]:
            self.state.providers[name] = relay.RelayProviderSession(peer_id=name, last_seen=100,
                peer={'peer_id': name, 'channel': 'c', 'model': 'm', 'models': ['m'],
                    'payment_address': signer(22), 'settlement': {'version': 10, 'chain_id': 31337,
                    'contract': self.contract, 'pricing_version': 1, 'pricing_hash': c['pricing_hash'],
                    'provider_signer': provider_signer}})
        self.request = relay._v7_normalize_request(self.state, '/v1/responses', self.body, payment=None)
        self.request['request_id'] = digest(1)
        self.auth = v.build_authorization(payment_key=key(1), chain_id=31337, settlement_contract=self.contract,
            channel_id=self.cid, request_id=digest(1), request_hash=self.request['request_hash'],
            max_fee=10000, issued_at=self.now, execute_by=self.now+300, deadline=self.now+9000)
        self.dispatch = v.build_relay_dispatch(authorization_payload=self.auth, relay_private_key=key(3))
        self.response = {'ok': True, 'request_id': digest(1), 'endpoint': 'responses', 'model': 'm',
            'output_text': 'answer', 'usage': {'input_tokens': 100, 'output_tokens': 10},
            'raw': {'output_text': 'answer', 'usage': {'input_tokens': 100, 'output_tokens': 10}}}
        self.signed = v.build_provider_receipt(provider_private_key=key(2), dispatch_payload=self.dispatch,
            response_hash=provider_response_hash(self.response), input_tokens=100, output_tokens=10,
            actual_fee=2000, channel=self.channel)
        self.response['settlement_v10'] = self.signed
        self.outbox = RelaySettlementOutbox(Path(self.tmp.name)/'settle.sqlite3')
        self.worker = RelaySettlementSubmitter(outbox=self.outbox, rpc_url='https://unit.invalid',
            private_key=key(8), settlement_version=10, expected_chain_id=31337,
            expected_contract=self.contract, batch_encoder=v.encode_signed_batch_tuples)

    def prepared(self):
        return prepare_v10_relay_settlement(self.signed, channel=self.channel,
            expected_chain_id=31337, expected_contract=self.contract)

    def test_prepare_retains_provider_receipt_and_reserved_batch(self):
        p = self.prepared()
        self.assertEqual(p.payload['signed_receipt'], self.signed)
        self.assertEqual(p.payload['settlement_key'], v.settlement_key_for(self.cid, digest(1)))
        self.assertEqual(p.calldata, v.encode_signed_batch([self.signed]))
        with self.assertRaises(RelaySettlementError):
            prepare_v10_relay_settlement(self.signed, channel={**self.channel, 'provider_owner': signer(5)},
                expected_chain_id=31337, expected_contract=self.contract)

    def test_status_requires_exact_channel(self):
        self.worker.enqueue(self.prepared())
        self.assertIsNone(self.worker.public_status(digest(1), key_address=signer(1)))
        self.assertIsNone(self.worker.public_status(digest(1), key_address=signer(1), channel_id=digest(2)))
        status = self.worker.public_status(digest(1), key_address=signer(1), channel_id=self.cid)
        self.assertEqual(status['protocol_version'], 10); self.assertEqual(status['channel_id'], self.cid)

    def test_dispatch_bytes_survive_restart_and_conflicting_auth_is_rejected(self):
        build=Mock(return_value=self.dispatch)
        self.assertEqual(self.outbox.v10_dispatch(self.auth,build=build),self.dispatch)
        restarted=RelaySettlementOutbox(self.outbox.path)
        self.assertEqual(restarted.v10_dispatch(self.auth,build=build),self.dispatch)
        build.assert_called_once()
        bad=copy.deepcopy(self.auth);bad['authorization']['max_fee']=9000
        with self.assertRaises(RelaySettlementError): restarted.v10_dispatch(bad,build=build)

    def test_default_two_hour_or_hundred_schedule_is_independent_of_batch_limit(self):
        self.worker.enqueue(self.prepared())
        self.assertEqual(self.worker.settlement_count_threshold,100)
        self.assertEqual(self.worker.settlement_interval_seconds,7200)
        self.assertLessEqual(self.worker.batch_size,32)
        self.assertEqual(self.worker._next_scheduled_batch(),[])

    def test_old_worker_rejects_v10_domain(self):
        old = RelaySettlementSubmitter(outbox=self.outbox, rpc_url='rpc', private_key=key(8), settlement_version=9)
        with self.assertRaises(RelaySettlementError): old.enqueue(self.prepared())

    def test_signed_response_body_is_verified(self):
        args = dict(authorization=self.auth, dispatch=self.dispatch, channel=self.channel,
            request=self.request, provider_public_key=None, response_audience='unused')
        self.assertEqual(validate_v10_response(self.response, **args), self.signed)
        with self.assertRaises(RelayIntegrityError):
            validate_v10_response({**self.response, 'output_text': 'changed'}, **args)

    def test_exact_dispatch_rejected_if_replaced(self):
        with self.assertRaises(RelayIntegrityError):
            validate_v10_response(self.response, authorization=self.auth, dispatch={}, channel=self.channel,
                request=self.request, provider_public_key=None, response_audience='unused')

    def test_route_signs_before_execution_and_does_not_resign_usage(self):
        submitter = Mock(); submitter.reserve_admission.return_value='held'; submitter.enqueue.return_value=('pending',True)
        submitter.outbox=self.outbox; self.outbox.v10_dispatch(self.auth, build=lambda:self.dispatch)
        self.state._settlement_submitter=submitter
        def provider_call(state, selected, message, **kwargs):
            self.assertEqual(selected.peer_id, 'first')
            self.assertEqual(message['relay_dispatch'], self.dispatch)
            self.assertEqual(message['payment_v10'], self.auth)
            return self.response
        with patch('gateway.reserved_execution.confirmed_channel_snapshot', return_value=self.channel), \
             patch.object(relay, '_relay_v7_provider', side_effect=provider_call) as infer:
            raw, receipt = relay.relay_v7_openai(self.state, '/v1/responses', self.body, self.auth)
        self.assertEqual(raw, self.response['raw']); self.assertEqual(receipt['signed_receipt'], self.signed)
        self.assertEqual(infer.call_count, 1); submitter.enqueue.assert_called_once()

    def test_unknown_outcome_never_changes_provider(self):
        self.state._settlement_submitter=Mock(outbox=self.outbox)
        with patch('gateway.reserved_execution.confirmed_channel_snapshot', return_value=self.channel), \
             patch.object(relay, '_relay_v7_provider', side_effect=relay.RelayOutcomeUnknownError('unknown')) as infer:
            with self.assertRaises(relay.RelayOutcomeUnknownError):
                relay.relay_v7_openai(self.state, '/v1/responses', self.body, self.auth)
        self.assertEqual(infer.call_count, 1)

    def test_snapshot_budget_is_fifteen_seconds_and_capped_by_request_deadline(self):
        self.state._settlement_submitter=Mock(outbox=self.outbox)
        for request_deadline,expected_snapshot_deadline in ((160.0,115.0),(108.0,108.0)):
            with self.subTest(request_deadline=request_deadline), \
                 patch.object(relay.time,'monotonic',return_value=100.0), \
                 patch('gateway.reserved_execution.confirmed_channel_snapshot',side_effect=ReservedExecutionError('fixture stop')) as snapshot, \
                 patch.object(relay,'_relay_v7_provider') as infer:
                with self.assertRaises(relay.RelayNotDispatchedError):
                    relay.relay_v10_openai(self.state,'/v1/responses',self.body,self.auth,
                        response_proof=False,deadline=request_deadline)
                self.assertEqual(snapshot.call_args.kwargs['timeout'],15.0)
                self.assertEqual(snapshot.call_args.kwargs['deadline'],expected_snapshot_deadline)
                self.assertEqual(snapshot.call_args.kwargs['confirmations'],6)
                self.assertIsNone(self.outbox.v10_dispatch(self.auth))
                infer.assert_not_called()

    def test_expired_request_never_persists_dispatch_after_snapshot(self):
        self.state._settlement_submitter=Mock(outbox=self.outbox)
        with patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value=self.channel), \
             patch.object(relay.time,'monotonic',side_effect=[100.0,116.0]), \
             patch.object(relay,'_relay_v7_provider') as infer:
            with self.assertRaisesRegex(relay.RelayNotDispatchedError,'total deadline'):
                relay.relay_v10_openai(self.state,'/v1/responses',self.body,self.auth,
                    response_proof=False,deadline=115.0)
        self.assertIsNone(self.outbox.v10_dispatch(self.auth))
        infer.assert_not_called()

    def test_other_relay_or_provider_hint_rejected_before_dispatch(self):
        self.state._settlement_submitter=Mock(outbox=self.outbox)
        with patch('gateway.reserved_execution.confirmed_channel_snapshot', return_value=self.channel), \
             patch.object(relay, '_relay_v7_provider') as infer:
            with self.assertRaises(relay.RelayNotDispatchedError):
                relay.relay_v7_openai(self.state, '/v1/responses', {**self.body, 'metadata': {}}, self.auth)
        infer.assert_not_called()

    def test_v2_status_signature_binds_channel(self):
        b = dict(chain_id=31337, settlement_contract=self.contract, key=signer(1),
            channel_id=self.cid, request_id=digest(1), issued_at=self.now)
        msg=(f"MycoMesh receipt status v2\nchain_id:{b['chain_id']}\nsettlement_contract:{self.contract}"
             f"\nkey:{b['key']}\nchannel_id:{self.cid}\nrequest_id:{b['request_id']}\nissued_at:{self.now}").encode()
        h=keccak256(b'\x19Ethereum Signed Message:\n'+str(len(msg)).encode()+msg)
        b['signature']='0x'+_signature_bytes(sign_evm_digest(key(1),h),'test').hex()
        self.assertEqual(relay._verify_receipt_status_request(self.state,b), (digest(1),signer(1)))
        with self.assertRaises(relay.RelaySchedulingError):
            relay._verify_receipt_status_request(self.state,{**b,'channel_id':digest(9)})

    def test_external_provider_settlement_reconciles_without_new_transaction(self):
        p=self.prepared(); self.worker.enqueue(p)
        auth=self.auth['authorization']; terms=self.channel
        info={'status':1,'release_at':self.now+300,'owner':terms['consumer_owner'],'key':auth['key'],
            'provider':terms['provider_owner'],'provider_signer':terms['provider_signer'],
            'relay':terms['relay'],'relay_signer':terms['relay_signer'],'request_id':auth['request_id'],
            'request_hash':auth['request_hash'],'authorization_hash':self.signed['receipt']['authorization_hash'],
            'response_hash':self.signed['receipt']['response_hash'],'gross_fee':2000}
        with patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value=self.channel), \
             patch.object(v,'settlement_info',return_value=info), patch.object(self.worker,'_send_transaction') as send, \
             patch('gateway.session_relayer.rpc_call',side_effect=lambda url,method,params,timeout:
                   hex(self.channel['block_number']+6) if method=='eth_blockNumber' else
                   {'number':hex(self.channel['block_number']), 'hash':self.channel['block_hash']}):
            self.assertEqual(self.worker.process_once(force=True),1)
        send.assert_not_called(); self.assertEqual(self.outbox.status(p.key),'escrowed')

    def test_submitted_unknown_keeps_same_tx_recovery(self):
        p=self.prepared(); self.worker.enqueue(p); tx='0x'+keccak256(bytes.fromhex('1234')).hex()
        self.outbox.mark_submitted_many([p.key],tx,raw_transaction='0x1234')
        # Even a fresh pending receipt approaching deadline cannot skip this
        # unknown nonce in a forced Provider rescue batch.
        from dataclasses import replace
        pending=replace(p,key=p.key+'-pending',session_id=digest(6))
        self.worker.enqueue(pending)
        with patch.object(self.worker,'_reconcile_v10_existing') as reconcile, \
             patch.object(self.worker,'_wait_for_receipt') as wait, patch.object(self.worker,'_send_transaction') as send:
            self.worker.process_once(force=True)
        reconcile.assert_not_called(); send.assert_not_called(); wait.assert_called_once_with([p.key],tx)
        self.assertEqual(self.outbox.status(pending.key),'pending')

    def test_health_identifies_reservation_mode_and_models(self):
        health=relay.v7_relay_capabilities(self.state)
        self.assertEqual(health['reservation_mode'],'provider_bound_channel')
        self.assertEqual(health['protocol_version'],10)
        self.assertEqual(health['provider_routes'][0]['models'],['m'])


if __name__ == '__main__': unittest.main()
