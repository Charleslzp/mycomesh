from dataclasses import replace
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from gateway import chain_v10, provider_jury
from gateway.chain import DEFAULT_CHANNEL_HASH, ZERO_ADDRESS, parse_private_key, private_key_to_address
from gateway.identity import sign_document
from gateway.p2p import (INFERENCE_REQUEST_PURPOSE, _inference_request_hash, handle_infer,
    handle_message, provider_min_reservation_units, provider_runtime_capabilities, P2PError,
    P2P_JURY_REQUEST_PURPOSE)
from gateway.reserved_execution import ReservedExecutionLedger
from tests import test_p2p_v8 as v8_tests
from tests.test_chain_v9 import address, digest

class ProviderV10Test(unittest.TestCase):
    def setUp(self):
        self.old = v8_tests.ProviderV8Test(); self.old.setUp()
        self.tmp = tempfile.TemporaryDirectory(); self.directory = Path(self.tmp.name).resolve()
        oldconfig = self.old.config(str(self.directory))
        self.db, self.anchor = self.directory/'v10.sqlite3', self.directory/'anchor.json'
        self.channel = dict(consumer_owner='0x'+'88'*20,
            consumer_key=private_key_to_address(parse_private_key(self.old.payment_key)),
            provider_owner=self.old.provider_address,provider_signer=self.old.provider_signer,
            relay=self.old.relay_payout,relay_signer=self.old.relay_signer,pool=ZERO_ADDRESS,
            channel=DEFAULT_CHANNEL_HASH,pricing_version=1,pricing_hash=self.old.pricing_hash,
            capacity=200_000,max_fee_per_request=100_000,valid_from=self.old.now-100,
            admit_until=self.old.now+7200,claim_until=self.old.now+9500,
            consumer_nonce=0,provider_nonce=0,permit_deadline=self.old.now-200)
        self.channel_id=chain_v10.channel_id_for(self.channel,chain_id=11155111,settlement_contract=self.old.contract)
        self.snapshot={**self.channel,'config':self.channel,'closed':False,'credit_remaining':200_000,
            'stake_remaining':200_000,'settled_max_fee':0,'block_timestamp':self.old.now-1000,
            'head_timestamp':self.old.now,'block_hash':'0x'+'ab'*32,'block_number':10}
        ledger=ReservedExecutionLedger(self.db,anchor_path=self.anchor,provider_signer=self.old.provider_signer,create=True)
        ledger.activate(self.old.contract,self.channel_id,self.snapshot,now=self.old.now-1000);ledger.close()
        self.jury_system_prompt='Decide only from the pinned canonical evidence document.'
        self.config=replace(oldconfig,settlement_version=10,reserved_execution_path=str(self.db),reserved_execution_anchor_path=str(self.anchor),operator_id='fixture-operator',jury_enabled=True,
            jury_relay_public_keys={self.old.relay_identity.public_key},
            jury_decision_policy_hash=provider_jury.decision_policy_hash(
                model=oldconfig.model,system_prompt=self.jury_system_prompt,
                max_output_tokens=512,task_ttl_seconds=300))
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('gateway.p2p.ensure_gateway_readiness'))
        self.snapshot_mock=self.stack.enter_context(patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value=self.snapshot))
        self.stack.enter_context(patch('gateway.p2p.v3_onchain_quote',side_effect=lambda config,channel,version,inputs,outputs,**kw: provider_min_reservation_units(channel,input_tokens=inputs,output_tokens=outputs)))
        self.gateway=self.stack.enter_context(patch('gateway.p2p.call_gateway',return_value={'output_text':'world','usage':{'input_tokens':5,'output_tokens':3}}))
    def tearDown(self):
        self.config._reserved_ledger.close();self.tmp.cleanup()
    def message(self, number=1, **auth_changes):
        unsigned={'type':'infer','request_id':'0x'+format(number,'064x'),'channel':self.config.channel,
            'endpoint':'responses','model':self.config.model,'input':'hello','max_output_tokens':4}
        args=dict(payment_key=self.old.payment_key,chain_id=11155111,settlement_contract=self.old.contract,
            channel_id=self.channel_id,request_id=unsigned['request_id'],request_hash='0x'+_inference_request_hash(self.config,unsigned,4),
            max_fee=100_000,issued_at=self.old.now,execute_by=self.old.now+300,deadline=self.old.now+9000)
        args.update(auth_changes)
        unsigned['payment_v10']=chain_v10.build_authorization(**args)
        unsigned['relay_dispatch']=chain_v10.build_relay_dispatch(authorization_payload=unsigned['payment_v10'],relay_private_key=self.old.relay_signer_key)
        return self.sign(unsigned)
    def sign(self, unsigned):
        return sign_document({k:v for k,v in unsigned.items() if k!='signature'},self.old.relay_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,audience=self.config.peer_id)
    def jury_task(self, *, assignment_hash=None):
        cap=provider_runtime_capabilities(self.config)['provider_jury']
        selected={'owner':cap['provider_owner'],'vote_signer':cap['vote_signer'],
            'operator_id':cap['operator_id'],'operator_id_hash':cap['operator_id_hash'],
            'peer_id':self.config.peer_id,'peer_id_hash':cap['peer_id_hash'],
            'capability':cap['capability'],'capability_hash':cap['capability_hash'],'reputation':95}
        if not hasattr(self,'_jury_artifact'):
            original=self.message(90)
            provider_response=handle_infer(self.config,original)
            self.assertTrue(provider_response['ok'],provider_response)
            self._jury_artifact=(original,provider_response)
        else:
            original,provider_response=self._jury_artifact
        self.gateway.reset_mock()
        request={
            'request_id':original['request_id'],'endpoint':original['endpoint'],
            'model':original['model'],'input':original.get('input'),
            'messages':original.get('messages'),'max_output_tokens':original['max_output_tokens'],
            'options':{},
        }
        settlement_key=chain_v10.settlement_key_for(self.channel_id,original['request_id'])
        reporter=address(88)
        evidence_document={
            'schema':provider_jury.EVIDENCE_DOCUMENT_SCHEMA,
            'settlement_key':settlement_key,'reporter':reporter,
            'origin_relay_public_key':self.old.relay_identity.public_key,
            'allegation':{'code':'incorrect_response',
                'summary':'Review the authenticated request and Provider response for fraud.'},
            'request':request,'provider_response':provider_response,
        }
        committed=provider_jury.evidence_hash(evidence_document)
        report_id=chain_v10.report_id_for(settlement_key,reporter,committed)
        _,receipt,_=chain_v10.verify_signed_receipt(
            provider_response['settlement_v10'],now=self.old.now)
        return provider_jury.build_jury_task(network_id=self.config.network_id,
            chain_id=self.config.settlement_chain_id,settlement_contract=self.config.settlement_contract,
            jury_registry=address(77),settlement_key=settlement_key,
            assignment_hash=assignment_hash or digest(71),selected_provider=selected,
            evidence={'report_id':report_id,'evidence_hash':committed,
                'request_hash':original['payment_v10']['authorization']['request_hash'],
                'response_hash':receipt.response_hash},
            decision_policy_hash=self.config.jury_decision_policy_hash,
            inference_request={'model':self.config.model,'system_prompt':self.jury_system_prompt,
                'evidence_document':evidence_document,'max_output_tokens':512},
            relay_identity=self.old.relay_identity,issued_at=self.old.now,deadline=self.old.now+300,
            nonce=digest(75))
    def jury_message(self, task):
        return sign_document({'type':'jury_infer','request_id':'jury-1','jury_task':task},
            self.old.relay_identity.private_key,purpose=P2P_JURY_REQUEST_PURPOSE,
            audience=self.config.peer_id,timestamp=self.old.now)
    def jury_chain(self, task):
        selected=task['selected_provider'];evidence=task['evidence']
        document=task['inference_request']['evidence_document']
        response=document['provider_response'];signed=response['settlement_v10']
        authorization,receipt,_=chain_v10.verify_signed_receipt(signed,now=self.old.now)
        return [
            patch('gateway.p2p._confirmed_settlement_block',return_value=100),
            patch('gateway.chain_v10.jury_registry_address',return_value=task['jury_registry']),
            patch('gateway.chain_v10.jury_assignment_hash',return_value=task['assignment_hash']),
            patch('gateway.chain_v10.jury_assignment_provider',return_value={
                'found':True,'owner':selected['owner'],'operator_id_hash':selected['operator_id_hash'],
                'peer_id_hash':selected['peer_id_hash'],'capability_hash':selected['capability_hash'],
                'reputation':selected['reputation']}),
            patch('gateway.chain_v10.settlement_info',return_value={'status':2,
                'request_id':authorization['authorization']['request_id'],
                'request_hash':evidence['request_hash'],
                'authorization_hash':authorization['authorization_hash'],
                'response_hash':evidence['response_hash'],
                'provider_signer':signed['provider_signer'],
                'relay_signer':signed['dispatch']['relay_signer'],
                'gross_fee':receipt.actual_fee,'release_at':self.old.now-100}),
            patch('gateway.chain_v10.report_info',return_value={'reporter':document['reporter'],
                'evidence_hash':evidence['evidence_hash'],'bond_claimed':False}),
            patch('gateway.chain_v10.dispute_info',return_value={'resolve_at':self.old.now+600}),
            patch('gateway.chain_v10.adjudicator_nonce',return_value=3),
            patch('gateway.chain.rpc_call',return_value={'timestamp':hex(self.old.now)}),
        ]
    def test_response_and_independent_receipt_durable_before_return(self):
        response=handle_infer(self.config,self.message())
        self.assertTrue(response['ok'],response)
        self.assertIs(self.snapshot_mock.call_args.kwargs['require_jury_ready'],True)
        auth,receipt,_=chain_v10.verify_signed_receipt(response['settlement_v10'],channel=self.snapshot)
        self.assertEqual(receipt.actual_fee,2000)
        from gateway.relay_integrity import provider_response_hash
        self.assertEqual(receipt.response_hash,provider_response_hash(response))
        saved=self.config._reserved_ledger.outbox()[0]
        self.assertEqual(saved['response'],response)
        self.assertEqual(saved['signed_receipt'],response['settlement_v10'])
        self.assertEqual(self.gateway.call_count,1)
    def test_completed_retry_survives_rpc_and_gateway_outage(self):
        message=self.message();first=handle_infer(self.config,message)
        self.assertTrue(first['ok'],first)
        self.snapshot_mock.side_effect=OSError('RPC down');self.gateway.side_effect=OSError('Gateway down')
        again=handle_infer(self.config,self.sign(message))
        self.assertTrue(again['ok'],again);self.assertEqual(again['settlement_v10'],first['settlement_v10'])
        self.assertEqual(self.gateway.call_count,1)
    def test_timeout_unknown_never_reexecutes_and_keeps_max_fee(self):
        self.gateway.side_effect=TimeoutError('unknown upstream state')
        message=self.message();first=handle_infer(self.config,message);again=handle_infer(self.config,self.sign(message))
        self.assertEqual(first['execution_status'],'unknown',first);self.assertFalse(again['retryable'])
        self.assertEqual(self.gateway.call_count,1)
        self.assertEqual(self.config._reserved_ledger.channel(self.old.contract,self.channel_id)['reserved'],'100000')
    def test_wrong_relay_signature_never_reaches_model(self):
        message=self.message();message['relay_dispatch']=chain_v10.build_relay_dispatch(authorization_payload=message['payment_v10'],relay_private_key=self.old.provider_key)
        result=handle_infer(self.config,self.sign(message));self.assertFalse(result['ok']);self.gateway.assert_not_called()
    def test_wrong_channel_provider_binding_never_reaches_model(self):
        self.snapshot_mock.return_value={**self.snapshot,'provider_signer':'0x'+'99'*20}
        result=handle_infer(self.config,self.message());self.assertFalse(result['ok']);self.gateway.assert_not_called()
    def test_missing_preactivation_never_reconstructs_budget(self):
        with self.config._reserved_ledger._transaction(): self.config._reserved_ledger._db.execute('DELETE FROM channels')
        result=handle_infer(self.config,self.message());self.assertFalse(result['ok']);self.assertIn('preactivated',result['error']);self.gateway.assert_not_called()
    def test_canonical_quote_mismatch_fails_before_model_or_debit(self):
        with patch('gateway.p2p.v3_onchain_quote',return_value=999999):
            result=handle_infer(self.config,self.message())
        self.assertFalse(result['ok']);self.assertIn('pricing',result['error']);self.gateway.assert_not_called()
        self.assertEqual(self.config._reserved_ledger.channel(self.old.contract,self.channel_id)['reserved'],'0')
    def test_chain_head_may_predate_fresh_authorization_within_window(self):
        self.snapshot_mock.return_value={**self.snapshot,'head_timestamp':self.old.now-10}
        result=handle_infer(self.config,self.message());self.assertTrue(result['ok'],result)
    def test_expired_admission_rejected_before_reserve(self):
        message=self.message(issued_at=self.old.now-99,execute_by=self.old.now-1,deadline=self.old.now+500)
        result=handle_infer(self.config,message);self.assertFalse(result['ok']);self.gateway.assert_not_called()
        self.assertEqual(self.config._reserved_ledger.channel(self.old.contract,self.channel_id)['reserved'],'0')
    def test_record_failure_returns_no_success_and_no_reexecute(self):
        message=self.message()
        with patch.object(self.config._reserved_ledger,'complete',side_effect=OSError('disk full')):
            result=handle_infer(self.config,message)
        self.assertEqual(result['execution_status'],'unknown',result)
        self.assertFalse(handle_infer(self.config,self.sign(message))['ok']);self.assertEqual(self.gateway.call_count,1)
    def test_anchor_failure_never_runs_model_and_reports_unknown(self):
        with patch.object(self.config._reserved_ledger,'_write_anchor',side_effect=OSError('disk full')):
            result=handle_infer(self.config,self.message())
        self.assertEqual(result['execution_status'],'unknown',result);self.gateway.assert_not_called()
    def test_v10_transport_identity_proof_binds_receipt_signer(self):
        from gateway.p2p import provider_descriptor
        from gateway.provider_identity_binding import build_provider_identity_binding, verify_provider_identity_binding
        peer={**provider_descriptor(self.config),'challenge':'challenge-123'}
        peer['settlement_identity_binding']=build_provider_identity_binding(peer,audience='relay',private_key=self.old.provider_key)
        self.assertEqual(verify_provider_identity_binding(peer,audience='relay'),self.old.provider_signer)
        peer['settlement']['version']=9
        with self.assertRaisesRegex(ValueError,'signature mismatch'):
            verify_provider_identity_binding(peer,audience='relay')
    def test_independent_submit_cli_is_dry_run_until_send(self):
        from gateway.reserved_execution import submit_execution_outbox
        response=handle_infer(self.config,self.message());self.assertTrue(response['ok'],response)
        with patch('gateway.session_relayer.RelaySettlementSubmitter') as submitter:
            result=submit_execution_outbox(self.config._reserved_ledger.outbox(),rpc_url='http://fixture',
                contract=self.old.contract,chain_id=11155111)
            self.assertFalse(result['broadcast']);self.assertEqual(result['prepared'],1)
            submitter.assert_not_called()
            instance=submitter.return_value;instance.process_once.return_value=1
            sent=submit_execution_outbox(self.config._reserved_ledger.outbox(),rpc_url='http://fixture',
                contract=self.old.contract,chain_id=11155111,send=True,
                transaction_identity=self.config.evm_identity_path,submission_outbox=str(self.directory/'submission.sqlite3'))
            self.assertTrue(sent['submission_attempted']);self.assertEqual(sent['processed'],1)
            instance.enqueue.assert_called_once();instance.process_once.assert_called_once_with(force=False)
    def test_config_requires_initialized_ledger_and_capability_is_explicit(self):
        capabilities=provider_runtime_capabilities(self.config);cap=capabilities['payment_key_settlement']
        self.assertEqual(cap['version'],10);self.assertTrue(cap['pre_execution_relay_dispatch'])
        jury_cap=capabilities['provider_jury']
        self.assertEqual(jury_cap['provider_owner'],self.old.provider_address)
        self.assertEqual(jury_cap['vote_signer'],self.old.provider_signer)
        self.assertEqual(jury_cap['operator_id'],'fixture-operator')
        self.assertEqual(jury_cap['capability']['models'],list(self.config.models))
        self.config._reserved_ledger.close();self.db.unlink()
        with self.assertRaisesRegex(P2PError,'journal'):replace(self.config)

    def test_dynamic_jury_endpoint_checks_chain_signs_and_replays_cached_verdict(self):
        task=self.jury_task();message=self.jury_message(task)
        self.gateway.return_value={'output_text':json.dumps({'confirmed':True,'confidence_bps':9000,
            'reason_code':'signed_mismatch','reasoning':'The canonical signed artifacts conflict.'})}
        with ExitStack() as stack:
            for context in self.jury_chain(task):stack.enter_context(context)
            first=handle_message(self.config,message);second=handle_message(self.config,message)
        self.assertTrue(first['ok'],first);self.assertFalse(first['cached'])
        self.assertTrue(second['ok'],second);self.assertTrue(second['cached'])
        self.assertEqual(self.gateway.call_count,1)
        verified=provider_jury.verify_provider_verdict(first['verdict'],task=task,now=self.old.now+1)
        self.assertEqual(verified['vote_permit']['nonce'],3)
        body=self.gateway.call_args.args[3]
        self.assertEqual(body['instructions'],self.jury_system_prompt)
        self.assertEqual(body['text']['format']['type'],'json_schema')

    def test_dynamic_jury_endpoint_rejects_noncanonical_assignment_before_model(self):
        task=self.jury_task();message=self.jury_message(task)
        with ExitStack() as stack:
            contexts=self.jury_chain(task)
            for context in contexts:stack.enter_context(context)
            with patch('gateway.chain_v10.jury_assignment_hash',return_value=digest(99)):
                result=handle_message(self.config,message)
        self.assertFalse(result['ok']);self.assertIn('canonical',result['error'])
        self.gateway.assert_not_called()

    def test_dynamic_jury_rejects_committed_but_tampered_request_artifact(self):
        task=self.jury_task()
        document=json.loads(json.dumps(task['inference_request']['evidence_document']))
        document['request']['input']='attacker-selected request'
        committed=provider_jury.evidence_hash(document)
        reporter=document['reporter']
        evidence={**task['evidence'],'evidence_hash':committed,
            'report_id':chain_v10.report_id_for(task['settlement_key'],reporter,committed)}
        tampered=provider_jury.build_jury_task(
            network_id=task['network_id'],chain_id=task['chain_id'],
            settlement_contract=task['settlement_contract'],jury_registry=task['jury_registry'],
            settlement_key=task['settlement_key'],assignment_hash=task['assignment_hash'],
            selected_provider=task['selected_provider'],evidence=evidence,
            decision_policy_hash=task['decision_policy_hash'],
            inference_request={**task['inference_request'],'evidence_document':document},
            relay_identity=self.old.relay_identity,issued_at=self.old.now,
            deadline=self.old.now+300,nonce=digest(76))
        with ExitStack() as stack:
            for context in self.jury_chain(tampered):stack.enter_context(context)
            result=handle_message(self.config,self.jury_message(tampered))
        self.assertFalse(result['ok'])
        self.assertIn('request_hash',result['error'])
        self.gateway.assert_not_called()

    def test_dynamic_jury_uses_evidence_origin_not_assignment_hash_coordinator(self):
        from gateway.identity import create_identity

        second = create_identity()
        pins = {self.old.relay_identity.public_key, second.public_key}
        self.config.jury_relay_public_keys = pins
        task = self.jury_task(assignment_hash=digest(100))
        self.gateway.return_value={'output_text':json.dumps({'confirmed':False,
            'confidence_bps':9000,'reason_code':'no_agreed_fraud',
            'reasoning':'The complete signed evidence affirmatively excludes every agreed fraud condition.'})}
        with ExitStack() as stack:
            for context in self.jury_chain(task):stack.enter_context(context)
            result = handle_message(self.config, self.jury_message(task))
        self.assertTrue(result['ok'],result)
        self.assertEqual(
            task['inference_request']['evidence_document']['origin_relay_public_key'],
            self.old.relay_identity.public_key)
        self.assertEqual(self.gateway.call_count,1)

    def test_dynamic_jury_malformed_output_can_retry_but_timeout_is_fenced(self):
        task=self.jury_task();message=self.jury_message(task)
        with ExitStack() as stack:
            for context in self.jury_chain(task):stack.enter_context(context)
            self.gateway.return_value={'output_text':'not json'}
            malformed=handle_message(self.config,message)
            self.gateway.return_value={'output_text':json.dumps({'confirmed':False,'confidence_bps':9000,
                'reason_code':'no_agreed_fraud',
                'reasoning':'The complete signed evidence affirmatively excludes every agreed fraud condition.'})}
            retried=handle_message(self.config,message)
        self.assertFalse(malformed['ok']);self.assertTrue(retried['ok'],retried)
        # A different assignment isolates the ambiguity fence from the completed first task.
        uncertain_task=self.jury_task(assignment_hash=digest(91));uncertain_message=self.jury_message(uncertain_task)
        self.gateway.reset_mock();self.gateway.side_effect=TimeoutError('ambiguous upstream timeout')
        with ExitStack() as stack:
            for context in self.jury_chain(uncertain_task):stack.enter_context(context)
            uncertain=handle_message(self.config,uncertain_message)
            again=handle_message(self.config,uncertain_message)
        self.assertFalse(uncertain['ok']);self.assertFalse(again['ok'])
        self.assertIn('uncertain',again['error']);self.assertEqual(self.gateway.call_count,1)

if __name__=='__main__':unittest.main()
