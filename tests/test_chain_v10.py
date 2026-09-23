from __future__ import annotations
import copy
import time
import unittest
from unittest.mock import patch
from gateway import chain_v10 as v, chain_v9
from gateway.chain import ChainError, abi_encode_arg, keccak256
from tests.test_chain_v9 import key, signer, address, digest, deployment_manifest


def config(now=None, **changes):
    now=int(time.time()) if now is None else now
    return dict(consumer_owner=signer(21),consumer_key=signer(1),provider_owner=signer(22),provider_signer=signer(2),relay=signer(3),relay_signer=signer(3),pool=address(90),channel=digest(101),pricing_version=1,pricing_hash=digest(102),capacity=20000,max_fee_per_request=10000,valid_from=now-10,admit_until=now+6000,claim_until=now+15000,consumer_nonce=0,provider_nonce=0,permit_deadline=now+100,**changes)

class ChainV10Tests(unittest.TestCase):
    def setUp(self):
        self.now=int(time.time());self.c=config(self.now);self.contract=address(50)
        self.id=v.channel_id_for(self.c,chain_id=31337,verifying_contract=self.contract)
        self.channel={**self.c,'channel_id':self.id,'credit_remaining':20000,'stake_remaining':20000,'settled_max_fee':0,'closed':False}
    def auth(self,**changes):
        args=dict(payment_key=key(1),chain_id=31337,settlement_contract=self.contract,channel_id=self.id,request_id=digest(1),request_hash=digest(2),max_fee=10000,issued_at=self.now,execute_by=self.now+300,deadline=self.now+9000);args.update(changes);return v.build_authorization(**args)
    def signed(self):
        d=v.build_relay_dispatch(authorization_payload=self.auth(),relay_private_key=key(3))
        return v.build_provider_receipt(provider_private_key=key(2),dispatch_payload=d,response_hash=digest(3),input_tokens=100,output_tokens=100,actual_fee=2000,channel=self.channel)
    def vote(self, assignment_hash=None, **changes):
        args=dict(settlement_key=digest(201),assignment_hash=assignment_hash or digest(202),confirmed=True,
                  report_id=digest(203),decision_hash=digest(204),nonce=7,deadline=self.now+300,
                  judge_private_key=key(4),chain_id=31337,settlement_contract=self.contract)
        args.update(changes)
        return v.build_dispute_vote(**args)
    def dynamic_manifest(self, **changes):
        genesis_hash=digest(77)
        history={
            'schema':v.REPUTATION_HISTORY_SCHEMA,
            'source_network_id':'mycomesh-v9-prior',
            'source_protocol_version':9,
            'source_chain_id':31337,
            'source_genesis_hash':genesis_hash,
            'source_settlement_contract':address(69),
            'source_runtime_code_hash':digest(78),
            'source_deployment_block':90,
            'source_deployment_block_hash':digest(74),
            'source_history_through_block':99,
            'source_history_through_block_hash':digest(75),
            'confirmations':6,
            'artifact_sha256':'7a'*32,
            'artifact_root':digest(76),
        }
        value={**deployment_manifest(),'protocol_version':10,'eip712_version':'10',
               'reservation_mode':v.RESERVATION_MODE,'chain_domain':'10',
               'max_authorization_ttl_seconds':10800,'authorization_deadline_seconds':9000,
               'max_channel_duration_seconds':v.MAX_CHANNEL_DURATION,
               'committee_mode':v.DYNAMIC_PROVIDER_JURY,'jury_registry':address(70),
               'reputation_authority':address(72),
               'minimum_provider_reputation':80,'jury_size':3,'adjudication_threshold':2,
               'jury_selection_delay_blocks':2,'jury_randomness':v.JURY_RANDOMNESS,
               'jury_decision_policy_hash':digest(79),'genesis_hash':genesis_hash,
               'deployment_block':100,'deployment_block_hash':digest(80),
               'settlement_runtime_code_keccak256':digest(81),
               v.REPUTATION_HISTORY_FIELD:history}
        value['jury_registry_governance']=value['governance']
        for name in ('adjudicators','adjudicator_operators','independence_attested'):
            value.pop(name,None)
        value.update(changes)
        return value
    def test_roundtrip_and_batch_encoding(self):
        r=self.signed();a,receipt,sigs=v.verify_signed_receipt(r,channel=self.channel)
        self.assertEqual(receipt.actual_fee,2000);self.assertEqual(len(sigs),3)
        self.assertEqual(v.encode_signed_batch([r]),v.encode_signed_batch_tuples([v.encode_signed_receipt_tuple(r)]))
        self.assertTrue(v.encode_signed_receipt(r).startswith('0x'+keccak256(v.SETTLE_SIGNATURE.encode())[:4].hex()))
    def test_domain_distinct_from_v9_and_other_chain(self):
        self.assertNotEqual(v.domain_separator(chain_id=31337,verifying_contract=self.contract),chain_v9.domain_separator(chain_id=31337,verifying_contract=self.contract))
        a=self.auth();a['chain_id']=1
        with self.assertRaises(ChainError):v.verify_authorization(a)
    def test_dispatch_is_preexecution_not_usage_signature(self):
        r=self.signed();r['relay_signature']=r['provider_signature']
        with self.assertRaises(ChainError):v.verify_signed_receipt(r)
    def test_channel_bound_provider_and_relay(self):
        r=self.signed()
        for name in ('provider_signer','relay_signer'):
            with self.subTest(name=name):
                c={**self.channel,name:signer(4)}
                with self.assertRaises(ChainError):v.verify_signed_receipt(r,channel=c)
    def test_channel_hash_rejects_changed_pricing_or_budget(self):
        for name,new in [('capacity',30000),('pricing_hash',digest(103)),('consumer_key',signer(4))]:
            with self.subTest(name=name):
                with self.assertRaises(ChainError):v.validate_channel_authorization({**self.channel,name:new},self.auth())
    def test_execution_window_separate_from_settlement(self):
        a=self.auth(execute_by=self.now+1)
        with self.assertRaises(ChainError):v.validate_channel_authorization(self.channel,a,now=self.now+2)
        v.validate_channel_authorization(self.channel,a,now=self.now+2,for_execution=False)
    def test_bools_floats_zero_and_long_ttl_rejected(self):
        for value in (True,1.2,0,-1):
            with self.assertRaises(ChainError):self.auth(max_fee=value)
        with self.assertRaises(ChainError):self.auth(deadline=self.now+10801)
    def test_high_s_and_payload_tamper(self):
        a=self.auth();a['key_signature']='0x'+('01'*32)+('ff'*32)+'1b'
        with self.assertRaises(ChainError):v.verify_authorization(a)
        r=self.signed();r['receipt']['output_tokens']=200
        with self.assertRaises(ChainError):v.verify_signed_receipt(r)
    def test_expired_auth_and_closed_channel(self):
        with self.assertRaises(ChainError):v.verify_authorization(self.auth(),now=self.now+9001)
        with self.assertRaises(ChainError):v.validate_channel_authorization({**self.channel,'closed':True},self.auth())
    def test_channel_permits_two_owners_and_domain(self):
        p=v.build_channel_permit(config=self.c,consumer_private_key=key(21),provider_private_key=key(22),chain_id=31337,settlement_contract=self.contract)
        self.assertEqual(v.verify_channel_permit(p).capacity,20000)
        future={**self.c,'valid_from':self.now+10}
        open_permit=v.build_channel_permit(config=future,consumer_private_key=key(21),provider_private_key=key(22),chain_id=31337,settlement_contract=self.contract)
        self.assertTrue(v.encode_open_capacity_channels([open_permit],now=self.now,max_channel_duration=v.MAX_CHANNEL_DURATION).startswith('0x'+keccak256(v.OPEN_SIGNATURE.encode())[:4].hex()))
        bad=copy.deepcopy(p);bad['config']['provider_nonce']=1
        with self.assertRaises(ChainError):v.verify_channel_permit(bad)
        bad=copy.deepcopy(p);bad['consumer_signature']=bad['provider_signature']
        with self.assertRaises(ChainError):v.verify_channel_permit(bad)
    def test_open_encoding_uses_contract_duration_semantics(self):
        safe={**self.c,'valid_from':self.now+600,'admit_until':self.now+20*86400,
              'claim_until':self.now+v.MAX_CHANNEL_DURATION}
        permit=v.build_channel_permit(config=safe,consumer_private_key=key(21),provider_private_key=key(22),chain_id=31337,settlement_contract=self.contract)
        v.encode_open_capacity_channels([permit],now=self.now,max_channel_duration=v.MAX_CHANNEL_DURATION)
        unsafe={**safe,'claim_until':safe['valid_from']+v.MAX_CHANNEL_DURATION}
        permit=v.build_channel_permit(config=unsafe,consumer_private_key=key(21),provider_private_key=key(22),chain_id=31337,settlement_contract=self.contract)
        with self.assertRaises(ChainError):v.encode_open_capacity_channels([permit],now=self.now,max_channel_duration=v.MAX_CHANNEL_DURATION)
    def test_batch_bounds(self):
        for values in ([],[b'']*33):
            with self.assertRaises(ChainError):v.encode_signed_batch_tuples(values)
    def test_channel_read_and_stake_include_allocation(self):
        vals=[self.c[n] for n,_ in v.OPEN_FIELDS]+[0,20000,20000,0]
        words=[abi_encode_arg(str(x)).hex() for x in vals]
        with patch.object(chain_v9,'_read',return_value=words):self.assertEqual(v.capacity_channel('rpc',self.contract,self.id)['capacity'],20000)
        with patch.object(chain_v9,'provider_stake_status',return_value={'stake':100,'locked':30,'available':70}),patch.object(chain_v9,'_read',return_value=[f'{40:064x}']):
            self.assertEqual(v.provider_stake_status('rpc',self.contract,signer(22),block_tag='0x1')['available'],30)
    def test_manifest_requires_new_domain_and_mode(self):
        m={**deployment_manifest(),'protocol_version':10,'eip712_version':'10','reservation_mode':v.RESERVATION_MODE,'chain_domain':'10','max_authorization_ttl_seconds':10800,'authorization_deadline_seconds':9000,'max_channel_duration_seconds':v.MAX_CHANNEL_DURATION}
        self.assertEqual(v.validate_deployment(m).protocol_version,10)
        self.assertEqual(v.validate_deployment({**m,'max_channel_duration_seconds':v.LEGACY_MAX_CHANNEL_DURATION}).max_channel_duration_seconds,v.LEGACY_MAX_CHANNEL_DURATION)
        for change in ({'reservation_mode':'unreserved'},{'eip712_version':'9'},{'max_authorization_ttl_seconds':3600},{'max_channel_duration_seconds':86400}):
            with self.assertRaises(ChainError):v.validate_deployment({**m,**change})
    def test_dynamic_provider_jury_manifest_is_not_a_fixed_roster(self):
        manifest=self.dynamic_manifest()
        config=v.validate_deployment(manifest)
        self.assertEqual(config.committee_mode,v.DYNAMIC_PROVIDER_JURY)
        self.assertEqual(config.jury_registry,address(70))
        self.assertEqual(config.jury_decision_policy_hash,digest(79))
        self.assertEqual(config.genesis_hash,digest(77))
        self.assertEqual(config.deployment_block,100)
        self.assertEqual(config.deployment_block_hash,digest(80))
        self.assertEqual(config.settlement_runtime_code_keccak256,digest(81))
        self.assertEqual(config.reputation_history_import,
                         manifest[v.REPUTATION_HISTORY_FIELD])
        self.assertEqual(config.adjudicators,())
        self.assertFalse(config.independence_attested)
        self.assertNotIn('adjudicators',config.to_dict())
        self.assertNotIn('jury_provider_evidence',config.to_dict())
        for change in (
            {'jury_randomness':'relay_random'}, {'jury_size':2}, {'adjudication_threshold':1},
            {'jury_selection_delay_blocks':65}, {'minimum_provider_reputation':0},
            {'jury_decision_policy_hash':digest(0)},
            {'jury_decision_policy_hash':digest(79).upper()},
            {'deployment_block':0}, {'deployment_block_hash':digest(0)},
            {'deployment_block_hash':digest(80).upper()},
            {'settlement_runtime_code_keccak256':digest(0)},
            {'settlement_runtime_code_keccak256':digest(81).upper()},
            {'jury_registry_governance':address(73)}, {'reputation_authority':address(70)},
            {'independence_attested':True},
            {v.REPUTATION_HISTORY_FIELD:None},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'unexpected':True}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'source_chain_id':1}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'source_genesis_hash':digest(75)}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'source_settlement_contract':manifest['settlement']}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'confirmations':1}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'source_deployment_block':0}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'source_history_through_block':89}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'source_history_through_block_hash':digest(0)}},
            {v.REPUTATION_HISTORY_FIELD:{**manifest[v.REPUTATION_HISTORY_FIELD],
                                         'artifact_sha256':'AA'*32}},
        ):
            with self.subTest(change=change),self.assertRaises(ChainError):
                v.validate_deployment(self.dynamic_manifest(**change))
    def test_dynamic_provider_jury_rejects_a_pinned_provider_roster(self):
        prohibited = {
            'adjudicators': [],
            'adjudicator_operators': {},
            'independence_attested': False,
            'jury_provider_evidence': [],
        }
        for name, value in prohibited.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                    ChainError, f'forbidden static committee fields: {name}'):
                v.validate_deployment({**self.dynamic_manifest(), name: value})

    def test_static_v10_rejects_reputation_history_import(self):
        manifest={**deployment_manifest(),'protocol_version':10,'eip712_version':'10',
                  'reservation_mode':v.RESERVATION_MODE,'chain_domain':'10',
                  'max_authorization_ttl_seconds':10800,
                  'authorization_deadline_seconds':9000,
                  'max_channel_duration_seconds':v.MAX_CHANNEL_DURATION,
                  v.REPUTATION_HISTORY_FIELD:None}
        with self.assertRaisesRegex(ChainError,'requires a dynamic'):
            v.validate_deployment(manifest)
    def test_dynamic_provider_jury_runtime_state_is_manifest_bound(self):
        config=v.validate_deployment(self.dynamic_manifest())
        state={'registry':config.jury_registry,'settlement':config.settlement,
               'governance':config.jury_registry_governance,
               'reputation_authority':config.reputation_authority,
               'bond_penalty_recipient':config.policy['bond_penalty_recipient'],
               'minimum_provider_reputation':config.minimum_provider_reputation,
               'jury_size':config.jury_size,'adjudication_threshold':config.adjudication_threshold,
               'jury_selection_delay_blocks':config.jury_selection_delay_blocks,
               'randomness_mode_hash':v.JURY_RANDOMNESS_HASH,
               'roster_version':4,'provider_count':4,
               'providers':(), 'can_form_jury':True}
        with patch.object(chain_v9,'_pinned_block_tag',return_value='0x1'), \
             patch.object(v,'jury_registry_address',return_value=config.jury_registry), \
             patch.object(v,'adjudication_threshold',return_value=2), \
             patch.object(v,'jury_registry_state',return_value=state):
            self.assertTrue(v.validate_dynamic_jury_state('rpc',config)['can_form_jury'])
            with patch.object(v,'jury_registry_state',return_value={**state,'can_form_jury':False}):
                with self.assertRaises(ChainError):v.validate_dynamic_jury_state('rpc',config)
    def test_channel_duration_getter_is_manifest_bound(self):
        word=f'{v.MAX_CHANNEL_DURATION:064x}'
        with patch.object(chain_v9,'_read',return_value=[word]):
            self.assertEqual(v.max_channel_duration('rpc',self.contract,expected=v.MAX_CHANNEL_DURATION),v.MAX_CHANNEL_DURATION)
            with self.assertRaises(ChainError):v.max_channel_duration('rpc',self.contract,expected=v.LEGACY_MAX_CHANNEL_DURATION)
    def test_settlement_key_scoped_to_channel(self):
        self.assertNotEqual(v.settlement_key_for(self.id,digest(1)),v.settlement_key_for(digest(50),digest(1)))
    def test_v10_exports_only_owner_dispute_opening_not_multi_report_submission(self):
        encoded=v.encode_open_dispute(digest(1),digest(2))
        self.assertTrue(encoded.startswith(
            '0x'+keccak256(b'openDispute(bytes32,bytes32)')[:4].hex()))
        self.assertFalse(hasattr(v,'encode_submit_evidence'))
    def test_dispute_vote_assignment_roundtrip_and_mismatch(self):
        permit=self.vote()
        verified=v.verify_dispute_vote(permit,expected_settlement_key=digest(201),
                                       expected_assignment_hash=digest(202),expected_chain_id=31337,
                                       expected_contract=self.contract,expected_judge=signer(4),now=self.now)
        self.assertEqual(verified['assignment_hash'],digest(202))
        with self.assertRaises(ChainError):
            v.verify_dispute_vote(permit,expected_assignment_hash=digest(205),now=self.now)
        changed={**permit,'assignment_hash':digest(205)}
        with self.assertRaises(ChainError):
            v.verify_dispute_vote(changed,expected_judge=signer(4),now=self.now)
    def test_dispute_vote_rejects_zero_assignment(self):
        with self.assertRaises(ChainError):self.vote(assignment_hash=digest(0))
        permit=self.vote();permit['assignment_hash']=digest(0)
        with self.assertRaises(ChainError):v.verify_dispute_vote(permit,now=self.now)
    def test_dispute_vote_type_hash_order_matches_contract(self):
        permit=self.vote()
        expected_type='DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)'
        self.assertEqual(v.VOTE_TYPE,expected_type)
        encoded=(keccak256(expected_type.encode())
                 +b''.join(abi_encode_arg(str(value)) for value in (
                     digest(201),digest(202),True,digest(203),digest(204),7,self.now+300)))
        self.assertEqual(v.dispute_vote_struct_hash(digest(201),permit),
                         '0x'+keccak256(encoded).hex())
    def test_dispute_vote_abi_contains_assignment_and_rejects_mixed_batch(self):
        permit=self.vote()
        raw=bytes.fromhex(v.encode_dispute_vote_by_sig(digest(201),[permit])[2:])
        expected_signature='voteDisputeBySig(bytes32,(bytes32,bool,bytes32,bytes32,uint256,uint64,bytes)[])'
        self.assertEqual(v.VOTE_SIGNATURE,expected_signature)
        self.assertEqual(raw[:4],keccak256(expected_signature.encode())[:4])
        self.assertEqual(raw[4:36],bytes.fromhex(digest(201)[2:]))
        self.assertEqual(int.from_bytes(raw[36:68],'big'),64)
        self.assertEqual(int.from_bytes(raw[68:100],'big'),1)
        self.assertEqual(int.from_bytes(raw[100:132],'big'),32)
        self.assertEqual(raw[132:164],bytes.fromhex(digest(202)[2:]))
        other=self.vote(assignment_hash=digest(205),judge_private_key=key(5))
        with self.assertRaises(ChainError):
            v.encode_dispute_vote_by_sig(digest(201),[permit,other])

    def test_dynamic_assignment_snapshot_and_vote_nonce_reads(self):
        words = [f'{1:064x}', f'{int(address(80),16):064x}', digest(81)[2:],
                 digest(82)[2:], digest(83)[2:], f'{95:064x}']
        with patch.object(v.v9,'_read',side_effect=[words,[digest(84)[2:]],[f'{7:064x}']]) as read:
            provider=v.jury_assignment_provider('rpc',address(70),digest(1),address(71))
            assignment=v.jury_assignment_hash('rpc',address(70),digest(1))
            nonce=v.adjudicator_nonce('rpc',address(72),digest(1),address(71))
        self.assertEqual(provider,{'found':True,'owner':address(80),'operator_id_hash':digest(81),
            'peer_id_hash':digest(82),'capability_hash':digest(83),'reputation':95})
        self.assertEqual(assignment,digest(84));self.assertEqual(nonce,7)
        self.assertIn('assignmentProviderForSigner(bytes32,address)',read.call_args_list[0].args)
        self.assertIn('adjudicatorNonce(bytes32,address)',read.call_args_list[2].args)

if __name__=='__main__':unittest.main()
