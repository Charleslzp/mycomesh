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
    def test_channel_duration_getter_is_manifest_bound(self):
        word=f'{v.MAX_CHANNEL_DURATION:064x}'
        with patch.object(chain_v9,'_read',return_value=[word]):
            self.assertEqual(v.max_channel_duration('rpc',self.contract,expected=v.MAX_CHANNEL_DURATION),v.MAX_CHANNEL_DURATION)
            with self.assertRaises(ChainError):v.max_channel_duration('rpc',self.contract,expected=v.LEGACY_MAX_CHANNEL_DURATION)
    def test_settlement_key_scoped_to_channel(self):
        self.assertNotEqual(v.settlement_key_for(self.id,digest(1)),v.settlement_key_for(digest(50),digest(1)))

if __name__=='__main__':unittest.main()
