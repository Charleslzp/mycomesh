"""Opt-in real V10 EVM tests, ephemeral loopback only and fixture keys only."""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import unittest
from gateway import chain_v10 as v, chain_v9
from gateway.chain import ChainError, abi_encode_arg, call_contract, deploy_contract_transaction, load_artifact_bytecode, rpc_call
from tests.test_chain_v9 import key, signer, digest, address
import tests.test_v9_local_chain as v9_fixture

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.environ.get('RUN_MYCO_V10_LOCAL_CHAIN')=='1','opt-in localhost EVM test')
class V10LocalChainTests(unittest.TestCase):
    _shutdown=classmethod(v9_fixture.V9LocalChainTests._shutdown.__func__)
    receipt=classmethod(v9_fixture.V9LocalChainTests.receipt.__func__)
    send=classmethod(v9_fixture.V9LocalChainTests.send.__func__)
    send_data=classmethod(v9_fixture.V9LocalChainTests.send_data.__func__)
    @classmethod
    def setUpClass(cls):
        hardhat=os.environ.get('MYCOMESH_TEST_HARDHAT_BIN');config=os.environ.get('MYCOMESH_TEST_HARDHAT_CONFIG')
        if not hardhat or not config:raise RuntimeError('explicit temporary Hardhat fixture required')
        artifacts=Path(os.environ['MYCOMESH_TEST_V10_ARTIFACT_ROOT'])
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        cls.rpc=f'http://127.0.0.1:{port}'
        cls.process=subprocess.Popen([hardhat,'node','--hostname','127.0.0.1','--port',str(port),'--network','v9local','--config',config],cwd=Path(config).parent,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.addClassCleanup(cls._shutdown)
        for _ in range(1000):
            try:
                if rpc_call(cls.rpc,'eth_chainId',[],1)=='0x7a69':break
            except (ChainError,OSError):time.sleep(.02)
        else:raise RuntimeError('localhost EVM did not start')
        for n in (1,2,3,10,11,12,20,21,22,23):rpc_call(cls.rpc,'hardhat_setBalance',[signer(n),hex(10**22)],2)
        cls.stable,_=deploy_contract_transaction(cls.rpc,key(20),31337,load_artifact_bytecode(artifacts/'MycoSettlementV9.t.sol/MockExactTokenV9.json'),5)
        cls.channel=digest(101)
        cfg=[1000,4000,2000,8500,300,200,1000,'true'];policy=[60,120,60,100,5000,10000,2000,1000,0,0,0,0,address(99)]
        args=[cls.stable,address(0),address(90),signer(20),cls.channel,*cfg,*policy,28*32,2,3,signer(10),signer(11),signer(12)]
        data=b''.join(abi_encode_arg(str(x)) for x in args)
        cls.contract,_=deploy_contract_transaction(cls.rpc,key(20),31337,load_artifact_bytecode(artifacts/'MycoSettlementV10.sol/MycoSettlementV10.json')+data,10)
        cls.pricing_hash=call_contract(cls.rpc,cls.contract,'channelPricingHash(bytes32,uint64)',[cls.channel,'1'])
        for n,amount in ((21,50000),(22,50000),(23,1000)):
            cls.send(20,cls.stable,'mint(address,uint256)',[signer(n),str(amount)]);cls.send(n,cls.stable,'approve(address,uint256)',[cls.contract,str(amount)])
        cls.send(21,cls.contract,'deposit(uint256)',['50000']);cls.send(21,cls.contract,'registerKey(address,uint256,uint64)',[signer(1),'20000','0'])
        cls.send(22,cls.contract,'depositStake(uint256)',['50000']);cls.send(22,cls.contract,'authorizeProviderSigner(address)',[signer(2)])
        cls.snapshot=rpc_call(cls.rpc,'evm_snapshot',[],2)
    def setUp(self):
        rpc_call(self.rpc,'evm_revert',[self.snapshot],2);type(self).snapshot=rpc_call(self.rpc,'evm_snapshot',[],2)
        self.opened=self.open_channel()
        self.jump(self.opened['valid_from'])
    def now(self):return int(rpc_call(self.rpc,'eth_getBlockByNumber',['latest',False],2)['timestamp'],16)
    def jump(self,timestamp):
        rpc_call(self.rpc,'evm_setNextBlockTimestamp',[timestamp],2);rpc_call(self.rpc,'evm_mine',[],2)
    def open_channel(self):
        now=self.now();cn=int(call_contract(self.rpc,self.contract,'consumerAllocationNonce(address)',[signer(21)]),16);pn=int(call_contract(self.rpc,self.contract,'providerAllocationNonce(address)',[signer(22)]),16)
        c=dict(consumer_owner=signer(21),consumer_key=signer(1),provider_owner=signer(22),provider_signer=signer(2),relay=signer(3),relay_signer=signer(3),pool=address(0),channel=self.channel,pricing_version=1,pricing_hash=self.pricing_hash,capacity=20000,max_fee_per_request=10000,valid_from=now+20,admit_until=now+6000,claim_until=now+15000,consumer_nonce=cn,provider_nonce=pn,permit_deadline=now+100)
        p=v.build_channel_permit(config=c,consumer_private_key=key(21),provider_private_key=key(22),chain_id=31337,settlement_contract=self.contract)
        self.send_data(3,v.encode_open_capacity_channels([p]));return v.capacity_channel(self.rpc,self.contract,p['channel_id'])
    def signed(self,request=1,channel=None):
        c=channel or self.opened;now=self.now()
        a=v.build_authorization(payment_key=key(1),chain_id=31337,settlement_contract=self.contract,channel_id=c['channel_id'],request_id=digest(request),request_hash=digest(1000+request),max_fee=10000,issued_at=now,execute_by=now+300,deadline=now+9000)
        d=v.build_relay_dispatch(authorization_payload=a,relay_private_key=key(3))
        return v.build_provider_receipt(provider_private_key=key(2),dispatch_payload=d,response_hash=digest(2000+request),input_tokens=100,output_tokens=100,actual_fee=2000,channel=c)
    def balance(self):return v.account_balance(self.rpc,self.contract,signer(21))
    def invariant(self):
        liabilities=int(call_contract(self.rpc,self.contract,'stableLiabilities()',[]),16)
        balance=int(call_contract(self.rpc,self.stable,'balanceOf(address)',[self.contract]),16)
        self.assertEqual(liabilities,balance)
        stake=v.provider_stake_status(self.rpc,self.contract,signer(22));self.assertGreaterEqual(stake['available'],0)
    def test_python_hashes_match_solidity_and_contract_fits(self):
        r=self.signed();a=v._auth(r['authorization']['authorization']);receipt=v._receipt(r['receipt'])
        self.assertEqual(call_contract(self.rpc,self.contract,f'authorizationStructHash({v.AUTH_TUPLE})',a.abi_args()),v.authorization_struct_hash(a))
        self.assertEqual(call_contract(self.rpc,self.contract,f'receiptStructHash({v.RECEIPT_TUPLE})',receipt.abi_args()),v.receipt_struct_hash(receipt))
        self.assertEqual(call_contract(self.rpc,self.contract,'dispatchStructHash(bytes32,bytes32)',[r['authorization']['authorization_hash'],self.opened['channel_id']]),r['dispatch']['dispatch_hash'])
        self.assertEqual(call_contract(self.rpc,self.contract,f'channelIdFor({v.OPEN_TUPLE})',v._config(self.opened).abi_args()),self.opened['channel_id'])
        self.assertLessEqual((len(rpc_call(self.rpc,'eth_getCode',[self.contract,'latest'],2))-2)//2,24576)
    def test_provider_can_submit_without_postexecution_relay(self):
        r=self.signed();tx=self.send_data(22,v.encode_signed_receipt(r))
        event=v.parse_receipt_escrowed(next(x for x in tx['logs'] if x['topics'][0]==v.RECEIPT_ESCROWED_TOPIC),expected_contract=self.contract)
        self.assertEqual(event['settlement_key'],v.settlement_key_for(self.opened['channel_id'],digest(1)))
        self.assertEqual(self.balance(),30000)
        self.assertEqual(v.provider_stake_status(self.rpc,self.contract,signer(22))['locked'],2000);self.invariant()
    def test_batch_burns_maxfee_not_actualfee(self):
        self.send_data(3,v.encode_signed_batch([self.signed(1),self.signed(2)]))
        c=v.capacity_channel(self.rpc,self.contract,self.opened['channel_id'])
        self.assertEqual((c['settled_max_fee'],c['credit_remaining']),(20000,16000))
        with self.assertRaises(ChainError):self.send_data(3,v.encode_signed_receipt(self.signed(3)))
        self.invariant()
    def test_revoke_and_withdraw_cannot_steal_prelocked_rights(self):
        r=self.signed();self.send(21,self.contract,'revokeKey(address)',[signer(1)]);self.send(22,self.contract,'revokeProviderSigner(address)',[signer(2)])
        with self.assertRaises(ChainError):self.send(22,self.contract,'withdrawStake(uint256)',['30001'])
        self.send(22,self.contract,'withdrawStake(uint256)',['30000']);self.send_data(22,v.encode_signed_receipt(r));self.invariant()
    def test_different_channels_same_request_id_both_pay(self):
        second=self.open_channel();self.jump(second['valid_from'])
        self.send_data(3,v.encode_signed_batch([self.signed(),self.signed(channel=second)]));self.invariant()
    def test_expired_channel_returns_only_unspent_and_keeps_locked(self):
        self.send_data(3,v.encode_signed_receipt(self.signed()));self.jump(self.opened['claim_until']+1)
        self.send_data(23,v.encode_close_expired_channel(self.opened['channel_id']))
        self.assertEqual(self.balance(),48000);stake=v.provider_stake_status(self.rpc,self.contract,signer(22));self.assertEqual((stake['allocated'],stake['locked']),(0,2000));self.invariant()
    def test_real_dispute_refund_slash_and_bond_claim(self):
        self.send_data(3,v.encode_signed_receipt(self.signed()));sid=v.settlement_key_for(self.opened['channel_id'],digest(1));evidence=digest(900)
        self.send_data(23,chain_v9.encode_open_dispute(sid,evidence));report=v.report_id_for(sid,signer(23),evidence)
        self.jump(v.settlement_info(self.rpc,self.contract,sid)['release_at'])
        for judge in (10,11):self.send_data(judge,chain_v9.encode_vote_dispute(sid,confirmed=True,report_id=report,decision_hash=digest(901)))
        self.send_data(23,chain_v9.encode_claim_dispute_bond(sid,report));self.assertEqual(self.balance(),32000)
        self.assertEqual(v.provider_stake_status(self.rpc,self.contract,signer(22))['stake'],49000);self.invariant()
    def test_unknown_rebroadcast_and_reorg_do_not_double_pay(self):
        data=v.encode_signed_receipt(self.signed());snap=rpc_call(self.rpc,'evm_snapshot',[],2);self.send_data(3,data)
        with self.assertRaises(ChainError):self.send_data(3,data)
        rpc_call(self.rpc,'evm_revert',[snap],2);self.send_data(3,data)
        self.assertEqual(v.capacity_channel(self.rpc,self.contract,self.opened['channel_id'])['settled_max_fee'],10000);self.invariant()

if __name__=='__main__':unittest.main()
