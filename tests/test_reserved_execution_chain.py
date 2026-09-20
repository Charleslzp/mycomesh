from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
import unittest
from unittest.mock import patch
from gateway.chain import ChainError, abi_encode_arg
from gateway.chain_v10 import OPEN_FIELDS, channel_id_for
from gateway.reserved_execution import confirmed_channel_snapshot, ReservedExecutionError

class ConfirmedChannelTests(unittest.TestCase):
    def setUp(self):
        self.contract='0x'+'aa'*20
        self.config={name:'0x'+format(n,'040x') for n,name in enumerate(('consumer_owner','consumer_key','provider_owner','provider_signer','relay','relay_signer','pool'),1)}
        self.config.update(channel='0x'+'bb'*32,pricing_version=1,pricing_hash='0x'+'cc'*32,
            capacity=100,max_fee_per_request=10,valid_from=2000,admit_until=9000,claim_until=10000,
            consumer_nonce=0,provider_nonce=0,permit_deadline=1500)
        self.channel_id=channel_id_for(self.config,chain_id=11155111,settlement_contract=self.contract)
        self.head={'number':'0x10','timestamp':hex(1000),'hash':'0x'+'11'*32}
        self.block={'number':'0xa','timestamp':hex(928),'hash':'0x'+'22'*32}
        self.channel={**self.config,'closed':False,'settled_max_fee':0,'credit_remaining':100,'stake_remaining':100}
    def read(self, **kwargs):
        return confirmed_channel_snapshot('http://fixture',self.contract,self.channel_id,chain_id=11155111,now=1000,**kwargs)

    @contextmanager
    def rpc_fixture(self, delay):
        calls=[]
        encoded='0x'+b''.join(abi_encode_arg(str(self.channel[name])) for name,_ in OPEN_FIELDS).hex()
        encoded+=''.join(format(v,'064x') for v in (0,100,100,0))
        head,block=self.head,self.block
        class Handler(BaseHTTPRequestHandler):
            def do_POST(inner):
                payload=json.loads(inner.rfile.read(int(inner.headers['Content-Length'])))
                calls.append(payload)
                method=payload['method']
                if method=='eth_chainId':result=hex(11155111)
                elif method=='eth_call':result=encoded
                else:result=head if payload['params'][0]=='latest' else block
                time.sleep(delay)
                body=json.dumps({'jsonrpc':'2.0','id':payload['id'],'result':result}).encode()
                try:
                    inner.send_response(200);inner.send_header('Content-Type','application/json')
                    inner.send_header('Content-Length',str(len(body)));inner.end_headers();inner.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.01},daemon=True)
        thread.start()
        try:yield 'http://127.0.0.1:'+str(server.server_address[1]),calls
        finally:server.shutdown();server.server_close();thread.join(timeout=2)

    def test_whole_snapshot_shares_budget_and_accepts_a_read_slower_than_three_seconds(self):
        clock=[100.0];seen=[];replies=iter([self.head,self.block,self.block]);durations=iter([4.0,1.0,0.5])
        def rpc_int(url,method,params,timeout):
            seen.append(timeout);clock[0]+=0.5;return 11155111
        def rpc_call(url,method,params,timeout):
            seen.append(timeout);clock[0]+=next(durations);return next(replies)
        def info(*args,timeout,block_tag):
            seen.append(timeout);clock[0]+=2
            self.assertEqual(block_tag,{'blockHash':self.block['hash'],'requireCanonical':True})
            return self.channel
        with patch('gateway.reserved_execution.time.monotonic',side_effect=lambda:clock[0]), \
             patch('gateway.chain.rpc_int',side_effect=rpc_int),patch('gateway.chain.rpc_call',side_effect=rpc_call), \
             patch('gateway.chain_v10.channel_info',side_effect=info):
            self.assertEqual(self.read(timeout=15,deadline=115)['block_hash'],self.block['hash'])
        self.assertEqual(seen,[15,14.5,10.5,9.5,7.5])

    def test_no_deadline_retains_existing_per_rpc_timeout(self):
        with patch('gateway.chain.rpc_int',return_value=11155111) as chain, \
             patch('gateway.chain.rpc_call',side_effect=[self.head,self.block,self.block]) as rpc, \
             patch('gateway.chain_v10.channel_info',return_value=self.channel) as info:
            self.read(timeout=3)
        self.assertEqual(chain.call_args.args[3],3)
        self.assertTrue(all(call.args[3]==3 for call in rpc.call_args_list))
        self.assertEqual(info.call_args.kwargs['timeout'],3)

    def test_expired_or_invalid_deadline_starts_no_rpc(self):
        with patch('gateway.reserved_execution.time.monotonic',return_value=100),patch('gateway.chain.rpc_int') as rpc:
            for deadline in (99,100,float('nan'),float('inf'),True,'100'):
                with self.subTest(deadline=deadline),self.assertRaisesRegex(ReservedExecutionError,'deadline'):
                    self.read(deadline=deadline)
            rpc.assert_not_called()

    def test_exhausted_budget_cannot_start_later_rpc_or_return_late_snapshot(self):
        for expired_after in ('head','final'):
            clock=[100.0]
            replies=iter([self.head,self.block,self.block])
            calls=[]
            def rpc_call(url,method,params,timeout):
                calls.append(params)
                if (expired_after=='head' or len(calls)==3):clock[0]=115
                return next(replies)
            with patch('gateway.reserved_execution.time.monotonic',side_effect=lambda:clock[0]), \
                 patch('gateway.chain.rpc_int',return_value=11155111),patch('gateway.chain.rpc_call',side_effect=rpc_call), \
                 patch('gateway.chain_v10.channel_info',return_value=self.channel) as info:
                with self.subTest(expired_after=expired_after),self.assertRaisesRegex(ReservedExecutionError,'deadline exceeded'):
                    self.read(timeout=15,deadline=115)
                self.assertEqual(len(calls),1 if expired_after=='head' else 3)
                self.assertEqual(info.call_count,0 if expired_after=='head' else 1)

    def test_real_rpc_read_keeps_canonical_block_under_one_deadline(self):
        with self.rpc_fixture(0.015) as (url,calls):
            result=confirmed_channel_snapshot(url,self.contract,self.channel_id,chain_id=11155111,now=1000,
                timeout=1,deadline=time.monotonic()+1)
        self.assertEqual(result['block_hash'],self.block['hash'])
        self.assertEqual(len(calls),5)
        self.assertEqual(calls[3]['params'][1],{'blockHash':self.block['hash'],'requireCanonical':True})

    def test_real_rpc_timeout_is_total_not_reset_for_each_read(self):
        with self.rpc_fixture(0.07) as (url,calls):
            started=time.monotonic()
            with self.assertRaises((ChainError,ReservedExecutionError)):
                confirmed_channel_snapshot(url,self.contract,self.channel_id,chain_id=11155111,now=1000,
                    timeout=1,deadline=started+0.20)
            elapsed=time.monotonic()-started
        self.assertLess(elapsed,0.5)
        self.assertLess(len(calls),5)
    def test_all_channel_reads_pin_the_same_canonical_confirmed_hash(self):
        with patch('gateway.chain.rpc_int',return_value=11155111), patch('gateway.chain.rpc_call',side_effect=[self.head,self.block,self.block]), patch('gateway.chain_v10.channel_info',return_value=self.channel) as info:
            snapshot=self.read()
        self.assertEqual(snapshot['block_number'],10)
        self.assertEqual(info.call_args.kwargs['block_tag'],{'blockHash':self.block['hash'],'requireCanonical':True})
    def test_reorg_between_channel_read_and_confirmation_is_rejected(self):
        changed={**self.block,'hash':'0x'+'33'*32}
        with patch('gateway.chain.rpc_int',return_value=11155111), patch('gateway.chain.rpc_call',side_effect=[self.head,self.block,changed]), patch('gateway.chain_v10.channel_info',return_value=self.channel):
            with self.assertRaisesRegex(ReservedExecutionError,'changed'):self.read()
    def test_wrong_chain_rejected_before_state_read(self):
        with patch('gateway.chain.rpc_int',return_value=1), patch('gateway.chain_v10.channel_info') as info:
            with self.assertRaisesRegex(ReservedExecutionError,'chain ID'):self.read()
            info.assert_not_called()
    def test_stale_clock_and_insufficient_confirmations_rejected(self):
        for changed in ({**self.head,'timestamp':hex(600)},{**self.head,'number':'0x5'}):
            with patch('gateway.chain.rpc_int',return_value=11155111),patch('gateway.chain.rpc_call',return_value=changed):
                with self.assertRaises(ReservedExecutionError):self.read()
    def test_untrusted_channel_binding_rejected(self):
        with patch('gateway.chain.rpc_int',return_value=11155111), patch('gateway.chain.rpc_call',side_effect=[self.head,self.block,self.block]),patch('gateway.chain_v10.channel_info',return_value={**self.channel,'capacity':200}):
            with self.assertRaisesRegex(ReservedExecutionError,'bindings mismatch'):self.read()
    def test_missing_eip1898_support_is_not_downgraded_to_latest(self):
        with patch('gateway.chain.rpc_int',return_value=11155111),patch('gateway.chain.rpc_call',side_effect=[self.head,self.block]),patch('gateway.chain_v10.channel_info',side_effect=ChainError('unsupported EIP-1898')) as info:
            with self.assertRaises(ChainError):self.read()
            self.assertEqual(info.call_count,1)

if __name__=='__main__':unittest.main()
