"""Local fallback schedule only: synthetic receipts, mocked processing; no RPC or broadcast."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from gateway.reserved_execution import submit_execution_outbox, ReservedExecutionError
from gateway.session_relayer import PreparedRelaySettlement, RelaySettlementOutbox

class ReservedSubmissionScheduleTests(unittest.TestCase):
    def setUp(self):
        self.now=1_800_000_000
        self.started=self.now
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name).resolve()/'submission.sqlite3'
        self.contract='0x'+'11'*20;self.channel='0x'+'22'*32;self.key='0x'+'33'*20
        self.processed=[]
        patches=[
            patch('gateway.session_relayer.time.time',side_effect=lambda:self.now),
            patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value={}),
            patch('gateway.provider_bootstrap.load_provider_evm_identity',return_value=SimpleNamespace(private_key='0x'+'44'*32,address='0x'+'55'*20)),
            patch('gateway.v10_relayer.prepare_v10_relay_settlement',side_effect=self.prepare),
            patch('gateway.session_relayer.RelaySettlementSubmitter._process',autospec=True,side_effect=self.process),
            patch('gateway.session_relayer.rpc_call',side_effect=AssertionError('No real RPC allowed'))]
        for p in patches:p.start();self.addCleanup(p.stop)
    def rows(self,count):
        return [{'contract':self.contract,'channel_id':self.channel,'request_id':'0x'+format(i,'064x'),
            'signed_receipt':{'chain_id':11155111,'index':i,'deadline':self.started+20000}} for i in range(1,count+1)]
    def prepare(self,receipt,**_):
        i=receipt['index'];rid='0x'+format(i,'064x')
        return PreparedRelaySettlement(key=f'v10:fixture:{i}',session_id=rid,receipt_hash='0x'+'66'*32,
            sequence=0,chain_id=11155111,settlement_contract=self.contract,calldata='0x1234',
            payload={'protocol_version':10,'tuple_data':'0x1234','signed_receipt':{
                'authorization':{'authorization':{'key':self.key,'deadline':receipt['deadline']}},'receipt':{'actual_fee':1}}})
    def process(self,worker,items):
        self.processed.append(len(items))
        worker.outbox.mark_confirmed_many([row['settlement_key'] for row in items])
    def poll(self,rows,**options):
        return submit_execution_outbox(rows,rpc_url='http://fixture.invalid',contract=self.contract,chain_id=11155111,
            send=True,transaction_identity='fixture-only',submission_outbox=str(self.path),**options)
    def test_minute_poll_does_not_force_or_reset_two_hour_schedule(self):
        rows=self.rows(1)
        for minute in range(120):
            self.now=self.started+60*minute
            self.assertEqual(self.poll(rows)['processed'],0)
        self.assertEqual(self.processed,[])
        schedule=RelaySettlementOutbox(self.path).batching_schedule(interval_seconds=7200,count_threshold=100,deadline_margin_seconds=300,now=self.now)
        self.assertEqual(schedule['oldest_pending_at'],self.started)
        self.assertEqual(schedule['next_trigger_at'],self.started+7200)
        self.now=self.started+7200
        self.assertEqual(self.poll(rows)['processed'],1)
    def test_99_does_not_flush_then_100_drains_durably_even_across_new_workers(self):
        self.assertEqual(self.poll(self.rows(99),batch_size=32)['processed'],0)
        self.now+=60
        self.assertEqual(self.poll(self.rows(99),batch_size=32)['processed'],0)
        self.now+=60
        for expected in (32,32,32,4):
            self.assertEqual(self.poll(self.rows(100),batch_size=32)['processed'],expected)
            self.now+=60
        self.assertEqual(self.processed,[32,32,32,4])
        self.assertEqual(self.poll(self.rows(100))['processed'],0)
    def test_force_is_explicit_and_default_provider_batch_is_two(self):
        self.assertEqual(self.poll(self.rows(3))['processed'],0)
        self.assertEqual(self.poll(self.rows(3),force=True)['processed'],2)
        self.assertEqual(self.processed,[2])
    def test_invalid_batch_sizes_cannot_bypass_bounds(self):
        for size in (0,33,True,2.5):
            with self.assertRaisesRegex(ReservedExecutionError,'batch_size'):self.poll([],batch_size=size)

if __name__=='__main__':unittest.main()
