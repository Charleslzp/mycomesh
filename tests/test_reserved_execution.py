import concurrent.futures
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gateway.reserved_execution import ReservedExecutionLedger, ReservedExecutionError

CONTRACT = '0x' + '11'*20
SIGNER = '0x' + '22'*20
CHANNEL = '0x' + '33'*32
HASH = '0x' + '44'*32

def rid(n): return '0x' + format(n, '064x')

class ReservedExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.db, self.anchor = self.base/'ledger.sqlite3', self.base/'anchor.json'
        self.ledger = self.open(create=True)
        self.snapshot = {'config': {'provider_signer':SIGNER, 'capacity':100, 'max_fee_per_request':60,
            'valid_from':1000, 'admit_until':2000, 'claim_until':4000}, 'closed':False,
            'block_timestamp':500, 'settled_max_fee':0, 'credit_remaining':100, 'stake_remaining':100}
        self.ledger.activate(CONTRACT, CHANNEL, self.snapshot, now=500)
    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()
    def open(self, **kw):
        return ReservedExecutionLedger(self.db, anchor_path=self.anchor, provider_signer=SIGNER, **kw)
    def reserve(self, n=1, fee=60, **kw):
        return self.ledger.reserve(CONTRACT,CHANNEL,request_id=rid(n),request_hash=HASH,max_fee=fee,
            authorization={'id':n},dispatch={'id':n},now=1100,**kw)
    def test_atomic_capacity_under_concurrency(self):
        def attempt(n):
            try: return self.reserve(n)['execute']
            except ReservedExecutionError: return False
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(1,9))),1)
        self.assertEqual(self.ledger.channel(CONTRACT,CHANNEL)['reserved'],'60')
    def test_unknown_restart_never_reexecutes_or_refunds(self):
        self.assertTrue(self.reserve()['execute'])
        self.ledger.close(); self.ledger=self.open()
        self.assertEqual(self.reserve()['state'],'unknown')
        self.assertFalse(self.reserve()['execute'])
        with self.assertRaisesRegex(ReservedExecutionError,'exhausted'): self.reserve(2)
    def test_completed_response_and_receipt_durable(self):
        self.reserve()
        receipt={'authorization':{'id':1},'dispatch':{'id':1},'receipt':{'actual_fee':10}}
        self.ledger.complete(CONTRACT,CHANNEL,rid(1),response={'output':'ok'},signed_receipt=receipt,now=1101)
        self.ledger.close(); self.ledger=self.open()
        result=self.reserve()
        self.assertFalse(result['execute']); self.assertEqual(result['response'],{'output':'ok'})
        self.assertEqual(self.ledger.outbox()[0]['signed_receipt'],receipt)
        self.assertEqual(self.ledger.channel(CONTRACT,CHANNEL)['reserved'],'60')
    def test_changed_request_identity_rejected(self):
        self.reserve()
        with self.assertRaisesRegex(ReservedExecutionError,'identity reused'): self.reserve(fee=59)
    def test_partial_loss_cannot_initialize_replacement(self):
        self.reserve(); self.ledger.close(); self.db.unlink()
        with self.assertRaisesRegex(ReservedExecutionError,'recovery'): self.open(create=True)
    def test_all_state_lost_past_channel_rejected(self):
        self.reserve(); self.ledger.close(); self.db.unlink(); self.anchor.unlink()
        self.ledger=self.open(create=True)
        with self.assertRaisesRegex(ReservedExecutionError,'future start'):
            self.ledger.activate(CONTRACT,CHANNEL,self.snapshot,now=1000)
    def test_rollback_database_detected_by_anchor(self):
        old=self.base/'backup'; shutil.copyfile(self.db,old)
        self.reserve(); self.ledger.close(); shutil.copyfile(old,self.db)
        with self.assertRaisesRegex(ReservedExecutionError,'rolled back'): self.open()
    def test_deletion_while_process_running_stops_execution(self):
        self.db.unlink()
        with self.assertRaisesRegex(ReservedExecutionError,'unavailable'): self.reserve()
    def test_second_writer_rejected(self):
        with self.assertRaisesRegex(ReservedExecutionError,'another Provider writer'): self.open()
    def test_anchor_failure_prevents_execution_but_occupies_budget(self):
        with patch.object(self.ledger,'_write_anchor',side_effect=OSError('disk failed')):
            with self.assertRaises(OSError): self.reserve()
        self.ledger.close(); self.ledger=self.open()
        self.assertFalse(self.reserve()['execute'])
    def test_unbacked_and_time_boundary_activation_rejected(self):
        for change in ({'credit_remaining':99},{'stake_remaining':99},{'closed':True},{'settled_max_fee':1}):
            with self.assertRaises(ReservedExecutionError):
                self.ledger.activate(CONTRACT,rid(2),{**self.snapshot,**change},now=500)
        with self.assertRaisesRegex(ReservedExecutionError,'future start'):
            self.ledger.activate(CONTRACT,rid(2),self.snapshot,now=700)
    def test_completion_cannot_change_auth_or_exceed_fee(self):
        self.reserve()
        for receipt in ({'authorization':{'id':2},'dispatch':{'id':1},'receipt':{'actual_fee':1}},
                        {'authorization':{'id':1},'dispatch':{'id':1},'receipt':{'actual_fee':61}}):
            with self.assertRaises(ReservedExecutionError):
                self.ledger.complete(CONTRACT,CHANNEL,rid(1),response={},signed_receipt=receipt,now=1101)
        self.assertEqual(self.ledger.lookup(CONTRACT,CHANNEL,rid(1))['state'],'unknown')

    def test_read_only_snapshot_while_writer_is_running(self):
        from gateway.reserved_execution import read_execution_outbox
        self.reserve()
        receipt={'authorization':{'id':1},'dispatch':{'id':1},'receipt':{'actual_fee':10}}
        self.ledger.complete(CONTRACT,CHANNEL,rid(1),response={'output':'ok'},signed_receipt=receipt,now=1101)
        rows=read_execution_outbox(self.db,anchor_path=self.anchor,provider_signer=SIGNER)
        self.assertEqual(rows[0]['signed_receipt'],receipt)
        self.assertTrue(self.reserve(2,fee=40)['execute'])
    def test_alias_anchor_cannot_bypass_writer_lock(self):
        other=self.base/'copy-anchor.json';shutil.copyfile(self.anchor,other)
        with self.assertRaisesRegex(ReservedExecutionError,'another Provider writer'):
            ReservedExecutionLedger(self.db,anchor_path=other,provider_signer=SIGNER)

    def test_expired_history_is_filtered_before_outbox_limit(self):
        from gateway.reserved_execution import read_execution_outbox
        for n,deadline in ((1,1000),(2,2000)):
            auth={'authorization':{'deadline':deadline}}
            dispatch={'id':n}
            self.ledger.reserve(CONTRACT,CHANNEL,request_id=rid(n),request_hash=HASH,max_fee=40,
                authorization=auth,dispatch=dispatch,now=1100)
            self.ledger.complete(CONTRACT,CHANNEL,rid(n),response={'id':n},signed_receipt={
                'authorization':auth,'dispatch':dispatch,'receipt':{'actual_fee':1}},now=1100+n)
        args=dict(anchor_path=self.anchor,provider_signer=SIGNER,limit=1)
        self.assertEqual(read_execution_outbox(self.db,**args)[0]['request_id'],rid(1))
        self.assertEqual(read_execution_outbox(self.db,unexpired_at=1100,**args)[0]['request_id'],rid(2))
        self.assertEqual(read_execution_outbox(self.db,unexpired_at=2000,**args),[])

    def test_terminal_submission_history_is_filtered_before_outbox_limit(self):
        from gateway.reserved_execution import read_execution_outbox
        from gateway.session_relayer import PreparedRelaySettlement, RelaySettlementOutbox
        for n in (1,2):
            auth={'authorization':{'deadline':3000}}
            dispatch={'id':n}
            self.ledger.reserve(CONTRACT,CHANNEL,request_id=rid(n),request_hash=HASH,max_fee=40,
                authorization=auth,dispatch=dispatch,now=1100)
            self.ledger.complete(CONTRACT,CHANNEL,rid(n),response={'id':n},signed_receipt={
                'chain_id':11155111,'authorization':auth,'dispatch':dispatch,
                'receipt':{'actual_fee':1}},now=1100+n)
        for status in ('escrowed','confirmed','failed','pending','submitted'):
            with self.subTest(status=status):
                outbox=RelaySettlementOutbox(self.base/(status+'.sqlite3'))
                item=PreparedRelaySettlement('known',rid(1),HASH,0,11155111,CONTRACT,'0x00',
                    {'protocol_version':10,'channel_id':CHANNEL})
                outbox.enqueue(item)
                if status=='escrowed':outbox.mark_escrowed_many({item.key:{}},'')
                elif status=='confirmed':outbox.mark_confirmed(item.key)
                elif status=='failed':outbox.mark_failed(item.key,'invalid_receipt',retryable=False)
                elif status=='submitted':outbox.mark_submitted(item.key,HASH)
                rows=read_execution_outbox(self.db,anchor_path=self.anchor,provider_signer=SIGNER,
                    limit=1,unexpired_at=1200,submission_outbox=outbox.path)
                self.assertEqual(rows[0]['request_id'],rid(1 if status in ('pending','submitted') else 2))

    def test_submission_filter_binds_channel_contract_and_chain(self):
        from gateway.reserved_execution import read_execution_outbox
        from gateway.session_relayer import PreparedRelaySettlement, RelaySettlementOutbox
        auth={'authorization':{'deadline':3000}};dispatch={'id':1}
        self.ledger.reserve(CONTRACT,CHANNEL,request_id=rid(1),request_hash=HASH,max_fee=40,
            authorization=auth,dispatch=dispatch,now=1100)
        self.ledger.complete(CONTRACT,CHANNEL,rid(1),response={},signed_receipt={
            'chain_id':11155111,'authorization':auth,'dispatch':dispatch,
            'receipt':{'actual_fee':1}},now=1101)
        variants=((11155111,CONTRACT,rid(9)),(11155111,SIGNER,CHANNEL),(31337,CONTRACT,CHANNEL))
        for n,(chain,contract,channel) in enumerate(variants):
            with self.subTest(chain=chain,contract=contract,channel=channel):
                outbox=RelaySettlementOutbox(self.base/f'other-{n}.sqlite3')
                outbox.enqueue(PreparedRelaySettlement('other',rid(1),HASH,0,chain,contract,'0x00',
                    {'protocol_version':10,'channel_id':channel}))
                outbox.mark_confirmed('other')
                rows=read_execution_outbox(self.db,anchor_path=self.anchor,provider_signer=SIGNER,
                    limit=1,submission_outbox=outbox.path)
                self.assertEqual(rows[0]['request_id'],rid(1))

    def test_submission_filter_does_not_create_missing_database(self):
        from gateway.reserved_execution import read_execution_outbox
        missing=self.base/'missing-submission.sqlite3'
        self.assertEqual(read_execution_outbox(self.db,anchor_path=self.anchor,
            provider_signer=SIGNER,submission_outbox=missing),[])
        self.assertFalse(missing.exists())

if __name__=='__main__': unittest.main()
