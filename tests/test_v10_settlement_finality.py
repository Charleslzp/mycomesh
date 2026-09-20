from __future__ import annotations

import time
import unittest
from unittest.mock import Mock, patch

from gateway.session_relayer import RelaySettlementError
from tests import test_v10_relay_runtime as fixtures
from tests.test_chain_v9 import digest


class V10SettlementFinalityTests(unittest.TestCase):
    setUp = fixtures.V10RelayRuntimeTests.setUp
    prepared = fixtures.V10RelayRuntimeTests.prepared

    def receipt(self, status='0x1'):
        return {'transactionHash':digest(77), 'blockHash':digest(88),
                'blockNumber':hex(500), 'status':status, 'logs':[],
                'gasUsed':hex(100), 'effectiveGasPrice':hex(1)}

    def rpc(self, receipt, *, head=505, canonical=None, fresh=None):
        block={'number':hex(500), 'hash':canonical or receipt['blockHash']}
        def read(url, method, params, timeout):
            if method=='eth_chainId': return hex(31337)
            if method=='eth_getTransactionReceipt': return receipt
            if method=='eth_blockNumber': return hex(head)
            if method=='eth_getBlockByNumber': return block
            self.fail('unexpected RPC '+method)
        return read

    def test_success_and_revert_need_six_confirmations(self):
        for status in ('0x1','0x0'):
            for head,ready in ((500,False),(504,False),(505,True)):
                with self.subTest(status=status,head=head):
                    receipt=self.receipt(status)
                    with patch('gateway.session_relayer.rpc_call',side_effect=self.rpc(receipt,head=head)):
                        actual=self.worker._transaction_receipt(digest(77),time.monotonic()+5)
                    self.assertEqual(actual is not None,ready)

    def test_noncanonical_mined_receipt_is_not_terminal(self):
        receipt=self.receipt()
        with patch('gateway.session_relayer.rpc_call',side_effect=self.rpc(receipt,canonical=digest(89))):
            self.assertIsNone(self.worker._transaction_receipt(digest(77),time.monotonic()+5))

    def test_receipt_disappears_or_moves_during_confirmation(self):
        receipt=self.receipt()
        for fresh in (None,{**receipt,'blockHash':digest(89)},{**receipt,'status':'0x0'}):
            with self.subTest(fresh=fresh):
                values=iter([receipt,fresh]); base=self.rpc(receipt)
                def read(url,method,params,timeout):
                    return next(values) if method=='eth_getTransactionReceipt' else base(url,method,params,timeout)
                with patch('gateway.session_relayer.rpc_call',side_effect=read):
                    self.assertIsNone(self.worker._transaction_receipt(digest(77),time.monotonic()+5))

    def test_canonical_block_changes_after_receipt_reread(self):
        receipt=self.receipt(); base=self.rpc(receipt)
        values=iter([{'number':hex(500),'hash':digest(88)},{'number':hex(500),'hash':digest(89)}])
        def read(url,method,params,timeout):
            return next(values) if method=='eth_getBlockByNumber' else base(url,method,params,timeout)
        with patch('gateway.session_relayer.rpc_call',side_effect=read):
            self.assertIsNone(self.worker._transaction_receipt(digest(77),time.monotonic()+5))

    def test_confirmation_count_falls_during_reread(self):
        receipt=self.receipt(); base=self.rpc(receipt); heads=iter([hex(505),hex(504)])
        def read(url,method,params,timeout):
            return next(heads) if method=='eth_blockNumber' else base(url,method,params,timeout)
        with patch('gateway.session_relayer.rpc_call',side_effect=read):
            self.assertIsNone(self.worker._transaction_receipt(digest(77),time.monotonic()+5))

    def test_unconfirmed_success_and_revert_hold_nonce_across_recovery(self):
        p=self.prepared(); self.worker.enqueue(p)
        self.outbox.mark_submitted_many([p.key],digest(77))
        for status in ('0x1','0x0'):
            receipt=self.receipt(status)
            self.worker.receipt_timeout_seconds=5
            with patch('gateway.session_relayer.rpc_call',side_effect=self.rpc(receipt,head=504)), \
                 patch.object(self.worker,'_send_transaction') as send, \
                 patch.object(self.worker,'_reconcile_v10_existing') as reconcile, \
                 patch.object(self.worker._stop,'wait',side_effect=RelaySettlementError('still pending',error_code='confirmation_timeout')):
                with self.assertRaises(RelaySettlementError): self.worker.process_once(force=True)
            self.assertEqual(self.outbox.status(p.key),'submitted')
            self.assertEqual(self.outbox.submission_items([p.key])[0]['tx_hash'],digest(77))
            send.assert_not_called(); reconcile.assert_not_called()

    def test_confirmed_success_marks_escrow_only_after_canonical_check(self):
        p=self.prepared(); self.worker.enqueue(p); self.outbox.mark_submitted_many([p.key],digest(77))
        with patch('gateway.session_relayer.rpc_call',side_effect=self.rpc(self.receipt())), \
             patch.object(self.worker,'_verified_v9_escrow_events',return_value={p.key:{'release_at':self.now+300}}) as events:
            self.worker.process_once(force=True)
        self.assertEqual(self.outbox.status(p.key),'escrowed'); events.assert_called_once()

    def test_confirmed_revert_reconciles_before_any_new_nonce(self):
        p=self.prepared(); self.worker.enqueue(p); self.outbox.mark_submitted_many([p.key],digest(77))
        with patch('gateway.session_relayer.rpc_call',side_effect=self.rpc(self.receipt('0x0'))), \
             patch.object(self.worker,'_reconcile_v10_existing',return_value=False) as reconcile, \
             patch.object(self.worker,'_send_transaction') as send:
            self.worker.process_once(force=True)
        self.assertEqual(self.outbox.status(p.key),'pending'); reconcile.assert_called_once(); send.assert_not_called()

    def test_external_settlement_fork_keeps_pending(self):
        p=self.prepared(); self.worker.enqueue(p)
        for head,hash_value in ((506,digest(77)),(502,self.channel['block_hash'])):
            with self.subTest(head=head,block_hash=hash_value):
                with patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value=self.channel), \
                     patch('gateway.chain_v10.settlement_info',return_value={'status':1}), \
                     patch('gateway.session_relayer.rpc_call',side_effect=lambda url,method,params,timeout:
                           hex(head) if method=='eth_blockNumber' else {'number':hex(500),'hash':hash_value}), \
                     patch.object(self.worker,'_send_transaction') as send:
                    with self.assertRaises(RelaySettlementError): self.worker.process_once(force=True)
                self.assertEqual(self.outbox.status(p.key),'pending'); send.assert_not_called()

    def test_expired_pending_reconciles_after_channel_closed_without_broadcast(self):
        p=self.prepared();self.worker.enqueue(p)
        auth=self.auth['authorization'];terms=self.channel
        info={'status':1,'release_at':self.now+300,'owner':terms['consumer_owner'],'key':auth['key'],
            'provider':terms['provider_owner'],'provider_signer':terms['provider_signer'],
            'relay':terms['relay'],'relay_signer':terms['relay_signer'],'request_id':auth['request_id'],
            'request_hash':auth['request_hash'],'authorization_hash':self.signed['receipt']['authorization_hash'],
            'response_hash':self.signed['receipt']['response_hash'],'gross_fee':2000}
        with patch('gateway.session_relayer.time.time',return_value=auth['deadline']+1), \
             patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value={**self.channel,'closed':True}), \
             patch('gateway.chain_v10.settlement_info',return_value=info), \
             patch('gateway.session_relayer.rpc_call',side_effect=lambda url,method,params,timeout:
                   hex(506) if method=='eth_blockNumber' else {'number':hex(500),'hash':self.channel['block_hash']}), \
             patch.object(self.worker,'_send_transaction') as send:
            self.assertEqual(self.worker.process_once(),1)
        self.assertEqual(self.outbox.status(p.key),'escrowed');send.assert_not_called()

    def test_expired_pending_fails_only_after_canonical_absence_is_verified(self):
        p=self.prepared();self.worker.enqueue(p)
        with patch('gateway.session_relayer.time.time',return_value=self.auth['authorization']['deadline']+1), \
             patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value={**self.channel,
                 'block_timestamp':self.auth['authorization']['deadline']+1}), \
             patch('gateway.chain_v10.settlement_info',return_value={'status':0}) as info, \
             patch('gateway.session_relayer.rpc_call',side_effect=lambda url,method,params,timeout:
                   hex(506) if method=='eth_blockNumber' else {'number':hex(500),'hash':self.channel['block_hash']}), \
             patch.object(self.worker,'_send_transaction') as send:
            self.assertEqual(self.worker.process_once(),1)
        self.assertEqual(self.outbox.status(p.key),'failed');info.assert_called_once();send.assert_not_called()

    def test_expiry_waits_until_confirmed_snapshot_passes_inclusive_deadline(self):
        p=self.prepared();self.worker.enqueue(p)
        deadline=self.auth['authorization']['deadline']
        for confirmed_at in (deadline-1,deadline,None):
            with self.subTest(confirmed_at=confirmed_at):
                with patch('gateway.session_relayer.time.time',return_value=deadline+1), \
                     patch('gateway.reserved_execution.confirmed_channel_snapshot',return_value={**self.channel,
                         'block_timestamp':confirmed_at}), \
                     patch('gateway.chain_v10.settlement_info',return_value={'status':0}), \
                     patch('gateway.session_relayer.rpc_call',side_effect=lambda url,method,params,timeout:
                           hex(506) if method=='eth_blockNumber' else {'number':hex(500),'hash':self.channel['block_hash']}), \
                     patch.object(self.worker,'_send_transaction') as send:
                    with self.assertRaisesRegex(RelaySettlementError,'confirmed block beyond'):
                        self.worker.process_once()
                self.assertEqual(self.outbox.status(p.key),'pending');send.assert_not_called()


if __name__=='__main__': unittest.main()
