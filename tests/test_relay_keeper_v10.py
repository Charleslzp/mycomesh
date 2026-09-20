"""Keeper recovery and safety checks use synthetic accounts and mocked RPC."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gateway import chain, chain_v9
from gateway.relay_adjudication_v9 import V9AdjudicationError
from gateway.relay_keeper_v10 import V10EscrowKeeper, V10MaintenanceClient, V10OperatorConfig, RoutedMaintenanceOutbox
from dataclasses import asdict
from gateway.relay_adjudication_v9 import V9AdjudicationClient, V9OperatorConfig
from tests.test_relay_adjudication_v9 import V9Fixture, address, digest, key


class V10KeeperTests(V9Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config=V10OperatorConfig(**asdict(self.config))
        self.client=V10MaintenanceClient(self.config)
        self.snap['domain']=self.config.domain
        check=patch.object(self.client,'_uint_call',return_value=1);check.start();self.addCleanup(check.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / "keeper.sqlite3"
        self.keyfile = Path(self.tmp.name) / "keeper.key"
        self.keyfile.write_text(key(20))
        self.keyfile.chmod(0o600)
        self.actor = address(20)
        self.snap["settlement"]["release_at"] = self.now
        self.head, self.nonce, self.receipt, self.fail_send = 99, 0, None, False
        self.sent, self.reorgs = [], {}
        self.logs = [{"address": self.config.settlement_contract,
            "topics": [chain_v9.RECEIPT_ESCROWED_TOPIC, self.settlement_key, digest(1), "0x" + address(7)[2:].zfill(64)],
            "data": "0x" + address(5)[2:].zfill(64) + f"{100:064x}" + f"{self.now:064x}",
            "blockNumber": hex(95), "blockHash": digest(95), "removed": False}]
        for target, kwargs in (("snapshot", {"side_effect": self.snapshot}),
                               ("confirmed_context", {"side_effect": self.context}),
                               ("rpc", {"side_effect": self.rpc})):
            mock = patch.object(self.client, target, **kwargs)
            mock.start()
            self.addCleanup(mock.stop)
        self.keepers = []
        self.keeper = self.make_keeper()
        self.addCleanup(lambda: [k.close() for k in self.keepers])

    def make_keeper(self, **kwargs):
        keeper = V10EscrowKeeper(self.client, actor=self.actor, database=self.database,
                               start_block=90, **kwargs)
        self.keepers.append(keeper)
        return keeper

    def context(self):
        return {"block_number": self.head, "block_hash": digest(self.head), "timestamp": self.now}

    def rpc(self, method, params):
        if method == "eth_getLogs":
            start, end = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
            return [copy.deepcopy(log) for log in self.logs if start <= int(log["blockNumber"], 16) <= end]
        if method == "eth_getBlockByNumber":
            number = int(params[0], 16)
            return {"hash": digest(10) if number == 0 else self.reorgs.get(number, digest(number))}
        if method == "eth_getTransactionCount": return hex(self.nonce)
        if method == "eth_gasPrice": return "0x1"
        if method == "eth_estimateGas": return hex(50000)
        if method == "eth_sendRawTransaction":
            self.sent.append(params[0])
            if self.fail_send: raise TimeoutError("lost RPC acknowledgement")
            return "0x" + chain.keccak256(bytes.fromhex(params[0][2:])).hex()
        if method == "eth_getTransactionReceipt": return self.receipt
        if method == "eth_chainId": return hex(31337)
        if method == "eth_blockNumber": return hex(100)
        raise AssertionError(method)

    def send(self, keeper=None, **kwargs):
        return (keeper or self.keeper).run_once(send=True, dedicated_sender=True,
            key_file=self.keyfile, max_gas_price_wei=10, max_gas_units=100000,
            max_total_gas_cost_wei=1000000, **kwargs)

    def test_scan_dry_run_is_durable_and_never_loads_a_key(self):
        with patch("gateway.relay_keeper_v10._protected_key", side_effect=AssertionError("key read")):
            result = self.keeper.run_once()
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["scan"]["through_block"], 99)
        self.assertEqual(result["candidates"][0]["plan"]["action"], "release")
        self.assertFalse(result["wallet_payout_verified"])
        self.assertEqual(self.sent, [])
        reopened = self.make_keeper()
        self.assertEqual(reopened.run_once()["scan"]["discovered"], 0)
        self.assertEqual(reopened.outbox.db.execute("SELECT count(*) FROM v10_keeper_escrows").fetchone()[0], 1)

    def test_scan_chunks_resume_without_skipping_events(self):
        keeper = self.make_keeper(max_scan_blocks=5)
        self.assertEqual(keeper.run_once()["scan"]["through_block"], 94)
        self.assertEqual(keeper.run_once()["scan"]["discovered"], 1)

    def test_checkpoint_reorg_halts_without_new_send(self):
        self.keeper.run_once()
        self.reorgs[99] = digest(777)
        with self.assertRaisesRegex(V9AdjudicationError, "checkpoint reorganized"):
            self.send()
        self.assertEqual(self.sent, [])

    def test_noncanonical_event_never_advances_cursor(self):
        self.logs[0]["blockHash"] = digest(777)
        with self.assertRaisesRegex(V9AdjudicationError, "not canonical"):
            self.keeper.run_once()
        self.assertEqual(self.keeper.outbox.db.execute("SELECT cursor_number FROM v10_keeper_config").fetchone()[0], 89)

    def test_immature_disputed_and_terminal_escrows_are_skipped(self):
        for status, release, resolve, expected in ((1, self.now + 1, self.now + 10, "not_mature"),
                (2, self.now - 100, self.now + 1, "dispute_active"),
                (3, self.now - 100, self.now - 1, "terminal_or_missing")):
            self.snap["settlement"].update(status=status, release_at=release)
            self.snap["dispute"]["resolve_at"] = resolve
            result = self.send()
            self.assertEqual(result["candidates"][0]["status"], expected)
        self.assertEqual(self.sent, [])

    def test_timeout_is_nonpunitive_and_only_after_full_deadline(self):
        self.snap["settlement"].update(status=2, release_at=self.now - 100)
        self.snap["dispute"]["resolve_at"] = self.now
        plan = self.keeper.run_once()["candidates"][0]["plan"]
        self.assertEqual(plan["action"], "timeout")
        self.assertFalse(plan["monetary_verdict"])
        self.assertEqual(plan["transaction"]["value"], 0)

    def test_uncertain_restart_never_allocates_a_new_nonce_or_rebroadcasts_by_default(self):
        self.fail_send = True
        first = self.send()["transactions"][0]
        self.snap["block_number"] += 1
        second = self.send(self.make_keeper())
        self.assertEqual(second["blocked"], "unresolved_transaction")
        self.assertEqual(second["transactions"][0]["tx_hash"], first["tx_hash"])
        self.assertEqual(len(self.sent), 1)

    def test_explicit_recovery_rebroadcasts_identical_bytes_without_signing(self):
        self.fail_send = True
        first = self.send()["transactions"][0]
        self.fail_send = False
        with patch("gateway.chain.sign_legacy_transaction", side_effect=AssertionError("new signature")):
            second = self.send(self.make_keeper(), resume_signed=True)
        self.assertEqual(second["transactions"][0]["tx_hash"], first["tx_hash"])
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[0], self.sent[1])
        self.assertEqual(second["blocked"], "unresolved_transaction")

    def test_unknown_consumed_nonce_never_rebroadcasts_or_gets_replaced(self):
        self.fail_send = True
        self.send()
        self.nonce = 1
        with self.assertRaisesRegex(V9AdjudicationError, "nonce changed"):
            self.send(resume_signed=True)
        self.assertEqual(len(self.sent), 1)

    def test_crash_after_durable_commit_before_broadcast_uses_the_saved_signature(self):
        with patch.object(self.client, "rpc", side_effect=lambda method, params:
                (_ for _ in ()).throw(KeyboardInterrupt()) if method == "eth_sendRawTransaction" else self.rpc(method, params)):
            with self.assertRaises(KeyboardInterrupt):
                self.send()
        saved = self.keeper.outbox.unresolved(self.actor)[0]
        self.assertEqual(saved["state"], "sending")
        self.assertEqual(self.sent, [])
        result = self.send(self.make_keeper(), resume_signed=True)
        self.assertEqual(result["transactions"][0]["tx_hash"], saved["tx_hash"])
        self.assertEqual(len(self.sent), 1)

    def test_business_confirmation_survives_restart_and_never_claims(self):
        first = self.send()["transactions"][0]
        self.receipt = {"transactionHash": first["tx_hash"], "blockNumber": hex(99), "blockHash": digest(99), "status": "0x1"}
        self.snap["settlement"]["status"] = 3
        result = self.send(self.make_keeper())
        self.assertEqual(result["transactions"][0]["settlement_outcome"]["status"], "released")
        self.assertFalse(result["transactions"][0]["settlement_outcome"]["wallet_payout_verified"])
        self.assertEqual(len(self.sent), 1)

    def test_evm_success_without_business_outcome_blocks_sender(self):
        first = self.send()["transactions"][0]
        self.receipt = {"transactionHash": first["tx_hash"], "blockNumber": hex(99), "blockHash": digest(99), "status": "0x1"}
        with self.assertRaisesRegex(V9AdjudicationError, "outcome"):
            self.send(self.make_keeper())
        self.assertEqual(self.keeper.outbox.get(first["plan_hash"])["state"], "uncertain")
        self.assertEqual(len(self.sent), 1)

    def test_dedicated_sender_attestation_and_reserved_addresses_enforced(self):
        with self.assertRaisesRegex(V9AdjudicationError, "dedicated keeper"):
            self.keeper.run_once(send=True)
        with self.assertRaisesRegex(V9AdjudicationError, "dedicated keeper"):
            self.send(self.make_keeper(reserved_senders=(self.actor,)))
        with self.assertRaisesRegex(V9AdjudicationError, "explicit send"):
            self.keeper.run_once(resume_signed=True)
        self.assertEqual(self.sent, [])

    def test_database_reuse_with_different_sender_is_rejected(self):
        with self.assertRaisesRegex(V9AdjudicationError, "another deployment"):
            V10EscrowKeeper(self.client, actor=address(21), database=self.database, start_block=90)

    def test_v10_settled_mapping_is_required(self):
        with patch.object(self.client,'_uint_call',return_value=0):
            with self.assertRaisesRegex(V9AdjudicationError,'confirmed escrow'):self.keeper.run_once()
    def test_keeper_has_no_monetary_judgement_or_claim_methods(self):
        for method in ('plan_report','plan_vote','plan_claim'):
            with self.assertRaises(V9AdjudicationError):getattr(self.client,method)()
    def test_shared_outbox_routes_old_domain_and_blocks_new_nonce(self):
        # A stored V10 pending nonce must also block an attempted legacy send.
        self.fail_send=True;pending=self.send()['transactions'][0]
        legacy_config=V9OperatorConfig(**{k:v for k,v in asdict(self.config).items() if k!='protocol_version'})
        legacy=V9AdjudicationClient(legacy_config)
        outbox=RoutedMaintenanceOutbox(self.database,[legacy,self.client]);self.addCleanup(outbox.close)
        with patch.object(legacy,'rpc',side_effect=AssertionError('wrong deployment recovery')):
            row=outbox.reconcile(legacy,pending['plan_hash'])
        self.assertEqual(row['tx_hash'],pending['tx_hash']);self.assertEqual(row['state'],'uncertain')
        self.assertEqual(len(self.sent),1)
    def test_unknown_saved_domain_halts_instead_of_ignoring(self):
        self.fail_send=True;pending=self.send()['transactions'][0]
        outbox=RoutedMaintenanceOutbox(self.database,[]);self.addCleanup(outbox.close)
        with self.assertRaisesRegex(V9AdjudicationError,'pins are unavailable'):outbox.reconcile(self.client,pending['plan_hash'])

    def test_shared_worker_retains_both_cursors_and_serializes_pending_nonce(self):
        from gateway.relay_keeper_v10 import SharedEscrowKeeper
        legacy_config=V9OperatorConfig(**{k:v for k,v in asdict(self.config).items() if k!='protocol_version'})
        legacy=V9AdjudicationClient(legacy_config)
        def legacy_snapshot(settlement_key,actor,report_id=chain.ZERO_BYTES32):
            snap=self.snapshot(settlement_key,actor,report_id);snap['domain']=legacy_config.domain;return snap
        with patch.object(legacy,'snapshot',side_effect=legacy_snapshot),patch.object(legacy,'confirmed_context',side_effect=self.context),patch.object(legacy,'rpc',side_effect=self.rpc):
            worker=SharedEscrowKeeper(self.client,actor=self.actor,database=self.database,start_block=90,legacy_client=legacy,legacy_start_block=90)
            try:
                self.fail_send=True
                result=worker.run_once(send=True,dedicated_sender=True,key_file=self.keyfile,max_gas_price_wei=10,max_gas_units=100000,max_total_gas_cost_wei=1000000)
                self.assertEqual(len(self.sent),1)
                self.assertEqual(result['deployments'][1]['blocked'],'unresolved_transaction')
                self.assertEqual(result['deployments'][0]['transactions'][0]['tx_hash'],result['deployments'][1]['transactions'][0]['tx_hash'])
                db=worker.keepers[0].outbox.db
                self.assertEqual(db.execute('SELECT cursor_number FROM v9_keeper_config').fetchone()[0],99)
                self.assertEqual(db.execute('SELECT cursor_number FROM v10_keeper_config').fetchone()[0],99)
            finally:worker.close()

class V10DiscoveryGateTests(unittest.TestCase):
    def test_discovery_keeps_protocol_binding_and_accepts_v10(self):
        from gateway.relay_discovery import normalize_context, DiscoveryError
        context=dict(network_id='test',channel_id='codex',chain_id=31337,settlement_contract=address(90),protocol_version=10,network_profile='testnet')
        self.assertEqual(normalize_context(context)['protocol_version'],10)
        with self.assertRaises(DiscoveryError):normalize_context({**context,'protocol_version':11})
    def test_pool_capability_accepts_v10_and_rejects_unknown(self):
        from gateway.pool import normalize_settlement_capability, PoolError
        c=dict(version=10,chain_id=31337,contract=address(90),pricing_version=1,pricing_hash=digest(1))
        self.assertEqual(normalize_settlement_capability(c,label='test')['version'],10)
        with self.assertRaises(PoolError):normalize_settlement_capability({**c,'version':11},label='test')

    def test_v10_channel_namespace_needs_separate_local_optin(self):
        from types import SimpleNamespace
        from gateway.channel_policy import require_deployment_channel_binding
        deployment=SimpleNamespace(network_id='mycomesh-v10-fixed-budget-controlled-test',channel_id='codex',channel='codex-standard-v1',backend_policy='codex-app-server-postvalidated-v1')
        for env in ({},{'MYCOMESH_ALLOW_CONTROLLED_V9_TEST':'1'},{'MYCOMESH_ALLOW_CONTROLLED_V10_TEST':'true'}):
            with patch.dict('os.environ',env,clear=True):
                with self.assertRaises(ValueError):require_deployment_channel_binding(deployment)
        with patch.dict('os.environ',{'MYCOMESH_ALLOW_CONTROLLED_V10_TEST':'1'},clear=True):
            self.assertEqual(require_deployment_channel_binding(deployment).network_id,deployment.network_id)
            deployment.network_id='mycomesh-v9-controlled-test'
            with self.assertRaises(ValueError):require_deployment_channel_binding(deployment)


if __name__ == "__main__":
    unittest.main()
