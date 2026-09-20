"""Local-only executor tests; all keys and independent roles are synthetic."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from gateway import chain, chain_v9
from gateway.relay_incidents import evidence_hash
from gateway.relay_adjudication_v9 import (
    V9AdjudicationClient, V9AdjudicationError, V9OperatorConfig, V9TransactionOutbox,
)


def key(number):
    return "0x" + f"{number:064x}"


def address(number):
    return chain.private_key_to_address(chain.parse_private_key(key(number)))


def digest(number):
    return "0x" + f"{number:064x}"


class V9Fixture:
    def setUp(self):
        self.now = int(time.time())
        self.policy = {"reporter_bond": 500, "bond_penalty_recipient": address(80)}
        self.config = V9OperatorConfig(
            rpc_url="http://127.0.0.1:18545", chain_id=31337,
            settlement_contract=address(90), runtime_code_hash="0x" + chain.keccak256(b"\x60\x00").hex(),
            genesis_hash=digest(10), policy_hash=evidence_hash(self.policy),
            adjudicators=(address(10), address(11), address(12)), threshold=2,
            adjudicator_operators={address(x): f"synthetic-fixture-operator-{x}" for x in (10, 11, 12)},
            independence_attested=True,
            observer_public_key="ab" * 32, reporter_address=address(9), confirmations=2,
        )
        self.client = V9AdjudicationClient(self.config)
        self.authorization = chain_v9.build_authorization(payment_key=key(1), chain_id=31337,
            settlement_contract=self.config.settlement_contract, request_id=digest(1), request_hash=digest(2),
            relay=address(3), relay_signer=address(4), channel_hash=digest(5), pricing_version=1,
            pricing_hash=digest(6), max_fee=1000, issued_at=self.now, deadline=self.now+300)
        self.receipt = chain_v9.build_provider_receipt(provider=address(5), provider_private_key=key(6),
            authorization_payload=self.authorization, response_hash=digest(8), relay=address(3),
            input_tokens=2, output_tokens=3, actual_fee=100)
        self.settlement_key = chain_v9.settlement_key_for(address(7), address(1), digest(1))
        self.incident = {"provider_id": "fixture-peer", "provider_signer": address(6),
            "request_id": digest(1), "request_hash": digest(2), "kind": "protocol:usage_receipt_mismatch",
            "severity": "hard", "evidence": {"settlement_version": 9,
                "provider_response": {"mycomesh_v9_settlement": self.receipt}}}
        self.rehash()
        self.snap = {"domain": self.config.domain, "block_number": 99, "block_hash": digest(99),
            "timestamp": self.now, "actor": address(9), "policy": self.policy,
            "adjudicators": list(self.config.adjudicators), "threshold": 2,
            "settlement_key": self.settlement_key, "report_id": chain.ZERO_BYTES32,
            "settlement": {"owner": address(7), "key": address(1), "provider": address(5),
                "provider_signer": address(6), "relay": address(3), "relay_signer": address(4),
                "pool": chain.ZERO_ADDRESS, "treasury": address(8), "request_id": digest(1),
                "request_hash": digest(2), "authorization_hash": self.receipt["receipt"]["authorization_hash"],
                "response_hash": digest(8), "gross_fee": 100, "settled_at": self.now-10,
                "release_at": self.now+100, "status": 1},
            "dispute": {"resolve_at": self.now+200}, "report": {"reporter": address(9),
                "evidence_hash": self.incident["record_hash"], "bond_claimed": False},
            "has_reported": False, "actor_vote": 0, "claimable": 40, "token_claimable": 60}
        # The independently tested full Relay evidence verifier is isolated here;
        # all V9 Provider receipt EVM signatures below are real, not mocked.
        self.evidence_mock = patch("gateway.relay_adjudication_v9.verify_relay_incident", return_value={
            "classification": "protocol_contradiction", "provider_signer": address(6)})
        self.verify = self.evidence_mock.start()
        self.addCleanup(self.evidence_mock.stop)

    def rehash(self):
        fields = ("provider_id", "provider_signer", "request_id", "request_hash", "kind", "severity", "evidence")
        self.incident["evidence_hash"] = evidence_hash(self.incident["evidence"])
        self.incident["record_hash"] = evidence_hash({x: self.incident[x] for x in fields})

    def snapshot(self, settlement_key, actor, report_id=chain.ZERO_BYTES32):
        result = copy.deepcopy(self.snap)
        result.update(actor=actor, settlement_key=settlement_key, report_id=report_id)
        return result

    def report(self):
        with patch.object(self.client, "snapshot", side_effect=self.snapshot):
            return self.client.plan_report(incident=self.incident, observed_at=self.now, settlement_key=self.settlement_key)

    def vote(self, *, confirmed=True, actor=None, review=None):
        actor = actor or address(10)
        review = review or {"reviewer": actor, "incident_record_hash": self.incident["record_hash"],
            "outcome": "confirmed" if confirmed else "dismissed", "reason": "Reviewed the exact immutable signed Provider transcript."}
        with patch.object(self.client, "snapshot", side_effect=self.snapshot):
            return self.client.plan_vote(incident=self.incident, observed_at=self.now,
                settlement_key=self.settlement_key, actor=actor, confirmed=confirmed, review=review)

    def voting_window(self):
        self.snap["settlement"]["status"] = 2
        self.snap["settlement"]["release_at"] = self.now


class V9AdjudicationTests(V9Fixture, unittest.TestCase):
    def test_operator_pins_are_required_and_committee_is_majority(self):
        for changes in ({"threshold": 1}, {"adjudicators": (address(10),)*3},
                        {"reporter_address": address(10)}, {"confirmations": 0},
                        {"independence_attested": False},
                        {"adjudicator_operators": {address(x): "same-operator" for x in (10, 11, 12)}},
                        {"genesis_hash": chain.ZERO_BYTES32}, {"observer_public_key": "not a key"}):
            with self.subTest(changes=changes), self.assertRaises(V9AdjudicationError):
                replace(self.config, **changes)

    def test_report_is_dry_run_and_commits_exact_incident(self):
        plan = self.report()
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["monetary_verdict"])
        self.assertEqual(plan["transaction"]["data"], chain_v9.encode_open_dispute(self.settlement_key, self.incident["record_hash"]))
        self.assertEqual(plan["amounts"], {"reporter_bond_units": 500})
        self.incident["evidence"]["mutated"] = True
        self.assertNotIn("mutated", plan["inputs"]["incident"]["evidence"])

    def test_second_report_uses_submit_evidence_and_never_reopens(self):
        self.snap["settlement"]["status"] = 2
        self.assertEqual(self.report()["transaction"]["data"],
            chain_v9.encode_submit_evidence(self.settlement_key, self.incident["record_hash"]))

    def test_soft_probe_or_contextual_failure_is_not_monetary_evidence(self):
        for classification in ("contextual_allegation", "inconclusive", "capability_mismatch"):
            self.verify.return_value["classification"] = classification
            with self.subTest(classification=classification), self.assertRaisesRegex(V9AdjudicationError, "soft probes"):
                self.report()

    def test_v8_incident_cannot_slash_v9(self):
        self.incident["evidence"]["settlement_version"] = 8
        self.rehash()
        with self.assertRaisesRegex(V9AdjudicationError, "V7/V8"):
            self.report()

    def test_hash_only_fabrication_or_provider_signature_tampering_fails(self):
        self.incident["evidence"]["provider_response"]["mycomesh_v9_settlement"]["receipt"]["actual_fee"] += 1
        with self.assertRaisesRegex(V9AdjudicationError, "content differs"):
            self.report()
        self.rehash()
        with self.assertRaises(chain.ChainError):
            self.report()

    def test_all_immutable_settlement_bindings_are_checked(self):
        for field in ("key", "request_id", "request_hash", "relay_signer", "provider", "provider_signer",
                      "relay", "pool", "authorization_hash", "response_hash", "gross_fee", "owner"):
            original = self.snap["settlement"][field]
            self.snap["settlement"][field] = 999 if type(original) is int else digest(999)
            with self.subTest(field=field), self.assertRaises((V9AdjudicationError, chain.ChainError)):
                self.report()
            self.snap["settlement"][field] = original

    def test_unsettled_and_expired_receipts_cannot_be_reported(self):
        for field, value in (("status", 0), ("settled_at", 0), ("status", 3), ("release_at", self.now)):
            original = self.snap["settlement"][field]
            self.snap["settlement"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(V9AdjudicationError):
                self.report()
            self.snap["settlement"][field] = original

    def test_repeat_report_fails_and_observer_is_pinned(self):
        self.report()
        self.assertEqual(self.verify.call_args.kwargs["expected_observer_public_key"], self.config.observer_public_key)
        self.snap["has_reported"] = True
        with self.assertRaisesRegex(V9AdjudicationError, "already submitted"):
            self.report()

    def test_independent_evm_vote_binds_exact_report_and_review(self):
        self.voting_window()
        plan = self.vote()
        self.assertEqual(plan["transaction"]["from"], address(10))
        self.assertEqual(plan["action"], "vote")
        self.assertEqual(plan["snapshot"]["report_id"], chain_v9.report_id_for(
            self.settlement_key, address(9), self.incident["record_hash"]))

    def test_judges_cannot_vote_before_evidence_window_or_after_deadline(self):
        with self.assertRaisesRegex(V9AdjudicationError, "window"):
            self.vote()
        self.voting_window()
        self.snap["dispute"]["resolve_at"] = self.now
        with self.assertRaisesRegex(V9AdjudicationError, "window"):
            self.vote()

    def test_reporter_provider_related_party_or_unpinned_key_cannot_vote(self):
        self.voting_window()
        for actor in (address(9), address(5), address(99)):
            with self.subTest(actor=actor), self.assertRaisesRegex(V9AdjudicationError, "independent"):
                self.vote(actor=actor)
        self.snap["settlement"]["treasury"] = address(10)
        with self.assertRaisesRegex(V9AdjudicationError, "independent"):
            self.vote()

    def test_existing_vote_or_report_prevents_vote(self):
        self.voting_window()
        for field in ("actor_vote", "has_reported"):
            self.snap[field] = 1
            with self.subTest(field=field), self.assertRaises(V9AdjudicationError):
                self.vote()
            self.snap[field] = 0

    def test_report_mismatch_or_ed25519_certificate_does_not_authorize_vote(self):
        self.voting_window()
        with self.assertRaisesRegex(V9AdjudicationError, "review"):
            self.vote(review={"signatures": ["ed25519-a", "ed25519-b"], "payable": True})
        self.snap["report"]["evidence_hash"] = digest(999)
        with self.assertRaisesRegex(V9AdjudicationError, "onchain report"):
            self.vote()

    def test_false_allegation_can_be_dismissed_without_claiming_verified_fraud(self):
        self.voting_window()
        self.verify.side_effect = ValueError("invalid evidence")
        plan = self.vote(confirmed=False)
        self.verify.assert_not_called()
        self.assertEqual(plan["inputs"]["review"]["outcome"], "dismissed")

    def test_claim_requires_real_chain_credit_or_refundable_bond(self):
        with patch.object(self.client, "snapshot", side_effect=self.snapshot):
            for kind, amount in (("stable", 40), ("token", 60)):
                self.assertEqual(self.client.plan_claim(actor=address(9), settlement_key=self.settlement_key,
                    kind=kind)["amounts"]["claim_units"], amount)
            with self.assertRaisesRegex(V9AdjudicationError, "not refundable"):
                self.client.plan_claim(actor=address(9), settlement_key=self.settlement_key, kind="bond")
            self.snap["settlement"]["status"] = 4
            self.assertEqual(self.client.plan_claim(actor=address(9), settlement_key=self.settlement_key,
                report_id=digest(88), kind="bond")["amounts"]["claim_units"], 500)
            self.snap["report"]["bond_claimed"] = True
            with self.assertRaises(V9AdjudicationError):
                self.client.plan_claim(actor=address(9), settlement_key=self.settlement_key, kind="bond")

    def test_plan_tampering_and_changed_state_fail_refresh(self):
        plan = self.report()
        tampered = copy.deepcopy(plan)
        tampered["transaction"]["to"] = address(99)
        with self.assertRaisesRegex(V9AdjudicationError, "hash"):
            self.client.refresh(tampered)
        with patch.object(self.client, "snapshot", side_effect=self.snapshot):
            self.client.refresh(plan)
            self.snap["settlement"]["status"] = 2
            with self.assertRaisesRegex(V9AdjudicationError, "state changed"):
                self.client.refresh(plan)

    def mock_snapshot_rpc(self):
        block = {"number": "0x63", "hash": digest(99), "timestamp": hex(self.now)}
        def rpc(method, params):
            if method == "eth_chainId": return hex(31337)
            if method == "eth_blockNumber": return "0x64"
            if method == "eth_getBlockByNumber": return {"hash": digest(10)} if params[0] == "0x0" else block
            if method == "eth_getCode": return "0x6000"
            if method == "eth_call": return "0x" + f"{2:064x}"
            raise AssertionError(method)
        return rpc

    def snapshot_patches(self):
        mapping = {"dispute_policy": self.policy, "adjudicators": list(self.config.adjudicators),
            "settlement_info": self.snap["settlement"], "dispute_info": self.snap["dispute"],
            "report_info": self.snap["report"], "has_reported": False, "dispute_vote": 0,
            "claimable_balance": 40, "token_claimable_balance": 60}
        mocks = {}
        for name, value in mapping.items():
            p = patch("gateway.chain_v9."+name, return_value=value)
            mocks[name] = p.start()
            self.addCleanup(p.stop)
        return mocks

    def test_snapshot_pins_every_call_to_same_confirmed_canonical_block(self):
        mocks = self.snapshot_patches()
        with patch.object(self.client, "rpc", side_effect=self.mock_snapshot_rpc()) as rpc:
            snap = self.client.snapshot(self.settlement_key, address(9), digest(88))
        self.assertEqual(snap["block_number"], 99)
        tag = {"blockHash": digest(99), "requireCanonical": True}
        for mock in mocks.values():
            self.assertEqual(mock.call_args.kwargs["block_tag"], tag)
        for call in rpc.call_args_list:
            if call.args[0] in ("eth_getCode", "eth_call"):
                self.assertEqual(call.args[1][1], tag)

    def test_wrong_chain_genesis_code_policy_committee_stale_or_reorg_fail(self):
        self.snapshot_patches()
        for case in ("chain", "genesis", "code", "stale", "reorg"):
            base = self.mock_snapshot_rpc()
            reads = [0]
            def rpc(method, params):
                result = base(method, params)
                if case == "chain" and method == "eth_chainId": return "0x1"
                if case == "genesis" and method == "eth_getBlockByNumber" and params[0] == "0x0": return {"hash": digest(11)}
                if case == "code" and method == "eth_getCode": return "0x6001"
                if method == "eth_getBlockByNumber" and params[0] != "0x0":
                    reads[0] += 1
                    if case == "stale": result["timestamp"] = hex(self.now-1000)
                    if case == "reorg" and reads[0] > 1: result["hash"] = digest(100)
                return result
            with self.subTest(case=case), patch.object(self.client, "rpc", side_effect=rpc), self.assertRaises(V9AdjudicationError):
                self.client.snapshot(self.settlement_key, address(9))
        with patch.object(self.client, "rpc", side_effect=self.mock_snapshot_rpc()):
            with patch("gateway.chain_v9.dispute_policy", return_value={**self.policy, "reporter_bond": 999}):
                with self.assertRaisesRegex(V9AdjudicationError, "policy or committee"):
                    self.client.snapshot(self.settlement_key, address(9))


class V9OutboxTests(V9Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.key_file = Path(self.directory.name)/"fixture-reporter-key"
        self.key_file.write_text(key(9))
        os.chmod(self.key_file, 0o600)
        self.outbox = V9TransactionOutbox(Path(self.directory.name)/"outbox.sqlite3")
        self.addCleanup(self.outbox.close)
        self.plan = self.report()
        self.send_calls = []
        self.receipt_result = None
        self.raise_send = False
        self.nonce = 0
        self.external_pending = False
        self.refresh_patch = patch.object(self.client, "refresh", return_value=self.plan)
        self.refresh_patch.start()
        self.addCleanup(self.refresh_patch.stop)
        self.rpc_patch = patch.object(self.client, "rpc", side_effect=self.rpc)
        self.rpc_patch.start()
        self.addCleanup(self.rpc_patch.stop)

    def rpc(self, method, params):
        if method == "eth_getTransactionCount": return hex(self.nonce + int(self.external_pending and params[1] == "pending"))
        if method == "eth_gasPrice": return "0x1"
        if method == "eth_estimateGas": return hex(50000)
        if method == "eth_sendRawTransaction":
            self.send_calls.append(params[0])
            if self.raise_send: raise TimeoutError("response lost after accepted")
            return "0x" + chain.keccak256(bytes.fromhex(params[0][2:])).hex()
        if method == "eth_getTransactionReceipt": return self.receipt_result
        if method == "eth_chainId": return hex(31337)
        if method == "eth_getBlockByNumber": return {"hash": digest(10) if params[0] == "0x0" else digest(99)}
        if method == "eth_blockNumber": return hex(100)
        raise AssertionError(method)

    def execute(self, plan=None, **overrides):
        plan = plan or self.plan
        kwargs = dict(allow_send=True, approved_plan_hash=plan["plan_hash"], key_file=self.key_file,
            max_gas_price_wei=10, max_gas_units=100000, max_total_gas_cost_wei=1000000)
        kwargs.update(overrides)
        return self.outbox.execute(self.client, plan, **kwargs)

    def another_plan(self):
        plan = copy.deepcopy(self.plan)
        plan["inputs"]["operator_note"] = "second plan"
        plan.pop("plan_hash")
        plan["plan_hash"] = evidence_hash(plan)
        return plan

    def test_dry_run_reads_no_keys_rpc_or_sender_nonce(self):
        result = self.outbox.execute(self.client, self.plan)
        self.assertEqual(result["sent"], False)
        self.client.rpc.assert_not_called()
        self.client.refresh.assert_not_called()
        self.assertIsNone(self.outbox.get(self.plan["plan_hash"]))

    def test_send_requires_exact_approval_and_all_gas_caps(self):
        for change in ({"approved_plan_hash": digest(9)}, {"key_file": None}, {"max_gas_units": None},
                       {"max_gas_price_wei": 0}, {"max_total_gas_cost_wei": True}):
            with self.subTest(change=change), self.assertRaises(V9AdjudicationError):
                self.execute(**change)
        self.assertEqual(self.send_calls, [])

    def test_protected_dedicated_matching_key_required(self):
        os.chmod(self.key_file, 0o644)
        with self.assertRaises(V9AdjudicationError): self.execute()
        os.chmod(self.key_file, 0o600)
        self.key_file.write_text(key(10))
        with self.assertRaisesRegex(V9AdjudicationError, "does not match"): self.execute()
        self.assertEqual(self.send_calls, [])

    def test_key_symlink_and_outbox_symlink_are_rejected(self):
        alias = Path(self.directory.name)/"key-alias"
        alias.symlink_to(self.key_file)
        with self.assertRaises(V9AdjudicationError): self.execute(key_file=alias)
        alias = Path(self.directory.name)/"db-alias"
        alias.symlink_to(Path(self.directory.name)/"outbox.sqlite3")
        with self.assertRaises(OSError): V9TransactionOutbox(alias)

    def test_persist_before_broadcast_and_exact_once_idempotency(self):
        original = self.rpc
        def rpc(method, params):
            if method == "eth_sendRawTransaction":
                row = self.outbox.get(self.plan["plan_hash"])
                self.assertEqual(row["state"], "sending")
                self.assertEqual(row["tx_hash"], "0x" + chain.keccak256(bytes.fromhex(params[0][2:])).hex())
            return original(method, params)
        self.client.rpc.side_effect = rpc
        first = self.execute()
        self.assertEqual(first["state"], "submitted")
        self.assertNotIn("raw_tx", first)
        self.assertEqual(self.execute(), first)
        self.assertEqual(len(self.send_calls), 1)

    def test_uncertain_send_never_retries_or_uses_another_nonce(self):
        self.raise_send = True
        result = self.execute()
        self.assertEqual(result["state"], "uncertain")
        self.execute()
        with self.assertRaisesRegex(V9AdjudicationError, "unresolved"):
            self.execute(self.another_plan())
        self.assertEqual(len(self.send_calls), 1)
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["state"], "uncertain")

    def test_pending_external_nonce_and_excess_gas_are_rejected(self):
        self.external_pending = True
        with self.assertRaisesRegex(V9AdjudicationError, "external pending"): self.execute()
        self.external_pending = False
        with self.assertRaisesRegex(V9AdjudicationError, "gas exceeds"): self.execute(max_gas_units=30000)
        self.assertEqual(self.send_calls, [])

    def test_wrong_rpc_send_hash_is_uncertain_and_not_retried(self):
        original = self.rpc
        def rpc(method, params):
            result = original(method, params)
            return digest(999) if method == "eth_sendRawTransaction" else result
        self.client.rpc.side_effect = rpc
        self.assertEqual(self.execute()["state"], "uncertain")
        self.assertEqual(self.execute()["state"], "uncertain")
        self.assertEqual(len(self.send_calls), 1)

    def test_reconcile_requires_canonical_confirmed_receipt(self):
        result = self.execute()
        self.receipt_result = {"transactionHash": result["tx_hash"], "blockNumber": hex(99),
                               "blockHash": digest(99), "status": "0x1"}
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["state"], "confirmed")
        self.receipt_result["blockHash"] = digest(100)
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["state"], "uncertain")
        with self.assertRaisesRegex(V9AdjudicationError, "unresolved"):
            self.execute(self.another_plan())

    def test_reverted_transaction_is_terminal_and_not_rebroadcast(self):
        result = self.execute()
        self.receipt_result = {"transactionHash": result["tx_hash"], "blockNumber": hex(99),
                               "blockHash": digest(99), "status": "0x0"}
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["state"], "reverted")
        self.assertEqual(self.execute()["state"], "reverted")
        self.assertEqual(len(self.send_calls), 1)

    def test_insufficient_confirmations_keep_sender_locked(self):
        result = self.execute()
        self.receipt_result = {"transactionHash": result["tx_hash"], "blockNumber": hex(100),
                               "blockHash": digest(99), "status": "0x1"}
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["state"], "submitted")
        with self.assertRaisesRegex(V9AdjudicationError, "unresolved"):
            self.execute(self.another_plan())

    def test_failed_durable_commit_never_broadcasts(self):
        # A separate read-only connection exposes the same durable file but cannot
        # reserve a nonce. No network write may happen after its insert fails.
        self.outbox.db.execute("PRAGMA query_only=ON")
        with self.assertRaises(Exception): self.execute()
        self.assertEqual(self.send_calls, [])
        self.assertIsNone(self.outbox.get(self.plan["plan_hash"]))

    def test_outbox_rejects_memory_and_survives_restart(self):
        with self.assertRaisesRegex(V9AdjudicationError, "durable"):
            V9TransactionOutbox(":memory:")
        self.execute()
        reopened = V9TransactionOutbox(Path(self.directory.name)/"outbox.sqlite3")
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.get(self.plan["plan_hash"])["state"], "submitted")
        self.assertEqual(reopened.execute(self.client, self.plan, allow_send=True,
            approved_plan_hash=self.plan["plan_hash"], key_file=self.key_file, max_gas_price_wei=10,
            max_gas_units=100000, max_total_gas_cost_wei=1000000)["state"], "submitted")
        self.assertEqual(len(self.send_calls), 1)


class V9RealEvidenceBridgeTests(unittest.TestCase):
    def test_real_signed_incident_requires_matching_settled_snapshot(self):
        from tests.test_relay_security_integration import RelaySecurityIntegrationTests
        from gateway.relay import RelaySchedulingError
        rig = RelaySecurityIntegrationTests()
        rig.version, rig.protocol = 9, chain_v9
        rig.setUp()
        self.addCleanup(rig.doCleanups)
        rig.mode = "body_mismatch"
        now = int(time.time())
        with self.assertRaises(RelaySchedulingError):
            rig.run_request()
        incident = rig.incident()
        payment, receipt, _, _, _ = chain_v9.verify_provider_receipt(
            incident["evidence"]["provider_response"]["mycomesh_v9_settlement"], now=now)
        auth = payment["authorization"]
        settlement_key = chain_v9.settlement_key_for(rig.key_address, auth["key"], auth["request_id"])
        policy = {"reporter_bond": 500, "bond_penalty_recipient": address(80)}
        config = V9OperatorConfig(rpc_url="http://127.0.0.1:18545", chain_id=11155111,
            settlement_contract=rig.contract, runtime_code_hash=digest(91), genesis_hash=digest(92),
            policy_hash=evidence_hash(policy), adjudicators=(address(101), address(102), address(103)),
            adjudicator_operators={address(x): f"synthetic-fixture-operator-{x}" for x in (101, 102, 103)},
            independence_attested=True, threshold=2, observer_public_key=rig.state._scheduler_identity.public_key,
            reporter_address=address(99), confirmations=1)
        client = V9AdjudicationClient(config)
        # Only the chain read is a fixture; Provider registration EVM binding,
        # transport signature, Relay observation, payment and receipt are real.
        record = {"owner": rig.key_address, "key": auth["key"], "request_id": auth["request_id"],
            "request_hash": auth["request_hash"], "relay_signer": auth["relay_signer"],
            "provider": receipt.provider, "provider_signer": receipt.provider_signer,
            "relay": receipt.relay, "pool": receipt.pool, "authorization_hash": receipt.authorization_hash,
            "response_hash": receipt.response_hash, "gross_fee": receipt.actual_fee,
            "settled_at": now, "release_at": now+100, "status": 0}
        snapshot = {"actor": config.reporter_address, "settlement": record, "timestamp": now,
                    "settlement_key": settlement_key, "policy": policy, "has_reported": False}
        with patch.object(client, "snapshot", return_value=snapshot):
            with self.assertRaisesRegex(V9AdjudicationError, "actually settled"):
                client.plan_report(incident=incident, observed_at=now, settlement_key=settlement_key)
            record["status"] = 1
            plan = client.plan_report(incident=incident, observed_at=now, settlement_key=settlement_key)
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["monetary_verdict"])
        self.assertEqual(plan["transaction"]["data"], chain_v9.encode_open_dispute(settlement_key, incident["record_hash"]))


if __name__ == "__main__":
    unittest.main()
