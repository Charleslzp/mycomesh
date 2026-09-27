from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from gateway import chain_v10, provider_jury
from gateway.provider_jury_chain import JURY_REQUESTED_TOPIC, JURY_UNAVAILABLE_TOPIC
from gateway.provider_jury_intake import (
    DISPUTE_OPENED_TOPIC,
    DISPUTE_RESOLVED_TOPIC,
    EVIDENCE_SUBMITTED_TOPIC,
    ProviderJuryEventIntake,
    ProviderJuryEventIntakeConfig,
    ProviderJuryIntakeError,
    RECEIPT_ESCROWED_TOPIC,
)
from gateway.relay_incidents import evidence_hash
from tests.test_chain_v9 import address, digest


def word(value: int) -> str:
    return f"{value:064x}"


def address_word(value: str) -> str:
    return value[2:].zfill(64)


def address_topic(value: str) -> str:
    return "0x" + address_word(value)


class FakeRuntime:
    def __init__(self, config: ProviderJuryEventIntakeConfig) -> None:
        self.worker = SimpleNamespace(
            network_id=config.network_id,
            chain_id=config.chain_id,
            settlement_contract=config.settlement_contract,
            jury_registry=config.jury_registry,
            required_confirmations=config.confirmations,
        )
        self.calls: list[tuple[str, dict, dict]] = []
        self.reconcile_calls: list[str] = []
        self.status = "confirmed"

    def process_case(self, settlement_key, evidence, document):
        self.calls.append((
            settlement_key, copy.deepcopy(evidence), copy.deepcopy(document),
        ))
        return {"status": self.status, "settlement_key": settlement_key}

    def reconcile_case(self, settlement_key):
        self.reconcile_calls.append(settlement_key)
        return {"status": self.status, "settlement_key": settlement_key}


class FakeRPC:
    def __init__(self, *, chain_id: int, head: int = 20) -> None:
        self.chain_id = chain_id
        self.head = head
        self.timestamp_base = 1_500
        self.hashes = {number: digest(number) for number in range(head + 20)}
        self.logs: list[dict] = []
        self.duplicate_logs = False
        self.ignore_topic_filter = False
        self.ignore_address_filter = False
        self.requests: list[tuple[str, list]] = []

    def __call__(self, method, params):
        self.requests.append((method, copy.deepcopy(params)))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            number = int(params[0], 16)
            return {
                "number": hex(number), "hash": self.hashes[number],
                "timestamp": hex(self.timestamp_base + number),
            }
        if method == "eth_getLogs":
            event_filter = params[0]
            start = int(event_filter["fromBlock"], 16)
            end = int(event_filter["toBlock"], 16)
            allowed = set(event_filter["topics"][0])
            selected = [
                copy.deepcopy(item) for item in self.logs
                if start <= int(item["blockNumber"], 16) <= end
                and (self.ignore_address_filter
                     or item["address"] == event_filter["address"])
                and (self.ignore_topic_filter or item["topics"][0] in allowed)
            ]
            return selected + (copy.deepcopy(selected) if self.duplicate_logs else [])
        raise AssertionError(method)


class ProviderJuryEventIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "jury-intake.sqlite3"
        self.settlement = address(50)
        self.registry = address(51)
        self.owner = address(1)
        self.provider = address(2)
        self.reporter = self.owner
        self.settlement_key = digest(100)
        self.request_id = digest(101)
        self.transaction_hash = digest(102)
        self.config = ProviderJuryEventIntakeConfig(
            network_id="fixture",
            rpc_url="https://rpc.invalid",
            chain_id=31337,
            genesis_hash=digest(9_000),
            settlement_contract=self.settlement,
            jury_registry=self.registry,
            deployment_block=10,
            confirmations=2,
            max_scan_blocks=20,
        )
        self.rpc = FakeRPC(chain_id=self.config.chain_id)
        self.rpc.hashes[0] = self.config.genesis_hash
        self.documents: dict[str, dict] = {}
        self.evidence_by_report: dict[str, dict] = {}
        report_id = self.add_case_events(seed=1)
        self.initial_report_id = report_id
        self.runtime = FakeRuntime(self.config)
        self.intakes: list[ProviderJuryEventIntake] = []
        self.intake = self.make_intake()
        self.addCleanup(self.close_intakes)

    def close_intakes(self) -> None:
        for intake in self.intakes:
            intake.close()

    def make_document(self, seed: int) -> dict:
        return {
            "schema": provider_jury.EVIDENCE_DOCUMENT_SCHEMA,
            "settlement_key": self.settlement_key,
            "reporter": self.reporter,
            "origin_relay_public_key": "11" * 32,
            "allegation": {"code": f"fixture-{seed}", "summary": "mismatch"},
            "request": {
                "request_id": self.request_id,
                "endpoint": "responses",
                "model": "fixture-model",
                "input": "hello",
                "messages": None,
                "max_output_tokens": 32,
                "options": {},
            },
            "provider_response": {"ok": True, "fixture": seed},
        }

    def event(self, *, address_value: str, topics: list[str], data: str,
              block: int, log_index: int, transaction_hash: str | None = None,
              removed: bool = False) -> dict:
        return {
            "address": address_value,
            "topics": topics,
            "data": data,
            "blockNumber": hex(block),
            "blockHash": self.rpc.hashes[block],
            "transactionHash": transaction_hash or self.transaction_hash,
            "transactionIndex": "0x0",
            "logIndex": hex(log_index),
            "removed": removed,
        }

    def add_case_events(self, *, seed: int, block: int = 12) -> str:
        document = self.make_document(seed)
        committed = evidence_hash(document)
        report_id = chain_v10.report_id_for(
            self.settlement_key, self.reporter, committed,
        )
        self.documents[report_id] = document
        self.evidence_by_report[report_id] = {
            "report_id": report_id,
            "evidence_hash": committed,
            "request_hash": digest(200 + seed),
            "response_hash": digest(300 + seed),
        }
        if not any(item["topics"][0] == RECEIPT_ESCROWED_TOPIC for item in self.rpc.logs):
            self.rpc.logs.append(self.event(
                address_value=self.settlement,
                topics=[
                    RECEIPT_ESCROWED_TOPIC, self.settlement_key, self.request_id,
                    address_topic(self.owner),
                ],
                data="0x" + address_word(self.provider) + word(100) + word(1_000),
                block=11,
                log_index=0,
                transaction_hash=digest(99),
            ))
        self.rpc.logs.extend([
            self.event(
                address_value=self.settlement,
                topics=[
                    EVIDENCE_SUBMITTED_TOPIC, self.settlement_key, report_id,
                    address_topic(self.reporter),
                ],
                data="0x" + committed[2:] + word(5),
                block=block,
                log_index=0,
            ),
            self.event(
                address_value=self.registry,
                topics=[JURY_REQUESTED_TOPIC, self.settlement_key, digest(seed)],
                data="0x" + word(block + 1) + digest(400 + seed)[2:],
                block=block,
                log_index=1,
            ),
            self.event(
                address_value=self.settlement,
                topics=[DISPUTE_OPENED_TOPIC, self.settlement_key],
                data="0x" + word(2_000),
                block=block,
                log_index=2,
            ),
        ])
        return report_id

    def resolver(self, snapshot):
        report_id = snapshot["evidence"]["payload"]["report_id"]
        return {
            "evidence": copy.deepcopy(self.evidence_by_report[report_id]),
            "evidence_document": copy.deepcopy(self.documents[report_id]),
        }

    def make_intake(self, *, runtime=None) -> ProviderJuryEventIntake:
        intake = ProviderJuryEventIntake(
            self.database,
            config=self.config,
            resolve_evidence=self.resolver,
            runtime=runtime or self.runtime,
            rpc=self.rpc,
        )
        self.intakes.append(intake)
        return intake

    def test_confirmed_events_are_durable_deduplicated_and_delivered_once(self):
        self.rpc.duplicate_logs = True
        synced = self.intake.sync_once()
        self.assertEqual(synced["events"], 4)
        self.assertEqual(synced["jobs"], 1)
        result = self.intake.dispatch_once()
        self.assertEqual(result["state"], "completed")
        self.assertEqual(len(self.runtime.calls), 1)
        self.assertEqual(self.runtime.calls[0][0], self.settlement_key)
        self.assertEqual(self.runtime.calls[0][1]["report_id"], self.initial_report_id)
        self.assertIsNone(self.intake.dispatch_once())
        self.assertTrue(self.intake.health()["ready"])

    def test_non_owner_evidence_report_fails_closed_before_cursor_commit(self):
        evidence = next(
            item for item in self.rpc.logs
            if item["topics"][0] == EVIDENCE_SUBMITTED_TOPIC
        )
        committed = "0x" + evidence["data"][2:66]
        outsider = address(3)
        evidence["topics"][2] = chain_v10.report_id_for(
            self.settlement_key, outsider, committed,
        )
        evidence["topics"][3] = address_topic(outsider)
        with self.assertRaisesRegex(ProviderJuryIntakeError, "differs from the escrow owner"):
            self.intake.sync_once()
        self.assertEqual(self.intake.health()["cursor"]["block_number"], 9)
        self.assertIsNone(self.intake.job(self.settlement_key))

    def test_multiple_evidence_reports_fail_closed_instead_of_selecting_first(self):
        evidence = next(
            item for item in self.rpc.logs
            if item["topics"][0] == EVIDENCE_SUBMITTED_TOPIC
        )
        extra = copy.deepcopy(evidence)
        committed = digest(777)
        extra["topics"][2] = chain_v10.report_id_for(
            self.settlement_key, self.owner, committed,
        )
        extra["data"] = "0x" + committed[2:] + word(5)
        extra["transactionHash"] = digest(778)
        extra["logIndex"] = "0x3"
        self.rpc.logs.append(extra)
        with self.assertRaisesRegex(ProviderJuryIntakeError, "exactly one"):
            self.intake.sync_once()
        self.assertEqual(self.intake.health()["cursor"]["block_number"], 9)
        self.assertIsNone(self.intake.job(self.settlement_key))

    def test_removed_wrong_address_and_wrong_topic_never_advance_cursor(self):
        mutations = (
            ("removed", lambda log: log.update(removed=True), False),
            ("address", lambda log: log.update(address=address(99)), True),
            ("topic", lambda log: log["topics"].__setitem__(0, digest(999)), False),
        )
        for name, mutate, ignore_address in mutations:
            with self.subTest(case=name):
                database = Path(self.temporary.name) / f"bad-{len(self.intakes)}.sqlite3"
                original = copy.deepcopy(self.rpc.logs)
                target = next(item for item in self.rpc.logs if item["topics"][0] == DISPUTE_OPENED_TOPIC)
                mutate(target)
                self.rpc.ignore_topic_filter = True
                self.rpc.ignore_address_filter = ignore_address
                intake = ProviderJuryEventIntake(
                    database, config=self.config, resolve_evidence=self.resolver,
                    runtime=self.runtime, rpc=self.rpc,
                )
                self.intakes.append(intake)
                with self.assertRaises(ProviderJuryIntakeError):
                    intake.sync_once()
                self.assertEqual(intake.health()["cursor"]["block_number"], 9)
                self.rpc.logs = original
                self.rpc.ignore_topic_filter = False
                self.rpc.ignore_address_filter = False

    def test_unconfirmed_log_is_not_queried_or_materialized(self):
        self.rpc.head = 12  # block 12 has only one confirmation
        first = self.intake.sync_once()
        self.assertEqual(first["through_block"], 11)
        self.assertIsNone(self.intake.job(self.settlement_key))
        log_filters = [params[0] for method, params in self.rpc.requests if method == "eth_getLogs"]
        self.assertTrue(log_filters)
        self.assertTrue(all(item["toBlock"] == "0xb" for item in log_filters))
        self.rpc.head = 13
        second = self.intake.sync_once()
        self.assertEqual(second["through_block"], 12)
        self.assertEqual(self.intake.job(self.settlement_key)["state"], "pending")

    def test_unavailable_assignment_does_not_create_runtime_job(self):
        requested = next(
            item for item in self.rpc.logs
            if item["topics"][0] == JURY_REQUESTED_TOPIC
        )
        requested["topics"][0] = JURY_UNAVAILABLE_TOPIC
        requested["data"] = "0x" + word(2)
        synced = self.intake.sync_once()
        self.assertEqual(synced["events"], 4)
        self.assertIsNone(self.intake.job(self.settlement_key))
        self.assertIsNone(self.intake.dispatch_once())
        self.assertEqual(self.runtime.calls, [])

    def test_canonical_resolution_before_delivery_suppresses_runtime(self):
        self.rpc.logs.append(self.event(
            address_value=self.settlement,
            topics=[DISPUTE_RESOLVED_TOPIC, self.settlement_key],
            data="0x" + word(4) + word(10) + word(2),
            block=13,
            log_index=0,
            transaction_hash=digest(103),
        ))
        self.intake.sync_once()
        self.assertEqual(self.intake.job(self.settlement_key)["state"], "chain_resolved")
        self.assertIsNone(self.intake.dispatch_once())
        self.assertEqual(self.runtime.calls, [])

    def test_cursor_and_processing_delivery_recover_after_restart(self):
        self.intake.sync_once()
        self.intake.db.execute(
            "UPDATE provider_jury_intake_jobs SET state='processing',dispatched_at=123"
        )
        self.intake.close()
        restarted_runtime = FakeRuntime(self.config)
        reopened = self.make_intake(runtime=restarted_runtime)
        self.assertEqual(reopened.health()["cursor"]["block_number"], 19)
        self.assertEqual(reopened.job(self.settlement_key)["state"], "active")
        reopened.dispatch_once()
        self.assertEqual(len(restarted_runtime.calls), 1)
        self.assertEqual(reopened.job(self.settlement_key)["state"], "completed")

    def test_runtime_delivery_waits_for_confirmed_evidence_window(self):
        self.rpc.timestamp_base = 0
        self.intake.sync_once()
        waiting = self.intake.dispatch_once()
        self.assertEqual(waiting["state"], "waiting_evidence_window")
        self.assertEqual(len(self.runtime.calls), 0)
        self.assertIsNone(self.intake.job(self.settlement_key)["dispatched_at"])
        self.rpc.timestamp_base = 1_000
        delivered = self.intake.dispatch_once()
        self.assertEqual(delivered["state"], "completed")
        self.assertEqual(len(self.runtime.calls), 1)

    def test_submitted_case_reconciles_after_window_across_restart(self):
        self.runtime.status = "submitted"
        self.rpc.timestamp_base = 1_979
        self.intake.sync_once()
        first = self.intake.dispatch_once()
        self.assertEqual(first["state"], "active")
        self.assertEqual(self.intake.job(self.settlement_key)["state"], "active")
        self.assertEqual(len(self.runtime.calls), 1)

        self.intake.close()
        self.rpc.logs.append(self.event(
            address_value=self.settlement,
            topics=[DISPUTE_RESOLVED_TOPIC, self.settlement_key],
            data="0x" + word(4) + word(10) + word(2),
            block=20,
            log_index=0,
            transaction_hash=digest(103),
        ))
        self.rpc.head = 22
        restarted_runtime = FakeRuntime(self.config)
        restarted_runtime.status = "confirmed"
        reopened = self.make_intake(runtime=restarted_runtime)
        reopened.sync_once()
        self.assertEqual(reopened.job(self.settlement_key)["state"], "active")
        reconciled = reopened.dispatch_once()
        self.assertEqual(reconciled["state"], "completed")
        self.assertEqual(restarted_runtime.reconcile_calls, [self.settlement_key])
        self.assertEqual(restarted_runtime.calls, [])

    def test_admitted_case_expires_after_window_without_collecting_again(self):
        self.runtime.status = "admitted"
        self.intake.sync_once()
        first = self.intake.dispatch_once()
        self.assertEqual(first["state"], "active")
        self.rpc.timestamp_base = 3_000
        expired = self.intake.dispatch_once()
        self.assertEqual(expired["state"], "expired")
        self.assertEqual(self.intake.job(self.settlement_key)["state"], "expired")
        self.assertEqual(self.runtime.reconcile_calls, [self.settlement_key])
        self.assertEqual(len(self.runtime.calls), 1)

    def test_active_recovery_state_reconciles_without_dispatch_marker(self):
        self.runtime.status = "submitted"
        self.intake.sync_once()
        self.intake.db.execute(
            "UPDATE provider_jury_intake_jobs SET state='active',dispatched_at=NULL"
        )
        self.rpc.timestamp_base = 3_000
        reconciled = self.intake.dispatch_once()
        self.assertEqual(reconciled["state"], "active")
        self.assertEqual(self.runtime.reconcile_calls, [self.settlement_key])
        self.assertEqual(self.runtime.calls, [])

    def test_pending_case_expires_without_runtime_delivery_after_window(self):
        self.intake.sync_once()
        self.rpc.timestamp_base = 3_000
        self.assertIsNone(self.intake.dispatch_once())
        self.assertEqual(self.intake.job(self.settlement_key)["state"], "expired")
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.runtime.reconcile_calls, [])

    def test_runtime_delivery_requires_cursor_at_current_confirmed_head(self):
        self.intake.sync_once()
        self.rpc.head += 1
        with self.assertRaisesRegex(ProviderJuryIntakeError, "not caught up"):
            self.intake.dispatch_once()
        self.assertEqual(len(self.runtime.calls), 0)
        self.assertFalse(self.intake.health()["ready"])
        self.intake.sync_once()
        self.intake.dispatch_once()
        self.assertEqual(len(self.runtime.calls), 1)

    def test_pending_case_rolls_back_and_replays_on_new_canonical_fork(self):
        self.intake.sync_once()
        self.assertEqual(self.intake.job(self.settlement_key)["report_id"], self.initial_report_id)
        self.rpc.logs = [
            item for item in self.rpc.logs if int(item["blockNumber"], 16) < 12
        ]
        for number in range(12, self.rpc.head + 1):
            self.rpc.hashes[number] = digest(1_000 + number)
        replacement = self.add_case_events(seed=2)
        replay = self.intake.sync_once()
        self.assertEqual(replay["from_block"], 12)
        self.assertEqual(self.intake.job(self.settlement_key)["report_id"], replacement)
        self.intake.dispatch_once()
        self.assertEqual(self.runtime.calls[0][1]["report_id"], replacement)

    def test_reorg_after_runtime_delivery_persistently_halts(self):
        self.intake.sync_once()
        self.intake.dispatch_once()
        for number in range(12, self.rpc.head + 1):
            self.rpc.hashes[number] = digest(2_000 + number)
        with self.assertRaisesRegex(ProviderJuryIntakeError, "after runtime delivery"):
            self.intake.sync_once()
        self.assertEqual(self.intake.job(self.settlement_key)["state"], "orphaned")
        self.assertFalse(self.intake.health()["ready"])
        self.assertTrue(self.intake.health()["halted"])
        self.intake.close()
        reopened = self.make_intake(runtime=FakeRuntime(self.config))
        self.assertEqual(reopened.health()["error_code"], "reorg_after_runtime_delivery")
        self.assertTrue(reopened.health()["halted"])
        with self.assertRaisesRegex(ProviderJuryIntakeError, "operator reconciliation"):
            reopened.dispatch_once()

    def test_wrong_chain_and_resolver_mismatch_fail_closed(self):
        self.rpc.chain_id = 1
        with self.assertRaisesRegex(ProviderJuryIntakeError, "chain differs"):
            self.intake.sync_once()
        self.assertEqual(self.intake.health()["cursor"]["block_number"], 9)
        self.rpc.chain_id = self.config.chain_id
        self.intake.sync_once()
        self.evidence_by_report[self.initial_report_id]["evidence_hash"] = digest(999)
        with self.assertRaisesRegex(ProviderJuryIntakeError, "canonical on-chain report"):
            self.intake.dispatch_once()
        self.assertEqual(len(self.runtime.calls), 0)
        self.assertIsNone(self.intake.job(self.settlement_key)["dispatched_at"])


if __name__ == "__main__":
    unittest.main()
