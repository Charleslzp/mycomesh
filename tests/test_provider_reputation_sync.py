from __future__ import annotations

import copy
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import time
import unittest

from gateway import chain, pool, provider_jury
from gateway.identity import create_identity, sign_document
from gateway.provider_identity_binding import build_provider_identity_binding
from gateway.provider_reputation_sync import (
    PROVIDER_UPDATED_TOPIC,
    ProviderReputationOutbox,
    ProviderReputationSync,
    ProviderReputationSyncConfig,
    ProviderReputationSyncError,
    ReputationHistoryImport,
    SNAPSHOT_PURPOSE,
    build_pool_reputation_snapshot,
)
from gateway.relay_incidents import evidence_hash
from gateway.v10_reputation import (
    DISPUTE_RESOLVED_TOPIC,
    FEEDBACK_SCHEMA,
    SETTLEMENT_RELEASED_TOPIC,
    V9_DISPUTE_RESOLVED_TOPIC,
    V10ReputationError,
    reputation_event_id,
)
from tests.test_chain_v9 import address, digest, key, signer


def abi(*values: object) -> str:
    return "0x" + b"".join(chain.abi_encode_arg(str(value)) for value in values).hex()


def topic_address(value: str) -> str:
    return "0x" + "00" * 12 + value[2:]


class FakeRegistryRPC:
    def __init__(self, case: "ProviderReputationSyncTests") -> None:
        self.case = case
        self.head = 100
        self.pending_assignments = 0
        self.send_error: Exception | None = None
        self.sent = 0
        self.tx_hash: str | None = None
        self.tx: dict | None = None
        self.receipt: dict | None = None
        self.provider_state: dict | None = None
        self.provider_source_state: dict | None = None
        self.authority = case.authority
        self.registry_settlement = case.settlement
        self.settlement_registry = case.registry

    def block(self, number: int) -> dict:
        return {
            "number": hex(number), "hash": digest(10_000 + number),
            "timestamp": hex(self.case.now),
        }

    def __call__(self, method: str, params: list):
        if method == "eth_chainId":
            return hex(self.case.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            tag = params[0]
            if tag == "0x0":
                return {"number": "0x0", "hash": self.case.genesis,
                        "timestamp": hex(self.case.now)}
            return self.block(int(tag, 16))
        if method == "eth_getCode":
            if params[0] == self.case.registry:
                return "0x" + self.case.runtime.hex()
            if params[0] == self.case.settlement:
                tag = params[1]
                if (
                    isinstance(tag, dict)
                    and tag.get("blockHash")
                    == self.block(self.case.settlement_deployment_block - 1)["hash"]
                ):
                    return "0x"
                return "0x" + self.case.settlement_runtime.hex()
            history = self.case.history_for_rpc
            if history is not None and params[0] == history.source_settlement_contract:
                tag = params[1]
                if tag["blockHash"] == self.block(
                    history.source_deployment_block - 1,
                )["hash"]:
                    return "0x"
                return "0x" + self.case.history_runtime.hex()
            raise AssertionError(f"unexpected code target {params[0]}")
        if method == "eth_getLogs":
            request = params[0]
            if request["address"] == self.case.settlement:
                start = int(request["fromBlock"], 16)
                end = int(request["toBlock"], 16)
                logs = []
                for event in self.case.live_chain_events:
                    if not start <= event["block_number"] <= end:
                        continue
                    status = {
                        "released": 3,
                        "confirmed": 4,
                        "dismissed": 5,
                        "timed_out": 6,
                        "jury_unavailable": 7,
                    }[event["terminal_status"]]
                    dispute = status != 3
                    words = [status, 0, 0] if dispute else [status]
                    logs.append({
                        "address": self.case.settlement,
                        "topics": [
                            DISPUTE_RESOLVED_TOPIC
                            if dispute else SETTLEMENT_RELEASED_TOPIC,
                            event["settlement_key"],
                        ],
                        "data": "0x" + b"".join(
                            word.to_bytes(32, "big") for word in words
                        ).hex(),
                        "transactionHash": event["tx_hash"],
                        "blockNumber": hex(event["block_number"]),
                        "blockHash": event["block_hash"],
                        "logIndex": hex(event["log_index"]),
                        "removed": False,
                    })
                return logs
            history = self.case.history_for_rpc
            if history is None:
                return []
            start = int(request["fromBlock"], 16)
            end = int(request["toBlock"], 16)
            logs = []
            chain_events = [
                event
                for events in history.entries.values()
                for event in events
            ] + list(self.case.history_extra_events)
            for event in chain_events:
                if start <= event["block_number"] <= end:
                    negative = event["terminal_status"] == "confirmed"
                    topic = (
                        V9_DISPUTE_RESOLVED_TOPIC
                        if negative else SETTLEMENT_RELEASED_TOPIC
                    )
                    words = [4, 0, 0, 0] if negative else [3]
                    logs.append({
                        "address": history.source_settlement_contract,
                        "topics": [topic, event["settlement_key"]],
                        "data": "0x" + b"".join(
                            word.to_bytes(32, "big") for word in words
                        ).hex(),
                        "transactionHash": event["tx_hash"],
                        "blockNumber": hex(event["block_number"]),
                        "blockHash": event["block_hash"],
                        "logIndex": hex(event["log_index"]),
                        "removed": False,
                    })
            return logs
        if method == "eth_call":
            transaction = params[0]
            data = transaction["data"]
            selector = data[:10]
            if selector == chain.encode_contract_call("reputationAuthority()", [])[:10]:
                return abi(self.authority)
            if selector == chain.encode_contract_call("minimumReputation()", [])[:10]:
                return abi(self.case.minimum_reputation)
            if selector == chain.encode_contract_call("pendingAssignments()", [])[:10]:
                return abi(self.pending_assignments)
            if selector == chain.encode_contract_call("settlement()", [])[:10]:
                self.case.assertEqual(transaction["to"], self.case.registry)
                return abi(self.registry_settlement)
            if selector == chain.encode_contract_call("juryRegistry()", [])[:10]:
                self.case.assertEqual(transaction["to"], self.case.settlement)
                return abi(self.settlement_registry)
            settlement_info_selector = chain.encode_contract_call(
                "settlementInfo(bytes32)", [digest(1)],
            )[:10]
            if selector == settlement_info_selector:
                self.case.assertEqual(transaction["to"], self.case.settlement)
                settlement_key = "0x" + data[10:74]
                matches = [
                    event for event in self.case.live_chain_events
                    if event["settlement_key"] == settlement_key
                ]
                if len(matches) != 1:
                    raise AssertionError("unknown or duplicate live settlement")
                event = matches[0]
                status = {
                    "released": 3,
                    "confirmed": 4,
                    "dismissed": 5,
                    "timed_out": 6,
                    "jury_unavailable": 7,
                }[event["terminal_status"]]
                return abi(
                    address(1), address(2), event["provider_owner"],
                    event["provider_signer"], address(3), address(4),
                    address(5), address(6), event["request_id"],
                    digest(20_001), digest(20_002), digest(20_003),
                    1, 1, 0, 0, 0, 1, 1, status,
                )
            if selector == chain.encode_contract_call("providerForOwner(address)", [self.case.owner])[:10]:
                if self.provider_state is None:
                    raise AssertionError("provider state was requested before mining")
                p = self.provider_state
                return abi(
                    p["owner"], p["vote_signer"], p["operator_id_hash"],
                    p["peer_id_hash"], p["capability_hash"],
                    p["reputation"], p["active"],
                )
            if selector == chain.encode_contract_call("providerSourceSequence(address)", [self.case.owner])[:10]:
                if self.provider_source_state is None:
                    raise AssertionError("provider source state was requested before mining")
                return abi(self.provider_source_state["sequence"])
            if selector == chain.encode_contract_call("providerSourceDigest(address)", [self.case.owner])[:10]:
                if self.provider_source_state is None:
                    raise AssertionError("provider source state was requested before mining")
                return abi(self.provider_source_state["digest"])
            set_provider_selector = "0x" + chain.keccak256(
                b"setProvider((address,address,bytes32,bytes32,bytes32,uint64,bool),uint64,bytes32)"
            )[:4].hex()
            if selector == set_provider_selector:
                return "0x"
            raise AssertionError(f"unexpected eth_call selector {selector}")
        if method == "eth_getTransactionCount":
            return "0x0"
        if method == "eth_gasPrice":
            return hex(2)
        if method == "eth_estimateGas":
            return hex(100_000)
        if method == "eth_sendRawTransaction":
            self.sent += 1
            if self.send_error is not None:
                raise self.send_error
            raw = bytes.fromhex(params[0][2:])
            self.tx_hash = "0x" + chain.keccak256(raw).hex()
            return self.tx_hash
        if method == "eth_getTransactionByHash":
            self.case.assertEqual(params[0], self.tx_hash)
            return self.tx
        if method == "eth_getTransactionReceipt":
            self.case.assertEqual(params[0], self.tx_hash)
            return self.receipt
        raise AssertionError(f"unexpected RPC method {method}")

    def mine(self, action: dict, *, status: int = 1, confirmations: int = 4) -> None:
        assert self.tx_hash is not None
        block_number = 99
        self.head = block_number + confirmations - 1
        block_hash = self.block(block_number)["hash"]
        self.provider_state = dict(action["provider"])
        self.provider_source_state = {
            "sequence": action["source"]["sequence"],
            "digest": action["source"]["source_digest"],
        }
        self.tx = {
            "hash": self.tx_hash, "from": self.case.authority,
            "to": self.case.registry, "nonce": "0x0", "value": "0x0",
            "input": action["calldata"], "chainId": hex(self.case.chain_id),
            "blockNumber": hex(block_number), "blockHash": block_hash,
        }
        p = action["provider"]
        log = {
            "address": self.case.registry,
            "topics": [
                PROVIDER_UPDATED_TOPIC, topic_address(p["owner"]),
                topic_address(p["vote_signer"]), p["operator_id_hash"],
            ],
            "data": abi(
                p["reputation"], p["active"],
                action["source"]["sequence"], action["source"]["source_digest"], 7,
            ),
            "transactionHash": self.tx_hash, "blockHash": block_hash,
            "blockNumber": hex(block_number), "logIndex": "0x0", "removed": False,
        }
        self.receipt = {
            "transactionHash": self.tx_hash, "blockHash": block_hash,
            "blockNumber": hex(block_number), "status": hex(status),
            "from": self.case.authority, "to": self.case.registry,
            "logs": [log],
        }


class StructuralEventVerifier:
    def __init__(self, config) -> None:
        self.config = config

    def verify(self, event, *, peer):
        if (
            event["peer_id"] != peer["peer_id"]
            or event["provider_signer"] != peer["settlement"]["provider_signer"]
            or (
                self.config.require_provider_owner_match
                and event["provider_owner"] != peer["payment_address"]
            )
        ):
            raise V10ReputationError("event identity mismatch")
        return {**event, "event_id": reputation_event_id(event)}


class ProviderReputationSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.now = int(time.time())
        self.chain_id = 31337
        self.genesis = digest(1)
        self.registry = address(51)
        self.settlement = address(50)
        self.authority = signer(9)
        self.owner = address(100)
        self.vote_signer = signer(20)
        self.minimum_reputation = 100
        self.runtime = b"\x60\x00\x60\x00"
        self.settlement_runtime = b"\x60\x00"
        self.settlement_deployment_block = 50
        self.history_runtime = b"\x60\x09"
        self.history_for_rpc: ReputationHistoryImport | None = None
        self.history_extra_events: list[dict] = []
        self.policy_hash = digest(8)
        self.pool_identity = create_identity()
        self.provider_identity = create_identity()
        self.capability = {
            "schema": provider_jury.CAPABILITY_SCHEMA,
            "models": ["judge-model"], "max_output_tokens": 1024,
            "supports_structured_verdict": True,
            "decision_policy_hash": self.policy_hash,
        }
        self.pool_config = pool.PoolConfig(reputation_path=None)
        proofs = [self.reputation_event(70 + index) for index in range(5)]
        self.live_chain_events = copy.deepcopy(proofs)
        self.pool_config.reputation[self.provider_identity.peer_id] = {
            "settlements": 5, "successes": 5,
        }
        self.pool_config.reputation_events[self.provider_identity.peer_id] = {
            reputation_event_id(event) for event in proofs
        }
        self.pool_config.reputation_proofs[self.provider_identity.peer_id] = {
            reputation_event_id(event): event for event in proofs
        }
        self.config = ProviderReputationSyncConfig(
            network_id="fixture", rpc_url="http://rpc.invalid", chain_id=self.chain_id,
            genesis_hash=self.genesis, settlement_contract=self.settlement,
            settlement_runtime_code_hash="0x" + chain.keccak256(
                self.settlement_runtime,
            ).hex(),
            settlement_deployment_block=self.settlement_deployment_block,
            settlement_deployment_block_hash=digest(
                10_000 + self.settlement_deployment_block,
            ),
            jury_registry=self.registry,
            registry_runtime_code_hash="0x" + chain.keccak256(self.runtime).hex(),
            minimum_reputation=self.minimum_reputation,
            decision_policy_hash=self.policy_hash,
            pool_snapshot_public_keys=(self.pool_identity.public_key,),
            snapshot_audience=self.registry,
            descriptor_audience="https://pool.example",
            confirmations=3,
            rpc_urls=("http://rpc.invalid", "http://rpc2.invalid"),
            allow_insecure_test_rpc=True,
        )
        self.rpc = FakeRegistryRPC(self)
        self.key_path = self.root / "authority.key"
        self.key_path.write_text(key(9) + "\n", encoding="ascii")
        os.chmod(self.key_path, 0o600)
        self.verifier_factory = (
            lambda verifier_config, _rpc: StructuralEventVerifier(verifier_config)
        )

    def reputation_event(self, number: int, *, peer_id: str | None = None) -> dict:
        return {
            "schema": FEEDBACK_SCHEMA,
            "network_id": "fixture",
            "chain_id": self.chain_id,
            "settlement_contract": self.settlement,
            "settlement_key": digest(1_000 + number),
            "request_id": digest(2_000 + number),
            "provider_owner": self.owner,
            "provider_signer": self.vote_signer,
            "peer_id": peer_id or self.provider_identity.peer_id,
            "tx_hash": digest(3_000 + number),
            "log_index": 0,
            "block_number": number,
            "block_hash": digest(10_000 + number),
            "terminal_status": "released",
            "outcome": "positive",
        }

    def snapshot(
        self, *, sequence: int = 1, now: int | None = None,
        history_import: ReputationHistoryImport | None = None,
    ) -> dict:
        return build_pool_reputation_snapshot(
            self.pool_config, peer_id=self.provider_identity.peer_id,
            network_id="fixture", sequence=sequence,
            pool_identity=self.pool_identity, audience=self.registry,
            now=self.now if now is None else now, ttl_seconds=300,
            history_import=history_import,
        )

    def history_import(
        self, *, provider_signer: str | None = None,
    ) -> ReputationHistoryImport:
        event = {
            **self.reputation_event(60),
            "network_id": "fixture-v9-history",
            "settlement_contract": address(49),
            "provider_owner": address(777),
            "provider_signer": provider_signer or self.vote_signer,
        }
        history = ReputationHistoryImport(
            source_network_id="fixture-v9-history",
            source_protocol_version=9,
            source_chain_id=self.chain_id,
            source_genesis_hash=self.genesis,
            source_settlement_contract=address(49),
            source_runtime_code_hash="0x" + chain.keccak256(
                self.history_runtime,
            ).hex(),
            confirmations=6,
            source_deployment_block=10,
            source_deployment_block_hash=self.rpc.block(10)["hash"],
            source_history_through_block=95,
            source_history_through_block_hash=self.rpc.block(95)["hash"],
            artifact_sha256="1" * 64,
            artifact_root=digest(9_998),
            entries={self.provider_identity.peer_id: (event,)},
        )
        return history

    def test_snapshot_event_commitment_is_scoped_per_peer(self) -> None:
        first = self.snapshot()
        other_peer = "another-provider-peer"
        other_event = self.reputation_event(90, peer_id=other_peer)
        self.pool_config.reputation[other_peer] = {
            "settlements": 1, "successes": 1, "failures": 0, "disputes": 0,
        }
        self.pool_config.reputation_events[other_peer] = {
            reputation_event_id(other_event)
        }
        self.pool_config.reputation_proofs[other_peer] = {
            reputation_event_id(other_event): other_event
        }
        second = build_pool_reputation_snapshot(
            self.pool_config, peer_id=other_peer, network_id="fixture", sequence=1,
            pool_identity=self.pool_identity, audience=self.registry, now=self.now,
        )
        self.assertEqual(first["receipt_count"], 5)
        self.assertEqual(second["receipt_count"], 1)
        self.assertNotEqual(first["receipt_set_hash"], second["receipt_set_hash"])

    def test_history_import_reverifies_all_rpc_and_allows_owner_rotation(self) -> None:
        history = self.history_import()
        self.history_for_rpc = history
        config = replace(self.config, history_import=history)
        observed_configs = []

        def factory(verifier_config, _rpc):
            observed_configs.append(verifier_config)
            return StructuralEventVerifier(verifier_config)

        sync = ProviderReputationSync(
            config, outbox_path=self.root / "history.sqlite3",
            sender=self.authority, rpc=self.rpc,
            event_verifier_factory=factory,
        )
        self.addCleanup(sync.close)
        row = sync.propose(
            self.snapshot(history_import=history), self.descriptor(), now=self.now,
        )
        self.assertEqual(row["action"]["provider"]["reputation"], 150)
        current = [item for item in observed_configs if item.protocol_version == 10]
        imported = [item for item in observed_configs if item.protocol_version == 9]
        self.assertEqual({item.rpc_url for item in current}, set(config.rpc_urls))
        self.assertEqual({item.rpc_url for item in imported}, set(config.rpc_urls))
        self.assertTrue(all(item.require_provider_owner_match for item in current))
        self.assertTrue(all(not item.require_provider_owner_match for item in imported))

    def test_history_import_rejects_signer_rebinding_and_omission(self) -> None:
        rebound = self.history_import(provider_signer=address(778))
        self.history_for_rpc = rebound
        rebound_config = replace(self.config, history_import=rebound)
        sync = ProviderReputationSync(
            rebound_config, outbox_path=self.root / "rebound.sqlite3",
            sender=self.authority, rpc=self.rpc,
            event_verifier_factory=self.verifier_factory,
        )
        self.addCleanup(sync.close)
        with self.assertRaisesRegex(ProviderReputationSyncError, "not canonical"):
            sync.propose(
                self.snapshot(history_import=rebound), self.descriptor(), now=self.now,
            )

        history = self.history_import()
        self.history_for_rpc = history
        config = replace(self.config, history_import=history)
        complete = self.snapshot(history_import=history)
        unsigned = {key_: copy.deepcopy(value) for key_, value in complete.items()
                    if key_ != "signature"}
        unsigned["events"] = [
            event for event in unsigned["events"]
            if event["settlement_contract"] == self.settlement
        ]
        event_ids = [reputation_event_id(event) for event in unsigned["events"]]
        unsigned["receipt_count"] = len(event_ids)
        unsigned["receipt_set_hash"] = evidence_hash({
            "schema": "mycomesh.pool.reputation-event-set.v2",
            "event_ids": event_ids,
        })
        unsigned["stats"] = {
            "score": 125, "successes": 5, "failures": 0,
            "settlements": 5, "disputes": 0,
        }
        omitted = sign_document(
            unsigned, self.pool_identity.private_key, SNAPSHOT_PURPOSE,
            timestamp=self.now, audience=self.registry,
        )
        omitted_sync = ProviderReputationSync(
            config, outbox_path=self.root / "omitted.sqlite3",
            sender=self.authority, rpc=self.rpc,
            event_verifier_factory=self.verifier_factory,
        )
        self.addCleanup(omitted_sync.close)
        with self.assertRaisesRegex(ProviderReputationSyncError, "omitted events"):
            omitted_sync.propose(omitted, self.descriptor(), now=self.now)

    def test_history_artifact_must_cover_window_and_later_terminal_events(self) -> None:
        history = self.history_import()
        self.history_for_rpc = history
        extra = {
            **self.reputation_event(61),
            "network_id": history.source_network_id,
            "settlement_contract": history.source_settlement_contract,
            "provider_owner": address(777),
            "provider_signer": self.vote_signer,
            "terminal_status": "confirmed",
            "outcome": "negative",
        }
        self.history_extra_events = [extra]
        config = replace(self.config, history_import=history)
        sync = ProviderReputationSync(
            config, outbox_path=self.root / "incomplete-history.sqlite3",
            sender=self.authority, rpc=self.rpc,
            event_verifier_factory=self.verifier_factory,
        )
        self.addCleanup(sync.close)
        with self.assertRaisesRegex(ProviderReputationSyncError, "omits or invents"):
            sync.propose(
                self.snapshot(history_import=history), self.descriptor(), now=self.now,
            )

        extra["block_number"] = 96
        extra["block_hash"] = digest(4_096)
        self.rpc.head = 101
        later_sync = ProviderReputationSync(
            config, outbox_path=self.root / "later-history.sqlite3",
            sender=self.authority, rpc=self.rpc,
            event_verifier_factory=self.verifier_factory,
        )
        self.addCleanup(later_sync.close)
        with self.assertRaisesRegex(ProviderReputationSyncError, "omits or invents"):
            later_sync.propose(
                self.snapshot(history_import=history), self.descriptor(), now=self.now,
            )

    def test_rpc_terminal_state_disagreement_fails_closed(self) -> None:
        class DivergentVerifier(StructuralEventVerifier):
            def verify(inner_self, event, *, peer):
                result = super(DivergentVerifier, inner_self).verify(event, peer=peer)
                if inner_self.config.rpc_url == "http://rpc2.invalid":
                    result["terminal_status_code"] = 255
                return result

        sync = self.sync(
            event_verifier_factory=lambda config, _rpc: DivergentVerifier(config),
        )
        with self.assertRaisesRegex(ProviderReputationSyncError, "disagree"):
            self.proposed(sync)

    def test_first_live_snapshot_cannot_omit_negative_or_neutral_events(self) -> None:
        negative = self.reputation_event(80)
        negative.update(terminal_status="confirmed", outcome="negative")
        neutral = self.reputation_event(81)
        neutral.update(terminal_status="timed_out", outcome="neutral")
        self.live_chain_events.extend((negative, neutral))
        with self.assertRaisesRegex(
            ProviderReputationSyncError,
            "omits or invents canonical live terminal events",
        ):
            self.proposed()

    def test_live_completeness_maps_terminal_events_by_settlement_signer(self) -> None:
        another = self.reputation_event(82, peer_id="another-provider-peer")
        another.update(
            provider_owner=address(778),
            provider_signer=address(779),
            terminal_status="confirmed",
            outcome="negative",
        )
        self.live_chain_events.append(another)
        row = self.proposed()
        self.assertEqual(row["action"]["source"]["receipt_count"], 5)

    def test_live_deployment_boundary_pins_fail_closed(self) -> None:
        for index, (change, message) in enumerate((
            ({"settlement_deployment_block_hash": digest(999_001)}, "release pin"),
            ({"settlement_runtime_code_hash": digest(999_002)}, "runtime code"),
        )):
            with self.subTest(change=change):
                sync = ProviderReputationSync(
                    replace(self.config, **change),
                    outbox_path=self.root / f"boundary-{index}.sqlite3",
                    sender=self.authority,
                    rpc=self.rpc,
                    event_verifier_factory=self.verifier_factory,
                )
                self.addCleanup(sync.close)
                with self.assertRaisesRegex(ProviderReputationSyncError, message):
                    self.proposed(sync)

    def test_live_terminal_log_rpc_divergence_fails_closed(self) -> None:
        def endpoint_rpc(url: str, method: str, params: list):
            value = self.rpc(method, params)
            if (
                method == "eth_getLogs"
                and params[0]["address"] == self.settlement
                and url == "http://rpc2.invalid"
            ):
                return value[:-1]
            return value

        sync = self.sync(endpoint_rpc=endpoint_rpc)
        with self.assertRaisesRegex(
            ProviderReputationSyncError,
            "disagree on canonical terminal logs",
        ):
            self.proposed(sync)

    def test_core_registry_rpc_disagreement_fails_closed(self) -> None:
        def endpoint_rpc(url: str, method: str, params: list):
            value = self.rpc(method, params)
            if method == "eth_chainId" and url == "http://rpc2.invalid":
                return hex(self.chain_id + 1)
            return value

        sync = self.sync(endpoint_rpc=endpoint_rpc)
        with self.assertRaisesRegex(
            ProviderReputationSyncError, "chain or genesis differs",
        ):
            self.proposed(sync)

    def test_production_rpc_urls_are_https_credential_free_and_host_unique(self) -> None:
        with self.assertRaisesRegex(ProviderReputationSyncError, "independent"):
            replace(
                self.config,
                rpc_url="https://rpc.example.test/a",
                rpc_urls=(
                    "https://rpc.example.test/a",
                    "https://rpc.example.test/b",
                ),
                allow_insecure_test_rpc=False,
            )
        with self.assertRaisesRegex(ProviderReputationSyncError, "credential-free"):
            replace(
                self.config,
                rpc_url="https://user:secret@rpc.example.test",
                rpc_urls=(
                    "https://user:secret@rpc.example.test",
                    "https://rpc2.example.test",
                ),
                allow_insecure_test_rpc=False,
            )

    def descriptor(self, *, now: int | None = None, operator_id: str = "operator-a") -> dict:
        peer_id = self.provider_identity.peer_id
        document = {
            "peer_id": peer_id,
            "public_key": self.provider_identity.public_key,
            "network_id": "fixture", "ttl_seconds": 300,
            "payment_address": self.owner,
            "settlement": {
                "version": 10, "chain_id": self.chain_id,
                "contract": self.settlement, "pricing_version": 1,
                "pricing_hash": digest(6), "provider_signer": self.vote_signer,
            },
            "provider_jury": {
                "schema": "mycomesh.provider-jury.descriptor.v1",
                "provider_owner": self.owner, "vote_signer": self.vote_signer,
                "operator_id": operator_id,
                "operator_id_hash": "0x" + chain.keccak256(operator_id.encode()).hex(),
                "peer_id_hash": "0x" + chain.keccak256(peer_id.encode()).hex(),
                "capability": self.capability,
                "capability_hash": provider_jury.capability_hash(self.capability),
            },
            "challenge": digest(77),
        }
        document["settlement_identity_binding"] = build_provider_identity_binding(
            document,
            audience=self.config.descriptor_audience,
            private_key=key(20),
        )
        return sign_document(
            document, self.provider_identity.private_key,
            purpose=pool.POOL_REGISTRATION_PURPOSE,
            audience=self.config.descriptor_audience,
            timestamp=self.now if now is None else now,
        )

    def sync(self, *, enabled: bool = False, **changes) -> ProviderReputationSync:
        arguments = {
            "outbox_path": self.root / "reputation.sqlite3",
            "sender": self.authority,
            "execution_enabled": enabled,
            "dedicated_sender": enabled,
            "key_file": self.key_path if enabled else None,
            "max_gas_price_wei": 100 if enabled else None,
            "max_gas_units": 1_000_000 if enabled else None,
            "max_total_gas_cost_wei": 100_000_000 if enabled else None,
            "rpc": self.rpc,
            "event_verifier_factory": self.verifier_factory,
        }
        arguments.update(changes)
        instance = ProviderReputationSync(self.config, **arguments)
        self.addCleanup(instance.close)
        return instance

    def proposed(self, sync: ProviderReputationSync | None = None, *, sequence: int = 1):
        instance = sync or self.sync()
        return instance.propose(
            self.snapshot(sequence=sequence), self.descriptor(), now=self.now,
        )

    def test_derives_bounded_registry_action_from_signed_sources(self) -> None:
        row = self.proposed()
        action = row["action"]
        self.assertEqual(row["state"], "proposed")
        self.assertEqual(action["provider"]["reputation"], 125)
        self.assertTrue(action["provider"]["active"])
        self.assertEqual(action["provider"]["owner"], self.owner)
        self.assertEqual(action["provider"]["vote_signer"], self.vote_signer)
        self.assertEqual(action["source"]["sequence"], 1)
        self.assertNotEqual(action["source"]["source_digest"], chain.ZERO_BYTES32)
        self.assertTrue(action["calldata"].startswith("0x"))
        self.assertNotIn("providers", action)
        self.assertNotIn("roster", action)

    def test_below_threshold_is_inactive_and_signed_counters_cannot_be_forged(self) -> None:
        negative = self.reputation_event(99)
        negative.update(terminal_status="confirmed", outcome="negative")
        negative_id = reputation_event_id(negative)
        self.pool_config.reputation_proofs[self.provider_identity.peer_id] = {
            negative_id: negative
        }
        self.pool_config.reputation_events[self.provider_identity.peer_id] = {negative_id}
        self.live_chain_events = [copy.deepcopy(negative)]
        self.rpc.head += 1
        sync = self.sync()
        low = sync.propose(self.snapshot(), self.descriptor(), now=self.now)
        self.assertEqual(low["action"]["provider"]["reputation"], 0)
        self.assertFalse(low["action"]["provider"]["active"])

        unsigned = {
            key_: value for key_, value in self.snapshot().items()
            if key_ != "signature"
        }
        maximum = 2**64 - 1
        unsigned["stats"] = {
            "score": maximum * 25,
            "settlements": maximum,
            "successes": maximum,
            "failures": 0,
            "disputes": 0,
        }
        unsigned["receipt_count"] = maximum
        unsigned["receipt_set_hash"] = digest(75)
        saturated_snapshot = sign_document(
            unsigned, self.pool_identity.private_key, SNAPSHOT_PURPOSE,
            audience=self.registry, timestamp=self.now,
        )
        with self.assertRaisesRegex(
            ProviderReputationSyncError, "event commitment|terminal-event proofs",
        ):
            sync.propose(saturated_snapshot, self.descriptor(), now=self.now)

    def test_snapshot_and_descriptor_authentication_fail_closed(self) -> None:
        sync = self.sync()
        snapshot = self.snapshot()
        snapshot["stats"]["score"] += 1
        with self.assertRaisesRegex(ProviderReputationSyncError, "snapshot"):
            sync.propose(snapshot, self.descriptor(), now=self.now)

        rogue = create_identity()
        unsigned = {k: v for k, v in self.snapshot().items() if k != "signature"}
        forged = sign_document(
            unsigned, rogue.private_key, SNAPSHOT_PURPOSE,
            audience=self.registry, timestamp=self.now,
        )
        with self.assertRaisesRegex(ProviderReputationSyncError, "not pinned"):
            sync.propose(forged, self.descriptor(), now=self.now)

        descriptor = self.descriptor()
        descriptor["provider_jury"]["peer_id_hash"] = digest(99)
        with self.assertRaisesRegex(ProviderReputationSyncError, "descriptor"):
            sync.propose(self.snapshot(), descriptor, now=self.now)

        descriptor = self.descriptor()
        unsigned = {key_: value for key_, value in descriptor.items() if key_ != "signature"}
        unsigned["settlement_identity_binding"] = None
        descriptor = sign_document(
            unsigned,
            self.provider_identity.private_key,
            purpose=pool.POOL_REGISTRATION_PURPOSE,
            audience=self.config.descriptor_audience,
            timestamp=self.now,
        )
        with self.assertRaisesRegex(ProviderReputationSyncError, "EVM vote-signer proof"):
            sync.propose(self.snapshot(), descriptor, now=self.now)

    def test_snapshot_sequence_is_a_durable_replay_and_equivocation_fence(self) -> None:
        sync = self.sync()
        snapshot = self.snapshot()
        descriptor = self.descriptor()
        first = sync.propose(snapshot, descriptor, now=self.now)
        replay = sync.propose(snapshot, descriptor, now=self.now)
        self.assertEqual(replay["action_hash"], first["action_hash"])

        rebound_descriptor = self.descriptor()
        with self.assertRaisesRegex(ProviderReputationSyncError, "rebound|equivocated"):
            sync.propose(self.snapshot(), rebound_descriptor, now=self.now)

        second = sync.propose(
            self.snapshot(sequence=2), rebound_descriptor, now=self.now,
        )
        self.assertNotEqual(second["action_hash"], first["action_hash"])
        with self.assertRaisesRegex(ProviderReputationSyncError, "stale"):
            sync.propose(self.snapshot(sequence=1), self.descriptor(), now=self.now)

    def test_newer_snapshot_cannot_replace_prior_negative_or_positive_events(self) -> None:
        sync = self.sync()
        self.proposed(sync)
        peer_id = self.provider_identity.peer_id
        prior_id = sorted(self.pool_config.reputation_proofs[peer_id])[0]
        self.pool_config.reputation_proofs[peer_id].pop(prior_id)
        self.pool_config.reputation_events[peer_id].remove(prior_id)
        replacement = self.reputation_event(75)
        replacement_id = reputation_event_id(replacement)
        self.pool_config.reputation_proofs[peer_id][replacement_id] = replacement
        self.pool_config.reputation_events[peer_id].add(replacement_id)
        self.live_chain_events = list(
            copy.deepcopy(self.pool_config.reputation_proofs[peer_id]).values()
        )
        self.rpc.head += 1
        with self.assertRaisesRegex(
            ProviderReputationSyncError, "removed authenticated terminal events",
        ):
            sync.propose(
                self.snapshot(sequence=2), self.descriptor(), now=self.now,
            )

    def test_pending_assignment_pauses_proposal_and_execution(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        self.rpc.pending_assignments = 1
        with self.assertRaisesRegex(ProviderReputationSyncError, "paused"):
            sync.execute(row["action_hash"])
        self.assertEqual(sync.outbox.get(row["action_hash"])["state"], "proposed")

        other = ProviderReputationSync(
            self.config, outbox_path=self.root / "pending.sqlite3",
            sender=self.authority, rpc=self.rpc,
            event_verifier_factory=self.verifier_factory,
        )
        self.addCleanup(other.close)
        with self.assertRaisesRegex(ProviderReputationSyncError, "paused"):
            other.propose(self.snapshot(sequence=2), self.descriptor(), now=self.now)

    def test_execution_is_explicit_and_gas_capped(self) -> None:
        disabled = self.sync()
        row = self.proposed(disabled)
        with self.assertRaisesRegex(ProviderReputationSyncError, "disabled"):
            disabled.execute(row["action_hash"])
        self.assertEqual(disabled.outbox.get(row["action_hash"])["state"], "proposed")

        with self.assertRaisesRegex(ProviderReputationSyncError, "dedicated"):
            ProviderReputationSync(
                self.config, outbox_path=self.root / "invalid.sqlite3",
                sender=self.authority, execution_enabled=True,
                dedicated_sender=False, key_file=self.key_path,
                max_gas_price_wei=1, max_gas_units=1,
                max_total_gas_cost_wei=1, rpc=self.rpc,
            )

        capped = ProviderReputationSync(
            self.config, outbox_path=self.root / "capped.sqlite3",
            sender=self.authority, execution_enabled=True, dedicated_sender=True,
            key_file=self.key_path, max_gas_price_wei=1,
            max_gas_units=1_000_000, max_total_gas_cost_wei=100_000_000,
            rpc=self.rpc, event_verifier_factory=self.verifier_factory,
        )
        self.addCleanup(capped.close)
        capped_row = capped.propose(self.snapshot(), self.descriptor(), now=self.now)
        with self.assertRaisesRegex(ProviderReputationSyncError, "gas caps"):
            capped.execute(capped_row["action_hash"])
        self.assertEqual(capped.outbox.get(capped_row["action_hash"])["state"], "proposed")

    def test_execute_rescans_and_rejects_a_newly_confirmed_live_event(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        negative = self.reputation_event(99)
        negative.update(terminal_status="confirmed", outcome="negative")
        self.live_chain_events.append(negative)
        self.rpc.head += 1
        with self.assertRaisesRegex(
            ProviderReputationSyncError,
            "omits or invents canonical live terminal events",
        ):
            sync.execute(row["action_hash"])
        self.assertEqual(sync.outbox.get(row["action_hash"])["state"], "proposed")
        self.assertEqual(self.rpc.sent, 0)

    def test_submit_and_exact_receipt_event_reconcile(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        submitted = sync.execute(row["action_hash"])
        self.assertEqual(submitted["state"], "submitted")
        self.assertEqual(self.rpc.sent, 2)
        self.rpc.mine(row["action"])
        result = sync.reconcile(row["action_hash"])
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["event"]["owner"], self.owner)
        self.assertEqual(result["event"]["source_sequence"], 1)
        self.assertEqual(
            result["event"]["source_digest"], row["action"]["source"]["source_digest"],
        )
        self.assertEqual(result["event"]["roster_version"], 7)
        self.assertEqual(sync.reconcile(row["action_hash"]), result)
        self.assertEqual(self.rpc.sent, 2)
        self.rpc.head += 1
        advanced = sync.reconcile(row["action_hash"])
        self.assertEqual(advanced["confirmations"], result["confirmations"] + 1)
        self.rpc.tx = None
        self.rpc.receipt = None
        with self.assertRaisesRegex(ProviderReputationSyncError, "not observable"):
            sync.reconcile(row["action_hash"])
        self.assertEqual(sync.outbox.get(row["action_hash"])["state"], "uncertain")

    def test_confirmed_receipt_disappearance_never_remains_confirmed(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        sync.execute(row["action_hash"])
        self.rpc.mine(row["action"])
        self.assertEqual(sync.reconcile(row["action_hash"])["status"], "confirmed")
        # Some RPCs can still return the transaction body while temporarily
        # losing its receipt.  A prior confirmation is no longer provable.
        self.rpc.receipt = None
        with self.assertRaisesRegex(ProviderReputationSyncError, "disappeared"):
            sync.reconcile(row["action_hash"])
        uncertain = sync.outbox.get(row["action_hash"])
        self.assertEqual(uncertain["state"], "uncertain")
        self.assertNotIn("result", uncertain)

    def test_canonical_revert_is_terminal_without_blocking_new_snapshot(self) -> None:
        sync = self.sync(enabled=True)
        first = self.proposed(sync)
        sync.execute(first["action_hash"])
        self.rpc.mine(first["action"], status=0)
        with self.assertRaisesRegex(ProviderReputationSyncError, "reverted"):
            sync.reconcile(first["action_hash"])
        self.assertEqual(sync.outbox.get(first["action_hash"])["state"], "reverted")

        second = sync.propose(
            self.snapshot(sequence=2), self.descriptor(), now=self.now,
        )
        leased, _lease_id = sync.outbox.begin_execution(
            second["action_hash"], lease_seconds=60,
        )
        self.assertEqual(leased["state"], "executing")

    def test_registry_and_settlement_must_be_bound_bidirectionally(self) -> None:
        sync = self.sync(enabled=False)
        self.rpc.registry_settlement = address(99)
        with self.assertRaisesRegex(ProviderReputationSyncError, "bound"):
            sync.confirmed_context()
        self.rpc.registry_settlement = self.settlement
        self.rpc.settlement_registry = address(98)
        with self.assertRaisesRegex(ProviderReputationSyncError, "bound"):
            sync.confirmed_context()

    def test_insufficient_confirmations_remain_submitted(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        sync.execute(row["action_hash"])
        self.rpc.mine(row["action"], confirmations=2)
        result = sync.reconcile(row["action_hash"])
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["confirmations"], 2)
        self.assertEqual(sync.outbox.get(row["action_hash"])["state"], "submitted")

    def test_unknown_broadcast_is_uncertain_and_never_resent(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        self.rpc.send_error = TimeoutError("unknown")
        with self.assertRaisesRegex(ProviderReputationSyncError, "uncertain"):
            sync.execute(row["action_hash"])
        uncertain = sync.outbox.get(row["action_hash"])
        self.assertEqual(uncertain["state"], "uncertain")
        self.assertIsNotNone(uncertain["tx_hash"])
        with self.assertRaisesRegex(ProviderReputationSyncError, "reconciled"):
            sync.execute(row["action_hash"])
        self.assertEqual(self.rpc.sent, 2)

    def test_restart_distinguishes_not_sent_from_durable_transaction(self) -> None:
        path = self.root / "lease.sqlite3"
        sync = ProviderReputationSync(
            self.config, outbox_path=path, sender=self.authority, rpc=self.rpc,
            event_verifier_factory=self.verifier_factory,
        )
        row = sync.propose(self.snapshot(), self.descriptor(), now=self.now)
        sync.outbox.begin_execution(row["action_hash"], lease_seconds=60)
        sync.close()
        reopened = ProviderReputationOutbox(path)
        self.assertEqual(reopened.get(row["action_hash"])["state"], "proposed")
        _leased, lease_id = reopened.begin_execution(
            row["action_hash"], lease_seconds=60,
        )
        reopened.attach_transaction(
            row["action_hash"], lease_id=lease_id, nonce=0, raw_tx=b"signed",
        )
        reopened.close()
        recovered = ProviderReputationOutbox(path)
        self.addCleanup(recovered.close)
        self.assertEqual(recovered.get(row["action_hash"])["state"], "uncertain")

    def test_expired_live_lease_without_transaction_can_be_reacquired(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        first, first_lease = sync.outbox.begin_execution(
            row["action_hash"], lease_seconds=5, now=self.now,
        )
        self.assertEqual(first["state"], "executing")
        second, second_lease = sync.outbox.begin_execution(
            row["action_hash"], lease_seconds=5, now=self.now + 5,
        )
        self.assertEqual(second["state"], "executing")
        self.assertNotEqual(second_lease, first_lease)

    def test_restart_repairs_legacy_uncertain_row_without_transaction(self) -> None:
        path = self.root / "legacy-uncertain.sqlite3"
        sync = ProviderReputationSync(
            self.config, outbox_path=path, sender=self.authority, rpc=self.rpc,
            event_verifier_factory=self.verifier_factory,
        )
        row = sync.propose(self.snapshot(), self.descriptor(), now=self.now)
        sync.outbox.db.execute(
            "UPDATE provider_reputation_actions SET state='uncertain' "
            "WHERE action_hash=?",
            (row["action_hash"],),
        )
        sync.close()
        reopened = ProviderReputationOutbox(path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.get(row["action_hash"])["state"], "proposed")

    def test_expired_live_lease_with_transaction_remains_uncertain(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        _leased, lease = sync.outbox.begin_execution(
            row["action_hash"], lease_seconds=5, now=self.now,
        )
        sync.outbox.attach_transaction(
            row["action_hash"], lease_id=lease, nonce=0, raw_tx=b"signed",
            now=self.now,
        )
        with self.assertRaisesRegex(
                ProviderReputationSyncError, "not eligible"):
            sync.outbox.begin_execution(
                row["action_hash"], lease_seconds=5, now=self.now + 5,
            )
        self.assertEqual(
            sync.outbox.get(row["action_hash"])["state"], "uncertain",
        )

    def test_receipt_or_event_identity_mismatch_stays_uncertain(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        sync.execute(row["action_hash"])
        self.rpc.mine(row["action"])
        self.rpc.receipt["logs"][0]["data"] = abi(
            row["action"]["provider"]["reputation"] + 1, True,
            row["action"]["source"]["sequence"],
            row["action"]["source"]["source_digest"], 7,
        )
        with self.assertRaisesRegex(ProviderReputationSyncError, "differs"):
            sync.reconcile(row["action_hash"])
        self.assertEqual(sync.outbox.get(row["action_hash"])["state"], "uncertain")

    def test_event_must_emit_exact_authenticated_source_identity(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        sync.execute(row["action_hash"])
        self.rpc.mine(row["action"])
        self.rpc.receipt["logs"][0]["data"] = abi(
            row["action"]["provider"]["reputation"], True,
            row["action"]["source"]["sequence"] + 1,
            digest(123_456), 7,
        )
        with self.assertRaisesRegex(ProviderReputationSyncError, "differs"):
            sync.reconcile(row["action_hash"])
        self.assertEqual(sync.outbox.get(row["action_hash"])["state"], "uncertain")

    def test_confirmed_registry_source_state_must_match_action(self) -> None:
        sync = self.sync(enabled=True)
        row = self.proposed(sync)
        sync.execute(row["action_hash"])
        self.rpc.mine(row["action"])
        self.rpc.provider_source_state["digest"] = digest(654_321)
        with self.assertRaisesRegex(ProviderReputationSyncError, "source identity"):
            sync.reconcile(row["action_hash"])
        self.assertEqual(sync.outbox.get(row["action_hash"])["state"], "uncertain")

    def test_injected_signer_is_used_but_exact_hash_is_still_fenced(self) -> None:
        calls = []

        def injected(**kwargs):
            calls.append(kwargs)
            return b"injected signed transaction"

        sync = self.sync(enabled=True, transaction_signer=injected)
        row = self.proposed(sync)
        submitted = sync.execute(row["action_hash"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["to_address"], self.registry)
        self.assertEqual(
            submitted["tx_hash"],
            "0x" + chain.keccak256(b"injected signed transaction").hex(),
        )

    def test_saved_action_cannot_override_scope_sender_or_target(self) -> None:
        sync = self.sync(enabled=False)
        row = self.proposed(sync)
        for name, value in (
            ("scope", "another:scope"),
            ("sender", address(88)),
            ("target", address(89)),
        ):
            changed = copy.deepcopy(row["action"])
            changed[name] = value
            with self.subTest(name=name), self.assertRaisesRegex(
                    ProviderReputationSyncError, "execution binding"):
                sync._validate_saved_action_sources(changed, now=self.now)


if __name__ == "__main__":
    unittest.main()
