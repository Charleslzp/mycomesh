from __future__ import annotations

import copy
import unittest

from gateway import chain
from gateway.provider_reputation_import import (
    ReputationImportError,
    SCAN_POLICY_SCHEMA,
    scan_history_import,
)
from gateway.provider_reputation_sync import load_reputation_history_import
from gateway.relay_incidents import evidence_hash
from gateway.v10_reputation import SETTLEMENT_RELEASED_TOPIC


def address(value: int) -> str:
    return "0x" + f"{value:040x}"


def digest(value: int) -> str:
    return "0x" + f"{value:064x}"


def word_address(value: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(value[2:])


class ImportRPC:
    def __init__(self) -> None:
        self.chain_id = 31337
        self.genesis = digest(1)
        self.settlement = address(2)
        self.owner = address(3)
        self.signer = address(4)
        self.key = digest(5)
        self.request_id = digest(6)
        self.tx_hash = digest(7)
        self.block_hash = digest(8)
        self.block_number = 100
        self.head = 110
        self.deployment_block = 90
        self.runtime = b"\x60\x00"
        self.disagree = False
        self.log_ranges: list[tuple[int, int]] = []
        self.extra_log_fields = False
        self.max_log_range: int | None = None

    def log(self) -> dict:
        value = {
            "address": self.settlement,
            "topics": [SETTLEMENT_RELEASED_TOPIC, self.key],
            "data": "0x" + (3).to_bytes(32, "big").hex(),
            "blockNumber": hex(self.block_number),
            "transactionHash": self.tx_hash,
            "transactionIndex": "0x0",
            "blockHash": self.block_hash,
            "logIndex": "0x0",
            "removed": False,
        }
        if self.extra_log_fields:
            value["blockTimestamp"] = "0x1234"
        return value

    def settlement_info(self) -> str:
        words = [b"\x00" * 32 for _ in range(20)]
        words[2] = word_address(self.owner)
        words[3] = word_address(self.signer)
        words[8] = bytes.fromhex(self.request_id[2:])
        words[19] = (3).to_bytes(32, "big")
        return "0x" + b"".join(words).hex()

    def __call__(self, url: str, method: str, params: list, _timeout: float):
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            if params[0] == "0x0":
                return {"number": "0x0", "hash": self.genesis}
            number = int(params[0], 16)
            block_hash = (
                self.block_hash if number == self.block_number else digest(10_000 + number)
            )
            return {"number": hex(number), "hash": block_hash}
        if method == "eth_getLogs":
            request = params[0]
            start = int(request["fromBlock"], 16)
            end = int(request["toBlock"], 16)
            self.log_ranges.append((start, end))
            if self.max_log_range is not None and end - start + 1 > self.max_log_range:
                raise chain.ChainError(
                    f"RPC error -32602: eth_getLogs is limited to 0 - {self.max_log_range} blocks range"
                )
            if self.disagree and "two" in url:
                return []
            return [self.log()] if start <= self.block_number <= end else []
        if method == "eth_call":
            return self.settlement_info()
        if method == "eth_getCode":
            tag = params[1]
            if tag["blockHash"] == digest(10_000 + self.deployment_block - 1):
                return "0x"
            return "0x" + self.runtime.hex()
        if method == "eth_getTransactionReceipt":
            return {
                "transactionHash": self.tx_hash,
                "status": "0x1",
                "blockNumber": hex(self.block_number),
                "blockHash": self.block_hash,
                "logs": [self.log()],
            }
        raise AssertionError(f"unexpected RPC method {method}")


class ProviderReputationImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rpc = ImportRPC()
        self.peer = "provider-peer"
        self.policy = {
            "schema": SCAN_POLICY_SCHEMA,
            "source_network_id": "history-v10",
            "source_protocol_version": 10,
            "source_chain_id": self.rpc.chain_id,
            "source_genesis_hash": self.rpc.genesis,
            "source_settlement_contract": self.rpc.settlement,
            "source_runtime_code_hash": "0x" + chain.keccak256(self.rpc.runtime).hex(),
            "confirmations": 6,
            "rpc_urls": ["https://one.rpc.test", "https://two.rpc.test"],
            "source_deployment_block": self.rpc.deployment_block,
            "signer_peer_map": {self.rpc.signer: self.peer},
            "timeout_seconds": 5,
        }

    def test_scan_builds_proof_carrying_import_and_loader_accepts_it(self) -> None:
        self.rpc.extra_log_fields = True
        artifact = scan_history_import(self.policy, rpc=self.rpc)

        self.assertEqual(len(artifact["entries"]), 1)
        event = artifact["entries"][0]["events"][0]
        self.assertEqual(event["provider_owner"], self.rpc.owner)
        self.assertEqual(event["provider_signer"], self.rpc.signer)
        self.assertEqual(event["peer_id"], self.peer)
        root = evidence_hash(artifact)
        loaded = load_reputation_history_import(
            artifact, artifact_sha256="1" * 64, expected_artifact_root=root,
        )
        self.assertEqual(loaded.source_protocol_version, 10)
        self.assertEqual(loaded.artifact_root, root)
        self.assertEqual(loaded.source_deployment_block, self.rpc.deployment_block)
        self.assertEqual(loaded.source_history_through_block, 105)

    def test_rpc_log_disagreement_and_signer_alias_fail_closed(self) -> None:
        self.rpc.disagree = True
        with self.assertRaisesRegex(ReputationImportError, "disagree"):
            scan_history_import(self.policy, rpc=self.rpc)

        self.rpc.disagree = False
        bad = copy.deepcopy(self.policy)
        bad["signer_peer_map"] = {self.rpc.signer: "wrong-peer"}
        artifact = scan_history_import(bad, rpc=self.rpc)
        self.assertEqual(artifact["entries"][0]["peer_id"], "wrong-peer")
        # The scan mapping alone cannot activate reputation.  Registry ops later
        # require this exact peer and signer to match a live signed descriptor.

    def test_scan_uses_rpc_compatible_thousand_block_chunks(self) -> None:
        self.rpc.head = 2_200
        policy = copy.deepcopy(self.policy)
        scan_history_import(policy, rpc=self.rpc)
        unique_ranges = sorted(set(self.rpc.log_ranges))
        self.assertEqual(
            unique_ranges,
            [(90, 1_089), (1_090, 2_089), (2_090, 2_195)],
        )
        self.assertTrue(all(end - start + 1 <= 1_000 for start, end in unique_ranges))

    def test_scan_pages_an_endpoint_declared_smaller_log_range(self) -> None:
        self.rpc.head = 240
        self.rpc.max_log_range = 50
        artifact = scan_history_import(self.policy, rpc=self.rpc)
        self.assertEqual(len(artifact["entries"]), 1)
        successful_ranges = [
            (start, end) for start, end in self.rpc.log_ranges
            if end - start + 1 <= 50
        ]
        self.assertTrue(successful_ranges)
        self.assertEqual(min(start for start, _end in successful_ranges), 90)
        self.assertEqual(max(end for _start, end in successful_ranges), 235)
        self.assertTrue(all(end - start + 1 <= 50 for start, end in successful_ranges))

    def test_scan_window_is_derived_and_rpc_hosts_must_be_distinct(self) -> None:
        arbitrary = copy.deepcopy(self.policy)
        arbitrary["from_block"] = self.rpc.deployment_block
        with self.assertRaisesRegex(ReputationImportError, "unknown or missing"):
            scan_history_import(arbitrary, rpc=self.rpc)

        aliases = copy.deepcopy(self.policy)
        aliases["rpc_urls"] = [
            "https://same.rpc.test/one", "https://same.rpc.test/two",
        ]
        with self.assertRaisesRegex(ReputationImportError, "unique"):
            scan_history_import(aliases, rpc=self.rpc)


if __name__ == "__main__":
    unittest.main()
