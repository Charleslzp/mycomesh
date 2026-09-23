from __future__ import annotations

import copy
import unittest

from gateway import chain
from gateway.v10_reputation import (
    DISPUTE_RESOLVED_TOPIC,
    FEEDBACK_SCHEMA,
    SETTLEMENT_RELEASED_TOPIC,
    TERMINAL_OUTCOMES,
    V9_DISPUTE_RESOLVED_TOPIC,
    V10ReputationError,
    V10ReputationEventVerifier,
    V10ReputationVerifierConfig,
    reputation_event_id,
)


def digest(byte: int) -> str:
    return "0x" + f"{byte:02x}" * 32


def address(byte: int) -> str:
    return "0x" + f"{byte:02x}" * 20


def address_word(value: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(value[2:])


class FakeReputationRPC:
    def __init__(self, case: "V10ReputationVerifierTests") -> None:
        self.case = case
        self.head = 110
        self.status = 3
        self.state_provider = case.owner
        self.state_signer = case.signer
        self.receipt_tx_hash = case.tx_hash
        self.reorg_after_state = False
        self.event_block_reads = 0
        self.protocol_version = 10

    def _block(self) -> dict:
        self.event_block_reads += 1
        block_hash = self.case.block_hash
        if self.reorg_after_state and self.event_block_reads > 1:
            block_hash = digest(99)
        return {"number": hex(self.case.block_number), "hash": block_hash}

    def _log(self) -> dict:
        topic = TERMINAL_OUTCOMES[self.status][2]
        words = [self.status]
        if topic == DISPUTE_RESOLVED_TOPIC:
            if self.protocol_version == 9:
                topic = V9_DISPUTE_RESOLVED_TOPIC
                words.extend((0, 0, 0))
            else:
                words.extend((0, 0))
        return {
            "address": self.case.settlement,
            "topics": [topic, self.case.settlement_key],
            "data": "0x" + b"".join(value.to_bytes(32, "big") for value in words).hex(),
            "logIndex": hex(self.case.log_index),
            "transactionHash": self.receipt_tx_hash,
            "blockNumber": hex(self.case.block_number),
            "blockHash": self.case.block_hash,
            "removed": False,
        }

    def _settlement_info(self) -> str:
        words = [b"\x00" * 32 for _ in range(20)]
        words[2] = address_word(self.state_provider)
        words[3] = address_word(self.state_signer)
        words[8] = bytes.fromhex(self.case.request_id[2:])
        words[19] = self.status.to_bytes(32, "big")
        return "0x" + b"".join(words).hex()

    def __call__(self, method: str, params: list) -> object:
        if method == "eth_chainId":
            return hex(self.case.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            if params[0] == "0x0":
                return {"number": "0x0", "hash": self.case.genesis}
            return self._block()
        if method == "eth_getTransactionReceipt":
            return {
                "transactionHash": self.receipt_tx_hash,
                "status": "0x1",
                "blockNumber": hex(self.case.block_number),
                "blockHash": self.case.block_hash,
                "logs": [self._log()],
            }
        if method == "eth_call":
            self.case.assertEqual(
                params[1], {"blockHash": self.case.block_hash, "requireCanonical": True},
            )
            return self._settlement_info()
        raise AssertionError(f"unexpected RPC method {method}")


class V10ReputationVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chain_id = 31337
        self.genesis = digest(1)
        self.settlement = address(2)
        self.settlement_key = digest(3)
        self.request_id = digest(4)
        self.owner = address(5)
        self.signer = address(6)
        self.tx_hash = digest(7)
        self.block_hash = digest(8)
        self.block_number = 100
        self.log_index = 2
        self.peer_id = "provider-peer"
        self.peer = {
            "peer_id": self.peer_id,
            "network_id": "fixture-v10",
            "payment_address": self.owner,
            "settlement": {
                "version": 10,
                "chain_id": self.chain_id,
                "contract": self.settlement,
                "provider_signer": self.signer,
            },
        }
        self.rpc = FakeReputationRPC(self)
        self.verifier = V10ReputationEventVerifier(
            V10ReputationVerifierConfig(
                network_id="fixture-v10",
                rpc_url="https://rpc.invalid",
                chain_id=self.chain_id,
                genesis_hash=self.genesis,
                settlement_contract=self.settlement,
                confirmations=6,
            ),
            rpc=self.rpc,
        )

    def feedback(self, status: int | None = None) -> dict:
        if status is not None:
            self.rpc.status = status
        name, outcome, _topic = TERMINAL_OUTCOMES[self.rpc.status]
        return {
            "schema": FEEDBACK_SCHEMA,
            "network_id": "fixture-v10",
            "chain_id": self.chain_id,
            "settlement_contract": self.settlement,
            "settlement_key": self.settlement_key,
            "request_id": self.request_id,
            "provider_owner": self.owner,
            "provider_signer": self.signer,
            "peer_id": self.peer_id,
            "tx_hash": self.tx_hash,
            "log_index": self.log_index,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "terminal_status": name,
            "outcome": outcome,
        }

    def test_all_deterministic_terminal_mappings(self) -> None:
        expected = {3: "positive", 4: "negative", 5: "positive", 6: "neutral", 7: "neutral"}
        for status, outcome in expected.items():
            with self.subTest(status=status):
                self.rpc.event_block_reads = 0
                result = self.verifier.verify(self.feedback(status), peer=self.peer)
                self.assertEqual(result["outcome"], outcome)
                self.assertEqual(result["terminal_status_code"], status)

    def test_forged_transaction_hash_is_rejected(self) -> None:
        self.rpc.receipt_tx_hash = digest(9)
        with self.assertRaisesRegex(V10ReputationError, "receipt differs"):
            self.verifier.verify(self.feedback(), peer=self.peer)

    def test_wrong_provider_or_peer_is_rejected(self) -> None:
        self.rpc.state_provider = address(99)
        with self.assertRaisesRegex(V10ReputationError, "settlement state differs"):
            self.verifier.verify(self.feedback(), peer=self.peer)
        self.rpc.state_provider = self.owner
        wrong_peer = {**self.peer, "peer_id": "another-peer"}
        with self.assertRaisesRegex(V10ReputationError, "current Provider peer"):
            self.verifier.verify(self.feedback(), peer=wrong_peer)

    def test_unconfirmed_and_in_flight_reorg_are_rejected(self) -> None:
        self.rpc.head = 103
        with self.assertRaisesRegex(V10ReputationError, "insufficient confirmations"):
            self.verifier.verify(self.feedback(), peer=self.peer)
        self.rpc.head = 110
        self.rpc.reorg_after_state = True
        self.rpc.event_block_reads = 0
        with self.assertRaisesRegex(V10ReputationError, "reorganized"):
            self.verifier.verify(self.feedback(), peer=self.peer)

    def test_noncanonical_rpc_quantity_is_rejected(self) -> None:
        def rpc(method: str, params: list) -> object:
            if method == "eth_blockNumber":
                return "0x06e"
            return self.rpc(method, params)

        verifier = V10ReputationEventVerifier(self.verifier.config, rpc=rpc)
        with self.assertRaisesRegex(V10ReputationError, "invalid chain head"):
            verifier.verify(self.feedback(), peer=self.peer)

    def test_cross_chain_reference_and_outcome_forgery_are_rejected(self) -> None:
        feedback = self.feedback()
        feedback["chain_id"] = 1
        with self.assertRaisesRegex(V10ReputationError, "another deployment"):
            self.verifier.verify(feedback, peer=self.peer)
        feedback = self.feedback()
        feedback["outcome"] = "negative"
        with self.assertRaisesRegex(V10ReputationError, "claimed reputation outcome"):
            self.verifier.verify(feedback, peer=self.peer)

    def test_event_identity_is_chain_and_contract_scoped(self) -> None:
        feedback = self.feedback()
        first = reputation_event_id(feedback)
        other = copy.deepcopy(feedback)
        other["chain_id"] = 1
        self.assertNotEqual(first, reputation_event_id(other))
        other = copy.deepcopy(feedback)
        other["settlement_contract"] = address(88)
        self.assertNotEqual(first, reputation_event_id(other))

    def test_v9_dispute_abi_is_verified_for_history_imports(self) -> None:
        self.rpc.protocol_version = 9
        v9_peer = copy.deepcopy(self.peer)
        v9_peer["settlement"]["version"] = 9
        verifier = V10ReputationEventVerifier(
            V10ReputationVerifierConfig(
                network_id="fixture-v10",
                rpc_url="https://rpc.invalid",
                chain_id=self.chain_id,
                genesis_hash=self.genesis,
                settlement_contract=self.settlement,
                confirmations=6,
                protocol_version=9,
                require_provider_owner_match=False,
            ),
            rpc=self.rpc,
        )
        result = verifier.verify(self.feedback(4), peer=v9_peer)
        self.assertEqual(result["terminal_status"], "confirmed")
        self.assertEqual(result["outcome"], "negative")

    def test_history_owner_may_rotate_but_provider_signer_may_not(self) -> None:
        rotated_peer = copy.deepcopy(self.peer)
        rotated_peer["payment_address"] = address(77)
        verifier = V10ReputationEventVerifier(
            V10ReputationVerifierConfig(
                network_id="fixture-v10",
                rpc_url="https://rpc.invalid",
                chain_id=self.chain_id,
                genesis_hash=self.genesis,
                settlement_contract=self.settlement,
                confirmations=6,
                require_provider_owner_match=False,
            ),
            rpc=self.rpc,
        )
        self.assertEqual(
            verifier.verify(self.feedback(), peer=rotated_peer)["provider_owner"],
            self.owner,
        )
        rotated_peer["settlement"]["provider_signer"] = address(78)
        with self.assertRaisesRegex(V10ReputationError, "signed Provider descriptor"):
            verifier.verify(self.feedback(), peer=rotated_peer)


if __name__ == "__main__":
    unittest.main()
