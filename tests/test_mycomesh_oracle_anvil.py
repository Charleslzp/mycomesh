"""On-chain inference end to end: a contract asks, a Relay dispatches, a Provider answers, the callback lands."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mycomesh import jury, oracle, rpc
from mycomesh.evm import abi_encode, address_of, decode_words, encode_call
from mycomesh.identity import create_identity
from mycomesh.pricing import NetworkPricing
from mycomesh.protocol import Prices
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.disputes import DisputeDesk
from mycomesh.relay.onchain import OracleDispatcher
from mycomesh.settlement import encode_release
from tests.mycomesh_anvil import DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, _artifact, available

ASK = "ask(uint32,string,string,uint256,uint8)"


def answer_backend(document: dict):
    """A model that answers yes/no questions."""
    return {"output_text": "yes" if "prime" in document["input"] else "no"}, 12, 1


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class OracleAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        admin = address_of(chain.admin)
        cls.oracle = chain.proxy(chain.deploy(_artifact("MycoInferenceOracleV11.sol", "MycoInferenceOracleV11")), encode_call(
            "initialize(address,address,address)", ["address", "address", "address"], [admin, chain.settlement, chain.registry]))
        chain.send(chain.admin, chain.settlement, encode_call("setOracle(address)", ["address"], [cls.oracle]))
        cls.app = chain.deploy(_artifact("MycoInferenceExample.sol", "MycoInferenceExample"),
                               abi_encode(["address", "address", "address"], [cls.oracle, chain.settlement, chain.token]))
        chain.send(chain.admin, chain.token, encode_call("mint(address,uint256)", ["address", "uint256"], [admin, 10_000_000]))
        chain.send(chain.admin, chain.token, encode_call("approve(address,uint256)", ["address", "uint256"], [cls.app, 2**255]))
        chain.send(chain.admin, cls.app, encode_call("fund(uint256)", ["uint256"], [5_000_000]))
        cls.reader = oracle.OracleReader(chain.rpc, cls.oracle)
        cls.cases = jury.CaseReader(chain.rpc, chain.deployment, chain.registry)
        cls.core = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, tmp / "relay")
        cls.desk = DisputeDesk(cls.core, cls.cases, chain.relay, chain.rpc)
        worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=chain.deployment,
                                backend=answer_backend, prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",),
                                data_dir=tmp / "provider", tier=1, oracle=cls.reader,
                                pricing=NetworkPricing(chain.rpc, chain.registry))  # the price moves day to day
        now = chain.now()
        cls.core.register_provider(worker.descriptor(now), lambda job: worker.handle_job(job, now=cls.chain.now()), now=now)
        cls.dispatcher = OracleDispatcher(cls.core, cls.reader, cls.cases, chain.rpc, chain.relay)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.chain.close()
        cls.tmp.cleanup()

    def _ask(self, question: str, finality: int) -> str:
        receipt = self.chain.send(self.chain.admin, self.app, encode_call(
            ASK, ["uint32", "string", "string", "uint256", "uint8"], [1, "gpt-5.5", question, 200_000, finality]))
        return next(entry["topics"][1] for entry in receipt["logs"] if entry["topics"][0] == oracle.REQUESTED)

    def _answer_of(self, request_id: str) -> bytes:
        raw = rpc.eth_call(self.chain.rpc, self.app, encode_call("answers(bytes32)", ["bytes32"], [request_id]))
        data = bytes.fromhex(raw[2:])
        return data[64:64 + int.from_bytes(data[32:64], "big")]

    def test_1_contract_gets_its_answer_in_the_callback(self) -> None:
        request_id = self._ask("Is 7 prime? Answer yes or no.", 0)
        self.assertEqual(self.reader.info(request_id)["state"], "open")
        self.assertEqual(self.dispatcher.cycle(), [(request_id, "delivered")])
        self.assertEqual(self._answer_of(request_id), b"yes")
        info = self.reader.info(request_id)
        record = self.cases.settlement(info["settlement_key"])
        # Paid from the contract's own deposit at the network price, escrowed like any request.
        self.assertEqual((record["owner"], record["status"], record["fee"]), (self.app, "pending", 100))  # the minimum fee
        reserved = int(rpc.eth_call(self.chain.rpc, self.chain.settlement,
                                    encode_call("oracleReserved(address)", ["address"], [self.app])), 16)
        self.assertEqual(reserved, 0)
        self.assertEqual(self.dispatcher.cycle(), [])  # answered once

    def test_2_final_answers_wait_for_the_dispute_window(self) -> None:
        request_id = self._ask("Is 9 prime? Answer yes or no.", 1)
        self.assertEqual(self.dispatcher.cycle(), [(request_id, "answered")])
        self.assertEqual(self._answer_of(request_id), b"")
        self.chain.advance(DISPUTE_WINDOW + 1)
        self.chain.send(self.chain.admin, self.chain.settlement, encode_release(self.reader.info(request_id)["settlement_key"]))
        self.assertEqual(self.dispatcher.cycle(), [(request_id, "delivered")])
        self.assertEqual(self._answer_of(request_id), b"yes")

    def test_3_the_named_disputer_takes_an_answer_to_a_jury_with_public_evidence(self) -> None:
        request_id = self._ask("Is the sky green? Answer yes or no.", 0)
        self.dispatcher.cycle()
        # Everything a jury needs is on-chain: the request log and the answer log with its signed receipt.
        request = self.reader.request(request_id)
        signed, response = self.reader.answer(request_id)
        self.assertEqual(response, b"no")
        evidence = oracle.build_evidence(request, signed, response, self.oracle, 31337, reason_code="wrong_answer",
                                         statement="The sky is not green; the answer is right, testing the path.")
        _, document, answer = jury.verify_evidence(evidence, self.chain.deployment)
        self.assertEqual((document["input"], answer["output_text"]), ("Is the sky green? Answer yes or no.", "no"))
        tampered = dict(evidence, response="eWVz")  # "yes": not what the Provider signed
        with self.assertRaises(Exception):
            jury.verify_evidence(tampered, self.chain.deployment)
        key = signed.authorization.settlement_key
        self.chain.send(self.chain.admin, self.chain.token, encode_call(
            "approve(address,uint256)", ["address", "uint256"], [self.chain.settlement, 2**255]))
        self.chain.send(self.chain.admin, self.chain.settlement, jury.encode_open_dispute(key, jury.evidence_hash(evidence)))
        accepted = self.desk.submit_evidence(evidence)
        self.assertEqual(accepted["report_id"], jury.report_id(key, address_of(self.chain.admin), jury.evidence_hash(evidence)))
        self.assertEqual(self.cases.settlement(key)["status"], "disputed")

    def test_4_unanswered_requests_return_their_reservation(self) -> None:
        self.core.suspend(address_of(PROVIDER_SIGNER), "test: no Provider serves")
        try:
            request_id = self._ask("Is 11 prime? Answer yes or no.", 0)
            self.assertEqual(self.dispatcher.cycle(), [])
            self.chain.advance(3_600 + 121)
            before = int(decode_words(rpc.eth_call(self.chain.rpc, self.chain.settlement, encode_call(
                "availableBalance(address)", ["address"], [self.app])), 1)[0].hex(), 16)
            self.assertEqual(self.dispatcher.cycle(), [(request_id, "expired")])
            after = int(decode_words(rpc.eth_call(self.chain.rpc, self.chain.settlement, encode_call(
                "availableBalance(address)", ["address"], [self.app])), 1)[0].hex(), 16)
            self.assertEqual(after - before, 200_000)
        finally:
            self.core.suspended.clear()


if __name__ == "__main__":
    unittest.main()
