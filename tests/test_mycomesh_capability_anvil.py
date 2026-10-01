"""Capability probes end to end: a Provider serving a weaker model than its tier promises is caught."""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from mycomesh import capability, jury, rpc
from mycomesh.evm import address_of, encode_call, keccak256
from mycomesh.identity import create_identity
from mycomesh.probe_evidence import verify_probe_evidence
from mycomesh.protocol import Prices
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.disputes import DisputeDesk
from mycomesh.relay.probes import ProbeRunner
from tests.mycomesh_anvil import PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

PROBE_RECORDED = "0x" + keccak256(b"ProbeRecorded(address,address,bytes32,bytes32,uint8)").hex()
WEAK_OWNER, WEAK_SIGNER = "0x" + "71" * 32, "0x" + "72" * 32
TASKS: dict[str, capability.CapabilityTask] = {}


ORIGINAL = capability.random_task


def next_task(kind: str | None = None) -> capability.CapabilityTask:
    """The real generator, remembered so the stand-in frontier model can look its answer up."""
    task = ORIGINAL(kind)
    TASKS[task.question] = task
    return task


def frontier(document: dict):
    """Solves every capability task, as the calibrated tier models do."""
    text = document["input"] if isinstance(document.get("input"), str) else str(document.get("messages") or document.get("input"))
    answer = next((task.reference for question, task in TASKS.items() if question in text), "I am not sure.")
    return {"output_text": answer}, 20, 5


def small_model(document: dict):
    """Answers confidently and is usually wrong, like the small substitutes in the calibration."""
    return {"output_text": "42"}, 20, 2


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class CapabilityAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        rpc.wait_for_receipt(chain.rpc, rpc.send_transaction(chain.rpc, chain.admin, to=address_of(WEAK_OWNER), value=10**18))
        chain.send(WEAK_OWNER, chain.settlement, encode_call("authorizeProviderSigner(address)", ["address"], [address_of(WEAK_SIGNER)]))
        chain.price_signer(WEAK_OWNER, address_of(WEAK_SIGNER))
        relay_owner = address_of(chain.relay)
        chain.send(chain.admin, chain.token, encode_call("mint(address,uint256)", ["address", "uint256"], [relay_owner, 100_000_000]))
        chain.send(chain.relay, chain.token, encode_call("approve(address,uint256)", ["address", "uint256"], [chain.settlement, 2**255]))
        chain.send(chain.relay, chain.settlement, encode_call("deposit(uint256)", ["uint256"], [50_000_000]))
        cls.cases = jury.CaseReader(chain.rpc, chain.deployment, chain.registry)
        cls.core = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, tmp / "relay")
        cls.desk = DisputeDesk(cls.core, cls.cases, chain.relay, chain.rpc)
        cls.runner = ProbeRunner(cls.core, cls.cases, cls.desk, owner_private=chain.relay, submitter_private=chain.relay,
                                 rpc_url=chain.rpc, keys_per_batch=4, ledger=chain.ledger, capability_share=1.0,
                                 capability_minimum=10, open_cases=False)
        now = chain.now()
        for index, (signer, backend) in enumerate([(PROVIDER_SIGNER, frontier), (WEAK_SIGNER, small_model)]):
            worker = ProviderWorker(identity=create_identity(), provider_private=signer, deployment=chain.deployment,
                                    backend=backend, prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",),
                                    data_dir=tmp / f"provider{index}", tier=1)
            cls.core.register_provider(worker.descriptor(now), lambda job, w=worker: w.handle_job(job, now=cls.chain.now()), now=now)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.chain.close()
        cls.tmp.cleanup()

    def test_substitute_model_is_suspended_and_the_frontier_one_is_not(self) -> None:
        strong, weak = address_of(PROVIDER_SIGNER), address_of(WEAK_SIGNER)
        # Keep blocks coming, as on a live chain: a probe settles once a block is newer than its authorization.
        stop = threading.Event()
        threading.Thread(target=lambda: [rpc.call(self.chain.rpc, "evm_mine", []) for _ in iter(lambda: stop.wait(1), True)],
                         daemon=True).start()
        self.addCleanup(stop.set)
        with mock.patch.object(capability, "random_task", side_effect=lambda kind=None: next_task(kind)):
            for _ in range(10):  # the daily free-probe allowance per Relay and Provider
                for signer in (strong, weak):
                    if signer in self.core.suspended:
                        continue
                    result = self.runner.probe(signer)
                    self.assertEqual(result.outcome, "answered", result)
        self.runner.flush(force=True)
        self.assertEqual(self.runner.capability_score(strong, 1), (10, 10))
        self.assertEqual(self.runner.capability_score(weak, 1)[0], 0)
        self.assertNotIn(strong, self.core.suspended)
        self.assertIn("capability probes", self.core.suspended[weak])  # 0 of 10: 99% sure it is below 85%
        # Every verdict is on-chain under the capability codes, and re-grades from its public evidence.
        logs = rpc.call(self.chain.rpc, "eth_getLogs", [{"address": self.chain.ledger, "fromBlock": "0x0", "toBlock": "latest",
                                                          "topics": [PROBE_RECORDED]}])
        codes = {}
        for entry in logs:
            provider = "0x" + entry["topics"][1][26:]
            codes.setdefault(provider, set()).add(int(entry["data"][66:130], 16))
        self.assertEqual(codes, {address_of(self.chain.provider): {3}, address_of(WEAK_OWNER): {4}})  # by Provider owner
        evidence = self.desk.evidence(logs[-1]["data"][:66])
        self.assertEqual(verify_probe_evidence(evidence, self.chain.deployment)[1], "wrong")


    def test_z_restarted_runner_asks_no_more_than_its_batch_was_granted(self) -> None:
        """A Relay restart must not forget a batch's fee cap (its keys would be refused for the fee)."""
        self.runner.commit_keys()
        restarted = ProbeRunner(self.core, self.cases, self.desk, owner_private=self.chain.relay,
                                submitter_private=self.chain.relay, rpc_url=self.chain.rpc, max_fee=200_000,
                                ledger=self.chain.ledger, capability_share=1.0, open_cases=False, voids_per_day=100)
        with mock.patch.object(capability, "random_task", side_effect=lambda kind=None: next_task(kind)):
            result = restarted.probe(address_of(PROVIDER_SIGNER))
        self.assertEqual(result.outcome, "answered", result.detail)

if __name__ == "__main__":
    unittest.main()
