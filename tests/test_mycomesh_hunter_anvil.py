"""Open probing end to end: a third-party hunter catches a Provider serving a weaker model and is paid.

The hunter is an ordinary Consumer to the Relay. It probes through the Relay's public route with
keys owned by fresh accounts, voids its probes in batches, then accuses the Provider with every probe
it voided. A jury of same-tier Providers replays each probe on its own model and convicts.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from mycomesh import capability, hunting, jury, rpc
from mycomesh.consumer import open_response, prepare_request
from mycomesh.evm import abi_encode, address_of, encode_call, keccak256
from mycomesh.hunter import hunter_runner
from mycomesh.identity import create_identity
from mycomesh.network import load_network
from mycomesh.protocol import Prices
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.disputes import DisputeDesk
from mycomesh.relay.server import RelayServer
from mycomesh.settlement import encode_release
from tests.mycomesh_anvil import CONSUMER_KEY, PARAMS, PARAMS_ABI, RELAY_SIGNER, AnvilV11, available
from tests.test_mycomesh_disputes_anvil import ASSIGNMENTS_SLOT, ROUND, ROUND_SIGNATURE

WINDOW = 600
JURORS = [("0x" + f"{n}" * 64, "0x" + f"{n + 3}" * 64) for n in (4, 5, 6)]  # (owner, signer)
CHEAT_OWNER, CHEAT_SIGNER = "0x" + "71" * 32, "0x" + "72" * 32
HUNTER = "0x" + "4b" * 32
TASKS: dict[str, capability.CapabilityTask] = {}
ORIGINAL = capability.random_task


def remembered_task(kind: str | None = None) -> capability.CapabilityTask:
    task = ORIGINAL(kind)
    TASKS[task.question] = task
    return task


def _text(document: dict) -> str:
    return json.dumps(document.get("messages") or document.get("input"))


def frontier(document: dict):
    """The tier's model: answers every hard task (looked up), and anything else plainly."""
    text = _text(document)
    answer = next((task.reference for question, task in TASKS.items() if json.dumps(question)[1:-1] in text), "ok")
    return {"output_text": answer}, 20, 5


def small_model(document: dict):
    return {"output_text": "42"}, 20, 2


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class HunterAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        params = list(PARAMS)
        params[0], params[13] = WINDOW, 30  # short dispute window; 30 free probes a day per Provider
        chain.send(chain.admin, chain.settlement, encode_call(
            "setParams((uint64,uint64,uint64,uint256,uint16,uint16,uint64,uint256,uint16,uint256,uint16,uint256,uint16,uint16,address))",
            [PARAMS_ABI], [params + [address_of(chain.admin)]]))
        cls.cases = jury.CaseReader(chain.rpc, chain.deployment, chain.registry)
        for owner, signer in JURORS + [(CHEAT_OWNER, CHEAT_SIGNER)]:
            rpc.wait_for_receipt(chain.rpc, rpc.send_transaction(chain.rpc, chain.admin, to=address_of(owner), value=10**18))
            chain.send(owner, chain.settlement, encode_call("authorizeProviderSigner(address)", ["address"], [address_of(signer)]))
            chain.price_signer(owner, address_of(signer))
        for owner, signer in JURORS:  # the vote signer is the Provider signer, priced in tier 1
            chain.send(owner, chain.registry, encode_call(
                "register(address,bytes32,bytes32,bytes32)", ["address", "bytes32", "bytes32", "bytes32"],
                [address_of(signer)] + ["0x" + keccak256(v).hex() for v in (owner.encode(), signer.encode(), b"gpt-5.5")]))
        hunter = address_of(HUNTER)
        rpc.wait_for_receipt(chain.rpc, rpc.send_transaction(chain.rpc, chain.admin, to=hunter, value=10**21))  # anvil gas gets dear
        chain.send(chain.admin, chain.token, encode_call("mint(address,uint256)", ["address", "uint256"], [hunter, 100_000_000]))
        chain.send(HUNTER, chain.token, encode_call("approve(address,uint256)", ["address", "uint256"], [chain.settlement, 2**255]))

        core = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, tmp / "relay")
        cls.desk = DisputeDesk(core, cls.cases, chain.relay, chain.rpc, beacon=lambda round_: ROUND_SIGNATURE)
        cls.relay = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", 0), chain.relay, chain.rpc, WINDOW,
                                settle_interval=0.0, settle_count=1, desk=cls.desk, dispute_interval=3_600)
        cls.relay.start()
        cls.url = f"http://127.0.0.1:{cls.relay.http_address[1]}"
        cls.stop = threading.Event()
        for index, (signer, backend) in enumerate([(s, frontier) for _, s in JURORS] + [(CHEAT_SIGNER, small_model)]):
            worker = ProviderWorker(identity=create_identity(), provider_private=signer, deployment=chain.deployment,
                                    backend=backend, prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",),
                                    data_dir=tmp / f"provider{index}", cases=cls.cases, tier=1)
            run_provider(worker, [RelayEndpoint("127.0.0.1", cls.relay.link_address[1])], cls.stop)
        deadline = time.monotonic() + 20
        while len(core.providers) < 4 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(core.providers) == 4, "Providers did not connect"
        cls.manifest = tmp / "network.json"
        cls.manifest.write_text(json.dumps(chain.manifest([{"url": cls.url, "signer": address_of(RELAY_SIGNER),
                                                             "link": f"127.0.0.1:{cls.relay.link_address[1]}"}])))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop.set()
        cls.relay.stop()
        cls.chain.close()
        cls.tmp.cleanup()

    def _pay(self, signer_private: str) -> str:
        """An ordinary paid request to one Provider."""
        signer = address_of(signer_private)
        descriptor = next(d for d in self.relay.core.provider_descriptors() if d["provider_signer"] == signer)
        prepared = prepare_request(descriptor=descriptor, deployment=self.chain.deployment, key_private=CONSUMER_KEY,
                                   relay_signer=address_of(RELAY_SIGNER), endpoint="responses", model="gpt-5.5",
                                   content="hello", max_output_tokens=50, max_fee=1_000_000)
        _, signed = open_response(prepared, self.relay.core.handle_request(prepared.payload), self.chain.deployment)
        return signed.authorization.settlement_key

    def test_hunter_catches_a_downgraded_provider_and_is_paid(self) -> None:
        chain = self.chain
        # Jurors earn eligibility, and the cheater earns holdback, from ordinary released requests.
        keys = [self._pay(signer) for _, signer in JURORS] + [self._pay(CHEAT_SIGNER)]
        self.relay.core.settle_queued(chain.relay, chain.rpc)
        cheat = address_of(CHEAT_OWNER)

        runner = hunter_runner(load_network(self.manifest), HUNTER, Path(self.tmp.name) / "hunter")
        runner.capability_share = 1.0
        with mock.patch.object(capability, "random_task", side_effect=remembered_task):
            for _ in range(20):
                result = runner.probe(address_of(CHEAT_SIGNER))
                self.assertEqual((result.outcome, result.grade), ("answered", "wrong"), result.detail)
            deadline = time.monotonic() + 60
            while runner.pending() and time.monotonic() < deadline:  # the Relay settles probes like any request
                runner.flush(force=True)
                time.sleep(0.5)
            self.assertEqual(runner.capability_score(address_of(CHEAT_SIGNER), 1), (0, 20))
            day = self.cases.probe_void(result.settlement_key)["day"]
            self.assertEqual(self.cases.hunter_probe_voids(address_of(HUNTER), cheat, day), 20)
            # The probe keys belonged to fresh accounts, never to the hunter.
            self.assertNotEqual(self.cases.settlement(result.settlement_key)["owner"], address_of(HUNTER))

            chain.advance(WINDOW + 1)  # (probes go first: their Providers check issuance against the wall clock)
            for key in keys:
                chain.send(chain.admin, chain.settlement, encode_release(key))
            chain.advance(86_400)  # cases cover closed days only
            [case] = runner.maybe_open_cases()
            self.assertEqual(case, hunting.case_id(address_of(HUNTER), cheat, day, day))
            record = self.cases.capability_case(case)
            self.assertEqual((record["status"], record["probes"]), ("open", 20))
            # The hunter published the evidence to the Relay's desk, which runs the jury.
            slot = keccak256(abi_encode(["bytes32", "uint256"], [case, ASSIGNMENTS_SLOT]))
            rpc.call(chain.rpc, "anvil_setStorageAt", [chain.registry, "0x" + slot.hex(),
                                                      "0x" + ((1 << 64) | ROUND).to_bytes(32, "big").hex()])
            actions = []
            deadline = time.monotonic() + 60
            while "confirmed" not in actions and time.monotonic() < deadline:
                actions += [action for key, action in self.desk.cycle() if key == case]
                time.sleep(0.5)
        self.assertEqual(actions[0], "jury_drawn")
        self.assertIn("confirmed", actions)
        record = self.cases.capability_case(case)
        self.assertEqual(record["status"], "confirmed")
        jurors = self.cases.assignment(case)["juror_signers"]
        self.assertEqual(sorted(jurors), sorted(address_of(s) for _, s in JURORS))  # same-tier, never the accused
        hunter = address_of(HUNTER)
        self.assertEqual(chain.reader.claimable_balance(hunter), record["bond"] + record["bounty"])
        self.assertGreater(record["penalty"], 0)
        owed = int(rpc.eth_call(chain.rpc, chain.emission, encode_call("mycoBountyOwed(address)", ["address"], [hunter])), 16)
        self.assertGreater(owed, 0)


if __name__ == "__main__":
    unittest.main()
