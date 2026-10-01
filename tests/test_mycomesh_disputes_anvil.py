"""V11 disputes end to end: Consumer evidence, drand jury, Provider-AI votes, Relay probes."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from mycomesh import jury, rpc
from mycomesh.consumer import dispute_evidence, open_response, prepare_request
from mycomesh.evm import abi_encode, address_of, encode_call, keccak256
from mycomesh.identity import create_identity
from mycomesh.protocol import Prices
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.disputes import DisputeDesk
from mycomesh.probe_evidence import ProbeEvidenceError, verify_probe_evidence
from mycomesh.relay.probes import MULTIPLY_ONLY, ProbeRunner
from mycomesh.relay.server import RelayServer
from mycomesh.settlement import encode_release
from tests.mycomesh_anvil import CONSUMER_KEY, PARAMS, PARAMS_ABI, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

# drand quicknet round 1,000,000 (uncompressed G1), the same vector the forge suite verifies.
ROUND = 1_000_000
ROUND_SIGNATURE = bytes.fromhex(
    "0000000000000000000000000000000003ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72"
    "0000000000000000000000000000000001776ff7408b39c5f6f9fa50746efd7eea17fbb61f2e7b9c849ff0528e5a3deeedd029d0df345199963d75ba93b5a02a"
)
ASSIGNMENTS_SLOT = 10  # ProviderJuryRegistryV11.assignments (forge inspect storageLayout)
WINDOW = 600
ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "packages/mycomesh-cli/bin/mycomesh-consumer.mjs"
JURORS = [("0x" + f"{n}" * 64, "0x" + f"{n + 3}" * 64) for n in (4, 5, 6)]  # (owner, signer)


def _text(document: dict) -> str:
    if document["endpoint"] == "chat":
        return " ".join(str(m.get("content")) for m in document["messages"])
    return str(document["input"])


def honest_backend(document: dict):
    """Answers arithmetic correctly; as a juror, confirms only responses that are unrelated to the request."""
    text = _text(document)
    if "Provider-AI juror" in text:
        case = json.loads(document["messages"][1]["content"].split("\n", 1)[1])
        unrelated = "UNRELATED" in json.dumps(case["response"])
        verdict = {"confirmed": unrelated, "confidence_bps": 9500,
                   "reason_code": "unrelated_response" if unrelated else "delivered", "reasoning": "checked"}
        return {"choices": [{"message": {"role": "assistant", "content": json.dumps(verdict)}}]}, 40, 20
    numbers = [int(n) for n in re.findall(r"\b\d+\b", text)]
    answer = str(numbers[0] * numbers[1]) if len(numbers) >= 2 else "ok"
    return {"output_text": answer, "usage": {"input_tokens": 10, "output_tokens": 2}}, 10, 2


def lying_backend(document: dict):
    return {"output_text": "UNRELATED: buy tokens now"}, 10, 5


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class DisputesAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        chain.send(chain.admin, chain.settlement, encode_call(
            "setParams((uint64,uint64,uint64,uint256,uint16,uint16,uint64,uint256,uint16,uint256,uint16,uint256,uint16,uint16,address))",
            [PARAMS_ABI], [[WINDOW] + PARAMS[1:] + [address_of(chain.admin)]]))
        cls.cases = jury.CaseReader(chain.rpc, chain.deployment, chain.registry)
        for owner, signer in JURORS:
            rpc.wait_for_receipt(chain.rpc, rpc.send_transaction(chain.rpc, chain.admin, to=address_of(owner), value=10**18))
            chain.send(owner, chain.settlement, encode_call("authorizeProviderSigner(address)", ["address"], [address_of(signer)]))
            chain.price_signer(owner, address_of(signer))
            chain.send(owner, chain.registry, encode_call(
                "register(address,bytes32,bytes32,bytes32)", ["address", "bytes32", "bytes32", "bytes32"],
                [address_of(signer)] + ["0x" + keccak256(v).hex() for v in (owner.encode(), signer.encode(), b"gpt-5.5")]))
        # The Relay owner funds its probe keys and reporter bonds from its own deposit.
        relay_owner = address_of(chain.relay)
        chain.send(chain.admin, chain.token, encode_call("mint(address,uint256)", ["address", "uint256"], [relay_owner, 100_000_000]))
        chain.send(chain.relay, chain.token, encode_call("approve(address,uint256)", ["address", "uint256"], [chain.settlement, 2**255]))
        chain.send(chain.relay, chain.settlement, encode_call("deposit(uint256)", ["uint256"], [50_000_000]))

        cls.core = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, tmp / "relay")
        cls.desk = DisputeDesk(cls.core, cls.cases, chain.relay, chain.rpc, beacon=lambda round_: ROUND_SIGNATURE)
        cls.probes = ProbeRunner(cls.core, cls.cases, cls.desk, owner_private=chain.relay, submitter_private=chain.relay,
                                 rpc_url=chain.rpc, keys_per_batch=1, tasks=MULTIPLY_ONLY, ledger=chain.ledger)
        # Commit two one-key batches now: test 1 moves the chain clock past the wall clock, and a probe
        # must be issued after its commitment.
        cls.probes.commit_keys()
        cls.probes.commit_keys()
        cls.relay = RelayServer(cls.core, ("127.0.0.1", 0), ("127.0.0.1", 0), chain.relay, chain.rpc, WINDOW,
                                settle_interval=3_600, settle_count=10_000, desk=cls.desk, dispute_interval=3_600)
        cls.relay.start()
        cls.url = f"http://127.0.0.1:{cls.relay.http_address[1]}"
        cls.stop = threading.Event()
        cls.links = []
        for index, (signer, backend) in enumerate([(PROVIDER_SIGNER, lying_backend)] + [(s, honest_backend) for _, s in JURORS]):
            worker = ProviderWorker(
                identity=create_identity(), provider_private=signer, deployment=chain.deployment, backend=backend,
                prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",), data_dir=tmp / f"provider{index}", cases=cls.cases,
            )
            cls.links += run_provider(worker, [RelayEndpoint("127.0.0.1", cls.relay.link_address[1])], cls.stop)
        deadline = time.monotonic() + 20
        while len(cls.core.providers) < 4 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(cls.core.providers) == 4, "Providers did not connect"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop.set()
        cls.relay.stop()
        cls.chain.close()
        cls.tmp.cleanup()

    def _post(self, path: str, payload: dict) -> dict:
        request = urllib.request.Request(self.url + path, data=json.dumps(payload).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise AssertionError(f"{path}: {exc.code} {exc.read().decode()}") from None

    def _request(self, signer_private: str, text: str):
        signer = address_of(signer_private)
        with urllib.request.urlopen(self.url + "/providers", timeout=10) as response:
            descriptor = next(d for d in json.loads(response.read())["providers"] if d["provider_signer"] == signer)
        prepared = prepare_request(descriptor=descriptor, deployment=self.chain.deployment, key_private=CONSUMER_KEY,
                                   relay_signer=address_of(RELAY_SIGNER), endpoint="responses", model="gpt-5.5",
                                   content=text, max_output_tokens=100, max_fee=1_000_000)
        response, signed = open_response(prepared, self._post("/v11/requests", prepared.payload), self.chain.deployment)
        return prepared, response, signed

    def _pin_round(self, key: str) -> None:
        """Move a pending draw onto drand round 1,000,000 so the known beacon can finalize it offline."""
        slot = keccak256(abi_encode(["bytes32", "uint256"], [key, ASSIGNMENTS_SLOT]))
        self.assertEqual(self.cases.assignment(key)["status"], "pending")
        rpc.call(self.chain.rpc, "anvil_setStorageAt", [self.chain.registry, "0x" + slot.hex(),
                                                        "0x" + ((1 << 64) | ROUND).to_bytes(32, "big").hex()])

    def _adjudicate(self, key: str) -> list[str]:
        self._pin_round(key)
        return [action for _ in range(3) for case, action in self.desk.cycle() if case == key]

    @unittest.skipUnless(shutil.which("node") and (ROOT / "packages/mycomesh-cli/node_modules/@noble/curves").exists(),
                         "Node Consumer dependencies are required")
    def test_0_node_consumer_records_and_disputes_a_request(self) -> None:
        tmp = Path(self.tmp.name)
        network = tmp / "network.json"
        network.write_text(json.dumps({
            "schema": "mycomesh.v11.network.v1", "network_id": "anvil-test", "chain_id": 31337,
            "settlement": self.chain.settlement, "stablecoin": self.chain.token, "registry": self.chain.registry,
            "rpc_urls": [self.chain.rpc], "relays": [{"url": self.url, "signer": address_of(RELAY_SIGNER)}],
        }))
        owner_key = tmp / "owner.key"
        owner_key.write_text(self.chain.consumer + "\n")

        def cli(*args: str) -> str:
            result = subprocess.run(["node", str(CLI), *args, "--network", str(network), "--data-dir", str(tmp / "node")],
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

        subprocess.run(["node", str(CLI), "init", "--data-dir", str(tmp / "node")], check=True, capture_output=True,
                       env={**os.environ, "MYCOMESH_WALLET_PASSWORD": "test wallet password"})
        cli("setup", "--owner-key-file", str(owner_key), "--deposit", "10000000", "--max-per-request", "1000000")
        reply = json.loads(cli("request", "--provider", address_of(PROVIDER_SIGNER), "what", "is", "6", "times", "7"))
        self.assertIn("UNRELATED", reply["output_text"])
        self.core.settle_queued(self.chain.relay, self.chain.rpc)
        disputed = json.loads(cli("dispute", "last", "--owner-key-file", str(owner_key), "--statement", "off-topic answer"))
        # The relay recomputed the Node evidence hash in Python and found it committed on-chain.
        self.assertEqual(disputed["relays_accepted"], [self.url])
        self.assertEqual(disputed["settlement_key"], reply["settlement_key"])
        self.assertEqual(self.cases.settlement(reply["settlement_key"])["status"], "disputed")
        self.assertEqual(self.desk.state(reply["settlement_key"]), "open")

    def test_1_jurors_earn_eligibility_then_confirm_a_consumer_dispute(self) -> None:
        # Each juror earns counted volume from a released, undisputed request.
        keys = [self._request(signer, f"what is {n} times 7")[2].authorization.settlement_key
                for n, (_, signer) in zip((3, 4, 5), JURORS)]
        self.core.settle_queued(self.chain.relay, self.chain.rpc)
        self.chain.advance(WINDOW + 1)
        for key in keys:
            self.chain.send(self.chain.admin, self.chain.settlement, encode_release(key))

        owner = address_of(self.chain.consumer)
        prepared, response, signed = self._request(PROVIDER_SIGNER, "what is 12 times 12")
        self.assertIn("UNRELATED", response["output"]["output_text"])
        self.core.settle_queued(self.chain.relay, self.chain.rpc)
        key = signed.authorization.settlement_key
        before = self.chain.reader.available_balance(owner) + self.chain.reader.claimable_balance(owner)

        evidence = dispute_evidence(prepared, signed, reason_code="unrelated_response",
                                    statement="The answer has nothing to do with the question.")
        # The Node setup in test_0 replaced the fixture's allowance; the reporter bond needs one again.
        self.chain.send(self.chain.consumer, self.chain.token, encode_call(
            "approve(address,uint256)", ["address", "uint256"], [self.chain.settlement, 2**255]))
        self.chain.send(self.chain.consumer, self.chain.settlement, jury.encode_open_dispute(key, jury.evidence_hash(evidence)))
        accepted = self._post("/v11/evidence", evidence)
        self.assertEqual(accepted["report_id"], jury.report_id(key, owner, jury.evidence_hash(evidence)))
        with urllib.request.urlopen(f"{self.url}/v11/evidence/{accepted['evidence_hash']}", timeout=10) as reply:
            self.assertEqual(json.loads(reply.read()), evidence)
        tampered = dict(evidence, allegation={"reason_code": "x", "statement": "edited"})
        with self.assertRaises(AssertionError):
            self._post("/v11/evidence", tampered)

        self.assertEqual(self._adjudicate(key), ["jury_drawn", "confirmed"])
        self.assertEqual(self.cases.settlement(key)["status"], "confirmed")
        assignment = self.cases.assignment(key)
        self.assertEqual(sorted(assignment["juror_signers"]), sorted(address_of(s) for _, s in JURORS))
        self.assertGreater(self.chain.reader.available_balance(owner) + self.chain.reader.claimable_balance(owner), before)

    def test_2_relay_probes_void_honest_providers_and_dispute_liars(self) -> None:
        honest = address_of(JURORS[0][1])
        result = self.probes.probe(honest)  # a batch of one key: answered, then voided by its fresh owner at once
        self.assertEqual(result.outcome, "answered", result.detail)
        self.assertEqual(self.cases.settlement(result.settlement_key)["status"], "voided")
        self.assertEqual(self.cases.probe_void(result.settlement_key)["hunter"], address_of(self.chain.relay))
        owner = self.cases.settlement(result.settlement_key)["owner"]
        self.assertNotEqual(owner, address_of(self.chain.relay))  # the probe key's owner is not the Relay
        # The verdict is on-chain, and anyone can re-grade the published evidence.
        verdict = int(rpc.eth_call(self.chain.rpc, self.chain.ledger, encode_call("verdictOf(bytes32)", ["bytes32"], [result.settlement_key])), 16)
        self.assertEqual(verdict, 1)
        logs = rpc.call(self.chain.rpc, "eth_getLogs", [{"address": self.chain.ledger, "fromBlock": "0x0", "toBlock": "latest"}])
        evidence_hash = "0x" + logs[-1]["data"][2:66]
        with urllib.request.urlopen(f"{self.url}/v11/evidence/{evidence_hash}", timeout=10) as reply:
            evidence = json.loads(reply.read())
        self.assertEqual(jury.evidence_hash(evidence), evidence_hash)
        self.assertEqual(verify_probe_evidence(evidence, self.chain.deployment), (honest, "pass"))
        forged = json.loads(json.dumps(evidence))
        forged["verdict"] = "wrong"  # a Relay claiming a correct answer was wrong is caught on re-grading
        with self.assertRaises(ProbeEvidenceError):
            verify_probe_evidence(forged, self.chain.deployment)

        result = self.probes.probe(address_of(PROVIDER_SIGNER))
        self.assertEqual((result.outcome, result.grade), ("answered", "unrelated"), result.detail)
        self.assertEqual(self.cases.settlement(result.settlement_key)["status"], "disputed")
        self.assertIn(address_of(PROVIDER_SIGNER), self.core.suspended)
        self.assertNotIn(address_of(PROVIDER_SIGNER), [d["provider_signer"] for d in self.core.provider_descriptors()])
        self.assertEqual(self.desk.state(result.settlement_key), "open")
        self.assertEqual(self._adjudicate(result.settlement_key), ["jury_drawn", "confirmed"])
        self.assertEqual(self.cases.settlement(result.settlement_key)["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
