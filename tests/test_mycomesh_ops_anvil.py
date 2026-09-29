"""Operator features: relay directory discovery, faucet, earnings and claims, monitoring."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from mycomesh import account, rpc
from mycomesh.consumer import open_response, prepare_request
from mycomesh.directory import encode_announce, list_relays
from mycomesh.evm import address_of, encode_call
from mycomesh.identity import create_identity
from mycomesh.monitor import Monitor
from mycomesh.network import load_network
from mycomesh.protocol import Prices
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.faucet import Faucet
from mycomesh.relay.server import RelayServer
from mycomesh.settlement import encode_release
from tests.mycomesh_anvil import (ANVIL_KEYS, CONSUMER_KEY, DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11,
                                  available)

FAUCET_KEY = "0x" + "77" * 32


def echo(document: dict):
    return {"output_text": "echo"}, 1_000, 1_000


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class OpsAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        rpc.wait_for_receipt(chain.rpc, rpc.send_transaction(chain.rpc, chain.admin, to=address_of(FAUCET_KEY), value=10**18))
        core = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, tmp / "relay")
        cls.faucet = Faucet(FAUCET_KEY, chain.rpc, chain.token, tmp / "relay", eth_wei=10**15, usdc_units=5_000_000)
        cls.relay = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", 0), chain.relay, chain.rpc, DISPUTE_WINDOW,
                                settle_interval=0.0, settle_count=1, faucet=cls.faucet)
        cls.relay.start()
        cls.url = f"http://127.0.0.1:{cls.relay.http_address[1]}"
        # The Relay announces itself on-chain; the manifest lists no Relays at all.
        chain.send(chain.relay, chain.directory, encode_announce(
            address_of(RELAY_SIGNER), cls.url, f"127.0.0.1:{cls.relay.link_address[1]}"))
        cls.manifest = tmp / "network.json"
        cls.manifest.write_text(json.dumps(chain.manifest([])))
        cls.network = load_network(cls.manifest)
        cls.stop = threading.Event()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop.set()
        cls.relay.stop()
        cls.chain.close()
        cls.tmp.cleanup()

    def _post(self, path: str, payload: dict, headers: dict | None = None) -> tuple[int, dict]:
        request = urllib.request.Request(self.url + path, data=json.dumps(payload).encode(), method="POST",
                                         headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=60) as reply:
                return reply.status, json.loads(reply.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_1_directory_discovery_joins_provider_and_serves_consumer(self) -> None:
        relays = self.network.all_relays()
        self.assertEqual([(r.url, r.signer) for r in relays], [(self.url, address_of(RELAY_SIGNER))])
        worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=self.chain.deployment,
                                backend=echo, prices=Prices(1_000, 1_000, 100), models=("gpt-5.5",),
                                data_dir=Path(self.tmp.name) / "provider")
        relay = relays[0]
        endpoint = RelayEndpoint(relay.link_host, relay.link_port, signer=relay.signer)
        links = run_provider(worker, [endpoint], self.stop)
        self.assertTrue(links[0].connected.wait(20), links[0].last_error)
        # A Provider refuses a Relay whose challenge signer differs from its announcement.
        impostor = run_provider(worker, [RelayEndpoint(relay.link_host, relay.link_port, signer="0x" + "12" * 20)], self.stop)
        time.sleep(1)
        self.assertFalse(impostor[0].connected.is_set())
        self.assertIn("differs", impostor[0].last_error or "")

        with urllib.request.urlopen(self.url + "/providers", timeout=10) as reply:
            descriptor = json.loads(reply.read())["providers"][0]
        prepared = prepare_request(descriptor=descriptor, deployment=self.chain.deployment, key_private=CONSUMER_KEY,
                                   relay_signer=relay.signer, endpoint="responses", model="gpt-5.5", content="hi",
                                   max_output_tokens=10, max_fee=1_000_000)
        status, body = self._post("/v11/requests", prepared.payload)
        self.assertEqual(status, 200, body)
        _, signed = open_response(prepared, body, self.chain.deployment)
        self.__class__.settled_key = signed.authorization.settlement_key

    def test_2_provider_earnings_and_claim(self) -> None:
        key = self.settled_key
        deadline = time.monotonic() + 30
        while not self.chain.reader.is_settled(key) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.chain.advance(DISPUTE_WINDOW + 1)
        self.chain.send(self.chain.admin, self.chain.settlement, encode_release(key))
        provider_owner = address_of(self.chain.provider)
        summary = account.summary(self.network, provider_owner)
        # Fee 2_000: 10% to the Relay; of the Provider's 1_800, 10% is held back.
        self.assertEqual((summary["claimable"], summary["holdback"], summary["in_escrow"]), (1_620, 180, 0))
        self.assertEqual(summary["clean_volume"], 2_000)
        before = int(rpc.eth_call(self.chain.rpc, self.chain.token, encode_call("balanceOf(address)", ["address"], [provider_owner])), 16)
        self.chain.send(self.chain.provider, self.chain.settlement, account.encode_claim())
        after = int(rpc.eth_call(self.chain.rpc, self.chain.token, encode_call("balanceOf(address)", ["address"], [provider_owner])), 16)
        self.assertEqual(after - before, 1_620)
        self.assertEqual(account.summary(self.network, provider_owner)["claimable"], 0)

    def test_3_faucet_funds_once_per_day(self) -> None:
        newcomer = "0x" + "ab" * 20
        status, body = self._post("/v11/faucet", {"address": newcomer}, {"X-Real-IP": "203.0.113.9"})
        self.assertEqual(status, 200, body)
        self.assertEqual(rpc.quantity(rpc.call(self.chain.rpc, "eth_getBalance", [newcomer, "latest"])), 10**15)
        balance = int(rpc.eth_call(self.chain.rpc, self.chain.token, encode_call("balanceOf(address)", ["address"], [newcomer])), 16)
        self.assertEqual(balance, 5_000_000)
        status, body = self._post("/v11/faucet", {"address": newcomer}, {"X-Real-IP": "203.0.113.9"})
        self.assertEqual(status, 429, body)
        status, _ = self._post("/v11/faucet", {"address": "not-an-address"})
        self.assertEqual(status, 400)

    def test_4_monitor_alerts_on_change_only(self) -> None:
        poor = "0x" + "cd" * 20
        monitor = Monitor(self.network, watch=(poor,), min_eth_wei=10**15)
        alerts = monitor.cycle()
        self.assertTrue(any(f"gas {poor}: low" in line for line in alerts), alerts)
        self.assertFalse(any("relay" in line for line in alerts), alerts)  # healthy Relay with a Provider
        self.assertEqual(monitor.cycle(), [])  # nothing changed, nothing repeated
        rpc.wait_for_receipt(self.chain.rpc, rpc.send_transaction(self.chain.rpc, self.chain.admin, to=poor, value=10**16))
        self.assertEqual(monitor.cycle(), [f"RESOLVED gas {poor}"])

    def test_5_directory_entry_goes_inactive_when_signer_revoked(self) -> None:
        self.chain.send(self.chain.relay, self.chain.settlement,
                        encode_call("revokeRelaySigner(address)", ["address"], [address_of(RELAY_SIGNER)]))
        self.assertFalse(list_relays(self.chain.rpc, self.chain.directory)[0]["active"])
        self.assertEqual(self.network.all_relays(), [])


if __name__ == "__main__":
    unittest.main()
