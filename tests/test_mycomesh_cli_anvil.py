"""The ``python -m mycomesh`` entrypoints as separate processes, plus the bridge keeper."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from mycomesh import jury
from mycomesh.consumer import open_response, prepare_request
from mycomesh.evm import address_of
from mycomesh.keeper import Keeper
from tests.mycomesh_anvil import CONSUMER_KEY, DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available
from tests.test_mycomesh_node_consumer_anvil import FakeOpenAI

ROOT = Path(__file__).resolve().parents[1]


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class CliAnvilTest(unittest.TestCase):
    def setUp(self) -> None:
        self.chain = AnvilV11()
        self.addCleanup(self.chain.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        model = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAI)
        threading.Thread(target=model.serve_forever, daemon=True).start()
        self.addCleanup(model.shutdown)
        self.model_url = f"http://127.0.0.1:{model.server_address[1]}/v1"

    def _key(self, name: str, value: str) -> str:
        path = self.tmp / f"{name}.key"
        path.write_text(value + "\n")
        return str(path)

    def _spawn(self, *args: str) -> subprocess.Popen:
        process = subprocess.Popen([sys.executable, "-m", "mycomesh", *args], cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, env={**os.environ, "PYTHONPATH": str(ROOT)})
        self.addCleanup(lambda: (process.terminate(), process.wait(10), process.stdout.close()))
        return process

    def test_relay_and_provider_processes_serve_and_settle_and_keeper_releases(self) -> None:
        http, link = _port(), _port()
        network = self.tmp / "network.json"
        network.write_text(json.dumps({
            "schema": "mycomesh.v11.network.v1", "network_id": "anvil-cli", "chain_id": 31337,
            "settlement": self.chain.settlement, "stablecoin": self.chain.token, "registry": self.chain.registry,
            "rpc_urls": [self.chain.rpc], "deployment_block": 0,
            "relays": [{"url": f"http://127.0.0.1:{http}", "signer": address_of(RELAY_SIGNER),
                        "link": f"127.0.0.1:{link}", "link_tls": False}],
        }))
        self._spawn("relay", "serve", "--network", str(network), "--owner-key", self._key("relay-owner", self.chain.relay),
                    "--signer-key", self._key("relay-signer", RELAY_SIGNER), "--data-dir", str(self.tmp / "relay"),
                    "--http", f"127.0.0.1:{http}", "--link", f"127.0.0.1:{link}", "--probe-interval", "0",
                    "--settle-interval", "0", "--settle-count", "1")
        self._spawn("provider", "serve", "--network", str(network), "--signer-key", self._key("provider", PROVIDER_SIGNER),
                    "--identity", str(self.tmp / "provider/identity.json"), "--data-dir", str(self.tmp / "provider"),
                    "--backend", "openai", "--base-url", self.model_url, "--model", "gpt-5.5")
        descriptor = None
        deadline = time.monotonic() + 30
        while descriptor is None and time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{http}/providers", timeout=2) as response:
                    descriptor = (json.loads(response.read())["providers"] or [None])[0]
            except OSError:
                pass
            time.sleep(0.2)
        self.assertIsNotNone(descriptor, "Provider process did not register with the Relay process")

        prepared = prepare_request(descriptor=descriptor, deployment=self.chain.deployment, key_private=CONSUMER_KEY,
                                   relay_signer=address_of(RELAY_SIGNER), endpoint="responses", model="gpt-5.5",
                                   content="via processes", max_output_tokens=50, max_fee=1_000_000)
        request = urllib.request.Request(f"http://127.0.0.1:{http}/v11/requests", data=json.dumps(prepared.payload).encode(),
                                         method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            reply, signed = open_response(prepared, json.loads(response.read()), self.chain.deployment)
        self.assertEqual(reply["output"]["output_text"], "hello from v11: via processes")
        key = signed.authorization.settlement_key
        cases = jury.CaseReader(self.chain.rpc, self.chain.deployment, self.chain.registry)
        deadline = time.monotonic() + 30
        while cases.settlement(key)["status"] != "pending" and time.monotonic() < deadline:
            time.sleep(0.3)
        self.assertEqual(cases.settlement(key)["status"], "pending")

        keeper = Keeper(cases, self.chain.admin, self.tmp / "keeper", start_block=0, grace=60)
        self.assertEqual(keeper.scan(), 1)
        self.assertEqual(keeper.act(), [])  # still inside the dispute window
        self.chain.advance(DISPUTE_WINDOW + 61)
        self.assertEqual(keeper.act(), [(key, "released")])
        self.assertEqual(cases.settlement(key)["status"], "released")
        self.assertEqual(keeper.scan(), 0)


if __name__ == "__main__":
    unittest.main()
