"""The Node V11 Consumer against the Python Relay and Provider on anvil."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mycomesh.evm import address_of
from mycomesh.identity import create_identity
from mycomesh.protocol import Prices
from mycomesh.provider.backends import OpenAICompatibleBackend
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.server import RelayServer
from tests.mycomesh_anvil import DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "packages/mycomesh-cli/bin/mycomesh-consumer.mjs"


class FakeOpenAI(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.endswith("/chat/completions"):
            reply = {"id": "chatcmpl_1", "model": body["model"], "choices": [{"index": 0, "message": {"role": "assistant", "content": "chat ok"}}],
                     "usage": {"prompt_tokens": 3, "completion_tokens": 2}}
        else:
            text = f"hello from v11: {body['input']}"
            reply = {"id": "resp_1", "object": "response", "status": "completed", "model": body["model"], "output_text": text,
                     "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}],
                     "usage": {"input_tokens": 10, "output_tokens": 5}}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _wait(predicate, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


@unittest.skipUnless(available() and shutil.which("node") and (ROOT / "packages/mycomesh-cli/node_modules/@noble/curves").exists(),
                     "anvil, forge artifacts and Node Consumer dependencies are required")
class NodeConsumerAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = AnvilV11(deposit=0)
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.model = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAI)
        threading.Thread(target=cls.model.serve_forever, daemon=True).start()
        cls.stop = threading.Event()
        core = RelayCore(cls.chain.deployment, RELAY_SIGNER, cls.chain.reader, tmp / "relay")
        cls.relay = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", 0), cls.chain.relay, cls.chain.rpc,
                                DISPUTE_WINDOW, settle_interval=0.0, settle_count=1)
        cls.relay.start()
        worker = ProviderWorker(
            identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=cls.chain.deployment,
            backend=OpenAICompatibleBackend(f"http://127.0.0.1:{cls.model.server_address[1]}/v1"),
            prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",), data_dir=tmp / "provider",
        )
        links = run_provider(worker, [RelayEndpoint("127.0.0.1", cls.relay.link_address[1])], cls.stop)
        assert _wait(lambda: links[0].connected.is_set()), "Provider did not connect"
        cls.network = tmp / "network.json"
        cls.network.write_text(json.dumps({
            "schema": "mycomesh.v11.network.v1", "network_id": "anvil-test", "chain_id": 31337,
            "settlement": cls.chain.settlement, "stablecoin": cls.chain.token, "registry": cls.chain.registry,
            "rpc_urls": [cls.chain.rpc],
            "relays": [{"url": f"http://127.0.0.1:{cls.relay.http_address[1]}", "signer": address_of(RELAY_SIGNER)}],
        }))
        cls.owner_key = tmp / "owner.key"
        cls.owner_key.write_text(cls.chain.consumer + "\n")
        cls.data = tmp / "consumer"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop.set()
        cls.relay.stop()
        cls.model.shutdown()
        cls.chain.close()
        cls.tmp.cleanup()

    def _cli(self, *args: str) -> str:
        result = subprocess.run(["node", str(CLI), *args, "--network", str(self.network), "--data-dir", str(self.data)],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_node_consumer_sets_up_requests_serves_and_settles(self) -> None:
        key = subprocess.run(["node", str(CLI), "init", "--data-dir", str(self.data)], capture_output=True, text=True).stdout.strip()
        self.assertRegex(key, r"^0x[0-9a-f]{40}$")
        self._cli("setup", "--owner-key-file", str(self.owner_key), "--deposit", "100000000", "--max-per-request", "2000000")
        owner = address_of(self.chain.consumer)
        self.assertEqual(self.chain.reader.available_balance(owner), 100_000_000)
        self.assertTrue(self.chain.reader.key_grant(key)["active"])

        reply = json.loads(self._cli("request", "--max-fee", "1000000", "ping", "from", "node"))
        self.assertEqual(reply["output_text"], "hello from v11: ping from node")
        self.assertEqual(reply["fee"], 100)  # 10 in + 5 out -> 30, raised to the 100 minimum fee

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = subprocess.Popen(["node", str(CLI), "serve", "--port", str(port), "--network", str(self.network),
                                   "--data-dir", str(self.data)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(server.stdout.close)
        self.addCleanup(server.wait)
        self.addCleanup(server.kill)
        self.assertIn("MycoMesh V11 Consumer", server.stdout.readline())
        base = f"http://127.0.0.1:{port}/v1"
        request = urllib.request.Request(f"{base}/responses", method="POST", headers={"Content-Type": "application/json"},
                                         data=json.dumps({"model": "gpt-5.5", "input": "stream me", "stream": True}).encode())
        with urllib.request.urlopen(request, timeout=60) as response:
            events = response.read().decode()
        self.assertIn("event: response.output_text.delta", events)
        self.assertIn("hello from v11: stream me", events)
        self.assertTrue(events.rstrip().split("\n")[-2].startswith("event: response.completed") or "response.completed" in events)
        chat = urllib.request.Request(f"{base}/chat/completions", method="POST", headers={"Content-Type": "application/json"},
                                      data=json.dumps({"model": "gpt-5.5", "messages": [{"role": "user", "content": "hi"}]}).encode())
        with urllib.request.urlopen(chat, timeout=60) as response:
            self.assertEqual(json.loads(response.read())["choices"][0]["message"]["content"], "chat ok")
        with urllib.request.urlopen(f"{base}/models", timeout=30) as response:
            self.assertEqual([item["id"] for item in json.loads(response.read())["data"]], ["gpt-5.5"])
        # Three requests at the 100-unit minimum fee settle on-chain via the Relay worker.
        self.assertTrue(_wait(lambda: self.chain.reader.available_balance(owner) == 100_000_000 - 300, 30),
                        "Relay did not settle the Node Consumer's receipts")


if __name__ == "__main__":
    unittest.main()
