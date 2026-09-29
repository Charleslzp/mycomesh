"""V11 over real sockets: two Relays, a multi-homed Provider, HTTP Consumers, settlement worker."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mycomesh.consumer import open_response, prepare_request
from mycomesh.evm import address_of, encode_call
from mycomesh.identity import create_identity
from mycomesh.protocol import Prices
from mycomesh.provider.backends import AnthropicBackend, OpenAICompatibleBackend
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.server import RelayServer
from tests.mycomesh_anvil import CONSUMER_KEY, DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

RELAY_B_SIGNER = "0x" + "55" * 32


class FakeModelAPI(BaseHTTPRequestHandler):
    """Answers OpenAI /responses and Anthropic /messages shapes."""

    seen: list[tuple[str, dict]] = []

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeModelAPI.seen.append((self.path, body))
        if self.path.endswith("/messages"):
            reply = {"content": [{"type": "text", "text": "claude ok"}], "usage": {"input_tokens": 11, "output_tokens": 7}}
        else:
            reply = {"output_text": "echo " + str(body.get("input")), "usage": {"input_tokens": 100, "output_tokens": 50}}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read())


def _post(url: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _wait(predicate, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class NetworkAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = AnvilV11()
        cls.chain.send(cls.chain.relay, cls.chain.settlement,
                       encode_call("authorizeRelaySigner(address)", ["address"], [address_of(RELAY_B_SIGNER)]))
        cls.model = ThreadingHTTPServer(("127.0.0.1", 0), FakeModelAPI)
        threading.Thread(target=cls.model.serve_forever, daemon=True).start()
        cls.model_url = f"http://127.0.0.1:{cls.model.server_address[1]}/v1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.model.shutdown()
        cls.chain.close()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stop = threading.Event()
        self.addCleanup(self.stop.set)
        self.relays = {name: self._relay(name, signer) for name, signer in (("a", RELAY_SIGNER), ("b", RELAY_B_SIGNER))}
        self.worker = ProviderWorker(
            identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=self.chain.deployment,
            backend=OpenAICompatibleBackend(self.model_url), prices=Prices(1_000, 4_000, 100),
            models=("gpt-5.5",), data_dir=Path(self.tmp.name) / "provider",
        )
        self.links = run_provider(self.worker, [RelayEndpoint("127.0.0.1", server.link_address[1])
                                                for server in self.relays.values()], self.stop)
        self.assertTrue(_wait(lambda: all(link.connected.is_set() for link in self.links)), "Provider not multi-homed")

    def _relay(self, name: str, signer: str, link_port: int = 0) -> RelayServer:
        core = RelayCore(self.chain.deployment, signer, self.chain.reader, Path(self.tmp.name) / f"relay-{name}")
        server = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", link_port), self.chain.relay, self.chain.rpc,
                             DISPUTE_WINDOW, settle_interval=0.0, settle_count=1)
        server.start()
        self.addCleanup(server.stop)
        return server

    def _request(self, server: RelayServer, signer: str, prompt: str):
        base = f"http://127.0.0.1:{server.http_address[1]}"
        descriptor = _get(f"{base}/providers")["providers"][0]
        now = self.chain.now()
        prepared = prepare_request(
            descriptor=descriptor, deployment=self.chain.deployment, key_private=CONSUMER_KEY,
            relay_signer=address_of(signer), endpoint="responses", model="gpt-5.5", content=prompt,
            max_output_tokens=500, max_fee=5_000_000, now=now,
        )
        status, body = _post(f"{base}/v11/requests", prepared.payload)
        self.assertEqual(status, 200, body)
        response, signed = open_response(prepared, body, self.chain.deployment, now=now)
        return response, signed

    def test_consumer_request_over_http_to_either_relay_and_worker_settles(self) -> None:
        owner = address_of(self.chain.consumer)
        before = self.chain.reader.available_balance(owner)
        response, signed = self._request(self.relays["a"], RELAY_SIGNER, "via relay a")
        self.assertEqual(response["output"]["output_text"], "echo via relay a")
        self._request(self.relays["b"], RELAY_B_SIGNER, "via relay b")
        # 100 in * 1000/1k + 50 out * 4000/1k = 300 per request; both workers settle on their own.
        self.assertTrue(_wait(lambda: self.chain.reader.available_balance(owner) == before - 600, 30),
                        "settlement worker did not settle")
        # The chain can show the settlement before the worker records the receipt.
        health_url = f"http://127.0.0.1:{self.relays['a'].http_address[1]}/health"
        self.assertTrue(_wait(lambda: _get(health_url)["queue"].get("settled") == 1), "queue not marked settled")
        self.assertEqual(_get(health_url)["providers"], 1)

    def test_provider_reconnects_after_a_relay_restart(self) -> None:
        old = self.relays["a"]
        port = old.link_address[1]
        old.stop()
        self.assertTrue(_wait(lambda: not self.links[0].connected.is_set()), "link did not notice the restart")
        restarted = self._relay("a2", RELAY_SIGNER, link_port=port)
        self.assertTrue(_wait(lambda: self.links[0].connected.is_set(), 20), "Provider did not reconnect")
        response, _ = self._request(restarted, RELAY_SIGNER, "after restart")
        self.assertEqual(response["output"]["output_text"], "echo after restart")

    def test_anthropic_backend_shapes_a_messages_request(self) -> None:
        backend = AnthropicBackend(api_key="test-key", base_url=self.model_url)
        output, input_tokens, output_tokens = backend({
            "endpoint": "responses", "model": "claude-sonnet-4-6", "input": "hi", "max_output_tokens": 64,
            "options": {"temperature": 0.2, "unsupported": True},
        })
        path, body = FakeModelAPI.seen[-1]
        self.assertTrue(path.endswith("/messages"))
        self.assertEqual(body, {"model": "claude-sonnet-4-6", "max_tokens": 64, "temperature": 0.2,
                                "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual((input_tokens, output_tokens), (11, 7))
        self.assertEqual(output["output_text"], "claude ok")


if __name__ == "__main__":
    unittest.main()
