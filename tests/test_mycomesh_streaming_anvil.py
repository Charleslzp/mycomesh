"""Sealed streaming: backend deltas reach the Consumer through a Relay that cannot read them."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mycomesh.consumer import prepare_request, read_stream
from mycomesh.evm import address_of
from mycomesh.identity import create_identity
from mycomesh.protocol import Prices
from mycomesh.provider.backends import AnthropicBackend, OpenAICompatibleBackend
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.server import RelayServer
from tests.mycomesh_anvil import CONSUMER_KEY, DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

WORDS = ["Sealed ", "streams ", "stay ", "private."]


class StreamingModelAPI(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body.get("stream") is True
        if self.path.endswith("/messages"):
            events = [{"type": "message_start", "message": {"id": "msg_1", "role": "assistant", "usage": {"input_tokens": 9}}}]
            events += [{"type": "content_block_delta", "delta": {"type": "text_delta", "text": w}} for w in WORDS]
            events += [{"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 4}}]
        elif self.path.endswith("/chat/completions"):
            events = [{"id": "c1", "model": body["model"], "choices": [{"delta": {"content": w}}]} for w in WORDS]
            events += [{"id": "c1", "choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": 4}}]
        else:
            events = [{"type": "response.output_text.delta", "delta": w} for w in WORDS]
            events += [{"type": "response.completed", "response": {"id": "r1", "status": "completed", "output_text": "".join(WORDS),
                                                                    "usage": {"input_tokens": 9, "output_tokens": 4}}}]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in events:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.06)
        self.wfile.write(b"data: [DONE]\n\n")


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class StreamingAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.model = ThreadingHTTPServer(("127.0.0.1", 0), StreamingModelAPI)
        threading.Thread(target=cls.model.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{cls.model.server_address[1]}/v1"
        core = RelayCore(cls.chain.deployment, RELAY_SIGNER, cls.chain.reader, tmp / "relay")
        cls.relay = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", 0), cls.chain.relay, cls.chain.rpc, DISPUTE_WINDOW)
        cls.relay.start()
        cls.stop = threading.Event()
        cls.backends = {"openai": OpenAICompatibleBackend(base), "anthropic": AnthropicBackend("k", base_url=base)}
        cls.worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER,
                                    deployment=cls.chain.deployment, backend=cls.backends["openai"],
                                    prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",), data_dir=tmp / "provider")
        run_provider(cls.worker, [RelayEndpoint("127.0.0.1", cls.relay.link_address[1])], cls.stop)
        deadline = time.monotonic() + 20
        while not core.providers and time.monotonic() < deadline:
            time.sleep(0.05)
        cls.url = f"http://127.0.0.1:{cls.relay.http_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop.set()
        cls.relay.stop()
        cls.model.shutdown()
        cls.chain.close()
        cls.tmp.cleanup()

    def _stream(self, endpoint: str, content) -> tuple[list[tuple[float, str]], dict]:
        with urllib.request.urlopen(self.url + "/providers", timeout=10) as reply:
            descriptor = json.loads(reply.read())["providers"][0]
        prepared = prepare_request(descriptor=descriptor, deployment=self.chain.deployment, key_private=CONSUMER_KEY,
                                   relay_signer=address_of(RELAY_SIGNER), endpoint=endpoint, model="gpt-5.5",
                                   content=content, max_output_tokens=50, max_fee=1_000_000)
        request = urllib.request.Request(self.url + "/v11/requests", data=json.dumps(prepared.payload).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "Accept": "application/x-ndjson"})
        seen: list[tuple[float, str]] = []
        with urllib.request.urlopen(request, timeout=60) as reply:
            self.assertEqual(reply.headers["Content-Type"], "application/x-ndjson")
            response, _ = read_stream(reply, prepared, self.chain.deployment,
                                      on_delta=lambda text: seen.append((time.monotonic(), text)))
        return seen, response

    def _check(self, seen, response) -> None:
        self.assertEqual("".join(text for _, text in seen), "".join(WORDS))
        self.assertGreater(len(seen), 1, "deltas were not streamed separately")
        self.assertGreater(seen[-1][0] - seen[0][0], 0.05, "deltas arrived all at once")
        self.assertEqual(response["usage"], {"input_tokens": 9, "output_tokens": 4})

    def test_openai_responses_and_chat_stream(self) -> None:
        self.worker.backend = self.backends["openai"]
        seen, response = self._stream("responses", "hi")
        self._check(seen, response)
        seen, response = self._stream("chat", [{"role": "user", "content": "hi"}])
        self._check(seen, response)
        self.assertEqual(response["output"]["choices"][0]["message"]["content"], "".join(WORDS))

    def test_anthropic_streams(self) -> None:
        self.worker.backend = self.backends["anthropic"]
        seen, response = self._stream("chat", [{"role": "user", "content": "hi"}])
        self._check(seen, response)

    def test_plain_json_requests_still_work(self) -> None:
        self.worker.backend = self.backends["openai"]
        # A non-streaming request uses the backend's streaming path only when asked.
        with urllib.request.urlopen(self.url + "/providers", timeout=10) as reply:
            descriptor = json.loads(reply.read())["providers"][0]
        prepared = prepare_request(descriptor=descriptor, deployment=self.chain.deployment, key_private=CONSUMER_KEY,
                                   relay_signer=address_of(RELAY_SIGNER), endpoint="responses", model="gpt-5.5",
                                   content="hi", max_output_tokens=50, max_fee=1_000_000)
        request = urllib.request.Request(self.url + "/v11/requests", data=json.dumps(prepared.payload).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError):  # the fake API only speaks streaming
            urllib.request.urlopen(request, timeout=60)


if __name__ == "__main__":
    unittest.main()
