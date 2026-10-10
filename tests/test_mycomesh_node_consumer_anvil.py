"""The Node V11 Consumer against the Python Relay and Provider on anvil."""
from __future__ import annotations

import json
import re
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mycomesh import rpc
from mycomesh.directory import encode_announce
from mycomesh.evm import address_of
from mycomesh.relay.faucet import Faucet
from mycomesh.identity import create_identity
from mycomesh.protocol import Prices
from mycomesh.provider.backends import OpenAICompatibleBackend
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.server import RelayServer
from tests.mycomesh_anvil import DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

ROOT = Path(__file__).resolve().parents[1]
FAUCET_KEY = "0x" + "78" * 32
CLI = ROOT / "packages/mycomesh-cli/bin/mycomesh-consumer.mjs"


class FakeOpenAI(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if body.get("stream"):
            self._stream(body)
            return
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

    def _stream(self, body: dict) -> None:
        words = ["streamed ", "word ", "by ", "word"]
        if self.path.endswith("/chat/completions"):
            events = [{"id": "c", "model": body["model"], "choices": [{"delta": {"content": w}}]} for w in words]
            events.append({"id": "c", "choices": [], "usage": {"prompt_tokens": 3, "completion_tokens": 4}})
        else:
            events = [{"type": "response.output_text.delta", "delta": w} for w in words]
            events.append({"type": "response.completed", "response": {
                "id": "resp_s", "object": "response", "status": "completed", "model": body["model"], "output_text": "".join(words),
                "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "".join(words)}]}],
                "usage": {"input_tokens": 3, "output_tokens": 4}}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in events:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.15)


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
        rpc.wait_for_receipt(cls.chain.rpc, rpc.send_transaction(cls.chain.rpc, cls.chain.admin, to=address_of(FAUCET_KEY), value=10**18))
        faucet = Faucet(FAUCET_KEY, cls.chain.rpc, cls.chain.token, tmp / "relay", eth_wei=2 * 10**17, usdc_units=20_000_000)
        cls.relay = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", 0), cls.chain.relay, cls.chain.rpc,
                                DISPUTE_WINDOW, settle_interval=0.0, settle_count=1, faucet=faucet)
        cls.relay.start()
        worker = ProviderWorker(
            identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=cls.chain.deployment,
            backend=OpenAICompatibleBackend(f"http://127.0.0.1:{cls.model.server_address[1]}/v1"),
            prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",), data_dir=tmp / "provider",
        )
        links = run_provider(worker, [RelayEndpoint("127.0.0.1", cls.relay.link_address[1])], cls.stop)
        assert _wait(lambda: links[0].connected.is_set()), "Provider did not connect"
        # The Relay is found only through the on-chain directory; the manifest lists none.
        relay_url = f"http://127.0.0.1:{cls.relay.http_address[1]}"
        cls.chain.send(cls.chain.relay, cls.chain.directory, encode_announce(address_of(RELAY_SIGNER), relay_url, ""))
        cls.network = tmp / "network.json"
        cls.network.write_text(json.dumps(cls.chain.manifest([], faucet_url=relay_url)))
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

    def _cli(self, *args: str, data: Path | None = None, env: dict | None = None) -> str:
        result = subprocess.run(["node", str(CLI), *args, "--network", str(self.network), "--data-dir", str(data or self.data)],
                                capture_output=True, text=True, timeout=180, env={**os.environ, **(env or {})})
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
        self.assertIn("streamed word by word", events)  # the backend streams; the Consumer relays it live
        self.assertTrue(events.rstrip().split("\n")[-2].startswith("event: response.completed") or "response.completed" in events)
        chat = urllib.request.Request(f"{base}/chat/completions", method="POST", headers={"Content-Type": "application/json"},
                                      data=json.dumps({"model": "gpt-5.5", "messages": [{"role": "user", "content": "hi"}]}).encode())
        with urllib.request.urlopen(chat, timeout=60) as response:
            self.assertEqual(json.loads(response.read())["choices"][0]["message"]["content"], "chat ok")
        with urllib.request.urlopen(f"{base}/models", timeout=30) as response:
            self.assertEqual([item["id"] for item in json.loads(response.read())["data"]], ["gpt-5.5"])

        # Anthropic Messages (what Claude Code speaks), plain and streamed; clients send some key, any is fine locally.
        root = f"http://127.0.0.1:{port}"
        def post(path: str, body: dict) -> tuple[str, str]:
            request = urllib.request.Request(root + path, method="POST", data=json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json", "x-api-key": "anything"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.headers.get("content-type"), response.read().decode()
        _, raw = post("/v1/messages", {"model": "gpt-5.5", "max_tokens": 50, "system": "be brief",
                                        "messages": [{"role": "user", "content": "hi"}]})
        message = json.loads(raw)
        self.assertEqual((message["type"], message["content"][0]["text"]), ("message", "chat ok"))
        self.assertEqual(message["usage"], {"input_tokens": 3, "output_tokens": 2})  # from the signed receipt
        kind, events = post("/v1/messages", {"model": "gpt-5.5", "max_tokens": 50, "stream": True,
                                             "messages": [{"role": "user", "content": "stream please"}]})
        self.assertIn("text/event-stream", kind)
        names = re.findall(r"^event: (\S+)$", events, re.M)
        self.assertEqual((names[0], names[-1]), ("message_start", "message_stop"))
        self.assertEqual("".join(json.loads(line[6:])["delta"]["text"] for line in events.splitlines()
                                 if line.startswith("data: ") and '"text_delta"' in line), "streamed word by word")
        # Gemini generateContent, plain and streamed (alt=sse).
        _, raw = post("/v1beta/models/gpt-5.5:generateContent", {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]})
        self.assertEqual(json.loads(raw)["candidates"][0]["content"]["parts"][0]["text"], "chat ok")
        _, events = post("/v1beta/models/gpt-5.5:streamGenerateContent?alt=sse",
                         {"contents": [{"role": "user", "parts": [{"text": "stream please"}]}]})
        chunks = [json.loads(line[6:]) for line in events.splitlines() if line.startswith("data: ")]
        self.assertEqual("".join(c["candidates"][0]["content"]["parts"][0]["text"] for c in chunks), "streamed word by word")
        self.assertEqual(chunks[-1]["candidates"][0]["finishReason"], "STOP")
        with self.assertRaises(urllib.error.HTTPError) as refused:
            post("/v1/messages", {"model": "gpt-5.5", "max_tokens": 5, "tools": [{"name": "x"}],
                                  "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(refused.exception.code, 400)
        self.assertEqual(json.loads(refused.exception.read())["error"]["type"], "invalid_request_error")
        # Seven requests at the 100-unit minimum fee settle on-chain via the Relay worker.
        self.assertTrue(_wait(lambda: self.chain.reader.available_balance(owner) == 100_000_000 - 700, 30),
                        "Relay did not settle the Node Consumer's receipts")


    def test_wallet_faucet_setup_and_streaming(self) -> None:
        data = Path(self.tmp.name) / "newcomer"
        env = {"MYCOMESH_WALLET_PASSWORD": "correct horse battery"}
        lines = self._cli("init", data=data, env=env).splitlines()
        wallet = lines[1].split()[2]
        keystore = json.loads((data / "owner-wallet.json").read_text())
        self.assertEqual("0x" + keystore["address"], wallet)
        self.assertNotIn(wallet[2:], (data / "owner-wallet.json").read_text().replace(keystore["address"], ""))
        # A brand-new wallet has no ETH and no tUSDC: setup funds it from the faucet, then deposits.
        self.assertIn("faucet", self._cli("setup", "--deposit", "10000000", "--max-per-request", "2000000", data=data, env=env))
        self.assertEqual(self.chain.reader.available_balance(wallet), 10_000_000)
        # anvil's base fee has climbed to ~150 gwei by now; Sepolia's is ~1 gwei, where the faucet's grant suffices.
        rpc.wait_for_receipt(self.chain.rpc, rpc.send_transaction(self.chain.rpc, self.chain.admin, to=wallet, value=10**18))
        self.assertEqual(self._cli("balance", data=data), "10000000")
        wrong = subprocess.run(["node", str(CLI), "dispute", "last", "--network", str(self.network), "--data-dir", str(data)],
                               capture_output=True, text=True, env={**os.environ, "MYCOMESH_WALLET_PASSWORD": "wrong password"})
        self.assertNotEqual(wrong.returncode, 0)

        result = subprocess.run(["node", str(CLI), "request", "--stream", "--max-fee", "1000000", "stream", "please",
                                 "--network", str(self.network), "--data-dir", str(data)], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.strip(), "streamed word by word")
        self.assertEqual(json.loads(result.stdout)["output_text"], "streamed word by word")

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = subprocess.Popen(["node", str(CLI), "serve", "--port", str(port), "--network", str(self.network),
                                   "--data-dir", str(data)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(server.stdout.close)
        self.addCleanup(server.wait)
        self.addCleanup(server.kill)
        server.stdout.readline()
        for path, body in (("responses", {"input": "hi"}), ("chat/completions", {"messages": [{"role": "user", "content": "hi"}]})):
            request = urllib.request.Request(f"http://127.0.0.1:{port}/v1/{path}", method="POST",
                                             headers={"Content-Type": "application/json"},
                                             data=json.dumps({"model": "gpt-5.5", "stream": True, **body}).encode())
            arrivals = []
            with urllib.request.urlopen(request, timeout=60) as response:
                for raw in response:
                    line = raw.decode()
                    if "output_text.delta" in line or '"content"' in line:
                        arrivals.append(time.monotonic())
            self.assertGreaterEqual(len(arrivals), 3, path)
            self.assertGreater(arrivals[-1] - arrivals[0], 0.2, f"{path} deltas were buffered, not streamed")

        # The local web console and its JSON API, reachable only from this machine's own pages.
        base = f"http://127.0.0.1:{port}"

        def call(path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict | str]:
            data = None if body is None else json.dumps(body).encode()
            request = urllib.request.Request(base + path, data=data, method="GET" if body is None else "POST",
                                             headers={"Content-Type": "application/json", **(headers or {})})
            try:
                with urllib.request.urlopen(request, timeout=120) as reply:
                    raw = reply.read().decode()
                    return reply.status, json.loads(raw) if reply.headers["Content-Type"].startswith("application/json") else raw
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read() or b"{}")

        status, page = call("/")
        self.assertEqual(status, 200)
        self.assertIn("MycoMesh 本地节点", page)
        status, info = call("/api/status")
        self.assertEqual(info["wallet"]["owner"], wallet)
        self.assertTrue(info["wallet"]["grant"]["active"])
        history = call("/api/history")[1]["entries"]
        self.assertGreaterEqual(len(history), 3)
        self.assertEqual(history[-1]["prompt"], "stream please")
        self.assertEqual(history[-1]["answer"], "streamed word by word")
        self.assertTrue(all(entry["status"] in {"none", "pending"} for entry in history))
        relays = call("/api/network")[1]["relays"]
        self.assertEqual(relays[0]["providers"][0]["models"], ["gpt-5.5"])
        self.assertEqual(call("/api/withdraw", {"password": "wrong password"})[0], 401)
        status, withdrawal = call("/api/withdraw", {"password": env["MYCOMESH_WALLET_PASSWORD"], "amount": "1000000"})
        self.assertEqual((status, withdrawal), (200, {"requested": "1000000"}))
        self.assertEqual(call("/api/status")[1]["wallet"]["withdrawal"]["amount"], "1000000")
        # A web page elsewhere, or a rebinding DNS name, cannot drive the node or spend the deposit.
        self.assertEqual(call("/api/status", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(call("/v1/models", headers={"Host": "evil.example"})[0], 403)
        chat = {"model": "gpt-5.5", "messages": [{"role": "user", "content": "hi"}]}
        self.assertEqual(call("/v1/chat/completions", chat, {"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(call("/api/faucet", {}, {"Content-Type": "text/plain"})[0], 415)

        # Multi-tenant: a tenant key with an on-chain budget, reachable from other hosts with its API key.
        created = call("/api/tenants", {"password": env["MYCOMESH_WALLET_PASSWORD"], "name": "acme",
                                        "budget": "300", "max_per_request": "100"})[1]
        self.assertTrue(created.get("api_key", "").startswith("mcm_"), created)
        tenant = {"Authorization": f"Bearer {created['api_key']}", "Host": "gateway.example", "Origin": "https://app.example"}
        for _ in range(3):
            status, reply = call("/v1/chat/completions", chat, tenant)
            self.assertEqual(status, 200, reply)
        status, reply = call("/v1/chat/completions", chat, tenant)
        self.assertEqual(status, 402, reply)  # 3 x 100 used the whole budget: refused before any Provider works
        self.assertIn("budget", reply["error"]["message"])
        self.assertEqual(call("/v1/chat/completions", chat, {"Authorization": "Bearer mcm_wrong", "Host": "gateway.example"})[0], 403)
        self.assertEqual(call("/api/tenants", headers={"Authorization": f"Bearer {created['api_key']}", "Host": "gateway.example"})[0], 403)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            listed = {t["name"]: t for t in call("/api/tenants")[1]["tenants"]}
            if listed["acme"]["spent"] == "300":
                break
            time.sleep(0.5)
        self.assertEqual((listed["acme"]["budget"], listed["acme"]["spent"]), ("300", "300"))
        self.assertEqual(call("/api/tenants/revoke", {"password": env["MYCOMESH_WALLET_PASSWORD"], "name": "acme"})[0], 200)
        self.assertEqual(call("/v1/chat/completions", chat, tenant)[0], 403)  # revoked keys stop at once

    def test_z_consumer_claims_myco_after_release(self) -> None:
        """Runs last: it moves the chain clock past the dispute window and the reward hour."""
        self.chain.advance(DISPUTE_WINDOW + 1)
        released: list[str] = []  # the worker marks receipts settled just after the chain sees them
        self.assertTrue(_wait(lambda: len(released.extend(self.relay.core.release_due(
            self.chain.relay, self.chain.rpc, DISPUTE_WINDOW, now=self.chain.now())) or released) >= 3, 30))
        self.chain.advance(3_601)
        rewards = self._cli("rewards", "claim", "--owner-key-file", str(self.owner_key))
        self.assertIn('claimed {"consumer":1}', rewards)
        summary = json.loads(rewards.split("\n", 1)[1].rsplit("\nMYCO", 1)[0])
        self.assertGreater(int(summary["myco_balance_wei"]), 0)
        self.assertEqual(summary["roles"]["consumer"]["claimable_wei"], "0")


if __name__ == "__main__":
    unittest.main()
