"""What operators see: a Provider's live status, the Relay's unsettled receipts, RPC failover on pruned history."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from mycomesh import rpc
from mycomesh.provider.link import write_status
from tests.test_mycomesh_delivery import DEPLOYMENT, RELAY_SIGNER, signed


class ProviderStatusTest(unittest.TestCase):
    def test_jobs_are_counted_per_day_and_written_with_the_links(self) -> None:
        from mycomesh.provider.worker import ProviderWorker

        worker = ProviderWorker.__new__(ProviderWorker)  # only the counters are exercised
        worker._lock, worker._stats = threading.Lock(), {}
        worker.signer, worker.models, worker.tier, worker.capacity = "0xabc", ("gpt-5.5",), 1, 30
        day = time.time()
        worker.record("served", now=day)
        worker.record("served", now=day)
        worker.record("refused", now=day)
        worker.record("failed", "BackendError: Codex error: 401 Unauthorized", now=day)
        stats = worker.stats()
        self.assertEqual((stats["served_today"], stats["refused_today"], stats["failed_today"], stats["served_total"]), (2, 1, 1, 2))
        self.assertIn("401", stats["last_error"])
        worker.record("served", now=day + 86_400)  # a new day starts the day's counts again
        self.assertEqual(worker._stats["served_today"], 1)
        self.assertEqual(worker._stats["served_total"], 3)

        link = SimpleNamespace(endpoint=SimpleNamespace(host="relay", port=10991), connected=threading.Event(),
                               connected_since=None, last_error="connection refused")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        worker._stats["day"] = int(time.time() // 86_400)
        status = write_status(Path(tmp.name) / "status.json", worker, [link], backend="codex")
        self.assertEqual(json.loads((Path(tmp.name) / "status.json").read_text()), status)
        self.assertEqual(status["relays"], [{"relay": "relay:10991", "connected": False, "since": None, "last_error": "connection refused"}])


class RelayReceiptsTest(unittest.TestCase):
    def test_lists_unsettled_receipts_and_requeues_those_still_settleable(self) -> None:
        from mycomesh.__main__ import relay_receipts
        from mycomesh.relay.core import SettlementQueue

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        queue = SettlementQueue(Path(tmp.name) / "relay-settlement.sqlite3")
        expired = signed()  # its authorization's deadline (8,000) is long past
        queue.add(expired, owner="0x" + "55" * 20, provider="0x" + "66" * 20)
        for _ in range(6):
            queue.fail(expired.authorization.settlement_key, "insufficient funds for gas")
        args = SimpleNamespace(data_dir=tmp.name, retry=True)
        out = []
        import builtins
        original = builtins.print
        builtins.print = lambda text: out.append(text)
        try:
            relay_receipts(args, None)
        finally:
            builtins.print = original
        report = json.loads(out[0])
        self.assertEqual(report["counts"], {"rejected": 1})
        self.assertEqual(report["retried"], [])  # expired: retrying cannot help
        self.assertEqual(report["rejected_expired_fees"], 900)
        self.assertIn("insufficient funds", report["receipts"][0]["error"])


class PrunedHistoryFailoverTest(unittest.TestCase):
    def test_an_endpoint_without_old_logs_hands_over_to_the_next(self) -> None:
        def server(reply: dict) -> ThreadingHTTPServer:
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args) -> None:
                    pass

                def do_POST(self) -> None:  # noqa: N802
                    self.rfile.read(int(self.headers["Content-Length"]))
                    data = json.dumps({"jsonrpc": "2.0", "id": 1, **reply}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            self.addCleanup(httpd.shutdown)
            return httpd

        pruned = server({"error": {"code": 4444, "message": "pruned history unavailable"}})
        archive = server({"result": ["a log"]})
        urls = [f"http://127.0.0.1:{s.server_address[1]}" for s in (pruned, archive)]
        self.assertEqual(rpc.call(urls, "eth_getLogs", [{}]), ["a log"])


if __name__ == "__main__":
    unittest.main()
