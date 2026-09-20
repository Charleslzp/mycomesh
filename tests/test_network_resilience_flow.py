"""Real loopback HTTP/TCP faults; no external requests, model calls, or funds."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import time
import unittest

from gateway.client import discover_peers_from_pools, join_provider_pools
from gateway.chain import parse_private_key, private_key_to_address
from gateway.identity import create_identity
from gateway.p2p import ProviderConfig
from gateway.pool import PoolError
from gateway.relay import RelayProviderTCPServer, RelayState, relay_infer, run_relay_provider


@contextmanager
def bridge_fault_server():
    release = threading.Event()
    calls: list[tuple[str, str, float]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.handle_request()

        def do_GET(self):
            self.handle_request()

        def handle_request(self):
            calls.append((self.command, self.path, time.monotonic()))
            if self.command == "POST":
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path.startswith("/blackhole"):
                release.wait(5)
                return
            if self.path.startswith("/disconnect"):
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            if self.path.startswith("/malformed"):
                body = b"not JSON"
            elif self.path.endswith("/peers"):
                body = json.dumps({"peers": [{"peer_id": "healthy-provider",
                    "address": "tcp://127.0.0.1:9700", "last_seen": 1}]}).encode()
            else:
                body = json.dumps({"ok": True, "protocol": "mycomesh-pool/0.2",
                    "peer": {"peer_id": "provider", "status": "online",
                             "expires_at": int(time.time()) + 30}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


class BridgeFaultIsolationTest(unittest.TestCase):
    def test_three_blackholes_share_one_registration_budget(self):
        with bridge_fault_server() as (origin, calls):
            urls = [origin + f"/blackhole-{i}" for i in range(3)] + [origin + "/healthy"]
            errors = []
            started = time.monotonic()
            result = join_provider_pools(urls, peer_factory=lambda _: {"peer_id": "provider"},
                timeout=0.4, on_error=lambda url, exc: errors.append((url, exc)))
            elapsed = time.monotonic() - started
        self.assertEqual([item["pool_url"] for item in result], [urls[-1]])
        self.assertEqual([item[0] for item in errors], urls[:-1])
        self.assertEqual(len(calls), 4)
        # Serial registration took >=1.2s and sometimes raised bare TimeoutError.
        # This bound leaves >2x headroom; it is not a production latency claim.
        self.assertLess(elapsed, 1.0)
        healthy_at = next(at for _, path, at in calls if path == "/healthy/join")
        self.assertLess(healthy_at - started, 0.4)

    def test_malformed_json_and_closed_socket_cannot_cancel_other_joins(self):
        with bridge_fault_server() as (origin, _):
            urls = [origin + "/malformed", origin + "/disconnect", origin + "/healthy"]
            errors = []
            results = join_provider_pools(urls, peer_factory=lambda _: {"peer_id": "provider"},
                timeout=1, on_error=lambda url, exc: errors.append((url, exc)))
        self.assertEqual([item["pool_url"] for item in results], [urls[-1]])
        self.assertEqual([item[0] for item in errors], urls[:2])

    def test_descriptors_stay_serial_and_duplicate_bridge_is_contacted_once(self):
        factory_calls = []
        calling_thread = threading.get_ident()

        def factory(url):
            factory_calls.append((url, threading.get_ident()))
            return {"peer_id": "provider", "audience": url}

        with bridge_fault_server() as (origin, calls):
            urls = [origin + "/second", origin + "/first", origin + "/second"]
            results = join_provider_pools(urls, peer_factory=factory, timeout=1)
        self.assertEqual(factory_calls, [(urls[0], calling_thread), (urls[1], calling_thread)])
        self.assertEqual([item["pool_url"] for item in results], urls[:2])
        self.assertEqual(len(calls), 2)

    def test_queued_registration_cannot_outlive_shared_deadline(self):
        with bridge_fault_server() as (origin, calls):
            urls = [origin + f"/blackhole-{i}" for i in range(9)]
            errors = []
            started = time.monotonic()
            results = join_provider_pools(urls, peer_factory=lambda _: {"peer_id": "provider"},
                timeout=0.4, on_error=lambda url, exc: errors.append((url, exc)))
            elapsed = time.monotonic() - started
        self.assertEqual(results, [])
        self.assertEqual(len(errors), 9)
        self.assertLessEqual(len(calls), 8)
        self.assertLess(elapsed, 1.0)
        self.assertIn("deadline exceeded", str(errors[-1][1]))

    def test_bad_budget_fails_before_descriptor_or_remote_work(self):
        for value in (0, -1, float("nan"), float("inf"), 61):
            with self.subTest(value=value), self.assertRaises(PoolError):
                join_provider_pools(["http://127.0.0.1:1"], peer_factory=lambda _: self.fail("factory ran"),
                                    timeout=value)

    def test_discovery_retains_healthy_peers_with_blackhole_and_invalid_bridge(self):
        with bridge_fault_server() as (origin, _):
            peers = discover_peers_from_pools([origin + "/blackhole", origin + "/malformed",
                                               origin + "/healthy"], timeout=0.4)
        self.assertEqual([peer["peer_id"] for peer in peers], ["healthy-provider"])


class RealTCPRelayFailoverTest(unittest.TestCase):
    def test_closed_primary_migrates_same_provider_and_serves_new_ping(self):
        identity = create_identity()
        primary_key, backup_key = "0x" + "11" * 32, "0x" + "22" * 32
        primary_signer = private_key_to_address(parse_private_key(primary_key))
        backup_signer = private_key_to_address(parse_private_key(backup_key))
        primary = RelayState(payment_address="0x" + "33" * 20, attestation_address=primary_signer,
                             attestation_private_keys={primary_signer: primary_key},
                             reconnect_grace_seconds=0)
        backup = RelayState(payment_address="0x" + "55" * 20, attestation_address=backup_signer,
                            attestation_private_keys={backup_signer: backup_key},
                            reconnect_grace_seconds=0)
        servers = [RelayProviderTCPServer(("127.0.0.1", 0), state, "127.0.0.1", 9900)
                   for state in (primary, backup)]
        threads = [threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
                   for server in servers]
        for worker in threads:
            worker.start()
        config = ProviderConfig(peer_id=identity.peer_id, channel="c", agent_id="test", agent_key="test",
            gateway_url="http://127.0.0.1:1/v1", model="m", advertise_host="relay", advertise_port=0,
            identity=identity, network_profile="local", relay_payment_address=primary.payment_address,
            relay_attestation_address=primary.attestation_address)
        stop = threading.Event()
        registered = [threading.Event(), threading.Event()]
        callbacks, cleanups, errors = [], [], []

        def on_registered(ack):
            callbacks.append(ack)
            index = 0 if ack["relay_provider_port"] == servers[0].server_address[1] else 1
            registered[index].set()

        def run():
            try:
                run_relay_provider("127.0.0.1", servers[0].server_address[1], config,
                    relay_public_url="http://127.0.0.1:9900", on_registered=on_registered, stop_event=stop,
                    on_disconnected=lambda: cleanups.append(config.relay_payment_address),
                    relay_fallbacks=[{"host": "127.0.0.1", "provider_port": servers[1].server_address[1],
                        "public_url": "http://127.0.0.1:9902", "provider_tls": False,
                        "payment_address": backup.payment_address, "attestation_address": backup.attestation_address}])
            except Exception as exc:
                errors.append(exc)

        provider = threading.Thread(target=run, daemon=True)
        provider.start()
        try:
            self.assertTrue(registered[0].wait(3), str(errors))
            first = relay_infer(primary, identity.peer_id, {"type": "ping", "request_id": "before"}, timeout=2)
            self.assertEqual(first["request_id"], "before")
            primary.providers[identity.peer_id].connection.shutdown(socket.SHUT_RDWR)
            self.assertTrue(registered[1].wait(5), str(errors))
            self.assertEqual(cleanups, [primary.payment_address])
            second = relay_infer(backup, identity.peer_id, {"type": "ping", "request_id": "after"}, timeout=2)
            self.assertEqual(second["request_id"], "after")
            self.assertEqual(second["peer"]["peer_id"], first["peer"]["peer_id"])
            self.assertIs(config.identity, identity)
            self.assertEqual(callbacks[-1]["relay_public_url"], "http://127.0.0.1:9902")
            self.assertEqual(backup.providers[identity.peer_id].peer["public_key"], identity.public_key)
            self.assertFalse(errors)
        finally:
            stop.set()
            for state in (primary, backup):
                for session in list(state.providers.values()):
                    try:
                        session.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            provider.join(timeout=4)
            for server in servers:
                server.shutdown()
                server.server_close()
            for worker in threads:
                worker.join(timeout=2)
        self.assertFalse(provider.is_alive())


if __name__ == "__main__":
    unittest.main()
