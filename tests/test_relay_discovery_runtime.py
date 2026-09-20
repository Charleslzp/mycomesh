from __future__ import annotations

import copy
import contextlib
import io
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.chain import parse_private_key, private_key_to_address
from gateway.client import _build_parser, _cmd_pool_serve
from gateway.identity import create_identity
from gateway.p2p import ProviderConfig
from gateway.pool import PoolConfig, PoolError, PoolHTTPServer, effective_trusted_relay_origins
from gateway.relay import RelayControlHTTPServer, RelayProviderTCPServer, RelayState, relay_infer, run_relay_provider
from gateway.relay_discovery import (
    DiscoveryError,
    RelayDiscoveryClient,
    build_admission,
    build_announcement,
    normalize_policy,
    request_json,
)
from gateway.relay_discovery_runtime import BridgeDiscoveryRuntime, RelayDiscoveryPublisher


AUTHORITY_KEY = "0x" + "11" * 32
RELAY_KEY = "0x" + "22" * 32
AUTHORITY = private_key_to_address(parse_private_key(AUTHORITY_KEY))
RELAY_SIGNER = private_key_to_address(parse_private_key(RELAY_KEY))


class RelayDiscoveryRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {
            "policy": normalize_policy({
                "authorities": [AUTHORITY], "threshold": 1,
                "refresh_seconds": 1, "timeout_seconds": 1,
            }),
            "context": {
                "network_id": "discovery-test", "channel_id": "codex-test",
                "chain_id": 31337, "settlement_contract": "0x" + "44" * 20,
                "protocol_version": 8, "network_profile": "local",
            },
            "bridge_urls": [],
        }
        self.binding = {
            **{key: value for key, value in self.config["context"].items() if key != "network_profile"},
            "host": "127.0.0.1", "provider_port": 19901,
            "public_url": "http://127.0.0.1:19900", "provider_tls": False,
            "payment_address": "0x" + "55" * 20, "attestation_address": RELAY_SIGNER,
        }

    def runtime(self, name: str, *, config: dict | None = None) -> BridgeDiscoveryRuntime:
        runtime = BridgeDiscoveryRuntime(config or self.config, str(Path(self.temp.name) / (name + ".sqlite3")))
        self.addCleanup(runtime.close)
        return runtime

    def bridge(self, name: str) -> tuple[BridgeDiscoveryRuntime, str]:
        runtime = self.runtime(name)
        config = PoolConfig(network_profile="local", reputation_path=None, relay_discovery=runtime)
        server = PoolHTTPServer(("127.0.0.1", 0), config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        return runtime, f"http://127.0.0.1:{server.server_port}"

    def admission(self, *, binding: dict | None = None) -> dict:
        return build_admission(binding or self.binding, expires_at=int(time.time()) + 3600, private_keys=[AUTHORITY_KEY])

    def publisher(self, name: str, *, bridges: list[str] | None = None) -> RelayDiscoveryPublisher:
        config = {**self.config, "bridge_urls": bridges or []}
        publisher = RelayDiscoveryPublisher(
            config, self.admission(), private_key=RELAY_KEY,
            sequence_path=str(Path(self.temp.name) / (name + ".sqlite3")),
            expected_bindings={"attestation_address": RELAY_SIGNER},
        )
        self.addCleanup(publisher.close)
        return publisher

    def test_three_bridges_sync_original_signed_announcement_over_real_http(self) -> None:
        first, first_url = self.bridge("bridge1")
        second, second_url = self.bridge("bridge2")
        third, third_url = self.bridge("bridge3")
        publisher = self.publisher("relay", bridges=[first_url])
        self.assertEqual(publisher.publish_once(), 1)
        original = publisher.current()
        self.assertEqual(first.live(), [original])
        second.bridge_urls = ["http://127.0.0.1:1", first_url]
        third.bridge_urls = [second_url]
        self.assertEqual(second.sync_once(), 1)
        self.assertEqual(third.sync_once(), 1)
        result = request_json(third_url + "/relays", timeout=1)
        self.assertEqual(result, {"schema": "mycomesh.relay-directory.v1", "relays": [original]})
        self.assertEqual(third.sync_once(), 0)
        self.assertEqual(third.live()[0]["expires_at"], original["expires_at"])

    def test_provider_discovers_unconfigured_relay_after_real_tcp_primary_failure(self) -> None:
        directory, bridge_url = self.bridge("provider-bridge")
        primary_key = "0x" + "33" * 32
        primary_signer = private_key_to_address(parse_private_key(primary_key))
        primary = RelayState(
            network_profile="local", settlement_version=8,
            payment_address="0x" + "66" * 20, attestation_address=primary_signer,
            attestation_private_keys={primary_signer: primary_key}, reconnect_grace_seconds=0,
            incident_store_path=None, probe_store_path=None,
        )
        discovered = RelayState(
            network_profile="local", settlement_version=8,
            payment_address=self.binding["payment_address"], attestation_address=RELAY_SIGNER,
            attestation_private_keys={RELAY_SIGNER: RELAY_KEY}, reconnect_grace_seconds=0,
            incident_store_path=None, probe_store_path=None,
        )

        def start_server(server):
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            self.addCleanup(server.server_close)
            self.addCleanup(worker.join, 2)
            self.addCleanup(server.shutdown)
            return server

        controls = [start_server(RelayControlHTTPServer(("127.0.0.1", 0), state))
                    for state in (primary, discovered)]
        servers = [start_server(RelayProviderTCPServer(("127.0.0.1", 0), state, "127.0.0.1", control.server_port))
                   for state, control in zip((primary, discovered), controls)]
        primary_url, discovered_url = [f"http://127.0.0.1:{server.server_port}" for server in controls]
        self.binding.update(provider_port=servers[1].server_address[1], public_url=discovered_url)
        publisher = self.publisher("discovered-relay", bridges=[bridge_url])
        discovered._discovery_publisher = publisher
        self.assertEqual(publisher.publish_once(), 1)
        announcement = publisher.current()
        self.assertEqual(directory.live(), [announcement])

        discovery = RelayDiscoveryClient(
            **{**self.config, "bridge_urls": [bridge_url]},
            cache_path=Path(self.temp.name) / "provider-directory.sqlite3",
        )
        self.addCleanup(discovery.close)
        identity = create_identity()
        config = ProviderConfig(
            peer_id=identity.peer_id, channel=self.config["context"]["channel_id"],
            agent_id="test", agent_key="test", gateway_url="http://127.0.0.1:1/v1", model="m",
            advertise_host="relay", advertise_port=0, identity=identity,
            network_profile="local", settlement_version=8,
            relay_payment_address=primary.payment_address, relay_attestation_address=primary_signer,
            settlement_rpc_url="http://127.0.0.1:1", settlement_chain_id=self.config["context"]["chain_id"],
            settlement_contract=self.config["context"]["settlement_contract"],
            payment_address="0x" + "88" * 20, replay_store_path=":memory:",
        )
        stop = threading.Event()
        registered = [threading.Event(), threading.Event()]
        callbacks, errors = [], []

        def on_registered(ack):
            callbacks.append(ack)
            index = 0 if ack["relay_provider_port"] == servers[0].server_address[1] else 1
            registered[index].set()

        def run():
            try:
                run_relay_provider(
                    "127.0.0.1", servers[0].server_address[1], config,
                    relay_public_url=primary_url, relay_fallbacks=(), relay_discovery=discovery,
                    on_registered=on_registered, stop_event=stop,
                )
            except Exception as exc:
                errors.append(exc)

        provider = threading.Thread(target=run, daemon=True)
        log = io.StringIO()
        # Only the settlement readiness snapshot is synthetic; discovery,
        # certificate verification, health HTTP, registration and ping use TCP.
        with patch("gateway.relay._relay_settlement_health", return_value={
            "enabled": True, "ready": True, "settlement_ready": True,
        }), contextlib.redirect_stderr(log):
            provider.start()
            try:
                self.assertTrue(registered[0].wait(5), f"{errors}: {log.getvalue()}")
                before = relay_infer(primary, identity.peer_id, {"type": "ping", "request_id": "before"}, timeout=2)
                self.assertEqual(before["request_id"], "before")
                self.assertFalse(discovered.providers)
                servers[0].shutdown()
                servers[0].server_close()
                primary.providers[identity.peer_id].connection.shutdown(socket.SHUT_RDWR)
                self.assertTrue(registered[1].wait(8), f"{errors}: {log.getvalue()}")
                after = relay_infer(discovered, identity.peer_id, {"type": "ping", "request_id": "after"}, timeout=2)
                self.assertEqual(after["request_id"], "after")
                self.assertEqual(after["peer"]["peer_id"], before["peer"]["peer_id"])
                self.assertEqual(discovered.providers[identity.peer_id].peer["public_key"], identity.public_key)
                self.assertIs(config.identity, identity)
                self.assertEqual(config.relay_payment_address, discovered.payment_address)
                self.assertEqual(config.relay_attestation_address, RELAY_SIGNER)
                self.assertEqual(callbacks[-1]["relay_public_url"], discovered_url)
                self.assertEqual(discovery.directory.live(), [announcement])
                self.assertFalse(errors)
            finally:
                stop.set()
                for state in (primary, discovered):
                    for session in list(state.providers.values()):
                        try:
                            session.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                provider.join(timeout=4)
        self.assertFalse(provider.is_alive())

    def test_invalid_and_rollback_registration_do_not_replace_current_record(self) -> None:
        runtime, url = self.bridge("bridge")
        publisher = self.publisher("relay", bridges=[url])
        old = publisher.current()
        self.assertEqual(publisher.publish_once(), 1)
        new = publisher.refresh_record()
        self.assertEqual(publisher.publish_once(), 1)
        bad = copy.deepcopy(new)
        bad["payment_address"] = "0x" + "66" * 20
        for record in [old, bad, {"unsigned": True}]:
            with self.subTest(record=record.get("sequence")):
                with self.assertRaises((DiscoveryError, OSError)):
                    request_json(url + "/relays/register", body={"announcement": record}, timeout=1)
        self.assertEqual(runtime.live(), [new])
        with self.assertRaises((DiscoveryError, OSError)):
            request_json(url + "/relays/register", body={"announcement": new, "ttl_seconds": 300}, timeout=1)

    def test_publisher_sequence_and_bridge_watermark_survive_restart(self) -> None:
        publisher = self.publisher("relay")
        first = publisher.current()
        runtime = self.runtime("bridge")
        runtime.merge(first)
        publisher.close()
        runtime.close()
        restarted = self.publisher("relay")
        second = restarted.current()
        self.assertGreater(second["sequence"], first["sequence"])
        restored = self.runtime("bridge")
        self.assertEqual(restored.live(), [first])
        restored.merge(second)
        with self.assertRaises(DiscoveryError):
            restored.merge(first)

    def test_relay_http_exposes_current_record_and_omits_expired_record(self) -> None:
        publisher = self.publisher("relay")
        state = RelayState(network_profile="local", incident_store_path=None, probe_store_path=None)
        state._discovery_publisher = publisher
        server = RelayControlHTTPServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}/relay-announcement"
        record = request_json(url, timeout=1)
        self.assertEqual(record, publisher.current())
        record["sequence"] = 999
        self.assertNotEqual(record, publisher.current())
        with patch("gateway.relay_discovery_runtime.time.time", return_value=publisher.current()["expires_at"]):
            with self.assertRaises((DiscoveryError, OSError)):
                request_json(url, timeout=1)

    def test_dynamic_trusted_origins_expire_without_mutating_static_allowlist(self) -> None:
        config = copy.deepcopy(self.config)
        config["context"]["network_profile"] = "testnet"
        runtime = self.runtime("public-bridge", config=config)
        binding = {**self.binding, "host": "8.8.8.8", "public_url": "https://8.8.8.8", "provider_tls": True}
        record = build_announcement(self.admission(binding=binding), RELAY_KEY, 1)
        runtime.merge(record)
        pool = PoolConfig(
            network_profile="testnet", relay_discovery=runtime,
            trusted_relay_origins={"https://static-relay.example"},
        )
        self.assertEqual(effective_trusted_relay_origins(pool), {"https://static-relay.example", "https://8.8.8.8"})
        with patch("gateway.relay_discovery.time.time", return_value=record["expires_at"]):
            self.assertEqual(effective_trusted_relay_origins(pool), {"https://static-relay.example"})
        self.assertEqual(pool.trusted_relay_origins, {"https://static-relay.example"})

    def test_context_and_publisher_identity_mismatch_fail_closed(self) -> None:
        runtime = self.runtime("bridge")
        with self.assertRaisesRegex(PoolError, "network_profile"):
            PoolConfig(network_profile="testnet", relay_discovery=runtime)
        with self.assertRaisesRegex(DiscoveryError, "payment_address"):
            RelayDiscoveryPublisher(
                self.config, self.admission(), private_key=RELAY_KEY,
                sequence_path=str(Path(self.temp.name) / "relay.sqlite3"),
                expected_bindings={"payment_address": "0x" + "77" * 20},
            )

    def test_background_sync_stops_without_erasing_directory(self) -> None:
        runtime, url = self.bridge("source")
        publisher = self.publisher("relay", bridges=[url])
        self.assertEqual(publisher.publish_once(), 1)
        destination = self.runtime("destination")
        destination.start([url])
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not destination.live():
            destination._stop.wait(0.02)
        self.assertEqual(destination.live(), runtime.live())
        destination.close()
        self.assertFalse(destination._thread.is_alive())
        restored = self.runtime("destination")
        self.assertEqual(restored.live(), runtime.live())

    def test_publisher_deadline_and_worker_limit_bound_stuck_bootstrap_requests(self) -> None:
        publisher = self.publisher("relay", bridges=[f"http://127.0.0.1:{20000 + i}" for i in range(8)])
        release = threading.Event()
        finished = threading.Event()
        lock = threading.Lock()
        calls = 0

        def blocked_request(*args, **kwargs):
            nonlocal calls
            release.wait(5)
            with lock:
                calls += 1
                if calls == 8:
                    finished.set()
            return {"ok": True}

        with patch("gateway.relay_discovery_runtime.request_json", side_effect=blocked_request) as request:
            try:
                started = time.monotonic()
                self.assertEqual(publisher.publish_once(), 0)
                self.assertLess(time.monotonic() - started, 1.8)
                self.assertEqual(publisher.publish_once(), 0)
                self.assertEqual(request.call_count, 8)
            finally:
                release.set()
                self.assertTrue(finished.wait(2))

    def test_cli_discovery_is_explicit_and_requires_durable_cache(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["bridge", "serve", "--network-profile", "local", "--network-config", "network.json"])
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(_cmd_pool_serve(args), 2)
        self.assertIn("--discovery-cache", output.getvalue())
        relay = parser.parse_args([
            "relay", "serve", "--network-config", "network.json", "--relay-admission", "admission.json",
            "--discovery-cache", "relay-discovery.sqlite3",
        ])
        self.assertEqual(relay.relay_admission, "admission.json")

    def test_cli_passes_all_configured_bootstraps_except_self(self) -> None:
        config = {**self.config, "bridge_urls": ["http://127.0.0.1:20001", "http://127.0.0.1:20002"]}
        args = _build_parser().parse_args([
            "bridge", "serve", "--network-profile", "local", "--network-config", "network.json",
            "--discovery-cache", str(Path(self.temp.name) / "bridge.sqlite3"),
            "--public-url", config["bridge_urls"][0],
        ])
        with patch("gateway.relay_discovery.load_discovery_config", return_value=config):
            with patch("gateway.client.serve_pool") as serve:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(_cmd_pool_serve(args), 0)
        pool = serve.call_args.kwargs["config"]
        self.assertEqual(pool.bootstrap_pools, [config["bridge_urls"][1]])
        self.assertIsNotNone(pool.relay_discovery)


if __name__ == "__main__":
    unittest.main()
