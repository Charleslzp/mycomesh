from __future__ import annotations

import io
import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from gateway.client import _hydrate_provider_relay_network, build_provider_process_command
from gateway.identity import create_identity
from gateway.p2p import ProviderConfig
from gateway.provider_bootstrap import ProviderBootstrapError, load_provider_network_config
from gateway.relay import RELAY_PROTOCOL_VERSION, RelayError, _normalize_relay_fallbacks, run_relay_provider
from tests.test_client import _provider_start_args
from tests.test_provider_bootstrap import _write_v8_fallback_network


POLICY = {"authorities": ["0x" + "11" * 20], "threshold": 1,
          "refresh_seconds": 30, "timeout_seconds": 3}


def endpoint(host="127.0.0.2", port=9901):
    return {"host": host, "provider_port": port, "provider_tls": False,
            "public_url": f"http://{host}:9900", "payment_address": "0x" + "55" * 20,
            "attestation_address": "0x" + "66" * 20}


def discovered_endpoint(host="127.0.0.2"):
    return {**endpoint(host), "discovery_expires_at": int(time.time()) + 300}


class ProviderDiscoveryManifestTest(unittest.TestCase):
    def write_manifest(self, root, policy):
        manifest = _write_v8_fallback_network(root, [])
        payload = json.loads(manifest.read_text())
        payload["relay_discovery"] = policy
        manifest.write_text(json.dumps(payload))
        return manifest

    def test_manifest_discovery_hydrates_in_worker_without_loading_private_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.write_manifest(Path(directory), POLICY)
            config = load_provider_network_config(manifest)
            args = SimpleNamespace(
                network_config=str(manifest), relay_host=config.relay_host, relay_port=config.relay_port,
                relay_public_url=config.relay_public_url, relay_provider_tls=config.relay_provider_tls,
                relay_payment_address=config.relay_payment_address, relay_attestation_address=config.relay_attestation_address,
                settlement_version=config.deployment.protocol_version, settlement_chain_id=config.deployment.chain_id,
                settlement_contract=config.deployment.settlement, pricing_version=config.deployment.pricing_version,
                pricing_hash=config.deployment.pricing_hash,
            )
            with patch("gateway.client.load_or_create_provider_evm_identity") as create_private, \
                 patch("gateway.client.load_provider_evm_identity") as load_private:
                self.assertIsNone(_hydrate_provider_relay_network(args))
            create_private.assert_not_called()
            load_private.assert_not_called()
            self.assertEqual(args.relay_discovery, POLICY)
            self.assertEqual(args.relay_discovery_settings["policy"], POLICY)
            self.assertEqual(args.relay_discovery_settings["bridge_urls"], list(config.bridge_urls))
            self.assertEqual(args.relay_discovery_settings["context"], {
                "network_id": config.network_id, "channel_id": config.channel_id,
                "chain_id": config.deployment.chain_id, "settlement_contract": config.deployment.settlement,
                "protocol_version": config.deployment.protocol_version, "network_profile": "testnet",
            })
            args.relay_discovery = {**POLICY, "authorities": ["0x" + "99" * 20]}
            self.assertIn("does not match", _hydrate_provider_relay_network(args))

    def test_invalid_policy_is_not_silently_downgraded_to_static_discovery(self):
        invalid = (None, {}, [], {**POLICY, "threshold": 0},
                   {**POLICY, "authorities": ["0x" + "00" * 20]},
                   {**POLICY, "authorities": ["0x" + "11" * 20, "0x" + "22" * 20]},
                   {**POLICY, "untrusted": True})
        with tempfile.TemporaryDirectory() as directory:
            for policy in invalid:
                with self.subTest(policy=policy), self.assertRaises(ProviderBootstrapError):
                    load_provider_network_config(self.write_manifest(Path(directory), policy))

    def test_discovery_configuration_is_never_dropped_across_subprocess_boundary(self):
        args = _provider_start_args(transport="relay", relay_discovery=POLICY)
        with self.assertRaisesRegex(ValueError, "network-config"):
            build_provider_process_command(args, gateway_url="http://127.0.0.1:8000/v1")


class ProviderDiscoveredRouteTest(unittest.TestCase):
    def provider(self):
        identity = create_identity()
        return ProviderConfig(
            peer_id=identity.peer_id, channel="c", agent_id="test", agent_key="test",
            gateway_url="http://127.0.0.1:8000/v1", model="m", advertise_host="relay", advertise_port=0,
            identity=identity, network_profile="local", settlement_version=8,
            relay_payment_address="0x" + "33" * 20, relay_attestation_address="0x" + "44" * 20,
            settlement_rpc_url="http://127.0.0.1:1", settlement_contract="0x" + "77" * 20,
            settlement_chain_id=1, payment_address="0x" + "88" * 20, replay_store_path=":memory:",
        )

    def test_startup_and_reconnect_discover_new_route_and_keep_provider_identity(self):
        config = self.provider()
        original_identity = config.identity
        discovered = discovered_endpoint()
        discovery = Mock()
        discovery.endpoints.return_value = [discovered]
        stop = threading.Event()
        provider_client, relay_server = socket.socketpair()
        calls, registered, peers, errors = [], [], [], []

        def write_line(writer, payload):
            writer.write(json.dumps(payload).encode() + b"\n")
            writer.flush()

        def serve_peer():
            reader, writer = relay_server.makefile("rb"), relay_server.makefile("wb")
            try:
                challenge = "ab" * 32
                write_line(writer, {"type": "provider_challenge", "protocol": RELAY_PROTOCOL_VERSION,
                                    "challenge": challenge, "audience": discovered["host"] + ":9901",
                                    "relay_payment_address": discovered["payment_address"],
                                    "relay_attestation_address": discovered["attestation_address"]})
                peers.append(json.loads(reader.readline())["peer"])
                write_line(writer, {"ok": True, "type": "provider_registered", "protocol": RELAY_PROTOCOL_VERSION,
                                    "peer_id": config.peer_id, "challenge": challenge,
                                    "relay_payment_address": discovered["payment_address"],
                                    "relay_attestation_address": discovered["attestation_address"],
                                    "relay_public_url": "http://untrusted.example"})
                stop.wait(timeout=2)
            except Exception as exc:
                errors.append(exc)
            finally:
                reader.close()
                writer.close()
                relay_server.close()

        def connect(host, port, timeout):
            calls.append((host, port))
            if host == "primary.example":
                self.assertEqual(discovery.endpoints.call_count, 0)
                raise OSError("primary offline")
            return provider_client

        def on_registered(value):
            registered.append(value)
            self.assertEqual(discovery.endpoints.call_count, 1)
            stop.set()

        worker = threading.Thread(target=serve_peer, daemon=True)
        worker.start()
        try:
            with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect), \
                 patch("gateway.relay.time.sleep"), redirect_stderr(io.StringIO()):
                run_relay_provider("primary.example", 9901, config, stop_event=stop,
                                   relay_public_url="http://primary.example", relay_discovery=discovery,
                                   on_registered=on_registered)
            self.assertFalse(errors)
            self.assertEqual(calls, [("primary.example", 9901), ("127.0.0.2", 9901)])
            self.assertEqual(discovery.endpoints.call_count, 1)
            discovery.start_refresh.assert_called_once_with()
            self.assertIs(config.identity, original_identity)
            self.assertEqual(peers[0]["peer_id"], original_identity.peer_id)
            self.assertEqual(config.relay_payment_address, discovered["payment_address"])
            self.assertEqual(config.relay_attestation_address, discovered["attestation_address"])
            self.assertEqual(registered[0]["relay_public_url"], discovered["public_url"])
        finally:
            stop.set()
            provider_client.close()
            relay_server.close()
            worker.join(timeout=2)

    def test_expired_route_returned_by_refresh_is_not_attempted(self):
        config, discovery, stop = self.provider(), Mock(), threading.Event()
        stale, current = discovered_endpoint("127.0.0.2"), discovered_endpoint("127.0.0.3")
        stale["discovery_expires_at"] = int(time.time()) - 1
        discovery.endpoints.return_value = [stale, current]
        calls = []

        def connect(host, port, timeout):
            calls.append(host)
            if len(calls) == 2:
                stop.set()
            raise OSError("not connected")

        with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect), \
             patch("gateway.relay.time.sleep"), redirect_stderr(io.StringIO()):
            run_relay_provider("primary.example", 9901, config, stop_event=stop,
                               relay_public_url="http://primary.example", relay_discovery=discovery)
        self.assertEqual(calls, ["primary.example", "127.0.0.3"])

    def test_rotating_probe_windows_do_not_starve_unattempted_relays(self):
        config, discovery, stop = self.provider(), Mock(), threading.Event()
        candidates = [
            {**discovered_endpoint(f"127.0.0.{index + 2}"),
             "attestation_address": "0x" + f"{index + 1:040x}"}
            for index in range(6)
        ]
        refreshes = 0
        calls = []

        def refresh():
            nonlocal refreshes
            offset = (refreshes % 2) * 3
            refreshes += 1
            return candidates[offset:offset + 3]

        def connect(host, port, timeout):
            calls.append(host)
            if len(calls) >= 7:
                stop.set()
            raise OSError("Provider TCP unavailable despite HTTP health")

        discovery.endpoints.side_effect = refresh
        with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect), \
             patch("gateway.relay.time.sleep"), redirect_stderr(io.StringIO()):
            run_relay_provider("primary.example", 9901, config, stop_event=stop,
                               relay_public_url="http://primary.example", relay_discovery=discovery)
        self.assertEqual(calls, ["primary.example", *[item["host"] for item in candidates]])

    def test_retained_candidate_expiry_is_enforced_when_bridge_later_fails(self):
        config, discovery, stop = self.provider(), Mock(), threading.Event()
        candidate = {**endpoint(), "discovery_expires_at": 101}
        discovery.endpoints.side_effect = [[candidate], OSError("Bridge offline"), OSError("Bridge offline")]
        clock, calls = [100], []

        def connect(host, port, timeout):
            calls.append(host)
            if host != "primary.example":
                clock[0] = 102
            if len(calls) >= 4:
                stop.set()
            raise OSError("unavailable")

        with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect), \
             patch("gateway.relay.time.time", side_effect=lambda: clock[0]), \
             patch("gateway.relay.time.sleep"), redirect_stderr(io.StringIO()):
            run_relay_provider("primary.example", 9901, config, stop_event=stop,
                               relay_public_url="http://primary.example", relay_discovery=discovery)
        self.assertEqual(calls, ["primary.example", candidate["host"], "primary.example", "primary.example"])

    def test_discovery_error_keeps_static_fallbacks_available(self):
        for error in (ValueError("Bridge response invalid"), sqlite3.OperationalError("cache locked")):
            with self.subTest(error=type(error).__name__):
                config, discovery, stop = self.provider(), Mock(), threading.Event()
                discovery.endpoints.side_effect = error
                fallback, calls = endpoint(), []

                def connect(host, port, timeout):
                    calls.append(host)
                    if len(calls) == 2:
                        stop.set()
                    raise OSError("not connected")

                with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect), \
                     patch("gateway.relay.time.sleep"), redirect_stderr(io.StringIO()):
                    run_relay_provider("primary.example", 9901, config, stop_event=stop,
                                       relay_public_url="http://primary.example", relay_fallbacks=[fallback],
                                       relay_discovery=discovery)
                self.assertEqual(calls, ["primary.example", "127.0.0.2"])

    def test_announcement_expiring_during_handshake_cannot_register_provider(self):
        config, discovery, stop = self.provider(), Mock(), threading.Event()
        discovery.endpoints.return_value = [{**endpoint(), "discovery_expires_at": 101}]
        clock, calls = [100], []
        connection = MagicMock()
        connection.__enter__.return_value = connection

        def connect(host, port, timeout):
            calls.append(host)
            if host == "primary.example":
                raise OSError("primary offline")
            clock[0] = 102
            return connection

        def retry_delay(_seconds):
            if len(calls) == 2:
                stop.set()

        challenge = {"type": "provider_challenge", "protocol": RELAY_PROTOCOL_VERSION,
                     "challenge": "ab" * 32, "audience": "127.0.0.2:9901",
                     "relay_payment_address": endpoint()["payment_address"],
                     "relay_attestation_address": endpoint()["attestation_address"]}
        with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect), \
             patch("gateway.relay.time.time", side_effect=lambda: clock[0]), \
             patch("gateway.relay.time.sleep", side_effect=retry_delay), \
             patch("gateway.relay._read_json_line", return_value=challenge), \
             patch("gateway.relay._write_json_line") as send_registration, redirect_stderr(io.StringIO()):
            run_relay_provider("primary.example", 9901, config, stop_event=stop,
                               relay_public_url="http://primary.example", relay_discovery=discovery)
        send_registration.assert_not_called()
        self.assertEqual(calls, ["primary.example", "127.0.0.2"])

    def test_literal_ipv6_discovered_endpoint_reaches_normalizer(self):
        value = {**endpoint(), "host": "::1", "public_url": "http://[::1]:9900"}
        self.assertEqual(_normalize_relay_fallbacks([value], network_profile="local"), [value])
        for host in ("fe80::1%en0", "[::1]", "::xyz"):
            with self.subTest(host=host), self.assertRaises(RelayError):
                _normalize_relay_fallbacks([{**value, "host": host}], network_profile="local")


if __name__ == "__main__":
    unittest.main()
