from __future__ import annotations

import io
import os
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from gateway.client import _relay_multihome_endpoints, _run_multihomed_relay_provider


PAYMENT = "0x" + "33" * 20
ATTESTATION = "0x" + "44" * 20


def relay_args(**changes) -> SimpleNamespace:
    values = {
        "relay_host": "relay-a.example",
        "relay_port": 10991,
        "relay_provider_tls": True,
        "relay_fallbacks": ({
            "host": "relay-b.example", "provider_port": 10991,
            "public_url": "https://relay-b.example:10443", "provider_tls": True,
            "payment_address": PAYMENT, "attestation_address": ATTESTATION,
        },),
        "relay_discovery_settings": None,
        "capacity": 1,
        "ttl": 300,
        "heartbeat_interval": 30,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def provider_config(**changes) -> SimpleNamespace:
    values = {
        "settlement_version": 10,
        "relay_payment_address": PAYMENT,
        "relay_attestation_address": ATTESTATION,
        "network_profile": "testnet",
    }
    values.update(changes)
    return SimpleNamespace(**values)


class RelayMultihomeSelectionTest(unittest.TestCase):
    def test_v10_replicas_sharing_the_channel_identity_are_all_served(self) -> None:
        endpoints = _relay_multihome_endpoints(
            relay_args(), provider_config(), "https://relay-a.example:10443",
        )
        self.assertEqual(
            [(item["host"], item["public_url"]) for item in endpoints],
            [("relay-a.example", "https://relay-a.example:10443"),
             ("relay-b.example", "https://relay-b.example:10443")],
        )

    def test_other_topologies_keep_single_session_failover(self) -> None:
        url = "https://relay-a.example:10443"
        other_identity = relay_args(relay_fallbacks=({
            **relay_args().relay_fallbacks[0], "attestation_address": "0x" + "55" * 20,
        },))
        cases = {
            "v9": (relay_args(), provider_config(settlement_version=9)),
            "no fallback": (relay_args(relay_fallbacks=()), provider_config()),
            "different identity": (other_identity, provider_config()),
            "discovery": (relay_args(relay_discovery_settings={"bridge_urls": []}), provider_config()),
        }
        for label, (args, config) in cases.items():
            with self.subTest(label):
                self.assertIsNone(_relay_multihome_endpoints(args, config, url))
        with patch.dict(os.environ, {"MYCOMESH_PROVIDER_RELAY_MULTIHOME": "0"}):
            self.assertIsNone(_relay_multihome_endpoints(relay_args(), provider_config(), url))


class RelayMultihomeRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoints = _relay_multihome_endpoints(
            relay_args(), provider_config(), "https://relay-a.example:10443",
        )
        self.started: list[list[str]] = []
        self.stopped: list[list] = []

    def _start(self, args, config, pool_urls, addresses):
        worker = SimpleNamespace(stop_event=threading.Event(), thread=SimpleNamespace(is_alive=lambda: False, join=lambda timeout=None: None))
        self.started.append(list(addresses))
        return [worker]

    def _stop(self, heartbeat):
        if heartbeat:
            self.stopped.append(heartbeat)

    def _run(self, session_script):
        stop = threading.Event()
        calls: list[dict] = []
        barrier = threading.Barrier(2)

        def run_provider(**kwargs):
            calls.append(kwargs)
            barrier.wait(timeout=2)
            session_script(kwargs, stop, barrier)

        with patch("gateway.client.run_relay_provider", side_effect=run_provider), \
             patch("gateway.client._start_relay_bridge_heartbeats", side_effect=self._start), \
             patch("gateway.client._stop_relay_bridge_heartbeats", side_effect=self._stop), \
             patch("gateway.client._stop_heartbeats", side_effect=self._stop), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = _run_multihomed_relay_provider(
                relay_args(), provider_config(), ["https://bridge.example"],
                "peer_test", stop, self.endpoints,
            )
        return result, calls

    def test_one_lease_covers_every_relay_and_survives_a_single_relay_restart(self) -> None:
        order = threading.Lock()

        def script(kwargs, stop, barrier):
            host = kwargs["relay_host"]
            with order:
                kwargs["on_registered"]({})
            barrier.wait(timeout=2)
            if host == "relay-a.example":
                # relay-a restarts: its session drops and re-registers.
                with order:
                    kwargs["on_disconnected"]()
                    self.assertEqual(self.stopped, [], "a surviving session keeps the lease")
                    kwargs["on_registered"]({})
            barrier.wait(timeout=2)
            with order:
                kwargs["on_disconnected"]()
            barrier.wait(timeout=2)
            stop.set()

        result, calls = self._run(script)
        self.assertEqual(result, 0)
        self.assertEqual(sorted(call["relay_host"] for call in calls), ["relay-a.example", "relay-b.example"])
        self.assertTrue(all("relay_fallbacks" not in call for call in calls))
        self.assertEqual(len(self.started), 1)
        self.assertEqual(len(self.started[0]), 2)
        self.assertTrue(all("peer_test" in address for address in self.started[0]))
        self.assertEqual(len(self.stopped), 1)

    def test_fatal_session_error_stops_every_session_and_fails_the_process(self) -> None:
        def script(kwargs, stop, barrier):
            if kwargs["relay_host"] == "relay-b.example":
                raise RuntimeError("callback cleanup failed")
            self.assertTrue(stop.wait(timeout=2))

        result, _ = self._run(script)
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
