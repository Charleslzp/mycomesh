from __future__ import annotations

import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from gateway.client import _relay_address_from_control_url
from gateway.identity import create_identity
from gateway.p2p import ProviderConfig
from gateway.pool import effective_trusted_relay_origins, relay_address_origin, validate_trusted_relay_addresses
from gateway.relay import (
    RelayAddress, RelayProviderTCPServer, RelayState, _normalize_relay_fallbacks, _post_relay_message,
    parse_relay_address, run_relay_provider, submit_relay_settlement,
)
from gateway.relay_discovery import (
    BINDING_FIELDS, ENDPOINT_FIELDS, RelayDirectory, build_admission, build_announcement, verify_announcement,
)
from tests.test_relay_discovery import KEYS, fixture


PUBLIC_IPV6 = "2606:4700:4700::1111"


class RelayDiscoveryIPv6Test(unittest.TestCase):
    def test_signed_announcement_survives_provider_to_bridge_address_conversion(self):
        now = int(time.time())
        policy, context, _, original = fixture(now=now)
        context = {**context, "network_profile": "testnet"}
        for port in (443, 8443):
            with self.subTest(port=port):
                origin = f"https://[{PUBLIC_IPV6}]" + (f":{port}" if port != 443 else "")
                binding = {key: original[key] for key in BINDING_FIELDS}
                binding.update(host=PUBLIC_IPV6, public_url=origin, provider_tls=True)
                admission = build_admission(binding, expires_at=now + 86400, private_keys=KEYS[:2])
                record = build_announcement(admission, KEYS[3], 1, now=now)
                verified = verify_announcement(record, policy=policy, context=context, now=now)
                endpoint = _normalize_relay_fallbacks(
                    [{key: verified[key] for key in ENDPOINT_FIELDS}], network_profile="testnet",
                )[0]
                provider_address = _relay_address_from_control_url(endpoint["public_url"], "provider-one", secure=True)
                self.assertEqual(provider_address, f"myco+relays://[{PUBLIC_IPV6}]:{port}/provider-one")
                parsed = parse_relay_address(provider_address)
                self.assertEqual(parsed.host, PUBLIC_IPV6)
                self.assertEqual(parsed.value, provider_address)
                self.assertEqual(relay_address_origin(provider_address), origin)
                directory = RelayDirectory(policy=policy, context=context)
                try:
                    directory.merge(record)
                    bridge_config = SimpleNamespace(trusted_relay_origins=set(), relay_discovery=directory)
                    trusted_origins = effective_trusted_relay_origins(bridge_config)
                    self.assertEqual(trusted_origins, {origin})
                    validate_trusted_relay_addresses([provider_address], trusted_origins)
                finally:
                    directory.close()

    def test_http_requests_keep_ipv6_authority_bracketed(self):
        address = RelayAddress(PUBLIC_IPV6, 8443, "provider-one", "myco+relays")
        self.assertEqual(address.http_origin, f"https://[{PUBLIC_IPV6}]:8443")
        response = MagicMock()
        response.__enter__.return_value = response
        with patch("gateway.relay._RELAY_HTTP_OPENER.open", return_value=response) as request, \
             patch("gateway.relay.read_bounded", return_value=b'{"ok":true}'):
            _post_relay_message(address, {"message": {}}, timeout=1)
            self.assertEqual(request.call_args.args[0].full_url,
                             f"https://[{PUBLIC_IPV6}]:8443/infer/provider-one")
            submit_relay_settlement(address, {"protocol_version": 6}, timeout=1)
            self.assertEqual(request.call_args.args[0].full_url,
                             f"https://[{PUBLIC_IPV6}]:8443/v6/settlements")

    def test_registration_acknowledgement_preserves_ipv6_urls(self):
        state = RelayState()
        server = RelayProviderTCPServer(("127.0.0.1", 0), state, PUBLIC_IPV6, 9900)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        identity = create_identity()
        config = ProviderConfig(
            peer_id=identity.peer_id, channel="c", agent_id="test", agent_key="test",
            gateway_url="http://127.0.0.1:1/v1", model="m", advertise_host="relay", advertise_port=0,
            identity=identity, network_profile="local",
        )
        stop, registrations = threading.Event(), []

        def on_registered(value):
            registrations.append(value)
            stop.set()

        def connect(_host, _port, *, timeout):
            return socket.create_connection(server.server_address, timeout=timeout)

        try:
            with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect):
                run_relay_provider(PUBLIC_IPV6, server.server_address[1], config,
                                   stop_event=stop, on_registered=on_registered)
            self.assertEqual(registrations[0]["relay"], f"http://[{PUBLIC_IPV6}]:9900")
            self.assertEqual(registrations[0]["relay_address"], f"relay://[{PUBLIC_IPV6}]:9900/{identity.peer_id}")
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
