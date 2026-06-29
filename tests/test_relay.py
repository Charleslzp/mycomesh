from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gateway.identity import create_identity, sign_document
from gateway.p2p import DEFAULT_CHANNEL, INFERENCE_REQUEST_PURPOSE
from gateway.pool import NETWORK_PROFILE_LOCAL, PoolConfig, list_live_peers, register_peer
from gateway.relay import (
    RELAY_PROVIDER_REGISTRATION_PURPOSE,
    RelayError,
    RelayState,
    parse_relay_address,
    _reserve_consumer_slot,
    _release_consumer_slot,
    verify_relay_consumer_request,
    verify_relay_provider_peer,
)


class RelayAddressTest(unittest.TestCase):
    def test_parse_relay_address(self) -> None:
        address = parse_relay_address("relay://relay.example.com:9900/peer-a")

        self.assertEqual(address.host, "relay.example.com")
        self.assertEqual(address.port, 9900)
        self.assertEqual(address.peer_id, "peer-a")
        self.assertEqual(address.value, "relay://relay.example.com:9900/peer-a")

    def test_pool_accepts_relay_addresses(self) -> None:
        config = PoolConfig(require_signed_peers=False, network_profile=NETWORK_PROFILE_LOCAL)
        register_peer(
            config,
            peer={
                "peer_id": "peer-a",
                "address": "relay://127.0.0.1:9900/peer-a",
                "channel": DEFAULT_CHANNEL,
                "model": "gpt-5.5",
            },
            ttl_seconds=30,
            now=100,
        )

        peers = list_live_peers(config, channel=DEFAULT_CHANNEL, now=101)

        self.assertEqual(peers[0]["address"], "relay://127.0.0.1:9900/peer-a")
        self.assertEqual(peers[0]["addresses"], ["relay://127.0.0.1:9900/peer-a"])

    def test_relay_provider_peer_signature_is_verified(self) -> None:
        identity = create_identity()
        peer = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "protocol": "mycomesh-relay/0.2",
                "channel": DEFAULT_CHANNEL,
                "payment_address": "0x00000000000000000000000000000000000000A2",
            },
            identity.private_key,
            purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE,
            audience="relay.local:9901",
        )

        verified = verify_relay_provider_peer(peer, audience="relay.local:9901")

        self.assertEqual(verified["peer_id"], identity.peer_id)
        self.assertEqual(verified["public_key"], identity.public_key)
        self.assertEqual(verified["payment_address"], "0x00000000000000000000000000000000000000a2")

    def test_relay_provider_peer_rejects_invalid_payment_address(self) -> None:
        identity = create_identity()
        peer = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "protocol": "mycomesh-relay/0.2",
                "channel": DEFAULT_CHANNEL,
                "payment_address": "not-an-address",
            },
            identity.private_key,
            purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE,
            audience="relay.local:9901",
        )

        with self.assertRaisesRegex(RelayError, "payment_address"):
            verify_relay_provider_peer(peer, audience="relay.local:9901")

    def test_relay_control_request_can_require_authorized_consumer_signature(self) -> None:
        identity = create_identity()
        state = RelayState(authorized_consumers={identity.public_key})
        message = sign_document(
            {
                "type": "infer",
                "request_id": "req-1",
                "channel": DEFAULT_CHANNEL,
                "input": "ok",
                "provider_peer_id": "peer-a",
            },
            identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience="peer-a",
        )

        verify_relay_consumer_request(state, message, peer_id="peer-a")

        with self.assertRaisesRegex(RelayError, "signature"):
            verify_relay_consumer_request(state, {"type": "infer", "request_id": "req-2"}, peer_id="peer-a")

        with self.assertRaisesRegex(RelayError, "mismatch"):
            verify_relay_consumer_request(state, message, peer_id="peer-b")

    def test_relay_control_rejects_open_allowlist_by_default(self) -> None:
        identity = create_identity()
        state = RelayState()
        message = sign_document(
            {
                "type": "infer",
                "request_id": "req-1",
                "channel": DEFAULT_CHANNEL,
                "input": "ok",
            },
            identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
        )

        with self.assertRaisesRegex(RelayError, "allowlist"):
            verify_relay_consumer_request(state, message)

    def test_relay_control_can_allow_any_signed_consumer_for_development(self) -> None:
        identity = create_identity()
        state = RelayState(allow_any_signed_consumer=True)
        message = sign_document(
            {
                "type": "infer",
                "request_id": "req-1",
                "channel": DEFAULT_CHANNEL,
                "input": "ok",
            },
            identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
        )

        verify_relay_consumer_request(state, message)

    def test_relay_control_rejects_duplicate_request_id_persistently(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            replay_db = str(Path(tmp) / "replay.sqlite3")
            first_state = RelayState(authorized_consumers={identity.public_key}, replay_store_path=replay_db)
            second_state = RelayState(authorized_consumers={identity.public_key}, replay_store_path=replay_db)
            message = sign_document(
                {
                    "type": "infer",
                    "request_id": "req-1",
                    "channel": DEFAULT_CHANNEL,
                    "input": "ok",
                    "provider_peer_id": "peer-a",
                },
                identity.private_key,
                purpose=INFERENCE_REQUEST_PURPOSE,
                audience="peer-a",
            )

            verify_relay_consumer_request(first_state, message, peer_id="peer-a")
            with self.assertRaisesRegex(RelayError, "duplicate"):
                verify_relay_consumer_request(second_state, message, peer_id="peer-a")

    def test_relay_consumer_concurrency_slots(self) -> None:
        state = RelayState(consumer_max_in_flight=1)
        _reserve_consumer_slot(state, "consumer-key")

        with self.assertRaisesRegex(RelayError, "concurrency"):
            _reserve_consumer_slot(state, "consumer-key")

        _release_consumer_slot(state, "consumer-key")
        _reserve_consumer_slot(state, "consumer-key")


if __name__ == "__main__":
    unittest.main()
