from __future__ import annotations

import io
import json
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from gateway.identity import create_identity, sign_document
from gateway.p2p import (
    DEFAULT_CHANNEL,
    INFERENCE_REQUEST_PURPOSE,
    P2P_SECURE_REQUEST_PURPOSE,
    ProviderConfig,
    handle_secure_frame,
    provider_descriptor,
)
from gateway.pool import (
    NETWORK_PROFILE_LOCAL,
    PoolConfig,
    list_live_peers,
    register_peer,
    verify_peer_relay_addresses,
)
from gateway.relay import (
    RELAY_PROVIDER_REGISTRATION_PURPOSE,
    RelayError,
    RelayControlHTTPServer,
    RelayProviderSession,
    RelayProviderTCPServer,
    RelayState,
    _decode_secure_frame,
    _encode_secure_frame,
    _consumer_rate_limit,
    parse_relay_address,
    _reserve_consumer_slot,
    _release_consumer_slot,
    _relay_provider_peer,
    _resolve_relay_rate_limit_client_ip,
    relay_infer,
    run_relay_provider,
    verify_relay_consumer_request,
    verify_relay_consumer_frame,
    verify_relay_provider_peer,
)
from gateway.secure_transport import generate_transport_key, seal_json_frame


class RelayAddressTest(unittest.TestCase):
    def test_parse_relay_address(self) -> None:
        address = parse_relay_address("relay://relay.example.com:9900/peer-a")

        self.assertEqual(address.host, "relay.example.com")
        self.assertEqual(address.port, 9900)
        self.assertEqual(address.peer_id, "peer-a")
        self.assertEqual(address.value, "relay://relay.example.com:9900/peer-a")

        secure_tls = parse_relay_address("myco+relays://relay.example.com:443/peer-a")
        self.assertTrue(secure_tls.secure)
        self.assertTrue(secure_tls.tls)
        self.assertEqual(secure_tls.value, "myco+relays://relay.example.com:443/peer-a")

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

    def test_relay_provider_registration_challenge_is_single_connection_bound(self) -> None:
        identity = create_identity()
        config = ProviderConfig(
            peer_id=identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="gateway-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="relay",
            advertise_port=0,
            identity=identity,
            network_profile="local",
        )
        state = RelayState()
        server = RelayProviderTCPServer(("127.0.0.1", 0), state, "bridge.example", 9900)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        def read_line(reader: Any) -> dict[str, Any]:
            return json.loads(reader.readline().decode("utf-8"))

        def write_line(writer: Any, value: dict[str, Any]) -> None:
            writer.write((json.dumps(value) + "\n").encode("utf-8"))
            writer.flush()

        signed_peer: dict[str, Any] | None = None
        first_challenge = ""
        try:
            with socket.create_connection(server.server_address, timeout=5) as connection:
                reader = connection.makefile("rb")
                writer = connection.makefile("wb")
                challenge = read_line(reader)
                first_challenge = challenge["challenge"]
                signed_peer = _relay_provider_peer(
                    config,
                    audience=challenge["audience"],
                    challenge=first_challenge,
                )
                write_line(writer, {"type": "provider_register", "peer": signed_peer})
                registered = read_line(reader)
                self.assertTrue(registered["ok"])
                self.assertEqual(registered["type"], "provider_registered")
                self.assertEqual(registered["peer_id"], identity.peer_id)
                self.assertEqual(registered["challenge"], first_challenge)

            with socket.create_connection(server.server_address, timeout=5) as connection:
                reader = connection.makefile("rb")
                writer = connection.makefile("wb")
                challenge = read_line(reader)
                self.assertNotEqual(challenge["challenge"], first_challenge)
                write_line(writer, {"type": "provider_register", "peer": signed_peer})
                rejected = read_line(reader)
                self.assertFalse(rejected["ok"])
                self.assertIn("challenge", rejected["error"])
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

    def test_relay_provider_client_requires_ca_verified_tls_and_strict_ack(self) -> None:
        identity = create_identity()
        config = ProviderConfig(
            peer_id=identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="gateway-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="relay",
            advertise_port=0,
            identity=identity,
            network_profile="local",
        )
        challenge = "ab" * 32
        incoming = io.BytesIO(
            (
                json.dumps(
                    {
                        "type": "provider_challenge",
                        "protocol": "mycomesh-relay/0.2",
                        "challenge": challenge,
                        "audience": "bridge.example:9901",
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "ok": True,
                        "type": "provider_registered",
                        "protocol": "mycomesh-relay/0.2",
                        "peer_id": identity.peer_id,
                        "challenge": challenge,
                    }
                )
                + "\n"
            ).encode("utf-8")
        )
        outgoing = io.BytesIO()

        class FakeSocket:
            def settimeout(self, _value: object) -> None:
                return

            def makefile(self, mode: str) -> Any:
                return incoming if "r" in mode else outgoing

            def close(self) -> None:
                return

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_args: object) -> None:
                return

        raw_socket = FakeSocket()
        tls_context = Mock()
        tls_context.wrap_socket.return_value = raw_socket
        stop = threading.Event()
        with patch("gateway.relay.socket.create_connection", return_value=raw_socket), patch(
            "gateway.relay.ssl.create_default_context", return_value=tls_context
        ):
            run_relay_provider(
                "bridge.example",
                9901,
                config,
                on_registered=lambda _value: stop.set(),
                stop_event=stop,
                provider_tls=True,
                tls_server_hostname="bridge.example",
            )

        tls_context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="bridge.example",
        )
        registration = json.loads(outgoing.getvalue().splitlines()[0])
        self.assertEqual(registration["type"], "provider_register")
        verified = verify_relay_provider_peer(
            registration["peer"],
            audience="bridge.example:9901",
            expected_challenge=challenge,
        )
        self.assertEqual(verified["peer_id"], identity.peer_id)

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

    def test_secure_relay_authenticates_opaque_frame_and_rejects_replay(self) -> None:
        provider = create_identity()
        consumer = create_identity()
        provider_transport = generate_transport_key(provider)
        with tempfile.TemporaryDirectory() as tmp:
            state = RelayState(
                authorized_consumers={create_identity().public_key},
                allow_any_signed_consumer=True,
                replay_store_path=str(Path(tmp) / "relay-replay.sqlite3"),
            )
            state.providers[provider.peer_id] = RelayProviderSession(
                peer_id=provider.peer_id,
                peer={
                    "peer_id": provider.peer_id,
                    "public_key": provider.public_key,
                    "transport_key": provider_transport.binding,
                    "transport_keys": [provider_transport.binding],
                    "secure_transport_required": True,
                },
            )
            frame = seal_json_frame(
                {"opaque": "relay cannot read this payload"},
                sender=consumer,
                recipient_binding=provider_transport.binding,
                expected_recipient_peer_id=provider.peer_id,
                expected_recipient_public_key=provider.public_key,
                purpose=P2P_SECURE_REQUEST_PURPOSE,
            )
            encoded = _encode_secure_frame(frame)

            self.assertEqual(
                verify_relay_consumer_frame(state, encoded, peer_id=provider.peer_id),
                consumer.public_key,
            )
            with self.assertRaisesRegex(RelayError, "already been forwarded"):
                verify_relay_consumer_frame(state, encoded, peer_id=provider.peer_id)

    def test_pool_relay_address_proof_round_trips_through_live_relay(self) -> None:
        provider = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            config = ProviderConfig(
                peer_id=provider.peer_id,
                channel=DEFAULT_CHANNEL,
                agent_id="coder",
                agent_key="gateway-key",
                gateway_url="http://127.0.0.1:8000/v1",
                model="gpt-5.5",
                advertise_host="relay",
                advertise_port=0,
                identity=provider,
                network_profile="local",
                replay_store_path=str(Path(tmp) / "provider-replay.sqlite3"),
            )
            descriptor = provider_descriptor(config)
            state = RelayState(
                allow_any_signed_consumer=True,
                replay_store_path=str(Path(tmp) / "relay-replay.sqlite3"),
            )
            session = RelayProviderSession(
                peer_id=provider.peer_id,
                peer=descriptor,
            )
            state.providers[provider.peer_id] = session
            server = RelayControlHTTPServer(("127.0.0.1", 0), state)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)

            def provider_worker() -> None:
                job = session.jobs.get(timeout=5)
                request_frame = _decode_secure_frame(job.message["secure_frame"])
                job.response_queue.put(
                    {
                        "type": "relay_job_result",
                        "job_id": job.job_id,
                        "response": {
                            "secure_frame": _encode_secure_frame(
                                handle_secure_frame(config, request_frame)
                            )
                        },
                    }
                )

            worker = threading.Thread(target=provider_worker, daemon=True)
            server_thread.start()
            worker.start()
            try:
                verify_peer_relay_addresses(
                    provider.peer_id,
                    [
                        f"myco+relay://127.0.0.1:{server.server_address[1]}/{provider.peer_id}"
                    ],
                    public_key=provider.public_key,
                    transport_key=descriptor["transport_key"],
                    audience="https://pool.example",
                    trusted_relay_origins=None,
                )
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)

    def test_secure_relay_provider_rejects_plaintext_job(self) -> None:
        state = RelayState()
        session = RelayProviderSession(
            peer_id="peer-a",
            peer={"peer_id": "peer-a", "secure_transport_required": True},
        )
        state.providers[session.peer_id] = session

        with self.assertRaisesRegex(RelayError, "sealed relay frames"):
            relay_infer(state, session.peer_id, {"type": "infer", "input": "plaintext"}, timeout=1)

    def test_relay_consumer_concurrency_slots(self) -> None:
        state = RelayState(consumer_max_in_flight=1)
        _reserve_consumer_slot(state, "consumer-key")

        with self.assertRaisesRegex(RelayError, "concurrency"):
            _reserve_consumer_slot(state, "consumer-key")

        _release_consumer_slot(state, "consumer-key")
        _reserve_consumer_slot(state, "consumer-key")

    def test_relay_consumer_rate_limit_identity_table_is_bounded(self) -> None:
        state = RelayState(rate_limit_window_seconds=60, rate_limit_max_requests=10)
        state.consumer_rate_limits = {"expired": [1.0], "active": [99.0]}

        with patch("gateway.relay.MAX_RELAY_RATE_LIMIT_IDENTITIES", 2), patch(
            "gateway.relay.time.time", return_value=100.0
        ):
            _consumer_rate_limit(state, "new")
            self.assertNotIn("expired", state.consumer_rate_limits)
            self.assertEqual(set(state.consumer_rate_limits), {"active", "new"})
            with self.assertRaisesRegex(RelayError, "identity capacity"):
                _consumer_rate_limit(state, "third")

    def test_relay_timeout_disconnects_unresponsive_provider(self) -> None:
        state = RelayState()
        session = RelayProviderSession(peer_id="peer-a", peer={"peer_id": "peer-a"})
        state.providers[session.peer_id] = session

        with self.assertRaisesRegex(RelayError, "timed out"):
            relay_infer(state, session.peer_id, {"type": "infer"}, timeout=0.01)

        self.assertNotIn(session.peer_id, state.providers)

    def test_relay_trusted_proxy_real_ip_is_same_host_only_and_global(self) -> None:
        default_state = RelayState()
        self.assertEqual(
            _resolve_relay_rate_limit_client_ip(
                default_state,
                "127.0.0.1",
                ["not-trusted"],
            ),
            "127.0.0.1",
        )

        trusted_state = RelayState(trust_proxy_headers=True)
        self.assertEqual(
            _resolve_relay_rate_limit_client_ip(
                trusted_state,
                "127.0.0.1",
                ["8.8.8.8"],
            ),
            "8.8.8.8",
        )
        self.assertEqual(
            _resolve_relay_rate_limit_client_ip(
                trusted_state,
                "172.18.0.1",
                ["1.1.1.1"],
            ),
            "1.1.1.1",
        )
        with self.assertRaisesRegex(RelayError, "loopback or private"):
            _resolve_relay_rate_limit_client_ip(
                trusted_state,
                "8.8.4.4",
                ["1.1.1.1"],
            )
        invalid_headers = (
            [],
            ["invalid"],
            ["10.0.0.1"],
            ["8.8.8.8, 1.1.1.1"],
            ["8.8.8.8", "1.1.1.1"],
        )
        for headers in invalid_headers:
            with self.subTest(headers=headers), self.assertRaisesRegex(
                RelayError, "X-Real-IP"
            ):
                _resolve_relay_rate_limit_client_ip(
                    trusted_state,
                    "::1",
                    headers,
                )

    def test_relay_connection_limits_reject_invalid_configuration(self) -> None:
        for field, value in (
            ("control_max_connections", 0),
            ("provider_max_connections", 5000),
            ("request_read_deadline_seconds", float("inf")),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(RelayError, field.split("_")[0]):
                RelayState(**{field: value})


if __name__ == "__main__":
    unittest.main()
