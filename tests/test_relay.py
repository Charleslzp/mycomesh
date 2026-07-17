from __future__ import annotations

import io
import json
import socket
import tempfile
import threading
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pathlib import Path

from gateway.browser_cors import CorsConfigurationError
from gateway.consumer_admission import ConsumerAdmissionError, RelayV3AdmissionConfig
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
    RelayControlHandler,
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
    serve_relay,
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

    def test_relay_uses_public_ports_for_registration_audience(self) -> None:
        with (
            patch("gateway.relay.RelayProviderTCPServer") as provider_server,
            patch("gateway.relay.RelayControlHTTPServer") as control_server,
        ):
            control_server.return_value.serve_forever.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                serve_relay(
                    "0.0.0.0",
                    control_port=9900,
                    provider_port=9901,
                    advertise_host="relay.example.com",
                    advertise_control_port=443,
                    advertise_provider_port=19901,
                    allow_any_signed_consumer=True,
                )

        args = provider_server.call_args.args
        self.assertEqual(args[0], ("0.0.0.0", 9901))
        self.assertEqual(args[2:], ("relay.example.com", 443, 19901))

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

    def test_relay_provider_registration_signs_v3_channel_capabilities(self) -> None:
        identity = create_identity()
        transport = generate_transport_key(identity)
        config = SimpleNamespace(
            peer_id=identity.peer_id,
            channel="codex-standard-v1",
            agent_id="coder",
            model="mycomesh-codex-standard-v1",
            network_profile="testnet",
            network_id="mycomesh-testnet",
            channel_id="codex",
            backend_policy="codex-app-server-postvalidated-v1",
            identity=identity,
            payment_address="0x" + "22" * 20,
            accepted_transport_bindings=lambda: [transport.binding],
        )
        settlement = {
            "settlement": {
                "version": 3,
                "chain_id": 11155111,
                "contract": "0x" + "33" * 20,
                "pricing_version": 1,
                "pricing_hash": "0x" + "44" * 32,
            }
        }

        with patch("gateway.relay.provider_runtime_capabilities", return_value=settlement):
            signed = _relay_provider_peer(config, audience="bridge.example:9901")
        verified = verify_relay_provider_peer(signed, audience="bridge.example:9901")

        self.assertEqual(verified["network_id"], "mycomesh-testnet")
        self.assertEqual(verified["channel_id"], "codex")
        self.assertEqual(
            verified["backend_policy"],
            "codex-app-server-postvalidated-v1",
        )
        self.assertEqual(verified["settlement"], settlement["settlement"])

    def test_nonlocal_relay_provider_rejects_wrong_channel_binding(self) -> None:
        identity = create_identity()
        transport = generate_transport_key(identity)
        peer = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "protocol": "mycomesh-relay/0.2",
                "network_profile": "testnet",
                "network_id": "mycomesh-testnet",
                "channel_id": "claude",
                "channel": "codex-standard-v1",
                "backend_policy": "codex-app-server-postvalidated-v1",
                "secure_transport_required": True,
                "transport_key": transport.binding,
                "transport_keys": [transport.binding],
                "payment_address": "0x" + "22" * 20,
            },
            identity.private_key,
            purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE,
            audience="relay.local:9901",
        )

        with self.assertRaisesRegex(RelayError, "reserved and not enabled"):
            verify_relay_provider_peer(peer, audience="relay.local:9901")

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
        server = RelayProviderTCPServer(
            ("127.0.0.1", 0),
            state,
            "bridge.example",
            443,
            19901,
        )
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
                self.assertEqual(challenge["audience"], "bridge.example:19901")
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
                self.assertEqual(registered["relay"], "http://bridge.example:443")

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

    def test_secure_relay_accepts_unpinned_consumer_only_after_v3_admission(self) -> None:
        provider = create_identity()
        consumer = create_identity()
        provider_transport = generate_transport_key(provider)
        admission = {"schema": "mycomesh.relay.consumer-admission.v1", "authorization": {}}
        with tempfile.TemporaryDirectory() as tmp:
            state = RelayState(
                v3_admission_config=RelayV3AdmissionConfig(
                    rpc_url="https://rpc.example",
                    chain_id=11155111,
                    settlement_contract="0x" + "33" * 20,
                ),
                replay_store_path=str(Path(tmp) / "relay-replay.sqlite3"),
            )
            state.providers[provider.peer_id] = RelayProviderSession(
                peer_id=provider.peer_id,
                peer={
                    "peer_id": provider.peer_id,
                    "public_key": provider.public_key,
                    "transport_key": provider_transport.binding,
                    "secure_transport_required": True,
                },
            )
            encoded = _encode_secure_frame(
                seal_json_frame(
                    {"opaque": "relay cannot read this payload"},
                    sender=consumer,
                    recipient_binding=provider_transport.binding,
                    expected_recipient_peer_id=provider.peer_id,
                    expected_recipient_public_key=provider.public_key,
                    purpose=P2P_SECURE_REQUEST_PURPOSE,
                )
            )

            with patch("gateway.relay.verify_relay_v3_admission", return_value={}) as verify:
                public_key = verify_relay_consumer_frame(
                    state,
                    encoded,
                    peer_id=provider.peer_id,
                    admission=admission,
                )

            self.assertEqual(public_key, consumer.public_key)
            verify.assert_called_once_with(
                admission,
                sender_public_key=consumer.public_key,
                provider_peer=state.providers[provider.peer_id].peer,
                config=state.v3_admission_config,
            )

    def test_secure_relay_claims_replay_before_v3_admission_rpc(self) -> None:
        provider = create_identity()
        consumer = create_identity()
        provider_transport = generate_transport_key(provider)
        with tempfile.TemporaryDirectory() as tmp:
            state = RelayState(
                v3_admission_config=RelayV3AdmissionConfig(
                    rpc_url="https://rpc.example",
                    chain_id=11155111,
                    settlement_contract="0x" + "33" * 20,
                ),
                replay_store_path=str(Path(tmp) / "relay-replay.sqlite3"),
            )
            state.providers[provider.peer_id] = RelayProviderSession(
                peer_id=provider.peer_id,
                peer={
                    "peer_id": provider.peer_id,
                    "public_key": provider.public_key,
                    "transport_key": provider_transport.binding,
                    "secure_transport_required": True,
                },
            )
            encoded = _encode_secure_frame(
                seal_json_frame(
                    {"opaque": "still private"},
                    sender=consumer,
                    recipient_binding=provider_transport.binding,
                    expected_recipient_peer_id=provider.peer_id,
                    expected_recipient_public_key=provider.public_key,
                    purpose=P2P_SECURE_REQUEST_PURPOSE,
                )
            )

            with patch(
                "gateway.relay.verify_relay_v3_admission",
                side_effect=ConsumerAdmissionError("reservation is not confirmed"),
            ):
                with self.assertRaisesRegex(RelayError, "reservation is not confirmed"):
                    verify_relay_consumer_frame(
                        state,
                        encoded,
                        peer_id=provider.peer_id,
                        admission={"schema": "mycomesh.relay.consumer-admission.v1"},
                    )
            self.assertNotIn(consumer.public_key, state.consumer_rate_limits)

            with patch("gateway.relay.verify_relay_v3_admission", return_value={}):
                with self.assertRaisesRegex(RelayError, "already been forwarded"):
                    verify_relay_consumer_frame(
                        state,
                        encoded,
                        peer_id=provider.peer_id,
                        admission={"schema": "mycomesh.relay.consumer-admission.v1"},
                    )

    def test_secure_relay_limits_v3_admission_concurrency_before_rpc(self) -> None:
        provider = create_identity()
        consumer = create_identity()
        provider_transport = generate_transport_key(provider)
        with tempfile.TemporaryDirectory() as tmp:
            state = RelayState(
                v3_admission_config=RelayV3AdmissionConfig(
                    rpc_url="https://rpc.example",
                    chain_id=11155111,
                    settlement_contract="0x" + "33" * 20,
                ),
                v3_admission_max_in_flight=1,
                replay_store_path=str(Path(tmp) / "relay-replay.sqlite3"),
            )
            state.providers[provider.peer_id] = RelayProviderSession(
                peer_id=provider.peer_id,
                peer={
                    "peer_id": provider.peer_id,
                    "public_key": provider.public_key,
                    "transport_key": provider_transport.binding,
                    "secure_transport_required": True,
                },
            )
            encoded = _encode_secure_frame(
                seal_json_frame(
                    {"opaque": "capacity test"},
                    sender=consumer,
                    recipient_binding=provider_transport.binding,
                    expected_recipient_peer_id=provider.peer_id,
                    expected_recipient_public_key=provider.public_key,
                    purpose=P2P_SECURE_REQUEST_PURPOSE,
                )
            )
            self.assertTrue(state._v3_admission_slots.acquire(blocking=False))
            try:
                with patch("gateway.relay.verify_relay_v3_admission") as verify:
                    with self.assertRaisesRegex(RelayError, "capacity is exhausted"):
                        verify_relay_consumer_frame(
                            state,
                            encoded,
                            peer_id=provider.peer_id,
                            admission={"schema": "mycomesh.relay.consumer-admission.v1"},
                        )
                verify.assert_not_called()
            finally:
                state._v3_admission_slots.release()

    def test_secure_relay_pinned_consumer_does_not_require_v3_admission(self) -> None:
        provider = create_identity()
        consumer = create_identity()
        provider_transport = generate_transport_key(provider)
        with tempfile.TemporaryDirectory() as tmp:
            state = RelayState(
                authorized_consumers={consumer.public_key},
                replay_store_path=str(Path(tmp) / "relay-replay.sqlite3"),
            )
            state.providers[provider.peer_id] = RelayProviderSession(
                peer_id=provider.peer_id,
                peer={
                    "peer_id": provider.peer_id,
                    "public_key": provider.public_key,
                    "transport_key": provider_transport.binding,
                    "secure_transport_required": True,
                },
            )
            encoded = _encode_secure_frame(
                seal_json_frame(
                    {"opaque": "compatibility request"},
                    sender=consumer,
                    recipient_binding=provider_transport.binding,
                    expected_recipient_peer_id=provider.peer_id,
                    expected_recipient_public_key=provider.public_key,
                    purpose=P2P_SECURE_REQUEST_PURPOSE,
                )
            )

            with patch("gateway.relay.verify_relay_v3_admission") as verify:
                self.assertEqual(
                    verify_relay_consumer_frame(state, encoded, peer_id=provider.peer_id),
                    consumer.public_key,
                )
                verify.assert_not_called()

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


class RelayCorsTest(unittest.TestCase):
    def test_preflight_allows_exact_origin_post_and_content_type_without_credentials(self) -> None:
        state = RelayState(cors_allowed_origins=("https://app.mycomesh.xyz",))
        handler = self._handler(
            state,
            origins=("https://app.mycomesh.xyz",),
            request_method="POST",
            request_headers="Content-Type",
        )
        handler._write = Mock()
        handler._write_empty = Mock()

        handler.do_OPTIONS()

        handler._write.assert_not_called()
        handler._write_empty.assert_called_once()
        self.assertEqual(handler._write_empty.call_args.args[0], 204)
        headers = handler._write_empty.call_args.kwargs["headers"]
        self.assertEqual(headers["Access-Control-Allow-Origin"], "https://app.mycomesh.xyz")
        self.assertEqual(headers["Access-Control-Allow-Methods"], "POST, OPTIONS")
        self.assertEqual(headers["Access-Control-Allow-Headers"], "Content-Type")
        self.assertEqual(headers["Access-Control-Max-Age"], "600")
        self.assertEqual(
            headers["Vary"],
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        )
        self.assertNotIn("Access-Control-Allow-Credentials", headers)

    def test_preflight_rejects_unlisted_or_ambiguous_origins_without_reflection(self) -> None:
        state = RelayState(cors_allowed_origins=("https://app.mycomesh.xyz",))
        origins_to_reject = (
            ("https://evil.example",),
            ("*",),
            ("null",),
            ("https://app.mycomesh.xyz/path",),
            ("https://app.mycomesh.xyz", "https://evil.example"),
        )
        for origins in origins_to_reject:
            with self.subTest(origins=origins):
                handler = self._handler(
                    state,
                    origins=origins,
                    request_method="POST",
                    request_headers="content-type",
                )
                handler._write = Mock()
                handler._write_empty = Mock()

                handler.do_OPTIONS()

                self.assertEqual(handler._write.call_args.args[0], 403)
                headers = handler._write.call_args.kwargs["headers"]
                self.assertNotIn("Access-Control-Allow-Origin", headers)
                self.assertIn("Origin", headers["Vary"])
                handler._write_empty.assert_not_called()

    def test_preflight_rejects_other_methods_and_request_headers(self) -> None:
        state = RelayState(cors_allowed_origins=("https://app.mycomesh.xyz",))
        for method, request_headers, expected_status in (
            ("GET", "content-type", 405),
            ("POST", "authorization", 400),
            ("POST", "content-type, authorization", 400),
        ):
            with self.subTest(method=method, request_headers=request_headers):
                handler = self._handler(
                    state,
                    origins=("https://app.mycomesh.xyz",),
                    request_method=method,
                    request_headers=request_headers,
                )
                handler._write = Mock()
                handler._write_empty = Mock()

                handler.do_OPTIONS()

                self.assertEqual(handler._write.call_args.args[0], expected_status)
                handler._write_empty.assert_not_called()

    def test_cross_origin_post_rejects_origin_and_cookies_before_reading_body(self) -> None:
        state = RelayState(cors_allowed_origins=("https://app.mycomesh.xyz",))
        cases = (
            (("https://evil.example",), None, 403),
            (("https://app.mycomesh.xyz", "https://evil.example"), None, 403),
            (("https://app.mycomesh.xyz",), "session=secret", 400),
        )
        for origins, cookie, expected_status in cases:
            with self.subTest(origins=origins, cookie=cookie):
                handler = self._handler(state, origins=origins, cookie=cookie)
                handler._rate_limit = Mock()
                handler._read_json = Mock()
                handler._write = Mock()

                handler.do_POST()

                self.assertEqual(handler._write.call_args.args[0], expected_status)
                self.assertNotIn(
                    "Access-Control-Allow-Credentials",
                    handler._write.call_args.kwargs["headers"],
                )
                handler._rate_limit.assert_not_called()
                handler._read_json.assert_not_called()

    def test_allowed_cross_origin_post_preserves_consumer_verification_and_relay_flow(self) -> None:
        state = RelayState(cors_allowed_origins=("https://app.mycomesh.xyz",))
        handler = self._handler(state, origins=("https://app.mycomesh.xyz",))
        handler._rate_limit = Mock()
        handler._read_json = Mock(return_value={"message": {"signed": "request"}})
        handler._write = Mock()

        with patch(
            "gateway.relay.verify_relay_consumer_request",
            return_value="consumer-public-key",
        ) as verify, patch("gateway.relay._reserve_consumer_slot") as reserve, patch(
            "gateway.relay._release_consumer_slot"
        ) as release, patch(
            "gateway.relay.relay_infer", return_value={"ok": True, "output_text": "done"}
        ) as infer:
            handler.do_POST()

        handler._rate_limit.assert_called_once_with()
        verify.assert_called_once_with(state, {"signed": "request"}, peer_id="peer-a")
        reserve.assert_called_once_with(state, "consumer-public-key")
        infer.assert_called_once_with(
            state,
            "peer-a",
            {"signed": "request"},
            timeout=180.0,
        )
        release.assert_called_once_with(state, "consumer-public-key")
        self.assertEqual(handler._write.call_args.args[0], 200)
        headers = handler._write.call_args.kwargs["headers"]
        self.assertEqual(headers["Access-Control-Allow-Origin"], "https://app.mycomesh.xyz")
        self.assertNotIn("Access-Control-Allow-Credentials", headers)

    def test_invalid_relay_origin_configuration_fails_closed(self) -> None:
        for origin in (
            "*",
            "null",
            "http://app.mycomesh.xyz",
            "https://app.mycomesh.xyz/path",
        ):
            with self.subTest(origin=origin), self.assertRaises(CorsConfigurationError):
                RelayState(cors_allowed_origins=(origin,))

    @staticmethod
    def _handler(
        state: RelayState,
        *,
        origins: tuple[str, ...],
        request_method: str | None = None,
        request_headers: str | None = None,
        cookie: str | None = None,
    ) -> RelayControlHandler:
        handler = RelayControlHandler.__new__(RelayControlHandler)
        handler.server = SimpleNamespace(state=state)
        handler.path = "/infer/peer-a"
        handler._read_deadline = None
        headers = Message()
        for origin in origins:
            headers["Origin"] = origin
        headers["Content-Type"] = "application/json; charset=utf-8"
        if request_method is not None:
            headers["Access-Control-Request-Method"] = request_method
        if request_headers is not None:
            headers["Access-Control-Request-Headers"] = request_headers
        if cookie is not None:
            headers["Cookie"] = cookie
        handler.headers = headers
        return handler


if __name__ == "__main__":
    unittest.main()
