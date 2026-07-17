from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import gateway.pool
from unittest.mock import patch

from gateway.chain import ChainError
from gateway.channel_policy import (
    CODEX_BACKEND_POLICY,
    CODEX_CHANNEL_ID,
    MYCOMESH_TESTNET_NETWORK_ID,
)
from gateway.client import _cmd_pool_infer, _cmd_pool_serve, _provider_profile_preflight, build_bridge_usage, discover_peers_from_pools, join_provider_pools
from gateway.identity import create_identity, sign_document
from gateway.p2p import ADDRESS_PROOF_PURPOSE, DEFAULT_CHANNEL, P2PError
from gateway.secure_transport import generate_transport_key
from gateway.pool import (
    MAX_NODE_TTL_SECONDS,
    MAX_PERMISSIONLESS_PEER_DESCRIPTOR_BYTES,
    MAX_POOL_PEER_LIST_LIMIT,
    NETWORK_PROFILE_LOCAL,
    NETWORK_PROFILE_OPEN,
    NETWORK_PROFILE_TESTNET,
    POOL_LEAVE_PURPOSE,
    POOL_REGISTRATION_PURPOSE,
    POOL_REPUTATION_PURPOSE,
    PoolConfig,
    PoolError,
    PoolHTTPServer,
    _enforce_pool_rate_limit,
    _resolve_observed_ipv4,
    _resolve_rate_limit_client_ip,
    start_pool_heartbeat,
    discover_peers,
    get_pool_observed_ip,
    join_pool,
    list_live_peers,
    load_pool_reputation,
    pool_health_payload,
    record_peer_reputation,
    register_peer,
    remove_peer,
    save_pool_reputation,
    validate_pool_launch_config,
    validate_public_peer_addresses,
    verify_leave_descriptor,
    verify_peer_addresses,
    verify_peer_relay_addresses,
    verify_reputation_feedback,
)


class PoolDirectoryTest(unittest.TestCase):
    def test_pool_connection_limits_reject_invalid_configuration(self) -> None:
        for field, value in (
            ("max_connections", 0),
            ("request_read_deadline_seconds", float("inf")),
            ("http_read_timeout_seconds", 61),
            ("max_peers", 0),
            ("max_rate_limit_clients", 0),
            ("rate_limit_max_requests", 10_001),
            ("max_concurrent_address_verifications", 0),
            ("registration_nonce_ttl_seconds", 3601),
            ("max_registration_nonces", 262_145),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(Exception, "pool"):
                PoolConfig(**{field: value})

    def test_permissionless_descriptor_and_peer_list_are_bounded(self) -> None:
        permissionless = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            allow_any_signed_provider=True,
            authorized_reputation_signers={create_identity().public_key},
        )
        with self.assertRaisesRegex(Exception, "permissionless provider descriptor is too large"):
            register_peer(
                permissionless,
                peer={"padding": "x" * MAX_PERMISSIONLESS_PEER_DESCRIPTOR_BYTES},
            )

        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            reputation_path=None,
            max_peers=MAX_POOL_PEER_LIST_LIMIT + 50,
        )
        config.peers = {
            f"peer-{index}": {
                "peer_id": f"peer-{index}",
                "channel": DEFAULT_CHANNEL,
                "last_seen": index,
                "expires_at": 4_000_000_000,
            }
            for index in range(MAX_POOL_PEER_LIST_LIMIT + 25)
        }
        server = PoolHTTPServer(("127.0.0.1", 0), config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_port}/peers?limit=999999",
                timeout=3,
            ) as response:
                payload = json.loads(response.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(len(payload["peers"]), MAX_POOL_PEER_LIST_LIMIT)

    def test_register_peer_and_filter_by_channel(self) -> None:
        config = PoolConfig(require_signed_peers=False, verify_direct_addresses=False, network_profile=NETWORK_PROFILE_LOCAL)
        register_peer(
            config,
            peer={
                "peer_id": "peer-a",
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
                "model": "gpt-5.5",
            },
            ttl_seconds=30,
            capacity={"max_concurrency": 2},
            now=100,
        )
        register_peer(
            config,
            peer={
                "peer_id": "peer-b",
                "address": "tcp://127.0.0.1:9701",
                "channel": "other",
                "model": "gpt-5.5",
            },
            ttl_seconds=30,
            now=101,
        )

        peers = list_live_peers(config, channel=DEFAULT_CHANNEL, now=102)

        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["peer_id"], "peer-a")
        self.assertEqual(peers[0]["capacity"]["max_concurrency"], 2)

    def test_list_live_peers_prunes_expired_entries(self) -> None:
        config = PoolConfig(require_signed_peers=False, verify_direct_addresses=False, network_profile=NETWORK_PROFILE_LOCAL)
        register_peer(
            config,
            peer={
                "peer_id": "peer-a",
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
            },
            ttl_seconds=5,
            now=100,
        )

        self.assertEqual(list_live_peers(config, now=104)[0]["peer_id"], "peer-a")
        self.assertEqual(list_live_peers(config, now=106), [])

    def test_pool_health_counts_live_peers_and_channels(self) -> None:
        config = PoolConfig(require_signed_peers=False, verify_direct_addresses=False, network_profile=NETWORK_PROFILE_LOCAL)
        register_peer(
            config,
            peer={
                "peer_id": "peer-a",
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
            },
            ttl_seconds=30,
        )

        health = pool_health_payload(config)

        self.assertTrue(health["ok"])
        self.assertEqual(health["live_peers"], 1)
        self.assertEqual(health["channels"], [DEFAULT_CHANNEL])

    def test_expected_v3_settlement_is_signed_admission_policy_and_public_health(self) -> None:
        identity = create_identity()
        expected = {
            "version": 3,
            "chain_id": 11155111,
            "contract": "0x" + "aB" * 20,
            "pricing_version": 7,
            "pricing_hash": "0x" + "cD" * 32,
        }
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            public_url="https://pool.example",
            authorized_provider_public_keys={identity.public_key},
            authorized_reputation_signers={create_identity().public_key},
            expected_settlement=expected,
            expected_network_id=MYCOMESH_TESTNET_NETWORK_ID,
            expected_channel_id=CODEX_CHANNEL_ID,
            expected_channel=DEFAULT_CHANNEL,
            expected_backend_policy=CODEX_BACKEND_POLICY,
        )
        descriptor = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "address": "myco+tcp://8.8.8.8:9700",
                "transport_key": generate_transport_key(identity).binding,
                "channel": DEFAULT_CHANNEL,
                "network_id": MYCOMESH_TESTNET_NETWORK_ID,
                "channel_id": CODEX_CHANNEL_ID,
                "backend_policy": CODEX_BACKEND_POLICY,
                "payment_address": "0x00000000000000000000000000000000000000a2",
                "ttl_seconds": 30,
                "capacity": {"max_concurrency": 2},
                "settlement": dict(expected),
            },
            identity.private_key,
            purpose=POOL_REGISTRATION_PURPOSE,
            audience="https://pool.example",
        )

        with patch("gateway.pool.verify_peer_addresses") as verify_addresses:
            registered = register_peer(config, descriptor, now=100)

        self.assertEqual(registered["peer_id"], identity.peer_id)
        verify_addresses.assert_called_once()

        health = pool_health_payload(config)
        self.assertEqual(
            health["settlement"],
            {
                "version": 3,
                "chain_id": 11155111,
                "contract": "0x" + "ab" * 20,
                "pricing_version": 7,
                "pricing_hash": "0x" + "cd" * 32,
            },
        )
        self.assertEqual(health["expected_channel"], DEFAULT_CHANNEL)
        self.assertEqual(health["expected_channel_id"], CODEX_CHANNEL_ID)
        self.assertEqual(health["expected_backend_policy"], CODEX_BACKEND_POLICY)
        health["settlement"]["chain_id"] = 1
        self.assertEqual(config.expected_settlement["chain_id"], 11155111)

    def test_expected_v3_settlement_rejects_missing_or_mismatched_capability_before_probe(self) -> None:
        identity = create_identity()
        expected = {
            "version": 3,
            "chain_id": 11155111,
            "contract": "0x" + "ab" * 20,
            "pricing_version": 7,
            "pricing_hash": "0x" + "cd" * 32,
        }
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            public_url="https://pool.example",
            authorized_provider_public_keys={identity.public_key},
            authorized_reputation_signers={create_identity().public_key},
            expected_settlement=expected,
            expected_network_id=MYCOMESH_TESTNET_NETWORK_ID,
            expected_channel_id=CODEX_CHANNEL_ID,
            expected_channel=DEFAULT_CHANNEL,
            expected_backend_policy=CODEX_BACKEND_POLICY,
        )
        transport_key = generate_transport_key(identity).binding

        def signed_peer(
            settlement: Any = None,
            channel: str = DEFAULT_CHANNEL,
            binding_overrides: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            descriptor = {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "address": "myco+tcp://8.8.8.8:9700",
                "transport_key": transport_key,
                "channel": channel,
                "network_id": MYCOMESH_TESTNET_NETWORK_ID,
                "channel_id": CODEX_CHANNEL_ID,
                "backend_policy": CODEX_BACKEND_POLICY,
                "payment_address": "0x00000000000000000000000000000000000000a2",
                "ttl_seconds": 30,
                "capacity": {"max_concurrency": 2},
            }
            descriptor.update(binding_overrides or {})
            if settlement is not None:
                descriptor["settlement"] = settlement
            return sign_document(
                descriptor,
                identity.private_key,
                purpose=POOL_REGISTRATION_PURPOSE,
                audience="https://pool.example",
            )

        rejected = (
            ("missing", None, "JSON object"),
            ("string integer", {**expected, "chain_id": "11155111"}, "must be an integer"),
            ("wrong contract", {**expected, "contract": "0x" + "ef" * 20}, "does not match"),
            ("wrong pricing", {**expected, "pricing_hash": "0x" + "01" * 32}, "does not match"),
        )
        with patch("gateway.pool.verify_peer_addresses") as verify_addresses:
            for label, settlement, error in rejected:
                with self.subTest(label=label), self.assertRaisesRegex(PoolError, error):
                    register_peer(config, signed_peer(settlement), now=100)
            with self.assertRaisesRegex(PoolError, "peer.channel"):
                register_peer(
                    config, signed_peer(expected, channel="other-channel"), now=100
                )
            for field, value in (
                ("channel_id", None),
                ("network_id", "other-network"),
                ("backend_policy", "other-backend"),
            ):
                with self.subTest(field=field), self.assertRaisesRegex(PoolError, f"peer.{field}"):
                    register_peer(
                        config,
                        signed_peer(expected, binding_overrides={field: value}),
                        now=100,
                    )
        verify_addresses.assert_not_called()

    def test_pool_serve_testnet_fails_before_listen_without_v3_manifest(self) -> None:
        args = argparse.Namespace(
            host="0.0.0.0",
            port=9800,
            public_url="https://pool.example",
            network_profile=NETWORK_PROFILE_TESTNET,
            provider_public_key=[create_identity().public_key],
            allow_any_signed_provider=False,
            trust_proxy_headers=False,
            skip_direct_address_verification=False,
            reputation_signer_public_key=[create_identity().public_key],
            allow_any_reputation_signer=False,
        )
        errors = io.StringIO()
        with patch(
            "gateway.client.load_active_myco_deployment",
            side_effect=ChainError("Myco V3 deployment not found"),
        ), patch("gateway.client.serve_pool") as serve, contextlib.redirect_stderr(errors):
            result = _cmd_pool_serve(args)

        self.assertEqual(result, 2)
        self.assertIn("V3 deployment manifest could not be loaded", errors.getvalue())
        serve.assert_not_called()

    def test_pool_serve_testnet_loads_manifest_into_admission_config(self) -> None:
        args = argparse.Namespace(
            host="0.0.0.0",
            port=9800,
            public_url="https://pool.example",
            network_profile=NETWORK_PROFILE_TESTNET,
            provider_public_key=[create_identity().public_key],
            allow_any_signed_provider=False,
            trust_proxy_headers=False,
            skip_direct_address_verification=False,
            reputation_signer_public_key=[create_identity().public_key],
            allow_any_reputation_signer=False,
        )
        deployment = SimpleNamespace(
            chain_id=11155111,
            settlement="0x" + "ab" * 20,
            pricing_version=7,
            pricing_hash="0x" + "cd" * 32,
            channel=DEFAULT_CHANNEL,
            network_id=MYCOMESH_TESTNET_NETWORK_ID,
            channel_id=CODEX_CHANNEL_ID,
            backend_policy=CODEX_BACKEND_POLICY,
        )
        with patch(
            "gateway.client.load_active_myco_deployment",
            return_value=deployment,
        ), patch("gateway.client.serve_pool") as serve:
            result = _cmd_pool_serve(args)

        self.assertEqual(result, 0)
        config = serve.call_args.kwargs["config"]
        self.assertEqual(
            config.expected_settlement,
            {
                "version": 3,
                "chain_id": 11155111,
                "contract": "0x" + "ab" * 20,
                "pricing_version": 7,
                "pricing_hash": "0x" + "cd" * 32,
            },
        )

        self.assertEqual(config.expected_channel, DEFAULT_CHANNEL)
        self.assertEqual(config.expected_channel_id, CODEX_CHANNEL_ID)
        self.assertEqual(config.expected_backend_policy, CODEX_BACKEND_POLICY)
    def test_reputation_score_is_returned_and_sorts_peers(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            reputation_path=None,
            network_profile=NETWORK_PROFILE_LOCAL,
        )
        register_peer(
            config,
            peer={"peer_id": "peer-a", "address": "tcp://127.0.0.1:9700", "channel": DEFAULT_CHANNEL},
            ttl_seconds=30,
            now=100,
        )
        register_peer(
            config,
            peer={"peer_id": "peer-b", "address": "tcp://127.0.0.1:9701", "channel": DEFAULT_CHANNEL},
            ttl_seconds=30,
            now=101,
        )
        record_peer_reputation(config, "peer-a", settled=True)

        peers = list_live_peers(config, channel=DEFAULT_CHANNEL, now=102)

        self.assertEqual(peers[0]["peer_id"], "peer-a")
        self.assertEqual(peers[0]["reputation"]["score"], 20)

    def test_reputation_feedback_requires_signature_and_persists(self) -> None:
        identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reputation.json"
            config = PoolConfig(
                require_signed_peers=False,
                verify_direct_addresses=False,
                public_url="http://pool.local",
                reputation_path=str(path),
                network_profile=NETWORK_PROFILE_LOCAL,
            )
            feedback = sign_document(
                {
                    "peer_id": "peer-a",
                    "receipt_hash": "0x" + "1" * 64,
                    "settled": True,
                },
                identity.private_key,
                purpose=POOL_REPUTATION_PURPOSE,
                audience="http://pool.local",
            )
            verified = verify_reputation_feedback(
                feedback,
                audience="http://pool.local",
                authorized_signers={identity.public_key},
            )
            record_peer_reputation(config, verified["peer_id"], settled=bool(verified.get("settled")))
            reloaded = PoolConfig(reputation_path=str(path))
            load_pool_reputation(reloaded)

        self.assertEqual(reloaded.reputation["peer-a"]["settlements"], 1)
        with self.assertRaisesRegex(Exception, "signature"):
            verify_reputation_feedback({"peer_id": "peer-a", "receipt_hash": "0x" + "1" * 64, "settled": True})

    def test_reputation_feedback_rejects_unauthorized_signer_by_default(self) -> None:
        identity = create_identity()
        feedback = sign_document(
            {
                "peer_id": "peer-a",
                "receipt_hash": "0x" + "1" * 64,
                "settled": True,
            },
            identity.private_key,
            purpose=POOL_REPUTATION_PURPOSE,
        )

        with self.assertRaisesRegex(Exception, "allowlist"):
            verify_reputation_feedback(feedback)

    def test_register_peer_accepts_signed_descriptor(self) -> None:
        identity = create_identity()
        config = PoolConfig(verify_direct_addresses=False, public_url="http://pool.local", network_profile=NETWORK_PROFILE_LOCAL)
        peer = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
                "model": "gpt-5.5",
            },
            identity.private_key,
            purpose=POOL_REGISTRATION_PURPOSE,
            audience="http://pool.local",
        )

        registered = register_peer(config, peer=peer, ttl_seconds=30, now=100)

        self.assertEqual(registered["peer_id"], identity.peer_id)
        self.assertEqual(registered["public_key"], identity.public_key)
        self.assertIn("signature", registered)

        with self.assertRaisesRegex(Exception, "audience"):
            register_peer(
                config,
                peer=sign_document(
                    {
                        "peer_id": identity.peer_id,
                        "public_key": identity.public_key,
                        "address": "tcp://127.0.0.1:9700",
                        "channel": DEFAULT_CHANNEL,
                    },
                    identity.private_key,
                    purpose=POOL_REGISTRATION_PURPOSE,
                    audience="http://other.pool",
                ),
                ttl_seconds=30,
            )

    def test_register_peer_rejects_invalid_payment_address(self) -> None:
        config = PoolConfig(require_signed_peers=False, verify_direct_addresses=False, network_profile=NETWORK_PROFILE_LOCAL)

        with self.assertRaisesRegex(Exception, "payment_address"):
            register_peer(
                config,
                peer={
                    "peer_id": "peer-a",
                    "address": "tcp://127.0.0.1:9700",
                    "channel": DEFAULT_CHANNEL,
                    "payment_address": "not-an-address",
                },
                ttl_seconds=30,
            )

    def test_register_peer_rejects_unsigned_descriptor_by_default(self) -> None:
        config = PoolConfig()

        with self.assertRaisesRegex(Exception, "signature"):
            register_peer(
                config,
                peer={
                    "peer_id": "peer-a",
                    "address": "tcp://127.0.0.1:9700",
                    "channel": DEFAULT_CHANNEL,
                },
                ttl_seconds=30,
            )

    def test_verify_leave_descriptor_requires_peer_owner_signature(self) -> None:
        identity = create_identity()
        leave = sign_document(
            {"peer_id": identity.peer_id},
            identity.private_key,
            purpose=POOL_LEAVE_PURPOSE,
        )

        self.assertEqual(verify_leave_descriptor(leave), identity.peer_id)

        with self.assertRaisesRegex(Exception, "signature"):
            verify_leave_descriptor({"peer_id": identity.peer_id})

        with self.assertRaisesRegex(Exception, "does not match"):
            verify_leave_descriptor(
                sign_document(
                    {"peer_id": "peer_not-owner"},
                    identity.private_key,
                    purpose=POOL_LEAVE_PURPOSE,
                )
            )

    def test_remove_peer_only_removes_existing_id_after_verification(self) -> None:
        config = PoolConfig(require_signed_peers=False, verify_direct_addresses=False, network_profile=NETWORK_PROFILE_LOCAL)
        register_peer(
            config,
            peer={
                "peer_id": "peer-a",
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
            },
            ttl_seconds=30,
            now=100,
        )

        self.assertTrue(remove_peer(config, "peer-a"))
        self.assertFalse(remove_peer(config, "peer-a"))

    def test_verify_peer_addresses_requires_matching_peer_id(self) -> None:
        def matching_response(peer: Any, message: dict[str, Any], timeout: float) -> dict[str, Any]:
            return {"request_id": message["request_id"], "peer": {"peer_id": "peer-a"}}

        with patch("gateway.pool.send_message", side_effect=matching_response):
            verify_peer_addresses("peer-a", ["tcp://127.0.0.1:9700"])

        def mismatching_response(peer: Any, message: dict[str, Any], timeout: float) -> dict[str, Any]:
            return {"request_id": message["request_id"], "peer": {"peer_id": "peer-b"}}

        with patch("gateway.pool.send_message", side_effect=mismatching_response):
            with self.assertRaisesRegex(Exception, "different peer_id"):
                verify_peer_addresses("peer-a", ["tcp://127.0.0.1:9700"])

    def test_verify_peer_addresses_requires_provider_signed_challenge(self) -> None:
        identity = create_identity()
        attacker = create_identity()

        def signed_response(signer: Any) -> Any:
            def respond(peer: Any, message: dict[str, Any], timeout: float) -> dict[str, Any]:
                return sign_document(
                    {
                        "type": "pong",
                        "ok": True,
                        "request_id": message["request_id"],
                        "peer": {
                            "peer_id": signer.peer_id,
                            "public_key": signer.public_key,
                        },
                    },
                    signer.private_key,
                    purpose=ADDRESS_PROOF_PURPOSE,
                    audience="https://pool.example",
                )

            return respond

        with patch("gateway.pool.send_message", side_effect=signed_response(identity)):
            verify_peer_addresses(
                identity.peer_id,
                ["tcp://127.0.0.1:9700"],
                public_key=identity.public_key,
                audience="https://pool.example",
                require_signed=True,
            )
        with patch("gateway.pool.send_message", side_effect=signed_response(attacker)):
            with self.assertRaisesRegex(Exception, "different provider key"):
                verify_peer_addresses(
                    identity.peer_id,
                    ["tcp://127.0.0.1:9700"],
                    public_key=identity.public_key,
                    audience="https://pool.example",
                    require_signed=True,
                )

    def test_nonlocal_address_validation_blocks_ssrf_targets_and_dns_rebinding(self) -> None:
        blocked = [
            "tcp://127.0.0.1:9700",
            "tcp://10.0.0.8:9700",
            "tcp://169.254.169.254:80",
            "tcp://[::1]:9700",
            "tcp://metadata.google.internal:80",
        ]
        for address in blocked:
            with self.subTest(address=address), self.assertRaises(Exception):
                validate_public_peer_addresses([address])

        private_resolution = [(2, 1, 6, "", ("192.168.1.20", 9700))]
        with patch("gateway.pool.socket.getaddrinfo", return_value=private_resolution):
            with self.assertRaisesRegex(Exception, "non-public"):
                validate_public_peer_addresses(["tcp://provider.example:9700"])

    def test_permissionless_testnet_admits_only_signed_public_direct_providers(self) -> None:
        identity = create_identity()
        transport_key = generate_transport_key(identity).binding
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            public_url="https://pool.example",
            allow_any_signed_provider=True,
            authorized_reputation_signers={create_identity().public_key},
            trusted_relay_origins={"https://relay.example"},
        )

        def descriptor(
            address: str,
            *,
            payment: bool = True,
            signed: bool = True,
        ) -> dict[str, Any]:
            value: dict[str, Any] = {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "address": address,
                "transport_key": transport_key,
                "channel": DEFAULT_CHANNEL,
                "ttl_seconds": 30,
                "capacity": {"max_concurrency": 2},
            }
            if payment:
                value["payment_address"] = "0x00000000000000000000000000000000000000A2"
            if not signed:
                return value
            return sign_document(
                value,
                identity.private_key,
                purpose=POOL_REGISTRATION_PURPOSE,
                audience="https://pool.example",
            )

        signed_peer = descriptor("myco+tcp://8.8.8.8:9700")
        with patch("gateway.pool.verify_peer_addresses") as verify_addresses:
            registered = register_peer(config, peer=signed_peer, now=100)
            with self.assertRaisesRegex(Exception, "nonce was already used"):
                register_peer(config, peer=signed_peer, now=101)

        self.assertEqual(registered["public_key"], identity.public_key)
        verify_addresses.assert_called_once()

        relay_peer = descriptor(
            f"myco+relays://relay.example:443/{identity.peer_id}"
        )
        with patch("gateway.pool.validate_public_peer_addresses"), patch(
            "gateway.pool.verify_peer_relay_addresses"
        ) as verify_relay:
            relay_registered = register_peer(config, peer=relay_peer, now=101)
        self.assertEqual(relay_registered["peer_id"], identity.peer_id)
        verify_relay.assert_called_once()

        failed_probe_peer = descriptor("myco+tcp://8.8.4.4:9701")
        with patch(
            "gateway.pool.verify_peer_addresses",
            side_effect=RuntimeError("probe failed"),
        ) as failed_probe:
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                register_peer(config, peer=failed_probe_peer, now=102)
            with self.assertRaisesRegex(Exception, "nonce was already used"):
                register_peer(config, peer=failed_probe_peer, now=103)
        failed_probe.assert_called_once()
        rejected = (
            ("unsigned", descriptor("myco+tcp://8.8.8.8:9700", signed=False), "signature"),
            ("no-payment", descriptor("myco+tcp://8.8.8.8:9700", payment=False), "payment_address"),
            ("dns", descriptor("myco+tcp://provider.example:9700"), "DNS names"),
            ("relay-only", descriptor("myco+relay://8.8.8.8:9900/provider"), r"myco\+tcp"),
            ("plaintext", descriptor("tcp://8.8.8.8:9700"), r"myco\+tcp"),
            ("private", descriptor("myco+tcp://127.0.0.1:9700"), "literal public IP"),
        )
        for label, peer, expected in rejected:
            with self.subTest(label=label), self.assertRaisesRegex(Exception, expected):
                register_peer(config, peer=peer, now=101)

    def test_peer_and_rate_limit_registries_are_bounded_and_pruned(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            max_peers=1,
            max_rate_limit_clients=2,
            rate_limit_window_seconds=10,
            rate_limit_max_requests=2,
        )

        def peer(peer_id: str) -> dict[str, Any]:
            return {
                "peer_id": peer_id,
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
            }

        register_peer(config, peer=peer("peer-a"), ttl_seconds=5, now=100)
        heartbeat = register_peer(config, peer=peer("peer-a"), ttl_seconds=5, now=101)
        self.assertEqual(heartbeat["expires_at"], 106)
        with self.assertRaisesRegex(Exception, "peer registry capacity"):
            register_peer(config, peer=peer("peer-b"), ttl_seconds=5, now=102)
        registered = register_peer(config, peer=peer("peer-b"), ttl_seconds=5, now=107)
        self.assertEqual(registered["peer_id"], "peer-b")
        self.assertNotIn("peer-a", config.peers)

        _enforce_pool_rate_limit(config, "client-a", now=100)
        _enforce_pool_rate_limit(config, "client-b", now=100)
        with self.assertRaisesRegex(Exception, "client registry capacity"):
            _enforce_pool_rate_limit(config, "client-c", now=100.5)
        _enforce_pool_rate_limit(config, "client-a", now=100.5)
        with self.assertRaisesRegex(Exception, "rate limit exceeded"):
            _enforce_pool_rate_limit(config, "client-a", now=101)
        _enforce_pool_rate_limit(config, "client-c", now=111)
        self.assertEqual(set(config.rate_limits), {"/join|client-c"})

    def test_trusted_proxy_real_ip_is_strict_and_rate_limits_by_path(self) -> None:
        default_config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
        )
        self.assertEqual(
            _resolve_rate_limit_client_ip(default_config, "127.0.0.1", ["invalid"]),
            "127.0.0.1",
        )

        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            trust_proxy_headers=True,
            rate_limit_max_requests=1,
        )
        self.assertEqual(
            _resolve_rate_limit_client_ip(config, "127.0.0.1", ["203.0.113.9"]),
            "203.0.113.9",
        )
        self.assertEqual(
            _resolve_rate_limit_client_ip(config, "8.8.8.8", ["invalid"]),
            "8.8.8.8",
        )
        for headers in ([], ["invalid"], ["203.0.113.9, 198.51.100.2"], ["203.0.113.9", "198.51.100.2"]):
            with self.subTest(headers=headers), self.assertRaisesRegex(Exception, "X-Real-IP"):
                _resolve_rate_limit_client_ip(config, "10.0.0.5", headers)

        _enforce_pool_rate_limit(config, "203.0.113.9", path="/join", now=100)
        _enforce_pool_rate_limit(config, "203.0.113.9", path="/heartbeat", now=100)
        with self.assertRaisesRegex(Exception, "rate limit exceeded"):
            _enforce_pool_rate_limit(config, "203.0.113.9", path="/join", now=100.5)
        _enforce_pool_rate_limit(config, "203.0.113.9", path="/unknown-a", now=100)
        with self.assertRaisesRegex(Exception, "rate limit exceeded"):
            _enforce_pool_rate_limit(config, "203.0.113.9", path="/unknown-b", now=100.5)

    def test_observed_ipv4_resolution_is_global_ipv4_only(self) -> None:
        trusted = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            trust_proxy_headers=True,
        )
        self.assertEqual(
            _resolve_observed_ipv4(trusted, "127.0.0.1", ["8.8.8.8"]),
            "8.8.8.8",
        )
        self.assertEqual(
            _resolve_observed_ipv4(trusted, "172.18.0.1", ["1.1.1.1"]),
            "1.1.1.1",
        )
        self.assertEqual(
            _resolve_observed_ipv4(trusted, "8.8.4.4", ["not-trusted"]),
            "8.8.4.4",
        )
        invalid = (
            [],
            ["invalid"],
            ["10.0.0.1"],
            ["2001:4860:4860::8888"],
            ["8.8.8.8, 1.1.1.1"],
            ["8.8.8.8", "1.1.1.1"],
        )
        for headers in invalid:
            with self.subTest(headers=headers), self.assertRaisesRegex(
                Exception, "IPv4|X-Real-IP"
            ):
                _resolve_observed_ipv4(trusted, "127.0.0.1", headers)
        with self.assertRaisesRegex(Exception, "global IPv4"):
            _resolve_observed_ipv4(
                PoolConfig(
                    require_signed_peers=False,
                    verify_direct_addresses=False,
                    network_profile=NETWORK_PROFILE_LOCAL,
                ),
                "127.0.0.1",
                ["8.8.8.8"],
            )
        with self.assertRaisesRegex(Exception, "global IPv4"):
            _resolve_observed_ipv4(
                trusted,
                "2001:4860:4860::8888",
                [],
            )

    def test_observed_ip_endpoint_is_no_store_non_cors_and_rate_limited(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            trust_proxy_headers=True,
            rate_limit_max_requests=1,
            cors_allowed_origins=("https://app.example",),
        )
        server = PoolHTTPServer(("127.0.0.1", 0), config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/observed-ip"
        headers = {
            "X-Real-IP": "8.8.8.8",
            "Origin": "https://app.example",
        }
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers),
                timeout=3,
            ) as response:
                payload = json.loads(response.read())
                self.assertEqual(response.headers.get("Cache-Control"), "no-store")
                self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
            self.assertEqual(payload, {"ok": True, "observed_ipv4": "8.8.8.8"})

            with self.assertRaises(urllib.error.HTTPError) as limited:
                urllib.request.urlopen(
                    urllib.request.Request(url, headers=headers),
                    timeout=3,
                )
            self.assertEqual(limited.exception.code, 400)
            self.assertEqual(limited.exception.headers.get("Cache-Control"), "no-store")

            options = urllib.request.Request(
                url,
                method="OPTIONS",
                headers={
                    "Origin": "https://app.example",
                    "Access-Control-Request-Method": "GET",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(options, timeout=3)
            self.assertEqual(rejected.exception.code, 404)
            self.assertIsNone(
                rejected.exception.headers.get("Access-Control-Allow-Origin")
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_get_pool_observed_ip_requires_https_and_disables_redirects(self) -> None:
        with self.assertRaisesRegex(Exception, "canonical HTTPS"):
            get_pool_observed_ip("http://bridge.example")
        with self.assertRaisesRegex(Exception, "canonical origin"):
            get_pool_observed_ip("https://bridge.example/prefix")

        encoded = io.BytesIO(b'{"ok":true,"observed_ipv4":"1.1.1.1"}')
        with patch.object(
            gateway.pool._POOL_NO_REDIRECT_OPENER,
            "open",
            return_value=encoded,
        ) as no_redirect, patch(
            "gateway.pool.urllib.request.urlopen",
            side_effect=AssertionError("redirecting opener must not be used"),
        ):
            self.assertEqual(
                get_pool_observed_ip("https://bridge.example"),
                "1.1.1.1",
            )
        no_redirect.assert_called_once()
        request = no_redirect.call_args.args[0]
        self.assertEqual(request.full_url, "https://bridge.example/observed-ip")
        self.assertEqual(request.get_method(), "GET")

        with patch(
            "gateway.pool._get_json_no_redirect",
            return_value={"ok": True, "observed_ipv4": "10.0.0.1"},
        ):
            with self.assertRaisesRegex(Exception, "global IPv4"):
                get_pool_observed_ip("https://bridge.example")


    def test_all_bridge_http_operations_disable_redirects(self) -> None:
        responses = [
            io.BytesIO(b'{"ok":true,"peer":{}}'),
            io.BytesIO(b'{"ok":true,"peer":{}}'),
            io.BytesIO(b'{"ok":true,"peers":[]}'),
            io.BytesIO(b'{"ok":true}'),
        ]
        with patch.object(
            gateway.pool._POOL_NO_REDIRECT_OPENER,
            "open",
            side_effect=responses,
        ) as no_redirect, patch(
            "gateway.pool.urllib.request.urlopen",
            side_effect=AssertionError("redirecting opener must not be used"),
        ):
            join_pool("https://bridge.example", {"peer_id": "peer-a"})
            gateway.pool.heartbeat_pool(
                "https://bridge.example", {"peer_id": "peer-a"}
            )
            discover_peers(
                "https://bridge.example",
                require_signed=False,
            )
            gateway.pool.get_pool_health("https://bridge.example")

        self.assertEqual(no_redirect.call_count, 4)
        self.assertEqual(
            [call.args[0].full_url for call in no_redirect.call_args_list],
            [
                "https://bridge.example/join",
                "https://bridge.example/heartbeat",
                "https://bridge.example/peers",
                "https://bridge.example/health",
            ],
        )


    def test_direct_address_probe_slots_fail_fast_and_release(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=True,
            network_profile=NETWORK_PROFILE_LOCAL,
            max_concurrent_address_verifications=1,
        )
        peer = {
            "peer_id": "peer-a",
            "address": "tcp://127.0.0.1:9700",
            "channel": DEFAULT_CHANNEL,
        }
        self.assertTrue(config._address_verification_slots.acquire(blocking=False))
        try:
            with patch("gateway.pool.verify_peer_addresses") as verify_addresses:
                with self.assertRaisesRegex(Exception, "verification capacity"):
                    register_peer(config, peer=peer, now=100)
                verify_addresses.assert_not_called()
        finally:
            config._address_verification_slots.release()

        with patch("gateway.pool.verify_peer_addresses", side_effect=RuntimeError("probe failed")):
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                register_peer(config, peer=peer, now=100)
        self.assertTrue(config._address_verification_slots.acquire(blocking=False))
        config._address_verification_slots.release()

    def test_join_and_heartbeat_response_does_not_disclose_all_peers(self) -> None:
        config = PoolConfig(
            require_signed_peers=False,
            verify_direct_addresses=False,
            network_profile=NETWORK_PROFILE_LOCAL,
            reputation_path=None,
        )
        server = PoolHTTPServer(("127.0.0.1", 0), config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            response = join_pool(
                f"http://127.0.0.1:{server.server_port}",
                {
                    "peer_id": "peer-a",
                    "address": "tcp://127.0.0.1:9700",
                    "channel": DEFAULT_CHANNEL,
                },
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response["peer"]["peer_id"], "peer-a")
        self.assertNotIn("peers", response)

    def test_testnet_launch_requires_allowlists_and_direct_verification(self) -> None:
        provider = create_identity()
        reputation_signer = create_identity()
        network_config = {
            "public_url": "https://pool.example",
            "expected_settlement": {
                "version": 3,
                "chain_id": 11155111,
                "contract": "0x" + "ab" * 20,
                "pricing_version": 1,
                "pricing_hash": "0x" + "cd" * 32,
            },
            "expected_channel": DEFAULT_CHANNEL,
            "expected_network_id": MYCOMESH_TESTNET_NETWORK_ID,
            "expected_channel_id": CODEX_CHANNEL_ID,
            "expected_backend_policy": CODEX_BACKEND_POLICY,
        }
        config = PoolConfig(
            **network_config,
            network_profile=NETWORK_PROFILE_TESTNET,
            authorized_provider_public_keys={provider.public_key},
            authorized_reputation_signers={reputation_signer.public_key},
        )

        validate_pool_launch_config(config)
        permissionless = PoolConfig(
            **network_config,
            network_profile=NETWORK_PROFILE_TESTNET,
            allow_any_signed_provider=True,
            authorized_reputation_signers={reputation_signer.public_key},
        )
        validate_pool_launch_config(permissionless)
        health = pool_health_payload(permissionless)
        self.assertEqual(health["provider_admission_mode"], "any_signed")
        self.assertTrue(health["allow_any_signed_provider"])

        with self.assertRaisesRegex(Exception, "canonical V3 deployment manifest"):
            validate_pool_launch_config(
                PoolConfig(
                    network_profile=NETWORK_PROFILE_TESTNET,
                    authorized_provider_public_keys={provider.public_key},
                    authorized_reputation_signers={reputation_signer.public_key},
                )
            )
        with self.assertRaisesRegex(Exception, "canonical HTTPS origin"):
            validate_pool_launch_config(
                PoolConfig(
                    **(network_config | {"public_url": "http://pool.example"}),
                    network_profile=NETWORK_PROFILE_TESTNET,
                    authorized_provider_public_keys={provider.public_key},
                    authorized_reputation_signers={reputation_signer.public_key},
                )
            )


        with self.assertRaisesRegex(Exception, "provider-public-key"):
            validate_pool_launch_config(
                PoolConfig(
                    **network_config,
                    network_profile=NETWORK_PROFILE_TESTNET,
                    authorized_reputation_signers={reputation_signer.public_key},
                )
            )
        with self.assertRaisesRegex(Exception, "reputation-signer-public-key"):
            validate_pool_launch_config(
                PoolConfig(
                    **network_config,
                    network_profile=NETWORK_PROFILE_TESTNET,
                    authorized_provider_public_keys={provider.public_key},
                )
            )
        with self.assertRaisesRegex(Exception, "direct address verification"):
            validate_pool_launch_config(
                PoolConfig(
                    **network_config,
                    network_profile=NETWORK_PROFILE_TESTNET,
                    verify_direct_addresses=False,
                    authorized_provider_public_keys={provider.public_key},
                    authorized_reputation_signers={reputation_signer.public_key},
                )
            )

        for overrides, expected in (
            ({"require_signed_peers": False}, "signed provider descriptors"),
            ({"require_provider_payment_address": False}, "provider payment addresses"),
            ({"verify_direct_addresses": False}, "direct address verification"),
        ):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(Exception, expected):
                validate_pool_launch_config(
                    PoolConfig(
                        **network_config,
                        network_profile=NETWORK_PROFILE_TESTNET,
                        allow_any_signed_provider=True,
                        authorized_reputation_signers={reputation_signer.public_key},
                        **overrides,
                    )
                )

    def test_open_profile_is_reserved_until_disputes_and_staking_exist(self) -> None:
        with self.assertRaisesRegex(Exception, "reserved"):
            validate_pool_launch_config(
                PoolConfig(
                    network_profile=NETWORK_PROFILE_OPEN,
                    allow_any_signed_provider=True,
                )
            )

    def test_testnet_registration_rejects_nonpublic_and_plaintext_provider_addresses(self) -> None:
        identity = create_identity()
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            public_url="https://pool.example",
            authorized_provider_public_keys={identity.public_key},
            authorized_reputation_signers={create_identity().public_key},
        )

        def signed_peer(signer: Any, address: str, *, payment: bool = True) -> dict[str, Any]:
            descriptor = {
                "peer_id": signer.peer_id,
                "public_key": signer.public_key,
                "address": address,
                "channel": DEFAULT_CHANNEL,
                "ttl_seconds": 30,
                "capacity": {"max_concurrency": 2},
            }
            if payment:
                descriptor["payment_address"] = "0x00000000000000000000000000000000000000A2"
            return sign_document(
                descriptor,
                signer.private_key,
                purpose=POOL_REGISTRATION_PURPOSE,
                audience="https://pool.example",
            )

        peer = signed_peer(identity, "tcp://127.0.0.1:9700")
        with self.assertRaisesRegex(Exception, "non-public"):
            register_peer(config, peer=peer, ttl_seconds=30, now=100)

        public_peer = signed_peer(identity, "tcp://8.8.8.8:9700")
        with self.assertRaisesRegex(Exception, "plaintext"):
            register_peer(config, peer=public_peer, ttl_seconds=30, now=100)

        unauthorized = create_identity()
        unauthorized_peer = signed_peer(unauthorized, "tcp://8.8.8.8:9701")
        missing_payment_peer = signed_peer(identity, "tcp://8.8.8.8:9702", payment=False)

        with self.assertRaisesRegex(Exception, "not authorized"):
            register_peer(config, peer=unauthorized_peer, ttl_seconds=30)
        with self.assertRaisesRegex(Exception, "payment_address"):
            register_peer(config, peer=missing_payment_peer, ttl_seconds=30)
        config.verify_direct_addresses = False
        with self.assertRaisesRegex(Exception, "direct address verification"):
            register_peer(config, peer=public_peer, ttl_seconds=30)

    def test_nonlocal_registration_cannot_bypass_descriptor_signature(self) -> None:
        identity = create_identity()
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            require_signed_peers=False,
            public_url="https://pool.example",
            authorized_provider_public_keys={identity.public_key},
            authorized_reputation_signers={create_identity().public_key},
        )
        unsigned = {
            "peer_id": identity.peer_id,
            "public_key": identity.public_key,
            "address": "tcp://8.8.8.8:9700",
            "channel": DEFAULT_CHANNEL,
            "payment_address": "0x00000000000000000000000000000000000000a2",
            "ttl_seconds": 30,
            "capacity": {"max_concurrency": 2},
        }

        with self.assertRaisesRegex(Exception, "signature"):
            register_peer(config, peer=unsigned, allow_unsigned=True)

    def test_testnet_ttl_and_capacity_are_bounded_and_taken_from_signed_descriptor(self) -> None:
        identity = create_identity()
        transport_key = generate_transport_key(identity).binding
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            public_url="https://pool.example",
            authorized_provider_public_keys={identity.public_key},
            authorized_reputation_signers={create_identity().public_key},
        )

        def descriptor(ttl_seconds: int, capacity: int) -> dict[str, Any]:
            return sign_document(
                {
                    "peer_id": identity.peer_id,
                    "public_key": identity.public_key,
                    "address": "myco+tcp://8.8.8.8:9700",
                    "transport_key": transport_key,
                    "channel": DEFAULT_CHANNEL,
                    "payment_address": "0x00000000000000000000000000000000000000A2",
                    "ttl_seconds": ttl_seconds,
                    "capacity": {"max_concurrency": capacity},
                },
                identity.private_key,
                purpose=POOL_REGISTRATION_PURPOSE,
                audience="https://pool.example",
            )

        with patch("gateway.pool.validate_public_peer_addresses"), patch(
            "gateway.pool.validate_secure_peer_transports"
        ), patch("gateway.pool.verify_peer_addresses"):
            registered = register_peer(
                config,
                peer=descriptor(30, 2),
                ttl_seconds=MAX_NODE_TTL_SECONDS,
                capacity={"max_concurrency": 999},
                now=100,
            )

        self.assertEqual(registered["ttl_seconds"], 30)
        self.assertEqual(registered["capacity"], {"max_concurrency": 2})
        self.assertEqual(registered["descriptor"]["ttl_seconds"], 30)

        with self.assertRaisesRegex(Exception, "between"):
            register_peer(config, peer=descriptor(MAX_NODE_TTL_SECONDS + 1, 2), ttl_seconds=30)
        with self.assertRaisesRegex(Exception, "between"):
            register_peer(config, peer=descriptor(30, 10_000), ttl_seconds=30)

    def test_remote_pool_discovery_reverifies_signed_descriptor_and_rejects_tampering(self) -> None:
        identity = create_identity()
        transport_key = generate_transport_key(identity).binding
        descriptor = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "address": "myco+tcp://8.8.8.8:9700",
                "addresses": ["myco+tcp://8.8.8.8:9700"],
                "transport_key": transport_key,
                "channel": DEFAULT_CHANNEL,
                "model": "gpt-5.5",
                "payment_address": "0x00000000000000000000000000000000000000A2",
                "ttl_seconds": 30,
                "capacity": {"max_concurrency": 2},
            },
            identity.private_key,
            purpose=POOL_REGISTRATION_PURPOSE,
            audience="https://pool.example",
        )
        pool_peer = dict(descriptor)
        pool_peer.update(
            {
                "descriptor": descriptor,
                "payment_address": "0x00000000000000000000000000000000000000a2",
                "status": "online",
                "last_seen": 100,
                "expires_at": 130,
                "reputation": {"score": 10},
            }
        )

        with patch("gateway.pool._get_json", return_value={"ok": True, "peers": [pool_peer]}):
            peers = discover_peers("https://pool.example", channel=DEFAULT_CHANNEL)
        self.assertEqual(peers[0]["peer_id"], identity.peer_id)
        self.assertEqual(peers[0]["address"], "myco+tcp://8.8.8.8:9700")

        tampered = dict(pool_peer)
        tampered["address"] = "tcp://attacker.example:9700"
        tampered["addresses"] = ["tcp://attacker.example:9700"]
        with patch("gateway.pool._get_json", return_value={"ok": True, "peers": [tampered]}):
            with self.assertRaisesRegex(Exception, "addresses"):
                discover_peers("https://pool.example", channel=DEFAULT_CHANNEL)


class PoolCliTest(unittest.TestCase):
    def test_provider_profile_preflight_keeps_testnet_strict(self) -> None:
        args = argparse.Namespace(
            network_profile=NETWORK_PROFILE_TESTNET,
            pool="https://bridge.example",
            allow_unsigned_requests=False,
            allow_unreserved_requests=False,
            allow_any_signed_consumer=False,
            consumer_public_key=["consumer-key"],
            payment_address="0x00000000000000000000000000000000000000a1",
            evm_identity="/tmp/provider-evm-identity.json",
            settlement_version=3,
            settlement_confirmations=6,
            pricing_hash="0x" + "1" * 64,
            pricing_config=None,
        )

        with patch(
            "gateway.client.load_provider_evm_identity",
            return_value=SimpleNamespace(address=args.payment_address),
        ):
            self.assertIsNone(_provider_profile_preflight(args))
            args.consumer_public_key = []
            self.assertIsNone(_provider_profile_preflight(args))
            args.allow_any_signed_consumer = True
            self.assertIn("allow-any-signed-consumer", _provider_profile_preflight(args) or "")

    def test_provider_profile_preflight_allows_local_and_reserves_open(self) -> None:
        args = argparse.Namespace(
            network_profile=NETWORK_PROFILE_LOCAL,
            allow_unsigned_requests=True,
            allow_unreserved_requests=True,
            allow_any_signed_consumer=True,
            consumer_public_key=[],
            payment_address=None,
            pricing_hash=None,
            pricing_config=None,
        )

        self.assertIsNone(_provider_profile_preflight(args))
        args.network_profile = NETWORK_PROFILE_OPEN
        self.assertIn("reserved", _provider_profile_preflight(args) or "")

    def test_discover_peers_from_multiple_pools_dedupes_by_latest_peer(self) -> None:
        observed_timeouts: list[float] = []

        def fake_discover(pool_url: str, channel: str | None = None, timeout: float = 5.0) -> list[dict[str, Any]]:
            self.assertEqual(channel, DEFAULT_CHANNEL)
            observed_timeouts.append(timeout)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 7.0)
            if pool_url.endswith("pool-a"):
                return [
                    {"peer_id": "peer-1", "address": "tcp://127.0.0.1:9700", "last_seen": 10},
                    {"peer_id": "peer-2", "address": "tcp://127.0.0.1:9701", "last_seen": 11},
                ]
            return [{"peer_id": "peer-1", "address": "tcp://127.0.0.1:9702", "last_seen": 20}]

        with patch("gateway.client.discover_peers", side_effect=fake_discover):
            peers = discover_peers_from_pools(
                ["http://127.0.0.1:9800/pool-a", "http://127.0.0.1:9801/pool-b"],
                channel=DEFAULT_CHANNEL,
                timeout=7.0,
            )

        self.assertEqual([peer["peer_id"] for peer in peers], ["peer-1", "peer-2"])
        self.assertEqual(peers[0]["address"], "tcp://127.0.0.1:9702")
        self.assertEqual(peers[0]["pool_url"], "http://127.0.0.1:9801/pool-b")
        self.assertLessEqual(observed_timeouts[1], observed_timeouts[0])

    def test_join_provider_pools_registers_with_each_pool(self) -> None:
        joined: list[str] = []

        def fake_join_pool(pool_url: str, peer: dict[str, Any], ttl_seconds: int, capacity: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
            joined.append(pool_url)
            self.assertEqual(peer["audience"], pool_url)
            return {"ok": True, "pool_url": pool_url}

        with patch("gateway.client.join_pool", side_effect=fake_join_pool):
            results = join_provider_pools(
                ["http://pool-a", "http://pool-b"],
                peer_factory=lambda pool_url: {"peer_id": "peer-a", "audience": pool_url},
                ttl_seconds=30,
                capacity={"max_concurrency": 2},
            )

        self.assertEqual(joined, ["http://pool-a", "http://pool-b"])
        self.assertEqual([item["pool_url"] for item in results], ["http://pool-a", "http://pool-b"])

    def test_pool_heartbeat_calls_success_callback_after_successful_response(self) -> None:
        response = {"ok": True, "peer": {"peer_id": "peer-a"}}
        observed: list[tuple[str, dict[str, Any]]] = []
        success_seen = threading.Event()

        def on_success(pool_url: str, result: dict[str, Any]) -> None:
            observed.append((pool_url, result))
            success_seen.set()

        with patch("gateway.pool.heartbeat_pool", return_value=response):
            worker = start_pool_heartbeat(
                "https://bridge.example",
                peer_factory=lambda: {"peer_id": "peer-a"},
                on_success=on_success,
            )
            try:
                self.assertTrue(success_seen.wait(1.0))
            finally:
                worker.stop()

        self.assertIs(worker.on_success, on_success)
        self.assertEqual(observed, [("https://bridge.example", response)])

    def test_pool_heartbeat_keeps_running_when_success_callback_raises(self) -> None:
        response = {"ok": True, "peer": {"peer_id": "peer-a"}}
        callback_attempts: list[tuple[str, dict[str, Any]]] = []
        callback_error_seen = threading.Event()
        next_success_seen = threading.Event()

        def on_success(pool_url: str, result: dict[str, Any]) -> None:
            callback_attempts.append((pool_url, result))
            if len(callback_attempts) == 1:
                callback_error_seen.set()
                raise RuntimeError("callback failed")
            next_success_seen.set()

        with patch("gateway.pool.heartbeat_pool", return_value=response):
            worker = start_pool_heartbeat(
                "https://bridge.example",
                peer_factory=lambda: {"peer_id": "peer-a"},
                interval_seconds=0.01,
                on_success=on_success,
            )
            try:
                self.assertTrue(callback_error_seen.wait(1.0))
                self.assertTrue(next_success_seen.wait(2.5))
                self.assertTrue(worker.thread.is_alive())
            finally:
                worker.stop()

        self.assertEqual(
            callback_attempts,
            [
                ("https://bridge.example", response),
                ("https://bridge.example", response),
            ],
        )

    def test_pool_heartbeat_recovers_after_error_without_false_success(self) -> None:
        response = {"ok": True, "peer": {"peer_id": "peer-a"}}
        attempts: list[int] = []
        errors: list[str] = []
        successes: list[tuple[str, dict[str, Any]]] = []
        error_seen = threading.Event()
        success_seen = threading.Event()
        allow_success = threading.Event()

        def fake_heartbeat(**_: Any) -> dict[str, Any]:
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("temporary Bridge failure")
            allow_success.wait(1.0)
            return response

        def on_error(exc: Exception) -> None:
            errors.append(str(exc))
            error_seen.set()

        def on_success(pool_url: str, result: dict[str, Any]) -> None:
            successes.append((pool_url, result))
            success_seen.set()

        with patch("gateway.pool.heartbeat_pool", side_effect=fake_heartbeat):
            worker = start_pool_heartbeat(
                "https://bridge.example",
                peer_factory=lambda: {"peer_id": "peer-a"},
                interval_seconds=0.01,
                on_error=on_error,
                on_success=on_success,
            )
            try:
                self.assertTrue(error_seen.wait(1.0))
                self.assertFalse(success_seen.is_set())
                allow_success.set()
                self.assertTrue(success_seen.wait(2.5))
                self.assertTrue(worker.thread.is_alive())
            finally:
                worker.stop()

        self.assertEqual(errors, ["temporary Bridge failure"])
        self.assertEqual(successes, [("https://bridge.example", response)])
        self.assertGreaterEqual(len(attempts), 2)

    def test_build_bridge_usage_records_pool_and_relay_contribution(self) -> None:
        usage = build_bridge_usage(
            "relay://127.0.0.1:9900/provider-a",
            "http://pool-a",
            {"pool_amount": "0.000120", "relay_amount": "0.000180"},
        )

        self.assertEqual(
            usage,
            [
                {"bridge_id": "http://pool-a", "type": "pool", "units": 1, "amount": "0.000120"},
                {"bridge_id": "127.0.0.1:9900", "type": "relay", "units": 1, "amount": "0.000180"},
            ],
        )

    def test_pool_infer_tries_next_peer_when_first_fails(self) -> None:
        peers = [
            {
                "peer_id": "bad-peer",
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
            },
            {
                "peer_id": "good-peer",
                "address": "tcp://127.0.0.1:9701",
                "channel": DEFAULT_CHANNEL,
            },
        ]
        sent: list[tuple[str, dict[str, Any]]] = []

        def fake_send_message(peer: Any, message: dict[str, Any], timeout: float) -> dict[str, Any]:
            sent.append((peer.value, message))
            if peer.port == 9700:
                raise P2PError("first peer failed")
            return {"ok": True, "request_id": message["request_id"], "output_text": "ok from pool"}

        args = argparse.Namespace(
            pool="http://127.0.0.1:9800",
            channel=DEFAULT_CHANNEL,
            model="gpt-5.5",
            endpoint="responses",
            timeout=180.0,
            raw=False,
            price=False,
            receipt=False,
            consumer="consumer-a",
            ledger="unused",
            no_ledger=True,
            input="Say OK",
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), patch("gateway.client.discover_peers", return_value=peers), patch(
            "gateway.client.send_message",
            side_effect=fake_send_message,
        ):
            result = _cmd_pool_infer(args)

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue().strip(), "ok from pool")
        self.assertEqual([item[0] for item in sent], ["127.0.0.1:9700", "127.0.0.1:9701"])
        self.assertEqual(sent[1][1]["metadata"]["selected_peer_id"], "good-peer")

    def test_pool_infer_uses_relay_address(self) -> None:
        peers = [
            {
                "peer_id": "relay-peer",
                "addresses": ["relay://127.0.0.1:9900/relay-peer"],
                "channel": DEFAULT_CHANNEL,
            }
        ]
        sent: list[tuple[str, dict[str, Any]]] = []

        def fake_send_relay_message(address: Any, message: dict[str, Any], timeout: float) -> dict[str, Any]:
            sent.append((address.value, message))
            return {"ok": True, "request_id": message["request_id"], "output_text": "ok through relay"}

        args = argparse.Namespace(
            pool="http://127.0.0.1:9800",
            channel=DEFAULT_CHANNEL,
            model="gpt-5.5",
            endpoint="responses",
            timeout=180.0,
            raw=False,
            price=False,
            receipt=False,
            consumer="consumer-a",
            ledger="unused",
            no_ledger=True,
            input="Say OK",
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), patch("gateway.client.discover_peers", return_value=peers), patch(
            "gateway.client.send_relay_message",
            side_effect=fake_send_relay_message,
        ):
            result = _cmd_pool_infer(args)

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue().strip(), "ok through relay")
        self.assertEqual(sent[0][0], "relay://127.0.0.1:9900/relay-peer")
        self.assertEqual(sent[0][1]["metadata"]["selected_address"], "relay://127.0.0.1:9900/relay-peer")

    def test_pool_infer_writes_pricing_receipt(self) -> None:
        peers = [
            {
                "peer_id": "good-peer",
                "address": "tcp://127.0.0.1:9701",
                "channel": DEFAULT_CHANNEL,
                "pool_url": "http://127.0.0.1:9801",
            }
        ]

        sent_request_ids: list[str] = []

        def fake_send_message(peer: Any, message: dict[str, Any], timeout: float) -> dict[str, Any]:
            sent_request_ids.append(str(message["request_id"]))
            return {
                "ok": True,
                "request_id": message["request_id"],
                "output_text": "priced ok",
                "usage": {"input_tokens": 1000, "output_tokens": 500},
            }

        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "receipts.jsonl"
            args = argparse.Namespace(
                pool="http://127.0.0.1:9800",
                channel=DEFAULT_CHANNEL,
                model="gpt-5.5",
                endpoint="responses",
                timeout=180.0,
                raw=False,
                price=False,
                receipt=False,
                consumer="consumer-a",
                ledger=str(ledger),
                no_ledger=False,
                input="Say OK",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), patch("gateway.client.discover_peers", return_value=peers), patch(
                "gateway.client.send_message",
                side_effect=fake_send_message,
            ):
                result = _cmd_pool_infer(args)

            payload = json.loads(ledger.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue().strip(), "priced ok")
        self.assertEqual(payload["job_id"], sent_request_ids[0])
        self.assertEqual(payload["consumer_id"], "consumer-a")
        self.assertEqual(payload["pool_url"], "http://127.0.0.1:9801")
        self.assertEqual(
            payload["bridge_usage"],
            [{"bridge_id": "http://127.0.0.1:9801", "type": "pool", "units": 1, "amount": "0.000060"}],
        )
        self.assertEqual(payload["pricing"]["gross_fee"], "0.003000")
        self.assertEqual(payload["pricing"]["provider_amount"], "0.002550")


if __name__ == "__main__":
    unittest.main()
