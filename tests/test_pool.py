from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from gateway.client import _cmd_pool_infer, _provider_profile_preflight, discover_peers_from_pools
from gateway.identity import create_identity, sign_document
from gateway.p2p import DEFAULT_CHANNEL, P2PError
from gateway.pool import (
    NETWORK_PROFILE_LOCAL,
    NETWORK_PROFILE_OPEN,
    NETWORK_PROFILE_TESTNET,
    POOL_LEAVE_PURPOSE,
    POOL_REGISTRATION_PURPOSE,
    POOL_REPUTATION_PURPOSE,
    PoolConfig,
    list_live_peers,
    load_pool_reputation,
    pool_health_payload,
    record_peer_reputation,
    register_peer,
    remove_peer,
    save_pool_reputation,
    validate_pool_launch_config,
    verify_leave_descriptor,
    verify_peer_addresses,
    verify_reputation_feedback,
)


class PoolDirectoryTest(unittest.TestCase):
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
        with patch("gateway.pool.send_message", return_value={"peer": {"peer_id": "peer-a"}}):
            verify_peer_addresses("peer-a", ["tcp://127.0.0.1:9700"])

        with patch("gateway.pool.send_message", return_value={"peer": {"peer_id": "peer-b"}}):
            with self.assertRaisesRegex(Exception, "different peer_id"):
                verify_peer_addresses("peer-a", ["tcp://127.0.0.1:9700"])

    def test_testnet_launch_requires_allowlists_and_direct_verification(self) -> None:
        provider = create_identity()
        reputation_signer = create_identity()
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            authorized_provider_public_keys={provider.public_key},
            authorized_reputation_signers={reputation_signer.public_key},
        )

        validate_pool_launch_config(config)

        with self.assertRaisesRegex(Exception, "provider-public-key"):
            validate_pool_launch_config(
                PoolConfig(
                    network_profile=NETWORK_PROFILE_TESTNET,
                    authorized_reputation_signers={reputation_signer.public_key},
                )
            )
        with self.assertRaisesRegex(Exception, "reputation-signer-public-key"):
            validate_pool_launch_config(
                PoolConfig(
                    network_profile=NETWORK_PROFILE_TESTNET,
                    authorized_provider_public_keys={provider.public_key},
                )
            )
        with self.assertRaisesRegex(Exception, "direct address verification"):
            validate_pool_launch_config(
                PoolConfig(
                    network_profile=NETWORK_PROFILE_TESTNET,
                    verify_direct_addresses=False,
                    authorized_provider_public_keys={provider.public_key},
                    authorized_reputation_signers={reputation_signer.public_key},
                )
            )

    def test_open_profile_is_reserved_until_disputes_and_staking_exist(self) -> None:
        with self.assertRaisesRegex(Exception, "reserved"):
            validate_pool_launch_config(PoolConfig(network_profile=NETWORK_PROFILE_OPEN))

    def test_testnet_registers_only_authorized_providers_with_payment_address(self) -> None:
        identity = create_identity()
        config = PoolConfig(
            network_profile=NETWORK_PROFILE_TESTNET,
            public_url="http://pool.local",
            authorized_provider_public_keys={identity.public_key},
            authorized_reputation_signers={create_identity().public_key},
        )
        peer = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "address": "tcp://127.0.0.1:9700",
                "channel": DEFAULT_CHANNEL,
                "payment_address": "0x00000000000000000000000000000000000000A2",
            },
            identity.private_key,
            purpose=POOL_REGISTRATION_PURPOSE,
            audience="http://pool.local",
        )

        with patch("gateway.pool.send_message", return_value={"peer": {"peer_id": identity.peer_id}}):
            registered = register_peer(config, peer=peer, ttl_seconds=30, now=100)

        self.assertEqual(registered["peer_id"], identity.peer_id)
        self.assertEqual(registered["payment_address"], "0x00000000000000000000000000000000000000a2")

        unauthorized = create_identity()
        unauthorized_peer = sign_document(
            {
                "peer_id": unauthorized.peer_id,
                "public_key": unauthorized.public_key,
                "address": "tcp://127.0.0.1:9701",
                "channel": DEFAULT_CHANNEL,
                "payment_address": "0x00000000000000000000000000000000000000A3",
            },
            unauthorized.private_key,
            purpose=POOL_REGISTRATION_PURPOSE,
            audience="http://pool.local",
        )
        missing_payment_peer = sign_document(
            {
                "peer_id": identity.peer_id,
                "public_key": identity.public_key,
                "address": "tcp://127.0.0.1:9702",
                "channel": DEFAULT_CHANNEL,
            },
            identity.private_key,
            purpose=POOL_REGISTRATION_PURPOSE,
            audience="http://pool.local",
        )

        with self.assertRaisesRegex(Exception, "not authorized"):
            register_peer(config, peer=unauthorized_peer, ttl_seconds=30)
        with self.assertRaisesRegex(Exception, "payment_address"):
            register_peer(config, peer=missing_payment_peer, ttl_seconds=30)
        config.verify_direct_addresses = False
        with self.assertRaisesRegex(Exception, "direct address verification"):
            register_peer(config, peer=peer, ttl_seconds=30)


class PoolCliTest(unittest.TestCase):
    def test_provider_profile_preflight_keeps_testnet_strict(self) -> None:
        args = argparse.Namespace(
            network_profile=NETWORK_PROFILE_TESTNET,
            allow_unsigned_requests=False,
            allow_unreserved_requests=False,
            allow_any_signed_consumer=False,
            consumer_public_key=["consumer-key"],
            payment_address="0x00000000000000000000000000000000000000a1",
            pricing_hash="0x" + "1" * 64,
            pricing_config=None,
        )

        self.assertIsNone(_provider_profile_preflight(args))
        args.consumer_public_key = []
        self.assertIn("consumer-public-key", _provider_profile_preflight(args) or "")
        args.consumer_public_key = ["consumer-key"]
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
        def fake_discover(pool_url: str, channel: str | None = None, timeout: float = 5.0) -> list[dict[str, Any]]:
            self.assertEqual(channel, DEFAULT_CHANNEL)
            self.assertEqual(timeout, 7.0)
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
            return {"ok": True, "output_text": "ok from pool"}

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
            return {"ok": True, "output_text": "ok through relay"}

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
            }
        ]

        def fake_send_message(peer: Any, message: dict[str, Any], timeout: float) -> dict[str, Any]:
            return {
                "ok": True,
                "request_id": "job-1",
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
        self.assertEqual(payload["job_id"], "job-1")
        self.assertEqual(payload["consumer_id"], "consumer-a")
        self.assertEqual(payload["pricing"]["gross_fee"], "0.003000")
        self.assertEqual(payload["pricing"]["provider_amount"], "0.002550")


if __name__ == "__main__":
    unittest.main()
