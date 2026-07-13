from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from gateway.p2p import DEFAULT_CHANNEL
from gateway.pricing import DEFAULT_PRICING
from gateway.pricing_source import channel_pricing_snapshot


class PricingSourceTest(unittest.TestCase):
    def test_override_takes_precedence(self) -> None:
        snapshot = channel_pricing_snapshot(
            DEFAULT_PRICING,
            DEFAULT_CHANNEL,
            override="0x" + "a" * 64,
        )

        self.assertEqual(snapshot.pricing_hash, "0x" + "a" * 64)
        self.assertEqual(snapshot.source, "override")
        self.assertEqual(snapshot.settlement_version, 2)

    def test_local_config_fallback(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            snapshot = channel_pricing_snapshot(DEFAULT_PRICING, DEFAULT_CHANNEL)

        self.assertEqual(snapshot.pricing_hash, DEFAULT_PRICING[DEFAULT_CHANNEL].config_hash())
        self.assertEqual(snapshot.source, "local")

    def test_strict_chain_pricing_rejects_local_and_default_fallback(self) -> None:
        with patch.dict(os.environ, {"MYCOMESH_STRICT_CHAIN_PRICING": "1"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "chain pricing"):
                channel_pricing_snapshot(DEFAULT_PRICING, DEFAULT_CHANNEL)

    def test_nonlocal_profile_defaults_to_strict_chain_pricing(self) -> None:
        with patch.dict(os.environ, {"MYCOMESH_NETWORK_PROFILE": "mainnet"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "chain pricing"):
                channel_pricing_snapshot(DEFAULT_PRICING, DEFAULT_CHANNEL)

    def test_v3_override_requires_pricing_version(self) -> None:
        with patch.dict(os.environ, {"MYCOMESH_SETTLEMENT_VERSION": "3"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "requires MYCOMESH_PRICING_VERSION"):
                channel_pricing_snapshot(DEFAULT_PRICING, DEFAULT_CHANNEL, override="0x" + "a" * 64)

    def test_v3_reads_latest_version_and_versioned_hash(self) -> None:
        calls: list[tuple[str, list[str], object]] = []

        def fake_call(_rpc: str, _settlement: str, signature: str, args: list[str], **kwargs: object) -> str:
            calls.append((signature, args, kwargs.get("block_tag")))
            if signature == "latestChannelVersion(bytes32)":
                return "0x" + (7).to_bytes(32, "big").hex()
            return "0x" + "b" * 64

        environment = {
            "MYCOMESH_SETTLEMENT_VERSION": "3",
            "MYCOMESH_PRICING_RPC_URL": "http://rpc.invalid",
            "MYCO_SETTLEMENT": "0x0000000000000000000000000000000000000001",
        }
        with patch.dict(os.environ, environment, clear=True), patch("gateway.chain.call_contract", side_effect=fake_call):
            snapshot = channel_pricing_snapshot(DEFAULT_PRICING, DEFAULT_CHANNEL, block_tag=94)

        self.assertEqual(snapshot.pricing_hash, "0x" + "b" * 64)
        self.assertEqual(snapshot.pricing_version, 7)
        self.assertEqual(snapshot.settlement_version, 3)
        self.assertEqual(calls[0][0], "latestChannelVersion(bytes32)")
        self.assertEqual(calls[1][0], "channelPricingHash(bytes32,uint64)")
        self.assertEqual(calls[1][1][1], "7")
        self.assertEqual(calls[0][2], 94)
        self.assertEqual(calls[1][2], 94)


if __name__ == "__main__":
    unittest.main()
