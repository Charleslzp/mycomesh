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

    def test_local_config_fallback(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            snapshot = channel_pricing_snapshot(DEFAULT_PRICING, DEFAULT_CHANNEL)

        self.assertEqual(snapshot.pricing_hash, DEFAULT_PRICING[DEFAULT_CHANNEL].config_hash())
        self.assertEqual(snapshot.source, "local")

    def test_strict_chain_pricing_rejects_local_and_default_fallback(self) -> None:
        with patch.dict(os.environ, {"MYCOMESH_STRICT_CHAIN_PRICING": "1"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "chain pricing"):
                channel_pricing_snapshot(DEFAULT_PRICING, DEFAULT_CHANNEL)


if __name__ == "__main__":
    unittest.main()
