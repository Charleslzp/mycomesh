"""Network pricing end to end: the chain's price is the only price, capacity binds, and the day's utilisation moves it."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mycomesh import rpc
from mycomesh.consumer import prepare_request
from mycomesh.evm import address_of, encode_call
from mycomesh.identity import create_identity
from mycomesh.pricing import EPOCH, NetworkPricing
from mycomesh.protocol import Prices
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore, RelayError
from tests.mycomesh_anvil import CONSUMER_KEY, PROVIDER_SIGNER, RELAY_SIGNER, TIER_ABI, AnvilV11, available

TIER = 2


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class PricingAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        # Base 1_000 / 4_000 per 1k tokens, minimum 100, new Providers capped at 5_000 work a day, target 70%.
        chain.send(chain.admin, chain.registry, encode_call("setTier(uint32,(uint128,uint128,uint128,uint128,uint16,bool))",
                                                            ["uint32", TIER_ABI], [TIER, [1_000, 4_000, 100, 5_000, 7_000, True]]))
        chain.price_signer(chain.provider, address_of(PROVIDER_SIGNER), tier=TIER, declared=1_000_000)
        cls.pricing = NetworkPricing(chain.rpc, chain.registry)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.chain.close()
        cls.tmp.cleanup()

    def setUp(self) -> None:
        tmp = Path(self.tmp.name)
        # Every request costs 1_000 input and 500 output tokens: 3_000 units of work at base prices.
        self.worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER,
                                     deployment=self.chain.deployment, backend=lambda document: ({"output_text": "ok"}, 1_000, 500),
                                     prices=Prices(1, 1, 1), models=("gpt-5.5",), data_dir=tmp / f"provider-{self.id()}",
                                     pricing=self.pricing, tier=TIER)
        self.relay = RelayCore(self.chain.deployment, RELAY_SIGNER, self.chain.reader, tmp / f"relay-{self.id()}", self.pricing)
        now = self.chain.now()
        self.relay.register_provider(self.worker.descriptor(now), lambda job: self.worker.handle_job(job, now=self.chain.now()), now=now)

    def _request(self, max_fee: int) -> dict:
        now = self.chain.now()
        prepared = prepare_request(descriptor=self.relay.provider_descriptors()[0], deployment=self.chain.deployment,
                                   key_private=CONSUMER_KEY, relay_signer=address_of(RELAY_SIGNER), endpoint="responses",
                                   model="gpt-5.5", content="price me", max_output_tokens=500, max_fee=max_fee, now=now)
        return self.relay.handle_request(prepared.payload, now=now)

    def _settle(self) -> None:
        self.assertTrue(self.relay.settle_queued(self.chain.relay, self.chain.rpc))

    def test_1_price_capacity_and_enforcement_on_day_one(self) -> None:
        self.assertEqual(self.worker.descriptor()["prices"], {"input_per_1k": 1_000, "output_per_1k": 4_000, "minimum_fee": 100})
        self.assertEqual(self.pricing.remaining_capacity(address_of(PROVIDER_SIGNER)), 5_000)  # proven nothing yet
        result = self._request(max_fee=3_000)
        self.assertEqual(result["receipt"]["receipt"]["actual_fee"], 3_000)
        self._settle()
        self.assertEqual(self.pricing.remaining_capacity(address_of(PROVIDER_SIGNER)), 2_000)
        with self.assertRaises(RelayError) as refused:
            self._request(max_fee=3_000)  # would exceed today's capacity: refused before any work
        self.assertEqual((refused.exception.status, refused.exception.dispatched), (503, False))
        self.worker.pricing = None  # a Provider quoting its own price is caught at the Relay
        with self.assertRaises(RelayError) as undercut:
            self._request(max_fee=1_000)
        self.assertIn("network price", str(undercut.exception))

    def test_2_next_day_price_follows_utilisation(self) -> None:
        now = self.chain.now()
        self.chain.advance((now // EPOCH + 1) * EPOCH + 60 - now)
        day = self.chain.now() // EPOCH
        # Yesterday: 3_000 of 5_000 capacity = 60% against a 70% target: 6000/7000 = -14%, capped at -10% a day.
        self.assertEqual(self.pricing.multiplier(TIER, day), 900_000)
        self.assertEqual(self.worker.descriptor(self.chain.now())["prices"]["output_per_1k"], 3_600)
        # Capacity grew with proven work: twice yesterday's 3_000, above the 5_000 base.
        self.assertEqual(self.pricing.remaining_capacity(address_of(PROVIDER_SIGNER)), 6_000)
        result = self._request(max_fee=5_000)  # the Relay reserves up to maxFee against the capacity left
        self.assertEqual(result["receipt"]["receipt"]["actual_fee"], 2_700)  # 3_000 x 0.9
        self._settle()  # the chain agrees: settlement enforces exactly this price
        market = self.pricing.market(TIER)
        self.assertEqual((market["today"]["demand"], market["multiplier"]), (3_000, 900_000))


if __name__ == "__main__":
    unittest.main()
