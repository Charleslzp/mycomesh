"""Under load a busy Provider is refused before any chain read, so Consumers fail over at once."""
from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from mycomesh.consumer import prepare_request
from mycomesh.evm import address_of
from mycomesh.identity import create_identity
from mycomesh.protocol import Prices
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore, RelayError
from tests.mycomesh_anvil import CONSUMER_KEY, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class LoadAnvilTest(unittest.TestCase):
    def test_busy_provider_is_refused_at_once_and_freed_after(self) -> None:
        chain = AnvilV11()
        self.addCleanup(chain.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        release = threading.Event()

        def slow(document):
            release.wait(20)
            return {"output_text": "done"}, 10, 2

        worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=chain.deployment,
                                backend=slow, prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",),
                                data_dir=Path(tmp.name) / "provider")
        relay = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, Path(tmp.name) / "relay")
        now = chain.now()
        relay.register_provider(worker.descriptor(now), lambda job: worker.handle_job(job, now=chain.now()), now=now)

        def payload():
            return prepare_request(descriptor=relay.provider_descriptors()[0], deployment=chain.deployment,
                                   key_private=CONSUMER_KEY, relay_signer=address_of(RELAY_SIGNER), endpoint="responses",
                                   model="gpt-5.5", content="hi", max_output_tokens=10, max_fee=1_000_000, now=chain.now()).payload

        first = threading.Thread(target=lambda: relay.handle_request(payload()))
        first.start()
        deadline = time.monotonic() + 10
        while relay.providers[address_of(PROVIDER_SIGNER)].in_flight == 0 and time.monotonic() < deadline:
            time.sleep(0.02)
        started = time.monotonic()
        with self.assertRaises(RelayError) as busy:
            relay.handle_request(payload())
        self.assertEqual((busy.exception.status, busy.exception.dispatched), (503, False))
        self.assertLess(time.monotonic() - started, 0.5)  # no chain reads, no round trip to the Provider
        release.set()
        first.join(20)
        self.assertEqual(relay.providers[address_of(PROVIDER_SIGNER)].in_flight, 0)
        self.assertEqual(len(relay.handle_request(payload())["receipt"]["receipt"]["response_hash"]), 66)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class PricedMaxFeeAnvilTest(unittest.TestCase):
    def test_provider_refuses_work_its_authorization_cannot_pay_for(self) -> None:
        chain = AnvilV11()
        self.addCleanup(chain.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ran = []

        class Backend:
            input_overhead_tokens = 7_000  # like Codex

            def __call__(self, document):
                ran.append(document)
                return {"output_text": "ok"}, 7_010, 5

        worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=chain.deployment,
                                backend=Backend(), prices=Prices(1_000, 4_000, 100), models=("gpt-5.5",),
                                data_dir=Path(tmp.name) / "provider")
        self.assertEqual(worker.descriptor()["input_overhead_tokens"], 7_000)
        relay = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, Path(tmp.name) / "relay")
        now = chain.now()
        relay.register_provider(worker.descriptor(now), lambda job: worker.handle_job(job, now=chain.now()), now=now)

        def send(max_fee: int):
            prepared = prepare_request(descriptor=relay.provider_descriptors()[0], deployment=chain.deployment,
                                       key_private=CONSUMER_KEY, relay_signer=address_of(RELAY_SIGNER), endpoint="responses",
                                       model="gpt-5.5", content="hi", max_output_tokens=100, max_fee=max_fee, now=chain.now())
            return relay.handle_request(prepared.payload)

        # Worst case: (7_000 overhead + 2) input x 1 + 100 output x 4 = 7_402: 7_000 cannot pay for it.
        with self.assertRaises(RelayError) as refused:
            send(7_000)
        self.assertEqual((refused.exception.status, refused.exception.dispatched), (502, False))
        self.assertIn("worst-case price 7402", str(refused.exception))
        self.assertEqual(ran, [])  # refused before the model ran
        receipt = send(7_402)["receipt"]["receipt"]
        self.assertEqual(receipt["actual_fee"], 7_030)  # 7_010 x 1 + 5 x 4
