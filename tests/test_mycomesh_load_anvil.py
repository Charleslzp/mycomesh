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
