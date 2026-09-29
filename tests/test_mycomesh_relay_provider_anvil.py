"""Relay-blind V11 request loop on anvil: Consumer -> Relay -> Provider -> settlement."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mycomesh.consumer import open_response, prepare_request
from mycomesh.evm import address_of
from mycomesh.identity import create_identity
from mycomesh.protocol import Prices
from mycomesh.provider.worker import JobRejected, ProviderWorker
from mycomesh.relay.core import RelayCore, RelayError
from tests.mycomesh_anvil import CONSUMER_KEY, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

SECRET_PROMPT = "the-private-prompt-7f3a91 needs no Relay to read it"


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class RelayProviderAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = AnvilV11()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.chain.close()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls: list[dict] = []

        def backend(document: dict) -> tuple[dict, int, int]:
            self.calls.append(document)
            return {"text": "answer to: " + json.dumps(document["input"])}, 1_000, 500

        self.worker = ProviderWorker(
            identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=self.chain.deployment,
            backend=backend, prices=Prices(input_per_1k=1_000, output_per_1k=4_000, minimum_fee=100),
            models=("gpt-5.5",), data_dir=Path(self.tmp.name) / "provider",
        )
        self.relay = RelayCore(self.chain.deployment, RELAY_SIGNER, self.chain.reader, Path(self.tmp.name) / "relay")
        now = self.chain.now()
        self.relay.register_provider(self.worker.descriptor(now), self.worker.handle_job, now=now)

    def _prepare(self, prompt: str = SECRET_PROMPT, max_fee: int = 5_000_000):
        now = self.chain.now()
        return prepare_request(
            descriptor=self.relay.provider_descriptors()[0], deployment=self.chain.deployment,
            key_private=CONSUMER_KEY, relay_signer=address_of(RELAY_SIGNER), endpoint="responses",
            model="gpt-5.5", content=prompt, max_output_tokens=2_000, max_fee=max_fee, now=now,
        ), now

    def test_relay_blind_request_is_executed_verified_and_settled(self) -> None:
        owner = address_of(self.chain.consumer)
        before = self.chain.reader.available_balance(owner)
        prepared, now = self._prepare()
        result = self.relay.handle_request(prepared.payload, now=now)
        # The Relay saw only ciphertext: the prompt is in no request, result or database byte.
        for blob in (json.dumps(prepared.payload), json.dumps(result),
                     (Path(self.tmp.name) / "relay/relay-settlement.sqlite3").read_bytes().decode("latin-1")):
            self.assertNotIn("the-private-prompt-7f3a91", blob)
        response, signed = open_response(prepared, result, self.chain.deployment, now=now)
        self.assertIn("the-private-prompt-7f3a91", response["output"]["text"])
        # 1000 input * 1000/1k + 500 output * 4000/1k = 3000 base units.
        self.assertEqual(signed.receipt.actual_fee, 3_000)
        settled = self.relay.settle_queued(self.chain.relay, self.chain.rpc)
        self.assertEqual(settled, [prepared.authorization.settlement_key])
        self.assertEqual(self.chain.reader.available_balance(owner), before - 3_000)

    def test_duplicate_delivery_never_executes_twice(self) -> None:
        prepared, now = self._prepare("duplicate delivery")
        first = self.relay.handle_request(prepared.payload, now=now)
        second = self.relay.handle_request(prepared.payload, now=now)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(first["receipt"], second["receipt"])
        self.assertEqual(self.relay.queue.counts().get("queued"), 1)

    def test_provider_refuses_content_or_reply_key_substituted_by_the_relay(self) -> None:
        prepared, now = self._prepare("original")
        other, _ = self._prepare("substituted")
        swapped = dict(prepared.payload, sealed_request=other.payload["sealed_request"])
        with self.assertRaises(RelayError):
            self.relay.handle_request(swapped, now=now)
        relay_reply = create_identity()
        from mycomesh.secure_transport import generate_transport_key
        stolen = dict(prepared.payload, reply_transport_key=generate_transport_key(relay_reply).binding)
        with self.assertRaises(RelayError):
            self.relay.handle_request(stolen, now=now)
        self.assertEqual(self.calls, [])
        with self.assertRaises(JobRejected):
            self.worker.handle_job(dict(stolen, relay_signature="0x" + "00" * 65), now=now)

    def test_admission_rejects_unbound_providers_and_uncovered_fees(self) -> None:
        stranger = ProviderWorker(
            identity=create_identity(), provider_private="0x" + "44" * 32, deployment=self.chain.deployment,
            backend=lambda document: ({}, 1, 1), prices=Prices(1, 1, 1), models=("gpt-5.5",),
            data_dir=Path(self.tmp.name) / "stranger",
        )
        with self.assertRaises(RelayError):
            self.relay.register_provider(stranger.descriptor(self.chain.now()), stranger.handle_job, now=self.chain.now())
        # Key grant caps a request at 10 USDC.
        prepared, now = self._prepare("too expensive", max_fee=10_000_001)
        with self.assertRaises(RelayError) as caught:
            self.relay.handle_request(prepared.payload, now=now)
        self.assertEqual(caught.exception.status, 402)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
