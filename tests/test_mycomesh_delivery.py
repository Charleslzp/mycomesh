"""A Relay settles a receipt with its delivery signature once the settlement requires one (v10), and with the
dispatch signature it carries before that: Relays and the contract can be upgraded in either order."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mycomesh import rpc
from mycomesh.evm import address_of
from mycomesh.relay.core import RelayCore
from mycomesh.settlement import (
    Authorization, Deployment, SettlementError, SignedReceipt, build_receipt, request_id_for, sign_authorization,
    sign_dispatch, sign_receipt,
)

CONSUMER_KEY, PROVIDER_SIGNER, RELAY_SIGNER = "0x" + "11" * 32, "0x" + "22" * 32, "0x" + "33" * 32
DEPLOYMENT = Deployment(chain_id=31337, settlement="0x" + "44" * 20)


class Reader:
    def __init__(self, requires: bool) -> None:
        self.requires, self.asked = requires, 0

    def requires_delivery(self) -> bool:
        self.asked += 1
        return self.requires


def signed() -> SignedReceipt:
    key = address_of(CONSUMER_KEY)
    authorization = Authorization(
        request_id=request_id_for(key, "0x" + "01" * 32), request_hash="0x" + "02" * 32, key=key,
        provider_signer=address_of(PROVIDER_SIGNER), relay_signer=address_of(RELAY_SIGNER), max_fee=1_000,
        issued_at=1_000, execute_by=1_060, deadline=8_000)
    receipt = build_receipt(authorization, response_hash="0x" + "ab" * 32, input_tokens=1, output_tokens=2, actual_fee=900)
    return SignedReceipt(authorization, receipt, sign_authorization(CONSUMER_KEY, authorization, DEPLOYMENT),
                         sign_receipt(PROVIDER_SIGNER, authorization, receipt, DEPLOYMENT),
                         sign_dispatch(RELAY_SIGNER, authorization, DEPLOYMENT))


class DeliveryTest(unittest.TestCase):
    def core(self, reader: Reader) -> RelayCore:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return RelayCore(DEPLOYMENT, RELAY_SIGNER, reader, Path(tmp.name))

    def test_settles_with_the_signature_the_contract_requires(self) -> None:
        receipt = signed()
        before = self.core(Reader(False))._for_settlement(receipt)
        self.assertEqual(before, receipt)  # an older settlement checks the dispatch
        after = self.core(Reader(True))._for_settlement(receipt)
        after.verify(DEPLOYMENT, delivered=True)
        with self.assertRaises(SettlementError):
            receipt.verify(DEPLOYMENT, delivered=True)  # what the Provider holds is not a delivery
        self.assertEqual(after.relay_signature, receipt.delivered(RELAY_SIGNER, DEPLOYMENT).relay_signature)

    def test_asks_once_then_again_after_a_failed_batch(self) -> None:
        reader = Reader(False)
        core = self.core(reader)
        for _ in range(3):
            core._for_settlement(signed())
        self.assertEqual(reader.asked, 1)
        reader.requires = True  # the contract is upgraded; the next batch reverts and the Relay asks again
        core.queue.add(signed(), owner="0x" + "55" * 20, provider="0x" + "66" * 20)
        sent: list[str] = []

        def submit(_private: str, _rpc: str, data: str) -> None:
            sent.append(data)
            if len(sent) == 1:
                raise rpc.RpcError("execution reverted")
        core._submit = submit
        self.assertEqual(len(core.settle_queued(RELAY_SIGNER, "http://unused")), 1)
        self.assertEqual(reader.asked, 2)
        self.assertNotEqual(sent[0], sent[1])  # the retry carried the delivery signature


if __name__ == "__main__":
    unittest.main()
