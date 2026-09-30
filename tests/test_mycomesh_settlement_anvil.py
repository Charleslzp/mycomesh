"""Settle real V11 receipts, signed by mycomesh.settlement, on a local anvil chain."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import unittest
from pathlib import Path

from mycomesh import rpc
from mycomesh.evm import abi_encode, address_of, encode_call
from tests.mycomesh_anvil import TIER_ABI
from mycomesh.settlement import (
    Authorization, Deployment, SettlementError, SettlementReader, SignedReceipt, build_receipt,
    encode_release, encode_settle_batch, request_id_for, sign_authorization, sign_dispatch, sign_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
ANVIL = shutil.which("anvil") or str(Path.home() / ".foundry/bin/anvil")
# anvil's deterministic development accounts.
ANVIL_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
]
CONSUMER_KEY = "0x" + "11" * 32
PROVIDER_SIGNER = "0x" + "22" * 32
RELAY_SIGNER = "0x" + "33" * 32
JUROR_SIGNERS = ["0x" + f"{0x40 + i:02x}" * 32 for i in range(3)]

PARAMS = [
    86_400, 172_800, 3_600, 100,        # dispute window, arbitration timeout, withdrawal delay, reporter bond
    1_000, 1_000, 7 * 86_400,           # relay bps, holdback bps, holdback period
    50_000_000, 1_000, 5_000_000_000,   # exposure base (50 USDC), growth bps, max
    10_000, 100_000_000, 5_000, 10,     # slash bps, slash cap, bounty bps, probe voids per day
]
PARAMS_ABI = ("tuple", ["uint64", "uint64", "uint64", "uint256", "uint16", "uint16", "uint64",
                        "uint256", "uint16", "uint256", "uint16", "uint256", "uint16", "uint16", "address"])
ELIGIBILITY_ABI = ("tuple", ["uint256", "uint64", "uint64", "uint64", "uint256"])


def _artifact(source: str, name: str) -> str:
    return json.loads((ROOT / "out" / source / f"{name}.json").read_text())["bytecode"]["object"]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(
    Path(ANVIL).exists() and (ROOT / "out/MycoSettlementV11.sol/MycoSettlementV11.json").exists(),
    "anvil and forge artifacts are required",
)
class MycomeshSettlementAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        port = _free_port()
        cls.anvil = subprocess.Popen(
            [ANVIL, "--port", str(port), "--chain-id", "31337", "--hardfork", "prague", "--silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.rpc = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                rpc.call(cls.rpc, "eth_chainId", [], timeout=1, attempts=1)
                break
            except rpc.RpcError:
                time.sleep(0.1)
        admin, cls.consumer, cls.provider, cls.relay = ANVIL_KEYS
        cls.token = cls._deploy(_artifact("TestUSDC.sol", "TestUSDC"))
        registry_impl = cls._deploy(_artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11"))
        registry_init = encode_call(
            "initialize(address,uint16,uint16,uint64,(uint256,uint64,uint64,uint64,uint256))",
            ["address", "uint16", "uint16", "uint64", ELIGIBILITY_ABI],
            [address_of(admin), 3, 2, 60, [1, 1, 0, 86_400, 1_000_000]],
        )
        cls.registry = cls._proxy(registry_impl, registry_init)
        settlement_impl = cls._deploy(_artifact("MycoSettlementV11.sol", "MycoSettlementV11"))
        settlement_init = encode_call(
            "initialize(address,address,address,(uint64,uint64,uint64,uint256,uint16,uint16,uint64,uint256,uint16,uint256,uint16,uint256,uint16,uint16,address))",
            ["address", "address", "address", PARAMS_ABI],
            [cls.token, cls.registry, address_of(admin), PARAMS + [address_of(admin)]],
        )
        cls.settlement = cls._proxy(settlement_impl, settlement_init)
        cls._send(admin, cls.registry, encode_call("bindSettlement(address)", ["address"], [cls.settlement]))
        cls.deployment = Deployment(31337, cls.settlement)
        cls.reader = SettlementReader(cls.rpc, cls.deployment)
        owner = address_of(cls.consumer)
        cls._send(admin, cls.token, encode_call("mint(address,uint256)", ["address", "uint256"], [owner, 1_000_000_000]))
        cls._send(cls.consumer, cls.token, encode_call("approve(address,uint256)", ["address", "uint256"], [cls.settlement, 2**255]))
        cls._send(cls.consumer, cls.settlement, encode_call("deposit(uint256)", ["uint256"], [500_000_000]))
        cls._send(cls.consumer, cls.settlement, encode_call(
            "registerKey(address,uint256,uint64)", ["address", "uint256", "uint64"], [address_of(CONSUMER_KEY), 10_000_000, 0]))
        cls._send(cls.provider, cls.settlement, encode_call("authorizeProviderSigner(address)", ["address"], [address_of(PROVIDER_SIGNER)]))
        # A tier whose minimum fee exceeds every test fee, so each receipt is priced at its Consumer cap.
        cls._send(admin, cls.registry, encode_call("setTier(uint32,(uint128,uint128,uint128,uint128,uint16,bool))",
                                                   ["uint32", TIER_ABI], [1, [1, 1, 10**12, 10**15, 7_000, True]]))
        cls._send(cls.provider, cls.registry, encode_call("setSignerTier(address,uint32,uint128)",
                                                          ["address", "uint32", "uint128"], [address_of(PROVIDER_SIGNER), 1, 10**15]))
        cls._send(cls.relay, cls.settlement, encode_call("authorizeRelaySigner(address)", ["address"], [address_of(RELAY_SIGNER)]))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.anvil.terminate()
        cls.anvil.wait(timeout=10)

    @classmethod
    def _send(cls, key: str, to: str | None, data: str | bytes) -> dict:
        tx = rpc.send_transaction(cls.rpc, key, to=to, data=data)
        return rpc.wait_for_receipt(cls.rpc, tx, timeout=30, poll=0.05)

    @classmethod
    def _deploy(cls, bytecode: str, constructor: bytes = b"") -> str:
        receipt = cls._send(ANVIL_KEYS[0], None, bytes.fromhex(bytecode[2:]) + constructor)
        return receipt["contractAddress"]

    @classmethod
    def _proxy(cls, implementation: str, init_data: str) -> str:
        constructor = abi_encode(["address", "bytes"], [implementation, init_data])
        return cls._deploy(_artifact("MycoUpgradeable.sol", "MycoERC1967Proxy"), constructor)

    def _now(self) -> int:
        return rpc.quantity(rpc.call(self.rpc, "eth_getBlockByNumber", ["latest", False])["timestamp"])

    def _signed(self, nonce: int, fee: int) -> SignedReceipt:
        now = self._now()
        key = address_of(CONSUMER_KEY)
        authorization = Authorization(
            request_id=request_id_for(key, "0x" + nonce.to_bytes(32, "big").hex()),
            request_hash="0x" + nonce.to_bytes(32, "big").hex()[::-1].replace("0", "1"),
            key=key, provider_signer=address_of(PROVIDER_SIGNER), relay_signer=address_of(RELAY_SIGNER),
            max_fee=fee, issued_at=now, execute_by=now + 60, deadline=now + 7_200,
        )
        receipt = build_receipt(authorization, response_hash="0x" + "ab" * 32,
                                input_tokens=120, output_tokens=340, actual_fee=fee)
        return SignedReceipt(
            authorization, receipt,
            sign_authorization(CONSUMER_KEY, authorization, self.deployment),
            sign_receipt(PROVIDER_SIGNER, authorization, receipt, self.deployment),
            sign_dispatch(RELAY_SIGNER, authorization, self.deployment),
        )

    def test_python_signed_batch_settles_and_releases_on_chain(self) -> None:
        owner = address_of(self.consumer)
        before = self.reader.available_balance(owner)
        receipts = [self._signed(1, 2_000_000), self._signed(2, 3_000_000)]
        for receipt in receipts:
            receipt.verify(self.deployment)
        self._send(self.relay, self.settlement, encode_settle_batch(receipts))
        self.assertEqual(self.reader.available_balance(owner), before - 5_000_000)
        provider_owner = self.reader.provider_owner(address_of(PROVIDER_SIGNER))
        self.assertEqual(provider_owner, address_of(self.provider))
        self.assertEqual(self.reader.exposure(provider_owner)[0], 5_000_000)
        key = receipts[0].authorization.settlement_key
        self.assertTrue(self.reader.is_settled(key))
        rpc.call(self.rpc, "evm_increaseTime", [86_400])
        rpc.call(self.rpc, "evm_mine", [])
        self._send(self.relay, self.settlement, encode_release(key))
        # 2 USDC fee: relay 10% = 0.2; provider gross 1.8 minus 10% holdback = 1.62.
        self.assertEqual(self.reader.claimable_balance(address_of(self.relay)), 200_000)
        self.assertEqual(self.reader.claimable_balance(provider_owner), 1_620_000)

    def test_tampered_receipts_fail_locally_and_on_chain(self) -> None:
        good = self._signed(10, 1_000_000)
        forged = SignedReceipt(
            good.authorization,
            build_receipt(good.authorization, response_hash=good.receipt.response_hash,
                          input_tokens=1, output_tokens=1, actual_fee=900_000),
            good.key_signature, good.provider_signature, good.relay_signature,
        )
        with self.assertRaises(SettlementError):
            forged.verify(self.deployment)
        with self.assertRaises(rpc.RpcError):
            self._send(self.relay, self.settlement, encode_settle_batch([forged]))
        with self.assertRaises(SettlementError):
            build_receipt(good.authorization, response_hash="0x" + "cd" * 32,
                          input_tokens=1, output_tokens=1, actual_fee=1_000_001)


if __name__ == "__main__":
    unittest.main()
