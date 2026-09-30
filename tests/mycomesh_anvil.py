"""Shared anvil fixture: deploy the V11 contracts with the mycomesh package itself."""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

from mycomesh import rpc
from mycomesh.evm import abi_encode, address_of, encode_call
from mycomesh.settlement import Deployment, SettlementReader

ROOT = Path(__file__).resolve().parents[1]
ANVIL = shutil.which("anvil") or str(Path.home() / ".foundry/bin/anvil")
# anvil's deterministic development accounts: admin, consumer, provider, relay.
ANVIL_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
]
CONSUMER_KEY = "0x" + "11" * 32
PROVIDER_SIGNER = "0x" + "22" * 32
RELAY_SIGNER = "0x" + "33" * 32
DISPUTE_WINDOW = 86_400
PARAMS = [
    DISPUTE_WINDOW, 172_800, 3_600, 100,  # dispute window, arbitration timeout, withdrawal delay, reporter bond
    1_000, 1_000, 7 * 86_400,              # relay bps, holdback bps, holdback period
    50_000_000, 1_000, 5_000_000_000,      # exposure base (50 USDC), growth bps, max
    10_000, 100_000_000, 5_000, 10,        # slash bps, slash cap, bounty bps, probe voids per day
]
PARAMS_ABI = ("tuple", ["uint64", "uint64", "uint64", "uint256", "uint16", "uint16", "uint64",
                        "uint256", "uint16", "uint256", "uint16", "uint256", "uint16", "uint16", "address"])
ELIGIBILITY_ABI = ("tuple", ["uint256", "uint64", "uint64", "uint64", "uint256"])
TIER_ABI = ("tuple", ["uint128", "uint128", "uint128", "uint128", "uint16", "bool"])


def available() -> bool:
    return Path(ANVIL).exists() and (ROOT / "out/MycoSettlementV11.sol/MycoSettlementV11.json").exists()


def _artifact(source: str, name: str) -> str:
    return json.loads((ROOT / "out" / source / f"{name}.json").read_text())["bytecode"]["object"]


class AnvilV11:
    """A fresh anvil chain with V11 deployed, a funded Consumer, and bound signers."""

    def __init__(self, deposit: int = 500_000_000) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.process = subprocess.Popen(
            [ANVIL, "--port", str(port), "--chain-id", "31337", "--hardfork", "prague", "--silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.rpc = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                rpc.call(self.rpc, "eth_chainId", [], timeout=1, attempts=1)
                break
            except rpc.RpcError:
                time.sleep(0.1)
        self.admin, self.consumer, self.provider, self.relay = ANVIL_KEYS
        self.token = self.deploy(_artifact("TestUSDC.sol", "TestUSDC"))
        registry_init = encode_call(
            "initialize(address,uint16,uint16,uint64,(uint256,uint64,uint64,uint64,uint256))",
            ["address", "uint16", "uint16", "uint64", ELIGIBILITY_ABI],
            [address_of(self.admin), 3, 2, 60, [1, 1, 0, 86_400, 1_000_000]],
        )
        self.registry = self.proxy(self.deploy(_artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11")), registry_init)
        settlement_init = encode_call(
            "initialize(address,address,address,(uint64,uint64,uint64,uint256,uint16,uint16,uint64,uint256,uint16,uint256,uint16,uint256,uint16,uint16,address))",
            ["address", "address", "address", PARAMS_ABI],
            [self.token, self.registry, address_of(self.admin), PARAMS + [address_of(self.admin)]],
        )
        disputes = self.deploy(_artifact("MycoSettlementDisputesV11.sol", "MycoSettlementDisputesV11"))
        self.settlement = self.proxy(self.deploy(_artifact("MycoSettlementV11.sol", "MycoSettlementV11"),
                                                 abi_encode(["address"], [disputes])), settlement_init)
        self.send(self.admin, self.registry, encode_call("bindSettlement(address)", ["address"], [self.settlement]))
        self.directory = self.deploy(_artifact("RelayDirectoryV11.sol", "RelayDirectoryV11"), abi_encode(["address"], [self.settlement]))
        self.ledger = self.deploy(_artifact("ProbeLedgerV11.sol", "ProbeLedgerV11"), abi_encode(["address"], [self.settlement]))
        # MYCO emission from now; every block pays out in full (no minimum spend) so tests can claim.
        self.emission_block = rpc.quantity(rpc.call(self.rpc, "eth_blockNumber", []))
        self.emission = self.proxy(self.deploy(_artifact("MycoEmissionV11.sol", "MycoEmissionV11")), encode_call(
            "initialize(address,address,address,uint64,uint256,uint256)",
            ["address", "address", "address", "uint64", "uint256", "uint256"],
            [address_of(self.admin), self.registry, self.token, self.now(), 0, 0]))
        self.myco = self.deploy(_artifact("MycoToken.sol", "MycoToken"), abi_encode(["address"], [self.emission]))
        self.send(self.admin, self.emission, encode_call("setToken(address)", ["address"], [self.myco]))
        self.send(self.admin, self.registry, encode_call("setEmission(address)", ["address"], [self.emission]))
        self.deployment = Deployment(31337, self.settlement)
        self.reader = SettlementReader(self.rpc, self.deployment)
        owner = address_of(self.consumer)
        self.send(self.admin, self.token, encode_call("mint(address,uint256)", ["address", "uint256"], [owner, 1_000_000_000]))
        self.send(self.consumer, self.token, encode_call("approve(address,uint256)", ["address", "uint256"], [self.settlement, 2**255]))
        if deposit:
            self.send(self.consumer, self.settlement, encode_call("deposit(uint256)", ["uint256"], [deposit]))
        self.send(self.consumer, self.settlement, encode_call(
            "registerKey(address,uint256,uint64)", ["address", "uint256", "uint64"], [address_of(CONSUMER_KEY), 10_000_000, 0]))
        self.send(self.provider, self.settlement, encode_call("authorizeProviderSigner(address)", ["address"], [address_of(PROVIDER_SIGNER)]))
        # Tier 1 at the prices the tests' Providers quote (1_000 / 4_000 per 1k, minimum 100), capacity unconstrained.
        self.send(self.admin, self.registry, encode_call(
            "setTier(uint32,(uint128,uint128,uint128,uint128,uint16,bool))", ["uint32", TIER_ABI],
            [1, [1_000, 4_000, 100, 10**15, 7_000, True]]))
        self.price_signer(self.provider, address_of(PROVIDER_SIGNER))
        self.send(self.relay, self.settlement, encode_call("authorizeRelaySigner(address)", ["address"], [address_of(RELAY_SIGNER)]))

    def price_signer(self, owner_key: str, signer: str, tier: int = 1, declared: int = 10**15) -> None:
        self.send(owner_key, self.registry, encode_call("setSignerTier(address,uint32,uint128)",
                                                        ["address", "uint32", "uint128"], [signer, tier, declared]))

    def close(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=10)

    def send(self, key: str, to: str | None, data: str | bytes) -> dict:
        tx = rpc.send_transaction(self.rpc, key, to=to, data=data)
        return rpc.wait_for_receipt(self.rpc, tx, timeout=30, poll=0.05)

    def deploy(self, bytecode: str, constructor: bytes = b"") -> str:
        return self.send(self.admin, None, bytes.fromhex(bytecode[2:]) + constructor)["contractAddress"]

    def proxy(self, implementation: str, init_data: str) -> str:
        return self.deploy(_artifact("MycoUpgradeable.sol", "MycoERC1967Proxy"),
                           abi_encode(["address", "bytes"], [implementation, init_data]))

    def manifest(self, relays: list[dict], **extra) -> dict:
        return {"schema": "mycomesh.v11.network.v1", "network_id": "anvil", "chain_id": 31337,
                "settlement": self.settlement, "stablecoin": self.token, "registry": self.registry,
                "relay_directory": self.directory, "probe_ledger": self.ledger, "rpc_urls": [self.rpc], "deployment_block": 0,
                "emission": self.emission, "token": self.myco, "emission_block": self.emission_block,
                "relays": relays, **extra}

    def now(self) -> int:
        return rpc.quantity(rpc.call(self.rpc, "eth_getBlockByNumber", ["latest", False])["timestamp"])

    def advance(self, seconds: int) -> None:
        rpc.call(self.rpc, "evm_increaseTime", [seconds])
        rpc.call(self.rpc, "evm_mine", [])
