#!/usr/bin/env python3
"""Deploy MycoMesh V11 to Sepolia and bind every testnet role.

Resumable: each step is journaled in .mycomesh/v11/deploy-state.json, so a
rerun continues where a failure stopped. Role keys are created under
.mycomesh/v11/roles (0600, never printed); only addresses and transaction
hashes leave this machine, in deployments/sepolia-myco-v11.json and the public
network manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mycomesh import rpc  # noqa: E402
from mycomesh.evm import abi_encode, address_of, encode_call, keccak256  # noqa: E402
from mycomesh.capability import FLOORS  # noqa: E402
from mycomesh.identity import load_or_create_identity  # noqa: E402

STATE_DIR = ROOT / ".mycomesh/v11"
ROLES = STATE_DIR / "roles"
STATE = Path(os.environ.get("MYCOMESH_DEPLOY_STATE", STATE_DIR / "deploy-state.json"))
DEPLOYMENT = ROOT / "deployments/sepolia-myco-v11.json"
NETWORK = ROOT / "deployments/mycomesh-v11-sepolia.network.json"
PACKAGE_NETWORKS = [ROOT / f"packages/{name}/networks/mycomesh-v11-sepolia.json"
                    for name in ("mycomesh-cli", "mycomesh-provider", "mycomesh-relay")]
CA_FILE = "mycomesh-testnet-ca.crt"
CHAIN_ID = 11155111
RPC_URLS = ["https://ethereum-sepolia-rpc.publicnode.com", "https://rpc.sepolia.ethpandaops.io",
            "https://sepolia.gateway.tenderly.co"]
# MYCOMESH_DEPLOY_RPC rehearses against a fork (anvil --fork-url ...) before touching Sepolia.
TARGET_RPC = [os.environ["MYCOMESH_DEPLOY_RPC"]] if os.environ.get("MYCOMESH_DEPLOY_RPC") else RPC_URLS
USDC = 10**6
RELAYS = {"relay1": "136.0.3.126", "relay3": "166.88.96.60"}
BRIDGES = ("bridge1", "bridge2", "bridge3")
PROVIDERS = ("provider1", "provider2", "provider3", "provider4")
DISPUTE_WINDOW = 86_400
PARAMS = [
    DISPUTE_WINDOW,          # disputeWindow: 24h
    172_800,                 # arbitrationTimeout: 48h after the window
    3_600,                   # consumerWithdrawalDelay
    1 * USDC,                # reporterBond
    500,                     # relayBps: 5% of each fee to the dispatching Relay
    1_000,                   # holdbackBps: 10% held back
    7 * 86_400,              # holdbackPeriod: 7 days
    50 * USDC,               # baseExposureCap for a new Provider
    1_000,                   # exposureGrowthBps of clean volume
    5_000 * USDC,            # maxExposureCap
    10_000,                  # slashBps of the fee on confirmed fraud
    100 * USDC,              # slashCap
    5_000,                   # reporterBountyBps of the penalty
    10,                      # probeVoidsPerDay per Relay per Provider
]
PARAMS_ABI = ("tuple", ["uint64", "uint64", "uint64", "uint256", "uint16", "uint16", "uint64",
                        "uint256", "uint16", "uint256", "uint16", "uint256", "uint16", "uint16", "address"])
# Jury of 5, 3 consistent votes, drawn from the drand round 60s after the dispute opens, in proportion
# to counted volume capped at 100 USDC per Provider.
JURY = [5, 3, 60, 100 * USDC]
# counted volume, distinct counterparties, registration age, fraud cooldown, per-counterparty cap
ELIGIBILITY = [1 * USDC, 5, 7 * 86_400, 30 * 86_400, 10 * USDC]
RELAY_URL = "https://{host}:10443"
RELAY_LINK = "{host}:10991"
FAUCET_RELAY = "relay1"
# Network pricing tiers: base prices per 1k tokens (input, output, minimum fee), the capacity a new Provider
# may settle a day (work at base prices), and the utilisation the daily adjustment steers toward.
TIERS = {
    1: {"name": "OpenAI frontier", "models": ["gpt-5.5"], "base": [20, 2_000, 1_000], "base_capacity": 5 * USDC, "target_bps": 7_000},
    2: {"name": "Anthropic Claude", "models": ["claude-sonnet-4-6", "claude-opus-4-8"], "base": [300, 1_500, 1_000],
        "base_capacity": 5 * USDC, "target_bps": 7_000},
}
PROVIDER_DAILY_CAPACITY = 10 * USDC
# MYCO emission: an hour's full schedule pays out once that hour's fees reach 0.1 tUSDC (quiet hours pay a
# fraction and carry the rest forward); keepers earn 0.01 tUSDC per release or jury draw from the treasury.
MIN_SPEND_PER_BLOCK = 100_000
BOUNTY_PER_CALL = 10_000
BOUNTY_FUNDING = 500 * USDC
TIER_ABI = ("tuple", ["uint128", "uint128", "uint128", "uint128", "uint16", "bool"])
ELIGIBILITY_ABI = ("tuple", ["uint256", "uint64", "uint64", "uint64", "uint256"])
ETH_FUNDING = {"relay": 5 * 10**16, "bridge": 3 * 10**16, "provider": 10**16, "consumer": 10**16, "faucet": 2 * 10**18}


def artifact(source: str, name: str) -> dict:
    return json.loads((ROOT / "out" / source / f"{name}.json").read_text())


class Deployer:
    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run
        self.state = json.loads(STATE.read_text()) if STATE.exists() else {"steps": {}}
        self.key = self.role_key("deployer", create=False)
        self.address = address_of(self.key)

    # ---------------- bookkeeping ----------------

    def save(self) -> None:
        STATE.write_text(json.dumps(self.state, indent=2, sort_keys=True) + "\n")
        os.chmod(STATE, 0o600)

    def role_key(self, name: str, *, create: bool = True) -> str:
        path = ROLES / f"{name}.key"
        if not path.exists():
            if not create:
                raise SystemExit(f"missing {path}")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write("0x" + secrets.token_hex(32) + "\n")
        value = path.read_text().strip()
        return value if value.startswith("0x") else "0x" + value

    def step(self, name: str, send) -> dict:
        """Run ``send() -> receipt`` once; later runs reuse the journaled result."""
        if name in self.state["steps"]:
            return self.state["steps"][name]
        if self.dry_run:
            print(f"[dry-run] {name}")
            return {"contractAddress": "0x" + "00" * 20, "transactionHash": "0x" + "00" * 32, "blockNumber": "0x0"}
        receipt = send()
        record = {"transactionHash": receipt["transactionHash"], "blockNumber": receipt["blockNumber"],
                  "contractAddress": receipt.get("contractAddress")}
        self.state["steps"][name] = record
        self.save()
        print(f"{name}: {receipt['transactionHash']}")
        return record

    def tx(self, key: str, to: str | None, data: bytes | str, value: int = 0) -> dict:
        tx = rpc.send_transaction(TARGET_RPC, key, to=to, data=data, value=value, chain_id=CHAIN_ID)
        return rpc.wait_for_receipt(TARGET_RPC, tx, timeout=600, poll=3)

    def deploy(self, name: str, bytecode: str, constructor: bytes = b"") -> str:
        return self.step(name, lambda: self.tx(self.key, None, bytes.fromhex(bytecode[2:]) + constructor))["contractAddress"]

    # ---------------- phases ----------------

    def preflight(self) -> None:
        chain = rpc.quantity(rpc.call(TARGET_RPC, "eth_chainId", []))
        if chain != CHAIN_ID:
            raise SystemExit(f"RPC is chain {chain}, not Sepolia")
        # EIP-2537 (Prague) precompiles back the in-contract drand verification.
        added = rpc.call(TARGET_RPC, "eth_call", [{"to": "0x" + "00" * 19 + "0b", "data": "0x" + "00" * 256}, "latest"])
        if added != "0x" + "00" * 128:
            raise SystemExit("Sepolia does not expose the BLS12-381 G1ADD precompile")
        balance = rpc.quantity(rpc.call(TARGET_RPC, "eth_getBalance", [self.address, "latest"]))
        print(f"deployer {self.address} balance {balance / 1e18:.4f} ETH")

    def contracts(self) -> dict:
        usdc = self.deploy("deploy:TestUSDC", artifact("TestUSDC.sol", "TestUSDC")["bytecode"]["object"])
        proxy_code = artifact("MycoUpgradeable.sol", "MycoERC1967Proxy")["bytecode"]["object"]
        registry_impl = self.deploy("deploy:RegistryImpl",
                                    artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11")["bytecode"]["object"])
        registry_init = encode_call(
            "initialize(address,uint16,uint16,uint64,(uint256,uint64,uint64,uint64,uint256))",
            ["address", "uint16", "uint16", "uint64", ELIGIBILITY_ABI], [self.address, 3, 2, 60, ELIGIBILITY])
        registry = self.deploy("deploy:RegistryProxy", proxy_code, abi_encode(["address", "bytes"], [registry_impl, registry_init]))
        settlement_impl = self.deploy("deploy:SettlementImpl",
                                      artifact("MycoSettlementV11.sol", "MycoSettlementV11")["bytecode"]["object"])
        settlement_init = encode_call(
            "initialize(address,address,address,(uint64,uint64,uint64,uint256,uint16,uint16,uint64,uint256,uint16,uint256,uint16,uint256,uint16,uint16,address))",
            ["address", "address", "address", PARAMS_ABI], [usdc, registry, self.address, PARAMS + [self.address]])
        settlement = self.deploy("deploy:SettlementProxy", proxy_code,
                                 abi_encode(["address", "bytes"], [settlement_impl, settlement_init]))
        self.step("registry:bindSettlement", lambda: self.tx(
            self.key, registry, encode_call("bindSettlement(address)", ["address"], [settlement])))
        return {"stablecoin": usdc, "registry": registry, "registry_implementation": registry_impl,
                "settlement": settlement, "settlement_implementation": settlement_impl}

    def harden(self, c: dict) -> dict:
        """v2: weighted 5/3 juries, stricter eligibility, renounce path, relay directory."""
        proxy_calls = lambda proxy, impl: encode_call("upgradeToAndCall(address,bytes)", ["address", "bytes"], [impl, b""])  # noqa: E731
        registry_v2 = self.deploy("deploy:RegistryImplV2",
                                  artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11")["bytecode"]["object"])
        self.step("upgrade:RegistryV2", lambda: self.tx(self.key, c["registry"], proxy_calls(c["registry"], registry_v2)))
        self.step("registry:setJury:v2", lambda: self.tx(self.key, c["registry"], encode_call(
            "setJury(uint16,uint16,uint64,uint256)", ["uint16", "uint16", "uint64", "uint256"], JURY)))
        self.step("registry:setEligibility:v2", lambda: self.tx(self.key, c["registry"], encode_call(
            "setEligibility((uint256,uint64,uint64,uint64,uint256))", [ELIGIBILITY_ABI], [ELIGIBILITY])))
        settlement_v2 = self.deploy("deploy:SettlementImplV2",
                                    artifact("MycoSettlementV11.sol", "MycoSettlementV11")["bytecode"]["object"])
        self.step("upgrade:SettlementV2", lambda: self.tx(self.key, c["settlement"], proxy_calls(c["settlement"], settlement_v2)))
        directory = self.deploy("deploy:RelayDirectory", artifact("RelayDirectoryV11.sol", "RelayDirectoryV11")["bytecode"]["object"],
                                abi_encode(["address"], [c["settlement"]]))
        for relay, host in RELAYS.items():
            owner_key, signer = self.role_key(f"{relay}-owner"), address_of(self.role_key(f"{relay}-signer"))
            self.step(f"{relay}:announce", lambda: self.tx(owner_key, directory, encode_call(
                "announce(address,string,string)", ["address", "string", "string"],
                [signer, RELAY_URL.format(host=host), RELAY_LINK.format(host=host)])))
        return {**c, "registry_implementation": registry_v2, "settlement_implementation": settlement_v2,
                "relay_directory": directory}

    def v3(self, c: dict) -> dict:
        """v3: per-key budgets (multi-tenant), upgrade sunset, probe ledger, certificate-pinned Relay entries."""
        import ssl

        from mycomesh.tlspin import PIN_PREFIX, fingerprint

        upgrade = lambda impl: encode_call("upgradeToAndCall(address,bytes)", ["address", "bytes"], [impl, b""])  # noqa: E731
        settlement_v3 = self.deploy("deploy:SettlementImplV3",
                                    artifact("MycoSettlementV11.sol", "MycoSettlementV11")["bytecode"]["object"])
        self.step("upgrade:SettlementV3", lambda: self.tx(self.key, c["settlement"], upgrade(settlement_v3)))
        registry_v3 = self.deploy("deploy:RegistryImplV3",
                                  artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11")["bytecode"]["object"])
        self.step("upgrade:RegistryV3", lambda: self.tx(self.key, c["registry"], upgrade(registry_v3)))
        ledger = self.deploy("deploy:ProbeLedger", artifact("ProbeLedgerV11.sol", "ProbeLedgerV11")["bytecode"]["object"],
                             abi_encode(["address"], [c["settlement"]]))
        context = ssl.create_default_context(cafile=str(ROOT / "deployments" / CA_FILE))
        for relay, host in RELAYS.items():
            # Pin the certificate each Relay actually serves (checked against the network CA first), so
            # clients can verify it from the directory alone.
            with context.wrap_socket(__import__("socket").create_connection((host, 10443), timeout=10), server_hostname=host) as sock:
                pin = PIN_PREFIX + fingerprint(sock.getpeercert(binary_form=True))
            owner_key, signer = self.role_key(f"{relay}-owner"), address_of(self.role_key(f"{relay}-signer"))
            self.step(f"{relay}:announce:pinned", lambda: self.tx(owner_key, c["relay_directory"], encode_call(
                "announce(address,string,string)", ["address", "string", "string"],
                [signer, RELAY_URL.format(host=host) + pin, RELAY_LINK.format(host=host) + pin])))
        return {**c, "settlement_implementation": settlement_v3, "registry_implementation": registry_v3, "probe_ledger": ledger}

    def v4(self, c: dict) -> dict:
        """v4: network pricing adjusted like Bitcoin's difficulty. Tiers and signer tiers exist before the
        settlement starts enforcing the network price, so no receipt ever lacks a price."""
        upgrade = lambda impl: encode_call("upgradeToAndCall(address,bytes)", ["address", "bytes"], [impl, b""])  # noqa: E731
        registry_v4 = self.deploy("deploy:RegistryImplV4",
                                  artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11")["bytecode"]["object"])
        self.step("upgrade:RegistryV4", lambda: self.tx(self.key, c["registry"], upgrade(registry_v4)))
        for tier, config in TIERS.items():
            values = [*config["base"], config["base_capacity"], config["target_bps"], True]
            self.step(f"registry:setTier:{tier}", lambda: self.tx(self.key, c["registry"], encode_call(
                "setTier(uint32,(uint128,uint128,uint128,uint128,uint16,bool))", ["uint32", TIER_ABI], [tier, values])))
        for provider in PROVIDERS:
            owner_key, signer = self.role_key(f"{provider}-owner"), address_of(self.role_key(f"{provider}-signer"))
            self.step(f"{provider}:setSignerTier", lambda: self.tx(owner_key, c["registry"], encode_call(
                "setSignerTier(address,uint32,uint128)", ["address", "uint32", "uint128"], [signer, 1, PROVIDER_DAILY_CAPACITY])))
        settlement_v4 = self.deploy("deploy:SettlementImplV4",
                                    artifact("MycoSettlementV11.sol", "MycoSettlementV11")["bytecode"]["object"])
        self.step("upgrade:SettlementV4", lambda: self.tx(self.key, c["settlement"], upgrade(settlement_v4)))
        return {**c, "settlement_implementation": settlement_v4, "registry_implementation": registry_v4}

    def v5(self, c: dict) -> dict:
        """v5: the MYCO token and its Bitcoin-style emission, and the 10% protocol treasury. The emission and
        token exist before the registry forwards to them; the registry takes the new hook before the settlement
        starts calling it, so at most one release in between records volume without rewards."""
        upgrade = lambda impl: encode_call("upgradeToAndCall(address,bytes)", ["address", "bytes"], [impl, b""])  # noqa: E731
        proxy_code = artifact("MycoUpgradeable.sol", "MycoERC1967Proxy")["bytecode"]["object"]
        emission_impl = self.deploy("deploy:EmissionImpl", artifact("MycoEmissionV11.sol", "MycoEmissionV11")["bytecode"]["object"])
        if "deploy:EmissionProxy" not in self.state["steps"]:
            self.state["emission_genesis"] = rpc.block_time(TARGET_RPC) // 3_600 * 3_600  # block 0 starts on the hour
            self.save()
        genesis = self.state.get("emission_genesis", 0)
        emission = self.deploy("deploy:EmissionProxy", proxy_code, abi_encode(["address", "bytes"], [emission_impl, encode_call(
            "initialize(address,address,address,uint64,uint256,uint256)",
            ["address", "address", "address", "uint64", "uint256", "uint256"],
            [self.address, c["registry"], c["stablecoin"], genesis, MIN_SPEND_PER_BLOCK, BOUNTY_PER_CALL])]))
        token = self.deploy("deploy:MycoToken", artifact("MycoToken.sol", "MycoToken")["bytecode"]["object"],
                            abi_encode(["address"], [emission]))
        self.step("emission:setToken", lambda: self.tx(self.key, emission, encode_call("setToken(address)", ["address"], [token])))
        self.step("mint:bounties", lambda: self.tx(self.key, c["stablecoin"], encode_call(
            "mint(address,uint256)", ["address", "uint256"], [self.address, BOUNTY_FUNDING])))
        self.step("approve:bounties", lambda: self.tx(self.key, c["stablecoin"], encode_call(
            "approve(address,uint256)", ["address", "uint256"], [emission, BOUNTY_FUNDING])))
        self.step("emission:fundBounties", lambda: self.tx(self.key, emission, encode_call(
            "fundBounties(uint256)", ["uint256"], [BOUNTY_FUNDING])))
        registry_v5 = self.deploy("deploy:RegistryImplV5",
                                  artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11")["bytecode"]["object"])
        self.step("upgrade:RegistryV5", lambda: self.tx(self.key, c["registry"], upgrade(registry_v5)))
        self.step("registry:setEmission", lambda: self.tx(self.key, c["registry"], encode_call(
            "setEmission(address)", ["address"], [emission])))
        settlement_v5 = self.deploy("deploy:SettlementImplV5",
                                    artifact("MycoSettlementV11.sol", "MycoSettlementV11")["bytecode"]["object"])
        self.step("upgrade:SettlementV5", lambda: self.tx(self.key, c["settlement"], upgrade(settlement_v5)))
        return {**c, "settlement_implementation": settlement_v5, "registry_implementation": registry_v5,
                "emission": emission, "emission_implementation": emission_impl, "token": token}

    def v6(self, c: dict) -> dict:
        """v6: the settlement split in two (disputes in a delegatecall module, same proxy, ABI and storage),
        batch releases with aggregated reward hooks, and a probe ledger with capability verdict codes. The
        emission and the registry learn the batch hook before the settlement starts calling it."""
        upgrade = lambda impl: encode_call("upgradeToAndCall(address,bytes)", ["address", "bytes"], [impl, b""])  # noqa: E731
        emission_v6 = self.deploy("deploy:EmissionImplV6", artifact("MycoEmissionV11.sol", "MycoEmissionV11")["bytecode"]["object"])
        self.step("upgrade:EmissionV6", lambda: self.tx(self.key, c["emission"], upgrade(emission_v6)))
        registry_v6 = self.deploy("deploy:RegistryImplV6",
                                  artifact("ProviderJuryRegistryV11.sol", "ProviderJuryRegistryV11")["bytecode"]["object"])
        self.step("upgrade:RegistryV6", lambda: self.tx(self.key, c["registry"], upgrade(registry_v6)))
        module = self.deploy("deploy:SettlementDisputesV6",
                             artifact("MycoSettlementDisputesV11.sol", "MycoSettlementDisputesV11")["bytecode"]["object"])
        settlement_v6 = self.deploy("deploy:SettlementImplV6", artifact("MycoSettlementV11.sol", "MycoSettlementV11")["bytecode"]["object"],
                                    abi_encode(["address"], [module]))
        self.step("upgrade:SettlementV6", lambda: self.tx(self.key, c["settlement"], upgrade(settlement_v6)))
        ledger = self.deploy("deploy:ProbeLedgerV6", artifact("ProbeLedgerV11.sol", "ProbeLedgerV11")["bytecode"]["object"],
                             abi_encode(["address"], [c["settlement"]]))
        return {**c, "emission_implementation": emission_v6, "registry_implementation": registry_v6,
                "settlement_implementation": settlement_v6, "settlement_dispute_module": module, "probe_ledger": ledger}

    def fund(self, name: str, kind: str, token: str | None = None, mint: int = 0) -> str:
        address = address_of(self.role_key(name))
        self.step(f"fund:{name}", lambda: self.tx(self.key, address, b"", value=ETH_FUNDING[kind]))
        if token and mint:
            self.step(f"mint:{name}", lambda: self.tx(
                self.key, token, encode_call("mint(address,uint256)", ["address", "uint256"], [address, mint])))
        return address

    def roles(self, c: dict) -> dict:
        roles: dict = {"relays": {}, "bridges": {}, "providers": {}}
        for relay in RELAYS:
            owner_key, signer_key = self.role_key(f"{relay}-owner"), self.role_key(f"{relay}-signer")
            owner = self.fund(f"{relay}-owner", "relay", c["stablecoin"], 200 * USDC)
            signer = address_of(signer_key)
            self.step(f"{relay}:authorizeRelaySigner", lambda: self.tx(
                owner_key, c["settlement"], encode_call("authorizeRelaySigner(address)", ["address"], [signer])))
            self.step(f"{relay}:approve", lambda: self.tx(owner_key, c["stablecoin"], encode_call(
                "approve(address,uint256)", ["address", "uint256"], [c["settlement"], 2**255])))
            self.step(f"{relay}:deposit", lambda: self.tx(
                owner_key, c["settlement"], encode_call("deposit(uint256)", ["uint256"], [100 * USDC])))
            roles["relays"][relay] = {"owner": owner, "signer": signer, "host": RELAYS[relay]}
        for bridge in BRIDGES:
            roles["bridges"][bridge] = {"keeper": self.fund(f"{bridge}-keeper", "bridge")}
        for provider in PROVIDERS:
            owner_key, signer_key = self.role_key(f"{provider}-owner"), self.role_key(f"{provider}-signer")
            owner = self.fund(f"{provider}-owner", "provider")
            signer = address_of(signer_key)
            identity = load_or_create_identity(ROLES / f"{provider}-identity.json")
            operator = f"mycomesh-testnet/{provider}"
            self.step(f"{provider}:authorizeProviderSigner", lambda: self.tx(
                owner_key, c["settlement"], encode_call("authorizeProviderSigner(address)", ["address"], [signer])))
            hashes = ["0x" + keccak256(v.encode()).hex() for v in (operator, identity.peer_id, "gpt-5.5")]
            self.step(f"{provider}:register", lambda: self.tx(owner_key, c["registry"], encode_call(
                "register(address,bytes32,bytes32,bytes32)", ["address", "bytes32", "bytes32", "bytes32"], [signer, *hashes])))
            roles["providers"][provider] = {"owner": owner, "signer": signer, "peer_id": identity.peer_id,
                                            "operator_id": operator}
        roles["consumer_test"] = self.fund("consumer-test-owner", "consumer", c["stablecoin"], 1_000 * USDC)
        roles["faucet"] = {"address": self.fund("faucet", "faucet"), "relay": FAUCET_RELAY}
        return roles

    def publish(self, c: dict, roles: dict) -> None:
        steps = self.state["steps"]
        first = steps["deploy:TestUSDC"]
        block = rpc.call(RPC_URLS, "eth_getBlockByNumber", [first["blockNumber"], False])

        def code_hash(address: str) -> str:
            return "0x" + keccak256(bytes.fromhex(rpc.call(RPC_URLS, "eth_getCode", [address, "latest"])[2:])).hex()

        deployment = {
            "schema": "mycomesh.v11.deployment.v1", "network_id": "mycomesh-v11-sepolia", "chain_id": CHAIN_ID,
            "deployment_class": "controlled_test", "admin": self.address, "upgrade_policy": "single-admin-uups-no-delay",
            "eip712": {"name": "MycoMesh Settlement", "version": "11"},
            "deployment_block": int(first["blockNumber"], 16), "deployment_block_hash": block["hash"],
            "contracts": c, "runtime_code_keccak256": {name: code_hash(address) for name, address in c.items()},
            "artifact_sha256": {name: hashlib.sha256((ROOT / "out" / f"{name}.sol" / f"{name}.json").read_bytes()).hexdigest()
                                for name in ("MycoSettlementV11", "ProviderJuryRegistryV11", "RelayDirectoryV11", "ProbeLedgerV11",
                                             "MycoEmissionV11", "MycoToken", "MycoSettlementDisputesV11", "TestUSDC")},
            "multi_tenant": "setKeyBudget(key, limit): one owner deposit, a capped payment key per tenant",
            "upgrade_sunset": "setUpgradeSunset(t): upgrades end at t; it can only ever move earlier",
            "pricing": {"model": "one network price per tier; daily multiplier follows utilisation toward the target, "
                                 "at most +/-10% a day, within 0.1x..10x; capacity binds and grows with proven work",
                        "tiers": {str(tier): config for tier, config in TIERS.items()},
                        "provider_daily_capacity": PROVIDER_DAILY_CAPACITY},
            "fee_split": {"provider_bps": 8_500, "relay_bps": PARAMS[4], "treasury_bps": 1_000,
                          "treasury": "the admin; protocol income, used to fund keeper bounties and buy MYCO"},
            "tokenomics": {
                "token": "MYCO, 1,000,000,000 max supply, 18 decimals, no premine: every token is minted by the emission",
                "emission": "hourly blocks; era 1 lasts 1 week and each later era doubles in length (2, 4, 8 weeks...) up to "
                            "4 years, then 4-year eras; the emission rate halves every era",
                "genesis": self.state.get("emission_genesis"), "block_seconds": 3_600,
                "shares_bps": {"consumer": 8_000, "provider": 1_000, "relay": 700, "bridge": 300},
                "consumer": "by fees paid in the block", "provider": "by fees served, x releases/(releases+frauds), claimable 48h after the block",
                "relay": "by fees dispatched", "bridge": "by fees released and juries drawn (plus a stablecoin bounty per call)",
                "min_spend_per_block": MIN_SPEND_PER_BLOCK, "bounty_per_call": BOUNTY_PER_CALL,
            },
            "upgrade_exit": "renounceUpgrades() then renounceAdmin() on each proxy (one-way)",
            "params": dict(zip(["dispute_window", "arbitration_timeout", "consumer_withdrawal_delay", "reporter_bond",
                                "relay_bps", "holdback_bps", "holdback_period", "base_exposure_cap",
                                "exposure_growth_bps", "max_exposure_cap", "slash_bps", "slash_cap",
                                "reporter_bounty_bps", "probe_voids_per_day"], PARAMS)),
            "jury": {"size": JURY[0], "threshold": JURY[1], "selection_delay": JURY[2], "max_jury_weight": JURY[3],
                     "selection": "drand-quicknet-eip2537, weighted by counted volume",
                     "eligibility": dict(zip(["min_counted_volume", "min_counterparties", "min_age", "fraud_cooldown",
                                              "per_counterparty_cap"], ELIGIBILITY))},
            "roles": roles, "transactions": {name: step["transactionHash"] for name, step in sorted(steps.items())},
        }
        DEPLOYMENT.write_text(json.dumps(deployment, indent=2) + "\n")
        network = {
            "schema": "mycomesh.v11.network.v1", "network_id": "mycomesh-v11-sepolia", "chain_id": CHAIN_ID,
            "settlement": c["settlement"], "stablecoin": c["stablecoin"], "registry": c["registry"],
            "relay_directory": c["relay_directory"], "probe_ledger": c["probe_ledger"],
            "emission": c["emission"], "token": c["token"], "emission_block": int(steps["deploy:EmissionProxy"]["blockNumber"], 16),
            # A tier's capability floor exists only once its model was calibrated (docs/release-evidence).
            "tiers": {str(tier): {"name": config["name"], "models": config["models"],
                                  **({"capability_floor": FLOORS[tier]} if tier in FLOORS else {})}
                      for tier, config in TIERS.items()},
            "deployment_block": deployment["deployment_block"], "rpc_urls": RPC_URLS, "tls_ca_file": CA_FILE,
            "faucet_url": RELAY_URL.format(host=RELAYS[FAUCET_RELAY]),
            "relays": [{"url": RELAY_URL.format(host=r["host"]), "signer": r["signer"], "link": RELAY_LINK.format(host=r["host"])}
                       for r in roles["relays"].values()],
        }
        for path in (NETWORK, *PACKAGE_NETWORKS):
            path.write_text(json.dumps(network, indent=2) + "\n")
        print(f"wrote {DEPLOYMENT.relative_to(ROOT)}, {NETWORK.relative_to(ROOT)} and the package manifests")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    ROLES.mkdir(parents=True, exist_ok=True, mode=0o700)
    deployer = Deployer(args.dry_run)
    deployer.preflight()
    contracts = deployer.contracts()
    roles = deployer.roles(contracts)
    contracts = deployer.harden(contracts)
    contracts = deployer.v3(contracts)
    contracts = deployer.v4(contracts)
    contracts = deployer.v5(contracts)
    contracts = deployer.v6(contracts)
    if not args.dry_run and not os.environ.get("MYCOMESH_DEPLOY_RPC"):
        deployer.publish(contracts, roles)
    return 0


if __name__ == "__main__":
    started = time.time()
    code = main()
    print(f"done in {time.time() - started:.0f}s")
    sys.exit(code)
