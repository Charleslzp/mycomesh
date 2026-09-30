#!/usr/bin/env python3
"""Run the whole V11 lifecycle on an L2 testnet and record what it costs.

Deploys a fresh V11 stack, then: deposit and key grant, a 10-receipt
settleBatch, release after the dispute window, a dispute whose jury is drawn
from a live drand quicknet beacon verified in-contract with EIP-2537, and a
2-of-2 Provider-AI vote that confirms it. Every transaction's gas and fee
(including the L1 data fee on OP-stack chains) goes to an evidence file.
Throwaway role keys are created in memory and funded with a little L2 ETH.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mycomesh import jury, rpc  # noqa: E402
from mycomesh.evm import abi_encode, address_of, encode_call  # noqa: E402
from mycomesh.settlement import (  # noqa: E402
    Authorization, Deployment, SignedReceipt, build_receipt, encode_release, encode_settle_batch, request_id_for,
    sign_authorization, sign_dispatch, sign_receipt,
)

USDC = 10**6
WINDOW = 120
PARAMS_ABI = ("tuple", ["uint64", "uint64", "uint64", "uint256", "uint16", "uint16", "uint64",
                        "uint256", "uint16", "uint256", "uint16", "uint256", "uint16", "uint16", "address"])
ELIGIBILITY_ABI = ("tuple", ["uint256", "uint64", "uint64", "uint64", "uint256"])


def artifact(name: str, source: str | None = None) -> bytes:
    path = ROOT / "out" / f"{source or name}.sol" / f"{name}.json"
    return bytes.fromhex(json.loads(path.read_text())["bytecode"]["object"][2:])


class Chain:
    def __init__(self, url: str, chain_id: int, deployer: str) -> None:
        self.url, self.chain_id, self.deployer = url, chain_id, deployer
        self.log: list[dict] = []

    def send(self, label: str, key: str, to: str | None, data: bytes | str = b"", value: int = 0) -> dict:
        tx = rpc.send_transaction(self.url, key, to=to, data=data, value=value, chain_id=self.chain_id)
        receipt = rpc.wait_for_receipt(self.url, tx, timeout=300, poll=1)
        gas, price = rpc.quantity(receipt["gasUsed"]), rpc.quantity(receipt.get("effectiveGasPrice") or "0x0")
        l1 = rpc.quantity(receipt["l1Fee"]) if receipt.get("l1Fee") else 0
        entry = {"step": label, "tx": tx, "gas_used": gas, "l2_fee_wei": gas * price, "l1_data_fee_wei": l1,
                 "total_fee_wei": gas * price + l1}
        self.log.append(entry)
        print(f"{label:<28} gas {gas:>9,}  fee {entry['total_fee_wei'] / 1e18:.8f} ETH")
        return receipt

    def deploy(self, label: str, code: bytes) -> str:
        return self.send(label, self.deployer, None, code)["contractAddress"]

    def proxy(self, label: str, implementation: str, init: str) -> str:
        return self.deploy(label, artifact("MycoERC1967Proxy", "MycoUpgradeable")
                           + abi_encode(["address", "bytes"], [implementation, init]))

    def now(self) -> int:
        return rpc.block_time(self.url)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="base-sepolia")
    parser.add_argument("--rpc", default="https://sepolia.base.org")
    parser.add_argument("--chain-id", type=int, default=84532)
    parser.add_argument("--out", default=str(ROOT / "docs/release-evidence/v11-l2-base-sepolia.json"))
    args = parser.parse_args()
    deployer = (ROOT / ".mycomesh/v11/roles/deployer.key").read_text().strip()
    admin = address_of(deployer)
    chain = Chain(args.rpc, args.chain_id, deployer)
    if rpc.quantity(rpc.call(args.rpc, "eth_chainId", [])) != args.chain_id:
        raise SystemExit("RPC chain id mismatch")

    # ---- deploy ----
    usdc = chain.deploy("deploy TestUSDC", artifact("TestUSDC"))
    registry = chain.proxy("deploy registry", chain.deploy("deploy registry impl", artifact("ProviderJuryRegistryV11")),
                           encode_call("initialize(address,uint16,uint16,uint64,(uint256,uint64,uint64,uint64,uint256))",
                                       ["address", "uint16", "uint16", "uint64", ELIGIBILITY_ABI],
                                       [admin, 2, 2, 60, [0, 0, 0, 86_400, 10 * USDC]]))
    params = [WINDOW, 3_600, 3_600, 1 * USDC, 500, 1_000, 7 * 86_400, 50 * USDC, 1_000, 5_000 * USDC,
              10_000, 100 * USDC, 5_000, 10, admin]
    settlement = chain.proxy("deploy settlement", chain.deploy("deploy settlement impl", artifact("MycoSettlementV11")),
                             encode_call("initialize(address,address,address,(uint64,uint64,uint64,uint256,uint16,uint16,"
                                         "uint64,uint256,uint16,uint256,uint16,uint256,uint16,uint16,address))",
                                         ["address", "address", "address", PARAMS_ABI], [usdc, registry, admin, params]))
    chain.send("bindSettlement", deployer, registry, encode_call("bindSettlement(address)", ["address"], [settlement]))
    deployment = Deployment(args.chain_id, settlement)

    # ---- roles: the deployer is Consumer owner and Relay owner; Provider and jurors are fresh owners ----
    owners = {name: "0x" + secrets.token_hex(32) for name in ("provider", "juror1", "juror2")}
    signers = {name: "0x" + secrets.token_hex(32) for name in ("provider", "juror1", "juror2", "relay", "key")}
    for name, key in owners.items():
        chain.send(f"fund {name}", deployer, address_of(key), value=3 * 10**15)
    chain.send("mint", deployer, usdc, encode_call("mint(address,uint256)", ["address", "uint256"], [admin, 1_000 * USDC]))
    chain.send("approve", deployer, usdc, encode_call("approve(address,uint256)", ["address", "uint256"], [settlement, 2**255]))
    chain.send("deposit", deployer, settlement, encode_call("deposit(uint256)", ["uint256"], [100 * USDC]))
    chain.send("registerKey", deployer, settlement, encode_call("registerKey(address,uint256,uint64)",
                                                                  ["address", "uint256", "uint64"], [address_of(signers["key"]), 5 * USDC, 0]))
    chain.send("authorizeRelaySigner", deployer, settlement, encode_call("authorizeRelaySigner(address)", ["address"], [address_of(signers["relay"])]))
    for name in owners:
        chain.send(f"authorizeProviderSigner {name}", owners[name], settlement,
                   encode_call("authorizeProviderSigner(address)", ["address"], [address_of(signers[name])]))
    for name in ("juror1", "juror2"):
        chain.send(f"register {name}", owners[name], registry, encode_call(
            "register(address,bytes32,bytes32,bytes32)", ["address", "bytes32", "bytes32", "bytes32"],
            [address_of(signers[name]), "0x" + secrets.token_hex(32), "0x" + secrets.token_hex(32), "0x" + "00" * 32]))

    def receipt(fee: int) -> SignedReceipt:
        issued = chain.now() - 5
        key = address_of(signers["key"])
        authorization = Authorization(
            request_id=request_id_for(key, "0x" + secrets.token_hex(32)), request_hash="0x" + secrets.token_hex(32), key=key,
            provider_signer=address_of(signers["provider"]), relay_signer=address_of(signers["relay"]), max_fee=fee,
            issued_at=issued, execute_by=issued + 300, deadline=issued + 7_200)
        usage = build_receipt(authorization, response_hash="0x" + secrets.token_hex(32), input_tokens=900, output_tokens=300,
                              actual_fee=fee)
        return SignedReceipt(authorization, usage, sign_authorization(signers["key"], authorization, deployment),
                             sign_receipt(signers["provider"], authorization, usage, deployment),
                             sign_dispatch(signers["relay"], authorization, deployment))

    # ---- settlement at scale ----
    batch = [receipt(10_000) for _ in range(10)]
    chain.send("settleBatch x10", deployer, settlement, encode_settle_batch(batch))
    single = receipt(10_000)
    chain.send("settleBatch x1", deployer, settlement, encode_settle_batch([single]))
    time.sleep(WINDOW + 5)
    chain.send("release", deployer, settlement, encode_release(batch[0].authorization.settlement_key))

    # ---- dispute with a live drand jury ----
    disputed = receipt(20_000)
    chain.send("settleBatch disputed", deployer, settlement, encode_settle_batch([disputed]))
    key = disputed.authorization.settlement_key
    evidence = "0x" + secrets.token_hex(32)
    chain.send("openDispute + requestJury", deployer, settlement, jury.encode_open_dispute(key, evidence))
    cases = jury.CaseReader(args.rpc, deployment, registry)
    round_number = cases.assignment(key)["round"]
    while time.time() < jury.round_time(round_number) + 3:
        time.sleep(2)
    beacon = jury.fetch_drand_signature(round_number)
    chain.send("finalizeJury (drand verify)", deployer, registry, jury.encode_finalize_jury(key, beacon))
    # Load-balanced RPCs can serve a read from a node that has not seen the last block yet.
    assignment = cases.assignment(key)
    while assignment["status"] != "ready":
        time.sleep(2)
        assignment = cases.assignment(key)
    report = jury.report_id(key, admin, evidence)
    decision = jury.decision_hash(key, assignment["hash"], True, report, jury.DEFAULT_POLICY)
    votes = [jury.sign_vote(signers[name], deployment, settlement_key=key, assignment_hash=assignment["hash"], confirmed=True,
                            report_id=report, decision=decision, nonce=0, deadline=chain.now() + 3_600)
             for name in ("juror1", "juror2")]
    try:
        chain.send("voteDisputeBySig 2/2", deployer, settlement, jury.encode_votes(key, votes))
    except rpc.RpcError:
        print("assignment", assignment)
        for name in ("juror1", "juror2"):
            print(name, address_of(signers[name]), "drawn", cases.is_vote_signer(key, address_of(signers[name])))
        print("report evidence", cases.report_evidence(key, report), "expected", evidence)
        print("settlement", cases.settlement(key))
        raise
    status = cases.settlement(key)["status"]
    if status != "confirmed":
        raise SystemExit(f"dispute ended {status}")

    per = {entry["step"]: entry for entry in chain.log}
    evidence_doc = {
        "schema": "mycomesh.v11.l2-verification.v1", "network": args.name, "chain_id": args.chain_id,
        "verified_at": int(time.time()),
        "contracts": {"settlement": settlement, "registry": registry, "stablecoin": usdc},
        "drand_round": round_number, "dispute_status": status,
        "per_receipt_in_batch_of_10": {k: per["settleBatch x10"][k] // 10 for k in ("gas_used", "total_fee_wei")},
        "summary_wei": {step: per[step]["total_fee_wei"] for step in (
            "settleBatch x1", "release", "openDispute + requestJury", "finalizeJury (drand verify)", "voteDisputeBySig 2/2")},
        "transactions": chain.log,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(evidence_doc, indent=2) + "\n")
    print(f"dispute {status}; evidence in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
