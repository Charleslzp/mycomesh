#!/usr/bin/env python3
"""Prepare the reputation-neutral serving Provider for the dynamic V10 mesh.

Provider1 is deliberately not a jury candidate: its signer has no imported
reputation evidence.  The three registry candidates remain the AI jury.  This
script only gives provider1 enough bounded test capacity, authorizes its
receipt signer, and records every transaction in a durable V10 outbox.

The deployed stablecoin is the controlled-test ``TestUSDC`` contract, whose
``mint`` entry point is intentionally unrestricted.  No production profile may
run this script.  Read-only is the default; ``--send`` is required to change
the chain.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import chain  # noqa: E402


RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
CHAIN_ID = 11_155_111
GENESIS_HASH = "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"
STABLECOIN = "0xeb487c6e778248e16361dc313e4223c20d4c23b5"
SETTLEMENT = "0x31d3f0a17c6c6f4594a2f9ffeebf72c41f9e1c3a"
PROVIDER_OWNER = "0x94515c8903cca8e5aedb1437e947db39970792cc"
PROVIDER_SIGNER = "0x83fd8e4518b26462bec8e06cf10b5adf30299688"
CAPACITY_TOTAL = 3_000_000
CONFIRMATIONS = 6
IDENTITY_FILE = ROOT / ".codex-run/mesh/v9-controlled-test-20260918/wallets/provider-owner.key"
OUTBOX = ROOT / ".mycomesh/v10/serving-provider1.sqlite3"
PLAN_FILE = ROOT / ".mycomesh/v10/serving-provider1-plan.json"
EXECUTOR_FILE = ROOT / ".codex-run/mesh/v10-redeploy-20260920/execute_plan.py"


def _load_executor() -> type:
    spec = importlib.util.spec_from_file_location("mycomesh_v10_serving_executor", EXECUTOR_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load durable V10 executor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Executor


Executor = _load_executor()


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError(f"unsafe Provider identity file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Provider identity is not an object")
    return value


def _provider_key() -> bytes:
    if IDENTITY_FILE.is_symlink() or not IDENTITY_FILE.is_file() or stat.S_IMODE(IDENTITY_FILE.stat().st_mode) & 0o077:
        raise RuntimeError(f"unsafe Provider key file: {IDENTITY_FILE}")
    key = chain.parse_private_key(IDENTITY_FILE.read_text(encoding="ascii").strip())
    address = chain.private_key_to_address(key)
    if address != chain.normalize_address(PROVIDER_OWNER):
        raise RuntimeError("provider1 owner key does not match the serving identity")
    return key


def _rpc(method: str, params: list[Any]) -> Any:
    return chain.rpc_call(RPC_URL, method, params, 30.0)


def _uint(target: str, signature: str, args: list[str]) -> int:
    data = chain.encode_contract_call(signature, args)
    result = _rpc("eth_call", [{"to": chain.normalize_address(target), "data": data}, "latest"])
    if not isinstance(result, str) or not result.startswith("0x") or len(result) < 66:
        raise RuntimeError(f"malformed {signature} response")
    return int(result[-64:], 16)


def _bool(target: str, signature: str, args: list[str]) -> bool:
    value = _uint(target, signature, args)
    if value not in (0, 1):
        raise RuntimeError(f"non-canonical boolean from {signature}")
    return value == 1


def _action(name: str, target: str, data: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "sender": chain.normalize_address(PROVIDER_OWNER),
        "target": chain.normalize_address(target),
        "data": data,
        "description": description,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    fd = temporary.open("wb", 0o600)
    try:
        fd.write(encoded)
        fd.flush()
        import os
        os.fsync(fd.fileno())
    finally:
        fd.close()
    temporary.replace(path)
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true", help="broadcast the reviewed bounded initialization")
    args = parser.parse_args()

    if _rpc("eth_chainId", []) != hex(CHAIN_ID):
        raise RuntimeError("wrong chain for serving Provider initialization")
    genesis = _rpc("eth_getBlockByNumber", ["0x0", False])
    if str(genesis.get("hash", "")).lower() != GENESIS_HASH.lower():
        raise RuntimeError("wrong Sepolia genesis")
    owner = chain.normalize_address(PROVIDER_OWNER)
    signer = chain.normalize_address(PROVIDER_SIGNER)
    settlement = chain.normalize_address(SETTLEMENT)
    token = chain.normalize_address(STABLECOIN)
    key = _provider_key()

    stake = _uint(settlement, "providerStake(address)", [owner])
    locked = _uint(settlement, "lockedStake(address)", [owner])
    allocated = _uint(settlement, "allocatedStake(address)", [owner])
    free_stake = stake - locked - allocated
    token_balance = _uint(token, "balanceOf(address)", [owner])
    allowance = _uint(token, "allowance(address,address)", [owner, settlement])
    authorized = _bool(settlement, "providerSigners(address,address)", [owner, signer])
    deficit = max(0, CAPACITY_TOTAL - free_stake)
    mint_amount = max(0, deficit - token_balance)

    actions: list[dict[str, Any]] = []
    if mint_amount:
        actions.append(_action(
            "serving-provider1-mint-test-usdc",
            token,
            chain.encode_contract_call("mint(address,uint256)", [owner, str(mint_amount)]),
            f"mint exactly {mint_amount} controlled-test stablecoin units for provider1 stake",
        ))
    if deficit and allowance < deficit:
        actions.append(_action(
            "serving-provider1-approve-stake",
            token,
            chain.encode_contract_call("approve(address,uint256)", [settlement, str(deficit)]),
            f"approve {deficit} stablecoin units for provider1 stake",
        ))
    if deficit:
        actions.append(_action(
            "serving-provider1-deposit-stake",
            settlement,
            chain.encode_contract_call("depositStake(uint256)", [str(deficit)]),
            f"deposit {deficit} stablecoin units as provider1 free capacity",
        ))
    if not authorized:
        actions.append(_action(
            "serving-provider1-authorize-signer",
            settlement,
            chain.encode_contract_call("authorizeProviderSigner(address)", [signer]),
            "authorize provider1 remote receipt signer",
        ))

    plan = {
        "schema": "mycomesh.v10.serving-provider1-preparation.v1",
        "chain_id": CHAIN_ID,
        "genesis_hash": GENESIS_HASH,
        "stablecoin": token,
        "settlement": settlement,
        "provider_owner": owner,
        "provider_signer": signer,
        "capacity_target": CAPACITY_TOTAL,
        "preflight": {
            "stake": stake,
            "locked": locked,
            "allocated": allocated,
            "free_stake": free_stake,
            "token_balance": token_balance,
            "allowance": allowance,
            "signer_authorized": authorized,
            "mint_amount": mint_amount,
            "deficit": deficit,
        },
        "actions": actions,
    }
    _write_json(PLAN_FILE, plan)

    executor = Executor(
        RPC_URL,
        {"chain_id": CHAIN_ID, "genesis_hash": GENESIS_HASH, "confirmations": CONFIRMATIONS},
        OUTBOX,
    )
    results: list[dict[str, Any]] = []
    try:
        for action in actions:
            operation = executor.operation(
                action["name"], action["sender"], action["target"], action["data"], kind="initialize",
            )
            if not args.send:
                results.append({
                    "name": action["name"],
                    "description": action["description"],
                    "dry_run": True,
                    "operation_hash": operation["plan_hash"],
                    "from": operation["transaction"]["from"],
                    "to": operation["transaction"]["to"],
                })
                continue
            result = executor.execute(
                operation,
                allow_send=args.send,
                approved_hash=operation["plan_hash"] if args.send else None,
                signing_key=key,
            )
            if args.send:
                while result["state"] not in ("confirmed", "reverted"):
                    import time
                    time.sleep(5)
                    result = executor.reconcile(operation["plan_hash"])
                if result["state"] != "confirmed":
                    raise RuntimeError(f"transaction reverted for {action['name']}")
            results.append({"name": action["name"], "description": action["description"], **result})
    finally:
        executor.close()
    _write_json(PLAN_FILE, {**plan, "results": results, "sent": args.send})
    print(json.dumps({"sent": args.send, "actions": results, "preflight": plan["preflight"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"stopped": True, "error_type": type(exc).__name__, "message": str(exc)[:240]}))
        raise SystemExit(1)
