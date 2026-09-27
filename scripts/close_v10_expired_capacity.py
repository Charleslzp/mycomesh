#!/usr/bin/env python3
"""Close expired dynamic V10 capacity channels through the durable executor.

This is intentionally a separate rotation step: closing an expired channel
returns its unused Consumer credit and Provider stake before a new batch is
opened. It never closes an active channel and never sends outside the durable
executor journal.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import chain, chain_v10  # noqa: E402

RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
POLICY = {
    "chain_id": 11_155_111,
    "genesis_hash": "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9",
    "confirmations": 6,
}
DEPLOYMENT = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
ROLES = ROOT / ".mycomesh/v10/roles.json"
OUTBOX = ROOT / ".mycomesh/v10/capacity-close.sqlite3"
KEY_FILE = ROOT / ".mycomesh/v10/roles/deployer.key"
EXECUTOR_FILE = ROOT / ".codex-run/mesh/v10-redeploy-20260920/execute_plan.py"


def _load_executor():
    spec = importlib.util.spec_from_file_location("mycomesh_v10_capacity_executor", EXECUTOR_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load durable V10 executor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Executor


def _words(value: str, count: int) -> list[str]:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 2 + count * 64:
        raise RuntimeError("malformed channelInfo response")
    return [value[index : index + 64] for index in range(2, len(value), 64)]


def _channel_info(executor, settlement: str, channel_id: str) -> dict[str, int | bool]:
    data = chain.encode_contract_call("channelInfo(bytes32)", [channel_id])
    words = _words(executor.rpc("eth_call", [{"to": settlement, "data": data}, "latest"]), 22)
    return {
        "capacity": int(words[10], 16),
        "claim_until": int(words[14], 16),
        "closed": int(words[21], 16) == 1,
        "credit_remaining": int(words[19], 16),
        "stake_remaining": int(words[20], 16),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true", help="broadcast reviewed close operations")
    parser.add_argument("--rpc", default=RPC_URL)
    args = parser.parse_args()
    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    roles = json.loads(ROLES.read_text(encoding="utf-8"))
    settlement = chain.normalize_address(deployment["settlement"])
    sender = chain.normalize_address(roles["addresses"]["deployer"])
    if sender != chain.normalize_address(deployment["deployer"]):
        raise RuntimeError("deployer role does not match deployment manifest")
    ids = deployment.get("capacity_channel_ids")
    if not isinstance(ids, list) or not ids:
        raise RuntimeError("dynamic deployment has no capacity channel IDs")
    Executor = _load_executor()
    executor = Executor(args.rpc, POLICY, OUTBOX)
    results: list[dict[str, object]] = []
    try:
        head = executor.rpc("eth_getBlockByNumber", ["latest", False])
        now = int(head["timestamp"], 16)
        for index, channel_id in enumerate(ids):
            channel_id = chain.normalize_bytes32(channel_id)
            info = _channel_info(executor, settlement, channel_id)
            if info["capacity"] == 0:
                raise RuntimeError(f"capacity channel {channel_id} does not exist")
            if info["closed"]:
                results.append({"channel_id": channel_id, "state": "already_closed", **info})
                continue
            if now <= int(info["claim_until"]):
                raise RuntimeError(f"capacity channel {channel_id} has not expired")
            operation = executor.operation(
                f"close-expired-v10-capacity-{index}",
                sender,
                settlement,
                chain_v10.encode_close_expired_channel(channel_id),
                kind="initialize",
            )
            result = executor.execute(
                operation,
                allow_send=args.send,
                approved_hash=operation["plan_hash"] if args.send else None,
                key_file=str(KEY_FILE) if args.send else None,
            )
            if args.send:
                while result["state"] not in ("confirmed", "reverted"):
                    time.sleep(5)
                    result = executor.reconcile(operation["plan_hash"])
                if result["state"] != "confirmed":
                    raise RuntimeError(f"close operation reverted for {channel_id}")
            results.append({"channel_id": channel_id, "state": result.get("state", "dry_run"), **info})
    finally:
        executor.close()
    print(json.dumps({"sent": args.send, "settlement": settlement, "channels": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
