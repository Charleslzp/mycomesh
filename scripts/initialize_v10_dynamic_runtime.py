#!/usr/bin/env python3
"""Initialize the new dynamic V10 runtime with a durable, idempotent outbox.

The script deliberately does not open capacity channels.  Channel permits pin
the live Relay payment and attestation addresses, so opening is gated on a
separate authenticated Relay/Bridge cutover evidence file.  This phase only
funds the three registered Providers and the Consumer and registers the
Consumer's existing payment key.

Read-only is the default.  Sending requires ``--send``; every transaction is
written to the shared V9 transaction outbox before broadcast and is reconciled
to six Sepolia confirmations before the next transaction from that sender is
allocated.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sqlite3
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import chain, chain_v9  # noqa: E402
from gateway.relay_incidents import evidence_hash  # noqa: E402


RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
CHAIN_ID = 11_155_111
GENESIS_HASH = "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"
CONFIRMATIONS = 6
STABLECOIN = "0xeb487c6e778248e16361dc313e4223c20d4c23b5"
SETTLEMENT = "0x31d3f0a17c6c6f4594a2f9ffeebf72c41f9e1c3a"
CONSUMER_OWNER = "0x8ac07c0ff3d1e6af7543b2d947f031f59fa8b99b"
CONSUMER_KEY = "0x5e69a109b24e623da7af21d0137f942e6f3a65d4"
DEPLOYER = "0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1"
PROVIDERS = (
    ("provider2", "0xabed1bf15451cff479c6b41bf24817437256eb00"),
    ("provider3", "0xc1c5038c26de3ba5fc305e5d280915c3b7256cda"),
    ("provider4", "0xa88182a20e597a3379f93b6273516fb377325333"),
)
CAPACITY_EACH = 1_000_000
CONSUMER_DEPOSIT = 3_000_000
KEY_MAX_FEE = 100_000
CONSUMER_GAS_TOPUP_WEI = 10_000_000_000_000_000
ROLES_DIR = ROOT / ".mycomesh/v10/roles"
CONSUMER_KEY_FILE = ROOT / ".codex-run/mesh/v9-controlled-test-20260918/wallets/consumer-key.key"
IDENTITY_DIR = ROOT / ".codex-run/mesh/v10-dynamic-provider-jury-20260923/identities"
OUTBOX = ROOT / ".mycomesh/v10/runtime-initialization.sqlite3"
PLAN_FILE = ROOT / ".mycomesh/v10/runtime-initialization-plan.json"
EXECUTOR_FILE = ROOT / ".codex-run/mesh/v10-redeploy-20260920/execute_plan.py"


def _load_executor() -> type:
    spec = importlib.util.spec_from_file_location("mycomesh_v10_initialization_executor", EXECUTOR_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load durable V10 executor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Executor


Executor = _load_executor()


def _protected_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600):
        raise RuntimeError(f"unsafe private key file: {path}")
    raw = path.read_text(encoding="ascii").strip()
    key = chain.parse_private_key(raw)
    return key


def _identity_key(path: Path, expected_address: str) -> bytes:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600):
        raise RuntimeError(f"unsafe Provider identity file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    key = chain.parse_private_key(str(value.get("private_key") or ""))
    derived = chain.private_key_to_address(key)
    if derived != chain.normalize_address(expected_address):
        raise RuntimeError(f"Provider identity does not match its owner: {path}")
    if chain.normalize_address(str(value.get("address") or "")) != derived:
        raise RuntimeError(f"Provider identity address is inconsistent: {path}")
    return key


def _rpc(method: str, params: list[Any]) -> Any:
    return chain.rpc_call(RPC_URL, method, params, 30.0)


def _uint_call(target: str, signature: str, args: list[str]) -> int:
    data = chain.encode_contract_call(signature, args)
    result = _rpc("eth_call", [{"to": chain.normalize_address(target), "data": data}, "latest"])
    if not isinstance(result, str) or not result.startswith("0x") or len(result) < 66:
        raise RuntimeError(f"malformed {signature} response")
    return int(result[-64:], 16)


def _erc20_balance(owner: str) -> int:
    return _uint_call(STABLECOIN, "balanceOf(address)", [owner])


def _allowance(owner: str, spender: str) -> int:
    return _uint_call(STABLECOIN, "allowance(address,address)", [owner, spender])


def _confirmed_operation(name: str) -> bool:
    """Use the local durable journal to distinguish our sponsorship from manual stake."""
    if not OUTBOX.exists():
        return False
    db = sqlite3.connect(OUTBOX)
    try:
        row = db.execute(
            "SELECT state FROM v9_operator_transactions WHERE plan_hash IN "
            "(SELECT plan_hash FROM v10_operation_names WHERE name=?)",
            (name,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    finally:
        db.close()
    return bool(row and row[0] == "confirmed")


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    os.chmod(path, 0o600)


def _plan_action(name: str, sender: str, target: str, data: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "sender": chain.normalize_address(sender),
        "target": chain.normalize_address(target),
        "data": data,
        "description": description,
    }


def _plan_value_action(name: str, sender: str, target: str, value_wei: int, description: str) -> dict[str, Any]:
    return {
        "kind": "value_transfer",
        "name": name,
        "sender": chain.normalize_address(sender),
        "target": chain.normalize_address(target),
        "data": "0x",
        "value_wei": int(value_wei),
        "description": description,
    }


def _execute_value_transfer(action: dict[str, Any], *, key_file: Path, send: bool) -> dict[str, Any]:
    """Durably send one bounded native-token top-up using the same outbox schema."""
    from gateway.relay_adjudication_v9 import V9TransactionOutbox, _protected_key

    tx = {
        "from": action["sender"],
        "to": action["target"],
        "data": "0x",
        "value": int(action["value_wei"]),
        "chain_id": CHAIN_ID,
    }
    op = {
        "schema": "mycomesh.v10.value-transfer.v1",
        "name": action["name"],
        "kind": "initialize",
        "transaction": tx,
        "genesis_hash": GENESIS_HASH,
        "confirmations": CONFIRMATIONS,
        "max_gas_cost_wei": 200_000_000_000_000,
    }
    op["plan_hash"] = evidence_hash(op)
    outbox = V9TransactionOutbox(OUTBOX)
    try:
        old = outbox.db.execute("SELECT plan_hash FROM v10_operation_names WHERE name=?", (action["name"],)).fetchone()
        if old and old["plan_hash"] != op["plan_hash"]:
            raise RuntimeError("gas top-up operation name is bound to a different plan")
        if old:
            row = outbox.get(op["plan_hash"])
            if row is None:
                raise RuntimeError("gas top-up journal is incomplete")
            return {"name": action["name"], "description": action["description"], **row}
        if not send:
            return {
                "name": action["name"], "description": action["description"], "dry_run": True,
                "operation_hash": op["plan_hash"], "from": tx["from"], "to": tx["to"],
                "value_wei": tx["value"],
            }
        if _rpc("eth_chainId", []) != hex(CHAIN_ID):
            raise RuntimeError("wrong chain for gas top-up")
        sender = tx["from"]
        latest = int(_rpc("eth_getTransactionCount", [sender, "latest"]), 16)
        pending = int(_rpc("eth_getTransactionCount", [sender, "pending"]), 16)
        if latest != pending:
            raise RuntimeError("deployer has an external pending nonce")
        blocked = outbox.db.execute(
            "SELECT 1 FROM v9_operator_transactions WHERE scope=? AND sender=? AND state NOT IN ('confirmed','reverted')",
            (f"{GENESIS_HASH}:{CHAIN_ID}", sender),
        ).fetchone()
        if blocked:
            raise RuntimeError("deployer has an unresolved transaction")
        head = _rpc("eth_getBlockByNumber", ["latest", False])
        price = max(int(_rpc("eth_gasPrice", []), 16), int(head.get("baseFeePerGas", "0x0"), 16) * 5 // 4 + 100_000_000)
        estimate = int(_rpc("eth_estimateGas", [{"from": sender, "to": tx["to"], "value": hex(tx["value"]), "data": "0x"}]), 16)
        gas = max(21_000, estimate * 12 // 10 + 5_000)
        if price > 5_000_000_000 or gas > 50_000 or gas * price > op["max_gas_cost_wei"]:
            raise RuntimeError("gas top-up fee exceeds fixed cap")
        if int(_rpc("eth_getBalance", [sender, "latest"]), 16) < tx["value"] + gas * price:
            raise RuntimeError("deployer lacks native balance for gas top-up")
        key = _protected_key(key_file)
        if chain.private_key_to_address(key) != sender:
            raise RuntimeError("gas top-up key does not match deployer")
        raw = chain.sign_legacy_transaction(key, latest, price, gas, tx["to"], tx["value"], b"", CHAIN_ID)
        tx_hash = "0x" + chain.keccak256(raw).hex()
        raw_hex = "0x" + raw.hex()
        scope = f"{GENESIS_HASH}:{CHAIN_ID}"
        outbox.db.execute("BEGIN IMMEDIATE")
        try:
            outbox.db.execute(
                "INSERT INTO v9_operator_transactions VALUES (?,?,?,?,?,?,?,'sending',NULL,?)",
                (op["plan_hash"], scope, sender, latest, tx_hash, raw_hex,
                 json.dumps(op, sort_keys=True, separators=(",", ":")), int(time.time())),
            )
            outbox.db.execute("INSERT INTO v10_operation_names VALUES (?,?)", (action["name"], op["plan_hash"]))
            outbox.db.commit()
        except BaseException:
            outbox.db.rollback()
            raise
        try:
            returned = _rpc("eth_sendRawTransaction", [raw_hex])
            state = "submitted" if returned.lower() == tx_hash else "uncertain"
        except Exception:
            state = "uncertain"
        outbox.db.execute("UPDATE v9_operator_transactions SET state=? WHERE plan_hash=?", (state, op["plan_hash"]))
        result = outbox.get(op["plan_hash"])
        if result is None:
            raise RuntimeError("gas top-up journal disappeared")
        while result["state"] not in ("confirmed", "reverted"):
            time.sleep(5)
            receipt = _rpc("eth_getTransactionReceipt", [tx_hash])
            next_state = "uncertain"
            if receipt:
                block = _rpc("eth_getBlockByNumber", [receipt["blockNumber"], False])
                head_number = int(_rpc("eth_blockNumber", []), 16)
                actual = _rpc("eth_getTransactionByHash", [tx_hash])
                if (actual and actual["from"].lower() == sender and actual["to"].lower() == tx["to"]
                        and int(actual["nonce"], 16) == latest and int(actual["value"], 16) == tx["value"]
                        and actual["input"] == "0x" and block["hash"].lower() == receipt["blockHash"].lower()):
                    next_state = "confirmed" if (
                        head_number - int(receipt["blockNumber"], 16) + 1 >= CONFIRMATIONS
                        and receipt.get("status") == "0x1"
                    ) else "submitted"
                    if receipt.get("status") != "0x1" and head_number - int(receipt["blockNumber"], 16) + 1 >= CONFIRMATIONS:
                        next_state = "reverted"
            outbox.db.execute("UPDATE v9_operator_transactions SET state=?,receipt_json=? WHERE plan_hash=?",
                              (next_state, json.dumps(receipt, sort_keys=True) if receipt else None, op["plan_hash"]))
            result = outbox.get(op["plan_hash"])
        if result["state"] != "confirmed":
            raise RuntimeError("gas top-up reverted")
        return {"name": action["name"], "description": action["description"], **result}
    finally:
        outbox.close()


def _wait_for_confirmation(executor: Any, operation: dict[str, Any], *, key_file: Path | None,
                           signing_key: bytes | None, send: bool) -> dict[str, Any]:
    if key_file is not None and signing_key is not None:
        raise RuntimeError("choose one signing source")
    result = executor.execute(
        operation,
        allow_send=send,
        approved_hash=operation["plan_hash"] if send else None,
        key_file=str(key_file) if key_file else None,
        signing_key=signing_key,
    )
    if not send:
        return result
    while result["state"] not in ("confirmed", "reverted"):
        time.sleep(5)
        result = executor.reconcile(operation["plan_hash"])
    if result["state"] != "confirmed":
        raise RuntimeError(f"transaction reverted for {operation['name']}")
    return result


def _execute_action(executor: Any, action: dict[str, Any], *, key_file: Path | None,
                    signing_key: bytes | None, send: bool) -> dict[str, Any]:
    operation = executor.operation(
        action["name"], action["sender"], action["target"], action["data"], kind="initialize",
    )
    if not send:
        return {
            "name": action["name"],
            "description": action["description"],
            "dry_run": True,
            "operation_hash": operation["plan_hash"],
            "from": operation["transaction"]["from"],
            "to": operation["transaction"]["to"],
        }
    result = _wait_for_confirmation(
        executor, operation, key_file=key_file, signing_key=signing_key, send=send,
    )
    return {"name": action["name"], "description": action["description"], **result}


def _state() -> dict[str, Any]:
    providers: list[dict[str, Any]] = []
    for name, owner in PROVIDERS:
        owner = chain.normalize_address(owner)
        providers.append({
            "name": name,
            "owner": owner,
            "stake": chain_v9.provider_stake_status(RPC_URL, SETTLEMENT, owner)["stake"],
            "journal_sponsored": _confirmed_operation(f"funding-sponsor-{name}"),
        })
    grant = chain_v9.key_grant(RPC_URL, SETTLEMENT, CONSUMER_KEY)
    return {
        "deployer_eth_balance": int(_rpc("eth_getBalance", [DEPLOYER, "latest"]), 16),
        "consumer_eth_balance": int(_rpc("eth_getBalance", [CONSUMER_OWNER, "latest"]), 16),
        "deployer_token_balance": _erc20_balance(DEPLOYER),
        "deployer_settlement_allowance": _allowance(DEPLOYER, SETTLEMENT),
        "consumer_token_balance": _erc20_balance(CONSUMER_OWNER),
        "consumer_settlement_allowance": _allowance(CONSUMER_OWNER, SETTLEMENT),
        "consumer_available_balance": chain_v9.account_balance(RPC_URL, SETTLEMENT, CONSUMER_OWNER),
        "consumer_key_grant": grant,
        "providers": providers,
    }


def _validate_state(state: dict[str, Any]) -> tuple[int, dict[str, int]]:
    deficits: dict[str, int] = {}
    for item in state["providers"]:
        stake = int(item["stake"])
        if item["journal_sponsored"]:
            if stake != CAPACITY_EACH:
                raise RuntimeError(
                    f"provider {item['name']} changed after its sponsored-capacity transaction; manual reconciliation required"
                )
        elif stake != 0:
            raise RuntimeError(
                f"provider {item['name']} has unjournaled stake; refusing to mix funds"
            )
        deficits[item["owner"]] = CAPACITY_EACH - stake
    total = sum(deficits.values())
    if state["deployer_token_balance"] < total:
        raise RuntimeError("deployer stablecoin balance cannot cover Provider sponsorship")
    if state["deployer_token_balance"] - total < 0:
        raise RuntimeError("invalid negative post-sponsorship balance")
    return total, deficits


def _build_actions(state: dict[str, Any], deficits: dict[str, int], total_sponsorship: int) -> list[tuple[dict[str, Any], Path | None, bytes | None]]:
    actions: list[tuple[dict[str, Any], Path | None, bytes | None]] = []
    deployer_key = ROLES_DIR / "deployer.key"
    consumer_owner_key = ROLES_DIR / "consumer.key"
    if total_sponsorship and state["deployer_settlement_allowance"] < total_sponsorship:
        actions.append((
            _plan_action(
                "funding-approve-provider-capacity",
                DEPLOYER,
                STABLECOIN,
                chain.encode_contract_call("approve(address,uint256)", [SETTLEMENT, str(total_sponsorship)]),
                f"approve {total_sponsorship} stablecoin units for Provider sponsorship",
            ),
            deployer_key,
            None,
        ))
    if total_sponsorship:
        actions.append((
            _plan_action(
                "funding-set-sponsored-capacity-limit",
                DEPLOYER,
                SETTLEMENT,
                chain.encode_contract_call("setSponsoredCapacityLimit(uint256)", [str(total_sponsorship)]),
                f"set the bounded network-sponsored capacity limit to {total_sponsorship} units",
            ),
            deployer_key,
            None,
        ))
        for name, owner in PROVIDERS:
            owner = chain.normalize_address(owner)
            amount = deficits[owner]
            if not amount:
                continue
            provider_key_file = IDENTITY_DIR / f"{name}-owner.json"
            provider_key = _identity_key(provider_key_file, owner)
            actions.append((
                _plan_action(
                    f"funding-sponsor-{name}",
                    DEPLOYER,
                    SETTLEMENT,
                    chain.encode_contract_call("sponsorProviderCapacity(address,uint256)", [owner, str(amount)]),
                    f"sponsor {amount} stablecoin units for {name}",
                ),
                deployer_key,
                None,
            ))

    consumer_deficit = max(0, CONSUMER_DEPOSIT - int(state["consumer_available_balance"]))
    if state["consumer_token_balance"] < consumer_deficit:
        transfer_amount = consumer_deficit - int(state["consumer_token_balance"])
        actions.append((
            _plan_action(
                "funding-transfer-consumer",
                DEPLOYER,
                STABLECOIN,
                chain.encode_contract_call("transfer(address,uint256)", [CONSUMER_OWNER, str(transfer_amount)]),
                f"transfer {transfer_amount} stablecoin units to the Consumer owner",
            ),
            deployer_key,
            None,
        ))
    if consumer_deficit and state["consumer_settlement_allowance"] < consumer_deficit:
        if state["consumer_eth_balance"] < 2_000_000_000_000_000:
            actions.append((
                _plan_value_action(
                    "funding-gas-consumer",
                    DEPLOYER,
                    CONSUMER_OWNER,
                    CONSUMER_GAS_TOPUP_WEI,
                    f"top up {CONSUMER_GAS_TOPUP_WEI} wei native gas for Consumer owner transactions",
                ),
                deployer_key,
                None,
            ))
        actions.append((
            _plan_action(
                "funding-approve-consumer-deposit",
                CONSUMER_OWNER,
                STABLECOIN,
                chain.encode_contract_call("approve(address,uint256)", [SETTLEMENT, str(consumer_deficit)]),
                f"approve {consumer_deficit} stablecoin units for Consumer deposit",
            ),
            consumer_owner_key,
            None,
        ))
    if consumer_deficit:
        actions.append((
            _plan_action(
                "funding-deposit-consumer",
                CONSUMER_OWNER,
                SETTLEMENT,
                chain.encode_contract_call("deposit(uint256)", [str(consumer_deficit)]),
                f"deposit {consumer_deficit} stablecoin units for the Consumer",
            ),
            consumer_owner_key,
            None,
        ))
    grant = state["consumer_key_grant"]
    if grant["owner"] == chain.ZERO_ADDRESS or grant["active"] is not True or int(grant["max_per_request"]) < KEY_MAX_FEE:
        actions.append((
            _plan_action(
                "funding-register-consumer-key",
                CONSUMER_OWNER,
                SETTLEMENT,
                chain.encode_contract_call("registerKey(address,uint256,uint64)", [CONSUMER_KEY, str(KEY_MAX_FEE), "0"]),
                f"register Consumer payment key with a {KEY_MAX_FEE}-unit request limit",
            ),
            consumer_owner_key,
            None,
        ))
    return actions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true", help="broadcast after durable preflight")
    args = parser.parse_args()
    state = _state()
    total, deficits = _validate_state(state)
    actions = _build_actions(state, deficits, total)
    plan = {
        "schema": "mycomesh.v10.dynamic-runtime-initialization.v1",
        "chain_id": CHAIN_ID,
        "genesis_hash": GENESIS_HASH,
        "settlement": SETTLEMENT,
        "stablecoin": STABLECOIN,
        "consumer_owner": CONSUMER_OWNER,
        "consumer_key": CONSUMER_KEY,
        "provider_capacity_each": CAPACITY_EACH,
        "consumer_target_balance": CONSUMER_DEPOSIT,
        "actions": [action for action, _, _ in actions],
        "preflight": state,
    }
    _write_json(PLAN_FILE, plan)
    executor = Executor(
        RPC_URL,
        {"chain_id": CHAIN_ID, "genesis_hash": GENESIS_HASH, "confirmations": CONFIRMATIONS},
        OUTBOX,
    )
    results: list[dict[str, Any]] = []
    try:
        for action, key_file, signing_key in actions:
            if action.get("kind") == "value_transfer":
                results.append(_execute_value_transfer(action, key_file=key_file, send=args.send))
            else:
                results.append(_execute_action(
                    executor, action, key_file=key_file, signing_key=signing_key, send=args.send,
                ))
    finally:
        executor.close()
    final_state = _state() if args.send else state
    _write_json(PLAN_FILE, {**plan, "results": results, "postflight": final_state, "sent": args.send})
    print(json.dumps({"sent": args.send, "actions": results, "postflight": final_state}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
