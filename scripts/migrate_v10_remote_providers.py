#!/usr/bin/env python3
"""Authorize the three existing remote Provider identities on the new V10 Settlement.

This is a deliberately small, durable migration.  It never copies a Provider
private key to a remote host and never writes private key material to the
journal.  A transaction hash is recorded before broadcast; an uncertain send
is reconciled by hash on the next run instead of being recreated.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.chain import (
    ChainError,
    encode_contract_call,
    estimate_gas,
    keccak256,
    legacy_gas_price,
    normalize_address,
    normalize_bytes32,
    parse_private_key,
    private_key_to_address,
    rpc_call,
    rpc_int,
    sign_legacy_transaction,
)
from gateway.chain_v8 import provider_signer_authorized


ROOT = Path(__file__).resolve().parents[1]
RPC = ",".join(
    (
        "https://rpc.sepolia.ethpandaops.io",
        "https://sepolia.gateway.tenderly.co",
        "https://ethereum-sepolia-rpc.publicnode.com",
    )
)
CHAIN_ID = 11_155_111
SETTLEMENT = "0x31d3f0a17c6c6f4594a2f9ffeebf72c41f9e1c3a"
DEPLOYER = "0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1"
TARGET_OWNER_BALANCE = 3_000_000_000_000_000  # 0.003 ETH, gas only
MAX_FUNDING_PER_OWNER = 4_000_000_000_000_000
MAX_GAS_COST_PER_STEP = 2_000_000_000_000_000
CONFIRMATIONS = 6
JOURNAL = ROOT / ".mycomesh/v10/provider-owner-migration.json"
IDENTITY_DIR = ROOT / ".codex-run/mesh/v10-dynamic-provider-jury-20260923/identities"
PROVIDERS = {
    "provider2": {
        "owner_file": IDENTITY_DIR / "provider2-owner.json",
        "signer": "0x6b21fd92347f055802434f83685f8089dfb943c8",
    },
    "provider3": {
        "owner_file": IDENTITY_DIR / "provider3-owner.json",
        "signer": "0x4d5100e6b1b05994bd5ee8e17dc94255e7af1e5f",
    },
    "provider4": {
        "owner_file": IDENTITY_DIR / "provider4-owner.json",
        "signer": "0xf3217abadf55b970fd029cc17beabc1cc12b099b",
    },
}


def _protected_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"protected key is not a regular file: {path}")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError(f"protected key permissions are too broad: {path}")
    return path.read_text(encoding="ascii").strip()


def _read_key(path: Path, *, json_field: str | None = None) -> bytes:
    raw = _protected_text(path)
    if json_field is not None:
        try:
            value = json.loads(raw)
            raw = str(value[json_field])
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError(f"invalid protected identity file: {path}") from exc
    return parse_private_key(raw)


def _atomic_write(value: dict) -> None:
    JOURNAL.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=JOURNAL.name + ".", dir=JOURNAL.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, JOURNAL)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load_journal() -> dict:
    if not JOURNAL.exists():
        return {
            "schema": "mycomesh.v10.remote-provider-migration.v1",
            "chain_id": CHAIN_ID,
            "settlement": normalize_address(SETTLEMENT),
            "deployer": normalize_address(DEPLOYER),
            "steps": {},
        }
    if JOURNAL.is_symlink() or stat.S_IMODE(JOURNAL.stat().st_mode) & 0o077:
        raise RuntimeError("migration journal is not protected")
    value = json.loads(JOURNAL.read_text(encoding="utf-8"))
    expected = (CHAIN_ID, normalize_address(SETTLEMENT), normalize_address(DEPLOYER))
    actual = (value.get("chain_id"), value.get("settlement"), value.get("deployer"))
    if actual != expected or value.get("schema") != "mycomesh.v10.remote-provider-migration.v1":
        raise RuntimeError("migration journal scope does not match the new V10 deployment")
    if not isinstance(value.get("steps"), dict):
        raise RuntimeError("migration journal steps are invalid")
    return value


def _receipt(tx_hash: str, timeout: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = rpc_call(RPC, "eth_getTransactionReceipt", [tx_hash], 20)
        if value:
            if int(value.get("status", "0x0"), 16) != 1:
                raise RuntimeError(f"transaction reverted: {tx_hash}")
            return value
        time.sleep(4)
    raise RuntimeError(f"receipt is still unknown; do not recreate transaction: {tx_hash}")


def _confirm(receipt: dict) -> None:
    block = int(receipt["blockNumber"], 16)
    required = block + CONFIRMATIONS - 1
    deadline = time.monotonic() + 240
    while rpc_int(RPC, "eth_blockNumber", [], 20) < required:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"confirmation wait incomplete at block {block}")
        time.sleep(6)


def _reconcile(step: str, expected: dict, journal: dict) -> bool:
    record = journal["steps"].get(step)
    if record is None:
        return False
    for key in ("from", "to", "value", "data", "nonce"):
        if record.get(key) != expected.get(key):
            raise RuntimeError(f"journal scope mismatch for {step}: {key}")
    receipt = _receipt(record["tx_hash"])
    record["status"] = "confirmed"
    record["receipt"] = receipt
    _confirm(receipt)
    record["confirmations_verified"] = True
    _atomic_write(journal)
    print(json.dumps({"step": step, "tx_hash": record["tx_hash"], "reconciled": True}))
    return True


def _send(step: str, private_key: bytes, to: str, value: int, data: str, journal: dict) -> str:
    sender = normalize_address(private_key_to_address(private_key))
    target = normalize_address(to)
    pending = rpc_int(RPC, "eth_getTransactionCount", [sender, "pending"], 20)
    latest = rpc_int(RPC, "eth_getTransactionCount", [sender, "latest"], 20)
    if pending != latest:
        raise RuntimeError(f"{sender} has an unrelated pending transaction; refusing nonce collision")
    gas_price = legacy_gas_price(RPC, 20)
    gas = estimate_gas(RPC, sender, target, data, 20)
    if gas > 300_000:
        raise RuntimeError(f"gas estimate exceeds migration bound for {step}")
    cost = gas * gas_price
    if cost > MAX_GAS_COST_PER_STEP:
        raise RuntimeError(f"gas cost exceeds migration bound for {step}")
    balance = rpc_int(RPC, "eth_getBalance", [sender, "latest"], 20)
    if balance < value + cost:
        raise RuntimeError(f"insufficient ETH for {step}")
    raw = sign_legacy_transaction(
        private_key, pending, gas_price, gas, target, value,
        bytes.fromhex(data[2:]), CHAIN_ID,
    )
    tx_hash = normalize_bytes32("0x" + keccak256(raw).hex())
    record = {
        "tx_hash": tx_hash, "from": sender, "to": target, "value": value,
        "data": data, "nonce": pending, "gas": gas, "gas_price": gas_price,
        "status": "prepared",
    }
    journal["steps"][step] = record
    _atomic_write(journal)
    result = rpc_call(RPC, "eth_sendRawTransaction", ["0x" + raw.hex()], 30)
    if normalize_bytes32(str(result)) != tx_hash:
        raise RuntimeError(f"RPC returned an unexpected transaction hash for {step}")
    record["status"] = "broadcast"
    _atomic_write(journal)
    print(json.dumps({"step": step, "tx_hash": tx_hash, "broadcast": True}))
    receipt = _receipt(tx_hash)
    record["status"] = "confirmed"
    record["receipt"] = receipt
    _atomic_write(journal)
    _confirm(receipt)
    record["confirmations_verified"] = True
    _atomic_write(journal)
    print(json.dumps({"step": step, "tx_hash": tx_hash, "confirmed": True}))
    return tx_hash


def main() -> int:
    deployer_key = _read_key(ROOT / ".mycomesh/v10/roles/deployer.key")
    if normalize_address(private_key_to_address(deployer_key)) != normalize_address(DEPLOYER):
        raise RuntimeError("deployer key does not match the new deployment")
    owner_keys: dict[str, bytes] = {}
    for name, item in PROVIDERS.items():
        key = _read_key(item["owner_file"], json_field="private_key")
        owner = normalize_address(private_key_to_address(key))
        expected_owner = normalize_address(json.loads(item["owner_file"].read_text())["address"])
        if owner != expected_owner:
            raise RuntimeError(f"{name} identity file address mismatch")
        owner_keys[name] = key

    if rpc_int(RPC, "eth_chainId", [], 20) != CHAIN_ID:
        raise RuntimeError("RPC chain id is not Sepolia")
    if rpc_call(RPC, "eth_getCode", [SETTLEMENT, "latest"], 20) in ("0x", "0x0"):
        raise RuntimeError("new V10 Settlement has no runtime code")
    journal = _load_journal()

    for name, item in PROVIDERS.items():
        owner = normalize_address(private_key_to_address(owner_keys[name]))
        current = rpc_int(RPC, "eth_getBalance", [owner, "latest"], 20)
        base_step = "fund-" + name
        record = journal["steps"].get(base_step)
        # A prepared/broadcast funding transaction must be reconciled by its
        # original value and nonce.  A confirmed funding transaction, however,
        # may have been partially consumed by the Provider's later gas spend;
        # never compare it with a newly computed top-up amount.
        if record and record.get("status") in {"prepared", "broadcast"}:
            expected = {
                "from": normalize_address(DEPLOYER), "to": owner,
                "value": record.get("value"), "data": record.get("data", "0x"),
                "nonce": record.get("nonce"),
            }
            _reconcile(base_step, expected, journal)
            current = rpc_int(RPC, "eth_getBalance", [owner, "latest"], 20)
        if current < TARGET_OWNER_BALANCE:
            value = TARGET_OWNER_BALANCE - current
            if value > MAX_FUNDING_PER_OWNER:
                raise RuntimeError(f"funding bound exceeded for {name}")
            if record and record.get("status") == "confirmed":
                index = 1
                step = f"{base_step}-topup-{index}"
                while step in journal["steps"]:
                    index += 1
                    step = f"{base_step}-topup-{index}"
            else:
                step = base_step
            _send(step, deployer_key, owner, value, "0x", journal)
        else:
            print(json.dumps({"step": base_step, "skipped": True}))

    for name, item in PROVIDERS.items():
        owner = normalize_address(private_key_to_address(owner_keys[name]))
        signer = normalize_address(item["signer"])
        if provider_signer_authorized(RPC, SETTLEMENT, owner, signer, timeout=20):
            print(json.dumps({"provider": name, "owner": owner, "signer": signer, "already_authorized": True}))
            continue
        step = "authorize-" + name
        data = encode_contract_call("authorizeProviderSigner(address)", [signer])
        existing = journal["steps"].get(step)
        if existing:
            expected = {"from": owner, "to": normalize_address(SETTLEMENT),
                        "value": 0, "data": data, "nonce": existing.get("nonce")}
            _reconcile(step, expected, journal)
        else:
            _send(step, owner_keys[name], SETTLEMENT, 0, data, journal)
        if not provider_signer_authorized(RPC, SETTLEMENT, owner, signer, timeout=20):
            raise RuntimeError(f"authorization postcondition failed for {name}")
        print(json.dumps({"provider": name, "owner": owner, "signer": signer, "authorized": True}))

    journal["completed_at"] = int(time.time())
    _atomic_write(journal)
    print(json.dumps({"complete": True, "settlement": normalize_address(SETTLEMENT), "providers_authorized": 3}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ChainError, OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"stopped": True, "error_type": type(exc).__name__, "message": str(exc)[:240]}))
        raise SystemExit(1)
