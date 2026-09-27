#!/usr/bin/env python3
"""Bootstrap the new dynamic V10 Registry from the old dynamic Registry.

The source of truth for this one-time migration is the old Registry's
canonical ``ProviderUpdated`` event plus its current ``providerAt`` row.  The
script deliberately does not manufacture settlement/terminal-event proofs;
those remain a separate reputation-history concern.  Every transaction is
journaled before broadcast and is reconciled by its original hash on retry.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import chain
from gateway.provider_reputation_sync import encode_set_provider


ROOT = Path(__file__).resolve().parents[1]
RPCS = (
    "https://sepolia.gateway.tenderly.co",
    "https://sepolia.rpc.thirdweb.com",
)
CHAIN_ID = 11_155_111
CONFIRMATIONS = 6
OLD_REGISTRY = "0x63131df381111022cea6f8adefc64714e83cbfdc"
OLD_REGISTRY_DEPLOYMENT_BLOCK = 11_765_832
NEW_REGISTRY = "0x1f4b01f9138cbf25e646cbc2498f77a12729bae7"
AUTHORITY = "0xc3568672d201c97b6ed08bf0339e0e53638969fd"
DEPLOYER = "0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1"
AUTHORITY_KEY = ROOT / ".mycomesh/v10/roles/reputation-authority.key"
DEPLOYER_KEY = ROOT / ".mycomesh/v10/roles/deployer.key"
JOURNAL = ROOT / ".mycomesh/v10/dynamic-provider-registry-migration.json"
MAX_GAS = 650_000
MAX_GAS_COST = 10_000_000_000_000_000
TARGET_AUTHORITY_BALANCE = 10_000_000_000_000_000
PROVIDER_OWNERS = {
    "0xabed1bf15451cff479c6b41bf24817437256eb00",
    "0xc1c5038c26de3ba5fc305e5d280915c3b7256cda",
    "0xa88182a20e597a3379f93b6273516fb377325333",
}
PROVIDER_UPDATED_TOPIC = "0x" + chain.keccak256(
    b"ProviderUpdated(address,address,bytes32,uint64,bool,uint64,bytes32,uint64)"
).hex()


def _read_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"authority key is not a regular file: {path}")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("authority key permissions are too broad")
    return chain.parse_private_key(path.read_text(encoding="ascii").strip())


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _atomic_write(value: dict[str, Any]) -> None:
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


def _load_journal() -> dict[str, Any]:
    if not JOURNAL.exists():
        return {
            "schema": "mycomesh.v10.dynamic-provider-registry-migration.v1",
            "chain_id": CHAIN_ID,
            "old_registry": chain.normalize_address(OLD_REGISTRY),
            "new_registry": chain.normalize_address(NEW_REGISTRY),
            "authority": chain.normalize_address(AUTHORITY),
            "providers": {},
        }
    if JOURNAL.is_symlink() or stat.S_IMODE(JOURNAL.stat().st_mode) & 0o077:
        raise RuntimeError("migration journal is not protected")
    value = json.loads(JOURNAL.read_text(encoding="utf-8"))
    expected = {
        "schema": "mycomesh.v10.dynamic-provider-registry-migration.v1",
        "chain_id": CHAIN_ID,
        "old_registry": chain.normalize_address(OLD_REGISTRY),
        "new_registry": chain.normalize_address(NEW_REGISTRY),
        "authority": chain.normalize_address(AUTHORITY),
    }
    if any(value.get(key) != expected[key] for key in expected):
        raise RuntimeError("migration journal scope does not match this deployment")
    if not isinstance(value.get("providers"), dict):
        raise RuntimeError("migration journal providers are invalid")
    return value


def _words(data: str) -> list[bytes]:
    raw = bytes.fromhex(data[2:])
    if len(raw) % 32:
        raise RuntimeError("contract return value is not word aligned")
    return [raw[i : i + 32] for i in range(0, len(raw), 32)]


def _address(word: bytes) -> str:
    return chain.normalize_address("0x" + word[-20:].hex())


def _hash(word: bytes) -> str:
    return chain.normalize_bytes32("0x" + word.hex())


def _event(log: dict[str, Any]) -> dict[str, Any]:
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 4:
        raise RuntimeError("ProviderUpdated has malformed topics")
    words = _words(str(log.get("data")))
    if len(words) != 5:
        raise RuntimeError("ProviderUpdated has malformed data")
    return {
        "owner": _address(bytes.fromhex(topics[1][2:])),
        "vote_signer": _address(bytes.fromhex(topics[2][2:])),
        "operator_id_hash": _hash(bytes.fromhex(topics[3][2:])),
        "reputation": int.from_bytes(words[0], "big"),
        "active": bool(int.from_bytes(words[1], "big")),
        "source_sequence": int.from_bytes(words[2], "big"),
        "source_digest": _hash(words[3]),
        "roster_version": int.from_bytes(words[4], "big"),
        "block_number": int(str(log["blockNumber"]), 16),
        "transaction_hash": chain.normalize_bytes32(str(log["transactionHash"])),
        "log_index": int(str(log["logIndex"]), 16),
    }


def _rpc(url: str, method: str, params: list[Any], timeout: float = 30) -> Any:
    return chain.rpc_call(url, method, params, timeout)


def _safe_heads() -> tuple[int, int]:
    heads = []
    for url in RPCS:
        if chain.rpc_int(url, "eth_chainId", [], 20) != CHAIN_ID:
            raise RuntimeError(f"RPC is not Sepolia: {url}")
        heads.append(chain.rpc_int(url, "eth_blockNumber", [], 20))
    head = min(heads)
    if head <= OLD_REGISTRY_DEPLOYMENT_BLOCK + CONFIRMATIONS:
        raise RuntimeError("RPC head is before the migration source boundary")
    return head, head - CONFIRMATIONS


def _logs(url: str, through: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for start in range(OLD_REGISTRY_DEPLOYMENT_BLOCK, through + 1, 900):
        end = min(through, start + 899)
        value = _rpc(
            url,
            "eth_getLogs",
            [{
                "address": chain.normalize_address(OLD_REGISTRY),
                "fromBlock": hex(start),
                "toBlock": hex(end),
                "topics": [PROVIDER_UPDATED_TOPIC],
            }],
            45,
        )
        if not isinstance(value, list):
            raise RuntimeError("RPC returned malformed ProviderUpdated logs")
        result.extend(value)
    return result


def _source_rows(through: int) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    all_events: list[list[dict[str, Any]]] = []
    all_rows: list[list[dict[str, Any]]] = []
    for url in RPCS:
        raw_logs = _logs(url, through)
        events = [_event(item) for item in raw_logs]
        events.sort(key=lambda item: (item["block_number"], item["transaction_hash"], item["log_index"]))
        all_events.append(events)
        count_data = _rpc(
            url,
            "eth_call",
            [{"to": chain.normalize_address(OLD_REGISTRY), "data": chain.encode_contract_call("providerCount()", [])}, "latest"],
            30,
        )
        count = int(str(count_data), 16)
        if count != len(PROVIDER_OWNERS):
            raise RuntimeError(f"old Registry provider count is {count}, expected three")
        rows: list[dict[str, Any]] = []
        for index in range(count):
            data = _rpc(
                url,
                "eth_call",
                [{"to": chain.normalize_address(OLD_REGISTRY), "data": chain.encode_contract_call("providerAt(uint256)", [str(index)])}, "latest"],
                30,
            )
            words = _words(str(data))
            if len(words) != 7:
                raise RuntimeError("old Registry providerAt returned malformed data")
            rows.append({
                "owner": _address(words[0]),
                "vote_signer": _address(words[1]),
                "operator_id_hash": _hash(words[2]),
                "peer_id_hash": _hash(words[3]),
                "capability_hash": _hash(words[4]),
                "reputation": int.from_bytes(words[5], "big"),
                "active": bool(int.from_bytes(words[6], "big")),
            })
        rows.sort(key=lambda item: item["owner"])
        all_rows.append(rows)
    if _json(all_events[0]) != _json(all_events[1]):
        raise RuntimeError("independent RPCs disagree on old ProviderUpdated history")
    if _json(all_rows[0]) != _json(all_rows[1]):
        raise RuntimeError("independent RPCs disagree on old Provider rows")
    events = all_events[0]
    rows = all_rows[0]
    by_owner: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["owner"] in PROVIDER_OWNERS:
            prior = by_owner.get(event["owner"])
            if prior is None or (event["block_number"], event["roster_version"]) > (prior["block_number"], prior["roster_version"]):
                by_owner[event["owner"]] = event
    if set(by_owner) != PROVIDER_OWNERS:
        raise RuntimeError("old Registry history does not contain all three Provider identities")
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        owner = row["owner"]
        event = by_owner.get(owner)
        if event is None:
            raise RuntimeError("old Registry row lacks a canonical ProviderUpdated event")
        for field in ("vote_signer", "operator_id_hash", "reputation", "active"):
            if row[field] != event[field]:
                raise RuntimeError(f"old Registry row/event mismatch for {owner}: {field}")
        output[owner] = {**row, "source_sequence": event["source_sequence"], "source_digest": event["source_digest"], "source_event": event}
    metadata = {
        "source_registry": chain.normalize_address(OLD_REGISTRY),
        "source_through_block": through,
        "source_event_count": len(events),
    }
    return output, metadata


def _new_state(owner: str) -> tuple[int, str]:
    sequence = chain.rpc_int(
        RPCS[0], "eth_call",
        [{"to": chain.normalize_address(NEW_REGISTRY), "data": chain.encode_contract_call("providerSourceSequence(address)", [owner])}, "latest"],
        30,
    )
    digest = chain.normalize_bytes32(_rpc(
        RPCS[0], "eth_call",
        [{"to": chain.normalize_address(NEW_REGISTRY), "data": chain.encode_contract_call("providerSourceDigest(address)", [owner])}, "latest"],
        30,
    ))
    return sequence, digest


def _receipt(tx_hash: str, timeout: float = 240) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        for url in RPCS:
            try:
                value = _rpc(url, "eth_getTransactionReceipt", [tx_hash], 30)
                if value:
                    if int(value.get("status", "0x0"), 16) != 1:
                        raise RuntimeError(f"transaction reverted: {tx_hash}")
                    return value
            except (chain.ChainError, OSError) as exc:
                last_error = exc
        time.sleep(4)
    if last_error is not None:
        raise RuntimeError(f"receipt is still unknown; last RPC error: {last_error}")
    raise RuntimeError(f"receipt is still unknown; do not recreate transaction: {tx_hash}")


def _confirm(receipt: dict[str, Any]) -> None:
    block = int(receipt["blockNumber"], 16)
    required = block + CONFIRMATIONS - 1
    deadline = time.monotonic() + 300
    while True:
        try:
            head = max(chain.rpc_int(url, "eth_blockNumber", [], 30) for url in RPCS)
        except chain.ChainError:
            head = block
        if head >= required:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"confirmation wait incomplete at block {block}")
        time.sleep(6)


def _known_transaction(tx_hash: str) -> bool:
    for url in RPCS:
        try:
            if _rpc(url, "eth_getTransactionReceipt", [tx_hash], 20):
                return True
            if _rpc(url, "eth_getTransactionByHash", [tx_hash], 20):
                return True
        except chain.ChainError:
            continue
    return False


def _ensure_authority_funded(deployer_key: bytes, journal: dict[str, Any]) -> None:
    authority = chain.normalize_address(AUTHORITY)
    deployer = chain.normalize_address(chain.private_key_to_address(deployer_key))
    if deployer != chain.normalize_address(DEPLOYER):
        raise RuntimeError("deployer key does not match the new deployment")
    record = journal.get("funding")
    if record and record.get("tx_hash"):
        receipt = _receipt(record["tx_hash"])
        record["status"] = "confirmed"
        record["receipt"] = receipt
        _confirm(receipt)
        record["confirmations_verified"] = True
        _atomic_write(journal)
    current = chain.rpc_int(RPCS[0], "eth_getBalance", [authority, "latest"], 30)
    if current >= TARGET_AUTHORITY_BALANCE:
        return
    value = TARGET_AUTHORITY_BALANCE - current
    record = journal.get("funding_topup")
    if not record or not record.get("tx_hash"):
        pending = chain.rpc_int(RPCS[0], "eth_getTransactionCount", [deployer, "pending"], 30)
        latest = chain.rpc_int(RPCS[0], "eth_getTransactionCount", [deployer, "latest"], 30)
        if pending != latest:
            raise RuntimeError("deployer has an unrelated pending transaction")
        gas_price = chain.legacy_gas_price(RPCS[0], 30)
        gas = 21_000
        cost = gas * gas_price
        balance = chain.rpc_int(RPCS[0], "eth_getBalance", [deployer, "latest"], 30)
        if balance < value + cost:
            raise RuntimeError("deployer has insufficient ETH for authority funding")
        raw = chain.sign_legacy_transaction(
            deployer_key, pending, gas_price, gas, authority, value, b"", CHAIN_ID,
        )
        tx_hash = chain.normalize_bytes32("0x" + chain.keccak256(raw).hex())
        record = {
            "tx_hash": tx_hash, "from": deployer, "to": authority,
            "value": value, "nonce": pending, "gas": gas,
            "gas_price": gas_price, "raw_tx": "0x" + raw.hex(), "status": "prepared",
        }
        journal["funding_topup"] = record
        _atomic_write(journal)
        result = _rpc(RPCS[1], "eth_sendRawTransaction", ["0x" + raw.hex()], 45)
        if chain.normalize_bytes32(str(result)) != tx_hash:
            raise RuntimeError("RPC returned an unexpected authority funding hash")
        record["status"] = "broadcast"
        _atomic_write(journal)
        print(json.dumps({"authority": authority, "funding_tx_hash": tx_hash, "broadcast": True}, sort_keys=True))
        receipt = _receipt(tx_hash)
        record["status"] = "confirmed"
        record["receipt"] = receipt
        _atomic_write(journal)
        _confirm(receipt)
        record["confirmations_verified"] = True
        _atomic_write(journal)
        print(json.dumps({"authority": authority, "funding_topup_tx_hash": tx_hash, "confirmed": True}, sort_keys=True))
    else:
        if _known_transaction(record["tx_hash"]):
            receipt = _receipt(record["tx_hash"])
            record["status"] = "confirmed"
            record["receipt"] = receipt
            _confirm(receipt)
            record["confirmations_verified"] = True
            _atomic_write(journal)
        else:
            nonce = int(record["nonce"])
            pending = chain.rpc_int(RPCS[1], "eth_getTransactionCount", [deployer, "pending"], 30)
            latest = chain.rpc_int(RPCS[1], "eth_getTransactionCount", [deployer, "latest"], 30)
            if pending != nonce or latest != nonce:
                raise RuntimeError("prepared authority top-up is not observable; refusing to recreate it")
            raw = bytes.fromhex(str(record.get("raw_tx", "0x"))[2:]) if record.get("raw_tx") else b""
            if not raw:
                raw = chain.sign_legacy_transaction(
                    deployer_key, nonce, int(record["gas_price"]), int(record["gas"]),
                    authority, int(record["value"]), b"", CHAIN_ID,
                )
                rebuilt = chain.normalize_bytes32("0x" + chain.keccak256(raw).hex())
                record["superseded_tx_hash"] = record["tx_hash"]
                record["tx_hash"] = rebuilt
                record["raw_tx"] = "0x" + raw.hex()
                _atomic_write(journal)
            if chain.normalize_bytes32("0x" + chain.keccak256(raw).hex()) != record["tx_hash"]:
                raise RuntimeError("prepared authority top-up bytes changed; refusing to resend")
            result = _rpc(RPCS[1], "eth_sendRawTransaction", ["0x" + raw.hex()], 45)
            if chain.normalize_bytes32(str(result)) != record["tx_hash"]:
                raise RuntimeError("RPC returned an unexpected authority top-up hash")
            record["status"] = "broadcast"
            _atomic_write(journal)
            print(json.dumps({"authority": authority, "funding_topup_tx_hash": record["tx_hash"], "rebroadcast": True}, sort_keys=True))
            receipt = _receipt(record["tx_hash"])
            record["status"] = "confirmed"
            record["receipt"] = receipt
            _atomic_write(journal)
            _confirm(receipt)
            record["confirmations_verified"] = True
            _atomic_write(journal)
            print(json.dumps({"authority": authority, "funding_topup_tx_hash": record["tx_hash"], "confirmed": True}, sort_keys=True))
    if chain.rpc_int(RPCS[0], "eth_getBalance", [authority, "latest"], 30) < TARGET_AUTHORITY_BALANCE:
        raise RuntimeError("authority funding postcondition failed")


def _send(owner: str, data: str, key: bytes, journal: dict[str, Any]) -> str:
    step = "set-provider-" + owner[2:]
    existing = journal["providers"].get(owner)
    sender = chain.normalize_address(chain.private_key_to_address(key))
    if existing and existing.get("tx_hash"):
        if _known_transaction(existing["tx_hash"]):
            receipt = _receipt(existing["tx_hash"])
            existing["status"] = "confirmed"
            existing["receipt"] = receipt
            _confirm(receipt)
            existing["confirmations_verified"] = True
            _atomic_write(journal)
            return existing["tx_hash"]
        # The previous RPC returned an error before accepting the raw
        # transaction.  Re-broadcast the exact same bytes only when both
        # nonce views still prove that nonce is unused.
        nonce = int(existing.get("nonce"))
        pending = chain.rpc_int(RPCS[1], "eth_getTransactionCount", [sender, "pending"], 30)
        latest = chain.rpc_int(RPCS[1], "eth_getTransactionCount", [sender, "latest"], 30)
        if pending != nonce or latest != nonce:
            raise RuntimeError("prepared transaction is not observable; refusing to recreate it")
        raw = chain.sign_legacy_transaction(
            key, nonce, int(existing["gas_price"]), int(existing["gas"]),
            NEW_REGISTRY, 0, bytes.fromhex(data[2:]), CHAIN_ID,
        )
        rebuilt = chain.normalize_bytes32("0x" + chain.keccak256(raw).hex())
        if rebuilt != existing["tx_hash"]:
            existing["superseded_tx_hash"] = existing["tx_hash"]
            existing["tx_hash"] = rebuilt
            existing["raw_tx"] = "0x" + raw.hex()
            _atomic_write(journal)
        elif not existing.get("raw_tx"):
            existing["raw_tx"] = "0x" + raw.hex()
            _atomic_write(journal)
        result = _rpc(RPCS[1], "eth_sendRawTransaction", ["0x" + raw.hex()], 45)
        if chain.normalize_bytes32(str(result)) != existing["tx_hash"]:
            raise RuntimeError("RPC returned an unexpected retry transaction hash")
        existing["status"] = "broadcast"
        _atomic_write(journal)
        print(json.dumps({"provider_owner": owner, "tx_hash": existing["tx_hash"], "rebroadcast": True}, sort_keys=True))
        receipt = _receipt(existing["tx_hash"])
        existing["status"] = "confirmed"
        existing["receipt"] = receipt
        _atomic_write(journal)
        _confirm(receipt)
        existing["confirmations_verified"] = True
        _atomic_write(journal)
        print(json.dumps({"provider_owner": owner, "tx_hash": existing["tx_hash"], "confirmed": True}, sort_keys=True))
        return existing["tx_hash"]
    pending = chain.rpc_int(RPCS[0], "eth_getTransactionCount", [sender, "pending"], 30)
    latest = chain.rpc_int(RPCS[0], "eth_getTransactionCount", [sender, "latest"], 30)
    if pending != latest:
        raise RuntimeError("reputation authority has an unrelated pending transaction")
    gas_price = chain.legacy_gas_price(RPCS[0], 30)
    gas = chain.estimate_gas(RPCS[0], sender, NEW_REGISTRY, data, 30)
    if gas > MAX_GAS:
        raise RuntimeError(f"setProvider gas estimate exceeds bound: {gas}")
    cost = gas * gas_price
    if cost > MAX_GAS_COST:
        raise RuntimeError("setProvider gas cost exceeds bound")
    balance = chain.rpc_int(RPCS[0], "eth_getBalance", [sender, "latest"], 30)
    if balance < cost:
        raise RuntimeError("reputation authority has insufficient ETH")
    raw = chain.sign_legacy_transaction(
        key, pending, gas_price, gas, NEW_REGISTRY, 0,
        bytes.fromhex(data[2:]), CHAIN_ID,
    )
    tx_hash = chain.normalize_bytes32("0x" + chain.keccak256(raw).hex())
    record = {"step": step, "tx_hash": tx_hash, "from": sender, "to": chain.normalize_address(NEW_REGISTRY), "data": data, "nonce": pending, "gas": gas, "gas_price": gas_price, "raw_tx": "0x" + raw.hex(), "status": "prepared"}
    journal["providers"][owner] = record
    _atomic_write(journal)
    result = _rpc(RPCS[0], "eth_sendRawTransaction", ["0x" + raw.hex()], 45)
    if chain.normalize_bytes32(str(result)) != tx_hash:
        raise RuntimeError("RPC returned an unexpected transaction hash")
    record["status"] = "broadcast"
    _atomic_write(journal)
    print(json.dumps({"provider_owner": owner, "tx_hash": tx_hash, "broadcast": True}, sort_keys=True))
    receipt = _receipt(tx_hash)
    record["status"] = "confirmed"
    record["receipt"] = receipt
    _atomic_write(journal)
    _confirm(receipt)
    record["confirmations_verified"] = True
    _atomic_write(journal)
    print(json.dumps({"provider_owner": owner, "tx_hash": tx_hash, "confirmed": True}, sort_keys=True))
    return tx_hash


def main() -> int:
    key = _read_key(AUTHORITY_KEY)
    if chain.normalize_address(chain.private_key_to_address(key)) != chain.normalize_address(AUTHORITY):
        raise RuntimeError("reputation authority key does not match the new Registry")
    deployer_key = _read_key(DEPLOYER_KEY)
    if chain.rpc_int(RPCS[0], "eth_chainId", [], 30) != CHAIN_ID:
        raise RuntimeError("RPC is not Sepolia")
    if _rpc(RPCS[0], "eth_getCode", [chain.normalize_address(NEW_REGISTRY), "latest"], 30) in ("0x", "0x0"):
        raise RuntimeError("new Registry has no runtime code")
    head, through = _safe_heads()
    rows, source = _source_rows(through)
    journal = _load_journal()
    journal["source"] = source
    journal["source_rows"] = {owner: {key: value for key, value in row.items() if key != "source_event"} for owner, row in rows.items()}
    _atomic_write(journal)
    _ensure_authority_funded(deployer_key, journal)
    for owner in sorted(rows):
        row = rows[owner]
        sequence, digest = _new_state(owner)
        if sequence > row["source_sequence"]:
            raise RuntimeError(f"new Registry has a newer source for {owner}; refusing downgrade")
        if sequence == row["source_sequence"]:
            if digest != row["source_digest"]:
                raise RuntimeError(f"new Registry source digest conflicts for {owner}")
            print(json.dumps({"provider_owner": owner, "already_registered": True}, sort_keys=True))
            continue
        data = encode_set_provider(row, source_sequence=row["source_sequence"], source_digest=row["source_digest"])
        simulation = _rpc(RPCS[0], "eth_call", [{"from": chain.normalize_address(AUTHORITY), "to": chain.normalize_address(NEW_REGISTRY), "data": data}, "latest"], 30)
        if simulation not in ("0x", "0x0"):
            raise RuntimeError(f"setProvider simulation returned unexpected data for {owner}")
        _send(owner, data, key, journal)
        confirmed_sequence, confirmed_digest = _new_state(owner)
        if confirmed_sequence != row["source_sequence"] or confirmed_digest != row["source_digest"]:
            raise RuntimeError(f"postcondition failed for {owner}")
    count = chain.rpc_int(RPCS[0], "eth_call", [{"to": chain.normalize_address(NEW_REGISTRY), "data": chain.encode_contract_call("providerCount()", [])}, "latest"], 30)
    can_form = bool(int(str(_rpc(RPCS[0], "eth_call", [{"to": chain.normalize_address(NEW_REGISTRY), "data": chain.encode_contract_call("canFormJury()", [])}, "latest"], 30)), 16))
    if count != len(PROVIDER_OWNERS) or not can_form:
        raise RuntimeError(f"new Registry postcondition failed: count={count}, can_form_jury={can_form}")
    journal["completed_at"] = int(time.time())
    journal["source_head"] = head
    _atomic_write(journal)
    print(json.dumps({"complete": True, "new_registry": chain.normalize_address(NEW_REGISTRY), "provider_count": count, "can_form_jury": can_form}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (chain.ChainError, OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"stopped": True, "error_type": type(exc).__name__, "message": str(exc)[:240]}, sort_keys=True))
        raise SystemExit(1)
