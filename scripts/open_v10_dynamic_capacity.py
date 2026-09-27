#!/usr/bin/env python3
"""Open the three bounded V10 capacity channels for the dynamic Provider pool.

The command is deliberately read-only unless ``--send`` is supplied.  It
pins all nonce and balance reads to one block, signs the two owner permits
locally, and uses the durable V10 executor for the single on-chain batch.
Private key material and signed permits are never printed.

Use ``--rotate`` after an earlier bounded channel batch has expired.  The
current on-chain allocation nonces are then used to derive a new batch; the
old channel IDs remain historical and are not reused.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import chain, chain_v9, chain_v10  # noqa: E402


RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
CONFIRMATIONS = 6
POLICY_FILE = ROOT / ".mycomesh/v10/deployment-policy.json"
ROLES_FILE = ROOT / ".mycomesh/v10/roles.json"
PUBLIC_IDENTITIES_FILE = ROOT / ".codex-run/mesh/v9-controlled-test-20260918/public-identities.json"
DEPLOYMENT_FILE = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
NETWORK_FILE = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
OUTBOX = ROOT / ".mycomesh/v10/capacity-open.sqlite3"
PLAN_FILE = ROOT / ".mycomesh/v10/capacity-open-plan.json"
CAPACITY_FILE = ROOT / ".mycomesh/v10/dynamic-capacity-channels.json"
PERMITS_FILE = ROOT / ".mycomesh/v10/dynamic-capacity-permits.json"
EXECUTOR_FILE = ROOT / ".codex-run/mesh/v10-redeploy-20260920/execute_plan.py"
DEPLOYER_KEY_FILE = ROOT / ".mycomesh/v10/roles/deployer.key"
CONSUMER_OWNER_KEY_FILE = ROOT / ".mycomesh/v10/roles/consumer.key"
IDENTITY_DIR = ROOT / ".codex-run/mesh/v10-dynamic-provider-jury-20260923/identities"
SERVING_PROVIDER_KEY_FILE = ROOT / ".codex-run/mesh/v9-controlled-test-20260918/wallets/provider-owner.key"
SERVING_PROVIDER_NAME = "provider1"
SERVING_PROVIDER_OWNER = "0x94515c8903cca8e5aedb1437e947db39970792cc"
SERVING_PROVIDER_SIGNER = "0x83fd8e4518b26462bec8e06cf10b5adf30299688"
MAX_FEE = 100_000
CAPACITY_EACH = 1_000_000
VALID_DELAY = 300
ADMIT_SECONDS = 14 * 24 * 60 * 60
CLAIM_GRACE_SECONDS = 10_800
PERMIT_TTL = 900
PROVIDERS = (
    # Three channels are intentionally backed by one serving Provider owner.
    # The provider allocation nonce makes the channel IDs distinct while the
    # jury registry remains populated only by the independent high-reputation
    # Providers (p2/p3/p4).
    ("provider1-channel-a", SERVING_PROVIDER_NAME, SERVING_PROVIDER_OWNER, SERVING_PROVIDER_SIGNER),
    ("provider1-channel-b", SERVING_PROVIDER_NAME, SERVING_PROVIDER_OWNER, SERVING_PROVIDER_SIGNER),
    ("provider1-channel-c", SERVING_PROVIDER_NAME, SERVING_PROVIDER_OWNER, SERVING_PROVIDER_SIGNER),
)


def _load_executor() -> type:
    spec = importlib.util.spec_from_file_location("mycomesh_v10_capacity_executor", EXECUTOR_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load durable V10 executor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Executor


Executor = _load_executor()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _protected_secret(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600):
        raise RuntimeError(f"unsafe private key file: {path}")
    raw = path.read_text(encoding="ascii").strip()
    key = chain.parse_private_key(raw)
    return "0x" + key.hex()


def _identity_secret(name: str, expected_owner: str) -> str:
    if name == SERVING_PROVIDER_NAME:
        expected = chain.normalize_address(expected_owner)
        if expected != chain.normalize_address(SERVING_PROVIDER_OWNER):
            raise RuntimeError("unexpected serving Provider owner")
        return _protected_secret(SERVING_PROVIDER_KEY_FILE)
    path = IDENTITY_DIR / f"{name}-owner.json"
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600):
        raise RuntimeError(f"unsafe Provider identity file: {path}")
    value = _read_json(path)
    key = chain.parse_private_key(str(value.get("private_key") or ""))
    address = chain.private_key_to_address(key)
    if address != chain.normalize_address(expected_owner) or chain.normalize_address(str(value.get("address") or "")) != address:
        raise RuntimeError(f"Provider identity does not match its owner: {path}")
    return "0x" + key.hex()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
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


def _words(value: Any, count: int, label: str) -> list[str]:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 2 + count * 64:
        raise RuntimeError(f"malformed {label} response")
    return [value[i : i + 64] for i in range(2, len(value), 64)]


def _call(executor: Any, target: str, signature: str, args: list[Any], snapshot: dict[str, Any], count: int) -> list[str]:
    data = chain.encode_contract_call(signature, [str(value) for value in args])
    return _words(executor.rpc("eth_call", [{"to": chain.normalize_address(target), "data": data}, snapshot]), count, signature)


def _uint(executor: Any, target: str, signature: str, args: list[Any], snapshot: dict[str, Any]) -> int:
    return int(_call(executor, target, signature, args, snapshot, 1)[0], 16)


def _bool(executor: Any, target: str, signature: str, args: list[Any], snapshot: dict[str, Any]) -> bool:
    value = int(_call(executor, target, signature, args, snapshot, 1)[0], 16)
    if value not in (0, 1):
        raise RuntimeError(f"non-canonical boolean from {signature}")
    return value == 1


def _address(word: str) -> str:
    if len(word) != 64:
        raise RuntimeError("malformed address word")
    return chain.normalize_address("0x" + word[24:])


def _registry_role_preflight(
    executor: Any,
    registry: str,
    snapshot: dict[str, Any],
    *,
    roles: set[str],
) -> dict[str, Any]:
    """Mirror Registry role exclusion before producing any owner permits.

    ``canFormJuryFor`` only accepts an existing channel, so channel creation
    itself is the first place the contract can evaluate these roles. Reading
    the live roster here lets the script fail before signing a batch that the
    Settlement would necessarily revert.
    """
    count = _uint(executor, registry, "providerCount()", [], snapshot)
    jury_size = _uint(executor, registry, "jurySize()", [], snapshot)
    if count < jury_size or not _bool(executor, registry, "canFormJury()", [], snapshot):
        raise RuntimeError("dynamic Provider registry cannot currently form a full jury")
    candidates: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for index in range(count):
        words = _call(executor, registry, "providerAt(uint256)", [index], snapshot, 7)
        owner = _address(words[0])
        signer = _address(words[1])
        candidate = {
            "index": index,
            "owner": owner,
            "vote_signer": signer,
            "reputation": int(words[5], 16),
            "active": int(words[6], 16) == 1,
        }
        candidates.append(candidate)
        for role in (owner, signer):
            if role in roles:
                conflicts.append({"candidate": candidate, "conflicting_role": role})
    if conflicts:
        raise RuntimeError("channel roles would exclude a live jury candidate")
    return {"provider_count": count, "jury_size": jury_size, "candidates": candidates}


def _channel_status(executor: Any, settlement: str, channel_id: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    words = _call(executor, settlement, "channelInfo(bytes32)", [channel_id], snapshot, 22)
    capacity = int(words[10], 16)
    if capacity == 0:
        return {"channel_id": channel_id, "exists": False}
    return {
        "channel_id": channel_id,
        "exists": True,
        "consumer_owner": chain.normalize_address("0x" + words[0][24:]),
        "provider_owner": chain.normalize_address("0x" + words[2][24:]),
        "capacity": capacity,
        "credit_remaining": int(words[19], 16),
        "stake_remaining": int(words[20], 16),
        "closed": int(words[21], 16) == 1,
    }


def _wait_for_confirmation(executor: Any, operation: dict[str, Any], key_file: Path) -> dict[str, Any]:
    result = executor.execute(
        operation,
        allow_send=True,
        approved_hash=operation["plan_hash"],
        key_file=str(key_file),
    )
    while result["state"] not in ("confirmed", "reverted"):
        time.sleep(5)
        result = executor.reconcile(operation["plan_hash"])
    if result["state"] != "confirmed":
        raise RuntimeError("capacity channel transaction reverted")
    return result


def _public_plan(deployment: dict[str, Any], snapshot: dict[str, Any], state: dict[str, Any], configs: list[dict[str, Any]], ids: list[str]) -> dict[str, Any]:
    return {
        "schema": "mycomesh.v10.dynamic-capacity-open-plan.v1",
        "chain_id": int(deployment["chain_id"]),
        "settlement": chain.normalize_address(deployment["settlement"]),
        "network_id": deployment["network_id"],
        "snapshot": {
            "block_number": int(snapshot["number"], 16),
            "block_hash": snapshot["hash"].lower(),
            "timestamp": int(snapshot["timestamp"], 16),
        },
        "capacity_each": CAPACITY_EACH,
        "max_fee_per_request": MAX_FEE,
        "channels": [
            {"provider_node": name, "channel_id": channel_id, "config": config}
            for (name, _identity_name, _owner, _signer), config, channel_id in zip(PROVIDERS, configs, ids)
        ],
        "preflight": state,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true", help="broadcast the reviewed open-channel batch")
    parser.add_argument("--rotate", action="store_true", help="derive a fresh batch after an earlier batch")
    parser.add_argument("--rpc", default=RPC_URL)
    args = parser.parse_args()

    policy = _read_json(POLICY_FILE)
    deployment = _read_json(DEPLOYMENT_FILE)
    network = _read_json(NETWORK_FILE)
    chain_v10.validate_deployment(deployment, allow_controlled_test=True)
    if deployment.get("capacity_channel_ids") and not args.rotate:
        raise RuntimeError("deployment already contains capacity_channel_ids; refuse to open another batch")
    if network.get("settlement", "").lower() != deployment["settlement"].lower():
        raise RuntimeError("Provider network manifest points at a different Settlement")

    executor = Executor(
        args.rpc,
        {"chain_id": int(policy["chain_id"]), "genesis_hash": policy["genesis_hash"], "confirmations": int(policy["confirmations"])},
        OUTBOX,
    )
    try:
        chain_id = int(deployment["chain_id"])
        settlement = chain.normalize_address(deployment["settlement"])
        consumer_owner_key = _protected_secret(CONSUMER_OWNER_KEY_FILE)
        consumer_owner = chain.private_key_to_address(chain.parse_private_key(consumer_owner_key))
        roles = _read_json(ROLES_FILE)
        expected_consumer = chain.normalize_address(roles["addresses"]["consumer"])
        if consumer_owner != expected_consumer:
            raise RuntimeError("Consumer owner key does not match the dynamic network manifest")
        public_identities = _read_json(PUBLIC_IDENTITIES_FILE)
        consumer_key = chain.normalize_address(public_identities["addresses"]["consumer-key"])
        consumer_owner_address = consumer_owner

        if executor.rpc("eth_chainId", []) != hex(chain_id):
            raise RuntimeError("wrong chain for V10 capacity opening")
        genesis = executor.rpc("eth_getBlockByNumber", ["0x0", False])
        if str(genesis.get("hash", "")).lower() != str(policy["genesis_hash"]).lower():
            raise RuntimeError("wrong Sepolia genesis for V10 capacity opening")
        head = executor.rpc("eth_getBlockByNumber", ["latest", False])
        if not isinstance(head, dict) or not head.get("hash") or not head.get("timestamp"):
            raise RuntimeError("RPC head is unavailable")
        snapshot = {"blockHash": head["hash"], "requireCanonical": True}
        now = int(head["timestamp"], 16)
        expected_settlement = chain.normalize_address(deployment["settlement"])
        if chain.normalize_address(network.get("settlement", "")) != expected_settlement:
            raise RuntimeError("network Settlement differs from deployment")

        # Confirm the deployed contract is the one bound to the Registry and
        # that this snapshot has enough unallocated credit and Provider stake.
        registry = chain.normalize_address(deployment["jury_registry"])
        if chain.normalize_address("0x" + _call(executor, settlement, "juryRegistry()", [], snapshot, 1)[0][24:]) != registry:
            raise RuntimeError("Settlement jury registry differs from the manifest")
        available_balance = _uint(executor, settlement, "availableBalance(address)", [consumer_owner_address], snapshot)
        grant_words = _call(executor, settlement, "keyGrants(address)", [consumer_key], snapshot, 4)
        grant_owner = chain.normalize_address("0x" + grant_words[0][24:])
        grant_max_fee = int(grant_words[1], 16)
        grant_active = int(grant_words[3], 16) == 1
        if grant_owner != consumer_owner_address or not grant_active or grant_max_fee < MAX_FEE:
            raise RuntimeError("Consumer payment key grant does not cover the channel fee")
        pricing = "0x" + _call(executor, settlement, "channelPricingHash(bytes32,uint64)", [deployment["channel_hash"], "1"], snapshot, 1)[0]
        if pricing.lower() != deployment["pricing_hash"].lower():
            raise RuntimeError("Settlement pricing hash differs from the manifest")
        consumer_nonce = _uint(executor, settlement, "consumerAllocationNonce(address)", [consumer_owner_address], snapshot)
        if available_balance < 3 * CAPACITY_EACH:
            raise RuntimeError("Consumer available balance is below the three-channel allocation")
        valid_from = now + VALID_DELAY
        admit_until = valid_from + ADMIT_SECONDS
        claim_until = admit_until + CLAIM_GRACE_SECONDS
        permit_deadline = now + PERMIT_TTL
        configs: list[dict[str, Any]] = []
        state: dict[str, Any] = {
            "consumer_owner": consumer_owner_address,
            "consumer_key": consumer_key,
            "consumer_available_balance": available_balance,
            "consumer_nonce": consumer_nonce,
            "providers": [],
        }
        relay = chain.normalize_address(network["relay"]["payment_address"])
        relay_signer = chain.normalize_address(network["relay"]["attestation_address"])
        # The treasury is part of channelVersions and is also excluded from
        # jury candidates by ProviderJuryRegistryV1._canFormJuryFor.
        version_words = _call(
            executor,
            settlement,
            "channelVersions(bytes32,uint64)",
            [deployment["channel_hash"], "1"],
            snapshot,
            10,
        )
        treasury = _address(version_words[8])
        role_addresses = {
            chain.normalize_address(value)
            for value in (
                consumer_owner_address,
                consumer_key,
                relay,
                relay_signer,
                chain.ZERO_ADDRESS,
                treasury,
                *(item[2] for item in PROVIDERS),
                *(item[3] for item in PROVIDERS),
            )
        }
        jury_preflight = _registry_role_preflight(executor, registry, snapshot, roles=role_addresses)
        state["jury_preflight"] = jury_preflight
        next_provider_nonce: dict[str, int] = {}
        for name, identity_name, owner_raw, signer_raw in PROVIDERS:
            owner = chain.normalize_address(owner_raw)
            signer = chain.normalize_address(signer_raw)
            if owner not in next_provider_nonce:
                next_provider_nonce[owner] = _uint(executor, settlement, "providerAllocationNonce(address)", [owner], snapshot)
            provider_nonce = next_provider_nonce[owner]
            next_provider_nonce[owner] += 1
            stake = _uint(executor, settlement, "providerStake(address)", [owner], snapshot)
            locked = _uint(executor, settlement, "lockedStake(address)", [owner], snapshot)
            allocated = _uint(executor, settlement, "allocatedStake(address)", [owner], snapshot)
            authorized = _bool(executor, settlement, "providerSigners(address,address)", [owner, signer], snapshot)
            if not authorized or stake - locked - allocated < CAPACITY_EACH:
                raise RuntimeError(f"{name} lacks authorized signer or free stake for its channel")
            config = {
                "consumer_owner": consumer_owner_address,
                "consumer_key": consumer_key,
                "provider_owner": owner,
                "provider_signer": signer,
                "relay": relay,
                "relay_signer": relay_signer,
                "pool": chain.ZERO_ADDRESS,
                "channel": chain.normalize_bytes32(deployment["channel_hash"]),
                "pricing_version": 1,
                "pricing_hash": chain.normalize_bytes32(deployment["pricing_hash"]),
                "capacity": CAPACITY_EACH,
                "max_fee_per_request": MAX_FEE,
                "valid_from": valid_from,
                "admit_until": admit_until,
                "claim_until": claim_until,
                "consumer_nonce": consumer_nonce + len(configs),
                "provider_nonce": provider_nonce,
                "permit_deadline": permit_deadline,
            }
            channel_id = chain_v10.channel_id_for(config, chain_id=chain_id, settlement_contract=settlement)
            existing = _channel_status(executor, settlement, channel_id, snapshot)
            if existing["exists"]:
                raise RuntimeError(f"computed channel already exists: {name}")
            configs.append(config)
            state["providers"].append({
                "name": name,
                "identity_name": identity_name,
                "owner": owner,
                "provider_signer": signer,
                "provider_nonce": provider_nonce,
                "stake": stake,
                "locked": locked,
                "allocated": allocated,
                "free_stake": stake - locked - allocated,
                "signer_authorized": authorized,
            })
        ids = [chain_v10.channel_id_for(config, chain_id=chain_id, settlement_contract=settlement) for config in configs]
        if len(set(ids)) != 3:
            raise RuntimeError("channel IDs are not distinct")
        state["channel_ids"] = ids
        state["snapshot_block"] = int(head["number"], 16)
        state["snapshot_timestamp"] = now
        plan = _public_plan(deployment, {**head, "number": head["number"]}, state, configs, ids)
        _atomic_json(PLAN_FILE, plan)

        if not args.send:
            print(json.dumps({"sent": False, "plan_file": str(PLAN_FILE), "channel_ids": ids, "preflight": state}, sort_keys=True))
            return 0

        provider_secrets = [_identity_secret(identity_name, owner) for _name, identity_name, owner, _signer in PROVIDERS]
        permits = [
            chain_v10.build_channel_permit(
                config=config,
                consumer_private_key=consumer_owner_key,
                provider_private_key=provider_secret,
                chain_id=chain_id,
                settlement_contract=settlement,
            )
            for config, provider_secret in zip(configs, provider_secrets)
        ]
        calldata = chain_v10.encode_open_capacity_channels(
            permits,
            now=now,
            max_channel_duration=int(deployment["max_channel_duration_seconds"]),
        )
        operation_name = (
            "fresh-v10-open-channels-rotate-" + str(consumer_nonce)
            if args.rotate else "fresh-v10-open-channels"
        )
        operation = executor.operation(
            operation_name,
            deployment["deployer"],
            settlement,
            calldata,
            kind="initialize",
        )
        _atomic_json(PERMITS_FILE, {"schema": "mycomesh.v10.dynamic-capacity-permits.v1", "settlement": settlement, "channel_ids": ids, "permits": permits})
        result = _wait_for_confirmation(executor, operation, DEPLOYER_KEY_FILE)
        receipt = json.loads(result.get("receipt_json") or "{}")
        artifact = {
            "schema": "mycomesh.v10.dynamic-capacity-channels.v1",
            "chain_id": chain_id,
            "settlement": settlement,
            "network_id": deployment["network_id"],
            "open_tx_hash": result["tx_hash"],
            "block_number": int(receipt.get("blockNumber", "0x0"), 16),
            "block_hash": str(receipt.get("blockHash", "")).lower(),
            "channel_ids": ids,
            "channels": plan["channels"],
        }
        _atomic_json(CAPACITY_FILE, artifact)
        print(json.dumps({"sent": True, "state": result["state"], "tx_hash": result["tx_hash"], "channel_ids": ids}, sort_keys=True))
        return 0
    finally:
        executor.close()


if __name__ == "__main__":
    raise SystemExit(main())
