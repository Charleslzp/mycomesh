#!/usr/bin/env python3
"""Materialize the confirmed V10 dynamic-Provider-jury deployment.

The deployment manifest contains protocol and chain facts only.  The network
manifest adds rotatable jury-relay transport identities and the Bridge/Relay
address allowed to broadcast already-signed votes.  No adjudicator roster is
ever written to either public manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
RPCS = (
    "https://rpc.sepolia.ethpandaops.io",
    "https://sepolia.gateway.tenderly.co",
    "https://ethereum-sepolia-rpc.publicnode.com",
)
CHAIN_ID = 11_155_111
GENESIS_HASH = "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"
STABLECOIN = "0xeb487c6e778248e16361dc313e4223c20d4c23b5"
ZERO_ADDRESS = "0x" + "0" * 40


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _rpc(url: str, method: str, params: list[object]) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json", "user-agent": "mycomesh-v10-manifest-builder/1"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        value = json.load(response)
    if value.get("error") is not None or "result" not in value:
        raise RuntimeError(f"RPC {method} failed: {value.get('error')}")
    return value["result"]


def _rpc_any(method: str, params: list[object]) -> object:
    last: Exception | None = None
    for url in RPCS:
        try:
            return _rpc(url, method, params)
        except Exception as exc:  # pragma: no cover - endpoint availability varies
            last = exc
    raise RuntimeError(f"all pinned RPC endpoints failed for {method}: {last}")


def _private_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError(f"unsafe private role key: {path}")
    raw = path.read_text(encoding="ascii").strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    value = bytes.fromhex(raw)
    if len(value) != 32:
        raise RuntimeError(f"invalid private role key: {path}")
    return value


def _write_private(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise RuntimeError(f"refusing unsafe private key: {path}")
        if _private_bytes(path) != value:
            raise RuntimeError(f"private key already exists with different material: {path}")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, ("0x" + value.hex() + "\n").encode("ascii"))
    finally:
        os.close(fd)


def _confirmed_steps(outbox: Path) -> dict[str, tuple[str, dict]]:
    db = sqlite3.connect(outbox)
    try:
        rows = db.execute(
            "SELECT step, tx_hash, state, verification_json "
            "FROM v10_deployment_steps ORDER BY step_index"
        ).fetchall()
    finally:
        db.close()
    result: dict[str, tuple[str, dict]] = {}
    for step, tx_hash, state, verification in rows:
        if state != "confirmed":
            raise RuntimeError(f"V10 deployment step is not confirmed: {step}={state}")
        result[str(step)] = (str(tx_hash), json.loads(verification or "{}"))
    if set(result) != {"registry", "settlement", "bind"}:
        raise RuntimeError(f"outbox does not contain all confirmed V10 steps: {sorted(result)}")
    return result


def _ed25519_relay_key(roles: dict, roles_dir: Path, *, role: str) -> tuple[str, str]:
    executor_address = str(roles["addresses"][role]).lower()
    role_key_path = roles_dir / f"{role}.key"
    role_key = _private_bytes(role_key_path)
    seed = hmac.new(
        role_key,
        f"mycomesh-v10-jury-relay-ed25519/{role}/v1".encode("ascii"),
        hashlib.sha256,
    ).digest()
    seed_path = roles_dir / f"jury-relay-ed25519-{role}.key"
    _write_private(seed_path, seed)
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    ).hex()
    return public_key, executor_address


def _stablecoin_sha256() -> str:
    code = str(_rpc_any("eth_getCode", [STABLECOIN, "latest"]))
    if not code.startswith("0x") or len(code) <= 2:
        raise RuntimeError("stablecoin has no runtime code")
    return hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=ROOT / ".mycomesh/v10")
    parser.add_argument("--deployment-out", type=Path, default=ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json")
    parser.add_argument("--provider-out", type=Path, default=ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json")
    parser.add_argument("--consumer-out", type=Path, default=ROOT / "packages/mycomesh-cli/networks/v10-dynamic-20260926.json")
    args = parser.parse_args()

    policy = _read_json(args.out_dir / "deployment-policy.json")
    plan = _read_json(args.out_dir / "deployment-plan.json")
    steps = _confirmed_steps(args.out_dir / "deployment-outbox.sqlite3")
    roles = _read_json(args.out_dir / "roles.json")
    addresses = {name: str(value).lower() for name, value in roles["addresses"].items()}
    jury_identities = [
        _ed25519_relay_key(
            roles, args.out_dir / "roles", role="jury-executor-bridge",
        ),
        _ed25519_relay_key(
            roles, args.out_dir / "roles", role="jury-executor-relay",
        ),
    ]

    # Capacity channel IDs are materialized only after the signed permits have
    # been opened on the new Settlement.  Keep this artifact local/protected;
    # its IDs are public, but the sibling permit file contains signatures.
    capacity_artifact = args.out_dir / "dynamic-capacity-channels.json"
    capacity_channel_ids: list[str] = []
    capacity_release: dict[str, object] = {}
    if capacity_artifact.exists():
        capacity_value = _read_json(capacity_artifact)
        if capacity_value.get("settlement", "").lower() != str(plan["addresses"]["settlement"]).lower():
            raise RuntimeError("capacity artifact points at a different Settlement")
        capacity_channel_ids = [str(value).lower() for value in capacity_value.get("channel_ids", [])]
        if len(capacity_channel_ids) != 3 or len(set(capacity_channel_ids)) != 3:
            raise RuntimeError("capacity artifact must contain three distinct channel IDs")
        if any(len(value) != 66 or not value.startswith("0x") for value in capacity_channel_ids):
            raise RuntimeError("capacity artifact contains a malformed channel ID")
        channel_rows = capacity_value.get("channels")
        if not isinstance(channel_rows, list) or len(channel_rows) != len(capacity_channel_ids):
            raise RuntimeError("capacity artifact channel rows are incomplete")
        configs = [row.get("config") if isinstance(row, dict) else None for row in channel_rows]
        if any(not isinstance(config, dict) for config in configs):
            raise RuntimeError("capacity artifact channel config is missing")
        if [row.get("channel_id") for row in channel_rows] != capacity_channel_ids:
            raise RuntimeError("capacity artifact channel IDs disagree with configs")
        common_fields = (
            "capacity", "max_fee_per_request", "valid_from", "admit_until", "claim_until",
        )
        common = {field: configs[0].get(field) for field in common_fields}
        if any(type(value) is not int or value <= 0 for value in common.values()):
            raise RuntimeError("capacity artifact window or budget is invalid")
        if not common["valid_from"] < common["admit_until"] < common["claim_until"]:
            raise RuntimeError("capacity artifact window is not ordered")
        if any(any(config.get(field) != value for field, value in common.items()) for config in configs):
            raise RuntimeError("capacity channels have inconsistent windows or budgets")
        open_tx = str(capacity_value.get("open_tx_hash", "")).lower()
        receipt = _rpc_any("eth_getTransactionReceipt", [open_tx])
        if not isinstance(receipt, dict) or receipt.get("status") != "0x1":
            raise RuntimeError("capacity opening is not confirmed successful")
        block_hash = str(capacity_value.get("block_hash", "")).lower()
        block_number = int(capacity_value.get("block_number", 0))
        if (
            str(receipt.get("blockHash", "")).lower() != block_hash
            or int(str(receipt.get("blockNumber", "0x0")), 16) != block_number
        ):
            raise RuntimeError("capacity opening artifact differs from chain receipt")
        block = _rpc_any("eth_getBlockByHash", [block_hash, False])
        if not isinstance(block, dict) or str(block.get("hash", "")).lower() != block_hash:
            raise RuntimeError("capacity opening block is unavailable")
        opened_at = int(str(block["timestamp"]), 16)
        capacity_release = {
            "fresh_channel_capacity": common["capacity"],
            "fresh_channel_max_fee_per_request": common["max_fee_per_request"],
            "fresh_channel_valid_from": common["valid_from"],
            "fresh_channel_admit_until": common["admit_until"],
            "fresh_channel_claim_until": common["claim_until"],
            "fresh_channel_open_tx_hashes": [open_tx] * len(capacity_channel_ids),
            "fresh_channel_open_block_timestamps": [opened_at] * len(capacity_channel_ids),
        }

    settlement_tx, settlement_receipt = steps["settlement"]
    registry_tx, registry_receipt = steps["registry"]
    bind_tx, bind_receipt = steps["bind"]
    settlement = str(plan["addresses"]["settlement"]).lower()
    registry = str(plan["addresses"]["registry"]).lower()
    deployment_block = int(settlement_receipt["block_number"])
    deployment_block_hash = str(settlement_receipt["block_hash"]).lower()
    runtime_hash = str(settlement_receipt["runtime_code_hash"]).lower()
    pricing_hash = str(settlement_receipt["pricing_hash"]).lower()
    if str(bind_receipt.get("settlement", "")).lower() != settlement:
        raise RuntimeError("confirmed Registry bind does not point at the new Settlement")
    if registry_receipt.get("settlement") not in (None, ZERO_ADDRESS):
        raise RuntimeError("Registry deployment unexpectedly contains a Settlement binding")
    if deployment_block <= 0 or not deployment_block_hash.startswith("0x"):
        raise RuntimeError("invalid confirmed Settlement deployment boundary")

    dispute_policy = dict(policy["dispute_policy"])
    deployment = {
        "protocol_version": 10,
        "eip712_name": "MycoMesh Settlement",
        "eip712_version": "10",
        "reservation_mode": "provider_bound_channel",
        "chain_domain": "10",
        "max_authorization_ttl_seconds": 10800,
        "authorization_deadline_seconds": 9000,
        "max_channel_duration_seconds": 2592000,
        "chain_id": CHAIN_ID,
        "confirmations": int(policy["confirmations"]),
        "genesis_hash": GENESIS_HASH,
        "deployer": addresses["deployer"],
        "governance": addresses["deployer"],
        "treasury": addresses["deployer"],
        "stablecoin": STABLECOIN,
        "stablecoin_runtime_code_keccak256": str(plan["stablecoin_runtime_code_hash"]).lower(),
        "stablecoin_runtime_code_sha256": _stablecoin_sha256(),
        "reward_token": ZERO_ADDRESS,
        "settlement": settlement,
        # Canonical identity used by the release-evidence schema.
        "tx_hash": settlement_tx,
        "settlement_deployment_tx_hash": settlement_tx,
        "deployment_block": deployment_block,
        "deployment_block_hash": deployment_block_hash,
        "settlement_runtime_code_keccak256": runtime_hash,
        "jury_registry": registry,
        "jury_registry_deployment_tx_hash": registry_tx,
        "jury_registry_deployment_block": int(registry_receipt["block_number"]),
        "jury_registry_deployment_block_hash": str(registry_receipt["block_hash"]).lower(),
        "jury_registry_runtime_code_keccak256": str(registry_receipt["runtime_code_hash"]).lower(),
        "bind_tx_hash": bind_tx,
        "committee_mode": "dynamic_provider_ai_v1",
        "jury_registry_governance": addresses["deployer"],
        "reputation_authority": addresses["reputation-authority"],
        "minimum_provider_reputation": int(policy["registry"]["minimum_reputation"]),
        "jury_size": int(policy["registry"]["jury_size"]),
        "adjudication_threshold": int(policy["registry"]["threshold"]),
        "jury_selection_delay_blocks": int(policy["registry"]["selection_delay_blocks"]),
        "jury_randomness": "future_blockhash_v1",
        "jury_decision_policy_hash": str(policy["jury_decision_policy_hash"]).lower(),
        "channel": "codex-standard-v1",
        "channel_hash": str(policy["initial_channel"]).lower(),
        "pricing_version": 1,
        "pricing_hash": pricing_hash,
        "channel_id": "codex",
        "backend_policy": "codex-app-server-postvalidated-v1",
        "capacity_channel_ids": capacity_channel_ids,
        **capacity_release,
        "policy": dispute_policy,
        "network_id": str(policy["network_id"]),
        "deployment_class": str(policy["deployment_class"]),
        "source_commit": str(policy["source_commit"]),
        "reputation_history_import": policy["reputation_history_import"],
    }

    network_common = {
        "schema_version": 1,
        "channel_id": deployment["channel_id"],
        "backend_policy": deployment["backend_policy"],
        "deployment": "sepolia-myco-v10-dynamic-20260926.json",
        "tls_ca_file": "v10-dynamic-20260926.ca.crt",
        "network_profile": "testnet",
        "provider_transport": "relay",
        "bridge_urls": [
            # These are the public Bridge endpoints.  Relay edge URLs belong
            # to `relay`/`relay_fallbacks` and must never be used for lease
            # admission.
            "https://166.88.209.61:10443",
            "https://216.173.64.214:10443",
        ],
        "relay": {
            "host": "136.0.3.126",
            "provider_port": 10991,
            "public_url": "https://136.0.3.126:10443",
            "provider_tls": True,
            "payment_address": addresses["relay"],
            "attestation_address": addresses["bridge"],
        },
        "relay_fallbacks": [
            {
                "host": "166.88.96.60",
                "provider_port": 10991,
                "public_url": "https://166.88.96.60:10443",
                "provider_tls": True,
                "payment_address": addresses["relay"],
                "attestation_address": addresses["bridge"],
            },
        ],
        "public_model_id": "gpt-5.5",
        "public_model_ids": ["gpt-5.5", "gpt-5.6-sol"],
        "require_response_proof": True,
        "reserve_input_bytes": 65536,
        "reserve_output_tokens": 2000,
        "settlement_rpc_url": RPCS[0],
        "settlement_rpc_urls": list(RPCS),
        "jury_relay_public_keys": [public_key for public_key, _ in jury_identities],
        "jury_transaction_senders": {
            public_key: sender for public_key, sender in jury_identities
        },
        "jury_transaction_max_total_gas_cost_wei": 25_000_000_000_000_000,
        "jury_transaction_sender_role": "self-controlled-bridge-or-relay-executor",
        "jury_pool_mode": "live_registry_reputation_snapshot",
        "jury_roster_is_unpinned": True,
        "jury_provider_count_source": "ProviderJuryRegistryV1",
    }

    # Materialized network manifests intentionally repeat deployment facts so
    # package consumers can inspect one file while still checking the sibling
    # deployment reference and exact lineage parity.
    provider_network = {**deployment, **network_common}
    provider_network["deployment"] = "sepolia-myco-v10-dynamic-20260926.json"
    consumer_network = {**provider_network}
    # The package manifest is self-contained.  It must not reference a source
    # checkout path that will not exist after npm installation.
    consumer_network.pop("deployment", None)

    for path, value, mode in (
        (args.deployment_out, deployment, 0o644),
        (args.provider_out, provider_network, 0o644),
        (args.consumer_out, consumer_network, 0o644),
    ):
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(path, mode)
    print(json.dumps({
        "deployment": str(args.deployment_out),
        "provider_network": str(args.provider_out),
        "consumer_network": str(args.consumer_out),
        "settlement": settlement,
        "jury_registry": registry,
        "jury_relay_public_keys": [public_key for public_key, _ in jury_identities],
        "jury_transaction_senders": {
            public_key: sender for public_key, sender in jury_identities
        },
        "capacity_channel_ids": capacity_channel_ids,
        "dynamic_jury": True,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
