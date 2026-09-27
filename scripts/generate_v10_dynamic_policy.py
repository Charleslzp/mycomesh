#!/usr/bin/env python3
"""Generate a self-controlled, dynamic-Provider-jury V10 deployment policy.

The input secret is read locally and is never printed.  Role keys are derived
with domain-separated HMAC-SHA256 so the same protected deployer key can own
the governance, reputation-authority, bond-recipient, and application roles
without putting a fixed adjudicator roster in the deployment manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).parents[1]))

from gateway import chain, chain_v9
from gateway import v10_deployment


RPCS = (
    "https://rpc.sepolia.ethpandaops.io",
    "https://sepolia.gateway.tenderly.co",
    "https://ethereum-sepolia-rpc.publicnode.com",
)
CHAIN_ID = 11_155_111
GENESIS_HASH = "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"
STABLECOIN = "0xeb487c6e778248e16361dc313e4223c20d4c23b5"
CHANNEL = "0xdedf8b58276b80863f354409c963cbaddf4ca7d5b866d528ff1386d74b339104"
SECP256K1_N = chain.SECP256K1_N
ROLE_NAMES = (
    "deployer", "consumer", "provider", "relay", "bridge",
    "reputation-authority", "bond-penalty-recipient",
    # Transaction senders are controlled by the Bridge/Relay services but are
    # deliberately separate EOAs so their nonce and gas budget cannot be
    # confused with a business or governance role.
    "jury-executor-bridge", "jury-executor-relay",
)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _read_secret(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"secret file is not a regular file: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SystemExit("secret file must not be readable or writable by group/other")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        raw = value["eth"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"secret JSON does not contain an eth key: {exc}") from None
    return chain.parse_private_key(raw)


def _derive(root: bytes, label: str) -> bytes:
    digest = hmac.new(root, f"mycomesh-v10-role/{label}".encode("ascii"), hashlib.sha256).digest()
    value = (int.from_bytes(digest, "big") % (SECP256K1_N - 1)) + 1
    return value.to_bytes(32, "big")


def _write_private_key(path: Path, key: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise SystemExit(f"refusing to reuse an unsafe role key: {path}")
        existing = chain.parse_private_key(path.read_text(encoding="ascii").strip())
        if existing != key:
            raise SystemExit(f"role key already exists with different material: {path}")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, ("0x" + key.hex() + "\n").encode("ascii"))
    finally:
        os.close(fd)


def _rpc(url: str, method: str, params: list[object]) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url, data=payload,
        headers={"content-type": "application/json", "user-agent": "mycomesh-v10-policy-generator/1"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        value = json.load(response)
    if value.get("error") is not None or "result" not in value:
        raise SystemExit(f"RPC {method} failed at {url}: {value.get('error')}")
    return value["result"]


def _block(url: str, tag: str) -> dict[str, object]:
    value = _rpc(url, "eth_getBlockByNumber", [tag, False])
    if not isinstance(value, dict) or not value.get("hash") or not value.get("number"):
        raise SystemExit(f"RPC returned an invalid block for {tag}: {url}")
    return value


def _history(source: Path, *, through_block: int, through_hash: str, source_block_hash: str) -> dict[str, object]:
    raw = source.read_bytes()
    old = json.loads(raw.decode("utf-8"))
    settlement = old.get("settlement")
    deployment_block = old.get("deployment_block")
    runtime_hash = old.get("settlement_runtime_code_keccak256")
    network_id = old.get("network_id")
    if not all((isinstance(settlement, str), isinstance(deployment_block, int),
                isinstance(runtime_hash, str), isinstance(network_id, str))):
        raise SystemExit(f"history manifest lacks a complete deployment boundary: {source}")
    canonical = _json(old).encode("utf-8")
    return {
        "schema": "mycomesh.v10.reputation-history-import.v1",
        "source_network_id": network_id,
        "source_protocol_version": int(old.get("protocol_version", 10)),
        "source_chain_id": CHAIN_ID,
        "source_genesis_hash": GENESIS_HASH,
        "source_settlement_contract": chain.normalize_address(settlement),
        "source_runtime_code_hash": chain.normalize_bytes32(runtime_hash),
        "source_deployment_block": deployment_block,
        "source_deployment_block_hash": source_block_hash,
        "source_history_through_block": through_block,
        "source_history_through_block_hash": through_hash,
        "confirmations": 6,
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "artifact_root": "0x" + chain.keccak256(canonical).hex(),
    }


def _policy_hash(policy_file: Path) -> str:
    value = json.loads((Path(__file__).parents[1] / "deployments/provider-jury-policy-v1.json").read_text())
    executable = {
        "schema": value["schema"], "model": value["model"],
        "system_prompt": value["system_prompt"],
        "max_output_tokens": value["max_output_tokens"],
        "task_ttl_seconds": value["task_ttl_seconds"],
        "verdict_fields": ["confirmed", "confidence_bps", "reason_code", "reasoning"],
    }
    digest = hashlib.sha256(_json(executable).encode("utf-8")).hexdigest()
    return "0x" + digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret", type=Path, default=Path("depres.json"))
    parser.add_argument("--out-dir", type=Path, default=Path(".mycomesh/v10"))
    parser.add_argument("--history-manifest", type=Path)
    parser.add_argument("--source-commit", default=None)
    args = parser.parse_args()

    root = Path(__file__).parents[1]
    secret = _read_secret(args.secret)
    roles_dir = args.out_dir / "roles"
    keys: dict[str, bytes] = {name: _derive(secret, name) for name in ROLE_NAMES}
    _write_private_key(roles_dir / "deployer.key", secret)
    for name, key in keys.items():
        if name == "deployer":
            continue
        _write_private_key(roles_dir / f"{name}.key", key)
    addresses = {name: chain.private_key_to_address(key) for name, key in keys.items()}
    addresses["deployer"] = chain.private_key_to_address(secret)

    if args.history_manifest is None:
        dynamic = root / ".codex-run/mesh/v10-dynamic-provider-jury-20260923/deployment.json"
        args.history_manifest = dynamic if dynamic.is_file() else root / "deployments/sepolia-myco-v10.json"
    heads = []
    for url in RPCS:
        if int(_rpc(url, "eth_chainId", []), 16) != CHAIN_ID:
            raise SystemExit(f"RPC is not Sepolia: {url}")
        genesis = _block(url, "0x0")
        if chain.normalize_bytes32(genesis["hash"]) != GENESIS_HASH:
            raise SystemExit(f"RPC genesis mismatch: {url}")
        heads.append(_block(url, "latest"))
    head_number = min(int(block["number"], 16) for block in heads)
    through_number = head_number - 6
    through = _block(RPCS[0], hex(through_number))
    source_value = json.loads(args.history_manifest.read_text(encoding="utf-8"))
    source_number = int(source_value["deployment_block"])
    source_block = _block(RPCS[0], hex(source_number))
    history = _history(
        args.history_manifest,
        through_block=through_number,
        through_hash=chain.normalize_bytes32(through["hash"]),
        source_block_hash=chain.normalize_bytes32(source_block["hash"]),
    )

    artifacts = {
        "registry": v10_deployment.load_artifact(root / "out/ProviderJuryRegistryV1.sol/ProviderJuryRegistryV1.json", "ProviderJuryRegistryV1"),
        "settlement": v10_deployment.load_artifact(root / "out/MycoSettlementV10.sol/MycoSettlementV10.json", "MycoSettlementV10"),
    }
    source_commit = args.source_commit
    if source_commit is None:
        source_commit = os.popen("git rev-parse HEAD").read().strip()
    policy = {
        "chain_id": CHAIN_ID,
        "genesis_hash": GENESIS_HASH,
        "confirmations": 6,
        "deployer": addresses["deployer"],
        "stablecoin": STABLECOIN,
        "reward_token": chain.ZERO_ADDRESS,
        "treasury": addresses["deployer"],
        "governance": addresses["deployer"],
        "initial_channel": CHANNEL,
        "initial_config": {
            "input_per_1k": 1000, "output_per_1k": 4000, "minimum_fee": 2000,
            "provider_bps": 8500, "relay_bps": 300, "pool_bps": 200,
            "treasury_bps": 1000, "active": True,
        },
        "dispute_policy": {
            "dispute_window": 1800, "arbitration_timeout": 1800,
            "consumer_withdrawal_delay": 600, "reporter_bond": 10000,
            "slash_bps": 10000, "slash_cap": 100000, "reporter_bounty_bps": 2000,
            "stable_bounty_cap": 20000, "token_reward": 0, "token_reward_cap": 0,
            "token_minimum_exposure": 0, "token_minimum_penalty": 0,
            "bond_penalty_recipient": addresses["bond-penalty-recipient"],
        },
        "registry": {
            "reputation_authority": addresses["reputation-authority"],
            "bond_penalty_recipient": addresses["bond-penalty-recipient"],
            "minimum_reputation": 75, "jury_size": 3, "threshold": 2,
            "selection_delay_blocks": 4,
        },
        "fee_policy": {
            "gas_price_wei": 2_000_000_000,
            "gas_limits": {"registry": 7_000_000, "settlement": 9_000_000, "bind": 300_000},
            "max_total_gas_cost_wei": 32_600_000_000_000_000,
        },
        "source_commit": source_commit,
        "artifact_pins": {
            name: {field: artifacts[name][field] for field in v10_deployment.ARTIFACT_PIN_FIELDS}
            for name in artifacts
        },
        "deployment_class": "controlled_test",
        "network_id": f"mycomesh-v10-dynamic-provider-ai-{time.strftime('%Y%m%d')}-controlled-test",
        "jury_decision_policy_hash": _policy_hash(root / "deployments/provider-jury-policy-v1.json"),
        "reputation_history_import": history,
    }
    validated = v10_deployment.validate_policy(policy)
    args.out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy_path = args.out_dir / "deployment-policy.json"
    roles_path = args.out_dir / "roles.json"
    policy_path.write_text(json.dumps(validated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(policy_path, 0o600)
    roles = {
        "schema": "mycomesh.v10.self-controlled-roles.v1",
        "derived_at": int(time.time()),
        "derivation": "HMAC-SHA256(root_eth_private_key, mycomesh-v10-role/<label>) mod secp256k1 order",
        "addresses": addresses,
        "key_files": {name: str(roles_dir / ("deployer.key" if name == "deployer" else f"{name}.key")) for name in addresses},
        "dynamic_jury": {
            "committee_mode": "dynamic_provider_ai_v1",
            "fixed_adjudicators": False,
            "jury_size": validated["registry"]["jury_size"],
            "threshold": validated["registry"]["threshold"],
        },
    }
    roles_path.write_text(json.dumps(roles, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(roles_path, 0o600)
    print(json.dumps({
        "policy": str(policy_path), "roles": str(roles_path),
        "network_id": validated["network_id"], "source_commit": validated["source_commit"],
        "role_addresses": addresses,
        "rpc_urls": list(RPCS), "history_manifest": str(args.history_manifest),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
