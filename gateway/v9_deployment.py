"""Explicit V9 deployment plans and a durable signed-transaction outbox.

Run ``python -m gateway.v9_deployment --help``. Planning is read-only. This
module never invents policy, identities, funds, or operator-independence claims.
Use one durable outbox and a dedicated deployer account across all processes.
Single-operator test committees require an explicit controlled_test policy and
--allow-controlled-test on every deployment-tool invocation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import chain, chain_v9
from .relay_adjudication_v9 import _protected_key


class DeploymentError(chain.ChainError):
    pass


CONFIG_FIELDS = ("input_per_1k", "output_per_1k", "minimum_fee", "provider_bps",
                 "relay_bps", "pool_bps", "treasury_bps", "active")
MANIFEST_INPUTS = ("chain_id", "deployer", "stablecoin", "treasury", "governance", "channel",
                   "channel_hash", "reward_token", "policy", "adjudicators", "adjudication_threshold",
                   "adjudicator_operators", "independence_attested", "network_id", "channel_id", "backend_policy")
POLICY_INPUTS = {*MANIFEST_INPUTS, "genesis_hash", "initial_config", "confirmations"}
OPTIONAL_POLICY_INPUTS = {"committee_mode", "max_authorization_ttl_seconds", "authorization_deadline_seconds"}
PLAN_SCHEMA = "mycomesh.v9.deployment-plan.v1"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value: Any) -> str:
    return "0x" + chain.keccak256(_json(value).encode()).hex()


def _uint(value: Any, name: str, *, positive: bool = False, bits: int = 256) -> int:
    if type(value) is not int or not int(positive) <= value < 2**bits:
        raise DeploymentError(f"invalid {name}")
    return value


def _bytes(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) % 2:
        raise DeploymentError(f"invalid {name}")
    try:
        result = bytes.fromhex(value[2:])
    except ValueError:
        raise DeploymentError(f"invalid {name}") from None
    if not result:
        raise DeploymentError(f"empty {name}")
    return result


def _words(values: Any) -> bytes:
    return b"".join(chain.abi_encode_arg(str(v).lower() if type(v) is bool else str(v)) for v in values)


def manifest_candidate(policy: Mapping[str, Any], nonce: int, *, allow_controlled_test: bool = False) -> dict[str, Any]:
    """Derive constructor-only fields; this is not evidence of a deployment."""
    config = policy["initial_config"]
    pricing = _words([policy["channel_hash"], 1, policy["treasury"], *[config[k] for k in CONFIG_FIELDS]])
    value = {key: policy[key] for key in MANIFEST_INPUTS}
    for name in OPTIONAL_POLICY_INPUTS:
        if name in policy:
            value[name] = policy[name]
    value.update(protocol_version=9, eip712_name="MycoMesh Settlement", eip712_version="9",
                 settlement=chain.derive_contract_address(policy["deployer"], nonce),
                 pricing_version=1, pricing_hash="0x" + chain.keccak256(pricing).hex())
    return chain_v9.validate_deployment(value, allow_controlled_test=allow_controlled_test).to_dict()


def validate_policy(value: Any, *, allow_controlled_test: bool = False) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or POLICY_INPUTS - set(value)
            or set(value) - POLICY_INPUTS - OPTIONAL_POLICY_INPUTS):
        raise DeploymentError("policy requires these explicit fields (optional committee_mode and authorization TTL policy): " + ", ".join(sorted(POLICY_INPUTS)))
    value = json.loads(_json(value))
    config = value["initial_config"]
    if not isinstance(config, dict) or set(config) != set(CONFIG_FIELDS):
        raise DeploymentError("initial_config requires every supported field")
    for name in CONFIG_FIELDS[:-1]:
        _uint(config[name], name, bits=16 if name.endswith("bps") else 256)
    if config["active"] is not True or sum(config[k] for k in CONFIG_FIELDS[3:7]) != 10000:
        raise DeploymentError("initial channel must be active and shares must total 10000 bps")
    value["genesis_hash"] = chain.normalize_bytes32(value["genesis_hash"])
    if value["genesis_hash"] == chain.ZERO_BYTES32:
        raise DeploymentError("genesis hash cannot be zero")
    _uint(value["confirmations"], "confirmations", positive=True)
    # Reuse manifest policy bounds and the explicit independence attestation.
    normalized = manifest_candidate(value, 0, allow_controlled_test=allow_controlled_test)
    for name in MANIFEST_INPUTS:
        value[name] = normalized[name]
    return json.loads(_json(value))


def constructor_data(policy: Mapping[str, Any], *, allow_controlled_test: bool = False) -> bytes:
    p = validate_policy(policy, allow_controlled_test=allow_controlled_test)
    # 5 scalar words + 8 static config words + 13 static policy words +
    # 1 dynamic address-array offset + 1 threshold word = 28 head words.
    return _words([p["stablecoin"], p["reward_token"], p["treasury"], p["governance"], p["channel_hash"],
                   *[p["initial_config"][k] for k in CONFIG_FIELDS],
                   *[p["policy"][k] for k in chain_v9.POLICY_FIELDS], 28 * 32,
                   p["adjudication_threshold"], len(p["adjudicators"]), *p["adjudicators"]])


def load_artifact(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    value = json.loads(raw)
    constructors = [item for item in value.get("abi", []) if item.get("type") == "constructor"]
    expected = ["address"] * 4 + ["bytes32", "tuple", "tuple", "address[]", "uint16"]
    if len(constructors) != 1 or [v["type"] for v in constructors[0]["inputs"]] != expected:
        raise DeploymentError("artifact is not the V9 constructor ABI")
    inputs = constructors[0]["inputs"]
    if ([v["type"] for v in inputs[5].get("components", [])] != ["uint256"] * 3 + ["uint16"] * 4 + ["bool"]
            or [v["type"] for v in inputs[6].get("components", [])] !=
            ["uint64"] * 3 + ["uint256", "uint16", "uint256", "uint16"] + ["uint256"] * 5 + ["address"]):
        raise DeploymentError("artifact has the wrong V9 tuple ABI")
    creation, runtime = value["bytecode"], value["deployedBytecode"]
    if creation.get("linkReferences") or runtime.get("linkReferences"):
        raise DeploymentError("linked artifacts are not supported")
    artifact = {"creation_bytecode": creation["object"], "runtime_template": runtime["object"],
                "immutable_references": runtime.get("immutableReferences", {}),
                "sha256": hashlib.sha256(raw).hexdigest()}
    _bytes(artifact["creation_bytecode"], "creation bytecode")
    _masked_runtime(artifact["runtime_template"], artifact)
    return artifact


def _masked_runtime(code: str, artifact: Mapping[str, Any]) -> bytes:
    result = bytearray(_bytes(code, "runtime bytecode"))
    covered: set[int] = set()
    for entries in artifact["immutable_references"].values():
        for entry in entries:
            start, length = entry["start"], entry["length"]
            _uint(start, "immutable start")
            if length != 32 or start + length > len(result):
                raise DeploymentError("invalid immutable reference")
            positions = set(range(start, start + length))
            if covered & positions:
                raise DeploymentError("overlapping immutable references")
            covered |= positions
            result[start:start + length] = b"\0" * length
    return bytes(result)


class V9DeploymentClient:
    def __init__(self, rpc_url: str, *, timeout: int = 15, max_snapshot_age: int = 300,
                 allow_controlled_test: bool = False):
        url = urlsplit(rpc_url)
        if "," in rpc_url or url.scheme not in ("http", "https") or not url.hostname:
            raise DeploymentError("deployment requires one explicit HTTP(S) RPC endpoint; fallback lists are forbidden")
        _uint(timeout, "RPC timeout", positive=True)
        _uint(max_snapshot_age, "maximum snapshot age", positive=True)
        self.rpc_url, self.timeout, self.max_snapshot_age = rpc_url, timeout, max_snapshot_age
        self.allow_controlled_test = allow_controlled_test is True

    def rpc(self, method: str, params: list[Any]) -> Any:
        return chain.rpc_call(self.rpc_url, method, params, self.timeout)

    def check_network(self, policy: Mapping[str, Any]) -> None:
        validate_policy(policy, allow_controlled_test=self.allow_controlled_test)
        if (int(self.rpc("eth_chainId", []), 16) != policy["chain_id"] or
                chain.normalize_bytes32(self.rpc("eth_getBlockByNumber", ["0x0", False])["hash"]) != policy["genesis_hash"]):
            raise DeploymentError("RPC chain or genesis differs from explicit policy")

    def plan(self, policy: Mapping[str, Any], artifact: Mapping[str, Any]) -> dict[str, Any]:
        p = validate_policy(policy, allow_controlled_test=self.allow_controlled_test)
        self.check_network(p)
        block = self.rpc("eth_getBlockByNumber", ["latest", False])
        number, block_hash = int(block["number"], 16), chain.normalize_bytes32(block["hash"])
        if not -30 <= int(time.time()) - int(block["timestamp"], 16) <= self.max_snapshot_age:
            raise DeploymentError("RPC head is stale or from the future")
        tag = {"blockHash": block_hash, "requireCanonical": True}
        tokens = {}
        for token in {p["stablecoin"], p["reward_token"]} - {chain.ZERO_ADDRESS}:
            tokens[token] = "0x" + chain.keccak256(_bytes(self.rpc("eth_getCode", [token, tag]), "token code")).hex()
        nonce = int(self.rpc("eth_getTransactionCount", [p["deployer"], "latest"]), 16)
        if nonce != int(self.rpc("eth_getTransactionCount", [p["deployer"], "pending"]), 16):
            raise DeploymentError("deployer has pending transactions; resolve them before planning")
        manifest = manifest_candidate(p, nonce, allow_controlled_test=self.allow_controlled_test)
        if self.rpc("eth_getCode", [manifest["settlement"], tag]) != "0x":
            raise DeploymentError("predicted deployment address already contains code")
        data = "0x" + (_bytes(artifact["creation_bytecode"], "creation bytecode") +
                      constructor_data(p, allow_controlled_test=self.allow_controlled_test)).hex()
        tx = {"from": p["deployer"], "data": data, "value": "0x0"}
        gas = int(self.rpc("eth_estimateGas", [tx]), 16) * 12 // 10 + 10000
        gas_price = int(self.rpc("eth_gasPrice", []), 16)
        if chain.normalize_bytes32(self.rpc("eth_getBlockByNumber", [hex(number), False])["hash"]) != block_hash:
            raise DeploymentError("planning snapshot was reorganized")
        result = {"schema": PLAN_SCHEMA, "dry_run": True, "policy": p, "artifact": dict(artifact),
                  "manifest_candidate": manifest, "token_code_hashes": tokens,
                  "snapshot": {"block_number": number, "block_hash": block_hash, "timestamp": int(block["timestamp"], 16)},
                  "transaction": {**tx, "chain_id": p["chain_id"], "nonce": nonce},
                  "estimate": {"gas_units": gas, "gas_price_wei": gas_price, "total_gas_cost_wei": gas * gas_price}}
        result = json.loads(_json(result))
        return {**result, "plan_hash": _hash(result)}

    def refresh(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        validate_plan(plan)
        fresh = self.plan(plan["policy"], plan["artifact"])
        for field in ("transaction", "manifest_candidate", "token_code_hashes"):
            if fresh[field] != plan[field]:
                raise DeploymentError(f"{field} changed; review a new plan")
        return fresh

    def verify_deployment(self, plan: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
        manifest = dict(plan["manifest_candidate"])
        target = manifest["settlement"]
        if chain.normalize_address(receipt["contractAddress"]) != target:
            raise DeploymentError("receipt deployed a different contract address")
        tag = {"blockHash": chain.normalize_bytes32(receipt["blockHash"]), "requireCanonical": True}
        runtime = self.rpc("eth_getCode", [target, tag])
        if _masked_runtime(runtime, plan["artifact"]) != _masked_runtime(plan["artifact"]["runtime_template"], plan["artifact"]):
            raise DeploymentError("deployed runtime differs from approved compiler artifact")

        def check(signature: str, args: list[str], expected: bytes) -> None:
            actual = self.rpc("eth_call", [{"to": target, "data": chain.encode_contract_call(signature, args)}, tag])
            if _bytes(actual, signature) != expected:
                raise DeploymentError(f"onchain {signature} differs from deployment plan")

        for signature, field in (("stablecoin()", "stablecoin"), ("rewardToken()", "reward_token"),
                                 ("governance()", "governance"), ("treasury()", "treasury"),
                                 ("adjudicationThreshold()", "adjudication_threshold")):
            check(signature, [], _words([manifest[field]]))
        check("policy()", [], _words([manifest["policy"][k] for k in chain_v9.POLICY_FIELDS]))
        check("MAX_AUTHORIZATION_TTL()", [], _words([manifest.get("max_authorization_ttl_seconds", chain_v9.LEGACY_MAX_AUTHORIZATION_TTL)]))
        check("adjudicators()", [], _words([32, len(manifest["adjudicators"]), *manifest["adjudicators"]]))
        check("DOMAIN_SEPARATOR()", [], _bytes(chain_v9.domain_separator(chain_id=manifest["chain_id"], verifying_contract=target), "domain"))
        check("latestChannelVersion(bytes32)", [manifest["channel_hash"]], _words([1]))
        check("channelPricingHash(bytes32,uint64)", [manifest["channel_hash"], "1"], _words([manifest["pricing_hash"]]))
        manifest.update(tx_hash=receipt["transactionHash"], deployment_block=int(receipt["blockNumber"], 16))
        return {"manifest": chain_v9.validate_deployment(manifest, allow_controlled_test=self.allow_controlled_test).to_dict(),
                "runtime_code_hash": "0x" + chain.keccak256(_bytes(runtime, "runtime")).hex(),
                "genesis_hash": plan["policy"]["genesis_hash"], "plan_hash": plan["plan_hash"]}


def validate_plan(plan: Mapping[str, Any]) -> None:
    if plan.get("schema") != PLAN_SCHEMA or plan.get("plan_hash") != _hash({k: v for k, v in plan.items() if k != "plan_hash"}):
        raise DeploymentError("invalid or modified deployment plan")


class V9DeploymentOutbox:
    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise DeploymentError("deployment outbox must be durable")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise DeploymentError("outbox must be an owned regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS v9_deployments (
            plan_hash TEXT PRIMARY KEY, scope TEXT NOT NULL, sender TEXT NOT NULL, nonce INTEGER NOT NULL,
            tx_hash TEXT NOT NULL UNIQUE, raw_tx TEXT NOT NULL, plan_json TEXT NOT NULL,
            state TEXT NOT NULL, result_json TEXT, UNIQUE(scope, sender, nonce))""")

    def close(self) -> None:
        self.db.close()

    def _row(self, plan_hash: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM v9_deployments WHERE plan_hash=?", (plan_hash,)).fetchone()

    def get(self, plan_hash: str) -> dict[str, Any] | None:
        with self.lock:
            row = self._row(plan_hash)
            if not row:
                return None
            result = {key: row[key] for key in ("plan_hash", "sender", "nonce", "tx_hash", "state")}
            if row["result_json"]:
                result["verification"] = json.loads(row["result_json"])
            return result

    def execute(self, client: V9DeploymentClient, plan: Mapping[str, Any], *, allow_send: bool = False,
                approved_plan_hash: str | None = None, key_file: str | Path | None = None,
                max_gas_price_wei: int | None = None, max_gas_units: int | None = None,
                max_total_gas_cost_wei: int | None = None) -> dict[str, Any]:
        validate_plan(plan)
        if not allow_send:
            return {"dry_run": True, "sent": False, "plan_hash": plan["plan_hash"]}
        if approved_plan_hash != plan["plan_hash"] or not key_file:
            raise DeploymentError("send requires exact approved plan hash and protected dedicated key file")
        for value, label in ((max_gas_price_wei, "gas price cap"), (max_gas_units, "gas units cap"),
                             (max_total_gas_cost_wei, "total gas cost cap")):
            _uint(value, label, positive=True)
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                existing = self.get(approved_plan_hash)
                if existing:
                    self.db.commit()
                    return existing  # Restart never allocates a nonce or silently rebroadcasts.
                p, tx = plan["policy"], plan["transaction"]
                scope = f"{p['genesis_hash']}:{p['chain_id']}"
                if self.db.execute("SELECT 1 FROM v9_deployments WHERE scope=? AND sender=? AND state NOT IN ('confirmed','reverted')",
                                   (scope, p["deployer"])).fetchone():
                    raise DeploymentError("deployer has an unresolved outbox transaction")
                fresh = client.refresh(plan)
                estimate = fresh["estimate"]
                if (estimate["gas_price_wei"] > max_gas_price_wei or estimate["gas_units"] > max_gas_units
                        or estimate["total_gas_cost_wei"] > max_total_gas_cost_wei):
                    raise DeploymentError("deployment gas exceeds explicit caps")
                if int(client.rpc("eth_getBalance", [p["deployer"], "latest"]), 16) < estimate["total_gas_cost_wei"]:
                    raise DeploymentError("deployer balance cannot cover bounded deployment gas")
                private_key = _protected_key(key_file)
                if chain.private_key_to_address(private_key) != p["deployer"]:
                    raise DeploymentError("key does not match approved deployer")
                raw = chain.sign_legacy_transaction(private_key, tx["nonce"], estimate["gas_price_wei"],
                                                    estimate["gas_units"], None, 0, _bytes(tx["data"], "init code"), p["chain_id"])
                raw_hex, tx_hash = "0x" + raw.hex(), "0x" + chain.keccak256(raw).hex()
                self.db.execute("INSERT INTO v9_deployments VALUES (?,?,?,?,?,?,?,'sending',NULL)",
                                (approved_plan_hash, scope, p["deployer"], tx["nonce"], tx_hash, raw_hex, _json(plan)))
                self.db.commit()  # FULL synchronous commit precedes every possible network send.
            except BaseException:
                self.db.rollback()
                raise
        return self._broadcast(client, approved_plan_hash)

    def _broadcast(self, client: V9DeploymentClient, plan_hash: str) -> dict[str, Any]:
        with self.lock:
            row = self._row(plan_hash)
            if row is None:
                raise DeploymentError("unknown deployment transaction")
            raw, tx_hash = row["raw_tx"], row["tx_hash"]
            if "0x" + chain.keccak256(_bytes(raw, "stored raw transaction")).hex() != tx_hash:
                raise DeploymentError("stored transaction hash mismatch")
        try:
            returned = client.rpc("eth_sendRawTransaction", [raw])
            state = "submitted" if chain.normalize_bytes32(returned) == tx_hash else "uncertain"
        except Exception:
            state = "uncertain"
        with self.lock:
            self.db.execute("UPDATE v9_deployments SET state=? WHERE plan_hash=? AND state NOT IN ('confirmed','reverted')", (state, plan_hash))
        return self.get(plan_hash)

    def rebroadcast(self, client: V9DeploymentClient, plan_hash: str, *, allow_send: bool = False) -> dict[str, Any]:
        if not allow_send:
            return {"dry_run": True, "sent": False, "plan_hash": plan_hash}
        result = self.reconcile(client, plan_hash)
        if result["state"] in ("confirmed", "reverted"):
            return result
        # Same persisted bytes, nonce, gas price and hash, even after RPC uncertainty.
        return self._broadcast(client, plan_hash)

    def reconcile(self, client: V9DeploymentClient, plan_hash: str) -> dict[str, Any]:
        with self.lock:
            row = self._row(plan_hash)
            if row is None:
                raise DeploymentError("unknown deployment transaction")
            # A previous confirmation cannot survive a failed current check.
            # Commit before RPC: errors/reorgs block another nonce until recovery.
            self.db.execute("UPDATE v9_deployments SET state='uncertain',result_json=NULL WHERE plan_hash=?", (plan_hash,))
            plan = json.loads(row["plan_json"])
        validate_plan(plan)
        client.check_network(plan["policy"])
        receipt = client.rpc("eth_getTransactionReceipt", [row["tx_hash"]])
        state, verified = "uncertain", None
        if receipt is not None:
            if chain.normalize_bytes32(receipt["transactionHash"]) != row["tx_hash"]:
                raise DeploymentError("receipt transaction hash mismatch")
            number = int(receipt["blockNumber"], 16)
            block_hash = chain.normalize_bytes32(receipt["blockHash"])
            block = client.rpc("eth_getBlockByNumber", [hex(number), False])
            head = int(client.rpc("eth_blockNumber", []), 16)
            if block and chain.normalize_bytes32(block["hash"]) == block_hash:
                state = "submitted"
                if head - number + 1 >= plan["policy"]["confirmations"]:
                    status = int(receipt["status"], 16)
                    if status not in (0, 1):
                        raise DeploymentError("invalid receipt status")
                    state = "confirmed" if status else "reverted"
                    if status:
                        verified = client.verify_deployment(plan, receipt)
                        if chain.normalize_bytes32(client.rpc("eth_getBlockByNumber", [hex(number), False])["hash"]) != block_hash:
                            raise DeploymentError("verification snapshot was reorganized")
        with self.lock:
            self.db.execute("UPDATE v9_deployments SET state=?,result_json=? WHERE plan_hash=?",
                            (state, _json(verified) if verified else None, plan_hash))
        return self.get(plan_hash)


def _read_json(path: str) -> Any:
    with open(path, "rb") as handle:
        raw = handle.read(4_194_305)
    if len(raw) > 4_194_304:
        raise DeploymentError("JSON input exceeds 4 MiB")
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--allow-controlled-test", action="store_true",
                        help="explicitly permit the labeled single-operator test committee; never an independence claim")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("plan", help="read-only policy, RPC and constructor validation")
    command.add_argument("--policy", required=True)
    command.add_argument("--artifact", required=True)
    command.add_argument("--output", required=True)
    command = commands.add_parser("execute", help="dry-run unless --send is explicit")
    command.add_argument("--plan", required=True)
    command.add_argument("--approved-plan-hash")
    command.add_argument("--key-file")
    for cap in ("gas-price-wei", "gas-units", "total-gas-cost-wei"):
        command.add_argument("--max-" + cap, type=int)
    for action in ("reconcile", "rebroadcast"):
        cmd = commands.add_parser(action)
        cmd.add_argument("--plan-hash", required=True)
        if action == "reconcile":
            cmd.add_argument("--manifest-output")
    for name in ("execute", "reconcile", "rebroadcast"):
        commands.choices[name].add_argument("--outbox", required=True)
    for name in ("execute", "rebroadcast"):
        commands.choices[name].add_argument("--send", action="store_true")
    args = parser.parse_args(argv)
    client = V9DeploymentClient(args.rpc_url, allow_controlled_test=args.allow_controlled_test)
    try:
        if args.command == "plan":
            result = client.plan(_read_json(args.policy), load_artifact(args.artifact))
            # Exclusive creation prevents accidentally replacing a reviewed plan.
            with open(args.output, "x", encoding="utf-8") as handle:
                handle.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
            result = {key: result[key] for key in ("plan_hash", "dry_run", "estimate", "manifest_candidate")}
        else:
            outbox = V9DeploymentOutbox(args.outbox)
            try:
                if args.command == "execute":
                    result = outbox.execute(client, _read_json(args.plan), allow_send=args.send,
                        approved_plan_hash=args.approved_plan_hash, key_file=args.key_file,
                        max_gas_price_wei=args.max_gas_price_wei, max_gas_units=args.max_gas_units,
                        max_total_gas_cost_wei=args.max_total_gas_cost_wei)
                elif args.command == "rebroadcast":
                    result = outbox.rebroadcast(client, args.plan_hash, allow_send=args.send)
                else:
                    result = outbox.reconcile(client, args.plan_hash)
                    if args.manifest_output:
                        if result["state"] != "confirmed":
                            raise DeploymentError("only a verified confirmed deployment can write a manifest")
                        with open(args.manifest_output, "x", encoding="utf-8") as handle:
                            handle.write(json.dumps(result["verification"]["manifest"], indent=2, sort_keys=True) + "\n")
            finally:
                outbox.close()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (chain.ChainError, ValueError, KeyError, TypeError, OSError, sqlite3.Error) as exc:
        parser.exit(1, f"deployment failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
