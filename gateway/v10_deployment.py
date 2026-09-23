"""Safe, explicit V10 registry/settlement deployment plans.

Planning is read-only.  Sending is opt-in and advances exactly one confirmed
stage at a time:

    ProviderJuryRegistryV1 -> MycoSettlementV10 -> bindSettlement

The second transaction is never signed before the registry deployment is
confirmed and verified; the binding transaction is never signed before both
contracts are confirmed and verified.  This deliberately trades speed for a
small, recoverable deployment state machine.

The timing gate is deliberately only a conservative controlled-Sepolia budget,
not a production liveness guarantee.  It budgets a slow 15-second block, three
confirmation windows (case intake, jury assignment, and vote), the pinned
Provider-jury task TTL, and an additional transaction/scheduling margin.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import chain, chain_v9, chain_v10


class DeploymentError(chain.ChainError):
    pass


PLAN_SCHEMA = "mycomesh.v10.deployment-plan.v1"
STEPS = ("registry", "settlement", "bind")
CONFIG_FIELDS = (
    "input_per_1k", "output_per_1k", "minimum_fee", "provider_bps",
    "relay_bps", "pool_bps", "treasury_bps", "active",
)
DISPUTE_POLICY_FIELDS = chain_v9.POLICY_FIELDS
REGISTRY_FIELDS = (
    "reputation_authority", "bond_penalty_recipient", "minimum_reputation",
    "jury_size", "threshold", "selection_delay_blocks",
)
POLICY_FIELDS = {
    "chain_id", "genesis_hash", "confirmations", "deployer", "stablecoin",
    "reward_token", "treasury", "governance", "initial_channel",
    "initial_config", "dispute_policy", "registry", "fee_policy",
    "source_commit", "artifact_pins", "deployment_class", "network_id",
    "jury_decision_policy_hash", "reputation_history_import",
}
ARTIFACT_PIN_FIELDS = {
    "source_sha256", "creation_keccak256", "runtime_template_keccak256",
}

# These assumptions belong to the explicitly controlled Sepolia deployment
# class.  A production randomness/finality design must supply its own measured
# timing policy instead of treating this budget as a guarantee.
CONTROLLED_SEPOLIA_BLOCK_BUDGET_SECONDS = 15
CONTROLLED_SEPOLIA_JURY_TASK_TTL_SECONDS = 300
CONTROLLED_SEPOLIA_FINALITY_PHASES = 3
CONTROLLED_SEPOLIA_TRANSACTION_MARGIN_SECONDS = 120
SEPOLIA_CHAIN_ID = 11_155_111
SEPOLIA_GENESIS_HASH = "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"
RPC_QUORUM_SIZE = 3
CONTROLLED_NETWORK_ID_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?-controlled-test$"
)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value: Any) -> str:
    return "0x" + chain.keccak256(_json(value).encode()).hex()


def _decode_strict_json(raw: bytes, *, name: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for field, item in items:
            if field in result:
                raise DeploymentError(f"{name} repeats field {field!r}")
            result[field] = item
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                DeploymentError(f"{name} contains non-finite value {value!r}")
            ),
        )
    except UnicodeDecodeError as exc:
        raise DeploymentError(f"{name} must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"{name} must be strict JSON") from exc


def _uint(value: Any, name: str, *, positive: bool = False, bits: int = 256) -> int:
    if type(value) is not int or not int(positive) <= value < 2**bits:
        raise DeploymentError(f"invalid {name}")
    return value


def _rpc_quantity(value: Any, name: str, *, bits: int = 256) -> int:
    try:
        parsed = int(value, 16)
    except (TypeError, ValueError):
        raise DeploymentError(f"RPC returned an invalid {name}") from None
    if (
        not isinstance(value, str)
        or value != hex(parsed)
        or parsed < 0
        or parsed >= 2**bits
    ):
        raise DeploymentError(f"RPC returned a noncanonical {name}")
    return parsed


def _rpc_endpoint_pin(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _validate_rpc_endpoint_pins(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) not in (1, RPC_QUORUM_SIZE)
        or len(set(value)) != len(value)
    ):
        raise DeploymentError("V10 plan requires one test RPC pin or three quorum RPC pins")
    for pin in value:
        if (
            not isinstance(pin, str)
            or len(pin) != 64
            or pin != pin.lower()
            or pin == "0" * 64
        ):
            raise DeploymentError("invalid V10 RPC endpoint pin")
        try:
            bytes.fromhex(pin)
        except ValueError:
            raise DeploymentError("invalid V10 RPC endpoint pin") from None
    return list(value)


def _normalized_rpc_hostname(hostname: str) -> str:
    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        try:
            normalized = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            raise DeploymentError("deployment RPC endpoint has an invalid hostname") from None
        if not normalized:
            raise DeploymentError("deployment RPC endpoint has an invalid hostname")
        return normalized


def _is_loopback_rpc_hostname(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _address(value: Any, name: str, *, zero: bool = False) -> str:
    try:
        result = chain.normalize_address(value)
    except (chain.ChainError, TypeError):
        raise DeploymentError(f"invalid {name}") from None
    if not zero and result == chain.ZERO_ADDRESS:
        raise DeploymentError(f"zero {name}")
    return result


def _bytes(value: Any, name: str, *, empty: bool = False) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) % 2:
        raise DeploymentError(f"invalid {name}")
    try:
        result = bytes.fromhex(value[2:])
    except ValueError:
        raise DeploymentError(f"invalid {name}") from None
    if not result and not empty:
        raise DeploymentError(f"empty {name}")
    return result


def _decode_rlp_item(
    raw: bytes, offset: int = 0, *, allow_list: bool = True,
) -> tuple[bytes | list[Any], int]:
    """Decode one canonical RLP item from untrusted outbox persistence."""
    if offset >= len(raw):
        raise DeploymentError("truncated stored V10 transaction RLP")
    prefix = raw[offset]
    if prefix < 0x80:
        return bytes([prefix]), offset + 1
    if prefix <= 0xB7:
        length = prefix - 0x80
        start, end = offset + 1, offset + 1 + length
        if end > len(raw):
            raise DeploymentError("truncated stored V10 transaction RLP")
        value = raw[start:end]
        if length == 1 and value[0] < 0x80:
            raise DeploymentError("noncanonical stored V10 transaction RLP")
        return value, end
    if prefix <= 0xBF:
        length_size = prefix - 0xB7
        start, stop = offset + 1, offset + 1 + length_size
        if stop > len(raw) or raw[start] == 0:
            raise DeploymentError("noncanonical stored V10 transaction RLP")
        length = int.from_bytes(raw[start:stop], "big")
        if length < 56:
            raise DeploymentError("noncanonical stored V10 transaction RLP")
        end = stop + length
        if end > len(raw):
            raise DeploymentError("truncated stored V10 transaction RLP")
        return raw[stop:end], end

    if not allow_list:
        raise DeploymentError("stored V10 transaction contains nested RLP fields")
    if prefix <= 0xF7:
        length, start = prefix - 0xC0, offset + 1
    else:
        length_size = prefix - 0xF7
        length_start, start = offset + 1, offset + 1 + length_size
        if start > len(raw) or raw[length_start] == 0:
            raise DeploymentError("noncanonical stored V10 transaction RLP")
        length = int.from_bytes(raw[length_start:start], "big")
        if length < 56:
            raise DeploymentError("noncanonical stored V10 transaction RLP")
    end = start + length
    if end > len(raw):
        raise DeploymentError("truncated stored V10 transaction RLP")
    items: list[Any] = []
    cursor = start
    while cursor < end:
        item, cursor = _decode_rlp_item(raw, cursor, allow_list=False)
        if cursor > end:
            raise DeploymentError("stored V10 transaction RLP crosses its list boundary")
        items.append(item)
    if cursor != end:
        raise DeploymentError("invalid stored V10 transaction RLP list")
    return items, end


def _rlp_uint(value: Any, name: str) -> int:
    if not isinstance(value, bytes) or (value and value[0] == 0) or len(value) > 32:
        raise DeploymentError(f"invalid stored V10 transaction {name}")
    return int.from_bytes(value, "big")


def _decode_signed_legacy_transaction(raw_hex: Any) -> dict[str, Any]:
    raw = _bytes(raw_hex, "stored raw transaction")
    # Approved creation payloads are already capped by EIP-3860. This leaves
    # ample framing room without permitting an unbounded recovery-time parse.
    if len(raw) > 65_536:
        raise DeploymentError("stored V10 transaction exceeds the safety bound")
    item, end = _decode_rlp_item(raw)
    if end != len(raw) or not isinstance(item, list) or len(item) != 9:
        raise DeploymentError("stored V10 transaction is not one canonical legacy transaction")
    if any(not isinstance(field, bytes) for field in item):
        raise DeploymentError("stored V10 transaction contains nested RLP fields")
    nonce, gas_price, gas_units = (
        _rlp_uint(item[0], "nonce"),
        _rlp_uint(item[1], "gas price"),
        _rlp_uint(item[2], "gas limit"),
    )
    to_raw = item[3]
    if len(to_raw) not in (0, 20):
        raise DeploymentError("invalid stored V10 transaction destination")
    to = None if not to_raw else "0x" + to_raw.hex()
    value = _rlp_uint(item[4], "value")
    data = item[5]
    v, r, s = (
        _rlp_uint(item[6], "v"),
        _rlp_uint(item[7], "r"),
        _rlp_uint(item[8], "s"),
    )
    if v < 35:
        raise DeploymentError("stored V10 transaction is not EIP-155 protected")
    recovery_id = (v - 35) % 2
    chain_id = (v - 35 - recovery_id) // 2
    if chain_id <= 0 or v != chain_id * 2 + 35 + recovery_id:
        raise DeploymentError("stored V10 transaction has an invalid EIP-155 chain id")
    if not 0 < r < chain.SECP256K1_N or not 0 < s <= chain.SECP256K1_N // 2:
        raise DeploymentError("stored V10 transaction has an invalid signature")
    signing_payload = chain.rlp_encode(
        [nonce, gas_price, gas_units, to_raw, value, data, chain_id, 0, 0]
    )
    sender = chain.recover_evm_address(
        chain.keccak256(signing_payload),
        chain.EvmSignature(
            r="0x" + r.to_bytes(32, "big").hex(),
            s="0x" + s.to_bytes(32, "big").hex(),
            v=recovery_id,
        ),
    )
    return {
        "raw": raw,
        "chain_id": chain_id,
        "sender": sender,
        "nonce": nonce,
        "gas_price_wei": gas_price,
        "gas_units": gas_units,
        "to": to,
        "value": value,
        "data": data,
    }


def _verify_stored_raw_transaction(
    plan: Mapping[str, Any], step: str, raw_hex: Any, tx_hash: Any,
) -> bytes:
    if step not in STEPS:
        raise DeploymentError("invalid stored V10 deployment step")
    decoded = _decode_signed_legacy_transaction(raw_hex)
    observed_hash = "0x" + chain.keccak256(decoded["raw"]).hex()
    if tx_hash != observed_hash:
        raise DeploymentError("stored V10 transaction hash mismatch")
    expected = plan["transactions"][step]
    if (
        decoded["chain_id"] != expected["chain_id"]
        or decoded["sender"] != expected["from"]
        or decoded["nonce"] != expected["nonce"]
        or decoded["gas_price_wei"] != expected["gas_price_wei"]
        or decoded["gas_units"] != expected["gas_units"]
        or decoded["to"] != expected["to"]
        or decoded["value"] != int(expected["value"], 16)
        or decoded["data"] != _bytes(expected["data"], f"{step} transaction data")
    ):
        raise DeploymentError("stored V10 transaction differs from its approved plan")
    return decoded["raw"]


def _words(values: Any) -> bytes:
    return b"".join(chain.abi_encode_arg(str(v).lower() if type(v) is bool else str(v)) for v in values)


def _normalize_mapping(value: Any, fields: set[str] | tuple[str, ...], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise DeploymentError(f"{name} requires exactly: " + ", ".join(sorted(fields)))
    return dict(value)


def _canonical_nonzero_bytes32(value: Any, name: str) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (chain.ChainError, TypeError):
        raise DeploymentError(f"invalid {name}") from None
    if value != normalized or normalized == chain.ZERO_BYTES32:
        raise DeploymentError(f"invalid {name}")
    return normalized


def _validate_reputation_history_import(
    value: Any, *, chain_id: int, genesis_hash: str, network_id: str,
) -> dict[str, Any]:
    history = _normalize_mapping(
        value, chain_v10.REPUTATION_HISTORY_FIELDS,
        "reputation_history_import",
    )
    source_network = history.get("source_network_id")
    source_protocol = history.get("source_protocol_version")
    source_chain = history.get("source_chain_id")
    if (
        history.get("schema") != chain_v10.REPUTATION_HISTORY_SCHEMA
        or not isinstance(source_network, str)
        or not source_network
        or source_network != source_network.strip()
        or len(source_network) > 160
        or source_network == network_id
        or type(source_protocol) is not int
        or source_protocol not in (9, 10)
        or type(source_chain) is not int
        or source_chain != chain_id
    ):
        raise DeploymentError(
            "reputation history must identify a distinct prior V9/V10 network on the target chain"
        )
    history["source_genesis_hash"] = _canonical_nonzero_bytes32(
        history.get("source_genesis_hash"), "history source genesis hash",
    )
    if history["source_genesis_hash"] != genesis_hash:
        raise DeploymentError("reputation history genesis differs from the target chain")
    raw_settlement = history.get("source_settlement_contract")
    history["source_settlement_contract"] = _address(
        raw_settlement, "history source settlement",
    )
    if raw_settlement != history["source_settlement_contract"]:
        raise DeploymentError("history source settlement must be canonical")
    history["source_runtime_code_hash"] = _canonical_nonzero_bytes32(
        history.get("source_runtime_code_hash"), "history source runtime code hash",
    )
    deployment_block = _uint(
        history.get("source_deployment_block"),
        "history source deployment block", positive=True, bits=64,
    )
    through_block = _uint(
        history.get("source_history_through_block"),
        "history source through block", positive=True, bits=64,
    )
    if through_block < deployment_block:
        raise DeploymentError("reputation history cutoff predates source deployment")
    history["source_deployment_block"] = deployment_block
    history["source_deployment_block_hash"] = _canonical_nonzero_bytes32(
        history.get("source_deployment_block_hash"),
        "history source deployment block hash",
    )
    history["source_history_through_block"] = through_block
    history["source_history_through_block_hash"] = _canonical_nonzero_bytes32(
        history.get("source_history_through_block_hash"),
        "history source through block hash",
    )
    confirmations = _uint(
        history.get("confirmations"), "history confirmations", positive=True, bits=16,
    )
    if not 2 <= confirmations <= 256:
        raise DeploymentError("history confirmations must be between two and 256")
    history["confirmations"] = confirmations
    artifact_sha = history.get("artifact_sha256")
    if (
        not isinstance(artifact_sha, str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact_sha) is None
        or artifact_sha == "0" * 64
    ):
        raise DeploymentError("invalid reputation history artifact sha256")
    history["artifact_root"] = _canonical_nonzero_bytes32(
        history.get("artifact_root"), "reputation history artifact root",
    )
    return history


def controlled_sepolia_min_arbitration_timeout_seconds(
    *, selection_delay_blocks: int, confirmations: int,
) -> int:
    """Return the conservative controlled-test adjudication budget.

    The extra block is required because ``finalizeJury`` becomes callable only
    after the selected future block.  Confirmation phases are intentionally
    summed even where they may overlap in normal operation.
    """
    return (
        (
            selection_delay_blocks + 1
            + confirmations * CONTROLLED_SEPOLIA_FINALITY_PHASES
        ) * CONTROLLED_SEPOLIA_BLOCK_BUDGET_SECONDS
        + CONTROLLED_SEPOLIA_JURY_TASK_TTL_SECONDS
        + CONTROLLED_SEPOLIA_TRANSACTION_MARGIN_SECONDS
    )


def validate_policy(value: Any) -> dict[str, Any]:
    value = _normalize_mapping(value, POLICY_FIELDS, "V10 deployment policy")
    value = json.loads(_json(value))
    if value["deployment_class"] != "controlled_test":
        raise DeploymentError(
            "future_blockhash V10 deployment must be explicitly classified controlled_test"
        )
    value["chain_id"] = _uint(value["chain_id"], "chain_id", positive=True, bits=64)
    value["confirmations"] = _uint(value["confirmations"], "confirmations", positive=True, bits=32)
    value["genesis_hash"] = chain.normalize_bytes32(value["genesis_hash"])
    if value["genesis_hash"] == "0x" + "00" * 32:
        raise DeploymentError("genesis hash cannot be zero")
    network_id = value.get("network_id")
    if (
        not isinstance(network_id, str)
        or len(network_id) > 160
        or CONTROLLED_NETWORK_ID_RE.fullmatch(network_id) is None
        or "--" in network_id
    ):
        raise DeploymentError(
            "network_id must be a canonical lowercase controlled-test identifier"
        )
    value["jury_decision_policy_hash"] = _canonical_nonzero_bytes32(
        value.get("jury_decision_policy_hash"), "jury decision policy hash",
    )
    value["reputation_history_import"] = _validate_reputation_history_import(
        value.get("reputation_history_import"),
        chain_id=value["chain_id"], genesis_hash=value["genesis_hash"],
        network_id=network_id,
    )
    for name in ("deployer", "stablecoin", "treasury", "governance"):
        value[name] = _address(value[name], name)
    if value["deployer"] != value["governance"]:
        raise DeploymentError("staged V10 deployment requires the deployer to be registry governance for binding")
    value["reward_token"] = _address(value["reward_token"], "reward_token", zero=True)
    if value["reward_token"] != chain.ZERO_ADDRESS:
        raise DeploymentError("V10 reward token must be disabled")
    source_commit = value["source_commit"]
    if (not isinstance(source_commit, str) or len(source_commit) != 40
            or source_commit != source_commit.lower()
            or source_commit == "0" * 40):
        raise DeploymentError("source_commit must be a canonical nonzero full Git commit")
    try:
        bytes.fromhex(source_commit)
    except ValueError:
        raise DeploymentError("source_commit must be a canonical nonzero full Git commit") from None
    pins = _normalize_mapping(value["artifact_pins"], {"registry", "settlement"}, "artifact_pins")
    for name in ("registry", "settlement"):
        pin = _normalize_mapping(pins[name], ARTIFACT_PIN_FIELDS, f"{name} artifact pin")
        source_hash = pin["source_sha256"]
        if (not isinstance(source_hash, str) or len(source_hash) != 64
                or source_hash != source_hash.lower() or source_hash == "0" * 64):
            raise DeploymentError(f"invalid {name} artifact source hash pin")
        try:
            bytes.fromhex(source_hash)
        except ValueError:
            raise DeploymentError(f"invalid {name} artifact source hash pin") from None
        for field in ("creation_keccak256", "runtime_template_keccak256"):
            try:
                normalized = chain.normalize_bytes32(pin[field])
            except (chain.ChainError, TypeError):
                raise DeploymentError(f"invalid {name} {field} pin") from None
            if normalized != pin[field] or normalized == chain.ZERO_BYTES32:
                raise DeploymentError(f"invalid {name} {field} pin")
        pins[name] = pin
    value["artifact_pins"] = pins
    value["initial_channel"] = chain.normalize_bytes32(value["initial_channel"])
    if value["initial_channel"] == "0x" + "00" * 32:
        raise DeploymentError("initial channel cannot be zero")

    config = _normalize_mapping(value["initial_config"], CONFIG_FIELDS, "initial_config")
    for name in CONFIG_FIELDS[:-1]:
        config[name] = _uint(config[name], name, bits=16 if name.endswith("bps") else 256)
    if config["active"] is not True or sum(config[name] for name in CONFIG_FIELDS[3:7]) != 10_000:
        raise DeploymentError("initial channel must be active and shares must total 10000 bps")
    value["initial_config"] = config

    dispute = _normalize_mapping(value["dispute_policy"], DISPUTE_POLICY_FIELDS, "dispute_policy")
    for name in DISPUTE_POLICY_FIELDS[:-1]:
        bits = 64 if name in ("dispute_window", "arbitration_timeout", "consumer_withdrawal_delay") else 16 if name.endswith("bps") else 256
        dispute[name] = _uint(dispute[name], name, bits=bits)
    dispute["bond_penalty_recipient"] = _address(dispute["bond_penalty_recipient"], "bond_penalty_recipient")
    if not all(0 < dispute[name] <= 30 * 86400 for name in
               ("dispute_window", "arbitration_timeout", "consumer_withdrawal_delay")):
        raise DeploymentError("V10 dispute time bounds are invalid")
    if (dispute["reporter_bond"] <= 0 or not 0 < dispute["slash_bps"] <= 10_000
            or dispute["slash_cap"] <= 0 or not 0 < dispute["reporter_bounty_bps"] < 10_000
            or not 0 < dispute["stable_bounty_cap"] <= dispute["slash_cap"]):
        raise DeploymentError("V10 dispute monetary policy is invalid")
    if any(dispute[name] != 0 for name in
           ("token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty")):
        raise DeploymentError("V10 token rewards must be disabled")
    value["dispute_policy"] = dispute

    registry = _normalize_mapping(value["registry"], REGISTRY_FIELDS, "registry")
    registry["reputation_authority"] = _address(registry["reputation_authority"], "reputation_authority")
    registry["bond_penalty_recipient"] = _address(registry["bond_penalty_recipient"], "registry bond_penalty_recipient")
    registry["minimum_reputation"] = _uint(registry["minimum_reputation"], "minimum_reputation", positive=True, bits=64)
    for name in ("jury_size", "threshold", "selection_delay_blocks"):
        registry[name] = _uint(registry[name], name, positive=True, bits=16)
    if not (3 <= registry["jury_size"] <= 7 and 2 <= registry["threshold"] <= registry["jury_size"]
            and registry["threshold"] > registry["jury_size"] // 2):
        raise DeploymentError("V10 jury threshold policy is invalid")
    if registry["selection_delay_blocks"] > 64:
        raise DeploymentError("V10 jury selection delay exceeds blockhash availability")
    minimum_arbitration_timeout = controlled_sepolia_min_arbitration_timeout_seconds(
        selection_delay_blocks=registry["selection_delay_blocks"],
        confirmations=value["confirmations"],
    )
    if dispute["arbitration_timeout"] < minimum_arbitration_timeout:
        raise DeploymentError(
            "V10 arbitration_timeout is below the controlled-Sepolia jury "
            f"liveness budget ({minimum_arbitration_timeout} seconds)"
        )
    registry_roles = {
        value["governance"],
        registry["reputation_authority"],
        registry["bond_penalty_recipient"],
    }
    if len(registry_roles) != 3:
        raise DeploymentError(
            "governance, reputation authority, and bond penalty recipient "
            "must be distinct identities"
        )
    if registry["bond_penalty_recipient"] != dispute["bond_penalty_recipient"]:
        raise DeploymentError("registry and settlement bond penalty recipients must match")
    value["registry"] = registry

    fees = _normalize_mapping(value["fee_policy"], {"gas_price_wei", "gas_limits", "max_total_gas_cost_wei"}, "fee_policy")
    fees["gas_price_wei"] = _uint(fees["gas_price_wei"], "gas_price_wei", positive=True)
    limits = _normalize_mapping(fees["gas_limits"], set(STEPS), "gas_limits")
    for step in STEPS:
        limits[step] = _uint(limits[step], f"{step} gas limit", positive=True, bits=64)
        if limits[step] > 30_000_000:
            raise DeploymentError(f"{step} gas limit exceeds safety bound")
    fees["gas_limits"] = limits
    fees["max_total_gas_cost_wei"] = _uint(fees["max_total_gas_cost_wei"], "max_total_gas_cost_wei", positive=True)
    total = fees["gas_price_wei"] * sum(limits.values())
    if total > fees["max_total_gas_cost_wei"]:
        raise DeploymentError("fixed V10 transactions exceed maximum total gas cost")
    value["fee_policy"] = fees
    return json.loads(_json(value))


def _masked_runtime(code: str, artifact: Mapping[str, Any]) -> bytes:
    result = bytearray(_bytes(code, "runtime bytecode"))
    covered: set[int] = set()
    references = artifact.get("immutable_references")
    if not isinstance(references, Mapping):
        raise DeploymentError("artifact immutable references are invalid")
    for entries in references.values():
        if not isinstance(entries, list):
            raise DeploymentError("artifact immutable references are invalid")
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise DeploymentError("artifact immutable reference is invalid")
            start = _uint(entry.get("start"), "immutable start")
            length = _uint(entry.get("length"), "immutable length", positive=True)
            if length != 32 or start + length > len(result):
                raise DeploymentError("invalid immutable reference")
            positions = set(range(start, start + length))
            if covered & positions:
                raise DeploymentError("overlapping immutable references")
            covered |= positions
            result[start:start + length] = b"\0" * length
    return bytes(result)


def load_artifact(path: str | Path, contract: str) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    if len(raw) > 4_194_304:
        raise DeploymentError("compiler artifact exceeds 4 MiB")
    value = _decode_strict_json(raw, name="compiler artifact")
    if not isinstance(value, Mapping):
        raise DeploymentError("compiler artifact must be a JSON object")
    target = value.get("metadata", {}).get("settings", {}).get("compilationTarget", {})
    if not isinstance(target, Mapping) or list(target.values()) != [contract]:
        raise DeploymentError(f"artifact compilation target is not {contract}")
    constructors = [item for item in value.get("abi", []) if item.get("type") == "constructor"]
    expected = {
        "ProviderJuryRegistryV1": ["address", "address", "address", "uint64", "uint16", "uint16", "uint16"],
        "MycoSettlementV10": ["address", "address", "address", "address", "bytes32", "tuple", "tuple", "address"],
    }
    if contract not in expected or len(constructors) != 1 or [item.get("type") for item in constructors[0].get("inputs", [])] != expected[contract]:
        raise DeploymentError(f"artifact is not the {contract} constructor ABI")
    if contract == "MycoSettlementV10":
        inputs = constructors[0]["inputs"]
        if ([v.get("type") for v in inputs[5].get("components", [])] != ["uint256"] * 3 + ["uint16"] * 4 + ["bool"]
                or [v.get("type") for v in inputs[6].get("components", [])] !=
                ["uint64"] * 3 + ["uint256", "uint16", "uint256", "uint16"] + ["uint256"] * 5 + ["address"]):
            raise DeploymentError("settlement artifact has the wrong tuple ABI")
    creation, runtime = value.get("bytecode", {}), value.get("deployedBytecode", {})
    if creation.get("linkReferences") or runtime.get("linkReferences"):
        raise DeploymentError("linked artifacts are not supported")
    artifact = {
        "contract": contract,
        "creation_bytecode": creation.get("object"),
        "runtime_template": runtime.get("object"),
        "immutable_references": runtime.get("immutableReferences", {}),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
    }
    creation_bytes = _bytes(artifact["creation_bytecode"], "creation bytecode")
    runtime_bytes = _bytes(artifact["runtime_template"], "runtime bytecode")
    _masked_runtime(artifact["runtime_template"], artifact)
    artifact["creation_keccak256"] = "0x" + chain.keccak256(creation_bytes).hex()
    artifact["runtime_template_keccak256"] = "0x" + chain.keccak256(runtime_bytes).hex()
    return artifact


def registry_constructor_data(policy: Mapping[str, Any]) -> bytes:
    p = validate_policy(policy)
    r = p["registry"]
    return _words([p["governance"], r["reputation_authority"], r["bond_penalty_recipient"],
                   r["minimum_reputation"], r["jury_size"], r["threshold"], r["selection_delay_blocks"]])


def settlement_constructor_data(policy: Mapping[str, Any], registry: str) -> bytes:
    p = validate_policy(policy)
    return _words([p["stablecoin"], p["reward_token"], p["treasury"], p["governance"], p["initial_channel"],
                   *[p["initial_config"][name] for name in CONFIG_FIELDS],
                   *[p["dispute_policy"][name] for name in DISPUTE_POLICY_FIELDS],
                   _address(registry, "predicted registry")])


def bind_calldata(settlement: str) -> str:
    return chain.encode_contract_call("bindSettlement(address)", [_address(settlement, "predicted settlement")])


def _transactions(policy: Mapping[str, Any], artifacts: Mapping[str, Any],
                  addresses: Mapping[str, str], nonce: int) -> dict[str, Any]:
    registry_data = "0x" + (_bytes(artifacts["registry"]["creation_bytecode"], "registry creation bytecode")
                              + registry_constructor_data(policy)).hex()
    settlement_data = "0x" + (_bytes(artifacts["settlement"]["creation_bytecode"], "settlement creation bytecode")
                                + settlement_constructor_data(policy, addresses["registry"])).hex()
    price = policy["fee_policy"]["gas_price_wei"]
    limits = policy["fee_policy"]["gas_limits"]
    return {
        "registry": {"from": policy["deployer"], "to": None, "data": registry_data, "value": "0x0",
                     "chain_id": policy["chain_id"], "nonce": nonce, "gas_price_wei": price, "gas_units": limits["registry"]},
        "settlement": {"from": policy["deployer"], "to": None, "data": settlement_data, "value": "0x0",
                       "chain_id": policy["chain_id"], "nonce": nonce + 1, "gas_price_wei": price, "gas_units": limits["settlement"]},
        "bind": {"from": policy["deployer"], "to": addresses["registry"],
                 "data": bind_calldata(addresses["settlement"]), "value": "0x0",
                 "chain_id": policy["chain_id"], "nonce": nonce + 2,
                 "gas_price_wei": price, "gas_units": limits["bind"]},
    }


def validate_artifacts(artifacts: Any) -> dict[str, Any]:
    artifacts = _normalize_mapping(artifacts, {"registry", "settlement"}, "artifacts")
    for key, contract in (("registry", "ProviderJuryRegistryV1"), ("settlement", "MycoSettlementV10")):
        artifact = artifacts[key]
        expected_fields = {"contract", "creation_bytecode", "runtime_template", "immutable_references",
                           "source_sha256", "creation_keccak256", "runtime_template_keccak256"}
        if not isinstance(artifact, Mapping) or set(artifact) != expected_fields or artifact.get("contract") != contract:
            raise DeploymentError(f"wrong {key} artifact")
        creation = _bytes(artifact.get("creation_bytecode"), f"{key} creation bytecode")
        runtime = _bytes(artifact.get("runtime_template"), f"{key} runtime bytecode")
        _masked_runtime(artifact.get("runtime_template"), artifact)
        if artifact.get("creation_keccak256") != "0x" + chain.keccak256(creation).hex():
            raise DeploymentError(f"modified {key} creation bytecode")
        if artifact.get("runtime_template_keccak256") != "0x" + chain.keccak256(runtime).hex():
            raise DeploymentError(f"modified {key} runtime bytecode")
        source_hash = artifact.get("source_sha256")
        if not isinstance(source_hash, str) or len(source_hash) != 64:
            raise DeploymentError(f"invalid {key} artifact source hash")
        try:
            bytes.fromhex(source_hash)
        except ValueError:
            raise DeploymentError(f"invalid {key} artifact source hash") from None
    return json.loads(_json(artifacts))


def _verify_artifact_pins(policy: Mapping[str, Any], artifacts: Mapping[str, Any]) -> None:
    for name in ("registry", "settlement"):
        pin = policy["artifact_pins"][name]
        if any(artifacts[name].get(field) != pin[field] for field in ARTIFACT_PIN_FIELDS):
            raise DeploymentError(
                f"{name} compiler artifact differs from the independently approved policy pin"
            )


def validate_plan(plan: Mapping[str, Any]) -> None:
    fields = {"schema", "dry_run", "policy", "policy_hash", "artifacts", "addresses", "transactions",
              "stablecoin_runtime_code_hash", "rpc_endpoint_pins", "snapshot",
              "total_gas_cost_wei", "plan_hash"}
    if (not isinstance(plan, Mapping) or set(plan) != fields or plan.get("schema") != PLAN_SCHEMA
            or plan.get("dry_run") is not True):
        raise DeploymentError("invalid V10 deployment plan schema")
    unsigned = {key: value for key, value in plan.items() if key != "plan_hash"}
    if plan.get("plan_hash") != _hash(unsigned):
        raise DeploymentError("invalid or modified V10 deployment plan")
    policy = validate_policy(plan.get("policy"))
    artifacts = validate_artifacts(plan.get("artifacts"))
    _verify_artifact_pins(policy, artifacts)
    if plan.get("policy_hash") != _hash(policy):
        raise DeploymentError("V10 deployment policy hash mismatch")
    transactions = plan.get("transactions", {})
    if not isinstance(transactions, Mapping) or set(transactions) != set(STEPS):
        raise DeploymentError("V10 plan does not contain exactly three transactions")
    nonce = transactions["registry"].get("nonce") if isinstance(transactions["registry"], Mapping) else None
    _uint(nonce, "registry transaction nonce")
    expected_addresses = {
        "registry": chain.derive_contract_address(policy["deployer"], nonce),
        "settlement": chain.derive_contract_address(policy["deployer"], nonce + 1),
    }
    if (
        policy["reputation_history_import"]["source_settlement_contract"]
        == expected_addresses["settlement"]
    ):
        raise DeploymentError(
            "reputation history source settlement conflicts with the predicted new Settlement"
        )
    if plan.get("addresses") != expected_addresses:
        raise DeploymentError("V10 predicted addresses differ from deployer nonce")
    if transactions != _transactions(policy, artifacts, expected_addresses, nonce):
        raise DeploymentError("V10 transactions differ from approved artifacts and constructor policy")
    expected_cost = policy["fee_policy"]["gas_price_wei"] * sum(policy["fee_policy"]["gas_limits"].values())
    if plan.get("total_gas_cost_wei") != expected_cost:
        raise DeploymentError("V10 total gas cost differs from fixed transaction fees")
    try:
        stablecoin_hash = chain.normalize_bytes32(plan.get("stablecoin_runtime_code_hash"))
    except chain.ChainError:
        raise DeploymentError("invalid pinned stablecoin runtime code hash") from None
    if stablecoin_hash == "0x" + "00" * 32:
        raise DeploymentError("pinned stablecoin runtime code hash cannot be zero")
    _validate_rpc_endpoint_pins(plan.get("rpc_endpoint_pins"))
    snapshot = plan.get("snapshot")
    if (not isinstance(snapshot, Mapping) or set(snapshot) != {"block_number", "block_hash", "timestamp"}
            or type(snapshot["block_number"]) is not int or snapshot["block_number"] < 0
            or type(snapshot["timestamp"]) is not int or snapshot["timestamp"] <= 0):
        raise DeploymentError("invalid V10 planning snapshot")
    chain.normalize_bytes32(snapshot["block_hash"])


class V10DeploymentClient:
    def __init__(self, rpc_url: str | list[str] | tuple[str, ...], *, timeout: int = 15,
                 max_snapshot_age: int = 300, allow_single_test_rpc: bool = False):
        if isinstance(rpc_url, str):
            rpc_urls = (rpc_url,)
        elif isinstance(rpc_url, (list, tuple)):
            rpc_urls = tuple(rpc_url)
        else:
            raise DeploymentError("deployment RPC endpoints must be explicit URLs")
        if (
            not all(isinstance(endpoint, str) for endpoint in rpc_urls)
            or len(rpc_urls) not in (1, RPC_QUORUM_SIZE)
            or len(set(rpc_urls)) != len(rpc_urls)
        ):
            raise DeploymentError(
                "deployment requires one test RPC or three distinct pinned quorum RPCs"
            )
        test_only = len(rpc_urls) == 1 and allow_single_test_rpc is True
        if len(rpc_urls) == 1 and not test_only:
            raise DeploymentError(
                "single RPC is test-only and requires allow_single_test_rpc=True"
            )
        hostnames: list[str] = []
        for endpoint in rpc_urls:
            if any(character.isspace() for character in endpoint):
                raise DeploymentError("deployment RPC endpoints must not contain whitespace")
            try:
                url = urlsplit(endpoint)
                hostname = url.hostname
                port = url.port
            except ValueError:
                raise DeploymentError("deployment RPC endpoint is malformed") from None
            if (
                "," in endpoint
                or not hostname
                or url.username is not None
                or url.password is not None
                or "@" in url.netloc
                or "?" in endpoint
                or "#" in endpoint
                or url.query
                or url.fragment
                or port is not None and not 0 < port < 65_536
            ):
                raise DeploymentError(
                    "deployment RPC endpoints must be credential-free URLs without query or fragment"
                )
            normalized_hostname = _normalized_rpc_hostname(hostname)
            if test_only:
                if url.scheme not in ("http", "https") or not _is_loopback_rpc_hostname(
                    normalized_hostname
                ):
                    raise DeploymentError(
                        "single test RPC must be an explicit loopback HTTP(S) endpoint"
                    )
            elif url.scheme != "https" or _is_loopback_rpc_hostname(normalized_hostname):
                raise DeploymentError(
                    "live V10 RPC endpoints must be non-loopback HTTPS"
                )
            hostnames.append(normalized_hostname)
        if len(hostnames) == RPC_QUORUM_SIZE and len(set(hostnames)) != len(hostnames):
            raise DeploymentError(
                "live V10 RPC quorum requires three distinct hostnames"
            )
        _uint(timeout, "RPC timeout", positive=True)
        _uint(max_snapshot_age, "maximum snapshot age", positive=True)
        self.rpc_urls = rpc_urls
        self.rpc_url = rpc_urls[0]
        self.rpc_endpoint_pins = [_rpc_endpoint_pin(endpoint) for endpoint in rpc_urls]
        self.timeout, self.max_snapshot_age = timeout, max_snapshot_age
        self.allow_single_test_rpc = test_only

    def rpc(self, method: str, params: list[Any]) -> Any:
        if len(self.rpc_urls) == 1:
            return chain.rpc_call(self.rpc_url, method, params, self.timeout)
        with ThreadPoolExecutor(max_workers=RPC_QUORUM_SIZE) as executor:
            futures = {
                executor.submit(
                    chain.rpc_call, endpoint, method, params, self.timeout,
                ): endpoint
                for endpoint in self.rpc_urls
            }
            results: list[Any] = []
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    continue
        if len(results) < 2:
            raise DeploymentError(f"V10 RPC quorum unavailable for {method}")
        if method in ("eth_gasPrice", "eth_estimateGas", "eth_getBalance", "eth_blockNumber"):
            values = [_rpc_quantity(value, method) for value in results]
            if method in ("eth_gasPrice", "eth_estimateGas"):
                return hex(max(values))
            if method == "eth_getBalance":
                return hex(min(values))
            values.sort()
            return hex(values[len(values) // 2] if len(values) == 3 else values[0])

        votes: dict[str, tuple[int, Any]] = {}
        for result in results:
            key = self._rpc_vote_key(method, result)
            count, _ = votes.get(key, (0, result))
            votes[key] = (count + 1, result)
        count, result = max(votes.values(), key=lambda item: item[0])
        if count < 2:
            raise DeploymentError(f"V10 RPC endpoints disagree on {method}")
        return result

    @staticmethod
    def _rpc_vote_key(method: str, result: Any) -> str:
        if method == "eth_getBlockByNumber" and isinstance(result, Mapping):
            result = {
                name: result.get(name) for name in ("number", "hash", "timestamp")
            }
        elif method == "eth_getTransactionReceipt" and isinstance(result, Mapping):
            result = {
                name: result.get(name) for name in (
                    "transactionHash", "blockHash", "blockNumber", "status",
                    "contractAddress",
                )
            }
        return _json(result)

    def require_quorum(self) -> None:
        if len(self.rpc_urls) != RPC_QUORUM_SIZE and not self.allow_single_test_rpc:
            raise DeploymentError("live V10 deployment requires three pinned RPC endpoints")

    def check_endpoint_pins(self, plan: Mapping[str, Any]) -> None:
        if plan.get("rpc_endpoint_pins") != self.rpc_endpoint_pins:
            raise DeploymentError("V10 RPC endpoints differ from the approved deployment plan")

    def check_network(self, policy: Mapping[str, Any]) -> None:
        p = validate_policy(policy)
        genesis = self.rpc("eth_getBlockByNumber", ["0x0", False])
        if (_rpc_quantity(self.rpc("eth_chainId", []), "chain id", bits=64) != p["chain_id"] or not genesis
                or chain.normalize_bytes32(genesis["hash"]) != p["genesis_hash"]):
            raise DeploymentError("RPC chain or genesis differs from explicit V10 policy")

    def _head(self, policy: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        self.check_network(policy)
        block = self.rpc("eth_getBlockByNumber", ["latest", False])
        if not block:
            raise DeploymentError("RPC did not return a latest block")
        timestamp = _rpc_quantity(block["timestamp"], "block timestamp", bits=64)
        if not -30 <= int(time.time()) - timestamp <= self.max_snapshot_age:
            raise DeploymentError("RPC head is stale or from the future")
        block_hash = chain.normalize_bytes32(block["hash"])
        return block, {"blockHash": block_hash, "requireCanonical": True}

    def plan(self, policy: Mapping[str, Any], artifacts: Mapping[str, Any]) -> dict[str, Any]:
        p, artifacts = validate_policy(policy), validate_artifacts(artifacts)
        _verify_artifact_pins(p, artifacts)
        block, tag = self._head(p)
        stablecoin_code = _bytes(self.rpc("eth_getCode", [p["stablecoin"], tag]), "stablecoin code")
        nonce = _rpc_quantity(
            self.rpc("eth_getTransactionCount", [p["deployer"], "latest"]),
            "latest deployer nonce",
        )
        if nonce != _rpc_quantity(
            self.rpc("eth_getTransactionCount", [p["deployer"], "pending"]),
            "pending deployer nonce",
        ):
            raise DeploymentError("deployer has pending transactions; resolve them before planning")
        addresses = {
            "registry": chain.derive_contract_address(p["deployer"], nonce),
            "settlement": chain.derive_contract_address(p["deployer"], nonce + 1),
        }
        if (
            p["reputation_history_import"]["source_settlement_contract"]
            == addresses["settlement"]
        ):
            raise DeploymentError(
                "reputation history source settlement conflicts with the predicted new Settlement"
            )
        if len(set(addresses.values())) != len(addresses):
            raise DeploymentError("predicted V10 contract addresses conflict")
        contract_roles = {
            "deployer": p["deployer"], "stablecoin": p["stablecoin"],
            "treasury": p["treasury"], "governance": p["governance"],
            "reputation authority": p["registry"]["reputation_authority"],
            "bond penalty recipient": p["dispute_policy"]["bond_penalty_recipient"],
        }
        for role, account in contract_roles.items():
            if account in addresses.values():
                raise DeploymentError(
                    f"{role} conflicts with a predicted V10 contract address"
                )
        for target in addresses.values():
            if self.rpc("eth_getCode", [target, tag]) != "0x":
                raise DeploymentError("predicted V10 deployment address already contains code")
        transactions = _transactions(p, artifacts, addresses, nonce)
        registry_data, settlement_data = transactions["registry"]["data"], transactions["settlement"]["data"]
        if len(_bytes(registry_data, "registry init code")) > 49_152 or len(_bytes(settlement_data, "settlement init code")) > 49_152:
            raise DeploymentError("V10 init code exceeds EIP-3860 size limit")
        if any(len(_bytes(artifacts[name]["runtime_template"], f"{name} runtime")) > 24_576 for name in ("registry", "settlement")):
            raise DeploymentError("V10 runtime exceeds EIP-170 size limit")
        price = p["fee_policy"]["gas_price_wei"]
        limits = p["fee_policy"]["gas_limits"]
        suggested = _rpc_quantity(self.rpc("eth_gasPrice", []), "gas price")
        if suggested > price:
            raise DeploymentError("current gas price exceeds the reviewed V10 gas price cap")
        number = _rpc_quantity(block["number"], "block number", bits=64)
        timestamp = _rpc_quantity(block["timestamp"], "block timestamp", bits=64)
        block_hash = chain.normalize_bytes32(block["hash"])
        canonical = self.rpc("eth_getBlockByNumber", [hex(number), False])
        if not canonical or chain.normalize_bytes32(canonical["hash"]) != block_hash:
            raise DeploymentError("V10 planning snapshot was reorganized")
        result = {
            "schema": PLAN_SCHEMA, "dry_run": True, "policy": p, "policy_hash": _hash(p),
            "artifacts": artifacts, "addresses": addresses, "transactions": transactions,
            "stablecoin_runtime_code_hash": "0x" + chain.keccak256(stablecoin_code).hex(),
            "rpc_endpoint_pins": self.rpc_endpoint_pins,
            "snapshot": {"block_number": number, "block_hash": block_hash, "timestamp": timestamp},
            "total_gas_cost_wei": price * sum(limits.values()),
        }
        result = json.loads(_json(result))
        return {**result, "plan_hash": _hash(result)}

    def _call(self, target: str, signature: str, args: list[str], count: int, tag: Any) -> bytes:
        raw = _bytes(self.rpc("eth_call", [{"to": target, "data": chain.encode_contract_call(signature, args)}, tag]), signature)
        if len(raw) != count * 32:
            raise DeploymentError(f"onchain {signature} returned malformed data")
        return raw

    def _check(self, target: str, signature: str, args: list[str], expected: list[Any], tag: Any) -> None:
        if self._call(target, signature, args, len(expected), tag) != _words(expected):
            raise DeploymentError(f"onchain {signature} differs from V10 deployment plan")

    def _verify_code(self, target: str, artifact: Mapping[str, Any], tag: Any) -> str:
        runtime = self.rpc("eth_getCode", [target, tag])
        if _masked_runtime(runtime, artifact) != _masked_runtime(artifact["runtime_template"], artifact):
            raise DeploymentError("deployed V10 runtime differs from approved compiler artifact")
        return "0x" + chain.keccak256(_bytes(runtime, "deployed runtime")).hex()

    def verify_stablecoin(self, plan: Mapping[str, Any], tag: Any) -> str:
        code = _bytes(
            self.rpc("eth_getCode", [plan["policy"]["stablecoin"], tag]),
            "stablecoin code",
        )
        observed = "0x" + chain.keccak256(code).hex()
        if observed != plan["stablecoin_runtime_code_hash"]:
            raise DeploymentError("stablecoin runtime code differs from the approved V10 plan")
        return observed

    def verify_registry(self, plan: Mapping[str, Any], tag: Any, *, expected_settlement: str) -> dict[str, Any]:
        p, target, r = plan["policy"], plan["addresses"]["registry"], plan["policy"]["registry"]
        code_hash = self._verify_code(target, plan["artifacts"]["registry"], tag)
        for signature, expected in (
            ("governance()", [p["governance"]]),
            ("reputationAuthority()", [r["reputation_authority"]]),
            ("bondPenaltyRecipient()", [r["bond_penalty_recipient"]]),
            ("minimumReputation()", [r["minimum_reputation"]]), ("jurySize()", [r["jury_size"]]),
            ("threshold()", [r["threshold"]]), ("selectionDelayBlocks()", [r["selection_delay_blocks"]]),
            ("MAX_JURY_SIZE()", [7]),
            ("settlement()", [expected_settlement]),
        ):
            self._check(target, signature, [], expected, tag)
        return {"runtime_code_hash": code_hash, "settlement": expected_settlement}

    def verify_settlement(self, plan: Mapping[str, Any], tag: Any) -> dict[str, Any]:
        p, target = plan["policy"], plan["addresses"]["settlement"]
        code_hash = self._verify_code(target, plan["artifacts"]["settlement"], tag)
        for signature, expected in (
            ("stablecoin()", [p["stablecoin"]]), ("rewardToken()", [p["reward_token"]]),
            ("treasury()", [p["treasury"]]), ("governance()", [p["governance"]]),
            ("juryRegistry()", [plan["addresses"]["registry"]]),
            ("adjudicationThreshold()", [p["registry"]["threshold"]]),
            ("MAX_AUTHORIZATION_TTL()", [chain_v10.MAX_AUTHORIZATION_TTL]),
            ("MAX_CHANNEL_DURATION()", [chain_v10.MAX_CHANNEL_DURATION]),
            ("DOMAIN_SEPARATOR()", [chain_v10.domain_separator(
                chain_id=p["chain_id"], verifying_contract=target)]),
            ("policy()", [p["dispute_policy"][name] for name in DISPUTE_POLICY_FIELDS]),
            ("latestChannelVersion(bytes32)", [1]),
        ):
            args = [p["initial_channel"]] if signature.startswith("latestChannelVersion") else []
            self._check(target, signature, args, expected, tag)
        pricing = _words([p["initial_channel"], 1, p["treasury"], *[p["initial_config"][name] for name in CONFIG_FIELDS]])
        pricing_hash = "0x" + chain.keccak256(pricing).hex()
        self._check(target, "channelPricingHash(bytes32,uint64)", [p["initial_channel"], "1"], [pricing_hash], tag)
        return {"runtime_code_hash": code_hash, "pricing_hash": pricing_hash}

    def preflight(self, plan: Mapping[str, Any], step: str) -> None:
        validate_plan(plan)
        self.check_endpoint_pins(plan)
        if step not in STEPS:
            raise DeploymentError("invalid V10 deployment step")
        p = plan["policy"]
        block, tag = self._head(p)
        stablecoin_code = _bytes(self.rpc("eth_getCode", [p["stablecoin"], tag]), "stablecoin code")
        if "0x" + chain.keccak256(stablecoin_code).hex() != plan["stablecoin_runtime_code_hash"]:
            raise DeploymentError("stablecoin runtime code changed since V10 planning")
        tx = plan["transactions"][step]
        latest = _rpc_quantity(
            self.rpc("eth_getTransactionCount", [p["deployer"], "latest"]),
            "latest deployer nonce",
        )
        pending = _rpc_quantity(
            self.rpc("eth_getTransactionCount", [p["deployer"], "pending"]),
            "pending deployer nonce",
        )
        if latest != tx["nonce"] or pending != tx["nonce"]:
            raise DeploymentError("deployer nonce changed from reviewed V10 plan")
        if _rpc_quantity(self.rpc("eth_gasPrice", []), "gas price") > tx["gas_price_wei"]:
            raise DeploymentError("current gas price exceeds the reviewed V10 gas price cap")
        registry, settlement = plan["addresses"]["registry"], plan["addresses"]["settlement"]
        if step == "registry":
            if self.rpc("eth_getCode", [registry, tag]) != "0x" or self.rpc("eth_getCode", [settlement, tag]) != "0x":
                raise DeploymentError("predicted V10 address is no longer empty")
        elif step == "settlement":
            self.verify_registry(plan, tag, expected_settlement=chain.ZERO_ADDRESS)
            if self.rpc("eth_getCode", [settlement, tag]) != "0x":
                raise DeploymentError("predicted settlement address is no longer empty")
        else:
            self.verify_registry(plan, tag, expected_settlement=chain.ZERO_ADDRESS)
            self.verify_settlement(plan, tag)
        estimate_request = {
            "from": p["deployer"], "data": tx["data"], "value": tx["value"],
            "gasPrice": hex(tx["gas_price_wei"]),
        }
        if tx["to"] is not None:
            estimate_request["to"] = tx["to"]
        raw_estimate = self.rpc("eth_estimateGas", [estimate_request, block["number"]])
        estimate = _rpc_quantity(raw_estimate, "V10 gas estimate")
        if estimate <= 0:
            raise DeploymentError("RPC returned a zero V10 gas estimate")
        required_gas = estimate * 12 // 10 + 10_000
        if tx["gas_units"] < required_gas:
            raise DeploymentError(
                f"reviewed {step} gas limit does not cover the canonical estimate and safety margin"
            )
        number = _rpc_quantity(block["number"], "block number", bits=64)
        block_hash = chain.normalize_bytes32(block["hash"])
        canonical = self.rpc("eth_getBlockByNumber", [hex(number), False])
        if not canonical or chain.normalize_bytes32(canonical["hash"]) != block_hash:
            raise DeploymentError("V10 preflight snapshot was reorganized")


def _prepare_private_sqlite_path(path: str | Path) -> tuple[Path, tuple[int, int]]:
    candidate = Path(os.path.abspath(os.fspath(path)))
    parent = candidate.parent
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) and info.st_uid != 0:
            raise DeploymentError("V10 outbox path contains a user-controlled symbolic link")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_link = os.lstat(parent)
    if stat.S_ISLNK(parent_link.st_mode) and parent_link.st_uid != 0:
        raise DeploymentError("V10 outbox parent must not be a user-controlled symbolic link")
    parent_info = os.stat(parent)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid not in {0, os.getuid()}
        or parent_info.st_mode & 0o022
    ):
        raise DeploymentError(
            "V10 outbox parent must be owned and not group/world writable"
        )
    fd = os.open(
        candidate, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise DeploymentError("V10 outbox must be an owned, unlinked regular file")
        os.fchmod(fd, 0o600)
        identity = (info.st_dev, info.st_ino)
    finally:
        os.close(fd)
    return candidate, identity


def _verify_private_sqlite_files(
    path: Path, *, identity: tuple[int, int], sidecars: bool,
) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise DeploymentError("V10 outbox disappeared while opening SQLite") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or (info.st_dev, info.st_ino) != identity
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise DeploymentError("V10 outbox changed after its protected open")
    if not sidecars:
        return
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        try:
            sidecar_info = os.lstat(sidecar)
        except FileNotFoundError:
            continue
        if (
            stat.S_ISLNK(sidecar_info.st_mode)
            or not stat.S_ISREG(sidecar_info.st_mode)
            or sidecar_info.st_uid != os.getuid()
            or sidecar_info.st_nlink != 1
        ):
            raise DeploymentError("V10 outbox SQLite sidecar is unsafe")
        os.chmod(sidecar, 0o600)


@contextmanager
def _deployment_sender_lock(
    key_file: str | Path, deployer: str,
):
    deployer = _address(deployer, "V10 deployer")
    requested_path = Path(os.path.abspath(os.fspath(key_file)))
    current = Path(requested_path.anchor)
    for part in requested_path.parts[1:]:
        current /= part
        try:
            component = os.lstat(current)
        except FileNotFoundError:
            raise DeploymentError("V10 deployment key path does not exist") from None
        if stat.S_ISLNK(component.st_mode) and component.st_uid != 0:
            raise DeploymentError(
                "V10 deployment key path contains a user-controlled symbolic link"
            )
    try:
        key_path = Path(os.path.realpath(requested_path, strict=True))
    except OSError:
        raise DeploymentError("unable to canonicalize V10 deployment key path") from None
    parent = key_path.parent
    parent_link = os.lstat(parent)
    parent_info = os.stat(parent)
    if (
        (stat.S_ISLNK(parent_link.st_mode) and parent_link.st_uid != 0)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid not in {0, os.getuid()}
        or parent_info.st_mode & 0o022
    ):
        raise DeploymentError(
            "V10 deployment key parent must be owned and not group/world writable"
        )
    try:
        key_fd = os.open(
            key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise DeploymentError("unable to open protected V10 deployment key") from None
    try:
        key_info = os.fstat(key_fd)
        if (
            not stat.S_ISREG(key_info.st_mode)
            or stat.S_IMODE(key_info.st_mode) not in (0o400, 0o600)
            or key_info.st_uid != os.getuid()
            or key_info.st_nlink != 1
        ):
            raise DeploymentError(
                "V10 deployment key must be an owned 0400/0600 regular file with exactly one link"
            )
        current_key = os.lstat(key_path)
        if (
            stat.S_ISLNK(current_key.st_mode)
            or (current_key.st_dev, current_key.st_ino)
            != (key_info.st_dev, key_info.st_ino)
        ):
            raise DeploymentError("V10 deployment key changed after its protected open")
        try:
            raw_key = os.read(key_fd, 257)
            if len(raw_key) > 256:
                raise DeploymentError("invalid dedicated V10 deployment key file")
            private_key = chain.parse_private_key(raw_key.decode("ascii").strip())
        except (OSError, UnicodeError, chain.ChainError):
            raise DeploymentError("unable to read protected V10 deployment key") from None
        if chain.private_key_to_address(private_key) != deployer:
            raise DeploymentError("key does not match approved V10 deployer")

        lock_path = parent / f".mycomesh-v10-deployment-{deployer[2:]}.lock"
        lock_fd = os.open(
            lock_path,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            info = os.fstat(lock_fd)
            try:
                current_lock = os.lstat(lock_path)
            except FileNotFoundError:
                raise DeploymentError("V10 deployment sender lock path changed") from None
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_ISLNK(current_lock.st_mode)
                or (current_lock.st_dev, current_lock.st_ino)
                != (info.st_dev, info.st_ino)
            ):
                raise DeploymentError("V10 deployment sender lock is unsafe")
            os.fchmod(lock_fd, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DeploymentError(
                    "another V10 deployment process is using this deployer identity"
                ) from None
            current_key = os.lstat(key_path)
            if (
                stat.S_ISLNK(current_key.st_mode)
                or current_key.st_nlink != 1
                or (current_key.st_dev, current_key.st_ino)
                != (key_info.st_dev, key_info.st_ino)
            ):
                raise DeploymentError("V10 deployment key changed while acquiring its sender lock")
            yield private_key
        finally:
            os.close(lock_fd)
    finally:
        os.close(key_fd)


class V10DeploymentOutbox:
    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise DeploymentError("V10 deployment outbox must be durable")
        path, identity = _prepare_private_sqlite_path(path)
        self.lock = threading.RLock()
        self.path = path
        self.db = sqlite3.connect(
            path, timeout=30, isolation_level=None, check_same_thread=False,
        )
        try:
            _verify_private_sqlite_files(path, identity=identity, sidecars=False)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA trusted_schema=OFF")
            mode = self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise DeploymentError("V10 outbox requires SQLite WAL mode")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("""CREATE TABLE IF NOT EXISTS v10_deployment_steps (
                plan_hash TEXT NOT NULL, step TEXT NOT NULL, step_index INTEGER NOT NULL,
                scope TEXT NOT NULL, sender TEXT NOT NULL, nonce INTEGER NOT NULL,
                tx_hash TEXT NOT NULL UNIQUE, raw_tx TEXT NOT NULL, plan_json TEXT NOT NULL,
                state TEXT NOT NULL, verification_json TEXT,
                PRIMARY KEY(plan_hash, step), UNIQUE(scope, sender, nonce))""")
            _verify_private_sqlite_files(path, identity=identity, sidecars=True)
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def _rows(self, plan_hash: str) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM v10_deployment_steps WHERE plan_hash=? ORDER BY step_index", (plan_hash,)).fetchall()

    def status(self, plan_hash: str) -> dict[str, Any]:
        with self.lock:
            rows = self._rows(plan_hash)
            steps = {}
            for row in rows:
                item = {key: row[key] for key in ("nonce", "tx_hash", "state")}
                if row["verification_json"]:
                    item["verification"] = json.loads(row["verification_json"])
                steps[row["step"]] = item
            reverted = next((name for name in STEPS if steps.get(name, {}).get("state") == "reverted"), None)
            next_step = next((name for name in STEPS if steps.get(name, {}).get("state") != "confirmed"), None)
            state = "reverted" if reverted else "confirmed" if next_step is None else "planned" if not rows else steps[next_step]["state"] if next_step in steps else "ready"
            result = {"plan_hash": plan_hash, "state": state, "complete": next_step is None,
                      "next_step": next_step, "steps": steps}
            settlement = steps.get("settlement", {})
            settlement_verification = settlement.get("verification")
            if (
                settlement.get("state") == "confirmed"
                and isinstance(settlement_verification, Mapping)
            ):
                # These are post-deployment facts, never plan-time guesses.
                # They can be copied directly into the dynamic deployment
                # manifest only after the canonical receipt and runtime have
                # passed reconcile verification.
                result.update(
                    deployment_block=settlement_verification["block_number"],
                    deployment_block_hash=settlement_verification["block_hash"],
                    settlement_runtime_code_keccak256=(
                        settlement_verification["runtime_code_hash"]
                    ),
                )
            return result

    def _plan(self, plan_hash: str) -> dict[str, Any]:
        rows = self._rows(plan_hash)
        if not rows:
            raise DeploymentError("unknown V10 deployment plan")
        plan = json.loads(rows[0]["plan_json"])
        validate_plan(plan)
        if plan["plan_hash"] != plan_hash or [row["step"] for row in rows] != list(STEPS[:len(rows)]):
            raise DeploymentError("V10 outbox stage sequence is invalid")
        scope = f"{plan['policy']['genesis_hash']}:{plan['policy']['chain_id']}"
        for index, row in enumerate(rows):
            tx = plan["transactions"][row["step"]]
            if (row["step_index"] != index or row["scope"] != scope
                    or row["sender"] != plan["policy"]["deployer"] or row["nonce"] != tx["nonce"]
                    or row["plan_json"] != rows[0]["plan_json"]):
                raise DeploymentError("V10 outbox row differs from its approved plan")
            _verify_stored_raw_transaction(
                plan, row["step"], row["raw_tx"], row["tx_hash"]
            )
        return plan

    def execute_next(self, client: V10DeploymentClient, plan: Mapping[str, Any], *, allow_send: bool = False,
                     approved_plan_hash: str | None = None, key_file: str | Path | None = None,
                     max_gas_price_wei: int | None = None, max_total_gas_cost_wei: int | None = None) -> dict[str, Any]:
        validate_plan(plan)
        if not allow_send:
            return {"dry_run": True, "sent": False, "plan_hash": plan["plan_hash"], "next_step": self.status(plan["plan_hash"])["next_step"]}
        if approved_plan_hash != plan["plan_hash"] or not key_file:
            raise DeploymentError("send requires exact approved V10 plan hash and protected dedicated key file")
        _uint(max_gas_price_wei, "operator gas price cap", positive=True)
        _uint(max_total_gas_cost_wei, "operator total gas cost cap", positive=True)
        if (plan["policy"]["fee_policy"]["gas_price_wei"] > max_gas_price_wei
                or plan["total_gas_cost_wei"] > max_total_gas_cost_wei):
            raise DeploymentError("reviewed V10 transaction fees exceed operator caps")
        client.require_quorum()
        with _deployment_sender_lock(key_file, plan["policy"]["deployer"]) as private_key:
            return self._execute_next_locked(
                client, plan, approved_plan_hash, private_key,
            )

    def _execute_next_locked(
        self, client: V10DeploymentClient, plan: Mapping[str, Any],
        approved_plan_hash: str, private_key: bytes,
    ) -> dict[str, Any]:
        with self.lock:
            rows = self._rows(approved_plan_hash)
        if rows:
            current = self.reconcile(client, approved_plan_hash)
            if current["state"] == "reverted":
                raise DeploymentError("a V10 deployment step reverted; create a new plan")
            next_step = current["next_step"]
            if next_step in current["steps"]:
                return current  # Existing uncertain/submitted bytes require explicit rebroadcast.
        else:
            next_step = STEPS[0]
        if next_step is None:
            return self.status(approved_plan_hash)
        index = STEPS.index(next_step)
        if any(self.status(approved_plan_hash)["steps"].get(prior, {}).get("state") != "confirmed" for prior in STEPS[:index]):
            raise DeploymentError("V10 deployment stages must be confirmed in order")
        client.preflight(plan, next_step)
        p, tx = plan["policy"], plan["transactions"][next_step]
        remaining_cost = sum(plan["transactions"][step]["gas_units"] * plan["transactions"][step]["gas_price_wei"] for step in STEPS[index:])
        if _rpc_quantity(
            client.rpc("eth_getBalance", [p["deployer"], "latest"]),
            "deployer balance",
        ) < remaining_cost:
            raise DeploymentError("deployer balance cannot cover remaining bounded V10 deployment gas")
        target = tx["to"]
        raw = chain.sign_legacy_transaction(private_key, tx["nonce"], tx["gas_price_wei"], tx["gas_units"],
                                            target, 0, _bytes(tx["data"], f"{next_step} transaction data"), p["chain_id"])
        raw_hex, tx_hash = "0x" + raw.hex(), "0x" + chain.keccak256(raw).hex()
        scope = f"{p['genesis_hash']}:{p['chain_id']}"
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if self._rows(approved_plan_hash) and self.db.execute(
                        "SELECT 1 FROM v10_deployment_steps WHERE plan_hash=? AND step=?", (approved_plan_hash, next_step)).fetchone():
                    self.db.rollback()
                    return self.status(approved_plan_hash)
                if self.db.execute(
                        "SELECT 1 FROM v10_deployment_steps WHERE scope=? AND sender=? AND plan_hash<>? "
                        "GROUP BY plan_hash HAVING "
                        "SUM(CASE WHEN state='reverted' THEN 1 ELSE 0 END)=0 AND NOT "
                        "(COUNT(*)=? AND SUM(CASE WHEN state='confirmed' THEN 1 ELSE 0 END)=?)",
                        (scope, p["deployer"], approved_plan_hash, len(STEPS), len(STEPS))).fetchone():
                    raise DeploymentError(
                        "deployer has an incomplete V10 deployment in another plan"
                    )
                if self.db.execute("SELECT 1 FROM v10_deployment_steps WHERE scope=? AND sender=? AND nonce=?",
                                   (scope, p["deployer"], tx["nonce"])).fetchone():
                    raise DeploymentError("V10 deployment nonce is already reserved in the durable outbox")
                self.db.execute("INSERT INTO v10_deployment_steps VALUES (?,?,?,?,?,?,?,?,?,'sending',NULL)",
                                (approved_plan_hash, next_step, index, scope, p["deployer"], tx["nonce"], tx_hash, raw_hex, _json(plan)))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        return self._broadcast(client, approved_plan_hash, next_step)

    def _broadcast(self, client: V10DeploymentClient, plan_hash: str, step: str) -> dict[str, Any]:
        with self.lock:
            plan = self._plan(plan_hash)
            row = self.db.execute("SELECT * FROM v10_deployment_steps WHERE plan_hash=? AND step=?", (plan_hash, step)).fetchone()
            if row is None:
                raise DeploymentError("unknown V10 deployment transaction")
            tx_hash = row["tx_hash"]
            raw = "0x" + _verify_stored_raw_transaction(
                plan, step, row["raw_tx"], tx_hash
            ).hex()
        try:
            returned = client.rpc("eth_sendRawTransaction", [raw])
            state = "submitted" if chain.normalize_bytes32(returned) == tx_hash else "uncertain"
        except Exception:
            state = "uncertain"
        with self.lock:
            self.db.execute("UPDATE v10_deployment_steps SET state=? WHERE plan_hash=? AND step=? AND state NOT IN ('confirmed','reverted')",
                            (state, plan_hash, step))
        return self.status(plan_hash)

    def rebroadcast(
        self, client: V10DeploymentClient, plan_hash: str, step: str, *,
        allow_send: bool = False, key_file: str | Path | None = None,
    ) -> dict[str, Any]:
        if step not in STEPS:
            raise DeploymentError("invalid V10 deployment step")
        if not allow_send:
            return {"dry_run": True, "sent": False, "plan_hash": plan_hash, "step": step}
        if not key_file:
            raise DeploymentError("V10 rebroadcast requires the protected dedicated key file")
        client.require_quorum()
        with self.lock:
            plan = self._plan(plan_hash)
        with _deployment_sender_lock(key_file, plan["policy"]["deployer"]):
            return self._rebroadcast_locked(client, plan_hash, step)

    def _rebroadcast_locked(
        self, client: V10DeploymentClient, plan_hash: str, step: str,
    ) -> dict[str, Any]:
        current = self.reconcile(client, plan_hash)
        state = current["steps"].get(step, {}).get("state")
        if state in ("confirmed", "reverted"):
            return current
        if state is None:
            raise DeploymentError("V10 deployment step has not been signed")
        if current["next_step"] != step or any(
            current["steps"].get(prior, {}).get("state") != "confirmed"
            for prior in STEPS[:STEPS.index(step)]
        ):
            raise DeploymentError(
                "V10 deployment rebroadcast requires every prior stage to remain confirmed"
            )
        return self._broadcast(client, plan_hash, step)

    def _reconcile_step(self, client: V10DeploymentClient, plan: Mapping[str, Any], row: sqlite3.Row) -> tuple[str, dict[str, Any] | None]:
        receipt = client.rpc("eth_getTransactionReceipt", [row["tx_hash"]])
        if receipt is None:
            return "uncertain", None
        if chain.normalize_bytes32(receipt["transactionHash"]) != row["tx_hash"]:
            raise DeploymentError("V10 receipt transaction hash mismatch")
        number = _rpc_quantity(receipt["blockNumber"], "receipt block number", bits=64)
        block_hash = chain.normalize_bytes32(receipt["blockHash"])
        block = client.rpc("eth_getBlockByNumber", [hex(number), False])
        head = _rpc_quantity(client.rpc("eth_blockNumber", []), "head block number", bits=64)
        if not block or chain.normalize_bytes32(block["hash"]) != block_hash:
            return "uncertain", None
        if head - number + 1 < plan["policy"]["confirmations"]:
            return "submitted", None
        status = _rpc_quantity(receipt["status"], "receipt status", bits=8)
        if status not in (0, 1):
            raise DeploymentError("invalid V10 receipt status")
        if status == 0:
            return "reverted", None
        tag = {"blockHash": block_hash, "requireCanonical": True}
        stablecoin_hash = client.verify_stablecoin(plan, tag)
        if row["step"] == "registry":
            if chain.normalize_address(receipt["contractAddress"]) != plan["addresses"]["registry"]:
                raise DeploymentError("registry receipt deployed a different address")
            verified = client.verify_registry(plan, tag, expected_settlement=chain.ZERO_ADDRESS)
        elif row["step"] == "settlement":
            if chain.normalize_address(receipt["contractAddress"]) != plan["addresses"]["settlement"]:
                raise DeploymentError("settlement receipt deployed a different address")
            verified = client.verify_settlement(plan, tag)
        else:
            if receipt.get("contractAddress") not in (None, "0x0000000000000000000000000000000000000000"):
                raise DeploymentError("binding receipt unexpectedly created a contract")
            verified = client.verify_registry(plan, tag, expected_settlement=plan["addresses"]["settlement"])
            client.verify_settlement(plan, tag)
        canonical = client.rpc("eth_getBlockByNumber", [hex(number), False])
        if not canonical or chain.normalize_bytes32(canonical["hash"]) != block_hash:
            raise DeploymentError("V10 verification snapshot was reorganized")
        return "confirmed", {
            **verified,
            "stablecoin_runtime_code_hash": stablecoin_hash,
            "transaction_hash": row["tx_hash"],
            "block_number": number,
            "block_hash": block_hash,
        }

    def reconcile(self, client: V10DeploymentClient, plan_hash: str) -> dict[str, Any]:
        with self.lock:
            plan = self._plan(plan_hash)
            rows = self._rows(plan_hash)
            # A stale confirmation must never authorize the next nonce.
            self.db.execute("UPDATE v10_deployment_steps SET state='uncertain',verification_json=NULL WHERE plan_hash=?", (plan_hash,))
        client.check_endpoint_pins(plan)
        client.check_network(plan["policy"])
        for index, row in enumerate(rows):
            try:
                state, verified = self._reconcile_step(client, plan, row)
            except BaseException:
                with self.lock:
                    self.db.execute("UPDATE v10_deployment_steps SET state='uncertain',verification_json=NULL WHERE plan_hash=? AND step_index>=?",
                                    (plan_hash, index))
                raise
            with self.lock:
                self.db.execute("UPDATE v10_deployment_steps SET state=?,verification_json=? WHERE plan_hash=? AND step=?",
                                (state, _json(verified) if verified else None, plan_hash, row["step"]))
                if state != "confirmed":
                    self.db.execute("UPDATE v10_deployment_steps SET state='uncertain',verification_json=NULL WHERE plan_hash=? AND step_index>?",
                                    (plan_hash, index))
                    break
        return self.status(plan_hash)


def _read_json(path: str) -> Any:
    with open(path, "rb") as handle:
        raw = handle.read(4_194_305)
    if len(raw) > 4_194_304:
        raise DeploymentError("JSON input exceeds 4 MiB")

    return _decode_strict_json(raw, name="JSON input")


def _require_controlled_sepolia_send(
    policy: Mapping[str, Any], *, allow_controlled_test: bool,
) -> None:
    p = validate_policy(policy)
    if not allow_controlled_test:
        raise DeploymentError(
            "V10 send requires explicit --allow-controlled-test acknowledgement"
        )
    if p["chain_id"] != SEPOLIA_CHAIN_ID or p["genesis_hash"] != SEPOLIA_GENESIS_HASH:
        raise DeploymentError(
            "V10 send is restricted to the pinned Sepolia chain and genesis"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rpc-url", action="append", required=True,
        help=(
            "credential-free HTTPS RPC endpoint; live plan/send/reconcile requires "
            "three distinct hostnames"
        ),
    )
    parser.add_argument(
        "--allow-controlled-test", action="store_true",
        help="explicitly acknowledge that V10 future-blockhash jury is controlled-test only",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("plan", help="read-only V10 policy, RPC and artifact validation")
    command.add_argument("--policy", required=True)
    command.add_argument("--registry-artifact", required=True)
    command.add_argument("--settlement-artifact", required=True)
    command.add_argument("--output", required=True)
    command = commands.add_parser("execute-next", help="dry-run unless --send is explicit; sends at most one stage")
    command.add_argument("--plan", required=True)
    command.add_argument("--approved-plan-hash")
    command.add_argument("--key-file")
    command.add_argument("--max-gas-price-wei", type=int)
    command.add_argument("--max-total-gas-cost-wei", type=int)
    for action in ("reconcile", "rebroadcast"):
        command = commands.add_parser(action)
        command.add_argument("--plan-hash", required=True)
        if action == "rebroadcast":
            command.add_argument("--step", choices=STEPS, required=True)
            command.add_argument("--key-file")
            command.add_argument("--send", action="store_true")
    for name in ("execute-next", "reconcile", "rebroadcast"):
        commands.choices[name].add_argument("--outbox", required=True)
    commands.choices["execute-next"].add_argument("--send", action="store_true")
    args = parser.parse_args(argv)
    try:
        client = V10DeploymentClient(args.rpc_url)
        if args.command == "plan":
            client.require_quorum()
            artifacts = {
                "registry": load_artifact(args.registry_artifact, "ProviderJuryRegistryV1"),
                "settlement": load_artifact(args.settlement_artifact, "MycoSettlementV10"),
            }
            result = client.plan(_read_json(args.policy), artifacts)
            with open(args.output, "x", encoding="utf-8") as handle:
                handle.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
            result = {key: result[key] for key in ("plan_hash", "policy_hash", "addresses", "total_gas_cost_wei")}
        else:
            outbox = V10DeploymentOutbox(args.outbox)
            try:
                if args.command == "execute-next":
                    plan = _read_json(args.plan)
                    if args.send:
                        client.require_quorum()
                        _require_controlled_sepolia_send(
                            plan["policy"],
                            allow_controlled_test=args.allow_controlled_test,
                        )
                    result = outbox.execute_next(client, plan, allow_send=args.send,
                        approved_plan_hash=args.approved_plan_hash, key_file=args.key_file,
                        max_gas_price_wei=args.max_gas_price_wei,
                        max_total_gas_cost_wei=args.max_total_gas_cost_wei)
                elif args.command == "rebroadcast":
                    if args.send:
                        client.require_quorum()
                        with outbox.lock:
                            plan = outbox._plan(args.plan_hash)
                        _require_controlled_sepolia_send(
                            plan["policy"],
                            allow_controlled_test=args.allow_controlled_test,
                        )
                    result = outbox.rebroadcast(
                        client, args.plan_hash, args.step, allow_send=args.send,
                        key_file=args.key_file,
                    )
                else:
                    client.require_quorum()
                    result = outbox.reconcile(client, args.plan_hash)
            finally:
                outbox.close()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (chain.ChainError, ValueError, KeyError, TypeError, OSError, sqlite3.Error) as exc:
        parser.exit(1, f"V10 deployment failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
