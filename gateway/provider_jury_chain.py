"""Hash-pinned EVM callbacks for the dynamic Provider-AI jury worker.

The Registry's per-dispute assignment is authoritative.  The live Provider
roster is deliberately *not* pinned here: reputation updates may change the
candidate pool after an assignment has been finalized, while the immutable
assignment snapshot remains verifiable on chain.

Transaction execution is opt-in and at-most-once.  The exact signed bytes and
locally derived transaction hash are committed to a durable outbox before the
first broadcast.  An RPC error, process crash, or mismatched response moves the
transaction to ``uncertain``; this module never automatically re-signs,
replaces, or re-broadcasts it.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from . import chain, chain_v10, provider_jury
from .relay_incidents import evidence_hash


class ProviderJuryChainError(ValueError):
    """The pinned chain state or durable transaction lifecycle is invalid."""


class ProviderJuryDefinitelyNotSentError(ProviderJuryChainError):
    """A failure happened before any durable transaction identity existed."""

    definitely_not_sent = True


ASSIGNMENT_SCHEMA = "mycomesh.v10.provider-jury-assignment.v1"
TRANSACTION_SCHEMA = "mycomesh.v10.provider-jury-chain-action.v1"
TRANSACTION_PLAN_SCHEMA = "mycomesh.v10.provider-jury-signed-transaction-plan.v1"
CHAIN_STORAGE_HEALTH_SCHEMA = "mycomesh.v10.provider-jury-chain-storage-health.v1"
ZERO_BYTES32 = chain.ZERO_BYTES32
ASSIGNMENT_TYPE = (
    "MycoProviderJuryAssignment(address registry,uint256 chainId,address settlement,"
    "bytes32 caseId,uint64 rosterVersion,bytes32 seed,uint64 minimumReputation,"
    "uint16 jurySize,uint16 threshold,bytes32 ownersHash,bytes32 voteSignersHash,"
    "bytes32 operatorsHash,bytes32 peersHash,bytes32 capabilitiesHash,bytes32 reputationsHash)"
)
ASSIGNMENT_TYPEHASH = chain.keccak256(ASSIGNMENT_TYPE.encode("utf-8"))
DISPUTE_VOTE_TOPIC = "0x" + chain.keccak256(
    b"DisputeVote(bytes32,address,bool,bytes32,bytes32)"
).hex()
DISPUTE_RESOLVED_TOPIC = "0x" + chain.keccak256(
    b"DisputeResolved(bytes32,uint8,uint256,uint256)"
).hex()
JURY_ASSIGNED_TOPIC = "0x" + chain.keccak256(
    b"JuryAssigned(bytes32,bytes32,bytes32,address[],address[],bytes32[])"
).hex()
JURY_FAILED_TOPIC = "0x" + chain.keccak256(
    b"JuryAssignmentFailed(bytes32,bytes32)"
).hex()
JURY_REQUESTED_TOPIC = "0x" + chain.keccak256(
    b"JuryRequested(bytes32,uint64,uint64,bytes32)"
).hex()
JURY_UNAVAILABLE_TOPIC = "0x" + chain.keccak256(
    b"JuryUnavailable(bytes32,uint64,uint256)"
).hex()


ProviderResolver = Callable[[Mapping[str, Any]], Mapping[str, Any]]
RPC = Callable[[str, list[Any]], Any]


def _json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ProviderJuryChainError("jury chain data must be strict JSON") from exc


def _uint(value: Any, label: str, *, bits: int = 256, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive) or value >= 2**bits:
        raise ProviderJuryChainError(f"{label} must be a bounded integer")
    return value


def _hex_uint(value: Any, label: str, *, bits: int = 256) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ProviderJuryChainError(f"{label} must be canonical RPC hex")
    try:
        parsed = int(value[2:] or "0", 16)
    except ValueError as exc:
        raise ProviderJuryChainError(f"{label} must be canonical RPC hex") from exc
    if value != hex(parsed) or parsed >= 2**bits:
        raise ProviderJuryChainError(f"{label} must be canonical RPC hex")
    return parsed


def _rpc_hostname(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        try:
            result = value.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            raise ProviderJuryChainError("jury RPC hostname is invalid") from None
        if not result:
            raise ProviderJuryChainError("jury RPC hostname is invalid")
        return result


def _is_loopback_hostname(value: str) -> bool:
    if value == "localhost" or value.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _validate_rpc_urls(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, tuple)
        or not 2 <= len(value) <= 8
        or not all(isinstance(endpoint, str) for endpoint in value)
        or len(set(value)) != len(value)
    ):
        raise ProviderJuryChainError(
            "production jury reads require 2 to 8 explicit RPC endpoints"
        )
    hostnames: list[str] = []
    for endpoint in value:
        if any(character.isspace() for character in endpoint):
            raise ProviderJuryChainError("jury RPC endpoints must not contain whitespace")
        try:
            parsed = urlsplit(endpoint)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            raise ProviderJuryChainError("jury RPC endpoint is malformed") from None
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or "@" in parsed.netloc
            or "?" in endpoint
            or "#" in endpoint
            or parsed.query
            or parsed.fragment
            or (port is not None and not 0 < port < 65_536)
        ):
            raise ProviderJuryChainError(
                "jury RPC endpoints must be credential-free HTTPS without query or fragment"
            )
        normalized = _rpc_hostname(hostname)
        if _is_loopback_hostname(normalized):
            raise ProviderJuryChainError("production jury RPC endpoints must not be loopback")
        hostnames.append(normalized)
    if len(set(hostnames)) != len(hostnames):
        raise ProviderJuryChainError(
            "production jury RPC endpoints require distinct hostnames"
        )
    return value


def _address(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        result = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryChainError(f"invalid {label}") from exc
    if result != value or (nonzero and result == chain.ZERO_ADDRESS):
        raise ProviderJuryChainError(f"{label} must be canonical and nonzero")
    return result


def _hash(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        result = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryChainError(f"invalid {label}") from exc
    if result != value or (nonzero and result == ZERO_BYTES32):
        raise ProviderJuryChainError(f"{label} must be canonical and nonzero")
    return result


def _word_uint(value: int) -> bytes:
    return _uint(value, "ABI uint").to_bytes(32, "big")


def _word_address(value: str) -> bytes:
    return bytes.fromhex("00" * 12 + _address(value, "ABI address")[2:])


def _word_hash(value: str) -> bytes:
    return bytes.fromhex(_hash(value, "ABI bytes32", nonzero=False)[2:])


def _array_encoding(values: list[Any], encoder: Callable[[Any], bytes]) -> bytes:
    # abi.encode(oneDynamicArray) includes the top-level offset.
    return _word_uint(32) + _word_uint(len(values)) + b"".join(encoder(item) for item in values)


def assignment_hash(*, registry: str, chain_id: int, settlement: str, case_id: str,
                    roster_version: int, seed: str, minimum_reputation: int,
                    jury_size: int, threshold: int, owners: list[str],
                    vote_signers: list[str], operator_id_hashes: list[str],
                    peer_id_hashes: list[str], capability_hashes: list[str],
                    reputations: list[int]) -> str:
    """Recompute ProviderJuryRegistryV1's immutable assignment commitment."""
    arrays = (
        chain.keccak256(_array_encoding(owners, _word_address)),
        chain.keccak256(_array_encoding(vote_signers, _word_address)),
        chain.keccak256(_array_encoding(operator_id_hashes, _word_hash)),
        chain.keccak256(_array_encoding(peer_id_hashes, _word_hash)),
        chain.keccak256(_array_encoding(capability_hashes, _word_hash)),
        chain.keccak256(_array_encoding(reputations, _word_uint)),
    )
    encoded = b"".join((
        ASSIGNMENT_TYPEHASH,
        _word_address(registry),
        _word_uint(_uint(chain_id, "chain id", positive=True)),
        _word_address(settlement),
        _word_hash(case_id),
        _word_uint(_uint(roster_version, "roster version", bits=64)),
        _word_hash(seed),
        _word_uint(_uint(minimum_reputation, "minimum reputation", bits=64, positive=True)),
        _word_uint(_uint(jury_size, "jury size", bits=16, positive=True)),
        _word_uint(_uint(threshold, "threshold", bits=16, positive=True)),
        *arrays,
    ))
    return "0x" + chain.keccak256(encoded).hex()


def _raw_result(value: Any, label: str) -> bytes:
    if (not isinstance(value, str) or not value.startswith("0x")
            or len(value) % 2 or any(ch not in "0123456789abcdef" for ch in value[2:])):
        raise ProviderJuryChainError(f"{label} returned malformed ABI data")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ProviderJuryChainError(f"{label} returned malformed ABI data") from exc


def _address_word(word: bytes, label: str) -> str:
    if len(word) != 32 or any(word[:12]):
        raise ProviderJuryChainError(f"{label} returned a malformed address")
    return _address("0x" + word[12:].hex(), label, nonzero=False)


def _uint_word(word: bytes, label: str, *, bits: int = 256) -> int:
    if len(word) != 32:
        raise ProviderJuryChainError(f"{label} returned a malformed integer")
    value = int.from_bytes(word, "big")
    return _uint(value, label, bits=bits)


def _strict_arrays(raw: bytes, *, head_words: int, offsets: list[int],
                   lengths_limit: int, label: str) -> list[list[bytes]]:
    """Decode canonical consecutive arrays of static ABI words."""
    cursor = head_words * 32
    arrays: list[list[bytes]] = []
    for offset in offsets:
        if offset != cursor or offset + 32 > len(raw):
            raise ProviderJuryChainError(f"{label} returned noncanonical array offsets")
        count = int.from_bytes(raw[offset:offset + 32], "big")
        if count > lengths_limit:
            raise ProviderJuryChainError(f"{label} returned an oversized array")
        end = offset + 32 + count * 32
        if end > len(raw):
            raise ProviderJuryChainError(f"{label} returned a truncated array")
        arrays.append([raw[offset + 32 + index * 32:offset + 64 + index * 32]
                       for index in range(count)])
        cursor = end
    if cursor != len(raw):
        raise ProviderJuryChainError(f"{label} returned trailing ABI data")
    return arrays


def _strict_json_document(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise ProviderJuryChainError(f"{label} must be strict JSON")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, item in items:
            if name in result:
                raise ProviderJuryChainError(f"{label} repeats field {name!r}")
            result[name] = item
        return result

    try:
        result = json.loads(
            value, object_pairs_hook=pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ProviderJuryChainError(f"{label} contains non-finite value {item!r}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise ProviderJuryChainError(f"{label} must be strict JSON") from exc
    if not isinstance(result, dict):
        raise ProviderJuryChainError(f"{label} must be a JSON object")
    return result


def _decode_rlp_item(
    raw: bytes, offset: int = 0, *, allow_list: bool = True,
) -> tuple[bytes | list[Any], int]:
    if offset >= len(raw):
        raise ProviderJuryChainError("truncated stored jury transaction RLP")
    prefix = raw[offset]
    if prefix < 0x80:
        return bytes([prefix]), offset + 1
    if prefix <= 0xB7:
        length = prefix - 0x80
        start, end = offset + 1, offset + 1 + length
        if end > len(raw):
            raise ProviderJuryChainError("truncated stored jury transaction RLP")
        value = raw[start:end]
        if length == 1 and value[0] < 0x80:
            raise ProviderJuryChainError("noncanonical stored jury transaction RLP")
        return value, end
    if prefix <= 0xBF:
        length_size = prefix - 0xB7
        start, stop = offset + 1, offset + 1 + length_size
        if stop > len(raw) or raw[start] == 0:
            raise ProviderJuryChainError("noncanonical stored jury transaction RLP")
        length = int.from_bytes(raw[start:stop], "big")
        if length < 56:
            raise ProviderJuryChainError("noncanonical stored jury transaction RLP")
        end = stop + length
        if end > len(raw):
            raise ProviderJuryChainError("truncated stored jury transaction RLP")
        return raw[stop:end], end
    if not allow_list:
        raise ProviderJuryChainError("stored jury transaction contains nested RLP fields")
    if prefix <= 0xF7:
        length, start = prefix - 0xC0, offset + 1
    else:
        length_size = prefix - 0xF7
        length_start, start = offset + 1, offset + 1 + length_size
        if start > len(raw) or raw[length_start] == 0:
            raise ProviderJuryChainError("noncanonical stored jury transaction RLP")
        length = int.from_bytes(raw[length_start:start], "big")
        if length < 56:
            raise ProviderJuryChainError("noncanonical stored jury transaction RLP")
    end = start + length
    if end > len(raw):
        raise ProviderJuryChainError("truncated stored jury transaction RLP")
    items: list[Any] = []
    cursor = start
    while cursor < end:
        item, cursor = _decode_rlp_item(raw, cursor, allow_list=False)
        if cursor > end:
            raise ProviderJuryChainError(
                "stored jury transaction RLP crosses its list boundary"
            )
        items.append(item)
    if cursor != end:
        raise ProviderJuryChainError("invalid stored jury transaction RLP list")
    return items, end


def _rlp_uint(value: Any, label: str) -> int:
    if not isinstance(value, bytes) or (value and value[0] == 0) or len(value) > 32:
        raise ProviderJuryChainError(f"invalid stored jury transaction {label}")
    return int.from_bytes(value, "big")


def _decode_signed_legacy_transaction(value: Any) -> dict[str, Any]:
    if isinstance(value, bytes):
        raw = value
    elif (
        isinstance(value, str)
        and value.startswith("0x")
        and len(value) % 2 == 0
        and value == value.lower()
    ):
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError:
            raise ProviderJuryChainError("stored jury transaction is malformed") from None
    else:
        raise ProviderJuryChainError("stored jury transaction is malformed")
    if not raw or len(raw) > 65_536:
        raise ProviderJuryChainError("stored jury transaction exceeds its safety bound")
    item, end = _decode_rlp_item(raw)
    if end != len(raw) or not isinstance(item, list) or len(item) != 9:
        raise ProviderJuryChainError(
            "stored jury transaction is not one canonical legacy transaction"
        )
    if any(not isinstance(field, bytes) for field in item):
        raise ProviderJuryChainError("stored jury transaction contains nested RLP fields")
    nonce, gas_price, gas_units = (
        _rlp_uint(item[0], "nonce"), _rlp_uint(item[1], "gas price"),
        _rlp_uint(item[2], "gas limit"),
    )
    destination = item[3]
    if len(destination) != 20:
        raise ProviderJuryChainError(
            "stored jury transaction must target one contract address"
        )
    value_int = _rlp_uint(item[4], "value")
    data = item[5]
    v, r, s = (
        _rlp_uint(item[6], "v"), _rlp_uint(item[7], "r"),
        _rlp_uint(item[8], "s"),
    )
    if v < 35:
        raise ProviderJuryChainError("stored jury transaction is not EIP-155 protected")
    recovery_id = (v - 35) % 2
    chain_id = (v - 35 - recovery_id) // 2
    if chain_id <= 0 or v != chain_id * 2 + 35 + recovery_id:
        raise ProviderJuryChainError("stored jury transaction has an invalid chain id")
    if not 0 < r < chain.SECP256K1_N or not 0 < s <= chain.SECP256K1_N // 2:
        raise ProviderJuryChainError("stored jury transaction has an invalid signature")
    signing_payload = chain.rlp_encode([
        nonce, gas_price, gas_units, destination, value_int, data, chain_id, 0, 0,
    ])
    try:
        sender = chain.recover_evm_address(
            chain.keccak256(signing_payload),
            chain.EvmSignature(
                r="0x" + r.to_bytes(32, "big").hex(),
                s="0x" + s.to_bytes(32, "big").hex(), v=recovery_id,
            ),
        )
    except chain.ChainError:
        raise ProviderJuryChainError(
            "stored jury transaction signature cannot be recovered"
        ) from None
    return {
        "raw": raw, "chain_id": chain_id, "sender": sender, "nonce": nonce,
        "gas_price_wei": gas_price, "gas_units": gas_units,
        "to": "0x" + destination.hex(), "value": value_int, "data": data,
    }


def _calldata_bytes(value: Any) -> bytes:
    if (
        not isinstance(value, str) or not value.startswith("0x")
        or value != value.lower() or len(value) % 2
    ):
        raise ProviderJuryChainError("jury calldata must be canonical hex")
    try:
        result = bytes.fromhex(value[2:])
    except ValueError:
        raise ProviderJuryChainError("jury calldata must be canonical hex") from None
    if not result:
        raise ProviderJuryChainError("jury calldata must not be empty")
    return result


def _verify_signed_transaction(plan: Mapping[str, Any], raw_value: Any, tx_hash: Any) -> bytes:
    transaction = plan.get("transaction")
    if not isinstance(transaction, Mapping):
        raise ProviderJuryChainError("durable jury transaction plan is malformed")
    decoded = _decode_signed_legacy_transaction(raw_value)
    observed_hash = "0x" + chain.keccak256(decoded["raw"]).hex()
    if tx_hash != observed_hash:
        raise ProviderJuryChainError("stored jury transaction hash mismatch")
    if (
        decoded["chain_id"] != transaction.get("chain_id")
        or decoded["sender"] != transaction.get("sender")
        or decoded["nonce"] != transaction.get("nonce")
        or decoded["gas_price_wei"] != transaction.get("gas_price_wei")
        or decoded["gas_units"] != transaction.get("gas_units")
        or decoded["to"] != transaction.get("to")
        or decoded["value"] != transaction.get("value")
        or decoded["data"] != _calldata_bytes(transaction.get("calldata"))
    ):
        raise ProviderJuryChainError(
            "stored jury transaction differs from its durable plan"
        )
    return decoded["raw"]


def _validated_action(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProviderJuryChainError("durable jury action must be an object")
    action = json.loads(_json(value))
    required = {
        "schema", "action", "network_id", "chain_id", "genesis_hash", "sender",
        "target", "value", "calldata", "settlement_key", "action_hash",
    }
    if not required.issubset(action) or action.get("schema") != TRANSACTION_SCHEMA:
        raise ProviderJuryChainError("durable jury action schema is invalid")
    if action.get("action") not in {
        "vote_dispute_by_sig", "finalize_jury", "expire_jury", "retry_jury",
    }:
        raise ProviderJuryChainError("durable jury action type is invalid")
    if (
        not isinstance(action.get("network_id"), str)
        or not action["network_id"]
        or action["network_id"] != action["network_id"].strip()
    ):
        raise ProviderJuryChainError("durable jury network id is invalid")
    _uint(action.get("chain_id"), "durable jury chain id", positive=True)
    _hash(action.get("genesis_hash"), "durable jury genesis hash")
    _address(action.get("sender"), "durable jury sender")
    _address(action.get("target"), "durable jury target")
    if action.get("value") != 0:
        raise ProviderJuryChainError("durable jury transaction value must be zero")
    _calldata_bytes(action.get("calldata"))
    _hash(action.get("settlement_key"), "durable jury settlement key")
    action_hash_value = _hash(action.get("action_hash"), "action hash")
    committed = {name: item for name, item in action.items() if name != "action_hash"}
    if evidence_hash(committed) != action_hash_value:
        raise ProviderJuryChainError("jury chain action hash is invalid")
    return action


def _transaction_plan(
    action: Mapping[str, Any], *, scope: str, nonce: int,
    gas_price_wei: int, gas_units: int,
) -> dict[str, Any]:
    body = _validated_action(action)
    expected_scope = f"{body['genesis_hash']}:{body['chain_id']}"
    if scope != expected_scope:
        raise ProviderJuryChainError("jury transaction scope differs from its action")
    transaction = {
        "chain_id": body["chain_id"], "sender": body["sender"],
        "nonce": _uint(nonce, "jury transaction nonce", bits=63),
        "gas_price_wei": _uint(
            gas_price_wei, "jury transaction gas price", positive=True,
        ),
        "gas_units": _uint(
            gas_units, "jury transaction gas units", positive=True, bits=64,
        ),
        "to": body["target"], "value": 0, "calldata": body["calldata"],
    }
    unsigned = {
        "schema": TRANSACTION_PLAN_SCHEMA, "scope": scope,
        "action": body, "transaction": transaction,
    }
    return {**unsigned, "plan_hash": evidence_hash(unsigned)}


def _validated_transaction_plan(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "scope", "action", "transaction", "plan_hash",
    }:
        raise ProviderJuryChainError("durable jury transaction plan is malformed")
    plan = json.loads(_json(value))
    if plan["schema"] != TRANSACTION_PLAN_SCHEMA:
        raise ProviderJuryChainError("durable jury transaction plan schema is invalid")
    unsigned = {name: item for name, item in plan.items() if name != "plan_hash"}
    if _hash(plan["plan_hash"], "transaction plan hash") != evidence_hash(unsigned):
        raise ProviderJuryChainError("durable jury transaction plan hash is invalid")
    action = _validated_action(plan["action"])
    transaction = plan["transaction"]
    if not isinstance(transaction, Mapping) or set(transaction) != {
        "chain_id", "sender", "nonce", "gas_price_wei", "gas_units", "to",
        "value", "calldata",
    }:
        raise ProviderJuryChainError("durable jury transaction fields are malformed")
    rebuilt = _transaction_plan(
        action, scope=plan["scope"], nonce=transaction.get("nonce"),
        gas_price_wei=transaction.get("gas_price_wei"),
        gas_units=transaction.get("gas_units"),
    )
    if rebuilt != plan:
        raise ProviderJuryChainError("durable jury transaction plan is inconsistent")
    return plan


@dataclass(frozen=True)
class ProviderJuryChainConfig:
    network_id: str
    rpc_urls: tuple[str, ...]
    chain_id: int
    genesis_hash: str
    settlement_contract: str
    settlement_runtime_code_hash: str
    jury_registry: str
    registry_runtime_code_hash: str
    jury_registry_governance: str
    reputation_authority: str
    bond_penalty_recipient: str
    minimum_reputation: int
    jury_size: int
    adjudication_threshold: int
    selection_delay_blocks: int
    confirmations: int
    max_snapshot_age_seconds: int = 300
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if (not isinstance(self.network_id, str) or not self.network_id.strip()
                or self.network_id != self.network_id.strip() or len(self.network_id) > 256):
            raise ProviderJuryChainError("network_id must be bounded canonical text")
        _validate_rpc_urls(self.rpc_urls)
        _uint(self.chain_id, "chain id", positive=True)
        for name in ("genesis_hash", "settlement_runtime_code_hash",
                     "registry_runtime_code_hash"):
            _hash(getattr(self, name), name)
        for name in ("settlement_contract", "jury_registry", "jury_registry_governance",
                     "reputation_authority", "bond_penalty_recipient"):
            _address(getattr(self, name), name)
        if len({self.settlement_contract, self.jury_registry, self.jury_registry_governance,
                self.reputation_authority}) != 4:
            raise ProviderJuryChainError("dynamic jury authorities and contracts must be distinct")
        _uint(self.minimum_reputation, "minimum reputation", bits=64, positive=True)
        if (not 3 <= self.jury_size <= 7
                or not 2 <= self.adjudication_threshold <= self.jury_size
                or self.adjudication_threshold * 2 <= self.jury_size):
            raise ProviderJuryChainError("dynamic jury requires a bounded strict majority")
        if not 1 <= self.selection_delay_blocks <= 64:
            raise ProviderJuryChainError("unsupported jury selection delay")
        if not 2 <= self.confirmations <= 256:
            raise ProviderJuryChainError("jury execution requires 2 to 256 confirmations")
        if not 30 <= self.max_snapshot_age_seconds <= 86400:
            raise ProviderJuryChainError("snapshot age bound is unsafe")
        if not 1 <= self.timeout_seconds <= 300:
            raise ProviderJuryChainError("RPC timeout is out of bounds")


def _canonical_key_path(path: str | os.PathLike[str]) -> Path:
    requested = Path(os.path.abspath(os.fspath(path)))
    current = Path(requested.anchor)
    for part in requested.parts[1:]:
        current /= part
        try:
            component = os.lstat(current)
        except FileNotFoundError:
            raise ProviderJuryChainError("jury key path does not exist") from None
        if stat.S_ISLNK(component.st_mode) and component.st_uid != 0:
            raise ProviderJuryChainError(
                "jury key path contains a user-controlled symbolic link"
            )
    try:
        return Path(os.path.realpath(requested, strict=True))
    except OSError:
        raise ProviderJuryChainError("unable to canonicalize jury key path") from None


@contextmanager
def _open_protected_key(path: str | os.PathLike[str]):
    key_path = _canonical_key_path(path)
    parent = key_path.parent
    parent_info = os.stat(parent)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid not in {0, os.getuid()}
        or parent_info.st_mode & 0o022
    ):
        raise ProviderJuryChainError(
            "jury key parent must be owned and not group/world writable"
        )
    try:
        descriptor = os.open(
            key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise ProviderJuryChainError("unable to open protected jury key") from None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise ProviderJuryChainError(
                "jury key must be an owned 0400/0600 regular file with exactly one link"
            )
        current = os.lstat(key_path)
        if (
            stat.S_ISLNK(current.st_mode)
            or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise ProviderJuryChainError("jury key changed after its protected open")
        try:
            raw = os.read(descriptor, 257)
            if len(raw) > 256:
                raise ProviderJuryChainError("invalid dedicated jury key file")
            private_key = chain.parse_private_key(raw.decode("ascii").strip())
        except (OSError, UnicodeError, chain.ChainError):
            raise ProviderJuryChainError("unable to read protected jury key") from None
        yield key_path, descriptor, info, private_key
    finally:
        os.close(descriptor)


def _protected_key(path: str | os.PathLike[str]) -> bytes:
    with _open_protected_key(path) as (_path, _descriptor, _info, private_key):
        return private_key


@contextmanager
def _jury_sender_lock(path: str | os.PathLike[str], sender: str):
    sender = _address(sender, "jury transaction sender")
    with _open_protected_key(path) as (key_path, _descriptor, key_info, private_key):
        if chain.private_key_to_address(private_key) != sender:
            raise ProviderJuryChainError(
                "execution key does not match the dedicated jury sender"
            )
        lock_path = key_path.parent / f".mycomesh-provider-jury-{sender[2:]}.lock"
        try:
            lock_fd = os.open(
                lock_path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
            )
        except OSError:
            raise ProviderJuryChainError("unable to open jury sender lock") from None
        try:
            lock_info = os.fstat(lock_fd)
            current_lock = os.lstat(lock_path)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != os.getuid()
                or lock_info.st_nlink != 1
                or stat.S_ISLNK(current_lock.st_mode)
                or (current_lock.st_dev, current_lock.st_ino)
                != (lock_info.st_dev, lock_info.st_ino)
            ):
                raise ProviderJuryChainError("jury sender lock is unsafe")
            os.fchmod(lock_fd, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProviderJuryChainError(
                    "another jury process is using this transaction sender"
                ) from None
            current_key = os.lstat(key_path)
            if (
                stat.S_ISLNK(current_key.st_mode)
                or current_key.st_nlink != 1
                or (current_key.st_dev, current_key.st_ino)
                != (key_info.st_dev, key_info.st_ino)
            ):
                raise ProviderJuryChainError(
                    "jury key changed while acquiring its sender lock"
                )
            yield private_key
        finally:
            os.close(lock_fd)


def _prepare_private_outbox(path: str | os.PathLike[str]) -> tuple[Path, tuple[int, int]]:
    target = Path(os.path.abspath(os.fspath(path)))
    parent = target.parent
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        try:
            component = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(component.st_mode) and component.st_uid != 0:
            raise ProviderJuryChainError(
                "jury outbox path contains a user-controlled symbolic link"
            )
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_link = os.lstat(parent)
    parent_info = os.stat(parent)
    if (
        (stat.S_ISLNK(parent_link.st_mode) and parent_link.st_uid != 0)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid not in {0, os.getuid()}
        or parent_info.st_mode & 0o022
    ):
        raise ProviderJuryChainError(
            "jury outbox parent must be owned and not group/world writable"
        )
    descriptor = os.open(
        target, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise ProviderJuryChainError(
                "jury outbox must be an owned regular file with exactly one link"
            )
        os.fchmod(descriptor, 0o600)
        identity = (info.st_dev, info.st_ino)
    finally:
        os.close(descriptor)
    return target, identity


def _verify_private_outbox(
    path: Path, *, identity: tuple[int, int], sidecars: bool,
) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise ProviderJuryChainError("jury outbox disappeared during SQLite open") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or (info.st_dev, info.st_ino) != identity
    ):
        raise ProviderJuryChainError("jury outbox changed after its protected open")
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
            raise ProviderJuryChainError("jury outbox SQLite sidecar is unsafe")
        os.chmod(sidecar, 0o600)


class JuryTransactionOutbox:
    """One durable nonce fence for finalize and vote transactions."""

    TERMINAL = frozenset({"confirmed", "reverted"})

    def __init__(self, path: str | os.PathLike[str]) -> None:
        if str(path) == ":memory:":
            raise ProviderJuryChainError("jury transaction outbox must be durable")
        target, identity = _prepare_private_outbox(path)
        _verify_private_outbox(target, identity=identity, sidecars=True)
        self._lock = threading.RLock()
        self.path = target
        self.db = sqlite3.connect(
            target, timeout=30, isolation_level=None, check_same_thread=False,
        )
        try:
            _verify_private_outbox(target, identity=identity, sidecars=False)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA trusted_schema=OFF")
            mode = self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise ProviderJuryChainError("jury outbox requires SQLite WAL mode")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("""CREATE TABLE IF NOT EXISTS provider_jury_chain_transactions (
                action_hash TEXT PRIMARY KEY, scope TEXT NOT NULL, action TEXT NOT NULL,
                sender TEXT NOT NULL, nonce INTEGER NOT NULL, tx_hash TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL, calldata TEXT NOT NULL, raw_tx TEXT NOT NULL,
                action_json TEXT NOT NULL, transaction_plan_json TEXT NOT NULL,
                state TEXT NOT NULL, receipt_json TEXT, created_at INTEGER NOT NULL,
                UNIQUE(scope,sender,nonce)
            )""")
            columns = {
                row[1] for row in self.db.execute(
                    "PRAGMA table_info(provider_jury_chain_transactions)"
                ).fetchall()
            }
            if columns != {
                "action_hash", "scope", "action", "sender", "nonce", "tx_hash",
                "target", "calldata", "raw_tx", "action_json",
                "transaction_plan_json", "state", "receipt_json", "created_at",
            }:
                raise ProviderJuryChainError(
                    "jury outbox schema is not the hardened transaction-plan schema"
                )
            _verify_private_outbox(target, identity=identity, sidecars=True)
            for row in self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions"
            ).fetchall():
                self._validated_row(row)
            # A hard crash after the durable commit is ambiguous. Never silently
            # attempt the stored bytes again.
            self.db.execute(
                "UPDATE provider_jury_chain_transactions SET state='uncertain' "
                "WHERE state='signing' OR state='sending'"
            )
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def storage_health(self) -> dict[str, Any]:
        """Return a non-mutating integrity/write-lock and backlog snapshot."""
        snapshot: dict[str, Any] = {
            "schema": CHAIN_STORAGE_HEALTH_SCHEMA,
            "ready": False,
            "quick_check": False,
            "writable": False,
            "backlog_count": 0,
            "uncertain_count": 0,
        }
        try:
            with self._lock:
                rows = self.db.execute("PRAGMA quick_check(1)").fetchall()
                if len(rows) != 1 or rows[0][0] != "ok":
                    snapshot["error_code"] = "integrity_check_failed"
                    return snapshot
                snapshot["quick_check"] = True
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    self.db.execute(
                        "UPDATE provider_jury_chain_transactions SET state=state WHERE 0"
                    )
                    for stored in self.db.execute(
                        "SELECT * FROM provider_jury_chain_transactions"
                    ).fetchall():
                        self._validated_row(stored)
                    snapshot["writable"] = True
                    row = self.db.execute(
                        "SELECT COUNT(*) AS backlog_count, "
                        "COALESCE(SUM(CASE WHEN state='uncertain' THEN 1 ELSE 0 END),0) "
                        "AS uncertain_count FROM provider_jury_chain_transactions "
                        "WHERE state NOT IN ('confirmed','reverted')"
                    ).fetchone()
                    snapshot["backlog_count"] = int(row["backlog_count"])
                    snapshot["uncertain_count"] = int(row["uncertain_count"])
                finally:
                    self.db.rollback()
                snapshot["ready"] = True
                return snapshot
        except Exception as exc:
            snapshot["error_code"] = type(exc).__name__
            return snapshot

    @staticmethod
    def _validated_row(
        row: sqlite3.Row,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        action = _strict_json_document(row["action_json"], "durable jury action")
        action = _validated_action(action)
        plan = _strict_json_document(
            row["transaction_plan_json"], "durable jury transaction plan",
        )
        plan = _validated_transaction_plan(plan)
        transaction = plan["transaction"]
        if (
            row["action_hash"] != action["action_hash"]
            or row["scope"] != plan["scope"]
            or row["action"] != action["action"]
            or row["sender"] != action["sender"]
            or row["nonce"] != transaction["nonce"]
            or row["target"] != action["target"]
            or row["calldata"] != action["calldata"]
            or plan["action"] != action
            or row["action_json"] != _json(action)
            or row["transaction_plan_json"] != _json(plan)
        ):
            raise ProviderJuryChainError(
                "durable jury row differs from its signed transaction plan"
            )
        _hash(row["tx_hash"], "durable jury transaction hash")
        _verify_signed_transaction(plan, row["raw_tx"], row["tx_hash"])
        if row["state"] not in {
            "signing", "sending", "submitted", "uncertain", "confirmed", "reverted",
        }:
            raise ProviderJuryChainError("durable jury transaction state is invalid")
        _uint(row["created_at"], "durable jury creation time", bits=64, positive=True)
        if row["receipt_json"] is not None:
            receipt = _strict_json_document(
                row["receipt_json"], "durable jury receipt",
            )
            if row["receipt_json"] != _json(receipt):
                raise ProviderJuryChainError("durable jury receipt is not canonical")
        return action, plan

    @classmethod
    def _public(cls, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        _action, plan = cls._validated_row(row)
        result = {name: row[name] for name in (
            "action_hash", "scope", "action", "sender", "nonce", "tx_hash",
            "target", "calldata", "state", "created_at",
        )}
        result["transaction_plan_hash"] = plan["plan_hash"]
        if row["receipt_json"]:
            result["receipt"] = _strict_json_document(
                row["receipt_json"], "durable jury receipt",
            )
        return result

    def get(self, action_hash: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions WHERE action_hash=?",
                (_hash(action_hash, "action hash"),),
            ).fetchone()
        return self._public(row)

    def action(self, action_hash: str) -> dict[str, Any]:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions WHERE action_hash=?",
                (_hash(action_hash, "action hash"),),
            ).fetchone()
        if row is None:
            raise ProviderJuryChainError("unknown jury transaction")
        action, _plan = self._validated_row(row)
        return action

    def unresolved(self, scope: str, sender: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions WHERE scope=? AND sender=? "
                "AND state NOT IN ('confirmed','reverted') ORDER BY nonce",
                (scope, _address(sender, "sender")),
            ).fetchall()
        return [self._public(row) for row in rows]

    def latest_for_case(
        self, *, scope: str, sender: str, action: str, settlement_key: str,
    ) -> dict[str, Any] | None:
        """Find the newest durable maintenance action for one exact case.

        ``calldata`` alone is insufficient because repeated ``retryJury`` calls
        intentionally use the same ABI payload after distinct failed draws.
        The hashed action document carries the failed-assignment fingerprint;
        this lookup is used only to recover an already-created transaction.
        """
        if not isinstance(action, str) or not action:
            raise ProviderJuryChainError("jury action name is required")
        case_key = _hash(settlement_key, "settlement key")
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions "
                "WHERE scope=? AND sender=? AND action=? ORDER BY rowid DESC",
                (scope, _address(sender, "sender"), action),
            ).fetchall()
        for row in rows:
            body, _plan = self._validated_row(row)
            if body.get("settlement_key") == case_key:
                return self._public(row)
        return None

    def reserve(self, *, action: Mapping[str, Any], scope: str, sender: str,
                nonce: int, target: str, calldata: str, gas_price_wei: int,
                gas_units: int, raw_tx: bytes) -> dict[str, Any]:
        body = _validated_action(action)
        action_hash_value = body["action_hash"]
        sender = _address(sender, "jury transaction sender")
        target = _address(target, "jury transaction target")
        _calldata_bytes(calldata)
        if (
            body["sender"] != sender or body["target"] != target
            or body["calldata"] != calldata
        ):
            raise ProviderJuryChainError(
                "jury transaction arguments differ from the committed action"
            )
        plan = _transaction_plan(
            body, scope=scope, nonce=nonce, gas_price_wei=gas_price_wei,
            gas_units=gas_units,
        )
        tx_hash = "0x" + chain.keccak256(raw_tx).hex()
        raw_hex = "0x" + raw_tx.hex()
        _verify_signed_transaction(plan, raw_hex, tx_hash)
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                prior = self.db.execute(
                    "SELECT * FROM provider_jury_chain_transactions WHERE action_hash=?",
                    (action_hash_value,),
                ).fetchone()
                if prior is not None:
                    prior_public = self._public(prior)
                    assert prior_public is not None
                    if (
                        prior["target"] != target or prior["calldata"] != calldata
                        or prior["sender"] != sender
                    ):
                        raise ProviderJuryChainError("saved jury action identity changed")
                    self.db.commit()
                    return prior_public
                blocked = self.db.execute(
                    "SELECT 1 FROM provider_jury_chain_transactions WHERE scope=? AND sender=? "
                    "AND state NOT IN ('confirmed','reverted') LIMIT 1", (scope, sender),
                ).fetchone()
                if blocked is not None:
                    raise ProviderJuryChainError(
                        "jury sender has an unresolved transaction; reconcile its exact hash"
                    )
                self.db.execute(
                    """INSERT INTO provider_jury_chain_transactions(
                           action_hash,scope,action,sender,nonce,tx_hash,target,calldata,
                           raw_tx,action_json,transaction_plan_json,state,receipt_json,
                           created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)""",
                    (action_hash_value, scope, body["action"], sender, nonce, tx_hash,
                     target, calldata, raw_hex, _json(body), _json(plan), "signing",
                     int(time.time())),
                )
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        result = self.get(action_hash_value)
        assert result is not None
        return result

    def mark(self, action_hash: str, state: str, *, receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if state not in {"sending", "submitted", "uncertain", "confirmed", "reverted"}:
            raise ProviderJuryChainError("invalid jury transaction state")
        if receipt is not None and not isinstance(receipt, Mapping):
            raise ProviderJuryChainError("jury receipt must be a JSON object")
        with self._lock:
            action_hash = _hash(action_hash, "action hash")
            existing = self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions WHERE action_hash=?",
                (action_hash,),
            ).fetchone()
            if existing is None:
                raise ProviderJuryChainError("unknown jury transaction")
            self._validated_row(existing)
            cursor = self.db.execute(
                "UPDATE provider_jury_chain_transactions SET state=?,receipt_json=? WHERE action_hash=?",
                (state, _json(receipt) if receipt is not None else None,
                 action_hash),
            )
            if cursor.rowcount != 1:
                raise ProviderJuryChainError("unknown jury transaction")
        result = self.get(action_hash)
        assert result is not None
        return result

    def begin_send(self, action_hash: str) -> dict[str, Any]:
        """Atomically grant exactly one caller permission to broadcast."""
        with self._lock:
            action_hash = _hash(action_hash, "action hash")
            existing = self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions WHERE action_hash=?",
                (action_hash,),
            ).fetchone()
            if existing is None:
                raise ProviderJuryChainError("unknown jury transaction")
            self._validated_row(existing)
            cursor = self.db.execute(
                "UPDATE provider_jury_chain_transactions SET state='sending' "
                "WHERE action_hash=? AND state='signing'",
                (action_hash,),
            )
            if cursor.rowcount != 1:
                raise ProviderJuryChainError(
                    "jury transaction is already being sent or requires reconciliation"
                )
        result = self.get(action_hash)
        assert result is not None
        return result

    def raw_transaction(self, action_hash: str) -> str:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM provider_jury_chain_transactions WHERE action_hash=?",
                (_hash(action_hash, "action hash"),),
            ).fetchone()
        if row is None:
            raise ProviderJuryChainError("unknown jury transaction")
        self._validated_row(row)
        return row["raw_tx"]


class ProviderJuryChainAdapter:
    """Real RPC callbacks consumed by :class:`ProviderJuryRelayWorker`.

    ``resolve_provider`` maps one immutable on-chain snapshot (addresses,
    hashes, reputation) to the full signed Relay descriptor containing the
    unhashed operator id, peer id and jury capability.  Every returned value is
    re-hashed and compared with the Registry snapshot.
    """

    def __init__(
        self, config: ProviderJuryChainConfig, *, outbox_path: str | os.PathLike[str],
        resolve_provider: ProviderResolver, sender: str,
        execution_enabled: bool = False, dedicated_sender: bool = False,
        key_file: str | os.PathLike[str] | None = None,
        max_gas_price_wei: int | None = None, max_gas_units: int | None = None,
        max_total_gas_cost_wei: int | None = None, rpc: RPC | None = None,
        allow_test_rpc_override: bool = False,
    ) -> None:
        if not isinstance(config, ProviderJuryChainConfig):
            raise ProviderJuryChainError("validated dynamic jury chain config is required")
        if not callable(resolve_provider):
            raise ProviderJuryChainError("Provider descriptor resolver is required")
        if type(execution_enabled) is not bool or type(dedicated_sender) is not bool:
            raise ProviderJuryChainError("jury execution flags must be explicit booleans")
        self.config = config
        self.resolve_provider = resolve_provider
        self.sender = _address(sender, "jury transaction sender")
        self.execution_enabled = execution_enabled
        self.dedicated_sender = dedicated_sender
        self.key_file = Path(key_file) if key_file is not None else None
        self.max_gas_price_wei = max_gas_price_wei
        self.max_gas_units = max_gas_units
        self.max_total_gas_cost_wei = max_total_gas_cost_wei
        if type(allow_test_rpc_override) is not bool:
            raise ProviderJuryChainError("jury RPC test override opt-in must be boolean")
        if rpc is None and allow_test_rpc_override:
            raise ProviderJuryChainError("jury RPC test override opt-in requires a callback")
        if rpc is not None and (
            not allow_test_rpc_override or not callable(rpc)
        ):
            raise ProviderJuryChainError(
                "jury RPC callback requires explicit test-only opt-in"
            )
        self._rpc_override = rpc
        if execution_enabled:
            if not dedicated_sender or self.key_file is None:
                raise ProviderJuryChainError(
                    "execution requires an explicitly dedicated sender and protected key file"
                )
            for value, label in (
                (max_gas_price_wei, "gas price cap"), (max_gas_units, "gas unit cap"),
                (max_total_gas_cost_wei, "total gas cost cap"),
            ):
                _uint(value, label, positive=True)
            try:
                configured_key = _protected_key(self.key_file)
            except Exception as exc:
                raise ProviderJuryChainError(
                    "execution key file is unavailable or not safely protected"
                ) from exc
            if chain.private_key_to_address(configured_key) != self.sender:
                raise ProviderJuryChainError(
                    "execution key does not match the dedicated jury sender"
                )
        elif dedicated_sender or self.key_file is not None or any(
            value is not None for value in (
                max_gas_price_wei, max_gas_units, max_total_gas_cost_wei,
            )
        ):
            raise ProviderJuryChainError(
                "jury key, dedicated sender, and gas caps require execution enablement"
            )
        self.outbox = JuryTransactionOutbox(outbox_path)

    def close(self) -> None:
        self.outbox.close()

    def storage_health(self) -> dict[str, Any]:
        return self.outbox.storage_health()

    def _rpc(self, method: str, params: list[Any]) -> Any:
        if self._rpc_override is not None:
            return self._rpc_override(method, params)
        endpoints = self.config.rpc_urls
        with ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
            futures = [
                executor.submit(
                    chain.rpc_call, endpoint, method, params,
                    self.config.timeout_seconds,
                )
                for endpoint in endpoints
            ]
            results: list[Any] = []
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    raise ProviderJuryChainError(
                        f"jury RPC quorum unavailable for {method}"
                    ) from None
        if len(results) != len(endpoints):
            raise ProviderJuryChainError(f"jury RPC quorum unavailable for {method}")
        if method in {"eth_gasPrice", "eth_estimateGas", "eth_getBalance", "eth_blockNumber"}:
            quantities = [_hex_uint(result, method) for result in results]
            if method in {"eth_gasPrice", "eth_estimateGas"}:
                return hex(max(quantities))
            return hex(min(quantities))
        first = _json(results[0])
        if any(_json(result) != first for result in results[1:]):
            raise ProviderJuryChainError(f"jury RPC endpoints disagree on {method}")
        return results[0]

    @property
    def _scope(self) -> str:
        return f"{self.config.genesis_hash}:{self.config.chain_id}"

    def _call(self, target: str, signature: str, args: list[str], tag: Any,
              *, sender: str | None = None) -> bytes:
        transaction = {"to": target, "data": chain.encode_contract_call(signature, args)}
        if sender is not None:
            transaction["from"] = sender
        return _raw_result(self._rpc("eth_call", [transaction, tag]), signature)

    def _call_words(self, target: str, signature: str, args: list[str], count: int,
                    tag: Any) -> list[bytes]:
        raw = self._call(target, signature, args, tag)
        if len(raw) != count * 32:
            raise ProviderJuryChainError(f"{signature} returned the wrong ABI length")
        return [raw[index * 32:(index + 1) * 32] for index in range(count)]

    def _one_uint(self, target: str, signature: str, tag: Any, *, bits: int = 256) -> int:
        return _uint_word(self._call_words(target, signature, [], 1, tag)[0], signature, bits=bits)

    def _one_address(self, target: str, signature: str, tag: Any) -> str:
        return _address_word(self._call_words(target, signature, [], 1, tag)[0], signature)

    def confirmed_context(self) -> dict[str, Any]:
        """Validate both runtimes and immutable policy at one canonical block."""
        c = self.config
        if _hex_uint(self._rpc("eth_chainId", []), "chain id") != c.chain_id:
            raise ProviderJuryChainError("RPC chain differs from the jury deployment")
        genesis = self._rpc("eth_getBlockByNumber", ["0x0", False])
        if (not isinstance(genesis, Mapping)
                or _hash(str(genesis.get("hash") or ""), "genesis hash") != c.genesis_hash):
            raise ProviderJuryChainError("RPC genesis differs from the jury deployment")
        head = _hex_uint(self._rpc("eth_blockNumber", []), "head block")
        number = head - c.confirmations + 1
        if number < 0:
            raise ProviderJuryChainError("chain has insufficient jury confirmations")
        block = self._rpc("eth_getBlockByNumber", [hex(number), False])
        if not isinstance(block, Mapping):
            raise ProviderJuryChainError("confirmed jury block is unavailable")
        block_hash = _hash(str(block.get("hash") or ""), "confirmed block hash")
        if _hex_uint(block.get("number"), "confirmed block number") != number:
            raise ProviderJuryChainError("RPC returned the wrong confirmed jury block")
        timestamp = _hex_uint(block.get("timestamp"), "confirmed block timestamp", bits=64)
        if not -30 <= int(time.time()) - timestamp <= c.max_snapshot_age_seconds:
            raise ProviderJuryChainError("confirmed jury snapshot is stale or from the future")
        tag = {"blockHash": block_hash, "requireCanonical": True}
        for address_value, expected_hash, label in (
            (c.settlement_contract, c.settlement_runtime_code_hash, "Settlement"),
            (c.jury_registry, c.registry_runtime_code_hash, "Jury Registry"),
        ):
            code = _raw_result(self._rpc("eth_getCode", [address_value, tag]), f"{label} code")
            if not code or "0x" + chain.keccak256(code).hex() != expected_hash:
                raise ProviderJuryChainError(f"{label} runtime differs from its release pin")
        settlement_registry = self._one_address(
            c.settlement_contract, "juryRegistry()", tag,
        )
        settlement_threshold = self._one_uint(
            c.settlement_contract, "adjudicationThreshold()", tag, bits=16,
        )
        protocol = self._one_uint(c.settlement_contract, "PROTOCOL_VERSION()", tag)
        registry_values = {
            "settlement": self._one_address(c.jury_registry, "settlement()", tag),
            "governance": self._one_address(c.jury_registry, "governance()", tag),
            "reputation_authority": self._one_address(
                c.jury_registry, "reputationAuthority()", tag,
            ),
            "bond_penalty_recipient": self._one_address(
                c.jury_registry, "bondPenaltyRecipient()", tag,
            ),
            "minimum_reputation": self._one_uint(
                c.jury_registry, "minimumReputation()", tag, bits=64,
            ),
            "jury_size": self._one_uint(c.jury_registry, "jurySize()", tag, bits=16),
            "threshold": self._one_uint(c.jury_registry, "threshold()", tag, bits=16),
            "selection_delay_blocks": self._one_uint(
                c.jury_registry, "selectionDelayBlocks()", tag, bits=16,
            ),
        }
        randomness = "0x" + self._call_words(
            c.jury_registry, "RANDOMNESS_MODE_HASH()", [], 1, tag,
        )[0].hex()
        expected = {
            "settlement": c.settlement_contract,
            "governance": c.jury_registry_governance,
            "reputation_authority": c.reputation_authority,
            "bond_penalty_recipient": c.bond_penalty_recipient,
            "minimum_reputation": c.minimum_reputation,
            "jury_size": c.jury_size,
            "threshold": c.adjudication_threshold,
            "selection_delay_blocks": c.selection_delay_blocks,
        }
        if (protocol != 10 or settlement_registry != c.jury_registry
                or settlement_threshold != c.adjudication_threshold
                or registry_values != expected
                or randomness != chain_v10.JURY_RANDOMNESS_HASH):
            raise ProviderJuryChainError("on-chain dynamic jury policy differs from its pins")
        boundary = self._rpc("eth_getBlockByNumber", [hex(number), False])
        if (not isinstance(boundary, Mapping)
                or str(boundary.get("hash") or "").lower() != block_hash):
            raise ProviderJuryChainError("confirmed jury snapshot reorganized during reads")
        return {"block_number": number, "block_hash": block_hash,
                "timestamp": timestamp, "block_tag": tag}

    def _assert_context_canonical(self, context: Mapping[str, Any]) -> None:
        boundary = self._rpc(
            "eth_getBlockByNumber", [hex(context["block_number"]), False],
        )
        if (not isinstance(boundary, Mapping)
                or str(boundary.get("hash") or "").lower() != context["block_hash"]):
            raise ProviderJuryChainError("jury assignment snapshot reorganized during reads")

    def _assignment_info(self, settlement_key: str, tag: Any) -> dict[str, Any]:
        data = self._call(
            self.config.jury_registry, "assignmentInfo(bytes32)", [settlement_key], tag,
        )
        if len(data) < 8 * 32:
            raise ProviderJuryChainError("assignmentInfo returned truncated ABI data")
        head = [data[index * 32:(index + 1) * 32] for index in range(8)]
        offsets = [_uint_word(head[index], "assignment array offset") for index in (5, 6, 7)]
        arrays = _strict_arrays(data, head_words=8, offsets=offsets,
                                lengths_limit=7, label="assignmentInfo")
        status = _uint_word(head[0], "assignment status", bits=8)
        if status > 3:
            raise ProviderJuryChainError("Registry returned an invalid assignment status")
        return {
            "status_code": status,
            "selection_block": _uint_word(head[1], "selection block", bits=64),
            "roster_version": _uint_word(head[2], "roster version", bits=64),
            "seed": "0x" + head[3].hex(),
            "result_hash": "0x" + head[4].hex(),
            "owners": [_address_word(word, "assigned owner") for word in arrays[0]],
            "vote_signers": [_address_word(word, "assigned vote signer") for word in arrays[1]],
            "operator_id_hashes": ["0x" + word.hex() for word in arrays[2]],
        }

    def _assignment_evidence(self, settlement_key: str, tag: Any) -> dict[str, Any]:
        data = self._call(
            self.config.jury_registry, "assignmentProviderEvidence(bytes32)",
            [settlement_key], tag,
        )
        if len(data) < 3 * 32:
            raise ProviderJuryChainError("assignmentProviderEvidence returned truncated ABI data")
        offsets = [int.from_bytes(data[index * 32:(index + 1) * 32], "big")
                   for index in range(3)]
        arrays = _strict_arrays(data, head_words=3, offsets=offsets,
                                lengths_limit=7, label="assignmentProviderEvidence")
        return {
            "peer_id_hashes": ["0x" + word.hex() for word in arrays[0]],
            "capability_hashes": ["0x" + word.hex() for word in arrays[1]],
            "reputations": [_uint_word(word, "assigned reputation", bits=64)
                            for word in arrays[2]],
        }

    def _assignment_signer_snapshot(self, settlement_key: str, signer: str,
                                    tag: Any) -> dict[str, Any]:
        words = self._call_words(
            self.config.jury_registry,
            "assignmentProviderForSigner(bytes32,address)",
            [settlement_key, signer], 6, tag,
        )
        found = _uint_word(words[0], "assigned signer found flag", bits=8)
        if found not in (0, 1):
            raise ProviderJuryChainError("Registry returned malformed signer membership")
        return {
            "found": bool(found), "owner": _address_word(words[1], "assigned owner"),
            "operator_id_hash": "0x" + words[2].hex(),
            "peer_id_hash": "0x" + words[3].hex(),
            "capability_hash": "0x" + words[4].hex(),
            "reputation": _uint_word(words[5], "assigned reputation", bits=64),
        }

    def _read_assignment(self, binding: Mapping[str, Any], *, resolve: bool) -> dict[str, Any]:
        expected_binding = {
            "schema": "mycomesh.v10.provider-jury-case.v1",
            "network_id": self.config.network_id,
            "chain_id": self.config.chain_id,
            "settlement_contract": self.config.settlement_contract,
            "jury_registry": self.config.jury_registry,
            "settlement_key": _hash(binding.get("settlement_key"), "settlement key"),
        }
        if dict(binding) != expected_binding:
            raise ProviderJuryChainError("jury assignment binding differs from chain pins")
        context = self.confirmed_context()
        key, tag = expected_binding["settlement_key"], context["block_tag"]
        info = self._assignment_info(key, tag)
        common = {**expected_binding, "block_number": context["block_number"],
                  "block_hash": context["block_hash"]}
        if info["status_code"] == 0:
            self._assert_context_canonical(context)
            return {**common, "status": "missing"}
        if info["status_code"] == 1:
            if (info["result_hash"] != ZERO_BYTES32 or info["seed"] != ZERO_BYTES32
                    or any(info[name] for name in ("owners", "vote_signers", "operator_id_hashes"))):
                raise ProviderJuryChainError("pending assignment already contains finalized data")
            self._assert_context_canonical(context)
            return {**common, "status": "pending",
                    "selection_block": info["selection_block"],
                    "roster_version": info["roster_version"]}
        if info["status_code"] == 3:
            self._assert_context_canonical(context)
            return {
                **common, "status": "failed", "seed": info["seed"],
                "selection_block": info["selection_block"],
                "roster_version": info["roster_version"],
            }
        evidence = self._assignment_evidence(key, tag)
        groups = (info["owners"], info["vote_signers"], info["operator_id_hashes"],
                  evidence["peer_id_hashes"], evidence["capability_hashes"],
                  evidence["reputations"])
        if any(len(group) != self.config.jury_size for group in groups):
            raise ProviderJuryChainError("finalized assignment has the wrong jury size")
        if (len(set(info["owners"])) != self.config.jury_size
                or len(set(info["vote_signers"])) != self.config.jury_size
                or chain.ZERO_ADDRESS in info["owners"]
                or chain.ZERO_ADDRESS in info["vote_signers"]
                or set(info["owners"]) & set(info["vote_signers"])
                or len(set(info["operator_id_hashes"])) != self.config.jury_size
                or len(set(evidence["peer_id_hashes"])) != self.config.jury_size
                or any(value == ZERO_BYTES32 for group in groups[2:5] for value in group)
                or any(score < self.config.minimum_reputation
                       for score in evidence["reputations"])):
            raise ProviderJuryChainError("finalized assignment is not independent and qualified")
        computed = assignment_hash(
            registry=self.config.jury_registry, chain_id=self.config.chain_id,
            settlement=self.config.settlement_contract, case_id=key,
            roster_version=info["roster_version"], seed=info["seed"],
            minimum_reputation=self.config.minimum_reputation,
            jury_size=self.config.jury_size,
            threshold=self.config.adjudication_threshold,
            owners=info["owners"], vote_signers=info["vote_signers"],
            operator_id_hashes=info["operator_id_hashes"],
            peer_id_hashes=evidence["peer_id_hashes"],
            capability_hashes=evidence["capability_hashes"],
            reputations=evidence["reputations"],
        )
        assignment_word = "0x" + self._call_words(
            self.config.jury_registry, "assignmentHash(bytes32)", [key], 1, tag,
        )[0].hex()
        if computed != info["result_hash"] or assignment_word != computed:
            raise ProviderJuryChainError("Registry assignment commitment does not match its snapshot")
        snapshots: list[dict[str, Any]] = []
        selected: list[dict[str, Any]] = []
        for index, signer in enumerate(info["vote_signers"]):
            snapshot = {
                "owner": info["owners"][index], "vote_signer": signer,
                "operator_id_hash": info["operator_id_hashes"][index],
                "peer_id_hash": evidence["peer_id_hashes"][index],
                "capability_hash": evidence["capability_hashes"][index],
                "reputation": evidence["reputations"][index],
            }
            per_signer = self._assignment_signer_snapshot(key, signer, tag)
            if not per_signer.pop("found") or per_signer != {
                    name: value for name, value in snapshot.items() if name != "vote_signer"}:
                raise ProviderJuryChainError("per-signer assignment snapshot is inconsistent")
            snapshots.append(snapshot)
            if resolve:
                try:
                    descriptor = provider_jury._selected_provider(
                        self.resolve_provider(dict(snapshot))
                    )
                except Exception as exc:
                    raise ProviderJuryChainError(
                        "selected Provider descriptor is unavailable or invalid"
                    ) from exc
                for name, value in snapshot.items():
                    if descriptor[name] != value:
                        raise ProviderJuryChainError(
                            "selected Provider descriptor differs from the on-chain snapshot"
                        )
                selected.append(descriptor)
        result = {
            "schema": ASSIGNMENT_SCHEMA, "status": "finalized",
            "network_id": self.config.network_id, "chain_id": self.config.chain_id,
            "settlement_contract": self.config.settlement_contract,
            "jury_registry": self.config.jury_registry, "settlement_key": key,
            "assignment_hash": computed,
            "threshold": self.config.adjudication_threshold,
            "selected_providers": selected if resolve else snapshots,
            "block_number": context["block_number"], "block_hash": context["block_hash"],
        }
        self._assert_context_canonical(context)
        return result

    def fetch_assignment(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        return self._read_assignment(binding, resolve=True)

    def _action(self, *, action: str, target: str, calldata: str,
                settlement_key: str, source_plan_hash: str | None = None) -> dict[str, Any]:
        body = {
            "schema": TRANSACTION_SCHEMA, "action": action,
            "network_id": self.config.network_id, "chain_id": self.config.chain_id,
            "genesis_hash": self.config.genesis_hash, "sender": self.sender,
            "target": target, "value": 0, "calldata": calldata,
            "settlement_key": settlement_key,
        }
        if source_plan_hash is not None:
            body["source_plan_hash"] = source_plan_hash
        return {**body, "action_hash": evidence_hash(body)}

    def _require_execution_key(self) -> Path:
        if not self.execution_enabled or not self.dedicated_sender or self.key_file is None:
            raise ProviderJuryChainError("automatic Provider jury chain execution is disabled")
        return self.key_file

    def _submit(self, action: Mapping[str, Any]) -> dict[str, Any]:
        action_hash_value = _hash(action.get("action_hash"), "action hash")
        existing = self.outbox.get(action_hash_value)
        if existing is not None:
            if existing["state"] == "submitted":
                return existing
            raise ProviderJuryChainError(
                "jury transaction already has an uncertain or terminal identity; reconcile it"
            )
        key_path = self._require_execution_key()
        with _jury_sender_lock(key_path, self.sender) as private_key:
            return self._submit_locked(action, action_hash_value, private_key)

    def _submit_locked(
        self, action: Mapping[str, Any], action_hash_value: str,
        private_key: bytes,
    ) -> dict[str, Any]:
        existing = self.outbox.get(action_hash_value)
        if existing is not None:
            if existing["state"] == "submitted":
                return existing
            raise ProviderJuryChainError(
                "jury transaction already has an uncertain or terminal identity; reconcile it"
            )
        if _hex_uint(self._rpc("eth_chainId", []), "chain id") != self.config.chain_id:
            raise ProviderJuryChainError("jury broadcast RPC changed to another chain")
        genesis = self._rpc("eth_getBlockByNumber", ["0x0", False])
        if (not isinstance(genesis, Mapping)
                or _hash(str(genesis.get("hash") or ""), "genesis hash")
                != self.config.genesis_hash):
            raise ProviderJuryChainError("jury broadcast RPC changed to another genesis")
        latest = _hex_uint(
            self._rpc("eth_getTransactionCount", [self.sender, "latest"]), "latest nonce",
        )
        pending = _hex_uint(
            self._rpc("eth_getTransactionCount", [self.sender, "pending"]), "pending nonce",
        )
        if latest != pending:
            raise ProviderJuryChainError("dedicated jury sender has an external pending transaction")
        if self.outbox.unresolved(self._scope, self.sender):
            raise ProviderJuryChainError("dedicated jury sender has an unresolved durable transaction")
        gas_price = _hex_uint(self._rpc("eth_gasPrice", []), "gas price")
        estimate = _hex_uint(self._rpc("eth_estimateGas", [{
            "from": self.sender, "to": action["target"], "value": "0x0",
            "data": action["calldata"],
        }]), "gas estimate")
        gas = estimate * 12 // 10 + 10_000
        assert self.max_gas_price_wei is not None
        assert self.max_gas_units is not None
        assert self.max_total_gas_cost_wei is not None
        if (gas_price > self.max_gas_price_wei or gas > self.max_gas_units
                or gas * gas_price > self.max_total_gas_cost_wei):
            raise ProviderJuryChainError("jury transaction exceeds explicit gas caps")
        raw = chain.sign_legacy_transaction(
            private_key, latest, gas_price, gas, action["target"], 0,
            bytes.fromhex(action["calldata"][2:]), self.config.chain_id,
        )
        saved = self.outbox.reserve(
            action=action, scope=self._scope, sender=self.sender, nonce=latest,
            target=action["target"], calldata=action["calldata"],
            gas_price_wei=gas_price, gas_units=gas, raw_tx=raw,
        )
        if saved["tx_hash"] != "0x" + chain.keccak256(raw).hex():
            raise ProviderJuryChainError(
                "another process already reserved this jury action; reconcile its exact hash"
            )
        raw_hex = self.outbox.raw_transaction(action_hash_value)
        if raw_hex != "0x" + raw.hex():
            raise ProviderJuryChainError(
                "durable jury transaction bytes differ from the locally signed plan"
            )
        self.outbox.begin_send(action_hash_value)
        try:
            returned = _hash(
                self._rpc("eth_sendRawTransaction", [raw_hex]),
                "broadcast transaction hash",
            )
            if returned != saved["tx_hash"]:
                raise ProviderJuryChainError("RPC returned another jury transaction hash")
        except BaseException as exc:
            self.outbox.mark(action_hash_value, "uncertain")
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ProviderJuryChainError(
                "jury broadcast is uncertain; inspect the locally derived transaction hash"
            ) from exc
        return self.outbox.mark(action_hash_value, "submitted")

    def _transaction_identity(self, row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "status": "submitted", "tx_hash": row["tx_hash"],
            "plan_hash": row["action_hash"], "chain_id": self.config.chain_id,
            "settlement_contract": row["target"], "sender": row["sender"],
            "nonce": row["nonce"],
            "transaction_plan_hash": row["transaction_plan_hash"],
        }

    def _preflight_finalize(self, binding: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        pending = self._read_assignment(binding, resolve=False)
        if pending["status"] != "pending":
            raise ProviderJuryChainError("jury assignment is not pending finalization")
        if not (pending["block_number"] > pending["selection_block"]
                and pending["block_number"] <= pending["selection_block"] + 256):
            raise ProviderJuryChainError("jury assignment entropy is not in its finalization window")
        calldata = chain.encode_contract_call(
            "finalizeJury(bytes32)", [pending["settlement_key"]],
        )
        result = self._call(
            self.config.jury_registry, "finalizeJury(bytes32)",
            [pending["settlement_key"]],
            {"blockHash": pending["block_hash"], "requireCanonical": True},
            sender=self.sender,
        )
        if len(result) != 32 or int.from_bytes(result, "big") not in (0, 1):
            raise ProviderJuryChainError("finalizeJury preflight returned malformed data")
        return pending, self._action(
            action="finalize_jury", target=self.config.jury_registry,
            calldata=calldata, settlement_key=pending["settlement_key"],
        )

    def finalize_assignment(self, binding: Mapping[str, Any], _fetched: Mapping[str, Any]) -> dict[str, Any]:
        current = self._read_assignment(binding, resolve=True)
        if current["status"] == "finalized":
            return current
        _, action = self._preflight_finalize(binding)
        row = self.outbox.get(action["action_hash"])
        if row is None:
            row = self._submit(action)
        observation = self._inspect_action(action, row)
        if observation["status"] != "confirmed":
            raise ProviderJuryChainError(
                "finalizeJury transaction is pending or uncertain; do not broadcast another nonce"
            )
        refreshed = self._read_assignment(binding, resolve=True)
        if refreshed["status"] != "finalized":
            raise ProviderJuryChainError("confirmed finalizeJury did not produce a ready assignment")
        event = observation.get("assignment_event")
        refreshed_context = self.confirmed_context()
        refreshed_info = self._assignment_info(
            refreshed["settlement_key"], refreshed_context["block_tag"],
        )
        if (not isinstance(event, Mapping) or event.get("event") != "JuryAssigned"
                or event.get("assignment_hash") != refreshed["assignment_hash"]
                or event.get("seed") != refreshed_info["seed"]
                or event.get("owners") != [item["owner"] for item in refreshed["selected_providers"]]
                or event.get("vote_signers")
                != [item["vote_signer"] for item in refreshed["selected_providers"]]
                or event.get("operator_id_hashes")
                != [item["operator_id_hash"] for item in refreshed["selected_providers"]]):
            raise ProviderJuryChainError(
                "finalizeJury event differs from the immutable assignment snapshot"
            )
        return refreshed

    def expire_assignment(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        """Release a Registry roster freeze after the blockhash window elapsed.

        This is a separate, explicit maintenance action.  A merely not-yet-ready
        assignment can never be expired, and a successful receipt must contain
        exactly one ``JuryAssignmentFailed(caseId, bytes32(0))`` event.
        """
        current = self._read_assignment(binding, resolve=False)
        key = _hash(binding.get("settlement_key"), "settlement key")
        action = self._expire_action(current)
        existing = self.outbox.get(action["action_hash"])
        if current["status"] == "failed" and existing is None:
            # Another permissionless maintainer already released the roster.
            return current
        if current["status"] != "pending" and existing is None:
            raise ProviderJuryChainError("jury assignment is not pending expiration")
        if existing is None:
            if current["block_number"] <= current["selection_block"] + 256:
                raise ProviderJuryChainError(
                    "jury assignment blockhash window has not expired"
                )
            simulated = self._call(
                self.config.jury_registry, "expireJury(bytes32)", [key],
                {"blockHash": current["block_hash"], "requireCanonical": True},
                sender=self.sender,
            )
            if simulated:
                raise ProviderJuryChainError("expireJury simulation returned unexpected data")
            existing = self._submit(action)
        observation = self._inspect_action(action, existing)
        if observation["status"] != "confirmed":
            raise ProviderJuryChainError(
                "expireJury transaction is pending or uncertain; do not broadcast another nonce"
            )
        event = observation.get("assignment_event")
        if (not isinstance(event, Mapping)
                or event != {"event": "JuryAssignmentFailed", "seed": ZERO_BYTES32}):
            raise ProviderJuryChainError(
                "expireJury receipt does not prove the unique zero-seed failure event"
            )
        refreshed = self._read_assignment(binding, resolve=False)
        if refreshed["status"] != "failed":
            raise ProviderJuryChainError(
                "confirmed expireJury did not release the pending assignment"
            )
        return refreshed

    def _expire_action(self, current: Mapping[str, Any]) -> dict[str, Any]:
        """Build an idempotent identity for one specific pending draw.

        ``expireJury(bytes32)`` has identical calldata for every retry round of
        a case.  Binding the outbox identity to the immutable round coordinates
        prevents a confirmed expiration from round N being mistaken for the
        expiration of a later round N+1.
        """
        key = _hash(current.get("settlement_key"), "settlement key")
        calldata = chain.encode_contract_call("expireJury(bytes32)", [key])
        base = self._action(
            action="expire_jury", target=self.config.jury_registry,
            calldata=calldata, settlement_key=key,
        )
        body = {name: value for name, value in base.items() if name != "action_hash"}
        body.update({
            "source_roster_version": _uint(
                current.get("roster_version"), "assignment roster version", bits=64,
            ),
            "source_selection_block": _uint(
                current.get("selection_block"), "assignment selection block", bits=64,
            ),
        })
        return {**body, "action_hash": evidence_hash(body)}

    def _retry_action(
        self, current: Mapping[str, Any], *, registry_roster_version: int,
    ) -> dict[str, Any]:
        key = _hash(current.get("settlement_key"), "settlement key")
        calldata = chain.encode_contract_call("retryJury(bytes32)", [key])
        base = self._action(
            action="retry_jury", target=self.config.jury_registry,
            calldata=calldata, settlement_key=key,
        )
        body = {name: value for name, value in base.items() if name != "action_hash"}
        body.update({
            # These fields make each legitimately new retry distinct while
            # preserving idempotence across crashes and repeated callers.
            "source_roster_version": _uint(
                current.get("roster_version"), "failed assignment roster version", bits=64,
            ),
            "source_selection_block": _uint(
                current.get("selection_block"), "failed assignment selection block", bits=64,
            ),
            "source_seed": _hash(
                current.get("seed"), "failed assignment seed", nonzero=False,
            ),
            "registry_roster_version": _uint(
                registry_roster_version, "Registry roster version", bits=64,
            ),
            # Provider-signer authorization lives in Settlement rather than the
            # Registry roster version. Pinning the canonical observation block
            # allows a later explicit retry after that external state changes,
            # while repeated calls at the same snapshot reuse one outbox row.
            "source_block_hash": _hash(
                current.get("block_hash"), "failed assignment observation block",
            ),
        })
        return {**body, "action_hash": evidence_hash(body)}

    def _retry_event(
        self, logs: list[Any], *, receipt: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> dict[str, Any]:
        matching: list[dict[str, Any]] = []
        for log in logs:
            if not isinstance(log, Mapping):
                raise ProviderJuryChainError("receipt contains a malformed event")
            topics = log.get("topics")
            if not isinstance(topics, list) or not topics or topics[0] not in {
                    JURY_REQUESTED_TOPIC, JURY_UNAVAILABLE_TOPIC}:
                continue
            self._log_identity(
                log, receipt=receipt, address_value=self.config.jury_registry,
            )
            if (len(topics) != 3
                    or _hash(topics[1], "retry case id") != action["settlement_key"]):
                raise ProviderJuryChainError("retryJury event targets another case")
            roster_version = _uint_word(
                bytes.fromhex(_hash(topics[2], "retry roster version")[2:]),
                "retry roster version", bits=64,
            )
            observed_roster_version = action.get("registry_roster_version")
            if (type(observed_roster_version) is not int
                    or roster_version < observed_roster_version):
                raise ProviderJuryChainError(
                    "retryJury event regressed behind the pinned Registry roster version"
                )
            data = _raw_result(
                log.get("data"),
                "JuryRequested" if topics[0] == JURY_REQUESTED_TOPIC else "JuryUnavailable",
            )
            if topics[0] == JURY_REQUESTED_TOPIC:
                if len(data) != 64:
                    raise ProviderJuryChainError("JuryRequested has malformed data")
                matching.append({
                    "event": "JuryRequested", "roster_version": roster_version,
                    "selection_block": _uint_word(
                        data[:32], "requested selection block", bits=64,
                    ),
                    "roster_commitment": _hash(
                        "0x" + data[32:].hex(), "requested roster commitment",
                    ),
                })
            else:
                if len(data) != 32:
                    raise ProviderJuryChainError("JuryUnavailable has malformed data")
                matching.append({
                    "event": "JuryUnavailable", "roster_version": roster_version,
                    "independent_candidate_count": _uint_word(
                        data, "independent candidate count", bits=256,
                    ),
                })
        if len(matching) != 1:
            raise ProviderJuryChainError(
                "retryJury receipt must contain one retry outcome event"
            )
        return matching[0]

    def _confirmed_retry_result(
        self, binding: Mapping[str, Any], action: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> dict[str, Any]:
        event = observation.get("assignment_event")
        if not isinstance(event, Mapping):
            raise ProviderJuryChainError("retryJury receipt has no verified outcome event")
        refreshed = self._read_assignment(binding, resolve=True)
        if event.get("event") == "JuryRequested":
            # A third party may already have finalized the draw by the time the
            # retry receipt reaches the configured confirmation depth. Return
            # the actual verified state; never relabel Pending as Finalized.
            if refreshed["status"] == "pending":
                if (refreshed.get("roster_version") != event.get("roster_version")
                        or refreshed.get("selection_block") != event.get("selection_block")):
                    raise ProviderJuryChainError(
                        "confirmed retryJury differs from the pending assignment"
                    )
            elif refreshed["status"] != "finalized":
                raise ProviderJuryChainError(
                    "confirmed retryJury did not create a pending assignment"
                )
            return refreshed
        if event.get("event") != "JuryUnavailable":
            raise ProviderJuryChainError("retryJury emitted an unknown outcome")
        if (event.get("independent_candidate_count", self.config.jury_size)
                >= self.config.jury_size):
            raise ProviderJuryChainError(
                "JuryUnavailable reported enough independent candidates"
            )
        if (refreshed["status"] != "failed"
                or refreshed.get("roster_version") != event.get("roster_version")
                or refreshed.get("seed") != ZERO_BYTES32):
            raise ProviderJuryChainError(
                "confirmed retryJury unavailability differs from Registry state"
            )
        return refreshed

    def retry_assignment(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        """Explicitly retry a failed Registry draw without finalizing it.

        The method is an at-most-once maintenance transaction. It can recover
        an earlier send from the durable outbox, but it never calls
        ``finalizeJury`` and never constructs or broadcasts a Settlement vote.
        """
        current = self._read_assignment(binding, resolve=False)
        key = _hash(binding.get("settlement_key"), "settlement key")
        if current["status"] in {"pending", "finalized"}:
            prior = self.outbox.latest_for_case(
                scope=self._scope, sender=self.sender, action="retry_jury",
                settlement_key=key,
            )
            if prior is None or prior["state"] in self.outbox.TERMINAL:
                # A permissionless external maintainer may have retried it.
                return self._read_assignment(binding, resolve=True)
            action = self.outbox.action(prior["action_hash"])
            observation = self._inspect_action(action, prior)
            if observation["status"] != "confirmed":
                raise ProviderJuryChainError(
                    "retryJury transaction is pending or uncertain; do not broadcast another nonce"
                )
            return self._confirmed_retry_result(binding, action, observation)
        if current["status"] != "failed":
            raise ProviderJuryChainError("jury assignment is not failed and retryable")

        tag = {"blockHash": current["block_hash"], "requireCanonical": True}
        roster_version = self._one_uint(
            self.config.jury_registry, "rosterVersion()", tag, bits=64,
        )
        action = self._retry_action(
            current, registry_roster_version=roster_version,
        )
        row = self.outbox.get(action["action_hash"])
        if row is None:
            simulated = self._call(
                self.config.jury_registry, "retryJury(bytes32)", [key], tag,
                sender=self.sender,
            )
            if len(simulated) != 32 or int.from_bytes(simulated, "big") not in (0, 1):
                raise ProviderJuryChainError("retryJury preflight returned malformed data")
            self._assert_context_canonical(current)
            row = self._submit(action)
        observation = self._inspect_action(action, row)
        if observation["status"] != "confirmed":
            raise ProviderJuryChainError(
                "retryJury transaction is pending or uncertain; do not broadcast another nonce"
            )
        return self._confirmed_retry_result(binding, action, observation)

    def _settlement_snapshot(self, settlement_key: str, tag: Any) -> dict[str, Any]:
        words = self._call_words(
            self.config.settlement_contract, "settlementInfo(bytes32)",
            [settlement_key], 20, tag,
        )
        addresses = [_address_word(word, "settlement party") for word in words[:8]]
        names = ("owner", "key", "provider", "provider_signer", "relay",
                 "relay_signer", "pool", "treasury")
        result = dict(zip(names, addresses))
        result.update(zip(("request_id", "request_hash", "authorization_hash", "response_hash"),
                          ("0x" + word.hex() for word in words[8:12])))
        result.update(zip(("gross_fee", "provider_amount", "relay_amount", "pool_amount",
                           "treasury_amount", "settled_at", "release_at", "status"),
                          (int.from_bytes(word, "big") for word in words[12:])))
        if (any(result[name] == chain.ZERO_ADDRESS for name in (
                "owner", "key", "provider", "provider_signer", "relay",
                "relay_signer", "treasury"))
                or result["status"] > 7 or result["gross_fee"] <= 0):
            raise ProviderJuryChainError("settlement snapshot is structurally invalid")
        return result

    def _dispute_snapshot(self, settlement_key: str, tag: Any) -> dict[str, Any]:
        words = self._call_words(
            self.config.settlement_contract, "disputeInfo(bytes32)",
            [settlement_key], 8, tag,
        )
        return {
            "opened_at": _uint_word(words[0], "dispute opened_at", bits=64),
            "resolve_at": _uint_word(words[1], "dispute resolve_at", bits=64),
            "dismiss_votes": _uint_word(words[2], "dispute dismiss votes", bits=16),
            "report_count": _uint_word(words[3], "dispute report count"),
            "total_bond": _uint_word(words[4], "dispute total bond"),
            "winning_report_id": "0x" + words[5].hex(),
            "slash_amount": _uint_word(words[6], "dispute slash amount"),
            "stable_bounty": _uint_word(words[7], "dispute stable bounty"),
        }

    def _vote_action(self, plan: Mapping[str, Any]) -> tuple[Mapping[str, Any], str, str, dict[str, Any]]:
        body = {name: value for name, value in plan.items() if name != "plan_hash"}
        if evidence_hash(body) != plan.get("plan_hash"):
            raise ProviderJuryChainError("jury worker plan hash is invalid")
        vote = plan.get("evm_vote")
        if not isinstance(vote, Mapping):
            raise ProviderJuryChainError("jury worker plan has no EVM vote")
        confirmed = vote.get("confirmed")
        if (plan.get("automatic_execution_allowed") is not True
                or type(confirmed) is not bool):
            raise ProviderJuryChainError("jury plan is not automatically executable")
        plan_hash = _hash(plan.get("plan_hash"), "jury worker plan hash")
        key = _hash(vote.get("settlement_key"), "settlement key")
        if (vote.get("chain_id") != self.config.chain_id
                or vote.get("settlement_contract") != self.config.settlement_contract
                or vote.get("to") != self.config.settlement_contract
                or vote.get("value") != "0x0"):
            raise ProviderJuryChainError("jury vote targets another deployment")
        permits = vote.get("vote_permits")
        votes = vote.get("votes")
        if (not isinstance(permits, list) or not isinstance(votes, list)
                or len(permits) != self.config.adjudication_threshold
                or len(votes) != len(permits)):
            raise ProviderJuryChainError("jury vote does not contain the exact threshold")
        report_id = _hash(vote.get("report_id"), "jury vote report id", nonzero=confirmed)
        if not confirmed and report_id != ZERO_BYTES32:
            raise ProviderJuryChainError("dismissal jury vote must use the zero report id")
        decision_hash = _hash(vote.get("decision_hash"), "jury vote decision hash")
        calldata = chain_v10.encode_dispute_vote_by_sig(key, permits)
        if calldata != vote.get("data"):
            raise ProviderJuryChainError("jury vote calldata differs from its signed permits")
        expected_votes = [{
            "judge": permit.get("judge"), "nonce": permit.get("nonce"),
            "deadline": permit.get("deadline"), "signature": permit.get("signature"),
        } for permit in permits if isinstance(permit, Mapping)]
        if len(expected_votes) != len(permits) or votes != expected_votes:
            raise ProviderJuryChainError("jury event plan differs from its signed permits")
        base_action = self._action(
            action="vote_dispute_by_sig", target=self.config.settlement_contract,
            calldata=calldata, settlement_key=key, source_plan_hash=plan_hash,
        )
        action_body = {
            name: value for name, value in base_action.items() if name != "action_hash"
        }
        action_body.update({
            "vote_confirmed": confirmed,
            "vote_report_id": report_id,
            "vote_decision_hash": decision_hash,
            "vote_judges": [
                _address(vote["judge"], "planned adjudicator")
                for vote in expected_votes
            ],
        })
        action = {**action_body, "action_hash": evidence_hash(action_body)}
        return vote, key, calldata, action

    def _preflight_vote(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        vote, key, calldata, action = self._vote_action(plan)
        permits = vote["vote_permits"]
        binding = {
            "schema": "mycomesh.v10.provider-jury-case.v1",
            "network_id": self.config.network_id, "chain_id": self.config.chain_id,
            "settlement_contract": self.config.settlement_contract,
            "jury_registry": self.config.jury_registry, "settlement_key": key,
        }
        assignment = self._read_assignment(binding, resolve=False)
        if assignment["status"] != "finalized" or assignment["assignment_hash"] != vote.get("assignment_hash"):
            raise ProviderJuryChainError("jury vote differs from the finalized assignment")
        saved_assignment = plan.get("assignment")
        if (not isinstance(saved_assignment, Mapping)
                or saved_assignment.get("assignment_hash") != assignment["assignment_hash"]):
            raise ProviderJuryChainError("jury worker plan lost its assignment binding")
        saved_providers = saved_assignment.get("selected_providers")
        if not isinstance(saved_providers, list) or len(saved_providers) != self.config.jury_size:
            raise ProviderJuryChainError("jury worker plan lost its selected Provider snapshot")
        for saved, observed in zip(saved_providers, assignment["selected_providers"]):
            if (not isinstance(saved, Mapping)
                    or any(saved.get(name) != value for name, value in observed.items())):
                raise ProviderJuryChainError(
                    "jury worker Provider snapshot differs from the Registry assignment"
                )
        context = self.confirmed_context()
        tag, timestamp = context["block_tag"], context["timestamp"]
        latest_assignment = "0x" + self._call_words(
            self.config.jury_registry, "assignmentHash(bytes32)", [key], 1, tag,
        )[0].hex()
        if latest_assignment != assignment["assignment_hash"]:
            raise ProviderJuryChainError("jury assignment changed across pinned snapshots")
        record = self._settlement_snapshot(key, tag)
        dispute = self._dispute_snapshot(key, tag)
        if (record["status"] != 2 or not record["release_at"] <= timestamp < dispute["resolve_at"]):
            raise ProviderJuryChainError("settlement is outside the adjudication window")
        evidence = plan.get("evidence")
        if (not isinstance(evidence, Mapping)
                or evidence.get("request_hash") != record["request_hash"]
                or evidence.get("response_hash") != record["response_hash"]):
            raise ProviderJuryChainError("jury evidence differs from the settled request and response")
        confirmed = vote.get("confirmed")
        report_id = vote.get("report_id")
        if type(confirmed) is not bool:
            raise ProviderJuryChainError("jury outcome must be a boolean")
        evidence_report_id = _hash(evidence.get("report_id"), "evidence report id")
        report = self._call_words(
            self.config.settlement_contract, "reports(bytes32,bytes32)",
            [key, evidence_report_id], 3, tag,
        )
        if (_address_word(report[0], "reporter") != record["owner"]
                or "0x" + report[1].hex() != evidence.get("evidence_hash")):
            raise ProviderJuryChainError(
                "owner jury report is absent or has another evidence commitment"
            )
        if confirmed:
            if report_id != evidence_report_id:
                raise ProviderJuryChainError("confirming jury vote targets another evidence report")
        elif report_id != ZERO_BYTES32:
            raise ProviderJuryChainError("dismissal jury vote must use the zero report id")
        assigned = {item["vote_signer"]: item for item in assignment["selected_providers"]}
        seen: set[str] = set()
        for permit in permits:
            checked = chain_v10.verify_dispute_vote(
                permit, expected_settlement_key=key,
                expected_assignment_hash=assignment["assignment_hash"],
                expected_chain_id=self.config.chain_id,
                expected_contract=self.config.settlement_contract, now=timestamp,
            )
            judge = checked["judge"]
            if (judge in seen or judge not in assigned
                    or checked["confirmed"] != confirmed
                    or checked["report_id"] != report_id
                    or checked["decision_hash"] != vote.get("decision_hash")):
                raise ProviderJuryChainError("jury permit is not an exact selected quorum vote")
            seen.add(judge)
            nonce = int.from_bytes(self._call_words(
                self.config.settlement_contract, "adjudicatorNonce(bytes32,address)",
                [key, judge], 1, tag,
            )[0], "big")
            prior_vote = int.from_bytes(self._call_words(
                self.config.settlement_contract, "disputeVotes(bytes32,address)",
                [key, judge], 1, tag,
            )[0], "big")
            # V10 has exactly one owner-submitted report. Registry assignment
            # plus Settlement's independent-party check excludes that owner,
            # so there is no separate public hasReported signer gate.
            if checked["nonce"] != nonce or prior_vote != 0:
                raise ProviderJuryChainError("jury permit nonce or on-chain eligibility changed")
        forbidden = set(record[name] for name in (
            "owner", "key", "provider", "provider_signer", "relay", "relay_signer",
            "pool", "treasury",
        )) | {self.config.jury_registry_governance, self.config.reputation_authority,
              self.config.bond_penalty_recipient}
        if self.sender in forbidden or self.sender in assigned:
            raise ProviderJuryChainError("dedicated jury submitter is reused by a case party or juror")
        # A hash-pinned simulation is required immediately before allocating a
        # sender nonce.  eth_estimateGas later checks the latest state as well.
        simulated = self._rpc("eth_call", [{
            "from": self.sender, "to": self.config.settlement_contract,
            "value": "0x0", "data": calldata,
        }, tag])
        if simulated != "0x":
            raise ProviderJuryChainError("voteDisputeBySig simulation returned unexpected data")
        return action

    def broadcast(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        """At-most-once worker callback for ``voteDisputeBySig``."""
        try:
            action = self._preflight_vote(plan)
        except ProviderJuryChainError as exc:
            raise ProviderJuryDefinitelyNotSentError(
                "jury vote failed its final preflight before transaction creation"
            ) from exc
        try:
            row = self._submit(action)
        except ProviderJuryChainError as exc:
            # Before reserve(), no signed transaction identity exists and no
            # send call is reachable. The worker may safely remain admitted.
            if self.outbox.get(action["action_hash"]) is None:
                raise ProviderJuryDefinitelyNotSentError(
                    "jury transaction was definitely not created or sent"
                ) from exc
            raise
        result = self._transaction_identity(row)
        # The worker's immutable plan hash is distinct from this adapter's
        # chain-action hash.  Persist the former in its result schema.
        result["plan_hash"] = plan["plan_hash"]
        return result

    def preflight(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        """Read-only validation to run before the worker acquires its send lease."""
        return self._preflight_vote(plan)

    def _rpc_transaction(self, row: Mapping[str, Any]) -> Mapping[str, Any] | None:
        transaction = self._rpc("eth_getTransactionByHash", [row["tx_hash"]])
        if transaction is None:
            return None
        if not isinstance(transaction, Mapping):
            raise ProviderJuryChainError("RPC returned a malformed jury transaction")
        data = transaction.get("input", transaction.get("data"))
        if (_hash(str(transaction.get("hash") or ""), "transaction hash") != row["tx_hash"]
                or _address(str(transaction.get("from") or ""), "transaction sender") != row["sender"]
                or _address(str(transaction.get("to") or ""), "transaction target") != row["target"]
                or _hex_uint(transaction.get("nonce"), "transaction nonce") != row["nonce"]
                or _hex_uint(transaction.get("value"), "transaction value") != 0
                or data != row["calldata"]):
            raise ProviderJuryChainError("on-chain jury transaction identity differs from the outbox")
        chain_id = transaction.get("chainId")
        if chain_id is not None and _hex_uint(chain_id, "transaction chain id") != self.config.chain_id:
            raise ProviderJuryChainError("on-chain jury transaction has another chain id")
        return transaction

    @staticmethod
    def _log_identity(log: Mapping[str, Any], *, receipt: Mapping[str, Any],
                      address_value: str) -> None:
        if (log.get("removed") not in (None, False)
                or _address(str(log.get("address") or ""), "log address") != address_value
                or _hash(str(log.get("transactionHash") or ""), "log transaction hash")
                != receipt["transaction_hash"]
                or _hash(str(log.get("blockHash") or ""), "log block hash")
                != receipt["block_hash"]
                or _hex_uint(log.get("blockNumber"), "log block number")
                != receipt["block_number"]):
            raise ProviderJuryChainError("jury event is not bound to its canonical receipt")
        _hex_uint(log.get("logIndex"), "log index")

    def _vote_events(self, logs: list[Any], *, receipt: Mapping[str, Any],
                     action: Mapping[str, Any]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for log in logs:
            if not isinstance(log, Mapping):
                raise ProviderJuryChainError("receipt contains a malformed event")
            topics = log.get("topics")
            if not isinstance(topics, list) or not topics or topics[0] != DISPUTE_VOTE_TOPIC:
                continue
            self._log_identity(log, receipt=receipt,
                               address_value=self.config.settlement_contract)
            if len(topics) != 3:
                raise ProviderJuryChainError("DisputeVote has malformed indexed topics")
            data = _raw_result(log.get("data"), "DisputeVote")
            if len(data) != 96 or int.from_bytes(data[:32], "big") not in (0, 1):
                raise ProviderJuryChainError("DisputeVote has malformed event data")
            result.append({
                "event": "DisputeVote", "address": self.config.settlement_contract,
                "adjudicator": _address_word(bytes.fromhex(_hash(topics[2], "adjudicator topic")[2:]),
                                             "event adjudicator"),
                "transaction_hash": receipt["transaction_hash"],
                "block_hash": receipt["block_hash"], "block_number": receipt["block_number"],
                "log_index": _hex_uint(log.get("logIndex"), "log index"), "removed": False,
                "settlement_key": _hash(topics[1], "event settlement key"),
                "confirmed": bool(int.from_bytes(data[:32], "big")),
                "report_id": "0x" + data[32:64].hex(),
                "decision_hash": "0x" + data[64:96].hex(),
            })
        if not result:
            raise ProviderJuryChainError("confirmed jury vote transaction emitted no DisputeVote events")
        expected_judges = action.get("vote_judges")
        expected_confirmed = action.get("vote_confirmed")
        expected_report = action.get("vote_report_id")
        expected_decision = action.get("vote_decision_hash")
        if (not isinstance(expected_judges, list)
                or len(expected_judges) != self.config.adjudication_threshold
                or type(expected_confirmed) is not bool
                or len(result) != len(expected_judges)):
            raise ProviderJuryChainError("durable jury action lost its exact vote quorum")
        expected = {
            (_address(judge, "planned adjudicator"), action["settlement_key"],
             expected_confirmed, expected_report, expected_decision)
            for judge in expected_judges
        }
        observed = {
            (event["adjudicator"], event["settlement_key"], event["confirmed"],
             event["report_id"], event["decision_hash"])
            for event in result
        }
        if len(expected) != len(expected_judges) or observed != expected:
            raise ProviderJuryChainError(
                "DisputeVote events differ from the durable selected quorum"
            )
        return result

    def _resolution_event(
        self, logs: list[Any], *, receipt: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return the one terminal resolution emitted by an atomic vote batch."""
        matching: list[dict[str, Any]] = []
        for log in logs:
            if not isinstance(log, Mapping):
                raise ProviderJuryChainError("receipt contains a malformed event")
            topics = log.get("topics")
            if not isinstance(topics, list) or not topics or topics[0] != DISPUTE_RESOLVED_TOPIC:
                continue
            self._log_identity(
                log, receipt=receipt, address_value=self.config.settlement_contract,
            )
            if (len(topics) != 2
                    or _hash(topics[1], "resolved settlement key")
                    != action["settlement_key"]):
                raise ProviderJuryChainError("DisputeResolved targets another case")
            data = _raw_result(log.get("data"), "DisputeResolved")
            if len(data) != 96:
                raise ProviderJuryChainError("DisputeResolved has malformed event data")
            status = _uint_word(data[:32], "resolved status", bits=8)
            slash_amount = _uint_word(data[32:64], "resolved slash amount")
            stable_bounty = _uint_word(data[64:96], "resolved stable bounty")
            matching.append({
                "event": "DisputeResolved",
                "address": self.config.settlement_contract,
                "transaction_hash": receipt["transaction_hash"],
                "block_hash": receipt["block_hash"],
                "block_number": receipt["block_number"],
                "log_index": _hex_uint(log.get("logIndex"), "log index"),
                "removed": False,
                "settlement_key": action["settlement_key"],
                "status": status,
                "slash_amount": slash_amount,
                "stable_bounty": stable_bounty,
            })
        if len(matching) != 1:
            raise ProviderJuryChainError(
                "voteDisputeBySig receipt must contain one DisputeResolved event"
            )
        expected_status = 4 if action.get("vote_confirmed") is True else 5
        event = matching[0]
        if event["status"] != expected_status:
            raise ProviderJuryChainError("DisputeResolved has the wrong jury outcome")
        if expected_status == 5 and (
            event["slash_amount"] != 0 or event["stable_bounty"] != 0
        ):
            raise ProviderJuryChainError(
                "dismissal resolution unexpectedly slashed stake or paid a bounty"
            )
        return event

    def _finalize_event(self, logs: list[Any], *, receipt: Mapping[str, Any],
                        action: Mapping[str, Any]) -> dict[str, Any]:
        matching: list[dict[str, Any]] = []
        for log in logs:
            if not isinstance(log, Mapping):
                raise ProviderJuryChainError("receipt contains a malformed event")
            topics = log.get("topics")
            if not isinstance(topics, list) or not topics or topics[0] not in {
                    JURY_ASSIGNED_TOPIC, JURY_FAILED_TOPIC}:
                continue
            self._log_identity(log, receipt=receipt,
                               address_value=self.config.jury_registry)
            if topics[0] == JURY_FAILED_TOPIC:
                if len(topics) != 2 or _hash(topics[1], "failed case id") != action["settlement_key"]:
                    raise ProviderJuryChainError("JuryAssignmentFailed targets another case")
                data = _raw_result(log.get("data"), "JuryAssignmentFailed")
                if len(data) != 32:
                    raise ProviderJuryChainError("JuryAssignmentFailed has malformed data")
                matching.append({"event": "JuryAssignmentFailed", "seed": "0x" + data.hex()})
                continue
            if (len(topics) != 3
                    or _hash(topics[1], "assigned case id") != action["settlement_key"]):
                raise ProviderJuryChainError("JuryAssigned targets another case")
            data = _raw_result(log.get("data"), "JuryAssigned")
            if len(data) < 128:
                raise ProviderJuryChainError("JuryAssigned has truncated data")
            offsets = [int.from_bytes(data[index * 32:(index + 1) * 32], "big")
                       for index in (1, 2, 3)]
            arrays = _strict_arrays(data, head_words=4, offsets=offsets,
                                    lengths_limit=7, label="JuryAssigned")
            matching.append({
                "event": "JuryAssigned", "assignment_hash": _hash(
                    topics[2], "assigned assignment hash"),
                "seed": "0x" + data[:32].hex(),
                "owners": [_address_word(word, "event owner") for word in arrays[0]],
                "vote_signers": [_address_word(word, "event signer") for word in arrays[1]],
                "operator_id_hashes": ["0x" + word.hex() for word in arrays[2]],
            })
        if len(matching) != 1:
            raise ProviderJuryChainError("finalizeJury receipt must contain one terminal assignment event")
        return matching[0]

    def _inspect_action(self, action: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
        if (row.get("action_hash") != action.get("action_hash")
                or row.get("target") != action.get("target")
                or row.get("calldata") != action.get("calldata")):
            raise ProviderJuryChainError("jury action differs from its durable transaction")
        if (_hex_uint(self._rpc("eth_chainId", []), "chain id") != self.config.chain_id
                or _hash(self._rpc("eth_getBlockByNumber", ["0x0", False])["hash"],
                         "genesis hash") != self.config.genesis_hash):
            raise ProviderJuryChainError("jury reconciliation network mismatch")
        transaction = self._rpc_transaction(row)
        raw_receipt = self._rpc("eth_getTransactionReceipt", [row["tx_hash"]])
        if raw_receipt is None:
            # The exact identity remains durable even when an RPC cannot find
            # it.  No automatic rebroadcast is permitted.
            if transaction is None:
                self.outbox.mark(action["action_hash"], "uncertain")
                raise ProviderJuryChainError(
                    "jury transaction is not observable; retain its original hash without resending"
                )
            self.outbox.mark(action["action_hash"], "submitted")
            return self._transaction_identity(row)
        if not isinstance(raw_receipt, Mapping):
            raise ProviderJuryChainError("RPC returned a malformed jury receipt")
        tx_hash = _hash(str(raw_receipt.get("transactionHash") or ""), "receipt transaction hash")
        block_hash = _hash(str(raw_receipt.get("blockHash") or ""), "receipt block hash")
        block_number = _hex_uint(raw_receipt.get("blockNumber"), "receipt block number")
        status = _hex_uint(raw_receipt.get("status"), "receipt status", bits=8)
        sender = _address(str(raw_receipt.get("from") or ""), "receipt sender")
        target = _address(str(raw_receipt.get("to") or ""), "receipt target")
        if (tx_hash != row["tx_hash"] or sender != row["sender"] or target != row["target"]
                or status not in (0, 1)):
            raise ProviderJuryChainError("jury receipt differs from its durable transaction")
        canonical = self._rpc("eth_getBlockByNumber", [hex(block_number), False])
        head = _hex_uint(self._rpc("eth_blockNumber", []), "head block")
        if (not isinstance(canonical, Mapping)
                or str(canonical.get("hash") or "").lower() != block_hash
                or _hex_uint(canonical.get("number"), "canonical block number") != block_number):
            self.outbox.mark(action["action_hash"], "uncertain", receipt=raw_receipt)
            raise ProviderJuryChainError(
                "jury receipt block is noncanonical; retain the original transaction identity"
            )
        confirmations = head - block_number + 1
        if head < block_number:
            raise ProviderJuryChainError("jury receipt block is ahead of the RPC head")
        if confirmations < self.config.confirmations:
            self.outbox.mark(action["action_hash"], "submitted", receipt=raw_receipt)
            return self._transaction_identity(row)
        if transaction is None:
            raise ProviderJuryChainError("confirmed receipt has no matching transaction body")
        if (_hex_uint(transaction.get("blockNumber"), "transaction block number") != block_number
                or _hash(str(transaction.get("blockHash") or ""), "transaction block hash")
                != block_hash):
            raise ProviderJuryChainError("jury transaction body differs from its receipt block")
        if status == 0:
            self.outbox.mark(action["action_hash"], "reverted", receipt=raw_receipt)
            raise ProviderJuryChainError("jury transaction reverted and must not be resent")
        normalized_receipt = {
            "transaction_hash": tx_hash, "block_number": block_number,
            "block_hash": block_hash, "status": 1, "from": sender, "to": target,
        }
        logs = raw_receipt.get("logs")
        if not isinstance(logs, list):
            raise ProviderJuryChainError("confirmed jury receipt has no canonical logs")
        result = {**self._transaction_identity(row), "status": "confirmed",
                  "confirmations": confirmations, "receipt": normalized_receipt}
        if action["action"] == "vote_dispute_by_sig":
            result["vote_events"] = self._vote_events(
                logs, receipt=normalized_receipt, action=action,
            )
            resolution = self._resolution_event(
                logs, receipt=normalized_receipt, action=action,
            )
            receipt_tag = {"blockHash": block_hash, "requireCanonical": True}
            settlement = self._settlement_snapshot(
                action["settlement_key"], receipt_tag,
            )
            dispute = self._dispute_snapshot(action["settlement_key"], receipt_tag)
            expected_status = 4 if action["vote_confirmed"] else 5
            if (settlement["status"] != expected_status
                    or resolution["status"] != expected_status
                    or resolution["slash_amount"] != dispute["slash_amount"]
                    or resolution["stable_bounty"] != dispute["stable_bounty"]):
                raise ProviderJuryChainError(
                    "confirmed jury transaction did not reach its exact terminal state"
                )
            if action["vote_confirmed"]:
                if dispute["winning_report_id"] != action["vote_report_id"]:
                    raise ProviderJuryChainError(
                        "confirmed jury state selected another evidence report"
                    )
                bond_forfeited = False
            else:
                # V10 is owner-only and has exactly one bonded report. In the
                # release-pinned runtime, Dismissed atomically releases the fee,
                # removes this positive total_bond from totalReporterBonds, and
                # credits it to bondPenaltyRecipient. These state constraints
                # prove that exact forfeiture branch, rather than a bare vote.
                if (dispute["dismiss_votes"] < self.config.adjudication_threshold
                        or dispute["report_count"] != 1
                        or dispute["total_bond"] <= 0
                        or dispute["winning_report_id"] != ZERO_BYTES32
                        or dispute["slash_amount"] != 0
                        or dispute["stable_bounty"] != 0):
                    raise ProviderJuryChainError(
                        "dismissed jury state does not prove report-bond forfeiture"
                    )
                bond_forfeited = True
            result["resolution_event"] = resolution
            result["settlement_outcome"] = {
                "status": "confirmed" if expected_status == 4 else "dismissed",
                "status_code": expected_status,
                "winning_report_id": dispute["winning_report_id"],
                "dismiss_votes": dispute["dismiss_votes"],
                "report_count": dispute["report_count"],
                "total_bond": dispute["total_bond"],
                "slash_amount": dispute["slash_amount"],
                "stable_bounty": dispute["stable_bounty"],
                "report_bond_forfeited": bond_forfeited,
            }
        elif action["action"] in {"finalize_jury", "expire_jury"}:
            result["assignment_event"] = self._finalize_event(
                logs, receipt=normalized_receipt, action=action,
            )
        elif action["action"] == "retry_jury":
            result["assignment_event"] = self._retry_event(
                logs, receipt=normalized_receipt, action=action,
            )
        else:
            raise ProviderJuryChainError("unknown durable jury chain action")
        boundary = self._rpc("eth_getBlockByNumber", [hex(block_number), False])
        if (not isinstance(boundary, Mapping)
                or str(boundary.get("hash") or "").lower() != block_hash
                or _hex_uint(boundary.get("number"), "boundary block number") != block_number):
            self.outbox.mark(action["action_hash"], "uncertain", receipt=raw_receipt)
            raise ProviderJuryChainError(
                "jury receipt block reorganized during event verification"
            )
        self.outbox.mark(action["action_hash"], "confirmed", receipt=raw_receipt)
        return result

    def inspect(self, plan: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
        """Worker callback that only observes the original durable vote hash."""
        _vote, _key, _calldata, action = self._vote_action(plan)
        row = self.outbox.get(action["action_hash"])
        if row is None:
            existing = current.get("result") if isinstance(current, Mapping) else None
            if not isinstance(existing, Mapping):
                raise ProviderJuryChainError("uncertain jury execution has no durable transaction identity")
            raise ProviderJuryChainError(
                "worker transaction identity is absent from the dedicated jury outbox"
            )
        try:
            result = self._inspect_action(action, row)
        except ProviderJuryChainError:
            refreshed = self.outbox.get(action["action_hash"])
            if refreshed is None or refreshed.get("state") != "uncertain":
                raise
            result = self._transaction_identity(refreshed)
            result["status"] = "uncertain"
        result["plan_hash"] = plan["plan_hash"]
        return result

    def broadcast_recorded(self, plan: Mapping[str, Any]) -> bool:
        """Prove whether this adapter durably reserved the plan's send action."""
        _vote, _key, _calldata, action = self._vote_action(plan)
        return self.outbox.get(action["action_hash"]) is not None


__all__ = [
    "ASSIGNMENT_SCHEMA", "CHAIN_STORAGE_HEALTH_SCHEMA", "ProviderJuryChainAdapter", "ProviderJuryChainConfig",
    "ProviderJuryChainError", "ProviderJuryDefinitelyNotSentError",
    "JuryTransactionOutbox", "assignment_hash", "JURY_REQUESTED_TOPIC",
    "JURY_UNAVAILABLE_TOPIC",
]
