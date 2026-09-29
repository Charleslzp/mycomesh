#!/usr/bin/env python3
"""Capture quorum-agreed V10 deployment/runtime evidence from pinned RPCs.

The output is evidence for ``scripts/release_gate.py --strict-artifacts``.  It
does not sign or deploy anything.  At least two RPC endpoints must agree on the
chain, deployment receipt, canonical block, block-hash-pinned runtime code,
contract configuration and currently usable capacity channels.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from gateway import chain


SCHEMA = "mycomesh.deployed-code.v4"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
JURY_RELAY_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
DNS_NAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_RUNTIME_BYTES = 128 * 1024
DYNAMIC_JURY_MODE = "dynamic_provider_ai_v1"
DYNAMIC_JURY_FORBIDDEN_FIELDS = frozenset({
    "adjudicators",
    "adjudicator_operators",
    "independence_attested",
    "jury_provider_evidence",
})
MAX_DYNAMIC_PROVIDERS = 64
ZERO_HASH = "0x" + "0" * 64
ZERO_ADDRESS = "0x" + "0" * 40
JURY_TRANSACTION_GAS_CAP_FIELD = "jury_transaction_max_total_gas_cost_wei"
REPUTATION_HISTORY_FIELD = "reputation_history_import"
REPUTATION_HISTORY_SCHEMA = "mycomesh.v10.reputation-history-import.v1"
REPUTATION_HISTORY_FIELDS = {
    "schema", "source_network_id", "source_protocol_version",
    "source_chain_id", "source_genesis_hash", "source_settlement_contract",
    "source_runtime_code_hash", "source_deployment_block",
    "source_deployment_block_hash", "source_history_through_block",
    "source_history_through_block_hash", "confirmations",
    "artifact_sha256", "artifact_root",
}
DYNAMIC_DEPLOYMENT_BOUNDARY_FIELDS = (
    "deployment_block", "deployment_block_hash",
    "settlement_runtime_code_keccak256",
)
EMPTY_CODE_KECCAK256 = "0x" + chain.keccak256(b"").hex()


class EvidenceError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("deployment manifest must be a regular file")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise EvidenceError("deployment manifest exceeds 2 MiB")
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise EvidenceError("deployment manifest exceeds 2 MiB")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                EvidenceError(f"invalid JSON constant: {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("deployment manifest is not strict JSON") from exc
    if not isinstance(value, dict) or value.get("protocol_version") != 10:
        raise EvidenceError("deployment manifest must describe protocol V10")
    return value, raw


def _canonical_rpc_url(value: str) -> str:
    if (not isinstance(value, str) or not value or value != value.strip()
            or "," in value or any(ord(character) < 0x20 for character in value)):
        raise EvidenceError("release evidence RPC endpoints must be credential-free HTTPS URLs")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise EvidenceError(
            "release evidence RPC endpoints must be credential-free HTTPS URLs"
        ) from exc
    hostname = parsed.hostname
    if (parsed.scheme != "https" or not hostname or parsed.username or parsed.password
            or parsed.fragment or port == 0):
        raise EvidenceError("release evidence RPC endpoints must be credential-free HTTPS URLs")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if DNS_NAME_RE.fullmatch(hostname) is None:
            raise EvidenceError(
                "release evidence RPC endpoints must use a valid DNS name or IP address"
            ) from None
    return value


def _rpc_origin(value: str) -> tuple[str, int]:
    """Return the network origin used to enforce a minimally independent quorum."""
    parsed = urlsplit(value)
    return parsed.hostname or "", parsed.port or 443


def _rpc_hex_int(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value):
        raise EvidenceError(f"RPC returned an invalid {label}")
    return int(value, 16)


def _hash(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise EvidenceError(f"RPC returned an invalid {label}") from exc
    if normalized != value:
        raise EvidenceError(f"RPC returned a noncanonical {label}")
    return normalized


def _address(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise EvidenceError(f"RPC returned an invalid {label}") from exc
    if normalized != value or normalized == chain.ZERO_ADDRESS:
        raise EvidenceError(f"RPC returned a noncanonical {label}")
    return normalized


def _runtime(value: Any) -> tuple[str, bytes]:
    if (not isinstance(value, str) or not value.startswith("0x") or len(value) <= 2
            or len(value) % 2 or not re.fullmatch(r"0x[0-9a-f]+", value)):
        raise EvidenceError("RPC returned invalid deployed runtime code")
    raw = bytes.fromhex(value[2:])
    if not raw or not any(raw):
        raise EvidenceError("deployed runtime code is empty")
    if len(raw) > MAX_RUNTIME_BYTES:
        raise EvidenceError("deployed runtime code exceeds 128 KiB")
    return value, raw


def _manifest_address(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise EvidenceError(f"deployment manifest has an invalid {label}") from exc
    if normalized != value or (nonzero and normalized == chain.ZERO_ADDRESS):
        raise EvidenceError(f"deployment manifest has a noncanonical {label}")
    return normalized


def _known_role_addresses(*values: Any) -> set[str]:
    """Collect every manifest/state EVM role while excluding the sender map itself."""
    result: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key != "jury_transaction_senders":
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif (
            isinstance(value, str)
            and ADDRESS_RE.fullmatch(value) is not None
            and value != ZERO_ADDRESS
        ):
            result.add(value)

    for value in values:
        visit(value)
    return result


def _jury_sender_config(
    manifest: dict[str, Any], network_manifest: dict[str, Any],
) -> tuple[list[str], dict[str, str], int]:
    """Validate the public sender map and its maximum per-transaction funding cap."""
    relay_keys = network_manifest.get("jury_relay_public_keys")
    if (
        not isinstance(relay_keys, list)
        or not 1 <= len(relay_keys) <= 4
        or any(
            not isinstance(key, str)
            or JURY_RELAY_PUBLIC_KEY_RE.fullmatch(key) is None
            for key in relay_keys
        )
        or len(set(relay_keys)) != len(relay_keys)
    ):
        raise EvidenceError(
            "dynamic Provider jury network requires 1 to 4 unique lowercase Ed25519 Relay public keys"
        )
    raw_senders = network_manifest.get("jury_transaction_senders")
    if not isinstance(raw_senders, dict):
        raise EvidenceError(
            "dynamic Provider jury network requires jury_transaction_senders object"
        )
    if set(raw_senders) != set(relay_keys):
        raise EvidenceError(
            "jury transaction sender keys must exactly match jury Relay public keys"
        )
    senders: dict[str, str] = {}
    for key in relay_keys:
        raw_sender = raw_senders.get(key)
        sender = _manifest_address(raw_sender, "jury transaction sender")
        if raw_sender != sender:
            raise EvidenceError("jury transaction sender must be a canonical lowercase address")
        senders[key] = sender
    if len(set(senders.values())) != len(senders):
        raise EvidenceError("jury transaction senders must be unique")
    cap = network_manifest.get(JURY_TRANSACTION_GAS_CAP_FIELD)
    if type(cap) is not int or not 0 < cap < 2**256:
        raise EvidenceError(
            f"{JURY_TRANSACTION_GAS_CAP_FIELD} must be a positive uint256"
        )
    conflicts = sorted(set(senders.values()) & _known_role_addresses(
        manifest, network_manifest,
    ))
    if conflicts:
        raise EvidenceError(
            f"jury transaction sender reuses a known manifest role: {conflicts}"
        )
    return relay_keys, senders, cap


def _jury_sender_evidence(
    rpc_url: str, *, senders: dict[str, str], gas_cap_wei: int,
    state_block_number: int, state_block_hash: str,
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> dict[str, Any]:
    block_tag = {"blockHash": state_block_hash, "requireCanonical": True}
    observed: dict[str, Any] = {}
    for relay_key, sender in senders.items():
        code = rpc_call(rpc_url, "eth_getCode", [sender, block_tag], timeout)
        if code != "0x":
            raise EvidenceError("jury transaction sender must be a canonical EOA with empty code")
        confirmed_nonce = _rpc_hex_int(
            rpc_call(rpc_url, "eth_getTransactionCount", [sender, block_tag], timeout),
            "jury sender confirmed nonce",
        )
        latest_nonce = _rpc_hex_int(
            rpc_call(rpc_url, "eth_getTransactionCount", [sender, "latest"], timeout),
            "jury sender latest nonce",
        )
        pending_nonce = _rpc_hex_int(
            rpc_call(rpc_url, "eth_getTransactionCount", [sender, "pending"], timeout),
            "jury sender pending nonce",
        )
        if not confirmed_nonce <= latest_nonce <= pending_nonce:
            raise EvidenceError("jury transaction sender nonces are internally inconsistent")
        balance = _rpc_hex_int(
            rpc_call(rpc_url, "eth_getBalance", [sender, block_tag], timeout),
            "jury sender balance",
        )
        if balance < gas_cap_wei:
            raise EvidenceError("jury transaction sender balance does not cover its gas cap")
        observed[relay_key] = {
            "relay_public_key": relay_key,
            "address": sender,
            "block_number": state_block_number,
            "block_hash": state_block_hash,
            "confirmed_nonce": confirmed_nonce,
            "latest_nonce": latest_nonce,
            "pending_nonce": pending_nonce,
            "pending_transaction": pending_nonce != latest_nonce,
            "balance_wei": balance,
            "code_keccak256": EMPTY_CODE_KECCAK256,
            "gas_cap_wei": gas_cap_wei,
        }
    return observed


def _reputation_history_lineage(
    value: Any, *, manifest: dict[str, Any], label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REPUTATION_HISTORY_FIELDS:
        raise EvidenceError(f"{label} must be a non-null exact lineage object")
    network_id = value.get("source_network_id")
    protocol = value.get("source_protocol_version")
    chain_id = value.get("source_chain_id")
    confirmations = value.get("confirmations")
    source_deployment_block = value.get("source_deployment_block")
    source_history_through_block = value.get("source_history_through_block")
    artifact_sha = value.get("artifact_sha256")
    if (
        value.get("schema") != REPUTATION_HISTORY_SCHEMA
        or not isinstance(network_id, str)
        or not network_id
        or network_id != network_id.strip()
        or len(network_id) > 160
        or network_id == manifest.get("network_id")
        or type(protocol) is not int
        or protocol not in {9, 10}
        or type(chain_id) is not int
        or chain_id != manifest.get("chain_id")
        or not isinstance(value.get("source_genesis_hash"), str)
        or HASH_RE.fullmatch(value["source_genesis_hash"]) is None
        or value["source_genesis_hash"] == ZERO_HASH
        or value["source_genesis_hash"] != manifest.get("genesis_hash")
        or not isinstance(value.get("source_settlement_contract"), str)
        or ADDRESS_RE.fullmatch(value["source_settlement_contract"]) is None
        or value["source_settlement_contract"] in {
            ZERO_ADDRESS, manifest.get("settlement"),
        }
        or not isinstance(value.get("source_runtime_code_hash"), str)
        or HASH_RE.fullmatch(value["source_runtime_code_hash"]) is None
        or value["source_runtime_code_hash"] == ZERO_HASH
        or type(source_deployment_block) is not int
        or source_deployment_block <= 0
        or not isinstance(value.get("source_deployment_block_hash"), str)
        or HASH_RE.fullmatch(value["source_deployment_block_hash"]) is None
        or value["source_deployment_block_hash"] == ZERO_HASH
        or type(source_history_through_block) is not int
        or source_history_through_block < source_deployment_block
        or not isinstance(value.get("source_history_through_block_hash"), str)
        or HASH_RE.fullmatch(value["source_history_through_block_hash"]) is None
        or value["source_history_through_block_hash"] == ZERO_HASH
        or type(confirmations) is not int
        or not 2 <= confirmations <= 256
        or not isinstance(artifact_sha, str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact_sha) is None
        or artifact_sha == "0" * 64
        or not isinstance(value.get("artifact_root"), str)
        or HASH_RE.fullmatch(value["artifact_root"]) is None
        or value["artifact_root"] == ZERO_HASH
    ):
        raise EvidenceError(f"{label} is invalid or not a prior same-chain deployment")
    return dict(value)


def _dynamic_deployment_boundary(
    value: dict[str, Any], *, label: str,
) -> dict[str, Any]:
    deployment_block = value.get("deployment_block")
    deployment_block_hash = value.get("deployment_block_hash")
    runtime_hash = value.get("settlement_runtime_code_keccak256")
    if (
        type(deployment_block) is not int
        or not 0 < deployment_block < 2**64
        or not isinstance(deployment_block_hash, str)
        or HASH_RE.fullmatch(deployment_block_hash) is None
        or deployment_block_hash == ZERO_HASH
        or not isinstance(runtime_hash, str)
        or HASH_RE.fullmatch(runtime_hash) is None
        or runtime_hash == ZERO_HASH
    ):
        raise EvidenceError(f"{label} dynamic Settlement deployment boundary is invalid")
    return {
        "deployment_block": deployment_block,
        "deployment_block_hash": deployment_block_hash,
        "settlement_runtime_code_keccak256": runtime_hash,
    }


def _call_bytes(
    rpc_url: str, address: str, signature: str, args: list[str], block_tag: dict[str, Any],
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> bytes:
    result = rpc_call(
        rpc_url, "eth_call",
        [{"to": address, "data": chain.encode_contract_call(signature, args)}, block_tag],
        timeout,
    )
    if (not isinstance(result, str) or not re.fullmatch(r"0x[0-9a-f]*", result)
            or len(result) % 2):
        raise EvidenceError(f"RPC returned invalid ABI data for {signature}")
    return bytes.fromhex(result[2:])


def _words(raw: bytes, signature: str, *, count: int | None = None) -> list[bytes]:
    if len(raw) % 32 or (count is not None and len(raw) != count * 32):
        raise EvidenceError(f"RPC returned an invalid ABI word count for {signature}")
    return [raw[index:index + 32] for index in range(0, len(raw), 32)]


def _word_uint(word: bytes) -> int:
    return int.from_bytes(word, "big")


def _word_bool(word: bytes, label: str) -> bool:
    value = _word_uint(word)
    if value not in {0, 1}:
        raise EvidenceError(f"RPC returned an invalid ABI boolean for {label}")
    return value == 1


def _word_address(word: bytes, label: str, *, nonzero: bool = True) -> str:
    if len(word) != 32 or any(word[:12]):
        raise EvidenceError(f"RPC returned an invalid ABI address for {label}")
    value = "0x" + word[12:].hex()
    if nonzero and value == chain.ZERO_ADDRESS:
        raise EvidenceError(f"RPC returned a zero ABI address for {label}")
    return value


def _domain_separator(manifest: dict[str, Any]) -> str:
    name, version = manifest.get("eip712_name"), manifest.get("eip712_version")
    chain_id, settlement = manifest.get("chain_id"), manifest.get("settlement")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise EvidenceError("deployment manifest is missing its EIP-712 domain")
    if type(chain_id) is not int or chain_id <= 0:
        raise EvidenceError("deployment manifest has an invalid EIP-712 chain")
    settlement = _manifest_address(settlement, "settlement")
    values = (
        chain.keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        chain.keccak256(name.encode("utf-8")),
        chain.keccak256(version.encode("utf-8")),
        chain_id.to_bytes(32, "big"),
        b"\0" * 12 + bytes.fromhex(settlement[2:]),
    )
    return "0x" + chain.keccak256(b"".join(values)).hex()


def _capacity_channel_id(
    manifest: dict[str, Any], addresses: list[str], channel_hash: str,
    pricing_hash: str, values: dict[str, int],
) -> str:
    typehash = chain.keccak256(
        b"OpenCapacityChannel(address consumerOwner,address consumerKey,address providerOwner,"
        b"address providerSigner,address relay,address relaySigner,address pool,bytes32 channel,"
        b"uint64 pricingVersion,bytes32 pricingHash,uint256 capacity,uint256 maxFeePerRequest,"
        b"uint64 validFrom,uint64 admitUntil,uint64 claimUntil,uint256 consumerNonce,"
        b"uint256 providerNonce,uint64 permitDeadline)"
    )
    words = [
        typehash,
        *(b"\0" * 12 + bytes.fromhex(address[2:]) for address in addresses),
        bytes.fromhex(channel_hash[2:]),
        values["pricing_version"].to_bytes(32, "big"),
        bytes.fromhex(pricing_hash[2:]),
        *(values[name].to_bytes(32, "big") for name in (
            "capacity", "max_fee_per_request", "valid_from", "admit_until",
            "claim_until", "consumer_nonce", "provider_nonce", "permit_deadline",
        )),
    ]
    struct_hash = chain.keccak256(b"".join(words))
    domain = bytes.fromhex(_domain_separator(manifest)[2:])
    return "0x" + chain.keccak256(b"\x19\x01" + domain + struct_hash).hex()


def _contract_state(
    rpc_url: str, *, manifest: dict[str, Any], address: str, block_tag: dict[str, Any],
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> dict[str, Any]:
    def call_words(signature: str, args: list[str] | None = None, count: int | None = None) -> list[bytes]:
        raw = _call_bytes(rpc_url, address, signature, args or [], block_tag, rpc_call, timeout)
        return _words(raw, signature, count=count)

    stablecoin = _word_address(call_words("stablecoin()", count=1)[0], "stablecoin")
    reward_token = _word_address(
        call_words("rewardToken()", count=1)[0], "reward token", nonzero=False,
    )
    threshold = _word_uint(call_words("adjudicationThreshold()", count=1)[0])
    governance = _word_address(call_words("governance()", count=1)[0], "governance")
    treasury = _word_address(call_words("treasury()", count=1)[0], "treasury")
    domain_separator = "0x" + call_words("DOMAIN_SEPARATOR()", count=1)[0].hex()
    max_channel_duration = _word_uint(call_words("MAX_CHANNEL_DURATION()", count=1)[0])
    expected_scalars = {
        "stablecoin": _manifest_address(manifest.get("stablecoin"), "stablecoin"),
        "reward_token": _manifest_address(
            manifest.get("reward_token"), "reward token", nonzero=False,
        ),
        "adjudication_threshold": manifest.get("adjudication_threshold"),
        "governance": _manifest_address(manifest.get("governance"), "governance"),
        "treasury": _manifest_address(manifest.get("treasury"), "treasury"),
        "domain_separator": _domain_separator(manifest),
        "max_channel_duration_seconds": manifest.get("max_channel_duration_seconds"),
    }
    observed_scalars = {
        "stablecoin": stablecoin, "reward_token": reward_token,
        "adjudication_threshold": threshold, "governance": governance,
        "treasury": treasury, "domain_separator": domain_separator,
        "max_channel_duration_seconds": max_channel_duration,
    }
    if observed_scalars != expected_scalars:
        raise EvidenceError("V10 contract state differs from the deployment manifest")

    stablecoin_runtime_hex, stablecoin_runtime = _runtime(
        rpc_call(rpc_url, "eth_getCode", [stablecoin, block_tag], timeout)
    )
    del stablecoin_runtime_hex
    stablecoin_runtime_sha256 = hashlib.sha256(stablecoin_runtime).hexdigest()
    stablecoin_runtime_keccak256 = "0x" + chain.keccak256(stablecoin_runtime).hex()
    if (
        stablecoin_runtime_sha256 != manifest.get("stablecoin_runtime_code_sha256")
        or stablecoin_runtime_keccak256
            != manifest.get("stablecoin_runtime_code_keccak256")
    ):
        raise EvidenceError("stablecoin runtime differs from the deployment manifest")
    stable_liabilities = _word_uint(call_words("stableLiabilities()", count=1)[0])
    stablecoin_balance = _word_uint(_words(
        _call_bytes(
            rpc_url, stablecoin, "balanceOf(address)", [address], block_tag,
            rpc_call, timeout,
        ),
        "balanceOf(address)", count=1,
    )[0])
    if stable_liabilities <= 0 or stablecoin_balance < stable_liabilities:
        raise EvidenceError("settlement stablecoin balance does not cover its liabilities")

    dynamic_jury = manifest.get("committee_mode") == DYNAMIC_JURY_MODE
    committee_state: dict[str, Any]
    if dynamic_jury:
        jury_registry = _word_address(
            call_words("juryRegistry()", count=1)[0], "jury registry",
        )
        if jury_registry != _manifest_address(
                manifest.get("jury_registry"), "jury registry"):
            raise EvidenceError("on-chain jury registry differs from the deployment manifest")
        committee_state = {"jury_registry": jury_registry}
    else:
        raw_adjudicators = _call_bytes(
            rpc_url, address, "adjudicators()", [], block_tag, rpc_call, timeout,
        )
        adjudicator_words = _words(raw_adjudicators, "adjudicators()")
        if (len(adjudicator_words) < 2 or len(adjudicator_words) > 18
                or _word_uint(adjudicator_words[0]) != 32
                or _word_uint(adjudicator_words[1]) != len(adjudicator_words) - 2):
            raise EvidenceError("RPC returned invalid adjudicator ABI data")
        adjudicators = [
            _word_address(word, "adjudicator") for word in adjudicator_words[2:]
        ]
        expected_adjudicators = manifest.get("adjudicators")
        if not isinstance(expected_adjudicators, list) or adjudicators != expected_adjudicators:
            raise EvidenceError("on-chain adjudicators differ from the deployment manifest")
        committee_state = {"adjudicators": adjudicators}

    policy_words = call_words("policy()", count=13)
    policy_names = (
        "dispute_window", "arbitration_timeout", "consumer_withdrawal_delay",
        "reporter_bond", "slash_bps", "slash_cap", "reporter_bounty_bps",
        "stable_bounty_cap", "token_reward", "token_reward_cap",
        "token_minimum_exposure", "token_minimum_penalty",
    )
    policy = {name: _word_uint(policy_words[index]) for index, name in enumerate(policy_names)}
    policy["bond_penalty_recipient"] = _word_address(
        policy_words[12], "bond penalty recipient",
    )
    if policy != manifest.get("policy"):
        raise EvidenceError("on-chain dispute policy differs from the deployment manifest")

    channel_hash = _hash(manifest.get("channel_hash"), "manifest channel hash")
    pricing_version = manifest.get("pricing_version")
    pricing_hash = _hash(manifest.get("pricing_hash"), "manifest pricing hash")
    if type(pricing_version) is not int or pricing_version <= 0:
        raise EvidenceError("deployment manifest pricing_version must be positive")
    latest_version = _word_uint(call_words(
        "latestChannelVersion(bytes32)", [channel_hash], count=1,
    )[0])
    channel_words = call_words(
        "channelVersions(bytes32,uint64)", [channel_hash, str(pricing_version)], count=10,
    )
    channel_config = {
        "input_per_1k": _word_uint(channel_words[0]),
        "output_per_1k": _word_uint(channel_words[1]),
        "minimum_fee": _word_uint(channel_words[2]),
        "provider_bps": _word_uint(channel_words[3]),
        "relay_bps": _word_uint(channel_words[4]),
        "pool_bps": _word_uint(channel_words[5]),
        "treasury_bps": _word_uint(channel_words[6]),
        "active": _word_uint(channel_words[7]) == 1,
    }
    channel_treasury = _word_address(channel_words[8], "channel treasury")
    observed_pricing_hash = "0x" + channel_words[9].hex()
    if (latest_version != pricing_version or not channel_config["active"]
            or channel_treasury != treasury or observed_pricing_hash != pricing_hash):
        raise EvidenceError("on-chain pricing channel differs from the deployment manifest")
    if sum(channel_config[name] for name in (
        "provider_bps", "relay_bps", "pool_bps", "treasury_bps",
    )) != 10_000:
        raise EvidenceError("on-chain pricing channel has invalid basis points")
    if channel_config["minimum_fee"] <= 0:
        raise EvidenceError("on-chain pricing channel cannot produce a positive minimum fee")
    return {
        **observed_scalars, **committee_state, "policy": policy,
        "stablecoin_runtime_code_sha256": stablecoin_runtime_sha256,
        "stablecoin_runtime_code_keccak256": stablecoin_runtime_keccak256,
        "stablecoin_balance": stablecoin_balance,
        "stable_liabilities": stable_liabilities,
        "channel": {
            "channel_hash": channel_hash, "pricing_version": latest_version,
            "pricing_hash": observed_pricing_hash, "treasury": channel_treasury,
            **channel_config,
        },
    }


def _jury_registry_state(
    rpc_url: str, *, manifest: dict[str, Any], address: str,
    block_tag: dict[str, Any],
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> dict[str, Any]:
    """Capture the full dynamic jury snapshot at the settlement state block."""
    policy = manifest.get("policy")
    minimum = manifest.get("minimum_provider_reputation")
    size = manifest.get("jury_size")
    expected_threshold = manifest.get("adjudication_threshold")
    delay = manifest.get("jury_selection_delay_blocks")
    if "jury_provider_evidence" in manifest:
        raise EvidenceError("deployment manifest must not pin the mutable jury Provider pool")
    if not isinstance(policy, dict):
        raise EvidenceError("deployment manifest has an invalid dispute policy")
    if (type(minimum) is not int or not 0 < minimum < 2**64
            or type(size) is not int or not 3 <= size <= 7
            or type(expected_threshold) is not int
            or not 2 <= expected_threshold <= size
            or expected_threshold <= size // 2
            or type(delay) is not int or not 0 < delay <= 64):
        raise EvidenceError("deployment manifest has an invalid jury policy")
    def call_words(
        signature: str, args: list[str] | None = None, count: int | None = None,
    ) -> list[bytes]:
        raw = _call_bytes(
            rpc_url, address, signature, args or [], block_tag, rpc_call, timeout,
        )
        return _words(raw, signature, count=count)

    governance = _word_address(call_words("governance()", count=1)[0], "jury governance")
    reputation_authority = _word_address(
        call_words("reputationAuthority()", count=1)[0], "reputation authority",
    )
    settlement = _word_address(
        call_words("settlement()", count=1)[0], "jury settlement",
    )
    bond_penalty_recipient = _word_address(
        call_words("bondPenaltyRecipient()", count=1)[0], "bond penalty recipient",
    )
    minimum_reputation = _word_uint(call_words("minimumReputation()", count=1)[0])
    jury_size = _word_uint(call_words("jurySize()", count=1)[0])
    threshold = _word_uint(call_words("threshold()", count=1)[0])
    selection_delay_blocks = _word_uint(
        call_words("selectionDelayBlocks()", count=1)[0]
    )
    randomness = "0x" + call_words("RANDOMNESS_MODE_HASH()", count=1)[0].hex()
    provider_count = _word_uint(call_words("providerCount()", count=1)[0])
    roster_version = _word_uint(call_words("rosterVersion()", count=1)[0])
    pending_assignments = _word_uint(call_words("pendingAssignments()", count=1)[0])
    can_form_jury = _word_bool(
        call_words("canFormJury()", count=1)[0], "canFormJury",
    )
    if (minimum_reputation >= 2**64 or roster_version >= 2**64
            or jury_size >= 2**16 or threshold >= 2**16
            or selection_delay_blocks >= 2**16):
        raise EvidenceError("jury registry returned an out-of-range typed scalar")
    if provider_count > MAX_DYNAMIC_PROVIDERS:
        raise EvidenceError("jury registry provider count exceeds the supported maximum")

    providers: list[dict[str, Any]] = []
    for index in range(provider_count):
        values = call_words("providerAt(uint256)", [str(index)], count=7)
        owner = _word_address(values[0], "jury provider owner")
        reputation = _word_uint(values[5])
        if reputation >= 2**64:
            raise EvidenceError("jury registry returned an invalid provider reputation")
        source_sequence = _word_uint(call_words(
            "providerSourceSequence(address)", [owner], count=1,
        )[0])
        source_digest = "0x" + call_words(
            "providerSourceDigest(address)", [owner], count=1,
        )[0].hex()
        if (
            not 0 < source_sequence < 2**64
            or source_digest == ZERO_HASH
        ):
            raise EvidenceError(
                "jury registry Provider lacks a committed reputation source"
            )
        providers.append({
            "owner": owner,
            "vote_signer": _word_address(values[1], "jury provider vote signer"),
            "operator_id_hash": "0x" + values[2].hex(),
            "peer_id_hash": "0x" + values[3].hex(),
            "capability_hash": "0x" + values[4].hex(),
            "reputation": reputation,
            "active": _word_bool(values[6], "jury provider active"),
            "source_sequence": source_sequence,
            "source_digest": source_digest,
        })

    authority_accounts = {
        address, governance, reputation_authority, settlement,
        bond_penalty_recipient, manifest.get("treasury"),
    }
    owners = [provider["owner"] for provider in providers]
    signers = [provider["vote_signer"] for provider in providers]
    eligible_operators = {
        provider["operator_id_hash"] for provider in providers
        if provider["active"] and provider["reputation"] >= minimum
    }
    if (
        not size <= provider_count <= MAX_DYNAMIC_PROVIDERS
        or any(provider["owner"] in authority_accounts
               or provider["vote_signer"] in authority_accounts
               or provider["owner"] == provider["vote_signer"]
               or provider["operator_id_hash"] == "0x" + "0" * 64
               or provider["peer_id_hash"] == "0x" + "0" * 64
               or provider["capability_hash"] == "0x" + "0" * 64
               for provider in providers)
        or len(owners) != len(set(owners))
        or len(signers) != len(set(signers))
        or bool(set(owners) & set(signers))
        or len(eligible_operators) < size
    ):
        raise EvidenceError("live jury reputation pool cannot form an independent jury")

    randomness_mode = manifest.get("jury_randomness")
    if not isinstance(randomness_mode, str) or not randomness_mode:
        raise EvidenceError("deployment manifest is missing its jury randomness mode")
    expected = {
        "address": _manifest_address(manifest.get("jury_registry"), "jury registry"),
        "governance": _manifest_address(
            manifest.get("jury_registry_governance"), "jury registry governance",
        ),
        "reputation_authority": _manifest_address(
            manifest.get("reputation_authority"), "reputation authority",
        ),
        "settlement": _manifest_address(manifest.get("settlement"), "settlement"),
        "bond_penalty_recipient": _manifest_address(
            policy.get("bond_penalty_recipient"),
            "bond penalty recipient",
        ),
        "minimum_reputation": minimum,
        "jury_size": size,
        "threshold": expected_threshold,
        "selection_delay_blocks": delay,
        "randomness": "0x" + chain.keccak256(randomness_mode.encode("utf-8")).hex(),
    }
    observed = {
        "address": address,
        "governance": governance,
        "reputation_authority": reputation_authority,
        "settlement": settlement,
        "bond_penalty_recipient": bond_penalty_recipient,
        "minimum_reputation": minimum_reputation,
        "jury_size": jury_size,
        "threshold": threshold,
        "selection_delay_blocks": selection_delay_blocks,
        "randomness": randomness,
    }
    if observed != expected or provider_count != len(providers):
        raise EvidenceError("jury registry state differs from the deployment manifest")
    if (roster_version < provider_count or pending_assignments != 0 or not can_form_jury
            or provider_count < size):
        raise EvidenceError("jury registry cannot safely form the declared jury")

    runtime_hex, runtime = _runtime(
        rpc_call(rpc_url, "eth_getCode", [address, block_tag], timeout)
    )
    return {
        **observed, "providers": providers,
        "provider_count": provider_count,
        "roster_version": roster_version,
        "pending_assignments": pending_assignments,
        "can_form_jury": can_form_jury,
        "runtime_code": runtime_hex,
        "runtime_code_sha256": hashlib.sha256(runtime).hexdigest(),
        "runtime_code_keccak256": "0x" + chain.keccak256(runtime).hex(),
    }


def _successful_call_receipt(
    rpc_url: str, *, transaction_hash: str, address: str,
    deployment_block: int, state_block_number: int, channel_id: str,
    consumer_owner: str, provider_owner: str, capacity: int,
    valid_from: int, claim_until: int,
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> dict[str, Any]:
    receipt = rpc_call(rpc_url, "eth_getTransactionReceipt", [transaction_hash], timeout)
    if not isinstance(receipt, dict):
        raise EvidenceError("capacity-channel transaction receipt is unavailable")
    receipt_hash = _hash(receipt.get("transactionHash"), "capacity receipt transaction hash")
    block_hash = _hash(receipt.get("blockHash"), "capacity receipt block hash")
    block_number = _rpc_hex_int(receipt.get("blockNumber"), "capacity receipt block number")
    status = _rpc_hex_int(receipt.get("status"), "capacity receipt status")
    target = _address(receipt.get("to"), "capacity receipt target")
    # The state block itself was selected confirmations-deep from the lowest
    # RPC head, so every receipt at or before that block already has the same
    # confirmation guarantee.  Do not accidentally require confirmations twice.
    if (receipt_hash != transaction_hash or target != address or status != 1
            or not deployment_block <= block_number <= state_block_number):
        raise EvidenceError("capacity-channel receipt differs from the deployment manifest")
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise EvidenceError("capacity-channel receipt is missing its event logs")
    event_topic = "0x" + chain.keccak256(
        b"CapacityChannelOpened(bytes32,address,address,uint256,uint64,uint64)"
    ).hex()
    consumer_topic = "0x" + (b"\0" * 12 + bytes.fromhex(consumer_owner[2:])).hex()
    provider_topic = "0x" + (b"\0" * 12 + bytes.fromhex(provider_owner[2:])).hex()
    expected_topics = [event_topic, channel_id, consumer_topic, provider_topic]
    expected_data = "0x" + b"".join(
        value.to_bytes(32, "big") for value in (capacity, valid_from, claim_until)
    ).hex()
    matching_logs: list[dict[str, Any]] = []
    for log in logs:
        topics = log.get("topics") if isinstance(log, dict) else None
        if not isinstance(topics, list) or topics[0:1] != [event_topic]:
            continue
        if (_address(log.get("address"), "capacity event address") != address
                or _hash(log.get("transactionHash"), "capacity event transaction hash")
                    != transaction_hash
                or _hash(log.get("blockHash"), "capacity event block hash") != block_hash
                or _rpc_hex_int(log.get("blockNumber"), "capacity event block number")
                    != block_number
                or type(log.get("removed")) is not bool or log["removed"]):
            raise EvidenceError("capacity-channel event is not a canonical receipt log")
        _rpc_hex_int(log.get("logIndex"), "capacity event log index")
        if topics == expected_topics and log.get("data") == expected_data:
            matching_logs.append(log)
    if len(matching_logs) != 1:
        raise EvidenceError("capacity-channel receipt does not prove the manifest channel open")
    block = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(block_number), False], timeout)
    if (not isinstance(block, dict) or _hash(block.get("hash"), "capacity block hash") != block_hash
            or _rpc_hex_int(block.get("number"), "capacity block number") != block_number):
        raise EvidenceError("capacity-channel receipt block is not canonical")
    open_block_timestamp = _rpc_hex_int(
        block.get("timestamp"), "capacity block timestamp",
    )
    return {"transaction_hash": transaction_hash, "block_number": block_number,
            "block_hash": block_hash, "open_block_timestamp": open_block_timestamp}


def _capacity_channels(
    rpc_url: str, *, manifest: dict[str, Any], network_manifest: dict[str, Any], address: str,
    block_tag: dict[str, Any], deployment_block: int, state_block_number: int,
    minimum_fee: int, jury_registry: str | None,
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> list[dict[str, Any]]:
    channel_ids = manifest.get("capacity_channel_ids")
    transaction_hashes = manifest.get("fresh_channel_open_tx_hashes")
    open_block_timestamps = manifest.get("fresh_channel_open_block_timestamps")
    if (not isinstance(channel_ids, list) or not isinstance(transaction_hashes, list)
            or not isinstance(open_block_timestamps, list) or not channel_ids
            or len(channel_ids) != len(transaction_hashes)
            or len(channel_ids) != len(open_block_timestamps)
            or len(set(channel_ids)) != len(channel_ids)):
        raise EvidenceError("deployment capacity channel IDs and transactions are incomplete")
    channel_hash = _hash(manifest.get("channel_hash"), "manifest channel hash")
    pricing_version = manifest.get("pricing_version")
    pricing_hash = _hash(manifest.get("pricing_hash"), "manifest pricing hash")
    expected_numbers = {
        "capacity": manifest.get("fresh_channel_capacity"),
        "max_fee_per_request": manifest.get("fresh_channel_max_fee_per_request"),
        "valid_from": manifest.get("fresh_channel_valid_from"),
        "admit_until": manifest.get("fresh_channel_admit_until"),
        "claim_until": manifest.get("fresh_channel_claim_until"),
    }
    if any(type(value) is not int or value <= 0 for value in expected_numbers.values()):
        raise EvidenceError("deployment capacity channel parameters are invalid")
    relay = network_manifest.get("relay")
    fallbacks = network_manifest.get("relay_fallbacks")
    relay_entries = [relay, *(fallbacks if isinstance(fallbacks, list) else [])]
    relay_identities = {
        (
            _manifest_address(entry.get("payment_address"), "Relay payment address"),
            _manifest_address(entry.get("attestation_address"), "Relay attestation address"),
        )
        for entry in relay_entries if isinstance(entry, dict)
    }
    if not relay_identities:
        raise EvidenceError("deployment Relay identities are incomplete")
    observed: list[dict[str, Any]] = []
    max_channel_duration = manifest.get("max_channel_duration_seconds")
    for raw_channel_id, raw_transaction_hash, expected_open_timestamp in zip(
            channel_ids, transaction_hashes, open_block_timestamps, strict=True):
        channel_id = _hash(raw_channel_id, "capacity channel id")
        transaction_hash = _hash(raw_transaction_hash, "capacity open transaction hash")
        raw = _call_bytes(
            rpc_url, address, "channelInfo(bytes32)", [channel_id], block_tag, rpc_call, timeout,
        )
        values = _words(raw, "channelInfo(bytes32)", count=22)
        addresses = [
            *(
                _word_address(values[index], f"capacity channel address {index}")
                for index in range(6)
            ),
            _word_address(values[6], "capacity channel pool", nonzero=False),
        ]
        numeric = {
            "pricing_version": _word_uint(values[8]),
            "capacity": _word_uint(values[10]),
            "max_fee_per_request": _word_uint(values[11]),
            "valid_from": _word_uint(values[12]),
            "admit_until": _word_uint(values[13]),
            "claim_until": _word_uint(values[14]),
            "consumer_nonce": _word_uint(values[15]),
            "provider_nonce": _word_uint(values[16]),
            "permit_deadline": _word_uint(values[17]),
            "settled_max_fee": _word_uint(values[18]),
            "credit_remaining": _word_uint(values[19]),
            "stake_remaining": _word_uint(values[20]),
        }
        closed_word = _word_uint(values[21])
        if closed_word not in {0, 1}:
            raise EvidenceError("capacity channel returned a malformed closed flag")
        if (_capacity_channel_id(
                manifest, addresses, channel_hash, pricing_hash, numeric,
            ) != channel_id
                or "0x" + values[7].hex() != channel_hash
                or numeric["pricing_version"] != pricing_version
                or "0x" + values[9].hex() != pricing_hash
                or any(numeric[name] != expected for name, expected in expected_numbers.items())
                or (addresses[4], addresses[5]) not in relay_identities
                or closed_word != 0
                or numeric["credit_remaining"] < numeric["max_fee_per_request"]
                or numeric["stake_remaining"] < numeric["max_fee_per_request"]
                or numeric["max_fee_per_request"] < minimum_fee
                or numeric["settled_max_fee"] + numeric["max_fee_per_request"]
                    > numeric["capacity"]):
            raise EvidenceError("capacity channel is not a currently usable manifest budget")
        receipt = _successful_call_receipt(
            rpc_url, transaction_hash=transaction_hash, address=address,
            deployment_block=deployment_block, state_block_number=state_block_number,
            channel_id=channel_id, consumer_owner=addresses[0],
            provider_owner=addresses[2], capacity=numeric["capacity"],
            valid_from=numeric["valid_from"], claim_until=numeric["claim_until"],
            rpc_call=rpc_call, timeout=timeout,
        )
        if (type(expected_open_timestamp) is not int
                or receipt["open_block_timestamp"] != expected_open_timestamp
                or not expected_open_timestamp < numeric["valid_from"]
                or type(max_channel_duration) is not int
                or numeric["claim_until"] - expected_open_timestamp
                    > max_channel_duration):
            raise EvidenceError("capacity channel duration differs from its open block")
        channel_evidence = {
            "channel_id": channel_id, **receipt,
            "consumer_owner": addresses[0], "consumer_key": addresses[1],
            "provider_owner": addresses[2], "provider_signer": addresses[3],
            "relay": addresses[4], "relay_signer": addresses[5], "pool": addresses[6],
            "channel_hash": channel_hash, "pricing_hash": pricing_hash,
            **numeric, "closed": False,
        }
        if jury_registry is not None:
            jury_ready = _word_bool(_words(_call_bytes(
                rpc_url, jury_registry, "canFormJuryFor(bytes32)", [channel_id],
                block_tag, rpc_call, timeout,
            ), "canFormJuryFor(bytes32)", count=1)[0], "canFormJuryFor")
            if not jury_ready:
                raise EvidenceError(
                    "capacity channel cannot form an independent Provider jury"
                )
            channel_evidence["jury_ready"] = True
        observed.append(channel_evidence)
    return observed


def _observe(
    rpc_url: str, *, manifest: dict[str, Any], network_manifest: dict[str, Any],
    jury_transaction_senders: dict[str, str], jury_transaction_gas_cap_wei: int,
    chain_id: int, address: str,
    transaction_hash: str, deployment_block: int, confirmations: int,
    state_block_number: int, state_block_hash: str,
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> dict[str, Any]:
    if _rpc_hex_int(rpc_call(rpc_url, "eth_chainId", [], timeout), "chain id") != chain_id:
        raise EvidenceError("RPC chain id differs from the deployment manifest")
    reputation_history = None
    if manifest.get("committee_mode") == DYNAMIC_JURY_MODE:
        reputation_history = _reputation_history_lineage(
            manifest.get(REPUTATION_HISTORY_FIELD),
            manifest=manifest,
            label="deployment reputation_history_import",
        )
        genesis = rpc_call(
            rpc_url, "eth_getBlockByNumber", ["0x0", False], timeout,
        )
        if (
            not isinstance(genesis, dict)
            or _rpc_hex_int(genesis.get("number"), "genesis block number") != 0
            or _hash(genesis.get("hash"), "genesis block hash")
                != reputation_history["source_genesis_hash"]
        ):
            raise EvidenceError(
                "RPC genesis differs from reputation history lineage"
            )
    receipt = rpc_call(rpc_url, "eth_getTransactionReceipt", [transaction_hash], timeout)
    if not isinstance(receipt, dict):
        raise EvidenceError("deployment receipt is unavailable")
    receipt_hash = _hash(receipt.get("transactionHash"), "receipt transaction hash")
    block_hash = _hash(receipt.get("blockHash"), "receipt block hash")
    block_number = _rpc_hex_int(receipt.get("blockNumber"), "receipt block number")
    status = _rpc_hex_int(receipt.get("status"), "receipt status")
    contract = _address(receipt.get("contractAddress"), "deployed contract address")
    if (receipt_hash != transaction_hash or block_number != deployment_block
            or status != 1 or contract != address):
        raise EvidenceError("deployment receipt differs from the manifest")
    transaction = rpc_call(rpc_url, "eth_getTransactionByHash", [transaction_hash], timeout)
    if not isinstance(transaction, dict):
        raise EvidenceError("deployment transaction is unavailable")
    deployer = _address(transaction.get("from"), "deployment sender")
    tx_hash = _hash(transaction.get("hash"), "deployment transaction hash")
    tx_block_hash = _hash(transaction.get("blockHash"), "deployment transaction block hash")
    tx_block_number = _rpc_hex_int(
        transaction.get("blockNumber"), "deployment transaction block number",
    )
    if (deployer != _manifest_address(manifest.get("deployer"), "deployer")
            or tx_hash != transaction_hash or tx_block_hash != block_hash
            or tx_block_number != block_number or transaction.get("to") is not None):
        raise EvidenceError("deployment transaction sender or creation target differs from manifest")
    head = _rpc_hex_int(rpc_call(rpc_url, "eth_blockNumber", [], timeout), "head block")
    if head - block_number + 1 < confirmations:
        raise EvidenceError("deployment does not have the required confirmations")
    if (
        reputation_history is not None
        and head - reputation_history["source_history_through_block"] + 1
            < reputation_history["confirmations"]
    ):
        raise EvidenceError(
            "reputation history cutoff does not have the required confirmations"
        )
    block = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(block_number), False], timeout)
    if (not isinstance(block, dict) or _hash(block.get("hash"), "canonical block hash") != block_hash
            or _rpc_hex_int(block.get("number"), "canonical block number") != block_number):
        raise EvidenceError("deployment receipt block is not canonical")
    deployment_block_tag = {"blockHash": block_hash, "requireCanonical": True}
    runtime_hex, runtime = _runtime(
        rpc_call(rpc_url, "eth_getCode", [address, deployment_block_tag], timeout)
    )
    if manifest.get("committee_mode") == DYNAMIC_JURY_MODE and (
        block_hash != manifest.get("deployment_block_hash")
        or "0x" + chain.keccak256(runtime).hex()
            != manifest.get("settlement_runtime_code_keccak256")
    ):
        raise EvidenceError(
            "live Settlement deployment boundary differs from the dynamic manifest"
        )
    state_block_tag = {"blockHash": state_block_hash, "requireCanonical": True}
    if reputation_history is not None:
        source_blocks: dict[str, dict[str, Any]] = {}
        for label, number_field, hash_field in (
            (
                "deployment", "source_deployment_block",
                "source_deployment_block_hash",
            ),
            (
                "history cutoff", "source_history_through_block",
                "source_history_through_block_hash",
            ),
        ):
            number = reputation_history[number_field]
            expected_hash = reputation_history[hash_field]
            source_block = rpc_call(
                rpc_url, "eth_getBlockByNumber", [hex(number), False], timeout,
            )
            if (
                not isinstance(source_block, dict)
                or _rpc_hex_int(
                    source_block.get("number"), f"source {label} block number",
                ) != number
                or _hash(
                    source_block.get("hash"), f"source {label} block hash",
                ) != expected_hash
            ):
                raise EvidenceError(
                    f"reputation history source {label} block is not canonical"
                )
            source_blocks[label] = {
                "blockHash": expected_hash, "requireCanonical": True,
            }
        prior_number = reputation_history["source_deployment_block"] - 1
        prior_block = rpc_call(
            rpc_url, "eth_getBlockByNumber", [hex(prior_number), False], timeout,
        )
        if (
            not isinstance(prior_block, dict)
            or _rpc_hex_int(
                prior_block.get("number"), "source predeployment block number",
            ) != prior_number
        ):
            raise EvidenceError("reputation history source predeployment block is unavailable")
        prior_hash = _hash(
            prior_block.get("hash"), "source predeployment block hash",
        )
        prior_code = rpc_call(
            rpc_url, "eth_getCode", [
                reputation_history["source_settlement_contract"],
                {"blockHash": prior_hash, "requireCanonical": True},
            ], timeout,
        )
        if prior_code != "0x":
            raise EvidenceError(
                "historical Settlement existed before its pinned deployment block"
            )
        _, source_runtime = _runtime(rpc_call(
            rpc_url,
            "eth_getCode",
            [
                reputation_history["source_settlement_contract"],
                source_blocks["deployment"],
            ],
            timeout,
        ))
        if (
            "0x" + chain.keccak256(source_runtime).hex()
            != reputation_history["source_runtime_code_hash"]
        ):
            raise EvidenceError(
                "historical Settlement runtime differs from reputation history lineage"
            )
    contract_state = _contract_state(
        rpc_url, manifest=manifest, address=address, block_tag=state_block_tag,
        rpc_call=rpc_call, timeout=timeout,
    )
    jury_registry_state = None
    if manifest.get("committee_mode") == DYNAMIC_JURY_MODE:
        jury_registry_state = _jury_registry_state(
            rpc_url, manifest=manifest,
            address=contract_state["jury_registry"], block_tag=state_block_tag,
            rpc_call=rpc_call, timeout=timeout,
        )
    capacity_channels = _capacity_channels(
        rpc_url, manifest=manifest, network_manifest=network_manifest,
        address=address, block_tag=state_block_tag,
        deployment_block=deployment_block, state_block_number=state_block_number,
        minimum_fee=contract_state["channel"]["minimum_fee"],
        jury_registry=(
            contract_state["jury_registry"]
            if manifest.get("committee_mode") == DYNAMIC_JURY_MODE else None
        ),
        rpc_call=rpc_call, timeout=timeout,
    )
    jury_senders_state = None
    if manifest.get("committee_mode") == DYNAMIC_JURY_MODE:
        conflicts = sorted(set(jury_transaction_senders.values()) & _known_role_addresses(
            manifest, network_manifest, contract_state, jury_registry_state,
            capacity_channels,
        ))
        if conflicts:
            raise EvidenceError(
                f"jury transaction sender reuses a known on-chain role: {conflicts}"
            )
        jury_senders_state = _jury_sender_evidence(
            rpc_url,
            senders=jury_transaction_senders,
            gas_cap_wei=jury_transaction_gas_cap_wei,
            state_block_number=state_block_number,
            state_block_hash=state_block_hash,
            rpc_call=rpc_call,
            timeout=timeout,
        )
    final_block = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(block_number), False], timeout)
    if (not isinstance(final_block, dict)
            or _hash(final_block.get("hash"), "final canonical block hash") != block_hash
            or _rpc_hex_int(final_block.get("number"), "final canonical block number")
                != block_number):
        raise EvidenceError("deployment block reorganized during runtime capture")
    final_state_block = rpc_call(
        rpc_url, "eth_getBlockByNumber", [hex(state_block_number), False], timeout,
    )
    if (not isinstance(final_state_block, dict)
            or _hash(final_state_block.get("hash"), "final state block hash") != state_block_hash
            or _rpc_hex_int(final_state_block.get("number"), "final state block number")
                != state_block_number):
        raise EvidenceError("confirmed state block reorganized during evidence capture")
    result = {
        "chain_id": chain_id, "address": address,
        "transaction_hash": transaction_hash, "block_number": block_number,
        "block_hash": block_hash, "runtime_code": runtime_hex,
        "runtime_code_sha256": hashlib.sha256(runtime).hexdigest(),
        "runtime_code_keccak256": "0x" + chain.keccak256(runtime).hex(),
        "deployer": deployer,
        "state_block_number": state_block_number,
        "state_block_hash": state_block_hash,
        "contract_state": contract_state,
        "capacity_channels": capacity_channels,
    }
    if jury_registry_state is not None:
        result["jury_registry_state"] = jury_registry_state
        result["jury_transaction_senders"] = jury_senders_state
        result[REPUTATION_HISTORY_FIELD] = reputation_history
    return result


def capture_release_evidence(
    *, deployment_path: Path, provider_network_path: Path,
    consumer_network_path: Path, source_commit: str,
    rpc_urls: list[str],
    confirmations: int = 6, timeout: float = 15.0,
    rpc_call: Callable[[str, str, list[Any], float], Any] = chain.rpc_call,
) -> dict[str, Any]:
    if not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit):
        raise EvidenceError("source commit must be lowercase 40-character hex")
    if type(confirmations) is not int or not 2 <= confirmations <= 256:
        raise EvidenceError("release evidence requires 2 to 256 confirmations")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 1 <= timeout <= 60):
        raise EvidenceError("RPC timeout must be between 1 and 60 seconds")
    if not isinstance(rpc_urls, list) or not all(isinstance(value, str) for value in rpc_urls):
        raise EvidenceError("RPC endpoints must be provided as a list of URLs")
    urls = [_canonical_rpc_url(value) for value in rpc_urls]
    origins = [_rpc_origin(value) for value in urls]
    if len(urls) < 2 or len(set(origins)) != len(origins):
        raise EvidenceError("at least two distinct RPC endpoint origins are required")
    manifest, manifest_raw = _load_manifest(deployment_path)
    # Deployed bytecode binds to the commit the manifests pin for the contract
    # deployment; npm and OCI artifacts bind to the release commit instead.
    deployment_source = manifest.get("source_commit", source_commit)
    if not isinstance(deployment_source, str) or not COMMIT_RE.fullmatch(deployment_source):
        raise EvidenceError("deployment source_commit must be lowercase 40-character hex")
    dynamic_jury = manifest.get("committee_mode") == DYNAMIC_JURY_MODE
    jury_network_fields = {
        "jury_relay_public_keys", "jury_transaction_senders",
        JURY_TRANSACTION_GAS_CAP_FIELD,
    }
    if jury_network_fields.intersection(manifest):
        raise EvidenceError(
            "jury Relay keys, transaction senders, and gas cap belong only in network manifests"
        )
    if dynamic_jury:
        deployment_boundary = _dynamic_deployment_boundary(
            manifest, label="deployment",
        )
        deployment_history = _reputation_history_lineage(
            manifest.get(REPUTATION_HISTORY_FIELD),
            manifest=manifest,
            label="deployment reputation_history_import",
        )
        forbidden = sorted(DYNAMIC_JURY_FORBIDDEN_FIELDS.intersection(manifest))
        if forbidden:
            raise EvidenceError(
                "dynamic Provider jury deployment manifest contains forbidden static "
                f"committee fields: {', '.join(forbidden)}"
            )
    decision_policy_hash = manifest.get("jury_decision_policy_hash")
    if dynamic_jury and (
        not isinstance(decision_policy_hash, str)
        or HASH_RE.fullmatch(decision_policy_hash) is None
        or decision_policy_hash == ZERO_HASH
    ):
        raise EvidenceError(
            "dynamic Provider jury requires a canonical nonzero SHA-256 decision policy hash"
        )
    network_manifest, network_manifest_raw = _load_manifest(provider_network_path)
    consumer_manifest, consumer_manifest_raw = _load_manifest(consumer_network_path)
    jury_transaction_senders: dict[str, str] = {}
    jury_transaction_gas_cap_wei = 0
    if dynamic_jury:
        for label, value in (
            ("Provider", network_manifest), ("Consumer", consumer_manifest),
        ):
            forbidden = sorted(DYNAMIC_JURY_FORBIDDEN_FIELDS.intersection(value))
            if forbidden:
                raise EvidenceError(
                    f"dynamic {label} jury network manifest contains forbidden static "
                    f"committee fields: {', '.join(forbidden)}"
                )
        _, jury_transaction_senders, jury_transaction_gas_cap_wei = (
            _jury_sender_config(manifest, network_manifest)
        )
        for label, value in (
            ("Provider", network_manifest), ("Consumer", consumer_manifest),
        ):
            if _dynamic_deployment_boundary(value, label=label) != deployment_boundary:
                raise EvidenceError(
                    f"{label} Settlement deployment boundary differs from deployment"
                )
            observed_history = _reputation_history_lineage(
                value.get(REPUTATION_HISTORY_FIELD),
                manifest=manifest,
                label=f"{label} reputation_history_import",
            )
            if observed_history != deployment_history:
                raise EvidenceError(
                    f"{label} reputation history lineage differs from deployment"
                )
        if (
            consumer_manifest.get("jury_relay_public_keys")
            != network_manifest.get("jury_relay_public_keys")
            or consumer_manifest.get("jury_transaction_senders")
            != network_manifest.get("jury_transaction_senders")
            or consumer_manifest.get(JURY_TRANSACTION_GAS_CAP_FIELD)
            != jury_transaction_gas_cap_wei
        ):
            raise EvidenceError(
                "Provider and Consumer jury sender configuration differs"
            )
    elif any(
        jury_network_fields.intersection(value)
        for value in (network_manifest, consumer_manifest)
    ) or any(REPUTATION_HISTORY_FIELD in value for value in (
        manifest, network_manifest, consumer_manifest,
    )):
        raise EvidenceError(
            "jury sender configuration requires a dynamic Provider jury deployment"
        )
    if network_manifest.get("deployment") != deployment_path.name:
        raise EvidenceError("Provider network manifest references the wrong deployment")
    drift = sorted(
        key for key in set(manifest) & set(network_manifest)
        if manifest[key] != network_manifest[key]
    )
    if drift:
        raise EvidenceError(f"Provider network/deployment manifest bindings drift: {drift}")
    provider_payload = {
        key: value for key, value in network_manifest.items()
        if key not in {"deployment", "tls_ca_file"}
    }
    expected_consumer = {**manifest, **provider_payload}
    actual_consumer = {
        key: value for key, value in consumer_manifest.items() if key != "tls_ca_file"
    }
    if actual_consumer != expected_consumer:
        raise EvidenceError(
            "Consumer V10 manifest is not the deployment/provider semantic union"
        )
    chain_id = manifest.get("chain_id")
    deployment_block = manifest.get("deployment_block")
    if type(chain_id) is not int or chain_id <= 0:
        raise EvidenceError("deployment chain_id must be positive")
    if type(deployment_block) is not int or deployment_block < 0:
        raise EvidenceError("deployment_block must be nonnegative")
    address = _address(manifest.get("settlement"), "manifest settlement address")
    transaction_hash = _hash(manifest.get("tx_hash"), "manifest transaction hash")
    heads: list[int] = []
    for url in urls:
        if _rpc_hex_int(rpc_call(url, "eth_chainId", [], float(timeout)), "chain id") != chain_id:
            raise EvidenceError("RPC chain id differs from the deployment manifest")
        heads.append(_rpc_hex_int(
            rpc_call(url, "eth_blockNumber", [], float(timeout)), "head block",
        ))
    state_block_number = min(heads) - confirmations + 1
    if state_block_number < deployment_block:
        raise EvidenceError("RPC heads do not expose a sufficiently confirmed deployment state")
    state_blocks = [
        rpc_call(url, "eth_getBlockByNumber", [hex(state_block_number), False], float(timeout))
        for url in urls
    ]
    state_hashes: list[str] = []
    state_timestamps: list[int] = []
    for block in state_blocks:
        if not isinstance(block, dict):
            raise EvidenceError("confirmed state block is unavailable")
        state_hashes.append(_hash(block.get("hash"), "confirmed state block hash"))
        if _rpc_hex_int(block.get("number"), "confirmed state block number") != state_block_number:
            raise EvidenceError("RPC returned the wrong confirmed state block")
        state_timestamps.append(_rpc_hex_int(
            block.get("timestamp"), "confirmed state block timestamp",
        ))
    if len(set(state_hashes)) != 1:
        raise EvidenceError("independent RPC endpoints disagree on the confirmed state block")
    if len(set(state_timestamps)) != 1:
        raise EvidenceError("independent RPC endpoints disagree on the confirmed state timestamp")
    state_block_hash = state_hashes[0]
    state_block_timestamp = state_timestamps[0]
    valid_from = manifest.get("fresh_channel_valid_from")
    admit_until = manifest.get("fresh_channel_admit_until")
    if (type(valid_from) is not int or type(admit_until) is not int
            or not valid_from <= state_block_timestamp < admit_until):
        raise EvidenceError("confirmed state is outside the capacity-channel admission window")
    observations = [
        _observe(
            url, manifest=manifest, network_manifest=network_manifest,
            jury_transaction_senders=jury_transaction_senders,
            jury_transaction_gas_cap_wei=jury_transaction_gas_cap_wei,
            chain_id=chain_id, address=address,
            transaction_hash=transaction_hash, deployment_block=deployment_block,
            confirmations=confirmations, state_block_number=state_block_number,
            state_block_hash=state_block_hash, rpc_call=rpc_call, timeout=float(timeout),
        )
        for url in urls
    ]
    reference = observations[0]
    if any(value != reference for value in observations[1:]):
        raise EvidenceError("independent RPC endpoints disagree on deployment runtime evidence")
    result = {
        "schema": SCHEMA, "source_commit": deployment_source,
        **reference,
        "confirmations": confirmations, "rpc_quorum": len(urls),
        "deployment_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "provider_network_manifest_sha256": hashlib.sha256(
            network_manifest_raw
        ).hexdigest(),
        "consumer_network_manifest_sha256": hashlib.sha256(
            consumer_manifest_raw
        ).hexdigest(),
        "state_block_timestamp": state_block_timestamp,
    }
    if dynamic_jury:
        result["jury_decision_policy_hash"] = decision_policy_hash
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--provider-network", type=Path, required=True)
    parser.add_argument("--consumer-network", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--rpc-url", action="append", required=True)
    parser.add_argument("--confirmations", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        evidence = capture_release_evidence(
            deployment_path=args.deployment.resolve(), source_commit=args.source_commit,
            provider_network_path=args.provider_network.resolve(),
            consumer_network_path=args.consumer_network.resolve(),
            rpc_urls=args.rpc_url, confirmations=args.confirmations, timeout=args.timeout,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(evidence, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
    except (EvidenceError, OSError, chain.ChainError) as exc:
        print(f"capture release evidence: {exc}", file=__import__("sys").stderr)
        return 1
    print(json.dumps({"output": str(args.output), "schema": SCHEMA}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
