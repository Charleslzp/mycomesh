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


SCHEMA = "mycomesh.deployed-code.v2"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
DNS_NAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_RUNTIME_BYTES = 128 * 1024


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
    expected_scalars = {
        "stablecoin": _manifest_address(manifest.get("stablecoin"), "stablecoin"),
        "reward_token": _manifest_address(
            manifest.get("reward_token"), "reward token", nonzero=False,
        ),
        "adjudication_threshold": manifest.get("adjudication_threshold"),
        "governance": _manifest_address(manifest.get("governance"), "governance"),
        "treasury": _manifest_address(manifest.get("treasury"), "treasury"),
        "domain_separator": _domain_separator(manifest),
    }
    observed_scalars = {
        "stablecoin": stablecoin, "reward_token": reward_token,
        "adjudication_threshold": threshold, "governance": governance,
        "treasury": treasury, "domain_separator": domain_separator,
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
        **observed_scalars, "adjudicators": adjudicators, "policy": policy,
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
    return {"transaction_hash": transaction_hash, "block_number": block_number,
            "block_hash": block_hash}


def _capacity_channels(
    rpc_url: str, *, manifest: dict[str, Any], network_manifest: dict[str, Any], address: str,
    block_tag: dict[str, Any], deployment_block: int, state_block_number: int,
    minimum_fee: int,
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> list[dict[str, Any]]:
    channel_ids = manifest.get("capacity_channel_ids")
    transaction_hashes = manifest.get("fresh_channel_open_tx_hashes")
    if (not isinstance(channel_ids, list) or not isinstance(transaction_hashes, list)
            or not channel_ids or len(channel_ids) != len(transaction_hashes)
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
    for raw_channel_id, raw_transaction_hash in zip(channel_ids, transaction_hashes):
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
        observed.append({
            "channel_id": channel_id, **receipt,
            "consumer_owner": addresses[0], "consumer_key": addresses[1],
            "provider_owner": addresses[2], "provider_signer": addresses[3],
            "relay": addresses[4], "relay_signer": addresses[5], "pool": addresses[6],
            "channel_hash": channel_hash, "pricing_hash": pricing_hash,
            **numeric, "closed": False,
        })
    return observed


def _observe(
    rpc_url: str, *, manifest: dict[str, Any], network_manifest: dict[str, Any],
    chain_id: int, address: str,
    transaction_hash: str, deployment_block: int, confirmations: int,
    state_block_number: int, state_block_hash: str,
    rpc_call: Callable[[str, str, list[Any], float], Any], timeout: float,
) -> dict[str, Any]:
    if _rpc_hex_int(rpc_call(rpc_url, "eth_chainId", [], timeout), "chain id") != chain_id:
        raise EvidenceError("RPC chain id differs from the deployment manifest")
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
    block = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(block_number), False], timeout)
    if (not isinstance(block, dict) or _hash(block.get("hash"), "canonical block hash") != block_hash
            or _rpc_hex_int(block.get("number"), "canonical block number") != block_number):
        raise EvidenceError("deployment receipt block is not canonical")
    deployment_block_tag = {"blockHash": block_hash, "requireCanonical": True}
    runtime_hex, runtime = _runtime(
        rpc_call(rpc_url, "eth_getCode", [address, deployment_block_tag], timeout)
    )
    state_block_tag = {"blockHash": state_block_hash, "requireCanonical": True}
    contract_state = _contract_state(
        rpc_url, manifest=manifest, address=address, block_tag=state_block_tag,
        rpc_call=rpc_call, timeout=timeout,
    )
    capacity_channels = _capacity_channels(
        rpc_url, manifest=manifest, network_manifest=network_manifest,
        address=address, block_tag=state_block_tag,
        deployment_block=deployment_block, state_block_number=state_block_number,
        minimum_fee=contract_state["channel"]["minimum_fee"],
        rpc_call=rpc_call, timeout=timeout,
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
    return {
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


def capture_release_evidence(
    *, deployment_path: Path, provider_network_path: Path, source_commit: str,
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
    network_manifest, network_manifest_raw = _load_manifest(provider_network_path)
    if network_manifest.get("deployment") != deployment_path.name:
        raise EvidenceError("Provider network manifest references the wrong deployment")
    drift = sorted(
        key for key in set(manifest) & set(network_manifest)
        if manifest[key] != network_manifest[key]
    )
    if drift:
        raise EvidenceError(f"Provider network/deployment manifest bindings drift: {drift}")
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
    return {
        "schema": SCHEMA, "source_commit": source_commit,
        **reference,
        "confirmations": confirmations, "rpc_quorum": len(urls),
        "deployment_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "provider_network_manifest_sha256": hashlib.sha256(
            network_manifest_raw
        ).hexdigest(),
        "state_block_timestamp": state_block_timestamp,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--provider-network", type=Path, required=True)
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
