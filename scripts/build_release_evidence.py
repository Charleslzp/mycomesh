#!/usr/bin/env python3
"""Build the offline declaration consumed by ``release_gate.py``.

This command does not contact npm, an OCI registry, or an RPC endpoint.  It
binds already captured release inputs together only after their identities and
hashes agree.  The output is created atomically with exclusive-create
semantics so an existing declaration is never overwritten.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


RELEASE_SCHEMA = "mycomesh.release-artifacts.v1"
NPM_SCHEMA = "mycomesh.npm-release-candidate.v1"
OCI_SCHEMA = "mycomesh.oci-metadata.v1"
DEPLOYED_CODE_SCHEMA = "mycomesh.deployed-code.v2"

DEPLOYMENT_PATH = Path("deployments/sepolia-myco-v10.json")
PROVIDER_NETWORK_PATH = Path("deployments/sepolia-provider-network-v10.json")
CONSUMER_NETWORK_PATH = Path("packages/mycomesh-cli/networks/v10-controlled-test.json")

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_RE = re.compile(
    r"^ghcr\.io/charleslzp/mycomesh-provider-codex@sha256:[0-9a-f]{64}$"
)
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.tgz$")

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TARBALL_MEMBERS = 4096
MAX_PACKAGE_JSON_BYTES = 1024 * 1024
REQUIRED_PLATFORMS = frozenset(("linux/amd64", "linux/arm64"))


class ReleaseEvidenceError(ValueError):
    """A release input is malformed or disagrees with another input."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseEvidenceError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _invalid_constant(value: str) -> Any:
    raise ReleaseEvidenceError(f"invalid JSON constant: {value}")


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ReleaseEvidenceError(f"{label} must be a regular, non-symbolic file: {path}")
    return path


def _read_bounded(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    _regular_file(path, label)
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ReleaseEvidenceError(f"{label} exceeds {maximum} bytes")
    return raw


def _json_value(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseEvidenceError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(f"{label} must contain a JSON object")
    return value


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded(path, label)
    return _json_value(raw, label), raw


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing or unexpected:
        raise ReleaseEvidenceError(
            f"{label} keys differ (missing={missing}, unexpected={unexpected})"
        )


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_digests(path: Path) -> tuple[int, str, str, str]:
    size = 0
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha512 = hashlib.sha512()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            sha256.update(block)
            sha1.update(block)
            sha512.update(block)
    integrity = "sha512-" + base64.b64encode(sha512.digest()).decode("ascii")
    return size, sha256.hexdigest(), sha1.hexdigest(), integrity


def _keccak256(raw: bytes) -> str:
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:  # pragma: no cover - release environment invariant
        raise ReleaseEvidenceError(
            "runtime verification requires pycryptodome for Ethereum Keccak-256"
        ) from exc
    digest = keccak.new(digest_bits=256)
    digest.update(raw)
    return "0x" + digest.hexdigest()


def _runtime(value: object) -> tuple[str, bytes]:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"0x[0-9a-f]+", value)
        or len(value) <= 2
        or len(value) % 2
    ):
        raise ReleaseEvidenceError("deployed runtime_code must be non-empty lowercase hex")
    raw = bytes.fromhex(value[2:])
    if not any(raw):
        raise ReleaseEvidenceError("deployed runtime_code must not be all zeroes")
    return value, raw


def _package_json_from_tgz(path: Path, label: str) -> dict[str, Any]:
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_TARBALL_MEMBERS:
                raise ReleaseEvidenceError(f"{label} contains too many members")
            package_members = []
            seen: set[str] = set()
            for member in members:
                name = member.name
                parts = PurePosixPath(name).parts
                if not parts or PurePosixPath(name).is_absolute() or ".." in parts:
                    raise ReleaseEvidenceError(f"{label} contains unsafe member {name!r}")
                if name in seen:
                    raise ReleaseEvidenceError(f"{label} contains duplicate member {name!r}")
                seen.add(name)
                if member.issym() or member.islnk() or member.isdev():
                    raise ReleaseEvidenceError(f"{label} contains unsupported member {name!r}")
                if name == "package/package.json":
                    package_members.append(member)
            if len(package_members) != 1:
                raise ReleaseEvidenceError(f"{label} must contain exactly one package/package.json")
            member = package_members[0]
            if not member.isfile() or member.size > MAX_PACKAGE_JSON_BYTES:
                raise ReleaseEvidenceError(f"{label} contains an invalid package/package.json")
            handle = archive.extractfile(member)
            if handle is None:
                raise ReleaseEvidenceError(f"cannot read {label} package/package.json")
            raw = handle.read(MAX_PACKAGE_JSON_BYTES + 1)
            if len(raw) > MAX_PACKAGE_JSON_BYTES:
                raise ReleaseEvidenceError(f"{label} package/package.json is too large")
    except (tarfile.TarError, OSError) as exc:
        raise ReleaseEvidenceError(f"{label} is not a readable gzip tarball") from exc
    return _json_value(raw, f"{label} package/package.json")


def _validate_package(
    role: str, declared: object, tgz_path: Path
) -> dict[str, str]:
    if not isinstance(declared, dict):
        raise ReleaseEvidenceError(f"npm packages.{role} must be an object")
    _exact_keys(
        declared,
        {"name", "version", "filename", "size", "sha256", "npm_shasum", "npm_integrity"},
        f"npm packages.{role}",
    )
    filename = declared.get("filename")
    if not isinstance(filename, str) or not FILENAME_RE.fullmatch(filename):
        raise ReleaseEvidenceError(f"npm packages.{role}.filename is invalid")
    _regular_file(tgz_path, f"{role} tarball")
    if tgz_path.name != filename:
        raise ReleaseEvidenceError(
            f"{role} tarball filename {tgz_path.name!r} differs from metadata {filename!r}"
        )
    size, sha256, sha1, integrity = _file_digests(tgz_path)
    if (
        type(declared.get("size")) is not int
        or declared["size"] != size
        or not isinstance(declared.get("sha256"), str)
        or not SHA256_RE.fullmatch(declared["sha256"])
        or declared["sha256"] != sha256
        or not isinstance(declared.get("npm_shasum"), str)
        or not SHA1_RE.fullmatch(declared["npm_shasum"])
        or declared["npm_shasum"] != sha1
        or declared.get("npm_integrity") != integrity
    ):
        raise ReleaseEvidenceError(f"{role} tarball size or digest metadata does not match")
    package = _package_json_from_tgz(tgz_path, f"{role} tarball")
    name, version = declared.get("name"), declared.get("version")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(version, str)
        or not version
        or package.get("name") != name
        or package.get("version") != version
    ):
        raise ReleaseEvidenceError(f"{role} tarball package identity differs from metadata")
    return {"name": name, "version": version, "sha256": sha256}


def _validate_npm(
    metadata: dict[str, Any], source_commit: str, provider_tgz: Path, consumer_tgz: Path
) -> tuple[dict[str, dict[str, str]], str]:
    _exact_keys(metadata, {"schema", "source_commit", "provider_image", "packages"}, "npm metadata")
    if metadata.get("schema") != NPM_SCHEMA:
        raise ReleaseEvidenceError(f"npm metadata schema must be {NPM_SCHEMA}")
    if metadata.get("source_commit") != source_commit:
        raise ReleaseEvidenceError("npm metadata source_commit differs from the requested commit")
    image = metadata.get("provider_image")
    if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
        raise ReleaseEvidenceError("npm metadata provider_image is not an official digest pin")
    packages = metadata.get("packages")
    if not isinstance(packages, dict):
        raise ReleaseEvidenceError("npm metadata packages must be an object")
    _exact_keys(packages, {"provider", "consumer"}, "npm metadata packages")
    return {
        "provider": _validate_package("provider", packages["provider"], provider_tgz),
        "consumer": _validate_package("consumer", packages["consumer"], consumer_tgz),
    }, image


def _validate_oci(
    metadata: dict[str, Any], raw: bytes, source_commit: str, provider_image: str
) -> dict[str, str]:
    _exact_keys(metadata, {"schema", "image", "index_digest", "revision", "platforms"}, "OCI metadata")
    if metadata.get("schema") != OCI_SCHEMA:
        raise ReleaseEvidenceError(f"OCI metadata schema must be {OCI_SCHEMA}")
    image, digest = metadata.get("image"), metadata.get("index_digest")
    if (
        not isinstance(image, str)
        or not IMAGE_RE.fullmatch(image)
        or image != provider_image
        or not isinstance(digest, str)
        or not OCI_DIGEST_RE.fullmatch(digest)
        or image != f"ghcr.io/charleslzp/mycomesh-provider-codex@{digest}"
    ):
        raise ReleaseEvidenceError("OCI image/index digest differs from the npm Provider pin")
    if metadata.get("revision") != source_commit:
        raise ReleaseEvidenceError("OCI index revision differs from source_commit")
    items = metadata.get("platforms")
    if not isinstance(items, list) or len(items) != len(REQUIRED_PLATFORMS):
        raise ReleaseEvidenceError("OCI metadata must contain exactly amd64 and arm64 platforms")
    observed: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ReleaseEvidenceError(f"OCI platform {index} must be an object")
        _exact_keys(item, {"os", "architecture", "digest", "revision"}, f"OCI platform {index}")
        platform = f"{item.get('os')}/{item.get('architecture')}"
        child_digest = item.get("digest")
        if (
            platform in observed
            or platform not in REQUIRED_PLATFORMS
            or not isinstance(child_digest, str)
            or not OCI_DIGEST_RE.fullmatch(child_digest)
            or item.get("revision") != source_commit
        ):
            raise ReleaseEvidenceError(f"OCI platform {index} identity, digest, or revision is invalid")
        observed.add(platform)
    if observed != REQUIRED_PLATFORMS:
        raise ReleaseEvidenceError("OCI metadata does not cover the required platforms")
    return {"image": image, "index_digest": digest, "metadata_sha256": _sha256_bytes(raw)}


def _validate_manifests(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    paths = {
        "deployment_manifest_sha256": root / DEPLOYMENT_PATH,
        "provider_network_manifest_sha256": root / PROVIDER_NETWORK_PATH,
        "consumer_network_manifest_sha256": root / CONSUMER_NETWORK_PATH,
    }
    values: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    for field, path in paths.items():
        value, raw = _load_json(path, str(path.relative_to(root)))
        values[field] = value
        hashes[field] = _sha256_bytes(raw)
        if value.get("protocol_version") != 10:
            raise ReleaseEvidenceError(f"{path.relative_to(root)} is not a V10 manifest")
    deployment = values["deployment_manifest_sha256"]
    provider = values["provider_network_manifest_sha256"]
    consumer = values["consumer_network_manifest_sha256"]
    if provider.get("deployment") != DEPLOYMENT_PATH.name:
        raise ReleaseEvidenceError("Provider network manifest references the wrong deployment")
    shared = set(deployment) & set(provider)
    drift = sorted(key for key in shared if deployment[key] != provider[key])
    if drift:
        raise ReleaseEvidenceError(f"Provider/deployment manifest bindings drift: {drift}")
    provider_payload = {
        key: value for key, value in provider.items() if key not in {"deployment", "tls_ca_file"}
    }
    expected_consumer = {**deployment, **provider_payload}
    actual_consumer = {key: value for key, value in consumer.items() if key != "tls_ca_file"}
    if actual_consumer != expected_consumer:
        raise ReleaseEvidenceError("Consumer V10 manifest is not the deployment/provider semantic union")
    return deployment, provider, hashes


def _abi_word(value: Any, label: str) -> bytes:
    if type(value) is bool:
        return int(value).to_bytes(32, "big")
    if type(value) is int and 0 <= value < 2**256:
        return value.to_bytes(32, "big")
    if isinstance(value, str) and ADDRESS_RE.fullmatch(value):
        return b"\0" * 12 + bytes.fromhex(value[2:])
    if isinstance(value, str) and HASH_RE.fullmatch(value):
        return bytes.fromhex(value[2:])
    raise ReleaseEvidenceError(f"{label} cannot be encoded as an ABI word")


def _expected_domain_separator(deployment: dict[str, Any]) -> str:
    name, version = deployment.get("eip712_name"), deployment.get("eip712_version")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise ReleaseEvidenceError("deployment EIP-712 domain is incomplete")
    words = (
        bytes.fromhex(_keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        )[2:]),
        bytes.fromhex(_keccak256(name.encode())[2:]),
        bytes.fromhex(_keccak256(version.encode())[2:]),
        _abi_word(deployment.get("chain_id"), "deployment chain_id"),
        _abi_word(deployment.get("settlement"), "deployment settlement"),
    )
    return _keccak256(b"".join(words))


def _capacity_channel_id(channel: dict[str, Any], domain_separator: str) -> str:
    typehash = _keccak256(
        b"OpenCapacityChannel(address consumerOwner,address consumerKey,address providerOwner,"
        b"address providerSigner,address relay,address relaySigner,address pool,bytes32 channel,"
        b"uint64 pricingVersion,bytes32 pricingHash,uint256 capacity,uint256 maxFeePerRequest,"
        b"uint64 validFrom,uint64 admitUntil,uint64 claimUntil,uint256 consumerNonce,"
        b"uint256 providerNonce,uint64 permitDeadline)"
    )
    fields = (
        "consumer_owner", "consumer_key", "provider_owner", "provider_signer",
        "relay", "relay_signer", "pool", "channel_hash", "pricing_version",
        "pricing_hash", "capacity", "max_fee_per_request", "valid_from",
        "admit_until", "claim_until", "consumer_nonce", "provider_nonce",
        "permit_deadline",
    )
    words = [bytes.fromhex(typehash[2:]), *(
        _abi_word(channel.get(name), f"capacity channel {name}") for name in fields
    )]
    struct_hash = bytes.fromhex(_keccak256(b"".join(words))[2:])
    return _keccak256(
        b"\x19\x01" + bytes.fromhex(domain_separator[2:]) + struct_hash
    )


def _validate_contract_state(state: Any, deployment: dict[str, Any]) -> int:
    if not isinstance(state, dict):
        raise ReleaseEvidenceError("deployed-code contract_state must be an object")
    scalar_keys = {
        "stablecoin", "reward_token", "adjudication_threshold", "governance",
        "treasury", "domain_separator", "adjudicators", "policy", "channel",
        "max_channel_duration_seconds",
        "stablecoin_runtime_code_sha256", "stablecoin_runtime_code_keccak256",
        "stablecoin_balance", "stable_liabilities",
    }
    _exact_keys(state, scalar_keys, "deployed-code contract_state")
    expected = {
        "stablecoin": deployment.get("stablecoin"),
        "reward_token": deployment.get("reward_token"),
        "adjudication_threshold": deployment.get("adjudication_threshold"),
        "governance": deployment.get("governance"),
        "treasury": deployment.get("treasury"),
        "domain_separator": _expected_domain_separator(deployment),
        "max_channel_duration_seconds": deployment.get("max_channel_duration_seconds"),
        "adjudicators": deployment.get("adjudicators"),
        "policy": deployment.get("policy"),
        "stablecoin_runtime_code_sha256": deployment.get(
            "stablecoin_runtime_code_sha256"
        ),
        "stablecoin_runtime_code_keccak256": deployment.get(
            "stablecoin_runtime_code_keccak256"
        ),
    }
    if any(state.get(key) != value for key, value in expected.items()):
        raise ReleaseEvidenceError("deployed-code contract_state differs from the manifest")
    expected_policy = deployment.get("policy")
    observed_policy = state.get("policy")
    if (
        not isinstance(expected_policy, dict) or not isinstance(observed_policy, dict)
        or set(observed_policy) != set(expected_policy)
        or any(type(observed_policy[key]) is not type(value)
               for key, value in expected_policy.items())
    ):
        raise ReleaseEvidenceError("deployed-code dispute policy has noncanonical types")
    if (
        type(state.get("stable_liabilities")) is not int
        or state["stable_liabilities"] <= 0
        or type(state.get("stablecoin_balance")) is not int
        or state["stablecoin_balance"] < state["stable_liabilities"]
    ):
        raise ReleaseEvidenceError("deployed-code settlement is not stably solvent")
    channel = state.get("channel")
    if not isinstance(channel, dict):
        raise ReleaseEvidenceError("deployed-code contract channel must be an object")
    channel_keys = {
        "channel_hash", "pricing_version", "pricing_hash", "treasury",
        "input_per_1k", "output_per_1k", "minimum_fee", "provider_bps",
        "relay_bps", "pool_bps", "treasury_bps", "active",
    }
    _exact_keys(channel, channel_keys, "deployed-code contract channel")
    if (
        channel.get("channel_hash") != deployment.get("channel_hash")
        or type(channel.get("pricing_version")) is not int
        or not 0 < channel["pricing_version"] < 2**64
        or channel["pricing_version"] != deployment.get("pricing_version")
        or channel.get("pricing_hash") != deployment.get("pricing_hash")
        or channel.get("treasury") != deployment.get("treasury")
        or channel.get("active") is not True
    ):
        raise ReleaseEvidenceError("deployed-code pricing channel differs from the manifest")
    numeric_names = (
        "input_per_1k", "output_per_1k", "minimum_fee", "provider_bps",
        "relay_bps", "pool_bps", "treasury_bps",
    )
    if any(type(channel.get(name)) is not int or channel[name] < 0 for name in numeric_names):
        raise ReleaseEvidenceError("deployed-code pricing channel contains invalid numbers")
    if sum(channel[name] for name in (
        "provider_bps", "relay_bps", "pool_bps", "treasury_bps",
    )) != 10_000:
        raise ReleaseEvidenceError("deployed-code pricing channel basis points do not sum to 10000")
    if channel["minimum_fee"] <= 0:
        raise ReleaseEvidenceError("deployed-code pricing channel has no positive minimum fee")
    pricing_words = [
        _abi_word(channel["channel_hash"], "channel hash"),
        _abi_word(channel["pricing_version"], "pricing version"),
        _abi_word(channel["treasury"], "channel treasury"),
        *(_abi_word(channel[name], f"channel {name}") for name in numeric_names),
        _abi_word(channel["active"], "channel active"),
    ]
    if _keccak256(b"".join(pricing_words)) != channel["pricing_hash"]:
        raise ReleaseEvidenceError("deployed-code pricing_hash does not bind the channel config")
    return channel["minimum_fee"]


def _validate_capacity_channels(
    channels: Any, deployment: dict[str, Any], provider_network: dict[str, Any],
    state_block_number: int, state_block_timestamp: int, minimum_fee: int,
) -> None:
    ids = deployment.get("capacity_channel_ids")
    transactions = deployment.get("fresh_channel_open_tx_hashes")
    open_timestamps = deployment.get("fresh_channel_open_block_timestamps")
    if (
        not isinstance(channels, list) or not isinstance(ids, list)
        or not isinstance(transactions, list) or not isinstance(open_timestamps, list)
        or len(channels) != len(ids) or len(ids) != len(transactions)
        or len(ids) != len(open_timestamps) or not channels
    ):
        raise ReleaseEvidenceError("deployed-code capacity channel evidence is incomplete")
    relay_entries = [provider_network.get("relay")]
    fallbacks = provider_network.get("relay_fallbacks")
    if isinstance(fallbacks, list):
        relay_entries.extend(fallbacks)
    relay_identities = {
        (entry.get("payment_address"), entry.get("attestation_address"))
        for entry in relay_entries if isinstance(entry, dict)
    }
    channel_keys = {
        "channel_id", "transaction_hash", "block_number", "block_hash",
        "open_block_timestamp",
        "consumer_owner", "consumer_key", "provider_owner", "provider_signer",
        "relay", "relay_signer", "pool", "channel_hash", "pricing_hash",
        "pricing_version", "capacity", "max_fee_per_request", "valid_from",
        "admit_until", "claim_until", "consumer_nonce", "provider_nonce",
        "permit_deadline", "settled_max_fee", "credit_remaining",
        "stake_remaining", "closed",
    }
    deployment_block = deployment.get("deployment_block")
    expected_numbers = {
        "capacity": deployment.get("fresh_channel_capacity"),
        "max_fee_per_request": deployment.get("fresh_channel_max_fee_per_request"),
        "valid_from": deployment.get("fresh_channel_valid_from"),
        "admit_until": deployment.get("fresh_channel_admit_until"),
        "claim_until": deployment.get("fresh_channel_claim_until"),
        "pricing_version": deployment.get("pricing_version"),
    }
    domain_separator = _expected_domain_separator(deployment)
    for index, channel in enumerate(channels):
        if not isinstance(channel, dict):
            raise ReleaseEvidenceError(f"deployed-code capacity channel {index} is not an object")
        _exact_keys(channel, channel_keys, f"deployed-code capacity channel {index}")
        if (
            channel.get("channel_id") != ids[index]
            or channel.get("transaction_hash") != transactions[index]
            or channel.get("open_block_timestamp") != open_timestamps[index]
            or channel.get("channel_hash") != deployment.get("channel_hash")
            or channel.get("pricing_hash") != deployment.get("pricing_hash")
            or any(channel.get(name) != value for name, value in expected_numbers.items())
            or (channel.get("relay"), channel.get("relay_signer")) not in relay_identities
            or channel.get("closed") is not False
        ):
            raise ReleaseEvidenceError(f"deployed-code capacity channel {index} differs from manifests")
        for name in expected_numbers:
            if type(channel.get(name)) is not int or not 0 <= channel[name] < 2**256:
                raise ReleaseEvidenceError(
                    f"deployed-code capacity channel {index} has noncanonical {name}"
                )
        for name in ("pricing_version", "valid_from", "admit_until", "claim_until"):
            if channel[name] >= 2**64:
                raise ReleaseEvidenceError(
                    f"deployed-code capacity channel {index} overflows {name}"
                )
        for name in (
            "consumer_owner", "consumer_key", "provider_owner", "provider_signer",
            "relay", "relay_signer", "pool",
        ):
            value = channel.get(name)
            if (
                not isinstance(value, str) or not ADDRESS_RE.fullmatch(value)
                or (name != "pool" and value == "0x" + "0" * 40)
            ):
                raise ReleaseEvidenceError(f"deployed-code capacity channel {index} has invalid {name}")
        if (
            type(channel.get("block_number")) is not int
            or not deployment_block <= channel["block_number"] <= state_block_number
            or not isinstance(channel.get("block_hash"), str)
            or not HASH_RE.fullmatch(channel["block_hash"])
        ):
            raise ReleaseEvidenceError(f"deployed-code capacity channel {index} has invalid block identity")
        open_timestamp = channel.get("open_block_timestamp")
        maximum_duration = deployment.get("max_channel_duration_seconds")
        if (
            type(open_timestamp) is not int
            or not 0 < open_timestamp <= state_block_timestamp
            or open_timestamp >= channel["valid_from"]
            or type(maximum_duration) is not int
            or channel["claim_until"] - open_timestamp > maximum_duration
        ):
            raise ReleaseEvidenceError(
                f"deployed-code capacity channel {index} has an invalid duration"
            )
        for name in (
            "consumer_nonce", "provider_nonce", "permit_deadline", "settled_max_fee",
            "credit_remaining", "stake_remaining",
        ):
            if type(channel.get(name)) is not int or channel[name] < 0:
                raise ReleaseEvidenceError(f"deployed-code capacity channel {index} has invalid {name}")
        if channel["permit_deadline"] >= 2**64:
            raise ReleaseEvidenceError(
                f"deployed-code capacity channel {index} permit deadline overflows uint64"
            )
        if _capacity_channel_id(channel, domain_separator) != channel["channel_id"]:
            raise ReleaseEvidenceError(
                f"deployed-code capacity channel {index} ID does not bind its configuration"
            )
        capacity = channel["capacity"]
        maximum = channel["max_fee_per_request"]
        if (
            channel["settled_max_fee"] + maximum > capacity
            or not maximum <= channel["credit_remaining"] <= capacity
            or not maximum <= channel["stake_remaining"] <= capacity
            or maximum < minimum_fee
        ):
            raise ReleaseEvidenceError(f"deployed-code capacity channel {index} is not usable")


def _validate_deployed_code(
    evidence: dict[str, Any], raw: bytes, source_commit: str,
    deployment: dict[str, Any], provider_network: dict[str, Any],
    manifest_hash: str, provider_network_hash: str,
) -> dict[str, Any]:
    expected_keys = {
        "schema", "source_commit", "chain_id", "address", "transaction_hash",
        "block_number", "block_hash", "runtime_code", "runtime_code_sha256",
        "runtime_code_keccak256", "confirmations", "rpc_quorum",
        "deployment_manifest_sha256", "provider_network_manifest_sha256",
        "deployer", "state_block_number", "state_block_hash",
        "state_block_timestamp", "contract_state", "capacity_channels",
    }
    _exact_keys(evidence, expected_keys, "deployed-code evidence")
    if evidence.get("schema") != DEPLOYED_CODE_SCHEMA:
        raise ReleaseEvidenceError(f"deployed-code schema must be {DEPLOYED_CODE_SCHEMA}")
    if evidence.get("source_commit") != source_commit:
        raise ReleaseEvidenceError("deployed-code source_commit differs from the requested commit")
    identity = {
        "chain_id": deployment.get("chain_id"),
        "address": deployment.get("settlement"),
        "transaction_hash": deployment.get("tx_hash"),
        "block_number": deployment.get("deployment_block"),
    }
    if (
        type(identity["chain_id"]) is not int
        or identity["chain_id"] <= 0
        or not isinstance(identity["address"], str)
        or not ADDRESS_RE.fullmatch(identity["address"])
        or identity["address"] == "0x" + "0" * 40
        or not isinstance(identity["transaction_hash"], str)
        or not HASH_RE.fullmatch(identity["transaction_hash"])
        or type(identity["block_number"]) is not int
        or identity["block_number"] < 0
        or any(evidence.get(key) != value for key, value in identity.items())
    ):
        raise ReleaseEvidenceError("deployed-code identity differs from the deployment manifest")
    if not isinstance(evidence.get("block_hash"), str) or not HASH_RE.fullmatch(evidence["block_hash"]):
        raise ReleaseEvidenceError("deployed-code block_hash is invalid")
    if (
        type(evidence.get("confirmations")) is not int
        or evidence["confirmations"] < 2
        or type(evidence.get("rpc_quorum")) is not int
        or evidence["rpc_quorum"] < 2
    ):
        raise ReleaseEvidenceError("deployed-code evidence requires confirmations and RPC quorum >= 2")
    if evidence.get("deployment_manifest_sha256") != manifest_hash:
        raise ReleaseEvidenceError("deployed-code deployment manifest hash differs from repository bytes")
    if evidence.get("provider_network_manifest_sha256") != provider_network_hash:
        raise ReleaseEvidenceError(
            "deployed-code Provider network manifest hash differs from repository bytes"
        )
    if evidence.get("deployer") != deployment.get("deployer"):
        raise ReleaseEvidenceError("deployed-code deployer differs from the deployment manifest")
    state_block_number = evidence.get("state_block_number")
    state_block_timestamp = evidence.get("state_block_timestamp")
    valid_from = deployment.get("fresh_channel_valid_from")
    admit_until = deployment.get("fresh_channel_admit_until")
    if (
        type(state_block_number) is not int
        or state_block_number < identity["block_number"]
        or not isinstance(evidence.get("state_block_hash"), str)
        or not HASH_RE.fullmatch(evidence["state_block_hash"])
        or type(state_block_timestamp) is not int
        or type(valid_from) is not int or type(admit_until) is not int
        or not valid_from <= state_block_timestamp < admit_until
    ):
        raise ReleaseEvidenceError("deployed-code confirmed state block is invalid or unusable")
    minimum_fee = _validate_contract_state(evidence.get("contract_state"), deployment)
    _validate_capacity_channels(
        evidence.get("capacity_channels"), deployment, provider_network,
        state_block_number, state_block_timestamp, minimum_fee,
    )
    _, runtime = _runtime(evidence.get("runtime_code"))
    runtime_sha256 = hashlib.sha256(runtime).hexdigest()
    runtime_keccak = _keccak256(runtime)
    if (
        evidence.get("runtime_code_sha256") != runtime_sha256
        or evidence.get("runtime_code_keccak256") != runtime_keccak
    ):
        raise ReleaseEvidenceError("deployed-code runtime hashes do not match runtime_code")
    return {
        **identity,
        "deployed_code_evidence_sha256": _sha256_bytes(raw),
        "runtime_code_sha256": runtime_sha256,
        "runtime_code_keccak256": runtime_keccak,
    }


def _validate_foundry_artifact(artifact: dict[str, Any], raw: bytes) -> dict[str, str]:
    abi = artifact.get("abi")
    if not isinstance(abi, list) or not all(isinstance(item, dict) for item in abi):
        raise ReleaseEvidenceError("Foundry artifact must contain an ABI array")
    functions = {
        item.get("name") for item in abi
        if item.get("type") == "function" and isinstance(item.get("name"), str)
    }
    required = {
        "MAX_CHANNEL_DURATION", "openCapacityChannels",
        "settleReservedReceipt", "voteDisputeBySig",
    }
    if not required.issubset(functions):
        raise ReleaseEvidenceError(f"Foundry ABI is missing functions: {sorted(required - functions)}")
    deployed = artifact.get("deployedBytecode")
    if not isinstance(deployed, dict):
        raise ReleaseEvidenceError("Foundry artifact must contain deployedBytecode")
    bytecode = deployed.get("object")
    references = deployed.get("immutableReferences")
    if (
        not isinstance(bytecode, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]+", bytecode)
        or len(bytecode) <= 2
        or len(bytecode) % 2
        or not isinstance(references, dict)
        or not references
    ):
        raise ReleaseEvidenceError("Foundry deployed bytecode or immutable references are invalid")
    canonical = json.dumps(
        abi, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return {
        "abi_artifact_sha256": _sha256_bytes(raw),
        "abi_sha256": _sha256_bytes(canonical),
    }


def build_release_evidence(
    *, root: Path, source_commit: str, npm_metadata_path: Path,
    provider_tgz: Path, consumer_tgz: Path, oci_metadata_path: Path,
    deployed_code_path: Path, foundry_artifact_path: Path,
) -> dict[str, Any]:
    if root.is_symlink():
        raise ReleaseEvidenceError("root must be a regular repository directory")
    root = root.resolve()
    if not root.is_dir():
        raise ReleaseEvidenceError("root must be a regular repository directory")
    if not COMMIT_RE.fullmatch(source_commit):
        raise ReleaseEvidenceError("source_commit must be lowercase 40-character hex")
    npm, _ = _load_json(npm_metadata_path, "npm release candidate metadata")
    oci, oci_raw = _load_json(oci_metadata_path, "OCI metadata")
    deployed, deployed_raw = _load_json(deployed_code_path, "deployed-code evidence")
    artifact, artifact_raw = _load_json(foundry_artifact_path, "Foundry V10 artifact")

    packages, provider_image = _validate_npm(
        npm, source_commit, provider_tgz, consumer_tgz
    )
    oci_declaration = _validate_oci(oci, oci_raw, source_commit, provider_image)
    deployment, provider_network, manifest_hashes = _validate_manifests(root)
    contract = _validate_deployed_code(
        deployed, deployed_raw, source_commit, deployment, provider_network,
        manifest_hashes["deployment_manifest_sha256"],
        manifest_hashes["provider_network_manifest_sha256"],
    )
    contract.update(_validate_foundry_artifact(artifact, artifact_raw))
    contract.update(manifest_hashes)
    return {
        "schema": RELEASE_SCHEMA,
        "source_commit": source_commit,
        "packages": packages,
        "oci": oci_declaration,
        "contract": contract,
    }


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ReleaseEvidenceError(f"output parent must already be a regular directory: {parent}")
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--npm-metadata", type=Path, required=True)
    parser.add_argument("--provider-tgz", type=Path, required=True)
    parser.add_argument("--consumer-tgz", type=Path, required=True)
    parser.add_argument("--oci-metadata", type=Path, required=True)
    parser.add_argument("--deployed-code-evidence", type=Path, required=True)
    parser.add_argument("--foundry-artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        evidence = build_release_evidence(
            root=args.root,
            source_commit=args.source_commit,
            npm_metadata_path=args.npm_metadata,
            provider_tgz=args.provider_tgz,
            consumer_tgz=args.consumer_tgz,
            oci_metadata_path=args.oci_metadata,
            deployed_code_path=args.deployed_code_evidence,
            foundry_artifact_path=args.foundry_artifact,
        )
        _write_exclusive(args.output, evidence)
    except (ReleaseEvidenceError, OSError, tarfile.TarError) as exc:
        print(f"build release evidence: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"output": str(args.output), "schema": RELEASE_SCHEMA}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
