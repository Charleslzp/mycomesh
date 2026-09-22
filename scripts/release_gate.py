#!/usr/bin/env python3
"""Dependency-free checks for the source side of a MycoMesh release.

This gate validates repository wiring, package metadata, and the consistency of
the checked-in V10 manifests. It deliberately does not claim to verify a
published npm tarball, an OCI image/revision, a signature, or live chain code;
those facts only exist after build/deploy and need a separate artifact gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
PROVIDER_IMAGE_RE = re.compile(
    r"^ghcr\.io/charleslzp/mycomesh-provider-codex@sha256:[0-9a-f]{64}$"
)
FORBIDDEN_PARTS = {"artifacts", "out", "cache", "__pycache__", "test-results"}

DEPLOYMENT_PATH = "deployments/sepolia-myco-v10.json"
PROVIDER_NETWORK_PATH = "deployments/sepolia-provider-network-v10.json"
CONSUMER_NETWORK_PATH = "packages/mycomesh-cli/networks/v10-controlled-test.json"

REQUIRED_RELEASE_FILES = (
    DEPLOYMENT_PATH,
    PROVIDER_NETWORK_PATH,
    "deployments/ip-mesh-testnet-ca.crt",
    "contracts/MycoSettlementV9.sol",
    "contracts/MycoSettlementV10.sol",
    "docs/v9-deployment-policy.draft.json",
    "scripts/build_release_evidence.py",
    "scripts/capture_oci_metadata.py",
    "scripts/capture_release_evidence.py",
    "scripts/stage-npm-release.mjs",
    CONSUMER_NETWORK_PATH,
    "packages/mycomesh-cli/networks/v10-controlled-test.ca.crt",
)

ARTIFACT_SCHEMA = "mycomesh.release-artifacts.v1"
OCI_METADATA_SCHEMA = "mycomesh.oci-metadata.v1"
DEPLOYED_CODE_SCHEMA = "mycomesh.deployed-code.v2"
REQUIRED_PLATFORMS = frozenset(("linux/amd64", "linux/arm64"))
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_TARBALL_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TARBALL_MEMBERS = 4096
MAX_TARBALL_TOTAL_BYTES = 64 * 1024 * 1024


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _tracked(root: Path) -> list[str]:
    # Include non-ignored new files so a development checkout can validate a
    # newly added release tool before it is committed.  In CI's clean checkout
    # every returned path is necessarily tracked.
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True,
        capture_output=True,
    )
    return [item for item in result.stdout.decode().split("\0") if item]


def _add(checks: list[dict[str, object]], name: str, ok: object, detail: object) -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant: {value}")


def _load_json(
    root: Path, relative: str, checks: list[dict[str, object]]
) -> dict[str, Any] | None:
    try:
        value = json.loads(
            _read(root, relative),
            object_pairs_hook=_strict_object,
            parse_constant=_invalid_constant,
        )
        if not isinstance(value, dict):
            raise ValueError("top-level JSON value must be an object")
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        _add(checks, f"json:{relative}", False, str(exc))
        return None
    _add(checks, f"json:{relative}", True, relative)
    return value


def _load_text(
    root: Path, relative: str, checks: list[dict[str, object]]
) -> str | None:
    try:
        return _read(root, relative)
    except (OSError, UnicodeError) as exc:
        _add(checks, f"read:{relative}", False, str(exc))
        return None


def _constant(source: str | None, pattern: str) -> tuple[str | None, str]:
    matches = [] if source is None else re.findall(pattern, source)
    if len(matches) != 1:
        return None, "missing" if not matches else "ambiguous"
    return matches[0], matches[0]


def _release_pin(source: str | None, name: str) -> tuple[str | None, str]:
    matches = [] if source is None else re.findall(
        rf"{re.escape(name)}\s*=\s*(null|\"[^\"]*\")\s*;",
        source,
    )
    if len(matches) != 1:
        return None, "missing" if not matches else "ambiguous"
    token = matches[0]
    if token == "null":
        return None, "unbound"
    return token[1:-1], token[1:-1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _nested(value: object, *keys: str) -> object | None:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _file_entries(package: dict[str, Any] | None) -> set[str]:
    raw = package.get("files") if package else None
    if not isinstance(raw, list) or not all(isinstance(value, str) for value in raw):
        return set()
    return set(raw)


def _read_bounded(path: Path, maximum: int = MAX_EVIDENCE_BYTES) -> bytes:
    with path.open("rb") as handle:
        value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError(f"file exceeds {maximum} bytes")
    return value


def _json_bytes(raw: bytes) -> dict[str, Any]:
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_invalid_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value must be an object")
    return value


def _external_json(
    path: Path | None,
    label: str,
    checks: list[dict[str, object]],
) -> tuple[dict[str, Any] | None, bytes | None]:
    if path is None:
        _add(checks, f"artifact-input:{label}", False, "missing required path")
        return None, None
    if path.is_symlink():
        _add(checks, f"artifact-input:{label}", False, f"symbolic link refused: {path}")
        return None, None
    resolved = path.resolve()
    if not resolved.is_file():
        _add(checks, f"artifact-input:{label}", False, f"not a regular file: {resolved}")
        return None, None
    try:
        raw = _read_bounded(resolved)
        value = _json_bytes(raw)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        _add(checks, f"artifact-input:{label}", False, str(exc))
        return None, None
    _add(checks, f"artifact-input:{label}", True, str(resolved))
    return value, raw


def _required_file(
    path: Path | None,
    label: str,
    checks: list[dict[str, object]],
) -> Path | None:
    if path is None:
        _add(checks, f"artifact-input:{label}", False, "missing required path")
        return None
    symlink = path.is_symlink()
    resolved = path.resolve()
    ok = not symlink and resolved.is_file()
    _add(checks, f"artifact-input:{label}", ok, str(resolved))
    return resolved if ok else None


def _git_head(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if COMMIT_RE.fullmatch(value) else None


def _tarball_files(path: Path, wanted: set[str] | None = None) -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_TARBALL_MEMBERS:
            raise ValueError("tarball contains too many members")
        for member in members:
            name = member.name
            parts = PurePosixPath(name).parts
            if PurePosixPath(name).is_absolute() or ".." in parts or not parts:
                raise ValueError(f"unsafe tar member: {name}")
            if name in seen:
                raise ValueError(f"duplicate tar member: {name}")
            seen.add(name)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"unsupported tar member: {name}")
            if member.isdir():
                continue
            if wanted is not None and name not in wanted:
                continue
            if not member.isfile() or member.size > MAX_TARBALL_MEMBER_BYTES:
                raise ValueError(f"invalid required tar member: {name}")
            total += member.size
            if total > MAX_TARBALL_TOTAL_BYTES:
                raise ValueError("tarball uncompressed content exceeds the safety limit")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot read tar member: {name}")
            raw = extracted.read(MAX_TARBALL_MEMBER_BYTES + 1)
            if len(raw) > MAX_TARBALL_MEMBER_BYTES:
                raise ValueError(f"tar member too large: {name}")
            values[name] = raw
    return values


def _package_source_files(root: Path, role: str) -> dict[str, bytes]:
    base = root if role == "provider" else root / "packages/mycomesh-cli"
    package = _json_bytes((base / "package.json").read_bytes())
    entries = package.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("package files list is missing")
    selected: set[Path] = {base / "package.json"}
    for entry in entries:
        if (not isinstance(entry, str) or not entry or Path(entry).is_absolute()
                or ".." in Path(entry).parts or any(char in entry for char in "*?[]")):
            raise ValueError(f"unsupported package files entry: {entry!r}")
        source = base / entry
        if source.is_symlink() or not source.exists():
            raise ValueError(f"package source is missing or symbolic: {entry}")
        if source.is_dir():
            for child in source.rglob("*"):
                if child.is_symlink():
                    raise ValueError(f"package source contains a symbolic link: {child}")
                if child.is_file():
                    selected.add(child)
        elif source.is_file():
            selected.add(source)
        else:
            raise ValueError(f"package source is not a regular file: {entry}")
    automatic = re.compile(r"^(?:readme|license|licence|notice|changelog)(?:\..*)?$", re.I)
    for child in base.iterdir():
        if child.is_file() and not child.is_symlink() and automatic.fullmatch(child.name):
            selected.add(child)
    return {
        "package/" + source.relative_to(base).as_posix(): source.read_bytes()
        for source in selected
    }


def _canonical_abi(raw: bytes) -> tuple[str, str, set[str]]:
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_invalid_constant,
    )
    abi = value.get("abi") if isinstance(value, dict) else value
    if not isinstance(abi, list) or not all(isinstance(item, dict) for item in abi):
        raise ValueError("ABI artifact must be an ABI array or contain an ABI array")
    canonical = json.dumps(
        abi,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    functions = {
        str(item.get("name")) for item in abi
        if item.get("type") == "function" and isinstance(item.get("name"), str)
    }
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(canonical).hexdigest(), functions


def _compiled_runtime(
    raw: bytes,
) -> tuple[bytes, tuple[tuple[tuple[int, int], ...], ...]]:
    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_strict_object,
        parse_constant=_invalid_constant,
    )
    deployed = value.get("deployedBytecode") if isinstance(value, dict) else None
    if not isinstance(deployed, dict):
        raise ValueError("compiler artifact must contain deployedBytecode")
    template = _hex_runtime(deployed.get("object"))
    references = deployed.get("immutableReferences")
    if not isinstance(references, dict) or not references:
        raise ValueError("compiler artifact must contain immutableReferences")
    if len(references) != 5:
        raise ValueError("V10 compiler artifact must contain exactly five immutable variables")
    groups: list[tuple[tuple[int, int], ...]] = []
    ranges: list[tuple[int, int]] = []
    for entries in references.values():
        if not isinstance(entries, list) or not entries:
            raise ValueError("compiler immutableReferences entry must be a non-empty list")
        group: list[tuple[int, int]] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"start", "length"}:
                raise ValueError("compiler immutable reference must contain start and length")
            start, length = entry["start"], entry["length"]
            if (type(start) is not int or type(length) is not int or start < 0 or length != 32
                    or start + length > len(template)):
                raise ValueError("compiler immutable reference must be one in-bounds ABI word")
            ranges.append((start, length))
            group.append((start, length))
        groups.append(tuple(sorted(group)))
    ranges.sort()
    previous_end = -1
    for start, length in ranges:
        if start < previous_end:
            raise ValueError("compiler immutable references overlap")
        previous_end = start + length
    return template, tuple(groups)


def _keccak_bytes(raw: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:  # pragma: no cover - exercised in minimal release images
        raise RuntimeError("strict runtime verification requires pycryptodome") from exc
    digest = keccak.new(digest_bits=256)
    digest.update(raw)
    return digest.digest()


def _expected_immutable_values(deployment: dict[str, Any]) -> dict[str, bytes]:
    def address_word(field: str) -> bytes:
        value = deployment.get(field)
        if not isinstance(value, str) or ADDRESS_RE.fullmatch(value) is None:
            raise ValueError(f"deployment {field} is not a canonical address")
        return b"\0" * 12 + bytes.fromhex(value[2:])

    chain_id = deployment.get("chain_id")
    threshold = deployment.get("adjudication_threshold")
    name = deployment.get("eip712_name")
    version = deployment.get("eip712_version")
    settlement = deployment.get("settlement")
    if type(chain_id) is not int or chain_id <= 0 or chain_id >= 2**256:
        raise ValueError("deployment chain_id cannot be encoded as uint256")
    if type(threshold) is not int or not 2 <= threshold < 2**16:
        raise ValueError("deployment adjudication_threshold cannot be encoded as uint16")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise ValueError("deployment EIP-712 name/version are missing")
    if not isinstance(settlement, str) or ADDRESS_RE.fullmatch(settlement) is None:
        raise ValueError("deployment settlement is not a canonical address")
    domain_words = (
        _keccak_bytes(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        _keccak_bytes(name.encode("utf-8")),
        _keccak_bytes(version.encode("utf-8")),
        chain_id.to_bytes(32, "big"),
        b"\0" * 12 + bytes.fromhex(settlement[2:]),
    )
    values = {
        "stablecoin": address_word("stablecoin"),
        "reward_token": address_word("reward_token"),
        "adjudication_threshold": threshold.to_bytes(32, "big"),
        "initial_chain_id": chain_id.to_bytes(32, "big"),
        "initial_domain_separator": _keccak_bytes(b"".join(domain_words)),
    }
    if len(set(values.values())) != len(values):
        raise ValueError("deployment immutable values are unexpectedly ambiguous")
    return values


def _verify_runtime_immutables(
    template: bytes,
    runtime: bytes,
    groups: tuple[tuple[tuple[int, int], ...], ...],
    deployment: dict[str, Any],
) -> dict[str, str]:
    if len(runtime) != len(template):
        raise ValueError("deployed runtime length differs from compiler artifact")
    expected = _expected_immutable_values(deployment)
    expected_by_value = {value: name for name, value in expected.items()}
    matched: dict[str, str] = {}
    patched = bytearray(template)
    for group in groups:
        observed_values: set[bytes] = set()
        for start, length in group:
            if template[start:start + length] != b"\0" * length:
                raise ValueError("compiler immutable placeholder is not zero-filled")
            observed_values.add(runtime[start:start + length])
        if len(observed_values) != 1:
            raise ValueError("deployed references for one immutable disagree")
        observed = observed_values.pop()
        name = expected_by_value.get(observed)
        if name is None or name in matched:
            raise ValueError("deployed immutable does not match the deployment manifest")
        matched[name] = "0x" + observed.hex()
        for start, length in group:
            patched[start:start + length] = observed
    if set(matched) != set(expected):
        raise ValueError("compiler immutable set does not match the V10 deployment")
    if bytes(patched) != runtime:
        raise ValueError("deployed runtime differs from compiler output outside exact immutables")
    return matched


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing or unexpected:
        raise ValueError(f"{label} keys differ (missing={missing}, unexpected={unexpected})")


def _abi_word(value: Any, label: str) -> bytes:
    if type(value) is bool:
        return int(value).to_bytes(32, "big")
    if type(value) is int and 0 <= value < 2**256:
        return value.to_bytes(32, "big")
    if isinstance(value, str) and ADDRESS_RE.fullmatch(value):
        return b"\0" * 12 + bytes.fromhex(value[2:])
    if isinstance(value, str) and HASH_RE.fullmatch(value):
        return bytes.fromhex(value[2:])
    raise ValueError(f"{label} cannot be encoded as an ABI word")


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


def _verify_deployed_state(
    evidence: dict[str, Any], deployment: dict[str, Any], provider_network: dict[str, Any],
    deployment_hash: str, provider_network_hash: str,
) -> dict[str, Any]:
    evidence_keys = {
        "schema", "source_commit", "chain_id", "address", "transaction_hash",
        "block_number", "block_hash", "runtime_code", "runtime_code_sha256",
        "runtime_code_keccak256", "confirmations", "rpc_quorum",
        "deployment_manifest_sha256", "provider_network_manifest_sha256",
        "deployer", "state_block_number", "state_block_hash",
        "state_block_timestamp", "contract_state", "capacity_channels",
    }
    _require_exact_keys(evidence, evidence_keys, "deployed-code evidence")
    if (
        evidence.get("deployment_manifest_sha256") != deployment_hash
        or evidence.get("provider_network_manifest_sha256") != provider_network_hash
        or evidence.get("deployer") != deployment.get("deployer")
    ):
        raise ValueError("deployed-code manifest hashes or deployer do not match")
    state_number = evidence.get("state_block_number")
    state_timestamp = evidence.get("state_block_timestamp")
    valid_from = deployment.get("fresh_channel_valid_from")
    admit_until = deployment.get("fresh_channel_admit_until")
    if (
        type(state_number) is not int
        or type(deployment.get("deployment_block")) is not int
        or state_number < deployment["deployment_block"]
        or not isinstance(evidence.get("state_block_hash"), str)
        or HASH_RE.fullmatch(evidence["state_block_hash"]) is None
        or type(state_timestamp) is not int
        or type(valid_from) is not int or type(admit_until) is not int
        or not valid_from <= state_timestamp < admit_until
    ):
        raise ValueError("deployed-code confirmed state block is invalid or unusable")

    state = evidence.get("contract_state")
    if not isinstance(state, dict):
        raise ValueError("deployed-code contract_state must be an object")
    _require_exact_keys(state, {
        "stablecoin", "reward_token", "adjudication_threshold", "governance",
        "treasury", "domain_separator", "adjudicators", "policy", "channel",
        "max_channel_duration_seconds",
        "stablecoin_runtime_code_sha256", "stablecoin_runtime_code_keccak256",
        "stablecoin_balance", "stable_liabilities",
    }, "deployed-code contract_state")
    expected_domain = "0x" + _expected_immutable_values(deployment)[
        "initial_domain_separator"
    ].hex()
    expected_state = {
        "stablecoin": deployment.get("stablecoin"),
        "reward_token": deployment.get("reward_token"),
        "adjudication_threshold": deployment.get("adjudication_threshold"),
        "governance": deployment.get("governance"),
        "treasury": deployment.get("treasury"),
        "domain_separator": expected_domain,
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
    if any(state.get(key) != value for key, value in expected_state.items()):
        raise ValueError("deployed-code contract state differs from deployment manifest")
    expected_policy = deployment.get("policy")
    observed_policy = state.get("policy")
    if (
        not isinstance(expected_policy, dict) or not isinstance(observed_policy, dict)
        or set(observed_policy) != set(expected_policy)
        or any(type(observed_policy[key]) is not type(value)
               for key, value in expected_policy.items())
    ):
        raise ValueError("deployed-code dispute policy has noncanonical types")
    if (
        type(state.get("stable_liabilities")) is not int
        or state["stable_liabilities"] <= 0
        or type(state.get("stablecoin_balance")) is not int
        or state["stablecoin_balance"] < state["stable_liabilities"]
    ):
        raise ValueError("deployed-code settlement stablecoin is insolvent")
    pricing = state.get("channel")
    if not isinstance(pricing, dict):
        raise ValueError("deployed-code pricing channel must be an object")
    pricing_keys = {
        "channel_hash", "pricing_version", "pricing_hash", "treasury",
        "input_per_1k", "output_per_1k", "minimum_fee", "provider_bps",
        "relay_bps", "pool_bps", "treasury_bps", "active",
    }
    _require_exact_keys(pricing, pricing_keys, "deployed-code pricing channel")
    if (
        pricing.get("channel_hash") != deployment.get("channel_hash")
        or type(pricing.get("pricing_version")) is not int
        or not 0 < pricing["pricing_version"] < 2**64
        or pricing["pricing_version"] != deployment.get("pricing_version")
        or pricing.get("pricing_hash") != deployment.get("pricing_hash")
        or pricing.get("treasury") != deployment.get("treasury")
        or pricing.get("active") is not True
    ):
        raise ValueError("deployed-code pricing channel differs from deployment manifest")
    numeric_names = (
        "input_per_1k", "output_per_1k", "minimum_fee", "provider_bps",
        "relay_bps", "pool_bps", "treasury_bps",
    )
    if any(type(pricing.get(name)) is not int or pricing[name] < 0 for name in numeric_names):
        raise ValueError("deployed-code pricing channel contains invalid numbers")
    if pricing["minimum_fee"] <= 0 or sum(pricing[name] for name in (
        "provider_bps", "relay_bps", "pool_bps", "treasury_bps",
    )) != 10_000:
        raise ValueError("deployed-code pricing channel is not usable")
    pricing_words = [
        _abi_word(pricing["channel_hash"], "channel hash"),
        _abi_word(pricing["pricing_version"], "pricing version"),
        _abi_word(pricing["treasury"], "channel treasury"),
        *(_abi_word(pricing[name], f"channel {name}") for name in numeric_names),
        _abi_word(pricing["active"], "channel active"),
    ]
    if _keccak256(b"".join(pricing_words)) != pricing["pricing_hash"]:
        raise ValueError("deployed-code pricing_hash does not bind its channel config")

    channels = evidence.get("capacity_channels")
    ids = deployment.get("capacity_channel_ids")
    transactions = deployment.get("fresh_channel_open_tx_hashes")
    open_timestamps = deployment.get("fresh_channel_open_block_timestamps")
    if (
        not isinstance(channels, list) or not isinstance(ids, list)
        or not isinstance(transactions, list) or not isinstance(open_timestamps, list)
        or not channels or len(channels) != len(ids)
        or len(ids) != len(transactions) or len(ids) != len(open_timestamps)
    ):
        raise ValueError("deployed-code capacity channel evidence is incomplete")
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
    expected_numbers = {
        "pricing_version": deployment.get("pricing_version"),
        "capacity": deployment.get("fresh_channel_capacity"),
        "max_fee_per_request": deployment.get("fresh_channel_max_fee_per_request"),
        "valid_from": valid_from,
        "admit_until": admit_until,
        "claim_until": deployment.get("fresh_channel_claim_until"),
    }
    domain_separator = expected_domain
    for index, channel in enumerate(channels):
        if not isinstance(channel, dict):
            raise ValueError(f"capacity channel {index} must be an object")
        _require_exact_keys(channel, channel_keys, f"capacity channel {index}")
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
            raise ValueError(f"capacity channel {index} differs from manifests")
        for name in expected_numbers:
            if type(channel.get(name)) is not int or not 0 <= channel[name] < 2**256:
                raise ValueError(f"capacity channel {index} has noncanonical {name}")
        for name in ("pricing_version", "valid_from", "admit_until", "claim_until"):
            if channel[name] >= 2**64:
                raise ValueError(f"capacity channel {index} overflows {name}")
        for name in (
            "consumer_owner", "consumer_key", "provider_owner", "provider_signer",
            "relay", "relay_signer", "pool",
        ):
            value = channel.get(name)
            if (
                not isinstance(value, str) or ADDRESS_RE.fullmatch(value) is None
                or (name != "pool" and value == "0x" + "0" * 40)
            ):
                raise ValueError(f"capacity channel {index} has invalid {name}")
        if (
            type(channel.get("block_number")) is not int
            or not deployment["deployment_block"] <= channel["block_number"] <= state_number
            or not isinstance(channel.get("block_hash"), str)
            or HASH_RE.fullmatch(channel["block_hash"]) is None
        ):
            raise ValueError(f"capacity channel {index} has invalid block identity")
        open_timestamp = channel.get("open_block_timestamp")
        maximum_duration = deployment.get("max_channel_duration_seconds")
        if (
            type(open_timestamp) is not int
            or not 0 < open_timestamp <= state_timestamp
            or open_timestamp >= channel["valid_from"]
            or type(maximum_duration) is not int
            or channel["claim_until"] - open_timestamp > maximum_duration
        ):
            raise ValueError(f"capacity channel {index} has invalid duration")
        for name in (
            "consumer_nonce", "provider_nonce", "permit_deadline", "settled_max_fee",
            "credit_remaining", "stake_remaining",
        ):
            if type(channel.get(name)) is not int or channel[name] < 0:
                raise ValueError(f"capacity channel {index} has invalid {name}")
        if channel["permit_deadline"] >= 2**64:
            raise ValueError(f"capacity channel {index} permit deadline overflows uint64")
        if _capacity_channel_id(channel, domain_separator) != channel["channel_id"]:
            raise ValueError(f"capacity channel {index} ID does not bind its configuration")
        capacity = channel["capacity"]
        maximum = channel["max_fee_per_request"]
        if (
            channel["settled_max_fee"] + maximum > capacity
            or not maximum <= channel["credit_remaining"] <= capacity
            or not maximum <= channel["stake_remaining"] <= capacity
            or maximum < pricing["minimum_fee"]
        ):
            raise ValueError(f"capacity channel {index} cannot admit another request")
    return {
        "state_block_number": state_number,
        "state_block_hash": evidence["state_block_hash"],
        "state_block_timestamp": state_timestamp,
        "capacity_channel_count": len(channels),
    }


def _keccak256(raw: bytes) -> str:
    # Ethereum uses legacy Keccak-256, not hashlib.sha3_256. Import lazily so
    # the default source gate remains standard-library-only.
    return "0x" + _keccak_bytes(raw).hex()


def _hex_runtime(value: object) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) <= 2 or len(value) % 2:
        raise ValueError("runtime_code must be non-empty even-length 0x hex")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError("runtime_code is not hex") from exc
    if not raw or not any(raw):
        raise ValueError("runtime_code is empty")
    return raw


def _manifest_checks(
    root: Path,
    checks: list[dict[str, object]],
    deployment: dict[str, Any] | None,
    provider_network: dict[str, Any] | None,
    consumer_network: dict[str, Any] | None,
) -> None:
    if not all(value is not None for value in (deployment, provider_network, consumer_network)):
        _add(checks, "v10-manifest-consistency", False, "one or more V10 manifests could not be read")
        return
    assert deployment is not None and provider_network is not None and consumer_network is not None

    versions = {
        "deployment": deployment.get("protocol_version"),
        "provider_network": provider_network.get("protocol_version"),
        "consumer_network": consumer_network.get("protocol_version"),
    }
    _add(checks, "v10-protocol-version", all(value == 10 for value in versions.values()), versions)

    deployment_name = provider_network.get("deployment")
    _add(
        checks,
        "v10-deployment-reference",
        deployment_name == Path(DEPLOYMENT_PATH).name,
        deployment_name if isinstance(deployment_name, str) else "missing",
    )

    # Shared fields are bindings, not overrides. A mismatch must never be
    # hidden by merge order.
    shared = sorted(set(deployment) & set(provider_network))
    drift = [key for key in shared if deployment[key] != provider_network[key]]
    _add(checks, "v10-provider-deployment-bindings", not drift, drift)

    # The bundled Consumer manifest is the semantic union of deployment and
    # Provider network manifests. Only the CA filename is package-relative.
    provider_payload = {
        key: value for key, value in provider_network.items() if key not in {"deployment", "tls_ca_file"}
    }
    expected_consumer = {**deployment, **provider_payload}
    actual_consumer = {key: value for key, value in consumer_network.items() if key != "tls_ca_file"}
    missing = sorted(set(expected_consumer) - set(actual_consumer))
    unexpected = sorted(set(actual_consumer) - set(expected_consumer))
    changed = sorted(
        key for key in set(expected_consumer) & set(actual_consumer)
        if expected_consumer[key] != actual_consumer[key]
    )
    _add(
        checks,
        "v10-consumer-manifest-merge",
        not (missing or unexpected or changed),
        {"missing": missing, "unexpected": unexpected, "changed": changed},
    )

    provider_ca = provider_network.get("tls_ca_file")
    consumer_ca = consumer_network.get("tls_ca_file")
    ca_ok = False
    ca_detail: object = {"provider": provider_ca, "consumer": consumer_ca}
    if (
        isinstance(provider_ca, str)
        and provider_ca == Path(provider_ca).name
        and isinstance(consumer_ca, str)
        and consumer_ca == Path(consumer_ca).name
    ):
        provider_path = root / "deployments" / provider_ca
        consumer_path = root / "packages/mycomesh-cli/networks" / consumer_ca
        try:
            provider_hash, consumer_hash = _sha256(provider_path), _sha256(consumer_path)
            ca_ok = provider_hash == consumer_hash
            ca_detail = {"provider_sha256": provider_hash, "consumer_sha256": consumer_hash}
        except OSError as exc:
            ca_detail = str(exc)
    _add(checks, "v10-ca-bundle", ca_ok, ca_detail)

    ids = deployment.get("capacity_channel_ids")
    ids_are_hashes = (
        isinstance(ids, list)
        and bool(ids)
        and all(isinstance(value, str) and HASH_RE.fullmatch(value) for value in ids)
    )
    ids_ok = bool(ids_are_hashes and len(ids) == len(set(ids)))
    _add(checks, "v10-capacity-channel-ids", ids_ok, ids if isinstance(ids, list) else "missing")

    window_names = (
        "fresh_channel_valid_from",
        "fresh_channel_admit_until",
        "fresh_channel_claim_until",
    )
    windows = [deployment.get(name) for name in window_names]
    windows_ok = all(type(value) is int and value >= 0 for value in windows)
    if windows_ok:
        windows_ok = windows[0] < windows[1] < windows[2]
    _add(checks, "v10-fresh-channel-window", windows_ok, dict(zip(window_names, windows, strict=True)))

    maximum_channel_duration = deployment.get("max_channel_duration_seconds")
    open_timestamps = deployment.get("fresh_channel_open_block_timestamps")
    timestamps_ok = (
        isinstance(open_timestamps, list)
        and isinstance(ids, list)
        and len(open_timestamps) == len(ids)
        and all(type(value) is int and value > 0 for value in open_timestamps)
    )
    duration_ok = (
        type(maximum_channel_duration) is int
        and maximum_channel_duration in {604_800, 2_592_000}
        and windows_ok
        and timestamps_ok
        and all(
            opened_at < windows[0]
            and windows[2] - opened_at <= maximum_channel_duration
            for opened_at in open_timestamps
        )
    )
    _add(
        checks,
        "v10-channel-duration",
        duration_ok,
        {
            "max_channel_duration_seconds": maximum_channel_duration,
            "open_block_timestamps": open_timestamps,
            "maximum_observed_duration_seconds": (
                max(windows[2] - value for value in open_timestamps)
                if windows_ok and timestamps_ok else None
            ),
        },
    )

    authorization_deadline = deployment.get("authorization_deadline_seconds")
    maximum_ttl = deployment.get("max_authorization_ttl_seconds")
    authorization_ok = (
        windows_ok
        and type(authorization_deadline) is int
        and type(maximum_ttl) is int
        and 0 < authorization_deadline <= maximum_ttl == 10_800
        and windows[2] - windows[1] >= authorization_deadline
    )
    _add(
        checks,
        "v10-authorization-window",
        authorization_ok,
        {
            "authorization_deadline_seconds": authorization_deadline,
            "max_authorization_ttl_seconds": maximum_ttl,
            "claim_tail_seconds": windows[2] - windows[1] if windows_ok else None,
        },
    )

    capacity = deployment.get("fresh_channel_capacity")
    maximum_fee = deployment.get("fresh_channel_max_fee_per_request")
    _add(
        checks,
        "v10-fresh-channel-budget",
        type(capacity) is int and type(maximum_fee) is int
            and 0 < maximum_fee <= capacity < 2**256,
        {"capacity": capacity, "max_fee_per_request": maximum_fee},
    )
    token_sha256 = deployment.get("stablecoin_runtime_code_sha256")
    token_keccak = deployment.get("stablecoin_runtime_code_keccak256")
    _add(
        checks,
        "v10-stablecoin-runtime-pin",
        isinstance(token_sha256, str) and SHA256_RE.fullmatch(token_sha256)
            and isinstance(token_keccak, str) and HASH_RE.fullmatch(token_keccak),
        {"sha256": token_sha256, "keccak256": token_keccak},
    )

    mode = deployment.get("committee_mode")
    network_id = deployment.get("network_id")
    judges = deployment.get("adjudicators")
    operators = deployment.get("adjudicator_operators")
    roster_ok = (
        isinstance(judges, list)
        and 2 <= len(judges) <= 16
        and all(isinstance(judge, str) and ADDRESS_RE.fullmatch(judge) for judge in judges)
        and len(judges) == len(set(judges))
        and isinstance(operators, dict)
        and set(operators) == set(judges)
        and all(isinstance(operator, str) and operator.strip() == operator and operator
                for operator in operators.values())
    )
    distinct_operators = (
        len({operator.casefold() for operator in operators.values()})
        if roster_ok else 0
    )
    controlled_ok = (
        mode == "controlled_test"
        and deployment.get("independence_attested") is False
        and isinstance(network_id, str)
        and network_id.endswith("-controlled-test")
        and distinct_operators == 1
        and deployment.get("reward_token") == "0x" + "00" * 20
    )
    independent_ok = (
        mode == "independent_users"
        and deployment.get("independence_attested") is True
        and isinstance(network_id, str)
        and not network_id.endswith("-controlled-test")
        and distinct_operators == len(judges or ())
    )
    _add(
        checks,
        "v10-committee-declaration",
        roster_ok and (controlled_ok or independent_ok),
        {
            "mode": mode,
            "independence_attested": deployment.get("independence_attested"),
            "network_id": network_id,
            "adjudicators": len(judges) if isinstance(judges, list) else None,
            "distinct_operators": distinct_operators,
        },
    )


def check(root: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    root = root.resolve()

    package = _load_json(root, "package.json", checks)
    package_lock = _load_json(root, "package-lock.json", checks)
    consumer_package = _load_json(root, "packages/mycomesh-cli/package.json", checks)
    consumer_lock = _load_json(root, "packages/mycomesh-cli/package-lock.json", checks)
    deployment = _load_json(root, DEPLOYMENT_PATH, checks)
    provider_network = _load_json(root, PROVIDER_NETWORK_PATH, checks)
    consumer_network = _load_json(root, CONSUMER_NETWORK_PATH, checks)

    provider = _load_text(root, "packages/mycomesh-cli/src/provider.mjs", checks)
    release_module = _load_text(root, "packages/mycomesh-cli/src/release.mjs", checks)
    consumer = _load_text(root, "packages/mycomesh-cli/src/consumer.mjs", checks)
    cli = _load_text(root, "packages/mycomesh-cli/src/cli.mjs", checks)
    makefile = _load_text(root, "Makefile", checks)

    provider_version, provider_version_detail = _constant(
        release_module, r'PROVIDER_RELEASE_VERSION\s*=\s*"([^"]+)"'
    )
    consumer_version, consumer_version_detail = _constant(
        release_module, r'CONSUMER_RELEASE_VERSION\s*=\s*"([^"]+)"'
    )
    release_ref, release_ref_detail = _release_pin(
        release_module, "PROVIDER_RELEASE_SOURCE_COMMIT"
    )
    release_image, release_image_detail = _release_pin(
        release_module, "PROVIDER_RELEASE_IMAGE"
    )
    provider_uses_release_ref = provider is not None and re.search(
        r"DEFAULT_REF\s*=\s*PROVIDER_RELEASE_SOURCE_COMMIT\s*;", provider
    ) is not None
    provider_uses_release_image = provider is not None and re.search(
        r"DEFAULT_PROVIDER_IMAGE\s*=\s*PROVIDER_RELEASE_IMAGE\s*;", provider
    ) is not None
    legacy_ref, legacy_ref_detail = _constant(provider, r'DEFAULT_REF\s*=\s*"([^"]+)"')
    legacy_image, legacy_image_detail = _constant(
        provider, r'DEFAULT_PROVIDER_IMAGE\s*=\s*\n?\s*"([^"]+)"'
    )
    provider_ref = release_ref if provider_uses_release_ref else legacy_ref
    provider_image = release_image if provider_uses_release_image else legacy_image
    provider_ref_detail = release_ref_detail if provider_uses_release_ref else legacy_ref_detail
    provider_image_detail = release_image_detail if provider_uses_release_image else legacy_image_detail

    package_version = package.get("version") if package else None
    _add(
        checks,
        "provider-version",
        provider_version is not None and provider_version == package_version,
        f"root={package_version} provider={provider_version_detail}",
    )
    root_lock_version = package_lock.get("version") if package_lock else None
    root_lock_package_version = _nested(package_lock, "packages", "", "version")
    _add(
        checks,
        "root-lock-version",
        package_version is not None
        and root_lock_version == package_version
        and root_lock_package_version == package_version,
        {
            "package": package_version,
            "lock": root_lock_version,
            "lock_package": root_lock_package_version,
        },
    )

    consumer_package_version = consumer_package.get("version") if consumer_package else None
    consumer_lock_version = consumer_lock.get("version") if consumer_lock else None
    consumer_lock_package_version = _nested(consumer_lock, "packages", "", "version")
    imports_release = all(
        source is not None
        and re.search(r'CONSUMER_RELEASE_VERSION\s*\}\s*from "\./release\.mjs"', source)
        for source in (consumer, cli)
    )
    _add(
        checks,
        "consumer-version",
        consumer_version is not None
        and consumer_version == consumer_package_version == consumer_lock_version == consumer_lock_package_version
        and imports_release,
        {
            "package": consumer_package_version,
            "runtime": consumer_version_detail,
            "lock": consumer_lock_version,
            "lock_package": consumer_lock_package_version,
        },
    )

    consumer_files = _file_entries(consumer_package)
    _add(
        checks,
        "consumer-release-files",
        {
            "src/release.mjs",
            "networks/v10-controlled-test.json",
            "networks/v10-controlled-test.ca.crt",
        }.issubset(consumer_files)
        and "networks" not in consumer_files,
        sorted(consumer_files),
    )
    provider_files = _file_entries(package)
    _add(
        checks,
        "provider-release-files",
        {
            "packages/mycomesh-cli/src",
            "packages/mycomesh-cli/networks/v10-controlled-test.json",
            "packages/mycomesh-cli/networks/v10-controlled-test.ca.crt",
        }.issubset(provider_files)
        and "packages/mycomesh-cli/networks" not in provider_files,
        sorted(provider_files),
    )
    _add(
        checks,
        "provider-ref-format",
        (provider_ref is not None and COMMIT_RE.fullmatch(provider_ref))
        or (provider_uses_release_ref and provider_ref_detail == "unbound"),
        provider_ref_detail,
    )
    _add(
        checks,
        "provider-image-pin",
        (provider_image is not None and PROVIDER_IMAGE_RE.fullmatch(provider_image))
        or (provider_uses_release_image and provider_image_detail == "unbound"),
        provider_image_detail,
    )
    _add(
        checks,
        "provider-release-binding-state",
        provider_uses_release_ref
        and provider_uses_release_image
        and provider_ref is None
        and provider_image is None
        and provider_ref_detail == "unbound"
        and provider_image_detail == "unbound",
        {"source_commit": provider_ref_detail, "image": provider_image_detail},
    )

    for relative in REQUIRED_RELEASE_FILES:
        path = root / relative
        _add(
            checks,
            f"release-file:{relative}",
            path.is_file() and not path.is_symlink(),
            relative,
        )

    _manifest_checks(root, checks, deployment, provider_network, consumer_network)

    for target in ("node-up", "node-health", "provider-health"):
        _add(
            checks,
            f"make-target:{target}",
            makefile is not None
            and re.search(rf"^{re.escape(target)}\s*:", makefile, re.MULTILINE) is not None,
            target,
        )

    try:
        tracked = _tracked(root)
        _add(checks, "git-tracked-files", True, len(tracked))
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        tracked = []
        _add(checks, "git-tracked-files", False, str(exc))
    tracked_set = set(tracked)
    missing_tracked = sorted(relative for relative in REQUIRED_RELEASE_FILES if relative not in tracked_set)
    _add(checks, "release-files-tracked", not missing_tracked, missing_tracked)

    generated = []
    for relative in tracked:
        parts = set(Path(relative).parts)
        if parts & FORBIDDEN_PARTS:
            generated.append(relative)
    _add(checks, "tracked-generated-files", not generated, generated)
    return {
        "schema": "mycomesh.release-source-gate.v1",
        "scope": "source",
        "ok": all(bool(item["ok"]) for item in checks),
        "checks": checks,
        "limitations": [
            "published npm tarballs not verified",
            "OCI image digest/revision/signature not verified",
            "live chain bytecode and deployment receipt not verified",
        ],
    }


def _section(
    value: dict[str, Any] | None,
    name: str,
    checks: list[dict[str, object]],
) -> dict[str, Any] | None:
    section = value.get(name) if value else None
    ok = isinstance(section, dict)
    _add(checks, f"artifact-section:{name}", ok, name if ok else "missing or not an object")
    return section if isinstance(section, dict) else None


def _verify_package_tarball(
    root: Path,
    role: str,
    path: Path | None,
    declared: dict[str, Any] | None,
    source_commit: str | None,
    image: str | None,
    checks: list[dict[str, object]],
) -> None:
    package_path = "package.json" if role == "provider" else "packages/mycomesh-cli/package.json"
    try:
        source_package = _json_bytes((root / package_path).read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        _add(checks, f"artifact-{role}-source-package", False, str(exc))
        return
    expected_name, expected_version = source_package.get("name"), source_package.get("version")
    declared_ok = (
        isinstance(declared, dict)
        and declared.get("name") == expected_name
        and declared.get("version") == expected_version
        and isinstance(declared.get("sha256"), str)
        and SHA256_RE.fullmatch(declared["sha256"])
    )
    _add(
        checks,
        f"artifact-{role}-declaration",
        declared_ok,
        {
            "expected_name": expected_name,
            "expected_version": expected_version,
            "declared": declared,
        },
    )
    if path is None:
        return

    try:
        actual_tgz_hash = _sha256(path)
    except OSError as exc:
        _add(checks, f"artifact-{role}-tgz-sha256", False, str(exc))
        return
    _add(
        checks,
        f"artifact-{role}-tgz-sha256",
        declared_ok and actual_tgz_hash == declared.get("sha256"),
        actual_tgz_hash,
    )

    prefix = "package/packages/mycomesh-cli" if role == "provider" else "package"
    try:
        files = _tarball_files(path)
        expected_files = _package_source_files(root, role)
        if role == "provider" and source_commit is not None and image is not None:
            release_member = f"{prefix}/src/release.mjs"
            release_bytes = expected_files[release_member]
            release_text = release_bytes.decode("utf-8")
            release_text = release_text.replace(
                "export const PROVIDER_RELEASE_SOURCE_COMMIT = null;",
                f'export const PROVIDER_RELEASE_SOURCE_COMMIT = "{source_commit}";',
            ).replace(
                "export const PROVIDER_RELEASE_IMAGE = null;",
                f'export const PROVIDER_RELEASE_IMAGE = "{image}";',
            )
            expected_files[release_member] = release_text.encode("utf-8")
    except (OSError, ValueError, tarfile.TarError) as exc:
        _add(checks, f"artifact-{role}-tgz-layout", False, str(exc))
        return
    missing = sorted(set(expected_files) - set(files))
    unexpected = sorted(set(files) - set(expected_files))
    mismatched = sorted(
        name for name in set(files) & set(expected_files)
        if files[name] != expected_files[name]
    )
    _add(
        checks, f"artifact-{role}-tgz-layout",
        not (missing or unexpected or mismatched),
        {"missing": missing, "unexpected": unexpected, "content_mismatch": mismatched},
    )
    if missing:
        return

    try:
        packed_package = _json_bytes(files["package/package.json"])
    except (UnicodeError, ValueError, TypeError) as exc:
        _add(checks, f"artifact-{role}-package-metadata", False, str(exc))
        return
    _add(
        checks,
        f"artifact-{role}-package-metadata",
        packed_package.get("name") == expected_name and packed_package.get("version") == expected_version,
        {"name": packed_package.get("name"), "version": packed_package.get("version")},
    )

    network_member = f"{prefix}/networks/v10-controlled-test.json"
    ca_member = f"{prefix}/networks/v10-controlled-test.ca.crt"
    expected_network = (root / CONSUMER_NETWORK_PATH).read_bytes()
    expected_ca = (root / "packages/mycomesh-cli/networks/v10-controlled-test.ca.crt").read_bytes()
    _add(
        checks,
        f"artifact-{role}-v10-network",
        files[network_member] == expected_network,
        hashlib.sha256(files[network_member]).hexdigest(),
    )
    _add(
        checks,
        f"artifact-{role}-v10-ca",
        files[ca_member] == expected_ca,
        hashlib.sha256(files[ca_member]).hexdigest(),
    )

    release_source = files[f"{prefix}/src/release.mjs"].decode("utf-8", errors="replace")
    version_name = "PROVIDER_RELEASE_VERSION" if role == "provider" else "CONSUMER_RELEASE_VERSION"
    packed_version, detail = _constant(
        release_source, rf'{version_name}\s*=\s*"([^"]+)"'
    )
    _add(
        checks,
        f"artifact-{role}-runtime-version",
        packed_version == expected_version,
        detail,
    )

    if role == "provider":
        provider_source = files[f"{prefix}/src/provider.mjs"].decode("utf-8", errors="replace")
        packed_ref, ref_detail = _release_pin(release_source, "PROVIDER_RELEASE_SOURCE_COMMIT")
        packed_image, image_detail = _release_pin(release_source, "PROVIDER_RELEASE_IMAGE")
        uses_ref = re.search(
            r"DEFAULT_REF\s*=\s*PROVIDER_RELEASE_SOURCE_COMMIT\s*;", provider_source
        ) is not None
        uses_image = re.search(
            r"DEFAULT_PROVIDER_IMAGE\s*=\s*PROVIDER_RELEASE_IMAGE\s*;", provider_source
        ) is not None
        if not uses_ref:
            packed_ref, ref_detail = _constant(provider_source, r'DEFAULT_REF\s*=\s*"([^"]+)"')
        if not uses_image:
            packed_image, image_detail = _constant(
                provider_source, r'DEFAULT_PROVIDER_IMAGE\s*=\s*\n?\s*"([^"]+)"'
            )
        _add(
            checks,
            "artifact-provider-source-commit",
            source_commit is not None and packed_ref == source_commit,
            ref_detail,
        )
        _add(
            checks,
            "artifact-provider-image-pin",
            image is not None and packed_image == image,
            image_detail,
        )


def _verify_oci_metadata(
    metadata: dict[str, Any] | None,
    metadata_raw: bytes | None,
    declared: dict[str, Any] | None,
    source_commit: str | None,
    checks: list[dict[str, object]],
) -> str | None:
    if not isinstance(declared, dict):
        return None
    image = declared.get("image")
    index_digest = declared.get("index_digest")
    declared_ok = (
        isinstance(image, str)
        and PROVIDER_IMAGE_RE.fullmatch(image)
        and isinstance(index_digest, str)
        and OCI_DIGEST_RE.fullmatch(index_digest)
        and image.endswith("@" + index_digest)
        and isinstance(declared.get("metadata_sha256"), str)
        and SHA256_RE.fullmatch(declared["metadata_sha256"])
    )
    _add(checks, "artifact-oci-declaration", declared_ok, declared)
    if metadata is None or metadata_raw is None:
        return image if isinstance(image, str) else None
    _add(
        checks,
        "artifact-oci-metadata-sha256",
        declared_ok and hashlib.sha256(metadata_raw).hexdigest() == declared.get("metadata_sha256"),
        hashlib.sha256(metadata_raw).hexdigest(),
    )
    _add(
        checks,
        "artifact-oci-schema",
        metadata.get("schema") == OCI_METADATA_SCHEMA,
        metadata.get("schema"),
    )
    _add(
        checks,
        "artifact-oci-index",
        metadata.get("image") == image and metadata.get("index_digest") == index_digest,
        {"image": metadata.get("image"), "index_digest": metadata.get("index_digest")},
    )
    _add(
        checks,
        "artifact-oci-revision",
        source_commit is not None and metadata.get("revision") == source_commit,
        metadata.get("revision"),
    )

    raw_platforms = metadata.get("platforms")
    platforms: set[str] = set()
    platform_ok = isinstance(raw_platforms, list) and bool(raw_platforms)
    if isinstance(raw_platforms, list):
        for item in raw_platforms:
            if not isinstance(item, dict):
                platform_ok = False
                continue
            os_name, architecture = item.get("os"), item.get("architecture")
            digest, revision = item.get("digest"), item.get("revision")
            if not isinstance(os_name, str) or not isinstance(architecture, str):
                platform_ok = False
                continue
            platform = f"{os_name}/{architecture}"
            if platform in platforms:
                platform_ok = False
            platforms.add(platform)
            if not isinstance(digest, str) or not OCI_DIGEST_RE.fullmatch(digest):
                platform_ok = False
            if source_commit is None or revision != source_commit:
                platform_ok = False
    platform_ok = bool(platform_ok and platforms == REQUIRED_PLATFORMS)
    _add(checks, "artifact-oci-platforms", platform_ok, sorted(platforms))
    return image if isinstance(image, str) else None


def _verify_contract_artifacts(
    root: Path,
    abi_path: Path | None,
    code_evidence: dict[str, Any] | None,
    code_evidence_raw: bytes | None,
    declared: dict[str, Any] | None,
    source_commit: str | None,
    checks: list[dict[str, object]],
) -> None:
    if not isinstance(declared, dict):
        return
    compiled_runtime: bytes | None = None
    immutable_groups: tuple[tuple[tuple[int, int], ...], ...] = ()

    manifest_fields = {
        "deployment_manifest_sha256": DEPLOYMENT_PATH,
        "provider_network_manifest_sha256": PROVIDER_NETWORK_PATH,
        "consumer_network_manifest_sha256": CONSUMER_NETWORK_PATH,
    }
    for field, relative in manifest_fields.items():
        actual = _sha256(root / relative)
        _add(
            checks,
            f"artifact-{field.replace('_sha256', '')}",
            declared.get(field) == actual,
            actual,
        )

    if abi_path is not None:
        try:
            abi_raw = _read_bounded(abi_path)
            artifact_hash, abi_hash, functions = _canonical_abi(abi_raw)
            compiled_runtime, immutable_groups = _compiled_runtime(abi_raw)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            _add(checks, "artifact-contract-abi", False, str(exc))
        else:
            required_functions = {
                "MAX_CHANNEL_DURATION", "openCapacityChannels",
                "settleReservedReceipt", "voteDisputeBySig",
            }
            abi_ok = (
                declared.get("abi_artifact_sha256") == artifact_hash
                and declared.get("abi_sha256") == abi_hash
                and required_functions.issubset(functions)
            )
            _add(
                checks,
                "artifact-contract-abi",
                abi_ok,
                {
                    "artifact_sha256": artifact_hash,
                    "abi_sha256": abi_hash,
                    "missing_functions": sorted(required_functions - functions),
                    "compiled_runtime_sha256": hashlib.sha256(compiled_runtime).hexdigest(),
                    "immutable_variable_count": len(immutable_groups),
                    "immutable_reference_count": sum(len(group) for group in immutable_groups),
                },
            )

    try:
        deployment = _json_bytes((root / DEPLOYMENT_PATH).read_bytes())
        provider_network = _json_bytes((root / PROVIDER_NETWORK_PATH).read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        _add(checks, "artifact-deployed-runtime", False, str(exc))
        return
    declared_identity_ok = (
        declared.get("chain_id") == deployment.get("chain_id")
        and declared.get("address") == deployment.get("settlement")
        and declared.get("transaction_hash") == deployment.get("tx_hash")
        and declared.get("deployment_block") == deployment.get("deployment_block")
    )
    _add(
        checks,
        "artifact-contract-deployment-identity",
        declared_identity_ok,
        {
            "chain_id": declared.get("chain_id"),
            "address": declared.get("address"),
            "transaction_hash": declared.get("transaction_hash"),
            "deployment_block": declared.get("deployment_block"),
        },
    )

    if code_evidence is None or code_evidence_raw is None:
        return
    evidence_hash = hashlib.sha256(code_evidence_raw).hexdigest()
    _add(
        checks,
        "artifact-deployed-code-evidence-sha256",
        declared.get("deployed_code_evidence_sha256") == evidence_hash,
        evidence_hash,
    )
    _add(
        checks,
        "artifact-deployed-code-schema",
        code_evidence.get("schema") == DEPLOYED_CODE_SCHEMA,
        code_evidence.get("schema"),
    )
    identity_ok = (
        source_commit is not None
        and code_evidence.get("source_commit") == source_commit
        and code_evidence.get("chain_id") == deployment.get("chain_id")
        and code_evidence.get("address") == deployment.get("settlement")
        and code_evidence.get("transaction_hash") == deployment.get("tx_hash")
        and code_evidence.get("block_number") == deployment.get("deployment_block")
        and isinstance(code_evidence.get("block_hash"), str)
        and HASH_RE.fullmatch(code_evidence["block_hash"])
        and code_evidence.get("deployment_manifest_sha256") == _sha256(root / DEPLOYMENT_PATH)
        and code_evidence.get("provider_network_manifest_sha256")
            == _sha256(root / PROVIDER_NETWORK_PATH)
    )
    _add(checks, "artifact-deployed-code-identity", identity_ok, {
        key: code_evidence.get(key) for key in (
            "source_commit", "chain_id", "address", "transaction_hash", "block_number", "block_hash"
        )
    })
    quorum_ok = (
        type(code_evidence.get("confirmations")) is int
        and code_evidence["confirmations"] >= 2
        and type(code_evidence.get("rpc_quorum")) is int
        and code_evidence["rpc_quorum"] >= 2
    )
    _add(
        checks,
        "artifact-deployed-code-quorum",
        quorum_ok,
        {
            "confirmations": code_evidence.get("confirmations"),
            "rpc_quorum": code_evidence.get("rpc_quorum"),
        },
    )
    try:
        state_summary = _verify_deployed_state(
            code_evidence, deployment, provider_network,
            _sha256(root / DEPLOYMENT_PATH), _sha256(root / PROVIDER_NETWORK_PATH),
        )
    except (ValueError, TypeError) as exc:
        _add(checks, "artifact-deployed-state", False, str(exc))
    else:
        _add(checks, "artifact-deployed-state", True, state_summary)
    try:
        runtime = _hex_runtime(code_evidence.get("runtime_code"))
        sha256_hash = hashlib.sha256(runtime).hexdigest()
        keccak_hash = _keccak256(runtime)
        if compiled_runtime is None or not immutable_groups:
            raise ValueError("a full compiler artifact is required to match deployed runtime")
        immutable_values = _verify_runtime_immutables(
            compiled_runtime, runtime, immutable_groups, deployment,
        )
    except (ValueError, RuntimeError) as exc:
        _add(checks, "artifact-deployed-runtime", False, str(exc))
        return
    runtime_ok = (
        code_evidence.get("runtime_code_sha256") == sha256_hash
        and code_evidence.get("runtime_code_keccak256") == keccak_hash
        and declared.get("runtime_code_sha256") == sha256_hash
        and declared.get("runtime_code_keccak256") == keccak_hash
    )
    _add(
        checks,
        "artifact-deployed-runtime",
        runtime_ok,
        {
            "runtime_code_sha256": sha256_hash,
            "runtime_code_keccak256": keccak_hash,
            "compiled_runtime_match": True,
            "verified_immutables": immutable_values,
            "source": "raw deployed runtime matched compiler output with every immutable resolved from the deployment manifest",
        },
    )


def _verify_promotion_policy(root: Path, checks: list[dict[str, object]]) -> None:
    """Require a real independent monetary roster for a promotable candidate."""
    detail: object
    try:
        deployment = _json_bytes((root / DEPLOYMENT_PATH).read_bytes())
        if deployment.get("max_channel_duration_seconds") != 2_592_000:
            raise ValueError("promotable V10 deployment must pin the 30-day channel duration")
        if deployment.get("committee_mode") != "independent_users":
            raise ValueError("controlled-test committee cannot produce a promotable candidate")
        network_id = deployment.get("network_id")
        if not isinstance(network_id, str) or network_id.endswith("-controlled-test"):
            raise ValueError("promotion network_id must not be controlled-test")
        # Import lazily so the source-only gate remains dependency-free. This
        # is the same validator used by the monetary execution path.
        from gateway.v10_enforcement import monetary_policy_from_deployment

        policy = monetary_policy_from_deployment(deployment)
        detail = {
            "mode": "independent_users",
            "policy_hash": policy.policy_hash,
            "required_votes": policy.required_votes,
            "signers": len(policy.signers),
        }
    except (OSError, UnicodeError, ValueError, TypeError, ImportError) as exc:
        _add(checks, "artifact-promotion-policy", False, str(exc))
        return
    except Exception as exc:
        # V10EnforcementError is deliberately not imported at module load.
        _add(checks, "artifact-promotion-policy", False, str(exc))
        return
    _add(checks, "artifact-promotion-policy", True, detail)


def check_artifacts(
    root: Path,
    *,
    artifact_evidence: Path | None,
    provider_tgz: Path | None,
    consumer_tgz: Path | None,
    oci_metadata: Path | None,
    deployed_code_evidence: Path | None,
    abi_artifact: Path | None,
    expected_source_commit: str | None = None,
) -> dict[str, object]:
    source_report = check(root)
    checks = list(source_report["checks"])
    root = root.resolve()
    _verify_promotion_policy(root, checks)

    evidence, _ = _external_json(artifact_evidence, "release-evidence", checks)
    oci, oci_raw = _external_json(oci_metadata, "oci-metadata", checks)
    deployed, deployed_raw = _external_json(deployed_code_evidence, "deployed-code", checks)
    provider_path = _required_file(provider_tgz, "provider-tgz", checks)
    consumer_path = _required_file(consumer_tgz, "consumer-tgz", checks)
    abi_path = _required_file(abi_artifact, "abi-artifact", checks)

    expected = expected_source_commit or _git_head(root)
    _add(
        checks,
        "artifact-expected-source-commit",
        isinstance(expected, str) and COMMIT_RE.fullmatch(expected),
        expected or "missing; pass --expected-source-commit outside a Git checkout",
    )
    _add(
        checks,
        "artifact-release-schema",
        evidence is not None and evidence.get("schema") == ARTIFACT_SCHEMA,
        evidence.get("schema") if evidence else "missing",
    )
    source_commit = evidence.get("source_commit") if evidence else None
    source_ok = (
        isinstance(source_commit, str)
        and COMMIT_RE.fullmatch(source_commit)
        and source_commit == expected
    )
    _add(checks, "artifact-source-commit", source_ok, source_commit or "missing")

    packages = _section(evidence, "packages", checks)
    provider_declared = _section(packages, "provider", checks)
    consumer_declared = _section(packages, "consumer", checks)
    oci_declared = _section(evidence, "oci", checks)
    contract_declared = _section(evidence, "contract", checks)

    image = _verify_oci_metadata(oci, oci_raw, oci_declared, source_commit, checks)
    _verify_package_tarball(
        root, "provider", provider_path, provider_declared, source_commit, image, checks
    )
    _verify_package_tarball(
        root, "consumer", consumer_path, consumer_declared, source_commit, image, checks
    )
    _verify_contract_artifacts(
        root,
        abi_path,
        deployed,
        deployed_raw,
        contract_declared,
        source_commit,
        checks,
    )
    return {
        "schema": "mycomesh.release-artifact-gate.v1",
        "scope": "artifacts",
        "ok": all(bool(item["ok"]) for item in checks),
        "checks": checks,
        "limitations": [
            "offline evidence consistency verified; registry and RPC were not contacted",
            "evidence authenticity still requires a detached signature/provenance verifier in the publishing workflow",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--strict-artifacts",
        action="store_true",
        help="fail closed unless every build/deployment evidence input verifies",
    )
    parser.add_argument("--artifact-evidence", type=Path, help="release artifact declaration JSON")
    parser.add_argument("--provider-tgz", type=Path, help="exact mycomesh-provider npm tarball")
    parser.add_argument("--consumer-tgz", type=Path, help="exact mycomesh-consumer npm tarball")
    parser.add_argument("--oci-metadata", type=Path, help="inspected multi-platform OCI metadata JSON")
    parser.add_argument("--deployed-code-evidence", type=Path, help="pinned-block deployed runtime JSON")
    parser.add_argument("--abi-artifact", type=Path, help="compiled V10 ABI or compiler artifact JSON")
    parser.add_argument(
        "--expected-source-commit",
        help="full commit expected in release evidence and every OCI revision; defaults to Git HEAD",
    )
    args = parser.parse_args(argv)
    artifact_values = (
        args.artifact_evidence,
        args.provider_tgz,
        args.consumer_tgz,
        args.oci_metadata,
        args.deployed_code_evidence,
        args.abi_artifact,
        args.expected_source_commit,
    )
    if args.strict_artifacts or any(value is not None for value in artifact_values):
        report = check_artifacts(
            args.root.resolve(),
            artifact_evidence=args.artifact_evidence,
            provider_tgz=args.provider_tgz,
            consumer_tgz=args.consumer_tgz,
            oci_metadata=args.oci_metadata,
            deployed_code_evidence=args.deployed_code_evidence,
            abi_artifact=args.abi_artifact,
            expected_source_commit=args.expected_source_commit,
        )
    else:
        report = check(args.root.resolve())
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for item in report["checks"]:
            print(f"{'PASS' if item['ok'] else 'FAIL'} {item['name']}: {item['detail']}")
        print(f"release {report['scope']} gate: " + ("PASS" if report["ok"] else "FAIL"))
        for limitation in report["limitations"]:
            print(f"NOT VERIFIED: {limitation}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
