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
import os
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


RELEASE_SCHEMA = "mycomesh.release-artifacts.v1"
NPM_SCHEMA = "mycomesh.npm-release-candidate.v1"
OCI_SCHEMA = "mycomesh.oci-metadata.v1"
DEPLOYED_CODE_SCHEMA = "mycomesh.deployed-code.v4"

def _release_profile_path(name: str, default: str) -> Path:
    value = os.environ.get(name, default)
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not value.strip():
        raise ValueError(f"{name} must be a relative repository path")
    return path


NETWORK_BASENAME = os.environ.get(
    "MYCOMESH_RELEASE_NETWORK_BASENAME", "v10-controlled-test"
)
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", NETWORK_BASENAME):
    raise ValueError("MYCOMESH_RELEASE_NETWORK_BASENAME is invalid")
DEPLOYMENT_PATH = _release_profile_path(
    "MYCOMESH_RELEASE_DEPLOYMENT_PATH", "deployments/sepolia-myco-v10.json"
)
PROVIDER_NETWORK_PATH = _release_profile_path(
    "MYCOMESH_RELEASE_PROVIDER_NETWORK_PATH",
    "deployments/sepolia-provider-network-v10.json",
)
CONSUMER_NETWORK_PATH = _release_profile_path(
    "MYCOMESH_RELEASE_CONSUMER_NETWORK_PATH",
    f"packages/mycomesh-cli/networks/{NETWORK_BASENAME}.json",
)
JURY_POLICY_PATH = Path("deployments/provider-jury-policy-v1.json")

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
JURY_RELAY_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
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
DYNAMIC_JURY_MODE = "dynamic_provider_ai_v1"
DYNAMIC_JURY_RANDOMNESS = "future_blockhash_v1"
DYNAMIC_JURY_FORBIDDEN_FIELDS = frozenset({
    "adjudicators",
    "adjudicator_operators",
    "independence_attested",
    "jury_provider_evidence",
})
SEPOLIA_CHAIN_ID = 11_155_111
ZERO_ADDRESS = "0x" + "0" * 40
ZERO_HASH = "0x" + "0" * 64
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
EMPTY_CODE_KECCAK256 = (
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
)
REGISTRY_REQUIRED_FUNCTION_SIGNATURES = frozenset({
    "RANDOMNESS_MODE_HASH()",
    "minimumReputation()",
    "jurySize()",
    "threshold()",
    "selectionDelayBlocks()",
    "providerCount()",
    "providerAt(uint256)",
    "canFormJury()",
    "canFormJuryFor(bytes32)",
    "assignmentProviderEvidence(bytes32)",
    "bondPenaltyRecipient()",
    "setProvider((address,address,bytes32,bytes32,bytes32,uint64,bool),uint64,bytes32)",
    "providerSourceSequence(address)",
    "providerSourceDigest(address)",
})
PROVIDER_UPDATED_EVENT_SIGNATURE = (
    "ProviderUpdated(address,address,bytes32,uint64,bool,uint64,bytes32,uint64)"
)
PROVIDER_UPDATED_EVENT_INDEXED = (True, True, True, False, False, False, False, False)
JURY_POLICY_SCHEMA = "mycomesh.v10.provider-jury-policy.v1"
JURY_POLICY_FIELDS = {
    "schema", "model", "system_prompt", "max_output_tokens", "task_ttl_seconds",
}
JURY_VERDICT_FIELDS = [
    "confirmed", "confidence_bps", "reason_code", "reasoning",
]
MAX_JURY_PROMPT_CHARS = 64 * 1024
MAX_JURY_TASK_TTL_SECONDS = 900


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


def _validate_jury_policy(
    root: Path, deployment: dict[str, Any],
) -> dict[str, Any]:
    """Bind the complete executable AI policy, not only a free-standing hash."""
    path = root / JURY_POLICY_PATH
    value, raw = _load_json(path, str(JURY_POLICY_PATH))
    _exact_keys(value, JURY_POLICY_FIELDS, "Provider jury policy")
    model = value.get("model")
    prompt = value.get("system_prompt")
    maximum = value.get("max_output_tokens")
    ttl = value.get("task_ttl_seconds")
    if value.get("schema") != JURY_POLICY_SCHEMA:
        raise ReleaseEvidenceError("unsupported Provider jury policy schema")
    if (
        not isinstance(model, str) or not model or model != model.strip()
        or len(model) > 160 or "\x00" in model
    ):
        raise ReleaseEvidenceError("Provider jury policy model is invalid")
    if (
        not isinstance(prompt, str) or not prompt or prompt != prompt.strip()
        or len(prompt) > MAX_JURY_PROMPT_CHARS or "\x00" in prompt
    ):
        raise ReleaseEvidenceError("Provider jury policy system_prompt is invalid")
    if type(maximum) is not int or not 1 <= maximum <= 1_000_000:
        raise ReleaseEvidenceError("Provider jury policy max_output_tokens is invalid")
    if type(ttl) is not int or not 1 <= ttl <= MAX_JURY_TASK_TTL_SECONDS:
        raise ReleaseEvidenceError("Provider jury policy task_ttl_seconds is invalid")
    executable = {
        "schema": JURY_POLICY_SCHEMA,
        "model": model,
        "system_prompt": prompt,
        "max_output_tokens": maximum,
        "task_ttl_seconds": ttl,
        "verdict_fields": JURY_VERDICT_FIELDS,
    }
    canonical = json.dumps(
        executable, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")
    decision_hash = "0x" + hashlib.sha256(canonical).hexdigest()
    if deployment.get("jury_decision_policy_hash") != decision_hash:
        raise ReleaseEvidenceError(
            "Provider jury executable policy differs from jury_decision_policy_hash"
        )
    return {
        "path": JURY_POLICY_PATH.as_posix(),
        "source_sha256": _sha256_bytes(raw),
        "decision_policy_hash": decision_hash,
        "model": model,
        "system_prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "max_output_tokens": maximum,
        "task_ttl_seconds": ttl,
    }


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


def _known_role_addresses(*values: Any) -> set[str]:
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
    deployment: dict[str, Any], provider: dict[str, Any], consumer: dict[str, Any],
) -> tuple[list[str], dict[str, str], int]:
    relay_keys = provider.get("jury_relay_public_keys")
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
        raise ReleaseEvidenceError(
            "dynamic Provider jury network requires 1 to 4 unique lowercase Ed25519 Relay public keys"
        )
    raw_senders = provider.get("jury_transaction_senders")
    if not isinstance(raw_senders, dict) or set(raw_senders) != set(relay_keys):
        raise ReleaseEvidenceError(
            "jury transaction sender keys must exactly match jury Relay public keys"
        )
    senders: dict[str, str] = {}
    for key in relay_keys:
        sender = raw_senders.get(key)
        if (
            not isinstance(sender, str)
            or ADDRESS_RE.fullmatch(sender) is None
            or sender == ZERO_ADDRESS
        ):
            raise ReleaseEvidenceError(
                "jury transaction sender must be a canonical nonzero lowercase address"
            )
        senders[key] = sender
    if len(set(senders.values())) != len(senders):
        raise ReleaseEvidenceError("jury transaction senders must be unique")
    gas_cap = provider.get(JURY_TRANSACTION_GAS_CAP_FIELD)
    if type(gas_cap) is not int or not 0 < gas_cap < 2**256:
        raise ReleaseEvidenceError(
            f"{JURY_TRANSACTION_GAS_CAP_FIELD} must be a positive uint256"
        )
    if (
        consumer.get("jury_relay_public_keys") != relay_keys
        or consumer.get("jury_transaction_senders") != raw_senders
        or consumer.get(JURY_TRANSACTION_GAS_CAP_FIELD) != gas_cap
    ):
        raise ReleaseEvidenceError(
            "Provider and Consumer jury sender configuration differs"
        )
    conflicts = sorted(set(senders.values()) & _known_role_addresses(
        deployment, provider,
    ))
    if conflicts:
        raise ReleaseEvidenceError(
            f"jury transaction sender reuses a known manifest role: {conflicts}"
        )
    return relay_keys, senders, gas_cap


def _reputation_history_lineage(
    value: Any, *, deployment: dict[str, Any], label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(f"{label} must be a non-null object")
    _exact_keys(value, REPUTATION_HISTORY_FIELDS, label)
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
        or network_id == deployment.get("network_id")
        or type(protocol) is not int
        or protocol not in {9, 10}
        or type(chain_id) is not int
        or chain_id != deployment.get("chain_id")
        or not isinstance(value.get("source_genesis_hash"), str)
        or HASH_RE.fullmatch(value["source_genesis_hash"]) is None
        or value["source_genesis_hash"] == ZERO_HASH
        or value["source_genesis_hash"] != deployment.get("genesis_hash")
        or not isinstance(value.get("source_settlement_contract"), str)
        or ADDRESS_RE.fullmatch(value["source_settlement_contract"]) is None
        or value["source_settlement_contract"] in {
            ZERO_ADDRESS, deployment.get("settlement"),
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
        or SHA256_RE.fullmatch(artifact_sha) is None
        or artifact_sha == "0" * 64
        or not isinstance(value.get("artifact_root"), str)
        or HASH_RE.fullmatch(value["artifact_root"]) is None
        or value["artifact_root"] == ZERO_HASH
    ):
        raise ReleaseEvidenceError(f"{label} is invalid or not a prior same-chain deployment")
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
        raise ReleaseEvidenceError(
            f"{label} dynamic Settlement deployment boundary is invalid"
        )
    return {
        "deployment_block": deployment_block,
        "deployment_block_hash": deployment_block_hash,
        "settlement_runtime_code_keccak256": runtime_hash,
    }


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
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE
    if dynamic_jury:
        deployment_source = deployment.get("source_commit")
        if (
            not isinstance(deployment_source, str)
            or COMMIT_RE.fullmatch(deployment_source) is None
            or provider.get("source_commit") != deployment_source
            or consumer.get("source_commit") != deployment_source
        ):
            raise ReleaseEvidenceError(
                "dynamic V10 manifests must share a valid deployment source_commit"
            )
    jury_network_fields = {
        "jury_relay_public_keys", "jury_transaction_senders",
        JURY_TRANSACTION_GAS_CAP_FIELD,
    }
    if jury_network_fields.intersection(deployment):
        raise ReleaseEvidenceError(
            "jury Relay keys, transaction senders, and gas cap belong only in network manifests"
        )
    if dynamic_jury:
        deployment_boundary = _dynamic_deployment_boundary(
            deployment, label="deployment",
        )
        deployment_history = _reputation_history_lineage(
            deployment.get(REPUTATION_HISTORY_FIELD),
            deployment=deployment,
            label="deployment reputation_history_import",
        )
        for label, value in (
            ("Provider network", provider), ("Consumer network", consumer),
        ):
            if _dynamic_deployment_boundary(value, label=label) != deployment_boundary:
                raise ReleaseEvidenceError(
                    f"{label} Settlement deployment boundary differs from deployment"
                )
            observed_history = _reputation_history_lineage(
                value.get(REPUTATION_HISTORY_FIELD),
                deployment=deployment,
                label=f"{label} reputation_history_import",
            )
            if observed_history != deployment_history:
                raise ReleaseEvidenceError(
                    f"{label} reputation history lineage differs from deployment"
                )
        for label, value in (
            ("deployment", deployment),
            ("Provider network", provider),
            ("Consumer network", consumer),
        ):
            forbidden = sorted(DYNAMIC_JURY_FORBIDDEN_FIELDS.intersection(value))
            if forbidden:
                raise ReleaseEvidenceError(
                    f"{label} dynamic Provider jury manifest contains forbidden "
                    f"static committee fields: {', '.join(forbidden)}"
                )
        _jury_sender_config(deployment, provider, consumer)
    elif (
        any(jury_network_fields.intersection(value) for value in (provider, consumer))
        or any(REPUTATION_HISTORY_FIELD in value for value in (
            deployment, provider, consumer,
        ))
    ):
        raise ReleaseEvidenceError(
            "jury sender/history configuration requires a dynamic Provider jury deployment"
        )
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
    if dynamic_jury:
        decision_policy_hash = deployment.get("jury_decision_policy_hash")
        if (
            not isinstance(decision_policy_hash, str)
            or HASH_RE.fullmatch(decision_policy_hash) is None
            or decision_policy_hash == ZERO_HASH
        ):
            raise ReleaseEvidenceError(
                "dynamic Provider jury requires a canonical nonzero SHA-256 decision policy hash"
            )
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
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE
    scalar_keys = {
        "stablecoin", "reward_token", "adjudication_threshold", "governance",
        "treasury", "domain_separator", "policy", "channel",
        "max_channel_duration_seconds",
        "stablecoin_runtime_code_sha256", "stablecoin_runtime_code_keccak256",
        "stablecoin_balance", "stable_liabilities",
    }
    scalar_keys.add("jury_registry" if dynamic_jury else "adjudicators")
    _exact_keys(state, scalar_keys, "deployed-code contract_state")
    expected = {
        "stablecoin": deployment.get("stablecoin"),
        "reward_token": deployment.get("reward_token"),
        "adjudication_threshold": deployment.get("adjudication_threshold"),
        "governance": deployment.get("governance"),
        "treasury": deployment.get("treasury"),
        "domain_separator": _expected_domain_separator(deployment),
        "max_channel_duration_seconds": deployment.get("max_channel_duration_seconds"),
        "policy": deployment.get("policy"),
        "stablecoin_runtime_code_sha256": deployment.get(
            "stablecoin_runtime_code_sha256"
        ),
        "stablecoin_runtime_code_keccak256": deployment.get(
            "stablecoin_runtime_code_keccak256"
        ),
    }
    expected["jury_registry" if dynamic_jury else "adjudicators"] = deployment.get(
        "jury_registry" if dynamic_jury else "adjudicators"
    )
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


def _validate_jury_registry_state(
    state: Any, deployment: dict[str, Any],
) -> dict[str, str]:
    if not isinstance(state, dict):
        raise ReleaseEvidenceError("deployed-code jury_registry_state must be an object")
    expected_keys = {
        "address", "governance", "reputation_authority", "settlement",
        "bond_penalty_recipient", "minimum_reputation", "jury_size", "threshold",
        "selection_delay_blocks", "randomness", "provider_count", "roster_version",
        "pending_assignments", "can_form_jury", "providers", "runtime_code",
        "runtime_code_sha256", "runtime_code_keccak256",
    }
    _exact_keys(state, expected_keys, "deployed-code jury_registry_state")
    policy = deployment.get("policy")
    if "jury_provider_evidence" in deployment:
        raise ReleaseEvidenceError(
            "deployment must not pin the mutable jury Provider pool"
        )
    expected = {
        "address": deployment.get("jury_registry"),
        "governance": deployment.get("jury_registry_governance"),
        "reputation_authority": deployment.get("reputation_authority"),
        "settlement": deployment.get("settlement"),
        "bond_penalty_recipient": (
            policy.get("bond_penalty_recipient") if isinstance(policy, dict) else None
        ),
        "minimum_reputation": deployment.get("minimum_provider_reputation"),
        "jury_size": deployment.get("jury_size"),
        "threshold": deployment.get("adjudication_threshold"),
        "selection_delay_blocks": deployment.get("jury_selection_delay_blocks"),
        "randomness": _keccak256(DYNAMIC_JURY_RANDOMNESS.encode("utf-8")),
    }
    address_fields = (
        "address", "governance", "reputation_authority", "settlement",
        "bond_penalty_recipient",
    )
    if any(
        not isinstance(expected[name], str)
        or ADDRESS_RE.fullmatch(expected[name]) is None
        or expected[name] == ZERO_ADDRESS
        for name in address_fields
    ):
        raise ReleaseEvidenceError("deployment jury registry addresses are invalid")
    network_id = deployment.get("network_id")
    if (
        deployment.get("jury_randomness") != DYNAMIC_JURY_RANDOMNESS
        or deployment.get("chain_id") != SEPOLIA_CHAIN_ID
        or not isinstance(network_id, str)
        or not network_id.endswith("-controlled-test")
    ):
        raise ReleaseEvidenceError("deployment jury randomness mode is unsupported")
    delay = expected["selection_delay_blocks"]
    if type(delay) is not int or not 0 < delay <= 64:
        raise ReleaseEvidenceError("deployment jury selection delay is invalid")
    if any(state.get(key) != value for key, value in expected.items()):
        raise ReleaseEvidenceError("deployed-code jury registry state differs from the manifest")

    providers = state.get("providers")
    minimum = expected["minimum_reputation"]
    size = expected["jury_size"]
    threshold = expected["threshold"]
    if (
        not isinstance(providers, list)
        or not providers
        or len(providers) > 64
        or state.get("provider_count") != len(providers)
        or type(state.get("roster_version")) is not int
        or state["roster_version"] < len(providers)
        or state.get("pending_assignments") != 0
        or state.get("can_form_jury") is not True
        or type(minimum) is not int
        or not 0 < minimum < 2**64
        or type(size) is not int
        or not 3 <= size <= 7
        or type(threshold) is not int
        or not 2 <= threshold <= size
        or threshold <= size // 2
    ):
        raise ReleaseEvidenceError("deployed-code jury registry cannot form the declared jury")
    required_provider_keys = {
        "owner", "vote_signer", "operator_id_hash", "peer_id_hash",
        "capability_hash", "reputation", "active", "source_sequence",
        "source_digest",
    }
    forbidden_accounts = {
        expected["address"], expected["governance"], expected["reputation_authority"],
        expected["settlement"], expected["bond_penalty_recipient"],
        deployment.get("treasury"),
    }
    owners: list[str] = []
    signers: list[str] = []
    eligible_operators: set[str] = set()
    for index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            raise ReleaseEvidenceError(f"jury provider {index} must be an object")
        _exact_keys(provider, required_provider_keys, f"jury provider {index}")
        owner, signer = provider.get("owner"), provider.get("vote_signer")
        hashes = tuple(provider.get(name) for name in (
            "operator_id_hash", "peer_id_hash", "capability_hash",
        ))
        reputation = provider.get("reputation")
        source_sequence = provider.get("source_sequence")
        source_digest = provider.get("source_digest")
        if (
            not isinstance(owner, str)
            or ADDRESS_RE.fullmatch(owner) is None
            or owner == ZERO_ADDRESS
            or not isinstance(signer, str)
            or ADDRESS_RE.fullmatch(signer) is None
            or signer == ZERO_ADDRESS
            or owner in forbidden_accounts
            or signer in forbidden_accounts
            or any(
                not isinstance(value, str)
                or HASH_RE.fullmatch(value) is None
                or value == ZERO_HASH
                for value in hashes
            )
            or type(reputation) is not int
            or not 0 <= reputation < 2**64
            or type(source_sequence) is not int
            or not 0 < source_sequence < 2**64
            or not isinstance(source_digest, str)
            or HASH_RE.fullmatch(source_digest) is None
            or source_digest == ZERO_HASH
            or type(provider.get("active")) is not bool
        ):
            raise ReleaseEvidenceError(f"jury provider {index} is malformed or conflicted")
        owners.append(owner)
        signers.append(signer)
        if provider["active"] and reputation >= minimum:
            eligible_operators.add(provider["operator_id_hash"])
    if (
        len(owners) != len(set(owners))
        or len(signers) != len(set(signers))
        or set(owners) & set(signers)
        or len(eligible_operators) < size
    ):
        raise ReleaseEvidenceError("jury provider/operator evidence cannot form a distinct jury")

    _, runtime = _runtime(state.get("runtime_code"))
    runtime_sha256 = hashlib.sha256(runtime).hexdigest()
    runtime_keccak = _keccak256(runtime)
    if (
        state.get("runtime_code_sha256") != runtime_sha256
        or state.get("runtime_code_keccak256") != runtime_keccak
    ):
        raise ReleaseEvidenceError("jury registry runtime hashes do not match runtime_code")
    return {
        "address": expected["address"],
        "runtime_code_sha256": runtime_sha256,
        "runtime_code_keccak256": runtime_keccak,
    }


def _validate_capacity_channels(
    channels: Any, deployment: dict[str, Any], provider_network: dict[str, Any],
    state_block_number: int, state_block_timestamp: int, minimum_fee: int,
) -> None:
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE
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
    if dynamic_jury:
        channel_keys.add("jury_ready")
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
            or (dynamic_jury and channel.get("jury_ready") is not True)
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


def _validate_jury_transaction_senders(
    observed: Any, *, deployment: dict[str, Any], provider_network: dict[str, Any],
    contract_state: Any, registry_state: Any, capacity_channels: Any,
    state_block_number: int, state_block_hash: str,
) -> dict[str, Any]:
    relay_keys = provider_network.get("jury_relay_public_keys")
    expected_senders = provider_network.get("jury_transaction_senders")
    gas_cap = provider_network.get(JURY_TRANSACTION_GAS_CAP_FIELD)
    if (
        not isinstance(relay_keys, list)
        or not isinstance(expected_senders, dict)
        or not isinstance(observed, dict)
        or set(observed) != set(relay_keys)
        or set(expected_senders) != set(relay_keys)
    ):
        raise ReleaseEvidenceError(
            "deployed-code jury transaction sender evidence keys differ from manifests"
        )
    conflicts = sorted(set(expected_senders.values()) & _known_role_addresses(
        deployment, provider_network, contract_state, registry_state,
        capacity_channels,
    ))
    if conflicts:
        raise ReleaseEvidenceError(
            f"jury transaction sender reuses a known on-chain role: {conflicts}"
        )
    item_keys = {
        "relay_public_key", "address", "block_number", "block_hash",
        "confirmed_nonce", "latest_nonce", "pending_nonce",
        "pending_transaction", "balance_wei", "code_keccak256",
        "gas_cap_wei",
    }
    summary: dict[str, Any] = {}
    for relay_key in relay_keys:
        item = observed.get(relay_key)
        if not isinstance(item, dict):
            raise ReleaseEvidenceError(
                f"deployed-code jury sender {relay_key} must be an object"
            )
        _exact_keys(item, item_keys, f"deployed-code jury sender {relay_key}")
        confirmed = item.get("confirmed_nonce")
        latest = item.get("latest_nonce")
        pending = item.get("pending_nonce")
        balance = item.get("balance_wei")
        if (
            item.get("relay_public_key") != relay_key
            or item.get("address") != expected_senders[relay_key]
            or item.get("block_number") != state_block_number
            or item.get("block_hash") != state_block_hash
            or type(confirmed) is not int
            or type(latest) is not int
            or type(pending) is not int
            or not 0 <= confirmed <= latest == pending < 2**256
            or item.get("pending_transaction") is not False
            or type(balance) is not int
            or not gas_cap <= balance < 2**256
            or item.get("code_keccak256") != EMPTY_CODE_KECCAK256
            or item.get("gas_cap_wei") != gas_cap
        ):
            raise ReleaseEvidenceError(
                f"deployed-code jury sender {relay_key} is unsafe, pending, or unbound"
            )
        summary[relay_key] = {
            "address": expected_senders[relay_key],
            "confirmed_nonce": confirmed,
            "latest_nonce": latest,
            "balance_wei": balance,
            "code_keccak256": EMPTY_CODE_KECCAK256,
            "gas_cap_wei": gas_cap,
        }
    return summary


def _validate_deployed_code(
    evidence: dict[str, Any], raw: bytes, source_commit: str,
    deployment: dict[str, Any], provider_network: dict[str, Any],
    manifest_hash: str, provider_network_hash: str, consumer_network_hash: str,
) -> dict[str, Any]:
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE
    expected_keys = {
        "schema", "source_commit", "chain_id", "address", "transaction_hash",
        "block_number", "block_hash", "runtime_code", "runtime_code_sha256",
        "runtime_code_keccak256", "confirmations", "rpc_quorum",
        "deployment_manifest_sha256", "provider_network_manifest_sha256",
        "consumer_network_manifest_sha256",
        "deployer", "state_block_number", "state_block_hash",
        "state_block_timestamp", "contract_state", "capacity_channels",
    }
    if dynamic_jury:
        expected_keys.update((
            "jury_registry_state", "jury_decision_policy_hash",
            "jury_transaction_senders", REPUTATION_HISTORY_FIELD,
        ))
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
    if evidence.get("consumer_network_manifest_sha256") != consumer_network_hash:
        raise ReleaseEvidenceError(
            "deployed-code Consumer network manifest hash differs from repository bytes"
        )
    if evidence.get("deployer") != deployment.get("deployer"):
        raise ReleaseEvidenceError("deployed-code deployer differs from the deployment manifest")
    if dynamic_jury and (
        evidence.get("jury_decision_policy_hash")
        != deployment.get("jury_decision_policy_hash")
    ):
        raise ReleaseEvidenceError(
            "deployed-code jury decision policy hash differs from the deployment manifest"
        )
    reputation_history = None
    if dynamic_jury:
        deployment_boundary = _dynamic_deployment_boundary(
            deployment, label="deployment",
        )
        if (
            evidence.get("block_number") != deployment_boundary["deployment_block"]
            or evidence.get("block_hash") != deployment_boundary["deployment_block_hash"]
            or evidence.get("runtime_code_keccak256")
                != deployment_boundary["settlement_runtime_code_keccak256"]
        ):
            raise ReleaseEvidenceError(
                "deployed-code Settlement boundary differs from manifests"
            )
        reputation_history = _reputation_history_lineage(
            evidence.get(REPUTATION_HISTORY_FIELD),
            deployment=deployment,
            label="deployed-code reputation_history_import",
        )
        if reputation_history != deployment.get(REPUTATION_HISTORY_FIELD):
            raise ReleaseEvidenceError(
                "deployed-code reputation history lineage differs from manifests"
            )
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
    jury_registry = (
        _validate_jury_registry_state(evidence.get("jury_registry_state"), deployment)
        if dynamic_jury else None
    )
    _validate_capacity_channels(
        evidence.get("capacity_channels"), deployment, provider_network,
        state_block_number, state_block_timestamp, minimum_fee,
    )
    jury_sender_summary = (
        _validate_jury_transaction_senders(
            evidence.get("jury_transaction_senders"),
            deployment=deployment,
            provider_network=provider_network,
            contract_state=evidence.get("contract_state"),
            registry_state=evidence.get("jury_registry_state"),
            capacity_channels=evidence.get("capacity_channels"),
            state_block_number=state_block_number,
            state_block_hash=evidence["state_block_hash"],
        )
        if dynamic_jury else None
    )
    _, runtime = _runtime(evidence.get("runtime_code"))
    runtime_sha256 = hashlib.sha256(runtime).hexdigest()
    runtime_keccak = _keccak256(runtime)
    if (
        evidence.get("runtime_code_sha256") != runtime_sha256
        or evidence.get("runtime_code_keccak256") != runtime_keccak
    ):
        raise ReleaseEvidenceError("deployed-code runtime hashes do not match runtime_code")
    result = {
        **identity,
        # The deployed-code schema calls this value ``block_number`` while
        # the release artifact contract section uses the manifest's
        # ``deployment_block`` name. Keep both explicit so the artifact gate
        # cannot silently lose the deployment boundary.
        "deployment_block": identity["block_number"],
        "deployed_code_evidence_sha256": _sha256_bytes(raw),
        "runtime_code_sha256": runtime_sha256,
        "runtime_code_keccak256": runtime_keccak,
    }
    if jury_registry is not None:
        result["jury_registry"] = jury_registry
        result["jury_decision_policy_hash"] = deployment["jury_decision_policy_hash"]
        result["jury_transaction_senders"] = jury_sender_summary
        result[REPUTATION_HISTORY_FIELD] = reputation_history
    return result


def _abi_parameter_type(value: Any) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        raise ReleaseEvidenceError("ABI parameter must have a type")
    abi_type = value["type"]
    if not abi_type.startswith("tuple"):
        return abi_type
    components = value.get("components")
    if not isinstance(components, list):
        raise ReleaseEvidenceError("ABI tuple parameter must have components")
    suffix = abi_type[len("tuple"):]
    return "(" + ",".join(_abi_parameter_type(item) for item in components) + ")" + suffix


def _abi_item_signature(item: dict[str, Any]) -> str:
    name, inputs = item.get("name"), item.get("inputs")
    if not isinstance(name, str) or not isinstance(inputs, list):
        raise ReleaseEvidenceError("ABI function/event must have a name and inputs")
    return name + "(" + ",".join(_abi_parameter_type(value) for value in inputs) + ")"


def _provider_updated_event_ok(abi: list[dict[str, Any]]) -> bool:
    matches = [
        item for item in abi
        if item.get("type") == "event" and item.get("name") == "ProviderUpdated"
    ]
    if len(matches) != 1:
        return False
    event = matches[0]
    try:
        signature = _abi_item_signature(event)
    except ReleaseEvidenceError:
        return False
    inputs = event.get("inputs")
    return bool(
        signature == PROVIDER_UPDATED_EVENT_SIGNATURE
        and event.get("anonymous") is False
        and isinstance(inputs, list)
        and tuple(item.get("indexed") for item in inputs)
            == PROVIDER_UPDATED_EVENT_INDEXED
    )


def _validate_foundry_artifact(
    artifact: dict[str, Any], raw: bytes, *, label: str = "Foundry V10",
    required_functions: set[str] | None = None,
    required_function_signatures: frozenset[str] | None = None,
    require_provider_updated_event: bool = False,
    expected_immutable_count: int | None = None,
) -> dict[str, str]:
    abi = artifact.get("abi")
    if not isinstance(abi, list) or not all(isinstance(item, dict) for item in abi):
        raise ReleaseEvidenceError(f"{label} artifact must contain an ABI array")
    functions = {
        item.get("name") for item in abi
        if item.get("type") == "function" and isinstance(item.get("name"), str)
    }
    function_signatures = {
        _abi_item_signature(item) for item in abi if item.get("type") == "function"
    }
    required = required_functions or {
        "MAX_CHANNEL_DURATION", "openCapacityChannels",
        "settleReservedReceipt", "voteDisputeBySig",
    }
    if not required.issubset(functions):
        raise ReleaseEvidenceError(
            f"{label} ABI is missing functions: {sorted(required - functions)}"
        )
    required_signatures = required_function_signatures or frozenset()
    missing_signatures = required_signatures - function_signatures
    if missing_signatures:
        raise ReleaseEvidenceError(
            f"{label} ABI is missing function signatures: {sorted(missing_signatures)}"
        )
    if require_provider_updated_event and not _provider_updated_event_ok(abi):
        raise ReleaseEvidenceError(
            f"{label} ABI is missing the canonical ProviderUpdated event"
        )
    deployed = artifact.get("deployedBytecode")
    if not isinstance(deployed, dict):
        raise ReleaseEvidenceError(f"{label} artifact must contain deployedBytecode")
    bytecode = deployed.get("object")
    references = deployed.get("immutableReferences")
    if (
        not isinstance(bytecode, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]+", bytecode)
        or len(bytecode) <= 2
        or len(bytecode) % 2
        or not isinstance(references, dict)
        or not references
        or (
            expected_immutable_count is not None
            and len(references) != expected_immutable_count
        )
    ):
        raise ReleaseEvidenceError(
            f"{label} deployed bytecode or immutable references are invalid"
        )
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
    jury_registry_artifact_path: Path | None = None,
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
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE
    jury_policy = (
        _validate_jury_policy(root, deployment) if dynamic_jury else None
    )
    deployment_source_commit = deployment.get("source_commit", source_commit)
    if (
        not isinstance(deployment_source_commit, str)
        or COMMIT_RE.fullmatch(deployment_source_commit) is None
    ):
        raise ReleaseEvidenceError("deployment source_commit is invalid")
    contract = _validate_deployed_code(
        deployed, deployed_raw, deployment_source_commit, deployment, provider_network,
        manifest_hashes["deployment_manifest_sha256"],
        manifest_hashes["provider_network_manifest_sha256"],
        manifest_hashes["consumer_network_manifest_sha256"],
    )
    settlement_required = {
        "MAX_CHANNEL_DURATION", "openCapacityChannels",
        "settleReservedReceipt", "voteDisputeBySig",
    }
    if dynamic_jury:
        settlement_required.add("juryRegistry")
    contract.update(_validate_foundry_artifact(
        artifact,
        artifact_raw,
        required_functions=settlement_required,
        expected_immutable_count=6 if dynamic_jury else None,
    ))
    if dynamic_jury:
        if jury_registry_artifact_path is None:
            raise ReleaseEvidenceError(
                "dynamic Provider jury release requires a jury registry Foundry artifact"
            )
        registry_artifact, registry_artifact_raw = _load_json(
            jury_registry_artifact_path, "ProviderJuryRegistryV1 Foundry artifact",
        )
        registry_declaration = contract.get("jury_registry")
        if not isinstance(registry_declaration, dict):
            raise ReleaseEvidenceError("deployed-code jury registry declaration is missing")
        registry_declaration.update(_validate_foundry_artifact(
            registry_artifact,
            registry_artifact_raw,
            label="ProviderJuryRegistryV1",
            required_functions={
                "RANDOMNESS_MODE_HASH", "governance", "reputationAuthority",
                "settlement", "bondPenaltyRecipient", "minimumReputation",
                "jurySize", "threshold", "selectionDelayBlocks", "providerCount",
                "rosterVersion", "pendingAssignments", "canFormJury", "providerAt",
                "assignmentProviderEvidence",
            },
            required_function_signatures=REGISTRY_REQUIRED_FUNCTION_SIGNATURES,
            require_provider_updated_event=True,
            expected_immutable_count=5,
        ))
        contract["jury_policy"] = jury_policy
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
    parser.add_argument(
        "--jury-registry-artifact",
        type=Path,
        help="ProviderJuryRegistryV1 Foundry artifact (required for dynamic jury releases)",
    )
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
            jury_registry_artifact_path=args.jury_registry_artifact,
        )
        _write_exclusive(args.output, evidence)
    except (ReleaseEvidenceError, OSError, tarfile.TarError) as exc:
        print(f"build release evidence: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"output": str(args.output), "schema": RELEASE_SCHEMA}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
