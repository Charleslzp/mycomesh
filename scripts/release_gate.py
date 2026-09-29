#!/usr/bin/env python3
"""Dependency-free checks for the source side of a MycoMesh release.

This gate validates repository wiring, package metadata, and the consistency of
the checked-in V10 manifests. It deliberately does not claim to verify a
published npm tarball, an OCI image/revision, a signature, or live chain code;
those facts only exist after build/deploy and need a separate artifact gate.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
JURY_RELAY_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NPM_METADATA_SCHEMA = "mycomesh.npm-release-candidate.v1"
NPM_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.tgz$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
PROVIDER_IMAGE_RE = re.compile(
    r"^ghcr\.io/charleslzp/mycomesh-provider-codex@sha256:[0-9a-f]{64}$"
)
FORBIDDEN_PARTS = {"artifacts", "out", "cache", "__pycache__", "test-results"}

def _release_profile_path(name: str, default: str) -> str:
    """Resolve a release profile path without permitting repository escape."""
    value = os.environ.get(name, default)
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not value.strip():
        raise ValueError(f"{name} must be a relative repository path")
    return value


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
CONSUMER_CA_PATH = f"packages/mycomesh-cli/networks/{NETWORK_BASENAME}.ca.crt"
JURY_POLICY_PATH = "deployments/provider-jury-policy-v1.json"

# The repository's active V10 candidate is checked in beside the legacy
# compatibility profile. Its source_commit pins the deployed contracts, not
# each subsequent application release.
ACTIVE_DYNAMIC_PROFILE = {
    "deployment": "deployments/sepolia-myco-v10-dynamic-20260926.json",
    "provider_network": "deployments/sepolia-provider-network-v10-dynamic-20260926.json",
    "consumer_network": "packages/mycomesh-cli/networks/v10-dynamic-20260926.json",
}
DEPLOYMENT_BUILD_INPUTS = (
    "contracts/MycoSettlementV10.sol",
    "contracts/ProviderJuryRegistryV1.sol",
    "foundry.toml",
)

REQUIRED_RELEASE_FILES = (
    "Dockerfile",
    DEPLOYMENT_PATH,
    PROVIDER_NETWORK_PATH,
    "deployments/ip-mesh-testnet-ca.crt",
    "contracts/MycoSettlementV9.sol",
    "contracts/MycoSettlementV10.sol",
    "contracts/ProviderJuryRegistryV1.sol",
    "gateway/provider_jury.py",
    "gateway/provider_jury_chain.py",
    "gateway/provider_jury_intake.py",
    "gateway/provider_jury_runtime.py",
    "gateway/provider_jury_service.py",
    "gateway/provider_jury_worker.py",
    "gateway/provider_reputation_ops.py",
    "gateway/provider_reputation_import.py",
    "gateway/provider_reputation_sync.py",
    "gateway/v10_reputation.py",
    JURY_POLICY_PATH,
    "docs/v9-deployment-policy.draft.json",
    "scripts/build_release_evidence.py",
    "scripts/capture_oci_metadata.py",
    "scripts/capture_release_evidence.py",
    "scripts/publish-npm-release.mjs",
    "scripts/stage-npm-release.mjs",
    CONSUMER_NETWORK_PATH,
    CONSUMER_CA_PATH,
)

ARTIFACT_SCHEMA = "mycomesh.release-artifacts.v1"
OCI_METADATA_SCHEMA = "mycomesh.oci-metadata.v1"
DEPLOYED_CODE_SCHEMA = "mycomesh.deployed-code.v4"
REQUIRED_PLATFORMS = frozenset(("linux/amd64", "linux/arm64"))
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_TARBALL_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TARBALL_MEMBERS = 4096
MAX_TARBALL_TOTAL_BYTES = 64 * 1024 * 1024
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
MAX_DYNAMIC_PROVIDERS = 64
MAX_DYNAMIC_JURY_SIZE = 7
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


def _read(root: Path, relative: str) -> str:
    path = root / relative
    if path.is_symlink():
        raise OSError("release input must not be a symbolic link")
    return path.read_text(encoding="utf-8")


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


def _jury_policy_declaration(
    root: Path, deployment: dict[str, Any],
) -> dict[str, Any]:
    """Recompute the executable Provider-AI jury policy preimage."""
    path = root / JURY_POLICY_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError("Provider jury policy must be a regular repository file")
    raw = _read_bounded(path)
    value = _json_bytes(raw)
    if set(value) != JURY_POLICY_FIELDS:
        raise ValueError("Provider jury policy has unknown or missing fields")
    model = value.get("model")
    prompt = value.get("system_prompt")
    maximum = value.get("max_output_tokens")
    ttl = value.get("task_ttl_seconds")
    if value.get("schema") != JURY_POLICY_SCHEMA:
        raise ValueError("unsupported Provider jury policy schema")
    if (
        not isinstance(model, str) or not model or model != model.strip()
        or len(model) > 160 or "\x00" in model
    ):
        raise ValueError("Provider jury policy model is invalid")
    if (
        not isinstance(prompt, str) or not prompt or prompt != prompt.strip()
        or len(prompt) > MAX_JURY_PROMPT_CHARS or "\x00" in prompt
    ):
        raise ValueError("Provider jury policy system_prompt is invalid")
    if type(maximum) is not int or not 1 <= maximum <= 1_000_000:
        raise ValueError("Provider jury policy max_output_tokens is invalid")
    if type(ttl) is not int or not 1 <= ttl <= MAX_JURY_TASK_TTL_SECONDS:
        raise ValueError("Provider jury policy task_ttl_seconds is invalid")
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
        raise ValueError(
            "Provider jury executable policy differs from jury_decision_policy_hash"
        )
    return {
        "path": JURY_POLICY_PATH,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "decision_policy_hash": decision_hash,
        "model": model,
        "system_prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "max_output_tokens": maximum,
        "task_ttl_seconds": ttl,
    }


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


def _npm_tarball_digests(path: Path) -> dict[str, object]:
    """Return the npm pack digests used by the staged candidate metadata."""
    raw = path.read_bytes()
    return {
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "npm_shasum": hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
        "npm_integrity": "sha512-" + base64.b64encode(
            hashlib.sha512(raw).digest()
        ).decode("ascii"),
    }


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


def _deployment_source_status(
    root: Path, deployment_source_commit: str,
) -> tuple[bool, dict[str, object]]:
    """Verify an existing deployment was built from unchanged contract inputs.

    Deployment provenance is intentionally distinct from the app release HEAD:
    npm and OCI artifacts bind to the latter, while deployed bytecode binds to
    the immutable commit recorded by the V10 manifests.
    """
    head = _git_head(root)
    if (
        not isinstance(deployment_source_commit, str)
        or COMMIT_RE.fullmatch(deployment_source_commit) is None
        or head is None
    ):
        return False, {
            "head": head,
            "deployment_source_commit": deployment_source_commit,
            "reason": "deployment source commit or Git HEAD is invalid",
        }
    try:
        ancestor = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", deployment_source_commit, head],
            check=False,
            capture_output=True,
            text=True,
        )
        committed_inputs = subprocess.run(
            ["git", "-C", str(root), "diff", "--quiet", deployment_source_commit, head,
             "--", *DEPLOYMENT_BUILD_INPUTS],
            check=False,
            capture_output=True,
            text=True,
        )
        working_inputs = subprocess.run(
            ["git", "-C", str(root), "diff", "--quiet", "HEAD", "--",
             *DEPLOYMENT_BUILD_INPUTS],
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, {
            "head": head,
            "deployment_source_commit": deployment_source_commit,
            "reason": str(exc),
        }
    ok = (
        ancestor.returncode == 0
        and committed_inputs.returncode == 0
        and working_inputs.returncode == 0
    )
    return ok, {
        "head": head,
        "deployment_source_commit": deployment_source_commit,
        "is_ancestor": ancestor.returncode == 0,
        "committed_build_inputs_unchanged": committed_inputs.returncode == 0,
        "working_tree_build_inputs_unchanged": working_inputs.returncode == 0,
    }


def _strict_git_source_status(
    root: Path, expected_source_commit: str | None,
) -> tuple[bool, dict[str, object]]:
    """Prove strict artifacts came from one clean, fully tracked Git HEAD.

    The ordinary source gate intentionally accepts a development checkout.  The
    artifact gate is a publication boundary, so it must not label working-tree
    or untracked jury code with the previous commit identifier.
    """
    head = _git_head(root)
    if (
        not isinstance(expected_source_commit, str)
        or COMMIT_RE.fullmatch(expected_source_commit) is None
        or head != expected_source_commit
    ):
        return False, {
            "head": head,
            "expected_source_commit": expected_source_commit,
            "reason": "Git HEAD differs from the release source commit",
        }
    try:
        tracked = subprocess.run(
            [
                "git", "-C", str(root), "ls-files", "--error-unmatch", "--",
                *REQUIRED_RELEASE_FILES,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        status = subprocess.run(
            [
                "git", "-C", str(root), "status", "--porcelain=v1",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, {"head": head, "reason": str(exc)}
    dirty = [line for line in status.stdout.splitlines() if line]
    ok = tracked.returncode == 0 and not dirty
    return ok, {
        "head": head,
        "expected_source_commit": expected_source_commit,
        "all_release_sources_tracked": tracked.returncode == 0,
        "dirty_entries": dirty,
        "tracked_error": tracked.stderr.strip() if tracked.returncode else "",
    }


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


def _abi_parameter_type(value: Any) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        raise ValueError("ABI parameter must have a type")
    abi_type = value["type"]
    if not abi_type.startswith("tuple"):
        return abi_type
    components = value.get("components")
    if not isinstance(components, list):
        raise ValueError("ABI tuple parameter must have components")
    suffix = abi_type[len("tuple"):]
    return "(" + ",".join(_abi_parameter_type(item) for item in components) + ")" + suffix


def _abi_item_signature(item: dict[str, Any]) -> str:
    name = item.get("name")
    inputs = item.get("inputs")
    if not isinstance(name, str) or not isinstance(inputs, list):
        raise ValueError("ABI function/event must have a name and inputs")
    return name + "(" + ",".join(_abi_parameter_type(value) for value in inputs) + ")"


def _canonical_abi_details(
    raw: bytes,
) -> tuple[str, str, set[str], set[str], list[dict[str, Any]]]:
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
    signatures = {
        _abi_item_signature(item) for item in abi if item.get("type") == "function"
    }
    return (
        hashlib.sha256(raw).hexdigest(), hashlib.sha256(canonical).hexdigest(),
        functions, signatures, abi,
    )


def _canonical_abi(raw: bytes) -> tuple[str, str, set[str]]:
    artifact_hash, abi_hash, functions, _, _ = _canonical_abi_details(raw)
    return artifact_hash, abi_hash, functions


def _provider_updated_event_ok(abi: list[dict[str, Any]]) -> bool:
    matches = [
        item for item in abi
        if item.get("type") == "event"
        and item.get("name") == "ProviderUpdated"
    ]
    if len(matches) != 1:
        return False
    event = matches[0]
    try:
        signature = _abi_item_signature(event)
    except ValueError:
        return False
    inputs = event.get("inputs")
    return bool(
        signature == PROVIDER_UPDATED_EVENT_SIGNATURE
        and event.get("anonymous") is False
        and isinstance(inputs, list)
        and tuple(item.get("indexed") for item in inputs)
            == PROVIDER_UPDATED_EVENT_INDEXED
    )


def _compiled_runtime(
    raw: bytes,
    *,
    expected_immutable_count: int = 5,
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
    if len(references) != expected_immutable_count:
        raise ValueError(
            "compiler artifact immutable count differs "
            f"(expected={expected_immutable_count}, actual={len(references)})"
        )
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
    if deployment.get("committee_mode") == DYNAMIC_JURY_MODE:
        values["jury_registry"] = address_word("jury_registry")
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


def _verify_registry_runtime_immutables(
    template: bytes,
    runtime: bytes,
    groups: tuple[tuple[tuple[int, int], ...], ...],
    deployment: dict[str, Any],
) -> dict[str, str]:
    """Match all registry immutables, including equal-valued uint settings."""
    if len(runtime) != len(template):
        raise ValueError("jury registry runtime length differs from compiler artifact")
    raw_expected = {
        "bond_penalty_recipient": deployment.get("policy", {}).get("bond_penalty_recipient"),
        "minimum_reputation": deployment.get("minimum_provider_reputation"),
        "jury_size": deployment.get("jury_size"),
        "threshold": deployment.get("adjudication_threshold"),
        "selection_delay_blocks": deployment.get("jury_selection_delay_blocks"),
    }
    expected: dict[str, bytes] = {}
    for name, value in raw_expected.items():
        if name == "bond_penalty_recipient":
            if not isinstance(value, str) or ADDRESS_RE.fullmatch(value) is None or value == ZERO_ADDRESS:
                raise ValueError("jury registry bond penalty recipient cannot be encoded as address")
            expected[name] = bytes.fromhex(value[2:]).rjust(32, b"\0")
            continue
        if type(value) is not int or value < 0 or value >= 2**256:
            raise ValueError(f"jury registry {name} cannot be encoded as uint256")
        expected[name] = value.to_bytes(32, "big")
    unmatched = list(expected)
    matched: dict[str, str] = {}
    patched = bytearray(template)
    for group in groups:
        observed_values: set[bytes] = set()
        for start, length in group:
            if template[start:start + length] != b"\0" * length:
                raise ValueError("jury registry immutable placeholder is not zero-filled")
            observed_values.add(runtime[start:start + length])
        if len(observed_values) != 1:
            raise ValueError("deployed references for one jury registry immutable disagree")
        observed = observed_values.pop()
        name = next((item for item in unmatched if expected[item] == observed), None)
        if name is None:
            raise ValueError("jury registry immutable does not match the deployment manifest")
        unmatched.remove(name)
        matched[name] = "0x" + observed.hex()
        for start, length in group:
            patched[start:start + length] = observed
    if unmatched:
        raise ValueError("jury registry compiler immutable set is incomplete")
    if bytes(patched) != runtime:
        raise ValueError(
            "jury registry runtime differs from compiler output outside exact immutables"
        )
    return matched


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing or unexpected:
        raise ValueError(f"{label} keys differ (missing={missing}, unexpected={unexpected})")


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


def _jury_sender_manifest_status(
    deployment: dict[str, Any], provider: dict[str, Any], consumer: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    relay_keys = provider.get("jury_relay_public_keys")
    senders = provider.get("jury_transaction_senders")
    gas_cap = provider.get(JURY_TRANSACTION_GAS_CAP_FIELD)
    keys_ok = (
        isinstance(relay_keys, list)
        and 1 <= len(relay_keys) <= 4
        and all(
            isinstance(key, str)
            and JURY_RELAY_PUBLIC_KEY_RE.fullmatch(key) is not None
            for key in relay_keys
        )
        and len(set(relay_keys)) == len(relay_keys)
    )
    mapping_ok = bool(
        keys_ok
        and isinstance(senders, dict)
        and set(senders) == set(relay_keys)
        and all(
            isinstance(value, str)
            and ADDRESS_RE.fullmatch(value) is not None
            and value != ZERO_ADDRESS
            for value in senders.values()
        )
        and len(set(senders.values())) == len(senders)
    )
    parity_ok = bool(
        keys_ok
        and consumer.get("jury_relay_public_keys") == relay_keys
        and consumer.get("jury_transaction_senders") == senders
        and consumer.get(JURY_TRANSACTION_GAS_CAP_FIELD) == gas_cap
    )
    conflicts = (
        sorted(set(senders.values()) & _known_role_addresses(deployment, provider))
        if mapping_ok else []
    )
    cap_ok = type(gas_cap) is int and 0 < gas_cap < 2**256
    ok = bool(mapping_ok and parity_ok and cap_ok and not conflicts)
    return ok, {
        "relay_keys": relay_keys,
        "senders": senders,
        "gas_cap_wei": gas_cap,
        "provider_consumer_parity": parity_ok,
        "role_conflicts": conflicts,
    }


def _reputation_history_lineage(
    value: Any, *, deployment: dict[str, Any], label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a non-null object")
    _require_exact_keys(value, REPUTATION_HISTORY_FIELDS, label)
    network_id = value.get("source_network_id")
    artifact_sha = value.get("artifact_sha256")
    source_deployment_block = value.get("source_deployment_block")
    source_history_through_block = value.get("source_history_through_block")
    if (
        value.get("schema") != REPUTATION_HISTORY_SCHEMA
        or not isinstance(network_id, str)
        or not network_id
        or network_id != network_id.strip()
        or len(network_id) > 160
        or network_id == deployment.get("network_id")
        or type(value.get("source_protocol_version")) is not int
        or value["source_protocol_version"] not in {9, 10}
        or type(value.get("source_chain_id")) is not int
        or value["source_chain_id"] != deployment.get("chain_id")
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
        or type(value.get("confirmations")) is not int
        or not 2 <= value["confirmations"] <= 256
        or not isinstance(artifact_sha, str)
        or SHA256_RE.fullmatch(artifact_sha) is None
        or artifact_sha == "0" * 64
        or not isinstance(value.get("artifact_root"), str)
        or HASH_RE.fullmatch(value["artifact_root"]) is None
        or value["artifact_root"] == ZERO_HASH
    ):
        raise ValueError(f"{label} is invalid or not a prior same-chain deployment")
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
        raise ValueError(f"{label} dynamic Settlement deployment boundary is invalid")
    return {
        "deployment_block": deployment_block,
        "deployment_block_hash": deployment_block_hash,
        "settlement_runtime_code_keccak256": runtime_hash,
    }


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
    deployment_hash: str, provider_network_hash: str, consumer_network_hash: str,
) -> dict[str, Any]:
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE
    evidence_keys = {
        "schema", "source_commit", "chain_id", "address", "transaction_hash",
        "block_number", "block_hash", "runtime_code", "runtime_code_sha256",
        "runtime_code_keccak256", "confirmations", "rpc_quorum",
        "deployment_manifest_sha256", "provider_network_manifest_sha256",
        "consumer_network_manifest_sha256",
        "deployer", "state_block_number", "state_block_hash",
        "state_block_timestamp", "contract_state", "capacity_channels",
    }
    if dynamic_jury:
        evidence_keys.update((
            "jury_registry_state", "jury_decision_policy_hash",
            "jury_transaction_senders", REPUTATION_HISTORY_FIELD,
        ))
    _require_exact_keys(evidence, evidence_keys, "deployed-code evidence")
    deployment_source = deployment.get("source_commit")
    if (
        deployment_source is not None
        and evidence.get("source_commit") != deployment_source
    ):
        raise ValueError("deployed-code source commit differs from deployment manifest")
    if (
        evidence.get("deployment_manifest_sha256") != deployment_hash
        or evidence.get("provider_network_manifest_sha256") != provider_network_hash
        or evidence.get("consumer_network_manifest_sha256") != consumer_network_hash
        or evidence.get("deployer") != deployment.get("deployer")
    ):
        raise ValueError("deployed-code manifest hashes or deployer do not match")
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
            raise ValueError(
                "deployed-code Settlement boundary differs from manifests"
            )
        decision_policy_hash = deployment.get("jury_decision_policy_hash")
        if (
            not isinstance(decision_policy_hash, str)
            or HASH_RE.fullmatch(decision_policy_hash) is None
            or decision_policy_hash == ZERO_HASH
            or evidence.get("jury_decision_policy_hash") != decision_policy_hash
        ):
            raise ValueError(
                "deployed-code jury decision policy hash differs from the manifest"
            )
        history = _reputation_history_lineage(
            evidence.get(REPUTATION_HISTORY_FIELD),
            deployment=deployment,
            label="deployed-code reputation_history_import",
        )
        if history != deployment.get(REPUTATION_HISTORY_FIELD):
            raise ValueError(
                "deployed-code reputation history lineage differs from manifests"
            )
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
    state_keys = {
        "stablecoin", "reward_token", "adjudication_threshold", "governance",
        "treasury", "domain_separator", "policy", "channel",
        "max_channel_duration_seconds",
        "stablecoin_runtime_code_sha256", "stablecoin_runtime_code_keccak256",
        "stablecoin_balance", "stable_liabilities",
    }
    state_keys.add("jury_registry" if dynamic_jury else "adjudicators")
    _require_exact_keys(state, state_keys, "deployed-code contract_state")
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
        "policy": deployment.get("policy"),
        "stablecoin_runtime_code_sha256": deployment.get(
            "stablecoin_runtime_code_sha256"
        ),
        "stablecoin_runtime_code_keccak256": deployment.get(
            "stablecoin_runtime_code_keccak256"
        ),
    }
    expected_state["jury_registry" if dynamic_jury else "adjudicators"] = deployment.get(
        "jury_registry" if dynamic_jury else "adjudicators"
    )
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

    registry_summary: dict[str, Any] | None = None
    if dynamic_jury:
        registry_state = evidence.get("jury_registry_state")
        if not isinstance(registry_state, dict):
            raise ValueError("deployed-code jury_registry_state must be an object")
        registry_keys = {
            "address", "governance", "reputation_authority", "settlement",
            "bond_penalty_recipient",
            "minimum_reputation", "jury_size", "threshold",
            "selection_delay_blocks", "randomness", "provider_count",
            "roster_version", "pending_assignments", "can_form_jury",
            "providers", "runtime_code", "runtime_code_sha256",
            "runtime_code_keccak256",
        }
        _require_exact_keys(
            registry_state, registry_keys, "deployed-code jury_registry_state"
        )
        expected_registry_state = {
            "address": deployment.get("jury_registry"),
            "governance": deployment.get("jury_registry_governance"),
            "reputation_authority": deployment.get("reputation_authority"),
            "settlement": deployment.get("settlement"),
            "bond_penalty_recipient": deployment.get("policy", {}).get("bond_penalty_recipient"),
            "minimum_reputation": deployment.get("minimum_provider_reputation"),
            "jury_size": deployment.get("jury_size"),
            "threshold": deployment.get("adjudication_threshold"),
            "selection_delay_blocks": deployment.get("jury_selection_delay_blocks"),
            "randomness": _keccak256(DYNAMIC_JURY_RANDOMNESS.encode("utf-8")),
        }
        if any(
            registry_state.get(key) != value
            for key, value in expected_registry_state.items()
        ):
            raise ValueError("jury registry state differs from deployment manifest")
        providers = registry_state.get("providers")
        registry_manifest = _dynamic_jury_manifest_status(deployment, providers)
        if (
            not registry_manifest["config_ok"]
            or not registry_manifest["providers_ok"]
            or not registry_manifest["can_form_jury"]
            or not isinstance(providers, list)
            or registry_state.get("provider_count") != len(providers)
            or type(registry_state.get("roster_version")) is not int
            or registry_state["roster_version"] < len(providers)
            or registry_state.get("pending_assignments") != 0
            or registry_state.get("can_form_jury") is not True
        ):
            raise ValueError("jury registry cannot safely form the declared jury")
        try:
            registry_runtime = _hex_runtime(registry_state.get("runtime_code"))
        except ValueError as exc:
            raise ValueError(f"invalid jury registry runtime: {exc}") from exc
        registry_sha256 = hashlib.sha256(registry_runtime).hexdigest()
        registry_keccak = _keccak256(registry_runtime)
        if (
            registry_state.get("runtime_code_sha256") != registry_sha256
            or registry_state.get("runtime_code_keccak256") != registry_keccak
        ):
            raise ValueError("jury registry runtime hashes do not match raw deployed code")
        registry_summary = {
            "address": registry_state["address"],
            "provider_count": registry_state["provider_count"],
            "roster_version": registry_state["roster_version"],
            "can_form_jury": True,
            "runtime_code_sha256": registry_sha256,
            "runtime_code_keccak256": registry_keccak,
        }
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
    if dynamic_jury:
        channel_keys.add("jury_ready")
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
            or (dynamic_jury and channel.get("jury_ready") is not True)
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
    jury_sender_summary: dict[str, Any] | None = None
    if dynamic_jury:
        relay_keys = provider_network.get("jury_relay_public_keys")
        expected_senders = provider_network.get("jury_transaction_senders")
        gas_cap = provider_network.get(JURY_TRANSACTION_GAS_CAP_FIELD)
        observed_senders = evidence.get("jury_transaction_senders")
        if (
            not isinstance(relay_keys, list)
            or not isinstance(expected_senders, dict)
            or not isinstance(observed_senders, dict)
            or set(observed_senders) != set(relay_keys)
            or set(expected_senders) != set(relay_keys)
        ):
            raise ValueError(
                "deployed-code jury transaction sender evidence keys differ from manifests"
            )
        conflicts = sorted(set(expected_senders.values()) & _known_role_addresses(
            deployment, provider_network, state, registry_state, channels,
        ))
        if conflicts:
            raise ValueError(
                f"jury transaction sender reuses a known on-chain role: {conflicts}"
            )
        sender_keys = {
            "relay_public_key", "address", "block_number", "block_hash",
            "confirmed_nonce", "latest_nonce", "pending_nonce",
            "pending_transaction", "balance_wei", "code_keccak256",
            "gas_cap_wei",
        }
        jury_sender_summary = {}
        for relay_key in relay_keys:
            item = observed_senders.get(relay_key)
            if not isinstance(item, dict):
                raise ValueError(f"jury sender {relay_key} must be an object")
            _require_exact_keys(item, sender_keys, f"jury sender {relay_key}")
            confirmed = item.get("confirmed_nonce")
            latest = item.get("latest_nonce")
            pending = item.get("pending_nonce")
            balance = item.get("balance_wei")
            if (
                item.get("relay_public_key") != relay_key
                or item.get("address") != expected_senders[relay_key]
                or item.get("block_number") != state_number
                or item.get("block_hash") != evidence["state_block_hash"]
                or type(confirmed) is not int
                or type(latest) is not int
                or type(pending) is not int
                or not 0 <= confirmed <= latest == pending < 2**256
                or item.get("pending_transaction") is not False
                or type(balance) is not int
                or type(gas_cap) is not int
                or not 0 < gas_cap <= balance < 2**256
                or item.get("code_keccak256") != EMPTY_CODE_KECCAK256
                or item.get("gas_cap_wei") != gas_cap
            ):
                raise ValueError(
                    f"jury sender {relay_key} is unsafe, pending, or unbound"
                )
            jury_sender_summary[relay_key] = {
                "address": expected_senders[relay_key],
                "confirmed_nonce": confirmed,
                "latest_nonce": latest,
                "balance_wei": balance,
                "code_keccak256": EMPTY_CODE_KECCAK256,
                "gas_cap_wei": gas_cap,
            }
    summary = {
        "state_block_number": state_number,
        "state_block_hash": evidence["state_block_hash"],
        "state_block_timestamp": state_timestamp,
        "capacity_channel_count": len(channels),
    }
    if registry_summary is not None:
        summary["jury_registry"] = registry_summary
        summary["jury_transaction_senders"] = jury_sender_summary
    return summary


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


def _dynamic_jury_manifest_status(
    deployment: dict[str, Any], providers: list[Any] | None = None,
) -> dict[str, Any]:
    """Validate dynamic jury policy and, when supplied, a live pool snapshot.

    Deployment manifests must never pin Provider membership: reputation can
    add, disable, or re-score eligible Providers after release.  Strict release
    evidence supplies ``providers`` from one confirmed Registry block so this
    helper can still independently prove that the live pool formed a jury.
    """
    registry = deployment.get("jury_registry")
    governance = deployment.get("jury_registry_governance")
    authority = deployment.get("reputation_authority")
    minimum = deployment.get("minimum_provider_reputation")
    size = deployment.get("jury_size")
    threshold = deployment.get("adjudication_threshold")
    delay = deployment.get("jury_selection_delay_blocks")
    randomness = deployment.get("jury_randomness")
    decision_policy_hash = deployment.get("jury_decision_policy_hash")
    settlement = deployment.get("settlement")
    network_id = deployment.get("network_id")

    addresses = (registry, governance, authority, settlement)
    address_ok = all(
        isinstance(value, str)
        and ADDRESS_RE.fullmatch(value) is not None
        and value != ZERO_ADDRESS
        for value in addresses
    )
    authority_ok = bool(
        address_ok
        and registry != settlement
        and registry != governance
        and registry != authority
        and governance != authority
        and governance == deployment.get("governance")
    )
    policy_ok = (
        type(minimum) is int
        and 0 < minimum < 2**64
        and type(size) is int
        and 3 <= size <= MAX_DYNAMIC_JURY_SIZE
        and type(threshold) is int
        and 2 <= threshold <= size
        and threshold > size // 2
        and type(delay) is int
        and 0 < delay <= 64
    )
    randomness_ok = (
        randomness == DYNAMIC_JURY_RANDOMNESS
        and deployment.get("chain_id") == SEPOLIA_CHAIN_ID
        and isinstance(network_id, str)
        and network_id.endswith("-controlled-test")
        and deployment.get("reward_token") == ZERO_ADDRESS
    )
    decision_policy_ok = bool(
        isinstance(decision_policy_hash, str)
        and HASH_RE.fullmatch(decision_policy_hash) is not None
        and decision_policy_hash != ZERO_HASH
    )

    forbidden_fields = sorted(DYNAMIC_JURY_FORBIDDEN_FIELDS.intersection(deployment))
    schema_ok = not forbidden_fields
    roster_unpinned = "jury_provider_evidence" not in deployment
    raw_providers = providers
    required_provider_keys = {
        "owner", "vote_signer", "operator_id_hash", "peer_id_hash",
        "capability_hash", "reputation", "active", "source_sequence",
        "source_digest",
    }
    providers_ok = schema_ok and (
        raw_providers is None
        or isinstance(raw_providers, list)
        and 0 < len(raw_providers) <= MAX_DYNAMIC_PROVIDERS
    )
    owners: list[str] = []
    signers: list[str] = []
    eligible_operators: set[str] = set()
    eligible_providers = 0
    malformed_indexes: list[int] = []
    authority_accounts = {
        governance, authority, settlement, registry, deployment.get("treasury"),
        deployment.get("policy", {}).get("bond_penalty_recipient"),
    }
    if isinstance(raw_providers, list):
        for index, item in enumerate(raw_providers):
            item_ok = isinstance(item, dict) and set(item) == required_provider_keys
            if not item_ok:
                malformed_indexes.append(index)
                providers_ok = False
                continue
            owner = item.get("owner")
            signer = item.get("vote_signer")
            hashes = tuple(item.get(name) for name in (
                "operator_id_hash", "peer_id_hash", "capability_hash",
            ))
            reputation = item.get("reputation")
            source_sequence = item.get("source_sequence")
            source_digest = item.get("source_digest")
            item_ok = (
                isinstance(owner, str)
                and ADDRESS_RE.fullmatch(owner) is not None
                and owner != ZERO_ADDRESS
                and isinstance(signer, str)
                and ADDRESS_RE.fullmatch(signer) is not None
                and signer != ZERO_ADDRESS
                and all(
                    isinstance(value, str)
                    and HASH_RE.fullmatch(value) is not None
                    and value != ZERO_HASH
                    for value in hashes
                )
                and type(reputation) is int
                and 0 <= reputation < 2**64
                and type(source_sequence) is int
                and 0 < source_sequence < 2**64
                and isinstance(source_digest, str)
                and HASH_RE.fullmatch(source_digest) is not None
                and source_digest != ZERO_HASH
                and type(item.get("active")) is bool
                and owner not in authority_accounts
                and signer not in authority_accounts
            )
            if not item_ok:
                malformed_indexes.append(index)
                providers_ok = False
                continue
            owners.append(owner)
            signers.append(signer)
            if item["active"] and policy_ok and reputation >= minimum:
                eligible_providers += 1
                eligible_operators.add(item["operator_id_hash"])
    identity_ok = bool(providers_ok and (
        raw_providers is None
        or len(owners) == len(set(owners))
        and len(signers) == len(set(signers))
        and not (set(owners) & set(signers))
    ))
    can_form = None if raw_providers is None else bool(
        identity_ok and policy_ok and len(eligible_operators) >= size
    )
    return {
        "config_ok": (
            schema_ok and authority_ok and policy_ok
            and randomness_ok and decision_policy_ok
        ),
        "schema_ok": schema_ok,
        "forbidden_fields": forbidden_fields,
        "authority_ok": authority_ok,
        "policy_ok": policy_ok,
        "randomness_ok": randomness_ok,
        "decision_policy_ok": decision_policy_ok,
        "providers_ok": identity_ok,
        "can_form_jury": can_form,
        "registry": registry,
        "governance": governance,
        "reputation_authority": authority,
        "minimum_reputation": minimum,
        "jury_size": size,
        "threshold": threshold,
        "selection_delay_blocks": delay,
        "randomness": randomness,
        "decision_policy_hash": decision_policy_hash,
        "production_grade_randomness": False,
        "roster_unpinned": roster_unpinned,
        "provider_count": len(raw_providers) if isinstance(raw_providers, list) else None,
        "eligible_provider_count": eligible_providers,
        "eligible_distinct_operator_count": len(eligible_operators),
        "malformed_provider_indexes": malformed_indexes,
    }


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

    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE

    # The manifests pin the deployed contract source. Application artifacts
    # bind separately to the release HEAD at the strict artifact boundary.
    manifest_commits = {
        label: value.get("source_commit")
        for label, value in (
            ("deployment", deployment),
            ("provider_network", provider_network),
            ("consumer_network", consumer_network),
        )
        if "source_commit" in value
    }
    if manifest_commits:
        missing_source_commits = sorted(
            label for label, value in (
                ("deployment", deployment),
                ("provider_network", provider_network),
                ("consumer_network", consumer_network),
            )
            if "source_commit" not in value
        )
        malformed = sorted(
            label for label, commit in manifest_commits.items()
            if not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None
        )
        distinct = sorted({commit for commit in manifest_commits.values() if isinstance(commit, str)})
        source_commit_ok = (
            not missing_source_commits
            and not malformed
            and len(distinct) == 1
        )
        deployment_source_detail: dict[str, object] = {
            "status": "not_checked",
            "reason": "manifest source commits are missing, malformed, or inconsistent",
        }
        if source_commit_ok:
            source_commit_ok, deployment_source_detail = _deployment_source_status(
                root, distinct[0],
            )
        _add(
            checks,
            "v10-manifest-source-commit",
            source_commit_ok,
            {
                "deployment_source": deployment_source_detail,
                "manifest_commits": manifest_commits,
                "missing": missing_source_commits,
                "malformed": malformed,
            },
        )
    else:
        # Legacy static manifests predate source provenance, but the dynamic
        # profile must never fall back to that compatibility path.
        _add(
            checks,
            "v10-manifest-source-commit",
            not dynamic_jury,
            {
                "status": "not_pinned" if not dynamic_jury else "required",
                "reason": "legacy static manifests" if not dynamic_jury
                else "dynamic jury manifests require a pinned deployment source",
            },
        )

    relay_keys = provider_network.get("jury_relay_public_keys")
    relay_keys_ok = (
        dynamic_jury
        and "jury_relay_public_keys" not in deployment
        and isinstance(relay_keys, list)
        and 1 <= len(relay_keys) <= 4
        and all(
            isinstance(key, str)
            and JURY_RELAY_PUBLIC_KEY_RE.fullmatch(key) is not None
            for key in relay_keys
        )
        and len(set(relay_keys)) == len(relay_keys)
        and consumer_network.get("jury_relay_public_keys") == relay_keys
    )
    if not dynamic_jury:
        relay_keys_ok = not any(
            "jury_relay_public_keys" in value
            for value in (deployment, provider_network, consumer_network)
        )
    _add(
        checks,
        "v10-jury-relay-public-key-pins",
        relay_keys_ok,
        {
            "mode": deployment.get("committee_mode"),
            "deployment_contains_keys": "jury_relay_public_keys" in deployment,
            "provider_keys": relay_keys,
            "consumer_keys": consumer_network.get("jury_relay_public_keys"),
        },
    )
    jury_network_fields = {
        "jury_relay_public_keys", "jury_transaction_senders",
        JURY_TRANSACTION_GAS_CAP_FIELD,
    }
    if dynamic_jury:
        sender_config_ok, sender_detail = _jury_sender_manifest_status(
            deployment, provider_network, consumer_network,
        )
        sender_config_ok = bool(
            sender_config_ok and not jury_network_fields.intersection(deployment)
        )
        sender_detail["deployment_fields"] = sorted(
            jury_network_fields.intersection(deployment)
        )
    else:
        present = {
            label: sorted(jury_network_fields.intersection(value))
            for label, value in (
                ("deployment", deployment),
                ("provider", provider_network),
                ("consumer", consumer_network),
            )
            if jury_network_fields.intersection(value)
        }
        sender_config_ok = not present
        sender_detail = {"unexpected_fields": present}
    _add(
        checks,
        "v10-jury-transaction-senders",
        sender_config_ok,
        sender_detail,
    )
    boundary_ok = True
    boundary_detail: object = {"mode": "static-compatible"}
    if dynamic_jury:
        try:
            deployment_boundary = _dynamic_deployment_boundary(
                deployment, label="deployment",
            )
            provider_boundary = _dynamic_deployment_boundary(
                provider_network, label="Provider",
            )
            consumer_boundary = _dynamic_deployment_boundary(
                consumer_network, label="Consumer",
            )
            boundary_ok = (
                deployment_boundary == provider_boundary == consumer_boundary
            )
            boundary_detail = deployment_boundary
        except (ValueError, TypeError) as exc:
            boundary_ok = False
            boundary_detail = str(exc)
    _add(
        checks,
        "v10-dynamic-settlement-deployment-boundary",
        boundary_ok,
        boundary_detail,
    )
    history_ok = False
    history_detail: object
    if dynamic_jury:
        try:
            deployment_history = _reputation_history_lineage(
                deployment.get(REPUTATION_HISTORY_FIELD),
                deployment=deployment,
                label="deployment reputation_history_import",
            )
            provider_history = _reputation_history_lineage(
                provider_network.get(REPUTATION_HISTORY_FIELD),
                deployment=deployment,
                label="Provider reputation_history_import",
            )
            consumer_history = _reputation_history_lineage(
                consumer_network.get(REPUTATION_HISTORY_FIELD),
                deployment=deployment,
                label="Consumer reputation_history_import",
            )
            history_ok = (
                deployment_history == provider_history == consumer_history
            )
            history_detail = deployment_history
        except (ValueError, TypeError) as exc:
            history_detail = str(exc)
    else:
        present = [
            label for label, value in (
                ("deployment", deployment),
                ("provider", provider_network),
                ("consumer", consumer_network),
            )
            if REPUTATION_HISTORY_FIELD in value
        ]
        history_ok = not present
        history_detail = {"unexpected_in": present}
    _add(
        checks,
        "v10-reputation-history-import",
        history_ok,
        history_detail,
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
    if mode == DYNAMIC_JURY_MODE:
        dynamic = _dynamic_jury_manifest_status(deployment)
        manifest_forbidden = {
            label: sorted(DYNAMIC_JURY_FORBIDDEN_FIELDS.intersection(value))
            for label, value in (
                ("deployment", deployment),
                ("provider_network", provider_network),
                ("consumer_network", consumer_network),
            )
        }
        _add(
            checks,
            "v10-dynamic-jury-schema",
            not any(manifest_forbidden.values()),
            manifest_forbidden,
        )
        _add(
            checks,
            "v10-dynamic-jury-config",
            dynamic["config_ok"],
            {key: dynamic[key] for key in (
                "registry", "governance", "reputation_authority",
                "minimum_reputation", "jury_size", "threshold",
                "selection_delay_blocks", "randomness", "decision_policy_hash",
                "production_grade_randomness",
            )},
        )
        try:
            jury_policy = _jury_policy_declaration(root, deployment)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            _add(checks, "v10-dynamic-jury-policy-preimage", False, str(exc))
        else:
            _add(
                checks, "v10-dynamic-jury-policy-preimage", True, jury_policy,
            )
        _add(
            checks,
            "v10-dynamic-jury-provider-pool-policy",
            dynamic["providers_ok"],
            {
                "roster_unpinned": dynamic["roster_unpinned"],
                "membership_source": "confirmed ProviderJuryRegistryV1 state",
            },
        )
        _add(
            checks,
            "v10-dynamic-jury-can-form",
            dynamic["providers_ok"],
            {
                "computed_can_form_jury": None,
                "jury_size": dynamic["jury_size"],
                "verification": "required from confirmed Registry evidence in strict release gate",
            },
        )
        _add(
            checks,
            "v10-committee-declaration",
            dynamic["config_ok"] and dynamic["providers_ok"],
            {
                "mode": mode,
                "network_id": network_id,
                "selection": "dynamic provider registry",
                "static_adjudicators_required": False,
                "production_grade_randomness": False,
            },
        )
    else:
        # Backward compatibility for already deployed static V10 committees.
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
            and deployment.get("reward_token") == ZERO_ADDRESS
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


def _active_dynamic_profile_check(root: Path, checks: list[dict[str, object]]) -> None:
    """Verify the active V10 profile pins one reusable deployment source.

    The command-line profile remains configurable for legacy fixtures, but a
    source gate run in the repository must not silently pass while the active
    dynamic manifests no longer share a valid deployment provenance.
    """
    configured_profile = {
        "deployment": DEPLOYMENT_PATH,
        "provider_network": PROVIDER_NETWORK_PATH,
        "consumer_network": CONSUMER_NETWORK_PATH,
    }
    if configured_profile == ACTIVE_DYNAMIC_PROFILE:
        # _manifest_checks already validates this exact profile, so avoid
        # emitting a duplicate failure when CI selects it explicitly.
        return
    paths = {
        role: root / relative
        for role, relative in ACTIVE_DYNAMIC_PROFILE.items()
    }
    missing = [role for role, path in paths.items() if not path.exists() and not path.is_symlink()]
    invalid = [
        role for role, path in paths.items()
        if path.is_symlink() or (path.exists() and not path.is_file())
    ]
    if not missing and not invalid:
        pass
    elif len(missing) == len(paths) and not invalid:
        _add(
            checks,
            "active-v10-manifest-source-commit",
            True,
            {"status": "not_present", "paths": ACTIVE_DYNAMIC_PROFILE},
        )
        return
    else:
        _add(
            checks,
            "active-v10-manifest-source-commit",
            False,
            {
                "status": "incomplete_or_symlinked",
                "missing": missing,
                "invalid": invalid,
                "paths": ACTIVE_DYNAMIC_PROFILE,
            },
        )
        return
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for role, path in paths.items():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            values[role] = payload.get("source_commit") if isinstance(payload, dict) else None
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors[role] = str(exc)
    commits = {value for value in values.values() if isinstance(value, str)}
    valid = (
        not errors
        and all(isinstance(value, str) and COMMIT_RE.fullmatch(value) for value in values.values())
        and len(commits) == 1
    )
    deployment_source_detail: dict[str, object] = {
        "status": "not_checked",
        "reason": "manifest source commits are malformed or inconsistent",
    }
    if valid:
        valid, deployment_source_detail = _deployment_source_status(root, next(iter(commits)))
    _add(
        checks,
        "active-v10-manifest-source-commit",
        valid,
        {
            "deployment_source": deployment_source_detail,
            "manifest_commits": values,
            "errors": errors,
        },
    )


def check(root: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    root = root.resolve()

    package = _load_json(root, "package.json", checks)
    package_lock = _load_json(root, "package-lock.json", checks)
    consumer_package = _load_json(root, "packages/mycomesh-cli/package.json", checks)
    consumer_lock = _load_json(root, "packages/mycomesh-cli/package-lock.json", checks)
    expected_repository_url = "https://github.com/Charleslzp/mycomesh"
    provenance_repositories = {
        role: metadata.get("repository") if isinstance(metadata, dict) else None
        for role, metadata in (("provider", package), ("consumer", consumer_package))
    }
    _add(
        checks,
        "npm-provenance-repository",
        all(
            isinstance(repository, dict)
            and repository.get("type") == "git"
            and repository.get("url") == expected_repository_url
            for repository in provenance_repositories.values()
        ),
        provenance_repositories,
    )
    deployment = _load_json(root, DEPLOYMENT_PATH, checks)
    provider_network = _load_json(root, PROVIDER_NETWORK_PATH, checks)
    consumer_network = _load_json(root, CONSUMER_NETWORK_PATH, checks)

    provider = _load_text(root, "packages/mycomesh-cli/src/provider.mjs", checks)
    release_module = _load_text(root, "packages/mycomesh-cli/src/release.mjs", checks)
    consumer = _load_text(root, "packages/mycomesh-cli/src/consumer.mjs", checks)
    cli = _load_text(root, "packages/mycomesh-cli/src/cli.mjs", checks)
    makefile = _load_text(root, "Makefile", checks)
    dockerfile = _load_text(root, "Dockerfile", checks)

    docker_runtime_copies = {
        "gateway": bool(
            dockerfile
            and re.search(r"(?m)^COPY\s+gateway\s+\./gateway\s*$", dockerfile)
        ),
        "deployments": bool(
            dockerfile
            and re.search(r"(?m)^COPY\s+deployments\s+\./deployments\s*$", dockerfile)
        ),
        "provider_reputation_import": bool(
            dockerfile
            and re.search(r"(?m)^COPY\s+gateway\s+\./gateway\s*$", dockerfile)
            and (root / "gateway/provider_reputation_import.py").is_file()
        ),
        "v10_reputation": bool(
            dockerfile
            and re.search(r"(?m)^COPY\s+gateway\s+\./gateway\s*$", dockerfile)
            and (root / "gateway/v10_reputation.py").is_file()
        ),
    }
    _add(
        checks,
        "oci-source-includes-provider-jury-runtime",
        all(docker_runtime_copies.values()),
        docker_runtime_copies,
    )

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
            f"networks/{NETWORK_BASENAME}.json",
            f"networks/{NETWORK_BASENAME}.ca.crt",
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
            f"packages/mycomesh-cli/networks/{NETWORK_BASENAME}.json",
            f"packages/mycomesh-cli/networks/{NETWORK_BASENAME}.ca.crt",
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
    _active_dynamic_profile_check(root, checks)

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
    limitations = [
        "published npm tarballs not verified",
        "OCI image digest/revision/signature not verified",
        "live chain bytecode and deployment receipt not verified",
    ]
    if isinstance(deployment, dict) and deployment.get("committee_mode") == DYNAMIC_JURY_MODE:
        limitations.append(
            "future_blockhash_v1 jury randomness is Sepolia test-only and is not production-grade VRF"
        )
    return {
        "schema": "mycomesh.release-source-gate.v1",
        "scope": "source",
        "ok": all(bool(item["ok"]) for item in checks),
        "checks": checks,
        "limitations": limitations,
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


def _verify_npm_candidate_metadata(
    root: Path,
    metadata: dict[str, Any] | None,
    provider_path: Path | None,
    consumer_path: Path | None,
    expected_source_commit: str | None,
    evidence_source_commit: str | None,
    evidence_packages: dict[str, Any] | None,
    image: str | None,
    checks: list[dict[str, object]],
) -> None:
    """Bind staged npm metadata to this source, evidence, and exact tarballs.

    ``stage-npm-release.mjs`` writes this declaration next to the tarballs.  It
    is deliberately checked independently of the aggregate release evidence so
    a caller cannot replace a tarball after evidence generation while retaining
    the old declaration.
    """
    if not isinstance(metadata, dict):
        return

    expected_keys = {"schema", "source_commit", "provider_image", "packages"}
    schema_ok = set(metadata) == expected_keys and metadata.get("schema") == NPM_METADATA_SCHEMA
    _add(
        checks,
        "artifact-npm-metadata-schema",
        schema_ok,
        metadata.get("schema"),
    )

    source_commit = metadata.get("source_commit")
    source_ok = (
        isinstance(source_commit, str)
        and COMMIT_RE.fullmatch(source_commit) is not None
        and source_commit == expected_source_commit
        and (evidence_source_commit is None or source_commit == evidence_source_commit)
    )
    _add(checks, "artifact-npm-source-commit", source_ok, source_commit or "missing")

    metadata_image = metadata.get("provider_image")
    image_ok = (
        isinstance(metadata_image, str)
        and PROVIDER_IMAGE_RE.fullmatch(metadata_image) is not None
        and (image is None or metadata_image == image)
    )
    _add(checks, "artifact-npm-provider-image", image_ok, metadata_image or "missing")

    packages = metadata.get("packages")
    packages_shape_ok = isinstance(packages, dict) and set(packages) == {"provider", "consumer"}
    _add(
        checks,
        "artifact-npm-packages",
        packages_shape_ok,
        sorted(packages) if isinstance(packages, dict) else "missing",
    )

    paths = {"provider": provider_path, "consumer": consumer_path}
    source_package_paths = {
        "provider": root / "package.json",
        "consumer": root / "packages/mycomesh-cli/package.json",
    }
    all_bindings_ok = schema_ok and source_ok and image_ok and packages_shape_ok
    binding_details: dict[str, object] = {}
    for role, path in paths.items():
        declaration = packages.get(role) if isinstance(packages, dict) else None
        role_ok = isinstance(declaration, dict)
        required = {
            "name", "version", "filename", "size", "sha256",
            "npm_shasum", "npm_integrity",
        }
        if role_ok and set(declaration) != required:
            role_ok = False
        try:
            source_package = _json_bytes(source_package_paths[role].read_bytes())
        except (OSError, UnicodeError, ValueError, TypeError):
            source_package = {}
            role_ok = False
        if role_ok:
            role_ok = (
                isinstance(declaration.get("name"), str)
                and declaration.get("name") == source_package.get("name")
                and isinstance(declaration.get("version"), str)
                and declaration.get("version") == source_package.get("version")
                and isinstance(declaration.get("filename"), str)
                and NPM_FILENAME_RE.fullmatch(declaration["filename"]) is not None
            )

        digest_detail: dict[str, object] = {}
        if path is None or not path.is_file() or path.is_symlink() or not role_ok:
            role_ok = False
        else:
            try:
                digest_detail = _npm_tarball_digests(path)
            except OSError:
                role_ok = False
            else:
                role_ok = (
                    role_ok
                    and path.name == declaration.get("filename")
                    and type(declaration.get("size")) is int
                    and declaration.get("size") == digest_detail["size"]
                    and isinstance(declaration.get("sha256"), str)
                    and SHA256_RE.fullmatch(declaration["sha256"]) is not None
                    and declaration.get("sha256") == digest_detail["sha256"]
                    and isinstance(declaration.get("npm_shasum"), str)
                    and SHA1_RE.fullmatch(declaration["npm_shasum"]) is not None
                    and declaration.get("npm_shasum") == digest_detail["npm_shasum"]
                    and declaration.get("npm_integrity") == digest_detail["npm_integrity"]
                )
                try:
                    packed = _tarball_files(path, {"package/package.json"})
                    packed_package = _json_bytes(packed["package/package.json"])
                except (OSError, UnicodeError, ValueError, TypeError, tarfile.TarError):
                    role_ok = False
                else:
                    role_ok = (
                        role_ok
                        and packed_package.get("name") == declaration.get("name")
                        and packed_package.get("version") == declaration.get("version")
                    )

        evidence_declaration = (
            evidence_packages.get(role) if isinstance(evidence_packages, dict) else None
        )
        if isinstance(evidence_declaration, dict) and isinstance(declaration, dict):
            role_ok = role_ok and all(
                declaration.get(field) == evidence_declaration.get(field)
                for field in ("name", "version", "sha256")
            )
        binding_details[role] = {
            "ok": role_ok,
            "filename": declaration.get("filename") if isinstance(declaration, dict) else None,
            "digests": digest_detail,
        }
        all_bindings_ok = all_bindings_ok and role_ok

    _add(checks, "artifact-npm-candidate-binding", all_bindings_ok, binding_details)


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

    network_member = f"{prefix}/networks/{NETWORK_BASENAME}.json"
    ca_member = f"{prefix}/networks/{NETWORK_BASENAME}.ca.crt"
    expected_network = (root / CONSUMER_NETWORK_PATH).read_bytes()
    expected_ca = (root / CONSUMER_CA_PATH).read_bytes()
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
    jury_registry_abi_path: Path | None,
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
    registry_compiled_runtime: bytes | None = None
    registry_immutable_groups: tuple[tuple[tuple[int, int], ...], ...] = ()

    try:
        deployment = _json_bytes((root / DEPLOYMENT_PATH).read_bytes())
        provider_network = _json_bytes((root / PROVIDER_NETWORK_PATH).read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        _add(checks, "artifact-deployed-runtime", False, str(exc))
        return
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE

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
            artifact_hash, abi_hash, functions, _, _ = _canonical_abi_details(abi_raw)
            compiled_runtime, immutable_groups = _compiled_runtime(
                abi_raw,
                expected_immutable_count=6 if dynamic_jury else 5,
            )
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            _add(checks, "artifact-contract-abi", False, str(exc))
        else:
            required_functions = {
                "MAX_CHANNEL_DURATION", "openCapacityChannels",
                "settleReservedReceipt", "voteDisputeBySig",
            }
            if dynamic_jury:
                required_functions.add("juryRegistry")
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

    if dynamic_jury:
        registry_declared = declared.get("jury_registry")
        if jury_registry_abi_path is not None:
            try:
                registry_abi_raw = _read_bounded(jury_registry_abi_path)
                (
                    registry_artifact_hash, registry_abi_hash,
                    registry_functions, registry_function_signatures, registry_abi,
                ) = _canonical_abi_details(registry_abi_raw)
                registry_compiled_runtime, registry_immutable_groups = _compiled_runtime(
                    registry_abi_raw, expected_immutable_count=5,
                )
            except (OSError, UnicodeError, ValueError, TypeError) as exc:
                _add(checks, "artifact-jury-registry-abi", False, str(exc))
            else:
                required_registry_functions = {
                    "RANDOMNESS_MODE_HASH", "minimumReputation", "jurySize",
                    "threshold", "selectionDelayBlocks", "providerCount",
                    "providerAt", "canFormJury", "assignmentProviderEvidence",
                    "bondPenaltyRecipient",
                }
                registry_abi_ok = (
                    isinstance(registry_declared, dict)
                    and registry_declared.get("abi_artifact_sha256")
                        == registry_artifact_hash
                    and registry_declared.get("abi_sha256") == registry_abi_hash
                    and required_registry_functions.issubset(registry_functions)
                    and REGISTRY_REQUIRED_FUNCTION_SIGNATURES.issubset(
                        registry_function_signatures
                    )
                    and _provider_updated_event_ok(registry_abi)
                )
                _add(
                    checks,
                    "artifact-jury-registry-abi",
                    registry_abi_ok,
                    {
                        "artifact_sha256": registry_artifact_hash,
                        "abi_sha256": registry_abi_hash,
                        "missing_functions": sorted(
                            required_registry_functions - registry_functions
                        ),
                        "missing_function_signatures": sorted(
                            REGISTRY_REQUIRED_FUNCTION_SIGNATURES
                            - registry_function_signatures
                        ),
                        "provider_updated_event_ok": _provider_updated_event_ok(
                            registry_abi
                        ),
                        "compiled_runtime_sha256": hashlib.sha256(
                            registry_compiled_runtime
                        ).hexdigest(),
                        "immutable_variable_count": len(registry_immutable_groups),
                    },
                )
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
    if dynamic_jury:
        registry_declared = declared.get("jury_registry")
        registry_identity_ok = (
            isinstance(registry_declared, dict)
            and registry_declared.get("address") == deployment.get("jury_registry")
            and isinstance(registry_declared.get("runtime_code_sha256"), str)
            and SHA256_RE.fullmatch(registry_declared["runtime_code_sha256"])
                is not None
            and isinstance(registry_declared.get("runtime_code_keccak256"), str)
            and HASH_RE.fullmatch(registry_declared["runtime_code_keccak256"])
                is not None
        )
        _add(
            checks,
            "artifact-jury-registry-declaration",
            registry_identity_ok,
            registry_declared if isinstance(registry_declared, dict) else "missing",
        )
        try:
            expected_jury_policy = _jury_policy_declaration(root, deployment)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            _add(checks, "artifact-jury-policy-preimage", False, str(exc))
        else:
            _add(
                checks,
                "artifact-jury-policy-preimage",
                declared.get("jury_policy") == expected_jury_policy,
                expected_jury_policy,
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
        and code_evidence.get("source_commit")
            == deployment.get("source_commit", source_commit)
        and code_evidence.get("chain_id") == deployment.get("chain_id")
        and code_evidence.get("address") == deployment.get("settlement")
        and code_evidence.get("transaction_hash") == deployment.get("tx_hash")
        and code_evidence.get("block_number") == deployment.get("deployment_block")
        and isinstance(code_evidence.get("block_hash"), str)
        and HASH_RE.fullmatch(code_evidence["block_hash"])
        and code_evidence.get("deployment_manifest_sha256") == _sha256(root / DEPLOYMENT_PATH)
        and code_evidence.get("provider_network_manifest_sha256")
            == _sha256(root / PROVIDER_NETWORK_PATH)
        and code_evidence.get("consumer_network_manifest_sha256")
            == _sha256(root / CONSUMER_NETWORK_PATH)
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
            _sha256(root / CONSUMER_NETWORK_PATH),
        )
    except (ValueError, TypeError) as exc:
        _add(checks, "artifact-deployed-state", False, str(exc))
    else:
        _add(checks, "artifact-deployed-state", True, state_summary)
        if dynamic_jury:
            _add(
                checks,
                "artifact-jury-transaction-senders",
                declared.get("jury_transaction_senders")
                == state_summary.get("jury_transaction_senders"),
                state_summary.get("jury_transaction_senders"),
            )
            _add(
                checks,
                "artifact-reputation-history-import",
                declared.get(REPUTATION_HISTORY_FIELD)
                == code_evidence.get(REPUTATION_HISTORY_FIELD)
                == deployment.get(REPUTATION_HISTORY_FIELD),
                code_evidence.get(REPUTATION_HISTORY_FIELD),
            )

    if dynamic_jury:
        registry_declared = declared.get("jury_registry")
        registry_state = code_evidence.get("jury_registry_state")
        decision_policy_hash = deployment.get("jury_decision_policy_hash")
        _add(
            checks,
            "artifact-jury-decision-policy-hash",
            isinstance(decision_policy_hash, str)
            and HASH_RE.fullmatch(decision_policy_hash) is not None
            and decision_policy_hash != ZERO_HASH
            and code_evidence.get("jury_decision_policy_hash") == decision_policy_hash
            and declared.get("jury_decision_policy_hash") == decision_policy_hash,
            decision_policy_hash,
        )
        try:
            if not isinstance(registry_declared, dict):
                raise ValueError("release declaration lacks jury registry")
            if not isinstance(registry_state, dict):
                raise ValueError("deployed evidence lacks jury registry state")
            registry_runtime = _hex_runtime(registry_state.get("runtime_code"))
            registry_sha256 = hashlib.sha256(registry_runtime).hexdigest()
            registry_keccak = _keccak256(registry_runtime)
            if registry_compiled_runtime is None or not registry_immutable_groups:
                raise ValueError(
                    "a full jury registry compiler artifact is required to match deployed runtime"
                )
            registry_immutable_values = _verify_registry_runtime_immutables(
                registry_compiled_runtime,
                registry_runtime,
                registry_immutable_groups,
                deployment,
            )
        except (ValueError, RuntimeError) as exc:
            _add(checks, "artifact-jury-registry-runtime", False, str(exc))
        else:
            registry_runtime_ok = (
                registry_state.get("runtime_code_sha256") == registry_sha256
                and registry_state.get("runtime_code_keccak256") == registry_keccak
                and registry_declared.get("runtime_code_sha256") == registry_sha256
                and registry_declared.get("runtime_code_keccak256") == registry_keccak
            )
            _add(
                checks,
                "artifact-jury-registry-runtime",
                registry_runtime_ok,
                {
                    "address": registry_state.get("address"),
                    "runtime_code_sha256": registry_sha256,
                    "runtime_code_keccak256": registry_keccak,
                    "compiled_runtime_match": True,
                    "verified_immutables": registry_immutable_values,
                    "source": (
                        "raw jury registry runtime matched compiler output with every "
                        "immutable resolved from the deployment manifest"
                    ),
                },
            )
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
    """Require an explicit, usable jury policy for a promotable candidate."""
    detail: object
    try:
        deployment = _json_bytes((root / DEPLOYMENT_PATH).read_bytes())
        if deployment.get("max_channel_duration_seconds") != 2_592_000:
            raise ValueError("promotable V10 deployment must pin the 30-day channel duration")
        mode = deployment.get("committee_mode")
        network_id = deployment.get("network_id")
        if mode != DYNAMIC_JURY_MODE:
            raise ValueError(
                "promotable V10 releases require dynamic_provider_ai_v1"
            )
        dynamic = _dynamic_jury_manifest_status(deployment)
        if not dynamic["config_ok"] or not dynamic["providers_ok"]:
            raise ValueError("dynamic Provider jury policy is not usable")
        jury_policy = _jury_policy_declaration(root, deployment)
        detail = {
            "mode": DYNAMIC_JURY_MODE,
            "registry": dynamic["registry"],
            "minimum_reputation": dynamic["minimum_reputation"],
            "jury_size": dynamic["jury_size"],
            "required_votes": dynamic["threshold"],
            "eligible_distinct_operators": None,
            "live_pool_proof_required": True,
            "randomness": dynamic["randomness"],
            "decision_policy_hash": dynamic["decision_policy_hash"],
            "decision_policy_source_sha256": jury_policy["source_sha256"],
            "production_grade_randomness": False,
            "release_class": "controlled Sepolia candidate",
            "network_id": network_id,
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
    npm_metadata: Path | None = None,
    provider_tgz: Path | None,
    consumer_tgz: Path | None,
    oci_metadata: Path | None,
    deployed_code_evidence: Path | None,
    abi_artifact: Path | None,
    jury_registry_abi_artifact: Path | None = None,
    expected_source_commit: str | None = None,
    require_npm_metadata: bool = False,
) -> dict[str, object]:
    source_report = check(root)
    checks = list(source_report["checks"])
    root = root.resolve()
    _verify_promotion_policy(root, checks)

    evidence, _ = _external_json(artifact_evidence, "release-evidence", checks)
    if require_npm_metadata and npm_metadata is None:
        _add(checks, "artifact-input:npm-metadata", False, "missing required path")
    npm_candidate, _ = (
        _external_json(npm_metadata, "npm-metadata", checks)
        if npm_metadata is not None else (None, None)
    )
    oci, oci_raw = _external_json(oci_metadata, "oci-metadata", checks)
    deployed, deployed_raw = _external_json(deployed_code_evidence, "deployed-code", checks)
    provider_path = _required_file(provider_tgz, "provider-tgz", checks)
    consumer_path = _required_file(consumer_tgz, "consumer-tgz", checks)
    abi_path = _required_file(abi_artifact, "abi-artifact", checks)
    try:
        deployment = _json_bytes((root / DEPLOYMENT_PATH).read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError):
        deployment = {}
    dynamic_jury = deployment.get("committee_mode") == DYNAMIC_JURY_MODE
    jury_registry_abi_path = (
        _required_file(
            jury_registry_abi_artifact, "jury-registry-abi-artifact", checks,
        )
        if dynamic_jury else None
    )

    expected = expected_source_commit or _git_head(root)
    _add(
        checks,
        "artifact-expected-source-commit",
        isinstance(expected, str) and COMMIT_RE.fullmatch(expected),
        expected or "missing; pass --expected-source-commit outside a Git checkout",
    )
    git_source_ok, git_source_detail = _strict_git_source_status(root, expected)
    _add(
        checks,
        "artifact-git-source-boundary",
        git_source_ok,
        git_source_detail,
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
    _verify_npm_candidate_metadata(
        root,
        npm_candidate,
        provider_path,
        consumer_path,
        expected,
        source_commit if isinstance(source_commit, str) else None,
        evidence.get("packages") if evidence else None,
        image,
        checks,
    )
    _verify_package_tarball(
        root, "provider", provider_path, provider_declared, source_commit, image, checks
    )
    _verify_package_tarball(
        root, "consumer", consumer_path, consumer_declared, source_commit, image, checks
    )
    _verify_contract_artifacts(
        root,
        abi_path,
        jury_registry_abi_path,
        deployed,
        deployed_raw,
        contract_declared,
        source_commit,
        checks,
    )
    limitations = [
        "offline evidence consistency verified; registry and RPC were not contacted",
        "evidence authenticity still requires a detached signature/provenance verifier in the publishing workflow",
    ]
    if dynamic_jury:
        limitations.append(
            "future_blockhash_v1 jury randomness is a controlled Sepolia candidate mechanism, not production-grade VRF"
        )
    return {
        "schema": "mycomesh.release-artifact-gate.v1",
        "scope": "artifacts",
        "ok": all(bool(item["ok"]) for item in checks),
        "checks": checks,
        "limitations": limitations,
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
    parser.add_argument(
        "--npm-metadata",
        type=Path,
        help="exact npm-release-candidate.json generated beside the package tarballs",
    )
    parser.add_argument("--provider-tgz", type=Path, help="exact mycomesh-provider npm tarball")
    parser.add_argument("--consumer-tgz", type=Path, help="exact mycomesh-consumer npm tarball")
    parser.add_argument("--oci-metadata", type=Path, help="inspected multi-platform OCI metadata JSON")
    parser.add_argument("--deployed-code-evidence", type=Path, help="pinned-block deployed runtime JSON")
    parser.add_argument("--abi-artifact", type=Path, help="compiled V10 ABI or compiler artifact JSON")
    parser.add_argument(
        "--jury-registry-abi-artifact",
        type=Path,
        help="compiled ProviderJuryRegistryV1 ABI/compiler artifact (required for dynamic jury releases)",
    )
    parser.add_argument(
        "--expected-source-commit",
        help="full commit expected in release evidence and every OCI revision; defaults to Git HEAD",
    )
    args = parser.parse_args(argv)
    artifact_values = (
        args.artifact_evidence,
        args.npm_metadata,
        args.provider_tgz,
        args.consumer_tgz,
        args.oci_metadata,
        args.deployed_code_evidence,
        args.abi_artifact,
        args.jury_registry_abi_artifact,
        args.expected_source_commit,
    )
    if args.strict_artifacts or any(value is not None for value in artifact_values):
        report = check_artifacts(
            args.root.resolve(),
            artifact_evidence=args.artifact_evidence,
            npm_metadata=args.npm_metadata,
            provider_tgz=args.provider_tgz,
            consumer_tgz=args.consumer_tgz,
            oci_metadata=args.oci_metadata,
            deployed_code_evidence=args.deployed_code_evidence,
            abi_artifact=args.abi_artifact,
            jury_registry_abi_artifact=args.jury_registry_abi_artifact,
            expected_source_commit=args.expected_source_commit,
            require_npm_metadata=args.strict_artifacts,
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
