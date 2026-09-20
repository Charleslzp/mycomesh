#!/usr/bin/env python3
"""Build an auditable, inactive V9 source candidate; never deploy or upload.

No git index is consulted. Every archive member is a regular file selected by
the explicit allowlist below, captured once and hashed from those exact bytes.
Run --self-test for isolated fixtures, or provide --output-dir to build.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Any
from urllib.parse import urlparse


ROOT_FILES = frozenset({
    "Makefile", "Dockerfile", "docker-compose.yml", "pyproject.toml",
    "requirements.txt", "requirements.lock", "foundry.toml", "package.json", "package-lock.json",
})
TREE_SUFFIXES = {
    "gateway": frozenset({".py", ".js"}),
    "scripts": frozenset({".py", ".sh"}),
    "contracts": frozenset({".sol"}),
    "tests": frozenset({".py"}),
    "test": frozenset({".sol"}),
    "packages/mycomesh-cli/src": frozenset({".mjs", ".js"}),
    "packages/mycomesh-cli/bin": frozenset({".mjs", ".js"}),
}
CLI_FILES = frozenset({"packages/mycomesh-cli/package.json", "packages/mycomesh-cli/package-lock.json"})
REQUIRED_FILES = frozenset({
    "contracts/MycoSettlementV9.sol", "gateway/chain_v9.py", "gateway/relay_adjudication_v9.py",
    "packages/mycomesh-cli/package.json",
})
EXCLUDED_DIRECTORIES = frozenset({
    "node_modules", "__pycache__", "runtime", "runtime-data", "runtime_data", "logs", "cache",
    "out", "build", "dist", "tmp", "temp", "venv", "secrets", "private", "wallets",
})
SECRET_FIELDS = frozenset({
    "privatekey", "secretkey", "signingkey", "mnemonic", "seed", "password", "passphrase",
    "clientsecret", "accesstoken", "refreshtoken", "apikey", "authorization",
})
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
METADATA_NAME = "_candidate/manifest.json"
SUMS_NAME = "_candidate/SHA256SUMS"


class CandidateError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relative_name(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or "\\" in value or "\x00" in value
            or any(part in ("", ".", "..") for part in value.split("/"))
            or path.as_posix() != value or any(ord(char) < 32 for char in value)):
        raise CandidateError("invalid relative archive path")
    return value


def open_directory(path: Path) -> int:
    """Walk each absolute source component without following any symlink."""
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def open_relative(root_fd: int, name: str, *, directory: bool = False) -> int:
    parts = relative_name(name).split("/")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = next_fd
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW
                       | (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=current)
    finally:
        os.close(current)


def read_snapshot(root_fd: int, name: str) -> tuple[bytes, int]:
    fd = open_relative(root_fd, name)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise CandidateError(f"not a bounded regular source file: {name}")
        chunks, length = [], 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, MAX_FILE_BYTES + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            if length > MAX_FILE_BYTES:
                raise CandidateError(f"source exceeds size limit: {name}")
        after = os.fstat(fd)
        attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
        if any(getattr(before, key) != getattr(after, key) for key in attributes) or length != before.st_size:
            raise CandidateError(f"source changed while being captured: {name}")
        return b"".join(chunks), 0o755 if before.st_mode & 0o111 else 0o644
    finally:
        os.close(fd)


def tree_names(root_fd: int, prefix: str, suffixes: frozenset[str], *, recursive: bool = True) -> list[str]:
    fd = open_relative(root_fd, prefix, directory=True)
    try:
        names = []
        with os.scandir(fd) as entries:
            ordered = sorted(entries, key=lambda item: item.name)
        for entry in ordered:
            if entry.name.startswith(".") or entry.name in EXCLUDED_DIRECTORIES:
                continue
            name = relative_name(prefix + "/" + entry.name)
            if entry.is_symlink():
                raise CandidateError(f"source symlink is forbidden: {name}")
            if entry.is_dir(follow_symlinks=False):
                if recursive:
                    names.extend(tree_names(root_fd, name, suffixes))
            elif Path(entry.name).suffix in suffixes:
                if not entry.is_file(follow_symlinks=False):
                    raise CandidateError(f"source is not a regular file: {name}")
                names.append(name)
        return names
    finally:
        os.close(fd)


def validate_public_deployment(name: str, data: bytes) -> None:
    if name.endswith(".crt"):
        if not data.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise CandidateError(f"deployment certificate must be public PEM: {name}")
        return
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise CandidateError(f"duplicate deployment JSON field: {name}")
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise CandidateError(f"invalid public deployment JSON: {name}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"deployment must be an object: {name}")
    if re.search(r"(?:fixture|local|hardhat|ganache|anvil|synthetic|v9)", Path(name).stem, re.I):
        raise CandidateError(f"candidate cannot include a fixture or V9 deployment manifest: {name}")

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                if normalized in SECRET_FIELDS or any(marker in normalized for marker in ("privatekey", "secretkey", "mnemonic")):
                    raise CandidateError(f"deployment contains a credential field: {name}")
                if normalized in ("chainid", "chain") and str(child) in ("31337", "1337", "0x7a69", "0x539"):
                    raise CandidateError(f"development-chain deployment is forbidden: {name}")
                if normalized in ("protocolversion", "settlementversion", "eip712version") and str(child) == "9":
                    raise CandidateError(f"inactive candidate must not include a V9 chain deployment: {name}")
                if (normalized in ("deployment", "deploymentname", "network", "networkid", "profile")
                        and isinstance(child, str) and re.search(r"(?:fixture|localhost|hardhat|ganache|anvil|synthetic|(?:^|[-_])v9(?:[-_.]|$))", child, re.I)):
                    raise CandidateError(f"fixture or V9 deployment reference is forbidden: {name}")
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, str):
            if item.startswith(("http://", "https://", "ws://", "wss://")):
                parsed = urlparse(item)
                if parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise CandidateError(f"deployment URL may contain credentials: {name}")
                host = (parsed.hostname or "").lower()
                if host in ("localhost", "::1", "0.0.0.0") or host.startswith("127.") or host.endswith(".localhost"):
                    raise CandidateError(f"localhost deployment is forbidden: {name}")
    visit(value)


def capture(source_root: Path) -> tuple[dict[str, tuple[bytes, int]], bytes]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise CandidateError("this platform cannot enforce source no-follow access")
    root_fd = open_directory(source_root)
    try:
        names = []
        for name in sorted(ROOT_FILES | CLI_FILES):
            try:
                fd = open_relative(root_fd, name)
            except FileNotFoundError:
                continue
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise CandidateError(f"root/package input is not a regular file: {name}")
            finally:
                os.close(fd)
            names.append(name)
        for prefix, suffixes in TREE_SUFFIXES.items():
            names.extend(tree_names(root_fd, prefix, suffixes))
        names.extend(tree_names(root_fd, "deployments", frozenset({".json", ".crt"}), recursive=False))
        if not REQUIRED_FILES.issubset(names):
            raise CandidateError("source is missing required V9 contract, operator, or Consumer files")
        snapshot, total = {}, 0
        for name in sorted(set(names)):
            data, mode = read_snapshot(root_fd, name)
            # Real key containers are never valid source-candidate inputs. Test
            # code deriving synthetic scalar fixtures is intentionally included.
            if re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", data):
                raise CandidateError(f"private key container is forbidden: {name}")
            if name.startswith("deployments/"):
                validate_public_deployment(name, data)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise CandidateError("candidate exceeds total source size limit")
            snapshot[name] = (data, mode)
        # Reject edits that occurred while other files were being captured.
        # The archive writer itself uses only this frozen in-memory snapshot.
        for name, expected in snapshot.items():
            if read_snapshot(root_fd, name) != expected:
                raise CandidateError(f"source changed during candidate snapshot: {name}")
    finally:
        os.close(root_fd)
    files = [{"path": name, "sha256": sha256(data), "size": len(data), "mode": f"{mode:04o}"}
             for name, (data, mode) in snapshot.items()]
    manifest = canonical({
        "schema": "mycomesh.v9.source-candidate.v1", "status": "candidate_not_activated",
        "activation_performed": False, "v9_chain_deployment_included": False,
        "network_requests_performed": False, "git_index_filtering": False,
        "authorization_ttl_migration": {
            "requires_new_contract": True,
            "activation_requires_onchain_ttl_readback": True,
            "existing_contract_receipts_must_be_drained_separately": True,
            "balance_or_stake_reservations_implemented_by_this_change": False,
        },
        "standalone_docker_build_context": False,
        "source_snapshot_sha256": sha256(canonical(files)), "source_file_count": len(files),
        "source_bytes": total, "files": files,
        "selection": {"root_files": sorted(ROOT_FILES), "cli_files": sorted(CLI_FILES),
                      "trees": {name: sorted(values) for name, values in TREE_SUFFIXES.items()},
                      "public_deployments": "top-level .json and public .crt; no V9/local-chain manifests",
                      "excluded_directories": sorted(EXCLUDED_DIRECTORIES), "hidden_paths": "excluded"},
        "notice": "Source candidate only. This archive does not deploy a V9 contract, migrate balances, activate a network, or include runtime identities. It is not a standalone Docker build context: web, deploy/codex-cli, and other non-allowlisted build inputs are excluded.",
    })
    return snapshot, manifest


def archive_bytes(snapshot: dict[str, tuple[bytes, int]], manifest: bytes) -> tuple[bytes, bytes]:
    members = {**snapshot, METADATA_NAME: (manifest, 0o644)}
    sums = "".join(f"{sha256(data)}  {name}\n" for name, (data, _) in sorted(members.items())).encode()
    members[SUMS_NAME] = (sums, 0o644)
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0, compresslevel=9) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, (data, mode) in sorted(members.items()):
                entry = tarfile.TarInfo(relative_name(name))
                entry.size, entry.mode, entry.mtime = len(data), mode, 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                entry.type = tarfile.REGTYPE
                archive.addfile(entry, io.BytesIO(data))
    result = stream.getvalue()
    with tarfile.open(fileobj=io.BytesIO(result), mode="r:gz") as archive:
        entries = archive.getmembers()
        if [entry.name for entry in entries] != sorted(members) or any(not entry.isfile() or entry.linkname for entry in entries):
            raise CandidateError("archive member verification failed")
        for entry in entries:
            if archive.extractfile(entry).read() != members[entry.name][0]:
                raise CandidateError("archive snapshot checksum verification failed")
    return result, sums


def build(source_root: Path, output_dir: Path) -> dict[str, Any]:
    snapshot, manifest = capture(source_root)
    packed, sums = archive_bytes(snapshot, manifest)
    metadata = json.loads(manifest)
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / ("mycomesh-v9-candidate-" + metadata["source_snapshot_sha256"][:20])
    destination.mkdir(mode=0o700)  # Never overwrite an earlier candidate.
    name = "mycomesh-v9-candidate.tar.gz"
    outputs = {name: packed, "manifest.json": manifest, "SHA256SUMS": sums,
               name + ".sha256": f"{sha256(packed)}  {name}\n".encode()}
    try:
        for filename, data in outputs.items():
            fd = os.open(destination / filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
    except BaseException:
        shutil.rmtree(destination)
        raise
    return {"status": metadata["status"], "directory": str(destination.absolute()),
            "archive": str((destination / name).absolute()), "archive_sha256": sha256(packed),
            "source_snapshot_sha256": metadata["source_snapshot_sha256"], "source_file_count": len(snapshot),
            "activation_performed": False, "v9_chain_deployment_included": False}


def self_test() -> dict[str, Any]:
    checks = 0
    with tempfile.TemporaryDirectory(prefix="mycomesh-v9-candidate-selftest-") as directory:
        # Resolve only this synthetic tempfile's platform-specific /var alias.
        base = Path(directory).resolve()
        root = base / "source"
        for name in [*TREE_SUFFIXES, "deployments"]:
            (root / name).mkdir(parents=True, exist_ok=True)
        for name in REQUIRED_FILES:
            (root / name).write_text("{}\n" if name.endswith(".json") else "# synthetic fixture\n")
        (root / "gateway/untracked.py").write_text("VALUE = 1\n")
        for name in (".env", "private.key", "~$private.xlsx", "gateway/.secret.py", "gateway/runtime/state.py",
                     "packages/mycomesh-cli/node_modules/dependency/index.js"):
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text("excluded synthetic fixture\n")
        snapshot, manifest = capture(root)
        assert "gateway/untracked.py" in snapshot
        assert not any(name in snapshot for name in (".env", "private.key", "~$private.xlsx", "gateway/.secret.py", "gateway/runtime/state.py"))
        checks += 1
        first, sums = archive_bytes(snapshot, manifest)
        assert first == archive_bytes(snapshot, manifest)[0]
        assert sha256(manifest).encode() in sums
        (root / "gateway/untracked.py").write_text("VALUE = 2\n")
        assert first == archive_bytes(snapshot, manifest)[0]  # Frozen bytes, not reread source.
        assert capture(root)[1] != manifest
        checks += 1
        result = build(root, base / "output")
        assert sha256(Path(result["archive"]).read_bytes()) == result["archive_sha256"]
        try:
            build(root, base / "output")
            raise AssertionError("candidate was overwritten")
        except FileExistsError:
            pass
        checks += 1
        for value in ("../escape.py", "/absolute.py", "gateway/../escape.py", "gateway//code.py", "gateway\\escape.py"):
            try:
                relative_name(value)
                raise AssertionError("invalid path accepted")
            except CandidateError:
                checks += 1
        for link, target in ((root / "gateway/link.py", root / "gateway/untracked.py"),
                             (root / "gateway/linkdir", base), (base / "source-link", root)):
            link.symlink_to(target, target_is_directory=target.is_dir())
            try:
                try:
                    capture(link if link.name == "source-link" else root)
                    raise AssertionError("source symlink accepted")
                except (CandidateError, OSError):
                    checks += 1
            finally:
                link.unlink()
        bad = root / "deployments/sepolia.json"
        for value in ({"private_key": "synthetic-not-a-key"}, {"chain_id": 31337},
                      {"rpc_url": "http://127.0.0.1:8545"}, {"protocol_version": 9},
                      {"deployment": "fixture-v9.json"},
                      {"rpc_url": "https://example.invalid/rpc?api_key=synthetic"}):
            bad.write_bytes(canonical(value))
            try:
                capture(root)
                raise AssertionError("unsafe deployment accepted")
            except CandidateError:
                checks += 1
        bad.write_text('{"chain_id":31337,"chain_id":11155111}')
        try:
            capture(root)
            raise AssertionError("duplicate deployment fields accepted")
        except CandidateError:
            checks += 1
        bad.unlink()
        os.mkfifo(root / "Makefile")
        try:
            try:
                capture(root)
                raise AssertionError("FIFO accepted as source file")
            except CandidateError:
                checks += 1
        finally:
            (root / "Makefile").unlink()
        (root / "gateway/untracked.py").write_text("CHANGED = True\n")
        assert json.loads(capture(root)[1])["status"] == "candidate_not_activated"
        checks += 1
    return {"self_test": "passed", "checks": checks, "network_requests_performed": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).absolute().parent.parent)
    parser.add_argument("--output-dir", type=Path, help="explicit local destination parent; creates a new immutable candidate directory")
    parser.add_argument("--self-test", action="store_true", help="exercise synthetic fixtures only; no repository build")
    args = parser.parse_args(argv)
    if not args.self_test and args.output_dir is None:
        parser.error("--output-dir is required for a repository candidate build")
    try:
        result = self_test() if args.self_test else build(args.source_root, args.output_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (CandidateError, OSError, ValueError, tarfile.TarError) as exc:
        print(json.dumps({"status": "rejected", "error": type(exc).__name__, "message": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
