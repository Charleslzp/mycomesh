from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from .identity import IdentityError, NodeIdentity, load_identity, public_key_from_private_key


MAX_IDENTITY_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


class ProxyIdentityError(RuntimeError):
    pass


def validate_proxy_identity(identity_path: str | Path, manifest_path: str | Path) -> NodeIdentity:
    identity_source = Path(identity_path)
    _require_secure_regular_file(identity_source, label="Proxy request identity")
    if identity_source.stat().st_size > MAX_IDENTITY_BYTES:
        raise ProxyIdentityError("Proxy request identity is too large")
    try:
        identity = load_identity(identity_source)
        if public_key_from_private_key(identity.private_key).lower() != identity.public_key.lower():
            raise IdentityError("private_key does not match public_key")
    except (OSError, ValueError, TypeError, AttributeError, IdentityError) as exc:
        raise ProxyIdentityError(f"Proxy request identity is invalid: {exc}") from exc

    manifest_source = Path(manifest_path)
    _require_regular_file(manifest_source, label="Provider network manifest")
    if manifest_source.stat().st_size > MAX_MANIFEST_BYTES:
        raise ProxyIdentityError("Provider network manifest is too large")
    try:
        manifest = json.loads(manifest_source.read_text(encoding="utf-8"))
        values = (
            manifest.get("gateway_consumer_public_keys", manifest.get("consumer_public_keys"))
            if isinstance(manifest, dict)
            else None
        )
        if not isinstance(values, list):
            raise ValueError("gateway_consumer_public_keys must be a list")
        authorized_keys = {str(value).strip().lower() for value in values if str(value).strip()}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ProxyIdentityError(f"Provider network manifest is invalid: {exc}") from exc
    if identity.public_key.lower() not in authorized_keys:
        raise ProxyIdentityError(
            "Proxy request identity public_key is not authorized for Gateway compatibility"
        )
    return identity


def import_proxy_identity(
    source_path: str | Path,
    target_path: str | Path,
    manifest_path: str | Path,
) -> NodeIdentity:
    identity = validate_proxy_identity(source_path, manifest_path)
    target = Path(target_path)
    parent_existed = target.parent.exists()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.parent.is_symlink():
        raise ProxyIdentityError("Proxy identity target directory must not be a symbolic link")
    if not parent_existed:
        target.parent.chmod(0o700)

    if target.exists() or target.is_symlink():
        existing = validate_proxy_identity(target, manifest_path)
        if existing != identity:
            raise ProxyIdentityError("Refusing to replace the existing pinned Proxy request identity")
        return existing

    payload = (json.dumps(identity.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        target.chmod(0o600)
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise ProxyIdentityError(f"Could not import Proxy request identity: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return validate_proxy_identity(target, manifest_path)


def _require_regular_file(path: Path, *, label: str) -> None:
    if path.is_symlink():
        raise ProxyIdentityError(f"{label} must not be a symbolic link")
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ProxyIdentityError(f"Could not read {label}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise ProxyIdentityError(f"{label} must be a regular file")


def _require_secure_regular_file(path: Path, *, label: str) -> None:
    _require_regular_file(path, label=label)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProxyIdentityError(f"{label} permissions must be 0600 or stricter")


def _public_payload(identity: NodeIdentity) -> dict[str, Any]:
    return {"ok": True, "peer_id": identity.peer_id, "public_key": identity.public_key}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate or restore the pinned Consumer Proxy identity.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--identity", required=True)
    validate.add_argument("--manifest", required=True)
    restore = subparsers.add_parser("import")
    restore.add_argument("--source", required=True)
    restore.add_argument("--target", required=True)
    restore.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            identity = validate_proxy_identity(args.identity, args.manifest)
        else:
            identity = import_proxy_identity(args.source, args.target, args.manifest)
    except ProxyIdentityError as exc:
        print(f"proxy identity: {exc}", file=sys.stderr)
        return 64
    print(json.dumps(_public_payload(identity), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
