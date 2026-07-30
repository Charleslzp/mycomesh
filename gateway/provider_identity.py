from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from .provider_bootstrap import (
    ProviderBootstrapError,
    ProviderEvmIdentity,
    load_provider_evm_identity,
)


class ProviderIdentityImportError(RuntimeError):
    pass


def validate_provider_evm_identity(identity_path: str | Path) -> ProviderEvmIdentity:
    try:
        return load_provider_evm_identity(identity_path)
    except ProviderBootstrapError as exc:
        raise ProviderIdentityImportError(str(exc)) from exc


def import_provider_evm_identity(
    source_path: str | Path,
    target_path: str | Path,
) -> ProviderEvmIdentity:
    identity = validate_provider_evm_identity(source_path)
    target = Path(target_path)
    parent_existed = target.parent.exists()
    if target.parent.is_symlink():
        raise ProviderIdentityImportError(
            "Provider EVM identity target directory must not be a symbolic link"
        )
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.parent.chmod(0o700)
    except OSError as exc:
        raise ProviderIdentityImportError(
            f"Could not secure Provider EVM identity target directory: {exc}"
        ) from exc
    if not parent_existed and target.parent.is_symlink():
        raise ProviderIdentityImportError(
            "Provider EVM identity target directory must not be a symbolic link"
        )

    if target.exists() or target.is_symlink():
        existing = validate_provider_evm_identity(target)
        if existing != identity:
            raise ProviderIdentityImportError(
                "Refusing to replace the existing Provider EVM identity"
            )
        return existing

    payload = (
        json.dumps(
            {
                "schema_version": 1,
                "address": identity.address,
                "private_key": identity.private_key,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    descriptor = -1
    linked = False
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target, follow_symlinks=False)
        linked = True
        target.chmod(0o600)
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError:
        existing = validate_provider_evm_identity(target)
        if existing != identity:
            raise ProviderIdentityImportError(
                "Refusing to replace the existing Provider EVM identity"
            )
        return existing
    except OSError as exc:
        if linked:
            try:
                target.unlink()
            except OSError:
                pass
        raise ProviderIdentityImportError(
            f"Could not import Provider EVM identity: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return validate_provider_evm_identity(target)


def _public_payload(identity: ProviderEvmIdentity) -> dict[str, Any]:
    return {"ok": True, "address": identity.address}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate or restore a Provider EVM payout identity."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--identity", required=True)
    restore = subparsers.add_parser("import")
    restore.add_argument("--source", required=True)
    restore.add_argument("--target", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            identity = validate_provider_evm_identity(args.identity)
        else:
            identity = import_provider_evm_identity(args.source, args.target)
    except ProviderIdentityImportError as exc:
        print(f"provider identity: {exc}", file=sys.stderr)
        return 64
    print(json.dumps(_public_payload(identity), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
