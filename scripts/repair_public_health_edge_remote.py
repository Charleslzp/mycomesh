#!/usr/bin/env python3
"""Open only the public Relay health probe on the legacy V10 edge.

The controlled-test edge inherits an operator IP allowlist at server scope.
That is appropriate for mutating and inference endpoints, but it makes the
public readiness probe unverifiable.  This script adds an explicit
``allow all`` only to ``/relay/health`` and keeps a remote rollback copy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))
import remote  # type: ignore  # noqa: E402


NODES = {
    "relay1": {
        "config": "/opt/mycomesh-v10-fixed-budget-20260918/config/nginx.conf",
        "host": "136.0.3.126",
    },
    "relay3": {
        "config": "/opt/mycomesh-v10-fixed-budget-20260918/config/nginx.conf",
        "host": "166.88.96.60",
    },
}


def _close(client: Any) -> None:
    client.close()
    if getattr(client, "_mesh_jump", None):
        client._mesh_jump.close()


def _run(client: Any, command: str, *, timeout: int = 30) -> str:
    rc, out, err = remote.execute(client, command, timeout=timeout)
    if rc:
        raise RuntimeError(remote.scrub(err or out).strip()[-1200:])
    return out


def _read(client: Any, path: str) -> bytes:
    with client.open_sftp() as sftp:
        with sftp.file(path, "rb") as handle:
            return handle.read()


def _write(client: Any, path: str, data: bytes, mode: int = 0o600) -> None:
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def _repair(node: str, *, dry_run: bool) -> dict[str, Any]:
    spec = NODES[node]
    path = spec["config"]
    client = remote.connect(node)
    try:
        old = _read(client, path)
        marker = b"location = /relay/health {"
        if old.count(marker) != 1:
            raise RuntimeError("expected exactly one Relay health location")
        if b"location = /relay/health { allow all;" in old:
            return {
                "node": node,
                "changed": False,
                "sha256": hashlib.sha256(old).hexdigest(),
                "dry_run": dry_run,
            }
        next_value = old.replace(
            marker,
            b"location = /relay/health { allow all;",
            1,
        )
        backup_dir = (
            "/opt/mycomesh-v10-fixed-budget-20260918/rollback/"
            f"public-health-edge-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
        )
        result = {
            "node": node,
            "changed": True,
            "dry_run": dry_run,
            "backup_dir": backup_dir,
            "before_sha256": hashlib.sha256(old).hexdigest(),
            "after_sha256": hashlib.sha256(next_value).hexdigest(),
        }
        if dry_run:
            return result

        quoted_path = shlex.quote(path)
        quoted_backup = shlex.quote(f"{backup_dir}/nginx.conf")
        _run(client, f"install -d -m 0700 -- {shlex.quote(backup_dir)}")
        _write(client, f"{backup_dir}/nginx.conf", old, 0o600)
        _run(client, f"chown --reference={quoted_path} -- {quoted_backup}")
        _write(client, f"{path}.health-next", next_value, 0o600)
        _run(client, f"chown --reference={quoted_path} -- {shlex.quote(path + '.health-next')}")
        _run(client, f"mv -f -- {shlex.quote(path + '.health-next')} {quoted_path}")
        try:
            _run(
                client,
                "nginx -t -p /opt/mycomesh-v10-fixed-budget-20260918/data/ "
                "-c /opt/mycomesh-v10-fixed-budget-20260918/config/nginx.conf",
            )
            _run(
                client,
                "nginx -p /opt/mycomesh-v10-fixed-budget-20260918/data/ "
                "-c /opt/mycomesh-v10-fixed-budget-20260918/config/nginx.conf "
                "-s reload",
            )
            _run(client, "sleep 1")
            _run(
                client,
                "curl -k -fsS --max-time 10 "
                "https://127.0.0.1:10443/relay/health "
                f"-H 'Host: {spec['host']}' -o /dev/null",
            )
        except Exception:
            _write(client, f"{path}.health-rollback", old, 0o600)
            _run(client, f"chown --reference={quoted_path} -- {shlex.quote(path + '.health-rollback')}")
            _run(client, f"mv -f -- {shlex.quote(path + '.health-rollback')} {quoted_path}")
            _run(
                client,
                "nginx -p /opt/mycomesh-v10-fixed-budget-20260918/data/ "
                "-c /opt/mycomesh-v10-fixed-budget-20260918/config/nginx.conf "
                "-s reload",
            )
            raise
        return result
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(NODES))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    for node in args.node or list(NODES):
        try:
            print(json.dumps(_repair(node, dry_run=args.dry_run), sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": node, "error": remote.scrub(str(exc))}, sort_keys=True))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
