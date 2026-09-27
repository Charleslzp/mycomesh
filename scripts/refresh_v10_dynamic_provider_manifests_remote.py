#!/usr/bin/env python3
"""Refresh the final V10 dynamic manifests on already-promoted Providers.

The Provider promotion keeps the public manifest in a host bind mount.  Once
capacity channels are opened, this command swaps only those public JSON files,
restarts one Provider at a time, and verifies the same Bridge lease admission
used during blue/green promotion.  Every node keeps a dated rollback copy.
No private key or token is read by this script.
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
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402


NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
DEPLOYMENT = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
REMOTE_ROOT = "/opt/mycomesh-v10-dynamic-20260926"
NETWORK_SHA256 = hashlib.sha256(NETWORK.read_bytes()).hexdigest()
DEPLOYMENT_SHA256 = hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest()
NETWORK_VALUE = json.loads(NETWORK.read_text(encoding="utf-8"))
DEPLOYMENT_VALUE = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
EXPECTED_NETWORK_ID = str(NETWORK_VALUE["network_id"])
EXPECTED_SETTLEMENT = str(DEPLOYMENT_VALUE["settlement"]).lower()

PROVIDERS = {
    "provider1": "mycomesh-provider-1",
    "provider2": "mycomesh-v10-test-provider",
    "provider3": "mycomesh-v10-test-provider",
    "provider4": "mycomesh-v10-test-provider",
}


def _close(client: Any) -> None:
    client.close()
    if getattr(client, "_mesh_jump", None):
        client._mesh_jump.close()


def _run(client: Any, command: str, *, timeout: int = 60) -> str:
    rc, out, err = remote.execute(client, command, timeout=timeout)
    if rc:
        raise RuntimeError(remote.scrub(err or out).strip()[-1200:])
    return out


def _run_allow(client: Any, command: str, *, timeout: int = 60) -> tuple[int, str, str]:
    return remote.execute(client, command, timeout=timeout)


def _read(client: Any, path: str) -> bytes:
    with client.open_sftp() as sftp:
        with sftp.file(path, "rb") as handle:
            return handle.read()


def _write(client: Any, path: str, data: bytes, mode: int = 0o644) -> None:
    parent = str(Path(path).parent)
    _run(client, f"mkdir -p -- {shlex.quote(parent)}", timeout=20)
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def _probe(client: Any, container: str) -> dict[str, Any]:
    deadline = time.monotonic() + 150
    last = "lease probe did not run"
    command = (
        f"docker exec -- {shlex.quote(container)} python -m gateway.provider_bootstrap "
        "--network-config /candidate/network.json --require-bridge-lease"
    )
    while time.monotonic() < deadline:
        state_rc, state_out, state_err = _run_allow(
            client,
            f"docker inspect --format '{{{{.State.Running}}}}|{{{{.State.Status}}}}' -- {shlex.quote(container)}",
            timeout=20,
        )
        if state_rc != 0:
            last = "Provider container disappeared"
        else:
            running, status = state_out.strip().split("|", 1)
            if running != "true":
                if status in {"exited", "dead"}:
                    raise RuntimeError(f"Provider stopped during manifest refresh: {status}")
                last = f"Provider is {status}"
            else:
                rc, out, err = _run_allow(client, command, timeout=30)
                if rc == 0:
                    return {"running": True, "lease": True}
                last = remote.scrub(err or out).strip()[-500:] or "lease probe failed"
        time.sleep(5)
    raise RuntimeError(f"Provider lease probe failed: {last}")


def _refresh(name: str, *, dry_run: bool) -> dict[str, Any]:
    container = PROVIDERS[name]
    network_path = f"{REMOTE_ROOT}/config/public/network.json"
    deployment_path = f"{REMOTE_ROOT}/config/public/deployment.json"
    deployment_alias_path = f"{REMOTE_ROOT}/config/public/sepolia-myco-v10-dynamic-20260926.json"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_dir = f"{REMOTE_ROOT}/rollback/provider-manifest-refresh-{stamp}-{name}"
    client = remote.connect(name)
    try:
        running, status = _run(client, f"docker inspect --format '{{{{.State.Running}}}}|{{{{.State.Status}}}}' -- {shlex.quote(container)}", timeout=20).strip().split("|", 1)
        if running != "true":
            raise RuntimeError(f"{container} is not running ({status})")
        old_network = _read(client, network_path)
        old_deployment = _read(client, deployment_path)
        old_alias = _read(client, deployment_alias_path)
        old_hashes = {
            "network_sha256": hashlib.sha256(old_network).hexdigest(),
            "deployment_sha256": hashlib.sha256(old_deployment).hexdigest(),
            "deployment_alias_sha256": hashlib.sha256(old_alias).hexdigest(),
        }
        if old_hashes["network_sha256"] == NETWORK_SHA256 and old_hashes["deployment_sha256"] == DEPLOYMENT_SHA256 and old_hashes["deployment_alias_sha256"] == DEPLOYMENT_SHA256:
            probe = _probe(client, container)
            return {"node": name, "changed": False, "container": container, "probe": probe, **old_hashes}
        result = {
            "node": name,
            "container": container,
            "changed": True,
            "backup_dir": backup_dir,
            "old": old_hashes,
            "new": {
                "network_sha256": NETWORK_SHA256,
                "deployment_sha256": DEPLOYMENT_SHA256,
                "deployment_alias_sha256": DEPLOYMENT_SHA256,
            },
        }
        if dry_run:
            result["dry_run"] = True
            return result
        _run(client, f"mkdir -m 0700 -p -- {shlex.quote(backup_dir)}", timeout=20)
        _write(client, f"{backup_dir}/network.json", old_network)
        _write(client, f"{backup_dir}/deployment.json", old_deployment)
        _write(client, f"{backup_dir}/sepolia-myco-v10-dynamic-20260926.json", old_alias)
        _write(client, f"{network_path}.refresh-{stamp}.next", NETWORK.read_bytes())
        _write(client, f"{deployment_path}.refresh-{stamp}.next", DEPLOYMENT.read_bytes())
        _write(client, f"{deployment_alias_path}.refresh-{stamp}.next", DEPLOYMENT.read_bytes())
        _run(
            client,
            f"mv -f -- {shlex.quote(network_path + '.refresh-' + stamp + '.next')} {shlex.quote(network_path)} "
            f"&& mv -f -- {shlex.quote(deployment_path + '.refresh-' + stamp + '.next')} {shlex.quote(deployment_path)} "
            f"&& mv -f -- {shlex.quote(deployment_alias_path + '.refresh-' + stamp + '.next')} {shlex.quote(deployment_alias_path)}",
            timeout=20,
        )
        try:
            _run(client, f"docker restart --time 35 -- {shlex.quote(container)}", timeout=60)
            result["probe"] = _probe(client, container)
        except Exception:
            _write(client, f"{network_path}.rollback.next", old_network)
            _write(client, f"{deployment_path}.rollback.next", old_deployment)
            _write(client, f"{deployment_alias_path}.rollback.next", old_alias)
            _run(
                client,
                f"mv -f -- {shlex.quote(network_path + '.rollback.next')} {shlex.quote(network_path)} "
                f"&& mv -f -- {shlex.quote(deployment_path + '.rollback.next')} {shlex.quote(deployment_path)} "
                f"&& mv -f -- {shlex.quote(deployment_alias_path + '.rollback.next')} {shlex.quote(deployment_alias_path)} "
                f"&& docker restart --time 35 -- {shlex.quote(container)}",
                timeout=90,
            )
            raise
        return result
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(PROVIDERS))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    names = args.node or list(PROVIDERS)
    for name in names:
        try:
            print(json.dumps(_refresh(name, dry_run=args.dry_run), sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
