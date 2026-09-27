#!/usr/bin/env python3
"""Atomically refresh the live dynamic-V10 manifests on Relay/Bridge nodes.

The blue/green promotion already moved these services to the new release, but
the first promotion was made from a manifest with an incorrect Bridge URL
set.  This command updates only the two public JSON manifests, keeps a dated
rollback copy on each host, restarts one service at a time, and restores the
previous files if the post-restart health check fails.

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

from stage_v10_dynamic_remote import NODES, REMOTE_ROOT  # type: ignore  # noqa: E402

NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
DEPLOYMENT = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
RELEASE = "v10-dynamic-provider-ai-20260926-f311cba9"
NETWORK_SHA256 = hashlib.sha256(NETWORK.read_bytes()).hexdigest()
DEPLOYMENT_SHA256 = hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest()
NETWORK_VALUE = json.loads(NETWORK.read_text(encoding="utf-8"))
DEPLOYMENT_VALUE = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
EXPECTED_NETWORK_ID = str(NETWORK_VALUE["network_id"])
EXPECTED_SETTLEMENT = str(DEPLOYMENT_VALUE["settlement"]).lower()
EXPECTED_PRICING_HASH = str(NETWORK_VALUE["pricing_hash"]).lower()

PRODUCTION = {
    "relay1": ("mycomesh-v10-dynamic-relay1.service", 11090),
    "relay3": ("mycomesh-v10-dynamic-relay3.service", 11090),
    "bridge1": ("mycomesh-v10-dynamic-bridge1.service", 11080),
    "bridge2": ("mycomesh-v10-dynamic-bridge2.service", 11080),
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


def _health(client: Any, name: str, port: int) -> dict[str, Any]:
    deadline = time.monotonic() + 90
    last = "health probe did not run"
    while time.monotonic() < deadline:
        rc, out, err = remote.execute(
            client,
            f"curl -fsS --max-time 20 http://127.0.0.1:{port}/health",
            timeout=30,
        )
        if rc == 0:
            try:
                value = json.loads(out)
                if isinstance(value, dict) and value.get("ok") is True:
                    if name.startswith("relay"):
                        v10 = value.get("v10") or {}
                        # A Relay restart can temporarily move all Provider
                        # sessions to the fallback Relay.  Provider count and
                        # inference readiness are therefore convergence
                        # signals, not manifest-switch safety gates.  The
                        # restarted process must still be V10/Settlement
                        # bound and its chain-anchored intake must be ready.
                        intake = value.get("provider_ai_jury_intake") or {}
                        if value.get("settlement_ready") is True and v10.get("enabled") is True and intake.get("ready") is True and intake.get("settlement_contract", "").lower() == EXPECTED_SETTLEMENT and intake.get("jury_registry", "").lower() == str(NETWORK_VALUE["jury_registry"]).lower():
                            return value
                    else:
                        settlement = value.get("settlement") or {}
                        if value.get("expected_network_id") == EXPECTED_NETWORK_ID and settlement.get("contract", "").lower() == EXPECTED_SETTLEMENT and int(settlement.get("pricing_version", -1)) == int(NETWORK_VALUE["pricing_version"]) and settlement.get("pricing_hash", "").lower() == EXPECTED_PRICING_HASH:
                            return value
                    last = "health reported old or incomplete runtime"
                else:
                    last = "health returned ok=false"
            except (ValueError, TypeError, AttributeError) as exc:
                last = f"health parse failed: {exc}"
        else:
            last = remote.scrub(err or out).strip()[-500:] or last
        time.sleep(3)
    raise RuntimeError(f"{name} post-refresh health failed: {last}")


def _refresh(name: str, *, dry_run: bool) -> dict[str, Any]:
    unit, port = PRODUCTION[name]
    network_path = f"{REMOTE_ROOT}/config/public/network.json"
    deployment_path = f"{REMOTE_ROOT}/config/public/deployment.json"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_dir = f"{REMOTE_ROOT}/rollback/manifest-refresh-{stamp}-{name}"
    client = remote.connect(name)
    try:
        state = _run(client, f"systemctl is-active -- {shlex.quote(unit)}", timeout=20).strip()
        if state != "active":
            raise RuntimeError(f"{unit} is {state}, refusing manifest refresh")
        old_network = _read(client, network_path)
        old_deployment = _read(client, deployment_path)
        old_hashes = {
            "network_sha256": hashlib.sha256(old_network).hexdigest(),
            "deployment_sha256": hashlib.sha256(old_deployment).hexdigest(),
        }
        if old_hashes["network_sha256"] == NETWORK_SHA256 and old_hashes["deployment_sha256"] == DEPLOYMENT_SHA256:
            value = _health(client, name, port)
            return {"node": name, "changed": False, "health": {"ok": value.get("ok"), "providers": value.get("providers"), "live_peers": value.get("live_peers")}, **old_hashes}
        result = {"node": name, "changed": True, "backup_dir": backup_dir, "old": old_hashes, "new": {"network_sha256": NETWORK_SHA256, "deployment_sha256": DEPLOYMENT_SHA256}, "release": RELEASE}
        if dry_run:
            result["dry_run"] = True
            return result
        _run(client, f"mkdir -m 0700 -p -- {shlex.quote(backup_dir)}", timeout=20)
        _write(client, f"{backup_dir}/network.json", old_network)
        _write(client, f"{backup_dir}/deployment.json", old_deployment)
        next_network = f"{network_path}.refresh-{stamp}.next"
        next_deployment = f"{deployment_path}.refresh-{stamp}.next"
        _write(client, next_network, NETWORK.read_bytes())
        _write(client, next_deployment, DEPLOYMENT.read_bytes())
        _run(client, f"mv -f -- {shlex.quote(next_network)} {shlex.quote(network_path)} && mv -f -- {shlex.quote(next_deployment)} {shlex.quote(deployment_path)}", timeout=20)
        try:
            _run(client, f"systemctl restart -- {shlex.quote(unit)}", timeout=60)
            value = _health(client, name, port)
        except Exception:
            # Restore only the files this invocation replaced, then restart the
            # same unit so the node is left in its known-good prior state.
            _write(client, f"{network_path}.rollback.next", old_network)
            _write(client, f"{deployment_path}.rollback.next", old_deployment)
            _run(client, f"mv -f -- {shlex.quote(network_path + '.rollback.next')} {shlex.quote(network_path)} && mv -f -- {shlex.quote(deployment_path + '.rollback.next')} {shlex.quote(deployment_path)} && systemctl restart -- {shlex.quote(unit)}", timeout=90)
            raise
        result["health"] = {"ok": value.get("ok"), "providers": value.get("providers"), "live_peers": value.get("live_peers")}
        return result
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(PRODUCTION))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    names = args.node or ["relay1", "relay3", "bridge1", "bridge2"]
    results = []
    for name in names:
        try:
            result = _refresh(name, dry_run=args.dry_run)
            results.append(result)
            print(json.dumps(result, sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
            return 1
    return 0 if len(results) == len(names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
