#!/usr/bin/env python3
"""Atomically promote a dynamic V10 Relay and its same-host Pool.

The public Nginx route is intentionally unchanged: Relay control traffic goes
to 11090 and the provider directory route goes to 12000.  This helper swaps
both backends together, keeping the old units and manifests available for an
explicit rollback if either new health check fails.
"""
from __future__ import annotations

import argparse
import copy
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
import promote_v10_dynamic_remote as relay_promotion  # type: ignore  # noqa: E402
from stage_v10_dynamic_pool_remote import (  # type: ignore  # noqa: E402
    POOL_NODE_TEMPLATE,
    POOL_RUNTIME_TEMPLATE,
    POOL_SPECS,
    _json_bytes,
    _runtime as pool_runtime,
)
from stage_v10_dynamic_remote import (  # type: ignore  # noqa: E402
    NODES,
    OLD_ROOT,
    REMOTE_RELEASE,
    REMOTE_ROOT,
    RELEASE_ID,
)


OLD_POOL_UNIT = "mycomesh-v10-test-pool.service"
PRODUCTION_POOL_UNITS = {
    "relay1": "mycomesh-v10-dynamic-pool1.service",
    "relay3": "mycomesh-v10-dynamic-pool3.service",
}
PRODUCTION_POOL_PORT = 12000
STATE_SCHEMA = "mycomesh.v10.dynamic-relay-pool-promotion.v1"


def _close(client: Any) -> None:
    client.close()
    if getattr(client, "_mesh_jump", None):
        client._mesh_jump.close()


def _remote_write(client: Any, path: str, data: bytes, mode: int = 0o600) -> None:
    parent = str(Path(path).parent)
    rc, _, err = remote.execute(client, f"mkdir -p -- {shlex.quote(parent)}", timeout=20)
    if rc:
        raise RuntimeError(f"remote mkdir failed: {remote.scrub(err)}")
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def _remote_read_json(client: Any, path: str) -> dict[str, Any]:
    with client.open_sftp() as sftp:
        with sftp.file(path, "rb") as handle:
            value = json.loads(handle.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"remote JSON is not an object: {path}")
    return value


def _remote_read_bytes(client: Any, path: str) -> bytes:
    with client.open_sftp() as sftp:
        with sftp.file(path, "rb") as handle:
            return handle.read()


def _state_path(name: str) -> str:
    return f"{REMOTE_ROOT}/rollback/{name}-relay-pool-promotion.json"


def _rollback_dir(name: str) -> str:
    return f"{REMOTE_ROOT}/rollback/{name}-relay-pool"


def _systemd_state(client: Any, unit: str) -> str:
    return relay_promotion._systemd_state(client, unit)


def _write_phase(client: Any, state: dict[str, Any], phase: str) -> None:
    state["phase"] = phase
    state["updated_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _remote_write(client, _state_path(str(state["node"])), _json_bytes(state), 0o600)


def _pool_candidate_health(client: Any, name: str) -> dict[str, Any]:
    spec = POOL_SPECS[name]
    rc, out, err = remote.execute(
        client,
        f"systemctl is-active --quiet -- {shlex.quote(spec['candidate_unit'])}",
        timeout=20,
    )
    if rc:
        raise RuntimeError(f"Pool candidate is not active: {remote.scrub(err or out)}")
    value = relay_promotion._health_request(client, int(spec["candidate_port"]), unit=spec["candidate_unit"])
    if value.get("ok") is not True:
        raise RuntimeError("Pool candidate health returned ok=false")
    if value.get("expected_network_id") != relay_promotion.EXPECTED["network_id"]:
        raise RuntimeError("Pool candidate network id does not match the new manifest")
    settlement = value.get("settlement")
    if not isinstance(settlement, dict):
        raise RuntimeError("Pool candidate settlement health is missing")
    if str(settlement.get("contract", "")).lower() != relay_promotion.EXPECTED["settlement"]:
        raise RuntimeError("Pool candidate settlement does not match the new manifest")
    if int(settlement.get("version", -1)) != relay_promotion.EXPECTED["protocol_version"]:
        raise RuntimeError("Pool candidate is not Settlement V10")
    if str(settlement.get("pricing_hash", "")).lower() != relay_promotion.EXPECTED["pricing_hash"]:
        raise RuntimeError("Pool candidate pricing hash does not match the new manifest")
    if int(value.get("authorized_provider_count", -1)) != 4:
        raise RuntimeError("Pool candidate Provider allowlist is incomplete")
    if int(value.get("authorized_reputation_signer_count", -1)) != 1:
        raise RuntimeError("Pool candidate reputation signer policy is not explicit")
    return value


def _replace_port(argv: list[str], value: int) -> None:
    positions = [idx for idx, item in enumerate(argv) if item == "--port"]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise RuntimeError("Pool candidate argv must contain exactly one --port")
    argv[positions[0] + 1] = str(value)


def _production_pool_node(name: str, candidate: dict[str, Any]) -> dict[str, Any]:
    spec = POOL_SPECS[name]
    if candidate.get("node") != name or candidate.get("role") != "pool":
        raise RuntimeError("Pool candidate node metadata is invalid")
    if candidate.get("candidate") != REMOTE_RELEASE:
        raise RuntimeError("Pool candidate release path is not the staged release")
    node = copy.deepcopy(candidate)
    argv = node.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise RuntimeError("Pool candidate argv is invalid")
    _replace_port(argv, PRODUCTION_POOL_PORT)
    node["promotion"] = {
        "schema": STATE_SCHEMA,
        "network_id": relay_promotion.EXPECTED["network_id"],
        "release": RELEASE_ID,
        "production": True,
    }
    return node


def _pool_production_runtime(name: str) -> bytes:
    candidate = POOL_NODE_TEMPLATE.format(name=name)
    production = f"{REMOTE_ROOT}/config/{name}-pool-production-node.json"
    value = pool_runtime(name).decode("utf-8")
    if candidate not in value:
        raise RuntimeError("Pool runtime template changed; refusing promotion")
    return value.replace(candidate, production).encode("utf-8")


def _pool_unit(name: str) -> bytes:
    unit = PRODUCTION_POOL_UNITS[name]
    runtime = f"{REMOTE_ROOT}/{name}-pool-production-runtime.py"
    return f"""[Unit]
Description=MycoMesh dynamic V10 {name} Pool production
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mycomesh-mesh
Group=mycomesh-mesh
WorkingDirectory={REMOTE_ROOT}/data
ExecStart=/opt/mycomesh-mesh/venv/bin/python {runtime}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={REMOTE_ROOT}/data
TimeoutStopSec=40

[Install]
WantedBy=multi-user.target
""".encode()


def _state(
    name: str,
    old_network_hash: str,
    old_deployment_hash: str,
    *,
    old_relay_initial_state: str,
    old_pool_initial_state: str,
) -> dict[str, Any]:
    relay_spec = NODES[name]
    pool_spec = POOL_SPECS[name]
    rollback_dir = _rollback_dir(name)
    return {
        "schema": STATE_SCHEMA,
        "node": name,
        "phase": "prepared",
        "release": RELEASE_ID,
        "network_id": relay_promotion.EXPECTED["network_id"],
        "settlement": relay_promotion.EXPECTED["settlement"],
        "network_sha256": relay_promotion.NETWORK_SHA256,
        "deployment_sha256": relay_promotion.DEPLOYMENT_SHA256,
        "relay_candidate_unit": relay_spec["candidate_unit"],
        "pool_candidate_unit": pool_spec["candidate_unit"],
        "relay_old_unit": relay_promotion.OLD_UNITS["relay"],
        "pool_old_unit": OLD_POOL_UNIT,
        "relay_production_unit": relay_promotion.PRODUCTION_UNITS[name],
        "pool_production_unit": PRODUCTION_POOL_UNITS[name],
        "relay_production_node": f"{REMOTE_ROOT}/config/node-production.json",
        "relay_production_runtime": f"{REMOTE_ROOT}/runtime-production.py",
        "pool_production_node": f"{REMOTE_ROOT}/config/{name}-pool-production-node.json",
        "pool_production_runtime": f"{REMOTE_ROOT}/{name}-pool-production-runtime.py",
        "pool_production_port": PRODUCTION_POOL_PORT,
        "rollback_dir": rollback_dir,
        "old_network_backup": f"{rollback_dir}/old-network.json",
        "old_deployment_backup": f"{rollback_dir}/old-deployment.json",
        "old_network_sha256": old_network_hash,
        "old_deployment_sha256": old_deployment_hash,
        "old_relay_initial_state": old_relay_initial_state,
        "old_pool_initial_state": old_pool_initial_state,
    }


def _prepare(
    client: Any,
    name: str,
    *,
    dry_run: bool,
    allow_old_pool_inactive: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    relay_spec = NODES[name]
    pool_spec = POOL_SPECS[name]
    relay_unit = relay_promotion.PRODUCTION_UNITS[name]
    pool_unit = PRODUCTION_POOL_UNITS[name]
    old_relay = relay_promotion.OLD_UNITS["relay"]
    for unit in (relay_unit, pool_unit):
        if _systemd_state(client, unit) == "active":
            raise RuntimeError(f"production unit is already active: {unit}")
    old_relay_state = _systemd_state(client, old_relay)
    old_pool_state = _systemd_state(client, OLD_POOL_UNIT)
    if old_relay_state != "active":
        raise RuntimeError(f"old Relay unit is not active: {old_relay}")
    if old_pool_state != "active" and not allow_old_pool_inactive:
        raise RuntimeError(f"old Pool unit is not active: {OLD_POOL_UNIT}")
    if old_pool_state != "active" and allow_old_pool_inactive:
        # This is deliberately opt-in.  The current old Pool has a known
        # restart incompatibility with its legacy deployment manifest; keep
        # the fact in the journal so rollback cannot claim full old-service
        # recovery when that service was already unavailable before promotion.
        old_pool_note = f"old Pool initial state is {old_pool_state}; continuing only because --allow-old-pool-inactive was supplied"
    else:
        old_pool_note = ""
    if dry_run:
        result = {
            "node": name,
            "dry_run": True,
            "network_id": relay_promotion.EXPECTED["network_id"],
            "settlement": relay_promotion.EXPECTED["settlement"],
            "relay_candidate": relay_spec["candidate_unit"],
            "pool_candidate": pool_spec["candidate_unit"],
            "old_relay_initial_state": old_relay_state,
            "old_pool_initial_state": old_pool_state,
        }
        if old_pool_note:
            result["warning"] = old_pool_note
        return (result, {}, {})

    state_path = _state_path(name)
    rollback_dir = _rollback_dir(name)
    required_absent = [
        state_path, rollback_dir,
        f"{rollback_dir}/old-network.json", f"{rollback_dir}/old-deployment.json",
        f"/etc/systemd/system/{relay_unit}", f"/etc/systemd/system/{pool_unit}",
    ]
    for path in required_absent:
        rc, _, _ = remote.execute(client, f"test ! -e {shlex.quote(path)}", timeout=15)
        if rc:
            raise RuntimeError(f"promotion journal/backup already exists: {path}; roll back or inspect it first")
    relay_candidate_path = f"{REMOTE_ROOT}/config/node.json"
    pool_candidate_path = POOL_NODE_TEMPLATE.format(name=name)
    old_network_path = f"{OLD_ROOT}/config/public/network.json"
    old_deployment_path = f"{OLD_ROOT}/config/public/deployment.json"
    for path in (relay_candidate_path, pool_candidate_path, old_network_path, old_deployment_path):
        rc, _, err = remote.execute(client, f"test -f {shlex.quote(path)}", timeout=15)
        if rc:
            raise RuntimeError(f"required remote file is missing: {path}: {remote.scrub(err)}")
    old_network = _remote_read_bytes(client, old_network_path)
    old_deployment = _remote_read_bytes(client, old_deployment_path)
    state = _state(
        name,
        hashlib.sha256(old_network).hexdigest(),
        hashlib.sha256(old_deployment).hexdigest(),
        old_relay_initial_state=old_relay_state,
        old_pool_initial_state=old_pool_state,
    )
    relay_node = _remote_read_json(client, relay_candidate_path)
    pool_node = _remote_read_json(client, pool_candidate_path)
    relay_production = relay_promotion._production_node(name, relay_spec, relay_node)
    pool_production = _production_pool_node(name, pool_node)
    rc, _, err = remote.execute(client, f"mkdir -m 0700 -p -- {shlex.quote(rollback_dir)}", timeout=20)
    if rc:
        raise RuntimeError(f"rollback directory creation failed: {remote.scrub(err)}")
    _remote_write(client, state_path, _json_bytes(state), 0o600)
    try:
        rc, _, err = remote.execute(
            client,
            f"install -o root -g root -m 0644 -- {shlex.quote(old_network_path)} {shlex.quote(rollback_dir + '/old-network.json')} && "
            f"install -o root -g root -m 0644 -- {shlex.quote(old_deployment_path)} {shlex.quote(rollback_dir + '/old-deployment.json')} && "
            f"install -o mycomesh-mesh -g mycomesh-mesh -m 0600 -- {shlex.quote(relay_candidate_path)} {shlex.quote(rollback_dir + '/relay-candidate-node.json')} && "
            f"install -o mycomesh-mesh -g mycomesh-mesh -m 0600 -- {shlex.quote(pool_candidate_path)} {shlex.quote(rollback_dir + '/pool-candidate-node.json')}",
            timeout=30,
        )
        if rc:
            raise RuntimeError(f"promotion backup failed: {remote.scrub(err)}")
        _remote_write(client, f"{REMOTE_ROOT}/config/node-production.json", _json_bytes(relay_production), 0o600)
        _remote_write(client, f"{REMOTE_ROOT}/runtime-production.py", relay_promotion._production_runtime(), 0o700)
        _remote_write(client, f"/etc/systemd/system/{relay_unit}", relay_promotion._production_unit(name), 0o644)
        _remote_write(client, f"{REMOTE_ROOT}/config/{name}-pool-production-node.json", _json_bytes(pool_production), 0o600)
        _remote_write(client, f"{REMOTE_ROOT}/{name}-pool-production-runtime.py", _pool_production_runtime(name), 0o700)
        _remote_write(client, f"/etc/systemd/system/{pool_unit}", _pool_unit(name), 0o644)
        rc, _, err = remote.execute(
            client,
            f"chown mycomesh-mesh:mycomesh-mesh -- {shlex.quote(REMOTE_ROOT + '/config/node-production.json')} {shlex.quote(REMOTE_ROOT + '/runtime-production.py')} {shlex.quote(REMOTE_ROOT + '/config/' + name + '-pool-production-node.json')} {shlex.quote(REMOTE_ROOT + '/' + name + '-pool-production-runtime.py')} && "
            f"chmod 0600 -- {shlex.quote(REMOTE_ROOT + '/config/node-production.json')} {shlex.quote(REMOTE_ROOT + '/config/' + name + '-pool-production-node.json')} && chmod 0700 -- {shlex.quote(REMOTE_ROOT + '/runtime-production.py')} {shlex.quote(REMOTE_ROOT + '/' + name + '-pool-production-runtime.py')} && systemctl daemon-reload",
            timeout=30,
        )
        if rc:
            raise RuntimeError(f"production unit preparation failed: {remote.scrub(err)}")
    except Exception:
        remote.execute(client, f"rm -f -- {shlex.quote(state_path)} {shlex.quote(REMOTE_ROOT + '/config/node-production.json')} {shlex.quote(REMOTE_ROOT + '/runtime-production.py')} {shlex.quote(REMOTE_ROOT + '/config/' + name + '-pool-production-node.json')} {shlex.quote(REMOTE_ROOT + '/' + name + '-pool-production-runtime.py')} {shlex.quote('/etc/systemd/system/' + relay_unit)} {shlex.quote('/etc/systemd/system/' + pool_unit)} && rm -rf -- {shlex.quote(rollback_dir)} && systemctl daemon-reload", timeout=30)
        raise
    return state, relay_production, pool_production


def _restore_old(client: Any, state: dict[str, Any]) -> None:
    relay_unit = str(state["relay_production_unit"])
    pool_unit = str(state["pool_production_unit"])
    old_relay = str(state["relay_old_unit"])
    old_pool = str(state["pool_old_unit"])
    for unit in (relay_unit, pool_unit):
        if _systemd_state(client, unit) == "active":
            rc, _, err = remote.execute(client, f"systemctl stop -- {shlex.quote(unit)}", timeout=60)
            if rc:
                raise RuntimeError(f"failed to stop new unit {unit}: {remote.scrub(err)}")
    current_network = relay_promotion._remote_sha256(client, f"{OLD_ROOT}/config/public/network.json")
    current_deployment = relay_promotion._remote_sha256(client, f"{OLD_ROOT}/config/public/deployment.json")
    if current_network != str(state["network_sha256"]) or current_deployment != str(state["deployment_sha256"]):
        raise RuntimeError("refusing rollback over manifests that changed outside this promotion")
    relay_promotion._atomic_manifest_switch(client, str(state["old_network_backup"]), f"{OLD_ROOT}/config/public/network.json")
    relay_promotion._atomic_manifest_switch(client, str(state["old_deployment_backup"]), f"{OLD_ROOT}/config/public/deployment.json")
    for unit in (relay_unit, pool_unit):
        remote.execute(client, f"systemctl disable -- {shlex.quote(unit)}", timeout=30)
    old_pool_was_active = str(state.get("old_pool_initial_state", "active")) == "active"
    for unit in (old_relay, old_pool):
        rc, _, err = remote.execute(client, f"systemctl enable -- {shlex.quote(unit)}", timeout=30)
        if rc:
            raise RuntimeError(f"failed to enable old unit {unit}: {remote.scrub(err)}")
        if _systemd_state(client, unit) != "active":
            rc, _, err = remote.execute(client, f"systemctl start -- {shlex.quote(unit)}", timeout=60)
            if rc:
                if unit == old_pool and not old_pool_was_active:
                    continue
                raise RuntimeError(f"failed to restart old unit {unit}: {remote.scrub(err)}")
        if _systemd_state(client, unit) != "active":
            if unit == old_pool and not old_pool_was_active:
                continue
            raise RuntimeError(f"old unit did not return to active state: {unit}")


def _promote(name: str, *, dry_run: bool, allow_old_pool_inactive: bool) -> dict[str, Any]:
    client = remote.connect(name)
    state: dict[str, Any] | None = None
    try:
        relay_spec = NODES[name]
        relay_health = relay_promotion._candidate_health(name, relay_spec)
        pool_health = _pool_candidate_health(client, name)
        prepared, _, _ = _prepare(
            client,
            name,
            dry_run=dry_run,
            allow_old_pool_inactive=allow_old_pool_inactive,
        )
        if dry_run:
            prepared["relay_health"] = {"ok": relay_health.get("ok"), "network_id": relay_promotion.EXPECTED["network_id"]}
            prepared["pool_health"] = {"ok": pool_health.get("ok"), "network_id": relay_promotion.EXPECTED["network_id"]}
            return prepared
        state = prepared
        relay_candidate = relay_spec["candidate_unit"]
        pool_candidate = POOL_SPECS[name]["candidate_unit"]
        old_relay = relay_promotion.OLD_UNITS["relay"]
        old_pool = OLD_POOL_UNIT
        new_relay = relay_promotion.PRODUCTION_UNITS[name]
        new_pool = PRODUCTION_POOL_UNITS[name]
        for unit in (relay_candidate, pool_candidate):
            rc, _, err = remote.execute(client, f"systemctl stop -- {shlex.quote(unit)}", timeout=60)
            if rc:
                raise RuntimeError(f"failed to stop candidate {unit}: {remote.scrub(err)}")
        _write_phase(client, state, "candidates_stopped")
        for unit in (relay_candidate, pool_candidate):
            if _systemd_state(client, unit) == "active":
                raise RuntimeError(f"candidate remained active: {unit}")
        for unit in (old_relay, old_pool):
            rc, _, err = remote.execute(client, f"systemctl stop -- {shlex.quote(unit)}", timeout=60)
            if rc:
                raise RuntimeError(f"failed to stop old {unit}: {remote.scrub(err)}")
        _write_phase(client, state, "old_stopped")
        for unit in (old_relay, old_pool):
            if _systemd_state(client, unit) == "active":
                raise RuntimeError(f"old unit remained active: {unit}")
        relay_promotion._atomic_manifest_switch(client, f"{REMOTE_ROOT}/config/public/network.json", f"{OLD_ROOT}/config/public/network.json")
        relay_promotion._atomic_manifest_switch(client, f"{REMOTE_ROOT}/config/public/deployment.json", f"{OLD_ROOT}/config/public/deployment.json")
        _write_phase(client, state, "manifests_switched")
        for unit in (new_pool, new_relay):
            rc, _, err = remote.execute(client, f"systemctl start -- {shlex.quote(unit)}", timeout=60)
            if rc:
                raise RuntimeError(f"failed to start new unit {unit}: {remote.scrub(err)}")
        _write_phase(client, state, "new_started")
        production_pool = relay_promotion._health_request(client, PRODUCTION_POOL_PORT, unit=new_pool)
        if production_pool.get("ok") is not True or production_pool.get("expected_network_id") != relay_promotion.EXPECTED["network_id"]:
            raise RuntimeError("production Pool did not report the new network")
        production_relay = relay_promotion._health_request(client, int(relay_promotion.PRODUCTION_PORTS[name]["control_port"]), unit=new_relay)
        relay_promotion._assert_dynamic_health(name, relay_spec, production_relay)
        for unit in (new_pool, new_relay):
            rc, _, err = remote.execute(client, f"systemctl enable -- {shlex.quote(unit)}", timeout=30)
            if rc:
                raise RuntimeError(f"failed to enable new unit {unit}: {remote.scrub(err)}")
        for unit in (old_relay, old_pool):
            rc, _, err = remote.execute(client, f"systemctl disable -- {shlex.quote(unit)}", timeout=30)
            if rc and "not found" not in (err or "").lower():
                raise RuntimeError(f"failed to disable old unit {unit}: {remote.scrub(err)}")
        _write_phase(client, state, "active")
        return {"node": name, "phase": "active", "network_id": relay_promotion.EXPECTED["network_id"], "settlement": relay_promotion.EXPECTED["settlement"], "relay_unit": new_relay, "pool_unit": new_pool, "relay_health": {"ok": production_relay.get("ok")}, "pool_health": {"ok": production_pool.get("ok"), "expected_network_id": production_pool.get("expected_network_id")}}
    except Exception:
        if state is not None and not dry_run:
            try:
                _restore_old(client, state)
                _write_phase(client, state, "rolled_back")
            except Exception as rollback_error:
                raise RuntimeError(f"promotion failed and rollback failed: {remote.scrub(str(rollback_error))}")
        raise
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(POOL_SPECS))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--allow-old-pool-inactive",
        action="store_true",
        help="Allow promotion only when the old same-host Pool was already unavailable; record that degraded rollback state in the journal.",
    )
    args = parser.parse_args()
    names = args.node or ["relay1", "relay3"]
    results = []
    for name in names:
        try:
            result = _promote(
                name,
                dry_run=args.dry_run,
                allow_old_pool_inactive=args.allow_old_pool_inactive,
            )
            results.append(result)
            print(json.dumps(result, sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
    return 0 if len(results) == len(names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
