#!/usr/bin/env python3
"""Promote a healthy dynamic-V10 candidate to the edge-backed service.

This is the second half of ``stage_v10_dynamic_remote.py``.  It is deliberately
conservative:

* the candidate must already be active and report the new settlement/runtime;
* the old unit and root are retained, and the old public manifests are backed
  up before the edge aliases are changed;
* production uses a separate node file, runtime wrapper, and systemd unit, so
  the stopped candidate can still be inspected or restarted independently;
* a failed switch is rolled back before the command returns an error.

No private key is printed or stored in the promotion journal.  The journal is
only a recovery record containing paths, hashes, unit names, and phases.
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
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402
from stage_v10_dynamic_remote import (  # type: ignore  # noqa: E402
    DEPLOYMENT,
    NETWORK,
    NODES,
    OLD_ROOT,
    REMOTE_RELEASE,
    REMOTE_ROOT,
    RELEASE_ID,
    RUNTIME_TEMPLATE,
)


# These are the ports already used by the V10 edge configuration on the
# remote machines.  Both Relay edge instances proxy 10443 to 11090 and expose
# the provider listener at 11991; both Bridge edge instances proxy to 11080.
# Changing a port here would require an independently validated Nginx change.
PRODUCTION_PORTS: dict[str, dict[str, int]] = {
    "relay1": {"control_port": 11090, "provider_port": 11991},
    "relay3": {"control_port": 11090, "provider_port": 11991},
    "bridge1": {"port": 11080},
    "bridge2": {"port": 11080},
}

OLD_UNITS = {
    "relay": "mycomesh-v10-test-relay.service",
    "bridge": "mycomesh-v10-test-bridge.service",
}

PRODUCTION_UNITS = {
    "relay1": "mycomesh-v10-dynamic-relay1.service",
    "relay3": "mycomesh-v10-dynamic-relay3.service",
    "bridge1": "mycomesh-v10-dynamic-bridge1.service",
    "bridge2": "mycomesh-v10-dynamic-bridge2.service",
}

STATE_SCHEMA = "mycomesh.v10.dynamic-promotion.v1"


def _manifest_values() -> dict[str, Any]:
    network = json.loads(NETWORK.read_text(encoding="utf-8"))
    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    if network.get("network_id") != deployment.get("network_id"):
        raise RuntimeError("network/deployment network_id mismatch")
    if network.get("settlement") != deployment.get("settlement"):
        raise RuntimeError("network/deployment settlement mismatch")
    return {
        "network_id": str(network["network_id"]),
        "settlement": str(deployment["settlement"]).lower(),
        "registry": str(network.get("jury_registry") or deployment.get("jury_registry") or "").lower(),
        "pricing_hash": str(network["pricing_hash"]).lower(),
        "pricing_version": int(network["pricing_version"]),
        "protocol_version": int(network["protocol_version"]),
        "chain_id": int(network["chain_id"]),
        "confirmations": int(network.get("confirmations", deployment.get("confirmations", 6))),
        "payment_address": str(network["relay"]["payment_address"]).lower(),
        "attestation_address": str(network["relay"]["attestation_address"]).lower(),
    }


EXPECTED = _manifest_values()
NETWORK_SHA256 = hashlib.sha256(NETWORK.read_bytes()).hexdigest()
DEPLOYMENT_SHA256 = hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _close(client: Any) -> None:
    if client is None:
        return
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


def _remote_sha256(client: Any, path: str) -> str:
    rc, out, err = remote.execute(client, f"sha256sum -- {shlex.quote(path)}", timeout=20)
    if rc or not out.split():
        raise RuntimeError(f"unable to hash remote file {path}: {remote.scrub(err or out)}")
    return out.split()[0]


def _state_path(name: str) -> str:
    return f"{REMOTE_ROOT}/rollback/{name}-promotion.json"


def _rollback_dir(name: str) -> str:
    return f"{REMOTE_ROOT}/rollback/{name}"


def _candidate_port(spec: dict[str, Any]) -> int:
    return int(spec["control_port"] if spec["role"] == "relay" else spec["port"])


def _production_port(name: str, spec: dict[str, Any]) -> int:
    values = PRODUCTION_PORTS[name]
    return int(values["control_port"] if spec["role"] == "relay" else values["port"])


def _health_request(client: Any, port: int, *, unit: str, timeout: float = 75.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error = "health probe did not run"
    while time.monotonic() < deadline:
        rc, out, err = remote.execute(
            client,
            f"curl -fsS --max-time 20 http://127.0.0.1:{int(port)}/health",
            timeout=30,
        )
        if rc == 0:
            try:
                value = json.loads(out)
                if isinstance(value, dict) and value.get("ok") is True:
                    return value
                last_error = "health returned ok=false"
            except json.JSONDecodeError as exc:
                last_error = f"health was not JSON: {exc}"
        else:
            last_error = remote.scrub(err or out or "health request failed")[-800:]
        time.sleep(3)
    logs = remote.execute(client, f"journalctl -u {shlex.quote(unit)} -n 40 --no-pager", timeout=20)
    raise RuntimeError(f"{unit} health failed: {last_error}\n{remote.scrub(logs[1])[-2000:]}")


def _assert_dynamic_health(name: str, spec: dict[str, Any], value: dict[str, Any]) -> None:
    """Reject a healthy-but-old candidate before any destructive operation."""
    if value.get("ok") is not True:
        raise RuntimeError("health returned ok=false")
    if spec["role"] == "relay":
        if value.get("settlement_ready") is not True:
            raise RuntimeError("Relay settlement_ready is false")
        if str(value.get("relay_payment_address", "")).lower() != EXPECTED["payment_address"]:
            raise RuntimeError("Relay payment identity does not match the new manifest")
        if str(value.get("relay_attestation_address", "")).lower() != EXPECTED["attestation_address"]:
            raise RuntimeError("Relay attestation identity does not match the new manifest")
        v10 = value.get("v10")
        if not isinstance(v10, dict) or v10.get("enabled") is not True or int(v10.get("protocol_version", -1)) != EXPECTED["protocol_version"]:
            raise RuntimeError("Relay is not reporting dynamic V10")
        intake = value.get("provider_ai_jury_intake")
        if not isinstance(intake, dict):
            raise RuntimeError("Relay jury intake health is missing")
        if str(intake.get("jury_registry", "")).lower() != EXPECTED["registry"]:
            raise RuntimeError("Relay jury registry does not match the new manifest")
        if str(intake.get("settlement_contract", "")).lower() != EXPECTED["settlement"]:
            raise RuntimeError("Relay jury settlement does not match the new manifest")
        if intake.get("chain_verified") is not True or intake.get("ready") is not True:
            raise RuntimeError("Relay jury intake is not chain-ready")
        if int(intake.get("confirmations", -1)) != EXPECTED["confirmations"]:
            raise RuntimeError("Relay jury confirmation policy does not match the manifest")
    else:
        if value.get("expected_network_id") != EXPECTED["network_id"]:
            raise RuntimeError("Bridge network id does not match the new manifest")
        settlement = value.get("settlement")
        if not isinstance(settlement, dict):
            raise RuntimeError("Bridge settlement health is missing")
        if str(settlement.get("contract", "")).lower() != EXPECTED["settlement"]:
            raise RuntimeError("Bridge settlement does not match the new manifest")
        if int(settlement.get("version", -1)) != EXPECTED["protocol_version"]:
            raise RuntimeError("Bridge settlement version is not V10")
        if str(settlement.get("pricing_hash", "")).lower() != EXPECTED["pricing_hash"]:
            raise RuntimeError("Bridge pricing hash does not match the new manifest")
        if int(settlement.get("pricing_version", -1)) != EXPECTED["pricing_version"]:
            raise RuntimeError("Bridge pricing version does not match the new manifest")


def _candidate_health(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    client = remote.connect(name)
    try:
        rc, out, err = remote.execute(
            client,
            f"systemctl is-active --quiet -- {shlex.quote(spec['candidate_unit'])}",
            timeout=20,
        )
        if rc:
            raise RuntimeError(f"candidate unit is not active: {remote.scrub(err or out)}")
        value = _health_request(client, _candidate_port(spec), unit=spec["candidate_unit"])
        _assert_dynamic_health(name, spec, value)
        return value
    finally:
        _close(client)


def _replace_arg(argv: list[str], flag: str, value: int) -> None:
    positions = [index for index, item in enumerate(argv) if item == flag]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise RuntimeError(f"candidate argv must contain exactly one {flag}")
    argv[positions[0] + 1] = str(value)


def _production_node(name: str, spec: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    if candidate.get("node") != name or candidate.get("role") != spec["role"]:
        raise RuntimeError("candidate node metadata does not match the requested node")
    if candidate.get("candidate") != REMOTE_RELEASE:
        raise RuntimeError("candidate release path is not the staged release")
    node = copy.deepcopy(candidate)
    argv = node.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise RuntimeError("candidate argv is invalid")
    if spec["role"] == "relay":
        _replace_arg(argv, "--control-port", PRODUCTION_PORTS[name]["control_port"])
        _replace_arg(argv, "--provider-port", PRODUCTION_PORTS[name]["provider_port"])
    else:
        _replace_arg(argv, "--port", PRODUCTION_PORTS[name]["port"])
    node["promotion"] = {
        "schema": STATE_SCHEMA,
        "network_id": EXPECTED["network_id"],
        "release": RELEASE_ID,
        "production": True,
    }
    return node


def _production_runtime() -> bytes:
    replacement = 'ROOT / "config/node-production.json"'
    expected = 'ROOT / "config/node.json"'
    if RUNTIME_TEMPLATE.count(expected) != 1:
        raise RuntimeError("stage runtime template changed; refusing promotion")
    # Expand the staged template before replacing the node file path.  The
    # candidate wrapper is parameterized with ``{root!r}``; leaving that token
    # in the production wrapper makes Python fail before the service binds.
    template = RUNTIME_TEMPLATE.format(root=REMOTE_ROOT)
    return template.replace(expected, replacement).encode("utf-8")


def _production_unit(name: str) -> bytes:
    unit = PRODUCTION_UNITS[name]
    return f"""[Unit]
Description=MycoMesh dynamic V10 {name} production
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mycomesh-mesh
Group=mycomesh-mesh
WorkingDirectory={REMOTE_ROOT}/data
ExecStart=/opt/mycomesh-mesh/venv/bin/python {REMOTE_ROOT}/runtime-production.py
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
""".encode("utf-8")


def _state(name: str, spec: dict[str, Any], *, phase: str, old_network_hash: str | None = None, old_deployment_hash: str | None = None) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "node": name,
        "role": spec["role"],
        "phase": phase,
        "release": RELEASE_ID,
        "network_id": EXPECTED["network_id"],
        "settlement": EXPECTED["settlement"],
        "registry": EXPECTED["registry"],
        "network_sha256": NETWORK_SHA256,
        "deployment_sha256": DEPLOYMENT_SHA256,
        "candidate_unit": spec["candidate_unit"],
        "old_unit": OLD_UNITS[spec["role"]],
        "production_unit": PRODUCTION_UNITS[name],
        "candidate_port": _candidate_port(spec),
        "production_ports": PRODUCTION_PORTS[name],
        "old_root": OLD_ROOT,
        "new_root": REMOTE_ROOT,
        "old_network_backup": f"{_rollback_dir(name)}/old-network.json",
        "old_deployment_backup": f"{_rollback_dir(name)}/old-deployment.json",
        "candidate_node_backup": f"{_rollback_dir(name)}/candidate-node.json",
        "production_node": f"{REMOTE_ROOT}/config/node-production.json",
        "production_runtime": f"{REMOTE_ROOT}/runtime-production.py",
        "production_unit_path": f"/etc/systemd/system/{PRODUCTION_UNITS[name]}",
        "old_network_sha256": old_network_hash,
        "old_deployment_sha256": old_deployment_hash,
    }


def _read_state(client: Any, name: str) -> dict[str, Any]:
    value = _remote_read_json(client, _state_path(name))
    if value.get("schema") != STATE_SCHEMA or value.get("node") != name:
        raise RuntimeError("promotion journal schema or node mismatch")
    return value


def _systemd_state(client: Any, unit: str) -> str:
    rc, out, err = remote.execute(
        client,
        f"systemctl is-active -- {shlex.quote(unit)}",
        timeout=20,
    )
    if rc and out.strip() not in {"inactive", "failed", "activating", "deactivating", "unknown"}:
        raise RuntimeError(f"unable to inspect {unit}: {remote.scrub(err or out)}")
    return out.strip() or "unknown"


def _atomic_manifest_switch(client: Any, source: str, target: str) -> None:
    pending = f"{target}.v10-dynamic.next"
    command = (
        f"install -o root -g root -m 0644 -- {shlex.quote(source)} {shlex.quote(pending)} && "
        f"mv -f -- {shlex.quote(pending)} {shlex.quote(target)}"
    )
    rc, _, err = remote.execute(client, command, timeout=20)
    if rc:
        raise RuntimeError(f"manifest switch failed: {remote.scrub(err)}")


def _write_phase(client: Any, state: dict[str, Any], phase: str) -> None:
    state["phase"] = phase
    state["updated_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _remote_write(client, _state_path(str(state["node"])), _json_bytes(state), 0o600)


def _prepare(client: Any, name: str, spec: dict[str, Any], production_node: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    old_unit = OLD_UNITS[spec["role"]]
    new_unit = PRODUCTION_UNITS[name]
    state_path = _state_path(name)
    rollback_dir = _rollback_dir(name)
    candidate_path = f"{REMOTE_ROOT}/config/node.json"
    network_old = f"{OLD_ROOT}/config/public/network.json"
    deployment_old = f"{OLD_ROOT}/config/public/deployment.json"
    if dry_run:
        if _systemd_state(client, new_unit) == "active":
            raise RuntimeError(f"production unit is already active: {new_unit}")
        if _systemd_state(client, old_unit) != "active":
            raise RuntimeError(f"old unit is not active: {old_unit}")
        return {
            "node": name,
            "dry_run": True,
            "candidate_unit": spec["candidate_unit"],
            "old_unit": old_unit,
            "production_unit": new_unit,
            "candidate_port": _candidate_port(spec),
            "production_ports": PRODUCTION_PORTS[name],
            "network_id": EXPECTED["network_id"],
            "settlement": EXPECTED["settlement"],
        }

    for path in (state_path, rollback_dir, f"{rollback_dir}/old-network.json", f"{rollback_dir}/old-deployment.json", f"/etc/systemd/system/{new_unit}"):
        rc, _, _ = remote.execute(client, f"test ! -e {shlex.quote(path)}", timeout=15)
        if rc == 0:
            continue
        raise RuntimeError(f"promotion journal/backup already exists: {path}; use --rollback first")
    for path in (candidate_path, network_old, deployment_old):
        rc, _, err = remote.execute(client, f"test -f {shlex.quote(path)}", timeout=15)
        if rc:
            raise RuntimeError(f"required remote file is missing: {path}: {remote.scrub(err)}")
    if _systemd_state(client, new_unit) == "active":
        raise RuntimeError(f"production unit is already active: {new_unit}")
    if _systemd_state(client, old_unit) != "active":
        raise RuntimeError(f"old unit is not active: {old_unit}")

    old_network = _remote_read_bytes(client, network_old)
    old_deployment = _remote_read_bytes(client, deployment_old)
    state = _state(
        name,
        spec,
        phase="prepared",
        old_network_hash=hashlib.sha256(old_network).hexdigest(),
        old_deployment_hash=hashlib.sha256(old_deployment).hexdigest(),
    )
    try:
        # Create the private journal directory before writing the first state
        # record.  The journal contains no secret material, but its mode is
        # still kept restrictive for consistency with the remote data root.
        rc, _, err = remote.execute(
            client,
            f"mkdir -m 0700 -p -- {shlex.quote(rollback_dir)} && chmod 0700 -- {shlex.quote(rollback_dir)}",
            timeout=20,
        )
        if rc:
            raise RuntimeError(f"promotion journal directory failed: {remote.scrub(err)}")
        _remote_write(client, state_path, _json_bytes(state), 0o600)

        rc, _, err = remote.execute(
            client,
            f"install -o root -g root -m 0644 -- {shlex.quote(network_old)} {shlex.quote(rollback_dir + '/old-network.json')} && "
            f"install -o root -g root -m 0644 -- {shlex.quote(deployment_old)} {shlex.quote(rollback_dir + '/old-deployment.json')} && "
            f"install -o mycomesh-mesh -g mycomesh-mesh -m 0600 -- {shlex.quote(candidate_path)} {shlex.quote(rollback_dir + '/candidate-node.json')}",
            timeout=30,
        )
        if rc:
            raise RuntimeError(f"promotion backup failed: {remote.scrub(err)}")
        _remote_write(client, f"{REMOTE_ROOT}/config/node-production.json", _json_bytes(production_node), 0o600)
        _remote_write(client, f"{REMOTE_ROOT}/runtime-production.py", _production_runtime(), 0o700)
        _remote_write(client, f"/etc/systemd/system/{new_unit}", _production_unit(name), 0o644)
        rc, _, err = remote.execute(
            client,
            f"chown mycomesh-mesh:mycomesh-mesh -- {shlex.quote(REMOTE_ROOT + '/config/node-production.json')} {shlex.quote(REMOTE_ROOT + '/runtime-production.py')} && "
            f"chmod 0600 -- {shlex.quote(REMOTE_ROOT + '/config/node-production.json')} && "
            f"chmod 0700 -- {shlex.quote(REMOTE_ROOT + '/runtime-production.py')} && "
            "systemctl daemon-reload",
            timeout=30,
        )
        if rc:
            raise RuntimeError(f"production runtime ownership/systemd reload failed: {remote.scrub(err)}")
        return state
    except Exception:
        # Nothing destructive has happened yet.  Remove only the files made by
        # this preparation attempt so a retry cannot accidentally reuse stale
        # artifacts or a half-written journal.
        remote.execute(
            client,
            f"rm -f -- {shlex.quote(state_path)} {shlex.quote(REMOTE_ROOT + '/config/node-production.json')} {shlex.quote(REMOTE_ROOT + '/runtime-production.py')} {shlex.quote('/etc/systemd/system/' + new_unit)} && "
            f"rm -rf -- {shlex.quote(rollback_dir)} && systemctl daemon-reload",
            timeout=30,
        )
        raise


def _rollback_remote(client: Any, name: str, spec: dict[str, Any], *, state: dict[str, Any] | None = None, dry_run: bool = False) -> dict[str, Any]:
    if state is None:
        state = _read_state(client, name)
    old_unit = str(state.get("old_unit") or OLD_UNITS[spec["role"]])
    new_unit = str(state.get("production_unit") or PRODUCTION_UNITS[name])
    rollback_dir = _rollback_dir(name)
    old_network_backup = str(state.get("old_network_backup") or f"{rollback_dir}/old-network.json")
    old_deployment_backup = str(state.get("old_deployment_backup") or f"{rollback_dir}/old-deployment.json")
    if dry_run:
        return {"node": name, "dry_run": True, "rollback": True, "phase": state.get("phase"), "old_unit": old_unit, "production_unit": new_unit}
    for path in (old_network_backup, old_deployment_backup):
        rc, _, err = remote.execute(client, f"test -f {shlex.quote(path)}", timeout=15)
        if rc:
            raise RuntimeError(f"rollback backup missing: {path}: {remote.scrub(err)}")
    if _systemd_state(client, new_unit) == "active":
        rc, _, err = remote.execute(client, f"systemctl stop -- {shlex.quote(new_unit)}", timeout=60)
        if rc:
            raise RuntimeError(f"failed to stop production unit: {remote.scrub(err)}")
    candidate_unit = str(state.get("candidate_unit") or spec["candidate_unit"])
    if state.get("phase") not in {"prepared", "rolled_back"} and _systemd_state(client, candidate_unit) == "active":
        raise RuntimeError("candidate unit is active during rollback; refusing shared-data rollback")
    for target, expected in (
        (f"{OLD_ROOT}/config/public/network.json", {NETWORK_SHA256, str(state.get("old_network_sha256") or "")}),
        (f"{OLD_ROOT}/config/public/deployment.json", {DEPLOYMENT_SHA256, str(state.get("old_deployment_sha256") or "")}),
    ):
        current = _remote_sha256(client, target)
        if current not in expected:
            raise RuntimeError(f"refusing rollback over an unexpected manifest: {target}")
    _atomic_manifest_switch(client, old_network_backup, f"{OLD_ROOT}/config/public/network.json")
    _atomic_manifest_switch(client, old_deployment_backup, f"{OLD_ROOT}/config/public/deployment.json")
    rc, _, err = remote.execute(client, f"systemctl disable -- {shlex.quote(new_unit)}", timeout=30)
    if rc and "not found" not in (err or "").lower():
        raise RuntimeError(f"failed to disable production unit: {remote.scrub(err)}")
    rc, _, err = remote.execute(client, f"systemctl enable -- {shlex.quote(old_unit)}", timeout=30)
    if rc:
        raise RuntimeError(f"failed to re-enable old unit: {remote.scrub(err)}")
    if _systemd_state(client, old_unit) != "active":
        rc, _, err = remote.execute(client, f"systemctl start -- {shlex.quote(old_unit)}", timeout=60)
        if rc:
            raise RuntimeError(f"failed to restart old unit: {remote.scrub(err)}")
    if _systemd_state(client, old_unit) != "active":
        raise RuntimeError("old unit did not return to active state")
    _write_phase(client, state, "rolled_back")
    return {"node": name, "rollback": True, "phase": "rolled_back", "old_unit": old_unit, "production_unit": new_unit}


def _promote(name: str, spec: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    client = remote.connect(name)
    state: dict[str, Any] | None = None
    try:
        candidate_health = _candidate_health(name, spec)
        candidate_node = _remote_read_json(client, f"{REMOTE_ROOT}/config/node.json")
        production_node = _production_node(name, spec, candidate_node)
        prepared = _prepare(client, name, spec, production_node, dry_run=dry_run)
        if dry_run:
            prepared["candidate_health"] = {
                "ok": candidate_health.get("ok"),
                "settlement_ready": candidate_health.get("settlement_ready"),
                "network_id": EXPECTED["network_id"],
            }
            return prepared
        state = prepared
        candidate_unit = spec["candidate_unit"]
        old_unit = OLD_UNITS[spec["role"]]
        new_unit = PRODUCTION_UNITS[name]
        rc, _, err = remote.execute(client, f"systemctl stop -- {shlex.quote(candidate_unit)}", timeout=60)
        if rc:
            raise RuntimeError(f"failed to stop candidate unit: {remote.scrub(err)}")
        _write_phase(client, state, "candidate_stopped")
        if _systemd_state(client, candidate_unit) == "active":
            raise RuntimeError("candidate unit remained active")
        rc, _, err = remote.execute(client, f"systemctl stop -- {shlex.quote(old_unit)}", timeout=60)
        if rc:
            raise RuntimeError(f"failed to stop old unit: {remote.scrub(err)}")
        _write_phase(client, state, "old_stopped")
        if _systemd_state(client, old_unit) == "active":
            raise RuntimeError("old unit remained active")
        _atomic_manifest_switch(client, f"{REMOTE_ROOT}/config/public/network.json", f"{OLD_ROOT}/config/public/network.json")
        _atomic_manifest_switch(client, f"{REMOTE_ROOT}/config/public/deployment.json", f"{OLD_ROOT}/config/public/deployment.json")
        _write_phase(client, state, "manifests_switched")
        rc, _, err = remote.execute(client, f"systemctl start -- {shlex.quote(new_unit)}", timeout=60)
        if rc:
            raise RuntimeError(f"failed to start production unit: {remote.scrub(err)}")
        _write_phase(client, state, "new_started")
        health = _health_request(client, _production_port(name, spec), unit=new_unit)
        _assert_dynamic_health(name, spec, health)
        rc, _, err = remote.execute(client, f"systemctl enable -- {shlex.quote(new_unit)}", timeout=30)
        if rc:
            raise RuntimeError(f"failed to enable production unit: {remote.scrub(err)}")
        rc, _, err = remote.execute(client, f"systemctl disable -- {shlex.quote(old_unit)}", timeout=30)
        if rc and "not found" not in (err or "").lower():
            raise RuntimeError(f"failed to disable old unit: {remote.scrub(err)}")
        _write_phase(client, state, "active")
        return {
            "node": name,
            "role": spec["role"],
            "phase": "active",
            "old_unit": old_unit,
            "production_unit": new_unit,
            "production_port": _production_port(name, spec),
            "network_id": EXPECTED["network_id"],
            "settlement": EXPECTED["settlement"],
            "candidate_health": {"ok": candidate_health.get("ok"), "settlement_ready": candidate_health.get("settlement_ready")},
            "production_health": {"ok": health.get("ok"), "settlement_ready": health.get("settlement_ready")},
        }
    except Exception:
        if state is not None and not dry_run:
            try:
                _rollback_remote(client, name, spec, state=state)
            except Exception as rollback_error:
                raise RuntimeError(f"promotion failed and automatic rollback failed: {remote.scrub(str(rollback_error))}")
        raise
    finally:
        _close(client)


def _rollback(name: str, spec: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    client = remote.connect(name)
    try:
        state = _read_state(client, name)
        return _rollback_remote(client, name, spec, state=state, dry_run=dry_run)
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(NODES), help="Promote or roll back one node; repeat for several.")
    parser.add_argument("--dry-run", action="store_true", help="Read and validate remote state without changing it.")
    parser.add_argument("--rollback", action="store_true", help="Restore the backed-up old unit/manifests for each node.")
    args = parser.parse_args()
    names = args.node or ["relay1", "relay3", "bridge1", "bridge2"]
    results: list[dict[str, Any]] = []
    for name in names:
        try:
            result = _rollback(name, NODES[name], dry_run=args.dry_run) if args.rollback else _promote(name, NODES[name], dry_run=args.dry_run)
            results.append(result)
            print(json.dumps(result, sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
    return 0 if len(results) == len(names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
