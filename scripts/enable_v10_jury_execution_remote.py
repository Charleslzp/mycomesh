#!/usr/bin/env python3
"""Enable durable Provider-AI jury execution on the primary V10 Relay.

This is an explicit, reversible promotion step.  It changes only the live
production Relay node configuration, installs the already-created dedicated
jury transaction key with mode 0600, and waits for the monetary-execution
health gate.  The serving/settlement submitter key is never replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import stat
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402

from gateway import chain  # noqa: E402
from reconnect_v10_dynamic_providers_remote import _reconnect  # noqa: E402
from stage_v10_dynamic_remote import NODES, REMOTE_ROOT  # type: ignore  # noqa: E402


NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
DEPLOYMENT = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
ROLE_KEY = ROOT / ".mycomesh/v10/roles/jury-executor-relay.key"
NODE = "relay1"
UNIT = "mycomesh-v10-dynamic-relay1.service"
HEALTH_PORT = 11090
EXPECTED_RELEASE = "v10-dynamic-provider-ai-20260926-f311cba9"
EXPECTED_JURY_PUBLIC_KEY = (
    "ec4245fbdf4ca146878df705317ff7d48eea6a37a036357041631c1341268bd2"
)
JURY_KEY_PATH = f"{REMOTE_ROOT}/config/jury-executor.key"
NODE_PATH = f"{REMOTE_ROOT}/config/node-production.json"
NETWORK_PATH = f"{REMOTE_ROOT}/config/public/network.json"
DEPLOYMENT_PATH = f"{REMOTE_ROOT}/config/public/deployment.json"
CAPS = {
    "--provider-jury-max-gas-price-wei": "2000000000",
    "--provider-jury-max-gas-units": "500000",
    "--provider-jury-max-total-gas-cost-wei": "1000000000000000",
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


def _write(client: Any, path: str, data: bytes, *, mode: int) -> None:
    parent = str(Path(path).parent)
    _run(client, f"mkdir -m 0700 -p -- {shlex.quote(parent)}", timeout=20)
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def _read_private(path: Path) -> bytes:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"jury key is not a regular file: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"jury key is group/other accessible: {path}")
    raw = path.read_text(encoding="ascii").strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    value = bytes.fromhex(raw)
    if len(value) != 32:
        raise RuntimeError("jury key must contain exactly 32 bytes")
    return value


def _argv_value(argv: list[Any], flag: str) -> str | None:
    positions = [i for i, item in enumerate(argv) if item == flag]
    if len(positions) > 1:
        raise RuntimeError(f"production argv repeats {flag}")
    if not positions:
        return None
    pos = positions[0]
    if pos + 1 >= len(argv) or not isinstance(argv[pos + 1], str):
        raise RuntimeError(f"production argv has no value for {flag}")
    return argv[pos + 1]


def _set_or_append(argv: list[Any], flag: str, value: str) -> None:
    current = _argv_value(argv, flag)
    if current is not None:
        if current != value:
            raise RuntimeError(f"production argv has an unexpected value for {flag}")
        return
    argv.extend([flag, value])


def _updated_node(raw: bytes) -> tuple[bytes, bool]:
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("role") != "relay":
        raise RuntimeError("remote production node is not a Relay configuration")
    if value.get("bundle_id") != EXPECTED_RELEASE:
        raise RuntimeError("remote production Relay release is not the verified V10 release")
    argv = value.get("argv")
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        raise RuntimeError("remote production Relay argv is invalid")
    if "--provider-jury-runtime-enabled" not in argv:
        raise RuntimeError("Provider-AI jury runtime is not enabled in production config")
    if "--jury-expected-public-key" not in argv:
        raise RuntimeError("production Relay has no pinned jury identity")
    if _argv_value(argv, "--jury-expected-public-key") != EXPECTED_JURY_PUBLIC_KEY:
        raise RuntimeError("production Relay jury identity differs from the verified node")

    enabled = "--provider-jury-execution-enabled" in argv
    disabled = "--no-provider-jury-execution-enabled" in argv
    if enabled and disabled:
        raise RuntimeError("production argv contains both jury execution flags")
    if not enabled and not disabled:
        raise RuntimeError("production argv has no explicit jury execution state")
    if disabled:
        argv.remove("--no-provider-jury-execution-enabled")
        argv.append("--provider-jury-execution-enabled")
        changed = True
    else:
        changed = False

    _set_or_append(argv, "--provider-jury-transaction-key-file", JURY_KEY_PATH)
    for flag, expected in CAPS.items():
        _set_or_append(argv, flag, expected)
    value["argv"] = argv
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return encoded, changed


def _health(client: Any, *, deadline_seconds: int = 180) -> dict[str, Any]:
    deadline = time.monotonic() + deadline_seconds
    last = "health probe did not run"
    while time.monotonic() < deadline:
        rc, out, err = remote.execute(
            client,
            f"curl -fsS --max-time 20 http://127.0.0.1:{HEALTH_PORT}/health",
            timeout=30,
        )
        if rc == 0:
            try:
                value = json.loads(out)
                anti = value.get("anti_cheat") or {}
                intake = value.get("provider_ai_jury_intake") or {}
                runtime = value.get("provider_ai_jury_runtime") or {}
                execution = runtime.get("execution") or {}
                if (
                    value.get("ok") is True
                    and value.get("inference_ready") is True
                    and int(value.get("providers", 0)) >= 3
                    and value.get("settlement_ready") is True
                    and anti.get("monetary_enforcement_enabled") is True
                    and anti.get("enforcement_mode") == "provider_ai_jury"
                    and intake.get("ready") is True
                    and runtime.get("monetary_ready") is True
                    and execution.get("enabled") is True
                    and execution.get("worker_enabled") is True
                    and execution.get("chain_enabled") is True
                    and execution.get("ready") is True
                ):
                    return value
                last = "health gate is not open yet"
            except (ValueError, TypeError, AttributeError) as exc:
                last = f"health parse failed: {exc}"
        else:
            last = remote.scrub(err or out).strip()[-500:] or last
        time.sleep(3)
    raise RuntimeError(f"jury execution health gate failed: {last}")


def _safe_health_summary(value: dict[str, Any]) -> dict[str, Any]:
    anti = value.get("anti_cheat") or {}
    runtime = value.get("provider_ai_jury_runtime") or {}
    return {
        "ok": value.get("ok"),
        "providers": value.get("providers"),
        "inference_ready": value.get("inference_ready"),
        "settlement_ready": value.get("settlement_ready"),
        "monetary_enforcement_enabled": anti.get("monetary_enforcement_enabled"),
        "enforcement_mode": anti.get("enforcement_mode"),
        "monetary_ready": runtime.get("monetary_ready"),
        "execution": runtime.get("execution"),
    }


def _reconnect_providers() -> list[dict[str, Any]]:
    """Restore Relay sessions after its process restart, one Provider at a time."""
    results = []
    for name in ("provider1", "provider2", "provider3", "provider4"):
        results.append(_reconnect(name, dry_run=False))
    return results


def _enable(*, dry_run: bool) -> dict[str, Any]:
    private = _read_private(ROLE_KEY)
    sender = chain.private_key_to_address(private)
    network = json.loads(NETWORK.read_text(encoding="utf-8"))
    expected_sender = str(network["jury_transaction_senders"][EXPECTED_JURY_PUBLIC_KEY]).lower()
    if sender.lower() != expected_sender:
        raise RuntimeError("local jury executor key does not match the network manifest sender")
    client = remote.connect(NODE)
    key_created = False
    backup_dir = f"{REMOTE_ROOT}/rollback/jury-execution-enable-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    old_node: bytes | None = None
    try:
        active = _run(client, f"systemctl is-active -- {shlex.quote(UNIT)}", timeout=20).strip()
        if active != "active":
            raise RuntimeError(f"{UNIT} is {active}; refusing execution promotion")
        remote_network = _read(client, NETWORK_PATH)
        remote_deployment = _read(client, DEPLOYMENT_PATH)
        if hashlib.sha256(remote_network).hexdigest() != hashlib.sha256(NETWORK.read_bytes()).hexdigest():
            raise RuntimeError("remote Relay network manifest is not the verified local manifest")
        if hashlib.sha256(remote_deployment).hexdigest() != hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest():
            raise RuntimeError("remote Relay deployment manifest is not the verified local manifest")
        old_node = _read(client, NODE_PATH)
        next_node, changed = _updated_node(old_node)
        key_exists = _run(
            client,
            f"if [ -e {shlex.quote(JURY_KEY_PATH)} ] || [ -L {shlex.quote(JURY_KEY_PATH)} ]; then printf yes; else printf no; fi",
            timeout=20,
        ).strip() == "yes"
        if key_exists:
            # Never replace an unknown key.  An already enabled, matching
            # configuration is safe to verify idempotently; a disabled config
            # with a stray key is refused.
            if changed:
                raise RuntimeError("dedicated jury key path already exists; refusing to overwrite it")
        result: dict[str, Any] = {
            "node": NODE,
            "sender": sender,
            "release": EXPECTED_RELEASE,
            "changed": changed,
            "dry_run": dry_run,
            "gas_caps": CAPS,
            "backup_dir": backup_dir,
        }
        if dry_run:
            result["node_sha256_before"] = hashlib.sha256(old_node).hexdigest()
            result["node_sha256_after"] = hashlib.sha256(next_node).hexdigest()
            result["key_present"] = key_exists
            return result

        _run(client, f"mkdir -m 0700 -p -- {shlex.quote(backup_dir)}", timeout=20)
        _write(client, f"{backup_dir}/node-production.json", old_node, mode=0o600)
        _run(
            client,
            f"chown mycomesh-mesh:mycomesh-mesh -- {shlex.quote(backup_dir + '/node-production.json')}",
            timeout=20,
        )
        if not key_exists:
            _write(client, JURY_KEY_PATH, (private.hex() + "\n").encode("ascii"), mode=0o600)
            _run(
                client,
                f"chown mycomesh-mesh:mycomesh-mesh -- {shlex.quote(JURY_KEY_PATH)} && chmod 0600 -- {shlex.quote(JURY_KEY_PATH)}",
                timeout=20,
            )
            key_created = True
        next_path = f"{NODE_PATH}.jury-enable.next"
        _write(client, next_path, next_node, mode=0o600)
        _run(
            client,
            f"chown mycomesh-mesh:mycomesh-mesh -- {shlex.quote(next_path)} && mv -f -- {shlex.quote(next_path)} {shlex.quote(NODE_PATH)}",
            timeout=20,
        )
        try:
            _run(client, f"systemctl restart -- {shlex.quote(UNIT)}", timeout=60)
            # The current Provider transport does not re-dial a Relay after a
            # process restart.  Reconnect the already-promoted containers
            # before evaluating the monetary execution health gate.
            result["provider_reconnect"] = _reconnect_providers()
            value = _health(client)
        except Exception:
            if old_node is not None:
                rollback_path = f"{NODE_PATH}.jury-enable.rollback.next"
                _write(client, rollback_path, old_node, mode=0o600)
                _run(
                    client,
                    f"chown mycomesh-mesh:mycomesh-mesh -- {shlex.quote(rollback_path)} && mv -f -- {shlex.quote(rollback_path)} {shlex.quote(NODE_PATH)}",
                    timeout=20,
                )
            if key_created:
                _run(client, f"rm -f -- {shlex.quote(JURY_KEY_PATH)}", timeout=20)
            _run(client, f"systemctl restart -- {shlex.quote(UNIT)}", timeout=60)
            try:
                _reconnect_providers()
            except Exception:
                # Preserve the original promotion failure while leaving the
                # Relay configuration restored; the next run will re-probe
                # every Provider before attempting execution again.
                pass
            raise
        result["node_sha256_before"] = hashlib.sha256(old_node).hexdigest()
        result["node_sha256_after"] = hashlib.sha256(next_node).hexdigest()
        result["health"] = _safe_health_summary(value)
        result["key_present"] = True
        return result
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(_enable(dry_run=args.dry_run), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"node": NODE, "error": remote.scrub(str(exc))}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
