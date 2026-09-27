#!/usr/bin/env python3
"""Roll Providers onto the current dynamic V10 manifest, one node at a time.

The migration keeps the existing sidecar, provider identity, and data bind
mount.  A candidate container is created from the exact image already used by
the Provider, but with the current gateway release and dynamic V10 manifests.
The old container is renamed and retained as a stopped rollback target after
the candidate passes its process and Bridge-lease checks.

No private key or token is printed.  The remote journal contains only paths,
hashes, container names, and lifecycle phases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402


NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
DEPLOYMENT = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
ARCHIVE = ROOT / ".codex-run/mesh/v10-dynamic-provider-jury-20260923/v10-dynamic-provider-ai-20260926-f311cba9.tar.gz"
RELEASE_ID = "v10-dynamic-provider-ai-20260926-f311cba9"
REMOTE_ROOT = "/opt/mycomesh-v10-dynamic-20260926"
REMOTE_RELEASE = f"/opt/mycomesh-mesh/releases/{RELEASE_ID}"
REMOTE_ARCHIVE = f"/opt/mycomesh-mesh/releases/{RELEASE_ID}.tar.gz"
PROVIDERS = {
    # provider1 is the serving-only Provider.  It is intentionally absent
    # from the on-chain jury registry because its signer has no imported
    # reputation evidence.  Its legacy container has a different name/root
    # from the three registry candidates.
    "provider1": {
        "owner": "0x94515c8903cca8e5aedb1437e947db39970792cc",
        "old_root": "/opt/mycomesh-v10-dynamic-provider",
        "old_container": "mycomesh-provider-1",
        "candidate_container": "mycomesh-provider-1-dynamic-candidate",
    },
    "provider2": {
        "owner": "0xabed1bf15451cff479c6b41bf24817437256eb00",
        "old_root": "/opt/mycomesh-v10-fixed-budget-20260918",
        "old_container": "mycomesh-v10-test-provider",
        "candidate_container": "mycomesh-v10-dynamic-provider-candidate",
    },
    "provider3": {
        "owner": "0xc1c5038c26de3ba5fc305e5d280915c3b7256cda",
        "old_root": "/opt/mycomesh-v10-fixed-budget-20260918",
        "old_container": "mycomesh-v10-test-provider",
        "candidate_container": "mycomesh-v10-dynamic-provider-candidate",
    },
    "provider4": {
        "owner": "0xa88182a20e597a3379f93b6273516fb377325333",
        "old_root": "/opt/mycomesh-v10-fixed-budget-20260918",
        "old_container": "mycomesh-v10-test-provider",
        "candidate_container": "mycomesh-v10-dynamic-provider-candidate",
    },
}


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _close(client: Any) -> None:
    if client is None:
        return
    client.close()
    if getattr(client, "_mesh_jump", None):
        client._mesh_jump.close()


def _write(client: Any, path: str, data: bytes, mode: int = 0o600) -> None:
    parent = str(Path(path).parent)
    rc, _, _ = remote.execute(client, f"mkdir -p -- {shlex.quote(parent)}", timeout=30)
    if rc:
        raise RuntimeError(f"remote mkdir failed: {path}")
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def _run(client: Any, command: str, *, step: str, timeout: int = 60) -> str:
    rc, out, _ = remote.execute(client, command, timeout=timeout)
    if rc:
        raise RuntimeError(f"{step} failed")
    return out


def _run_allow(client: Any, command: str, *, timeout: int = 60) -> tuple[int, str, str]:
    return remote.execute(client, command, timeout=timeout)


def _inspect(client: Any, name: str) -> dict[str, Any]:
    out = _run(client, f"docker inspect -- {shlex.quote(name)}", step=f"inspect {name}")
    value = json.loads(out)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeError(f"unexpected docker inspect for {name}")
    return value[0]


def _container_state(client: Any, name: str) -> tuple[bool, str]:
    out = _run(client, f"docker inspect --format '{{{{.State.Running}}}}|{{{{.State.Status}}}}' -- {shlex.quote(name)}", step=f"inspect state {name}")
    running, status = out.strip().split("|", 1)
    return running == "true", status


def _env_file(env: dict[str, str]) -> bytes:
    rows: list[str] = []
    for key, value in env.items():
        if "\n" in value or "\r" in value or "\x00" in value:
            raise RuntimeError(f"unsafe newline in environment value: {key}")
        rows.append(f"{key}={value}")
    return ("\n".join(rows) + "\n").encode("utf-8")


def _replace_arg(args: list[str], flag: str, value: str) -> None:
    try:
        index = args.index(flag)
    except ValueError as exc:
        raise RuntimeError(f"provider command missing {flag}") from exc
    if index + 1 >= len(args):
        raise RuntimeError(f"provider command has no value for {flag}")
    args[index + 1] = value


def _candidate_create_command(old: dict[str, Any], env_path: str, command: list[str], candidate_container: str) -> str:
    config = old.get("Config") or {}
    host = old.get("HostConfig") or {}
    mounts = old.get("Mounts") or []
    args: list[str] = ["docker", "create", "--name", candidate_container, "--env-file", env_path]

    network_mode = str(host.get("NetworkMode") or "")
    if network_mode:
        args += ["--network", network_mode]
    user = str(config.get("User") or "")
    if user:
        args += ["--user", user]
    workdir = str(config.get("WorkingDir") or "")
    if workdir:
        args += ["--workdir", workdir]
    entrypoint = config.get("Entrypoint") or []
    if isinstance(entrypoint, list) and entrypoint:
        args += ["--entrypoint", str(entrypoint[0])]
    restart = str((host.get("RestartPolicy") or {}).get("Name") or "unless-stopped")
    if restart:
        args += ["--restart", restart]
    if host.get("ShmSize"):
        args += ["--shm-size", str(int(host["ShmSize"]))]
    if host.get("Privileged"):
        raise RuntimeError("refusing to migrate a privileged Provider container")
    for security in host.get("SecurityOpt") or []:
        args += ["--security-opt", str(security)]
    for cap in host.get("CapDrop") or []:
        args += ["--cap-drop", str(cap)]
    if host.get("ReadonlyRootfs"):
        args.append("--read-only")
    for mount in mounts:
        if mount.get("Type") != "bind":
            raise RuntimeError("Provider migration only supports the existing bind mounts")
        source = str(mount.get("Source") or "")
        destination = str(mount.get("Destination") or "")
        if destination == "/app/gateway":
            source = REMOTE_RELEASE + "/gateway"
        elif destination == "/candidate":
            source = REMOTE_ROOT + "/config/public"
        elif destination == "/run/mesh-ca.crt":
            source = REMOTE_ROOT + "/config/ca-bundle.crt"
        if not source or not destination:
            raise RuntimeError("Provider mount is incomplete")
        args += ["--volume", f"{source}:{destination}:{'ro' if not mount.get('RW') else 'rw'}"]
    image = str(old.get("Image") or "")
    if not image.startswith("sha256:"):
        raise RuntimeError("Provider image is not pinned by digest")
    args.append(image)
    args.extend(command)
    return " ".join(shlex.quote(part) for part in args)


def _wait_running(client: Any, name: str, *, timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        running, status = _container_state(client, name)
        if running:
            return
        if status in {"exited", "dead"}:
            raise RuntimeError(f"{name} stopped during startup")
        time.sleep(2)
    raise RuntimeError(f"{name} did not become running")


def _journal(client: Any, name: str, value: dict[str, Any]) -> None:
    _write(client, f"{REMOTE_ROOT}/rollback/{name}-provider-promotion.json", _json_bytes(value), 0o600)


def _make_archive() -> tuple[Path, str]:
    if ARCHIVE.is_file():
        digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
        return ARCHIVE, digest
    ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(ARCHIVE, "w:gz") as archive:
        archive.add(ROOT / "gateway", arcname="gateway", recursive=True)
    ARCHIVE.chmod(0o600)
    return ARCHIVE, hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()


def _promote(name: str, archive: Path, archive_sha256: str) -> dict[str, Any]:
    network = json.loads(NETWORK.read_text(encoding="utf-8"))
    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    network_id = str(network["network_id"])
    spec = PROVIDERS[name]
    owner = str(spec["owner"]).lower()
    old_root = str(spec["old_root"])
    old_container = str(spec["old_container"])
    candidate_container = str(spec["candidate_container"])
    client = remote.connect(name)
    old_started = False
    candidate_started = False
    old_renamed = False
    old_rollback = f"{old_container}.rollback-v10-dynamic-20260926"
    failed_candidate = f"{candidate_container}.failed-v10-dynamic-20260926"
    state: dict[str, Any] = {
        "schema": "mycomesh.v10.provider-promotion.v1",
        "node": name,
        "network_id": network_id,
        "release": RELEASE_ID,
        "archive_sha256": archive_sha256,
        "network_sha256": hashlib.sha256(NETWORK.read_bytes()).hexdigest(),
        "deployment_sha256": hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest(),
        "old_container": old_container,
        "candidate_container": candidate_container,
        "failed_candidate": failed_candidate,
        "rollback_container": old_rollback,
        "phase": "starting",
    }
    try:
        old = _inspect(client, old_container)
        running, _ = _container_state(client, old_container)
        if not running:
            raise RuntimeError("old Provider container is not running")
        if _run_allow(client, f"docker inspect -- {shlex.quote(candidate_container)}", timeout=20)[0] == 0:
            raise RuntimeError("candidate container already exists; inspect rollback journal before retrying")
        if _run_allow(client, f"docker inspect -- {shlex.quote(old_rollback)}", timeout=20)[0] == 0:
            raise RuntimeError("rollback container name already exists; refusing to overwrite it")

        config = old.get("Config") or {}
        old_env: dict[str, str] = {}
        for item in config.get("Env") or []:
            if "=" in item:
                key, value = item.split("=", 1)
                old_env[key] = value
        env = dict(old_env)
        env.update({
            "MYCOMESH_NETWORK_ID": network_id,
            "MYCOMESH_PROVIDER_NETWORK_CONFIG": "/candidate/network.json",
            "MYCO_DEPLOYMENT": "/candidate/sepolia-myco-v10-dynamic-20260926.json",
            "MYCOMESH_SETTLEMENT_VERSION": "10",
            "MYCOMESH_ALLOW_CONTROLLED_V10_TEST": "1",
            "MYCOMESH_SETTLEMENT_RPC_URL": str(network["settlement_rpc_url"]),
            "ETH_RPC_URL": ",".join(str(v) for v in network["settlement_rpc_urls"]),
            "MYCOMESH_SETTLEMENT_CONFIRMATIONS": str(int(network.get("confirmations", 6))),
            "MYCOMESH_PROVIDER_RUN_DIR": "/data/run-dynamic-v10-20260926",
            "PYTHONPATH": "/app",
            "SSL_CERT_FILE": "/run/mesh-ca.crt",
            "REQUESTS_CA_BUNDLE": "/run/mesh-ca.crt",
            "MYCOMESH_PROVIDER_JURY_ENABLED": "true",
        })
        command = [str(v) for v in config.get("Cmd") or []]
        _replace_arg(command, "--network-config", "/candidate/network.json")
        _replace_arg(command, "--network-id", network_id)
        _replace_arg(command, "--run-dir", "/data/run-dynamic-v10-20260926")
        if "--payment-address" in command:
            _replace_arg(command, "--payment-address", owner)
        env_path = f"{REMOTE_ROOT}/config/provider.env"

        _run(client, f"mkdir -p -- {shlex.quote(REMOTE_ROOT + '/config/public')} {shlex.quote(REMOTE_RELEASE)} {shlex.quote(REMOTE_ROOT + '/rollback')}", step="create Provider staging directories")
        with client.open_sftp() as sftp:
            sftp.put(str(archive), REMOTE_ARCHIVE)
            sftp.chmod(REMOTE_ARCHIVE, 0o644)
        digest_out = _run(client, f"sha256sum -- {shlex.quote(REMOTE_ARCHIVE)}", step="verify Provider release upload", timeout=30)
        if not digest_out.split() or digest_out.split()[0] != archive_sha256:
            raise RuntimeError("Provider release digest mismatch")
        _run(client, f"rm -rf -- {shlex.quote(REMOTE_RELEASE)} && mkdir -p -- {shlex.quote(REMOTE_RELEASE)} && tar -xzf {shlex.quote(REMOTE_ARCHIVE)} -C {shlex.quote(REMOTE_RELEASE)} --no-same-owner", step="extract Provider release", timeout=120)
        _run(client, f"install -m 0644 -- {shlex.quote(old_root + '/config/ca-bundle.crt')} {shlex.quote(REMOTE_ROOT + '/config/ca-bundle.crt')}", step="stage Provider CA")
        _write(client, REMOTE_ROOT + "/config/public/network.json", NETWORK.read_bytes(), 0o644)
        _write(client, REMOTE_ROOT + "/config/public/deployment.json", DEPLOYMENT.read_bytes(), 0o644)
        _write(client, REMOTE_ROOT + "/config/public/sepolia-myco-v10-dynamic-20260926.json", DEPLOYMENT.read_bytes(), 0o644)
        _write(client, env_path, _env_file(env), 0o600)
        data_mount = next((str(m.get("Source") or "") for m in (old.get("Mounts") or []) if m.get("Destination") == "/data"), "")
        if not data_mount:
            raise RuntimeError("Provider container has no /data bind/volume")
        new_run_dir = data_mount + "/run-dynamic-v10-20260926"
        _run(client, f"mkdir -p -- {shlex.quote(new_run_dir)} && chown -R 10001:10001 -- {shlex.quote(new_run_dir)}", step="prepare Provider run directory")

        create_cmd = _candidate_create_command(old, env_path, command, candidate_container)
        _run(client, create_cmd, step="create Provider candidate", timeout=60)
        state["phase"] = "prepared"
        _journal(client, name, state)

        _run(client, f"docker update --restart=no -- {shlex.quote(old_container)}", step="disable old Provider restart")
        _run(client, f"docker stop --time 35 -- {shlex.quote(old_container)}", step="stop old Provider", timeout=60)
        old_started = False
        state["phase"] = "old_stopped"
        _journal(client, name, state)

        _run(client, f"docker start -- {shlex.quote(candidate_container)}", step="start Provider candidate", timeout=60)
        candidate_started = True
        _wait_running(client, candidate_container, timeout=90)
        # The lease check binds the new manifest, Bridge set, and node identity.
        check = f"docker exec -- {shlex.quote(candidate_container)} python -m gateway.provider_bootstrap --network-config /candidate/network.json --require-bridge-lease"
        lease_deadline = time.monotonic() + 150
        lease_detail = "no diagnostic"
        while time.monotonic() < lease_deadline:
            lease_rc, lease_out, lease_err = _run_allow(client, check, timeout=25)
            if lease_rc == 0:
                break
            lease_detail = remote.scrub((lease_err or lease_out).strip())[-1000:] or lease_detail
            time.sleep(5)
        else:
            raise RuntimeError(f"verify Provider Bridge lease failed: {lease_detail}")
        _wait_running(client, candidate_container, timeout=15)
        state["phase"] = "candidate_verified"
        _journal(client, name, state)

        _run(client, f"docker rename -- {shlex.quote(old_container)} {shlex.quote(old_rollback)}", step="retain old Provider rollback")
        old_renamed = True
        _run(client, f"docker rename -- {shlex.quote(candidate_container)} {shlex.quote(old_container)}", step="activate new Provider name")
        candidate_started = False
        _run(client, f"docker update --restart=unless-stopped -- {shlex.quote(old_container)}", step="enable new Provider restart")
        state["phase"] = "active"
        _journal(client, name, state)
        # The env file contains the inherited environment and is no longer needed
        # after docker has created the candidate.
        _run_allow(client, f"rm -f -- {shlex.quote(env_path)}", timeout=20)
        return {"node": name, "phase": "active", "network_id": network_id, "release": RELEASE_ID, "archive_sha256": archive_sha256}
    except Exception:
        state["phase"] = "rollback_required"
        try:
            _journal(client, name, state)
        except Exception:
            pass
        # Restore only the explicitly named containers.  If a rename completed,
        # undo it before starting the old image.  Never delete the old rollback.
        try:
            candidate_exists = _run_allow(client, f"docker inspect -- {shlex.quote(candidate_container)}", timeout=15)[0] == 0
            if candidate_exists:
                _run_allow(client, f"docker stop --time 35 -- {shlex.quote(candidate_container)}", timeout=60)
                # Keep a stopped failed candidate for postmortem; it contains
                # no new identity material and can be removed after the cause
                # is recorded.  Refuse to overwrite a prior failed attempt.
                if _run_allow(client, f"docker inspect -- {shlex.quote(failed_candidate)}", timeout=15)[0] != 0:
                    _run_allow(client, f"docker rename -- {shlex.quote(candidate_container)} {shlex.quote(failed_candidate)}", timeout=30)
                else:
                    _run_allow(client, f"docker rm -- {shlex.quote(candidate_container)}", timeout=30)
            if old_renamed:
                current_exists = _run_allow(client, f"docker inspect -- {shlex.quote(old_container)}", timeout=15)[0] == 0
                if current_exists:
                    _run_allow(client, f"docker rename -- {shlex.quote(old_container)} {shlex.quote(candidate_container)}", timeout=30)
                _run_allow(client, f"docker rename -- {shlex.quote(old_rollback)} {shlex.quote(old_container)}", timeout=30)
            _run_allow(client, f"docker update --restart=unless-stopped -- {shlex.quote(old_container)}", timeout=20)
            _run_allow(client, f"docker start -- {shlex.quote(old_container)}", timeout=60)
            _journal(client, name, {**state, "phase": "rolled_back"})
        except Exception:
            _journal(client, name, {**state, "phase": "rollback_failed"})
        raise
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(PROVIDERS), help="Provider to migrate; repeat for a selected set")
    args = parser.parse_args()
    archive, digest = _make_archive()
    names = args.node or list(PROVIDERS)
    results: list[dict[str, Any]] = []
    for name in names:
        try:
            result = _promote(name, archive, digest)
            results.append(result)
            print(json.dumps(result, sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": str(exc), "release": RELEASE_ID}, sort_keys=True))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
