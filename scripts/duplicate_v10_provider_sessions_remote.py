#!/usr/bin/env python3
"""Start isolated relay3 Provider sessions on the provider2/provider3 hosts.

The existing Provider containers remain untouched.  Each duplicate gets a new
P2P identity and run/data directory while retaining the already registered EVM
owner, so the on-chain jury assignment can select provider2/provider3/provider4
on relay3.  The manifest and deployment bytes are copied from the verified
local V10 candidate and every remote mutation is recorded under a rollback
directory.  No private material is printed.
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
NETWORK_VALUE = json.loads(NETWORK.read_text(encoding="utf-8"))
DEPLOYMENT_VALUE = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
NETWORK_SHA256 = hashlib.sha256(NETWORK.read_bytes()).hexdigest()
DEPLOYMENT_SHA256 = hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest()
REMOTE_ROOT = "/opt/mycomesh-v10-dynamic-20260926"

NODES = {
    "provider2": {
        "container": "mycomesh-v10-test-provider",
        "duplicate": "mycomesh-v10-relay3-provider2",
        "operator": "mycomesh-controlled-test/provider2",
        "payment": "0xabed1bf15451cff479c6b41bf24817437256eb00",
    },
    "provider3": {
        "container": "mycomesh-v10-test-provider",
        "duplicate": "mycomesh-v10-relay3-provider3",
        "operator": "mycomesh-controlled-test/provider3",
        "payment": "0xc1c5038c26de3ba5fc305e5d280915c3b7256cda",
    },
}


def _close(client: Any) -> None:
    jump = getattr(client, "_mesh_jump", None)
    client.close()
    if jump:
        jump.close()


def _run(client: Any, command: str, *, timeout: int = 60) -> str:
    rc, out, err = remote.execute(client, command, timeout=timeout)
    if rc:
        raise RuntimeError(remote.scrub(err or out).strip()[-1200:])
    return out


def _run_allow(client: Any, command: str, *, timeout: int = 60) -> tuple[int, str, str]:
    return remote.execute(client, command, timeout=timeout)


def _write(client: Any, path: str, payload: bytes, *, mode: int = 0o644) -> None:
    parent = str(Path(path).parent)
    _run(client, f"mkdir -m 0755 -p -- {shlex.quote(parent)}", timeout=20)
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(payload)
        sftp.chmod(path, mode)


def _read(client: Any, path: str) -> bytes:
    with client.open_sftp() as sftp:
        with sftp.file(path, "rb") as handle:
            return handle.read()


def _endpoint(name: str) -> dict[str, Any]:
    if name == "relay3":
        value = NETWORK_VALUE["relay_fallbacks"][0]
    else:
        value = NETWORK_VALUE["relay"]
    return json.loads(json.dumps(value))


def _network_payload() -> bytes:
    value = json.loads(json.dumps(NETWORK_VALUE))
    value["relay"] = _endpoint("relay3")
    value["relay_fallbacks"] = [_endpoint("relay1")]
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _deployment_payload() -> bytes:
    return DEPLOYMENT.read_bytes()


def _inspect(client: Any, container: str) -> dict[str, Any]:
    raw = _run(client, f"docker inspect --format '{{{{json .}}}}' -- {shlex.quote(container)}", timeout=20)
    value = json.loads(raw)
    config = value.get("Config") or {}
    mounts = {item.get("Destination"): item for item in value.get("Mounts") or ()}
    required = ("/app/gateway", "/agent", "/run/mesh-ca.crt")
    if any(not isinstance(mounts.get(path, {}).get("Source"), str) for path in required):
        raise RuntimeError("existing Provider is missing a required read-only mount")
    if config.get("User") != "10001:10001" or config.get("WorkingDir") != "/data":
        raise RuntimeError("existing Provider runtime user or workdir is unexpected")
    if (value.get("State") or {}).get("Running") is not True:
        raise RuntimeError("existing Provider container is not running")
    return {
        "image": config.get("Image"),
        "gateway": mounts["/app/gateway"]["Source"],
        "agent": mounts["/agent"]["Source"],
        "ca": mounts["/run/mesh-ca.crt"]["Source"],
    }


def _probe(client: Any, container: str) -> dict[str, Any]:
    deadline = time.monotonic() + 180
    last = "not started"
    command = (
        f"docker exec -- {shlex.quote(container)} python -m gateway.provider_bootstrap "
        "--network-config /candidate/network.json --require-bridge-lease"
    )
    while time.monotonic() < deadline:
        rc, out, err = _run_allow(
            client,
            f"docker inspect --format '{{{{.State.Running}}}}|{{{{.State.Status}}}}' -- {shlex.quote(container)}",
            timeout=20,
        )
        if rc:
            last = "container inspect failed"
        else:
            running, status = out.strip().split("|", 1)
            if running != "true":
                if status in {"exited", "dead"}:
                    raise RuntimeError(f"duplicate Provider stopped: {status}")
                last = f"Provider is {status}"
            else:
                rc, probe_out, probe_err = _run_allow(client, command, timeout=30)
                if rc == 0:
                    return {"running": True, "lease": True}
                last = remote.scrub(probe_err or probe_out).strip()[-400:] or "lease probe failed"
        time.sleep(5)
    raise RuntimeError(f"relay3 duplicate lease probe failed: {last}")


def _duplicate(node: str, *, dry_run: bool) -> dict[str, Any]:
    spec = NODES[node]
    client = remote.connect(node)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    duplicate_root = f"{REMOTE_ROOT}/duplicates/{node}-relay3"
    data_dir = f"{duplicate_root}/data"
    candidate_dir = f"{duplicate_root}/candidate"
    backup_dir = f"{REMOTE_ROOT}/rollback/duplicate-provider-{stamp}-{node}"
    try:
        inspected = _inspect(client, spec["container"])
        existing = _run_allow(client, f"docker inspect --format '{{{{.State.Running}}}}' -- {shlex.quote(spec['duplicate'])}", timeout=20)
        if existing[0] == 0:
            result = {"node": node, "duplicate": spec["duplicate"], "changed": False, "already_present": True}
            if not dry_run:
                result["probe"] = _probe(client, spec["duplicate"])
            return result
        if dry_run:
            return {
                "node": node,
                "duplicate": spec["duplicate"],
                "changed": True,
                "dry_run": True,
                "network_sha256": hashlib.sha256(_network_payload()).hexdigest(),
                "deployment_sha256": DEPLOYMENT_SHA256,
            }

        _run(client, f"mkdir -m 0700 -p -- {shlex.quote(backup_dir)} {shlex.quote(data_dir)} {shlex.quote(candidate_dir)}", timeout=20)
        # Keep a hash-only record plus the old container inspection for rollback
        # without copying or printing any private environment values.
        _run(client, f"docker inspect --format '{{{{json .}}}}' -- {shlex.quote(spec['container'])} | sha256sum > {shlex.quote(backup_dir + '/container-inspect.sha256')}", timeout=20)
        _write(client, f"{backup_dir}/network.json", _read(client, f"{REMOTE_ROOT}/config/public/network.json"))
        _write(client, f"{candidate_dir}/network.json", _network_payload())
        _write(client, f"{candidate_dir}/deployment.json", _deployment_payload())
        _write(client, f"{candidate_dir}/sepolia-myco-v10-dynamic-20260926.json", _deployment_payload())
        _run(client, f"cp -- {shlex.quote(REMOTE_ROOT + '/config/public/provider-jury-policy-v1.json')} {shlex.quote(candidate_dir + '/provider-jury-policy-v1.json')} 2>/dev/null || true", timeout=20)
        _run(client, f"cp -- {shlex.quote(REMOTE_ROOT + '/config/public/sepolia-myco-v10-dynamic-20260926.json')} {shlex.quote(backup_dir + '/deployment-existing.json')} 2>/dev/null || true", timeout=20)
        evm_source = f"{REMOTE_ROOT}/config/../"  # replaced below by the mounted canonical data path
        # The existing /data mount is known from the staged Provider.  Copy only
        # the registered EVM identity; the new P2P identity is generated in the
        # isolated directory on first start.
        old_data = "/opt/mycomesh-v10-fixed-budget-20260918/data"
        _run(client, f"cp -- {shlex.quote(old_data + '/provider-evm-identity.json')} {shlex.quote(data_dir + '/provider-evm-identity.json')} && chown 10001:10001 -- {shlex.quote(data_dir + '/provider-evm-identity.json')} && chmod 0600 -- {shlex.quote(data_dir + '/provider-evm-identity.json')}", timeout=20)
        _run(client, f"chown -R 10001:10001 -- {shlex.quote(data_dir)} && chmod 0700 -- {shlex.quote(data_dir)}", timeout=20)
        image = inspected.get("image")
        if not isinstance(image, str) or not image:
            raise RuntimeError("existing Provider image is unavailable")
        name = shlex.quote(spec["duplicate"])
        data = shlex.quote(data_dir)
        candidate = shlex.quote(candidate_dir)
        gateway = shlex.quote(inspected["gateway"])
        agent = shlex.quote(inspected["agent"])
        ca = shlex.quote(inspected["ca"])
        image_arg = shlex.quote(image)
        env = {
            "MYCOMESH_PROVIDER_NETWORK_CONFIG": "/candidate/network.json",
            "MYCOMESH_PROVIDER_IDENTITY": "/data/node-identity.json",
            "MYCOMESH_PROVIDER_EVM_IDENTITY": "/data/provider-evm-identity.json",
            "MYCOMESH_PROVIDER_RUN_DIR": "/data/run-dynamic-v10-relay3",
            "MYCOMESH_PROVIDER_JURY_ENABLED": "true",
            "MYCOMESH_PROVIDER_OPERATOR_ID": spec["operator"],
            "MYCOMESH_PROVIDER_PAYOUT_ADDRESS": spec["payment"],
            "MYCO_DEPLOYMENT": "/candidate/sepolia-myco-v10-dynamic-20260926.json",
            "MYCOMESH_NETWORK_ID": str(NETWORK_VALUE["network_id"]),
            "MYCOMESH_NETWORK_PROFILE": "testnet",
            "MYCOMESH_SETTLEMENT_VERSION": "10",
            "MYCOMESH_ALLOW_CONTROLLED_V10_TEST": "1",
            "MYCOMESH_PROVIDER_TRANSPORT": "relay",
            "GATEWAY_BACKEND": "codex_app_server",
            "MYCOMESH_DATA_DIR": "/data",
            "PYTHONPATH": "/app",
            "AGENTS_FILE": "/agent/agents.json",
            "SSL_CERT_FILE": "/run/mesh-ca.crt",
            "REQUESTS_CA_BUNDLE": "/run/mesh-ca.crt",
        }
        env_file = f"{backup_dir}/provider-env"
        _run(
            client,
            f"docker inspect --format '{{{{range .Config.Env}}}}{{{{println .}}}}' -- {shlex.quote(spec['container'])} > {shlex.quote(env_file)} && chmod 0600 -- {shlex.quote(env_file)}",
            timeout=20,
        )
        env_args = " ".join(f"-e {shlex.quote(k + '=' + v)}" for k, v in env.items())
        # The staged image has ``python`` as its ENTRYPOINT, therefore the
        # Docker command must begin with ``-m gateway`` (not another python).
        cmd = (
            "-m gateway --agents-file /agent/agents.json provider start --skip-login "
            "--gateway-url http://provider-sidecar:8000/v1 --allow-private-gateway-http "
            "--network-config /candidate/network.json "
            f"--network-id {shlex.quote(str(NETWORK_VALUE['network_id']))} --settlement-version 10 "
            "--network-profile testnet --transport relay --identity /data/node-identity.json "
            "--evm-identity /data/provider-evm-identity.json --run-dir /data/run-dynamic-v10-relay3 "
            "--model gpt-5.5 --reserve-input-tokens 65536 --reserve-output-tokens 2000 "
            "--capacity 1 --ttl 300 --heartbeat-interval 30 --timeout 150 "
            f"--payment-address {shlex.quote(spec['payment'])} --operator-id {shlex.quote(spec['operator'])} --jury-enabled"
        )
        run = (
            f"docker run -d --name {name} --restart unless-stopped --init --network mycomesh_provider-net "
            "--user 10001:10001 --workdir /data --security-opt no-new-privileges:true --cap-drop ALL "
            "--pids-limit 512 --memory 2g --cpus 2 "
            f"-v {candidate}:/candidate:ro -v {data}:/data:rw -v {agent}:/agent:ro "
            f"-v {ca}:/run/mesh-ca.crt:ro -v {gateway}:/app/gateway:ro "
            f"--env-file {shlex.quote(env_file)} {env_args} {image_arg} {cmd}"
        )
        _run(client, run, timeout=90)
        _run(client, f"rm -f -- {shlex.quote(env_file)}", timeout=20)
        result = {
            "node": node,
            "duplicate": spec["duplicate"],
            "changed": True,
            "backup_dir": backup_dir,
            "network_sha256": hashlib.sha256(_network_payload()).hexdigest(),
            "deployment_sha256": DEPLOYMENT_SHA256,
            "image": image,
        }
        result["probe"] = _probe(client, spec["duplicate"])
        return result
    except Exception:
        # Do not remove a pre-existing container.  If this command created one
        # and the lease probe failed, leave it stopped for inspection and
        # rollback evidence rather than silently deleting state.
        raise
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(NODES))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    for node in args.node or sorted(NODES):
        try:
            print(json.dumps(_duplicate(node, dry_run=args.dry_run), sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": node, "error": remote.scrub(str(exc))}, sort_keys=True))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
