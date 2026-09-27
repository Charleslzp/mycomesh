#!/usr/bin/env python3
"""Stage the Relay-hosted Pool candidates for the dynamic V10 cutover.

The edge Nginx configuration already routes provider directory traffic to a
same-host Pool on port 12000.  This helper starts a new Pool on an alternate
loopback port and leaves the old Pool untouched.  Promotion is performed by
``promote_v10_dynamic_remote.py`` together with the matching Relay, so a
Relay can never advertise the new manifest while its directory still runs the
old Settlement.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402
from stage_v10_dynamic_remote import (  # type: ignore  # noqa: E402
    DEPLOYMENT,
    GENESIS_HASH,
    NODES,
    OLD_ROOT,
    PROVIDER_PUBLIC_KEYS,
    REMOTE_RELEASE,
    REMOTE_ROOT,
    RELEASE_ID,
    RPC,
    _json_bytes,
)


# The edge service has a stable 12000 backend.  Candidates use distinct
# loopback ports and distinct systemd units so they cannot share a listening
# socket or accidentally stop the old service.
POOL_SPECS: dict[str, dict[str, Any]] = {
    "relay1": {
        "host": "136.0.3.126",
        "candidate_unit": "mycomesh-v10-dynamic-pool1-candidate.service",
        "candidate_port": 12100,
        "production_unit": "mycomesh-v10-dynamic-pool1.service",
    },
    "relay3": {
        "host": "166.88.96.60",
        "candidate_unit": "mycomesh-v10-dynamic-pool3-candidate.service",
        "candidate_port": 12103,
        "production_unit": "mycomesh-v10-dynamic-pool3.service",
    },
}

OLD_POOL_UNIT = "mycomesh-v10-test-pool.service"
REPUTATION_SIGNER_PUBLIC_KEY = "96aa8c50ce03d57187e8cc4af216d44a21fb7dc64d7fcbcf4aa832d74e50fa56"
PUBLIC_NETWORK = f"{REMOTE_ROOT}/config/public/network.json"
PUBLIC_DEPLOYMENT = f"{REMOTE_ROOT}/config/public/sepolia-myco-v10-dynamic-20260926.json"
POOL_NODE_TEMPLATE = f"{REMOTE_ROOT}/config/{{name}}-pool-node.json"
POOL_RUNTIME_TEMPLATE = f"{REMOTE_ROOT}/{{name}}-pool-runtime.py"
POOL_DATA_TEMPLATE = f"{REMOTE_ROOT}/data/{{name}}-pool.sqlite3"


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


def _node(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    data = f"{REMOTE_ROOT}/data"
    env = {
        "MYCOMESH_ALLOW_CONTROLLED_V10_TEST": "1",
        "MYCOMESH_BACKEND_POLICY": "codex-app-server-postvalidated-v1",
        "MYCOMESH_CHANNEL": "codex-standard-v1",
        "MYCOMESH_CHANNEL_ID": "codex",
        "MYCOMESH_NETWORK_ID": "mycomesh-v10-dynamic-provider-ai-20260926-controlled-test",
        "MYCOMESH_NETWORK_PROFILE": "testnet",
        "MYCOMESH_SETTLEMENT_VERSION": "10",
        "MYCO_DEPLOYMENT": PUBLIC_DEPLOYMENT,
        "MYCOMESH_SETTLEMENT_RPC_URL": RPC,
        "ETH_RPC_URL": RPC,
        "MYCOMESH_POOL_REPUTATION_RPC_URL": RPC,
        "MYCOMESH_POOL_REPUTATION_GENESIS_HASH": GENESIS_HASH,
        "MYCOMESH_POOL_REPUTATION_CONFIRMATIONS": "6",
    }
    args: list[str] = [
        "pool", "serve", "--host", "127.0.0.1", "--port", str(spec["candidate_port"]),
        "--public-url", f"https://{spec['host']}:10443",
        "--network-profile", "testnet",
        "--require-provider-backend-metadata", "--trust-proxy-headers",
        "--reputation-signer-public-key", REPUTATION_SIGNER_PUBLIC_KEY,
        "--reputation-rpc-url", RPC,
        "--reputation-genesis-hash", GENESIS_HASH,
        "--reputation-confirmations", "6",
    ]
    for key in PROVIDER_PUBLIC_KEYS:
        args += ["--provider-public-key", key]
    return {
        "node": name,
        "role": "pool",
        "candidate": REMOTE_RELEASE,
        "bundle_id": RELEASE_ID,
        "public_url": f"https://{spec['host']}:10443",
        "env": env,
        "argv": args,
        "network_config": PUBLIC_NETWORK,
        "deployment": PUBLIC_DEPLOYMENT,
        "data_path": POOL_DATA_TEMPLATE.format(name=name),
    }


def _runtime(name: str) -> bytes:
    node_path = POOL_NODE_TEMPLATE.format(name=name)
    return (
        "import json, os, sys\n"
        "from pathlib import Path\n"
        f"ROOT = Path({REMOTE_ROOT!r})\n"
        f"C = json.loads(Path({node_path!r}).read_text())\n"
        "sys.path.insert(0, C['candidate'])\n"
        "os.environ.update(C['env'])\n"
        "os.environ.update(PYTHONPATH=C['candidate'], PYTHONDONTWRITEBYTECODE='1', "
        "SSL_CERT_FILE=str(ROOT / 'config/ca-bundle.crt'), "
        "REQUESTS_CA_BUNDLE=str(ROOT / 'config/ca-bundle.crt'))\n"
        "os.chdir(ROOT / 'data')\n"
        "from gateway.client import main\n"
        "raise SystemExit(main(C['argv']))\n"
    ).encode()


def _unit(name: str, spec: dict[str, Any]) -> bytes:
    return f"""[Unit]
Description=MycoMesh dynamic V10 {name} Pool blue-green candidate
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mycomesh-mesh
Group=mycomesh-mesh
WorkingDirectory={REMOTE_ROOT}/data
ExecStart=/opt/mycomesh-mesh/venv/bin/python {POOL_RUNTIME_TEMPLATE.format(name=name)}
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


def _health(client: Any, name: str, spec: dict[str, Any]) -> dict[str, Any]:
    rc, out, err = remote.execute(
        client,
        f"curl -fsS --max-time 20 http://127.0.0.1:{int(spec['candidate_port'])}/health",
        timeout=30,
    )
    if rc:
        logs = remote.execute(client, f"journalctl -u {shlex.quote(spec['candidate_unit'])} -n 40 --no-pager", timeout=20)
        raise RuntimeError(f"Pool candidate health failed: {remote.scrub(err)}\n{remote.scrub(logs[1])}")
    value = json.loads(out)
    if value.get("ok") is not True:
        raise RuntimeError("Pool candidate health returned ok=false")
    expected = "mycomesh-v10-dynamic-provider-ai-20260926-controlled-test"
    if value.get("expected_network_id") != expected:
        raise RuntimeError("Pool candidate reports the wrong network id")
    settlement = value.get("settlement")
    if not isinstance(settlement, dict) or str(settlement.get("contract", "")).lower() != str(json.loads(DEPLOYMENT.read_text())["settlement"]).lower():
        raise RuntimeError("Pool candidate reports the wrong Settlement contract")
    if int(value.get("authorized_provider_count", -1)) != len(PROVIDER_PUBLIC_KEYS):
        raise RuntimeError("Pool candidate provider allowlist is incomplete")
    if int(value.get("authorized_reputation_signer_count", -1)) != 1:
        raise RuntimeError("Pool candidate reputation signer policy is not explicit")
    return value


def _stage(name: str, *, start: bool) -> dict[str, Any]:
    spec = POOL_SPECS[name]
    client = remote.connect(name)
    try:
        rc, out, err = remote.execute(client, f"systemctl is-active -- {shlex.quote(spec['candidate_unit'])}", timeout=15)
        if rc == 0 and out.strip() == "active":
            raise RuntimeError("Pool candidate is already active; refusing to overwrite it")
        for path in (REMOTE_RELEASE, f"{REMOTE_ROOT}/config", f"{REMOTE_ROOT}/data", f"{REMOTE_ROOT}/config/ca-bundle.crt"):
            rc, _, err = remote.execute(client, f"test -e {shlex.quote(path)}", timeout=15)
            if rc:
                raise RuntimeError(f"required staged path is missing: {path}: {remote.scrub(err)}")
        node = _node(name, spec)
        _remote_write(client, POOL_NODE_TEMPLATE.format(name=name), _json_bytes(node), 0o600)
        _remote_write(client, POOL_RUNTIME_TEMPLATE.format(name=name), _runtime(name), 0o700)
        _remote_write(client, f"/etc/systemd/system/{spec['candidate_unit']}", _unit(name, spec), 0o644)
        rc, _, err = remote.execute(
            client,
            f"chown mycomesh-mesh:mycomesh-mesh -- {shlex.quote(POOL_NODE_TEMPLATE.format(name=name))} {shlex.quote(POOL_RUNTIME_TEMPLATE.format(name=name))} && "
            f"chmod 0600 -- {shlex.quote(POOL_NODE_TEMPLATE.format(name=name))} && chmod 0700 -- {shlex.quote(POOL_RUNTIME_TEMPLATE.format(name=name))} && "
            "systemctl daemon-reload",
            timeout=30,
        )
        if rc:
            raise RuntimeError(f"Pool candidate ownership/systemd staging failed: {remote.scrub(err)}")
        if start:
            rc, _, err = remote.execute(client, f"systemctl start -- {shlex.quote(spec['candidate_unit'])}", timeout=60)
            if rc:
                logs = remote.execute(client, f"journalctl -u {shlex.quote(spec['candidate_unit'])} -n 50 --no-pager", timeout=20)
                raise RuntimeError(f"Pool candidate start failed: {remote.scrub(err)}\n{remote.scrub(logs[1])}")
            health = _health(client, name, spec)
        else:
            health = None
        return {"node": name, "role": "pool", "release": RELEASE_ID, "candidate_port": spec["candidate_port"], "started": start, "health": health}
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(POOL_SPECS))
    parser.add_argument("--no-start", action="store_true")
    parser.add_argument("--health", action="store_true")
    args = parser.parse_args()
    names = args.node or ["relay1", "relay3"]
    results = []
    for name in names:
        try:
            if args.health:
                client = remote.connect(name)
                try:
                    results.append({"node": name, "role": "pool", "health": _health(client, name, POOL_SPECS[name])})
                finally:
                    _close(client)
            else:
                results.append(_stage(name, start=not args.no_start))
            print(json.dumps(results[-1], sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "role": "pool", "error": remote.scrub(str(exc))}, sort_keys=True))
    return 0 if len(results) == len(names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
