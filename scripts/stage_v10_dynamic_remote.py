#!/usr/bin/env python3
"""Stage and start blue/green candidates for the dynamic V10 mesh.

The command uses a new remote root and alternate loopback ports. It never
stops or renames the currently running controlled-test services.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402

from gateway import chain  # noqa: E402
from gateway.identity import peer_id_from_public_key, public_key_from_private_key  # noqa: E402


NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
DEPLOYMENT = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
POLICY = ROOT / "deployments/provider-jury-policy-v1.json"
ROLES = ROOT / ".mycomesh/v10/roles"
RELEASE_ID = "v10-dynamic-provider-ai-20260926-f311cba9"
REMOTE_RELEASE = f"/opt/mycomesh-mesh/releases/{RELEASE_ID}"
ARCHIVE_LOCAL = ROOT / ".codex-run/mesh/v10-dynamic-provider-jury-20260923" / f"{RELEASE_ID}.tar.gz"
REMOTE_ARCHIVE = f"/opt/mycomesh-mesh/releases/{RELEASE_ID}.tar.gz"
REMOTE_ROOT = "/opt/mycomesh-v10-dynamic-20260926"
OLD_ROOT = "/opt/mycomesh-v10-fixed-budget-20260918"
RPC = "https://rpc.sepolia.ethpandaops.io"
CHAIN_ID = 11155111
PAYMENT_ADDRESS = "0x80a9337a3c37eeffad65031e6c2a89c820b14fe3"
ATTESTATION_ADDRESS = "0x684114a7d8cbb51fad3de5b0597c2938c25ce8f4"
CONSUMER_REQUEST_PUBLIC_KEY = "522c1e23ab696b36a81d03e666096b90d199607245d3d5931ea625bf5e89ea3a"
GENESIS_HASH = "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"

# Existing Provider node identities are preserved by the volume-backed
# provider cutover, so these signed transport keys remain stable.
PROVIDER_PUBLIC_KEYS = (
    "c068ce33519f24b478fc1fce163ddd14916b349152b5d7b1d2fcfe3029c383f1",
    "3b86350fce27833e3a11d9367046b878bdfeb485a5342660a15322f4124591be",
    "e20404900d276400b0b8fc9ad5f871584b5bb8c8e6bcb0834300f47e72abe973",
    "f213c56971c62126e5b137adbc0923193494c9cfd753b277f8da145a4c9abbd5",
)

NODES: dict[str, dict[str, Any]] = {
    "relay1": {
        "host": "136.0.3.126", "role": "relay",
        "candidate_unit": "mycomesh-v10-dynamic-relay1-candidate.service",
        "control_port": 11190, "provider_port": 12191,
        "jury_key_role": "jury-executor-relay",
        "jury_public_key": "ec4245fbdf4ca146878df705317ff7d48eea6a37a036357041631c1341268bd2",
        "submitter_old": f"{OLD_ROOT}/config/submitter.key",
    },
    "relay3": {
        "host": "166.88.96.60", "role": "relay",
        "candidate_unit": "mycomesh-v10-dynamic-relay3-candidate.service",
        "control_port": 11193, "provider_port": 12194,
        "jury_key_role": "jury-executor-bridge",
        "jury_public_key": "32ae49e6e49e303b268ea5236ab5650c4780c2f63514999f082e60dec1c78af7",
        "submitter_old": f"{OLD_ROOT}/config/submitter.key",
    },
    "bridge1": {
        "host": "166.88.209.61", "role": "bridge",
        "candidate_unit": "mycomesh-v10-dynamic-bridge1-candidate.service",
        "port": 11180,
    },
    "bridge2": {
        "host": "216.173.64.214", "role": "bridge",
        "candidate_unit": "mycomesh-v10-dynamic-bridge2-candidate.service",
        "port": 11182,
    },
}


def _read_private(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError(f"unsafe private key file: {path}")
    raw = path.read_text(encoding="ascii").strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    value = bytes.fromhex(raw)
    if len(value) != 32:
        raise RuntimeError(f"invalid private key file: {path}")
    return value


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _make_archive() -> tuple[Path, str]:
    ARCHIVE_LOCAL.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(ARCHIVE_LOCAL, "w:gz") as archive:
        archive.add(ROOT / "gateway", arcname="gateway", recursive=True)
    digest = hashlib.sha256(ARCHIVE_LOCAL.read_bytes()).hexdigest()
    os.chmod(ARCHIVE_LOCAL, 0o600)
    return ARCHIVE_LOCAL, digest


def _jury_identity_payload(role: str) -> bytes:
    private = _read_private(ROLES / f"jury-relay-ed25519-{role}.key")
    public = public_key_from_private_key(private.hex())
    return _json_bytes({
        "private_key": private.hex(), "public_key": public,
        "peer_id": peer_id_from_public_key(public),
    })


def _evm_identity_payload(role: str) -> bytes:
    private = _read_private(ROLES / f"{role}.key")
    address = chain.private_key_to_address(private)
    return _json_bytes({
        "schema_version": 1, "address": address,
        "private_key": "0x" + private.hex(),
    })


def _node_payload(name: str, spec: dict[str, Any], *, candidate: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    network = json.loads(NETWORK.read_text(encoding="utf-8"))
    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    root, data, public = REMOTE_ROOT, f"{REMOTE_ROOT}/data", f"{REMOTE_ROOT}/config/public"
    env: dict[str, str] = {
        "MYCOMESH_ALLOW_CONTROLLED_V10_TEST": "1",
        "MYCOMESH_BACKEND_POLICY": str(deployment["backend_policy"]),
        "MYCOMESH_CHANNEL": str(deployment["channel"]),
        "MYCOMESH_CHANNEL_ID": str(deployment["channel_id"]),
        "MYCOMESH_NETWORK_ID": str(deployment["network_id"]),
        "MYCOMESH_NETWORK_PROFILE": "testnet",
        "MYCOMESH_SETTLEMENT_VERSION": "10",
        "MYCO_DEPLOYMENT": f"{public}/sepolia-myco-v10-dynamic-20260926.json",
        "PUBLIC_MODEL_ID": str(network["public_model_id"]),
        "PUBLIC_MODEL_IDS": ",".join(network["public_model_ids"]),
        "MYCOMESH_SETTLEMENT_RPC_URL": RPC,
        "ETH_RPC_URL": ",".join(network["settlement_rpc_urls"]),
    }
    files: dict[str, bytes] = {
        f"{public}/network.json": NETWORK.read_bytes(),
        f"{public}/deployment.json": DEPLOYMENT.read_bytes(),
        f"{public}/sepolia-myco-v10-dynamic-20260926.json": DEPLOYMENT.read_bytes(),
        f"{root}/config/provider-jury-policy-v1.json": POLICY.read_bytes(),
    }
    if spec["role"] == "relay":
        args = [
            "relay", "serve", "--host", "127.0.0.1",
            "--control-port", str(spec["control_port"]),
            "--provider-port", str(spec["provider_port"]),
            "--advertise-host", str(spec["host"]),
            "--advertise-control-port", "10443", "--advertise-provider-port", "10991",
            "--network-profile", "testnet", "--settlement-version", "10",
            "--consumer-public-key", CONSUMER_REQUEST_PUBLIC_KEY,
            "--payment-address", PAYMENT_ADDRESS,
            "--attestation-identity", f"{data}/attestation-identity.json",
            "--trust-proxy-headers", "--settlement-interval-seconds", "7200",
            "--settlement-count-threshold", "100", "--settlement-batch-size", "32",
            "--network-config", f"{public}/network.json",
            "--jury-identity", f"{root}/config/jury-relay.json",
            "--jury-expected-public-key", str(spec["jury_public_key"]),
            "--provider-jury-runtime-enabled", "--no-provider-jury-execution-enabled",
            "--provider-jury-rpc-url", RPC,
            "--provider-jury-policy", f"{root}/config/provider-jury-policy-v1.json",
            "--provider-jury-worker-db", f"{data}/provider-jury-worker.sqlite3",
            "--provider-jury-transaction-db", f"{data}/provider-jury-transaction.sqlite3",
            "--provider-jury-intake-db", f"{data}/provider-jury-intake.sqlite3",
            "--provider-jury-intake-poll-seconds", "5", "--provider-jury-rpc-timeout-seconds", "20",
            "--settlement-chain-id", str(CHAIN_ID), "--settlement-contract", str(deployment["settlement"]),
            "--settlement-db-path", f"{data}/relay-settlement.sqlite3",
        ]
        env.update({
            "MYCOMESH_RELAY_SETTLEMENT_RPC_URL": RPC,
            "MYCOMESH_RELAY_SETTLEMENT_CHAIN_ID": str(CHAIN_ID),
            "MYCOMESH_RELAY_SETTLEMENT_CONTRACT": str(deployment["settlement"]),
            "MYCOMESH_RELAY_SETTLEMENT_VERSION": "10",
            "MYCOMESH_RELAY_SETTLEMENT_DB": f"{data}/relay-settlement.sqlite3",
            "MYCOMESH_REPLAY_DB": f"{data}/relay-replay.sqlite3",
            "MYCOMESH_RELAY_PROVIDER_PUBLIC_KEYS": ",".join(PROVIDER_PUBLIC_KEYS),
            "MYCOMESH_RELAY_SETTLEMENT_BATCH_SIZE": "32",
            "MYCOMESH_RELAY_SETTLEMENT_COUNT_THRESHOLD": "100",
            "MYCOMESH_RELAY_SETTLEMENT_INTERVAL_SECONDS": "7200",
        })
        files[f"{root}/config/jury-relay.json"] = _jury_identity_payload(str(spec["jury_key_role"]))
        files[f"{data}/attestation-identity.json"] = _evm_identity_payload("bridge")
    else:
        args = [
            "bridge", "serve", "--host", "127.0.0.1", "--port", str(spec["port"]),
            "--public-url", f"https://{spec['host']}:10443", "--network-profile", "testnet",
            "--require-provider-backend-metadata", "--trust-proxy-headers",
            "--trusted-relay-origin", "https://136.0.3.126:10443",
            "--trusted-relay-origin", "https://166.88.96.60:10443",
        ]
        for key in PROVIDER_PUBLIC_KEYS:
            args += ["--provider-public-key", key]
        args += [
            "--reputation-signer-public-key", "96aa8c50ce03d57187e8cc4af216d44a21fb7dc64d7fcbcf4aa832d74e50fa56",
            "--reputation-rpc-url", RPC, "--reputation-genesis-hash", GENESIS_HASH,
        ]
    node: dict[str, Any] = {
        "node": name, "role": spec["role"], "root": root,
        "candidate": candidate, "bundle_id": RELEASE_ID,
        "public_url": f"https://{spec['host']}:10443", "env": env, "argv": args,
    }
    if spec["role"] == "relay":
        node["submitter_source"] = spec["submitter_old"]
    return node, files


RUNTIME_TEMPLATE = '''import json, os, sys\nfrom pathlib import Path\nROOT = Path({root!r})\nC = json.loads((ROOT / "config/node.json").read_text())\nsys.path.insert(0, C["candidate"])\nos.environ.update(C["env"])\nos.environ.update(PYTHONPATH=C["candidate"], PYTHONDONTWRITEBYTECODE="1", SSL_CERT_FILE=str(ROOT / "config/ca-bundle.crt"), REQUESTS_CA_BUNDLE=str(ROOT / "config/ca-bundle.crt"))\nos.chdir(ROOT / "data")\nif C["role"] == "relay":\n    from gateway.chain import parse_private_key, private_key_to_address\n    key = (ROOT / "config/submitter.key").read_text().strip()\n    assert private_key_to_address(parse_private_key(key)) == C["submitter"]\n    os.environ["MYCOMESH_RELAY_SETTLEMENT_PRIVATE_KEY"] = key\nfrom gateway.client import main\nraise SystemExit(main(C["argv"]))\n'''


def _unit(name: str) -> str:
    return f"""[Unit]
Description=MycoMesh dynamic V10 {name} blue-green candidate
After=network-online.target

[Service]
Type=simple
User=mycomesh-mesh
Group=mycomesh-mesh
WorkingDirectory={REMOTE_ROOT}/data
ExecStart=/opt/mycomesh-mesh/venv/bin/python {REMOTE_ROOT}/runtime.py
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
"""


def _remote_write(c: Any, path: str, data: bytes, mode: int = 0o600) -> None:
    parent = str(Path(path).parent)
    rc, _, err = remote.execute(c, f"mkdir -p -- {parent}", timeout=20)
    if rc:
        raise RuntimeError(f"remote mkdir failed: {remote.scrub(err)}")
    with c.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def _remote_stage(name: str, spec: dict[str, Any], archive: Path, digest: str, *, start: bool) -> dict[str, Any]:
    c = remote.connect(name)
    try:
        rc, out, err = remote.execute(c, f"systemctl is-active -- {spec['candidate_unit']}", timeout=15)
        if rc == 0 and out.strip() == "active":
            raise RuntimeError("candidate is already active; refusing to overwrite its live config")
        node, files = _node_payload(name, spec, candidate=REMOTE_RELEASE)
        rc, _, err = remote.execute(c, f"mkdir -p -- {REMOTE_RELEASE} {REMOTE_ROOT}/config/public {REMOTE_ROOT}/data", timeout=20)
        if rc:
            raise RuntimeError(f"remote directory staging failed: {remote.scrub(err)}")
        with c.open_sftp() as sftp:
            sftp.put(str(archive), REMOTE_ARCHIVE)
            sftp.chmod(REMOTE_ARCHIVE, 0o644)
        rc, out, err = remote.execute(c, f"sha256sum -- {REMOTE_ARCHIVE}", timeout=30)
        if rc or not out.splitlines() or out.splitlines()[0].split()[0] != digest:
            raise RuntimeError(f"remote release digest mismatch: {remote.scrub(err)}")
        rc, _, err = remote.execute(c, f"tar -xzf {REMOTE_ARCHIVE} -C {REMOTE_RELEASE} --no-same-owner", timeout=90)
        if rc:
            raise RuntimeError(f"remote release extraction failed: {remote.scrub(err)}")
        rc, _, err = remote.execute(c, f"install -m 0644 -- {OLD_ROOT}/config/ca-bundle.crt {REMOTE_ROOT}/config/ca-bundle.crt", timeout=20)
        if rc:
            raise RuntimeError(f"remote CA staging failed: {remote.scrub(err)}")
        if spec["role"] == "relay":
            rc, _, err = remote.execute(c, f"install -m 0600 -- {spec['submitter_old']} {REMOTE_ROOT}/config/submitter.key", timeout=20)
            if rc:
                raise RuntimeError(f"remote submitter staging failed: {remote.scrub(err)}")
            rc, out, err = remote.execute(c, f"python3 -c 'import json; print(json.load(open(\"{OLD_ROOT}/config/node.json\"))[\"submitter\"])'", timeout=20)
            if rc:
                raise RuntimeError(f"remote submitter address read failed: {remote.scrub(err)}")
            node["submitter"] = out.strip()
        for path, data in files.items():
            protected = path.endswith("jury-relay.json") or path.endswith("attestation-identity.json")
            _remote_write(c, path, data, 0o600 if protected else 0o644)
        _remote_write(c, f"{REMOTE_ROOT}/config/node.json", _json_bytes(node), 0o600)
        _remote_write(c, f"{REMOTE_ROOT}/runtime.py", RUNTIME_TEMPLATE.format(root=REMOTE_ROOT).encode(), 0o755)
        _remote_write(c, f"/etc/systemd/system/{spec['candidate_unit']}", _unit(name).encode(), 0o644)
        rc, _, err = remote.execute(
            c,
            f"chown -R mycomesh-mesh:mycomesh-mesh -- {REMOTE_ROOT} && "
            f"chown -R root:root -- {REMOTE_RELEASE} && "
            f"chmod 0700 -- {REMOTE_ROOT}/data {REMOTE_ROOT}/config && "
            f"systemctl daemon-reload",
            timeout=45,
        )
        if rc:
            raise RuntimeError(f"remote ownership/systemd staging failed: {remote.scrub(err)}")
        if start:
            rc, _, err = remote.execute(c, f"systemctl start -- {spec['candidate_unit']}", timeout=60)
            if rc:
                logs = remote.execute(c, f"journalctl -u {spec['candidate_unit']} -n 40 --no-pager", timeout=20)
                raise RuntimeError(f"candidate start failed: {remote.scrub(err)}\n{remote.scrub(logs[1])}")
        return {"node": name, "role": spec["role"], "release": RELEASE_ID, "digest": digest, "started": start}
    finally:
        c.close()
        if getattr(c, "_mesh_jump", None):
            c._mesh_jump.close()


def _health(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    c = remote.connect(name)
    try:
        port = spec["control_port"] if spec["role"] == "relay" else spec["port"]
        rc, out, err = remote.execute(c, f"curl -fsS --max-time 20 http://127.0.0.1:{port}/health", timeout=30)
        if rc:
            logs = remote.execute(c, f"journalctl -u {spec['candidate_unit']} -n 40 --no-pager", timeout=20)
            raise RuntimeError(f"candidate health failed: {remote.scrub(err)}\n{remote.scrub(logs[1])}")
        value = json.loads(out)
        if value.get("ok") is not True:
            raise RuntimeError("candidate health returned ok=false")
        return value
    finally:
        c.close()
        if getattr(c, "_mesh_jump", None):
            c._mesh_jump.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(NODES), help="Stage one node; repeat. Defaults to all reachable candidates.")
    parser.add_argument("--no-start", action="store_true", help="Stage files but do not start candidate units.")
    parser.add_argument("--health", action="store_true", help="Only query already-started candidate health.")
    args = parser.parse_args()
    names = args.node or ["relay1", "relay3", "bridge1", "bridge2"]
    if args.health:
        for name in names:
            try:
                print(json.dumps({"node": name, "health": _health(name, NODES[name])}, sort_keys=True))
            except Exception as exc:
                print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
        return 0
    archive, digest = _make_archive()
    results = []
    for name in names:
        try:
            result = _remote_stage(name, NODES[name], archive, digest, start=not args.no_start)
            if not args.no_start:
                result["health"] = _health(name, NODES[name])
            results.append(result)
            print(json.dumps(result, sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
    return 0 if len(results) == len(names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
