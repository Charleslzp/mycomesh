#!/usr/bin/env python3
"""Roll one Git commit of the gateway source onto the dynamic-V10 mesh.

Every node runs source from ``/opt/mycomesh-mesh/releases/<release>/gateway``.
This command ships the exact ``git archive`` of a committed revision (never
the working tree), verifies its digest on the host, and switches one node at a
time:

* ``relay``: repoints ``node-production.json`` at the new release and restarts
  the production unit; the loopback health gate must pass.
* ``provider``: recreates the Provider container from its own ``docker
  inspect`` document with only the ``/app/gateway`` bind changed, then waits for
  the container, the Bridge lease, and its signer on the public Relays.

A failed gate restores the previous node file or container before returning.
Each run leaves a remote journal with hashes, names, and phases; no private
material is read or printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402


RELEASES = "/opt/mycomesh-mesh/releases"
RELEASE_PREFIX = "v10-dynamic-provider-ai-20260926"
REMOTE_ROOT = "/opt/mycomesh-v10-dynamic-20260926"
NODE_PATH = f"{REMOTE_ROOT}/config/node-production.json"
RELAY_UNITS = {
    "relay1": "mycomesh-v10-dynamic-relay1.service",
    "relay3": "mycomesh-v10-dynamic-relay3.service",
}
RELAY_HEALTH_PORT = 11090
PROVIDER_CONTAINERS = {
    "provider1": "mycomesh-provider-1",
    "provider2": "mycomesh-v10-test-provider",
    "provider3": "mycomesh-v10-test-provider",
    "provider4": "mycomesh-v10-test-provider",
}
NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
CA_FILE = ROOT / "packages/mycomesh-cli/networks/v10-dynamic-20260926.ca.crt"
GATEWAY_MOUNT = "/app/gateway"
DOCKER_CREATE = r'''
import http.client, json, socket, sys
class Unix(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/var/run/docker.sock")
body = open(sys.argv[1], "rb").read()
conn = Unix("localhost")
conn.request("POST", "/containers/create?name=" + sys.argv[2], body, {"Content-Type": "application/json"})
response = conn.getresponse()
payload = response.read().decode()
print(payload)
sys.exit(0 if response.status == 201 else 1)
'''


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


def _write(client: Any, path: str, data: bytes, mode: int = 0o600) -> None:
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def _archive(commit: str) -> tuple[str, bytes, str]:
    resolved = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", f"{commit}^{{commit}}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    data = subprocess.run(
        ["git", "-C", str(ROOT), "archive", "--format=tar.gz", resolved, "gateway"],
        check=True, capture_output=True,
    ).stdout
    return resolved, data, hashlib.sha256(data).hexdigest()


def _stage(client: Any, release: str, data: bytes, digest: str) -> str:
    """Upload and unpack one release idempotently; return its gateway path."""
    target = f"{RELEASES}/{release}"
    archive = f"{target}.tar.gz"
    marker = f"{target}/.archive-sha256"
    rc, out, _ = remote.execute(client, f"cat -- {shlex.quote(marker)}", timeout=20)
    if rc == 0 and out.strip() == digest:
        return f"{target}/gateway"
    rc, _, _ = remote.execute(client, f"test -e {shlex.quote(target)}", timeout=20)
    if rc == 0:
        raise RuntimeError(f"{target} exists without the expected archive digest")
    _write(client, archive, data, 0o644)
    observed = _run(client, f"sha256sum -- {shlex.quote(archive)}", timeout=30).split()[0]
    if observed != digest:
        raise RuntimeError("uploaded release archive digest mismatch")
    _run(
        client,
        f"mkdir -m 0755 -- {shlex.quote(target)} && "
        f"tar -xzf {shlex.quote(archive)} -C {shlex.quote(target)} --no-same-owner && "
        f"chmod -R u=rwX,go=rX -- {shlex.quote(target)} && "
        f"printf %s {shlex.quote(digest)} > {shlex.quote(marker)}",
        timeout=90,
    )
    return f"{target}/gateway"


def _journal(client: Any, directory: str, name: str, value: Any) -> None:
    _write(client, f"{directory}/{name}", (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def _relay_health(client: Any, deadline_seconds: int = 180) -> dict[str, Any]:
    deadline = time.monotonic() + deadline_seconds
    last = "health probe did not run"
    while time.monotonic() < deadline:
        rc, out, err = remote.execute(
            client,
            f"curl -fsS --max-time 20 http://127.0.0.1:{RELAY_HEALTH_PORT}/health",
            timeout=30,
        )
        if rc == 0:
            try:
                value = json.loads(out)
                v10 = value.get("v10") or {}
                if (
                    value.get("ok") is True
                    and value.get("settlement_ready") is True
                    and v10.get("enabled") is True
                    and (value.get("provider_ai_jury_intake") or {}).get("ready") is True
                ):
                    return {
                        "providers": value.get("providers"),
                        "settlement_ready": True,
                        "monetary_ready": (value.get("provider_ai_jury_runtime") or {}).get("monetary_ready"),
                    }
                last = "health gate is not open yet"
            except (ValueError, TypeError, AttributeError) as exc:
                last = f"health parse failed: {exc}"
        else:
            last = remote.scrub(err or out).strip()[-400:] or last
        time.sleep(3)
    raise RuntimeError(f"Relay health gate failed: {last}")


def deploy_relay(node: str, commit: str, *, dry_run: bool) -> dict[str, Any]:
    resolved, data, digest = _archive(commit)
    release = f"{RELEASE_PREFIX}-{resolved[:8]}"
    unit = RELAY_UNITS[node]
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    rollback = f"{REMOTE_ROOT}/rollback/release-{release}-{stamp}"
    client = remote.connect(node)
    try:
        if _run(client, f"systemctl is-active -- {shlex.quote(unit)}", timeout=20).strip() != "active":
            raise RuntimeError(f"{unit} is not active; refusing to deploy")
        old_node = _read(client, NODE_PATH)
        node_config = json.loads(old_node)
        previous = str(node_config.get("candidate") or "")
        result: dict[str, Any] = {
            "node": node, "commit": resolved, "release": release,
            "archive_sha256": digest, "previous": previous, "dry_run": dry_run,
        }
        target = f"{RELEASES}/{release}"
        if previous == target:
            result["changed"] = False
            result["health"] = _relay_health(client)
            return result
        if dry_run:
            return result
        _stage(client, release, data, digest)
        # Rewriting the existing file in place keeps its owner; keep its mode.
        mode = int(_run(client, f"stat -c %a -- {shlex.quote(NODE_PATH)}", timeout=20).strip(), 8)
        _run(client, f"mkdir -m 0700 -p -- {shlex.quote(rollback)}", timeout=20)
        _write(client, f"{rollback}/node-production.json", old_node, 0o600)
        _journal(client, rollback, "journal.json", {**result, "phase": "switching"})
        node_config["candidate"] = target
        node_config["bundle_id"] = release
        _write(client, NODE_PATH, (json.dumps(node_config, indent=2, sort_keys=True) + "\n").encode(), mode)
        try:
            _run(client, f"systemctl restart -- {shlex.quote(unit)}", timeout=90)
            result["health"] = _relay_health(client)
        except Exception as exc:
            _write(client, NODE_PATH, old_node, mode)
            _run(client, f"systemctl restart -- {shlex.quote(unit)}", timeout=90)
            _journal(client, rollback, "journal.json", {**result, "phase": "rolled_back", "error": remote.scrub(str(exc))})
            raise RuntimeError(f"{node} rolled back to {previous}: {remote.scrub(str(exc))}") from exc
        result["changed"] = True
        result["rollback"] = rollback
        _journal(client, rollback, "journal.json", {**result, "phase": "complete"})
        return result
    finally:
        _close(client)


def _create_body(inspected: dict[str, Any], gateway_source: str) -> dict[str, Any]:
    config = dict(inspected["Config"])
    host = dict(inspected["HostConfig"])
    binds = list(host.get("Binds") or [])
    replaced = []
    for bind in binds:
        source, _, rest = bind.partition(":")
        destination = rest.split(":", 1)[0]
        replaced.append(f"{gateway_source}:{rest}" if destination == GATEWAY_MOUNT else bind)
    if sum(1 for bind in binds if bind.partition(":")[2].split(":", 1)[0] == GATEWAY_MOUNT) != 1:
        raise RuntimeError("Provider container must have exactly one /app/gateway bind")
    host["Binds"] = replaced
    networks = (inspected.get("NetworkSettings") or {}).get("Networks") or {}
    short_id = str(inspected.get("Id") or "")[:12]
    endpoints = {}
    for name, value in networks.items():
        aliases = [alias for alias in (value.get("Aliases") or []) if alias != short_id]
        endpoints[name] = {"Aliases": aliases} if aliases else {}
    body = {
        key: config[key]
        for key in (
            "User", "Env", "Cmd", "Entrypoint", "WorkingDir", "Labels",
            "ExposedPorts", "Healthcheck", "StopSignal", "StopTimeout", "Tty",
            "OpenStdin", "Volumes",
        )
        if config.get(key) is not None
    }
    # Pin the exact image the old container ran, not a mutable tag.
    body["Image"] = inspected["Image"]
    body["HostConfig"] = host
    body["NetworkingConfig"] = {"EndpointsConfig": endpoints}
    return body


def _provider_signers() -> dict[str, list[str]]:
    network = json.loads(NETWORK.read_text(encoding="utf-8"))
    urls = [network["relay"]["public_url"], *[item["public_url"] for item in network.get("relay_fallbacks", [])]]
    context = ssl.create_default_context(cafile=str(CA_FILE))
    signers: dict[str, list[str]] = {}
    for url in urls:
        try:
            with urllib.request.urlopen(f"{url}/relay/health", timeout=25, context=context) as response:
                value = json.loads(response.read())
            signers[url] = [str(item).lower() for item in (value.get("v10") or {}).get("provider_signers") or []]
        except (OSError, ValueError) as exc:
            signers[url] = [f"unavailable:{type(exc).__name__}"]
    return signers


def _provider_gate(client: Any, container: str, signer: str | None, deadline_seconds: int = 240) -> dict[str, Any]:
    deadline = time.monotonic() + deadline_seconds
    last = "not started"
    lease = False
    while time.monotonic() < deadline:
        state = _run(client, f"docker inspect --format '{{{{.State.Running}}}}|{{{{.State.Status}}}}|{{{{.RestartCount}}}}' -- {shlex.quote(container)}", timeout=20).strip()
        running, status, restarts = state.split("|")
        if running != "true":
            if status in {"exited", "dead"}:
                raise RuntimeError(f"new Provider container stopped: {status}")
            last = f"Provider is {status}"
        elif not lease:
            rc, out, err = remote.execute(
                client,
                f"docker exec -- {shlex.quote(container)} python -m gateway.provider_bootstrap "
                "--network-config /candidate/network.json --require-bridge-lease",
                timeout=40,
            )
            lease = rc == 0
            last = "Bridge lease pending" if not lease else last
        if lease:
            if signer is None:
                return {"running": True, "lease": True, "restarts": int(restarts)}
            relays = _provider_signers()
            if all(signer in values for values in relays.values()):
                return {"running": True, "lease": True, "restarts": int(restarts), "relays": sorted(relays)}
            last = f"signer not yet on every Relay: {relays}"
        time.sleep(5)
    raise RuntimeError(f"Provider gate failed: {last}")


def deploy_provider(node: str, commit: str, *, dry_run: bool, require_all_relays: bool) -> dict[str, Any]:
    resolved, data, digest = _archive(commit)
    release = f"{RELEASE_PREFIX}-{resolved[:8]}"
    container = PROVIDER_CONTAINERS[node]
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    rollback = f"{REMOTE_ROOT}/rollback/release-{release}-{stamp}"
    previous_name = f"{container}.pre-{resolved[:8]}-{stamp}"
    client = remote.connect(node)
    try:
        inspected = json.loads(_run(client, f"docker inspect -- {shlex.quote(container)}", timeout=30))[0]
        if (inspected.get("State") or {}).get("Running") is not True:
            raise RuntimeError(f"{container} is not running; refusing to deploy")
        gateway_source = f"{RELEASES}/{release}/gateway"
        current = [
            bind.partition(":")[0] for bind in inspected["HostConfig"].get("Binds") or []
            if bind.partition(":")[2].split(":", 1)[0] == GATEWAY_MOUNT
        ]
        signer = None
        if require_all_relays:
            # Print only the public address; the identity file holds a key.
            signer = _run(
                client,
                f"docker exec -- {shlex.quote(container)} python -c "
                + shlex.quote("import json;print(json.load(open('/data/provider-evm-identity.json'))['address'])"),
                timeout=20,
            ).strip().lower() or None
        result: dict[str, Any] = {
            "node": node, "container": container, "commit": resolved, "release": release,
            "archive_sha256": digest, "previous_gateway": current, "image": inspected["Image"],
            "signer": signer, "dry_run": dry_run,
        }
        if current == [gateway_source]:
            result["changed"] = False
            result["gate"] = _provider_gate(client, container, signer)
            return result
        body = _create_body(inspected, gateway_source)
        if dry_run:
            result["binds"] = body["HostConfig"]["Binds"]
            return result
        _stage(client, release, data, digest)
        _run(client, f"mkdir -m 0700 -p -- {shlex.quote(rollback)}", timeout=20)
        _write(client, f"{rollback}/container-inspect.json", json.dumps(inspected).encode(), 0o600)
        _write(client, f"{rollback}/create-body.json", json.dumps(body).encode(), 0o600)
        _write(client, f"{rollback}/docker-create.py", DOCKER_CREATE.encode(), 0o600)
        _journal(client, rollback, "journal.json", {**result, "phase": "recreating", "previous_name": previous_name})
        _run(client, f"docker rename -- {shlex.quote(container)} {shlex.quote(previous_name)}", timeout=20)
        created = False
        try:
            _run(client, f"python3 {shlex.quote(rollback + '/docker-create.py')} {shlex.quote(rollback + '/create-body.json')} {shlex.quote(container)}", timeout=60)
            created = True
            _run(client, f"docker stop --time 35 -- {shlex.quote(previous_name)}", timeout=60)
            _run(client, f"docker start -- {shlex.quote(container)}", timeout=60)
            result["gate"] = _provider_gate(client, container, signer)
        except Exception as exc:
            if created:
                remote.execute(client, f"docker stop --time 10 -- {shlex.quote(container)}", timeout=40)
                remote.execute(client, f"docker rename -- {shlex.quote(container)} {shlex.quote(container + '.failed-' + stamp)}", timeout=20)
            _run(client, f"docker rename -- {shlex.quote(previous_name)} {shlex.quote(container)} && "
                         f"docker start -- {shlex.quote(container)}", timeout=60)
            _journal(client, rollback, "journal.json", {**result, "phase": "rolled_back", "error": remote.scrub(str(exc))})
            raise RuntimeError(f"{node} rolled back to its previous container: {remote.scrub(str(exc))}") from exc
        result["changed"] = True
        result["previous_container"] = previous_name
        result["rollback"] = rollback
        _journal(client, rollback, "journal.json", {**result, "phase": "complete"})
        return result
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("role", choices=("relay", "provider"))
    parser.add_argument("--node", action="append", required=True)
    parser.add_argument("--commit", required=True, help="Committed revision to deploy (e.g. origin/main).")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--require-all-relays", action="store_true",
        help="Provider gate also requires its signer on every pinned public Relay.",
    )
    args = parser.parse_args()
    allowed = RELAY_UNITS if args.role == "relay" else PROVIDER_CONTAINERS
    for node in args.node:
        if node not in allowed:
            parser.error(f"unknown {args.role} node: {node}")
    for node in args.node:
        try:
            if args.role == "relay":
                result = deploy_relay(node, args.commit, dry_run=args.dry_run)
            else:
                result = deploy_provider(
                    node, args.commit, dry_run=args.dry_run,
                    require_all_relays=args.require_all_relays,
                )
            print(json.dumps(result, sort_keys=True), flush=True)
        except Exception as exc:
            print(json.dumps({"node": node, "error": remote.scrub(str(exc))}, sort_keys=True), flush=True)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
