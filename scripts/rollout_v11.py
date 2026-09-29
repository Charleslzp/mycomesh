#!/usr/bin/env python3
"""Roll one committed ``mycomesh/`` release onto the testnet hosts and retire V10.

  relay:    systemd ``mycomesh-v11-relay`` + ``mycomesh-v11-edge`` (nginx TLS on
            10443 for HTTP and 10991 for Provider links)
  bridge:   systemd ``mycomesh-v11-keeper``
  provider: docker ``mycomesh-v11-provider`` on the host's existing Codex image,
            reusing its ChatGPT-login CODEX_HOME

Every host gets the exact ``git archive`` of the commit (digest-checked), its
own role keys (0600), and the public network manifest. ``--cutover`` stops and
disables every pre-V11 MycoMesh unit and container on the host first. No
private material is printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402

BASE = "/opt/mycomesh-v11"
ROLES = ROOT / ".mycomesh/v11/roles"
NETWORK = ROOT / "deployments/mycomesh-v11-sepolia.network.json"
CA = ROOT / "deployments/mycomesh-testnet-ca.crt"
PYTHON = "/opt/mycomesh-mesh/venv/bin/python"
SERVICE_USER = "mycomesh-mesh"
PROVIDER_UID = 10001
CODEX_VOLUME = "/var/lib/docker/volumes/mycomesh_mycomesh-provider-codex-data/_data/codex-home"
PROVIDER_MODELS = ("gpt-5.5",)
# stablecoin units (6 decimals) per 1k tokens; Codex turns carry ~14k tokens of system context
PROVIDER_PRICES = {"input": 20, "output": 2_000, "min": 1_000}
HOSTS = {
    "relay1": "relay", "relay3": "relay",
    "bridge1": "bridge", "bridge2": "bridge",  # bridge3 is unreachable over SSH
    "provider1": "provider", "provider2": "provider", "provider3": "provider", "provider4": "provider",
}

NGINX = """load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user {user};
worker_processes 1;
pid {base}/data/nginx.pid;
error_log stderr warn;
events {{ worker_connections 1024; }}
http {{
  access_log off; server_tokens off;
  client_body_temp_path {base}/data/nginx/client_body; proxy_temp_path {base}/data/nginx/proxy;
  server {{
    listen 10443 ssl; server_name {host};
    ssl_certificate /etc/mycomesh-mesh/node.crt; ssl_certificate_key /etc/mycomesh-mesh/node.key;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off;
    client_max_body_size 16m;
    location = /.well-known/mycomesh-network.json {{ alias {base}/config/network.json; default_type application/json; }}
    location / {{
      proxy_pass http://127.0.0.1:11100; proxy_http_version 1.1; proxy_set_header Host $http_host;
      proxy_set_header Connection ""; proxy_buffering off; proxy_next_upstream off; proxy_read_timeout 340s;
    }}
  }}
}}
stream {{
  server {{
    listen 10991 ssl;
    ssl_certificate /etc/mycomesh-mesh/node.crt; ssl_certificate_key /etc/mycomesh-mesh/node.key;
    ssl_protocols TLSv1.2 TLSv1.3; proxy_pass 127.0.0.1:11101; proxy_timeout 1d;
  }}
}}
"""

UNIT = """[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
User={user}
WorkingDirectory={base}/current
Environment=PYTHONPATH={base}/current PYTHONUNBUFFERED=1
ExecStart={exec}
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def run(client: Any, command: str, *, timeout: int = 120, check: bool = True) -> str:
    rc, out, err = remote.execute(client, command, timeout=timeout)
    if rc and check:
        raise RuntimeError(remote.scrub(err or out).strip()[-1200:])
    return out


def write(client: Any, path: str, data: bytes, mode: int = 0o600) -> None:
    with client.open_sftp() as sftp:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        sftp.chmod(path, mode)


def archive(commit: str) -> tuple[str, bytes, str]:
    resolved = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", f"{commit}^{{commit}}"],
                              check=True, capture_output=True, text=True).stdout.strip()
    data = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar.gz", resolved, "mycomesh"],
                          check=True, capture_output=True).stdout
    return resolved, data, hashlib.sha256(data).hexdigest()


def stage(client: Any, commit: str, data: bytes, digest: str, owner: str) -> None:
    """Unpack the release, point ``current`` at it, install network manifest and CA."""
    target = f"{BASE}/releases/{commit[:12]}"
    run(client, f"mkdir -p {BASE}/releases {BASE}/config {BASE}/keys {BASE}/data && chmod 0755 {BASE} {BASE}/releases {BASE}/config")
    write(client, f"{target}.tar.gz", data, 0o644)
    if run(client, f"sha256sum {target}.tar.gz").split()[0] != digest:
        raise RuntimeError("uploaded release digest mismatch")
    run(client, f"rm -rf {target} && mkdir -m 0755 {target} && tar -xzf {target}.tar.gz -C {target} --no-same-owner "
                f"&& chmod -R u=rwX,go=rX {target} && ln -sfn {target} {BASE}/current")
    write(client, f"{BASE}/config/network.json", NETWORK.read_bytes(), 0o644)
    write(client, f"{BASE}/config/{CA.name}", CA.read_bytes(), 0o644)
    run(client, f"chown -R {owner} {BASE}/keys {BASE}/data && chmod 0700 {BASE}/keys {BASE}/data")


def put_key(client: Any, name: str, remote_name: str, owner: str) -> None:
    path = f"{BASE}/keys/{remote_name}"
    write(client, path, (ROLES / name).read_bytes(), 0o600)
    run(client, f"chown {owner} {path}")


def cutover(client: Any, role: str) -> list[str]:
    """Stop and disable every pre-V11 MycoMesh unit and container; keep files for forensics."""
    units = [u for u in run(client, "systemctl list-units --all --type=service,timer --no-legend --plain | awk '{print $1}'").split()
             if u.startswith("mycomesh") and not u.startswith("mycomesh-v11")]
    if units:
        run(client, "systemctl disable --now " + " ".join(shlex.quote(u) for u in units), timeout=180)
    stopped = list(units)
    if role == "provider":
        names = [n for n in run(client, "docker ps --format '{{.Names}}'", check=False).split()
                 if n.startswith("mycomesh") and not n.startswith("mycomesh-v11")]
        if names:
            run(client, "docker update --restart=no " + " ".join(names) + " && docker stop " + " ".join(names), timeout=180)
        stopped += names
    return stopped


def install_unit(client: Any, name: str, description: str, command: str, user: str = SERVICE_USER) -> None:
    write(client, f"/etc/systemd/system/{name}.service",
          UNIT.format(description=description, user=user, base=BASE, exec=command).encode(), 0o644)
    run(client, f"systemctl daemon-reload && systemctl enable {name} && systemctl restart {name}")


def deploy_relay(client: Any, node: str) -> dict[str, Any]:
    host = json.loads((ROOT / "deployments/sepolia-myco-v11.json").read_text())["roles"]["relays"][node]["host"]
    put_key(client, f"{node}-owner.key", "owner.key", SERVICE_USER)
    put_key(client, f"{node}-signer.key", "signer.key", SERVICE_USER)
    run(client, f"mkdir -p {BASE}/data/nginx {BASE}/data/relay && chown -R {SERVICE_USER} {BASE}/data")
    write(client, f"{BASE}/config/nginx.conf", NGINX.format(user=SERVICE_USER, base=BASE, host=host).encode(), 0o644)
    run(client, f"openssl verify -CAfile {BASE}/config/{CA.name} /etc/mycomesh-mesh/node.crt && "
                f"nginx -t -p {BASE}/data/ -c {BASE}/config/nginx.conf")
    install_unit(client, "mycomesh-v11-relay", f"MycoMesh V11 Relay ({node})",
                 f"{PYTHON} -m mycomesh relay serve --network {BASE}/config/network.json --owner-key {BASE}/keys/owner.key "
                 f"--signer-key {BASE}/keys/signer.key --data-dir {BASE}/data/relay")
    write(client, "/etc/systemd/system/mycomesh-v11-edge.service", f"""[Unit]
Description=MycoMesh V11 TLS edge ({node})
After=network-online.target mycomesh-v11-relay.service

[Service]
ExecStart=/usr/sbin/nginx -p {BASE}/data/ -c {BASE}/config/nginx.conf -g "daemon off;"
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""".encode(), 0o644)
    run(client, "systemctl daemon-reload && systemctl enable mycomesh-v11-edge && systemctl restart mycomesh-v11-edge")
    deadline = time.monotonic() + 90
    while True:
        rc, out, _ = remote.execute(client, f"curl -sf --cacert {BASE}/config/{CA.name} https://{host}:10443/health", timeout=20)
        if rc == 0:
            return json.loads(out)
        if time.monotonic() > deadline:
            raise RuntimeError("relay health gate failed: " + run(client, "journalctl -u mycomesh-v11-relay -n 20 --no-pager", check=False)[-800:])
        time.sleep(3)


def deploy_bridge(client: Any, node: str) -> dict[str, Any]:
    put_key(client, f"{node}-keeper.key", "keeper.key", SERVICE_USER)
    run(client, f"id {SERVICE_USER} >/dev/null 2>&1 || useradd --system --home {BASE} --shell /usr/sbin/nologin {SERVICE_USER}")
    run(client, f"mkdir -p {BASE}/data/keeper && chown -R {SERVICE_USER} {BASE}/data")
    install_unit(client, "mycomesh-v11-keeper", f"MycoMesh V11 bridge keeper ({node})",
                 f"{PYTHON} -m mycomesh keeper serve --network {BASE}/config/network.json --key {BASE}/keys/keeper.key "
                 f"--data-dir {BASE}/data/keeper")
    time.sleep(8)
    return {"active": run(client, "systemctl is-active mycomesh-v11-keeper", check=False).strip(),
            "log": run(client, "journalctl -u mycomesh-v11-keeper -n 3 --no-pager -o cat", check=False).strip()[-400:]}


def deploy_provider(client: Any, node: str) -> dict[str, Any]:
    owner = f"{PROVIDER_UID}:{PROVIDER_UID}"
    put_key(client, f"{node}-signer.key", "signer.key", owner)
    put_key(client, f"{node}-identity.json", "identity.json", owner)
    run(client, f"mkdir -p {BASE}/data/provider && chown -R {owner} {BASE}/data")
    image = run(client, "docker inspect mycomesh-provider-sidecar-1 --format '{{.Image}}'").strip()
    run(client, f"test -f {CODEX_VOLUME}/auth.json")
    run(client, "docker rm -f mycomesh-v11-provider >/dev/null 2>&1 || true")
    command = [
        "python", "-m", "mycomesh", "provider", "serve", "--network", "/config/network.json",
        "--signer-key", "/keys/signer.key", "--identity", "/keys/identity.json", "--data-dir", "/data",
        "--backend", "codex", "--codex-home", "/codex", "--price-input", str(PROVIDER_PRICES["input"]),
        "--price-output", str(PROVIDER_PRICES["output"]), "--price-min", str(PROVIDER_PRICES["min"]),
    ]
    for model in PROVIDER_MODELS:
        command += ["--model", model]
    run(client, " ".join([
        "docker run -d --name mycomesh-v11-provider --restart unless-stopped",
        f"--user {owner} --workdir /app -e PYTHONPATH=/app -e PYTHONUNBUFFERED=1 -e HOME=/tmp",
        "--entrypoint python",
        f"-v {BASE}/current/mycomesh:/app/mycomesh:ro -v {BASE}/config:/config:ro -v {BASE}/keys:/keys:ro",
        f"-v {BASE}/data/provider:/data -v {CODEX_VOLUME}:/codex",
        "--log-opt max-size=20m --log-opt max-file=3",
        image, *[shlex.quote(part) for part in command[1:]],
    ]))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        logs = run(client, "docker logs --tail 5 mycomesh-v11-provider 2>&1", check=False)
        if "linking to" in logs:
            break
        time.sleep(3)
    return {"state": run(client, "docker inspect mycomesh-v11-provider --format '{{.State.Status}}'").strip(),
            "log": run(client, "docker logs --tail 3 mycomesh-v11-provider 2>&1", check=False).strip()[-400:]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--cutover", action="store_true", help="stop and disable all pre-V11 units/containers first")
    parser.add_argument("nodes", nargs="*", default=list(HOSTS))
    args = parser.parse_args()
    commit, data, digest = archive(args.commit)
    print(f"release {commit[:12]} sha256 {digest}")
    results = {}
    for node in args.nodes:
        role = HOSTS[node]
        client = remote.connect(node)
        try:
            stopped = cutover(client, role) if args.cutover else []
            owner = f"{PROVIDER_UID}:{PROVIDER_UID}" if role == "provider" else SERVICE_USER
            if role == "bridge":
                run(client, f"id {SERVICE_USER} >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin {SERVICE_USER}")
            stage(client, commit, data, digest, owner)
            result = {"relay": deploy_relay, "bridge": deploy_bridge, "provider": deploy_provider}[role](client, node)
            results[node] = {"role": role, "stopped": stopped, "result": result}
            print(json.dumps({node: results[node]}, default=str)[:1500])
        finally:
            client.close()
            if getattr(client, "_mesh_jump", None):
                client._mesh_jump.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
