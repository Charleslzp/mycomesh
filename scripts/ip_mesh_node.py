#!/usr/bin/env python3
"""Provision one IP-addressed, TLS-verified MycoMesh testnet node.

``init`` only generates configuration and identities; it never starts services,
changes the firewall, transfers funds, or modifies existing MycoMesh services.
Install Python dependencies, nginx + its stream module, and the certificates
before running it. Install the private CA on participating clients separately.
``--stage-only`` writes units under CONFIG/systemd without user/group changes.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


SERVICE_USER = "mycomesh-mesh"
ORIGINS = (
    "https://mycomesh.xyz", "https://app.mycomesh.xyz",
    "http://127.0.0.1:8110", "http://localhost:8110",
    "http://127.0.0.1:8111", "http://localhost:8111",
)


def absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 3:
        raise ValueError("Paths must be specific absolute directories without '..'")
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)):
        raise ValueError("Paths must contain only letters, digits, underscores, dots, slashes, and hyphens")
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError(f"Refusing symbolic link: {ancestor}")
    return path


def https_origins(value: str) -> list[str]:
    result = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "://" not in item:
            item = "https://" + item
        parsed = urlsplit(item)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.path or parsed.query or parsed.fragment
                or parsed.port not in (None, 443)):
            raise ValueError("Bridge/Relay addresses must be canonical HTTPS origins on port 443")
        if not re.fullmatch(r"[a-z0-9.-]+", parsed.hostname):
            raise ValueError("This IPv4 deployment supports public IPv4 addresses or DNS names")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if "." not in parsed.hostname:
                raise ValueError("A public hostname is required") from None
        else:
            if address.version != 4 or not address.is_global:
                raise ValueError("A globally routable IPv4 address is required")
        canonical = f"https://{parsed.hostname}"
        if item != canonical:
            raise ValueError("Bridge/Relay origins must omit :443 and trailing slashes")
        if canonical not in result:
            result.append(canonical)
    if not result:
        raise ValueError("At least one HTTPS origin is required")
    return result


def write_file(path: Path, content: str, mode: int = 0o644) -> None:
    """Atomic write, refusing symlinks and retaining the previous configuration."""
    absolute_path(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file():
            raise ValueError(f"Not a regular file: {path}")
        if path.read_text() == content:
            path.chmod(mode)
            return
        backup = path.with_name(path.name + ".before-ip-mesh")
        if not backup.exists():
            absolute_path(str(backup))
            shutil.copyfile(path, backup)
            backup.chmod(stat.S_IMODE(path.stat().st_mode))
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def nginx_config(config: dict, stream_module: str | None) -> str:
    directory = config["config_dir"]
    data = config["data_dir"]
    relay = config["role"] == "relay"
    tls = f"""ssl_certificate {directory}/node.crt;
        ssl_certificate_key {directory}/node.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_tickets off;"""
    proxy = """proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Connection "";
            proxy_connect_timeout 5s;
            proxy_read_timeout 300s;
            proxy_send_timeout 30s;
            proxy_buffering off;
            proxy_next_upstream off;"""
    if relay:
        # Signed V10 settlement envelopes exceed nginx's default 4 KiB header buffer.
        proxy += "\n            proxy_buffer_size 32k;\n            proxy_buffers 4 32k;\n            proxy_busy_buffers_size 64k;"
    role_locations = f"""
        location / {{
            proxy_pass http://127.0.0.1:{9900 if relay else 9800};
            {proxy}
        }}"""
    if relay:
        role_locations += f"""
        location = /relay/health {{
            limit_except GET {{ deny all; }}
            proxy_pass http://127.0.0.1:9900/health;
            {proxy}
        }}"""
    module = f"load_module {stream_module};\n" if relay and stream_module else ""
    stream = f"""
stream {{
    limit_conn_zone $binary_remote_addr zone=mesh_provider_connections:1m;
    server {{
        listen 9901 ssl;
        {tls}
        limit_conn mesh_provider_connections 8;
        proxy_connect_timeout 5s;
        proxy_timeout 1d;
        proxy_pass 127.0.0.1:19901;
    }}
}}
""" if relay else ""
    return f"""# Generated by ip_mesh_node.py; isolated from /etc/nginx/nginx.conf.
{module}user {SERVICE_USER};
worker_processes auto;
pid /run/mycomesh-ip-edge/nginx.pid;
error_log stderr warn;
events {{ worker_connections 1024; }}
http {{
    access_log off;
    server_tokens off;
    client_body_temp_path {data}/nginx/client_body;
    proxy_temp_path {data}/nginx/proxy;
    fastcgi_temp_path {data}/nginx/fastcgi;
    uwsgi_temp_path {data}/nginx/uwsgi;
    scgi_temp_path {data}/nginx/scgi;
    limit_req_zone $binary_remote_addr zone=mesh_http:1m rate=20r/s;
    limit_conn_zone $binary_remote_addr zone=mesh_http_connections:1m;
    server {{
        listen 443 ssl default_server;
        server_name {config['ip']};
        {tls}
        client_max_body_size 1m;
        client_body_timeout 15s;
        client_header_timeout 15s;
        keepalive_timeout 30s;
        limit_req zone=mesh_http burst=40 nodelay;
        limit_req_status 429;
        limit_conn mesh_http_connections 32;
        add_header X-Content-Type-Options nosniff always;
        location = /.well-known/mycomesh-network.json {{
            alias {directory}/public/network.json;
            default_type application/json;
            add_header Cache-Control "no-store";
        }}
        location = /.well-known/{config.get('deployment_name', 'sepolia-myco-v8.json')} {{
            alias {directory}/public/{config.get('deployment_name', 'sepolia-myco-v8.json')};
            default_type application/json;
        }}
        {role_locations}
    }}
}}
{stream}"""


def role_unit(config: dict) -> str:
    root, directory, data = (config[k] for k in ("root", "config_dir", "data_dir"))
    return f"""[Unit]
Description=MycoMesh IP mesh {config['role']} ({config['name']})
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_USER}
WorkingDirectory={data}
EnvironmentFile={directory}/public.env
ExecStart={root}/venv/bin/python {root}/app/scripts/ip_mesh_node.py run --config-dir {directory}
Restart=on-failure
RestartSec=5
TimeoutStopSec=35
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={data}
RestrictSUIDSGID=true
LimitNOFILE=8192
MemoryMax=768M
CPUQuota=200%
TasksMax=256

[Install]
WantedBy=multi-user.target
"""


def edge_unit(config: dict) -> str:
    directory, data = config["config_dir"], config["data_dir"]
    return f"""[Unit]
Description=MycoMesh IP TLS edge ({config['name']})
Wants=network-online.target mycomesh-ip-{config['role']}.service
After=network-online.target mycomesh-ip-{config['role']}.service
StartLimitIntervalSec=0

[Service]
Type=simple
RuntimeDirectory=mycomesh-ip-edge
RuntimeDirectoryMode=0755
ExecStartPre=/usr/sbin/nginx -t -c {directory}/nginx.conf
ExecStart=/usr/sbin/nginx -c {directory}/nginx.conf -g 'daemon off;'
ExecReload=/usr/sbin/nginx -c {directory}/nginx.conf -s reload
KillSignal=SIGQUIT
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=35
UMask=0077
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={data} /run/mycomesh-ip-edge
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
"""


def provision(args: argparse.Namespace) -> dict:
    root, directory, data = map(absolute_path, (args.root, args.config_dir, args.data_dir))
    if not args.stage_only and os.geteuid() != 0:
        raise ValueError("init requires root; use --stage-only for non-mutating service staging")
    address = ipaddress.ip_address(args.ip)
    if address.version != 4 or not address.is_global or str(address) != args.ip:
        raise ValueError("--ip must be a canonical globally routable IPv4 address")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", args.name):
        raise ValueError("Invalid node name")
    bridges, relays = https_origins(args.bridges), https_origins(args.relays)
    source = root / "app"
    sys.path.insert(0, str(source))
    from gateway.chain import normalize_address
    from gateway.provider_bootstrap import load_or_create_provider_evm_identity, load_provider_network_config

    payout = normalize_address(args.payout)
    if int(payout[2:], 16) == 0:
        raise ValueError("--payout must be nonzero")
    template = (absolute_path(args.network_config) if getattr(args, "network_config", None)
                else source / "deployments/sepolia-provider-network-v8.json")
    load_provider_network_config(template)
    manifest = json.loads(template.read_text())
    deployment = json.loads((template.parent / manifest["deployment"]).read_text())
    version = deployment["protocol_version"]
    if version not in {8, 9, 10}:
        raise ValueError("Only explicit V8/V9/V10 testnet manifests are supported")
    from gateway.provider_admission import manifest_provider_keys
    provider_keys = manifest_provider_keys(manifest, required=version in {9, 10})
    deployment_name = manifest["deployment"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", deployment_name):
        raise ValueError("Deployment must use a safe sibling JSON filename")
    for filename in ("node.crt", "node.key", "ca.crt"):
        certificate = absolute_path(str(directory / filename))
        if not certificate.is_file():
            raise ValueError(f"Missing certificate prerequisite: {certificate}")
    bundle = directory / "ca-bundle.crt"
    if not bundle.exists():
        # Trust the node CA only for this service, retaining public RPC trust.
        import ssl
        system_bundle = ssl.get_default_verify_paths().cafile
        if not system_bundle or not Path(system_bundle).is_file():
            raise ValueError("System CA bundle is unavailable; provision ca-bundle.crt explicitly")
        write_file(bundle, Path(system_bundle).read_text() + "\n" + (directory / "ca.crt").read_text())
    # Local staging permits dummy certificate fixtures. Actual deployment must
    # prove the key matches, the CA signs it, and the SAN includes the public IP.
    if not args.stage_only:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(directory / "node.crt"), str(directory / "node.key"))
        subprocess.run(["openssl", "verify", "-CAfile", str(directory / "ca.crt"),
                        "-verify_ip", args.ip, str(directory / "node.crt")],
                       check=True, stdout=subprocess.DEVNULL)
    for cert in ("node.crt", "ca.crt", "ca-bundle.crt"):
        (directory / cert).chmod(0o644)
    (directory / "node.key").chmod(0o600)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    data.chmod(0o700)
    public = directory / "public"
    public.mkdir(exist_ok=True, mode=0o755)
    # Consumers need the private testnet trust root when Relay endpoints use
    # IP SANs and an internal CA. The CA certificate is public by design; the
    # private node key never enters this directory. The manifest references it
    # by a relative path so installers can stage network.json + ca.crt as one
    # self-contained controlled-test bundle.
    write_file(public / "ca.crt", (directory / "ca.crt").read_text(), 0o644)
    manifest.update(bridge_urls=bridges)
    manifest["tls_ca_file"] = "ca.crt"
    manifest.setdefault("public_model_id", "gpt-5.5")
    manifest.setdefault("public_model_ids", [manifest["public_model_id"]])
    manifest["deployment"] = deployment_name
    manifest["relay_urls"] = relays
    manifest["mesh_node"] = {"name": args.name, "role": args.role, "url": f"https://{args.ip}"}
    metadata = {"role": args.role, "name": args.name, "url": f"https://{args.ip}",
                "manifest_path": str(public / "network.json")}
    identity_files = []
    if args.role == "relay":
        for filename, field in (("attestation-identity.json", "attestation_address"),
                                ("submitter-identity.json", "submitter_address")):
            identity_path = data / filename
            identity = load_or_create_provider_evm_identity(identity_path)
            metadata[field] = identity.address
            identity_files.append(identity_path)
        if len({payout, metadata["attestation_address"], metadata["submitter_address"]}) != 3:
            raise ValueError("Payout, attestation, and submitter identities must be separate")
        manifest["relay"] = {
            "attestation_address": metadata["attestation_address"], "host": args.ip,
            "payment_address": payout, "provider_port": 9901, "provider_tls": True,
            "public_url": f"https://{args.ip}",
        }
    write_file(public / deployment_name, json_text(deployment))
    write_file(public / "network.json", json_text(manifest))
    load_provider_network_config(public / "network.json")
    public_keys = manifest.get("gateway_consumer_public_keys", [])
    reputation_keys = args.reputation_key or public_keys
    if not reputation_keys or any(not re.fullmatch(r"[0-9a-f]{64}", k) for k in reputation_keys):
        raise ValueError("A canonical Ed25519 reputation public key is required")
    env = {
        "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(source),
        "SSL_CERT_FILE": str(directory / "ca-bundle.crt"),
        "REQUESTS_CA_BUNDLE": str(directory / "ca-bundle.crt"),
        "NODE_EXTRA_CA_CERTS": str(directory / "ca.crt"),
        "MYCOMESH_NETWORK_PROFILE": "testnet", "MYCOMESH_NETWORK_ID": manifest["network_id"],
        "MYCOMESH_SETTLEMENT_VERSION": str(version), "MYCO_DEPLOYMENT": str(public / deployment_name),
        "MYCOMESH_POOL_CORS_ALLOWED_ORIGINS": ",".join(ORIGINS),
        "MYCOMESH_REPLAY_DB": str(data / "relay-replay.sqlite3"),
        "MYCOMESH_RELAY_NETWORK_CONFIG": str(public / "network.json"),
        "MYCOMESH_RELAY_SETTLEMENT_VERSION": str(version),
        "MYCOMESH_RELAY_SETTLEMENT_RPC_URL": ",".join(
            manifest.get("settlement_rpc_urls") or [manifest["settlement_rpc_url"]]
        ),
        "MYCOMESH_RELAY_SETTLEMENT_CHAIN_ID": str(deployment["chain_id"]),
        "MYCOMESH_RELAY_SETTLEMENT_CONTRACT": deployment["settlement"],
        "MYCOMESH_RELAY_SETTLEMENT_DB": str(data / "relay-settlement.sqlite3"),
        "MYCOMESH_RELAY_INCIDENT_DB": str(data / "relay-incidents.sqlite3"),
        "MYCOMESH_RELAY_PROBE_DB": str(data / "relay-probes.sqlite3"),
        "MYCOMESH_RELAY_PROBES_ENABLED": "false",
        "MYCOMESH_RELAY_SETTLEMENT_BATCH_SIZE": "8",
        "PUBLIC_MODEL_ID": manifest["public_model_id"], "PUBLIC_MODEL_IDS": ",".join(manifest["public_model_ids"]),
        "MYCOMESH_RELAY_SETTLEMENT_INTERVAL_SECONDS": "7200",
        "MYCOMESH_RELAY_SETTLEMENT_COUNT_THRESHOLD": "100" if version == 10 else "1",
    }
    if version == 10 and deployment.get("committee_mode") == "controlled_test":
        env["MYCOMESH_ALLOW_CONTROLLED_V10_TEST"] = "1"
    if provider_keys is not None:
        env["MYCOMESH_RELAY_PROVIDER_PUBLIC_KEYS"] = ",".join(sorted(provider_keys))
    config = {"role": args.role, "name": args.name, "ip": args.ip, "root": str(root),
              "config_dir": str(directory), "data_dir": str(data), "env": env,
              "payout": payout, "bridges": bridges, "relays": relays,
              "settlement_version": version, "deployment_name": deployment_name,
              "consumer_public_keys": public_keys, "reputation_public_keys": reputation_keys}
    if provider_keys is not None:
        config["provider_public_keys"] = sorted(provider_keys)
    write_file(directory / "runtime.json", json_text(config))
    write_file(directory / "public.env", "".join(f"{k}={shlex.quote(v)}\n" for k, v in env.items()))
    module = args.stream_module
    if args.role == "relay" and module is None:
        candidates = ("/usr/lib/nginx/modules/ngx_stream_module.so", "/usr/lib64/nginx/modules/ngx_stream_module.so")
        module = next((item for item in candidates if Path(item).is_file()), None)
        if module is None and not args.stage_only:
            result = subprocess.run(["/usr/sbin/nginx", "-V"], capture_output=True, text=True, check=True)
            if not re.search(r"(?:^|\s)--with-stream(?:\s|$)", result.stderr):
                raise ValueError("Install libnginx-mod-stream or provide --stream-module")
    if module:
        absolute_path(module)
    write_file(directory / "nginx.conf", nginx_config(config, module))
    units = directory / "systemd" if args.stage_only else Path("/etc/systemd/system")
    write_file(units / f"mycomesh-ip-{args.role}.service", role_unit(config))
    write_file(units / "mycomesh-ip-edge.service", edge_unit(config))
    directories = [data, data / ".codex-run", data / "nginx"]
    directories.extend(data / "nginx" / name for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
    for item in directories:
        absolute_path(str(item))
        item.mkdir(exist_ok=True, mode=0o700)
    if not args.stage_only:
        try:
            account = pwd.getpwnam(SERVICE_USER)
        except KeyError:
            subprocess.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(data),
                            "--shell", "/usr/sbin/nologin", SERVICE_USER], check=True,
                           stdout=subprocess.DEVNULL)
            account = pwd.getpwnam(SERVICE_USER)
        directory.chmod(0o750)
        os.chown(directory, 0, account.pw_gid)
        os.chown(directory / "node.key", 0, 0)
        for item in (*directories, *identity_files):
            os.chown(item, account.pw_uid, account.pw_gid)
    return metadata


def run_node(directory: str) -> int:
    config = json.loads((absolute_path(directory) / "runtime.json").read_text())
    os.environ.update(config["env"])
    sys.path.insert(0, str(Path(config["root"]) / "app"))
    from gateway.provider_admission import normalize_provider_keys
    provider_keys = config.get("provider_public_keys")
    if provider_keys is not None or config.get("settlement_version") in {9, 10}:
        provider_keys = normalize_provider_keys(provider_keys)
        os.environ["MYCOMESH_RELAY_PROVIDER_PUBLIC_KEYS"] = ",".join(sorted(provider_keys))
    data = Path(config["data_dir"])
    os.chdir(data)
    if config["role"] == "relay":
        from gateway.provider_bootstrap import load_provider_evm_identity
        identity = load_provider_evm_identity(data / "submitter-identity.json")
        # Never place private keys in command arguments, public files, or logs.
        os.environ["MYCOMESH_RELAY_SETTLEMENT_PRIVATE_KEY"] = identity.private_key
        arguments = ["relay", "serve", "--host", "127.0.0.1", "--control-port", "9900",
                     "--provider-port", "19901", "--advertise-host", config["ip"],
                     "--advertise-control-port", "443", "--advertise-provider-port", "9901",
                     "--network-profile", "testnet", "--payment-address", config["payout"],
                     "--attestation-identity", str(data / "attestation-identity.json"),
                     "--settlement-version", str(config.get("settlement_version", 8)), "--trust-proxy-headers"]
        arguments += ["--settlement-interval-seconds", "7200",
                      "--settlement-count-threshold", "100" if config.get("settlement_version") == 10 else "1"]
        for key in config["consumer_public_keys"]:
            arguments += ["--consumer-public-key", key]
        for origin in ORIGINS:
            arguments += ["--cors-allowed-origin", origin]
    else:
        arguments = ["bridge", "serve", "--host", "127.0.0.1", "--port", "9800",
                     "--public-url", f"https://{config['ip']}", "--network-profile", "testnet",
                     "--require-provider-backend-metadata",
                     "--trust-proxy-headers"]
        if provider_keys is None:
            arguments += ["--allow-any-signed-provider"]
        else:
            for key in sorted(provider_keys):
                arguments += ["--provider-public-key", key]
        for origin in config["relays"]:
            arguments += ["--trusted-relay-origin", origin]
        for key in config["reputation_public_keys"]:
            arguments += ["--reputation-signer-public-key", key]
    from gateway.client import main
    return main(arguments)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Write isolated services/configs; do not start or enable them")
    init.add_argument("--role", choices=("bridge", "relay"), required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--ip", required=True)
    init.add_argument("--root", default="/opt/mycomesh-mesh")
    init.add_argument("--config-dir", default="/etc/mycomesh-mesh")
    init.add_argument("--data-dir", default="/var/lib/mycomesh-mesh")
    init.add_argument("--bridges", required=True, help="Comma-separated canonical HTTPS origins or IPv4 addresses")
    init.add_argument("--relays", required=True, help="Include existing Relay origin when preserving old Providers")
    init.add_argument("--payout", required=True)
    init.add_argument("--network-config", help="Explicit local network manifest and sibling deployment; default remains bundled V8")
    init.add_argument("--reputation-key", action="append", help="Existing Ed25519 public key; repeatable")
    init.add_argument("--stream-module", help="Absolute nginx stream module path; otherwise autodetected")
    init.add_argument("--stage-only", action="store_true", help="No root, user, chown, or system service changes")
    run = commands.add_parser("run", help="Systemd entrypoint; private keys remain out of process arguments")
    run.add_argument("--config-dir", default="/etc/mycomesh-mesh")
    args = parser.parse_args()
    try:
        if args.command == "run":
            return run_node(args.config_dir)
        print(json.dumps(provision(args), sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ip-mesh: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
