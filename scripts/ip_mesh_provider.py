#!/usr/bin/env python3
"""Prepare an isolated Provider Compose overlay, retaining existing auth volumes.

No Docker commands, service starts, key reads, chain writes, or original deployment
writes occur. Supply a verified local Relay network manifest or its HTTPS URL.
The dedicated pki directory must contain ca.crt and an image-system-CA bundle
with ca.crt appended; --image-ca-file can construct that bundle during prepare.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request
import ipaddress


VOLUMES = ("mycomesh-provider-data", "mycomesh-provider-codex-data",
           "mycomesh-provider-agent-data", "mycomesh-provider-workspace")


def checked_path(value: str) -> Path:
    path = Path(value)
    if (not path.is_absolute() or len(path.parts) < 3 or ".." in path.parts
            or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path))):
        raise ValueError("Use a specific absolute path with no spaces, metacharacters, or '..'")
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("Symbolic links are not accepted for deployment paths")
    return path


def write_file(path: Path, text: str, mode: int = 0o644) -> None:
    checked_path(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file():
            raise ValueError("An output path is not a regular file")
        if path.read_text() == text:
            path.chmod(mode)
            return
        backup = path.with_name(path.name + ".before-ip-mesh")
        if not backup.exists():
            # A backup inherits the requested privacy level, including mesh.env.
            write_file(backup, path.read_text(), mode)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def parse_rpc_urls(value: str) -> list[str]:
    """Validate an explicit RPC override without relaxing runtime retry policy."""
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("RPC URLs must not contain control characters")
    result = []
    for item in value.split(","):
        url = item.strip()
        if not url or any(char.isspace() for char in url) or "\\" in url:
            raise ValueError("RPC URLs must be a nonempty comma-separated HTTPS list")
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port
        except ValueError:
            raise ValueError("RPC URL is malformed") from None
        if (not url.startswith("https://") or parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or port == 0):
            raise ValueError("RPC URLs must use HTTPS without userinfo or fragments")
        if url not in result:
            result.append(url)
    # Keep the same endpoint count supported by gateway.chain.MAX_RPC_ENDPOINTS.
    if len(result) > 4:
        raise ValueError("At most four distinct RPC URLs are supported")
    return result


def read_manifest(value: str, bundle: Path) -> dict:
    if value.startswith("https://"):
        # No redirects to untrusted hosts/protocols or a system proxy carrying credentials.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, message, headers, new_url):
                raise ValueError("Manifest redirects are not accepted")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(bundle))),
        )
        parsed = urllib.parse.urlsplit(value)
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Manifest URL cannot contain credentials or a fragment")
        with opener.open(value, timeout=20) as response:
            raw = response.read(262145)
    elif "://" in value:
        raise ValueError("Remote network manifests require verified HTTPS")
    else:
        raw = checked_path(value).read_bytes()
    if len(raw) > 262144:
        raise ValueError("Manifest is too large")
    return json.loads(raw)


def validate_manifest(manifest: dict, deployment: dict) -> None:
    version = deployment.get("protocol_version")
    if (manifest.get("schema_version") != 1 or manifest.get("network_profile") != "testnet"
            or manifest.get("provider_transport") != "relay"
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", str(manifest.get("deployment") or ""))
            or manifest.get("public_model_id") != "gpt-5.5"):
        raise ValueError("Manifest must describe a strict Relay testnet with gpt-5.5 as its default model")
    if (version not in {8, 9, 10} or deployment.get("chain_id") != 11155111
            or any(manifest.get(k) != deployment.get(k) for k in ("network_id", "channel_id", "backend_policy"))):
        raise ValueError("Manifest does not match the local V8/V9/V10 settlement deployment")
    models = manifest.get("public_model_ids", ["gpt-5.5"])
    if not isinstance(models, list) or "gpt-5.5" not in models:
        raise ValueError("Manifest public_model_ids must include gpt-5.5")
    if version in {8, 9} and models != ["gpt-5.5"]:
        raise ValueError("V8/V9 Provider manifests expose only gpt-5.5")
    if version == 9:
        from gateway.chain import ChainError
        from gateway.chain_v9 import validate_deployment
        try:
            validate_deployment(deployment)  # No defaults for committee or money policy.
        except ChainError as exc:
            raise ValueError(f"Invalid explicit V9 deployment: {exc}") from exc
    if version == 10:
        from gateway.chain import ChainError
        from gateway.chain_v10 import validate_deployment
        if (deployment.get("committee_mode") != "controlled_test"
                or deployment.get("independence_attested") is not False
                or not str(deployment.get("network_id", "")).endswith("-controlled-test")
                or str(deployment.get("reward_token", "")).lower() != "0x" + "0" * 40):
            raise ValueError("V10 Provider manifests must be explicitly marked controlled_test with rewards disabled")
        try:
            validate_deployment(deployment, allow_controlled_test=True)
        except ChainError as exc:
            raise ValueError(f"Invalid explicit V10 deployment: {exc}") from exc
    relay = manifest.get("relay", {})
    relay_host = str(relay.get("host", ""))
    relay_url = str(relay.get("public_url", ""))
    try:
        parsed_relay = urllib.parse.urlsplit(relay_url)
        relay_ip = ipaddress.ip_address(relay_host)
    except ValueError:
        parsed_relay = None
        relay_ip = None
    if version in {8, 9}:
        relay_valid = (relay.get("provider_tls") is True and relay.get("provider_port") == 9901
                       and relay_url == "https://" + relay_host)
    else:
        # V10 controlled Relays currently expose their HTTPS origin on 10443
        # and are pinned by public IP under the dedicated testnet CA.
        relay_valid = (relay.get("provider_tls") is True and relay.get("provider_port") == 10991
                       and parsed_relay is not None and parsed_relay.scheme == "https"
                       and parsed_relay.hostname == relay_host.lower() and parsed_relay.port == 10443
                       and relay_ip is not None and relay_ip.is_global)
    if not relay_valid:
        raise ValueError("Relay must use its exact HTTPS origin and the protocol-specific Provider port (V8/V9: 9901; V10 controlled test: 10991 with public :10443)")
    for key in ("payment_address", "attestation_address"):
        if not re.fullmatch(r"0x[0-9a-f]{40}", relay.get(key, "")) or int(relay[key][2:], 16) == 0:
            raise ValueError("Relay public identities must be nonzero canonical EVM addresses")
    bridges = manifest.get("bridge_urls", [])
    if not bridges:
        raise ValueError("Manifest Bridge origins must not be empty")
    for bridge in bridges:
        parsed = urllib.parse.urlsplit(str(bridge))
        if version == 10:
            try:
                ip = ipaddress.ip_address(parsed.hostname or "")
            except ValueError:
                ip = None
            if (parsed.scheme != "https" or not parsed.hostname or parsed.port != 10443
                    or ip is None or not ip.is_global or parsed.username or parsed.password
                    or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
                raise ValueError("V10 controlled Bridge origins must be public HTTPS :10443 URLs")
        elif not re.fullmatch(r"https://[a-z0-9.-]+", str(bridge)):
            raise ValueError("Manifest Bridge origins must all use HTTPS")
    for rpc in manifest.get("settlement_rpc_urls") or [manifest.get("settlement_rpc_url", "")]:
        if not rpc.startswith("https://") or any(c in rpc for c in ("\n", "\r", "'")):
            raise ValueError("Settlement RPC endpoints must use HTTPS")


def provider_environment(manifest: dict, payout: str, *, settlement_version: int = 8) -> dict[str, str]:
    if settlement_version not in {8, 9, 10}:
        raise ValueError("Provider environment requires V8, V9 or V10")
    rpc = ",".join(manifest.get("settlement_rpc_urls") or [manifest["settlement_rpc_url"]])
    network_id = str(manifest.get("network_id") or "mycomesh-testnet")
    public_models = manifest.get("public_model_ids") or ["gpt-5.5"]
    values = {
        "GATEWAY_BACKEND": "codex_app_server", "PUBLIC_MODEL_ID": "gpt-5.5",
        "PUBLIC_MODEL_IDS": ",".join(str(model) for model in public_models), "CODEX_INTERNAL_MODEL": "gpt-5.5", "CENTER_MODEL": "gpt-5.5",
        "MYCOMESH_RESERVE_INPUT_TOKENS": "65536", "MYCOMESH_RESERVE_OUTPUT_TOKENS": "2000",
        "UPSTREAM_API_KEY": "", "CODEX_PROVIDER_BASE_URL": "", "MYCOMESH_NETWORK_PROFILE": "testnet",
        "MYCOMESH_NETWORK_ID": network_id, "MYCOMESH_CODEX_TESTNET_METERING": "true",
        "MYCOMESH_PROVIDER_NETWORK_CONFIG": f"/app/deployments/sepolia-provider-network-v{settlement_version}.json",
        "MYCOMESH_PROVIDER_EVM_IDENTITY": "/data/provider-evm-identity.json",
        "MYCOMESH_PROVIDER_POOL_URL": "", "MYCOMESH_PROVIDER_TRANSPORT": "relay",
        "MYCOMESH_PROVIDER_ADVERTISE_HOST": "auto", "MYCOMESH_PROVIDER_BIND_ADDRESS": "127.0.0.1",
        "MYCOMESH_PROVIDER_CONSUMER_PUBLIC_KEY": "", "MYCOMESH_PROVIDER_PAYMENT_ADDRESS": payout,
        "MYCOMESH_PROVIDER_PAYOUT_ADDRESS": payout, "MYCOMESH_PROVIDER_PRICING_HASH": "",
        "MYCOMESH_PROVIDER_EXTRA_ARGS": "", "MYCOMESH_SETTLEMENT_VERSION": str(settlement_version),
        "MYCOMESH_PROVIDER_SETTLEMENT_VERSION": str(settlement_version), "MYCOMESH_PRICING_VERSION": "",
        "MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL": rpc, "MYCOMESH_SETTLEMENT_RPC_URL": rpc,
        "MYCOMESH_SETTLEMENT_CONTRACT": "", "MYCOMESH_SETTLEMENT_CHAIN_ID": "",
        "MYCOMESH_PROVIDER_DEPLOYMENT": "/app/deployments/" + manifest["deployment"],
        "MYCO_DEPLOYMENT": "/app/deployments/" + manifest["deployment"],
        "MYCO_SETTLEMENT": "", "MYCO_TOKEN": "", "MYCO_TEST_USDC": "", "MYCO_TREASURY": "", "MYCO_CHANNEL_HASH": "",
        "MYCOMESH_PROVIDER_OPERATOR_CONFIG": "", "MYCOMESH_PROVIDER_IDENTITY_SOURCE": "",
        "MYCOMESH_BRIDGE_EXTRA_ARGS": "", "MYCOMESH_RELAY_EXTRA_ARGS": "",
        "MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER": "false", "ALLOW_ANONYMOUS_GATEWAY": "false",
        "ALLOW_PUBLIC_USER_REGISTRATION": "false", "CODEX_SANDBOX": "read-only",
        "CODEX_MAX_CONCURRENT_PROCESSES": "1", "MYCOMESH_PROVIDER_CAPACITY": "1",
        "MYCOMESH_PROVIDER_CPUS": "2.0", "MYCOMESH_CODEX_TESTNET_WEB_SEARCH": "false",
        "MYCOMESH_SETTLEMENT_CONFIRMATIONS": "6", "NODE_TLS_REJECT_UNAUTHORIZED": "1",
        "CODEX_TESTNET_MAX_OUTPUT_TOKENS": "2000", "UPSTREAM_DEFAULT_MAX_OUTPUT_TOKENS": "2000",
    }
    if settlement_version == 10:
        values["MYCOMESH_ALLOW_CONTROLLED_V10_TEST"] = "1"
    return values


def prepare(args: argparse.Namespace) -> dict:
    root, source_env = checked_path(args.root), checked_path(args.source_env)
    if root == source_env.parent or source_env.is_relative_to(root):
        raise ValueError("The mesh directory must be separate from the original deployment")
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", args.payout) or int(args.payout[2:], 16) == 0:
        raise ValueError("Payout must be a nonzero public EVM address")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", args.volume_prefix):
        raise ValueError("Invalid existing volume project prefix")
    root.mkdir(parents=True, exist_ok=True)
    pki = root / "pki"
    ca, bundle = pki / "ca.crt", pki / "ca-bundle.crt"
    if not checked_path(str(ca)).is_file():
        raise ValueError("Install the dedicated public CA certificate in pki/ca.crt first")
    if not bundle.exists():
        if not args.image_ca_file:
            raise ValueError("Supply pki/ca-bundle.crt or --image-ca-file extracted from the existing image")
        system_ca = checked_path(args.image_ca_file).read_text()
        write_file(bundle, system_ca + "\n" + ca.read_text())
    if ca.read_text().strip() not in bundle.read_text():
        raise ValueError("The prepared bundle must include the dedicated mesh CA")
    ssl.create_default_context(cafile=str(bundle))
    templates = checked_path(args.templates) if args.templates else root / "app"
    for name in ("docker-compose.yml", "Makefile"):
        source = templates / name
        if source.is_file():
            if source != root / name:
                write_file(root / name, source.read_text())
        elif not (root / name).is_file():
            raise ValueError("Upload the current Compose and Makefile templates first")
    manifest = read_manifest(args.network, bundle)
    rpc_override = getattr(args, "rpc_urls", None)
    if rpc_override is not None:
        rpc_urls = parse_rpc_urls(rpc_override)
        manifest["settlement_rpc_url"] = rpc_urls[0]
        manifest["settlement_rpc_urls"] = rpc_urls
    deployment_name = str(manifest.get("deployment") or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", deployment_name):
        raise ValueError("Deployment must use a safe sibling JSON filename")
    deployment_path = root / "app/deployments" / deployment_name
    deployment = json.loads(deployment_path.read_text())
    if deployment.get("protocol_version") == 9:
        sys.path.insert(0, str(root / "app"))
    validate_manifest(manifest, deployment)
    version = deployment["protocol_version"]
    write_file(root / f"app/deployments/sepolia-provider-network-v{version}.json", json_text(manifest))
    original = source_env.read_text()
    overrides = provider_environment(manifest, args.payout.lower(), settlement_version=version)
    if args.image:
        if not re.fullmatch(r"[A-Za-z0-9_./:@-]+", args.image):
            raise ValueError("Invalid existing Provider image reference")
        overrides["MYCOMESH_PROVIDER_IMAGE"] = args.image
    # Keep unrelated settings opaque: never parse, evaluate, or print secrets.
    preserved = []
    for line in original.splitlines(keepends=True):
        assignment = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if assignment and assignment[1] in overrides:
            continue
        preserved.append(line)
    rendered = "".join(preserved).rstrip() + "\n\n# Strict IP mesh Provider overrides\n"
    rendered += "".join(f"{key}={shlex.quote(value)}\n" for key, value in overrides.items())
    write_file(root / "mesh.env", rendered, 0o600)
    code_mounts = [
        {"type": "bind", "source": str(root / "app/gateway"), "target": "/app/gateway", "read_only": True},
        {"type": "bind", "source": str(root / "app/deployments"), "target": "/app/deployments", "read_only": True},
    ]
    tls_env = {"SSL_CERT_FILE": "/run/mycomesh-pki/ca-bundle.crt",
               "REQUESTS_CA_BUNDLE": "/run/mycomesh-pki/ca-bundle.crt",
               "CURL_CA_BUNDLE": "/run/mycomesh-pki/ca-bundle.crt",
               "NODE_EXTRA_CA_CERTS": "/run/mycomesh-pki/ca.crt",
               "NODE_TLS_REJECT_UNAUTHORIZED": "1"}
    services = {}
    for role, memory in (("provider-sidecar", "1400m"), ("provider", "384m"), ("provider-volume-init", "256m")):
        settings = {"volumes": list(code_mounts), "mem_limit": memory}
        if role != "provider-volume-init":
            for certificate in ("ca.crt", "ca-bundle.crt"):
                settings["volumes"].append({"type": "bind", "source": str(pki / certificate),
                                            "target": "/run/mycomesh-pki/" + certificate, "read_only": True})
            settings["environment"] = dict(tls_env)
            if role == "provider":
                settings["environment"]["MYCOMESH_PROVIDER_PAYOUT_ADDRESS"] = args.payout.lower()
        services[role] = settings
    overlay = {"services": services, "volumes": {
        name: {"external": True, "name": f"{args.volume_prefix}_{name}"} for name in VOLUMES
    }}
    write_file(root / "mesh.override.json", json_text(overlay))
    prefix = f"docker compose -p mycomesh --env-file {root}/mesh.env -f {root}/docker-compose.yml -f {root}/mesh.override.json --profile provider"
    return {
        "prepared": True, "started": False, "root": str(root), "relay_url": manifest["relay"]["public_url"],
        "bridge_urls": manifest["bridge_urls"], "payout": args.payout.lower(),
        "validate_command": prefix + " config --quiet",
        "init_command": prefix + " run --rm --no-deps --pull never provider-volume-init",
        "sidecar_command": prefix + " up -d --no-deps --no-build --pull never --wait --wait-timeout 120 provider-sidecar",
        "provider_after_signer_authorization_command": prefix + " up -d --no-deps --no-build --pull never --wait --wait-timeout 120 provider",
        "notes": ["Verify all four external volumes exist before starting; no empty replacements are created.",
                  "Do not run provider-up: its build flags do not preserve the existing pinned image.",
                  "Existing operator settings remain untouched and may cause a strict version mismatch at Provider startup."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare"])
    parser.add_argument("--root", default="/opt/mycomesh-mesh")
    parser.add_argument("--source-env", default="/opt/mycomesh/.env.deploy")
    parser.add_argument("--templates", help="Current repo directory containing docker-compose.yml and Makefile")
    parser.add_argument("--network", required=True, help="Verified local Relay manifest or HTTPS manifest URL")
    parser.add_argument("--rpc-urls", help="Optional comma-separated verified HTTPS RPC endpoints; overrides the local manifest and Provider environment")
    parser.add_argument("--payout", required=True)
    parser.add_argument("--image", help="Existing local Provider image reference; never pulled or built here")
    parser.add_argument("--image-ca-file", help="Public system CA PEM already extracted from the existing Provider image")
    parser.add_argument("--volume-prefix", default="mycomesh", help="Existing Docker Compose project prefix")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args), sort_keys=True))
        return 0
    except (OSError, ValueError, urllib.error.URLError) as exc:
        # Do not print parser excerpts or source file contents: env files may hold secrets.
        print(f"ip-mesh-provider: {type(exc).__name__}; prepare failed (no services started)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
