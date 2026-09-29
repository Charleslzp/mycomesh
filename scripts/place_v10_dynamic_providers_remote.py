#!/usr/bin/env python3
"""Place selected V10 Providers on the secondary Relay with rollback evidence.

The published network manifest contains the canonical Relay and fallback.  A
Provider normally chooses the canonical endpoint, so merely restarting it does
not create a second live fault domain.  This command creates a per-host
placement variant by swapping only ``relay`` and ``relay_fallbacks`` in the
already verified public network manifest, then restarts that host's existing
Provider container.  The deployment manifest, network id, settlement,
identity and image are untouched.  Every change gets a dated remote backup
and before/after hashes; an unexpected manifest is rejected fail-closed.
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

from refresh_v10_dynamic_provider_manifests_remote import (  # type: ignore  # noqa: E402
    DEPLOYMENT,
    NETWORK,
    PROVIDERS,
    _close,
    _probe,
    _read,
    _run,
    _write,
)


REMOTE_ROOT = "/opt/mycomesh-v10-dynamic-20260926"
NETWORK_PATH = f"{REMOTE_ROOT}/config/public/network.json"
DEPLOYMENT_PATH = f"{REMOTE_ROOT}/config/public/deployment.json"
CANONICAL_NETWORK = json.loads(NETWORK.read_text(encoding="utf-8"))
CANONICAL_DEPLOYMENT = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
CANONICAL_NETWORK_SHA256 = hashlib.sha256(NETWORK.read_bytes()).hexdigest()
CANONICAL_DEPLOYMENT_SHA256 = hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest()

RELAY_ENDPOINTS = {
    "relay1": CANONICAL_NETWORK["relay"],
    "relay3": CANONICAL_NETWORK["relay_fallbacks"][0],
}


def _canonical_endpoint(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("Relay endpoint is not an object")
    required = {
        "host",
        "public_url",
        "provider_port",
        "provider_tls",
        "payment_address",
        "attestation_address",
    }
    if set(value) != required:
        raise RuntimeError("Relay endpoint fields differ from the verified manifest")
    return {key: value[key] for key in sorted(required)}


def _placement_value(raw: bytes, relay_name: str) -> tuple[bytes, dict[str, Any]]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("remote Provider network manifest is not an object")
    if value.get("network_id") != CANONICAL_NETWORK["network_id"]:
        raise RuntimeError("remote Provider network id is not the verified V10 network")
    if value.get("source_commit") != CANONICAL_NETWORK["source_commit"]:
        raise RuntimeError("remote Provider network source commit is not the verified V10 release")
    if value.get("deployment_class") != CANONICAL_NETWORK["deployment_class"]:
        raise RuntimeError("remote Provider network deployment class is unexpected")
    if value.get("chain_id") != CANONICAL_NETWORK["chain_id"]:
        raise RuntimeError("remote Provider network chain id is unexpected")
    if value.get("relay") == RELAY_ENDPOINTS[relay_name] and value.get("relay_fallbacks") == [RELAY_ENDPOINTS["relay1" if relay_name == "relay3" else "relay3"]]:
        return raw, {"changed": False, "placement": relay_name}

    current_primary = _canonical_endpoint(value.get("relay"))
    current_fallbacks = value.get("relay_fallbacks")
    if not isinstance(current_fallbacks, list) or len(current_fallbacks) != 1:
        raise RuntimeError("remote Provider manifest does not have exactly one verified fallback")
    current_fallback = _canonical_endpoint(current_fallbacks[0])
    known = {_canonical_endpoint(v)["host"] for v in RELAY_ENDPOINTS.values()}
    if current_primary["host"] not in known or current_fallback["host"] not in known:
        raise RuntimeError("remote Provider manifest has an unknown Relay endpoint")
    if current_primary["host"] == current_fallback["host"]:
        raise RuntimeError("remote Provider manifest has duplicate Relay endpoints")

    fallback_name = "relay1" if relay_name == "relay3" else "relay3"
    value["relay"] = RELAY_ENDPOINTS[relay_name]
    value["relay_fallbacks"] = [RELAY_ENDPOINTS[fallback_name]]
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return encoded, {"changed": True, "placement": relay_name}


def _deployment_matches(client: Any) -> None:
    observed = _read(client, DEPLOYMENT_PATH)
    if hashlib.sha256(observed).hexdigest() != CANONICAL_DEPLOYMENT_SHA256:
        raise RuntimeError("remote Provider deployment manifest is not the verified V10 version")


def _place(name: str, relay_name: str, *, dry_run: bool) -> dict[str, Any]:
    if name not in PROVIDERS:
        raise ValueError(f"unknown Provider {name}")
    client = remote.connect(name)
    container = PROVIDERS[name]
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_dir = f"{REMOTE_ROOT}/rollback/provider-placement-{stamp}-{name}"
    try:
        running, status = _run(
            client,
            f"docker inspect --format '{{{{.State.Running}}}}|{{{{.State.Status}}}}' -- {shlex.quote(container)}",
            timeout=20,
        ).strip().split("|", 1)
        if running != "true":
            raise RuntimeError(f"{container} is not running ({status})")
        _deployment_matches(client)
        old_network = _read(client, NETWORK_PATH)
        next_network, placement = _placement_value(old_network, relay_name)
        result: dict[str, Any] = {
            "node": name,
            "container": container,
            "placement": relay_name,
            "changed": placement["changed"],
            "dry_run": dry_run,
            "old_network_sha256": hashlib.sha256(old_network).hexdigest(),
            "new_network_sha256": hashlib.sha256(next_network).hexdigest(),
            "canonical_network_sha256": CANONICAL_NETWORK_SHA256,
        }
        if not placement["changed"]:
            if dry_run:
                return result
            result["probe"] = _probe(client, container)
            return result
        result["backup_dir"] = backup_dir
        if dry_run:
            return result
        _run(client, f"mkdir -m 0700 -p -- {shlex.quote(backup_dir)}", timeout=20)
        # The staged Provider hosts intentionally serve this read-only public
        # manifest as root:root (mode 0644); preserve that existing ownership
        # model instead of assuming a service account that may not exist.
        _write(client, f"{backup_dir}/network.json", old_network, mode=0o644)
        next_path = f"{NETWORK_PATH}.placement.next"
        _write(client, next_path, next_network, mode=0o644)
        _run(
            client,
            f"mv -f -- {shlex.quote(next_path)} {shlex.quote(NETWORK_PATH)}",
            timeout=20,
        )
        try:
            _run(client, f"docker restart --time 35 -- {shlex.quote(container)}", timeout=60)
            result["probe"] = _probe(client, container)
        except Exception:
            rollback_path = f"{NETWORK_PATH}.placement.rollback.next"
            _write(client, rollback_path, old_network, mode=0o644)
            _run(
                client,
                f"mv -f -- {shlex.quote(rollback_path)} {shlex.quote(NETWORK_PATH)}",
                timeout=20,
            )
            try:
                _run(client, f"docker restart --time 35 -- {shlex.quote(container)}", timeout=60)
            except Exception:
                pass
            raise
        return result
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(PROVIDERS))
    parser.add_argument("--relay", choices=sorted(RELAY_ENDPOINTS), default="relay3")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    names = args.node or ["provider3", "provider4"]
    for name in names:
        try:
            print(json.dumps(_place(name, args.relay, dry_run=args.dry_run), sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
