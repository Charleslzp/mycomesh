#!/usr/bin/env python3
"""Reconnect the already-promoted dynamic-V10 Provider containers.

Provider transports keep their Relay endpoint in the signed network manifest,
but the current container process does not reconnect after the Relay process
is restarted.  This command only restarts each existing container, verifies
the public manifest hashes, and waits for the Bridge lease probe.  It does
not change an image, identity, key, capacity channel, or on-chain state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
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
)


NETWORK_PATH = "/opt/mycomesh-v10-dynamic-20260926/config/public/network.json"
DEPLOYMENT_PATH = "/opt/mycomesh-v10-dynamic-20260926/config/public/deployment.json"
NETWORK_SHA256 = hashlib.sha256(NETWORK.read_bytes()).hexdigest()
DEPLOYMENT_SHA256 = hashlib.sha256(DEPLOYMENT.read_bytes()).hexdigest()


def _reconnect(name: str, *, dry_run: bool) -> dict[str, Any]:
    container = PROVIDERS[name]
    client = remote.connect(name)
    try:
        state = _run(
            client,
            "docker inspect --format '{{.State.Running}}|{{.State.Status}}' -- "
            + container,
            timeout=20,
        ).strip()
        running, status = state.split("|", 1)
        if running != "true":
            raise RuntimeError(f"{container} is not running ({status})")
        network = _read(client, NETWORK_PATH)
        deployment = _read(client, DEPLOYMENT_PATH)
        observed = {
            "network_sha256": hashlib.sha256(network).hexdigest(),
            "deployment_sha256": hashlib.sha256(deployment).hexdigest(),
        }
        if observed != {
            "network_sha256": NETWORK_SHA256,
            "deployment_sha256": DEPLOYMENT_SHA256,
        }:
            raise RuntimeError("Provider public manifest is not the verified dynamic-V10 version")
        result: dict[str, Any] = {
            "node": name,
            "container": container,
            "changed": True,
            "manifest": observed,
            "dry_run": dry_run,
        }
        if dry_run:
            return result
        _run(client, f"docker restart --time 35 -- {container}", timeout=60)
        result["probe"] = _probe(client, container)
        return result
    finally:
        _close(client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=sorted(PROVIDERS))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    names = args.node or list(PROVIDERS)
    for name in names:
        try:
            print(json.dumps(_reconnect(name, dry_run=args.dry_run), sort_keys=True))
        except Exception as exc:
            print(json.dumps({"node": name, "error": remote.scrub(str(exc))}, sort_keys=True))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
