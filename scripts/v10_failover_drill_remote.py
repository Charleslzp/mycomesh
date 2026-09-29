#!/usr/bin/env python3
"""Fault-injection and recovery-time drills for the V10 mesh.

Drills (each prints one JSON evidence line):

* ``relay``: stop one Relay unit, verify the surviving Relay keeps every
  Provider and jury readiness and that the gateway V10 route stays ready, then
  start the unit and measure the time to full health (RTO).
* ``provider``: restart one Provider container and measure the time until its
  signer is registered on every Relay again.
* ``rpc``: make one Relay host resolve the primary jury RPC to a closed port
  for a bounded window (self-reverting on the host), record the fail-closed
  state, and measure recovery after the outage ends.

All faults are bounded and reverted by the command; they target the
controlled-test mesh only.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402

from gateway.v10_gateway_route import load_v10_gateway_route  # noqa: E402

NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
CA_FILE = ROOT / "packages/mycomesh-cli/networks/v10-dynamic-20260926.ca.crt"
RELAYS = {
    "relay1": ("https://136.0.3.126:10443", "mycomesh-v10-dynamic-relay1.service"),
    "relay3": ("https://166.88.96.60:10443", "mycomesh-v10-dynamic-relay3.service"),
}
PROVIDER_CONTAINERS = {
    "provider1": "mycomesh-provider-1",
    "provider2": "mycomesh-v10-test-provider",
    "provider3": "mycomesh-v10-test-provider",
    "provider4": "mycomesh-v10-test-provider",
}
JURY_RPC_HOST = "rpc.sepolia.ethpandaops.io"
CONTEXT = ssl.create_default_context(cafile=str(CA_FILE))


def _health(url: str) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(f"{url}/relay/health", timeout=20, context=CONTEXT) as response:
            return json.loads(response.read())
    except (OSError, ValueError):
        return None


def _summary(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {"reachable": False}
    runtime = value.get("provider_ai_jury_runtime") or {}
    return {
        "reachable": True,
        "providers": value.get("providers"),
        "signers": sorted((value.get("v10") or {}).get("provider_signers") or []),
        "settlement_ready": value.get("settlement_ready"),
        "monetary_ready": runtime.get("monetary_ready"),
        "enforcement_mode": (value.get("anti_cheat") or {}).get("enforcement_mode"),
    }


def _fully_healthy(summary: dict[str, Any], providers: int) -> bool:
    return (
        summary.get("reachable") is True
        and summary.get("providers") == providers
        and summary.get("settlement_ready") is True
        and summary.get("monetary_ready") is True
        and summary.get("enforcement_mode") == "provider_ai_jury"
    )


def _wait(predicate, *, timeout: float, interval: float = 2.0) -> float | None:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if predicate():
            return round(time.monotonic() - started, 1)
        time.sleep(interval)
    return None


def _gateway_route_ready() -> bool:
    route = load_v10_gateway_route({
        "MYCOMESH_V10_PROVIDER_NETWORK_CONFIG": str(NETWORK),
        "MYCOMESH_V10_RELAY_CA_FILE": str(CA_FILE),
    })
    route._refresh_health()
    snapshot = route.health_snapshot() or {"relays": []}
    return any(relay.get("ready") is True for relay in snapshot["relays"])


def _with_client(node: str, command: str, *, timeout: int = 90) -> str:
    client = remote.connect(node)
    try:
        rc, out, err = remote.execute(client, command, timeout=timeout)
        if rc:
            raise RuntimeError(remote.scrub(err or out).strip()[-800:])
        return out
    finally:
        client.close()
        if getattr(client, "_mesh_jump", None):
            client._mesh_jump.close()


def relay_drill(node: str, *, outage_seconds: int) -> dict[str, Any]:
    url, unit = RELAYS[node]
    survivor = next(name for name in RELAYS if name != node)
    survivor_url = RELAYS[survivor][0]
    baseline = _summary(_health(url))
    providers = int(baseline.get("providers") or 0)
    if not _fully_healthy(baseline, providers) or providers < 3:
        raise RuntimeError(f"{node} is not fully healthy before the drill: {baseline}")
    result: dict[str, Any] = {"drill": "relay_outage", "node": node, "baseline": baseline}
    _with_client(node, f"systemctl stop -- {shlex.quote(unit)}")
    stopped_at = time.monotonic()
    try:
        time.sleep(5)
        result["during_outage"] = {
            "failed_relay": _summary(_health(url)),
            "survivor": _summary(_health(survivor_url)),
            "gateway_v10_route_ready": _gateway_route_ready(),
        }
        time.sleep(max(0, outage_seconds - (time.monotonic() - stopped_at)))
        result["survivor_after_outage"] = _summary(_health(survivor_url))
    finally:
        _with_client(node, f"systemctl start -- {shlex.quote(unit)}")
    started_at = time.monotonic()
    rto = _wait(lambda: _fully_healthy(_summary(_health(url)), providers), timeout=300)
    result.update(
        outage_seconds=round(started_at - stopped_at, 1),
        rto_seconds=rto,
        recovered=_summary(_health(url)),
        ok=(
            rto is not None
            and result["during_outage"]["gateway_v10_route_ready"] is True
            and _fully_healthy(result["during_outage"]["survivor"], providers)
            and _fully_healthy(result["survivor_after_outage"], providers)
        ),
    )
    return result


def provider_drill(node: str) -> dict[str, Any]:
    container = PROVIDER_CONTAINERS[node]
    signer = _with_client(
        node,
        f"docker exec -- {shlex.quote(container)} python -c "
        + shlex.quote("import json;print(json.load(open('/data/provider-evm-identity.json'))['address'])"),
    ).strip().lower()
    urls = [value[0] for value in RELAYS.values()]

    def on_every_relay() -> bool:
        return all(signer in _summary(_health(url)).get("signers", []) for url in urls)

    if not on_every_relay():
        raise RuntimeError(f"{node} signer is not on every Relay before the drill")
    _with_client(node, f"docker restart --time 35 -- {shlex.quote(container)}", timeout=120)
    restarted_at = time.monotonic()
    recovery = _wait(on_every_relay, timeout=300)
    return {
        "drill": "provider_restart", "node": node, "signer": signer,
        "recovery_seconds": recovery, "ok": recovery is not None,
        "relays_after": {url: _summary(_health(url)) for url in urls},
        "measured_from_restart_return_seconds": round(time.monotonic() - restarted_at, 1),
    }


def rpc_drill(node: str, *, outage_seconds: int) -> dict[str, Any]:
    url = RELAYS[node][0]
    baseline = _summary(_health(url))
    providers = int(baseline.get("providers") or 0)
    if not _fully_healthy(baseline, providers):
        raise RuntimeError(f"{node} is not fully healthy before the drill: {baseline}")
    marker = "# mycomesh-rpc-drill"
    # The revert runs on the host even if this session disconnects.
    script = (
        f"cp /etc/hosts /etc/hosts.mycomesh-drill && "
        f"printf '%s\\n' '0.0.0.0 {JURY_RPC_HOST} {marker}' >> /etc/hosts && "
        f"nohup sh -c 'sleep {int(outage_seconds)}; "
        f"grep -v \"{marker}\" /etc/hosts > /etc/hosts.mycomesh-drill.next && "
        f"cat /etc/hosts.mycomesh-drill.next > /etc/hosts && rm -f /etc/hosts.mycomesh-drill.next' "
        f">/dev/null 2>&1 &"
    )
    _with_client(node, script)
    began = time.monotonic()
    samples = []
    while time.monotonic() - began < outage_seconds:
        samples.append(_summary(_health(url)))
        time.sleep(10)
    reverted = _wait(
        lambda: "mycomesh-rpc-drill" not in _with_client(node, "cat /etc/hosts"),
        timeout=60, interval=3,
    )
    ended = time.monotonic()
    recovery = _wait(lambda: _fully_healthy(_summary(_health(url)), providers), timeout=300)
    return {
        "drill": "jury_rpc_outage", "node": node, "blocked_host": JURY_RPC_HOST,
        "outage_seconds": round(ended - began, 1),
        "hosts_reverted": reverted is not None,
        "during_outage": {
            "samples": len(samples),
            "jury_fail_closed_samples": sum(1 for sample in samples if sample.get("monetary_ready") is False),
            "settlement_ready_samples": sum(1 for sample in samples if sample.get("settlement_ready") is True),
            "providers_min": min((sample.get("providers") or 0 for sample in samples), default=None),
        },
        "recovery_seconds": recovery,
        "ok": reverted is not None and recovery is not None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("drill", choices=("relay", "provider", "rpc"))
    parser.add_argument("--node", required=True)
    parser.add_argument("--outage-seconds", type=int, default=60)
    args = parser.parse_args()
    os.environ.setdefault("MYCOMESH_ALLOW_CONTROLLED_V10_TEST", "1")
    try:
        if args.drill == "relay":
            result = relay_drill(args.node, outage_seconds=args.outage_seconds)
        elif args.drill == "provider":
            result = provider_drill(args.node)
        else:
            result = rpc_drill(args.node, outage_seconds=args.outage_seconds)
    except Exception as exc:
        result = {"drill": args.drill, "node": args.node, "ok": False, "error": remote.scrub(str(exc))}
    result["at"] = int(time.time())
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
