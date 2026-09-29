#!/usr/bin/env python3
"""Probe the V10 mesh on an interval and record JSONL canary evidence.

Each sample reads every pinned Relay's public ``/relay/health`` with the
manifest CA and records latency, Provider count and signers, jury enforcement
mode, monetary readiness and settlement readiness.  ``--summary`` reduces a
recorded file to availability, latency percentiles and invariant violations.
Nothing here changes remote state.
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NETWORK = ROOT / "deployments/sepolia-provider-network-v10-dynamic-20260926.json"
CA_FILE = ROOT / "packages/mycomesh-cli/networks/v10-dynamic-20260926.ca.crt"
MIN_PROVIDERS = 3


def relay_urls() -> list[str]:
    network = json.loads(NETWORK.read_text(encoding="utf-8"))
    return [network["relay"]["public_url"], *[item["public_url"] for item in network.get("relay_fallbacks", [])]]


def probe(url: str, context: ssl.SSLContext, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    sample: dict[str, Any] = {"url": url}
    try:
        with urllib.request.urlopen(f"{url}/relay/health", timeout=timeout, context=context) as response:
            payload = json.loads(response.read())
            sample["status"] = response.status
    except Exception as exc:  # recorded, never raised: the canary must keep sampling
        sample.update(status=None, error=type(exc).__name__)
        sample["latency_ms"] = round((time.monotonic() - started) * 1000)
        return sample
    sample["latency_ms"] = round((time.monotonic() - started) * 1000)
    anti = payload.get("anti_cheat") or {}
    runtime = payload.get("provider_ai_jury_runtime") or {}
    v10 = payload.get("v10") or {}
    sample.update(
        providers=payload.get("providers"),
        signers=sorted(v10.get("provider_signers") or []),
        enforcement_mode=anti.get("enforcement_mode"),
        monetary_ready=runtime.get("monetary_ready"),
        jury_error=runtime.get("error_code"),
        settlement_ready=payload.get("settlement_ready"),
        inference_ready=payload.get("inference_ready"),
        pending_settlements=((payload.get("settlement_submitter") or {}).get("batching") or {}).get("pending_count"),
    )
    return sample


def healthy(sample: dict[str, Any]) -> bool:
    return (
        sample.get("status") == 200
        and isinstance(sample.get("providers"), int)
        and sample["providers"] >= MIN_PROVIDERS
        and sample.get("enforcement_mode") == "provider_ai_jury"
        and sample.get("monetary_ready") is True
        and sample.get("settlement_ready") is True
        and sample.get("inference_ready") is True
    )


def run(output: Path, *, interval: float, duration: float, timeout: float) -> None:
    context = ssl.create_default_context(cafile=str(CA_FILE))
    urls = relay_urls()
    deadline = time.time() + duration
    output.parent.mkdir(parents=True, exist_ok=True)
    while time.time() < deadline:
        tick = time.time()
        record = {"at": int(tick), "relays": [probe(url, context, timeout) for url in urls]}
        record["healthy"] = all(healthy(sample) for sample in record["relays"])
        with output.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        time.sleep(max(0.0, interval - (time.time() - tick)))


def percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def summary(path: Path) -> dict[str, Any]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    result: dict[str, Any] = {
        "file": str(path),
        "samples": len(records),
        "first_at": records[0]["at"] if records else None,
        "last_at": records[-1]["at"] if records else None,
        "healthy_samples": sum(1 for record in records if record["healthy"]),
        "relays": {},
    }
    if records:
        result["span_hours"] = round((records[-1]["at"] - records[0]["at"]) / 3600, 2)
        result["mesh_availability"] = round(result["healthy_samples"] / len(records), 5)
    for url in {sample["url"] for record in records for sample in record["relays"]}:
        samples = [sample for record in records for sample in record["relays"] if sample["url"] == url]
        ok = [sample for sample in samples if sample.get("status") == 200]
        latencies = [sample["latency_ms"] for sample in ok]
        result["relays"][url] = {
            "samples": len(samples),
            "http_ok": len(ok),
            "healthy": sum(1 for sample in samples if healthy(sample)),
            "errors": sorted({sample.get("error") for sample in samples if sample.get("error")}),
            "min_providers": min((sample.get("providers") or 0 for sample in ok), default=None),
            "not_jury_mode": sum(1 for sample in ok if sample.get("enforcement_mode") != "provider_ai_jury"),
            "latency_ms": {
                "p50": percentile(latencies, 0.50),
                "p95": percentile(latencies, 0.95),
                "p99": percentile(latencies, 0.99),
                "max": max(latencies, default=None),
            },
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--interval", type=float, default=60.0)
    parser.add_argument("--duration", type=float, default=24 * 3600.0)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--summary", action="store_true", help="Summarize an existing file instead of sampling.")
    args = parser.parse_args()
    if args.summary:
        print(json.dumps(summary(args.output), indent=2, sort_keys=True))
        return 0
    run(args.output, interval=args.interval, duration=args.duration, timeout=args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
