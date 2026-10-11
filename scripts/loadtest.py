#!/usr/bin/env python3
"""Load-test the network through a Consumer's local endpoint (mycomesh-consumer serve).

Runs stages of N concurrent streaming chat requests and reports, per stage: success rate, end-to-end
latency and time to first token (p50/p90/max), requests and tokens per minute, and what the requests
cost at the network price. Everything goes the real path: local signing and sealing, a Relay, a
Provider's model, a signed receipt, on-chain settlement.

    npx mycomesh-consumer serve --port 8118 &
    python3 scripts/loadtest.py --endpoint http://127.0.0.1:8118 --stages 1:8,4:32,8:32 --budget-usd 100
"""
from __future__ import annotations

import argparse
import http.client
import json
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

TOPICS = ["how tides work", "the history of paper money", "why bread rises", "how a CPU cache works", "the life cycle of a star",
          "how vaccines train immunity", "the rules of go", "how noise-cancelling headphones work", "the Silk Road",
          "how bees communicate", "what causes inflation", "how GPS finds your position", "the invention of the telescope",
          "how glaciers move", "what a hash function is", "how coral reefs form"]


def one_request(endpoint: str, model: str, index: int, max_tokens: int) -> dict:
    parts = urlsplit(endpoint)
    body = json.dumps({"model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": max_tokens,
                       "messages": [{"role": "user", "content": f"In about 150 words, explain {TOPICS[index % len(TOPICS)]}."}]})
    started = time.monotonic()
    first = None
    usage = {}
    text = []
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=600)
    try:
        conn.request("POST", "/v1/chat/completions", body=body, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 200:
            return {"ok": False, "error": f"HTTP {response.status}: {response.read()[:200].decode('utf-8', 'replace')}",
                    "latency": time.monotonic() - started}
        for raw in response:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:") or line == "data: [DONE]":
                continue
            event = json.loads(line[5:])
            if "error" in event:
                return {"ok": False, "error": str(event["error"])[:200], "latency": time.monotonic() - started}
            for choice in event.get("choices") or []:
                delta = (choice.get("delta") or {}).get("content")
                if delta:
                    first = first or time.monotonic()
                    text.append(delta)
            usage = event.get("usage") or usage
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200], "latency": time.monotonic() - started}
    finally:
        conn.close()
    end = time.monotonic()
    return {"ok": bool(text), "latency": end - started, "ttft": (first or end) - started, "chars": len("".join(text)),
            "input_tokens": int(usage.get("prompt_tokens") or 0), "output_tokens": int(usage.get("completion_tokens") or 0),
            "error": None if text else "empty answer"}


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))] if ordered else 0.0


def run_stage(endpoint: str, model: str, concurrency: int, count: int, max_tokens: int, offset: int) -> dict:
    results: list[dict] = []
    lock = threading.Lock()
    started = time.monotonic()

    def task(i: int) -> None:
        result = one_request(endpoint, model, offset + i, max_tokens)
        with lock:
            results.append(result)
            done = len(results)
        mark = "ok " if result["ok"] else "ERR"
        print(f"  [{concurrency:>2}] {done:>3}/{count} {mark} {result['latency']:6.1f}s"
              + (f" ttft {result['ttft']:5.1f}s out {result['output_tokens']}" if result["ok"] else f" {result['error']}"), flush=True)

    with ThreadPoolExecutor(concurrency) as pool:
        list(pool.map(task, range(count)))
    wall = time.monotonic() - started
    good = [r for r in results if r["ok"]]
    minutes = wall / 60
    errors: dict[str, int] = {}
    for r in results:
        if not r["ok"]:
            key = r["error"].split(":")[0][:60] if r["error"] else "?"
            errors[key] = errors.get(key, 0) + 1
    return {
        "concurrency": concurrency, "requests": count, "ok": len(good), "wall_s": round(wall, 1),
        "rpm": round(len(good) / minutes, 1) if minutes else 0,
        "tpm_output": round(sum(r["output_tokens"] for r in good) / minutes) if minutes else 0,
        "tpm_total": round(sum(r["input_tokens"] + r["output_tokens"] for r in good) / minutes) if minutes else 0,
        "latency_s": {"p50": round(pct([r["latency"] for r in good], .5), 1), "p90": round(pct([r["latency"] for r in good], .9), 1),
                      "max": round(max((r["latency"] for r in good), default=0), 1)},
        "ttft_s": {"p50": round(pct([r["ttft"] for r in good], .5), 1), "p90": round(pct([r["ttft"] for r in good], .9), 1),
                   "max": round(max((r["ttft"] for r in good), default=0), 1)},
        "avg_input_tokens": round(statistics.mean([r["input_tokens"] for r in good])) if good else 0,
        "avg_output_tokens": round(statistics.mean([r["output_tokens"] for r in good])) if good else 0,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8118")
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument("--stages", default="1:8,2:16,4:32,8:32,16:32", help="concurrency:requests,...")
    parser.add_argument("--max-tokens", type=int, default=600)
    parser.add_argument("--budget-usd", type=float, default=100.0, help="stop starting stages once the estimate passes this")
    parser.add_argument("--price-input-per-1k", type=float, help="tUSDC base units per 1k input tokens (network price)")
    parser.add_argument("--price-output-per-1k", type=float)
    parser.add_argument("--min-fee", type=float)
    parser.add_argument("--out", default="docs/release-evidence/loadtest.json")
    args = parser.parse_args()
    price = (args.price_input_per_1k, args.price_output_per_1k, args.min_fee)
    report = {"started_at": int(time.time()), "endpoint": args.endpoint, "model": args.model, "max_tokens": args.max_tokens,
              "network_price": dict(zip(["input_per_1k", "output_per_1k", "minimum_fee"], price)), "stages": []}
    spent = 0.0
    offset = 0
    for spec in args.stages.split(","):
        concurrency, count = (int(x) for x in spec.split(":"))
        if spent >= args.budget_usd:
            print(f"budget of ${args.budget_usd} reached; skipping the rest")
            break
        print(f"stage: {concurrency} concurrent, {count} requests", flush=True)
        stage = run_stage(args.endpoint, args.model, concurrency, count, args.max_tokens, offset)
        offset += count
        if all(p is not None for p in price):
            per = max(price[2], stage["avg_input_tokens"] * price[0] / 1000 + stage["avg_output_tokens"] * price[1] / 1000)
            stage["cost_usd"] = round(per * stage["ok"] / 1e6, 6)
            stage["cost_per_request_usd"] = round(per / 1e6, 6)
            spent += stage["cost_usd"]
        report["stages"].append(stage)
        print(json.dumps(stage), flush=True)
    report["spent_usd_estimate"] = round(spent, 6)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=1) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
