#!/usr/bin/env python3
"""Measure how often a model passes each capability probe kind.

Generates one fixed task set (``make``), then runs it against a model:
``openai`` for any OpenAI-compatible endpoint (vLLM, Ollama), or ``codex`` for
a ChatGPT-login Codex CLI, which is run on a Provider host inside its
container (``--host provider1``; the script ships itself over stdin). Results
go to docs/release-evidence/capability-calibration.json, which sets each
tier's floor.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "docs/release-evidence/capability-tasks.json"
RESULTS = ROOT / "docs/release-evidence/capability-calibration.json"
SUFFIX = " Reply with the answer only."


def run_openai(base_url: str, model: str, question: str, timeout: float) -> str:
    import urllib.request

    body = {"model": model, "messages": [{"role": "user", "content": question + SUFFIX}], "max_tokens": 16_000}
    request = urllib.request.Request(f"{base_url}/chat/completions", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer none"})
    with urllib.request.urlopen(request, timeout=timeout) as reply:
        return json.loads(reply.read())["choices"][0]["message"]["content"] or ""


REMOTE = """
import json, sys, time
sys.path.insert(0, "/app")
from mycomesh.provider.codex import CodexBackend
spec = json.loads(sys.stdin.readline())
backend = CodexBackend(codex_home="/codex", timeout=600)
for item in spec["questions"]:
    started = time.time()
    try:
        text, _, out = backend.turn(spec["model"], item + spec["suffix"], None, effort=spec["effort"])
    except Exception as exc:
        text, out = "", 0
        print(json.dumps({"error": str(exc)[:200]}), file=sys.stderr)
    print(json.dumps({"answer": text, "output_tokens": out, "seconds": round(time.time() - started, 1)}), flush=True)
"""


def run_codex(host: str, model: str, effort: str | None, questions: list[str]) -> list[dict]:
    """One remote process answers every question in turn; returns their answers in order."""
    spec = json.dumps({"model": model, "effort": effort, "suffix": SUFFIX, "questions": questions})
    program = base64.b64encode(REMOTE.encode()).decode()
    command = [sys.executable, str(ROOT / ".codex-run/mesh/remote.py"), host, "--timeout", "7200", "--command",
               f"docker exec -i mycomesh-v11-provider python -c \"$(echo {program} | base64 -d)\" <<'SPEC'\n{spec}\nSPEC"]
    result = json.loads(subprocess.run(command, capture_output=True, text=True, check=True).stdout)
    return [json.loads(line) for line in result["stdout"].splitlines() if line.startswith("{")]


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from mycomesh.capability import KINDS, PROBE_KINDS, build_capability_task, random_task

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("make")
    make.add_argument("--per-kind", type=int, default=8)
    sub.add_parser("regrade")
    run = sub.add_parser("run")
    run.add_argument("backend", choices=["openai", "codex"])
    run.add_argument("--model", required=True)
    run.add_argument("--label")
    run.add_argument("--base-url", default="http://127.0.0.1:11434/v1")
    run.add_argument("--host", default="provider1", help="comma-separated Provider hosts")
    run.add_argument("--effort")
    run.add_argument("--timeout", type=float, default=900)
    run.add_argument("--per-kind", type=int, help="only the first N tasks of each kind (slow local models)")
    args = parser.parse_args()

    if args.command == "regrade":
        # Apply the current grader to every stored answer (full-set runs are in task-file order).
        stored = json.loads(TASKS.read_text())
        results = json.loads(RESULTS.read_text())
        for label, run in results.items():
            per_kind = {kind: [0, 0] for kind in KINDS}
            for index, sample in enumerate(run["samples"]):
                params = sample.get("params") or stored[index]["params"]
                sample["params"] = params
                task = build_capability_task(sample["kind"], params)
                sample["grade"] = task.grade(sample["answer"])
                per_kind[task.kind][0] += sample["grade"] == "pass"
                per_kind[task.kind][1] += 1
            run["per_kind"] = {kind: f"{p}/{n}" for kind, (p, n) in per_kind.items()}
            run["pass_rate"] = round(sum(p for p, _ in per_kind.values()) / sum(n for _, n in per_kind.values()), 3)
            print(label, run["pass_rate"], run["per_kind"])
        RESULTS.write_text(json.dumps(results, indent=1) + "\n")
        return 0

    if args.command == "make":
        tasks = [{"kind": kind, "params": random_task(kind).params} for kind in PROBE_KINDS for _ in range(args.per_kind)]
        TASKS.write_text(json.dumps(tasks, indent=1) + "\n")
        print(f"wrote {len(tasks)} tasks to {TASKS.relative_to(ROOT)}")
        return 0

    tasks = [build_capability_task(item["kind"], item["params"]) for item in json.loads(TASKS.read_text())]
    if args.per_kind:
        tasks = [task for kind in KINDS for task in [t for t in tasks if t.kind == kind][:args.per_kind]]
    if args.backend == "codex":
        # Hosts answer interleaved shares of the tasks in parallel.
        from concurrent.futures import ThreadPoolExecutor

        hosts = args.host.split(",")
        with ThreadPoolExecutor(len(hosts)) as pool:
            shares = list(pool.map(lambda i: run_codex(hosts[i], args.model, args.effort,
                                                       [task.question for task in tasks[i::len(hosts)]]), range(len(hosts))))
        answers = [None] * len(tasks)
        for i, share in enumerate(shares):
            answers[i::len(hosts)] = share
    else:
        answers = []
        for task in tasks:
            started = time.time()
            try:
                answers.append({"answer": run_openai(args.base_url, args.model, task.question, args.timeout),
                                "seconds": round(time.time() - started, 1)})
            except OSError as exc:
                answers.append({"answer": "", "error": str(exc)[:200]})
            print(f"{task.kind:<14} {task.grade(answers[-1]['answer'])}", flush=True)
    per_kind: dict[str, list[int]] = {kind: [0, 0] for kind in KINDS}
    # (samples keep the whole answer, so a later grading change can be re-applied)
    samples = []
    for task, answer in zip(tasks, answers):
        grade = task.grade(answer["answer"])
        per_kind[task.kind][0] += grade == "pass"
        per_kind[task.kind][1] += 1
        samples.append({"kind": task.kind, "params": task.params, "reference": task.reference, "grade": grade,
                        "answer": answer["answer"][-2000:], "seconds": answer.get("seconds")})
    label = args.label or (args.model + (f"@{args.effort}" if args.effort else ""))
    total = sum(p for p, _ in per_kind.values()), sum(n for _, n in per_kind.values())
    with open(RESULTS.with_suffix(".lock"), "w") as lock:  # several runs may finish together
        fcntl.flock(lock, fcntl.LOCK_EX)
        results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
        results[label] = {"measured_at": int(time.time()), "backend": args.backend, "pass_rate": round(total[0] / total[1], 3),
                          "per_kind": {kind: f"{p}/{n}" for kind, (p, n) in per_kind.items() if n}, "samples": samples}
        RESULTS.write_text(json.dumps(results, indent=1) + "\n")
    print(json.dumps({label: {k: v for k, v in results[label].items() if k != "samples"}}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
