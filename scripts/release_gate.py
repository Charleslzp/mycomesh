#!/usr/bin/env python3
"""Small, dependency-free release consistency gate.

This deliberately checks release wiring and repository hygiene only.  It does
not validate a live chain, image registry, or Docker daemon.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
FORBIDDEN_PARTS = {"artifacts", "out", "cache", "__pycache__", "test-results"}


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _tracked(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [item for item in result.stdout.decode().split("\0") if item]


def check(root: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []

    package = json.loads(_read(root, "package.json"))
    package_lock = json.loads(_read(root, "package-lock.json"))
    consumer_package = json.loads(_read(root, "packages/mycomesh-cli/package.json"))
    consumer_lock = json.loads(_read(root, "packages/mycomesh-cli/package-lock.json"))
    provider = _read(root, "packages/mycomesh-cli/src/provider.mjs")
    release_module = _read(root, "packages/mycomesh-cli/src/release.mjs")
    consumer = _read(root, "packages/mycomesh-cli/src/consumer.mjs")
    cli = _read(root, "packages/mycomesh-cli/src/cli.mjs")
    version_match = re.search(r'PROVIDER_RELEASE_VERSION = "([^"]+)"', release_module)
    ref_match = re.search(r'DEFAULT_REF = "([^"]+)"', provider)
    image_match = re.search(r'DEFAULT_PROVIDER_IMAGE =\n\s+"([^"]+)"', provider)
    checks.append({"name": "provider-version", "ok": bool(version_match and version_match.group(1) == package.get("version")),
                   "detail": f"root={package.get('version')} provider={version_match.group(1) if version_match else 'missing'}"})
    checks.append({"name": "root-lock-version", "ok": package_lock.get("version") == package.get("version") and package_lock.get("packages", {}).get("", {}).get("version") == package.get("version"),
                   "detail": f"package={package.get('version')} lock={package_lock.get('version')}"})
    consumer_version_match = re.search(r'CONSUMER_RELEASE_VERSION = "([^"]+)"', release_module)
    checks.append({"name": "consumer-version", "ok": bool(consumer_version_match and consumer_version_match.group(1) == consumer_package.get("version") == consumer_lock.get("version") and re.search(r'CONSUMER_RELEASE_VERSION\s*\}\s*from "\./release\.mjs"', consumer) and re.search(r'CONSUMER_RELEASE_VERSION\s*\}\s*from "\./release\.mjs"', cli)),
                   "detail": f"package={consumer_package.get('version')} runtime={consumer_version_match.group(1) if consumer_version_match else 'missing'}"})
    checks.append({"name": "consumer-release-file", "ok": "src/release.mjs" in consumer_package.get("files", []), "detail": "src/release.mjs is included in the npm package"})
    checks.append({"name": "provider-ref", "ok": bool(ref_match and COMMIT_RE.fullmatch(ref_match.group(1))),
                   "detail": ref_match.group(1) if ref_match else "missing"})
    checks.append({"name": "provider-image-digest", "ok": bool(image_match and DIGEST_RE.search(image_match.group(1))),
                   "detail": image_match.group(1) if image_match else "missing"})

    # V10 has two runtime manifests; V9's deployable source and policy are
    # kept separately because V9 operators supply their own chain manifest.
    required = [
        "deployments/sepolia-myco-v10.json",
        "deployments/sepolia-provider-network-v10.json",
        "contracts/MycoSettlementV9.sol",
        "docs/v9-deployment-policy.draft.json",
        "packages/mycomesh-cli/networks/v10-controlled-test.json",
    ]
    for relative in required:
        checks.append({"name": f"release-file:{relative}", "ok": (root / relative).is_file(), "detail": relative})

    makefile = _read(root, "Makefile")
    for target in ("node-up", "node-health", "provider-health"):
        checks.append({"name": f"make-target:{target}", "ok": re.search(rf"^{re.escape(target)}\s*:", makefile, re.MULTILINE) is not None, "detail": target})

    generated = []
    for relative in _tracked(root):
        parts = set(Path(relative).parts)
        if parts & FORBIDDEN_PARTS:
            generated.append(relative)
    checks.append({"name": "tracked-generated-files", "ok": not generated, "detail": generated})
    return {"ok": all(bool(item["ok"]) for item in checks), "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    report = check(args.root.resolve())
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for item in report["checks"]:
            print(f"{'PASS' if item['ok'] else 'FAIL'} {item['name']}: {item['detail']}")
        print("release gate: " + ("PASS" if report["ok"] else "FAIL"))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
