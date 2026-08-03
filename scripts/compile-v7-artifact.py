#!/usr/bin/env python3
"""Compile the standalone V7 settlement contract."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "MycoSettlementV7.sol"
ARTIFACT = ROOT / "out" / "MycoSettlementV7.sol" / "MycoSettlementV7.json"


def main() -> int:
    request = {
        "language": "Solidity",
        "sources": {SOURCE.name: {"content": SOURCE.read_text(encoding="utf-8")}},
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "viaIR": True,
            "outputSelection": {
                "*": {"MycoSettlementV7": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]}
            },
        },
    }
    try:
        completed = subprocess.run(
            ["npx", "--yes", "solc@0.8.28", "--standard-json"],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            cwd=ROOT,
            check=False,
            timeout=300,
        )
        raw = completed.stdout[completed.stdout.find("{") :]
        output = json.loads(raw)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"V7 Solidity compiler failed: {exc}", file=sys.stderr)
        return 1
    errors = [item for item in output.get("errors", []) if item.get("severity") == "error"]
    if completed.returncode != 0 or errors:
        print("\n".join(str(item.get("formattedMessage") or item) for item in errors), file=sys.stderr)
        return 1
    contract = output.get("contracts", {}).get(SOURCE.name, {}).get("MycoSettlementV7")
    if not isinstance(contract, dict):
        print("solc output does not contain MycoSettlementV7", file=sys.stderr)
        return 1
    bytecode = contract["evm"]["bytecode"]["object"]
    runtime = contract["evm"]["deployedBytecode"]["object"]
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(
        json.dumps(
            {
                "abi": contract["abi"],
                "bytecode": {"object": "0x" + bytecode.removeprefix("0x")},
                "deployedBytecode": {"object": "0x" + runtime.removeprefix("0x")},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {ARTIFACT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
