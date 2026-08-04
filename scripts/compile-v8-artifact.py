#!/usr/bin/env python3
"""Compile the standalone V8 settlement contract."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "MycoSettlementV8.sol"
ARTIFACT = ROOT / "out" / "MycoSettlementV8.sol" / "MycoSettlementV8.json"


def main() -> int:
    def compile_selection(selection: list[str]) -> dict:
        request = {
            "language": "Solidity",
            "sources": {SOURCE.name: {"content": SOURCE.read_text(encoding="utf-8")}},
            "settings": {
                "optimizer": {"enabled": True, "runs": 200},
                "viaIR": True,
                "outputSelection": {"*": {"MycoSettlementV8": selection}},
            },
        }
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
        errors = [item for item in output.get("errors", []) if item.get("severity") == "error"]
        if completed.returncode != 0 or errors:
            raise RuntimeError("\n".join(str(item.get("formattedMessage") or item) for item in errors))
        return output["contracts"][SOURCE.name]["MycoSettlementV8"]

    try:
        # Keep each solc response below Node's stdout pipe ceiling.
        abi_contract = compile_selection(["abi"])
        bytecode_contract = compile_selection(["evm.bytecode.object"])
        runtime_contract = compile_selection(
            [
                "evm.deployedBytecode.object",
                "evm.deployedBytecode.immutableReferences",
            ]
        )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, RuntimeError) as exc:
        print(f"V8 Solidity compiler failed: {exc}", file=sys.stderr)
        return 1
    bytecode = bytecode_contract["evm"]["bytecode"]["object"]
    runtime = runtime_contract["evm"]["deployedBytecode"]["object"]
    immutable_references = runtime_contract["evm"]["deployedBytecode"].get(
        "immutableReferences", {}
    )
    contract = abi_contract
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(
        json.dumps(
            {
                "abi": contract["abi"],
                "bytecode": {"object": "0x" + bytecode.removeprefix("0x")},
                "deployedBytecode": {
                    "object": "0x" + runtime.removeprefix("0x"),
                    "immutableReferences": immutable_references,
                },
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
