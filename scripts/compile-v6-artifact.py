#!/usr/bin/env python3
"""Compile the standalone V6 contract into a Foundry-compatible artifact."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "MycoSettlementV6.sol"
ARTIFACT = ROOT / "out" / "MycoSettlementV6.sol" / "MycoSettlementV6.json"


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    def compile_outputs(outputs: list[str]) -> dict:
        request = {
            "language": "Solidity",
            "sources": {SOURCE.name: {"content": source}},
            "settings": {
                # V6 exposes the V5 session surface plus historical Relay
                # route getters. Keep the deployed runtime below EIP-170.
                "optimizer": {"enabled": True, "runs": 1},
                "viaIR": True,
                "outputSelection": {"*": {"MycoSettlementV6": outputs}},
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
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"V6 Solidity compiler failed to start: {exc}") from exc
        raw = completed.stdout.strip()
        # npm may print a warning before standard-json output; parse from its first JSON object.
        start = raw.find("{")
        if start < 0:
            raise RuntimeError(completed.stderr.strip() or "solc returned no JSON output")
        try:
            output = json.loads(raw[start:])
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid solc JSON output: {exc}") from exc
        errors = [
            item
            for item in output.get("errors", [])
            if isinstance(item, dict) and item.get("severity") == "error"
        ]
        if completed.returncode != 0 or errors:
            details = "\n".join(str(item.get("formattedMessage") or item) for item in errors)
            raise RuntimeError(details or completed.stderr.strip() or f"solc exited with {completed.returncode}")
        contract = output.get("contracts", {}).get(SOURCE.name, {}).get("MycoSettlementV6")
        if not isinstance(contract, dict):
            raise RuntimeError("solc output does not contain MycoSettlementV6")
        return contract

    try:
        metadata = compile_outputs(["abi", "evm.deployedBytecode.immutableReferences"])
        abi = metadata.get("abi")
        immutable_references = (
            metadata.get("evm", {}).get("deployedBytecode", {}).get("immutableReferences")
        )
        bytecode = compile_outputs(["evm.bytecode.object"]).get("evm", {}).get("bytecode", {}).get("object")
        runtime = compile_outputs(["evm.deployedBytecode.object"]).get("evm", {}).get("deployedBytecode", {}).get("object")
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if (
        not isinstance(bytecode, str)
        or not bytecode
        or not isinstance(runtime, str)
        or not runtime
        or not isinstance(abi, list)
        or not isinstance(immutable_references, dict)
    ):
        print("solc output is missing V6 ABI or bytecode", file=sys.stderr)
        return 1
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(
        json.dumps(
            {
                "abi": abi,
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
