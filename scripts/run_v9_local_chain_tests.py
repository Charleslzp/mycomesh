#!/usr/bin/env python3
"""Run mandatory V9 EVM tests with locked, temporary, loopback-only fixtures.

Python requirements and the native Consumer dependencies must already be
installed. Hardhat is installed only in a temporary directory; Forge outputs
and caches also stay there. No deployment credentials or external RPC are used.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/v9-local-chain"
TEST_CLASSES = (
    "tests.test_v9_local_chain.V9LocalChainTests",
    "tests.test_v9_deployment.LocalChainDeploymentTests",
)
MINIMUM_TESTS = 10


def loopback_only(event: str, args: tuple) -> None:
    """Reject external Python network access while real RPC tests execute."""
    if event == "socket.connect":
        destination = args[1]
        if not isinstance(destination, tuple):
            return  # Local Unix socket.
        host = destination[0]
    elif event == "socket.getaddrinfo":
        host = args[0]
    else:
        return
    if host in {"localhost", b"localhost"}:
        return
    try:
        address = ipaddress.ip_address(host.decode() if isinstance(host, bytes) else host)
    except ValueError as exc:
        raise RuntimeError("V9 integration tests permit only loopback RPC") from exc
    if not address.is_loopback:
        raise RuntimeError("V9 integration tests permit only loopback RPC")


def run_suite() -> int:
    # Opt-in is set before importing classes, so decorators cannot silently skip.
    sys.path.insert(0, str(ROOT))
    sys.addaudithook(loopback_only)
    suite = unittest.defaultTestLoader.loadTestsFromNames(TEST_CLASSES)
    selected = suite.countTestCases()
    if selected < MINIMUM_TESTS:
        raise RuntimeError(f"Expected at least {MINIMUM_TESTS} V9 EVM tests; found {selected}")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print(f"ERROR: skipped V9 EVM tests are forbidden: {result.skipped}", file=sys.stderr)
    if result.testsRun != selected:
        print(f"ERROR: executed {result.testsRun} of {selected} V9 EVM tests", file=sys.stderr)
    return 0 if result.wasSuccessful() and not result.skipped and result.testsRun == selected else 1


def main() -> int:
    os.chdir(ROOT)
    node_version = subprocess.check_output(["node", "--version"], text=True).strip()
    if node_version != "v22.22.2":
        raise RuntimeError(f"V9 EVM tests require pinned Node v22.22.2; found {node_version}")
    # Ignore deployment/profile/fallback-RPC and proxy settings from the host.
    for name in list(os.environ):
        if name.startswith(("MYCO", "RUN_MYCO")) or name.lower().endswith("_proxy"):
            os.environ.pop(name)
    os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"
    with tempfile.TemporaryDirectory(prefix="mycomesh-v9-local-chain-") as directory:
        work = Path(directory).resolve()
        for name in ("package.json", "package-lock.json", "hardhat.config.js"):
            shutil.copy2(FIXTURE / name, work / name)
        subprocess.run(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=work, check=True, timeout=300,
        )
        installed = json.loads((work / "node_modules/hardhat/package.json").read_text())
        if installed["version"] != "3.0.6":
            raise RuntimeError("Unexpected Hardhat version after locked install")
        artifacts = work / "out"
        subprocess.run(
            ["forge", "build", "--use", "0.8.28", "--evm-version", "prague",
             "--out", str(artifacts), "--cache-path", str(work / "cache")],
            cwd=ROOT, check=True, timeout=600,
        )
        os.environ.update({
            "RUN_MYCO_V9_LOCAL_CHAIN": "1",
            "MYCOMESH_TEST_HARDHAT_BIN": str(work / "node_modules/.bin/hardhat"),
            "MYCOMESH_TEST_HARDHAT_CONFIG": str(work / "hardhat.config.js"),
            "MYCOMESH_TEST_V9_ARTIFACT_ROOT": str(artifacts),
        })
        return run_suite()


if __name__ == "__main__":
    raise SystemExit(main())
