"""Make deployment selection must never silently downgrade explicit V9 roles."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ROLES = (("PUBLIC_NODE", "public-node-up"), ("PROVIDER", "provider-up"))


class V9MakeManifestTest(unittest.TestCase):
    def dry_run(self, target: str, values: dict[str, str], env_text: str = ""):
        with tempfile.TemporaryDirectory(prefix="mycomesh-make-v9-") as directory:
            env_file = Path(directory) / "deploy.env"
            env_file.write_text(env_text, encoding="utf-8")
            env = {
                key: value for key, value in os.environ.items()
                if not key.startswith(("MYCO", "PUBLIC_NODE_", "PROVIDER_"))
                and key not in {"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS"}
            }
            return subprocess.run(
                ["make", "--no-print-directory", "--dry-run", "-f", str(ROOT / "Makefile"),
                 target, f"DEPLOY_ENV_FILE={env_file}",
                 *[f"{key}={value}" for key, value in values.items()]],
                cwd=ROOT, env=env, text=True, capture_output=True, timeout=10,
            )

    def test_v9_requires_both_explicit_paths(self):
        for role, target in ROLES:
            for omitted in ("DEPLOYMENT", "NETWORK_CONFIG"):
                with self.subTest(role=role, omitted=omitted):
                    values = {f"{role}_SETTLEMENT_VERSION": "9"}
                    other = "NETWORK_CONFIG" if omitted == "DEPLOYMENT" else "DEPLOYMENT"
                    values[f"{role}_{other}"] = "/app/approved-v9.json"
                    result = self.dry_run(target, values)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"requires explicit {role}_{omitted}", result.stderr)
                    self.assertNotIn("docker compose", result.stdout)

    def test_v9_rejects_explicit_empty_path(self):
        for role, target in ROLES:
            for empty in ("DEPLOYMENT", "NETWORK_CONFIG"):
                with self.subTest(role=role, empty=empty):
                    values = {
                        f"{role}_SETTLEMENT_VERSION": "9",
                        f"{role}_DEPLOYMENT": "/app/approved-contract.json",
                        f"{role}_NETWORK_CONFIG": "/app/approved-network.json",
                        f"{role}_{empty}": "",
                    }
                    result = self.dry_run(target, values)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"requires explicit {role}_{empty}", result.stderr)
                    self.assertNotIn("docker compose", result.stdout)

    def test_v9_uses_explicit_operator_paths(self):
        for role, target in ROLES:
            with self.subTest(role=role):
                result = self.dry_run(target, {
                    f"{role}_SETTLEMENT_VERSION": "9",
                    f"{role}_DEPLOYMENT": "/app/approved-contract.json",
                    f"{role}_NETWORK_CONFIG": "/app/approved-network.json",
                })
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("MYCOMESH_SETTLEMENT_VERSION=9", result.stdout)
                self.assertIn("/app/approved-contract.json", result.stdout)
                self.assertIn("/app/approved-network.json", result.stdout)
                self.assertNotIn("sepolia-myco-v6.json", result.stdout)
                self.assertNotIn("sepolia-provider-network-v8.json", result.stdout)

    def test_v9_reads_explicit_paths_from_deploy_env(self):
        for role, target in ROLES:
            with self.subTest(role=role):
                result = self.dry_run(target, {}, "\n".join([
                    f"MYCOMESH_{role}_SETTLEMENT_VERSION=9",
                    f"MYCOMESH_{role}_DEPLOYMENT=/app/approved-contract.json",
                    f"MYCOMESH_{role}_NETWORK_CONFIG=/app/approved-network.json",
                ]))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("MYCOMESH_SETTLEMENT_VERSION=9", result.stdout)
                self.assertIn("/app/approved-contract.json", result.stdout)
                self.assertIn("/app/approved-network.json", result.stdout)

    def test_v8_defaults_remain_available(self):
        for role, target in ROLES:
            with self.subTest(role=role):
                result = self.dry_run(target, {})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("MYCOMESH_SETTLEMENT_VERSION=8", result.stdout)
                self.assertIn("/app/deployments/sepolia-myco-v8.json", result.stdout)
                self.assertIn("/app/deployments/sepolia-provider-network-v8.json", result.stdout)

    def test_v10_provider_is_explicit_controlled_test_and_public_node_fails_closed(self):
        result = self.dry_run("provider-up", {"PROVIDER_SETTLEMENT_VERSION": "10"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MYCOMESH_NETWORK_ID=mycomesh-v10-fixed-budget-controlled-test", result.stdout)
        self.assertIn("MYCOMESH_ALLOW_CONTROLLED_V10_TEST=1", result.stdout)
        self.assertIn("sepolia-myco-v10.json", result.stdout)
        self.assertIn("sepolia-provider-network-v10.json", result.stdout)

        result = self.dry_run("public-node-up", {"PUBLIC_NODE_SETTLEMENT_VERSION": "10"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PUBLIC_NODE does not support Settlement V10", result.stderr)
        self.assertNotIn("docker compose", result.stdout)

    def test_provider_configure_requires_and_passes_v9_paths_to_installer(self):
        result = self.dry_run("provider-configure", {"PROVIDER_SETTLEMENT_VERSION": "9"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires explicit PROVIDER_DEPLOYMENT", result.stderr)
        self.assertNotIn("docker compose", result.stdout)
        result = self.dry_run("provider-configure", {
            "PROVIDER_SETTLEMENT_VERSION": "9",
            "PROVIDER_DEPLOYMENT": "/app/approved-contract.json",
            "PROVIDER_NETWORK_CONFIG": "/app/approved-network.json",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('MYCOMESH_PUBLIC_PROVIDER_SETTLEMENT_VERSION="9"', result.stdout)
        self.assertIn('MYCOMESH_PUBLIC_PROVIDER_DEPLOYMENT="/app/approved-contract.json"', result.stdout)
        self.assertIn('MYCOMESH_PUBLIC_PROVIDER_NETWORK_CONFIG="/app/approved-network.json"', result.stdout)

    def test_v10_claim_payout_does_not_fall_back_to_v4(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn('case "$$settlement_version" in 8|9|10)', makefile)
        self.assertIn('V$$settlement_version payout requires the external payout wallet', makefile)


if __name__ == "__main__":
    unittest.main()
