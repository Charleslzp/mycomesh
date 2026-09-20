import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_gate import check


class ReleaseGateTest(unittest.TestCase):
    def test_repository_passes_release_gate(self):
        report = check(Path(__file__).parents[1])
        self.assertTrue(report["ok"], report)

    def test_bad_provider_version_is_reported(self):
        root = Path(__file__).parents[1]
        provider = (root / "packages/mycomesh-cli/src/provider.mjs").read_text()
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            for relative in (
                "package.json",
                "package-lock.json",
                "packages/mycomesh-cli/package.json",
                "packages/mycomesh-cli/package-lock.json",
                "packages/mycomesh-cli/src/provider.mjs",
                "packages/mycomesh-cli/src/release.mjs",
                "packages/mycomesh-cli/src/consumer.mjs",
                "packages/mycomesh-cli/src/cli.mjs",
                "Makefile",
                "contracts/MycoSettlementV9.sol",
                "docs/v9-deployment-policy.draft.json",
                "deployments/sepolia-myco-v10.json",
                "deployments/sepolia-provider-network-v10.json",
                "packages/mycomesh-cli/networks/v10-controlled-test.json",
            ):
                target = fixture / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                source = root / relative
                target.write_text((provider if relative.endswith("provider.mjs") else source.read_text()))
            package = json.loads((fixture / "package.json").read_text())
            package["version"] = "0.0.0"
            (fixture / "package.json").write_text(json.dumps(package))
            with patch("scripts.release_gate._tracked", return_value=[]):
                report = check(fixture)
            self.assertFalse(report["ok"])
            self.assertFalse(next(item for item in report["checks"] if item["name"] == "provider-version")["ok"])


if __name__ == "__main__":
    unittest.main()
