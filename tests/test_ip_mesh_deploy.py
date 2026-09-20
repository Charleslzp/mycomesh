from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import ssl
import stat
import shlex
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


def script(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provider = script("ip_mesh_provider")
node = script("ip_mesh_node")


class IPMeshProviderPrepareTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ip-mesh-test-", dir=REPO)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "mesh"
        self.old_env = self.base / "legacy/.env.deploy"
        self.original = "# Existing settings\nUPSTREAM_API_KEY=old-upstream-secret\nCUSTOM_PRIVATE_KEY=retained-secret\nMYCOMESH_NETWORK_PROFILE=local\n"
        provider.write_file(self.old_env, self.original, 0o600)
        system_ca = ssl.get_default_verify_paths().cafile
        if not system_ca:
            self.skipTest("System CA fixture unavailable")
        certificate = Path(system_ca).read_text()
        provider.write_file(self.root / "pki/ca.crt", certificate)
        provider.write_file(self.root / "pki/ca-bundle.crt", certificate)
        provider.write_file(self.root / "app/deployments/sepolia-myco-v8.json",
                            (REPO / "deployments/sepolia-myco-v8.json").read_text())
        (self.root / "app/gateway").mkdir(parents=True)
        self.manifest = json.loads((REPO / "deployments/sepolia-provider-network-v8.json").read_text())
        self.manifest["public_model_ids"] = ["gpt-5.5"]
        self.manifest["relay"]["host"] = "136.0.3.126"
        self.manifest["relay"]["public_url"] = "https://136.0.3.126"
        self.network = self.base / "network.json"
        provider.write_file(self.network, provider.json_text(self.manifest))
        self.args = argparse.Namespace(root=str(self.root), source_env=str(self.old_env),
            templates=str(REPO), network=str(self.network),
            payout="0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1", image="mycomesh/gateway:local",
            image_ca_file=None, volume_prefix="mycomesh")

    def test_secrets_stay_out_of_public_output_and_override(self):
        result = provider.prepare(self.args)
        overlay = (self.root / "mesh.override.json").read_text()
        self.assertNotIn("retained-secret", json.dumps(result) + overlay)
        self.assertNotIn("old-upstream-secret", (self.root / "mesh.env").read_text())
        self.assertIn("CUSTOM_PRIVATE_KEY=retained-secret", (self.root / "mesh.env").read_text())
        self.assertEqual(stat.S_IMODE((self.root / "mesh.env").stat().st_mode), 0o600)
        self.assertEqual(self.old_env.read_text(), self.original)
        self.assertFalse(result["started"])

    def test_external_volumes_and_read_only_code_and_certificate_mounts(self):
        provider.prepare(self.args)
        overlay = json.loads((self.root / "mesh.override.json").read_text())
        self.assertEqual(set(overlay["volumes"]), set(provider.VOLUMES))
        for key, value in overlay["volumes"].items():
            self.assertEqual(value, {"external": True, "name": "mycomesh_" + key})
        for role, value in overlay["services"].items():
            self.assertTrue(all(mount["read_only"] for mount in value["volumes"]))
            self.assertTrue(all(".env" not in mount["source"] for mount in value["volumes"]))
            self.assertFalse(any(mount["source"] == str(self.root / "pki") for mount in value["volumes"]))
            self.assertEqual(value["mem_limit"], {"provider": "384m", "provider-sidecar": "1400m", "provider-volume-init": "256m"}[role])

    def test_strict_environment_and_safe_separate_start_commands(self):
        result = provider.prepare(self.args)
        env = (self.root / "mesh.env").read_text()
        for item in ("MYCOMESH_NETWORK_PROFILE=testnet", "PUBLIC_MODEL_IDS=gpt-5.5",
                     "MYCOMESH_PROVIDER_TRANSPORT=relay", "MYCOMESH_CODEX_TESTNET_METERING=true",
                     "MYCOMESH_PROVIDER_SETTLEMENT_VERSION=8", "CODEX_SANDBOX=read-only"):
            self.assertIn(item, env)
        for key in ("init_command", "sidecar_command", "provider_after_signer_authorization_command"):
            self.assertIn("-p mycomesh", result[key])
            self.assertIn("--pull never", result[key])
        init_args = shlex.split(result["init_command"])
        self.assertIn("run", init_args)
        self.assertNotIn("--build", init_args)
        # Compose run has --build, but no --no-build flag (unlike Compose up).
        self.assertNotIn("--no-build", init_args)
        for key in ("sidecar_command", "provider_after_signer_authorization_command"):
            self.assertIn("--no-build --pull never", result[key])
        self.assertTrue(result["sidecar_command"].endswith("provider-sidecar"))
        self.assertNotIn(" down ", json.dumps(result))

    def test_idempotent_prepare_and_loader_compatibility(self):
        result = provider.prepare(self.args)
        env = (self.root / "mesh.env").read_text()
        self.assertEqual(provider.prepare(self.args), result)
        self.assertEqual((self.root / "mesh.env").read_text(), env)
        from gateway.provider_bootstrap import load_provider_network_config
        config = load_provider_network_config(self.root / "app/deployments/sepolia-provider-network-v8.json")
        self.assertEqual(config.public_model_ids, ("gpt-5.5",))
        self.assertEqual(config.relay_public_url, "https://136.0.3.126")

    def test_reject_original_deployment_as_output(self):
        self.args.root = str(self.old_env.parent)
        with self.assertRaises(ValueError):
            provider.prepare(self.args)
        self.assertEqual(self.old_env.read_text(), self.original)

    def test_reject_http_and_credential_urls(self):
        bundle = self.root / "pki/ca-bundle.crt"
        for url in ("http://136.0.3.126/network.json", "https://user:secret@136.0.3.126/network.json"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                provider.read_manifest(url, bundle)

    def test_reject_non_v8_and_non_tls_manifest(self):
        deployment = json.loads((self.root / "app/deployments/sepolia-myco-v8.json").read_text())
        bad = dict(self.manifest, network_profile="local")
        with self.assertRaises(ValueError):
            provider.validate_manifest(bad, deployment)
        bad = dict(self.manifest, relay=dict(self.manifest["relay"], provider_tls=False))
        with self.assertRaises(ValueError):
            provider.validate_manifest(bad, deployment)

    def test_rpc_override_deduplicates_and_updates_manifest_and_env(self):
        urls = ["https://rpc.sepolia.ethpandaops.io", "https://sepolia.gateway.tenderly.co"]
        self.args.rpc_urls = " " + urls[0] + ", " + urls[1] + "," + urls[0] + " "
        provider.prepare(self.args)
        generated = json.loads((self.root / "app/deployments/sepolia-provider-network-v8.json").read_text())
        self.assertEqual(generated["settlement_rpc_url"], urls[0])
        self.assertEqual(generated["settlement_rpc_urls"], urls)
        env = (self.root / "mesh.env").read_text()
        for key in ("MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL", "MYCOMESH_SETTLEMENT_RPC_URL"):
            self.assertIn(key + "=" + ",".join(urls) + "\n", env)
        self.assertEqual(json.loads(self.network.read_text()), self.manifest)
        from gateway.provider_bootstrap import load_provider_network_config
        loaded = load_provider_network_config(self.root / "app/deployments/sepolia-provider-network-v8.json")
        self.assertEqual(loaded.settlement_rpc_urls, tuple(urls))

    def test_absent_or_none_rpc_override_preserves_manifest_defaults(self):
        self.assertFalse(hasattr(self.args, "rpc_urls"))
        provider.prepare(self.args)
        path = self.root / "app/deployments/sepolia-provider-network-v8.json"
        original = path.read_text()
        self.args.rpc_urls = None
        provider.prepare(self.args)
        self.assertEqual(path.read_text(), original)
        generated = json.loads(original)
        self.assertEqual(generated["settlement_rpc_url"], self.manifest["settlement_rpc_url"])
        self.assertEqual(generated["settlement_rpc_urls"], self.manifest["settlement_rpc_urls"])

    def test_reject_invalid_rpc_overrides(self):
        invalid = ["", " ", "http://rpc.example.com", "https://", "https://user@rpc.example.com",
                   "https://user:secret@rpc.example.com", "https://@rpc.example.com",
                   "https://rpc.example.com\n", "https://rpc.example.com\r", "https://rpc.example.com\t",
                   "https://rpc.example.com/path with space", "https://rpc.example.com#fragment",
                   "https://rpc.example.com:bad", "https://rpc.example.com:0",
                   "https://rpc.example.com:99999", "https://rpc.example.com,,https://other.example.com",
                   "https://rpc.example.com\\path", ",".join(f"https://rpc{i}.example.com" for i in range(5))]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                provider.parse_rpc_urls(value)

    def test_rpc_limit_is_applied_after_deduplication(self):
        urls = [f"https://rpc{i}.example.com/path?chain=sepolia" for i in range(4)]
        self.assertEqual(provider.parse_rpc_urls(",".join(urls + [urls[0]])), urls)


class V10CanonicalManifestTests(unittest.TestCase):
    def test_controlled_manifest_is_explicit_and_provider_environment_is_pinned(self):
        manifest = json.loads((REPO / "deployments/sepolia-provider-network-v10.json").read_text())
        deployment = json.loads((REPO / "deployments/sepolia-myco-v10.json").read_text())
        provider.validate_manifest(manifest, deployment)
        self.assertEqual(deployment["protocol_version"], 10)
        self.assertEqual(deployment["committee_mode"], "controlled_test")
        self.assertFalse(deployment["independence_attested"])
        self.assertEqual(provider.provider_environment(
            manifest, "0x" + "11" * 20, settlement_version=10
        )["MYCOMESH_ALLOW_CONTROLLED_V10_TEST"], "1")

    def test_v10_manifest_rejects_reward_enabled_or_noncontrolled_deployment(self):
        manifest = json.loads((REPO / "deployments/sepolia-provider-network-v10.json").read_text())
        deployment = json.loads((REPO / "deployments/sepolia-myco-v10.json").read_text())
        deployment["reward_token"] = "0x" + "22" * 20
        with self.assertRaises(ValueError):
            provider.validate_manifest(manifest, deployment)


class IPMeshNodeConfigurationTests(unittest.TestCase):
    def test_node_origin_validation(self):
        self.assertEqual(node.https_origins("136.0.3.126,https://bridge.mycomesh.xyz"),
                         ["https://136.0.3.126", "https://bridge.mycomesh.xyz"])
        for url in ("http://136.0.3.126", "https://127.0.0.1", "https://example.com/",
                    "https://example.com:443", "https://user@example.com"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                node.https_origins(url)

    def test_node_unit_limits_and_no_secrets_in_command(self):
        config = {"root": "/opt/mycomesh-mesh", "config_dir": "/etc/mycomesh-mesh",
                  "data_dir": "/var/lib/mycomesh-mesh", "role": "relay", "name": "relay1"}
        unit = node.role_unit(config)
        for limit in ("MemoryMax=768M", "CPUQuota=200%", "TasksMax=256"):
            self.assertIn(limit, unit)
        self.assertNotIn("private-key", unit)
        self.assertNotIn("PRIVATE_KEY", unit)


if __name__ == "__main__":
    unittest.main()
