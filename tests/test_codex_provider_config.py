from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 remains supported by the package.
    tomllib = None

from gateway.codex_provider_config import (
    MANAGED_CONFIG_MARKER,
    CodexProviderConfigError,
    configure_codex_provider_from_env,
    secure_codex_home,
)


class CodexProviderConfigTest(unittest.TestCase):
    expected_disabled_features = {
        "shell_tool",
        "unified_exec",
        "shell_snapshot",
        "hooks",
        "code_mode",
        "code_mode_host",
        "multi_agent",
        "apps",
        "plugins",
        "in_app_browser",
        "browser_use",
        "browser_use_full_cdp_access",
        "browser_use_external",
        "computer_use",
        "remote_plugin",
        "plugin_sharing",
        "image_generation",
        "skill_mcp_dependency_install",
        "tool_suggest",
        "tool_call_mcp_elicitation",
        "auth_elicitation",
        "workspace_dependencies",
    }

    def test_default_config_forces_file_backed_chatgpt_without_custom_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "codex-home"
            path = configure_codex_provider_from_env(home, {})
            document = path.read_text(encoding="utf-8")

            self.assertTrue(document.startswith(MANAGED_CONFIG_MARKER + "\n"))
            self.assertIn('forced_login_method = "chatgpt"', document)
            self.assertIn('cli_auth_credentials_store = "file"', document)
            self.assertIn("check_for_update_on_startup = false", document)
            self.assertIn('web_search = "disabled"', document)
            self.assertIn('[history]\npersistence = "none"', document)
            self.assertNotIn("disable_response_storage", document)
            self.assertNotIn("model_provider =", document)
            self.assertNotIn("[model_providers.", document)
            for feature in self.expected_disabled_features:
                self.assertIn(f"{feature} = false", document)
            self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_explicit_https_override_writes_managed_model_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "codex-home"
            path = configure_codex_provider_from_env(
                home,
                {
                    "CODEX_PROVIDER_BASE_URL": "https://Proxy.Example:443/codex/",
                    "CODEX_MODEL_PROVIDER": "private_proxy",
                    "CODEX_PROVIDER_NAME": "Private Codex Proxy",
                },
            )
            document = path.read_text(encoding="utf-8")

            self.assertIn('model_provider = "private_proxy"', document)
            self.assertIn('[model_providers."private_proxy"]', document)
            self.assertIn('name = "Private Codex Proxy"', document)
            self.assertIn('base_url = "https://proxy.example/codex"', document)
            self.assertIn('wire_api = "responses"', document)
            self.assertIn("requires_openai_auth = true", document)
            self.assertLess(
                document.index('model_provider = "private_proxy"'),
                document.index("[history]"),
            )
            self.assertLess(
                document.index("[features]"),
                document.index('[model_providers."private_proxy"]'),
            )

    @unittest.skipIf(tomllib is None, "tomllib is unavailable on Python 3.10")
    def test_rendered_toml_matches_the_managed_schema_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            default_path = configure_codex_provider_from_env(
                Path(tmp) / "default",
                {},
            )
            custom_path = configure_codex_provider_from_env(
                Path(tmp) / "custom",
                {
                    "CODEX_PROVIDER_BASE_URL": "https://proxy.example/codex",
                    "CODEX_MODEL_PROVIDER": "private_proxy",
                },
            )
            default = tomllib.loads(default_path.read_text(encoding="utf-8"))
            custom = tomllib.loads(custom_path.read_text(encoding="utf-8"))

            self.assertEqual(
                set(default),
                {
                    "forced_login_method",
                    "cli_auth_credentials_store",
                    "check_for_update_on_startup",
                    "web_search",
                    "history",
                    "features",
                },
            )
            self.assertEqual(default["history"], {"persistence": "none"})
            self.assertEqual(
                set(default["features"]),
                self.expected_disabled_features,
            )
            self.assertTrue(
                all(value is False for value in default["features"].values())
            )
            self.assertEqual(
                set(custom),
                set(default) | {"model_provider", "model_providers"},
            )
            self.assertEqual(custom["model_provider"], "private_proxy")
            self.assertEqual(
                custom["model_providers"]["private_proxy"]["base_url"],
                "https://proxy.example/codex",
            )

    @unittest.skipUnless(shutil.which("codex"), "Codex CLI is not installed")
    def test_codex_0_144_1_accepts_default_and_custom_rendered_configs(self) -> None:
        version = subprocess.run(
            ["codex", "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if version.stdout.strip() != "codex-cli 0.144.1":
            self.skipTest("schema integration is pinned to codex-cli 0.144.1")

        with tempfile.TemporaryDirectory() as tmp:
            for name, values in (
                ("default", {}),
                (
                    "custom",
                    {
                        "CODEX_PROVIDER_BASE_URL": "https://proxy.example/codex",
                        "CODEX_MODEL_PROVIDER": "private_proxy",
                    },
                ),
            ):
                with self.subTest(name=name):
                    home = Path(tmp) / name
                    configure_codex_provider_from_env(home, values)
                    env = dict(os.environ)
                    env["CODEX_HOME"] = str(home)
                    for variable in (
                        "OPENAI_API_KEY",
                        "OPENAI_API_TOKEN",
                        "OPENAI_ACCESS_TOKEN",
                        "CODEX_API_KEY",
                        "CODEX_ACCESS_TOKEN",
                        "CHATGPT_ACCESS_TOKEN",
                    ):
                        env.pop(variable, None)
                    result = subprocess.run(
                        ["codex", "features", "list"],
                        env=env,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(
                        result.returncode,
                        0,
                        result.stderr or result.stdout,
                    )

    def test_loopback_http_override_is_allowed_but_remote_http_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first_home = Path(tmp) / "loopback"
            path = configure_codex_provider_from_env(
                first_home,
                {"CODEX_PROVIDER_BASE_URL": "http://127.0.0.1:9000"},
            )
            self.assertIn(
                'base_url = "http://127.0.0.1:9000"',
                path.read_text(encoding="utf-8"),
            )

            with self.assertRaisesRegex(CodexProviderConfigError, "must use HTTPS"):
                configure_codex_provider_from_env(
                    Path(tmp) / "remote",
                    {"CODEX_PROVIDER_BASE_URL": "http://proxy.example"},
                )

    def test_testnet_rejects_a_custom_provider_before_login(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                CodexProviderConfigError,
                "testnet.*CODEX_PROVIDER_BASE_URL",
            ):
                configure_codex_provider_from_env(
                    Path(tmp) / "testnet",
                    {
                        "MYCOMESH_NETWORK_PROFILE": "testnet",
                        "CODEX_PROVIDER_BASE_URL": "https://proxy.example/codex",
                    },
                )

    def test_unmanaged_config_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "codex-home"
            home.mkdir(mode=0o700)
            path = home / "config.toml"
            original = 'model = "operator-owned"\n'
            path.write_text(original, encoding="utf-8")

            with self.assertRaisesRegex(CodexProviderConfigError, "unmanaged"):
                configure_codex_provider_from_env(home, {})

            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_default_host_codex_home_and_symlink_home_are_rejected(self) -> None:
        with self.assertRaisesRegex(CodexProviderConfigError, "non-isolated"):
            configure_codex_provider_from_env(Path.home() / ".codex", {})

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            link = Path(tmp) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(CodexProviderConfigError, "symbolic link"):
                configure_codex_provider_from_env(link, {})

    def test_secure_home_tightens_auth_permissions_without_reading_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "codex-home"
            configure_codex_provider_from_env(home, {})
            auth = home / "auth.json"
            auth.write_bytes(b"opaque-auth-data")
            auth.chmod(0o664)
            home.chmod(0o755)

            secured = secure_codex_home(home)

            self.assertEqual(secured, home)
            self.assertEqual(auth.read_bytes(), b"opaque-auth-data")
            self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)

    def test_auth_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "codex-home"
            configure_codex_provider_from_env(home, {})
            target = Path(tmp) / "outside-auth"
            target.write_text("do-not-follow", encoding="utf-8")
            (home / "auth.json").symlink_to(target)

            with self.assertRaisesRegex(CodexProviderConfigError, "symbolic link"):
                secure_codex_home(home)

            self.assertEqual(target.read_text(encoding="utf-8"), "do-not-follow")


if __name__ == "__main__":
    unittest.main()
