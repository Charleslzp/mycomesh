from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from scripts.configure_proxy_env import (
    ConfigurationError,
    SECP256K1_ORDER,
    check,
    configure,
    parse_env,
)


class ConfigureProxyEnvTest(unittest.TestCase):
    def test_configures_missing_values_without_disclosing_or_rotating_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            path.write_text(
                "# existing setting\n"
                "MYCOMESH_NODE_IMAGE=registry.example/node:1\n"
                "MYCOMESH_PROXY_BIND_ADDRESS=127.0.0.2\n",
                encoding="utf-8",
            )

            configure(path, rpc_url="https://rpc.example.test")
            first = path.read_text(encoding="utf-8")
            values = parse_env(first)
            check(path)
            configure(path, rpc_url="https://different.example.test")

            self.assertEqual(path.read_text(encoding="utf-8"), first)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE(path.with_name(path.name + ".lock").stat().st_mode),
                0o600,
            )
            self.assertIn("# existing setting", first)
            self.assertEqual(values["MYCOMESH_NODE_IMAGE"], "registry.example/node:1")
            self.assertEqual(values["MYCOMESH_PROXY_BIND_ADDRESS"], "127.0.0.2")
            self.assertEqual(values["MYCOMESH_SESSION_V4_ENABLED"], "true")
            self.assertEqual(values["MYCOMESH_SETTLEMENT_RPC_URL"], "https://rpc.example.test")
            self.assertEqual(values["ETH_RPC_URL"], "https://rpc.example.test")
            self.assertEqual(values["MYCOMESH_SESSION_RPC_URL"], "https://rpc.example.test")
            self.assertGreaterEqual(len(values["MYCOMESH_ADMIN_TOKEN"]), 32)
            self.assertGreaterEqual(len(values["MYCOMESH_SESSION_KEY_SECRET"]), 32)
            self.assertIn(values["MYCOMESH_POSTGRES_PASSWORD"], values["MYCOMESH_BILLING_DB"])
            private_key = values["MYCOMESH_SESSION_RELAYER_PRIVATE_KEY"]
            self.assertRegex(private_key, r"^0x[0-9a-f]{64}$")
            self.assertLess(int(private_key, 16), SECP256K1_ORDER)

    def test_check_fails_closed_without_mutating_missing_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            path.write_text("MYCOMESH_PROXY_BIND_ADDRESS=127.0.0.1\n", encoding="utf-8")
            path.chmod(0o600)
            before = path.read_bytes()
            with self.assertRaisesRegex(ConfigurationError, "restore the environment backup"):
                check(path)
            self.assertEqual(path.read_bytes(), before)

    def test_replaces_placeholders_and_rejects_weak_existing_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            placeholder = Path(directory) / "placeholder.env"
            placeholder.write_text(
                "MYCOMESH_ADMIN_TOKEN=change-me-admin-token\n"
                "MYCOMESH_POSTGRES_PASSWORD=change-me-database-password\n"
                "MYCOMESH_BILLING_DB=postgresql://mycomesh:change-me-database-password@postgres:5432/mycomesh\n",
                encoding="utf-8",
            )
            configure(placeholder, rpc_url="https://rpc.example.test")
            values = parse_env(placeholder.read_text(encoding="utf-8"))
            self.assertNotIn("change-me", values["MYCOMESH_ADMIN_TOKEN"])
            self.assertNotIn("change-me", values["MYCOMESH_BILLING_DB"])

            weak = Path(directory) / "weak.env"
            weak.write_text("MYCOMESH_ADMIN_TOKEN=short-but-not-placeholder\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "at least 32"):
                configure(weak, rpc_url="https://rpc.example.test")

    def test_preserves_strong_secret_that_contains_placeholder_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            admin_token = "prefix-change-me-example.com-strong-secret-value"
            path.write_text(f"MYCOMESH_ADMIN_TOKEN={admin_token}\n", encoding="utf-8")
            configure(path, rpc_url="https://rpc.example.test")
            self.assertEqual(
                parse_env(path.read_text(encoding="utf-8"))["MYCOMESH_ADMIN_TOKEN"],
                admin_token,
            )

    def test_preserves_standard_base64_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            admin_token = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF/QQ=="
            path.write_text(
                f"MYCOMESH_ADMIN_TOKEN={admin_token}\n",
                encoding="utf-8",
            )
            configure(path, rpc_url="https://rpc.example.test")
            self.assertEqual(
                parse_env(path.read_text(encoding="utf-8"))["MYCOMESH_ADMIN_TOKEN"],
                admin_token,
            )

    def test_rejects_secret_characters_that_compose_dotenv_can_reinterpret(self) -> None:
        unsafe_values = (
            "a" * 32 + "$EXPANDED",
            '"' + "a" * 32 + '"',
            "a" * 32 + "\\tail",
            " " + "a" * 32,
            "a" * 32 + " ",
            "a" * 32 + "#comment",
        )
        for index, value in enumerate(unsafe_values):
            with self.subTest(value_index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / ".env.deploy"
                path.write_text(
                    f"MYCOMESH_ADMIN_TOKEN={value}\n",
                    encoding="utf-8",
                )
                before = path.read_bytes()
                with self.assertRaisesRegex(ConfigurationError, "portable dotenv"):
                    configure(path, rpc_url="https://rpc.example.test")
                self.assertEqual(path.read_bytes(), before)

    def test_rejects_angle_wrapped_secret_without_rotating_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            path.write_text(
                "MYCOMESH_ADMIN_TOKEN=<" + "a" * 40 + ">\n",
                encoding="utf-8",
            )
            before = path.read_bytes()
            with self.assertRaisesRegex(ConfigurationError, "angle-bracket placeholder"):
                configure(path, rpc_url="https://rpc.example.test")
            self.assertEqual(path.read_bytes(), before)

    def test_rejects_non_https_rpc_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.env"
            target.write_text("# empty\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "credential-free HTTPS"):
                configure(target, rpc_url="http://rpc.example.test")

            link = Path(directory) / "link.env"
            os.symlink(target, link)
            with self.assertRaisesRegex(ConfigurationError, "regular file"):
                configure(link, rpc_url="https://rpc.example.test")

    def test_rejects_billing_dsn_that_does_not_match_postgres(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            path.write_text(
                "MYCOMESH_POSTGRES_PASSWORD=" + "a" * 32 + "\n"
                "MYCOMESH_BILLING_DB=postgresql://mycomesh:wrong@postgres:5432/mycomesh\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "must match"):
                configure(path, rpc_url="https://rpc.example.test")

    def test_rejects_public_proxy_bind_and_invalid_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "public.env"
            public.write_text(
                "MYCOMESH_PROXY_BIND_ADDRESS=0.0.0.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "IPv4 loopback"):
                configure(public, rpc_url="https://rpc.example.test")

            invalid = Path(directory) / "invalid.env"
            invalid.write_text(
                "MYCOMESH_PUBLIC_KEY_REGISTRATION=maybe\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "must be true or false"):
                configure(invalid, rpc_url="https://rpc.example.test")

    def test_check_rejects_group_readable_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            path.write_text("# new\n", encoding="utf-8")
            configure(path, rpc_url="https://rpc.example.test")
            path.chmod(0o640)
            with self.assertRaisesRegex(ConfigurationError, "group/others"):
                check(path)

    def test_check_rejects_host_environment_secret_and_bind_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.deploy"
            path.write_text("# new\n", encoding="utf-8")
            configure(path, rpc_url="https://rpc.example.test")
            values = parse_env(path.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(
                ConfigurationError,
                "MYCOMESH_PROXY_BIND_ADDRESS, MYCOMESH_SESSION_RELAYER_PRIVATE_KEY",
            ):
                check(
                    path,
                    environ={
                        "MYCOMESH_PROXY_BIND_ADDRESS": "0.0.0.0",
                        "MYCOMESH_SESSION_RELAYER_PRIVATE_KEY": "0x" + "1" * 64,
                    },
                )
            check(
                path,
                environ={
                    "MYCOMESH_PROXY_BIND_ADDRESS": values[
                        "MYCOMESH_PROXY_BIND_ADDRESS"
                    ],
                    "MYCOMESH_SESSION_RELAYER_PRIVATE_KEY": values[
                        "MYCOMESH_SESSION_RELAYER_PRIVATE_KEY"
                    ],
                },
            )


if __name__ == "__main__":
    unittest.main()
