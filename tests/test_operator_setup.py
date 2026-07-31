import json
import stat
import tempfile
import unittest
import urllib.request
from pathlib import Path
from threading import Thread

from gateway.operator_setup import (
    OperatorConfigError,
    _WizardServer,
    load_operator_config,
    normalize_operator_config,
    shell_env,
    write_operator_config,
)


class OperatorConfigTest(unittest.TestCase):
    def test_normalizes_public_address_and_period_budget(self) -> None:
        config = normalize_operator_config(
            {
                "payout_address": "0x" + "AB" * 20,
                "max_concurrency": "7",
                "usage_limit_usdc": "12.345678",
                "usage_period_seconds": "86400",
            },
            role="provider",
        )
        self.assertEqual(config["payout_address"], "0x" + "ab" * 20)
        self.assertEqual(config["max_concurrency"], 7)
        self.assertEqual(config["usage_limit_units"], 12_345_678)
        self.assertEqual(config["usage_period_seconds"], 86_400)

    def test_private_key_fields_are_rejected(self) -> None:
        with self.assertRaisesRegex(OperatorConfigError, "private keys"):
            normalize_operator_config(
                {"private_key": "0x" + "11" * 32},
                role="relay",
            )

    def test_non_object_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("[]", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(OperatorConfigError, "JSON object"):
                load_operator_config(path, role="provider")

    def test_profile_is_private_and_shell_env_is_role_specific(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "provider.json"
            config = normalize_operator_config(
                {
                    "payout_address": "0x" + "12" * 20,
                    "max_concurrency": 3,
                    "usage_limit_usdc": "1",
                    "usage_period_seconds": 3600,
                },
                role="provider",
            )
            write_operator_config(path, config)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            loaded = load_operator_config(path, role="provider")
            self.assertEqual(loaded, config)
            env = shell_env(loaded, role="provider")
            self.assertIn("MYCOMESH_PROVIDER_CAPACITY=3", env)
            self.assertIn("MYCOMESH_PROVIDER_USAGE_LIMIT_UNITS=1000000", env)
            self.assertNotIn("PRIVATE", env.upper())
            relay_env = shell_env(
                normalize_operator_config(
                    {"max_concurrency": 5, "usage_period_seconds": 3600},
                    role="relay",
                ),
                role="relay",
            )
            self.assertIn("MYCOMESH_RELAY_CONSUMER_MAX_IN_FLIGHT=5", relay_env)
            self.assertIn("MYCOMESH_RELAY_CONTROL_MAX_CONNECTIONS=5", relay_env)

    def test_loopback_wizard_saves_once_with_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "relay.json"
            server = _WizardServer(("127.0.0.1", 0), role="relay", output=output, token="test-token")
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                page = urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/?role=relay&token=test-token"
                ).read()
                self.assertIn(b"Public payout address", page)
                payload = json.dumps(
                    {
                        "token": "test-token",
                        "payout_address": "0x" + "34" * 20,
                        "max_concurrency": "4",
                        "usage_limit_usdc": "2.5",
                        "usage_period_seconds": "7200",
                    }
                ).encode()
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    data=payload,
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                response = json.loads(urllib.request.urlopen(request).read())
                self.assertTrue(response["ok"])
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(load_operator_config(output, role="relay")["max_concurrency"], 4)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
