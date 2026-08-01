import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from gateway.operator_setup import (
    OperatorConfigError,
    _WizardServer,
    _new_provider_identity,
    _html_page,
    load_operator_config,
    load_protected_provider_profile,
    normalize_operator_config,
    run_wizard,
    shell_env,
    write_operator_config,
)
from gateway.provider_identity import (
    provider_identity_fingerprint,
    validate_provider_evm_identity,
    write_provider_evm_identity,
)


class OperatorConfigTest(unittest.TestCase):
    def test_operator_setup_import_does_not_require_httpx(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.modules['httpx'] = None; import gateway.operator_setup",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_first_provider_page_defaults_to_generated_wallet_with_visible_key(self) -> None:
        identity = _new_provider_identity()
        page = _html_page(
            role="provider",
            token="test-token",
            generated_identity=identity,
        )
        self.assertIn(b"Create a new local wallet", page)
        self.assertIn(b"Import an existing private key", page)
        self.assertIn(b'<option value="generated" selected>', page)
        self.assertIn(b"there is no separate payout address", page)
        self.assertIn(b"Maximum concurrent admitted requests", page)
        self.assertIn(b"Save settings", page)
        self.assertIn(b"class=\"danger\"", page)
        self.assertIn(b"private key is displayed only once", page)
        self.assertIn(b"I have securely saved this private key", page)
        self.assertIn(b"first 4 and last 8 private-key characters", page)
        self.assertIn(b'id="backup_confirmation"', page)
        self.assertIn(b"disabled", page)
        self.assertIn(b"backupSaved.addEventListener('change'", page)
        self.assertIn(identity.private_key.encode(), page)
        self.assertNotIn(provider_identity_fingerprint(identity).encode(), page)

    def test_existing_provider_page_never_renders_a_blank_private_key_field(self) -> None:
        identity = _new_provider_identity()
        page = _html_page(
            role="provider",
            token="test-token",
            current={
                "payout_address": identity.address,
                "max_concurrency": 3,
                "usage_period_seconds": 3600,
            },
            generated_identity=None,
            identity_locked=True,
        )
        self.assertIn(b"Protected Provider wallet", page)
        self.assertIn(identity.address.encode(), page)
        self.assertIn(b"private key is intentionally never displayed again", page)
        self.assertNotIn(b"Create a new local wallet", page)
        self.assertNotIn(b"Import an existing private key", page)
        self.assertNotIn(b'id="generated_private_key"', page)
        self.assertNotIn(b'id="private_key"', page)

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

    def test_provider_wallet_source_is_normalized_without_a_private_key(self) -> None:
        config = normalize_operator_config(
            {
                "wallet_source": "imported",
                "wallet_address": "0x" + "12" * 20,
                "wallet_fingerprint": "abcd...1234",
                "max_concurrency": 2,
                "usage_period_seconds": 60,
            },
            role="provider",
        )
        self.assertEqual(config["wallet_source"], "imported")
        self.assertEqual(config["payout_address"], "0x" + "12" * 20)
        self.assertNotIn("private_key", config)

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

    def test_protected_profile_requires_identity_and_uses_its_address(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "provider.json"
            identity_path = root / "provider-evm-identity.json"
            identity = _new_provider_identity()
            write_provider_evm_identity(identity_path, identity)

            profile = load_protected_provider_profile(config_path, identity_path)
            self.assertEqual(profile["wallet_source"], "existing")
            self.assertEqual(profile["payout_address"], identity.address)
            self.assertEqual(profile["max_concurrency"], 1)

            mismatched = normalize_operator_config(
                {
                    "wallet_source": "existing",
                    "wallet_address": _new_provider_identity().address,
                    "max_concurrency": 2,
                    "usage_period_seconds": 3600,
                },
                role="provider",
            )
            write_operator_config(config_path, mismatched)
            with self.assertRaisesRegex(OperatorConfigError, "does not match"):
                load_protected_provider_profile(config_path, identity_path)

    def test_stale_public_profile_does_not_lock_a_missing_wallet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "provider.json"
            identity_path = root / "provider-evm-identity.json"
            write_operator_config(
                output,
                normalize_operator_config(
                    {
                        "wallet_source": "existing",
                        "wallet_address": _new_provider_identity().address,
                        "max_concurrency": 2,
                        "usage_period_seconds": 3600,
                    },
                    role="provider",
                ),
            )
            pending = _new_provider_identity()
            server = _WizardServer(
                ("127.0.0.1", 0),
                role="provider",
                output=output,
                token="provider-token",
                identity_output=identity_path,
                pending_identity=pending,
            )
            try:
                self.assertFalse(server.identity_locked)
            finally:
                server.server_close()

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
                self.assertIn(b"Leave blank to use the payout identity", page)
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

    def test_provider_generated_wallet_requires_backup_confirmation_and_stages_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "provider.json"
            identity_path = root / "provider-evm-identity.json"
            identity = _new_provider_identity()
            server = _WizardServer(
                ("127.0.0.1", 0),
                role="provider",
                output=output,
                token="provider-token",
                identity_output=identity_path,
                pending_identity=identity,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                base = {
                    "token": "provider-token",
                    "wallet_source": "generated",
                    "max_concurrency": "2",
                    "usage_period_seconds": "3600",
                }
                missing_saved = dict(
                    base,
                    backup_confirmation=provider_identity_fingerprint(identity),
                )
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    data=json.dumps(missing_saved).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as missing_error:
                    urllib.request.urlopen(request)
                self.assertIn(b"securely saved", missing_error.exception.read())
                self.assertFalse(identity_path.exists())

                bad = dict(
                    base,
                    backup_saved="yes",
                    backup_confirmation="0000...00000000",
                )
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    data=json.dumps(bad).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as confirmation_error:
                    urllib.request.urlopen(request)
                self.assertIn(b"first 4 and last 8", confirmation_error.exception.read())
                self.assertFalse(identity_path.exists())

                invalid_settings = dict(
                    base,
                    backup_saved="yes",
                    backup_confirmation=provider_identity_fingerprint(identity),
                    max_concurrency="0",
                )
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    data=json.dumps(invalid_settings).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as settings_error:
                    urllib.request.urlopen(request)
                self.assertIn(b"max_concurrency", settings_error.exception.read())
                self.assertFalse(identity_path.exists())

                good = dict(
                    base,
                    backup_saved="yes",
                    backup_confirmation=provider_identity_fingerprint(identity),
                )
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    data=json.dumps(good).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                response = json.loads(urllib.request.urlopen(request).read())
                self.assertTrue(response["ok"])
                saved = load_operator_config(output, role="provider")
                self.assertEqual(saved["wallet_source"], "generated")
                self.assertEqual(saved["payout_address"], identity.address)
                self.assertNotIn(identity.private_key, output.read_text(encoding="utf-8"))
                self.assertEqual(validate_provider_evm_identity(identity_path), identity)
            finally:
                server.shutdown()
                server.server_close()

    def test_provider_existing_wallet_accepts_empty_hidden_wallet_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "provider.json"
            identity = _new_provider_identity()
            identity_path = root / "provider-evm-identity.json"
            write_provider_evm_identity(identity_path, identity)
            server = _WizardServer(
                ("127.0.0.1", 0),
                role="provider",
                output=output,
                token="provider-token",
                identity_output=identity_path,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                payload = {
                    "token": "provider-token",
                    "wallet_source": "existing",
                    "private_key": "",
                    "backup_confirmation": "",
                    "max_concurrency": "2",
                    "usage_period_seconds": "3600",
                }
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    data=json.dumps(payload).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                self.assertTrue(json.loads(urllib.request.urlopen(request).read())["ok"])
                saved = load_operator_config(output, role="provider")
                self.assertEqual(saved["wallet_source"], "existing")
                self.assertEqual(saved["payout_address"], identity.address)
            finally:
                server.shutdown()
                server.server_close()

    def test_existing_provider_wallet_rejects_generated_or_imported_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "provider.json"
            identity_path = root / "provider-evm-identity.json"
            existing = _new_provider_identity()
            replacement = _new_provider_identity()
            write_provider_evm_identity(identity_path, existing)
            server = _WizardServer(
                ("127.0.0.1", 0),
                role="provider",
                output=output,
                token="provider-token",
                identity_output=identity_path,
                pending_identity=replacement,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                for payload in (
                    {
                        "token": "provider-token",
                        "wallet_source": "generated",
                        "backup_saved": "yes",
                        "backup_confirmation": provider_identity_fingerprint(replacement),
                        "max_concurrency": "2",
                        "usage_period_seconds": "3600",
                    },
                    {
                        "token": "provider-token",
                        "wallet_source": "imported",
                        "private_key": replacement.private_key,
                        "max_concurrency": "2",
                        "usage_period_seconds": "3600",
                    },
                ):
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/config",
                        data=json.dumps(payload).encode(),
                        headers={"content-type": "application/json"},
                        method="POST",
                    )
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(request)
                    self.assertIn(b"cannot replace it", error.exception.read())
                self.assertEqual(validate_provider_evm_identity(identity_path), existing)
                self.assertFalse(output.exists())
            finally:
                server.shutdown()
                server.server_close()

    def test_provider_imported_wallet_does_not_require_generated_backup_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "provider.json"
            identity_path = root / "provider-evm-identity.json"
            identity = _new_provider_identity()
            server = _WizardServer(
                ("127.0.0.1", 0),
                role="provider",
                output=output,
                token="provider-token",
                identity_output=identity_path,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                payload = {
                    "token": "provider-token",
                    "wallet_source": "imported",
                    "private_key": identity.private_key,
                    "max_concurrency": "2",
                    "usage_period_seconds": "3600",
                }
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    data=json.dumps(payload).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                self.assertTrue(json.loads(urllib.request.urlopen(request).read())["ok"])
                self.assertEqual(validate_provider_evm_identity(identity_path), identity)
            finally:
                server.shutdown()
                server.server_close()

    def test_wizard_port_zero_prints_and_opens_the_allocated_url(self) -> None:
        class FakeServer:
            server_address = ("127.0.0.1", 43123)
            saved = {"role": "provider"}

            def serve_forever(self, poll_interval: float) -> None:
                self.poll_interval = poll_interval

            def server_close(self) -> None:
                self.closed = True

        fake_server = FakeServer()
        output = io.StringIO()
        with patch("gateway.operator_setup._WizardServer", return_value=fake_server), patch(
            "gateway.operator_setup._open_browser"
        ) as open_browser, redirect_stdout(output):
            result = run_wizard(
                role="provider",
                output="/tmp/provider-settings.json",
                host="127.0.0.1",
                port=0,
            )

        self.assertEqual(result, {"role": "provider"})
        printed_url = output.getvalue().strip().split(": ", 1)[1]
        self.assertIn("http://127.0.0.1:43123/", printed_url)
        open_browser.assert_called_once_with(printed_url)
        self.assertEqual(fake_server.poll_interval, 0.1)
        self.assertTrue(fake_server.closed)

    def test_container_bind_requires_opt_in_and_uses_caller_token_in_loopback_url(self) -> None:
        with self.assertRaisesRegex(OperatorConfigError, "must bind to loopback"):
            run_wizard(
                role="relay",
                output="/tmp/relay-settings.json",
                host="0.0.0.0",
                port=8765,
                no_browser=True,
            )

        class FakeServer:
            server_address = ("0.0.0.0", 8765)
            saved = {"role": "relay"}

            def serve_forever(self, poll_interval: float) -> None:
                self.poll_interval = poll_interval

            def server_close(self) -> None:
                self.closed = True

        token = "a" * 64
        fake_server = FakeServer()
        output = io.StringIO()
        with patch(
            "gateway.operator_setup._WizardServer", return_value=fake_server
        ) as factory, redirect_stdout(output):
            result = run_wizard(
                role="relay",
                output="/tmp/relay-settings.json",
                host="0.0.0.0",
                port=8765,
                no_browser=True,
                token=token,
                display_host="127.0.0.1",
                allow_container_bind=True,
            )

        self.assertEqual(result, {"role": "relay"})
        self.assertIn(f"http://127.0.0.1:8765/?role=relay&token={token}", output.getvalue())
        self.assertEqual(factory.call_args.args[0], ("0.0.0.0", 8765))
        self.assertEqual(factory.call_args.kwargs["token"], token)

    def test_caller_supplied_onboarding_token_is_validated(self) -> None:
        with self.assertRaisesRegex(OperatorConfigError, "URL-safe"):
            run_wizard(
                role="relay",
                output="/tmp/relay-settings.json",
                host="127.0.0.1",
                port=0,
                no_browser=True,
                token="too-short",
            )


if __name__ == "__main__":
    unittest.main()
