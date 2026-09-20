"""Offline regressions for first-run setup and no-click Provider restarts."""

import json
import http.client
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from gateway.operator_setup import (
    _html_page,
    _new_provider_identity,
    _WizardServer,
    OperatorConfigError,
    provider_authorization_plan,
    load_protected_provider_profile,
    normalize_operator_config,
    write_operator_config,
)
from gateway.provider_identity import provider_identity_fingerprint, write_provider_evm_identity
from gateway.chain import encode_contract_call
from gateway.provider_authorization_state import ProviderAuthorizationState, AuthorizationStateError


ROOT = Path(__file__).resolve().parents[1]


def shell_function(path, name):
    source = path.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", source, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"missing function: {name}")
    return match.group(0)


class ProviderProfileReuseTest(unittest.TestCase):
    def test_only_matching_persisted_profiles_are_reusable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = _new_provider_identity()
            identity_path = root / "identity.json"
            config_path = root / "settings.json"
            write_provider_evm_identity(identity_path, identity)
            self.assertFalse(load_protected_provider_profile(config_path, identity_path)["settings_reusable"])
            for version in (8, 9):
                config = normalize_operator_config({
                    "settlement_version": version,
                    "payout_address": "0x" + "ab" * 20,
                    "provider_signer_address": identity.address,
                    "wallet_fingerprint": provider_identity_fingerprint(identity),
                    "max_concurrency": 3,
                }, role="provider")
                write_operator_config(config_path, config)
                profile = load_protected_provider_profile(config_path, identity_path)
                self.assertTrue(profile["settings_reusable"])
                self.assertEqual(profile["max_concurrency"], 3)
                self.assertNotIn(identity.private_key, json.dumps(profile))
                for field, value in (
                    ("provider_signer_address", "0x" + "cd" * 20),
                    ("wallet_fingerprint", "incorrect"),
                    ("payout_address", None),
                ):
                    with self.subTest(version=version, field=field):
                        write_operator_config(config_path, {**config, field: value, "settings_reusable": True})
                        self.assertFalse(load_protected_provider_profile(config_path, identity_path)["settings_reusable"])
            config_path.write_text("not JSON", encoding="utf-8")
            self.assertFalse(load_protected_provider_profile(config_path, identity_path)["settings_reusable"])

    def test_capacity_is_optional_and_no_provider_key_is_exposed(self):
        identity = _new_provider_identity()
        for version in (8, 9):
            for locked in (False, True):
                with self.subTest(version=version, locked=locked):
                    page = _html_page(
                        role="provider", token="test-token", settlement_version=version,
                        generated_identity=identity, protected_identity=identity,
                        identity_locked=locked,
                    ).decode()
                    self.assertIn("Capacity and usage limits (optional)", page)
                    self.assertIn('<details ><summary>', page)
                    self.assertNotIn("<details open", page)
                    self.assertIn('value="1" required', page)
                    self.assertIn("does not complete that authorization", page)
                    self.assertIn("Return to the terminal to finish sign-in and connection checks", page)
                    self.assertNotIn(identity.private_key, page)
                    self.assertNotIn('id="private_key"', page)
                    self.assertNotIn('id="backup_confirmation"', page)

    def test_model_configuration_is_escaped_and_never_claimed_as_probed(self):
        identity = _new_provider_identity()
        network = SimpleNamespace(
            deployment=SimpleNamespace(chain_id=31337, settlement="0x" + "33" * 20),
            public_model_ids=("gpt-5.6-sol", "<script>untrusted</script>"),
        )
        page = _html_page(role="provider", token="test-token", settlement_version=9,
                          generated_identity=identity, authorization_network=network).decode()
        self.assertIn("gpt-5.6-sol", page)
        self.assertIn("&lt;script&gt;untrusted&lt;/script&gt;", page)
        self.assertNotIn("<script>untrusted</script>", page)
        self.assertIn("Capability evidence: configuration only.", page)
        self.assertIn("Online status not verified", page)
        self.assertIn("have not been checked on this page", page)


class ProviderRestartShellTest(unittest.TestCase):
    def test_authorization_state_path_does_not_follow_checkout_or_settings(self):
        function = shell_function(ROOT / "scripts/provider-onboarding-container.sh", "provider_authorization_state_directory")
        with tempfile.TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment.pop("MYCOMESH_PROVIDER_AUTHORIZATION_STATE_DIR", None)
            def resolve_path(checkout, override=None):
                values = environment.copy()
                if override is not None:
                    values["MYCOMESH_PROVIDER_AUTHORIZATION_STATE_DIR"] = override
                return subprocess.run(["bash", "-c", f"""
set -eu
output_dir={shlex.quote(checkout)}
die() {{ printf '%s\\n' "$*" >&2; exit 64; }}
{function}
provider_authorization_state_directory
"""], env=values, text=True, capture_output=True, timeout=5)
            # Resolve only: never create or touch the real user's home state.
            first = resolve_path(directory + "/release-a/settings")
            upgraded = resolve_path(directory + "/release-b/settings")
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(upgraded.stdout, first.stdout)
            self.assertEqual(first.stdout, str(Path.home() / ".mycomesh/provider/authorization-state"))
            explicit = directory + "/stable-authorization"
            self.assertEqual(resolve_path(directory + "/release-c", explicit).stdout, explicit)
            self.assertEqual(resolve_path(directory + "/release-c", "relative-state").returncode, 64)

    def restore(self, profile, *, force=0, configure_only=0, export_ok=True):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "settings.json"
            functions = shell_function(ROOT / "scripts/install-provider.sh", "restore_protected_provider_config")
            result = subprocess.run(["bash", "-c", f"""
set -eu
DRY_RUN=0
FORCE_PROVIDER_CONFIG={force}
CONFIGURE_ONLY={configure_only}
CONFIGURE_PROVIDER=1
PROVIDER_PROTECTED_WALLET=0
PUBLIC_PROVIDER_SETTLEMENT_VERSION=8
PROVIDER_OPERATOR_CONFIG={shlex.quote(str(config_path))}
die() {{ printf '%s\\n' "$*" >&2; exit 64; }}
export_protected_provider_config() {{ {'cat' if export_ok else 'return 1'}; }}
{functions}
restore_protected_provider_config
printf 'CONFIGURE_PROVIDER=%s\\n' "$CONFIGURE_PROVIDER"
"""], input=json.dumps(profile) if profile is not None else "", text=True, capture_output=True, timeout=5)
            return result

    def test_restart_reuses_only_validated_matching_protocol(self):
        for profile, expected in (
            ({"settlement_version": 8, "settings_reusable": True}, 0),
            ({"settlement_version": 9, "settings_reusable": True}, 1),
            ({"settlement_version": 8, "settings_reusable": False}, 1),
            ({"settlement_version": 8}, 1),
            (None, 1),
        ):
            with self.subTest(profile=profile):
                result = self.restore(profile)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"CONFIGURE_PROVIDER={expected}", result.stdout)

    def test_explicit_configuration_still_opens_the_wizard(self):
        for options in ({"force": 1}, {"configure_only": 1}):
            with self.subTest(options=options):
                result = self.restore({"settlement_version": 8, "settings_reusable": True}, **options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("CONFIGURE_PROVIDER=1", result.stdout)

    def test_failed_protected_volume_inspection_cannot_be_reported_ready(self):
        result = self.restore(None, export_ok=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn("refusing to replace", result.stderr)
        self.assertNotIn("CONFIGURE_PROVIDER=", result.stdout)

    def test_legacy_config_validation_is_not_inverted(self):
        function = shell_function(ROOT / "scripts/bootstrap-provider.sh", "bootstrap_prepare_legacy_provider_config")
        for valid, configure, expected in ((True, False, "reused"), (False, False, "wizard"), (True, True, "wizard")):
            with self.subTest(valid=valid, configure=configure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "gateway").mkdir()
                (root / "gateway/operator_setup.py").touch()
                (root / "settings.json").write_text("fixture", encoding="utf-8")
                result = subprocess.run(["bash", "-c", f"""
set -eu
source_dir={shlex.quote(str(root))}
MYCOMESH_PROVIDER_OPERATOR_CONFIG="$source_dir/settings.json"
provider_python=fake_python
bootstrap_installer_supports_provider_config() {{ return 1; }}
bootstrap_ensure_provider_host_python() {{ :; }}
bootstrap_installer_has_arg() {{ [[ "$1" == --configure && {int(configure)} == 1 ]]; }}
fake_python() {{
  if [[ "$3" == env ]]; then return {0 if valid else 1}; fi
  printf 'wizard\\n'
}}
{function}
bootstrap_prepare_legacy_provider_config
"""], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("wizard\n" in result.stdout, expected == "wizard")
                self.assertEqual("Using existing Provider settings" in result.stdout, expected == "reused")

    def test_first_setup_persists_to_volume_before_wallet_step(self):
        installer = (ROOT / "scripts/install-provider.sh").read_text()
        start = installer.index('  run "${wizard_args[@]}"')
        persist = installer.index('  make_target provider-config-apply-image', start)
        authorize = installer.index('  ensure_provider_authorization', persist)
        self.assertLess(persist, authorize)

    def test_authorization_commands_use_the_same_pinned_provider_image(self):
        source = (ROOT / "Makefile").read_text()
        onboard = source.split("provider-onboard: provider-configure", 1)[1].split("\nprovider-start:", 1)[0]
        self.assertNotIn("provider-authorize", onboard)
        with tempfile.TemporaryDirectory() as directory:
            for target in ("provider-authorize", "provider-authorization-status"):
                with self.subTest(target=target):
                    result = subprocess.run([
                        "make", "-n", "-f", str(ROOT / "Makefile"), target,
                        "PROVIDER_IMAGE=fixture/provider@sha256:abc",
                        f"DEPLOY_ENV_FILE={directory}/fixture.env",
                    ], cwd=ROOT, text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("MYCOMESH_PROVIDER_IMAGE=fixture/provider@sha256:abc", result.stdout)

    def test_v8_v9_withdrawal_cannot_fall_back_to_an_internal_identity(self):
        makefile = (ROOT / "Makefile").read_text()
        target = makefile.split("provider-claim-payout: deploy-env", 1)[1].split("\nproxy-identity:", 1)[0]
        guard = target.split('settlement_version="', 1)[1].split("claim_command=", 1)[0]
        guard = 'settlement_version="' + guard
        guard = guard.replace("$$", "$").replace("\\\n", "\n")
        for version in (8, 9):
            with self.subTest(version=version):
                env = os.environ.copy()
                env["MYCOMESH_SETTLEMENT_VERSION"] = str(version)
                result = subprocess.run(["sh", "-ec", guard], env=env, text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertIn(f"V{version} payout requires the external payout wallet", result.stderr)

    def test_restarts_resume_only_unfinished_authorization_and_rpc_failure_is_not_ready(self):
        function = shell_function(ROOT / "scripts/install-provider.sh", "ensure_provider_authorization")
        for authorized, rpc_ok in ((True, True), (False, True), (False, False)):
            with self.subTest(authorized=authorized, rpc_ok=rpc_ok):
                output = json.dumps({"authorized": authorized})
                result = subprocess.run(["bash", "-c", f"""
set -eu
DRY_RUN=0
NO_BROWSER=1
PUBLIC_PROVIDER_SETTLEMENT_VERSION=8
PROVIDER_PROTECTED_WALLET=0
PROVIDER_ONBOARDING_HELPER=fixture-wizard
PROVIDER_IMAGE=fixture-image
PROVIDER_OPERATOR_CONFIG=/fixture/settings.json
PROVIDER_IDENTITY_SOURCE=/fixture/identity.json
PUBLIC_PROVIDER_NETWORK_CONFIG=/fixture/network.json
die() {{ printf '%s\\n' "$*" >&2; exit 64; }}
make_target() {{ if [[ "$1" == provider-authorization-status ]]; then printf '%s' {shlex.quote(output)}; return {0 if rpc_ok else 1}; fi; }}
restore_protected_provider_config() {{ PROVIDER_PROTECTED_WALLET=1; }}
run() {{ printf 'WIZARD %s\\n' "$*"; }}
{function}
ensure_provider_authorization
"""], text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0 if rpc_ok else 64, result.stderr)
                self.assertEqual("WIZARD" in result.stdout, not authorized and rpc_ok)
                if not authorized and rpc_ok:
                    self.assertIn("--authorization-only", result.stdout)
                    self.assertIn("--protected-wallet", result.stdout)


class ProviderWalletHttpTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.config_path = root / "settings.json"
        self.identity_path = root / "identity.json"
        self.identity = _new_provider_identity()
        write_provider_evm_identity(self.identity_path, self.identity)
        self.config = normalize_operator_config({
            "settlement_version": 8, "payout_address": "0x" + "11" * 20,
            "provider_signer_address": self.identity.address,
            "wallet_fingerprint": provider_identity_fingerprint(self.identity),
        }, role="provider")
        write_operator_config(self.config_path, self.config)
        self.network = SimpleNamespace(
            deployment=SimpleNamespace(protocol_version=8, chain_id=31337, settlement="0x" + "33" * 20),
            settlement_rpc_url="https://fixture.invalid",
        )
        self.server = _WizardServer(
            ("127.0.0.1", 0), role="provider", output=self.config_path,
            token="test-token", identity_output=self.identity_path,
            settlement_version=8, authorization_network=self.network,
            authorization_state_path=root / "authorization" / "intents.sqlite3",
        )
        self.thread = Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.directory.cleanup()

    def post(self, path="/api/provider-authorization", *, fields=None, origin=None, host=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/json", "Origin": origin or self.origin}
        if host is not None:
            headers["Host"] = host
        raw = {**self.config, "token": "test-token", **(fields or {})}
        try:
            connection.request("POST", path, body=json.dumps(raw), headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_browser_plan_is_pinned_unsigned_and_does_not_mutate_profile(self):
        original = self.config_path.read_bytes()
        with patch("gateway.operator_setup.rpc_int", return_value=31337), patch("gateway.operator_setup.provider_signer_authorized", return_value=False) as authorized:
            status, result = self.post(fields={"provider_signer_address": "0x" + "55" * 20})
        self.assertEqual(status, 200)
        self.assertFalse(result["authorized"])
        transaction = result["plan"]["transaction"]
        self.assertEqual(transaction, {
            "chainId": "0x7a69", "from": self.config["payout_address"], "to": self.network.deployment.settlement,
            "value": "0x0", "data": encode_contract_call("authorizeProviderSigner(address)", [self.identity.address]),
        })
        self.assertEqual(authorized.call_args.args[3], self.identity.address)
        self.assertNotIn(self.identity.private_key, json.dumps(result))
        self.assertEqual(self.config_path.read_bytes(), original)
        self.assertIsNone(self.server.saved)

    def test_wrong_origin_host_token_and_rpc_chain_fail_closed(self):
        with patch("gateway.operator_setup.rpc_int", return_value=1) as rpc:
            for values in ({"origin": "https://evil.example"}, {"host": "evil.example"}, {"fields": {"token": "wrong"}}):
                with self.subTest(values=values):
                    status, result = self.post(**values)
                    self.assertIn(status, (400, 403))
                    self.assertFalse(result["ok"])
            rpc.assert_not_called()
            status, result = self.post()
            self.assertEqual(status, 400)
            self.assertIn("does not match", result["error"])

    def test_ephemeral_identity_cannot_be_authorized(self):
        self.server.authorization_identity_persisted = False
        self.server.identity_locked = True  # A staged file write must not upgrade persistence.
        with patch("gateway.operator_setup.rpc_int") as rpc:
            status, result = self.post()
        self.assertEqual(status, 400)
        self.assertIn("persist", result["error"])
        rpc.assert_not_called()

    def test_send_intent_is_atomic_and_wrong_cancellation_cannot_release_it(self):
        with patch("gateway.operator_setup.rpc_int", return_value=31337), patch("gateway.operator_setup.provider_signer_authorized", return_value=False):
            status, first = self.post("/api/provider-authorization-intent", fields={"action": "reserve"})
            self.assertEqual(status, 200)
            self.assertTrue(first["pending"])
            status, _ = self.post("/api/provider-authorization-intent", fields={"action": "reserve"})
            self.assertEqual(status, 400)
            status, _ = self.post("/api/provider-authorization-intent", fields={"action": "rejected", "intent_id": "wrong", "wallet_error_code": 4001})
            self.assertEqual(status, 400)
            status, status_body = self.post()
            self.assertTrue(status_body["pending"])
            status, cancelled = self.post("/api/provider-authorization-intent", fields={"action": "rejected", "intent_id": first["intent_id"], "wallet_error_code": 4001})
            self.assertEqual(status, 200)
            self.assertFalse(cancelled["pending"])

    def test_authorization_resume_cannot_change_saved_capacity_or_wallet(self):
        self.server.authorization_only = True
        with patch("gateway.operator_setup.rpc_int", return_value=31337), patch("gateway.operator_setup.provider_signer_authorized", return_value=True):
            status, _ = self.post("/api/config", fields={"payout_address": "0x" + "77" * 20})
            self.assertEqual(status, 400)
            status, _ = self.post("/api/config", fields={"max_concurrency": 42})
            self.assertEqual(status, 200)
        self.assertEqual(self.server.saved["max_concurrency"], self.config["max_concurrency"])

    def test_unauthorized_wallet_cannot_complete_second_step(self):
        with patch("gateway.operator_setup.rpc_int", return_value=31337), patch("gateway.operator_setup.provider_signer_authorized", return_value=False):
            status, result = self.post("/api/config")
        self.assertEqual(status, 400)
        self.assertIn("one-time wallet authorization", result["error"])
        self.assertIsNone(self.server.saved)

    def test_verified_authorization_allows_save_but_never_claims_online(self):
        with patch("gateway.operator_setup.rpc_int", return_value=31337), patch("gateway.operator_setup.provider_signer_authorized", return_value=True):
            status, result = self.post("/api/config")
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertTrue(result["authorization_verified"])
        self.assertNotIn("online", result)
        self.assertIsNotNone(self.server.saved)

    def test_settings_only_save_does_not_claim_wallet_authorization(self):
        self.server.authorization_network = None
        with patch("gateway.operator_setup.provider_signer_authorized") as authorized:
            status, result = self.post("/api/config")
        self.assertEqual(status, 200)
        self.assertFalse(result["authorization_verified"])
        authorized.assert_not_called()
        self.assertNotIn("online", result)

    def test_wizard_health_is_not_an_authorization_or_network_readiness_check(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {"ok": True, "role": "provider"})
        finally:
            connection.close()

    def test_offline_plan_requires_matching_version_and_persisted_identity(self):
        with patch("gateway.operator_setup.load_provider_network_config", return_value=self.network), patch("gateway.operator_setup.rpc_int") as rpc:
            plan = provider_authorization_plan(self.config_path, self.identity_path, "fixture.json")
            self.assertEqual(plan["transaction"]["from"], self.config["payout_address"])
            self.assertNotIn(self.identity.private_key, json.dumps(plan))
            rpc.assert_not_called()
            self.network.deployment.protocol_version = 9
            with self.assertRaisesRegex(OperatorConfigError, "match"):
                provider_authorization_plan(self.config_path, self.identity_path, "fixture.json")
        makefile = (ROOT / "Makefile").read_text()
        target = makefile.split("provider-authorize: deploy-env", 1)[1].split("provider-operator-config-export-image:", 1)[0]
        self.assertIn("provider-authorization-plan", target)
        self.assertNotIn("private-key", target)
        self.assertNotIn("read -r", target)


class ProviderSendFenceTest(unittest.TestCase):
    def test_parallel_claim_and_restart_keep_exactly_one_durable_send_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "intents.sqlite3"
            first = ProviderAuthorizationState(path)
            plan = {"transaction": {"chainId": "0x1", "from": "0x" + "11" * 20, "to": "0x" + "22" * 20, "data": "0x12345678", "value": "0x0"}}
            def reserve(_):
                try:
                    return ProviderAuthorizationState(path).reserve(plan)
                except AuthorizationStateError:
                    return None
            with ThreadPoolExecutor(max_workers=8) as pool:
                intents = list(pool.map(reserve, range(8)))
            self.assertEqual(sum(intent is not None for intent in intents), 1)
            restarted = ProviderAuthorizationState(path)
            self.assertIsNotNone(restarted.pending(plan))
            with self.assertRaises(AuthorizationStateError):
                restarted.reserve(plan)
            restarted.confirmed(plan)
            self.assertIsNone(first.pending(plan))
            self.assertIsNotNone(first.reserve(plan))


if __name__ == "__main__":
    unittest.main()
