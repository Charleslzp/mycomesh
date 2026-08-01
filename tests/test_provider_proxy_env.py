from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROXY_HELPER = ROOT / "scripts" / "provider-proxy-env.sh"
BOOTSTRAP_PROVIDER = ROOT / "scripts" / "bootstrap-provider.sh"

PROXY_ENV_NAMES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "MYCOMESH_PROVIDER_HTTP_PROXY",
    "MYCOMESH_PROVIDER_HTTPS_PROXY",
    "MYCOMESH_PROVIDER_ALL_PROXY",
    "MYCOMESH_PROVIDER_NO_PROXY",
)


def _clean_proxy_env(**overrides: str) -> dict[str, str]:
    env = os.environ.copy()
    for name in PROXY_ENV_NAMES:
        env.pop(name, None)
    env.update(overrides)
    return env


def _run_helper(
    shell_body: str,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["bash", "-c", 'source "$1"; shift; ' + shell_body, "bash", str(PROXY_HELPER)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _nul_fields(output: bytes) -> list[str]:
    fields = output.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    return [field.decode("utf-8") for field in fields]


def _service_block(compose: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)",
        compose,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing Compose service {name}")
    return match.group(0)


class ProviderProxyEnvironmentTest(unittest.TestCase):
    def test_empty_no_proxy_is_safe_under_installer_strict_mode(self) -> None:
        result = _run_helper(
            "set -Eeuo pipefail; mycomesh_provider_prepare_proxy_env; "
            "printf '%s' \"$MYCOMESH_PROVIDER_NO_PROXY\"",
            env=_clean_proxy_env(http_proxy="http://127.0.0.1:10792"),
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            result.stdout.decode("utf-8"),
            "127.0.0.1,localhost,::1,provider,provider-sidecar",
        )

    def test_lowercase_proxy_variables_take_precedence(self) -> None:
        env = _clean_proxy_env(
            HTTP_PROXY="http://upper-http.example:8080",
            http_proxy="http://lower-http.example:8081",
            HTTPS_PROXY="http://upper-https.example:8082",
            https_proxy="http://lower-https.example:8083",
            ALL_PROXY="socks5://upper-all.example:1080",
            all_proxy="socks5://lower-all.example:1081",
            NO_PROXY="upper.example",
            no_proxy="lower.example",
        )
        result = _run_helper(
            "mycomesh_provider_prepare_proxy_env; "
            "printf '%s\\0%s\\0%s\\0%s\\0' "
            '"$MYCOMESH_PROVIDER_HTTP_PROXY" '
            '"$MYCOMESH_PROVIDER_HTTPS_PROXY" '
            '"$MYCOMESH_PROVIDER_ALL_PROXY" '
            '"$MYCOMESH_PROVIDER_NO_PROXY"',
            env=env,
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        http, https, all_proxy, no_proxy = _nul_fields(result.stdout)
        self.assertEqual(http, "http://lower-http.example:8081")
        self.assertEqual(https, "http://lower-https.example:8083")
        self.assertEqual(all_proxy, "socks5://lower-all.example:1081")
        self.assertEqual(no_proxy.split(",", 1)[0], "lower.example")

    def test_explicit_mycomesh_proxy_variables_take_precedence(self) -> None:
        env = _clean_proxy_env(
            http_proxy="http://lower-http.example:8081",
            https_proxy="http://lower-https.example:8083",
            all_proxy="socks5://lower-all.example:1081",
            no_proxy="lower.example",
            MYCOMESH_PROVIDER_HTTP_PROXY="http://explicit-http.example:9081",
            MYCOMESH_PROVIDER_HTTPS_PROXY="http://explicit-https.example:9083",
            MYCOMESH_PROVIDER_ALL_PROXY="socks5://explicit-all.example:9085",
            MYCOMESH_PROVIDER_NO_PROXY="explicit.example",
        )
        result = _run_helper(
            "mycomesh_provider_prepare_proxy_env; "
            "printf '%s\\0%s\\0%s\\0%s\\0' "
            '"$MYCOMESH_PROVIDER_HTTP_PROXY" '
            '"$MYCOMESH_PROVIDER_HTTPS_PROXY" '
            '"$MYCOMESH_PROVIDER_ALL_PROXY" '
            '"$MYCOMESH_PROVIDER_NO_PROXY"',
            env=env,
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        http, https, all_proxy, no_proxy = _nul_fields(result.stdout)
        self.assertEqual(http, "http://explicit-http.example:9081")
        self.assertEqual(https, "http://explicit-https.example:9083")
        self.assertEqual(all_proxy, "socks5://explicit-all.example:9085")
        self.assertEqual(no_proxy.split(",", 1)[0], "explicit.example")

    def test_loopback_proxy_hosts_are_rewritten_without_losing_url_parts(self) -> None:
        cases = {
            "ipv4": (
                "http://alice:secret@127.0.0.1:10792/proxy/path?mode=fast#login",
                "http://alice:secret@host.docker.internal:10792/proxy/path?mode=fast#login",
            ),
            "localhost": (
                "socks5://bob:secret@LocalHost:1080/tunnel/path",
                "socks5://bob:secret@host.docker.internal:1080/tunnel/path",
            ),
            "ipv6": (
                "https://carol:secret@[::1]:8443/auth/path?step=1",
                "https://carol:secret@host.docker.internal:8443/auth/path?step=1",
            ),
        }

        for label, (value, expected) in cases.items():
            with self.subTest(label=label):
                result = _run_helper(
                    'mycomesh_provider_rewrite_loopback_proxy "$PROXY_UNDER_TEST"',
                    env=_clean_proxy_env(PROXY_UNDER_TEST=value),
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stdout.decode("utf-8"), expected)

    def test_remote_proxy_url_is_unchanged(self) -> None:
        value = "http://alice:secret@proxy.example:3128/proxy/path?mode=fast#login"
        result = _run_helper(
            'mycomesh_provider_rewrite_loopback_proxy "$PROXY_UNDER_TEST"',
            env=_clean_proxy_env(PROXY_UNDER_TEST=value),
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.decode("utf-8"), value)

    def test_no_proxy_preserves_values_and_adds_internal_hosts_once(self) -> None:
        result = _run_helper(
            "mycomesh_provider_prepare_proxy_env; "
            "printf '%s' \"$MYCOMESH_PROVIDER_NO_PROXY\"",
            env=_clean_proxy_env(no_proxy="example.com,localhost,provider"),
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        entries = result.stdout.decode("utf-8").split(",")
        self.assertEqual(
            entries,
            [
                "example.com",
                "localhost",
                "provider",
                "127.0.0.1",
                "::1",
                "provider-sidecar",
            ],
        )
        self.assertEqual(len(entries), len(set(entries)))

    def test_proxy_url_rejects_newline_and_carriage_return(self) -> None:
        for label, value in (
            ("newline", "http://127.0.0.1:10792\nINJECTED=value"),
            ("carriage return", "http://127.0.0.1:10792\rINJECTED=value"),
        ):
            with self.subTest(label=label):
                result = _run_helper(
                    "mycomesh_provider_prepare_proxy_env",
                    env=_clean_proxy_env(MYCOMESH_PROVIDER_HTTP_PROXY=value),
                )
                self.assertEqual(result.returncode, 64)
                self.assertIn(
                    b"Provider proxy URLs must be single-line values",
                    result.stderr,
                )


class ProviderProxyBootstrapCompatibilityTest(unittest.TestCase):
    def test_bootstrap_rejects_a_managed_checkout_for_another_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_dir = Path(directory) / "managed"
            scripts_dir = source_dir / "scripts"
            scripts_dir.mkdir(parents=True)
            (source_dir / "Makefile").write_text("all:\n\t@true\n", encoding="utf-8")
            installer = scripts_dir / "install-provider.sh"
            installer.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            installer.chmod(0o755)
            (source_dir / ".mycomesh-bootstrap-source").write_text(
                "https://github.com/Charleslzp/mycomesh\nv0.1.3\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "bash",
                    str(BOOTSTRAP_PROVIDER),
                    "--source-dir",
                    str(source_dir),
                    "--ref",
                    "v0.1.4",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 64)
            self.assertIn("different repository/ref", result.stderr)

    def test_bootstrap_onboards_an_existing_checkout_with_an_old_installer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            source_dir = temporary_root / "old-checkout"
            scripts_dir = source_dir / "scripts"
            gateway_dir = source_dir / "gateway"
            fake_bin = temporary_root / "fake-bin"
            installer_capture = temporary_root / "installer.txt"
            python_capture = temporary_root / "python.txt"
            scripts_dir.mkdir(parents=True)
            gateway_dir.mkdir()
            fake_bin.mkdir()
            (source_dir / "Makefile").write_text("provider-up-image:\n\t@true\n")
            (source_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (gateway_dir / "operator_setup.py").write_text("# compatibility marker\n")

            fake_installer = scripts_dir / "install-provider.sh"
            fake_installer.write_text(
                "#!/usr/bin/env bash\n"
                "{\n"
                "  printf 'config=%s\\n' \"${PROVIDER_OPERATOR_CONFIG:-}\"\n"
                "  printf '%s\\n' \"$@\"\n"
                "} >\"$MYCOMESH_TEST_INSTALLER_CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_installer.chmod(
                fake_installer.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "case \"${1-}\" in\n"
                "  --version) printf 'Docker version 27.0.0, build test\\n' ;;\n"
                "  compose) printf 'Docker Compose version v2.29.0\\n' ;;\n"
                "  *) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_docker.chmod(
                fake_docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

            fake_python = fake_bin / "python3"
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"${1-}\" == -c ]]; then exit 0; fi\n"
                "printf '%s\\n' \"$@\" >\"$MYCOMESH_TEST_PYTHON_CAPTURE\"\n"
                "output=\n"
                "while (($#)); do\n"
                "  case \"$1\" in\n"
                "    --output) output=\"$2\"; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "mkdir -p -- \"$(dirname -- \"$output\")\"\n"
                "printf '{}\\n' >\"$output\"\n"
                "chmod 600 \"$output\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(
                fake_python.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

            env = _clean_proxy_env(
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                MYCOMESH_TEST_INSTALLER_CAPTURE=str(installer_capture),
                MYCOMESH_TEST_PYTHON_CAPTURE=str(python_capture),
            )
            result = subprocess.run(
                [
                    "bash",
                    str(BOOTSTRAP_PROVIDER),
                    "--source-dir",
                    str(source_dir),
                    "--no-browser",
                    "--skip-codex-login",
                ],
                cwd=temporary_root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Provider settings saved", result.stdout)
            config_path = source_dir / ".mycomesh" / "operator" / "provider.json"
            self.assertTrue(config_path.is_file())
            python_args = python_capture.read_text(encoding="utf-8").splitlines()
            self.assertIn("gateway.operator_setup", python_args)
            self.assertIn("wizard", python_args)
            self.assertIn("provider", python_args)
            self.assertIn("--no-browser", python_args)
            installer_lines = installer_capture.read_text(encoding="utf-8").splitlines()
            self.assertEqual(installer_lines[0], f"config={config_path}")
            self.assertEqual(installer_lines[1:], ["--skip-codex-login"])

    def test_bootstrap_ignores_non_docker_executable_and_selects_real_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            source_dir = temporary_root / "old-checkout"
            scripts_dir = source_dir / "scripts"
            bad_bin = temporary_root / "bad-bin"
            docker_bin = temporary_root / "docker-bin"
            capture_file = temporary_root / "docker-cli.txt"
            scripts_dir.mkdir(parents=True)
            bad_bin.mkdir()
            docker_bin.mkdir()
            (source_dir / "Makefile").write_text("provider-up-image:\n\t@true\n")
            (source_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            fake_installer = scripts_dir / "install-provider.sh"
            fake_installer.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s' \"$MYCOMESH_DOCKER_CLI\" >\"$MYCOMESH_TEST_CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_installer.chmod(
                fake_installer.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )
            bad_docker = bad_bin / "docker"
            bad_docker.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'node docker package\\n'\n",
                encoding="utf-8",
            )
            bad_docker.chmod(
                bad_docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )
            real_docker = docker_bin / "docker"
            real_docker.write_text(
                "#!/usr/bin/env bash\n"
                "case \"${1-}\" in\n"
                "  --version) printf 'Docker version 27.0.0, build test\\n' ;;\n"
                "  compose) printf 'Docker Compose version v2.29.0\\n' ;;\n"
                "  *) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            real_docker.chmod(
                real_docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )
            env = _clean_proxy_env(
                PATH=f"{bad_bin}:{docker_bin}:{os.environ['PATH']}",
                MYCOMESH_TEST_CAPTURE=str(capture_file),
            )
            result = subprocess.run(
                ["bash", str(BOOTSTRAP_PROVIDER), "--source-dir", str(source_dir)],
                cwd=temporary_root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Ignoring non-Docker executable", result.stdout)
            self.assertEqual(capture_file.read_text(encoding="utf-8"), str(real_docker))

    def test_existing_old_checkout_receives_ephemeral_compose_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            source_dir = temporary_root / "old-checkout"
            scripts_dir = source_dir / "scripts"
            proxy_tmp = temporary_root / "proxy-tmp"
            capture_file = temporary_root / "installer-capture.txt"
            override_copy = temporary_root / "override-copy.yml"
            override_path_capture = temporary_root / "override-path.txt"
            scripts_dir.mkdir(parents=True)
            proxy_tmp.mkdir()
            (source_dir / "Makefile").write_text("provider-up-image:\n\t@true\n")
            (source_dir / "docker-compose.yml").write_text(
                "services:\n"
                "  provider-sidecar:\n"
                "    image: example/old-sidecar:latest\n"
                "  provider:\n"
                "    image: example/old-provider:latest\n",
                encoding="utf-8",
            )
            fake_installer = scripts_dir / "install-provider.sh"
            fake_installer.write_text(
                "#!/usr/bin/env bash\n"
                "set -Eeuo pipefail\n"
                "override=${COMPOSE_FILE##*${COMPOSE_PATH_SEPARATOR}}\n"
                "{\n"
                "  printf 'http=%s\\n' \"$MYCOMESH_PROVIDER_HTTP_PROXY\"\n"
                "  printf 'compose_file=%s\\n' \"$COMPOSE_FILE\"\n"
                "  printf 'separator=%s\\n' \"$COMPOSE_PATH_SEPARATOR\"\n"
                "} >\"$MYCOMESH_TEST_CAPTURE\"\n"
                "printf '%s' \"$override\" >\"$MYCOMESH_TEST_OVERRIDE_PATH\"\n"
                "cp -- \"$override\" \"$MYCOMESH_TEST_OVERRIDE_COPY\"\n",
                encoding="utf-8",
            )
            fake_installer.chmod(
                fake_installer.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

            proxy_url = "http://alice:secret@127.0.0.1:10792/proxy/path"
            env = _clean_proxy_env(
                http_proxy=proxy_url,
                MYCOMESH_TEST_CAPTURE=str(capture_file),
                MYCOMESH_TEST_OVERRIDE_COPY=str(override_copy),
                MYCOMESH_TEST_OVERRIDE_PATH=str(override_path_capture),
                TMPDIR=str(proxy_tmp),
            )
            result = subprocess.run(
                ["bash", str(BOOTSTRAP_PROVIDER), "--source-dir", str(source_dir)],
                cwd=temporary_root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "Applying Provider proxy compatibility for the existing checkout.",
                result.stdout,
            )
            capture = capture_file.read_text(encoding="utf-8")
            self.assertIn(
                "http=http://alice:secret@host.docker.internal:10792/proxy/path",
                capture,
            )
            self.assertIn(f"compose_file={source_dir / 'docker-compose.yml'}:", capture)
            self.assertIn("separator=:\n", capture)

            override = override_copy.read_text(encoding="utf-8")
            self.assertIn("provider-sidecar:", override)
            self.assertIn('"host.docker.internal=host-gateway"', override)
            self.assertIn("${MYCOMESH_PROVIDER_HTTP_PROXY:-}", override)
            self.assertNotIn("alice", override)
            self.assertNotIn("secret", override)
            self.assertNotIn(proxy_url, override)

            override_path = Path(override_path_capture.read_text(encoding="utf-8"))
            self.assertFalse(override_path.exists())
            self.assertEqual(list(proxy_tmp.glob("mycomesh-provider-proxy.*")), [])


class ProviderInstallerMigrationTest(unittest.TestCase):
    def test_restores_protected_settings_before_first_managed_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mycomesh provider migration ") as directory:
            temporary_root = Path(directory)
            scripts_dir = temporary_root / "scripts"
            fake_bin = temporary_root / "fake-bin"
            scripts_dir.mkdir()
            fake_bin.mkdir()
            shutil.copy2(ROOT / "scripts" / "install-provider.sh", scripts_dir)
            shutil.copy2(ROOT / "scripts" / "provider-proxy-env.sh", scripts_dir)
            onboarding_capture = temporary_root / "onboarding-args.txt"
            fake_onboarding = scripts_dir / "provider-onboarding-container.sh"
            fake_onboarding.write_text(
                "#!/usr/bin/env bash\n"
                "set -Eeuo pipefail\n"
                "printf '%s\\n' \"$*\" >\"$MYCOMESH_TEST_ONBOARDING_CAPTURE\"\n"
                "protected_identity=\n"
                "while (($#)); do\n"
                "  if [[ \"$1\" == --protected-identity ]]; then protected_identity=\"$2\"; shift 2; else shift; fi\n"
                "done\n"
                "if [[ -n \"$protected_identity\" ]]; then\n"
                "  [[ -f \"$protected_identity\" && ! -L \"$protected_identity\" ]] || exit 93\n"
                "  [[ \"$(stat -c %a \"$protected_identity\")\" == 600 ]] || exit 94\n"
                "  cmp -s \"$protected_identity\" \"$MYCOMESH_TEST_PROTECTED_IDENTITY\" || exit 95\n"
                "fi\n"
                "[[ \"${MYCOMESH_TEST_ONBOARDING_FAIL:-0}\" != 1 ]] || exit 96\n",
                encoding="utf-8",
            )
            fake_onboarding.chmod(0o755)
            (temporary_root / "Makefile").write_text("all:\n\t@true\n", encoding="utf-8")
            (temporary_root / "docker-compose.yml").write_text(
                "services: {}\n", encoding="utf-8"
            )
            (temporary_root / ".env.deploy.example").write_text("\n", encoding="utf-8")

            protected = temporary_root / "protected.json"
            protected_value = {
                "schema": "mycomesh.operator.v1",
                "role": "provider",
                "payout_address": "0x" + "12" * 20,
                "wallet_source": "existing",
                "max_concurrency": 7,
                "usage_limit_units": 12_500_000,
                "usage_limit_usdc": "12.500000",
                "usage_period_seconds": 3600,
                "configured_at": 1_785_000_000,
            }
            protected.write_text(json.dumps(protected_value) + "\n", encoding="utf-8")
            protected_identity = temporary_root / "protected-identity.json"
            protected_private_key = "0x" + "31" * 32
            protected_identity.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "address": protected_value["payout_address"],
                        "private_key": protected_private_key,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            protected_identity.chmod(0o600)
            make_capture = temporary_root / "make-calls.txt"

            fake_make = fake_bin / "make"
            fake_make.write_text(
                "#!/usr/bin/env bash\n"
                "set -Eeuo pipefail\n"
                "if [[ \"${1-}\" == --version ]]; then printf 'GNU Make 4.4\\n'; exit 0; fi\n"
                "printf '%s\\n' \"$*\" >>\"$MYCOMESH_TEST_MAKE_CAPTURE\"\n"
                "export_file=\n"
                "for arg in \"$@\"; do\n"
                "  if [[ \"$arg\" == PROVIDER_IDENTITY_EXPORT_FILE=* ]]; then export_file=\"${arg#*=}\"; fi\n"
                "  if [[ \"$arg\" == provider-operator-config-export-image ]]; then\n"
                "    [[ -z \"${MYCOMESH_PROVIDER_OPERATOR_CONFIG:-}\" ]] || exit 90\n"
                "    cat \"$MYCOMESH_TEST_PROTECTED_CONFIG\"\n"
                "  fi\n"
                "  if [[ \"$arg\" == provider-identity-export-image ]]; then\n"
                "    [[ -z \"${MYCOMESH_PROVIDER_IDENTITY_SOURCE:-}\" ]] || exit 91\n"
                "    [[ -n \"$export_file\" ]] || exit 92\n"
                "    cat \"$MYCOMESH_TEST_PROTECTED_IDENTITY\" >\"$export_file\"\n"
                "  fi\n"
                "done\n",
                encoding="utf-8",
            )
            fake_make.chmod(0o755)

            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "case \"${1-}\" in\n"
                "  --version) printf 'Docker version 27.0.0, build test\\n' ;;\n"
                "  compose) if [[ \"${2-}\" == version ]]; then printf 'Docker Compose version v2.29.0\\n'; fi ;;\n"
                "  info) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)

            settings = temporary_root / "managed settings" / "settings.json"
            settings.parent.mkdir(parents=True)
            stale_identity = settings.parent / "provider-evm-identity.json"
            stale_identity.write_text("stale local identity\n", encoding="utf-8")
            stale_identity.chmod(0o600)
            env = _clean_proxy_env(
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                MAKE_BIN=str(fake_make),
                MYCOMESH_PROVIDER_OPERATOR_CONFIG=str(settings),
                MYCOMESH_TEST_MAKE_CAPTURE=str(make_capture),
                MYCOMESH_TEST_PROTECTED_CONFIG=str(protected),
                MYCOMESH_TEST_PROTECTED_IDENTITY=str(protected_identity),
                MYCOMESH_TEST_ONBOARDING_CAPTURE=str(onboarding_capture),
                PYTHONPATH=str(ROOT),
            )
            failed = subprocess.run(
                [
                    "bash",
                    str(scripts_dir / "install-provider.sh"),
                    "--provider-image",
                    "ghcr.io/example/provider@sha256:abc",
                    "--skip-codex-login",
                ],
                cwd=temporary_root,
                env={**env, "MYCOMESH_TEST_ONBOARDING_FAIL": "1"},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(list(settings.parent.glob(".provider-identity.backup.*")), [])
            self.assertNotIn(protected_private_key, failed.stdout + failed.stderr)
            make_capture.write_text("", encoding="utf-8")
            onboarding_capture.write_text("", encoding="utf-8")

            result = subprocess.run(
                [
                    "bash",
                    str(scripts_dir / "install-provider.sh"),
                    "--provider-image",
                    "ghcr.io/example/provider@sha256:abc",
                    "--skip-codex-login",
                ],
                cwd=temporary_root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Restored existing Provider settings", result.stdout)
            self.assertEqual(json.loads(settings.read_text(encoding="utf-8")), protected_value)
            self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o600)
            calls = make_capture.read_text(encoding="utf-8")
            self.assertIn("provider-operator-config-export-image", calls)
            self.assertIn("provider-identity-export-image", calls)
            after_restore = calls.split("provider-operator-config-export-image", 1)[1]
            self.assertNotIn("PROVIDER_IDENTITY_SOURCE=/", after_restore)
            self.assertIn("provider-config-apply-image", after_restore)
            onboarding_args = onboarding_capture.read_text(encoding="utf-8")
            self.assertIn("--protected-wallet", onboarding_args)
            self.assertIn("--protected-identity", onboarding_args)
            self.assertNotIn(protected_private_key, result.stdout)
            self.assertNotIn(protected_private_key, result.stderr)
            self.assertNotIn(protected_private_key, onboarding_args)
            self.assertEqual(list(settings.parent.glob(".provider-identity.backup.*")), [])
            self.assertEqual(stale_identity.read_text(encoding="utf-8"), "stale local identity\n")
            self.assertNotIn("gateway.operator_setup wizard", result.stdout)

            confirmed_value = dict(
                protected_value,
                wallet_fingerprint="3131...31313131",
                backup_confirmed_at=1_785_000_001,
            )
            protected.write_text(json.dumps(confirmed_value) + "\n", encoding="utf-8")
            make_capture.write_text("", encoding="utf-8")
            onboarding_capture.write_text("", encoding="utf-8")
            confirmed_result = subprocess.run(
                [
                    "bash",
                    str(scripts_dir / "install-provider.sh"),
                    "--provider-image",
                    "ghcr.io/example/provider@sha256:abc",
                    "--skip-codex-login",
                ],
                cwd=temporary_root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(confirmed_result.returncode, 0, confirmed_result.stderr)
            self.assertNotIn(
                "provider-identity-export-image",
                make_capture.read_text(encoding="utf-8"),
            )
            confirmed_args = onboarding_capture.read_text(encoding="utf-8")
            self.assertIn("--protected-wallet", confirmed_args)
            self.assertNotIn("--protected-identity", confirmed_args)
            self.assertEqual(list(settings.parent.glob(".provider-identity.backup.*")), [])


class ProviderProxyComposeConfigTest(unittest.TestCase):
    def test_proxy_environment_and_host_alias_are_sidecar_only(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        sidecar = _service_block(compose, "provider-sidecar")
        provider = _service_block(compose, "provider")
        expected_environment = {
            "HTTP_PROXY": "${MYCOMESH_PROVIDER_HTTP_PROXY:-}",
            "HTTPS_PROXY": "${MYCOMESH_PROVIDER_HTTPS_PROXY:-}",
            "ALL_PROXY": "${MYCOMESH_PROVIDER_ALL_PROXY:-}",
            "NO_PROXY": "${MYCOMESH_PROVIDER_NO_PROXY:-127.0.0.1,localhost,::1,provider,provider-sidecar}",
            "http_proxy": "${MYCOMESH_PROVIDER_HTTP_PROXY:-}",
            "https_proxy": "${MYCOMESH_PROVIDER_HTTPS_PROXY:-}",
            "all_proxy": "${MYCOMESH_PROVIDER_ALL_PROXY:-}",
            "no_proxy": "${MYCOMESH_PROVIDER_NO_PROXY:-127.0.0.1,localhost,::1,provider,provider-sidecar}",
        }

        self.assertIn("extra_hosts:", sidecar)
        self.assertIn('"host.docker.internal=host-gateway"', sidecar)
        self.assertNotIn("host.docker.internal=host-gateway", provider)
        for name, value in expected_environment.items():
            expected_line = f"      {name}: {value}"
            with self.subTest(variable=name):
                self.assertIn(expected_line, sidecar)
                self.assertNotIn(expected_line, provider)
                self.assertEqual(compose.count(expected_line), 1)


if __name__ == "__main__":
    unittest.main()
