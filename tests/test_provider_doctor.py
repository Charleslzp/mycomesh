"""Run the real read-only doctor with controlled dependency executables."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProviderDoctorTest(unittest.TestCase):
    def run_doctor(self, *, docker=True, compose=True, engine=True, make=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            installer = scripts / "install-provider.sh"
            shutil.copyfile(ROOT / "scripts/install-provider.sh", installer)
            binary = root / "bin"
            binary.mkdir()
            docker_cli = binary / "docker"
            docker_cli.write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> "{root / 'docker-calls'}"
case "$*" in
  --version) {'echo "Docker version fixture"' if docker else 'exit 1'} ;;
  'compose version') exit {0 if compose else 1} ;;
  info) exit {0 if engine else 1} ;;
  *) echo 'unexpected mutating command' >&2; exit 99 ;;
esac
''')
            docker_cli.chmod(0o700)
            for name in ("make", "gmake"):
                path = binary / name
                path.write_text('#!/bin/sh\n' + ('echo "GNU Make fixture"\n' if make else 'exit 1\n'))
                path.chmod(0o700)
            environment = {**os.environ, "PATH": str(binary) + os.pathsep + os.defpath,
                           "MYCOMESH_DOCKER_CLI": str(docker_cli), "MAKE_BIN": str(binary / "make")}
            # Doctor must exit before inspecting checkout files, image options,
            # proxy configuration or any mutable runtime/profile state.
            environment["MYCOMESH_PROVIDER_IMAGE"] = "not a valid image"
            result = subprocess.run(["bash", str(installer), "--doctor"], env=environment,
                                    text=True, capture_output=True, timeout=10)
            self.assertFalse((root / ".env.deploy").exists())
            self.assertFalse((root / ".mycomesh").exists())
            calls = (root / "docker-calls").read_text().splitlines()
            self.assertTrue(set(calls) <= {"--version", "compose version", "info"}, calls)
            self.assertIn("Not checked: image download, Codex login/model access", result.stdout)
            return result

    def test_ready_dependencies_do_not_claim_provider_is_online(self):
        result = self.run_doctor()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Local dependencies are ready", result.stdout)
        self.assertIn("does not mean the Provider is online", result.stdout)

    def test_stopped_engine_has_actionable_recovery(self):
        result = self.run_doctor(engine=False)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("[OK] Docker Compose V2", result.stdout)
        self.assertIn("[BLOCKED] Docker engine", result.stdout)
        self.assertIn("docker context show", result.stdout)
        self.assertIn("--doctor", result.stdout)

    def test_missing_compose_is_distinct_from_working_engine(self):
        result = self.run_doctor(compose=False)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("[BLOCKED] Docker Compose V2", result.stdout)
        self.assertIn("[OK] Docker engine is reachable", result.stdout)

    def test_missing_cli_does_not_try_compose_or_engine(self):
        result = self.run_doctor(docker=False)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("[BLOCKED] Docker CLI", result.stdout)
        self.assertIn("[NOT CHECKED] Compose and engine", result.stdout)

    def test_reports_all_missing_dependencies_together(self):
        result = self.run_doctor(compose=False, engine=False, make=False)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertEqual(result.stdout.count("[BLOCKED]"), 3)
        self.assertIn("GNU Make", result.stdout)


if __name__ == "__main__":
    unittest.main()
