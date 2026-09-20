import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway import client


class ProviderProcessLivenessTests(unittest.TestCase):
    def test_reused_supervisor_pid_starts_a_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pidfile = root / "provider-relay-10991.pid"
            pidfile.write_text(str(os.getpid()))
            args = Namespace(transport="relay", relay_port=10991)
            worker = SimpleNamespace(pid=987654)
            with patch.object(client, "build_provider_process_command", return_value=["python", "-m", "gateway", "p2p", "relay"]), patch.object(client, "_popen_logged", return_value=worker) as spawn:
                runtime = client.start_provider_process(args, root, "http://localhost:8000/v1")
            self.assertFalse(runtime.already_running)
            self.assertIs(runtime.process, worker)
            self.assertEqual(pidfile.read_text(), "987654")
            spawn.assert_called_once()

    def test_linux_worker_must_match_all_arguments(self):
        command = ["/usr/bin/python3", "-m", "gateway", "p2p", "relay", "--relay-port", "10991"]
        with patch.object(client.sys, "platform", "linux"), patch.object(client, "_process_running", return_value=True), patch.object(Path, "read_bytes", return_value=b"\0".join(os.fsencode(v) for v in command) + b"\0"):
            self.assertTrue(client._matching_provider_pid(987654, command))
            with self.assertRaisesRegex(ValueError, "different arguments"):
                client._matching_provider_pid(987654, command[:-1] + ["10992"])

    def test_unrelated_reused_pid_is_not_adopted(self):
        with patch.object(client.sys, "platform", "linux"), patch.object(client, "_process_running", return_value=True), patch.object(Path, "read_bytes", return_value=b"python\0-m\0gateway\0provider\0start\0"):
            self.assertFalse(client._matching_provider_pid(987654, ["python", "-m", "gateway", "p2p", "relay"]))

    def test_unreadable_process_fails_closed(self):
        with patch.object(client.sys, "platform", "linux"), patch.object(client, "_process_running", return_value=True), patch.object(Path, "read_bytes", side_effect=PermissionError):
            with self.assertRaisesRegex(ValueError, "cannot verify"):
                client._matching_provider_pid(987654, ["python", "-m", "gateway", "p2p", "relay"])


if __name__ == "__main__":
    unittest.main()
