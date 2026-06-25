from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from gateway.client import (
    _health_url,
    create_agent_key,
    delete_agent_key,
    discover_public_url,
    key_fingerprint,
    list_agent_keys,
    rotate_agent_key,
)


class GatewayClientTest(unittest.TestCase):
    def test_create_and_delete_agent_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agents_file = Path(tmp) / "agents.json"
            agents_file.write_text(
                json.dumps(
                    {
                        "agents": {
                            "coder": {
                                "keys": ["existing-key"],
                                "role": "coder",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            created = create_agent_key(agents_file, agent_id="coder")
            self.assertEqual(created.agent_id, "coder")
            self.assertTrue(created.key.startswith("gwk_"))

            keys = list_agent_keys(agents_file, agent_id="coder")
            self.assertEqual([key.key for key in keys], ["existing-key", created.key])

            removed = delete_agent_key(
                agents_file,
                agent_id="coder",
                selector=created.fingerprint[:8],
            )
            self.assertEqual(removed.key, created.key)
            self.assertEqual(
                [key.key for key in list_agent_keys(agents_file, agent_id="coder")],
                ["existing-key"],
            )

    def test_create_agent_key_creates_missing_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agents_file = Path(tmp) / "agents.json"
            created = create_agent_key(
                agents_file,
                agent_id="provider",
                role="provider",
                description="External provider node.",
            )

            payload = json.loads(agents_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["agents"]["provider"]["role"], "provider")
            self.assertEqual(payload["agents"]["provider"]["description"], "External provider node.")
            self.assertEqual(payload["agents"]["provider"]["keys"], [created.key])

    def test_delete_rejects_ambiguous_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agents_file = Path(tmp) / "agents.json"
            agents_file.write_text(
                json.dumps({"agents": {"coder": {"keys": ["same-a", "same-b"]}}}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "multiple keys"):
                delete_agent_key(agents_file, agent_id="coder", selector="same")

    def test_rotate_agent_key_replaces_selected_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agents_file = Path(tmp) / "agents.json"
            agents_file.write_text(
                json.dumps({"agents": {"coder": {"keys": ["old-key", "keep-key"]}}}),
                encoding="utf-8",
            )

            new_key, old_key = rotate_agent_key(
                agents_file,
                agent_id="coder",
                selector=key_fingerprint("old-key")[:8],
            )

            self.assertEqual(old_key.key, "old-key")
            self.assertTrue(new_key.key.startswith("gwk_"))
            self.assertEqual(
                [key.key for key in list_agent_keys(agents_file, agent_id="coder")],
                [new_key.key, "keep-key"],
            )

    def test_key_fingerprint_is_stable(self) -> None:
        self.assertEqual(key_fingerprint("secret-key"), key_fingerprint("secret-key"))
        self.assertEqual(len(key_fingerprint("secret-key")), 16)

    def test_discover_public_url_reads_latest_cloudflared_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            older = run_dir / "cloudflared-older.log"
            newer = run_dir / "cloudflared-newer.log"
            older.write_text("https://old-example.trycloudflare.com", encoding="utf-8")
            newer.write_text(
                "line one\nhttps://new-example.trycloudflare.com\n",
                encoding="utf-8",
            )
            os.utime(older, (1_700_000_000, 1_700_000_000))
            os.utime(newer, (1_700_000_010, 1_700_000_010))

            self.assertEqual(
                discover_public_url(run_dir),
                "https://new-example.trycloudflare.com",
            )

    def test_health_url_defaults_and_public_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "cloudflared.log").write_text(
                "https://public-example.trycloudflare.com",
                encoding="utf-8",
            )

            self.assertEqual(
                _health_url(None, public=False, run_dir=run_dir, port=8001),
                "http://127.0.0.1:8001/health",
            )
            self.assertEqual(
                _health_url("https://example.com/v1", public=False, run_dir=run_dir, port=8001),
                "https://example.com/health",
            )
            self.assertEqual(
                _health_url("https://example.com/health", public=False, run_dir=run_dir, port=8001),
                "https://example.com/health",
            )
            self.assertEqual(
                _health_url(None, public=True, run_dir=run_dir, port=8001),
                "https://public-example.trycloudflare.com/health",
            )


if __name__ == "__main__":
    unittest.main()
