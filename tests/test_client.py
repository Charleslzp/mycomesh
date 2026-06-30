from __future__ import annotations

import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from gateway.client import (
    _health_url,
    _provider_pool_url,
    build_provider_process_command,
    codex_auth_exists,
    codex_login_required,
    create_agent_key,
    delete_agent_key,
    discover_public_url,
    ensure_agent_key,
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

    def test_codex_auth_exists_detects_gateway_login_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            self.assertFalse(codex_auth_exists(home))
            (home / "auth.json").write_text("{}", encoding="utf-8")
            self.assertTrue(codex_auth_exists(home))

    def test_codex_login_required_only_for_codex_backends(self) -> None:
        self.assertTrue(codex_login_required(Namespace(backend="codex_cli")))
        self.assertTrue(codex_login_required(Namespace(backend="codex_app_server")))
        self.assertFalse(codex_login_required(Namespace(backend="openai_http")))

    def test_ensure_agent_key_reuses_or_creates_provider_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agents_file = Path(tmp) / "agents.json"

            created, was_created = ensure_agent_key(agents_file, "coder")
            self.assertTrue(was_created)
            self.assertTrue(created.key.startswith("gwk_"))

            reused, was_created = ensure_agent_key(agents_file, "coder")
            self.assertFalse(was_created)
            self.assertEqual(reused.key, created.key)

            payload = json.loads(agents_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["agents"]["coder"]["role"], "provider")
            self.assertEqual(payload["agents"]["coder"]["description"], "MycoMesh provider node.")

    def test_build_provider_process_command_direct_omits_gateway_key(self) -> None:
        args = _provider_start_args(
            agents_file="/tmp/agents.json",
            transport="direct",
            bootstrap=["127.0.0.1:9701"],
            consumer_public_key=["consumer-key"],
        )

        command = build_provider_process_command(args, gateway_url="http://127.0.0.1:8000/v1")

        self.assertEqual(command[1:5], ["-m", "gateway", "--agents-file", "/tmp/agents.json"])
        self.assertIn("serve", command)
        self.assertIn("--bootstrap", command)
        self.assertIn("127.0.0.1:9701", command)
        self.assertIn("--consumer-public-key", command)
        self.assertIn("consumer-key", command)
        self.assertNotIn("--key", command)

    def test_build_provider_process_command_relay(self) -> None:
        args = _provider_start_args(
            transport="relay",
            relay_host="relay.example.com",
            relay_port=9901,
            relay_public_url="https://relay.example.com",
        )

        command = build_provider_process_command(args, gateway_url="http://127.0.0.1:8000/v1")

        self.assertIn("relay", command)
        self.assertIn("--relay-host", command)
        self.assertIn("relay.example.com", command)
        self.assertIn("--relay-public-url", command)
        self.assertIn("https://relay.example.com", command)
        self.assertNotIn("--bootstrap", command)

    def test_provider_pool_url_preserves_configured_pools(self) -> None:
        self.assertIsNone(_provider_pool_url(None))
        self.assertEqual(
            _provider_pool_url("http://127.0.0.1:9800, http://127.0.0.1:9802"),
            "http://127.0.0.1:9800,http://127.0.0.1:9802",
        )

def _provider_start_args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "agents_file": "agents.json",
        "transport": "direct",
        "provider_host": "0.0.0.0",
        "provider_port": 9700,
        "advertise_host": "127.0.0.1",
        "relay_host": "127.0.0.1",
        "relay_port": 9901,
        "relay_public_url": None,
        "agent": "coder",
        "channel": "codex-standard-v1",
        "model": "gpt-5.5",
        "identity": ".codex-run/node-identity.json",
        "peer_id": None,
        "network_profile": "testnet",
        "pool": "http://127.0.0.1:9800",
        "ttl": 60,
        "heartbeat_interval": 20.0,
        "capacity": 1,
        "reserve_input_tokens": 8000,
        "reserve_output_tokens": 2000,
        "bootstrap": [],
        "consumer_public_key": [],
        "payment_address": "0x0000000000000000000000000000000000000001",
        "pricing_config": None,
        "pricing_hash": "0xpricing",
        "allow_any_signed_consumer": False,
        "allow_unsigned_requests": False,
        "allow_unreserved_requests": False,
    }
    values.update(overrides)
    return Namespace(**values)


if __name__ == "__main__":
    unittest.main()
