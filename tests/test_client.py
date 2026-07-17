from __future__ import annotations

import hashlib
import json
import io
import os
import signal
import subprocess
import tempfile
import time
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from gateway.chain import ChainError, parse_private_key, private_key_to_address, sign_evm_digest
from gateway.chain_v3 import V3ReceiptInput, receipt_digest, signature_bytes
from gateway.client import (
    DEFAULT_MYCO_V3_DEPLOYMENT_PATH,
    _build_parser,
    _cmd_chain_v3_prepare_receipt,
    _cmd_chain_v3_settle_provider_fallback,
    _cmd_chain_v3_settle_signed_receipt,
    _cmd_p2p_infer,
    _cmd_p2p_ping,
    _cmd_pool_infer,
    _cmd_provider_start,
    _health_url,
    _gateway_profile_health_error,
    _mycomesh_credential_scope,
    _prepare_evm_session_authorization,
    _parse_v3_external_signature,
    _provider_pool_url,
    _provider_pool_peer,
    _provider_profile_preflight,
    _pool_post_json,
    _hydrate_provider_v3_manifest,
    _resolve_provider_advertise_address,
    _relay_address_from_control_url,
    _send_infer_to_address,
    build_provider_process_command,
    codex_auth_exists,
    codex_chatgpt_login_ready,
    codex_login_required,
    create_agent_key,
    delete_agent_key,
    discover_public_url,
    ensure_agent_key,
    key_fingerprint,
    list_agent_keys,
    rotate_agent_key,
    run_codex_login,
    start_gateway,
    _without_codex_api_credentials,
)
from gateway.p2p import DEFAULT_PUBLIC_MODEL_ID, ProviderConfig
from gateway.identity import create_identity
from gateway.reservation import (
    MAX_RESERVATION_TTL_SECONDS,
    build_evm_session_authorization,
    evm_session_authorization_digest,
    inference_request_hash,
    verify_eoa_session_authorization,
    verify_payment_reservation,
)


class GatewayClientTest(unittest.TestCase):
    def test_provider_pool_descriptor_binds_public_execution_limits(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel="codex-standard-v1",
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model=DEFAULT_PUBLIC_MODEL_ID,
            advertise_host="127.0.0.1",
            advertise_port=9700,
            network_profile="local",
            reserve_input_tokens=8000,
            reserve_output_tokens=2000,
        )

        peer = _provider_pool_peer(
            config,
            capacity={"max_concurrency": 3, "transport": "relay"},
        )

        self.assertEqual(
            peer["capacity"],
            {
                "max_concurrency": 3,
                "transport": "relay",
                "reserve_input_bytes": 8000,
                "reserve_output_tokens": 2000,
            },
        )

    def test_testnet_provider_pool_descriptor_binds_enabled_channel_policy(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel="codex-standard-v1",
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model=DEFAULT_PUBLIC_MODEL_ID,
            advertise_host="127.0.0.1",
            advertise_port=9700,
            network_profile="local",
        )
        config.network_profile = "testnet"
        config.network_id = "mycomesh-testnet"
        config.channel_id = "codex"
        config.backend_policy = "codex-app-server-postvalidated-v1"

        with patch("gateway.client.provider_runtime_capabilities", return_value={}):
            peer = _provider_pool_peer(config)

        self.assertEqual(peer["network_id"], "mycomesh-testnet")
        self.assertEqual(peer["channel_id"], "codex")
        self.assertEqual(peer["backend_policy"], "codex-app-server-postvalidated-v1")

    def test_public_cli_model_defaults_to_canonical_id(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            args = _build_parser().parse_args(["provider", "start"])

        self.assertEqual(args.model, DEFAULT_PUBLIC_MODEL_ID)

    def test_mycomesh_cli_credentials_bind_canonical_gateway_scope(self) -> None:
        env = {
            "MYCOMESH_NETWORK_PROFILE": "local",
            "MYCOMESH_NETWORK_ID": "mycomesh-local-test",
            "MYCOMESH_PUBLIC_GATEWAY_URL": "http://LOCALHOST:8100/v1/",
            "ETH_CHAIN_ID": "11155111",
            "MYCO_SETTLEMENT": "0x0000000000000000000000000000000000000002",
        }
        with patch.dict(os.environ, env, clear=True):
            scope = _mycomesh_credential_scope()

        self.assertEqual(scope["credential_origin"], "http://localhost:8100")
        self.assertEqual(scope["credential_network_id"], "mycomesh-local-test")
        self.assertEqual(scope["credential_chain_id"], 11155111)
        self.assertEqual(
            scope["credential_settlement"],
            "0x0000000000000000000000000000000000000002",
        )

    def test_indexer_sync_uses_v3_manifest_and_rejects_conflicting_pins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest = tmp_path / "sepolia-myco-v3.json"
            deployment = {
                "protocol_version": 3,
                "chain_id": 11155111,
                "deployer": "0x" + "aa" * 20,
                "test_usdc": "0x" + "bb" * 20,
                "stablecoin": "0x" + "bb" * 20,
                "settlement": "0x" + "22" * 20,
                "token": "0x" + "cc" * 20,
                "treasury": "0x" + "dd" * 20,
                "governance": "0x" + "ee" * 20,
                "max_consumer_rebate_bps": 1_000,
                "max_supply": 10**27,
                "network_id": "mycomesh-testnet",
                "channel_id": "codex",
                "channel": "codex-standard-v1",
                "backend_policy": "codex-app-server-postvalidated-v1",
                "channel_hash": "0xdedf8b58276b80863f354409c963cbaddf4ca7d5b866d528ff1386d74b339104",
                "pricing_version": 1,
                "pricing_hash": "0x" + "13" * 32,
            }
            manifest.write_text(json.dumps(deployment), encoding="utf-8")
            env = {
                "MYCOMESH_SETTLEMENT_VERSION": "3",
                "MYCO_DEPLOYMENT": str(manifest),
                "MYCOMESH_NETWORK_PROFILE": "testnet",
                "MYCOMESH_NETWORK_ID": "mycomesh-testnet",
                "MYCOMESH_PUBLIC_GATEWAY_URL": "https://gateway.example/v1",
            }
            arguments = [
                "mycomesh",
                "indexer",
                "sync",
                "--rpc-url",
                "https://rpc.example",
                "--account",
                "acct-a",
                "--db",
                str(tmp_path / "billing.sqlite3"),
                "--state",
                str(tmp_path / "indexer.json"),
            ]
            result = SimpleNamespace(to_dict=lambda: {"synced": True})
            with patch.dict(os.environ, env, clear=True):
                args = _build_parser().parse_args(arguments)
                self.assertIsNone(args.deployment)
                with patch(
                    "gateway.client.sync_prepaid_balances",
                    return_value=result,
                ) as sync, redirect_stdout(io.StringIO()):
                    code = args.func(args)

            self.assertEqual(code, 0)
            self.assertEqual(sync.call_args.kwargs["chain_id"], deployment["chain_id"])
            self.assertEqual(sync.call_args.kwargs["settlement"], deployment["settlement"])
            self.assertEqual(sync.call_args.kwargs["accounts"], ["acct-a"])

            with patch.dict(os.environ, env, clear=True):
                credential_scope = _mycomesh_credential_scope()
            self.assertEqual(credential_scope["credential_chain_id"], deployment["chain_id"])
            self.assertEqual(credential_scope["credential_settlement"], deployment["settlement"])

            with patch.dict(
                os.environ,
                {**env, "MYCO_SETTLEMENT": "0x" + "99" * 20},
                clear=True,
            ):
                with self.assertRaisesRegex(ChainError, "MYCO_SETTLEMENT does not match"):
                    _mycomesh_credential_scope()
                args = _build_parser().parse_args(arguments)
                errors = io.StringIO()
                with patch("gateway.client.sync_prepaid_balances") as rejected_sync, redirect_stderr(errors):
                    rejected = args.func(args)

            self.assertEqual(rejected, 1)
            self.assertIn("MYCO_SETTLEMENT does not match", errors.getvalue())
            rejected_sync.assert_not_called()

    def test_indexer_sync_keeps_v2_manifest_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest = tmp_path / "sepolia-myco-v2.json"
            deployment = {
                "protocol_version": 2,
                "chain_id": 11155111,
                "deployer": "0x" + "aa" * 20,
                "test_usdc": "0x" + "bb" * 20,
                "settlement": "0x" + "22" * 20,
                "token": "0x" + "cc" * 20,
                "treasury": "0x" + "dd" * 20,
                "channel": "codex-standard-v1",
                "channel_hash": "0xdedf8b58276b80863f354409c963cbaddf4ca7d5b866d528ff1386d74b339104",
            }
            manifest.write_text(json.dumps(deployment), encoding="utf-8")
            env = {
                "MYCOMESH_SETTLEMENT_VERSION": "2",
                "MYCO_DEPLOYMENT": str(manifest),
            }
            arguments = [
                "mycomesh",
                "indexer",
                "sync",
                "--rpc-url",
                "https://rpc.example",
                "--account",
                "acct-v2",
                "--db",
                str(tmp_path / "billing.sqlite3"),
                "--state",
                str(tmp_path / "indexer.json"),
            ]
            result = SimpleNamespace(to_dict=lambda: {"synced": True})
            with patch.dict(os.environ, env, clear=True):
                args = _build_parser().parse_args(arguments)
                with patch(
                    "gateway.client.sync_prepaid_balances",
                    return_value=result,
                ) as sync, redirect_stdout(io.StringIO()):
                    code = args.func(args)

        self.assertEqual(code, 0)
        self.assertEqual(sync.call_args.kwargs["chain_id"], deployment["chain_id"])
        self.assertEqual(sync.call_args.kwargs["settlement"], deployment["settlement"])
        self.assertEqual(sync.call_args.kwargs["accounts"], ["acct-v2"])

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

    def test_codex_status_requires_chatgpt_and_strips_api_credentials(self) -> None:
        config = SimpleNamespace(
            codex_command="codex",
            codex_home="/data/codex-home",
        )
        completed = subprocess.CompletedProcess(
            ["codex", "login", "status"],
            0,
            stdout="Logged in using ChatGPT\n",
        )
        environment = {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "must-not-pass",
            "CODEX_API_KEY": "must-not-pass",
            "CODEX_ACCESS_TOKEN": "must-not-pass",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "gateway.client.subprocess.run",
            return_value=completed,
        ) as run:
            self.assertTrue(codex_chatgpt_login_ready(config))

        child_env = run.call_args.kwargs["env"]
        self.assertEqual(child_env["CODEX_HOME"], "/data/codex-home")
        self.assertNotIn("OPENAI_API_KEY", child_env)
        self.assertNotIn("CODEX_API_KEY", child_env)
        self.assertNotIn("CODEX_ACCESS_TOKEN", child_env)
        self.assertEqual(run.call_args.kwargs["umask"], 0o077)

    def test_codex_status_rejects_api_key_login(self) -> None:
        config = SimpleNamespace(codex_command="codex", codex_home="/data/codex-home")
        completed = subprocess.CompletedProcess(
            ["codex", "login", "status"],
            0,
            stdout="Logged in using an API key\n",
        )
        with patch("gateway.client.subprocess.run", return_value=completed):
            self.assertFalse(codex_chatgpt_login_ready(config))

    def test_run_codex_login_uses_device_auth_and_isolated_managed_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = SimpleNamespace(
                codex_command="codex",
                codex_home=str(Path(tmp) / "codex-home"),
            )
            login = subprocess.CompletedProcess(["codex", "login"], 0)
            status = subprocess.CompletedProcess(
                ["codex", "login", "status"],
                0,
                stdout="Logged in using ChatGPT\n",
            )
            with patch(
                "gateway.client.subprocess.run",
                side_effect=[login, status],
            ) as run, redirect_stdout(io.StringIO()):
                self.assertEqual(run_codex_login(config), 0)

            self.assertEqual(
                run.call_args_list[0].args[0],
                ["codex", "login", "--device-auth"],
            )
            managed = (Path(config.codex_home) / "config.toml").read_text(
                encoding="utf-8"
            )
            self.assertIn('forced_login_method = "chatgpt"', managed)
            self.assertIn('cli_auth_credentials_store = "file"', managed)

    def test_codex_api_credential_filter_preserves_unrelated_values(self) -> None:
        self.assertEqual(
            _without_codex_api_credentials(
                {
                    "OPENAI_API_KEY": "secret",
                    "CODEX_API_KEY": "secret",
                    "CODEX_ACCESS_TOKEN": "secret",
                    "PATH": "/usr/bin",
                }
            ),
            {"PATH": "/usr/bin"},
        )

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
            advertise_port=19700,
        )

        command = build_provider_process_command(args, gateway_url="http://127.0.0.1:8000/v1")

        self.assertEqual(command[1:5], ["-m", "gateway", "--agents-file", "/tmp/agents.json"])
        self.assertIn("serve", command)
        self.assertIn("--bootstrap", command)
        self.assertIn("127.0.0.1:9701", command)
        self.assertIn("--consumer-public-key", command)
        self.assertIn("consumer-key", command)
        self.assertEqual(_option_value(command, "--advertise-port"), "19700")
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
        self.assertIn("--relay-provider-tls", command)
        self.assertNotIn("--bootstrap", command)

    def test_https_relay_control_url_keeps_tls_in_secure_peer_address(self) -> None:
        address = _relay_address_from_control_url(
            "https://relay.example.com",
            "peer-a",
            secure=True,
        )

        self.assertEqual(address, "myco+relays://relay.example.com:443/peer-a")

    def test_provider_rejects_gateway_profile_mismatch_and_unready_backend(self) -> None:
        self.assertIn(
            "profile mismatch",
            _gateway_profile_health_error(
                {"network_profile": "local", "settlement_ready": False},
                "testnet",
            )
            or "",
        )
        self.assertIn(
            "not settlement-ready",
            _gateway_profile_health_error(
                {
                    "network_profile": "testnet",
                    "production_strict": True,
                    "settlement_ready": False,
                    "inference_capabilities": {"limitation": "native cap unavailable"},
                },
                "testnet",
            )
            or "",
        )
        meter_public_key = "11" * 32
        meter_fingerprint = hashlib.sha256(bytes.fromhex(meter_public_key)).hexdigest()[:16]
        env = {
            "CENTER_MODEL": "engine-model",
            "UPSTREAM_EXPECTED_MODEL_REVISION": "sha256:engine",
            "UPSTREAM_CAPABILITIES_SHA256": "ab" * 32,
            "UPSTREAM_METERING_PUBLIC_KEY": meter_public_key,
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertIsNone(
                _gateway_profile_health_error(
                    {
                        "network_profile": "testnet",
                        "production_strict": True,
                        "settlement_ready": True,
                        "inference_capabilities": {
                            "schema": "mycomesh.inference.capabilities.v1",
                            "backend": "native_metered_http",
                            "native_output_token_cap": True,
                            "native_usage_events": True,
                            "trusted_native_usage": True,
                            "runtime_metering_proof": True,
                            "supports_streaming": False,
                            "production_ready": True,
                            "model": "engine-model",
                            "model_revision": "sha256:engine",
                            "capabilities_sha256": "ab" * 32,
                            "metering_key_fingerprint": meter_fingerprint,
                            "maximum_output_token_cap": 2000,
                        },
                    },
                    "testnet",
                )
            )

    def test_provider_accepts_explicit_codex_testnet_readiness_contract(self) -> None:
        payload = {
            "network_profile": "testnet",
            "production_strict": True,
            "settlement_ready": True,
            "public_model_id": "gpt-5.5",
            "inference_capabilities": {
                "schema": "mycomesh.inference.capabilities.v1",
                "backend": "codex_app_server",
                "native_output_token_cap": False,
                "native_usage_events": True,
                "trusted_native_usage": True,
                "runtime_metering_proof": False,
                "post_execution_output_cap_validation": True,
                "metering_mode": "codex-app-server-postvalidated-v1",
                "maximum_output_token_cap": 2000,
                "supports_streaming": False,
                "production_ready": True,
            },
        }
        with patch.dict(
            os.environ,
            {"MYCOMESH_CODEX_TESTNET_METERING": "true"},
            clear=True,
        ):
            self.assertIsNone(
                _gateway_profile_health_error(
                    payload,
                    "testnet",
                    expected_model="gpt-5.5",
                    minimum_output_token_cap=2000,
                )
            )

            payload["inference_capabilities"]["runtime_metering_proof"] = True
            self.assertIn(
                "Codex testnet contract",
                _gateway_profile_health_error(payload, "testnet") or "",
            )

    def test_provider_rejects_codex_testnet_readiness_without_explicit_policy(self) -> None:
        payload = {
            "network_profile": "testnet",
            "production_strict": True,
            "settlement_ready": True,
            "inference_capabilities": {
                "backend": "codex_app_server",
            },
        }
        with patch.dict(os.environ, {}, clear=True):
            self.assertIn(
                "explicit testnet policy",
                _gateway_profile_health_error(payload, "testnet") or "",
            )

    def test_start_gateway_passes_provider_network_profile_to_subprocess(self) -> None:
        process = SimpleNamespace(pid=12345)
        with tempfile.TemporaryDirectory() as tmp, patch(
            "gateway.client._read_pid", return_value=None
        ), patch("gateway.client._popen_logged", return_value=process) as popen, patch(
            "gateway.client._write_pid"
        ):
            start_gateway(
                host="127.0.0.1",
                port=8000,
                run_dir=Path(tmp),
                network_profile="testnet",
            )

        self.assertEqual(popen.call_args.kwargs["env"]["MYCOMESH_NETWORK_PROFILE"], "testnet")

    def test_build_provider_process_command_forwards_remote_gateway_https_opt_in(self) -> None:
        args = _provider_start_args(
            network_profile="local",
            allow_remote_gateway_https=True,
        )

        command = build_provider_process_command(args, gateway_url="https://gateway.example/v1")

        self.assertIn("--allow-remote-gateway-https", command)

    def test_build_provider_process_command_forwards_settlement_verification_config(self) -> None:
        args = _provider_start_args(
            settlement_version=3,
            pricing_version=7,
            settlement_rpc_url="https://rpc.example",
            settlement_contract="0x1111111111111111111111111111111111111111",
            settlement_chain_id=11155111,
            settlement_confirmations=12,
            settlement_rpc_timeout=9.5,
        )

        command = build_provider_process_command(args, gateway_url="http://127.0.0.1:8000/v1")

        self.assertEqual(_option_value(command, "--settlement-version"), "3")
        self.assertEqual(_option_value(command, "--pricing-version"), "7")
        self.assertEqual(_option_value(command, "--settlement-rpc-url"), "https://rpc.example")
        self.assertEqual(
            _option_value(command, "--settlement-contract"),
            "0x1111111111111111111111111111111111111111",
        )
        self.assertEqual(_option_value(command, "--settlement-chain-id"), "11155111")
        self.assertEqual(_option_value(command, "--settlement-confirmations"), "12")
        self.assertEqual(_option_value(command, "--settlement-rpc-timeout"), "9.5")

    def test_bridge_serve_forwards_explicit_any_signed_provider_mode(self) -> None:
        parser = _build_parser()
        defaults = parser.parse_args(["pool", "serve"])
        self.assertFalse(defaults.allow_any_signed_provider)
        self.assertFalse(defaults.trust_proxy_headers)
        signer = create_identity()
        args = parser.parse_args(
            [
                "bridge",
                "serve",
                "--public-url",
                "https://bridge.example",
                "--allow-any-signed-provider",
                "--trusted-relay-origin",
                "https://bridge.example",
                "--trust-proxy-headers",
                "--reputation-signer-public-key",
                signer.public_key,
            ]
        )

        deployment = SimpleNamespace(
            chain_id=11155111,
            settlement="0x" + "ab" * 20,
            pricing_version=7,
            pricing_hash="0x" + "cd" * 32,
            channel="codex-standard-v1",
            network_id="mycomesh-testnet",
            channel_id="codex",
            backend_policy="codex-app-server-postvalidated-v1",
        )
        with patch(
            "gateway.client.load_active_myco_deployment",
            return_value=deployment,
        ), patch("gateway.client.serve_pool") as serve, redirect_stdout(io.StringIO()):
            code = args.func(args)

        self.assertEqual(code, 0)
        config = serve.call_args.kwargs["config"]
        self.assertTrue(config.allow_any_signed_provider)
        self.assertTrue(config.trust_proxy_headers)
        self.assertEqual(config.trusted_relay_origins, {"https://bridge.example"})
        self.assertEqual(config.authorized_provider_public_keys, set())
        self.assertEqual(
            config.expected_settlement,
            {
                "version": 3,
                "chain_id": 11155111,
                "contract": "0x" + "ab" * 20,
                "pricing_version": 7,
                "pricing_hash": "0x" + "cd" * 32,
            },
        )
        self.assertEqual(config.expected_channel, "codex-standard-v1")

    def test_provider_parser_accepts_pinned_settlement_config(self) -> None:
        args = _build_parser().parse_args(
            [
                "p2p",
                "serve",
                "--settlement-version",
                "3",
                "--pricing-version",
                "4",
                "--settlement-rpc-url",
                "https://rpc.example",
                "--settlement-contract",
                "0x1111111111111111111111111111111111111111",
                "--settlement-chain-id",
                "11155111",
                "--settlement-confirmations",
                "8",
                "--settlement-rpc-timeout",
                "7.5",
            ]
        )

        self.assertEqual(args.settlement_version, 3)
        self.assertEqual(args.pricing_version, 4)
        self.assertEqual(args.settlement_chain_id, 11155111)
        self.assertEqual(args.settlement_confirmations, 8)
        self.assertEqual(args.settlement_rpc_timeout, 7.5)

    def test_testnet_provider_profile_requires_v3_finality_and_canonical_pools(self) -> None:
        base = {
            "network_profile": "testnet",
            "settlement_version": 3,
            "settlement_confirmations": 6,
            "pricing_hash": "0x" + "ab" * 32,
            "pool": "https://bridge.example,https://backup.example:8443",
            "consumer_public_key": ["consumer-key"],
        }

        def args_for(**overrides: object) -> Namespace:
            values = dict(base)
            values.update(overrides)
            return _provider_start_args(**values)

        def preflight(args: Namespace) -> str | None:
            with patch(
                "gateway.client.load_provider_evm_identity",
                return_value=SimpleNamespace(address=args.payment_address),
            ):
                return _provider_profile_preflight(args)

        self.assertIsNone(preflight(args_for()))
        self.assertIsNone(preflight(args_for(consumer_public_key=[])))
        cases = [
            ({"settlement_version": 2}, "--settlement-version 3"),
            ({"settlement_confirmations": 5}, "at least 6 settlement confirmations"),
            ({"settlement_confirmations": 6.5}, "at least 6 settlement confirmations"),
            (
                {"pricing_hash": None, "pricing_config": "pricing.json"},
                "explicit --pricing-hash",
            ),
            ({"pool": "http://bridge.example"}, "canonical HTTPS origins"),
            (
                {"pool": "https://bridge.example,https://Backup.example/"},
                "canonical HTTPS origins",
            ),
            (
                {"allow_any_signed_consumer": True},
                "wallet-bound V3 sessions",
            ),
        ]
        for overrides, expected_error in cases:
            with self.subTest(overrides=overrides):
                self.assertIn(
                    expected_error,
                    preflight(args_for(**overrides)) or "",
                )

        self.assertIsNone(
            _provider_profile_preflight(
                args_for(
                    network_profile="local",
                    settlement_version=2,
                    settlement_confirmations=0,
                    pricing_hash=None,
                    pool="http://127.0.0.1:9800",
                    consumer_public_key=[],
                )
            )
        )

    def test_direct_provider_entrypoints_apply_testnet_static_preflight(self) -> None:
        commands = [
            [
                "p2p",
                "serve",
                "--network-profile",
                "testnet",
                "--pool",
                "https://bridge.example",
                "--settlement-version",
                "2",
            ],
            [
                "p2p",
                "relay",
                "--network-profile",
                "testnet",
                "--pool",
                "https://bridge.example",
                "--settlement-version",
                "2",
            ],
        ]
        identity = create_identity()

        for command in commands:
            with self.subTest(command=command[1]):
                args = _build_parser().parse_args(command)
                errors = io.StringIO()
                with patch(
                    "gateway.client.first_agent_key",
                    return_value="gateway-key",
                ), patch(
                    "gateway.client.load_or_create_identity",
                    return_value=identity,
                ), patch(
                    "gateway.client._provider_gateway_health_preflight"
                ) as health_preflight, redirect_stderr(errors):
                    code = args.func(args)

                self.assertEqual(code, 2)
                self.assertIn("--settlement-version 3", errors.getvalue())
                health_preflight.assert_not_called()

    def test_provider_start_cleans_owned_children_on_all_exit_paths(self) -> None:
        scenarios = [
            ("normal", 7),
            ("exception", RuntimeError("provider launch failed")),
            ("keyboard", KeyboardInterrupt()),
        ]

        for mode, outcome in scenarios:
            with self.subTest(mode=mode):
                args = _local_provider_runtime_args()
                gateway_process = Mock(returncode=None)
                gateway_process.poll.return_value = None
                provider_process = Mock(returncode=7)
                if mode == "normal":
                    provider_process.poll.return_value = outcome
                elif mode == "keyboard":
                    provider_process.poll.side_effect = outcome
                gateway = _runtime_process("gateway", gateway_process)
                provider = _runtime_process("provider-direct", provider_process)
                start_error = outcome if mode == "exception" else None
                previous_sigterm = object()

                with patch(
                    "gateway.client.load_or_create_identity",
                    return_value=create_identity(),
                ), patch(
                    "gateway.client.load_config",
                    return_value=SimpleNamespace(backend="openai_http"),
                ), patch(
                    "gateway.client.ensure_agent_key",
                    return_value=(SimpleNamespace(fingerprint="provider-key"), False),
                ), patch(
                    "gateway.client.start_gateway",
                    return_value=gateway,
                ), patch(
                    "gateway.client.wait_for_gateway_health",
                    return_value=True,
                ), patch(
                    "gateway.client.fetch_health",
                    return_value=(200, "{}"),
                ), patch(
                    "gateway.client._gateway_profile_health_error",
                    return_value=None,
                ), patch(
                    "gateway.client.start_provider_process",
                    return_value=provider,
                    side_effect=start_error,
                ), patch(
                    "gateway.client.signal.getsignal",
                    return_value=previous_sigterm,
                ), patch(
                    "gateway.client.signal.signal"
                ) as set_signal, patch(
                    "gateway.client._terminate_process"
                ) as terminate, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    if mode == "exception":
                        with self.assertRaisesRegex(RuntimeError, "provider launch failed"):
                            _cmd_provider_start(args)
                    else:
                        code = _cmd_provider_start(args)

                if mode == "normal":
                    self.assertEqual(code, 7)
                elif mode == "keyboard":
                    self.assertEqual(code, 130)
                expected_cleanup = (
                    [call(gateway_process)]
                    if mode == "exception"
                    else [call(provider_process), call(gateway_process)]
                )
                self.assertEqual(terminate.call_args_list, expected_cleanup)
                self.assertEqual(
                    set_signal.call_args_list[-1],
                    call(signal.SIGTERM, previous_sigterm),
                )

    def test_provider_start_sigterm_preserves_existing_gateway(self) -> None:
        args = _local_provider_runtime_args()
        existing_gateway_process = Mock(returncode=None)
        existing_gateway_process.poll.return_value = None
        provider_process = Mock(returncode=None)
        gateway = _runtime_process(
            "gateway",
            existing_gateway_process,
            already_running=True,
        )
        provider = _runtime_process("provider-direct", provider_process)
        previous_sigterm = object()
        handlers: list[object] = []

        def set_handler(_signum: int, handler: object) -> None:
            handlers.append(handler)

        def request_termination() -> None:
            handler = handlers[0]
            self.assertTrue(callable(handler))
            handler(signal.SIGTERM, None)

        provider_process.poll.side_effect = request_termination
        with patch(
            "gateway.client.load_or_create_identity",
            return_value=create_identity(),
        ), patch(
            "gateway.client.load_config",
            return_value=SimpleNamespace(backend="openai_http"),
        ), patch(
            "gateway.client.ensure_agent_key",
            return_value=(SimpleNamespace(fingerprint="provider-key"), False),
        ), patch(
            "gateway.client.start_gateway",
            return_value=gateway,
        ), patch(
            "gateway.client.wait_for_gateway_health",
            return_value=True,
        ), patch(
            "gateway.client.fetch_health",
            return_value=(200, "{}"),
        ), patch(
            "gateway.client._gateway_profile_health_error",
            return_value=None,
        ), patch(
            "gateway.client.start_provider_process",
            return_value=provider,
        ), patch(
            "gateway.client.signal.getsignal",
            return_value=previous_sigterm,
        ), patch(
            "gateway.client.signal.signal",
            side_effect=set_handler,
        ), patch(
            "gateway.client._terminate_process"
        ) as terminate, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = _cmd_provider_start(args)

        self.assertEqual(code, 143)
        terminate.assert_called_once_with(provider_process)
        self.assertIs(handlers[-1], previous_sigterm)

    def test_p2p_ping_requires_live_bridge_registration(self) -> None:
        args = _build_parser().parse_args(
            ["p2p", "ping", "127.0.0.1:9700", "--require-bridge-ready"]
        )
        errors = io.StringIO()

        with patch(
            "gateway.client.send_message",
            return_value={"ok": True, "bridge_ready": False},
        ), redirect_stderr(errors):
            code = _cmd_p2p_ping(args)

        self.assertEqual(code, 1)
        self.assertIn("no live Bridge registration", errors.getvalue())

    def test_provider_start_v3_preflight_fails_before_starting_services(self) -> None:
        args = _provider_start_args(
            settlement_version=3,
            settlement_rpc_url="https://rpc.example",
            settlement_contract="0x1111111111111111111111111111111111111111",
            settlement_chain_id=11155111,
            pricing_hash="0x" + "ab" * 32,
        )
        identity = create_identity()
        errors = io.StringIO()

        with patch(
            "gateway.client._hydrate_provider_v3_manifest",
            return_value=None,
        ), patch(
            "gateway.client._resolve_provider_advertise_address",
            return_value=None,
        ), patch(
            "gateway.client.load_or_create_identity",
            return_value=identity,
        ), patch(
            "gateway.client._provider_profile_preflight",
            return_value=None,
        ), patch(
            "gateway.client.load_active_myco_deployment",
            return_value=SimpleNamespace(),
        ), patch(
            "gateway.client.verify_v3_deployment_preflight",
            side_effect=ChainError("finalized deployment mismatch"),
        ), patch("gateway.client.start_gateway") as start_gateway_mock, patch(
            "gateway.client.start_provider_process"
        ) as start_provider_mock, redirect_stdout(io.StringIO()), redirect_stderr(errors):
            code = _cmd_provider_start(args)

        self.assertEqual(code, 1)
        self.assertIn("Settlement V3 finalized preflight failed", errors.getvalue())
        start_gateway_mock.assert_not_called()
        start_provider_mock.assert_not_called()

    def test_inference_parser_accepts_v3_reservation_binding(self) -> None:
        reservation_id = "0x" + "ab" * 32
        wallet_private_key = "0x" + "11" * 32
        args = _build_parser().parse_args(
            [
                "p2p",
                "infer",
                "127.0.0.1:9700",
                "hello",
                "--settlement-version",
                "3",
                "--pricing-version",
                "7",
                "--onchain-reservation-id",
                reservation_id,
                "--reservation-expires-at",
                "2000000000",
                "--settlement-deadline",
                "1999999999",
                "--settlement-chain-id",
                "11155111",
                "--settlement-contract",
                "0x3333333333333333333333333333333333333333",
                "--consumer-wallet-private-key",
                wallet_private_key,
            ]
        )

        self.assertEqual(args.settlement_version, 3)
        self.assertEqual(args.pricing_version, 7)
        self.assertEqual(args.onchain_reservation_id, reservation_id)
        self.assertEqual(args.reservation_expires_at, 2_000_000_000)
        self.assertEqual(args.settlement_deadline, 1_999_999_999)
        self.assertEqual(args.settlement_chain_id, 11155111)
        self.assertEqual(args.consumer_wallet_private_key, wallet_private_key)

    def test_send_infer_builds_complete_v3_payment_reservation(self) -> None:
        identity = create_identity()
        wallet_private_key = "0x" + "11" * 32
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        settlement_contract = "0x3333333333333333333333333333333333333333"
        expires_at = int(time.time()) + 300
        captured: dict[str, object] = {}

        def fake_send(_peer: object, message: dict[str, object], timeout: float) -> dict[str, object]:
            captured.update(message)
            return {"ok": True, "request_id": message["request_id"], "output_text": "ok"}

        with patch("gateway.client.send_message", side_effect=fake_send):
            _send_infer_to_address(
                address="tcp://127.0.0.1:9700",
                channel="codex-standard-v1",
                endpoint="responses",
                model="gpt-5.5",
                input_value="hello",
                pool_url="http://127.0.0.1:9800",
                peer_id="peer-provider",
                timeout=5.0,
                identity=identity,
                consumer_id="consumer-a",
                consumer_payment_address=consumer_address,
                provider_payment_address=_ADDRESS_B,
                pricing_hash="0x" + "cd" * 32,
                max_fee_units=100_000,
                max_output_tokens=2000,
                settlement_version=3,
                pricing_version=7,
                onchain_reservation_id="0x" + "ab" * 32,
                expires_at=expires_at,
                settlement_deadline=expires_at - 1,
                settlement_chain_id=11155111,
                settlement_contract=settlement_contract,
                consumer_wallet_private_key=wallet_private_key,
                network_id="mycomesh-testnet",
                channel_id="codex",
                backend_policy="codex-app-server-postvalidated-v1",
            )

        reservation = verify_payment_reservation(
            captured["payment_reservation"],
            request_id=str(captured["request_id"]),
            channel="codex-standard-v1",
            provider_id="peer-provider",
            provider_payment_address=_ADDRESS_B,
            consumer_public_key=identity.public_key,
            settlement_version=3,
            pricing_version=7,
            settlement_chain_id=11155111,
            settlement_contract=settlement_contract,
        )
        self.assertEqual(reservation["onchain_reservation_id"], "0x" + "ab" * 32)
        self.assertEqual(
            reservation["request_hash"],
            "0x"
            + inference_request_hash(
                endpoint="responses",
                model="gpt-5.5",
                input_value="hello",
                max_output_tokens=2000,
            ),
        )
        self.assertEqual(reservation["expires_at"], expires_at)
        self.assertEqual(reservation["settlement_deadline"], expires_at - 1)
        self.assertFalse(reservation["provider_fallback_allowed"])
        verify_eoa_session_authorization(reservation["evm_session_authorization"])
        self.assertNotIn("metadata", captured)
        self.assertNotIn("provider_peer_id", captured)

    def test_send_infer_keeps_route_metadata_only_for_legacy_v2(self) -> None:
        captured: dict[str, object] = {}

        def fake_send(_peer: object, message: dict[str, object], timeout: float) -> dict[str, object]:
            captured.update(message)
            return {"ok": True, "request_id": message["request_id"], "output_text": "ok"}

        with patch("gateway.client.send_message", side_effect=fake_send):
            _send_infer_to_address(
                address="tcp://127.0.0.1:9700",
                channel="codex-standard-v1",
                endpoint="responses",
                model="gpt-5.5",
                input_value="hello",
                pool_url="http://127.0.0.1:9800",
                peer_id="peer-provider",
                timeout=5.0,
            )

        self.assertEqual(
            captured["metadata"],
            {
                "pool_url": "http://127.0.0.1:9800",
                "selected_peer_id": "peer-provider",
                "selected_address": "tcp://127.0.0.1:9700",
            },
        )

    def test_direct_v3_infer_consumes_all_wallet_authorization_inputs(self) -> None:
        identity = create_identity()
        wallet_private_key = "0x" + "11" * 32
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        expires_at = int(time.time()) + 900
        deadline = expires_at - 1
        pricing_hash = "0x" + "cd" * 32
        request_hash = "0x" + inference_request_hash(
            endpoint="responses",
            model="gpt-5.5",
            input_value="hello",
            max_output_tokens=1,
        )
        full_authorization = build_evm_session_authorization(
            chain_id=11155111,
            settlement_contract="0x3333333333333333333333333333333333333333",
            onchain_reservation_id="0x" + "ab" * 32,
            consumer_payment_address=consumer_address,
            provider_id="peer-provider",
            provider_payment_address=_ADDRESS_B,
            channel="codex-standard-v1",
            pricing_hash=pricing_hash,
            pricing_version=7,
            request_hash=request_hash,
            max_fee_units=100_000,
            expires_at=expires_at,
            settlement_deadline=deadline,
            provider_fallback_allowed=False,
            session_public_key=identity.public_key,
            wallet_private_key=wallet_private_key,
        )
        cases = {
            "local-key": ["--consumer-wallet-private-key", wallet_private_key],
            "external-signature": [
                "--session-authorization-signature",
                "0x1234",
                "--session-authorization-nonce",
                "0x" + "99" * 32,
            ],
            "full-json": ["--evm-session-authorization", json.dumps(full_authorization)],
        }

        for label, source_args in cases.items():
            with self.subTest(source=label):
                args = _build_parser().parse_args(
                    _v3_inference_cli_args("direct", consumer_address, expires_at) + source_args
                )
                captured: dict[str, object] = {}

                def fake_send(
                    _peer: object,
                    message: dict[str, object],
                    timeout: float,
                ) -> dict[str, object]:
                    captured.update(message)
                    return {"ok": True, "request_id": message["request_id"], "output_text": "ok"}

                with patch("gateway.client.load_or_create_identity", return_value=identity), patch(
                    "gateway.client.send_message",
                    side_effect=fake_send,
                ), patch("gateway.client.verify_provider_response"), redirect_stdout(io.StringIO()):
                    code = _cmd_p2p_infer(args)

                self.assertEqual(code, 0)
                authorization = captured["payment_reservation"]["evm_session_authorization"]
                if label == "local-key":
                    verify_eoa_session_authorization(authorization)
                elif label == "external-signature":
                    self.assertEqual(authorization["wallet_signature"], "0x1234")
                    self.assertEqual(authorization["nonce"], "0x" + "99" * 32)
                else:
                    self.assertEqual(authorization, full_authorization)

    def test_pool_v3_infer_forwards_all_wallet_authorization_inputs(self) -> None:
        identity = create_identity()
        wallet_private_key = "0x" + "11" * 32
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        expires_at = int(time.time()) + 900
        complete_authorization = {"authorization_version": "complete-test-document"}
        cases = {
            "local-key": (
                ["--consumer-wallet-private-key", wallet_private_key],
                "consumer_wallet_private_key",
                wallet_private_key,
            ),
            "external-signature": (
                [
                    "--session-authorization-signature",
                    "0x1234",
                    "--session-authorization-nonce",
                    "0x" + "99" * 32,
                ],
                "session_authorization_signature",
                "0x1234",
            ),
            "full-json": (
                ["--evm-session-authorization", json.dumps(complete_authorization)],
                "evm_session_authorization",
                complete_authorization,
            ),
        }
        peer = {
            "peer_id": "peer-provider",
            "address": "tcp://127.0.0.1:9700",
            "payment_address": _ADDRESS_B,
            "pool_url": "http://127.0.0.1:9800",
            "capacity": {"max_concurrency": 1},
        }

        for label, (source_args, expected_key, expected_value) in cases.items():
            with self.subTest(source=label):
                args = _build_parser().parse_args(
                    _v3_inference_cli_args("pool", consumer_address, expires_at) + source_args
                )
                args.route_state = None
                args.no_ledger = True
                captured: dict[str, object] = {}

                def fake_send(**kwargs: object) -> dict[str, object]:
                    captured.update(kwargs)
                    return {
                        "ok": True,
                        "request_id": "req-pool-v3",
                        "output_text": "ok",
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    }

                with patch("gateway.client.load_or_create_identity", return_value=identity), patch(
                    "gateway.client.discover_peers_from_pools",
                    return_value=[peer],
                ), patch(
                    "gateway.client._send_infer_to_address",
                    side_effect=fake_send,
                ), redirect_stdout(io.StringIO()):
                    code = _cmd_pool_infer(args)

                self.assertEqual(code, 0)
                self.assertEqual(captured[expected_key], expected_value)
                self.assertEqual(captured["settlement_chain_id"], 11155111)
                self.assertEqual(
                    captured["settlement_contract"],
                    "0x3333333333333333333333333333333333333333",
                )

    def test_direct_and_pool_prepare_session_authorization_without_network(self) -> None:
        identity = create_identity()
        wallet_private_key = "0x" + "11" * 32
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        expires_at = int(time.time()) + 900

        for mode in ("direct", "pool"):
            with self.subTest(mode=mode):
                args = _build_parser().parse_args(
                    _v3_inference_cli_args(mode, consumer_address, expires_at)
                    + ["--prepare-session-authorization"]
                )
                args.consumer_wallet_private_key = None
                args.session_authorization_signature = None
                output = io.StringIO()
                with patch("gateway.client.load_or_create_identity", return_value=identity), patch(
                    "gateway.client.send_message",
                ) as direct_send, patch(
                    "gateway.client.discover_peers_from_pools",
                ) as pool_discovery, redirect_stdout(output):
                    code = _cmd_p2p_infer(args) if mode == "direct" else _cmd_pool_infer(args)

                self.assertEqual(code, 0)
                prepared = json.loads(output.getvalue())
                authorization = prepared["authorization"]
                self.assertNotIn("wallet_signature", authorization)
                self.assertEqual(authorization["session_public_key"], identity.public_key)
                self.assertEqual(
                    prepared["eip191_digest"],
                    "0x" + evm_session_authorization_digest(authorization).hex(),
                )
                self.assertEqual(json.loads(prepared["canonical_message"]), authorization)
                direct_send.assert_not_called()
                pool_discovery.assert_not_called()

    def test_prepared_authorization_matches_external_signed_fields(self) -> None:
        identity = create_identity()
        consumer_address = private_key_to_address(parse_private_key("0x" + "11" * 32))
        expires_at = int(time.time()) + 900
        nonce = "0x" + "99" * 32
        settlement = {
            "settlement_version": 3,
            "settlement_chain_id": 11155111,
            "settlement_contract": "0x3333333333333333333333333333333333333333",
            "onchain_reservation_id": "0x" + "ab" * 32,
            "pricing_version": 7,
            "expires_at": expires_at,
            "settlement_deadline": expires_at - 1,
            "provider_fallback_allowed": False,
            "session_authorization_nonce": nonce,
        }
        prepared = _prepare_evm_session_authorization(
            identity=identity,
            consumer_payment_address=consumer_address,
            provider_id="peer-provider",
            provider_payment_address=_ADDRESS_B,
            channel="codex-standard-v1",
            pricing_hash="0x" + "cd" * 32,
            request_hash="0x" + "ef" * 32,
            max_fee_units=100_000,
            settlement=settlement,
        )
        signed = build_evm_session_authorization(
            chain_id=11155111,
            settlement_contract=str(settlement["settlement_contract"]),
            onchain_reservation_id=str(settlement["onchain_reservation_id"]),
            consumer_payment_address=consumer_address,
            provider_id="peer-provider",
            provider_payment_address=_ADDRESS_B,
            channel="codex-standard-v1",
            pricing_hash="0x" + "cd" * 32,
            pricing_version=7,
            request_hash="0x" + "ef" * 32,
            max_fee_units=100_000,
            expires_at=expires_at,
            settlement_deadline=expires_at - 1,
            provider_fallback_allowed=False,
            session_public_key=identity.public_key,
            nonce=nonce,
            wallet_signature="0x1234",
        )

        signed_fields = dict(signed)
        signed_fields.pop("wallet_signature")
        self.assertEqual(signed_fields, prepared["authorization"])

    def test_direct_v3_infer_loads_complete_authorization_from_file(self) -> None:
        identity = create_identity()
        wallet_private_key = "0x" + "11" * 32
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        expires_at = int(time.time()) + 900
        authorization = build_evm_session_authorization(
            chain_id=11155111,
            settlement_contract="0x3333333333333333333333333333333333333333",
            onchain_reservation_id="0x" + "ab" * 32,
            consumer_payment_address=consumer_address,
            provider_id="peer-provider",
            provider_payment_address=_ADDRESS_B,
            channel="codex-standard-v1",
            pricing_hash="0x" + "cd" * 32,
            pricing_version=7,
            request_hash="0x"
            + inference_request_hash(
                endpoint="responses",
                model="gpt-5.5",
                input_value="hello",
                max_output_tokens=1,
            ),
            max_fee_units=100_000,
            expires_at=expires_at,
            settlement_deadline=expires_at - 1,
            provider_fallback_allowed=False,
            session_public_key=identity.public_key,
            wallet_private_key=wallet_private_key,
        )
        captured: dict[str, object] = {}

        def fake_send(_peer: object, message: dict[str, object], timeout: float) -> dict[str, object]:
            captured.update(message)
            return {"ok": True, "request_id": message["request_id"], "output_text": "ok"}

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authorization.json"
            path.write_text(json.dumps(authorization), encoding="utf-8")
            args = _build_parser().parse_args(
                _v3_inference_cli_args("direct", consumer_address, expires_at)
                + ["--evm-session-authorization", "@" + str(path)]
            )
            args.consumer_wallet_private_key = None
            args.session_authorization_signature = None
            with patch("gateway.client.load_or_create_identity", return_value=identity), patch(
                "gateway.client.send_message",
                side_effect=fake_send,
            ), patch("gateway.client.verify_provider_response"), redirect_stdout(io.StringIO()):
                code = _cmd_p2p_infer(args)

        self.assertEqual(code, 0)
        self.assertEqual(captured["payment_reservation"]["evm_session_authorization"], authorization)

    def test_v2_prepare_session_authorization_fails_without_network(self) -> None:
        identity = create_identity()
        commands = {
            "direct": ["p2p", "infer", "127.0.0.1:9700", "hello"],
            "pool": ["pool", "infer", "hello", "--pool", "http://127.0.0.1:9800"],
        }
        for mode, command in commands.items():
            for explicit_version in (False, True):
                with self.subTest(mode=mode, explicit_version=explicit_version), patch.dict(
                    os.environ,
                    {"MYCOMESH_SETTLEMENT_VERSION": "2"},
                ):
                    cli = command + ["--prepare-session-authorization"]
                    if explicit_version:
                        cli += ["--settlement-version", "2"]
                    args = _build_parser().parse_args(cli)
                    errors = io.StringIO()
                    with patch("gateway.client.load_or_create_identity", return_value=identity), patch(
                        "gateway.client.send_message",
                    ) as direct_send, patch(
                        "gateway.client.discover_peers_from_pools",
                    ) as pool_discovery, redirect_stderr(errors):
                        code = _cmd_p2p_infer(args) if mode == "direct" else _cmd_pool_infer(args)

                    self.assertEqual(code, 2)
                    self.assertIn("requires --settlement-version 3", errors.getvalue())
                    direct_send.assert_not_called()
                    pool_discovery.assert_not_called()

    def test_prepare_session_authorization_rejects_invalid_time_windows_without_network(self) -> None:
        identity = create_identity()
        consumer_address = private_key_to_address(parse_private_key("0x" + "11" * 32))
        now = int(time.time())
        cases = {
            "expired": (now - 10, now - 20, "within the next 30 days"),
            "too-far": (
                now + MAX_RESERVATION_TTL_SECONDS + 60,
                now + 60,
                "within the next 30 days",
            ),
            "inactive-deadline": (now + 900, now - 10, "deadline must be active"),
            "deadline-after-expiry": (now + 900, now + 901, "deadline must be active"),
        }

        for mode in ("direct", "pool"):
            for label, (expires_at, deadline, expected_error) in cases.items():
                with self.subTest(mode=mode, case=label):
                    cli = _v3_inference_cli_args(mode, consumer_address, expires_at)
                    cli[cli.index("--settlement-deadline") + 1] = str(deadline)
                    args = _build_parser().parse_args(cli + ["--prepare-session-authorization"])
                    args.consumer_wallet_private_key = None
                    args.session_authorization_signature = None
                    args.evm_session_authorization = None
                    errors = io.StringIO()
                    with patch("gateway.client.load_or_create_identity", return_value=identity), patch(
                        "gateway.client.send_message",
                    ) as direct_send, patch(
                        "gateway.client.discover_peers_from_pools",
                    ) as pool_discovery, redirect_stderr(errors):
                        code = _cmd_p2p_infer(args) if mode == "direct" else _cmd_pool_infer(args)

                    self.assertEqual(code, 2)
                    self.assertIn(expected_error, errors.getvalue())
                    direct_send.assert_not_called()
                    pool_discovery.assert_not_called()

    def test_all_v3_chain_commands_are_registered(self) -> None:
        parser = _build_parser()
        commands = {
            "deploy-myco-v3-testnet": [],
            "myco-v3-info": [],
            "v3-mint-test-usdc": ["--to", _ADDRESS_A, "--amount-usdc", "1"],
            "v3-approve-usdc": ["--amount-usdc", "1"],
            "v3-deposit-prepaid": ["--amount-usdc", "1"],
            "v3-withdraw-prepaid": ["--amount-usdc", "1"],
            "v3-prepaid-balance": ["--account", _ADDRESS_A],
            "v3-create-reservation": [
                "--provider",
                _ADDRESS_B,
                "--input",
                "hello",
                "--amount-usdc",
                "1",
                "--expires-at",
                "2000000000",
            ],
            "v3-release-reservation": ["--reservation-id", "0x" + "11" * 32],
            "v3-prepare-receipt": [],
            "v3-settle-signed-receipt": [],
            "v3-prepare-provider-fallback": [],
            "v3-settle-provider-fallback": [],
        }

        for command, extra in commands.items():
            with self.subTest(command=command):
                args = parser.parse_args(["chain", command, *extra])
                self.assertEqual(args.chain_command, command)
                self.assertEqual(args.deployment, DEFAULT_MYCO_V3_DEPLOYMENT_PATH)

    def test_prepare_v3_receipt_prints_digest_and_named_abi_fields(self) -> None:
        deployment, settlement, chain_id, receipt_input = _v3_receipt_fixture()
        args = Namespace()
        output = io.StringIO()

        with patch(
            "gateway.client._load_v3_receipt_input",
            return_value=(deployment, settlement, chain_id, {}, receipt_input),
        ), redirect_stdout(output):
            code = _cmd_chain_v3_prepare_receipt(args)

        self.assertEqual(code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["eip712_domain"]["verifyingContract"], settlement)
        self.assertRegex(payload["eip712_digest"], r"^0x[0-9a-f]{64}$")
        self.assertEqual(payload["receipt_abi_fields"]["reservationId"], receipt_input.reservation_id)
        self.assertEqual(len(payload["receipt_abi_args"]), 15)

    def test_settle_v3_receipt_accepts_valid_external_signatures(self) -> None:
        deployment, settlement, chain_id, receipt_input = _v3_receipt_fixture()
        digest = receipt_digest(receipt_input, chain_id=chain_id, verifying_contract=settlement)
        consumer_signature = signature_bytes(sign_evm_digest(_CONSUMER_KEY, digest))
        provider_signature = signature_bytes(sign_evm_digest(_PROVIDER_KEY, digest))
        args = _v3_settle_args(
            consumer_signature="0x" + consumer_signature.hex(),
            provider_signature="0x" + provider_signature.hex(),
        )
        output = io.StringIO()

        with patch(
            "gateway.client._load_v3_receipt_input",
            return_value=(deployment, settlement, chain_id, {}, receipt_input),
        ), patch("gateway.client.settle_v3_signed_receipt", return_value="0x" + "99" * 32) as settle, redirect_stdout(output):
            code = _cmd_chain_v3_settle_signed_receipt(args)

        self.assertEqual(code, 0)
        signed_receipt = settle.call_args.kwargs["signed_receipt"]
        self.assertEqual(signed_receipt.consumer_signature, consumer_signature)
        self.assertEqual(signed_receipt.provider_signature, provider_signature)
        self.assertEqual(json.loads(output.getvalue())["eip712_digest"], "0x" + digest.hex())

    def test_settle_v3_receipt_supports_local_consumer_and_provider_keys(self) -> None:
        deployment, settlement, chain_id, receipt_input = _v3_receipt_fixture()
        signed_receipt = SimpleNamespace(
            receipt=receipt_input,
            consumer_signature=b"c" * 65,
            provider_signature=b"p" * 65,
        )
        args = _v3_settle_args(
            consumer_private_key=_CONSUMER_KEY,
            provider_private_key=_PROVIDER_KEY,
        )

        with patch(
            "gateway.client._load_v3_receipt_input",
            return_value=(deployment, settlement, chain_id, {"job_id": "job-1"}, receipt_input),
        ), patch(
            "gateway.client.build_v3_signed_receipt_input",
            return_value=signed_receipt,
        ) as build_signed, patch(
            "gateway.client.settle_v3_signed_receipt",
            return_value="0x" + "99" * 32,
        ) as settle, redirect_stdout(io.StringIO()):
            code = _cmd_chain_v3_settle_signed_receipt(args)

        self.assertEqual(code, 0)
        self.assertEqual(build_signed.call_args.args[0], {"job_id": "job-1"})
        self.assertEqual(build_signed.call_args.kwargs["consumer_private_key"], _CONSUMER_KEY)
        self.assertEqual(build_signed.call_args.kwargs["provider_private_key"], _PROVIDER_KEY)
        self.assertIs(settle.call_args.kwargs["signed_receipt"], signed_receipt)

    def test_settle_v3_receipt_rejects_signature_for_wrong_address(self) -> None:
        deployment, settlement, chain_id, receipt_input = _v3_receipt_fixture()
        digest = receipt_digest(receipt_input, chain_id=chain_id, verifying_contract=settlement)
        wrong_consumer_signature = signature_bytes(sign_evm_digest(_PROVIDER_KEY, digest))
        provider_signature = signature_bytes(sign_evm_digest(_PROVIDER_KEY, digest))
        args = _v3_settle_args(
            consumer_signature="0x" + wrong_consumer_signature.hex(),
            provider_signature="0x" + provider_signature.hex(),
        )
        errors = io.StringIO()

        with patch(
            "gateway.client._load_v3_receipt_input",
            return_value=(deployment, settlement, chain_id, {}, receipt_input),
        ), patch("gateway.client.settle_v3_signed_receipt") as settle, redirect_stderr(errors):
            code = _cmd_chain_v3_settle_signed_receipt(args)

        self.assertEqual(code, 1)
        self.assertIn("consumer signature does not match", errors.getvalue())
        settle.assert_not_called()

    def test_settle_v3_fallback_supports_eip1271_contract_signature(self) -> None:
        deployment, settlement, chain_id, receipt_input = _v3_receipt_fixture()
        contract_signature = b"safe-contract-signature"
        args = _v3_settle_args(provider_contract_signature="0x" + contract_signature.hex())

        with patch(
            "gateway.client._load_v3_provider_fallback_input",
            return_value=(deployment, settlement, chain_id, {}, receipt_input),
        ), patch("gateway.client.verify_v3_eip1271_signature") as verify, patch(
            "gateway.client.settle_v3_provider_fallback",
            return_value="0x" + "99" * 32,
        ) as settle, redirect_stdout(io.StringIO()):
            code = _cmd_chain_v3_settle_provider_fallback(args)

        self.assertEqual(code, 0)
        self.assertEqual(verify.call_args.kwargs["signer"], receipt_input.provider)
        self.assertEqual(verify.call_args.kwargs["signature"], contract_signature)
        self.assertEqual(verify.call_args.kwargs["caller"], settlement)
        self.assertEqual(settle.call_args.kwargs["provider_signature"], contract_signature)

    def test_external_v3_signature_parser_is_strict_and_normalizes_recovery_id(self) -> None:
        signature = "0x" + (1).to_bytes(32, "big").hex() + (1).to_bytes(32, "big").hex() + "00"
        parsed = _parse_v3_external_signature(signature, "consumer")
        self.assertEqual(len(parsed), 65)
        self.assertEqual(parsed[-1], 27)

        with self.assertRaisesRegex(ChainError, "exactly 65 bytes"):
            _parse_v3_external_signature("0x1234", "consumer")
        with self.assertRaisesRegex(ChainError, "recovery id"):
            _parse_v3_external_signature(signature[:-2] + "02", "consumer")

    def test_v3_manifest_hydrates_provider_public_network_fields(self) -> None:
        deployment = SimpleNamespace(
            settlement="0x1111111111111111111111111111111111111111",
            chain_id=11155111,
            pricing_version=7,
            pricing_hash="0x" + "ab" * 32,
            channel="codex-standard-v1",
            network_id="mycomesh-testnet",
            channel_id="codex",
            backend_policy="codex-app-server-postvalidated-v1",
        )
        args = _provider_start_args(
            settlement_version=3,
            settlement_contract=None,
            settlement_chain_id=None,
            pricing_version=None,
            pricing_hash=None,
        )

        with patch("gateway.client.load_active_myco_deployment", return_value=deployment):
            error = _hydrate_provider_v3_manifest(args)

        self.assertIsNone(error)
        self.assertEqual(args.settlement_contract, deployment.settlement)
        self.assertEqual(args.settlement_chain_id, deployment.chain_id)
        self.assertEqual(args.pricing_version, deployment.pricing_version)
        self.assertEqual(args.pricing_hash, deployment.pricing_hash)

    def test_v3_manifest_rejects_conflicting_provider_override(self) -> None:
        deployment = SimpleNamespace(
            settlement="0x1111111111111111111111111111111111111111",
            chain_id=11155111,
            pricing_version=1,
            pricing_hash="0x" + "ab" * 32,
            channel="codex-standard-v1",
            network_id="mycomesh-testnet",
            channel_id="codex",
            backend_policy="codex-app-server-postvalidated-v1",
        )
        args = _provider_start_args(
            settlement_version=3,
            settlement_contract="0x2222222222222222222222222222222222222222",
            settlement_chain_id=None,
            pricing_version=None,
            pricing_hash=None,
        )

        with patch("gateway.client.load_active_myco_deployment", return_value=deployment):
            error = _hydrate_provider_v3_manifest(args)

        self.assertIn("does not match", error or "")

    def test_provider_auto_ipv4_requires_bridge_consensus(self) -> None:
        args = _provider_start_args(
            advertise_host="auto",
            advertise_port=19700,
            pool="https://bridge-a.example,https://bridge-b.example",
        )
        with patch(
            "gateway.client.get_pool_observed_ip",
            side_effect=["8.8.8.8", "8.8.8.8"],
        ) as observed:
            self.assertIsNone(_resolve_provider_advertise_address(args))

        self.assertEqual(args.advertise_host, "8.8.8.8")
        self.assertEqual(args.advertise_port, 19700)
        self.assertEqual(observed.call_count, 2)

        args.advertise_host = "auto"
        with patch(
            "gateway.client.get_pool_observed_ip",
            side_effect=["8.8.8.8", "1.1.1.1"],
        ):
            self.assertIn(
                "disagree",
                _resolve_provider_advertise_address(args) or "",
            )

    def test_explicit_provider_ipv4_skips_discovery_and_rejects_private_ip(self) -> None:
        args = _provider_start_args(
            advertise_host="8.8.4.4",
            advertise_port=None,
            provider_port=9701,
        )
        with patch("gateway.client.get_pool_observed_ip") as observed:
            self.assertIsNone(_resolve_provider_advertise_address(args))
        observed.assert_not_called()
        self.assertEqual(args.advertise_port, 9701)

        args.advertise_host = "127.0.0.1"
        self.assertIn(
            "literal public IPv4",
            _resolve_provider_advertise_address(args) or "",
        )


    def test_pool_post_json_disables_redirects(self) -> None:
        response = io.BytesIO(b'{"ok":true}')
        with patch(
            "gateway.client._HEALTH_OPENER.open",
            return_value=response,
        ) as no_redirect, patch(
            "gateway.client.urllib.request.urlopen",
            side_effect=AssertionError("redirecting opener must not be used"),
        ):
            self.assertEqual(
                _pool_post_json(
                    "https://bridge.example",
                    "/leave",
                    {"peer_id": "peer-a"},
                    timeout=5,
                ),
                {"ok": True},
            )

        request = no_redirect.call_args.args[0]
        self.assertEqual(request.full_url, "https://bridge.example/leave")
        self.assertEqual(request.get_method(), "POST")


    def test_provider_pool_url_preserves_configured_pools(self) -> None:
        self.assertIsNone(_provider_pool_url(None))
        self.assertEqual(
            _provider_pool_url("http://127.0.0.1:9800, http://127.0.0.1:9802"),
            "http://127.0.0.1:9800,http://127.0.0.1:9802",
        )

def _provider_start_args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "agents_file": "agents.json",
        "skip_login": True,
        "no_device_auth": False,
        "gateway_host": "127.0.0.1",
        "gateway_port": 8000,
        "gateway_url": None,
        "gateway_reload": False,
        "run_dir": ".codex-run",
        "health_timeout": 1.0,
        "transport": "direct",
        "provider_host": "0.0.0.0",
        "provider_port": 9700,
        "advertise_host": "127.0.0.1",
        "advertise_port": None,
        "relay_host": "127.0.0.1",
        "relay_port": 9901,
        "relay_public_url": None,
        "relay_provider_tls": True,
        "agent": "coder",
        "channel": "codex-standard-v1",
        "network_id": "mycomesh-testnet",
        "channel_id": "codex",
        "backend_policy": "codex-app-server-postvalidated-v1",
        "model": "gpt-5.5",
        "identity": ".codex-run/node-identity.json",
        "evm_identity": ".codex-run/provider-evm-identity.json",
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
        "allow_remote_gateway_https": False,
        "settlement_version": 2,
        "pricing_version": 1,
        "settlement_rpc_url": None,
        "settlement_contract": None,
        "settlement_chain_id": None,
        "settlement_confirmations": 6,
        "settlement_rpc_timeout": 20.0,
    }
    values.update(overrides)
    return Namespace(**values)


def _local_provider_runtime_args() -> Namespace:
    return _provider_start_args(
        network_profile="local",
        pool="http://127.0.0.1:9800",
        settlement_version=2,
        settlement_confirmations=0,
        pricing_hash=None,
    )


def _runtime_process(
    name: str,
    process: object,
    *,
    already_running: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        pid=12345,
        log_path=Path(".codex-run") / f"{name}.log",
        process=process,
        already_running=already_running,
    )


_CONSUMER_KEY = "0x" + "11" * 32
_PROVIDER_KEY = "0x" + "22" * 32
_ADDRESS_A = "0x1111111111111111111111111111111111111111"
_ADDRESS_B = "0x2222222222222222222222222222222222222222"


def _v3_inference_cli_args(mode: str, consumer_address: str, expires_at: int) -> list[str]:
    if mode == "direct":
        command = ["p2p", "infer", "127.0.0.1:9700", "hello", "--max-output-tokens", "1"]
    elif mode == "pool":
        command = [
            "pool",
            "infer",
            "hello",
            "--pool",
            "http://127.0.0.1:9800",
            "--reserve-input-tokens",
            "8",
            "--reserve-output-tokens",
            "1",
            "--no-ledger",
        ]
    else:
        raise AssertionError(mode)
    return command + [
        "--consumer-payment-address",
        consumer_address,
        "--provider-peer-id",
        "peer-provider",
        "--provider-payment-address",
        _ADDRESS_B,
        "--pricing-hash",
        "0x" + "cd" * 32,
        "--settlement-version",
        "3",
        "--pricing-version",
        "7",
        "--settlement-chain-id",
        "11155111",
        "--settlement-contract",
        "0x3333333333333333333333333333333333333333",
        "--onchain-reservation-id",
        "0x" + "ab" * 32,
        "--reservation-expires-at",
        str(expires_at),
        "--settlement-deadline",
        str(expires_at - 1),
    ]


def _option_value(command: list[str], option: str) -> str:
    return command[command.index(option) + 1]


def _v3_receipt_fixture() -> tuple[SimpleNamespace, str, int, V3ReceiptInput]:
    settlement = "0x3333333333333333333333333333333333333333"
    chain_id = 11155111
    deployment = SimpleNamespace(
        protocol_version=3,
        eip712_name="MycoMesh Settlement",
        eip712_version="3",
    )
    receipt_input = V3ReceiptInput(
        receipt_hash="0x" + "01" * 32,
        accepted_hash="0x" + "02" * 32,
        reservation_id="0x" + "03" * 32,
        request_hash="0x" + "04" * 32,
        response_hash="0x" + "05" * 32,
        channel_hash="0x" + "06" * 32,
        pricing_version=1,
        pricing_hash="0x" + "07" * 32,
        consumer=private_key_to_address(parse_private_key(_CONSUMER_KEY)),
        provider=private_key_to_address(parse_private_key(_PROVIDER_KEY)),
        relay="0x0000000000000000000000000000000000000000",
        pool="0x0000000000000000000000000000000000000000",
        input_tokens=12,
        output_tokens=34,
        deadline=2_000_000_000,
    )
    return deployment, settlement, chain_id, receipt_input


def _v3_settle_args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "consumer_private_key": None,
        "provider_private_key": None,
        "consumer_signature": None,
        "provider_signature": None,
        "consumer_contract_signature": None,
        "provider_contract_signature": None,
        "rpc_url": "https://rpc.example",
        "private_key": "0x" + "33" * 32,
        "timeout": 5.0,
        "consumer_address": None,
        "provider_address": None,
        "relay_address": None,
        "pool_address": None,
    }
    values.update(overrides)
    return Namespace(**values)


if __name__ == "__main__":
    unittest.main()
