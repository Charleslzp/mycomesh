from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .config import load_config
from .identity import (
    DEFAULT_NODE_IDENTITY_PATH,
    DEFAULT_REQUEST_IDENTITY_PATH,
    NodeIdentity,
    load_or_create_identity,
    sign_document,
)
from .billing import BillingError, BillingStore, usdc_to_units
from .indexer import DEFAULT_INDEXER_STATE_PATH, sync_prepaid_balances, sync_prepaid_balances_from_events
from .ledger import DEFAULT_LEDGER_PATH, append_receipt, append_receipt_payload, build_receipt, sign_acceptance
from .p2p import (
    DEFAULT_CHANNEL,
    DEFAULT_P2P_PORT,
    P2PError,
    ProviderConfig,
    parse_peer_address,
    send_message,
    serve_provider,
)
from .pool import (
    DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
    DEFAULT_NODE_TTL_SECONDS,
    DEFAULT_POOL_PORT,
    DEFAULT_POOL_URL,
    NETWORK_PROFILE_LOCAL,
    NETWORK_PROFILE_OPEN,
    NETWORK_PROFILE_TESTNET,
    PoolConfig,
    PoolError,
    POOL_REGISTRATION_PURPOSE,
    POOL_LEAVE_PURPOSE,
    discover_peers,
    get_pool_health,
    join_pool,
    normalize_network_profile,
    serve_pool,
    start_pool_heartbeat,
    validate_pool_launch_config,
)
from .pricing import load_pricing_config, quote_usage
from .pricing_source import channel_pricing_snapshot
from .p2p import INFERENCE_REQUEST_PURPOSE
from .protocol import ProtocolValidationError, validate_settlement_receipt, verify_provider_response
from .reservation import build_payment_reservation
from .settlement_blocks import (
    DEFAULT_BRIDGE_BLOCK_REWARD_BPS,
    DEFAULT_CONSUMER_BLOCK_REWARD_BPS,
    DEFAULT_CONSUMER_VOLUME_BASE_SPEND,
    DEFAULT_CONSUMER_VOLUME_BETA,
    DEFAULT_CONSUMER_VOLUME_MAX_MULTIPLIER,
    DEFAULT_PROVIDER_BLOCK_REWARD_BPS,
    DEFAULT_SETTLEMENT_BLOCK_SECONDS,
    BlockRewardSplit,
    ConsumerVolumeRewardConfig,
    build_settlement_blocks,
    write_settlement_blocks,
)
from .replay import DEFAULT_REPLAY_DB
from .routing import (
    DEFAULT_ROUTE_STATE_PATH,
    RouteState,
    load_route_state,
    rank_peers,
    record_route_acceptance,
    record_route_dispute,
    record_route_failure,
    record_route_settlement,
    record_route_success,
    release_peer,
    reserve_peer,
    save_route_state,
)
from .relay import (
    DEFAULT_RELAY_CONTROL_PORT,
    DEFAULT_RELAY_PROVIDER_PORT,
    RelayError,
    parse_relay_address,
    run_relay_provider,
    send_relay_message,
    serve_relay,
)
from .chain import (
    DEFAULT_CHANNEL_HASH,
    DEFAULT_DEPLOYMENT_PATH,
    SEPOLIA_CHAIN_ID,
    ZERO_ADDRESS,
    ChainError,
    accept_governance_executor,
    build_delegated_receipt_settlement_args,
    build_delegated_receipt_settlement_args_from_signatures,
    approve_usdc,
    build_receipt_settlement_args,
    build_signed_receipt_settlement_args,
    deploy_myco_testnet,
    deploy_testnet,
    deposit_prepaid,
    governance_action_hash,
    load_deployment,
    load_myco_deployment,
    load_receipt,
    load_receipts,
    evm_signature_from_json,
    mint_test_usdc,
    parse_private_key,
    prepaid_balance,
    private_key_to_address,
    private_key_arg,
    rpc_url_arg,
    save_deployment,
    save_myco_deployment,
    schedule_governance_action,
    set_channel,
    set_economics,
    set_governance_delay,
    set_governance_executor,
    set_operator,
    set_settlement_delegate,
    set_treasury,
    set_trusted_settlement_enabled,
    settle_delegated_prepaid_receipt,
    settle_receipt,
    settle_signed_prepaid_receipt,
    settle_trusted_prepaid_receipt,
    stablecoin_amount,
    myco_delegate_digest,
    treasury_buyback_burn,
    treasury_arg,
    withdraw_prepaid,
    DEFAULT_MYCO_DEPLOYMENT_PATH,
)


DEFAULT_AGENT_ID = "coder"
DEFAULT_RUN_DIR = ".codex-run"
KEY_PREFIX = "gwk"
PUBLIC_URL_PATTERN = re.compile(r"https://[a-zA-Z0-9.-]+\.trycloudflare\.com")


@dataclass(frozen=True)
class RuntimeProcess:
    name: str
    pid: int
    log_path: Path
    process: subprocess.Popen | None = None
    already_running: bool = False


@dataclass(frozen=True)
class ManagedKey:
    agent_id: str
    key: str

    @property
    def fingerprint(self) -> str:
        return key_fingerprint(self.key)

    @property
    def display(self) -> str:
        if len(self.key) <= 14:
            return self.key
        return f"{self.key[:10]}...{self.key[-4:]}"


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gateway-client",
        description="Manage the local Codex gateway client.",
    )
    parser.add_argument(
        "--agents-file",
        default=os.getenv("AGENTS_FILE", "agents.json"),
        help="Path to the agents config file. Defaults to AGENTS_FILE or agents.json.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login = subparsers.add_parser("login", help="Start the official Codex login flow.")
    login.add_argument(
        "--no-device-auth",
        action="store_true",
        help="Run `codex login` instead of `codex login --device-auth`.",
    )
    login.set_defaults(func=_cmd_login)

    logout = subparsers.add_parser("logout", help="Clear this gateway's isolated Codex login state.")
    logout.add_argument(
        "--yes",
        action="store_true",
        help="Do not prompt before moving auth files out of CODEX_HOME.",
    )
    logout.set_defaults(func=_cmd_logout)

    key = subparsers.add_parser("key", help="Manage gateway agent keys.")
    key_subparsers = key.add_subparsers(dest="key_command", required=True)

    key_create = key_subparsers.add_parser(
        "create",
        aliases=["generate"],
        help="Generate and store a new key for an agent.",
    )
    key_create.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Agent id to update.")
    key_create.add_argument("--role", default="worker", help="Role for a new agent.")
    key_create.add_argument("--description", help="Description for a new agent.")
    key_create.set_defaults(func=_cmd_key_create)

    key_delete = key_subparsers.add_parser("delete", help="Delete a stored agent key.")
    key_delete.add_argument("selector", help="Full key, unique key prefix, or fingerprint prefix.")
    key_delete.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Agent id to update.")
    key_delete.set_defaults(func=_cmd_key_delete)

    key_list = key_subparsers.add_parser("list", help="List stored key fingerprints.")
    key_list.add_argument("--agent", help="Only list keys for this agent.")
    key_list.set_defaults(func=_cmd_key_list)

    key_rotate = key_subparsers.add_parser(
        "rotate",
        help="Create a replacement key and remove the selected old key.",
    )
    key_rotate.add_argument("selector", help="Old full key, unique key prefix, or fingerprint prefix.")
    key_rotate.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Agent id to update.")
    key_rotate.add_argument("--role", default="worker", help="Role for a new agent if missing.")
    key_rotate.add_argument("--description", help="Description for a new agent if missing.")
    key_rotate.set_defaults(func=_cmd_key_rotate)

    url = subparsers.add_parser("url", help="Print the public gateway URL if known.")
    url.add_argument(
        "--run-dir",
        default=DEFAULT_RUN_DIR,
        help="Directory containing cloudflared logs. Defaults to .codex-run.",
    )
    url.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    url.set_defaults(func=_cmd_url)

    status = subparsers.add_parser("status", help="Print local client status.")
    status.add_argument(
        "--run-dir",
        default=DEFAULT_RUN_DIR,
        help="Directory containing gateway and cloudflared runtime files.",
    )
    status.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    status.set_defaults(func=_cmd_status)

    serve = subparsers.add_parser("serve", help="Start the gateway server.")
    serve.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    serve.add_argument("--reload", action="store_true", help="Pass --reload to uvicorn.")
    serve.add_argument("--with-tunnel", action="store_true", help="Also start a Cloudflare quick tunnel.")
    serve.add_argument(
        "--tunnel-protocol",
        choices=["quic", "http2"],
        help="Optional cloudflared protocol override.",
    )
    serve.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    serve.set_defaults(func=_cmd_serve)

    tunnel = subparsers.add_parser("tunnel", help="Manage a Cloudflare quick tunnel.")
    tunnel_subparsers = tunnel.add_subparsers(dest="tunnel_command", required=True)

    tunnel_start = tunnel_subparsers.add_parser("start", help="Start a Cloudflare quick tunnel.")
    tunnel_start.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    tunnel_start.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    tunnel_start.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    tunnel_start.add_argument("--protocol", choices=["quic", "http2"], help="Optional protocol override.")
    tunnel_start.set_defaults(func=_cmd_tunnel_start)

    tunnel_stop = tunnel_subparsers.add_parser("stop", help="Stop a managed Cloudflare tunnel.")
    tunnel_stop.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    tunnel_stop.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    tunnel_stop.set_defaults(func=_cmd_tunnel_stop)

    tunnel_status = tunnel_subparsers.add_parser("status", help="Print managed tunnel status.")
    tunnel_status.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    tunnel_status.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    tunnel_status.set_defaults(func=_cmd_tunnel_status)

    health = subparsers.add_parser("health", help="Call the gateway /health endpoint.")
    health.add_argument("--url", help="Base URL or /health URL. Defaults to local gateway.")
    health.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    health.add_argument("--public", action="store_true", help="Use the discovered public tunnel URL.")
    health.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    health.add_argument("--timeout", type=float, default=5.0)
    health.set_defaults(func=_cmd_health)

    provider = subparsers.add_parser("provider", help="Onboard and run this machine as a MycoMesh provider.")
    provider_subparsers = provider.add_subparsers(dest="provider_command", required=True)

    provider_start = provider_subparsers.add_parser(
        "start",
        help="Login to Codex, start the local gateway, and register a provider in the pool.",
    )
    provider_start.add_argument(
        "--transport",
        choices=["direct", "relay"],
        default=os.getenv("MYCOMESH_PROVIDER_TRANSPORT", "direct"),
        help="Provider transport to advertise.",
    )
    provider_start.add_argument(
        "--skip-login",
        action="store_true",
        help="Fail instead of running Codex login when no gateway auth state is found.",
    )
    provider_start.add_argument(
        "--no-device-auth",
        action="store_true",
        help="Run `codex login` instead of `codex login --device-auth` when login is needed.",
    )
    provider_start.add_argument("--gateway-host", default=os.getenv("HOST", "127.0.0.1"))
    provider_start.add_argument("--gateway-port", type=int, default=int(os.getenv("PORT", "8000")))
    provider_start.add_argument("--gateway-url", help="Gateway URL used by the provider. Defaults to the local gateway.")
    provider_start.add_argument("--gateway-reload", action="store_true", help="Pass --reload to the managed gateway.")
    provider_start.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    provider_start.add_argument(
        "--health-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for the local gateway /health endpoint before starting the provider.",
    )
    provider_start.add_argument("--provider-host", default="0.0.0.0", help="Direct P2P listen host.")
    provider_start.add_argument("--provider-port", type=int, default=DEFAULT_P2P_PORT, help="Direct P2P listen port.")
    provider_start.add_argument("--advertise-host", default="127.0.0.1", help="Direct P2P host announced to peers.")
    provider_start.add_argument("--relay-host", default="127.0.0.1", help="Relay provider host for relay transport.")
    provider_start.add_argument("--relay-port", type=int, default=DEFAULT_RELAY_PROVIDER_PORT, help="Relay provider port.")
    provider_start.add_argument("--relay-public-url", help="Relay control URL stored in the pool for relay transport.")
    provider_start.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Local gateway agent id to use.")
    provider_start.add_argument("--channel", default=DEFAULT_CHANNEL)
    provider_start.add_argument("--model", default=os.getenv("PUBLIC_MODEL_ID", "gpt-5.5"))
    provider_start.add_argument("--identity", default=DEFAULT_NODE_IDENTITY_PATH, help="Node identity file.")
    provider_start.add_argument("--peer-id", help="Stable peer id. Defaults to the node identity peer id.")
    provider_start.add_argument(
        "--network-profile",
        choices=[NETWORK_PROFILE_LOCAL, NETWORK_PROFILE_TESTNET, NETWORK_PROFILE_OPEN],
        default=os.getenv("MYCOMESH_NETWORK_PROFILE", NETWORK_PROFILE_TESTNET),
        help="Network safety profile. testnet is allowlisted by default; local is development only.",
    )
    provider_start.add_argument(
        "--consumer-public-key",
        action="append",
        default=[],
        help="Allowed consumer/proxy Ed25519 public key. Can be repeated.",
    )
    provider_start.add_argument(
        "--allow-any-signed-consumer",
        action="store_true",
        help="Development only: accept any signed consumer request when no allowlist is configured.",
    )
    provider_start.add_argument(
        "--allow-unsigned-requests",
        action="store_true",
        help="Development only: accept unsigned P2P inference requests.",
    )
    provider_start.add_argument(
        "--allow-unreserved-requests",
        action="store_true",
        help="Development only: accept inference without a signed payment reservation.",
    )
    provider_start.add_argument("--payment-address", help="Provider EVM address paid by settlement receipts.")
    provider_start.add_argument("--pricing-config", help="Versioned channel pricing JSON file used to verify reservations.")
    provider_start.add_argument("--pricing-hash", help="Expected chain channel pricing hash for reservations.")
    provider_start.add_argument("--reserve-input-tokens", type=int, default=int(os.getenv("MYCOMESH_RESERVE_INPUT_TOKENS", "8000")))
    provider_start.add_argument("--reserve-output-tokens", type=int, default=int(os.getenv("MYCOMESH_RESERVE_OUTPUT_TOKENS", "2000")))
    provider_start.add_argument("--bootstrap", action="append", default=[], help="Direct transport bootstrap peer host:port.")
    provider_start.add_argument(
        "--pool",
        default=os.getenv("MYCOMESH_PROVIDER_POOL_URL") or os.getenv("MYCOMESH_POOL_URL"),
        help="Pool/Bridge URL to join and heartbeat. Comma-separated values register with multiple Bridges.",
    )
    provider_start.add_argument("--ttl", type=int, default=DEFAULT_NODE_TTL_SECONDS, help="Pool registration TTL seconds.")
    provider_start.add_argument(
        "--heartbeat-interval",
        type=float,
        default=DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        help="Pool heartbeat interval seconds.",
    )
    provider_start.add_argument("--capacity", type=int, default=1, help="Advertised max concurrency for this provider.")
    provider_start.set_defaults(func=_cmd_provider_start)

    p2p = subparsers.add_parser("p2p", help="Run or call the P2P inference network.")
    p2p_subparsers = p2p.add_subparsers(dest="p2p_command", required=True)

    p2p_serve = p2p_subparsers.add_parser("serve", help="Expose this gateway as a P2P provider.")
    p2p_serve.add_argument("--host", default="0.0.0.0", help="P2P listen host.")
    p2p_serve.add_argument("--port", type=int, default=DEFAULT_P2P_PORT, help="P2P listen port.")
    p2p_serve.add_argument("--advertise-host", default="127.0.0.1", help="Host announced to peers.")
    p2p_serve.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Local gateway agent id to use.")
    p2p_serve.add_argument("--key", help="Gateway key to use. Defaults to first key for --agent.")
    p2p_serve.add_argument("--channel", default=DEFAULT_CHANNEL)
    p2p_serve.add_argument("--model", default=os.getenv("PUBLIC_MODEL_ID", "gpt-5.5"))
    p2p_serve.add_argument("--gateway-url", default=os.getenv("GATEWAY_URL", "http://127.0.0.1:8000/v1"))
    p2p_serve.add_argument("--identity", default=DEFAULT_NODE_IDENTITY_PATH, help="Node identity file.")
    p2p_serve.add_argument("--peer-id", help="Stable peer id. Defaults to the node identity peer id.")
    p2p_serve.add_argument(
        "--network-profile",
        choices=[NETWORK_PROFILE_LOCAL, NETWORK_PROFILE_TESTNET, NETWORK_PROFILE_OPEN],
        default=os.getenv("MYCOMESH_NETWORK_PROFILE", NETWORK_PROFILE_TESTNET),
        help="Network safety profile. testnet is allowlisted by default; local is development only.",
    )
    p2p_serve.add_argument(
        "--consumer-public-key",
        action="append",
        default=[],
        help="Allowed consumer Ed25519 public key. Can be repeated.",
    )
    p2p_serve.add_argument(
        "--allow-any-signed-consumer",
        action="store_true",
        help="Development only: accept any signed consumer request when no allowlist is configured.",
    )
    p2p_serve.add_argument(
        "--allow-unsigned-requests",
        action="store_true",
        help="Development only: accept unsigned P2P inference requests.",
    )
    p2p_serve.add_argument(
        "--allow-unreserved-requests",
        action="store_true",
        help="Development only: accept inference without a signed payment reservation.",
    )
    p2p_serve.add_argument("--payment-address", help="Provider EVM address paid by settlement receipts.")
    p2p_serve.add_argument("--pricing-config", help="Versioned channel pricing JSON file used to verify reservations.")
    p2p_serve.add_argument("--pricing-hash", help="Expected chain channel pricing hash for reservations.")
    p2p_serve.add_argument("--reserve-input-tokens", type=int, default=int(os.getenv("MYCOMESH_RESERVE_INPUT_TOKENS", "8000")))
    p2p_serve.add_argument("--reserve-output-tokens", type=int, default=int(os.getenv("MYCOMESH_RESERVE_OUTPUT_TOKENS", "2000")))
    p2p_serve.add_argument("--bootstrap", action="append", default=[], help="Bootstrap peer host:port.")
    p2p_serve.add_argument("--pool", help="Optional pool/Bridge URL list to join, for example http://127.0.0.1:9800,http://127.0.0.1:9801.")
    p2p_serve.add_argument("--ttl", type=int, default=DEFAULT_NODE_TTL_SECONDS, help="Pool registration TTL seconds.")
    p2p_serve.add_argument(
        "--heartbeat-interval",
        type=float,
        default=DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        help="Pool heartbeat interval seconds.",
    )
    p2p_serve.add_argument("--capacity", type=int, default=1, help="Advertised max concurrency for this provider.")
    p2p_serve.set_defaults(func=_cmd_p2p_serve)

    p2p_infer = p2p_subparsers.add_parser("infer", help="Send one inference task to a P2P peer.")
    p2p_infer.add_argument("peer", help="Peer address host:port or tcp://host:port.")
    p2p_infer.add_argument("input", help="Prompt/input text.")
    p2p_infer.add_argument("--channel", default=DEFAULT_CHANNEL)
    p2p_infer.add_argument("--model", default=os.getenv("PUBLIC_MODEL_ID", "gpt-5.5"))
    p2p_infer.add_argument("--endpoint", choices=["responses", "chat"], default="responses")
    p2p_infer.add_argument("--timeout", type=float, default=180.0)
    p2p_infer.add_argument("--identity", default=DEFAULT_REQUEST_IDENTITY_PATH, help="Consumer request identity file.")
    p2p_infer.add_argument("--consumer", default="anonymous", help="Consumer id used in the payment reservation.")
    p2p_infer.add_argument("--consumer-payment-address", help="Consumer EVM prepaid address used in the reservation.")
    p2p_infer.add_argument("--provider-peer-id", help="Expected provider peer id. Required by production providers.")
    p2p_infer.add_argument("--provider-payment-address", help="Expected provider EVM payout address.")
    p2p_infer.add_argument("--pricing-hash", help="Channel pricing hash included in the reservation.")
    p2p_infer.add_argument("--max-fee-usdc", default="0.10", help="Maximum fee authorized by the reservation.")
    p2p_infer.add_argument("--raw", action="store_true", help="Print full JSON response.")
    p2p_infer.set_defaults(func=_cmd_p2p_infer)

    p2p_ping = p2p_subparsers.add_parser("ping", help="Ping a P2P peer.")
    p2p_ping.add_argument("peer", help="Peer address host:port or tcp://host:port.")
    p2p_ping.add_argument("--timeout", type=float, default=10.0)
    p2p_ping.set_defaults(func=_cmd_p2p_ping)

    p2p_peers = p2p_subparsers.add_parser("peers", help="Ask a peer for known peers.")
    p2p_peers.add_argument("peer", help="Peer address host:port or tcp://host:port.")
    p2p_peers.add_argument("--timeout", type=float, default=10.0)
    p2p_peers.set_defaults(func=_cmd_p2p_peers)

    p2p_relay = p2p_subparsers.add_parser("relay", help="Expose this gateway through a relay connection.")
    p2p_relay.add_argument("--relay-host", default="127.0.0.1", help="Relay provider host.")
    p2p_relay.add_argument("--relay-port", type=int, default=DEFAULT_RELAY_PROVIDER_PORT, help="Relay provider port.")
    p2p_relay.add_argument("--relay-public-url", help="Relay control URL stored in the pool.")
    p2p_relay.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Local gateway agent id to use.")
    p2p_relay.add_argument("--key", help="Gateway key to use. Defaults to first key for --agent.")
    p2p_relay.add_argument("--channel", default=DEFAULT_CHANNEL)
    p2p_relay.add_argument("--model", default=os.getenv("PUBLIC_MODEL_ID", "gpt-5.5"))
    p2p_relay.add_argument("--gateway-url", default=os.getenv("GATEWAY_URL", "http://127.0.0.1:8000/v1"))
    p2p_relay.add_argument("--identity", default=DEFAULT_NODE_IDENTITY_PATH, help="Node identity file.")
    p2p_relay.add_argument("--peer-id", help="Stable peer id. Defaults to the node identity peer id.")
    p2p_relay.add_argument(
        "--network-profile",
        choices=[NETWORK_PROFILE_LOCAL, NETWORK_PROFILE_TESTNET, NETWORK_PROFILE_OPEN],
        default=os.getenv("MYCOMESH_NETWORK_PROFILE", NETWORK_PROFILE_TESTNET),
        help="Network safety profile. testnet is allowlisted by default; local is development only.",
    )
    p2p_relay.add_argument(
        "--consumer-public-key",
        action="append",
        default=[],
        help="Allowed consumer Ed25519 public key. Can be repeated.",
    )
    p2p_relay.add_argument(
        "--allow-any-signed-consumer",
        action="store_true",
        help="Development only: accept any signed consumer request when no allowlist is configured.",
    )
    p2p_relay.add_argument(
        "--allow-unsigned-requests",
        action="store_true",
        help="Development only: accept unsigned P2P inference requests.",
    )
    p2p_relay.add_argument(
        "--allow-unreserved-requests",
        action="store_true",
        help="Development only: accept inference without a signed payment reservation.",
    )
    p2p_relay.add_argument("--payment-address", help="Provider EVM address paid by settlement receipts.")
    p2p_relay.add_argument("--pricing-config", help="Versioned channel pricing JSON file used to verify reservations.")
    p2p_relay.add_argument("--pricing-hash", help="Expected chain channel pricing hash for reservations.")
    p2p_relay.add_argument("--reserve-input-tokens", type=int, default=int(os.getenv("MYCOMESH_RESERVE_INPUT_TOKENS", "8000")))
    p2p_relay.add_argument("--reserve-output-tokens", type=int, default=int(os.getenv("MYCOMESH_RESERVE_OUTPUT_TOKENS", "2000")))
    p2p_relay.add_argument("--pool", help="Optional pool/Bridge URL list to join.")
    p2p_relay.add_argument("--ttl", type=int, default=DEFAULT_NODE_TTL_SECONDS)
    p2p_relay.add_argument("--heartbeat-interval", type=float, default=DEFAULT_HEARTBEAT_INTERVAL_SECONDS)
    p2p_relay.add_argument("--capacity", type=int, default=1)
    p2p_relay.set_defaults(func=_cmd_p2p_relay)

    pool = subparsers.add_parser("pool", help="Run or use the distributed provider pool.")
    pool_subparsers = pool.add_subparsers(dest="pool_command", required=True)

    pool_serve = pool_subparsers.add_parser("serve", help="Start a bootstrap provider pool.")
    pool_serve.add_argument("--host", default="127.0.0.1", help="Pool listen host.")
    pool_serve.add_argument("--port", type=int, default=DEFAULT_POOL_PORT, help="Pool listen port.")
    pool_serve.add_argument("--public-url", help="Canonical pool URL used as the peer signature audience.")
    pool_serve.add_argument(
        "--network-profile",
        choices=[NETWORK_PROFILE_LOCAL, NETWORK_PROFILE_TESTNET, NETWORK_PROFILE_OPEN],
        default=os.getenv("MYCOMESH_NETWORK_PROFILE", NETWORK_PROFILE_TESTNET),
        help="Network safety profile. testnet requires explicit provider and reputation allowlists.",
    )
    pool_serve.add_argument(
        "--provider-public-key",
        action="append",
        help="Provider Ed25519 public key allowed to join a testnet pool. Can be repeated.",
    )
    pool_serve.add_argument(
        "--skip-direct-address-verification",
        action="store_true",
        help="Development only: do not probe tcp:// provider addresses during join/heartbeat.",
    )
    pool_serve.add_argument(
        "--reputation-signer-public-key",
        action="append",
        help="Public key allowed to submit signed pool reputation feedback. Can be repeated.",
    )
    pool_serve.add_argument(
        "--allow-any-reputation-signer",
        action="store_true",
        help="Development only: accept reputation feedback from any valid signer.",
    )
    pool_serve.set_defaults(func=_cmd_pool_serve)

    pool_join = pool_subparsers.add_parser("join", help="Register one P2P provider in a pool once.")
    pool_join.add_argument("--pool", default=DEFAULT_POOL_URL, help="Pool base URL.")
    pool_join.add_argument("--peer-id", required=True, help="Provider peer id.")
    pool_join.add_argument("--address", action="append", required=True, help="Provider address. Can be repeated.")
    pool_join.add_argument("--channel", default=DEFAULT_CHANNEL)
    pool_join.add_argument("--model", default=os.getenv("PUBLIC_MODEL_ID", "gpt-5.5"))
    pool_join.add_argument("--agent", default=DEFAULT_AGENT_ID)
    pool_join.add_argument("--identity", default=DEFAULT_NODE_IDENTITY_PATH, help="Node identity file.")
    pool_join.add_argument("--payment-address", help="Provider EVM address paid by settlement receipts.")
    pool_join.add_argument("--ttl", type=int, default=DEFAULT_NODE_TTL_SECONDS)
    pool_join.add_argument("--capacity", type=int, default=1)
    pool_join.add_argument("--timeout", type=float, default=5.0)
    pool_join.set_defaults(func=_cmd_pool_join)

    pool_leave = pool_subparsers.add_parser("leave", help="Remove this provider from a pool with a signed leave request.")
    pool_leave.add_argument("--pool", default=DEFAULT_POOL_URL, help="Pool base URL.")
    pool_leave.add_argument("--identity", default=DEFAULT_NODE_IDENTITY_PATH, help="Node identity file.")
    pool_leave.add_argument("--peer-id", help="Provider peer id. Defaults to the node identity peer id.")
    pool_leave.add_argument("--timeout", type=float, default=5.0)
    pool_leave.set_defaults(func=_cmd_pool_leave)

    pool_peers = pool_subparsers.add_parser("peers", help="List live providers in a pool.")
    pool_peers.add_argument("--pool", default=DEFAULT_POOL_URL, help="Pool/Bridge base URL list.")
    pool_peers.add_argument("--channel", help="Only list providers for this channel.")
    pool_peers.add_argument("--timeout", type=float, default=5.0)
    pool_peers.add_argument("--raw", action="store_true", help="Print full JSON.")
    pool_peers.set_defaults(func=_cmd_pool_peers)

    pool_infer = pool_subparsers.add_parser("infer", help="Discover a provider from the pool and run inference.")
    pool_infer.add_argument("input", help="Prompt/input text.")
    pool_infer.add_argument("--pool", default=DEFAULT_POOL_URL, help="Pool/Bridge base URL list.")
    pool_infer.add_argument("--channel", default=DEFAULT_CHANNEL)
    pool_infer.add_argument("--model", default=os.getenv("PUBLIC_MODEL_ID", "gpt-5.5"))
    pool_infer.add_argument("--endpoint", choices=["responses", "chat"], default="responses")
    pool_infer.add_argument("--timeout", type=float, default=180.0)
    pool_infer.add_argument("--raw", action="store_true", help="Print full JSON response.")
    pool_infer.add_argument("--price", action="store_true", help="Print pricing details after inference.")
    pool_infer.add_argument("--receipt", action="store_true", help="Print an inference receipt after inference.")
    pool_infer.add_argument("--accept", action="store_true", help="Sign an accepted receipt with the consumer identity.")
    pool_infer.add_argument("--consumer", default="anonymous", help="Consumer id stored in the receipt.")
    pool_infer.add_argument("--identity", default=DEFAULT_REQUEST_IDENTITY_PATH, help="Consumer request identity file.")
    pool_infer.add_argument("--consumer-payment-address", help="Consumer EVM prepaid address stored in receipts/reservations.")
    pool_infer.add_argument("--pricing-config", help="Versioned channel pricing JSON file.")
    pool_infer.add_argument("--pricing-hash", help="Chain channel pricing hash. Defaults to MYCOMESH_CHANNEL_PRICING_HASH/local config hash.")
    pool_infer.add_argument("--reserve-input-tokens", type=int, help="Input token assumption for max-fee reservation.")
    pool_infer.add_argument("--reserve-output-tokens", type=int, help="Output token assumption for max-fee reservation.")
    pool_infer.add_argument("--reserve-multiplier", help="Reservation safety multiplier.")
    pool_infer.add_argument("--route-state", default=DEFAULT_ROUTE_STATE_PATH, help="Local route score state file.")
    pool_infer.add_argument("--ledger", default=DEFAULT_LEDGER_PATH, help="JSONL receipt path.")
    pool_infer.add_argument("--no-ledger", action="store_true", help="Do not append the receipt to the local ledger.")
    pool_infer.set_defaults(func=_cmd_pool_infer)

    pool_health = pool_subparsers.add_parser("health", help="Call the pool /health endpoint.")
    pool_health.add_argument("--pool", default=DEFAULT_POOL_URL, help="Pool base URL.")
    pool_health.add_argument("--timeout", type=float, default=5.0)
    pool_health.set_defaults(func=_cmd_pool_health)

    relay = subparsers.add_parser("relay", help="Run a provider relay for NATed nodes.")
    relay_subparsers = relay.add_subparsers(dest="relay_command", required=True)

    relay_serve = relay_subparsers.add_parser("serve", help="Start a relay control/provider server.")
    relay_serve.add_argument("--host", default="127.0.0.1", help="Relay listen host.")
    relay_serve.add_argument("--advertise-host", help="Host advertised in relay addresses.")
    relay_serve.add_argument("--control-port", type=int, default=DEFAULT_RELAY_CONTROL_PORT)
    relay_serve.add_argument("--provider-port", type=int, default=DEFAULT_RELAY_PROVIDER_PORT)
    relay_serve.add_argument(
        "--consumer-public-key",
        action="append",
        help="Consumer/proxy public key allowed to call relay control inference. Can be repeated.",
    )
    relay_serve.add_argument(
        "--allow-any-signed-consumer",
        action="store_true",
        help="Development only: accept any valid signed consumer request at relay control.",
    )
    relay_serve.set_defaults(func=_cmd_relay_serve)

    mycomesh = subparsers.add_parser("mycomesh", help="Run and manage the MycoMesh consumer proxy.")
    mycomesh_subparsers = mycomesh.add_subparsers(dest="mycomesh_command", required=True)

    mycomesh_serve = mycomesh_subparsers.add_parser("serve", help="Start the MycoMesh OpenAI-compatible proxy.")
    mycomesh_serve.add_argument("--host", default=os.getenv("MYCOMESH_HOST", "127.0.0.1"))
    mycomesh_serve.add_argument("--port", type=int, default=int(os.getenv("MYCOMESH_PORT", "8100")))
    mycomesh_serve.add_argument("--reload", action="store_true")
    mycomesh_serve.set_defaults(func=_cmd_mycomesh_serve)

    mycomesh_account = mycomesh_subparsers.add_parser("account", help="Manage local MycoMesh API accounts.")
    mycomesh_account_subparsers = mycomesh_account.add_subparsers(dest="account_command", required=True)

    account_create = mycomesh_account_subparsers.add_parser("create", help="Create a local consumer API key.")
    account_create.add_argument("--account-id")
    account_create.add_argument("--payment-address", help="Consumer EVM address used in settlement receipts.")
    account_create.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_create.set_defaults(func=_cmd_mycomesh_account_create)

    account_deposit = mycomesh_account_subparsers.add_parser("deposit", help="Credit a local prepaid balance.")
    account_deposit.add_argument("account_id")
    account_deposit.add_argument("--amount-usdc", required=True)
    account_deposit.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_deposit.set_defaults(func=_cmd_mycomesh_account_deposit)

    account_sync = mycomesh_account_subparsers.add_parser("sync-balance", help="Replace a cached prepaid balance from an external/indexed source.")
    account_sync.add_argument("account_id")
    account_sync.add_argument("--balance-usdc", required=True)
    account_sync.add_argument("--chain-id", type=int, help="Set cache chain_id freshness metadata.")
    account_sync.add_argument("--settlement", help="Set cache settlement address freshness metadata.")
    account_sync.add_argument("--latest-block", type=int, help="Set the latest observed chain block.")
    account_sync.add_argument("--synced-block", type=int, help="Set the block synced into the local cache.")
    account_sync.add_argument("--confirmations", type=int, default=0, help="Confirmations used by the external sync source.")
    account_sync.add_argument("--source", default="cli-sync-balance", help="Sync state source label.")
    account_sync.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_sync.set_defaults(func=_cmd_mycomesh_account_sync_balance)

    account_balance = mycomesh_account_subparsers.add_parser("balance", help="Print a local prepaid balance.")
    account_balance.add_argument("account_id")
    account_balance.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_balance.set_defaults(func=_cmd_mycomesh_account_balance)

    account_payment = mycomesh_account_subparsers.add_parser("payment-address", help="Set a consumer EVM payment address.")
    account_payment.add_argument("account_id")
    account_payment.add_argument("--payment-address", required=True)
    account_payment.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_payment.set_defaults(func=_cmd_mycomesh_account_payment_address)

    account_policy = mycomesh_account_subparsers.add_parser("policy", help="Set account quota, tier, discount, and reseller relationship.")
    account_policy.add_argument("account_id")
    account_policy.add_argument("--parent-account-id")
    account_policy.add_argument("--discount-bps", type=int)
    account_policy.add_argument("--reseller-margin-bps", type=int)
    account_policy.add_argument("--monthly-quota-usdc")
    account_policy.add_argument("--usage-tier")
    account_policy.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_policy.set_defaults(func=_cmd_mycomesh_account_policy)

    account_status = mycomesh_account_subparsers.add_parser("status", help="Set a local consumer account status.")
    account_status.add_argument("account_id")
    account_status.add_argument("--status", choices=["active", "suspended", "closed"], required=True)
    account_status.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_status.set_defaults(func=_cmd_mycomesh_account_status)

    account_rotate = mycomesh_account_subparsers.add_parser("rotate", help="Rotate a local consumer API key.")
    account_rotate.add_argument("account_id")
    account_rotate.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_rotate.set_defaults(func=_cmd_mycomesh_account_rotate)

    account_delete = mycomesh_account_subparsers.add_parser("delete", help="Delete a local consumer API account.")
    account_delete.add_argument("account_id")
    account_delete.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_delete.set_defaults(func=_cmd_mycomesh_account_delete)

    account_cleanup = mycomesh_account_subparsers.add_parser("cleanup-reservations", help="Release stale reserved local prepaid balances.")
    account_cleanup.add_argument("--max-age-seconds", type=int, default=int(os.getenv("MYCOMESH_RESERVATION_MAX_AGE_SECONDS", "900")))
    account_cleanup.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    account_cleanup.set_defaults(func=_cmd_mycomesh_account_cleanup_reservations)

    mycomesh_indexer = mycomesh_subparsers.add_parser("indexer", help="Synchronize on-chain prepaid balances into the local proxy cache.")
    mycomesh_indexer_subparsers = mycomesh_indexer.add_subparsers(dest="indexer_command", required=True)

    indexer_sync = mycomesh_indexer_subparsers.add_parser("sync", help="Read prepaid balances for local accounts from the settlement contract.")
    indexer_sync.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    indexer_sync.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    indexer_sync.add_argument("--settlement", help="Override Myco settlement address.")
    indexer_sync.add_argument("--chain-id", type=int, help="Expected chain id. Defaults to deployment chain_id.")
    indexer_sync.add_argument("--account", action="append", help="Local account id to sync. Can be repeated.")
    indexer_sync.add_argument("--events", action="store_true", help="Use settlement events, confirmations, and the indexer cursor.")
    indexer_sync.add_argument("--confirmations", type=int, default=6)
    indexer_sync.add_argument("--lookback-blocks", type=int, default=5000)
    indexer_sync.add_argument("--chunk-blocks", type=int, default=1000)
    indexer_sync.add_argument("--db", default=os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
    indexer_sync.add_argument("--state", default=DEFAULT_INDEXER_STATE_PATH)
    indexer_sync.add_argument("--timeout", type=float, default=20.0)
    indexer_sync.set_defaults(func=_cmd_mycomesh_indexer_sync)

    pricing = subparsers.add_parser("pricing", help="Quote stablecoin inference prices.")
    pricing_subparsers = pricing.add_subparsers(dest="pricing_command", required=True)

    pricing_quote = pricing_subparsers.add_parser("quote", help="Quote one channel usage.")
    pricing_quote.add_argument("--channel", default=DEFAULT_CHANNEL)
    pricing_quote.add_argument("--input-tokens", type=int, default=0)
    pricing_quote.add_argument("--output-tokens", type=int, default=0)
    pricing_quote.set_defaults(func=_cmd_pricing_quote)

    ledger = subparsers.add_parser("ledger", help="Inspect local inference receipts.")
    ledger_subparsers = ledger.add_subparsers(dest="ledger_command", required=True)

    ledger_receipts = ledger_subparsers.add_parser("receipts", help="Print recent local receipts.")
    ledger_receipts.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
    ledger_receipts.add_argument("--limit", type=int, default=20)
    ledger_receipts.set_defaults(func=_cmd_ledger_receipts)

    ledger_blocks = ledger_subparsers.add_parser("blocks", help="Build MycoMesh protocol settlement blocks from accepted receipts.")
    ledger_blocks.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
    ledger_blocks.add_argument(
        "--window-seconds",
        type=int,
        default=int(os.getenv("MYCOMESH_SETTLEMENT_BLOCK_SECONDS", str(DEFAULT_SETTLEMENT_BLOCK_SECONDS))),
        help="Protocol settlement block duration in seconds.",
    )
    ledger_blocks.add_argument("--genesis-timestamp", type=int, help="Fixed protocol genesis timestamp for block height calculation.")
    ledger_blocks.add_argument("--from-timestamp", type=int, help="Only include receipts finished at or after this timestamp.")
    ledger_blocks.add_argument("--to-timestamp", type=int, help="Only include receipts finished before this timestamp.")
    ledger_blocks.add_argument("--include-unaccepted", action="store_true", help="Development only: include receipts without consumer acceptance.")
    ledger_blocks.add_argument("--include-empty", action="store_true", help="Emit empty fixed-window blocks between non-empty blocks.")
    ledger_blocks.add_argument(
        "--provider-reward-bps",
        type=int,
        default=int(os.getenv("MYCOMESH_BLOCK_PROVIDER_REWARD_BPS", str(DEFAULT_PROVIDER_BLOCK_REWARD_BPS))),
    )
    ledger_blocks.add_argument(
        "--bridge-reward-bps",
        type=int,
        default=int(os.getenv("MYCOMESH_BLOCK_BRIDGE_REWARD_BPS", str(DEFAULT_BRIDGE_BLOCK_REWARD_BPS))),
    )
    ledger_blocks.add_argument(
        "--consumer-reward-bps",
        type=int,
        default=int(os.getenv("MYCOMESH_BLOCK_CONSUMER_REWARD_BPS", str(DEFAULT_CONSUMER_BLOCK_REWARD_BPS))),
    )
    ledger_blocks.add_argument(
        "--consumer-volume-base-spend",
        default=os.getenv("MYCOMESH_CONSUMER_VOLUME_BASE_SPEND", str(DEFAULT_CONSUMER_VOLUME_BASE_SPEND)),
        help="Stablecoin spend where consumer volume rewards begin to bend upward.",
    )
    ledger_blocks.add_argument(
        "--consumer-volume-beta",
        default=os.getenv("MYCOMESH_CONSUMER_VOLUME_BETA", str(DEFAULT_CONSUMER_VOLUME_BETA)),
        help="Log-curve strength for consumer volume rewards.",
    )
    ledger_blocks.add_argument(
        "--consumer-volume-max-multiplier",
        default=os.getenv("MYCOMESH_CONSUMER_VOLUME_MAX_MULTIPLIER", str(DEFAULT_CONSUMER_VOLUME_MAX_MULTIPLIER)),
        help="Upper bound for consumer volume reward multiplier.",
    )
    ledger_blocks.add_argument("--output", help="Optional JSONL file to write settlement blocks.")
    ledger_blocks.set_defaults(func=_cmd_ledger_blocks)

    ledger_dispute = ledger_subparsers.add_parser("dispute", help="Record a local routing dispute for a receipt provider.")
    ledger_dispute.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
    ledger_dispute.add_argument("--receipt-index", type=int, default=-1)
    ledger_dispute.add_argument("--reason", required=True)
    ledger_dispute.add_argument("--route-state", default=DEFAULT_ROUTE_STATE_PATH)
    ledger_dispute.set_defaults(func=_cmd_ledger_dispute)

    chain = subparsers.add_parser("chain", help="Deploy and settle the protocol on an Ethereum testnet.")
    chain_subparsers = chain.add_subparsers(dest="chain_command", required=True)

    chain_deploy = chain_subparsers.add_parser("deploy-testnet", help="Deploy the legacy v1 testnet settlement system.")
    chain_deploy.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_deploy.add_argument("--private-key", help="Deployer private key. Defaults to PRIVATE_KEY.")
    chain_deploy.add_argument("--treasury", help="Treasury EVM address. Defaults to TREASURY.")
    chain_deploy.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_deploy.add_argument("--deployment", default=DEFAULT_DEPLOYMENT_PATH)
    chain_deploy.add_argument(
        "--solc",
        help="Optional local solc path. If set, artifacts are rebuilt with this compiler before client-side deployment.",
    )
    chain_deploy.add_argument("--timeout", type=float, default=300.0)
    chain_deploy.set_defaults(func=_cmd_chain_deploy_testnet)

    chain_deploy_myco = chain_subparsers.add_parser("deploy-myco-testnet", help="Deploy the MycoMesh v2 testnet system.")
    chain_deploy_myco.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_deploy_myco.add_argument("--private-key", help="Deployer private key. Defaults to PRIVATE_KEY.")
    chain_deploy_myco.add_argument("--treasury", help="Treasury EVM address. Defaults to TREASURY.")
    chain_deploy_myco.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_deploy_myco.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_deploy_myco.add_argument("--solc", help="Optional local solc path.")
    chain_deploy_myco.add_argument("--timeout", type=float, default=300.0)
    chain_deploy_myco.set_defaults(func=_cmd_chain_deploy_myco_testnet)

    chain_info = chain_subparsers.add_parser("info", help="Print local chain deployment config.")
    chain_info.add_argument("--deployment", default=DEFAULT_DEPLOYMENT_PATH)
    chain_info.set_defaults(func=_cmd_chain_info)

    chain_myco_info = chain_subparsers.add_parser("myco-info", help="Print local MycoMesh v2 deployment config.")
    chain_myco_info.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_myco_info.set_defaults(func=_cmd_chain_myco_info)

    chain_mint = chain_subparsers.add_parser("mint-test-usdc", help="Mint test USDC on the deployed testnet token.")
    chain_mint.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_mint.add_argument("--private-key", help="Minter private key. Defaults to PRIVATE_KEY.")
    chain_mint.add_argument("--deployment", default=DEFAULT_DEPLOYMENT_PATH)
    chain_mint.add_argument("--token", help="Override test USDC address.")
    chain_mint.add_argument("--to", required=True, help="Recipient EVM address.")
    chain_mint.add_argument("--amount-usdc", required=True, help="Human USDC amount, for example 10 or 0.5.")
    chain_mint.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_mint.add_argument("--timeout", type=float, default=120.0)
    chain_mint.set_defaults(func=_cmd_chain_mint_test_usdc)

    chain_approve = chain_subparsers.add_parser("approve-usdc", help="Approve the settlement contract to pull USDC.")
    chain_approve.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_approve.add_argument("--private-key", help="Consumer private key. Defaults to PRIVATE_KEY.")
    chain_approve.add_argument("--deployment", default=DEFAULT_DEPLOYMENT_PATH)
    chain_approve.add_argument("--token", help="Override test USDC address.")
    chain_approve.add_argument("--spender", help="Override settlement address.")
    chain_approve.add_argument("--amount-usdc", required=True, help="Human USDC amount, for example 10 or 0.5.")
    chain_approve.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_approve.add_argument("--timeout", type=float, default=120.0)
    chain_approve.set_defaults(func=_cmd_chain_approve_usdc)

    chain_deposit = chain_subparsers.add_parser("deposit-prepaid", help="Deposit USDC into MycoMesh v2 prepaid balance.")
    chain_deposit.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_deposit.add_argument("--private-key", help="Consumer private key. Defaults to PRIVATE_KEY.")
    chain_deposit.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_deposit.add_argument("--settlement", help="Override Myco settlement address.")
    chain_deposit.add_argument("--amount-usdc", required=True)
    chain_deposit.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_deposit.add_argument("--timeout", type=float, default=120.0)
    chain_deposit.set_defaults(func=_cmd_chain_deposit_prepaid)

    chain_withdraw = chain_subparsers.add_parser("withdraw-prepaid", help="Withdraw USDC from MycoMesh v2 prepaid balance.")
    chain_withdraw.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_withdraw.add_argument("--private-key", help="Consumer private key. Defaults to PRIVATE_KEY.")
    chain_withdraw.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_withdraw.add_argument("--settlement", help="Override Myco settlement address.")
    chain_withdraw.add_argument("--amount-usdc", required=True)
    chain_withdraw.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_withdraw.add_argument("--timeout", type=float, default=120.0)
    chain_withdraw.set_defaults(func=_cmd_chain_withdraw_prepaid)

    chain_balance = chain_subparsers.add_parser("prepaid-balance", help="Read a MycoMesh v2 prepaid balance.")
    chain_balance.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_balance.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_balance.add_argument("--settlement", help="Override Myco settlement address.")
    chain_balance.add_argument("--account", required=True, help="Consumer EVM address.")
    chain_balance.add_argument("--timeout", type=float, default=20.0)
    chain_balance.set_defaults(func=_cmd_chain_prepaid_balance)

    chain_delegate = chain_subparsers.add_parser(
        "set-settlement-delegate",
        help="Allow or revoke an operator/delegate to settle receipts for this prepaid account.",
    )
    chain_delegate.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_delegate.add_argument("--private-key", help="Account private key. Defaults to PRIVATE_KEY.")
    chain_delegate.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_delegate.add_argument("--settlement", help="Override Myco settlement address.")
    chain_delegate.add_argument("--delegate", required=True, help="Operator/delegate EVM address.")
    chain_delegate.add_argument("--allowed", choices=["true", "false"], default="true")
    chain_delegate.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_delegate.add_argument("--timeout", type=float, default=120.0)
    chain_delegate.set_defaults(func=_cmd_chain_set_settlement_delegate)

    chain_treasury = chain_subparsers.add_parser("set-treasury", help="Set MycoMesh v2 treasury after timelock scheduling.")
    chain_treasury.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_treasury.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_treasury.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_treasury.add_argument("--settlement", help="Override Myco settlement address.")
    chain_treasury.add_argument("--treasury", required=True)
    chain_treasury.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_treasury.add_argument("--timeout", type=float, default=120.0)
    chain_treasury.set_defaults(func=_cmd_chain_set_treasury)

    chain_operator = chain_subparsers.add_parser("set-operator", help="Set MycoMesh v2 operator permission after timelock scheduling.")
    chain_operator.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_operator.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_operator.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_operator.add_argument("--settlement", help="Override Myco settlement address.")
    chain_operator.add_argument("--operator", required=True)
    chain_operator.add_argument("--allowed", choices=["true", "false"], required=True)
    chain_operator.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_operator.add_argument("--timeout", type=float, default=120.0)
    chain_operator.set_defaults(func=_cmd_chain_set_operator)

    chain_governance = chain_subparsers.add_parser(
        "set-governance-executor",
        help="Move MycoMesh v2 governance authority to another executor address.",
    )
    chain_governance.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_governance.add_argument("--private-key", help="Current governance private key. Defaults to PRIVATE_KEY.")
    chain_governance.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_governance.add_argument("--settlement", help="Override Myco settlement address.")
    chain_governance.add_argument("--executor", required=True)
    chain_governance.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_governance.add_argument("--timeout", type=float, default=120.0)
    chain_governance.set_defaults(func=_cmd_chain_set_governance_executor)

    chain_governance_accept = chain_subparsers.add_parser(
        "accept-governance-executor",
        help="Accept pending MycoMesh v2 governance authority.",
    )
    chain_governance_accept.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_governance_accept.add_argument("--private-key", help="Pending governance private key. Defaults to PRIVATE_KEY.")
    chain_governance_accept.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_governance_accept.add_argument("--settlement", help="Override Myco settlement address.")
    chain_governance_accept.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_governance_accept.add_argument("--timeout", type=float, default=120.0)
    chain_governance_accept.set_defaults(func=_cmd_chain_accept_governance_executor)

    chain_governance_delay = chain_subparsers.add_parser(
        "set-governance-delay",
        help="Set the timelock delay for scheduled governance actions.",
    )
    chain_governance_delay.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_governance_delay.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_governance_delay.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_governance_delay.add_argument("--settlement", help="Override Myco settlement address.")
    chain_governance_delay.add_argument("--delay-seconds", type=int, required=True)
    chain_governance_delay.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_governance_delay.add_argument("--timeout", type=float, default=120.0)
    chain_governance_delay.set_defaults(func=_cmd_chain_set_governance_delay)

    chain_governance_schedule = chain_subparsers.add_parser(
        "schedule-governance-action",
        help="Schedule a precomputed governance action hash before executing it.",
    )
    chain_governance_schedule.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_governance_schedule.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_governance_schedule.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_governance_schedule.add_argument("--settlement", help="Override Myco settlement address.")
    chain_governance_schedule.add_argument("--action-hash", required=True)
    chain_governance_schedule.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_governance_schedule.add_argument("--timeout", type=float, default=120.0)
    chain_governance_schedule.set_defaults(func=_cmd_chain_schedule_governance_action)

    chain_governance_hash = chain_subparsers.add_parser(
        "governance-action-hash",
        help="Compute a MycoMesh v2 governance action hash for timelock scheduling.",
    )
    chain_governance_hash.add_argument(
        "action",
        choices=[
            "treasury",
            "operator",
            "governance-executor",
            "governance-delay",
            "economics",
            "trusted-settlement",
            "channel",
            "buyback-burn",
        ],
    )
    chain_governance_hash.add_argument("--treasury")
    chain_governance_hash.add_argument("--operator")
    chain_governance_hash.add_argument("--executor")
    chain_governance_hash.add_argument("--allowed", choices=["true", "false"])
    chain_governance_hash.add_argument("--enabled", choices=["true", "false"])
    chain_governance_hash.add_argument("--delay-seconds", type=int)
    chain_governance_hash.add_argument("--epoch-seconds", type=int)
    chain_governance_hash.add_argument("--epoch-emission-myco")
    chain_governance_hash.add_argument("--halving-interval-epochs", type=int)
    chain_governance_hash.add_argument("--max-consumer-rebate-bps", type=int)
    chain_governance_hash.add_argument("--channel-hash", default=DEFAULT_CHANNEL_HASH)
    chain_governance_hash.add_argument("--input-per-1k-usdc")
    chain_governance_hash.add_argument("--output-per-1k-usdc")
    chain_governance_hash.add_argument("--minimum-fee-usdc")
    chain_governance_hash.add_argument("--provider-bps", type=int)
    chain_governance_hash.add_argument("--relay-bps", type=int)
    chain_governance_hash.add_argument("--pool-bps", type=int)
    chain_governance_hash.add_argument("--treasury-bps", type=int)
    chain_governance_hash.add_argument("--provider-reward-bps", type=int)
    chain_governance_hash.add_argument("--consumer-reward-bps", type=int)
    chain_governance_hash.add_argument("--reward-per-treasury-unit", type=int)
    chain_governance_hash.add_argument("--active", choices=["true", "false"], default="true")
    chain_governance_hash.add_argument("--amount-myco")
    chain_governance_hash.set_defaults(func=_cmd_chain_governance_action_hash)

    chain_economics = chain_subparsers.add_parser(
        "set-economics",
        help="Set epoch emission, halving, and consumer rebate governance parameters.",
    )
    chain_economics.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_economics.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_economics.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_economics.add_argument("--settlement", help="Override Myco settlement address.")
    chain_economics.add_argument("--epoch-seconds", type=int, required=True)
    chain_economics.add_argument("--epoch-emission-myco", required=True)
    chain_economics.add_argument("--halving-interval-epochs", type=int, required=True)
    chain_economics.add_argument("--max-consumer-rebate-bps", type=int, required=True)
    chain_economics.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_economics.add_argument("--timeout", type=float, default=120.0)
    chain_economics.set_defaults(func=_cmd_chain_set_economics)

    chain_channel = chain_subparsers.add_parser(
        "set-channel",
        help="Set a channel price, stablecoin split, and MYCO reward split.",
    )
    chain_channel.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_channel.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_channel.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_channel.add_argument("--settlement", help="Override Myco settlement address.")
    chain_channel.add_argument("--channel-hash", default=DEFAULT_CHANNEL_HASH)
    chain_channel.add_argument("--input-per-1k-usdc", required=True)
    chain_channel.add_argument("--output-per-1k-usdc", required=True)
    chain_channel.add_argument("--minimum-fee-usdc", required=True)
    chain_channel.add_argument("--provider-bps", type=int, required=True)
    chain_channel.add_argument("--relay-bps", type=int, required=True)
    chain_channel.add_argument("--pool-bps", type=int, required=True)
    chain_channel.add_argument("--treasury-bps", type=int, required=True)
    chain_channel.add_argument("--provider-reward-bps", type=int, required=True)
    chain_channel.add_argument("--consumer-reward-bps", type=int, required=True)
    chain_channel.add_argument("--reward-per-treasury-unit", type=int, required=True)
    chain_channel.add_argument("--active", choices=["true", "false"], default="true")
    chain_channel.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_channel.add_argument("--timeout", type=float, default=120.0)
    chain_channel.set_defaults(func=_cmd_chain_set_channel)

    chain_burn = chain_subparsers.add_parser(
        "treasury-buyback-burn",
        help="Burn MYCO from the treasury after an off-chain buyback.",
    )
    chain_burn.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_burn.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_burn.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_burn.add_argument("--settlement", help="Override Myco settlement address.")
    chain_burn.add_argument("--amount-myco", required=True)
    chain_burn.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_burn.add_argument("--timeout", type=float, default=120.0)
    chain_burn.set_defaults(func=_cmd_chain_treasury_buyback_burn)

    chain_trusted = chain_subparsers.add_parser(
        "set-trusted-settlement",
        help="Enable or disable demo-only trusted settlement after timelock scheduling.",
    )
    chain_trusted.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_trusted.add_argument("--private-key", help="Governance private key. Defaults to PRIVATE_KEY.")
    chain_trusted.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_trusted.add_argument("--settlement", help="Override Myco settlement address.")
    chain_trusted.add_argument("--enabled", choices=["true", "false"], required=True)
    chain_trusted.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_trusted.add_argument("--timeout", type=float, default=120.0)
    chain_trusted.set_defaults(func=_cmd_chain_set_trusted_settlement)

    chain_settle = chain_subparsers.add_parser("settle-receipt", help="Settle one local inference receipt on-chain.")
    chain_settle.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_settle.add_argument("--private-key", help="Operator private key. Defaults to PRIVATE_KEY.")
    chain_settle.add_argument("--deployment", default=DEFAULT_DEPLOYMENT_PATH)
    chain_settle.add_argument("--settlement", help="Override settlement contract address.")
    chain_settle.add_argument("--ledger", default=DEFAULT_LEDGER_PATH, help="Receipt JSONL path.")
    chain_settle.add_argument("--receipt-json", help="Single receipt JSON file. Overrides --ledger.")
    chain_settle.add_argument("--receipt-index", type=int, default=-1, help="JSONL receipt index. Defaults to latest.")
    chain_settle.add_argument("--consumer-address", help="Paying consumer EVM address. Defaults to receipt consumer_payment_address.")
    chain_settle.add_argument("--provider-address", help="Provider payout EVM address. Defaults to receipt provider_payment_address.")
    chain_settle.add_argument("--relay-address", default=ZERO_ADDRESS, help="Relay payout EVM address or zero address.")
    chain_settle.add_argument("--pool-address", default=ZERO_ADDRESS, help="Pool payout EVM address or zero address.")
    chain_settle.add_argument("--channel-hash", default=DEFAULT_CHANNEL_HASH, help="On-chain bytes32 channel id.")
    chain_settle.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_settle.add_argument("--timeout", type=float, default=120.0)
    chain_settle.set_defaults(func=_cmd_chain_settle_receipt)

    chain_settle_prepaid = chain_subparsers.add_parser(
        "settle-prepaid-receipt",
        help="Legacy demo settlement for one prepaid receipt. Prefer settle-delegated-prepaid-receipt.",
    )
    chain_settle_prepaid.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_settle_prepaid.add_argument("--private-key", help="Operator private key. Defaults to PRIVATE_KEY.")
    chain_settle_prepaid.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_settle_prepaid.add_argument("--settlement", help="Override Myco settlement address.")
    chain_settle_prepaid.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
    chain_settle_prepaid.add_argument("--receipt-json")
    chain_settle_prepaid.add_argument("--receipt-index", type=int, default=-1)
    chain_settle_prepaid.add_argument("--consumer-address", help="Defaults to receipt consumer_payment_address.")
    chain_settle_prepaid.add_argument("--provider-address", help="Defaults to receipt provider_payment_address.")
    chain_settle_prepaid.add_argument("--consumer-private-key", help="Demo-only consumer EVM key used to sign the receipt digest.")
    chain_settle_prepaid.add_argument("--provider-private-key", help="Demo-only provider EVM key used to sign the receipt digest.")
    chain_settle_prepaid.add_argument(
        "--operator-signature",
        action="store_true",
        help="Also include an operator EVM signature over the receipt digest.",
    )
    chain_settle_prepaid.add_argument(
        "--trusted",
        action="store_true",
        help="Use operator-only trusted settlement. Disabled by default on-chain and in CLI unless explicitly allowed.",
    )
    chain_settle_prepaid.add_argument(
        "--allow-demo-trusted",
        action="store_true",
        help="Explicitly allow trusted settlement from this CLI call. Requires the contract trusted settlement switch to be enabled.",
    )
    chain_settle_prepaid.add_argument("--relay-address", default=ZERO_ADDRESS)
    chain_settle_prepaid.add_argument("--pool-address", default=ZERO_ADDRESS)
    chain_settle_prepaid.add_argument("--pricing-hash")
    chain_settle_prepaid.add_argument("--deadline", type=int, default=0)
    chain_settle_prepaid.add_argument("--accepted-hash")
    chain_settle_prepaid.add_argument("--route-state", default=DEFAULT_ROUTE_STATE_PATH)
    chain_settle_prepaid.add_argument("--channel-hash", default=DEFAULT_CHANNEL_HASH)
    chain_settle_prepaid.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_settle_prepaid.add_argument("--timeout", type=float, default=120.0)
    chain_settle_prepaid.set_defaults(func=_cmd_chain_settle_prepaid_receipt)

    chain_settle_delegated = chain_subparsers.add_parser(
        "settle-delegated-prepaid-receipt",
        help="Settle one accepted prepaid receipt using consumer/provider settlement delegate signatures.",
    )
    chain_settle_delegated.add_argument("--rpc-url", help="Ethereum RPC URL. Defaults to ETH_RPC_URL.")
    chain_settle_delegated.add_argument("--private-key", help="Operator/delegate private key. Defaults to PRIVATE_KEY.")
    chain_settle_delegated.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_settle_delegated.add_argument("--settlement", help="Override Myco settlement address.")
    chain_settle_delegated.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
    chain_settle_delegated.add_argument("--receipt-json")
    chain_settle_delegated.add_argument("--receipt-index", type=int, default=-1)
    chain_settle_delegated.add_argument("--consumer-address", help="Defaults to receipt consumer_payment_address.")
    chain_settle_delegated.add_argument("--provider-address", help="Defaults to receipt provider_payment_address.")
    chain_settle_delegated.add_argument("--consumer-delegate-private-key", help="Demo-only local signer. Prefer --consumer-signature-json.")
    chain_settle_delegated.add_argument("--provider-delegate-private-key", help="Demo-only local signer. Prefer --provider-signature-json.")
    chain_settle_delegated.add_argument("--consumer-signature-json", help="Wallet-produced delegate signature JSON with r/s/v.")
    chain_settle_delegated.add_argument("--provider-signature-json", help="Wallet-produced delegate signature JSON with r/s/v.")
    chain_settle_delegated.add_argument("--delegate", help="Defaults to the operator private key address.")
    chain_settle_delegated.add_argument("--max-usdc", help="Delegate max settlement amount. Defaults to receipt gross fee.")
    chain_settle_delegated.add_argument("--expires-at", type=int, default=0)
    chain_settle_delegated.add_argument("--consumer-nonce", type=int)
    chain_settle_delegated.add_argument("--provider-nonce", type=int)
    chain_settle_delegated.add_argument(
        "--operator-signature",
        action="store_true",
        help="Also include an operator EVM signature over the receipt digest.",
    )
    chain_settle_delegated.add_argument("--relay-address", default=ZERO_ADDRESS)
    chain_settle_delegated.add_argument("--pool-address", default=ZERO_ADDRESS)
    chain_settle_delegated.add_argument("--pricing-hash")
    chain_settle_delegated.add_argument("--deadline", type=int, default=0)
    chain_settle_delegated.add_argument("--accepted-hash")
    chain_settle_delegated.add_argument("--route-state", default=DEFAULT_ROUTE_STATE_PATH)
    chain_settle_delegated.add_argument("--channel-hash", default=DEFAULT_CHANNEL_HASH)
    chain_settle_delegated.add_argument("--chain-id", type=int, default=SEPOLIA_CHAIN_ID)
    chain_settle_delegated.add_argument("--timeout", type=float, default=120.0)
    chain_settle_delegated.set_defaults(func=_cmd_chain_settle_delegated_prepaid_receipt)

    chain_prepare_delegate = chain_subparsers.add_parser(
        "prepare-delegate-signatures",
        help="Print EIP-712 delegate digests that consumer/provider wallets should sign.",
    )
    chain_prepare_delegate.add_argument("--deployment", default=DEFAULT_MYCO_DEPLOYMENT_PATH)
    chain_prepare_delegate.add_argument("--settlement", help="Override Myco settlement address.")
    chain_prepare_delegate.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
    chain_prepare_delegate.add_argument("--receipt-json")
    chain_prepare_delegate.add_argument("--receipt-index", type=int, default=-1)
    chain_prepare_delegate.add_argument("--consumer-address", help="Defaults to receipt consumer_payment_address.")
    chain_prepare_delegate.add_argument("--provider-address", help="Defaults to receipt provider_payment_address.")
    chain_prepare_delegate.add_argument("--delegate", required=True)
    chain_prepare_delegate.add_argument("--max-usdc")
    chain_prepare_delegate.add_argument("--expires-at", type=int, default=0)
    chain_prepare_delegate.add_argument("--consumer-nonce", type=int, required=True)
    chain_prepare_delegate.add_argument("--provider-nonce", type=int, required=True)
    chain_prepare_delegate.add_argument("--relay-address", default=ZERO_ADDRESS)
    chain_prepare_delegate.add_argument("--pool-address", default=ZERO_ADDRESS)
    chain_prepare_delegate.add_argument("--pricing-hash")
    chain_prepare_delegate.add_argument("--deadline", type=int, default=0)
    chain_prepare_delegate.add_argument("--accepted-hash")
    chain_prepare_delegate.add_argument("--channel-hash", default=DEFAULT_CHANNEL_HASH)
    chain_prepare_delegate.add_argument("--chain-id", type=int)
    chain_prepare_delegate.set_defaults(func=_cmd_chain_prepare_delegate_signatures)

    chain_prepare_batch = chain_subparsers.add_parser("prepare-prepaid-batch", help="Build signed-settlement batch input metadata from local accepted receipts.")
    chain_prepare_batch.add_argument("--ledger", default=DEFAULT_LEDGER_PATH)
    chain_prepare_batch.add_argument("--limit", type=int, default=100)
    chain_prepare_batch.add_argument("--consumer-address")
    chain_prepare_batch.add_argument("--provider-address")
    chain_prepare_batch.add_argument("--relay-address", default=ZERO_ADDRESS)
    chain_prepare_batch.add_argument("--pool-address", default=ZERO_ADDRESS)
    chain_prepare_batch.add_argument("--pricing-hash")
    chain_prepare_batch.add_argument("--deadline", type=int, default=0)
    chain_prepare_batch.add_argument("--accepted-hash")
    chain_prepare_batch.add_argument("--channel-hash", default=DEFAULT_CHANNEL_HASH)
    chain_prepare_batch.set_defaults(func=_cmd_chain_prepare_prepaid_batch)

    return parser


def _cmd_login(args: argparse.Namespace) -> int:
    config = load_config()
    return run_codex_login(config, no_device_auth=args.no_device_auth)


def _cmd_logout(args: argparse.Namespace) -> int:
    config = load_config()
    codex_home = Path(config.codex_home)
    auth_paths = [
        codex_home / "auth.json",
        codex_home / "login.json",
    ]
    existing = [path for path in auth_paths if path.exists()]
    if not existing:
        print("No Codex auth files found for this gateway.")
        return 0

    if not args.yes:
        print("This will move the gateway Codex auth files into a backup directory:")
        for path in existing:
            print(f"- {path}")
        answer = input("Continue? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Logout cancelled.")
            return 1

    backup_dir = codex_home / "auth-backups" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in existing:
        target = backup_dir / path.name
        path.replace(target)
        print(f"Moved {path} -> {target}")
    print("Gateway Codex login state cleared.")
    return 0


def _cmd_key_create(args: argparse.Namespace) -> int:
    key = create_agent_key(
        path=Path(args.agents_file),
        agent_id=args.agent,
        role=args.role,
        description=args.description,
    )
    print("Created gateway key.")
    print(f"agent_id: {key.agent_id}")
    print(f"api_key: {key.key}")
    print(f"fingerprint: {key.fingerprint}")
    print("Use it as `Authorization: Bearer <api_key>` or an OpenAI-compatible api_key.")
    return 0


def _cmd_key_delete(args: argparse.Namespace) -> int:
    removed = delete_agent_key(
        path=Path(args.agents_file),
        agent_id=args.agent,
        selector=args.selector,
    )
    print("Deleted gateway key.")
    print(f"agent_id: {removed.agent_id}")
    print(f"key: {removed.display}")
    print(f"fingerprint: {removed.fingerprint}")
    return 0


def _cmd_key_list(args: argparse.Namespace) -> int:
    keys = list_agent_keys(Path(args.agents_file), agent_id=args.agent)
    if not keys:
        print("No gateway keys found.")
        return 0
    for key in keys:
        print(f"{key.agent_id}\t{key.display}\t{key.fingerprint}")
    return 0


def _cmd_key_rotate(args: argparse.Namespace) -> int:
    new_key, old_key = rotate_agent_key(
        path=Path(args.agents_file),
        agent_id=args.agent,
        selector=args.selector,
        role=args.role,
        description=args.description,
    )
    print("Rotated gateway key.")
    print(f"agent_id: {new_key.agent_id}")
    print(f"old_key: {old_key.display}")
    print(f"old_fingerprint: {old_key.fingerprint}")
    print(f"new_api_key: {new_key.key}")
    print(f"new_fingerprint: {new_key.fingerprint}")
    print("Restart an already running gateway so the new key config is loaded.")
    return 0


def _cmd_url(args: argparse.Namespace) -> int:
    public_url = discover_public_url(Path(args.run_dir))
    if public_url:
        print(public_url.rstrip("/") + "/v1")
        return 0
    print(f"No public tunnel URL found. Local URL: http://127.0.0.1:{args.port}/v1")
    return 1


def _cmd_status(args: argparse.Namespace) -> int:
    config = load_config()
    agents_path = Path(args.agents_file)
    public_url = discover_public_url(Path(args.run_dir))
    print(f"backend: {config.backend}")
    print(f"codex_home: {config.codex_home}")
    print(f"agents_file: {agents_path}")
    print(f"agent_keys: {len(list_agent_keys(agents_path))}")
    print(f"local_url: http://127.0.0.1:{args.port}/v1")
    print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'not found'}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    gateway = start_gateway(
        host=args.host,
        port=args.port,
        run_dir=run_dir,
        reload=args.reload,
        agents_file=Path(args.agents_file),
    )
    print(f"Gateway running on http://{args.host}:{args.port}/v1")
    print(f"gateway_pid: {gateway.pid}")
    print(f"gateway_log: {gateway.log_path}")

    tunnel: RuntimeProcess | None = None
    if args.with_tunnel:
        tunnel = start_tunnel(
            host=args.host,
            port=args.port,
            run_dir=run_dir,
            protocol=args.tunnel_protocol,
        )
        print(f"tunnel_pid: {tunnel.pid}")
        print(f"tunnel_log: {tunnel.log_path}")
        public_url = wait_for_public_url(run_dir, timeout_seconds=20)
        print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'pending'}")

    print("Press Ctrl+C to stop processes started by this command.")
    processes = [proc.process for proc in (gateway, tunnel) if proc and proc.process]
    try:
        while True:
            for process in processes:
                if process.poll() is not None:
                    return process.returncode or 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping...")
        for process in reversed(processes):
            _terminate_process(process)
        return 130


def _cmd_provider_start(args: argparse.Namespace) -> int:
    args.pool = _provider_pool_url(args.pool)
    if not args.pool:
        print("error: provider start requires --pool, MYCOMESH_PROVIDER_POOL_URL, or MYCOMESH_POOL_URL", file=sys.stderr)
        return 2

    agents_file = Path(args.agents_file)
    identity = load_or_create_identity(args.identity)
    peer_id = args.peer_id or identity.peer_id
    print(f"peer_id: {peer_id}")
    print(f"public_key: {identity.public_key}")
    if normalize_network_profile(args.network_profile) == NETWORK_PROFILE_TESTNET:
        print("testnet_note: the pool must allowlist this public_key before registration can succeed.")

    preflight_error = _provider_profile_preflight(args)
    if preflight_error:
        print(f"error: {preflight_error}", file=sys.stderr)
        return 2

    config = load_config()
    if codex_login_required(config):
        if not codex_auth_exists(config.codex_home):
            if args.skip_login:
                print(f"error: no Codex auth state found in {config.codex_home}; run `python -m gateway login`", file=sys.stderr)
                return 2
            login_code = run_codex_login(config, no_device_auth=args.no_device_auth)
            if login_code != 0:
                return login_code
        else:
            print(f"codex_login: existing ({config.codex_home})")
    else:
        print(f"codex_login: skipped (backend={config.backend})")

    try:
        key, created = ensure_agent_key(agents_file, args.agent)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if created:
        print("Created provider gateway key.")
        print(f"agent_id: {key.agent_id}")
        print(f"key_fingerprint: {key.fingerprint}")
    else:
        print(f"gateway_key: existing ({key.fingerprint})")

    run_dir = Path(args.run_dir)
    gateway = start_gateway(
        host=args.gateway_host,
        port=args.gateway_port,
        run_dir=run_dir,
        reload=args.gateway_reload,
        agents_file=agents_file,
    )
    print(f"Gateway running on http://{args.gateway_host}:{args.gateway_port}/v1")
    print(f"gateway_pid: {gateway.pid}")
    print(f"gateway_log: {gateway.log_path}")
    if gateway.already_running and created:
        print(
            "error: gateway was already running before this command created the provider key; "
            "restart the gateway or rerun provider start so it can load the new agents file",
            file=sys.stderr,
        )
        return 2

    gateway_health_url = f"http://127.0.0.1:{args.gateway_port}/health"
    if not wait_for_gateway_health(gateway_health_url, timeout_seconds=args.health_timeout):
        print(f"error: gateway did not become healthy at {gateway_health_url}", file=sys.stderr)
        if gateway.process is not None:
            _terminate_process(gateway.process)
        return 1

    provider = start_provider_process(args, run_dir=run_dir, gateway_url=_provider_gateway_url(args))
    print(f"Provider starting with {args.transport} transport.")
    print(f"provider_pid: {provider.pid}")
    print(f"provider_log: {provider.log_path}")
    print(f"pool_url: {args.pool}")
    print("provider_status: starting; check the provider log for pool_status: joined")
    print("Press Ctrl+C to stop processes started by this command.")

    processes = [proc.process for proc in (gateway, provider) if proc and proc.process]
    try:
        while True:
            for process in processes:
                if process.poll() is not None:
                    return process.returncode or 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping...")
        for process in reversed(processes):
            _terminate_process(process)
        return 130


def _cmd_tunnel_start(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    tunnel = start_tunnel(
        host=args.host,
        port=args.port,
        run_dir=run_dir,
        protocol=args.protocol,
    )
    if tunnel.already_running:
        print(f"Tunnel already running with pid {tunnel.pid}.")
    else:
        print(f"Started tunnel with pid {tunnel.pid}.")
    print(f"tunnel_log: {tunnel.log_path}")
    public_url = wait_for_public_url(run_dir, timeout_seconds=20)
    print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'pending'}")
    return 0


def _cmd_tunnel_stop(args: argparse.Namespace) -> int:
    stopped = stop_managed_process(_pid_path(Path(args.run_dir), "cloudflared", args.port))
    print("Stopped tunnel." if stopped else "No managed tunnel is running.")
    return 0 if stopped else 1


def _cmd_tunnel_status(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    pid_path = _pid_path(run_dir, "cloudflared", args.port)
    pid = _read_pid(pid_path)
    running = bool(pid and _process_running(pid))
    public_url = discover_public_url(run_dir)
    print(f"running: {str(running).lower()}")
    print(f"pid: {pid if pid else 'not found'}")
    print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'not found'}")
    return 0 if running else 1


def _cmd_health(args: argparse.Namespace) -> int:
    url = _health_url(args.url, args.public, Path(args.run_dir), args.port)
    try:
        status_code, body = fetch_health(url, timeout=args.timeout)
    except urllib.error.URLError as exc:
        print(f"health_url: {url}")
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"health_url: {url}")
    print(f"status_code: {status_code}")
    print(body)
    return 0 if 200 <= status_code < 300 else 1


def _cmd_p2p_serve(args: argparse.Namespace) -> int:
    agent_key = args.key or first_agent_key(Path(args.agents_file), args.agent)
    identity = load_or_create_identity(args.identity)
    peer_id = args.peer_id or identity.peer_id
    bootstrap_peers = [parse_peer_address(peer) for peer in args.bootstrap]
    preflight_error = _provider_profile_preflight(args)
    if preflight_error:
        print(f"error: {preflight_error}", file=sys.stderr)
        return 2
    heartbeat = None
    config = ProviderConfig(
        peer_id=peer_id,
        channel=args.channel,
        agent_id=args.agent,
        agent_key=agent_key,
        gateway_url=args.gateway_url,
        model=args.model,
        advertise_host=args.advertise_host,
        advertise_port=args.port,
        identity=identity,
        require_signed_requests=not args.allow_unsigned_requests,
        allow_any_signed_consumer=args.allow_any_signed_consumer,
        authorized_consumers=set(args.consumer_public_key or []),
        payment_address=args.payment_address,
        require_payment_reservation=not args.allow_unreserved_requests,
        pricing_config_path=args.pricing_config,
        pricing_hash=args.pricing_hash,
        reserve_input_tokens=args.reserve_input_tokens,
        reserve_output_tokens=args.reserve_output_tokens,
        replay_store_path=os.getenv("MYCOMESH_REPLAY_DB", DEFAULT_REPLAY_DB),
        max_concurrency=args.capacity,
    )
    print(f"P2P provider listening on {args.host}:{args.port}")
    print(f"peer_id: {peer_id}")
    print(f"public_key: {identity.public_key}")
    print(f"network_profile: {normalize_network_profile(args.network_profile)}")
    if args.payment_address:
        print(f"payment_address: {args.payment_address}")
    print(f"channel: {args.channel}")
    print(f"model: {args.model}")
    print(f"gateway_url: {args.gateway_url}")
    if bootstrap_peers:
        print(f"bootstrap_peers: {', '.join(peer.value for peer in bootstrap_peers)}")

    def on_started(started_config: ProviderConfig) -> None:
        nonlocal heartbeat
        if not args.pool:
            return
        capacity = {"max_concurrency": args.capacity}
        pool_urls = _split_urls(args.pool)
        join_results = join_provider_pools(
            pool_urls,
            peer_factory=lambda pool_url: _provider_pool_peer(started_config, pool_url=pool_url),
            ttl_seconds=args.ttl,
            capacity=capacity,
            on_error=lambda pool_url, exc: print(f"pool_join_error[{pool_url}]: {exc}", file=sys.stderr),
        )
        for result in join_results:
            print(f"pool_url: {result['pool_url']}")
            print("pool_status: joined")
        heartbeat = start_provider_pool_heartbeats(
            pool_urls,
            peer_factory=lambda pool_url: _provider_pool_peer(started_config, pool_url=pool_url),
            ttl_seconds=args.ttl,
            interval_seconds=args.heartbeat_interval,
            capacity=capacity,
            on_error=lambda pool_url, exc: print(f"pool_heartbeat_error[{pool_url}]: {exc}", file=sys.stderr),
        )

    try:
        serve_provider(
            listen_host=args.host,
            listen_port=args.port,
            config=config,
            bootstrap_peers=bootstrap_peers,
            on_started=on_started,
        )
    except KeyboardInterrupt:
        print("P2P provider stopped.")
        _stop_heartbeats(heartbeat)
        return 130
    return 0


def _cmd_p2p_infer(args: argparse.Namespace) -> int:
    peer = parse_peer_address(args.peer)
    identity = load_or_create_identity(args.identity)
    request_id = uuid.uuid4().hex
    message: dict[str, Any] = {
        "type": "infer",
        "request_id": request_id,
        "channel": args.channel,
        "endpoint": args.endpoint,
        "model": args.model,
        "input": args.input,
    }
    if args.provider_peer_id and args.pricing_hash:
        message["payment_reservation"] = build_payment_reservation(
            request_id=request_id,
            consumer_id=args.consumer,
            consumer_payment_address=args.consumer_payment_address,
            provider_id=args.provider_peer_id,
            provider_payment_address=args.provider_payment_address,
            channel=args.channel,
            pricing_hash=args.pricing_hash,
            max_fee_units=usdc_to_units(args.max_fee_usdc),
            signer=identity,
        )
    message = sign_document(message, identity.private_key, purpose=INFERENCE_REQUEST_PURPOSE, audience=args.provider_peer_id)
    try:
        response = send_message(peer, message, timeout=args.timeout)
    except P2PError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.raw:
        print(json.dumps(response, indent=2, ensure_ascii=False))
    else:
        print(response.get("output_text") or "")
    return 0


def _cmd_p2p_ping(args: argparse.Namespace) -> int:
    peer = parse_peer_address(args.peer)
    try:
        response = send_message(
            peer,
            {"type": "ping", "request_id": uuid.uuid4().hex},
            timeout=args.timeout,
        )
    except P2PError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


def _cmd_p2p_peers(args: argparse.Namespace) -> int:
    peer = parse_peer_address(args.peer)
    try:
        response = send_message(
            peer,
            {"type": "peers", "request_id": uuid.uuid4().hex},
            timeout=args.timeout,
        )
    except P2PError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


def _cmd_p2p_relay(args: argparse.Namespace) -> int:
    agent_key = args.key or first_agent_key(Path(args.agents_file), args.agent)
    identity = load_or_create_identity(args.identity)
    peer_id = args.peer_id or identity.peer_id
    preflight_error = _provider_profile_preflight(args)
    if preflight_error:
        print(f"error: {preflight_error}", file=sys.stderr)
        return 2
    config = ProviderConfig(
        peer_id=peer_id,
        channel=args.channel,
        agent_id=args.agent,
        agent_key=agent_key,
        gateway_url=args.gateway_url,
        model=args.model,
        advertise_host="relay",
        advertise_port=0,
        identity=identity,
        require_signed_requests=not args.allow_unsigned_requests,
        allow_any_signed_consumer=args.allow_any_signed_consumer,
        authorized_consumers=set(args.consumer_public_key or []),
        payment_address=args.payment_address,
        require_payment_reservation=not args.allow_unreserved_requests,
        pricing_config_path=args.pricing_config,
        pricing_hash=args.pricing_hash,
        reserve_input_tokens=args.reserve_input_tokens,
        reserve_output_tokens=args.reserve_output_tokens,
        replay_store_path=os.getenv("MYCOMESH_REPLAY_DB", DEFAULT_REPLAY_DB),
        max_concurrency=args.capacity,
    )
    heartbeat = None
    stop_event = threading.Event()
    relay_public_url = args.relay_public_url or f"http://{args.relay_host}:{DEFAULT_RELAY_CONTROL_PORT}"
    relay_address = _relay_address_from_control_url(relay_public_url, peer_id)
    print(f"P2P relay provider connecting to {args.relay_host}:{args.relay_port}")
    print(f"peer_id: {peer_id}")
    print(f"public_key: {identity.public_key}")
    print(f"network_profile: {normalize_network_profile(args.network_profile)}")
    if args.payment_address:
        print(f"payment_address: {args.payment_address}")
    print(f"channel: {args.channel}")
    print(f"model: {args.model}")
    print(f"gateway_url: {args.gateway_url}")
    print(f"relay_address: {relay_address}")

    def on_registered(_: dict[str, Any]) -> None:
        nonlocal heartbeat
        if not args.pool or heartbeat is not None:
            return
        capacity = {"max_concurrency": args.capacity, "transport": "relay"}
        pool_urls = _split_urls(args.pool)
        join_results = join_provider_pools(
            pool_urls,
            peer_factory=lambda pool_url: _provider_pool_peer(config, addresses=[relay_address], pool_url=pool_url),
            ttl_seconds=args.ttl,
            capacity=capacity,
            on_error=lambda pool_url, exc: print(f"pool_join_error[{pool_url}]: {exc}", file=sys.stderr),
        )
        for result in join_results:
            print(f"pool_url: {result['pool_url']}")
            print("pool_status: joined")
        heartbeat = start_provider_pool_heartbeats(
            pool_urls,
            peer_factory=lambda pool_url: _provider_pool_peer(config, addresses=[relay_address], pool_url=pool_url),
            ttl_seconds=args.ttl,
            interval_seconds=args.heartbeat_interval,
            capacity=capacity,
            on_error=lambda pool_url, exc: print(f"pool_heartbeat_error[{pool_url}]: {exc}", file=sys.stderr),
        )

    try:
        run_relay_provider(
            relay_host=args.relay_host,
            relay_port=args.relay_port,
            config=config,
            on_registered=on_registered,
            stop_event=stop_event,
        )
    except KeyboardInterrupt:
        print("P2P relay provider stopped.")
        stop_event.set()
        _stop_heartbeats(heartbeat)
        return 130
    return 0


def _cmd_pool_serve(args: argparse.Namespace) -> int:
    config = PoolConfig(
        verify_direct_addresses=not args.skip_direct_address_verification,
        public_url=args.public_url,
        authorized_reputation_signers=set(args.reputation_signer_public_key or []),
        allow_any_reputation_signer=args.allow_any_reputation_signer,
        network_profile=args.network_profile,
        authorized_provider_public_keys=set(args.provider_public_key or []),
    )
    try:
        validate_pool_launch_config(config)
    except PoolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Provider pool listening on http://{args.host}:{args.port}")
    if args.public_url:
        print(f"pool_public_url: {args.public_url}")
    try:
        serve_pool(
            listen_host=args.host,
            listen_port=args.port,
            config=config,
        )
    except PoolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Provider pool stopped.")
        return 130
    return 0


def _cmd_pool_join(args: argparse.Namespace) -> int:
    addresses = list(dict.fromkeys(args.address))
    identity = load_or_create_identity(args.identity)
    peer = {
        "peer_id": args.peer_id,
        "protocol": "mycomesh-p2p/0.2",
        "address": addresses[0],
        "addresses": addresses,
        "channel": args.channel,
        "agent_id": args.agent,
        "model": args.model,
        "public_key": identity.public_key,
    }
    if args.payment_address:
        peer["payment_address"] = args.payment_address
    peer = sign_document(peer, identity.private_key, purpose=POOL_REGISTRATION_PURPOSE, audience=args.pool)
    try:
        response = join_pool(
            pool_url=args.pool,
            peer=peer,
            ttl_seconds=args.ttl,
            capacity={"max_concurrency": args.capacity},
            timeout=args.timeout,
        )
    except PoolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


def _cmd_pool_leave(args: argparse.Namespace) -> int:
    identity = load_or_create_identity(args.identity)
    peer_id = args.peer_id or identity.peer_id
    leave = sign_document({"peer_id": peer_id}, identity.private_key, purpose=POOL_LEAVE_PURPOSE, audience=args.pool)
    try:
        response = _pool_post_json(args.pool, "/leave", {"leave": leave}, timeout=args.timeout)
    except PoolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


def _cmd_pool_peers(args: argparse.Namespace) -> int:
    try:
        peers = discover_peers_from_pools(_split_urls(args.pool), channel=args.channel, timeout=args.timeout)
    except PoolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.raw:
        print(json.dumps({"peers": peers}, indent=2, ensure_ascii=False))
        return 0
    if not peers:
        print("No live peers found.")
        return 1
    for peer in peers:
        print(
            "\t".join(
                [
                    str(peer.get("peer_id") or ""),
                    str(peer.get("channel") or ""),
                    str(peer.get("model") or ""),
                    ",".join(_peer_addresses(peer)),
                    f"expires_at={peer.get('expires_at')}",
                ]
            )
        )
    return 0


def _cmd_pool_infer(args: argparse.Namespace) -> int:
    identity = load_or_create_identity(getattr(args, "identity", DEFAULT_REQUEST_IDENTITY_PATH))
    route_state_path = getattr(args, "route_state", None)
    route_state = load_route_state(route_state_path) if route_state_path else RouteState()
    pricing_table = load_pricing_config(getattr(args, "pricing_config", None))
    channel_pricing_hash = _channel_pricing_hash(args, pricing_table)
    accept_receipt = bool(getattr(args, "accept", False))
    try:
        peers = discover_peers_from_pools(_split_urls(args.pool), channel=args.channel, timeout=min(args.timeout, 10.0))
    except PoolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not peers:
        print(f"error: no live peers found for channel {args.channel}", file=sys.stderr)
        return 1

    last_error: Exception | None = None
    for peer_info in rank_peers(peers, route_state):
        peer_id = str(peer_info.get("peer_id") or "")
        try:
            lease_id = reserve_peer(route_state, peer_info, ttl_seconds=int(args.timeout))
            if route_state_path:
                save_route_state(route_state, route_state_path)
        except ValueError as exc:
            last_error = exc
            continue
        for address in _peer_addresses(peer_info):
            selected_pool_url = str(peer_info.get("pool_url") or args.pool)
            started_at = time.time()
            try:
                response = _send_infer_to_address(
                    address=address,
                    channel=args.channel,
                    endpoint=args.endpoint,
                    model=args.model,
                    input_value=args.input,
                    pool_url=selected_pool_url,
                    peer_id=peer_id,
                    timeout=args.timeout,
                    identity=identity,
                    consumer_id=args.consumer,
                    consumer_payment_address=getattr(args, "consumer_payment_address", None),
                    provider_payment_address=str(peer_info.get("payment_address") or "") or None,
                    pricing_hash=channel_pricing_hash,
                    max_fee_units=_max_fee_units(args, pricing_table),
                )
            except (P2PError, RelayError, ValueError) as exc:
                last_error = exc
                record_route_failure(route_state, peer_id, exc)
                if route_state_path:
                    save_route_state(route_state, route_state_path)
                continue
            finished_at = time.time()
            try:
                if peer_info.get("public_key"):
                    verify_provider_response(response, peer_info)
            except ProtocolValidationError as exc:
                last_error = exc
                record_route_failure(route_state, peer_id, exc)
                if route_state_path:
                    save_route_state(route_state, route_state_path)
                continue
            record_route_success(route_state, peer_id, int((finished_at - started_at) * 1000))
            if route_state_path:
                save_route_state(route_state, route_state_path)
            quote = quote_usage(
                args.channel,
                response.get("usage") if isinstance(response, dict) else None,
                pricing_table=pricing_table,
            )
            receipt = build_receipt(
                consumer_id=args.consumer,
                provider_id=str(peer_info.get("peer_id") or ""),
                relay_id=_relay_id_for_address(address),
                pool_url=selected_pool_url,
                selected_address=address,
                channel=args.channel,
                model=args.model,
                endpoint=args.endpoint,
                input_value=args.input,
                response=response,
                quote=quote,
                started_at=started_at,
                finished_at=finished_at,
                consumer_public_key=identity.public_key,
                consumer_payment_address=getattr(args, "consumer_payment_address", None),
                provider_public_key=str(peer_info.get("public_key") or "") or None,
                provider_payment_address=str(peer_info.get("payment_address") or "") or None,
                bridge_usage=build_bridge_usage(address, selected_pool_url, quote.to_dict()),
                channel_pricing_hash=channel_pricing_hash,
                signer=identity,
            )
            receipt_payload = (
                sign_acceptance(receipt.to_dict(), identity, accepted_by=args.consumer)
                if accept_receipt
                else receipt.to_dict()
            )
            if accept_receipt:
                record_route_acceptance(route_state, peer_id)
                if route_state_path:
                    save_route_state(route_state, route_state_path)
            if not args.no_ledger:
                if accept_receipt:
                    append_receipt_payload(Path(args.ledger), receipt_payload)
                else:
                    append_receipt(Path(args.ledger), receipt)
            if args.raw:
                print(json.dumps(response, indent=2, ensure_ascii=False))
            else:
                print(response.get("output_text") or "")
            if args.price:
                print(json.dumps({"pricing": quote.to_dict()}, indent=2, ensure_ascii=False))
            if args.receipt:
                print(json.dumps({"receipt": receipt_payload}, indent=2, ensure_ascii=False))
            release_peer(route_state, lease_id)
            if route_state_path:
                save_route_state(route_state, route_state_path)
            return 0
        release_peer(route_state, lease_id)
        if route_state_path:
            save_route_state(route_state, route_state_path)
    print(f"error: all pool peers failed: {last_error}", file=sys.stderr)
    return 1


def _cmd_pool_health(args: argparse.Namespace) -> int:
    try:
        response = get_pool_health(args.pool, timeout=args.timeout)
    except PoolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


def _cmd_relay_serve(args: argparse.Namespace) -> int:
    advertise_host = args.advertise_host or args.host
    if not args.consumer_public_key and not args.allow_any_signed_consumer:
        print(
            "error: relay serve requires --consumer-public-key, or --allow-any-signed-consumer for development",
            file=sys.stderr,
        )
        return 2
    print(f"Relay control listening on http://{args.host}:{args.control_port}")
    print(f"Relay provider listening on tcp://{args.host}:{args.provider_port}")
    print(f"relay_advertise_host: {advertise_host}")
    try:
        serve_relay(
            host=args.host,
            control_port=args.control_port,
            provider_port=args.provider_port,
            advertise_host=advertise_host,
            authorized_consumers=set(args.consumer_public_key or []),
            allow_any_signed_consumer=args.allow_any_signed_consumer,
            replay_store_path=os.getenv("MYCOMESH_REPLAY_DB", DEFAULT_REPLAY_DB),
        )
    except KeyboardInterrupt:
        print("Relay stopped.")
        return 130
    return 0


def _provider_profile_preflight(args: argparse.Namespace) -> str | None:
    profile = normalize_network_profile(getattr(args, "network_profile", NETWORK_PROFILE_TESTNET))
    if profile == NETWORK_PROFILE_LOCAL:
        return None
    if profile == NETWORK_PROFILE_OPEN:
        return "open network profile is reserved until staking, slashing, and disputes are implemented"
    if getattr(args, "allow_unsigned_requests", False):
        return "testnet provider cannot use --allow-unsigned-requests"
    if getattr(args, "allow_unreserved_requests", False):
        return "testnet provider cannot use --allow-unreserved-requests"
    if getattr(args, "allow_any_signed_consumer", False):
        return "testnet provider requires --consumer-public-key instead of --allow-any-signed-consumer"
    if not getattr(args, "consumer_public_key", None):
        return "testnet provider requires --consumer-public-key"
    if not getattr(args, "payment_address", None):
        return "testnet provider requires --payment-address"
    if not getattr(args, "pricing_hash", None) and not getattr(args, "pricing_config", None):
        return "testnet provider requires --pricing-hash or --pricing-config"
    return None


def _cmd_mycomesh_serve(args: argparse.Namespace) -> int:
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "gateway.mycomesh:app",
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    if args.reload:
        command.append("--reload")
    print(f"MycoMesh proxy running on http://{args.host}:{args.port}/v1")
    try:
        return subprocess.run(command, check=False).returncode
    except FileNotFoundError:
        print("uvicorn command not found; install requirements first", file=sys.stderr)
        return 127


def _cmd_mycomesh_account_create(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    account = store.create_account(args.account_id, payment_address=args.payment_address)
    payload = _billing_account_payload(account)
    payload["api_key"] = account.api_key
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_mycomesh_account_deposit(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    account = store.deposit(args.account_id, args.amount_usdc)
    print(json.dumps({"account_id": account.account_id, "balance_usdc": account.balance_usdc}, indent=2))
    return 0


def _cmd_mycomesh_account_sync_balance(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    try:
        chain_sync = _chain_sync_state_from_args(args)
        account = store.set_balance(args.account_id, args.balance_usdc)
        if chain_sync is not None:
            store.set_chain_sync_state(**chain_sync)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "account_id": account.account_id,
                "balance_usdc": account.balance_usdc,
                "chain_sync": store.get_chain_sync_state(),
            },
            indent=2,
        )
    )
    return 0


def _cmd_mycomesh_account_balance(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    account = store.get_by_account(args.account_id)
    if account is None:
        print(f"error: account not found: {args.account_id}", file=sys.stderr)
        return 1
    print(json.dumps(_billing_account_payload(account), indent=2))
    return 0


def _cmd_mycomesh_account_payment_address(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    try:
        account = store.set_payment_address(args.account_id, args.payment_address)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(_billing_account_payload(account), indent=2))
    return 0


def _cmd_mycomesh_account_policy(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    try:
        account = store.configure_account(
            args.account_id,
            parent_account_id=args.parent_account_id,
            discount_bps=args.discount_bps,
            reseller_margin_bps=args.reseller_margin_bps,
            monthly_quota_usdc=args.monthly_quota_usdc,
            usage_tier=args.usage_tier,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(_billing_account_payload(account), indent=2))
    return 0


def _cmd_mycomesh_account_status(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    try:
        account = store.set_account_status(args.account_id, args.status)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(_billing_account_payload(account), indent=2))
    return 0


def _cmd_mycomesh_account_rotate(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    try:
        account = store.rotate_key(args.account_id)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    payload = _billing_account_payload(account)
    payload["api_key"] = account.api_key
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_mycomesh_account_delete(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    deleted = store.delete_account(args.account_id)
    print(json.dumps({"account_id": args.account_id, "deleted": deleted}, indent=2))
    return 0


def _cmd_mycomesh_account_cleanup_reservations(args: argparse.Namespace) -> int:
    store = BillingStore(args.db)
    try:
        released = store.release_expired_reservations(args.max_age_seconds)
    except BillingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"released": released, "max_age_seconds": args.max_age_seconds}, indent=2))
    return 0


def _cmd_mycomesh_indexer_sync(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        chain_id = int(args.chain_id or deployment.chain_id)
        if args.events:
            result = sync_prepaid_balances_from_events(
                store=BillingStore(args.db),
                rpc_url=rpc_url_arg(args.rpc_url),
                settlement=args.settlement or deployment.settlement,
                accounts=args.account,
                chain_id=chain_id,
                confirmations=args.confirmations,
                lookback_blocks=args.lookback_blocks,
                chunk_blocks=args.chunk_blocks,
                timeout=args.timeout,
                state_path=args.state,
            )
        else:
            if not args.account:
                raise ChainError("--account is required unless --events is set")
            result = sync_prepaid_balances(
                store=BillingStore(args.db),
                rpc_url=rpc_url_arg(args.rpc_url),
                settlement=args.settlement or deployment.settlement,
                accounts=args.account,
                chain_id=chain_id,
                timeout=args.timeout,
                state_path=args.state,
            )
    except (ChainError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0


def _billing_account_payload(account) -> dict[str, object]:
    from .billing import units_to_usdc

    return {
        "account_id": account.account_id,
        "status": account.status,
        "balance_usdc": account.balance_usdc,
        "payment_address": account.payment_address,
        "key_fingerprint": account.key_fingerprint,
        "parent_account_id": account.parent_account_id,
        "discount_bps": account.discount_bps,
        "reseller_margin_bps": account.reseller_margin_bps,
        "monthly_quota_usdc": units_to_usdc(account.monthly_quota_units),
        "monthly_used_usdc": units_to_usdc(account.monthly_used_units),
        "usage_tier": account.usage_tier,
    }


def _chain_sync_state_from_args(args: argparse.Namespace) -> dict[str, object] | None:
    values = (args.chain_id, args.settlement, args.latest_block, args.synced_block)
    if not any(value is not None for value in values):
        return None
    if args.chain_id is None or not args.settlement or args.synced_block is None:
        raise BillingError("--chain-id, --settlement, and --synced-block are required together")
    return {
        "chain_id": args.chain_id,
        "settlement": args.settlement,
        "latest_block": args.latest_block if args.latest_block is not None else args.synced_block,
        "synced_block": args.synced_block,
        "confirmations": args.confirmations,
        "source": args.source,
    }


def _cmd_pricing_quote(args: argparse.Namespace) -> int:
    quote = quote_usage(
        args.channel,
        {
            "input_tokens": args.input_tokens,
            "output_tokens": args.output_tokens,
        },
    )
    print(json.dumps({"pricing": quote.to_dict()}, indent=2, ensure_ascii=False))
    return 0


def _cmd_ledger_receipts(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print("No receipts found.")
        return 1
    lines = path.read_text(encoding="utf-8").splitlines()
    selected = lines[-max(1, args.limit) :]
    for line in selected:
        print(line)
    return 0 if selected else 1


def _cmd_ledger_blocks(args: argparse.Namespace) -> int:
    try:
        receipts = load_receipts(Path(args.ledger))
        blocks = build_settlement_blocks(
            receipts,
            window_seconds=args.window_seconds,
            genesis_timestamp=args.genesis_timestamp,
            from_timestamp=args.from_timestamp,
            to_timestamp=args.to_timestamp,
            include_unaccepted=args.include_unaccepted,
            include_empty=args.include_empty,
            reward_split=BlockRewardSplit(
                provider_bps=args.provider_reward_bps,
                bridge_bps=args.bridge_reward_bps,
                consumer_bps=args.consumer_reward_bps,
            ),
            consumer_reward_config=ConsumerVolumeRewardConfig(
                base_spend=Decimal(str(args.consumer_volume_base_spend)),
                beta=Decimal(str(args.consumer_volume_beta)),
                max_multiplier=Decimal(str(args.consumer_volume_max_multiplier)),
            ),
        )
    except (ChainError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        write_settlement_blocks(Path(args.output), blocks)
    print(json.dumps({"count": len(blocks), "blocks": blocks}, indent=2, ensure_ascii=False))
    return 0


def _cmd_ledger_dispute(args: argparse.Namespace) -> int:
    try:
        receipt = load_receipt(Path(args.ledger), index=args.receipt_index)
    except (ChainError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    provider_id = str(receipt.get("provider_id") or "")
    if not provider_id:
        print("error: receipt has no provider_id", file=sys.stderr)
        return 1
    state = load_route_state(args.route_state)
    record_route_dispute(state, provider_id, args.reason)
    save_route_state(state, args.route_state)
    print(json.dumps({"provider_id": provider_id, "disputed": True, "reason": args.reason}, indent=2))
    return 0


def _cmd_chain_deploy_testnet(args: argparse.Namespace) -> int:
    try:
        deployment = deploy_testnet(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            treasury=treasury_arg(args.treasury),
            chain_id=args.chain_id,
            solc=args.solc,
            timeout=args.timeout,
        )
        save_deployment(Path(args.deployment), deployment)
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"deployment": deployment.to_dict(), "saved_to": args.deployment}, indent=2))
    return 0


def _cmd_chain_deploy_myco_testnet(args: argparse.Namespace) -> int:
    try:
        private_key = private_key_arg(args.private_key)
        rpc_url = rpc_url_arg(args.rpc_url)
        deployment = deploy_myco_testnet(
            rpc_url=rpc_url,
            private_key=private_key,
            treasury=treasury_arg(args.treasury),
            chain_id=args.chain_id,
            solc=args.solc,
            timeout=args.timeout,
        )
        accept_tx_hash = accept_governance_executor(
            rpc_url=rpc_url,
            private_key=private_key,
            settlement=deployment.settlement,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
        save_myco_deployment(Path(args.deployment), deployment)
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"deployment": deployment.to_dict(), "governance_accept_tx": accept_tx_hash, "saved_to": args.deployment}, indent=2))
    return 0


def _cmd_chain_info(args: argparse.Namespace) -> int:
    try:
        deployment = load_deployment(Path(args.deployment))
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"deployment": deployment.to_dict()}, indent=2))
    return 0


def _cmd_chain_myco_info(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"deployment": deployment.to_dict()}, indent=2))
    return 0


def _cmd_chain_mint_test_usdc(args: argparse.Namespace) -> int:
    try:
        deployment = load_deployment(Path(args.deployment))
        tx_hash = mint_test_usdc(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            token_address=args.token or deployment.test_usdc,
            to_address=args.to,
            amount_usdc=args.amount_usdc,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"tx_hash": tx_hash, "amount_units": stablecoin_amount(args.amount_usdc)}, indent=2))
    return 0


def _cmd_chain_approve_usdc(args: argparse.Namespace) -> int:
    try:
        deployment = load_deployment(Path(args.deployment))
        tx_hash = approve_usdc(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            token_address=args.token or deployment.test_usdc,
            spender=args.spender or deployment.settlement,
            amount_usdc=args.amount_usdc,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"tx_hash": tx_hash, "amount_units": stablecoin_amount(args.amount_usdc)}, indent=2))
    return 0


def _cmd_chain_deposit_prepaid(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = deposit_prepaid(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            amount_usdc=args.amount_usdc,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"tx_hash": tx_hash, "amount_units": stablecoin_amount(args.amount_usdc)}, indent=2))
    return 0


def _cmd_chain_withdraw_prepaid(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = withdraw_prepaid(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            amount_usdc=args.amount_usdc,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"tx_hash": tx_hash, "amount_units": stablecoin_amount(args.amount_usdc)}, indent=2))
    return 0


def _cmd_chain_prepaid_balance(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        units = prepaid_balance(
            rpc_url=rpc_url_arg(args.rpc_url),
            settlement=args.settlement or deployment.settlement,
            account=args.account,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"account": args.account, "balance_units": units, "balance_usdc": f"{units / 1_000_000:.6f}"}, indent=2))
    return 0


def _cmd_chain_set_settlement_delegate(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = set_settlement_delegate(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            delegate=args.delegate,
            allowed=args.allowed == "true",
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "delegate": args.delegate, "allowed": args.allowed == "true"}, indent=2))
    return 0


def _cmd_chain_set_treasury(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = set_treasury(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            treasury=args.treasury,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "treasury": args.treasury}, indent=2))
    return 0


def _cmd_chain_set_operator(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        allowed = args.allowed == "true"
        tx_hash = set_operator(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            operator=args.operator,
            allowed=allowed,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "operator": args.operator, "allowed": allowed}, indent=2))
    return 0


def _cmd_chain_set_governance_executor(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = set_governance_executor(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            next_executor=args.executor,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "executor": args.executor}, indent=2))
    return 0


def _cmd_chain_accept_governance_executor(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = accept_governance_executor(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "accepted": True}, indent=2))
    return 0


def _cmd_chain_set_governance_delay(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = set_governance_delay(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            delay_seconds=args.delay_seconds,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "delay_seconds": args.delay_seconds}, indent=2))
    return 0


def _cmd_chain_schedule_governance_action(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = schedule_governance_action(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            action_hash=args.action_hash,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "action_hash": args.action_hash}, indent=2))
    return 0


def _cmd_chain_governance_action_hash(args: argparse.Namespace) -> int:
    try:
        action_hash = governance_action_hash(
            args.action,
            treasury=args.treasury,
            operator=args.operator,
            executor=args.executor,
            allowed=args.allowed,
            enabled=args.enabled,
            delay_seconds=args.delay_seconds,
            epoch_seconds=args.epoch_seconds,
            epoch_emission_myco=args.epoch_emission_myco,
            halving_interval_epochs=args.halving_interval_epochs,
            max_consumer_rebate_bps=args.max_consumer_rebate_bps,
            channel_hash=args.channel_hash,
            input_per_1k_usdc=args.input_per_1k_usdc,
            output_per_1k_usdc=args.output_per_1k_usdc,
            minimum_fee_usdc=args.minimum_fee_usdc,
            provider_bps=args.provider_bps,
            relay_bps=args.relay_bps,
            pool_bps=args.pool_bps,
            treasury_bps=args.treasury_bps,
            provider_reward_bps=args.provider_reward_bps,
            consumer_reward_bps=args.consumer_reward_bps,
            reward_per_treasury_unit=args.reward_per_treasury_unit,
            active=args.active,
            amount_myco=args.amount_myco,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"action": args.action, "action_hash": action_hash}, indent=2))
    return 0


def _cmd_chain_set_economics(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = set_economics(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            epoch_seconds=args.epoch_seconds,
            epoch_emission_myco=args.epoch_emission_myco,
            halving_interval_epochs=args.halving_interval_epochs,
            max_consumer_rebate_bps=args.max_consumer_rebate_bps,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "tx_hash": tx_hash,
                "epoch_seconds": args.epoch_seconds,
                "epoch_emission_myco": args.epoch_emission_myco,
                "halving_interval_epochs": args.halving_interval_epochs,
                "max_consumer_rebate_bps": args.max_consumer_rebate_bps,
            },
            indent=2,
        )
    )
    return 0


def _cmd_chain_set_channel(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = set_channel(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            channel_hash=args.channel_hash,
            input_per_1k_usdc=args.input_per_1k_usdc,
            output_per_1k_usdc=args.output_per_1k_usdc,
            minimum_fee_usdc=args.minimum_fee_usdc,
            provider_bps=args.provider_bps,
            relay_bps=args.relay_bps,
            pool_bps=args.pool_bps,
            treasury_bps=args.treasury_bps,
            provider_reward_bps=args.provider_reward_bps,
            consumer_reward_bps=args.consumer_reward_bps,
            reward_per_treasury_unit=args.reward_per_treasury_unit,
            active=args.active == "true",
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "tx_hash": tx_hash,
                "channel_hash": args.channel_hash,
                "input_per_1k_usdc": args.input_per_1k_usdc,
                "output_per_1k_usdc": args.output_per_1k_usdc,
                "minimum_fee_usdc": args.minimum_fee_usdc,
                "active": args.active == "true",
            },
            indent=2,
        )
    )
    return 0


def _cmd_chain_set_trusted_settlement(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        enabled = args.enabled == "true"
        tx_hash = set_trusted_settlement_enabled(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            enabled=enabled,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "enabled": enabled}, indent=2))
    return 0


def _cmd_chain_treasury_buyback_burn(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        tx_hash = treasury_buyback_burn(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            amount_myco=args.amount_myco,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except ChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tx_hash": tx_hash, "amount_myco": args.amount_myco}, indent=2))
    return 0


def _cmd_chain_settle_receipt(args: argparse.Namespace) -> int:
    try:
        deployment = load_deployment(Path(args.deployment))
        receipt_path = Path(args.receipt_json or args.ledger)
        receipt_index = 0 if args.receipt_json else args.receipt_index
        receipt = load_receipt(receipt_path, index=receipt_index)
        settlement_args = build_receipt_settlement_args(
            receipt,
            consumer=args.consumer_address,
            provider=args.provider_address,
            relay=args.relay_address,
            pool=args.pool_address,
            channel_hash=args.channel_hash,
        )
        tx_hash = settle_receipt(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=private_key_arg(args.private_key),
            settlement=args.settlement or deployment.settlement,
            settlement_args=settlement_args,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
    except (ChainError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "tx_hash": tx_hash,
                "receipt_hash": settlement_args.receipt_hash,
                "input_tokens": settlement_args.input_tokens,
                "output_tokens": settlement_args.output_tokens,
            },
            indent=2,
        )
    )
    return 0


def _cmd_chain_settle_prepaid_receipt(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        receipt_path = Path(args.receipt_json or args.ledger)
        receipt_index = 0 if args.receipt_json else args.receipt_index
        receipt = load_receipt(receipt_path, index=receipt_index)
        settlement_address = args.settlement or deployment.settlement
        operator_private_key = private_key_arg(args.private_key)
        if args.trusted:
            if not args.allow_demo_trusted and os.getenv("MYCOMESH_ALLOW_TRUSTED_SETTLEMENT", "").strip().lower() not in {
                "1",
                "true",
                "yes",
                "on",
            }:
                raise ChainError(
                    "trusted settlement is disabled by default; pass --allow-demo-trusted or set MYCOMESH_ALLOW_TRUSTED_SETTLEMENT=1"
                )
            settlement_args = build_receipt_settlement_args(
                receipt,
                consumer=args.consumer_address,
                provider=args.provider_address,
                relay=args.relay_address,
                pool=args.pool_address,
                channel_hash=args.channel_hash,
                pricing_hash=args.pricing_hash,
                deadline=args.deadline,
                accepted_hash=args.accepted_hash,
            )
            tx_hash = settle_trusted_prepaid_receipt(
                rpc_url=rpc_url_arg(args.rpc_url),
                private_key=operator_private_key,
                settlement=settlement_address,
                settlement_args=settlement_args,
                chain_id=args.chain_id,
                timeout=args.timeout,
            )
        else:
            if not args.consumer_private_key:
                raise ChainError("signed settlement requires --consumer-private-key or pass --trusted for demo mode")
            if not args.provider_private_key:
                raise ChainError("signed settlement requires --provider-private-key or pass --trusted for demo mode")
            signed_args = build_signed_receipt_settlement_args(
                receipt,
                consumer_private_key=args.consumer_private_key,
                provider_private_key=args.provider_private_key,
                operator_private_key=operator_private_key if args.operator_signature else None,
                consumer=args.consumer_address,
                provider=args.provider_address,
                relay=args.relay_address,
                pool=args.pool_address,
                channel_hash=args.channel_hash,
                pricing_hash=args.pricing_hash,
                deadline=args.deadline,
                accepted_hash=args.accepted_hash,
                chain_id=args.chain_id,
                verifying_contract=settlement_address,
            )
            settlement_args = signed_args.receipt
            tx_hash = settle_signed_prepaid_receipt(
                rpc_url=rpc_url_arg(args.rpc_url),
                private_key=operator_private_key,
                settlement=settlement_address,
                settlement_args=signed_args,
                chain_id=args.chain_id,
                timeout=args.timeout,
            )
        _record_settled_receipt(args.route_state, receipt)
    except (ChainError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "tx_hash": tx_hash,
                "receipt_hash": settlement_args.receipt_hash,
                "input_tokens": settlement_args.input_tokens,
                "output_tokens": settlement_args.output_tokens,
            },
            indent=2,
        )
    )
    return 0


def _cmd_chain_settle_delegated_prepaid_receipt(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        receipt_path = Path(args.receipt_json or args.ledger)
        receipt_index = 0 if args.receipt_json else args.receipt_index
        receipt = load_receipt(receipt_path, index=receipt_index)
        settlement_address = args.settlement or deployment.settlement
        operator_private_key = private_key_arg(args.private_key)
        delegate = args.delegate or private_key_to_address(parse_private_key(operator_private_key))
        max_amount = stablecoin_amount(args.max_usdc) if args.max_usdc is not None else _receipt_gross_fee_units(receipt)
        nonce_seed = int(time.time() * 1000)
        consumer_nonce = args.consumer_nonce if args.consumer_nonce is not None else nonce_seed
        provider_nonce = args.provider_nonce if args.provider_nonce is not None else nonce_seed + 1
        common = {
            "receipt": receipt,
            "delegate": delegate,
            "max_amount": max_amount,
            "expires_at": args.expires_at,
            "consumer_nonce": consumer_nonce,
            "provider_nonce": provider_nonce,
            "operator_private_key": operator_private_key if args.operator_signature else None,
            "consumer": args.consumer_address,
            "provider": args.provider_address,
            "relay": args.relay_address,
            "pool": args.pool_address,
            "channel_hash": args.channel_hash,
            "pricing_hash": args.pricing_hash,
            "deadline": args.deadline,
            "accepted_hash": args.accepted_hash,
            "chain_id": args.chain_id,
            "verifying_contract": settlement_address,
        }
        if args.consumer_signature_json or args.provider_signature_json:
            if not args.consumer_signature_json or not args.provider_signature_json:
                raise ChainError("both --consumer-signature-json and --provider-signature-json are required")
            delegated_args = build_delegated_receipt_settlement_args_from_signatures(
                consumer_delegate_signature=evm_signature_from_json(args.consumer_signature_json),
                provider_delegate_signature=evm_signature_from_json(args.provider_signature_json),
                **common,
            )
        else:
            if not args.consumer_delegate_private_key or not args.provider_delegate_private_key:
                raise ChainError(
                    "wallet signatures are required; pass --consumer-signature-json/--provider-signature-json "
                    "or use demo-only --consumer-delegate-private-key/--provider-delegate-private-key"
                )
            delegated_args = build_delegated_receipt_settlement_args(
                consumer_delegate_private_key=args.consumer_delegate_private_key,
                provider_delegate_private_key=args.provider_delegate_private_key,
                **common,
            )
        tx_hash = settle_delegated_prepaid_receipt(
            rpc_url=rpc_url_arg(args.rpc_url),
            private_key=operator_private_key,
            settlement=settlement_address,
            settlement_args=delegated_args,
            chain_id=args.chain_id,
            timeout=args.timeout,
        )
        _record_settled_receipt(args.route_state, receipt)
    except (ChainError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "tx_hash": tx_hash,
                "receipt_hash": delegated_args.receipt.receipt_hash,
                "delegate": delegate,
                "max_amount_units": delegated_args.max_amount,
                "consumer_nonce": delegated_args.consumer_nonce,
                "provider_nonce": delegated_args.provider_nonce,
            },
            indent=2,
        )
    )
    return 0


def _cmd_chain_prepare_delegate_signatures(args: argparse.Namespace) -> int:
    try:
        deployment = load_myco_deployment(Path(args.deployment))
        receipt_path = Path(args.receipt_json or args.ledger)
        receipt_index = 0 if args.receipt_json else args.receipt_index
        receipt = load_receipt(receipt_path, index=receipt_index)
        settlement_address = args.settlement or deployment.settlement
        settlement_args = build_receipt_settlement_args(
            receipt,
            consumer=args.consumer_address,
            provider=args.provider_address,
            relay=args.relay_address,
            pool=args.pool_address,
            channel_hash=args.channel_hash,
            pricing_hash=args.pricing_hash,
            deadline=args.deadline,
            accepted_hash=args.accepted_hash,
        )
        max_amount = stablecoin_amount(args.max_usdc) if args.max_usdc is not None else _receipt_gross_fee_units(receipt)
        chain_id = int(args.chain_id or deployment.chain_id)
        delegate = args.delegate
        consumer_digest = myco_delegate_digest(
            account=settlement_args.consumer,
            delegate=delegate,
            receipt=settlement_args,
            max_amount=max_amount,
            expires_at=args.expires_at,
            nonce=args.consumer_nonce,
            chain_id=chain_id,
            verifying_contract=settlement_address,
        )
        provider_digest = myco_delegate_digest(
            account=settlement_args.provider,
            delegate=delegate,
            receipt=settlement_args,
            max_amount=max_amount,
            expires_at=args.expires_at,
            nonce=args.provider_nonce,
            chain_id=chain_id,
            verifying_contract=settlement_address,
        )
    except (ChainError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "settlement": settlement_address,
                "chain_id": chain_id,
                "delegate": delegate,
                "receipt_hash": settlement_args.receipt_hash,
                "accepted_hash": settlement_args.accepted_hash,
                "max_amount_units": max_amount,
                "expires_at": args.expires_at,
                "consumer": settlement_args.consumer,
                "consumer_nonce": args.consumer_nonce,
                "consumer_digest": "0x" + consumer_digest.hex(),
                "provider": settlement_args.provider,
                "provider_nonce": args.provider_nonce,
                "provider_digest": "0x" + provider_digest.hex(),
            },
            indent=2,
        )
    )
    return 0


def _cmd_chain_prepare_prepaid_batch(args: argparse.Namespace) -> int:
    try:
        receipts = load_receipts(Path(args.ledger), limit=args.limit)
        prepared = [
            build_receipt_settlement_args(
                receipt,
                consumer=args.consumer_address,
                provider=args.provider_address,
                relay=args.relay_address,
                pool=args.pool_address,
                channel_hash=args.channel_hash,
                pricing_hash=args.pricing_hash,
                deadline=args.deadline,
                accepted_hash=args.accepted_hash,
            ).abi_args()
            for receipt in receipts
        ]
    except (ChainError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"count": len(prepared), "receipts": prepared}, indent=2))
    return 0


def _record_settled_receipt(route_state_path: str | None, receipt: dict[str, Any]) -> None:
    if not route_state_path:
        return
    provider_id = str(receipt.get("provider_id") or "")
    if not provider_id:
        return
    state = load_route_state(route_state_path)
    record_route_settlement(state, provider_id)
    save_route_state(state, route_state_path)


def _receipt_gross_fee_units(receipt: dict[str, Any]) -> int:
    pricing = receipt.get("pricing")
    if not isinstance(pricing, dict):
        raise ChainError("receipt pricing is missing; pass --max-usdc for delegated settlement")
    gross_fee = pricing.get("gross_fee")
    if gross_fee is None:
        raise ChainError("receipt pricing.gross_fee is missing; pass --max-usdc for delegated settlement")
    return stablecoin_amount(str(gross_fee))


def create_agent_key(
    path: Path,
    agent_id: str,
    role: str = "worker",
    description: str | None = None,
) -> ManagedKey:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    agent = agents.get(agent_id)
    if agent is None:
        agent = {"keys": [], "role": role}
        if description:
            agent["description"] = description
        agents[agent_id] = agent
    if not isinstance(agent, dict):
        raise ValueError(f"agent {agent_id!r} must be an object")

    keys = agent.setdefault("keys", [])
    if not isinstance(keys, list):
        raise ValueError(f"agent {agent_id!r} keys must be a list")

    key = _new_key()
    keys.append(key)
    _write_agents_document(path, document)
    return ManagedKey(agent_id=agent_id, key=key)


def delete_agent_key(path: Path, agent_id: str, selector: str) -> ManagedKey:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    agent = agents.get(agent_id)
    if not isinstance(agent, dict):
        raise ValueError(f"agent {agent_id!r} not found")
    keys = agent.get("keys")
    if not isinstance(keys, list):
        raise ValueError(f"agent {agent_id!r} keys must be a list")

    matches = [
        key
        for key in keys
        if isinstance(key, str) and _matches_selector(key=key, selector=selector)
    ]
    if not matches:
        raise ValueError(f"no key matched selector {selector!r}")
    if len(matches) > 1:
        fingerprints = ", ".join(key_fingerprint(key) for key in matches)
        raise ValueError(f"selector matched multiple keys: {fingerprints}")

    removed = matches[0]
    keys.remove(removed)
    _write_agents_document(path, document)
    return ManagedKey(agent_id=agent_id, key=removed)


def rotate_agent_key(
    path: Path,
    agent_id: str,
    selector: str,
    role: str = "worker",
    description: str | None = None,
) -> tuple[ManagedKey, ManagedKey]:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    agent = agents.get(agent_id)
    if agent is None:
        raise ValueError(f"agent {agent_id!r} not found")
    if not isinstance(agent, dict):
        raise ValueError(f"agent {agent_id!r} must be an object")
    keys = agent.get("keys")
    if not isinstance(keys, list):
        raise ValueError(f"agent {agent_id!r} keys must be a list")

    matches = [
        key
        for key in keys
        if isinstance(key, str) and _matches_selector(key=key, selector=selector)
    ]
    if not matches:
        raise ValueError(f"no key matched selector {selector!r}")
    if len(matches) > 1:
        fingerprints = ", ".join(key_fingerprint(key) for key in matches)
        raise ValueError(f"selector matched multiple keys: {fingerprints}")

    old_key = matches[0]
    new_key = _new_key()
    keys[keys.index(old_key)] = new_key
    if "role" not in agent:
        agent["role"] = role
    if description and "description" not in agent:
        agent["description"] = description
    _write_agents_document(path, document)
    return ManagedKey(agent_id=agent_id, key=new_key), ManagedKey(agent_id=agent_id, key=old_key)


def list_agent_keys(path: Path, agent_id: str | None = None) -> list[ManagedKey]:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    managed: list[ManagedKey] = []
    for current_agent_id, agent in agents.items():
        if agent_id is not None and current_agent_id != agent_id:
            continue
        if not isinstance(agent, dict):
            continue
        keys = agent.get("keys", [])
        if not isinstance(keys, list):
            continue
        for key in keys:
            if isinstance(key, str):
                managed.append(ManagedKey(agent_id=current_agent_id, key=key))
    return managed


def first_agent_key(path: Path, agent_id: str) -> str:
    keys = list_agent_keys(path, agent_id=agent_id)
    if not keys:
        raise ValueError(f"no keys found for agent {agent_id!r}; run `python -m gateway key create --agent {agent_id}`")
    return keys[0].key


def discover_public_url(run_dir: Path) -> str | None:
    configured = os.getenv("PUBLIC_BASE_URL") or os.getenv("GATEWAY_PUBLIC_URL")
    if configured:
        return configured.rstrip("/")

    if not run_dir.exists():
        return None
    candidates: list[tuple[float, str]] = []
    for log_path in run_dir.glob("cloudflared*.log"):
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = PUBLIC_URL_PATTERN.findall(text)
        if matches:
            candidates.append((log_path.stat().st_mtime, matches[-1]))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1].rstrip("/")


def wait_for_public_url(run_dir: Path, timeout_seconds: float) -> str | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        public_url = discover_public_url(run_dir)
        if public_url:
            return public_url
        time.sleep(0.5)
    return discover_public_url(run_dir)


def codex_auth_exists(codex_home: str | Path) -> bool:
    home = Path(codex_home)
    return any((home / name).exists() for name in ("auth.json", "login.json"))


def codex_login_required(config: Any) -> bool:
    return str(getattr(config, "backend", "")).strip() in {"codex_cli", "codex_app_server"}


def run_codex_login(config: Any, no_device_auth: bool = False) -> int:
    Path(config.codex_home).mkdir(parents=True, exist_ok=True)
    command = [config.codex_command, "login"]
    if not no_device_auth:
        command.append("--device-auth")

    print("Starting Codex login.")
    print("Use the link printed by Codex to sign in with your Codex/OpenAI account.")
    print(f"CODEX_HOME={config.codex_home}")
    try:
        completed = subprocess.run(
            command,
            env={**os.environ, "CODEX_HOME": config.codex_home},
            check=False,
        )
    except FileNotFoundError:
        print(f"Codex command not found: {config.codex_command}", file=sys.stderr)
        return 127
    return completed.returncode


def ensure_agent_key(path: Path, agent_id: str) -> tuple[ManagedKey, bool]:
    keys = list_agent_keys(path, agent_id=agent_id)
    if keys:
        return keys[0], False
    return (
        create_agent_key(
            path=path,
            agent_id=agent_id,
            role="provider",
            description="MycoMesh provider node.",
        ),
        True,
    )


def wait_for_gateway_health(url: str, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            status_code, _ = fetch_health(url, timeout=2.0)
            if 200 <= status_code < 300:
                return True
        except (OSError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.5)
    return False


def _provider_gateway_url(args: argparse.Namespace) -> str:
    return args.gateway_url or f"http://127.0.0.1:{args.gateway_port}/v1"


def _provider_pool_url(value: str | None) -> str | None:
    urls = [item.strip() for item in str(value or "").split(",") if item.strip()]
    if not urls:
        return None
    return ",".join(urls)


def build_provider_process_command(args: argparse.Namespace, gateway_url: str) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "gateway",
        "--agents-file",
        str(Path(args.agents_file)),
    ]
    if args.transport == "relay":
        command.extend(
            [
                "p2p",
                "relay",
                "--relay-host",
                str(args.relay_host),
                "--relay-port",
                str(args.relay_port),
            ]
        )
        _append_option(command, "--relay-public-url", args.relay_public_url)
    else:
        command.extend(
            [
                "p2p",
                "serve",
                "--host",
                str(args.provider_host),
                "--port",
                str(args.provider_port),
                "--advertise-host",
                str(args.advertise_host),
            ]
        )
        _append_repeated_option(command, "--bootstrap", args.bootstrap)

    command.extend(
        [
            "--agent",
            str(args.agent),
            "--channel",
            str(args.channel),
            "--model",
            str(args.model),
            "--gateway-url",
            gateway_url,
            "--identity",
            str(args.identity),
            "--network-profile",
            str(args.network_profile),
            "--pool",
            str(args.pool),
            "--ttl",
            str(args.ttl),
            "--heartbeat-interval",
            str(args.heartbeat_interval),
            "--capacity",
            str(args.capacity),
            "--reserve-input-tokens",
            str(args.reserve_input_tokens),
            "--reserve-output-tokens",
            str(args.reserve_output_tokens),
        ]
    )
    _append_option(command, "--peer-id", args.peer_id)
    _append_repeated_option(command, "--consumer-public-key", args.consumer_public_key)
    _append_option(command, "--payment-address", args.payment_address)
    _append_option(command, "--pricing-config", args.pricing_config)
    _append_option(command, "--pricing-hash", args.pricing_hash)
    if args.allow_any_signed_consumer:
        command.append("--allow-any-signed-consumer")
    if args.allow_unsigned_requests:
        command.append("--allow-unsigned-requests")
    if args.allow_unreserved_requests:
        command.append("--allow-unreserved-requests")
    return command


def start_provider_process(args: argparse.Namespace, run_dir: Path, gateway_url: str) -> RuntimeProcess:
    run_dir.mkdir(parents=True, exist_ok=True)
    port = args.provider_port if args.transport == "direct" else args.relay_port
    pid_path = _pid_path(run_dir, f"provider-{args.transport}", port)
    existing_pid = _read_pid(pid_path)
    log_path = run_dir / f"provider-{args.transport}-{port}.log"
    if existing_pid and _process_running(existing_pid):
        return RuntimeProcess(
            name=f"provider-{args.transport}",
            pid=existing_pid,
            log_path=log_path,
            already_running=True,
        )

    command = build_provider_process_command(args, gateway_url=gateway_url)
    process = _popen_logged(command, log_path)
    _write_pid(pid_path, process.pid)
    return RuntimeProcess(name=f"provider-{args.transport}", pid=process.pid, log_path=log_path, process=process)


def _append_option(command: list[str], flag: str, value: Any) -> None:
    if value is None or value == "":
        return
    command.extend([flag, str(value)])


def _append_repeated_option(command: list[str], flag: str, values: list[str] | None) -> None:
    for value in values or []:
        _append_option(command, flag, value)


def start_gateway(
    host: str,
    port: int,
    run_dir: Path,
    reload: bool = False,
    agents_file: Path | None = None,
) -> RuntimeProcess:
    run_dir.mkdir(parents=True, exist_ok=True)
    pid_path = _pid_path(run_dir, "gateway", port)
    existing_pid = _read_pid(pid_path)
    log_path = run_dir / f"gateway-{port}.log"
    if existing_pid and _process_running(existing_pid):
        return RuntimeProcess(
            name="gateway",
            pid=existing_pid,
            log_path=log_path,
            already_running=True,
        )

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "gateway.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload:
        command.append("--reload")
    env = None
    if agents_file is not None:
        env = {**os.environ, "AGENTS_FILE": str(agents_file)}
    process = _popen_logged(command, log_path, env=env)
    _write_pid(pid_path, process.pid)
    return RuntimeProcess(name="gateway", pid=process.pid, log_path=log_path, process=process)


def start_tunnel(
    host: str,
    port: int,
    run_dir: Path,
    protocol: str | None = None,
) -> RuntimeProcess:
    run_dir.mkdir(parents=True, exist_ok=True)
    pid_path = _pid_path(run_dir, "cloudflared", port)
    existing_pid = _read_pid(pid_path)
    log_path = run_dir / f"cloudflared-{port}.log"
    if existing_pid and _process_running(existing_pid):
        return RuntimeProcess(
            name="cloudflared",
            pid=existing_pid,
            log_path=log_path,
            already_running=True,
        )

    command = [
        "cloudflared",
        "tunnel",
        "--url",
        f"http://{host}:{port}",
    ]
    if protocol:
        command.extend(["--protocol", protocol])
    try:
        process = _popen_logged(command, log_path)
    except FileNotFoundError as exc:
        raise ValueError("cloudflared command not found") from exc
    _write_pid(pid_path, process.pid)
    return RuntimeProcess(name="cloudflared", pid=process.pid, log_path=log_path, process=process)


def stop_managed_process(pid_path: Path) -> bool:
    pid = _read_pid(pid_path)
    if not pid:
        return False
    if not _process_running(pid):
        _remove_pid(pid_path)
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        _remove_pid(pid_path)
        return False

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _process_running(pid):
            _remove_pid(pid_path)
            return True
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    _remove_pid(pid_path)
    return True


def fetch_health(url: str, timeout: float) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def _provider_pool_peer(config: ProviderConfig, addresses: list[str] | None = None, pool_url: str | None = None) -> dict[str, Any]:
    peer_addresses = addresses or [f"tcp://{config.advertise_host}:{config.advertise_port}"]
    peer = {
        "peer_id": config.peer_id,
        "protocol": "mycomesh-p2p/0.2",
        "address": peer_addresses[0],
        "addresses": peer_addresses,
        "channel": config.channel,
        "agent_id": config.agent_id,
        "model": config.model,
        "last_seen": int(time.time()),
    }
    if config.identity is not None:
        peer["public_key"] = config.identity.public_key
    if config.payment_address:
        peer["payment_address"] = config.payment_address
    if config.identity is not None:
        return sign_document(peer, config.identity.private_key, purpose=POOL_REGISTRATION_PURPOSE, audience=pool_url)
    return peer


def _peer_addresses(peer_info: dict[str, Any]) -> list[str]:
    addresses: list[str] = []
    raw_addresses = peer_info.get("addresses")
    if isinstance(raw_addresses, list):
        addresses.extend(str(address).strip() for address in raw_addresses if str(address).strip())
    address = str(peer_info.get("address") or "").strip()
    if address:
        addresses.insert(0, address)
    return list(dict.fromkeys(addresses))


def _split_urls(value: str | None) -> list[str]:
    urls = [item.strip() for item in str(value or "").split(",") if item.strip()]
    return urls or [DEFAULT_POOL_URL]


def _stop_heartbeats(heartbeats: Any) -> None:
    if not heartbeats:
        return
    if not isinstance(heartbeats, list):
        heartbeats = [heartbeats]
    for heartbeat in heartbeats:
        if heartbeat is not None:
            heartbeat.stop()


def join_provider_pools(
    pool_urls: list[str],
    *,
    peer_factory: Any,
    ttl_seconds: int = DEFAULT_NODE_TTL_SECONDS,
    capacity: dict[str, Any] | None = None,
    timeout: float = 5.0,
    on_error: Any = None,
) -> list[dict[str, Any]]:
    joined: list[dict[str, Any]] = []
    for pool_url in pool_urls:
        try:
            response = join_pool(
                pool_url=pool_url,
                peer=peer_factory(pool_url),
                ttl_seconds=ttl_seconds,
                capacity=capacity,
                timeout=timeout,
            )
        except PoolError as exc:
            if on_error is not None:
                on_error(pool_url, exc)
            continue
        joined.append({"pool_url": pool_url, "response": response})
    return joined


def start_provider_pool_heartbeats(
    pool_urls: list[str],
    *,
    peer_factory: Any,
    ttl_seconds: int = DEFAULT_NODE_TTL_SECONDS,
    interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
    capacity: dict[str, Any] | None = None,
    timeout: float = 5.0,
    on_error: Any = None,
) -> list[Any]:
    heartbeats = []
    for pool_url in pool_urls:
        heartbeat = start_pool_heartbeat(
            pool_url=pool_url,
            peer_factory=lambda pool_url=pool_url: peer_factory(pool_url),
            ttl_seconds=ttl_seconds,
            interval_seconds=interval_seconds,
            capacity=capacity,
            timeout=timeout,
            on_error=(lambda exc, pool_url=pool_url: on_error(pool_url, exc)) if on_error is not None else None,
        )
        heartbeats.append(heartbeat)
    return heartbeats


def _pool_post_json(pool_url: str, path: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        pool_url.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise PoolError(f"pool returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise PoolError(f"failed to reach pool: {exc}") from exc
    value = json.loads(body)
    if not isinstance(value, dict):
        raise PoolError("pool response must be a JSON object")
    if value.get("ok") is False:
        raise PoolError(str(value.get("error") or "pool request failed"))
    return value


def discover_peers_from_pools(pool_urls: list[str], channel: str | None = None, timeout: float = 5.0) -> list[dict[str, Any]]:
    peers_by_id: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for pool_url in pool_urls:
        try:
            for peer in discover_peers(pool_url, channel=channel, timeout=timeout):
                peer_id = str(peer.get("peer_id") or "")
                if not peer_id:
                    continue
                merged = dict(peer)
                merged.setdefault("pool_url", pool_url)
                current = peers_by_id.get(peer_id)
                if current is None or int(merged.get("last_seen") or 0) >= int(current.get("last_seen") or 0):
                    peers_by_id[peer_id] = merged
        except PoolError as exc:
            errors.append(f"{pool_url}: {exc}")
    if not peers_by_id and errors:
        raise PoolError("; ".join(errors))
    return list(peers_by_id.values())


def build_bridge_usage(address: str, pool_url: str | None, pricing: dict[str, Any]) -> list[dict[str, Any]]:
    usage: list[dict[str, Any]] = []
    if pool_url:
        pool_amount = str(pricing.get("pool_amount") or "0")
        if Decimal(pool_amount) > 0:
            usage.append(
                {
                    "bridge_id": pool_url,
                    "type": "pool",
                    "units": 1,
                    "amount": pool_amount,
                }
            )
    relay_id = _relay_id_for_address(address)
    if relay_id:
        relay_amount = str(pricing.get("relay_amount") or "0")
        if Decimal(relay_amount) > 0:
            usage.append(
                {
                    "bridge_id": relay_id,
                    "type": "relay",
                    "units": 1,
                    "amount": relay_amount,
                }
            )
    return usage


def _send_infer_to_address(
    address: str,
    channel: str,
    endpoint: str,
    model: str,
    input_value: Any,
    pool_url: str,
    peer_id: str,
    timeout: float,
    identity: NodeIdentity | None = None,
    consumer_id: str | None = None,
    consumer_payment_address: str | None = None,
    provider_payment_address: str | None = None,
    pricing_hash: str | None = None,
    max_fee_units: int | None = None,
    max_output_tokens: int | None = None,
) -> dict[str, Any]:
    request_id = uuid.uuid4().hex
    message: dict[str, Any] = {
        "type": "infer",
        "request_id": request_id,
        "provider_peer_id": peer_id,
        "channel": channel,
        "endpoint": endpoint,
        "model": model,
        "metadata": {
            "pool_url": pool_url,
            "selected_peer_id": peer_id,
            "selected_address": address,
        },
    }
    if max_output_tokens is not None and int(max_output_tokens) > 0:
        message["max_output_tokens"] = int(max_output_tokens)
    if endpoint == "chat" and isinstance(input_value, list):
        message["messages"] = input_value
    else:
        message["input"] = input_value
    if identity is not None:
        if pricing_hash and max_fee_units:
            message["payment_reservation"] = build_payment_reservation(
                request_id=request_id,
                consumer_id=consumer_id or identity.peer_id,
                consumer_payment_address=consumer_payment_address,
                provider_id=peer_id,
                provider_payment_address=provider_payment_address,
                channel=channel,
                pricing_hash=pricing_hash,
                max_fee_units=max_fee_units,
                signer=identity,
            )
        message = sign_document(message, identity.private_key, purpose=INFERENCE_REQUEST_PURPOSE, audience=peer_id)
    if address.startswith("relay://"):
        return send_relay_message(parse_relay_address(address), message, timeout=timeout)
    return send_message(parse_peer_address(address), message, timeout=timeout)


def _channel_pricing_hash(args: argparse.Namespace, pricing_table: dict[str, Any]) -> str:
    return channel_pricing_snapshot(
        pricing_table,
        getattr(args, "channel", DEFAULT_CHANNEL),
        override=getattr(args, "pricing_hash", None),
    ).pricing_hash


def _max_fee_units(args: argparse.Namespace, pricing_table: dict[str, Any]) -> int:
    input_tokens = int(getattr(args, "reserve_input_tokens", None) or os.getenv("MYCOMESH_RESERVE_INPUT_TOKENS", "8000"))
    output_tokens = int(getattr(args, "reserve_output_tokens", None) or os.getenv("MYCOMESH_RESERVE_OUTPUT_TOKENS", "2000"))
    quote = quote_usage(
        getattr(args, "channel", DEFAULT_CHANNEL),
        {"input_tokens": input_tokens, "output_tokens": output_tokens},
        pricing_table=pricing_table,
    )
    multiplier = Decimal(str(getattr(args, "reserve_multiplier", None) or os.getenv("MYCOMESH_RESERVE_MULTIPLIER", "1.25")))
    return max(1, int(Decimal(quote.to_dict()["gross_fee"]) * multiplier * Decimal("1000000")))


def _relay_address_from_control_url(control_url: str, peer_id: str) -> str:
    parsed = urllib.parse.urlparse(control_url)
    if not parsed.hostname:
        raise ValueError("relay control URL must include a host")
    scheme = "relay"
    port = parsed.port or DEFAULT_RELAY_CONTROL_PORT
    return f"{scheme}://{parsed.hostname}:{port}/{peer_id}"


def _relay_id_for_address(address: str) -> str | None:
    if not address.startswith("relay://"):
        return None
    parsed = urllib.parse.urlparse(address)
    if not parsed.hostname:
        return None
    return f"{parsed.hostname}:{parsed.port or DEFAULT_RELAY_CONTROL_PORT}"


def key_fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _new_key() -> str:
    return f"{KEY_PREFIX}_{secrets.token_urlsafe(32)}"


def _matches_selector(key: str, selector: str) -> bool:
    selector = selector.strip()
    return key == selector or key.startswith(selector) or key_fingerprint(key).startswith(selector)


def _load_agents_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"agents": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_agents_document(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _agents_object(document: dict[str, Any]) -> dict[str, Any]:
    raw_agents = document.setdefault("agents", {})
    if not isinstance(raw_agents, dict):
        raise ValueError("agents config must contain an object named 'agents'")
    return raw_agents


def _health_url(base_or_health_url: str | None, public: bool, run_dir: Path, port: int) -> str:
    if base_or_health_url:
        value = base_or_health_url.rstrip("/")
        if value.endswith("/health"):
            return value
        if value.endswith("/v1"):
            value = value[:-3]
        return value.rstrip("/") + "/health"
    if public:
        public_url = discover_public_url(run_dir)
        if not public_url:
            raise ValueError("no public tunnel URL found")
        return public_url.rstrip("/") + "/health"
    return f"http://127.0.0.1:{port}/health"


def _pid_path(run_dir: Path, name: str, port: int) -> Path:
    return run_dir / f"{name}-{port}.pid"


def _read_pid(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _write_pid(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), encoding="utf-8")


def _remove_pid(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _popen_logged(command: list[str], log_path: Path, env: dict[str, str] | None = None) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("ab")
    return subprocess.Popen(
        command,
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        close_fds=True,
        env=env,
    )


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
