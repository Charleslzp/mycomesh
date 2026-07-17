from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .billing import BillingError, BillingStore
from .chain import ChainError, load_active_myco_deployment, normalize_address


class IndexerServiceError(RuntimeError):
    pass


MIN_TESTNET_CONFIRMATIONS = 6
MAX_TESTNET_CONFIRMATIONS = 64
MAX_CHAIN_SYNC_AGE_SECONDS = 300
MAX_CHAIN_SYNC_BLOCK_LAG = 64


@dataclass(frozen=True)
class IndexerServiceConfig:
    deployment: str
    state_path: str
    database: str
    rpc_url: str
    chain_id: int
    settlement: str
    confirmations: int
    lookback_blocks: int
    chunk_blocks: int
    rpc_timeout: float
    interval_seconds: int
    retry_seconds: int
    max_age_seconds: int
    max_block_lag: int


def load_config(env: Mapping[str, str] | None = None) -> IndexerServiceConfig:
    values = os.environ if env is None else env
    if values.get("MYCOMESH_NETWORK_PROFILE", "").strip() != "testnet":
        raise IndexerServiceError("balance indexer requires MYCOMESH_NETWORK_PROFILE=testnet")
    if values.get("MYCOMESH_SETTLEMENT_VERSION", "").strip() != "3":
        raise IndexerServiceError("balance indexer requires MYCOMESH_SETTLEMENT_VERSION=3")
    if values.get("MYCOMESH_BILLING_MODE", "").strip() != "onchain-prepaid":
        raise IndexerServiceError("balance indexer requires MYCOMESH_BILLING_MODE=onchain-prepaid")
    if values.get("MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE", "").strip().lower() not in {"1", "true", "yes", "on"}:
        raise IndexerServiceError("balance indexer requires MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE=1")

    deployment_path = values.get("MYCO_DEPLOYMENT", "").strip()
    if not deployment_path:
        raise IndexerServiceError("MYCO_DEPLOYMENT is required")
    rpc_url = (values.get("ETH_RPC_URL") or values.get("MYCOMESH_SETTLEMENT_RPC_URL") or "").strip()
    if not rpc_url:
        raise IndexerServiceError("ETH_RPC_URL or MYCOMESH_SETTLEMENT_RPC_URL is required")
    database = values.get("MYCOMESH_BILLING_DB", "").strip()
    if not database:
        raise IndexerServiceError("MYCOMESH_BILLING_DB is required")
    if "change-me-database-password" in database:
        raise IndexerServiceError("replace the default password in MYCOMESH_BILLING_DB")

    try:
        deployment = load_active_myco_deployment(
            deployment_path,
            settlement_version=3,
            env=values,
        )
        chain_id = int(values.get("ETH_CHAIN_ID") or deployment.chain_id)
        settlement = normalize_address(values.get("MYCO_SETTLEMENT") or deployment.settlement)
        confirmations = _positive_int(values, "MYCOMESH_CHAIN_SYNC_MIN_CONFIRMATIONS", 6)
        lookback_blocks = _positive_int(values, "MYCOMESH_INDEXER_LOOKBACK_BLOCKS", 100)
        chunk_blocks = _positive_int(values, "MYCOMESH_INDEXER_CHUNK_BLOCKS", 100)
        rpc_timeout = _positive_float(values, "MYCOMESH_INDEXER_RPC_TIMEOUT_SECONDS", 20.0)
        interval_seconds = _positive_int(values, "MYCOMESH_INDEXER_SYNC_INTERVAL_SECONDS", 30)
        retry_seconds = _positive_int(values, "MYCOMESH_INDEXER_RETRY_SECONDS", 10)
        max_age_seconds = _positive_int(values, "MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS", 120)
        max_block_lag = _nonnegative_int(values, "MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG", 12)
    except (ChainError, TypeError, ValueError) as exc:
        raise IndexerServiceError(str(exc)) from exc
    if chain_id != int(deployment.chain_id):
        raise IndexerServiceError("ETH_CHAIN_ID does not match the active V3 deployment")
    if settlement != normalize_address(deployment.settlement):
        raise IndexerServiceError("MYCO_SETTLEMENT does not match the active V3 deployment")
    if not MIN_TESTNET_CONFIRMATIONS <= confirmations <= MAX_TESTNET_CONFIRMATIONS:
        raise IndexerServiceError(
            "MYCOMESH_CHAIN_SYNC_MIN_CONFIRMATIONS must be between "
            f"{MIN_TESTNET_CONFIRMATIONS} and {MAX_TESTNET_CONFIRMATIONS} on testnet"
        )
    if max_age_seconds < interval_seconds * 2:
        raise IndexerServiceError(
            "MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS must cover at least two sync intervals"
        )
    if max_age_seconds > MAX_CHAIN_SYNC_AGE_SECONDS:
        raise IndexerServiceError(
            f"MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS must not exceed {MAX_CHAIN_SYNC_AGE_SECONDS} on testnet"
        )
    if max_block_lag < confirmations:
        raise IndexerServiceError("MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG must be at least the confirmation count")
    if max_block_lag > MAX_CHAIN_SYNC_BLOCK_LAG:
        raise IndexerServiceError(
            f"MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG must not exceed {MAX_CHAIN_SYNC_BLOCK_LAG} on testnet"
        )

    return IndexerServiceConfig(
        deployment=deployment_path,
        state_path=values.get("MYCOMESH_INDEXER_STATE", "/data/mycomesh-indexer.json").strip()
        or "/data/mycomesh-indexer.json",
        database=database,
        rpc_url=rpc_url,
        chain_id=chain_id,
        settlement=settlement,
        confirmations=confirmations,
        lookback_blocks=lookback_blocks,
        chunk_blocks=chunk_blocks,
        rpc_timeout=rpc_timeout,
        interval_seconds=interval_seconds,
        retry_seconds=retry_seconds,
        max_age_seconds=max_age_seconds,
        max_block_lag=max_block_lag,
    )


def sync_command(config: IndexerServiceConfig, account_ids: Sequence[str]) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "gateway",
        "mycomesh",
        "indexer",
        "sync",
        "--deployment",
        config.deployment,
        "--settlement",
        config.settlement,
        "--chain-id",
        str(config.chain_id),
        "--events",
        "--confirmations",
        str(config.confirmations),
        "--lookback-blocks",
        str(config.lookback_blocks),
        "--chunk-blocks",
        str(config.chunk_blocks),
        "--state",
        config.state_path,
        "--timeout",
        str(config.rpc_timeout),
    ]
    for account_id in dict.fromkeys(str(value) for value in account_ids if value):
        command.extend(("--account", account_id))
    return command


def run_forever(env: Mapping[str, str] | None = None) -> int:
    values = dict(os.environ if env is None else env)
    config = load_config(values)
    child_env = dict(values)
    child_env["ETH_RPC_URL"] = config.rpc_url
    child_env["MYCOMESH_BILLING_DB"] = config.database
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    while not stop.is_set():
        try:
            accounts = BillingStore(config.database).accounts_by_payment_address().values()
            account_ids = sorted(account.account_id for account in accounts if account.status == "active")
            return_code = _run_sync_process(sync_command(config, account_ids), child_env, stop)
        except (BillingError, OSError, ValueError) as exc:
            print(f"balance indexer sync failed: {exc}", file=sys.stderr, flush=True)
            return_code = 1
        if stop.is_set():
            break
        delay = config.interval_seconds if return_code == 0 else config.retry_seconds
        if return_code != 0:
            print(f"balance indexer sync exited with status {return_code}; retrying", file=sys.stderr, flush=True)
        stop.wait(delay)
    return 0


def _run_sync_process(command: Sequence[str], env: Mapping[str, str], stop: threading.Event) -> int:
    process = subprocess.Popen(
        list(command),
        env=dict(env),
        stdout=subprocess.DEVNULL,
    )
    while process.poll() is None:
        if stop.wait(0.25):
            process.terminate()
            try:
                return process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait(timeout=5)
    return int(process.returncode or 0)


def check_cache_health(env: Mapping[str, str] | None = None) -> dict[str, object]:
    config = load_config(env)
    try:
        current = BillingStore(config.database).require_fresh_chain_sync(
            chain_id=config.chain_id,
            settlement=config.settlement,
            max_age_seconds=config.max_age_seconds,
            max_block_lag=config.max_block_lag,
            min_confirmations=config.confirmations,
        )
    except BillingError as exc:
        raise IndexerServiceError(str(exc)) from exc
    return {
        "ok": True,
        "service": "mycomesh-balance-cache",
        "chain_id": config.chain_id,
        "settlement": config.settlement,
        "synced_block": int(current["synced_block"]),
        "synced_at": int(current["synced_at"]),
    }


def check_health(env: Mapping[str, str] | None = None) -> dict[str, object]:
    config = load_config(env)
    try:
        state = json.loads(Path(config.state_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IndexerServiceError(f"indexer state is unavailable: {exc}") from exc
    if not isinstance(state, dict) or state.get("source") != "events":
        raise IndexerServiceError("indexer state is not an event cursor")
    try:
        if int(state.get("chain_id", -1)) != config.chain_id:
            raise IndexerServiceError("indexer state chain_id mismatch")
        if normalize_address(str(state.get("settlement") or "")) != config.settlement:
            raise IndexerServiceError("indexer state settlement mismatch")
        if int(state.get("confirmations", -1)) < config.confirmations:
            raise IndexerServiceError("indexer state has insufficient confirmations")
        synced_block = int(state.get("to_block", -1))
        latest_block = int(state.get("latest_block", -1))
        if synced_block < 0 or latest_block < synced_block:
            raise IndexerServiceError("indexer state has an invalid block cursor")
        if latest_block - synced_block > config.max_block_lag:
            raise IndexerServiceError("indexer state block lag exceeded")
        state_hash = str(state.get("synced_block_hash") or "")
        if not state_hash.startswith("0x") or len(state_hash) != 66:
            raise IndexerServiceError("indexer state is missing its confirmed block hash")
        state_synced_at = int(state.get("synced_at", 0))
    except (ChainError, TypeError, ValueError) as exc:
        raise IndexerServiceError(str(exc)) from exc

    current = check_cache_health(env)
    if int(current.get("synced_at", 0)) < state_synced_at:
        raise IndexerServiceError("billing cache is older than the persisted event cursor")
    return {
        "ok": True,
        "service": "mycomesh-balance-indexer",
        "chain_id": config.chain_id,
        "settlement": config.settlement,
        "synced_block": int(current["synced_block"]),
    }


def _positive_int(values: Mapping[str, str], name: str, default: int) -> int:
    value = int(values.get(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _nonnegative_int(values: Mapping[str, str], name: str, default: int) -> int:
    value = int(values.get(name, str(default)))
    if value < 0:
        raise ValueError(f"{name} must be nonnegative")
    return value


def _positive_float(values: Mapping[str, str], name: str, default: float) -> float:
    value = float(values.get(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    command = list(argv if argv is not None else sys.argv[1:])
    if command == ["run"]:
        try:
            return run_forever()
        except IndexerServiceError as exc:
            print(f"balance indexer preflight failed: {exc}", file=sys.stderr)
            return 64
    if command == ["health"]:
        try:
            print(json.dumps(check_health(), sort_keys=True))
            return 0
        except IndexerServiceError as exc:
            print(f"balance indexer unhealthy: {exc}", file=sys.stderr)
            return 1
    if command == ["cache-health"]:
        try:
            print(json.dumps(check_cache_health(), sort_keys=True))
            return 0
        except IndexerServiceError as exc:
            print(f"balance cache unhealthy: {exc}", file=sys.stderr)
            return 1
    print("usage: python -m gateway.indexer_service {run|health|cache-health}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
