from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .billing import BillingStore, units_to_usdc
from .chain import ChainError, keccak256, normalize_address, prepaid_balance, rpc_call


DEFAULT_INDEXER_STATE_PATH = ".codex-run/mycomesh-indexer.json"


@dataclass(frozen=True)
class AccountSyncResult:
    account_id: str
    payment_address: str
    balance_units: int
    balance_usdc: str


@dataclass(frozen=True)
class IndexerSyncResult:
    synced_at: int
    settlement: str
    accounts: list[AccountSyncResult]
    chain_id: int = 0
    from_block: int | None = None
    to_block: int | None = None
    latest_block: int | None = None
    confirmations: int | None = None
    logs_seen: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "synced_at": self.synced_at,
            "settlement": self.settlement,
            "chain_id": self.chain_id,
            "accounts": [asdict(account) for account in self.accounts],
            "from_block": self.from_block,
            "to_block": self.to_block,
            "latest_block": self.latest_block,
            "confirmations": self.confirmations,
            "logs_seen": self.logs_seen,
        }


def sync_prepaid_balances(
    *,
    store: BillingStore,
    rpc_url: str,
    settlement: str,
    accounts: Iterable[str],
    chain_id: int = 0,
    timeout: float = 20.0,
    state_path: str | Path | None = DEFAULT_INDEXER_STATE_PATH,
) -> IndexerSyncResult:
    settlement = normalize_address(settlement)
    synced_accounts: list[AccountSyncResult] = []
    for account_id in accounts:
        account = store.get_by_account(account_id)
        if account is None:
            raise ChainError(f"billing account not found: {account_id}")
        if not account.payment_address:
            raise ChainError(f"billing account has no payment_address: {account_id}")
        balance_units = prepaid_balance(
            rpc_url=rpc_url,
            settlement=settlement,
            account=account.payment_address,
            timeout=timeout,
        )
        updated = store.set_balance(account_id, units_to_usdc(balance_units))
        synced_accounts.append(
            AccountSyncResult(
                account_id=updated.account_id,
                payment_address=updated.payment_address or account.payment_address,
                balance_units=updated.balance_units,
                balance_usdc=updated.balance_usdc,
            )
        )

    latest_block = _rpc_block_number(rpc_url, timeout=timeout)
    result = IndexerSyncResult(
        synced_at=int(time.time()),
        settlement=settlement,
        accounts=synced_accounts,
        chain_id=int(chain_id),
        from_block=latest_block,
        to_block=latest_block,
        latest_block=latest_block,
        confirmations=0,
    )
    store.set_chain_sync_state(
        chain_id=int(chain_id),
        settlement=settlement,
        latest_block=latest_block,
        synced_block=latest_block,
        confirmations=0,
        source="direct",
        synced_at=result.synced_at,
    )
    if state_path is not None:
        path = Path(state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def sync_prepaid_balances_from_events(
    *,
    store: BillingStore,
    rpc_url: str,
    settlement: str,
    accounts: Iterable[str] | None = None,
    chain_id: int = 0,
    confirmations: int = 6,
    lookback_blocks: int = 5000,
    chunk_blocks: int = 1000,
    timeout: float = 20.0,
    state_path: str | Path | None = DEFAULT_INDEXER_STATE_PATH,
) -> IndexerSyncResult:
    settlement = normalize_address(settlement)
    confirmations = max(0, int(confirmations))
    latest_block = _rpc_block_number(rpc_url, timeout=timeout)
    to_block = latest_block - confirmations
    if to_block < 0:
        to_block = 0

    previous = _load_state(state_path)
    previous_settlement = str(previous.get("settlement") or "").lower()
    previous_chain_id = int(previous.get("chain_id") or 0)
    if previous_settlement and previous_settlement != settlement.lower():
        previous = {}
    elif previous_chain_id and previous_chain_id != int(chain_id):
        previous = {}
    previous_block = int(previous.get("last_block") or -1)
    from_block = previous_block + 1 if previous_block >= 0 else max(0, to_block - max(1, int(lookback_blocks)) + 1)
    if from_block > to_block:
        return _write_event_state(
            store=store,
            state_path=state_path,
            chain_id=int(chain_id),
            settlement=settlement,
            synced_accounts=[],
            from_block=from_block,
            to_block=to_block,
            latest_block=latest_block,
            confirmations=confirmations,
            logs_seen=0,
        )

    logs = []
    chunk = max(1, int(chunk_blocks))
    cursor = from_block
    while cursor <= to_block:
        chunk_to = min(to_block, cursor + chunk - 1)
        logs.extend(
            _rpc_get_logs(
                rpc_url,
                settlement=settlement,
                from_block=cursor,
                to_block=chunk_to,
                timeout=timeout,
            )
        )
        cursor = chunk_to + 1
    changed_addresses = _affected_accounts_from_logs(logs)
    local_accounts = store.accounts_by_payment_address()
    selected_account_ids = set(accounts or [])
    for address in changed_addresses:
        account = local_accounts.get(address.lower())
        if account is not None:
            selected_account_ids.add(account.account_id)

    synced_accounts = _sync_account_ids(
        store=store,
        rpc_url=rpc_url,
        settlement=settlement,
        accounts=sorted(selected_account_ids),
        timeout=timeout,
    )
    return _write_event_state(
        store=store,
        state_path=state_path,
        chain_id=int(chain_id),
        settlement=settlement,
        synced_accounts=synced_accounts,
        from_block=from_block,
        to_block=to_block,
        latest_block=latest_block,
        confirmations=confirmations,
        logs_seen=len(logs),
    )


def _sync_account_ids(
    *,
    store: BillingStore,
    rpc_url: str,
    settlement: str,
    accounts: Iterable[str],
    timeout: float,
) -> list[AccountSyncResult]:
    synced_accounts: list[AccountSyncResult] = []
    for account_id in accounts:
        account = store.get_by_account(account_id)
        if account is None:
            raise ChainError(f"billing account not found: {account_id}")
        if not account.payment_address:
            raise ChainError(f"billing account has no payment_address: {account_id}")
        balance_units = prepaid_balance(
            rpc_url=rpc_url,
            settlement=settlement,
            account=account.payment_address,
            timeout=timeout,
        )
        updated = store.set_balance(account_id, units_to_usdc(balance_units))
        synced_accounts.append(
            AccountSyncResult(
                account_id=updated.account_id,
                payment_address=updated.payment_address or account.payment_address,
                balance_units=updated.balance_units,
                balance_usdc=updated.balance_usdc,
            )
        )
    return synced_accounts


def _rpc_block_number(rpc_url: str, timeout: float) -> int:
    result = rpc_call(rpc_url, "eth_blockNumber", [], timeout)
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ChainError(f"unexpected eth_blockNumber response: {result!r}")
    return int(result, 16)


def _rpc_get_logs(
    rpc_url: str,
    *,
    settlement: str,
    from_block: int,
    to_block: int,
    timeout: float,
) -> list[dict[str, object]]:
    result = rpc_call(
        rpc_url,
        "eth_getLogs",
        [
            {
                "address": settlement,
                "fromBlock": hex(max(0, from_block)),
                "toBlock": hex(max(0, to_block)),
                "topics": [[DEPOSITED_TOPIC, WITHDRAWN_TOPIC, RECEIPT_SETTLED_TOPIC]],
            }
        ],
        timeout,
    )
    if not isinstance(result, list):
        raise ChainError(f"unexpected eth_getLogs response: {result!r}")
    return [dict(item) for item in result if isinstance(item, dict)]


def _affected_accounts_from_logs(logs: Iterable[dict[str, object]]) -> set[str]:
    addresses: set[str] = set()
    for log in logs:
        topics = log.get("topics")
        if not isinstance(topics, list) or not topics:
            continue
        topic0 = str(topics[0]).lower()
        if topic0 in {DEPOSITED_TOPIC, WITHDRAWN_TOPIC} and len(topics) > 1:
            addresses.add(_topic_address(str(topics[1])))
        elif topic0 == RECEIPT_SETTLED_TOPIC and len(topics) > 3:
            addresses.add(_topic_address(str(topics[3])))
    return {address for address in addresses if address}


def _topic_address(topic: str) -> str:
    value = topic.lower()
    if not value.startswith("0x") or len(value) != 66:
        return ""
    return "0x" + value[-40:]


def _load_state(state_path: str | Path | None) -> dict[str, object]:
    if state_path is None:
        return {}
    path = Path(state_path)
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _write_event_state(
    *,
    store: BillingStore,
    state_path: str | Path | None,
    chain_id: int,
    settlement: str,
    synced_accounts: list[AccountSyncResult],
    from_block: int,
    to_block: int,
    latest_block: int,
    confirmations: int,
    logs_seen: int,
) -> IndexerSyncResult:
    result = IndexerSyncResult(
        synced_at=int(time.time()),
        settlement=settlement,
        accounts=synced_accounts,
        chain_id=int(chain_id),
        from_block=from_block,
        to_block=to_block,
        latest_block=latest_block,
        confirmations=confirmations,
        logs_seen=logs_seen,
    )
    store.set_chain_sync_state(
        chain_id=int(chain_id),
        settlement=settlement,
        latest_block=latest_block,
        synced_block=to_block,
        confirmations=confirmations,
        source="events",
        synced_at=result.synced_at,
    )
    if state_path is not None:
        payload = result.to_dict()
        payload["last_block"] = to_block
        path = Path(state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _event_topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode("utf-8")).hex()


DEPOSITED_TOPIC = _event_topic("Deposited(address,uint256)")
WITHDRAWN_TOPIC = _event_topic("Withdrawn(address,uint256)")
RECEIPT_SETTLED_TOPIC = _event_topic("ReceiptSettled(bytes32,bytes32,address,address,uint256,uint256,uint256)")
