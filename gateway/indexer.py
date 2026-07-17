from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .billing import BillingError, BillingStore, ChainSyncSuperseded
from .chain import ChainError, keccak256, normalize_address, prepaid_balance, rpc_call


DEFAULT_INDEXER_STATE_PATH = ".codex-run/mycomesh-indexer.json"


class IndexerSyncSuperseded(ChainError):
    pass


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
    synced_block_hash: str | None = None

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
            "synced_block_hash": self.synced_block_hash,
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
    latest_block = _rpc_block_number(rpc_url, timeout=timeout)
    synced_block_hash = _rpc_block_hash(rpc_url, latest_block, timeout=timeout)
    synced_at = int(time.time())
    account_ids = list(dict.fromkeys(str(account_id) for account_id in accounts))
    database_state = store.get_chain_sync_state()
    _invalidate_accounts_if_current(
        store,
        account_ids,
        chain_id=int(chain_id),
        settlement=settlement,
        expected_state=database_state,
    )
    observations = _fetch_account_balances(
        store=store,
        rpc_url=rpc_url,
        settlement=settlement,
        accounts=account_ids,
        timeout=timeout,
        synced_block=latest_block,
    )

    if _rpc_block_hash(rpc_url, latest_block, timeout=timeout) != synced_block_hash:
        _mark_reorg_if_current(
            store,
            chain_id=int(chain_id),
            settlement=settlement,
            expected_state=database_state,
            account_ids=account_ids,
        )
        raise ChainError("chain reorganization detected while synchronizing prepaid balances")
    try:
        synced_accounts = _publish_account_balances(
            store=store,
            observations=observations,
            expected_state=database_state,
            chain_id=int(chain_id),
            settlement=settlement,
            latest_block=latest_block,
            synced_block=latest_block,
            confirmations=0,
            source="direct",
            synced_at=synced_at,
            synced_block_hash=synced_block_hash,
        )
    except IndexerSyncSuperseded:
        raise
    except ChainError:
        _mark_reorg_if_current(
            store,
            chain_id=int(chain_id),
            settlement=settlement,
            expected_state=database_state,
            account_ids=account_ids,
        )
        raise

    result = IndexerSyncResult(
        synced_at=synced_at,
        settlement=settlement,
        accounts=synced_accounts,
        chain_id=int(chain_id),
        from_block=latest_block,
        to_block=latest_block,
        latest_block=latest_block,
        confirmations=0,
        synced_block_hash=synced_block_hash,
    )
    if state_path is not None:
        payload = result.to_dict()
        payload["source"] = "direct"
        _write_state(state_path, payload)
    return result


def sync_prepaid_balances_from_events(
    *,
    store: BillingStore,
    rpc_url: str,
    settlement: str,
    accounts: Iterable[str] | None = None,
    chain_id: int = 0,
    confirmations: int = 6,
    lookback_blocks: int = 100,
    chunk_blocks: int = 100,
    timeout: float = 20.0,
    state_path: str | Path | None = DEFAULT_INDEXER_STATE_PATH,
) -> IndexerSyncResult:
    settlement = normalize_address(settlement)
    requested_confirmations = max(0, int(confirmations))
    latest_block = _rpc_block_number(rpc_url, timeout=timeout)
    to_block = latest_block - requested_confirmations
    if to_block < 0:
        to_block = 0
    confirmations = latest_block - to_block

    database_state = store.get_chain_sync_state()
    recovering_reorg = bool(
        database_state is not None
        and int(database_state.get("chain_id") or 0) == int(chain_id)
        and str(database_state.get("settlement") or "").lower() == settlement.lower()
        and int(database_state.get("reorg_detected") or 0)
    )
    previous: dict[str, object] = {}
    if (
        not recovering_reorg
        and database_state is not None
        and int(database_state.get("chain_id") or 0) == int(chain_id)
        and str(database_state.get("settlement") or "").lower() == settlement.lower()
    ):
        previous = {
            "last_block": int(database_state["synced_block"]),
            "last_block_hash": database_state.get("synced_block_hash"),
            "chain_id": int(database_state["chain_id"]),
            "settlement": str(database_state["settlement"]),
        }
    raw_previous_block = previous.get("last_block")
    if raw_previous_block is None:
        raw_previous_block = previous.get("to_block")
    previous_block = int(raw_previous_block) if raw_previous_block is not None else -1
    establishing_event_source = bool(
        database_state is None or str(database_state.get("source") or "") != "events"
    )
    previous_block_hash = str(previous.get("last_block_hash") or previous.get("synced_block_hash") or "").lower()
    if previous_block >= 0 and previous_block_hash:
        canonical_hash = _rpc_block_hash(rpc_url, previous_block, timeout=timeout)
        if canonical_hash.lower() != previous_block_hash:
            _mark_reorg_if_current(
                store,
                chain_id=int(chain_id),
                settlement=settlement,
                expected_state=database_state,
            )
            raise ChainError("chain reorganization detected at the persisted indexer cursor")
    if previous_block > to_block:
        _mark_reorg_if_current(
            store,
            chain_id=int(chain_id),
            settlement=settlement,
            expected_state=database_state,
        )
        raise ChainError("confirmed chain head moved behind the persisted indexer cursor")
    from_block = previous_block + 1 if previous_block >= 0 else max(0, to_block - max(1, int(lookback_blocks)) + 1)
    synced_block_hash = _rpc_block_hash(rpc_url, to_block, timeout=timeout)
    if from_block > to_block:
        if _rpc_block_hash(rpc_url, to_block, timeout=timeout) != synced_block_hash:
            _mark_reorg_if_current(
                store,
                chain_id=int(chain_id),
                settlement=settlement,
                expected_state=database_state,
            )
            raise ChainError("chain reorganization detected while advancing the event cursor")
        synced_at = int(time.time())
        observations: list[tuple[str, str, int]] = []
        if establishing_event_source or accounts:
            local_accounts = store.accounts_by_payment_address()
            selected_account_ids = set(accounts or [])
            if establishing_event_source:
                selected_account_ids.update(account.account_id for account in local_accounts.values())
            observations = _fetch_account_balances(
                store=store,
                rpc_url=rpc_url,
                settlement=settlement,
                accounts=sorted(selected_account_ids),
                timeout=timeout,
                synced_block=to_block,
            )
        synced_accounts = _publish_account_balances(
            store=store,
            observations=observations,
            expected_state=database_state,
            chain_id=int(chain_id),
            settlement=settlement,
            latest_block=latest_block,
            synced_block=to_block,
            confirmations=confirmations,
            source="events",
            synced_at=synced_at,
            synced_block_hash=synced_block_hash,
            canonical_logs=[],
            settled_receipts=[],
            reconcile_from_block=from_block,
            reconcile_to_block=to_block,
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
            logs_seen=0,
            synced_block_hash=synced_block_hash,
            synced_at=synced_at,
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
    if any(bool(log.get("removed")) for log in logs):
        _mark_reorg_if_current(
            store,
            chain_id=int(chain_id),
            settlement=settlement,
            expected_state=database_state,
        )
        raise ChainError("RPC returned a removed log; chain cache invalidated")
    try:
        canonical_logs = _canonical_chain_logs(
            rpc_url,
            logs,
            timeout=timeout,
            known_block_hashes={to_block: synced_block_hash},
        )
    except ChainError:
        _mark_reorg_if_current(
            store,
            chain_id=int(chain_id),
            settlement=settlement,
            expected_state=database_state,
        )
        raise
    changed_addresses = _affected_accounts_from_logs(logs)
    local_accounts = store.accounts_by_payment_address()
    selected_account_ids = set(accounts or [])
    if recovering_reorg or establishing_event_source:
        selected_account_ids.update(account.account_id for account in local_accounts.values())
    try:
        selected_account_ids.update(
            store.accounts_with_chain_settled_receipts(
                chain_id=int(chain_id),
                settlement=settlement,
                from_block=from_block,
                to_block=to_block,
            )
        )
    except BillingError as exc:
        raise ChainError(str(exc)) from exc
    for address in changed_addresses:
        account = local_accounts.get(address.lower())
        if account is not None:
            selected_account_ids.add(account.account_id)
    _invalidate_accounts_if_current(
        store,
        sorted(selected_account_ids),
        chain_id=int(chain_id),
        settlement=settlement,
        expected_state=database_state,
    )
    settled_receipts = _settled_receipt_events(canonical_logs)
    observations = _fetch_account_balances(
        store=store,
        rpc_url=rpc_url,
        settlement=settlement,
        accounts=sorted(selected_account_ids),
        timeout=timeout,
        synced_block=to_block,
    )
    if _rpc_block_hash(rpc_url, to_block, timeout=timeout) != synced_block_hash:
        _mark_reorg_if_current(
            store,
            chain_id=int(chain_id),
            settlement=settlement,
            expected_state=database_state,
        )
        raise ChainError("chain reorganization detected while synchronizing chain events")
    synced_at = int(time.time())
    try:
        synced_accounts = _publish_account_balances(
            store=store,
            observations=observations,
            expected_state=database_state,
            chain_id=int(chain_id),
            settlement=settlement,
            latest_block=latest_block,
            synced_block=to_block,
            confirmations=confirmations,
            source="events",
            synced_at=synced_at,
            synced_block_hash=synced_block_hash,
            canonical_logs=canonical_logs,
            settled_receipts=settled_receipts,
            reconcile_from_block=from_block,
            reconcile_to_block=to_block,
            reorg_recovery=recovering_reorg,
        )
    except IndexerSyncSuperseded:
        raise
    except ChainError:
        _mark_reorg_if_current(
            store,
            chain_id=int(chain_id),
            settlement=settlement,
            expected_state=database_state,
        )
        raise
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
        synced_block_hash=synced_block_hash,
        synced_at=synced_at,
    )


def _fetch_account_balances(
    *,
    store: BillingStore,
    rpc_url: str,
    settlement: str,
    accounts: Iterable[str],
    timeout: float,
    synced_block: int,
) -> list[tuple[str, str, int]]:
    observations: list[tuple[str, str, int]] = []
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
            block_tag=synced_block,
        )
        observations.append((account.account_id, account.payment_address, balance_units))
    return observations


def _invalidate_accounts_if_current(
    store: BillingStore,
    account_ids: list[str],
    *,
    chain_id: int,
    settlement: str,
    expected_state: dict[str, object] | None,
) -> None:
    try:
        store.invalidate_chain_accounts_if_current(
            account_ids,
            chain_id=chain_id,
            settlement=settlement,
            expected_state=expected_state,
        )
    except ChainSyncSuperseded as exc:
        raise IndexerSyncSuperseded(str(exc)) from exc


def _mark_reorg_if_current(
    store: BillingStore,
    *,
    chain_id: int,
    settlement: str,
    expected_state: dict[str, object] | None,
    account_ids: list[str] | None = None,
) -> None:
    try:
        store.mark_chain_reorg_if_current(
            chain_id=chain_id,
            settlement=settlement,
            expected_state=expected_state,
            account_ids=account_ids,
        )
    except ChainSyncSuperseded as exc:
        raise IndexerSyncSuperseded(str(exc)) from exc


def _publish_account_balances(
    *,
    store: BillingStore,
    observations: list[tuple[str, str, int]],
    expected_state: dict[str, object] | None,
    chain_id: int,
    settlement: str,
    latest_block: int,
    synced_block: int,
    confirmations: int,
    source: str,
    synced_at: int,
    synced_block_hash: str,
    canonical_logs: list[dict[str, object]] | None = None,
    settled_receipts: list[tuple[str, str, int, str | None]] | None = None,
    reconcile_from_block: int | None = None,
    reconcile_to_block: int | None = None,
    reorg_recovery: bool = False,
) -> list[AccountSyncResult]:
    try:
        updated_accounts = store.publish_canonical_chain_balances(
            observations,
            expected_state=expected_state,
            chain_id=chain_id,
            settlement=settlement,
            latest_block=latest_block,
            synced_block=synced_block,
            confirmations=confirmations,
            source=source,
            synced_at=synced_at,
            synced_block_hash=synced_block_hash,
            canonical_logs=canonical_logs,
            settled_receipts=settled_receipts,
            reconcile_from_block=reconcile_from_block,
            reconcile_to_block=reconcile_to_block,
            reorg_recovery=reorg_recovery,
        )
    except ChainSyncSuperseded as exc:
        raise IndexerSyncSuperseded(str(exc)) from exc
    except BillingError as exc:
        raise ChainError(str(exc)) from exc
    return [
        AccountSyncResult(
            account_id=updated.account_id,
            payment_address=updated.payment_address or observations[index][1],
            balance_units=updated.balance_units,
            balance_usdc=updated.balance_usdc,
        )
        for index, updated in enumerate(updated_accounts)
    ]


def _rpc_block_number(rpc_url: str, timeout: float) -> int:
    result = rpc_call(rpc_url, "eth_blockNumber", [], timeout)
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ChainError(f"unexpected eth_blockNumber response: {result!r}")
    return int(result, 16)


def _rpc_block_hash(rpc_url: str, block_number: int, timeout: float) -> str:
    result = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(max(0, int(block_number))), False], timeout)
    if not isinstance(result, dict):
        raise ChainError(f"unexpected eth_getBlockByNumber response: {result!r}")
    block_hash = str(result.get("hash") or "").lower()
    if not block_hash.startswith("0x") or len(block_hash) != 66:
        raise ChainError(f"unexpected block hash response: {block_hash!r}")
    return block_hash


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
                "topics": [sorted(DEPOSITED_TOPICS | {WITHDRAWN_TOPIC} | RECEIPT_SETTLED_TOPICS)],
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
        if topic0 in DEPOSITED_TOPICS | {WITHDRAWN_TOPIC} and len(topics) > 1:
            addresses.add(_topic_address(str(topics[1])))
        elif topic0 in RECEIPT_SETTLED_TOPICS and len(topics) > 3:
            addresses.add(_topic_address(str(topics[3])))
    return {address for address in addresses if address}


def _settled_receipts(logs: Iterable[dict[str, object]]) -> list[tuple[str, str]]:
    return [
        (receipt_hash, consumer)
        for receipt_hash, consumer, _block_number, _reservation_id in _settled_receipt_events(logs)
    ]


def _settled_receipt_events(logs: Iterable[dict[str, object]]) -> list[tuple[str, str, int, str | None]]:
    receipts: list[tuple[str, str, int, str | None]] = []
    seen: set[tuple[str, str, str | None]] = set()
    for log in logs:
        topics = log.get("topics")
        if not isinstance(topics, list) or len(topics) < 4:
            continue
        topic0 = str(topics[0]).lower()
        if topic0 not in RECEIPT_SETTLED_TOPICS:
            continue
        receipt_hash = str(topics[1]).lower()
        consumer = _topic_address(str(topics[3]))
        if not re.fullmatch(r"0x[a-f0-9]{64}", receipt_hash) or not consumer:
            continue
        reservation_id: str | None = None
        if topic0 == RECEIPT_SETTLED_V3_TOPIC:
            reservation_id = str(topics[2]).lower()
            if not re.fullmatch(r"0x[a-f0-9]{64}", reservation_id):
                continue
        try:
            block_number = _rpc_quantity(log.get("blockNumber"))
        except (TypeError, ValueError):
            block_number = -1
        identity = (receipt_hash, consumer, reservation_id)
        if identity not in seen:
            seen.add(identity)
            receipts.append((receipt_hash, consumer, block_number, reservation_id))
    return receipts


def _canonical_chain_logs(
    rpc_url: str,
    logs: Iterable[dict[str, object]],
    *,
    timeout: float,
    known_block_hashes: dict[int, str] | None = None,
) -> list[dict[str, object]]:
    known = {int(number): str(value).lower() for number, value in (known_block_hashes or {}).items()}
    identified: list[tuple[dict[str, object], int, str]] = []
    for log in logs:
        block_hash = str(log.get("blockHash") or "").lower()
        tx_hash = str(log.get("transactionHash") or "").lower()
        if not re.fullmatch(r"0x[a-f0-9]{64}", block_hash):
            continue
        if not re.fullmatch(r"0x[a-f0-9]{64}", tx_hash):
            continue
        try:
            block_number = _rpc_quantity(log.get("blockNumber"))
            _rpc_quantity(log.get("logIndex"))
        except (TypeError, ValueError):
            continue
        previous = known.get(block_number)
        if previous is not None and previous != block_hash:
            raise ChainError(f"log block hash does not match canonical block {block_number}")
        known[block_number] = block_hash
        identified.append((log, block_number, block_hash))
    for block_number, expected_hash in sorted(known.items()):
        if known_block_hashes and block_number in known_block_hashes:
            continue
        if _rpc_block_hash(rpc_url, block_number, timeout=timeout).lower() != expected_hash:
            raise ChainError(f"log block hash does not match canonical block {block_number}")
    return [log for log, _block_number, _block_hash in identified]


def _rpc_quantity(value: object) -> int:
    if isinstance(value, int):
        return value
    raw = str(value or "")
    if raw.startswith("0x"):
        return int(raw, 16)
    return int(raw)


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


def _write_state(state_path: str | Path, payload: dict[str, object]) -> None:
    path = Path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


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
    synced_block_hash: str,
    synced_at: int,
) -> IndexerSyncResult:
    result = IndexerSyncResult(
        synced_at=int(synced_at),
        settlement=settlement,
        accounts=synced_accounts,
        chain_id=int(chain_id),
        from_block=from_block,
        to_block=to_block,
        latest_block=latest_block,
        confirmations=confirmations,
        logs_seen=logs_seen,
        synced_block_hash=synced_block_hash,
    )
    if state_path is not None:
        payload = result.to_dict()
        payload["source"] = "events"
        payload["last_block"] = to_block
        payload["last_block_hash"] = synced_block_hash
        _write_state(state_path, payload)
    return result


def _event_topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode("utf-8")).hex()


DEPOSITED_V2_TOPIC = _event_topic("Deposited(address,uint256)")
DEPOSITED_V3_TOPIC = _event_topic("Deposited(address,uint256,uint256)")
DEPOSITED_TOPIC = DEPOSITED_V2_TOPIC
DEPOSITED_TOPICS = frozenset({DEPOSITED_V2_TOPIC, DEPOSITED_V3_TOPIC})
WITHDRAWN_TOPIC = _event_topic("Withdrawn(address,uint256)")
RECEIPT_SETTLED_V2_TOPIC = _event_topic(
    "ReceiptSettled(bytes32,bytes32,address,address,uint256,uint256,uint256)"
)
RECEIPT_SETTLED_V3_TOPIC = _event_topic("ReceiptSettled(bytes32,bytes32,address,address,uint256)")
RECEIPT_SETTLED_TOPIC = RECEIPT_SETTLED_V2_TOPIC
RECEIPT_SETTLED_TOPICS = frozenset({RECEIPT_SETTLED_V2_TOPIC, RECEIPT_SETTLED_V3_TOPIC})
