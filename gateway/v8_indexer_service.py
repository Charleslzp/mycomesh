from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .chain import ChainError, abi_encode_arg, keccak256, normalize_address, normalize_bytes32, rpc_call
from .chain_v8 import load_deployment, verify_signed_receipt


logger = logging.getLogger(__name__)

RECEIPT_EVENT_SIGNATURE = "ReceiptSettled(bytes32,bytes32,address,address,address,address,uint256)"
RECEIPT_EVENT_TOPIC = "0x" + keccak256(RECEIPT_EVENT_SIGNATURE.encode("ascii")).hex()
DEFAULT_DATABASE = "/data/v8-receipts.sqlite3"
DEFAULT_OUTBOX_DATABASE = "/relay-data/relay-settlement.sqlite3"
DEFAULT_DEPLOYMENT = "/app/deployments/sepolia-myco-v8.json"
HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")


class V8IndexerError(RuntimeError):
    pass


@dataclass(frozen=True)
class IndexerConfig:
    rpc_url: str
    chain_id: int
    settlement: str
    deployment_block: int
    database: str = DEFAULT_DATABASE
    outbox_database: str = DEFAULT_OUTBOX_DATABASE
    confirmations: int = 6
    chunk_blocks: int = 2_000
    rpc_timeout: float = 30.0
    interval_seconds: float = 15.0
    retry_seconds: float = 5.0
    reorg_blocks: int = 256
    host: str = "0.0.0.0"
    port: int = 9910
    cors_origins: tuple[str, ...] = (
        "https://mycomesh.xyz",
        "https://app.mycomesh.xyz",
        "http://127.0.0.1:8110",
        "http://localhost:8110",
    )


@dataclass(frozen=True)
class IndexedReceipt:
    settlement_key: str
    request_id: str
    owner: str
    provider: str
    provider_signer: str
    relay: str
    actual_fee_units: str
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int
    block_timestamp: int
    input_tokens: int | None = None
    output_tokens: int | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["enriched"] = self.input_tokens is not None and self.output_tokens is not None
        return value


@dataclass(frozen=True)
class IndexerCursor:
    block_number: int
    block_hash: str
    updated_at: int


def load_config(env: Mapping[str, str] | None = None) -> IndexerConfig:
    values = os.environ if env is None else env
    deployment_path = values.get("MYCOMESH_V8_INDEXER_DEPLOYMENT", DEFAULT_DEPLOYMENT).strip()
    try:
        deployment = load_deployment(Path(deployment_path))
        deployment_block = int(deployment.deployment_block or 0)
        if deployment_block <= 0:
            raise V8IndexerError("V8 deployment block is required")
        rpc_url = (
            values.get("MYCOMESH_V8_INDEXER_RPC_URL")
            or values.get("MYCOMESH_RELAY_SETTLEMENT_RPC_URL")
            or ""
        ).strip()
        if not rpc_url:
            raise V8IndexerError("MYCOMESH_V8_INDEXER_RPC_URL is required")
        chain_id = _positive_int(values, "MYCOMESH_V8_INDEXER_CHAIN_ID", int(deployment.chain_id))
        settlement = normalize_address(
            values.get("MYCOMESH_V8_INDEXER_SETTLEMENT", deployment.settlement)
        )
        if chain_id != int(deployment.chain_id):
            raise V8IndexerError("indexer chain ID does not match the V8 deployment")
        if settlement != normalize_address(deployment.settlement):
            raise V8IndexerError("indexer settlement address does not match the V8 deployment")
        confirmations = _nonnegative_int(values, "MYCOMESH_V8_INDEXER_CONFIRMATIONS", 6)
        if confirmations > 64:
            raise V8IndexerError("indexer confirmations must not exceed 64")
        origins = tuple(
            dict.fromkeys(
                origin.strip()
                for origin in values.get(
                    "MYCOMESH_V8_INDEXER_CORS_ALLOWED_ORIGINS",
                    "https://mycomesh.xyz,https://app.mycomesh.xyz,http://127.0.0.1:8110,http://localhost:8110",
                ).split(",")
                if origin.strip()
            )
        )
        return IndexerConfig(
            rpc_url=rpc_url,
            chain_id=chain_id,
            settlement=settlement,
            deployment_block=deployment_block,
            database=values.get("MYCOMESH_V8_INDEXER_DB", DEFAULT_DATABASE).strip() or DEFAULT_DATABASE,
            outbox_database=values.get(
                "MYCOMESH_V8_INDEXER_RELAY_OUTBOX", DEFAULT_OUTBOX_DATABASE
            ).strip(),
            confirmations=confirmations,
            chunk_blocks=_positive_int(values, "MYCOMESH_V8_INDEXER_CHUNK_BLOCKS", 2_000),
            rpc_timeout=_positive_float(values, "MYCOMESH_V8_INDEXER_RPC_TIMEOUT_SECONDS", 30.0),
            interval_seconds=_positive_float(values, "MYCOMESH_V8_INDEXER_INTERVAL_SECONDS", 15.0),
            retry_seconds=_positive_float(values, "MYCOMESH_V8_INDEXER_RETRY_SECONDS", 5.0),
            reorg_blocks=_positive_int(values, "MYCOMESH_V8_INDEXER_REORG_BLOCKS", 256),
            host=values.get("MYCOMESH_V8_INDEXER_HOST", "0.0.0.0").strip() or "0.0.0.0",
            port=_positive_int(values, "MYCOMESH_V8_INDEXER_PORT", 9910),
            cors_origins=origins,
        )
    except (ChainError, OSError, TypeError, ValueError) as exc:
        raise V8IndexerError(str(exc)) from exc


class ReceiptStore:
    def __init__(self, path: str | Path, *, chain_id: int, settlement: str) -> None:
        self.path = Path(path)
        self.chain_id = int(chain_id)
        self.settlement = normalize_address(settlement)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10.0)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS v8_receipts (
                    settlement_key TEXT PRIMARY KEY,
                    chain_id INTEGER NOT NULL,
                    settlement_contract TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    provider_signer TEXT NOT NULL,
                    relay TEXT NOT NULL,
                    actual_fee_units TEXT NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    block_number INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    transaction_hash TEXT NOT NULL,
                    transaction_index INTEGER NOT NULL,
                    log_index INTEGER NOT NULL,
                    block_timestamp INTEGER NOT NULL,
                    indexed_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_v8_receipts_owner_order
                    ON v8_receipts(owner, block_number DESC, log_index DESC);
                CREATE TABLE IF NOT EXISTS v8_indexer_cursor (
                    chain_id INTEGER NOT NULL,
                    settlement_contract TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(chain_id, settlement_contract)
                );
                """
            )

    def cursor(self) -> IndexerCursor | None:
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT block_number, block_hash, updated_at FROM v8_indexer_cursor "
                "WHERE chain_id=? AND settlement_contract=?",
                (self.chain_id, self.settlement),
            ).fetchone()
        if row is None:
            return None
        return IndexerCursor(int(row["block_number"]), str(row["block_hash"]), int(row["updated_at"]))

    def apply_chunk(self, receipts: Sequence[IndexedReceipt], cursor: IndexerCursor) -> None:
        now = int(time.time())
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany(
                """
                INSERT INTO v8_receipts(
                    settlement_key, chain_id, settlement_contract, request_id, owner,
                    provider, provider_signer, relay, actual_fee_units, input_tokens,
                    output_tokens, block_number, block_hash, transaction_hash,
                    transaction_index, log_index, block_timestamp, indexed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(settlement_key) DO UPDATE SET
                    request_id=excluded.request_id,
                    owner=excluded.owner,
                    provider=excluded.provider,
                    provider_signer=excluded.provider_signer,
                    relay=excluded.relay,
                    actual_fee_units=excluded.actual_fee_units,
                    input_tokens=excluded.input_tokens,
                    output_tokens=excluded.output_tokens,
                    block_number=excluded.block_number,
                    block_hash=excluded.block_hash,
                    transaction_hash=excluded.transaction_hash,
                    transaction_index=excluded.transaction_index,
                    log_index=excluded.log_index,
                    block_timestamp=excluded.block_timestamp,
                    indexed_at=excluded.indexed_at
                """,
                [
                    (
                        item.settlement_key,
                        self.chain_id,
                        self.settlement,
                        item.request_id,
                        item.owner,
                        item.provider,
                        item.provider_signer,
                        item.relay,
                        item.actual_fee_units,
                        item.input_tokens,
                        item.output_tokens,
                        item.block_number,
                        item.block_hash,
                        item.transaction_hash,
                        item.transaction_index,
                        item.log_index,
                        item.block_timestamp,
                        now,
                    )
                    for item in receipts
                ],
            )
            db.execute(
                """
                INSERT INTO v8_indexer_cursor(
                    chain_id, settlement_contract, block_number, block_hash, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, settlement_contract) DO UPDATE SET
                    block_number=excluded.block_number,
                    block_hash=excluded.block_hash,
                    updated_at=excluded.updated_at
                """,
                (self.chain_id, self.settlement, cursor.block_number, cursor.block_hash, cursor.updated_at),
            )
            db.commit()

    def rewind(self, from_block: int, previous: IndexerCursor | None) -> None:
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM v8_receipts WHERE chain_id=? AND settlement_contract=? AND block_number>=?",
                (self.chain_id, self.settlement, int(from_block)),
            )
            db.execute(
                "DELETE FROM v8_indexer_cursor WHERE chain_id=? AND settlement_contract=?",
                (self.chain_id, self.settlement),
            )
            if previous is not None:
                db.execute(
                    "INSERT INTO v8_indexer_cursor(chain_id, settlement_contract, block_number, block_hash, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        self.chain_id,
                        self.settlement,
                        previous.block_number,
                        previous.block_hash,
                        previous.updated_at,
                    ),
                )
            db.commit()

    def unenriched_receipts(self, limit: int = 1_000) -> list[IndexedReceipt]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM v8_receipts WHERE chain_id=? AND settlement_contract=? "
                "AND (input_tokens IS NULL OR output_tokens IS NULL) "
                "ORDER BY block_number DESC, log_index DESC LIMIT ?",
                (self.chain_id, self.settlement, int(limit)),
            ).fetchall()
        return [_indexed_receipt_row(row) for row in rows]

    def update_enrichment(self, receipts: Sequence[IndexedReceipt]) -> int:
        resolved = [
            item for item in receipts if item.input_tokens is not None and item.output_tokens is not None
        ]
        if not resolved:
            return 0
        with self._lock, self._connect() as db:
            db.executemany(
                "UPDATE v8_receipts SET input_tokens=?, output_tokens=?, indexed_at=? "
                "WHERE chain_id=? AND settlement_contract=? AND settlement_key=?",
                [
                    (
                        item.input_tokens,
                        item.output_tokens,
                        int(time.time()),
                        self.chain_id,
                        self.settlement,
                        item.settlement_key,
                    )
                    for item in resolved
                ],
            )
            db.commit()
        return len(resolved)

    def list_receipts(
        self,
        owner: str,
        *,
        limit: int,
        before: tuple[int, int] | None = None,
    ) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
        normalized_owner = normalize_address(owner)
        where = "chain_id=? AND settlement_contract=? AND owner=?"
        params: list[Any] = [self.chain_id, self.settlement, normalized_owner]
        if before is not None:
            where += " AND (block_number<? OR (block_number=? AND log_index<?))"
            params.extend((before[0], before[0], before[1]))
        with self._lock, self._connect() as db:
            rows = db.execute(
                f"SELECT * FROM v8_receipts WHERE {where} "
                "ORDER BY block_number DESC, log_index DESC LIMIT ?",
                (*params, int(limit) + 1),
            ).fetchall()
            summary_rows = db.execute(
                "SELECT actual_fee_units, input_tokens, output_tokens FROM v8_receipts "
                "WHERE chain_id=? AND settlement_contract=? AND owner=?",
                (self.chain_id, self.settlement, normalized_owner),
            )
            count = 0
            fee = 0
            input_tokens = 0
            output_tokens = 0
            enriched = 0
            for item in summary_rows:
                count += 1
                fee += int(item["actual_fee_units"])
                if item["input_tokens"] is not None and item["output_tokens"] is not None:
                    enriched += 1
                    input_tokens += int(item["input_tokens"])
                    output_tokens += int(item["output_tokens"])
        has_more = len(rows) > limit
        selected = rows[:limit]
        items = [_receipt_row(row) for row in selected]
        next_cursor = None
        if has_more and selected:
            last = selected[-1]
            next_cursor = f"{int(last['block_number'])}:{int(last['log_index'])}"
        return items, next_cursor, {
            "receipt_count": count,
            "actual_fee_units": str(fee),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "enriched_receipt_count": enriched,
        }


class V8ReceiptIndexer:
    def __init__(self, config: IndexerConfig, store: ReceiptStore) -> None:
        self.config = config
        self.store = store

    def sync_once(self) -> dict[str, int]:
        chain_id = _rpc_hex_int(
            rpc_call(self.config.rpc_url, "eth_chainId", [], self.config.rpc_timeout),
            "chain ID",
        )
        if chain_id != self.config.chain_id:
            raise V8IndexerError("RPC chain ID does not match the V8 deployment")
        latest = _rpc_hex_int(
            rpc_call(self.config.rpc_url, "eth_blockNumber", [], self.config.rpc_timeout),
            "block number",
        )
        confirmed_head = max(0, latest - self.config.confirmations)
        cursor = self.store.cursor()
        if cursor is not None:
            canonical = self._block(cursor.block_number)
            if cursor.block_number > confirmed_head or canonical["hash"] != cursor.block_hash:
                cursor = self._rewind(cursor)
        next_block = self.config.deployment_block if cursor is None else cursor.block_number + 1
        indexed = 0
        chunks = 0
        while next_block <= confirmed_head:
            to_block = min(confirmed_head, next_block + self.config.chunk_blocks - 1)
            raw_logs = rpc_call(
                self.config.rpc_url,
                "eth_getLogs",
                [
                    {
                        "address": self.config.settlement,
                        "fromBlock": hex(next_block),
                        "toBlock": hex(to_block),
                        "topics": [RECEIPT_EVENT_TOPIC],
                    }
                ],
                self.config.rpc_timeout,
            )
            if not isinstance(raw_logs, list):
                raise V8IndexerError("RPC returned an invalid receipt log list")
            receipts = [decode_receipt_log(item, expected_contract=self.config.settlement) for item in raw_logs]
            block_cache: dict[int, dict[str, Any]] = {}
            for block_number in {item.block_number for item in receipts} | {to_block}:
                block_cache[block_number] = self._block(block_number)
            receipts = [
                replace(item, block_timestamp=int(block_cache[item.block_number]["timestamp"]))
                for item in receipts
            ]
            receipts = enrich_receipts_from_outbox(
                receipts,
                self.config.outbox_database,
                chain_id=self.config.chain_id,
                settlement=self.config.settlement,
            )
            self.store.apply_chunk(
                receipts,
                IndexerCursor(to_block, str(block_cache[to_block]["hash"]), int(time.time())),
            )
            indexed += len(receipts)
            chunks += 1
            next_block = to_block + 1
        missing = self.store.unenriched_receipts()
        enriched = self.store.update_enrichment(
            enrich_receipts_from_outbox(
                missing,
                self.config.outbox_database,
                chain_id=self.config.chain_id,
                settlement=self.config.settlement,
            )
        )
        return {
            "latest_block": latest,
            "confirmed_head": confirmed_head,
            "indexed": indexed,
            "enriched": enriched,
            "chunks": chunks,
        }

    def _block(self, block_number: int) -> dict[str, Any]:
        value = rpc_call(
            self.config.rpc_url,
            "eth_getBlockByNumber",
            [hex(int(block_number)), False],
            self.config.rpc_timeout,
        )
        if not isinstance(value, Mapping):
            raise V8IndexerError(f"RPC returned no block for {block_number}")
        block_hash = _hash(value.get("hash"), "block hash")
        timestamp = _rpc_hex_int(value.get("timestamp"), "block timestamp")
        return {"hash": block_hash, "timestamp": timestamp}

    def _rewind(self, cursor: IndexerCursor) -> IndexerCursor | None:
        from_block = max(self.config.deployment_block, cursor.block_number - self.config.reorg_blocks + 1)
        previous_block = from_block - 1
        previous = None
        if previous_block >= self.config.deployment_block:
            block = self._block(previous_block)
            previous = IndexerCursor(previous_block, str(block["hash"]), int(time.time()))
        self.store.rewind(from_block, previous)
        return previous


class IndexerRuntime:
    def __init__(self, indexer: V8ReceiptIndexer) -> None:
        self.indexer = indexer
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_result: dict[str, int] | None = None
        self.last_error: str | None = None
        self.last_sync_at: int | None = None

    def start(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="v8-receipt-indexer", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=10)

    def health(self) -> dict[str, Any]:
        cursor = self.indexer.store.cursor()
        return {
            "ok": self.thread is not None and self.thread.is_alive(),
            "service": "mycomesh-v8-receipt-indexer",
            "chain_id": self.indexer.config.chain_id,
            "settlement": self.indexer.config.settlement,
            "confirmations": self.indexer.config.confirmations,
            "indexed_block": cursor.block_number if cursor else None,
            "indexed_block_hash": cursor.block_hash if cursor else None,
            "last_sync_at": self.last_sync_at,
            "last_result": self.last_result,
            "last_error": self.last_error,
            "enrichment_available": Path(self.indexer.config.outbox_database).is_file(),
        }

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.last_result = self.indexer.sync_once()
                self.last_error = None
                self.last_sync_at = int(time.time())
                delay = self.indexer.config.interval_seconds
            except Exception as exc:  # The service remains queryable while RPCs recover.
                self.last_error = str(exc)
                logger.exception("V8 receipt indexer sync failed")
                delay = self.indexer.config.retry_seconds
            self.stop_event.wait(delay)


def create_app(
    config: IndexerConfig,
    store: ReceiptStore | None = None,
    runtime: IndexerRuntime | None = None,
    *,
    start_runtime: bool = True,
) -> FastAPI:
    resolved_store = store or ReceiptStore(
        config.database,
        chain_id=config.chain_id,
        settlement=config.settlement,
    )
    resolved_runtime = runtime or IndexerRuntime(V8ReceiptIndexer(config, resolved_store))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Iterator[None]:
        if start_runtime:
            resolved_runtime.start()
        try:
            yield
        finally:
            if start_runtime:
                resolved_runtime.stop()

    app = FastAPI(title="MycoMesh V8 Receipt Indexer", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.cors_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Accept"],
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return resolved_runtime.health()

    @app.get("/v1/receipts")
    def receipts(
        owner: str = Query(...),
        limit: int = Query(50, ge=1, le=100),
        before: str | None = Query(None),
    ) -> dict[str, Any]:
        try:
            normalized_owner = normalize_address(owner)
            page_cursor = _parse_page_cursor(before)
            items, next_cursor, summary = resolved_store.list_receipts(
                normalized_owner,
                limit=limit,
                before=page_cursor,
            )
        except (ChainError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        cursor = resolved_store.cursor()
        return {
            "schema": "mycomesh.indexer.v8.receipts.v1",
            "chain_id": config.chain_id,
            "settlement": config.settlement,
            "owner": normalized_owner,
            "receipts": items,
            "next_cursor": next_cursor,
            "summary": summary,
            "provenance": {
                "event": RECEIPT_EVENT_SIGNATURE,
                "confirmations": config.confirmations,
                "indexed_block": cursor.block_number if cursor else None,
                "token_usage_source": "verified Relay receipt when available",
            },
        }

    return app


def decode_receipt_log(value: Any, *, expected_contract: str) -> IndexedReceipt:
    if not isinstance(value, Mapping):
        raise V8IndexerError("receipt log must be an object")
    if value.get("removed") is True:
        raise V8IndexerError("removed receipt log cannot be indexed")
    if normalize_address(str(value.get("address") or "")) != normalize_address(expected_contract):
        raise V8IndexerError("receipt log contract does not match the deployment")
    topics = value.get("topics")
    if not isinstance(topics, list) or len(topics) != 4:
        raise V8IndexerError("receipt log topics are invalid")
    if str(topics[0]).lower() != RECEIPT_EVENT_TOPIC:
        raise V8IndexerError("receipt log topic does not match ReceiptSettled")
    data = str(value.get("data") or "")
    if not data.startswith("0x") or len(data) != 2 + 4 * 64:
        raise V8IndexerError("receipt log data is invalid")
    words = [data[2 + index * 64 : 2 + (index + 1) * 64] for index in range(4)]
    block_hash = _hash(value.get("blockHash"), "block hash")
    return IndexedReceipt(
        settlement_key=normalize_bytes32(str(topics[1])),
        request_id=normalize_bytes32(str(topics[2])),
        owner=_topic_address(topics[3], "owner"),
        provider=_word_address(words[0], "provider"),
        provider_signer=_word_address(words[1], "provider signer"),
        relay=_word_address(words[2], "relay"),
        actual_fee_units=str(int(words[3], 16)),
        block_number=_rpc_hex_int(value.get("blockNumber"), "block number"),
        block_hash=block_hash,
        transaction_hash=_hash(value.get("transactionHash"), "transaction hash"),
        transaction_index=_rpc_hex_int(value.get("transactionIndex"), "transaction index"),
        log_index=_rpc_hex_int(value.get("logIndex"), "log index"),
        block_timestamp=0,
    )


def enrich_receipts_from_outbox(
    receipts: Sequence[IndexedReceipt],
    outbox_path: str | Path,
    *,
    chain_id: int,
    settlement: str,
) -> list[IndexedReceipt]:
    path = Path(outbox_path)
    if not receipts or not path.is_file():
        return list(receipts)
    wanted = {(item.transaction_hash, item.request_id): item for item in receipts}
    enriched: dict[tuple[str, str], tuple[int, int]] = {}
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        rows = db.execute(
            "SELECT tx_hash, payload_json FROM relay_settlement_outbox "
            "WHERE status='confirmed' AND chain_id=? AND settlement_contract=? AND tx_hash IS NOT NULL",
            (int(chain_id), normalize_address(settlement)),
        )
        for row in rows:
            tx_hash = str(row["tx_hash"] or "").lower()
            if not any(key[0] == tx_hash for key in wanted):
                continue
            try:
                payload = json.loads(str(row["payload_json"]))
                signed = payload["signed_receipt"]
                unverified_raw = signed["authorization"]["authorization"]
                request_id = normalize_bytes32(str(unverified_raw["request_id"]))
                event = wanted.get((tx_hash, request_id))
                if event is None:
                    continue
                authorization, receipt, _ = verify_signed_receipt(
                    signed,
                    now=event.block_timestamp,
                )
                raw = authorization["authorization"]
                key = normalize_address(str(raw["key"]))
                settlement_key = "0x" + keccak256(
                    abi_encode_arg(event.owner) + abi_encode_arg(key) + abi_encode_arg(request_id)
                ).hex()
                if settlement_key != event.settlement_key:
                    continue
                if (
                    receipt.provider != event.provider
                    or receipt.provider_signer != event.provider_signer
                    or receipt.relay != event.relay
                    or receipt.actual_fee != int(event.actual_fee_units)
                ):
                    continue
                enriched[(tx_hash, request_id)] = (receipt.input_tokens, receipt.output_tokens)
            except (ChainError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
    except sqlite3.Error as exc:
        logger.warning("Relay receipt enrichment unavailable: %s", exc)
        return list(receipts)
    finally:
        if "db" in locals():
            db.close()
    return [
        replace(item, input_tokens=usage[0], output_tokens=usage[1])
        if (usage := enriched.get((item.transaction_hash, item.request_id))) is not None
        else item
        for item in receipts
    ]


def _receipt_row(row: sqlite3.Row) -> dict[str, Any]:
    item = {
        key: row[key]
        for key in (
            "settlement_key",
            "request_id",
            "owner",
            "provider",
            "provider_signer",
            "relay",
            "actual_fee_units",
            "input_tokens",
            "output_tokens",
            "block_number",
            "block_hash",
            "transaction_hash",
            "transaction_index",
            "log_index",
            "block_timestamp",
        )
    }
    item["enriched"] = item["input_tokens"] is not None and item["output_tokens"] is not None
    return item


def _indexed_receipt_row(row: sqlite3.Row) -> IndexedReceipt:
    return IndexedReceipt(
        settlement_key=str(row["settlement_key"]),
        request_id=str(row["request_id"]),
        owner=str(row["owner"]),
        provider=str(row["provider"]),
        provider_signer=str(row["provider_signer"]),
        relay=str(row["relay"]),
        actual_fee_units=str(row["actual_fee_units"]),
        input_tokens=int(row["input_tokens"]) if row["input_tokens"] is not None else None,
        output_tokens=int(row["output_tokens"]) if row["output_tokens"] is not None else None,
        block_number=int(row["block_number"]),
        block_hash=str(row["block_hash"]),
        transaction_hash=str(row["transaction_hash"]),
        transaction_index=int(row["transaction_index"]),
        log_index=int(row["log_index"]),
        block_timestamp=int(row["block_timestamp"]),
    )


def _parse_page_cursor(value: str | None) -> tuple[int, int] | None:
    if value is None or not value.strip():
        return None
    match = re.fullmatch(r"(\d+):(\d+)", value.strip())
    if match is None:
        raise ValueError("before cursor must use block:log format")
    return int(match.group(1)), int(match.group(2))


def _hash(value: Any, label: str) -> str:
    text = str(value or "")
    if HASH_PATTERN.fullmatch(text) is None:
        raise V8IndexerError(f"invalid {label}")
    return text.lower()


def _topic_address(value: Any, label: str) -> str:
    text = _hash(value, f"{label} topic")[2:]
    return _word_address(text, label)


def _word_address(value: str, label: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdefABCDEF" for character in value):
        raise V8IndexerError(f"invalid {label} word")
    if int(value[:24], 16) != 0:
        raise V8IndexerError(f"invalid {label} padding")
    return normalize_address("0x" + value[-40:])


def _rpc_hex_int(value: Any, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-fA-F]+", value) is None:
        raise V8IndexerError(f"invalid RPC {label}")
    return int(value, 16)


def _positive_int(values: Mapping[str, str], name: str, default: int) -> int:
    value = int(values.get(name, str(default)))
    if value <= 0:
        raise V8IndexerError(f"{name} must be positive")
    return value


def _nonnegative_int(values: Mapping[str, str], name: str, default: int) -> int:
    value = int(values.get(name, str(default)))
    if value < 0:
        raise V8IndexerError(f"{name} must be non-negative")
    return value


def _positive_float(values: Mapping[str, str], name: str, default: float) -> float:
    value = float(values.get(name, str(default)))
    if value <= 0:
        raise V8IndexerError(f"{name} must be positive")
    return value


def main() -> None:
    logging.basicConfig(level=os.environ.get("MYCOMESH_LOG_LEVEL", "INFO"))
    config = load_config()
    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


if __name__ == "__main__":
    main()
