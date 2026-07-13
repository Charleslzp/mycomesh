from __future__ import annotations

import json
import re
import secrets
import hashlib
import sqlite3
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from .database import DatabaseConfigurationError, DatabaseTarget, connect_database


DEFAULT_BILLING_DB = ".codex-run/mycomesh-billing.sqlite3"
API_KEY_PREFIX = "msk"
USDC_SCALE = Decimal("1000000")
EVM_ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
API_KEY_HASH_PATTERN = re.compile(r"^(0x)?[a-fA-F0-9]{64}$")
DEFAULT_KEY_CHALLENGE_CAPACITY = 1024
MAX_KEY_CHALLENGE_CAPACITY = 100_000
DEFAULT_KEY_CHALLENGE_RATE_PER_MINUTE = 120
MAX_KEY_CHALLENGE_RATE_PER_MINUTE = 10_000
DEFAULT_KEY_CHALLENGE_VERIFICATION_ATTEMPTS = 5
MAX_KEY_CHALLENGE_VERIFICATION_ATTEMPTS = 100


class BillingError(RuntimeError):
    pass


class KeyChallengeVerificationInProgress(BillingError):
    """Raised when another process owns the challenge verification lease."""


class KeyChallengeVerificationLimitExceeded(BillingError):
    """Raised after a challenge has exhausted its bounded verification attempts."""


class ChainSyncSuperseded(BillingError):
    """Raised when a chain writer is publishing from an obsolete DB snapshot."""


class ChainBalanceUnavailable(BillingError):
    """Raised when an on-chain cached balance cannot authorize new spend."""


@dataclass(frozen=True)
class ConsumerAccount:
    account_id: str
    api_key: str | None
    balance_units: int
    status: str = "active"
    payment_address: str | None = None
    key_fingerprint: str | None = None
    parent_account_id: str | None = None
    discount_bps: int = 0
    reseller_margin_bps: int = 0
    monthly_quota_units: int = 0
    monthly_used_units: int = 0
    usage_period: str = ""
    usage_tier: str = "standard"
    credential_origin: str | None = None
    credential_network_id: str | None = None
    credential_chain_id: int | None = None
    credential_settlement: str | None = None

    @property
    def balance_usdc(self) -> str:
        return units_to_usdc(self.balance_units)


class BillingStore:
    def __init__(self, path: str | Path = DEFAULT_BILLING_DB) -> None:
        try:
            self._database_target = DatabaseTarget.parse(path)
        except DatabaseConfigurationError as exc:
            raise BillingError(str(exc)) from exc
        self.dialect = self._database_target.dialect
        self.path: str | Path = (
            self._database_target.value
            if self.dialect == "postgresql"
            else Path(self._database_target.value)
        )
        self._init()

    @property
    def is_postgresql(self) -> bool:
        return self.dialect == "postgresql"

    def _connect(self, *, timeout_seconds: float = 5.0) -> Any:
        try:
            return connect_database(self._database_target, timeout_seconds=timeout_seconds)
        except DatabaseConfigurationError as exc:
            raise BillingError(str(exc)) from exc

    def _transaction_lock(
        self,
        conn: Any,
        namespace: str,
        value: str = "",
        *,
        shared: bool = False,
    ) -> None:
        if self.is_postgresql:
            function = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
            conn.execute(
                f"SELECT {function}(hashtext(?))",
                (f"myco-billing:{namespace}:{value}",),
            )

    def _for_update(self, sql: str) -> str:
        return sql + " FOR UPDATE" if self.is_postgresql else sql

    def _init(self) -> None:
        with self._connect(timeout_seconds=30.0) as conn:
            # Schema inspection plus ALTER TABLE must be serialized across workers.
            conn.execute("BEGIN EXCLUSIVE")
            self._transaction_lock(conn, "schema", "v1")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    api_key TEXT UNIQUE,
                    api_key_hash TEXT UNIQUE,
                    key_fingerprint TEXT,
                    balance_units INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'active',
                    payment_address TEXT,
                    parent_account_id TEXT,
                    discount_bps INTEGER NOT NULL DEFAULT 0,
                    reseller_margin_bps INTEGER NOT NULL DEFAULT 0,
                    monthly_quota_units INTEGER NOT NULL DEFAULT 0,
                    monthly_used_units INTEGER NOT NULL DEFAULT 0,
                    usage_period TEXT NOT NULL DEFAULT '',
                    usage_tier TEXT NOT NULL DEFAULT 'standard',
                    credential_origin TEXT,
                    credential_network_id TEXT,
                    credential_chain_id INTEGER,
                    credential_settlement TEXT,
                    created_at INTEGER NOT NULL
                )
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()}
            if "payment_address" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN payment_address TEXT")
            if "api_key_hash" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN api_key_hash TEXT")
            if "key_fingerprint" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN key_fingerprint TEXT")
            if "status" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            if "parent_account_id" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN parent_account_id TEXT")
            if "discount_bps" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN discount_bps INTEGER NOT NULL DEFAULT 0")
            if "reseller_margin_bps" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN reseller_margin_bps INTEGER NOT NULL DEFAULT 0")
            if "monthly_quota_units" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN monthly_quota_units INTEGER NOT NULL DEFAULT 0")
            if "monthly_used_units" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN monthly_used_units INTEGER NOT NULL DEFAULT 0")
            if "usage_period" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN usage_period TEXT NOT NULL DEFAULT ''")
            if "usage_tier" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN usage_tier TEXT NOT NULL DEFAULT 'standard'")
            if "credential_origin" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN credential_origin TEXT")
            if "credential_network_id" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN credential_network_id TEXT")
            if "credential_chain_id" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN credential_chain_id INTEGER")
            if "credential_settlement" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN credential_settlement TEXT")
            rows = conn.execute("SELECT account_id, api_key FROM accounts WHERE api_key_hash IS NULL AND api_key IS NOT NULL").fetchall()
            for row in rows:
                api_key = str(row["api_key"])
                conn.execute(
                    "UPDATE accounts SET api_key_hash = ?, key_fingerprint = ?, api_key = NULL WHERE account_id = ?",
                    (_api_key_hash(api_key), _api_key_fingerprint(api_key), str(row["account_id"])),
                )
            duplicate_address = conn.execute(
                (
                    "SELECT lower(payment_address) AS payment_address FROM accounts "
                    "WHERE payment_address IS NOT NULL AND payment_address != '' "
                    "GROUP BY lower(payment_address) HAVING COUNT(*) > 1 LIMIT 1"
                )
            ).fetchone()
            if duplicate_address is not None:
                raise BillingError(
                    f"duplicate payment_address in billing database: {duplicate_address['payment_address']}"
                )
            conn.execute(
                (
                    "CREATE UNIQUE INDEX IF NOT EXISTS accounts_payment_address_unique_idx "
                    "ON accounts(lower(payment_address)) "
                    "WHERE payment_address IS NOT NULL AND payment_address != ''"
                )
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_events (
                    event_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    reservation_id TEXT,
                    amount_units INTEGER NOT NULL,
                    receipt_json TEXT,
                    receipt_hash TEXT,
                    onchain_reservation_id TEXT,
                    chain_settled_at INTEGER,
                    chain_settled_block INTEGER,
                    chain_settled_chain_id INTEGER,
                    chain_settled_settlement TEXT,
                    created_at INTEGER NOT NULL
                )
                """
            )
            usage_columns = {row["name"] for row in conn.execute("PRAGMA table_info(usage_events)").fetchall()}
            if "reservation_id" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN reservation_id TEXT")
            if "onchain_reservation_id" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN onchain_reservation_id TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_sync_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    chain_id INTEGER NOT NULL,
                    settlement TEXT NOT NULL,
                    latest_block INTEGER NOT NULL,
                    synced_block INTEGER NOT NULL,
                    confirmations INTEGER NOT NULL,
                    synced_at INTEGER NOT NULL,
                    source TEXT NOT NULL
                )
                """
            )
            chain_sync_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(chain_sync_state)").fetchall()
            }
            if "synced_block_hash" not in chain_sync_columns:
                conn.execute("ALTER TABLE chain_sync_state ADD COLUMN synced_block_hash TEXT")
            if "reorg_detected" not in chain_sync_columns:
                conn.execute("ALTER TABLE chain_sync_state ADD COLUMN reorg_detected INTEGER NOT NULL DEFAULT 0")
            if "revision" not in chain_sync_columns:
                conn.execute("ALTER TABLE chain_sync_state ADD COLUMN revision INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_account_state (
                    account_id TEXT PRIMARY KEY,
                    chain_id INTEGER NOT NULL DEFAULT 0,
                    settlement TEXT NOT NULL DEFAULT '',
                    observed_balance_units INTEGER NOT NULL DEFAULT 0,
                    pending_spend_units INTEGER NOT NULL DEFAULT 0,
                    latest_block INTEGER NOT NULL DEFAULT -1,
                    synced_block INTEGER NOT NULL DEFAULT -1,
                    synced_block_hash TEXT,
                    confirmations INTEGER NOT NULL DEFAULT 0,
                    synced_at INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT '',
                    reorg_detected INTEGER NOT NULL DEFAULT 0,
                    metadata_pending INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_events (
                    chain_id INTEGER NOT NULL,
                    settlement TEXT NOT NULL,
                    tx_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    block_number INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    topic0 TEXT NOT NULL,
                    observed_at INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, settlement, tx_hash, log_index)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipt_outbox (
                    receipt_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    exported_at INTEGER
                )
                """
            )
            outbox_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(receipt_outbox)").fetchall()
            }
            if "status" not in outbox_columns:
                conn.execute("ALTER TABLE receipt_outbox ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
            if "claim_token" not in outbox_columns:
                conn.execute("ALTER TABLE receipt_outbox ADD COLUMN claim_token TEXT")
            if "claimed_at" not in outbox_columns:
                conn.execute("ALTER TABLE receipt_outbox ADD COLUMN claimed_at INTEGER")
            if "attempt_count" not in outbox_columns:
                conn.execute("ALTER TABLE receipt_outbox ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE receipt_outbox SET status = 'exported' WHERE exported_at IS NOT NULL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reservations (
                    reservation_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    amount_units INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS key_challenges (
                    nonce TEXT PRIMARY KEY,
                    wallet TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS key_challenges_expires_at_idx ON key_challenges(expires_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS key_challenges_created_at_idx ON key_challenges(created_at)"
            )
            key_challenge_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(key_challenges)").fetchall()
            }
            if "verification_token" not in key_challenge_columns:
                conn.execute("ALTER TABLE key_challenges ADD COLUMN verification_token TEXT")
            if "verification_started_at" not in key_challenge_columns:
                conn.execute("ALTER TABLE key_challenges ADD COLUMN verification_started_at INTEGER")
            if "verification_attempts" not in key_challenge_columns:
                conn.execute(
                    "ALTER TABLE key_challenges ADD COLUMN verification_attempts INTEGER NOT NULL DEFAULT 0"
                )
            usage_columns = {row["name"] for row in conn.execute("PRAGMA table_info(usage_events)").fetchall()}
            if "receipt_hash" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN receipt_hash TEXT")
            if "chain_settled_at" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN chain_settled_at INTEGER")
            if "chain_settled_block" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN chain_settled_block INTEGER")
            if "chain_settled_chain_id" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN chain_settled_chain_id INTEGER")
            if "chain_settled_settlement" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN chain_settled_settlement TEXT")
            for row in conn.execute(
                (
                    "SELECT event_id, receipt_json, receipt_hash, onchain_reservation_id FROM usage_events "
                    "WHERE receipt_json IS NOT NULL AND (receipt_hash IS NULL OR onchain_reservation_id IS NULL)"
                )
            ).fetchall():
                try:
                    receipt = json.loads(str(row["receipt_json"]))
                except (TypeError, json.JSONDecodeError):
                    continue
                if isinstance(receipt, dict):
                    conn.execute(
                        (
                            "UPDATE usage_events SET receipt_hash = COALESCE(receipt_hash, ?), "
                            "onchain_reservation_id = COALESCE(onchain_reservation_id, ?) WHERE event_id = ?"
                        ),
                        (
                            _receipt_hash(receipt),
                            _receipt_onchain_reservation_id(receipt),
                            str(row["event_id"]),
                        ),
                    )
            conn.execute("CREATE INDEX IF NOT EXISTS usage_events_receipt_hash_idx ON usage_events(receipt_hash)")
            conn.execute(
                (
                    "CREATE INDEX IF NOT EXISTS usage_events_v3_receipt_idx "
                    "ON usage_events(receipt_hash, onchain_reservation_id)"
                )
            )

    def create_account(
        self,
        account_id: str | None = None,
        payment_address: str | None = None,
        *,
        credential_origin: str | None = None,
        credential_network_id: str | None = None,
        credential_chain_id: int | None = None,
        credential_settlement: str | None = None,
    ) -> ConsumerAccount:
        payment_address = normalize_payment_address(payment_address)
        credential_scope = _normalize_credential_scope(
            credential_origin,
            credential_network_id,
            credential_chain_id,
            credential_settlement,
        )
        resolved_account_id = account_id or "acct_" + secrets.token_hex(8)
        api_key = API_KEY_PREFIX + "_" + secrets.token_urlsafe(32)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _require_available_payment_address(conn, payment_address, account_id=resolved_account_id)
            conn.execute(
                (
                    "INSERT INTO accounts(account_id, api_key, api_key_hash, key_fingerprint, balance_units, "
                    "payment_address, credential_origin, credential_network_id, credential_chain_id, "
                    "credential_settlement, created_at) VALUES (?, NULL, ?, ?, 0, ?, ?, ?, ?, ?, ?)"
                ),
                (
                    resolved_account_id,
                    _api_key_hash(api_key),
                    _api_key_fingerprint(api_key),
                    payment_address,
                    *credential_scope,
                    now,
                ),
            )
        return ConsumerAccount(
            account_id=resolved_account_id,
            api_key=api_key,
            balance_units=0,
            status="active",
            payment_address=payment_address,
            key_fingerprint=_api_key_fingerprint(api_key),
            credential_origin=credential_scope[0],
            credential_network_id=credential_scope[1],
            credential_chain_id=credential_scope[2],
            credential_settlement=credential_scope[3],
        )

    def register_key_hash(
        self,
        account_id: str,
        key_hash: str,
        payment_address: str | None = None,
        *,
        credential_origin: str | None = None,
        credential_network_id: str | None = None,
        credential_chain_id: int | None = None,
        credential_settlement: str | None = None,
    ) -> ConsumerAccount:
        normalized_key_hash = normalize_api_key_hash(key_hash)
        payment_address = normalize_payment_address(payment_address)
        credential_scope = _normalize_credential_scope(
            credential_origin,
            credential_network_id,
            credential_chain_id,
            credential_settlement,
        )
        fingerprint = _api_key_hash_fingerprint(normalized_key_hash)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._register_key_hash_tx(
                conn,
                account_id=str(account_id),
                normalized_key_hash=normalized_key_hash,
                payment_address=payment_address,
                credential_scope=credential_scope,
                fingerprint=fingerprint,
                now=now,
            )
        return _account_from_row(row)

    def _register_key_hash_tx(
        self,
        conn: sqlite3.Connection,
        *,
        account_id: str,
        normalized_key_hash: str,
        payment_address: str | None,
        credential_scope: tuple[str | None, str | None, int | None, str | None],
        fingerprint: str,
        now: int,
    ) -> sqlite3.Row:
        self._transaction_lock(conn, "api-key-hash", normalized_key_hash)
        self._transaction_lock(conn, "account", account_id)
        if payment_address is not None:
            self._transaction_lock(conn, "payment-address", payment_address)
        existing_key = conn.execute(
            "SELECT account_id FROM accounts WHERE api_key_hash = ?",
            (normalized_key_hash,),
        ).fetchone()
        if existing_key is not None and str(existing_key["account_id"]) != account_id:
            raise BillingError("api key hash is already registered to another account")
        existing_account = conn.execute(
            self._for_update("SELECT * FROM accounts WHERE account_id = ?"),
            (account_id,),
        ).fetchone()
        _require_available_payment_address(conn, payment_address, account_id=account_id)
        if existing_account is None:
            conn.execute(
                (
                    "INSERT INTO accounts(account_id, api_key, api_key_hash, key_fingerprint, balance_units, "
                    "payment_address, credential_origin, credential_network_id, credential_chain_id, "
                    "credential_settlement, created_at) VALUES (?, NULL, ?, ?, 0, ?, ?, ?, ?, ?, ?)"
                ),
                (account_id, normalized_key_hash, fingerprint, payment_address, *credential_scope, now),
            )
        else:
            if credential_scope[0] is None:
                credential_scope = (
                    existing_account["credential_origin"],
                    existing_account["credential_network_id"],
                    existing_account["credential_chain_id"],
                    existing_account["credential_settlement"],
                )
            conn.execute(
                (
                    "UPDATE accounts SET api_key = NULL, api_key_hash = ?, key_fingerprint = ?, "
                    "payment_address = COALESCE(?, payment_address), credential_origin = ?, "
                    "credential_network_id = ?, credential_chain_id = ?, credential_settlement = ? "
                    "WHERE account_id = ?"
                ),
                (normalized_key_hash, fingerprint, payment_address, *credential_scope, account_id),
            )
        row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if row is None:
            raise BillingError(f"account not found after key registration: {account_id}")
        return row

    def get_by_key(
        self,
        api_key: str,
        *,
        credential_origin: str | None = None,
        credential_network_id: str | None = None,
        credential_chain_id: int | None = None,
        credential_settlement: str | None = None,
    ) -> ConsumerAccount | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE api_key_hash = ?", (_api_key_hash(api_key),)).fetchone()
        if row is None:
            return None
        account = _account_from_row(row)
        if account.credential_origin is None:
            return account
        try:
            expected_scope = _normalize_credential_scope(
                credential_origin,
                credential_network_id,
                credential_chain_id,
                credential_settlement,
            )
        except BillingError:
            return None
        actual_scope = (
            account.credential_origin,
            account.credential_network_id,
            account.credential_chain_id,
            account.credential_settlement,
        )
        return account if actual_scope == expected_scope else None

    def get_by_key_hash(self, key_hash: str) -> ConsumerAccount | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE api_key_hash = ?", (normalize_api_key_hash(key_hash),)).fetchone()
        return _account_from_row(row) if row else None

    def get_by_account(self, account_id: str) -> ConsumerAccount | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(row) if row else None

    def accounts_by_payment_address(self) -> dict[str, ConsumerAccount]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM accounts WHERE payment_address IS NOT NULL AND payment_address != ''").fetchall()
        accounts: dict[str, ConsumerAccount] = {}
        for row in rows:
            account = _account_from_row(row)
            if account.payment_address:
                accounts[account.payment_address.lower()] = account
        return accounts

    def rotate_key(
        self,
        account_id: str,
        *,
        credential_origin: str | None = None,
        credential_network_id: str | None = None,
        credential_chain_id: int | None = None,
        credential_settlement: str | None = None,
    ) -> ConsumerAccount:
        api_key = API_KEY_PREFIX + "_" + secrets.token_urlsafe(32)
        credential_scope = _normalize_credential_scope(
            credential_origin,
            credential_network_id,
            credential_chain_id,
            credential_settlement,
        )
        with self._connect() as conn:
            if credential_scope[0] is None:
                conn.execute(
                    "UPDATE accounts SET api_key = NULL, api_key_hash = ?, key_fingerprint = ? WHERE account_id = ?",
                    (_api_key_hash(api_key), _api_key_fingerprint(api_key), account_id),
                )
            else:
                conn.execute(
                    (
                        "UPDATE accounts SET api_key = NULL, api_key_hash = ?, key_fingerprint = ?, "
                        "credential_origin = ?, credential_network_id = ?, credential_chain_id = ?, "
                        "credential_settlement = ? WHERE account_id = ?"
                    ),
                    (_api_key_hash(api_key), _api_key_fingerprint(api_key), *credential_scope, account_id),
                )
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if row is None:
            raise BillingError(f"account not found: {account_id}")
        account = _account_from_row(row)
        return ConsumerAccount(
            account_id=account.account_id,
            api_key=api_key,
            balance_units=account.balance_units,
            status=account.status,
            payment_address=account.payment_address,
            key_fingerprint=_api_key_fingerprint(api_key),
            parent_account_id=account.parent_account_id,
            discount_bps=account.discount_bps,
            reseller_margin_bps=account.reseller_margin_bps,
            monthly_quota_units=account.monthly_quota_units,
            monthly_used_units=account.monthly_used_units,
            usage_period=account.usage_period,
            usage_tier=account.usage_tier,
            credential_origin=account.credential_origin,
            credential_network_id=account.credential_network_id,
            credential_chain_id=account.credential_chain_id,
            credential_settlement=account.credential_settlement,
        )

    def set_account_status(self, account_id: str, status: str) -> ConsumerAccount:
        normalized = str(status or "").strip().lower()
        if normalized not in {"active", "suspended", "closed"}:
            raise BillingError("account status must be active, suspended, or closed")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            result = conn.execute("UPDATE accounts SET status = ? WHERE account_id = ?", (normalized, account_id))
            if int(result.rowcount or 0) != 1:
                raise BillingError(f"account not found: {account_id}")
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(row)

    def set_payment_address(self, account_id: str, payment_address: str | None) -> ConsumerAccount:
        payment_address = normalize_payment_address(payment_address)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _require_available_payment_address(conn, payment_address, account_id=account_id)
            previous = conn.execute(
                "SELECT payment_address FROM accounts WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            conn.execute("UPDATE accounts SET payment_address = ? WHERE account_id = ?", (payment_address, account_id))
            if previous is not None and str(previous["payment_address"] or "").lower() != str(payment_address or "").lower():
                conn.execute("DELETE FROM chain_account_state WHERE account_id = ?", (account_id,))
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if row is None:
            raise BillingError(f"account not found: {account_id}")
        return _account_from_row(row)

    def configure_account(
        self,
        account_id: str,
        *,
        parent_account_id: str | None = None,
        discount_bps: int | None = None,
        reseller_margin_bps: int | None = None,
        monthly_quota_usdc: str | None = None,
        usage_tier: str | None = None,
    ) -> ConsumerAccount:
        updates: list[str] = []
        values: list[object] = []
        if parent_account_id is not None:
            updates.append("parent_account_id = ?")
            values.append(parent_account_id or None)
        if discount_bps is not None:
            updates.append("discount_bps = ?")
            values.append(_bps(discount_bps, "discount_bps"))
        if reseller_margin_bps is not None:
            updates.append("reseller_margin_bps = ?")
            values.append(_bps(reseller_margin_bps, "reseller_margin_bps"))
        if monthly_quota_usdc is not None:
            updates.append("monthly_quota_units = ?")
            values.append(usdc_to_units(monthly_quota_usdc))
        if usage_tier is not None:
            updates.append("usage_tier = ?")
            values.append(str(usage_tier or "standard"))
        if not updates:
            account = self.get_by_account(account_id)
            if account is None:
                raise BillingError(f"account not found: {account_id}")
            return account
        values.append(account_id)
        with self._connect() as conn:
            conn.execute(f"UPDATE accounts SET {', '.join(updates)} WHERE account_id = ?", values)
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if row is None:
            raise BillingError(f"account not found: {account_id}")
        return _account_from_row(row)

    def delete_account(self, account_id: str) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            result = conn.execute("DELETE FROM accounts WHERE account_id = ?", (account_id,))
            conn.execute("DELETE FROM reservations WHERE account_id = ?", (account_id,))
            conn.execute("DELETE FROM chain_account_state WHERE account_id = ?", (account_id,))
        return int(result.rowcount or 0) > 0

    def deposit(self, account_id: str, amount_usdc: str) -> ConsumerAccount:
        amount_units = usdc_to_units(amount_usdc)
        if amount_units <= 0:
            raise BillingError("deposit amount must be positive")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE accounts SET balance_units = balance_units + ? WHERE account_id = ?",
                (amount_units, account_id),
            )
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if row is None:
            raise BillingError(f"account not found: {account_id}")
        return _account_from_row(row)

    def set_balance(self, account_id: str, amount_usdc: str) -> ConsumerAccount:
        amount_units = usdc_to_units(amount_usdc)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._sync_chain_balance_tx(
                conn,
                account_id=account_id,
                observed_balance_units=amount_units,
                metadata=None,
            )
        return _account_from_row(row)

    def sync_chain_balance(
        self,
        account_id: str,
        observed_balance_units: int,
        *,
        chain_id: int,
        settlement: str,
        latest_block: int,
        synced_block: int,
        confirmations: int,
        source: str,
        synced_at: int | None = None,
        synced_block_hash: str | None = None,
    ) -> ConsumerAccount:
        if int(observed_balance_units) < 0:
            raise BillingError("observed chain balance cannot be negative")
        latest, synced, confirmed, block_hash = _validate_chain_cursor(
            latest_block=latest_block,
            synced_block=synced_block,
            confirmations=confirmations,
            synced_block_hash=synced_block_hash,
        )
        metadata = {
            "chain_id": int(chain_id),
            "settlement": _normalize_settlement_address(settlement),
            "latest_block": latest,
            "synced_block": synced,
            "confirmations": confirmed,
            "source": str(source),
            "synced_at": int(synced_at if synced_at is not None else time.time()),
            "synced_block_hash": block_hash,
        }
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._sync_chain_balance_tx(
                conn,
                account_id=account_id,
                observed_balance_units=int(observed_balance_units),
                metadata=metadata,
                clear_reorg=False,
            )
        return _account_from_row(row)

    def publish_direct_chain_balance(
        self,
        account_id: str,
        amount_usdc: str,
        *,
        expected_state: dict[str, object] | None,
        chain_id: int,
        settlement: str,
        latest_block: int,
        synced_block: int,
        confirmations: int,
        synced_block_hash: str,
        synced_at: int | None = None,
    ) -> ConsumerAccount:
        account = self.get_by_account(account_id)
        if account is None:
            raise BillingError(f"account not found: {account_id}")
        if account.payment_address is None:
            raise BillingError(f"billing account has no payment_address: {account_id}")
        published = self.publish_canonical_chain_balances(
            [(account_id, account.payment_address, usdc_to_units(amount_usdc))],
            expected_state=expected_state,
            chain_id=chain_id,
            settlement=settlement,
            latest_block=latest_block,
            synced_block=synced_block,
            confirmations=confirmations,
            source="direct",
            synced_at=synced_at,
            synced_block_hash=synced_block_hash,
        )
        return published[0]

    def publish_canonical_chain_balances(
        self,
        observations: list[tuple[str, str, int]],
        *,
        expected_state: dict[str, object] | None,
        chain_id: int,
        settlement: str,
        latest_block: int,
        synced_block: int,
        confirmations: int,
        source: str,
        synced_at: int | None = None,
        synced_block_hash: str | None = None,
        canonical_logs: list[dict[str, object]] | None = None,
        settled_receipts: list[tuple[str, str, int, str | None]] | None = None,
        reconcile_from_block: int | None = None,
        reconcile_to_block: int | None = None,
        reorg_recovery: bool = False,
    ) -> list[ConsumerAccount]:
        latest, synced, confirmed, block_hash = _validate_chain_cursor(
            latest_block=latest_block,
            synced_block=synced_block,
            confirmations=confirmations,
            synced_block_hash=synced_block_hash,
        )
        normalized_settlement = _normalize_settlement_address(settlement)
        metadata = {
            "chain_id": int(chain_id),
            "settlement": normalized_settlement,
            "latest_block": latest,
            "synced_block": synced,
            "confirmations": confirmed,
            "source": str(source),
            "synced_at": int(synced_at if synced_at is not None else time.time()),
            "synced_block_hash": block_hash,
        }
        normalized_observations: list[tuple[str, str, int]] = []
        seen: set[str] = set()
        for account_id, payment_address, observed_balance_units in observations:
            normalized_account_id = str(account_id)
            if normalized_account_id in seen:
                raise BillingError(f"duplicate account in canonical balance publication: {normalized_account_id}")
            seen.add(normalized_account_id)
            balance_units = int(observed_balance_units)
            if balance_units < 0:
                raise BillingError("observed chain balance cannot be negative")
            normalized_address = normalize_payment_address(payment_address)
            if normalized_address is None:
                raise BillingError(f"billing account has no payment_address: {normalized_account_id}")
            normalized_observations.append((normalized_account_id, normalized_address, balance_units))

        rows: list[sqlite3.Row] = []
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            current_state = _require_expected_chain_state_tx(conn, expected_state)
            same_domain = bool(
                current_state is not None
                and int(current_state["chain_id"]) == int(chain_id)
                and str(current_state["settlement"]).lower() == normalized_settlement
            )
            if current_state is not None and not same_domain:
                raise BillingError("chain sync publication cannot change chain_id or settlement")
            if (
                current_state is not None
                and str(current_state["source"]) == "events"
                and str(source) != "events"
            ):
                raise BillingError("event-indexed chain state cannot be downgraded to a direct balance source")
            if current_state is not None and int(current_state["reorg_detected"]):
                if not reorg_recovery:
                    raise BillingError("canonical event recovery is required after a chain reorganization")
                if canonical_logs is None or str(source) != "events":
                    raise BillingError("chain reorganization recovery requires canonical event publication")
                required_accounts = {
                    str(row["account_id"])
                    for row in conn.execute(
                        (
                            "SELECT account_id FROM accounts WHERE status = 'active' "
                            "AND payment_address IS NOT NULL AND payment_address != ''"
                        )
                    ).fetchall()
                }
                observed_accounts = {account_id for account_id, _address, _balance in normalized_observations}
                missing_accounts = required_accounts - observed_accounts
                if missing_accounts:
                    raise BillingError(
                        "chain reorganization recovery is missing account balances: "
                        + ", ".join(sorted(missing_accounts))
                    )
            elif reorg_recovery:
                raise ChainSyncSuperseded("chain reorganization recovery snapshot was superseded")

            if current_state is not None and same_domain:
                previous_synced = int(current_state["synced_block"])
                previous_latest = int(current_state["latest_block"])
                previous_hash = _normalize_block_hash(current_state["synced_block_hash"])
                if not reorg_recovery and synced < previous_synced:
                    raise ChainSyncSuperseded("chain sync publication would move the canonical cursor backwards")
                if not reorg_recovery and latest < previous_latest:
                    raise ChainSyncSuperseded("chain sync publication would move the observed chain head backwards")
                if not reorg_recovery and synced == previous_synced and previous_hash != block_hash:
                    raise BillingError("canonical block hash changed at the persisted chain cursor")

            establishing_event_source = bool(
                str(source) == "events"
                and not reorg_recovery
                and (current_state is None or str(current_state["source"]) != "events")
            )
            if establishing_event_source:
                required_accounts = {
                    str(row["account_id"])
                    for row in conn.execute(
                        (
                            "SELECT account_id FROM accounts WHERE status = 'active' "
                            "AND payment_address IS NOT NULL AND payment_address != ''"
                        )
                    ).fetchall()
                }
                observed_accounts = {
                    account_id for account_id, _address, _balance in normalized_observations
                }
                missing_accounts = required_accounts - observed_accounts
                if missing_accounts:
                    raise BillingError(
                        "initial canonical event publication is missing account balances: "
                        + ", ".join(sorted(missing_accounts))
                    )

            if canonical_logs is not None:
                if reconcile_from_block is None or reconcile_to_block is None:
                    raise BillingError("canonical event publication requires a reconciliation block range")
                from_block = int(reconcile_from_block)
                to_block = int(reconcile_to_block)
                empty_advance = from_block == to_block + 1
                if from_block < 0 or to_block < 0 or to_block < from_block - 1:
                    raise BillingError("invalid canonical event reconciliation block range")
                if to_block != synced:
                    raise BillingError("canonical event reconciliation must end at synced_block")
                if current_state is not None and same_domain and not reorg_recovery:
                    expected_from = int(current_state["synced_block"]) + 1
                    if from_block != expected_from:
                        raise ChainSyncSuperseded("canonical event publication does not continue the persisted cursor")
                if empty_advance and (
                    current_state is None
                    or reorg_recovery
                    or synced != int(current_state["synced_block"])
                ):
                    raise BillingError("empty canonical publication can only refresh the current cursor")
                rewound_accounts = set()
                if not empty_advance:
                    rewound_accounts = self._rewind_chain_receipts_tx(
                        conn,
                        chain_id=int(chain_id),
                        settlement=str(normalized_settlement),
                        from_block=from_block,
                        to_block=to_block,
                    )
                observed_accounts = {account_id for account_id, _address, _balance in normalized_observations}
                missing_accounts = rewound_accounts - observed_accounts
                if missing_accounts:
                    raise BillingError(
                        "canonical event reconciliation is missing account balances: "
                        + ", ".join(sorted(missing_accounts))
                    )
                if not empty_advance:
                    conn.execute(
                        (
                            "DELETE FROM chain_events WHERE chain_id = ? AND settlement = ? "
                            "AND block_number BETWEEN ? AND ?"
                        ),
                        (int(chain_id), normalized_settlement, from_block, to_block),
                    )
                    _inserted, conflict = self._record_chain_events_tx(
                        conn,
                        chain_id=int(chain_id),
                        settlement=str(normalized_settlement),
                        logs=canonical_logs,
                        observed_at=int(metadata["synced_at"]),
                        expected_from_block=from_block,
                        expected_to_block=to_block,
                    )
                    if conflict:
                        raise BillingError("conflicting block hashes for an already indexed chain event")
                for receipt_hash, consumer, settled_block, onchain_reservation_id in settled_receipts or []:
                    self._confirm_chain_receipts_tx(
                        conn,
                        [receipt_hash],
                        chain_id=int(chain_id),
                        settlement=str(normalized_settlement),
                        settled_block=int(settled_block),
                        settled_at=int(metadata["synced_at"]),
                        consumer_addresses={receipt_hash: consumer},
                        onchain_reservation_ids={receipt_hash: onchain_reservation_id},
                    )
            for account_id, payment_address, balance_units in normalized_observations:
                current = conn.execute(
                    "SELECT payment_address FROM accounts WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
                if current is None:
                    raise BillingError(f"account not found: {account_id}")
                if str(current["payment_address"] or "").lower() != payment_address:
                    raise BillingError(f"payment_address changed during chain balance synchronization: {account_id}")
                rows.append(
                    self._sync_chain_balance_tx(
                        conn,
                        account_id=account_id,
                        observed_balance_units=balance_units,
                        metadata=metadata,
                        clear_reorg=True,
                    )
                )
            if str(source) == "events":
                conn.execute(
                    (
                        "UPDATE chain_account_state SET latest_block = ?, synced_block = ?, synced_block_hash = ?, "
                        "confirmations = ?, synced_at = ?, source = 'events' "
                        "WHERE chain_id = ? AND settlement = ? AND reorg_detected = 0 "
                        "AND metadata_pending = 0 AND source = 'events'"
                    ),
                    (
                        latest,
                        synced,
                        block_hash,
                        confirmed,
                        int(metadata["synced_at"]),
                        int(chain_id),
                        normalized_settlement,
                    ),
                )
            next_revision = int(current_state["revision"]) + 1 if current_state is not None else 1
            if current_state is None:
                conn.execute(
                    (
                        "INSERT INTO chain_sync_state(id, chain_id, settlement, latest_block, synced_block, "
                        "confirmations, synced_at, source, synced_block_hash, reorg_detected, revision) "
                        "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)"
                    ),
                    (
                        int(chain_id),
                        normalized_settlement,
                        latest,
                        synced,
                        confirmed,
                        int(metadata["synced_at"]),
                        str(source),
                        block_hash,
                        next_revision,
                    ),
                )
            else:
                result = conn.execute(
                    (
                        "UPDATE chain_sync_state SET latest_block = ?, synced_block = ?, confirmations = ?, "
                        "synced_at = ?, source = ?, synced_block_hash = ?, reorg_detected = 0, revision = ? "
                        "WHERE id = 1 AND revision = ?"
                    ),
                    (
                        latest,
                        synced,
                        confirmed,
                        int(metadata["synced_at"]),
                        str(source),
                        block_hash,
                        next_revision,
                        int(current_state["revision"]),
                    ),
                )
                if int(result.rowcount or 0) != 1:
                    raise ChainSyncSuperseded("chain sync publication snapshot was superseded")
        return [_account_from_row(row) for row in rows]

    def accounts_with_chain_settled_receipts(
        self,
        *,
        chain_id: int,
        settlement: str,
        from_block: int,
        to_block: int,
    ) -> set[str]:
        normalized_settlement = _normalize_settlement_address(settlement)
        start = int(from_block)
        end = int(to_block)
        if start < 0 or end < start:
            raise BillingError("invalid settled receipt query block range")
        with self._connect() as conn:
            rows = conn.execute(
                (
                    "SELECT DISTINCT usage_events.account_id FROM usage_events "
                    "JOIN accounts ON accounts.account_id = usage_events.account_id "
                    "WHERE usage_events.chain_settled_at IS NOT NULL "
                    "AND usage_events.chain_settled_block BETWEEN ? AND ? AND ("
                    "(usage_events.chain_settled_chain_id = ? "
                    "AND lower(usage_events.chain_settled_settlement) = ?) "
                    "OR usage_events.chain_settled_chain_id IS NULL "
                    "OR usage_events.chain_settled_settlement IS NULL)"
                ),
                (start, end, int(chain_id), normalized_settlement),
            ).fetchall()
        return {str(row["account_id"]) for row in rows}

    def set_chain_sync_state(
        self,
        *,
        chain_id: int,
        settlement: str,
        latest_block: int,
        synced_block: int,
        confirmations: int,
        source: str,
        synced_at: int | None = None,
        synced_block_hash: str | None = None,
        account_id: str | None = None,
        clear_reorg: bool = False,
    ) -> None:
        now = int(synced_at if synced_at is not None else time.time())
        latest, synced, confirmed, block_hash = _validate_chain_cursor(
            latest_block=latest_block,
            synced_block=synced_block,
            confirmations=confirmations,
            synced_block_hash=synced_block_hash,
        )
        normalized_settlement = _normalize_settlement_address(settlement)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            current_state = conn.execute(
                self._for_update("SELECT * FROM chain_sync_state WHERE id = 1")
            ).fetchone()
            if current_state is not None:
                if (
                    int(current_state["chain_id"]) != int(chain_id)
                    or str(current_state["settlement"]).lower() != normalized_settlement
                ):
                    raise BillingError("chain sync state cannot change chain_id or settlement")
                source_changed = str(current_state["source"]) != str(source)
                sticky_event_refresh = bool(
                    source_changed
                    and int(current_state["reorg_detected"])
                    and str(current_state["source"]) == "reorg-detected"
                    and str(source) == "events"
                )
                if source_changed and not sticky_event_refresh:
                    raise BillingError(
                        "chain sync source changes require a canonical balance publication"
                    )
                if not source_changed and synced < int(current_state["synced_block"]):
                    raise ChainSyncSuperseded("chain sync state cannot move backwards")
                if not source_changed and latest < int(current_state["latest_block"]):
                    raise ChainSyncSuperseded("chain sync latest block cannot move backwards")
                if (
                    not source_changed
                    and synced == int(current_state["synced_block"])
                    and _normalize_block_hash(current_state["synced_block_hash"]) != block_hash
                ):
                    raise BillingError("canonical block hash changed at the persisted chain cursor")
                if int(current_state["reorg_detected"]) and clear_reorg:
                    raise BillingError("only a canonical event publication can clear a chain reorganization")
            next_revision = int(current_state["revision"]) + 1 if current_state is not None else 1
            conn.execute(
                (
                    "INSERT INTO chain_sync_state(id, chain_id, settlement, latest_block, synced_block, confirmations, synced_at, source, "
                    "synced_block_hash, reorg_detected, revision) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?) "
                    "ON CONFLICT(id) DO UPDATE SET chain_id = excluded.chain_id, settlement = excluded.settlement, "
                    "latest_block = excluded.latest_block, synced_block = excluded.synced_block, confirmations = excluded.confirmations, "
                    "synced_at = excluded.synced_at, source = excluded.source, synced_block_hash = excluded.synced_block_hash, "
                    "reorg_detected = CASE WHEN ? THEN 0 ELSE chain_sync_state.reorg_detected END, "
                    "revision = excluded.revision"
                ),
                (
                    int(chain_id),
                    normalized_settlement,
                    latest,
                    synced,
                    confirmed,
                    now,
                    str(source),
                    block_hash,
                    next_revision,
                    int(bool(clear_reorg)),
                ),
            )
            if account_id is None:
                pending_filter = "metadata_pending = 1"
                values: tuple[object, ...] = (
                    int(chain_id),
                    normalized_settlement,
                    latest,
                    synced,
                    block_hash,
                    confirmed,
                    now,
                    str(source),
                )
            else:
                pending_filter = "account_id = ?"
                values = (
                    int(chain_id),
                    normalized_settlement,
                    latest,
                    synced,
                    block_hash,
                    confirmed,
                    now,
                    str(source),
                    account_id,
                )
            conn.execute(
                (
                    "UPDATE chain_account_state SET chain_id = ?, settlement = ?, latest_block = ?, synced_block = ?, "
                    "synced_block_hash = ?, confirmations = ?, synced_at = ?, source = ?, "
                    "reorg_detected = CASE WHEN ? THEN 0 ELSE reorg_detected END, "
                    f"metadata_pending = 0 WHERE {pending_filter}"
                ),
                (*values[:-1], int(bool(clear_reorg)), values[-1])
                if account_id is not None
                else (*values, 0),
            )

    def get_chain_sync_state(self, account_id: str | None = None) -> dict[str, object] | None:
        with self._connect() as conn:
            if account_id is None:
                row = conn.execute("SELECT * FROM chain_sync_state WHERE id = 1").fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM chain_account_state WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
        return dict(row) if row is not None else None

    def require_fresh_chain_sync(
        self,
        *,
        chain_id: int,
        settlement: str,
        max_age_seconds: int,
        max_block_lag: int,
        account_id: str | None = None,
        min_confirmations: int = 0,
    ) -> dict[str, object]:
        normalized_settlement = _normalize_settlement_address(settlement)
        states: list[dict[str, object]] = []
        with self._connect() as conn:
            conn.execute("BEGIN")
            global_row = conn.execute("SELECT * FROM chain_sync_state WHERE id = 1").fetchone()
            global_state = dict(global_row) if global_row is not None else None
            if global_state is None:
                raise BillingError("global on-chain balance cache has never been synchronized")
            if account_id is not None:
                row = conn.execute(
                    "SELECT * FROM chain_account_state WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
                if row is None:
                    raise BillingError(f"on-chain balance cache for account {account_id} has never been synchronized")
                states = [dict(row)]
            else:
                required_accounts = conn.execute(
                    "SELECT account_id FROM accounts WHERE status = 'active' AND payment_address IS NOT NULL AND payment_address != ''"
                ).fetchall()
                if required_accounts:
                    for account in required_accounts:
                        row = conn.execute(
                            "SELECT * FROM chain_account_state WHERE account_id = ?",
                            (str(account["account_id"]),),
                        ).fetchone()
                        if row is None:
                            raise BillingError(
                                f"on-chain balance cache for account {account['account_id']} has never been synchronized"
                            )
                        states.append(dict(row))
            if not states:
                states = [global_state]
        reference_latest_block: int | None = None
        if global_state is not None:
            self._validate_chain_sync_state(
                global_state,
                chain_id=chain_id,
                settlement=normalized_settlement,
                max_age_seconds=max_age_seconds,
                max_block_lag=max_block_lag,
                min_confirmations=min_confirmations,
            )
            reference_latest_block = int(global_state["latest_block"])
        for state in states:
            self._validate_chain_sync_state(
                state,
                chain_id=chain_id,
                settlement=normalized_settlement,
                max_age_seconds=max_age_seconds,
                max_block_lag=max_block_lag,
                min_confirmations=min_confirmations,
                reference_latest_block=reference_latest_block,
            )
        state = min(states, key=lambda item: (int(item["synced_at"]), int(item["synced_block"])))
        return state

    def _validate_chain_sync_state(
        self,
        state: dict[str, object],
        *,
        chain_id: int,
        settlement: str,
        max_age_seconds: int,
        max_block_lag: int,
        min_confirmations: int,
        reference_latest_block: int | None = None,
    ) -> None:
        if int(state.get("reorg_detected") or 0):
            raise BillingError("on-chain balance cache is invalid because a chain reorganization was detected")
        if int(state["chain_id"]) != int(chain_id):
            raise BillingError("on-chain balance cache chain_id mismatch")
        if str(state["settlement"]).lower() != str(settlement).lower():
            raise BillingError("on-chain balance cache settlement mismatch")
        if int(state["confirmations"]) < int(min_confirmations):
            raise BillingError("on-chain balance cache has insufficient confirmations")
        if int(min_confirmations) > 0 and _normalize_block_hash(state.get("synced_block_hash")) is None:
            raise BillingError("on-chain balance cache is missing its confirmed block hash")
        now = int(time.time())
        if int(state["synced_at"]) > now + 30:
            raise BillingError("on-chain balance cache timestamp is in the future")
        age = now - int(state["synced_at"])
        if age > int(max_age_seconds):
            raise BillingError("on-chain balance cache is stale")
        latest = int(state["latest_block"])
        if reference_latest_block is not None:
            latest = max(latest, int(reference_latest_block))
        synced = int(state["synced_block"])
        if latest - synced > int(max_block_lag):
            raise BillingError("on-chain balance cache block lag exceeded")

    def advance_chain_account_freshness(
        self,
        *,
        chain_id: int,
        settlement: str,
        latest_block: int,
        synced_block: int,
        confirmations: int,
        source: str,
        synced_at: int | None = None,
        synced_block_hash: str | None = None,
    ) -> int:
        normalized_settlement = _normalize_settlement_address(settlement)
        now = int(synced_at if synced_at is not None else time.time())
        latest, synced, confirmed, block_hash = _validate_chain_cursor(
            latest_block=latest_block,
            synced_block=synced_block,
            confirmations=confirmations,
            synced_block_hash=synced_block_hash,
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            result = conn.execute(
                (
                    "UPDATE chain_account_state SET latest_block = ?, synced_block = ?, synced_block_hash = ?, "
                    "confirmations = ?, synced_at = ?, source = ? WHERE chain_id = ? AND settlement = ? "
                    "AND reorg_detected = 0 AND metadata_pending = 0 AND source = 'events'"
                ),
                (
                    latest,
                    synced,
                    block_hash,
                    confirmed,
                    now,
                    str(source),
                    int(chain_id),
                    normalized_settlement,
                ),
            )
        return int(result.rowcount or 0)

    def mark_chain_reorg(
        self,
        *,
        chain_id: int,
        settlement: str,
        account_ids: list[str] | None = None,
    ) -> None:
        self._mark_chain_reorg(
            chain_id=chain_id,
            settlement=settlement,
            account_ids=account_ids,
            expected_state=None,
            require_expected_state=False,
        )

    def mark_chain_reorg_if_current(
        self,
        *,
        chain_id: int,
        settlement: str,
        expected_state: dict[str, object] | None,
        account_ids: list[str] | None = None,
    ) -> None:
        self._mark_chain_reorg(
            chain_id=chain_id,
            settlement=settlement,
            account_ids=account_ids,
            expected_state=expected_state,
            require_expected_state=True,
        )

    def _mark_chain_reorg(
        self,
        *,
        chain_id: int,
        settlement: str,
        account_ids: list[str] | None,
        expected_state: dict[str, object] | None,
        require_expected_state: bool,
    ) -> None:
        normalized_settlement = _normalize_settlement_address(settlement)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            if require_expected_state:
                _require_expected_chain_state_tx(conn, expected_state)
            for account_id in dict.fromkeys(str(value) for value in (account_ids or []) if value):
                account = conn.execute(
                    "SELECT account_id FROM accounts WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
                if account is None:
                    continue
                pending_spend_units = int(
                    conn.execute(
                        (
                            "SELECT COALESCE(SUM(amount_units), 0) AS total FROM usage_events "
                            "WHERE account_id = ? AND chain_settled_at IS NULL"
                        ),
                        (account_id,),
                    ).fetchone()["total"]
                )
                conn.execute(
                    (
                        "INSERT INTO chain_account_state(account_id, chain_id, settlement, pending_spend_units, "
                        "source, reorg_detected) VALUES (?, ?, ?, ?, 'reorg-detected', 1) "
                        "ON CONFLICT(account_id) DO UPDATE SET reorg_detected = 1, synced_at = 0, "
                        "source = 'reorg-detected'"
                    ),
                    (account_id, int(chain_id), normalized_settlement, pending_spend_units),
                )
            self._mark_chain_reorg_tx(
                conn,
                chain_id=int(chain_id),
                settlement=normalized_settlement,
            )

    def _mark_chain_reorg_tx(
        self,
        conn: sqlite3.Connection,
        *,
        chain_id: int,
        settlement: str,
    ) -> None:
        self._rewind_chain_receipts_tx(
            conn,
            chain_id=chain_id,
            settlement=settlement,
        )
        current_state = conn.execute("SELECT * FROM chain_sync_state WHERE id = 1").fetchone()
        if current_state is None:
            conn.execute(
                (
                    "INSERT INTO chain_sync_state(id, chain_id, settlement, latest_block, synced_block, "
                    "confirmations, synced_at, source, synced_block_hash, reorg_detected, revision) "
                    "VALUES (1, ?, ?, 0, 0, 0, 0, 'reorg-detected', NULL, 1, 1)"
                ),
                (int(chain_id), settlement),
            )
        else:
            if (
                int(current_state["chain_id"]) != int(chain_id)
                or str(current_state["settlement"]).lower() != settlement
            ):
                raise BillingError("chain reorganization domain does not match persisted chain sync state")
            conn.execute(
                (
                    "UPDATE chain_sync_state SET reorg_detected = 1, source = 'reorg-detected', "
                    "revision = revision + 1 WHERE id = 1"
                )
            )
        conn.execute(
            "UPDATE chain_account_state SET reorg_detected = 1 WHERE chain_id = ? AND settlement = ?",
            (int(chain_id), settlement),
        )
        conn.execute(
            "DELETE FROM chain_events WHERE chain_id = ? AND settlement = ?",
            (int(chain_id), settlement),
        )
        conn.execute(
            (
                "UPDATE accounts SET balance_units = 0 WHERE account_id IN ("
                "SELECT account_id FROM chain_account_state WHERE reorg_detected = 1 "
                "AND chain_id = ? AND settlement = ?)"
            )
            ,
            (int(chain_id), settlement),
        )

    def _rewind_chain_receipts_tx(
        self,
        conn: sqlite3.Connection,
        *,
        chain_id: int,
        settlement: str,
        from_block: int | None = None,
        to_block: int | None = None,
    ) -> set[str]:
        block_filter = ""
        parameters: list[object] = [int(chain_id), settlement]
        if from_block is not None or to_block is not None:
            if from_block is None or to_block is None:
                raise BillingError("receipt rewind requires both block range bounds")
            block_filter = " AND chain_settled_block BETWEEN ? AND ?"
            parameters.extend((int(from_block), int(to_block)))
        settled_rows = conn.execute(
            (
                "SELECT event_id, account_id, amount_units FROM usage_events "
                "WHERE chain_settled_at IS NOT NULL AND ("
                "(chain_settled_chain_id = ? AND lower(chain_settled_settlement) = ?) "
                "OR chain_settled_chain_id IS NULL OR chain_settled_settlement IS NULL)"
                + block_filter
            ),
            parameters,
        ).fetchall()
        affected: dict[str, int] = {}
        if settled_rows:
            event_ids = [str(row["event_id"]) for row in settled_rows]
            for row in settled_rows:
                account_id = str(row["account_id"])
                affected[account_id] = affected.get(account_id, 0) + int(row["amount_units"])
            placeholders = ",".join("?" for _ in event_ids)
            conn.execute(
                (
                    "UPDATE usage_events SET chain_settled_at = NULL, chain_settled_block = NULL, "
                    "chain_settled_chain_id = NULL, chain_settled_settlement = NULL "
                    f"WHERE event_id IN ({placeholders})"
                ),
                event_ids,
            )
            for account_id, amount_units in affected.items():
                conn.execute(
                    (
                        "UPDATE chain_account_state SET pending_spend_units = pending_spend_units + ?, "
                        "reorg_detected = 1 WHERE account_id = ?"
                    ),
                    (amount_units, account_id),
                )
        return set(affected)

    def invalidate_chain_accounts(self, account_ids: list[str]) -> int:
        unique_ids = list(dict.fromkeys(str(item) for item in account_ids if item))
        if not unique_ids:
            return 0
        placeholders = ",".join("?" for _ in unique_ids)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            result = conn.execute(
                (
                    f"UPDATE chain_account_state SET synced_at = 0, source = 'invalidated-by-chain-event' "
                    f"WHERE account_id IN ({placeholders})"
                ),
                unique_ids,
            )
        return int(result.rowcount or 0)

    def invalidate_chain_accounts_if_current(
        self,
        account_ids: list[str],
        *,
        chain_id: int,
        settlement: str,
        expected_state: dict[str, object] | None,
    ) -> int:
        normalized_settlement = _normalize_settlement_address(settlement)
        unique_ids = list(dict.fromkeys(str(item) for item in account_ids if item))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            _require_expected_chain_state_tx(conn, expected_state)
            if not unique_ids:
                return 0
            placeholders = ",".join("?" for _ in unique_ids)
            result = conn.execute(
                (
                    f"UPDATE chain_account_state SET synced_at = 0, source = 'invalidated-by-chain-event' "
                    f"WHERE account_id IN ({placeholders}) AND chain_id = ? AND settlement = ?"
                ),
                (*unique_ids, int(chain_id), normalized_settlement),
            )
        return int(result.rowcount or 0)

    def record_chain_events(
        self,
        *,
        chain_id: int,
        settlement: str,
        logs: list[dict[str, object]],
        observed_at: int | None = None,
    ) -> int:
        now = int(observed_at if observed_at is not None else time.time())
        normalized_settlement = _normalize_settlement_address(settlement)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            inserted, conflict = self._record_chain_events_tx(
                conn,
                chain_id=int(chain_id),
                settlement=normalized_settlement,
                logs=logs,
                observed_at=now,
            )
            if conflict:
                self._mark_chain_reorg_tx(
                    conn,
                    chain_id=int(chain_id),
                    settlement=normalized_settlement,
                )
        if conflict:
            raise BillingError("conflicting block hashes for an already indexed chain event")
        return inserted

    def _record_chain_events_tx(
        self,
        conn: sqlite3.Connection,
        *,
        chain_id: int,
        settlement: str,
        logs: list[dict[str, object]],
        observed_at: int,
        expected_from_block: int | None = None,
        expected_to_block: int | None = None,
    ) -> tuple[int, bool]:
        inserted = 0
        conflict = False
        for log in logs:
            identity = _chain_log_identity(log)
            if identity is None:
                continue
            block_number = int(identity["block_number"])
            if expected_from_block is not None and block_number < int(expected_from_block):
                raise BillingError("canonical log falls before the reconciliation block range")
            if expected_to_block is not None and block_number > int(expected_to_block):
                raise BillingError("canonical log falls after the reconciliation block range")
            existing = conn.execute(
                (
                    "SELECT block_hash FROM chain_events WHERE chain_id = ? AND settlement = ? "
                    "AND tx_hash = ? AND log_index = ?"
                ),
                (int(chain_id), settlement, identity["tx_hash"], identity["log_index"]),
            ).fetchone()
            if existing is not None:
                if str(existing["block_hash"]).lower() != str(identity["block_hash"]).lower():
                    conflict = True
                continue
            conn.execute(
                (
                    "INSERT INTO chain_events(chain_id, settlement, tx_hash, log_index, block_number, block_hash, "
                    "topic0, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                ),
                (
                    int(chain_id),
                    settlement,
                    identity["tx_hash"],
                    identity["log_index"],
                    block_number,
                    identity["block_hash"],
                    identity["topic0"],
                    int(observed_at),
                ),
            )
            inserted += 1
        return inserted, conflict

    def confirm_chain_receipts(
        self,
        receipt_hashes: list[str],
        *,
        chain_id: int,
        settlement: str,
        settled_block: int,
        settled_at: int | None = None,
        consumer_addresses: dict[str, str] | None = None,
        onchain_reservation_ids: dict[str, str | None] | None = None,
    ) -> int:
        now = int(settled_at if settled_at is not None else time.time())
        normalized_settlement = _normalize_settlement_address(settlement)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer")
            return self._confirm_chain_receipts_tx(
                conn,
                receipt_hashes,
                chain_id=int(chain_id),
                settlement=normalized_settlement,
                settled_block=int(settled_block),
                settled_at=now,
                consumer_addresses=consumer_addresses,
                onchain_reservation_ids=onchain_reservation_ids,
            )

    def _confirm_chain_receipts_tx(
        self,
        conn: sqlite3.Connection,
        receipt_hashes: list[str],
        *,
        chain_id: int,
        settlement: str,
        settled_block: int,
        settled_at: int,
        consumer_addresses: dict[str, str] | None,
        onchain_reservation_ids: dict[str, str | None] | None = None,
    ) -> int:
        confirmed = 0
        normalized_consumers = {
            str(receipt_hash).lower(): str(address).lower()
            for receipt_hash, address in (consumer_addresses or {}).items()
        }
        normalized_reservations: dict[str, str | None] = {}
        for receipt_hash, reservation_id in (onchain_reservation_ids or {}).items():
            normalized_hash = str(receipt_hash).lower()
            if reservation_id is None:
                normalized_reservations[normalized_hash] = None
                continue
            normalized_reservation = str(reservation_id).lower()
            if not re.fullmatch(r"0x[a-f0-9]{64}", normalized_reservation):
                raise BillingError("on-chain reservation id must be a 32-byte hex value")
            normalized_reservations[normalized_hash] = normalized_reservation
        for value in dict.fromkeys(str(item).lower() for item in receipt_hashes if item):
            reservation_filter = ""
            parameters: list[object] = [value, int(chain_id), settlement]
            if normalized_reservations.get(value) is not None:
                reservation_filter = " AND lower(usage_events.onchain_reservation_id) = ?"
                parameters.append(normalized_reservations[value])
            rows = conn.execute(
                (
                    "SELECT usage_events.event_id, usage_events.account_id, usage_events.amount_units, "
                    "accounts.payment_address FROM usage_events "
                    "JOIN chain_account_state ON chain_account_state.account_id = usage_events.account_id "
                    "JOIN accounts ON accounts.account_id = usage_events.account_id "
                    "WHERE lower(usage_events.receipt_hash) = ? AND usage_events.chain_settled_at IS NULL "
                    "AND chain_account_state.chain_id = ? AND chain_account_state.settlement = ?"
                    + reservation_filter
                ),
                parameters,
            ).fetchall()
            for row in rows:
                expected_consumer = normalized_consumers.get(value)
                if expected_consumer is not None and str(row["payment_address"] or "").lower() != expected_consumer:
                    continue
                result = conn.execute(
                    (
                        "UPDATE usage_events SET chain_settled_at = ?, chain_settled_block = ?, "
                        "chain_settled_chain_id = ?, chain_settled_settlement = ? "
                        "WHERE event_id = ? AND chain_settled_at IS NULL"
                    ),
                    (
                        int(settled_at),
                        int(settled_block),
                        int(chain_id),
                        settlement,
                        str(row["event_id"]),
                    ),
                )
                if int(result.rowcount or 0) != 1:
                    continue
                conn.execute(
                    (
                        "UPDATE chain_account_state SET pending_spend_units = "
                        "MAX(0, pending_spend_units - ?) WHERE account_id = ? AND chain_id = ? AND settlement = ?"
                    ),
                    (int(row["amount_units"]), str(row["account_id"]), int(chain_id), settlement),
                )
                confirmed += 1
        return confirmed

    def _sync_chain_balance_tx(
        self,
        conn: sqlite3.Connection,
        *,
        account_id: str,
        observed_balance_units: int,
        metadata: dict[str, object] | None,
        clear_reorg: bool = False,
    ) -> sqlite3.Row:
        account = conn.execute(
            self._for_update("SELECT * FROM accounts WHERE account_id = ?"),
            (account_id,),
        ).fetchone()
        if account is None:
            raise BillingError(f"account not found: {account_id}")
        state = conn.execute(
            self._for_update("SELECT * FROM chain_account_state WHERE account_id = ?"),
            (account_id,),
        ).fetchone()
        if state is None:
            pending_spend_units = int(
                conn.execute(
                    (
                        "SELECT COALESCE(SUM(amount_units), 0) AS total FROM usage_events "
                        "WHERE account_id = ? AND chain_settled_at IS NULL"
                    ),
                    (account_id,),
                ).fetchone()["total"]
            )
        else:
            pending_spend_units = int(state["pending_spend_units"])
            if metadata is not None:
                old_chain_id = int(state["chain_id"])
                old_settlement = str(state["settlement"] or "").lower()
                new_chain_id = int(metadata["chain_id"])
                new_settlement = str(metadata["settlement"]).lower()
                if (old_chain_id not in {0, new_chain_id} or old_settlement not in {"", new_settlement}) and pending_spend_units:
                    raise BillingError("cannot change chain balance source while unsettled local spend exists")
        locked_units = int(
            conn.execute(
                "SELECT COALESCE(SUM(amount_units), 0) AS total FROM reservations WHERE account_id = ? AND status = 'reserved'",
                (account_id,),
            ).fetchone()["total"]
        )
        reorg_detected = bool(state is not None and int(state["reorg_detected"])) and not clear_reorg
        available_units = 0 if reorg_detected else max(
            0,
            int(observed_balance_units) - pending_spend_units - locked_units,
        )
        if metadata is None:
            values = {
                "chain_id": int(state["chain_id"]) if state is not None else 0,
                "settlement": str(state["settlement"]) if state is not None else "",
                "latest_block": int(state["latest_block"]) if state is not None else -1,
                "synced_block": int(state["synced_block"]) if state is not None else -1,
                "synced_block_hash": state["synced_block_hash"] if state is not None else None,
                "confirmations": int(state["confirmations"]) if state is not None else 0,
                "synced_at": int(state["synced_at"]) if state is not None else 0,
                "source": str(state["source"]) if state is not None else "",
                "reorg_detected": 0 if clear_reorg or state is None else int(state["reorg_detected"]),
                "metadata_pending": 1,
            }
        else:
            values = {
                **metadata,
                "reorg_detected": 0 if clear_reorg or state is None else int(state["reorg_detected"]),
                "metadata_pending": 0,
            }
        conn.execute(
            (
                "INSERT INTO chain_account_state(account_id, chain_id, settlement, observed_balance_units, pending_spend_units, "
                "latest_block, synced_block, synced_block_hash, confirmations, synced_at, source, reorg_detected, metadata_pending) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(account_id) DO UPDATE SET chain_id = excluded.chain_id, settlement = excluded.settlement, "
                "observed_balance_units = excluded.observed_balance_units, pending_spend_units = excluded.pending_spend_units, "
                "latest_block = excluded.latest_block, synced_block = excluded.synced_block, "
                "synced_block_hash = excluded.synced_block_hash, confirmations = excluded.confirmations, "
                "synced_at = excluded.synced_at, source = excluded.source, "
                "reorg_detected = excluded.reorg_detected, "
                "metadata_pending = excluded.metadata_pending"
            ),
            (
                account_id,
                int(values["chain_id"]),
                str(values["settlement"]).lower(),
                int(observed_balance_units),
                pending_spend_units,
                int(values["latest_block"]),
                int(values["synced_block"]),
                values["synced_block_hash"],
                int(values["confirmations"]),
                int(values["synced_at"]),
                str(values["source"]),
                int(values["reorg_detected"]),
                int(values["metadata_pending"]),
            ),
        )
        conn.execute(
            "UPDATE accounts SET balance_units = ? WHERE account_id = ?",
            (available_units, account_id),
        )
        return conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()

    def debit(self, account_id: str, amount_units: int, event_id: str, receipt: dict | None = None) -> ConsumerAccount:
        if amount_units <= 0:
            raise BillingError("debit amount must be positive")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "usage-event", event_id)
            existing = self._existing_event(conn, event_id)
            if existing is not None:
                if str(existing["account_id"]) == account_id and int(existing["amount_units"]) == int(amount_units):
                    row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
                    if row is None:
                        raise BillingError(f"account not found: {account_id}")
                    return _account_from_row(row)
                raise BillingError("duplicate event_id")
            row = conn.execute(
                self._for_update("SELECT * FROM accounts WHERE account_id = ?"),
                (account_id,),
            ).fetchone()
            if row is None:
                raise BillingError(f"account not found: {account_id}")
            self._require_active(row)
            if int(row["balance_units"]) < amount_units:
                raise BillingError("insufficient prepaid balance")
            self._require_quota(conn, row, amount_units)
            result = conn.execute(
                "UPDATE accounts SET balance_units = balance_units - ? WHERE account_id = ? AND status = 'active' AND balance_units >= ?",
                (amount_units, account_id, amount_units),
            )
            if int(result.rowcount or 0) != 1:
                raise BillingError("insufficient prepaid balance")
            self._increment_usage(conn, account_id, amount_units)
            conn.execute(
                (
                    "INSERT INTO usage_events(event_id, account_id, reservation_id, amount_units, receipt_json, "
                    "receipt_hash, onchain_reservation_id, created_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?)"
                ),
                (
                    event_id,
                    account_id,
                    amount_units,
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True) if receipt else None,
                    _receipt_hash(receipt) if receipt else None,
                    _receipt_onchain_reservation_id(receipt),
                    int(time.time()),
                ),
            )
            conn.execute(
                "UPDATE chain_account_state SET pending_spend_units = pending_spend_units + ? WHERE account_id = ?",
                (amount_units, account_id),
            )
            updated = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(updated)

    def reserve(self, account_id: str, amount_units: int, reservation_id: str) -> ConsumerAccount:
        if amount_units <= 0:
            raise BillingError("reservation amount must be positive")
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            updated = self._reserve_tx(conn, account_id, amount_units, reservation_id, now=now)
        return _account_from_row(updated)

    def reserve_with_chain_guard(
        self,
        account_id: str,
        amount_units: int,
        reservation_id: str,
        *,
        chain_id: int,
        settlement: str,
        max_age_seconds: int,
        max_block_lag: int,
        min_confirmations: int = 0,
    ) -> ConsumerAccount:
        if amount_units <= 0:
            raise BillingError("reservation amount must be positive")
        normalized_settlement = _normalize_settlement_address(settlement)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "chain-indexer", shared=True)
            account = conn.execute(
                self._for_update("SELECT account_id FROM accounts WHERE account_id = ?"),
                (account_id,),
            ).fetchone()
            if account is None:
                raise BillingError(f"account not found: {account_id}")
            global_state = conn.execute(
                self._for_update("SELECT * FROM chain_sync_state WHERE id = 1")
            ).fetchone()
            if global_state is None:
                raise ChainBalanceUnavailable("global on-chain balance cache has never been synchronized")
            state = conn.execute(
                self._for_update("SELECT * FROM chain_account_state WHERE account_id = ?"),
                (account_id,),
            ).fetchone()
            if state is None:
                raise ChainBalanceUnavailable(
                    f"on-chain balance cache for account {account_id} has never been synchronized"
                )
            try:
                reference_latest_block = None
                if global_state is not None:
                    self._validate_chain_sync_state(
                        dict(global_state),
                        chain_id=int(chain_id),
                        settlement=normalized_settlement,
                        max_age_seconds=int(max_age_seconds),
                        max_block_lag=int(max_block_lag),
                        min_confirmations=int(min_confirmations),
                    )
                    reference_latest_block = int(global_state["latest_block"])
                self._validate_chain_sync_state(
                    dict(state),
                    chain_id=int(chain_id),
                    settlement=normalized_settlement,
                    max_age_seconds=int(max_age_seconds),
                    max_block_lag=int(max_block_lag),
                    min_confirmations=int(min_confirmations),
                    reference_latest_block=reference_latest_block,
                )
            except BillingError as exc:
                raise ChainBalanceUnavailable(str(exc)) from exc
            updated = self._reserve_tx(conn, account_id, amount_units, reservation_id, now=now)
        return _account_from_row(updated)

    def _reserve_tx(
        self,
        conn: sqlite3.Connection,
        account_id: str,
        amount_units: int,
        reservation_id: str,
        *,
        now: int,
    ) -> sqlite3.Row:
        self._transaction_lock(conn, "reservation", reservation_id)
        existing = conn.execute(
            self._for_update("SELECT * FROM reservations WHERE reservation_id = ?"),
            (reservation_id,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing["account_id"]) == account_id
                and int(existing["amount_units"]) == int(amount_units)
                and str(existing["status"]) == "reserved"
            ):
                row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
                if row is None:
                    raise BillingError(f"account not found: {account_id}")
                return row
            raise BillingError("duplicate reservation_id")
        row = conn.execute(
            self._for_update("SELECT * FROM accounts WHERE account_id = ?"),
            (account_id,),
        ).fetchone()
        if row is None:
            raise BillingError(f"account not found: {account_id}")
        self._require_active(row)
        if int(row["balance_units"]) < amount_units:
            raise BillingError("insufficient prepaid balance")
        self._require_quota(conn, row, amount_units)
        result = conn.execute(
            (
                "UPDATE accounts SET balance_units = balance_units - ? "
                "WHERE account_id = ? AND status = 'active' AND balance_units >= ?"
            ),
            (amount_units, account_id, amount_units),
        )
        if int(result.rowcount or 0) != 1:
            raise BillingError("insufficient prepaid balance")
        conn.execute(
            (
                "INSERT INTO reservations(reservation_id, account_id, amount_units, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'reserved', ?, ?)"
            ),
            (reservation_id, account_id, amount_units, now, now),
        )
        updated = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if updated is None:
            raise BillingError(f"account not found: {account_id}")
        return updated

    def capture(
        self,
        reservation_id: str,
        final_amount_units: int,
        event_id: str,
        receipt: dict | None = None,
        outbox_payload: dict | None = None,
    ) -> ConsumerAccount:
        if final_amount_units <= 0:
            raise BillingError("capture amount must be positive")
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "reservation", reservation_id)
            self._transaction_lock(conn, "usage-event", event_id)
            existing = self._existing_event(conn, event_id)
            if existing is not None:
                if (
                    str(existing["reservation_id"] or "") == reservation_id
                    and int(existing["amount_units"]) == int(final_amount_units)
                ):
                    row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (str(existing["account_id"]),)).fetchone()
                    if row is None:
                        raise BillingError(f"account not found: {existing['account_id']}")
                    return _account_from_row(row)
                raise BillingError("duplicate event_id")
            reservation = conn.execute(
                self._for_update("SELECT * FROM reservations WHERE reservation_id = ?"),
                (reservation_id,),
            ).fetchone()
            if reservation is None:
                raise BillingError(f"reservation not found: {reservation_id}")
            if str(reservation["status"]) != "reserved":
                raise BillingError(f"reservation is not open: {reservation_id}")
            reserved_units = int(reservation["amount_units"])
            account_id = str(reservation["account_id"])
            if final_amount_units > reserved_units:
                raise BillingError("capture amount exceeds reserved max_fee")
            row = conn.execute(
                self._for_update("SELECT * FROM accounts WHERE account_id = ?"),
                (account_id,),
            ).fetchone()
            if row is None:
                raise BillingError(f"account not found: {account_id}")
            self._require_active(row)
            self._require_quota(conn, row, final_amount_units, exclude_reservation_id=reservation_id)
            transition = conn.execute(
                "UPDATE reservations SET status = 'captured', amount_units = ?, updated_at = ? WHERE reservation_id = ? AND status = 'reserved'",
                (final_amount_units, now, reservation_id),
            )
            if int(transition.rowcount or 0) != 1:
                raise BillingError(f"reservation is not open: {reservation_id}")
            if final_amount_units < reserved_units:
                refund = reserved_units - final_amount_units
                self._refund_available_balance_tx(conn, account_id, refund)
            conn.execute(
                (
                    "INSERT INTO usage_events(event_id, account_id, reservation_id, amount_units, receipt_json, "
                    "receipt_hash, onchain_reservation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                ),
                (
                    event_id,
                    account_id,
                    reservation_id,
                    final_amount_units,
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True) if receipt else None,
                    _receipt_hash(receipt) if receipt else None,
                    _receipt_onchain_reservation_id(receipt),
                    now,
                ),
            )
            conn.execute(
                "UPDATE chain_account_state SET pending_spend_units = pending_spend_units + ? WHERE account_id = ?",
                (final_amount_units, account_id),
            )
            self._increment_usage(conn, account_id, final_amount_units)
            if outbox_payload is not None:
                conn.execute(
                    (
                        "INSERT INTO receipt_outbox(receipt_id, account_id, payload_json, exported_at, status, claim_token, claimed_at, attempt_count) "
                        "VALUES (?, ?, ?, NULL, 'pending', NULL, NULL, 0)"
                    ),
                    (
                        event_id,
                        account_id,
                        json.dumps(outbox_payload, ensure_ascii=False, sort_keys=True),
                    ),
                )
            updated = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(updated)

    def claim_pending_receipts(
        self,
        limit: int = 100,
        *,
        claim_timeout_seconds: int = 300,
    ) -> list[dict[str, object]]:
        claim_token = secrets.token_urlsafe(24)
        now = int(time.time())
        stale_before = now - max(1, int(claim_timeout_seconds))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                (
                    "UPDATE receipt_outbox SET status = 'pending', claim_token = NULL, claimed_at = NULL "
                    "WHERE status = 'claimed' AND exported_at IS NULL AND claimed_at IS NOT NULL AND claimed_at <= ?"
                ),
                (stale_before,),
            )
            if self.is_postgresql:
                rows = conn.execute(
                    (
                        "SELECT receipt_id FROM receipt_outbox WHERE status = 'pending' "
                        "ORDER BY receipt_id ASC LIMIT ? FOR UPDATE SKIP LOCKED"
                    ),
                    (max(1, int(limit)),),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT receipt_id FROM receipt_outbox WHERE status = 'pending' ORDER BY rowid ASC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
            receipt_ids = [str(row["receipt_id"]) for row in rows]
            if not receipt_ids:
                return []
            placeholders = ",".join("?" for _ in receipt_ids)
            conn.execute(
                (
                    f"UPDATE receipt_outbox SET status = 'claimed', claim_token = ?, claimed_at = ?, "
                    f"attempt_count = attempt_count + 1 WHERE status = 'pending' AND receipt_id IN ({placeholders})"
                ),
                (claim_token, now, *receipt_ids),
            )
            order_column = "receipt_id" if self.is_postgresql else "rowid"
            claimed = conn.execute(
                (
                    f"SELECT * FROM receipt_outbox WHERE claim_token = ? AND status = 'claimed' "
                    f"AND receipt_id IN ({placeholders}) ORDER BY {order_column} ASC"
                ),
                (claim_token, *receipt_ids),
            ).fetchall()
        return [dict(row) for row in claimed]

    def pending_receipts(
        self,
        limit: int = 100,
        *,
        claim_timeout_seconds: int = 300,
    ) -> list[dict[str, object]]:
        return self.claim_pending_receipts(limit=limit, claim_timeout_seconds=claim_timeout_seconds)

    def mark_receipt_exported(self, receipt_id: str, claim_token: str | None = None) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if claim_token is None:
                result = conn.execute(
                    (
                        "UPDATE receipt_outbox SET exported_at = ?, status = 'exported' "
                        "WHERE receipt_id = ? AND status = 'claimed'"
                    ),
                    (int(time.time()), receipt_id),
                )
            else:
                result = conn.execute(
                    (
                        "UPDATE receipt_outbox SET exported_at = ?, status = 'exported' "
                        "WHERE receipt_id = ? AND status = 'claimed' AND claim_token = ?"
                    ),
                    (int(time.time()), receipt_id, claim_token),
                )
        return int(result.rowcount or 0) == 1

    def release_receipt_claim(self, receipt_id: str, claim_token: str) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            result = conn.execute(
                (
                    "UPDATE receipt_outbox SET status = 'pending', claim_token = NULL, claimed_at = NULL "
                    "WHERE receipt_id = ? AND status = 'claimed' AND claim_token = ?"
                ),
                (receipt_id, claim_token),
            )
        return int(result.rowcount or 0) == 1

    def release(self, reservation_id: str) -> ConsumerAccount | None:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "reservation", reservation_id)
            reservation = conn.execute(
                self._for_update("SELECT * FROM reservations WHERE reservation_id = ?"),
                (reservation_id,),
            ).fetchone()
            if reservation is None or str(reservation["status"]) != "reserved":
                return None
            account_id = str(reservation["account_id"])
            amount_units = int(reservation["amount_units"])
            transition = conn.execute(
                "UPDATE reservations SET status = 'released', updated_at = ? WHERE reservation_id = ? AND status = 'reserved'",
                (now, reservation_id),
            )
            if int(transition.rowcount or 0) != 1:
                return None
            self._refund_available_balance_tx(conn, account_id, amount_units)
            updated = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(updated) if updated is not None else None

    def release_expired_reservations(self, max_age_seconds: int) -> int:
        if max_age_seconds <= 0:
            raise BillingError("max_age_seconds must be positive")
        now = int(time.time())
        cutoff = now - int(max_age_seconds)
        released = 0
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            reservation_query = (
                "SELECT * FROM reservations WHERE status = 'reserved' AND created_at <= ?"
            )
            if self.is_postgresql:
                reservation_query += " FOR UPDATE SKIP LOCKED"
            rows = conn.execute(
                reservation_query,
                (cutoff,),
            ).fetchall()
            for reservation in rows:
                account_id = str(reservation["account_id"])
                amount_units = int(reservation["amount_units"])
                transition = conn.execute(
                    (
                        "UPDATE reservations SET status = 'expired', updated_at = ? "
                        "WHERE reservation_id = ? AND status = 'reserved'"
                    ),
                    (now, str(reservation["reservation_id"])),
                )
                if int(transition.rowcount or 0) != 1:
                    continue
                self._refund_available_balance_tx(conn, account_id, amount_units)
                released += 1
        return released

    def _refund_available_balance_tx(
        self,
        conn: sqlite3.Connection,
        account_id: str,
        amount_units: int,
    ) -> None:
        conn.execute(
            (
                "UPDATE accounts SET balance_units = balance_units + ? WHERE account_id = ? "
                "AND NOT EXISTS (SELECT 1 FROM chain_account_state "
                "WHERE chain_account_state.account_id = accounts.account_id "
                "AND chain_account_state.reorg_detected = 1)"
            ),
            (int(amount_units), account_id),
        )

    def create_key_challenge(
        self,
        *,
        wallet: str,
        key_hash: str,
        chain_id: int = 0,
        ttl_seconds: int = 600,
        nonce: str | None = None,
        now: int | None = None,
        capacity: int = DEFAULT_KEY_CHALLENGE_CAPACITY,
        rate_per_minute: int = DEFAULT_KEY_CHALLENGE_RATE_PER_MINUTE,
    ) -> dict[str, object]:
        wallet = normalize_payment_address(wallet)
        if wallet is None:
            raise BillingError("wallet is required")
        normalized_key_hash = normalize_api_key_hash(key_hash)
        ttl = max(1, int(ttl_seconds))
        maximum = _bounded_key_challenge_limit(
            capacity,
            label="key challenge capacity",
            maximum=MAX_KEY_CHALLENGE_CAPACITY,
        )
        issuance_rate = _bounded_key_challenge_limit(
            rate_per_minute,
            label="key challenge rate_per_minute",
            maximum=MAX_KEY_CHALLENGE_RATE_PER_MINUTE,
        )
        challenge_nonce = _challenge_nonce(nonce)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._transaction_lock(conn, "key-challenge-issuance")
            timestamp = int(now if now is not None else time.time())
            payload = {
                "wallet": wallet,
                "key_hash": normalized_key_hash,
                "chain_id": int(chain_id),
                "nonce": challenge_nonce,
                "expires_at": timestamp + ttl,
            }
            conn.execute(
                "DELETE FROM key_challenges WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND created_at <= ?)",
                (timestamp, timestamp - 60),
            )
            active = int(
                conn.execute(
                    "SELECT COUNT(*) FROM key_challenges WHERE consumed_at IS NULL"
                ).fetchone()[0]
            )
            if active >= maximum:
                raise BillingError("key registration challenge capacity exceeded")
            issued_recently = int(
                conn.execute(
                    "SELECT COUNT(*) FROM key_challenges WHERE created_at > ?",
                    (timestamp - 60,),
                ).fetchone()[0]
            )
            if issued_recently >= issuance_rate:
                raise BillingError("key registration challenge rate limit exceeded")
            conn.execute(
                (
                    "INSERT INTO key_challenges(nonce, wallet, key_hash, chain_id, expires_at, consumed_at, created_at) "
                    "VALUES (?, ?, ?, ?, ?, NULL, ?)"
                ),
                (
                    challenge_nonce,
                    wallet,
                    normalized_key_hash,
                    int(chain_id),
                    int(payload["expires_at"]),
                    timestamp,
                ),
            )
        return payload

    def consume_key_challenge(
        self,
        *,
        wallet: str,
        key_hash: str,
        chain_id: int,
        nonce: str,
        verification_token: str | None = None,
        now: int | None = None,
    ) -> dict[str, object]:
        wallet = normalize_payment_address(wallet)
        if wallet is None:
            raise BillingError("wallet is required")
        normalized_key_hash = normalize_api_key_hash(key_hash)
        challenge_nonce = _challenge_nonce(nonce)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            timestamp = int(now if now is not None else time.time())
            row = self._consume_key_challenge_tx(
                conn,
                wallet=wallet,
                normalized_key_hash=normalized_key_hash,
                chain_id=int(chain_id),
                challenge_nonce=challenge_nonce,
                verification_token=verification_token,
                now=timestamp,
            )
        return dict(row)

    def _consume_key_challenge_tx(
        self,
        conn: sqlite3.Connection,
        *,
        wallet: str,
        normalized_key_hash: str,
        chain_id: int,
        challenge_nonce: str,
        verification_token: str | None,
        now: int,
    ) -> sqlite3.Row:
        row = conn.execute(
            self._for_update("SELECT * FROM key_challenges WHERE nonce = ?"),
            (challenge_nonce,),
        ).fetchone()
        _validate_key_challenge_row(
            row,
            wallet=wallet,
            key_hash=normalized_key_hash,
            chain_id=chain_id,
            now=now,
        )
        stored_token = str(row["verification_token"] or "")
        supplied_token = str(verification_token or "")
        if stored_token and not supplied_token:
            raise BillingError("key registration verification claim token is required")
        if supplied_token and not secrets.compare_digest(stored_token, supplied_token):
            raise BillingError("key registration verification claim is no longer current")
        token_clause = " AND verification_token = ?" if supplied_token else " AND verification_token IS NULL"
        parameters: tuple[object, ...] = (now, challenge_nonce, now)
        if supplied_token:
            parameters += (supplied_token,)
        consumed = conn.execute(
            (
                "UPDATE key_challenges SET consumed_at = ?, verification_token = NULL, "
                "verification_started_at = NULL "
                "WHERE nonce = ? AND consumed_at IS NULL AND expires_at > ?" + token_clause
            ),
            parameters,
        )
        if int(consumed.rowcount or 0) != 1:
            raise BillingError("key registration challenge has already been consumed or expired")
        return row

    def consume_key_challenge_and_register_key_hash(
        self,
        *,
        account_id: str,
        wallet: str,
        key_hash: str,
        chain_id: int,
        nonce: str,
        verification_token: str,
        payment_address: str | None = None,
        credential_origin: str | None = None,
        credential_network_id: str | None = None,
        credential_chain_id: int | None = None,
        credential_settlement: str | None = None,
        now: int | None = None,
    ) -> ConsumerAccount:
        normalized_wallet = normalize_payment_address(wallet)
        if normalized_wallet is None:
            raise BillingError("wallet is required")
        if str(account_id).lower() != normalized_wallet:
            raise BillingError("key registration account_id must match the challenge wallet")
        normalized_key_hash = normalize_api_key_hash(key_hash)
        normalized_payment_address = normalize_payment_address(payment_address)
        if normalized_payment_address is not None and normalized_payment_address != normalized_wallet:
            raise BillingError("key registration payment_address must match the challenge wallet")
        credential_scope = _normalize_credential_scope(
            credential_origin,
            credential_network_id,
            credential_chain_id,
            credential_settlement,
        )
        if credential_scope[2] is not None and int(credential_scope[2]) != int(chain_id):
            raise BillingError("key registration credential_chain_id must match the challenge chain_id")
        challenge_nonce = _challenge_nonce(nonce)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            timestamp = int(now if now is not None else time.time())
            self._consume_key_challenge_tx(
                conn,
                wallet=normalized_wallet,
                normalized_key_hash=normalized_key_hash,
                chain_id=int(chain_id),
                challenge_nonce=challenge_nonce,
                verification_token=verification_token,
                now=timestamp,
            )
            row = self._register_key_hash_tx(
                conn,
                account_id=str(account_id),
                normalized_key_hash=normalized_key_hash,
                payment_address=normalized_payment_address,
                credential_scope=credential_scope,
                fingerprint=_api_key_hash_fingerprint(normalized_key_hash),
                now=timestamp,
            )
        return _account_from_row(row)

    def claim_key_challenge_verification(
        self,
        *,
        wallet: str,
        key_hash: str,
        chain_id: int,
        nonce: str,
        now: int | None = None,
        max_attempts: int = DEFAULT_KEY_CHALLENGE_VERIFICATION_ATTEMPTS,
    ) -> dict[str, object]:
        normalized_wallet = normalize_payment_address(wallet)
        if normalized_wallet is None:
            raise BillingError("wallet is required")
        normalized_key_hash = normalize_api_key_hash(key_hash)
        challenge_nonce = _challenge_nonce(nonce)
        attempt_limit = _bounded_key_challenge_limit(
            max_attempts,
            label="key challenge verification max_attempts",
            maximum=MAX_KEY_CHALLENGE_VERIFICATION_ATTEMPTS,
        )
        claim_token = secrets.token_urlsafe(24)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            timestamp = int(now if now is not None else time.time())
            row = conn.execute(
                self._for_update("SELECT * FROM key_challenges WHERE nonce = ?"),
                (challenge_nonce,),
            ).fetchone()
            _validate_key_challenge_row(
                row,
                wallet=normalized_wallet,
                key_hash=normalized_key_hash,
                chain_id=int(chain_id),
                now=timestamp,
            )
            stored_token = str(row["verification_token"] or "")
            if stored_token:
                raise KeyChallengeVerificationInProgress(
                    "key registration verification is already in progress"
                )
            if int(row["verification_attempts"] or 0) >= attempt_limit:
                raise KeyChallengeVerificationLimitExceeded(
                    "key registration verification attempt limit exceeded"
                )
            claimed = conn.execute(
                (
                    "UPDATE key_challenges SET verification_token = ?, verification_started_at = ?, "
                    "verification_attempts = verification_attempts + 1 "
                    "WHERE nonce = ? AND consumed_at IS NULL AND expires_at > ? "
                    "AND verification_token IS NULL"
                ),
                (claim_token, timestamp, challenge_nonce, timestamp),
            )
            if int(claimed.rowcount or 0) != 1:
                raise KeyChallengeVerificationInProgress(
                    "key registration verification is already in progress"
                )
            claimed_row = conn.execute(
                "SELECT * FROM key_challenges WHERE nonce = ?",
                (challenge_nonce,),
            ).fetchone()
        result = dict(claimed_row)
        result["verification_token"] = claim_token
        return result

    def release_key_challenge_verification(self, nonce: str, verification_token: str) -> bool:
        challenge_nonce = _challenge_nonce(nonce)
        token = str(verification_token or "").strip()
        if not token:
            return False
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            released = conn.execute(
                (
                    "UPDATE key_challenges SET verification_token = NULL, verification_started_at = NULL "
                    "WHERE nonce = ? AND consumed_at IS NULL AND verification_token = ?"
                ),
                (challenge_nonce, token),
            )
        return int(released.rowcount or 0) == 1

    def rollback_key_challenge_verification_claim(
        self,
        nonce: str,
        verification_token: str,
    ) -> bool:
        """Undo a claim only when its executor submission never succeeded."""
        challenge_nonce = _challenge_nonce(nonce)
        token = str(verification_token or "").strip()
        if not token:
            return False
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            released = conn.execute(
                (
                    "UPDATE key_challenges SET verification_token = NULL, verification_started_at = NULL, "
                    "verification_attempts = CASE WHEN verification_attempts > 0 "
                    "THEN verification_attempts - 1 ELSE 0 END "
                    "WHERE nonce = ? AND consumed_at IS NULL AND verification_token = ?"
                ),
                (challenge_nonce, token),
            )
        return int(released.rowcount or 0) == 1

    def validate_key_challenge(
        self,
        *,
        wallet: str,
        key_hash: str,
        chain_id: int,
        nonce: str,
        now: int | None = None,
    ) -> dict[str, object]:
        normalized_wallet = normalize_payment_address(wallet)
        if normalized_wallet is None:
            raise BillingError("wallet is required")
        normalized_key_hash = normalize_api_key_hash(key_hash)
        challenge_nonce = _challenge_nonce(nonce)
        timestamp = int(now if now is not None else time.time())
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM key_challenges WHERE nonce = ?",
                (challenge_nonce,),
            ).fetchone()
        _validate_key_challenge_row(
            row,
            wallet=normalized_wallet,
            key_hash=normalized_key_hash,
            chain_id=int(chain_id),
            now=timestamp,
        )
        return dict(row)

    def get_key_challenge(self, nonce: str) -> dict[str, object] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM key_challenges WHERE nonce = ?", (_challenge_nonce(nonce),)).fetchone()
        return dict(row) if row is not None else None

    def _existing_event(self, conn: sqlite3.Connection, event_id: str) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM usage_events WHERE event_id = ?", (event_id,)).fetchone()

    def _require_active(self, row: sqlite3.Row) -> None:
        status = str(row["status"]) if "status" in row.keys() and row["status"] else "active"
        if status != "active":
            raise BillingError(f"account is {status}")

    def _require_quota(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        amount_units: int,
        exclude_reservation_id: str | None = None,
    ) -> None:
        quota = int(row["monthly_quota_units"]) if "monthly_quota_units" in row.keys() else 0
        if quota <= 0:
            return
        account_id = str(row["account_id"])
        used = self._current_period_usage(conn, row)
        reserved = self._pending_reserved_units(conn, account_id, exclude_reservation_id=exclude_reservation_id)
        if used + reserved + int(amount_units) > quota:
            raise BillingError("monthly quota exceeded")

    def _increment_usage(self, conn: sqlite3.Connection, account_id: str, amount_units: int) -> None:
        conn.execute(
            "UPDATE accounts SET monthly_used_units = monthly_used_units + ?, usage_period = ? WHERE account_id = ?",
            (int(amount_units), _current_usage_period(), account_id),
        )

    def _current_period_usage(self, conn: sqlite3.Connection, row: sqlite3.Row) -> int:
        used = int(row["monthly_used_units"]) if "monthly_used_units" in row.keys() else 0
        period = str(row["usage_period"]) if "usage_period" in row.keys() and row["usage_period"] else ""
        current_period = _current_usage_period()
        if not period:
            conn.execute(
                "UPDATE accounts SET usage_period = ? WHERE account_id = ?",
                (current_period, str(row["account_id"])),
            )
            return used
        if period == current_period:
            return used
        conn.execute(
            "UPDATE accounts SET monthly_used_units = 0, usage_period = ? WHERE account_id = ?",
            (current_period, str(row["account_id"])),
        )
        return 0

    def _pending_reserved_units(
        self,
        conn: sqlite3.Connection,
        account_id: str,
        exclude_reservation_id: str | None = None,
    ) -> int:
        if exclude_reservation_id is None:
            row = conn.execute(
                "SELECT COALESCE(SUM(amount_units), 0) AS amount FROM reservations WHERE account_id = ? AND status = 'reserved'",
                (account_id,),
            ).fetchone()
        else:
            row = conn.execute(
                (
                    "SELECT COALESCE(SUM(amount_units), 0) AS amount FROM reservations "
                    "WHERE account_id = ? AND status = 'reserved' AND reservation_id != ?"
                ),
                (account_id, exclude_reservation_id),
            ).fetchone()
        return int(row["amount"]) if row is not None else 0


def usdc_to_units(amount_usdc: str | Decimal) -> int:
    parsed = Decimal(str(amount_usdc))
    if parsed < 0:
        raise BillingError("amount must be non-negative")
    scaled = parsed * USDC_SCALE
    if scaled != scaled.to_integral_value():
        raise BillingError("amount supports at most 6 decimal places")
    return int(scaled)


def units_to_usdc(units: int) -> str:
    return format((Decimal(int(units)) / USDC_SCALE).quantize(Decimal("0.000001")), "f")


def normalize_payment_address(payment_address: str | None) -> str | None:
    if payment_address is None:
        return None
    value = str(payment_address).strip()
    if not value:
        return None
    if not EVM_ADDRESS_PATTERN.fullmatch(value):
        raise BillingError("payment_address must be an EVM address")
    return "0x" + value[2:].lower()


def _normalize_settlement_address(settlement: str) -> str:
    normalized = normalize_payment_address(settlement)
    if normalized is None or int(normalized[2:], 16) == 0:
        raise BillingError("settlement must be a non-zero EVM address")
    return normalized


def _validate_key_challenge_row(
    row: sqlite3.Row | None,
    *,
    wallet: str,
    key_hash: str,
    chain_id: int,
    now: int,
) -> None:
    if row is None:
        raise BillingError("key registration challenge not found")
    if row["consumed_at"] is not None:
        raise BillingError("key registration challenge has already been consumed")
    if str(row["wallet"]).lower() != wallet.lower():
        raise BillingError("key registration wallet does not match challenge")
    if str(row["key_hash"]).lower() != key_hash.lower():
        raise BillingError("key registration key_hash does not match challenge")
    if int(row["chain_id"]) != int(chain_id):
        raise BillingError("key registration chain_id does not match challenge")
    if int(row["expires_at"]) <= int(now):
        raise BillingError("key registration challenge expired")


def normalize_api_key_hash(key_hash: str) -> str:
    value = str(key_hash or "").strip()
    if not API_KEY_HASH_PATTERN.fullmatch(value):
        raise BillingError("key_hash must be a 32-byte sha256 hex digest")
    if value.startswith(("0x", "0X")):
        value = value[2:]
    return value.lower()


def _require_available_payment_address(
    conn: sqlite3.Connection,
    payment_address: str | None,
    *,
    account_id: str,
) -> None:
    if payment_address is None:
        return
    existing = conn.execute(
        (
            "SELECT account_id FROM accounts WHERE lower(payment_address) = lower(?) "
            "AND account_id != ? LIMIT 1"
        ),
        (payment_address, account_id),
    ).fetchone()
    if existing is not None:
        raise BillingError("payment_address is already registered to another account")


def _bps(value: int, label: str) -> int:
    parsed = int(value)
    if parsed < 0 or parsed > 10_000:
        raise BillingError(f"{label} must be between 0 and 10000")
    return parsed


def _account_from_row(row: sqlite3.Row) -> ConsumerAccount:
    return ConsumerAccount(
        account_id=str(row["account_id"]),
        api_key=str(row["api_key"]) if "api_key" in row.keys() and row["api_key"] else None,
        balance_units=int(row["balance_units"]),
        status=str(row["status"]) if "status" in row.keys() and row["status"] else "active",
        payment_address=str(row["payment_address"]) if "payment_address" in row.keys() and row["payment_address"] else None,
        key_fingerprint=str(row["key_fingerprint"]) if "key_fingerprint" in row.keys() and row["key_fingerprint"] else None,
        parent_account_id=str(row["parent_account_id"]) if "parent_account_id" in row.keys() and row["parent_account_id"] else None,
        discount_bps=int(row["discount_bps"]) if "discount_bps" in row.keys() else 0,
        reseller_margin_bps=int(row["reseller_margin_bps"]) if "reseller_margin_bps" in row.keys() else 0,
        monthly_quota_units=int(row["monthly_quota_units"]) if "monthly_quota_units" in row.keys() else 0,
        monthly_used_units=int(row["monthly_used_units"]) if "monthly_used_units" in row.keys() else 0,
        usage_period=str(row["usage_period"]) if "usage_period" in row.keys() and row["usage_period"] else "",
        usage_tier=str(row["usage_tier"]) if "usage_tier" in row.keys() and row["usage_tier"] else "standard",
        credential_origin=(
            str(row["credential_origin"])
            if "credential_origin" in row.keys() and row["credential_origin"]
            else None
        ),
        credential_network_id=(
            str(row["credential_network_id"])
            if "credential_network_id" in row.keys() and row["credential_network_id"]
            else None
        ),
        credential_chain_id=(
            int(row["credential_chain_id"])
            if "credential_chain_id" in row.keys() and row["credential_chain_id"] is not None
            else None
        ),
        credential_settlement=(
            str(row["credential_settlement"])
            if "credential_settlement" in row.keys() and row["credential_settlement"]
            else None
        ),
    )


def _normalize_credential_scope(
    origin: str | None,
    network_id: str | None,
    chain_id: int | None,
    settlement: str | None,
) -> tuple[str | None, str | None, int | None, str | None]:
    values = (origin, network_id, chain_id, settlement)
    if all(value is None for value in values):
        return None, None, None, None
    if any(value is None for value in values):
        raise BillingError("credential origin, network_id, chain_id, and settlement must be provided together")
    normalized_origin = str(origin).strip()
    normalized_network = str(network_id).strip()
    if not normalized_origin or len(normalized_origin) > 2048 or any(character.isspace() for character in normalized_origin):
        raise BillingError("credential_origin is invalid")
    if not normalized_network or len(normalized_network) > 128:
        raise BillingError("credential_network_id is invalid")
    try:
        normalized_chain = int(chain_id)
    except (TypeError, ValueError) as exc:
        raise BillingError("credential_chain_id must be an integer") from exc
    if normalized_chain < 0:
        raise BillingError("credential_chain_id must be non-negative")
    normalized_settlement = normalize_payment_address(str(settlement))
    if normalized_settlement is None or int(normalized_settlement[2:], 16) == 0:
        raise BillingError("credential_settlement must be a non-zero EVM address")
    return normalized_origin, normalized_network, normalized_chain, normalized_settlement


def _bounded_key_challenge_limit(value: int, *, label: str, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise BillingError(f"{label} must be an integer") from exc
    if parsed < 1 or parsed > maximum:
        raise BillingError(f"{label} must be between 1 and {maximum}")
    return parsed


def _api_key_hash(api_key: str) -> str:
    return hashlib.sha256(str(api_key).encode("utf-8")).hexdigest()


def _api_key_fingerprint(api_key: str) -> str:
    return _api_key_hash(api_key)[:12]


def _api_key_hash_fingerprint(key_hash: str) -> str:
    return normalize_api_key_hash(key_hash)[:12]


def _receipt_hash(receipt: dict) -> str:
    unsigned = {
        key: value
        for key, value in receipt.items()
        if key not in {"acceptance", "acceptance_signature", "accepted_hash"}
    }
    payload = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, default=str)
    return "0x" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _receipt_onchain_reservation_id(receipt: dict | None) -> str | None:
    if not isinstance(receipt, dict):
        return None
    value = str(receipt.get("onchain_reservation_id") or "").strip().lower()
    return value if re.fullmatch(r"0x[a-f0-9]{64}", value) else None


def _require_expected_chain_state_tx(
    conn: sqlite3.Connection,
    expected_state: dict[str, object] | None,
) -> sqlite3.Row | None:
    current = conn.execute("SELECT * FROM chain_sync_state WHERE id = 1").fetchone()
    if expected_state is None:
        if current is not None:
            raise ChainSyncSuperseded("chain sync state was initialized by another writer")
        return None
    if current is None:
        raise ChainSyncSuperseded("chain sync state was removed by another writer")
    try:
        expected_revision = int(expected_state["revision"])
        expected_chain_id = int(expected_state["chain_id"])
        expected_settlement = str(expected_state["settlement"]).lower()
        expected_synced_block = int(expected_state["synced_block"])
        expected_reorg = int(expected_state.get("reorg_detected") or 0)
        expected_hash = _normalize_block_hash(expected_state.get("synced_block_hash"))
    except (KeyError, TypeError, ValueError) as exc:
        raise BillingError("invalid expected chain sync state") from exc
    matches = (
        int(current["revision"]) == expected_revision
        and int(current["chain_id"]) == expected_chain_id
        and str(current["settlement"]).lower() == expected_settlement
        and int(current["synced_block"]) == expected_synced_block
        and int(current["reorg_detected"]) == expected_reorg
        and _normalize_block_hash(current["synced_block_hash"]) == expected_hash
    )
    if not matches:
        raise ChainSyncSuperseded("chain sync state was advanced by another writer")
    return current


def _normalize_block_hash(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not re.fullmatch(r"0x[a-f0-9]{64}", normalized):
        raise BillingError("block hash must be a 32-byte hex value")
    return normalized


def _validate_chain_cursor(
    *,
    latest_block: int,
    synced_block: int,
    confirmations: int,
    synced_block_hash: str | None,
) -> tuple[int, int, int, str | None]:
    latest = int(latest_block)
    synced = int(synced_block)
    confirmed = int(confirmations)
    if latest < 0 or synced < 0 or confirmed < 0:
        raise BillingError("chain cursor values cannot be negative")
    if synced > latest:
        raise BillingError("synced_block cannot exceed latest_block")
    if confirmed != latest - synced:
        raise BillingError("confirmations must equal latest_block - synced_block")
    block_hash = _normalize_block_hash(synced_block_hash)
    if confirmed > 0 and block_hash is None:
        raise BillingError("synced_block_hash is required for a confirmed chain cursor")
    return latest, synced, confirmed, block_hash


def _chain_log_identity(log: dict[str, object]) -> dict[str, object] | None:
    tx_hash = str(log.get("transactionHash") or "").lower()
    block_hash = str(log.get("blockHash") or "").lower()
    if not re.fullmatch(r"0x[a-f0-9]{64}", tx_hash) or not re.fullmatch(r"0x[a-f0-9]{64}", block_hash):
        return None
    try:
        log_index = _rpc_quantity(log.get("logIndex"))
        block_number = _rpc_quantity(log.get("blockNumber"))
    except (TypeError, ValueError):
        return None
    topics = log.get("topics")
    topic0 = str(topics[0]).lower() if isinstance(topics, list) and topics else ""
    return {
        "tx_hash": tx_hash,
        "log_index": log_index,
        "block_number": block_number,
        "block_hash": block_hash,
        "topic0": topic0,
    }


def _rpc_quantity(value: object) -> int:
    if isinstance(value, int):
        return value
    raw = str(value or "")
    if raw.startswith("0x"):
        return int(raw, 16)
    return int(raw)


def _challenge_nonce(nonce: str | None = None) -> str:
    value = str(nonce or "").strip()
    if not value:
        return "kreg_" + secrets.token_urlsafe(24)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", value):
        raise BillingError("challenge nonce must be 8-128 URL-safe characters")
    return value


def _current_usage_period() -> str:
    return time.strftime("%Y-%m", time.gmtime())
