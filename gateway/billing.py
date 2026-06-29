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


DEFAULT_BILLING_DB = ".codex-run/mycomesh-billing.sqlite3"
API_KEY_PREFIX = "msk"
USDC_SCALE = Decimal("1000000")
EVM_ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")


class BillingError(RuntimeError):
    pass


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

    @property
    def balance_usdc(self) -> str:
        return units_to_usdc(self.balance_units)


class BillingStore:
    def __init__(self, path: str | Path = DEFAULT_BILLING_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
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
            rows = conn.execute("SELECT account_id, api_key FROM accounts WHERE api_key_hash IS NULL AND api_key IS NOT NULL").fetchall()
            for row in rows:
                api_key = str(row["api_key"])
                conn.execute(
                    "UPDATE accounts SET api_key_hash = ?, key_fingerprint = ?, api_key = NULL WHERE account_id = ?",
                    (_api_key_hash(api_key), _api_key_fingerprint(api_key), str(row["account_id"])),
                )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_events (
                    event_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    reservation_id TEXT,
                    amount_units INTEGER NOT NULL,
                    receipt_json TEXT,
                    created_at INTEGER NOT NULL
                )
                """
            )
            usage_columns = {row["name"] for row in conn.execute("PRAGMA table_info(usage_events)").fetchall()}
            if "reservation_id" not in usage_columns:
                conn.execute("ALTER TABLE usage_events ADD COLUMN reservation_id TEXT")
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

    def create_account(self, account_id: str | None = None, payment_address: str | None = None) -> ConsumerAccount:
        payment_address = normalize_payment_address(payment_address)
        resolved_account_id = account_id or "acct_" + secrets.token_hex(8)
        api_key = API_KEY_PREFIX + "_" + secrets.token_urlsafe(32)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                (
                    "INSERT INTO accounts(account_id, api_key, api_key_hash, key_fingerprint, balance_units, payment_address, created_at) "
                    "VALUES (?, NULL, ?, ?, 0, ?, ?)"
                ),
                (resolved_account_id, _api_key_hash(api_key), _api_key_fingerprint(api_key), payment_address, now),
            )
        return ConsumerAccount(
            account_id=resolved_account_id,
            api_key=api_key,
            balance_units=0,
            status="active",
            payment_address=payment_address,
            key_fingerprint=_api_key_fingerprint(api_key),
        )

    def get_by_key(self, api_key: str) -> ConsumerAccount | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE api_key_hash = ?", (_api_key_hash(api_key),)).fetchone()
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

    def rotate_key(self, account_id: str) -> ConsumerAccount:
        api_key = API_KEY_PREFIX + "_" + secrets.token_urlsafe(32)
        with self._connect() as conn:
            conn.execute(
                "UPDATE accounts SET api_key = NULL, api_key_hash = ?, key_fingerprint = ? WHERE account_id = ?",
                (_api_key_hash(api_key), _api_key_fingerprint(api_key), account_id),
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
            conn.execute("UPDATE accounts SET payment_address = ? WHERE account_id = ?", (payment_address, account_id))
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
            conn.execute(
                "UPDATE accounts SET balance_units = ? WHERE account_id = ?",
                (amount_units, account_id),
            )
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if row is None:
            raise BillingError(f"account not found: {account_id}")
        return _account_from_row(row)

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
    ) -> None:
        now = int(synced_at if synced_at is not None else time.time())
        with self._connect() as conn:
            conn.execute(
                (
                    "INSERT INTO chain_sync_state(id, chain_id, settlement, latest_block, synced_block, confirmations, synced_at, source) "
                    "VALUES (1, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET chain_id = excluded.chain_id, settlement = excluded.settlement, "
                    "latest_block = excluded.latest_block, synced_block = excluded.synced_block, confirmations = excluded.confirmations, "
                    "synced_at = excluded.synced_at, source = excluded.source"
                ),
                (
                    int(chain_id),
                    str(settlement).lower(),
                    int(latest_block),
                    int(synced_block),
                    int(confirmations),
                    now,
                    str(source),
                ),
            )

    def get_chain_sync_state(self) -> dict[str, object] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM chain_sync_state WHERE id = 1").fetchone()
        return dict(row) if row is not None else None

    def require_fresh_chain_sync(
        self,
        *,
        chain_id: int,
        settlement: str,
        max_age_seconds: int,
        max_block_lag: int,
    ) -> dict[str, object]:
        state = self.get_chain_sync_state()
        if state is None:
            raise BillingError("on-chain balance cache has never been synchronized")
        if int(state["chain_id"]) != int(chain_id):
            raise BillingError("on-chain balance cache chain_id mismatch")
        if str(state["settlement"]).lower() != str(settlement).lower():
            raise BillingError("on-chain balance cache settlement mismatch")
        age = int(time.time()) - int(state["synced_at"])
        if age > int(max_age_seconds):
            raise BillingError("on-chain balance cache is stale")
        latest = int(state["latest_block"])
        synced = int(state["synced_block"])
        if latest - synced > int(max_block_lag):
            raise BillingError("on-chain balance cache block lag exceeded")
        return state

    def debit(self, account_id: str, amount_units: int, event_id: str, receipt: dict | None = None) -> ConsumerAccount:
        if amount_units <= 0:
            raise BillingError("debit amount must be positive")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = self._existing_event(conn, event_id)
            if existing is not None:
                if str(existing["account_id"]) == account_id and int(existing["amount_units"]) == int(amount_units):
                    row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
                    if row is None:
                        raise BillingError(f"account not found: {account_id}")
                    return _account_from_row(row)
                raise BillingError("duplicate event_id")
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
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
                "INSERT INTO usage_events(event_id, account_id, reservation_id, amount_units, receipt_json, created_at) VALUES (?, ?, NULL, ?, ?, ?)",
                (
                    event_id,
                    account_id,
                    amount_units,
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True) if receipt else None,
                    int(time.time()),
                ),
            )
            updated = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(updated)

    def reserve(self, account_id: str, amount_units: int, reservation_id: str) -> ConsumerAccount:
        if amount_units <= 0:
            raise BillingError("reservation amount must be positive")
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM reservations WHERE reservation_id = ?", (reservation_id,)).fetchone()
            if existing is not None:
                if (
                    str(existing["account_id"]) == account_id
                    and int(existing["amount_units"]) == int(amount_units)
                    and str(existing["status"]) == "reserved"
                ):
                    row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
                    return _account_from_row(row)
                raise BillingError("duplicate reservation_id")
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
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
            conn.execute(
                "INSERT INTO reservations(reservation_id, account_id, amount_units, status, created_at, updated_at) VALUES (?, ?, ?, 'reserved', ?, ?)",
                (reservation_id, account_id, amount_units, now, now),
            )
            updated = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(updated)

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
                "SELECT * FROM reservations WHERE reservation_id = ?",
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
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
            if row is None:
                raise BillingError(f"account not found: {account_id}")
            self._require_active(row)
            self._require_quota(conn, row, final_amount_units, exclude_reservation_id=reservation_id)
            if final_amount_units < reserved_units:
                refund = reserved_units - final_amount_units
                conn.execute(
                    "UPDATE accounts SET balance_units = balance_units + ? WHERE account_id = ?",
                    (refund, account_id),
                )
            conn.execute(
                "UPDATE reservations SET status = 'captured', amount_units = ?, updated_at = ? WHERE reservation_id = ? AND status = 'reserved'",
                (final_amount_units, now, reservation_id),
            )
            conn.execute(
                "INSERT INTO usage_events(event_id, account_id, reservation_id, amount_units, receipt_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    account_id,
                    reservation_id,
                    final_amount_units,
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True) if receipt else None,
                    now,
                ),
            )
            self._increment_usage(conn, account_id, final_amount_units)
            if outbox_payload is not None:
                conn.execute(
                    "INSERT INTO receipt_outbox(receipt_id, account_id, payload_json, exported_at) VALUES (?, ?, ?, NULL)",
                    (
                        event_id,
                        account_id,
                        json.dumps(outbox_payload, ensure_ascii=False, sort_keys=True),
                    ),
                )
            updated = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return _account_from_row(updated)

    def pending_receipts(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM receipt_outbox WHERE exported_at IS NULL ORDER BY rowid ASC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_receipt_exported(self, receipt_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE receipt_outbox SET exported_at = ? WHERE receipt_id = ?",
                (int(time.time()), receipt_id),
            )

    def release(self, reservation_id: str) -> ConsumerAccount | None:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            reservation = conn.execute(
                "SELECT * FROM reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if reservation is None or str(reservation["status"]) != "reserved":
                return None
            account_id = str(reservation["account_id"])
            amount_units = int(reservation["amount_units"])
            conn.execute(
                "UPDATE accounts SET balance_units = balance_units + ? WHERE account_id = ?",
                (amount_units, account_id),
            )
            conn.execute(
                "UPDATE reservations SET status = 'released', updated_at = ? WHERE reservation_id = ?",
                (now, reservation_id),
            )
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
            rows = conn.execute(
                "SELECT * FROM reservations WHERE status = 'reserved' AND created_at <= ?",
                (cutoff,),
            ).fetchall()
            for reservation in rows:
                account_id = str(reservation["account_id"])
                amount_units = int(reservation["amount_units"])
                conn.execute(
                    "UPDATE accounts SET balance_units = balance_units + ? WHERE account_id = ?",
                    (amount_units, account_id),
                )
                conn.execute(
                    "UPDATE reservations SET status = 'expired', updated_at = ? WHERE reservation_id = ?",
                    (now, str(reservation["reservation_id"])),
                )
                released += 1
        return released

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
    )


def _api_key_hash(api_key: str) -> str:
    return hashlib.sha256(str(api_key).encode("utf-8")).hexdigest()


def _api_key_fingerprint(api_key: str) -> str:
    return _api_key_hash(api_key)[:12]


def _current_usage_period() -> str:
    return time.strftime("%Y-%m", time.gmtime())
