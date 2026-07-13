from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from gateway.billing import BillingError, BillingStore
from gateway.database import (
    DatabaseTarget,
    PostgreSQLConnection,
    PostgreSQLRow,
    _translate_postgresql,
)


class FakeCursor:
    def __init__(self, rows: list[dict[str, object]] | None = None, rowcount: int = 0) -> None:
        self.rows = list(rows or [])
        self.rowcount = rowcount

    def fetchone(self) -> dict[str, object] | None:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[dict[str, object]]:
        return self.rows


class FakeBillingConnection:
    dialect = "postgresql"

    def __init__(self, handler) -> None:
        self.handler = handler
        self.statements: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self) -> "FakeBillingConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, sql: str, parameters=()) -> FakeCursor:
        values = tuple(parameters)
        self.statements.append((sql, values))
        return self.handler(sql, values)


class FakeRawCursor:
    rowcount = 1
    description = ()

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class FakeRawConnection:
    def __init__(self) -> None:
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def execute(self, sql: str, parameters=()) -> FakeRawCursor:
        self.statements.append((sql, tuple(parameters)))
        return FakeRawCursor()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closes += 1


def postgres_store() -> BillingStore:
    with patch.object(BillingStore, "_init", autospec=True):
        return BillingStore("postgresql://billing.example/myco")


class PostgreSQLDatabaseAdapterTest(unittest.TestCase):
    def test_database_target_selects_postgresql_without_treating_dsn_as_path(self) -> None:
        target = DatabaseTarget.parse("postgres://user:secret@db.example/myco")
        self.assertEqual(target.dialect, "postgresql")
        self.assertEqual(target.value, "postgres://user:secret@db.example/myco")

    def test_unknown_database_url_fails_closed(self) -> None:
        with patch.object(BillingStore, "_init", autospec=True):
            with self.assertRaisesRegex(BillingError, "unsupported billing database URL scheme"):
                BillingStore("mysql://db.example/myco")

    def test_missing_psycopg_fails_closed(self) -> None:
        store = postgres_store()
        with patch("gateway.database.importlib.import_module", side_effect=ModuleNotFoundError):
            with self.assertRaisesRegex(BillingError, "requires psycopg 3"):
                store._connect()

    def test_connection_error_fails_closed_without_exposing_dsn(self) -> None:
        store = postgres_store()
        driver = SimpleNamespace(
            __version__="3.2.1",
            connect=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")),
        )
        with patch("gateway.database.importlib.import_module", return_value=driver):
            with self.assertRaises(BillingError) as raised:
                store._connect()
        self.assertEqual(
            str(raised.exception),
            "unable to connect to the configured PostgreSQL billing database",
        )

    def test_sql_translation_preserves_literals_and_maps_sqlite_constructs(self) -> None:
        sql, parameters = _translate_postgresql(
            (
                "UPDATE ledger SET note = '?', pending_spend_units = "
                "MAX(0, pending_spend_units - ?) WHERE id = ?"
            ),
            (5, "event-1"),
        )
        self.assertEqual(
            sql,
            (
                "UPDATE ledger SET note = '?', pending_spend_units = "
                "GREATEST(0, pending_spend_units - %s) WHERE id = %s"
            ),
        )
        self.assertEqual(parameters, (5, "event-1"))

        ddl, _ = _translate_postgresql(
            "CREATE TABLE IF NOT EXISTS ledger (amount INTEGER NOT NULL)",
            (),
        )
        self.assertIn("amount BIGINT NOT NULL", ddl)

        pragma, pragma_parameters = _translate_postgresql("PRAGMA table_info(accounts)", ())
        self.assertIn("information_schema.columns", pragma)
        self.assertEqual(pragma_parameters, ("accounts",))

    def test_postgresql_connection_commits_or_rolls_back_context(self) -> None:
        committed = FakeRawConnection()
        with PostgreSQLConnection(committed) as conn:
            conn.execute("BEGIN IMMEDIATE")
        self.assertEqual(committed.statements, [("BEGIN", ())])
        self.assertEqual((committed.commits, committed.rollbacks, committed.closes), (1, 0, 1))

        rolled_back = FakeRawConnection()
        with self.assertRaisesRegex(RuntimeError, "abort"):
            with PostgreSQLConnection(rolled_back):
                raise RuntimeError("abort")
        self.assertEqual((rolled_back.commits, rolled_back.rollbacks, rolled_back.closes), (0, 1, 1))

    def test_postgresql_row_matches_sqlite_row_access_contract(self) -> None:
        row = PostgreSQLRow(("count", "account_id"), (2, "acct-a"))
        self.assertEqual(row[0], 2)
        self.assertEqual(row["account_id"], "acct-a")
        self.assertEqual(dict(row), {"count": 2, "account_id": "acct-a"})


class PostgreSQLBillingConcurrencyTest(unittest.TestCase):
    def test_reserve_locks_account_and_reservation_before_quota_check(self) -> None:
        store = postgres_store()
        account = {
            "account_id": "acct-a",
            "api_key": None,
            "balance_units": 900,
            "status": "active",
            "monthly_quota_units": 1_000,
            "monthly_used_units": 0,
            "usage_period": "",
        }

        def handle(sql: str, parameters: tuple[object, ...]) -> FakeCursor:
            if "FROM reservations WHERE reservation_id" in sql:
                return FakeCursor()
            if "COALESCE(SUM(amount_units), 0) AS amount" in sql:
                return FakeCursor([{"amount": 0}])
            if "FROM accounts WHERE account_id" in sql:
                return FakeCursor([account])
            if sql.startswith("UPDATE accounts SET balance_units = balance_units -"):
                return FakeCursor(rowcount=1)
            return FakeCursor(rowcount=1)

        connection = FakeBillingConnection(handle)
        with patch.object(store, "_connect", return_value=connection):
            result = store.reserve("acct-a", 100, "reservation-1")

        statements = [sql for sql, _ in connection.statements]
        self.assertTrue(any("pg_advisory_xact_lock" in sql for sql in statements))
        self.assertTrue(
            any(
                "FROM reservations WHERE reservation_id = ? FOR UPDATE" in sql
                for sql in statements
            )
        )
        self.assertTrue(
            any("FROM accounts WHERE account_id = ? FOR UPDATE" in sql for sql in statements)
        )
        account_lock_index = next(
            index
            for index, sql in enumerate(statements)
            if "FROM accounts WHERE account_id = ? FOR UPDATE" in sql
        )
        quota_query_index = next(
            index
            for index, sql in enumerate(statements)
            if "COALESCE(SUM(amount_units), 0) AS amount" in sql
        )
        self.assertLess(account_lock_index, quota_query_index)
        self.assertEqual(result.account_id, "acct-a")

    def test_capture_and_release_lock_the_reservation_transition(self) -> None:
        store = postgres_store()
        account = {
            "account_id": "acct-a",
            "api_key": None,
            "balance_units": 900,
            "status": "active",
            "monthly_quota_units": 0,
        }
        reservation = {
            "reservation_id": "reservation-1",
            "account_id": "acct-a",
            "amount_units": 100,
            "status": "reserved",
        }

        def handle(sql: str, parameters: tuple[object, ...]) -> FakeCursor:
            if "FROM usage_events WHERE event_id" in sql:
                return FakeCursor()
            if "FROM reservations WHERE reservation_id" in sql:
                return FakeCursor([reservation])
            if "FROM accounts WHERE account_id" in sql:
                return FakeCursor([account])
            return FakeCursor(rowcount=1)

        capture_connection = FakeBillingConnection(handle)
        with patch.object(store, "_connect", return_value=capture_connection):
            store.capture("reservation-1", 100, "event-1")
        capture_sql = [sql for sql, _ in capture_connection.statements]
        self.assertTrue(
            any("FROM reservations WHERE reservation_id = ? FOR UPDATE" in sql for sql in capture_sql)
        )
        self.assertTrue(any("FROM accounts WHERE account_id = ? FOR UPDATE" in sql for sql in capture_sql))

        release_connection = FakeBillingConnection(handle)
        with patch.object(store, "_connect", return_value=release_connection):
            store.release("reservation-1")
        release_sql = [sql for sql, _ in release_connection.statements]
        self.assertTrue(
            any("FROM reservations WHERE reservation_id = ? FOR UPDATE" in sql for sql in release_sql)
        )

    def test_outbox_claim_uses_skip_locked_and_never_postgresql_rowid(self) -> None:
        store = postgres_store()

        def handle(sql: str, parameters: tuple[object, ...]) -> FakeCursor:
            if sql.startswith("SELECT receipt_id FROM receipt_outbox"):
                return FakeCursor([{"receipt_id": "event-1"}])
            if sql.startswith("SELECT * FROM receipt_outbox"):
                return FakeCursor(
                    [
                        {
                            "receipt_id": "event-1",
                            "account_id": "acct-a",
                            "payload_json": "{}",
                            "status": "claimed",
                        }
                    ]
                )
            return FakeCursor(rowcount=1)

        connection = FakeBillingConnection(handle)
        with patch.object(store, "_connect", return_value=connection):
            claimed = store.claim_pending_receipts(limit=10)

        statements = [sql for sql, _ in connection.statements]
        claim_select = next(sql for sql in statements if sql.startswith("SELECT receipt_id"))
        self.assertIn("FOR UPDATE SKIP LOCKED", claim_select)
        self.assertTrue(all("rowid" not in sql.lower() for sql in statements))
        self.assertEqual([row["receipt_id"] for row in claimed], ["event-1"])

    def test_chain_guard_uses_shared_indexer_lock(self) -> None:
        store = postgres_store()
        connection = FakeBillingConnection(lambda sql, parameters: FakeCursor())
        store._transaction_lock(connection, "chain-indexer", shared=True)
        self.assertIn("pg_advisory_xact_lock_shared", connection.statements[0][0])

    def test_key_challenge_consumption_locks_nonce_row(self) -> None:
        store = postgres_store()
        challenge = {
            "nonce": "challenge-1",
            "wallet": "0x00000000000000000000000000000000000000a1",
            "key_hash": "11" * 32,
            "chain_id": 1,
            "expires_at": 200,
            "consumed_at": None,
            "verification_token": None,
        }

        def handle(sql: str, parameters: tuple[object, ...]) -> FakeCursor:
            if "FROM key_challenges WHERE nonce" in sql:
                return FakeCursor([challenge])
            return FakeCursor(rowcount=1)

        connection = FakeBillingConnection(handle)
        with patch.object(store, "_connect", return_value=connection):
            store.consume_key_challenge(
                wallet=str(challenge["wallet"]),
                key_hash=str(challenge["key_hash"]),
                chain_id=1,
                nonce="challenge-1",
                now=100,
            )
        self.assertTrue(
            any(
                "FROM key_challenges WHERE nonce = ? FOR UPDATE" in sql
                for sql, _ in connection.statements
            )
        )


if __name__ == "__main__":
    unittest.main()
