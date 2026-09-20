"""Keep every connection reachable so GC cannot hide leaked SQLite handles."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.session_relayer import RelaySettlementOutbox


class ConnectionLifetimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.connections = []
        real_connect = sqlite3.connect
        connections = self.connections

        class TrackedConnection(sqlite3.Connection):
            close_calls = 0

            def close(self):
                self.close_calls += 1
                return super().close()

        def connect(*args, **kwargs):
            connection = real_connect(*args, factory=TrackedConnection, **kwargs)
            connections.append(connection)
            return connection

        patched = patch("gateway.session_relayer.sqlite3.connect", side_effect=connect)
        patched.start()
        self.addCleanup(patched.stop)
        self.outbox = RelaySettlementOutbox(Path(temp.name) / "outbox.sqlite3")

    def assert_all_closed(self):
        self.assertTrue(self.connections)
        for connection in self.connections:
            self.assertEqual(connection.close_calls, 1)
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_repeated_health_pending_and_status_reads_close_without_gc(self):
        for _ in range(100):
            self.outbox.snapshot()
            self.outbox.blocking_error()
            self.outbox.next_batch()
            self.outbox.expire_pending()
            self.outbox.status("unknown")
            self.outbox.public_status("0x" + "01" * 32, key_address="0x" + "02" * 20)
        self.assertEqual(len(self.connections), 601)
        self.assert_all_closed()

    def test_failed_transaction_is_rolled_back_and_connection_closed(self):
        with self.assertRaisesRegex(RuntimeError, "abort"):
            with self.outbox._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE rollback_fixture (id INTEGER)")
                raise RuntimeError("abort")
        with self.outbox._connect() as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='rollback_fixture'").fetchone())
        self.assert_all_closed()


if __name__ == "__main__":
    unittest.main()
