"""The Relay's settlement queue retries transient failures and keeps old databases working."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from mycomesh.relay.core import MAX_SETTLE_ATTEMPTS, SettlementQueue


class SettlementQueueTest(unittest.TestCase):
    def test_failures_reject_only_after_repeated_attempts_and_old_schema_migrates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "relay-settlement.sqlite3"
            old = sqlite3.connect(path)
            old.execute("CREATE TABLE receipts (settlement_key TEXT PRIMARY KEY, payload TEXT NOT NULL, owner TEXT NOT NULL, "
                        "provider TEXT NOT NULL, fee INTEGER NOT NULL, state TEXT NOT NULL, error TEXT, "
                        "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)")
            old.execute("INSERT INTO receipts VALUES ('k', '{}', 'o', 'p', 1, 'queued', NULL, 0, 0)")
            old.commit()
            old.close()
            queue = SettlementQueue(path)
            for _ in range(MAX_SETTLE_ATTEMPTS - 1):
                queue.fail("k", "upstream timeout")
            self.assertEqual(queue.counts(), {"queued": 1})
            queue.fail("k", "execution reverted")
            self.assertEqual(queue.counts(), {"rejected": 1})


if __name__ == "__main__":
    unittest.main()
