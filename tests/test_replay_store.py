from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.replay import ReplayError, ReplayStore


class ReplayStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database = Path(self.temporary_directory.name) / "replay.sqlite3"

    def store(self) -> ReplayStore:
        return ReplayStore(self.database)

    def test_remember_preserves_expiry_and_duplicate_semantics(self) -> None:
        store = self.store()
        store.remember("request", "one", 10, now=100)

        with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
            store.remember("request", "one", 10, now=110)

        store.remember("request", "one", 10, now=111)

    def test_claim_many_rolls_back_every_key_when_one_is_duplicate(self) -> None:
        store = self.store()
        store.remember("reservation", "used", 100, now=100)

        with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
            store.claim_many(
                (
                    ("request", "must-rollback", 200),
                    ("reservation", "used", 200),
                ),
                now=100,
            )

        store.remember("request", "must-rollback", 100, now=100)

    def test_claim_many_is_atomic_across_store_instances(self) -> None:
        first = self.store()
        second = self.store()

        def claim(store: ReplayStore) -> bool:
            try:
                store.claim_many(
                    (("request", "same", 200), ("reservation", "same", 200)),
                    now=100,
                )
            except ReplayError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(claim, (first, second)))

        self.assertEqual(sorted(outcomes), [False, True])

    def test_execution_lifecycle_caches_one_idempotent_result(self) -> None:
        store = self.store()
        claim = store.claim_execution("v3", "reservation-1", "worker-a", 30, now=100)
        self.assertTrue(claim.acquired)
        self.assertEqual(claim.state, "claimed")

        with self.assertRaisesRegex(ReplayError, "already claimed"):
            store.claim_execution("v3", "reservation-1", "worker-b", 30, now=100)

        started = store.mark_execution_started(
            "v3", "reservation-1", "worker-a", claim.fencing_token, 60, now=101
        )
        self.assertEqual(started.state, "started")
        self.assertFalse(store.release_execution("v3", "reservation-1", "worker-a", claim.fencing_token))

        completed = store.complete_execution(
            "v3",
            "reservation-1",
            "worker-a",
            claim.fencing_token,
            "sha256:result",
            '{"answer":"done"}',
            now=102,
        )
        self.assertEqual(completed.state, "completed")

        repeated = store.complete_execution(
            "v3",
            "reservation-1",
            "worker-a",
            claim.fencing_token,
            "sha256:result",
            '{"answer":"done"}',
            now=103,
        )
        self.assertEqual(repeated.result_payload, '{"answer":"done"}')

        cached = store.claim_execution("v3", "reservation-1", "worker-b", 30, now=104)
        self.assertFalse(cached.acquired)
        self.assertEqual(cached.state, "completed")
        self.assertEqual(cached.result_hash, "sha256:result")

        with self.assertRaisesRegex(ReplayError, "does not match"):
            store.complete_execution(
                "v3",
                "reservation-1",
                "worker-a",
                claim.fencing_token,
                "sha256:different",
                now=105,
            )

    def test_expired_unstarted_claim_is_reassigned_with_new_fence(self) -> None:
        store = self.store()
        stale = store.claim_execution("v3", "reservation-2", "worker-a", 5, now=100)
        current = store.claim_execution("v3", "reservation-2", "worker-b", 5, now=106)

        self.assertTrue(current.acquired)
        self.assertGreater(current.fencing_token, stale.fencing_token)
        with self.assertRaisesRegex(ReplayError, "fencing token is stale"):
            store.mark_execution_started(
                "v3", "reservation-2", "worker-a", stale.fencing_token, 60, now=107
            )

    def test_started_or_uncertain_execution_is_never_automatically_reassigned(self) -> None:
        store = self.store()
        claim = store.claim_execution("v3", "reservation-3", "worker-a", 5, now=100)
        store.mark_execution_started("v3", "reservation-3", "worker-a", claim.fencing_token, 5, now=101)

        with self.assertRaisesRegex(ReplayError, "already started"):
            store.claim_execution("v3", "reservation-3", "worker-b", 5, now=200)

        uncertain = store.mark_execution_uncertain(
            "v3", "reservation-3", "worker-a", claim.fencing_token, now=201
        )
        self.assertEqual(uncertain.state, "uncertain")
        with self.assertRaisesRegex(ReplayError, "already uncertain"):
            store.claim_execution("v3", "reservation-3", "worker-b", 5, now=300)

    def test_only_unstarted_claim_can_be_released(self) -> None:
        store = self.store()
        first = store.claim_execution("v3", "reservation-4", "worker-a", 30, now=100)
        self.assertTrue(store.release_execution("v3", "reservation-4", "worker-a", first.fencing_token))

        second = store.claim_execution("v3", "reservation-4", "worker-b", 30, now=101)
        self.assertGreater(second.fencing_token, first.fencing_token)

    def test_postgres_url_fails_closed_when_optional_driver_is_missing(self) -> None:
        with patch("gateway.replay.import_module", side_effect=ModuleNotFoundError("psycopg")):
            with self.assertRaisesRegex(ReplayError, "requires psycopg 3"):
                ReplayStore("postgresql://db.example/myco")

        self.assertFalse((Path.cwd() / "postgresql:").exists())

    def test_postgres_connection_failure_does_not_fall_back_to_sqlite(self) -> None:
        def unavailable(_dsn: str) -> None:
            raise OSError("database unavailable")

        driver = SimpleNamespace(connect=unavailable)
        with patch("gateway.replay.import_module", return_value=driver):
            with self.assertRaisesRegex(ReplayError, "failed to initialize PostgreSQL"):
                ReplayStore("postgres://db.example/myco")

        self.assertFalse((Path.cwd() / "postgres:").exists())

    def test_unknown_database_url_is_rejected(self) -> None:
        with self.assertRaisesRegex(ReplayError, "unsupported replay store URL scheme"):
            ReplayStore("mysql://db.example/myco")


if __name__ == "__main__":
    unittest.main()
