from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
from threading import Barrier
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.replay import (
    ABORTED_CLAIMS_RELEASED_MARKER,
    ReplayClaimsPendingError,
    ReplayError,
    ReplayOwnershipError,
    ReplayStore,
)


class ReplayStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database = Path(self.temporary_directory.name) / "replay.sqlite3"

    def store(self) -> ReplayStore:
        return ReplayStore(self.database)

    def test_execution_expiry_cleanup_has_a_dedicated_index(self) -> None:
        self.store()

        with sqlite3.connect(self.database) as db:
            indexes = {str(row[1]) for row in db.execute("PRAGMA index_list(execution_claims)")}
            columns = [
                str(row[2])
                for row in db.execute("PRAGMA index_info(execution_claims_expires_at_idx)")
            ]

        self.assertIn("execution_claims_expires_at_idx", indexes)
        self.assertEqual(columns, ["expires_at"])

    def test_remember_preserves_expiry_and_duplicate_semantics(self) -> None:
        store = self.store()
        store.remember("request", "one", 10, now=100)

        with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
            store.remember("request", "one", 10, now=110)

        store.remember("request", "one", 10, now=111)

    def test_remember_and_execution_lookup_keep_default_clock_compatibility(self) -> None:
        store = self.store()
        with patch("gateway.replay.time.time", return_value=100):
            store.remember("request", "default-clock", 10)
        claim = store.claim_execution("v4", "synthetic", "worker", 5, now=100)

        self.assertTrue(claim.acquired)
        self.assertIsNotNone(store.get_execution("v4", "synthetic"))

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

    def test_replay_ownership_columns_migrate_and_generic_claims_are_unowned(self) -> None:
        with sqlite3.connect(self.database) as db:
            db.execute(
                """
                CREATE TABLE replay_nonces (
                    scope TEXT NOT NULL,
                    replay_key TEXT NOT NULL,
                    seen_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY(scope, replay_key)
                )
                """
            )
            db.execute(
                "INSERT INTO replay_nonces VALUES (?, ?, ?, ?)",
                ("legacy", "one", 90, 200),
            )

        store = self.store()
        store.remember("generic", "two", 100, now=100)

        with sqlite3.connect(self.database) as db:
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(replay_nonces)")}
            self.assertTrue(
                {
                    "execution_scope",
                    "execution_key",
                    "execution_owner",
                    "execution_fencing_token",
                }.issubset(columns)
            )
            rows = db.execute(
                "SELECT execution_scope, execution_key, execution_owner, "
                "execution_fencing_token FROM replay_nonces ORDER BY scope"
            ).fetchall()
        self.assertEqual(rows, [(None, None, None, None), (None, None, None, None)])

    def test_owned_replay_claims_require_the_exact_claimed_execution(self) -> None:
        store = self.store()
        execution = store.claim_execution("v6", "execution", "worker-a", 60, now=100)
        claims = (("a.request", "one", 200), ("b.sequence", "one", 300))
        store.claim_many_for_execution(
            claims,
            "v6",
            "execution",
            "worker-a",
            execution.fencing_token,
            now=100,
        )

        with sqlite3.connect(self.database) as db:
            owners = db.execute(
                "SELECT execution_scope, execution_key, execution_owner, "
                "execution_fencing_token FROM replay_nonces ORDER BY scope"
            ).fetchall()
        self.assertEqual(
            owners,
            [
                ("v6", "execution", "worker-a", execution.fencing_token),
                ("v6", "execution", "worker-a", execution.fencing_token),
            ],
        )

        with self.assertRaisesRegex(ReplayError, "fencing token is stale"):
            store.claim_many_for_execution(
                (("wrong-fence", "must-not-stick", 200),),
                "v6",
                "execution",
                "worker-a",
                execution.fencing_token + 1,
                now=100,
            )
        store.remember("wrong-fence", "must-not-stick", 100, now=100)

    def test_owned_replay_claim_insert_rolls_back_on_duplicate(self) -> None:
        store = self.store()
        execution = store.claim_execution("v6", "execution", "worker-a", 60, now=100)
        store.remember("z.duplicate", "used", 100, now=100)

        with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
            store.claim_many_for_execution(
                (("a.request", "must-rollback", 200), ("z.duplicate", "used", 200)),
                "v6",
                "execution",
                "worker-a",
                execution.fencing_token,
                now=100,
            )

        store.remember("a.request", "must-rollback", 100, now=100)

    def test_release_execution_with_claims_is_atomic_and_fail_closed(self) -> None:
        store = self.store()
        execution = store.claim_execution("v6", "release", "worker-a", 60, now=100)
        owned = (("request", "release", 200), ("sequence", "release", 200))
        owned_keys = tuple((scope, key) for scope, key, _ in owned)
        store.claim_many_for_execution(
            owned,
            "v6",
            "release",
            "worker-a",
            execution.fencing_token,
            now=100,
        )
        store.remember("legacy", "unowned", 100, now=100)

        with self.assertRaisesRegex(ReplayError, "not owned"):
            store.release_execution_with_claims(
                "v6",
                "release",
                "worker-a",
                execution.fencing_token,
                (owned_keys[0], ("legacy", "unowned")),
            )
        current = store.get_execution("v6", "release", now=100)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.state, "claimed")

        self.assertTrue(
            store.release_execution_with_claims(
                "v6",
                "release",
                "worker-a",
                execution.fencing_token,
                owned_keys,
            )
        )
        self.assertIsNone(store.get_execution("v6", "release", now=100))
        for scope, key in owned_keys:
            store.remember(scope, key, 100, now=100)

    def test_release_with_claims_never_deletes_after_execution_starts(self) -> None:
        store = self.store()
        execution = store.claim_execution("v6", "started", "worker-a", 60, now=100)
        claims = (("request", "started", 200), ("sequence", "started", 200))
        claim_keys = tuple((scope, key) for scope, key, _ in claims)
        store.claim_many_for_execution(
            claims,
            "v6",
            "started",
            "worker-a",
            execution.fencing_token,
            now=100,
        )
        store.mark_execution_started(
            "v6", "started", "worker-a", execution.fencing_token, 60, now=101
        )

        self.assertFalse(
            store.release_execution_with_claims(
                "v6", "started", "worker-a", execution.fencing_token, claim_keys
            )
        )
        with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
            store.claim_many((("request", "started", 300),), now=102)

    def test_release_with_claims_rejects_missing_or_mismatched_ownership(self) -> None:
        for failure in ("missing", "mismatched"):
            with self.subTest(failure=failure):
                database = Path(self.temporary_directory.name) / f"{failure}.sqlite3"
                store = ReplayStore(database)
                execution = store.claim_execution("v6", "release", "worker-a", 60, now=100)
                claims = (("request", failure, 200), ("sequence", failure, 200))
                claim_keys = tuple((scope, key) for scope, key, _ in claims)
                store.claim_many_for_execution(
                    claims,
                    "v6",
                    "release",
                    "worker-a",
                    execution.fencing_token,
                    now=100,
                )
                with sqlite3.connect(database) as db:
                    if failure == "missing":
                        db.execute(
                            "DELETE FROM replay_nonces WHERE scope = ? AND replay_key = ?",
                            claim_keys[1],
                        )
                    else:
                        db.execute(
                            "UPDATE replay_nonces SET execution_owner = ? "
                            "WHERE scope = ? AND replay_key = ?",
                            ("worker-b", *claim_keys[1]),
                        )

                with self.assertRaisesRegex(ReplayError, "not owned"):
                    store.release_execution_with_claims(
                        "v6",
                        "release",
                        "worker-a",
                        execution.fencing_token,
                        claim_keys,
                    )
                current = store.get_execution("v6", "release", now=101)
                self.assertIsNotNone(current)
                assert current is not None
                self.assertEqual(current.state, "claimed")
                with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
                    store.claim_many((("request", failure, 300),), now=101)

    def test_abort_execution_with_claims_releases_and_fences_idempotently(self) -> None:
        store = self.store()
        execution = store.claim_execution("v6", "abort", "worker-a", 60, now=100)
        claims = (("request", "abort", 200), ("sequence", "abort", 200))
        claim_keys = tuple((scope, key) for scope, key, _ in claims)
        store.claim_many_for_execution(
            claims,
            "v6",
            "abort",
            "worker-a",
            execution.fencing_token,
            now=100,
        )
        store.mark_execution_started(
            "v6", "abort", "worker-a", execution.fencing_token, 60, now=101
        )

        self.assertFalse(
            store.abort_execution_with_claims("v6", "abort", claim_keys, 100, now=102)
        )
        self.assertTrue(
            store.abort_execution_with_claims("v6", "abort", claim_keys, 101, now=102)
        )
        self.assertFalse(
            store.abort_execution_with_claims("v6", "abort", claim_keys, 999, now=103)
        )
        aborted = store.get_execution("v6", "abort", now=103)
        self.assertIsNotNone(aborted)
        assert aborted is not None
        self.assertEqual(aborted.state, "aborted")
        self.assertEqual(aborted.result_hash, ABORTED_CLAIMS_RELEASED_MARKER)
        with self.assertRaisesRegex(ReplayError, "has not started"):
            store.complete_execution(
                "v6",
                "abort",
                "worker-a",
                execution.fencing_token,
                "sha256:too-late",
                now=104,
            )
        for scope, key in claim_keys:
            store.remember(scope, key, 100, now=104)

    def test_zero_nonce_claim_aborts_only_after_the_missing_claim_timeout(self) -> None:
        store = self.store()
        store.claim_execution("v6", "missing-claims", "worker-a", 300, now=100)
        claim_keys = (("request", "missing-claims"), ("sequence", "missing-claims"))

        with self.assertRaises(ReplayClaimsPendingError):
            store.abort_execution_with_claims(
                "v6",
                "missing-claims",
                claim_keys,
                200,
                states=("claimed",),
                missing_claims_stale_before=99,
                now=200,
            )
        self.assertTrue(
            store.abort_execution_with_claims(
                "v6",
                "missing-claims",
                claim_keys,
                200,
                states=("claimed",),
                missing_claims_stale_before=100,
                now=201,
            )
        )
        aborted = store.get_execution("v6", "missing-claims", now=201)
        self.assertIsNotNone(aborted)
        assert aborted is not None
        self.assertEqual(aborted.state, "aborted")
        self.assertEqual(aborted.result_hash, ABORTED_CLAIMS_RELEASED_MARKER)

        started = store.claim_execution("v6", "missing-started", "worker-a", 300, now=100)
        store.mark_execution_started(
            "v6", "missing-started", "worker-a", started.fencing_token, 300, now=101
        )
        with self.assertRaises(ReplayOwnershipError):
            store.abort_execution_with_claims(
                "v6",
                "missing-started",
                (("request", "missing-started"), ("sequence", "missing-started")),
                200,
                states=("started",),
                missing_claims_stale_before=200,
                now=201,
            )

    def test_abort_with_claims_rolls_back_database_failure(self) -> None:
        store = self.store()
        execution = store.claim_execution("v6", "rollback", "worker-a", 60, now=100)
        claims = (("request", "rollback", 200), ("sequence", "rollback", 200))
        claim_keys = tuple((scope, key) for scope, key, _ in claims)
        store.claim_many_for_execution(
            claims,
            "v6",
            "rollback",
            "worker-a",
            execution.fencing_token,
            now=100,
        )
        store.mark_execution_started(
            "v6", "rollback", "worker-a", execution.fencing_token, 60, now=101
        )
        with sqlite3.connect(self.database) as db:
            db.execute(
                """
                CREATE TRIGGER fail_owned_replay_delete
                BEFORE DELETE ON replay_nonces
                WHEN OLD.scope = 'request'
                BEGIN
                    SELECT RAISE(ABORT, 'forced delete failure');
                END
                """
            )

        with self.assertRaisesRegex(ReplayError, "operation failed"):
            store.abort_execution_with_claims("v6", "rollback", claim_keys, 101, now=102)
        current = store.get_execution("v6", "rollback", now=102)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.state, "started")
        with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
            store.claim_many((("sequence", "rollback", 300),), now=102)

    def test_abort_with_claims_and_complete_are_serialized(self) -> None:
        first = self.store()
        second = self.store()
        execution = first.claim_execution("v6", "race-complete", "worker-a", 60, now=100)
        claims = (("request", "race-complete", 200), ("sequence", "race-complete", 200))
        claim_keys = tuple((scope, key) for scope, key, _ in claims)
        first.claim_many_for_execution(
            claims,
            "v6",
            "race-complete",
            "worker-a",
            execution.fencing_token,
            now=100,
        )
        first.mark_execution_started(
            "v6", "race-complete", "worker-a", execution.fencing_token, 60, now=101
        )
        barrier = Barrier(2)

        def abort() -> bool:
            barrier.wait()
            return first.abort_execution_with_claims(
                "v6", "race-complete", claim_keys, 101, states=("started",), now=102
            )

        def complete() -> bool:
            barrier.wait()
            try:
                second.complete_execution(
                    "v6",
                    "race-complete",
                    "worker-a",
                    execution.fencing_token,
                    "sha256:done",
                    now=102,
                )
            except ReplayError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            abort_result = pool.submit(abort)
            complete_result = pool.submit(complete)
        outcomes = (abort_result.result(), complete_result.result())
        self.assertEqual(sum(outcomes), 1)

        current = first.get_execution("v6", "race-complete", now=102)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.state, "aborted" if outcomes[0] else "completed")
        if outcomes[0]:
            for scope, key in claim_keys:
                first.remember(scope, key, 100, now=103)
        else:
            with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
                first.claim_many((("sequence", "race-complete", 300),), now=103)

    def test_abort_with_claims_and_mark_started_are_serialized(self) -> None:
        first = self.store()
        second = self.store()
        execution = first.claim_execution("v6", "race-start", "worker-a", 60, now=100)
        claims = (("request", "race-start", 200), ("sequence", "race-start", 200))
        claim_keys = tuple((scope, key) for scope, key, _ in claims)
        first.claim_many_for_execution(
            claims,
            "v6",
            "race-start",
            "worker-a",
            execution.fencing_token,
            now=100,
        )
        barrier = Barrier(2)

        def abort() -> bool:
            barrier.wait()
            return first.abort_execution_with_claims(
                "v6", "race-start", claim_keys, 100, states=("claimed",), now=101
            )

        def start() -> bool:
            barrier.wait()
            try:
                second.mark_execution_started(
                    "v6", "race-start", "worker-a", execution.fencing_token, 60, now=101
                )
            except ReplayError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            abort_result = pool.submit(abort)
            start_result = pool.submit(start)
        outcomes = (abort_result.result(), start_result.result())
        self.assertEqual(sum(outcomes), 1)

        current = first.get_execution("v6", "race-start", now=101)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.state, "aborted" if outcomes[0] else "started")
        if outcomes[0]:
            for scope, key in claim_keys:
                first.remember(scope, key, 100, now=102)
        else:
            with self.assertRaisesRegex(ReplayError, "duplicate replay key"):
                first.claim_many((("sequence", "race-start", 300),), now=102)

    def test_absent_tombstone_and_inference_claim_are_serialized(self) -> None:
        first = self.store()
        second = self.store()
        barrier = Barrier(2)

        def tombstone() -> str:
            barrier.wait()
            return first.tombstone_absent_execution(
                "v6", "race-absent", "status-worker", 300, now=100
            ).state

        def claim() -> str:
            barrier.wait()
            try:
                acquired = second.claim_execution(
                    "v6", "race-absent", "infer-worker", 200, now=100
                )
            except ReplayError:
                return "rejected"
            return acquired.state

        with ThreadPoolExecutor(max_workers=2) as pool:
            tombstone_result = pool.submit(tombstone)
            claim_result = pool.submit(claim)
        outcomes = (tombstone_result.result(), claim_result.result())

        current = first.get_execution("v6", "race-absent", now=100)
        self.assertIsNotNone(current)
        assert current is not None
        if current.state == "aborted":
            self.assertEqual(outcomes, ("aborted", "rejected"))
            self.assertEqual(current.result_hash, ABORTED_CLAIMS_RELEASED_MARKER)
        else:
            self.assertEqual(current.state, "claimed")
            self.assertEqual(outcomes, ("claimed", "claimed"))

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

    def test_completed_execution_payload_survives_store_reopen(self) -> None:
        first = self.store()
        claim = first.claim_execution("v4", "consumer:request-1", "provider-a", 60, now=100)
        first.mark_execution_started(
            "v4",
            "consumer:request-1",
            "provider-a",
            claim.fencing_token,
            60,
            now=101,
        )
        first.complete_execution(
            "v4",
            "consumer:request-1",
            "provider-a",
            claim.fencing_token,
            "sha256:stable",
            '{"response":{"output_text":"same"}}',
            now=102,
        )

        reopened = ReplayStore(self.database)
        cached = reopened.get_execution("v4", "consumer:request-1", now=102)
        self.assertIsNotNone(cached)
        assert cached is not None
        self.assertEqual(cached.state, "completed")
        self.assertEqual(cached.result_hash, "sha256:stable")
        self.assertEqual(cached.result_payload, '{"response":{"output_text":"same"}}')

    def test_uncertain_execution_can_be_completed_by_original_owner(self) -> None:
        store = self.store()
        claim = store.claim_execution("v4", "consumer:request-2", "provider-a", 60, now=100)
        store.mark_execution_started(
            "v4",
            "consumer:request-2",
            "provider-a",
            claim.fencing_token,
            60,
            now=101,
        )
        uncertain = store.mark_execution_uncertain(
            "v4", "consumer:request-2", "provider-a", claim.fencing_token, now=102
        )
        self.assertEqual(uncertain.state, "uncertain")

        completed = store.complete_execution(
            "v4",
            "consumer:request-2",
            "provider-a",
            claim.fencing_token,
            "sha256:recovered",
            '{"response":{"output_text":"recovered"}}',
            now=103,
        )
        self.assertEqual(completed.state, "completed")
        self.assertEqual(completed.result_payload, '{"response":{"output_text":"recovered"}}')

        cached = store.claim_execution("v4", "consumer:request-2", "provider-b", 60, now=104)
        self.assertFalse(cached.acquired)
        self.assertEqual(cached.state, "completed")

    def test_session_progress_survives_reopen_and_is_monotonic(self) -> None:
        first = self.store()
        first.set_session_progress(
            "p2p.v4.session",
            "111:contract:session",
            sequence=1,
            cumulative_spend_units=1_000,
            expires_at=500,
            now=100,
        )
        # A stale writer cannot rewind an already committed sequence.
        first.set_session_progress(
            "p2p.v4.session",
            "111:contract:session",
            sequence=0,
            cumulative_spend_units=0,
            expires_at=500,
            now=101,
        )

        reopened = ReplayStore(self.database)
        self.assertEqual(
            reopened.get_session_progress(
                "p2p.v4.session", "111:contract:session", now=102
            ),
            (1, 1_000),
        )

        reopened.set_session_progress(
            "p2p.v4.session",
            "111:contract:session",
            sequence=2,
            cumulative_spend_units=2_000,
            expires_at=600,
            now=103,
        )
        self.assertEqual(
            first.get_session_progress("p2p.v4.session", "111:contract:session", now=104),
            (2, 2_000),
        )

    def test_session_progress_rejects_conflicting_spend_for_same_sequence(self) -> None:
        store = self.store()
        store.set_session_progress(
            "p2p.v4.session",
            "session",
            sequence=3,
            cumulative_spend_units=3_000,
            expires_at=500,
            now=100,
        )
        with self.assertRaisesRegex(ReplayError, "conflicts"):
            store.set_session_progress(
                "p2p.v4.session",
                "session",
                sequence=3,
                cumulative_spend_units=3_001,
                expires_at=500,
                now=101,
            )
        with self.assertRaisesRegex(ReplayError, "conflicts"):
            store.set_session_progress(
                "p2p.v4.session",
                "session",
                sequence=4,
                cumulative_spend_units=2_999,
                expires_at=500,
                now=102,
            )

    def test_expired_execution_is_removed_before_cached_lookup_and_key_reuse(self) -> None:
        for state in ("claimed", "completed", "aborted"):
            with self.subTest(state=state):
                database = Path(self.temporary_directory.name) / f"expired-{state}.sqlite3"
                store = ReplayStore(database)
                claim = store.claim_execution("v4", "same-request", "worker-old", 5, now=100)
                if state == "completed":
                    store.mark_execution_started(
                        "v4", "same-request", "worker-old", claim.fencing_token, 5, now=101
                    )
                    store.complete_execution(
                        "v4",
                        "same-request",
                        "worker-old",
                        claim.fencing_token,
                        "sha256:old",
                        now=102,
                    )
                elif state == "aborted":
                    self.assertTrue(
                        store.abort_stale_execution(
                            "v4", "same-request", 100, states=("claimed",), now=102
                        )
                    )

                self.assertIsNone(store.get_execution("v4", "same-request", now=107))
                replacement = store.claim_execution(
                    "v4", "same-request", "worker-new", 60, now=107
                )
                self.assertTrue(replacement.acquired)
                self.assertGreater(replacement.fencing_token, claim.fencing_token)

    def test_tombstone_replaces_an_expired_execution_with_a_new_fence(self) -> None:
        store = self.store()
        original = store.claim_execution("v6", "status-key", "worker-old", 5, now=100)
        self.assertTrue(
            store.abort_stale_execution(
                "v6", "status-key", 100, states=("claimed",), now=101
            )
        )

        replacement = store.tombstone_absent_execution(
            "v6", "status-key", "status-worker", 300, now=106
        )

        self.assertEqual(replacement.state, "aborted")
        self.assertEqual(replacement.owner, "status-worker")
        self.assertGreater(replacement.fencing_token, original.fencing_token)
        self.assertEqual(replacement.result_hash, ABORTED_CLAIMS_RELEASED_MARKER)

    def test_only_one_concurrent_claim_reuses_an_expired_execution_key(self) -> None:
        first = self.store()
        second = self.store()
        original = first.claim_execution("v4", "expired-race", "worker-old", 5, now=100)
        first.mark_execution_started(
            "v4", "expired-race", "worker-old", original.fencing_token, 5, now=101
        )
        first.complete_execution(
            "v4",
            "expired-race",
            "worker-old",
            original.fencing_token,
            "sha256:old",
            now=102,
        )
        barrier = Barrier(2)

        def claim(store: ReplayStore, owner: str) -> object:
            barrier.wait()
            try:
                return store.claim_execution("v4", "expired-race", owner, 60, now=107)
            except ReplayError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(
                    lambda item: claim(*item),
                    ((first, "worker-a"), (second, "worker-b")),
                )
            )

        winners = [outcome for outcome in outcomes if not isinstance(outcome, Exception)]
        self.assertEqual(len(winners), 1)
        current = first.get_execution("v4", "expired-race", now=107)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.state, "claimed")
        self.assertGreater(current.fencing_token, original.fencing_token)
        with self.assertRaisesRegex(ReplayError, "fencing token is stale"):
            first.complete_execution(
                "v4",
                "expired-race",
                "worker-old",
                original.fencing_token,
                "sha256:late-old-worker",
                now=108,
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

    def test_started_or_uncertain_execution_is_reassigned_only_after_expiry(self) -> None:
        for state in ("started", "uncertain"):
            with self.subTest(state=state):
                database = Path(self.temporary_directory.name) / f"expiry-{state}.sqlite3"
                store = ReplayStore(database)
                claim = store.claim_execution("v3", "reservation-3", "worker-a", 5, now=100)
                store.mark_execution_started(
                    "v3", "reservation-3", "worker-a", claim.fencing_token, 5, now=101
                )
                if state == "uncertain":
                    store.mark_execution_uncertain(
                        "v3", "reservation-3", "worker-a", claim.fencing_token, now=102
                    )

                with self.assertRaisesRegex(ReplayError, f"already {state}"):
                    store.claim_execution("v3", "reservation-3", "worker-b", 5, now=106)

                replacement = store.claim_execution(
                    "v3", "reservation-3", "worker-b", 5, now=107
                )
                self.assertTrue(replacement.acquired)
                self.assertGreater(replacement.fencing_token, claim.fencing_token)
                with self.assertRaisesRegex(ReplayError, "fencing token is stale"):
                    store.complete_execution(
                        "v3",
                        "reservation-3",
                        "worker-a",
                        claim.fencing_token,
                        "sha256:late",
                        now=108,
                    )

    def test_stale_execution_abort_is_terminal_for_original_fence(self) -> None:
        store = self.store()
        for state in ("claimed", "started", "uncertain"):
            with self.subTest(state=state):
                execution_key = f"stale-{state}"
                claim = store.claim_execution("v4", execution_key, "worker-a", 300, now=100)
                updated_at = 100
                if state in {"started", "uncertain"}:
                    store.mark_execution_started(
                        "v4", execution_key, "worker-a", claim.fencing_token, 300, now=101
                    )
                    updated_at = 101
                if state == "uncertain":
                    store.mark_execution_uncertain(
                        "v4", execution_key, "worker-a", claim.fencing_token, now=102
                    )
                    updated_at = 102

                self.assertTrue(
                    store.abort_stale_execution(
                        "v4", execution_key, updated_at, now=200
                    )
                )
                aborted = store.get_execution("v4", execution_key, now=200)
                self.assertIsNotNone(aborted)
                assert aborted is not None
                self.assertEqual(aborted.state, "aborted")
                self.assertEqual(aborted.updated_at, 200)
                self.assertFalse(
                    store.abort_stale_execution("v4", execution_key, 999, now=201)
                )
                with self.assertRaisesRegex(ReplayError, "already aborted"):
                    store.mark_execution_started(
                        "v4", execution_key, "worker-a", claim.fencing_token, 60, now=202
                    )
                with self.assertRaisesRegex(ReplayError, "only a started execution"):
                    store.mark_execution_uncertain(
                        "v4", execution_key, "worker-a", claim.fencing_token, now=202
                    )
                with self.assertRaisesRegex(ReplayError, "has not started"):
                    store.complete_execution(
                        "v4",
                        execution_key,
                        "worker-a",
                        claim.fencing_token,
                        "sha256:too-late",
                        now=202,
                    )

    def test_abort_ignores_fresh_completed_and_missing_executions(self) -> None:
        store = self.store()
        claim = store.claim_execution("v4", "fresh", "worker-a", 60, now=100)
        store.mark_execution_started("v4", "fresh", "worker-a", claim.fencing_token, 60, now=110)

        self.assertFalse(store.abort_stale_execution("v4", "fresh", 109, now=120))
        self.assertFalse(
            store.abort_stale_execution(
                "v4",
                "fresh",
                999,
                states=("claimed",),
                now=120,
            )
        )
        completed = store.complete_execution(
            "v4", "fresh", "worker-a", claim.fencing_token, "sha256:done", now=121
        )
        self.assertEqual(completed.state, "completed")
        self.assertFalse(store.abort_stale_execution("v4", "fresh", 999, now=122))
        self.assertFalse(store.abort_stale_execution("v4", "missing", 999, now=122))

    def test_only_one_concurrent_stale_abort_wins(self) -> None:
        first = self.store()
        second = self.store()
        claim = first.claim_execution("v4", "concurrent", "worker-a", 300, now=100)
        first.mark_execution_started(
            "v4", "concurrent", "worker-a", claim.fencing_token, 300, now=101
        )

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(
                    lambda store: store.abort_stale_execution(
                        "v4", "concurrent", 101, now=200
                    ),
                    (first, second),
                )
            )

        self.assertEqual(sorted(outcomes), [False, True])
        current = first.get_execution("v4", "concurrent", now=200)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.state, "aborted")

    def test_existing_execution_state_constraint_is_migrated_for_abort(self) -> None:
        with sqlite3.connect(self.database) as db:
            db.execute(
                """
                CREATE TABLE execution_claims (
                    scope TEXT NOT NULL,
                    execution_key TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('claimed', 'started', 'uncertain', 'completed')),
                    owner TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    claimed_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    result_hash TEXT,
                    result_payload TEXT,
                    PRIMARY KEY(scope, execution_key)
                )
                """
            )
            db.execute(
                "INSERT INTO execution_claims VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("v4", "legacy", "uncertain", "worker-a", 1, 90, 100, 200, None, None),
            )

        store = self.store()
        self.assertTrue(store.abort_stale_execution("v4", "legacy", 100, now=101))
        migrated = store.get_execution("v4", "legacy", now=101)
        self.assertIsNotNone(migrated)
        assert migrated is not None
        self.assertEqual(migrated.state, "aborted")

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
