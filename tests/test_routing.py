from __future__ import annotations

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from gateway.routing import (
    RouteState,
    active_leases,
    load_route_state,
    rank_peers,
    record_route_acceptance,
    record_route_dispute,
    record_route_failure,
    record_route_settlement,
    record_route_success,
    release_peer,
    reserve_peer,
    save_route_state,
)


class RoutingTest(unittest.TestCase):
    def test_rank_peers_prefers_capacity_and_success(self) -> None:
        state = RouteState()
        record_route_failure(state, "bad", "timeout")
        record_route_success(state, "good", 100)
        peers = [
            {"peer_id": "bad", "capacity": {"max_concurrency": 10}},
            {"peer_id": "good", "capacity": {"max_concurrency": 1}},
        ]

        ranked = rank_peers(peers, state)

        self.assertEqual(ranked[0]["peer_id"], "good")

    def test_rank_peers_uses_acceptance_settlement_and_disputes(self) -> None:
        state = RouteState()
        record_route_acceptance(state, "accepted")
        record_route_settlement(state, "settled")
        record_route_dispute(state, "disputed", "bad receipt")
        peers = [
            {"peer_id": "disputed", "capacity": {"max_concurrency": 10}},
            {"peer_id": "accepted", "capacity": {"max_concurrency": 1}},
            {"peer_id": "settled", "capacity": {"max_concurrency": 1}},
        ]

        ranked = rank_peers(peers, state)

        self.assertEqual(ranked[0]["peer_id"], "settled")
        self.assertEqual(ranked[-1]["peer_id"], "disputed")

    def test_reserve_peer_limits_local_capacity(self) -> None:
        state = RouteState()
        peer = {"peer_id": "provider-a", "capacity": {"max_concurrency": 1}}

        lease_id = reserve_peer(state, peer, ttl_seconds=60)

        self.assertEqual(active_leases(state, "provider-a"), 1)
        with self.assertRaisesRegex(ValueError, "capacity"):
            reserve_peer(state, peer, ttl_seconds=60)
        release_peer(state, lease_id)
        self.assertEqual(active_leases(state, "provider-a"), 0)

    def test_saved_release_does_not_resurrect_lease(self) -> None:
        peer = {"peer_id": "provider-a", "capacity": {"max_concurrency": 1}}

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "route-state.json"
            state = RouteState()
            lease_id = reserve_peer(state, peer, ttl_seconds=60)
            save_route_state(state, path)

            reloaded = load_route_state(path)
            release_peer(reloaded, lease_id)
            save_route_state(reloaded, path)

            persisted = load_route_state(path)

        self.assertEqual(active_leases(persisted, "provider-a"), 0)
        self.assertNotIn(lease_id, persisted.leases)

    def test_saved_release_preserves_other_worker_lease(self) -> None:
        peer = {"peer_id": "provider-a", "capacity": {"max_concurrency": 2}}

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "route-state.json"
            first = RouteState()
            first_lease = reserve_peer(first, peer, ttl_seconds=60)
            save_route_state(first, path)

            second = load_route_state(path)
            second_lease = reserve_peer(second, peer, ttl_seconds=60)
            save_route_state(second, path)

            release_peer(first, first_lease)
            save_route_state(first, path)
            persisted = load_route_state(path)
            release_peer(second, second_lease)
            save_route_state(second, path)
            fully_released = load_route_state(path)

        self.assertEqual(active_leases(persisted, "provider-a"), 1)
        self.assertNotIn(first_lease, persisted.leases)
        self.assertIn(second_lease, persisted.leases)
        self.assertEqual(active_leases(fully_released, "provider-a"), 0)

    def test_save_prunes_expired_lease_and_does_not_serialize_tombstones(self) -> None:
        peer = {"peer_id": "provider-a", "capacity": {"max_concurrency": 1}}
        state = RouteState()
        expired_lease = reserve_peer(state, peer, ttl_seconds=60)
        state.leases[expired_lease]["expires_at"] = int(time.time()) - 1
        state.released_leases.add("lease_provider-a_released")

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "route-state.json"
            save_route_state(state, path)
            persisted = load_route_state(path)
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertNotIn(expired_lease, persisted.leases)
        self.assertNotIn("released_leases", payload)


if __name__ == "__main__":
    unittest.main()
