from __future__ import annotations

import unittest

from gateway.routing import (
    RouteState,
    active_leases,
    rank_peers,
    record_route_acceptance,
    record_route_dispute,
    record_route_failure,
    record_route_settlement,
    record_route_success,
    release_peer,
    reserve_peer,
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


if __name__ == "__main__":
    unittest.main()
