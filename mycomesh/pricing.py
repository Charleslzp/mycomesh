"""Network pricing reads: one price per tier, adjusted daily from utilisation (see ProviderJuryRegistryV11)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import rpc
from .evm import decode_words, encode_call

EPOCH = 86_400
UNIT = 1_000_000


def _ints(raw: str, count: int) -> list[int]:
    return [int.from_bytes(word, "big") for word in decode_words(raw, count)]


@dataclass
class NetworkPricing:
    rpc_url: Any
    registry: str
    _cache: dict = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def _call(self, signature: str, types: list[Any], values: list[Any], count: int) -> list[int]:
        return _ints(rpc.eth_call(self.rpc_url, self.registry, encode_call(signature, types, values)), count)

    def quote(self, signer: str, issued_at: int, input_tokens: int, output_tokens: int) -> int:
        """Exactly the price settlement will enforce (before the Consumer's maxFee cap)."""
        return self._call("quote(address,uint64,uint256,uint256)", ["address", "uint64", "uint256", "uint256"],
                          [signer, issued_at, input_tokens, output_tokens], 1)[0]

    def remaining_capacity(self, signer: str) -> int:
        return self._call("remainingCapacity(address)", ["address"], [signer], 1)[0]

    def signer(self, signer: str) -> dict[str, int]:
        tier, last_epoch, declared, peak, counted, served = self._call("signerPricing(address)", ["address"], [signer], 6)
        return {"tier": tier, "last_epoch": last_epoch, "declared": declared, "peak": peak, "counted": counted, "served": served}

    def tier(self, tier: int) -> dict[str, int]:
        base_in, base_out, min_fee, base_capacity, target, active = self._call("tiers(uint32)", ["uint32"], [tier], 6)
        return {"base_in": base_in, "base_out": base_out, "min_fee": min_fee, "base_capacity": base_capacity,
                "target_bps": target, "active": bool(active)}

    def multiplier(self, tier: int, epoch: int | None = None) -> int:
        epoch = int(time.time()) // EPOCH if epoch is None else epoch
        key = (tier, epoch)
        with self._lock:
            if key in self._cache and epoch < int(time.time()) // EPOCH + 1:
                return self._cache[key]
        value = self._call("multiplierFor(uint32,uint64)", ["uint32", "uint64"], [tier, epoch], 1)[0]
        with self._lock:
            self._cache[key] = value
        return value

    def effective_prices(self, tier: int, now: int | None = None) -> dict[str, int]:
        """Today's per-1k-token prices for display; settlement uses quote()."""
        config = self.tier(tier)
        multiplier = self.multiplier(tier, None if now is None else now // EPOCH)
        scale = lambda value: -(-value * multiplier // UNIT)  # noqa: E731
        return {"input_per_1k": scale(config["base_in"]), "output_per_1k": scale(config["base_out"]),
                "minimum_fee": scale(config["min_fee"]), "multiplier": multiplier}

    def market(self, tier: int) -> dict[str, Any]:
        """Yesterday's and today's demand and supply, and the resulting price step (by chain time)."""
        today = rpc.block_time(self.rpc_url) // EPOCH
        rows = {}
        for label, epoch in (("yesterday", today - 1), ("today", today)):
            demand = self._call("demandAt(uint32,uint64)", ["uint32", "uint64"], [tier, epoch], 1)[0]
            supply = self._call("supplyAt(uint32,uint64)", ["uint32", "uint64"], [tier, epoch], 1)[0]
            rows[label] = {"demand": demand, "supply": supply, "utilization_bps": demand * 10_000 // supply if supply else 0}
        return {**rows, "multiplier": self.multiplier(tier, today), "multiplier_yesterday": self.multiplier(tier, today - 1)}
