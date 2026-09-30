"""What an owner has on the network: deposit, earnings in escrow and holdback, reputation."""
from __future__ import annotations

from typing import Any

from . import rpc
from .evm import decode_words, encode_call

USDC = 10**6


def _word(network: Any, to: str, signature: str, types: list[Any], values: list[Any], count: int = 1) -> list[int]:
    raw = rpc.eth_call(network.rpc_urls, to, encode_call(signature, types, values))
    return [int.from_bytes(word, "big") for word in decode_words(raw, count)]


def summary(network: Any, owner: str) -> dict[str, Any]:
    settlement = network.settlement
    one = lambda signature: _word(network, settlement, signature, ["address"], [owner])[0]  # noqa: E731
    provider, stats_eligible = None, None
    try:
        words = _word(network, network.registry, "providerOf(address)", ["address"], [owner], 12)
        if words[0]:
            provider = {"active": bool(words[6]), "registered_at": words[5]}
            stats_eligible = {"epoch": words[7], "counterparties": words[8], "last_fraud_at": words[9],
                              "counted_volume": words[10], "jury_eligible": bool(words[11])}
    except rpc.RpcError:
        pass
    rules = None
    try:
        rule = _word(network, network.registry, "eligibility()", [], [], 5)
        size, threshold = (_word(network, network.registry, signature, [], [])[0] for signature in ("jurySize()", "threshold()"))
        rules = {"min_counted_volume": rule[0], "min_counterparties": rule[1], "min_age": rule[2], "fraud_cooldown": rule[3],
                 "per_counterparty_cap": rule[4], "jury_size": size, "threshold": threshold}
    except rpc.RpcError:
        pass
    return {
        "owner": owner,
        "jury_rules": rules,
        "eth_wei": rpc.quantity(rpc.call(network.rpc_urls, "eth_getBalance", [owner, "latest"])),
        "deposit": one("availableBalance(address)"),
        "claimable": one("claimableBalance(address)"),
        "holdback": one("holdbackBalance(address)"),
        "in_escrow": one("pendingExposure(address)"),
        "exposure_cap": one("exposureCap(address)"),
        "clean_volume": one("cleanVolume(address)"),
        "provider": provider,
        "reputation": stats_eligible,
    }


def encode_claim() -> str:
    return encode_call("claim()", [], [])


def encode_release_holdback(owner: str) -> str:
    return encode_call("releaseHoldback(address)", ["address"], [owner])
