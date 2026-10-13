"""What an owner has on the network: deposit, earnings in escrow and holdback, reputation."""
from __future__ import annotations

from typing import Any

from . import rpc
from .evm import decode_words, encode_call, keccak256

USDC = 10**6
LOG_CHUNK = 10_000
BLOCK_SECONDS = 12  # Sepolia; only bounds how far back the logs are read
ESCROWED = "0x" + keccak256(b"ReceiptEscrowed(bytes32,bytes32,address,address,uint256,uint256)").hex()
HOLDBACK_ADDED = "0x" + keccak256(b"HoldbackAdded(address,uint256,uint64)").hex()


def _word(network: Any, to: str, signature: str, types: list[Any], values: list[Any], count: int = 1) -> list[int]:
    raw = rpc.eth_call(network.rpc_urls, to, encode_call(signature, types, values))
    return [int.from_bytes(word, "big") for word in decode_words(raw, count)]


def pricing_summary(network: Any, signer: str) -> dict[str, Any] | None:
    from .pricing import NetworkPricing

    pricing = NetworkPricing(network.rpc_urls, network.registry)
    try:
        state = pricing.signer(signer)
        if not state["tier"]:
            return None
        return {"signer": signer, "tier": state["tier"], "declared_capacity": state["declared"], "peak_day": state["peak"],
                "remaining_today": pricing.remaining_capacity(signer),
                "prices": pricing.effective_prices(state["tier"], rpc.block_time(network.rpc_urls)),
                "market": pricing.market(state["tier"])}
    except rpc.RpcError:
        return None


def _logs(network: Any, query: dict[str, Any], seconds_back: int) -> list[dict[str, Any]]:
    head = rpc.quantity(rpc.call(network.rpc_urls, "eth_blockNumber", []))
    start = max(0, head - seconds_back // BLOCK_SECONDS)
    found: list[dict[str, Any]] = []
    for first in range(start, head + 1, LOG_CHUNK):
        last = min(head, first + LOG_CHUNK - 1)
        try:
            found += rpc.call(network.rpc_urls, "eth_getLogs", [{**query, "fromBlock": hex(first), "toBlock": hex(last)}])
        except rpc.RpcError as exc:  # a load-balanced RPC a block behind the head
            if "beyond current head" not in str(exc):
                raise
            found += rpc.call(network.rpc_urls, "eth_getLogs", [{**query, "fromBlock": hex(first), "toBlock": hex(max(first, last - 3))}])
    return found


def schedule(network: Any, owner: str, now: int) -> dict[str, Any]:
    """When the money now locked becomes claimable: escrowed fees after their dispute window (then a Relay or
    keeper releases them within minutes), held-back shares after the holdback period."""
    params = _word(network, network.settlement, "params()", [], [], 15)
    dispute_window, holdback_period = params[0], params[6]
    owner_word = owner.lower().removeprefix("0x").rjust(64, "0")
    escrow: list[tuple[int, int]] = []
    for entry in _logs(network, {"address": network.settlement, "topics": [ESCROWED]}, dispute_window + 7_200):
        data = entry["data"].removeprefix("0x")
        if data[:64] == owner_word:  # the Provider's owner, not indexed
            release_at = int(data[128:192], 16)
            if release_at > now:
                escrow.append((release_at, int(data[64:128], 16)))
    holdback: dict[int, int] = {}
    for entry in _logs(network, {"address": network.settlement, "topics": [HOLDBACK_ADDED, "0x" + owner_word]},
                       holdback_period + 86_400):
        data = entry["data"].removeprefix("0x")
        day = int(data[64:128], 16)
        holdback[day] = holdback.get(day, 0) + int(data[:64], 16)
    maturing = sorted((day * 86_400 + holdback_period, amount) for day, amount in holdback.items())
    return {
        "dispute_window": dispute_window, "holdback_period": holdback_period,
        "escrow_next_release_at": min((at for at, _ in escrow), default=None),
        "escrow_all_released_by": max((at for at, _ in escrow), default=None),
        "holdback_maturing": [{"at": at, "amount": amount} for at, amount in maturing if at > now],
    }


def summary(network: Any, owner: str, signer: str | None = None) -> dict[str, Any]:
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
    result = {
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
        "pricing": pricing_summary(network, signer) if signer else None,
        "schedule": _schedule_or_none(network, owner),
    }
    if result["schedule"] is not None:  # held back long enough, waiting only for the next claim to move it
        result["schedule"]["holdback_matured"] = max(
            0, result["holdback"] - sum(item["amount"] for item in result["schedule"]["holdback_maturing"]))
    return result


def _schedule_or_none(network: Any, owner: str) -> dict[str, Any] | None:
    try:
        return schedule(network, owner, rpc.block_time(network.rpc_urls))
    except (rpc.RpcError, ValueError):
        return None


def encode_claim() -> str:
    return encode_call("claim()", [], [])


def encode_release_holdback(owner: str) -> str:
    return encode_call("releaseHoldback(address)", ["address"], [owner])
