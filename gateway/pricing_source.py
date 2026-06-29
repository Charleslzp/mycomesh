from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from .pricing import DEFAULT_CHANNEL


DEFAULT_CHANNEL_HASH = "0xdedf8b58276b80863f354409c963cbaddf4ca7d5b866d528ff1386d74b339104"
BYTES32_PATTERN = re.compile(r"^0x[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class ChannelPricingSnapshot:
    channel: str
    pricing_hash: str
    source: str


def channel_pricing_snapshot(
    pricing_table: dict[str, Any] | None,
    channel: str = DEFAULT_CHANNEL,
    *,
    override: str | None = None,
    rpc_url: str | None = None,
    settlement: str | None = None,
    timeout: float = 20.0,
) -> ChannelPricingSnapshot:
    configured_override = override or os.getenv("MYCOMESH_CHANNEL_PRICING_HASH")
    if configured_override:
        return ChannelPricingSnapshot(channel=channel, pricing_hash=normalize_bytes32(configured_override), source="override")

    strict = _strict_chain_pricing()
    configured_rpc = rpc_url or os.getenv("MYCOMESH_PRICING_RPC_URL") or os.getenv("ETH_RPC_URL")
    configured_settlement = settlement or os.getenv("MYCO_SETTLEMENT")
    if configured_rpc and configured_settlement:
        try:
            from .chain import ChainError, call_contract, channel_to_hash

            channel_hash = channel_to_hash(channel)
            output = call_contract(
                configured_rpc,
                configured_settlement,
                "channelPricingHash(bytes32)",
                [channel_hash],
                timeout=timeout,
            )
            return ChannelPricingSnapshot(channel=channel, pricing_hash=normalize_bytes32(output[-66:]), source="chain")
        except ChainError:
            if strict:
                raise
    elif strict:
        raise RuntimeError("strict chain pricing requires MYCOMESH_PRICING_RPC_URL/ETH_RPC_URL and MYCO_SETTLEMENT")

    table = pricing_table or {}
    config = table.get(channel)
    if strict:
        raise RuntimeError("no chain pricing hash available; configure MYCOMESH_PRICING_RPC_URL and MYCO_SETTLEMENT or set MYCOMESH_CHANNEL_PRICING_HASH")
    if config is not None and hasattr(config, "config_hash"):
        return ChannelPricingSnapshot(channel=channel, pricing_hash=str(config.config_hash()), source="local")
    return ChannelPricingSnapshot(channel=channel, pricing_hash=DEFAULT_CHANNEL_HASH, source="default")


def _strict_chain_pricing() -> bool:
    return os.getenv("MYCOMESH_STRICT_CHAIN_PRICING", "").strip().lower() in {"1", "true", "yes", "on"}


def normalize_bytes32(value: str) -> str:
    if not isinstance(value, str) or not BYTES32_PATTERN.match(value):
        raise ValueError(f"invalid bytes32 value: {value!r}")
    return "0x" + value[2:].lower()
