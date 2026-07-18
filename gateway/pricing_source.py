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
    pricing_version: int | None = None
    settlement_version: int = 2


def channel_pricing_snapshot(
    pricing_table: dict[str, Any] | None,
    channel: str = DEFAULT_CHANNEL,
    *,
    override: str | None = None,
    rpc_url: str | None = None,
    settlement: str | None = None,
    pricing_version: int | None = None,
    settlement_version: int | None = None,
    timeout: float = 20.0,
    block_tag: str | int = "latest",
) -> ChannelPricingSnapshot:
    configured_settlement_version = _settlement_version(settlement_version)
    configured_pricing_version = _pricing_version(pricing_version)
    configured_override = override or os.getenv("MYCOMESH_CHANNEL_PRICING_HASH")
    if configured_override:
        if configured_settlement_version >= 3 and configured_pricing_version is None:
            raise RuntimeError("Settlement V3 pricing override requires MYCOMESH_PRICING_VERSION")
        return ChannelPricingSnapshot(
            channel=channel,
            pricing_hash=normalize_bytes32(configured_override),
            source="override",
            pricing_version=configured_pricing_version,
            settlement_version=configured_settlement_version,
        )

    strict = _strict_chain_pricing()
    configured_rpc = rpc_url or os.getenv("MYCOMESH_PRICING_RPC_URL") or os.getenv("ETH_RPC_URL")
    configured_settlement = settlement or os.getenv("MYCO_SETTLEMENT")
    if configured_rpc and configured_settlement:
        try:
            from .chain import ChainError, call_contract, channel_to_hash

            channel_hash = channel_to_hash(channel)
            if configured_settlement_version >= 3:
                if configured_pricing_version is None:
                    version_output = call_contract(
                        configured_rpc,
                        configured_settlement,
                        "latestChannelVersion(bytes32)",
                        [channel_hash],
                        timeout=timeout,
                        block_tag=block_tag,
                    )
                    configured_pricing_version = int(version_output, 16)
                if configured_pricing_version <= 0:
                    raise RuntimeError("Settlement V3 channel has no active pricing version")
                output = call_contract(
                    configured_rpc,
                    configured_settlement,
                    "channelPricingHash(bytes32,uint64)",
                    [channel_hash, str(configured_pricing_version)],
                    timeout=timeout,
                    block_tag=block_tag,
                )
            else:
                output = call_contract(
                    configured_rpc,
                    configured_settlement,
                    "channelPricingHash(bytes32)",
                    [channel_hash],
                    timeout=timeout,
                    block_tag=block_tag,
                )
            return ChannelPricingSnapshot(
                channel=channel,
                pricing_hash=normalize_bytes32(output[-66:]),
                source="chain",
                pricing_version=configured_pricing_version,
                settlement_version=configured_settlement_version,
            )
        except ChainError:
            if strict:
                raise
    elif strict:
        raise RuntimeError("strict chain pricing requires MYCOMESH_PRICING_RPC_URL/ETH_RPC_URL and MYCO_SETTLEMENT")

    table = pricing_table or {}
    config = table.get(channel)
    if strict:
        raise RuntimeError("no chain pricing hash available; configure MYCOMESH_PRICING_RPC_URL and MYCO_SETTLEMENT or set MYCOMESH_CHANNEL_PRICING_HASH")
    if configured_settlement_version >= 3:
        raise RuntimeError("Settlement V3 pricing cannot fall back to a local V2 hash")
    if config is not None and hasattr(config, "config_hash"):
        return ChannelPricingSnapshot(
            channel=channel,
            pricing_hash=str(config.config_hash()),
            source="local",
            pricing_version=None,
            settlement_version=configured_settlement_version,
        )
    return ChannelPricingSnapshot(
        channel=channel,
        pricing_hash=DEFAULT_CHANNEL_HASH,
        source="default",
        pricing_version=None,
        settlement_version=configured_settlement_version,
    )


def _strict_chain_pricing() -> bool:
    configured = os.getenv("MYCOMESH_STRICT_CHAIN_PRICING")
    if configured is not None:
        return configured.strip().lower() in {"1", "true", "yes", "on"}
    profile = os.getenv("MYCOMESH_NETWORK_PROFILE")
    return bool(profile and profile.strip().lower() != "local")


def _settlement_version(value: int | None) -> int:
    raw: Any = value if value is not None else os.getenv("MYCOMESH_SETTLEMENT_VERSION", "2")
    try:
        parsed = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("MYCOMESH_SETTLEMENT_VERSION must be an integer") from exc
    if parsed not in {2, 3, 4}:
        raise ValueError("MYCOMESH_SETTLEMENT_VERSION must be 2, 3, or 4")
    return parsed


def _pricing_version(value: int | None) -> int | None:
    raw: Any = value if value is not None else os.getenv("MYCOMESH_PRICING_VERSION")
    if raw in {None, ""}:
        return None
    try:
        parsed = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("MYCOMESH_PRICING_VERSION must be an integer") from exc
    if parsed <= 0 or parsed > (1 << 64) - 1:
        raise ValueError("MYCOMESH_PRICING_VERSION must be a positive uint64")
    return parsed


def normalize_bytes32(value: str) -> str:
    if not isinstance(value, str) or not BYTES32_PATTERN.match(value):
        raise ValueError(f"invalid bytes32 value: {value!r}")
    return "0x" + value[2:].lower()
