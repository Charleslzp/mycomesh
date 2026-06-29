from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any


MONEY_QUANT = Decimal("0.000001")
TOKEN_UNIT = Decimal("1000")
DEFAULT_CHANNEL = "codex-standard-v1"


@dataclass(frozen=True)
class ChannelPricing:
    channel: str
    stablecoin: str = "USDC"
    input_per_1k: Decimal = Decimal("0.001")
    output_per_1k: Decimal = Decimal("0.004")
    minimum_fee: Decimal = Decimal("0.002")
    base_multiplier: Decimal = Decimal("1.0")
    utilization_multiplier: Decimal = Decimal("1.0")
    quality_multiplier: Decimal = Decimal("1.0")
    provider_share: Decimal = Decimal("0.85")
    relay_share: Decimal = Decimal("0.03")
    pool_share: Decimal = Decimal("0.02")
    treasury_share: Decimal = Decimal("0.10")
    reward_token_multiplier: Decimal = Decimal("1.0")

    @property
    def effective_multiplier(self) -> Decimal:
        return self.base_multiplier * self.utilization_multiplier * self.quality_multiplier

    def config_hash(self) -> str:
        return solidity_channel_pricing_hash(self)


@dataclass(frozen=True)
class PriceQuote:
    channel: str
    stablecoin: str
    input_tokens: int
    output_tokens: int
    gross_fee: Decimal
    provider_amount: Decimal
    relay_amount: Decimal
    pool_amount: Decimal
    treasury_amount: Decimal
    protocol_token_reward: Decimal
    effective_multiplier: Decimal
    pricing_config_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "stablecoin": self.stablecoin,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "gross_fee": format_decimal(self.gross_fee),
            "provider_amount": format_decimal(self.provider_amount),
            "relay_amount": format_decimal(self.relay_amount),
            "pool_amount": format_decimal(self.pool_amount),
            "treasury_amount": format_decimal(self.treasury_amount),
            "protocol_token_reward": format_decimal(self.protocol_token_reward),
            "effective_multiplier": format_decimal(self.effective_multiplier),
            "pricing_config_hash": self.pricing_config_hash,
        }


DEFAULT_PRICING = {
    DEFAULT_CHANNEL: ChannelPricing(channel=DEFAULT_CHANNEL),
}


def load_pricing_config(path: str | Path | None = None) -> dict[str, ChannelPricing]:
    if path is None:
        return DEFAULT_PRICING
    resolved = Path(path)
    if not resolved.exists():
        return DEFAULT_PRICING
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    channels = payload.get("channels", payload)
    if not isinstance(channels, dict):
        raise ValueError("pricing config must contain a channels object")
    loaded: dict[str, ChannelPricing] = {}
    for channel, raw in channels.items():
        if not isinstance(raw, dict):
            continue
        loaded[str(channel)] = ChannelPricing(
            channel=str(channel),
            stablecoin=str(raw.get("stablecoin", "USDC")),
            input_per_1k=Decimal(str(raw.get("input_per_1k", "0.001"))),
            output_per_1k=Decimal(str(raw.get("output_per_1k", "0.004"))),
            minimum_fee=Decimal(str(raw.get("minimum_fee", "0.002"))),
            base_multiplier=Decimal(str(raw.get("base_multiplier", "1.0"))),
            utilization_multiplier=Decimal(str(raw.get("utilization_multiplier", "1.0"))),
            quality_multiplier=Decimal(str(raw.get("quality_multiplier", "1.0"))),
            provider_share=Decimal(str(raw.get("provider_share", "0.85"))),
            relay_share=Decimal(str(raw.get("relay_share", "0.03"))),
            pool_share=Decimal(str(raw.get("pool_share", "0.02"))),
            treasury_share=Decimal(str(raw.get("treasury_share", "0.10"))),
            reward_token_multiplier=Decimal(str(raw.get("reward_token_multiplier", "1.0"))),
        )
    return {**DEFAULT_PRICING, **loaded}


def quote_usage(
    channel: str,
    usage: dict[str, Any] | None,
    pricing: ChannelPricing | None = None,
    pricing_table: dict[str, ChannelPricing] | None = None,
) -> PriceQuote:
    table = pricing_table or DEFAULT_PRICING
    config = pricing or table.get(channel) or ChannelPricing(channel=channel)
    input_tokens, output_tokens = usage_tokens(usage)
    multiplier = config.effective_multiplier
    usage_fee = (
        (Decimal(input_tokens) / TOKEN_UNIT * config.input_per_1k)
        + (Decimal(output_tokens) / TOKEN_UNIT * config.output_per_1k)
    ) * multiplier
    gross = max(config.minimum_fee, usage_fee).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    provider_amount = (gross * config.provider_share).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    relay_amount = (gross * config.relay_share).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    pool_amount = (gross * config.pool_share).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    treasury_amount = (gross - provider_amount - relay_amount - pool_amount).quantize(
        MONEY_QUANT,
        rounding=ROUND_HALF_UP,
    )
    token_reward = (treasury_amount * config.reward_token_multiplier).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    return PriceQuote(
        channel=config.channel,
        stablecoin=config.stablecoin,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        gross_fee=gross,
        provider_amount=provider_amount,
        relay_amount=relay_amount,
        pool_amount=pool_amount,
        treasury_amount=treasury_amount,
        protocol_token_reward=token_reward,
        effective_multiplier=multiplier,
        pricing_config_hash=config.config_hash(),
    )


def solidity_channel_pricing_hash(config: ChannelPricing) -> str:
    """Mirror MycoSettlementV2._channelPricingHash ABI encoding."""
    channel_hash = keccak256(config.channel.encode("utf-8"))
    encoded = b"".join(
        [
            channel_hash,
            _uint256(_usdc_units(config.input_per_1k)),
            _uint256(_usdc_units(config.output_per_1k)),
            _uint256(_usdc_units(config.minimum_fee)),
            _uint256(_share_bps(config.provider_share)),
            _uint256(_share_bps(config.relay_share)),
            _uint256(_share_bps(config.pool_share)),
            _uint256(_share_bps(config.treasury_share)),
            _uint256(9000),
            _uint256(1000),
            _uint256(_reward_per_treasury_unit(config.reward_token_multiplier)),
            _uint256(1),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def usage_tokens(usage: dict[str, Any] | None) -> tuple[int, int]:
    if not isinstance(usage, dict):
        return 0, 0
    input_tokens = _usage_int(
        usage,
        "input_tokens",
        "prompt_tokens",
        "input_token_count",
    )
    output_tokens = _usage_int(
        usage,
        "output_tokens",
        "completion_tokens",
        "output_token_count",
    )
    if input_tokens == 0 and output_tokens == 0:
        total_tokens = _usage_int(usage, "total_tokens")
        input_tokens = total_tokens
    return input_tokens, output_tokens


def format_decimal(value: Decimal) -> str:
    quantized = value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    return format(quantized, "f")


def keccak256(payload: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
    except ImportError:  # pragma: no cover - pycryptodome is in requirements
        return hashlib.sha3_256(payload).digest()
    digest = keccak.new(digest_bits=256)
    digest.update(payload)
    return digest.digest()


def _uint256(value: int) -> bytes:
    if value < 0:
        raise ValueError("uint256 cannot be negative")
    return int(value).to_bytes(32, "big")


def _usdc_units(value: Decimal) -> int:
    return int(value * Decimal("1000000"))


def _share_bps(value: Decimal) -> int:
    return int(value * Decimal("10000"))


def _reward_per_treasury_unit(value: Decimal) -> int:
    return int(value * Decimal("1000000000000"))


def _usage_int(usage: dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = usage.get(key)
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        if parsed > 0:
            return parsed
    return 0
