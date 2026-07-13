from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any


MONEY_QUANT = Decimal("0.000001")
USDC_SCALE = Decimal("1000000")
BPS_SCALE = Decimal("10000")
UINT256_MAX = (1 << 256) - 1
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

    def __post_init__(self) -> None:
        if not self.channel.strip():
            raise ValueError("pricing channel is required")
        if not self.stablecoin.strip():
            raise ValueError("pricing stablecoin is required")
        for name in ("input_per_1k", "output_per_1k", "minimum_fee"):
            _validate_fixed_point(name, getattr(self, name), USDC_SCALE)
        for name in ("provider_share", "relay_share", "pool_share", "treasury_share"):
            value = getattr(self, name)
            _validate_fixed_point(name, value, BPS_SCALE)
            if value > 1:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.provider_share + self.relay_share + self.pool_share + self.treasury_share != 1:
            raise ValueError("pricing shares must sum to 1")
        _validate_fixed_point("reward_token_multiplier", self.reward_token_multiplier, Decimal("1000000000000"))
        for name in ("base_multiplier", "utilization_multiplier", "quality_multiplier"):
            value = getattr(self, name)
            if not value.is_finite() or value != 1:
                raise ValueError(f"{name} is not supported by the settlement contract and must be 1")

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
    input_rate = _usdc_units(config.input_per_1k)
    output_rate = _usdc_units(config.output_per_1k)
    weighted_usage = _checked_add(
        _checked_multiply(input_tokens, input_rate),
        _checked_multiply(output_tokens, output_rate),
    )
    usage_units = weighted_usage // 1000
    gross_units = max(_usdc_units(config.minimum_fee), usage_units)
    provider_units = _checked_multiply(gross_units, _share_bps(config.provider_share)) // 10_000
    relay_units = _checked_multiply(gross_units, _share_bps(config.relay_share)) // 10_000
    pool_units = _checked_multiply(gross_units, _share_bps(config.pool_share)) // 10_000
    treasury_units = gross_units - provider_units - relay_units - pool_units
    gross = _from_usdc_units(gross_units)
    provider_amount = _from_usdc_units(provider_units)
    relay_amount = _from_usdc_units(relay_units)
    pool_amount = _from_usdc_units(pool_units)
    treasury_amount = _from_usdc_units(treasury_units)
    token_reward = (
        Decimal(treasury_units) * Decimal(_reward_per_treasury_unit(config.reward_token_multiplier))
        / Decimal("1000000000000000000")
    )
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
    return int(value * USDC_SCALE)


def _share_bps(value: Decimal) -> int:
    return int(value * BPS_SCALE)


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
            if parsed > UINT256_MAX:
                raise ValueError("token count exceeds uint256")
            return parsed
    return 0


def _from_usdc_units(value: int) -> Decimal:
    return Decimal(value) / USDC_SCALE


def _validate_fixed_point(name: str, value: Decimal, scale: Decimal) -> None:
    if not value.is_finite() or value < 0:
        raise ValueError(f"{name} must be a finite non-negative decimal")
    scaled = value * scale
    if scaled != scaled.to_integral_value():
        raise ValueError(f"{name} has more precision than the settlement contract supports")
    if scaled > UINT256_MAX:
        raise ValueError(f"{name} exceeds uint256")


def _checked_multiply(left: int, right: int) -> int:
    if left < 0 or right < 0 or (left and right > UINT256_MAX // left):
        raise ValueError("pricing calculation exceeds uint256")
    return left * right


def _checked_add(left: int, right: int) -> int:
    if left > UINT256_MAX - right:
        raise ValueError("pricing calculation exceeds uint256")
    return left + right


DEFAULT_PRICING = {
    DEFAULT_CHANNEL: ChannelPricing(channel=DEFAULT_CHANNEL),
}
