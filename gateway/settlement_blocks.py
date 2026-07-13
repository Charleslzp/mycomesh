from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP, localcontext
from pathlib import Path
from typing import Any

from .ledger import receipt_hash, stable_hash, verify_acceptance, verify_receipt_signature
from .pricing import MONEY_QUANT, format_decimal


SETTLEMENT_BLOCK_VERSION = "mycomesh-settlement-block-v1"
DEFAULT_SETTLEMENT_BLOCK_SECONDS = 3600
DEFAULT_PROVIDER_BLOCK_REWARD_BPS = 8000
DEFAULT_BRIDGE_BLOCK_REWARD_BPS = 1000
DEFAULT_CONSUMER_BLOCK_REWARD_BPS = 1000
DEFAULT_CONSUMER_VOLUME_BASE_SPEND = Decimal("100")
DEFAULT_CONSUMER_VOLUME_BETA = Decimal("0.2")
DEFAULT_CONSUMER_VOLUME_MAX_MULTIPLIER = Decimal("2.0")
ZERO_BLOCK_HASH = "0x" + ("0" * 64)
RATIO_QUANT = Decimal("0.000001")


@dataclass(frozen=True)
class BlockRewardSplit:
    provider_bps: int = DEFAULT_PROVIDER_BLOCK_REWARD_BPS
    bridge_bps: int = DEFAULT_BRIDGE_BLOCK_REWARD_BPS
    consumer_bps: int = DEFAULT_CONSUMER_BLOCK_REWARD_BPS

    def validate(self) -> None:
        values = (self.provider_bps, self.bridge_bps, self.consumer_bps)
        if any(value < 0 for value in values):
            raise ValueError("block reward bps values must be non-negative")
        if sum(values) != 10_000:
            raise ValueError("provider, bridge, and consumer block reward bps must sum to 10000")


@dataclass(frozen=True)
class ConsumerVolumeRewardConfig:
    base_spend: Decimal = DEFAULT_CONSUMER_VOLUME_BASE_SPEND
    beta: Decimal = DEFAULT_CONSUMER_VOLUME_BETA
    max_multiplier: Decimal = DEFAULT_CONSUMER_VOLUME_MAX_MULTIPLIER

    def validate(self) -> None:
        if self.base_spend <= 0:
            raise ValueError("consumer volume base spend must be positive")
        if self.beta < 0:
            raise ValueError("consumer volume beta must be non-negative")
        if self.max_multiplier < 1:
            raise ValueError("consumer volume max multiplier must be at least 1")


def build_settlement_blocks(
    receipts: list[dict[str, Any]],
    *,
    window_seconds: int = DEFAULT_SETTLEMENT_BLOCK_SECONDS,
    genesis_timestamp: int | None = None,
    from_timestamp: int | None = None,
    to_timestamp: int | None = None,
    include_unaccepted: bool = False,
    include_empty: bool = False,
    reward_split: BlockRewardSplit | None = None,
    consumer_reward_config: ConsumerVolumeRewardConfig | None = None,
) -> list[dict[str, Any]]:
    """Build deterministic MycoMesh protocol settlement blocks from local receipts."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    split = reward_split or BlockRewardSplit()
    split.validate()
    consumer_config = consumer_reward_config or ConsumerVolumeRewardConfig()
    consumer_config.validate()

    selected = _select_receipts(
        receipts,
        include_unaccepted=include_unaccepted,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
    )
    if not selected:
        return []
    if genesis_timestamp is None:
        first_timestamp = min(item[0] for item in selected)
        genesis_timestamp = (first_timestamp // window_seconds) * window_seconds

    buckets: dict[int, list[tuple[int, str, dict[str, Any]]]] = {}
    for timestamp, stable_id, receipt in selected:
        if timestamp < genesis_timestamp:
            continue
        height = (timestamp - genesis_timestamp) // window_seconds
        buckets.setdefault(height, []).append((timestamp, stable_id, receipt))
    if not buckets:
        return []

    heights = range(min(buckets), max(buckets) + 1) if include_empty else sorted(buckets)
    previous_hash = ZERO_BLOCK_HASH
    blocks: list[dict[str, Any]] = []
    for height in heights:
        bucket_receipts = sorted(buckets.get(height, []), key=lambda item: (item[0], item[1]))
        started_at = genesis_timestamp + (height * window_seconds)
        block = _build_block(
            height=height,
            window_seconds=window_seconds,
            started_at=started_at,
            receipts=[item[2] for item in bucket_receipts],
            reward_split=split,
            consumer_reward_config=consumer_config,
            previous_block_hash=previous_hash,
        )
        previous_hash = str(block["block_hash"])
        blocks.append(block)
    return blocks


def write_settlement_blocks(path: Path, blocks: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        for block in blocks:
            file.write(json.dumps(block, ensure_ascii=False, sort_keys=True) + "\n")


def _select_receipts(
    receipts: list[dict[str, Any]],
    *,
    include_unaccepted: bool,
    from_timestamp: int | None,
    to_timestamp: int | None,
) -> list[tuple[int, str, dict[str, Any]]]:
    selected: list[tuple[int, str, dict[str, Any]]] = []
    seen_hashes: set[str] = set()
    for receipt in receipts:
        if not include_unaccepted and not _is_accepted(receipt):
            continue
        timestamp = _receipt_timestamp(receipt)
        if timestamp is None:
            continue
        if from_timestamp is not None and timestamp < from_timestamp:
            continue
        if to_timestamp is not None and timestamp >= to_timestamp:
            continue
        digest = receipt_hash(receipt)
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        selected.append((timestamp, digest, receipt))
    return sorted(selected, key=lambda item: (item[0], item[1]))


def _build_block(
    *,
    height: int,
    window_seconds: int,
    started_at: int,
    receipts: list[dict[str, Any]],
    reward_split: BlockRewardSplit,
    consumer_reward_config: ConsumerVolumeRewardConfig,
    previous_block_hash: str,
) -> dict[str, Any]:
    receipt_summaries = [
        {
            "receipt_hash": receipt_hash(receipt),
            "job_id": str(receipt.get("job_id") or ""),
            "provider_id": str(receipt.get("provider_id") or ""),
            "consumer_id": str(receipt.get("consumer_id") or ""),
            "finished_at": _receipt_timestamp(receipt),
        }
        for receipt in receipts
    ]
    receipt_hashes = [item["receipt_hash"] for item in receipt_summaries]

    providers: dict[str, dict[str, Any]] = {}
    bridges: dict[str, dict[str, Any]] = {}
    consumers: dict[str, dict[str, Any]] = {}
    stablecoin = {
        "gross_fees": Decimal("0"),
        "provider_amount": Decimal("0"),
        "bridge_amount": Decimal("0"),
        "relay_amount": Decimal("0"),
        "pool_amount": Decimal("0"),
        "treasury_amount": Decimal("0"),
    }
    reward_budget = Decimal("0")
    stablecoin_symbol = ""

    for receipt in receipts:
        pricing = receipt.get("pricing") if isinstance(receipt.get("pricing"), dict) else {}
        if isinstance(pricing, dict):
            stablecoin_symbol = stablecoin_symbol or str(pricing.get("stablecoin") or "")
        gross_fee = _pricing_amount(receipt, "gross_fee")
        provider_amount = _pricing_amount(receipt, "provider_amount")
        relay_amount = _pricing_amount(receipt, "relay_amount")
        pool_amount = _pricing_amount(receipt, "pool_amount")
        treasury_amount = _pricing_amount(receipt, "treasury_amount")
        reward_budget += _pricing_amount(receipt, "protocol_token_reward")

        stablecoin["gross_fees"] += gross_fee
        stablecoin["provider_amount"] += provider_amount
        stablecoin["relay_amount"] += relay_amount
        stablecoin["pool_amount"] += pool_amount
        stablecoin["bridge_amount"] += relay_amount + pool_amount
        stablecoin["treasury_amount"] += treasury_amount

        provider_id = str(receipt.get("provider_id") or "unknown-provider")
        provider = _participant(
            providers,
            provider_id,
            role="provider",
            participant_id=provider_id,
        )
        provider["stablecoin_amount"] += provider_amount
        provider["contribution"] += provider_amount
        provider["receipt_count"] += 1
        _set_once(provider, "payment_address", receipt.get("provider_payment_address"))
        _set_once(provider, "public_key", receipt.get("provider_public_key"))

        consumer_id = str(receipt.get("consumer_id") or "unknown-consumer")
        consumer_payment_address = str(receipt.get("consumer_payment_address") or "")
        consumer_key = f"address:{consumer_payment_address.lower()}" if consumer_payment_address else f"id:{consumer_id}"
        participant_id = consumer_payment_address or consumer_id
        consumer = _participant(
            consumers,
            consumer_key,
            role="consumer",
            participant_id=participant_id,
        )
        consumer["spent_amount"] += gross_fee
        consumer["receipt_count"] += 1
        _set_once(consumer, "consumer_id", consumer_id)
        _set_once(consumer, "payment_address", consumer_payment_address)
        _set_once(consumer, "public_key", receipt.get("consumer_public_key"))

        _record_bridge_usage(
            bridges,
            receipt,
            fallback_relay_amount=relay_amount,
            fallback_pool_amount=pool_amount,
        )

    reward_budget = reward_budget.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    role_allocations, role_unallocated = _allocate_decimal(
        reward_budget,
        {
            "provider": Decimal(reward_split.provider_bps),
            "bridge": Decimal(reward_split.bridge_bps),
            "consumer": Decimal(reward_split.consumer_bps),
        },
    )
    provider_reward_budget = role_allocations.get("provider", Decimal("0"))
    bridge_reward_budget = role_allocations.get("bridge", Decimal("0"))
    consumer_reward_budget = role_allocations.get("consumer", Decimal("0"))

    _apply_consumer_volume_weights(consumers, consumer_reward_config)

    unallocated_reward = role_unallocated
    unallocated_reward += _assign_block_rewards(providers, provider_reward_budget)
    unallocated_reward += _assign_block_rewards(bridges, bridge_reward_budget)
    unallocated_reward += _assign_block_rewards(consumers, consumer_reward_budget)

    block: dict[str, Any] = {
        "settlement_block_version": SETTLEMENT_BLOCK_VERSION,
        "height": height,
        "window_seconds": window_seconds,
        "started_at": started_at,
        "ended_at": started_at + window_seconds,
        "receipt_count": len(receipts),
        "receipt_root": _receipt_root(receipt_hashes),
        "previous_block_hash": previous_block_hash,
        "stablecoin": {
            "symbol": stablecoin_symbol or "USDC",
            "gross_fees": format_decimal(stablecoin["gross_fees"]),
            "provider_amount": format_decimal(stablecoin["provider_amount"]),
            "bridge_amount": format_decimal(stablecoin["bridge_amount"]),
            "relay_amount": format_decimal(stablecoin["relay_amount"]),
            "pool_amount": format_decimal(stablecoin["pool_amount"]),
            "treasury_amount": format_decimal(stablecoin["treasury_amount"]),
        },
        "block_rewards": {
            "budget": format_decimal(reward_budget),
            "provider_bps": reward_split.provider_bps,
            "bridge_bps": reward_split.bridge_bps,
            "consumer_bps": reward_split.consumer_bps,
            "provider_amount": format_decimal(provider_reward_budget),
            "bridge_amount": format_decimal(bridge_reward_budget),
            "consumer_amount": format_decimal(consumer_reward_budget),
            "unallocated_amount": format_decimal(unallocated_reward),
            "consumer_volume_base_spend": format_decimal(consumer_reward_config.base_spend),
            "consumer_volume_beta": format_ratio(consumer_reward_config.beta),
            "consumer_volume_max_multiplier": format_ratio(consumer_reward_config.max_multiplier),
        },
        "participants": {
            "providers": _format_participants(providers),
            "bridges": _format_participants(bridges),
            "consumers": _format_participants(consumers),
        },
        "treasury": {
            "stablecoin_amount": format_decimal(stablecoin["treasury_amount"]),
        },
        "receipts": receipt_summaries,
    }
    block["block_hash"] = "0x" + stable_hash(block)
    return block


def _assign_block_rewards(participants: dict[str, dict[str, Any]], reward_budget: Decimal) -> Decimal:
    if reward_budget <= 0:
        return Decimal("0")
    weights = {
        key: value["contribution"]
        for key, value in participants.items()
        if isinstance(value.get("contribution"), Decimal) and value["contribution"] > 0
    }
    allocations, unallocated = _allocate_decimal(reward_budget, weights)
    for key, amount in allocations.items():
        participants[key]["block_reward"] += amount
    return unallocated


def _record_bridge_usage(
    bridges: dict[str, dict[str, Any]],
    receipt: dict[str, Any],
    *,
    fallback_relay_amount: Decimal,
    fallback_pool_amount: Decimal,
) -> None:
    bridge_usage = receipt.get("bridge_usage")
    if isinstance(bridge_usage, list) and bridge_usage:
        for item in bridge_usage:
            if not isinstance(item, dict):
                continue
            bridge_id = str(item.get("bridge_id") or "")
            bridge_type = str(item.get("type") or "bridge")
            if not bridge_id:
                continue
            amount = _money(item.get("amount"))
            if amount <= 0:
                continue
            _record_bridge_participant(bridges, bridge_id, bridge_type, amount)
        return

    relay_id = str(receipt.get("relay_id") or "")
    if relay_id and fallback_relay_amount > 0:
        _record_bridge_participant(bridges, relay_id, "relay", fallback_relay_amount)

    pool_url = str(receipt.get("pool_url") or "")
    if pool_url and fallback_pool_amount > 0:
        _record_bridge_participant(bridges, pool_url, "pool", fallback_pool_amount)


def _record_bridge_participant(
    bridges: dict[str, dict[str, Any]],
    bridge_id: str,
    bridge_type: str,
    amount: Decimal,
) -> None:
    bridge = _participant(
        bridges,
        f"{bridge_type}:{bridge_id}",
        role="bridge",
        participant_id=bridge_id,
        bridge_type=bridge_type,
    )
    bridge["stablecoin_amount"] += amount
    bridge["contribution"] += amount
    bridge["receipt_count"] += 1


def _apply_consumer_volume_weights(
    consumers: dict[str, dict[str, Any]],
    config: ConsumerVolumeRewardConfig,
) -> None:
    for consumer in consumers.values():
        spent = consumer.get("spent_amount")
        if not isinstance(spent, Decimal) or spent <= 0:
            multiplier = Decimal("1")
            reward_weight = Decimal("0")
        else:
            multiplier = consumer_volume_multiplier(spent, config)
            reward_weight = (spent * multiplier).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
        consumer["volume_multiplier"] = multiplier
        consumer["reward_weight"] = reward_weight
        consumer["contribution"] = reward_weight


def consumer_volume_multiplier(spent_amount: Decimal, config: ConsumerVolumeRewardConfig | None = None) -> Decimal:
    resolved = config or ConsumerVolumeRewardConfig()
    resolved.validate()
    if spent_amount <= 0:
        return Decimal("1")
    with localcontext() as context:
        context.prec = 28
        ratio = Decimal("1") + (spent_amount / resolved.base_spend)
        multiplier = Decimal("1") + (resolved.beta * ratio.ln())
    return min(resolved.max_multiplier, multiplier).quantize(RATIO_QUANT, rounding=ROUND_HALF_UP)


def _allocate_decimal(total: Decimal, weights: dict[str, Decimal]) -> tuple[dict[str, Decimal], Decimal]:
    total = total.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    total_weight = sum(weights.values(), Decimal("0"))
    if total <= 0 or total_weight <= 0:
        return {}, total

    ordered = sorted(weights)
    allocations: dict[str, Decimal] = {}
    allocated = Decimal("0")
    for key in ordered:
        raw = total * weights[key] / total_weight
        amount = raw.quantize(MONEY_QUANT, rounding=ROUND_DOWN)
        allocations[key] = amount
        allocated += amount

    remainder = (total - allocated).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    if remainder > 0:
        largest_key = sorted(weights, key=lambda key: (-weights[key], key))[0]
        allocations[largest_key] += remainder
        allocated += remainder
    return allocations, (total - allocated).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


def _participant(
    participants: dict[str, dict[str, Any]],
    key: str,
    *,
    role: str,
    participant_id: str,
    bridge_type: str | None = None,
) -> dict[str, Any]:
    if key not in participants:
        participant = {
            "id": participant_id,
            "role": role,
            "receipt_count": 0,
            "contribution": Decimal("0"),
            "block_reward": Decimal("0"),
        }
        if role == "consumer":
            participant["spent_amount"] = Decimal("0")
        else:
            participant["stablecoin_amount"] = Decimal("0")
        if bridge_type:
            participant["bridge_type"] = bridge_type
        participants[key] = participant
    return participants[key]


def _format_participants(participants: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    formatted: list[dict[str, Any]] = []
    for participant in sorted(participants.values(), key=lambda item: (str(item.get("role")), str(item.get("id")))):
        item: dict[str, Any] = {
            "id": participant["id"],
            "role": participant["role"],
            "receipt_count": participant["receipt_count"],
            "contribution": format_decimal(participant["contribution"]),
            "block_reward": format_decimal(participant["block_reward"]),
        }
        if "stablecoin_amount" in participant:
            item["stablecoin_amount"] = format_decimal(participant["stablecoin_amount"])
        if "spent_amount" in participant:
            item["spent_amount"] = format_decimal(participant["spent_amount"])
        if "reward_weight" in participant:
            item["reward_weight"] = format_decimal(participant["reward_weight"])
        if "volume_multiplier" in participant:
            item["volume_multiplier"] = format_ratio(participant["volume_multiplier"])
        if participant.get("role") == "consumer":
            item["effective_rebate_rate"] = _effective_rebate_rate(participant)
        for key in ("bridge_type", "consumer_id", "payment_address", "public_key"):
            if participant.get(key):
                item[key] = participant[key]
        formatted.append(item)
    return formatted


def _effective_rebate_rate(participant: dict[str, Any]) -> str:
    spent = participant.get("spent_amount")
    reward = participant.get("block_reward")
    if not isinstance(spent, Decimal) or not isinstance(reward, Decimal) or spent <= 0:
        return format_ratio(Decimal("0"))
    return format_ratio(reward / spent)


def format_ratio(value: Decimal) -> str:
    quantized = value.quantize(RATIO_QUANT, rounding=ROUND_HALF_UP)
    return format(quantized, "f")


def _receipt_root(receipt_hashes: list[str]) -> str:
    return "0x" + stable_hash(receipt_hashes)


def _pricing_amount(receipt: dict[str, Any], key: str) -> Decimal:
    pricing = receipt.get("pricing")
    if not isinstance(pricing, dict):
        return Decimal("0")
    return _money(pricing.get(key))


def _money(value: Any) -> Decimal:
    if value is None:
        return Decimal("0")
    try:
        return Decimal(str(value)).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0")


def _receipt_timestamp(receipt: dict[str, Any]) -> int | None:
    for key in ("finished_at", "started_at"):
        value = receipt.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _is_accepted(receipt: dict[str, Any]) -> bool:
    if not receipt.get("accepted_hash") or not receipt.get("acceptance_signature"):
        return False
    try:
        verify_receipt_signature(receipt)
        verify_acceptance(receipt)
    except Exception:
        return False
    return True


def _set_once(participant: dict[str, Any], key: str, value: Any) -> None:
    if participant.get(key) or not value:
        return
    participant[key] = str(value)
