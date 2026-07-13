from __future__ import annotations

import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from gateway.identity import create_identity
from gateway.ledger import build_receipt, sign_acceptance
from gateway.p2p import DEFAULT_CHANNEL
from gateway.pricing import quote_usage
from gateway.settlement_blocks import (
    BlockRewardSplit,
    ConsumerVolumeRewardConfig,
    build_settlement_blocks,
    consumer_volume_multiplier,
    write_settlement_blocks,
)


class SettlementBlocksTest(unittest.TestCase):
    def test_builds_protocol_block_rewards_for_provider_bridge_and_consumer(self) -> None:
        receipt = _accepted_receipt(
            job_id="job-a",
            provider_id="provider-a",
            consumer_id="consumer-a",
            relay_id="relay-a",
            pool_url="http://pool-a",
            started_at=10.0,
            finished_at=20.0,
        )

        blocks = build_settlement_blocks([receipt], window_seconds=60, genesis_timestamp=0)

        self.assertEqual(len(blocks), 1)
        block = blocks[0]
        self.assertEqual(block["settlement_block_version"], "mycomesh-settlement-block-v1")
        self.assertEqual(block["height"], 0)
        self.assertEqual(block["started_at"], 0)
        self.assertEqual(block["ended_at"], 60)
        self.assertEqual(block["receipt_count"], 1)
        self.assertTrue(str(block["receipt_root"]).startswith("0x"))
        self.assertTrue(str(block["block_hash"]).startswith("0x"))
        self.assertEqual(block["stablecoin"]["gross_fees"], "0.006000")
        self.assertEqual(block["stablecoin"]["provider_amount"], "0.005100")
        self.assertEqual(block["stablecoin"]["bridge_amount"], "0.000300")
        self.assertEqual(block["stablecoin"]["treasury_amount"], "0.000600")
        self.assertEqual(block["block_rewards"]["budget"], "0.000600")
        self.assertEqual(block["block_rewards"]["provider_amount"], "0.000480")
        self.assertEqual(block["block_rewards"]["bridge_amount"], "0.000060")
        self.assertEqual(block["block_rewards"]["consumer_amount"], "0.000060")

        provider = block["participants"]["providers"][0]
        self.assertEqual(provider["id"], "provider-a")
        self.assertEqual(provider["stablecoin_amount"], "0.005100")
        self.assertEqual(provider["block_reward"], "0.000480")

        bridges = {item["id"]: item for item in block["participants"]["bridges"]}
        self.assertEqual(bridges["relay-a"]["stablecoin_amount"], "0.000180")
        self.assertEqual(bridges["relay-a"]["block_reward"], "0.000036")
        self.assertEqual(bridges["http://pool-a"]["stablecoin_amount"], "0.000120")
        self.assertEqual(bridges["http://pool-a"]["block_reward"], "0.000024")

        consumer = block["participants"]["consumers"][0]
        self.assertEqual(consumer["id"], "0x0000000000000000000000000000000000000001")
        self.assertEqual(consumer["consumer_id"], "consumer-a")
        self.assertEqual(consumer["spent_amount"], "0.006000")
        self.assertEqual(consumer["block_reward"], "0.000060")
        self.assertEqual(consumer["reward_weight"], "0.006000")
        self.assertEqual(consumer["volume_multiplier"], "1.000012")

    def test_defaults_to_accepted_receipts_only(self) -> None:
        accepted = _accepted_receipt(job_id="accepted", finished_at=20.0)
        unaccepted = _receipt(job_id="unaccepted", finished_at=30.0)

        accepted_only = build_settlement_blocks([accepted, unaccepted], window_seconds=60, genesis_timestamp=0)
        include_unaccepted = build_settlement_blocks(
            [accepted, unaccepted],
            window_seconds=60,
            genesis_timestamp=0,
            include_unaccepted=True,
        )

        self.assertEqual(accepted_only[0]["receipt_count"], 1)
        self.assertEqual(include_unaccepted[0]["receipt_count"], 2)

    def test_block_windows_and_previous_hash_are_deterministic(self) -> None:
        first = _accepted_receipt(job_id="job-a", finished_at=20.0)
        second = _accepted_receipt(job_id="job-b", finished_at=140.0)

        blocks = build_settlement_blocks([second, first], window_seconds=60, genesis_timestamp=0, include_empty=True)
        repeat = build_settlement_blocks([first, second], window_seconds=60, genesis_timestamp=0, include_empty=True)

        self.assertEqual(blocks, repeat)
        self.assertEqual([block["height"] for block in blocks], [0, 1, 2])
        self.assertEqual(blocks[1]["receipt_count"], 0)
        self.assertEqual(blocks[1]["previous_block_hash"], blocks[0]["block_hash"])
        self.assertEqual(blocks[2]["previous_block_hash"], blocks[1]["block_hash"])

    def test_rejects_invalid_reward_split(self) -> None:
        receipt = _accepted_receipt()

        with self.assertRaises(ValueError):
            build_settlement_blocks(
                [receipt],
                reward_split=BlockRewardSplit(provider_bps=9000, bridge_bps=1000, consumer_bps=1000),
            )

    def test_consumer_volume_curve_rewards_larger_addresses_more_per_unit(self) -> None:
        config = ConsumerVolumeRewardConfig(
            base_spend=quote_usage(DEFAULT_CHANNEL, {"input_tokens": 2000, "output_tokens": 1000}).gross_fee,
            beta=Decimal("0.5"),
            max_multiplier=Decimal("2.0"),
        )
        small = _accepted_receipt(
            job_id="small",
            consumer_id="small-consumer",
            consumer_payment_address="0x0000000000000000000000000000000000000011",
            finished_at=20.0,
        )
        large_one = _accepted_receipt(
            job_id="large-a",
            consumer_id="large-consumer-a",
            consumer_payment_address="0x0000000000000000000000000000000000000022",
            finished_at=21.0,
        )
        large_two = _accepted_receipt(
            job_id="large-b",
            consumer_id="large-consumer-b",
            consumer_payment_address="0x0000000000000000000000000000000000000022",
            finished_at=22.0,
        )

        block = build_settlement_blocks(
            [small, large_one, large_two],
            window_seconds=60,
            genesis_timestamp=0,
            consumer_reward_config=config,
        )[0]
        consumers = {item["id"]: item for item in block["participants"]["consumers"]}
        small_consumer = consumers["0x0000000000000000000000000000000000000011"]
        large_consumer = consumers["0x0000000000000000000000000000000000000022"]

        self.assertEqual(small_consumer["spent_amount"], "0.006000")
        self.assertEqual(large_consumer["spent_amount"], "0.012000")
        self.assertEqual(small_consumer["receipt_count"], 1)
        self.assertEqual(large_consumer["receipt_count"], 2)
        self.assertGreater(Decimal(large_consumer["volume_multiplier"]), Decimal(small_consumer["volume_multiplier"]))
        self.assertGreater(Decimal(large_consumer["effective_rebate_rate"]), Decimal(small_consumer["effective_rebate_rate"]))
        self.assertEqual(large_consumer["consumer_id"], "large-consumer-a")

    def test_consumer_volume_multiplier_is_capped(self) -> None:
        config = ConsumerVolumeRewardConfig(
            base_spend=Decimal("1"),
            beta=Decimal("10"),
            max_multiplier=Decimal("1.5"),
        )

        self.assertEqual(consumer_volume_multiplier(Decimal("1000000"), config), Decimal("1.500000"))

    def test_bridge_rewards_prefer_bridge_usage_details(self) -> None:
        receipt = _accepted_receipt(
            relay_id="legacy-relay",
            pool_url="http://legacy-pool",
            bridge_usage=[
                {"bridge_id": "http://pool-b", "type": "pool", "amount": "0.000120", "units": 1},
                {"bridge_id": "relay-b", "type": "relay", "amount": "0.000180", "units": 1},
            ],
        )

        block = build_settlement_blocks([receipt], window_seconds=60, genesis_timestamp=0)[0]
        bridges = {item["id"]: item for item in block["participants"]["bridges"]}

        self.assertIn("http://pool-b", bridges)
        self.assertIn("relay-b", bridges)
        self.assertNotIn("http://legacy-pool", bridges)
        self.assertNotIn("legacy-relay", bridges)
        self.assertEqual(bridges["relay-b"]["block_reward"], "0.000036")
        self.assertEqual(bridges["http://pool-b"]["block_reward"], "0.000024")

    def test_rejects_tampered_and_deduplicates_accepted_receipts(self) -> None:
        receipt = _accepted_receipt(job_id="unique", finished_at=20.0)
        tampered = dict(receipt)
        tampered["provider_id"] = "attacker"

        blocks = build_settlement_blocks(
            [receipt, dict(receipt), tampered],
            window_seconds=60,
            genesis_timestamp=0,
        )

        self.assertEqual(blocks[0]["receipt_count"], 1)
        self.assertEqual(blocks[0]["receipts"][0]["job_id"], "unique")

    def test_writes_jsonl_blocks(self) -> None:
        receipt = _accepted_receipt()
        blocks = build_settlement_blocks([receipt], window_seconds=60, genesis_timestamp=0)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blocks.jsonl"
            write_settlement_blocks(path, blocks)
            payload = json.loads(path.read_text(encoding="utf-8").strip())

        self.assertEqual(payload["block_hash"], blocks[0]["block_hash"])


def _accepted_receipt(
    *,
    job_id: str = "job-a",
    provider_id: str = "provider-a",
    consumer_id: str = "consumer-a",
    relay_id: str = "relay-a",
    pool_url: str = "http://pool-a",
    consumer_payment_address: str = "0x0000000000000000000000000000000000000001",
    started_at: float = 10.0,
    finished_at: float = 20.0,
    bridge_usage: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    identity = create_identity()
    return sign_acceptance(
        _receipt(
            job_id=job_id,
            provider_id=provider_id,
            consumer_id=consumer_id,
            relay_id=relay_id,
            pool_url=pool_url,
            consumer_payment_address=consumer_payment_address,
            started_at=started_at,
            finished_at=finished_at,
            bridge_usage=bridge_usage,
            signer=identity,
        ),
        identity,
        accepted_by=consumer_id,
    )


def _receipt(
    *,
    job_id: str = "job-a",
    provider_id: str = "provider-a",
    consumer_id: str = "consumer-a",
    relay_id: str = "relay-a",
    pool_url: str = "http://pool-a",
    consumer_payment_address: str = "0x0000000000000000000000000000000000000001",
    started_at: float = 10.0,
    finished_at: float = 20.0,
    bridge_usage: list[dict[str, object]] | None = None,
    signer=None,
) -> dict[str, object]:
    quote = quote_usage(DEFAULT_CHANNEL, {"input_tokens": 2000, "output_tokens": 1000})
    receipt = build_receipt(
        consumer_id=consumer_id,
        provider_id=provider_id,
        relay_id=relay_id,
        pool_url=pool_url,
        selected_address=f"relay://{relay_id}/{provider_id}",
        channel=DEFAULT_CHANNEL,
        model="gpt-5.5",
        endpoint="responses",
        input_value="hello",
        response={
            "request_id": job_id,
            "output_text": "world",
            "usage": {"input_tokens": 2000, "output_tokens": 1000},
        },
        quote=quote,
        started_at=started_at,
        finished_at=finished_at,
        consumer_payment_address=consumer_payment_address,
        provider_payment_address="0x0000000000000000000000000000000000000002",
        bridge_usage=bridge_usage,
        signer=signer,
    )
    return receipt.to_dict()


if __name__ == "__main__":
    unittest.main()
