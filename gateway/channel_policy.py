from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any


MYCOMESH_TESTNET_NETWORK_ID = "mycomesh-testnet"
MYCOMESH_CONTROLLED_V9_TEST_NETWORK_ID = "mycomesh-v9-controlled-test"
MYCOMESH_CONTROLLED_V10_TEST_NETWORK_ID = "mycomesh-v10-fixed-budget-controlled-test"
CODEX_CHANNEL_ID = "codex"
CODEX_SETTLEMENT_CHANNEL = "codex-standard-v1"
CODEX_BACKEND_POLICY = "codex-app-server-postvalidated-v1"

# These identifiers reserve the public namespace only. They intentionally have
# no settlement channel, backend, routing, or pricing configuration yet.
RESERVED_CHANNEL_IDS = frozenset({"claude", "open"})
KNOWN_CHANNEL_IDS = frozenset({CODEX_CHANNEL_ID, *RESERVED_CHANNEL_IDS})


@dataclass(frozen=True)
class ChannelBinding:
    network_id: str
    channel_id: str
    channel: str
    backend_policy: str

    def to_dict(self) -> dict[str, str]:
        return {
            "network_id": self.network_id,
            "channel_id": self.channel_id,
            "channel": self.channel,
            "backend_policy": self.backend_policy,
        }


CODEX_CHANNEL_BINDING = ChannelBinding(
    network_id=MYCOMESH_TESTNET_NETWORK_ID,
    channel_id=CODEX_CHANNEL_ID,
    channel=CODEX_SETTLEMENT_CHANNEL,
    backend_policy=CODEX_BACKEND_POLICY,
)


def require_enabled_channel_binding(
    *,
    network_id: Any,
    channel_id: Any,
    channel: Any,
    backend_policy: Any,
    label: str = "channel binding",
    allow_controlled_test: bool | None = None,
    allow_controlled_v10_test: bool | None = None,
) -> ChannelBinding:
    values = {
        "network_id": network_id,
        "channel_id": channel_id,
        "channel": channel,
        "backend_policy": backend_policy,
    }
    normalized: dict[str, str] = {}
    for field, value in values.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} {field} is required")
        if value != value.strip():
            raise ValueError(f"{label} {field} must not contain surrounding whitespace")
        normalized[field] = value

    requested_channel_id = normalized["channel_id"]
    if requested_channel_id in RESERVED_CHANNEL_IDS:
        raise ValueError(
            f"{label} channel_id {requested_channel_id!r} is reserved and not enabled"
        )
    if requested_channel_id not in KNOWN_CHANNEL_IDS:
        raise ValueError(f"{label} channel_id {requested_channel_id!r} is unknown")

    # Test processes must opt in locally. A remote network identifier cannot
    # enable this separate namespace on an ordinary public node.
    if allow_controlled_test is None:
        allow_controlled_test = os.environ.get("MYCOMESH_ALLOW_CONTROLLED_V9_TEST") == "1"
    if allow_controlled_v10_test is None:
        allow_controlled_v10_test = os.environ.get("MYCOMESH_ALLOW_CONTROLLED_V10_TEST") == "1"
    expected_binding = CODEX_CHANNEL_BINDING
    if (allow_controlled_test is True
            and normalized["network_id"] == MYCOMESH_CONTROLLED_V9_TEST_NETWORK_ID):
        expected_binding = ChannelBinding(MYCOMESH_CONTROLLED_V9_TEST_NETWORK_ID, CODEX_CHANNEL_ID,
                                          CODEX_SETTLEMENT_CHANNEL, CODEX_BACKEND_POLICY)
    if (allow_controlled_v10_test is True
            and normalized["network_id"] == MYCOMESH_CONTROLLED_V10_TEST_NETWORK_ID):
        expected_binding = ChannelBinding(MYCOMESH_CONTROLLED_V10_TEST_NETWORK_ID, CODEX_CHANNEL_ID,
                                          CODEX_SETTLEMENT_CHANNEL, CODEX_BACKEND_POLICY)
    for field, expected in expected_binding.to_dict().items():
        if normalized[field] != expected:
            raise ValueError(
                f"{label} {field} does not match the enabled {CODEX_CHANNEL_ID} binding"
            )
    return expected_binding


def require_deployment_channel_binding(deployment: Any) -> ChannelBinding:
    return require_enabled_channel_binding(
        network_id=getattr(deployment, "network_id", None),
        channel_id=getattr(deployment, "channel_id", None),
        channel=getattr(deployment, "channel", None),
        backend_policy=getattr(deployment, "backend_policy", None),
        label="V3 deployment",
    )
