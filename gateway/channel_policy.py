from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MYCOMESH_TESTNET_NETWORK_ID = "mycomesh-testnet"
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

    for field, expected in CODEX_CHANNEL_BINDING.to_dict().items():
        if normalized[field] != expected:
            raise ValueError(
                f"{label} {field} does not match the enabled {CODEX_CHANNEL_ID} binding"
            )
    return CODEX_CHANNEL_BINDING


def require_deployment_channel_binding(deployment: Any) -> ChannelBinding:
    return require_enabled_channel_binding(
        network_id=getattr(deployment, "network_id", None),
        channel_id=getattr(deployment, "channel_id", None),
        channel=getattr(deployment, "channel", None),
        backend_policy=getattr(deployment, "backend_policy", None),
        label="V3 deployment",
    )
