"""Operator-selected Provider membership, checked after signature verification."""
from __future__ import annotations

import os
import re
from collections.abc import Mapping

ENV_NAME = "MYCOMESH_RELAY_PROVIDER_PUBLIC_KEYS"


def normalize_provider_keys(values: object) -> frozenset[str]:
    if not isinstance(values, (list, tuple, set, frozenset)) or not 1 <= len(values) <= 1024:
        raise ValueError("Provider allowlist requires 1 to 1024 public keys")
    if any(not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key) for key in values):
        raise ValueError("Provider allowlist keys must be canonical Ed25519 public keys")
    return frozenset(values)


def provider_keys_from_env() -> frozenset[str] | None:
    raw = os.environ.get(ENV_NAME)
    # Absence keeps existing deployments compatible. An explicit empty value
    # is a configuration error, never a switch back to public admission.
    return None if raw is None else normalize_provider_keys(raw.split(","))


def manifest_provider_keys(manifest: Mapping, *, required: bool = False) -> frozenset[str] | None:
    mode = manifest.get("provider_admission")
    if mode is None and not required:
        if "provider_public_keys" in manifest:
            raise ValueError("Provider keys require explicit allowlist admission")
        return None
    if mode != "allowlist":
        raise ValueError("This controlled deployment requires provider_admission=allowlist")
    return normalize_provider_keys(manifest.get("provider_public_keys"))


def admitted_provider(peer: Mapping, keys: frozenset[str] | None) -> bool:
    """Only call on a registration whose Ed25519 signature was verified."""
    return keys is None or peer.get("public_key") in keys
