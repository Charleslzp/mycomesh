from __future__ import annotations

import argparse
import json
import os
import re
import stat
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from .chain import MAX_RPC_ENDPOINTS, ChainError, normalize_address, parse_private_key, private_key_to_address
from .chain_v3 import V3Deployment, load_deployment as load_v3_deployment
from .channel_policy import require_enabled_channel_binding
from .identity import IdentityError, load_identity
from .pool import PoolError, discover_peers
from .gateway_registry import GatewayRegistryError, normalize_gateway_url


DEFAULT_PROVIDER_NETWORK_PATH = "/app/deployments/sepolia-provider-network.json"
DEFAULT_PROVIDER_EVM_IDENTITY_PATH = "/data/provider-evm-identity.json"
MAX_PROVIDER_CONFIG_BYTES = 64 * 1024
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_PUBLIC_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_NETWORK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class ProviderBootstrapError(ValueError):
    pass


@dataclass(frozen=True)
class ProviderEvmIdentity:
    private_key: str = field(repr=False)
    address: str


@dataclass(frozen=True)
class ProviderNetworkConfig:
    path: Path
    network_id: str
    channel_id: str
    backend_policy: str
    deployment_path: Path
    deployment: V3Deployment
    settlement_rpc_url: str
    settlement_rpc_urls: tuple[str, ...]
    public_model_id: str
    reserve_input_bytes: int
    reserve_output_tokens: int
    bridge_urls: tuple[str, ...]
    consumer_public_keys: tuple[str, ...]
    provider_transport: str
    relay_host: str
    relay_port: int
    relay_public_url: str
    relay_provider_tls: bool


def load_provider_network_config(path: str | Path) -> ProviderNetworkConfig:
    source = Path(path)
    payload = _read_json_object(source, label="Provider network config")
    required = {
        "schema_version",
        "network_profile",
        "network_id",
        "channel_id",
        "backend_policy",
        "deployment",
        "settlement_rpc_url",
        "public_model_id",
        "reserve_input_bytes",
        "reserve_output_tokens",
        "bridge_urls",
        "provider_transport",
        "relay",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise ProviderBootstrapError(
            "Provider network config is missing required fields: " + ", ".join(missing)
        )
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise ProviderBootstrapError("Provider network config schema_version must be 1")
    if payload["network_profile"] != "testnet":
        raise ProviderBootstrapError("Provider network config must use the testnet profile")

    network_id = str(payload["network_id"])
    if _NETWORK_ID_PATTERN.fullmatch(network_id) is None:
        raise ProviderBootstrapError("Provider network config has an invalid network_id")

    deployment_name = str(payload["deployment"])
    if not deployment_name or Path(deployment_name).name != deployment_name:
        raise ProviderBootstrapError("Provider network deployment must be a sibling filename")
    deployment_path = source.parent / deployment_name
    try:
        deployment = load_v3_deployment(deployment_path)
    except (ChainError, OSError, TypeError, ValueError) as exc:
        raise ProviderBootstrapError(f"Provider V3 deployment manifest is invalid: {exc}") from exc

    channel_id = str(payload["channel_id"])
    backend_policy = str(payload["backend_policy"])
    try:
        require_enabled_channel_binding(
            network_id=network_id,
            channel_id=channel_id,
            channel=deployment.channel,
            backend_policy=backend_policy,
            label="Provider network config",
        )
    except ValueError as exc:
        raise ProviderBootstrapError(str(exc)) from exc
    if (
        deployment.network_id != network_id
        or deployment.channel_id != channel_id
        or deployment.backend_policy != backend_policy
    ):
        raise ProviderBootstrapError(
            "Provider network config channel binding does not match its V3 deployment"
        )

    primary_settlement_rpc_url = _https_url(
        payload["settlement_rpc_url"],
        label="Provider settlement RPC URL",
        require_origin=False,
    )
    rpc_values = payload.get("settlement_rpc_urls", [primary_settlement_rpc_url])
    if not isinstance(rpc_values, list) or not rpc_values:
        raise ProviderBootstrapError("Provider network settlement_rpc_urls must be a non-empty list")
    if len(rpc_values) > MAX_RPC_ENDPOINTS:
        raise ProviderBootstrapError(
            f"Provider network settlement_rpc_urls must contain at most {MAX_RPC_ENDPOINTS} URLs"
        )
    settlement_rpc_urls = tuple(
        _https_url(value, label="Provider settlement RPC URL", require_origin=False)
        for value in rpc_values
    )
    if len(set(settlement_rpc_urls)) != len(settlement_rpc_urls):
        raise ProviderBootstrapError("Provider network settlement_rpc_urls must be unique")
    if settlement_rpc_urls[0] != primary_settlement_rpc_url:
        raise ProviderBootstrapError(
            "Provider network settlement_rpc_url must be the first settlement_rpc_urls entry"
        )
    settlement_rpc_url = ",".join(settlement_rpc_urls)
    public_model_id = str(payload["public_model_id"])
    if _MODEL_ID_PATTERN.fullmatch(public_model_id) is None:
        raise ProviderBootstrapError("Provider network public_model_id is invalid")
    reserve_input_bytes = _bounded_manifest_int(
        payload["reserve_input_bytes"], "reserve_input_bytes", 1_000_000
    )
    reserve_output_tokens = _bounded_manifest_int(
        payload["reserve_output_tokens"], "reserve_output_tokens", 1_000_000
    )
    bridge_values = payload["bridge_urls"]
    if not isinstance(bridge_values, list) or not bridge_values:
        raise ProviderBootstrapError("Provider network bridge_urls must be a non-empty list")
    bridge_urls = tuple(_canonical_bridge_url(value) for value in bridge_values)
    if len(set(bridge_urls)) != len(bridge_urls):
        raise ProviderBootstrapError("Provider network bridge_urls must be unique")

    consumer_values = payload.get("consumer_public_keys", [])
    if not isinstance(consumer_values, list):
        raise ProviderBootstrapError(
            "Provider network consumer_public_keys must be a list"
        )
    consumer_public_keys = tuple(_consumer_public_key(value) for value in consumer_values)
    if len(set(consumer_public_keys)) != len(consumer_public_keys):
        raise ProviderBootstrapError("Provider network consumer_public_keys must be unique")

    provider_transport = str(payload["provider_transport"])
    if provider_transport not in {"direct", "relay"}:
        raise ProviderBootstrapError("Provider network provider_transport must be direct or relay")

    relay = payload["relay"]
    if not isinstance(relay, dict):
        raise ProviderBootstrapError("Provider network relay must be an object")
    relay_host = str(relay.get("host") or "")
    parsed_relay_host = urlsplit("//" + relay_host)
    if (
        not relay_host
        or parsed_relay_host.hostname != relay_host.lower()
        or parsed_relay_host.username is not None
        or parsed_relay_host.password is not None
    ):
        raise ProviderBootstrapError("Provider network relay host must be a DNS hostname")
    relay_port = relay.get("provider_port")
    if type(relay_port) is not int or not 1 <= relay_port <= 65535:
        raise ProviderBootstrapError("Provider network relay provider_port must be 1-65535")
    relay_public_url = _https_url(
        relay.get("public_url"),
        label="Provider relay public URL",
        require_origin=True,
    )
    relay_provider_tls = relay.get("provider_tls")
    if type(relay_provider_tls) is not bool:
        raise ProviderBootstrapError("Provider network relay provider_tls must be a boolean")
    if provider_transport == "relay" and not relay_provider_tls:
        raise ProviderBootstrapError("Testnet Relay Provider transport requires provider_tls=true")
    if urlsplit(relay_public_url).hostname != relay_host.lower():
        raise ProviderBootstrapError("Provider relay public URL must match relay host")

    return ProviderNetworkConfig(
        path=source,
        network_id=network_id,
        channel_id=channel_id,
        backend_policy=backend_policy,
        deployment_path=deployment_path,
        deployment=deployment,
        settlement_rpc_url=settlement_rpc_url,
        settlement_rpc_urls=settlement_rpc_urls,
        public_model_id=public_model_id,
        reserve_input_bytes=reserve_input_bytes,
        reserve_output_tokens=reserve_output_tokens,
        bridge_urls=bridge_urls,
        consumer_public_keys=consumer_public_keys,
        provider_transport=provider_transport,
        relay_host=relay_host,
        relay_port=relay_port,
        relay_public_url=relay_public_url,
        relay_provider_tls=relay_provider_tls,
    )


def apply_provider_network_config(
    args: argparse.Namespace | SimpleNamespace,
    path: str | Path,
    *,
    evm_identity_path: str | Path = DEFAULT_PROVIDER_EVM_IDENTITY_PATH,
    env: MutableMapping[str, str] | None = None,
) -> ProviderNetworkConfig:
    """Hydrate public testnet values and a private, volume-local payout identity."""

    values = os.environ if env is None else env
    config = load_provider_network_config(path)
    _require_or_set(args, "network_profile", "testnet", label="network profile")
    _require_or_set(args, "network_id", config.network_id, label="network id")
    _require_or_set(args, "channel_id", config.channel_id, label="channel id")
    _require_or_set(args, "backend_policy", config.backend_policy, label="backend policy")
    _require_or_set(args, "channel", config.deployment.channel, label="settlement channel")
    _require_env_or_set(values, "MYCOMESH_NETWORK_ID", config.network_id)
    _require_env_or_set(values, "MYCOMESH_CHANNEL_ID", config.channel_id)
    _require_env_or_set(values, "MYCOMESH_BACKEND_POLICY", config.backend_policy)
    _require_env_or_set(values, "MYCOMESH_CHANNEL", config.deployment.channel)

    configured_deployment = str(values.get("MYCO_DEPLOYMENT") or "").strip()
    if configured_deployment:
        if Path(configured_deployment).absolute() != config.deployment_path.absolute():
            raise ProviderBootstrapError(
                "MYCO_DEPLOYMENT does not match the Provider network config"
            )
    else:
        values["MYCO_DEPLOYMENT"] = str(config.deployment_path)

    _require_or_set(args, "settlement_version", 3, label="settlement version")
    _require_or_set(args, "model", config.public_model_id, label="public model id")
    _require_or_set(
        args,
        "reserve_input_tokens",
        config.reserve_input_bytes,
        label="input byte reserve",
    )
    _require_or_set(
        args,
        "reserve_output_tokens",
        config.reserve_output_tokens,
        label="output token reserve",
    )
    _require_env_or_set(values, "PUBLIC_MODEL_ID", config.public_model_id)
    _require_env_or_set(values, "MYCOMESH_RESERVE_INPUT_TOKENS", str(config.reserve_input_bytes))
    _require_env_or_set(values, "MYCOMESH_RESERVE_OUTPUT_TOKENS", str(config.reserve_output_tokens))
    configured_rpc = str(getattr(args, "settlement_rpc_url", None) or "").strip()
    if configured_rpc:
        configured_rpc_urls = tuple(
            _https_url(value, label="Provider settlement RPC URL", require_origin=False)
            for value in _comma_values(configured_rpc)
        )
        if not configured_rpc_urls or len(configured_rpc_urls) > MAX_RPC_ENDPOINTS:
            raise ProviderBootstrapError(
                f"Provider settlement RPC list must contain 1-{MAX_RPC_ENDPOINTS} URLs"
            )
        args.settlement_rpc_url = ",".join(configured_rpc_urls)
    else:
        args.settlement_rpc_url = config.settlement_rpc_url

    configured_pools = _comma_values(getattr(args, "pool", None))
    if configured_pools:
        normalized_pools = tuple(_canonical_bridge_url(value) for value in configured_pools)
        if normalized_pools != config.bridge_urls:
            raise ProviderBootstrapError(
                "Provider Bridge override does not match the published network config"
            )
    args.pool = ",".join(config.bridge_urls)

    configured_consumers = tuple(getattr(args, "consumer_public_key", None) or ())
    if configured_consumers:
        normalized_consumers = tuple(_consumer_public_key(value) for value in configured_consumers)
        if normalized_consumers != config.consumer_public_keys:
            raise ProviderBootstrapError(
                "Provider Consumer key override does not match the published network config"
            )
    args.consumer_public_key = list(config.consumer_public_keys)

    transport = str(getattr(args, "transport", None) or config.provider_transport)
    if transport not in {"direct", "relay"}:
        raise ProviderBootstrapError("Provider transport must be direct or relay")
    args.transport = transport
    _require_or_set(args, "relay_host", config.relay_host, label="relay host")
    _require_or_set(args, "relay_port", config.relay_port, label="relay provider port")
    _require_or_set(
        args,
        "relay_public_url",
        config.relay_public_url,
        label="relay public URL",
    )
    _require_or_set(
        args,
        "relay_provider_tls",
        config.relay_provider_tls,
        label="Relay Provider TLS",
    )

    identity = load_or_create_provider_evm_identity(evm_identity_path)
    configured_payment_address = str(getattr(args, "payment_address", None) or "").strip()
    if configured_payment_address:
        try:
            configured_payment_address = normalize_address(configured_payment_address)
        except ChainError as exc:
            raise ProviderBootstrapError(f"Provider payment address is invalid: {exc}") from exc
        if configured_payment_address != identity.address:
            raise ProviderBootstrapError(
                "Provider payment address does not match its local EVM signing identity"
            )
    args.payment_address = identity.address
    return config


def load_or_create_provider_evm_identity(path: str | Path) -> ProviderEvmIdentity:
    target = Path(path)
    if target.is_symlink():
        raise ProviderBootstrapError("Provider EVM identity must not be a symbolic link")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.parent.is_symlink():
        raise ProviderBootstrapError("Provider EVM identity directory must not be a symbolic link")
    try:
        target.parent.chmod(0o700)
    except OSError as exc:
        raise ProviderBootstrapError(f"could not secure Provider identity directory: {exc}") from exc

    if target.exists():
        identity = _load_provider_evm_identity(target)
        _secure_identity_file(target)
        return identity

    while True:
        private_key_bytes = os.urandom(32)
        private_key_int = int.from_bytes(private_key_bytes, "big")
        if 0 < private_key_int < SECP256K1_N:
            break
    private_key = "0x" + private_key_bytes.hex()
    identity = ProviderEvmIdentity(
        private_key=private_key,
        address=private_key_to_address(private_key_bytes),
    )
    payload = json.dumps(
        {
            "schema_version": 1,
            "address": identity.address,
            "private_key": identity.private_key,
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError:
        identity = _load_provider_evm_identity(target)
        _secure_identity_file(target)
        return identity
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    _secure_identity_file(target)
    return identity



def load_provider_evm_identity(path: str | Path) -> ProviderEvmIdentity:
    """Read an existing Provider signer without creating or mutating it."""
    target = Path(path)
    if not target.exists():
        raise ProviderBootstrapError("Provider EVM identity does not exist")
    if target.is_symlink():
        raise ProviderBootstrapError("Provider EVM identity must not be a symbolic link")
    try:
        mode = target.stat().st_mode
    except OSError as exc:
        raise ProviderBootstrapError(f"could not inspect Provider EVM identity: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise ProviderBootstrapError("Provider EVM identity must be a regular file")
    if stat.S_IMODE(mode) & 0o077:
        raise ProviderBootstrapError("Provider EVM identity permissions must be 0600 or stricter")
    return _load_provider_evm_identity(target)

def _load_provider_evm_identity(path: Path) -> ProviderEvmIdentity:
    payload = _read_json_object(path, label="Provider EVM identity")
    if payload.get("schema_version") != 1:
        raise ProviderBootstrapError("Provider EVM identity schema_version must be 1")
    private_key = str(payload.get("private_key") or "")
    try:
        private_key_bytes = parse_private_key(private_key)
        derived_address = private_key_to_address(private_key_bytes)
        stored_address = normalize_address(str(payload.get("address") or ""))
    except ChainError as exc:
        raise ProviderBootstrapError(f"Provider EVM identity is invalid: {exc}") from exc
    if stored_address != derived_address:
        raise ProviderBootstrapError(
            "Provider EVM identity address does not match its private key"
        )
    return ProviderEvmIdentity(private_key="0x" + private_key_bytes.hex(), address=derived_address)


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink():
        raise ProviderBootstrapError(f"{label} must not be a symbolic link")
    try:
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode):
            raise ProviderBootstrapError(f"{label} must be a regular file")
        with path.open("rb") as handle:
            raw = handle.read(MAX_PROVIDER_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ProviderBootstrapError(f"could not read {label}: {exc}") from exc
    if len(raw) > MAX_PROVIDER_CONFIG_BYTES:
        raise ProviderBootstrapError(f"{label} is too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderBootstrapError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ProviderBootstrapError(f"{label} must be a JSON object")
    return payload


def _secure_identity_file(path: Path) -> None:
    if path.is_symlink():
        raise ProviderBootstrapError("Provider EVM identity must not be a symbolic link")
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise ProviderBootstrapError("Provider EVM identity must be a regular file")
        path.chmod(0o600)
    except OSError as exc:
        raise ProviderBootstrapError(f"could not secure Provider EVM identity: {exc}") from exc


def _canonical_bridge_url(value: Any) -> str:
    raw = str(value or "")
    try:
        gateway_url = normalize_gateway_url(raw, allow_localhost=False)
    except GatewayRegistryError as exc:
        raise ProviderBootstrapError(f"Provider Bridge URL is invalid: {exc}") from exc
    canonical_origin = gateway_url[: -len("/v1")]
    if raw != canonical_origin:
        raise ProviderBootstrapError(
            "Provider Bridge URLs must be canonical HTTPS origins"
        )
    return canonical_origin


def _https_url(value: Any, *, label: str, require_origin: bool) -> str:
    raw = str(value or "")
    if raw != raw.strip() or not raw:
        raise ProviderBootstrapError(f"{label} must be non-empty without whitespace")
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ProviderBootstrapError(f"{label} must be an HTTPS URL without credentials")
    if require_origin and (parsed.path not in {"", "/"} or parsed.query):
        raise ProviderBootstrapError(f"{label} must be a canonical HTTPS origin")
    if require_origin and raw.endswith("/"):
        raise ProviderBootstrapError(f"{label} must not have a trailing slash")
    return raw


def _consumer_public_key(value: Any) -> str:
    public_key = str(value or "")
    if _PUBLIC_KEY_PATTERN.fullmatch(public_key) is None:
        raise ProviderBootstrapError(
            "Provider Consumer public keys must be lowercase 32-byte hex"
        )
    return public_key


def _bounded_manifest_int(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or value <= 0 or value > maximum:
        raise ProviderBootstrapError(f"Provider network {label} must be between 1 and {maximum}")
    return value


def _comma_values(value: Any) -> tuple[str, ...]:
    return tuple(item.strip() for item in str(value or "").split(",") if item.strip())


def _require_or_set(args: Any, attribute: str, expected: Any, *, label: str) -> None:
    current = getattr(args, attribute, None)
    if current is None or current == "":
        setattr(args, attribute, expected)
        return
    if current != expected:
        raise ProviderBootstrapError(
            f"Provider {label} override does not match the published network config"
        )


def _require_env_or_set(values: MutableMapping[str, str], name: str, expected: str) -> None:
    current = str(values.get(name) or "").strip()
    if current and current != expected:
        raise ProviderBootstrapError(
            f"{name} does not match the published Provider network config"
        )
    values[name] = expected


def require_provider_bridge_lease(
    network_config_path: str | Path,
    identity_path: str | Path,
    *,
    timeout: float = 5.0,
) -> None:
    config = load_provider_network_config(network_config_path)
    try:
        identity = load_identity(identity_path)
    except (IdentityError, OSError, ValueError) as exc:
        raise ProviderBootstrapError(f"Provider node identity is invalid: {exc}") from exc
    errors: list[str] = []
    for bridge_url in config.bridge_urls:
        try:
            peers = discover_peers(
                bridge_url,
                channel=config.deployment.channel,
                timeout=timeout,
            )
        except PoolError as exc:
            errors.append(f"{bridge_url}: {exc}")
            continue
        if any(str(peer.get("peer_id") or "") == identity.peer_id for peer in peers):
            return
    if errors:
        raise ProviderBootstrapError("Provider Bridge lease check failed: " + "; ".join(errors))
    raise ProviderBootstrapError("Provider has no live lease in the published Bridges")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect the local Provider payout identity.")
    parser.add_argument(
        "--identity",
        default=os.getenv("MYCOMESH_PROVIDER_EVM_IDENTITY", DEFAULT_PROVIDER_EVM_IDENTITY_PATH),
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--network-config",
        default=os.getenv("MYCOMESH_PROVIDER_NETWORK_CONFIG") or None,
    )
    parser.add_argument(
        "--node-identity",
        default=os.getenv("MYCOMESH_PROVIDER_IDENTITY", "/data/node-identity.json"),
    )
    parser.add_argument("--require-bridge-lease", action="store_true")
    args = parser.parse_args(argv)
    if args.require_bridge_lease:
        if not args.network_config:
            parser.error("--network-config is required for a Bridge lease check")
        try:
            require_provider_bridge_lease(
                args.network_config,
                args.node_identity,
            )
        except ProviderBootstrapError as exc:
            parser.error(str(exc))
        return 0
    try:
        identity = load_or_create_provider_evm_identity(args.identity)
    except ProviderBootstrapError as exc:
        parser.error(str(exc))
    payload = {"identity": str(args.identity), "address": identity.address}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"identity: {payload['identity']}")
        print(f"address: {payload['address']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
