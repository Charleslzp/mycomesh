from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .chain import (
    ZERO_ADDRESS,
    ChainError,
    call_contract,
    channel_to_hash,
    normalize_address,
    normalize_bytes32,
    rpc_call,
    rpc_int,
)
from .chain_v3 import V3Deployment, domain_separator as v3_domain_separator
from .channel_policy import require_deployment_channel_binding


_HEX_DATA_PATTERN = re.compile(r"^0x[0-9a-fA-F]*$")


@dataclass(frozen=True)
class V3DeploymentPreflight:
    chain_id: int
    block_tag: str
    code_sizes: dict[str, int]
    deployer_test_usdc: str
    deployer_settlement: str
    deployer_token: str
    stablecoin: str
    token: str
    treasury: str
    governance: str
    max_consumer_rebate_bps: int
    latest_channel_version: int
    pricing_hash: str
    domain_separator: str
    quote: int
    rewards_enabled: bool
    mint_authority: str
    max_supply: int
    stablecoin_decimals: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_v3_manifest(deployment: V3Deployment) -> V3Deployment:
    if type(deployment.protocol_version) is not int or deployment.protocol_version != 3:
        raise ChainError("deployment is not a Myco Settlement V3 deployment")
    if type(deployment.chain_id) is not int or deployment.chain_id <= 0:
        raise ChainError("V3 deployment chain_id must be positive")
    if type(deployment.pricing_version) is not int or not 0 < deployment.pricing_version < (1 << 64):
        raise ChainError("V3 deployment pricing_version must be a positive uint64")
    if (
        type(deployment.max_consumer_rebate_bps) is not int
        or deployment.max_consumer_rebate_bps < 0
        or deployment.max_consumer_rebate_bps > 10_000
    ):
        raise ChainError("V3 deployment max_consumer_rebate_bps must be between 0 and 10000")
    if type(deployment.max_supply) is not int or deployment.max_supply <= 0:
        raise ChainError("V3 deployment max_supply must be positive")
    if not isinstance(deployment.channel, str) or not deployment.channel.strip():
        raise ChainError("V3 deployment channel must not be empty")
    try:
        require_deployment_channel_binding(deployment)
    except ValueError as exc:
        raise ChainError(str(exc)) from exc

    addresses = {
        "deployer": deployment.deployer,
        "test_usdc": deployment.test_usdc,
        "stablecoin": deployment.stablecoin,
        "settlement": deployment.settlement,
        "token": deployment.token,
        "treasury": deployment.treasury,
        "governance": deployment.governance,
    }
    normalized_addresses: dict[str, str] = {}
    for label, value in addresses.items():
        normalized = normalize_address(value)
        if normalized == ZERO_ADDRESS:
            raise ChainError(f"V3 deployment {label} must be non-zero")
        normalized_addresses[label] = normalized

    if normalized_addresses["test_usdc"] != normalized_addresses["stablecoin"]:
        raise ChainError("V3 deployment test_usdc must match stablecoin")
    if len(
        {
            normalized_addresses["stablecoin"],
            normalized_addresses["settlement"],
            normalized_addresses["token"],
        }
    ) != 3:
        raise ChainError("V3 deployment stablecoin, settlement, and token must be distinct")
    expected_channel_hash = normalize_bytes32(channel_to_hash(deployment.channel))
    if normalize_bytes32(deployment.channel_hash) != expected_channel_hash:
        raise ChainError("V3 deployment channel_hash does not match channel")
    if normalize_bytes32(deployment.pricing_hash) == "0x" + "0" * 64:
        raise ChainError("V3 deployment pricing_hash must be non-zero")
    if deployment.eip712_name != "MycoMesh Settlement" or deployment.eip712_version != "3":
        raise ChainError("V3 deployment EIP-712 domain does not match Settlement V3")
    return deployment


def validate_v3_environment(
    deployment: V3Deployment,
    env: Mapping[str, str] | None = None,
) -> V3Deployment:
    validate_v3_manifest(deployment)
    values: Mapping[str, str] = os.environ if env is None else env

    _match_int(values, "MYCOMESH_SETTLEMENT_VERSION", 3)
    _match_int(values, "ETH_CHAIN_ID", deployment.chain_id)
    _match_int(values, "MYCOMESH_SETTLEMENT_CHAIN_ID", deployment.chain_id)
    _match_int(values, "MYCOMESH_PRICING_VERSION", deployment.pricing_version)
    if str(values.get("MYCOMESH_NETWORK_PROFILE") or "").strip().lower() != "local":
        _match_text(values, "MYCOMESH_NETWORK_ID", deployment.network_id)
        _match_text(values, "MYCOMESH_CHANNEL_ID", deployment.channel_id)
        _match_text(values, "MYCOMESH_CHANNEL", deployment.channel)
        _match_text(values, "MYCOMESH_BACKEND_POLICY", deployment.backend_policy)

    for name, expected in (
        ("MYCO_DEPLOYER", deployment.deployer),
        ("MYCO_TEST_USDC", deployment.test_usdc),
        ("MYCO_STABLECOIN", deployment.stablecoin),
        ("MYCO_SETTLEMENT", deployment.settlement),
        ("MYCOMESH_SETTLEMENT_CONTRACT", deployment.settlement),
        ("MYCO_TOKEN", deployment.token),
        ("MYCO_TREASURY", deployment.treasury),
        ("TREASURY", deployment.treasury),
        ("MYCOMESH_GOVERNANCE", deployment.governance),
        ("GOVERNANCE", deployment.governance),
    ):
        _match_address(values, name, expected)

    for name, expected in (
        ("MYCO_CHANNEL_HASH", deployment.channel_hash),
        ("MYCOMESH_CHANNEL_PRICING_HASH", deployment.pricing_hash),
        ("MYCOMESH_PROVIDER_PRICING_HASH", deployment.pricing_hash),
        ("MYCO_PRICING_HASH", deployment.pricing_hash),
    ):
        _match_bytes32(values, name, expected)
    return deployment


def verify_v3_deployment_preflight(
    *,
    rpc_url: str,
    deployment: V3Deployment,
    env: Mapping[str, str] | None = None,
    timeout: float = 20.0,
    block_tag: str | int = "latest",
    quote_input_tokens: int = 1_000,
    quote_output_tokens: int = 500,
    expected_quote: int | None = None,
) -> V3DeploymentPreflight:
    validate_v3_environment(deployment, env)
    if not str(rpc_url or "").strip():
        raise ChainError("V3 deployment preflight requires an RPC URL")
    if type(quote_input_tokens) is not int or quote_input_tokens < 0:
        raise ChainError("V3 deployment preflight quote_input_tokens must be non-negative")
    if type(quote_output_tokens) is not int or quote_output_tokens < 0:
        raise ChainError("V3 deployment preflight quote_output_tokens must be non-negative")

    chain_id = rpc_int(rpc_url, "eth_chainId", [], timeout)
    if chain_id != deployment.chain_id:
        raise ChainError(
            f"V3 deployment RPC chain id mismatch: expected {deployment.chain_id}, got {chain_id}"
        )

    resolved_block_tag = _block_tag(block_tag)
    code_sizes: dict[str, int] = {}
    code_cache: dict[str, int] = {}
    for label, address in (
        ("deployer", deployment.deployer),
        ("test_usdc", deployment.test_usdc),
        ("stablecoin", deployment.stablecoin),
        ("settlement", deployment.settlement),
        ("token", deployment.token),
    ):
        normalized = normalize_address(address)
        size = code_cache.get(normalized)
        if size is None:
            size = _contract_code_size(
                rpc_call(rpc_url, "eth_getCode", [normalized, resolved_block_tag], timeout),
                label,
            )
            code_cache[normalized] = size
        code_sizes[label] = size

    deployer_test_usdc = _call_address(
        rpc_url, deployment.deployer, "testUSDC()", [], timeout, resolved_block_tag
    )
    deployer_settlement = _call_address(
        rpc_url, deployment.deployer, "settlement()", [], timeout, resolved_block_tag
    )
    deployer_token = _call_address(
        rpc_url, deployment.deployer, "token()", [], timeout, resolved_block_tag
    )
    stablecoin = _call_address(rpc_url, deployment.settlement, "stablecoin()", [], timeout, resolved_block_tag)
    token = _call_address(rpc_url, deployment.settlement, "rewardToken()", [], timeout, resolved_block_tag)
    treasury = _call_address(rpc_url, deployment.settlement, "treasury()", [], timeout, resolved_block_tag)
    governance = _call_address(rpc_url, deployment.settlement, "governance()", [], timeout, resolved_block_tag)
    max_consumer_rebate_bps = _call_uint(
        rpc_url, deployment.settlement, "maxConsumerRebateBps()", [], timeout, resolved_block_tag
    )
    latest_channel_version = _call_uint(
        rpc_url,
        deployment.settlement,
        "latestChannelVersion(bytes32)",
        [deployment.channel_hash],
        timeout,
        resolved_block_tag,
    )
    pricing_hash = _call_bytes32(
        rpc_url,
        deployment.settlement,
        "channelPricingHash(bytes32,uint64)",
        [deployment.channel_hash, str(deployment.pricing_version)],
        timeout,
        resolved_block_tag,
    )
    onchain_domain_separator = _call_bytes32(
        rpc_url, deployment.settlement, "DOMAIN_SEPARATOR()", [], timeout, resolved_block_tag
    )
    expected_domain_separator = v3_domain_separator(
        chain_id=chain_id, verifying_contract=deployment.settlement
    )
    quote = _call_uint(
        rpc_url,
        deployment.settlement,
        "quote(bytes32,uint64,uint256,uint256)",
        [
            deployment.channel_hash,
            str(deployment.pricing_version),
            str(quote_input_tokens),
            str(quote_output_tokens),
        ],
        timeout,
        resolved_block_tag,
    )
    rewards_enabled = _call_bool(
        rpc_url, deployment.settlement, "rewardsEnabled()", [], timeout, resolved_block_tag
    )
    mint_authority = _call_address(rpc_url, deployment.token, "mintAuthority()", [], timeout, resolved_block_tag)
    max_supply = _call_uint(rpc_url, deployment.token, "maxSupply()", [], timeout, resolved_block_tag)
    stablecoin_decimals = _call_uint(rpc_url, deployment.stablecoin, "decimals()", [], timeout, resolved_block_tag)

    _require_equal("Deployer test USDC", deployer_test_usdc, deployment.test_usdc)
    _require_equal("Deployer settlement", deployer_settlement, deployment.settlement)
    _require_equal("Deployer token", deployer_token, deployment.token)
    _require_equal("Settlement stablecoin", stablecoin, deployment.stablecoin)
    _require_equal("Settlement reward token", token, deployment.token)
    _require_equal("Settlement treasury", treasury, deployment.treasury)
    _require_equal("Settlement governance", governance, deployment.governance)
    _require_equal(
        "Settlement max consumer rebate bps",
        max_consumer_rebate_bps,
        deployment.max_consumer_rebate_bps,
    )
    _require_equal("Settlement latest channel version", latest_channel_version, deployment.pricing_version)
    _require_equal("Settlement channel pricing hash", pricing_hash, deployment.pricing_hash)
    _require_equal("Reward token mint authority", mint_authority, deployment.settlement)
    _require_equal(
        "Settlement EIP-712 domain separator",
        onchain_domain_separator,
        expected_domain_separator,
    )
    _require_equal("Reward token max supply", max_supply, deployment.max_supply)
    if quote <= 0:
        raise ChainError("Settlement V3 quote must be positive")
    if expected_quote is not None:
        _require_equal("Settlement quote", quote, int(expected_quote))
    _require_equal("Settlement stablecoin decimals", stablecoin_decimals, 6)

    return V3DeploymentPreflight(
        chain_id=chain_id,
        block_tag=resolved_block_tag,
        code_sizes=code_sizes,
        deployer_test_usdc=deployer_test_usdc,
        deployer_settlement=deployer_settlement,
        deployer_token=deployer_token,
        stablecoin=stablecoin,
        token=token,
        treasury=treasury,
        governance=governance,
        max_consumer_rebate_bps=max_consumer_rebate_bps,
        latest_channel_version=latest_channel_version,
        pricing_hash=pricing_hash,
        quote=quote,
        domain_separator=onchain_domain_separator,
        rewards_enabled=rewards_enabled,
        mint_authority=mint_authority,
        max_supply=max_supply,
        stablecoin_decimals=stablecoin_decimals,
    )


def _match_int(values: Mapping[str, str], name: str, expected: int) -> None:
    raw = str(values.get(name) or "").strip()
    if not raw:
        return
    try:
        actual = int(raw)
    except ValueError as exc:
        raise ChainError(f"{name} must be an integer") from exc
    if actual != expected:
        raise ChainError(f"{name} does not match V3 deployment: expected {expected}, got {actual}")


def _match_text(values: Mapping[str, str], name: str, expected: str) -> None:
    raw = str(values.get(name) or "")
    if not raw:
        return
    if raw != expected:
        raise ChainError(f"{name} does not match V3 deployment: expected {expected}, got {raw}")


def _match_address(values: Mapping[str, str], name: str, expected: str) -> None:
    raw = str(values.get(name) or "").strip()
    if not raw:
        return
    try:
        actual = normalize_address(raw)
    except ChainError as exc:
        raise ChainError(f"{name} is not a valid EVM address") from exc
    normalized_expected = normalize_address(expected)
    if actual != normalized_expected:
        raise ChainError(f"{name} does not match V3 deployment")


def _match_bytes32(values: Mapping[str, str], name: str, expected: str) -> None:
    raw = str(values.get(name) or "").strip()
    if not raw:
        return
    try:
        actual = normalize_bytes32(raw)
    except ChainError as exc:
        raise ChainError(f"{name} is not a valid bytes32 value") from exc
    if actual != normalize_bytes32(expected):
        raise ChainError(f"{name} does not match V3 deployment")


def _block_tag(value: str | int) -> str:
    if isinstance(value, bool):
        raise ChainError("V3 deployment preflight block_tag must be a block number or RPC tag")
    if isinstance(value, int):
        if value < 0:
            raise ChainError("V3 deployment preflight block number must be non-negative")
        return hex(value)
    resolved = str(value or "").strip()
    if not resolved:
        raise ChainError("V3 deployment preflight block_tag must not be empty")
    return resolved


def _contract_code_size(value: Any, label: str) -> int:
    if not isinstance(value, str) or _HEX_DATA_PATTERN.fullmatch(value) is None or len(value[2:]) % 2:
        raise ChainError(f"V3 deployment {label} eth_getCode returned malformed hex data")
    raw = bytes.fromhex(value[2:])
    if not raw or not any(raw):
        raise ChainError(f"V3 deployment {label} has no contract code")
    return len(raw)


def _call_address(
    rpc_url: str,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float,
    block_tag: str | int,
) -> str:
    word = _call_word(rpc_url, contract, signature, args, timeout, block_tag)
    if word[:24] != "0" * 24:
        raise ChainError(f"{signature} returned a malformed address")
    return normalize_address("0x" + word[-40:])


def _call_uint(
    rpc_url: str,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float,
    block_tag: str | int,
) -> int:
    return int(_call_word(rpc_url, contract, signature, args, timeout, block_tag), 16)


def _call_bool(
    rpc_url: str,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float,
    block_tag: str | int,
) -> bool:
    value = _call_uint(rpc_url, contract, signature, args, timeout, block_tag)
    if value not in {0, 1}:
        raise ChainError(f"{signature} returned a malformed boolean")
    return bool(value)


def _call_bytes32(
    rpc_url: str,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float,
    block_tag: str | int,
) -> str:
    return normalize_bytes32("0x" + _call_word(rpc_url, contract, signature, args, timeout, block_tag))


def _call_word(
    rpc_url: str,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float,
    block_tag: str | int,
) -> str:
    output = call_contract(
        rpc_url=rpc_url,
        contract=contract,
        signature=signature,
        args=args,
        timeout=timeout,
        block_tag=block_tag,
    )
    if not isinstance(output, str) or re.fullmatch(r"0x[0-9a-fA-F]{64}", output) is None:
        raise ChainError(f"{signature} returned malformed ABI data")
    return output[2:].lower()


def _require_equal(label: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        raise ChainError(f"{label} mismatch: expected {expected}, got {actual}")
