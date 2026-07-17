from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .ledger import DEFAULT_LEDGER_PATH, receipt_hash as ledger_receipt_hash
from .netio import NetworkIOError, bounded_timeout, read_bounded, text_preview
from .pricing import DEFAULT_CHANNEL, usage_tokens
from .protocol import ProtocolValidationError, validate_settlement_receipt


SEPOLIA_CHAIN_ID = 11155111
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
DEFAULT_DEPLOYMENT_PATH = "deployments/sepolia.json"
DEFAULT_MYCO_DEPLOYMENT_PATH = "deployments/sepolia-myco-v2.json"
DEFAULT_CHANNEL_HASH = "0xdedf8b58276b80863f354409c963cbaddf4ca7d5b866d528ff1386d74b339104"
ZERO_BYTES32 = "0x0000000000000000000000000000000000000000000000000000000000000000"
MYCO_RECEIPT_TYPE = (
    "Receipt(bytes32 receiptHash,bytes32 acceptedHash,bytes32 channel,address consumer,address provider,address relay,address pool,"
    "uint256 inputTokens,uint256 outputTokens,bytes32 pricingHash,uint256 deadline)"
)
MYCO_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
LEGACY_DEPLOYER_CONTRACT = "contracts/FandaiTestnetDeployer.sol:FandaiTestnetDeployer"
LEGACY_DEPLOYER_ARTIFACT = "out/FandaiTestnetDeployer.sol/FandaiTestnetDeployer.json"
MYCO_DEPLOYER_ARTIFACT = "out/MycoTestnetDeployer.sol/MycoTestnetDeployer.json"
USDC_DECIMALS = 6
MYCO_DECIMALS = 18
MAX_RPC_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_RPC_LOG_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RPC_TIMEOUT_SECONDS = 300.0
MAX_RPC_ENDPOINTS = 4
RPC_ENDPOINT_COOLDOWN_SECONDS = 60.0
ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
BYTES32_PATTERN = re.compile(r"^0x[a-fA-F0-9]{64}$")
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


class ChainError(RuntimeError):
    pass


class _RetryableRPCError(ChainError):
    pass


_RPC_ENDPOINT_COOLDOWNS: dict[str, float] = {}
_RPC_ENDPOINT_LOCK = threading.Lock()


@dataclass(frozen=True)
class ChainDeployment:
    chain_id: int
    deployer: str
    test_usdc: str
    token: str
    settlement: str
    treasury: str
    channel: str
    channel_hash: str
    tx_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MycoDeployment:
    chain_id: int
    deployer: str
    test_usdc: str
    token: str
    settlement: str
    treasury: str
    channel: str
    channel_hash: str
    tx_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReceiptSettlementArgs:
    receipt_hash: str
    accepted_hash: str
    channel_hash: str
    consumer: str
    provider: str
    relay: str
    pool: str
    input_tokens: int
    output_tokens: int
    pricing_hash: str = "0x0000000000000000000000000000000000000000000000000000000000000000"
    deadline: int = 0
    gross_fee_units: int = 0

    def legacy_abi_args(self) -> list[str]:
        return [
            self.receipt_hash,
            self.channel_hash,
            self.consumer,
            self.provider,
            self.relay,
            self.pool,
            str(self.input_tokens),
            str(self.output_tokens),
        ]

    def abi_args(self) -> list[str]:
        return [
            self.receipt_hash,
            self.accepted_hash,
            self.channel_hash,
            self.consumer,
            self.provider,
            self.relay,
            self.pool,
            str(self.input_tokens),
            str(self.output_tokens),
            self.pricing_hash,
            str(self.deadline),
        ]


@dataclass(frozen=True)
class EvmSignature:
    r: str
    s: str
    v: int

    def abi_args(self) -> list[str]:
        return [self.r, self.s, str(self.v)]


@dataclass(frozen=True)
class SignedReceiptSettlementArgs:
    receipt: ReceiptSettlementArgs
    consumer_signature: EvmSignature
    provider_signature: EvmSignature
    operator_signature: EvmSignature | None = None

    def abi_args(self) -> list[str]:
        operator = self.operator_signature or EvmSignature(
            r="0x" + "0" * 64,
            s="0x" + "0" * 64,
            v=0,
        )
        return [
            *self.receipt.abi_args(),
            *self.consumer_signature.abi_args(),
            *self.provider_signature.abi_args(),
            *operator.abi_args(),
            "1" if self.operator_signature else "0",
        ]


@dataclass(frozen=True)
class DelegatedReceiptSettlementArgs:
    receipt: ReceiptSettlementArgs
    consumer_delegate_signature: EvmSignature
    provider_delegate_signature: EvmSignature
    max_amount: int
    expires_at: int
    consumer_nonce: int
    provider_nonce: int
    operator_signature: EvmSignature | None = None

    def abi_args(self) -> list[str]:
        empty_signature = EvmSignature(
            r="0x" + "0" * 64,
            s="0x" + "0" * 64,
            v=0,
        )
        operator = self.operator_signature or empty_signature
        return [
            *self.receipt.abi_args(),
            *empty_signature.abi_args(),
            *empty_signature.abi_args(),
            *operator.abi_args(),
            "1" if self.operator_signature else "0",
            *self.consumer_delegate_signature.abi_args(),
            *self.provider_delegate_signature.abi_args(),
            str(self.max_amount),
            str(self.expires_at),
            str(self.consumer_nonce),
            str(self.provider_nonce),
        ]


@dataclass(frozen=True)
class DelegateAuthorization:
    account: str
    delegate: str
    receipt: ReceiptSettlementArgs
    max_amount: int
    expires_at: int
    nonce: int
    signature: EvmSignature

    def abi_args(self) -> list[str]:
        return [
            self.account,
            self.delegate,
            *self.receipt.abi_args(),
            str(self.max_amount),
            str(self.expires_at),
            str(self.nonce),
            *self.signature.abi_args(),
        ]


def deploy_testnet(
    rpc_url: str,
    private_key: str,
    treasury: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    solc: str | None = None,
    artifact: str = LEGACY_DEPLOYER_ARTIFACT,
    timeout: float = 300.0,
) -> ChainDeployment:
    treasury = normalize_address(treasury)
    if solc or not Path(artifact).exists():
        build_command = ["forge", "build"]
        if solc:
            build_command.extend(["--use", solc, "--offline"])
        run_tool(build_command, timeout=timeout)

    bytecode = load_artifact_bytecode(Path(artifact))
    constructor_args = abi_encode_arg(treasury)
    deployer, tx_hash = deploy_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        bytecode=bytecode + constructor_args,
        timeout=timeout,
    )
    addresses = derive_testnet_addresses(deployer)
    return ChainDeployment(
        chain_id=chain_id,
        deployer=deployer,
        test_usdc=addresses["test_usdc"],
        token=addresses["token"],
        settlement=addresses["settlement"],
        treasury=treasury,
        channel=DEFAULT_CHANNEL,
        channel_hash=DEFAULT_CHANNEL_HASH,
        tx_hash=tx_hash,
    )


def deploy_myco_testnet(
    rpc_url: str,
    private_key: str,
    treasury: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    solc: str | None = None,
    artifact: str = MYCO_DEPLOYER_ARTIFACT,
    timeout: float = 300.0,
) -> MycoDeployment:
    treasury = normalize_address(treasury)
    if solc or not Path(artifact).exists():
        build_command = ["forge", "build"]
        if solc:
            build_command.extend(["--use", solc, "--offline"])
        run_tool(build_command, timeout=timeout)

    bytecode = load_artifact_bytecode(Path(artifact))
    constructor_args = abi_encode_arg(treasury)
    deployer, tx_hash = deploy_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        bytecode=bytecode + constructor_args,
        timeout=timeout,
    )
    addresses = derive_testnet_addresses(deployer)
    return MycoDeployment(
        chain_id=chain_id,
        deployer=deployer,
        test_usdc=addresses["test_usdc"],
        token=addresses["token"],
        settlement=addresses["settlement"],
        treasury=treasury,
        channel=DEFAULT_CHANNEL,
        channel_hash=DEFAULT_CHANNEL_HASH,
        tx_hash=tx_hash,
    )


def load_artifact_bytecode(path: Path) -> bytes:
    if not path.exists():
        raise ChainError(f"artifact not found: {path}; run forge build first")
    payload = json.loads(path.read_text(encoding="utf-8"))
    bytecode = payload.get("bytecode", {})
    if isinstance(bytecode, dict):
        bytecode = bytecode.get("object")
    if not isinstance(bytecode, str) or not bytecode.startswith("0x"):
        raise ChainError(f"artifact does not contain bytecode: {path}")
    return bytes.fromhex(bytecode[2:])


def deploy_contract_transaction(
    rpc_url: str,
    private_key: str,
    chain_id: int,
    bytecode: bytes,
    timeout: float,
) -> tuple[str, str]:
    private_key_bytes = parse_private_key(private_key)
    from_address = private_key_to_address(private_key_bytes)
    nonce = rpc_int(rpc_url, "eth_getTransactionCount", [from_address, "pending"], timeout)
    gas_price = rpc_int(rpc_url, "eth_gasPrice", [], timeout)
    gas_limit = estimate_gas(
        rpc_url=rpc_url,
        from_address=from_address,
        to_address=None,
        data="0x" + bytecode.hex(),
        timeout=timeout,
    )
    raw_tx = sign_legacy_transaction(
        private_key=private_key_bytes,
        nonce=nonce,
        gas_price=gas_price,
        gas_limit=gas_limit,
        to_address=None,
        value=0,
        data=bytecode,
        chain_id=chain_id,
    )
    result = rpc_call(rpc_url, "eth_sendRawTransaction", ["0x" + raw_tx.hex()], timeout)
    if not isinstance(result, str):
        raise ChainError(f"unexpected eth_sendRawTransaction response: {result!r}")
    return derive_contract_address(from_address, nonce), normalize_bytes32(result)


def mint_test_usdc(
    rpc_url: str,
    private_key: str,
    token_address: str,
    to_address: str,
    amount_usdc: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    amount = stablecoin_amount(amount_usdc)
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(token_address),
        signature="mint(address,uint256)",
        args=[normalize_address(to_address), str(amount)],
        timeout=timeout,
    )


def approve_usdc(
    rpc_url: str,
    private_key: str,
    token_address: str,
    spender: str,
    amount_usdc: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    amount = stablecoin_amount(amount_usdc)
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(token_address),
        signature="approve(address,uint256)",
        args=[normalize_address(spender), str(amount)],
        timeout=timeout,
    )


def deposit_prepaid(
    rpc_url: str,
    private_key: str,
    settlement: str,
    amount_usdc: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    amount = stablecoin_amount(amount_usdc)
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="deposit(uint256)",
        args=[str(amount)],
        timeout=timeout,
    )


def withdraw_prepaid(
    rpc_url: str,
    private_key: str,
    settlement: str,
    amount_usdc: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    amount = stablecoin_amount(amount_usdc)
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="withdraw(uint256)",
        args=[str(amount)],
        timeout=timeout,
    )


def prepaid_balance(
    rpc_url: str,
    settlement: str,
    account: str,
    timeout: float = 20.0,
    block_tag: str | int = "latest",
) -> int:
    return call_uint256(
        rpc_url=rpc_url,
        contract=normalize_address(settlement),
        signature="prepaidBalance(address)",
        args=[normalize_address(account)],
        timeout=timeout,
        block_tag=block_tag,
    )


def set_settlement_delegate(
    rpc_url: str,
    private_key: str,
    settlement: str,
    delegate: str,
    allowed: bool,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setSettlementDelegate(address,bool)",
        args=[normalize_address(delegate), "true" if allowed else "false"],
        timeout=timeout,
    )


def set_treasury(
    rpc_url: str,
    private_key: str,
    settlement: str,
    treasury: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setTreasury(address)",
        args=[normalize_address(treasury)],
        timeout=timeout,
    )


def set_operator(
    rpc_url: str,
    private_key: str,
    settlement: str,
    operator: str,
    allowed: bool,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setOperator(address,bool)",
        args=[normalize_address(operator), "true" if allowed else "false"],
        timeout=timeout,
    )


def set_governance_executor(
    rpc_url: str,
    private_key: str,
    settlement: str,
    next_executor: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setGovernanceExecutor(address)",
        args=[normalize_address(next_executor)],
        timeout=timeout,
    )


def accept_governance_executor(
    rpc_url: str,
    private_key: str,
    settlement: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="acceptOwnership()",
        args=[],
        timeout=timeout,
    )


def set_governance_delay(
    rpc_url: str,
    private_key: str,
    settlement: str,
    delay_seconds: int,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setGovernanceDelay(uint256)",
        args=[str(max(0, int(delay_seconds)))],
        timeout=timeout,
    )


def schedule_governance_action(
    rpc_url: str,
    private_key: str,
    settlement: str,
    action_hash: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="scheduleGovernanceAction(bytes32)",
        args=[normalize_bytes32(action_hash)],
        timeout=timeout,
    )


def set_economics(
    rpc_url: str,
    private_key: str,
    settlement: str,
    epoch_seconds: int,
    epoch_emission_myco: str,
    halving_interval_epochs: int,
    max_consumer_rebate_bps: int,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setEconomics((uint256,uint256,uint256,uint16))",
        args=[
            str(epoch_seconds),
            str(reward_token_amount(epoch_emission_myco)),
            str(halving_interval_epochs),
            str(max_consumer_rebate_bps),
        ],
        timeout=timeout,
    )


def set_channel(
    rpc_url: str,
    private_key: str,
    settlement: str,
    channel_hash: str,
    input_per_1k_usdc: str,
    output_per_1k_usdc: str,
    minimum_fee_usdc: str,
    provider_bps: int,
    relay_bps: int,
    pool_bps: int,
    treasury_bps: int,
    provider_reward_bps: int,
    consumer_reward_bps: int,
    reward_per_treasury_unit: int,
    active: bool,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setChannel(bytes32,(uint256,uint256,uint256,uint16,uint16,uint16,uint16,uint16,uint16,uint256,bool))",
        args=[
            normalize_bytes32(channel_hash),
            str(stablecoin_amount(input_per_1k_usdc)),
            str(stablecoin_amount(output_per_1k_usdc)),
            str(stablecoin_amount(minimum_fee_usdc)),
            str(provider_bps),
            str(relay_bps),
            str(pool_bps),
            str(treasury_bps),
            str(provider_reward_bps),
            str(consumer_reward_bps),
            str(reward_per_treasury_unit),
            "true" if active else "false",
        ],
        timeout=timeout,
    )


def set_trusted_settlement_enabled(
    rpc_url: str,
    private_key: str,
    settlement: str,
    enabled: bool,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="setTrustedSettlementEnabled(bool)",
        args=["true" if enabled else "false"],
        timeout=timeout,
    )


def treasury_buyback_burn(
    rpc_url: str,
    private_key: str,
    settlement: str,
    amount_myco: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="treasuryBuybackBurn(uint256)",
        args=[str(reward_token_amount(amount_myco))],
        timeout=timeout,
    )


def settle_receipt(
    rpc_url: str,
    private_key: str,
    settlement: str,
    settlement_args: ReceiptSettlementArgs,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="settleReceipt(bytes32,bytes32,address,address,address,address,uint256,uint256)",
        args=settlement_args.legacy_abi_args(),
        timeout=timeout,
    )


def settle_prepaid_receipt(
    rpc_url: str,
    private_key: str,
    settlement: str,
    settlement_args: ReceiptSettlementArgs,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    raise ChainError(
        "settle_prepaid_receipt was removed because it hid the trusted settlement path; "
        "use settle_signed_prepaid_receipt for production or settle_trusted_prepaid_receipt for explicit demo mode"
    )


def settle_trusted_prepaid_receipt(
    rpc_url: str,
    private_key: str,
    settlement: str,
    settlement_args: ReceiptSettlementArgs,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_data_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        data=encode_contract_call(
            "settleTrustedReceiptFromBalance((bytes32,bytes32,bytes32,address,address,address,address,uint256,uint256,bytes32,uint256))",
            settlement_args.abi_args(),
        ),
        timeout=timeout,
    )


def settle_signed_prepaid_receipt(
    rpc_url: str,
    private_key: str,
    settlement: str,
    settlement_args: SignedReceiptSettlementArgs,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_data_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        data=encode_settle_signed_receipt_call(settlement_args),
        timeout=timeout,
    )


def settle_delegated_prepaid_receipt(
    rpc_url: str,
    private_key: str,
    settlement: str,
    settlement_args: DelegatedReceiptSettlementArgs,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_data_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        data=encode_settle_delegated_receipt_call(settlement_args),
        timeout=timeout,
    )


def send_contract_transaction(
    rpc_url: str,
    private_key: str,
    chain_id: int,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float,
) -> str:
    data = encode_contract_call(signature, args)
    return send_contract_data_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=contract,
        data=data,
        timeout=timeout,
    )


def send_contract_data_transaction(
    rpc_url: str,
    private_key: str,
    chain_id: int,
    contract: str,
    data: str,
    timeout: float,
) -> str:
    private_key_bytes = parse_private_key(private_key)
    from_address = private_key_to_address(private_key_bytes)
    nonce = rpc_int(rpc_url, "eth_getTransactionCount", [from_address, "pending"], timeout)
    gas_price = rpc_int(rpc_url, "eth_gasPrice", [], timeout)
    gas_limit = estimate_gas(
        rpc_url=rpc_url,
        from_address=from_address,
        to_address=contract,
        data=data,
        timeout=timeout,
    )
    raw_tx = sign_legacy_transaction(
        private_key=private_key_bytes,
        nonce=nonce,
        gas_price=gas_price,
        gas_limit=gas_limit,
        to_address=contract,
        value=0,
        data=bytes.fromhex(data[2:]),
        chain_id=chain_id,
    )
    result = rpc_call(rpc_url, "eth_sendRawTransaction", ["0x" + raw_tx.hex()], timeout)
    if not isinstance(result, str):
        raise ChainError(f"unexpected eth_sendRawTransaction response: {result!r}")
    return normalize_bytes32(result)


def call_contract(
    rpc_url: str,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float = 20.0,
    block_tag: str | int = "latest",
) -> str:
    resolved_block_tag = hex(max(0, block_tag)) if isinstance(block_tag, int) else str(block_tag)
    result = rpc_call(
        rpc_url,
        "eth_call",
        [
            {
                "to": normalize_address(contract),
                "data": encode_contract_call(signature, args),
            },
            resolved_block_tag,
        ],
        timeout,
    )
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ChainError(f"unexpected eth_call response: {result!r}")
    return result


def call_uint256(
    rpc_url: str,
    contract: str,
    signature: str,
    args: list[str],
    timeout: float = 20.0,
    block_tag: str | int = "latest",
) -> int:
    output = call_contract(rpc_url, contract, signature, args, timeout=timeout, block_tag=block_tag)
    if len(output) < 66:
        raise ChainError(f"eth_call returned too little data: {output}")
    return int(output[-64:], 16)


def estimate_gas(
    rpc_url: str,
    from_address: str,
    to_address: str | None,
    data: str,
    timeout: float,
) -> int:
    tx = {
        "from": normalize_address(from_address),
        "data": data,
        "value": "0x0",
    }
    if to_address is not None:
        tx["to"] = normalize_address(to_address)
    params = [tx]
    gas = rpc_int(rpc_url, "eth_estimateGas", params, timeout)
    return max(21_000, int(gas * 12 // 10) + 10_000)


def rpc_int(rpc_url: str, method: str, params: list[Any], timeout: float) -> int:
    result = rpc_call(rpc_url, method, params, timeout)
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ChainError(f"unexpected {method} response: {result!r}")
    return int(result, 16)


def rpc_call(rpc_url: str, method: str, params: list[Any], timeout: float) -> Any:
    try:
        resolved_timeout = bounded_timeout(timeout, maximum=MAX_RPC_TIMEOUT_SECONDS, label="RPC timeout")
    except NetworkIOError as exc:
        raise ChainError(str(exc)) from exc
    endpoints = _rpc_endpoints(rpc_url)
    deadline = time.monotonic() + resolved_timeout
    last_error: _RetryableRPCError | None = None
    for endpoint in _available_rpc_endpoints(endpoints):
        try:
            result = _rpc_call_once(
                endpoint,
                method=method,
                params=params,
                deadline=deadline,
            )
        except _RetryableRPCError as exc:
            last_error = exc
            _cooldown_rpc_endpoint(endpoint)
            continue
        with _RPC_ENDPOINT_LOCK:
            _RPC_ENDPOINT_COOLDOWNS.pop(endpoint, None)
        return result
    if last_error is not None:
        raise ChainError(str(last_error)) from last_error
    raise ChainError(f"RPC request failed for {method}: no endpoint was available")


def _rpc_endpoints(value: str) -> tuple[str, ...]:
    endpoints = tuple(dict.fromkeys(part.strip() for part in str(value or "").split(",") if part.strip()))
    if not endpoints:
        raise ChainError("RPC URL must not be empty")
    if len(endpoints) > MAX_RPC_ENDPOINTS:
        raise ChainError(f"RPC URL list must contain at most {MAX_RPC_ENDPOINTS} endpoints")
    if any(any(character.isspace() for character in endpoint) for endpoint in endpoints):
        raise ChainError("RPC URL must not contain whitespace")
    return endpoints


def _available_rpc_endpoints(endpoints: tuple[str, ...]) -> tuple[str, ...]:
    now = time.monotonic()
    with _RPC_ENDPOINT_LOCK:
        available = tuple(
            endpoint
            for endpoint in endpoints
            if _RPC_ENDPOINT_COOLDOWNS.get(endpoint, 0.0) <= now
        )
    return available or endpoints


def _cooldown_rpc_endpoint(endpoint: str) -> None:
    with _RPC_ENDPOINT_LOCK:
        _RPC_ENDPOINT_COOLDOWNS[endpoint] = time.monotonic() + RPC_ENDPOINT_COOLDOWN_SECONDS


def _rpc_call_once(
    rpc_url: str,
    *,
    method: str,
    params: list[Any],
    deadline: float,
) -> Any:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _RetryableRPCError(f"RPC request failed for {method}: deadline exceeded")
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    request = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "mycomesh-gateway/0.2",
        },
        method="POST",
    )
    response_limit = MAX_RPC_LOG_RESPONSE_BYTES if method == "eth_getLogs" else MAX_RPC_RESPONSE_BYTES
    try:
        with urllib.request.urlopen(request, timeout=remaining) as response:
            body = read_bounded(
                response,
                maximum=response_limit,
                label="RPC response",
                deadline=deadline,
            ).decode(
                "utf-8", errors="replace"
            )
    except NetworkIOError as exc:
        raise ChainError(f"RPC request failed for {method}: {exc}") from exc
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        error = f"RPC request failed for {method}: HTTP {status}"
        if status in {403, 408, 425, 429} or 500 <= status <= 599:
            raise _RetryableRPCError(error) from exc
        raise ChainError(error) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise _RetryableRPCError(f"RPC request failed for {method}: connection failed") from exc

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise _RetryableRPCError(f"RPC returned invalid JSON for {method}: {text_preview(body)}") from exc
    if not isinstance(parsed, dict):
        raise _RetryableRPCError(f"RPC returned a non-object response for {method}")
    if "error" in parsed:
        error = f"RPC error for {method}: {text_preview(str(parsed['error']))}"
        normalized = error.lower()
        if any(
            marker in normalized
            for marker in ("rate limit", "too many requests", "temporarily unavailable", "no nodes available")
        ):
            raise _RetryableRPCError(error)
        raise ChainError(error)
    return parsed.get("result")


def run_tool(command: list[str], timeout: float) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ChainError(f"command not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ChainError(f"{command[0]} timed out after {timeout:.0f}s") from exc

    output = "\n".join(part.strip() for part in [completed.stdout, completed.stderr] if part.strip())
    if completed.returncode != 0:
        raise ChainError(output or f"{command[0]} exited with {completed.returncode}")
    return output


def encode_contract_call(signature: str, args: list[str]) -> str:
    selector = keccak256(signature.encode("utf-8"))[:4]
    encoded_args = b"".join(abi_encode_arg(arg) for arg in args)
    return "0x" + (selector + encoded_args).hex()


def governance_action_hash(action: str, **kwargs: Any) -> str:
    normalized = action.strip().lower().replace("_", "-")
    if normalized == "treasury":
        encoded = abi_encode_string_prefixed("setTreasury", [normalize_address(str(kwargs.get("treasury") or ""))])
    elif normalized == "operator":
        encoded = abi_encode_string_prefixed(
            "setOperator",
            [
                normalize_address(str(kwargs.get("operator") or "")),
                _bool_word(kwargs.get("allowed")),
            ],
        )
    elif normalized in {"governance-executor", "executor"}:
        encoded = abi_encode_string_prefixed(
            "setGovernanceExecutor",
            [normalize_address(str(kwargs.get("executor") or ""))],
        )
    elif normalized in {"governance-delay", "delay"}:
        encoded = abi_encode_string_prefixed("setGovernanceDelay", [str(_required_int(kwargs, "delay_seconds"))])
    elif normalized == "economics":
        encoded = abi_encode_string_prefixed(
            "setEconomics",
            [
                str(_required_int(kwargs, "epoch_seconds")),
                str(reward_token_amount(str(_required_value(kwargs, "epoch_emission_myco")))),
                str(_required_int(kwargs, "halving_interval_epochs")),
                str(_required_int(kwargs, "max_consumer_rebate_bps")),
            ],
        )
    elif normalized in {"trusted-settlement", "trusted"}:
        encoded = abi_encode_string_prefixed("setTrustedSettlementEnabled", [_bool_word(kwargs.get("enabled"))])
    elif normalized == "channel":
        encoded = abi_encode_string_prefixed(
            "setChannel",
            [
                normalize_bytes32(str(kwargs.get("channel_hash") or DEFAULT_CHANNEL_HASH)),
                str(stablecoin_amount(str(_required_value(kwargs, "input_per_1k_usdc")))),
                str(stablecoin_amount(str(_required_value(kwargs, "output_per_1k_usdc")))),
                str(stablecoin_amount(str(_required_value(kwargs, "minimum_fee_usdc")))),
                str(_required_int(kwargs, "provider_bps")),
                str(_required_int(kwargs, "relay_bps")),
                str(_required_int(kwargs, "pool_bps")),
                str(_required_int(kwargs, "treasury_bps")),
                str(_required_int(kwargs, "provider_reward_bps")),
                str(_required_int(kwargs, "consumer_reward_bps")),
                str(_required_int(kwargs, "reward_per_treasury_unit")),
                _bool_word(kwargs.get("active")),
            ],
        )
    elif normalized in {"buyback-burn", "buyback"}:
        encoded = abi_encode_string_prefixed(
            "treasuryBuybackBurn",
            [str(reward_token_amount(str(_required_value(kwargs, "amount_myco"))))],
        )
    else:
        raise ChainError(f"unsupported governance action: {action}")
    return "0x" + keccak256(encoded).hex()


def abi_encode_string_prefixed(method: str, static_args: list[str]) -> bytes:
    method_bytes = method.encode("utf-8")
    head = [(32 * (len(static_args) + 1)).to_bytes(32, "big")]
    head.extend(abi_encode_arg(arg) for arg in static_args)
    padded_length = ((len(method_bytes) + 31) // 32) * 32
    tail = len(method_bytes).to_bytes(32, "big") + method_bytes.ljust(padded_length, b"\x00")
    return b"".join(head) + tail


def encode_settle_signed_receipt_call(args: SignedReceiptSettlementArgs) -> str:
    signature = (
        "settleSignedReceiptFromBalance("
        "((bytes32,bytes32,bytes32,address,address,address,address,uint256,uint256,bytes32,uint256),"
        "(bytes32,bytes32,uint8),(bytes32,bytes32,uint8),(bytes32,bytes32,uint8),bool)"
        ")"
    )
    selector = keccak256(signature.encode("utf-8"))[:4]
    encoded = b"".join(abi_encode_arg(arg) for arg in args.abi_args())
    return "0x" + (selector + encoded).hex()


def encode_settle_delegated_receipt_call(args: DelegatedReceiptSettlementArgs) -> str:
    signature = (
        "settleDelegatedReceiptFromBalance("
        "((bytes32,bytes32,bytes32,address,address,address,address,uint256,uint256,bytes32,uint256),"
        "(bytes32,bytes32,uint8),(bytes32,bytes32,uint8),(bytes32,bytes32,uint8),bool),"
        "(bytes32,bytes32,uint8),(bytes32,bytes32,uint8),uint256,uint256,uint256,uint256"
        ")"
    )
    selector = keccak256(signature.encode("utf-8"))[:4]
    encoded = b"".join(abi_encode_arg(arg) for arg in args.abi_args())
    return "0x" + (selector + encoded).hex()


def abi_encode_arg(value: str) -> bytes:
    if ADDRESS_PATTERN.match(value):
        return bytes(12) + bytes.fromhex(value[2:])
    if BYTES32_PATTERN.match(value):
        return bytes.fromhex(value[2:])
    if value in {"true", "false"}:
        return (1 if value == "true" else 0).to_bytes(32, "big")
    if value in {"True", "False"}:
        return (1 if value == "True" else 0).to_bytes(32, "big")
    parsed = int(value)
    if parsed < 0:
        raise ChainError("uint256 argument cannot be negative")
    return parsed.to_bytes(32, "big")


def _required_value(values: dict[str, Any], key: str) -> Any:
    value = values.get(key)
    if value is None:
        raise ChainError(f"{key} is required")
    return value


def _required_int(values: dict[str, Any], key: str) -> int:
    value = _required_value(values, key)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ChainError(f"{key} must be an integer") from exc


def _bool_word(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(_required_value({"value": value}, "value")).strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return "true"
    if text in {"false", "0", "no", "n"}:
        return "false"
    raise ChainError("boolean value must be true or false")


def parse_private_key(value: str) -> bytes:
    value = value.strip()
    raw = value[2:] if value.startswith("0x") else value
    if not re.fullmatch(r"[a-fA-F0-9]{64}", raw):
        raise ChainError("private key must be 32 bytes hex")
    parsed = int(raw, 16)
    if parsed <= 0 or parsed >= SECP256K1_N:
        raise ChainError("private key is outside secp256k1 range")
    return bytes.fromhex(raw)


def private_key_to_address(private_key: bytes) -> str:
    key_int = int.from_bytes(private_key, "big")
    key = ec.derive_private_key(key_int, ec.SECP256K1())
    numbers = key.public_key().public_numbers()
    public_key = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    return "0x" + keccak256(public_key)[-20:].hex()


def sign_legacy_transaction(
    private_key: bytes,
    nonce: int,
    gas_price: int,
    gas_limit: int,
    to_address: str | None,
    value: int,
    data: bytes,
    chain_id: int,
) -> bytes:
    to = b"" if to_address is None else bytes.fromhex(normalize_address(to_address)[2:])
    signing_payload = rlp_encode(
        [
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            chain_id,
            0,
            0,
        ]
    )
    digest = keccak256(signing_payload)
    r, s, recovery_id = sign_digest(private_key, digest)
    v = chain_id * 2 + 35 + recovery_id
    return rlp_encode(
        [
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            v,
            r,
            s,
        ]
    )


def sign_digest(private_key: bytes, digest: bytes) -> tuple[int, int, int]:
    key_int = int.from_bytes(private_key, "big")
    key = ec.derive_private_key(key_int, ec.SECP256K1())
    signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(signature)
    public_numbers = key.public_key().public_numbers()
    target = (public_numbers.x, public_numbers.y)
    recovery_id = recover_id(digest, r, s, target)
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
        recovery_id ^= 1
    return r, s, recovery_id


def recover_id(digest: bytes, r: int, s: int, target: tuple[int, int]) -> int:
    z = int.from_bytes(digest, "big")
    for recovery_id in range(4):
        point = recover_public_key(z, r, s, recovery_id)
        if point == target:
            return recovery_id
    raise ChainError("could not recover ECDSA public key")


def recover_public_key(z: int, r: int, s: int, recovery_id: int) -> tuple[int, int] | None:
    x = r + (recovery_id // 2) * SECP256K1_N
    if x >= SECP256K1_P:
        return None
    y = secp256k1_y(x, recovery_id % 2)
    if y is None:
        return None
    r_point = (x, y)
    r_inv = pow(r, -1, SECP256K1_N)
    s_r = point_mul(s % SECP256K1_N, r_point)
    z_g = point_mul(z % SECP256K1_N, SECP256K1_G)
    if s_r is None or z_g is None:
        return None
    candidate = point_mul(r_inv, point_add(s_r, point_neg(z_g)))
    return candidate


def secp256k1_y(x: int, parity: int) -> int | None:
    alpha = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
    beta = pow(alpha, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(beta, 2, SECP256K1_P) != alpha:
        return None
    return beta if beta % 2 == parity else SECP256K1_P - beta


def point_add(
    first: tuple[int, int] | None,
    second: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if first == second:
        slope = (3 * x1 * x1 + SECP256K1_A) * pow(2 * y1, -1, SECP256K1_P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, SECP256K1_P)
    slope %= SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def point_neg(point: tuple[int, int] | None) -> tuple[int, int] | None:
    if point is None:
        return None
    return point[0], (-point[1]) % SECP256K1_P


def point_mul(scalar: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def keccak256(payload: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(payload)
    return digest.digest()


def build_receipt_settlement_args(
    receipt: dict[str, Any],
    consumer: str | None,
    provider: str | None,
    relay: str | None = None,
    pool: str | None = None,
    channel_hash: str | None = None,
    pricing_hash: str | None = None,
    deadline: int | None = None,
    accepted_hash: str | None = None,
) -> ReceiptSettlementArgs:
    input_tokens, output_tokens = receipt_token_usage(receipt)
    channel = str(receipt.get("channel") or DEFAULT_CHANNEL)
    consumer_address = consumer or str(receipt.get("consumer_payment_address") or "")
    provider_address = provider or str(receipt.get("provider_payment_address") or "")
    if not consumer_address:
        raise ChainError("consumer address is required; pass --consumer-address or include consumer_payment_address in receipt")
    if not provider_address:
        raise ChainError("provider address is required; pass --provider-address or include provider_payment_address in receipt")
    return ReceiptSettlementArgs(
        receipt_hash=receipt_hash(receipt),
        accepted_hash=normalize_bytes32(accepted_hash or str(receipt.get("accepted_hash") or ZERO_BYTES32)),
        channel_hash=normalize_bytes32(channel_hash or channel_to_hash(channel)),
        consumer=normalize_address(consumer_address),
        provider=normalize_address(provider_address),
        relay=normalize_address(relay or ZERO_ADDRESS),
        pool=normalize_address(pool or ZERO_ADDRESS),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        pricing_hash=normalize_bytes32(
            pricing_hash
            or str(receipt.get("channel_pricing_hash") or _receipt_pricing_hash(receipt) or ZERO_BYTES32)
        ),
        deadline=int(deadline if deadline is not None else int(receipt.get("settlement_deadline") or 0)),
        gross_fee_units=_receipt_gross_fee_units(receipt, input_tokens=input_tokens, output_tokens=output_tokens),
    )


def receipt_hash(receipt: dict[str, Any]) -> str:
    return ledger_receipt_hash(receipt)


def build_signed_receipt_settlement_args(
    receipt: dict[str, Any],
    consumer_private_key: str,
    provider_private_key: str,
    operator_private_key: str | None = None,
    consumer: str | None = None,
    provider: str | None = None,
    relay: str | None = None,
    pool: str | None = None,
    channel_hash: str | None = None,
    pricing_hash: str | None = None,
    deadline: int | None = None,
    accepted_hash: str | None = None,
    chain_id: int = SEPOLIA_CHAIN_ID,
    verifying_contract: str | None = None,
) -> SignedReceiptSettlementArgs:
    if not verifying_contract:
        raise ChainError("verifying contract is required for signed Myco receipt settlement")
    try:
        validate_settlement_receipt(
            receipt,
            consumer_address=consumer or str(receipt.get("consumer_payment_address") or ""),
            provider_address=provider or str(receipt.get("provider_payment_address") or ""),
            consumer_public_key=str(receipt.get("consumer_public_key") or "") or None,
            provider_public_key=str(receipt.get("provider_public_key") or "") or None,
        )
    except ProtocolValidationError as exc:
        raise ChainError(str(exc)) from exc
    settlement_args = build_receipt_settlement_args(
        receipt,
        consumer=consumer,
        provider=provider,
        relay=relay,
        pool=pool,
        channel_hash=channel_hash,
        pricing_hash=pricing_hash,
        deadline=deadline,
        accepted_hash=accepted_hash,
    )
    if settlement_args.accepted_hash == ZERO_BYTES32:
        raise ChainError("signed settlement requires an accepted receipt; include accepted_hash or pass --trusted")
    if settlement_args.pricing_hash == ZERO_BYTES32:
        raise ChainError("signed settlement requires a channel pricing hash; include channel_pricing_hash in receipt or pass --pricing-hash")
    digest = myco_receipt_digest(settlement_args, chain_id=chain_id, verifying_contract=verifying_contract)
    consumer_sig = sign_evm_digest(consumer_private_key, digest)
    provider_sig = sign_evm_digest(provider_private_key, digest)
    operator_sig = sign_evm_digest(operator_private_key, digest) if operator_private_key else None
    consumer_address = private_key_to_address(parse_private_key(consumer_private_key))
    provider_address = private_key_to_address(parse_private_key(provider_private_key))
    if consumer_address != settlement_args.consumer:
        raise ChainError(f"consumer private key address {consumer_address} does not match receipt consumer {settlement_args.consumer}")
    if provider_address != settlement_args.provider:
        raise ChainError(f"provider private key address {provider_address} does not match receipt provider {settlement_args.provider}")
    return SignedReceiptSettlementArgs(
        receipt=settlement_args,
        consumer_signature=consumer_sig,
        provider_signature=provider_sig,
        operator_signature=operator_sig,
    )


def build_delegated_receipt_settlement_args(
    receipt: dict[str, Any],
    consumer_delegate_private_key: str,
    provider_delegate_private_key: str,
    delegate: str,
    max_amount: int,
    expires_at: int,
    consumer_nonce: int,
    provider_nonce: int,
    operator_private_key: str | None = None,
    consumer: str | None = None,
    provider: str | None = None,
    relay: str | None = None,
    pool: str | None = None,
    channel_hash: str | None = None,
    pricing_hash: str | None = None,
    deadline: int | None = None,
    accepted_hash: str | None = None,
    chain_id: int = SEPOLIA_CHAIN_ID,
    verifying_contract: str | None = None,
) -> DelegatedReceiptSettlementArgs:
    if not verifying_contract:
        raise ChainError("verifying contract is required for delegated Myco receipt settlement")
    try:
        validate_settlement_receipt(
            receipt,
            consumer_address=consumer or str(receipt.get("consumer_payment_address") or ""),
            provider_address=provider or str(receipt.get("provider_payment_address") or ""),
            consumer_public_key=str(receipt.get("consumer_public_key") or "") or None,
            provider_public_key=str(receipt.get("provider_public_key") or "") or None,
        )
    except ProtocolValidationError as exc:
        raise ChainError(str(exc)) from exc
    settlement_args = build_receipt_settlement_args(
        receipt,
        consumer=consumer,
        provider=provider,
        relay=relay,
        pool=pool,
        channel_hash=channel_hash,
        pricing_hash=pricing_hash,
        deadline=deadline,
        accepted_hash=accepted_hash,
    )
    if settlement_args.accepted_hash == ZERO_BYTES32:
        raise ChainError("delegated settlement requires an accepted receipt; include accepted_hash")
    if settlement_args.pricing_hash == ZERO_BYTES32:
        raise ChainError("delegated settlement requires a channel pricing hash; include channel_pricing_hash in receipt or pass --pricing-hash")
    if max_amount < 0:
        raise ChainError("delegate max amount must be non-negative")
    if expires_at < 0:
        raise ChainError("delegate expiry must be non-negative")
    if consumer_nonce < 0 or provider_nonce < 0:
        raise ChainError("delegate nonces must be non-negative")
    delegate = normalize_address(delegate)
    consumer_auth = build_delegate_authorization(
        account_private_key=consumer_delegate_private_key,
        delegate=delegate,
        receipt=settlement_args,
        max_amount=max_amount,
        expires_at=expires_at,
        nonce=consumer_nonce,
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )
    provider_auth = build_delegate_authorization(
        account_private_key=provider_delegate_private_key,
        delegate=delegate,
        receipt=settlement_args,
        max_amount=max_amount,
        expires_at=expires_at,
        nonce=provider_nonce,
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )
    if consumer_auth.account != settlement_args.consumer:
        raise ChainError(f"consumer delegate key address {consumer_auth.account} does not match receipt consumer {settlement_args.consumer}")
    if provider_auth.account != settlement_args.provider:
        raise ChainError(f"provider delegate key address {provider_auth.account} does not match receipt provider {settlement_args.provider}")
    operator_sig = None
    if operator_private_key:
        operator_sig = sign_evm_digest(
            operator_private_key,
            myco_receipt_digest(settlement_args, chain_id=chain_id, verifying_contract=verifying_contract),
        )
    return DelegatedReceiptSettlementArgs(
        receipt=settlement_args,
        consumer_delegate_signature=consumer_auth.signature,
        provider_delegate_signature=provider_auth.signature,
        max_amount=int(max_amount),
        expires_at=int(expires_at),
        consumer_nonce=int(consumer_nonce),
        provider_nonce=int(provider_nonce),
        operator_signature=operator_sig,
    )


def build_delegated_receipt_settlement_args_from_signatures(
    receipt: dict[str, Any],
    *,
    consumer_delegate_signature: EvmSignature,
    provider_delegate_signature: EvmSignature,
    delegate: str,
    max_amount: int,
    expires_at: int,
    consumer_nonce: int,
    provider_nonce: int,
    operator_private_key: str | None = None,
    consumer: str | None = None,
    provider: str | None = None,
    relay: str | None = None,
    pool: str | None = None,
    channel_hash: str | None = None,
    pricing_hash: str | None = None,
    deadline: int | None = None,
    accepted_hash: str | None = None,
    chain_id: int = SEPOLIA_CHAIN_ID,
    verifying_contract: str | None = None,
) -> DelegatedReceiptSettlementArgs:
    if not verifying_contract:
        raise ChainError("verifying contract is required for delegated Myco receipt settlement")
    try:
        validate_settlement_receipt(
            receipt,
            consumer_address=consumer or str(receipt.get("consumer_payment_address") or ""),
            provider_address=provider or str(receipt.get("provider_payment_address") or ""),
            consumer_public_key=str(receipt.get("consumer_public_key") or "") or None,
            provider_public_key=str(receipt.get("provider_public_key") or "") or None,
        )
    except ProtocolValidationError as exc:
        raise ChainError(str(exc)) from exc
    settlement_args = build_receipt_settlement_args(
        receipt,
        consumer=consumer,
        provider=provider,
        relay=relay,
        pool=pool,
        channel_hash=channel_hash,
        pricing_hash=pricing_hash,
        deadline=deadline,
        accepted_hash=accepted_hash,
    )
    if settlement_args.accepted_hash == ZERO_BYTES32:
        raise ChainError("delegated settlement requires an accepted receipt; include accepted_hash")
    if settlement_args.pricing_hash == ZERO_BYTES32:
        raise ChainError("delegated settlement requires a channel pricing hash; include channel_pricing_hash in receipt or pass --pricing-hash")
    delegate = normalize_address(delegate)
    consumer_recovered = recover_evm_address(
        myco_delegate_digest(
            account=settlement_args.consumer,
            delegate=delegate,
            receipt=settlement_args,
            max_amount=max_amount,
            expires_at=expires_at,
            nonce=consumer_nonce,
            chain_id=chain_id,
            verifying_contract=verifying_contract,
        ),
        consumer_delegate_signature,
    )
    provider_recovered = recover_evm_address(
        myco_delegate_digest(
            account=settlement_args.provider,
            delegate=delegate,
            receipt=settlement_args,
            max_amount=max_amount,
            expires_at=expires_at,
            nonce=provider_nonce,
            chain_id=chain_id,
            verifying_contract=verifying_contract,
        ),
        provider_delegate_signature,
    )
    if consumer_recovered != settlement_args.consumer:
        raise ChainError("consumer delegate signature does not recover receipt consumer")
    if provider_recovered != settlement_args.provider:
        raise ChainError("provider delegate signature does not recover receipt provider")
    operator_sig = None
    if operator_private_key:
        operator_sig = sign_evm_digest(
            operator_private_key,
            myco_receipt_digest(settlement_args, chain_id=chain_id, verifying_contract=verifying_contract),
        )
    return DelegatedReceiptSettlementArgs(
        receipt=settlement_args,
        consumer_delegate_signature=consumer_delegate_signature,
        provider_delegate_signature=provider_delegate_signature,
        max_amount=int(max_amount),
        expires_at=int(expires_at),
        consumer_nonce=int(consumer_nonce),
        provider_nonce=int(provider_nonce),
        operator_signature=operator_sig,
    )


def myco_receipt_struct_hash(args: ReceiptSettlementArgs) -> str:
    encoded = b"".join(
        [
            bytes.fromhex(myco_receipt_typehash()[2:]),
            abi_encode_arg(args.receipt_hash),
            abi_encode_arg(args.accepted_hash),
            abi_encode_arg(args.channel_hash),
            abi_encode_arg(args.consumer),
            abi_encode_arg(args.provider),
            abi_encode_arg(args.relay),
            abi_encode_arg(args.pool),
            abi_encode_arg(str(args.input_tokens)),
            abi_encode_arg(str(args.output_tokens)),
            abi_encode_arg(args.pricing_hash),
            abi_encode_arg(str(args.deadline)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def myco_receipt_digest(args: ReceiptSettlementArgs, chain_id: int, verifying_contract: str) -> bytes:
    domain = myco_domain_separator(chain_id=chain_id, verifying_contract=verifying_contract)
    struct_hash = myco_receipt_struct_hash(args)
    return keccak256(b"\x19\x01" + bytes.fromhex(domain[2:]) + bytes.fromhex(struct_hash[2:]))


def myco_domain_separator(chain_id: int, verifying_contract: str) -> str:
    encoded = b"".join(
        [
            bytes.fromhex(myco_domain_typehash()[2:]),
            keccak256(b"MycoMesh Settlement"),
            keccak256(b"2"),
            abi_encode_arg(str(chain_id)),
            abi_encode_arg(normalize_address(verifying_contract)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def myco_receipt_typehash() -> str:
    return "0x" + keccak256(MYCO_RECEIPT_TYPE.encode("utf-8")).hex()


def myco_domain_typehash() -> str:
    return "0x" + keccak256(MYCO_DOMAIN_TYPE.encode("utf-8")).hex()


def myco_delegate_digest(
    *,
    account: str,
    delegate: str,
    receipt: ReceiptSettlementArgs,
    max_amount: int,
    expires_at: int,
    nonce: int,
    chain_id: int,
    verifying_contract: str,
) -> bytes:
    delegate_typehash = keccak256(
        b"SettlementDelegate(address account,address delegate,bytes32 receiptHash,bytes32 acceptedHash,bytes32 channel,address counterparty,uint256 grossFee,uint256 maxAmount,uint256 expiresAt,uint256 nonce)"
    )
    normalized_account = normalize_address(account)
    if normalized_account not in {receipt.consumer, receipt.provider}:
        raise ChainError("delegate account must be the receipt consumer or provider")
    counterparty = receipt.provider if normalized_account == receipt.consumer else receipt.consumer
    gross_fee = _receipt_gross_fee_units_from_args(receipt)
    encoded = b"".join(
        [
            delegate_typehash,
            abi_encode_arg(normalized_account),
            abi_encode_arg(normalize_address(delegate)),
            abi_encode_arg(receipt.receipt_hash),
            abi_encode_arg(receipt.accepted_hash),
            abi_encode_arg(receipt.channel_hash),
            abi_encode_arg(counterparty),
            abi_encode_arg(str(gross_fee)),
            abi_encode_arg(str(max_amount)),
            abi_encode_arg(str(expires_at)),
            abi_encode_arg(str(nonce)),
        ]
    )
    struct_hash = keccak256(encoded)
    domain = myco_domain_separator(chain_id=chain_id, verifying_contract=verifying_contract)
    return keccak256(b"\x19\x01" + bytes.fromhex(domain[2:]) + struct_hash)


def build_delegate_authorization(
    *,
    account_private_key: str,
    delegate: str,
    receipt: ReceiptSettlementArgs,
    max_amount: int,
    expires_at: int,
    nonce: int,
    chain_id: int,
    verifying_contract: str,
) -> DelegateAuthorization:
    account = private_key_to_address(parse_private_key(account_private_key))
    digest = myco_delegate_digest(
        account=account,
        delegate=delegate,
        receipt=receipt,
        max_amount=max_amount,
        expires_at=expires_at,
        nonce=nonce,
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )
    return DelegateAuthorization(
        account=account,
        delegate=normalize_address(delegate),
        receipt=receipt,
        max_amount=int(max_amount),
        expires_at=int(expires_at),
        nonce=int(nonce),
        signature=sign_evm_digest(account_private_key, digest),
    )


def sign_evm_digest(private_key: str, digest: bytes) -> EvmSignature:
    r, s, recovery_id = sign_digest(parse_private_key(private_key), digest)
    return EvmSignature(
        r="0x" + r.to_bytes(32, "big").hex(),
        s="0x" + s.to_bytes(32, "big").hex(),
        v=27 + recovery_id,
    )


def recover_evm_address(digest: bytes, signature: EvmSignature) -> str:
    recovery_id = int(signature.v)
    if recovery_id >= 27:
        recovery_id -= 27
    if recovery_id < 0 or recovery_id > 3:
        raise ChainError("signature v must be 0/1/27/28 or recovery id 0..3")
    r = _signature_scalar(signature.r, "r")
    s = _signature_scalar(signature.s, "s")
    point = recover_public_key(int.from_bytes(digest, "big"), r, s, recovery_id)
    if point is None:
        raise ChainError("could not recover signature public key")
    public_key = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return "0x" + keccak256(public_key)[-20:].hex()


def evm_signature_from_json(value: str | dict[str, Any]) -> EvmSignature:
    payload = json.loads(value) if isinstance(value, str) else value
    if not isinstance(payload, dict):
        raise ChainError("signature JSON must be an object")
    return EvmSignature(
        r=normalize_bytes32(str(payload.get("r") or "")),
        s=normalize_bytes32(str(payload.get("s") or "")),
        v=int(payload.get("v")),
    )


def _signature_scalar(value: str, label: str) -> int:
    normalized = normalize_bytes32(value)
    parsed = int(normalized, 16)
    if parsed <= 0 or parsed >= SECP256K1_N:
        raise ChainError(f"signature {label} is outside secp256k1 range")
    return parsed


def receipt_token_usage(receipt: dict[str, Any]) -> tuple[int, int]:
    pricing = receipt.get("pricing")
    if isinstance(pricing, dict):
        try:
            return max(0, int(pricing.get("input_tokens") or 0)), max(0, int(pricing.get("output_tokens") or 0))
        except (TypeError, ValueError):
            pass
    usage = receipt.get("usage")
    return usage_tokens(usage if isinstance(usage, dict) else None)


def _receipt_gross_fee_units(
    receipt: dict[str, Any],
    *,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
) -> int:
    pricing = receipt.get("pricing")
    if isinstance(pricing, dict) and pricing.get("gross_fee") is not None:
        return stablecoin_amount(str(pricing["gross_fee"]))
    if input_tokens is None or output_tokens is None:
        input_tokens, output_tokens = receipt_token_usage(receipt)
    # Default channel economics in MycoSettlementV2. Custom pricing must include
    # pricing.gross_fee so delegated signatures bind the same fee the chain quotes.
    gross = ((max(0, int(input_tokens)) * 1000) + (max(0, int(output_tokens)) * 4000)) // 1000
    return max(2000, gross)


def _receipt_gross_fee_units_from_args(receipt: ReceiptSettlementArgs) -> int:
    if receipt.gross_fee_units > 0:
        return int(receipt.gross_fee_units)
    gross = ((max(0, int(receipt.input_tokens)) * 1000) + (max(0, int(receipt.output_tokens)) * 4000)) // 1000
    return max(2000, gross)


def _receipt_pricing_hash(receipt: dict[str, Any]) -> str | None:
    for key in ("channel_pricing_hash",):
        value = receipt.get(key)
        if isinstance(value, str) and BYTES32_PATTERN.match(value):
            return normalize_bytes32(value)
    pricing = receipt.get("pricing")
    if isinstance(pricing, dict):
        for key in ("channel_pricing_hash",):
            value = pricing.get(key)
            if isinstance(value, str) and BYTES32_PATTERN.match(value):
                return normalize_bytes32(value)
    return None


def load_receipt(path: Path, index: int = -1) -> dict[str, Any]:
    if not path.exists():
        raise ChainError(f"receipt file not found: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ChainError(f"receipt file is empty: {path}")
    if path.suffix.lower() == ".json":
        value = json.loads(text)
        if isinstance(value, dict) and "receipt" in value and isinstance(value["receipt"], dict):
            return value["receipt"]
        if isinstance(value, dict):
            return value
        raise ChainError("receipt JSON must be an object")

    lines = [line for line in text.splitlines() if line.strip()]
    try:
        selected = lines[index]
    except IndexError as exc:
        raise ChainError(f"receipt index {index} is out of range") from exc
    value = json.loads(selected)
    if not isinstance(value, dict):
        raise ChainError("receipt JSONL line must be an object")
    return value


def load_receipts(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    if not path.exists():
        raise ChainError(f"receipt file not found: {path}")
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, list):
            return [dict(item) for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value["receipt"] if isinstance(value.get("receipt"), dict) else value]
        raise ChainError("receipt JSON must be an object or array")
    receipts: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ChainError("receipt JSONL line must be an object")
        receipts.append(value)
    if limit is not None and limit > 0:
        return receipts[-limit:]
    return receipts


def save_deployment(path: Path, deployment: ChainDeployment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(deployment.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def save_myco_deployment(path: Path, deployment: MycoDeployment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(deployment.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_deployment(path: Path = Path(DEFAULT_DEPLOYMENT_PATH)) -> ChainDeployment:
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        return ChainDeployment(
            chain_id=int(payload.get("chain_id") or SEPOLIA_CHAIN_ID),
            deployer=normalize_address(payload["deployer"]),
            test_usdc=normalize_address(payload["test_usdc"]),
            token=normalize_address(payload["token"]),
            settlement=normalize_address(payload["settlement"]),
            treasury=normalize_address(payload["treasury"]),
            channel=str(payload.get("channel") or DEFAULT_CHANNEL),
            channel_hash=normalize_bytes32(str(payload.get("channel_hash") or DEFAULT_CHANNEL_HASH)),
            tx_hash=payload.get("tx_hash"),
        )

    settlement = os.getenv("FANDAI_SETTLEMENT")
    test_usdc = os.getenv("FANDAI_TEST_USDC")
    token = os.getenv("FANDAI_TOKEN")
    treasury = os.getenv("FANDAI_TREASURY") or os.getenv("TREASURY")
    if settlement and test_usdc and token and treasury:
        return ChainDeployment(
            chain_id=int(os.getenv("ETH_CHAIN_ID", str(SEPOLIA_CHAIN_ID))),
            deployer=normalize_address(os.getenv("FANDAI_DEPLOYER", ZERO_ADDRESS)),
            test_usdc=normalize_address(test_usdc),
            token=normalize_address(token),
            settlement=normalize_address(settlement),
            treasury=normalize_address(treasury),
            channel=os.getenv("FANDAI_CHANNEL", DEFAULT_CHANNEL),
            channel_hash=normalize_bytes32(os.getenv("FANDAI_CHANNEL_HASH", DEFAULT_CHANNEL_HASH)),
        )

    raise ChainError(f"deployment not found: {path}")


def load_myco_deployment(
    path: Path = Path(DEFAULT_MYCO_DEPLOYMENT_PATH),
    *,
    env: Mapping[str, str] | None = None,
) -> MycoDeployment:
    values: Mapping[str, str] = os.environ if env is None else env
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ChainError("Myco deployment must be a JSON object")
        protocol_version = payload.get("protocol_version")
        if protocol_version is not None:
            if type(protocol_version) is not int:
                raise ChainError("Myco deployment protocol_version must be an integer")
            if protocol_version != 2:
                raise ChainError("V2 loader refuses a non-V2 Myco deployment manifest")
        return MycoDeployment(
            chain_id=int(payload.get("chain_id") or SEPOLIA_CHAIN_ID),
            deployer=normalize_address(payload["deployer"]),
            test_usdc=normalize_address(payload["test_usdc"]),
            token=normalize_address(payload["token"]),
            settlement=normalize_address(payload["settlement"]),
            treasury=normalize_address(payload["treasury"]),
            channel=str(payload.get("channel") or DEFAULT_CHANNEL),
            channel_hash=normalize_bytes32(str(payload.get("channel_hash") or DEFAULT_CHANNEL_HASH)),
            tx_hash=payload.get("tx_hash"),
        )

    settlement = values.get("MYCO_SETTLEMENT")
    test_usdc = values.get("MYCO_TEST_USDC")
    token = values.get("MYCO_TOKEN")
    treasury = values.get("MYCO_TREASURY") or values.get("TREASURY")
    if settlement and test_usdc and token and treasury:
        return MycoDeployment(
            chain_id=int(values.get("ETH_CHAIN_ID", str(SEPOLIA_CHAIN_ID))),
            deployer=normalize_address(values.get("MYCO_DEPLOYER", ZERO_ADDRESS)),
            test_usdc=normalize_address(test_usdc),
            token=normalize_address(token),
            settlement=normalize_address(settlement),
            treasury=normalize_address(treasury),
            channel=values.get("MYCO_CHANNEL", DEFAULT_CHANNEL),
            channel_hash=normalize_bytes32(values.get("MYCO_CHANNEL_HASH", DEFAULT_CHANNEL_HASH)),
        )

    raise ChainError(f"Myco deployment not found: {path}")


def load_active_myco_deployment(
    path: str | Path | None = None,
    *,
    settlement_version: int | None = None,
    env: Mapping[str, str] | None = None,
) -> Any:
    values: Mapping[str, str] = os.environ if env is None else env
    if settlement_version is not None:
        if type(settlement_version) is not int:
            raise ChainError("MYCOMESH_SETTLEMENT_VERSION must be an integer")
        version = settlement_version
    else:
        raw_version = values.get("MYCOMESH_SETTLEMENT_VERSION", "2")
        if not isinstance(raw_version, str) or re.fullmatch(r"[+-]?\d+", raw_version.strip()) is None:
            raise ChainError("MYCOMESH_SETTLEMENT_VERSION must be an integer")
        version = int(raw_version)
    if version not in {2, 3}:
        raise ChainError("MYCOMESH_SETTLEMENT_VERSION must be 2 or 3")

    if version == 3:
        from .chain_v3 import DEFAULT_MYCO_V3_DEPLOYMENT_PATH, load_deployment
        from .deployment_validation import validate_v3_environment

        resolved = Path(path or values.get("MYCO_DEPLOYMENT") or DEFAULT_MYCO_V3_DEPLOYMENT_PATH)
        if not resolved.is_absolute() and not resolved.exists():
            bundled = Path(__file__).resolve().parent.parent / resolved
            if bundled.exists():
                resolved = bundled
        return validate_v3_environment(load_deployment(resolved), values)

    resolved = Path(path or values.get("MYCO_DEPLOYMENT") or DEFAULT_MYCO_DEPLOYMENT_PATH)
    return load_myco_deployment(resolved, env=values)


def rpc_url_arg(value: str | None) -> str:
    resolved = value or os.getenv("ETH_RPC_URL")
    if not resolved:
        raise ChainError("missing RPC URL; pass --rpc-url or set ETH_RPC_URL")
    return resolved


def private_key_arg(value: str | None) -> str:
    resolved = value or os.getenv("PRIVATE_KEY") or os.getenv("ETH_PRIVATE_KEY")
    if not resolved:
        raise ChainError("missing private key; pass --private-key or set PRIVATE_KEY")
    return resolved


def treasury_arg(value: str | None) -> str:
    resolved = value or os.getenv("TREASURY") or os.getenv("MYCO_TREASURY") or os.getenv("FANDAI_TREASURY")
    if not resolved:
        raise ChainError("missing treasury address; pass --treasury or set TREASURY")
    return normalize_address(resolved)


def channel_to_hash(channel: str) -> str:
    if channel == DEFAULT_CHANNEL:
        return DEFAULT_CHANNEL_HASH
    return "0x" + keccak256(channel.encode("utf-8")).hex()


def stablecoin_amount(amount: str) -> int:
    parsed = Decimal(str(amount))
    if parsed < 0:
        raise ChainError("amount must be non-negative")
    scaled = (parsed * (10**USDC_DECIMALS)).quantize(Decimal("1"), rounding=ROUND_DOWN)
    return int(scaled)


def reward_token_amount(amount: str) -> int:
    parsed = Decimal(str(amount))
    if parsed < 0:
        raise ChainError("amount must be non-negative")
    scaled = (parsed * (10**MYCO_DECIMALS)).quantize(Decimal("1"), rounding=ROUND_DOWN)
    return int(scaled)


def derive_testnet_addresses(deployer: str) -> dict[str, str]:
    deployer = normalize_address(deployer)
    return {
        "test_usdc": derive_contract_address(deployer, 1),
        "token": derive_contract_address(deployer, 2),
        "settlement": derive_contract_address(deployer, 3),
    }


def derive_contract_address(sender: str, nonce: int) -> str:
    sender_bytes = bytes.fromhex(normalize_address(sender)[2:])
    encoded = rlp_encode([sender_bytes, nonce])
    return "0x" + keccak256(encoded)[-20:].hex()


def rlp_encode(value: Any) -> bytes:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("RLP cannot encode negative integers")
        if value == 0:
            return bytes([0x80])
        return _rlp_encode_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))
    if isinstance(value, bytes):
        return _rlp_encode_bytes(value)
    if isinstance(value, list):
        payload = b"".join(rlp_encode(item) for item in value)
        return _rlp_prefix(payload, 0xC0)
    raise TypeError(f"unsupported RLP value: {type(value).__name__}")


def normalize_address(value: str) -> str:
    if not isinstance(value, str) or not ADDRESS_PATTERN.match(value):
        raise ChainError(f"invalid EVM address: {value!r}")
    return "0x" + value[2:].lower()


def normalize_bytes32(value: str) -> str:
    if not isinstance(value, str) or not BYTES32_PATTERN.match(value):
        raise ChainError(f"invalid bytes32 value: {value!r}")
    return "0x" + value[2:].lower()


def _rlp_encode_bytes(value: bytes) -> bytes:
    if len(value) == 1 and value[0] < 0x80:
        return value
    return _rlp_prefix(value, 0x80)


def _rlp_prefix(payload: bytes, offset: int) -> bytes:
    if len(payload) <= 55:
        return bytes([offset + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(length)]) + length + payload


def _extract_address(output: str, label: str) -> str:
    pattern = re.compile(rf"{re.escape(label)}:\s*(0x[a-fA-F0-9]{{40}})")
    match = pattern.search(output)
    if not match:
        match = re.search(r"0x[a-fA-F0-9]{40}", output)
    if not match:
        raise ChainError(f"could not parse deployed address from tool output:\n{output}")
    return normalize_address(match.group(1))


def _extract_optional_hash(output: str, label: str) -> str | None:
    pattern = re.compile(rf"{re.escape(label)}:\s*(0x[a-fA-F0-9]{{64}})")
    match = pattern.search(output)
    if not match:
        return None
    return normalize_bytes32(match.group(1))


def _extract_transaction_hash(output: str) -> str:
    labeled = _extract_optional_hash(output, "transactionHash") or _extract_optional_hash(output, "Transaction hash")
    if labeled:
        return labeled
    match = re.search(r"0x[a-fA-F0-9]{64}", output)
    if not match:
        raise ChainError(f"could not parse transaction hash from tool output:\n{output}")
    return normalize_bytes32(match.group(0))
