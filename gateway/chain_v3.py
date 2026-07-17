from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .attestation import AttestationError, verify_provider_settlement_attestation
from .chain import (
    BYTES32_PATTERN,
    DEFAULT_CHANNEL_HASH,
    SEPOLIA_CHAIN_ID,
    ZERO_ADDRESS,
    ChainError,
    EvmSignature,
    abi_encode_arg,
    channel_to_hash,
    deploy_contract_transaction,
    derive_contract_address,
    keccak256,
    load_artifact_bytecode,
    normalize_address,
    normalize_bytes32,
    parse_private_key,
    private_key_to_address,
    recover_evm_address,
    reward_token_amount,
    rpc_call,
    run_tool,
    send_contract_data_transaction,
    send_contract_transaction,
    sign_evm_digest,
    stablecoin_amount,
)
from .ledger import receipt_hash as ledger_receipt_hash
from .pricing import DEFAULT_CHANNEL
from .channel_policy import (
    CODEX_BACKEND_POLICY,
    CODEX_CHANNEL_ID,
    MYCOMESH_TESTNET_NETWORK_ID,
)
from .protocol import ProtocolValidationError, validate_settlement_receipt


MYCO_V3_RECEIPT_TYPE = (
    "Receipt(bytes32 receiptHash,bytes32 acceptedHash,bytes32 reservationId,bytes32 requestHash,bytes32 responseHash,"
    "bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,address consumer,address provider,address relay,address pool,"
    "uint256 inputTokens,uint256 outputTokens,uint256 deadline)"
)
MYCO_V3_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
SETTLE_SIGNED_V3_SIGNATURE = (
    "settleSignedReceipt(((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,address,address,"
    "uint256,uint256,uint256),bytes,bytes))"
)
SETTLE_PROVIDER_FALLBACK_V3_SIGNATURE = (
    "settleProviderFallback((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,address,"
    "address,uint256,uint256,uint256),bytes)"
)
MYCO_V3_DEPLOYER_ARTIFACT = "out/MycoV3TestnetDeployer.sol/MycoV3TestnetDeployer.json"
DEFAULT_MYCO_V3_DEPLOYMENT_PATH = "deployments/sepolia-myco-v3.json"
MAX_EIP1271_SIGNATURE_BYTES = 16 * 1024
EIP1271_MAGIC_VALUE = "0x1626ba7e"
V3_DEPLOYMENT_REQUIRED_FIELDS = (
    "protocol_version",
    "chain_id",
    "deployer",
    "test_usdc",
    "stablecoin",
    "settlement",
    "token",
    "treasury",
    "governance",
    "max_consumer_rebate_bps",
    "max_supply",
    "network_id",
    "channel_id",
    "channel",
    "backend_policy",
    "channel_hash",
    "pricing_version",
    "pricing_hash",
)
V3_PROVIDER_SETTLEMENT_SCHEMA = "mycomesh.settlement.v3.provider.v1"
V3_RECEIPT_COMMITMENT_TYPE = (
    "MycoMeshV3ReceiptCommitment(bytes32 reservationId,bytes32 requestHash,bytes32 responseHash,"
    "bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,address consumer,address provider,address relay,"
    "address pool,uint256 inputTokens,uint256 outputTokens,uint256 deadline)"
)
V3_ACCEPTANCE_COMMITMENT_TYPE = (
    "MycoMeshV3ConsumerAcceptance(bytes32 receiptHash,bytes32 reservationId,address consumer,address provider)"
)
V3_PROVIDER_SETTLEMENT_FIELDS = frozenset(
    {"schema", "chain_id", "settlement_contract", "receipt", "receipt_digest", "provider_signature"}
)
V3_RECEIPT_PAYLOAD_FIELDS = frozenset(
    {
        "receipt_hash",
        "accepted_hash",
        "reservation_id",
        "request_hash",
        "response_hash",
        "channel",
        "pricing_version",
        "pricing_hash",
        "consumer",
        "provider",
        "relay",
        "pool",
        "input_tokens",
        "output_tokens",
        "deadline",
    }
)


class EIP1271SignatureRejected(ChainError):
    """The wallet answered successfully but did not validate the signature."""


@dataclass(frozen=True)
class V3Deployment:
    protocol_version: int
    chain_id: int
    deployer: str
    test_usdc: str
    stablecoin: str
    settlement: str
    token: str
    treasury: str
    governance: str
    max_consumer_rebate_bps: int
    max_supply: int
    channel: str
    channel_hash: str
    pricing_version: int
    pricing_hash: str
    eip712_name: str = "MycoMesh Settlement"
    eip712_version: str = "3"
    tx_hash: str | None = None
    network_id: str = MYCOMESH_TESTNET_NETWORK_ID
    channel_id: str = CODEX_CHANNEL_ID
    backend_policy: str = CODEX_BACKEND_POLICY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def deploy_testnet(
    *,
    rpc_url: str,
    private_key: str,
    treasury: str,
    governance: str,
    max_consumer_rebate_bps: int = 1_000,
    max_supply_myco: str = "1000000000",
    chain_id: int = SEPOLIA_CHAIN_ID,
    solc: str | None = None,
    artifact: str = MYCO_V3_DEPLOYER_ARTIFACT,
    timeout: float = 300.0,
) -> V3Deployment:
    treasury = normalize_address(treasury)
    governance = normalize_address(governance)
    rebate_cap = int(max_consumer_rebate_bps)
    if rebate_cap < 1_000 or rebate_cap > 10_000:
        raise ChainError("V3 testnet max consumer rebate must be between 1000 and 10000 bps")
    max_supply = reward_token_amount(max_supply_myco)
    if max_supply <= 0:
        raise ChainError("V3 max MYCO supply must be positive")
    if solc or not Path(artifact).exists():
        command = ["forge", "build"]
        if solc:
            command.extend(["--use", solc, "--offline"])
        run_tool(command, timeout=timeout)
    bytecode = load_artifact_bytecode(Path(artifact))
    constructor_args = b"".join(
        [
            abi_encode_arg(treasury),
            abi_encode_arg(governance),
            abi_encode_arg(str(rebate_cap)),
            abi_encode_arg(str(max_supply)),
        ]
    )
    deployer, tx_hash = deploy_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        bytecode=bytecode + constructor_args,
        timeout=timeout,
    )
    addresses = derive_v3_testnet_addresses(deployer)
    return V3Deployment(
        protocol_version=3,
        chain_id=chain_id,
        deployer=deployer,
        test_usdc=addresses["test_usdc"],
        stablecoin=addresses["test_usdc"],
        settlement=addresses["settlement"],
        token=addresses["token"],
        treasury=treasury,
        governance=governance,
        max_consumer_rebate_bps=rebate_cap,
        max_supply=max_supply,
        channel=DEFAULT_CHANNEL,
        channel_hash=DEFAULT_CHANNEL_HASH,
        pricing_version=1,
        pricing_hash=default_pricing_hash(treasury),
        tx_hash=tx_hash,
    )


def derive_v3_testnet_addresses(deployer: str) -> dict[str, str]:
    return {
        "test_usdc": derive_contract_address(deployer, 1),
        "settlement": derive_contract_address(deployer, 2),
        "token": derive_contract_address(deployer, 3),
    }


def default_pricing_hash(treasury: str) -> str:
    encoded = b"".join(
        abi_encode_arg(value)
        for value in [
            DEFAULT_CHANNEL_HASH,
            "1",
            normalize_address(treasury),
            "1000",
            "4000",
            "2000",
            "8500",
            "300",
            "200",
            "1000",
            "9000",
            "1000",
            "1000000000000",
            "true",
        ]
    )
    return "0x" + keccak256(encoded).hex()


def save_deployment(path: Path, deployment: V3Deployment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(deployment.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _manifest_int(payload: dict[str, Any], field: str) -> int:
    value = payload[field]
    if type(value) is not int:
        raise ChainError(f"Myco V3 deployment {field} must be an integer")
    return value


def load_deployment(path: Path = Path(DEFAULT_MYCO_V3_DEPLOYMENT_PATH)) -> V3Deployment:
    if not path.exists():
        raise ChainError(f"Myco V3 deployment not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ChainError("Myco V3 deployment must be a JSON object")
    missing = [
        field
        for field in V3_DEPLOYMENT_REQUIRED_FIELDS
        if field not in payload
        or payload[field] is None
        or (isinstance(payload[field], str) and not payload[field].strip())
    ]
    if missing:
        raise ChainError(
            "Myco V3 deployment is missing required fields: " + ", ".join(missing)
        )
    protocol_version = _manifest_int(payload, "protocol_version")
    if protocol_version != 3:
        raise ChainError("deployment is not a Myco Settlement V3 deployment")
    stablecoin = normalize_address(str(payload["stablecoin"]))
    deployment = V3Deployment(
        protocol_version=protocol_version,
        chain_id=_manifest_int(payload, "chain_id"),
        deployer=normalize_address(str(payload["deployer"])),
        test_usdc=normalize_address(str(payload["test_usdc"])),
        stablecoin=stablecoin,
        settlement=normalize_address(str(payload["settlement"])),
        token=normalize_address(str(payload["token"])),
        treasury=normalize_address(str(payload["treasury"])),
        governance=normalize_address(str(payload["governance"])),
        max_consumer_rebate_bps=_manifest_int(payload, "max_consumer_rebate_bps"),
        max_supply=_manifest_int(payload, "max_supply"),
        channel=payload["channel"],
        channel_hash=normalize_bytes32(payload["channel_hash"]),
        pricing_version=_manifest_int(payload, "pricing_version"),
        pricing_hash=normalize_bytes32(payload["pricing_hash"]),
        eip712_name=str(payload.get("eip712_name") or "MycoMesh Settlement"),
        eip712_version=str(payload.get("eip712_version") or "3"),
        tx_hash=normalize_bytes32(str(payload["tx_hash"])) if payload.get("tx_hash") else None,
        network_id=str(payload["network_id"]),
        channel_id=str(payload["channel_id"]),
        backend_policy=str(payload["backend_policy"]),
    )
    from .deployment_validation import validate_v3_manifest

    return validate_v3_manifest(deployment)


@dataclass(frozen=True)
class V3ReceiptInput:
    receipt_hash: str
    accepted_hash: str
    reservation_id: str
    request_hash: str
    response_hash: str
    channel_hash: str
    pricing_version: int
    pricing_hash: str
    consumer: str
    provider: str
    relay: str
    pool: str
    input_tokens: int
    output_tokens: int
    deadline: int

    def abi_args(self) -> list[str]:
        if self.pricing_version <= 0 or self.pricing_version > (1 << 64) - 1:
            raise ChainError("pricing_version must be a positive uint64")
        for label, value in (
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
            ("deadline", self.deadline),
        ):
            if value < 0 or value > (1 << 256) - 1:
                raise ChainError(f"{label} must fit uint256")
        if self.deadline <= 0:
            raise ChainError("Settlement V3 receipt deadline is required")
        return [
            normalize_bytes32(self.receipt_hash),
            normalize_bytes32(self.accepted_hash),
            normalize_bytes32(self.reservation_id),
            normalize_bytes32(self.request_hash),
            normalize_bytes32(self.response_hash),
            normalize_bytes32(self.channel_hash),
            str(self.pricing_version),
            normalize_bytes32(self.pricing_hash),
            normalize_address(self.consumer),
            normalize_address(self.provider),
            normalize_address(self.relay),
            normalize_address(self.pool),
            str(self.input_tokens),
            str(self.output_tokens),
            str(self.deadline),
        ]

    def to_payload(self) -> dict[str, Any]:
        return {
            "receipt_hash": normalize_bytes32(self.receipt_hash),
            "accepted_hash": normalize_bytes32(self.accepted_hash),
            "reservation_id": normalize_bytes32(self.reservation_id),
            "request_hash": normalize_bytes32(self.request_hash),
            "response_hash": normalize_bytes32(self.response_hash),
            "channel": normalize_bytes32(self.channel_hash),
            "pricing_version": int(self.pricing_version),
            "pricing_hash": normalize_bytes32(self.pricing_hash),
            "consumer": normalize_address(self.consumer),
            "provider": normalize_address(self.provider),
            "relay": normalize_address(self.relay),
            "pool": normalize_address(self.pool),
            "input_tokens": int(self.input_tokens),
            "output_tokens": int(self.output_tokens),
            "deadline": int(self.deadline),
        }


@dataclass(frozen=True)
class V3SignedReceiptInput:
    receipt: V3ReceiptInput
    consumer_signature: bytes
    provider_signature: bytes


@dataclass(frozen=True)
class V3ReservationSubmission:
    transaction_hash: str
    reservation_id: str
    reservation_salt: str
    request_hash: str


def reservation_id_for(
    *,
    settlement: str,
    chain_id: int,
    consumer: str,
    reservation_salt: str,
) -> str:
    encoded = b"".join(
        [
            abi_encode_arg(normalize_address(settlement)),
            abi_encode_arg(str(_uint(chain_id, "chain_id"))),
            abi_encode_arg(normalize_address(consumer)),
            abi_encode_arg(normalize_bytes32(reservation_salt)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def create_reservation(
    *,
    rpc_url: str,
    private_key: str,
    settlement: str,
    reservation_salt: str,
    provider: str,
    channel_hash: str,
    request_hash: str,
    pricing_version: int,
    amount_usdc: str,
    expires_at: int,
    provider_fallback_allowed: bool = False,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> V3ReservationSubmission:
    if type(provider_fallback_allowed) is not bool:
        raise ChainError("provider_fallback_allowed must be a boolean")
    consumer = private_key_to_address(parse_private_key(private_key))
    salt = normalize_bytes32(reservation_salt)
    normalized_request_hash = normalize_bytes32(request_hash)
    if normalized_request_hash == "0x" + "0" * 64:
        raise ChainError("request_hash must be non-zero")
    reservation_id = reservation_id_for(
        settlement=settlement,
        chain_id=chain_id,
        consumer=consumer,
        reservation_salt=salt,
    )
    transaction_hash = send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="createReservation(bytes32,address,bytes32,bytes32,uint64,uint256,uint64,bool)",
        args=[
            salt,
            normalize_address(provider),
            normalize_bytes32(channel_hash),
            normalized_request_hash,
            str(_uint64(pricing_version, "pricing_version", positive=True)),
            str(stablecoin_amount(amount_usdc)),
            str(_uint64(expires_at, "expires_at", positive=True)),
            "true" if provider_fallback_allowed else "false",
        ],
        timeout=timeout,
    )
    return V3ReservationSubmission(transaction_hash, reservation_id, salt, normalized_request_hash)


def release_expired_reservation(
    *,
    rpc_url: str,
    private_key: str,
    settlement: str,
    reservation_id: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="releaseExpiredReservation(bytes32)",
        args=[normalize_bytes32(reservation_id)],
        timeout=timeout,
    )


def build_receipt_input(
    receipt: dict[str, Any],
    *,
    consumer: str | None = None,
    provider: str | None = None,
    relay: str | None = None,
    pool: str | None = None,
) -> V3ReceiptInput:
    try:
        validate_settlement_receipt(
            receipt,
            consumer_address=consumer or str(receipt.get("consumer_payment_address") or ""),
            provider_address=provider or str(receipt.get("provider_payment_address") or ""),
            consumer_public_key=str(receipt.get("consumer_public_key") or "") or None,
            provider_public_key=str(receipt.get("provider_public_key") or "") or None,
            allow_legacy_receipts=False,
            required_settlement_version=3,
        )
    except ProtocolValidationError as exc:
        raise ChainError(str(exc)) from exc
    pricing = receipt.get("pricing")
    if not isinstance(pricing, dict):
        raise ChainError("receipt pricing is required")
    input_tokens = _non_negative_int(pricing.get("input_tokens"), "input_tokens")
    output_tokens = _non_negative_int(pricing.get("output_tokens"), "output_tokens")
    pricing_version = _positive_int(receipt.get("pricing_version"), "pricing_version")
    deadline = _positive_int(receipt.get("settlement_deadline"), "settlement_deadline")
    args = V3ReceiptInput(
        receipt_hash=ledger_receipt_hash(receipt),
        accepted_hash=_bytes32(receipt.get("accepted_hash"), "accepted_hash"),
        reservation_id=_bytes32(receipt.get("onchain_reservation_id"), "onchain_reservation_id"),
        request_hash=_bytes32(receipt.get("request_hash"), "request_hash"),
        response_hash=_bytes32(receipt.get("response_hash"), "response_hash"),
        channel_hash=channel_to_hash(str(receipt.get("channel") or "")),
        pricing_version=pricing_version,
        pricing_hash=_bytes32(receipt.get("channel_pricing_hash"), "channel_pricing_hash"),
        consumer=consumer or str(receipt.get("consumer_payment_address") or ""),
        provider=provider or str(receipt.get("provider_payment_address") or ""),
        relay=relay or str(receipt.get("relay_payment_address") or ZERO_ADDRESS),
        pool=pool or str(receipt.get("pool_payment_address") or ZERO_ADDRESS),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        deadline=deadline,
    )
    args.abi_args()
    _verify_receipt_provider_attestation(receipt, args)
    return args


def build_provider_fallback_receipt_input(
    receipt: dict[str, Any],
    *,
    consumer: str | None = None,
    provider: str | None = None,
    relay: str | None = None,
    pool: str | None = None,
) -> V3ReceiptInput:
    if not isinstance(receipt, dict):
        raise ChainError("fallback receipt must be a JSON object")
    if int(receipt.get("settlement_version") or 0) != 3:
        raise ChainError("provider fallback requires a Settlement V3 receipt")
    pricing = receipt.get("pricing")
    if not isinstance(pricing, dict):
        raise ChainError("receipt pricing is required")
    args = V3ReceiptInput(
        receipt_hash=ledger_receipt_hash(receipt),
        accepted_hash="0x" + "0" * 64,
        reservation_id=_bytes32(receipt.get("onchain_reservation_id"), "onchain_reservation_id"),
        request_hash=_bytes32(receipt.get("request_hash"), "request_hash"),
        response_hash=_bytes32(receipt.get("response_hash"), "response_hash"),
        channel_hash=channel_to_hash(str(receipt.get("channel") or "")),
        pricing_version=_positive_int(receipt.get("pricing_version"), "pricing_version"),
        pricing_hash=_bytes32(receipt.get("channel_pricing_hash"), "channel_pricing_hash"),
        consumer=consumer or str(receipt.get("consumer_payment_address") or ""),
        provider=provider or str(receipt.get("provider_payment_address") or ""),
        relay=relay or str(receipt.get("relay_payment_address") or ZERO_ADDRESS),
        pool=pool or str(receipt.get("pool_payment_address") or ZERO_ADDRESS),
        input_tokens=_non_negative_int(pricing.get("input_tokens"), "input_tokens"),
        output_tokens=_non_negative_int(pricing.get("output_tokens"), "output_tokens"),
        deadline=_positive_int(receipt.get("settlement_deadline"), "settlement_deadline"),
    )
    args.abi_args()
    _verify_receipt_provider_attestation(receipt, args)
    return args


def build_signed_receipt_input(
    receipt: dict[str, Any],
    *,
    consumer_private_key: str,
    provider_private_key: str,
    chain_id: int,
    verifying_contract: str,
    consumer: str | None = None,
    provider: str | None = None,
    relay: str | None = None,
    pool: str | None = None,
) -> V3SignedReceiptInput:
    args = build_receipt_input(receipt, consumer=consumer, provider=provider, relay=relay, pool=pool)
    expected_consumer = private_key_to_address(parse_private_key(consumer_private_key))
    expected_provider = private_key_to_address(parse_private_key(provider_private_key))
    if expected_consumer != normalize_address(args.consumer):
        raise ChainError("consumer private key does not match receipt consumer")
    if expected_provider != normalize_address(args.provider):
        raise ChainError("provider private key does not match receipt provider")
    digest = receipt_digest(args, chain_id=chain_id, verifying_contract=verifying_contract)
    return V3SignedReceiptInput(
        receipt=args,
        consumer_signature=signature_bytes(sign_evm_digest(consumer_private_key, digest)),
        provider_signature=signature_bytes(sign_evm_digest(provider_private_key, digest)),
    )


def settle_signed_receipt(
    *,
    rpc_url: str,
    submitter_private_key: str,
    settlement: str,
    signed_receipt: V3SignedReceiptInput,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_data_transaction(
        rpc_url=rpc_url,
        private_key=submitter_private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        data=encode_settle_signed_receipt(signed_receipt),
        timeout=timeout,
    )


def settle_provider_fallback(
    *,
    rpc_url: str,
    submitter_private_key: str,
    settlement: str,
    receipt: V3ReceiptInput,
    provider_signature: bytes,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    return send_contract_data_transaction(
        rpc_url=rpc_url,
        private_key=submitter_private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        data=encode_settle_provider_fallback(receipt, provider_signature),
        timeout=timeout,
    )


def receipt_struct_hash(receipt: V3ReceiptInput) -> str:
    encoded = bytes.fromhex(receipt_typehash()[2:]) + b"".join(abi_encode_arg(value) for value in receipt.abi_args())
    return "0x" + keccak256(encoded).hex()


def receipt_digest(receipt: V3ReceiptInput, *, chain_id: int, verifying_contract: str) -> bytes:
    domain = domain_separator(chain_id=chain_id, verifying_contract=verifying_contract)
    struct_hash = receipt_struct_hash(receipt)
    return keccak256(b"\x19\x01" + bytes.fromhex(domain[2:]) + bytes.fromhex(struct_hash[2:]))


def domain_separator(*, chain_id: int, verifying_contract: str) -> str:
    encoded = b"".join(
        [
            keccak256(MYCO_V3_DOMAIN_TYPE.encode("utf-8")),
            keccak256(b"MycoMesh Settlement"),
            keccak256(b"3"),
            abi_encode_arg(str(_uint(chain_id, "chain_id"))),
            abi_encode_arg(normalize_address(verifying_contract)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def receipt_typehash() -> str:
    return "0x" + keccak256(MYCO_V3_RECEIPT_TYPE.encode("utf-8")).hex()


def signature_bytes(signature: EvmSignature) -> bytes:
    r = bytes.fromhex(normalize_bytes32(signature.r)[2:])
    s = bytes.fromhex(normalize_bytes32(signature.s)[2:])
    v = int(signature.v)
    if v not in {0, 1, 27, 28}:
        raise ChainError("signature v must be 0, 1, 27 or 28")
    return r + s + bytes([v])

def build_runtime_v3_receipt(
    *,
    reservation_id: str,
    request_hash: str,
    response_hash: str,
    channel_hash: str,
    pricing_version: int,
    pricing_hash: str,
    consumer: str,
    provider: str,
    input_tokens: int,
    output_tokens: int,
    deadline: int,
    relay: str = ZERO_ADDRESS,
    pool: str = ZERO_ADDRESS,
) -> V3ReceiptInput:
    values = {
        "reservation_id": _nonzero_bytes32(reservation_id, "reservation_id"),
        "request_hash": _nonzero_bytes32(request_hash, "request_hash"),
        "response_hash": _nonzero_bytes32(response_hash, "response_hash"),
        "channel_hash": _nonzero_bytes32(channel_hash, "channel"),
        "pricing_version": _strict_payload_uint(pricing_version, "pricing_version", bits=64, positive=True),
        "pricing_hash": _nonzero_bytes32(pricing_hash, "pricing_hash"),
        "consumer": _nonzero_address(consumer, "consumer"),
        "provider": _nonzero_address(provider, "provider"),
        "relay": normalize_address(relay),
        "pool": normalize_address(pool),
        "input_tokens": _strict_payload_uint(input_tokens, "input_tokens"),
        "output_tokens": _strict_payload_uint(output_tokens, "output_tokens"),
        "deadline": _strict_payload_uint(deadline, "deadline", positive=True),
    }
    if values["consumer"] == values["provider"]:
        raise ChainError("Settlement V3 consumer and provider must differ")
    receipt_hash = _runtime_receipt_hash(**values)
    accepted_hash = _runtime_acceptance_hash(
        receipt_hash=receipt_hash,
        reservation_id=values["reservation_id"],
        consumer=values["consumer"],
        provider=values["provider"],
    )
    receipt = V3ReceiptInput(
        receipt_hash=receipt_hash,
        accepted_hash=accepted_hash,
        **values,
    )
    receipt.abi_args()
    return receipt


def build_provider_settlement_payload(
    *,
    provider_private_key: str,
    chain_id: int,
    settlement_contract: str,
    reservation_id: str,
    request_hash: str,
    response_hash: str,
    channel_hash: str,
    pricing_version: int,
    pricing_hash: str,
    consumer: str,
    provider: str,
    input_tokens: int,
    output_tokens: int,
    deadline: int,
    relay: str = ZERO_ADDRESS,
    pool: str = ZERO_ADDRESS,
) -> dict[str, Any]:
    normalized_chain_id = _strict_payload_uint(chain_id, "chain_id", positive=True)
    normalized_contract = _nonzero_address(settlement_contract, "settlement_contract")
    receipt = build_runtime_v3_receipt(
        reservation_id=reservation_id,
        request_hash=request_hash,
        response_hash=response_hash,
        channel_hash=channel_hash,
        pricing_version=pricing_version,
        pricing_hash=pricing_hash,
        consumer=consumer,
        provider=provider,
        relay=relay,
        pool=pool,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        deadline=deadline,
    )
    signer_address = private_key_to_address(parse_private_key(provider_private_key))
    if signer_address != normalize_address(receipt.provider):
        raise ChainError("Provider EVM identity does not match receipt provider")
    digest = receipt_digest(
        receipt,
        chain_id=normalized_chain_id,
        verifying_contract=normalized_contract,
    )
    signature = signature_bytes(sign_evm_digest(provider_private_key, digest))
    return {
        "schema": V3_PROVIDER_SETTLEMENT_SCHEMA,
        "chain_id": normalized_chain_id,
        "settlement_contract": normalized_contract,
        "receipt": receipt.to_payload(),
        "receipt_digest": "0x" + digest.hex(),
        "provider_signature": "0x" + signature.hex(),
    }


def verify_provider_settlement_payload(payload: Any) -> V3ReceiptInput:
    if not isinstance(payload, dict):
        raise ChainError("Provider V3 settlement payload must be an object")
    if set(payload) != V3_PROVIDER_SETTLEMENT_FIELDS:
        missing = sorted(V3_PROVIDER_SETTLEMENT_FIELDS - set(payload))
        unknown = sorted(set(payload) - V3_PROVIDER_SETTLEMENT_FIELDS)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unknown:
            detail.append("unknown " + ", ".join(unknown))
        raise ChainError("Provider V3 settlement payload fields are invalid: " + "; ".join(detail))
    if payload.get("schema") != V3_PROVIDER_SETTLEMENT_SCHEMA:
        raise ChainError("unsupported Provider V3 settlement payload schema")
    chain_id = _strict_payload_uint(payload.get("chain_id"), "chain_id", positive=True)
    settlement_contract = _nonzero_address(payload.get("settlement_contract"), "settlement_contract")
    receipt_value = payload.get("receipt")
    if not isinstance(receipt_value, dict) or set(receipt_value) != V3_RECEIPT_PAYLOAD_FIELDS:
        raise ChainError("Provider V3 settlement receipt fields are invalid")
    receipt = V3ReceiptInput(
        receipt_hash=_nonzero_bytes32(receipt_value.get("receipt_hash"), "receipt_hash"),
        accepted_hash=_nonzero_bytes32(receipt_value.get("accepted_hash"), "accepted_hash"),
        reservation_id=_nonzero_bytes32(receipt_value.get("reservation_id"), "reservation_id"),
        request_hash=_nonzero_bytes32(receipt_value.get("request_hash"), "request_hash"),
        response_hash=_nonzero_bytes32(receipt_value.get("response_hash"), "response_hash"),
        channel_hash=_nonzero_bytes32(receipt_value.get("channel"), "channel"),
        pricing_version=_strict_payload_uint(
            receipt_value.get("pricing_version"), "pricing_version", bits=64, positive=True
        ),
        pricing_hash=_nonzero_bytes32(receipt_value.get("pricing_hash"), "pricing_hash"),
        consumer=_nonzero_address(receipt_value.get("consumer"), "consumer"),
        provider=_nonzero_address(receipt_value.get("provider"), "provider"),
        relay=normalize_address(str(receipt_value.get("relay") or "")),
        pool=normalize_address(str(receipt_value.get("pool") or "")),
        input_tokens=_strict_payload_uint(receipt_value.get("input_tokens"), "input_tokens"),
        output_tokens=_strict_payload_uint(receipt_value.get("output_tokens"), "output_tokens"),
        deadline=_strict_payload_uint(receipt_value.get("deadline"), "deadline", positive=True),
    )
    expected = build_runtime_v3_receipt(
        reservation_id=receipt.reservation_id,
        request_hash=receipt.request_hash,
        response_hash=receipt.response_hash,
        channel_hash=receipt.channel_hash,
        pricing_version=receipt.pricing_version,
        pricing_hash=receipt.pricing_hash,
        consumer=receipt.consumer,
        provider=receipt.provider,
        relay=receipt.relay,
        pool=receipt.pool,
        input_tokens=receipt.input_tokens,
        output_tokens=receipt.output_tokens,
        deadline=receipt.deadline,
    )
    if receipt.receipt_hash != expected.receipt_hash:
        raise ChainError("Provider V3 settlement receipt_hash mismatch")
    if receipt.accepted_hash != expected.accepted_hash:
        raise ChainError("Provider V3 settlement accepted_hash mismatch")
    digest = receipt_digest(
        receipt,
        chain_id=chain_id,
        verifying_contract=settlement_contract,
    )
    supplied_digest = _nonzero_bytes32(payload.get("receipt_digest"), "receipt_digest")
    if supplied_digest != "0x" + digest.hex():
        raise ChainError("Provider V3 settlement receipt_digest mismatch")
    signature = _payload_signature(payload.get("provider_signature"))
    if recover_evm_address(digest, signature) != receipt.provider:
        raise ChainError("Provider V3 settlement signature does not recover receipt provider")
    return receipt


def _runtime_receipt_hash(
    *,
    reservation_id: str,
    request_hash: str,
    response_hash: str,
    channel_hash: str,
    pricing_version: int,
    pricing_hash: str,
    consumer: str,
    provider: str,
    relay: str,
    pool: str,
    input_tokens: int,
    output_tokens: int,
    deadline: int,
) -> str:
    encoded = b"".join(
        [
            keccak256(V3_RECEIPT_COMMITMENT_TYPE.encode("utf-8")),
            abi_encode_arg(reservation_id),
            abi_encode_arg(request_hash),
            abi_encode_arg(response_hash),
            abi_encode_arg(channel_hash),
            abi_encode_arg(str(pricing_version)),
            abi_encode_arg(pricing_hash),
            abi_encode_arg(consumer),
            abi_encode_arg(provider),
            abi_encode_arg(relay),
            abi_encode_arg(pool),
            abi_encode_arg(str(input_tokens)),
            abi_encode_arg(str(output_tokens)),
            abi_encode_arg(str(deadline)),
        ]
    )
    value = "0x" + keccak256(encoded).hex()
    return _nonzero_bytes32(value, "receipt_hash")


def _runtime_acceptance_hash(
    *,
    receipt_hash: str,
    reservation_id: str,
    consumer: str,
    provider: str,
) -> str:
    encoded = b"".join(
        [
            keccak256(V3_ACCEPTANCE_COMMITMENT_TYPE.encode("utf-8")),
            abi_encode_arg(receipt_hash),
            abi_encode_arg(reservation_id),
            abi_encode_arg(consumer),
            abi_encode_arg(provider),
        ]
    )
    value = "0x" + keccak256(encoded).hex()
    return _nonzero_bytes32(value, "accepted_hash")


def _payload_signature(value: Any) -> EvmSignature:
    raw = str(value or "")
    if not raw.startswith("0x") or len(raw) != 132 or re.fullmatch(r"0x[0-9a-fA-F]{130}", raw) is None:
        raise ChainError("provider_signature must be a 65-byte hex signature")
    encoded = bytes.fromhex(raw[2:])
    v = int(encoded[64])
    if v not in {0, 1, 27, 28}:
        raise ChainError("provider_signature v must be 0, 1, 27 or 28")
    s = int.from_bytes(encoded[32:64], "big")
    if s <= 0 or s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0:
        raise ChainError("provider_signature has a non-canonical s value")
    return EvmSignature(
        r="0x" + encoded[:32].hex(),
        s="0x" + encoded[32:64].hex(),
        v=v,
    )


def _strict_payload_uint(value: Any, label: str, *, bits: int = 256, positive: bool = False) -> int:
    if type(value) is not int:
        raise ChainError(f"{label} must be an integer")
    minimum = 1 if positive else 0
    if value < minimum or value > (1 << bits) - 1:
        requirement = "positive" if positive else "non-negative"
        raise ChainError(f"{label} must be a {requirement} uint{bits}")
    return value


def _nonzero_bytes32(value: Any, label: str) -> str:
    normalized = _bytes32(value, label)
    if int(normalized[2:], 16) == 0:
        raise ChainError(f"{label} must be non-zero")
    return normalized


def _nonzero_address(value: Any, label: str) -> str:
    normalized = normalize_address(str(value or ""))
    if normalized == ZERO_ADDRESS:
        raise ChainError(f"{label} must be non-zero")
    return normalized



def encode_settle_signed_receipt(input_value: V3SignedReceiptInput) -> str:
    _validate_signature_bytes(input_value.consumer_signature, "consumer")
    _validate_signature_bytes(input_value.provider_signature, "provider")
    receipt_words = b"".join(abi_encode_arg(value) for value in input_value.receipt.abi_args())
    tuple_head_size = (len(input_value.receipt.abi_args()) + 2) * 32
    consumer_tail = _dynamic_bytes(input_value.consumer_signature)
    provider_tail = _dynamic_bytes(input_value.provider_signature)
    tuple_value = b"".join(
        [
            receipt_words,
            tuple_head_size.to_bytes(32, "big"),
            (tuple_head_size + len(consumer_tail)).to_bytes(32, "big"),
            consumer_tail,
            provider_tail,
        ]
    )
    selector = keccak256(SETTLE_SIGNED_V3_SIGNATURE.encode("utf-8"))[:4]
    return "0x" + (selector + (32).to_bytes(32, "big") + tuple_value).hex()


def encode_settle_provider_fallback(receipt: V3ReceiptInput, provider_signature: bytes) -> str:
    _validate_signature_bytes(provider_signature, "provider")
    receipt_words = b"".join(abi_encode_arg(value) for value in receipt.abi_args())
    signature_tail = _dynamic_bytes(provider_signature)
    signature_offset = (len(receipt.abi_args()) + 1) * 32
    selector = keccak256(SETTLE_PROVIDER_FALLBACK_V3_SIGNATURE.encode("utf-8"))[:4]
    return "0x" + (selector + receipt_words + signature_offset.to_bytes(32, "big") + signature_tail).hex()


def verify_eip1271_signature(
    *,
    rpc_url: str,
    signer: str,
    digest: bytes,
    signature: bytes,
    caller: str,
    timeout: float = 20.0,
) -> None:
    try:
        normalized_signer = normalize_address(signer)
    except ChainError as exc:
        raise EIP1271SignatureRejected(str(exc)) from exc
    normalized_caller = normalize_address(caller)
    if len(digest) != 32:
        raise EIP1271SignatureRejected("EIP-1271 digest must be exactly 32 bytes")
    try:
        _validate_signature_bytes(signature, "contract wallet")
    except ChainError as exc:
        raise EIP1271SignatureRejected(str(exc)) from exc
    deadline = time.monotonic() + float(timeout)
    code = rpc_call(rpc_url, "eth_getCode", [normalized_signer, "latest"], timeout)
    if not isinstance(code, str) or not code.startswith("0x"):
        raise EIP1271SignatureRejected(f"unexpected eth_getCode response: {code!r}")
    encoded_code = code[2:]
    if len(encoded_code) % 2 or re.fullmatch(r"[0-9a-fA-F]*", encoded_code) is None:
        raise EIP1271SignatureRejected(f"unexpected eth_getCode response: {code!r}")
    code_bytes = bytes.fromhex(encoded_code)
    if not code_bytes or not any(code_bytes):
        raise EIP1271SignatureRejected("EIP-1271 signer address has no contract code")

    selector = keccak256(b"isValidSignature(bytes32,bytes)")[:4]
    calldata = b"".join(
        [
            selector,
            digest,
            (64).to_bytes(32, "big"),
            _dynamic_bytes(signature),
        ]
    )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ChainError("EIP-1271 RPC deadline exceeded")
    result = rpc_call(
        rpc_url,
        "eth_call",
        [
            {
                "from": normalized_caller,
                "to": normalized_signer,
                "data": "0x" + calldata.hex(),
            },
            "latest",
        ],
        remaining,
    )
    if not isinstance(result, str) or not result.lower().startswith("0x"):
        raise EIP1271SignatureRejected("contract wallet rejected the EIP-1271 signature")
    encoded_result = result[2:]
    try:
        return_data = bytes.fromhex(encoded_result)
    except ValueError as exc:
        raise EIP1271SignatureRejected("contract wallet rejected the EIP-1271 signature") from exc
    if len(encoded_result) != len(return_data) * 2 or len(return_data) < 32:
        raise EIP1271SignatureRejected("contract wallet rejected the EIP-1271 signature")
    if return_data[:4] != bytes.fromhex(EIP1271_MAGIC_VALUE[2:]):
        raise EIP1271SignatureRejected("contract wallet rejected the EIP-1271 signature")


def _verify_receipt_provider_attestation(receipt: dict[str, Any], args: V3ReceiptInput) -> None:
    pricing = receipt.get("pricing") if isinstance(receipt.get("pricing"), dict) else {}
    try:
        verify_provider_settlement_attestation(
            receipt.get("provider_settlement_attestation"),
            provider_public_key=str(receipt.get("provider_public_key") or ""),
            consumer_public_key=str(receipt.get("consumer_public_key") or ""),
            expected={
                "request_id": str(receipt.get("job_id") or ""),
                "request_hash": str(receipt.get("request_hash") or ""),
                "response_hash": str(receipt.get("response_hash") or ""),
                "channel": str(receipt.get("channel") or ""),
                "model": str(receipt.get("model") or ""),
                "endpoint": str(receipt.get("endpoint") or ""),
                "input_tokens": args.input_tokens,
                "output_tokens": args.output_tokens,
                "gross_fee_units": stablecoin_amount(str(pricing.get("gross_fee") or "0")),
                "consumer_payment_address": args.consumer,
                "provider_payment_address": args.provider,
                "pricing_hash": args.pricing_hash,
                "settlement_version": 3,
                "pricing_version": args.pricing_version,
                "onchain_reservation_id": args.reservation_id,
                "settlement_deadline": args.deadline,
            },
        )
    except AttestationError as exc:
        raise ChainError(str(exc)) from exc


def _dynamic_bytes(value: bytes) -> bytes:
    padding = (-len(value)) % 32
    return len(value).to_bytes(32, "big") + value + (b"\x00" * padding)


def _validate_signature_bytes(value: bytes, label: str) -> None:
    if not isinstance(value, bytes) or not value:
        raise ChainError(f"{label} signature must be non-empty bytes")
    if len(value) > MAX_EIP1271_SIGNATURE_BYTES:
        raise ChainError(f"{label} signature exceeds {MAX_EIP1271_SIGNATURE_BYTES} bytes")


def _bytes32(value: Any, label: str) -> str:
    text = str(value or "")
    if not text.startswith("0x") and len(text) == 64:
        text = "0x" + text
    if not BYTES32_PATTERN.fullmatch(text):
        raise ChainError(f"{label} must be bytes32")
    return normalize_bytes32(text)


def _uint(value: int, label: str) -> int:
    parsed = int(value)
    if parsed < 0 or parsed > (1 << 256) - 1:
        raise ChainError(f"{label} must fit uint256")
    return parsed


def _uint64(value: int, label: str, *, positive: bool = False) -> int:
    parsed = int(value)
    if parsed < (1 if positive else 0) or parsed > (1 << 64) - 1:
        requirement = "a positive uint64" if positive else "uint64"
        raise ChainError(f"{label} must be {requirement}")
    return parsed


def _positive_int(value: Any, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ChainError(f"{label} must be an integer") from exc
    if parsed <= 0:
        raise ChainError(f"{label} must be positive")
    return parsed


def _non_negative_int(value: Any, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ChainError(f"{label} must be an integer") from exc
    if parsed < 0:
        raise ChainError(f"{label} must be non-negative")
    return parsed
