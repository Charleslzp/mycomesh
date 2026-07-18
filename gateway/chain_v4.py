from __future__ import annotations

"""Small, dependency-free helpers for the MycoMesh Settlement V4 session escrow.

The V4 contract intentionally lives beside the existing V3 implementation.  A
V4 receipt is request-bound and signed by the short-lived session key and the
Provider EVM key; any funded relayer may submit it.
"""

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .chain import (
    BYTES32_PATTERN,
    DEFAULT_CHANNEL_HASH,
    SEPOLIA_CHAIN_ID,
    ZERO_ADDRESS,
    ChainError,
    abi_encode_arg,
    channel_to_hash,
    deploy_contract_transaction,
    keccak256,
    load_artifact_bytecode,
    normalize_address,
    normalize_bytes32,
    parse_private_key,
    private_key_to_address,
    recover_evm_address,
    run_tool,
    send_contract_data_transaction,
    reward_token_amount,
    sign_evm_digest,
    stablecoin_amount,
)
from .pricing import DEFAULT_CHANNEL
from .channel_policy import CODEX_BACKEND_POLICY, CODEX_CHANNEL_ID, MYCOMESH_TESTNET_NETWORK_ID


MYCO_V4_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
MYCO_V4_SESSION_RECEIPT_TYPE = (
    "SessionReceipt(bytes32 receiptHash,bytes32 acceptedHash,bytes32 sessionId,bytes32 requestHash,"
    "bytes32 responseHash,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,address consumer,"
    "address provider,address relay,address pool,uint256 inputTokens,uint256 outputTokens,uint256 sequence,"
    "uint256 quotedFee,uint256 deadline)"
)
MYCO_V4_DEPLOYER_ARTIFACT = "out/MycoSettlementV4.sol/MycoSettlementV4.json"
DEFAULT_MYCO_V4_DEPLOYMENT_PATH = "deployments/sepolia-myco-v4.json"
V4_SESSION_RECEIPT_SIGNATURE = (
    "settleSignedReceipt(((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,"
    "address,address,uint256,uint256,uint256,uint256,uint256),bytes,bytes))"
)
V4_SETTLEMENT_SCHEMA = "mycomesh.settlement.v4.provider.v1"
V4_RECEIPT_FIELDS = frozenset(
    {
        "receipt_hash",
        "accepted_hash",
        "session_id",
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
        "sequence",
        "quoted_fee",
        "deadline",
    }
)
V4_PAYLOAD_FIELDS = frozenset(
    {"schema", "chain_id", "settlement_contract", "receipt", "receipt_digest", "provider_signature"}
)


@dataclass(frozen=True)
class V4Deployment:
    protocol_version: int
    chain_id: int
    deployer: str
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
    eip712_version: str = "4"
    tx_hash: str | None = None
    deployment_block: int | None = None
    network_id: str = MYCOMESH_TESTNET_NETWORK_ID
    channel_id: str = CODEX_CHANNEL_ID
    backend_policy: str = CODEX_BACKEND_POLICY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class V4SessionReceipt:
    receipt_hash: str
    accepted_hash: str
    session_id: str
    request_hash: str
    response_hash: str
    channel: str
    pricing_version: int
    pricing_hash: str
    consumer: str
    provider: str
    relay: str
    pool: str
    input_tokens: int
    output_tokens: int
    sequence: int
    quoted_fee: int
    deadline: int

    def abi_args(self) -> list[str]:
        return [
            self.receipt_hash,
            self.accepted_hash,
            self.session_id,
            self.request_hash,
            self.response_hash,
            self.channel,
            str(self.pricing_version),
            self.pricing_hash,
            self.consumer,
            self.provider,
            self.relay,
            self.pool,
            str(self.input_tokens),
            str(self.output_tokens),
            str(self.sequence),
            str(self.quoted_fee),
            str(self.deadline),
        ]

    def to_payload(self) -> dict[str, Any]:
        return {
            "receipt_hash": self.receipt_hash,
            "accepted_hash": self.accepted_hash,
            "session_id": self.session_id,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "channel": self.channel,
            "pricing_version": self.pricing_version,
            "pricing_hash": self.pricing_hash,
            "consumer": self.consumer,
            "provider": self.provider,
            "relay": self.relay,
            "pool": self.pool,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "sequence": self.sequence,
            "quoted_fee": self.quoted_fee,
            "deadline": self.deadline,
        }


def default_pricing_hash(treasury: str) -> str:
    """Return the V4 version-1 hash for the canonical Codex test channel."""
    values = [
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
    return "0x" + keccak256(b"".join(abi_encode_arg(value) for value in values)).hex()


def domain_separator(*, chain_id: int, verifying_contract: str) -> str:
    encoded = b"".join(
        [
            keccak256(MYCO_V4_DOMAIN_TYPE.encode("utf-8")),
            keccak256(b"MycoMesh Settlement"),
            keccak256(b"4"),
            abi_encode_arg(str(_positive_uint(chain_id, "chain_id"))),
            abi_encode_arg(normalize_address(verifying_contract)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def session_receipt_typehash() -> str:
    return "0x" + keccak256(MYCO_V4_SESSION_RECEIPT_TYPE.encode("utf-8")).hex()


def session_receipt_struct_hash(receipt: V4SessionReceipt) -> str:
    return "0x" + keccak256(
        bytes.fromhex(session_receipt_typehash()[2:])
        + b"".join(abi_encode_arg(value) for value in receipt.abi_args())
    ).hex()


def session_receipt_digest(receipt: V4SessionReceipt, *, chain_id: int, verifying_contract: str) -> bytes:
    domain = domain_separator(chain_id=chain_id, verifying_contract=verifying_contract)
    struct_hash = session_receipt_struct_hash(receipt)
    return keccak256(b"\x19\x01" + bytes.fromhex(domain[2:]) + bytes.fromhex(struct_hash[2:]))


def build_runtime_session_receipt(
    *,
    session_id: str,
    request_hash: str,
    response_hash: str,
    channel_hash: str,
    pricing_version: int,
    pricing_hash: str,
    consumer: str,
    provider: str,
    input_tokens: int,
    output_tokens: int,
    sequence: int,
    quoted_fee: int,
    deadline: int,
    relay: str = ZERO_ADDRESS,
    pool: str = ZERO_ADDRESS,
) -> V4SessionReceipt:
    values = {
        "session_id": _nonzero_bytes32(session_id, "session_id"),
        "request_hash": _nonzero_bytes32(request_hash, "request_hash"),
        "response_hash": _nonzero_bytes32(response_hash, "response_hash"),
        "channel": _nonzero_bytes32(channel_hash, "channel"),
        "pricing_version": _positive_uint(pricing_version, "pricing_version", bits=64),
        "pricing_hash": _nonzero_bytes32(pricing_hash, "pricing_hash"),
        "consumer": _nonzero_address(consumer, "consumer"),
        "provider": _nonzero_address(provider, "provider"),
        "relay": normalize_address(relay),
        "pool": normalize_address(pool),
        "input_tokens": _uint(input_tokens, "input_tokens"),
        "output_tokens": _uint(output_tokens, "output_tokens"),
        "sequence": _uint(sequence, "sequence"),
        "quoted_fee": _positive_uint(quoted_fee, "quoted_fee"),
        "deadline": _positive_uint(deadline, "deadline"),
    }
    if values["consumer"] == values["provider"]:
        raise ChainError("V4 consumer and provider must differ")
    receipt_hash = _runtime_receipt_hash(values)
    accepted_hash = _runtime_acceptance_hash(
        receipt_hash=receipt_hash,
        session_id=values["session_id"],
        consumer=values["consumer"],
        provider=values["provider"],
    )
    return V4SessionReceipt(receipt_hash=receipt_hash, accepted_hash=accepted_hash, **values)


def build_provider_settlement_payload(
    *,
    provider_private_key: str,
    chain_id: int,
    settlement_contract: str,
    session_id: str,
    request_hash: str,
    response_hash: str,
    channel_hash: str,
    pricing_version: int,
    pricing_hash: str,
    consumer: str,
    provider: str,
    input_tokens: int,
    output_tokens: int,
    sequence: int,
    quoted_fee: int,
    deadline: int,
    relay: str = ZERO_ADDRESS,
    pool: str = ZERO_ADDRESS,
) -> dict[str, Any]:
    normalized_chain = _positive_uint(chain_id, "chain_id")
    contract = _nonzero_address(settlement_contract, "settlement_contract")
    receipt = build_runtime_session_receipt(
        session_id=session_id,
        request_hash=request_hash,
        response_hash=response_hash,
        channel_hash=channel_hash,
        pricing_version=pricing_version,
        pricing_hash=pricing_hash,
        consumer=consumer,
        provider=provider,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        sequence=sequence,
        quoted_fee=quoted_fee,
        deadline=deadline,
        relay=relay,
        pool=pool,
    )
    signer = private_key_to_address(parse_private_key(provider_private_key))
    if signer != normalize_address(receipt.provider):
        raise ChainError("Provider EVM identity does not match receipt provider")
    digest = session_receipt_digest(receipt, chain_id=normalized_chain, verifying_contract=contract)
    signature = _signature_bytes(sign_evm_digest(provider_private_key, digest), "provider")
    return {
        "schema": V4_SETTLEMENT_SCHEMA,
        "chain_id": normalized_chain,
        "settlement_contract": contract,
        "receipt": receipt.to_payload(),
        "receipt_digest": "0x" + digest.hex(),
        "provider_signature": "0x" + signature.hex(),
    }


def sign_session_receipt_digest(
    private_key: str,
    receipt: V4SessionReceipt,
    *,
    chain_id: int,
    verifying_contract: str,
) -> bytes:
    """Sign the contract's EIP-712 V4 receipt digest.

    The Provider signs the same digest in ``build_provider_settlement_payload``.
    A Gateway/relayer uses this helper for the independent session-key
    signature; keeping it here prevents accidentally using the transport
    protocol's EIP-191 receipt digest for an on-chain settlement.
    """
    signer = private_key_to_address(parse_private_key(private_key))
    # The contract does not require the session key to be the consumer wallet,
    # so callers must separately bind this signature to the session record.
    if signer == ZERO_ADDRESS:
        raise ChainError("session receipt signer cannot be the zero address")
    digest = session_receipt_digest(
        receipt,
        chain_id=_positive_uint(chain_id, "chain_id"),
        verifying_contract=verifying_contract,
    )
    return _signature_bytes(sign_evm_digest(private_key, digest), "session")


def verify_provider_settlement_payload(payload: Any) -> V4SessionReceipt:
    if not isinstance(payload, dict) or set(payload) != V4_PAYLOAD_FIELDS:
        raise ChainError("Provider V4 settlement payload fields are invalid")
    if payload.get("schema") != V4_SETTLEMENT_SCHEMA:
        raise ChainError("unsupported Provider V4 settlement payload schema")
    chain_id = _positive_uint(payload.get("chain_id"), "chain_id")
    contract = _nonzero_address(payload.get("settlement_contract"), "settlement_contract")
    raw = payload.get("receipt")
    if not isinstance(raw, dict) or set(raw) != V4_RECEIPT_FIELDS:
        raise ChainError("Provider V4 settlement receipt fields are invalid")
    receipt = V4SessionReceipt(
        receipt_hash=_nonzero_bytes32(raw.get("receipt_hash"), "receipt_hash"),
        accepted_hash=_nonzero_bytes32(raw.get("accepted_hash"), "accepted_hash"),
        session_id=_nonzero_bytes32(raw.get("session_id"), "session_id"),
        request_hash=_nonzero_bytes32(raw.get("request_hash"), "request_hash"),
        response_hash=_nonzero_bytes32(raw.get("response_hash"), "response_hash"),
        channel=_nonzero_bytes32(raw.get("channel"), "channel"),
        pricing_version=_positive_uint(raw.get("pricing_version"), "pricing_version", bits=64),
        pricing_hash=_nonzero_bytes32(raw.get("pricing_hash"), "pricing_hash"),
        consumer=_nonzero_address(raw.get("consumer"), "consumer"),
        provider=_nonzero_address(raw.get("provider"), "provider"),
        relay=normalize_address(str(raw.get("relay") or "")),
        pool=normalize_address(str(raw.get("pool") or "")),
        input_tokens=_uint(raw.get("input_tokens"), "input_tokens"),
        output_tokens=_uint(raw.get("output_tokens"), "output_tokens"),
        sequence=_uint(raw.get("sequence"), "sequence"),
        quoted_fee=_positive_uint(raw.get("quoted_fee"), "quoted_fee"),
        deadline=_positive_uint(raw.get("deadline"), "deadline"),
    )
    expected = build_runtime_session_receipt(
        session_id=receipt.session_id,
        request_hash=receipt.request_hash,
        response_hash=receipt.response_hash,
        channel_hash=receipt.channel,
        pricing_version=receipt.pricing_version,
        pricing_hash=receipt.pricing_hash,
        consumer=receipt.consumer,
        provider=receipt.provider,
        relay=receipt.relay,
        pool=receipt.pool,
        input_tokens=receipt.input_tokens,
        output_tokens=receipt.output_tokens,
        sequence=receipt.sequence,
        quoted_fee=receipt.quoted_fee,
        deadline=receipt.deadline,
    )
    if receipt.receipt_hash != expected.receipt_hash or receipt.accepted_hash != expected.accepted_hash:
        raise ChainError("Provider V4 settlement receipt commitment mismatch")
    digest = session_receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    supplied = _nonzero_bytes32(payload.get("receipt_digest"), "receipt_digest")
    if supplied != "0x" + digest.hex():
        raise ChainError("Provider V4 settlement receipt_digest mismatch")
    signature = _parse_signature(payload.get("provider_signature"), "provider")
    if recover_evm_address(digest, signature) != receipt.provider:
        raise ChainError("Provider V4 settlement signature does not recover receipt provider")
    return receipt


def encode_settle_signed_receipt(receipt: V4SessionReceipt, session_key_signature: bytes, provider_signature: bytes) -> str:
    _validate_raw_signature(session_key_signature, "session key")
    _validate_raw_signature(provider_signature, "provider")
    receipt_words = b"".join(abi_encode_arg(value) for value in receipt.abi_args())
    tuple_head_size = (len(receipt.abi_args()) + 2) * 32
    session_tail = _dynamic_bytes(session_key_signature)
    provider_tail = _dynamic_bytes(provider_signature)
    tuple_value = b"".join(
        [
            receipt_words,
            tuple_head_size.to_bytes(32, "big"),
            (tuple_head_size + len(session_tail)).to_bytes(32, "big"),
            session_tail,
            provider_tail,
        ]
    )
    selector = keccak256(V4_SESSION_RECEIPT_SIGNATURE.encode("utf-8"))[:4]
    return "0x" + (selector + (32).to_bytes(32, "big") + tuple_value).hex()


def deploy_testnet(
    *,
    rpc_url: str,
    private_key: str,
    stablecoin: str,
    reward_token: str,
    treasury: str,
    governance: str,
    max_consumer_rebate_bps: int = 1_000,
    max_supply_myco: str = "1000000000",
    chain_id: int = SEPOLIA_CHAIN_ID,
    artifact: str = MYCO_V4_DEPLOYER_ARTIFACT,
    timeout: float = 300.0,
) -> V4Deployment:
    """Deploy the standalone V4 contract using existing V3 token addresses."""
    if not Path(artifact).exists():
        run_tool(["forge", "build"], timeout=timeout)
    bytecode = load_artifact_bytecode(Path(artifact))
    config = [
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
    constructor_args = b"".join(
        [
            abi_encode_arg(normalize_address(stablecoin)),
            abi_encode_arg(normalize_address(reward_token)),
            abi_encode_arg(normalize_address(treasury)),
            abi_encode_arg(normalize_address(governance)),
            abi_encode_arg(str(int(max_consumer_rebate_bps))),
            abi_encode_arg(DEFAULT_CHANNEL_HASH),
            *[abi_encode_arg(item) for item in config],
        ]
    )
    settlement, tx_hash = deploy_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        bytecode=bytecode + constructor_args,
        timeout=timeout,
    )
    deployer = private_key_to_address(parse_private_key(private_key))
    pricing_hash = default_pricing_hash(treasury)
    return V4Deployment(
        protocol_version=4,
        chain_id=chain_id,
        deployer=deployer,
        stablecoin=normalize_address(stablecoin),
        settlement=settlement,
        token=normalize_address(reward_token),
        treasury=normalize_address(treasury),
        governance=normalize_address(governance),
        max_consumer_rebate_bps=int(max_consumer_rebate_bps),
        max_supply=reward_token_amount(max_supply_myco),
        channel=DEFAULT_CHANNEL,
        channel_hash=DEFAULT_CHANNEL_HASH,
        pricing_version=1,
        pricing_hash=pricing_hash,
        tx_hash=tx_hash,
    )


def save_deployment(path: Path, deployment: V4Deployment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(deployment.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_deployment(path: Path = Path(DEFAULT_MYCO_V4_DEPLOYMENT_PATH)) -> V4Deployment:
    if not path.exists():
        raise ChainError(f"Myco V4 deployment not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ChainError("Myco V4 deployment must be a JSON object")
    required = {
        "protocol_version", "chain_id", "deployer", "stablecoin", "settlement", "token", "treasury",
        "governance", "max_consumer_rebate_bps", "max_supply", "channel", "channel_hash", "pricing_version",
        "pricing_hash",
    }
    missing = sorted(field for field in required if field not in payload)
    if missing:
        raise ChainError("Myco V4 deployment is missing required fields: " + ", ".join(missing))
    if int(payload["protocol_version"]) != 4:
        raise ChainError("deployment is not a Myco Settlement V4 deployment")
    return V4Deployment(
        protocol_version=4,
        chain_id=_positive_uint(payload["chain_id"], "chain_id"),
        deployer=_nonzero_address(payload["deployer"], "deployer"),
        stablecoin=_nonzero_address(payload["stablecoin"], "stablecoin"),
        settlement=_nonzero_address(payload["settlement"], "settlement"),
        token=_nonzero_address(payload["token"], "token"),
        treasury=_nonzero_address(payload["treasury"], "treasury"),
        governance=_nonzero_address(payload["governance"], "governance"),
        max_consumer_rebate_bps=_positive_uint(payload["max_consumer_rebate_bps"], "max_consumer_rebate_bps"),
        max_supply=_positive_uint(payload["max_supply"], "max_supply"),
        channel=str(payload["channel"]),
        channel_hash=_nonzero_bytes32(payload["channel_hash"], "channel_hash"),
        pricing_version=_positive_uint(payload["pricing_version"], "pricing_version", bits=64),
        pricing_hash=_nonzero_bytes32(payload["pricing_hash"], "pricing_hash"),
        eip712_name=str(payload.get("eip712_name") or "MycoMesh Settlement"),
        eip712_version=str(payload.get("eip712_version") or "4"),
        tx_hash=payload.get("tx_hash"),
        deployment_block=payload.get("deployment_block"),
        network_id=str(payload.get("network_id") or MYCOMESH_TESTNET_NETWORK_ID),
        channel_id=str(payload.get("channel_id") or CODEX_CHANNEL_ID),
        backend_policy=str(payload.get("backend_policy") or CODEX_BACKEND_POLICY),
    )


def _runtime_receipt_hash(values: dict[str, Any]) -> str:
    commitment = (
        "MycoMeshV4SessionReceipt(bytes32 sessionId,bytes32 requestHash,bytes32 responseHash,bytes32 channel,"
        "uint64 pricingVersion,bytes32 pricingHash,address consumer,address provider,address relay,address pool,"
        "uint256 inputTokens,uint256 outputTokens,uint256 sequence,uint256 quotedFee,uint256 deadline)"
    )
    encoded = b"".join(
        [keccak256(commitment.encode("utf-8"))]
        + [abi_encode_arg(str(values[key])) for key in (
            "session_id", "request_hash", "response_hash", "channel", "pricing_version", "pricing_hash",
            "consumer", "provider", "relay", "pool", "input_tokens", "output_tokens", "sequence",
            "quoted_fee", "deadline",
        )]
    )
    return _nonzero_bytes32("0x" + keccak256(encoded).hex(), "receipt_hash")


def _runtime_acceptance_hash(*, receipt_hash: str, session_id: str, consumer: str, provider: str) -> str:
    commitment = "MycoMeshV4ConsumerAcceptance(bytes32 receiptHash,bytes32 sessionId,address consumer,address provider)"
    encoded = b"".join(
        [keccak256(commitment.encode("utf-8")), abi_encode_arg(receipt_hash), abi_encode_arg(session_id), abi_encode_arg(consumer), abi_encode_arg(provider)]
    )
    return _nonzero_bytes32("0x" + keccak256(encoded).hex(), "accepted_hash")


def _dynamic_bytes(value: bytes) -> bytes:
    padded = (len(value) + 31) // 32 * 32
    return len(value).to_bytes(32, "big") + value.ljust(padded, b"\x00")


def _validate_raw_signature(value: bytes, label: str) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 65:
        raise ChainError(f"{label} signature must be 65 bytes")


def _signature_bytes(signature: Any, label: str) -> bytes:
    raw = bytes.fromhex(normalize_bytes32(signature.r)[2:] + normalize_bytes32(signature.s)[2:]) + bytes([int(signature.v)])
    _validate_raw_signature(raw, label)
    return raw


def _parse_signature(value: Any, label: str) -> Any:
    from .chain import EvmSignature

    raw = str(value or "")
    if not re.fullmatch(r"0x[0-9a-fA-F]{130}", raw):
        raise ChainError(f"{label} signature must be 65-byte hex")
    return EvmSignature(r="0x" + raw[2:66], s="0x" + raw[66:130], v=int(raw[130:132], 16))


def _positive_uint(value: Any, label: str, *, bits: int = 256) -> int:
    if isinstance(value, bool):
        raise ChainError(f"{label} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ChainError(f"{label} must be an integer") from exc
    if parsed <= 0 or parsed >= (1 << bits):
        raise ChainError(f"{label} is out of range")
    return parsed


def _uint(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ChainError(f"{label} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ChainError(f"{label} must be an integer") from exc
    if parsed < 0 or parsed >= (1 << 256):
        raise ChainError(f"{label} is out of range")
    return parsed


def _nonzero_bytes32(value: Any, label: str) -> str:
    text = str(value or "")
    if len(text) == 64:
        text = "0x" + text
    if not BYTES32_PATTERN.fullmatch(text) or int(text[2:], 16) == 0:
        raise ChainError(f"{label} must be a non-zero bytes32 value")
    return text.lower()


def _nonzero_address(value: Any, label: str) -> str:
    normalized = normalize_address(str(value or ""))
    if normalized == ZERO_ADDRESS:
        raise ChainError(f"{label} must be non-zero")
    return normalized
