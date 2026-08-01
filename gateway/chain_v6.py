from __future__ import annotations

"""Settlement V6 helpers for immutable routes and Relay attestations."""

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .chain import (
    DEFAULT_CHANNEL_HASH,
    SEPOLIA_CHAIN_ID,
    ZERO_ADDRESS,
    ChainError,
    abi_encode_arg,
    deploy_contract_transaction,
    keccak256,
    load_artifact_bytecode,
    normalize_address,
    parse_private_key,
    private_key_to_address,
    recover_evm_address,
    reward_token_amount,
    run_tool,
    SECP256K1_N,
    sign_evm_digest,
)
from .chain_v4 import (
    _dynamic_bytes,
    _nonzero_address,
    _nonzero_bytes32,
    _optional_bool,
    _parse_signature,
    _positive_uint,
    _signature_bytes,
    _uint,
    _validate_raw_signature,
    default_pricing_hash,
)
from .channel_policy import CODEX_BACKEND_POLICY, CODEX_CHANNEL_ID, MYCOMESH_TESTNET_NETWORK_ID
from .pricing import DEFAULT_CHANNEL


MYCO_V6_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
MYCO_V6_SESSION_RECEIPT_TYPE = (
    "SessionReceipt(bytes32 receiptHash,bytes32 acceptedHash,bytes32 sessionId,bytes32 requestHash,"
    "bytes32 responseHash,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,address consumer,"
    "address provider,address relay,address pool,uint64 relayEpoch,uint256 inputTokens,uint256 outputTokens,uint256 sequence,"
    "uint256 quotedFee,uint256 deadline)"
)
MYCO_V6_RELAY_ATTESTATION_TYPE = (
    "RelayRequestAttestation(bytes32 sessionId,bytes32 requestHash,address provider,address relay,"
    "uint64 relayEpoch,uint256 sequence,uint256 deadline)"
)
MYCO_V6_DEPLOYER_ARTIFACT = "out/MycoSettlementV6.sol/MycoSettlementV6.json"
DEFAULT_MYCO_V6_DEPLOYMENT_PATH = "deployments/sepolia-myco-v6.json"
V6_SESSION_RECEIPT_SIGNATURE = (
    "settleSignedReceipt(((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,"
    "address,address,uint64,uint256,uint256,uint256,uint256,uint256),(bytes32,bytes32,address,address,uint64,uint256,uint256),"
    "bytes,bytes,bytes))"
)
V6_SESSION_RECEIPT_BATCH_SIGNATURE = (
    "settleSignedBatch(((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,address,address,"
    "address,address,uint64,uint256,uint256,uint256,uint256,uint256),(bytes32,bytes32,address,address,uint64,uint256,uint256),"
    "bytes,bytes,bytes)[])"
)
V6_CLAIM_PAYOUT_SIGNATURE = "claim()"
V6_SETTLEMENT_SCHEMA = "mycomesh.settlement.v6.provider.v1"
V6_RELAY_ATTESTATION_SCHEMA = "mycomesh.relay.v6.attestation.v1"
V6_RECEIPT_FIELDS = frozenset(
    {
        "receipt_hash", "accepted_hash", "session_id", "request_hash", "response_hash", "channel",
        "pricing_version", "pricing_hash", "consumer", "provider", "relay", "pool", "input_tokens",
        "relay_epoch", "output_tokens", "sequence", "quoted_fee", "deadline",
    }
)
V6_PAYLOAD_FIELDS = frozenset(
    {"schema", "chain_id", "settlement_contract", "receipt", "receipt_digest", "provider_signature"}
)
V6_RELAY_ATTESTATION_FIELDS = frozenset(
    {
        "schema", "chain_id", "settlement_contract", "session_id", "request_hash", "provider", "relay",
        "relay_epoch", "sequence", "deadline", "signer", "attestation_digest", "signature",
    }
)
SECP256K1_HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


@dataclass(frozen=True)
class V6SessionReceipt:
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
    relay_epoch: int
    input_tokens: int
    output_tokens: int
    sequence: int
    quoted_fee: int
    deadline: int

    def abi_args(self) -> list[str]:
        return [
            self.receipt_hash, self.accepted_hash, self.session_id, self.request_hash, self.response_hash,
            self.channel, str(self.pricing_version), self.pricing_hash, self.consumer, self.provider,
            self.relay, self.pool, str(self.relay_epoch), str(self.input_tokens), str(self.output_tokens),
            str(self.sequence), str(self.quoted_fee), str(self.deadline),
        ]

    def to_payload(self) -> dict[str, Any]:
        return {
            "receipt_hash": self.receipt_hash, "accepted_hash": self.accepted_hash,
            "session_id": self.session_id, "request_hash": self.request_hash,
            "response_hash": self.response_hash, "channel": self.channel,
            "pricing_version": self.pricing_version, "pricing_hash": self.pricing_hash,
            "consumer": self.consumer, "provider": self.provider, "relay": self.relay,
            "pool": self.pool, "relay_epoch": self.relay_epoch, "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens, "sequence": self.sequence,
            "quoted_fee": self.quoted_fee, "deadline": self.deadline,
        }


@dataclass(frozen=True)
class V6Deployment:
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
    eip712_version: str = "6"
    tx_hash: str | None = None
    deployment_block: int | None = None
    network_id: str = MYCOMESH_TESTNET_NETWORK_ID
    channel_id: str = CODEX_CHANNEL_ID
    backend_policy: str = CODEX_BACKEND_POLICY
    pull_payments_enabled: bool = True
    immutable_routes_enabled: bool = True
    relay_attestations_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def domain_separator(*, chain_id: int, verifying_contract: str) -> str:
    encoded = b"".join(
        [
            keccak256(MYCO_V6_DOMAIN_TYPE.encode("utf-8")),
            keccak256(b"MycoMesh Settlement"),
            keccak256(b"6"),
            abi_encode_arg(str(_positive_uint(chain_id, "chain_id"))),
            abi_encode_arg(normalize_address(verifying_contract)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def session_receipt_typehash() -> str:
    return "0x" + keccak256(MYCO_V6_SESSION_RECEIPT_TYPE.encode("utf-8")).hex()


def relay_attestation_typehash() -> str:
    return "0x" + keccak256(MYCO_V6_RELAY_ATTESTATION_TYPE.encode("utf-8")).hex()


def session_receipt_struct_hash(receipt: V6SessionReceipt) -> str:
    return "0x" + keccak256(
        bytes.fromhex(session_receipt_typehash()[2:])
        + b"".join(abi_encode_arg(value) for value in receipt.abi_args())
    ).hex()


def session_receipt_digest(receipt: V6SessionReceipt, *, chain_id: int, verifying_contract: str) -> bytes:
    return _typed_data_digest(
        session_receipt_struct_hash(receipt),
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )


def relay_attestation_struct_hash(
    *,
    session_id: str,
    request_hash: str,
    provider: str,
    relay: str,
    relay_epoch: int,
    sequence: int,
    deadline: int,
) -> str:
    values = [
        _nonzero_bytes32(session_id, "session_id"),
        _nonzero_bytes32(request_hash, "request_hash"),
        _nonzero_address(provider, "provider"),
        _nonzero_address(relay, "relay"),
        str(_uint64(relay_epoch, "relay_epoch")),
        str(_uint(sequence, "sequence")),
        str(_positive_uint(deadline, "deadline")),
    ]
    return "0x" + keccak256(
        bytes.fromhex(relay_attestation_typehash()[2:])
        + b"".join(abi_encode_arg(value) for value in values)
    ).hex()


def relay_attestation_digest(
    *,
    chain_id: int,
    verifying_contract: str,
    session_id: str,
    request_hash: str,
    provider: str,
    relay: str,
    relay_epoch: int,
    sequence: int,
    deadline: int,
) -> bytes:
    struct_hash = relay_attestation_struct_hash(
        session_id=session_id,
        request_hash=request_hash,
        provider=provider,
        relay=relay,
        relay_epoch=relay_epoch,
        sequence=sequence,
        deadline=deadline,
    )
    return _typed_data_digest(
        struct_hash,
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )


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
    relay_epoch: int = 0,
) -> V6SessionReceipt:
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
        "relay_epoch": _uint64(relay_epoch, "relay_epoch"),
        "input_tokens": _uint(input_tokens, "input_tokens"),
        "output_tokens": _uint(output_tokens, "output_tokens"),
        "sequence": _uint(sequence, "sequence"),
        "quoted_fee": _positive_uint(quoted_fee, "quoted_fee"),
        "deadline": _positive_uint(deadline, "deadline"),
    }
    if values["consumer"] == values["provider"]:
        raise ChainError("V6 consumer and provider must differ")
    receipt_hash = _runtime_receipt_hash(values)
    accepted_hash = _runtime_acceptance_hash(
        receipt_hash=receipt_hash,
        session_id=values["session_id"],
        consumer=values["consumer"],
        provider=values["provider"],
    )
    return V6SessionReceipt(receipt_hash=receipt_hash, accepted_hash=accepted_hash, **values)


def build_provider_settlement_payload(*, provider_private_key: str, chain_id: int, settlement_contract: str, **values: Any) -> dict[str, Any]:
    normalized_chain = _positive_uint(chain_id, "chain_id")
    contract = _nonzero_address(settlement_contract, "settlement_contract")
    receipt = build_runtime_session_receipt(**values)
    signer = private_key_to_address(parse_private_key(provider_private_key))
    if signer != normalize_address(receipt.provider):
        raise ChainError("Provider EVM identity does not match V6 receipt provider")
    digest = session_receipt_digest(receipt, chain_id=normalized_chain, verifying_contract=contract)
    signature = _signature_bytes(sign_evm_digest(provider_private_key, digest), "provider")
    return {
        "schema": V6_SETTLEMENT_SCHEMA,
        "chain_id": normalized_chain,
        "settlement_contract": contract,
        "receipt": receipt.to_payload(),
        "receipt_digest": "0x" + digest.hex(),
        "provider_signature": "0x" + signature.hex(),
    }


def build_relay_attestation(
    *,
    private_key: str,
    chain_id: int,
    settlement_contract: str,
    session_id: str,
    request_hash: str,
    provider: str,
    relay: str,
    relay_epoch: int,
    sequence: int,
    deadline: int,
) -> dict[str, Any]:
    contract = _nonzero_address(settlement_contract, "settlement_contract")
    signer = private_key_to_address(parse_private_key(private_key))
    digest = relay_attestation_digest(
        chain_id=chain_id,
        verifying_contract=contract,
        session_id=session_id,
        request_hash=request_hash,
        provider=provider,
        relay=relay,
        relay_epoch=relay_epoch,
        sequence=sequence,
        deadline=deadline,
    )
    signature = _signature_bytes(sign_evm_digest(private_key, digest), "Relay attestation")
    return {
        "schema": V6_RELAY_ATTESTATION_SCHEMA,
        "chain_id": _positive_uint(chain_id, "chain_id"),
        "settlement_contract": contract,
        "session_id": _nonzero_bytes32(session_id, "session_id"),
        "request_hash": _nonzero_bytes32(request_hash, "request_hash"),
        "provider": _nonzero_address(provider, "provider"),
        "relay": _nonzero_address(relay, "relay"),
        "relay_epoch": _uint64(relay_epoch, "relay_epoch"),
        "sequence": _uint(sequence, "sequence"),
        "deadline": _positive_uint(deadline, "deadline"),
        "signer": signer,
        "attestation_digest": "0x" + digest.hex(),
        "signature": "0x" + signature.hex(),
    }


def verify_relay_attestation(
    value: Any,
    *,
    expected_signer: str,
    receipt: V6SessionReceipt | None = None,
    expected_chain_id: int | None = None,
    expected_contract: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != V6_RELAY_ATTESTATION_FIELDS:
        raise ChainError("Relay V6 attestation fields are invalid")
    if value.get("schema") != V6_RELAY_ATTESTATION_SCHEMA:
        raise ChainError("unsupported Relay V6 attestation schema")
    normalized = {
        "schema": V6_RELAY_ATTESTATION_SCHEMA,
        "chain_id": _positive_uint(value.get("chain_id"), "chain_id"),
        "settlement_contract": _nonzero_address(value.get("settlement_contract"), "settlement_contract"),
        "session_id": _nonzero_bytes32(value.get("session_id"), "session_id"),
        "request_hash": _nonzero_bytes32(value.get("request_hash"), "request_hash"),
        "provider": _nonzero_address(value.get("provider"), "provider"),
        "relay": _nonzero_address(value.get("relay"), "relay"),
        "relay_epoch": _uint64(value.get("relay_epoch"), "relay_epoch"),
        "sequence": _uint(value.get("sequence"), "sequence"),
        "deadline": _positive_uint(value.get("deadline"), "deadline"),
        "signer": _nonzero_address(value.get("signer"), "signer"),
        "attestation_digest": _nonzero_bytes32(value.get("attestation_digest"), "attestation_digest"),
        "signature": str(value.get("signature") or ""),
    }
    signer = _nonzero_address(expected_signer, "expected_signer")
    if normalized["signer"] != signer:
        raise ChainError("Relay V6 attestation signer does not match the session route")
    if expected_chain_id is not None:
        chain_id = _positive_uint(expected_chain_id, "expected_chain_id")
        if normalized["chain_id"] != chain_id:
            raise ChainError("Relay V6 attestation chain_id does not match the deployment")
    if expected_contract is not None:
        contract = _nonzero_address(expected_contract, "expected_contract")
        if normalized["settlement_contract"] != contract:
            raise ChainError("Relay V6 attestation contract does not match the deployment")
    current = int(time.time() if now is None else now)
    if normalized["deadline"] < current:
        raise ChainError("Relay V6 attestation deadline has elapsed")
    digest = relay_attestation_digest(
        chain_id=normalized["chain_id"],
        verifying_contract=normalized["settlement_contract"],
        session_id=normalized["session_id"],
        request_hash=normalized["request_hash"],
        provider=normalized["provider"],
        relay=normalized["relay"],
        relay_epoch=normalized["relay_epoch"],
        sequence=normalized["sequence"],
        deadline=normalized["deadline"],
    )
    if normalized["attestation_digest"] != "0x" + digest.hex():
        raise ChainError("Relay V6 attestation digest mismatch")
    signature = _strict_signature(normalized["signature"], "Relay attestation")
    if recover_evm_address(digest, signature) != signer:
        raise ChainError("Relay V6 attestation signature does not recover the session signer")
    if receipt is not None:
        expected = {
            "session_id": receipt.session_id,
            "request_hash": receipt.request_hash,
            "provider": receipt.provider,
            "relay": receipt.relay,
            "relay_epoch": receipt.relay_epoch,
            "sequence": receipt.sequence,
            "deadline": receipt.deadline,
        }
        for field, expected_value in expected.items():
            actual = normalized[field]
            if str(actual).lower() != str(expected_value).lower():
                raise ChainError(f"Relay V6 attestation {field} does not match the receipt")
    return normalized


def verify_provider_settlement_payload(payload: Any) -> V6SessionReceipt:
    if not isinstance(payload, dict) or set(payload) != V6_PAYLOAD_FIELDS:
        raise ChainError("Provider V6 settlement payload fields are invalid")
    if payload.get("schema") != V6_SETTLEMENT_SCHEMA:
        raise ChainError("unsupported Provider V6 settlement payload schema")
    chain_id = _positive_uint(payload.get("chain_id"), "chain_id")
    contract = _nonzero_address(payload.get("settlement_contract"), "settlement_contract")
    raw = payload.get("receipt")
    if not isinstance(raw, dict) or set(raw) != V6_RECEIPT_FIELDS:
        raise ChainError("Provider V6 settlement receipt fields are invalid")
    receipt = V6SessionReceipt(
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
        relay_epoch=_uint64(raw.get("relay_epoch"), "relay_epoch"),
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
        relay_epoch=receipt.relay_epoch,
        input_tokens=receipt.input_tokens,
        output_tokens=receipt.output_tokens,
        sequence=receipt.sequence,
        quoted_fee=receipt.quoted_fee,
        deadline=receipt.deadline,
    )
    if receipt.receipt_hash != expected.receipt_hash or receipt.accepted_hash != expected.accepted_hash:
        raise ChainError("Provider V6 settlement receipt commitment mismatch")
    digest = session_receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    if _nonzero_bytes32(payload.get("receipt_digest"), "receipt_digest") != "0x" + digest.hex():
        raise ChainError("Provider V6 settlement receipt_digest mismatch")
    if recover_evm_address(digest, _strict_signature(payload.get("provider_signature"), "provider")) != receipt.provider:
        raise ChainError("Provider V6 settlement signature does not recover receipt provider")
    return receipt


def encode_settle_signed_receipt(
    receipt: V6SessionReceipt,
    relay_attestation: Mapping[str, Any] | None,
    session_key_signature: bytes,
    provider_signature: bytes,
    relay_signature: bytes,
) -> str:
    tuple_value = encode_settle_signed_receipt_tuple(
        receipt,
        relay_attestation,
        session_key_signature,
        provider_signature,
        relay_signature,
    )
    selector = keccak256(V6_SESSION_RECEIPT_SIGNATURE.encode("utf-8"))[:4]
    return "0x" + (selector + (32).to_bytes(32, "big") + tuple_value).hex()


def encode_settle_signed_receipt_tuple(
    receipt: V6SessionReceipt,
    relay_attestation: Mapping[str, Any] | None,
    session_key_signature: bytes,
    provider_signature: bytes,
    relay_signature: bytes,
) -> bytes:
    """Encode one SignedSessionReceipt tuple without a function selector."""

    for value, label in (
        (session_key_signature, "session key"),
        (provider_signature, "provider"),
    ):
        _validate_strict_raw_signature(value, label)
    if relay_attestation is not None and not relay_signature:
        raise ChainError("Relay attestation signature is required")
    if relay_attestation is None and relay_signature:
        raise ChainError("Relay attestation signature requires an attestation")
    if relay_signature:
        _validate_strict_raw_signature(relay_signature, "Relay attestation")
    receipt_words = b"".join(abi_encode_arg(value) for value in receipt.abi_args())
    if relay_attestation is None:
        attestation_values = ["0x" + "0" * 64, "0x" + "0" * 64, ZERO_ADDRESS, ZERO_ADDRESS, "0", "0", "0"]
    else:
        attestation_values = [
            _nonzero_bytes32(relay_attestation.get("session_id"), "relay session_id"),
            _nonzero_bytes32(relay_attestation.get("request_hash"), "relay request_hash"),
            _nonzero_address(relay_attestation.get("provider"), "relay provider"),
            _nonzero_address(relay_attestation.get("relay"), "relay payout"),
            str(_uint64(relay_attestation.get("relay_epoch"), "relay epoch")),
            str(_uint(relay_attestation.get("sequence"), "relay sequence")),
            str(_positive_uint(relay_attestation.get("deadline"), "relay deadline")),
        ]
    attestation_words = b"".join(abi_encode_arg(value) for value in attestation_values)
    tuple_head_size = (len(receipt.abi_args()) + len(attestation_values) + 3) * 32
    session_tail = _dynamic_bytes(session_key_signature)
    provider_tail = _dynamic_bytes(provider_signature)
    relay_tail = _dynamic_bytes(relay_signature)
    tuple_value = b"".join(
        [
            receipt_words,
            attestation_words,
            tuple_head_size.to_bytes(32, "big"),
            (tuple_head_size + len(session_tail)).to_bytes(32, "big"),
            (tuple_head_size + len(session_tail) + len(provider_tail)).to_bytes(32, "big"),
            session_tail,
            provider_tail,
            relay_tail,
        ]
    )
    return tuple_value


def encode_settle_signed_batch_tuples(tuple_values: Sequence[bytes]) -> str:
    """Encode a V6 signed-receipt batch from already validated tuple values."""

    if not tuple_values or len(tuple_values) > 32:
        raise ChainError("V6 signed receipt batch must contain between 1 and 32 receipts")
    normalized: list[bytes] = []
    for value in tuple_values:
        if not isinstance(value, bytes) or not value:
            raise ChainError("V6 signed receipt batch tuple is invalid")
        normalized.append(value)
    array_body = len(normalized).to_bytes(32, "big")
    offset = len(normalized) * 32
    for value in normalized:
        array_body += offset.to_bytes(32, "big")
        offset += len(value)
    array_body += b"".join(normalized)
    selector = keccak256(V6_SESSION_RECEIPT_BATCH_SIGNATURE.encode("utf-8"))[:4]
    return "0x" + (selector + (32).to_bytes(32, "big") + array_body).hex()


def encode_settle_signed_batch(
    inputs: Sequence[tuple[V6SessionReceipt, Mapping[str, Any] | None, bytes, bytes, bytes]],
) -> str:
    """Encode a V6 signed-receipt batch from validated receipt components."""

    return encode_settle_signed_batch_tuples(
        [encode_settle_signed_receipt_tuple(*item) for item in inputs]
    )


def encode_claim_payout() -> str:
    return "0x" + keccak256(V6_CLAIM_PAYOUT_SIGNATURE.encode("utf-8"))[:4].hex()


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
    artifact: str = MYCO_V6_DEPLOYER_ARTIFACT,
    timeout: float = 300.0,
) -> V6Deployment:
    if not Path(artifact).exists():
        try:
            run_tool(["forge", "build"], timeout=timeout)
        except ChainError as forge_error:
            try:
                run_tool(["python3", "scripts/compile-v6-artifact.py"], timeout=timeout)
            except ChainError as compile_error:
                raise ChainError(
                    f"V6 artifact is missing; forge build failed ({forge_error}) and solc fallback failed ({compile_error})"
                ) from compile_error
    artifact_path = Path(artifact)
    _validate_artifact(artifact_path)
    config = ["1000", "4000", "2000", "8500", "300", "200", "1000", "9000", "1000", "1000000000000", "true"]
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
        bytecode=load_artifact_bytecode(artifact_path) + constructor_args,
        timeout=timeout,
    )
    return V6Deployment(
        protocol_version=6,
        chain_id=chain_id,
        deployer=private_key_to_address(parse_private_key(private_key)),
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
        pricing_hash=default_pricing_hash(treasury),
        tx_hash=tx_hash,
    )


def save_deployment(path: Path, deployment: V6Deployment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(deployment.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_deployment(path: Path = Path(DEFAULT_MYCO_V6_DEPLOYMENT_PATH)) -> V6Deployment:
    if not path.exists():
        raise ChainError(f"Myco V6 deployment not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or int(payload.get("protocol_version") or 0) != 6:
        raise ChainError("deployment is not a Myco Settlement V6 deployment")
    required = {
        "chain_id", "deployer", "stablecoin", "settlement", "token", "treasury", "governance",
        "max_consumer_rebate_bps", "max_supply", "channel", "channel_hash", "pricing_version", "pricing_hash",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise ChainError("Myco V6 deployment is missing required fields: " + ", ".join(missing))
    return V6Deployment(
        protocol_version=6,
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
        eip712_version=str(payload.get("eip712_version") or "6"),
        tx_hash=payload.get("tx_hash"),
        deployment_block=payload.get("deployment_block"),
        network_id=str(payload.get("network_id") or MYCOMESH_TESTNET_NETWORK_ID),
        channel_id=str(payload.get("channel_id") or CODEX_CHANNEL_ID),
        backend_policy=str(payload.get("backend_policy") or CODEX_BACKEND_POLICY),
        pull_payments_enabled=_optional_bool(payload.get("pull_payments_enabled", True), "pull_payments_enabled"),
        immutable_routes_enabled=_optional_bool(payload.get("immutable_routes_enabled", True), "immutable_routes_enabled"),
        relay_attestations_enabled=_optional_bool(payload.get("relay_attestations_enabled", True), "relay_attestations_enabled"),
    )


def _typed_data_digest(struct_hash: str, *, chain_id: int, verifying_contract: str) -> bytes:
    domain = domain_separator(chain_id=chain_id, verifying_contract=verifying_contract)
    return keccak256(b"\x19\x01" + bytes.fromhex(domain[2:]) + bytes.fromhex(struct_hash[2:]))


def _runtime_receipt_hash(values: Mapping[str, Any]) -> str:
    commitment = (
        "MycoMeshV6SessionReceipt(bytes32 sessionId,bytes32 requestHash,bytes32 responseHash,bytes32 channel,"
        "uint64 pricingVersion,bytes32 pricingHash,address consumer,address provider,address relay,address pool,uint64 relayEpoch,"
        "uint256 inputTokens,uint256 outputTokens,uint256 sequence,uint256 quotedFee,uint256 deadline)"
    )
    order = (
        "session_id", "request_hash", "response_hash", "channel", "pricing_version", "pricing_hash", "consumer",
        "provider", "relay", "pool", "relay_epoch", "input_tokens", "output_tokens", "sequence", "quoted_fee", "deadline",
    )
    encoded = b"".join([keccak256(commitment.encode("utf-8"))] + [abi_encode_arg(str(values[key])) for key in order])
    return _nonzero_bytes32("0x" + keccak256(encoded).hex(), "receipt_hash")


def _runtime_acceptance_hash(*, receipt_hash: str, session_id: str, consumer: str, provider: str) -> str:
    commitment = "MycoMeshV6ConsumerAcceptance(bytes32 receiptHash,bytes32 sessionId,address consumer,address provider)"
    encoded = b"".join(
        [keccak256(commitment.encode("utf-8")), abi_encode_arg(receipt_hash), abi_encode_arg(session_id), abi_encode_arg(consumer), abi_encode_arg(provider)]
    )
    return _nonzero_bytes32("0x" + keccak256(encoded).hex(), "accepted_hash")


def _validate_artifact(path: Path) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ChainError(f"could not read V6 artifact {path}: {exc}") from exc
    abi = payload.get("abi") if isinstance(payload, dict) else None
    if not isinstance(abi, list):
        raise ChainError(f"V6 artifact does not contain an ABI: {path}")
    function_names = {str(item.get("name")) for item in abi if isinstance(item, dict) and item.get("type") == "function"}
    required = {"claim", "claimableBalance", "relayRequestAttestationDigest", "settleSignedReceipt"}
    missing = sorted(required - function_names)
    if missing:
        raise ChainError("V6 artifact ABI is missing required functions: " + ", ".join(missing))


def _uint64(value: Any, label: str) -> int:
    parsed = _uint(value, label)
    if parsed >= 1 << 64:
        raise ChainError(f"{label} is out of range")
    return parsed


def _strict_signature(value: Any, label: str) -> Any:
    signature = _parse_signature(value, label)
    if int(signature.v) not in {0, 1, 27, 28}:
        raise ChainError(f"{label} signature v must be 0, 1, 27, or 28")
    r = int(signature.r, 16)
    s = int(signature.s, 16)
    if not 0 < r < SECP256K1_N:
        raise ChainError(f"{label} signature r is out of range")
    if not 0 < s <= SECP256K1_HALF_ORDER:
        raise ChainError(f"{label} signature must use canonical low-s form")
    return signature


def _validate_strict_raw_signature(value: bytes, label: str) -> None:
    _validate_raw_signature(value, label)
    raw = bytes(value)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    if not 0 < r < SECP256K1_N:
        raise ChainError(f"{label} signature r is out of range")
    if not 0 < s <= SECP256K1_HALF_ORDER:
        raise ChainError(f"{label} signature must use canonical low-s form")
    if raw[64] not in {0, 1, 27, 28}:
        raise ChainError(f"{label} signature v must be 0, 1, 27, or 28")
