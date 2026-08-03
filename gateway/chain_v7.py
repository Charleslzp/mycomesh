from __future__ import annotations

"""Settlement V7 request-key authorization and receipt helpers."""

import base64
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .chain import (
    DEFAULT_CHANNEL_HASH,
    SEPOLIA_CHAIN_ID,
    ZERO_ADDRESS,
    ChainError,
    EvmSignature,
    abi_encode_arg,
    call_contract,
    deploy_contract_transaction,
    keccak256,
    load_artifact_bytecode,
    normalize_address,
    normalize_bytes32,
    parse_private_key,
    private_key_to_address,
    recover_evm_address,
    sign_evm_digest,
    send_contract_transaction,
)
from .chain_v4 import _dynamic_bytes, _positive_uint, _signature_bytes, _uint
from .channel_policy import CODEX_BACKEND_POLICY, CODEX_CHANNEL_ID, MYCOMESH_TESTNET_NETWORK_ID
from .pricing import DEFAULT_CHANNEL


DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
AUTHORIZATION_TYPE = (
    "PaymentAuthorization(bytes32 requestId,bytes32 requestHash,address key,address relay,address relaySigner,bytes32 channel,"
    "uint64 pricingVersion,bytes32 pricingHash,uint256 maxFee,uint64 issuedAt,uint64 deadline)"
)
RECEIPT_TYPE = (
    "UsageReceipt(bytes32 authorizationHash,bytes32 responseHash,address provider,address relay,address pool,"
    "uint256 inputTokens,uint256 outputTokens,uint256 actualFee)"
)
SETTLE_SIGNATURE = (
    "settleSignedReceipt(((bytes32,bytes32,address,address,address,bytes32,uint64,bytes32,uint256,uint64,uint64),"
    "(bytes32,bytes32,address,address,address,uint256,uint256,uint256),bytes,bytes,bytes))"
)
BATCH_SIGNATURE = (
    "settleSignedBatch(((bytes32,bytes32,address,address,address,bytes32,uint64,bytes32,uint256,uint64,uint64),"
    "(bytes32,bytes32,address,address,address,uint256,uint256,uint256),bytes,bytes,bytes)[])"
)
ARTIFACT = "out/MycoSettlementV7.sol/MycoSettlementV7.json"
DEFAULT_DEPLOYMENT = "deployments/sepolia-myco-v7.json"
DEFAULT_MYCO_V7_DEPLOYMENT_PATH = DEFAULT_DEPLOYMENT
AUTH_SCHEMA = "mycomesh.x402.myco-credit-v1"
PROVIDER_SCHEMA = "mycomesh.settlement.v7.provider.v1"
SIGNED_SCHEMA = "mycomesh.settlement.v7.signed.v1"
MAX_AUTHORIZATION_TTL = 3600


@dataclass(frozen=True)
class PaymentAuthorization:
    request_id: str
    request_hash: str
    key: str
    relay: str
    relay_signer: str
    channel: str
    pricing_version: int
    pricing_hash: str
    max_fee: int
    issued_at: int
    deadline: int

    def abi_args(self) -> list[str]:
        return [
            self.request_id,
            self.request_hash,
            self.key,
            self.relay,
            self.relay_signer,
            self.channel,
            str(self.pricing_version),
            self.pricing_hash,
            str(self.max_fee),
            str(self.issued_at),
            str(self.deadline),
        ]

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class UsageReceipt:
    authorization_hash: str
    response_hash: str
    provider: str
    relay: str
    pool: str
    input_tokens: int
    output_tokens: int
    actual_fee: int

    def abi_args(self) -> list[str]:
        return [
            self.authorization_hash,
            self.response_hash,
            self.provider,
            self.relay,
            self.pool,
            str(self.input_tokens),
            str(self.output_tokens),
            str(self.actual_fee),
        ]

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class V7Deployment:
    protocol_version: int
    chain_id: int
    deployer: str
    stablecoin: str
    settlement: str
    treasury: str
    governance: str
    channel: str
    channel_hash: str
    pricing_version: int
    pricing_hash: str
    tx_hash: str | None = None
    deployment_block: int | None = None
    network_id: str = MYCOMESH_TESTNET_NETWORK_ID
    channel_id: str = CODEX_CHANNEL_ID
    backend_policy: str = CODEX_BACKEND_POLICY
    eip712_name: str = "MycoMesh Settlement"
    eip712_version: str = "7"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def generate_payment_key() -> str:
    while True:
        candidate = secrets.token_bytes(32)
        try:
            parse_private_key(candidate.hex())
        except ChainError:
            continue
        return "myco_sk_" + base64.urlsafe_b64encode(candidate).decode("ascii").rstrip("=")


def payment_private_key(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("myco_sk_"):
        encoded = text.removeprefix("myco_sk_")
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, TypeError) as exc:
            raise ChainError("invalid Myco payment key") from exc
        text = raw.hex()
    parse_private_key(text)
    return "0x" + text.removeprefix("0x").lower()


def payment_key_address(value: str) -> str:
    return private_key_to_address(parse_private_key(payment_private_key(value)))


def domain_separator(*, chain_id: int, verifying_contract: str) -> str:
    encoded = b"".join(
        [
            keccak256(DOMAIN_TYPE.encode()),
            keccak256(b"MycoMesh Settlement"),
            keccak256(b"7"),
            abi_encode_arg(str(_positive_uint(chain_id, "chain_id"))),
            abi_encode_arg(normalize_address(verifying_contract)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def authorization_struct_hash(value: PaymentAuthorization) -> str:
    return "0x" + keccak256(
        keccak256(AUTHORIZATION_TYPE.encode())
        + b"".join(abi_encode_arg(item) for item in value.abi_args())
    ).hex()


def receipt_struct_hash(value: UsageReceipt) -> str:
    return "0x" + keccak256(
        keccak256(RECEIPT_TYPE.encode())
        + b"".join(abi_encode_arg(item) for item in value.abi_args())
    ).hex()


def authorization_digest(value: PaymentAuthorization, *, chain_id: int, verifying_contract: str) -> bytes:
    return _typed_digest(authorization_struct_hash(value), chain_id=chain_id, contract=verifying_contract)


def receipt_digest(value: UsageReceipt, *, chain_id: int, verifying_contract: str) -> bytes:
    return _typed_digest(receipt_struct_hash(value), chain_id=chain_id, contract=verifying_contract)


def build_authorization(
    *,
    payment_key: str,
    chain_id: int,
    settlement_contract: str,
    request_id: str,
    request_hash: str,
    relay: str,
    relay_signer: str,
    channel_hash: str,
    pricing_version: int,
    pricing_hash: str,
    max_fee: int,
    issued_at: int | None = None,
    deadline: int | None = None,
) -> dict[str, Any]:
    private_key = payment_private_key(payment_key)
    now = int(time.time() if issued_at is None else issued_at)
    expires = int(deadline if deadline is not None else now + 900)
    authorization = PaymentAuthorization(
        request_id=normalize_bytes32(request_id),
        request_hash=normalize_bytes32(request_hash),
        key=payment_key_address(private_key),
        relay=_nonzero_address(relay, "relay"),
        relay_signer=_nonzero_address(relay_signer, "relay_signer"),
        channel=normalize_bytes32(channel_hash),
        pricing_version=_positive_uint(pricing_version, "pricing_version", bits=64),
        pricing_hash=normalize_bytes32(pricing_hash),
        max_fee=_positive_uint(max_fee, "max_fee"),
        issued_at=_positive_uint(now, "issued_at", bits=64),
        deadline=_positive_uint(expires, "deadline", bits=64),
    )
    if authorization.request_id == "0x" + "0" * 64:
        raise ChainError("V7 request_id cannot be zero")
    if authorization.request_hash == "0x" + "0" * 64:
        raise ChainError("V7 request_hash cannot be zero")
    if authorization.channel == "0x" + "0" * 64:
        raise ChainError("V7 channel cannot be zero")
    if authorization.pricing_hash == "0x" + "0" * 64:
        raise ChainError("V7 pricing_hash cannot be zero")
    if authorization.deadline <= authorization.issued_at or authorization.deadline - authorization.issued_at > MAX_AUTHORIZATION_TTL:
        raise ChainError("V7 authorization lifetime must be between 1 and 3600 seconds")
    digest = authorization_digest(authorization, chain_id=chain_id, verifying_contract=settlement_contract)
    signature = _signature_bytes(sign_evm_digest(private_key, digest), "payment key")
    return {
        "schema": AUTH_SCHEMA,
        "chain_id": _positive_uint(chain_id, "chain_id"),
        "settlement_contract": _nonzero_address(settlement_contract, "settlement_contract"),
        "authorization": authorization.to_payload(),
        "authorization_hash": authorization_struct_hash(authorization),
        "authorization_digest": "0x" + digest.hex(),
        "key_signature": "0x" + signature.hex(),
    }


def verify_authorization(
    value: Any,
    *,
    expected_chain_id: int | None = None,
    expected_contract: str | None = None,
    expected_relay: str | None = None,
    expected_relay_signer: str | None = None,
    expected_request_id: str | None = None,
    expected_request_hash: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema") != AUTH_SCHEMA:
        raise ChainError("unsupported V7 payment authorization")
    chain_id = _positive_uint(value.get("chain_id"), "chain_id")
    contract = _nonzero_address(value.get("settlement_contract"), "settlement_contract")
    raw = value.get("authorization")
    if not isinstance(raw, Mapping):
        raise ChainError("V7 payment authorization is missing")
    authorization = PaymentAuthorization(
        request_id=normalize_bytes32(str(raw.get("request_id") or "")),
        request_hash=normalize_bytes32(str(raw.get("request_hash") or "")),
        key=_nonzero_address(raw.get("key"), "key"),
        relay=_nonzero_address(raw.get("relay"), "relay"),
        relay_signer=_nonzero_address(raw.get("relay_signer"), "relay_signer"),
        channel=normalize_bytes32(str(raw.get("channel") or "")),
        pricing_version=_positive_uint(raw.get("pricing_version"), "pricing_version", bits=64),
        pricing_hash=normalize_bytes32(str(raw.get("pricing_hash") or "")),
        max_fee=_positive_uint(raw.get("max_fee"), "max_fee"),
        issued_at=_positive_uint(raw.get("issued_at"), "issued_at", bits=64),
        deadline=_positive_uint(raw.get("deadline"), "deadline", bits=64),
    )
    if authorization.request_id == "0x" + "0" * 64:
        raise ChainError("V7 request_id cannot be zero")
    if authorization.request_hash == "0x" + "0" * 64:
        raise ChainError("V7 request_hash cannot be zero")
    if authorization.channel == "0x" + "0" * 64:
        raise ChainError("V7 channel cannot be zero")
    if authorization.pricing_hash == "0x" + "0" * 64:
        raise ChainError("V7 pricing_hash cannot be zero")
    current = int(time.time() if now is None else now)
    if authorization.issued_at > current + 30 or authorization.deadline < current:
        raise ChainError("V7 payment authorization is outside its time window")
    if authorization.deadline <= authorization.issued_at or authorization.deadline - authorization.issued_at > MAX_AUTHORIZATION_TTL:
        raise ChainError("V7 payment authorization lifetime is invalid")
    _expect(expected_chain_id, chain_id, "chain_id")
    _expect_address(expected_contract, contract, "settlement_contract")
    _expect_address(expected_relay, authorization.relay, "relay")
    _expect_address(expected_relay_signer, authorization.relay_signer, "relay_signer")
    _expect_bytes32(expected_request_id, authorization.request_id, "request_id")
    _expect_bytes32(expected_request_hash, authorization.request_hash, "request_hash")
    struct_hash = authorization_struct_hash(authorization)
    if normalize_bytes32(str(value.get("authorization_hash") or "")) != struct_hash:
        raise ChainError("V7 authorization hash mismatch")
    digest = authorization_digest(authorization, chain_id=chain_id, verifying_contract=contract)
    if normalize_bytes32(str(value.get("authorization_digest") or "")) != "0x" + digest.hex():
        raise ChainError("V7 authorization digest mismatch")
    signature = _raw_signature(value.get("key_signature"), "payment key")
    if recover_evm_address(digest, _evm_signature(signature)) != authorization.key:
        raise ChainError("V7 payment key signature mismatch")
    return {**dict(value), "authorization": authorization.to_payload()}


def build_provider_receipt(
    *,
    provider_private_key: str,
    authorization_payload: Mapping[str, Any],
    response_hash: str,
    relay: str,
    pool: str = ZERO_ADDRESS,
    input_tokens: int,
    output_tokens: int,
    actual_fee: int,
) -> dict[str, Any]:
    verified = verify_authorization(authorization_payload, expected_relay=relay)
    chain_id = int(verified["chain_id"])
    contract = str(verified["settlement_contract"])
    provider = private_key_to_address(parse_private_key(provider_private_key))
    receipt = UsageReceipt(
        authorization_hash=normalize_bytes32(str(verified["authorization_hash"])),
        response_hash=normalize_bytes32(response_hash),
        provider=provider,
        relay=_nonzero_address(relay, "relay"),
        pool=normalize_address(pool),
        input_tokens=_uint(input_tokens, "input_tokens"),
        output_tokens=_uint(output_tokens, "output_tokens"),
        actual_fee=_positive_uint(actual_fee, "actual_fee"),
    )
    digest = receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    signature = _signature_bytes(sign_evm_digest(provider_private_key, digest), "provider")
    return {
        "schema": PROVIDER_SCHEMA,
        "chain_id": chain_id,
        "settlement_contract": contract,
        "authorization": dict(verified),
        "receipt": receipt.to_payload(),
        "receipt_digest": "0x" + digest.hex(),
        "provider_signature": "0x" + signature.hex(),
    }


def finalize_relay_receipt(value: Mapping[str, Any], *, relay_private_key: str) -> dict[str, Any]:
    authorization, receipt, provider_signature, chain_id, contract = verify_provider_receipt(value)
    relay = private_key_to_address(parse_private_key(relay_private_key))
    relay_signer = normalize_address(str(authorization["authorization"]["relay_signer"]))
    if relay != relay_signer:
        raise ChainError("Relay key does not match V7 authorization relay signer")
    digest = receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    relay_signature = _signature_bytes(sign_evm_digest(relay_private_key, digest), "relay")
    return {
        "schema": SIGNED_SCHEMA,
        "chain_id": chain_id,
        "settlement_contract": contract,
        "authorization": authorization,
        "receipt": receipt.to_payload(),
        "key_signature": str(authorization["key_signature"]),
        "provider_signature": "0x" + provider_signature.hex(),
        "relay_signature": "0x" + relay_signature.hex(),
    }


def verify_provider_receipt(value: Mapping[str, Any]) -> tuple[dict[str, Any], UsageReceipt, bytes, int, str]:
    if not isinstance(value, Mapping) or value.get("schema") != PROVIDER_SCHEMA:
        raise ChainError("unsupported V7 Provider receipt")
    authorization = verify_authorization(value.get("authorization"))
    chain_id = int(authorization["chain_id"])
    contract = str(authorization["settlement_contract"])
    if int(value.get("chain_id") or 0) != chain_id or normalize_address(str(value.get("settlement_contract") or "")) != contract:
        raise ChainError("V7 Provider receipt deployment mismatch")
    raw = value.get("receipt")
    receipt = _receipt_from_payload(raw)
    if receipt.authorization_hash != authorization_struct_hash(_authorization_from_payload(authorization["authorization"])):
        raise ChainError("V7 Provider receipt authorization mismatch")
    digest = receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    if normalize_bytes32(str(value.get("receipt_digest") or "")) != "0x" + digest.hex():
        raise ChainError("V7 Provider receipt digest mismatch")
    signature = _raw_signature(value.get("provider_signature"), "provider")
    if recover_evm_address(digest, _evm_signature(signature)) != receipt.provider:
        raise ChainError("V7 Provider signature mismatch")
    return authorization, receipt, signature, chain_id, contract


def encode_signed_receipt(value: Mapping[str, Any]) -> str:
    tuple_value = encode_signed_receipt_tuple(value)
    return "0x" + (keccak256(SETTLE_SIGNATURE.encode())[:4] + (32).to_bytes(32, "big") + tuple_value).hex()


def encode_signed_receipt_tuple(value: Mapping[str, Any]) -> bytes:
    authorization_payload, receipt, signatures = verify_signed_receipt(value)
    authorization = _authorization_from_payload(authorization_payload["authorization"])
    head_words = len(authorization.abi_args()) + len(receipt.abi_args()) + 3
    head_size = head_words * 32
    tails = [_dynamic_bytes(item) for item in signatures]
    offsets: list[bytes] = []
    offset = head_size
    for tail in tails:
        offsets.append(offset.to_bytes(32, "big"))
        offset += len(tail)
    return b"".join(
        [
            *(abi_encode_arg(item) for item in authorization.abi_args()),
            *(abi_encode_arg(item) for item in receipt.abi_args()),
            *offsets,
            *tails,
        ]
    )


def encode_signed_batch(values: Sequence[Mapping[str, Any]]) -> str:
    tuples = [encode_signed_receipt_tuple(item) for item in values]
    if not tuples or len(tuples) > 32:
        raise ChainError("V7 batch must contain between 1 and 32 receipts")
    body = len(tuples).to_bytes(32, "big")
    offset = len(tuples) * 32
    for item in tuples:
        body += offset.to_bytes(32, "big")
        offset += len(item)
    body += b"".join(tuples)
    return "0x" + (keccak256(BATCH_SIGNATURE.encode())[:4] + (32).to_bytes(32, "big") + body).hex()


def encode_signed_batch_tuples(tuples: Sequence[bytes]) -> str:
    if not tuples or len(tuples) > 32:
        raise ChainError("V7 batch must contain between 1 and 32 receipts")
    body = len(tuples).to_bytes(32, "big")
    offset = len(tuples) * 32
    for item in tuples:
        body += offset.to_bytes(32, "big")
        offset += len(item)
    body += b"".join(tuples)
    return "0x" + (keccak256(BATCH_SIGNATURE.encode())[:4] + (32).to_bytes(32, "big") + body).hex()


def verify_signed_receipt(
    value: Mapping[str, Any],
) -> tuple[dict[str, Any], UsageReceipt, list[bytes]]:
    if not isinstance(value, Mapping) or value.get("schema") != SIGNED_SCHEMA:
        raise ChainError("unsupported signed V7 receipt")
    authorization = verify_authorization(value.get("authorization"))
    receipt = _receipt_from_payload(value.get("receipt"))
    auth_struct = _authorization_from_payload(authorization["authorization"])
    if receipt.authorization_hash != authorization_struct_hash(auth_struct):
        raise ChainError("V7 signed receipt authorization mismatch")
    if receipt.relay != normalize_address(str(auth_struct.relay)):
        raise ChainError("V7 signed receipt Relay payout mismatch")
    digest = receipt_digest(
        receipt,
        chain_id=int(authorization["chain_id"]),
        verifying_contract=str(authorization["settlement_contract"]),
    )
    key_signature = _raw_signature(value.get("key_signature"), "payment key")
    if key_signature != _raw_signature(authorization.get("key_signature"), "payment key"):
        raise ChainError("V7 signed receipt payment signature mismatch")
    provider_signature = _raw_signature(value.get("provider_signature"), "provider")
    relay_signature = _raw_signature(value.get("relay_signature"), "relay")
    if recover_evm_address(digest, _evm_signature(provider_signature)) != receipt.provider:
        raise ChainError("V7 Provider signature mismatch")
    if recover_evm_address(digest, _evm_signature(relay_signature)) != auth_struct.relay_signer:
        raise ChainError("V7 Relay signature mismatch")
    return authorization, receipt, [key_signature, provider_signature, relay_signature]


def key_grant(rpc_url: str, settlement: str, key: str, *, timeout: float = 15.0) -> dict[str, Any]:
    output = call_contract(rpc_url, settlement, "keyGrants(address)", [normalize_address(key)], timeout=timeout)
    words = _words(output, 4, "key grant")
    return {
        "owner": normalize_address("0x" + words[0][-40:]),
        "max_per_request": int(words[1], 16),
        "valid_until": int(words[2], 16),
        "active": int(words[3], 16) != 0,
    }


def account_balance(rpc_url: str, settlement: str, owner: str, *, timeout: float = 15.0) -> int:
    output = call_contract(rpc_url, settlement, "availableBalance(address)", [normalize_address(owner)], timeout=timeout)
    return int(_words(output, 1, "account balance")[0], 16)


def register_payment_key(
    *,
    rpc_url: str,
    owner_private_key: str,
    settlement: str,
    key: str,
    max_per_request: int,
    valid_until: int = 0,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    """Register or refresh a reusable V7 bearer key from its wallet owner."""
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=owner_private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="registerKey(address,uint256,uint64)",
        args=[normalize_address(key), str(_positive_uint(max_per_request, "max_per_request")), str(_uint(valid_until, "valid_until"))],
        timeout=timeout,
    )


def revoke_payment_key(
    *,
    rpc_url: str,
    owner_private_key: str,
    settlement: str,
    key: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    timeout: float = 120.0,
) -> str:
    """Revoke a reusable V7 bearer key from its wallet owner."""
    return send_contract_transaction(
        rpc_url=rpc_url,
        private_key=owner_private_key,
        chain_id=chain_id,
        contract=normalize_address(settlement),
        signature="revokeKey(address)",
        args=[normalize_address(key)],
        timeout=timeout,
    )


def deploy_testnet(
    *,
    rpc_url: str,
    private_key: str,
    stablecoin: str,
    treasury: str,
    governance: str,
    chain_id: int = SEPOLIA_CHAIN_ID,
    artifact: str = ARTIFACT,
    timeout: float = 300.0,
) -> V7Deployment:
    artifact_path = Path(artifact)
    if not artifact_path.exists():
        raise ChainError("V7 artifact is missing; run python3 scripts/compile-v7-artifact.py")
    config = ["1000", "4000", "2000", "8500", "300", "200", "1000", "true"]
    constructor = b"".join(
        [
            abi_encode_arg(normalize_address(stablecoin)),
            abi_encode_arg(normalize_address(treasury)),
            abi_encode_arg(normalize_address(governance)),
            abi_encode_arg(DEFAULT_CHANNEL_HASH),
            *(abi_encode_arg(item) for item in config),
        ]
    )
    settlement, tx_hash = deploy_contract_transaction(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        bytecode=load_artifact_bytecode(artifact_path) + constructor,
        timeout=timeout,
    )
    pricing_hash = _read_pricing_hash(rpc_url, settlement, DEFAULT_CHANNEL_HASH, 1, timeout=timeout)
    return V7Deployment(
        protocol_version=7,
        chain_id=chain_id,
        deployer=private_key_to_address(parse_private_key(private_key)),
        stablecoin=normalize_address(stablecoin),
        settlement=settlement,
        treasury=normalize_address(treasury),
        governance=normalize_address(governance),
        channel=DEFAULT_CHANNEL,
        channel_hash=DEFAULT_CHANNEL_HASH,
        pricing_version=1,
        pricing_hash=pricing_hash,
        tx_hash=tx_hash,
    )


def save_deployment(path: Path, deployment: V7Deployment) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(deployment.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_deployment(path: Path = Path(DEFAULT_DEPLOYMENT)) -> V7Deployment:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or int(payload.get("protocol_version") or 0) != 7:
        raise ChainError("deployment is not Myco Settlement V7")
    names = {field.name for field in V7Deployment.__dataclass_fields__.values()}
    return V7Deployment(**{name: payload[name] for name in names if name in payload})


def _read_pricing_hash(rpc_url: str, settlement: str, channel: str, version: int, *, timeout: float) -> str:
    output = call_contract(
        rpc_url,
        settlement,
        "channelVersions(bytes32,uint64)",
        [normalize_bytes32(channel), str(version)],
        timeout=timeout,
    )
    return "0x" + _words(output, 10, "channel version")[9]


def _authorization_from_payload(raw: Mapping[str, Any]) -> PaymentAuthorization:
    return PaymentAuthorization(
        request_id=normalize_bytes32(str(raw["request_id"])),
        request_hash=normalize_bytes32(str(raw["request_hash"])),
        key=normalize_address(str(raw["key"])),
        relay=normalize_address(str(raw["relay"])),
        relay_signer=normalize_address(str(raw["relay_signer"])),
        channel=normalize_bytes32(str(raw["channel"])),
        pricing_version=int(raw["pricing_version"]),
        pricing_hash=normalize_bytes32(str(raw["pricing_hash"])),
        max_fee=int(raw["max_fee"]),
        issued_at=int(raw["issued_at"]),
        deadline=int(raw["deadline"]),
    )


def _receipt_from_payload(raw: Any) -> UsageReceipt:
    if not isinstance(raw, Mapping):
        raise ChainError("V7 usage receipt is missing")
    return UsageReceipt(
        authorization_hash=normalize_bytes32(str(raw.get("authorization_hash") or "")),
        response_hash=normalize_bytes32(str(raw.get("response_hash") or "")),
        provider=_nonzero_address(raw.get("provider"), "provider"),
        relay=_nonzero_address(raw.get("relay"), "relay"),
        pool=normalize_address(str(raw.get("pool") or ZERO_ADDRESS)),
        input_tokens=_uint(raw.get("input_tokens"), "input_tokens"),
        output_tokens=_uint(raw.get("output_tokens"), "output_tokens"),
        actual_fee=_positive_uint(raw.get("actual_fee"), "actual_fee"),
    )


def _typed_digest(struct_hash: str, *, chain_id: int, contract: str) -> bytes:
    return keccak256(
        b"\x19\x01"
        + bytes.fromhex(domain_separator(chain_id=chain_id, verifying_contract=contract)[2:])
        + bytes.fromhex(normalize_bytes32(struct_hash)[2:])
    )


def _nonzero_address(value: Any, label: str) -> str:
    address = normalize_address(str(value or ""))
    if address == ZERO_ADDRESS:
        raise ChainError(f"{label} cannot be zero")
    return address


def _raw_signature(value: Any, label: str) -> bytes:
    text = str(value or "")
    try:
        raw = bytes.fromhex(text.removeprefix("0x"))
    except ValueError as exc:
        raise ChainError(f"{label} signature must be hex") from exc
    if len(raw) != 65:
        raise ChainError(f"{label} signature must be 65 bytes")
    return raw


def _evm_signature(raw: bytes) -> EvmSignature:
    return EvmSignature(
        r="0x" + raw[:32].hex(),
        s="0x" + raw[32:64].hex(),
        v=raw[64],
    )


def _expect(expected: Any | None, actual: Any, label: str) -> None:
    if expected is not None and int(expected) != int(actual):
        raise ChainError(f"V7 {label} mismatch")


def _expect_address(expected: str | None, actual: str, label: str) -> None:
    if expected is not None and normalize_address(expected) != actual:
        raise ChainError(f"V7 {label} mismatch")


def _expect_bytes32(expected: str | None, actual: str, label: str) -> None:
    if expected is not None and normalize_bytes32(expected) != actual:
        raise ChainError(f"V7 {label} mismatch")


def _words(output: str, count: int, label: str) -> list[str]:
    raw = str(output or "").removeprefix("0x")
    if len(raw) < count * 64:
        raise ChainError(f"{label} returned malformed ABI data")
    return [raw[index : index + 64] for index in range(0, count * 64, 64)]
