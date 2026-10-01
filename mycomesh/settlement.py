"""MycoSettlementV11 off-chain protocol: authorizations, dispatches, receipts, settlement calls.

Every hash and type string here mirrors contracts/MycoSettlementV11.sol exactly;
tests/test_mycomesh_settlement_anvil.py settles on a real deployment to prove it.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from . import rpc as rpc_module
from .evm import (
    abi_encode, address_of, decode_words, domain_separator, encode_call, keccak256, normalize_address,
    normalize_bytes32, recover_address, sign_digest, typed_data_digest, word_to_address,
)

DOMAIN_NAME = "MycoMesh Settlement"
DOMAIN_VERSION = "11"
MAX_AUTHORIZATION_TTL = 3 * 60 * 60
MAX_BATCH_SIZE = 32

AUTHORIZATION_TYPE = (
    "PaymentAuthorization(bytes32 requestId,bytes32 requestHash,address key,address providerSigner,"
    "address relaySigner,uint256 maxFee,uint64 issuedAt,uint64 executeBy,uint64 deadline)"
)
RECEIPT_TYPE = (
    "UsageReceipt(bytes32 authorizationHash,bytes32 dispatchHash,bytes32 responseHash,uint256 inputTokens,"
    "uint256 outputTokens,uint256 actualFee)"
)
DISPATCH_TYPE = "RelayDispatch(bytes32 authorizationHash)"
DISPUTE_VOTE_TYPE = (
    "DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,"
    "bytes32 decisionHash,uint256 nonce,uint64 deadline)"
)
AUTHORIZATION_TYPEHASH = keccak256(AUTHORIZATION_TYPE.encode())
RECEIPT_TYPEHASH = keccak256(RECEIPT_TYPE.encode())
DISPATCH_TYPEHASH = keccak256(DISPATCH_TYPE.encode())
DISPUTE_VOTE_TYPEHASH = keccak256(DISPUTE_VOTE_TYPE.encode())

_AUTHORIZATION_ABI = ("tuple", ["bytes32", "bytes32", "address", "address", "address", "uint256", "uint64", "uint64", "uint64"])
_RECEIPT_ABI = ("tuple", ["bytes32", "bytes32", "bytes32", "uint256", "uint256", "uint256"])
_SIGNED_RECEIPT_ABI = ("tuple", [_AUTHORIZATION_ABI, _RECEIPT_ABI, "bytes", "bytes", "bytes"])
_SIGNED_RECEIPT_SIGNATURE = (
    "((bytes32,bytes32,address,address,address,uint256,uint64,uint64,uint64),"
    "(bytes32,bytes32,bytes32,uint256,uint256,uint256),bytes,bytes,bytes)"
)


class SettlementError(ValueError):
    pass


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


@dataclass(frozen=True)
class Deployment:
    chain_id: int
    settlement: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "settlement", normalize_address(self.settlement))
        if type(self.chain_id) is not int or self.chain_id <= 0:
            raise SettlementError("chain id must be a positive integer")

    @property
    def domain(self) -> bytes:
        return domain_separator(DOMAIN_NAME, DOMAIN_VERSION, self.chain_id, self.settlement)

    def digest(self, struct_hash: bytes) -> bytes:
        return typed_data_digest(self.domain, struct_hash)


@dataclass(frozen=True)
class Authorization:
    request_id: str
    request_hash: str
    key: str
    provider_signer: str
    relay_signer: str
    max_fee: int
    issued_at: int
    execute_by: int
    deadline: int

    def __post_init__(self) -> None:
        for name in ("request_id", "request_hash"):
            value = normalize_bytes32(getattr(self, name))
            if int(value, 16) == 0:
                raise SettlementError(f"{name} must be nonzero")
            object.__setattr__(self, name, value)
        for name in ("key", "provider_signer", "relay_signer"):
            object.__setattr__(self, name, normalize_address(getattr(self, name)))
        for name in ("max_fee", "issued_at", "execute_by", "deadline"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise SettlementError(f"{name} must be a non-negative integer")
        if self.max_fee <= 0:
            raise SettlementError("max_fee must be positive")
        if not (self.issued_at <= self.execute_by < self.deadline
                and self.deadline - self.issued_at <= MAX_AUTHORIZATION_TTL):
            raise SettlementError("authorization window is invalid")

    def values(self) -> list[Any]:
        return [self.request_id, self.request_hash, self.key, self.provider_signer, self.relay_signer,
                self.max_fee, self.issued_at, self.execute_by, self.deadline]

    @property
    def struct_hash(self) -> bytes:
        return keccak256(abi_encode(["bytes32"] + _AUTHORIZATION_ABI[1], [_hex(AUTHORIZATION_TYPEHASH)] + self.values()))

    @property
    def dispatch_hash(self) -> bytes:
        return dispatch_struct_hash(self.struct_hash)

    @property
    def settlement_key(self) -> str:
        return settlement_key(self.key, self.request_id)

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_payload(cls, value: Any) -> "Authorization":
        fields = {"request_id", "request_hash", "key", "provider_signer", "relay_signer",
                  "max_fee", "issued_at", "execute_by", "deadline"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise SettlementError("authorization fields are invalid")
        return cls(**{name: value[name] for name in fields})


@dataclass(frozen=True)
class Receipt:
    authorization_hash: str
    dispatch_hash: str
    response_hash: str
    input_tokens: int
    output_tokens: int
    actual_fee: int

    def __post_init__(self) -> None:
        for name in ("authorization_hash", "dispatch_hash", "response_hash"):
            object.__setattr__(self, name, normalize_bytes32(getattr(self, name)))
        if int(self.response_hash, 16) == 0:
            raise SettlementError("response_hash must be nonzero")
        for name in ("input_tokens", "output_tokens", "actual_fee"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise SettlementError(f"{name} must be a non-negative integer")
        if self.actual_fee <= 0:
            raise SettlementError("actual_fee must be positive")

    def values(self) -> list[Any]:
        return [self.authorization_hash, self.dispatch_hash, self.response_hash,
                self.input_tokens, self.output_tokens, self.actual_fee]

    @property
    def struct_hash(self) -> bytes:
        return keccak256(abi_encode(["bytes32"] + _RECEIPT_ABI[1], [_hex(RECEIPT_TYPEHASH)] + self.values()))

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_payload(cls, value: Any) -> "Receipt":
        fields = {"authorization_hash", "dispatch_hash", "response_hash", "input_tokens", "output_tokens", "actual_fee"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise SettlementError("receipt fields are invalid")
        return cls(**{name: value[name] for name in fields})


def dispatch_struct_hash(authorization_hash: bytes) -> bytes:
    return keccak256(abi_encode(["bytes32", "bytes32"], [_hex(DISPATCH_TYPEHASH), _hex(authorization_hash)]))


def settlement_key(key: str, request_id: str) -> str:
    return _hex(keccak256(abi_encode(["address", "bytes32"], [key, request_id])))


def request_id_for(key: str, nonce: str) -> str:
    """A collision-resistant request id from a Consumer key and a local nonce."""
    return _hex(keccak256(abi_encode(["address", "bytes32"], [key, nonce])))


# ---------------- signing and verification ----------------

def sign_authorization(key_private: str, authorization: Authorization, deployment: Deployment) -> str:
    if address_of(key_private) != authorization.key:
        raise SettlementError("signing key does not match authorization.key")
    return sign_digest(key_private, deployment.digest(authorization.struct_hash))


def verify_authorization(
    authorization: Authorization, signature: str, deployment: Deployment, *, now: int,
    request_hash: str | None = None, provider_signer: str | None = None, relay_signer: str | None = None,
) -> None:
    if recover_address(deployment.digest(authorization.struct_hash), signature) != authorization.key:
        raise SettlementError("authorization signature does not match its key")
    if not (authorization.issued_at <= now + 30 and now <= authorization.execute_by):
        raise SettlementError("authorization is outside its execution window")
    for expected, actual, label in (
        (request_hash, authorization.request_hash, "request_hash"),
        (provider_signer, authorization.provider_signer, "provider_signer"),
        (relay_signer, authorization.relay_signer, "relay_signer"),
    ):
        if expected is not None and str(expected).lower() != actual:
            raise SettlementError(f"authorization {label} mismatch")


def sign_dispatch(relay_private: str, authorization: Authorization, deployment: Deployment) -> str:
    if address_of(relay_private) != authorization.relay_signer:
        raise SettlementError("relay key does not match authorization.relay_signer")
    return sign_digest(relay_private, deployment.digest(authorization.dispatch_hash))


def verify_dispatch(authorization: Authorization, signature: str, deployment: Deployment) -> None:
    if recover_address(deployment.digest(authorization.dispatch_hash), signature) != authorization.relay_signer:
        raise SettlementError("dispatch signature does not match the relay signer")


def build_receipt(authorization: Authorization, *, response_hash: str, input_tokens: int, output_tokens: int,
                  actual_fee: int) -> Receipt:
    if actual_fee > authorization.max_fee:
        raise SettlementError("actual fee exceeds the authorized maximum")
    return Receipt(_hex(authorization.struct_hash), _hex(authorization.dispatch_hash), response_hash,
                   input_tokens, output_tokens, actual_fee)


def sign_receipt(provider_private: str, authorization: Authorization, receipt: Receipt, deployment: Deployment) -> str:
    if address_of(provider_private) != authorization.provider_signer:
        raise SettlementError("provider key does not match authorization.provider_signer")
    return sign_digest(provider_private, deployment.digest(receipt.struct_hash))


@dataclass(frozen=True)
class SignedReceipt:
    authorization: Authorization
    receipt: Receipt
    key_signature: str
    provider_signature: str
    relay_signature: str

    def verify(self, deployment: Deployment) -> None:
        """Every check the contract makes that needs no chain state."""
        a, r = self.authorization, self.receipt
        if r.authorization_hash != _hex(a.struct_hash) or r.dispatch_hash != _hex(a.dispatch_hash):
            raise SettlementError("receipt is not bound to its authorization")
        if not 0 < r.actual_fee <= a.max_fee:
            raise SettlementError("receipt fee exceeds the authorization")
        if recover_address(deployment.digest(a.struct_hash), self.key_signature) != a.key:
            raise SettlementError("bad consumer key signature")
        verify_dispatch(a, self.relay_signature, deployment)
        if recover_address(deployment.digest(r.struct_hash), self.provider_signature) != a.provider_signer:
            raise SettlementError("bad provider signature")

    def abi_value(self) -> list[Any]:
        return [self.authorization.values(), self.receipt.values(),
                self.key_signature, self.provider_signature, self.relay_signature]

    def to_payload(self) -> dict[str, Any]:
        return {"authorization": self.authorization.to_payload(), "receipt": self.receipt.to_payload(),
                "key_signature": self.key_signature, "provider_signature": self.provider_signature,
                "relay_signature": self.relay_signature}

    @classmethod
    def from_payload(cls, value: Any) -> "SignedReceipt":
        fields = {"authorization", "receipt", "key_signature", "provider_signature", "relay_signature"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise SettlementError("signed receipt fields are invalid")
        return cls(Authorization.from_payload(value["authorization"]), Receipt.from_payload(value["receipt"]),
                   str(value["key_signature"]), str(value["provider_signature"]), str(value["relay_signature"]))


def encode_settle_batch(receipts: Sequence[SignedReceipt]) -> str:
    if not 0 < len(receipts) <= MAX_BATCH_SIZE:
        raise SettlementError(f"a batch holds 1 to {MAX_BATCH_SIZE} receipts")
    return encode_call(f"settleBatch({_SIGNED_RECEIPT_SIGNATURE}[])", [("array", _SIGNED_RECEIPT_ABI)],
                       [[receipt.abi_value() for receipt in receipts]])


def encode_release(key: str) -> str:
    return encode_call("release(bytes32)", ["bytes32"], [key])


RELEASE_BATCH = 64  # MAX_RELEASE_BATCH in the contract


def encode_release_batch(keys: list[str]) -> str:
    """Release every due receipt among ``keys`` in one transaction; the contract skips the rest."""
    return encode_call("releaseBatch(bytes32[])", [("array", "bytes32")], [list(keys)])


# ---------------- chain reads ----------------

@dataclass(frozen=True)
class SettlementReader:
    rpc: str
    deployment: Deployment

    def _call(self, signature: str, types: list[Any], values: list[Any], words: int, block: Any = "latest") -> list[bytes]:
        result = rpc_module.eth_call(self.rpc, self.deployment.settlement, encode_call(signature, types, values), block=block)
        return decode_words(result, words)

    def available_balance(self, owner: str) -> int:
        return int.from_bytes(self._call("availableBalance(address)", ["address"], [owner], 1)[0], "big")

    def claimable_balance(self, account: str) -> int:
        return int.from_bytes(self._call("claimableBalance(address)", ["address"], [account], 1)[0], "big")

    def key_grant(self, key: str) -> dict[str, Any]:
        owner, maximum, valid_until, active = self._call("keyGrants(address)", ["address"], [key], 4)
        return {"owner": word_to_address(owner), "max_per_request": int.from_bytes(maximum, "big"),
                "valid_until": int.from_bytes(valid_until, "big"), "active": bool(int.from_bytes(active, "big"))}

    def key_budget(self, key: str) -> tuple[int, int]:
        """(limit, spent) for a tenant key; a zero limit means unlimited."""
        limit, spent = self._call("keyBudgets(address)", ["address"], [key], 2)
        return int.from_bytes(limit, "big"), int.from_bytes(spent, "big")

    def provider_owner(self, signer: str) -> str:
        return word_to_address(self._call("providerSignerOwner(address)", ["address"], [signer], 1)[0])

    def relay_owner(self, signer: str) -> str:
        return word_to_address(self._call("relaySignerOwner(address)", ["address"], [signer], 1)[0])

    def exposure(self, provider: str) -> tuple[int, int]:
        pending = int.from_bytes(self._call("pendingExposure(address)", ["address"], [provider], 1)[0], "big")
        cap = int.from_bytes(self._call("exposureCap(address)", ["address"], [provider], 1)[0], "big")
        return pending, cap

    def is_settled(self, key: str) -> bool:
        return bool(int.from_bytes(self._call("settled(bytes32)", ["bytes32"], [key], 1)[0], "big"))
