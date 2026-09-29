"""EVM primitives: keys, secp256k1 signatures, keccak, ABI encoding, EIP-712, transactions."""
from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
ZERO_ADDRESS = "0x" + "00" * 20
ZERO_BYTES32 = "0x" + "00" * 32

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-fA-F]{64}$")


class EvmError(ValueError):
    pass


def keccak256(payload: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(payload)
    return digest.digest()


def normalize_address(value: Any) -> str:
    if not isinstance(value, str) or not _ADDRESS.match(value):
        raise EvmError(f"invalid EVM address: {value!r}")
    return "0x" + value[2:].lower()


def normalize_bytes32(value: Any) -> str:
    if not isinstance(value, str) or not _BYTES32.match(value):
        raise EvmError(f"invalid bytes32 value: {value!r}")
    return "0x" + value[2:].lower()


def parse_private_key(value: str) -> bytes:
    text = str(value).strip()
    raw = text[2:] if text.startswith("0x") else text
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        raise EvmError("private key must be 32 bytes of hex")
    if not 0 < int(raw, 16) < SECP256K1_N:
        raise EvmError("private key is outside the secp256k1 range")
    return bytes.fromhex(raw)


def address_of(private_key: bytes | str) -> str:
    key = parse_private_key(private_key) if isinstance(private_key, str) else private_key
    numbers = ec.derive_private_key(int.from_bytes(key, "big"), ec.SECP256K1()).public_key().public_numbers()
    return "0x" + keccak256(numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"))[-20:].hex()


# ---------------- secp256k1 signatures ----------------

def _point_add(a: tuple[int, int] | None, b: tuple[int, int] | None) -> tuple[int, int] | None:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SECP256K1_P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, SECP256K1_P)
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, SECP256K1_P)
    slope %= SECP256K1_P
    x = (slope * slope - a[0] - b[0]) % SECP256K1_P
    return x, (slope * (a[0] - x) - a[1]) % SECP256K1_P


def _point_mul(scalar: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    result = None
    while scalar:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _recover_point(z: int, r: int, s: int, recovery_id: int) -> tuple[int, int] | None:
    x = r + (recovery_id // 2) * SECP256K1_N
    if x >= SECP256K1_P:
        return None
    alpha = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    beta = pow(alpha, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(beta, 2, SECP256K1_P) != alpha:
        return None
    y = beta if beta % 2 == recovery_id % 2 else SECP256K1_P - beta
    sr = _point_mul(s % SECP256K1_N, (x, y))
    zg = _point_mul(z % SECP256K1_N, SECP256K1_G)
    if sr is None or zg is None:
        return None
    return _point_mul(pow(r, -1, SECP256K1_N), _point_add(sr, (zg[0], (-zg[1]) % SECP256K1_P)))


def _sign(private_key: bytes, digest: bytes) -> tuple[int, int, int]:
    key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
    # RFC 6979 deterministic nonces: the same message always yields the same
    # signature, and signing never depends on the quality of a random source.
    r, s = utils.decode_dss_signature(
        key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
    )
    numbers = key.public_key().public_numbers()
    target = (numbers.x, numbers.y)
    z = int.from_bytes(digest, "big")
    recovery_id = next((i for i in range(4) if _recover_point(z, r, s, i) == target), None)
    if recovery_id is None:
        raise EvmError("could not derive the signature recovery id")
    if s > SECP256K1_N // 2:  # canonical low-s, as the contracts require
        s = SECP256K1_N - s
        recovery_id ^= 1
    return r, s, recovery_id


def sign_digest(private_key: bytes | str, digest: bytes) -> str:
    """Return a 65-byte r||s||v (v = 27/28) signature as 0x-hex."""
    key = parse_private_key(private_key) if isinstance(private_key, str) else private_key
    if len(digest) != 32:
        raise EvmError("digest must be 32 bytes")
    r, s, recovery_id = _sign(key, digest)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + recovery_id]).hex()


def recover_address(digest: bytes, signature: str) -> str:
    raw = bytes.fromhex(signature[2:] if str(signature).startswith("0x") else str(signature))
    if len(raw) != 65 or len(digest) != 32:
        raise EvmError("signature must be 65 bytes over a 32-byte digest")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64] - 27 if raw[64] >= 27 else raw[64]
    if not (0 < r < SECP256K1_N and 0 < s <= SECP256K1_N // 2 and v in (0, 1)):
        raise EvmError("signature is not canonical")
    point = _recover_point(int.from_bytes(digest, "big"), r, s, v)
    if point is None:
        raise EvmError("signature does not recover a public key")
    return "0x" + keccak256(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[-20:].hex()


# ---------------- ABI encoding ----------------
#
# Types: "uint256", "uint64", "uint16", "uint8", "bool", "address", "bytes32",
# "bytes", "string", tuples as ("tuple", [types]) and dynamic arrays as
# ("array", type).

def _is_dynamic(kind: Any) -> bool:
    if kind in ("bytes", "string"):
        return True
    if isinstance(kind, tuple):
        if kind[0] == "array":
            return True
        if kind[0] == "tuple":
            return any(_is_dynamic(item) for item in kind[1])
    return False


def _encode_static(kind: str, value: Any) -> bytes:
    if kind.startswith("uint"):
        number = int(value)
        if number < 0 or number >= 1 << int(kind[4:] or 256):
            raise EvmError(f"{kind} out of range: {value}")
        return number.to_bytes(32, "big")
    if kind == "bool":
        return (1 if value else 0).to_bytes(32, "big")
    if kind == "address":
        return bytes(12) + bytes.fromhex(normalize_address(value)[2:])
    if kind == "bytes32":
        return bytes.fromhex(normalize_bytes32(value)[2:])
    raise EvmError(f"unsupported ABI type: {kind}")


def _encode_value(kind: Any, value: Any) -> bytes:
    if kind in ("bytes", "string"):
        raw = value.encode("utf-8") if kind == "string" else _as_bytes(value)
        return len(raw).to_bytes(32, "big") + raw + bytes(-len(raw) % 32)
    if isinstance(kind, tuple) and kind[0] == "tuple":
        return abi_encode(kind[1], list(value))
    if isinstance(kind, tuple) and kind[0] == "array":
        items = list(value)
        return len(items).to_bytes(32, "big") + abi_encode([kind[1]] * len(items), items)
    return _encode_static(kind, value)


def abi_encode(types: Sequence[Any], values: Sequence[Any]) -> bytes:
    if len(types) != len(values):
        raise EvmError("ABI types and values differ in length")
    heads: list[bytes] = []
    tails: list[bytes] = []
    head_size = sum(32 if _is_dynamic(kind) else len(_encode_value(kind, value)) for kind, value in zip(types, values))
    offset = head_size
    for kind, value in zip(types, values):
        encoded = _encode_value(kind, value)
        if _is_dynamic(kind):
            heads.append(offset.to_bytes(32, "big"))
            tails.append(encoded)
            offset += len(encoded)
        else:
            heads.append(encoded)
    return b"".join(heads) + b"".join(tails)


def function_selector(signature: str) -> bytes:
    return keccak256(signature.encode("ascii"))[:4]


def encode_call(signature: str, types: Sequence[Any], values: Sequence[Any]) -> str:
    return "0x" + (function_selector(signature) + abi_encode(types, values)).hex()


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    text = str(value)
    return bytes.fromhex(text[2:] if text.startswith("0x") else text)


def decode_words(data: str | bytes, count: int) -> list[bytes]:
    raw = _as_bytes(data)
    if len(raw) < count * 32:
        raise EvmError("ABI result is too short")
    return [raw[index * 32:(index + 1) * 32] for index in range(count)]


def word_to_address(word: bytes) -> str:
    if any(word[:12]):
        raise EvmError("ABI word is not an address")
    return "0x" + word[12:].hex()


# ---------------- EIP-712 ----------------

DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)


def domain_separator(name: str, version: str, chain_id: int, verifying_contract: str) -> bytes:
    return keccak256(abi_encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        ["0x" + DOMAIN_TYPEHASH.hex(), "0x" + keccak256(name.encode()).hex(),
         "0x" + keccak256(version.encode()).hex(), chain_id, verifying_contract],
    ))


def typed_data_digest(domain: bytes, struct_hash: bytes) -> bytes:
    return keccak256(b"\x19\x01" + domain + struct_hash)


# ---------------- transactions ----------------

def rlp_encode(value: Any) -> bytes:
    if isinstance(value, int):
        if value < 0:
            raise EvmError("RLP cannot encode negative integers")
        return _rlp_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b"")
    if isinstance(value, bytes):
        return _rlp_bytes(value)
    if isinstance(value, list):
        return _rlp_prefix(b"".join(rlp_encode(item) for item in value), 0xC0)
    raise EvmError(f"unsupported RLP value: {type(value).__name__}")


def _rlp_bytes(value: bytes) -> bytes:
    if len(value) == 1 and value[0] < 0x80:
        return value
    return _rlp_prefix(value, 0x80)


def _rlp_prefix(payload: bytes, offset: int) -> bytes:
    if len(payload) <= 55:
        return bytes([offset + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(length)]) + length + payload


def sign_legacy_transaction(
    private_key: bytes | str, *, nonce: int, gas_price: int, gas_limit: int,
    to: str | None, value: int, data: bytes, chain_id: int,
) -> bytes:
    """EIP-155 legacy transaction, accepted on every EVM chain we target."""
    key = parse_private_key(private_key) if isinstance(private_key, str) else private_key
    recipient = b"" if to is None else bytes.fromhex(normalize_address(to)[2:])
    fields = [nonce, gas_price, gas_limit, recipient, value, data]
    r, s, recovery_id = _sign(key, keccak256(rlp_encode(fields + [chain_id, 0, 0])))
    return rlp_encode(fields + [chain_id * 2 + 35 + recovery_id, r, s])
