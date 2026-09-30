"""Ethereum V3 keystores (the format MetaMask and geth use), so owner keys need not be plaintext files."""
from __future__ import annotations

import json
import os
import secrets
import uuid
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

from .evm import address_of, keccak256

PASSWORD_ENV = "MYCOMESH_KEY_PASSWORD"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 15, 8, 1


class KeystoreError(ValueError):
    pass


def _ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return cipher.update(data) + cipher.finalize()


def encrypt(private_key: str, password: str) -> dict[str, Any]:
    if len(password) < 8:
        raise KeystoreError("use a key password of at least 8 characters")
    salt, iv = secrets.token_bytes(32), secrets.token_bytes(16)
    derived = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode())
    ciphertext = _ctr(derived[:16], iv, bytes.fromhex(private_key.removeprefix("0x")))
    return {"version": 3, "id": str(uuid.uuid4()), "address": address_of(private_key)[2:],
            "crypto": {"cipher": "aes-128-ctr", "cipherparams": {"iv": iv.hex()}, "ciphertext": ciphertext.hex(),
                       "kdf": "scrypt", "kdfparams": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": 32, "salt": salt.hex()},
                       "mac": keccak256(derived[16:32] + ciphertext).hex()}}


def decrypt(keystore: dict[str, Any], password: str) -> str:
    crypto = keystore.get("crypto") or keystore.get("Crypto") or {}
    if keystore.get("version") != 3 or crypto.get("cipher") != "aes-128-ctr":
        raise KeystoreError("unsupported keystore")
    params, salt = crypto["kdfparams"], bytes.fromhex(crypto["kdfparams"]["salt"])
    if crypto["kdf"] == "scrypt":
        derived = Scrypt(salt=salt, length=params["dklen"], n=params["n"], r=params["r"], p=params["p"]).derive(password.encode())
    elif crypto["kdf"] == "pbkdf2" and params.get("prf") == "hmac-sha256":
        derived = PBKDF2HMAC(hashes.SHA256(), params["dklen"], salt, params["c"]).derive(password.encode())
    else:
        raise KeystoreError(f"unsupported keystore KDF {crypto['kdf']}")
    ciphertext = bytes.fromhex(crypto["ciphertext"])
    if keccak256(derived[16:32] + ciphertext).hex() != crypto["mac"].lower():
        raise KeystoreError("wrong key password")
    private = "0x" + _ctr(derived[:16], bytes.fromhex(crypto["cipherparams"]["iv"]), ciphertext).hex()
    if keystore.get("address") and address_of(private)[2:] != keystore["address"].lower().removeprefix("0x"):
        raise KeystoreError("keystore address does not match its key")
    return private


def read(text: str, password: str | None = None) -> str:
    """A key file's private key: raw hex, or a keystore unlocked with MYCOMESH_KEY_PASSWORD."""
    text = text.strip()
    if not text.startswith("{"):
        return text if text.startswith("0x") else "0x" + text
    secret = password if password is not None else os.environ.get(PASSWORD_ENV)
    if not secret:
        raise KeystoreError(f"this key is encrypted; set {PASSWORD_ENV}")
    return decrypt(json.loads(text), secret)
