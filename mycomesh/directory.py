"""Relay discovery from the permissionless on-chain RelayDirectoryV11."""
from __future__ import annotations

from typing import Any

from . import rpc
from .evm import decode_words, encode_call, word_to_address


def _int(word: bytes) -> int:
    return int.from_bytes(word, "big")


def _string(raw: bytes, offset: int) -> str:
    length = _int(raw[offset:offset + 32])
    return raw[offset + 32:offset + 32 + length].decode("utf-8", "replace")


def list_relays(rpc_url: Any, directory: str) -> list[dict[str, Any]]:
    """Every announced Relay; ``active`` is false once its signer is no longer bound to its owner."""
    count = _int(decode_words(rpc.eth_call(rpc_url, directory, encode_call("relayCount()", [], [])), 1)[0])
    relays = []
    for index in range(count):
        raw = bytes.fromhex(rpc.eth_call(rpc_url, directory, encode_call("relayAt(uint256)", ["uint256"], [index]))[2:])
        base = _int(raw[:32])
        active = bool(_int(raw[32:64]))
        entry = raw[base:]
        relays.append({
            "owner": word_to_address(entry[0:32]), "signer": word_to_address(entry[32:64]),
            "url": _string(entry, _int(entry[64:96])).rstrip("/"), "link": _string(entry, _int(entry[96:128])),
            "updated_at": _int(entry[128:160]), "active": active,
        })
    return relays


def encode_announce(signer: str, url: str, link: str) -> str:
    return encode_call("announce(address,string,string)", ["address", "string", "string"], [signer, url, link])
