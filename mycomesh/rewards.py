"""MYCO rewards: find the blocks an account earned in, show what is claimable, claim it."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import rpc
from .evm import decode_words, encode_call, keccak256

POINTS = "0x" + keccak256(b"Points(uint64,uint8,address,uint256)").hex()
ROLES = {0: "consumer", 1: "provider", 2: "relay", 3: "bridge"}
LOG_CHUNK = 10_000
CLAIM_BATCH = 100


def _word(rpc_url: Any, to: str, signature: str, types: list[Any], values: list[Any]) -> int:
    return int.from_bytes(decode_words(rpc.eth_call(rpc_url, to, encode_call(signature, types, values)), 1)[0], "big")


def earned_blocks(rpc_url: Any, emission: str, account: str, from_block: int) -> dict[int, set[int]]:
    """role -> emission blocks in which the account earned points (from the Points events)."""
    head = rpc.quantity(rpc.call(rpc_url, "eth_blockNumber", []))
    topic = "0x" + account.lower().removeprefix("0x").rjust(64, "0")
    found: dict[int, set[int]] = defaultdict(set)
    for start in range(from_block, head + 1, LOG_CHUNK):
        for entry in rpc.call(rpc_url, "eth_getLogs", [{
            "address": emission, "topics": [POINTS, None, None, topic],
            "fromBlock": hex(start), "toBlock": hex(min(head, start + LOG_CHUNK - 1)),
        }]):
            found[int(entry["topics"][2], 16)].add(int(entry["topics"][1], 16))
    return found


def summary(rpc_url: Any, emission: str, token: str | None, account: str, from_block: int) -> dict[str, Any]:
    roles = {}
    for role, blocks in earned_blocks(rpc_url, emission, account, from_block).items():
        claimable, waiting = 0, 0
        for block in sorted(blocks):
            amount = _word(rpc_url, emission, "claimable(uint64,uint8,address)", ["uint64", "uint8", "address"], [block, role, account])
            held = _word(rpc_url, emission, "points(uint64,uint8,address)", ["uint64", "uint8", "address"], [block, role, account])
            if amount:
                claimable += amount
            elif held:
                waiting += 1  # not final yet, or a Provider block inside its 48-hour delay
        roles[ROLES[role]] = {"claimable_wei": claimable, "blocks_waiting": waiting, "blocks": len(blocks)}
    return {
        "account": account, "roles": roles,
        "myco_balance_wei": _word(rpc_url, token, "balanceOf(address)", ["address"], [account]) if token else None,
        "bounty_owed": _word(rpc_url, emission, "bountyOwed(address)", ["address"], [account]),
    }


def finalize(rpc_url: Any, emission: str, key_private: str) -> bool:
    """Close the last active block if its hour is over (nobody has touched the emission since)."""
    open_block = _word(rpc_url, emission, "openBlock()", [], [])
    if not _word(rpc_url, emission, "hasOpen()", [], []) or open_block >= _word(rpc_url, emission, "currentBlock()", [], []):
        return False
    rpc.wait_for_receipt(rpc_url, rpc.send_transaction(rpc_url, key_private, to=emission, data=encode_call("poke()", [], [])))
    return True


def claim(rpc_url: Any, emission: str, key_private: str, account: str, from_block: int) -> dict[str, Any]:
    """Claim every claimable block in every role, then any stablecoin bounty."""
    claimed: dict[str, int] = {}
    finalize(rpc_url, emission, key_private)
    for role, blocks in earned_blocks(rpc_url, emission, account, from_block).items():
        ready = [b for b in sorted(blocks) if _word(rpc_url, emission, "claimable(uint64,uint8,address)",
                                                    ["uint64", "uint8", "address"], [b, role, account])]
        for start in range(0, len(ready), CLAIM_BATCH):
            data = encode_call("claim(uint64[],uint8)", [("array", "uint64"), "uint8"], [ready[start:start + CLAIM_BATCH], role])
            rpc.wait_for_receipt(rpc_url, rpc.send_transaction(rpc_url, key_private, to=emission, data=data))
        if ready:
            claimed[ROLES[role]] = len(ready)
    if _word(rpc_url, emission, "bountyOwed(address)", ["address"], [account]):
        rpc.wait_for_receipt(rpc_url, rpc.send_transaction(rpc_url, key_private, to=emission, data=encode_call("claimBounty()", [], [])))
        claimed["bounty"] = 1
    return claimed
