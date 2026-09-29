"""Bridge keeper: the permissionless backstop for every settlement on the network.

Relays release their own receipts and gather jury votes. A keeper follows the
contract logs instead and, after a grace period, performs the calls anyone may
make: ``release`` for escrow past its dispute window, ``finalizeJury`` once a
case's drand round is published, and ``resolveTimedOutDispute`` for silent
juries. Nothing here needs a Relay to be honest or online.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import jury, rpc
from .evm import encode_call, keccak256
from .settlement import encode_release

log = logging.getLogger("mycomesh.keeper")

RECEIPT_ESCROWED = "0x" + keccak256(b"ReceiptEscrowed(bytes32,bytes32,address,address,uint256,uint256)").hex()
DISPUTE_OPENED = "0x" + keccak256(b"DisputeOpened(bytes32,uint256)").hex()
JURY_REQUESTED = "0x" + keccak256(b"JuryRequested(bytes32,uint64,bytes32,uint256)").hex()


@dataclass
class Keeper:
    cases: jury.CaseReader
    key_private: str
    data_dir: Path
    start_block: int
    grace: int = 3_600
    log_chunk: int = 2_000
    beacon: Callable[[int], bytes] = jury.fetch_drand_signature

    def __post_init__(self) -> None:
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(Path(self.data_dir) / "keeper.sqlite3", timeout=30, isolation_level=None,
                                   check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY CHECK (id = 1), block INTEGER NOT NULL)")
        # kind: release | dispute | jury; due: chain time after which the call is attempted
        self._db.execute("CREATE TABLE IF NOT EXISTS duties (settlement_key TEXT NOT NULL, kind TEXT NOT NULL, "
                         "due INTEGER NOT NULL, PRIMARY KEY (settlement_key, kind))")

    @property
    def rpc(self) -> str:
        return self.cases.rpc

    def _cursor(self) -> int:
        row = self._db.execute("SELECT block FROM cursor WHERE id=1").fetchone()
        return self.start_block if row is None else row[0]

    def scan(self) -> int:
        """Record new duties from the logs; returns the number found."""
        head = rpc.quantity(rpc.call(self.rpc, "eth_blockNumber", []))
        start, found = self._cursor(), 0
        while start <= head:
            end = min(head, start + self.log_chunk - 1)
            for entry in rpc.call(self.rpc, "eth_getLogs", [{
                "fromBlock": hex(start), "toBlock": hex(end),
                "address": [self.cases.deployment.settlement, self.cases.registry],
                "topics": [[RECEIPT_ESCROWED, DISPUTE_OPENED, JURY_REQUESTED]],
            }]):
                topic, key = entry["topics"][0], entry["topics"][1]
                data = bytes.fromhex(entry["data"][2:])
                if topic == RECEIPT_ESCROWED:
                    duty = ("release", int.from_bytes(data[64:96], "big") + self.grace)
                elif topic == DISPUTE_OPENED:
                    duty = ("dispute", int.from_bytes(data[:32], "big") + self.grace)
                else:
                    duty = ("jury", jury.round_time(int.from_bytes(data[:32], "big")) + self.grace // 12)
                self._db.execute("INSERT OR REPLACE INTO duties VALUES (?, ?, ?)", (key, *duty))
                found += 1
            self._db.execute("INSERT OR REPLACE INTO cursor VALUES (1, ?)", (end + 1,))
            start = end + 1
        return found

    def act(self) -> list[tuple[str, str]]:
        """Perform every due duty that is still needed."""
        now = rpc.block_time(self.rpc)
        done = []
        for key, kind in self._db.execute("SELECT settlement_key, kind FROM duties WHERE due <= ?", (now,)).fetchall():
            try:
                action = self._perform(key, kind)
            except (rpc.RpcError, jury.JuryError, OSError, ValueError) as exc:
                log.warning("keeper %s %s: %s", kind, key, exc)
                continue
            self._db.execute("DELETE FROM duties WHERE settlement_key=? AND kind=?", (key, kind))
            if action:
                done.append((key, action))
        return done

    def _perform(self, key: str, kind: str) -> str | None:
        status = self.cases.settlement(key)["status"]
        if kind == "release":
            if status != "pending":
                return None
            self._send(self.cases.deployment.settlement, encode_release(key))
            return "released"
        if kind == "dispute":
            if status != "disputed":
                return None
            self._send(self.cases.deployment.settlement,
                       encode_call("resolveTimedOutDispute(bytes32)", ["bytes32"], [key]))
            return "timed_out"
        assignment = self.cases.assignment(key)
        if status != "disputed" or assignment["status"] != "pending":
            return None
        self._send(self.cases.registry, jury.encode_finalize_jury(key, self.beacon(assignment["round"])))
        return "jury_drawn"

    def _send(self, to: str, calldata: str) -> None:
        rpc.wait_for_receipt(self.rpc, rpc.send_transaction(self.rpc, self.key_private, to=to, data=calldata))

    def run(self, stop: threading.Event, *, interval: float = 60.0) -> None:
        while not stop.is_set():
            try:
                self.scan()
                for key, action in self.act():
                    log.info("keeper %s: %s", key, action)
            except Exception as exc:  # keep following the chain
                log.warning("keeper cycle failed: %s", exc)
            stop.wait(interval)
