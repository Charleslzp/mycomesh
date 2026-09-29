"""Testnet faucet: a little ETH for gas and some tUSDC, so a new Consumer needs nothing else."""
from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import rpc
from ..evm import address_of, encode_call, normalize_address
from .core import RelayError

DAY = 86_400


@dataclass
class Faucet:
    key_private: str
    rpc_url: Any
    stablecoin: str
    data_dir: Path
    eth_wei: int = 2 * 10**16
    usdc_units: int = 100_000_000
    per_ip_per_day: int = 5
    per_day: int = 500

    def __post_init__(self) -> None:
        self.address = address_of(self.key_private)
        self._db = sqlite3.connect(Path(self.data_dir) / "faucet.sqlite3", timeout=30, isolation_level=None,
                                   check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS grants (address TEXT NOT NULL, ip TEXT NOT NULL, at INTEGER NOT NULL)")
        # One grant at a time keeps the faucet account's nonces in order.
        self._lock = threading.Lock()

    def grant(self, payload: dict[str, Any], ip: str) -> dict[str, Any]:
        try:
            address = normalize_address(payload.get("address"))
        except (ValueError, TypeError) as exc:
            raise RelayError("address is invalid") from exc
        now = int(time.time())
        with self._lock:
            recent = lambda column, value: self._db.execute(  # noqa: E731
                f"SELECT COUNT(*) FROM grants WHERE {column}=? AND at>?", (value, now - DAY)).fetchone()[0]
            if recent("address", address):
                raise RelayError("this address was funded in the last 24 hours", 429)
            if recent("ip", ip) >= self.per_ip_per_day:
                raise RelayError("too many faucet requests from this network today", 429)
            if self._db.execute("SELECT COUNT(*) FROM grants WHERE at>?", (now - DAY,)).fetchone()[0] >= self.per_day:
                raise RelayError("the faucet's daily budget is spent", 429)
            txs = {}
            balance = rpc.quantity(rpc.call(self.rpc_url, "eth_getBalance", [address, "latest"]))
            if balance < self.eth_wei:
                txs["eth"] = self._send(address, b"", self.eth_wei)
            txs["usdc"] = self._send(self.stablecoin, encode_call(
                "mint(address,uint256)", ["address", "uint256"], [address, self.usdc_units]), 0)
            self._db.execute("INSERT INTO grants VALUES (?, ?, ?)", (address, ip, now))
        return {"address": address, "eth_wei": self.eth_wei if "eth" in txs else 0, "usdc_units": self.usdc_units,
                "transactions": txs}

    def _send(self, to: str, data: Any, value: int) -> str:
        try:
            tx = rpc.send_transaction(self.rpc_url, self.key_private, to=to, data=data, value=value)
            rpc.wait_for_receipt(self.rpc_url, tx, timeout=180)
        except rpc.RpcError as exc:
            raise RelayError(f"faucet transaction failed: {exc}", 503) from exc
        return tx
