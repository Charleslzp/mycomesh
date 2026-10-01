"""Relay side of on-chain inference: watch the oracle, dispatch to a Provider of the tier, fulfil.

Any Relay may serve any request (the first valid fulfilment wins); the Relay
pays the fulfilment gas and earns its usual share of the fee. It also hands
over answers that wait for the dispute window, and returns the reservation of
requests nobody answered.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .. import oracle as onchain
from .. import rpc
from ..protocol import b64decode, b64encode
from ..settlement import Authorization, Receipt, SettlementError, sign_dispatch
from .core import RelayCore

log = logging.getLogger("mycomesh.relay.onchain")
FINAL_STATUSES = {"released", "dismissed", "timed_out"}


class OracleDispatcher:
    def __init__(self, core: RelayCore, reader: onchain.OracleReader, cases: Any, rpc_url: Any, submitter_private: str,
                 *, start_block: int = 0, log_chunk: int = 2_000, expire_grace: int = 120) -> None:
        self.core, self.reader, self.cases = core, reader, cases
        self.rpc_url = rpc_url
        self.submitter_private = submitter_private
        self.start_block = start_block
        self.log_chunk = log_chunk
        self.expire_grace = expire_grace
        path = Path(core.data_dir) / "relay-oracle.sqlite3"
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY CHECK (id = 1), block INTEGER NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY, request TEXT NOT NULL, "
                         "state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, response TEXT, settlement_key TEXT)")
        self._lock = threading.Lock()

    # ---------------- discovery ----------------

    def scan(self) -> int:
        row = self._db.execute("SELECT block FROM cursor WHERE id=1").fetchone()
        start = self.start_block if row is None else row[0]
        head = rpc.quantity(rpc.call(self.rpc_url, "eth_blockNumber", []))
        found = 0
        while start <= head:
            end = min(head, start + self.log_chunk - 1)
            try:
                requests = self.reader.requests(start, end)
            except rpc.RpcError as exc:
                if "beyond current head" in str(exc):  # a load-balanced RPC a block behind: next cycle
                    break
                raise
            for item in requests:
                record = {**item.__dict__, "prompt": b64encode(item.prompt)}
                self._db.execute("INSERT OR IGNORE INTO requests (request_id, request, state) VALUES (?, ?, 'open')",
                                 (item.request_id, json.dumps(record)))
                found += 1
            self._db.execute("INSERT OR REPLACE INTO cursor VALUES (1, ?)", (end + 1,))
            start = end + 1
        return found

    # ---------------- serving ----------------

    def cycle(self) -> list[tuple[str, str]]:
        self.scan()
        done = []
        now = rpc.block_time(self.rpc_url)
        for request_id, raw, state, attempts, response, key in self._db.execute(
                "SELECT request_id, request, state, attempts, response, settlement_key FROM requests "
                "WHERE state IN ('open', 'answered')").fetchall():
            item = json.loads(raw)
            try:
                if state == "open":
                    action = self._serve(request_id, item, attempts, now)
                else:
                    action = self._deliver(request_id, item, b64decode(response), key)
            except Exception as exc:  # one request's failure (a busy Provider, a lost race) never stops the rest
                log.warning("on-chain request %s: %s", request_id, exc)
                action = None
            if action:
                done.append((request_id, action))
        return done

    def _mark(self, request_id: str, state: str, **fields: Any) -> None:
        sets = ", ".join(["state=?"] + [f"{name}=?" for name in fields])
        self._db.execute(f"UPDATE requests SET {sets} WHERE request_id=?", (state, *fields.values(), request_id))

    def _serve(self, request_id: str, item: dict[str, Any], attempts: int, now: int) -> str | None:
        info = self.reader.info(request_id)
        if info["state"] != "open":  # another Relay answered, or it expired
            self._mark(request_id, info["state"])
            return info["state"]
        if now > info["deadline"]:
            if now > info["deadline"] + self.expire_grace:  # give the requester its reservation back
                self._submit(onchain.encode_expire(request_id))
                self._mark(request_id, "expired")
                return "expired"
            return None
        with self.core._lock:
            sessions = [(signer, session) for signer, session in self.core.providers.items()
                        if signer not in self.core.suspended
                        and int(session.descriptor.get("tier") or 0) == item["tier"]
                        and item["model"] in session.descriptor.get("models", [])]
        if not sessions:
            return None
        signer, session = sessions[attempts % len(sessions)]
        self._db.execute("UPDATE requests SET attempts=attempts+1 WHERE request_id=?", (request_id,))
        result = session.send({"kind": "onchain", "request_id": request_id, "model": item["model"], "prompt": item["prompt"],
                               "max_output_tokens": item["max_output_tokens"], "relay_signer": self.core.signer})
        authorization = Authorization.from_payload(result["authorization"])
        if authorization.relay_signer != self.core.signer or authorization.provider_signer != signer:
            raise SettlementError("the Provider signed for another Relay or signer")
        signed = onchain.unsigned_receipt(authorization, Receipt.from_payload(result["receipt"]), result["provider_signature"],
                                          sign_dispatch(self.core.relay_private, authorization, self.core.deployment))
        response = onchain.response_from(result)
        request = onchain.OnchainRequest(**{**item, "prompt": b64decode(item["prompt"])})
        onchain.verify_answer(signed, request, response, self.core.deployment, self.reader.oracle)
        self._submit(onchain.encode_fulfill(request_id, signed, response))
        final = item["finality"] == "immediate"
        self._mark(request_id, "delivered" if final else "answered", response=b64encode(response),
                   settlement_key=authorization.settlement_key)
        return "delivered" if final else "answered"

    def _deliver(self, request_id: str, item: dict[str, Any], response: bytes, key: str) -> str | None:
        status = self.cases.settlement(key)["status"]
        if status == "confirmed":  # the answer was judged fraudulent: never delivered, the fee was refunded
            self._mark(request_id, "fraud")
            return "fraud"
        if status not in FINAL_STATUSES:
            return None
        if self.reader.info(request_id)["state"] == "answered":
            self._submit(onchain.encode_deliver(request_id, response))
        self._mark(request_id, "delivered")
        return "delivered"

    def _submit(self, data: str) -> None:
        rpc.wait_for_receipt(self.rpc_url, rpc.send_transaction(self.rpc_url, self.submitter_private,
                                                                to=self.reader.oracle, data=data))


def oracle_loop(dispatcher: OracleDispatcher, stop: threading.Event, *, interval: float = 5.0) -> None:
    while not stop.wait(interval):
        try:
            for request_id, action in dispatcher.cycle():
                log.info("on-chain request %s: %s", request_id, action)
        except Exception as exc:  # keep following the oracle
            log.warning("oracle cycle failed: %s", exc)
