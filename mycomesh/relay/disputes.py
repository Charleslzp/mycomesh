"""Relay dispute desk: hold evidence, finalize drand juries, gather juror votes.

The desk has no authority of its own. The disputing owner commits the evidence
hash on-chain; the registry draws the jury from a future drand round; every
juror re-checks the case against the chain before signing; the settlement
contract accepts only a threshold of consistent votes from the drawn jurors.
Any party can run a desk, and a silent desk only delays the timeout refund.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .. import jury, rpc
from ..evm import encode_call
from ..protocol import ProtocolError
from ..settlement import SettlementError
from .core import RelayCore, RelayError

log = logging.getLogger("mycomesh.relay.disputes")

# round -> 128-byte uncompressed G1 signature (raises until the round is published)
BeaconSource = Callable[[int], bytes]


class DisputeDesk:
    def __init__(self, core: RelayCore, cases: jury.CaseReader, submitter_private: str, rpc_url: str,
                 *, beacon: BeaconSource = jury.fetch_drand_signature) -> None:
        self.core = core
        self.cases = cases
        self.submitter_private = submitter_private
        self.rpc_url = rpc_url
        self.beacon = beacon
        self._db = sqlite3.connect(Path(core.data_dir) / "relay-disputes.sqlite3", timeout=30,
                                   isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS cases (settlement_key TEXT PRIMARY KEY, report_id TEXT NOT NULL, "
            "evidence_hash TEXT NOT NULL, evidence TEXT NOT NULL, state TEXT NOT NULL, updated_at INTEGER NOT NULL)"
        )
        self._lock = threading.Lock()
        # settlement key -> juror signer -> signed permit or None (abstained / unreachable this round)
        self._answers: dict[str, dict[str, dict[str, Any] | None]] = {}

    # ---------------- evidence ----------------

    def submit_evidence(self, evidence: Any) -> dict[str, Any]:
        """Accept evidence only once its hash is the one the owner committed on-chain."""
        try:
            signed, _, _ = jury.verify_evidence(evidence, self.core.deployment)
        except (jury.JuryError, SettlementError, ProtocolError, ValueError, TypeError) as exc:
            raise RelayError(f"invalid evidence: {exc}") from exc
        key = signed.authorization.settlement_key
        digest = jury.evidence_hash(evidence)
        record = self.cases.settlement(key)
        report = jury.report_id(key, record["owner"], digest)
        if record["status"] != "disputed" or self.cases.report_evidence(key, report) != digest:
            raise RelayError("no open dispute commits to this evidence", 409)
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO cases VALUES (?, ?, ?, ?, 'open', ?)",
                (key, report, digest, json.dumps(evidence, sort_keys=True), int(time.time())),
            )
        return {"settlement_key": key, "report_id": report, "evidence_hash": digest}

    def evidence(self, digest: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT evidence FROM cases WHERE evidence_hash=?", (digest.lower(),)).fetchone()
        return None if row is None else json.loads(row[0])

    def open_cases(self) -> list[tuple[str, str, dict[str, Any]]]:
        with self._lock:
            rows = self._db.execute("SELECT settlement_key, report_id, evidence FROM cases WHERE state='open'").fetchall()
        return [(key, report, json.loads(evidence)) for key, report, evidence in rows]

    def state(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT state FROM cases WHERE settlement_key=?", (key,)).fetchone()
        return None if row is None else row[0]

    def _close(self, key: str, state: str) -> None:
        with self._lock:
            self._db.execute("UPDATE cases SET state=?, updated_at=? WHERE settlement_key=?", (state, int(time.time()), key))
        self._answers.pop(key, None)

    # ---------------- adjudication ----------------

    def cycle(self) -> list[tuple[str, str]]:
        """Advance every open case one step; returns (settlement key, action) pairs."""
        actions = []
        for key, report, evidence in self.open_cases():
            try:
                action = self._advance(key, report, evidence)
            except (rpc.RpcError, jury.JuryError, OSError, ValueError) as exc:
                log.warning("dispute %s: %s", key, exc)
                action = None
            if action:
                actions.append((key, action))
        return actions

    def _advance(self, key: str, report: str, evidence: Mapping[str, Any]) -> str | None:
        status = self.cases.settlement(key)["status"]
        if status != "disputed":
            self._close(key, status)
            return status
        if rpc.block_time(self.rpc_url) >= self.cases.resolve_at(key):
            self._submit(self.core.deployment.settlement, encode_call("resolveTimedOutDispute(bytes32)", ["bytes32"], [key]))
            self._close(key, self.cases.settlement(key)["status"])
            return "timed_out"
        assignment = self.cases.assignment(key)
        if assignment["status"] == "pending":
            if rpc.block_time(self.rpc_url) < jury.round_time(assignment["round"]):
                return None
            self._submit(self.cases.registry, jury.encode_finalize_jury(key, self.beacon(assignment["round"])))
            return "jury_drawn"
        if assignment["status"] == "ready":
            return self._gather(key, report, evidence, assignment)
        return None  # failed: no eligible jury; the timeout refunds the owner

    def _gather(self, key: str, report: str, evidence: Mapping[str, Any], assignment: Mapping[str, Any]) -> str | None:
        answers = self._answers.setdefault(key, {})
        # A juror's registry vote signer is its Provider signer, so the Relay reaches it over its link.
        with self.core._lock:
            reachable = {signer: self.core.providers[signer].send for signer in assignment["juror_signers"]
                         if signer in self.core.providers and signer not in answers}
        job = {"kind": "jury", "settlement_key": key, "report_id": report, "evidence": dict(evidence)}

        def ask(item: tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]) -> tuple[str, dict[str, Any] | None]:
            signer, send = item
            try:
                result = send(job)
            except Exception as exc:  # unreachable jurors are asked again next cycle
                log.info("juror %s did not answer: %s", signer, exc)
                return signer, {"retry": True}
            return signer, None if result.get("abstain") else result

        if reachable:
            with ThreadPoolExecutor(max_workers=len(reachable)) as pool:
                for signer, permit in pool.map(ask, reachable.items()):
                    # Abstentions are final; retries and stale permits are not recorded.
                    if permit is None or permit.get("assignment_hash") == assignment["hash"]:
                        answers[signer] = permit
        threshold = self.cases.threshold()
        groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for permit in answers.values():
            if permit is not None:
                groups.setdefault((permit["confirmed"], permit["report_id"], permit["decision_hash"]), []).append(permit)
        for (confirmed, _, _), permits in groups.items():
            if len(permits) >= threshold:
                self._submit(self.core.deployment.settlement, jury.encode_votes(key, permits[:threshold]))
                self._close(key, "confirmed" if confirmed else "dismissed")
                return "confirmed" if confirmed else "dismissed"
        return None

    def _submit(self, to: str, calldata: str) -> None:
        tx = rpc.send_transaction(self.rpc_url, self.submitter_private, to=to, data=calldata)
        rpc.wait_for_receipt(self.rpc_url, tx)

