"""Fail-closed V10 monetary-action admission and execution hand-off.

The verifier authenticates an operator-authored action envelope.  The durable
execution store adds the missing safety boundary for an automatic worker:
action IDs and nonces are committed before a callback is invoked, and an
uncertain callback is never retried automatically.  This module still does
not own a wallet or broadcast a transaction.  A caller may hand the returned
EVM vote plan to a separately funded, policy-capped keeper.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Mapping
from collections.abc import Callable

from . import chain, chain_v10
from .identity import IdentityError, verify_document
from .relay_incidents import evidence_hash


class V10EnforcementError(ValueError):
    pass


APPROVAL_PURPOSE = "mycomesh.v10.monetary-approval.v1"
ACTION_SCHEMA = "mycomesh.v10.monetary-action.v1"
PLAN_SCHEMA = "mycomesh.v10.monetary-plan.v1"
EVM_VOTE_SCHEMA = "mycomesh.v10.evm-vote.v1"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _action_hash(action: Mapping[str, Any]) -> str:
    return evidence_hash({key: value for key, value in action.items()
                          if key != "user_signatures"})


def _required_replay_fields(action: Mapping[str, Any]) -> tuple[str, int]:
    action_id = action.get("action_id")
    if not isinstance(action_id, str) or not action_id.strip() or action_id != action_id.strip() or len(action_id) > 160:
        raise V10EnforcementError("a bounded action_id is required for automatic execution")
    nonce = action.get("nonce")
    if type(nonce) is not int or nonce < 0 or nonce >= 2**256:
        raise V10EnforcementError("a uint256 action nonce is required for automatic execution")
    return action_id, nonce


def _decision_hash(action: Mapping[str, Any]) -> str:
    """Commit the exact case and operation without creating a hash cycle."""
    body = {key: value for key, value in action.items()
            if key not in {"user_signatures", "decision_hash"}}
    execution = body.get("execution")
    if isinstance(execution, Mapping) and "vote_permits" in execution:
        # EVM permits sign this decision hash, so their signatures cannot be
        # included in the value they sign. Their own typed-data signatures
        # still bind the exact target, outcome, nonce and deadline.
        body["execution"] = {key: value for key, value in execution.items()
                              if key not in {"vote_permits", "decision_hash"}}
    return evidence_hash(body)


def _execution_result(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise V10EnforcementError("execution result must be a mapping")
    tx_hash = value.get("tx_hash")
    status = value.get("status")
    if (not isinstance(tx_hash, str) or not tx_hash.startswith("0x")
            or status not in {"submitted", "confirmed"}):
        raise V10EnforcementError("execution result must contain a bounded transaction status")
    return dict(value)


def verify_monetary_action(
    action: Mapping[str, Any], *, evidence: Mapping[str, Any],
    high_reputation_users: Mapping[str, int], required_reputation: int = 80,
    statutory_votes: int, required_votes: int, now: int | None = None,
    high_reputation_operators: Mapping[str, str] | None = None,
    require_replay_fields: bool = False,
) -> dict[str, Any]:
    """Return a non-payable, reviewable plan when every independent gate passes.

    ``action`` contains one signed document per high-reputation user under
    ``user_signatures``. Signatures bind the exact evidence hash and action.
    """
    if not isinstance(action, Mapping) or action.get("schema") != ACTION_SCHEMA:
        raise V10EnforcementError("unsupported V10 monetary action")
    if require_replay_fields:
        _required_replay_fields(action)
    if not isinstance(evidence, Mapping) or not evidence:
        raise V10EnforcementError("committed evidence is required")
    if action.get("evidence_hash") != evidence_hash(dict(evidence)):
        raise V10EnforcementError("monetary action evidence commitment mismatch")
    if type(required_reputation) is not int or required_reputation < 0:
        raise V10EnforcementError("invalid reputation threshold")
    if type(required_votes) is not int or required_votes < 1 or type(statutory_votes) is not int:
        raise V10EnforcementError("statutory vote count is invalid")
    if statutory_votes < required_votes:
        raise V10EnforcementError("statutory vote threshold not met")
    signatures = action.get("user_signatures")
    if not isinstance(signatures, list) or not signatures:
        raise V10EnforcementError("independent high-reputation user signatures are required")
    seen: set[str] = set()
    seen_operators: set[str] = set()
    verified = []
    for signed in signatures:
        if not isinstance(signed, dict):
            raise V10EnforcementError("invalid user signature envelope")
        try:
            unsigned = verify_document(signed, APPROVAL_PURPOSE, now=now)
        except (IdentityError, TypeError, ValueError) as exc:
            raise V10EnforcementError("invalid user signature") from exc
        signer = str((signed.get("signature") or {}).get("public_key") or "")
        if signer in seen or signer not in high_reputation_users:
            raise V10EnforcementError("signer is not an independent high-reputation user")
        if high_reputation_users[signer] < required_reputation:
            raise V10EnforcementError("signer reputation is below the required threshold")
        if high_reputation_operators is not None:
            operator = high_reputation_operators.get(signer)
            if not isinstance(operator, str) or not operator.strip():
                raise V10EnforcementError("signer has no pinned operator identity")
            operator_key = operator.strip().casefold()
            if operator_key in seen_operators:
                raise V10EnforcementError("independent approvals share an operator identity")
            seen_operators.add(operator_key)
        if unsigned.get("action_hash") != evidence_hash({k: v for k, v in action.items() if k != "user_signatures"}):
            raise V10EnforcementError("user approval does not bind the action")
        seen.add(signer)
        verified.append(signer)
    if len(verified) < required_votes:
        raise V10EnforcementError("insufficient independent user approvals")
    return {"schema": PLAN_SCHEMA, "payable": False,
            "execution_required": True, "evidence_hash": action["evidence_hash"],
            "approved_by": verified, "statutory_votes": statutory_votes,
            "action_hash": _action_hash(action),
            **({"action_id": action["action_id"], "nonce": action["nonce"]}
               if "action_id" in action and "nonce" in action else {})}


def build_evm_vote_plan(
    action: Mapping[str, Any], *, approved_by: list[str],
    evm_addresses: Mapping[str, str],
) -> dict[str, Any]:
    """Build one signed-approval-to-EVM-vote hand-off, without broadcasting.

    The user approvals are Ed25519 documents, while ``voteDispute`` authorizes
    the EVM adjudicator addresses.  The caller must therefore pin a one-to-one
    mapping from every approved user key to its EVM address.  The returned
    transactions are *permits for a separately funded keeper*; this function
    has no private-key or RPC access.
    """
    _required_replay_fields(action)
    if action.get("operation") not in ("confirm", "dismiss"):
        raise V10EnforcementError("automatic V10 execution requires confirm or dismiss operation")
    if action.get("decision_hash") != _decision_hash(action):
        raise V10EnforcementError("decision hash does not bind the exact action")
    execution = action.get("execution")
    expected_fields = {"schema", "chain_id", "settlement_contract", "settlement_key",
                       "confirmed", "report_id", "decision_hash", "vote_permits"}
    if not isinstance(execution, Mapping) or set(execution) != expected_fields:
        raise V10EnforcementError("complete EVM vote execution target is required")
    if execution.get("schema") != EVM_VOTE_SCHEMA:
        raise V10EnforcementError("unsupported EVM vote execution target")
    if type(execution.get("chain_id")) is not int or execution["chain_id"] <= 0:
        raise V10EnforcementError("EVM vote chain_id is invalid")
    try:
        contract = chain.normalize_address(execution["settlement_contract"])
        settlement_key = chain.normalize_bytes32(execution["settlement_key"])
        report_id = chain.normalize_bytes32(execution["report_id"])
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise V10EnforcementError("EVM vote target contains malformed identifiers") from exc
    if contract != execution["settlement_contract"] or contract == chain.ZERO_ADDRESS:
        raise V10EnforcementError("EVM vote contract must be canonical and nonzero")
    if settlement_key == chain.ZERO_BYTES32:
        raise V10EnforcementError("EVM vote settlement key must be nonzero")
    confirmed = execution.get("confirmed")
    if type(confirmed) is not bool or confirmed != (action["operation"] == "confirm"):
        raise V10EnforcementError("EVM vote outcome does not match the action")
    if execution["decision_hash"] != action["decision_hash"]:
        raise V10EnforcementError("EVM vote decision hash is not bound to the action")
    if confirmed and report_id == chain.ZERO_BYTES32:
        raise V10EnforcementError("a confirming vote requires a nonzero report id")
    if not confirmed and report_id != chain.ZERO_BYTES32:
        raise V10EnforcementError("a dismissing vote must use the zero report id")
    if (not isinstance(approved_by, list) or not approved_by
            or len(set(approved_by)) != len(approved_by)):
        raise V10EnforcementError("approved users must be a distinct nonempty list")
    if not isinstance(evm_addresses, Mapping):
        raise V10EnforcementError("each approved user needs a pinned EVM address")
    approval_addresses: dict[str, str] = {}
    for signed in action.get("user_signatures", []):
        if not isinstance(signed, Mapping):
            raise V10EnforcementError("invalid user approval envelope")
        try:
            unsigned = verify_document(signed, APPROVAL_PURPOSE, max_age_seconds=0)
        except (IdentityError, TypeError, ValueError) as exc:
            raise V10EnforcementError("invalid user approval envelope") from exc
        public_key = str((signed.get("signature") or {}).get("public_key") or "")
        claimed = unsigned.get("evm_address")
        if claimed is not None:
            try:
                approval_addresses[public_key] = chain.normalize_address(claimed)
            except (TypeError, ValueError, chain.ChainError) as exc:
                raise V10EnforcementError("user approval EVM address is malformed") from exc
    permits = execution.get("vote_permits")
    if not isinstance(permits, list) or len(permits) != len(approved_by) or not permits:
        raise V10EnforcementError("each approved user must provide one EVM vote permit")
    votes = []
    seen_addresses: set[str] = set()
    seen_users: set[str] = set()
    for permit in permits:
        if not isinstance(permit, Mapping):
            raise V10EnforcementError("malformed EVM vote permit")
        public_key = permit.get("public_key")
        if not isinstance(public_key, str) or public_key in seen_users or public_key not in approved_by:
            raise V10EnforcementError("EVM vote permit is not bound to an approved user")
        seen_users.add(public_key)
        address = evm_addresses.get(public_key)
        try:
            normalized = chain.normalize_address(address)
        except (TypeError, ValueError, chain.ChainError) as exc:
            raise V10EnforcementError("approved user EVM address is malformed") from exc
        if normalized != address or normalized == chain.ZERO_ADDRESS or normalized in seen_addresses:
            raise V10EnforcementError("approved users must map to distinct nonzero EVM addresses")
        if approval_addresses.get(public_key) != normalized:
            raise V10EnforcementError("user approval does not bind its EVM judge address")
        seen_addresses.add(normalized)
        vote = dict(permit)
        vote.pop("public_key", None)
        vote.update({"settlement_key": settlement_key, "chain_id": execution["chain_id"],
                     "settlement_contract": contract, "confirmed": confirmed,
                     "report_id": report_id if confirmed else chain.ZERO_BYTES32,
                     "decision_hash": action["decision_hash"]})
        try:
            verified = chain_v10.verify_dispute_vote(
                vote, expected_settlement_key=settlement_key,
                expected_chain_id=execution["chain_id"], expected_contract=contract,
                expected_judge=normalized,
            )
        except (chain.ChainError, TypeError, ValueError) as exc:
            raise V10EnforcementError("invalid EVM judge vote permit") from exc
        votes.append({"public_key": public_key, "judge": normalized,
                      "nonce": verified["nonce"], "deadline": verified["deadline"],
                      "signature": verified["signature"]})
    if seen_users != set(approved_by):
        raise V10EnforcementError("EVM vote permits must cover every approved user")
    data = chain_v10.encode_dispute_vote_by_sig(
            settlement_key, [dict(p, chain_id=execution["chain_id"],
                                  settlement_contract=contract,
                                  settlement_key=settlement_key,
                                  confirmed=confirmed,
                                  report_id=report_id if confirmed else chain.ZERO_BYTES32,
                                  decision_hash=action["decision_hash"])
                               for p in permits]
        )
    body = {
        "schema": "mycomesh.v10.evm-vote-plan.v1", "action_hash": _action_hash(action),
        "action_id": action["action_id"], "nonce": action["nonce"],
        "chain_id": execution["chain_id"], "settlement_contract": contract,
        "settlement_key": settlement_key, "confirmed": confirmed,
        "report_id": report_id, "decision_hash": action["decision_hash"],
        "to": contract, "value": "0x0", "votes": votes, "data": data,
        "execution_required": True, "broadcast": False,
    }
    return {**body, "plan_hash": evidence_hash(body)}


class V10MonetaryExecutionStore:
    """Durable admission and at-most-once execution fence for V10 votes.

    A worker may pass ``execute`` to perform the actual, policy-capped EVM
    broadcasts.  The store commits ``executing`` before invoking it.  A crash
    or exception leaves an ``uncertain`` record, so a retry can never silently
    submit the same economic action twice.  Reconciliation is an explicit
    operator action via :meth:`record_result`.
    """

    def __init__(self, path: str | os.PathLike[str], *, enabled: bool = False) -> None:
        if str(path) == ":memory:":
            raise V10EnforcementError("automatic execution replay guard must be durable")
        self.path = str(path)
        self.enabled = bool(enabled)
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._lock = __import__("threading").RLock()
        self._db = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                                   check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS v10_monetary_actions (
            action_hash TEXT PRIMARY KEY, action_id TEXT NOT NULL UNIQUE,
            nonce TEXT NOT NULL, plan_json TEXT NOT NULL,
            status TEXT NOT NULL, result_json TEXT, error_code TEXT,
            created_at INTEGER NOT NULL)""")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _public_row(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = {"action_hash": row["action_hash"], "action_id": row["action_id"],
                  "nonce": int(row["nonce"]), "status": row["status"],
                  "created_at": row["created_at"]}
        if row["result_json"]:
            result["result"] = json.loads(row["result_json"])
        if row["error_code"]:
            result["error_code"] = row["error_code"]
        return result

    def get(self, action_hash: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM v10_monetary_actions WHERE action_hash=?",
                                   (action_hash,)).fetchone()
            return self._public_row(row)

    def admit_and_execute(
        self, action: Mapping[str, Any], *, evidence: Mapping[str, Any],
        high_reputation_users: Mapping[str, int], required_reputation: int,
        statutory_votes: int, required_votes: int,
        evm_addresses: Mapping[str, str], execute: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        high_reputation_operators: Mapping[str, str] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Verify, persist and optionally execute one exact EVM vote plan."""
        admission = verify_monetary_action(
            action, evidence=evidence, high_reputation_users=high_reputation_users,
            required_reputation=required_reputation, statutory_votes=statutory_votes,
            required_votes=required_votes, now=now,
            high_reputation_operators=high_reputation_operators,
            require_replay_fields=True,
        )
        vote_plan = build_evm_vote_plan(action, approved_by=admission["approved_by"],
                                        evm_addresses=evm_addresses)
        plan = {"schema": PLAN_SCHEMA, "action_hash": admission["action_hash"],
                "action_id": action["action_id"], "nonce": action["nonce"],
                "admission": admission, "evm_vote": vote_plan, "broadcast": False}
        plan["plan_hash"] = evidence_hash(plan)
        action_hash, action_id, nonce = admission["action_hash"], action["action_id"], action["nonce"]
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute("SELECT * FROM v10_monetary_actions WHERE action_hash=?",
                                            (action_hash,)).fetchone()
                if existing is not None:
                    self._db.commit()
                    saved = self._public_row(existing)
                    assert saved is not None
                    return saved
                conflict = self._db.execute("SELECT action_hash FROM v10_monetary_actions WHERE action_id=?",
                                            (action_id,)).fetchone()
                if conflict is not None:
                    raise V10EnforcementError("action_id was already used with different content")
                self._db.execute(
                    "INSERT INTO v10_monetary_actions(action_hash,action_id,nonce,plan_json,status,result_json,error_code,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (action_hash, action_id, str(nonce), _canonical(plan), "admitted", None, None, int(time.time())),
                )
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise
        if execute is None:
            saved = self.get(action_hash)
            assert saved is not None
            return saved
        if not self.enabled:
            raise V10EnforcementError("automatic monetary execution is disabled by policy")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute("SELECT * FROM v10_monetary_actions WHERE action_hash=?",
                                   (action_hash,)).fetchone()
            if row is None:
                self._db.rollback()
                raise V10EnforcementError("execution admission disappeared")
            if row["status"] != "admitted":
                self._db.commit()
                saved = self._public_row(row)
                assert saved is not None
                return saved
            self._db.execute("UPDATE v10_monetary_actions SET status='executing' WHERE action_hash=?",
                             (action_hash,))
            self._db.commit()
        try:
            result = execute(plan)
            result = _execution_result(result)
        except Exception as exc:
            with self._lock:
                self._db.execute("UPDATE v10_monetary_actions SET status='uncertain',error_code=? WHERE action_hash=?",
                                 (type(exc).__name__, action_hash))
            raise V10EnforcementError("automatic execution is uncertain; reconcile before retrying") from exc
        with self._lock:
            self._db.execute("UPDATE v10_monetary_actions SET status='executed',result_json=?,error_code=NULL WHERE action_hash=?",
                             (_canonical(dict(result)), action_hash))
        saved = self.get(action_hash)
        assert saved is not None
        return saved

    def record_result(self, action_hash: str, result: Mapping[str, Any]) -> dict[str, Any]:
        """Explicitly reconcile an uncertain callback; never broadcasts."""
        result = _execution_result(result)
        with self._lock:
            row = self._db.execute("SELECT status FROM v10_monetary_actions WHERE action_hash=?",
                                   (action_hash,)).fetchone()
            if row is None:
                raise V10EnforcementError("unknown monetary action")
            if row["status"] == "executed":
                return self.get(action_hash)  # type: ignore[return-value]
            if row["status"] != "uncertain":
                raise V10EnforcementError("only an uncertain action may be reconciled")
            self._db.execute("UPDATE v10_monetary_actions SET status='executed',result_json=?,error_code=NULL WHERE action_hash=?",
                             (_canonical(dict(result)), action_hash))
        return self.get(action_hash)  # type: ignore[return-value]
