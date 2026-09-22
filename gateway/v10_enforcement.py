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
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
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
MONETARY_POLICY_SCHEMA = "mycomesh.v10.monetary-policy.v1"
MIN_AUTOMATIC_REPUTATION = 80
_VALIDATED_POLICY_TOKEN = object()


@dataclass(frozen=True)
class V10MonetarySigner:
    """One deployment-pinned approval identity and its on-chain judge."""

    public_key: str
    evm_address: str
    operator_id: str
    reputation: int


@dataclass(frozen=True)
class V10MonetaryPolicy:
    """Immutable automatic-enforcement policy derived from one deployment.

    The worker accepts this object instead of caller-supplied thresholds and
    lookup tables.  Its hash is committed by every monetary action, so roster
    or wallet rotation creates a new policy and cannot silently reinterpret an
    already signed action.
    """

    network_id: str
    chain_id: int
    settlement_contract: str
    required_reputation: int
    required_votes: int
    signers: tuple[V10MonetarySigner, ...]
    policy_hash: str
    _deployment_json: str = field(repr=False, compare=False)
    _validation_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._validation_token is not _VALIDATED_POLICY_TOKEN:
            raise V10EnforcementError(
                "monetary policy must be created from a validated deployment manifest"
            )

    @property
    def reputations(self) -> dict[str, int]:
        return {signer.public_key: signer.reputation for signer in self.signers}

    @property
    def operators(self) -> dict[str, str]:
        return {signer.public_key: signer.operator_id for signer in self.signers}

    @property
    def evm_addresses(self) -> dict[str, str]:
        return {signer.public_key: signer.evm_address for signer in self.signers}


def _strict_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise V10EnforcementError("monetary policy deployment must be a regular file")

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise V10EnforcementError(f"duplicate JSON key in monetary policy: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                V10EnforcementError(f"invalid JSON number in monetary policy: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise V10EnforcementError("cannot read monetary policy deployment") from exc


def monetary_policy_from_deployment(deployment: Mapping[str, Any]) -> V10MonetaryPolicy:
    """Validate and freeze the policy embedded in a V10 deployment manifest."""
    if not isinstance(deployment, Mapping) or deployment.get("protocol_version") != 10:
        raise V10EnforcementError("automatic enforcement requires a V10 deployment")
    if deployment.get("independence_attested") is not True:
        raise V10EnforcementError("automatic enforcement requires attested operator independence")
    network_id = deployment.get("network_id")
    chain_id = deployment.get("chain_id")
    threshold = deployment.get("adjudication_threshold")
    if not isinstance(network_id, str) or not network_id.strip() or network_id != network_id.strip():
        raise V10EnforcementError("deployment network_id is invalid")
    if type(chain_id) is not int or chain_id <= 0:
        raise V10EnforcementError("deployment chain_id is invalid")
    if type(threshold) is not int or threshold < 2:
        raise V10EnforcementError("automatic enforcement requires an on-chain quorum of at least two")
    settlement = _address(deployment.get("settlement"), "deployment settlement contract")
    adjudicators = deployment.get("adjudicators")
    operator_map = deployment.get("adjudicator_operators")
    if not isinstance(adjudicators, list) or not isinstance(operator_map, Mapping):
        raise V10EnforcementError("deployment adjudicator roster is incomplete")
    normalized_adjudicators: list[str] = []
    deployment_operators: dict[str, str] = {}
    for raw_address in adjudicators:
        address = _address(raw_address, "deployment adjudicator")
        operator = operator_map.get(address)
        if not isinstance(operator, str) or not operator.strip() or operator != operator.strip():
            raise V10EnforcementError("every adjudicator needs a pinned operator identity")
        normalized_adjudicators.append(address)
        deployment_operators[address] = operator
    if (len(set(normalized_adjudicators)) != len(normalized_adjudicators)
            or len(set(value.casefold() for value in deployment_operators.values()))
            != len(deployment_operators)):
        raise V10EnforcementError("deployment adjudicators are not independently operated")
    if (len(normalized_adjudicators) > 16
            or threshold > len(normalized_adjudicators)
            or threshold <= len(normalized_adjudicators) // 2
            or set(operator_map) != set(normalized_adjudicators)):
        raise V10EnforcementError("deployment adjudicator roster does not match its operator map")

    raw_policy = deployment.get("monetary_policy")
    expected_policy_keys = {
        "schema", "network_id", "chain_id", "settlement_contract",
        "required_reputation", "required_votes", "signers",
    }
    if not isinstance(raw_policy, Mapping) or set(raw_policy) != expected_policy_keys:
        raise V10EnforcementError("deployment has no complete pinned monetary policy")
    if (raw_policy.get("schema") != MONETARY_POLICY_SCHEMA
            or raw_policy.get("network_id") != network_id
            or raw_policy.get("chain_id") != chain_id
            or raw_policy.get("settlement_contract") != settlement):
        raise V10EnforcementError("monetary policy is not bound to this deployment")
    required_reputation = raw_policy.get("required_reputation")
    required_votes = raw_policy.get("required_votes")
    if (type(required_reputation) is not int
            or not MIN_AUTOMATIC_REPUTATION <= required_reputation <= 100):
        raise V10EnforcementError(
            f"automatic monetary reputation threshold must be at least {MIN_AUTOMATIC_REPUTATION}"
        )
    if type(required_votes) is not int or required_votes != threshold:
        raise V10EnforcementError("monetary approval quorum must equal the on-chain threshold")
    raw_signers = raw_policy.get("signers")
    if not isinstance(raw_signers, list) or not raw_signers:
        raise V10EnforcementError("monetary policy signer roster is empty")
    signers: list[V10MonetarySigner] = []
    public_keys: set[str] = set()
    addresses: set[str] = set()
    operators: set[str] = set()
    for raw_signer in raw_signers:
        if not isinstance(raw_signer, Mapping) or set(raw_signer) != {
            "public_key", "evm_address", "operator_id", "reputation",
        }:
            raise V10EnforcementError("monetary signer entry is malformed")
        public_key = raw_signer.get("public_key")
        if (not isinstance(public_key, str) or len(public_key) != 64
                or public_key != public_key.lower()):
            raise V10EnforcementError("monetary signer public key must be canonical Ed25519 hex")
        try:
            if len(bytes.fromhex(public_key)) != 32:
                raise ValueError
        except ValueError as exc:
            raise V10EnforcementError("monetary signer public key must be canonical Ed25519 hex") from exc
        address = _address(raw_signer.get("evm_address"), "monetary signer EVM address")
        operator = raw_signer.get("operator_id")
        reputation = raw_signer.get("reputation")
        if (address not in deployment_operators or not isinstance(operator, str)
                or operator != deployment_operators[address]):
            raise V10EnforcementError("monetary signer does not match the deployment operator roster")
        operator_key = operator.casefold()
        if type(reputation) is not int or not 0 <= reputation <= 100:
            raise V10EnforcementError("monetary signer reputation must be between 0 and 100")
        if public_key in public_keys or address in addresses or operator_key in operators:
            raise V10EnforcementError("monetary signer identities must be independent and unique")
        public_keys.add(public_key)
        addresses.add(address)
        operators.add(operator_key)
        signers.append(V10MonetarySigner(public_key, address, operator, reputation))
    if sum(signer.reputation >= required_reputation for signer in signers) < required_votes:
        raise V10EnforcementError("monetary policy cannot satisfy its own reputation quorum")
    canonical_policy = dict(raw_policy)
    policy_hash = evidence_hash(canonical_policy)
    return V10MonetaryPolicy(
        network_id=network_id, chain_id=chain_id, settlement_contract=settlement,
        required_reputation=required_reputation, required_votes=required_votes,
        signers=tuple(signers), policy_hash=policy_hash,
        _deployment_json=_canonical(deployment),
        _validation_token=_VALIDATED_POLICY_TOKEN,
    )


def load_monetary_policy(path: str | os.PathLike[str]) -> V10MonetaryPolicy:
    """Load only a regular, strict-JSON deployment manifest."""
    return monetary_policy_from_deployment(_strict_json(Path(path)))


def _validated_policy(policy: Any) -> V10MonetaryPolicy:
    """Rebuild a policy from its manifest to reject copied/mutated dataclasses."""
    if (not isinstance(policy, V10MonetaryPolicy)
            or policy._validation_token is not _VALIDATED_POLICY_TOKEN):
        raise V10EnforcementError("a deployment-pinned monetary policy is required")
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise V10EnforcementError(f"duplicate JSON key in monetary policy: {key}")
            result[key] = value
        return result

    try:
        deployment = json.loads(
            policy._deployment_json,
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                V10EnforcementError(f"invalid JSON number in monetary policy: {value}")
            ),
        )
    except (TypeError, json.JSONDecodeError) as exc:
        raise V10EnforcementError("monetary policy lost its deployment binding") from exc
    rebuilt = monetary_policy_from_deployment(deployment)
    fields = (
        "network_id", "chain_id", "settlement_contract", "required_reputation",
        "required_votes", "signers", "policy_hash", "_deployment_json",
    )
    if any(getattr(policy, name) != getattr(rebuilt, name) for name in fields):
        raise V10EnforcementError("monetary policy differs from its validated deployment")
    return policy


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


def _bytes32(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise V10EnforcementError(f"{label} must be a canonical bytes32 value") from exc
    if normalized != value:
        raise V10EnforcementError(f"{label} must be lowercase canonical hex")
    return normalized


def _address(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise V10EnforcementError(f"{label} must be a canonical EVM address") from exc
    if normalized != value or (nonzero and normalized == chain.ZERO_ADDRESS):
        raise V10EnforcementError(f"{label} must be lowercase, canonical and nonzero")
    return normalized


def _execution_result(
    value: Mapping[str, Any], *, plan: Mapping[str, Any],
    existing: Mapping[str, Any] | None = None, required_confirmations: int = 2,
) -> dict[str, Any]:
    """Validate the durable transaction identity and confirmed vote outcome.

    This deliberately accepts structured observations only.  The caller is
    responsible for obtaining them from the pinned chain/RPC; the store then
    prevents a result for another chain, contract, sender, nonce or vote plan
    from being attached to this action.
    """
    if not isinstance(value, Mapping):
        raise V10EnforcementError("execution result must be a mapping")
    status = value.get("status")
    if status not in {"submitted", "confirmed"}:
        raise V10EnforcementError("execution result status must be submitted or confirmed")
    vote_plan = plan.get("evm_vote")
    if not isinstance(vote_plan, Mapping):
        raise V10EnforcementError("saved execution plan is malformed")
    tx_hash = _bytes32(value.get("tx_hash"), "transaction hash")
    plan_hash = _bytes32(value.get("plan_hash"), "plan hash")
    if plan_hash != plan.get("plan_hash"):
        raise V10EnforcementError("execution result belongs to another plan")
    chain_id = value.get("chain_id")
    if type(chain_id) is not int or chain_id != vote_plan.get("chain_id"):
        raise V10EnforcementError("execution result chain does not match the plan")
    contract = _address(value.get("settlement_contract"), "settlement contract")
    if contract != vote_plan.get("settlement_contract"):
        raise V10EnforcementError("execution result contract does not match the plan")
    sender = _address(value.get("sender"), "transaction sender")
    nonce = value.get("nonce")
    if type(nonce) is not int or nonce < 0 or nonce >= 2**256:
        raise V10EnforcementError("execution result requires a uint256 transaction nonce")
    result = {
        "status": status, "tx_hash": tx_hash, "plan_hash": plan_hash,
        "chain_id": chain_id, "settlement_contract": contract,
        "sender": sender, "nonce": nonce,
    }
    if existing is not None:
        for field in ("tx_hash", "plan_hash", "chain_id", "settlement_contract", "sender", "nonce"):
            if field in existing and existing.get(field) != result[field]:
                raise V10EnforcementError("reconciliation changed the submitted transaction identity")
    if status == "submitted":
        return result
    if type(required_confirmations) is not int or required_confirmations < 1:
        raise V10EnforcementError("required confirmations must be a positive integer")
    confirmations = value.get("confirmations")
    if type(confirmations) is not int or confirmations < required_confirmations:
        raise V10EnforcementError("confirmed result has insufficient chain confirmations")
    receipt = value.get("receipt")
    if not isinstance(receipt, Mapping):
        raise V10EnforcementError("confirmed result requires a verified receipt")
    receipt_tx = _bytes32(receipt.get("transaction_hash"), "receipt transaction hash")
    receipt_block_hash = _bytes32(receipt.get("block_hash"), "receipt block hash")
    receipt_from = _address(receipt.get("from"), "receipt sender")
    receipt_to = _address(receipt.get("to"), "receipt target")
    block_number = receipt.get("block_number")
    receipt_status = receipt.get("status")
    receipt_succeeded = (
        (type(receipt_status) is int and receipt_status == 1)
        or receipt_status == "0x1"
    )
    if (receipt_tx != tx_hash or receipt_from != sender or receipt_to != contract
            or type(block_number) is not int or block_number < 0
            or not receipt_succeeded):
        raise V10EnforcementError("receipt does not prove the planned successful transaction")
    events = value.get("vote_events")
    planned_votes = vote_plan.get("votes")
    if not isinstance(events, list) or not isinstance(planned_votes, list) or len(events) != len(planned_votes):
        raise V10EnforcementError("confirmed result must prove every planned dispute vote event")
    expected = {
        (vote["judge"], vote_plan["settlement_key"], vote_plan["confirmed"],
         vote_plan["report_id"], vote_plan["decision_hash"])
        for vote in planned_votes
    }
    observed: set[tuple[Any, ...]] = set()
    observed_log_indices: set[int] = set()
    for event in events:
        if not isinstance(event, Mapping) or event.get("event") != "DisputeVote":
            raise V10EnforcementError("confirmed result contains an invalid dispute vote event")
        event_contract = _address(event.get("address"), "event contract")
        judge = _address(event.get("adjudicator"), "event adjudicator")
        event_tx = _bytes32(event.get("transaction_hash"), "event transaction hash")
        event_block_hash = _bytes32(event.get("block_hash"), "event block hash")
        event_block_number = event.get("block_number")
        log_index = event.get("log_index")
        removed = event.get("removed")
        settlement_key = _bytes32(event.get("settlement_key"), "event settlement key")
        report_id = _bytes32(event.get("report_id"), "event report id")
        decision_hash = _bytes32(event.get("decision_hash"), "event decision hash")
        confirmed = event.get("confirmed")
        if (event_contract != contract or event_tx != receipt_tx
                or event_block_hash != receipt_block_hash
                or type(event_block_number) is not int or event_block_number != block_number
                or type(log_index) is not int or log_index < 0
                or log_index in observed_log_indices or removed is not False
                or type(confirmed) is not bool):
            raise V10EnforcementError("dispute vote event is not bound to the planned contract")
        observed_log_indices.add(log_index)
        observed.add((judge, settlement_key, confirmed, report_id, decision_hash))
    if observed != expected or len(observed) != len(events):
        raise V10EnforcementError("dispute vote events do not match the exact planned quorum")
    result.update({
        "confirmations": confirmations,
        "receipt": {
            "transaction_hash": receipt_tx, "block_number": block_number,
            "block_hash": receipt_block_hash, "status": receipt_status,
            "from": receipt_from, "to": receipt_to,
        },
        "vote_events": [dict(event) for event in events],
    })
    return result


def verify_monetary_action(
    action: Mapping[str, Any], *, evidence: Mapping[str, Any],
    policy: V10MonetaryPolicy, now: int | None = None,
    require_replay_fields: bool = False,
) -> dict[str, Any]:
    """Return a non-payable, reviewable plan when every independent gate passes.

    ``action`` contains one signed document per high-reputation user under
    ``user_signatures``. Signatures bind the exact evidence hash and action.
    """
    if not isinstance(action, Mapping) or action.get("schema") != ACTION_SCHEMA:
        raise V10EnforcementError("unsupported V10 monetary action")
    policy = _validated_policy(policy)
    if action.get("policy_hash") != policy.policy_hash:
        raise V10EnforcementError("monetary action is not bound to the active policy")
    if require_replay_fields:
        _required_replay_fields(action)
    if not isinstance(evidence, Mapping) or not evidence:
        raise V10EnforcementError("committed evidence is required")
    if action.get("evidence_hash") != evidence_hash(dict(evidence)):
        raise V10EnforcementError("monetary action evidence commitment mismatch")
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
        if signer in seen or signer not in policy.reputations:
            raise V10EnforcementError("signer is not an independent high-reputation user")
        if policy.reputations[signer] < policy.required_reputation:
            raise V10EnforcementError("signer reputation is below the required threshold")
        operator_key = policy.operators[signer].casefold()
        if operator_key in seen_operators:
            raise V10EnforcementError("independent approvals share an operator identity")
        seen_operators.add(operator_key)
        if unsigned.get("action_hash") != evidence_hash({k: v for k, v in action.items() if k != "user_signatures"}):
            raise V10EnforcementError("user approval does not bind the action")
        seen.add(signer)
        verified.append(signer)
    if len(verified) != policy.required_votes:
        raise V10EnforcementError("approval count must equal the pinned on-chain quorum")
    return {"schema": PLAN_SCHEMA, "payable": False,
            "execution_required": True, "evidence_hash": action["evidence_hash"],
            "approved_by": verified, "statutory_votes": len(verified),
            "policy_hash": policy.policy_hash,
            "action_hash": _action_hash(action),
            **({"action_id": action["action_id"], "nonce": action["nonce"]}
               if "action_id" in action and "nonce" in action else {})}


def build_evm_vote_plan(
    action: Mapping[str, Any], *, approved_by: list[str],
    policy: V10MonetaryPolicy,
) -> dict[str, Any]:
    """Build one signed-approval-to-EVM-vote hand-off, without broadcasting.

    The user approvals are Ed25519 documents, while ``voteDispute`` authorizes
    EVM adjudicator addresses.  The deployment-pinned policy supplies the
    one-to-one identity mapping and exact chain/contract target.  The returned
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
    policy = _validated_policy(policy)
    if action.get("policy_hash") != policy.policy_hash:
        raise V10EnforcementError("EVM vote plan requires the action's pinned monetary policy")
    if execution.get("chain_id") != policy.chain_id:
        raise V10EnforcementError("EVM vote chain does not match the monetary policy")
    try:
        contract = chain.normalize_address(execution["settlement_contract"])
        settlement_key = chain.normalize_bytes32(execution["settlement_key"])
        report_id = chain.normalize_bytes32(execution["report_id"])
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise V10EnforcementError("EVM vote target contains malformed identifiers") from exc
    if contract != execution["settlement_contract"] or contract == chain.ZERO_ADDRESS:
        raise V10EnforcementError("EVM vote contract must be canonical and nonzero")
    if contract != policy.settlement_contract:
        raise V10EnforcementError("EVM vote contract does not match the monetary policy")
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
    if (not isinstance(approved_by, list)
            or len(approved_by) != policy.required_votes
            or len(set(approved_by)) != len(approved_by)):
        raise V10EnforcementError("approved users must equal the distinct pinned quorum")
    evm_addresses = policy.evm_addresses
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
    """Durable V10 vote admission, lease and confirmation state machine.

    ``executing`` is a short worker lease, never a success state.  A normal
    callback persists ``submitted`` or a fully checked ``confirmed`` result.
    A callback error, or an expired lease after a hard process crash, becomes
    ``uncertain`` and is never broadcast again automatically.  Explicit
    reconciliation may bind the original transaction identity and later move
    it to ``confirmed`` after receipt and vote-event checks.
    """

    STATUSES = frozenset({"admitted", "executing", "submitted", "confirmed", "uncertain"})

    def __init__(
        self, path: str | os.PathLike[str], *, enabled: bool = False,
        lease_seconds: int = 120, required_confirmations: int = 2,
    ) -> None:
        if str(path) == ":memory:":
            raise V10EnforcementError("automatic execution replay guard must be durable")
        if type(enabled) is not bool:
            raise V10EnforcementError("automatic monetary execution flag must be an explicit boolean")
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 3600:
            raise V10EnforcementError("execution lease must be between 5 and 3600 seconds")
        if type(required_confirmations) is not int or not 2 <= required_confirmations <= 256:
            raise V10EnforcementError("automatic execution requires 2 to 256 confirmations")
        self.path = str(path)
        self.enabled = enabled
        self.lease_seconds = lease_seconds
        self.required_confirmations = required_confirmations
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
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            lease_owner TEXT, lease_expires_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0)""")
        columns = {row["name"] for row in self._db.execute(
            "PRAGMA table_info(v10_monetary_actions)"
        ).fetchall()}
        for name, definition in (
            ("updated_at", "INTEGER"), ("lease_owner", "TEXT"),
            ("lease_expires_at", "INTEGER"), ("attempts", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if name not in columns:
                self._db.execute(f"ALTER TABLE v10_monetary_actions ADD COLUMN {name} {definition}")
        self._db.execute(
            "UPDATE v10_monetary_actions SET updated_at=created_at WHERE updated_at IS NULL"
        )
        self._db.execute(
            "UPDATE v10_monetary_actions SET attempts=0 WHERE attempts IS NULL"
        )
        # A row created by the previous implementation can be left in
        # ``executing`` after a hard process exit, but it has no lease identity
        # or expiry from which ownership could be recovered safely.  Fence it
        # permanently until an operator reconciles the chain observation.
        self._db.execute(
            """UPDATE v10_monetary_actions
               SET status='uncertain',error_code='legacy_execution_requires_reconciliation',
                   updated_at=?
               WHERE status='executing' AND lease_owner IS NULL AND lease_expires_at IS NULL""",
            (int(time.time()),),
        )
        # The previous schema did not bind chain/contract/sender/nonce or prove
        # receipt events.  Preserve its observation for audit but require an
        # explicit reconciliation before assigning a new state.
        for row in self._db.execute(
            "SELECT action_hash,result_json FROM v10_monetary_actions WHERE status='executed'"
        ).fetchall():
            status = "uncertain"
            self._db.execute(
                """UPDATE v10_monetary_actions
                   SET status=?,error_code='legacy_result_requires_reconciliation',updated_at=?
                   WHERE action_hash=?""",
                (status, int(time.time()), row["action_hash"]),
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _public_row(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        plan = json.loads(row["plan_json"])
        result = {"action_hash": row["action_hash"], "action_id": row["action_id"],
                  "nonce": int(row["nonce"]), "status": row["status"],
                  "plan_hash": plan.get("plan_hash"),
                  "created_at": row["created_at"], "updated_at": row["updated_at"],
                  "attempts": row["attempts"]}
        if row["status"] == "executing":
            result["lease_expires_at"] = row["lease_expires_at"]
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

    def get_plan(self, action_hash: str) -> dict[str, Any] | None:
        """Return the immutable saved plan for a reconciler; never broadcasts."""
        with self._lock:
            row = self._db.execute(
                "SELECT plan_json FROM v10_monetary_actions WHERE action_hash=?", (action_hash,)
            ).fetchone()
            return json.loads(row["plan_json"]) if row is not None else None

    def recover_expired_leases(self, *, now: int | None = None) -> int:
        """Fence hard-crashed workers without ever retrying their transaction."""
        timestamp = int(time.time()) if now is None else now
        if type(timestamp) is not int or timestamp < 0:
            raise V10EnforcementError("lease recovery time must be a nonnegative integer")
        with self._lock:
            cursor = self._db.execute(
                """UPDATE v10_monetary_actions
                   SET status='uncertain',error_code='execution_lease_expired',
                       lease_owner=NULL,lease_expires_at=NULL,updated_at=?
                   WHERE status='executing' AND lease_expires_at IS NOT NULL
                         AND lease_expires_at<=?""",
                (timestamp, timestamp),
            )
            return cursor.rowcount

    def admit_and_execute(
        self, action: Mapping[str, Any], *, evidence: Mapping[str, Any],
        policy: V10MonetaryPolicy,
        execute: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Verify, persist and optionally execute one exact EVM vote plan."""
        admission = verify_monetary_action(
            action, evidence=evidence, policy=policy, now=now, require_replay_fields=True,
        )
        vote_plan = build_evm_vote_plan(action, approved_by=admission["approved_by"],
                                        policy=policy)
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
                else:
                    conflict = self._db.execute("SELECT action_hash FROM v10_monetary_actions WHERE action_id=?",
                                                (action_id,)).fetchone()
                    if conflict is not None:
                        raise V10EnforcementError("action_id was already used with different content")
                    created_at = int(time.time())
                    self._db.execute(
                        """INSERT INTO v10_monetary_actions(
                               action_hash,action_id,nonce,plan_json,status,result_json,error_code,
                               created_at,updated_at,lease_owner,lease_expires_at,attempts)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (action_hash, action_id, str(nonce), _canonical(plan), "admitted", None, None,
                         created_at, created_at, None, None, 0),
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
        execution_now = int(time.time())
        self.recover_expired_leases(now=execution_now)
        lease_owner = secrets.token_hex(16)
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
            self._db.execute(
                """UPDATE v10_monetary_actions
                   SET status='executing',lease_owner=?,lease_expires_at=?,
                       attempts=attempts+1,updated_at=?,error_code=NULL
                   WHERE action_hash=? AND status='admitted'""",
                (lease_owner, execution_now + self.lease_seconds, execution_now, action_hash),
            )
            self._db.commit()
        try:
            result = execute(plan)
            result = _execution_result(
                result, plan=plan, required_confirmations=self.required_confirmations,
            )
        except Exception as exc:
            with self._lock:
                self._db.execute(
                    """UPDATE v10_monetary_actions
                       SET status='uncertain',error_code=?,lease_owner=NULL,
                           lease_expires_at=NULL,updated_at=?
                       WHERE action_hash=? AND status='executing' AND lease_owner=?""",
                    (type(exc).__name__, int(time.time()), action_hash, lease_owner),
                )
            raise V10EnforcementError("automatic execution is uncertain; reconcile before retrying") from exc
        with self._lock:
            cursor = self._db.execute(
                """UPDATE v10_monetary_actions
                   SET status=?,result_json=?,error_code=NULL,lease_owner=NULL,
                       lease_expires_at=NULL,updated_at=?
                   WHERE action_hash=? AND status='executing' AND lease_owner=?""",
                (result["status"], _canonical(result), int(time.time()), action_hash, lease_owner),
            )
            if cursor.rowcount != 1:
                raise V10EnforcementError("execution lease was lost before its result was persisted")
        saved = self.get(action_hash)
        assert saved is not None
        return saved

    def record_result(self, action_hash: str, result: Mapping[str, Any]) -> dict[str, Any]:
        """Persist a pinned-chain observation for the original transaction.

        This method never signs or broadcasts.  ``submitted`` records may be
        completed later; ``confirmed`` additionally requires a successful
        receipt, enough confirmations and the exact planned vote events.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM v10_monetary_actions WHERE action_hash=?", (action_hash,)
                ).fetchone()
                if row is None:
                    raise V10EnforcementError("unknown monetary action")
                if row["status"] not in {"uncertain", "submitted", "confirmed"}:
                    raise V10EnforcementError("only uncertain or submitted actions may be reconciled")
                plan = json.loads(row["plan_json"])
                existing = json.loads(row["result_json"]) if row["result_json"] else None
                checked = _execution_result(
                    result, plan=plan, existing=existing,
                    required_confirmations=self.required_confirmations,
                )
                if row["status"] == "confirmed":
                    if checked != existing:
                        raise V10EnforcementError("confirmed monetary result is immutable")
                    saved = self._public_row(row)
                    assert saved is not None
                    self._db.commit()
                    return saved
                self._db.execute(
                    """UPDATE v10_monetary_actions
                       SET status=?,result_json=?,error_code=NULL,lease_owner=NULL,
                           lease_expires_at=NULL,updated_at=? WHERE action_hash=?""",
                    (checked["status"], _canonical(checked), int(time.time()), action_hash),
                )
                updated = self._db.execute(
                    "SELECT * FROM v10_monetary_actions WHERE action_hash=?", (action_hash,)
                ).fetchone()
                saved = self._public_row(updated)
                assert saved is not None
                self._db.commit()
                return saved
            except BaseException:
                self._db.rollback()
                raise

    def reconcile(
        self, action_hash: str,
        inspect: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Inspect the saved plan/current state and persist the checked result."""
        if not callable(inspect):
            raise V10EnforcementError("reconciliation requires a chain inspection callback")
        plan = self.get_plan(action_hash)
        current = self.get(action_hash)
        if plan is None or current is None:
            raise V10EnforcementError("unknown monetary action")
        observed = inspect(plan, current)
        return self.record_result(action_hash, observed)
