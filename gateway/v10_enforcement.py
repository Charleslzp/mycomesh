"""Fail-closed V10 monetary-action admission.

This module only verifies an operator-authored action envelope.  It never
submits a transaction, refunds a consumer, or confiscates a Provider balance.
"""
from __future__ import annotations

from typing import Any, Mapping

from .identity import IdentityError, verify_document
from .relay_incidents import evidence_hash


class V10EnforcementError(ValueError):
    pass


def verify_monetary_action(
    action: Mapping[str, Any], *, evidence: Mapping[str, Any],
    high_reputation_users: Mapping[str, int], required_reputation: int = 80,
    statutory_votes: int, required_votes: int, now: int | None = None,
) -> dict[str, Any]:
    """Return a non-payable, reviewable plan when every independent gate passes.

    ``action`` contains one signed document per high-reputation user under
    ``user_signatures``. Signatures bind the exact evidence hash and action.
    """
    if not isinstance(action, Mapping) or action.get("schema") != "mycomesh.v10.monetary-action.v1":
        raise V10EnforcementError("unsupported V10 monetary action")
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
    verified = []
    for signed in signatures:
        if not isinstance(signed, dict):
            raise V10EnforcementError("invalid user signature envelope")
        try:
            unsigned = verify_document(signed, "mycomesh.v10.monetary-approval.v1", now=now)
        except (IdentityError, TypeError, ValueError) as exc:
            raise V10EnforcementError("invalid user signature") from exc
        signer = str((signed.get("signature") or {}).get("public_key") or "")
        if signer in seen or signer not in high_reputation_users:
            raise V10EnforcementError("signer is not an independent high-reputation user")
        if high_reputation_users[signer] < required_reputation:
            raise V10EnforcementError("signer reputation is below the required threshold")
        if unsigned.get("action_hash") != evidence_hash({k: v for k, v in action.items() if k != "user_signatures"}):
            raise V10EnforcementError("user approval does not bind the action")
        seen.add(signer)
        verified.append(signer)
    if len(verified) < required_votes:
        raise V10EnforcementError("insufficient independent user approvals")
    return {"schema": "mycomesh.v10.monetary-plan.v1", "payable": False,
            "execution_required": True, "evidence_hash": action["evidence_hash"],
            "approved_by": verified, "statutory_votes": statutory_votes}
