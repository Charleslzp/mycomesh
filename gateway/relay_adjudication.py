"""Offline, pinned-quorum adjudication certificates; NEVER a payment executor.

Distinct authority keys must be onboarded as independently controlled operators.
Cryptography cannot establish that two keys belong to different people. Reporter
keys cannot vote. Certificates bind the exact incident, policy, financial context,
network and settlement contract. This verifies a quorum's decision, not model
identity or the underlying allegation automatically.

Exposure inputs must come from an independently trusted settlement/escrow
adapter, never the reporter. There is no such onchain adapter here: V8 cannot
execute these Ed25519 certificates, refunds, escrow slashing or token rewards.
All amounts are offline plans, always payable=False and onchain_linked=False.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any, Iterator, Mapping, Sequence

from .identity import IdentityError, verify_document
from .relay_incidents import evidence_hash


ADJUDICATION_PURPOSE = "mycomesh.relay.adjudication.v1"
_KEY = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_HASH = re.compile(r"^0x[0-9a-f]{64}$")
_INCIDENT_FIELDS = ("provider_id", "provider_signer", "request_id", "request_hash", "kind", "severity", "evidence")


class AdjudicationError(ValueError):
    pass


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise AdjudicationError(f"{field} must be a nonempty string")
    return value


def _integer(value: Any, field: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise AdjudicationError(f"{field} must be an exact nonnegative integer within its cap")
    return value


def _key(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _KEY.fullmatch(value):
        raise AdjudicationError(f"{field} must be a canonical Ed25519 public key")
    return value


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise AdjudicationError("decision must be finite JSON") from exc


@dataclass(frozen=True)
class AdjudicationPolicy:
    network_id: str
    chain_id: int
    settlement_contract: str
    authority_public_keys: tuple[str, ...]
    threshold: int
    max_refund_units: int = 0
    token_reward_units: int = 0
    max_token_reward_units: int = 0
    stable_reward_bps: int = 0
    max_stable_reward_units: int = 0
    max_decision_lifetime_seconds: int = 86_400

    def __post_init__(self) -> None:
        _text(self.network_id, "network_id")
        if _integer(self.chain_id, "chain_id") == 0:
            raise AdjudicationError("chain_id must be positive")
        if not isinstance(self.settlement_contract, str) or not _ADDRESS.fullmatch(self.settlement_contract):
            raise AdjudicationError("settlement_contract must be a canonical EVM address")
        if not isinstance(self.authority_public_keys, tuple):
            raise AdjudicationError("authority_public_keys must be an immutable tuple")
        keys = [_key(value, "authority public key") for value in self.authority_public_keys]
        if len(set(keys)) != len(keys):
            raise AdjudicationError("authority public keys must be distinct")
        if type(self.threshold) is not int or self.threshold < 2 or self.threshold > len(keys):
            raise AdjudicationError("threshold requires at least two distinct pinned authorities")
        for field in ("max_refund_units", "max_token_reward_units", "max_stable_reward_units"):
            _integer(getattr(self, field), field)
        _integer(self.token_reward_units, "token_reward_units", self.max_token_reward_units)
        _integer(self.stable_reward_bps, "stable_reward_bps", 10_000)
        if _integer(self.max_decision_lifetime_seconds, "max_decision_lifetime_seconds") == 0:
            raise AdjudicationError("max_decision_lifetime_seconds must be positive")

    @property
    def domain(self) -> dict[str, Any]:
        return {"network_id": self.network_id, "chain_id": self.chain_id, "settlement_contract": self.settlement_contract}

    @property
    def policy_hash(self) -> str:
        return evidence_hash({
            "domain": self.domain, "authority_public_keys": sorted(self.authority_public_keys),
            "threshold": self.threshold, "max_refund_units": self.max_refund_units,
            "token_reward_units": self.token_reward_units, "max_token_reward_units": self.max_token_reward_units,
            "stable_reward_bps": self.stable_reward_bps, "max_stable_reward_units": self.max_stable_reward_units,
            "max_decision_lifetime_seconds": self.max_decision_lifetime_seconds,
        })

    @property
    def audience(self) -> str:
        return ADJUDICATION_PURPOSE + ":" + self.policy_hash


@dataclass(frozen=True)
class EconomicExposure:
    """Trusted-adapter inputs; not facts established by a reporter/certificate."""

    consumer_paid_units: int
    recoverable_provider_units: int

    def __post_init__(self) -> None:
        _integer(self.consumer_paid_units, "consumer_paid_units")
        _integer(self.recoverable_provider_units, "recoverable_provider_units")

    def to_dict(self) -> dict[str, int]:
        return {"consumer_paid_units": self.consumer_paid_units,
                "recoverable_provider_units": self.recoverable_provider_units}


def _incident_binding(incident: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(incident, Mapping) or any(field not in incident for field in _INCIDENT_FIELDS):
        raise AdjudicationError("full expected incident record is required")
    identity = _text(incident.get("incident_id"), "incident_id")
    committed_hash = incident.get("record_hash")
    if not isinstance(committed_hash, str) or not _HASH.fullmatch(committed_hash):
        raise AdjudicationError("expected incident record_hash is required")
    record = {field: incident[field] for field in _INCIDENT_FIELDS}
    if not isinstance(record["evidence"], Mapping):
        raise AdjudicationError("incident evidence must be an object")
    _canonical(record)
    if evidence_hash(record) != committed_hash or evidence_hash(record["evidence"]) != incident.get("evidence_hash"):
        raise AdjudicationError("incident content does not match committed hash")
    return identity, committed_hash


def _amounts(policy: AdjudicationPolicy, exposure: EconomicExposure, outcome: str) -> dict[str, int]:
    _integer(exposure.consumer_paid_units, "consumer_paid_units", policy.max_refund_units)
    if outcome == "dismissed":
        return {"refund_units": 0, "unfunded_refund_units": 0, "token_reward_units": 0, "stable_reward_units": 0}
    if outcome != "confirmed":
        raise AdjudicationError("outcome must be confirmed or dismissed")
    refund = min(exposure.consumer_paid_units, exposure.recoverable_provider_units)
    shortfall = exposure.consumer_paid_units - refund
    remaining = exposure.recoverable_provider_units - refund
    # No stablecoin or token award while the consumer's full refund is unfunded.
    stable = min(remaining * policy.stable_reward_bps // 10_000, policy.max_stable_reward_units) if not shortfall else 0
    token = policy.token_reward_units if not shortfall else 0
    return {"refund_units": refund, "unfunded_refund_units": shortfall,
            "token_reward_units": token, "stable_reward_units": stable}


def build_decision_document(
    *, expected_incident: Mapping[str, Any], reporter_public_key: str, policy: AdjudicationPolicy,
    exposure: EconomicExposure, outcome: str, issued_at: int, expires_at: int, nonce: str,
) -> dict[str, Any]:
    """Prepare exact unsigned content for independent authorities to review/sign.

    No signer keys are accepted here. Authorities sign with identity.sign_document
    using ADJUDICATION_PURPOSE and policy.audience, outside the Relay reporter.
    """
    identity, digest = _incident_binding(expected_incident)
    reporter_public_key = _key(reporter_public_key, "reporter_public_key")
    if reporter_public_key != expected_incident["evidence"].get("observer_public_key"):
        raise AdjudicationError("reporter does not match the incident observer")
    _integer(issued_at, "issued_at")
    _integer(expires_at, "expires_at")
    if expires_at <= issued_at or expires_at - issued_at > policy.max_decision_lifetime_seconds:
        raise AdjudicationError("decision lifetime exceeds policy or is empty")
    if len(_text(nonce, "nonce")) > 128:
        raise AdjudicationError("nonce is too long")
    return {
        "version": 1, "domain": policy.domain, "policy_hash": policy.policy_hash,
        "incident_id": identity, "incident_record_hash": digest, "reporter_public_key": reporter_public_key,
        "outcome": outcome, "economic_context": exposure.to_dict(), "amounts": _amounts(policy, exposure, outcome),
        "issued_at": issued_at, "expires_at": expires_at, "nonce": nonce,
    }


def verify_adjudication(
    signed_votes: Sequence[Mapping[str, Any]], *, expected_incident: Mapping[str, Any],
    reporter_public_key: str, policy: AdjudicationPolicy, exposure: EconomicExposure, now: int | None = None,
) -> dict[str, Any]:
    """Validate a pinned quorum, returning an explicitly nonpayable certificate."""
    current_time = _integer(int(time.time()) if now is None else now, "now")
    if not isinstance(signed_votes, (list, tuple)) or not policy.threshold <= len(signed_votes) <= len(policy.authority_public_keys):
        raise AdjudicationError("insufficient or excessive quorum votes")
    reporter_public_key = _key(reporter_public_key, "reporter_public_key")
    verified_document = None
    signers: set[str] = set()
    frozen_votes = []
    for signed_vote in signed_votes:
        if not isinstance(signed_vote, Mapping):
            raise AdjudicationError("signed vote must be an object")
        frozen = json.loads(_canonical(dict(signed_vote)))
        signature = frozen.get("signature")
        if not isinstance(signature, dict):
            raise AdjudicationError("missing adjudicator signature")
        public_key = _key(signature.get("public_key"), "adjudicator public key")
        if public_key == reporter_public_key:
            raise AdjudicationError("reporter is excluded from adjudication")
        evidence = expected_incident.get("evidence") if isinstance(expected_incident, Mapping) else None
        registration = evidence.get("provider_registration") if isinstance(evidence, Mapping) else None
        if isinstance(registration, Mapping) and public_key == registration.get("public_key"):
            raise AdjudicationError("accused provider is excluded from adjudication")
        if public_key not in policy.authority_public_keys:
            raise AdjudicationError("adjudicator is not a pinned authority")
        if public_key in signers:
            raise AdjudicationError("duplicate adjudicator does not form a quorum")
        signature_time = _integer(signature.get("timestamp"), "signature timestamp")
        _text(signature.get("nonce"), "signature nonce")
        try:
            document = verify_document(frozen, purpose=ADJUDICATION_PURPOSE, audience=policy.audience,
                                       max_age_seconds=0, now=current_time)
        except (IdentityError, TypeError, ValueError) as exc:
            raise AdjudicationError(f"invalid adjudicator signature: {exc}") from exc
        expected = build_decision_document(
            expected_incident=expected_incident, reporter_public_key=reporter_public_key, policy=policy,
            exposure=exposure, outcome=document.get("outcome"), issued_at=document.get("issued_at"),
            expires_at=document.get("expires_at"), nonce=document.get("nonce"),
        )
        if _canonical(document) != _canonical(expected):
            raise AdjudicationError("decision does not match expected incident, policy, domain, or derived amounts")
        if document["issued_at"] > current_time + 30 or document["expires_at"] <= current_time:
            raise AdjudicationError("decision is expired or issued in the future")
        if not document["issued_at"] <= signature_time < document["expires_at"] or signature_time > current_time + 30:
            raise AdjudicationError("signature timestamp is outside the decision validity window")
        if verified_document is not None and _canonical(document) != _canonical(verified_document):
            raise AdjudicationError("adjudicators signed conflicting decisions")
        signers.add(public_key)
        frozen_votes.append(frozen)
        verified_document = document
    assert verified_document is not None
    return {
        "decision": verified_document, "decision_hash": evidence_hash(verified_document),
        "authority_public_keys": sorted(signers), "signed_votes": frozen_votes,
        "payable": False, "onchain_linked": False,
    }


class AdjudicationStore:
    """Durable terminal decisions; no balances, mint keys, or execution methods.

    Expiry is enforced at submission. Previously accepted decisions remain
    retrievable after expiry; expired certificates cannot initiate a new record.
    """

    def __init__(self, path: str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.fchmod(descriptor, 0o600)
            os.close(descriptor)
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("""CREATE TABLE IF NOT EXISTS adjudications (
            incident_id TEXT PRIMARY KEY, incident_record_hash TEXT NOT NULL,
            decision_hash TEXT NOT NULL, certificate_json TEXT NOT NULL, accepted_at INTEGER NOT NULL
        )""")

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self) -> AdjudicationStore:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeError("adjudication store is closed")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def submit(self, signed_votes: Sequence[Mapping[str, Any]], **verification: Any) -> dict[str, Any]:
        certificate = verify_adjudication(signed_votes, **verification)
        decision = certificate["decision"]
        now = verification.get("now")
        accepted_at = int(time.time()) if now is None else now
        with self._transaction() as db:
            row = db.execute("SELECT * FROM adjudications WHERE incident_id=?", (decision["incident_id"],)).fetchone()
            if row is not None:
                if row["decision_hash"] != certificate["decision_hash"] or row["incident_record_hash"] != decision["incident_record_hash"]:
                    raise AdjudicationError("conflicting terminal adjudication")
                return json.loads(row["certificate_json"])
            db.execute("INSERT INTO adjudications VALUES (?, ?, ?, ?, ?)",
                       (decision["incident_id"], decision["incident_record_hash"], certificate["decision_hash"],
                        _canonical(certificate), accepted_at))
            return certificate

    def get(self, incident_id: str) -> dict[str, Any] | None:
        with self._transaction() as db:
            row = db.execute("SELECT * FROM adjudications WHERE incident_id=?", (_text(incident_id, "incident_id"),)).fetchone()
            return json.loads(row["certificate_json"]) if row else None
