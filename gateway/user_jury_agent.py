"""High-reputation users review V9 disputes with their own optional Codex.

Reputation is an explicitly trusted, signed USER roster, not Provider routing
score or proof of independent control. Assignments are off-chain: current V9
still enforces its constructor-pinned committee. This module never signs or
broadcasts a transaction and never turns a model response into a human vote.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from . import chain, chain_v9
from .identity import IdentityError, verify_document
from .relay_adjudication_v9 import V9AdjudicationClient, V9AdjudicationError, V9OperatorConfig, _incident_commitment
from .relay_evidence import RelayEvidenceError, verify_relay_incident
from .relay_incidents import evidence_hash
from .adjudication_agent_model import AdvisorError, FACT_NAMES, validate_advice, validate_facts

ROSTER_PURPOSE = "mycomesh.jury.user-reputation.v1"
TASK_SCHEMA = "mycomesh.user-jury-task.v1"
REVIEW_SCHEMA = "mycomesh.user-jury-review.v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
PARTY_FIELDS = ("owner", "key", "provider", "provider_signer", "relay", "relay_signer", "pool", "treasury")


class JuryError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JuryError("duplicate JSON field")
        result[key] = value
    return result


def read_json(path: str | Path) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            raise JuryError("input must be a bounded regular JSON file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(MAX_JSON_BYTES + 1)
        if len(data) > MAX_JSON_BYTES:
            raise JuryError("input exceeds size limit")
        value = json.loads(data, object_pairs_hook=_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(JuryError("nonfinite JSON")))
        if not isinstance(value, dict):
            raise JuryError("input must be a JSON object")
        return value
    finally:
        os.close(fd)


def write_private_json(path: str | Path, value: dict) -> None:
    data = _canonical(value)
    if len(data) > MAX_JSON_BYTES:
        raise JuryError("output exceeds size limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _uint(value, label, maximum=10**9):
    if type(value) is not int or not 0 <= value <= maximum:
        raise JuryError("invalid " + label)
    return value


def _address(value):
    normalized = chain.normalize_address(value)
    if value != normalized or normalized == chain.ZERO_ADDRESS:
        raise JuryError("noncanonical or zero user address")
    return normalized


def _text(value, label, maximum=200):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise JuryError("invalid " + label)
    return value


def verify_user_roster(signed: dict, *, config: V9OperatorConfig, authority_public_key: str,
                       now: int) -> list[dict]:
    """Verify an attestation; do not pretend the attested score is chain-derived."""
    if not re.fullmatch(r"[0-9a-f]{64}", authority_public_key or ""):
        raise JuryError("a separately pinned reputation authority is required")
    if (not isinstance(signed, dict) or not isinstance(signed.get("signature"), dict)
            or signed["signature"].get("public_key") != authority_public_key):
        raise JuryError("untrusted user reputation authority")
    try:
        roster = verify_document(signed, purpose=ROSTER_PURPOSE, audience=evidence_hash(config.domain),
                                 now=now, max_age_seconds=86400)
    except (IdentityError, TypeError, ValueError) as exc:
        raise JuryError("user reputation signature is invalid") from exc
    if set(roster) != {"schema", "domain", "issued_at", "expires_at", "users"}:
        raise JuryError("invalid user reputation schema")
    if roster["schema"] != ROSTER_PURPOSE or roster["domain"] != config.domain:
        raise JuryError("user reputation targets another deployment")
    issued = _uint(roster["issued_at"], "roster time", 2**63 - 1)
    expires = _uint(roster["expires_at"], "roster expiry", 2**63 - 1)
    if (not issued <= now < expires or expires - issued > 86400
            or signed["signature"]["timestamp"] != issued):
        raise JuryError("user reputation is not current")
    if not isinstance(roster["users"], list) or not 1 <= len(roster["users"]) <= 1024:
        raise JuryError("invalid user roster size")
    users, seen = [], set()
    for user in roster["users"]:
        if not isinstance(user, dict) or set(user) != {
            "address", "operator_id", "score", "score_source_hash", "affiliated_addresses", "opt_in"
        }:
            raise JuryError("invalid user reputation entry")
        address = _address(user["address"])
        if address in seen:
            raise JuryError("duplicate user")
        seen.add(address)
        _text(user["operator_id"], "operator identity")
        _uint(user["score"], "user reputation")
        if chain.normalize_bytes32(user["score_source_hash"]) == chain.ZERO_BYTES32:
            raise JuryError("reputation source commitment is required")
        if type(user["opt_in"]) is not bool:
            raise JuryError("user opt-in must be explicit")
        aliases = user["affiliated_addresses"]
        if (not isinstance(aliases, list) or len(aliases) > 32
                or any(not isinstance(alias, str) for alias in aliases) or len(set(aliases)) != len(aliases)):
            raise JuryError("invalid affiliated addresses")
        for alias in aliases:
            _address(alias)
        users.append(copy.deepcopy(user))
    return users


def review_incident(incident: dict, *, observer_public_key: str, observed_at: int,
                    observation_source_ref: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", observer_public_key or ""):
        raise JuryError("an independently pinned observer is required")
    _uint(observed_at, "trusted observation time", 2**63 - 1)
    _text(observation_source_ref, "observation source")
    if len(_canonical(incident)) > MAX_JSON_BYTES:
        raise JuryError("incident exceeds size limit")
    committed, verified = False, None
    try:
        _incident_commitment(incident)
        committed = True
        verified = verify_relay_incident(incident, expected_observer_public_key=observer_public_key,
                                         observed_at=observed_at)
    except (V9AdjudicationError, RelayEvidenceError, KeyError, TypeError, ValueError):
        pass  # Exceptions may reflect attacker text; never send them to Codex.
    protocol = ("v9" if incident["evidence"]["settlement_version"] == 9 else "other") if verified else "unverified"
    values = ["verified" if committed else "unverified", "verified" if verified else "unverified",
              verified["classification"] if verified else "unverifiable", protocol,
              "not_checked", "not_checked", "not_checked", "not_checked"]
    facts = validate_facts([{"id": f"F{i+1:02}", "name": name, "value": value}
                            for i, (name, value) in enumerate(zip(FACT_NAMES, values))])
    return {"schema": REVIEW_SCHEMA, "mode": "user_review", "facts": facts,
            "incident_record_hash": incident["record_hash"] if committed else None,
            "provenance": {"observer_public_key": observer_public_key, "observed_at": observed_at,
                           "observation_source_ref": observation_source_ref, "verifier": "relay_evidence.v1"},
            "recommendation": "requires_user_review" if verified and protocol == "v9" else "insufficient_evidence",
            "monetary_verdict": False, "model_identity_proven": False, "transaction_authorized": False,
            "codex_advice": None, "codex_status": "not_requested"}


class UserJuryAgent:
    def __init__(self, client: V9AdjudicationClient, *, reputation_public_key: str, minimum_score: int):
        self.client = client
        if not re.fullmatch(r"[0-9a-f]{64}", reputation_public_key or ""):
            raise JuryError("reputation authority must be pinned locally")
        self.reputation_public_key = reputation_public_key
        self.minimum_score = _uint(minimum_score, "minimum reputation")
        if not self.minimum_score:
            raise JuryError("minimum user reputation must be positive")

    def _case(self, incident, settlement_key, actor):
        _incident_commitment(incident)
        c = self.client.config
        report_id = chain_v9.report_id_for(settlement_key, c.reporter_address, incident["record_hash"])
        snapshot = self.client.snapshot(settlement_key, actor, report_id)
        if (snapshot["report"]["reporter"] != c.reporter_address
                or snapshot["report"]["evidence_hash"] != incident["record_hash"]):
            raise JuryError("case does not match an actual onchain report")
        record = snapshot["settlement"]
        if (record["status"] != 2 or not record["release_at"] <= snapshot["timestamp"]
                < snapshot["dispute"]["resolve_at"]):
            raise JuryError("case is outside its voting window")
        return snapshot

    def _eligible(self, signed_roster, snapshot):
        c = self.client.config
        users = verify_user_roster(signed_roster, config=c, authority_public_key=self.reputation_public_key,
                                   now=int(time.time()))
        parties = {snapshot["settlement"][f] for f in PARTY_FIELDS}
        parties.update((c.reporter_address, snapshot["policy"]["bond_penalty_recipient"]))
        eligible = []
        for user in users:
            address = user["address"]
            if (not user["opt_in"] or user["score"] < self.minimum_score or address not in c.adjudicators
                    or user["operator_id"] != c.adjudicator_operators[address]
                    or parties.intersection({address, *user["affiliated_addresses"]})):
                continue
            eligible.append(user)
        # Deterministic priority, NOT a claim of unbiased random selection.
        return sorted(eligible, key=lambda u: (-u["score"], u["address"]))

    def assign(self, *, incident: dict, observed_at: int, observation_source_ref: str,
               settlement_key: str, signed_roster: dict) -> list[dict]:
        c = self.client.config
        review_incident(incident, observer_public_key=c.observer_public_key, observed_at=observed_at,
                        observation_source_ref=observation_source_ref)
        snapshot = self._case(incident, settlement_key, c.reporter_address)
        eligible = self._eligible(signed_roster, snapshot)
        if len(eligible) < c.threshold:
            raise JuryError("not enough opted-in, qualified, nonconflicting registered users")
        tasks = []
        # Current V9 requires a majority of its fixed committee, so do not
        # strand lower-ranked eligible users behind an exhausted top-N slice.
        for user in eligible:
            user_snapshot = self._case(incident, settlement_key, user["address"])
            if user_snapshot["actor_vote"] or user_snapshot["has_reported"]:
                continue
            task = {"schema": TASK_SCHEMA, "domain": c.domain, "reviewer": user["address"],
                    "settlement_key": settlement_key, "incident": copy.deepcopy(incident),
                    "observed_at": observed_at, "observation_source_ref": observation_source_ref,
                    "signed_user_roster": copy.deepcopy(signed_roster), "minimum_score": self.minimum_score,
                    "roster_authority": self.reputation_public_key,
                    "assignment_block": {"number": user_snapshot["block_number"], "hash": user_snapshot["block_hash"]},
                    "expires_at": min(signed_roster["expires_at"], snapshot["dispute"]["resolve_at"]),
                    "selection_enforcement": "offchain_assignment_existing_v9_committee",
                    "transaction_authorized": False}
            task["task_hash"] = evidence_hash(task)
            tasks.append(task)
        return tasks

    def _validate_task(self, task, reviewer, *, observed_at, observation_source_ref):
        fields = {"schema", "domain", "reviewer", "settlement_key", "incident", "observed_at",
                  "observation_source_ref", "signed_user_roster", "minimum_score", "roster_authority",
                  "assignment_block", "expires_at", "selection_enforcement", "transaction_authorized", "task_hash"}
        if not isinstance(task, dict) or set(task) != fields or task["schema"] != TASK_SCHEMA:
            raise JuryError("invalid user task schema")
        if evidence_hash({k: v for k, v in task.items() if k != "task_hash"}) != task["task_hash"]:
            raise JuryError("task content changed")
        # A task hash is not an authentication or timestamp authority. The user
        # supplies observation provenance independently of the received task.
        _uint(observed_at, "trusted observation time", 2**63 - 1)
        _text(observation_source_ref, "observation source")
        _uint(task["observed_at"], "task observation time", 2**63 - 1)
        _uint(task["expires_at"], "task expiry", 2**63 - 1)
        _uint(task["minimum_score"], "task minimum reputation")
        if (task["observed_at"] != observed_at
                or task["observation_source_ref"] != observation_source_ref):
            raise JuryError("task observation does not match independently trusted provenance")
        if (task["domain"] != self.client.config.domain or task["reviewer"] != _address(reviewer)
                or task["roster_authority"] != self.reputation_public_key
                or task["minimum_score"] != self.minimum_score or task["transaction_authorized"] is not False
                or task["selection_enforcement"] != "offchain_assignment_existing_v9_committee"
                or int(time.time()) >= task["expires_at"]):
            raise JuryError("task does not match local user/deployment/reputation pins or has expired")
        snapshot = self._case(task["incident"], task["settlement_key"], reviewer)
        if task["expires_at"] != min(task["signed_user_roster"]["expires_at"], snapshot["dispute"]["resolve_at"]):
            raise JuryError("task expiry does not match roster and dispute limits")
        eligible = self._eligible(task["signed_user_roster"], snapshot)
        if reviewer not in {u["address"] for u in eligible} or len(eligible) < self.client.config.threshold:
            raise JuryError("user is not eligible for this assignment")
        if snapshot["actor_vote"] or snapshot["has_reported"]:
            raise JuryError("user has already voted or reported")
        return snapshot

    def review(self, task: dict, *, reviewer: str, observed_at: int,
               observation_source_ref: str, advisor=None) -> dict:
        snapshot = self._validate_task(task, reviewer, observed_at=observed_at,
                                       observation_source_ref=observation_source_ref)
        c = self.client.config
        report = review_incident(task["incident"], observer_public_key=c.observer_public_key,
                                 observed_at=task["observed_at"], observation_source_ref=task["observation_source_ref"])
        facts = report["facts"]
        if facts[2]["value"] == "protocol_contradiction" and facts[3]["value"] == "v9":
            try:
                self.client._evidence(task["incident"], task["observed_at"], snapshot)
                facts[4]["value"] = "matched"
            except (V9AdjudicationError, RelayEvidenceError, chain.ChainError, KeyError, TypeError, ValueError):
                facts[4]["value"] = "mismatched"
                report["recommendation"] = "insufficient_evidence"
        facts[5]["value"], facts[6]["value"], facts[7]["value"] = "matched", "eligible", "open"
        report.update(task_hash=task["task_hash"], reviewer=reviewer,
                      snapshot_block={"number": snapshot["block_number"], "hash": snapshot["block_hash"]},
                      eligible_for_confirming_vote_review=facts[4]["value"] == "matched")
        if advisor is not None:
            try:
                advice = validate_advice(advisor.advise(copy.deepcopy(facts)), facts)
                if advice["recommendation"] == "review_violation" and facts[4]["value"] != "matched":
                    report["codex_status"] = "unsupported_suggestion"
                else:
                    report.update(codex_advice=advice, codex_status="suggestion_only")
            except AdvisorError:
                report["codex_status"] = "unavailable_or_invalid"
        report["review_hash"] = evidence_hash(report)
        return report

    def plan_user_vote(self, task: dict, *, reviewer: str, observed_at: int,
                       observation_source_ref: str, approved_review: dict) -> dict:
        """User-written review is still unsigned; the existing outbox signs later."""
        self._validate_task(task, reviewer, observed_at=observed_at, observation_source_ref=observation_source_ref)
        if not isinstance(approved_review, dict) or set(approved_review) != {
            "task_hash", "reviewer", "incident_record_hash", "outcome", "reason"
        }:
            raise JuryError("explicit user review is required; a Codex suggestion is not a vote")
        if (approved_review["task_hash"] != task["task_hash"] or approved_review["reviewer"] != reviewer
                or approved_review["incident_record_hash"] != task["incident"]["record_hash"]):
            raise JuryError("user approval does not bind this exact case")
        if approved_review["outcome"] not in ("confirmed", "dismissed"):
            raise JuryError("user must choose confirmed or dismissed; abstention sends no vote")
        review = {k: v for k, v in approved_review.items() if k != "task_hash"}
        return self.client.plan_vote(incident=task["incident"], observed_at=task["observed_at"],
                                     settlement_key=task["settlement_key"], actor=reviewer,
                                     confirmed=review["outcome"] == "confirmed", review=review)


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Locally pinned V9 operator config")
    parser.add_argument("--reputation-public-key", required=True)
    parser.add_argument("--minimum-score", required=True, type=int)
    commands = parser.add_subparsers(dest="command", required=True)
    assign = commands.add_parser("assign")
    assign.add_argument("--incident", required=True)
    assign.add_argument("--roster", required=True)
    assign.add_argument("--settlement-key", required=True)
    assign.add_argument("--observed-at", required=True, type=int)
    assign.add_argument("--observation-source", required=True)
    assign.add_argument("--output-directory", required=True)
    for command in ("review", "plan-vote"):
        sub = commands.add_parser(command)
        sub.add_argument("--task", required=True)
        sub.add_argument("--reviewer", required=True)
        sub.add_argument("--observed-at", required=True, type=int, help="Independently trusted observation time, not copied from task")
        sub.add_argument("--observation-source", required=True, help="Independently trusted observation record reference")
        sub.add_argument("--output", required=True)
        if command == "plan-vote":
            sub.add_argument("--approved-review", required=True)
        else:
            sub.add_argument("--use-own-codex", action="store_true")
            sub.add_argument("--codex-command", default="codex")
            sub.add_argument("--codex-home")
            sub.add_argument("--model")
    args = parser.parse_args(argv)
    agent = UserJuryAgent(V9AdjudicationClient(V9OperatorConfig.load(args.config)),
                          reputation_public_key=args.reputation_public_key, minimum_score=args.minimum_score)
    if args.command == "assign":
        tasks = agent.assign(incident=read_json(args.incident), observed_at=args.observed_at,
                             observation_source_ref=args.observation_source, settlement_key=args.settlement_key,
                             signed_roster=read_json(args.roster))
        directory = Path(args.output_directory)
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        for task in tasks:
            write_private_json(directory / (task["reviewer"] + ".json"), task)
        print(json.dumps({"tasks": len(tasks), "directory": str(directory), "sent": False}))
    elif args.command == "review":
        advisor = None
        if args.use_own_codex:
            if not args.codex_home or not args.model:
                parser.error("--use-own-codex requires the user's --codex-home and --model")
            from .adjudication_agent_model import LocalCodexAdvisor
            advisor = LocalCodexAdvisor(command=args.codex_command, codex_home=args.codex_home, model=args.model)
        result = agent.review(read_json(args.task), reviewer=args.reviewer, observed_at=args.observed_at,
                               observation_source_ref=args.observation_source, advisor=advisor)
        write_private_json(args.output, result)
        print(json.dumps({"review_hash": result["review_hash"], "codex_status": result["codex_status"], "sent": False}))
    else:
        plan = agent.plan_user_vote(read_json(args.task), reviewer=args.reviewer,
                                    observed_at=args.observed_at, observation_source_ref=args.observation_source,
                                    approved_review=read_json(args.approved_review))
        write_private_json(args.output, plan)
        print(json.dumps({"plan_hash": plan["plan_hash"], "sent": False}))
    return 0


def main(argv=None) -> int:
    try:
        return _main(argv)
    except (JuryError, V9AdjudicationError, chain.ChainError, AdvisorError,
            OSError, ValueError, KeyError, TypeError):
        # RPC errors may contain credentials and evidence errors attacker text.
        print(json.dumps({"error": "User jury operation failed; verify local pins, task, evidence and chain state.",
                          "sent": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
