"""Operator-gated V9 reporting, voting, claims, and overdue escrow maintenance.

This is NOT a fraud oracle or an automatic slashing worker. A verified Relay
incident permits a bonded *allegation*, not a verdict. Independent, pinned EVM
committee operators review evidence and explicitly approve their own votes.
An explicitly opted-in controlled test mode labels a single operator's test
wallets honestly; it does not establish independent users or reputation.
Ed25519 certificates never grant EVM voting authority. All public plan methods
are read-only; execution requires the exact approved plan hash, protected key,
chain/deployment pins and a durable one-shot transaction outbox.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any, Mapping

from . import chain, chain_v9
from .relay_evidence import verify_relay_incident
from .relay_incidents import evidence_hash


class V9AdjudicationError(ValueError):
    pass


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _uint(value: Any, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive) or value >= 2**256:
        raise V9AdjudicationError(f"invalid {name}")
    return value


def _address(value: Any) -> str:
    return chain.normalize_address(value)


def _hash(value: Any) -> str:
    return chain.normalize_bytes32(value)


def _incident_commitment(incident: Mapping[str, Any]) -> None:
    fields = ("provider_id", "provider_signer", "request_id", "request_hash", "kind", "severity", "evidence")
    try:
        if (evidence_hash({field: incident[field] for field in fields}) != incident["record_hash"]
                or evidence_hash(incident["evidence"]) != incident["evidence_hash"]):
            raise V9AdjudicationError("incident content differs from the onchain evidence commitment")
    except (KeyError, TypeError) as exc:
        raise V9AdjudicationError("complete committed incident is required") from exc


@dataclass(frozen=True)
class V9OperatorConfig:
    """Pins are supplied by the operator, never discovered and silently trusted."""

    rpc_url: str
    chain_id: int
    settlement_contract: str
    runtime_code_hash: str
    genesis_hash: str
    policy_hash: str
    adjudicators: tuple[str, ...]
    adjudicator_operators: Mapping[str, str]
    independence_attested: bool
    threshold: int
    observer_public_key: str
    reporter_address: str
    confirmations: int
    max_snapshot_age_seconds: int = 300
    timeout_seconds: int = 15
    committee_mode: str = chain_v9.INDEPENDENT_COMMITTEE
    allow_controlled_test: bool = False

    def __post_init__(self) -> None:
        _uint(self.chain_id, "chain_id", positive=True)
        _uint(self.confirmations, "confirmations", positive=True)
        _uint(self.max_snapshot_age_seconds, "max_snapshot_age_seconds", positive=True)
        _uint(self.timeout_seconds, "timeout_seconds", positive=True)
        for name in ("settlement_contract", "reporter_address"):
            if _address(getattr(self, name)) != getattr(self, name) or getattr(self, name) == chain.ZERO_ADDRESS:
                raise V9AdjudicationError(f"noncanonical {name}")
        for name in ("runtime_code_hash", "genesis_hash", "policy_hash"):
            if _hash(getattr(self, name)) != getattr(self, name) or getattr(self, name) == chain.ZERO_BYTES32:
                raise V9AdjudicationError(f"noncanonical {name}")
        if (not isinstance(self.adjudicators, tuple) or len(set(self.adjudicators)) != len(self.adjudicators)
                or not 2 <= self.threshold <= len(self.adjudicators) <= 16
                or self.threshold <= len(self.adjudicators) // 2
                or any(_address(x) != x or x == chain.ZERO_ADDRESS for x in self.adjudicators)):
            raise V9AdjudicationError("operator must pin a distinct majority EVM committee")
        if (not isinstance(self.observer_public_key, str) or len(self.observer_public_key) != 64
                or any(c not in "0123456789abcdef" for c in self.observer_public_key)):
            raise V9AdjudicationError("operator must pin the evidence observer public key")
        if self.reporter_address in self.adjudicators:
            raise V9AdjudicationError("reporter must not be a committee address")
        operators = self.adjudicator_operators
        if (not isinstance(operators, Mapping) or set(operators) != set(self.adjudicators)
                or any(not isinstance(value, str) or not value.strip() for value in operators.values())):
            raise V9AdjudicationError("explicit distinct-operator committee attestation is required")
        distinct_operators = len({value.strip().casefold() for value in operators.values()})
        if self.committee_mode == chain_v9.CONTROLLED_TEST_COMMITTEE:
            if (self.allow_controlled_test is not True or self.independence_attested is not False
                    or distinct_operators != 1 or self.chain_id not in chain_v9.CONTROLLED_TEST_CHAIN_IDS):
                raise V9AdjudicationError("controlled test requires explicit opt-in, one declared operator, false independence and a test chain")
        elif (self.committee_mode != chain_v9.INDEPENDENT_COMMITTEE or self.independence_attested is not True
              or distinct_operators != len(self.adjudicators)):
            raise V9AdjudicationError("explicit distinct-operator committee attestation is required")
        # This operator declaration is auditable context, not proof of distinct
        # human control. Controlled mode declares one actual operator explicitly.
        object.__setattr__(self, "adjudicator_operators", dict(operators))

    @property
    def domain(self) -> dict[str, Any]:
        value = {name: getattr(self, name) for name in (
            "chain_id", "settlement_contract", "runtime_code_hash", "genesis_hash", "policy_hash",
        )}
        if self.committee_mode == chain_v9.CONTROLLED_TEST_COMMITTEE:
            value["committee_mode"] = self.committee_mode
        return value

    @classmethod
    def load(cls, path: str | Path) -> "V9OperatorConfig":
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
        value["adjudicators"] = tuple(value["adjudicators"])
        return cls(**value)


class V9AdjudicationClient:
    def __init__(self, config: V9OperatorConfig) -> None:
        self.config = config

    def rpc(self, method: str, params: list[Any]) -> Any:
        return chain.rpc_call(self.config.rpc_url, method, params, self.config.timeout_seconds)

    def confirmed_context(self) -> dict[str, Any]:
        """Validate deployment pins at a fresh, confirmed canonical block."""
        c = self.config
        if int(self.rpc("eth_chainId", []), 16) != c.chain_id:
            raise V9AdjudicationError("RPC chain does not match pinned chain")
        if self.rpc("eth_getBlockByNumber", ["0x0", False])["hash"].lower() != c.genesis_hash:
            raise V9AdjudicationError("RPC genesis does not match pinned network")
        head = int(self.rpc("eth_blockNumber", []), 16)
        number = head - c.confirmations + 1
        if number < 0:
            raise V9AdjudicationError("insufficient chain confirmations")
        block = self.rpc("eth_getBlockByNumber", [hex(number), False])
        block_hash, timestamp = _hash(block["hash"]), int(block["timestamp"], 16)
        if int(block["number"], 16) != number:
            raise V9AdjudicationError("RPC returned the wrong block")
        if not -30 <= int(time.time()) - timestamp <= c.max_snapshot_age_seconds:
            raise V9AdjudicationError("confirmed snapshot is stale or from the future")
        tag = {"blockHash": block_hash, "requireCanonical": True}
        code = self.rpc("eth_getCode", [c.settlement_contract, tag])
        if code == "0x" or "0x" + chain.keccak256(bytes.fromhex(code[2:])).hex() != c.runtime_code_hash:
            raise V9AdjudicationError("settlement bytecode does not match operator pin")
        kw = {"timeout": c.timeout_seconds, "block_tag": tag}
        args = (c.rpc_url, c.settlement_contract)
        policy = chain_v9.dispute_policy(*args, **kw)
        judges = chain_v9.adjudicators(*args, **kw)
        threshold = self._uint_call("adjudicationThreshold()", [], tag)
        if evidence_hash(policy) != c.policy_hash or set(judges) != set(c.adjudicators) or threshold != c.threshold:
            raise V9AdjudicationError("onchain policy or committee differs from operator pins")
        if self.rpc("eth_getBlockByNumber", [hex(number), False])["hash"].lower() != block_hash:
            raise V9AdjudicationError("snapshot block was reorganized")
        return {"domain": c.domain, "block_number": number, "block_hash": block_hash,
                "timestamp": timestamp, "policy": policy, "adjudicators": judges, "threshold": threshold}

    def snapshot(self, settlement_key: str, actor: str, report_id: str = chain.ZERO_BYTES32) -> dict[str, Any]:
        """Every eth_call and bytecode read is pinned to one canonical block hash."""
        c = self.config
        settlement_key, actor, report_id = _hash(settlement_key), _address(actor), _hash(report_id)
        context = self.confirmed_context()
        number, block_hash = context["block_number"], context["block_hash"]
        tag = {"blockHash": block_hash, "requireCanonical": True}
        kw = {"timeout": c.timeout_seconds, "block_tag": tag}
        args = (c.rpc_url, c.settlement_contract)
        snapshot = {
            **context,
            "settlement_key": settlement_key, "actor": actor, "report_id": report_id,
            "settlement": chain_v9.settlement_info(*args, settlement_key, **kw),
            "dispute": chain_v9.dispute_info(*args, settlement_key, **kw),
            "report": (chain_v9.report_info(*args, settlement_key, report_id, **kw)
                       if report_id != chain.ZERO_BYTES32 else
                       {"reporter": chain.ZERO_ADDRESS, "evidence_hash": chain.ZERO_BYTES32, "bond_claimed": False}),
            "has_reported": chain_v9.has_reported(*args, settlement_key, actor, **kw),
            "actor_vote": chain_v9.dispute_vote(*args, settlement_key, actor, **kw),
            "claimable": chain_v9.claimable_balance(*args, actor, **kw),
            "token_claimable": chain_v9.token_claimable_balance(*args, actor, **kw),
        }
        # Detect a reorg during the set of reads, even with a permissive RPC.
        if self.rpc("eth_getBlockByNumber", [hex(number), False])["hash"].lower() != block_hash:
            raise V9AdjudicationError("snapshot block was reorganized")
        return snapshot

    def _uint_call(self, signature: str, args: list[str], tag: Any) -> int:
        data = self.rpc("eth_call", [{"to": self.config.settlement_contract,
                                     "data": chain.encode_contract_call(signature, args)}, tag])
        if not isinstance(data, str) or len(data) != 66:
            raise V9AdjudicationError("malformed uint256 RPC response")
        return int(data[2:], 16)

    def _evidence(self, incident: Mapping[str, Any], observed_at: int, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        c, record = self.config, snapshot["settlement"]
        _incident_commitment(incident)
        verified = verify_relay_incident(incident, expected_observer_public_key=c.observer_public_key,
                                         observed_at=observed_at)
        if verified["classification"] != "protocol_contradiction":
            raise V9AdjudicationError("soft probes and contextual allegations cannot trigger monetary reports")
        evidence = incident["evidence"]
        if evidence["settlement_version"] != 9:
            raise V9AdjudicationError("V7/V8 evidence cannot slash a V9 settlement")
        envelope = evidence["provider_response"].get("mycomesh_v9_settlement")
        payment, receipt, _, _, _ = chain_v9.verify_provider_receipt(envelope, now=observed_at)
        auth = payment["authorization"]
        if envelope["chain_id"] != c.chain_id or _address(envelope["settlement_contract"]) != c.settlement_contract:
            raise V9AdjudicationError("incident targets another deployment")
        if record["status"] == 0 or not record["settled_at"]:
            raise V9AdjudicationError("only an actually settled receipt can be disputed")
        bindings = {
            "key": auth["key"], "request_id": auth["request_id"], "request_hash": auth["request_hash"],
            "relay_signer": auth["relay_signer"], "provider": receipt.provider,
            "provider_signer": receipt.provider_signer, "relay": receipt.relay, "pool": receipt.pool,
            "authorization_hash": receipt.authorization_hash, "response_hash": receipt.response_hash,
            "gross_fee": receipt.actual_fee,
        }
        if any(record.get(field) != value for field, value in bindings.items()):
            raise V9AdjudicationError("incident receipt differs from immutable onchain settlement")
        if verified["provider_signer"] != record["provider_signer"]:
            raise V9AdjudicationError("evidence signer differs from settled Provider")
        if snapshot["settlement_key"] != chain_v9.settlement_key_for(record["owner"], auth["key"], auth["request_id"]):
            raise V9AdjudicationError("settlement key does not bind owner/key/request")
        if incident["request_id"] != auth["request_id"] or incident["request_hash"] != auth["request_hash"]:
            raise V9AdjudicationError("incident request differs from settlement")
        return verified

    def _plan(self, action: str, snapshot: dict[str, Any], data: str, inputs: dict[str, Any],
              *, amounts: dict[str, int] | None = None) -> dict[str, Any]:
        plan = {
            "schema": "mycomesh.v9.operator-plan.v1", "action": action, "dry_run": True,
            "domain": self.config.domain, "snapshot": snapshot, "inputs": inputs,
            "transaction": {"from": snapshot["actor"], "to": self.config.settlement_contract,
                            "chain_id": self.config.chain_id, "value": 0, "data": data},
            "amounts": amounts or {}, "monetary_verdict": False,
        }
        # Copy before hashing: mutation of the original incident cannot edit a plan.
        plan = json.loads(_json(plan))
        return {**plan, "plan_hash": evidence_hash(plan)}

    def plan_report(self, *, incident: Mapping[str, Any], observed_at: int, settlement_key: str) -> dict[str, Any]:
        actor = self.config.reporter_address
        snap = self.snapshot(settlement_key, actor)
        self._evidence(incident, observed_at, snap)
        record = snap["settlement"]
        if record["status"] not in (1, 2) or snap["timestamp"] >= record["release_at"]:
            raise V9AdjudicationError("settlement is outside its evidence window")
        if actor in (record["provider"], record["provider_signer"], snap["policy"]["bond_penalty_recipient"]):
            raise V9AdjudicationError("reporter is a forbidden party")
        if snap["has_reported"]:
            raise V9AdjudicationError("reporter already submitted evidence")
        evidence_commitment = _hash(incident["record_hash"])
        encode = chain_v9.encode_open_dispute if record["status"] == 1 else chain_v9.encode_submit_evidence
        return self._plan("report", snap, encode(settlement_key, evidence_commitment), {
            "incident": dict(incident), "observed_at": observed_at, "settlement_key": settlement_key,
        }, amounts={"reporter_bond_units": snap["policy"]["reporter_bond"]})

    def plan_vote(self, *, incident: Mapping[str, Any], observed_at: int, settlement_key: str,
                  actor: str, confirmed: bool, review: Mapping[str, Any]) -> dict[str, Any]:
        """An operator-authored review commits reasons; it is not an auto-verdict."""
        if type(confirmed) is not bool:
            raise V9AdjudicationError("confirmed must be a boolean")
        actor = _address(actor)
        report_id = chain_v9.report_id_for(settlement_key, self.config.reporter_address, incident["record_hash"])
        snap = self.snapshot(settlement_key, actor, report_id)
        if confirmed:
            self._evidence(incident, observed_at, snap)
        else:
            # A judge must be able to dismiss malformed/unproven allegations.
            # Only confirming votes require a reproduced Provider contradiction;
            # dismissal still commits the exact reported bytes and human review.
            _incident_commitment(incident)
        record, dispute, report = snap["settlement"], snap["dispute"], snap["report"]
        if (record["status"] != 2 or not record["release_at"] <= snap["timestamp"] < dispute["resolve_at"]):
            raise V9AdjudicationError("settlement is not in its adjudication window")
        parties = [record[field] for field in ("owner", "key", "provider", "provider_signer", "relay",
                                               "relay_signer", "pool", "treasury")]
        parties += [self.config.reporter_address, snap["policy"]["bond_penalty_recipient"]]
        if actor not in self.config.adjudicators or actor in parties or snap["has_reported"]:
            raise V9AdjudicationError("vote requires an independent pinned EVM committee member")
        if snap["actor_vote"]:
            raise V9AdjudicationError("adjudicator already voted; votes are irreversible")
        if report["reporter"] != self.config.reporter_address or report["evidence_hash"] != incident["record_hash"]:
            raise V9AdjudicationError("onchain report does not match the reviewed evidence")
        if not isinstance(review, Mapping) or set(review) != {"reviewer", "incident_record_hash", "outcome", "reason"}:
            raise V9AdjudicationError("explicit independent reviewer/reason/incident/outcome document required")
        if (review["reviewer"] != actor or review["incident_record_hash"] != incident["record_hash"]
                or review["outcome"] != ("confirmed" if confirmed else "dismissed")
                or not isinstance(review["reason"], str) or not 20 <= len(review["reason"].strip()) <= 8000):
            raise V9AdjudicationError("review does not bind independent reviewer, incident, outcome and reasons")
        decision = {"domain": self.config.domain, "settlement_key": settlement_key,
                    "report_id": report_id, "review": dict(review), "policy": snap["policy"]}
        data = chain_v9.encode_vote_dispute(settlement_key, confirmed=confirmed,
                report_id=report_id if confirmed else chain.ZERO_BYTES32, decision_hash=evidence_hash(decision))
        return self._plan("vote", snap, data, {
            "incident": dict(incident), "observed_at": observed_at, "settlement_key": settlement_key,
            "actor": actor, "confirmed": confirmed, "review": dict(review),
        })

    def plan_claim(self, *, actor: str, settlement_key: str, kind: str,
                   report_id: str = chain.ZERO_BYTES32) -> dict[str, Any]:
        snap = self.snapshot(settlement_key, actor, report_id)
        if kind == "stable":
            amount, data = snap["claimable"], chain.encode_contract_call("claim()", [])
        elif kind == "token":
            amount, data = snap["token_claimable"], chain_v9.encode_claim_token_reward()
        elif kind == "bond":
            report = snap["report"]
            if (snap["settlement"]["status"] not in (4, 6) or report["reporter"] != _address(actor)
                    or report["bond_claimed"]):
                raise V9AdjudicationError("reporter bond is not refundable to this actor")
            amount = snap["policy"]["reporter_bond"]
            data = chain_v9.encode_claim_dispute_bond(settlement_key, report_id)
        else:
            raise V9AdjudicationError("unknown claim kind")
        if amount <= 0:
            raise V9AdjudicationError("no onchain credit is claimable")
        return self._plan("claim", snap, data, {"actor": actor, "settlement_key": settlement_key,
            "kind": kind, "report_id": report_id}, amounts={"claim_units": amount})

    def _plan_lifecycle(self, action: str, *, actor: str, settlement_key: str) -> dict[str, Any]:
        actor, settlement_key = _address(actor), _hash(settlement_key)
        if actor == chain.ZERO_ADDRESS or settlement_key == chain.ZERO_BYTES32:
            raise V9AdjudicationError("maintenance requires a nonzero actor and settlement key")
        snap = self.snapshot(settlement_key, actor)
        record = snap["settlement"]
        if (not record["settled_at"] or record["gross_fee"] <= 0
                or settlement_key != chain_v9.settlement_key_for(record["owner"], record["key"], record["request_id"])):
            raise V9AdjudicationError("maintenance requires a matching escrowed settlement")
        if action == "release":
            if record["status"] != 1 or snap["timestamp"] < record["release_at"]:
                raise V9AdjudicationError("undisputed escrow is not due for release")
            data = chain_v9.encode_release(settlement_key)
        else:
            if (record["status"] != 2 or snap["dispute"]["resolve_at"] <= record["release_at"]
                    or snap["timestamp"] < snap["dispute"]["resolve_at"]):
                raise V9AdjudicationError("disputed escrow is not due for timeout resolution")
            data = chain_v9.encode_resolve_timed_out_dispute(settlement_key)
        return self._plan(action, snap, data, {"actor": actor, "settlement_key": settlement_key},
                          amounts={"escrow_fee_units": record["gross_fee"]})

    def plan_release(self, *, actor: str, settlement_key: str) -> dict[str, Any]:
        """Plan one permissionless matured release; never claim recipients' funds."""
        return self._plan_lifecycle("release", actor=actor, settlement_key=settlement_key)

    def plan_timeout(self, *, actor: str, settlement_key: str) -> dict[str, Any]:
        """Plan nonpunitive timeout resolution; silence is never a fraud verdict."""
        return self._plan_lifecycle("timeout", actor=actor, settlement_key=settlement_key)

    def verify_lifecycle(self, plan: Mapping[str, Any], *, minimum_block_number: int) -> dict[str, Any]:
        """Check business completion separately from successful EVM execution.

        This fresh, hash-pinned confirmed snapshot must include the transaction.
        Released earnings are claimable, not evidence of a wallet payout.
        """
        body = {key: value for key, value in plan.items() if key != "plan_hash"}
        if evidence_hash(body) != plan.get("plan_hash") or plan.get("domain") != self.config.domain:
            raise V9AdjudicationError("plan hash or deployment pin mismatch")
        action = plan.get("action")
        if action not in ("release", "timeout"):
            raise V9AdjudicationError("not an escrow maintenance plan")
        _uint(minimum_block_number, "minimum block number")
        snap = self.snapshot(**plan["inputs"])
        record, previous = snap["settlement"], plan["snapshot"]["settlement"]
        if snap["block_number"] < minimum_block_number:
            raise V9AdjudicationError("confirmed settlement snapshot predates the transaction")
        expected = 3 if action == "release" else 6
        if record["status"] != expected:
            raise V9AdjudicationError("transaction succeeded but expected settlement outcome is not verified")
        if any(record.get(name) != value for name, value in previous.items() if name not in ("status", "status_name")):
            raise V9AdjudicationError("settlement outcome differs from approved escrow")
        return {"verified": True, "settlement_key": snap["settlement_key"],
                "status": "released" if expected == 3 else "timed_out",
                "block_number": snap["block_number"], "block_hash": snap["block_hash"],
                "gross_fee_units": record["gross_fee"], "wallet_payout_verified": False}

    def refresh(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        body = {key: value for key, value in plan.items() if key != "plan_hash"}
        if evidence_hash(body) != plan.get("plan_hash") or plan.get("domain") != self.config.domain:
            raise V9AdjudicationError("plan hash or deployment pin mismatch")
        action = plan.get("action")
        if action not in ("report", "vote", "claim", "release", "timeout"):
            raise V9AdjudicationError("unsupported transaction action")
        fresh = getattr(self, "plan_" + action)(**plan["inputs"])
        if fresh["transaction"] != plan["transaction"] or fresh["amounts"] != plan["amounts"]:
            raise V9AdjudicationError("onchain state changed the approved transaction; create a new plan")
        return fresh


def _protected_key(path: str | Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
                    or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
                raise V9AdjudicationError("key must be an owned regular 0400/0600 file")
            raw = os.read(fd, 257)
            if len(raw) > 256:
                raise V9AdjudicationError("invalid dedicated key file")
        finally:
            os.close(fd)
        return chain.parse_private_key(raw.decode("ascii").strip())
    except (OSError, UnicodeError, chain.ChainError):
        raise V9AdjudicationError("unable to read protected dedicated operator key") from None


class V9TransactionOutbox:
    """Default at-most-once broadcast; uncertain nonce blocks new transactions.

    Store and fsync happen before broadcast. A crash/timeout never retries with a
    fresh nonce (or broadcasts again automatically). Explicit lifecycle recovery
    can re-send the identical stored signed bytes, never a replacement. Operators
    reconcile using the locally computed hash. Use one database and one dedicated
    key per sender across all processes; do not use this key in another wallet.
    """

    def __init__(self, path: str | Path) -> None:
        if str(path) == ":memory:":
            raise V9AdjudicationError("transaction outbox must be durable")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
                raise V9AdjudicationError("outbox must be an owned regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS v9_operator_transactions (
            plan_hash TEXT PRIMARY KEY, scope TEXT NOT NULL, sender TEXT NOT NULL,
            nonce INTEGER NOT NULL, tx_hash TEXT NOT NULL UNIQUE, raw_tx TEXT NOT NULL,
            plan_json TEXT NOT NULL, state TEXT NOT NULL, receipt_json TEXT,
            created_at INTEGER NOT NULL, UNIQUE(scope,sender,nonce))""")
        # A separate table upgrades existing outboxes without changing their
        # durable transaction layout or discarding a pending sender nonce.
        self.db.execute("""CREATE TABLE IF NOT EXISTS v9_operator_outcomes (
            plan_hash TEXT PRIMARY KEY, outcome_json TEXT NOT NULL)""")

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def get(self, plan_hash: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM v9_operator_transactions WHERE plan_hash=?", (plan_hash,)).fetchone()
            outcome = self.db.execute("SELECT outcome_json FROM v9_operator_outcomes WHERE plan_hash=?", (plan_hash,)).fetchone()
        if not row:
            return None
        # Raw signed transaction and evidence stay local; normal status omits them.
        result = {key: row[key] for key in ("plan_hash", "scope", "sender", "nonce", "tx_hash", "state", "receipt_json")}
        if outcome:
            result["settlement_outcome"] = json.loads(outcome["outcome_json"])
        return result

    def unresolved(self, sender: str) -> list[dict[str, Any]]:
        """Public metadata only; one shared outbox coordinates a dedicated sender."""
        with self._lock:
            rows = self.db.execute("SELECT plan_hash FROM v9_operator_transactions WHERE sender=? "
                "AND state NOT IN ('confirmed','reverted') ORDER BY nonce", (_address(sender),)).fetchall()
        return [self.get(row["plan_hash"]) for row in rows]

    def resume_signed_lifecycle(self, client: V9AdjudicationClient, plan_hash: str, *,
                                allow_send: bool = False) -> dict[str, Any]:
        """Explicit recovery of identical signed bytes, never a replacement nonce.

        Normal execute/reconcile retain their no-rebroadcast behavior. A keeper
        may opt into this narrow recovery after a crash between durable storage
        and broadcast. No key is loaded, fee changed, or new transaction signed.
        """
        row = self.reconcile(client, plan_hash)
        if not allow_send or row["state"] != "uncertain" or row["receipt_json"] is not None:
            return row
        with self._lock:
            stored = self.db.execute("SELECT raw_tx,plan_json FROM v9_operator_transactions WHERE plan_hash=?",
                                     (plan_hash,)).fetchone()
        plan = json.loads(stored["plan_json"])
        if plan.get("action") not in ("release", "timeout"):
            raise V9AdjudicationError("signed recovery is restricted to escrow maintenance")
        client.refresh(plan)
        raw = stored["raw_tx"]
        if "0x" + chain.keccak256(bytes.fromhex(raw[2:])).hex() != row["tx_hash"]:
            raise V9AdjudicationError("stored signed transaction hash mismatch")
        if int(client.rpc("eth_getTransactionCount", [row["sender"], "latest"]), 16) != row["nonce"]:
            raise V9AdjudicationError("maintenance nonce changed without a canonical receipt; manual reconciliation required")
        try:
            result = client.rpc("eth_sendRawTransaction", [raw])
            state = "submitted" if _hash(result) == row["tx_hash"] else "uncertain"
        except Exception:
            state = "uncertain"
        with self._lock:
            # A parallel reconciler may already have confirmed this exact hash.
            self.db.execute("UPDATE v9_operator_transactions SET state=? WHERE plan_hash=? "
                            "AND state NOT IN ('confirmed','reverted')", (state, plan_hash))
        return self.get(plan_hash)

    def execute(self, client: V9AdjudicationClient, plan: Mapping[str, Any], *, allow_send: bool = False,
                approved_plan_hash: str | None = None, key_file: str | Path | None = None,
                max_gas_price_wei: int | None = None, max_gas_units: int | None = None,
                max_total_gas_cost_wei: int | None = None) -> dict[str, Any]:
        if not allow_send:
            return {"dry_run": True, "plan_hash": plan.get("plan_hash"), "sent": False}
        if approved_plan_hash != plan.get("plan_hash") or not approved_plan_hash or not key_file:
            raise V9AdjudicationError("sending requires explicit exact plan approval and a dedicated key file")
        for value, label in ((max_gas_price_wei, "gas price cap"), (max_gas_units, "gas limit cap"),
                             (max_total_gas_cost_wei, "total gas cost cap")):
            _uint(value, label, positive=True)
        existing = self.get(approved_plan_hash)
        if existing:
            return existing  # no broadcast or nonce change on repeated execution
        client.refresh(plan)
        private_key = _protected_key(key_file)
        sender = chain.private_key_to_address(private_key)
        if sender != plan["transaction"]["from"]:
            raise V9AdjudicationError("dedicated key does not match approved transaction actor")
        c, tx = client.config, plan["transaction"]
        scope = f"{c.genesis_hash}:{c.chain_id}"
        # Lock includes RPC reads and durable reservation across processes.
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                existing = self.get(approved_plan_hash)
                if existing:
                    self.db.commit()
                    return existing
                blocked = self.db.execute("SELECT 1 FROM v9_operator_transactions WHERE scope=? AND sender=? "
                    "AND state NOT IN ('confirmed','reverted') LIMIT 1", (scope, sender)).fetchone()
                if blocked:
                    raise V9AdjudicationError("sender has an unresolved transaction; reconcile, never allocate another nonce")
                latest = int(client.rpc("eth_getTransactionCount", [sender, "latest"]), 16)
                pending = int(client.rpc("eth_getTransactionCount", [sender, "pending"]), 16)
                if latest != pending:
                    raise V9AdjudicationError("dedicated key has external pending transactions")
                gas_price = int(client.rpc("eth_gasPrice", []), 16)
                gas = int(client.rpc("eth_estimateGas", [{"from": sender, "to": tx["to"],
                    "value": "0x0", "data": tx["data"]}]), 16) * 12 // 10 + 10000
                if gas_price > max_gas_price_wei or gas > max_gas_units or gas * gas_price > max_total_gas_cost_wei:
                    raise V9AdjudicationError("estimated gas exceeds explicit operator caps")
                raw = chain.sign_legacy_transaction(private_key, latest, gas_price, gas,
                    tx["to"], 0, bytes.fromhex(tx["data"][2:]), c.chain_id)
                tx_hash, raw_hex = "0x" + chain.keccak256(raw).hex(), "0x" + raw.hex()
                self.db.execute("INSERT INTO v9_operator_transactions VALUES (?,?,?,?,?,?,?,'sending',NULL,?)",
                    (approved_plan_hash, scope, sender, latest, tx_hash, raw_hex, _json(plan), int(time.time())))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        try:
            returned_hash = client.rpc("eth_sendRawTransaction", [raw_hex])
            state = "submitted" if _hash(returned_hash) == tx_hash else "uncertain"
        except Exception:
            # An RPC error may mean the transaction WAS accepted. Never retry.
            state = "uncertain"
        with self._lock:
            self.db.execute("UPDATE v9_operator_transactions SET state=? WHERE plan_hash=?",
                            (state, approved_plan_hash))
        return self.get(approved_plan_hash)

    def reconcile(self, client: V9AdjudicationClient, plan_hash: str) -> dict[str, Any]:
        row = self.get(plan_hash)
        if row is None:
            raise V9AdjudicationError("unknown outbox transaction")
        with self._lock:
            plan = json.loads(self.db.execute("SELECT plan_json FROM v9_operator_transactions WHERE plan_hash=?",
                                              (plan_hash,)).fetchone()["plan_json"])
        c = client.config
        if (row["scope"] != f"{c.genesis_hash}:{c.chain_id}"
                or int(client.rpc("eth_chainId", []), 16) != c.chain_id
                or client.rpc("eth_getBlockByNumber", ["0x0", False])["hash"].lower() != c.genesis_hash):
            raise V9AdjudicationError("reconciliation network mismatch")
        receipt = client.rpc("eth_getTransactionReceipt", [row["tx_hash"]])
        state = "uncertain"
        if receipt is not None:
            if _hash(receipt["transactionHash"]) != row["tx_hash"]:
                raise V9AdjudicationError("receipt transaction hash mismatch")
            number = int(receipt["blockNumber"], 16)
            canonical = client.rpc("eth_getBlockByNumber", [hex(number), False])
            head = int(client.rpc("eth_blockNumber", []), 16)
            if canonical and canonical["hash"].lower() == _hash(receipt["blockHash"]):
                if head - number + 1 >= c.confirmations:
                    status = int(receipt["status"], 16)
                    if status not in (0, 1):
                        raise V9AdjudicationError("invalid receipt execution status")
                    state = "confirmed" if status else "reverted"
                else:
                    state = "submitted"
        outcome, verification_error = None, None
        if state == "confirmed" and plan.get("action") in ("release", "timeout"):
            try:
                outcome = client.verify_lifecycle(plan, minimum_block_number=int(receipt["blockNumber"], 16))
                # Recheck the transaction's block after business-state RPC reads.
                canonical = client.rpc("eth_getBlockByNumber", [receipt["blockNumber"], False])
                if not canonical or canonical["hash"].lower() != _hash(receipt["blockHash"]):
                    raise V9AdjudicationError("maintenance receipt was reorganized during verification")
            except Exception as exc:
                state, outcome, verification_error = "uncertain", None, exc
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("UPDATE v9_operator_transactions SET state=?,receipt_json=? WHERE plan_hash=?",
                                (state, _json(receipt) if receipt else None, plan_hash))
                self.db.execute("DELETE FROM v9_operator_outcomes WHERE plan_hash=?", (plan_hash,))
                if outcome is not None:
                    self.db.execute("INSERT INTO v9_operator_outcomes VALUES (?,?)", (plan_hash, _json(outcome)))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        if verification_error is not None:
            raise verification_error
        return self.get(plan_hash)


def _read_json(path: str) -> dict[str, Any]:
    with open(path, "rb") as handle:
        raw = handle.read(2_097_153)
    if len(raw) > 2_097_152:
        raise V9AdjudicationError("operator artifact exceeds 2 MiB")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise V9AdjudicationError("operator artifact must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    """Operator CLI; no config bootstrap, key generation, funding, or auto-votes."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="operator-reviewed deployment/committee pins")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan-report", "plan-vote"):
        command = commands.add_parser(name)
        command.add_argument("--incident", required=True)
        command.add_argument("--observed-at", required=True, type=int, help="independently trusted observation time")
        command.add_argument("--settlement-key", required=True)
        if name == "plan-vote":
            command.add_argument("--actor", required=True)
            command.add_argument("--outcome", choices=("confirmed", "dismissed"), required=True)
            command.add_argument("--review", required=True, help="independent operator review JSON")
    command = commands.add_parser("plan-claim")
    command.add_argument("--actor", required=True)
    command.add_argument("--settlement-key", required=True)
    command.add_argument("--kind", choices=("stable", "token", "bond"), required=True)
    command.add_argument("--report-id", default=chain.ZERO_BYTES32)
    for name in ("plan-release", "plan-timeout"):
        command = commands.add_parser(name)
        command.add_argument("--actor", required=True, help="dedicated maintenance transaction sender")
        command.add_argument("--settlement-key", required=True, help="exact approved escrow; no unbounded discovery")
    command = commands.add_parser("execute")
    command.add_argument("--plan", required=True)
    command.add_argument("--outbox", required=True)
    command.add_argument("--send", action="store_true", help="explicitly enable one broadcast attempt")
    command.add_argument("--approve-plan-hash")
    command.add_argument("--key-file")
    command.add_argument("--max-gas-price-wei", type=int)
    command.add_argument("--max-gas-units", type=int)
    command.add_argument("--max-total-gas-cost-wei", type=int)
    command = commands.add_parser("reconcile")
    command.add_argument("--outbox", required=True)
    command.add_argument("--plan-hash", required=True)
    args = parser.parse_args(argv)
    try:
        client = V9AdjudicationClient(V9OperatorConfig.load(args.config))
        if args.command in ("plan-report", "plan-vote"):
            kwargs = {"incident": _read_json(args.incident), "observed_at": args.observed_at,
                      "settlement_key": args.settlement_key}
            if args.command == "plan-vote":
                kwargs.update(actor=args.actor, confirmed=args.outcome == "confirmed", review=_read_json(args.review))
            result = getattr(client, args.command.replace("-", "_"))(**kwargs)
        elif args.command == "plan-claim":
            result = client.plan_claim(actor=args.actor, settlement_key=args.settlement_key,
                                       kind=args.kind, report_id=args.report_id)
        elif args.command in ("plan-release", "plan-timeout"):
            result = getattr(client, args.command.replace("-", "_"))(actor=args.actor,
                                                                     settlement_key=args.settlement_key)
        else:
            outbox = V9TransactionOutbox(args.outbox)
            try:
                if args.command == "execute":
                    result = outbox.execute(client, _read_json(args.plan), allow_send=args.send,
                        approved_plan_hash=args.approve_plan_hash, key_file=args.key_file,
                        max_gas_price_wei=args.max_gas_price_wei, max_gas_units=args.max_gas_units,
                        max_total_gas_cost_wei=args.max_total_gas_cost_wei)
                else:
                    result = outbox.reconcile(client, args.plan_hash)
            finally:
                outbox.close()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (V9AdjudicationError, chain.ChainError, OSError, ValueError, KeyError, TypeError) as exc:
        # Chain errors can include RPC URLs; do not dump exceptions or key contents.
        print(json.dumps({"error": type(exc).__name__, "message": "operator action rejected; no automatic retry"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
