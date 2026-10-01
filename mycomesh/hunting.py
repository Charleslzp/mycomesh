"""Open probing: anyone may probe Providers for free (within a daily allowance) and accuse a cheater.

A hunter (a Relay, a custodial service, anyone) commits a batch of probe keys
behind keccak256(abi.encode(hunter, merkleRoot, salt)), sends ordinary-looking
requests with them, and afterwards the keys' owner voids them: refunded, the
Provider unpaid. The commitment reveals nobody until the void.

One wrong answer proves nothing, so a model downgrade is judged statistically.
The hunter opens a capability case with every probe it voided on the Provider
over closed days (the chain counts them), publishing each probe's task,
plaintexts and Provider-signed receipt. Jurors drawn from the accused's tier
replay every request on their own model as a control group, grade both, and
vote to convict only when the accused did significantly worse on the same
questions (``decide``).
"""
from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

from . import capability
from .evm import abi_encode, encode_call, keccak256
from .identity import canonical_json
from .protocol import b64decode, b64encode, output_text, sha256_hex
from .settlement import Deployment, SignedReceipt

CASE_SCHEMA = "mycomesh.v11.capability-case.v1"
MIN_CASE_PROBES = 20
MAX_CASE_PROBES = 120
MAX_CASE_DAYS = 30
# The jurors' rule, bound into every vote's decision hash.
CAPABILITY_POLICY = {
    "schema": "mycomesh.v11.capability-policy.v1",
    "rule": "replay each probe request on the juror's own model; grade accused and control answers with the task's "
            "grader; b = control right and accused wrong, c = accused right and control wrong; convict when the "
            "one-sided exact binomial P(X >= b | b + c, 1/2) <= 0.01 and (b - c) / n >= 0.10",
    "alpha": 0.01,
    "materiality": 0.10,
}


class CaseError(ValueError):
    pass


# ---------------- commitments and calls ----------------

def probe_commitment(hunter: str, root: str, salt: str) -> str:
    return "0x" + keccak256(abi_encode(["address", "bytes32", "bytes32"], [hunter, root, salt])).hex()


def encode_commit_probes(commitment: str) -> str:
    return encode_call("commitProbes(bytes32)", ["bytes32"], [commitment])


def encode_void_probe(key: str, hunter: str, root: str, salt: str, proof: Sequence[str]) -> str:
    return encode_call("voidProbe(bytes32,address,bytes32,bytes32,bytes32[])",
                       ["bytes32", "address", "bytes32", "bytes32", ("array", "bytes32")], [key, hunter, root, salt, list(proof)])


def case_id(hunter: str, provider: str, from_day: int, to_day: int) -> str:
    return "0x" + keccak256(abi_encode(["string", "address", "address", "uint64", "uint64"],
                                       ["mycomesh.capability-case", hunter, provider, from_day, to_day])).hex()


def keys_hash(keys: Sequence[str]) -> str:
    return "0x" + keccak256(abi_encode([("array", "bytes32")], [list(keys)])).hex()


def encode_open_case(provider: str, from_day: int, to_day: int, keys: Sequence[str], evidence: str) -> str:
    return encode_call("openCapabilityCase(address,uint64,uint64,bytes32[],bytes32)",
                       ["address", "uint64", "uint64", ("array", "bytes32"), "bytes32"],
                       [provider, from_day, to_day, sorted(keys, key=lambda k: int(k, 16)), evidence])


def encode_case_votes(case: str, permits: Sequence[Mapping[str, Any]]) -> str:
    from .jury import VOTE_PERMIT_ABI

    return encode_call(
        "voteCapabilityCase(bytes32,(bytes32,bool,bytes32,bytes32,uint256,uint64,bytes)[])",
        ["bytes32", ("array", VOTE_PERMIT_ABI)],
        [case, [[p["assignment_hash"], p["confirmed"], p["report_id"], p["decision_hash"], p["nonce"], p["deadline"],
                 p["signature"]] for p in permits]])


# ---------------- evidence ----------------

def probe_record(signed: SignedReceipt, request: bytes, response: bytes, kind: str, params: dict) -> dict[str, Any]:
    return {"settlement_key": signed.authorization.settlement_key, "signed_receipt": signed.to_payload(),
            "request": b64encode(request), "response": b64encode(response), "task": {"kind": kind, "params": params}}


def build_case_evidence(hunter: str, provider: str, from_day: int, to_day: int, probes: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted(probes, key=lambda item: int(item["settlement_key"], 16))
    return {"schema": CASE_SCHEMA, "hunter": hunter.lower(), "provider": provider.lower(), "from_day": from_day,
            "to_day": to_day, "probes": [dict(item) for item in ordered]}


def evidence_hash(evidence: Mapping[str, Any]) -> str:
    return "0x" + keccak256(canonical_json(dict(evidence)).encode()).hex()


def task_for(probe: Mapping[str, Any]):
    from .relay.probes import build_task

    return build_task(str(probe["task"]["kind"]), dict(probe["task"]["params"]))


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def verify_case_evidence(evidence: Any, deployment: Deployment) -> list[tuple[Mapping[str, Any], dict, str]]:
    """Every probe is bound to its Provider-signed receipt and asks its task's question.

    Returns (probe, request document, accused answer text) in key order. On-chain facts (the case, each
    void and its hunter, the signer's owner) are the caller's to check against the chain.
    """
    if not isinstance(evidence, Mapping) or evidence.get("schema") != CASE_SCHEMA:
        raise CaseError("not capability case evidence")
    probes = evidence.get("probes")
    if not isinstance(probes, list) or not MIN_CASE_PROBES <= len(probes) <= MAX_CASE_PROBES:
        raise CaseError("case size out of range")
    keys = [str(item["settlement_key"]).lower() for item in probes]
    if keys != sorted(keys, key=lambda k: int(k, 16)) or len(set(keys)) != len(keys):
        raise CaseError("probes must be sorted and distinct")
    checked = []
    for item in probes:
        signed = SignedReceipt.from_payload(item["signed_receipt"])
        signed.verify(deployment)
        if signed.authorization.settlement_key != item["settlement_key"]:
            raise CaseError("a probe names another settlement")
        request, response = b64decode(item["request"]), b64decode(item["response"])
        if sha256_hex(request) != signed.authorization.request_hash or sha256_hex(response) != signed.receipt.response_hash:
            raise CaseError("a probe's plaintexts differ from its signed receipt")
        document = json.loads(request)
        task = task_for(item)
        if not any(task.question in text for text in _strings(document)):
            raise CaseError("a probe request does not ask its stated question")
        checked.append((item, document, output_text(json.loads(response).get("output"))))
    return checked


# ---------------- the jurors' rule ----------------

def binomial_tail(successes: int, trials: int) -> float:
    """P(X >= successes) for X ~ Binomial(trials, 1/2)."""
    return sum(math.comb(trials, k) for k in range(successes, trials + 1)) / 2 ** trials if trials else 1.0


def decide(accused: Sequence[bool], control: Sequence[bool], *, alpha: float = CAPABILITY_POLICY["alpha"],
           materiality: float = CAPABILITY_POLICY["materiality"]) -> dict[str, Any]:
    """Paired comparison on the same questions: did the accused do significantly worse than the control?"""
    if len(accused) != len(control) or not accused:
        raise CaseError("accused and control grades must pair up")
    b = sum(1 for a, c in zip(accused, control) if c and not a)
    c = sum(1 for a, ctl in zip(accused, control) if a and not ctl)
    p_value = binomial_tail(b, b + c)
    convict = p_value <= alpha and (b - c) / len(accused) >= materiality
    return {"convict": convict, "accused_passed": sum(accused), "control_passed": sum(control), "n": len(accused),
            "control_only": b, "accused_only": c, "p_value": round(p_value, 6)}


def control_request(document: Mapping[str, Any], models: Sequence[str]) -> dict[str, Any]:
    """The accused's exact request, replayed on the juror's own model."""
    replay = {key: document[key] for key in ("endpoint", "input", "messages", "options", "max_output_tokens") if key in document}
    replay["model"] = document.get("model") if document.get("model") in models else models[0]
    replay.setdefault("options", {})
    return replay
