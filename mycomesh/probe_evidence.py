"""Self-verifying probe verdicts: anyone can re-grade what a Relay recorded on-chain.

The evidence holds the task parameters, the Provider-signed receipt and both
plaintexts. A verifier checks the signatures and hashes, rebuilds the question
and answer from the parameters, and grades the Provider's own signed response.
A Relay therefore cannot report a wrong answer the Provider never gave.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .evm import encode_call
from .jury import evidence_hash
from .protocol import b64decode, b64encode, output_text, sha256_hex
from .settlement import Deployment, SignedReceipt

SCHEMA = "mycomesh.v11.probe-evidence.v1"
VERDICTS = {"pass": 1, "wrong": 2}
# Capability probes are recorded under their own codes, so pass rates per category can be read from the ledger alone.
CAPABILITY_VERDICTS = {"pass": 3, "wrong": 4}


def verdict_code(kind: str, verdict: str) -> int:
    from .capability import CUSTOM, KINDS

    return (CAPABILITY_VERDICTS if kind in KINDS or kind == CUSTOM else VERDICTS)[verdict]


class ProbeEvidenceError(ValueError):
    pass


def build_probe_evidence(signed: SignedReceipt, request: bytes, response: bytes, *, kind: str, params: dict,
                         verdict: str) -> dict[str, Any]:
    return {"schema": SCHEMA, "settlement_key": signed.authorization.settlement_key, "signed_receipt": signed.to_payload(),
            "request": b64encode(request), "response": b64encode(response), "task": {"kind": kind, "params": params},
            "verdict": verdict}


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def verify_probe_evidence(evidence: Any, deployment: Deployment) -> tuple[str, str]:
    """Return (provider signer, verdict) after re-grading; raise if anything does not check out."""
    from .relay.probes import build_task

    if not isinstance(evidence, Mapping) or evidence.get("schema") != SCHEMA:
        raise ProbeEvidenceError("not probe evidence")
    signed = SignedReceipt.from_payload(evidence["signed_receipt"])
    signed.verify(deployment)
    if evidence["settlement_key"] != signed.authorization.settlement_key:
        raise ProbeEvidenceError("evidence names a different settlement")
    request, response = b64decode(evidence["request"]), b64decode(evidence["response"])
    if sha256_hex(request) != signed.authorization.request_hash or sha256_hex(response) != signed.receipt.response_hash:
        raise ProbeEvidenceError("plaintexts do not match the Provider-signed receipt")
    task = build_task(str(evidence["task"]["kind"]), dict(evidence["task"]["params"]))
    if not any(task.question in text for text in _strings(json.loads(request))):
        raise ProbeEvidenceError("the request does not ask the stated question")
    grade = task.grade(output_text(json.loads(response).get("output")))
    if grade not in VERDICTS or grade != evidence.get("verdict"):
        raise ProbeEvidenceError(f"re-grading gives {grade}, not {evidence.get('verdict')}")
    return signed.authorization.provider_signer, grade


def encode_record(settlement_key: str, evidence: Mapping[str, Any]) -> str:
    return encode_call("record(bytes32,bytes32,uint8)", ["bytes32", "bytes32", "uint8"],
                       [settlement_key, evidence_hash(evidence), verdict_code(evidence["task"]["kind"], evidence["verdict"])])
