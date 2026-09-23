"""Signed Provider-AI jury tasks and verdicts for dynamic V10 assignments.

The chain selects Provider identities; it cannot call their inference services.
Relay workers use this module to create assignment-bound tasks. Providers sign
every auditable model result with Ed25519 and issue an executable EIP-712 vote
permit for either high-confidence outcome. Positive permits bind the one
owner-submitted report; dismissal permits bind the zero report id required by
the contract. A shared decision hash deliberately excludes juror-specific
prose, so independently matching outcomes can form one quorum.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any, Mapping, Sequence

from . import chain, chain_v10
from .identity import IdentityError, NodeIdentity, peer_id_from_public_key, sign_document, verify_document
from .relay_incidents import evidence_hash


class ProviderJuryError(ValueError):
    pass


TASK_SCHEMA = "mycomesh.v10.provider-jury-task.v1"
CONTEXT_SCHEMA = "mycomesh.v10.provider-jury-context.v1"
VERDICT_SCHEMA = "mycomesh.v10.provider-jury-verdict.v1"
DECISION_SCHEMA = "mycomesh.v10.provider-jury-decision.v1"
CAPABILITY_SCHEMA = "mycomesh.provider-jury.capability.v1"
POLICY_SCHEMA = "mycomesh.v10.provider-jury-policy.v1"
EVIDENCE_DOCUMENT_SCHEMA = "mycomesh.v10.provider-jury-evidence.v1"
TASK_PURPOSE = "mycomesh.v10.provider-jury-task.v1"
VERDICT_PURPOSE = "mycomesh.v10.provider-jury-verdict.v1"
MAX_TASK_TTL_SECONDS = 900
MAX_EVIDENCE_DOCUMENT_BYTES = 64 * 1024
# Kept as an import-compatible alias for the worker/runtime policy checks.  The
# actual boundary is bytes, not Python characters: UTF-8 evidence is what is
# durably committed, transported, and presented to a juror model.
MAX_PROMPT_CHARS = MAX_EVIDENCE_DOCUMENT_BYTES
MAX_REASONING_CHARS = 16 * 1024
MAX_MODEL_OUTPUT_BYTES = 64 * 1024
# Both automatic monetary outcomes move funds: confirmation refunds/slashes,
# while dismissal releases escrow and forfeits the owner's report bond. Keep
# the historical name as a compatibility alias, but apply one floor to both.
MIN_AUTOMATIC_CONFIDENCE_BPS = 9_000
MIN_CONFIRMATION_CONFIDENCE_BPS = MIN_AUTOMATIC_CONFIDENCE_BPS
ZERO_BYTES32 = "0x" + "00" * 32


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ProviderJuryError("jury document must be strict canonical JSON data") from exc


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProviderJuryError(f"{label} has unknown or missing fields")
    return value


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or len(value) > maximum or "\x00" in value):
        raise ProviderJuryError(f"{label} must be bounded canonical text")
    return value


def _uint(value: Any, label: str, *, maximum: int = 2**64 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ProviderJuryError(f"{label} must be a bounded nonnegative integer")
    return value


def _hash(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryError(f"{label} must be a canonical bytes32") from exc
    if normalized != value or (nonzero and normalized == ZERO_BYTES32):
        raise ProviderJuryError(f"{label} must be lowercase canonical nonzero bytes32")
    return normalized


def _address(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (TypeError, ValueError, chain.ChainError) as exc:
        raise ProviderJuryError(f"{label} must be a canonical EVM address") from exc
    if normalized != value or normalized == chain.ZERO_ADDRESS:
        raise ProviderJuryError(f"{label} must be lowercase canonical nonzero EVM address")
    return normalized


def _relay_public_key(value: Any, label: str = "origin Relay public key") -> str:
    if (not isinstance(value, str) or len(value) != 64
            or value != value.lower()):
        raise ProviderJuryError(f"{label} must be lowercase Ed25519 hex")
    try:
        peer_id_from_public_key(value)
    except (IdentityError, ValueError) as exc:
        raise ProviderJuryError(f"{label} is invalid") from exc
    return value


def _keccak_text(value: str) -> str:
    return "0x" + chain.keccak256(value.encode("utf-8")).hex()


def capability_hash(value: Mapping[str, Any]) -> str:
    capability = _capability(value)
    return "0x" + chain.keccak256(_canonical(capability).encode("utf-8")).hex()


def _capability(value: Any) -> dict[str, Any]:
    value = _exact(value, {"schema", "models", "max_output_tokens", "supports_structured_verdict",
                           "decision_policy_hash"},
                   "Provider jury capability")
    if value.get("schema") != CAPABILITY_SCHEMA:
        raise ProviderJuryError("unsupported Provider jury capability")
    raw_models = value.get("models")
    if not isinstance(raw_models, (list, tuple)) or not 1 <= len(raw_models) <= 32:
        raise ProviderJuryError("Provider jury capability needs a bounded model list")
    models = tuple(_text(item, "Provider jury model", maximum=160) for item in raw_models)
    if len(set(models)) != len(models):
        raise ProviderJuryError("Provider jury capability models must be unique")
    maximum = _uint(value.get("max_output_tokens"), "Provider jury max output tokens", maximum=1_000_000)
    if maximum == 0 or value.get("supports_structured_verdict") is not True:
        raise ProviderJuryError("Provider jury capability cannot produce a structured verdict")
    return {"schema": CAPABILITY_SCHEMA, "models": list(models), "max_output_tokens": maximum,
            "supports_structured_verdict": True,
            "decision_policy_hash": _hash(value.get("decision_policy_hash"), "capability decision policy hash")}


def _selected_provider(value: Any) -> dict[str, Any]:
    value = _exact(value, {"owner", "vote_signer", "operator_id", "operator_id_hash", "peer_id",
                           "peer_id_hash", "capability", "capability_hash", "reputation"},
                   "selected Provider")
    operator_id = _text(value.get("operator_id"), "operator_id", maximum=160)
    peer_id = _text(value.get("peer_id"), "peer_id", maximum=160)
    capability = _capability(value.get("capability"))
    result = {
        "owner": _address(value.get("owner"), "Provider owner"),
        "vote_signer": _address(value.get("vote_signer"), "Provider vote signer"),
        "operator_id": operator_id,
        "operator_id_hash": _hash(value.get("operator_id_hash"), "operator_id_hash"),
        "peer_id": peer_id,
        "peer_id_hash": _hash(value.get("peer_id_hash"), "peer_id_hash"),
        "capability": capability,
        "capability_hash": _hash(value.get("capability_hash"), "capability_hash"),
        "reputation": _uint(value.get("reputation"), "Provider reputation"),
    }
    if result["operator_id_hash"] != _keccak_text(operator_id):
        raise ProviderJuryError("selected Provider operator hash mismatch")
    if result["peer_id_hash"] != _keccak_text(peer_id):
        raise ProviderJuryError("selected Provider peer hash mismatch")
    if result["capability_hash"] != capability_hash(capability):
        raise ProviderJuryError("selected Provider capability hash mismatch")
    return result


def _evidence(value: Any) -> dict[str, str]:
    value = _exact(value, {"report_id", "evidence_hash", "request_hash", "response_hash"}, "jury evidence")
    return {name: _hash(value.get(name), name) for name in
            ("report_id", "evidence_hash", "request_hash", "response_hash")}


def _evidence_document(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ProviderJuryError("jury evidence document must be a nonempty object")
    encoded = _canonical(value)
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_DOCUMENT_BYTES:
        raise ProviderJuryError("jury evidence document exceeds the bounded prompt size")
    # Canonicalize through strict JSON so custom Mapping/list subclasses cannot
    # change after the task hash has been checked.
    parsed = json.loads(encoded)
    if not isinstance(parsed, dict):
        raise ProviderJuryError("jury evidence document must be an object")
    return parsed


def _v10_evidence_document(value: Any) -> dict[str, Any]:
    """Normalize the only evidence envelope that may reach a juror model."""
    value = _evidence_document(value)
    _exact(
        value,
        {"schema", "settlement_key", "reporter", "origin_relay_public_key",
         "allegation", "request", "provider_response"},
        "V10 jury evidence document",
    )
    if value.get("schema") != EVIDENCE_DOCUMENT_SCHEMA:
        raise ProviderJuryError("unsupported V10 jury evidence document")
    allegation = _exact(value.get("allegation"), {"code", "summary"}, "jury allegation")
    request = _exact(
        value.get("request"),
        {"request_id", "endpoint", "model", "input", "messages", "max_output_tokens", "options"},
        "jury evidence request",
    )
    endpoint = _text(request.get("endpoint"), "jury evidence endpoint", maximum=16)
    if endpoint not in {"responses", "chat"}:
        raise ProviderJuryError("jury evidence endpoint is unsupported")
    if endpoint == "responses" and request.get("messages") is not None:
        raise ProviderJuryError("responses evidence must not contain chat messages")
    if endpoint == "chat" and request.get("input") is not None:
        raise ProviderJuryError("chat evidence must not contain responses input")
    if not isinstance(request.get("options"), Mapping):
        raise ProviderJuryError("jury evidence request options must be an object")
    response = value.get("provider_response")
    if not isinstance(response, Mapping) or not response:
        raise ProviderJuryError("jury evidence requires the complete Provider response")
    return {
        "schema": EVIDENCE_DOCUMENT_SCHEMA,
        "settlement_key": _hash(value.get("settlement_key"), "evidence settlement key"),
        "reporter": _address(value.get("reporter"), "evidence reporter"),
        "origin_relay_public_key": _relay_public_key(
            value.get("origin_relay_public_key"),
        ),
        "allegation": {
            "code": _text(allegation.get("code"), "jury allegation code", maximum=160),
            "summary": _text(allegation.get("summary"), "jury allegation summary", maximum=4096),
        },
        "request": {
            "request_id": _hash(request.get("request_id"), "evidence request_id"),
            "endpoint": endpoint,
            "model": _text(request.get("model"), "evidence request model", maximum=160),
            "input": request.get("input"),
            "messages": request.get("messages"),
            "max_output_tokens": _uint(
                request.get("max_output_tokens"), "evidence max_output_tokens", maximum=1_000_000,
            ),
            "options": dict(request["options"]),
        },
        "provider_response": dict(response),
    }


def verify_v10_evidence_document(
    task: Mapping[str, Any], *, settlement: Mapping[str, Any], reporter: str,
) -> dict[str, Any]:
    """Cryptographically replay the V10 request/receipt/response artifacts.

    The report hash merely commits bytes.  This verifier additionally proves
    those bytes are the consumer-authorized request and Provider-signed response
    that produced the disputed on-chain settlement.  The allegation text stays
    explicitly untrusted input for the selected Provider AI.
    """
    from .relay_integrity import (
        PROVIDER_RESPONSE_PURPOSE, RelayIntegrityError, _extract_output_text,
        _validated_usage, provider_response_hash,
    )
    from .reservation import (
        ReservationError, inference_request_hash, normalize_inference_request_options,
    )

    try:
        evidence = _evidence(task.get("evidence"))
        inference = task.get("inference_request")
        if not isinstance(inference, Mapping):
            raise ProviderJuryError("jury task inference request is missing")
        document = _v10_evidence_document(inference.get("evidence_document"))
        if document["settlement_key"] != _hash(task.get("settlement_key"), "task settlement key"):
            raise ProviderJuryError("jury evidence belongs to another settlement")
        expected_reporter = _address(reporter, "on-chain evidence reporter")
        if document["reporter"] != expected_reporter:
            raise ProviderJuryError("jury evidence reporter differs from the on-chain report")
        if evidence_hash(document) != evidence["evidence_hash"]:
            raise ProviderJuryError("jury evidence document differs from the on-chain commitment")
        expected_report_id = chain_v10.report_id_for(
            document["settlement_key"], expected_reporter, evidence["evidence_hash"],
        )
        if expected_report_id != evidence["report_id"]:
            raise ProviderJuryError("jury evidence report_id is not canonical")

        request = document["request"]
        normalized_options = normalize_inference_request_options(
            request["endpoint"], request["options"],
        )
        if normalized_options != request["options"]:
            raise ProviderJuryError("jury evidence request options are not canonical")
        computed_request_hash = "0x" + inference_request_hash(
            endpoint=request["endpoint"], model=request["model"],
            input_value=request["input"], messages=request["messages"],
            max_output_tokens=request["max_output_tokens"], options=normalized_options,
        )
        if computed_request_hash != evidence["request_hash"]:
            raise ProviderJuryError("jury evidence does not reproduce the settled request_hash")

        response = document["provider_response"]
        signed_receipt = response.get("settlement_v10")
        raw_authorization = (
            signed_receipt.get("authorization", {}).get("authorization", {})
            if isinstance(signed_receipt, Mapping) else {}
        )
        issued_at = raw_authorization.get("issued_at")
        if type(issued_at) is not int:
            raise ProviderJuryError("jury evidence receipt has no canonical issuance time")
        authorization, receipt, _signatures = chain_v10.verify_signed_receipt(
            signed_receipt, now=issued_at,
        )
        auth = authorization["authorization"]
        if (chain_v10.settlement_key_for(auth["channel_id"], auth["request_id"])
                != document["settlement_key"]):
            raise ProviderJuryError("jury evidence receipt derives another settlement key")
        if (auth["request_id"] != request["request_id"]
                or auth["request_hash"] != computed_request_hash):
            raise ProviderJuryError("jury evidence request differs from its signed authorization")
        if (response.get("ok") is not True
                or response.get("request_id") != request["request_id"]
                or response.get("endpoint") != request["endpoint"]
                or response.get("model") != request["model"]):
            raise ProviderJuryError("jury Provider response differs from the committed request")

        signature = response.get("signature")
        signed_at = signature.get("timestamp") if isinstance(signature, Mapping) else None
        audience = response.get("consumer_public_key")
        if type(signed_at) is not int or not isinstance(audience, str) or not audience:
            raise ProviderJuryError("jury Provider response transport signature is incomplete")
        unsigned_response = verify_document(
            dict(response), purpose=PROVIDER_RESPONSE_PURPOSE, audience=audience,
            max_age_seconds=0, now=signed_at,
        )
        peer = unsigned_response.get("peer")
        public_key = signature.get("public_key") if isinstance(signature, Mapping) else None
        if (not isinstance(peer, Mapping) or peer.get("public_key") != public_key
                or peer.get("peer_id") != peer_id_from_public_key(str(public_key or ""))):
            raise ProviderJuryError("jury Provider response peer signature is not bound")
        if provider_response_hash(response) != receipt.response_hash:
            raise ProviderJuryError("jury Provider response does not reproduce response_hash")
        raw = response.get("raw")
        usage = response.get("usage")
        output_text = response.get("output_text")
        if (not isinstance(raw, Mapping) or not isinstance(output_text, str)
                or raw.get("usage") != usage
                or _extract_output_text(request["endpoint"], raw) != output_text):
            raise ProviderJuryError("jury Provider response body is internally inconsistent")
        input_tokens, output_tokens = _validated_usage(usage)
        if (receipt.input_tokens != input_tokens or receipt.output_tokens != output_tokens
                or output_tokens > request["max_output_tokens"]):
            raise ProviderJuryError("jury Provider receipt usage differs from the response")

        required_record = {
            "request_id": auth["request_id"],
            "request_hash": auth["request_hash"],
            "authorization_hash": authorization["authorization_hash"],
            "response_hash": receipt.response_hash,
            "provider_signer": _address(
                signed_receipt.get("provider_signer"), "receipt Provider signer",
            ),
            "relay_signer": _address(
                signed_receipt.get("dispatch", {}).get("relay_signer"), "receipt Relay signer",
            ),
            "gross_fee": receipt.actual_fee,
        }
        for name, expected in required_record.items():
            if settlement.get(name) != expected:
                raise ProviderJuryError(
                    f"jury evidence {name} differs from the immutable settlement"
                )
        if receipt.response_hash != evidence["response_hash"]:
            raise ProviderJuryError("jury evidence response_hash differs from the report")
        return {
            "schema": EVIDENCE_DOCUMENT_SCHEMA,
            "settlement_key": document["settlement_key"],
            "report_id": evidence["report_id"],
            "reporter": expected_reporter,
            "origin_relay_public_key": document["origin_relay_public_key"],
            "request_hash": computed_request_hash,
            "response_hash": receipt.response_hash,
            "provider_signer": required_record["provider_signer"],
            "relay_signer": required_record["relay_signer"],
            "document": document,
        }
    except ProviderJuryError:
        raise
    except (chain.ChainError, IdentityError, RelayIntegrityError, ReservationError,
            KeyError, TypeError, ValueError) as exc:
        raise ProviderJuryError(f"jury evidence artifacts could not be verified: {exc}") from exc


def _decision_policy(*, model: Any, system_prompt: Any,
                     max_output_tokens: Any, task_ttl_seconds: Any) -> dict[str, Any]:
    """Return the complete canonical policy that governs a jury inference.

    The deployment pin must commit to every Relay-controlled execution input,
    not just the prompt.  Otherwise a compromised Relay could keep the pinned
    prompt while silently selecting a different model, output budget, or task
    lifetime.  The verdict fields are fixed protocol surface and are included
    so a future schema change necessarily produces a different pin.
    """
    normalized_model = _text(model, "jury policy model", maximum=160)
    prompt = _text(system_prompt, "jury system prompt", maximum=MAX_PROMPT_CHARS)
    maximum = _uint(
        max_output_tokens, "jury policy output-token limit", maximum=1_000_000,
    )
    ttl = _uint(
        task_ttl_seconds, "jury policy task TTL", maximum=MAX_TASK_TTL_SECONDS,
    )
    if maximum == 0:
        raise ProviderJuryError("jury policy output-token limit must be positive")
    if ttl == 0:
        raise ProviderJuryError("jury policy task TTL must be positive")
    return {
        "schema": POLICY_SCHEMA,
        "model": normalized_model,
        "system_prompt": prompt,
        "max_output_tokens": maximum,
        "task_ttl_seconds": ttl,
        "verdict_fields": ["confirmed", "confidence_bps", "reason_code", "reasoning"],
    }


def _decision_policy_hash(*, model: Any, system_prompt: Any,
                          max_output_tokens: Any, task_ttl_seconds: Any) -> str:
    return evidence_hash(_decision_policy(
        model=model,
        system_prompt=system_prompt,
        max_output_tokens=max_output_tokens,
        task_ttl_seconds=task_ttl_seconds,
    ))


def decision_policy_hash(*, model: Any, system_prompt: Any,
                         max_output_tokens: Any, task_ttl_seconds: Any) -> str:
    """Hash the complete executable Provider-AI jury policy."""
    return _decision_policy_hash(
        model=model,
        system_prompt=system_prompt,
        max_output_tokens=max_output_tokens,
        task_ttl_seconds=task_ttl_seconds,
    )


def _inference_request(value: Any, capability: Mapping[str, Any]) -> dict[str, Any]:
    value = _exact(value, {"model", "system_prompt", "evidence_document", "max_output_tokens"},
                   "jury inference request")
    model = _text(value.get("model"), "jury inference model", maximum=160)
    if model not in capability["models"]:
        raise ProviderJuryError("jury inference model is not in the selected Provider capability")
    system_prompt = _text(value.get("system_prompt"), "jury system prompt", maximum=MAX_PROMPT_CHARS)
    evidence_document = _evidence_document(value.get("evidence_document"))
    if evidence_document.get("schema") == EVIDENCE_DOCUMENT_SCHEMA:
        evidence_document = _v10_evidence_document(evidence_document)
    maximum = _uint(value.get("max_output_tokens"), "jury output-token limit", maximum=1_000_000)
    if maximum == 0 or maximum > capability["max_output_tokens"]:
        raise ProviderJuryError("jury output-token limit exceeds Provider capability")
    return {"model": model, "system_prompt": system_prompt, "evidence_document": evidence_document,
            "max_output_tokens": maximum}


def _context(task: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": CONTEXT_SCHEMA,
        "network_id": task["network_id"], "chain_id": task["chain_id"],
        "settlement_contract": task["settlement_contract"], "jury_registry": task["jury_registry"],
        "settlement_key": task["settlement_key"], "assignment_hash": task["assignment_hash"],
        "evidence": task["evidence"], "decision_policy_hash": task["decision_policy_hash"],
        "inference_request": task["inference_request"],
    }


def jury_context_hash(task: Mapping[str, Any]) -> str:
    return evidence_hash(_context(task))


_TASK_FIELDS = {"schema", "network_id", "chain_id", "settlement_contract", "jury_registry",
                "settlement_key", "assignment_hash", "selected_provider", "evidence",
                "decision_policy_hash", "inference_request", "context_hash", "relay_peer_id",
                "nonce", "issued_at", "deadline"}


def build_jury_task(*, network_id: str, chain_id: int, settlement_contract: str, jury_registry: str,
                    settlement_key: str, assignment_hash: str, selected_provider: Mapping[str, Any],
                    evidence: Mapping[str, Any], decision_policy_hash: str,
                    inference_request: Mapping[str, Any], relay_identity: NodeIdentity,
                    issued_at: int | None = None, deadline: int | None = None,
                    nonce: str | None = None) -> dict[str, Any]:
    provider = _selected_provider(selected_provider)
    current = int(time.time()) if issued_at is None else _uint(issued_at, "jury task issued_at")
    expires = current + 300 if deadline is None else _uint(deadline, "jury task deadline")
    if not current < expires <= current + MAX_TASK_TTL_SECONDS:
        raise ProviderJuryError("jury task deadline exceeds the bounded execution window")
    normalized_inference = _inference_request(inference_request, provider["capability"])
    document = normalized_inference["evidence_document"]
    if (document.get("schema") == EVIDENCE_DOCUMENT_SCHEMA
            and document["origin_relay_public_key"] != relay_identity.public_key):
        raise ProviderJuryError("jury task signer differs from the evidence origin Relay")
    normalized_evidence = _evidence(evidence)
    policy_hash = _hash(decision_policy_hash, "decision policy hash")
    if normalized_evidence["evidence_hash"] != evidence_hash(normalized_inference["evidence_document"]):
        raise ProviderJuryError("jury evidence document hash does not match the on-chain evidence")
    if policy_hash != _decision_policy_hash(
        model=normalized_inference["model"],
        system_prompt=normalized_inference["system_prompt"],
        max_output_tokens=normalized_inference["max_output_tokens"],
        task_ttl_seconds=expires - current,
    ):
        raise ProviderJuryError("jury decision policy hash does not match the executable policy")
    if policy_hash != provider["capability"]["decision_policy_hash"]:
        raise ProviderJuryError("jury task policy differs from the selected Provider capability")
    task = {
        "schema": TASK_SCHEMA, "network_id": _text(network_id, "network_id"),
        "chain_id": _uint(chain_id, "chain_id", maximum=2**256 - 1),
        "settlement_contract": _address(settlement_contract, "settlement contract"),
        "jury_registry": _address(jury_registry, "jury registry"),
        "settlement_key": _hash(settlement_key, "settlement key"),
        "assignment_hash": _hash(assignment_hash, "assignment hash"),
        "selected_provider": provider, "evidence": normalized_evidence,
        "decision_policy_hash": policy_hash,
        "inference_request": normalized_inference,
        "relay_peer_id": relay_identity.peer_id,
        "nonce": _hash(nonce or "0x" + secrets.token_hex(32), "jury task nonce"),
        "issued_at": current, "deadline": expires,
    }
    task["context_hash"] = jury_context_hash(task)
    return sign_document(task, relay_identity.private_key, TASK_PURPOSE, timestamp=current,
                         audience=provider["peer_id"])


def verify_jury_task(value: Any, *, expected_relay_public_key: str | None = None,
                     expected_assignment_hash: str | None = None,
                     expected_provider: Mapping[str, Any] | None = None,
                     now: int | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderJuryError("jury task must be an object")
    raw_provider = value.get("selected_provider")
    audience = str(raw_provider.get("peer_id") or "") if isinstance(raw_provider, Mapping) else ""
    try:
        unsigned = verify_document(value, TASK_PURPOSE, audience=audience,
                                   max_age_seconds=MAX_TASK_TTL_SECONDS, now=now)
    except IdentityError as exc:
        raise ProviderJuryError(f"invalid Relay jury task signature: {exc}") from exc
    _exact(unsigned, _TASK_FIELDS, "jury task")
    if unsigned.get("schema") != TASK_SCHEMA:
        raise ProviderJuryError("unsupported jury task schema")
    signature = value.get("signature")
    public_key = signature.get("public_key") if isinstance(signature, Mapping) else None
    if expected_relay_public_key is not None and public_key != expected_relay_public_key:
        raise ProviderJuryError("jury task Relay identity mismatch")
    if peer_id_from_public_key(str(public_key or "")) != unsigned.get("relay_peer_id"):
        raise ProviderJuryError("jury task Relay peer identity mismatch")
    provider = _selected_provider(unsigned.get("selected_provider"))
    evidence = _evidence(unsigned.get("evidence"))
    normalized = {**unsigned, "network_id": _text(unsigned.get("network_id"), "network_id"),
                  "chain_id": _uint(unsigned.get("chain_id"), "chain_id", maximum=2**256 - 1),
                  "settlement_contract": _address(unsigned.get("settlement_contract"), "settlement contract"),
                  "jury_registry": _address(unsigned.get("jury_registry"), "jury registry"),
                  "settlement_key": _hash(unsigned.get("settlement_key"), "settlement key"),
                  "assignment_hash": _hash(unsigned.get("assignment_hash"), "assignment hash"),
                  "selected_provider": provider, "evidence": evidence,
                  "decision_policy_hash": _hash(unsigned.get("decision_policy_hash"), "decision policy hash"),
                  "inference_request": _inference_request(unsigned.get("inference_request"), provider["capability"]),
                  "context_hash": _hash(unsigned.get("context_hash"), "jury context hash"),
                  "nonce": _hash(unsigned.get("nonce"), "jury task nonce"),
                  "issued_at": _uint(unsigned.get("issued_at"), "jury task issued_at"),
                  "deadline": _uint(unsigned.get("deadline"), "jury task deadline")}
    current = int(time.time()) if now is None else now
    if not normalized["issued_at"] <= current <= normalized["deadline"]:
        raise ProviderJuryError("jury task is not currently executable")
    if normalized["deadline"] - normalized["issued_at"] > MAX_TASK_TTL_SECONDS:
        raise ProviderJuryError("jury task TTL exceeds protocol policy")
    if normalized["context_hash"] != jury_context_hash(normalized):
        raise ProviderJuryError("jury task context hash mismatch")
    document = normalized["inference_request"]["evidence_document"]
    if (document.get("schema") == EVIDENCE_DOCUMENT_SCHEMA
            and document["origin_relay_public_key"] != public_key):
        raise ProviderJuryError("jury task signer differs from the evidence origin Relay")
    if normalized["evidence"]["evidence_hash"] != evidence_hash(normalized["inference_request"]["evidence_document"]):
        raise ProviderJuryError("jury evidence document hash mismatch")
    if normalized["decision_policy_hash"] != decision_policy_hash(
        model=normalized["inference_request"]["model"],
        system_prompt=normalized["inference_request"]["system_prompt"],
        max_output_tokens=normalized["inference_request"]["max_output_tokens"],
        task_ttl_seconds=normalized["deadline"] - normalized["issued_at"],
    ):
        raise ProviderJuryError("jury decision policy hash mismatch")
    if normalized["decision_policy_hash"] != provider["capability"]["decision_policy_hash"]:
        raise ProviderJuryError("jury decision policy differs from Provider capability")
    if expected_assignment_hash is not None and normalized["assignment_hash"] != _hash(expected_assignment_hash, "expected assignment hash"):
        raise ProviderJuryError("jury task belongs to another assignment")
    if expected_provider is not None and provider != _selected_provider(expected_provider):
        raise ProviderJuryError("jury task selected Provider mismatch")
    return normalized


def _model_output(value: Any) -> dict[str, Any]:
    value = _exact(value, {"confirmed", "confidence_bps", "reason_code", "reasoning"}, "jury model output")
    if type(value.get("confirmed")) is not bool:
        raise ProviderJuryError("jury model confirmed value must be boolean")
    confidence = _uint(
        value.get("confidence_bps"), "jury confidence", maximum=10_000,
    )
    if confidence < MIN_AUTOMATIC_CONFIDENCE_BPS:
        raise ProviderJuryError(
            "jury verdict does not meet the automatic monetary confidence floor"
        )
    return {"confirmed": value["confirmed"],
            "confidence_bps": confidence,
            "reason_code": _text(value.get("reason_code"), "jury reason code", maximum=160),
            "reasoning": _text(value.get("reasoning"), "jury reasoning", maximum=MAX_REASONING_CHARS)}


def model_output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["confirmed", "confidence_bps", "reason_code", "reasoning"],
        "properties": {
            "confirmed": {"type": "boolean"},
            "confidence_bps": {"type": "integer", "minimum": 0, "maximum": 10_000},
            "reason_code": {"type": "string", "minLength": 1, "maxLength": 160},
            "reasoning": {"type": "string", "minLength": 1, "maxLength": MAX_REASONING_CHARS},
        },
    }


def parse_model_output(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
        raise ProviderJuryError("jury model output must be bounded JSON text")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderJuryError("jury model output must be strict JSON") from exc
    return _model_output(value)


def _decision(task: Mapping[str, Any], confirmed: bool) -> dict[str, Any]:
    return {"schema": DECISION_SCHEMA, "network_id": task["network_id"], "chain_id": task["chain_id"],
            "settlement_contract": task["settlement_contract"], "jury_registry": task["jury_registry"],
            "settlement_key": task["settlement_key"], "assignment_hash": task["assignment_hash"],
            "context_hash": task["context_hash"], "confirmed": confirmed,
            "report_id": task["evidence"]["report_id"] if confirmed else ZERO_BYTES32,
            "evidence_hash": task["evidence"]["evidence_hash"],
            "decision_policy_hash": task["decision_policy_hash"]}


_VERDICT_FIELDS = {"schema", "task_hash", "context_hash", "provider", "model", "model_output",
                   "model_output_hash", "decision", "decision_hash", "completed_at", "vote_permit"}


def build_provider_verdict(*, task: Mapping[str, Any], model_output: Mapping[str, Any],
                           provider_identity: NodeIdentity, evm_private_key: str,
                           vote_nonce: int, vote_deadline: int, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else _uint(now, "jury verdict time")
    verified_task = verify_jury_task(dict(task), expected_provider=task.get("selected_provider"), now=current)
    provider = verified_task["selected_provider"]
    if provider_identity.peer_id != provider["peer_id"]:
        raise ProviderJuryError("Provider identity was not selected for this jury task")
    output = _model_output(model_output)
    decision = _decision(verified_task, output["confirmed"])
    decision_hash = evidence_hash(decision)
    permit_deadline = _uint(vote_deadline, "jury vote deadline")
    if not current <= permit_deadline <= verified_task["deadline"]:
        raise ProviderJuryError("jury vote permit exceeds the Relay task window")
    try:
        signer = chain.private_key_to_address(chain.parse_private_key(evm_private_key))
    except chain.ChainError as exc:
        raise ProviderJuryError(f"invalid Provider jury vote key: {exc}") from exc
    if signer != provider["vote_signer"]:
        raise ProviderJuryError("Provider EVM key does not match the selected vote signer")
    try:
        permit = chain_v10.build_dispute_vote(
            settlement_key=verified_task["settlement_key"], assignment_hash=verified_task["assignment_hash"],
            confirmed=output["confirmed"], report_id=decision["report_id"],
            decision_hash=decision_hash,
            nonce=vote_nonce, deadline=permit_deadline, judge_private_key=evm_private_key,
            chain_id=verified_task["chain_id"], settlement_contract=verified_task["settlement_contract"],
        )
    except chain.ChainError as exc:
        raise ProviderJuryError(f"cannot sign Provider jury vote: {exc}") from exc
    verdict = {"schema": VERDICT_SCHEMA, "task_hash": evidence_hash(dict(task)),
               "context_hash": verified_task["context_hash"], "provider": provider,
               "model": verified_task["inference_request"]["model"], "model_output": output,
               "model_output_hash": evidence_hash(output), "decision": decision,
               "decision_hash": decision_hash, "completed_at": current, "vote_permit": permit}
    return sign_document(verdict, provider_identity.private_key, VERDICT_PURPOSE, timestamp=current,
                         audience=verified_task["relay_peer_id"])


def verify_provider_verdict(value: Any, *, task: Mapping[str, Any], now: int | None = None) -> dict[str, Any]:
    verified_task = verify_jury_task(dict(task), now=now)
    if not isinstance(value, dict):
        raise ProviderJuryError("Provider jury verdict must be an object")
    try:
        unsigned = verify_document(value, VERDICT_PURPOSE, audience=verified_task["relay_peer_id"],
                                   max_age_seconds=MAX_TASK_TTL_SECONDS, now=now)
    except IdentityError as exc:
        raise ProviderJuryError(f"invalid Provider jury verdict signature: {exc}") from exc
    _exact(unsigned, _VERDICT_FIELDS, "Provider jury verdict")
    if unsigned.get("schema") != VERDICT_SCHEMA or unsigned.get("task_hash") != evidence_hash(dict(task)):
        raise ProviderJuryError("Provider jury verdict is not bound to this task")
    provider = _selected_provider(unsigned.get("provider"))
    if provider != verified_task["selected_provider"]:
        raise ProviderJuryError("jury verdict Provider differs from its task")
    public_key = value.get("signature", {}).get("public_key")
    if peer_id_from_public_key(str(public_key or "")) != provider["peer_id"]:
        raise ProviderJuryError("jury verdict signing identity differs from selected Provider")
    output = _model_output(unsigned.get("model_output"))
    if unsigned.get("model") != verified_task["inference_request"]["model"]:
        raise ProviderJuryError("jury verdict used an unassigned model")
    if unsigned.get("model_output_hash") != evidence_hash(output):
        raise ProviderJuryError("jury verdict model output hash mismatch")
    decision = _decision(verified_task, output["confirmed"])
    decision_hash = evidence_hash(decision)
    if unsigned.get("decision") != decision or unsigned.get("decision_hash") != decision_hash:
        raise ProviderJuryError("jury verdict decision document mismatch")
    completed = _uint(unsigned.get("completed_at"), "jury verdict completed_at")
    if not verified_task["issued_at"] <= completed <= verified_task["deadline"]:
        raise ProviderJuryError("jury verdict completed outside its task window")
    permit = unsigned.get("vote_permit")
    try:
        permit = chain_v10.verify_dispute_vote(
            permit, expected_settlement_key=verified_task["settlement_key"],
            expected_assignment_hash=verified_task["assignment_hash"],
            expected_chain_id=verified_task["chain_id"], expected_contract=verified_task["settlement_contract"],
            expected_judge=provider["vote_signer"], now=now,
        )
    except chain.ChainError as exc:
        raise ProviderJuryError(f"invalid Provider jury EVM permit: {exc}") from exc
    if (permit["confirmed"] is not output["confirmed"]
            or permit["report_id"] != decision["report_id"]
            or permit["decision_hash"] != decision_hash):
        raise ProviderJuryError("Provider jury EVM permit differs from the signed model verdict")
    return {**unsigned, "provider": provider, "model_output": output, "decision": decision,
            "vote_permit": permit}


def aggregate_quorum(verdicts: Sequence[Mapping[str, Any]], *, tasks: Mapping[str, Mapping[str, Any]],
                     threshold: int, now: int | None = None) -> dict[str, Any]:
    if type(threshold) is not int or threshold < 2 or len(verdicts) != threshold:
        raise ProviderJuryError("Provider jury quorum must contain exactly the on-chain threshold")
    checked = []
    for verdict in verdicts:
        task_hash = verdict.get("task_hash") if isinstance(verdict, Mapping) else None
        task = tasks.get(task_hash) if isinstance(task_hash, str) else None
        if not isinstance(task, Mapping):
            raise ProviderJuryError("Provider jury verdict has no matching Relay task")
        checked.append(verify_provider_verdict(dict(verdict), task=dict(task), now=now))
    first = checked[0]
    if any(item["context_hash"] != first["context_hash"] or item["decision_hash"] != first["decision_hash"]
           for item in checked[1:]):
        raise ProviderJuryError("Provider jury verdicts do not share one context and decision")
    identities = {(item["provider"]["vote_signer"], item["provider"]["operator_id_hash"],
                   item["provider"]["peer_id_hash"]) for item in checked}
    if len(identities) != threshold or len({item[0] for item in identities}) != threshold \
            or len({item[1] for item in identities}) != threshold or len({item[2] for item in identities}) != threshold:
        raise ProviderJuryError("Provider jury quorum identities are not independent")
    permits = [item["vote_permit"] for item in checked]
    settlement_key = first["decision"]["settlement_key"]
    confirmed = first["decision"]["confirmed"]
    if len(permits) != threshold:
        raise ProviderJuryError("Provider jury quorum lacks the exact executable permit threshold")
    return {"settlement_key": settlement_key, "assignment_hash": first["decision"]["assignment_hash"],
            "context_hash": first["context_hash"], "decision_hash": first["decision_hash"],
            "confirmed": confirmed, "report_id": first["decision"]["report_id"],
            "vote_permits": permits,
            "calldata": chain_v10.encode_dispute_vote_by_sig(settlement_key, permits)}
