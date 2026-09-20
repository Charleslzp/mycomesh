"""Offline cryptographic replay of locally retained Relay incident artifacts.

This is not an adjudicator, timestamp authority, model oracle or payment gate.
The caller pins the expected observer key AND supplies a trusted observation
time (for example from its own authenticated ledger snapshot). Unkeyed record
hashes detect corruption, not malicious rewriting. The pinned observer signs
the retained envelope; Provider signatures independently establish its transcript.
"""
from __future__ import annotations

from typing import Any, Mapping

from .chain import ChainError, ZERO_ADDRESS, normalize_address
from .identity import IdentityError, peer_id_from_public_key, verify_document
from .provider_identity_binding import verify_provider_identity_binding
from .relay_incidents import evidence_hash
from .relay_integrity import RelayIntegrityError, validate_provider_response


REGISTRATION_PURPOSE = "mycomesh.relay.provider.v1"
OBSERVATION_PURPOSE = "mycomesh.relay.protocol_observation.v1"
_RECORD_FIELDS = (
    "provider_id", "provider_signer", "request_id", "request_hash", "kind", "severity", "evidence",
)
# These describe contradictions in the authenticated Provider transcript itself.
# Model/output limits, selected route, and which request was dispatched still
# need independently established context; a Relay-authored constraint is not a
# Consumer-signed opening of the original request hash.
_SELF_CONTAINED_CODES = frozenset({
    "response_hash_mismatch", "usage_receipt_mismatch", "usage_body_mismatch",
    "output_body_mismatch", "usage_alias_mismatch", "usage_total_mismatch",
    "usage_shape", "output_shape", "raw_shape", "fee_limit",
    "relay_payout_mismatch", "peer_binding_mismatch", "receipt_missing",
    "receipt_verification_failed",
})
_INCONCLUSIVE_CODES = frozenset({
    "receipt_time_window", "admission_context_invalid", "verification_failed",
    "response_signature", "response_audience", "provider_identity",
})


class RelayEvidenceError(ValueError):
    pass


def verify_relay_incident(
    incident: Mapping[str, Any], *, expected_observer_public_key: str, observed_at: int,
) -> dict[str, Any]:
    """Replay a stored incident without trusting reported verdict/alias flags.

    ``observed_at`` is deliberately required; never substitute an untrusted
    exported ``created_at`` automatically. Legacy records missing the signed
    registration or identity binding fail as unverifiable, not as fraud proof.
    The result cannot authorize a refund, slash, bounty, or model-identity claim.
    """
    try:
        if type(observed_at) is not int or observed_at < 0:
            raise RelayEvidenceError("observed_at must be an explicit trusted nonnegative integer")
        if not isinstance(incident, Mapping) or not all(field in incident for field in _RECORD_FIELDS):
            raise RelayEvidenceError("incident immutable record is incomplete")
        record = {field: incident[field] for field in _RECORD_FIELDS}
        evidence = record["evidence"]
        if not isinstance(evidence, Mapping):
            raise RelayEvidenceError("incident evidence must be an object")
        if evidence_hash(record) != incident.get("record_hash") or evidence_hash(evidence) != incident.get("evidence_hash"):
            raise RelayEvidenceError("incident evidence/record hash mismatch")
        if evidence.get("schema") != "mycomesh.relay.protocol-observation.v1":
            raise RelayEvidenceError("unsupported incident evidence schema")
        if not isinstance(expected_observer_public_key, str) or len(expected_observer_public_key) != 64:
            raise RelayEvidenceError("expected observer public key is required")
        if evidence.get("observer_public_key") != expected_observer_public_key:
            raise RelayEvidenceError("incident observer does not match the pinned observer")
        observer_signature = evidence.get("signature")
        observer_context = evidence.get("request_constraints")
        observer_payment = evidence.get("expected_authorization")
        observer_auth = observer_payment.get("authorization") if isinstance(observer_payment, Mapping) else None
        if not all(isinstance(value, Mapping) for value in (observer_signature, observer_context, observer_auth)):
            raise RelayEvidenceError("signed observer envelope is required")
        if observer_signature.get("public_key") != expected_observer_public_key:
            raise RelayEvidenceError("observation signer does not match the pinned observer")
        version = evidence.get("settlement_version")
        if type(version) is not int or version not in (7, 8, 9):
            raise RelayEvidenceError("unsupported evidence settlement version")
        if version == 9:
            from .chain_v9 import verify_authorization
        elif version == 8:
            from .chain_v8 import verify_authorization
        else:
            from .chain_v7 import verify_authorization
        # Anchor to the cryptographically verified canonical authorization, not
        # its JSON representation: the payment protocol accepts decimal-string
        # integers, while Observer signature timestamps are emitted as integers.
        # Verify separately so a fabricated admission context cannot become a
        # reproducible accusation against an otherwise valid Provider.
        verified_payment = verify_authorization(
            observer_payment, expected_chain_id=observer_context["chain_id"],
            expected_contract=observer_context["contract"],
            expected_request_id=observer_context["request_id"],
            expected_request_hash=observer_context["request_hash"], now=observed_at,
        )
        auth = verified_payment["authorization"]
        if (evidence.get("signature_time_semantics") != "authorization_issued_at"
                or type(observer_signature.get("timestamp")) is not int
                or observer_signature["timestamp"] != auth["issued_at"]):
            raise RelayEvidenceError("observer signature must use the documented authorization time anchor")
        verify_document(
            dict(evidence), purpose=OBSERVATION_PURPOSE,
            audience=f'{observer_context["chain_id"]}:{normalize_address(observer_context["contract"])}',
            max_age_seconds=0, now=observed_at,
        )
        if evidence.get("monetary_verdict") is not False:
            raise RelayEvidenceError("incident must not claim a monetary verdict")
        code = evidence.get("code")
        if not isinstance(code, str) or record["kind"] != f"protocol:{code}":
            raise RelayEvidenceError("incident kind does not match its claimed code")
        registration = evidence.get("provider_registration")
        if not isinstance(registration, Mapping):
            raise RelayEvidenceError("original Provider registration is required")
        signature = registration.get("signature")
        if not isinstance(signature, Mapping) or not isinstance(signature.get("audience"), str) or not signature["audience"]:
            raise RelayEvidenceError("signed Provider registration audience is required")
        timestamp = signature.get("timestamp")
        if type(timestamp) is not int or timestamp < 0 or timestamp > observed_at + 30:
            raise RelayEvidenceError("Provider registration timestamp is incompatible with observation")
        # A connection can last longer than the transport signature TTL. Verify
        # its signature at its own signed timestamp, bounded above by trusted
        # observation time; do not misclassify old retained registration as bad.
        unsigned_registration = verify_document(
            dict(registration), purpose=REGISTRATION_PURPOSE,
            audience=signature["audience"], max_age_seconds=300, now=timestamp,
        )
        public_key = unsigned_registration.get("public_key")
        if signature.get("public_key") != public_key or record["provider_id"] != peer_id_from_public_key(public_key):
            raise RelayEvidenceError("registered Provider identity does not match the incident")
        if unsigned_registration.get("peer_id") != record["provider_id"]:
            raise RelayEvidenceError("Provider registration peer ID mismatch")
        signer = verify_provider_identity_binding(registration, audience=signature["audience"])
        if record["provider_signer"] is not None and normalize_address(record["provider_signer"]) != signer:
            raise RelayEvidenceError("incident economic alias does not match the authenticated signer")
        request = evidence.get("request_constraints")
        payment = evidence.get("expected_authorization")
        response = evidence.get("provider_response")
        if not all(isinstance(value, Mapping) for value in (request, payment, response)):
            raise RelayEvidenceError("incident request, authorization and Provider response are required")
        if request.get("request_id") != record["request_id"] or request.get("request_hash") != record["request_hash"]:
            raise RelayEvidenceError("incident request binding fields disagree")
        deployment = unsigned_registration.get("settlement")
        if (not isinstance(deployment, Mapping) or deployment.get("version") != version
                or deployment.get("chain_id") != request.get("chain_id")
                or normalize_address(deployment.get("contract")) != normalize_address(request.get("contract"))):
            raise RelayEvidenceError("registered Provider deployment does not match incident context")
        try:
            validate_provider_response(
                response, payment, settlement_version=version, request=request,
                expected_provider=unsigned_registration["payment_address"],
                expected_provider_signer=signer,
                expected_relay=auth["relay"], expected_relay_signer=auth["relay_signer"],
                expected_provider_public_key=public_key,
                expected_response_audience=expected_observer_public_key,
                expected_pool=ZERO_ADDRESS, verification_time=observed_at,
            )
        except RelayIntegrityError as error:
            if error.code != code:
                raise RelayEvidenceError(f"claimed violation did not reproduce (observed {error.code})") from error
            if not error.response_signature_verified:
                raise RelayEvidenceError("Provider response signature is not authenticated") from error
            if code in _INCONCLUSIVE_CODES:
                classification = "inconclusive"
            else:
                classification = "protocol_contradiction" if code in _SELF_CONTAINED_CODES else "contextual_allegation"
            return {
                "schema": "mycomesh.relay.verified-evidence.v1", "code": code,
                "classification": classification,
                "provider_id": record["provider_id"], "provider_signer": signer,
                "provider_response_authenticated": True,
                "observer_public_key": expected_observer_public_key,
                "reporter_authentication": "ed25519_observer_signature",
                "observed_at": observed_at, "record_hash": incident["record_hash"],
                "monetary_verdict": False, "model_identity_proven": False,
            }
        raise RelayEvidenceError("claimed violation did not reproduce: Provider response is consistent")
    except RelayEvidenceError:
        raise
    except (ChainError, IdentityError, KeyError, TypeError, ValueError) as exc:
        raise RelayEvidenceError(f"incident artifacts could not be verified: {exc}") from exc
