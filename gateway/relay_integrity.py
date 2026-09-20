"""Fail-closed checks performed *before* a Relay co-signs a Provider receipt.

These checks establish protocol consistency, not which upstream model ran.  A
Provider and Relay upgrading to this commitment format must be rolled out
together: legacy text-only commitments are deliberately not accepted.
"""
from __future__ import annotations

import hashlib
import base64
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .chain import ChainError, normalize_address, normalize_bytes32
from .identity import IdentityError, peer_id_from_public_key, verify_document
from .pricing import ChannelPricing, quote_usage, usage_tokens


RESPONSE_COMMITMENT_SCHEMA = "mycomesh.provider-response-commitment.v1"
RESPONSE_PROOF_SCHEMA = "mycomesh.provider-response-proof.v1"
PROVIDER_RESPONSE_PURPOSE = "mycomesh.inference.provider_response.v1"
_BYTES_FIELDS = {"request_id", "request_hash", "channel", "pricing_hash"}
_ADDRESS_FIELDS = {"key", "relay", "relay_signer"}
_INT_FIELDS = {"pricing_version", "max_fee", "issued_at", "deadline"}


class RelayIntegrityError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        # Never populate these from an unverified claimed identity.
        self.verified_provider_signer: str | None = None
        self.authenticated_receipt: dict[str, Any] | None = None
        self.response_signature_verified = False
        self.signer_identity_bound = False


@dataclass(frozen=True)
class VerifiedProviderResponse:
    authorization: dict[str, Any]
    receipt: dict[str, Any]
    provider_signer: str
    chain_id: int
    contract: str
    response_signature_verified: bool
    signer_identity_bound: bool


def provider_response_commitment(response: Mapping[str, Any]) -> dict[str, Any]:
    """Commit the full returned body, including structured outputs/tool calls.

    Dynamic transport signatures, elapsed times, descriptors and the receipt
    itself must not be included (the latter would introduce a circular hash).
    """
    peer = response.get("peer")
    return {
        "schema": RESPONSE_COMMITMENT_SCHEMA,
        "provider_peer_id": peer.get("peer_id") if isinstance(peer, Mapping) else None,
        "provider_public_key": peer.get("public_key") if isinstance(peer, Mapping) else None,
        **{field: response.get(field) for field in (
            "request_id", "endpoint", "model", "output_text", "usage", "raw",
        )},
    }


def provider_response_bytes(response: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            provider_response_commitment(response), ensure_ascii=False,
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RelayIntegrityError("response_encoding", "Provider response is not canonical JSON") from exc


def provider_response_hash(response: Mapping[str, Any]) -> str:
    return "0x" + hashlib.sha256(provider_response_bytes(response)).hexdigest()


def provider_response_proof(response: Mapping[str, Any]) -> dict[str, str]:
    # Send the exact committed bytes, not a reserialized cross-language JSON
    # object. In particular Python and JS format floats/large integers
    # differently. This replaces the raw body; it does not duplicate it in a
    # response header or require changing existing Provider commitments.
    return {"schema": RESPONSE_PROOF_SCHEMA,
            "commitment_b64": base64.b64encode(provider_response_bytes(response)).decode("ascii")}


def verify_response_proof(proof: Mapping[str, Any], receipt: Mapping[str, Any], *,
                          request_id: str, endpoint: str, model: str) -> dict[str, Any]:
    """Called after receipt verification; authenticates bytes, then extracts raw."""
    def reject_constant(_value: str) -> None:
        raise ValueError("nonfinite JSON")

    try:
        if not isinstance(proof, Mapping) or proof.get("schema") != RESPONSE_PROOF_SCHEMA:
            raise ValueError("missing Provider response proof")
        text = proof["commitment_b64"]
        if not isinstance(text, str) or len(text) > 32 * 1024 * 1024:
            raise ValueError("invalid Provider response proof size")
        encoded = base64.b64decode(text, validate=True)
        if base64.b64encode(encoded).decode("ascii") != text:
            raise ValueError("noncanonical base64 proof")
        if "0x" + hashlib.sha256(encoded).hexdigest() != receipt["response_hash"]:
            raise ValueError("Provider response does not match its signed commitment")
        commitment = json.loads(encoded.decode("utf-8"), parse_constant=reject_constant)
        if (commitment.get("schema") != RESPONSE_COMMITMENT_SCHEMA
                or commitment.get("request_id") != request_id
                or commitment.get("endpoint") != endpoint or commitment.get("model") != model
                or not isinstance(commitment.get("raw"), dict)):
            raise ValueError("Provider response proof does not bind this request")
        return commitment["raw"]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise RelayIntegrityError("consumer_response_proof", str(exc)) from exc


def validate_authorization_binding(
    expected_authorization: Mapping[str, Any], actual_authorization: Mapping[str, Any],
) -> None:
    """Compare all authorization fields; incomplete test stubs are not exempt."""
    for field in sorted(_BYTES_FIELDS | _ADDRESS_FIELDS | _INT_FIELDS):
        if field not in expected_authorization or field not in actual_authorization:
            raise RelayIntegrityError("authorization_missing", f"Provider receipt authorization is missing {field}")
        try:
            if field in _BYTES_FIELDS:
                expected = normalize_bytes32(str(expected_authorization[field]))
                actual = normalize_bytes32(str(actual_authorization[field]))
            elif field in _ADDRESS_FIELDS:
                expected = normalize_address(str(expected_authorization[field]))
                actual = normalize_address(str(actual_authorization[field]))
            else:
                expected = _exact_uint(expected_authorization[field], field)
                actual = _exact_uint(actual_authorization[field], field)
        except (ChainError, ValueError, TypeError) as exc:
            raise RelayIntegrityError("authorization_invalid", f"Provider receipt authorization has invalid {field}") from exc
        if expected != actual:
            raise RelayIntegrityError("authorization_mismatch", f"Provider receipt authorization conflicts with the dispatched request ({field})")


def validate_provider_response(
    response: Mapping[str, Any], expected_authorization: Mapping[str, Any], *,
    settlement_version: int, request: Mapping[str, Any], expected_provider: str,
    expected_relay: str, expected_relay_signer: str,
    expected_provider_signer: str | None = None,
    expected_provider_public_key: str | None = None,
    expected_response_audience: str | None = None,
    expected_pool: str | None = None,
    pricing: ChannelPricing | None = None,
    verification_time: int | None = None,
) -> VerifiedProviderResponse:
    """Verify a current receipt and response before signing or queueing it.

    ``expected_authorization`` must be the full payment envelope that this
    Relay admitted, not data obtained from the returned Provider receipt.
    ``pricing`` may only come from trusted deployment configuration; a Provider
    descriptor is not an authoritative price table. Without it, the signed
    max fee is enforced here and the contract remains the exact-quote checker.
    ``verification_time`` is reserved for offline evidence replay using a trusted
    observation time. Live request paths must omit it, never read it from a body.
    """
    verified: tuple[Any, ...] | None = None
    outer_verified = False
    signer_identity_bound = False
    settlement: Mapping[str, Any] | None = None
    try:
        if verification_time is not None:
            _exact_uint(verification_time, "verification_time")
        if settlement_version == 9:
            from .chain_v9 import verify_authorization, verify_provider_receipt
        elif settlement_version == 8:
            from .chain_v8 import verify_authorization, verify_provider_receipt
        elif settlement_version == 7:
            from .chain_v7 import verify_authorization, verify_provider_receipt
        else:
            raise RelayIntegrityError("unsupported_version", "Response integrity requires Settlement V7, V8, or V9")
        if not isinstance(response, Mapping):
            raise RelayIntegrityError("response_missing", "Provider response is missing")
        # Authenticate the transport peer even if the enclosed EVM receipt is
        # malformed. Only the separate successful EVM/commitment check below
        # can additionally attribute a signing/economic identity.
        if expected_provider_public_key is not None:
            if not expected_response_audience:
                raise RelayIntegrityError("response_audience", "Expected Provider response audience is required")
            signature = response.get("signature")
            if not isinstance(signature, Mapping) or signature.get("public_key") != expected_provider_public_key:
                raise RelayIntegrityError("response_signature", "Provider response signer conflicts with the registered peer")
            verify_document(
                dict(response), purpose=PROVIDER_RESPONSE_PURPOSE,
                audience=expected_response_audience,
                # No valid authorization lasts longer than one hour. Cached
                # responses are re-signed by the Provider when refreshed.
                max_age_seconds=3600,
                now=verification_time,
            )
            outer_verified = True
        peer = response.get("peer")
        if outer_verified:
            if not isinstance(peer, Mapping) or peer.get("public_key") != expected_provider_public_key or peer.get("peer_id") != peer_id_from_public_key(expected_provider_public_key):
                raise RelayIntegrityError("peer_binding_mismatch", "Provider committed peer identity conflicts with its response signer")
        settlement = response.get(f"mycomesh_v{settlement_version}_settlement")
        if not isinstance(settlement, Mapping):
            raise RelayIntegrityError("receipt_missing", "Provider response is missing its receipt")
        try:
            verified = verify_provider_receipt(settlement, now=verification_time)
        except ChainError as exc:
            # A slow inference crossing the payment deadline is not proof of
            # malicious behavior and must not trigger punitive quarantine.
            code = "receipt_time_window" if "outside its time window" in str(exc) else "receipt_verification_failed"
            raise RelayIntegrityError(code, f"Provider receipt verification failed: {exc}") from exc
        actual_envelope, receipt, _, chain_id, contract = verified
        hash_matches = receipt.response_hash == provider_response_hash(response)
        if outer_verified:
            # A stolen valid receipt paired with an attacker's signed outer
            # response must NOT quarantine the receipt's innocent EVM signer.
            # The EVM commitment itself must bind this authenticated peer.
            signer_identity_bound = hash_matches
        try:
            expected = verify_authorization(
                expected_authorization,
                expected_chain_id=request["chain_id"], expected_contract=request["contract"],
                expected_relay=expected_relay, expected_relay_signer=expected_relay_signer,
                expected_request_id=request["request_id"], expected_request_hash=request["request_hash"],
                now=verification_time,
            )
        except (ChainError, KeyError, TypeError, ValueError) as exc:
            raise RelayIntegrityError("admission_context_invalid", f"Relay admitted authorization context is invalid: {exc}") from exc
        if chain_id != int(expected["chain_id"]) or contract != normalize_address(expected["settlement_contract"]):
            raise RelayIntegrityError("deployment_mismatch", "Provider receipt deployment conflicts with the admitted authorization")
        validate_authorization_binding(expected["authorization"], actual_envelope["authorization"])
        auth = expected["authorization"]
        if receipt.provider != normalize_address(expected_provider):
            raise RelayIntegrityError("provider_payout_mismatch", "Provider receipt payout conflicts with the selected Provider")
        signer = receipt.provider_signer if settlement_version in {8, 9} else receipt.provider
        if expected_provider_signer is not None and signer != normalize_address(expected_provider_signer):
            raise RelayIntegrityError("provider_signer_mismatch", "Provider receipt signer conflicts with the selected Provider")
        if receipt.relay != normalize_address(expected_relay):
            raise RelayIntegrityError("relay_payout_mismatch", "Provider receipt Relay payout conflicts with the authorization")
        if expected_pool is not None and receipt.pool != normalize_address(expected_pool):
            raise RelayIntegrityError("pool_payout_mismatch", "Provider receipt pool payout conflicts with the request")
        for field in ("request_id", "endpoint", "model"):
            if response.get(field) != request.get(field):
                raise RelayIntegrityError("response_binding_mismatch", f"Provider response {field} conflicts with the dispatched request")
        if response.get("ok") is not True:
            raise RelayIntegrityError("response_failed", "Cannot settle an unsuccessful Provider response")
        # Check the commitment before interpreting data it authenticates.
        if not hash_matches:
            raise RelayIntegrityError("response_hash_mismatch", "Provider response body conflicts with its signed response_hash")
        usage = response.get("usage")
        billed_input, output_tokens = _validated_usage(usage)
        raw = response.get("raw")
        output_text = response.get("output_text")
        if not isinstance(output_text, str):
            raise RelayIntegrityError("output_shape", "Provider output_text must be a string")
        if not isinstance(raw, Mapping):
            raise RelayIntegrityError("raw_shape", "Provider response must include the exact raw API body")
        if raw.get("usage") != usage:
            raise RelayIntegrityError("usage_body_mismatch", "Provider raw usage conflicts with response usage")
        if _extract_output_text(str(request["endpoint"]), raw) != output_text:
            raise RelayIntegrityError("output_body_mismatch", "Provider raw output conflicts with output_text")
        if receipt.input_tokens != billed_input or receipt.output_tokens != output_tokens:
            raise RelayIntegrityError("usage_receipt_mismatch", "Provider response usage conflicts with its signed receipt")
        if output_tokens > _exact_uint(request["max_output_tokens"], "max_output_tokens"):
            raise RelayIntegrityError("output_limit", "Provider receipt output exceeds the authorized output token limit")
        if receipt.actual_fee > int(auth["max_fee"]):
            raise RelayIntegrityError("fee_limit", "Provider receipt fee exceeds the authorized max_fee")
        if pricing is not None:
            if pricing.channel != request.get("channel"):
                raise RelayIntegrityError("pricing_channel", "Trusted pricing configuration does not match request channel")
            quote = quote_usage(pricing.channel, dict(usage), pricing=pricing)
            units = int(quote.gross_fee * 1_000_000)
            if receipt.actual_fee != units:
                raise RelayIntegrityError("fee_quote_mismatch", "Provider receipt fee conflicts with the trusted usage quote")
        return VerifiedProviderResponse(
            authorization=dict(actual_envelope), receipt=receipt.to_payload(),
            provider_signer=signer, chain_id=chain_id, contract=contract,
            response_signature_verified=outer_verified,
            signer_identity_bound=signer_identity_bound,
        )
    except (ChainError, IdentityError, KeyError, TypeError, ValueError) as exc:
        error = exc if isinstance(exc, RelayIntegrityError) else RelayIntegrityError("verification_failed", f"Provider receipt verification failed: {exc}")
        if verified is not None:
            receipt = verified[1]
            if signer_identity_bound:
                error.verified_provider_signer = receipt.provider_signer if settlement_version in {8, 9} else receipt.provider
            error.authenticated_receipt = dict(settlement) if settlement is not None else None
        error.response_signature_verified = outer_verified
        error.signer_identity_bound = signer_identity_bound
        if error is exc:
            raise
        raise error from exc


def _exact_uint(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= (1 << 256):
        raise RelayIntegrityError("usage_shape", f"{label} must be a non-negative uint256 integer")
    return value


def _validated_usage(usage: Any) -> tuple[int, int]:
    if not isinstance(usage, dict):
        raise RelayIntegrityError("usage_shape", "Provider usage is missing")
    groups = (("input_tokens", "prompt_tokens", "input_token_count"),
              ("output_tokens", "completion_tokens", "output_token_count"))
    counts: list[int] = []
    seen = False
    for aliases in groups:
        values = [_exact_uint(usage[field], field) for field in aliases if field in usage]
        seen = seen or bool(values)
        if values and any(value != values[0] for value in values):
            raise RelayIntegrityError("usage_alias_mismatch", "Provider usage aliases disagree")
        counts.append(values[0] if values else 0)
    if "total_tokens" in usage:
        total = _exact_uint(usage["total_tokens"], "total_tokens")
        if seen and total != sum(counts):
            raise RelayIntegrityError("usage_total_mismatch", "Provider total_tokens conflicts with input/output usage")
        seen = True
    if not seen:
        raise RelayIntegrityError("usage_shape", "Provider usage has no token counters")
    cache_counts = []
    for field in ("input_tokens_details", "prompt_tokens_details"):
        if field not in usage:
            continue
        details = usage[field]
        if not isinstance(details, dict):
            raise RelayIntegrityError("usage_shape", f"Provider {field} must be an object")
        if "cached_tokens" in details:
            cache_counts.append(_exact_uint(details["cached_tokens"], "cached_tokens"))
    if cache_counts and any(value != cache_counts[0] for value in cache_counts):
        raise RelayIntegrityError("usage_alias_mismatch", "Provider cached token aliases disagree")
    try:
        return usage_tokens(usage)
    except ValueError as exc:
        raise RelayIntegrityError("usage_shape", str(exc)) from exc


def _extract_output_text(endpoint: str, raw: Mapping[str, Any]) -> str:
    # Mirrors the Provider's existing API normalization without importing p2p
    # (which imports provider_response_hash to create its own receipts).
    if endpoint == "responses":
        return str(raw.get("output_text") or "")
    try:
        return str(raw["choices"][0]["message"].get("content") or "")
    except (KeyError, IndexError, TypeError):
        return ""
