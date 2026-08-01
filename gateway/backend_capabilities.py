from __future__ import annotations

import json
import re
from typing import Any, Mapping


BACKEND_CAPABILITY_SCHEMA = "mycomesh.provider.backend_capability.v1"
TRUST_EVIDENCE_SCHEMA = "mycomesh.provider.trust_evidence.v1"

CODEX_OAUTH_SIDECAR_KIND = "codex_oauth_sidecar"
SELF_ATTESTED_TRUST_MODE = "self_attested"
SELF_ATTESTED_TRUST_LEVEL = "self_attested"

OPENAI_COMPATIBLE_PROTOCOL = "openai_compatible"
RESPONSES_ENDPOINT = "/v1/responses"
CHAT_COMPLETIONS_ENDPOINT = "/v1/chat/completions"

MAX_CAPABILITY_BYTES = 32 * 1024
MAX_ENDPOINTS = 16
MAX_ENDPOINT_LENGTH = 128

_TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ENDPOINT_PATTERN = re.compile(r"^/v1/[a-z0-9][a-z0-9_./-]*$")
_BACKEND_KINDS = {
    "codex_app_server": CODEX_OAUTH_SIDECAR_KIND,
    "codex_cli": "codex_cli",
    "native_metered_http": "native_metered_http",
    "openai_http": "openai_compatible_http",
}
_REQUIRED_SELF_ATTESTED_CLAIMS = {
    "runtime_integrity": "not_verified",
    "credential_origin": "not_verified",
    "upstream_identity": "not_verified",
    "usage_integrity": "not_verified",
}
_RESERVED_TRUST_ASSERTION_FIELDS = {
    "attestation",
    "claimed_level",
    "claimed_trust_level",
    "level",
    "runtime_verified",
    "trust_level",
    "verified_trust_level",
    "tee",
    "tee_attestation",
    "remote_attestation",
    "upstream_signature",
    "upstream_signed",
    "upstream_verified",
    "metering_proof",
    "metering_verified",
}
_CREDENTIAL_FIELDS = {
    "access_token",
    "api_key",
    "auth_json",
    "authorization",
    "client_secret",
    "credentials",
    "id_token",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_token",
    "token",
}


class BackendCapabilityError(ValueError):
    pass


def build_backend_capability(backend: Any) -> dict[str, Any]:
    """Build the conservative capability advertised for a configured backend."""

    selector = _backend_selector(backend)
    kind = _BACKEND_KINDS.get(selector, "unspecified")
    capability = {
        "schema": BACKEND_CAPABILITY_SCHEMA,
        "kind": kind,
        "protocol": OPENAI_COMPATIBLE_PROTOCOL,
        "endpoints": [RESPONSES_ENDPOINT, CHAT_COMPLETIONS_ENDPOINT],
        # Provider transport remains request/response. Only app-server exposes
        # the dynamic client-tool bridge used by the Responses API.
        "supports_streaming": False,
        "supports_tools": selector == "codex_app_server",
    }
    return normalize_backend_capability(capability)


def normalize_backend_capability(value: Any) -> dict[str, Any]:
    capability = _json_object_copy(value, label="backend capability")
    _require_schema(capability, BACKEND_CAPABILITY_SCHEMA, label="backend capability")

    kind = _token(capability.get("kind"), label="backend capability kind")
    protocol = capability.get("protocol")
    if protocol != OPENAI_COMPATIBLE_PROTOCOL:
        raise BackendCapabilityError(
            f"backend capability protocol must be {OPENAI_COMPATIBLE_PROTOCOL!r}"
        )

    endpoints = capability.get("endpoints")
    if not isinstance(endpoints, list) or isinstance(endpoints, (str, bytes)):
        raise BackendCapabilityError("backend capability endpoints must be a list")
    if not endpoints or len(endpoints) > MAX_ENDPOINTS:
        raise BackendCapabilityError(
            f"backend capability endpoints must contain 1-{MAX_ENDPOINTS} entries"
        )
    normalized_endpoints: list[str] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            raise BackendCapabilityError("backend capability endpoints must be strings")
        if (
            len(endpoint) > MAX_ENDPOINT_LENGTH
            or _ENDPOINT_PATTERN.fullmatch(endpoint) is None
            or "//" in endpoint
            or endpoint.endswith("/")
        ):
            raise BackendCapabilityError(
                "backend capability endpoints must be canonical /v1 paths"
            )
        if endpoint in normalized_endpoints:
            raise BackendCapabilityError("backend capability endpoints must be unique")
        normalized_endpoints.append(endpoint)

    supports_streaming = _boolean(
        capability.get("supports_streaming"),
        label="backend capability supports_streaming",
    )
    supports_tools = _boolean(
        capability.get("supports_tools"),
        label="backend capability supports_tools",
    )
    if kind == CODEX_OAUTH_SIDECAR_KIND and RESPONSES_ENDPOINT not in normalized_endpoints:
        raise BackendCapabilityError(
            "codex_oauth_sidecar backend capability must expose /v1/responses"
        )
    _reject_reserved_trust_assertions_recursive(
        capability,
        label="backend capability",
    )
    _reject_credential_fields(capability, label="backend capability")

    capability.update(
        {
            "schema": BACKEND_CAPABILITY_SCHEMA,
            "kind": kind,
            "protocol": OPENAI_COMPATIBLE_PROTOCOL,
            "endpoints": normalized_endpoints,
            "supports_streaming": supports_streaming,
            "supports_tools": supports_tools,
        }
    )
    return capability


def build_self_attested_trust_evidence() -> dict[str, Any]:
    return normalize_trust_evidence(
        {
            "schema": TRUST_EVIDENCE_SCHEMA,
            "mode": SELF_ATTESTED_TRUST_MODE,
            "claims": dict(_REQUIRED_SELF_ATTESTED_CLAIMS),
        }
    )


def normalize_trust_evidence(value: Any) -> dict[str, Any]:
    evidence = _json_object_copy(value, label="trust evidence")
    _require_schema(evidence, TRUST_EVIDENCE_SCHEMA, label="trust evidence")
    mode = evidence.get("mode")
    if mode != SELF_ATTESTED_TRUST_MODE:
        raise BackendCapabilityError(
            "trust evidence mode is unsupported; only self_attested is accepted"
        )
    _reject_reserved_trust_assertions_recursive(evidence, label="trust evidence")
    _reject_credential_fields(evidence, label="trust evidence")

    claims = evidence.get("claims")
    if not isinstance(claims, dict):
        raise BackendCapabilityError("trust evidence claims must be a JSON object")
    for field, expected in _REQUIRED_SELF_ATTESTED_CLAIMS.items():
        if claims.get(field) != expected:
            raise BackendCapabilityError(
                f"self_attested trust evidence {field} must be {expected!r}"
            )

    evidence.update(
        {
            "schema": TRUST_EVIDENCE_SCHEMA,
            "mode": SELF_ATTESTED_TRUST_MODE,
            "claims": claims,
        }
    )
    return evidence


def derive_verified_trust_level(value: Any) -> str:
    """Derive the highest level supported by locally verified evidence.

    Structural validation does not turn Provider claims into runtime, upstream,
    or usage proof. Version one therefore derives only ``self_attested``.
    """

    evidence = normalize_trust_evidence(value)
    if evidence["mode"] == SELF_ATTESTED_TRUST_MODE:
        return SELF_ATTESTED_TRUST_LEVEL
    raise BackendCapabilityError("trust evidence cannot derive a verified trust level")


def parse_provider_backend_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BackendCapabilityError("provider descriptor must be a JSON object")
    backend_capability = normalize_backend_capability(value.get("backend_capability"))
    trust_evidence = normalize_trust_evidence(value.get("trust_evidence"))
    return {
        "backend_capability": backend_capability,
        "trust_evidence": trust_evidence,
        "verified_trust_level": derive_verified_trust_level(trust_evidence),
    }


def verify_provider_backend_metadata(value: Any) -> dict[str, Any]:
    """Structurally verify metadata from an already authenticated descriptor."""

    return parse_provider_backend_metadata(value)


def validate_provider_backend_metadata(value: Any) -> dict[str, Any]:
    """Validate capability and trust fields without upgrading self-attestation."""

    return parse_provider_backend_metadata(value)


def validate_backend_matches_selector(backend: Any, capability: Any) -> dict[str, Any]:
    normalized = normalize_backend_capability(capability)
    selector = _backend_selector(backend)
    expected_kind = _BACKEND_KINDS.get(selector)
    if expected_kind is not None and normalized["kind"] != expected_kind:
        raise BackendCapabilityError(
            f"backend capability kind must be {expected_kind!r} for backend {selector!r}"
        )
    return normalized


def _backend_selector(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "unspecified"
    normalized = value.strip().lower()
    if _TOKEN_PATTERN.fullmatch(normalized) is None:
        raise BackendCapabilityError("backend selector must be a lowercase identifier")
    return normalized


def _require_schema(value: Mapping[str, Any], expected: str, *, label: str) -> None:
    if value.get("schema") != expected:
        raise BackendCapabilityError(f"{label} schema must be {expected!r}")


def _token(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _TOKEN_PATTERN.fullmatch(value) is None:
        raise BackendCapabilityError(f"{label} must be a lowercase identifier")
    return value


def _boolean(value: Any, *, label: str) -> bool:
    if type(value) is not bool:
        raise BackendCapabilityError(f"{label} must be a boolean")
    return value


def _json_object_copy(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BackendCapabilityError(f"{label} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise BackendCapabilityError(f"{label} keys must be strings")
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > MAX_CAPABILITY_BYTES:
            raise BackendCapabilityError(
                f"{label} exceeds the {MAX_CAPABILITY_BYTES}-byte limit"
            )
        decoded = json.loads(encoded)
    except BackendCapabilityError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise BackendCapabilityError(f"{label} must contain JSON-compatible values") from exc
    if not isinstance(decoded, dict):
        raise BackendCapabilityError(f"{label} must be a JSON object")
    return decoded


def _reject_reserved_trust_assertions(value: Mapping[str, Any], *, label: str) -> None:
    reserved = _matching_fields(value, _RESERVED_TRUST_ASSERTION_FIELDS)
    if reserved:
        raise BackendCapabilityError(
            f"{label} contains unverified reserved trust assertions: {', '.join(reserved)}"
        )


def _reject_reserved_trust_assertions_recursive(value: Any, *, label: str) -> None:
    if isinstance(value, Mapping):
        _reject_reserved_trust_assertions(value, label=label)
        for nested in value.values():
            _reject_reserved_trust_assertions_recursive(nested, label=label)
    elif isinstance(value, list):
        for nested in value:
            _reject_reserved_trust_assertions_recursive(nested, label=label)


def _reject_credential_fields(value: Any, *, label: str) -> None:
    if isinstance(value, dict):
        forbidden = _matching_fields(value, _CREDENTIAL_FIELDS)
        if forbidden:
            raise BackendCapabilityError(
                f"{label} must not contain credentials: {', '.join(forbidden)}"
            )
        for nested in value.values():
            _reject_credential_fields(nested, label=label)
    elif isinstance(value, list):
        for nested in value:
            _reject_credential_fields(nested, label=label)


def _matching_fields(value: Mapping[str, Any], forbidden: set[str]) -> list[str]:
    canonical_forbidden = {_canonical_field_name(field) for field in forbidden}
    return sorted(
        field
        for field in value
        if _canonical_field_name(field) in canonical_forbidden
    )


def _canonical_field_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())
