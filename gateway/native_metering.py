from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .identity import IdentityError, verify_document
from .upstream import UpstreamClient


CAPABILITIES_CHALLENGE_SCHEMA = "mycomesh.inference.capabilities.challenge.v1"
CAPABILITIES_SCHEMA = "mycomesh.inference.capabilities.v1"
CAPABILITIES_PURPOSE = CAPABILITIES_SCHEMA
INFERENCE_REQUEST_SCHEMA = "mycomesh.inference.request.v1"
INFERENCE_RESULT_SCHEMA = "mycomesh.inference.result.v1"
METERING_SCHEMA = "mycomesh.inference.metering.v1"
METERING_PURPOSE = METERING_SCHEMA
CAPABILITIES_PATH = "/mycomesh/capabilities"
INFERENCE_PATH = "/mycomesh/infer"
PROOF_MAX_AGE_SECONDS = 120
CAPABILITIES_MAX_LIFETIME_SECONDS = 3600
CAPABILITIES_REFRESH_SKEW_SECONDS = 30
CAPABILITIES_PROBE_TIMEOUT_SECONDS = 5.0
CAPABILITIES_RETRY_BACKOFF_SECONDS = 5.0
MAX_TOKEN_COUNT = (1 << 63) - 1

_OUTPUT_CAP_ALIASES = frozenset({"max_tokens", "max_completion_tokens", "max_output_tokens"})
_CHAT_ALLOWED_FIELDS = frozenset(
    {"model", "messages", "n", "mycomesh_p2p_request_hash"}
) | _OUTPUT_CAP_ALIASES
_RESPONSES_ALLOWED_FIELDS = frozenset(
    {"model", "input", "mycomesh_p2p_request_hash"}
) | _OUTPUT_CAP_ALIASES


class NativeMeteringError(RuntimeError):
    pass


class NativeMeteringRequestError(ValueError):
    pass


@dataclass(frozen=True)
class CanonicalNativeRequest:
    """Exact native payload shared by the Gateway and settlement Provider."""

    endpoint: str
    model: str
    output_token_cap: int
    payload: dict[str, Any]
    p2p_request_hash: str


@dataclass(frozen=True)
class PreparedInference:
    endpoint: str
    request_id: str
    nonce: str
    output_token_cap: int
    request_hash: str
    envelope: dict[str, Any]


class NativeMeteredBackend:
    """Fail-closed adapter for an engine-controlled, signed metering sidecar."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None,
        expected_model: str,
        expected_model_revision: str,
        metering_public_key: str,
        capabilities_sha256: str,
        audience: str,
        default_output_token_cap: int,
    ) -> None:
        _validate_transport(base_url)
        if not isinstance(api_key, str) or len(api_key) < 32 or api_key != api_key.strip():
            raise ValueError(
                "native_metered_http requires an UPSTREAM_API_KEY of at least 32 characters"
            )
        self.expected_model = _required_text(expected_model, "CENTER_MODEL")
        self.expected_model_revision = _required_text(
            expected_model_revision, "UPSTREAM_EXPECTED_MODEL_REVISION"
        )
        self.metering_public_key = _public_key(metering_public_key)
        self.capabilities_sha256 = _sha256_hex(
            capabilities_sha256, "UPSTREAM_CAPABILITIES_SHA256"
        )
        self.audience = _required_text(audience, "UPSTREAM_METERING_AUDIENCE")
        self.default_output_token_cap = _positive_int(
            default_output_token_cap, "UPSTREAM_DEFAULT_MAX_OUTPUT_TOKENS"
        )
        self._ready = False
        self._backend_id: str | None = None
        self._maximum_output_token_cap: int | None = None
        self._capabilities_expires_at = 0
        self._capabilities_lock = asyncio.Lock()
        self._next_probe_at = 0.0
        self._last_probe_error: str | None = None

    @property
    def capabilities(self) -> dict[str, Any]:
        ready = self._capabilities_ready(
            minimum_validity_seconds=CAPABILITIES_REFRESH_SKEW_SECONDS
        )
        maximum = self._maximum_output_token_cap
        limitation = None
        if not ready:
            limitation = self._last_probe_error or (
                "signed native-metering capabilities are unavailable or expired"
            )
        return {
            "schema": CAPABILITIES_SCHEMA,
            "backend": "native_metered_http",
            "backend_id": self._backend_id,
            "native_output_token_cap": ready,
            "native_usage_events": ready,
            "trusted_native_usage": ready,
            "runtime_metering_proof": ready,
            "supports_streaming": False,
            "production_ready": ready,
            "model": self.expected_model,
            "model_revision": self.expected_model_revision,
            "maximum_output_token_cap": maximum,
            "capabilities_sha256": self.capabilities_sha256,
            "metering_key_fingerprint": hashlib.sha256(
                bytes.fromhex(self.metering_public_key)
            ).hexdigest()[:16],
            "limitation": limitation,
        }

    def _capabilities_ready(
        self, *, now: float | None = None, minimum_validity_seconds: int = 0
    ) -> bool:
        current_time = time.time() if now is None else now
        return (
            self._ready
            and self._maximum_output_token_cap is not None
            and self._capabilities_expires_at > current_time + minimum_validity_seconds
        )

    async def ensure_ready(self, upstream: UpstreamClient) -> None:
        if self._capabilities_ready(
            minimum_validity_seconds=CAPABILITIES_REFRESH_SKEW_SECONDS
        ):
            return
        monotonic_now = time.monotonic()
        if monotonic_now < self._next_probe_at:
            raise NativeMeteringError("native-metering capability refresh is in backoff")
        async with self._capabilities_lock:
            if self._capabilities_ready(
                minimum_validity_seconds=CAPABILITIES_REFRESH_SKEW_SECONDS
            ):
                return
            monotonic_now = time.monotonic()
            if monotonic_now < self._next_probe_at:
                raise NativeMeteringError("native-metering capability refresh is in backoff")
            try:
                await asyncio.wait_for(
                    self.startup_probe(upstream),
                    timeout=CAPABILITIES_PROBE_TIMEOUT_SECONDS,
                )
            except (NativeMeteringError, ValueError, RuntimeError, TimeoutError) as exc:
                self._next_probe_at = time.monotonic() + CAPABILITIES_RETRY_BACKOFF_SECONDS
                self._last_probe_error = "signed native-metering capability refresh failed"
                raise NativeMeteringError(self._last_probe_error) from exc
            self._next_probe_at = 0.0
            self._last_probe_error = None

    async def startup_probe(self, upstream: UpstreamClient) -> None:
        challenge = secrets.token_hex(32)
        response = await upstream.post_json(
            CAPABILITIES_PATH,
            {
                "schema": CAPABILITIES_CHALLENGE_SCHEMA,
                "challenge": challenge,
                "audience": self.audience,
            },
        )
        if response.status_code != 200:
            raise NativeMeteringError(
                f"native-metering capability endpoint returned HTTP {response.status_code}"
            )
        document = _response_json(response.content, "capability response")
        self.accept_capabilities(document, challenge=challenge)

    def accept_capabilities(
        self,
        document: dict[str, Any],
        *,
        challenge: str,
        now: int | None = None,
    ) -> None:
        current_time = int(time.time() if now is None else now)
        unsigned = _verify_pinned_document(
            document,
            purpose=CAPABILITIES_PURPOSE,
            audience=self.audience,
            public_key=self.metering_public_key,
            now=current_time,
        )
        _expect_equal(unsigned, "schema", CAPABILITIES_SCHEMA)
        _expect_equal(unsigned, "challenge", challenge)
        _expect_equal(unsigned, "model", self.expected_model)
        _expect_equal(unsigned, "model_revision", self.expected_model_revision)
        _expect_equal(unsigned, "capabilities_sha256", self.capabilities_sha256)
        _expect_true(unsigned, "native_output_token_cap")
        _expect_true(unsigned, "trusted_native_usage")
        _expect_false(unsigned, "supports_streaming")
        try:
            backend_id = _required_text(unsigned.get("backend_id"), "capability backend_id")
            maximum = _positive_int(
                unsigned.get("maximum_output_token_cap"),
                "capability maximum_output_token_cap",
            )
        except ValueError as exc:
            raise NativeMeteringError(f"invalid signed capability: {exc}") from exc
        if self.default_output_token_cap > maximum:
            raise NativeMeteringError(
                "UPSTREAM_DEFAULT_MAX_OUTPUT_TOKENS exceeds the signed capability maximum"
            )
        expires_at = _validate_expiry(
            unsigned,
            now=current_time,
            label="capability",
            maximum_lifetime_seconds=CAPABILITIES_MAX_LIFETIME_SECONDS,
        )
        self._backend_id = backend_id
        self._maximum_output_token_cap = maximum
        self._capabilities_expires_at = expires_at
        self._ready = True

    def prepare_request(self, endpoint: str, body: dict[str, Any]) -> PreparedInference:
        if not self._capabilities_ready(
            minimum_validity_seconds=CAPABILITIES_REFRESH_SKEW_SECONDS
        ):
            raise NativeMeteringError("native-metering backend is not ready")
        canonical_request = canonicalize_native_request(
            endpoint,
            body,
            expected_model=self.expected_model,
            default_output_token_cap=self.default_output_token_cap,
            maximum_output_token_cap=self._maximum_output_token_cap,
        )
        request_id = "mreq_" + secrets.token_hex(16)
        nonce = secrets.token_hex(32)
        envelope = build_native_inference_envelope(
            canonical_request,
            request_id=request_id,
            nonce=nonce,
            audience=self.audience,
            model_revision=self.expected_model_revision,
        )
        return PreparedInference(
            endpoint=canonical_request.endpoint,
            request_id=request_id,
            nonce=nonce,
            output_token_cap=canonical_request.output_token_cap,
            request_hash=native_inference_request_hash(
                canonical_request,
                request_id=request_id,
                nonce=nonce,
                audience=self.audience,
                model_revision=self.expected_model_revision,
            ),
            envelope=envelope,
        )

    def verify_result(
        self,
        prepared: PreparedInference,
        document: dict[str, Any],
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        current_time = int(time.time() if now is None else now)
        _expect_equal(document, "schema", INFERENCE_RESULT_SCHEMA)
        _expect_equal(document, "request_id", prepared.request_id)
        result = document.get("result")
        proof = document.get("metering")
        if not isinstance(result, dict):
            raise NativeMeteringError("native-metering result must be a JSON object")
        if not isinstance(proof, dict):
            raise NativeMeteringError("native-metering proof is missing")
        validate_metered_result_shape(prepared.endpoint, result)

        unsigned = _verify_pinned_document(
            proof,
            purpose=METERING_PURPOSE,
            audience=self.audience,
            public_key=self.metering_public_key,
            now=current_time,
        )
        _expect_equal(unsigned, "schema", METERING_SCHEMA)
        _expect_equal(unsigned, "request_id", prepared.request_id)
        _expect_equal(unsigned, "nonce", prepared.nonce)
        _expect_equal(unsigned, "request_hash", prepared.request_hash)
        _expect_equal(unsigned, "response_hash", _metered_response_hash(result))
        _expect_equal(unsigned, "endpoint", prepared.endpoint)
        _expect_equal(unsigned, "model", self.expected_model)
        _expect_equal(unsigned, "model_revision", self.expected_model_revision)
        _expect_equal(unsigned, "capabilities_sha256", self.capabilities_sha256)
        _expect_equal(unsigned, "output_token_cap", prepared.output_token_cap)
        _expect_equal(
            unsigned,
            "p2p_request_hash",
            prepared.envelope["payload"]["mycomesh_p2p_request_hash"],
        )
        _validate_expiry(
            unsigned,
            now=current_time,
            label="metering proof",
            maximum_lifetime_seconds=PROOF_MAX_AGE_SECONDS,
        )

        input_tokens = _token_count(unsigned.get("input_tokens"), "input_tokens")
        output_tokens = _token_count(unsigned.get("output_tokens"), "output_tokens")
        total_tokens = _token_count(unsigned.get("total_tokens"), "total_tokens")
        if total_tokens != input_tokens + output_tokens:
            raise NativeMeteringError("metering total_tokens must equal input_tokens + output_tokens")
        if output_tokens > prepared.output_token_cap:
            raise NativeMeteringError("metered output_tokens exceed the authorized output-token cap")
        if result.get("model") != self.expected_model:
            raise NativeMeteringError("inference result model does not match the pinned model")
        verified = dict(result)
        if prepared.endpoint == "chat":
            verified["usage"] = {
                "prompt_tokens": input_tokens,
                "completion_tokens": output_tokens,
                "total_tokens": total_tokens,
            }
        else:
            verified["usage"] = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
            }
        verified["_mycomesh_metering"] = proof
        verified["_mycomesh_capabilities_sha256"] = self.capabilities_sha256
        return verified

    def parse_and_verify_result(
        self,
        prepared: PreparedInference,
        content: bytes,
    ) -> dict[str, Any]:
        return self.verify_result(prepared, _response_json(content, "inference response"))


def canonicalize_native_request(
    endpoint: str,
    body: dict[str, Any],
    *,
    expected_model: str,
    default_output_token_cap: int,
    maximum_output_token_cap: int | None = None,
) -> CanonicalNativeRequest:
    """Normalize the only inference payload accepted by native metering."""
    if not isinstance(body, dict):
        raise NativeMeteringRequestError("native-metered inference body must be a JSON object")
    if endpoint not in {"chat", "responses"}:
        raise NativeMeteringRequestError(f"unsupported metered inference endpoint: {endpoint}")
    _validate_request_json(body)
    if body.get("stream") is True:
        raise NativeMeteringRequestError(
            "streaming is disabled for settlement-backed native metering"
        )
    allowed_fields = (
        _CHAT_ALLOWED_FIELDS if endpoint == "chat" else _RESPONSES_ALLOWED_FIELDS
    )
    unsupported = sorted(set(body) - allowed_fields)
    if unsupported:
        raise NativeMeteringRequestError(
            "native-metered inference does not support fields: " + ", ".join(unsupported)
        )

    model = _required_text(expected_model, "expected native model")
    if body.get("model") != model:
        raise NativeMeteringRequestError(
            f"native-metered inference requires model {model!r}"
        )
    p2p_request_hash = _canonical_hash(
        body.get("mycomesh_p2p_request_hash"),
        "mycomesh_p2p_request_hash",
    )
    supplied_caps = [
        (field, body[field]) for field in _OUTPUT_CAP_ALIASES if field in body
    ]
    if len(supplied_caps) > 1:
        raise NativeMeteringRequestError("provide exactly one output-token cap field")
    try:
        default_cap = _positive_int(
            default_output_token_cap, "default_output_token_cap"
        )
        output_token_cap = (
            _positive_int(supplied_caps[0][1], supplied_caps[0][0])
            if supplied_caps
            else default_cap
        )
    except ValueError as exc:
        raise NativeMeteringRequestError(str(exc)) from exc
    if maximum_output_token_cap is not None:
        try:
            maximum = _positive_int(
                maximum_output_token_cap, "signed capability maximum_output_token_cap"
            )
        except ValueError as exc:
            raise NativeMeteringError(str(exc)) from exc
        if output_token_cap > maximum:
            raise NativeMeteringRequestError(
                "requested output-token cap exceeds the signed capability maximum"
            )

    if endpoint == "chat":
        if type(body.get("n", 1)) is not int or body.get("n", 1) != 1:
            raise NativeMeteringRequestError("native-metered chat requires n=1")
        messages = body.get("messages")
        _validate_text_messages(messages)
        payload = {
            "model": model,
            "messages": messages,
            "mycomesh_p2p_request_hash": p2p_request_hash,
        }
    else:
        input_value = body.get("input")
        if not isinstance(input_value, str):
            raise NativeMeteringRequestError(
                "native-metered responses input must be text"
            )
        payload = {
            "model": model,
            "input": input_value,
            "mycomesh_p2p_request_hash": p2p_request_hash,
        }
    return CanonicalNativeRequest(
        endpoint=endpoint,
        model=model,
        output_token_cap=output_token_cap,
        payload=payload,
        p2p_request_hash=p2p_request_hash,
    )


def build_native_inference_envelope(
    request: CanonicalNativeRequest,
    *,
    request_id: str,
    nonce: str,
    audience: str,
    model_revision: str,
) -> dict[str, Any]:
    """Build the exact document whose hash the sidecar must sign."""
    if not isinstance(request, CanonicalNativeRequest):
        raise ValueError("request must be a CanonicalNativeRequest")
    if request.endpoint not in {"chat", "responses"}:
        raise ValueError("native request endpoint must be chat or responses")
    model = _required_text(request.model, "native request model")
    revision = _required_text(model_revision, "native request model_revision")
    request_audience = _required_text(audience, "native request audience")
    normalized_request_id = _required_text(request_id, "native request_id")
    normalized_nonce = _canonical_hash(nonce, "native request nonce")
    try:
        output_token_cap = _positive_int(
            request.output_token_cap, "native request output_token_cap"
        )
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(request.payload, dict):
        raise ValueError("native request payload must be a JSON object")
    payload = dict(request.payload)
    p2p_request_hash = _canonical_hash(
        request.p2p_request_hash, "mycomesh_p2p_request_hash"
    )
    expected_fields = (
        {"model", "messages", "mycomesh_p2p_request_hash"}
        if request.endpoint == "chat"
        else {"model", "input", "mycomesh_p2p_request_hash"}
    )
    if set(payload) != expected_fields:
        raise ValueError("native request payload has unexpected fields")
    if payload.get("model") != model:
        raise ValueError("native request payload model does not match")
    if payload.get("mycomesh_p2p_request_hash") != p2p_request_hash:
        raise ValueError("native request payload p2p_request_hash does not match")
    if request.endpoint == "chat":
        _validate_text_messages(payload.get("messages"))
    elif not isinstance(payload.get("input"), str):
        raise ValueError("native request responses input must be text")
    _validate_request_json(payload)
    return {
        "schema": INFERENCE_REQUEST_SCHEMA,
        "request_id": normalized_request_id,
        "nonce": normalized_nonce,
        "audience": request_audience,
        "endpoint": request.endpoint,
        "model": model,
        "model_revision": revision,
        "max_output_tokens": output_token_cap,
        "payload": payload,
    }


def native_inference_request_hash(
    request: CanonicalNativeRequest,
    *,
    request_id: str,
    nonce: str,
    audience: str,
    model_revision: str,
) -> str:
    return _document_hash(
        build_native_inference_envelope(
            request,
            request_id=request_id,
            nonce=nonce,
            audience=audience,
            model_revision=model_revision,
        )
    )


def validate_metered_result_shape(endpoint: str, result: dict[str, Any]) -> None:
    """Reject sidecar responses that cannot satisfy the selected OpenAI surface."""
    if endpoint not in {"chat", "responses"}:
        raise NativeMeteringError("metered result used an unsupported endpoint")
    if not isinstance(result, dict):
        raise NativeMeteringError("native-metering result must be a JSON object")
    if any(
        isinstance(key, str) and key.startswith("_mycomesh_")
        for key in result
    ):
        raise NativeMeteringError(
            "native-metering result must not contain reserved _mycomesh_ fields"
        )
    try:
        _document_hash(result)
    except NativeMeteringError as exc:
        raise NativeMeteringError(
            "native-metering result must be strict canonical JSON"
        ) from exc
    if not isinstance(result.get("usage"), dict):
        raise NativeMeteringError("inference result must include a usage object")
    if endpoint == "chat":
        choices = result.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise NativeMeteringError(
                "native-metering chat result must contain exactly one choice"
            )
        choice = choices[0]
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            raise NativeMeteringError(
                "native-metering chat result choice must contain a message"
            )
        if message.get("role") != "assistant" or not isinstance(
            message.get("content"), str
        ):
            raise NativeMeteringError(
                "native-metering chat result must contain assistant text content"
            )
        if "tool_calls" in message:
            raise NativeMeteringError(
                "native-metering chat result must not contain tool calls"
            )
    elif not isinstance(result.get("output_text"), str):
        raise NativeMeteringError(
            "native-metering responses result must contain text output_text"
        )


def _verify_pinned_document(
    document: dict[str, Any],
    *,
    purpose: str,
    audience: str,
    public_key: str,
    now: int,
) -> dict[str, Any]:
    try:
        unsigned = verify_document(
            document,
            purpose=purpose,
            audience=audience,
            max_age_seconds=PROOF_MAX_AGE_SECONDS,
            now=now,
        )
    except IdentityError as exc:
        raise NativeMeteringError(f"invalid signed {purpose} document: {exc}") from exc
    signature = document.get("signature")
    actual_key = signature.get("public_key") if isinstance(signature, dict) else None
    if actual_key != public_key:
        raise NativeMeteringError("signed metering document used an unpinned public key")
    return unsigned


def _validate_transport(base_url: str) -> None:
    parsed = urlsplit(base_url)
    if parsed.scheme == "https":
        return
    hostname = parsed.hostname or ""
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if hostname.lower() != "localhost":
            raise ValueError(
                "native_metered_http requires HTTPS unless UPSTREAM_BASE_URL is loopback"
            )
    else:
        if not address.is_loopback:
            raise ValueError(
                "native_metered_http requires HTTPS unless UPSTREAM_BASE_URL is loopback"
            )


def _response_json(content: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise NativeMeteringError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise NativeMeteringError(f"{label} contains non-finite number {value}")

    try:
        payload = json.loads(
            content,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeMeteringError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise NativeMeteringError(f"{label} must be a JSON object")
    return payload


def _validate_expiry(
    document: dict[str, Any],
    *,
    now: int,
    label: str,
    maximum_lifetime_seconds: int,
) -> int:
    issued_at = _exact_int(document.get("issued_at"), f"{label} issued_at")
    expires_at = _exact_int(document.get("expires_at"), f"{label} expires_at")
    if issued_at > now + 30:
        raise NativeMeteringError(f"{label} issued_at is in the future")
    if expires_at < now:
        raise NativeMeteringError(f"{label} has expired")
    if expires_at <= issued_at or expires_at - issued_at > maximum_lifetime_seconds:
        raise NativeMeteringError(f"{label} lifetime exceeds the protocol maximum")
    return expires_at


def _expect_equal(document: dict[str, Any], field: str, expected: Any) -> None:
    if document.get(field) != expected:
        raise NativeMeteringError(f"signed metering field {field!r} does not match")


def _expect_true(document: dict[str, Any], field: str) -> None:
    if document.get(field) is not True:
        raise NativeMeteringError(f"signed capability {field!r} must be true")


def _expect_false(document: dict[str, Any], field: str) -> None:
    if document.get(field) is not False:
        raise NativeMeteringError(f"signed capability {field!r} must be false")


def _validate_text_messages(value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise NativeMeteringRequestError("native-metered chat messages must be a non-empty list")
    for message in value:
        if not isinstance(message, dict) or set(message) - {"role", "content"}:
            raise NativeMeteringRequestError(
                "native-metered chat messages support only role and text content"
            )
        if message.get("role") not in {"system", "user", "assistant"}:
            raise NativeMeteringRequestError("native-metered chat message role is unsupported")
        if not isinstance(message.get("content"), str):
            raise NativeMeteringRequestError("native-metered chat content must be text")


def _validate_request_json(value: Any) -> None:
    try:
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise NativeMeteringRequestError(
            "native-metered request must be strict canonical JSON"
        ) from exc


def _canonical_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise NativeMeteringRequestError(f"{label} must be 32-byte lowercase hex")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise NativeMeteringRequestError(f"{label} must be 32-byte lowercase hex") from exc
    return value


def _metered_response_hash(result: dict[str, Any]) -> str:
    unsigned_result = {
        key: value
        for key, value in result.items()
        if key != "usage"
    }
    return _document_hash(unsigned_result)


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 512:
        raise ValueError(f"{label} must be a non-empty bounded string")
    return value


def _public_key(value: Any) -> str:
    key = _required_text(value, "UPSTREAM_METERING_PUBLIC_KEY").lower()
    try:
        raw = bytes.fromhex(key)
    except ValueError as exc:
        raise ValueError("UPSTREAM_METERING_PUBLIC_KEY must be 32-byte hex") from exc
    if len(raw) != 32:
        raise ValueError("UPSTREAM_METERING_PUBLIC_KEY must be 32-byte hex")
    return key


def _sha256_hex(value: Any, label: str) -> str:
    digest = _required_text(value, label).lower()
    if len(digest) != 64:
        raise ValueError(f"{label} must be 32-byte lowercase hex")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise ValueError(f"{label} must be 32-byte lowercase hex") from exc
    return digest


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{label} must be an exact JSON integer")
    if value <= 0 or value > MAX_TOKEN_COUNT:
        raise ValueError(f"{label} must be between 1 and {MAX_TOKEN_COUNT}")
    return value


def _token_count(value: Any, label: str) -> int:
    parsed = _exact_int(value, label)
    if parsed < 0 or parsed > MAX_TOKEN_COUNT:
        raise NativeMeteringError(f"{label} must be between 0 and {MAX_TOKEN_COUNT}")
    return parsed


def _exact_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise NativeMeteringError(f"{label} must be an exact JSON integer")
    return value


def _document_hash(document: dict[str, Any]) -> str:
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativeMeteringError("metering document must be strict canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()
