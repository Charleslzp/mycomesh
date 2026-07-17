# Native Metered Upstream Protocol

This protocol is the only HTTP inference backend that may report
`production_ready=true` to a non-local MycoMesh Provider. Generic
OpenAI-compatible HTTP and the bundled Codex backends remain fail-closed.

The metering sidecar must be the only component able to invoke the inference
engine. It must apply the engine's native generation cap and read token counts
from the same engine execution. Signing an ordinary proxy response, counting
tokens after generation, or truncating text after generation does not satisfy
this trust boundary.

## Configuration

```dotenv
GATEWAY_BACKEND=native_metered_http
UPSTREAM_BASE_URL=https://meter.example/v1
UPSTREAM_API_KEY=<at-least-32-character-secret>
CENTER_MODEL=<exact-engine-model-id>
PUBLIC_MODEL_ID=<network-facing-model-id>
UPSTREAM_EXPECTED_MODEL_REVISION=<immutable-model-or-image-digest>
UPSTREAM_METERING_PUBLIC_KEY=<32-byte-ed25519-public-key-hex>
UPSTREAM_CAPABILITIES_SHA256=<64-lowercase-hex-contract-digest>
UPSTREAM_METERING_AUDIENCE=<deployment-unique-audience>
UPSTREAM_DEFAULT_MAX_OUTPUT_TOKENS=2000
```

Remote upstreams require HTTPS. Plain HTTP is accepted only on loopback.
Redirects are never followed. The metering private key belongs only in the
sidecar or an HSM/TEE available to it; the Gateway and Provider receive only
the public key.

The capability digest is SHA-256 over the canonical JSON form of the reviewed,
immutable sidecar contract. At minimum that contract should identify the
backend ID, exact model and revision, sidecar image digest, metering
implementation digest, native token semantics, maximum output cap, and key ID.
Canonical JSON uses UTF-8, sorted object keys, no insignificant whitespace, and
JSON literals rather than language-specific values.

## Signing

Documents use the existing `gateway.identity.sign_document` envelope. The
Ed25519 message is canonical JSON of:

```json
{
  "document": {},
  "signature": {
    "audience": "deployment audience",
    "nonce": "random hex",
    "public_key": "32-byte hex",
    "purpose": "protocol purpose",
    "timestamp": 1800000000
  }
}
```

The hexadecimal signature is then added as `signature.signature`. Capability
and metering signatures use different purposes:

- `mycomesh.inference.capabilities.v1`
- `mycomesh.inference.metering.v1`

Capability documents may be valid for at most 3600 seconds and are refreshed 30 seconds before expiry. Per-request metering proofs must expire within 120 seconds. The Gateway additionally
pins the exact public key and audience.

## Capability Handshake

The Gateway calls `POST /mycomesh/capabilities` relative to
`UPSTREAM_BASE_URL` during startup and capability refresh:

```json
{
  "schema": "mycomesh.inference.capabilities.challenge.v1",
  "challenge": "<32-byte-random-hex>",
  "audience": "<configured-audience>"
}
```

The sidecar returns a signed document with these unsigned fields:

```json
{
  "schema": "mycomesh.inference.capabilities.v1",
  "challenge": "<exact-request-challenge>",
  "backend_id": "<stable-reviewed-backend-id>",
  "model": "<exact-center-model>",
  "model_revision": "<exact-pinned-revision>",
  "capabilities_sha256": "<exact-pinned-contract-digest>",
  "native_output_token_cap": true,
  "trusted_native_usage": true,
  "supports_streaming": false,
  "maximum_output_token_cap": 8192,
  "issued_at": 1800000000,
  "expires_at": 1800000060
}
```

The Gateway computes readiness itself. An upstream-supplied
`production_ready` field is ignored. `GET /health` is process liveness only;
it may return `200` while metering or settlement is unavailable. `GET /ready`
refreshes the signed capability and returns `200` only when
`settlement_ready=true`, otherwise `503`.

## Inference

For paid P2P work, the Provider first commits the provider and consumer keys,
request ID, request-signature nonce, reservation nonce, and settlement request
hash into the SHA-256 `mycomesh_p2p_request_hash`. It then calls the
authenticated, Provider-only Gateway route `POST /mycomesh/p2p-infer`:

```json
{
  "schema": "mycomesh.gateway.p2p-native.v1",
  "endpoint": "responses",
  "request": {
    "model": "<exact-center-model>",
    "input": "<exact-text-input>",
    "max_output_tokens": 2000,
    "mycomesh_p2p_request_hash": "<64-lowercase-hex>"
  }
}
```

This route does not add agent prompts, routing context, history, metadata, or
model rewrites. It is an internal Provider-to-Gateway contract, not a public
OpenAI endpoint. The Gateway accepts exactly one output-cap field, canonicalizes
the request, and sends this envelope to `POST /mycomesh/infer` on the sidecar:

```json
{
  "schema": "mycomesh.inference.request.v1",
  "request_id": "mreq_<random>",
  "nonce": "<32-byte-random-hex>",
  "audience": "<configured-audience>",
  "endpoint": "responses",
  "model": "<exact-center-model>",
  "model_revision": "<exact-pinned-revision>",
  "max_output_tokens": 2000,
  "payload": {
    "model": "<exact-center-model>",
    "input": "<exact-text-input>",
    "mycomesh_p2p_request_hash": "<64-lowercase-hex>"
  }
}
```

The request hash is SHA-256 of this complete canonical JSON object. The
sidecar returns:

```json
{
  "schema": "mycomesh.inference.result.v1",
  "request_id": "mreq_<same-request>",
  "result": {
    "model": "<exact-center-model>",
    "output_text": "<generated-text>",
    "usage": {}
  },
  "metering": {
    "schema": "mycomesh.inference.metering.v1",
    "request_id": "mreq_<same-request>",
    "nonce": "<same-request-nonce>",
    "request_hash": "<canonical-request-sha256>",
    "response_hash": "<canonical-result-sha256>",
    "endpoint": "responses",
    "model": "<exact-center-model>",
    "model_revision": "<exact-pinned-revision>",
    "capabilities_sha256": "<exact-pinned-contract-digest>",
    "p2p_request_hash": "<same-P2P-execution-commitment>",
    "output_token_cap": 2000,
    "input_tokens": 100,
    "output_tokens": 50,
    "total_tokens": 150,
    "issued_at": 1800000000,
    "expires_at": 1800000060,
    "signature": {}
  }
}
```

`response_hash` is SHA-256 over canonical `result` after removing only
`result.usage`; no other response field is omitted. A Responses result must
contain text `output_text`. A chat result must contain exactly one assistant
text choice and no tool calls. The Gateway verifies the proof before returning
any result, then replaces `result.usage` with the signed integer counts. Counts
must be exact JSON integers, non-negative, bounded to signed 63-bit range,
`total=input+output`, and `output<=output_token_cap`.

Streaming, tools, non-text input/content, metadata, continuations, stateful
sessions, multiple chat choices, multiple or conflicting output-cap aliases,
unknown request fields, and generic `/v1/*` proxy routes are rejected by this
first protocol version. This ensures no output byte or settlement evidence is
released before the final proof is verified. The Provider independently
reconstructs the complete sidecar request hash, verifies the exact
`p2p_request_hash`, response hash, usage bounds, trust pins and proof lifetime,
and consumes each proof once in its persistent replay store.

## Provider Deployment Gate

A testnet Provider is intentionally fail-closed. In addition to the native
metering variables above, startup requires an actual V3 deployment manifest,
an explicit pricing version and pricing hash matching that manifest, matching
chain/settlement configuration, and at least six settlement confirmations. The
CLI performs a read-only preflight at the finalized block and verifies deployed
contract code, identities, channel pricing and an on-chain quote before the
Provider listens or registers.

`MYCOMESH_PROVIDER_EXTRA_ARGS` must be exactly empty in the testnet Compose
profile; local development bypass flags are not accepted. A non-local Provider
also remains unavailable until at least one configured Bridge has accepted its
signed registration. Successful join/heartbeat responses create only a bounded
in-memory readiness lease, so an expired Bridge registration makes P2P health
and inference fail closed until the next valid heartbeat.

The Bridge may be operated in permissionless signed-Provider mode with
`--allow-any-signed-provider`. This option defaults to false and removes only
the need to pre-register each Provider Ed25519 public key. Initial permissionless
admission requires at least one signed `myco+tcp://` endpoint whose host is a
literal public IP; DNS hosts and relay-only descriptors are rejected. The flag
does not relax signed descriptor verification, the secure transport-key binding,
public direct-address verification, Provider payment-address requirements, or
the explicit reputation-signer allowlist. It also does not relax any
Provider-side native-metering, V3 manifest, finalized RPC, pricing, reservation, or payment
gate described above. The `open` mainnet profile remains disabled; this option
is an admission mode for the production testnet Bridge, not an open-mainnet
launch.

For a public Bridge behind Nginx, `--trust-proxy-headers` may be added alongside
`--allow-any-signed-provider` so per-client rate limits use `X-Real-IP`. It
defaults to false. Enable it only when the Bridge listener is reachable
exclusively from a controlled private or loopback reverse proxy and that proxy
overwrites any inbound value with exactly one `X-Real-IP` header. Leave it off
if clients can reach the Bridge port directly or through any untrusted private
network peer.

With a complete testnet Provider configuration, `make provider-up` starts the
containers, performs the signed Bridge join, and maintains the bounded
registration lease by heartbeat. No manual Provider-key onboarding is needed
when the target Bridge enabled this mode. `make provider-health` still requires
both Gateway settlement readiness and a live Bridge lease.

## Production Checklist

1. Pin the sidecar image and immutable model revision before computing the
   capability digest.
2. Mount the meter private key only into the sidecar; mount no private meter
   material into the Gateway or Provider.
3. Expose the sidecar only to the Gateway, using loopback or authenticated TLS.
4. Confirm long-output canaries stop at cap 1 and at the configured maximum.
5. Validate hidden reasoning, cached input, and tokenizer accounting semantics
   for the pinned engine revision.
6. Rotate the key by deploying a new capability digest and public-key pin as
   one controlled release; never accept both keys implicitly.
7. Keep generic `openai_http` unavailable to settlement-backed Providers.
8. Check `/ready`, not `/health`, for Gateway settlement readiness, and use a
   Provider ping that requires `bridge_ready=true` before advertising traffic.
9. Keep the V3 manifest, chain ID, settlement address, pricing version/hash and
   finalized RPC result internally consistent; use at least six confirmations.
