# Provider Runtime, API Compatibility, and Client Delivery

This document fixes the role boundaries for the MycoMesh deployment. It also
defines what “Sub2API-compatible” means in this repository: MycoMesh keeps its
own accounts, API keys, routing, settlement, and receipts while exposing the
OpenAI-compatible request and event shapes clients already use. No Sub2API
account, billing, scheduler, admin, or credential-import code is embedded.

## Deployment Decision

| Role | Delivery | Runs continuously | Holds credentials |
| --- | --- | --- | --- |
| Browser or ordinary API consumer | Browser, OpenAI SDK, or npm CLI | No | MycoMesh API key only |
| Optional local Direct Consumer | Docker, bound to localhost | Optional | Consumer wallet/identity |
| Public Consumer Proxy | Docker | Yes | MycoMesh account and service keys |
| Public Node | Docker: separate Bridge and Relay containers | Yes | Node identities; never Codex auth |
| Provider ingress | Docker | Yes | Provider node identity, payout key, settlement state |
| Provider Codex sidecar | Docker, private Compose network | Yes | Isolated Codex OAuth state |
| Operator commands | `make`/CLI | No | Used only for login, status, backup, and upgrade |

Docker is required for public daemons because it gives reproducible process,
filesystem, network, restart, and resource boundaries. It is not an
anti-tamper boundary. The npm CLI is the low-friction consumer interface; it is
not used to hide Provider logic or to run a production Relay.

## Control and Data Planes

```text
control: Provider -> Bridge (signed registration, heartbeat, capability)
control: Consumer -> Bridge (discovery)

data:    Consumer -> Provider
data:    Consumer -> Relay -> Provider
```

Bridge and Relay are one public-node operator role but remain separate logical
services and containers. Bridge never carries inference payloads. Relay forwards
bounded, replay-protected sealed frames and never parses prompts, OAuth tokens,
OpenAI payloads, usage, or billing data. Running an API on a Relay host means
running a separate Provider; it does not change the Relay role.

## Provider Split

The Compose `provider` profile starts two long-running containers:

- `provider` is the P2P ingress. It owns the Ed25519 node identity, EVM payout
  identity, replay state, Bridge lease, Relay/direct transport, and settlement.
- `provider-sidecar` is the private OpenAI-compatible execution service. It owns
  `CODEX_HOME`, launches the official Codex App Server, and has no published
  host port.

Their only shared filesystem data is `/agent/agents.json`, a random internal
bearer credential mounted read-only by both. They communicate over the private
`provider-net` network. The ingress does not mount the Codex or workspace
volumes, and the sidecar does not mount the Provider identity volume.
The sidecar URL is accepted over HTTP only through the explicit
`--allow-private-gateway-http` option and only when every resolved address is
loopback, RFC1918, or IPv6 ULA. Private DNS hosts must be single-label container
service names; public/FQDN remote Gateways still require HTTPS.

The official Codex App Server remains the execution core because it supplies
the supported login and structured runtime protocol. The compatibility adapter
sits around it; it does not replace Codex authentication. See the
[official Codex App Server documentation](https://developers.openai.com/codex/app-server).

### Volumes

| Volume | Mounted by |
| --- | --- |
| `mycomesh-provider-data` | Provider ingress only |
| `mycomesh-provider-codex-data` | Codex sidecar only |
| `mycomesh-provider-agent-data` | Both long-running containers, read-only |
| `mycomesh-provider-workspace` | Codex sidecar only; read-only at runtime |

Existing installations keep the payout and node identities in
`mycomesh-provider-data`. Codex auth formerly stored in that volume is not
automatically copied into the new credential volume. After upgrading, run
`make provider-login` once to establish auth in the new sidecar volume. Do not
delete the old Provider data volume: it contains the payout identity.

## API Compatibility Boundary

MycoMesh account credentials remain authoritative at the public Consumer Proxy.
Clients use a MycoMesh key with these stable routes:

- `GET /v1/models`
- `POST /v1/responses`
- `POST /v1/chat/completions`

The adapter preserves OpenAI-style success and error envelopes and accepts the
Responses and Chat request shapes supported by the selected Provider
capability. The current paid P2P policy is deliberately narrower than a full
Sub2API deployment: native streaming and tools are not advertised for the
testnet settlement channel. A request with `stream: true` is returned as
buffered SSE and carries `x-mycomesh-streaming-mode: buffered`; clients must not
treat that as token-live streaming. Non-empty `tools`/`tool_choice` requests are
rejected explicitly instead of being silently discarded.

Compatibility work is clean-room. Sub2API is useful as a behavioral reference
for endpoint conversion, SSE lifecycle, cancellation, bounded queues, and OAuth
refresh handling, but its LGPL implementation and its Postgres/Redis account
pool are not copied into this runtime.

The Provider accepts only the official interactive Codex login stored in its
isolated volume. It does not import `sub2api-data` JSON, `access_token`,
`refresh_token`, or `id_token` fields. Such exports are live secrets, not account
configuration. If one is exposed, revoke/rotate it rather than converting it
into a MycoMesh account.

## Signed Capabilities and Trust

Each non-local Provider signs its complete Bridge descriptor, including:

- `backend_capability`: adapter schema, backend kind, protocol/endpoints, and
  conservative feature flags;
- `trust_evidence`: the evidence mode and claims actually available;
- settlement, metering, transport key, capacity, model, and channel binding.

Bridge registration and Consumer discovery re-verify the descriptor signature.
Public testnet Bridges reject registrations without valid backend/trust
metadata. Before selecting a paid V3 or V4 route, the Consumer Proxy checks the
requested endpoint and requires the configured backend kind and minimum trust
level (`codex_oauth_sidecar` and `self_attested` by default). A Provider cannot
promote itself by adding a `trust_level` string. The initial Codex sidecar mode
is `self_attested`: the identity signature makes false claims accountable to a
stable Provider key, but does not prove that the advertised container image ran
or that a response came from OpenAI.

The packaged public node and Provider both default to the committed V4
deployment, so their signed settlement capabilities match at registration.
Operators can deliberately select the committed V3 deployment for a legacy
fleet, but a single Bridge never mixes Provider settlement capabilities.

This distinction is intentional:

| Property | Current guarantee |
| --- | --- |
| Request/response confidentiality through Relay | End-to-end sealed transport |
| Descriptor integrity and Provider identity | Ed25519 signature |
| Settlement fields and response binding | Signed request, receipt, and attestation |
| Direct OAuth-file access from ingress compromise | Blocked by separate volumes/processes/network exposure |
| Protection from the Provider host owner/root | Not provided |
| Proof of unmodified runtime or upstream execution | Not provided; requires verified TEE/remote attestation or upstream-signed evidence |

Docker images, minified npm bundles, and compiled binaries can all be patched by
the machine owner. They raise operational friction but cannot make a client or
Provider “uncrackable.” For unattended per-token settlement, use only a future
capability level whose attestation verifier and policy are implemented and
pinned by the Consumer. Until then, signed usage is Provider-accountable rather
than independently proven.

The volume boundary protects the OAuth files themselves. It does not make the
ingress harmless: a compromised ingress can still use its internal bearer key
to invoke the sidecar and consume the logged-in account's quota. Protect the
Provider host, rotate the internal key by recreating its role-scoped volume
after an incident, and treat host/root compromise as full Provider compromise.

## Consumer npm CLI

The npm CLI is a stateless API client. It reads `MYCOMESH_BASE_URL` and
`MYCOMESH_API_KEY`, supports health/models/Responses/Chat requests, accepts JSON
from a flag or stdin, and writes JSON or SSE to stdout. It does not contain Codex
OAuth state and does not run Bridge, Relay, Provider, account storage, or a
background daemon.

Use the browser or standard OpenAI SDK directly when a dedicated CLI adds no
value. Use the local Consumer Docker profile only for the wallet-backed Direct
Consumer workflow. Public Proxy, Public Node, and Provider remain Docker roles.
