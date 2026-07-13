# MycoMesh Role Deploy

This guide is for different operators cloning the same git repo and starting
only their own role. It is not an all-in-one production topology.

> Security status: `local` uses plaintext `tcp://`/`relay://`; non-local
> profiles require signed `myco+tcp://`/`myco+relay(s)://` descriptors and
> end-to-end sealed inference frames. The bundled inference backends still do
> not pass the production cap-and-usage capability gate, so these commands are
> a local smoke test unless `/health` reports `settlement_ready=true`. See
> [security-audit-and-remediation.md](security-audit-and-remediation.md).

## Common Setup

```bash
git clone <mycomesh-repo>
cd <mycomesh-repo>
make deploy-env
```

Edit `.env.deploy` for the role you are running. Do not commit `.env.deploy`.
Compose publishes ports on `MYCOMESH_BIND_ADDRESS=127.0.0.1` by default. Keep
local plaintext roles on loopback and put public HTTP control planes behind an
HTTPS reverse proxy.

All roles use this repository. Gateway, Bridge, Proxy and Relay share the base
image; the login-backed Provider uses its dedicated Codex image and isolated
login, identity and workspace volumes:

```bash
make build
```

For servers, the repository publishes separate GHCR images for the shared node
roles and the login-backed Provider. Pull them and use the `*-image` Make targets
to guarantee Compose does not rebuild local source. See
[container-images.md](container-images.md) for package visibility checks,
registry login, immutable image tags, the combined main-node target, and
Provider login commands.

## Production Web Domains And Browser CORS

For `mycomesh.xyz`, use separate public hosts for the human-facing sites and
protocol services:

| Host | Purpose | Reverse-proxy upstream |
| --- | --- | --- |
| `https://mycomesh.xyz` | Project homepage and public network status | Static web deployment |
| `https://app.mycomesh.xyz` | Wallet, API-key and inference dApp | Static web deployment |
| `https://gateway.mycomesh.xyz` | Consumer Proxy and canonical API origin | `127.0.0.1:8100` |
| `https://bridge.mycomesh.xyz` | Public Bridge discovery reads | `127.0.0.1:9800` |

Set the canonical service URLs independently from browser CORS. CORS entries
are the exact origins of the calling web pages, not API URLs, and therefore do
not include `/v1` or any trailing path:

```bash
MYCOMESH_PUBLIC_GATEWAY_URL=https://gateway.mycomesh.xyz/v1
MYCOMESH_POOL_PUBLIC_URL=https://bridge.mycomesh.xyz
MYCOMESH_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
MYCOMESH_POOL_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
```

Both allowlists default to empty, which disables cross-origin browser access.
They accept only comma-separated exact origins. `*`, `null`, userinfo, paths,
queries, fragments, ambiguous numeric hosts and non-loopback HTTP origins fail
closed during startup. Add a separate explicit localhost origin only in a local
development environment, for example `http://127.0.0.1:5173`.

The Consumer Proxy permits browser `GET`, `POST` and `OPTIONS` requests with
only `Authorization` and `Content-Type` request headers; it does not enable
credentialed cookie CORS. The Bridge permits cross-origin reads only for
`GET /health` and `GET /peers` (plus their `OPTIONS` preflights), with no custom
request headers. Browser access to Bridge writes such as `/join`, `/heartbeat`,
`/leave` and `/reputation` remains unavailable. CORS is a browser boundary, not
authentication or DDoS protection; keep canonical SNI/Host enforcement, rate
limits and authentication at the reverse proxy and services.

## Bridge Operator

Bridge nodes provide provider discovery, pool registration, and public bootstrap
routing.

For a local smoke test:

```bash
MYCOMESH_NETWORK_PROFILE=local
MYCOMESH_POOL_PUBLIC_URL=http://127.0.0.1:9800
MYCOMESH_BRIDGE_EXTRA_ARGS=--skip-direct-address-verification --allow-any-reputation-signer
```

Start:

```bash
make bridge
```

Health:

```bash
curl http://127.0.0.1:9800/health
```

You can start a public testnet Bridge for signed secure provider registration.
Require allowlists:

```bash
MYCOMESH_NETWORK_PROFILE=testnet
MYCOMESH_POOL_PUBLIC_URL=https://bridge.mycomesh.xyz
MYCOMESH_POOL_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
MYCOMESH_BRIDGE_EXTRA_ARGS=--provider-public-key <provider-node-public-key> --reputation-signer-public-key <proxy-public-key>
```

Provider public keys come from Provider operators. Proxy public keys come from
Consumer Proxy operators.

## Provider Operator

Provider nodes run the local gateway, register into one or more Bridges, and
serve AI work.

### Codex login Provider in Docker

Use this path when inference must depend on a Codex login completed by the
Provider operator on this machine. The Codex CLI supports **Sign in with
ChatGPT**. In `.env.deploy`, select the login-backed backend and keep the login
secret out of environment variables:

```bash
PROVIDER_GATEWAY_BACKEND=codex_app_server
```

Log in interactively, check the persisted authentication state, and then start
the Provider:

```bash
make provider-login
make provider-auth-status
make provider-up
```

The default is a Provider-specific Docker volume. Codex authentication is stored
at `/data/codex-home`; a separate Provider data volume stores the node identity
at `/data/node-identity.json`. Neither is baked into the image or tracked by git,
and both survive container recreation. Treat both volumes as sensitive operator
state and include them in an encrypted backup plan.
Normal `make down` does not remove named volumes. Do not run
`docker compose down -v` unless you intentionally want to erase the Codex login,
Provider identity, and Provider workspace.

An advanced operator who has already logged in on the host may explicitly bind
that Codex home instead. Put the persistent choice in `.env.deploy`:

```dotenv
MYCOMESH_CODEX_HOME_SOURCE=/absolute/path/.codex
```

Then run:

```bash
make provider-auth-status
make provider-up
```

This override is only appropriate when the host login and Provider belong to
the same trusted user. Do not mount another user's credentials. Keep the mount
writable so token refresh can update the login state; a read-only mount may
cause delayed authentication failures. Do not run the host CLI and several
Provider processes concurrently against the same Codex home. The container
currently runs as root, so this writable bind can change ownership of host files
and gives the container full control over the login. Prefer the dedicated
Docker volume created by `make provider-login`.

The combined Provider process starts an internal AI Gateway on container port
`8000`, but Compose does not publish that port. Peers reach the Provider protocol
on `9700` directly, or through a configured relay when direct inbound access is
not available. Do not reverse-proxy or expose the internal `8000` endpoint.

For a Provider that should only make an outbound connection to a Relay, set:

```bash
MYCOMESH_PROVIDER_TRANSPORT=relay
MYCOMESH_PROVIDER_RELAY_HOST=relay.mycomesh.xyz
MYCOMESH_PROVIDER_RELAY_PORT=9901
MYCOMESH_PROVIDER_RELAY_PUBLIC_URL=https://relay.mycomesh.xyz
```

In relay mode, the Provider does not need a publicly reachable `9700`; the Relay
provider port must be reachable from the Provider machine. The public Relay
control URL still terminates TLS and is the URL advertised to consumers. The
Relay's `MYCOMESH_RELAY_ADVERTISE_HOST` must exactly match the Provider's
`MYCOMESH_PROVIDER_RELAY_HOST`; registration signatures bind that DNS name and
the Relay's `MYCOMESH_RELAY_ADVERTISE_PROVIDER_PORT`.

After the interactive login is available, set
`MYCOMESH_PROVIDER_TRANSPORT=direct` and verify the complete local path:

```bash
make provider-auth-status
make provider-up

docker compose --env-file .env.deploy --profile provider exec provider \
  python -m gateway p2p ping 127.0.0.1:9700
docker compose --env-file .env.deploy --profile provider exec provider \
  python -m gateway p2p infer 127.0.0.1:9700 "Only reply OK"

# Run separately when you want to follow logs:
make logs SERVICE=provider
```

Run this first with `MYCOMESH_NETWORK_PROFILE=local`. A successful response
confirms the Docker Provider can use the persisted Codex login for inference.
It does not satisfy production metering and settlement requirements. The current
Codex backend still reports `settlement_ready=false`, so the `testnet` Provider
remains blocked by the settlement capability gate.

### API key Provider

Set the upstream backend:

```bash
PROVIDER_GATEWAY_BACKEND=openai_http
UPSTREAM_BASE_URL=https://api.openai.com/v1
UPSTREAM_API_KEY=sk-...
UPSTREAM_TIMEOUT_SECONDS=180
UPSTREAM_MAX_RESPONSE_BYTES=33554432
UPSTREAM_MAX_STREAM_BYTES=33554432
AGENT_KEYS=coder=<strong-local-provider-key>
PUBLIC_MODEL_ID=gpt-5.5
```

Generate the Provider node public key for Bridge allowlists:

```bash
make provider-identity
```

For local smoke testing:

```bash
MYCOMESH_NETWORK_PROFILE=local
MYCOMESH_PROVIDER_POOL_URL=http://bridge:9800
MYCOMESH_PROVIDER_ADVERTISE_HOST=provider
MYCOMESH_PROVIDER_EXTRA_ARGS=--allow-any-signed-consumer --allow-unreserved-requests
```

`MYCOMESH_NETWORK_PROFILE=testnet` enables sealed provider transport, but startup
also requires the local AI Gateway health response to report
`settlement_ready=true`. The current Codex bridges and generic unpinned
OpenAI-compatible backend deliberately fail that gate. This prevents encrypted
transport from being mistaken for trustworthy token settlement.

Start:

```bash
make provider-up
```

Provider logs should eventually show `pool_status: joined`.

## Consumer Proxy Operator

Consumer Proxy nodes expose the OpenAI-compatible URL+key interface to users.
Consumers do not need to run local clients.

Set:

```bash
MYCOMESH_ADMIN_TOKEN=<at-least-32-character-random-secret>
MYCOMESH_BILLING_MODE=local
MYCOMESH_POOL_URL=http://bridge:9800
MYCOMESH_MAX_REQUEST_BYTES=1048576
```

Non-local profiles reject the example placeholder and administrator secrets
shorter than 32 characters.

Generate the proxy request public key for Provider/Bridge allowlists:

```bash
make proxy-identity
```

Start:

```bash
make proxy
```

Local API base URL:

```text
http://127.0.0.1:8100/v1
```

Create a local test account:

```bash
docker compose --env-file .env.deploy --profile proxy exec proxy \
  mycomesh proxy account create \
  --payment-address 0x0000000000000000000000000000000000000001
```

Credit local test balance:

```bash
docker compose --env-file .env.deploy --profile proxy exec proxy \
  mycomesh proxy account deposit <account_id> --amount-usdc 10
```

Call the proxy:

```bash
curl http://127.0.0.1:8100/v1/chat/completions \
  -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mycomesh-codex-standard-v1",
    "messages": [{"role": "user", "content": "Only reply OK"}]
  }'
```

The exact stable API base URL is mandatory in every profile; the local Docker
template uses `http://127.0.0.1:8100/v1`. For a public URL+key proxy, terminate
TLS at a reverse proxy. Outside `local`, HTTPS and a public DNS hostname are
mandatory; HTTP is accepted only for localhost in the local profile.

```bash
MYCOMESH_NETWORK_PROFILE=testnet
MYCOMESH_NETWORK_ID=mycomesh-testnet
MYCOMESH_PUBLIC_GATEWAY_URL=https://gateway.mycomesh.xyz/v1
MYCOMESH_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
ETH_CHAIN_ID=11155111
MYCO_SETTLEMENT=<settlement-address-for-this-network>
MYCOMESH_PUBLIC_KEY_REGISTRATION=false
MYCOMESH_KEY_CHALLENGE_CAPACITY=1024
MYCOMESH_KEY_CHALLENGE_RATE_PER_MINUTE=120
MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY=4
MYCOMESH_KEY_REGISTRATION_RPC_TIMEOUT=20
MYCOMESH_KEY_REGISTRATION_MAX_ATTEMPTS=5
```

Keep public wallet registration disabled until rate limiting and operational
monitoring are in place, then explicitly set
`MYCOMESH_PUBLIC_KEY_REGISTRATION=true`. The challenge signature binds the key
hash to the configured origin, network, chain, settlement, nonce and expiry.
The stored credential keeps that scope, and every authenticated request checks
it plus the canonical request `Host`.
Consequently an API key registered at `https://gateway.mycomesh.xyz` is valid
only in that Gateway's credential store; it cannot be reused automatically at
another discovered URL. Register a distinct key at each failover origin.
The direct account create/rotate CLI uses the same four environment values and
persists the same scope; missing URL/network/chain/settlement configuration fails
closed instead of issuing a portable key.

The capacity and rate variables above apply per shared billing database;
independent databases each receive the full allowance. Configure per-source
limits for both registration endpoints at the reverse proxy before
enabling them publicly. Set a trusted `ETH_RPC_URL` to support EIP-1271 contract
wallet registration; without it registration can verify EOAs only. Registration
RPC uses an independent bounded executor and a single absolute deadline; its
concurrency bound is per process. Only requests that obtain an executor slot take
a transactional verification lease and consume a configured attempt. Executor submission
failure rolls back that token-bound attempt; submitted failures/timeouts count,
and another process cannot take over the same unexpired challenge. The worker
releases its claim on exit; after a process crash, issue a new challenge instead
of taking over the old one. Challenge expiry is rechecked
under the final write lock. Challenge consumption and key registration commit
atomically. Replicas for one origin must
share the same PostgreSQL `MYCOMESH_BILLING_DB` DSN. Independent SQLite files do
not coordinate these claims; SQLite is for single-host operation.

The reverse proxy must accept only the configured SNI/Host and preserve that
Host upstream. Verify `recommended_gateway.descriptor` from discovery and use
its signed `public_url`; do not trust `recommended_base_url` on its own. Pin the
expected node key, network, chain and settlement from the deployment manifest.

The canonical URL must not contain credentials, query parameters or fragments,
and must never be inferred from an untrusted `Host` header or provider-supplied
callback. Wallet-based key registration uses:

```text
GET  /.well-known/mycomesh.json
POST /v1/mycomesh/keys/challenge
POST /v1/mycomesh/keys/register
POST /v1/mycomesh/keys/rotate
```

`GET /.well-known/mycomesh.json` returns the local canonical URL plus registered
node descriptors for the same `network_id`, `chain_id`, and `settlement`. Outside local mode,
descriptor registration requires the admin token and a node Ed25519 signature.
Descriptors also carry a monotonic sequence and a 30-3600 second expiry. A
client must verify the descriptor signature, recompute `node_id` from the public
key, check the network/chain/settlement/expiry/sequence, and pin the expected node key
before connecting. Discovery metadata such as self-reported weight, capacity or
latency is not a trust signal.

The proxy enforces `MYCOMESH_MAX_REQUEST_BYTES` before route dispatch, including
requests without `Content-Length`; the managed AI gateway separately enforces
`GATEWAY_MAX_REQUEST_BYTES`. Inline PDF extraction is disabled in the Codex
gateway and rejected by providers. Extract a document in a memory/CPU/time-
bounded sandbox and submit the exact result as `input_text`, so the committed
request bytes and the text actually sent upstream cannot diverge.

`UPSTREAM_MAX_RESPONSE_BYTES` and `UPSTREAM_MAX_STREAM_BYTES` cap decoded model
responses, including compressed responses. The Codex stdout/stderr/event limits
protect local resources but do not make Codex CLI usage trustworthy for billing.
Do not use `codex_cli` or `codex_app_server` for production token settlement until
the selected backend both enforces the signed output cap during generation and
returns verifiable native token usage.

Keep `MYCOMESH_INFERENCE_CONCURRENCY` at a capacity the host can sustain (default
8, hard maximum 64) and `MYCOMESH_TIMEOUT_SECONDS` within 300 seconds. ASGI request
concurrency, request-body deadlines, Codex process permits and Uvicorn incomplete-
header buffers are also bounded by the template. These do not provide a request-
header deadline before ASGI dispatch, so a public endpoint must use a reverse
proxy with canonical SNI/Host enforcement, connection limits and a total header-
read timeout.

## Relay Operator

Relay nodes help Providers behind NAT. `local` uses plaintext `relay://`.
Non-local providers use end-to-end sealed `myco+relay(s)://`; terminate the
public control endpoint with TLS so descriptors use `myco+relays://`.

Local smoke test:

```bash
MYCOMESH_RELAY_ADVERTISE_HOST=relay
MYCOMESH_RELAY_EXTRA_ARGS=--allow-any-signed-consumer
```

For a public Relay, set `MYCOMESH_RELAY_ADVERTISE_HOST` to the exact DNS name
used by Providers. Set `MYCOMESH_RELAY_ADVERTISE_CONTROL_PORT` and
`MYCOMESH_RELAY_ADVERTISE_PROVIDER_PORT` to the externally reachable ports.
These are independent from the container listeners, so a TLS reverse proxy on
`443 -> 9900` or a raw TCP mapping such as `19901 -> 9901` can be represented
correctly; Providers connect to the corresponding public provider port.

On the Relay host, expose only the raw Provider listener directly. Keep the
control listener on loopback for the HTTPS reverse proxy:

```bash
MYCOMESH_BIND_ADDRESS=127.0.0.1
MYCOMESH_RELAY_PROVIDER_BIND_ADDRESS=0.0.0.0
MYCOMESH_RELAY_ADVERTISE_HOST=relay.mycomesh.xyz
MYCOMESH_RELAY_ADVERTISE_CONTROL_PORT=443
MYCOMESH_RELAY_ADVERTISE_PROVIDER_PORT=9901
```

The relay cannot decrypt sealed prompts/results, but it sees routing metadata.
Public operation still requires a consumer allowlist, shared persistent replay
storage, connection/rate limits and an external security review.

Start:

```bash
make relay
```

## Local Demo Only

To run Bridge, Provider, and Proxy on one machine for a private smoke test:

```bash
make demo
```

This is useful before public deployment, but it is not the target operator
topology.

## Local V3 Settlement Test

Create `deployments/sepolia-myco-v3.json` with the V3 deploy command before
building the image, then rebuild so Docker contains the pinned record. Configure
the provider with one internally consistent deployment:

```bash
MYCOMESH_NETWORK_PROFILE=local
MYCOMESH_SETTLEMENT_VERSION=3
MYCOMESH_PRICING_VERSION=1
MYCO_DEPLOYMENT=/app/deployments/sepolia-myco-v3.json
MYCO_SETTLEMENT=<v3-settlement>
MYCOMESH_SETTLEMENT_RPC_URL=<sepolia-rpc-url>
MYCOMESH_SETTLEMENT_CONTRACT=<same-v3-settlement>
MYCOMESH_SETTLEMENT_CHAIN_ID=11155111
MYCOMESH_SETTLEMENT_CONFIRMATIONS=6
MYCOMESH_PROVIDER_EXTRA_ARGS=--consumer-public-key <proxy-public-key> --payment-address <provider-address> --pricing-hash <v3-version-1-pricing-hash>
```

Do not include `--allow-unreserved-requests` in a V3 settlement test. The
provider reads `channelPricingHash`, `quote` and the request-bound reservation at
one confirmed block before calling its local AI gateway. Create the reservation
with exactly one of `v3-create-reservation --input <exact-scalar-input>` or
`--request-hash <request-v2-sha256>`. When using `--input`, explicitly pin the
same endpoint, model and output cap as the inference request, for example:

```bash
python -m gateway chain v3-create-reservation \
  --deployment deployments/sepolia-myco-v3.json \
  --private-key "$CONSUMER_PRIVATE_KEY" \
  --provider <provider-payment-address> \
  --input "Summarize this document" \
  --endpoint responses \
  --model gpt-5.5 \
  --max-output-tokens 2000 \
  --amount-usdc 1 \
  --expires-at <unix-timestamp>
```

The matching local EOA inference is:

```bash
python -m gateway p2p infer <provider-host:port> "Summarize this document" \
  --endpoint responses \
  --model gpt-5.5 \
  --max-output-tokens 2000 \
  --settlement-version 3 \
  --pricing-version 1 \
  --settlement-chain-id 11155111 \
  --settlement-contract <v3-settlement> \
  --onchain-reservation-id <returned-reservation-id> \
  --reservation-expires-at <same-unix-timestamp> \
  --settlement-deadline <deadline-with-inclusion-buffer> \
  --consumer-payment-address <consumer-address> \
  --provider-peer-id <provider-peer-id> \
  --provider-payment-address <provider-payment-address> \
  --pricing-hash <version-1-pricing-hash> \
  --max-fee-usdc 1 \
  --consumer-wallet-private-key "$CONSUMER_PRIVATE_KEY"
```

The V3 inference must carry the returned reservation ID and the same chain,
settlement, provider, pricing, expiry and payment bindings. The
v2 request commitment hashes a compact, sorted-key UTF-8 JSON envelope containing
`request_hash_version`, endpoint, model, canonical `input` or `messages`, and
`max_output_tokens`. Chat must hash the original structured `messages` array, not
a stringified or reconstructed copy. A legacy hash of only `input` is not
compatible and its V3 reservation must be recreated. The request model must also
equal the provider's configured and signed-descriptor model.

Before upstream execution, the provider rejects canonical input JSON whose
UTF-8 byte length exceeds `reserve_input_tokens`. This is only an admission-size
check. Fee authorization uses the provider's full `reserve_input_tokens` budget,
which must be configured to cover agent/system/routing context injected by the
complete upstream pipeline. The provider resolves a missing output cap to
`reserve_output_tokens`, rejects a larger explicit cap, and quotes the full input
budget plus resolved output cap against the payment reservation and confirmed
V3 state. `max_output_tokens`, `max_completion_tokens`, and `max_tokens` must be
native positive integers and, when combined, must be equal or the HTTP request
returns `422`. The
settlement deadline must allow the provider timeout plus 60 seconds for
transaction inclusion and cannot exceed reservation expiry. A mismatch or an
insufficient bound is rejected before the local AI gateway is called.

The local wallet flag creates a one-reservation
`mycomesh.evm.session.v1` EIP-191 authorization that binds the EVM consumer to
the CLI's Ed25519 session key and all request/payment fields. For an external
EOA or EIP-1271 wallet, replace it with `--prepare-session-authorization`, sign
the printed canonical message, then rerun with
`--session-authorization-signature` plus the printed
`--session-authorization-nonce`; a complete signed JSON object is accepted by
`--evm-session-authorization @authorization.json`.

After capacity and every validation pass, the provider atomically consumes the
request ID, payment nonce, reservation ID and session nonce in its persistent
replay store, then begins upstream execution. Capacity rejection does not consume them;
uncertain failure after execution starts is non-retryable under the at-most-once
policy. Provider replicas need one shared transactional replay store. Configure
the same PostgreSQL `MYCOMESH_REPLAY_DB` DSN across replicas; separate SQLite
files cannot enforce a global claim.

The built-in servers limit concurrent connection threads and impose an absolute
deadline while reading unauthenticated requests. Keep an external reverse proxy,
connection-rate limit and DDoS service in front of any HTTP control plane.

Provider fallback remains off unless the consumer adds
`--allow-provider-fallback` to both reservation creation and the matching
inference. Opt-in authorizes only a non-refundable `minimumFee` claim with zero
`acceptedHash`; it is not proof that useful or correct service was delivered.
This remains a local/private transport test, not a public V3 network. Rewards
are globally disabled by default and must remain disabled until an anti-Sybil
quality signal has been reviewed. The chain transactions, final ABI and
fallback commands are documented in
[settlement-v3-cli-integration.md](settlement-v3-cli-integration.md).

## Useful Commands

```bash
make logs SERVICE=bridge
make logs SERVICE=provider
make logs SERVICE=proxy
make ps
make down
```

Install the CLI directly without Docker:

```bash
python -m pip install -e .
mycomesh --help
mycomesh bridge serve --network-profile local
```

## Legacy Sepolia V2 Deployment

This record is retained for compatibility and migration testing. It is not a
production endorsement. The deployed `test_usdc` is test-only, and V2 balances,
allowances and receipts are not automatically migrated to V3.

```text
chain_id: 11155111
settlement: 0x780e8daa596981c055148633849a6dd90a0f8d15
myco_token: 0x27ce5e8e3811a2664cb66cd1d7aea93f79dff1df
test_usdc: 0x860ccadc1e1926b718cfe4ec24fefa42095c6f68
channel: codex-standard-v1
channel_hash: 0xdedf8b58276b80863f354409c963cbaddf4ca7d5b866d528ff1386d74b339104
```

For V3, stop new V2 work, settle or expire outstanding receipts, withdraw the
available V2 balance, revoke the V2 stablecoin allowance, then approve/deposit
into V3 and create new provider- and request-specific reservations. The final
V3 ABI is also incompatible with earlier V3 deployments: deploy a fresh final
V3 instance and recreate every reservation, including any reservation that used
the legacy input-only request hash. The V3 deployer's unrestricted-mint
`TestUSDC` must never be used in production; a production V3 stablecoin must be
standard, non-rebasing and free of transfer fees because exact balance deltas
are enforced. See
[settlement-v3-cli-integration.md](settlement-v3-cli-integration.md) for the
transaction fields and the security audit for the remaining rollout gates.
