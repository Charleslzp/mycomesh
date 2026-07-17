# MycoMesh Role Deploy

This guide is for different operators cloning the same git repo and starting
only their own role. It is not an all-in-one production topology.

> Security status: `local` uses plaintext `tcp://`/`relay://`; non-local
> profiles require signed `myco+tcp://`/`myco+relay(s)://` descriptors and
> end-to-end sealed inference frames. The Codex app-server policy is accepted
> only on Sepolia testnet and validates native usage after execution; it does
> not provide a generation-time output cap. The `open` profile remains disabled.
> A Provider is usable only when `/ready` reports `settlement_ready=true`. See
> [security-audit-and-remediation.md](security-audit-and-remediation.md).

## Common Setup

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
make deploy-env
```

Edit `.env.deploy` for the role you are running. Do not commit `.env.deploy`.
Compose publishes ports on `MYCOMESH_BIND_ADDRESS=127.0.0.1` by default. Keep
local plaintext roles on loopback and put public HTTP control planes behind an
HTTPS reverse proxy.

Every role uses the same immutable image, but production state is isolated in
role-specific named volumes. Application processes run as the image's fixed
UID 10001; one-shot volume init services migrate existing root-owned files
before startup. The standalone development Gateway is the only service that
explicitly runs as root for bind-mounted workspace compatibility.

```bash
make build
```

## Production Web Domains And Browser CORS

For `mycomesh.xyz`, use separate public hosts for the human-facing sites and
protocol services:

| Host | Purpose | Reverse-proxy upstream |
| --- | --- | --- |
| `https://mycomesh.xyz` | Project homepage and public network status | Static web deployment |
| `https://app.mycomesh.xyz` | Wallet, API-key and inference dApp | Static web deployment |
| `https://gateway.mycomesh.xyz` | Consumer Proxy and canonical API origin | `127.0.0.1:8100` |
| `https://bridge.mycomesh.xyz` | Public Bridge discovery and registration | `127.0.0.1:9800` |
| `https://bridge.mycomesh.xyz/infer/*` | Relay Consumer control endpoint | `127.0.0.1:9900` |

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
closed during startup. The canonical public-node target additionally allows
`http://127.0.0.1:8110` and `http://localhost:8110` for the packaged local
Consumer Web app. Other localhost origins belong only in explicit development
configuration.

The Consumer Proxy permits browser `GET`, `POST` and `OPTIONS` requests with
only `Authorization` and `Content-Type` request headers; it does not enable
credentialed cookie CORS. The Bridge permits cross-origin reads only for
`GET /health` and `GET /peers` (plus their `OPTIONS` preflights), with no custom
request headers. Browser access to Bridge writes such as `/join`, `/heartbeat`,
`/leave` and `/reputation` remains unavailable. CORS is a browser boundary, not
authentication or DDoS protection; keep canonical SNI/Host enforcement, rate
limits and authentication at the reverse proxy and services.

## Public Bridge And Relay Node

A host with a public IP can run the Bridge discovery service and the Relay for
Providers behind NAT as one production-style testnet role. The Make target pins
the testnet profile, bundled V3 manifest, canonical mycomesh.xyz origins,
permissionless signed-Provider admission and safe host bindings. Configure only
the V3 RPC plus any optional compatibility or reputation identity in the ignored
`.env.deploy` file:

```bash
MYCOMESH_RELAY_V3_ADMISSION_RPC_URL=<sepolia-rpc-url>
MYCOMESH_BRIDGE_REPUTATION_SIGNER_PUBLIC_KEYS=<proxy-ed25519-public-key>
MYCOMESH_RELAY_CONSUMER_PUBLIC_KEYS=<proxy-ed25519-public-key>
```

The reputation signer authorizes Bridge reputation updates and is required by
the testnet Bridge preflight; the Make target supplies the canonical compatibility
identity unless it is overridden. The Relay Consumer key is optional and
preserves pinned Gateway/V2 access. Browser V3 Consumers do not depend on either
value for Relay admission; the Relay verifies their wallet-bound session and
confirmed Reservation through the configured read-only RPC. These are public
Ed25519 keys, not private keys. Bridge has no database credential, and Relay
stores replay claims in its own `/data/relay-replay.sqlite3` volume; neither role
receives Proxy PostgreSQL, administrator, or upstream secrets. The image bundles
the verified `deployments/sepolia-myco-v3.json` record; startup fails when it is
absent or invalid.

Start both services, wait for health, then inspect them:

```bash
make public-node-up
make public-node-health
make public-node-logs
```

Stop the role without deleting its volumes with `make public-node-down`.
Bridge reputation and Relay replay state use separate persistent volumes. Live
Provider registrations and Relay TCP sessions are intentionally ephemeral and
reconnect after restart.

Install `deploy/nginx-mycomesh.conf` on the same host and issue one certificate
covering `mycomesh.xyz`, `app.mycomesh.xyz`, `gateway.mycomesh.xyz` and
`bridge.mycomesh.xyz`. Public DNS for the Bridge name must point at this host. Allow inbound TCP 80/443 and 9901; do not expose container control ports
9800, 9900 or the loopback Relay backend on 19901. Nginx routes
`https://bridge.mycomesh.xyz/infer/*` to Relay control, all other Bridge paths
to discovery, and terminates CA-verifiable TLS on Provider port 9901. On
Ubuntu, install the stream module and use the ordered install target:

```bash
sudo apt-get install nginx libnginx-mod-stream
make nginx-install
```

The target installs HTTP snippets first, then the top-level stream configuration,
then the site; it runs `nginx -t` before reloading. Do not copy only the site
file because its snippet includes and stream TLS listener are required.

The strict public-node target accepts only `testnet`, rejects development
allow flags, requires a canonical HTTPS origin and explicit signer allowlists,
and verifies that HTTP control and the raw Relay Provider backend remain on
loopback; only Nginx 443/9901 are public. Bridge and Relay are currently identified by their canonical
HTTPS origins rather than a signed node descriptor; do not present an unused
local key as a protocol identity.

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

For a permissionless signed-Provider Bridge behind the repository Nginx proxy,
use `--allow-any-signed-provider --trust-proxy-headers` together with the
required reputation-signer key. The Bridge listener must be reachable only from
that controlled proxy, and the proxy must overwrite inbound values with exactly
one `X-Real-IP` header. `/observed-ip` then returns that global IPv4 without
CORS or caching; Provider auto-discovery still requires the canonical HTTPS
Bridge origin. Leave proxy-header trust disabled when clients connect directly
to the Bridge listener.

## Provider Operator

Provider nodes run the local gateway, register into one or more Bridges, and
serve AI work.

For a local API-backed smoke test, set an OpenAI-compatible upstream:

```bash
GATEWAY_BACKEND=openai_http
UPSTREAM_BASE_URL=https://api.openai.com/v1
UPSTREAM_API_KEY=sk-...
UPSTREAM_TIMEOUT_SECONDS=180
UPSTREAM_MAX_RESPONSE_BYTES=33554432
UPSTREAM_MAX_STREAM_BYTES=33554432
AGENT_KEYS=coder=<strong-local-provider-key>
PUBLIC_MODEL_ID=gpt-5.5
```

For the Dockerized Codex client plus the repository Gateway reverse proxy, no
OpenAI API key is used. The `provider-*` Make targets apply the production
profile from `deployments/sepolia-provider-network.json`; operators do not copy
Bridge, Relay, Consumer key, payout address, RPC or V3 contract values into an
environment file. The network file contains only public discovery data and
references `deployments/sepolia-myco-v3.json`. The Provider's private
secp256k1 payout/signing key is generated locally in its Docker volume and is
never emitted to logs.

The image bundles `deployments/sepolia-myco-v3.json` and uses it as the canonical
source for the public Settlement address, chain ID, channel, pricing version and
pricing hash. `MYCO_SETTLEMENT`, `MYCOMESH_SETTLEMENT_CONTRACT`,
`MYCOMESH_SETTLEMENT_CHAIN_ID`, `MYCOMESH_PRICING_VERSION` and
`MYCOMESH_PROVIDER_PRICING_HASH` are optional consistency pins, not duplicate
required configuration. Any supplied pin must match the manifest.

The repository bundles the verified public Sepolia record at
`deployments/sepolia-myco-v3.json`. Its public chain addresses belong in Git.
Never commit private keys, Codex auth, access tokens, RPC credentials or
database passwords. Testnet startup rejects a custom
`CODEX_PROVIDER_BASE_URL`; leave it empty so ChatGPT credentials cannot be sent
to another origin. The Provider container forces a read-only Codex sandbox,
one Codex process, disabled shell/plugins/browser/MCP tools, and a minimal Codex
subprocess environment.

Establish the isolated ChatGPT login once, then start and verify the node:

```bash
make provider-login
make provider-up
make provider-health
```

`provider-login` prints the official device-auth URL and code. Its auth files
remain in `mycomesh-provider-data`; the host `~/.codex` directory is not mounted.
After login, the container creates its signed node identity, joins the Bridge,
creates an independent EVM payout/signing identity and renews its Bridge lease
automatically. The published network defaults to an outbound Relay connection,
so a Provider behind NAT or CGNAT needs no inbound firewall rule. A Bridge
reporting `any_signed` Provider admission needs no manual Provider key
allowlist. Mismatched public route, Consumer-key, deployment or payout
overrides fail closed.

`make provider-up` automatically loads the public Bridge, Relay, Consumer key,
Sepolia RPC, V3 contracts, channel, pricing, public model and request limits from
the committed Provider network manifest. Do not add an OpenAI API key, Provider
allowlist entry or public IP for the default Relay flow. After the one-time
device login, subsequent restarts use the isolated login state in the Provider
volume and rejoin the published Bridge automatically.

A publicly reachable Provider can opt into direct transport:

```bash
make provider-up PROVIDER_TRANSPORT=direct PROVIDER_BIND_ADDRESS=0.0.0.0
```

Direct mode uses `MYCOMESH_PROVIDER_ADVERTISE_HOST=auto` to request
`/observed-ip` from every configured Bridge. Startup fails if the Bridges
disagree, and the Bridge callback must verify a fresh proof from the same
Provider identity before admission.

The container listens on `9700`. If Docker publishes another host port, set both
the published and advertised values, then open that port in the firewall:

```bash
MYCOMESH_PROVIDER_PORT=19700
MYCOMESH_PROVIDER_ADVERTISE_PORT=19700
```

If an upstream router maps a different public port, advertise that public-facing
port. For asymmetric NAT, set `MYCOMESH_PROVIDER_ADVERTISE_HOST` to the literal
inbound public IPv4 instead of `auto`. For CGNAT or any host with no inbound port
mapping, direct transport cannot work; deploy Relay transport instead.

Inspect the Provider Ed25519 node public key and EVM payout address when
needed (the EVM private key is never printed):

```bash
make provider-identity
```

### Provider Payout Identity Recovery

The Compose logical volume `mycomesh-provider-data` stores the Provider payout
signer at `/data/provider-evm-identity.json`. Losing this file creates a new
payout address on the next startup and can make funds or unsettled receipts tied
to the old address unrecoverable. Treat it as a production wallet key, separate
from the replaceable Ed25519 node identity and ChatGPT login.

Before accepting paid work, stop the Provider and copy that file directly into
an approved encrypted backup system (for example, envelope encryption backed by
the organization's KMS or an offline recipient key). Keep at least two tested,
offline copies under separate custody. The backup must be encrypted before it
leaves the host; never print it, paste it into a shell argument, attach it to a
ticket, or commit it to Git. Do not retain an unencrypted staging copy.

For recovery, restore only into an empty Provider data volume, before
`make provider-up`. The restored path must be a regular file owned by container
UID/GID 10001 with mode `0600`; the `/data` directory must be mode `0700`, and
neither may be a symlink. Run `make provider-identity` and compare only the
reported EVM address with the address recorded in the operations inventory.
Start the Provider only after that address matches. Never overwrite an existing
identity blindly: if the addresses differ, stop and reconcile reservations,
receipts and balances associated with both addresses. Test this restore process
on a disposable, offline volume after every backup-policy or image change.

For local smoke testing:

```bash
MYCOMESH_NETWORK_PROFILE=local
MYCOMESH_PROVIDER_POOL_URL=http://bridge:9800
MYCOMESH_PROVIDER_ADVERTISE_HOST=provider
MYCOMESH_PROVIDER_EXTRA_ARGS=--allow-any-signed-consumer --allow-unreserved-requests
```

`MYCOMESH_NETWORK_PROFILE=testnet` enables sealed provider transport and requires
the local Gateway to report `settlement_ready=true`. `codex_cli` and generic
unpinned OpenAI-compatible backends deliberately fail that gate. The explicit
Codex app-server policy is testnet-only and post-validates usage; native signed
metering remains the alternative for a hard generation-time cap.

Start a local foreground Provider:

```bash
make provider
```

Provider logs should eventually show `pool_status: joined`.

## Consumer Proxy Operator

Consumer Proxy nodes expose the OpenAI-compatible URL+key interface to users.
Consumers do not need to run local clients.

The production Compose profile pins on-chain V3 billing and starts a separate
Indexer. Set only the Proxy/Indexer secrets and RPC configuration:

```bash
MYCOMESH_ADMIN_TOKEN=<at-least-32-character-random-secret>
MYCOMESH_POSTGRES_PASSWORD=<random-database-password>
MYCOMESH_BILLING_DB=postgresql://mycomesh:<url-encoded-password>@postgres:5432/mycomesh
MYCOMESH_SETTLEMENT_RPC_URL=<sepolia-rpc-url>
MYCOMESH_PUBLIC_KEY_REGISTRATION=true
MYCOMESH_CHAIN_SYNC_MIN_CONFIRMATIONS=6
MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS=120
MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG=12
```

Non-local profiles reject the example placeholder and administrator secrets
shorter than 32 characters. Testnet Indexer confirmations are hard bounded to
6-64, the cache age to at most 300 seconds and at least two sync intervals, and
block lag to at most 64. Proxy and Indexer alone receive the PostgreSQL and RPC
credentials. Public Nginx routes cannot reach administrator or internal account
write endpoints; use authenticated local administration or `docker compose exec`.

The canonical Proxy identity is pinned in the public Provider manifest. On a
fresh host, restore its mode-0600 offline backup into the Docker volume, then
inspect the public identity:

```bash
make proxy-identity-import PROXY_IDENTITY_FILE=/secure/request-identity.json
make proxy-identity
```

The import fails if the private/public keys do not match, the source is
group/world-readable, the public key is absent from the pinned manifest, or a
different identity already exists. A new random identity cannot join existing
Providers until its public key is deliberately published in a new network
manifest and those Providers are upgraded.

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
protect local resources but do not make `codex_cli` trustworthy for billing.
The explicit `codex_app_server` policy is limited to Sepolia testing: it requires
Codex's native usage event and rejects an over-cap result after execution. Do not
use that policy for open/mainnet settlement because it cannot stop generation at
the signed cap. Open/mainnet requires a native cap and verifiable runtime proof.

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
Relay is required for CGNAT or any Provider that cannot expose an inbound TCP
port. Public-IP auto-discovery only observes an outbound address and cannot
create a NAT or firewall mapping.

Local smoke test:

```bash
MYCOMESH_RELAY_ADVERTISE_HOST=127.0.0.1
MYCOMESH_RELAY_EXTRA_ARGS=--allow-any-signed-consumer
```

The relay cannot decrypt sealed prompts/results, but it sees routing metadata.
Pinned Consumer keys remain available for Gateway/V2 compatibility. Browser V3
Consumers instead present a wallet-bound session and a confirmed, request-bound
Settlement Reservation; they do not require a static Consumer allowlist. Public
operation still requires persistent replay storage, connection/rate limits and
an external security review. Multi-replica Relay deployments must share a
transactional replay store; the standard Compose role is intentionally a single
instance with its own durable SQLite volume.

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

Commit the verified public `deployments/sepolia-myco-v3.json` record, then
rebuild so Docker contains it. The Provider loads the network fields from that
record; configure only the local runtime values:

```bash
MYCOMESH_NETWORK_PROFILE=local
MYCOMESH_SETTLEMENT_VERSION=3
MYCO_DEPLOYMENT=/app/deployments/sepolia-myco-v3.json
MYCOMESH_SETTLEMENT_RPC_URL=<sepolia-rpc-url>
MYCOMESH_SETTLEMENT_CONFIRMATIONS=6
MYCOMESH_PROVIDER_EXTRA_ARGS=--consumer-public-key <proxy-public-key> --payment-address <provider-address>
```

Contract, chain and pricing environment values may be added as consistency pins,
but are not required and must exactly match the manifest.

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
the same separately permissioned transactional replay database across replicas;
the standard single-instance Compose uses private Provider/Relay SQLite files,
which cannot enforce a global claim across hosts.

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
