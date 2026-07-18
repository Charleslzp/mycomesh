# MycoMesh Gateway

This is the MycoMesh execution gateway and local orchestrator for multi-agent code automation. Child agents call it with the OpenAI Chat Completions HTTP protocol, while the gateway maps each request to a user, workspace, code task, child agent, and session before forwarding it to one central inference backend.

Do not put your OpenAI or Codex account password into this project. Use either an OpenAI-compatible API key, or run the official `codex login` command yourself and let the gateway call the local Codex CLI login state.

## Fast Deploy

The fastest operator path is role-based Docker Compose from this git repo:

```bash
make public-node-up
make provider-login
make provider-up
make proxy-up
```

Each operator only runs the role they own in a local smoke test:

```bash
make public-node-up  # Public-IP Bridge + Relay operator
make provider-up      # AI service Provider operator, after provider-login
make proxy-up         # Consumer URL+key gateway operator
```

An end user can start the Gateway-independent Direct browser Consumer with:

```bash
make consumer-up
```

Open `http://127.0.0.1:8110/app/playground` and connect an injected wallet. The
browser creates a non-extractable Ed25519 Consumer identity, discovers signed
Providers through the public Bridge, sends sealed frames through Relay, and uses
Settlement V3 without depending on the public Gateway. Its public key, Peer ID,
Bridge URL and local URLs are visible at `http://127.0.0.1:8110/app/access`.

The same container exposes a localhost-only OpenAI-compatible edge at
`http://127.0.0.1:8110/v1`. That separate headless interface remains
fail-closed for inference until an external wallet signer and V3 reservation
executor are connected; this does not block the browser Consumer. Initialization
and status details are in [docs/local-consumer.md](docs/local-consumer.md).

For a one-machine local demo only, use `make demo`.
Production application services run as the fixed non-root UID 10001 and use
separate Gateway, local Consumer, Proxy, Indexer, Bridge, Relay and Provider volumes. Compose
migrates existing volume ownership with role-scoped one-shot init services.
Only the standalone development Gateway explicitly runs as root for workspace
bind-mount compatibility. Production HTTP upstreams bind fixed loopback ports;
keep local plaintext `tcp://` and `relay://` endpoints on loopback.

For a remote Codex-backed Sepolia Provider, no network or wallet values need
to be copied into `.env.deploy`. The published V4 network manifest is selected
automatically; V3 remains available only for compatibility clients. Run:

```bash
make provider-login   # one interactive ChatGPT device login
make provider-up      # detached start, signed Bridge join, and heartbeats
make provider-health  # Codex login, Gateway readiness, and Bridge lease
```

The image contains the pinned official Codex CLI and this repository's Gateway
reverse proxy. It does not use an OpenAI API key. The login is stored only in
the Provider Docker volume; the host `~/.codex` directory and private keys are
never mounted or copied into the image.

For a machine that should pull a published image instead of building from the
checkout, use the GHCR flow in
[docs/container-images.md](docs/container-images.md):

```bash
docker login ghcr.io --username Charleslzp
export IMAGE_TAG=sha-<published-commit>
make provider-image-pull
make provider-login-image
make provider-up-image
```

The image pull targets preserve the same testnet manifest, volume initialization,
Codex configuration and readiness checks as the source-build targets.

`make provider-up` loads the committed public network manifest automatically.
For the V4 session path, the Consumer opens one bounded escrow session after
the initial deposit. Each later API request is signed and metered off-chain;
there is no per-request wallet transaction and no seven-block admission wait.
The Gateway writes signed receipts to a durable outbox and a single relayer
submits them in sequence batches. V3 clients continue to use their legacy
per-request reservation and confirmation flow.
The default Relay transport needs neither a Provider allowlist entry, an inbound
public IP, nor an API key; only the one-time interactive ChatGPT device login is
operator-specific. Back up the independently generated payout identity before
accepting paid work. The backup and recovery requirements are in
[docs/quick-deploy.md](docs/quick-deploy.md#provider-payout-identity-recovery).

Public discovery is versioned in
`deployments/sepolia-provider-network-v4.json`. It references the V4 deployment
manifest and pins the canonical Bridge, Relay, public Sepolia RPC and Consumer
Proxy signing key. The default Provider connects outbound through Relay, so it
works behind NAT without an inbound firewall rule. The Provider-to-Relay socket uses
system-CA and hostname-verified TLS on `bridge.mycomesh.xyz:9901`; each
connection receives a fresh Relay challenge that is bound into the Provider
registration signature, and the acknowledgement must echo that challenge. Its Ed25519 node identity
and independent secp256k1 payout/signing identity are generated once in the
Provider-only Docker volume with private file permissions.

Startup validates every network-config field, verifies the pinned V4 manifest
and rejects mismatched environment overrides. V4 admission does not wait for a
confirmed block; the six-confirmation gate remains only on the V3 compatibility
path. `GET /health` is liveness; `GET /ready` is settlement readiness. Against a Bridge using
`--allow-any-signed-provider`, no Provider node-key allowlist entry is needed.

A Provider with a reachable public port can explicitly use direct transport:

```bash
make provider-up PROVIDER_TRANSPORT=direct PROVIDER_BIND_ADDRESS=0.0.0.0
```

Direct mode discovers its public IPv4 through the configured Bridge and still
requires the Bridge's signed callback proof before admission.

The repository bundles the verified public Sepolia V4 deployment record at
`deployments/sepolia-myco-v4.json`; every new testnet role hydrates public chain
configuration from that file. The V3 record remains in the repository for
legacy clients. Public addresses belong in Git. Private keys,
Codex auth, access tokens, RPC credentials and database passwords never do.

The recommended production split for the owned domain is the homepage at
`https://mycomesh.xyz`, dApp at `https://app.mycomesh.xyz`, Consumer Proxy at
`https://gateway.mycomesh.xyz`, Bridge at `https://bridge.mycomesh.xyz`, and Relay control at
`https://bridge.mycomesh.xyz/infer/<provider-peer-id>`.
The browser origins are explicit, comma-separated allowlists:

```bash
MYCOMESH_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
MYCOMESH_POOL_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
```

The Proxy accepts browser `GET`/`POST` API calls without credentialed cookie
CORS. Bridge CORS is read-only for `/health` and `/peers`; browser writes remain
disabled. Both settings default to no cross-origin access and reject wildcards,
paths and insecure non-loopback HTTP origins. The complete DNS, canonical URL
and reverse-proxy layout is in [docs/quick-deploy.md](docs/quick-deploy.md).

See [docs/quick-deploy.md](docs/quick-deploy.md) for the full quickstart and
[docs/security-audit-and-remediation.md](docs/security-audit-and-remediation.md)
for the security status and production gates. Non-local profiles require signed
`myco+tcp://` or `myco+relay(s)://` descriptors and end-to-end sealed frames.
`codex_cli` remains local-only. The explicit `codex_app_server` policy is
accepted only on Sepolia testnet, where native usage is checked after execution;
it is not a generation-time output cap. The `open`/mainnet profile therefore
continues to fail closed. `make demo` is not a public deployment recipe.

The CLI can also be installed directly:

```bash
python -m pip install -e .
mycomesh --help
```

## What It Does

- Accepts `POST /v1/chat/completions`
- Accepts `POST /v1/responses`
- Accepts `GET /v1/models`
- Uses internal agent keys to identify child agents
- Tracks user, workspace, task, agent, and session context
- Keeps isolated SQLite history per `(user_id, workspace_id, task_id, agent_id, session_id)`
- Injects routing context and per-agent code-task prompts
- Forwards to one upstream OpenAI-compatible endpoint, or local Codex CLI
- Supports a Codex center-orchestrator mode that routes work to child agents
- Provides local username/password login for your own gateway users
- Transparently proxies other `/v1/*` routes to the upstream

## OpenAI Compatibility

For child agents, configure only:

```text
base_url = http://<gateway-host>:8000/v1
api_key = <agent-key>
```

Supported with `GATEWAY_BACKEND=codex_cli` or `GATEWAY_BACKEND=codex_app_server`:

- `/v1/chat/completions`: bridged to Codex
- `/v1/chat/completions` with `stream=true`: returns buffered OpenAI-style SSE chunks after Codex completes
- `/v1/responses`: bridged to Codex
- `/v1/responses` with `stream=true`: returns buffered Responses-style SSE events after Codex completes
- `/v1/models`: returns gateway model ids
- model identity: `PUBLIC_MODEL_ID` controls the model name exposed to child agents

Explicitly unsupported with Codex backends:

- `/v1/embeddings`
- `/v1/files`
- `/v1/audio/*`
- `/v1/images/*`
- true OpenAI tool execution semantics
- inline PDF extraction; extract documents in a resource-bounded sandbox and
  submit the exact text as `input_text`

Tool calls and JSON response formats have compatibility shims for SDK/test compatibility, but Codex is still the actual backend. Unsupported endpoints return an OpenAI-style JSON error instead of silently failing. With `GATEWAY_BACKEND=openai_http`, unsupported local routes are proxied to the configured upstream.

`GATEWAY_MAX_REQUEST_BYTES` bounds every HTTP request before route dispatch,
including chunked requests and routes that FastAPI parses automatically. The
Consumer Proxy has the separate `MYCOMESH_MAX_REQUEST_BYTES` limit. A declared
or streamed body over either limit receives `413` before application work.
Decoded upstream responses and SSE streams are bounded by
`UPSTREAM_MAX_RESPONSE_BYTES` and `UPSTREAM_MAX_STREAM_BYTES`. Codex CLI stdout,
stderr retention and app-server cumulative JSON-RPC events also have explicit
byte/message limits.

`codex_cli` is a local compatibility backend and is never settlement-ready. The
explicit Sepolia `codex_app_server` mode consumes Codex's native usage event and
rejects a result that exceeds the reserved output bound, but that validation is
post-execution. It does not prove the model enforced the cap while generating.
The `open`/mainnet profile therefore still requires a backend with a native
generation-time cap and verifiable metering proof.

## Codex Center Orchestration

When an agent in `agents.json` has `"orchestrates": true`, requests using that agent's key are handled as a center-orchestrator request. The gateway asks Codex to return a strict JSON decision:

```json
{
  "action": "final",
  "final": "answer to return"
}
```

or:

```json
{
  "action": "call_agent",
  "target_agent": "planner",
  "input": "task for the child agent",
  "session_id": "optional-child-session"
}
```

For `call_agent`, the gateway invokes the target child agent internally with that agent's prompt and isolated session, then gives the child result back to the center Codex orchestrator. This repeats up to `GATEWAY_ORCHESTRATION_MAX_STEPS`, then the final answer is wrapped as a normal OpenAI-compatible chat completion.

The default `agents.json` marks `coder-local-key` as the center entrypoint:

```text
external child/client -> coder-local-key -> center Codex -> planner/coder/reviewer -> final OpenAI-style response
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
cp agents.example.json agents.json
```

Edit `.env`:

```bash
GATEWAY_BACKEND=openai_http
UPSTREAM_BASE_URL=https://api.openai.com/v1
UPSTREAM_API_KEY=your-openai-api-key
UPSTREAM_TIMEOUT_SECONDS=180
UPSTREAM_MAX_RESPONSE_BYTES=33554432
UPSTREAM_MAX_STREAM_BYTES=33554432
CENTER_MODEL=your-central-model
PUBLIC_MODEL_ID=gpt-5.5
DEFAULT_USER_ID=local-user
DEFAULT_WORKSPACE_ID=default-workspace
```

`openai_http` is intentionally non-settleable and is suitable only for local
development. Sepolia Providers may use either the signed `native_metered_http`
contract in [Native Metered Upstream Protocol](docs/native-metered-upstream.md)
or the explicit Codex app-server post-validation policy documented above. Only
the native-metered backend claims a generation-time output cap and signed
runtime proof.

The Docker Provider path is:

```text
signed MycoMesh request -> Provider TCP/9700 -> repository Gateway -> Codex app-server -> ChatGPT/Codex account
```

Configure it with `GATEWAY_BACKEND=codex_app_server`, an empty
`UPSTREAM_API_KEY`, `MYCOMESH_CODEX_TESTNET_METERING=true`,
`CODEX_SANDBOX=read-only`, and `CODEX_MAX_CONCURRENT_PROCESSES=1`. Leave
`CODEX_PROVIDER_BASE_URL` empty for the official service. Testnet startup rejects
a custom value so the Codex bearer credential cannot be redirected; the override
exists only for isolated local development.

For Codex Pro/Plus via official CLI login:

```bash
codex login
```

Then set:

```bash
GATEWAY_BACKEND=codex_app_server
CODEX_COMMAND=codex
CODEX_HOME=/Users/lzp/mutilpleagent/.codex-gateway-home
CODEX_WORKDIR=/path/to/your/code/workspace
CODEX_SANDBOX=workspace-write
CENTER_MODEL=
PUBLIC_MODEL_ID=gpt-5.5
CODEX_INTERNAL_MODEL=gpt-5.5
CODEX_STDOUT_MAX_BYTES=8388608
CODEX_STDERR_MAX_BYTES=1048576
CODEX_APP_SERVER_STDOUT_MAX_BYTES=33554432
CODEX_APP_SERVER_STDERR_RETAIN_BYTES=1048576
CODEX_APP_SERVER_MAX_MESSAGES=100000
CODEX_APP_SERVER_MAX_PENDING_TURNS=8
CODEX_APP_SERVER_PENDING_TTL_SECONDS=300
```

This uses the Codex CLI auth state inside `CODEX_HOME`; the gateway never asks for or stores your OpenAI/Codex password. Keep `CODEX_HOME` project-specific if you want this gateway login to be isolated from your normal `~/.codex` setup. `CODEX_INTERNAL_MODEL` is passed to Codex as the actual model selection. Use `GATEWAY_BACKEND=codex_cli` instead if you need the older `codex exec` bridge.

Start an isolated browser/device login for this gateway:

```bash
CODEX_HOME=/Users/lzp/mutilpleagent/.codex-gateway-home codex login --device-auth
```

Or use the bundled gateway client command:

```bash
python -m gateway login
```

Start the gateway:

```bash
uvicorn gateway.main:app --reload --host 127.0.0.1 --port 8000
```

Run tests:

```bash
python -m unittest discover -s tests -q
```

## Gateway Client Commands

The gateway can be operated as a local client around the existing server.

Start the official Codex login flow:

```bash
python -m gateway login
```

Generate a gateway API key for an agent:

```bash
python -m gateway key create --agent coder
```

List stored key fingerprints:

```bash
python -m gateway key list
```

Delete a key by full key, unique key prefix, or fingerprint prefix:

```bash
python -m gateway key delete --agent coder <selector>
```

Rotate a key by creating a replacement and removing the selected old key:

```bash
python -m gateway key rotate --agent coder <selector>
```

Print the public OpenAI-compatible base URL when a Cloudflare tunnel URL is
present in `.codex-run/cloudflared*.log`:

```bash
python -m gateway url --port 8000
```

Call the local or public liveness endpoint:

```bash
python -m gateway health --port 8000
python -m gateway health --public --port 8000
```

For settlement-backed operation, query readiness explicitly:

```bash
python -m gateway health --url http://127.0.0.1:8000/ready --require-settlement-ready
```

Print a compact local status summary:

```bash
python -m gateway status --port 8000
```

Start the gateway in the foreground:

```bash
python -m gateway serve --port 8000
```

Start the gateway and a Cloudflare quick tunnel together:

```bash
python -m gateway serve --port 8000 --with-tunnel
```

Manage only the tunnel:

```bash
python -m gateway tunnel start --port 8000
python -m gateway tunnel status --port 8000
python -m gateway tunnel stop --port 8000
```

Clear the isolated Codex login state used by this gateway:

```bash
python -m gateway logout
```

Generated keys are stored in `agents.json`. Restart an already running gateway
after creating or deleting keys so the server reloads the updated agent config.
Managed gateway and tunnel processes write logs and pid files to `.codex-run`.

## MycoMesh Network And Settlement

MycoMesh is the decentralized inference-network mode built on top of this
gateway. The implementation has a legacy V2 settlement path and a hardened V3
settlement path. Local traffic uses plaintext loopback transports; non-local
Provider and relay traffic uses signed descriptors and end-to-end sealed
frames.

- Provider pool entries are signed Ed25519 node descriptors, and direct
  `tcp://` addresses are probed by default before entering the live pool.
- P2P and relay inference requests are signed by the consumer identity and
  carry a signed payment reservation. V3 providers verify the exact request
  hash, confirmed on-chain reservation, pricing hash and quote before calling
  the local Codex gateway.
- Relay provider registration is signed, so another node cannot trivially steal
  an existing `peer_id`.
- Receipts include protocol version, consumer/provider public keys, hashes,
  pricing, settlement deadlines, operator signatures, and optional consumer
  acceptance signatures.
- Consumers can call an OpenAI-compatible MycoMesh proxy with only `base_url`
  and `api_key`.
- Public Gateway nodes can register signed descriptors containing a canonical
  `public_url`, `network_id`, `chain_id`, `settlement`, monotonic sequence, and
  short expiry.
  `/v1/mycomesh/gateways` returns matching descriptors for independent client
  verification; self-reported weight and latency are not trusted for ranking.
- Wallet users can register a client-generated API key by submitting only
  `sha256(api_key)` plus a wallet signature; plaintext keys are never stored by
  the Gateway.
- The proxy reserves prepaid balance before dispatching work and captures the
  actual fee after a valid response, so unpaid consumers cannot freely consume
  provider quota.
- Account API keys can be suspended or closed, and reserve/capture operations
  are idempotent around reservation ids and receipt event ids.
- Provider and relay request ids are replay-checked. The single-instance Compose
  roles use separate `/data/provider-replay.sqlite3` and
  `/data/relay-replay.sqlite3` stores and receive no Proxy database credential.
- Legacy MycoMesh settlement V2 supports prepaid stablecoin balances, withdrawal,
  signed prepaid receipt settlement, delegated settlement authorization, batch
  settlement preparation, treasury buyback burn hooks, and MYCO reward minting
  capped by epoch emission. New deployments should use V3 after completing the
  production gates documented in the security audit.

Create a local MycoMesh API account and credit test balance:

```bash
export MYCOMESH_NETWORK_PROFILE=local
export MYCOMESH_NETWORK_ID=mycomesh-local
export MYCOMESH_PUBLIC_GATEWAY_URL=http://127.0.0.1:8100/v1
export ETH_CHAIN_ID=11155111
export MYCO_SETTLEMENT=0x780e8daa596981c055148633849a6dd90a0f8d15

python -m gateway mycomesh account create \
  --account-id acct-alice \
  --payment-address <consumer-evm-address>
python -m gateway mycomesh account deposit acct-alice --amount-usdc 1
python -m gateway mycomesh account rotate acct-alice

python -m gateway mycomesh account policy acct-alice \
  --usage-tier pro \
  --discount-bps 500 \
  --monthly-quota-usdc 100

python -m gateway mycomesh account status acct-alice --status suspended
```

The HTTP account administration endpoints require `MYCOMESH_ADMIN_TOKEN`.
Outside the local profile, placeholder values and secrets shorter than 32
characters are rejected.
Local CLI account commands operate directly on the local billing database.
Set `MYCOMESH_BILLING_MODE=local` for managed local balances. When using
on-chain prepaid balances as the source of truth, do not mutate local balances
directly; sync deposits from chain events or an operator process through
`POST /accounts/{account_id}/sync-balance` and run the proxy with
`MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE=1`. In `onchain-prepaid` mode the proxy
serves fail-closed unless the local cache has a recent sync state matching the
configured `ETH_CHAIN_ID` and settlement address. Tune
`MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS` and `MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG`
for the indexer freshness window.

If you use the manual sync endpoint instead of the event indexer, include the
full freshness metadata. This is a trusted operator assertion, not proof of its
chain origin; only the event indexer verifies RPC results and the canonical block
hash:

```bash
python -m gateway mycomesh account sync-balance acct-alice \
  --balance-usdc 10 \
  --chain-id 11155111 \
  --settlement <myco-settlement> \
  --latest-block <latest-observed-block> \
  --synced-block <confirmed-synced-block> \
  --synced-block-hash <confirmed-synced-block-hash> \
  --confirmations 6
```

For manual testnet operation, sync confirmed chain events into the local URL+key
proxy cache and release stale local reservations with:

```bash
python -m gateway mycomesh indexer sync \
  --deployment deployments/sepolia-myco-v2.json \
  --events \
  --confirmations 6 \
  --chunk-blocks 1000

python -m gateway mycomesh account cleanup-reservations --max-age-seconds 900
```

A one-account direct balance read is only for an empty/direct-only debug cache.
After the global source has become `events`, recovery must continue through the
event indexer; a direct account read cannot overwrite or downgrade that state.
Each account's lag is measured against the global latest block. The final balance
reservation repeats chain freshness and reorg checks inside the same write
transaction as the deduction. While a sticky reorg is active, reservation refunds
do not restore spendable balance; only canonical event recovery can clear the
condition and recompute balances.

Start the consumer proxy and copy the `consumer_public_key` from the admin
health endpoint. Public `/health` returns only minimal service status unless
`MYCOMESH_HEALTH_PUBLIC_DETAILS=1` is explicitly set:

```bash
MYCOMESH_POOL_URL=http://127.0.0.1:9800,http://127.0.0.1:9802 \
python -m gateway mycomesh serve --port 8100

curl http://127.0.0.1:8100/health
curl -H "Authorization: Bearer $MYCOMESH_ADMIN_TOKEN" \
  http://127.0.0.1:8100/admin/health
```

Consumers then use:

```text
base_url = http://127.0.0.1:8100/v1
api_key = <msk_...>
```

For a public URL+key Gateway, first put a stable public DNS name behind a valid
TLS reverse proxy and configure that exact API base URL:

```bash
MYCOMESH_NETWORK_PROFILE=testnet
MYCOMESH_NETWORK_ID=mycomesh-testnet
MYCOMESH_PUBLIC_GATEWAY_URL=https://gateway.mycomesh.xyz/v1
MYCOMESH_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
ETH_CHAIN_ID=11155111
MYCO_SETTLEMENT=<settlement-address-for-this-network>
```

`MYCOMESH_PUBLIC_GATEWAY_URL` is required in every profile. Outside the local
profile, the URL must use `https://` and a public DNS name.
Userinfo, query strings, fragments, private/reserved IP literals, and localhost
are rejected, as are surrounding whitespace, control characters, and
backslashes. Hex/octal/integer and shortened legacy IPv4 hostnames are also
rejected. Plain HTTP is accepted only for localhost in the `local` profile.
Do not derive this value from a request `Host` header or a provider callback.

Gateway registry entries are node-signed descriptors. A valid descriptor binds
the Ed25519 `node_id` and public key to the canonical URL, network, chain,
settlement, monotonic sequence, and an expiry no more than one hour away. Registration is
admin-authorized outside the local compatibility profile. A consumer should
verify the signature and pin the expected node key, network, chain and settlement before
using a discovered URL.

Discovery also returns `recommended_gateway.descriptor`, signed by the local
request identity. Verify that descriptor and select its signed `public_url`;
`recommended_base_url` is retained only as a compatibility field and is not a
trust anchor. Signature validity alone is not node trust: pin the expected node
public key, network, chain, and settlement from the deployment manifest.

Consumers discover usable entry URLs from any reachable Gateway:

```bash
curl https://api.mycomesh.network/v1/mycomesh/gateways
curl https://api.mycomesh.network/.well-known/mycomesh.json
```

Discovered URLs are **not** interchangeable credential targets. An API key is
bound to origin, network, chain, and settlement and must be registered
separately at each selected Gateway. The
wallet-signed challenge includes the HTTPS origin, network ID, chain ID,
settlement address, key hash, nonce and expiry, so a registration signature from
one origin cannot be replayed at another. Users generate the secret locally and
submit only its hash:

```bash
API_KEY="msk_$(openssl rand -base64 32 | tr -d '=+/')"
KEY_HASH="$(printf "%s" "$API_KEY" | shasum -a 256 | awk '{print $1}')"

curl -X POST https://gw-a.operator.example/v1/mycomesh/keys/challenge \
  -H "Content-Type: application/json" \
  -d '{"wallet":"<consumer-evm-address>","key_hash":"'"$KEY_HASH"'","chain_id":11155111}'

# Sign the returned `message` with the wallet, then register:
curl -X POST https://gw-a.operator.example/v1/mycomesh/keys/register \
  -H "Content-Type: application/json" \
  -d '{
    "wallet": "<consumer-evm-address>",
    "key_hash": "'"$KEY_HASH"'",
    "chain_id": 11155111,
    "nonce": "<challenge-nonce>",
    "signature": "0x..."
  }'
```

The Gateway stores only `key_hash`. Key rotation is the same flow with a new
locally generated key; the old key stops working, while account balance and
usage history remain attached to the wallet address on that Gateway. Failover
requires an independently registered key (preferably a different secret) on the
other origin; the system does not replicate credentials or balances between
independently operated Gateway databases.

The stored credential scope is checked on every authenticated request, together
with the request `Host`. The TLS reverse proxy must accept only the canonical
SNI/Host and preserve that Host upstream. Legacy unscoped keys are always
rejected; rotate them through the admin endpoint before rollout.
The direct `mycomesh account create` and `account rotate` CLI paths also
require the canonical URL, network, chain and settlement environment and persist
the same scope.

Challenge issuance is transactionally bounded by
`MYCOMESH_KEY_CHALLENGE_CAPACITY` and
`MYCOMESH_KEY_CHALLENGE_RATE_PER_MINUTE`; these bounds apply per shared billing
database, not across independent databases, and are not a replacement for
reverse-proxy per-source limits. With `ETH_RPC_URL`
configured, registration supports both EOAs and EIP-1271 contract wallets.
Contract-wallet RPC verification runs in a bounded worker pool controlled by
`MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY` and a shared total deadline set by
`MYCOMESH_KEY_REGISTRATION_RPC_TIMEOUT`; concurrency is per process. Only after
an RPC worker slot is acquired is the challenge claimed with a transactional verification
lease, so capacity rejection does not consume an attempt. Challenge consumption
and key registration commit atomically and require the current claim token.
If the executor rejects submission, that token-bound claim and its attempt are
rolled back atomically; once a worker is submitted, failures and timeouts count,
and its claim cannot be taken over by another process while the challenge remains
valid. The background worker releases it on exit; after a process crash, clients
must use a new challenge instead of taking over the old claim. Challenge
expiry is rechecked after acquiring the database write lock before registration.
`MYCOMESH_KEY_REGISTRATION_MAX_ATTEMPTS` defaults to 5 and fails the challenge
closed after that many verification attempts. Replicas for the same origin must
share the same PostgreSQL DSN; independent SQLite files cannot coordinate the
claim. SQLite remains supported for a single-process or single-host deployment.

This command starts a local gateway and a local plaintext P2P provider. The node
identity is created automatically at
`.codex-run/node-identity.json` unless `--identity` is supplied:

```bash
python -m gateway provider start \
  --provider-port 9700 \
  --advertise-host 127.0.0.1 \
  --agent coder \
  --network-profile local \
  --pool http://127.0.0.1:9800 \
  --consumer-public-key <proxy-consumer-public-key> \
  --payment-address <provider-evm-address> \
  --pricing-hash <channel-pricing-hash>
```

The command prints the provider `peer_id` and Ed25519 `public_key`. `local` uses
plaintext `tcp://`/`relay://`. A `testnet` provider instead advertises
`myco+tcp://` or `myco+relay(s)://` with an Ed25519-signed X25519 transport-key
binding and ChaCha20-Poly1305 sealed frames. The relay forwards opaque payloads
and cannot decrypt prompts or results, although endpoints, timing, sizes and
routing metadata remain visible. Transport keys rotate with an overlap window.
This message-layer design does not provide Noise-style session forward secrecy;
it still requires independent cryptographic review and perimeter protection.

For hardened local integration runs:

- Set `MYCOMESH_STRICT_CHAIN_PRICING=1` and provide `ETH_RPC_URL` plus
  `MYCO_SETTLEMENT` so providers and proxies read `channelPricingHash(bytes32)`
  from the settlement contract.
- Keep `MYCOMESH_REQUIRE_PROVIDER_SETTLEMENT_FIELDS=1` so proxies only route to
  providers with signed public keys and payment addresses.
- Require consumer account `payment_address` outside local billing mode, or set
  `MYCOMESH_REQUIRE_CONSUMER_PAYMENT_ADDRESS=1` for local settlement dry-runs.
- Keep Provider and Relay replay stores on their separate durable role volumes.
  The standard single-instance Compose deliberately uses isolated SQLite files.
- A custom multi-host deployment needs separately permissioned transactional
  replay databases for each replicated role; Proxy replicas share only their
  own PostgreSQL `MYCOMESH_BILLING_DB` credential.
- Bound proxy work with `MYCOMESH_INFERENCE_CONCURRENCY` (default 8, maximum 64)
  and `MYCOMESH_TIMEOUT_SECONDS` (code default 120, maximum 300). The production
  deployment template uses 300 seconds so V3 admission RPCs and Codex execution
  share one deadline. A deadline failure releases any uncaptured balance
  reservation and peer lease.
- Keep the ASGI and server caps enabled: `GATEWAY_MAX_CONCURRENT_REQUESTS`,
  `MYCOMESH_MAX_CONCURRENT_REQUESTS`, the two request-body timeout variables,
  and the `*_UVICORN_*` limits. Public traffic still needs a reverse proxy with
  a total request-header read deadline because ASGI starts only after headers.
- `CODEX_MAX_CONCURRENT_PROCESSES` defaults to 4 and is capped at 64 across CLI
  and app-server backends; cancellation terminates the whole spawned process group.

Strict mode only accepts chain pricing or an explicit
`MYCOMESH_CHANNEL_PRICING_HASH`; local pricing config is a development fallback.

Deploy the legacy MycoMesh V2 testnet contracts only for compatibility testing:

```bash
python -m gateway chain deploy-myco-testnet \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --treasury "$TREASURY" \
  --solc /path/to/solc-0.8.28
```

The deploy command accepts the settlement governance executor automatically and
the testnet deployer sets the minimum governance delay before handoff. After
that, privileged settlement changes must be scheduled with an action hash and
executed only after the timelock delay has elapsed.

Consumers approve tUSDC once and deposit prepaid balance. Operators settle
accepted receipts from that balance through the delegated flow below:

```bash
python -m gateway chain approve-usdc \
  --deployment deployments/sepolia-myco-v2.json \
  --spender <myco-settlement> \
  --amount-usdc 10

python -m gateway chain deposit-prepaid \
  --deployment deployments/sepolia-myco-v2.json \
  --amount-usdc 10

python -m gateway chain prepaid-balance \
  --deployment deployments/sepolia-myco-v2.json \
  --account <consumer-evm-address>
```

`--trusted` keeps the operator-only settlement path available for demos and
migration, but it is disabled by default in both CLI and contract. To use it,
governance must schedule and execute `set-trusted-settlement --enabled true`,
and the CLI call must pass `--allow-demo-trusted` or set
`MYCOMESH_ALLOW_TRUSTED_SETTLEMENT=1`. Signed settlement is the production path
and requires an accepted receipt; `pool infer --accept` and the MycoMesh proxy
both attach `accepted_hash` before receipts are written to the local ledger.

For the URL+key product path, consumers and providers should approve a
settlement delegate once with `setSettlementDelegate(delegate, true)`. This
session/delegate model lets the operator settle accepted receipts without
asking either side to expose a private key on every request.

```bash
python -m gateway chain set-settlement-delegate \
  --deployment deployments/sepolia-myco-v2.json \
  --delegate <operator-or-upstream-address> \
  --allowed true

python -m gateway chain prepare-delegate-signatures \
  --deployment deployments/sepolia-myco-v2.json \
  --delegate <operator-or-upstream-address> \
  --consumer-nonce 1001 \
  --provider-nonce 1002

python -m gateway chain settle-delegated-prepaid-receipt \
  --deployment deployments/sepolia-myco-v2.json \
  --delegate <operator-or-upstream-address> \
  --consumer-nonce 1001 \
  --provider-nonce 1002 \
  --consumer-signature-json '{"r":"0x...","s":"0x...","v":27}' \
  --provider-signature-json '{"r":"0x...","s":"0x...","v":27}'
```

The delegated settlement call uses a receipt-level max amount, expiry, and
nonce for each side. If `--max-usdc` is omitted, the CLI uses the accepted
receipt `pricing.gross_fee` as the authorization cap. If `--delegate` is
omitted, the operator transaction signer is used as the delegate address. The
delegate signature is bound to the receipt hash, accepted hash, channel,
counterparty, and gross fee, so an authorization for one receipt cannot be
replayed onto another receipt. `--consumer-delegate-private-key` and
`--provider-delegate-private-key` still exist for local demos; production should
pass wallet-produced `r/s/v` signatures.

Governance-controlled maintenance commands are available for moving execution
authority, changing operators, tuning channel economics, enabling demo trusted
settlement, and burning MYCO that the treasury has repurchased. For each
privileged action, first compute and schedule the action hash, wait for the
configured delay, then run the matching mutation command:

```bash
python -m gateway chain governance-action-hash governance-executor \
  --executor <governance-executor-address>

python -m gateway chain schedule-governance-action \
  --deployment deployments/sepolia-myco-v2.json \
  --action-hash <action_hash-from-previous-command>

# Wait for governanceDelaySeconds before executing the scheduled action.

python -m gateway chain set-governance-executor \
  --deployment deployments/sepolia-myco-v2.json \
  --executor <governance-executor-address>

python -m gateway chain accept-governance-executor \
  --deployment deployments/sepolia-myco-v2.json

python -m gateway chain governance-action-hash governance-delay --delay-seconds 86400
python -m gateway chain governance-action-hash operator \
  --operator <operator-address> \
  --allowed true

python -m gateway chain governance-action-hash economics \
  --epoch-seconds 604800 \
  --epoch-emission-myco 1000000 \
  --halving-interval-epochs 210000 \
  --max-consumer-rebate-bps 2000

python -m gateway chain governance-action-hash channel \
  --channel-hash <bytes32-channel> \
  --input-per-1k-usdc 0.001 \
  --output-per-1k-usdc 0.004 \
  --minimum-fee-usdc 0.002 \
  --provider-bps 8500 \
  --relay-bps 300 \
  --pool-bps 200 \
  --treasury-bps 1000 \
  --provider-reward-bps 9000 \
  --consumer-reward-bps 1000 \
  --reward-per-treasury-unit 1000000000000

python -m gateway chain governance-action-hash trusted-settlement --enabled true
python -m gateway chain governance-action-hash buyback-burn --amount-myco 1000
```

`governance-action-hash` supports `treasury`, `operator`,
`governance-executor`, `governance-delay`, `economics`, `trusted-settlement`,
`channel`, and `buyback-burn`. `set-governance-delay` refuses values below one
hour.

Prepare batch settlement inputs from accepted local receipts:

```bash
python -m gateway chain prepare-prepaid-batch \
  --ledger .codex-run/receipts.jsonl \
  --limit 100
```

## Settlement V3

Settlement V3 replaces mutable channel economics with immutable pricing
versions, locks prepaid funds in an on-chain provider-specific reservation, and
requires consumer and provider EIP-712 authorization for every receipt (directly
or through receipt-scoped delegate signatures). It removes the V2 trusted
operator settlement path, supports EIP-1271 wallets, caps batches, credits only
standard non-rebasing/no-transfer-fee stablecoins with exact balance deltas, and
does not let a reward-mint failure revert the stablecoin payment. The EIP-712
domain separator is rebuilt if the chain ID changes.

Before a testnet Provider listens or registers, it loads the bundled
`deployments/sepolia-myco-v3.json` manifest and runs a read-only preflight
against the `finalized` block. Chain ID, deployed code, settlement address,
stablecoin, reward token, treasury, governance, EIP-712 domain, channel pricing
version/hash and the configured reservation-size quote must agree with the
manifest. The manifest supplies the Provider settlement contract, chain ID,
channel, pricing version and pricing hash. The corresponding environment
variables remain optional consistency pins and fail closed on any mismatch.
The Compose testnet profile also requires
`MYCOMESH_SETTLEMENT_CONFIRMATIONS` to be an integer of at least `6`.

Every new reservation is bound to the SHA-256 `requestHash` of the versioned,
billable inference envelope. Version `mycomesh.inference.request.v2` commits the
normalized endpoint, exact model string, canonical `input` or `messages` JSON,
and positive `max_output_tokens`; routing metadata and `request_id` are not
included. `v3-create-reservation` therefore requires exactly one of `--input`
or `--request-hash`:

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

The inference must use the identical tuple. The simplest local EOA flow is:

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

Chat commits the original `messages` array as structured JSON; it must never
stringify or reconstruct that array before hashing. For structured chat input,
compute the v2 envelope hash with
`gateway.reservation.inference_request_hash` and pass it to reservation creation
through `--request-hash`.

Every V3 inference also carries a one-reservation EIP-191 authorization that
binds the consumer EVM wallet to the Ed25519 request key. Its
`mycomesh.evm.session.v1` canonical JSON binds the chain, settlement,
reservation, consumer/provider identities, channel, pricing hash/version,
request hash, maximum fee, expiry, receipt deadline, fallback choice, unique
nonce and Ed25519 session public key. The wallet signature is carried beside,
not inside, those signed fields. For an external EOA or EIP-1271 wallet, run the
same command with `--prepare-session-authorization` and no signing source, sign
the printed canonical EIP-191 message, then rerun it with
`--session-authorization-signature 0x...` and the printed
`--session-authorization-nonce`. A complete signed object can instead be passed
as `--evm-session-authorization @authorization.json`.

The provider selects the consumer wallet type with `eth_getCode` at the same
confirmed block used for reservation checks. It locally recovers EOAs; for an
EIP-1271 consumer it calls `isValidSignature(bytes32,bytes)` and requires the
exact 32-byte ABI value `0x1626ba7e` followed by 28 zero bytes. This is scoped to
one reservation/request, not a reusable session registry or a general actively
revocable delegation.

Before calling the local AI gateway, the provider canonicalizes `input` or
`messages` as compact JSON and rejects its UTF-8 byte length above
`reserve_input_tokens`; this is an admission-size check, not token counting.
Pre-execution fee authorization deliberately quotes the provider's full
`reserve_input_tokens` budget so injected agent/system/routing context is also
covered. Operators remain responsible for sizing that budget for their complete
upstream prompt pipeline. The provider rejects a requested model that differs
from its configured/descriptor model, rejects an explicit output cap above
`reserve_output_tokens`, defaults a missing cap to the provider limit, and
always forwards the resolved cap upstream. OpenAI-compatible
`max_output_tokens`, `max_completion_tokens`, and `max_tokens` are accepted only
as native positive integers; if more than one is present, all values must match
or the HTTP API returns `422`. The pre-execution local/V3 on-chain quote must fit
the reservation. A V3 settlement
deadline must be at least the provider timeout plus a 60-second inclusion buffer
from the current time and must not exceed reservation expiry. The provider also
reads `channelPricingHash`, the nine-word `reservations` getter and `quote` at
one confirmed block; every failure occurs before inference.

After capacity and all admission, chain and wallet checks pass, the provider
atomically claims request ID, payment signature nonce,
`(chain, settlement, reservationId)` and
`(chain, settlement, consumer, session nonce)` in its persistent replay store,
before calling the upstream model. A
capacity rejection does not consume any of the four claims. Once execution has started,
an uncertain upstream failure is reported as non-retryable and the claims stay
consumed, providing at-most-once execution. The standard Provider Compose role
uses the durable `/data/provider-replay.sqlite3` file in its private volume.
Replicas must use a separately permissioned shared transactional store because
independent databases cannot provide a global claim; that multi-host topology
is intentionally outside the single-instance Compose file.

Provider, Pool and Relay servers bound concurrent connection threads and apply an
absolute deadline while reading unauthenticated request headers/bodies. Relay
providers may remain connected after signed registration, but an inference
timeout removes the session and closes its connection.

Provider fallback is disabled by default. A consumer who deliberately accepts a
non-refundable minimum service fee must add `--allow-provider-fallback` when
creating the on-chain reservation and repeat that flag in the matching inference
reservation. Only then, if the consumer refuses the final EVM receipt signature,
can the provider prepare and submit the minimum-fee fallback:

```bash
python -m gateway chain v3-prepare-provider-fallback \
  --deployment deployments/sepolia-myco-v3.json \
  --ledger .codex-run/receipts.jsonl

python -m gateway chain v3-settle-provider-fallback \
  --deployment deployments/sepolia-myco-v3.json \
  --ledger .codex-run/receipts.jsonl \
  --private-key "$RELAYER_PRIVATE_KEY" \
  --provider-signature 0x<65-byte-signature>
```

An EIP-1271 provider wallet instead uses
`--provider-contract-signature 0x<arbitrary-wallet-signature>`; the CLI checks
`isValidSignature(bytes32,bytes)` over RPC before submission. The RPC return
must contain at least one 32-byte ABI word whose decoded `bytes4` is
`0x1626ba7e`; a raw four-byte return is rejected to match the settlement
contract. Signed settlement
likewise accepts `--consumer-contract-signature` and
`--provider-contract-signature`. Each role must choose exactly one local private
key, 65-byte EOA signature, or nonempty EIP-1271 signature (maximum 16 KiB).

Fallback additionally requires `acceptedHash == 0`. It spends only the
reservation's pre-authorized `minimumFee`:
`providerBps` goes to the provider and all remaining stablecoin goes to the
version-pinned treasury. It pays no relay or pool share, mints no reward, and is
an irrevocable base-fee authorization, not proof of service delivery,
correctness, uniqueness, quality, or consumer acceptance.

The final reservation ABI is
`createReservation(bytes32,address,bytes32,bytes32,uint64,uint256,uint64,bool)`
(`0xd8f2bc55`); its final argument is the native Solidity/Python boolean
`providerFallbackAllowed` (no string or integer coercion), and the public
`reservations(bytes32)` getter returns nine static words with that flag last.
Settlement replay state is keyed by
`keccak256(abi.encode(reservationId, receiptHash))`, so callers must use
`receiptSettled(bytes32,bytes32)` (`0xaa061aa6`) and
`settlement(bytes32,bytes32)` (`0x28d93e69`) rather than receipt-hash-only
queries. `settlementKeyFor(bytes32,bytes32)` (`0x640b1ad5`) derives the key;
`settlementKeySettled(bytes32)` (`0xe24b6931`) queries an already-derived key.
The V3 event indexer confirms a local usage record only when the emitted
`receiptHash`, `reservationId`, and consumer address all match; receipt hash alone
is not a settlement identity.

MYCO rewards are globally disabled on deployment. Enabling them requires the
typed `scheduleRewardEnable()` timelock followed by `enableRewards()`;
`pauseRewards()` is immediate. Keep rewards disabled until an independently
audited anti-Sybil work/quality signal exists. Emission epochs start at the V3
deployment timestamp, halve every 208 weekly epochs (about four years), and
only successful token mints consume `epochMinted` capacity.

The testnet deployer creates an unrestricted-mint `TestUSDC`. That token is test
infrastructure only and must never be configured as the stablecoin in a
production deployment. Production requires a separately reviewed standard
stablecoin, multisig governance, RPC diversity, monitoring, and an external
contract audit.

V2 state is not copied automatically. A consumer migration is: stop new V2
work, settle or expire outstanding receipts, withdraw the available V2 balance,
revoke the old stablecoin allowance, approve and deposit into V3, then create a
request-bound V3 reservation for the selected provider and immutable pricing
version. Keep V2 read/indexer access until every old receipt and withdrawal has
been reconciled. The final V3 ABI is also incompatible with earlier V3
deployments: redeploy the contracts and recreate every outstanding reservation;
do not reuse old V3 calldata, signatures, deployment records or reservation
IDs. This also applies to reservations created with the legacy input-only
request hash: recreate them with the v2 inference envelope hash. See
[docs/settlement-v3-cli-integration.md](docs/settlement-v3-cli-integration.md)
for contract/CLI fields and
[docs/security-audit-and-remediation.md](docs/security-audit-and-remediation.md)
for unresolved production risks.

The on-chain reservation binds the payer, provider, channel, pricing version,
request v2 hash, amount, expiry and explicit fallback choice. The scoped EIP-191
authorization then binds that reservation and its exact payment/request fields
to the Ed25519 transport key. It neither authorizes another reservation nor
replaces the EIP-712 authorization required for final signed-receipt settlement.

## P2P Inference Provider

The gateway supports plaintext TCP JSON-lines for `local` integration and sealed
binary frames for non-local P2P inference. Non-local descriptors bind the
provider identity to a rotating X25519 transport key and reject plaintext
downgrades and replayed frames.

Start the local gateway manually when debugging the lower-level P2P commands:

```bash
python -m gateway serve --port 8000
```

Generate a provider key if needed:

```bash
python -m gateway key create --agent coder
```

For local provider onboarding, use the one-command path:

```bash
python -m gateway provider start \
  --pool http://127.0.0.1:9800 \
  --network-profile local \
  --consumer-public-key <consumer-public-key> \
  --payment-address <provider-evm-address> \
  --pricing-hash <channel-pricing-hash>
```

For local debugging, expose an already-running gateway as a P2P provider:

```bash
python -m gateway p2p serve \
  --port 9700 \
  --advertise-host 127.0.0.1 \
  --agent coder \
  --gateway-url http://127.0.0.1:8000/v1 \
  --network-profile local \
  --channel codex-standard-v1 \
  --consumer-public-key <consumer-public-key> \
  --allow-unreserved-requests
```

Ping a provider:

```bash
python -m gateway p2p ping 127.0.0.1:9700
```

Send one inference task through P2P:

```bash
python -m gateway p2p infer 127.0.0.1:9700 "只回复 OK"
```

For local throwaway testing only, a provider can use
`--allow-any-signed-consumer` and `--allow-unreserved-requests`. For any
settlement test, use an explicit `--consumer-public-key` and
`--payment-address`; V3 settlement and pricing defaults come from the bundled
manifest. For `testnet`, the Provider AI Gateway must also return `200` from
`/ready` with `settlement_ready=true`. Generic `openai_http` and `codex_cli`
fail that capability check. The explicit `codex_app_server` post-validation
policy can pass it only on Sepolia testnet; a correctly pinned
`native_metered_http` sidecar is the alternative with a generation-time cap.
Testnet Compose also requires `MYCOMESH_PROVIDER_EXTRA_ARGS` to be exactly empty,
so local bypass flags cannot override the production profile.

Paid P2P requests use the authenticated internal
`POST /mycomesh/p2p-infer` route, not the normal agent-facing OpenAI routes.
That path preserves the canonical consumer payload, adds no routing prompt or
session history, and binds the Provider execution commitment into the selected
testnet metering path.

Bootstrap one local provider to another:

```bash
python -m gateway p2p serve \
  --port 9701 \
  --network-profile local \
  --consumer-public-key <consumer-public-key> \
  --allow-unreserved-requests \
  --bootstrap 127.0.0.1:9700
python -m gateway p2p peers 127.0.0.1:9700
```

In this MVP, the generated gateway key is local to the provider node. External
peers never receive the key. They send P2P inference tasks to the provider; the
provider then calls its own local gateway with its local agent key.

## Provider Pool

The pool is a bootstrap directory for live P2P providers. Providers join the
pool and keep their registration alive with heartbeats; consumers discover live
providers from the pool, then use one of the providers' advertised transports.
Local transports use plaintext direct TCP or relay. Testnet transports use
signed `myco+tcp://`, `myco+relay://`, or TLS-control `myco+relays://`
descriptors with end-to-end sealed inference frames.

For non-local Providers, a successful signed join or heartbeat creates a
bounded in-memory Bridge readiness lease. The returned peer must match the
Provider ID, be `online`, and have an unexpired registration. P2P inference and
the production health check fail closed when every configured Bridge lease has
expired. Check it directly with:

```bash
python -m gateway p2p ping tcp://127.0.0.1:9700 --require-bridge-ready
```

Start a local pool:

```bash
python -m gateway pool serve \
  --host 127.0.0.1 \
  --port 9800 \
  --public-url http://127.0.0.1:9800 \
  --network-profile local
```

The default network profile is `testnet`, not `local`. Testnet always requires
signed Provider descriptors, secure non-local transports, direct public-address
verification, Provider payout addresses, and an explicit reputation-signer
allowlist. Provider identity admission is manually allowlisted by default. A
Bridge operator can instead pass `--allow-any-signed-provider` to admit any
cryptographically valid Provider identity that passes those remaining checks.
The flag defaults to false and removes only the manual Provider public-key list;
it does not create an unauthenticated or plaintext registration path. The
`open` mainnet profile remains reserved until staking, slashing, and dispute
handling are implemented.

Start an allowlisted testnet pool:

```bash
python -m gateway pool serve \
  --host 0.0.0.0 \
  --port 9800 \
  --public-url https://pool.example.com \
  --network-profile testnet \
  --provider-public-key <provider-node-public-key> \
  --reputation-signer-public-key <proxy-or-indexer-public-key>
```

Start a permissionless signed-Provider testnet Bridge:

```bash
python -m gateway pool serve \
  --host 0.0.0.0 \
  --port 9800 \
  --public-url https://bridge.mycomesh.xyz \
  --network-profile testnet \
  --allow-any-signed-provider \
  --trust-proxy-headers \
  --reputation-signer-public-key <proxy-or-indexer-public-key>
```

This public Nginx example assumes the Bridge listener is reachable only from
the controlled private/loopback reverse proxy. `--trust-proxy-headers` defaults
to false and should be enabled only when that proxy overwrites any inbound
value with exactly one `X-Real-IP` header. Do not enable it if a client can
reach the Bridge port directly or through an untrusted private-network peer.
The flag controls per-client rate-limit attribution and the address returned by
`/observed-ip`. When the Bridge is reached directly, leave it disabled so the
socket peer address remains authoritative.

This mode removes the Provider key onboarding step only. Initial permissionless admission accepts either signed `myco+tcp://`
literal-public-IP endpoints with direct callback proof, or relay-only
`myco+relays://` endpoints on an explicit trusted HTTPS Relay origin. Relay
admission sends an end-to-end sealed random ping and verifies the Provider
transport key, peer ID, signer, request ID and Bridge audience; Relay metadata
alone is never sufficient. This probe is a liveness-only address proof: it uses
a dedicated ping-only secure purpose and does not authorize inference.
Registration also requires a payment address and the pinned V4 settlement
capability. Each Provider independently remains fail-closed on its declared
metering policy, the V4 deployment, pricing, session sequence, and payment
validation. The Codex post-validation policy is
testnet-only; native metering remains required for an eventual open/mainnet
profile. Once those Provider settings are
complete, `make provider-up` joins the configured Bridge and renews the bounded
registration lease automatically; `make provider-health` fails when that lease
or Gateway settlement readiness is lost.

The Docker Provider defaults `MYCOMESH_PROVIDER_ADVERTISE_HOST=auto`. Before it
constructs the signed descriptor, it requests `/observed-ip` from every
configured Bridge. All Bridge URLs must be canonical HTTPS origins, redirects
are not followed, every response must be a global IPv4 address, and multiple
Bridges must agree. This discovers the Provider's outbound public address only;
the Bridge then connects back to the advertised port and verifies a fresh
challenge signed by the same Provider identity. Discovery is therefore not a
substitute for inbound reachability.

The container listens on `9700`, while `MYCOMESH_PROVIDER_ADVERTISE_PORT`
declares the externally reachable port. With the current Compose mapping, set
the host-published and advertised ports together when they differ from `9700`:

```bash
MYCOMESH_PROVIDER_PORT=19700
MYCOMESH_PROVIDER_ADVERTISE_PORT=19700
```

Open that TCP port in the host firewall/security group. If a router maps a
different public port to the host port, advertise the public-facing port. For
asymmetric NAT where the outbound address is not the inbound address, set
`MYCOMESH_PROVIDER_ADVERTISE_HOST` to the literal inbound public IPv4 instead of
`auto`; the Bridge callback still has to succeed. CGNAT or any network without
an inbound port mapping cannot run direct Provider transport and must use Relay
transport rather than advertising a guessed address.

The following provider/pool workflow is local-only. A testnet pool accepts only
secure provider descriptors and verifies the signed transport-key binding.
Inference still requires a provider backend that passes the production
capability gate.

Start a provider and join a local pool:

```bash
python -m gateway provider start \
  --provider-port 9700 \
  --advertise-host 127.0.0.1 \
  --agent coder \
  --network-profile local \
  --channel codex-standard-v1 \
  --pool http://127.0.0.1:9800 \
  --capacity 1 \
  --consumer-public-key <consumer-public-key> \
  --payment-address <provider-evm-address> \
  --pricing-hash <channel-pricing-hash>
```

List live providers in the pool:

```bash
python -m gateway pool peers --pool http://127.0.0.1:9800 --channel codex-standard-v1
```

Send one inference task through the pool:

```bash
python -m gateway pool infer \
  --pool http://127.0.0.1:9800 \
  --channel codex-standard-v1 \
  --consumer user-alice \
  --consumer-payment-address <consumer-evm-address> \
  --pricing-hash <channel-pricing-hash> \
  --accept \
  "只回复 OK"
```

The minimal pool lifecycle is:

```text
p2p serve = this machine can provide inference
pool join/heartbeat = this provider is available to the network
pool leave = signed provider removal from the pool
pool peers = consumers can discover usable providers
pool infer = consumers discover a provider, then try direct TCP or relay inference
```

Pools persist signed reputation feedback in `.codex-run/pool-reputation.json`
by default and include reputation scores in `pool peers`. Public pools should
start with `--reputation-signer-public-key <proxy-or-indexer-public-key>` for
each authorized feedback producer. `--allow-any-reputation-signer` is a local
development shortcut only. Reputation is only a routing signal: signed receipts,
accepted hashes, and settlement still define the economic trust boundary.

## Relay Transport

Relay transport lets a provider join an inference network without a public IP.
The provider opens an outbound connection to a relay and keeps it alive. A
consumer sends a task to the relay control endpoint; the relay forwards it over
the provider's existing outbound connection and returns the provider result.
Use this path for CGNAT or any host where no inbound TCP port can be mapped;
`MYCOMESH_PROVIDER_ADVERTISE_HOST=auto` cannot make such a direct node reachable.
Local `relay://` is plaintext. Non-local `myco+relay(s)://` carries end-to-end
sealed frames; use HTTPS control (`myco+relays://`) on public networks. The relay
authenticates outer metadata for routing/replay control but cannot decrypt the
prompt or provider result.

Start a relay:

```bash
python -m gateway relay serve \
  --host 127.0.0.1 \
  --advertise-host 127.0.0.1 \
  --control-port 9900 \
  --provider-port 9901 \
  --v3-admission-deployment deployments/sepolia-myco-v3.json \
  --v3-admission-rpc-url <sepolia-rpc-url> \
  --v3-admission-confirmations 6
```

V3 admission verifies the wallet authorization, signed Consumer session key and
confirmed onchain Reservation before forwarding a request. This admits ephemeral
browser Consumers without a static public-key allowlist. Add
`--consumer-public-key` only for a pinned V2 or Gateway compatibility identity.
For throwaway local development, `--allow-any-signed-consumer` accepts any valid
signed Consumer request; testnet rejects that bypass. A public Relay also needs a
TLS reverse proxy, persistent shared replay storage, connection/rate limits and
an external security review.

Start a provider behind NAT and join the pool through the relay:

```bash
python -m gateway provider start \
  --transport relay \
  --relay-host 127.0.0.1 \
  --relay-port 9901 \
  --relay-public-url http://127.0.0.1:9900 \
  --agent coder \
  --network-profile local \
  --channel codex-standard-v1 \
  --pool http://127.0.0.1:9800 \
  --capacity 1 \
  --consumer-public-key <consumer-public-key> \
  --payment-address <provider-evm-address> \
  --pricing-hash <channel-pricing-hash>
```

Consume through the pool as usual:

```bash
python -m gateway pool infer \
  --pool http://127.0.0.1:9800 \
  --channel codex-standard-v1 \
  --consumer user-alice \
  --consumer-payment-address <consumer-evm-address> \
  --pricing-hash <channel-pricing-hash> \
  --accept \
  "只回复 OK"
```

Pool entries can now advertise either direct or relay addresses:

```json
{
  "peer_id": "peer_xxx",
  "addresses": [
    "tcp://127.0.0.1:9700",
    "relay://127.0.0.1:9900/peer_xxx"
  ]
}
```

Consumers try the advertised addresses in order. Both forms are local-only
until authenticated transport encryption is available.

Pool URLs can be comma-separated. Consumers aggregate peers across all configured
bootstrap pools and deduplicate by `peer_id`, so a single pool is no longer the
only discovery entry point.

## Pricing And Receipts

The local pricing layer uses stablecoin accounting with protocol receipts. It
does not move funds by itself. Each channel has a stablecoin price, split rules,
and a protocol-token reward derived from treasury income.

Quote a task before running it:

```bash
python -m gateway pricing quote \
  --channel codex-standard-v1 \
  --input-tokens 1000 \
  --output-tokens 500
```

Default `codex-standard-v1` pricing:

```text
stablecoin: USDC
input_per_1k: 0.001
output_per_1k: 0.004
minimum_fee: 0.002
provider_share: 85%
relay_share: 3%
pool_share: 2%
treasury_share: 10%
```

Run inference and print pricing/receipt details:

```bash
python -m gateway pool infer \
  --pool http://127.0.0.1:9800 \
  --channel codex-standard-v1 \
  --consumer user-alice \
  --price \
  --receipt \
  --accept \
  "只回复 OK"
```

Successful `pool infer` calls append a JSONL receipt by default:

```bash
python -m gateway ledger receipts --ledger .codex-run/receipts.jsonl --limit 5
```

All append paths share one local-filesystem lock. A sidecar SQLite index tracks
inode and byte offset for incremental repair after rotation or a partial final
line; conflicting `job_id` payloads fail closed and one JSONL record is capped at
16 MiB. These guarantees require every writer to share the same local filesystem;
they do not make independent multi-host ledgers consistent.

Build MycoMesh protocol settlement blocks from accepted receipts:

```bash
python -m gateway ledger blocks \
  --ledger .codex-run/receipts.jsonl \
  --window-seconds 3600 \
  --output .codex-run/settlement-blocks.jsonl
```

These are MycoMesh settlement blocks, not physical L1/L2 blocks. Each block is a
fixed time window over local accepted receipts, linked by `previous_block_hash`,
and emits deterministic Provider, Bridge, and Consumer rewards from the receipt
`protocol_token_reward` budget. The default block reward split is Provider 80%,
Bridge 10%, Consumer 10%; override it with `--provider-reward-bps`,
`--bridge-reward-bps`, and `--consumer-reward-bps`. Bridge rewards include both
relay and pool contribution.

Multiple Bridge URLs can be supplied as a comma-separated pool list. Providers
register and heartbeat to each Bridge, while Consumers query all Bridges, merge
deduplicated providers, and record the actual pool/relay path used in the
receipt `bridge_usage` field:

```bash
python -m gateway provider start \
  --pool http://bridge-a:9800,http://bridge-b:9800,http://bridge-c:9800 \
  --network-profile local \
  --consumer-public-key <consumer-public-key> \
  --payment-address <provider-evm-address> \
  --pricing-hash <channel-pricing-hash>

python -m gateway pool infer \
  --pool http://bridge-a:9800,http://bridge-b:9800,http://bridge-c:9800 \
  --accept \
  "只回复 OK"
```

Settlement blocks prefer `bridge_usage` when present and only fall back to the
legacy `relay_id`/`pool_url` fields for older receipts.

Consumer block rewards are weighted by payment address, so a single address with
larger accepted spend receives a higher reward rate through a capped logarithmic
volume curve:

```text
reward_weight = spent_amount * min(max_multiplier, 1 + beta * ln(1 + spent_amount / base_spend))
```

The defaults are `base_spend=100`, `beta=0.2`, and `max_multiplier=2.0`.
Adjust them with `--consumer-volume-base-spend`, `--consumer-volume-beta`, and
`--consumer-volume-max-multiplier`.

Receipts include:

```text
consumer_id
provider_id
consumer_public_key
consumer_payment_address
provider_public_key
provider_payment_address
relay_id
bridge_usage
request_hash
response_hash
usage tokens
gross USDC fee
provider/relay/pool/treasury split
protocol token reward
pricing_config_hash
optional chain channel_pricing_hash
accepted_hash after consumer acceptance
```

Receipts are the bridge into settlement: the full prompt and response stay off
chain, while the chain stores the receipt hash, token usage, stablecoin split,
accepted receipt hash, and protocol token reward.

Production settlement is preceded by local protocol validation: the operator
checks the receipt signature, consumer acceptance signature, provider response
signature, consumer/provider payment addresses, and channel pricing hash before
building the EIP-712 settlement digest.

## Legacy V2 Ethereum Testnet Settlement

The first chain target is Sepolia. The P2P pool, relay, and inference path stay
off chain; Ethereum only handles prepaid balances, channel parameters,
settlement splits, treasury income, and MYCO reward minting.

The legacy V2 testnet system contains:

```text
TestUSDC              test stablecoin with 6 decimals
MycoToken             protocol reward token
MycoSettlementV2      prepaid balances, signed receipt settlement, split rules, rewards
MycoTestnetDeployer   one-shot deployer for the three contracts above
```

Default `codex-standard-v1` on-chain pricing matches the local quote command:

```text
input_per_1k: 0.001 tUSDC
output_per_1k: 0.004 tUSDC
minimum_fee: 0.002 tUSDC
provider/relay/pool/treasury: 85% / 3% / 2% / 10%
reward: 1 MYCO-denominated unit per configured treasury tUSDC unit
provider/consumer MYCO reward split: 90% / 10%
```

Compile and test contracts:

```bash
forge test --use /path/to/solc-0.8.28 --offline
```

Deploy to Sepolia:

```bash
export ETH_RPC_URL=https://sepolia.example-rpc
export PRIVATE_KEY=0x...
export TREASURY=0x...

python -m gateway chain deploy-myco-testnet \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --treasury "$TREASURY" \
  --solc /path/to/solc-0.8.28
```

Deployment output is saved to `deployments/sepolia-myco-v2.json`. The client derives
the child contract addresses from the deployer contract, so users do not need to
call ABI methods manually. The deploy command rebuilds the Foundry artifact when
`--solc` is supplied, sends the deployment transaction, accepts settlement
governance for the deployer wallet, and records the governance accept tx hash.
The testnet deployer sets the one-hour minimum governance delay before handing
off settlement ownership, so later privileged actions require scheduling.

On testnet, mint tUSDC to a consumer, approve settlement once, and deposit a
prepaid balance:

```bash
python -m gateway chain mint-test-usdc --to <consumer-address> --amount-usdc 10

# Run this with the consumer wallet private key.
python -m gateway chain approve-usdc \
  --deployment deployments/sepolia-myco-v2.json \
  --spender <myco-settlement-address> \
  --amount-usdc 10

python -m gateway chain deposit-prepaid \
  --deployment deployments/sepolia-myco-v2.json \
  --amount-usdc 10

python -m gateway chain prepaid-balance \
  --deployment deployments/sepolia-myco-v2.json \
  --account <consumer-evm-address>
```

Run inference through the pool and settle the latest local receipt:

```bash
python -m gateway pool infer \
  --pool http://127.0.0.1:9800 \
  --channel codex-standard-v1 \
  --consumer user-alice \
  --price \
  --receipt \
  --accept \
  "只回复 OK"

# Run this with an operator/delegate wallet private key. The consumer and
# provider wallets sign the printed EIP-712 digests outside the operator.
python -m gateway chain prepare-delegate-signatures \
  --deployment deployments/sepolia-myco-v2.json \
  --consumer-address <consumer-address> \
  --provider-address <provider-address> \
  --delegate <operator-or-upstream-address> \
  --consumer-nonce 1001 \
  --provider-nonce 1002

python -m gateway chain settle-delegated-prepaid-receipt \
  --deployment deployments/sepolia-myco-v2.json \
  --delegate <operator-or-upstream-address> \
  --consumer-nonce 1001 \
  --provider-nonce 1002 \
  --consumer-signature-json '{"r":"0x...","s":"0x...","v":27}' \
  --provider-signature-json '{"r":"0x...","s":"0x...","v":27}'
```

Consumers only use this gateway client. The client fixes the protocol contract
ABI, hash format, stablecoin decimals, and default channel id instead of asking
users to choose an Ethereum SDK.

## Local User Login

This login is for your gateway users, not for OpenAI/Codex.

Register a local user:

```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123","user_id":"user-alice"}'
```

Login:

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

The response returns `access_token`. Send it as `X-User-Token`:

```bash
curl http://127.0.0.1:8000/auth/me \
  -H "X-User-Token: <access_token>"
```

Set `REQUIRE_USER_AUTH=true` in `.env` if every gateway request must include `X-User-Token`.

## Child Agent Request

Each child agent uses the gateway as its OpenAI base URL and its own internal key as the API key.

```python
from openai import OpenAI

planner = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="planner-local-key",
)

response = planner.chat.completions.create(
    model="gpt-5.5",
    extra_headers={
        "X-User-Token": "optional-local-user-token",
        "X-User-ID": "user-001",
        "X-Workspace-ID": "repo-main",
        "X-Task-ID": "task-123",
        "X-Session-ID": "planner-session",
    },
    messages=[
        {"role": "user", "content": "Plan the code change for adding login rate limits."}
    ],
)

print(response.choices[0].message.content)
```

Responses API example:

```python
response = planner.responses.create(
    model="gpt-5.5",
    input="只回复 OK，测试 Responses API"
)

print(response.output_text)
```

Recommended routing headers:

- `Authorization: Bearer <agent-key>`: identifies the child agent
- `X-User-Token`: local gateway user token when `REQUIRE_USER_AUTH=true`
- `X-User-ID`: your end user or owner id
- `X-Workspace-ID`: repo/workspace id
- `X-Task-ID`: code task id
- `X-Session-ID`: child-agent conversation id within that task

If a child agent cannot send custom headers, it can put the same values in the request body:

```json
{
  "gateway_user_id": "user-001",
  "gateway_workspace_id": "repo-main",
  "gateway_task_id": "task-123",
  "gateway_session_id": "planner-session",
  "messages": []
}
```

The OpenAI-compatible `user` field is also accepted as a fallback user/session id.

## Session Behavior

When a session id is present, the gateway is stateful by default:

```text
user id + workspace id + task id + agent key + session id -> isolated stored conversation
```

For stateful calls, send only the new turn in `messages`; the gateway injects prior stored turns. If a child agent sends the full conversation every time, set `gateway_stateful=false` or omit the session id to avoid duplicate history.

Useful controls:

- `user`: OpenAI-compatible fallback user/session id
- `X-Session-ID`: session id header
- `gateway_session_id`: body field for clients that support extra body fields
- `gateway_stateful=false`: disable stored history for one request
- `gateway_clear_session=true`: clear the session before this request

## Inspect Or Clear Sessions

```bash
curl http://127.0.0.1:8000/gateway/sessions

curl -H "X-User-ID: user-001" \
  -H "X-Workspace-ID: repo-main" \
  -H "X-Task-ID: task-123" \
  http://127.0.0.1:8000/gateway/sessions

curl -X DELETE \
  -H "Authorization: Bearer planner-local-key" \
  -H "X-User-ID: user-001" \
  -H "X-Workspace-ID: repo-main" \
  -H "X-Task-ID: task-123" \
  http://127.0.0.1:8000/gateway/sessions/planner-session
```

## Agent Config

`agents.json` defines internal keys, roles, and per-agent prompts:

```json
{
  "agents": {
    "planner": {
      "keys": ["planner-local-key"],
      "role": "planner",
      "description": "Break a code task into ordered implementation steps.",
      "system_prompt": "You are the planner agent for code-change tasks."
    }
  }
}
```

These keys are your gateway's internal access tokens. They are not OpenAI API keys.

Optional per-agent restrictions:

```json
{
  "workspace_ids": ["repo-main"],
  "allowed_users": ["user-001"]
}
```

If these arrays are present, the gateway rejects requests outside the allowed user/workspace scope.
