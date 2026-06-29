# MycoMesh Gateway

This is the MycoMesh execution gateway and local orchestrator for multi-agent code automation. Child agents call it with the OpenAI Chat Completions HTTP protocol, while the gateway maps each request to a user, workspace, code task, child agent, and session before forwarding it to one central inference backend.

Do not put your OpenAI or Codex account password into this project. Use either an OpenAI-compatible API key, or run the official `codex login` command yourself and let the gateway call the local Codex CLI login state.

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

Tool calls and JSON response formats have compatibility shims for SDK/test compatibility, but Codex is still the actual backend. Unsupported endpoints return an OpenAI-style JSON error instead of silently failing. With `GATEWAY_BACKEND=openai_http`, unsupported local routes are proxied to the configured upstream.

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
CENTER_MODEL=your-central-model
PUBLIC_MODEL_ID=gpt-5.5
DEFAULT_USER_ID=local-user
DEFAULT_WORKSPACE_ID=default-workspace
```

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

Call the local or public `/health` endpoint:

```bash
python -m gateway health --port 8000
python -m gateway health --public --port 8000
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

## MycoMesh V2 Network Layer

MycoMesh is the decentralized inference-network mode built on top of this
gateway. The v2 prototype adds the safety boundaries needed before opening a
provider pool:

- Provider pool entries are signed Ed25519 node descriptors, and direct
  `tcp://` addresses are probed by default before entering the live pool.
- P2P and relay inference requests are signed by the consumer identity and
  carry a signed payment reservation. Providers verify the reservation pricing
  hash and minimum fee before calling the local Codex gateway.
- Relay provider registration is signed, so another node cannot trivially steal
  an existing `peer_id`.
- Receipts include protocol version, consumer/provider public keys, hashes,
  pricing, settlement deadlines, operator signatures, and optional consumer
  acceptance signatures.
- Consumers can call an OpenAI-compatible MycoMesh proxy with only `base_url`
  and `api_key`.
- The proxy reserves prepaid balance before dispatching work and captures the
  actual fee after a valid response, so unpaid consumers cannot freely consume
  provider quota.
- Account API keys can be suspended or closed, and reserve/capture operations
  are idempotent around reservation ids and receipt event ids.
- Provider and relay request ids are replay-checked; CLI-launched providers use
  the persistent `MYCOMESH_REPLAY_DB` store by default.
- MycoMesh settlement v2 supports prepaid stablecoin balances, withdrawal,
  signed prepaid receipt settlement, delegated settlement authorization, batch
  settlement preparation, treasury buyback burn hooks, and MYCO reward minting
  capped by epoch emission.

Create a local MycoMesh API account and credit test balance:

```bash
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
same freshness metadata so the proxy can prove the cache came from the expected
chain and settlement contract:

```bash
python -m gateway mycomesh account sync-balance acct-alice \
  --balance-usdc 10 \
  --chain-id 11155111 \
  --settlement <myco-settlement> \
  --latest-block <latest-observed-block> \
  --synced-block <confirmed-synced-block> \
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

# You can still force one account balance read for recovery/debugging:
python -m gateway mycomesh indexer sync \
  --deployment deployments/sepolia-myco-v2.json \
  --account acct-alice

python -m gateway mycomesh account cleanup-reservations --max-age-seconds 900
```

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

Run a signed provider node. The node identity is created automatically at
`.codex-run/node-identity.json` unless `--identity` is supplied:

```bash
python -m gateway p2p serve \
  --port 9700 \
  --advertise-host 127.0.0.1 \
  --agent coder \
  --gateway-url http://127.0.0.1:8000/v1 \
  --network-profile testnet \
  --pool http://127.0.0.1:9800 \
  --consumer-public-key <proxy-consumer-public-key> \
  --payment-address <provider-evm-address> \
  --pricing-hash <channel-pricing-hash>
```

For production-like runs:

- Set `MYCOMESH_STRICT_CHAIN_PRICING=1` and provide `ETH_RPC_URL` plus
  `MYCO_SETTLEMENT` so providers and proxies read `channelPricingHash(bytes32)`
  from the settlement contract.
- Keep `MYCOMESH_REQUIRE_PROVIDER_SETTLEMENT_FIELDS=1` so proxies only route to
  providers with signed public keys and payment addresses.
- Require consumer account `payment_address` outside local billing mode, or set
  `MYCOMESH_REQUIRE_CONSUMER_PAYMENT_ADDRESS=1` for local settlement dry-runs.
- Keep `MYCOMESH_REPLAY_DB` on durable local storage for providers and relays.

Strict mode only accepts chain pricing or an explicit
`MYCOMESH_CHANNEL_PRICING_HASH`; local pricing config is a development fallback.

Deploy the MycoMesh v2 testnet contracts:

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

## P2P Inference Provider

The current gateway can run as the local execution client for a P2P inference
provider. The first P2P version uses a direct TCP JSON-lines protocol so the
useful-work path can be tested before adding DHT/libp2p discovery.

Start the local gateway:

```bash
python -m gateway serve --port 8000
```

Generate a provider key if needed:

```bash
python -m gateway key create --agent coder
```

Expose this gateway as a P2P provider:

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
`--allow-any-signed-consumer` and `--allow-unreserved-requests`. Public and
testnet providers should use `--consumer-public-key`, `--payment-address`, and
`--pricing-hash` so the provider only serves the proxy identity it trusts and
can settle accepted work.

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
providers from the pool, then use one of the provider's advertised transports.
The first transports are direct TCP and relay.

Start a local pool:

```bash
python -m gateway pool serve \
  --host 127.0.0.1 \
  --port 9800 \
  --public-url http://127.0.0.1:9800 \
  --network-profile local
```

The default network profile is `testnet`, not `local`. A testnet pool is
allowlisted by design: it requires explicit provider public keys, explicit
reputation signer public keys, signed provider descriptors, direct address
verification, and provider payout addresses. The `open` profile is reserved
until staking, slashing, and dispute handling are implemented.

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

Start a provider and join the pool:

```bash
python -m gateway p2p serve \
  --port 9700 \
  --advertise-host 127.0.0.1 \
  --agent coder \
  --gateway-url http://127.0.0.1:8000/v1 \
  --network-profile testnet \
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

Relay transport lets a provider join the inference network without a public IP.
The provider opens an outbound connection to a relay and keeps it alive. A
consumer sends a task to the relay control endpoint; the relay forwards it over
the provider's existing outbound connection and returns the provider result.

Start a relay:

```bash
python -m gateway relay serve \
  --host 0.0.0.0 \
  --advertise-host <relay-public-host> \
  --control-port 9900 \
  --provider-port 9901 \
  --consumer-public-key <proxy-consumer-public-key>
```

`--consumer-public-key` is required by default. For local development only,
`--allow-any-signed-consumer` lets the relay accept any valid signed consumer
request; public relays should use an explicit allowlist so the relay control
plane filters unauthorized inference requests before forwarding work to NATed
providers.

Start a provider behind NAT and join the pool through the relay:

```bash
python -m gateway p2p relay \
  --relay-host <relay-public-host> \
  --relay-port 9901 \
  --relay-public-url http://<relay-public-host>:9900 \
  --agent coder \
  --gateway-url http://127.0.0.1:8000/v1 \
  --network-profile testnet \
  --channel codex-standard-v1 \
  --pool http://<pool-public-host>:9800 \
  --capacity 1 \
  --consumer-public-key <consumer-public-key> \
  --payment-address <provider-evm-address> \
  --pricing-hash <channel-pricing-hash>
```

Consume through the pool as usual:

```bash
python -m gateway pool infer \
  --pool http://<pool-public-host>:9800 \
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
    "tcp://node.example.com:9700",
    "relay://relay.example.com:9900/peer_xxx"
  ]
}
```

Consumers try the advertised addresses in order. Direct TCP is still useful for
public nodes, while relay is the practical fallback for home networks, CGNAT,
and locked-down office networks.

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

Receipts include:

```text
consumer_id
provider_id
consumer_public_key
consumer_payment_address
provider_public_key
provider_payment_address
relay_id
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

## Ethereum Testnet Settlement

The first chain target is Sepolia. The P2P pool, relay, and inference path stay
off chain; Ethereum only handles prepaid balances, channel parameters,
settlement splits, treasury income, and MYCO reward minting.

The testnet system contains:

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
