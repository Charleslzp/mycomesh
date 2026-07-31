# Local Consumer

The `consumer` Compose profile is the end-user edge. It listens only on
`127.0.0.1:8110`, exposes an OpenAI-compatible API at
`http://127.0.0.1:8110/v1`, and serves the wallet UI at
`http://127.0.0.1:8110/app/playground`.

The local process owns the parts that must survive a blocked public domain:

- signed Provider discovery and route health, using the manifest list or the
  independent origins in `MYCOMESH_CONSUMER_DISCOVERY_URLS`;
- the durable V5 Session store, request sequence, session-key derivation and
  Provider/Relay retry path;
- the stable local URL used by Codex and other OpenAI-compatible clients.

The public Gateway is not required by this path. Discovery origins are signed
and checked against the local V5 manifest; configure several independent HTTPS
origins when a single Bridge domain is not reliable:

```bash
export MYCOMESH_CONSUMER_DISCOVERY_URLS=https://bridge-a.example,https://bridge-b.example
make consumer
```

## Start

```bash
make consumer
```

For service-only startup and manual Codex launch:

```bash
make consumer-up
make consumer-health
make consumer-credentials
```

`consumer` starts the service, waits for the loopback health check, and opens
`http://127.0.0.1:8110/app/playground` in the system browser. The first screen
bootstraps the volume-local API key, asks for an injected or WalletConnect
wallet, lets you choose the prepaid Session limit, and then submits the exact
ERC-20 approval/deposit plus the one-time V5 `openSession` transaction. After
the chain receipt is verified it shows the local Codex command:

```bash
eval "$(make consumer-codex-env)" && codex
```

After the Session is verified, `consumer` starts the host Codex process itself.
Use `make consumer-up` followed by `make consumer-codex` when launching Codex
separately.

The bundled image always supports injected browser wallets. To show a
WalletConnect QR option as well, set the public `VITE_WALLETCONNECT_PROJECT_ID`
when building the Web bundle; it is never a secret or a wallet credential.

On a headless server, skip the browser while keeping the same service startup:

```bash
MYCOMESH_NO_BROWSER=1 make consumer-up
```

`consumer-credentials` prints the loopback base URL, the volume-local API key,
and the public Consumer identity. The key, identity private key, Session secret,
and SQLite state are stored under the protected `mycomesh-consumer-data`
volume. The HTTP API never returns the Session private key or accepts an EVM
private key.

Inspect status without printing the API key:

```bash
docker compose --profile consumer exec consumer \
  python -m gateway.local_consumer status

curl -sS -H "Authorization: Bearer $LOCAL_MYCOMESH_API_KEY" \
  http://127.0.0.1:8110/v1/mycomesh/local/status
```

## Wallet And Session

Open the local Playground and connect an injected browser wallet or a
WalletConnect-compatible third-party wallet. The onboarding performs the chain
checks, exact token approval/deposit and the one-time V5 `openSession` transaction.
The local Consumer receives only the public wallet address and the activated
Session metadata; it verifies the Session on-chain before routing each request.

For a headless setup, register only a public address:

```bash
docker compose --profile consumer exec consumer \
  python -m gateway.local_consumer init-wallet --address 0xYOUR_CONSUMER_WALLET
```

Then prepare a route-bound Session. The returned plan is opened in the local
Playground wallet, or by another local signer that you control:

```bash
curl -sS -X POST http://127.0.0.1:8110/v1/mycomesh/session/prepare \
  -H "Authorization: Bearer $LOCAL_MYCOMESH_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"mycomesh-codex-standard-v1","max_output_tokens":256}'
```

Do not send a wallet private key to this API. Private-key import, when used,
must stay in a local wallet/signer process and must never be put in Compose
environment variables, browser requests, or Provider/Relay traffic. The
supported default is an injected/third-party wallet because it keeps funds and
transaction approval outside the Consumer container.

Once the Session is active, send normal OpenAI-shaped requests with the local
key and Session ID:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8110/v1
export OPENAI_API_KEY="$LOCAL_MYCOMESH_API_KEY"
export MYCOMESH_SESSION_ID=0xYOUR_ACTIVE_SESSION_ID

curl -sS "$OPENAI_BASE_URL/responses" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d @- <<JSON
{"model":"mycomesh-codex-standard-v1","input":"hello","mycomesh_session":{"session_id":"$MYCOMESH_SESSION_ID"}}
JSON
```

The npm CLI defaults to the same loopback base URL. Use `make consumer-codex-env`
to print shell exports and apply them with `eval` in the current shell; it does
not modify Codex files or send credentials to a public URL.

`/health` describes process liveness. `/ready` becomes `200` only after the
local Consumer has verified a live V5 Session; before that it returns a
structured `503` with the wallet or Session blocker. This is intentional:
discovery and session preparation can run while inference remains fail-closed.

The network, model, channel, pricing hash, Settlement V5 contract, and default
Bridge seed come from `deployments/sepolia-provider-network.json`. There is no
fixed Gateway URL in the Consumer service configuration.
