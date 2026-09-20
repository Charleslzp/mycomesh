# mycomesh-consumer

Native Node.js Consumer for the MycoMesh Settlement V8 Relay network. It runs
on the user's machine with no Docker, Python runtime, Compose file, or public
Gateway dependency.

## Install

Requirements: Node.js 20 or newer. The package contains only the small
cryptographic dependencies needed for V8 EIP-712 payment-key authorizations;
Codex is an independent client.

```sh
npm install --global mycomesh-consumer
mycomesh-consumer
```

The default remains the public V8-compatible network for existing installs.
The pinned V10 fixed-budget committee is a controlled testnet and must be
selected explicitly:

```sh
mycomesh-consumer --v10-controlled-test
```

This option uses the manifest and private testnet CA shipped in the package,
pins both test Relays, and requires the wallet to fund an active fixed budget
channel. It is not a production network and does not enable token rewards or
independent arbitration.

For a checkout:

```sh
npm install --global ./packages/mycomesh-cli
```

The command starts the Consumer API on `127.0.0.1:8110`, prints and optionally
opens the local credentials page, and stays available for any
OpenAI-compatible client. It does not start or configure Codex.

The page starts with a wallet signature check. The selected wallet must match
the local payment key's active on-chain grant before the API key/export and
inference are enabled. It exposes only the local API URL, payment key/export,
prepaid balance, key operations, and local consumption history. It has no
conversation or request-session UI. The payment key is generated once and stored at
`~/.mycomesh/consumer/payment-key` with mode `0600`; set
`MYCOMESH_CONSUMER_DATA_DIR` to choose another directory.

## Connect a client

The default command is already service-only. Sign in on the local page first,
then load the export block into a shell and use Codex or another compatible
client:

```sh
mycomesh-consumer --no-browser
```

Open the printed setup URL, sign in, and use **Copy export** on the local page.
Paste the export into the client terminal, then run `codex`. An unauthenticated
request to `/credentials` is rejected even after the wallet is unlocked.

The optional convenience wrapper is explicit:

```sh
mycomesh-consumer --codex
```

Use `--no-browser` on a headless machine. Stop the process without deleting
the key or history with `mycomesh-consumer --stop`. A full reset is explicit:

```sh
MYCOMESH_CONFIRM_RESET=RESET mycomesh-consumer --reset-local
```

The local API is OpenAI-compatible:

```sh
export OPENAI_BASE_URL=http://127.0.0.1:8110/v1
export OPENAI_API_KEY='myco_sk_...'
mycomesh responses --input 'hello' --model gpt-5.5
```

The browser's export block is the canonical way to obtain both values after
wallet verification. `--codex` waits for that verification before launching
Codex.

## Temporary sharing

The local page can create one time-limited HTTPS API URL and an independent
`myco_share_...` key for testing an OpenAI-compatible client outside the
Consumer machine. Install `cloudflared`, choose a lifetime, and click **Start
sharing**. The public endpoint exposes only models, Responses, Chat
Completions, and Codex search routes; it does not expose the dashboard or the
payment key. Stopping the share, reaching its expiry, or restarting the
Consumer invalidates the temporary key.

## Relay scheduling and V8 payments

The Consumer checks each configured Relay's selected protocol health (V8 by
default, or V10 when explicitly selected) and automatically tries the next
Relay after a health, timeout, or retryable HTTP failure. A single
request ID is preserved across failover. Each attempt carries a fresh V8
EIP-712 payment authorization signed by the persisted key; the Relay resolves
the key address to its on-chain grant and settles the signed receipt. A wallet
signature unlocks each Consumer process once; inference has no per-request
wallet signature or Consumer-managed conversation state.

Configure multiple Relay origins and an optional outbound proxy:

```sh
export MYCOMESH_V8_RELAY_URLS='https://relay-a.example,https://relay-b.example'
mycomesh-consumer --proxy http://127.0.0.1:10792
```

The default Relay is `https://bridge.mycomesh.xyz`. The V8 deployment and RPC
defaults are embedded in the package; `MYCOMESH_CONSUMER_NETWORK_CONFIG` and
`MYCOMESH_CONSUMER_SETTLEMENT_RPC_URLS` can override them for another network.
For the controlled V10 path, use `--v10-controlled-test` or provide an
equivalent manifest with `--network-config` and `--controlled-test`.

## Stateless request CLI

The package also keeps the stateless API commands:

```sh
mycomesh health
mycomesh models
mycomesh responses --input 'Summarize this' --max-output-tokens 500
mycomesh chat --message 'Explain this function'
```

Use `--json @file`, `--json -`, or piped JSON for complete OpenAI-shaped
requests. `--stream` returns buffered-compatible SSE events from the Relay.

## Development

```sh
cd packages/mycomesh-cli
npm test
```
