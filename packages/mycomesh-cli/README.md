# mycomesh-consumer

Native Node.js Consumer for the MycoMesh Settlement V8 Relay network. It runs
on the user's machine with no Docker, Python runtime, Compose file, or public
Gateway dependency.

## Install

Requirements: Node.js 20 or newer. The package includes the official Codex
dependency and the small cryptographic dependencies needed for V8 EIP-712
payment-key authorizations.

```sh
npm install --global mycomesh-consumer
mycomesh-consumer
```

For a checkout:

```sh
npm install --global ./packages/mycomesh-cli
```

The command starts `127.0.0.1:8110`, prints and optionally opens the local
credentials page, waits for a healthy Settlement V8 Relay, and launches Codex
with a one-run `mycomesh` provider configuration. It does not edit Codex files.

The page exposes only the local API URL, payment key/export, prepaid balance,
key operations, and local consumption history. It has no conversation or
request-session UI. The payment key is generated once and stored at
`~/.mycomesh/consumer/payment-key` with mode `0600`; set
`MYCOMESH_CONSUMER_DATA_DIR` to choose another directory.

## Service-only mode

Keep the native Consumer running without launching Codex:

```sh
mycomesh-consumer --no-codex
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
mycomesh responses --input 'hello' --model mycomesh-codex-standard-v1
```

The browser's export block is the canonical way to obtain both values.

## Relay scheduling and V8 payments

The Consumer checks each configured Relay's V8 health and automatically tries
the next Relay after a health, timeout, or retryable HTTP failure. A single
request ID is preserved across failover. Each attempt carries a fresh V8
EIP-712 payment authorization signed by the persisted key; the Relay resolves
the key address to its on-chain grant and settles the signed receipt. No wallet
signature or Consumer-managed conversation state is involved in inference.

Configure multiple Relay origins and an optional outbound proxy:

```sh
export MYCOMESH_V8_RELAY_URLS='https://relay-a.example,https://relay-b.example'
mycomesh-consumer --proxy http://127.0.0.1:10792
```

The default Relay is `https://bridge.mycomesh.xyz`. The V8 deployment and RPC
defaults are embedded in the package; `MYCOMESH_CONSUMER_NETWORK_CONFIG` and
`MYCOMESH_CONSUMER_SETTLEMENT_RPC_URLS` can override them for another network.

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
