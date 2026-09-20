# Local Consumer

The Consumer is a native Node.js process on the user's machine. It binds only
to `127.0.0.1:8110`, exposes an OpenAI-compatible API at
`http://127.0.0.1:8110/v1`, and serves the credential page at `/`.

It does not use Docker, Python, Compose, a public Gateway, or a browser
conversation store. Relay discovery, payment-key signing, failover, receipt
verification, history, and the stable loopback URL all live in this one
process.

## Start

```sh
npm install --global mycomesh-consumer
mycomesh-consumer
```

For the fixed-budget V10 controlled testnet, opt in explicitly:

```sh
mycomesh-consumer --v10-controlled-test
```

This selects the bundled V10 network manifest, pinned Relay fallbacks and its
CA certificate. The controlled committee is not the production default. The
Consumer remains locked until the wallet owns its payment key and an active
fixed-budget channel covers the selected model.

The default command is service-only; it does not start Codex or bind the
Consumer lifecycle to a Codex process. For a headless process:

```sh
mycomesh-consumer --no-browser
curl -sS http://127.0.0.1:8110/health
```

Each Consumer process starts locked. Open the local page and sign the one-time
message with the wallet that owns this payment key's on-chain grant. Until that
check passes, `/credentials`, the export block, temporary sharing, and
inference stay unavailable. For an unregistered local key, use **Activate
Key** once; the wallet submits `registerKey`, then the Consumer verifies the
grant before revealing the key.

After unlocking Consumer, use the local page's copy-export button, paste that
export into your client terminal, then run `codex`. The credentials endpoint
requires the local management session; an unauthenticated curl is rejected.

`mycomesh-consumer --codex` is an optional convenience wrapper; it is not
required for the Consumer or payment-key inference.

The command prints the local setup URL. After wallet verification, the page
shows the export block, payment key/address, prepaid balance, key actions, and
consumption history. It does not show a conversation list or request-session
controls.

The key is stored at `~/.mycomesh/consumer/payment-key` with mode `0600` and
history is appended to `receipt-history.jsonl`. Set
`MYCOMESH_CONSUMER_DATA_DIR` to move both files. `--stop` stops the native
process while preserving this state; an explicit reset requires
`MYCOMESH_CONFIRM_RESET=RESET`.

## Credentials

The page's export block is equivalent to:

```sh
export OPENAI_BASE_URL='http://127.0.0.1:8110/v1'
export OPENAI_API_KEY='myco_sk_...'
```

The key is a reusable payment credential. V8 signs each request against its
key grant; V10 signs a request-bound authorization against a fixed capacity
channel. The Relay maps the payment key to its pinned network route and settles
the signed receipt. Wallet login is required once after every Consumer start,
while normal inference never asks for a per-request wallet signature.

## Relay and provider scheduling

The Consumer checks the selected protocol's health document for every configured Relay. If a
Relay has no live Provider, times out, or returns a retryable status, the next
Relay is tried automatically. The request ID is retained across attempts so
the payment scope does not change during failover.

```sh
export MYCOMESH_V8_RELAY_URLS='https://relay-a.example,https://relay-b.example'
mycomesh-consumer --proxy http://127.0.0.1:10792
```

The default is `https://bridge.mycomesh.xyz`. A proxy is an optional native
Node outbound dispatcher; it is not a container bridge.

For an explicit controlled V10 manifest outside the bundled package, pass both
the manifest and the opt-in flag. A private CA is accepted only in this mode:

```sh
mycomesh-consumer --controlled-test \
  --network-config ./network.json --ca-file ./ca.crt
```

The CA file must be distributed with a trusted, pinned network manifest. TLS
verification is never disabled; an untrusted Relay returns
`relay_tls_untrusted`. `/models` reports whether each model has multiple Relay
routes or only a single route.

## Top-up and key operations

The local page builds `approve`, `deposit`, `registerKey`, and `revokeKey`
transaction plans for the verified wallet. Private keys are never sent to the
Consumer, Relay, or Provider. Key rotation creates a new local key, waits for
its on-chain grant, switches the Consumer to it, and revokes the previous key.
If a payment key has leaked, revoke it with its owner wallet; the local startup
lock prevents accidental reuse on this device but cannot revoke a leaked bearer
key elsewhere.

## API compatibility

The native edge supports `/responses`, `/responses/compact`, and
`/chat/completions` under the usual `/v1` aliases, `/models`, `/health`, and
buffered OpenAI-compatible SSE. It forwards the Relay's `PAYMENT-RESPONSE`
header after validating the signed receipt. The request CLI remains
stateless and accepts standard OpenAI-shaped JSON.
