# Provider and Relay onboarding

Provider and Relay operators can configure the public payout address and local
capacity from a browser without putting a private key into a form or an
environment variable.  The wizard listens on loopback only, uses a one-time
URL token, and writes a 0600 profile under `.mycomesh/operator/`.  Compose
copies that profile into the role's protected Docker volume before startup.

## Provider

```bash
make provider-start
```

This opens a local browser at a temporary `127.0.0.1` URL.  Enter the public
EVM payout address, maximum concurrent sessions, optional maximum usage in
USDC, and the period length in seconds.  After saving, the command runs the
existing isolated Codex login step (if needed) and starts the Provider.

The generated file is `.mycomesh/operator/provider.json`.  It contains no
private key.  The Provider's V5 payout identity still has to be imported or
created in its protected Docker volume and must match the public address.

## Relay

```bash
make relay-start
```

The Relay wizard uses the same fields.  Its maximum concurrent sessions is
applied to the Relay's signed consumer in-flight limit.  The Relay payout
address is public; its online-attestation private key remains in the Relay
volume and is never accepted by the wizard.

The same Relay role can submit V5 receipts. Configure its protected
transaction identity separately with `MYCOMESH_RELAY_SETTLEMENT_RPC_URL` and
`MYCOMESH_RELAY_SETTLEMENT_PRIVATE_KEY`; fund only the derived transaction
relayer address with native gas. This key is not the payout key and is not the
attestation key. The Relay persists Consumer receipts at `/v5/settlements`
before submitting them. It submits up to eight ordered receipts per
transaction by default (the V5 contract permits at most 32) and halves a
batch after a revert to isolate a bad receipt, so no standalone keeper process
is required.

To print only the public gas address after configuring the protected key:

```bash
make relay-transaction-address
```

For a headless deployment, skip the wizard and set the existing Compose
variables directly (`MYCOMESH_PROVIDER_PAYMENT_ADDRESS`,
`MYCOMESH_PROVIDER_CAPACITY`, `MYCOMESH_RELAY_PAYMENT_ADDRESS`, and
`MYCOMESH_RELAY_CONSUMER_MAX_IN_FLIGHT`). For a Relay configured above the
default 128 slots, also set `MYCOMESH_RELAY_CONTROL_MAX_CONNECTIONS` to at
least the same value. The usage limit and period are
persisted and exported to the role runtime as
`*_USAGE_LIMIT_UNITS`/`*_USAGE_PERIOD_SECONDS`; zero means unlimited.  The
public network's settlement manifest and on-chain authorization remain the
source of truth for payout addresses.

The wizard is intentionally not a wallet: use an injected wallet or a
separate local signer for any chain transaction.  Never paste an EVM private
key, seed phrase, access token, or API key into the browser.
