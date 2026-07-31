# Provider and Relay onboarding

Provider and Relay operators can configure local capacity from a browser. The
wizard listens on loopback only, uses a one-time URL token, and writes a 0600
public profile under `.mycomesh/operator/`. Provider wallet identities are
staged in a separate 0600 file and copied into the protected Docker volume
only after validation.

## Provider

```bash
make provider-start
```

This opens a local browser at a temporary `127.0.0.1` URL. Select one of these
Provider wallet sources:

- **Protected Provider wallet** keeps the identity already in the Docker volume.
- **New local wallet** generates a key locally, shows it once for backup, and
  requires the first and last four characters as a backup acknowledgement.
- **Import existing private key** derives the address and performs a local
  sign/recover check before staging the identity.

The address is derived from the signing key and cannot be entered separately.
Configure maximum concurrent inference requests, an optional maximum usage in
USDC, and the period length in seconds. After saving, the command runs the
existing isolated Codex login step (if needed) and starts the Provider.

The generated file is `.mycomesh/operator/provider.json`; it contains only the
wallet source, derived public address, and short fingerprint. The separate
`.mycomesh/operator/provider-evm-identity.json` file is mode 0600 and contains
the signing key used for startup. Never commit or share it. Existing Docker
volumes are never replaced by a different identity.

The npm/image installer opens this same page automatically when the profile is
missing. To change an existing profile without repeating Codex login:

```bash
make provider-configure
IMAGE_TAG=sha-<published-commit> make provider-up-image
make provider-health
```

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

The Provider wizard is loopback-only and accepts a private key only for the
explicit import option. Never paste a key into a remote page, URL, chat, or
environment variable. A browser extension can prove ownership with a signed
nonce, but it cannot sign unattended Provider receipts unless an external
signer is configured.
