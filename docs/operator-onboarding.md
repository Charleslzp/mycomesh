# Provider and Relay onboarding

Provider and Relay operators can configure local capacity from a browser. The
wizard listens on loopback only, uses a one-time URL token, and writes a 0600
public profile under `.mycomesh/operator/` (the npm launcher uses
`~/.mycomesh/provider/settings.json`). Provider signing identities are managed
automatically and persisted in the protected Docker volume; private signing
material never appears in the browser.

## Provider

Before installation, run the read-only local dependency check:

```bash
scripts/install-provider.sh --doctor
```

It checks GNU Make, the Docker CLI, Compose V2 and whether the Docker engine is
reachable. Blocked checks include recovery steps; exit code 64 means an item
still needs attention. It does not pull images, create settings, start Docker,
open a wallet, log into Codex or inspect economic balances. A successful doctor
run means local dependencies are available, not that a Provider is online.

```bash
make provider-start
```

This opens a local browser at a temporary `127.0.0.1` URL. Enter the public
payout address, or connect a browser wallet such as OKX to select it. Capacity
and usage limits have defaults and are collapsed under optional settings.
First save persists the runtime-managed signing identity before any wallet can
authorize it. A second local page then asks the payout wallet to approve that
identity once; the wallet alone signs and sends after user confirmation. The
page validates account, chain, contract and calldata, and the server independently
checks the pinned network authorization. Only then does the installer continue
to isolated Codex login (if needed), Provider startup and readiness checks.

Ordinary restarts reuse verified settings and independently check authorization.
If the wallet step was interrupted, only that step is reopened; no capacity or
payout reconfiguration is necessary. Failed RPC checks or missing authorization
are not reported as an online Provider. V10 controlled-test admission can use
network-funded capacity, so a normal Provider does not need to submit a
personal stake transaction. The network operator must provision the bounded
sponsorship budget first; this onboarding flow never moves funds or claims
that capacity is ready.

The settings page lists the current setup stages and gives restart instructions
after saving. Wallet authorization is marked verified only when the server has
checked it against the pinned network; saving public settings alone does not
mark it verified. After a successful save the page disables its save button
because the temporary setup server has finished. Return to the original terminal
to continue; if interrupted, rerun the same start command to resume from saved
settings. An unresolved wallet submission is checked before any new send.

The optional models and earnings section labels model names from the pinned
network manifest as **configuration only**. It does not probe account access or
claim that any model is callable. Capacity admission, gas, escrow and claimable
balances are also explicitly unchecked on this page. For V10 controlled tests,
network-funded capacity is separate from Provider-owned stake; the sponsorship
budget is bounded and the Provider cannot withdraw the sponsored principal.
Production sponsorship requires an independently reviewed reclaim and rotation
policy before public admission.

Wallet sends use an atomic persistent intent fence at
`~/.mycomesh/provider/authorization-state`, independent of checkout version and
temporary browser port. Unknown submissions remain blocked across tabs and
restarts until verified or investigated; they are never automatically repeated.
`MYCOMESH_PROVIDER_AUTHORIZATION_STATE_DIR` may name a dedicated absolute path,
but it must remain unchanged for the same identity. It contains public
transaction scopes/status only. No existing directory is moved or deleted.

The generated file is `.mycomesh/operator/provider.json`; it contains the
public payout address and serving limits. The protected runtime keeps its
signing identity in a separate mode `0600` volume. Existing Docker volumes are
never replaced by a different identity.

This describes the current source implementation, tested with local HTTP,
SQLite and simulated wallet responses—not a completed real-wallet acceptance
test. The published npm launcher still pins its older commit/image; these changes
require a newly built, reviewed image and launcher release before packaged users
receive them. The image installer runs the wizard inside that image and publishes
only host loopback; it does not require host Python. To change a profile without
repeating Codex login:

```bash
PROVIDER_IMAGE=ghcr.io/charleslzp/mycomesh-provider-codex@sha256:<digest> \
  make provider-configure
PROVIDER_IMAGE=ghcr.io/charleslzp/mycomesh-provider-codex@sha256:<digest> \
  make provider-up-image
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

The Provider wizard is loopback-only and accepts public settings only. The
protected runtime owns receipt signing. Provider earnings are claimed later by
the payout wallet; a claim transaction must be signed by that wallet at
withdrawal time.
For V8, V9 and V10, `make provider-claim-payout` fails closed instead of using the
internal signing identity or falling back to an older settlement command.
`make provider-authorize` only prints an unsigned wallet authorization plan;
it never requests a wallet private key or sends a transaction.
