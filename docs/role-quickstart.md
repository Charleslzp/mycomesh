# MycoMesh Role Quickstart

This guide starts from a clean Git checkout and separates canonical-network
users from infrastructure operators. A command listed for one role is not a
prerequisite for every other role.

## Choose One Role

| External role | Runs continuously | Credentials/state | Start path |
| --- | --- | --- | --- |
| Consumer | Optional local process | Wallet, local session key, local receipt outbox | Web app, npm CLI, or `make consumer` |
| Provider | Yes | Isolated Codex login, node identity, Provider EVM identity | Provider installer |
| Relay | Yes | Public payout address, attestation identity, gas-funded transaction identity | `make relay-start` |

Bridge discovery, the transaction keeper, and the HTTP/API proxy are internal
modules of these three roles. They are not additional operator roles. Docker is
normally used for Provider and Relay; the Consumer can run locally without a
fixed public Gateway URL.

## Consumer: Web First, CLI Second

The canonical V5 flow uses the wallet only for funding and one bounded Session
activation. Each later inference request uses the API key and active Session ID;
it does not request a wallet transaction per prompt.

### 1. Register Consumer access

Open `https://app.mycomesh.xyz/app/access`, connect the intended Sepolia wallet
and create a wallet-bound API key. Copy the key when it is shown. The Gateway
stores its hash, not the plaintext key, and the browser keeps the complete value
only in the current tab.

An API key is scoped to its Gateway origin. A key created for
`gateway.mycomesh.xyz` is not a credential for another operator's Proxy.

### 2. Fund the V5 escrow

Open `https://app.mycomesh.xyz/app/funds`. On Sepolia, the page can mint test
tUSDC with no monetary value. Select **Deposit**, approve the exact amount, then
deposit it into the verified V5 Settlement contract. Approval and deposit are
separate wallet transactions.

### 3. Open one V5 Session

Open `https://app.mycomesh.xyz/app/playground` and submit the first request. The
Gateway prepares a Provider-bound plan and the wallet asks for one `openSession`
transaction. Wait until the page reports **Prepaid session active**.

After the first response, expand **Price and receipt envelope** and record
`session.session_id`. The Session ID is not a private key, but it is valid only
with the API key/account and wallet that funded that Session.

### 4. Use the npm CLI

Install the public Consumer package with Node.js 20 or newer:

```bash
npm install --global mycomesh-consumer
```

The installed commands are `mycomesh-consumer` and the shorter `mycomesh`; they
are equivalent. For a local checkout, the equivalent command is
`npm install --global ./packages/mycomesh-cli`.

To avoid a global install, use `npx`:

```bash
npx --yes --package=mycomesh-consumer mycomesh-consumer health
```

Configure the canonical origin and the values retained above:

```bash
export MYCOMESH_BASE_URL=https://gateway.mycomesh.xyz/v1
export MYCOMESH_API_KEY='replace-with-wallet-bound-mycomesh-key'
export MYCOMESH_SESSION_ID='0x...replace-with-active-v5-session-id'

mycomesh health
mycomesh models
```

Include the Session ID in every paid canonical request:

```bash
mycomesh responses \
  --model mycomesh-codex-standard-v1 \
  --input "Summarize this text" \
  --max-output-tokens 500

mycomesh chat \
  --model mycomesh-codex-standard-v1 \
  --message "Explain this function" \
  --max-completion-tokens 500
```

The CLI validates `MYCOMESH_SESSION_ID` as a 32-byte hex value and adds the
`mycomesh_session` extension object automatically. `--session-id 0x...` is the
per-command equivalent and overrides the environment value.

The CLI is stateless. It does not register API keys, connect wallets, approve or
deposit tokens, prepare a Session, or submit `openSession`. If the Session
expires, closes, exhausts its cap, or its bound Provider is unavailable, return
to the Web dApp and activate an appropriate Session.

## Provider: Canonical Codex Service

### Requirements

- GNU Make;
- Docker Engine or Docker Desktop with Compose V2;
- `amd64` or `arm64` Linux containers;
- outbound access to official OpenAI authentication and Codex services;
- a ChatGPT/Codex account eligible to use the official Codex device login.

Do not paste an OpenAI password, OAuth export, `access_token`, `refresh_token` or
Sub2API account JSON into this repository.

### Install and start

The shortest new-Provider bootstrap is one shell command. It downloads a
persistent checkout into `./mycomesh`, performs the official device login,
opens the local settings page, and starts the Provider after the page is saved.

With Node.js 20 installed, install the public npm package and start the
Provider:

```bash
npm install --global mycomesh-provider
mycomesh-provider
```

For a host-local outbound proxy, export the usual variables before starting:

```bash
export http_proxy=http://127.0.0.1:10792
export https_proxy=http://127.0.0.1:10792
mycomesh-provider
```

The npm launcher first uses these proxy settings for its pinned bootstrap
download. The installer then passes them only to `provider-sidecar`, covering
the interactive Codex login and later inference traffic. Loopback proxy hosts are
automatically mapped to `host.docker.internal`; uppercase variables and the
Provider-specific `MYCOMESH_PROVIDER_*_PROXY` overrides are also accepted. The
proxy application must allow connections from Docker Desktop or the Docker
bridge. Existing npm-managed checkouts receive a temporary compatibility
override and do not need to be deleted.

Use `npm install ... && mycomesh-provider ...` when one shell line is preferred.
This is a launcher for the same Docker installer; Docker Compose V2 and GNU
Make are still required. The npm command never receives a private key or Codex
credential.

```bash
curl -fsSL https://raw.githubusercontent.com/Charleslzp/mycomesh/main/scripts/bootstrap-provider.sh \
  -o /tmp/mycomesh-provider.sh && \
bash /tmp/mycomesh-provider.sh --image-tag latest
```

The `main`/`latest` pair is intentionally labeled mutable and is suitable only
for a first install. For a reproducible Provider, download the bootstrap from a
reviewed release or commit and pass matching values:

```bash
bash /tmp/mycomesh-provider.sh \
  --ref <commit-or-tag> \
  --image-tag sha-<short-commit>
```

To retain an existing payout address, complete
[Use an existing Provider payout identity](#use-an-existing-provider-payout-identity)
before running the installer. `MYCOMESH_SOURCE_DIR` or `--source-dir` selects a
different persistent checkout directory.

The script checks the host, creates a mode-`0600` `.env.deploy`, pulls the
Provider image, displays the official one-time Codex device-auth URL and code,
starts the Provider ingress and private Codex sidecar, and runs
`make provider-health`.

Use `--image-tag latest` only for a first mutable smoke test. Public GHCR images
need no registry login; if package visibility still requires it, rerun with
`--ghcr-login` and enter a dedicated read-only package token interactively.

### Record and protect the Provider identity

After the Provider starts, enter the downloaded checkout:

```bash
cd mycomesh
make provider-identity
make provider-health
```

The first command prints the Ed25519 node identity and public EVM payout/signing
address; it does not print the EVM private key. The private EVM identity is
created in `mycomesh-provider-data` and must match the payment address because it
signs V5 receipts. Supplying only an unrelated payout address is not supported.

`MYCOMESH_PROVIDER_PAYMENT_ADDRESS` may be set in `.env.deploy` before startup,
but it is a public consistency pin rather than a second payout destination. The
Provider refuses to start unless it equals the address derived from the local
EVM identity.

### Use an existing Provider payout identity

To keep an established Provider address, import the complete protected identity
file before the first Provider start. Do not pass its private key on the command
line:

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
make deploy-env
PROVIDER_EVM_IDENTITY_FILE=/absolute/secure/provider-evm-identity.json \
  make provider-identity-import
```

The source file must be a regular, non-symlink Provider identity backup. The
import target validates it, writes it into the Provider-only Docker volume with
private permissions, and refuses to replace a different existing identity. Set
its public address as an optional startup pin in `.env.deploy`:

```dotenv
MYCOMESH_PROVIDER_PAYMENT_ADDRESS=0xYourProviderAddress
```

Then run the normal installer. After startup, `make provider-identity` must show
the expected address. If it does not, stop and reconcile the identities before
serving any request.

Back up `/data/provider-evm-identity.json` from that volume using an approved
encrypted backup process before accepting paid work. Do not remove Provider
volumes and do not use `docker compose down -v` during routine upgrades. Follow
the complete [recovery procedure](quick-deploy.md#provider-payout-identity-recovery)
before restoring an identity.

For an upgrade that reuses the existing Codex login and identities:

```bash
git pull --ff-only
PROVIDER_TAG="sha-$(git rev-parse --short HEAD)"
scripts/install-provider.sh --image-tag "$PROVIDER_TAG" --skip-codex-login
```

The installer opens and prints the loopback Provider settings page on every
default start. The page lets the operator reuse
the protected wallet, generate a new local wallet with a backup acknowledgement,
or import an existing private key. It derives the Provider address from that
signing key and performs a sign/recover check; there is no independent payout
address field. Use `--skip-provider-config` for unattended restarts. The normal
settings command is `mycomesh-provider --configure`; source-checkout operators
can pass the same pinned `PROVIDER_IMAGE` to `make provider-configure`, then rerun
`make provider-up-image`. The fields control
concurrent sessions and the rolling USDC usage budget; a blank budget is
unlimited. The public settings file never contains a private key; a selected
generated/imported identity is staged separately with mode 0600 and refuses to
replace a different identity in the Docker volume.

Useful checks:

```bash
make provider-health
make provider-logs
make provider-identity
```

## Relay: discovery, transport, settlement

Relay is the only public infrastructure role. Its internal modules provide
signed Provider discovery (the legacy Bridge API on port 9800), end-to-end
sealed forwarding for Providers behind NAT, request-level V5 attestations,
and ordered receipt submission to the Settlement contract. The Relay transaction
worker is a keeper implementation detail, not a fourth role.

### Canonical public node

`make public-node-up` is for the operator controlling the checked-in canonical
domain, DNS, certificate and reverse-proxy topology. It is not a generic command
that turns an arbitrary host into a member of the official network. The official
operator procedure is:

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
make deploy-env
# Restore the official operator environment and verify this public address is
# identical to relay.payment_address in the checked-in V5 Provider network manifest:
# MYCOMESH_RELAY_PAYMENT_ADDRESS=0x...
# Keep the Relay online-attestation identity at:
# MYCOMESH_RELAY_ATTESTATION_IDENTITY=/data/relay-attestation-identity.json
# Then follow the linked DNS/TLS steps.
make public-node-up
make public-node-health
# Run this after the certificate and Nginx stream listener are installed.
make public-node-tls-health
```

DNS, Certbot, Nginx stream TLS and firewall prerequisites are documented in
[Role Deploy](quick-deploy.md#public-bridge-and-relay-node).

### Third-party Relay status

The published Provider manifest currently pins `bridge.mycomesh.xyz` as its
Relay. A third-party Relay cannot yet self-register into that manifest, receive
canonical Provider traffic, or claim canonical Relay rewards merely by running
the repository.

`make relay-start` starts the Relay role and its internal discovery module using
the `.env.deploy` template.
Set the Relay payout and online-attestation addresses before startup if this
private network will exercise V5 settlement:

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
make deploy-env
# Edit .env.deploy:
# MYCOMESH_RELAY_PAYMENT_ADDRESS=0xYourRelayAddress
# MYCOMESH_RELAY_ATTESTATION_IDENTITY=/data/relay-attestation-identity.json
make relay-start
```

With Node.js 20 or newer, the same onboarding flow can be started from the
public npm package. Docker Compose V2 and GNU Make remain required because the
package is a launcher for the Docker-backed role:

```bash
npm install --global mycomesh-relay
mycomesh-relay
```

The first run downloads a persistent `./mycomesh` checkout and opens the
loopback wizard. Use `--ref <reviewed-commit>` for a pinned checkout,
`--source-dir /srv/mycomesh` for another location, or `--no-browser` when the
machine has no desktop browser. The wizard only accepts the public payout
address, maximum concurrency and optional usage limit; settlement signer
credentials still belong in the protected `.env.deploy`.

That foreground process is appropriate for loopback/private interoperability
testing only; its plaintext local transport must not be exposed to the Internet.
A separate network operator may publish its own manifests and trust
configuration, but that creates a distinct network whose API keys, Providers
and payout policy are not the canonical MycoMesh network.

The Relay runtime receives a public payout address and a protected online-
attestation identity file; the payout private key can remain offline until the
operator claims accumulated credits. The attestation address is derived from
that identity file and is checked against the published network manifest.
Outside the local profile, the Relay payout and online-attestation signer are
required together and must match the addresses authorized by the V5 Session.
For the canonical network they must match `relay.payment_address` and
`relay.attestation_address` in `deployments/sepolia-provider-network.json`:
`0x27bd63aef83554700042685c2862da6f6a9197e8` and
`0x36390747ae29f5f8ae55ddd7daace89ad57644cf`. Entering another address locally
does not alter that manifest or enroll the Relay into canonical settlement.

The Relay can accept Consumer-signed V5 receipts at `/v5/settlements`. It
persists each receipt before returning `202`, deduplicates by session and
receipt hash, and submits with its own gas-funded transaction identity. The
transaction identity is separate from both the public payout address and the
online-attestation identity. A Relay outage leaves the signed receipt in the
Consumer outbox for retry. The default worker groups up to eight ordered
receipts per transaction; a reverted batch is automatically split until the
bad receipt is isolated.

This is a fail-closed runtime trust chain: the Relay, Provider, signed Provider
descriptor and Consumer plan all reject a unilateral address substitution.
Settlement V5 stores the Provider payout, Relay payout, Relay online-attestation
signer, and optional Pool payout in `openSession`. The Relay signs the
request-level attestation and the contract checks it against the fixed signer;
the Provider still signs the receipt. This prevents a unilateral route
substitution without giving the Relay access to prompts, responses, or Codex
credentials.

## Consumer implementation notes

The repository still contains a canonical HTTP Proxy implementation for the
official network. Treat it as an internal Consumer deployment, not a separate
fourth role. It requires state that a fresh Git clone intentionally does not
contain:

- the Proxy request identity pinned by the Provider network manifest;
- stable Proxy, Session and PostgreSQL secrets;
- persistent account, indexer and Session outbox state;
- canonical DNS, TLS and reverse-proxy configuration.

In the three-role path, the Consumer sends its completed signed receipt to the
Relay. The Relay pays native gas and submits it; it is not the payout recipient.

Consequently, `make proxy-up` on a new checkout is expected to fail closed until
the official operator restores and validates that state. Generating a random
Proxy identity does not create another canonical Gateway. The recovery and
operator-only startup sequence is in
[Consumer Proxy Operator](quick-deploy.md#consumer-proxy-operator).

## Optional Local Direct Consumer

This separate Docker profile serves the wallet-owned V3 diagnostic application
on localhost:

```bash
make consumer-up
make consumer-health
```

Open `http://127.0.0.1:8110/app/playground`. This is not the canonical V5 npm CLI
onboarding path, and its headless localhost API remains unavailable until an
external V3 signer/executor is integrated. See [Local Consumer Docker](local-consumer.md).
