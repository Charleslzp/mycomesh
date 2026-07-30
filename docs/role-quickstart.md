# MycoMesh Role Quickstart

This guide starts from a clean Git checkout and separates canonical-network
users from infrastructure operators. A command listed for one role is not a
prerequisite for every other role.

## Choose One Role

| Role | Runs continuously | Credentials/state | Supported canonical path |
| --- | --- | --- | --- |
| Web Consumer | No | Sepolia wallet, wallet-bound MycoMesh API key | `app.mycomesh.xyz` |
| npm Consumer CLI | No | The same API key and an already active V4 Session ID | Repository-local npm package |
| Provider | Yes | Isolated Codex login, node identity, Provider EVM identity | Provider installer and canonical Relay |
| Canonical Bridge + Relay | Yes | Official DNS/TLS and persistent public-node state | Official operator only |
| Canonical Consumer Proxy | Yes | Pinned Proxy identity, account DB, Session secrets, funded relayer | Official operator only |
| Third-party Relay | Yes | Operator-defined private-network configuration | Local/private networks only today |
| Local Direct Consumer | Optional | Local browser identity and wallet | V3 diagnostic path only |

Docker is required for continuously running Provider, Bridge, Relay and Proxy
roles. It is not required for the Web Consumer or npm CLI.

## Consumer: Web First, CLI Second

The canonical V4 flow uses the wallet only for funding and one bounded Session
activation. Each later inference request uses the API key and active Session ID;
it does not request a wallet transaction per prompt.

### 1. Register Consumer access

Open `https://app.mycomesh.xyz/app/access`, connect the intended Sepolia wallet
and create a wallet-bound API key. Copy the key when it is shown. The Gateway
stores its hash, not the plaintext key, and the browser keeps the complete value
only in the current tab.

An API key is scoped to its Gateway origin. A key created for
`gateway.mycomesh.xyz` is not a credential for another operator's Proxy.

### 2. Fund the V4 escrow

Open `https://app.mycomesh.xyz/app/funds`. On Sepolia, the page can mint test
tUSDC with no monetary value. Select **Deposit**, approve the exact amount, then
deposit it into the verified V4 Settlement contract. Approval and deposit are
separate wallet transactions.

### 3. Open one V4 Session

Open `https://app.mycomesh.xyz/app/playground` and submit the first request. The
Gateway prepares a Provider-bound plan and the wallet asks for one `openSession`
transaction. Wait until the page reports **Prepaid session active**.

After the first response, expand **Price and receipt envelope** and record
`session.session_id`. The Session ID is not a private key, but it is valid only
with the API key/account and wallet that funded that Session.

### 4. Use the npm CLI

The package is not yet published to the public npm registry. Install it from the
checkout with Node.js 20 or newer:

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
npm install --global ./packages/mycomesh-cli
```

Configure the canonical origin and the values retained above:

```bash
export MYCOMESH_BASE_URL=https://gateway.mycomesh.xyz/v1
export MYCOMESH_API_KEY='replace-with-wallet-bound-mycomesh-key'
export MYCOMESH_SESSION_ID='0x...replace-with-active-v4-session-id'

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

Clone the exact commit whose published image you intend to run. The command
below is for a new Provider and creates its payout/signing identity on first
start. To retain an existing address, complete
[Use an existing Provider payout identity](#use-an-existing-provider-payout-identity)
before running the installer:

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
PROVIDER_TAG="sha-$(git rev-parse --short HEAD)"
scripts/install-provider.sh --image-tag "$PROVIDER_TAG"
```

The script checks the host, creates a mode-`0600` `.env.deploy`, pulls the
Provider image, displays the official one-time Codex device-auth URL and code,
starts the Provider ingress and private Codex sidecar, and runs
`make provider-health`.

Use `--image-tag latest` only for a first mutable smoke test. Public GHCR images
need no registry login; if package visibility still requires it, rerun with
`--ghcr-login` and enter a dedicated read-only package token interactively.

### Record and protect the Provider identity

After the Provider starts:

```bash
make provider-identity
make provider-health
```

The first command prints the Ed25519 node identity and public EVM payout/signing
address; it does not print the EVM private key. The private EVM identity is
created in `mycomesh-provider-data` and must match the payment address because it
signs V4 receipts. Supplying only an unrelated payout address is not supported.

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

Useful checks:

```bash
make provider-health
make provider-logs
make provider-identity
```

## Bridge and Relay

Bridge and Relay are separate logical services. Bridge handles signed Provider
discovery; Relay forwards end-to-end sealed traffic for Providers behind NAT.
The canonical deployment operates them together as the public-node role.

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
# identical to relay.payment_address in the checked-in Provider network manifest:
# MYCOMESH_RELAY_PAYMENT_ADDRESS=0x...
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

`make relay` starts the local development role using the `.env.deploy` template.
Set the Relay's public payout address before startup if this private network will
exercise V4 settlement:

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
make deploy-env
# Edit .env.deploy:
# MYCOMESH_RELAY_PAYMENT_ADDRESS=0xYourRelayAddress
make relay
```

That foreground process is appropriate for loopback/private interoperability
testing only; its plaintext local transport must not be exposed to the Internet.
A separate network operator may publish its own manifests and trust
configuration, but that creates a distinct network whose API keys, Providers
and payout policy are not the canonical MycoMesh network.

The Relay runtime receives only the public payout address; its payout private key
can remain offline until the operator claims accumulated credits. Outside the
local profile the address is required, is bound into the Relay challenge and
Provider descriptor, and must match the address authorized by the V4 Session.
For the canonical network it must also match `relay.payment_address` in
`deployments/sepolia-provider-network-v4.json`. Entering another address locally
does not alter that manifest or enroll the Relay into canonical settlement.

This is a fail-closed runtime trust chain: the Relay, Provider, signed Provider
descriptor and Consumer plan all reject a unilateral address substitution. The
current V4 contract still validates the Relay address per dual-signed receipt;
it does not store one immutable Relay in `openSession`. Consequently, V4 does
not provide an on-chain proof that the named Relay carried the traffic when a
Consumer and Provider collude. A future contract version must bind the Relay in
the opened Session to make that stronger guarantee.

## Canonical Consumer Proxy

Ordinary Consumers and Provider operators do not run the canonical Proxy. It is
the official `gateway.mycomesh.xyz` service and requires all of the following
state that a Git clone intentionally does not contain:

- the Proxy request identity pinned by the Provider network manifest;
- stable Proxy, Session and PostgreSQL secrets;
- persistent account, indexer and Session outbox state;
- a funded Sepolia transaction-relayer identity;
- canonical DNS, TLS and reverse-proxy configuration.

The transaction relayer in this list submits V4 receipts to the Settlement
contract. It is not the Bridge/Relay transport daemon.

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

Open `http://127.0.0.1:8110/app/playground`. This is not the canonical V4 npm CLI
onboarding path, and its headless localhost API remains unavailable until an
external V3 signer/executor is integrated. See [Local Consumer Docker](local-consumer.md).
