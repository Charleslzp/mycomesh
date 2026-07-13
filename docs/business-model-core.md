# MycoMesh Business Model Core Mechanism

This document records the core economic and protocol model for the future
decentralized AI inference network.

## Positioning

The protocol is not a new public blockchain. It is a decentralized AI inference
service network built on top of existing blockchains.

Working brand:

```text
Protocol: MycoMesh Protocol
Network: MycoMesh Network
Node: Spore Node
Token: MYCO
Work proof: Proof of Useful Inference
```

Existing chains provide:

- Ledger consensus
- Asset custody
- Stablecoin payments
- Treasury accounting
- Token issuance and settlement

This protocol provides:

- P2P node discovery
- Task distribution
- AI inference execution
- Result acceptance
- Useful work accounting
- Optional epoch reward allocation after anti-Sybil review and governance enablement

In this model, proof of work is intended for future reward allocation, not for
block production or ledger consensus. Settlement V3 keeps rewards globally
disabled by default because signed receipts alone are not Sybil-resistant proof
of useful or unique work.

## Core Thesis

Traditional PoW networks spend work to compete for accounting rights. This
network spends work on real AI inference tasks that users actually need.

The useful work is:

- User-paid AI inference
- Completed by decentralized provider nodes
- Accounted as valid work after task completion or acceptance
- Used to distribute service income
- Eligible for protocol token emissions only after stronger work/quality signals are deployed

The network is therefore a useful-work mining system:

```text
User demand -> request-bound reservation -> AI inference -> accepted receipt -> stablecoin settlement
```

## Layer Model

```text
Existing blockchain = ledger layer
Protocol contracts = settlement layer
P2P inference network = useful work layer
Provider clients = execution layer
```

The protocol does not need to solve public-chain consensus. Its current role is
to authenticate requests/results and account paid inference; proving semantic
quality, unique execution and Sybil-resistant useful work remains a separate
release requirement.

## Payment Model

Users pay for inference with stablecoins.

Settlement V3 supports only standard non-rebasing stablecoins without transfer
fees and checks exact balance deltas on every transfer.

Stablecoin pricing can use either:

- A fixed channel price
- A reference price based on official provider pricing
- A protocol oracle that maps official pricing into channel pricing

The goal is to keep the external service price predictable for users.

The user-facing API should feel like a normal centralized AI proxy:

```text
base_url + api_key -> prepaid balance -> pooled provider routing -> receipt
```

A self-custodied V3 user creates an on-chain request-bound reservation before
dispatching each exact input. A managed URL+key gateway may hide that operation
behind a funded account or explicitly authorized wallet/delegate workflow, but
it must not reuse a reservation for another request. Final accepted receipts can
still be submitted permissionlessly or in bounded batches.

## Platform Token Model

The platform token is MYCO. Settlement V3 defines a capped epoch emission path,
but token minting is globally disabled at deployment. Provider/consumer rewards
become possible only after a typed governance delay, and should remain disabled
until the network has an audited anti-Sybil work and quality signal.

The token is not used as the only external payment unit at the start. Its core
roles are:

- Conditional provider/consumer incentive
- Protocol value capture
- Future governance or coordination asset
- Economic exposure to network growth

## Treasury And Buyback

A portion of stablecoin revenue is routed to the protocol treasury.

The treasury may eventually use stablecoin revenue to buy back platform tokens
from the market and burn them. This is a future policy layer, not a function of
the current Settlement V3 contract.

This creates two opposing token flows:

```text
Emission: governance-enabled, capped rewards may release new platform tokens
Burn: stablecoin revenue buys back and destroys platform tokens
```

Long-term token value is intended to come from:

- Scarce or decreasing token emission
- Real inference revenue
- Buyback and burn pressure
- Network growth and service demand

## Halving Logic

Settlement V3 uses deployment-relative weekly epochs. The emission cap starts
at deployment and halves every 208 epochs (about four years). Only successful
token mints increase `epochMinted`; a failed mint leaves capacity available.

The purpose of halving is to:

- Incentivize early provider supply
- Create a predictable emission curve
- Gradually shift the network from subsidy-driven rewards to service-fee-driven
  rewards

The emission model is:

```text
Node income = stablecoin service share + optional governance-enabled token reward
```

Over time:

```text
Early stage: stablecoin-first operation with rewards paused
Later stage: more reliance on real service fees and treasury buyback
```

## Channels

Different inference sources should not be mixed into a single quality pool.

The network should support separate channels such as:

- `codex-standard-v1`
- `premium-api-v1`
- `local-open-model-v1`
- `cheap-fast-v1`

Each channel can define:

- Accepted client/runtime
- Model or provider standard
- Output schema
- Completion rules
- Price formula
- Work accounting formula
- Reward weight

This keeps service quality and pricing coherent within each channel.

## Valid Work

The simplest initial definition:

```text
Valid work = a paid inference task that was completed and accepted.
```

Accepted work determines normal stablecoin settlement. It may contribute to a
future reward signal, but acceptance and signatures alone are not sufficient
for permissionless epoch rewards.

In the current implementation, normal settlement requires explicit consumer and
provider EVM authorization over an EIP-712 receipt containing `acceptedHash`.
There is no trusted-operator bypass in V3. A separate provider fallback may
settle only when the consumer explicitly enabled it for that reservation and
the consumer withholds the final signature. It charges the non-refundable
`minimumFee`: only `providerBps` goes to the provider, the rest goes to treasury,
and relay/pool/rewards are disabled. This fallback is base-fee authorization,
not proof of service delivery or consumer quality acceptance.

The launch path is intentionally staged:

- `local`: developer-only demos, where unsigned/unreserved shortcuts can be
  enabled explicitly.
- `testnet`: supports chain/contract tests and authenticated sealed provider
  transport. Paid inference additionally requires an AI backend whose health
  reports production-safe output-cap enforcement and trusted native usage.
- `open`: reserved until staking, slashing, quality sampling, dispute handling,
  independent transport review and production operations are complete.

Before the `open` profile can launch, the protocol needs concrete rules for:

- Inference units
- Task difficulty
- Latency
- Failure rate
- User dispute rate
- Channel-specific acceptance rules
- Provider stake and slashing triggers

## Design Boundary

This model intentionally separates:

- Useful AI work from ledger consensus
- Stable external pricing from platform-token incentives
- Existing-chain settlement from P2P inference execution
- Channel-specific service standards from the global protocol economy

The central claim is:

```text
Proof of useful AI inference may allocate network rewards only after its
anti-Sybil and quality assumptions are enforceable; existing blockchains handle
accounting and asset settlement.
```

## V3 Security Boundary

Open participation requires cryptographic identity, request-bound payment and a
separate anti-Sybil quality mechanism before token incentives can work safely.
The current V3 boundary is:

- Provider pool entries, relay registration, consumer requests and provider
  responses are signed. Request IDs use a durable replay store.
- A consumer creates an on-chain reservation for one provider, channel,
  immutable pricing version, request v2 hash, maximum amount, expiry and an
  explicit provider-fallback choice. The v2 hash binds endpoint, exact model,
  canonical `input`/`messages`, and the positive output cap.
- Before inference, the provider selects one confirmed block and reads
  `channelPricingHash`, `quote` and `reservations` there. It verifies chain,
  settlement, consumer/provider, channel, request hash, pricing version/hash,
  amount, expiry, fallback flag and deadline. The request model must equal the
  configured/descriptor model. Canonical input bytes are an admission check;
  fee authorization uses the full configured input reserve so injected
  system/agent/routing context is covered, plus the resolved output cap. The
  deadline must cover provider timeout plus a 60-second transaction inclusion
  buffer. Failures occur before upstream execution.
- A one-reservation `mycomesh.evm.session.v1` EIP-191 authorization binds the
  consumer EVM wallet to the exact request/payment scope, a unique nonce and the
  Ed25519 request key. The provider validates an EOA or EIP-1271 wallet at the
  same confirmed block. This is not a reusable session registry or a general
  actively revocable long-lived delegation.
- After capacity and every validation pass, the provider atomically claims the
  reservation ID and session nonce in persistent replay state through expiry,
  then starts inference. Capacity rejection does not consume the claim;
  uncertain execution failure is non-retryable, giving at-most-once execution.
- After inference, the provider compares its local usage quote with the V3
  on-chain quote at that same confirmed block. A mismatch rejects settlement
  evidence.
- Signed usage is only economically valid when the execution backend enforces the
  authorized output cap and returns trustworthy native token counts. The current
  Codex CLI compatibility bridges return zero/estimated usage and do not enforce
  the cap during generation, so they are local-test backends rather than
  production token meters.
- Normal settlement requires consumer and provider EIP-712 authorization, or
  receipt-scoped delegate authorizations. EOA and EIP-1271 wallets are
  supported; there is no V3 trusted operator endpoint.
- The EIP-712 domain binds current chain ID and settlement address.
  `DOMAIN_SEPARATOR()` dynamically rebuilds if the chain ID changes.
- Provider fallback is disabled by default and requires deliberate per-
  reservation consumer opt-in. It requires zero `acceptedHash` and settles only
  the non-refundable `minimumFee`: `providerBps` goes to the provider and the
  rest to the version-pinned treasury, with no relay, pool or reward. It does
  not prove service delivery, response quality, uniqueness or acceptance.
- Settlement V3 supports only standard non-rebasing stablecoins without
  transfer fees. Deposit, withdrawal and every split transfer require exact
  sender/recipient balance deltas; unsupported token behavior reverts.
- Rewards are globally off at deployment. `scheduleRewardEnable()` plus the
  two-day delay is required to enable them, while `pauseRewards()` is immediate.
  Keep them off until anti-Sybil and quality signals are independently reviewed.
- Emission epochs are weekly from the deployment timestamp and halve every 208
  weeks. Only a successful mint increases `epochMinted`; mint failure cannot
  roll back stablecoin settlement.
- Channel and treasury changes use public typed scheduling functions whose
  parameters are visible in events. Old immutable channel versions remain
  usable for their existing reservations.
- Indexers use confirmed events, block hashes and rewind support. Multiple proxy
  replicas use one PostgreSQL billing DSN for transactional balance,
  registration and indexer coordination; SQLite remains single-host only.
- Multiple provider replicas use one PostgreSQL replay DSN to enforce global
  single use of a V3 reservation and session nonce. Independent SQLite files do
  not coordinate and remain single-host only.
- Settlement replay state is keyed by `(reservationId, receiptHash)`, not a
  globally unique receipt hash. Indexers and readers must preserve that pair.
- Non-local provider and relay descriptors bind Ed25519 identity to rotating
  X25519 transport keys and carry ChaCha20-Poly1305 sealed inference frames.
  Relays cannot read prompts/results, but traffic metadata remains visible and
  the message-layer design does not provide session forward secrecy.
- The final V3 ABI is incompatible with early V3 deployments: create ends with
  `bool providerFallbackAllowed`, the reservation getter returns nine words, and
  settlement reads take `(reservationId, receiptHash)`. Operators must redeploy
  and recreate reservations, including legacy input-only commitments; old
  calldata, signatures and query keys are not reusable.

The normal paid-work definition is:

```text
Paid work = request-bound reservation + signed provider result + consumer-accepted receipt + settled payment.
```

That definition proves authorization, integrity and payment. It does not by
itself prove semantic correctness, unique execution or Sybil-resistant useful
work, which is why reward issuance remains disabled by default.
