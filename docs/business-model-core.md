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
- Epoch reward allocation

In this model, proof of work is used for reward allocation, not for block
production or ledger consensus.

## Core Thesis

Traditional PoW networks spend work to compete for accounting rights. This
network spends work on real AI inference tasks that users actually need.

The useful work is:

- User-paid AI inference
- Completed by decentralized provider nodes
- Accounted as valid work after task completion or acceptance
- Used to distribute service income and protocol token emissions

The network is therefore a useful-work mining system:

```text
User demand -> AI inference work -> valid service output -> reward allocation
```

## Layer Model

```text
Existing blockchain = ledger layer
Protocol contracts = settlement layer
P2P inference network = useful work layer
Provider clients = execution layer
```

The protocol does not need to solve public-chain consensus. It only needs to
prove and account which nodes completed valid inference work.

## Payment Model

Users pay for inference with stablecoins.

Stablecoin pricing can use either:

- A fixed channel price
- A reference price based on official provider pricing
- A protocol oracle that maps official pricing into channel pricing

The goal is to keep the external service price predictable for users.

The user-facing API should feel like a normal centralized AI proxy:

```text
base_url + api_key -> prepaid balance -> pooled provider routing -> receipt
```

Individual requests should not require a wallet signature or an on-chain
transaction. Users prepay stablecoin into a contract or managed gateway balance;
the protocol records actual usage off chain and settles receipts in batches.

## Platform Token Model

The platform token is MYCO. MYCO is produced through useful-work mining.

Provider nodes earn platform tokens according to their share of valid inference
work in each epoch.

The token is not used as the only external payment unit at the start. Its core
roles are:

- Mining reward
- Protocol value capture
- Future governance or coordination asset
- Economic exposure to network growth

## Treasury And Buyback

A portion of stablecoin revenue is routed to the protocol treasury.

The treasury can periodically use stablecoin revenue to buy back platform tokens
from the market and burn them.

This creates two opposing token flows:

```text
Emission: useful-work mining releases new platform tokens
Burn: stablecoin revenue buys back and destroys platform tokens
```

Long-term token value is intended to come from:

- Scarce or decreasing token emission
- Real inference revenue
- Buyback and burn pressure
- Network growth and service demand

## Halving Logic

Platform token emissions can follow a halving schedule.

The purpose of halving is to:

- Incentivize early provider supply
- Create a predictable emission curve
- Gradually shift the network from subsidy-driven rewards to service-fee-driven
  rewards

The emission model is:

```text
Node reward = stablecoin service share + platform token mining reward
```

Over time:

```text
Early stage: higher token subsidy
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

Valid work is used to calculate each node's share of epoch rewards.

In the current implementation, acceptance is an explicit consumer-side receipt
signature. The signed settlement path includes `accepted_hash` in the EIP-712
receipt digest, so a provider/operator cannot settle a production receipt that
was only locally observed but never accepted by the consumer identity. The
operator-only trusted path remains available for demos and migration.

The launch path is intentionally staged:

- `local`: developer-only demos, where unsigned/unreserved shortcuts can be
  enabled explicitly.
- `testnet`: the default public launch profile. Pools require signed provider
  descriptors, direct address probes, provider payout addresses, explicit
  provider public-key allowlists, and explicit reputation signer allowlists.
- `open`: reserved until staking, slashing, quality sampling, and dispute
  handling are implemented. Permissionless provider joins should not be enabled
  before those mechanisms exist.

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
Proof of useful AI inference should allocate network rewards, while existing
blockchains handle accounting and asset settlement.
```

## V2 Security Boundary

Open participation requires cryptographic identity before economic incentives
can work.

The v2 protocol boundary is:

- Provider pool entries are signed node descriptors.
- Pools verify signed joins/heartbeats/leaves, probe direct addresses before
  admitting them by default, rate-limit HTTP callers, and persist signed
  reputation feedback as a routing signal. The default public launch is an
  allowlisted testnet: pools require explicit provider public keys and explicit
  proxy/indexer reputation signer keys. Accepting any reputation signer is a
  development mode.
- Relay provider registration is signed, preventing simple peer-id takeover.
- Consumer inference requests are signed and can be allowlisted by providers and
  public relays.
- Consumer requests carry signed payment reservations with pricing hash,
  maximum fee, expiry, and nonce semantics; providers reject missing or
  underfunded reservations before spending local Codex quota.
- Provider and relay request ids are replay-checked with a durable local replay
  store in production launches, so restarting a node does not reopen a replay
  window for recently seen requests.
- Provider responses are signed and verified against the pool descriptor before
  a proxy accepts the work, captures prepaid balance, or writes an accepted
  receipt.
- Provider payout addresses are included in signed descriptors and copied into
  receipts, so settlement can pay the address advertised by the node instead of
  relying on a manually typed provider address.
- Consumer accounts can bind a payment address, so receipts carry the payer
  address needed for prepaid settlement.
- Stablecoin payment should use prepaid balances and batch receipt settlement,
  keeping the user-facing API compatible with normal `base_url + api_key`
  gateway usage.
- Consumer proxies should reserve prepaid balance before dispatching work, then
  capture the actual fee after the response. Failed routes release the
  reservation; stale reservations can be released by an operator cleanup job.
  Captures cannot exceed the reserved maximum fee and accepted receipts are
  written to a local outbox in the same transaction as balance capture.
  Reservation ids and usage event ids are idempotency keys, and account status
  can suspend or close API keys before more work is dispatched.
- Providers verify payment reservations against the current channel pricing
  hash and a minimum reserved fee before spending local Codex quota.
- Channel pricing hashes should come from the settlement contract or a signed
  governance snapshot. Local config hashes are a development fallback, not the
  production source of truth.
- Receipts contain consumer/provider public keys, request/response hashes,
  pricing config hashes, optional chain pricing hashes, usage, quality
  attestations, deadlines, operator signatures, and consumer acceptance
  signatures.
- Production settlement verifies signed prepaid receipts locally before sending
  the transaction, requires a non-zero `accepted_hash`, and requires a non-zero
  channel pricing hash. Contract signature recovery rejects high-s ECDSA
  signatures. Operator-only settlement is retained only for demos and migration.
- URL+key users should authorize settlement delegates once, instead of signing
  every inference receipt directly. Delegated settlement keeps the product
  experience simple while preserving account-controlled spending permission.
- Delegated settlement authorizations are bound to the exact receipt hash,
  accepted hash, channel, counterparty, and gross fee. A delegated signature for
  one accepted job is therefore not reusable for a different job or payout path.
- Operators should settle delegated receipts with wallet-produced signature JSON
  rather than collecting consumer/provider private keys. Local private-key flags
  are a demo path only.
- On-chain prepaid balances need an indexer/reconciler that updates the local
  proxy cache from confirmed contract events and refuses serving when the cache
  is stale, on the wrong chain, or for a different settlement address.
- Consumer accounts can express natural reseller roles through parent account
  ids, usage tiers, discounts, reseller margin parameters, and monthly quotas;
  no extra hard-coded role layer is required.
- Platform-token rewards are capped by epoch emission, so halving parameters
  constrain actual minting rather than only describing it.
- Treasury buyback/burn is represented as a governance-controlled hook so
  stablecoin revenue can be converted into token supply reduction under a
  transparent policy.
- Governance actions that mutate settlement treasury, operators, executor,
  delay, pricing, economics, trusted settlement, or buyback burn are timelocked
  after bootstrap. Action hashes are computed by the client before scheduling.
- Routing uses channel, liveness, capacity, local leases, latency, acceptance,
  settlement, dispute, and failure history.
- Bootstrap discovery can aggregate multiple pools and deduplicate by peer id;
  one pool is an indexer, not the protocol's source of truth. Pools can publish
  local reputation scores to improve routing, but settlement signatures and
  receipts remain the economic trust boundary.

This is still not a complete trustless proof of model quality. The first valid
work definition remains:

```text
Valid work = signed completed inference + consumer accepted receipt + settled payment.
```
