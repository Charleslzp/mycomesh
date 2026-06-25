# Business Model Core Mechanism

This document records the core economic and protocol model for the future
decentralized AI inference network.

## Positioning

The protocol is not a new public blockchain. It is a decentralized AI inference
service network built on top of existing blockchains.

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

## Platform Token Model

The platform token is produced through useful-work mining.

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

Future versions may refine this with:

- Inference units
- Task difficulty
- Latency
- Failure rate
- User dispute rate
- Channel-specific acceptance rules

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
