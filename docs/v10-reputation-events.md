# V10 dynamic-jury reputation events

Pool reputation is derived from confirmed `MycoSettlementV10` terminal events. The
Ed25519 reputation authority signs an event reference; it cannot directly select
success/failure/settled/disputed counters. A testnet V10 Pool then verifies the
reference through one operator-pinned RPC, chain ID, genesis hash, Settlement
address, and confirmation depth before changing reputation.

The signed `mycomesh.pool.reputation-event.v2` body binds `network_id`, `chain_id`,
`settlement_contract`, `settlement_key`, `request_id`, Provider owner and signer,
current `peer_id`, transaction/log/block identity, terminal status, and outcome.
The Pool checks the canonical block, successful receipt, exact log, terminal event
ABI, and `settlementInfo` at the canonical block. It also rechecks the block hash
after the state read. Replay identity is the hash of chain ID, Settlement address,
transaction hash, and log index.

The deterministic scoring inputs are:

- `Released` and `Dismissed`: positive; increment `successes` and `settlements`.
- `Confirmed`: negative; increment `failures` and `disputes`.
- `TimedOut` and `JuryUnavailable`: neutral; retained as evidence but do not change counters.

The existing score remains
`max(0, settlements*20 + successes*5 - failures*10 - disputes*50)`.
The durable store is `mycomesh.pool.reputation-store.v3` and has an independent
verified-event set for each peer. V1/v2 and unversioned stores fail closed because
their arbitrary hashes and counters are not canonical-chain evidence. Snapshot v2
keeps the compatibility field names `receipt_count` and `receipt_set_hash`, but they
now count and commit only to that peer's verified terminal-event identities.

For a V10 testnet Pool, configure a pinned feedback signer plus
`--reputation-rpc-url`, `--reputation-genesis-hash`, and a conservative
`--reputation-confirmations` value. `MYCOMESH_POOL_REPUTATION_RPC_URL`,
`MYCOMESH_POOL_REPUTATION_GENESIS_HASH`, and
`MYCOMESH_POOL_REPUTATION_CONFIRMATIONS` are the equivalent environment settings.
Only `local` profile may opt into `--allow-unverified-local-reputation`; it is
disabled by default and cannot start a testnet V10 verifier path.

This prevents a reputation signer from inventing outcomes, but it does not solve
operator Sybil identity. `operator_id` is a signed self-asserted string/hash, not
proof that two wallets, peers, machines, or organizations are independently
controlled. Deployment policy must still cap concentration and add independently
verifiable stake/identity/failure-domain evidence before treating the jury as
production-independent.
