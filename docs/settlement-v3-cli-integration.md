# Settlement V3 CLI Integration

This document is the deployment and transaction contract for a V3-aware CLI or
indexer. The V3 testnet deployer uses `TestUSDC`, whose `mint` function is
unrestricted. Anyone can mint it: it has no monetary value and must never be
used as a production stablecoin deployment. A production launch requires a
separate audited stablecoin configuration and external review of the complete
deployment, not merely replacing the token address in a test record.

## Atomic Testnet Deployment

Deploy `MycoV3TestnetDeployer` with these constructor arguments, in order:

| Field | Solidity type | Meaning |
| --- | --- | --- |
| `treasury` | `address` | Stablecoin fee recipient captured by each immutable channel version |
| `governance` | `address` | Timelocked governance account; use a multisig outside local testing |
| `maxConsumerRebateBps` | `uint16` | Protocol-wide upper bound for consumer reward share; the default channel requires `1000..10000` |
| `maxSupply` | `uint256` | Immutable 18-decimal MYCO supply cap |

The constructor creates children in this fixed order: `TestUSDC` at child nonce 1, `MycoSettlementV3` at nonce 2, and `MycoTokenV2` at nonce 3. It reverts unless all predicted addresses and immutable cross-references match. The settlement constructor also creates active version 1 of `CODEX_STANDARD_V1` (`keccak256("codex-standard-v1")`) with rates `1000/4000`, minimum fee `2000`, stablecoin split `8500/300/200/1000`, reward split `9000/1000`, and reward multiplier `1e12`. Reservations can be created immediately after deployment.

Rewards are globally disabled at deployment even though version 1 commits reward
parameters. `emissionStartedAt` is the settlement deployment timestamp. An epoch
is seven days, and the emission cap halves every 208 epochs (208 weeks, about
four years).

Read the deployed addresses from `testUSDC()`, `settlement()`, and `token()`, or from:

```solidity
event MycoV3TestnetDeployed(
    address indexed testUSDC,
    address indexed settlement,
    address indexed token,
    address treasury,
    address governance,
    uint16 maxConsumerRebateBps,
    uint256 maxSupply
);
```

The current CLI deployment record fields are `protocol_version`, `chain_id`,
`deployer`, `tx_hash`, `test_usdc`, `stablecoin`, `settlement`, `token`,
`treasury`, `governance`, `max_consumer_rebate_bps`, `max_supply`, `channel`,
`channel_hash`, `pricing_version`, `pricing_hash`, `eip712_name`, and
`eip712_version`. An indexer should augment that record with the confirmed
deployment block and block hash. For V3, the EIP-712 values are
`MycoMesh Settlement`, `3`, and the settlement address as verifying contract.

For a direct production deployment of `MycoSettlementV3`, the constructor fields are `stablecoin_` (`address`), `rewardToken_` (`address`), `treasury_` (`address`), `governance_` (`address`), `maxConsumerRebateBps_` (`uint16`), `initialChannel_` (`bytes32`), and `initialConfig_` (the `ChannelConfig` tuple in contract field order). The initial channel must be nonzero, active, have valid BPS totals, and respect the consumer rebate cap. It is committed as version 1 and emits `ChannelVersionAdded` during construction. The stablecoin must be a standard, non-rebasing token with no incoming or outgoing transfer fee. V3 checks exact sender and recipient balance deltas and reverts on unsupported token behavior.

## CLI Flow

Deploy and pin a V3 testnet record:

```bash
python -m gateway chain deploy-myco-v3-testnet \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$DEPLOYER_PRIVATE_KEY" \
  --treasury "$TREASURY" \
  --governance "$GOVERNANCE" \
  --deployment deployments/sepolia-myco-v3.json

python -m gateway chain myco-v3-info \
  --deployment deployments/sepolia-myco-v3.json
```

On the testnet token only, mint, approve and deposit:

```bash
python -m gateway chain v3-mint-test-usdc \
  --deployment deployments/sepolia-myco-v3.json \
  --to <consumer-address> \
  --amount-usdc 10

python -m gateway chain v3-approve-usdc \
  --deployment deployments/sepolia-myco-v3.json \
  --private-key "$CONSUMER_PRIVATE_KEY" \
  --amount-usdc 10

python -m gateway chain v3-deposit-prepaid \
  --deployment deployments/sepolia-myco-v3.json \
  --private-key "$CONSUMER_PRIVATE_KEY" \
  --amount-usdc 10

python -m gateway chain v3-prepaid-balance \
  --deployment deployments/sepolia-myco-v3.json \
  --account <consumer-address>
```

Create a provider-specific, request-bound reservation. `--expires-at` is a Unix
timestamp and must respect the contract's maximum reservation duration. Omit
`--reservation-salt` to generate a cryptographically random bytes32 salt.
Exactly one of `--input` and `--request-hash` is required. `--input` is
appropriate when the CLI can construct the exact billable envelope; endpoint,
model and output cap must match the inference that will actually run. For a
structured `messages` value, pass the canonical v2 protocol SHA-256 as
`--request-hash` so the provider computes the identical bytes32 value:

```bash
python -m gateway chain v3-create-reservation \
  --deployment deployments/sepolia-myco-v3.json \
  --private-key "$CONSUMER_PRIVATE_KEY" \
  --provider <provider-payment-address> \
  --input "Summarize this document" \
  --endpoint responses \
  --model gpt-5.5 \
  --max-output-tokens 2000 \
  --pricing-version 1 \
  --amount-usdc 1 \
  --expires-at <unix-timestamp>
```

Run the matching inference with the same four committed values:

```bash
python -m gateway p2p infer <provider-host:port> "Summarize this document" \
  --endpoint responses \
  --model gpt-5.5 \
  --max-output-tokens 2000 \
  --settlement-version 3 \
  --pricing-version 1 \
  --settlement-chain-id 11155111 \
  --settlement-contract <v3-settlement> \
  --onchain-reservation-id <returned-reservation-id> \
  --reservation-expires-at <same-unix-timestamp> \
  --settlement-deadline <deadline-with-inclusion-buffer> \
  --consumer-payment-address <consumer-address> \
  --provider-peer-id <provider-peer-id> \
  --provider-payment-address <provider-payment-address> \
  --pricing-hash <version-1-pricing-hash> \
  --max-fee-usdc 1 \
  --consumer-wallet-private-key "$CONSUMER_PRIVATE_KEY"
```

The canonical commitment is SHA-256 over compact, sorted-key JSON encoded as
UTF-8 with non-ASCII preserved and non-finite numbers rejected. The object is:

```json
{
  "request_hash_version": "mycomesh.inference.request.v2",
  "endpoint": "responses",
  "model": "gpt-5.5",
  "input": "Summarize this document",
  "max_output_tokens": 2000
}
```

Serialization is compact and sorted, so whitespace and the display order above
are not hashed. `endpoint` is trimmed/lowercased and must be `responses` or
`chat`; the model string is exact. Use `input` for `responses` and `messages` for
`chat`. A chat client must hash and forward the original `messages` array; a
stringified, summarized, or reconstructed array is a different request.
Transport/routing metadata, payment data and `request_id` are excluded.
Interoperable Python clients should call the protocol helper rather than
reimplement serialization:

```python
from gateway.reservation import inference_request_hash

request_hash = "0x" + inference_request_hash(
    endpoint="responses",
    model="gpt-5.5",
    input_value="Summarize this document",
    max_output_tokens=2000,
)
```

An earlier V3 reservation that hashes only `input`/`messages` is incompatible
with request v2. Do not send work against it; release/reconcile it and create a
new reservation with the full v2 envelope commitment.

### Wallet-To-Ed25519 Session Authorization

The last flag in the example signs a one-reservation EIP-191 authorization with
a local EOA key. For an external EOA or EIP-1271 consumer wallet, first run the
same `p2p infer` command with the local-key flag removed and add:

```bash
  --session-authorization-nonce 0x<unique-32-byte-nonce> \
  --prepare-session-authorization
```

The command prints `authorization`, its `canonical_message`, and its
`eip191_digest` without sending inference. Sign that exact EIP-191 personal-sign
message, then rerun the otherwise identical command with:

```bash
  --session-authorization-nonce 0x<same-32-byte-nonce> \
  --session-authorization-signature 0x<wallet-signature>
```

Alternatively, add `wallet_signature` to the printed authorization object and
pass the complete signed object as inline JSON or
`--evm-session-authorization @authorization.json`. These three signing sources
are mutually exclusive. EIP-1271 signatures may be arbitrary nonempty bytes up
to 16 KiB.

The version is `mycomesh.evm.session.v1`. Its canonical JSON contains exactly
these signed fields; `wallet_signature` is not part of the signed payload:

```text
authorization_version, chain_id, settlement_contract,
onchain_reservation_id, consumer_payment_address, provider_id,
provider_payment_address, channel, pricing_hash, pricing_version,
request_hash, max_fee_units, expires_at, settlement_deadline,
provider_fallback_allowed, nonce, session_public_key
```

`session_public_key` is the Ed25519 key from the CLI `--identity`. Serialization
uses sorted keys, compact separators, ASCII JSON and rejects non-finite values;
EIP-191 applies the standard personal-message length prefix to those UTF-8
bytes. Every field must exactly match the on-chain reservation, provider and
inference command.

At the pinned confirmed block, the provider uses `eth_getCode` to distinguish
an EOA from a contract wallet. It locally recovers an EOA signature. For an
EIP-1271 wallet it calls `isValidSignature(bytes32,bytes)` at that same block and
accepts only the exact 32-byte ABI return `0x1626ba7e` followed by 28 zero bytes;
a raw 4-byte return or extra return data is rejected for this session path.

This authorization has one reservation/request scope. It is not a reusable
wallet session registry. Before use, the consumer can avoid publishing it,
release the reservation when permitted, or wait for expiry; there is no general
on-chain active-revocation registry for reusable sessions.

For a local provider settlement test, pin the same deployment values and require
confirmed reservation reads:

```bash
python -m gateway provider start \
  --network-profile local \
  --settlement-version 3 \
  --pricing-version 1 \
  --settlement-rpc-url "$ETH_RPC_URL" \
  --settlement-contract <v3-settlement> \
  --settlement-chain-id 11155111 \
  --settlement-confirmations 6 \
  --consumer-public-key <authorized-consumer-key> \
  --payment-address <provider-payment-address> \
  --pricing-hash <version-1-pricing-hash>
```

After a receipt contains provider evidence and consumer acceptance, print the
exact EIP-712 digest for external wallets, then submit both EOA signatures:

```bash
python -m gateway chain v3-prepare-receipt \
  --deployment deployments/sepolia-myco-v3.json \
  --ledger .codex-run/receipts.jsonl

python -m gateway chain v3-settle-signed-receipt \
  --deployment deployments/sepolia-myco-v3.json \
  --ledger .codex-run/receipts.jsonl \
  --private-key "$RELAYER_PRIVATE_KEY" \
  --consumer-signature 0x<65-byte-signature> \
  --provider-signature 0x<65-byte-signature>
```

The settlement command also accepts `--consumer-private-key` and
`--provider-private-key` for local tests. For an EIP-1271 contract wallet, use
`--consumer-contract-signature 0x<arbitrary-wallet-signature>` and/or
`--provider-contract-signature 0x<arbitrary-wallet-signature>`. Contract-wallet
signatures are nonempty arbitrary byte strings up to 16 KiB, not necessarily
65-byte ECDSA values. Before submitting, the CLI verifies that the signer has
contract code and that `isValidSignature(bytes32,bytes)` returns at least one
32-byte ABI word whose decoded `bytes4` is `0x1626ba7e` at `latest`; a bare
four-byte return is rejected. Each party must provide exactly one of its local private key, 65-byte
EOA signature, or EIP-1271 contract signature. Do not place user or provider
signing keys on a production relayer; use the prepare command and external
wallets. Anyone may call `v3-release-reservation --reservation-id <bytes32>`
after expiry.

Fallback is disabled unless the consumer explicitly created the on-chain
reservation with `providerFallbackAllowed == true` (`--allow-provider-fallback`)
and the signed off-chain payment reservation carries the same value. If opted in
and the consumer then refuses the final EVM signature, prepare the provider-only
digest and submit it with an external EOA signature, EIP-1271 contract signature,
or the local provider key:

```bash
python -m gateway chain v3-prepare-provider-fallback \
  --deployment deployments/sepolia-myco-v3.json \
  --ledger .codex-run/receipts.jsonl

python -m gateway chain v3-settle-provider-fallback \
  --deployment deployments/sepolia-myco-v3.json \
  --ledger .codex-run/receipts.jsonl \
  --private-key "$RELAYER_PRIVATE_KEY" \
  --provider-signature 0x<65-byte-signature>
```

`v3-settle-provider-fallback` requires exactly one of
`--provider-signature`, `--provider-contract-signature`, or
`--provider-private-key`. It uses an EIP-712 receipt whose `acceptedHash` is zero
and charges only the channel version's
`minimumFee`. The provider receives `providerBps`; every remaining stablecoin
unit goes to the version-pinned treasury. Relay and pool receive nothing, and
the path never mints MYCO. This is an explicitly authorized, non-refundable base
fee. It is not proof of service delivery, response correctness, quality,
uniqueness, or consumer acceptance. A reservation created without opt-in cannot
use fallback.

## Typed Governance And Rewards

The deployer creates the initial channel during settlement construction, so no timelock wait is required for version 1. Governance actions expose their full typed parameters and cannot be scheduled through a public arbitrary-action hash endpoint:

1. A channel update calls `scheduleChannelVersion(channel, config)`, waits at least `GOVERNANCE_DELAY_SECONDS()` (two days), then calls `addChannelVersion(channel, config)` with exactly the scheduled parameters.
2. A treasury update calls `scheduleTreasuryUpdate(nextTreasury)`, waits the same delay, then calls `setTreasury(nextTreasury)`.
3. Reward activation calls `scheduleRewardEnable()`, waits the same delay, then calls `enableRewards()`.
4. `pauseRewards()` is immediate and also cancels a pending reward-enable action. Re-enabling always requires a fresh schedule and delay.
5. `cancelGovernanceAction(actionHash)` cancels a queued typed action. Governance transfer uses the separate delayed `beginGovernanceTransfer` / `acceptGovernance` flow.

Persist the typed scheduling events and the emitted `version` and `pricingHash` from `ChannelVersionAdded`. New reservations must use `latestChannelVersion(channel)`, while an existing reservation remains bound to its original version. Keep `rewardsEnabled == false` until a separately reviewed anti-Sybil work and quality signal exists; request/response hashes and signatures prove authorization and integrity, not unique useful work.

The reward budget is deployment-relative: `currentEpoch()` counts seven-day
epochs from `emissionStartedAt`, not from the Unix epoch. The emission cap halves
after each 208 epochs. `epochMinted[epoch]` increases only after a reward token
`mint` succeeds, so a failed provider or consumer mint does not consume that
epoch's remaining capacity. Stablecoin settlement remains final and emits
`RewardMintFailed` for each failed mint.

EIP-712 signing clients should read `DOMAIN_SEPARATOR()` or construct the domain
from the current chain ID and settlement address. The contract caches the
deployment separator but dynamically rebuilds it if `block.chainid` changes, so
a signature from the former chain ID is not valid in the new domain.

## Reservation And Receipt Flow

The first `createReservation` argument is a consumer-chosen `reservationSalt`, not a caller-supplied global ID. Compute the canonical ID before submission with `reservationIdFor(consumer, reservationSalt)`. Its exact definition is:

```solidity
keccak256(abi.encode(settlementAddress, chainId, consumerAddress, reservationSalt))
```

The final function is
`createReservation(bytes32,address,bytes32,bytes32,uint64,uint256,uint64,bool)`
with selector `0xd8f2bc55`. Its arguments are `reservationSalt`, `provider`,
`channel`, the nonzero v2 inference `requestHash`, `pricingVersion`, `amount`,
`expiresAt`, and `providerFallbackAllowed`. It returns the canonical reservation
ID and emits it in `ReservationCreated`. The final boolean defaults to false in
the CLI, must be a native boolean without string/integer coercion, and must be a
deliberate per-reservation opt-in. A copied mempool salt
derives a different ID for a different caller and cannot block the consumer.

The public `reservations(bytes32)` getter returns exactly nine static ABI words,
in this order: `consumer`, `provider`, `channel`, `requestHash`,
`pricingVersion`, `expiresAt`, `amount`, `closed`, and
`providerFallbackAllowed`. Decoders written for the earlier eight-word tuple
must fail closed and be upgraded.

Receipt replay and settlement records use the composite key
`keccak256(abi.encode(reservationId, receiptHash))`. This prevents an unrelated
reservation that reuses the same `receiptHash` from blocking another consumer.
The final read ABI is:

| Function | Selector | Meaning |
| --- | --- | --- |
| `receiptSettled(bytes32,bytes32)` | `0xaa061aa6` | Query `(reservationId, receiptHash)` |
| `settlement(bytes32,bytes32)` | `0x28d93e69` | Read the settlement for the same pair |
| `settlementKeyFor(bytes32,bytes32)` | `0x640b1ad5` | Derive the composite storage key |
| `settlementKeySettled(bytes32)` | `0xe24b6931` | Low-level query by the already-derived key |

Receipt-hash-only query calldata and indexer keys are invalid for the final
contract.

The normal payment sequence is `stablecoin.approve` -> `deposit` -> `createReservation` -> EIP-712 signatures -> permissionless `settleSignedReceipt`. V3 accepts a deposit only when the token decreases the sender balance and increases the settlement balance by exactly `amount`; withdrawals and every settlement transfer enforce the same exact debit/credit invariant. Fee-on-transfer, rebasing, reflection and otherwise nonstandard balance behavior are unsupported and revert.

The EIP-712 `Receipt` fields and order must exactly match `RECEIPT_TYPEHASH` in `MycoSettlementV3`; in particular `pricingVersion` is `uint64`, and `reservationId`, relay, pool, pricing hash, evidence hashes, usage and deadline are all signed. V3 has no trusted-operator settlement endpoint.

Before performing inference, a V3 provider pins one confirmed block
(`latest - settlement_confirmations`) and reads `channelPricingHash`, `quote`
and the nine-word `reservations` getter at that block. Before any upstream call,
it requires the request model to equal `ProviderConfig.model`, which is also the
model in its signed descriptor. It canonicalizes the effective `input` or
original chat `messages` JSON and rejects a UTF-8 byte length above
`reserve_input_tokens`; bytes are an admission metric, not the fee token count.
The provider instead quotes the full configured `reserve_input_tokens` budget
locally and with V3 `quote`, so operator-injected system/agent/routing context is
covered. Operators must size this value for the complete upstream prompt
pipeline. An explicit positive output cap must not exceed
`reserve_output_tokens`; if omitted it defaults to that provider cap, and the
resolved cap is always forwarded upstream. The payment reservation must cover
the full input budget plus resolved output cap.

At the OpenAI-compatible HTTP edge, `max_output_tokens`,
`max_completion_tokens`, and `max_tokens` are equivalent. Each non-null value
must be a native positive integer; if multiple fields are present their values
must match, otherwise the request fails with HTTP `422`.

It also verifies the chain ID, configured settlement address, nonzero consumer,
`closed == false`, consumer/provider addresses, channel, v2 request hash,
pricing version/hash, amount, expiry, the fallback flag, and a settlement
deadline of at least `ceil(now + provider_timeout + 60 seconds)` but no later
than reservation expiry. Any malformed JSON, bound violation, insufficient
reservation, short deadline, RPC failure, malformed return, configured pricing
hash mismatch, request mismatch or local/on-chain quote mismatch rejects before
inference. After inference, it additionally compares the actual-usage local and
on-chain quotes at the same confirmed block before producing evidence. Reading
only `latest` is insufficient because a short reorg can remove the reservation.

Capacity is acquired before these checks. A concurrency/capacity rejection is
retryable and does not consume the V3 authorization. After every admission,
confirmed-chain, quote and wallet check succeeds, the provider atomically
inserts two persistent claims before the upstream call:

```text
p2p.v3.onchain.reservation:
  chain_id:settlement_contract:onchain_reservation_id
p2p.v3.session.authorization:
  chain_id:settlement_contract:consumer_payment_address:nonce
```

Both keys are inserted in one transaction and expire with the reservation. V3
defaults to `.codex-run/mycomesh-replay.sqlite3`, overridable with
`MYCOMESH_REPLAY_DB`; a duplicate key rejects before execution. Once the claim
is committed and execution begins, an uncertain
upstream failure remains consumed and is returned with `retryable: false`. The
client must reconcile the attempt or create a new reservation instead of
blindly resending it. This is intentionally at-most-once execution.

## V2 To V3 Migration

There is no storage migration or contract upgrade from V2. Treat V3 as a new
settlement domain and migrate explicitly:

1. Stop accepting new V2 jobs and record the V2 cutoff block.
2. Settle all accepted V2 receipts; expire/reconcile every outstanding local and
   on-chain reservation.
3. Withdraw each consumer's available V2 stablecoin balance.
4. Revoke the V2 settlement allowance at the stablecoin contract.
5. Verify the V3 chain ID, settlement bytecode, stablecoin, treasury, governance,
   EIP-712 domain, channel version and pricing hash from two RPC sources.
6. Approve V3, deposit, and reconcile the emitted `receivedAmount`.
7. Create a provider-specific, request-bound V3 reservation and wait for the
   configured confirmation depth before sending that exact work.
8. Produce the provider evidence, consumer acceptance, and both EIP-712
   signatures, then submit permissionless settlement.
9. Keep the V2 indexer and records read-only until all V2 balances and receipts
   reconcile to the cutoff block.

Never reuse a V2 signature, receipt hash, delegate authorization, or deployment
record in V3. The V3 EIP-712 chain ID and verifying contract provide a new replay
domain.

The final request-bound V3 ABI is also a breaking migration from every earlier
V3 deployment. An old V3 contract cannot be upgraded in place to reinterpret
its nine-field `Reservation` tuple, final-bool `createReservation` calldata, or
composite settlement queries. Deploy fresh V3 contracts, publish a new
deployment record, stop submissions to the old address, reconcile or release
old funds, and recreate every reservation with its v2 inference-envelope
`requestHash`. This includes reservations made against a newer contract but
with the legacy input-only hash. Old V3 reservations, calldata, receipt/delegate
signatures, settlement query keys and cached ABI decoders must not be reused.

## Remaining Integration Boundaries

V3 fixes settlement authorization, but it does not make the surrounding network
production-ready by itself:

- Non-local direct and relay inference uses signed transport-key bindings and
  sealed frames. Relay control should use HTTPS (`myco+relays://`). This is
  message-level encryption rather than a Noise session: metadata remains
  visible and independent cryptographic review is still a release gate.
- Proxy replicas must share one PostgreSQL `MYCOMESH_BILLING_DB`; separate
  SQLite files do not share a global reservation or key-registration lock.
- Provider replicas backed by independent replay databases do not share the V3
  reservation/session claim. All replicas for a provider must use one
  transactional shared claim store before production multi-host routing. Use
  one PostgreSQL `MYCOMESH_REPLAY_DB`; SQLite remains single-host only.
- The production-strict Gateway gate rejects every currently bundled backend:
  Codex app-server exposes native usage but no enforceable output cap, Codex CLI
  exposes neither, and a generic OpenAI-compatible URL is not a pinned metering
  contract. A backend must report both capabilities before paid testnet startup.
- Production confirmation depth, RPC diversity, alerting, key management,
  multisig governance, incident response and an external Solidity audit remain
  operator responsibilities.
- Only standard non-rebasing/no-transfer-fee stablecoins are supported. Token
  upgrades, deny-lists and pauses remain external issuer risks even when exact
  balance-delta checks pass.
- Provider fallback is off by default and usable only after explicit per-
  reservation opt-in. Even then it proves only a non-refundable base-fee
  authorization, not service delivery, response correctness, quality,
  uniqueness or consumer acceptance. Rewards must remain paused until anti-Sybil
  and quality signals are deployed and reviewed.

## Events To Index

Index at least `Deposited`, `Withdrawn`, `ReservationCreated`,
`ReservationReleased`, `ReceiptSettled`, `DelegateAuthorizationUsed`,
`ProviderFallbackSettled`, `RewardMintFailed`, `RewardsEnabled`, `RewardsPaused`,
`ChannelVersionAdded`, and the typed governance scheduling events. Deduplicate
by `(chain_id, contract, transaction_hash, log_index)`, retain block hashes, and
rewind on a parent-hash mismatch. `RewardMintFailed` means reward delivery
failed after stablecoin accounting; it does not roll back or invalidate
`ReceiptSettled`, and a failed mint does not increase `epochMinted`.
For settlement state, index `(reservationId, receiptHash)` rather than treating
`receiptHash` as globally unique.

Read stablecoin display units from `stablecoin.decimals()`. MYCO always uses 18 decimals.
