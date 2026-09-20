# V10 Provider execution journal

This is the fixed-budget Provider path. V8/V9 runtime and receipt domains remain separate. V10 accepts `payment_v10` plus the Relay's **pre-execution** `relay_dispatch`, and returns `settlement_v10` containing the original authorization, dispatch, and Provider usage signature. No second Relay signature is needed after inference.

## Start a controlled channel

Use a unique receipt signer for each active Provider writer. Do not run copies of a receipt signer on different hosts or isolated filesystems. The process holds exclusive locks on its ledger and anchor paths; this is local single-writer fencing, not a distributed consensus lock. A channel's fixed signer cannot migrate to another instance by creating an empty ledger.

The Provider uses these environment settings:

- `MYCOMESH_V10_EXECUTION_LEDGER`, default `/data/v10-execution.sqlite3`
- `MYCOMESH_V10_EXECUTION_ANCHOR`, default `/data/v10-execution-anchor.json`
- Existing protected `evm_identity_path` supplies the receipt signer; the payout remains an external owner wallet.
- Controlled committee manifests require the explicit existing policy opt-in `MYCOMESH_ALLOW_CONTROLLED_V10_TEST=1`; this does not weaken channel accounting.

Create the ledger explicitly once, while the Provider is stopped:

```sh
python -m gateway.reserved_execution initialize \
  --ledger /data/v10-execution.sqlite3 \
  --anchor /data/v10-execution-anchor.json \
  --provider-signer "$PROVIDER_SIGNER"
```

Open a channel with enough future `valid_from` to wait for six confirmations and still leave more than 300 seconds. A 20-minute startup window is suitable for the controlled Sepolia rollout. After it is confirmed, activate it **before starting the Provider**:

```sh
python -m gateway.reserved_execution activate \
  --ledger /data/v10-execution.sqlite3 \
  --anchor /data/v10-execution-anchor.json \
  --provider-signer "$PROVIDER_SIGNER" \
  --rpc-url "$SETTLEMENT_RPC" --chain-id 11155111 \
  --contract "$SETTLEMENT_CONTRACT" --channel-id "$CAPACITY_CHANNEL_ID" \
  --confirmations 6
```

The reader pins one confirmed block hash with `requireCanonical: true`, validates the chain ID and channel hash, and rechecks the block's canonical hash. A missing channel, changed binding, stale head clock, unsupported hash-pinned RPC, insufficient backing, or reorg fails closed. First activation also requires zero settled max fees and the full channel credit and stake reservations. It never treats zero on-chain settlements as evidence that an already-started channel has not executed.

Start the V10 Provider after activation; requests remain blocked until both the local clock and chain head reach `valid_from`. V10 testnet runtime requires at least six confirmations. Adding another channel currently requires a brief stop/activation/restart; the management UI is separate work.

## Execution and recovery

Before inference, the Provider verifies the Consumer signature, pre-execution Relay signature, immutable Provider/Relay/pricing terms, confirmed channel backing, local pricing against the hash-pinned chain quote, and execution time bounds. It then commits the full authorization and dispatch plus the **maximum** fee in SQLite with `synchronous=FULL`, and fsyncs a separate sequence anchor. The model is called only after both succeed.

The maximum fee is permanently occupied in the channel ledger. Actual fees do not replenish it. Completion atomically stores the full response and signed receipt before returning success. A replay with the same identity and content returns the saved response. Changed authorization/content fails. Any ambiguous execution remains `unknown` and is not automatically replayed, refunded locally, or presented as a confirmed bill.

Keep the latest ledger and anchor together. Loss of either file, an older database against a newer anchor, replacement during runtime, or an inconsistent signer stops execution. If all local state is lost after `valid_from`, recover the latest trusted state or open a new future-start channel. Restoring an older **complete** database-and-anchor backup is not safe; neither local file fencing nor chain settled totals can discover lost unsubmitted executions.

## Independent Provider settlement

Read or export receipts while the Provider writer continues running:

```sh
python -m gateway.reserved_execution outbox \
  --ledger /data/v10-execution.sqlite3 \
  --anchor /data/v10-execution-anchor.json \
  --provider-signer "$PROVIDER_SIGNER"
```

Plan a submission with canonical channel verification. This does not read a gas key or send a transaction:

```sh
python -m gateway.reserved_execution submit \
  --ledger /data/v10-execution.sqlite3 \
  --anchor /data/v10-execution-anchor.json \
  --provider-signer "$PROVIDER_SIGNER" \
  --rpc-url "$SETTLEMENT_RPC" --chain-id 11155111 \
  --contract "$SETTLEMENT_CONTRACT"
```

To submit, add `--send --transaction-identity /data/provider-settlement-gas.json --submission-outbox /data/provider-submission.sqlite3`. The identity uses the existing protected Provider identity JSON format and needs gas. Use a dedicated transaction account for this persistent submission outbox; do not share it with another submitter/outbox. This permissionless sender does not need the Consumer's key, the owner wallet, or a fresh Relay signature.

Each independent Provider command processes at most one batch (default 2 receipts; `--batch-size 1..32` adjusts it without bypassing gas admission) when the durable two-hour / 100-receipt schedule is due (or a receipt deadline requires an earlier safety flush). A one-minute timer can poll this safely: re-enqueueing does not reset the original queue time, and polling does not force settlement. Add `--force` explicitly to bypass the schedule for one batch. Repeat with the same submission DB to process a due cohort or reconcile unknown transactions. The submitter persists transaction state before broadcast and checks already-settled channel/request records. Submission attempts and confirmed settlements are reported separately. Expired or invalid unqueued receipts are reported as skipped, never silently reauthorized. Export defaults to 1,000 completed records; `--limit` raises that bound when needed. Submit filters expired authorizations before the limit so old history cannot starve active receipts. Use `--include-expired` for an explicit all-history submission plan; pending/unknown transactions in the separate submission DB are still reconciled even when the execution export is empty.

When a submission DB is supplied, terminal receipts in that DB are also filtered before the export limit, using the chain, contract, channel, and request identity together. This keeps already-handled live history from hiding newer receipts. The read-only `outbox` export still includes all completed history. The Provider fallback timer also reconciles expired durable pending receipts even when the live execution export is empty and Relay health is green. It checks canonical settlement state first, including after channel closure; absence permits recording expiry only after the confirmed block timestamp has passed the authorization deadline. An earlier snapshot cannot rule out a competing submission in the unconfirmed blocks. Submitted or unknown transactions retain their original transaction recovery path.

## Validation scope

Ledger tests cover concurrency, crash/anchor failure, exact replay, missing files, rollback, writer exclusion, and read-only outbox access. Provider tests use real cryptographic authorization/dispatch/receipt signatures with fixture RPC and inference responses; they cover response persistence, timeouts, wrong route/signer, admission expiry, missing activation, price checks, and explicit dry-run versus submission calls. RPC boundary tests cover canonical hash pinning, reorgs, wrong chain, head-clock drift, and unsupported EIP-1898. These tests are not evidence of a successful live Provider/Relay deployment or a real model execution.
