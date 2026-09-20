# Discovery Rollout: 2026-09-18

Status: Relay3 recovered and upgraded; production discovery is NOT enabled.

## Production State

| Node | Result |
| --- | --- |
| Bridge1 | Discovery-only code deployed; health and strict TLS verified |
| Bridge2 | Discovery-only code deployed; health and strict TLS verified |
| Bridge3 | Discovery-only code deployed via Bridge1; health and strict TLS verified |
| Relay1 | Discovery-only code deployed; settlement ready; two connected Providers after Relay3 maintenance |
| Relay2 | SSH direct/jump and public HTTPS timed out; not deployed |
| Relay3 | Discovery-only V8 code plus durable broadcast recovery deployed; inference and settlement ready; Provider4 connected |
| Provider2-4 | No code/configuration upgrade; Provider4 worker restarted while idle to restore its existing preferred Relay3 route; sidecar unchanged |
| Native Consumers | Existing unlocked processes retained; not upgraded or reconfigured |

The release is a discovery-only backport onto the actual deployed V8 baseline.
It does not include the workspace's pending V9, receipt-format, identity-binding,
or anti-cheat changes. Model configuration remains `gpt-5.5`. No wallet identity,
Provider login, deployment manifest, or trust root was changed by the rollout.
The code rollout did not clear the settlement ledger; the separately authorized
recovery below retired one expired row while retaining its evidence. Each deployed
node has a timestamped source backup.

Discovery authorities have not been created or selected. The proposed policy
requires operator confirmation: one separate discovery identity per Bridge,
with two of three endorsements required. Wallet, payment, and adjudication keys
must not be reused. Provider and Consumer production enablement remains pending.

## Verification

- The staged Python package passed 42 discovery, signature, configuration, IPv6,
  HTTP synchronization, expiry, replay, and real TCP failover tests. The runtime
  test copy omits only constructor arguments for the excluded anti-cheat modules.
- Native Consumer discovery tests: 24 passed. These are local integration tests,
  not evidence of production discovery enablement.
- One real baseline request used the existing Consumer's key and URL at port
  8113 and reached Relay3 / `gpt-5.5`: HTTP 200 in 6.805 seconds, expected response,
  accepted payment receipt, and exactly one matching Consumer history record.
- That baseline receipt initially remained pending, so the initial full workflow
  did not pass. The recovery below subsequently proved it unpaid and expired;
  it was not marked confirmed or rebilled.

## Original Settlement Blocker

The baseline request exposed `broadcast_unknown` in Relay3's existing settlement
worker. Its outbox contains one submitted item with one broadcast attempt:

```text
request: 0x78661880daf7172e38bb838668ee6dc42f856aff1e4c5fbdfc4be9125c96c5c3
tx hash: 0xec59acaad9117d627c343b4ea8460921ad2bb85eab195fdbcb9b5268fa66f35e
```

Successful read-only queries to the configured publicnode, ethpandaops, and
Tenderly endpoints returned no transaction or receipt for this hash. Observed
latest/pending submitter nonces were both 6. The dRPC endpoint returned HTTP 400.
Absence from these RPC responses does not prove that broadcast never occurred.

Before recovery, Relay3 remained active with three connected Providers but reported
`settlement_ready=false`; new requests are consequently blocked. This occurred
before Relay3's code deployment. The existing implementation persists only the
transaction hash, not the signed transaction bytes, so it cannot safely
rebroadcast the identical transaction after an ambiguous send. No outbox rows
were cleared, no confirmation was fabricated, and no replacement transaction
or additional payment was sent.

## Relay3 Recovery

The user authorized resetting and upgrading Relay3. Recovery preserved its
identities, configuration, Provider authorizations and complete settlement history.
SQLite was backed up using the backup API, including WAL contents; configuration
and identities were backed up on the host under a protected directory.

For the exact stuck row, payment, Provider and Relay signatures and the encoded
calldata were verified. Tenderly and publicnode independently agreed on finalized
block `11725690`, hash
`0xdcbcf97c5cd54c1babd16c1481fd5eebd04231cc9e26463c1da551fb66b51c4e`.
Its timestamp `1789672416` was strictly later than authorization deadline
`1789671918`; the correctly derived owner/key/request settlement mapping was false.
Executable V8 bytecode matched the audited artifact after masking constructor
immutables. The only other difference was the CBOR IPFS metadata hash, not code
or compiler version. Latest and pending submitter nonces were both 6.

After stopping the idle Relay, a guarded update changed only this row to
`failed / authorization_expired`. Its transaction hash, signatures, calldata and
timestamps other than `updated_at` remain preserved. No payment retry, replacement
transaction, cancellation or fabricated confirmation was made. A lost expired
transaction could in principle still consume gas/nonce while reverting; it cannot
newly settle this expired authorization.

The upgraded worker persists signed transaction bytes and their deterministic
hash before broadcasting, polls receipts across RPCs even after a primary returns
null, and can rebroadcast only identical bytes to chain-checked RPCs after restart.
It never allocates a fresh nonce for an ambiguous submitted transaction. Legacy
rows without signed bytes still require evidence-based reconciliation. Fee-bump
replacement is not implemented. Database directory/file modes remain `0700/0600`.

Recovery tests: main settlement/V9 suites 99 passed, settlement-block tests 9
passed, staged V8 tests 56 passed; an independent final run of submission, health
and connection tests passed all 49 tests. Production candidate imports, installed
hashes, unchanged configuration/identities and the untouched edge process passed.

All three Providers failed over to Relay1 during maintenance. Provider4 was then
restarted only after idle checks to restore its existing Relay3 preference; its
container identity, replay ledger and sidecar process were unchanged. This leaves
two Providers on Relay1 and one on Relay3, without requiring reauthorization.

One real post-upgrade Consumer request used its existing key and URL at port 8113,
`/v1/responses`, model `gpt-5.5`. It reached Relay3 / Provider4 and returned the
expected `mesh recovery ok` response in **9.639 seconds**. The worker recorded
successful settlement; the outbox now contains seven confirmed rows and the one
expired failed row, with no pending or submitted rows.

Independent read-only verification through publicnode and Tenderly agreed on
successful transaction
`0x451541c606ed267302ffc1af7f914f4e6ce995a29bb9e28cf01f560151f71386`
in canonical block `11725775`, with 23 confirmations at verification time. Both
matched the exact request, owner, payment key mapping, Provider signer and payout,
Relay payout, expected submitter, and fee of **2140 base units (0.002140 tUSDC)**.
The on-chain settlement mapping is true. Earlier EthPandaOps read errors remain
preserved in the evidence rather than being treated as failed transactions.

The Consumer history contains exactly one matching request, but its locally
stored status remains `pending`. The existing Consumer was not reauthenticated
or modified to force a refresh; its displayed billing status is not yet verified
as confirmed, despite the independently confirmed on-chain settlement.

Discovery trust still needs explicit configuration, followed by compatible
Provider/Consumer upgrades and production discovery, streaming and session
continuity tests. Those discovery tests remain outstanding; recovery does not
enable discovery or deploy the pending V9/anti-cheat migration.

## Local Evidence

The ignored `.codex-run/mesh/discovery-release-20260918/` directory contains:

- `20260917-discovery-code-190120Z.json`: Bridge1 deployment and backup.
- `20260917-discovery-code-190309Z.json`: Bridge2, Bridge3, Relay1 deployment.
- `20260917-discovery-code-190355Z.json`: Relay3 guard rejection before mutation.
- `provider-readiness-preflight.json`: Provider2-4 health and idle snapshots.
- `baseline-inference.json`: the single real inference result, without API keys.
- `baseline-settlement-check.json`: read-only RPC and Consumer history evidence.
- `20260917-relay3-reconcile-192642Z-apply.json`: finalized chain proof and exact-row recovery.
- `20260917-relay3-recovery-192556Z.json`: deployment hashes, backups and verification.
- `provider4-reconnect-20260917-192959Z.json`: idle reconnect and unchanged sidecar evidence.
- `recovery-inference.json`: real post-upgrade Consumer request.
- `recovery-settlement-verification.json`: two-RPC confirmation, exact fee/event checks, and Consumer history status.

Backup directory names use UTC; the document date uses Asia/Shanghai.
