# Settlement V9: local escrow/dispute prototype

Status: **undeployed, unaudited for production, no real transactions or funding**.
The implementation is [MycoSettlementV9.sol](../contracts/MycoSettlementV9.sol)
with [local Foundry tests](../test/MycoSettlementV9.t.sol). Test fixture amounts,
addresses and delays are not deployment recommendations.

This is a separate contract with EIP-712 domain version `9`, not a V8 upgrade.
It preserves the request-key authorization and separate Provider payout/signer
receipt structure, but existing V8 signatures are not valid on V9. No deployed
V8 balance, receipt or historical claim is migrated, frozen or clawed back.
The Relay/client now have explicit V9 protocol support, but remain on V8 unless
configured with a validated V9 deployment. See [the integration runbook](settlement-v9-integration.md).

## Explicit constructor policy

There are no selected production assets, judges or economic defaults.
Constructor arguments are the stablecoin, optional reward-token address,
initial treasury, governance, initial channel/configuration, dispute policy,
adjudicator addresses and threshold.

| Policy field | Contract constraint and meaning |
| --- | --- |
| `disputeWindow` | Positive, at most 30 days; full evidence-collection window measured from settlement. |
| `arbitrationTimeout` | Positive, at most 30 days; additional voting period after the collection window ends. |
| `consumerWithdrawalDelay` | Positive, at most 30 days; available-balance withdrawal delay, separate from earnings escrow. |
| `reporterBond` | Positive stablecoin units, taken once per report. |
| `slashBps`, `slashCap` | 1–10,000 basis points and a positive absolute stablecoin cap. Slash is `min(floor(grossFee × slashBps / 10000), slashCap)`. |
| `reporterBountyBps`, `stableBountyCap` | 1–9,999 basis points and a positive cap no greater than `slashCap`. Stable bounty is a capped fraction of the slash, never of the Consumer refund. |
| `tokenReward`, `tokenRewardCap` | Fixed reward per eligible confirmed case and a lifetime award/funding cap, in reward-token native units. No minting. |
| `tokenMinimumExposure` | Positive minimum gross stablecoin fee before a confirmed case can receive tokens. |
| `tokenMinimumPenalty` | Positive minimum `slash − stableBounty` before tokens can be awarded; no greater than `slashCap`. |
| `bondPenaltyRecipient` | Explicit nonzero recipient of dismissed bonds and the non-bounty portion of a confirmed slash. |

Set reward-token address to zero **and** all four token-policy quantities to zero
to disable tokens. Otherwise the reward token must have code and differ from
the stablecoin; `tokenReward` must be positive and at most `tokenRewardCap`.
No rewards are promised from an empty reserve. Partial rewards and retroactive
top-ups to a resolved case are not supported.

The adjudicator set is constructor-pinned, distinct, at most 16 addresses, and
requires a strict majority threshold of at least two. It cannot later be
replaced by governance. Addresses matching initial governance, treasury or the
penalty recipient are rejected. Distinct addresses do not establish distinct
operators: onboarding and independent control remain external obligations.

For each receipt, Consumer/key, Provider/payout signer, Relay/payout signer, Pool,
versioned treasury and penalty-recipient addresses cannot adjudicate their own
record. Settlement admission rejects records without enough independent judges.
Judges cannot submit reports. Governance cannot be transferred to a judge.

Channel pricing and revenue shares remain versioned. Governance can create new
versions and change the treasury for later versions, but cannot rewrite stored
shares, dispute policy, reward policy, judge membership or earlier receipts.

## Escrow and full-window evidence flow

1. `settleSignedReceipt` verifies all three signatures and authorization/price
   bindings. It deducts the gross fee from Consumer available credit, escrows
   that entire fee, and locks an equal amount of the Provider's deposited stake.
   No earnings become claimable yet. Duplicate request keys cannot be settled.
2. Until `releaseAt = settledAt + disputeWindow`, a bonded first report can call
   `openDispute`; other reporters can call `submitEvidence` on that case. Each
   reporter can submit once. Reports are immutable commitments keyed by the
   settlement, reporter and evidence hash, with no first-reporter monopoly.
3. The **entire original collection window remains open**. Judges cannot vote,
   confirm or dismiss a report before `releaseAt`. Supplemental reports do not
   extend the fixed deadline `releaseAt + arbitrationTimeout`.
4. After collection, each eligible judge can cast one irreversible vote. A
   confirmation quorum must select the same report ID. Rejecting the case also
   needs a quorum. Hashes merely reference independently verified evidence and
   reasons; the contract does not determine their truth or authorship.
5. A case cannot reopen after resolution. Bond returns are claimed individually;
   no unbounded report-array loop is necessary for resolution or Consumer refund.

Different reporters may submit the same evidence hash. Otherwise an observer
could copy a genuine report's pending transaction and censor its original
reporter. The jury must assess attribution, choose the actual winning report,
and not reward the first submitted hash merely because it was first. A junk
first report therefore cannot prevent a later genuine report from winning.

| Outcome | Consumer gross fee | Provider stake | Reporter bonds | Bounty |
| --- | --- | --- | --- | --- |
| No report, released after window | Stored shares become claimable | Exposure unlocked | None | None |
| Confirmed winning report | Entire fee returns to Consumer available credit | Capped slash; remainder unlocked | Each reporter can reclaim its own bond | Winning reporter only; stable amount from slash, optional prefunded tokens |
| Dismissed after window | Stored shares become claimable | Unlocked, not slashed | All bonds credited to explicit penalty recipient | None |
| No quorum by fixed deadline | Stored shares become claimable | Unlocked, not slashed | Each reporter can reclaim its own bond | None |

Consumer refunds are ledger credits, not immediate pushed transfers. Consumers
use the available-balance withdrawal flow; payees use `claim()`. Anyone can call
`claimDisputeBond`, but the bond always becomes claimable by the recorded
reporter, never by the caller. Token rewards have a separate `claimTokenReward`
so a failed reward transfer cannot prevent stablecoin refund/adjudication.

## Conservation and transfer assumptions

For supported exact-transfer tokens, stablecoin balance covers:

```text
totalAvailable + totalClaimable + totalPendingFees + totalStake + totalReporterBonds
```

`stableLiabilities()` exposes that sum. Direct token donations can make balance
larger; they do not create spendable user credit. Every report bond and reward
funding deposit checks both sender and contract balance deltas. Outgoing token
transfers likewise check contract and recipient deltas. Fee-on-transfer,
additional-sender-debit and rebasing tokens are unsupported. Token methods or
balances controlled by a dishonest issuer still require asset-level trust.

`lockedStake[provider]` is the sum of that Provider's pending/disputed gross fees.
Stake withdrawal cannot touch it. A confirmed slash cannot exceed that case's
fee-sized exposure and cannot consume another pending receipt's collateral.
The Consumer's **entire escrowed fee is refunded**; its refund never funds the
reporter's reward. Stable bounty plus the explicit residual penalty equal the
slash, while bond returns consume only bond liabilities.

Reward accounting is separate:

```text
rewardReserve + totalTokenClaimable <= reward-token balance
totalRewardAwarded <= tokenRewardCap
totalRewardFunded <= tokenRewardCap
```

No external reward-token call occurs while deciding a dispute. The contract
never invokes a mint function and does not allow governance to withdraw user
credit, collateral, bonds or reward reserves. Reentrant state mutations are
rejected across token-transfer and adjudication entry points.

## Limits that remain before any deployment

- The contract trusts the pinned jury's independently verified evidence. It
  does not prove a named model, software integrity, computational correctness,
  or independence of human operators behind different addresses.
- Judges must coordinate on one report before voting. If honest judges choose
  different reports, their votes do not combine into an invented quorum; a
  split can reach the nonpunitive timeout even when all believe cheating
  occurred. There is no revote/certificate aggregation implementation here.
- Timeout returns bonds rather than declaring a report false. This prevents
  permanent fund lock and automatic punishment on silence, but permits bonded
  delay/griefing. Evidence spam and lost/unavailable judges still require
  operational safeguards. Membership replacement is deliberately not hidden
  behind governance in this prototype.
- Minimum exposure and a positive non-returned slash prevent a zero-rounded
  penalty or full stablecoin rebate from earning tokens. They **do not** solve
  colluding Provider/Consumer/reporter farms or compare the market value of two
  assets. Set an independently reviewed reward-to-cost policy or keep tokens
  disabled; the lifetime cap bounds losses, not Sybil identities.
- Provider stock is locked only after on-chain receipt settlement. Consumer
  authorizations do not reserve a fee in advance, and a short available-credit
  withdrawal delay can still race unfinished work. Admission and prepayment
  policy for that V8-inherited service risk are separate deployment decisions.
- Asset safety, economic parameters, judge onboarding/availability, evidence
  retention, watcher costs, fees/gas, approved deployment manifests and
  migration/rollout still require operator decisions. The integration adds
  domain-aware clients and explicit deployment tooling, not those decisions.

`gateway/relay_adjudication.py` verifies separate **offline Ed25519** quorum
certificates and produces non-payable plans. Those certificates are not EVM
transactions, V9 vote signatures, or authorization to move money. The new
`relay_adjudication_v9.py` bridge requires each V9 judge's explicit independent
review and EVM transaction authorization. Its pinned-chain, default-dry-run
workflow does not treat an offline certificate as permission to spend.

Before activation, obtain external security/economic review and explicitly
select production assets, independently operated committee/threshold, dispute
and withdrawal windows, collateral/slash/bond amounts and reward caps. No such
choices or authority to deploy/fund have been assumed here.

## Local verification

Executed without network or compiler downloads:

```sh
forge test --offline --match-contract MycoSettlementV9Test -vv
```

Result: **30 tests passed, 0 failed**, including the accounting resolution fuzz
test with **256 runs**. Coverage includes early claims/locked stake, exact full
refund, slash and bounty caps, adversarial first-report ordering, late evidence,
same-report quorum, split-vote timeout, terminal replay, conflicted judges,
token scarcity/failure, zero-rounded slash, transfer fees, reentrancy,
domain/chain signature binding and mixed terminal accounting with all withdrawals.
This is local regression coverage and internal review, not a production audit
or a formal proof.

The additional whole-repository run, `forge test --offline --summary`, was **not
green**: 89 passed and 3 failed in unchanged V4/V5 test files. V4's
`testFailedClaimRetainsCredit` is rejected by the installed Foundry version's
removed `testFail*` naming convention; V5's
`testDuplicateReceiptAndSequenceSettlementRejected` and
`testReceiptCannotChangeBoundRelayOrPool` report an unmet expected revert.
Those unrelated tests were not edited as part of this prototype.
