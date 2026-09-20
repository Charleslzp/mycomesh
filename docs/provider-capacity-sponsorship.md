# V10 Provider network-funded capacity

V10 keeps the Provider's own collateral optional for controlled testnet admission. A Provider can be admitted with capacity funded by the network governance account; the Provider does not need to approve a token transfer or submit a stake transaction.

The contract exposes a bounded sponsorship path:

1. Governance calls `setSponsoredCapacityLimit(remainingBudget)` on the V10 settlement contract. A zero value leaves sponsorship disabled.
2. Governance approves the settlement contract for the exact stablecoin amount and calls `sponsorProviderCapacity(provider, amount)`.
3. The sponsored amount is added to the Provider's capacity account and is included in the normal `capacity >= channel` check. The Provider signs the channel permit but does not fund the sponsored principal.
4. `withdrawStake` excludes sponsored principal, so a Provider cannot withdraw the network's reserve. If a confirmed dispute produces a slash, the sponsored portion is consumed first and the remaining sponsorship budget is restored by that amount.

The sponsorship budget is a **remaining global budget**, not a per-Provider unlimited faucet. In this controlled testnet implementation, funded sponsorship is intentionally retained until the deployment is retired; there is no public reclaim function. Set the limit conservatively and record each funding transaction in the operator ledger. A production deployment must add a governance-timelocked reclaim/rotation path and publish the pool's accounting before enabling public admission.

This mechanism does not turn off dispute protection. A Provider can still be quarantined for hard protocol violations, and monetary consequences remain disabled until the independent adjudication flow resolves evidence. Relay `/health` reports this explicitly as `enforcement_mode: quarantine_only` and `monetary_enforcement_enabled: false`.

The feature is additive to the V10 ABI: it does not change the constructor, `OpenChannel` typed data, or `CapacityChannel` tuple. Existing V10 deployments do not contain the new functions and must be redeployed before sponsorship is used.
