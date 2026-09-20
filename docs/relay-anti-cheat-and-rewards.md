# Relay integrity, probes and reward boundary

## Implemented locally; no rollout or payments performed

The Relay verifies the complete signed Provider response, original Consumer
authorization, deployment, payout/signer, output commitment, usage and output/fee
limits **before** co-signing or enqueueing a V7/V8 receipt. Pool payout must be
zero, matching the current Provider reservation path. Exact pricing is still
enforced by the contract unless trusted pricing is supplied to the verifier;
reported usage does not prove actual compute.

The commitment is `mycomesh.provider-response-commitment.v1`: full raw API body
(including structured output/tool calls), outer text/usage, request/model/endpoint
and Provider peer identity. Legacy text-only hashes are not accepted. Upgrade
Provider and Relay together after draining old in-flight work and allowing old
cached authorizations to expire. No silent downgrade is provided. The V7/V8
EIP-712 ABI is unchanged. Existing Consumers do not independently check this full
body commitment; this protects Provider-to-Relay, not against a malicious Relay.

Public V7/V8 registration also requires the receipt signer to sign the peer key,
fresh challenge, audience and deployment. Merely advertising another signer's
address cannot implicate it. This proves control of two keys, not a machine,
model or payout wallet authorization (the latter is checked on chain).
Provider payout private keys remain unnecessary during inference.

## Quarantine and evidence

New work checks quarantine at candidate selection, enqueue and actual dispatch,
including direct `/infer/<peer>`. Already dispatched work is not automatically
replayed or confiscated. Recovery/status calls are currently blocked too; there
is no unchecked bypass.

Risk is keyed by peer and authenticated receipt signer scoped to chain/contract.
Checks also include the Relay's configured deployment, so advertising another
contract does not hide a quarantined signer from direct inference. Changing
only the peer does not clear it. Changing both signing and economic
identities still needs staking/admission costs; this is not Sybil resistance.
Risk is never attributed to an unverified claimed wallet. Database outages pause
new dispatch and log errors; memory fallback protects the current process.

Original Consumer authorizations, Provider responses/registrations and request
constraints are retained with an immutable record hash and a Relay observer
signature. They are observations, not monetary verdicts. Offline
`verify_relay_incident(..., expected_observer_public_key=..., observed_at=...)`
pins the observer key, requires an independently trusted observation time and
rechecks registration, economic identity, authorization and the original signed
response. It distinguishes self-contained protocol contradictions from
context-dependent allegations; Relay-authored context alone does not prove what
was dispatched. The deterministic observer signature uses authorization issue
time as an anchor, not as proof of observation time. Historical replay does not
weaken the live payment verifier, which still rejects expired authorizations.

`MYCOMESH_RELAY_INCIDENT_DB` selects the SQLite file. Docker/IP-mesh configure it;
public `serve_relay` defaults it beside the settlement DB. Files use mode 0600.
Responses may contain sensitive output: restrict access, use encrypted storage
and establish retention policy before production. Incident records do not add
raw user prompts.

Evidence plus hard-risk updates are atomic. Identical retries are idempotent;
conflicting retries fail. Soft failures can reach `suspect`, never permanent
quarantine. Hard quarantine is sticky. Local operator-only
`clear_quarantine(provider_id, operator_id, reason, action_id)` records recovery;
there is no public recovery route or automatic monetary verdict. Clear affected
peer and signer scopes after review. Migration preserves prior quarantines.

## Active probes: explicit sponsorship, disabled by default

The bounded worker issues randomized JSON/arithmetic challenges, scores locally
and uses ordinary paid V8 inference with all receipt/body checks. It targets the
selected peer exactly. Signed probe artifacts are retained. Timeout, local
errors and unverifiable results are inconclusive, not cheating. Simple probes
can be recognized or selectively routed; they cannot identify a named model.

Opt-in requires:

- `MYCOMESH_RELAY_PROBES_ENABLED=true`
- Durable `MYCOMESH_RELAY_PROBE_DB` and `MYCOMESH_RELAY_INCIDENT_DB`
- `MYCOMESH_RELAY_PROBE_SPONSOR_KEY_FILE`: dedicated pre-authorized payment key
  in a process-owned regular 0400/0600 file. Never reuse a user's, payout,
  receipt-signer or transaction-relayer key.
- Positive `MYCOMESH_RELAY_PROBE_MAX_FEE_UNITS` per-probe maximum.
- Positive `MYCOMESH_RELAY_PROBE_DAILY_BUDGET_UNITS` UTC-day maximum.

Startup never funds or authorizes keys. The full maximum is durably reserved
before dispatch and never released on uncertainty/error/restart; this
conservatively overcounts possible charges. The budget is per durable Relay
database, not a global wallet cap across Relays. Defaults: one concurrent probe,
one attempt per 60 seconds. Hung callbacks retain their slot rather than spawn
unbounded threads. See `relay_probe_runtime.py` for optional interval/timeout and
budget-file settings. Shutdown stops new probes and drains existing calls before
stopping the settlement submitter, bounded to 30 seconds. Calls still unresolved
at that deadline remain uncertain; their reserved budget is never refunded.

## Independent decisions and money

`relay_adjudication.py` verifies immutable off-chain decisions from at least two
pinned Ed25519 authorities. Reporter and accused Provider are excluded. Decisions
bind record hash, domain, policy and independently trusted financial context.
Amounts are not trusted from reporters. Results always say `payable=False`,
`onchain_linked=False`. Distinct keys do not prove independent human operators.
These certificates are not EVM payment authorizations. The separate
`relay_adjudication_v9.py` operator bridge builds V9 transactions from pinned
on-chain state and verifiable evidence; it does not turn Ed25519 signatures
into EVM committee votes. See [the V9 integration runbook](settlement-v9-integration.md).

V8 has no earnings escrow, dispute/slash/refund or reward-token entry points.
Historical V8 funds cannot be frozen or reclaimed by these modules.
`MycoSettlementV9.sol` is a separate undeployed contract, not a V8 migration
or production-ready release. Python Provider/Relay, native Consumer, and the
operator execution bridge now support explicit V9 deployments. Constructor
policy, assets and adjudicators must be chosen explicitly. Review, economic
calibration, funding and coordinated rollout are required before activation. A bounty intent
does not represent paid tokens or guaranteed refunds.

## Local verification for this change

- Final focused Python regression: **354 passed** across Relay, scheduler,
  robustness, receipt/response integrity, cryptographic integration, quarantine,
  evidence replay, incident/probe stores, active-probe runtime, adjudication,
  V7/V8 Provider/chain, attestation, Pool and IP-mesh tests.
- V9 Foundry regression: **30 passed**, including 256 accounting fuzz runs;
  see [the prototype report](myco-settlement-v9-prototype.md).
- `git diff --check` and scoped Solidity formatting checks passed.
- Expanded Python regression is **not entirely green**: deployment-config
  assertions still expect fixed 4-CPU Provider settings and the old
  `--protected-identity` onboarding flag; the current unrelated working-tree
  configuration uses configurable 2-CPU defaults and `--protected-wallet`.
- The full Foundry run also has three unchanged V4/V5 failures, documented in
  the prototype report. These failures were not hidden or fixed by weakening
  assertions. No live network rollout, paid upstream probe, funding or chain
  transaction was performed during this implementation.
