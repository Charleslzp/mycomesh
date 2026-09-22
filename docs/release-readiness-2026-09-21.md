# Release readiness — 2026-09-21

This release keeps the V7–V9 protocol modules because they are still imported by
Relay compatibility paths, operator tooling, or regression tests. The cleanup
removes generated output from the source boundary and consolidates runtime
release metadata; it does not delete a protocol implementation that is still
part of a supported migration or settlement path.

The source release boundary is checked by `python3 scripts/release_gate.py` and
by `make release-check` before the full test target runs. The gate verifies:

- Provider package version `0.1.38` and Consumer package version `0.1.52` match
  the versions reported by their runtime entry points and lockfiles.
- Source checkouts keep Provider release pins intentionally unbound; the
  release staging command injects the exact commit and Provider index digest
  only into the temporary Provider tarball.
- Consumer and Provider npm allowlists include only the active V10 manifest
  and CA, so local historical manifest backups cannot enter a release tarball.
- V9 policy and V10 deployment/network manifests are present.
- Canonical `node-up`, `node-health`, and `provider-health` targets exist.
- Generated directories are absent from Git tracked files.

Artifact release readiness is a distinct, stricter gate. The image workflow
now publishes only `candidate-<full-commit>` multi-platform tags with explicit
OCI revision labels, SBOM, and provenance; it cannot update `latest`, `main`, or
semantic-version tags. The manual `release-candidate.yml` workflow accepts only
an exact 40-character source commit and immutable Provider index digest. It
requires matching amd64/arm64 revision labels, at least seven days of remaining
V10 channel admission, six confirmations and agreement from two distinct
Sepolia RPC origins, compiler/runtime bytecode agreement, the exact deployer and
current contract policy, stablecoin runtime and solvency, pricing configuration,
EIP-712 capacity-channel identities, canonical open events and enough remaining
budget for another maximum-fee request. A promotable candidate additionally
requires `committee_mode=independent_users`, distinct attested operators, and a
complete deployment-bound high-reputation `monetary_policy`; the current
`controlled_test` manifest is intentionally rejected. It also requires byte-for-byte npm
package agreement before signing and uploading a candidate bundle. It neither
publishes npm packages nor deploys or retags an image.

Passing the source gate alone therefore does not establish that npm, OCI, or
live-chain artifacts are ready. A release is eligible for human promotion only
after the strict candidate workflow succeeds. Promotion of a verified digest
to any stable tag and npm publication remain separate, explicitly authorized
operations and are not performed by either workflow.

The workflow verifies the Provider image's GitHub attestation against the exact
image-build workflow, `refs/heads/main`, source commit and GitHub-hosted runner.
This is still conditional on repository administration: as of the 2026-09-22
audit, `main` has no branch protection/ruleset, Actions does not require SHA
pinning, and the `release-candidate` environment does not yet exist (therefore
has no required reviewers). Those settings,
plus a newly deployed V10 runtime and fresh channels, are hard promotion
blockers; checked-in workflow code cannot substitute for them.

The Provider launcher now reports saved setup state, settlement protocol, and
its pinned release ref through `mycomesh-provider --doctor`. It reports a
missing settings file as first-run setup instead of making the operator infer
that state from a later Docker failure. Secrets are never included in the
diagnostic output. Automation and support tools can use
`mycomesh-provider --doctor-json`, which emits the stable
`mycomesh.provider.doctor.v1` schema with per-check recovery guidance.

The Consumer now separates fast liveness from paid readiness. `/ready` reports
whether the local service is alive without pretending that a paid request can
succeed; `/paid-ready` verifies the wallet, chain and settlement code, usable
V10 channel budget, and model routes, with actionable 402/423/503 outcomes.
The first screen and dashboard show wallet, network, budget and model state.

The Consumer playground now offers an explicit retry button only for transient
transport or route failures. Budget, authorization, and payment-status errors
keep the user in the appropriate setup or reconciliation flow; the retry action
also states that no new request is sent until the user presses it.

The native Consumer now has the matching read-only `--doctor` and
`--doctor-json` checks. They validate the data directory, persisted payment key,
network manifest, Relay URLs, local PID and Relay health without creating a key,
starting a process or sending a paid request.

Provider capability advertisements now refresh from the public model allowlist
while a Relay connection is alive. A changed allowlist causes a reconnect and a
new signed registration, so a Relay does not retain a stale model set. The
controlled V10 network also keeps an explicit explanation in Relay health when
active probes need a dedicated funded V10 channel. Monetary actions remain
fail-closed behind committed evidence, independent high-reputation user
signatures, and statutory quorum; the gate never submits a refund or penalty by
itself. V10 now supports atomic relayed EIP-712 judge votes with per-judge
nonces and expiry, while the durable execution store stays disabled unless an
operator explicitly enables its separately funded broadcast callback.

The web application loads the workspace routes lazily. The public landing
bundle is now separated from the app bundle, reducing the largest production
JavaScript chunk from roughly 866 kB to 377 kB before gzip. This shortens the
first page load without changing wallet or settlement behavior.

## Experience review

The automated Web3/AI review scored the pre-change baseline as Consumer 7.5,
Provider 7, Relay/Settlement 7.5, node operations 6.5, and recovery/speed 8.
After this release, the release and operations dimensions improve through the
diagnostic and consistency gates, while live chain and wallet E2E scores remain
unverified until Docker, wallets, and the testnet are running. The next gate to
reach a real 9 is a Playwright flow with a mock wallet/RPC/Relay covering first
setup, wrong chain, rejection, timeout, failover, pending settlement, reorg,
and safe retry.

## Verification

- Consumer CLI: 323 passed.
- Web: 106 passed; production build succeeded with split app chunks.
- Release gate and unit test: passed.
- Provider capability refresh and V10 monetary-admission gate tests passed.
- Full Python suite: 1,907 passed, 21 skipped. Foundry: 137 passed.
- Historical V10 probes saw both `gpt-5.5` and `gpt-5.6-sol` advertised by both
  Relays. Current remote readiness is not asserted by this release: it must be
  recaptured by the candidate workflow after the new deployment and channels.
- The automatic anti-cheat path is implemented and locally verified, but the
  live network still uses the previous V10 deployment until a new contract,
  funded probe channels, and judge-wallet cutover are approved together.
