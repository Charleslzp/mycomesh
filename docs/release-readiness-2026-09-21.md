# Release readiness — 2026-09-21

This release keeps the V7–V9 protocol modules because they are still imported by
Relay compatibility paths, operator tooling, or regression tests. The cleanup
removes generated output from the source boundary and consolidates runtime
release metadata; it does not delete a protocol implementation that is still
part of a supported migration or settlement path.

The release boundary is now checked by `python3 scripts/release_gate.py` and by
`make release-check` before the full test target runs. The gate verifies:

- Provider package version `0.1.38` and Consumer package version `0.1.51` match
  the versions reported by their runtime entry points and lockfiles.
- Provider bootstrap uses a complete commit ref and a digest-pinned image.
- V9 policy and V10 deployment/network manifests are present.
- Canonical `node-up`, `node-health`, and `provider-health` targets exist.
- Generated directories are absent from Git tracked files.

The Provider launcher now reports saved setup state, settlement protocol, and
its pinned release ref through `mycomesh-provider --doctor`. It reports a
missing settings file as first-run setup instead of making the operator infer
that state from a later Docker failure. Secrets are never included in the
diagnostic output. Automation and support tools can use
`mycomesh-provider --doctor-json`, which emits the stable
`mycomesh.provider.doctor.v1` schema with per-check recovery guidance.

The Consumer playground now offers an explicit retry button only for transient
transport or route failures. Budget, authorization, and payment-status errors
keep the user in the appropriate setup or reconciliation flow; the retry action
also states that no new request is sent until the user presses it.

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

- Consumer CLI: 312 passed, 1 skipped.
- Web: 106 passed; production build succeeded with split app chunks.
- Release gate and unit test: passed.
- Full Python and Foundry suites remain the release checks from the previous
  validated commit; live Docker verification is unavailable while the local
  Docker daemon is stopped.
