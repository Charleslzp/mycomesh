# V10 dynamic mesh release evidence — 2026-09-29

Network: `mycomesh-v10-dynamic-provider-ai-20260926-controlled-test` (Sepolia,
`deployment_class: controlled_test`, one operator, no independence
attestation). Contracts are reused from the pinned deployment commit
`f311cba91035be9705daf10eca44bea9590de6c8`.

## Single source commit

Release commit: `fa21790e0aef2e82380027d9d5ed34ebfaf64510`

| Artifact | Binding | Status |
| --- | --- | --- |
| relay1, relay3 | `/opt/mycomesh-mesh/releases/v10-dynamic-provider-ai-20260926-fa21790e`, archive sha256 `f02fa421…b046` | running |
| provider1–4 | same release directory mounted at `/app/gateway` | running, multi-homed on both Relays |
| OCI `mycomesh-provider-codex` | `candidate-fa21790e…`, index `sha256:a34dbd8c632d9c72adaa31bd68aaea87cf20d025b7f8b9efdd6b899e0a64c149` | built and attested (run 36583234904) |
| OCI `mycomesh-node` | `candidate-fa21790e…`, index `sha256:4b6da5e9f0015081c6867b5b37e2aa887d2093cbd06a64043fa5295dd3b1c629` | built |
| Release candidate | `Verify and attest release candidate` run 36583234904 (image attestation, amd64/arm64 revision, live chain evidence from two RPC origins, strict gate) | passed |
| npm `mycomesh-provider@0.1.39`, `mycomesh-consumer@0.1.53` | `Publish approved npm release` run 36583613515 | **blocked: repository secret `NPM_TOKEN` is not configured.** Revalidation passed; re-run that run after adding the secret. |

## Live state after rollout

Both Relays: 4/4 Providers, `enforcement_mode = provider_ai_jury`,
`monetary_ready = true`, `settlement_ready = true`; jury execution enabled on
relay1 (executor `0x69c2…0f30`) and relay3 (executor `0x44ae…654b`).

## Readiness defects found and fixed during rollout

Five-minute canaries at 10 s resolution (`readiness/`):

| Stage | Mesh availability | /relay/health p95 |
| --- | --- | --- |
| Before fixes | 26.9 % | 11.1 s / 15.5 s |
| After transport retry + non-blocking intake health (#5) | 70.0 % | 2.4 s / 3.3 s |
| After intake dispatch race + lagging-RPC fixes (#6) | 96.7 % | 1.8 s / 1.7 s |

The remaining misses in the last stage were one simultaneous
`settlement_ready = false` sample on both Relays (single settlement RPC). Both
Relays were then configured with the manifest's three settlement RPC
endpoints (backups under `rollback/settlement-rpc-failover-*`).

## Drills

`failover-drills.jsonl`, `backup-restore-drill.jsonl`:

| Drill | Result |
| --- | --- |
| relay3 stopped 63 s | relay1 kept 4 Providers, jury and settlement ready; gateway V10 route ready; **RTO 17.1 s** |
| relay1 stopped 63 s | relay3 kept 4 Providers, jury and settlement ready; gateway V10 route ready; **RTO 49.3 s** |
| provider2 container restart | back on both Relays in **4.7 s** |
| relay3 primary jury RPC blackholed 70 s | jury failed closed 6/6 samples, settlement stayed ready 6/6 (failover), 4 Providers kept; recovered **6.2 s** after revert |
| Online SQLite backup of all 7 stores per Relay | `integrity_check = ok`, restored copies match schema and row counts on both Relays |

## Open items

- **npm publish** needs `NPM_TOKEN` (or npm trusted publishing) configured.
- **24 h canary** started 2026-09-29 13:42 UTC
  (`.codex-run/release-evidence/canary-24h-20260929.jsonl`, 60 s interval).
  The interim summary covers rollout and drills, so it is not an SLO figure.
  It shows one unexplained 8-minute window (13:43–13:51 UTC) where both
  Relays reported `monetary_ready = false` with no intake errors logged,
  consistent with the unanimous three-RPC jury quorum failing on a provider
  incident; fail-closed is intended there, but the chain probe exposes only
  an exception class.
- **Paid end-to-end request latency** requires an unlocked Consumer (wallet
  signature) and was not measured.
- `future_blockhash_v1` jury randomness is Sepolia test-only, not
  production-grade VRF.
