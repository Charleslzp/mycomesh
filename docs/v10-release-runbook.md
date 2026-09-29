# V10 dynamic mesh release runbook

Scope: the controlled-test V10 dynamic-Provider-AI mesh
(`mycomesh-v10-dynamic-provider-ai-20260926-controlled-test`, Sepolia). All
Providers and Relays are run by one operator; the deployment stays
`controlled_test` and makes no independence attestation.

## Topology invariants

- relay1 and relay3 share one channel-bound Relay payment/signing identity, so
  they are replicas. Each has its own jury identity and jury executor.
- Every V10 Provider holds a session on every replica Relay (multi-home). One
  Bridge lease advertises all replica addresses. A Relay restart therefore
  needs no Provider action; `providers` on both Relays should equal the number
  of Providers.
- Jury execution requires at least three Providers on the executing Relay.

## One source commit

npm packages, OCI candidates, Relays and Providers ship from the same `main`
commit. Deployed contracts are pinned separately by the manifests'
`source_commit`; the release gate proves it is an ancestor with unchanged
contract build inputs.

1. Merge to `main` with CI green. `Build container image candidates` runs on
   the push.
2. Roll the commit onto the mesh, Providers first (canary one, then the rest),
   then Relays:

   ```bash
   python3 scripts/deploy_v10_release_remote.py provider --node provider1 \
     --commit <sha> --require-all-relays
   python3 scripts/deploy_v10_release_remote.py provider --node provider2 \
     --node provider3 --node provider4 --commit <sha> --require-all-relays
   python3 scripts/deploy_v10_release_remote.py relay --node relay3 --commit <sha>
   python3 scripts/deploy_v10_release_remote.py relay --node relay1 --commit <sha>
   ```

   Each node ships the `git archive` of the commit to
   `/opt/mycomesh-mesh/releases/v10-dynamic-provider-ai-20260926-<sha8>` and
   is gated (Relay: loopback health; Provider: container, Bridge lease, signer
   on every public Relay). A failed gate restores the previous node file or
   container; journals are under `/opt/mycomesh-v10-dynamic-20260926/rollback/`.
3. Keep jury execution enabled on both Relays (idempotent):

   ```bash
   python3 scripts/enable_v10_jury_execution_remote.py --node relay1
   python3 scripts/enable_v10_jury_execution_remote.py --node relay3
   ```

4. Dispatch `Verify and attest release candidate` with the commit, then
   `Publish approved npm release` with that run id and commit.

## Health acceptance

`GET https://<relay>:10443/relay/health` (manifest CA) must answer promptly
under concurrency and report `providers` = all Providers,
`anti_cheat.enforcement_mode = provider_ai_jury` and
`provider_ai_jury_runtime.monetary_ready = true` on both Relays. The Relay
never blocks this endpoint on RPC: the jury probe is served from a
bounded-age cache (120 s hard limit) and refreshed in the background.

## Public gateway V10 route

Set `MYCOMESH_V10_PROVIDER_NETWORK_CONFIG` (and `MYCOMESH_V10_RELAY_CA_FILE`
for the private CA). `GET /ready` then reports `v10_gateway_route` from a
non-blocking probe of the pinned Relays. The gateway only verifies and
forwards Consumer-signed x402 authorizations; it holds no payment key.
