# Settlement V9 integration

Status: application integration and local-chain tests implemented; **no Sepolia
V9 contract has been deployed, no live network has been migrated, and no real
reward, stake, sponsor funding or gas transfer has been authorized by this work**.
The existing V8 network remains a separate deployment. Test identities and
fixture economic values are not production choices.

## Protocol and receipt path

- V9 uses EIP-712 version `9`, authorization schema
  `mycomesh.x402.myco-credit-v3`, and distinct V9 Provider/signed-receipt schemas.
  V8 signatures must fail on V9; changing a schema string does not convert them.
- Provider/Relay select an explicit deployment. They check signer authorization
  and available Provider stake before work; this read does not reserve stake.
  Concurrent work may consume collateral before on-chain settlement.
- Complete response integrity checks remain before co-signing and enqueueing.
  A successful transaction must contain the matching `ReceiptEscrowed` event
  before the Relay records `escrowed`, not `confirmed` or `claimable` earnings.
- The native Consumer pins protocol, chain and contract, binds a returned
  receipt to its original payment, and uses `settlementInfo` at a safe block to
  distinguish escrow, dispute, release and refund. Relay-supplied labels do not
  establish any on-chain terminal state. The legacy Python Consumer keeps V9
  receipt history pending until independently reconciled; it does not assert
  that a Relay's success label proves release.
- Updated on 2026-09-16: V9 Consumers now require the full response-body proof
  capability before dispatch. The Relay sends the exact Provider-committed
  bytes as a negotiated response body, and the Consumer checks the signed hash
  before extracting the API result. This catches Relay content substitution;
  it still does not prove which upstream model the Provider actually ran.
  Existing V8 remains compatible; set `require_response_proof: true` in its
  local Consumer network manifest to prevent a missing-capability downgrade.
  See [experience/security verification](experience-security-resilience-2026-09-16.md).

## Independent operator workflow

The command entry point is:

```sh
python3 -m gateway.relay_adjudication_v9 --help
```

`V9OperatorConfig` requires explicit chain ID, genesis hash, deployed runtime
code hash, contract, policy hash, committee/threshold, distinct operator
declarations, evidence observer key, reporter address and RPC. Distinct operator
declarations remain an onboarding obligation, not cryptographic proof of
independent human control.

1. `plan-report` replays the signed incident and reads a confirmed, hash-pinned
   chain snapshot. Its authorization, receipt, parties, request and amount must
   exactly match an already escrowed V9 record. The report is only a calldata
   plan; it is not sent and its evidence is not a monetary verdict.
2. After the full evidence window, each eligible judge independently reviews
   the exact report and creates `plan-vote`, including bound reasons/outcome.
   Confirming requires reproduced protocol evidence. Dismissal can reject an
   unproven report without treating it as confirmed wrongdoing. A judge's EVM
   key is required; an Ed25519 certificate cannot authorize this transaction.
3. `execute` defaults to dry-run. Sending requires explicit send mode, the exact
   approved plan hash, a protected dedicated key file, and gas-price, gas-unit
   and total-gas-cost caps. State is checked again before signing.
4. The SQLite outbox stores the signed transaction, nonce and hash before its
   one broadcast attempt. RPC uncertainty blocks another nonce for that actor;
   use `reconcile`, not a new send. Confirmation checks the canonical block and
   configured confirmation depth.
   An outbox `confirmed` state means transaction execution succeeded; it must
   not be presented as business-level proof that a refund or reward was paid.
   Check the corresponding contract record, balances and events separately.
5. `plan-claim` prepares stablecoin, token or refundable report-bond claims.
   Confirmation refunds the full Consumer fee first; rewards draw on the
   defined slash and prefunded token reserve. No token mint authority is added.

These are operator commands, not a public unauthenticated payment endpoint.
Independent review and exact per-transaction approval are intentional; the
Relay is not an autonomous judge. Invalid responses rejected before settlement
have no escrowed bill to dispute. Soft capability failures, timeouts and model
guessing do not qualify as automatically slashable evidence.

## Activation requirements

Supply independently controlled committee addresses and threshold; stablecoin
and optional reward-token addresses; treasury/governance/penalty recipients;
dispute/arbitration/withdrawal windows; bond, slash and bounty caps; and explicit
gas, collateral, probe and reward funding limits. Use the constructor policy
constraints in [the contract report](myco-settlement-v9-prototype.md).

Deploy only after approving that policy. Record the actual receipt, bytecode,
genesis and policy pins, and create a validated V9 deployment plus a sibling
Provider network manifest. Existing V8 credit, grants, Provider authorizations
and stake are not migrated automatically. Initialize and authorize the V9
accounts deliberately, then configure paired Provider/Relay upgrades and an
explicitly pinned Consumer. Keep the V8 manifest unchanged for rollback.

Probe sponsorship remains opt-in and budget-limited. A production token reward
must not be enabled merely because a fixture test could mint a test token.

## Verification

`tests/test_v9_local_chain.py` exercises real localhost HTTP JSON-RPC and signed
transactions: V8 rejection, V9 escrow/release, Node-to-Python signature
interoperability, report and majority vote, full refund, slash, stable/token
claims, and timeout/bond recovery. A fifth test uses the actual operator client:
genesis/code/policy/committee pins, canonical snapshot, claim planning, exact
approval, protected fixture key, bounded gas, broadcast, reconciliation and
idempotent execution. The claimable balance is also checked independently.
All five passed against isolated Hardhat 3.0.6 with Shanghai-targeted test
artifacts. Ganache 7.9.2 passed the first four but rejected EIP-1898 hash-pinned
reads, so it could not validate the operator path. Production verification was
not relaxed. The production compilation target and repository dependencies
were not changed. All keys and assets are synthetic; the node stops afterward.

Focused unit/integration suites cover malformed evidence, immutable plans,
nonce uncertainty, cross-domain replay, chain reorganization, collateral
admission, escrow-event identity and Consumer state reporting. Local tests do
not constitute an external security or economic audit, or proof of upstream
model identity.

### Focused verification, 2026-09-16

The main agent independently reran these commands after integration:

```sh
python3 -B -m unittest \
  tests.test_chain_v9 tests.test_relay_adjudication_v9 \
  tests.test_consumer_v8 tests.test_consumer_v9 \
  tests.test_relay_v9_runtime tests.test_v9_network_config \
  tests.test_session_relayer_connections
# 138 passed

node --test --test-timeout=30000 \
  packages/mycomesh-cli/test/consumer-v9.test.mjs \
  packages/mycomesh-cli/test/consumer-history.test.mjs \
  packages/mycomesh-cli/test/consumer-history-runtime.test.mjs \
  packages/mycomesh-cli/test/consumer.test.mjs \
  packages/mycomesh-cli/test/consumer-routing.test.mjs
# 95 passed

node --test --test-timeout=30000 --test-reporter=tap \
  packages/mycomesh-cli/test/*.test.mjs
# Entire Node suite: 144 passed, 0 skipped

forge test --offline --match-contract MycoSettlementV9Test
# 30 passed, including 256 fuzz runs, 0 skipped
```

The explicitly enabled local-chain suite passed 5 tests with no skips. These
counts overlap broader regression runs and must not be added to them. This is
not an all-repository green claim: older V4/V5 Forge tests and stale deployment/
operator-setup expectations remain outside this focused verification. The
operator-setup wizard must not be run unattended as a broad discovery test.

To reproduce the real-chain tests independently, use Node 22.10 or newer and
an isolated temporary directory (not repository dependencies):

```sh
myco_v9_test_dir=$(mktemp -d /tmp/mycomesh-v9-evm.XXXXXX)
npm install --prefix "$myco_v9_test_dir" hardhat@3.0.6 --no-audit --no-fund
forge build --offline --evm-version shanghai \
  --out "$myco_v9_test_dir/out" --cache-path "$myco_v9_test_dir/cache"
```

Set `"type": "module"` in that temporary directory's `package.json` and create
`hardhat.config.js` there containing:

```js
export default {
  networks: {
    v9local: {
      type: 'edr-simulated', chainType: 'l1', chainId: 31337,
      initialDate: new Date(Date.now() - 120000).toISOString(),
    },
  },
};
```

Then run:

```sh
RUN_MYCO_V9_LOCAL_CHAIN=1 \
MYCOMESH_TEST_HARDHAT_BIN="$myco_v9_test_dir/node_modules/.bin/hardhat" \
MYCOMESH_TEST_HARDHAT_CONFIG="$myco_v9_test_dir/hardhat.config.js" \
MYCOMESH_TEST_V9_ARTIFACT_ROOT="$myco_v9_test_dir/out" \
python3 -B -m unittest tests.test_v9_local_chain
```

The fixture selects an ephemeral localhost port and starts/stops its own node;
it does not accept an external production RPC. Without the opt-in and required
local tools/artifacts it skips; a skip is not a successful chain verification.

### Existing network

Only a narrowly scoped SQLite connection-closing hotfix was deployed to the
existing V8 Relay1 and Relay3. Relay3 regained three Providers; Relay1 health
recovered but has no Providers. Bridge3 and Relay2 still timed out from the
testing location. See the [network recovery record](network-recovery-2026-09-16.md)
for exact hashes, backups, health measurements and recovery limits. These
health checks did not send paid inference or activate V9 rewards.
