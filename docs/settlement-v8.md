# Settlement V8

Settlement V8 keeps the V7 payment-key flow and separates the Provider payout
wallet from the server-side receipt signer.

- Consumer signs each x402 authorization with its prepaid `myco_sk_...` key.
- Provider returns a receipt whose `provider` is the payout address and whose
  `providerSigner` is the local EVM identity.
- The payout wallet authorizes that signer once with
  `authorizeProviderSigner(address)`. It can later revoke it without changing
  the payout address.
- Relay signs the receipt, batches it, and submits it. No Consumer Session is
  created or retained.

Compile the contract:

```sh
python3 scripts/compile-v8-artifact.py
```

Deploy after supplying the existing Sepolia deployer and stablecoin values:

```sh
python3 -m gateway.client chain deploy-myco-v8-testnet \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --stablecoin "$MYCO_TEST_USDC" \
  --deployment deployments/sepolia-myco-v8.json
```

Authorize the Provider server signer from the payout wallet:

```sh
python3 -m gateway.client chain v8-authorize-provider-signer \
  --deployment deployments/sepolia-myco-v8.json \
  --private-key "$PROVIDER_PAYOUT_PRIVATE_KEY" \
  --signer "$(python3 -m gateway.provider_bootstrap --identity /data/provider-evm-identity.json --json | jq -r .address)"
```

Claim accumulated Provider credits from the payout-wallet machine, not the
Provider server:

```sh
python3 -m gateway.client chain v8-claim-payout \
  --deployment deployments/sepolia-myco-v8.json \
  --private-key "$PROVIDER_PAYOUT_PRIVATE_KEY"
```

Set `MYCOMESH_SETTLEMENT_VERSION=8` and point Provider, Relay, and Consumer at
the V8 deployment/network manifests. V7 remains available for existing
deployments.
