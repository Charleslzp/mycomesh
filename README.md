# MycoMesh

A peer-to-peer market for AI inference. Consumers keep one custodied deposit
and sign each request; Relays forward ciphertext they cannot read; Providers
serve OpenAI (via a ChatGPT-login Codex CLI or an API key) and Claude models
without posting stake. Fraud is caught by free Relay probes and settled by
randomly drawn Provider-AI juries, all on Ethereum (Sepolia testnet).

Design: [docs/v11-design.md](docs/v11-design.md). Live deployment:
[deployments/sepolia-myco-v11.json](deployments/sepolia-myco-v11.json).

## Consumer

```sh
npm install --global mycomesh-consumer
mycomesh-consumer init                                   # local payment key
mycomesh-consumer setup --owner-key-file owner.key --faucet 100000000 --deposit 100000000
mycomesh-consumer request "hello"
mycomesh-consumer serve                                  # OpenAI-compatible API on :8110
mycomesh-consumer dispute last --owner-key-file owner.key --statement "unrelated answer"
```

The owner account needs a little Sepolia ETH for gas. `--faucet` mints testnet
tUSDC.

## Provider

```sh
python -m mycomesh key new provider/signer.key
python -m mycomesh provider register --network packages/mycomesh-cli/networks/mycomesh-v11-sepolia.json \
  --owner-key owner.key --signer-key provider/signer.key --identity provider/identity.json \
  --operator-id you/provider-1 --model gpt-5.5
docker compose run --rm provider-login                   # ChatGPT device login for Codex
docker compose up -d provider
```

`--backend openai --api-key-env OPENAI_API_KEY` or `--backend anthropic
--api-key-env ANTHROPIC_API_KEY` serve from an API key instead of Codex.

## Relay and bridge keeper

```sh
python -m mycomesh relay register --network N --owner-key owner.key --signer-key signer.key --deposit 100000000
python -m mycomesh relay serve --network N --owner-key owner.key --signer-key signer.key
python -m mycomesh keeper serve --network N --key keeper.key
```

A Relay serves `/providers`, `/v11/requests` and `/v11/evidence` on
127.0.0.1:11100 and Provider links on 127.0.0.1:11101; put TLS in front of both.

## Development

```sh
make test     # forge tests, anvil end-to-end tests (Python + Node Consumer), Node unit tests
```

Requires Foundry 1.4.4 (anvil with the Prague hardfork), Python ≥ 3.10 with
`cryptography`, and Node ≥ 20.
