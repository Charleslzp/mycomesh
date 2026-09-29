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

No stake is required. Needs Node.js 20+ and Docker.

```sh
npm install --global mycomesh-provider
mycomesh-provider init                                   # signer key in ~/.mycomesh/provider
mycomesh-provider login                                  # ChatGPT device login for Codex
mycomesh-provider register --owner-key-file owner.key    # owner receives payouts; needs Sepolia ETH
mycomesh-provider start
```

`start --backend openai --api-key-env OPENAI_API_KEY` or `--backend anthropic
--api-key-env ANTHROPIC_API_KEY --model claude-sonnet-4-6` serve from an API key
instead of Codex. Without npm: `python -m mycomesh provider register|serve` or
`docker compose up -d provider`.

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
