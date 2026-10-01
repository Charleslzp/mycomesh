# MycoMesh

A peer-to-peer market for AI inference. Consumers keep one custodied deposit
and sign each request; Relays forward ciphertext they cannot read; Providers
serve OpenAI (via a ChatGPT-login Codex CLI or an API key) and Claude models
without posting stake. Fraud is caught by free Relay probes and settled by
randomly drawn Provider-AI juries, all on Ethereum (Sepolia testnet).

Each fee splits Provider 85% / Relay 5% / treasury 10%. MYCO (1 billion max,
no premine) is minted hourly by a Bitcoin-style halving schedule to the people
who use the network: 80% to Consumers by fees paid, 10% to Providers by fees
served × success rate, 7% to Relays and 3% to keepers.

Design: [docs/v11-design.md](docs/v11-design.md). Live deployment:
[deployments/sepolia-myco-v11.json](deployments/sepolia-myco-v11.json).

## Consumer

```sh
npx mycomesh-consumer            # opens http://127.0.0.1:8110/: create a wallet, fund it, chat
```

The console walks a new user through an encrypted local wallet and a one-click
testnet deposit. `request`, `serve`, `dispute`, `withdraw` and `tenant ...` are
also available on the command line.

**Multi-tenant accounts.** One deposit can serve many tenants: `tenant add NAME
--budget UNITS` creates a payment key capped on-chain and an API key that works
from any host. Custodial services and teams can build on this; the protocol
charges them nothing extra.

**MYCO rewards.** `mycomesh-consumer rewards` shows the MYCO the wallet earned
by paying fees; `rewards claim` (or the console's wallet tab) mints it.

## Provider

```sh
npx mycomesh-provider            # opens http://127.0.0.1:8120/ and walks through every step
```

No stake is required. The dashboard generates the signer, signs in to ChatGPT
with a device code, creates an encrypted payout wallet, registers on-chain
(testnet gas from the faucet) and starts the Docker container. `--backend openai`
or `--backend anthropic` serve from an API key; `--base-url http://host:11434/v1`
serves open-weight models from vLLM or Ollama.

## Relay and bridge keeper

```sh
npm install --global mycomesh-relay
mycomesh-relay init && mycomesh-relay register && mycomesh-relay start --with-keeper
```

Like a Bitcoin node, a Relay needs no domain name or certificate authority: its
self-signed certificate is pinned in the on-chain Relay directory, and Consumers
and Providers discover and verify it from the chain.

## Hunter (open probing)

```sh
python -m mycomesh hunter serve --network deployments/mycomesh-v11-sepolia.network.json --key hunter.key
```

Anyone may probe Providers for free (20 probes per Provider a day, shared) and accuse one that serves a
weaker model than its tier. A same-tier jury replays the probes as a control group; a conviction pays
the hunter half the Provider's forfeited holdback and a MYCO bounty. Bring your own questions with
`--questions questions.jsonl`.

## Development

```sh
make test     # forge tests, anvil end-to-end tests (Python + Node Consumer), Node unit tests
```

Requires Foundry 1.4.4 (anvil with the Prague hardfork), Python ≥ 3.10 with
`cryptography`, and Node ≥ 20.
