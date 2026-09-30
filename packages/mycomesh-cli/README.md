# mycomesh-consumer

The MycoMesh V11 Consumer. One deposit custodied by the settlement contract
pays any Provider on the network; every request is signed by a local payment
key and sealed end to end, so Relays forward ciphertext only.

Requires Node.js 20 or newer. No Docker or Python.

```sh
npm install --global mycomesh-consumer
mycomesh-consumer init            # payment key + password-protected owner wallet
mycomesh-consumer setup --deposit 20000000
mycomesh-consumer request --stream "What is MycoMesh?"
mycomesh-consumer serve           # http://127.0.0.1:8110/v1 (responses, chat/completions, models; live streaming)
```

- `init` creates the payment key and an owner wallet in `~/.mycomesh/v11`. The wallet is an
  Ethereum V3 keystore (MetaMask can import it) protected by a password from
  `MYCOMESH_WALLET_PASSWORD` or a terminal prompt; `--owner-key-file` uses your own key instead.
- `setup --deposit UNITS` deposits tUSDC and authorizes the payment key up to `--max-per-request`
  units per request. On the testnet it first tops the wallet up from the faucet (gas ETH and tUSDC);
  `faucet` does that on its own.
- `balance` shows the deposit.
- `request "..." [--model gpt-5.5] [--provider SIGNER]` prints the verified answer,
  the fee and the settlement key.
- `serve` runs a local OpenAI-compatible endpoint for Codex and other clients;
  set `MYCOMESH_CONSUMER_API_KEY` to require a bearer token.
- `dispute <settlement-key|last> --statement "..."`
  reveals a recorded request and response to a randomly drawn Provider-AI jury
  within the 24-hour dispute window. The 1 tUSDC reporter bond is returned and a
  bounty paid when fraud is confirmed.

Each response is decrypted locally and checked against the Provider-signed
receipt before it is shown; streamed text is checked against it too. Relays come from the bundled
manifest and the on-chain Relay directory. The bundled network manifest is
`networks/mycomesh-v11-sepolia.json`; use `--network FILE` for another.
