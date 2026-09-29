# mycomesh-consumer

The MycoMesh V11 Consumer. One deposit custodied by the settlement contract
pays any Provider on the network; every request is signed by a local payment
key and sealed end to end, so Relays forward ciphertext only.

Requires Node.js 20 or newer. No Docker or Python.

```sh
npm install --global mycomesh-consumer
mycomesh-consumer init
mycomesh-consumer setup --owner-key-file owner.key --faucet 100000000 --deposit 100000000
mycomesh-consumer request "What is MycoMesh?"
mycomesh-consumer serve          # http://127.0.0.1:8110/v1 (responses, chat/completions, models; streaming)
```

- `init` creates the payment key in `~/.mycomesh/v11` (it never leaves the machine).
- `setup` uses the owner account (which needs Sepolia ETH for gas) to deposit
  tUSDC and authorize the payment key up to `--max-per-request` units per request.
  `--faucet UNITS` first mints testnet tUSDC to the owner.
- `balance --owner-key-file owner.key` shows the deposit.
- `request "..." [--model gpt-5.5] [--provider SIGNER]` prints the verified answer,
  the fee and the settlement key.
- `serve` runs a local OpenAI-compatible endpoint for Codex and other clients;
  set `MYCOMESH_CONSUMER_API_KEY` to require a bearer token.
- `dispute <settlement-key|last> --owner-key-file owner.key --statement "..."`
  reveals a recorded request and response to a randomly drawn Provider-AI jury
  within the 24-hour dispute window. The 1 tUSDC reporter bond is returned and a
  bounty paid when fraud is confirmed.

Each response is decrypted locally and checked against the Provider-signed
receipt before it is shown. The bundled network manifest is
`networks/mycomesh-v11-sepolia.json`; use `--network FILE` for another.
