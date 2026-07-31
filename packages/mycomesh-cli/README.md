# mycomesh-consumer

Node.js CLI for consumers calling a MycoMesh OpenAI-compatible Consumer edge.
The commands remain stateless: wallet funding and V5 Session activation happen
in the browser, while this package sends API requests to the local loopback
edge or an explicitly configured HTTPS Gateway.

The package is published as `mycomesh-consumer`. `mycomesh-consumer` and the
short `mycomesh` command are equivalent.

## Requirements

- Node.js 20 or newer
- A MycoMesh Consumer base URL (the default is the local loopback edge)
- A consumer API key for authenticated endpoints
- For paid V5 inference, an active Session ID opened by the same wallet in the
  local Web dApp

For local development, install it directly from the repository:

```sh
npm install --global ./packages/mycomesh-cli
```

For an npm install from the public registry:

```sh
npm install --global mycomesh-consumer
mycomesh-consumer health
```

This installs only the stateless Consumer CLI. It does not install or start
Bridge, Relay, Proxy, or Codex services. Provider operators should install the
separate `mycomesh-provider` package.

For a one-shot command without a global install:

```sh
npx --yes --package=mycomesh-consumer mycomesh-consumer health
```

## Configuration

```sh
export MYCOMESH_BASE_URL=http://127.0.0.1:8110/v1
export MYCOMESH_API_KEY=your-consumer-key
```

`--base-url` and `--api-key` override their corresponding environment
variables. A base URL may be the service root or end in `/v1`.
Remote base URLs must use HTTPS. Loopback HTTP remains available for local
development; `--allow-insecure-http` is an explicit test-only escape hatch.
Requests default to a 300-second deadline. Set `MYCOMESH_TIMEOUT_SECONDS` or
`--timeout`; successful JSON bodies are capped at 32 MiB while SSE remains
streamed with backpressure.

Prefer `MYCOMESH_API_KEY` over `--api-key`: command-line arguments may be stored
in shell history or visible to other local processes. The CLI never writes the
key to disk and redacts it from HTTP error output.

For the local network, start `make consumer-up`, open the local Playground,
connect a browser wallet, fund V5 escrow and approve the one-time `openSession`
transaction. Copy the active Session ID from the local status/Playground, then
set:

```sh
export MYCOMESH_BASE_URL=http://127.0.0.1:8110/v1
export MYCOMESH_API_KEY='replace-with-local-consumer-key'
export MYCOMESH_SESSION_ID='0x...replace-with-active-v5-session-id'
```

The Session ID is not a replacement for the API key. Both values must belong to
the same local Consumer wallet. The CLI does not connect a wallet, move funds,
or open a V5 Session; the browser wallet flow does that once. A public Gateway
can still be used explicitly with `--base-url`, but it is never the default.

## Commands

```sh
mycomesh health
mycomesh models

mycomesh responses \
  --input "Summarize this text" \
  --model mycomesh-codex-standard-v1 \
  --max-output-tokens 500

mycomesh chat \
  --message "Explain this function" \
  --system "Be concise." \
  --model mycomesh-codex-standard-v1 \
  --max-completion-tokens 500
```

The CLI validates `MYCOMESH_SESSION_ID` and adds the required
`mycomesh_session` object automatically. Use `--session-id 0x...` to override it
for one command. A bare OpenAI-shaped request without either value is useful
only with a Gateway whose operator has explicitly configured another billing
path.

Use `--stream` to request SSE. SSE bytes are forwarded to stdout as they arrive,
without rewriting event boundaries:

```sh
mycomesh responses \
  --input "Write a short status update" \
  --max-output-tokens 500 \
  --stream
```

## JSON Input

Pass an inline object, read a file, or read stdin explicitly:

```sh
mycomesh responses --json '{"model":"my-model","input":"hello"}'
mycomesh chat --json @request.json
generate-request | mycomesh responses --json -
```

When `MYCOMESH_SESSION_ID` or `--session-id` is set, the CLI overwrites any JSON
session field with that validated value. A client constructing the complete raw
request body instead may include the extension directly:

```json
{
  "mycomesh_session": {
    "session_id": "0x..."
  }
}
```

Piped stdin is treated as JSON even without `--json`:

```sh
printf '%s' '{"model":"my-model","messages":[{"role":"user","content":"hello"}]}' \
  | mycomesh chat
```

Explicit flags such as `--model`, `--input`, `--message`, `--system`, and
`--stream` override the corresponding JSON fields. Successful JSON responses
are pretty-printed. SSE and other response types are copied to stdout. HTTP and
input errors are written to stderr and return a nonzero exit status.

## Development

```sh
cd packages/mycomesh-cli
npm test
```
