# @mycomesh/cli

Zero-dependency Node.js CLI for consumers calling a MycoMesh OpenAI-compatible
gateway. It does not run a Provider, Bridge, Relay, or Codex runtime.

The package is intentionally marked `private` until its public package name and
release process are finalized.

## Requirements

- Node.js 20 or newer
- A MycoMesh consumer base URL
- A consumer API key for authenticated endpoints

For local development, install it directly from the repository:

```sh
npm install --global ./packages/mycomesh-cli
```

## Configuration

```sh
export MYCOMESH_BASE_URL=http://127.0.0.1:8100
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

## Commands

```sh
mycomesh health
mycomesh models

mycomesh responses "Summarize this text" \
  --model mycomesh-codex-standard-v1 \
  --max-output-tokens 500

mycomesh chat "Explain this function" \
  --system "Be concise." \
  --model mycomesh-codex-standard-v1
```

Use `--stream` to request SSE. SSE bytes are forwarded to stdout as they arrive,
without rewriting event boundaries:

```sh
mycomesh responses "Write a short status update" --stream
```

## JSON Input

Pass an inline object, read a file, or read stdin explicitly:

```sh
mycomesh responses --json '{"model":"my-model","input":"hello"}'
mycomesh chat --json @request.json
generate-request | mycomesh responses --json -
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
