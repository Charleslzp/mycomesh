#!/bin/sh
set -eu

# The selected payment-key Consumer becomes ready after it can discover a live Relay. Keep the
# terminal attached while the loopback edge comes up, then launch Codex.
timeout_seconds=${MYCOMESH_CONSUMER_READY_TIMEOUT_SECONDS:-1800}
case "$timeout_seconds" in
  ''|*[!0-9]*) echo "MYCOMESH_CONSUMER_READY_TIMEOUT_SECONDS must be an integer" >&2; exit 2 ;;
esac
if [ "$timeout_seconds" -lt 1 ] || [ "$timeout_seconds" -gt 86400 ]; then
  echo "MYCOMESH_CONSUMER_READY_TIMEOUT_SECONDS must be between 1 and 86400" >&2
  exit 2
fi

started_at=$(date +%s)
consumer_version=${MYCOMESH_CONSUMER_PROTOCOL_VERSION:-8}
printf '%s\n' "Waiting for a healthy Settlement V${consumer_version} Relay..."
while :; do
  if curl --noproxy '*' --fail --silent --show-error --max-time 3 http://127.0.0.1:8110/ready >/dev/null 2>&1; then
    break
  fi
  now=$(date +%s)
  if [ "$((now - started_at))" -ge "$timeout_seconds" ]; then
    echo "Timed out waiting for the local Consumer V${consumer_version} edge." >&2
    echo "Open http://127.0.0.1:8110/ to view the two exported credentials." >&2
    exit 1
  fi
  sleep 2
done

if ! codex_env=$(make consumer-codex-env); then
  echo "Could not load Codex credentials from the local Consumer." >&2
  exit 1
fi
eval "$codex_env"
unset codex_env
codex_command=${MYCOMESH_CODEX_COMMAND:-codex}
if ! command -v "$codex_command" >/dev/null 2>&1; then
  echo "The Consumer is ready, but '$codex_command' is not installed on this host." >&2
  echo "OPENAI_BASE_URL=$OPENAI_BASE_URL" >&2
  echo "Run the Codex command after installing it, or set MYCOMESH_CODEX_COMMAND." >&2
  exit 127
fi
exec "$codex_command" \
  -c 'model="gpt-5.5"' \
  -c 'model_provider="mycomesh"' \
  -c 'model_providers.mycomesh.name="MycoMesh"' \
  -c 'model_providers.mycomesh.base_url="http://127.0.0.1:8110/v1"' \
  -c 'model_providers.mycomesh.env_key="OPENAI_API_KEY"' \
  -c 'model_providers.mycomesh.wire_api="responses"' \
  "$@"
