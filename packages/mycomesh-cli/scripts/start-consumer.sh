#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
COMPOSE_FILE="$SCRIPT_DIR/../consumer.compose.yml"
PROJECT_NAME="mycomesh-consumer"
NODE_IMAGE="${MYCOMESH_NODE_IMAGE:-}"
CODEX_COMMAND="${MYCOMESH_CODEX_COMMAND:-codex}"
READY_TIMEOUT="${MYCOMESH_CONSUMER_READY_TIMEOUT_SECONDS:-1800}"
PROXY_URL="${MYCOMESH_CONSUMER_PROXY:-}"
NO_BROWSER=0
NO_CODEX=0
STOP=0
RESET_LOCAL=0
DRY_RUN=0
CODEX_ARGS=()

die() {
  printf 'error: %s\n' "$*" >&2
  exit 64
}

is_docker_cli() {
  local candidate="${1-}" version_output
  [[ -n "$candidate" && -x "$candidate" && ! -d "$candidate" ]] || return 1
  case "$candidate" in */node_modules/*) return 1 ;; esac
  version_output="$("$candidate" --version 2>/dev/null)" || return 1
  [[ "$version_output" == "Docker version "* ]] || return 1
  "$candidate" compose version >/dev/null 2>&1 || return 1
}

find_docker_cli() {
  local configured="${MYCOMESH_DOCKER_CLI:-}" path_entry candidate name fallback old_ifs="$IFS"
  if [[ -n "$configured" ]]; then
    candidate="$configured"
    [[ "$candidate" == */* ]] || candidate="$(command -v "$candidate" 2>/dev/null || true)"
    is_docker_cli "$candidate" || die "MYCOMESH_DOCKER_CLI is not a Docker CLI with Compose V2"
    printf '%s' "$candidate"
    return
  fi
  IFS=:
  for path_entry in ${PATH:-}; do
    [[ -n "$path_entry" ]] || path_entry=.
    for name in docker docker.exe; do
      candidate="$path_entry/$name"
      if is_docker_cli "$candidate"; then
        IFS="$old_ifs"
        printf '%s' "$candidate"
        return
      fi
    done
  done
  IFS="$old_ifs"
  for fallback in /usr/local/bin/docker /opt/homebrew/bin/docker /usr/bin/docker \
    /Applications/Docker.app/Contents/Resources/bin/docker \
    '/c/Program Files/Docker/Docker/resources/bin/docker.exe'; do
    if is_docker_cli "$fallback"; then
      printf '%s' "$fallback"
      return
    fi
  done
  die "Docker Desktop/Engine with Compose V2 is required"
}

rewrite_loopback_proxy() {
  local value="${1-}" scheme authority suffix userinfo host_port tail=""
  case "$value" in *$'\n'*|*$'\r'*) die "Consumer proxy URLs must be single-line values" ;; esac
  if [[ ! "$value" =~ ^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*)(.*)$ ]]; then
    printf '%s' "$value"
    return
  fi
  scheme="${BASH_REMATCH[1]}"; authority="${BASH_REMATCH[2]}"; suffix="${BASH_REMATCH[3]}"
  userinfo=""; host_port="$authority"
  if [[ "$authority" == *@* ]]; then userinfo="${authority%@*}@"; host_port="${authority##*@}"; fi
  if [[ "$host_port" == "127.0.0.1" ]]; then :
  elif [[ "$host_port" == 127.0.0.1:* ]]; then tail="${host_port#127.0.0.1}"
  elif [[ "$host_port" == "[::1]" ]]; then :
  elif [[ "$host_port" == "[::1]:"* ]]; then tail="${host_port#\[::1\]}"
  elif [[ "$host_port" =~ ^[Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt](:.*)?$ ]]; then tail="${BASH_REMATCH[1]}"
  else printf '%s' "$value"; return
  fi
  printf '%s' "${scheme}${userinfo}host.docker.internal${tail}${suffix}"
}

prepare_proxy_env() {
  local all_proxy_value no_proxy_value
  all_proxy_value="${MYCOMESH_CONSUMER_ALL_PROXY:-}"
  export MYCOMESH_CONSUMER_HTTP_PROXY="$(rewrite_loopback_proxy "${MYCOMESH_CONSUMER_HTTP_PROXY:-$PROXY_URL}")"
  export MYCOMESH_CONSUMER_HTTPS_PROXY="$(rewrite_loopback_proxy "${MYCOMESH_CONSUMER_HTTPS_PROXY:-$PROXY_URL}")"
  export MYCOMESH_CONSUMER_ALL_PROXY="$(rewrite_loopback_proxy "$all_proxy_value")"
  no_proxy_value="${MYCOMESH_CONSUMER_NO_PROXY:-}"
  export MYCOMESH_CONSUMER_NO_PROXY="${no_proxy_value:+${no_proxy_value},}127.0.0.1,localhost,::1"
  export NO_PROXY="$MYCOMESH_CONSUMER_NO_PROXY"
  export no_proxy="$MYCOMESH_CONSUMER_NO_PROXY"
}

run() {
  if ((DRY_RUN)); then printf '+'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}

compose() {
  run "$DOCKER" compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

open_browser() {
  local url="$1" opener=""
  printf 'MycoMesh Consumer onboarding: %s\n' "$url"
  ((NO_BROWSER)) && return
  case "$(uname -s 2>/dev/null || printf unknown)" in
    Darwin) opener=open ;;
    Linux*) command -v xdg-open >/dev/null 2>&1 && opener=xdg-open ;;
    MINGW*|MSYS*|CYGWIN*)
      if command -v cmd.exe >/dev/null 2>&1; then cmd.exe /c start "" "$url" >/dev/null 2>&1 & return; fi ;;
  esac
  if [[ -n "$opener" ]]; then "$opener" "$url" >/dev/null 2>&1 &
  else printf '%s\n' "Open this URL in a browser to connect a wallet, fund it, and activate a V5 Session."; fi
}

while (($#)); do
  case "$1" in
    --node-image) (($# >= 2)) || die "--node-image requires a value"; NODE_IMAGE="$2"; shift 2 ;;
    --codex-command) (($# >= 2)) || die "--codex-command requires a value"; CODEX_COMMAND="$2"; shift 2 ;;
    --ready-timeout) (($# >= 2)) || die "--ready-timeout requires a value"; READY_TIMEOUT="$2"; shift 2 ;;
    --proxy) (($# >= 2)) || die "--proxy requires a value"; PROXY_URL="$2"; shift 2 ;;
    --no-browser) NO_BROWSER=1; shift ;;
    --no-codex) NO_CODEX=1; shift ;;
    --stop) STOP=1; shift ;;
    --reset-local) RESET_LOCAL=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --) shift; CODEX_ARGS=("$@"); break ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -f "$COMPOSE_FILE" ]] || die "bundled Consumer Compose file is missing"
[[ "$NODE_IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:[a-f0-9]{64}$ ]] || die "Consumer image must be pinned by digest"
[[ "$READY_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "--ready-timeout must be a positive integer"
((READY_TIMEOUT <= 86400)) || die "--ready-timeout must not exceed 86400 seconds"

DOCKER="$(find_docker_cli)"
if ((!DRY_RUN)); then "$DOCKER" info >/dev/null 2>&1 || die "Docker Engine/Desktop is not running"; fi
prepare_proxy_env
if [[ -n "$MYCOMESH_CONSUMER_HTTP_PROXY$MYCOMESH_CONSUMER_HTTPS_PROXY$MYCOMESH_CONSUMER_ALL_PROXY" ]]; then
  printf '%s\n' "Consumer network: explicit proxy"
else
  printf '%s\n' "Consumer network: direct"
fi
export MYCOMESH_NODE_IMAGE="$NODE_IMAGE"

if ((STOP)); then
  compose stop consumer
  printf '%s\n' "MycoMesh Consumer stopped. Its wallet and Session state remain in the Docker volume."
  exit 0
fi

if ((RESET_LOCAL)); then
  if ((DRY_RUN)); then
    printf '%s\n' "Would remove the Consumer containers, network, and protected local volume."
    exit 0
  fi
  printf '%s\n' "This removes the local API key, Consumer identity, wallet metadata and SQLite Session records."
  printf '%s' 'Type RESET to continue: '
  read -r confirmation
  [[ "$confirmation" == RESET ]] || die "local Consumer reset cancelled"
  compose down --volumes --remove-orphans
  printf '%s\n' "Local Consumer state removed. Any on-chain V5 Session remains on-chain."
  exit 0
fi

compose pull consumer-volume-init consumer
if ! compose up -d --wait --wait-timeout 90 consumer; then
  printf '%s\n' "Consumer startup failed. Check whether another process owns 127.0.0.1:8110." >&2
  "$DOCKER" compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE" logs --tail=120 consumer >&2 || true
  exit 1
fi
url="http://127.0.0.1:8110/app/playground"
open_browser "$url"

if ((DRY_RUN || NO_CODEX)); then
  printf '%s\n' "MycoMesh Consumer is running at http://127.0.0.1:8110/v1"
  ((DRY_RUN)) && printf '%s\n' "Dry run complete; no container or Codex process was started."
  exit 0
fi

printf '%s\n' "Waiting for the browser to activate the local V5 Session..."
command -v curl >/dev/null 2>&1 || die "curl is required while waiting for wallet onboarding"
started_at="$(date +%s)"
while ! curl --noproxy '*' --fail --silent --max-time 3 http://127.0.0.1:8110/ready >/dev/null 2>&1; do
  if (( $(date +%s) - started_at >= READY_TIMEOUT )); then
    die "timed out waiting for the local Consumer V5 Session; reopen $url"
  fi
  sleep 2
done

if ! codex_env="$("$DOCKER" compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE" exec -T consumer python -m gateway.local_consumer codex-env)"; then
  die "could not load Codex credentials from the local Consumer"
fi
eval "$codex_env"
unset codex_env
if ! command -v "$CODEX_COMMAND" >/dev/null 2>&1; then
  printf "error: Consumer is ready, but '%s' is not installed on this host\n" "$CODEX_COMMAND" >&2
  exit 127
fi

printf '%s\n' "Opening Codex through the local MycoMesh Consumer."
codex_command=(
  "$CODEX_COMMAND"
  -c 'model="gpt-5.5"' \
  -c 'model_provider="mycomesh"' \
  -c 'model_providers.mycomesh.name="MycoMesh"' \
  -c 'model_providers.mycomesh.base_url="http://127.0.0.1:8110/v1"' \
  -c 'model_providers.mycomesh.env_key="MYCOMESH_API_KEY"' \
  -c 'model_providers.mycomesh.wire_api="responses"'
)
if ((${#CODEX_ARGS[@]})); then
  codex_command+=("${CODEX_ARGS[@]}")
fi
exec "${codex_command[@]}"
