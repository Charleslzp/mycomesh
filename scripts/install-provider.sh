#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Bootstrap the image-backed Codex Provider without copying wallet or Codex
# secrets into the repository. The actual device login remains interactive.

SCRIPT_PATH="${BASH_SOURCE[0]}"
if [[ ! -f "$SCRIPT_PATH" ]]; then
  printf '%s\n' "Download this script first; do not pipe it into bash." >&2
  exit 64
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
PROVIDER_PROXY_HELPER="$SCRIPT_DIR/provider-proxy-env.sh"
PROVIDER_ONBOARDING_HELPER="$SCRIPT_DIR/provider-onboarding-container.sh"
GHCR_HOST="ghcr.io"
DEFAULT_GHCR_USERNAME="Charleslzp"
PUBLIC_PROVIDER_SETTLEMENT_VERSION="8"
if [[ -n "${MYCOMESH_PUBLIC_PROVIDER_SETTLEMENT_VERSION:-}" ]]; then
  PUBLIC_PROVIDER_SETTLEMENT_VERSION="$MYCOMESH_PUBLIC_PROVIDER_SETTLEMENT_VERSION"
fi
PUBLIC_PROVIDER_NETWORK_CONFIG="${MYCOMESH_PUBLIC_PROVIDER_NETWORK_CONFIG:-/app/deployments/sepolia-provider-network-v${PUBLIC_PROVIDER_SETTLEMENT_VERSION}.json}"
PUBLIC_PROVIDER_DEPLOYMENT="${MYCOMESH_PUBLIC_PROVIDER_DEPLOYMENT:-/app/deployments/sepolia-myco-v${PUBLIC_PROVIDER_SETTLEMENT_VERSION}.json}"
PUBLIC_PROVIDER_BRIDGE_URL="https://bridge.mycomesh.xyz"

IMAGE_TAG="${MYCOMESH_IMAGE_TAG:-}"
PROVIDER_IMAGE="${MYCOMESH_PROVIDER_IMAGE:-}"
GHCR_USERNAME="${GHCR_USERNAME:-$DEFAULT_GHCR_USERNAME}"
MAKE_BIN="${MAKE_BIN:-make}"
GHCR_LOGIN=0
CODEX_LOGIN=1
FORCE_CODEX_LOGIN=0
START_PROVIDER=1
CONFIGURE_PROVIDER=1
# First run configures the Provider; later starts reuse a validated protected
# profile. --configure explicitly reopens the local settings page.
FORCE_PROVIDER_CONFIG=0
NO_BROWSER=0
DRY_RUN=0
CONFIGURE_ONLY=0
PULL_PROVIDER_IMAGE=1
DOCTOR=0

PROVIDER_OPERATOR_CONFIG="${MYCOMESH_PROVIDER_OPERATOR_CONFIG:-$REPO_ROOT/.mycomesh/operator/provider.json}"
PROVIDER_IDENTITY_SOURCE="${MYCOMESH_PROVIDER_IDENTITY_SOURCE:-$(dirname -- "$PROVIDER_OPERATOR_CONFIG")/provider-evm-identity.json}"
PROVIDER_PROTECTED_WALLET=0

usage() {
  cat <<'USAGE'
Usage: scripts/install-provider.sh [options]

Prepare and start the image-backed MycoMesh Codex Provider.

Options:
  --image-tag TAG          Use a registry tag (default: latest; prefer sha-*).
  --provider-image IMAGE   Use a complete image tag or digest instead of a tag.
  --ghcr-username NAME     Username for the interactive GHCR login.
  --ghcr-login             Run an interactive GHCR login (only for private packages).
  --skip-codex-login       Require an existing login without opening sign-in.
  --reauthenticate         Back up the existing login and sign in again.
  --skip-provider-config   Do not open the wizard; keep persisted settings/defaults.
  --configure              Reopen the settings page before starting.
  --configure-only         Save settings without checking Codex login or starting.
  --no-browser             Print the settings URL without opening a browser.
  --no-start               Pull and authenticate, but do not start the Provider.
  --dry-run                Print the planned commands without changing state.
  --doctor                 Check local dependencies only; do not install or start anything.
  -h, --help               Show this help.

The script must be checked out with the repository. It supports Linux, macOS,
and Linux containers running through WSL/Git Bash. Docker Desktop/Compose V2
is required on desktop systems. Standard HTTP_PROXY, HTTPS_PROXY, ALL_PROXY,
and NO_PROXY variables (including lowercase forms) are forwarded only to the
private Codex sidecar. MYCOMESH_PROVIDER_*_PROXY values take precedence.
MYCOMESH_DOCKER_CLI may pin the real Docker CLI when another executable named
docker appears earlier in PATH. The local settings wizard runs inside the
already-pulled Provider image, so the host does not need Python, venv, pip, or
Python packages.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 64
}

is_docker_cli() {
  local candidate="${1-}"
  local require_compose="${2:-1}"
  local version_output

  [[ -n "$candidate" && -x "$candidate" && ! -d "$candidate" ]] || return 1
  case "$candidate" in
    */node_modules/*) return 1 ;;
  esac
  version_output="$("$candidate" --version 2>/dev/null)" || return 1
  [[ "$version_output" == "Docker version "* ]] || return 1
  if ((require_compose)); then
    "$candidate" compose version >/dev/null 2>&1 || return 1
  fi
}

find_docker_cli() {
  local configured="${MYCOMESH_DOCKER_CLI:-}"
  local require_compose="${1:-1}"
  local path_entry candidate name fallback
  local old_ifs="$IFS"

  if [[ -n "$configured" ]]; then
    candidate="$configured"
    if [[ "$candidate" != */* ]]; then
      candidate="$(command -v "$candidate" 2>/dev/null || true)"
    fi
    is_docker_cli "$candidate" "$require_compose" || die "MYCOMESH_DOCKER_CLI is not a usable Docker CLI; run scripts/install-provider.sh --doctor"
    printf '%s' "$candidate"
    return 0
  fi

  IFS=:
  for path_entry in ${PATH:-}; do
    [[ -n "$path_entry" ]] || path_entry=.
    for name in docker docker.exe; do
      candidate="$path_entry/$name"
      if is_docker_cli "$candidate" "$require_compose"; then
        IFS="$old_ifs"
        printf '%s' "$candidate"
        return 0
      fi
    done
  done
  IFS="$old_ifs"

  for fallback in \
    /usr/local/bin/docker \
    /opt/homebrew/bin/docker \
    /usr/bin/docker \
    /Applications/Docker.app/Contents/Resources/bin/docker \
    '/c/Program Files/Docker/Docker/resources/bin/docker.exe'; do
    if is_docker_cli "$fallback" "$require_compose"; then
      printf '%s' "$fallback"
      return 0
    fi
  done
  die "Docker Desktop/Engine CLI with Compose V2 is required; run scripts/install-provider.sh --doctor for recovery steps"
}

dependency_recovery() {
  local issue="$1" host_os
  host_os="$(uname -s)"
  case "$issue" in
    docker) printf '%s\n' 'Install Docker Desktop (macOS/Windows) or Docker Engine (Linux): https://docs.docker.com/get-started/get-docker/' ;;
    compose) printf '%s\n' 'Update Docker Desktop, or install the Docker Compose V2 plugin on Linux: https://docs.docker.com/compose/install/'; printf '%s\n' 'Check again with: docker compose version' ;;
    engine)
      if [[ "$host_os" == Darwin ]]; then
        printf '%s\n' 'Start Docker Desktop: open -a Docker'
      elif [[ "$host_os" == Linux ]]; then
        printf '%s\n' 'Start your Docker runtime. For a systemd Docker Engine install: sudo systemctl start docker'
      else
        printf '%s\n' 'Open Docker Desktop and wait for the engine to be running.'
      fi
      printf '%s\n' 'Then check: docker info. If Docker is already running, check docker context show and access to that context; do not make the socket world-writable.'
      ;;
    make)
      if [[ "$host_os" == Darwin ]]; then
        printf '%s\n' 'Install GNU Make (for Homebrew users: brew install make), then retry with MAKE_BIN=gmake.'
      else
        printf '%s\n' 'Install GNU Make with your system package manager, then verify: make --version'
      fi
      ;;
  esac
}

provider_doctor() {
  local failures=0 selected="" make_version="" make_candidate="$MAKE_BIN"
  printf '%s\n' 'MycoMesh Provider dependency check (read-only)'
  if ! command -v "$make_candidate" >/dev/null 2>&1 || ! make_version="$("$make_candidate" --version 2>/dev/null)" || [[ "$make_version" != *"GNU Make"* ]]; then
    make_candidate=gmake
    if ! make_version="$(gmake --version 2>/dev/null)"; then make_version=""; fi
  fi
  if [[ "$make_version" == *"GNU Make"* ]]; then
    printf '[OK] GNU Make: %s\n' "$make_candidate"
  else
    printf '%s\n' '[BLOCKED] GNU Make is unavailable.'
    dependency_recovery make
    failures=$((failures + 1))
  fi
  if selected="$(find_docker_cli 0 2>/dev/null)"; then
    printf '[OK] Docker CLI: %s\n' "$selected"
    if "$selected" compose version >/dev/null 2>&1; then
      printf '%s\n' '[OK] Docker Compose V2'
    else
      printf '%s\n' '[BLOCKED] Docker Compose V2 is unavailable.'
      dependency_recovery compose
      failures=$((failures + 1))
    fi
    if "$selected" info >/dev/null 2>&1; then
      printf '%s\n' '[OK] Docker engine is reachable.'
    else
      printf '%s\n' '[BLOCKED] Docker engine is stopped or inaccessible from the current context.'
      dependency_recovery engine
      failures=$((failures + 1))
    fi
  else
    printf '%s\n' '[BLOCKED] Docker CLI is unavailable or MYCOMESH_DOCKER_CLI points to an invalid executable.'
    dependency_recovery docker
    printf '%s\n' '[NOT CHECKED] Compose and engine require a working Docker CLI.'
    failures=$((failures + 1))
  fi
  printf '%s\n' 'Not checked: image download, Codex login/model access, wallet authorization, network-funded capacity admission, personal stake, gas, Relay/Bridge connection or earnings.'
  if ((failures)); then
    printf '%s\n' 'Fix the blocked items, then rerun: scripts/install-provider.sh --doctor'
    return 64
  fi
  printf '%s\n' 'Local dependencies are ready. This does not mean the Provider is online; rerun your original start command to continue.'
}

prepare_docker_cli() {
  local previous selected selected_dir

  previous="$(command -v docker 2>/dev/null || true)"
  selected="$(find_docker_cli)"
  selected_dir="$(dirname -- "$selected")"
  PATH="$selected_dir:${PATH:-}"
  MYCOMESH_DOCKER_CLI="$selected"
  export PATH MYCOMESH_DOCKER_CLI
  hash -r
  if [[ -n "$previous" && "$previous" != "$selected" ]]; then
    printf 'Ignoring non-Docker executable at %s; using Docker CLI at %s.\n' \
      "$previous" "$selected"
  fi
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

run() {
  if ((DRY_RUN)); then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

make_target() {
  local make_args=(
    "PROVIDER_SETTLEMENT_VERSION=$PUBLIC_PROVIDER_SETTLEMENT_VERSION"
    "PROVIDER_NETWORK_CONFIG=$PUBLIC_PROVIDER_NETWORK_CONFIG"
    "PROVIDER_DEPLOYMENT=$PUBLIC_PROVIDER_DEPLOYMENT"
    "$@"
  )
  # An empty value deliberately overrides stale .env.deploy values. The
  # Provider entrypoint derives the address from its protected identity.
  make_args+=("PROVIDER_PAYMENT_ADDRESS=")
  if [[ -n "${PROVIDER_OPERATOR_CONFIG:-}" && -s "$PROVIDER_OPERATOR_CONFIG" ]]; then
    make_args+=("PROVIDER_OPERATOR_CONFIG=$PROVIDER_OPERATOR_CONFIG")
  fi
  if ((!PROVIDER_PROTECTED_WALLET)) \
    && [[ -n "${PROVIDER_IDENTITY_SOURCE:-}" && -s "$PROVIDER_IDENTITY_SOURCE" ]]; then
    make_args+=("PROVIDER_IDENTITY_SOURCE=$PROVIDER_IDENTITY_SOURCE")
  else
    make_args+=("PROVIDER_IDENTITY_SOURCE=")
  fi
  if ((DRY_RUN)); then
    printf '+ env PROVIDER_IMAGE=%q %q' "$PROVIDER_IMAGE" "$MAKE_BIN"
    printf ' %q' "${make_args[@]}"
    printf '\n'
  else
    env PROVIDER_IMAGE="$PROVIDER_IMAGE" "$MAKE_BIN" --silent --no-print-directory "${make_args[@]}"
  fi
}

export_protected_provider_config() {
  env -u MYCOMESH_PROVIDER_OPERATOR_CONFIG -u MYCOMESH_PROVIDER_IDENTITY_SOURCE \
    PROVIDER_IMAGE="$PROVIDER_IMAGE" \
    "$MAKE_BIN" --silent --no-print-directory \
    "PROVIDER_SETTLEMENT_VERSION=$PUBLIC_PROVIDER_SETTLEMENT_VERSION" \
    "PROVIDER_NETWORK_CONFIG=$PUBLIC_PROVIDER_NETWORK_CONFIG" \
    "PROVIDER_DEPLOYMENT=$PUBLIC_PROVIDER_DEPLOYMENT" \
    provider-operator-config-export-image
}

restore_protected_provider_config() {
  local config_dir temporary_config

  ((DRY_RUN)) && return 0

  config_dir="$(dirname -- "$PROVIDER_OPERATOR_CONFIG")"
  install -d -m 700 "$config_dir"
  temporary_config="$(mktemp "$config_dir/.provider-settings.restore.XXXXXX")"
  if ! export_protected_provider_config >"$temporary_config"; then
    rm -f -- "$temporary_config"
    die "could not inspect protected Provider settings; refusing to replace them"
  fi
  if [[ ! -s "$temporary_config" ]]; then
    rm -f -- "$temporary_config"
    return 0
  fi
  PROVIDER_PROTECTED_WALLET=1
  chmod 600 "$temporary_config"
  mv -f -- "$temporary_config" "$PROVIDER_OPERATOR_CONFIG"
  chmod 600 "$PROVIDER_OPERATOR_CONFIG"
  printf 'Restored existing Provider settings: %s\n' "$PROVIDER_OPERATOR_CONFIG"
  if ((!FORCE_PROVIDER_CONFIG && !CONFIGURE_ONLY)) \
    && grep -Eq '"settings_reusable"[[:space:]]*:[[:space:]]*true([[:space:]]*[,}])' "$PROVIDER_OPERATOR_CONFIG" \
    && grep -Eq '"settlement_version"[[:space:]]*:[[:space:]]*'"$PUBLIC_PROVIDER_SETTLEMENT_VERSION"'([[:space:]]*[,}])' "$PROVIDER_OPERATOR_CONFIG"; then
    CONFIGURE_PROVIDER=0
    printf '%s\n' "Using saved Provider settings. To change them: mycomesh-provider --configure"
  fi
}

ensure_provider_authorization() {
  local status_output
  local -a authorization_args
  [[ "$PUBLIC_PROVIDER_SETTLEMENT_VERSION" == 8 || "$PUBLIC_PROVIDER_SETTLEMENT_VERSION" == 9 || "$PUBLIC_PROVIDER_SETTLEMENT_VERSION" == 10 ]] || return 0
  if ((DRY_RUN)); then
    make_target provider-authorization-status
    printf '%s\n' "Would resume only wallet authorization if the saved Provider is not authorized."
    return 0
  fi
  status_output="$(make_target provider-authorization-status)" \
    || die "Could not verify Provider wallet authorization; no transaction was sent. Retry when the network is reachable."
  if grep -Eq '"authorized"[[:space:]]*:[[:space:]]*true([[:space:]]*[,}])' <<<"$status_output"; then
    return 0
  fi
  grep -Eq '"authorized"[[:space:]]*:[[:space:]]*false([[:space:]]*[,}])' <<<"$status_output" \
    || die "Provider authorization check returned an invalid result"
  restore_protected_provider_config
  ((PROVIDER_PROTECTED_WALLET)) || die "Provider identity is not persisted; refusing wallet authorization"
  printf '%s\n' "Resuming one-time wallet authorization. Your Provider settings are unchanged."
  authorization_args=(
    "$PROVIDER_ONBOARDING_HELPER" --image "$PROVIDER_IMAGE"
    --output "$PROVIDER_OPERATOR_CONFIG" --identity-output "$PROVIDER_IDENTITY_SOURCE"
    --port "${MYCOMESH_PROVIDER_WIZARD_PORT:-0}" --network-config "$PUBLIC_PROVIDER_NETWORK_CONFIG"
    --protected-wallet --authorization-only
  )
  if ((NO_BROWSER)); then authorization_args+=(--no-browser); fi
  run "${authorization_args[@]}"
  make_target provider-config-apply-image
}

while (($#)); do
  case "$1" in
    --image-tag)
      (($# >= 2)) || die "--image-tag requires a value"
      IMAGE_TAG="$2"
      shift 2
      ;;
    --provider-image)
      (($# >= 2)) || die "--provider-image requires a value"
      PROVIDER_IMAGE="$2"
      shift 2
      ;;
    --ghcr-username)
      (($# >= 2)) || die "--ghcr-username requires a value"
      GHCR_USERNAME="$2"
      shift 2
      ;;
    --ghcr-login)
      GHCR_LOGIN=1
      shift
      ;;
    --skip-codex-login)
      CODEX_LOGIN=0
      shift
      ;;
    --reauthenticate)
      FORCE_CODEX_LOGIN=1
      shift
      ;;
    --skip-provider-config)
      CONFIGURE_PROVIDER=0
      FORCE_PROVIDER_CONFIG=0
      shift
      ;;
    --configure)
      FORCE_PROVIDER_CONFIG=1
      shift
      ;;
    --configure-only)
      CONFIGURE_ONLY=1
      START_PROVIDER=0
      shift
      ;;
    --skip-image-pull)
      PULL_PROVIDER_IMAGE=0
      shift
      ;;
    --no-browser)
      NO_BROWSER=1
      shift
      ;;
    --no-start)
      START_PROVIDER=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --doctor)
      DOCTOR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if ((DOCTOR)); then
  provider_doctor
  exit 0
fi

if [[ -n "$IMAGE_TAG" && -n "$PROVIDER_IMAGE" ]]; then
  die "use either --image-tag or --provider-image, not both"
fi
if ((!CONFIGURE_PROVIDER && FORCE_PROVIDER_CONFIG)); then
  die "use either --configure or --skip-provider-config, not both"
fi
if ((!CODEX_LOGIN && FORCE_CODEX_LOGIN)); then
  die "use either --reauthenticate or --skip-codex-login, not both"
fi

if [[ -z "$PROVIDER_IMAGE" ]]; then
  IMAGE_TAG="${IMAGE_TAG:-latest}"
  [[ "$IMAGE_TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "invalid image tag"
  PROVIDER_IMAGE="${GHCR_HOST}/charleslzp/mycomesh-provider-codex:${IMAGE_TAG}"
  if [[ "$IMAGE_TAG" == latest ]]; then
    warn "latest is mutable; use --image-tag sha-<commit> or --provider-image ...@sha256:... for production"
  fi
else
  [[ "$PROVIDER_IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._/@:-]*$ ]] || die "invalid provider image reference"
fi

[[ -f "$REPO_ROOT/Makefile" ]] || die "Makefile not found; run this from a repository checkout"
[[ -f "$REPO_ROOT/docker-compose.yml" ]] || die "docker-compose.yml not found; checkout is incomplete"
[[ -f "$REPO_ROOT/.env.deploy.example" ]] || die ".env.deploy.example is missing"
[[ -r "$PROVIDER_PROXY_HELPER" ]] || die "scripts/provider-proxy-env.sh is missing"
if ((CONFIGURE_PROVIDER)); then
  [[ -x "$PROVIDER_ONBOARDING_HELPER" ]] \
    || die "scripts/provider-onboarding-container.sh is missing or not executable"
fi

# shellcheck source=provider-proxy-env.sh
source "$PROVIDER_PROXY_HELPER"
mycomesh_provider_prepare_proxy_env || die "invalid Provider proxy configuration"

case "$(uname -s)" in
  Linux|Darwin|MINGW*|MSYS*|CYGWIN*) ;;
  *) die "unsupported host OS: $(uname -s); use Docker Linux containers or WSL" ;;
esac

case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) die "unsupported architecture: $(uname -m); published images support amd64 and arm64" ;;
esac

command -v "$MAKE_BIN" >/dev/null 2>&1 || { dependency_recovery make >&2; die "$MAKE_BIN is required; run scripts/install-provider.sh --doctor"; }
prepare_docker_cli

MAKE_VERSION="$("$MAKE_BIN" --version 2>/dev/null || true)"
if [[ "$MAKE_VERSION" != *"GNU Make"* ]]; then
  GMAKE_VERSION=""
  if command -v gmake >/dev/null 2>&1; then
    GMAKE_VERSION="$(gmake --version 2>/dev/null || true)"
  fi
  if [[ "$GMAKE_VERSION" == *"GNU Make"* ]]; then
    MAKE_BIN="gmake"
  else
    dependency_recovery make >&2
    die "GNU Make is required; run scripts/install-provider.sh --doctor"
  fi
fi

if ! ((DRY_RUN)); then
  "$MYCOMESH_DOCKER_CLI" compose version >/dev/null 2>&1 || die "Docker Compose V2 is required (docker compose version)"
  "$MYCOMESH_DOCKER_CLI" info >/dev/null 2>&1 || { dependency_recovery engine >&2; die "Docker Engine/Desktop is not running or is inaccessible; run scripts/install-provider.sh --doctor"; }
fi

if mycomesh_provider_proxy_enabled; then
  printf '%s\n' "Provider Codex proxy enabled for login and runtime traffic."
fi

cd "$REPO_ROOT"
[[ ! -L .env.deploy ]] || die ".env.deploy must not be a symbolic link"
if [[ ! -e .env.deploy ]]; then
  run cp .env.deploy.example .env.deploy
fi
run chmod 600 .env.deploy

if ((GHCR_LOGIN)); then
  printf '%s\n' "GHCR login is interactive; the token is not read from an environment variable or written to .env.deploy."
  run "$MYCOMESH_DOCKER_CLI" login "$GHCR_HOST" --username "$GHCR_USERNAME"
fi

if ((PULL_PROVIDER_IMAGE)); then
  make_target provider-image-pull
fi
restore_protected_provider_config
if ((CONFIGURE_PROVIDER)); then
  printf '%s\n' "Opening the local Provider settings page. Enter the payout address and serving limits."
  wizard_args=(
    "$PROVIDER_ONBOARDING_HELPER"
    --image "$PROVIDER_IMAGE"
    --output "$PROVIDER_OPERATOR_CONFIG"
    --identity-output "$PROVIDER_IDENTITY_SOURCE"
    --port "${MYCOMESH_PROVIDER_WIZARD_PORT:-0}"
    --network-config "$PUBLIC_PROVIDER_NETWORK_CONFIG"
  )
  if ((NO_BROWSER)); then
    wizard_args+=(--no-browser)
  fi
  if ((PROVIDER_PROTECTED_WALLET)); then
    wizard_args+=(--protected-wallet)
  fi
  run "${wizard_args[@]}"
  make_target provider-config-apply-image
  if ((DRY_RUN)); then
    printf 'Provider settings would be saved to %s\n' "$PROVIDER_OPERATOR_CONFIG"
  else
    printf 'Provider settings saved to %s\n' "$PROVIDER_OPERATOR_CONFIG"
  fi
elif ((START_PROVIDER)); then
  printf '%s\n' "Provider settings wizard skipped; persisted settings are unchanged (defaults apply only when none exist)."
  printf '%s\n' "Run: make provider-configure"
elif [[ ! -s "$PROVIDER_OPERATOR_CONFIG" ]]; then
  printf '%s\n' "Provider settings are not configured because --no-start was used."
  printf '%s\n' "Run: make provider-configure"
fi

if ((START_PROVIDER || CONFIGURE_ONLY)); then
  ensure_provider_authorization
fi

if ((CONFIGURE_ONLY)); then
  printf '\n%s\n' "Provider settings are configured; Provider start was skipped."
  printf 'Provider settings: %s\n' "$PROVIDER_OPERATOR_CONFIG"
  exit 0
fi

if ((FORCE_CODEX_LOGIN)); then
  printf '%s\n' "Backing up the protected Codex login before a fresh sign-in."
  make_target provider-auth-reset-image
fi
if ((CODEX_LOGIN)); then
  printf '%s\n' "Checking the protected Codex login. A sign-in URL and code are shown only when login is needed."
  make_target provider-auth-ensure-image
else
  make_target provider-auth-status-image
fi

if ((START_PROVIDER)); then
  make_target provider-up-image
  make_target provider-health
  if ((DRY_RUN)); then
    printf '\n%s\n' "Dry run complete; the Provider was not started."
  else
    printf '\n%s\n' "MycoMesh Provider is running and connected to the network."
    printf 'Network: %s\n' "$PUBLIC_PROVIDER_BRIDGE_URL"
  fi
else
  printf '\n%s\n' "Images and authentication are ready; Provider start was skipped."
fi

printf 'Provider settings: %s\n' "$PROVIDER_OPERATOR_CONFIG"
printf '%s\n' "Next start: mycomesh-provider"
printf '%s\n' "Change settings: mycomesh-provider --configure"

cat <<'NEXT'

Persistent Docker volumes retain the Codex login and Provider identities.
Do not run `docker compose down -v` unless you intend to erase them.
NEXT
