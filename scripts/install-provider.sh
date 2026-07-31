#!/usr/bin/env bash
set -Eeuo pipefail

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
GHCR_HOST="ghcr.io"
DEFAULT_GHCR_USERNAME="Charleslzp"
PUBLIC_PROVIDER_SETTLEMENT_VERSION="5"
PUBLIC_PROVIDER_NETWORK_CONFIG="/app/deployments/sepolia-provider-network.json"
PUBLIC_PROVIDER_DEPLOYMENT="/app/deployments/sepolia-myco-v5.json"

IMAGE_TAG="${MYCOMESH_IMAGE_TAG:-}"
PROVIDER_IMAGE="${MYCOMESH_PROVIDER_IMAGE:-}"
GHCR_USERNAME="${GHCR_USERNAME:-$DEFAULT_GHCR_USERNAME}"
MAKE_BIN="${MAKE_BIN:-make}"
GHCR_LOGIN=0
CODEX_LOGIN=1
START_PROVIDER=1
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: scripts/install-provider.sh [options]

Prepare and start the image-backed MycoMesh Codex Provider.

Options:
  --image-tag TAG          Use a registry tag (default: latest; prefer sha-*).
  --provider-image IMAGE   Use a complete image tag or digest instead of a tag.
  --ghcr-username NAME     Username for the interactive GHCR login.
  --ghcr-login             Run an interactive GHCR login (only for private packages).
  --skip-codex-login       Reuse the Codex login already in the Docker volume.
  --no-start               Pull and authenticate, but do not start the Provider.
  --dry-run                Print the planned commands without changing state.
  -h, --help               Show this help.

The script must be checked out with the repository. It supports Linux, macOS,
and Linux containers running through WSL/Git Bash. Docker Desktop/Compose V2
is required on desktop systems. Standard HTTP_PROXY, HTTPS_PROXY, ALL_PROXY,
and NO_PROXY variables (including lowercase forms) are forwarded only to the
private Codex sidecar. MYCOMESH_PROVIDER_*_PROXY values take precedence.
MYCOMESH_DOCKER_CLI may pin the real Docker CLI when another executable named
docker appears earlier in PATH.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 64
}

is_docker_cli() {
  local candidate="${1-}"
  local version_output

  [[ -n "$candidate" && -x "$candidate" && ! -d "$candidate" ]] || return 1
  case "$candidate" in
    */node_modules/*) return 1 ;;
  esac
  version_output="$("$candidate" --version 2>/dev/null)" || return 1
  [[ "$version_output" == "Docker version "* ]] || return 1
  "$candidate" compose version >/dev/null 2>&1 || return 1
}

find_docker_cli() {
  local configured="${MYCOMESH_DOCKER_CLI:-}"
  local path_entry candidate name fallback
  local old_ifs="$IFS"

  if [[ -n "$configured" ]]; then
    candidate="$configured"
    if [[ "$candidate" != */* ]]; then
      candidate="$(command -v "$candidate" 2>/dev/null || true)"
    fi
    is_docker_cli "$candidate" || die "MYCOMESH_DOCKER_CLI is not a Docker CLI with Compose V2"
    printf '%s' "$candidate"
    return 0
  fi

  IFS=:
  for path_entry in ${PATH:-}; do
    [[ -n "$path_entry" ]] || path_entry=.
    for name in docker docker.exe; do
      candidate="$path_entry/$name"
      if is_docker_cli "$candidate"; then
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
    if is_docker_cli "$fallback"; then
      printf '%s' "$fallback"
      return 0
    fi
  done
  die "Docker Desktop/Engine CLI with Compose V2 is required"
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
  if ((DRY_RUN)); then
    printf '+ env PROVIDER_IMAGE=%q %q' "$PROVIDER_IMAGE" "$MAKE_BIN"
    printf ' %q' "${make_args[@]}"
    printf '\n'
  else
    env PROVIDER_IMAGE="$PROVIDER_IMAGE" "$MAKE_BIN" "${make_args[@]}"
  fi
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
    --no-start)
      START_PROVIDER=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
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

if [[ -n "$IMAGE_TAG" && -n "$PROVIDER_IMAGE" ]]; then
  die "use either --image-tag or --provider-image, not both"
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

command -v "$MAKE_BIN" >/dev/null 2>&1 || die "$MAKE_BIN is required"
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
    die "GNU Make is required; install gmake on macOS or make on Linux/WSL"
  fi
fi

if ! ((DRY_RUN)); then
  "$MYCOMESH_DOCKER_CLI" compose version >/dev/null 2>&1 || die "Docker Compose V2 is required (docker compose version)"
  "$MYCOMESH_DOCKER_CLI" info >/dev/null 2>&1 || die "Docker Engine/Desktop is not running"
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

make_target provider-image-pull

if ((CODEX_LOGIN)); then
  printf '%s\n' "Starting the one-time Codex device login. Follow the URL and code printed by the container."
  make_target provider-login-image
fi

make_target provider-auth-status-image

if ((START_PROVIDER)); then
  make_target provider-up-image
  make_target provider-health
  if ((DRY_RUN)); then
    printf '\n%s\n' "Dry run complete; the Provider was not started."
  else
    printf '\n%s\n' "MycoMesh Provider is running and passed its health checks."
  fi
else
  printf '\n%s\n' "Images and authentication are ready; Provider start was skipped."
fi

cat <<'NEXT'

Persistent Docker volumes retain the Codex login and Provider identities.
Do not run `docker compose down -v` unless you intend to erase them.
For an immutable deployment, rerun with --image-tag sha-<commit> or a digest.
NEXT
