#!/usr/bin/env bash
set -Eeuo pipefail

# Download a pinned repository snapshot, then delegate to the checked-in
# Provider installer. The downloaded checkout is kept so .env.deploy and the
# Compose configuration remain available for upgrades and health checks.

DEFAULT_REPOSITORY_URL="https://github.com/Charleslzp/mycomesh"
repository_url="${MYCOMESH_REPOSITORY_URL:-$DEFAULT_REPOSITORY_URL}"
repository_ref="${MYCOMESH_REF:-main}"
source_dir="${MYCOMESH_SOURCE_DIR:-$PWD/mycomesh}"
installer_args=()

usage() {
  cat <<'USAGE'
Usage: scripts/bootstrap-provider.sh [bootstrap options] [installer options]

Download a MycoMesh checkout and run scripts/install-provider.sh.

Bootstrap options:
  --ref REF              Branch, tag, or commit (env: MYCOMESH_REF; default: main)
  --repo-url URL         HTTPS GitHub repository URL
                         (env: MYCOMESH_REPOSITORY_URL)
  --source-dir PATH      Persistent checkout directory
                         (env: MYCOMESH_SOURCE_DIR; default: ./mycomesh)

All other options are passed to scripts/install-provider.sh, including
--image-tag, --provider-image, --ghcr-login, --skip-codex-login, --no-start,
and --dry-run.

Set MYCOMESH_DOCKER_CLI to an absolute Docker CLI path when another executable
named docker appears earlier in PATH (for example, an npm package).

The script downloads the archive over HTTPS and never reads or stores a wallet
private key, Codex password, OAuth export, or registry token.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 64
}

bootstrap_is_docker_cli() {
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

bootstrap_find_docker_cli() {
  local configured="${MYCOMESH_DOCKER_CLI:-}"
  local path_entry candidate name fallback
  local old_ifs="$IFS"

  if [[ -n "$configured" ]]; then
    candidate="$configured"
    if [[ "$candidate" != */* ]]; then
      candidate="$(command -v "$candidate" 2>/dev/null || true)"
    fi
    bootstrap_is_docker_cli "$candidate" || die "MYCOMESH_DOCKER_CLI is not a Docker CLI with Compose V2"
    printf '%s' "$candidate"
    return 0
  fi

  IFS=:
  for path_entry in ${PATH:-}; do
    [[ -n "$path_entry" ]] || path_entry=.
    for name in docker docker.exe; do
      candidate="$path_entry/$name"
      if bootstrap_is_docker_cli "$candidate"; then
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
    if bootstrap_is_docker_cli "$fallback"; then
      printf '%s' "$fallback"
      return 0
    fi
  done
  die "Docker Desktop/Engine CLI with Compose V2 is required"
}

bootstrap_prepare_docker_cli() {
  local previous selected selected_dir

  previous="$(command -v docker 2>/dev/null || true)"
  selected="$(bootstrap_find_docker_cli)"
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

bootstrap_rewrite_loopback_proxy() {
  local value="${1-}"
  local scheme authority suffix userinfo host_port replacement_tail

  case "$value" in
    *$'\n'*|*$'\r'*) die "Provider proxy URLs must be single-line values" ;;
  esac
  if [[ ! "$value" =~ ^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*)(.*)$ ]]; then
    printf '%s' "$value"
    return 0
  fi

  scheme="${BASH_REMATCH[1]}"
  authority="${BASH_REMATCH[2]}"
  suffix="${BASH_REMATCH[3]}"
  userinfo=""
  host_port="$authority"
  if [[ "$authority" == *@* ]]; then
    userinfo="${authority%@*}@"
    host_port="${authority##*@}"
  fi

  replacement_tail=""
  if [[ "$host_port" == "127.0.0.1" ]]; then
    :
  elif [[ "$host_port" == 127.0.0.1:* ]]; then
    replacement_tail="${host_port#127.0.0.1}"
  elif [[ "$host_port" == "[::1]" ]]; then
    :
  elif [[ "$host_port" == "[::1]:"* ]]; then
    replacement_tail="${host_port#\[::1\]}"
  elif [[ "$host_port" =~ ^[Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt](:.*)?$ ]]; then
    replacement_tail="${BASH_REMATCH[1]}"
  else
    printf '%s' "$value"
    return 0
  fi
  printf '%s' "${scheme}${userinfo}host.docker.internal${replacement_tail}${suffix}"
}

bootstrap_prepare_proxy_env() {
  local resolved_http resolved_https resolved_all resolved_no_proxy

  if [[ -r "$source_dir/scripts/provider-proxy-env.sh" ]]; then
    # shellcheck source=provider-proxy-env.sh
    source "$source_dir/scripts/provider-proxy-env.sh"
    mycomesh_provider_prepare_proxy_env || die "invalid Provider proxy configuration"
    return 0
  fi

  resolved_http="${MYCOMESH_PROVIDER_HTTP_PROXY:-${http_proxy:-${HTTP_PROXY:-}}}"
  resolved_https="${MYCOMESH_PROVIDER_HTTPS_PROXY:-${https_proxy:-${HTTPS_PROXY:-}}}"
  resolved_all="${MYCOMESH_PROVIDER_ALL_PROXY:-${all_proxy:-${ALL_PROXY:-}}}"
  resolved_no_proxy="${MYCOMESH_PROVIDER_NO_PROXY:-${no_proxy:-${NO_PROXY:-}}}"
  resolved_http="$(bootstrap_rewrite_loopback_proxy "$resolved_http")"
  resolved_https="$(bootstrap_rewrite_loopback_proxy "$resolved_https")"
  resolved_all="$(bootstrap_rewrite_loopback_proxy "$resolved_all")"
  resolved_no_proxy="${resolved_no_proxy:+${resolved_no_proxy},}127.0.0.1,localhost,::1,provider,provider-sidecar"

  export MYCOMESH_PROVIDER_HTTP_PROXY="$resolved_http"
  export MYCOMESH_PROVIDER_HTTPS_PROXY="$resolved_https"
  export MYCOMESH_PROVIDER_ALL_PROXY="$resolved_all"
  export MYCOMESH_PROVIDER_NO_PROXY="$resolved_no_proxy"
}

bootstrap_proxy_enabled() {
  [[ -n "${MYCOMESH_PROVIDER_HTTP_PROXY:-}" \
    || -n "${MYCOMESH_PROVIDER_HTTPS_PROXY:-}" \
    || -n "${MYCOMESH_PROVIDER_ALL_PROXY:-}" ]]
}

download_dir=""
proxy_override_dir=""
cleanup() {
  if [[ -n "$download_dir" && -d "$download_dir" ]]; then
    rm -rf -- "$download_dir"
  fi
  if [[ -n "$proxy_override_dir" && -d "$proxy_override_dir" ]]; then
    rm -rf -- "$proxy_override_dir"
  fi
}
trap cleanup EXIT

run_installer() {
  local compose_path_separator override_file

  bootstrap_prepare_docker_cli
  bootstrap_prepare_proxy_env
  if bootstrap_proxy_enabled \
    && ! grep -q 'MYCOMESH_PROVIDER_HTTP_PROXY' "$source_dir/docker-compose.yml"; then
    proxy_override_dir="$(mktemp -d "${TMPDIR:-/tmp}/mycomesh-provider-proxy.XXXXXX")"
    override_file="$proxy_override_dir/compose.yml"
    cat >"$override_file" <<'YAML'
services:
  provider-sidecar:
    extra_hosts:
      - "host.docker.internal=host-gateway"
    environment:
      HTTP_PROXY: ${MYCOMESH_PROVIDER_HTTP_PROXY:-}
      HTTPS_PROXY: ${MYCOMESH_PROVIDER_HTTPS_PROXY:-}
      ALL_PROXY: ${MYCOMESH_PROVIDER_ALL_PROXY:-}
      NO_PROXY: ${MYCOMESH_PROVIDER_NO_PROXY:-127.0.0.1,localhost,::1,provider,provider-sidecar}
      http_proxy: ${MYCOMESH_PROVIDER_HTTP_PROXY:-}
      https_proxy: ${MYCOMESH_PROVIDER_HTTPS_PROXY:-}
      all_proxy: ${MYCOMESH_PROVIDER_ALL_PROXY:-}
      no_proxy: ${MYCOMESH_PROVIDER_NO_PROXY:-127.0.0.1,localhost,::1,provider,provider-sidecar}
YAML
    chmod 600 "$override_file"

    compose_path_separator="${COMPOSE_PATH_SEPARATOR:-}"
    if [[ -z "$compose_path_separator" ]]; then
      case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) compose_path_separator=";" ;;
        *) compose_path_separator=":" ;;
      esac
    fi
    export COMPOSE_PATH_SEPARATOR="$compose_path_separator"
    export COMPOSE_FILE="${COMPOSE_FILE:-$source_dir/docker-compose.yml}${compose_path_separator}${override_file}"
    printf '%s\n' "Applying Provider proxy compatibility for the existing checkout."
  fi

  "$source_dir/scripts/install-provider.sh" "${installer_args[@]}"
}

while (($#)); do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --ref)
      (($# >= 2)) || die "--ref requires a value"
      repository_ref="$2"
      shift 2
      ;;
    --repo-url)
      (($# >= 2)) || die "--repo-url requires a value"
      repository_url="$2"
      shift 2
      ;;
    --source-dir)
      (($# >= 2)) || die "--source-dir requires a value"
      source_dir="$2"
      shift 2
      ;;
    --)
      shift
      installer_args+=("$@")
      break
      ;;
    *)
      installer_args+=("$1")
      shift
      ;;
  esac
done

[[ "$repository_url" == https://* ]] || die "--repo-url must use HTTPS"
[[ "$repository_ref" =~ ^[A-Za-z0-9._/-]{1,160}$ ]] || die "invalid repository ref"
[[ "$repository_ref" != *".."* && "$repository_ref" != /* ]] || die "invalid repository ref"
[[ "$source_dir" != / ]] || die "--source-dir cannot be the filesystem root"

source_dir="$(
  source_parent="$(dirname -- "$source_dir")"
  source_name="$(basename -- "$source_dir")"
  if [[ "$source_name" == .. ]]; then
    printf 'error: --source-dir cannot resolve to the parent directory\n' >&2
    exit 64
  fi
  mkdir -p -- "$source_parent"
  cd -- "$source_parent"
  printf '%s/%s' "$PWD" "$source_name"
)"

if [[ -f "$source_dir/Makefile" && -x "$source_dir/scripts/install-provider.sh" ]]; then
  run_installer
  exit 0
fi
if [[ -e "$source_dir" ]]; then
  die "source directory exists but is not a complete MycoMesh checkout: $source_dir"
fi

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

archive_url="${repository_url%.git}/archive/${repository_ref}.tar.gz"
download_dir="$(mktemp -d "${source_dir}.download.XXXXXX")"

printf 'Downloading MycoMesh %s into %s\n' "$repository_ref" "$source_dir"
curl --fail --silent --show-error --location --retry 3 \
  "$archive_url" --output "$download_dir/source.tar.gz"
tar -xzf "$download_dir/source.tar.gz" -C "$download_dir"

extracted_root=""
extracted_root_count=0
for candidate in "$download_dir"/*; do
  [[ -d "$candidate" ]] || continue
  extracted_root="$candidate"
  extracted_root_count=$((extracted_root_count + 1))
done
[[ "$extracted_root_count" -eq 1 ]] || die "repository archive has an unexpected layout"
[[ -f "$extracted_root/Makefile" ]] || die "repository archive is missing Makefile"
[[ -x "$extracted_root/scripts/install-provider.sh" ]] || die "repository archive is missing Provider installer"

mv -- "$extracted_root" "$source_dir"
run_installer
