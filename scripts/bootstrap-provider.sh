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
--image-tag, --provider-image, --ghcr-login, --skip-codex-login,
--skip-provider-config, --configure, --no-browser, --no-start, and --dry-run.

Set MYCOMESH_DOCKER_CLI to an absolute Docker CLI path when another executable
named docker appears earlier in PATH (for example, an npm package).

The first-run browser wizard uses an isolated Python environment under the
Provider state directory and installs its two crypto dependencies when they
are missing. Set MYCOMESH_PROVIDER_PYTHON or MYCOMESH_PROVIDER_HOST_VENV to
override those defaults.

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

bootstrap_provider_python_ready() {
  "$provider_python" -c 'import Crypto.Hash.keccak, cryptography' >/dev/null 2>&1
}

bootstrap_ensure_provider_host_python() {
  local base_python="${MYCOMESH_PROVIDER_PYTHON:-python3}"
  local config_path host_venv

  config_path="${MYCOMESH_PROVIDER_OPERATOR_CONFIG:-${PROVIDER_OPERATOR_CONFIG:-$source_dir/.mycomesh/operator/provider.json}}"
  host_venv="${MYCOMESH_PROVIDER_HOST_VENV:-$(dirname -- "$config_path")/.venv}"
  provider_python="${MYCOMESH_PROVIDER_PYTHON:-$host_venv/bin/python}"

  command -v "$base_python" >/dev/null 2>&1 \
    || die "Python 3.10 or newer is required for Provider onboarding"
  "$base_python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10 or newer is required for Provider onboarding"

  if [[ -n "${MYCOMESH_PROVIDER_PYTHON:-}" ]]; then
    bootstrap_provider_python_ready \
      || die "MYCOMESH_PROVIDER_PYTHON is missing Crypto/cryptography"
  else
    provider_python="$base_python"
    if bootstrap_provider_python_ready; then
      export MYCOMESH_PROVIDER_PYTHON="$provider_python"
      return 0
    fi
    provider_python="$host_venv/bin/python"
    if [[ ! -x "$host_venv/bin/python" ]]; then
      printf '%s\n' "Preparing the local Provider onboarding environment."
      install -d -m 700 "$(dirname -- "$host_venv")"
      "$base_python" -m venv "$host_venv" \
        || die "could not create Provider Python environment at $host_venv"
    fi
    provider_python="$host_venv/bin/python"
    if ! bootstrap_provider_python_ready; then
      printf '%s\n' "Installing Provider onboarding crypto dependencies."
      "$provider_python" -m pip install \
        --disable-pip-version-check --no-input \
        "cryptography==46.0.7" "pycryptodome==3.23.0" \
        || die "could not install Provider onboarding dependencies"
    fi
    bootstrap_provider_python_ready \
      || die "Provider onboarding Python environment is missing Crypto/cryptography"
  fi
  export MYCOMESH_PROVIDER_PYTHON="$provider_python"
}

bootstrap_installer_has_arg() {
  local expected="$1" arg
  for arg in "${installer_args[@]}"; do
    [[ "$arg" == "$expected" ]] && return 0
  done
  return 1
}

bootstrap_installer_supports_provider_config() {
  grep -q -- '--skip-provider-config)' "$source_dir/scripts/install-provider.sh"
}

bootstrap_prepare_legacy_provider_config() {
  local config_path identity_path wizard_port config_is_reusable=0
  local -a wizard_args

  bootstrap_installer_supports_provider_config && return 0

  config_path="${MYCOMESH_PROVIDER_OPERATOR_CONFIG:-${PROVIDER_OPERATOR_CONFIG:-$source_dir/.mycomesh/operator/provider.json}}"
  if [[ "$config_path" != /* ]]; then
    config_path="$source_dir/$config_path"
  fi
  PROVIDER_OPERATOR_CONFIG="$config_path"
  export PROVIDER_OPERATOR_CONFIG
  identity_path="${MYCOMESH_PROVIDER_IDENTITY_SOURCE:-$(dirname -- "$config_path")/provider-evm-identity.json}"
  PROVIDER_IDENTITY_SOURCE="$identity_path"
  export PROVIDER_IDENTITY_SOURCE

  if bootstrap_installer_has_arg --no-start; then
    return 0
  fi
  if bootstrap_installer_has_arg --skip-provider-config; then
    printf '%s\n' "Provider settings wizard skipped; persisted settings are unchanged (defaults apply only when none exist)."
    return 0
  fi
  if [[ ! -f "$source_dir/gateway/operator_setup.py" ]]; then
    printf '%s\n' "warning: existing checkout predates Provider browser settings; update it to configure capacity and payout" >&2
    return 0
  fi

  if [[ -s "$config_path" ]]; then
    if ! (cd -- "$source_dir" && "$provider_python" -m gateway.operator_setup env \
        --role provider --config "$config_path" >/dev/null 2>&1); then
      config_is_reusable=1
    fi
  fi
  if ((config_is_reusable)) && ! bootstrap_installer_has_arg --configure; then
    printf 'Using existing Provider settings: %s\n' "$config_path"
    return 0
  fi
  if [[ -s "$config_path" ]] && (( ! config_is_reusable )); then
    printf '%s\n' "warning: existing Provider settings are invalid; reopening the settings page" >&2
  fi

  wizard_port="${MYCOMESH_PROVIDER_WIZARD_PORT:-8765}"
  wizard_args=(
    "$provider_python" -m gateway.operator_setup wizard provider
    --output "$config_path"
    --identity-output "$identity_path"
    --port "$wizard_port"
  )
  if bootstrap_installer_has_arg --no-browser; then
    wizard_args+=(--no-browser)
  fi

  printf '%s\n' "Opening the local Provider settings page for the existing checkout."
  if bootstrap_installer_has_arg --dry-run; then
    printf '+'
    printf ' %q' "${wizard_args[@]}"
    printf '\n'
    printf 'Provider settings would be saved to %s\n' "$config_path"
    return 0
  fi
  install -d -m 700 "$(dirname -- "$config_path")"
  (cd -- "$source_dir" && "${wizard_args[@]}")
  printf 'Provider settings saved to %s\n' "$config_path"
}

bootstrap_filter_legacy_installer_args() {
  local arg
  local -a filtered=()

  bootstrap_installer_supports_provider_config && return 0
  for arg in "${installer_args[@]}"; do
    case "$arg" in
      --skip-provider-config|--configure|--no-browser) ;;
      *) filtered+=("$arg") ;;
    esac
  done
  installer_args=("${filtered[@]}")
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
  bootstrap_ensure_provider_host_python
  bootstrap_prepare_legacy_provider_config
  bootstrap_filter_legacy_installer_args
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
checkout_marker="$source_dir/.mycomesh-bootstrap-source"

if [[ -f "$source_dir/Makefile" && -x "$source_dir/scripts/install-provider.sh" ]]; then
  if [[ -f "$checkout_marker" ]]; then
    expected_marker="$(printf '%s\n%s' "$repository_url" "$repository_ref")"
    actual_marker="$(cat -- "$checkout_marker")"
    if [[ "$actual_marker" != "$expected_marker" ]]; then
      die "source directory belongs to a different repository/ref: $source_dir"
    fi
  fi
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
printf '%s\n%s\n' "$repository_url" "$repository_ref" >"$extracted_root/.mycomesh-bootstrap-source"
chmod 0644 "$extracted_root/.mycomesh-bootstrap-source"

mv -- "$extracted_root" "$source_dir"
run_installer
