#!/usr/bin/env bash
set -Eeuo pipefail

# Download a pinned repository snapshot and start the Relay's existing
# loopback onboarding flow. The checkout is retained for upgrades and health
# checks; no private key is read by this bootstrapper.

DEFAULT_REPOSITORY_URL="https://github.com/Charleslzp/mycomesh"
repository_url="${MYCOMESH_REPOSITORY_URL:-$DEFAULT_REPOSITORY_URL}"
repository_ref="${MYCOMESH_REF:-main}"
source_dir="${MYCOMESH_SOURCE_DIR:-$PWD/mycomesh}"
wizard_port="${MYCOMESH_RELAY_WIZARD_PORT:-8766}"
no_browser=0
no_start=0
dry_run=0

usage() {
  cat <<'USAGE'
Usage: scripts/bootstrap-relay.sh [options]

Download a MycoMesh checkout and start the Relay onboarding wizard.

Options:
  --ref REF              Branch, tag, or commit (env: MYCOMESH_REF; default: main)
  --repo-url URL         HTTPS repository URL (env: MYCOMESH_REPOSITORY_URL)
  --source-dir PATH      Persistent checkout directory (env: MYCOMESH_SOURCE_DIR; default: ./mycomesh)
  --wizard-port PORT     Loopback browser wizard port (default: 8766)
  --no-browser            Print the onboarding URL without opening a browser
  --no-start              Download/prepare the checkout without starting Relay
  --dry-run               Print planned operations without changing state
  -h, --help              Show this help

The browser wizard accepts a public payout address, concurrency and a usage
limit. It never accepts a wallet private key, seed phrase, or credential. A
Relay transaction signer, when settlement is enabled, remains in the protected
operator environment and is not handled by this script.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 64
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
    --wizard-port)
      (($# >= 2)) || die "--wizard-port requires a value"
      wizard_port="$2"
      shift 2
      ;;
    --no-browser)
      no_browser=1
      shift
      ;;
    --no-start)
      no_start=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --)
      shift
      (($# == 0)) || die "unexpected arguments after --"
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "$repository_url" == https://* ]] || die "--repo-url must use HTTPS"
[[ "$repository_ref" =~ ^[A-Za-z0-9._/-]{1,160}$ ]] || die "invalid repository ref"
[[ "$repository_ref" != *".."* && "$repository_ref" != /* ]] || die "invalid repository ref"
[[ "$wizard_port" =~ ^[0-9]+$ ]] || die "--wizard-port must be an integer"
((wizard_port >= 1 && wizard_port <= 65535)) || die "--wizard-port is out of range"
[[ "$source_dir" != / ]] || die "--source-dir cannot be the filesystem root"

source_dir="$({
  source_parent="$(dirname -- "$source_dir")"
  source_name="$(basename -- "$source_dir")"
  [[ "$source_name" != .. ]] || {
    printf 'error: --source-dir cannot resolve to the parent directory\n' >&2
    exit 64
  }
  mkdir -p -- "$source_parent"
  cd -- "$source_parent"
  printf '%s/%s' "$PWD" "$source_name"
})"

if [[ -f "$source_dir/Makefile" && -f "$source_dir/gateway/operator_setup.py" ]]; then
  if ((no_start)); then
    printf 'Relay checkout is ready at %s\n' "$source_dir"
    exit 0
  fi
  cd -- "$source_dir"
  if ((dry_run)); then
    printf '+ make -n relay-start MYCOMESH_RELAY_WIZARD_PORT=%q\n' "$wizard_port"
    exit 0
  fi
  relay_env=("MYCOMESH_RELAY_WIZARD_PORT=$wizard_port")
  if ((no_browser)); then
    relay_env+=("MYCOMESH_NO_BROWSER=1")
  fi
  exec env "${relay_env[@]}" make relay-start
fi

if [[ -e "$source_dir" ]]; then
  die "source directory exists but is not a complete MycoMesh checkout: $source_dir"
fi

if ((dry_run)); then
  printf '+ download %s/archive/%s.tar.gz -> %s\n' "${repository_url%.git}" "$repository_ref" "$source_dir"
  if ((no_start)); then
    printf 'Relay checkout would be prepared at %s\n' "$source_dir"
  else
    printf '+ make relay-start MYCOMESH_RELAY_WIZARD_PORT=%q\n' "$wizard_port"
  fi
  exit 0
fi

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v make >/dev/null 2>&1 || die "GNU Make is required"
command -v docker >/dev/null 2>&1 || die "Docker CLI is required"
docker compose version >/dev/null 2>&1 || die "Docker Compose V2 is required (docker compose version)"

archive_url="${repository_url%.git}/archive/${repository_ref}.tar.gz"
temporary_dir="$(mktemp -d "${source_dir}.download.XXXXXX")"
cleanup() {
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT

printf 'Downloading MycoMesh %s into %s\n' "$repository_ref" "$source_dir"
curl --fail --silent --show-error --location --retry 3 \
  "$archive_url" --output "$temporary_dir/source.tar.gz"
tar -xzf "$temporary_dir/source.tar.gz" -C "$temporary_dir"

extracted_root=""
extracted_root_count=0
for candidate in "$temporary_dir"/*; do
  [[ -d "$candidate" ]] || continue
  extracted_root="$candidate"
  extracted_root_count=$((extracted_root_count + 1))
done
[[ "$extracted_root_count" -eq 1 ]] || die "repository archive has an unexpected layout"
[[ -f "$extracted_root/Makefile" ]] || die "repository archive is missing Makefile"
[[ -f "$extracted_root/gateway/operator_setup.py" ]] || die "repository archive is missing Relay onboarding"

mv -- "$extracted_root" "$source_dir"
trap - EXIT

if ((no_start)); then
  printf 'Relay checkout is ready at %s\n' "$source_dir"
  exit 0
fi

cd -- "$source_dir"
relay_env=("MYCOMESH_RELAY_WIZARD_PORT=$wizard_port")
if ((no_browser)); then
  relay_env+=("MYCOMESH_NO_BROWSER=1")
fi
exec env "${relay_env[@]}" make relay-start
