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

The script downloads the archive over HTTPS and never reads or stores a wallet
private key, Codex password, OAuth export, or registry token.
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
  exec "$source_dir/scripts/install-provider.sh" "${installer_args[@]}"
fi
if [[ -e "$source_dir" ]]; then
  die "source directory exists but is not a complete MycoMesh checkout: $source_dir"
fi

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

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
[[ -x "$extracted_root/scripts/install-provider.sh" ]] || die "repository archive is missing Provider installer"

mv -- "$extracted_root" "$source_dir"
trap - EXIT
exec "$source_dir/scripts/install-provider.sh" "${installer_args[@]}"
