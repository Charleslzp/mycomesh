#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Run the Provider settings wizard from the already-pulled runtime image. Only
# an ephemeral staging directory is writable; Docker publishes the wizard
# solely on the host loopback interface.

PROVIDER_IMAGE=""
OUTPUT=""
IDENTITY_OUTPUT=""
PROTECTED_IDENTITY=""
HOST_PORT="${MYCOMESH_PROVIDER_WIZARD_PORT:-0}"
NO_BROWSER=0
PROTECTED_WALLET=0
DOCKER_BIN="${MYCOMESH_DOCKER_CLI:-docker}"
CONTAINER_PORT=8765
CONTAINER_NAME=""
STAGING_DIR=""
CONFIG_TEMPORARY=""
IDENTITY_TEMPORARY=""

die() {
  printf 'error: %s\n' "$*" >&2
  exit 64
}

usage() {
  cat <<'USAGE'
Usage: scripts/provider-onboarding-container.sh --image IMAGE --output FILE --identity-output FILE [options]

Options:
  --port PORT    Host loopback port (default: an automatically assigned port).
  --no-browser   Print the local URL without opening a browser.
  --protected-wallet  Reuse a wallet confirmed in the protected Docker volume.
  --protected-identity FILE  Temporary identity used only while backup is unconfirmed.
  -h, --help     Show this help.
USAGE
}

cleanup() {
  if [[ -n "$CONTAINER_NAME" ]]; then
    "$DOCKER_BIN" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  if [[ -n "$STAGING_DIR" ]]; then
    case "$STAGING_DIR" in
      "$output_dir"/.mycomesh-provider-onboarding.*)
        rm -rf -- "$STAGING_DIR"
        ;;
    esac
  fi
  [[ -z "$CONFIG_TEMPORARY" ]] || rm -f -- "$CONFIG_TEMPORARY"
  [[ -z "$IDENTITY_TEMPORARY" ]] || rm -f -- "$IDENTITY_TEMPORARY"
}
trap cleanup EXIT INT TERM

while (($#)); do
  case "$1" in
    --image)
      (($# >= 2)) || die "--image requires a value"
      PROVIDER_IMAGE="$2"
      shift 2
      ;;
    --output)
      (($# >= 2)) || die "--output requires a value"
      OUTPUT="$2"
      shift 2
      ;;
    --identity-output)
      (($# >= 2)) || die "--identity-output requires a value"
      IDENTITY_OUTPUT="$2"
      shift 2
      ;;
    --port)
      (($# >= 2)) || die "--port requires a value"
      HOST_PORT="$2"
      shift 2
      ;;
    --no-browser)
      NO_BROWSER=1
      shift
      ;;
    --protected-wallet)
      PROTECTED_WALLET=1
      shift
      ;;
    --protected-identity)
      (($# >= 2)) || die "--protected-identity requires a value"
      PROTECTED_IDENTITY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$PROVIDER_IMAGE" ]] || die "--image is required"
[[ -n "$OUTPUT" ]] || die "--output is required"
[[ -n "$IDENTITY_OUTPUT" ]] || die "--identity-output is required"
[[ "$HOST_PORT" =~ ^[0-9]+$ ]] || die "wizard port must be an integer"
((HOST_PORT >= 0 && HOST_PORT <= 65535)) || die "wizard port must be between 0 and 65535"
if ((HOST_PORT > 0 && HOST_PORT < 1024)); then
  die "wizard port must be 0 or between 1024 and 65535"
fi
case "$OUTPUT$IDENTITY_OUTPUT$PROTECTED_IDENTITY" in
  *$'\n'*|*$'\r'*) die "Provider state paths must be single-line values" ;;
  *,*) die "Provider state paths must not contain commas" ;;
esac
if ((PROTECTED_WALLET)); then
  if [[ -n "$PROTECTED_IDENTITY" ]]; then
    [[ ! -L "$PROTECTED_IDENTITY" && -f "$PROTECTED_IDENTITY" ]] \
      || die "protected Provider identity must be a regular file"
  fi
elif [[ -n "$PROTECTED_IDENTITY" ]]; then
  die "--protected-identity requires --protected-wallet"
fi

output_dir="$(dirname -- "$OUTPUT")"
identity_dir="$(dirname -- "$IDENTITY_OUTPUT")"
install -d -m 700 "$output_dir" "$identity_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"
identity_dir="$(cd -- "$identity_dir" && pwd -P)"
output_name="$(basename -- "$OUTPUT")"
identity_name="$(basename -- "$IDENTITY_OUTPUT")"
[[ "$output_name" != . && "$output_name" != .. && "$output_name" != */* ]] \
  || die "invalid Provider settings filename"
[[ "$identity_name" != . && "$identity_name" != .. && "$identity_name" != */* ]] \
  || die "invalid Provider identity filename"
output_target="$output_dir/$output_name"
identity_target="$identity_dir/$identity_name"
for target in "$output_target" "$identity_target"; do
  [[ ! -L "$target" ]] || die "Provider state files must not be symbolic links"
  [[ ! -e "$target" || -f "$target" ]] \
    || die "Provider state paths must be regular files"
done

# The default Provider home also contains downloaded release source. Stage only
# the two state files into a fresh directory so the onboarding image never gets
# a writable mount of their parent directories.
STAGING_DIR="$(mktemp -d "$output_dir/.mycomesh-provider-onboarding.XXXXXX")"
chmod 700 "$STAGING_DIR"
container_output="/run/mycomesh-state/settings.json"
container_identity="/run/mycomesh-state/provider-evm-identity.json"
if [[ -f "$output_target" ]]; then
  cp -p -- "$output_target" "$STAGING_DIR/settings.json"
fi
if ((PROTECTED_WALLET)) && [[ -n "$PROTECTED_IDENTITY" ]]; then
  cp -p -- "$PROTECTED_IDENTITY" "$STAGING_DIR/provider-evm-identity.json"
elif ((!PROTECTED_WALLET)) && [[ -f "$identity_target" ]]; then
  cp -p -- "$identity_target" "$STAGING_DIR/provider-evm-identity.json"
fi

# Generate the ephemeral CSRF token without requiring host Python or OpenSSL.
token="$(LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')"
[[ "$token" =~ ^[0-9a-f]{64}$ ]] || die "could not generate onboarding token"
CONTAINER_NAME="mycomesh-provider-onboarding-$$-$RANDOM"
protected_wallet_args=()
if ((PROTECTED_WALLET)); then
  protected_wallet_args+=(--protected-wallet)
fi

publish_arg="127.0.0.1::${CONTAINER_PORT}"
if ((HOST_PORT > 0)); then
  publish_arg="127.0.0.1:${HOST_PORT}:${CONTAINER_PORT}"
fi

container_id=$("$DOCKER_BIN" run --detach \
  --name "$CONTAINER_NAME" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --publish "$publish_arg" \
  --mount "type=bind,source=$STAGING_DIR,target=/run/mycomesh-state" \
  --entrypoint python \
  "$PROVIDER_IMAGE" \
  -m gateway.operator_setup wizard provider \
  --output "$container_output" \
  --identity-output "$container_identity" \
  --host 0.0.0.0 \
  --port "$CONTAINER_PORT" \
  --allow-container-bind \
  --token "$token" \
  --display-host 127.0.0.1 \
  --settlement-version "${MYCOMESH_SETTLEMENT_VERSION:-${PROVIDER_SETTLEMENT_VERSION:-${MYCOMESH_PUBLIC_PROVIDER_SETTLEMENT_VERSION:-8}}}" \
  "${protected_wallet_args[@]}" \
  --no-browser) || die "could not start the Provider settings container"
[[ -n "$container_id" ]] || die "Docker did not return the Provider settings container ID"

published=$("$DOCKER_BIN" port "$CONTAINER_NAME" "$CONTAINER_PORT/tcp" 2>/dev/null | head -n 1)
actual_port="${published##*:}"
[[ "$actual_port" =~ ^[0-9]+$ ]] || die "could not determine the local Provider settings port"
url="http://127.0.0.1:${actual_port}/?role=provider&token=${token}"

ready=0
for ((_attempt = 0; _attempt < 100; _attempt++)); do
  if "$DOCKER_BIN" exec "$CONTAINER_NAME" python -c \
      'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8765/health", timeout=1).read()' \
      >/dev/null 2>&1; then
    ready=1
    break
  fi
  if [[ "$("$DOCKER_BIN" inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)" != true ]]; then
    break
  fi
  sleep 0.1
done
if ((!ready)); then
  "$DOCKER_BIN" logs "$CONTAINER_NAME" >&2 || true
  die "Provider settings container did not become ready"
fi

printf 'MycoMesh provider onboarding: %s\n' "$url"
if ((!NO_BROWSER)); then
  case "$(uname -s)" in
    Darwin) open "$url" >/dev/null 2>&1 & ;;
    MINGW*|MSYS*|CYGWIN*) cmd.exe /C start "" "$url" >/dev/null 2>&1 & ;;
    *)
      if command -v wslview >/dev/null 2>&1; then
        wslview "$url" >/dev/null 2>&1 &
      elif command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -Command Start-Process "$url" >/dev/null 2>&1 &
      elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$url" >/dev/null 2>&1 &
      fi
      ;;
  esac
fi

exit_status=$("$DOCKER_BIN" wait "$CONTAINER_NAME")
if [[ "$exit_status" != 0 ]]; then
  "$DOCKER_BIN" logs "$CONTAINER_NAME" >&2 || true
  die "Provider settings wizard exited with status $exit_status"
fi

staged_config="$STAGING_DIR/settings.json"
staged_identity="$STAGING_DIR/provider-evm-identity.json"
[[ -f "$staged_config" && ! -L "$staged_config" ]] \
  || die "Provider settings wizard did not produce a regular settings file"

if ((!PROTECTED_WALLET)) && [[ -e "$staged_identity" ]]; then
  [[ -f "$staged_identity" && ! -L "$staged_identity" ]] \
    || die "Provider settings wizard produced an invalid identity file"
  if [[ -e "$identity_target" ]]; then
    cmp -s -- "$staged_identity" "$identity_target" \
      || die "refusing to replace the existing Provider identity"
  else
    IDENTITY_TEMPORARY="$identity_dir/.${identity_name}.onboarding.$$.$RANDOM"
    install -m 0600 "$staged_identity" "$IDENTITY_TEMPORARY"
    if ! ln -- "$IDENTITY_TEMPORARY" "$identity_target"; then
      die "could not install the Provider identity without replacing an existing file"
    fi
    rm -f -- "$IDENTITY_TEMPORARY"
    IDENTITY_TEMPORARY=""
  fi
fi

CONFIG_TEMPORARY="$output_dir/.${output_name}.onboarding.$$.$RANDOM"
install -m 0600 "$staged_config" "$CONFIG_TEMPORARY"
mv -f -- "$CONFIG_TEMPORARY" "$output_target"
CONFIG_TEMPORARY=""
