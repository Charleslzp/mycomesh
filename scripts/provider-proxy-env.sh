#!/usr/bin/env bash

# Resolve host proxy variables for the private Codex sidecar. This file is
# sourced by the Provider installer and intentionally produces no output.

mycomesh_provider_rewrite_loopback_proxy() {
  local value="${1-}"
  local scheme authority suffix userinfo host_port replacement_tail

  case "$value" in
    *$'\n'*|*$'\r'*)
      printf '%s\n' "Provider proxy URLs must be single-line values" >&2
      return 64
      ;;
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

mycomesh_provider_append_no_proxy() {
  local result="${1-}"
  local candidate
  shift || true

  for candidate in "$@"; do
    case ",$result," in
      *",$candidate,"*) ;;
      *) result="${result:+${result},}${candidate}" ;;
    esac
  done
  printf '%s' "$result"
}

mycomesh_provider_prepare_proxy_env() {
  local resolved_http resolved_https resolved_all resolved_no_proxy

  resolved_http="${MYCOMESH_PROVIDER_HTTP_PROXY:-${http_proxy:-${HTTP_PROXY:-}}}"
  resolved_https="${MYCOMESH_PROVIDER_HTTPS_PROXY:-${https_proxy:-${HTTPS_PROXY:-}}}"
  resolved_all="${MYCOMESH_PROVIDER_ALL_PROXY:-${all_proxy:-${ALL_PROXY:-}}}"
  resolved_no_proxy="${MYCOMESH_PROVIDER_NO_PROXY:-${no_proxy:-${NO_PROXY:-}}}"

  resolved_http="$(mycomesh_provider_rewrite_loopback_proxy "$resolved_http")" || return
  resolved_https="$(mycomesh_provider_rewrite_loopback_proxy "$resolved_https")" || return
  resolved_all="$(mycomesh_provider_rewrite_loopback_proxy "$resolved_all")" || return
  resolved_no_proxy="$(
    mycomesh_provider_append_no_proxy \
      "$resolved_no_proxy" \
      127.0.0.1 localhost ::1 provider provider-sidecar
  )"

  export MYCOMESH_PROVIDER_HTTP_PROXY="$resolved_http"
  export MYCOMESH_PROVIDER_HTTPS_PROXY="$resolved_https"
  export MYCOMESH_PROVIDER_ALL_PROXY="$resolved_all"
  export MYCOMESH_PROVIDER_NO_PROXY="$resolved_no_proxy"
}

mycomesh_provider_proxy_enabled() {
  [[ -n "${MYCOMESH_PROVIDER_HTTP_PROXY:-}" \
    || -n "${MYCOMESH_PROVIDER_HTTPS_PROXY:-}" \
    || -n "${MYCOMESH_PROVIDER_ALL_PROXY:-}" ]]
}
