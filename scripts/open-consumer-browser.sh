#!/bin/sh
set -eu

# The browser is an optional convenience for local interactive installs. A
# headless server can opt out without changing the Consumer service itself.
url=${MYCOMESH_CONSUMER_BROWSER_URL:-http://127.0.0.1:8110/}

if [ "${MYCOMESH_NO_BROWSER:-}" = "1" ] || [ "${CI:-}" = "true" ]; then
  printf '%s\n' "Consumer is ready: $url"
  exit 0
fi

open_command=''
case "$(uname -s 2>/dev/null || printf unknown)" in
  Darwin) open_command='open' ;;
  MINGW*|MSYS*|CYGWIN*)
    if command -v cmd.exe >/dev/null 2>&1; then
      cmd.exe /c start "" "$url" >/dev/null 2>&1 &
      printf '%s\n' "Consumer is ready: $url"
      exit 0
    fi
    ;;
  Linux*)
    if command -v xdg-open >/dev/null 2>&1; then open_command='xdg-open'; fi
    ;;
esac

if [ -n "$open_command" ] && command -v "$open_command" >/dev/null 2>&1; then
  "$open_command" "$url" >/dev/null 2>&1 &
  printf '%s\n' "Opened Consumer onboarding: $url"
else
  printf '%s\n' "Consumer is ready: $url"
  printf '%s\n' "Open this URL in a browser to view the local export, key, balance, and history."
fi
