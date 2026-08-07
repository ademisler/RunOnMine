#!/usr/bin/env bash
set -euo pipefail
binary=${1:?desktop binary path is required}
if [[ ! -x "$binary" ]]; then
  echo "desktop binary is missing or not executable" >&2
  exit 2
fi
if [[ $(uname -s) == Darwin ]]; then
  # macOS Unix-domain sockets have a short sockaddr_un path limit. Keep the
  # isolated HOME under /tmp so the desktop single-instance socket remains
  # below SUN_LEN while preserving the same filesystem isolation contract.
  sandbox=$(mktemp -d /tmp/rm.XXXXXX)
else
  sandbox=$(mktemp -d)
fi
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf -- "$sandbox"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$sandbox/home" "$sandbox/xdg-config" "$sandbox/xdg-state" "$sandbox/xdg-data"
HOME="$sandbox/home" USERPROFILE="$sandbox/home" APPDATA="$sandbox/appdata" \
LOCALAPPDATA="$sandbox/localappdata" XDG_CONFIG_HOME="$sandbox/xdg-config" \
XDG_STATE_HOME="$sandbox/xdg-state" XDG_DATA_HOME="$sandbox/xdg-data" \
RUNONMINE_TEST_FILE_SECRETS=1 \
RUNONMINE_MASTER_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
"$binary" >"$sandbox/stdout.log" 2>"$sandbox/stderr.log" &
pid=$!
sleep "${RUNONMINE_DESKTOP_SOAK_SECONDS:-3}"
if ! kill -0 "$pid" 2>/dev/null; then
  cat "$sandbox/stderr.log" >&2
  exit 1
fi
kill "$pid"
wait "$pid" 2>/dev/null || [[ "$?" -eq 143 ]]
pid=""
echo "RunOnMine desktop launch smoke test passed."
