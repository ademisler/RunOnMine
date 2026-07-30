#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
binary=${RUNONMINE_BIN:-"$repo_root/target/debug/runonmine"}

if [ ! -x "$binary" ]; then
  (cd "$repo_root" && cargo build --locked -p runonmine)
fi

sandbox=$(mktemp -d)
cleanup() { rm -rf "$sandbox"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$sandbox/home" "$sandbox/project" "$sandbox/xdg-config" "$sandbox/xdg-state" "$sandbox/xdg-data"

run_cli() {
  HOME="$sandbox/home" \
  USERPROFILE="$sandbox/home" \
  APPDATA="$sandbox/appdata" \
  LOCALAPPDATA="$sandbox/localappdata" \
  XDG_CONFIG_HOME="$sandbox/xdg-config" \
  XDG_STATE_HOME="$sandbox/xdg-state" \
  XDG_DATA_HOME="$sandbox/xdg-data" \
  RUNONMINE_TEST_FILE_SECRETS=1 \
  RUNONMINE_MASTER_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  "$binary" "$@"
}

setup_output=$(run_cli setup --root "$sandbox/project")
printf '%s\n' "$setup_output" | grep -F 'RunOnMine is initialized.' >/dev/null
printf '%s\n' "$setup_output" | grep -F 'Allowed roots: 1' >/dev/null
run_cli policy show | grep -F 'AdminExec: Deny' >/dev/null
run_cli connect list | grep -F 'LocalHttp' >/dev/null
credential_file="$sandbox/local-http.json"
local_http_output=$(run_cli connect local-http enable --token-output "$credential_file")
printf '%s
' "$local_http_output" | grep -F 'Bearer token stored' >/dev/null
if printf '%s
' "$local_http_output" | grep -F 'Bearer token:' >/dev/null; then
  echo 'local HTTP token leaked to standard output' >&2
  exit 1
fi
grep -F '"bearer_token"' "$credential_file" >/dev/null
if run_cli connect local-http status --show-token >/dev/null 2>&1; then
  echo 'legacy local HTTP token reveal option was accepted' >&2
  exit 1
fi
run_cli connect local-http disable | grep -F 'token was deleted' >/dev/null
rm -f "$credential_file"
run_cli approvals list | grep -F 'No pending approvals.' >/dev/null
run_cli audit tail --limit 5 >/dev/null
run_cli lock | grep -F 'RunOnMine is locked.' >/dev/null
run_cli uninstall --purge --confirm PURGE | grep -F 'permanently removed' >/dev/null

if find "$sandbox" -type f -print -quit | grep . >/dev/null; then
  echo 'isolated smoke test left files below the temporary sandbox' >&2
  exit 1
fi

echo 'RunOnMine isolated CLI smoke test passed.'
