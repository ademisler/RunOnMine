#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <runonmine-desktop>" >&2
  exit 2
fi

desktop=$1
case "$desktop" in
  /*) ;;
  *) echo "desktop binary must be an absolute path" >&2; exit 2 ;;
esac
[ -x "$desktop" ] || { echo "desktop binary is missing or not executable" >&2; exit 2; }
cli="$(dirname "$desktop")/runonmine"
[ -x "$cli" ] || { echo "runonmine must be installed beside the desktop binary" >&2; exit 2; }
for command in python3 openssl dbus-run-session xvfb-run; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 2; }
done

sandbox=$(mktemp -d)
cleanup() { rm -rf "$sandbox"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$sandbox/home" "$sandbox/config" "$sandbox/state" "$sandbox/data" "$sandbox/cache"
report="$sandbox/desktop-acceptance.json"
master_key=$(openssl rand -hex 32)

timeout "${RUNONMINE_DESKTOP_ACCEPTANCE_TIMEOUT:-30}s" \
  dbus-run-session -- xvfb-run -a env \
  HOME="$sandbox/home" \
  USERPROFILE="$sandbox/home" \
  XDG_CONFIG_HOME="$sandbox/config" \
  XDG_STATE_HOME="$sandbox/state" \
  XDG_DATA_HOME="$sandbox/data" \
  XDG_CACHE_HOME="$sandbox/cache" \
  RUNONMINE_TEST_FILE_SECRETS=1 \
  RUNONMINE_MASTER_KEY="$master_key" \
  RUNONMINE_DESKTOP_ACCEPTANCE_REPORT="$report" \
  "$desktop"

python3 - "$report" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
expected = ["overview", "approvals", "connections", "permissions", "oauth", "audit", "diagnostics"]
assert data["schema_version"] == 1
assert [item["name"] for item in data["rendered_views"]] == expected
assert all(item["width"] > 0 and item["height"] > 0 for item in data["rendered_views"])
assert data["native_shell_actions"] == ["show", "lock", "quit"]
assert data["default_viewport"] == [1320.0, 860.0]
assert data["minimum_viewport"] == [1040.0, 680.0]
assert data["application_icon"] is True
assert data["close_to_tray"] == data["native_shell_available"]
print(json.dumps(data, sort_keys=True))
PY

echo "RunOnMine desktop parity smoke test passed."
