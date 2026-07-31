#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <runonmine-desktop>" >&2
  exit 2
fi
desktop=$1
[[ $desktop = /* && -x $desktop ]] || { echo "desktop binary must be an executable absolute path" >&2; exit 2; }
cli="$(dirname "$desktop")/runonmine"
[[ -x $cli ]] || { echo "runonmine must be installed beside the desktop binary" >&2; exit 2; }
for variable in DISPLAY DBUS_SESSION_BUS_ADDRESS XAUTHORITY XDG_RUNTIME_DIR; do
  [[ -n ${!variable:-} ]] || { echo "$variable is required" >&2; exit 2; }
done
for command in busctl gdbus openssl python3 wmctrl xdotool; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

sandbox=$(mktemp -d)
app_pid=""
cleanup() {
  if [[ -n $app_pid ]]; then
    kill "$app_pid" 2>/dev/null || true
    wait "$app_pid" 2>/dev/null || true
  fi
  rm -rf "$sandbox"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$sandbox/home" "$sandbox/config" "$sandbox/state" "$sandbox/data" "$sandbox/cache"
master_key=$(openssl rand -hex 32)
common_env=(
  HOME="$sandbox/home"
  USERPROFILE="$sandbox/home"
  XDG_CONFIG_HOME="$sandbox/config"
  XDG_STATE_HOME="$sandbox/state"
  XDG_DATA_HOME="$sandbox/data"
  XDG_CACHE_HOME="$sandbox/cache"
  RUNONMINE_TEST_FILE_SECRETS=1
  RUNONMINE_MASTER_KEY="$master_key"
)

report="$sandbox/session-report.json"
env "${common_env[@]}" RUNONMINE_DESKTOP_ACCEPTANCE_REPORT="$report" "$desktop"
python3 - "$report" <<'PY'
import json, pathlib, sys
report=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["platform"] == "linux"
assert report["native_shell_available"] is True
assert report["close_to_tray"] is True
assert len(report["rendered_views"]) == 7
assert report["native_shell_actions"] == ["show", "lock", "quit"]
PY

before=$(busctl --user list --no-legend | awk '/org.kde.StatusNotifierItem-/ {print $1}' | sort)
env "${common_env[@]}" "$desktop" >"$sandbox/stdout" 2>"$sandbox/stderr" &
app_pid=$!
window=""
for _ in $(seq 1 300); do
  window=$(xdotool search --onlyvisible --name '^RunOnMine$' 2>/dev/null | tail -n1 || true)
  [[ -n $window ]] && break
  kill -0 "$app_pid" 2>/dev/null || break
  sleep 0.05
done
[[ -n $window ]] || { cat "$sandbox/stderr" >&2; echo "visible RunOnMine window was not found" >&2; exit 1; }
after=$(busctl --user list --no-legend | awk '/org.kde.StatusNotifierItem-/ {print $1}' | sort)
tray_name=$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | head -n1)
[[ -n $tray_name ]] || { echo "RunOnMine StatusNotifierItem was not registered" >&2; exit 1; }

window_hex=$(printf '0x%x' "$window")
wmctrl -ic "$window_hex"
visible=""
for _ in $(seq 1 200); do
  visible=$(xdotool search --onlyvisible --name '^RunOnMine$' 2>/dev/null | tail -n1 || true)
  [[ -z $visible ]] && break
  sleep 0.05
done
[[ -z $visible ]] || { echo "RunOnMine window did not hide after window-manager close" >&2; exit 1; }
kill -0 "$app_pid"

gdbus call --session --dest "$tray_name" --object-path /StatusNotifierItem \
  --method org.kde.StatusNotifierItem.Activate 0 0 >/dev/null
reopened=""
for _ in $(seq 1 200); do
  reopened=$(xdotool search --onlyvisible --name '^RunOnMine$' 2>/dev/null | tail -n1 || true)
  [[ -n $reopened ]] && break
  sleep 0.05
done
[[ -n $reopened ]] || { echo "RunOnMine tray activation did not reopen the window" >&2; exit 1; }

kill "$app_pid"
wait "$app_pid" 2>/dev/null || true
app_pid=""
for _ in $(seq 1 100); do
  busctl --user list --no-legend | awk -v name="$tray_name" '$1 == name { found=1 } END { exit found ? 0 : 1 }' || break
  sleep 0.05
done
if busctl --user list --no-legend | awk -v name="$tray_name" '$1 == name { found=1 } END { exit found ? 0 : 1 }'; then
  echo "RunOnMine StatusNotifierItem remained after exit" >&2
  exit 1
fi

echo "RunOnMine Linux desktop session, close-to-tray and reopen acceptance passed."
