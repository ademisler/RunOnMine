#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <directory-containing-windows-gnu-binaries>" >&2
  exit 2
fi
binary_dir=$1
[[ $binary_dir = /* && -d $binary_dir ]] || { echo "binary directory must be absolute" >&2; exit 2; }
for binary in runonmine.exe runonmine-desktop.exe; do
  [[ -f $binary_dir/$binary ]] || { echo "missing $binary" >&2; exit 2; }
done
for command in openssl python3 wine wineboot winepath wineserver xvfb-run; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

sandbox=$(mktemp -d)
cleanup() {
  WINEPREFIX="$sandbox/prefix" wineserver -k >/dev/null 2>&1 || true
  rm -rf "$sandbox"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$sandbox/bin" "$sandbox/output"
cp "$binary_dir/runonmine.exe" "$binary_dir/runonmine-desktop.exe" "$sandbox/bin/"
export SANDBOX="$sandbox"

xvfb-run -a bash -s <<'INNER'
set -euo pipefail
export WINEARCH=win64
export WINEPREFIX="$SANDBOX/prefix"
export WINEDEBUG=-all
export WINEDLLOVERRIDES=mscoree,mshtml=
wineboot -u >/dev/null 2>&1
report_posix="$SANDBOX/output/desktop-report.json"
report_windows=$(winepath -w "$report_posix" | tr -d '\r')
master_key=$(openssl rand -hex 32)
RUNONMINE_TEST_FILE_SECRETS=1 \
RUNONMINE_MASTER_KEY="$master_key" \
RUNONMINE_DESKTOP_ACCEPTANCE_REPORT="$report_windows" \
  wine "$SANDBOX/bin/runonmine-desktop.exe" >"$SANDBOX/stdout" 2>"$SANDBOX/stderr" &
wine_pid=$!
completed=false
for _ in $(seq 1 600); do
  if [[ -f $report_posix ]]; then
    completed=true
    break
  fi
  kill -0 "$wine_pid" 2>/dev/null || break
  sleep 0.05
done
if [[ $completed != true ]]; then
  cat "$SANDBOX/stderr" >&2 || true
  exit 1
fi
for _ in $(seq 1 200); do
  kill -0 "$wine_pid" 2>/dev/null || break
  sleep 0.05
done
if kill -0 "$wine_pid" 2>/dev/null; then
  kill "$wine_pid" 2>/dev/null || true
fi
wait "$wine_pid" 2>/dev/null || true
INNER

python3 - "$sandbox/output/desktop-report.json" <<'PY'
import json, pathlib, sys
report=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["schema_version"] == 1
assert report["platform"] == "windows"
assert report["architecture"] == "x86_64"
assert [item["name"] for item in report["rendered_views"]] == [
    "overview", "approvals", "connections", "permissions", "oauth", "audit", "diagnostics"
]
assert report["native_shell_available"] is True
assert report["close_to_tray"] is True
assert report["native_shell_actions"] == ["show", "lock", "quit"]
assert report["default_viewport"] == [1320.0, 860.0]
assert report["minimum_viewport"] == [1040.0, 680.0]
assert report["application_icon"] is True
print(json.dumps(report, sort_keys=True))
PY

echo "RunOnMine supplemental Windows GNU/Wine desktop acceptance passed."
