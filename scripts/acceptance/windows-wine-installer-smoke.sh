#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <windows-nsis-installer>" >&2
  exit 2
fi
installer=$1
[[ $installer = /* && -f $installer ]] || { echo "installer must be an absolute file path" >&2; exit 2; }
for command in openssl python3 wine wineboot winepath wineserver xvfb-run; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

sandbox=$(mktemp -d)
cleanup() {
  WINEPREFIX="$sandbox/prefix" wineserver -k >/dev/null 2>&1 || true
  rm -rf "$sandbox"
}
trap cleanup EXIT HUP INT TERM
export SANDBOX="$sandbox" INSTALLER="$installer"

xvfb-run -a bash -s <<'INNER'
set -euo pipefail
export WINEARCH=win64
export WINEPREFIX="$SANDBOX/prefix"
export WINEDEBUG=-all
export WINEDLLOVERRIDES=mscoree,mshtml=
wineboot -u >/dev/null 2>&1
wine "$INSTALLER" /S
wineserver -w

localappdata_win=$(wine cmd /d /c 'echo %LOCALAPPDATA%' | tr -d '\r' | tail -n1)
appdata_win=$(wine cmd /d /c 'echo %APPDATA%' | tr -d '\r' | tail -n1)
userprofile_win=$(wine cmd /d /c 'echo %USERPROFILE%' | tr -d '\r' | tail -n1)
install_posix=$(winepath -u "${localappdata_win}\\RunOnMine")
local_data_posix=$(winepath -u "${localappdata_win}\\RunOnMine\\RunOnMine")
appdata_posix=$(winepath -u "$appdata_win")
userprofile_posix=$(winepath -u "$userprofile_win")

wine reg query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\RunOnMine' >"$SANDBOX/registry"
for binary in runonmine.exe runonmine-agent.exe runonmine-helper.exe runonmine-desktop.exe uninstall.exe; do
  [[ -f $install_posix/$binary ]] || { echo "installed file is missing: $binary" >&2; exit 1; }
done
find "$appdata_posix/Microsoft/Windows/Start Menu/Programs" -iname '*RunOnMine*.lnk' -print >"$SANDBOX/start-menu"
find "$userprofile_posix/Desktop" -iname '*RunOnMine*.lnk' -print >"$SANDBOX/desktop-shortcut"
[[ -s $SANDBOX/start-menu ]] || { echo "Start Menu shortcut is missing" >&2; exit 1; }
[[ -s $SANDBOX/desktop-shortcut ]] || { echo "desktop shortcut is missing" >&2; exit 1; }

report_posix="$SANDBOX/installed-report.json"
report_windows=$(winepath -w "$report_posix" | tr -d '\r')
master_key=$(openssl rand -hex 32)
RUNONMINE_TEST_FILE_SECRETS=1 \
RUNONMINE_MASTER_KEY="$master_key" \
RUNONMINE_DESKTOP_ACCEPTANCE_REPORT="$report_windows" \
  wine "$install_posix/runonmine-desktop.exe" >"$SANDBOX/stdout" 2>"$SANDBOX/stderr" &
app_pid=$!
for _ in $(seq 1 600); do
  [[ -f $report_posix ]] && break
  kill -0 "$app_pid" 2>/dev/null || break
  sleep 0.05
done
[[ -f $report_posix ]] || { cat "$SANDBOX/stderr" >&2 || true; exit 1; }
for _ in $(seq 1 200); do kill -0 "$app_pid" 2>/dev/null || break; sleep 0.05; done
if kill -0 "$app_pid" 2>/dev/null; then kill "$app_pid" 2>/dev/null || true; fi
wait "$app_pid" 2>/dev/null || true

wine "$install_posix/uninstall.exe" /S
wineserver -w
if wine reg query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\RunOnMine' >/dev/null 2>&1; then
  echo "uninstall registry record remained" >&2
  exit 1
fi
for managed in runonmine.exe runonmine-agent.exe runonmine-helper.exe runonmine-desktop.exe uninstall.exe README.md; do
  [[ ! -e $install_posix/$managed ]] || { echo "managed file remained: $managed" >&2; exit 1; }
done
while IFS= read -r shortcut; do [[ ! -e $shortcut ]] || { echo "Start Menu shortcut remained" >&2; exit 1; }; done <"$SANDBOX/start-menu"
while IFS= read -r shortcut; do [[ ! -e $shortcut ]] || { echo "desktop shortcut remained" >&2; exit 1; }; done <"$SANDBOX/desktop-shortcut"
[[ -d $local_data_posix ]] || { echo "retained local user data is missing" >&2; exit 1; }
unexpected=$(find "$install_posix" -type f ! -path "$local_data_posix/*" -print -quit 2>/dev/null || true)
[[ -z $unexpected ]] || { echo "unexpected managed residue: $unexpected" >&2; exit 1; }
INNER

python3 - "$sandbox/installed-report.json" <<'PY'
import json, pathlib, sys
report=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["platform"] == "windows"
assert report["architecture"] == "x86_64"
assert [item["name"] for item in report["rendered_views"]] == [
    "overview", "approvals", "connections", "permissions", "oauth", "audit", "diagnostics"
]
assert report["native_shell_available"] is True
assert report["close_to_tray"] is True
assert report["native_shell_actions"] == ["show", "lock", "quit"]
assert report["application_icon"] is True
print(json.dumps(report, sort_keys=True))
PY

grep -F 'DisplayName' "$sandbox/registry" >/dev/null
grep -F 'Publisher' "$sandbox/registry" >/dev/null
echo "RunOnMine supplemental Windows GNU/Wine NSIS install, retained-data uninstall and residue acceptance passed."
