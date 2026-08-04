#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage:
  macos-clean-install.sh prepare --dmg ABSOLUTE_DMG --sbom ABSOLUTE_SBOM --output ABSOLUTE_DIRECTORY
  macos-clean-install.sh verify --output ABSOLUTE_DIRECTORY

The prepare stage installs the DMG into /Applications, exercises both universal
slices and the native desktop lifecycle, configures Local HTTP plus a temporary
Cloudflare Quick Tunnel, installs the per-user LaunchAgent, and records the boot
session. Reboot the Mac, then run verify in the same logged-in user session.
USAGE
  exit 2
}

[[ $# -ge 1 ]] || usage
stage=$1
shift
dmg=""
sbom=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dmg) [[ $# -ge 2 ]] || usage; dmg=$2; shift 2 ;;
    --sbom) [[ $# -ge 2 ]] || usage; sbom=$2; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ $stage == prepare || $stage == verify ]] || usage
[[ -n $output && $output == /* ]] || usage

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
app=/Applications/RunOnMine.app
app_bin="$app/Contents/MacOS"
cli="$app_bin/runonmine"
desktop="$app_bin/runonmine-desktop"
agent="$app_bin/runonmine-agent"
helper="$app_bin/runonmine-helper"
state="$output/acceptance-state.json"
macmcp_baseline="$output/macmcp-baseline.json"
evidence="$output/macos-universal-clean-install.json"
mkdir -p "$output"
chmod 700 "$output"

fail() { printf 'macOS clean-install acceptance failed: %s\n' "$*" >&2; exit 1; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
boot_session() { sysctl -n kern.bootsessionuuid; }

require_clean_revision() {
  [[ -z $(git -C "$repo_root" status --porcelain) ]] || fail "repository must be clean and committed"
  git -C "$repo_root" rev-parse HEAD
}

capture_macmcp() {
  local destination=$1 uid broker tunnel
  uid=$(id -u)
  broker="$HOME/Library/LaunchAgents/com.idemasler.macmcp.broker.plist"
  tunnel="$HOME/Library/LaunchAgents/com.idemasler.macmcp.tunnel.plist"
  [[ -f $broker && -f $tunnel ]] || fail "MacMCP LaunchAgent files are missing"
  launchctl print "gui/$uid/com.idemasler.macmcp.broker" >/dev/null 2>&1 || fail "MacMCP broker is not loaded"
  launchctl print "gui/$uid/com.idemasler.macmcp.tunnel" >/dev/null 2>&1 || fail "MacMCP tunnel is not loaded"
  lsof -nP -iTCP:45799 -sTCP:LISTEN | grep -F '127.0.0.1:45799' >/dev/null || fail "MacMCP loopback port 45799 is not listening"
  python3 - "$destination" "$(sha256 "$broker")" "$(sha256 "$tunnel")" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "broker_plist_sha256": sys.argv[2],
    "tunnel_plist_sha256": sys.argv[3],
    "broker_loaded": True,
    "tunnel_loaded": True,
    "loopback_45799_listening": True,
}, indent=2) + "\n")
PY
  chmod 600 "$destination"
}

verify_macmcp() {
  local current="$output/macmcp-current.json"
  capture_macmcp "$current"
  python3 - "$macmcp_baseline" "$current" <<'PY'
import json, pathlib, sys
before=json.loads(pathlib.Path(sys.argv[1]).read_text())
after=json.loads(pathlib.Path(sys.argv[2]).read_text())
if before != after:
    raise SystemExit(f"MacMCP invariant changed: before={before!r} after={after!r}")
PY
}

wait_health() {
  local port=$1
  for _ in $(seq 1 300); do
    if python3 - "$port" <<'PY' >/dev/null 2>&1
import http.client, sys
port=int(sys.argv[1])
c=http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
c.request("GET", "/healthz", headers={"Host": f"127.0.0.1:{port}"})
r=c.getresponse(); body=r.read(); c.close()
raise SystemExit(0 if r.status == 200 and body == b"ok" else 1)
PY
    then return 0; fi
    sleep 0.1
  done
  fail "agent health endpoint did not become ready"
}

wait_connector_ready() {
  local port=$1 connector_id=$2
  for _ in $(seq 1 600); do
    if python3 - "$port" "$connector_id" <<'PY' >/dev/null 2>&1
import http.client, json, sys
port=int(sys.argv[1]); wanted=sys.argv[2]
c=http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
c.request("GET", "/healthz/connectors", headers={"Host": f"127.0.0.1:{port}"})
r=c.getresponse(); body=r.read(); c.close()
if r.status != 200: raise SystemExit(1)
data=json.loads(body)
for item in data.get("connectors", []):
    if item.get("connector_id") == wanted and item.get("phase") == "ready":
        raise SystemExit(0)
raise SystemExit(1)
PY
    then return 0; fi
    sleep 0.25
  done
  fail "Cloudflare Quick Tunnel did not become ready"
}

validate_desktop_report() {
  local path=$1 architecture=$2
  python3 - "$path" "$architecture" <<'PY'
import json, pathlib, sys
report=json.loads(pathlib.Path(sys.argv[1]).read_text())
expected=sys.argv[2]
assert report["schema_version"] == 1
assert report["platform"] == "macos"
assert report["architecture"] == expected, report
assert len(report["rendered_views"]) == 7
assert report["native_shell_available"] is True
assert report["close_to_tray"] is True
assert report["native_shell_actions"] == ["show", "lock", "quit"]
assert report["application_icon"] is True
PY
}

install_dmg() {
  local mount_plist="$output/dmg-attach.plist" attach_log="$output/dmg-license.log" mount source_app
  [[ -f $dmg && $dmg == /* ]] || fail "DMG is missing or not absolute"
  [[ ! -e $app ]] || fail "$app already exists; clean-install acceptance refuses to overwrite it"
  printf 'Y\n' | hdiutil attach -readonly -nobrowse "$dmg" >"$attach_log"
  hdiutil info -plist >"$mount_plist"
  mount=$(python3 - "$mount_plist" "$dmg" <<'PY'
import os, plistlib, sys
with open(sys.argv[1], 'rb') as handle:
    data=plistlib.load(handle)
wanted=os.path.realpath(sys.argv[2])
matches=[]
for image in data.get('images', []):
    if os.path.realpath(image.get('image-path', '')) != wanted:
        continue
    points=[item.get('mount-point') for item in image.get('system-entities', []) if item.get('mount-point')]
    matches.extend(points)
if len(matches) != 1:
    raise SystemExit(f"expected one mount point for {wanted}, received {matches!r}")
print(matches[0])
PY
)
  source_app=$(find "$mount" -maxdepth 1 -type d -name 'RunOnMine.app' -print -quit)
  if [[ -z $source_app ]]; then
    hdiutil detach "$mount" >/dev/null || true
    fail "DMG does not contain RunOnMine.app"
  fi
  ditto "$source_app" "$app"
  hdiutil detach "$mount" >/dev/null
}

verify_bundle() {
  [[ -d $app ]] || fail "installed application bundle is missing"
  for binary in "$cli" "$agent" "$desktop" "$helper"; do
    [[ -x $binary ]] || fail "installed binary is missing: $binary"
    lipo "$binary" -verify_arch arm64 x86_64 >/dev/null || fail "binary is not universal: $binary"
  done
  [[ $(defaults read "$app/Contents/Info" CFBundleIdentifier) == dev.runonmine.app ]] || fail "bundle identifier mismatch"
  codesign --verify --deep --strict "$app" >/dev/null 2>&1 || fail "application bundle signature structure is invalid"
  "$cli" --version | grep -Fx 'runonmine 0.1.0-beta.1' >/dev/null
}

has_preexisting_runonmine_state() {
  local managed_path first_entry
  [[ -e "$HOME/Library/LaunchAgents/dev.runonmine.agent.plist" ]] && return 0
  launchctl print "gui/$(id -u)/dev.runonmine.agent" >/dev/null 2>&1 && return 0
  pgrep -f '^/Applications/RunOnMine.app/Contents/MacOS/runonmine-(agent|desktop)( |$)' >/dev/null 2>&1 && return 0
  for managed_path in \
    "$HOME/Library/Application Support/dev.RunOnMine.RunOnMine" \
    "$HOME/Library/Preferences/dev.RunOnMine.RunOnMine" \
    "$HOME/Library/Logs/dev.RunOnMine.RunOnMine"; do
    [[ -L $managed_path ]] && return 0
    [[ -e $managed_path && ! -d $managed_path ]] && return 0
    if [[ -d $managed_path ]]; then
      first_entry=""
      first_entry=$(find "$managed_path" -mindepth 1 ! -type d -print -quit) || return 0
      [[ -n $first_entry ]] && return 0
    fi
  done
  return 1
}

run_desktop_acceptance() {
  local arm_report="$output/desktop-arm64.json" intel_report="$output/desktop-x86_64.json"
  rm -f -- "$arm_report" "$intel_report"
  RUNONMINE_DESKTOP_ACCEPTANCE_REPORT="$arm_report" arch -arm64 "$desktop" >"$output/desktop-arm64.log" 2>&1
  validate_desktop_report "$arm_report" aarch64
  RUNONMINE_DESKTOP_ACCEPTANCE_REPORT="$intel_report" arch -x86_64 "$desktop" >"$output/desktop-x86_64.log" 2>&1
  validate_desktop_report "$intel_report" x86_64
}

run_desktop_lifecycle() {
  local report="$output/desktop-lifecycle.json" ready="$output/desktop-lifecycle.ready"
  local primary_pid secondary_status=0 primary_status=0
  rm -f -- "$report" "$ready"
  RUNONMINE_DESKTOP_LIFECYCLE_REPORT="$report" \
  RUNONMINE_DESKTOP_LIFECYCLE_READY="$ready" \
    "$desktop" >"$output/desktop-primary.log" 2>&1 &
  primary_pid=$!
  for _ in $(seq 1 600); do
    [[ -f $ready ]] && break
    kill -0 "$primary_pid" 2>/dev/null || fail "desktop process exited before close-to-menu-bar completed"
    sleep 0.05
  done
  [[ -f $ready ]] || fail "desktop lifecycle ready marker was not created"
  [[ $(cat "$ready") == hidden ]] || fail "desktop lifecycle ready marker is invalid"
  "$desktop" >"$output/desktop-secondary.log" 2>&1 || secondary_status=$?
  [[ $secondary_status -eq 0 ]] || fail "second desktop instance exited with $secondary_status"
  for _ in $(seq 1 600); do
    [[ -f $report ]] && break
    kill -0 "$primary_pid" 2>/dev/null || break
    sleep 0.05
  done
  wait "$primary_pid" || primary_status=$?
  [[ $primary_status -eq 0 && -f $report ]] || fail "primary desktop lifecycle did not finish cleanly"
  python3 - "$report" <<'PYLIFECYCLE'
import json, pathlib, sys
report=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["schema_version"] == 1
assert report["platform"] == "macos"
assert report["architecture"] == "aarch64"
assert report["native_shell_available"] is True
assert report["close_request_intercepted"] is True
assert report["restored_by_second_instance"] is True
assert report["single_instance_transport"] == "owner-private-unix-socket"
PYLIFECYCLE
  if pgrep -f "^$desktop$" >/dev/null 2>&1; then
    fail "desktop lifecycle left a process running"
  fi
}


prepare() {
  [[ -n $dmg && -n $sbom ]] || usage
  [[ $dmg == /* && $sbom == /* && -f $sbom ]] || fail "DMG and SBOM must be existing absolute files"
  [[ ! -e $state ]] || fail "acceptance output already contains state"
  local revision artifact_hash port quick_id endpoint had_preexisting_state=0
  revision=$(require_clean_revision)
  capture_macmcp "$macmcp_baseline"
  has_preexisting_runonmine_state && had_preexisting_state=1
  python3 "$repo_root/scripts/release/validate-clean-install-evidence.py" "$repo_root/acceptance/evidence/clean-install.template.json" >/dev/null
  cargo run --quiet --locked -p xtask --manifest-path "$repo_root/Cargo.toml" -- validate-sbom --path "$sbom" --target universal-apple-darwin
  install_dmg
  verify_bundle

  # Purge only state that existed before the clean-install attempt. A fresh CLI
  # intentionally refuses destructive purge without configuration because it
  # cannot enumerate unknown credential-store entries safely.
  if [[ $had_preexisting_state -eq 1 ]]; then
    "$cli" uninstall --purge --confirm PURGE >"$output/preexisting-purge.log" 2>&1 || {
      "$cli" uninstall >"$output/preexisting-uninstall.log" 2>&1 || true
      fail "pre-existing RunOnMine state could not be safely purged"
    }
  else
    printf '%s\n' 'No pre-existing RunOnMine managed state was present.' >"$output/preexisting-purge.log"
  fi
  run_desktop_acceptance
  run_desktop_lifecycle

  mkdir -p "$output/project"
  "$cli" setup --root "$output/project" >"$output/setup.log"
  "$cli" connect cloudflare quick >"$output/cloudflare-quick-create.log"
  quick_id=$("$cli" connect list | awk '$2 == "CloudflareQuick" {print $1; exit}')
  [[ -n $quick_id ]] || fail "Cloudflare Quick Tunnel connector ID was not found"
  "$cli" connect local-http enable --token-output "$output/local-http.json" >"$output/local-http-enable.log"
  chmod 600 "$output/local-http.json"
  endpoint=$(python3 - "$output/local-http.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["endpoint"])
PY
)
  port=$(python3 - "$endpoint" <<'PY'
from urllib.parse import urlsplit
import sys
print(urlsplit(sys.argv[1]).port)
PY
)
  "$cli" service install >"$output/service-install.log"
  "$cli" service status >"$output/service-status-before-reboot.log"
  wait_health "$port"
  wait_connector_ready "$port" "$quick_id"
  artifact_hash=$(sha256 "$dmg")
  python3 - "$state" "$revision" "$(boot_session)" "$(basename "$dmg")" "$artifact_hash" "$port" "$quick_id" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "source_revision": sys.argv[2],
    "boot_session_before": sys.argv[3],
    "artifact": sys.argv[4],
    "artifact_sha256": sys.argv[5],
    "port": int(sys.argv[6]),
    "quick_connector_id": sys.argv[7],
}, indent=2) + "\n")
PY
  chmod 600 "$state"
  printf 'macOS clean-install prepare stage passed. Reboot is required before verify.\n'
}

run_mcp_approval() {
  local endpoint client_pid approval_id="" client_status=0
  endpoint=$(python3 - "$output/local-http.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["endpoint"])
PY
)
  python3 "$repo_root/scripts/acceptance/mcp-http-smoke.py" \
    --url "$endpoint" --token-file "$output/local-http.json" \
    --approval-write-path "$output/project/approved-after-reboot.txt" \
    >"$output/mcp-client.log" 2>"$output/mcp-client.stderr" &
  client_pid=$!
  for _ in $(seq 1 6000); do
    approval_id=$("$cli" approvals list 2>/dev/null | sed -nE 's/^([0-9a-fA-F-]{36})  .*/\1/p' | head -n1)
    if [[ -n $approval_id ]]; then
      "$cli" approvals approve "$approval_id" --once >"$output/approval.log"
      break
    fi
    kill -0 "$client_pid" 2>/dev/null || break
    sleep 0.05
  done
  wait "$client_pid" || client_status=$?
  [[ $client_status -eq 0 && -n $approval_id ]] || fail "post-reboot MCP approval flow failed"
  grep -Fx 'approved MCP acceptance write' "$output/project/approved-after-reboot.txt" >/dev/null || fail "approved write result is missing"
}

remove_app() {
  [[ -d $app ]] || return 0
  rm -rf -- "$app"
}

write_evidence() {
  local tested_at
  tested_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  python3 - "$state" "$evidence" "$tested_at" <<'PY'
import json, pathlib, sys
state=json.loads(pathlib.Path(sys.argv[1]).read_text())
steps=[
 ("install", "DMG mounted read-only; RunOnMine.app copied to /Applications; bundle ID, four universal binaries, version and code-signature structure verified"),
 ("reboot", "macOS boot session UUID changed after the installed per-user LaunchAgent was configured"),
 ("agent_ready", "LaunchAgent remained loaded and loopback health returned ready after reboot"),
 ("mcp_initialize", "post-reboot Streamable HTTP client initialized an authenticated MCP session"),
 ("approved_tool_call", "owner-approved fs_write succeeded once; admin_exec remained denied by the MCP acceptance client"),
 ("connector", "Cloudflare Quick Tunnel reached ready before and after reboot without recording its secret public URL"),
 ("desktop_launch", "installed arm64 desktop launched from the application bundle in the active GUI session"),
 ("desktop_views", "all seven security-control views rendered in both arm64 and Rosetta x86_64 slices"),
 ("native_shell", "native menu-bar integration reported available and closing the main window kept the process alive"),
 ("single_instance", "a second installed desktop process exited and restored the hidden primary window"),
 ("native_slice_launch", "arm64 slice produced the validated seven-view acceptance report"),
 ("rosetta_slice_launch", "x86_64 slice launched under Rosetta and produced the validated seven-view acceptance report"),
 ("uninstall", "LaunchAgent was removed, managed credentials/data were purged, and RunOnMine.app was deleted"),
 ("residue_check", "no application bundle, LaunchAgent, RunOnMine process, loopback agent listener, or managed data directory remained; MacMCP invariants were unchanged"),
]
evidence={
 "schema_version":1,
 "platform":"macos-universal",
 "artifact":state["artifact"],
 "artifact_sha256":state["artifact_sha256"],
 "source_revision":state["source_revision"],
 "tester":"OpenAI automated acceptance on owner-authorized Apple Silicon Mac",
 "tested_at":sys.argv[3],
 "steps":[{"id":sid,"status":"passed","evidence":detail} for sid,detail in steps],
 "residues":[],
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(evidence, indent=2)+"\n")
PY
  python3 "$repo_root/scripts/release/validate-clean-install-evidence.py" "$evidence"
}

verify() {
  [[ -f $state ]] || fail "prepare-stage state is missing"
  verify_bundle
  local before revision port quick_id
  before=$(python3 - "$state" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["boot_session_before"])
PY
)
  [[ $(boot_session) != "$before" ]] || fail "Mac was not rebooted after prepare"
  revision=$(python3 - "$state" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["source_revision"])
PY
)
  [[ $(require_clean_revision) == "$revision" ]] || fail "repository revision changed after prepare"
  port=$(python3 - "$state" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["port"])
PY
)
  quick_id=$(python3 - "$state" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["quick_connector_id"])
PY
)
  verify_macmcp
  "$cli" service status >"$output/service-status-after-reboot.log"
  launchctl print "gui/$(id -u)/dev.runonmine.agent" >"$output/launchagent-after-reboot.log"
  wait_health "$port"
  wait_connector_ready "$port" "$quick_id"
  run_mcp_approval
  "$cli" lock >"$output/emergency-lock.log"
  for _ in $(seq 1 150); do
    if ! lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && fail "emergency lock left the agent listener active"
  "$cli" uninstall >"$output/uninstall-retain.log"
  [[ -e "$HOME/Library/Application Support/dev.RunOnMine.RunOnMine" ]] || fail "non-purge uninstall did not retain user data"
  "$cli" uninstall --purge --confirm PURGE >"$output/uninstall-purge.log"
  remove_app

  [[ ! -e $app ]] || fail "application bundle residue remains"
  [[ ! -e "$HOME/Library/LaunchAgents/dev.runonmine.agent.plist" ]] || fail "LaunchAgent plist residue remains"
  launchctl print "gui/$(id -u)/dev.runonmine.agent" >/dev/null 2>&1 && fail "LaunchAgent remains loaded"
  pgrep -f '/RunOnMine.app/Contents/MacOS/runonmine-(agent|desktop)' >/dev/null 2>&1 && fail "RunOnMine process residue remains"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && fail "RunOnMine loopback listener residue remains"
  for path in \
    "$HOME/Library/Application Support/dev.RunOnMine.RunOnMine" \
    "$HOME/Library/Preferences/dev.RunOnMine.RunOnMine" \
    "$HOME/Library/Logs/dev.RunOnMine.RunOnMine"; do
    [[ ! -e $path ]] || fail "managed data residue remains at $path"
  done
  verify_macmcp
  write_evidence
  printf 'RunOnMine macOS universal clean-install acceptance passed.\n'
}

case "$stage" in
  prepare) prepare ;;
  verify) verify ;;
  *) usage ;;
esac
