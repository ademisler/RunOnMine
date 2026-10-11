#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 || $1 != stage1 && $1 != stage2 && $1 != stage3 ]]; then
  echo "usage: $0 <stage1|stage2|stage3>" >&2
  exit 2
fi

stage=$1
work=/opt/runonmine-acceptance
headless_only=${RUNONMINE_ACCEPTANCE_HEADLESS_ONLY:-0}
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
[[ $headless_only == 0 || $headless_only == 1 ]] || {
  echo "RUNONMINE_ACCEPTANCE_HEADLESS_ONLY must be 0 or 1" >&2
  exit 2
}
user_account=romuser
system_account=romsystem
user_port=48921
system_port=48922
user_project=/srv/runonmine-user-project
system_project=/srv/runonmine-system-project
user_key_file="$work/user-master-key"
system_key_file="$work/system-master-key"

require_file() {
  [[ -f $1 ]] || { echo "required acceptance file is missing: $(basename "$1")" >&2; exit 2; }
}

account_uid() {
  id -u "$1"
}

user_runtime() {
  printf '/run/user/%s' "$(account_uid "$1")"
}

user_cli() {
  local key runtime uid
  key=$(<"$user_key_file")
  uid=$(account_uid "$user_account")
  runtime=$(user_runtime "$user_account")
  runuser -u "$user_account" -- env \
    HOME="/home/$user_account" USER="$user_account" LOGNAME="$user_account" \
    XDG_CONFIG_HOME="/home/$user_account/.config" \
    XDG_STATE_HOME="/home/$user_account/.local/state" \
    XDG_DATA_HOME="/home/$user_account/.local/share" \
    XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
    RUNONMINE_MASTER_KEY="$key" \
    "$@"
}

system_cli() {
  local key
  key=$(<"$system_key_file")
  runuser -u "$system_account" -- env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR \
    HOME="/home/$system_account" USER="$system_account" LOGNAME="$system_account" \
    XDG_CONFIG_HOME="/home/$system_account/.config" \
    XDG_STATE_HOME="/home/$system_account/.local/state" \
    XDG_DATA_HOME="/home/$system_account/.local/share" \
    RUNONMINE_MASTER_KEY="$key" \
    "$@"
}

user_systemctl() {
  local runtime uid
  uid=$(account_uid "$user_account")
  runtime=$(user_runtime "$user_account")
  runuser -u "$user_account" -- env \
    HOME="/home/$user_account" USER="$user_account" LOGNAME="$user_account" \
    XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
    systemctl --user "$@"
}

wait_user_manager() {
  local account=$1 uid runtime
  uid=$(account_uid "$account")
  runtime=$(user_runtime "$account")
  loginctl enable-linger "$account"
  systemctl start "user@$uid.service"
  for _ in $(seq 1 120); do
    [[ -S $runtime/bus ]] && return 0
    sleep 0.1
  done
  echo "systemd user manager did not create a session bus" >&2
  return 1
}

find_config() {
  local home=$1
  find "$home/.config" -type f -name config.toml -print -quit
}

set_config_port() {
  local home=$1 port=$2 config
  config=$(find_config "$home")
  [[ -n $config ]] || { echo "RunOnMine config was not created" >&2; return 1; }
  python3 - "$config" "$port" <<'PY'
from pathlib import Path
import re, sys
path = Path(sys.argv[1])
updated, count = re.subn(r'(?m)^port = \d+$', f'port = {sys.argv[2]}', path.read_text(), count=1)
if count != 1:
    raise SystemExit('config port was not found')
path.write_text(updated)
PY
}

wait_health() {
  local port=$1
  python3 - "$port" <<'PY'
import http.client, sys, time
port = int(sys.argv[1])
for _ in range(300):
    try:
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=0.3)
        connection.request('GET', '/healthz', headers={'Host': f'127.0.0.1:{port}'})
        response = connection.getresponse()
        body = response.read()
        connection.close()
        if response.status == 200 and body == b'ok':
            raise SystemExit(0)
    except OSError:
        pass
    time.sleep(0.1)
raise SystemExit('agent health endpoint did not become ready')
PY
}

wait_quick_runtime() {
  local status=0
  python3 - "/home/$user_account" <<'PY' || status=$?
import json, pathlib, sys, time
home = pathlib.Path(sys.argv[1])
for _ in range(6000):
    candidates = list(home.glob('.local/**/quick-tunnel-runtime/*'))
    for path in candidates:
        if path.name == '.lock' or not path.is_file():
            continue
        try:
            record = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        url = record.get('public_url')
        if isinstance(url, str) and url.startswith('https://') and 'trycloudflare.com' in url:
            raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit('Cloudflare Quick Tunnel did not publish runtime state within 600 seconds')
PY
  if [[ $status -ne 0 ]]; then
    user_cli runonmine doctor --json >&2 || true
  fi
  return $status
}

assert_no_quick_runtime() {
  python3 - "/home/$user_account" <<'PY'
import json, pathlib, sys
home = pathlib.Path(sys.argv[1])
for path in home.glob('.local/**/quick-tunnel-runtime/*'):
    if path.name == '.lock' or not path.is_file():
        continue
    try:
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        continue
    if record.get('public_url'):
        raise SystemExit('Quick Tunnel runtime URL remained after emergency lock')
PY
}

stale_token_is_rejected() {
  local port=$1 token_file=$2
  python3 - "$port" "$token_file" <<'PY'
import http.client, json, pathlib, sys
port = int(sys.argv[1])
token = json.loads(pathlib.Path(sys.argv[2]).read_text())['bearer_token']
payload = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"stale-token-check","version":"1"}}}'
connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
connection.request('POST', '/mcp', body=payload, headers={
    'Authorization': f'Bearer {token}',
    'Accept': 'application/json, text/event-stream',
    'Content-Type': 'application/json',
    'Host': f'127.0.0.1:{port}',
})
response = connection.getresponse()
response.read()
connection.close()
if response.status != 401:
    raise SystemExit(f'stale token returned HTTP {response.status}, expected 401')
PY
}

run_mcp_acceptance() {
  local token_file="/home/$user_account/local-http.json"
  local approved_path="$user_project/approved.txt"
  local stdout="$work/mcp.stdout"
  local stderr="$work/mcp.stderr"
  rm -f "$stdout" "$stderr" "$approved_path"
  runuser -u "$user_account" -- python3 "$work/mcp-http-smoke.py" \
    --url "http://127.0.0.1:$user_port/mcp" \
    --token-file "$token_file" \
    --approval-write-path "$approved_path" >"$stdout" 2>"$stderr" &
  local client_pid=$! approval_id=""
  for _ in $(seq 1 1200); do
    local pending
    pending=$(user_cli runonmine approvals list 2>/dev/null || true)
    approval_id=$(printf '%s\n' "$pending" | sed -nE 's/^([0-9a-fA-F-]{36})  .*/\1/p' | head -n1)
    if [[ -n $approval_id ]]; then
      user_cli runonmine approvals approve "$approval_id" --once >/dev/null
      break
    fi
    kill -0 "$client_pid" 2>/dev/null || break
    sleep 0.05
  done
  local status=0
  wait "$client_pid" || status=$?
  if [[ $status -ne 0 || -z $approval_id ]]; then
    cat "$stderr" >&2 || true
    return 1
  fi
  python3 - "$stdout" <<'PY'
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert result['status'] == 'passed'
assert result['approved_write'] is True
assert result['denied_admin_call'] is True
assert result['safe_tool_call'] == 'machine_info'
PY
  grep -Fx 'approved MCP acceptance write' "$approved_path" >/dev/null
}

make_previous_deb() {
  local current=$1 output=$2 expected_package=$3
  local directory
  directory=$(mktemp -d)
  dpkg-deb --raw-extract "$current" "$directory/root"
  grep -Fx "Package: $expected_package" "$directory/root/DEBIAN/control" >/dev/null
  sed -i 's/^Version: .*/Version: 0.1.0-beta.0/' "$directory/root/DEBIAN/control"
  dpkg-deb --root-owner-group -Zgzip -z1 --build "$directory/root" "$output" >/dev/null
  rm -rf "$directory"
  dpkg-deb --field "$output" Version | grep -Fx '0.1.0-beta.0' >/dev/null
}

package_version_is() {
  local package=$1 expected=$2
  dpkg-query -W -f='${Version}\n' "$package" | grep -Fx "$expected" >/dev/null
}

package_is_installed() {
  local package=$1
  dpkg-query -W -f='${db:Status-Abbrev}\n' "$package" 2>/dev/null | grep -Fx 'ii ' >/dev/null
}

cleanup_user_manager() {
  local account=$1 uid
  uid=$(account_uid "$account")
  loginctl disable-linger "$account" >/dev/null 2>&1 || true
  systemctl stop "user@$uid.service" >/dev/null 2>&1 || true
}

stage1() {
  rm -f /etc/apt/apt.conf.d/50command-not-found /etc/apt/apt.conf.d/50appstream
  require_file "$work/headless.deb"
  require_file "$work/mcp-http-smoke.py"
  if [[ $headless_only == 0 ]]; then
    require_file "$work/cloudflared"
    require_file "$work/desktop.deb"
    require_file "$work/desktop-parity-smoke.sh"
  fi
  explicit_cloudflared=false
  if [[ -f $work/cloudflared ]]; then
    install -m 0755 "$work/cloudflared" /usr/local/bin/cloudflared-acceptance
    explicit_cloudflared=true
  fi
  if [[ ! -f $user_key_file ]]; then
    umask 077
    openssl rand -hex 32 >"$user_key_file"
    openssl rand -hex 32 >"$system_key_file"
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update >/dev/null

  useradd --create-home --shell /bin/bash "$user_account"
  useradd --create-home --shell /bin/bash "$system_account"
  install -d -m 0700 -o "$user_account" -g "$user_account" "$user_project"
  install -d -m 0700 -o "$system_account" -g "$system_account" "$system_project"

  make_previous_deb "$work/headless.deb" "$work/headless-beta0.deb" runonmine
  apt-get install --yes --no-install-recommends "$work/headless-beta0.deb" >/dev/null
  package_version_is runonmine 0.1.0-beta.0
  for binary in runonmine runonmine-agent runonmine-helper; do
    test -x "/usr/bin/$binary"
  done

  wait_user_manager "$user_account"
  user_cli runonmine setup --root "$user_project" >/dev/null
  set_config_port "/home/$user_account" "$user_port"
  user_cli runonmine connect local-http enable \
    --token-output "/home/$user_account/local-http.json" >/dev/null
  config_before=$(sha256sum "$(find_config "/home/$user_account")" | awk '{print $1}')
  state_before=$(sha256sum "/home/$user_account/.local/state/runonmine/state.db" | awk '{print $1}')
  apt-get install --yes --no-install-recommends "$work/headless.deb" >/dev/null
  package_version_is runonmine 0.1.0-beta.1
  test "$config_before" = "$(sha256sum "$(find_config "/home/$user_account")" | awk '{print $1}')"
  test "$state_before" = "$(sha256sum "/home/$user_account/.local/state/runonmine/state.db" | awk '{print $1}')"
  user_cli runonmine connect local-http status --json >/dev/null
  if [[ $explicit_cloudflared == true ]]; then
    user_cli runonmine connect cloudflare quick \
      --cloudflared /usr/local/bin/cloudflared-acceptance >/dev/null
    user_cli runonmine connect pin-external-binaries >/dev/null
  else
    user_cli runonmine connect cloudflare quick >/dev/null
  fi
  user_cli runonmine service install >/dev/null
  wait_health "$user_port"
  wait_quick_runtime
  user_systemctl is-enabled runonmine-agent.service >/dev/null
  user_systemctl is-active runonmine-agent.service >/dev/null
  grep -F 'LoadCredential=' "/home/$user_account/.config/systemd/user/runonmine-agent.service" >/dev/null
  credential=$(find "/home/$user_account/.local/share" -path '*/service-credentials/runonmine-master-key' -print -quit)
  test -n "$credential"
  test "$(stat -c '%a' "$credential")" = 600

  system_cli runonmine setup --root "$system_project" >/dev/null
  set_config_port "/home/$system_account" "$system_port"
  system_cli runonmine connect local-http enable \
    --token-output "/home/$system_account/local-http.json" >/dev/null
  install -d -m 0700 /etc/runonmine
  install -m 0600 "$system_key_file" /etc/runonmine/master-key
  runonmine service install --system --user "$system_account" >/dev/null
  systemctl is-enabled runonmine-agent.service >/dev/null
  systemctl is-active runonmine-agent.service >/dev/null
  wait_health "$system_port"

  python3 - "$work/stage1.json" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    'schema_version': 1,
    'install': True,
    'headless_in_place_upgrade': True,
    'user_service': True,
    'system_service': True,
    'quick_tunnel': True,
}, indent=2) + '\n')
PY
  echo 'Linux clean-install stage 1 passed.'
}

stage2() {
  require_file "$work/stage1.json"
  wait_user_manager "$user_account"
  user_systemctl is-enabled runonmine-agent.service >/dev/null
  for _ in $(seq 1 300); do
    user_systemctl is-active runonmine-agent.service >/dev/null 2>&1 && break
    sleep 0.1
  done
  user_systemctl is-active runonmine-agent.service >/dev/null
  systemctl is-active runonmine-agent.service >/dev/null
  wait_health "$user_port"
  wait_health "$system_port"
  wait_quick_runtime
  run_mcp_acceptance

  user_cli runonmine lock >"$work/lock.out"
  grep -F 'RunOnMine is locked.' "$work/lock.out" >/dev/null
  if user_systemctl is-active runonmine-agent.service >/dev/null 2>&1; then
    echo 'user service remained active after emergency lock' >&2
    exit 1
  fi
  assert_no_quick_runtime
  user_cli runonmine service start >/dev/null
  wait_health "$user_port"
  stale_token_is_rejected "$user_port" "/home/$user_account/local-http.json"
  user_cli runonmine service stop >/dev/null

  user_cli runonmine uninstall --purge --confirm PURGE >/dev/null
  runonmine service uninstall --system >/dev/null
  systemctl is-active runonmine-agent.service >/dev/null 2>&1 && {
    echo 'system service remained active after uninstall' >&2
    exit 1
  }

  wait_user_manager "$system_account"
  key=$(<"$system_key_file")
  runtime=$(user_runtime "$system_account")
  runuser -u "$system_account" -- env \
    HOME="/home/$system_account" USER="$system_account" LOGNAME="$system_account" \
    XDG_CONFIG_HOME="/home/$system_account/.config" \
    XDG_STATE_HOME="/home/$system_account/.local/state" \
    XDG_DATA_HOME="/home/$system_account/.local/share" \
    XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
    RUNONMINE_MASTER_KEY="$key" \
    runonmine uninstall --purge --confirm PURGE >/dev/null

  if [[ $headless_only == 1 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get remove --yes runonmine >/dev/null
    for path in /usr/bin/runonmine /usr/bin/runonmine-agent /usr/bin/runonmine-helper \
      /etc/systemd/system/runonmine-agent.service \
      /usr/local/libexec/runonmine/runonmine-agent; do
      test ! -e "$path"
    done
    pgrep -f '[c]loudflared.*tunnel' >/dev/null && {
      echo 'Cloudflare child remained after uninstall' >&2
      exit 1
    }
    cleanup_user_manager "$user_account"
    cleanup_user_manager "$system_account"
    userdel --remove "$user_account" >/dev/null 2>&1 || true
    userdel --remove "$system_account" >/dev/null 2>&1 || true
    rm -rf "$user_project" "$system_project" /etc/runonmine /usr/local/bin/cloudflared-acceptance
    python3 - "$work/result.json" <<'PYHEADLESS'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    'schema_version': 1,
    'status': 'passed',
    'checks': {
        'install': True,
        'headless_reboot': True,
        'user_service_recovery': True,
        'system_service_recovery': True,
        'mcp_initialize': True,
        'approved_tool_call': True,
        'denied_admin_call': True,
        'quick_tunnel': True,
        'emergency_lock': True,
        'stale_token_rejected': True,
        'uninstall': True,
        'residue_check': True,
    },
}, indent=2) + '\n')
PYHEADLESS
    echo 'Linux headless clean-install stage 2 passed.'
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  python3 - <<'PYREPO'
from pathlib import Path
legacy = Path("/etc/apt/sources.list")
if legacy.is_file():
    lines = []
    for line in legacy.read_text().splitlines():
        if line.startswith("deb ") and " noble " in line:
            fields = line.split()
            if "main" in fields[3:] and "universe" not in fields[3:]:
                fields.append("universe")
                line = " ".join(fields)
        lines.append(line)
    legacy.write_text("\n".join(lines) + "\n")
for path in Path("/etc/apt/sources.list.d").glob("*.sources"):
    lines = []
    for line in path.read_text().splitlines():
        if line.startswith("Components:"):
            components = line.split()[1:]
            if "main" in components and "universe" not in components:
                components.append("universe")
                line = "Components: " + " ".join(components)
        lines.append(line)
    path.write_text("\n".join(lines) + "\n")
PYREPO
  apt-get update >/dev/null
  make_previous_deb "$work/desktop.deb" "$work/desktop-beta0.deb" runonmine-desktop
  apt-get install --yes --no-install-recommends "$work/desktop-beta0.deb" \
    dbus-x11 xvfb wmctrl xdotool libglib2.0-bin >/dev/null
  package_version_is runonmine-desktop 0.1.0-beta.0
  if package_is_installed runonmine; then
    echo 'headless and desktop packages remained installed together' >&2
    exit 1
  fi
  apt-get install --yes --no-install-recommends "$work/desktop.deb" >/dev/null
  package_version_is runonmine-desktop 0.1.0-beta.1
  python3 - "$work/stage2.json" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    'schema_version': 1,
    'headless_reboot': True,
    'mcp': True,
    'emergency_lock': True,
    'desktop_installed': True,
    'desktop_in_place_upgrade': True,
}, indent=2) + '\n')
PY
  echo 'Linux clean-install stage 2 passed.'
}

stage3() {
  [[ $headless_only == 0 ]] || { echo "stage3 is unavailable in headless-only mode" >&2; exit 2; }
  require_file "$work/stage2.json"
  dpkg-query -W -f='${Status}\n' runonmine-desktop | grep -Fx 'install ok installed' >/dev/null
  if package_is_installed runonmine; then
    echo 'headless package returned after desktop reboot' >&2
    exit 1
  fi
  test -x /usr/bin/runonmine-desktop
  test -f /usr/share/applications/runonmine-desktop.desktop
  "$work/desktop-parity-smoke.sh" /usr/bin/runonmine-desktop >"$work/desktop-parity.out"

  apt-get install --yes --no-install-recommends "$work/headless.deb" >/dev/null
  dpkg-query -W -f='${Status}\n' runonmine | grep -Fx 'install ok installed' >/dev/null
  if package_is_installed runonmine-desktop; then
    echo 'desktop package remained after headless replacement' >&2
    exit 1
  fi
  apt-get remove --yes runonmine >/dev/null

  for path in /usr/bin/runonmine /usr/bin/runonmine-agent /usr/bin/runonmine-helper \
    /usr/bin/runonmine-desktop /usr/share/applications/runonmine-desktop.desktop \
    /etc/systemd/system/runonmine-agent.service \
    /usr/local/libexec/runonmine/runonmine-agent; do
    test ! -e "$path"
  done
  pgrep -f '[c]loudflared.*tunnel' >/dev/null && {
    echo 'Cloudflare child remained after uninstall' >&2
    exit 1
  }

  cleanup_user_manager "$user_account"
  cleanup_user_manager "$system_account"
  userdel --remove "$user_account" >/dev/null 2>&1 || true
  userdel --remove "$system_account" >/dev/null 2>&1 || true
  rm -rf "$user_project" "$system_project" /etc/runonmine /usr/local/bin/cloudflared-acceptance

  python3 - "$work/result.json" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    'schema_version': 1,
    'status': 'passed',
    'checks': {
        'install': True,
        'headless_in_place_upgrade': True,
        'desktop_in_place_upgrade': True,
        'headless_reboot': True,
        'desktop_reboot': True,
        'user_service_recovery': True,
        'system_service_recovery': True,
        'mcp_initialize': True,
        'approved_tool_call': True,
        'denied_admin_call': True,
        'quick_tunnel': True,
        'emergency_lock': True,
        'stale_token_rejected': True,
        'desktop_views': True,
        'package_replacement': True,
        'uninstall': True,
        'residue_check': True,
    },
}, indent=2) + '\n')
PY
  echo 'Linux clean-install stage 3 passed.'
}

case "$stage" in
  stage1) stage1 ;;
  stage2) stage2 ;;
  stage3) stage3 ;;
esac
