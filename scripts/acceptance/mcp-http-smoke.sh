#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cli=${RUNONMINE_BIN:-"$repo_root/target/debug/runonmine"}
agent=${RUNONMINE_AGENT_BIN:-"$repo_root/target/debug/runonmine-agent"}
client="$repo_root/scripts/acceptance/mcp-http-smoke.py"

if [ -z "${RUNONMINE_BIN:-}" ] || [ -z "${RUNONMINE_AGENT_BIN:-}" ]; then
  (cd "$repo_root" && cargo build --locked --no-default-features -p runonmine -p runonmine-agent)
elif [ ! -x "$cli" ] || [ ! -x "$agent" ]; then
  echo "explicit RunOnMine acceptance binary is missing or not executable" >&2
  exit 2
fi

sandbox=$(mktemp -d)
agent_pid=""
cleanup() {
  if [ -n "$agent_pid" ]; then
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
  fi
  rm -rf "$sandbox"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$sandbox/home" "$sandbox/project" "$sandbox/xdg-config" "$sandbox/xdg-state" "$sandbox/xdg-data"

run_env() {
  HOME="$sandbox/home" \
  USERPROFILE="$sandbox/home" \
  APPDATA="$sandbox/appdata" \
  LOCALAPPDATA="$sandbox/localappdata" \
  XDG_CONFIG_HOME="$sandbox/xdg-config" \
  XDG_STATE_HOME="$sandbox/xdg-state" \
  XDG_DATA_HOME="$sandbox/xdg-data" \
  RUNONMINE_TEST_FILE_SECRETS=1 \
  RUNONMINE_MASTER_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  "$@"
}

port=$(python3 - <<'PYPORT'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PYPORT
)
run_env "$cli" setup --root "$sandbox/project" >/dev/null
config=$(find "$sandbox" -name config.toml -type f -print -quit)
[ -n "$config" ]
python3 - "$config" "$port" <<'PYCONFIG'
from pathlib import Path
import re, sys
path=Path(sys.argv[1])
text=path.read_text()
updated,count=re.subn(r'(?m)^port = \d+$', f'port = {sys.argv[2]}', text, count=1)
if count != 1:
    raise SystemExit("config port was not found")
path.write_text(updated)
PYCONFIG
credential="$sandbox/local-http.json"
run_env "$cli" connect local-http enable --token-output "$credential" >/dev/null

run_env "$agent" run >"$sandbox/agent.log" 2>&1 &
agent_pid=$!
ready=0
for _ in $(seq 1 100); do
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$sandbox/agent.log" >&2
    exit 1
  fi
  if python3 - "$port" <<'PYHEALTH' >/dev/null 2>&1
import http.client,sys
c=http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=0.2)
c.request("GET", "/healthz", headers={"Host": f"127.0.0.1:{sys.argv[1]}"})
r=c.getresponse(); body=r.read(); c.close()
raise SystemExit(0 if r.status == 200 and body == b"ok" else 1)
PYHEALTH
  then
    ready=1
    break
  fi
  sleep 0.05
done
[ "$ready" -eq 1 ] || { cat "$sandbox/agent.log" >&2; exit 1; }

approved_path="$sandbox/project/approved.txt"
client_stdout="$sandbox/client.stdout"
client_stderr="$sandbox/client.stderr"
python3 "$client" --url "http://127.0.0.1:$port/mcp" \
  --token-file "$credential" \
  --iterations "${RUNONMINE_MCP_SOAK_ITERATIONS:-1}" \
  --approval-write-path "$approved_path" >"$client_stdout" 2>"$client_stderr" &
client_pid=$!
approval_id=""
for _ in $(seq 1 "${RUNONMINE_APPROVAL_POLL_ITERATIONS:-6000}"); do
  pending=$(run_env "$cli" approvals list 2>/dev/null || true)
  approval_id=$(printf '%s\n' "$pending" | sed -nE 's/^([0-9a-fA-F-]{36})  .*/\1/p' | head -n1)
  if [ -n "$approval_id" ]; then
    run_env "$cli" approvals approve "$approval_id" --once >/dev/null
    break
  fi
  if ! kill -0 "$client_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
client_status=0
wait "$client_pid" || client_status=$?
if [ "$client_status" -ne 0 ] || [ -z "$approval_id" ]; then
  cat "$client_stderr" >&2 || true
  echo "== agent log ==" >&2
  cat "$sandbox/agent.log" >&2
  echo "== connector list ==" >&2
  run_env "$cli" connect list >&2 || true
  echo "== doctor ==" >&2
  run_env "$cli" doctor --json >&2 || true
  exit 1
fi
cat "$client_stdout"
grep -Fx 'approved MCP acceptance write' "$approved_path" >/dev/null

kill "$agent_pid"
wait "$agent_pid" 2>/dev/null || [ "$?" -eq 143 ]
agent_pid=""
run_env "$cli" uninstall --purge --confirm PURGE >/dev/null

echo "RunOnMine MCP HTTP smoke test passed."
