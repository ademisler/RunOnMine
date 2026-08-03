#!/bin/bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <ubuntu-arm64-cloud-image> <headless-arm64.deb> <output-dir>" >&2
  exit 2
fi

base_image=$1
headless_deb=$2
output_dir=$3
repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
firmware=${RUNONMINE_ARM64_FIRMWARE:-/usr/share/qemu-efi-aarch64/QEMU_EFI.fd}

[[ $(id -u) -eq 0 ]] || { echo "ARM64 VM acceptance must run as root" >&2; exit 2; }
for path in "$base_image" "$headless_deb" "$output_dir" "$firmware"; do
  [[ $path = /* ]] || { echo "acceptance paths must be absolute" >&2; exit 2; }
done
for file in "$base_image" "$headless_deb" "$firmware"; do
  [[ -f $file && ! -L $file ]] || { echo "acceptance input is not a safe regular file: $file" >&2; exit 2; }
done
for command in qemu-img qemu-system-aarch64 cloud-localds ssh scp ssh-keygen dpkg-deb python3; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 2; }
done
[[ $(qemu-img info --output=json "$base_image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])') == qcow2 ]] \
  || { echo "Ubuntu cloud image must be qcow2" >&2; exit 2; }
[[ $(dpkg-deb --field "$headless_deb" Architecture) == arm64 ]] \
  || { echo "headless DEB is not arm64" >&2; exit 2; }

repo_owner=$(stat -c %U "$repo_root")
source_revision=$(runuser -u "$repo_owner" -- git -C "$repo_root" rev-parse HEAD)
formal=true
if ! runuser -u "$repo_owner" -- git -C "$repo_root" diff --quiet \
  || ! runuser -u "$repo_owner" -- git -C "$repo_root" diff --cached --quiet \
  || [[ -n $(runuser -u "$repo_owner" -- git -C "$repo_root" ls-files --others --exclude-standard) ]]; then
  formal=false
  [[ ${RUNONMINE_ACCEPTANCE_ALLOW_DIRTY:-0} == 1 ]] || {
    echo "formal clean-install evidence requires a clean committed worktree" >&2
    exit 2
  }
fi

stamp=$(date -u +%Y%m%d%H%M%S)
name="rom-arm64-${stamp}-$$"
run_root="/var/lib/runonmine-acceptance/runs/$name"
disk="$run_root/disk.qcow2"
seed="$run_root/seed.img"
serial="$run_root/serial.log"
private_key="$run_root/id_ed25519"
pid_file="$run_root/qemu.pid"
install -d -m 0700 "$run_root"
install -d -m 0755 "$output_dir"

acceptance_status=1
ssh_port=0
cleanup() {
  local pid=""
  [[ -f $pid_file ]] && pid=$(cat "$pid_file" 2>/dev/null || true)
  if [[ -n $pid && -f $private_key && $ssh_port -gt 0 ]]; then
    ssh -i "$private_key" -p "$ssh_port" -o BatchMode=yes -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 romtest@127.0.0.1 \
      'sudo poweroff' >/dev/null 2>&1 || true
    for _ in $(seq 1 180); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if [[ ${RUNONMINE_ACCEPTANCE_KEEP_FAILED:-0} == 1 && $acceptance_status -ne 0 ]]; then
    echo "preserved failed ARM64 VM acceptance directory: $run_root" >&2
    return
  fi
  rm -rf --one-file-system "$run_root"
}
trap cleanup EXIT HUP INT TERM

ssh_port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)
ssh-keygen -q -t ed25519 -N '' -f "$private_key"
public_key=$(cat "$private_key.pub")
cat >"$run_root/user-data" <<EOF_USER
#cloud-config
hostname: $name
manage_etc_hosts: true
users:
  - name: romtest
    gecos: RunOnMine ARM64 Acceptance
    groups: [adm, sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
package_update: false
runcmd:
  - [ sh, -c, 'echo ready > /var/lib/cloud/runonmine-ready' ]
EOF_USER
cat >"$run_root/meta-data" <<EOF_META
instance-id: $name
local-hostname: $name
EOF_META
cloud-localds "$seed" "$run_root/user-data" "$run_root/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$disk" 20G

qemu-system-aarch64 \
  -machine virt -accel "tcg,thread=multi" -cpu cortex-a72 -smp 4 -m 4096 \
  -bios "$firmware" \
  -drive "file=$disk,if=virtio,format=qcow2,cache=writeback" \
  -drive "file=$seed,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none -monitor none -serial "file:$serial" \
  >"$run_root/qemu.stdout" 2>"$run_root/qemu.stderr" &
qemu_pid=$!
echo "$qemu_pid" >"$pid_file"

ssh_options=(
  -i "$private_key" -p "$ssh_port" -o BatchMode=yes
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  -o ServerAliveInterval=5 -o ServerAliveCountMax=12
)
scp_options=(
  -i "$private_key" -P "$ssh_port" -o BatchMode=yes
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
)

wait_ssh() {
  for _ in $(seq 1 1800); do
    if ssh "${ssh_options[@]}" -o ConnectTimeout=2 romtest@127.0.0.1 true >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$qemu_pid" 2>/dev/null || {
      cat "$run_root/qemu.stderr" >&2 || true
      tail -n 160 "$serial" >&2 || true
      return 1
    }
    sleep 0.5
  done
  echo "ARM64 VM SSH did not become ready" >&2
  tail -n 160 "$serial" >&2 || true
  return 1
}

wait_cloud_init() {
  for _ in $(seq 1 1200); do
    status=$(ssh "${ssh_options[@]}" romtest@127.0.0.1 'cloud-init status 2>/dev/null || true' || true)
    if [[ $status == *'status: done'* ]] \
      && ssh "${ssh_options[@]}" romtest@127.0.0.1 \
        'test -f /var/lib/cloud/runonmine-ready' >/dev/null 2>&1; then
      return 0
    fi
    [[ $status != *'status: error'* ]] || { echo "$status" >&2; return 1; }
    sleep 0.5
  done
  echo "ARM64 cloud-init did not finish" >&2
  return 1
}

reboot_vm() {
  local before after saw_disconnect=false
  before=$(ssh "${ssh_options[@]}" romtest@127.0.0.1 cat /proc/sys/kernel/random/boot_id)
  ssh "${ssh_options[@]}" romtest@127.0.0.1 'sudo reboot' >/dev/null 2>&1 || true
  for _ in $(seq 1 1800); do
    if ! ssh "${ssh_options[@]}" -o ConnectTimeout=2 romtest@127.0.0.1 true >/dev/null 2>&1; then
      saw_disconnect=true
    elif [[ $saw_disconnect == true ]]; then
      after=$(ssh "${ssh_options[@]}" romtest@127.0.0.1 cat /proc/sys/kernel/random/boot_id)
      if [[ -n $after && $after != "$before" ]]; then
        return 0
      fi
    fi
    kill -0 "$qemu_pid" 2>/dev/null || { echo "ARM64 VM exited during reboot" >&2; return 1; }
    sleep 0.5
  done
  echo "ARM64 VM did not complete a verified reboot" >&2
  return 1
}

wait_ssh
wait_cloud_init
scp "${scp_options[@]}" \
  "$headless_deb" \
  "$repo_root/scripts/acceptance/linux-clean-install-guest.sh" \
  "$repo_root/scripts/acceptance/mcp-http-smoke.py" \
  romtest@127.0.0.1:/tmp/
headless_name=$(basename "$headless_deb")
ssh "${ssh_options[@]}" romtest@127.0.0.1 bash -s -- "$headless_name" <<'REMOTE_INSTALL'
set -euo pipefail
sudo install -d -m 0755 /opt/runonmine-acceptance
sudo install -m 0644 "/tmp/$1" /opt/runonmine-acceptance/headless.deb
sudo install -m 0755 /tmp/linux-clean-install-guest.sh /opt/runonmine-acceptance/linux-clean-install-guest.sh
sudo install -m 0644 /tmp/mcp-http-smoke.py /opt/runonmine-acceptance/mcp-http-smoke.py
REMOTE_INSTALL

ssh "${ssh_options[@]}" romtest@127.0.0.1 \
  'sudo env RUNONMINE_ACCEPTANCE_HEADLESS_ONLY=1 /opt/runonmine-acceptance/linux-clean-install-guest.sh stage1' \
  | tee "$output_dir/linux-arm64-vm-stage1.txt"
reboot_vm
ssh "${ssh_options[@]}" romtest@127.0.0.1 \
  'sudo env RUNONMINE_ACCEPTANCE_HEADLESS_ONLY=1 /opt/runonmine-acceptance/linux-clean-install-guest.sh stage2' \
  | tee "$output_dir/linux-arm64-vm-stage2.txt"

for remote in result.json mcp.stdout; do
  scp "${scp_options[@]}" "romtest@127.0.0.1:/opt/runonmine-acceptance/$remote" \
    "$output_dir/linux-arm64-${remote}"
done

python3 - "$output_dir" "$headless_deb" "$source_revision" "$formal" <<'PY'
import datetime, hashlib, json, pathlib, sys
output = pathlib.Path(sys.argv[1])
artifact = pathlib.Path(sys.argv[2])
revision = sys.argv[3]
formal = sys.argv[4] == 'true'
result = json.loads((output / 'linux-arm64-result.json').read_text())
if result.get('status') != 'passed' or not all(result.get('checks', {}).values()):
    raise SystemExit('ARM64 VM acceptance result is incomplete')
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
summary = {
    'schema_version': 1,
    'report_type': 'clean_install_acceptance' if formal else 'development_clean_install_acceptance',
    'source_revision': revision,
    'tested_at': now,
    'environment': 'Ubuntu 24.04 ARM64 full QEMU VM',
    'artifact': {'name': artifact.name, 'sha256': digest},
    'checks': result['checks'],
}
(output / 'linux-arm64-clean-install-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
if not formal:
    raise SystemExit(0)
steps = [
    {'id': 'install', 'status': 'passed', 'evidence': 'linux-arm64-result.json: clean install and beta.0 to beta.1 upgrade'},
    {'id': 'reboot', 'status': 'passed', 'evidence': 'linux-arm64-vm-stage2.txt: distinct ARM64 VM boot IDs'},
    {'id': 'agent_ready', 'status': 'passed', 'evidence': 'linux-arm64-result.json: user and system services recovered'},
    {'id': 'mcp_initialize', 'status': 'passed', 'evidence': 'linux-arm64-mcp.stdout: Streamable HTTP initialize and tools/list'},
    {'id': 'approved_tool_call', 'status': 'passed', 'evidence': 'linux-arm64-mcp.stdout: locally approved fs_write'},
    {'id': 'connector', 'status': 'passed', 'evidence': 'linux-arm64-result.json: managed ARM64 Cloudflare Quick runtime discovered'},
    {'id': 'denied_admin_call', 'status': 'passed', 'evidence': 'linux-arm64-mcp.stdout: direct admin_exec denied'},
    {'id': 'emergency_lock', 'status': 'passed', 'evidence': 'linux-arm64-result.json: stop, runtime cleanup and stale-token rejection'},
    {'id': 'uninstall', 'status': 'passed', 'evidence': 'linux-arm64-result.json: package and service removal'},
    {'id': 'residue_check', 'status': 'passed', 'evidence': 'linux-arm64-result.json: no unexpected RunOnMine residue'},
]
evidence = {
    'schema_version': 1,
    'platform': 'linux-aarch64',
    'artifact': artifact.name,
    'artifact_sha256': digest,
    'source_revision': revision,
    'tester': 'Oty QEMU Ubuntu 24.04 ARM64 acceptance',
    'tested_at': now,
    'steps': steps,
    'residues': [],
}
(output / 'linux-aarch64-clean-install.json').write_text(json.dumps(evidence, indent=2) + '\n')
PY

if [[ $formal == true ]]; then
  python3 "$repo_root/scripts/release/validate-clean-install-evidence.py" \
    "$output_dir/linux-aarch64-clean-install.json"
fi

acceptance_status=0
echo "RunOnMine Linux ARM64 QEMU clean-install acceptance passed."
