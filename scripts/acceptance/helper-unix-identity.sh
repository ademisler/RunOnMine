#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" != 0 ]]; then
  echo "helper Unix identity acceptance requires root" >&2
  exit 2
fi
repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
target=$(mktemp -d /tmp/runonmine-helper-identity.XXXXXX)
cleanup() { rm -rf -- "$target"; }
trap cleanup EXIT HUP INT TERM
export HOME=/root
export CARGO_HOME=/home/github1-dev/.cargo
export RUSTUP_HOME=/home/github1-dev/.rustup
export PATH=/home/github1-dev/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_TARGET_DIR="$target"
cd "$repo_root"
cargo test --locked -p runonmine-platform \
  helper::unix::tests::real_peer_uid_and_socket_acl_reject_a_second_user \
  -- --ignored --exact --nocapture
echo "RunOnMine real Unix helper identity acceptance passed."
