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

case "$(uname -s)" in
  Darwin)
    owner_user="${RUNONMINE_ACCEPTANCE_OWNER_USER:-$(stat -f %Su /dev/console)}"
    attacker_user="${RUNONMINE_ACCEPTANCE_ATTACKER_USER:-}"
    if [[ -z "$attacker_user" ]]; then
      echo "RUNONMINE_ACCEPTANCE_ATTACKER_USER must name a real second macOS user" >&2
      exit 2
    fi
    owner_home=$(dscl . -read "/Users/$owner_user" NFSHomeDirectory | awk '{print $2}')
    export HOME=/var/root
    export CARGO_HOME="${CARGO_HOME:-$owner_home/.cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-$owner_home/.rustup}"
    export PATH="$CARGO_HOME/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    ;;
  Linux)
    repo_owner=$(stat -c %U "$repo_root")
    owner_user="${RUNONMINE_ACCEPTANCE_OWNER_USER:-$repo_owner}"
    attacker_user="${RUNONMINE_ACCEPTANCE_ATTACKER_USER:-nobody}"
    owner_home=$(getent passwd "$owner_user" | cut -d: -f6)
    [[ -n "$owner_home" && -d "$owner_home" ]] || {
      echo "unable to resolve a home directory for owner user $owner_user" >&2
      exit 2
    }
    export HOME=/root
    export CARGO_HOME="${CARGO_HOME:-$owner_home/.cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-$owner_home/.rustup}"
    export PATH="$CARGO_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ;;
  *)
    echo "helper Unix identity acceptance supports only macOS and Linux" >&2
    exit 2
    ;;
esac

export RUNONMINE_ACCEPTANCE_OWNER_USER="$owner_user"
export RUNONMINE_ACCEPTANCE_ATTACKER_USER="$attacker_user"
export CARGO_TARGET_DIR="$target"
cd "$repo_root"
cargo test --locked -p runonmine-platform   helper::unix::tests::real_peer_uid_and_socket_acl_reject_a_second_user   -- --ignored --exact --nocapture
echo "RunOnMine real Unix helper identity acceptance passed for owner=$owner_user attacker=$attacker_user."
