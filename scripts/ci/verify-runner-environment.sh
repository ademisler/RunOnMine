#!/usr/bin/env bash
set -euo pipefail

expected_user=${RUNONMINE_CI_USER:-runonmine-ci}
expected_home=${RUNONMINE_CI_HOME:-/home/runonmine-ci}
expected_cargo_home="$expected_home/.cargo"
expected_rustup_home="$expected_home/.rustup"

fail() {
  printf 'runner environment verification failed: %s\n' "$*" >&2
  exit 1
}

[ "$(id -un)" = "$expected_user" ] || fail "expected user $expected_user, got $(id -un)"
[ "${HOME:-}" = "$expected_home" ] || fail "HOME must be $expected_home"
[ "${USER:-}" = "$expected_user" ] || fail "USER must be $expected_user"
[ "${LOGNAME:-}" = "$expected_user" ] || fail "LOGNAME must be $expected_user"
[ "${CARGO_HOME:-}" = "$expected_cargo_home" ] || fail "CARGO_HOME must be $expected_cargo_home"
[ "${RUSTUP_HOME:-}" = "$expected_rustup_home" ] || fail "RUSTUP_HOME must be $expected_rustup_home"

case ":${PATH:-}:" in
  *::*|*:.:*) fail "PATH contains an empty or current-directory component" ;;
esac

IFS=':' read -r -a path_entries <<< "${PATH:-}"
for entry in "${path_entries[@]}"; do
  [[ "$entry" = /* ]] || fail "PATH contains a relative component: $entry"
  case "$entry" in
    /home/*)
      [[ "$entry" == "$expected_home"/* ]] || fail "PATH crosses into another home directory: $entry"
      ;;
  esac
done

if [ -n "${RUNNER_TEMP:-}" ]; then
  runner_root=$(dirname "$(dirname "$RUNNER_TEMP")")
  for captured in "$runner_root/.env" "$runner_root/.path"; do
    [ -e "$captured" ] || continue
    [ ! -L "$captured" ] || fail "$captured must not be a symlink"
    owner=$(stat -c '%U:%G' "$captured")
    [ "$owner" = "$expected_user:$expected_user" ] || fail "$captured owner is $owner"
    mode=$(stat -c '%a' "$captured")
    [ "$mode" = '600' ] || fail "$captured mode is $mode, expected 600"
    while IFS= read -r line; do
      case "$line" in
        *'/home/'*)
          sanitized=${line//"$expected_home"/}
          [[ "$sanitized" != *'/home/'* ]] || fail "$captured references another home directory"
          ;;
      esac
    done < "$captured"
  done
fi

printf 'Runner environment verified for %s.\n' "$expected_user"
