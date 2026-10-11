#!/usr/bin/env bash
set -euo pipefail
version=8.24.3
archive="gitleaks_${version}_linux_x64.tar.gz"
expected=9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c
if command -v gitleaks >/dev/null 2>&1 && [[ $(gitleaks version) == "$version" ]]; then
  exit 0
fi
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo "the pinned Gitleaks bootstrap supports only hosted Linux x86_64" >&2
  exit 2
}
temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
curl --fail --location --silent --show-error \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}" \
  --output "$temporary/$archive"
printf '%s  %s\n' "$expected" "$temporary/$archive" | sha256sum --check --status
mkdir -p "$HOME/.local/bin"
tar -xzf "$temporary/$archive" -C "$temporary" gitleaks
install -m 0755 "$temporary/gitleaks" "$HOME/.local/bin/gitleaks"
if [[ -n ${GITHUB_PATH:-} ]]; then
  printf '%s\n' "$HOME/.local/bin" >> "$GITHUB_PATH"
fi
"$HOME/.local/bin/gitleaks" version | grep -Fx "$version"
