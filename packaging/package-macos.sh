#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# cargo-packager's CI mode invokes create-dmg with --skip-jenkins, avoiding
# Finder AppleScript automation prompts while preserving the application,
# Applications symlink, volume icon, EULA, compression, and signing paths.
CI=true
export CI

identity=${RUNONMINE_APPLE_SIGNING_IDENTITY:-}
if [ -z "$identity" ]; then
  exec cargo packager --config packaging/Packager.macos.toml
fi
case "$identity" in
  *[![:print:]]*|*\"*|*\\*) echo "invalid Apple signing identity" >&2; exit 2 ;;
esac
[ -n "${APPLE_CERTIFICATE:-}" ] || { echo "APPLE_CERTIFICATE is required for signed macOS packaging" >&2; exit 2; }
[ -n "${APPLE_CERTIFICATE_PASSWORD:-}" ] || { echo "APPLE_CERTIFICATE_PASSWORD is required for signed macOS packaging" >&2; exit 2; }
if [ -z "${APPLE_KEYCHAIN_PROFILE:-}" ]; then
  [ -n "${APPLE_API_KEY:-}" ] || { echo "APPLE_API_KEY is required unless APPLE_KEYCHAIN_PROFILE is configured" >&2; exit 2; }
  [ -n "${APPLE_API_ISSUER:-}" ] || { echo "APPLE_API_ISSUER is required unless APPLE_KEYCHAIN_PROFILE is configured" >&2; exit 2; }
  [ -n "${APPLE_API_KEY_PATH:-}" ] || { echo "APPLE_API_KEY_PATH is required unless APPLE_KEYCHAIN_PROFILE is configured" >&2; exit 2; }
  [ -f "$APPLE_API_KEY_PATH" ] || { echo "APPLE_API_KEY_PATH does not exist" >&2; exit 2; }
fi

temporary=packaging/.Packager.macos.signed.$$.json
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
python3 - "$identity" "$temporary" <<'PY2'
import json, pathlib, sys, tomllib
source=pathlib.Path('packaging/Packager.macos.toml')
config=tomllib.loads(source.read_text())
macos=config.setdefault('macos', {})
macos['signingIdentity']=sys.argv[1]
macos['entitlements']='entitlements.macos.plist'
pathlib.Path(sys.argv[2]).write_text(json.dumps(config, indent=2)+"\n")
PY2
cargo packager --config "$temporary"
app=$(find target/distrib dist -maxdepth 2 -type d -name 'RunOnMine.app' -print 2>/dev/null | head -n1)
dmg=$(find dist -maxdepth 1 -type f -name 'RunOnMine*.dmg' -print | head -n1)
[ -n "$app" ] && [ -n "$dmg" ] || { echo "signed app or DMG output is missing" >&2; exit 1; }
./scripts/release/verify-macos-distribution.sh "$app" "$dmg"
