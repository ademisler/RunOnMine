#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# cargo-packager's CI mode invokes create-dmg with --skip-jenkins, avoiding
# Finder AppleScript automation prompts while preserving the application,
# Applications symlink, volume icon, EULA, compression, and signing paths.
CI=true
export CI

identity=${RUNONMINE_APPLE_SIGNING_IDENTITY:-}
mode=private-beta
signing_identity=-
if [ -n "$identity" ]; then
  mode=public
  signing_identity=$identity
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
fi

# cargo-packager treats the presence of Apple credential environment variables
# as a request to initialize a signing keychain, even when their values are
# empty. GitHub Actions exposes missing secrets as empty strings, so the
# explicitly unsigned/ad-hoc beta path must remove those variables before
# invoking cargo-packager. Signed packaging keeps the validated environment
# above and remains fail-closed.
if [ "$mode" = private-beta ]; then
  unset APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD \
    APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID \
    APPLE_API_KEY APPLE_API_ISSUER APPLE_API_KEY_PATH APPLE_API_KEY_P8 \
    APPLE_KEYCHAIN_PROFILE RUNONMINE_APPLE_SIGNING_IDENTITY
fi

temporary=packaging/.Packager.macos.signed.$$.json
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
python3 - "$signing_identity" "$temporary" <<'PY'
import json, pathlib, sys, tomllib
source=pathlib.Path('packaging/Packager.macos.toml')
config=tomllib.loads(source.read_text())
macos=config.setdefault('macos', {})
macos['signingIdentity']=sys.argv[1]
macos['entitlements']='entitlements.macos.plist'
pathlib.Path(sys.argv[2]).write_text(json.dumps(config, indent=2)+"\n")
PY

rm -rf -- dist/RunOnMine.app target/distrib/RunOnMine.app
find dist -maxdepth 1 -type f -name 'RunOnMine*.dmg' -delete 2>/dev/null || true
cargo packager --config "$temporary"

dmg_count=$(find dist -maxdepth 1 -type f -name 'RunOnMine*.dmg' -print | wc -l | tr -d ' ')
[ "$dmg_count" -eq 1 ] || { echo "expected exactly one macOS DMG, found $dmg_count" >&2; exit 1; }
dmg=$(find dist -maxdepth 1 -type f -name 'RunOnMine*.dmg' -print)

if [ "$mode" = public ]; then
  ./scripts/release/verify-macos-distribution.sh "$dmg"
else
  ./scripts/release/verify-macos-private-beta.sh "$dmg"
fi
