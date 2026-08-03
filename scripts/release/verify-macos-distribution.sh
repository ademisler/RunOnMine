#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo "macOS distribution verification requires macOS" >&2; exit 2; }
[[ $# -eq 2 ]] || { echo "usage: $0 <RunOnMine.app> <RunOnMine.dmg>" >&2; exit 2; }
app=$1
dmg=$2
[[ -d $app && -f $dmg ]] || { echo "application bundle or DMG is missing" >&2; exit 1; }
identity=$(codesign -dv --verbose=4 "$app" 2>&1 | sed -n 's/^Authority=//p' | head -n1)
[[ $identity == Developer\ ID\ Application:* ]] || {
  echo "application is not signed with Developer ID Application" >&2
  exit 1
}
codesign --verify --deep --strict --verbose=2 "$app"
codesign --verify --strict --verbose=2 "$dmg"
spctl --assess --type execute --verbose=4 "$app"
spctl --assess --type open --context context:primary-signature --verbose=4 "$dmg"
xcrun stapler validate "$app"
mount_plist=$(mktemp)
mount_point=""
cleanup() {
  if [[ -n $mount_point ]]; then hdiutil detach "$mount_point" >/dev/null 2>&1 || true; fi
  rm -f -- "$mount_plist"
}
trap cleanup EXIT HUP INT TERM
printf 'Y\n' | hdiutil attach -readonly -nobrowse "$dmg" >/dev/null
hdiutil info -plist >"$mount_plist"
mount_point=$(python3 - "$mount_plist" "$dmg" <<'PY2'
import os, plistlib, sys
with open(sys.argv[1], 'rb') as handle:
    data=plistlib.load(handle)
wanted=os.path.realpath(sys.argv[2])
points=[]
for image in data.get('images', []):
    if os.path.realpath(image.get('image-path', '')) != wanted:
        continue
    points.extend(
        entry.get('mount-point')
        for entry in image.get('system-entities', [])
        if entry.get('mount-point')
    )
if len(points) != 1:
    raise SystemExit(f"unexpected mount points for {wanted}: {points!r}")
print(points[0])
PY2
)
installed="$mount_point/RunOnMine.app"
[[ -d $installed ]] || { echo "DMG does not contain RunOnMine.app" >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$installed"
xcrun stapler validate "$installed"
for binary in runonmine runonmine-agent runonmine-desktop runonmine-helper; do
  lipo "$installed/Contents/MacOS/$binary" -verify_arch arm64 x86_64
  codesign --verify --strict "$installed/Contents/MacOS/$binary"
done
echo "RunOnMine Developer ID signing, hardened runtime, notarization, stapling, and DMG verification passed."
