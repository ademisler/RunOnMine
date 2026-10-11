#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo "macOS private-beta verification requires macOS" >&2; exit 2; }
[[ $# -eq 1 ]] || { echo "usage: $0 <RunOnMine.dmg>" >&2; exit 2; }
dmg=$1
[[ -f $dmg ]] || { echo "DMG is missing" >&2; exit 1; }

/usr/bin/codesign --verify --strict --verbose=2 "$dmg"
dmg_signature=$(/usr/bin/codesign -dv --verbose=4 "$dmg" 2>&1)
grep -Fx 'Signature=adhoc' <<<"$dmg_signature" >/dev/null || {
  echo "private-beta DMG is not ad-hoc signed" >&2
  exit 1
}

mount_plist=$(mktemp)
mount_point=""
cleanup() {
  if [[ -n $mount_point ]]; then /usr/bin/hdiutil detach "$mount_point" >/dev/null 2>&1 || true; fi
  rm -f -- "$mount_plist"
}
trap cleanup EXIT HUP INT TERM
printf 'Y\n' | /usr/bin/hdiutil attach -readonly -nobrowse "$dmg" >/dev/null
/usr/bin/hdiutil info -plist >"$mount_plist"
mount_point=$(python3 - "$mount_plist" "$dmg" <<'PY'
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
PY
)
app="$mount_point/RunOnMine.app"
[[ -d $app ]] || { echo "DMG does not contain RunOnMine.app" >&2; exit 1; }
[[ $(/usr/bin/defaults read "$app/Contents/Info" CFBundleIdentifier) == dev.runonmine.app ]] || {
  echo "application bundle identifier mismatch" >&2
  exit 1
}

/usr/bin/codesign --verify --deep --strict --verbose=2 "$app"
app_signature=$(/usr/bin/codesign -dv --verbose=4 "$app" 2>&1)
grep -Fx 'Signature=adhoc' <<<"$app_signature" >/dev/null || {
  echo "private-beta application is not ad-hoc signed" >&2
  exit 1
}
grep -E '^CodeDirectory .*flags=.*\(adhoc,runtime\)' <<<"$app_signature" >/dev/null || {
  echo "private-beta application does not enable hardened runtime" >&2
  exit 1
}
grep -E '^Sealed Resources version=2 ' <<<"$app_signature" >/dev/null || {
  echo "private-beta application resources are not sealed" >&2
  exit 1
}
if grep -q '^Authority=' <<<"$app_signature"; then
  echo "private-beta application unexpectedly claims a publisher authority" >&2
  exit 1
fi

for binary in runonmine runonmine-agent runonmine-desktop runonmine-helper; do
  path="$app/Contents/MacOS/$binary"
  /usr/bin/lipo "$path" -verify_arch arm64 x86_64
  /usr/bin/codesign --verify --strict "$path"
  signature=$(/usr/bin/codesign -dv --verbose=4 "$path" 2>&1)
  grep -Fx 'Signature=adhoc' <<<"$signature" >/dev/null || {
    echo "$binary is not ad-hoc signed" >&2
    exit 1
  }
  grep -E '^CodeDirectory .*flags=.*\(adhoc,runtime\)' <<<"$signature" >/dev/null || {
    echo "$binary does not enable hardened runtime" >&2
    exit 1
  }
done

echo "RunOnMine private-beta ad-hoc signing, hardened runtime, sealed resources, universal slices, and DMG verification passed."
