#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <deb> <package-name> <conflicting-package>" >&2
  exit 2
fi
deb=$1
package=$2
conflict=$3
[ -f "$deb" ] || { echo "DEB is missing" >&2; exit 2; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 2; }

dpkg-deb --field "$deb" Package | grep -Fx "$package" >/dev/null
dpkg-deb --field "$deb" Architecture | grep -E "^(amd64|arm64)$" >/dev/null
depends=$(dpkg-deb --field "$deb" Depends)
for dependency in libc6 libgcc-s1; do
  printf '%s
' "$depends" | tr ',' '
' | sed 's/^[[:space:]]*//;s/[[:space:]].*$//' | grep -Fx "$dependency" >/dev/null
done
if [ "$package" = runonmine ]; then
  for dependency in libgbm1 libxcb1; do
    printf '%s
' "$depends" | tr ',' '
' | sed 's/^[[:space:]]*//;s/[[:space:]].*$//' | grep -Fx "$dependency" >/dev/null
  done
fi
if [ "$package" = runonmine-desktop ]; then
  for dependency in libx11-6 libx11-xcb1 libxcursor1 libxi6 libxkbcommon-x11-0; do
    printf '%s
' "$depends" | tr ',' '
' | sed 's/^[[:space:]]*//;s/[[:space:]].*$//' | grep -Fx "$dependency" >/dev/null
  done
fi
for field in Conflicts Replaces; do
  dpkg-deb --field "$deb" "$field" | tr "," "\n" \
    | sed "s/^[[:space:]]*//;s/[[:space:]]*$//" | grep -Fx "$conflict" >/dev/null
done

contents=$(dpkg-deb --contents "$deb")
printf "%s\n" "$contents" | grep -E "[[:space:]]\./usr/bin/runonmine$" >/dev/null
printf "%s\n" "$contents" | grep -E "[[:space:]]\./usr/bin/runonmine-agent$" >/dev/null
printf "%s\n" "$contents" | grep -E "[[:space:]]\./usr/bin/runonmine-helper$" >/dev/null
case "$package" in
  runonmine-desktop)
    printf "%s\n" "$contents" | grep -E "[[:space:]]\./usr/bin/runonmine-desktop$" >/dev/null
    printf "%s\n" "$contents" | grep -E "[[:space:]]\./usr/share/applications/runonmine-desktop.desktop$" >/dev/null
    ;;
esac

echo "RunOnMine Linux DEB metadata inspection passed."
