#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <packager-config> <package-name> <conflicting-package>" >&2
  exit 2
fi
config=$1
package=$2
conflict=$3
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

[ "$(uname -s)" = Linux ] || { echo "Linux DEB packaging requires Linux" >&2; exit 2; }
command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 2; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 2; }

cargo packager --config "$config"
deb=$(find dist -maxdepth 1 -type f -name "${package}_*.deb" -printf "%T@ %p\n" \
  | sort -nr | sed -n "1s/^[^ ]* //p")
[ -n "$deb" ] || { echo "packager did not produce a ${package} DEB" >&2; exit 1; }

work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

dpkg-deb --raw-extract "$deb" "$work/root"
control="$work/root/DEBIAN/control"
[ -f "$control" ] || { echo "DEB control file is missing" >&2; exit 1; }
for field in Conflicts Replaces; do
  if grep -q "^${field}:" "$control"; then
    echo "${field} already exists in DEB control metadata" >&2
    exit 1
  fi
done
{
  printf "Conflicts: %s\n" "$conflict"
  printf "Replaces: %s\n" "$conflict"
} >>"$control"

temporary="$deb.tmp"
dpkg-deb --root-owner-group --build "$work/root" "$temporary" >/dev/null
mv "$temporary" "$deb"

dpkg-deb --field "$deb" Package | grep -Fx "$package" >/dev/null
dpkg-deb --field "$deb" Conflicts | tr "," "\n" | sed "s/^[[:space:]]*//;s/[[:space:]]*$//" | grep -Fx "$conflict" >/dev/null
dpkg-deb --field "$deb" Replaces | tr "," "\n" | sed "s/^[[:space:]]*//;s/[[:space:]]*$//" | grep -Fx "$conflict" >/dev/null
./scripts/acceptance/linux-deb-metadata.sh "$deb" "$package" "$conflict"
sha256sum "$deb" >"$deb.sha256"
printf "%s\n" "$deb"
