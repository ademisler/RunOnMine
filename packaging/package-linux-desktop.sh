#!/bin/sh
set -eu
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
[ "$(uname -s)" = Linux ] || { echo "Linux desktop packaging requires Linux" >&2; exit 2; }
[ "$(uname -m)" = x86_64 ] || { echo "Linux desktop packaging currently requires x86_64" >&2; exit 2; }
exec ./packaging/package-linux-deb.sh \
  packaging/Packager.linux-desktop-x86_64.toml runonmine-desktop runonmine
