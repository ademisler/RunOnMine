#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <archive> <sbom.json>" >&2
  exit 2
fi
archive=$1
sbom=$2

verify_checksum() {
  file=$1
  checksum="$file.sha256"
  test -f "$checksum"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$file")" && sha256sum -c "$(basename "$checksum")")
  else
    (cd "$(dirname "$file")" && shasum -a 256 -c "$(basename "$checksum")")
  fi
}

verify_checksum "$archive"
verify_checksum "$sbom"
python3 - "$sbom" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
assert data.get("bomFormat") == "CycloneDX"
assert data.get("specVersion") == "1.6"
assert data.get("components")
assert data.get("dependencies") is not None
properties = data.get("metadata", {}).get("properties", [])
assert any(item.get("name") == "runonmine:cargo-lock-sha256" for item in properties)
PY

case "$archive" in
  *.zip) unzip -Z1 "$archive" >/dev/null ;;
  *.tar.gz) tar -tzf "$archive" >/dev/null ;;
  *) echo "unsupported archive type: $archive" >&2; exit 2 ;;
esac

echo 'RunOnMine package integrity inspection passed.'
