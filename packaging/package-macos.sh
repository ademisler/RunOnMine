#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config=$(python3 - "$root" <<'PY'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
print(json.dumps({
    "productName": "RunOnMine",
    "version": "0.1.0-beta.1",
    "identifier": "dev.runonmine.app",
    "description": "Let AI work on the machines you own.",
    "homepage": "https://github.com/ademisler/RunOnMine",
    "authors": ["RunOnMine contributors"],
    "licenseFile": str(root / "LICENSE"),
    "binariesDir": str(root / "target/packager-input"),
    "outDir": str(root / "dist"),
    "targetTriple": "universal-apple-darwin",
    "formats": ["dmg"],
    "resources": [str(root / "README.md")],
    "binaries": [
        {"path": "runonmine-desktop", "main": True},
        {"path": "runonmine", "main": False},
        {"path": "runonmine-agent", "main": False},
        {"path": "runonmine-helper", "main": False},
    ],
    "macos": {"minimumSystemVersion": "12.0"},
}))
PY
)
cd "$root"
exec cargo packager --config "$config"
