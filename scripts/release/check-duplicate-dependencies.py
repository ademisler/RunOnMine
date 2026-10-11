#!/usr/bin/env python3
import json, pathlib, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[2]
baseline_path=root/"release/duplicate-dependency-baseline.json"
metadata=json.loads(subprocess.check_output(["cargo","metadata","--format-version","1","--locked"],cwd=root))
versions={}
for package in metadata["packages"]:
    versions.setdefault(package["name"],set()).add(package["version"])
current={name:sorted(values) for name,values in versions.items() if len(values)>1}
if "--write-baseline" in sys.argv:
    baseline_path.write_text(json.dumps({"schema_version":1,"duplicates":current},indent=2,sort_keys=True)+"\n")
    print(f"wrote {baseline_path}")
    raise SystemExit(0)
baseline=json.loads(baseline_path.read_text())
allowed=baseline.get("duplicates",{})
regressions=[]
for name, values in current.items():
    if name not in allowed:
        regressions.append(f"new duplicate package {name}: {values}")
    elif not set(values).issubset(set(allowed[name])):
        regressions.append(f"new duplicate versions for {name}: {values} (baseline {allowed[name]})")
if regressions:
    raise SystemExit("duplicate dependency ratchet failed:\n"+"\n".join(regressions))
resolved=sum(len(v) for v in allowed.values())-sum(len(v) for v in current.values())
print(f"duplicate dependency ratchet passed: {len(current)} package names; version entries reduced by {max(resolved,0)}")
for path in sorted((root/"dist").glob("*")) if (root/"dist").exists() else []:
    if path.is_file(): print(f"artifact_size_bytes {path.name} {path.stat().st_size}")
