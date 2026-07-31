#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import sys

REQUIRED_STEPS = {
    "install", "reboot", "agent_ready", "mcp_initialize", "approved_tool_call",
    "connector", "uninstall", "residue_check"
}
SUPPORTED = {
    "macos-universal", "linux-x86_64", "linux-aarch64",
    "linux-desktop-x86_64", "windows-x86_64"
}
DESKTOP_REQUIRED_STEPS = {"desktop_launch", "desktop_views", "native_shell"}
MACOS_REQUIRED_STEPS = {"native_slice_launch", "rosetta_slice_launch"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

def fail(message):
    raise SystemExit(f"clean-install evidence invalid: {message}")

def main(path):
    data=json.loads(pathlib.Path(path).read_text())
    if data.get("schema_version") != 1: fail("schema_version must be 1")
    platform=data.get("platform")
    if platform not in SUPPORTED: fail("unsupported platform")
    artifact=data.get("artifact")
    if (not isinstance(artifact,str) or not artifact.strip()
            or pathlib.Path(artifact).name != artifact):
        fail("artifact must be a non-empty basename")
    if not HEX64.fullmatch(data.get("artifact_sha256", "")): fail("artifact_sha256")
    if not HEX40.fullmatch(data.get("source_revision", "")): fail("source_revision")
    if not isinstance(data.get("tester"), str) or len(data["tester"].strip()) < 2: fail("tester")
    if not isinstance(data.get("tested_at"), str) or "T" not in data["tested_at"]: fail("tested_at")
    steps=data.get("steps")
    if not isinstance(steps,list): fail("steps must be an array")
    ids=[]
    for step in steps:
        if not isinstance(step,dict): fail("step must be an object")
        step_id=step.get("id")
        ids.append(step_id)
        if step.get("status") != "passed": fail(f"{step_id} is not passed")
        evidence=step.get("evidence")
        if not isinstance(evidence,str) or not evidence.strip(): fail(f"{step_id} evidence missing")
    required=set(REQUIRED_STEPS)
    if platform in {"macos-universal", "linux-desktop-x86_64", "windows-x86_64"}:
        required.update(DESKTOP_REQUIRED_STEPS)
    if platform == "macos-universal":
        required.update(MACOS_REQUIRED_STEPS)
    missing=required-set(ids)
    if missing: fail(f"missing steps: {sorted(missing)}")
    if len(ids) != len(set(ids)): fail("duplicate step IDs")
    residues=data.get("residues")
    if not isinstance(residues,list): fail("residues must be an array")
    for item in residues:
        if not isinstance(item,dict) or item.get("expected") is not True:
            fail("every retained residue must be explicitly expected")
    print(f"valid clean-install evidence: {data['platform']} {data['artifact_sha256']}")

if __name__ == "__main__":
    if len(sys.argv)!=2: fail("usage: validate-clean-install-evidence.py FILE")
    main(sys.argv[1])
