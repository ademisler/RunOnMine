#!/usr/bin/env python3
"""Write a non-release artifact preflight report.

This deliberately does not claim reboot, code-signing, notarization, or clean-VM
release acceptance. Those remain separate evidence gates.
"""
import argparse, datetime, hashlib, json, os, pathlib, subprocess

parser=argparse.ArgumentParser()
parser.add_argument('--platform', required=True)
parser.add_argument('--artifact', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--checks', required=True, help='comma-separated checks actually completed')
args=parser.parse_args()
artifact=pathlib.Path(args.artifact)
if not artifact.is_file(): raise SystemExit('artifact is missing')
checks=[item.strip() for item in args.checks.split(',') if item.strip()]
required={'build','checksum','setup','agent_ready','mcp_initialize','approved_tool_call','uninstall','residue_check'}
missing=required-set(checks)
if missing: raise SystemExit(f'preflight checks missing: {sorted(missing)}')
report={
    'schema_version':1,
    'report_type':'artifact_preflight_not_release_acceptance',
    'platform':args.platform,
    'artifact':artifact.name,
    'artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),
    'source_revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
    'runner':os.environ.get('RUNNER_NAME','local'),
    'tested_at':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),
    'completed_checks':checks,
    'not_claimed':['operating_system_reboot','publisher_signature','notarization','release_clean_install_acceptance'],
}
path=pathlib.Path(args.output); path.parent.mkdir(parents=True,exist_ok=True)
path.write_text(json.dumps(report,indent=2)+'\n')
print(path)
