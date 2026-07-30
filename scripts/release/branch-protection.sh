#!/usr/bin/env bash
set -euo pipefail
mode="${1:-check}"
repo="${RUNONMINE_GITHUB_REPOSITORY:-ademisler/RunOnMine}"
branch="${RUNONMINE_PROTECTED_BRANCH:-main}"
required_contexts=("Linux quality" "Platform matrix" "Dependency review")
if [[ "$mode" != check && "$mode" != apply ]]; then
  echo "usage: $0 [check|apply]" >&2; exit 2
fi
command -v gh >/dev/null || { echo "gh is required" >&2; exit 2; }
if [[ "$mode" == apply ]]; then
  contexts=$(printf '%s\n' "${required_contexts[@]}" | jq -R . | jq -s .)
  jq -n --argjson contexts "$contexts" '{required_status_checks:{strict:true,contexts:$contexts},enforce_admins:true,required_pull_request_reviews:{dismiss_stale_reviews:true,require_code_owner_reviews:true,required_approving_review_count:1,require_last_push_approval:true},restrictions:null,required_linear_history:true,allow_force_pushes:false,allow_deletions:false,block_creations:false,required_conversation_resolution:true,lock_branch:false,allow_fork_syncing:true}' |
    gh api --method PUT -H 'Accept: application/vnd.github+json' "repos/$repo/branches/$branch/protection" --input -
fi
json=$(gh api -H 'Accept: application/vnd.github+json' "repos/$repo/branches/$branch/protection")
python3 - "$json" <<'PY2'
import json,sys
p=json.loads(sys.argv[1])
checks={c["context"] for c in p.get("required_status_checks",{}).get("checks",[])} | set(p.get("required_status_checks",{}).get("contexts",[]))
required={"Linux quality","Platform matrix","Dependency review"}
errors=[]
if not p.get("required_status_checks",{}).get("strict"): errors.append("strict status checks disabled")
if not required.issubset(checks): errors.append(f"missing required checks: {sorted(required-checks)}")
reviews=p.get("required_pull_request_reviews",{})
if reviews.get("required_approving_review_count",0)<1: errors.append("review count < 1")
if not reviews.get("require_code_owner_reviews"): errors.append("CODEOWNERS review not required")
if p.get("allow_force_pushes",{}).get("enabled"): errors.append("force pushes allowed")
if p.get("allow_deletions",{}).get("enabled"): errors.append("branch deletion allowed")
if errors: raise SystemExit("branch protection invalid: "+"; ".join(errors))
print("branch protection is compliant")
PY2
