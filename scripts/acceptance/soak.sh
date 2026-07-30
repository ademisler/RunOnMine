#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"
cargo test --locked -p runonmine-core   storage::tests::large_audit_chain_incremental_verification_soak   -- --ignored --exact --nocapture
RUNONMINE_MCP_SOAK_ITERATIONS="${RUNONMINE_MCP_SOAK_ITERATIONS:-5000}"   ./scripts/acceptance/mcp-http-smoke.sh
for iteration in $(seq 1 "${RUNONMINE_BROWSER_SOAK_ITERATIONS:-10}"); do
  echo "real Chromium adversarial soak $iteration"
  cargo test --locked -p runonmine-browser     browser_wide_proxy_blocks_popup_workers_websocket_and_rebinding     -- --exact --nocapture
done
echo "RunOnMine state and MCP soak acceptance passed."
