# Testing


## CI platform and coverage contracts

Relevant pull requests run the macOS, Windows and ARM platform jobs directly;
there is no repository variable that silently skips them. Workflows install the
exact Rust toolchain through `scripts/ci/install-rust-toolchain.sh`, which pins
components and targets with `rustup` rather than relying on unsupported action
inputs.

Coverage is measured from LCOV and enforced by `scripts/ci/check-lcov.py` at
70% globally, 90% in policy/auth/storage/approval-critical modules, and 80% of
changed executable lines on pull requests. The main Linux quality job also runs
a real Streamable HTTP MCP lifecycle: initialize, initialized notification,
tools/list, a safe tool call, negative authentication and malformed-body checks,
and session deletion.

## Fuzzing and concurrency

Nightly fuzz targets cover TOML config, filesystem resolution, policy,
redaction, OAuth request models, restricted browser URLs, and privileged-helper
request frames. MCP HTTP health publishes a fresh process epoch and documents
that sessions and rate-limit buckets reset after restart. OAuth dynamic client
registration is limited both globally and per registration source. A
64-concurrent-call test exercises atomic rate-limit admission on every normal
quality run.


## Acceptance and soak

`./scripts/acceptance/mcp-http-smoke.sh` starts a real isolated agent and covers
Streamable HTTP initialize, initialized notification, repeated `tools/list`,
`machine_info`, an approval-gated `fs_write` resolved once through the CLI,
invalid bearer and malformed-body rejection, and session deletion. Set
`RUNONMINE_MCP_SOAK_ITERATIONS` to increase the repeated discovery count.

`./scripts/acceptance/soak.sh` verifies 20,000 audit rows, appends and
incrementally verifies 2,000 more, and runs 5,000 MCP discovery calls in the
scheduled workflow. `helper-unix-identity.sh` is root-only and uses real owner
and attacker UIDs. `artifact-preflight.yml` runs fresh-host artifact checks but
explicitly does not claim OS reboot, code signing, notarization or release
clean-install acceptance.
