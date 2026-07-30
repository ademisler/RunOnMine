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

The scheduled fuzz matrix builds every committed target from the independent
`fuzz/Cargo.lock` before running it. Targets cover TOML config, policy rules,
OAuth request models, restricted browser URL parsing, privileged-helper frames,
MCP session/header binding transitions, verified ZIP/TAR executable-entry
selection, and SQLite-backed approval transitions. Parser/state targets also
receive local libFuzzer smoke runs before changes are accepted.

Normal tests use reference models for approval resolution and MCP session
binding. The weekly mutation workflow narrows `cargo-mutants` to those critical
state machines instead of mutating the entire workspace: the current baseline
catches all 20 generated MCP session mutants and all 15 viable approval mutants.
OAuth dynamic client registration remains globally and per-source limited, and
a 64-concurrent-call test exercises atomic rate-limit admission on every normal
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


## Real Unix helper identity acceptance

On macOS, run the helper identity acceptance as root with a real temporary second user:

```console
RUNONMINE_ACCEPTANCE_ATTACKER_USER=<second-user> sudo -E ./scripts/acceptance/helper-unix-identity.sh
```

The active console user is the helper owner. The test verifies UID ownership, socket mode `0600`, a successful owner health frame, and kernel denial for the second user. Remove the temporary account after the run.

## Physical macOS desktop acceptance

A physical Apple-silicon acceptance run builds both `aarch64-apple-darwin` and
`x86_64-apple-darwin`, merges the four application binaries with `lipo`,
validates the portable archive and CycloneDX SBOM, and packages the universal
DMG with cargo-packager 0.11.8. The installed application is exercised through
native and Rosetta launches, LaunchAgent install/stop/start, loopback health,
Streamable HTTP initialize and discovery, `machine_info`, a locally approved
`fs_write`, every desktop navigation view at the supported layout bounds,
non-purge uninstall, full purge, and restoration of the pre-existing user
state.

This acceptance does not substitute for Developer ID signing, Apple
notarization, or a real operating-system reboot. Unsigned local artifacts are
expected to fail Gatekeeper assessment until the release credentials are
provided.
