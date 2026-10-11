# GitHub-hosted CI

RunOnMine repository workflows use ephemeral GitHub-hosted runners. The stable
`Linux quality` job, scheduled security/coverage/fuzz/mutation/soak jobs, hosted
platform matrix, and artifact preflight must not select a persistent repository
self-hosted runner.

## Trust boundary

Pull requests from forks are untrusted code. They receive only the permissions
explicitly declared by the workflow and must never receive repository secrets or
access to a long-lived machine. `actions/checkout` disables credential
persistence, workflow permissions default to read-only, and third-party actions
are pinned to exact commit SHAs.

The Linux quality and Security jobs install Gitleaks 8.24.3 through
`scripts/ci/install-gitleaks.sh`. That bootstrap accepts only Linux x86_64,
downloads the exact upstream archive, verifies the checked-in SHA-256, installs
into the ephemeral runner home, and verifies the installed version before use.

## Build isolation

Jobs that produce large Rust outputs place `CARGO_TARGET_DIR` below
`RUNNER_TEMP` when practical and remove those outputs with `always()` cleanup.
GitHub-hosted runners are discarded after the job, so no build state or tool
credential should be relied on across runs. Workflows must install every
non-standard tool they need and must not assume a preconfigured user HOME,
Cargo directory, PATH entry, daemon, secret, or browser profile.

## Platform evidence

A successful hosted job proves only the checks it actually executed. A job that
never receives a runner and has no executed steps is infrastructure-allocation
evidence, not product acceptance. macOS, Windows, Linux ARM, clean-package, and
physical clean-install requirements remain separate gates where declared in
`acceptance/release-gates.toml`.

Repository visibility, branch protection, and security settings are owner-side
GitHub controls. Before public beta, confirm the repository has no registered
persistent self-hosted runner and apply the protected-main policy documented in
[releasing.md](releasing.md).
