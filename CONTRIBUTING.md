# Contributing

RunOnMine is security-sensitive. Keep changes small, reviewable, and covered by
tests. Never add real hostnames, machine identifiers, credentials, browser
profiles, logs, or generated MCP URLs to the repository.

Before opening a pull request, run:

```console
cargo run --locked -p xtask -- verify
```

On a headless Linux development machine, use `--headless`. The full command
runs formatting, version consistency, desktop/full-feature and headless Clippy
and tests, dependency policy, and the complete-history Gitleaks scan. Do not use
`--skip-secret-scan` for a release candidate.

Run the isolated real-binary flow after changing setup, policy, connector,
approval, audit, lock, uninstall, secret, or path behavior:

```console
./scripts/acceptance/cli-smoke.sh
```

Changes to authentication, policy evaluation, privileged IPC, process
execution, filesystem boundaries, or browser profile handling must include a
security regression test and an update to the threat model.

Application logic must remain Rust. JavaScript, TypeScript, Python, and shell
scripts are not accepted as runtime components. YAML, Markdown, and TOML are
used only for CI, documentation, and configuration.
