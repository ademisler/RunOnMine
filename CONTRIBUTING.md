# Contributing

RunOnMine is security-sensitive. Keep changes small, reviewable, and covered by
tests. Never add real hostnames, machine identifiers, credentials, browser
profiles, logs, or generated MCP URLs to the repository.

Before opening a pull request, run:

```console
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo audit --deny warnings
cargo deny check
```

Changes to authentication, policy evaluation, privileged IPC, process
execution, filesystem boundaries, or browser profile handling must include a
security regression test and an update to the threat model.

Application logic must remain Rust. JavaScript, TypeScript, Python, and shell
scripts are not accepted as runtime components. YAML, Markdown, and TOML are
used only for CI, documentation, and configuration.
