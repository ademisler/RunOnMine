# RunOnMine contributor instructions

## Security invariants

- Keep the HTTP listener on loopback. Never expose `/mcp` directly on a public bind address.
- Local HTTP must remain disabled by default and must require its credential-store bearer token.
- Never print, serialize, log, or persist plaintext connector credentials or OAuth tokens.
- Internet-facing connectors must not bypass the remote safety ceiling. Administrator execution, external CDP attachment, and private-network browser access remain unavailable remotely.
- Approval grants must be scoped to the exact connector, tool, and argument hash unless a separately reviewed policy feature explicitly narrows a resource boundary.
- Dangerous actions must fail closed when authorization or audit persistence is unavailable.
- Do not weaken selected-root filesystem checks, managed-binary receipt verification, process environment clearing, output limits, or process-tree termination.
- Port `45799` belongs to the existing MacMCP installation and must remain untouched.

## Development workflow

Use Rust `1.95.0` from `rust-toolchain.toml` and keep `Cargo.lock` committed.

Before opening a pull request, run:

```console
cargo fmt --all --check
cargo run --locked -p xtask -- verify-versions
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo clippy --workspace --exclude runonmine-desktop --no-default-features --all-targets --locked -- -D warnings
cargo test --workspace --exclude runonmine-desktop --no-default-features --locked
cargo audit --deny warnings
cargo deny check
gitleaks git --redact --no-banner --verbose
```

Dependency advisories are release blockers. Do not add an advisory exception without an owner-approved, time-bounded risk record and an automated dependency-path assertion.

## Change discipline

- Add a regression test for every security or authorization fix.
- Keep migrations forward-compatible and reject unknown future schema versions.
- Update `README.md`, `CHANGELOG.md`, and the relevant file under `docs/` when behavior changes.
- Do not commit generated `target/`, local state databases, credentials, browser profiles, release artifacts, or machine-specific configuration.
- Keep the repository private unless the owner explicitly changes that decision.
- Do not change the current CI runner strategy without an explicit owner request; migration to GitHub-hosted runners is planned separately.
