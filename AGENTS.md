# RunOnMine contributor instructions

## Security invariants

- Keep the HTTP listener on loopback. Never expose `/mcp` directly on a public bind address.
- Local HTTP must remain disabled by default and must require its credential-store bearer token.
- Never print, serialize, log, or persist plaintext connector credentials or OAuth tokens.
- Internet-facing connectors keep the remote safety ceiling by default. The only reviewed exception is an explicit `owner_full_access` opt-in on a GitHub-owner-authenticated Cloudflare Named Tunnel; it must default to false, remain visible in CLI/UI, retain OAuth scopes/policy/audit enforcement, and must never apply to Quick Tunnel or OpenAI connectors.
- Approval grants must be scoped to the exact connector, tool, and argument hash unless a separately reviewed policy feature explicitly narrows a resource boundary.
- Dangerous actions must fail closed when authorization or audit persistence is unavailable.
- Do not weaken selected-root filesystem checks, managed-binary receipt verification, process environment clearing, output limits, or process-tree termination.
- Do not stop, rewrite, or claim ownership of unrelated local services, listeners, or application data during development or acceptance.

## Development workflow

Use Rust `1.95.0` from `rust-toolchain.toml` and keep `Cargo.lock` committed.

Before opening a pull request, run:

```console
python3 scripts/ci/check-docs.py
python3 scripts/release/check-duplicate-dependencies.py
cargo run --locked -p xtask -- verify
```

Use `--headless` only on supported Linux/VPS development hosts. Run
`./scripts/acceptance/cli-smoke.sh` after changing setup, secrets, policy,
approvals, audit, lock, uninstall, or path discovery. Do not skip the secret
scan for release work.

Dependency advisories are release blockers. Do not add an advisory exception without an owner-approved, time-bounded risk record and an automated dependency-path assertion.

## Change discipline

- Add a regression test for every security or authorization fix.
- Keep migrations forward-compatible and reject unknown future schema versions.
- Update `README.md`, `CHANGELOG.md`, and the relevant file under `docs/` when behavior changes.
- Do not commit generated `target/`, local state databases, credentials, browser profiles, release artifacts, or machine-specific configuration.
- Do not change repository visibility, publish a release, or transfer repository ownership without explicit owner approval.
- Do not attach persistent self-hosted runners to the public repository. CI and scheduled repository workflows must use ephemeral GitHub-hosted runners unless a separately reviewed isolation design is introduced.
