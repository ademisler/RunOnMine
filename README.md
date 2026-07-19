# RunOnMine

**Let AI work on the machines you own.**

RunOnMine is an open-source, local-first MCP agent that lets AI assistants use
files, terminals, browsers, and desktop applications on machines you own. The
AI model stays in the chosen AI service; approved tool calls run on your macOS,
Linux, or Windows machine.

> [!WARNING]
> RunOnMine is pre-release software. Shell, browser, desktop, and administrator
> tools can make destructive or external changes. The default policy requires
> local approval before write or execution operations and denies administrator
> access.

## Status

The Rust `0.1.0-beta.1` implementation is in security-hardening and acceptance
testing. The repository must remain private until the final security review is
presented to its owner. There is no supported production release yet.

Implemented connection modes:

- local stdio and loopback MCP Streamable HTTP;
- Cloudflare Quick Tunnel with a rotating 256-bit secret path for temporary use;
- Cloudflare Named Tunnel with an embedded OAuth 2.1 server and GitHub owner login;
- OpenAI Secure MCP Tunnel through the official external `tunnel-client`.

RunOnMine never binds its MCP server to a public interface. Tunnel processes
connect outward to the loopback listener at `127.0.0.1:47821`.

## Components

- `runonmine`: setup, connectors, policy, approvals, services, audit, and diagnostics;
- `runonmine-agent`: MCP server and connector supervisor;
- `runonmine-desktop`: tray menu, settings, and local approvals;
- `runonmine-helper`: optional, separately installed privileged helper.

The helper is absent by default. Normal setup and user-service installation do
not install it.

## First local run

```console
runonmine setup --root /absolute/path/to/a/project
runonmine policy show
runonmine agent run
```

In another local MCP client, use:

```console
runonmine mcp stdio --connector <connector-id>
```

Use `runonmine ui` for approvals, or approve locally from another terminal with
`runonmine approvals list` and `runonmine approvals approve <id> --once`.
Approvals cannot be granted through MCP.

## Security model

- Connector policy resolves as tool override, capability override, preset, then deny.
- Denied tools are omitted from MCP discovery and rejected if called directly.
- File operations are restricted to explicitly selected canonical roots.
- The default browser profile is isolated from the user's daily browser profile.
- Secrets use the operating-system credential store, with an explicit encrypted
  headless Linux fallback.
- Audit records contain argument summaries and hashes rather than raw command,
  token, cookie, or stdin contents.
- Audit records form a tamper-evident chain and retain 30 days or 100 MiB by default.
- Shell execution is not a sandbox; when allowed, it has the full authority of
  the account running the agent.

Read [permissions](docs/permissions.md), the [threat model](docs/threat-model.md),
and [browser security](docs/browser-security.md) before enabling write or
execution capabilities.

## Development

Requirements:

- Stable Rust, selected by `rust-toolchain.toml` (MSRV 1.95 documented in `Cargo.toml`);
- the platform C/C++ toolchain required by bundled SQLite and desktop crates.

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Build a Linux/VPS agent without desktop dependencies:

```console
cargo build --release --no-default-features \
  -p runonmine -p runonmine-agent -p runonmine-helper
```

Release candidates are unsigned. The release workflow creates portable
`cargo-dist` archives, native `cargo-packager` installers, CycloneDX SBOMs, and
SHA-256 checksum files, then opens a draft GitHub prerelease. It never changes
repository visibility.

The legacy reference under `Eski örnek` is intentionally ignored and must not
be committed.

## Documentation

- [Architecture](docs/architecture.md)
- [Connection modes](docs/connections.md)
- [Tools](docs/tools.md)
- [Platform installation](docs/platforms/macos.md)
- [Linux and VPS](docs/platforms/linux.md)
- [Windows](docs/platforms/windows.md)
- [Release process](docs/releasing.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
