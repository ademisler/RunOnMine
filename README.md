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
presented to its owner. Release tags are blocked by machine-readable acceptance
gates until clean-machine, cross-platform, and owner-review evidence is recorded.
There is no supported production release yet.

Implemented connection modes:

- local stdio and opt-in, bearer-authenticated loopback MCP Streamable HTTP;
- Cloudflare Quick Tunnel with a rotating 256-bit secret path for temporary use;
- Cloudflare Named Tunnel with an embedded OAuth 2.1 server pinned to the owner's immutable GitHub numeric ID;
- OpenAI Secure MCP Tunnel through the official external `tunnel-client`.

RunOnMine never binds its MCP server to a public interface. Tunnel processes
connect outward to the loopback listener at `127.0.0.1:47821`. For the named
OAuth connector, the immutable positive GitHub numeric user ID is the sole owner
authority. The login is display metadata only; after a successful same-ID
callback, a safe GitHub rename is atomically reflected in local config.

## Components

- `runonmine`: setup, connectors, policy, approvals, services, audit, and diagnostics;
- `runonmine-agent`: MCP server and connector supervisor;
- `runonmine-desktop`: local security control center for approvals, connector setup and credential rotation, roots, visual principal/resource policy rules, OAuth, audit, and diagnostics;
- `runonmine-helper`: optional, separately installed privileged helper.

The helper is absent by default. Normal setup and user-service installation do
not install it. Executable identity alone never authorizes arbitrary privileged
arguments: `--allow-program` is argument-free, while subcommands, flags,
positional values and path roots require an explicit versioned command profile.
See [`docs/admin-helper.md`](docs/admin-helper.md).

## First local run

```console
runonmine setup --root /absolute/path/to/a/project
runonmine policy show
runonmine agent run
```

In another local MCP client, use stdio:

```console
runonmine mcp stdio --connector <connector-id>
```

Loopback HTTP is disabled by default. Enable it explicitly; the token is never
printed and may be exported only to a new private file:

```console
runonmine connect local-http enable --token-output /absolute/private/local-http.json
runonmine agent run
```

Every request to `http://127.0.0.1:47821/mcp` must include
`Authorization: Bearer <token>`. Rotate or recover it through a new private file
with `--token-output`, or disable it with `runonmine connect local-http disable`.

Use `runonmine ui` for approvals, or approve locally from another terminal with
`runonmine approvals list` and `runonmine approvals approve <id> --once`.
Approvals cannot be granted through MCP. Approval prompts show the concrete
command, path, URL, selector, or script target after local secret redaction.
Ten-minute and persistent approvals apply only to the exact connector, tool, and argument hash that was reviewed. A later explicit `deny` rule always overrides an existing exact-action grant.

Immediately stop the service, reject queued approvals, revoke OAuth sessions,
and invalidate temporary connector credentials with:

```console
runonmine lock
```

For private troubleshooting, generate a bounded support archive instead of
sharing raw configuration, state, or log directories:

```console
runonmine doctor
runonmine support-bundle --output runonmine-support.zip
```

The ZIP contains generated structural summaries, service state, an audit outcome
summary, per-entry checksums, and at most five bounded redacted text-log tails.
It excludes raw configuration, the state database, credential stores, browser
profiles, audit arguments, connector identifiers, hostnames, URLs, and selected
filesystem roots. Redaction is defense in depth, so review the ZIP before
sharing it.

## Local connector health

The base health probe remains `http://127.0.0.1:47821/healthz`. For sanitized
managed-connector lifecycle details, query the owner-only loopback route:

```console
curl -sS http://127.0.0.1:47821/healthz/connectors
```

It reports `starting`, `backoff`, `ready`, `degraded`, and `stopped` states. The
detailed endpoint rejects forwarded/public-host requests and never includes
credentials, child-process output, command lines, or generated public URLs.
Cloudflare Quick Tunnel discovery is kept separately in private,
generation-bound runtime state rather than durable configuration; it is cleared
on restart/backoff and removed on process stop.

## Security model

- Connector policy first evaluates principal/resource rules, then tool override, capability override, preset, and finally deny. Explicit deny decisions are evaluated before exact-action grants. Grants are bound to the connector, exact requester principal, tool, and argument hash. Multi-path operations such as `fs_move` authorize every canonical selected-root source and destination resource.
- Internet-facing connectors have a non-bypassable safety ceiling: destructive
  capabilities can require local approval but cannot be configured to auto-run;
  administrator execution remains denied.
- Denied tools are omitted from MCP discovery and rejected if called directly.
- Connector binaries have an explicit trust state. Managed versions are immutable
  digest-addressed files with private receipts; external absolute paths are shown
  as unpinned until the owner runs `runonmine connect pin-external-binaries`.
  Pinned path, digest, ownership, mode, size, and modification time are verified
  again before agent startup, and a changed pin degrades only that connector.
  Managed and external clients are also compatibility-probed during setup,
  doctor, update and startup. Current supported stable ranges are OpenAI
  tunnel-client `0.0.10` and cloudflared `>=2025.1.0,<2027.0.0`; unsupported
  candidates cannot replace the known-good active version.
- Managed connector downloads do not trust a live “latest release” response. RunOnMine embeds provider catalogs in 2-of-2 Ed25519 envelopes signed by a shared security root and a separate Cloudflare or OpenAI root. The signed payload binds the official source repository and commit, release tag, exact platform asset URL, SHA-256, size and archive format; new receipts retain that envelope for startup re-verification.
- File operations use open directory capabilities and descriptor-relative traversal inside explicitly selected roots; path checks and file access are not separated by a canonicalize-then-open race.
- The default browser profile is disposable and isolated from the user's daily
  browser profile. A browser-process-wide loopback proxy covers pages, popups,
  dedicated/shared/service workers, background targets, HTTP(S), and WebSocket
  connections. It resolves every outbound connection, rejects the whole answer
  set when any address is private or non-routable, and connects only to the
  checked IP. QUIC and non-proxied WebRTC UDP are disabled. Private-network
  access is a local-connector-only opt-in and remains blocked for remote connectors.
  Every browser/CDP operation also has a configurable 1–300 second deadline
  (45 seconds by default); a timeout quarantines the session, terminates owned
  Chromium when necessary, and permits a clean lazy restart.
  Owned launches also carry owner-only crash leases. Agent and stdio startup
  remove stale disposable profiles and terminate only same-user Chromium
  processes whose token, exact profile, executable, PID, and start identity all
  match; ambiguous entries are left untouched and reported.
  The local owner may choose an exact Chrome, Chromium, or Edge binary with
  `runonmine browser executable set /absolute/path`, return to platform discovery
  with `browser executable auto`, and inspect the resolved identity with
  `browser executable show`. Missing or unsupported selections disable browser
  tools without invalidating the rest of the configuration. External CDP remains
  a separate loopback-only expert mode and never launches the selected binary.
- Secrets use the operating-system credential store, with an explicit encrypted headless Linux fallback. The encrypted file backend uses an owner-only cross-process lock so CLI, desktop, and agent updates cannot overwrite one another.
- Core state and OAuth SQLite connections are owned by dedicated serialized database workers instead of request-handler mutexes. The core worker has a bounded 128-job queue, one-second enqueue backpressure, and overload metrics; dangerous authorization and audit paths fail closed when work cannot be admitted. Accepted jobs finish without an ambiguous reply timeout. Database directories are private, database/WAL/shared-memory files are owner-only, and worker threads are joined during shutdown. MCP authorization, approval, and audit paths use asynchronous worker replies.
- OAuth clients, authorization state, codes, tokens, and refresh families are isolated by connector/issuer even when connectors share one local SQLite database.
- Audit records contain argument summaries and hashes rather than raw command,
  token, cookie, or stdin contents.
- Audit records form a tamper-evident chain and retain 30 days or 100 MiB by default.
- Shell execution is not a sandbox; when allowed, it has the full authority of
  the account running the agent, but starts from a cleared environment so agent
  secrets are not inherited automatically. The canonical effective working
  directory is bound to policy and exact-action grants, and stdout plus stderr
  share one retained-output budget while both pipes continue draining.
  Command-prefix rules reject shell composition, pipelines, redirection,
  substitution, and multiline payloads.

Read [permissions](docs/permissions.md), the [threat model](docs/threat-model.md),
and [browser security](docs/browser-security.md) before enabling write or
execution capabilities.

## Development

Requirements:

- Stable Rust, selected by `rust-toolchain.toml` (MSRV 1.95 documented in `Cargo.toml`);
- the platform C/C++ toolchain required by bundled SQLite and desktop crates.

```console
cargo run --locked -p xtask -- verify
```

Use `--headless` on a Linux/VPS development host and `--skip-secret-scan` only
when Gitleaks is unavailable locally. CI separately enforces a 45% headless line
coverage floor and runs scheduled parser/policy fuzz targets. The isolated CLI
acceptance smoke test is available as:

```console
./scripts/acceptance/cli-smoke.sh
```

Build a Linux/VPS agent without desktop dependencies:

```console
cargo build --release --no-default-features \
  -p runonmine -p runonmine-agent -p runonmine-helper
```

Release candidates are unsigned. The release workflow creates portable `cargo-dist` archives, native `cargo-packager` installers, CycloneDX SBOMs with dependency edges and Cargo.lock checksums, and SHA-256 artifact checksum files, then opens a draft GitHub prerelease. It never changes repository visibility.

The legacy reference under `Eski örnek` is intentionally ignored and must not
be committed.

## Documentation

- [Architecture](docs/architecture.md)
- [Connection modes](docs/connections.md)
- [Connector provenance and key rotation](docs/connector-provenance.md)
- [Tools](docs/tools.md)
- [Platform installation](docs/platforms/macos.md)
- [Linux and VPS](docs/platforms/linux.md)
- [Windows](docs/platforms/windows.md)
- [Release process](docs/releasing.md)
- [Release acceptance](docs/acceptance.md)
- [Self-hosted CI runner](docs/ci-runner.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
