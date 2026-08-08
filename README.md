<div align="center">
  <img src="packaging/assets/runonmine.svg" width="108" alt="RunOnMine logo">
  <h1>RunOnMine</h1>
  <p><strong>Let AI work on the machines you own — through a local security boundary you control.</strong></p>
  <p>A local-first Model Context Protocol (MCP) gateway and desktop control center for macOS, Linux, and Windows.</p>
  <p>
    <a href="#install">Install</a> ·
    <a href="#quick-start">Quick start</a> ·
    <a href="#how-it-works">How it works</a> ·
    <a href="#security-at-a-glance">Security</a> ·
    <a href="docs/README.md">Documentation</a>
  </p>
</div>

RunOnMine sits between an AI assistant and a machine you own. It gives the AI
controlled access to files, terminals, browsers, and desktop applications while
keeping execution, policy, credentials, approvals, and audit records on your
machine.

Instead of exposing SSH, a raw shell, or a public MCP listener, RunOnMine checks
**who is asking, what tool is being called, which resource it targets, and
whether the action needs local approval** before anything executes.

<p align="center">
  <img src="docs/images/control-center-overview.png" width="920" alt="RunOnMine security control center">
</p>

## What you get

| Capability | RunOnMine boundary |
| --- | --- |
| **Files** | AI access is limited to directories you explicitly select. |
| **Terminal & processes** | Commands are evaluated by policy and can require exact local approval. |
| **Browser automation** | Uses an isolated browser profile with network and private-address protections. |
| **Desktop control** | Native desktop actions run only when the OS/session permits them. |
| **Remote connectivity** | Managed tunnels connect outward; the MCP server stays on loopback. |
| **Safety controls** | Local approvals, explicit deny rules, tamper-evident audit, diagnostics, and Emergency Lock. |

The AI model still runs in the AI service you choose. **Tool execution happens
through the RunOnMine boundary on the machine you control.**

## How it works

![AI requests pass through the local RunOnMine security boundary before tools execute](docs/assets/security-flow.svg)

1. An AI client sends an MCP tool request through a configured connector.
2. RunOnMine evaluates connector/requester identity, selected roots, policy,
   resource scope, and any exact-action approval.
3. The action is **allowed**, **held for local approval**, or **denied**.
4. The result is returned to the AI and the local audit trail is updated.

RunOnMine supports local stdio, opt-in authenticated loopback HTTP, Cloudflare
connectors, and OpenAI Secure MCP Tunnel. See
[Connection modes](docs/connections.md) for the full connector model.

## Install

> [!NOTE]
> RunOnMine is currently **pre-release/private-beta software**. Windows and Linux
> prerelease packages are available from [GitHub Releases](https://github.com/ademisler/RunOnMine/releases).
> macOS is supported and clean-machine tested, but a public Developer ID signed
> and notarized DMG is not published yet; use the source build below for now.

| Platform | Recommended install today |
| --- | --- |
| **Windows x86_64** | Current-user NSIS desktop installer from Releases |
| **Linux x86_64** | Desktop DEB or headless DEB from Releases |
| **Linux ARM64** | Headless DEB from Releases |
| **macOS 12+** | Native source build; public signed/notarized DMG is pending |

Private-beta installers are not publisher-signed production builds. Verify the
adjacent SHA-256 checksum asset before running a downloaded package.

### Windows x86_64

Download the `runonmine-desktop_*_x64-setup.exe` prerelease asset and run it.
The installer is a **current-user install**; the optional LocalSystem helper is
not installed or activated unless you explicitly request it later.

Then initialize the project directory the AI may access:

```powershell
$rom = Join-Path $env:LOCALAPPDATA "RunOnMine\runonmine.exe"
& $rom setup --root "C:\path\to\your\project"
& $rom service install
```

Launch **RunOnMine** from the Start Menu to open the security control center.
See the [Windows guide](docs/platforms/windows.md) for package lifecycle,
uninstall behavior, and the optional privileged helper.

### Linux desktop (x86_64)

Download the desktop DEB from Releases, then:

```console
sudo apt install ./runonmine-desktop_*_amd64.deb
runonmine setup --root "$HOME/Projects/my-project"
runonmine service install
runonmine-desktop
```

For headless x86_64 or ARM64 systems, use the corresponding `runonmine_*` DEB.
Headless services need an explicit secure secret-store setup, so follow the
[Linux and VPS guide](docs/platforms/linux.md) rather than copying desktop
service assumptions to a server.

### macOS 12+

Until the public notarized installer is available, build the native app from
source. You need Xcode Command Line Tools and Rust; the repository pins Rust
`1.95.0` in `rust-toolchain.toml`.

```console
git clone https://github.com/ademisler/RunOnMine.git
cd RunOnMine
cargo build --release --locked \
  -p runonmine -p runonmine-agent -p runonmine-desktop

./target/release/runonmine setup --root "$HOME/Projects/my-project"
./target/release/runonmine service install
./target/release/runonmine-desktop
```

RunOnMine does not bypass macOS consent prompts. Desktop input/capture may
require Accessibility or Screen Recording permission. See the
[macOS guide](docs/platforms/macos.md).

## Quick start

### 1. Select only the directories AI may use

```console
runonmine setup --root /absolute/path/to/project
```

Do not select your whole home directory unless that broader access is genuinely
required.

### 2. Start with the Safe policy

```console
runonmine policy show
```

New connectors start with **Safe**: reads are available, writes/execution ask
locally, and administrator execution is denied. **Developer** is intended for
trusted selected-root coding work. **Automation** (`full` in the CLI) is the
broadest local preset and should be used only on a dedicated or tightly scoped
machine.

### 3. Run the agent

For a one-off foreground session:

```console
runonmine agent run
```

Or install the normal per-user service so RunOnMine can recover with your login
session:

```console
runonmine service install
runonmine service status
```

### 4. Connect your AI client

The smallest local surface is the default stdio connector:

```console
runonmine connect list
runonmine mcp stdio --connector <local-connector-id>
```

Authenticated loopback HTTP is opt-in and its bearer token is never printed:

```console
runonmine connect local-http enable \
  --token-output /absolute/private/local-http.json
```

For remote access, use a managed Cloudflare or OpenAI connector instead of
opening the MCP listener to the network. See [Connection modes](docs/connections.md).

## Everyday controls

| Task | Command / UI |
| --- | --- |
| Review pending actions | **Approvals** in the desktop app or `runonmine approvals list` |
| Approve once | `runonmine approvals approve <id> --once` |
| Inspect policy | `runonmine policy show` |
| Check health | `runonmine doctor` |
| Create a redacted support bundle | `runonmine support-bundle --output runonmine-support.zip` |
| Stop access immediately | `runonmine lock` |

`runonmine lock` stops the agent and managed connectors, rejects queued
approvals, revokes live OAuth sessions, and invalidates temporary connector
credentials.

## Why not direct SSH or a raw MCP server?

| Direct machine access | RunOnMine |
| --- | --- |
| Broad account authority | Capability- and resource-scoped policy |
| One credential often unlocks everything | Connector/requester identity is evaluated per action |
| No built-in human checkpoint | Dangerous actions can require exact local approval |
| Public listener or inbound firewall rule | MCP remains on loopback; managed tunnels connect outward |
| Ad-hoc logs | Tamper-evident audit plus Emergency Lock |

## Security at a glance

RunOnMine is designed to make the machine boundary visible rather than pretend
machine automation is harmless:

- MCP is never bound directly to a public network interface.
- Remote connectors cannot approve their own dangerous requests.
- Remote administrator execution is denied by a non-bypassable safety ceiling.
- The optional privileged helper is **absent by default** and requires separate,
  explicit installation.
- Filesystem tools operate inside explicitly selected roots.
- Browser automation uses an isolated profile instead of the user’s daily
  browser profile.
- Secrets stay in the operating-system credential store or the documented
  encrypted headless fallback.
- Audit records are tamper-evident and avoid storing raw secrets or command
  payloads.

> [!WARNING]
> Shell, browser, desktop, and privileged tools can make destructive or external
> changes. RunOnMine is a security boundary and approval system, **not a sandbox**.
> Give the agent only the account authority and selected roots it actually needs.

Read the [Permissions model](docs/permissions.md),
[Threat model](docs/threat-model.md), and
[Browser security](docs/browser-security.md) before enabling broader write or
execution capabilities.

## Components

- **`runonmine`** — setup, connectors, policy, approvals, service lifecycle,
  diagnostics, audit, and Emergency Lock.
- **`runonmine-agent`** — local MCP server and connector supervisor.
- **`runonmine-desktop`** — security control center for approvals, connections,
  permissions, OAuth, audit, and diagnostics.
- **`runonmine-helper`** — optional separately installed privileged helper.

## Project status

RunOnMine is still pre-release software. The repository records release state in
machine-readable form: `acceptance/release-candidate.toml` identifies the frozen
source candidate and `acceptance/release-gates.toml` records which acceptance
and security gates actually passed.

A signed public release remains fail-closed until the public release gates are
satisfied. Do not interpret an unsigned private-beta artifact as a publisher-
trusted production build.

## Documentation

Start with the [documentation index](docs/README.md).

- **Get started:** [secure onboarding](docs/onboarding.md) and
  [troubleshooting](docs/troubleshooting.md)
- **Platforms:** [macOS](docs/platforms/macos.md),
  [Linux/VPS](docs/platforms/linux.md), and
  [Windows](docs/platforms/windows.md)
- **Architecture:** [architecture](docs/architecture.md),
  [connection modes](docs/connections.md), and [MCP tools](docs/tools.md)
- **Security:** [permissions](docs/permissions.md),
  [threat model](docs/threat-model.md),
  [audit integrity](docs/audit-security.md), and
  [privileged helper](docs/admin-helper.md)
- **Quality & release:** [testing](docs/testing.md),
  [release acceptance](docs/acceptance.md), and
  [release process](docs/releasing.md)

## Development

RunOnMine is a Rust workspace pinned to Rust `1.95.0`. Keep `Cargo.lock`
committed. Before opening a pull request, run:

```console
python3 scripts/ci/check-docs.py
cargo run --locked -p xtask -- verify
```

On supported headless Linux development hosts, use `--headless`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for security-sensitive change requirements
and the complete contributor workflow.

## License

Apache License 2.0. See [LICENSE](LICENSE).
