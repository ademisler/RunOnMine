# Changelog

All notable changes to RunOnMine are documented here. The project is still in
pre-release development and does not yet provide compatibility guarantees.

## Unreleased

### Security

- Require bearer authentication for opt-in local HTTP MCP access and keep it disabled by default.
- Intercept browser redirects and subresources, block private destinations for remote connectors, and clean disposable profiles.
- Store persistent approvals as exact connector/tool/argument grants instead of broad tool-wide policy changes.
- Verify managed connector binaries against persisted installation receipts on every load.
- Show bounded, locally redacted commands, paths, URLs, selectors, and scripts in approval prompts.
- Scope ten-minute approvals to the exact connector, tool, and argument hash.
- Block dangerous tool calls when the local audit store cannot record authorization.
- Clear the inherited environment before user-shell execution and restore only a minimal safe allowlist.
- Stream bounded file reads, reject non-regular files, and preserve UTF-8 boundaries.
- Add MCP request-body and concurrency limits.
- Cap destructive capabilities from internet-facing connectors at local approval and deny remote administrator execution.
- Deny private and non-routable browser destinations by default, with an explicit local-network opt-in.
- Rate-limit dynamic OAuth client registration, cap registered clients, and prune expired OAuth state.
- Add an emergency lock that stops access, denies pending approvals, clears temporary grants, revokes OAuth state, rotates Quick Tunnel secrets, and removes OpenAI runtime keys.
- Harden the temporary self-hosted CI runner with a dedicated unprivileged account; migration to GitHub-hosted runners remains planned.

### Maintenance

- Add component-scoped SQLite schema versions and future-version rejection.
- Centralize internal workspace dependency versions and add an automated version consistency gate.
- Expand the desktop application into a security control center for connectors, roots, policies, OAuth, audit, and diagnostics.
- Pin the repository Rust toolchain to 1.95.0.
- Group Dependabot minor and patch updates to reduce pull-request noise.
- Add CI verification that temporarily ignored `quick-xml` advisories remain confined to expected build/proc-macro dependency paths.
