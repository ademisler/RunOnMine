# Changelog

All notable changes to RunOnMine are documented here. The project is still in
pre-release development and does not yet provide compatibility guarantees.

## Unreleased

### Security

- Commit connector creation, enablement, removal, desktop credential replacement, emergency rotation, and purge enumeration against the latest locked configuration; restore every previous credential value before unlocking after handled secret-store, validation, or save failures.
- Serialize high-frequency configuration read-modify-write operations across the agent, desktop, and CLI with an owner-only sidecar lock so Quick Tunnel URL discovery, setup, browser, and policy updates cannot silently overwrite one another.
- Roll back partially started external connectors on startup failure, delay Quick Tunnel public-URL persistence until every connector has initialized successfully, and recover from buffered event lag after activation.
- Let dropped connector supervisor handles complete process-group termination, output draining, and terminal-state publication instead of aborting cleanup immediately.
- Require Cloudflare OAuth requests and OAuth metadata routes to use the configured public hostname with no explicit port or HTTPS port 443, rejecting Host-header port confusion.
- Correctly distinguish 64-character hexadecimal master keys from Base64 and exercise the encrypted fallback through isolated real-binary acceptance tests.
- Make explicit deny rules override exact-action grants and authorize every filesystem resource in multi-path operations.
- Require immutable GitHub numeric owner IDs for OAuth connectors and persist dynamic registration rate limits across restarts.
- Serialize fallback encrypted-secret updates across processes and enforce private SQLite database, WAL, and shared-memory permissions.
- Remove ambient PATH binary discovery and privileged `id`/`chown` command execution from security boundaries.
- Reject credential-bearing external CDP URLs and validate final browser redirect destinations.
- Upgrade all `quick-xml` dependency paths to 0.41 and remove the temporary RustSec advisory exceptions.
- Replace canonicalize-then-open filesystem operations with capability-based, descriptor-relative access and managed in-root trash.
- Add principal/resource policy rules for OAuth clients and subjects, filesystem prefixes, browser origins, executable paths, and command prefixes.
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

### User experience

- Add a bounded, redacted `runonmine support-bundle` ZIP containing structural diagnostics, audit summaries, service state, checksums, and sanitized log tails without raw configuration or credentials.
- Bound and redact desktop child-process output, make multi-secret credential replacement transactional, and detect incomplete first-run setup from selected roots.
- Prevent desktop sidebar controls and overview metrics from colliding at the minimum supported window size by reserving a fixed footer region and using a responsive metric grid.
- Add a desktop connector setup wizard for Cloudflare Quick Tunnel, Cloudflare OAuth, and OpenAI Secure MCP Tunnel without placing secrets in process arguments.
- Add visual principal/resource policy rule creation and removal, connector credential rotation, secret-path rotation, and confirmed connector removal.

### Maintenance

- Add property-based regression tests for policy precedence, equal-specificity deny behavior, remote safety ceilings, and lexical filesystem traversal rejection.
- Extract Cloudflare/OpenAI connector process supervision, Quick Tunnel URL persistence, and private connector artifact handling into a dedicated module with permission and symlink regression tests.
- Extract loopback HTTP transport, connector authentication, OAuth host routing, and MCP session bindings from the MCP tool implementation into a dedicated module with direct boundary tests.
- Pin and verify the isolated self-hosted runner account, HOME, Cargo homes, captured environment files, and cross-user PATH boundaries in every self-hosted workflow.
- Consolidate pull-request Linux quality gates into one ephemeral self-hosted job while retaining scheduled security/coverage sweeps and the opt-in hosted platform matrix.
- Extract per-principal MCP rate limiting into a dedicated module with deterministic limit, isolation, expiry, and fail-closed regression tests.
- Extract MCP session limits, idle expiry, and protocol session tracking into a dedicated lifecycle module with direct permit-release regression coverage.
- Add a unified `xtask verify` command, machine-readable release acceptance gates, clean-machine smoke scripts, enforced coverage, scheduled fuzzing, and tested desktop layout breakpoints.
- Mark workspace crates as non-publishable by default and provide consistent package description/homepage metadata.
- Add deterministic directory pagination, fixed-size managed-trash names, joined SQLite/supervisor lifecycles, exact platform package manifests, and automatic full-feature/platform CI gates.
- Use one macOS packager configuration source and require advisory-free dependency checks in contributor and CI workflows.
- Redesign the desktop control center with a cohesive dark theme, persistent sidebar navigation, status cards, improved empty states, modern connector and policy workflows, and clearer destructive-action confirmation.
- Move core state and OAuth SQLite connections to dedicated serialized database workers and use asynchronous replies on MCP authorization paths.
- Split CLI connector commands and MCP authorization, argument, and validation layers into focused modules.
- Add component-scoped SQLite schema versions and future-version rejection.
- Centralize internal workspace dependency versions and add an automated version consistency gate.
- Expand the desktop application into a security control center for connectors, roots, policies, OAuth, audit, and diagnostics.
- Pin the repository Rust toolchain to 1.95.0.
- Group Dependabot minor and patch updates to reduce pull-request noise.
- Generate CycloneDX SBOMs with dependency edges, package checksums, and Cargo.lock integrity metadata.
