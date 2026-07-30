# Changelog

All notable changes to RunOnMine are documented here. The project is still in
pre-release development and does not yet provide compatibility guarantees.

## Unreleased

### Security

- Revoke live connector access after disable/removal without a manual restart: every runtime policy lookup reloads the committed connector state and rejects missing or disabled connectors immediately; successful connector mutations detect a running HTTP agent marker, issue a platform restart with a fresh version handshake, and thereby terminate active MCP sessions and managed tunnel child processes.
- Upgrade core-state audit integrity to schema v3 with a private per-database 256-bit HMAC-SHA256 key, MAC every canonical payload/sequence/hash link, authenticate the current tail, compare every denormalized query column with the canonical payload, reject MAC-column loss on v3 reopen, and preserve one-time v1/v2 migration backfill without legitimizing later truncation.
- Require a running-version handshake after agent and helper installation: helper health now reports protocol and package versions; agent HTTP startup atomically publishes PID, executable identity, instance ID, protocol and package version only after loopback bind; installers explicitly restart services, reject stale markers or old processes, validate active state, and roll back helper upgrades on version mismatch.
- Make privileged-helper installation transactional and serialized by a root/SYSTEM-only install lock: stage the binary, policy and service definition on their destination filesystems before stopping the service; snapshot the previous artifacts and installed/enabled/running state; activate, restart and health-check the new helper; and restore every prior file and service state after partial activation, service-start or health failures.
- Pin privileged-helper execution to a verified open executable: use `O_NOFOLLOW` handle inspection and `/proc/self/fd` inode execution on Linux, retain a read-sharing-only file handle plus volume/file-index identity on Windows, revalidate handle/path identity and SHA-256 immediately before spawn on other platforms, and reject in-place content changes.
- Replace executable-only privileged-helper authorization with version-2 command profiles covering exact subcommands, typed flags and values, deny-first forbidden flags, exact positional schemas, response-file rejection and canonical path roots; make `--allow-program` argument-free and reject legacy broad-argument policies until explicit reinstall.
- Enforce browser private-network policy with a Chromium-process-wide loopback proxy covering popups, dedicated/shared/service workers, background targets, HTTP(S), WebSockets, mixed DNS answers, and DNS rebinding; disable QUIC and non-proxied WebRTC UDP, and reject protected external CDP fail-closed.
- Commit approval timeout state and its `timed_out` audit event in one SQLite transaction, roll back both on audit failure, prevent late owner actions from creating grants, and preserve an owner decision that commits first.
- Namespace OAuth clients, registration limits, authorization state, consents, codes, tokens, and sessions by connector; require connector-qualified administrative revocation and discard legacy namespace-free beta credentials during migration.
- Mark dynamically registered OAuth client names as unverified and show a stable client fingerprint, registration time, requested redirect origin, and every registered redirect origin on the local consent page.
- Split platform-native automation from `shell:exec` with a dedicated `platform:exec` OAuth scope and explicit AppleScript, PowerShell, and D-Bus consent text.
- Default dynamic OAuth registrations that omit `scope` to only `machine:read` instead of every supported capability.
- Require an owner-controlled initial access token for OAuth dynamic client registration; validate before accounting, enforce atomic per-source/global quotas, expire and prune unused clients, recover capacity, and add no-overwrite owner-only token export and rotation.
- Canonicalize privileged executable policy resources with the exact root/SYSTEM ownership and path identity resolver used by the helper allowlist.
- Bind every current-page browser operation to the active normalized origin, include that origin in exact-action grants and approval previews, and re-authorize when the page changes origin during an approval wait.
- Stop printing local HTTP bearer tokens; add an explicit absolute, no-overwrite, current-user-only JSON export channel for enable, rotate, and status, and remove the legacy `--show-token` path.
- Reconcile the Linux per-user systemd sandbox with canonical selected roots, include them as explicit write exceptions, and restart an active service after root changes.
- Bind pending approvals plus temporary and persistent exact-action grants to a transport-aware requester principal fingerprint, isolate OAuth clients and subjects, show requester identity locally, and remove pre-principal grants fail-closed during state migration.
- Resolve filesystem policy resources through the same selected-root identity used by execution so relative paths cannot bypass absolute prefix rules.
- Reject shell composition, pipelines, redirection, command substitution, backticks, and multiline input from command-prefix authorization.
- Reject port zero in loopback connector origins, MCP targets, and health URLs; reject health URL fragments and exercise URL boundary invariants with generated cases.
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

- Extract MCP approval request creation, pending/decision/timeout transitions, and required audit handoff into a dedicated lifecycle module with direct approved, denied, expired, timeout, and audit-failure tests.
- Extract MCP audit event construction, fail-closed persistence policy, and best-effort completion logging into a dedicated module with direct failure-path tests.
- Add committed beta-v0 core-state and beta-v1 OAuth SQLite fixtures that verify safe schema upgrades, preservation of approvals, exact grants, clients, and sessions, and removal of legacy broad temporary grants.
- Add property-based regression coverage for support-bundle redaction of known values, labeled credentials, URLs, email addresses, filesystem paths, IP addresses, and hostnames, including ANSI and NUL obfuscation.
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
