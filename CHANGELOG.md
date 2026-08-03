# Changelog

All notable changes to RunOnMine are documented here. The project is still in
pre-release development and does not yet provide compatibility guarantees.

## Unreleased

- Re-read the Local HTTP bearer token from the shared secret store on every request so `runonmine lock` invalidates already-issued credentials immediately in a running agent.
- Explicitly load `System.Net.Http` in the Windows smoke test so stale-token rejection works under Windows PowerShell 5.1 as well as newer PowerShell runtimes.
- Make the Windows owner-approval acceptance loop tolerate transient state-store open contention and report the last captured CLI error instead of aborting on PowerShell native-error conversion.
- Use `System.Diagnostics.Process` in Windows acceptance scripts so PowerShell 5.1 cannot turn successful MCP, desktop, installer, or uninstaller runs into false failures through a null `Start-Process.ExitCode`.
- Install SQLite busy handling before lock-taking connection PRAGMAs so owner approval commands wait for an in-flight agent transaction instead of spuriously reporting that setup is missing.
- Treat normal and verbatim absolute Windows paths as the same selected-root identity so approved filesystem tools remain fail-closed without rejecting valid `C:\\...` requests.
- Complete the Linux package lifecycle: canonical `runonmine`/`runonmine-desktop` DEB identities, explicit runtime dependencies, mutual `Conflicts`/`Replaces`, metadata inspection in release/preflight, synthetic beta.0-to-beta.1 upgrade coverage, and full Ubuntu VM install/reboot/uninstall acceptance.
- Make the Linux desktop single-instance through an owner-private Unix socket; a second launch asks the primary process to restore/focus its window, while stale or unsafe filesystem entries fail closed.
- Persist an explicitly supplied headless user-service master key into a private same-user systemd credential source, prefer explicit headless key material over ambient session detection, and verify user/system services across real VM reboots.
- Observe Cloudflare Quick Tunnel URLs from both stdout and stderr and clear configured Quick runtime records during emergency lock before access is restored.
- Preserve external-binary pin verification inside hardened Linux user services by normalizing only kernel-declared UID/GID user-namespace mappings and overflow identities; path, digest, size, modification time, and mode remain strict.
- Render the Windows control center through eframe WGPU/Direct3D instead of requiring OpenGL, while retaining Glow on macOS and Linux; add a platform renderer regression test.
- Update `event-listener` to 5.4.2 so the dependency graph is no longer affected by RUSTSEC-2026-0221.
- Remove the unused `trash` dependency; RunOnMine uses its own descriptor-relative managed trash, and the stale crate also forced an incompatible Windows bindings version into the Direct3D graph.
- Make Windows desktop viewport acceptance numeric instead of string-based so Windows PowerShell 5.1 decimal formatting cannot reject the correct 1320×860 and 1040×680 contracts.
- Audit the complete documentation set against CLI help, package manifests, acceptance scripts, and workflows; add a comprehensive documentation index plus automated relative-link, anchor, index-coverage, stale-claim, MCP-tool-inventory, and headless/desktop clean-install evidence-template validation to Linux CI.
- Correct platform build paths, coverage thresholds, unconditional hosted-platform CI semantics, Windows retained-data uninstall wording, and hosted-runner pre-start evidence handling. Hard-block public-beta packaging until checked-in Apple and Windows signing steps exist instead of treating secret presence as signing evidence.
- Bring the Linux and Windows control centers to the macOS desktop contract: one seven-screen UI, native Open/Lock/Quit tray actions, dynamic tray status, application icons, close-to-tray behavior, and an in-app Diagnostics integration card. Linux uses freedesktop StatusNotifierItem without GTK/AppIndicator; Windows release binaries use the GUI subsystem.
- Add deterministic cross-platform desktop reports, isolated seven-view Xvfb acceptance, physical Xfce StatusNotifier close/reopen acceptance, real-window/WM_CLOSE Windows acceptance, and current-user NSIS install/uninstall residue checks. Hosted Windows preflight verifies render/report and package lifecycle without claiming an interactive HWND/tray result; GNU/Wine remains explicit supplemental Windows compatibility evidence.
- Add Windows application and installer artwork, English/French/Turkish NSIS UI, HKCU current-user installation, Start Menu/desktop shortcuts, and explicit cleanup of standard RunOnMine roaming/local application-data roots when the user elects to remove app data.
- Make MCP HTTP acceptance own and terminate the real agent PID, with bounded TERM/KILL cleanup, so successful smoke runs cannot orphan listeners or deleted temporary state.
- Add a standalone Linux x86_64 desktop DEB with all four RunOnMine binaries, a freedesktop menu entry and icon, four-binary SBOM/archive provenance, Xvfb launch acceptance, and real install/remove preflight coverage.
- Keep `tray-icon` target-specific to macOS/Windows, use `ksni` StatusNotifierItem integration on Linux without GTK/AppIndicator, and keep Linux emergency lock scoped to the current user service.

- Restore macOS desktop compilation by declaring its direct Serde dependency and remove platform-only warning regressions exposed by full-feature Clippy.
- Make every cargo-packager 0.11.8 configuration self-identifying and resolve license, binary, output, and resource paths from the configuration directory; add an xtask regression gate for this contract.
- Validate the universal macOS DMG on a physical Apple-silicon Mac through native and Rosetta launches, LaunchAgent lifecycle, Streamable HTTP MCP approval flow, all desktop navigation views, retained-data uninstall, full purge, and user-state restoration. Developer ID signing, notarization, and reboot evidence remain separate release gates.

- Make GitHub OAuth callback recovery replay-safe with short-lived state+code claims, bounded user-endpoint retries, atomic consent completion, and explicit root-only issuer deployment.

### Security

- Add a real Streamable HTTP MCP acceptance client covering JSON/SSE negotiation, session lifecycle, repeated discovery, a safe read, an owner-approved exact fs_write, negative authentication/malformed requests and disconnect.
- Share one access-bound, expiring MCP session transition model between production middleware, deterministic tests, fuzzing and targeted mutation testing; all 20 generated session mutants are caught.
- Pre-scan verified ZIP and gzip-TAR releases for unsafe, non-regular or duplicate executable entries before creating the destination, and fuzz the exact production scanners.
- Expand the scheduled fuzz matrix to eight build-verified targets and add SQLite-backed approval reference-model tests plus targeted mutation checks with no surviving viable approval mutant.
- Split desktop rendering into per-screen modules, StateStore into worker/approval, audit/checkpoint, migration and test modules, and MCP into macro-bound tools, runtime identity, authorization/bootstrap and tests; replace the monolithic connector CLI dispatcher with typed command-family handlers.
- Remove every `clippy::too_many_lines` suppression by extracting MCP authorization decisions, Cloudflare supervisor setup, approval-preview formatters and connector setup/credential flows into focused helpers.
- Persist authenticated incremental audit-verification checkpoints and move desktop config/state/OAuth/audit/connector-health refresh into a bounded background snapshot.
- Extend real Chromium private-network regression coverage to redirects, popups, iframes, downloads, workers, WebSockets, rebinding, file URLs and IPv6 variants, with zero private-probe connections.
- Verify the Unix helper boundary with real distinct UIDs and a kernel-enforced owner-only socket; add fresh-host artifact preflight workflows without claiming reboot or publisher signing.
- Remove direct production rand 0.9 usage in favor of fallible getrandom calls and raise enforced measured coverage to 70% global / 90% critical / 80% changed lines.

- Store desktop credential, token, password and API-key form inputs in zeroizing memory and explicitly wipe existing submit/cancel/reset paths instead of retaining ordinary `String` buffers.
- Make macOS, Windows and ARM platform CI unconditional for relevant pull requests and replace unsupported Rust-toolchain action inputs with a checked-in exact `rustup` installer.
- Add global/critical/changed-line coverage ratchets, three additional fuzz targets, a 64-concurrent-call admission soak test, an observable MCP process epoch, and per-source OAuth registration limits.
- Replace release-target substring matching with an exact six-target allowlist and validate per-target CycloneDX 1.6 SBOM provenance before upload.
- Add clean-install evidence validation, duplicate-dependency ratcheting, branch-protection automation, public-release signing-material gates, and explicit application/connector/database/helper rollback policy.
- Type connector supervisor failures and cleanup outcomes; uncertain process-group termination now reports orphan risk and blocks restart rather than claiming a clean stop.
- Make config/secret updates crash-recoverable with generation journals, config snapshot digests, backend-protected secret backups, startup reconciliation, and fault tests for process loss, write failure, downgrade, corrupt SQLite/WAL, restore, and concurrent migration.
- Install user agents from immutable per-user version directories, atomically/fsync service definitions, add Windows scheduled-task restart policy, and add macOS crash throttling plus continuously bounded private service logs.
- Deliver the headless Linux master key through a root-owned systemd credential; environment delivery remains only a documented compatibility fallback.
- Add startup and doctor reconciliation for config-less connector artifacts: valid orphan directories are preserved in owner-only quarantine, stale Quick Tunnel runtime records are removed, and ambiguous or symlinked entries remain untouched and visible.
- Maintain a credential-name-only owner index so doctor can report and explicitly repair orphan connector secrets without exposing values; encrypted storage has complete enumeration while legacy platform-keyring coverage is marked partial.
- Replace the monolithic doctor output with typed modular checks and add a shared versioned JSON envelope to doctor, audit tail, service status, and local HTTP status.
- Require connector IDs to be 8-64 lowercase ASCII token characters with alphanumeric boundaries; keep UUIDs for generated connectors, reject ambiguous legacy beta IDs fail-closed, and redact configured connector IDs only at exact identity boundaries in support logs.
- Upgrade support bundles to schema v3 with privacy-preserving input completeness records for included, skipped and truncated log material; rename service-manager capture to bounded command output rather than implying that truncation sanitizes secrets.
- Preserve sanitized internal diagnostics without widening remote errors: MCP tool, authorization, approval, audit, storage, browser, helper and output failures now carry request/incident correlation and audit UUIDs when available; OAuth storage failures log bounded request/connector/category/operation fields while public OAuth bodies remain unchanged. Raw causes, arguments and secrets are excluded from these structured failure logs.
- Make the immutable GitHub numeric user ID the sole OAuth owner authority. GitHub login is now display metadata: a verified same-ID rename is atomically reconciled into config, while ID mismatch, invalid provider metadata, connector removal, or concurrent authority changes fail closed without mutating the stored owner.
- Add explicit Chrome, Chromium, or Edge executable selection with `browser executable set|auto|show`. Selection stores a canonical supported binary, every launch revalidates it, missing selections degrade only browser availability, local CLI output shows the exact path, and MCP/support diagnostics expose only bounded source/product/basename identity; external CDP remains loopback-only, local-only, and incompatible with protected mode.
- Track every owned Chromium launch with an owner-only crash lease and reconcile browser leftovers before HTTP or stdio startup. Reaping requires same-user, token, exact profile, executable and PID/start-time evidence; ambiguous processes are retained and reported, while stale disposable profiles are removed.
- Bound every browser/CDP operation with a configurable deadline and recover timed-out sessions by quarantining the connection, force-terminating owned Chromium, cleaning ephemeral state, and lazily starting a fresh session; expose only bounded timeout counters and operation categories in browser diagnostics.
- Replace 250 ms approval database polling with cross-process native filesystem notifications emitted after committed approval changes. MCP approval waits now re-check state immediately on owner decisions and use a five-second SQLite poll only as recovery when watcher events are unavailable or missed.
- Replace live GitHub release-metadata trust for managed connector downloads with embedded threshold-signed provenance catalogs: every accepted Cloudflare or OpenAI artifact is bound to an official source repository and commit, release tag, exact asset URL, SHA-256, size and archive format by both a shared RunOnMine Ed25519 root and an independent provider root. Persist the signed envelope in new receipts and re-verify it during managed binary startup; legacy digest-only receipts remain readable and upgrade on the next managed update.
- Bound the serialized StateStore SQLite worker to 128 queued jobs with a one-second sync/async enqueue timeout and observable queue, active, high-watermark, rejected and completed counters. Accepted database operations are never abandoned behind a reply timeout, avoiding ambiguous late commits.
- Enforce connector-client compatibility before setup, doctor, managed update and agent process start: stable OpenAI tunnel-client `0.0.10` and stable cloudflared releases in the supported date-version range are accepted; prerelease, old and future-incompatible clients fail before activation and leave the known-good active manifest unchanged.
- Route connector startup, CLI loading, doctor/list trust reporting, and external pinning through one binary trust resolver: immutable managed versions require matching private receipts, pinned external binaries require canonical path/digest/ownership/metadata continuity, changed pins fail before process start, and unpinned external binaries remain visible with an explicit warning.
- Complete `connect update-managed-binaries` for managed Cloudflare and OpenAI connectors: stage, receipt-verify, compatibility-probe and store a new immutable version, atomically rewrite only managed config paths, activate the manifest, restart the running agent, and restore both config and active version on failure. Valid legacy OpenAI binary/receipt pairs migrate into the version store without deleting the originals.
- Bind `shell_exec` authorization, exact-action grants, approval previews, audit identity, and execution to the canonical effective working directory; filesystem-prefix rules now evaluate that directory alongside the command resource.
- Enforce one combined stdout/stderr retention budget for user shell, connector probe/init/doctor, platform-native automation, privileged helper, and desktop CLI child processes while continuing to drain both pipes after the budget is exhausted.
- Preserve invalid or incomplete managed Cloudflare binary/receipt pairs and fail closed instead of deleting them implicitly during connector setup; repair and rollback now require an explicit managed-binary operation.
- Generate the GitHub OAuth owner-verifier User-Agent from the workspace package version so network diagnostics cannot drift from the running build.
- Move Cloudflare Quick Tunnel public URL discovery out of durable configuration into a private generation-bound runtime store; clear legacy/stale URLs, reject stale observer writes, clear discovery during restart/backoff, remove state on stop, and keep corrupt runtime artifacts scoped to the affected connector.
- Move OpenAI tunnel-client `init` and `doctor` out of blocking agent startup: after the loopback listener binds, each OpenAI connector activates in an owned background task with a 75-second preparation deadline and a separate 30-second readiness deadline; runtime phases (`starting`, `backoff`, `ready`, `degraded`, `stopped`) are exposed only through the direct-loopback `/healthz/connectors` endpoint, while forwarded or public Host requests receive `404`.
- Enforce OpenAI Secure MCP Tunnel as an explicit configured singleton while it uses the fixed loopback health endpoint; a second OpenAI connector is rejected during pure configuration validation even when configured with a different auxiliary port, before binary/profile staging, credential writes, `init`, or `doctor` can run.
- Remove pre-commit OpenAI connector side effects: validate the candidate before preparation, build profile/health artifacts only in owner-private staging, run `init` and `doctor` against the prepared immutable tunnel-client path, then revalidate the final candidate before committing configuration, credentials and version activation. Handled failures restore prior configuration, credentials and active version; incomplete or integrity-invalid legacy pairs are preserved and rejected fail-closed.
- Make connector removal recoverable and idempotent with an owner-only, process-locked phase journal: record intent before configuration mutation, fingerprint the exact connector, remove configuration/secrets, approvals/grants, scoped OAuth rows and artifact directories in monotonic restartable phases, reconcile pending records before HTTP or stdio agent startup, and block connector-ID reuse until cleanup completes.
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
- Serialize high-frequency durable configuration read-modify-write operations across the agent, desktop, and CLI with an owner-only sidecar lock so setup, browser, policy, and connector mutations cannot silently overwrite one another.
- Isolate external connector startup failures per connector: retain already-started healthy supervisors, record the failed connector as degraded in memory with a structured error log, continue bringing up the local HTTP agent and unrelated transports, lazily open the secret store only for OpenAI startup, and activate Quick Tunnel URL observers only for successfully started Quick connectors.
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
- Harden the dedicated self-hosted Linux quality runner with an unprivileged account while keeping macOS, Windows, ARM, and artifact preflight on GitHub-hosted runners.

### User experience

- Replace ambiguous diagnostics fallbacks with typed degraded states. MCP machine information, browser profile diagnostics, privileged-helper status, agent restart handshakes, and support-bundle schema v2 now distinguish available, missing, disabled, corrupt, unavailable, and permission-denied conditions where relevant; legacy booleans remain for compatibility, while corrupt prior helper policy snapshots fail closed.
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
- Extract Cloudflare/OpenAI connector process supervision, Quick Tunnel runtime discovery, and private connector artifact handling into a dedicated module with permission and symlink regression tests.
- Extract loopback HTTP transport, connector authentication, OAuth host routing, and MCP session bindings from the MCP tool implementation into a dedicated module with direct boundary tests.
- Pin and verify the isolated self-hosted runner account, HOME, Cargo homes, captured environment files, and cross-user PATH boundaries in every self-hosted workflow.
- Consolidate pull-request Linux quality gates into one ephemeral self-hosted job while retaining scheduled security/coverage sweeps and the unconditional hosted platform matrix.
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
