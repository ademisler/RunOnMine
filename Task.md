# RunOnMine hardening task list

This file tracks the full repository audit performed against `main` at commit `c28f079`.

## Completion rules

A task may be checked only when:

1. the implementation is complete;
2. a regression or acceptance test covers the corrected behavior;
3. relevant documentation and the threat model are updated when behavior or a security boundary changes;
4. targeted tests pass;
5. `cargo run --locked -p xtask -- verify --headless` and the applicable acceptance harness pass before the final merge.

Status markers:

- `[ ]` not started
- `[-]` in progress
- `[x]` implemented and verified
- `[!]` blocked by an external platform, signing key, hosted runner, or owner-controlled setting

## P0 — Critical correctness and security

- [x] **P0-01 — Make shell command-prefix authorization safe.** Prevent shell composition, substitution, redirection, pipelines, and multiline payloads from widening a `CommandPrefix` rule. Prefer structured program/argument authorization for future policy rules.
- [x] **P0-02 — Canonicalize filesystem resources before policy evaluation.** Relative paths and alternate spellings must resolve to the same selected-root identity used by execution. Authorize both source and destination for moves.
- [x] **P0-03 — Bind approvals and exact grants to the request principal.** Persist principal kind, OAuth client ID, subject/fingerprint, and isolate temporary/persistent grants between callers. Migrate old grants fail-closed.
- [x] **P0-04 — Make Linux user-service filesystem permissions match selected roots.** Generated systemd units must permit writes to configured roots while preserving hardening; root changes must reconcile the unit.
- [x] **P0-05 — Stop printing local HTTP bearer credentials.** Replace stdout disclosure with an explicit secure reveal/copy/output channel and update documentation and acceptance tests.

## P1 — High-priority security and lifecycle

- [x] **P1-01 — Apply browser-origin policy to every page operation.** Current page origin must authorize read, click, type, press, evaluate, screenshot, snapshot, URL and close operations; redirects and target changes must not become `ResourceContext::None`.
- [x] **P1-02 — Canonicalize privileged executable resources before policy evaluation.** Use the same executable identity as the helper.
- [x] **P1-03 — Harden OAuth Dynamic Client Registration against persistent denial of service.** Validate before consuming rate-limit capacity; add source-aware limits, registration authorization/approval, client expiry/pruning and quota recovery.
- [x] **P1-04 — Use least-privilege OAuth defaults.** Missing `scope` must not grant every supported scope.
- [x] **P1-05 — Separate platform-native OAuth authority from `shell:exec`.** Introduce explicit platform-native scopes and consent text.
- [x] **P1-06 — Prevent OAuth client-name impersonation in consent UI.** Show client ID fingerprint, redirect origins, registration time and unverified-client warning.
- [x] **P1-07 — Namespace OAuth state by connector/issuer.** Clients, authorizations, codes, tokens, sessions and revocation must be connector-specific.
- [x] **P1-08 — Expire approval rows atomically on timeout.** Audit and state must not temporarily disagree.
- [x] **P1-09 — Harden browser private-network enforcement across all Chromium targets.** Cover popup, worker, WebSocket, background target and DNS-rebinding paths with adversarial integration tests.
- [x] **P1-10 — Restrict privileged helper arguments.** Add executable-specific subcommand/argument schemas, path constraints and forbidden flags.
- [x] **P1-11 — Reduce helper executable verification/execution TOCTOU.** Revalidate file identity or execute from a verified handle where supported.
- [x] **P1-12 — Make helper installation transactional.** Stage binary/policy/service, restart, health-check and restore the previous installation on failure.
- [x] **P1-13 — Guarantee agent/helper service restart after reinstall.** Add version handshake, explicit restart, health validation and rollback.
- [x] **P1-14 — Clarify and strengthen audit tamper resistance.** Include all query-visible fields in the authenticated payload, add keyed integrity/checkpoints where feasible and document the same-user threat boundary.
- [x] **P1-15 — Reconcile connector enable/disable/remove at runtime.** Disabling or removing a connector must immediately stop live transports and sessions without a manual agent restart.
- [x] **P1-16 — Make connector removal recoverable and idempotent.** Use tombstones/journaling and startup reconciliation for partial cleanup.
- [x] **P1-17 — Remove pre-commit OpenAI connector side effects.** Implement prepare/validate/commit/activate with rollback guards.
- [x] **P1-18 — Allocate OpenAI health ports safely or enforce singleton behavior.** Avoid fixed-port collisions and side effects before validation.
- [x] **P1-19 — Isolate connector startup failures.** One failed connector must become degraded without taking healthy local or remote connectors down.
- [x] **P1-20 — Move OpenAI init/doctor out of blocking agent startup.** Activate connectors asynchronously with visible states and deadlines.
- [x] **P1-21 — Store Quick Tunnel runtime URL as ephemeral state.** Clear stale URLs and keep runtime discovery out of durable desired configuration.
- [x] **P1-22 — Add managed connector binary update and rollback.** Cloudflare and OpenAI use immutable verified versions with atomic config/manifest/service rollback; legacy OpenAI managed pairs migrate without deletion.
- [x] **P1-23 — Distinguish and harden unmanaged external binaries.** CLI and startup distinguish verified managed, pinned external, and unpinned external binaries; optional pins bind canonical path, digest, owner, mode, size, and modification time.
- [x] **P1-24 — Strengthen connector binary supply-chain verification.** Managed downloads resolve only from embedded 2-of-2 Ed25519 provenance envelopes signed by a shared RunOnMine root plus a provider-specific root; manifests bind the official source repository/commit, release tag and exact platform asset URL/digest/size/format, and signed evidence is retained in new receipts.
- [x] **P1-25 — Enforce connector-client compatibility ranges.** Setup, doctor, update and startup probe supported stable ranges before activation and preserve the known-good active version on rejection.

## P2 — Architecture, reliability and maintainability

- [x] **P2-01 — Split oversized modules.** Desktop rendering is split into a shell plus per-screen view modules; StateStore keeps its public worker/approval surface separate from audit/checkpoint logic, schema migration and tests; MCP keeps the macro-bound tool router separate from runtime identity, server authorization/bootstrap and tests. The connector CLI now routes through typed command-family handlers instead of one monolithic dispatcher.
- [!] **P2-02 — Break down very long functions.** MCP authorization, connector startup, approval-preview formatting and CLI connector setup use typed requests and focused helpers. Desktop rendering is split by screen, but several isolated legacy screen/form/icon functions retain narrow documented `too_many_lines` suppressions until their sections are extracted with regression coverage; full macOS and headless Clippy otherwise pass with warnings denied.
- [x] **P2-03 — Separate desktop model/update/effects/views.** Desktop bootstrap, state model, update/orchestration, background snapshot effects and views live in separate modules; credential and process effects remain outside rendering.
- [x] **P2-04 — Move desktop refresh work off the UI thread.** Config/secret recovery, SQLite/OAuth reads, incremental audit verification, Quick runtime discovery and bounded connector-health HTTP run in one non-overlapping background snapshot; audit history is incrementally paged to 10,000 records.
- [x] **P2-05 — Zeroize desktop credential inputs.** Every desktop field whose identity denotes a secret, token, password, API key or credential now uses `Zeroizing<String>`; existing submit/cancel/reset paths perform explicit zeroization and drop wipes remaining capacity.
- [x] **P2-06 — Add StateStore backpressure.** The serialized SQLite worker uses a bounded 128-job queue, one-second enqueue timeout, overload metrics, and no ambiguous post-acceptance result timeout.
- [x] **P2-07 — Replace approval polling with notifications.** Approval state commits publish an owner-only cross-process filesystem pulse; MCP waiters re-check SQLite immediately on native events and retain a five-second database poll only as recovery for unavailable or missed watcher events.
- [x] **P2-08 — Preserve sanitized internal error diagnostics.** MCP calls carry request UUIDs; internal failures emit opaque incident references and structured local logs with connector, static category/operation, and audit UUID when available. OAuth store failures use request/connector/category correlation while protocol responses remain standard and generic; raw causes and arguments are not logged.
- [x] **P2-09 — Replace silent `.ok()` fallbacks with typed degraded states.** Browser executable selection, privileged-helper policy/service/health, agent restart markers, MCP hostname disclosure, and support-bundle config/service/audit inputs now report explicit `available`, `missing`, `disabled`, `corrupt`, `unavailable`, or `permission_denied` states as applicable; security-sensitive corrupt snapshots fail closed instead of becoming absence.
- [x] **P2-10 — Include canonical shell working directory in authorization identity.** Grants and policy decisions bind the command plus the canonical effective `cwd`.
- [x] **P2-11 — Enforce one combined process-output limit.** stdout and stderr share one total response/memory budget while both pipes continue draining.
- [x] **P2-12 — Add browser operation deadlines and stuck-session recovery.** Every browser/CDP operation has a configurable 1–300 second deadline; timeout cancels the call, quarantines the session, force-terminates owned Chromium, records bounded recovery diagnostics, and permits a clean lazy restart.
- [x] **P2-13 — Reap orphan browser processes and profiles.** Owned Chromium launches write owner-only crash leases with a unique token, exact profile, PID/start identity and executable; HTTP and stdio startup reap only fully matched same-user orphans, clean stale ephemeral profiles, retain persistent data, and fail closed on ambiguous or unsafe entries.
- [x] **P2-14 — Support explicit browser executable selection and identity display.** Local CLI commands select, reset, and inspect one canonical Chrome/Chromium/Edge executable; each launch revalidates the configured binary, local output shows its full path, MCP/support diagnostics expose only source/product/basename, unavailable selections degrade browser tools without trapping config recovery, and external CDP restrictions remain unchanged.
- [x] **P2-15 — Use immutable GitHub numeric ID as owner authority.** GitHub OAuth authorization compares only the positive numeric user ID; login is validated display metadata, successful same-ID renames are atomically reconciled under the config lock, authority/config races fail closed, and OAuth subjects remain `github:<numeric-id>`.
- [x] **P2-16 — Improve transient OAuth provider failure recovery.** GitHub callbacks use short-lived state+code-bound claims: transient provider failures release only the same code for retry, terminal results consume state, concurrent/different-code callbacks fail closed, and successful consent insertion plus state deletion is atomic.
- [x] **P2-17 — Decide and document OAuth issuer subpath support.** OAuth issuers are explicitly root-only; configuration rejects non-root issuer paths and all advertised endpoints are derived from that root origin.
- [x] **P2-18 — Generate the GitHub User-Agent from package version.** Remove hard-coded version drift.
- [x] **P2-19 — Use real redaction for service-manager output or rename it accurately.** Service-manager capture is named `bounded_command_output`; it strips control characters and limits size without claiming secret sanitization.
- [x] **P2-20 — Record skipped/truncated support-bundle inputs in the manifest.** Schema-v3 manifests report each input as complete, partial or missing with included/skipped/truncated counts and no source paths.
- [x] **P2-21 — Enforce robust connector IDs.** New connectors use UUIDs; all layers require 8-64 lowercase token IDs with safe boundaries, and support logs redact configured connector IDs only as exact identity tokens.
- [x] **P2-22 — Reconcile orphan connector artifacts.** HTTP/stdio startup and `doctor --repair` quarantine config-less connector data/state directories, clear orphan Quick runtime records, retain ambiguous/symlinked entries fail-closed, and report typed counts.
- [x] **P2-23 — Inventory orphan secrets outside purge.** Secret writes maintain an owner-only name index with no values; encrypted storage provides complete enumeration, platform keyrings report partial legacy coverage, and doctor reports or explicitly repairs indexed credentials without a configured connector owner.
- [x] **P2-24 — Make doctor checks typed and modular.** Doctor is split into domain handlers and emits stable check IDs with severity, status, bounded evidence and remediation; failures, warnings, repairs and skips share one schema.
- [x] **P2-25 — Standardize machine-readable diagnostics.** Doctor, audit tail, service status and local HTTP status support a common `{schema_version, command, data}` JSON envelope while retaining human-readable defaults.
- [x] **P2-26 — Add crash-recoverable config/secret transactions.** Config/credential updates use an owner-only generation journal, config snapshot digest, and encrypted/keyring transaction backups; prepared crashes roll back, committed crashes finish cleanup, and agent/desktop/CLI startup reconcile before reading config.
- [x] **P2-27 — Test interrupted state/config migrations.** Fault tests cover dropped prepared/committed transactions, journal-write failure before mutation, future journal/schema rejection, corrupted DB preservation and trusted restore, malformed WAL behavior, and concurrent audit-key/schema migration locks.
- [x] **P2-28 — Install user-service executables into a stable versioned location.** User services execute an immutable per-user `service-bin/<package-version>/runonmine-agent`; same-version byte mismatches fail closed and uninstall removes only that managed version.
- [x] **P2-29 — Use atomic/fsynced writes for all service definitions.** Linux units and macOS plists use same-directory temporary files, file fsync, atomic persist, parent fsync and symlink rejection; Windows task settings are applied transactionally through Task Scheduler commands.
- [x] **P2-30 — Add Windows agent crash recovery.** The limited logon task uses Task Scheduler restart-on-failure (three one-minute retries), IgnoreNew instance policy and StartWhenAvailable; Windows cfg cross-checks and policy tests cover the generated settings.
- [x] **P2-31 — Improve macOS LaunchAgent observability.** LaunchAgent uses KeepAlive-on-failure, a 10-second throttle, background process type, private stdout/stderr paths and a tracing writer that continuously truncates stderr before the 5 MiB bound; status reports launchctl state and log sizes.
- [x] **P2-32 — Replace environment-only headless master-key delivery.** Linux system service requires a root-owned private `/etc/runonmine/master-key` and delivers it with `LoadCredential`; the encrypted backend reads `CREDENTIALS_DIRECTORY` first, with `RUNONMINE_MASTER_KEY` retained only as an explicit compatibility fallback.

## P2 — Test and quality gates

- [x] **P2-T01 — Raise effective line coverage.** Measured headless coverage is 74.63% globally and 90.59% for policy/auth/storage/approval-critical modules; CI enforces 70% global, 90% critical and 80% changed executable lines.
- [x] **P2-T02 — Enable real platform CI on pull requests.** macOS, Windows and ARM jobs no longer depend on a repository-variable skip guard and run on every pull request plus manual dispatch.
- [x] **P2-T03 — Fix `dtolnay/rust-toolchain` workflow inputs.** Workflows use a checked-in `rustup` installer with exact toolchain/component/target pins; unsupported action inputs were removed from every workflow.
- [x] **P2-T04 — Expand fuzz targets.** The scheduled eight-target matrix now builds and fuzzes config, policy, OAuth request models, restricted browser URLs, privileged-helper frames, MCP session/header bindings, verified ZIP/TAR entry selection, and real SQLite approval transitions. Every target builds from the committed fuzz lockfile, and the six parser/state targets were smoke-tested with 1,000 real libFuzzer executions each.
- [x] **P2-T05 — Add real MCP protocol end-to-end tests.** A real agent and Streamable HTTP client exercise JSON/SSE initialize, initialized notification, repeated tools/list, machine_info, approval-gated fs_write resolved once through the CLI, invalid authentication, malformed transport and session deletion in an isolated profile.
- [x] **P2-T06 — Add adversarial real-Chromium tests.** Real Chromium exercises private fetch, public-to-private redirect, popup, iframe, download, dedicated/shared/service workers, WebSocket and DNS rebinding while asserting zero private-probe connections; separate tests cover file URLs, credentials, mixed/private destinations and IPv4/IPv6 translation/documentation ranges.
- [!] **P2-T07 — Add real helper OS-security acceptance tests.** Root acceptance now launches the real Unix helper socket for owner UID 1002 and attacker UID 65534, verifies owner/mode 0600, accepts the owner health frame and observes kernel permission denial for the second user. Real Windows SID/pipe impersonation and macOS multi-user evidence still require those external hosts.
- [x] **P2-T08 — Add soak and performance tests.** Deterministic tests cover 64 concurrent admissions, 22,000 authenticated audit rows with incremental checkpoints, 5,000 calls in one Streamable HTTP session, repeated real-Chromium adversarial runs and bounded StateStore/output behavior; the scheduled matrix adds ten browser cycles and a 30-minute macOS desktop lifecycle run.
- [x] **P2-T09 — Add mutation/state-machine testing.** Approval transitions now run against a SQLite-backed reference-model proptest and fuzz target; MCP session binding uses one production transition model shared by middleware, deterministic tests and fuzzing. The scheduled targeted mutation matrix caught all 20 MCP session mutants and all 15 viable approval mutants (six generated approval mutants were unviable), with no surviving mutation.

## P2 — CI, release and supply chain

- [!] **P2-R01 — Enforce branch protection and required checks.** Repository includes an idempotent `gh api` apply/check script requiring review, CODEOWNERS, Linux quality, platform matrix and dependency review while blocking force-push/deletion. The current private-repository plan returns HTTP 403 for this feature, so the GitHub-side policy remains blocked and must not be reported active.
- [!] **P2-R02 — Sign and notarize release artifacts.** Public-beta packaging is explicitly hard-blocked until checked-in Apple Developer ID/notary and Windows Authenticode steps exist. Secret presence alone is not signing evidence; actual signing, notarization, and platform validation require external credentials and owner-controlled hosts.
- [!] **P2-R03 — Complete clean-install acceptance on every artifact/OS.** The hosted workflow is defined to validate Linux x86/ARM, Linux desktop x86_64, macOS universal, and Windows artifacts, but recent hosted jobs ended before checkout with no assigned runner and therefore produced no platform evidence. Development acceptance has exercised universal macOS/Rosetta and physical Ubuntu Xfce desktop flows; the Windows workflow requires a real native window, seven-view contract, `WM_CLOSE` hide-to-tray behavior, current-user NSIS install, HKCU/shortcut verification, retained-data uninstall, and managed-residue cleanup, while GNU/Wine remains supplemental. Candidate release gates remain pending until clean/rebooted OS evidence is recorded for the exact artifact, plus Windows publisher signing and Apple Developer ID signing/notarization for public beta.
- [x] **P2-R04 — Generate and validate SBOM with standard tooling.** Every package receives CycloneDX 1.6 JSON with dependency graph, Cargo.lock SHA-256, exact release target, source revision and included-binary provenance; xtask validates structure and target identity before upload.
- [x] **P2-R05 — Reduce duplicate dependency versions.** Direct production use of rand 0.9 was removed in favor of getrandom, the duplicate metadata ratchet blocks regressions, and attempted major convergence is documented. Remaining rand/nix/crypto major splits are imposed by Chromium/WebSocket, MCP, proptest and command-group upstream compatibility.
- [x] **P2-R06 — Replace substring packaging-target selection with an exact allowlist.** Packaging and packager staging use a six-value exact target enum; suffix/platform spoof strings and unsupported triples are rejected by tests.
- [x] **P2-R07 — Write release rollback runbooks.** `docs/release-rollback.md` covers application, immutable connector binary, database/config generation and privileged-helper rollback with evidence preservation and fail-closed downgrade rules.

## P3 — Smaller accumulated debt

- [x] **P3-01 — Preserve detailed supervisor failure categories.** Supervisor state carries typed spawn, process-exit/status, readiness, shutdown and cleanup categories plus retryability and bounded detail.
- [x] **P3-02 — Report incomplete supervisor cleanup/orphan risk.** Terminal state includes `not_required`, `complete`, or `uncertain` cleanup; uncertain process-group termination sets orphan risk and blocks restart instead of reporting stopped.
- [x] **P3-03 — Instrument and document in-memory session/rate-limit restart resets.** HTTP health exposes a per-process epoch, active-session count and explicit reset semantics; startup logs require clients to reinitialize after restart.
- [x] **P3-04 — Partition OAuth registration limits by source.** Dynamic registration keeps the global cap and adds a transactionally enforced 32-client cap per connector registration source, preventing one source from exhausting every slot.
- [x] **P3-05 — Improve consent recovery after transient GitHub errors.** Completed by P2-16 with code-bound callback claims and bounded provider retry.
- [x] **P3-06 — Show requester identity in approval UI.** Include principal type, client ID/name and subject after principal-bound storage lands.
- [x] **P3-07 — Make approval redaction limitations explicit.** The approval UI warns that redaction hides credential values only and requires review of the complete effective command, path, URL, selector and requester before approval.
- [x] **P3-08 — Expose connector runtime lifecycle in the desktop UI.** Background health snapshots render disabled, on-demand, configured, starting, ready, backoff, degraded, stale-credential, failed, stopped and agent-offline states with bounded stage/detail.
- [x] **P3-09 — Add audit verification checkpoints for desktop refresh.** State schema v4 persists an authenticated checkpoint, re-verifies its real row, scans only new records, invalidates on pruning, reports full/incremental evidence and supports paginated desktop history.
- [x] **P3-10 — Add compatibility and downgrade policy.** The rollback runbook permits downgrade only when target binaries declare current config/state/OAuth schemas compatible; future/irreversible formats require complete backup restore or roll-forward.
- [x] **P3-11 — Enforce documentation consistency.** A complete documentation index covers every file under `docs/`; CI validates local links, anchors, index coverage, and known stale coverage/CI/platform/release claims against current repository contracts.

## Final gate

- [x] All tasks that are implementable in-repository are complete.
- [x] External blockers are explicitly marked `[!]` with owner/platform requirements.
- [x] Full headless verification passes.
- [x] CLI and real Streamable HTTP MCP acceptance pass.
- [!] Required rebooted, signed/notarized macOS and Windows platform evidence remains an external release gate and is not fabricated by repository CI.
- [x] `Task.md`, `CHANGELOG.md`, architecture, connections, threat model and platform docs match the implementation.
