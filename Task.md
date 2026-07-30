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
- [ ] **P1-05 — Separate platform-native OAuth authority from `shell:exec`.** Introduce explicit platform-native scopes and consent text.
- [ ] **P1-06 — Prevent OAuth client-name impersonation in consent UI.** Show client ID fingerprint, redirect origins, registration time and unverified-client warning.
- [ ] **P1-07 — Namespace OAuth state by connector/issuer.** Clients, authorizations, codes, tokens, sessions and revocation must be connector-specific.
- [ ] **P1-08 — Expire approval rows atomically on timeout.** Audit and state must not temporarily disagree.
- [ ] **P1-09 — Harden browser private-network enforcement across all Chromium targets.** Cover popup, worker, WebSocket, background target and DNS-rebinding paths with adversarial integration tests.
- [ ] **P1-10 — Restrict privileged helper arguments.** Add executable-specific subcommand/argument schemas, path constraints and forbidden flags.
- [ ] **P1-11 — Reduce helper executable verification/execution TOCTOU.** Revalidate file identity or execute from a verified handle where supported.
- [ ] **P1-12 — Make helper installation transactional.** Stage binary/policy/service, restart, health-check and restore the previous installation on failure.
- [ ] **P1-13 — Guarantee agent/helper service restart after reinstall.** Add version handshake, explicit restart, health validation and rollback.
- [ ] **P1-14 — Clarify and strengthen audit tamper resistance.** Include all query-visible fields in the authenticated payload, add keyed integrity/checkpoints where feasible and document the same-user threat boundary.
- [ ] **P1-15 — Reconcile connector enable/disable/remove at runtime.** Disabling or removing a connector must immediately stop live transports and sessions without a manual agent restart.
- [ ] **P1-16 — Make connector removal recoverable and idempotent.** Use tombstones/journaling and startup reconciliation for partial cleanup.
- [ ] **P1-17 — Remove pre-commit OpenAI connector side effects.** Implement prepare/validate/commit/activate with rollback guards.
- [ ] **P1-18 — Allocate OpenAI health ports safely or enforce singleton behavior.** Avoid fixed-port collisions and side effects before validation.
- [ ] **P1-19 — Isolate connector startup failures.** One failed connector must become degraded without taking healthy local or remote connectors down.
- [ ] **P1-20 — Move OpenAI init/doctor out of blocking agent startup.** Activate connectors asynchronously with visible states and deadlines.
- [ ] **P1-21 — Store Quick Tunnel runtime URL as ephemeral state.** Clear stale URLs and keep runtime discovery out of durable desired configuration.
- [ ] **P1-22 — Add managed connector binary update and rollback.** Use versioned verified installs and atomic activation.
- [ ] **P1-23 — Distinguish and harden unmanaged external binaries.** Show trust level and optionally pin ownership/digest.
- [ ] **P1-24 — Strengthen connector binary supply-chain verification.** Add signed manifests/provenance and independent trust roots.
- [ ] **P1-25 — Enforce connector-client compatibility ranges.** Probe supported versions and preserve known-good rollback.

## P2 — Architecture, reliability and maintainability

- [ ] **P2-01 — Split oversized modules.** Refactor desktop main, MCP dispatcher, CLI commands, storage, OAuth store/service, installer and xtask into domain modules.
- [ ] **P2-02 — Break down very long functions.** Replace broad `too_many_lines` suppressions with typed handlers and state transitions.
- [ ] **P2-03 — Separate desktop model/update/effects/views.** Remove direct database, secret and child-process orchestration from rendering code.
- [ ] **P2-04 — Move desktop refresh work off the UI thread.** Use background snapshots, incremental audit verification and pagination.
- [ ] **P2-05 — Zeroize desktop credential inputs.** Use secret wrappers and explicit clearing.
- [ ] **P2-06 — Add StateStore backpressure.** Replace the unbounded worker queue with bounded capacity, timeout and metrics.
- [ ] **P2-07 — Replace approval polling with notifications.** Retain polling only as a recovery fallback.
- [ ] **P2-08 — Preserve sanitized internal error diagnostics.** Keep generic remote errors while logging request/connector/audit references and categories.
- [ ] **P2-09 — Replace silent `.ok()` fallbacks with typed degraded states.** Distinguish missing, disabled, corrupt, unavailable and permission-denied conditions.
- [ ] **P2-10 — Include canonical shell working directory in authorization identity.** Grants and policy decisions must bind command plus `cwd`.
- [ ] **P2-11 — Enforce one combined process-output limit.** stdout and stderr must share a total response/memory budget.
- [ ] **P2-12 — Add browser operation deadlines and stuck-session recovery.** Avoid one call blocking the entire session indefinitely.
- [ ] **P2-13 — Reap orphan browser processes and profiles.** Inventory and clean leftovers on startup.
- [ ] **P2-14 — Support explicit browser executable selection and identity display.** Keep external CDP restrictions intact.
- [ ] **P2-15 — Use immutable GitHub numeric ID as owner authority.** Treat login as display data and migrate safe renames.
- [ ] **P2-16 — Improve transient OAuth provider failure recovery.** Preserve safe retry semantics without permitting replay.
- [ ] **P2-17 — Decide and document OAuth issuer subpath support.** Either support path-based issuers or explicitly enforce/document root-only deployment.
- [ ] **P2-18 — Generate the GitHub User-Agent from package version.** Remove hard-coded version drift.
- [ ] **P2-19 — Use real redaction for service-manager output or rename it accurately.** Do not imply truncation is sanitization.
- [ ] **P2-20 — Record skipped/truncated support-bundle inputs in the manifest.** Make incomplete diagnostics visible.
- [ ] **P2-21 — Enforce robust connector IDs.** Raise minimum length/use UUIDs and apply exact identity redaction.
- [ ] **P2-22 — Reconcile orphan connector artifacts.** Doctor/startup must report and repair config-less directories and runtime state.
- [ ] **P2-23 — Inventory orphan secrets outside purge.** Doctor should report credentials with no configured owner.
- [ ] **P2-24 — Make doctor checks typed and modular.** Standardize ID, severity, status, evidence and remediation.
- [ ] **P2-25 — Standardize machine-readable diagnostics.** Add consistent `--json` output to status/doctor/audit/service commands.
- [ ] **P2-26 — Add crash-recoverable config/secret transactions.** Journal generations and reconcile interrupted changes.
- [ ] **P2-27 — Test interrupted state/config migrations.** Cover process kill, disk full, WAL corruption, restore, downgrade and concurrent migration.
- [ ] **P2-28 — Install user-service executables into a stable versioned location.** Do not depend on a movable archive path.
- [ ] **P2-29 — Use atomic/fsynced writes for all service definitions.** Prevent truncated unit/plist/task files.
- [ ] **P2-30 — Add Windows agent crash recovery.** Use service recovery or an equivalent restart strategy.
- [ ] **P2-31 — Improve macOS LaunchAgent observability.** Add bounded logs, throttle and crash-loop visibility.
- [ ] **P2-32 — Replace environment-only headless master-key delivery.** Prefer systemd credentials and native platform stores with rotation guidance.

## P2 — Test and quality gates

- [ ] **P2-T01 — Raise effective line coverage.** Move global headless baseline from 45% toward 70%, changed lines to 80% and policy/auth/storage to 90%.
- [ ] **P2-T02 — Enable real platform CI on relevant pull requests.** macOS, Windows and ARM jobs must not silently skip security-sensitive changes.
- [ ] **P2-T03 — Fix `dtolnay/rust-toolchain` workflow inputs.** Remove unsupported `toolchain` input and keep exact pinning.
- [ ] **P2-T04 — Expand fuzz targets.** Cover OAuth models/state, MCP headers/sessions, filesystem resolution, archives, redaction, helper frames, approval transitions and browser URL/IP validation.
- [ ] **P2-T05 — Add real MCP protocol end-to-end tests.** Cover initialize, list/call, sessions, expiry/refresh, disable, rate limit, approval, disconnect and malformed transport.
- [ ] **P2-T06 — Add adversarial real-Chromium tests.** Cover private redirects, rebinding, popup, iframe, workers, WebSocket, downloads, file URLs and IPv6 variants.
- [ ] **P2-T07 — Add real helper OS-security acceptance tests.** Cover second users, UID/SID/ACL, replacement races, restart identity and rollback.
- [ ] **P2-T08 — Add soak and performance tests.** Large audit/OAuth/approval state, 64 concurrent calls, crash loops, long desktop/browser sessions and output streams.
- [ ] **P2-T09 — Add mutation/state-machine testing.** Focus policy precedence, OAuth rotation, approval resolve-once, connector lifecycle, emergency lock and migrations.

## P2 — CI, release and supply chain

- [ ] **P2-R01 — Enforce branch protection and required checks.** Require PR review, Linux quality, platform matrix and security ownership; block force-push.
- [ ] **P2-R02 — Sign and notarize release artifacts.** macOS notarization, Windows code signing and signed Linux repositories remain release blockers.
- [ ] **P2-R03 — Complete clean-install acceptance on every artifact/OS.** Record checksum, tester, install, reboot, MCP call, approval, connector, uninstall and residue evidence.
- [ ] **P2-R04 — Generate and validate SBOM with standard tooling.** Include schema validation, target-specific dependencies, hashes and provenance.
- [ ] **P2-R05 — Reduce duplicate dependency versions.** Track binary size, audit surface and platform compatibility while converging direct dependencies.
- [ ] **P2-R06 — Replace substring packaging-target selection with an exact allowlist.** Reject unsupported targets explicitly.
- [ ] **P2-R07 — Write release rollback runbooks.** Cover application, connector binary, database migration and helper rollback.

## P3 — Smaller accumulated debt

- [ ] **P3-01 — Preserve detailed supervisor failure categories.** Distinguish process exit, readiness, stream and cleanup failures.
- [ ] **P3-02 — Report incomplete supervisor cleanup/orphan risk.** Do not label uncertain shutdown as stopped.
- [ ] **P3-03 — Document and instrument in-memory rate/session reset behavior.** Add metrics and restart semantics.
- [ ] **P3-04 — Partition OAuth registration limits by source.** One bad client must not consume all legitimate capacity.
- [ ] **P3-05 — Improve consent recovery after transient GitHub errors.** Avoid unnecessary full restarts while preserving replay safety.
- [x] **P3-06 — Show requester identity in approval UI.** Include principal type, client ID/name and subject after principal-bound storage lands.
- [ ] **P3-07 — Make approval redaction limitations explicit.** Require owner review of the complete effective action.
- [ ] **P3-08 — Verify audit chains incrementally.** Persist the last verified sequence/checkpoint.
- [ ] **P3-09 — Reconcile runtime connector artifacts and health in UI.** Show configured, starting, ready, degraded, failed, backoff and stale-credential states.
- [ ] **P3-10 — Add compatibility and downgrade policy.** State supported migrations and behavior for old/new beta formats.

## Final gate

- [ ] All tasks that are implementable in-repository are complete.
- [ ] External blockers are explicitly marked `[!]` with owner/platform requirements.
- [ ] Full headless verification passes.
- [ ] CLI acceptance passes.
- [ ] Required platform acceptance evidence is attached.
- [ ] `Task.md`, `CHANGELOG.md`, architecture, connections, threat model and platform docs match the implementation.
