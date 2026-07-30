# Threat Model

This model covers the local agent, connector processes, embedded OAuth server,
browser automation, desktop control, and optional privileged helper. It assumes
the operating system and official external tunnel binaries are not already
compromised.

## Assets

- files and credentials available to the agent's operating-system account;
- browser sessions and cookies in RunOnMine's isolated profile;
- connector, OAuth, and tunnel credentials;
- local policy and approval decisions;
- privileged helper policy and IPC identity;
- the integrity of the audit trail.

## Trust boundaries

1. the public tunnel endpoint to loopback HTTP;
2. the MCP client identity and requested OAuth scopes;
3. OAuth scope to local connector policy;
4. local policy to the approval UI or CLI;
5. the user agent to operating-system files, processes, browser, and desktop;
6. the unprivileged agent to the optional root or LocalSystem helper.

## Threats and controls

| Threat | Primary controls |
| --- | --- |
| An internet user discovers a tunnel endpoint | Quick paths contain 256 random bits; permanent connections use OAuth; invalid paths return 404 |
| A forged Host authority routes a request into the public OAuth connector | exact configured hostname matching, only absent/default HTTPS port 443 accepted, unmatched authorities return 404 |
| A confused-deputy or prompt-injection request invokes a destructive tool | deny/ask/allow policy, argument-aware local-only approval, exact connector/principal/tool/argument grants, explicit deny precedence over grants, remote safety ceiling, truthful destructive/open-world annotations |
| A token asks for more authority than granted locally | OAuth scope is intersected with policy and never expands it |
| An OAuth client reuses another caller's prior approval | grants and pending approvals are bound to a domain-separated requester fingerprint containing connector transport and exact OAuth client/subject identity; legacy connector-wide grants are removed during migration |
| A shell command-prefix rule is widened with a second command | prefix matching rejects control operators, pipelines, redirection, command substitution, backticks, and multiline shell text; complex commands remain approval-gated |
| A shell approval created in one project directory is reused in another | the requested or effective current directory is resolved to one existing canonical directory; command and canonical `cwd` are evaluated as separate resources and included together in the exact-action grant identity and executed request |
| A browser redirects or changes target after navigation and later actions lose their origin rule | every current-page read/action/evaluate/screenshot/close/profile call derives `ResourceContext::Browser` from the active page, binds normalized origin into the grant hash, rechecks after approval waits, and fails closed after repeated changes |
| A relative or alternate file path avoids a resource rule, escapes a selected root, or a move targets a differently restricted path | policy resolution through the same selected-root identity used by execution, descriptor-relative root capabilities, component checks, symlink rejection, authorization of both source and destination, bounded operations |
| The Linux user service policy allows a write but systemd still blocks the selected project | generated `ReadWritePaths` entries include every canonical selected root; setup and desktop root changes reconcile the installed unit and restart it when active |
| Output or errors reveal credentials or exhaust memory | generic remote errors, redaction, cleared shell environment, no raw environment or stdin audit data, and one combined stdout/stderr retention budget across shell, connector one-shot/probe, platform-native, privileged-helper, and desktop child processes while readers keep draining excess bytes |
| Local HTTP setup or recovery leaks its bearer token through terminal logs | bearer values are never printed; explicit export uses an absolute no-overwrite file restricted to the current OS user, and legacy `--show-token` is rejected |
| Support material reveals credentials or private machine data | generated summaries instead of raw config/state files, allowlisted text-log extensions, bounded file count and tails, known-value plus generic redaction, omission of audit arguments and connector identity, no-overwrite owner-only ZIP, per-entry checksum manifest, explicit user review warning |
| A timed-out command or dropped connector supervisor leaves descendants running | Unix process groups and Windows Job Objects terminate the process tree; dropped handles signal shutdown and detach the cleanup task instead of aborting it |
| A renderer or CDP request stalls while holding the browser session lock | every browser operation has a bounded configurable deadline; timeout cancellation releases the lock, quarantines the active connection, force-terminates owned Chromium, removes ephemeral state, and allows a clean lazy restart; external CDP is disconnected but never killed |
| An agent crash leaves owned Chromium or disposable profiles behind | owner-only per-launch leases bind a random token, canonical profile/executable, owner PID/start identity and browser PID/start identity; startup reaps only fully matched same-user processes, defers live owners and ambiguous evidence, removes confirmed stale disposable profiles, and never kills external CDP |
| One external connector fails discovery, credential loading, preparation, health-command construction or supervisor startup after another connector has started | per-connector startup error boundary; structured degraded record containing connector ID/kind and sanitized authentication/process stage; previously started healthy supervisors and observers remain alive; local HTTP startup continues; OpenAI credential-store access is lazy and isolated; Quick URL observers attach only to successful Quick supervisors |
| OpenAI `init`, `doctor`, or readiness blocks agent availability or survives shutdown | OpenAI activation runs in a cancellable background task after loopback bind; bounded preparation/readiness deadlines; explicit starting/backoff/ready/degraded/stopped registry; shutdown signal consumes and stops the supervisor before task join; lifecycle detail is available only through a direct-loopback Host/port-checked endpoint and excludes secrets/process output |
| A stale Quick Tunnel observer republishes an old public URL, or corrupt runtime state aborts unrelated connectors | private generation-bound runtime records; stale writes/clears are rejected; restart/backoff clears discovery; stop removes the generation; runtime cleanup failures remain inside the affected connector startup boundary |
| Concurrent desktop, setup, browser, policy, or connector writers lose unrelated configuration changes | owner-only configuration sidecar lock, reload-under-lock transaction API, validated atomic replacement |
| A connector credential write/delete fails after another credential or config field changed | all connector credential writers use the config sidecar lock, snapshot each prior value, and restore snapshots before unlocking after handled mutation, validation, or save errors |
| OpenAI connector setup fails after downloading a client, writing a profile, storing a runtime key or exposing only part of the final artifacts | validate before preparation; owner-private same-filesystem binary/profile/state staging; staged `init` and `doctor`; configuration-lock commit followed by no-overwrite activation; transaction markers and digest/receipt ownership checks; rollback of prior config/secret values and transaction-owned artifacts; invalid existing managed installations preserved and rejected fail-closed |
| GitHub release metadata, an upstream release account, or one RunOnMine catalog signing key is compromised | managed selection ignores live release metadata; a bounded embedded manifest must carry valid Ed25519 signatures from both the shared RunOnMine root and the provider-specific root, and binds official repository, source commit, tag, URL, digest, size and format; duplicate, missing, cross-provider or tampered signatures fail closed before download |
| Connector setup encounters a tampered or incomplete managed binary installation | binary and receipt presence must match; symlinks and non-regular files are rejected; provider/path/digest verification fails closed; setup preserves the existing artifacts instead of deleting or replacing forensic state implicitly |
| A configured external connector binary is replaced after owner review | optional owner-only pins bind connector kind, canonical path, SHA-256, file size, modification time and platform ownership/mode; startup re-verifies the pin before process creation and confines mismatch failure to that connector |
| A managed connector update activates a binary but config save or service restart fails | immutable preparation, receipt verification and compatibility probing precede mutation; config replacement, active-manifest switch and running-agent restart are one rollback-aware transaction for Cloudflare and OpenAI; failure restores the prior config and active version while preserving version artifacts |
| An official connector release changes its CLI contract or a prerelease is selected | code-owned stable compatibility ranges are enforced during setup, doctor, update and startup; an incompatible candidate is rejected before manifest activation and the known-good version remains selected |
| A legacy managed OpenAI binary is migrated incompletely | the legacy binary/receipt pair is verified and compatibility-probed first, then copied into a digest-addressed immutable version; originals are preserved and activation remains rollback-aware |
| Multiple OpenAI connectors contend for the fixed tunnel-client health listener | explicit one-configured-OpenAI singleton validation, independent auxiliary-port uniqueness checks, and candidate validation before staging, credential writes or external process execution |
| A crash or filesystem error leaves connector removal half-complete, or the same ID is recreated over stale state | owner-only process lock and bounded phase journal written before mutation; exact connector fingerprint; idempotent config/secret, authorization, OAuth and directory cleanup; HTTP/stdio startup reconciliation; ID reuse blocked until journal completion |
| Concurrent local processes overwrite encrypted fallback secrets | owner-only inter-process file locking around every read-modify-write transaction |
| OAuth registration floods or abandoned clients exhaust persistent capacity | owner-controlled 256-bit initial access token, validation before accounting, domain-hashed Cloudflare source keys, atomic per-source/global SQLite windows, 256-client cap, 24-hour unused-client expiry, use-based renewal, and pre-capacity pruning |
| An OAuth dynamic client omits `scope` and silently receives every capability | omission defaults to only `machine:read`; broader scopes must be explicitly registered and later authorization requests remain a subset of that registration |
| A token granted ordinary `shell:exec` silently gains AppleScript, PowerShell, or D-Bus automation | platform-native tools require the distinct `platform:exec` scope, tool discovery checks that exact scope, and consent renders an explicit operating-system automation description |
| A malicious OAuth client claims a trusted product or publisher name in consent | claimed names are labeled unverified; consent shows a stable client-ID fingerprint, UTC registration time, current and all registered redirect origins; display-control characters are rejected and all values are context-escaped |
| SQLite sidecars expose state | private parent directories and owner-only database, WAL, and shared-memory files |
| A burst of MCP authorization, approval or audit work exhausts memory through the state worker | bounded 128-job SQLite queue; one-second enqueue backpressure for synchronous and asynchronous callers; rejected/high-watermark/completed metrics; dangerous paths fail closed when enqueue is unavailable; accepted jobs have no ambiguous late-commit reply timeout |
| Approval polling creates sustained SQLite load or a filesystem notification is lost | committed insert/resolve/timeout/removal/emergency-lock transitions publish an owner-only atomic pulse watched across processes; waiters subscribe before reading status and re-check immediately on an event; a five-second SQLite poll remains only as recovery, and the timeout transaction still arbitrates races atomically |
| A second local user reaches the privileged helper | owner-only Unix socket with peer credentials, or SID-restricted Windows pipe with token validation |
| The helper runs an attacker-replaced executable | absolute allowlist, root/SYSTEM ownership and ACL checks, SHA-256 pinning |
| An alternate executable path spelling avoids a canonical admin policy rule | MCP authorization and helper allowlist installation share the same root/SYSTEM-owned, non-symlink canonical program identity |
| A hash-pinned helper executable is abused through dangerous subcommands, flags, response files, or path arguments | executable-specific command schemas; exact subcommand and positional sequence; allowlisted typed flag values; deny-first forbidden flags; response-file rejection; canonical existing/create path roots; argument-free compatibility entries |
| An allowlisted helper executable is replaced between verification and process creation | opened-file identity and SHA-256 verification; `O_NOFOLLOW`; Linux execution through the verified `/proc/self/fd` inode; Windows read-sharing-only handle and volume/file-index checks; immediate handle/path identity and digest revalidation on other platforms |
| Helper upgrade fails after replacing only part of the privileged installation, or overlaps another install/uninstall | root/SYSTEM-only process lock; same-filesystem staging; previous binary/policy/service snapshots; explicit stop, activation, restart and authenticated health phases; reverse-order artifact and installed/enabled/running service-state rollback; failed first-install cleanup |
| Browser automation reaches an unrelated daily profile or internal network through a popup, worker, background target, WebSocket, mixed DNS answer, or DNS rebinding | isolated profile by default; process-wide loopback proxy with no implicit bypass; QUIC and non-proxied WebRTC UDP disabled; every connection re-resolves and rejects any mixed/private answer before exact-IP connect; CDP URL checks remain defense in depth; protected external CDP fails closed |
| Audit rows are edited or reordered | BLAKE3 hash chain, retained chain anchor, startup and doctor verification |
| A stale refresh token is replayed | one-time rotation and family-wide revocation on reuse |
| Session identifiers cross connector boundaries | connector-bound session state, 30-minute idle expiry, request body limit, concurrency and rate limits |
| The owner needs to terminate access immediately | local emergency lock stops the service, rejects approvals, clears grants, revokes OAuth state, and invalidates temporary credentials |

## Privileged helper boundary

The helper is absent by default and is not a general privileged shell. During
installation, the owner supplies absolute executable paths and either an
argument-free compatibility entry or a versioned command profile. The
root/SYSTEM policy records identity, a SHA-256 digest, exact subcommands,
allowlisted typed flags, deny-first forbidden flags, exact positional schemas,
and canonical path constraints. Requests are framed and size limited, arguments
are passed without shell parsing, and execution has a process-tree timeout.
Version-1 broad-argument policies are rejected and require reinstall.

On macOS and Linux, peer credentials must match the installing UID; root is
accepted only for the helper health check used during installation. On Windows,
the pipe rejects remote clients, validates the service as LocalSystem, and
impersonates the client to compare its exact SID to the owner.

## Explicit limitations

Approval timeout state and its `timed_out` audit event are committed in one SQLite transaction. If audit insertion fails, the state transition rolls back and the row remains pending. A late approval cannot create a temporary or persistent grant after the timeout commits. If the machine owner's decision commits first, the timeout transition returns that existing decision and the owner action is honored and audited instead.

`shell_exec` is not a sandbox. Once allowed, it can perform any operation the
agent account can perform. Platform-native scripts, browser actions, and desktop
input can create external side effects.

Hash chaining detects accidental or unsophisticated modification, but cannot
prevent a fully compromised user account from deleting the database and its
anchor. A malicious process already running as the same user can also interact
with user-accessible files and UI outside RunOnMine's control.

Quick Tunnel with no user identity is a temporary development mode, not a substitute for OAuth. Its secret path is a bearer credential and is rotated by the emergency lock. Browser destination validation occurs before navigation, after the final navigation result, during CDP Fetch interception, and at the browser-process-wide proxy for every HTTP(S) or WebSocket connection. The proxy is not a defense against a compromised Chromium process or another malicious process already running as the same user.
Unsigned beta packages provide checksums and SBOMs but no publisher identity,
notarization, or code-signing guarantee.

The helper's executable check and process creation are tied to one retained
file handle. Linux executes the verified inode through `/proc/self/fd`, while
Windows keeps a handle whose sharing mode prevents write, delete, or replacement
until the process has been created. macOS and other Unix builds revalidate the
retained handle against a freshly opened canonical path and digest immediately
before spawn; this is risk reduction rather than a kernel-level immutable-exec
guarantee. Root/SYSTEM or kernel compromise remains out of scope.

Handled helper installation failures are fail-safe. The old service is not
stopped until every replacement artifact is staged and every existing artifact
is snapshotted. A privileged process lock prevents overlapping install and
uninstall operations. Activation, platform service restart and authenticated
health are one transaction; rollback restores both files and the previous
installed/enabled/running state. A previously running helper must pass health
again after restoration. Sudden power loss or process termination between
filesystem operations is not yet a durable journaled transaction and remains a
separate recovery item.
