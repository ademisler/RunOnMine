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
| A browser redirects or changes target after navigation and later actions lose their origin rule | every current-page read/action/evaluate/screenshot/close/profile call derives `ResourceContext::Browser` from the active page, binds normalized origin into the grant hash, rechecks after approval waits, and fails closed after repeated changes |
| A relative or alternate file path avoids a resource rule, escapes a selected root, or a move targets a differently restricted path | policy resolution through the same selected-root identity used by execution, descriptor-relative root capabilities, component checks, symlink rejection, authorization of both source and destination, bounded operations |
| The Linux user service policy allows a write but systemd still blocks the selected project | generated `ReadWritePaths` entries include every canonical selected root; setup and desktop root changes reconcile the installed unit and restart it when active |
| Output or errors reveal credentials | generic remote errors, bounded output, desktop child-output redaction, approval redaction, cleared shell environment, no raw environment or stdin audit data |
| Local HTTP setup or recovery leaks its bearer token through terminal logs | bearer values are never printed; explicit export uses an absolute no-overwrite file restricted to the current OS user, and legacy `--show-token` is rejected |
| Support material reveals credentials or private machine data | generated summaries instead of raw config/state files, allowlisted text-log extensions, bounded file count and tails, known-value plus generic redaction, omission of audit arguments and connector identity, no-overwrite owner-only ZIP, per-entry checksum manifest, explicit user review warning |
| A timed-out command or dropped connector supervisor leaves descendants running | Unix process groups and Windows Job Objects terminate the process tree; dropped handles signal shutdown and detach the cleanup task instead of aborting it |
| External connector startup fails after another connector has started | transactional startup explicitly stops and joins partial supervisors; Quick Tunnel observers activate only after all connector initialization succeeds and continue after buffered-event lag |
| Concurrent Quick URL, desktop, setup, browser, or policy writers lose unrelated configuration changes | owner-only configuration sidecar lock, reload-under-lock transaction API, validated atomic replacement |
| A connector credential write/delete fails after another credential or config field changed | all connector credential writers use the config sidecar lock, snapshot each prior value, and restore snapshots before unlocking after handled mutation, validation, or save errors |
| Concurrent local processes overwrite encrypted fallback secrets | owner-only inter-process file locking around every read-modify-write transaction |
| OAuth registration floods or abandoned clients exhaust persistent capacity | owner-controlled 256-bit initial access token, validation before accounting, domain-hashed Cloudflare source keys, atomic per-source/global SQLite windows, 256-client cap, 24-hour unused-client expiry, use-based renewal, and pre-capacity pruning |
| An OAuth dynamic client omits `scope` and silently receives every capability | omission defaults to only `machine:read`; broader scopes must be explicitly registered and later authorization requests remain a subset of that registration |
| A token granted ordinary `shell:exec` silently gains AppleScript, PowerShell, or D-Bus automation | platform-native tools require the distinct `platform:exec` scope, tool discovery checks that exact scope, and consent renders an explicit operating-system automation description |
| A malicious OAuth client claims a trusted product or publisher name in consent | claimed names are labeled unverified; consent shows a stable client-ID fingerprint, UTC registration time, current and all registered redirect origins; display-control characters are rejected and all values are context-escaped |
| SQLite sidecars expose state | private parent directories and owner-only database, WAL, and shared-memory files |
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
