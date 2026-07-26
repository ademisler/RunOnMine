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
| A confused-deputy or prompt-injection request invokes a destructive tool | deny/ask/allow policy, argument-aware local-only approval, exact-hash temporary grants, explicit deny precedence over grants, remote safety ceiling, truthful destructive/open-world annotations |
| A token asks for more authority than granted locally | OAuth scope is intersected with policy and never expands it |
| A file path escapes a selected root or a move targets a differently restricted path | descriptor-relative root capabilities, component checks, symlink rejection, authorization of both source and destination, bounded operations |
| Output or errors reveal credentials | generic remote errors, bounded output, desktop child-output redaction, approval redaction, cleared shell environment, no raw environment or stdin audit data |
| Support material reveals credentials or private machine data | generated summaries instead of raw config/state files, allowlisted text-log extensions, bounded file count and tails, known-value plus generic redaction, omission of audit arguments and connector identity, no-overwrite owner-only ZIP, per-entry checksum manifest, explicit user review warning |
| A timed-out command leaves descendants running | Unix process groups and Windows Job Objects terminate the process tree |
| Concurrent local processes overwrite encrypted fallback secrets | owner-only inter-process file locking around every read-modify-write transaction |
| OAuth registration floods survive behind a public tunnel | SQLite-backed atomic registration windows, registered-client cap, restart-persistent pruning |
| SQLite sidecars expose state | private parent directories and owner-only database, WAL, and shared-memory files |
| A second local user reaches the privileged helper | owner-only Unix socket with peer credentials, or SID-restricted Windows pipe with token validation |
| The helper runs an attacker-replaced executable | absolute allowlist, root/SYSTEM ownership and ACL checks, SHA-256 pinning |
| Browser automation reaches an unrelated daily profile or internal network | isolated profile by default; private-network destinations denied by default; expert attachment requires a credential-free loopback CDP URL; initial and final navigation destinations plus redirects/subresources are validated |
| Audit rows are edited or reordered | BLAKE3 hash chain, retained chain anchor, startup and doctor verification |
| A stale refresh token is replayed | one-time rotation and family-wide revocation on reuse |
| Session identifiers cross connector boundaries | connector-bound session state, 30-minute idle expiry, request body limit, concurrency and rate limits |
| The owner needs to terminate access immediately | local emergency lock stops the service, rejects approvals, clears grants, revokes OAuth state, and invalidates temporary credentials |

## Privileged helper boundary

The helper is absent by default and is not a general privileged shell. During
installation, the owner supplies absolute executable paths. The root/SYSTEM
policy records identity and a SHA-256 digest. Requests are framed and size
limited, arguments are passed without shell parsing, and execution has a
process-tree timeout.

On macOS and Linux, peer credentials must match the installing UID; root is
accepted only for the helper health check used during installation. On Windows,
the pipe rejects remote clients, validates the service as LocalSystem, and
impersonates the client to compare its exact SID to the owner.

## Explicit limitations

`shell_exec` is not a sandbox. Once allowed, it can perform any operation the
agent account can perform. Platform-native scripts, browser actions, and desktop
input can create external side effects.

Hash chaining detects accidental or unsophisticated modification, but cannot
prevent a fully compromised user account from deleting the database and its
anchor. A malicious process already running as the same user can also interact
with user-accessible files and UI outside RunOnMine's control.

Quick Tunnel with no user identity is a temporary development mode, not a substitute for OAuth. Its secret path is a bearer credential and is rotated by the emergency lock. Browser destination validation occurs before navigation, after the final navigation result, and during CDP Fetch interception for redirects and subresources. This reduces SSRF exposure but is not a complete network sandbox.
Unsigned beta packages provide checksums and SBOMs but no publisher identity,
notarization, or code-signing guarantee.
