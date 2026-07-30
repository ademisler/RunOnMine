# Architecture

RunOnMine is a local-first Rust workspace. The AI model continues to run in the
user's chosen AI service; tool calls execute on a machine the user owns.

## Processes

- `runonmine` manages setup, connectors, policies, approvals, diagnostics, audit export, and services.
- `runonmine-agent` serves MCP over stdio or loopback Streamable HTTP.
- `runonmine-desktop` provides the local approval window, settings, and tray menu.
- `runonmine-helper` is an optional, separately installed privileged process.

Shared crates isolate configuration and persistence, MCP routing, OAuth,
connectors, Chromium automation, and operating-system adapters. Within
`runonmine-mcp`, tool dispatch remains in the crate root, `approval_flow.rs`
owns approval request creation, owner-decision polling, timeout/expiry transitions,
and the required audit handoff. `audit.rs` owns audit event construction plus
fail-closed persistence for dangerous capabilities, `http.rs` owns the loopback
transport, connector authentication, public Host routing, and HTTP MCP session
bindings, and `managed_connectors.rs` owns
Cloudflare/OpenAI process supervision plus private connector artifacts. In the CLI,
`connector_transactions.rs`
coordinates connector config and credential changes separately from transport setup and
user interaction in `connectors.rs`. The `desktop-control` feature contains capture and input
dependencies. Linux/VPS builds with `--no-default-features` do not include those
dependencies.

The normal agent always runs as the signed-in user. The Linux per-user unit keeps
home and the system read-only except for RunOnMine state plus the exact canonical
roots selected in configuration. Root additions and removals reconcile an
installed unit and restart it when active. The Linux headless system unit is
installed by root but runs as an explicitly selected non-root account. Installing
either normal service never installs the privileged helper.

## Request path

```text
AI client
  -> HTTPS tunnel or local stdio
  -> connector authentication and token scope
  -> MCP session and rate limits
  -> local connector policy for every relevant resource (deny / ask / allow)
  -> canonical resource identity and requester-principal binding
  -> explicit deny revocation before exact-action grant evaluation
  -> principal-bound local approval when required
  -> capability implementation
  -> operating-system account boundary
```

Authentication scopes can reduce access but can never override local policy.
Approval is deliberately absent from the MCP tool surface. Approval and grant
rows carry a domain-separated fingerprint for local stdio, local HTTP, Quick
Tunnel, or an exact OAuth client/subject pair. State-schema migration does not
preserve grants that predate that identity boundary.

Current-page browser operations add the normalized active origin to both policy
context and the exact-action authorization identity. An inactive session uses
`about:blank` without starting Chromium. The origin is read again after any local
approval wait; a changed origin is re-authorized before the operation continues.

When private-network access is disabled, the isolated Chromium process is
launched behind a RunOnMine-owned loopback HTTP proxy. Process-level proxy,
host-resolver, QUIC, loopback-bypass, and WebRTC settings make the boundary
independent of page/target attachment, covering popups, workers, service workers,
background targets, and WebSockets. The proxy validates the complete DNS answer
on every connection and connects to the exact checked IP. Existing external CDP
processes are rejected in protected mode because their launch-time network
configuration cannot be proven or replaced.

Privileged executable resources use the helper's shared canonical program
identity resolver before local policy evaluation. The resolver requires an
absolute root/SYSTEM-owned regular non-symlink file, enforces platform ACL/mode
rules, and returns the canonical path used by the installed allowlist. The helper
still verifies the pinned SHA-256 immediately before execution. Executable
identity is only the first gate: the complete argument vector must also match one
installed version-2 command profile covering the exact subcommand, declared and
forbidden flags, exact positional schemas, and canonical path roots. A local MCP
approval can narrow or confirm an invocation but cannot widen that root-owned
profile.

The loopback HTTP server supports at most 32 simultaneous MCP sessions, expires
sessions after 30 idle minutes, and permits 120 calls per connector per minute
by default. The server validates the connector bound to each session and
rejects session reuse through a different connector.

OAuth dynamic registration authenticates with a separately domain-hashed initial
access token loaded from the credential store. The HTTP layer validates that
bearer credential and registration payload before entering one SQLite
`IMMEDIATE` transaction that prunes expired clients, enforces source/global
windows plus total capacity, records the attempt, and inserts the client.
Unsuccessful validation consumes no slot. Client expiry is refreshed on real
authorization use rather than registration polling. After owner authentication,
the consent challenge reloads the registered client and derives display identity
from server-held state: a stable client-ID fingerprint, registration timestamp,
requested redirect origin, and the deduplicated registered-origin set. The
client-supplied name remains explicitly unverified.

## Local data

- `config.toml` contains non-secret configuration, is replaced atomically, and uses an owner-only sidecar lock for transactional read-modify-write updates.
- `state.db` contains approvals, sessions, OAuth token/source hashes, expiring registered-client metadata, and audit records.
- platform credential storage contains connector paths, external API credentials, OAuth hash keys, and owner-controlled registration access tokens.
- isolated Chromium profiles live below the per-user RunOnMine data directory.

Quick Tunnel URL discovery plus desktop, setup, browser, policy, and connector lifecycle mutations use the shared configuration transaction API, which reloads the latest validated document while holding the sidecar lock before atomically replacing it. Connector operations that also modify credentials record every previous secret value while that configuration lock is held and restore those values before releasing the lock after handled secret-store, validation, or save failures. Desktop credential replacement, emergency rotation, and purge enumeration use the same lock order. This is coordinated rollback across two stores, not a crash-proof distributed transaction. On headless Linux without Secret Service, secrets are stored only when an explicit `RUNONMINE_MASTER_KEY` supplies a 32-byte key. The file backend uses XChaCha20-Poly1305 with a random nonce and per-entry associated data. A separate owner-only file lock serializes secret updates across CLI, desktop, and agent processes. Missing or invalid key material fails closed.

The audit log is hash-chained. Retention pruning stores a chain anchor, so the remaining records continue to verify after the default 30-day/100-MiB retention window removes old records. State directories use owner-only permissions; SQLite database, WAL, and shared-memory files are restricted to the owning account. Dedicated database workers and connector supervisor tasks have explicit shutdown and join lifecycles.

## Recoverable connector removal

Connector deletion is a durable phase transaction. An owner-only journal records
the exact connector fingerprint before desired configuration changes, and an
inter-process lock serializes deletion, startup recovery and ID reuse. Cleanup
then advances through configuration and secret removal, authorization rows,
connector-scoped OAuth state and artifact directories. HTTP and stdio startup
resume pending records before building any connector runtime; failed phases stay
journaled for a later retry.

## Transactional OpenAI connector creation

OpenAI connector creation separates pure validation, private preparation,
configuration/credential commit and artifact activation. Candidate configuration
and connector-ID availability are checked first. Managed tunnel-client downloads,
profile generation, `init`, `doctor` and health-file preparation occur only in
owner-private staging locations on the destination filesystems. The configuration
sidecar lock remains held while the validated connector and credential are saved
and transaction-owned binary/receipt plus profile/state directories are
activated.

Activation uses no-overwrite same-filesystem links or renames and transaction
markers before exposing final paths. A handled activation error restores the
previous configuration snapshot and secret values before unlocking, then removes
only files whose digest/receipt or transaction marker proves ownership. Existing
managed binary/receipt pairs are never repaired implicitly: incomplete, symlinked
or integrity-invalid pairs fail closed without pre-commit replacement.

## Network ownership

The MCP listener is fixed to `127.0.0.1:47821`; configuration validation rejects
other bind hosts and reserves the existing MacMCP port `45799`. Cloudflare and
OpenAI tunnel processes connect outward. RunOnMine does not open a public
listener or modify firewall rules.

Cloudflare Quick Tunnel uses `/<secret>/mcp`. Named Tunnel uses `/mcp` plus the
embedded OAuth endpoints. OpenAI Secure MCP Tunnel launches the official
external client against `runonmine mcp stdio --connector <id>`.

## Privileged executable preparation

Privileged execution is prepared as a capability-like open executable object.
Argument schemas are evaluated first; the selected root/SYSTEM-owned file is
then opened without following the final symlink, identified and hashed from the
handle, retained through process creation, and revalidated immediately before
spawn. Linux launches the descriptor path itself; Windows holds a non-write/non-
delete-sharing handle; other platforms compare the retained handle with the
current canonical path at the last possible point.

## Transactional helper installation

Helper installation is a staged transaction rather than a sequence of
independent writes. The installer prepares the executable, policy and service
definition in their destination directories, snapshots the previous artifacts
and installed/enabled/running service state, stops the service, atomically
activates the files, restarts the platform service and verifies authenticated
health. A root/SYSTEM-only process lock serializes install and uninstall. Any
handled failure restores the old artifacts and service state; an unsuccessful
first install is fully removed.

## Running-service version handshakes

Service installation verifies the process that is actually running, not only the
binary present on disk. Helper health responses include the IPC protocol version,
workspace package version and allowlisted program count. The transactional
helper installer accepts health only when both versions match the installer; a
stale helper process therefore triggers the same full rollback as any other
health failure.

The HTTP agent publishes an owner-only atomic runtime marker only after its
loopback listener has bound successfully. The marker contains the status
protocol, package version, PID, canonical running executable, random instance
ID and start timestamp. User and Linux system service installers delete the old
marker, issue an explicit platform restart after installation, verify the
service manager reports an active process, and wait for a fresh matching marker.
A pre-existing marker, wrong package/protocol version, zero PID, invalid
executable identity or pre-restart timestamp fails installation.

## Audit integrity

Audit events retain their BLAKE3 previous-hash chain and additionally use a
per-state-database HMAC-SHA256 key stored in a separate owner-only sidecar. The
MAC covers sequence, chain hashes and canonical payload; a keyed tail state
binds the newest event. Verification compares every denormalized SQLite column
to the canonical event before accepting the chain. Version-3 databases never
silently regenerate missing MAC data. See
[`audit-security.md`](audit-security.md) for the exact trust boundary.

Connector configuration is also a live revocation boundary. Runtime connector
lookups reload the locked configuration and fail when an ID is disabled or no
longer present. Successful disable/removal then reconciles the transport plane:
a detected HTTP agent is explicitly restarted and must publish a fresh version
handshake. This closes protocol sessions and tears down managed tunnel process
groups rather than waiting for an operator restart.
