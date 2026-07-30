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
owns approval request creation, notification-first owner-decision waits, timeout/expiry transitions,
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


Approval changes use a notification-first lifecycle. After a SQLite transaction
commits an insert, owner decision, timeout, connector cleanup, or emergency lock,
`StateStore` atomically replaces an owner-only `approval-events` pulse in the
state directory. Each process watches that directory through the native
filesystem backend and fans matching events into a Tokio watch channel. MCP
waiters subscribe before reading status and re-check immediately after an event.
A five-second SQLite check is retained only to recover from unsupported
filesystems, watcher startup failure, event coalescing, or a missed event.
Notification delivery and pulse-write failures are exposed through
`approval_notification_metrics`; notification failure never changes the result
of an already committed owner decision.

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

For `shell_exec`, the effective working directory is resolved before
authorization. A supplied path or the process current directory must exist and
canonicalize to a directory. The command and canonical directory are evaluated
as separate policy resources; the same normalized arguments and resources form
the exact-action hash and are then passed to execution. Process capture uses a
single atomic retained-byte budget shared by stdout and stderr. Readers continue
draining after the budget reaches zero, avoiding both double allocation and
pipe-backpressure deadlocks. The same combined-budget primitive protects
connector one-shot/probe, platform-native, helper, and desktop CLI processes.

Current-page browser operations add the normalized active origin to both policy
context and the exact-action authorization identity. An inactive session uses
`about:blank` without starting Chromium. The origin is read again after any local
approval wait; a changed origin is re-authorized before the operation continues.

Every browser and CDP operation is wrapped in one configured session deadline
(default 45 seconds, accepted range 1–300 seconds). A timeout cancels the pending
future and then acquires the session slot only after cancellation has released it.
The active connection is removed before reuse; owned Chromium is force-terminated
if graceful CDP shutdown cannot complete, the request interceptor and process-wide
network guard are stopped, and ephemeral profile state is removed. The next call
starts a clean session lazily. External CDP processes are never killed: their
RunOnMine connection is quarantined and must be reattached on the next call.
Recovery count and the last bounded operation category are available through
browser profile diagnostics without exposing page content or JavaScript.

Browser launch identity is explicit and revalidated. Configuration may retain one
absolute executable selection; the local CLI accepts it only after canonicalizing
a real executable whose identity is Chrome, Chromium, or Edge. Auto mode searches
a fixed platform candidate list. Runtime resolves and validates the selection
again before every owned launch, disables browser tools when no supported binary
is available, and records the real post-launch executable in the crash lease.
Local `browser executable show` may display the canonical path. MCP profile and
support diagnostics expose only selection source, product family, availability,
and executable basename so remote BrowserRead callers do not receive a user path.
An unavailable retained selection remains loadable so the owner can recover with
`browser executable auto` or a new `set`. External CDP bypasses launch selection
entirely and retains all existing loopback, connector, and protected-mode gates.

Owned Chromium launch is registered before process creation with a private,
atomically replaced lease inside the exact profile directory. The lease binds a
random launch token, profile mode/path, launcher identity, agent PID/start time,
and—after launch—the real browser PID/start time and executable. HTTP and stdio
startup inventory these leases before accepting requests. A process is killed
only when it is owned by the current user and all available token, profile,
executable, PID, and start-time evidence agrees. A live owner defers cleanup;
invalid, symlinked, broadly readable, PID-reused, or otherwise ambiguous entries
are logged and retained. Confirmed stale leases are removed, disposable profiles
are deleted, and persistent profile data is preserved. Legacy three-level UUID
disposable profiles are removed only when no live process references their exact
`--user-data-dir`.

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

OAuth owner authority is the configured positive GitHub numeric user ID, and
subjects are stored as `github:<numeric-user-id>`. Login strings never
participate in authorization. After GitHub returns the expected ID, a separate
observer validates the returned login as bounded display metadata and updates
only that field through the owner-only config lock and atomic save. Connector
disappearance, ID mismatch, invalid login metadata, or a concurrent configured-ID
change aborts the callback with a generic server error and leaves authority
unchanged.

## Local data

- `config.toml` contains non-secret configuration, is replaced atomically, and uses an owner-only sidecar lock for transactional read-modify-write updates.
- `state.db` contains approvals, sessions, OAuth token/source hashes, expiring registered-client metadata, and audit records.
- platform credential storage contains connector paths, external API credentials, OAuth hash keys, and owner-controlled registration access tokens.
- isolated Chromium profiles live below the per-user RunOnMine data directory.
- immutable managed connector versions live below `data/managed-binaries/<executable>/versions/<sha256>/`, with an owner-only active manifest and receipt per version.
- optional external connector pins live in an owner-only state document and contain only binary identity/metadata, never connector credentials.
- connector compatibility ranges are code-owned release gates applied by setup, doctor, update and startup before a child process becomes active.
- connector release provenance catalogs are compiled into the application as bounded base64 payload envelopes. A managed artifact is selectable only after strict Ed25519 verification by both the shared RunOnMine root and its provider-specific root; the payload binds repository, source commit, release tag and exact asset metadata. New installation receipts carry the envelope for startup re-verification.

Cloudflare Quick Tunnel public URL discovery is runtime state rather than desired configuration. Each successful Quick process start creates a private generation-bound record below the state directory. Only the observer holding that generation may publish or clear the URL; restart/backoff clears it, process stop removes the record, startup replaces stale generations, and legacy Quick URLs are removed from `config.toml` under the configuration lock. The desktop, doctor, and support summary read this bounded state without exposing the URL through public health routes or support archives.

Desktop, setup, browser, policy, and connector lifecycle mutations use the shared configuration transaction API, which reloads the latest validated document while holding the sidecar lock before atomically replacing it. Connector operations that also modify credentials record every previous secret value while that configuration lock is held and restore those values before releasing the lock after handled secret-store, validation, or save failures. Desktop credential replacement, emergency rotation, and purge enumeration use the same lock order. This is coordinated rollback across two stores, not a crash-proof distributed transaction. On headless Linux without Secret Service, secrets are stored only when an explicit `RUNONMINE_MASTER_KEY` supplies a 32-byte key. The file backend uses XChaCha20-Poly1305 with a random nonce and per-entry associated data. A separate owner-only file lock serializes secret updates across CLI, desktop, and agent processes. Missing or invalid key material fails closed.

The audit log is hash-chained. Retention pruning stores a chain anchor, so the remaining records continue to verify after the default 30-day/100-MiB retention window removes old records. State directories use owner-only permissions; SQLite database, WAL, and shared-memory files are restricted to the owning account. The core StateStore worker admits at most 128 queued jobs; synchronous and asynchronous callers wait at most one second for queue capacity and fail closed when the queue remains full. `StateStore::worker_metrics()` exposes queue capacity, queued and active jobs, high-watermark, rejected enqueue count, and completed jobs. Once accepted, a database job is allowed to finish without a reply timeout so a caller cannot receive a timeout while a write later commits. Dedicated database workers drain accepted work and join during shutdown; connector supervisor tasks also have explicit shutdown and join lifecycles.

## Connector startup isolation

Managed external connectors start behind a per-connector error boundary. Binary
resolution first classifies the exact executable as a verified immutable managed
version, pinned external path, or unpinned external path. Managed receipts and
external pins are rechecked before process creation; a mismatch is retained as a
connector-scoped degraded state. Binary discovery, connector-specific directories
and profiles, credential lookup,
health-command construction and supervisor startup may mark only that connector
as degraded. The failure is retained in the in-memory managed-connector set and
emitted as a structured log with connector ID, kind and a sanitized authentication/process stage.
Already-started healthy child processes and their observers remain active, and
the loopback HTTP agent continues serving local and healthy remote connectors.

Only agent-wide prerequisites outside an individual connector boundary—such as
an invalid common loopback origin—abort managed-connector initialization. Secret
storage is opened lazily by the OpenAI branch so an unavailable credential
backend cannot prevent Cloudflare or local connectors from starting. Quick
Tunnel URL observers are attached only to Quick supervisors that started
successfully.

## Asynchronous OpenAI activation and runtime health

The loopback listener and local MCP router do not wait for OpenAI tunnel-client
profile initialization or `doctor`. The configured binary is receipt/pin checked
and compatibility-probed before activation. After the listener binds, each configured
OpenAI connector receives an owned activation task. The task performs binary
and profile discovery, optional profile `init`, credential lookup and `doctor`
inside a 75-second preparation deadline, then starts the supervisor and requires
a healthy readiness event within a separate 30-second deadline. Dropping a
timed-out preparation future cancels its bounded child process, and the task
owns the supervisor handle until agent shutdown so no detached connector process
is leaked.

A shared in-memory registry records `starting`, `backoff`, `ready`, `degraded`
and `stopped` phases plus the sanitized authentication, preparation, process or
readiness stage. Supervisor health/restart events update the registry throughout
the agent lifetime. `/healthz` remains the stable plain-text liveness endpoint;
`/healthz/connectors` returns the runtime snapshot as JSON only when the request
uses the exact direct-loopback Host and contains no proxy/forwarding headers.
Public tunnel hosts, wrong ports and forwarded requests receive `404` so local
connector IDs and lifecycle state are not exposed remotely.

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

Because the beta tunnel-client profile uses fixed loopback health port `47823`,
configuration validation permits at most one configured OpenAI connector. The
singleton check is evaluated with the full candidate before any staging or
external process execution; it does not rely only on an eventual bind failure.

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
