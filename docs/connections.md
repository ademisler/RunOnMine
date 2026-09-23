# Connection Modes

Each machine is configured as a separate MCP connector. A managed multi-machine
hub is outside the first beta.

## Local stdio

```console
runonmine mcp stdio --connector <id>
```

This starts one MCP process for an existing connector. It is also the process
target used by OpenAI Secure MCP Tunnel.

## Loopback Streamable HTTP

Loopback HTTP is disabled by default and is not treated as an identity boundary.
Enable it explicitly:

```console
runonmine connect local-http enable --token-output /absolute/private/local-http.json
runonmine agent run
```

The enable command creates a 256-bit bearer token in the operating-system
credential store and never prints it to standard output. `--token-output` is an
optional explicit export channel: it requires an absolute path below an existing
directory, creates a new no-overwrite JSON file, and restricts that file to the
current operating-system user (`0600` on Unix and a current-user SID DACL on
Windows). Every `/mcp` request must send `Authorization: Bearer <token>`.

Use `local-http rotate --token-output <new-absolute-file>` to replace and export
a token, `local-http status --token-output <new-absolute-file>` to recover the
current credential through the same secure channel, or `local-http disable` to
remove access. Omitting `--token-output` keeps the token only in the credential
store. The agent listens on `127.0.0.1:47821` by default; configuration rejects public
bind addresses and requires a non-zero loopback port.

## Degraded connector startup

An enabled external connector that cannot discover its binary, prepare its
connector-specific artifacts, load its required credential, pass startup checks,
or create its supervisor is marked degraded for that agent process and logged
with its connector ID, kind and sanitized authentication/process stage. That failure does not stop the loopback HTTP
agent, local connectors, or external connectors that already started
successfully. A later agent restart retries the connector from desired
configuration.

Runtime lifecycle state is kept in memory and exposed to the local owner at:

```console
curl -sS http://127.0.0.1:47821/healthz/connectors
```

The response reports a sanitized aggregate plus per-connector `starting`,
`backoff`, `ready`, `degraded`, or `stopped` state and the current startup stage.
The detailed route accepts only a direct loopback Host with the configured port
and returns `404` for forwarded/public requests. It contains no credentials,
process output, command lines, or external URLs.

OpenAI `init` and `doctor` execute asynchronously after the agent begins serving,
with bounded preparation and readiness deadlines. Stopping the agent cancels a
pending activation and joins cleanup. Quick Tunnel URL discovery starts only for
a successfully supervised Quick connector, and an OpenAI credential-store
failure remains confined to the OpenAI connector.

## Cloudflare Quick Tunnel

```console
runonmine connect cloudflare quick
```

This development-only mode creates a 256-bit secret URL path, stores it in the
platform credential store, and launches a verified official `cloudflared`
binary. It is not the recommended permanent deployment. Rotate an existing
connector with:

```console
runonmine connect cloudflare quick --rotate <connector-id>
```

The agent reads the current secret for each request, so rotation immediately
invalidates the previous URL. Unknown or incorrect paths return 404. The
`trycloudflare.com` origin discovered from `cloudflared` is not written to
`config.toml`: it lives in a private, generation-bound runtime record, is cleared
during restart/backoff, and is removed when the process or agent stops. A stale
observer cannot overwrite a newer process generation. The desktop and
`runonmine doctor` may show whether a current URL has been discovered, but local
health details and support bundles never include the generated URL. Cloudflare
describes Quick Tunnels as a testing and development facility; do not treat the
secret URL as a long-term identity system.

## Cloudflare Named Tunnel with OAuth 2.1

```console
runonmine connect cloudflare oauth \
  --registration-token-output /absolute/private/oauth-registration.json
```

For a dedicated machine you own, an explicit workstation mode is also available:

```console
runonmine connect cloudflare oauth \
  --owner-full-access \
  --registration-token-output /absolute/private/oauth-registration.json
runonmine policy preset full --connector <connector-id>
```

`--owner-full-access` is intentionally dangerous. It disables the generic remote
safety ceiling only for that GitHub-owner-authenticated Named Tunnel. OAuth
scopes, requester identity, configured policy rules, selected roots, audit
integrity, and helper allowlists still apply. It is never enabled implicitly and
does not exist for Quick Tunnel or OpenAI connectors.

The recommended Cloudflare mode uses Cloudflare only as the HTTPS carrier. The
Rust agent owns protected-resource metadata, authorization-server metadata,
dynamic client registration, authorization code flow, PKCE S256, consent, CSRF
protection, token rotation, and revocation. GitHub proves the configured machine
owner's identity. Strict MCP discovery is supported at both the root OAuth
metadata endpoint and the resource-specific `/.well-known/oauth-authorization-server/mcp`
alias; unauthenticated `/mcp` responses advertise
`/.well-known/oauth-protected-resource/mcp`. Both authorization metadata routes
explicitly advertise `code_challenge_methods_supported: ["S256"]`.

Dynamic client registration is not anonymous. `/oauth/register` requires the
256-bit owner-controlled initial access token from the connector credential
store as `Authorization: Bearer <token>`. The token is never printed. The optional
creation flag above exports a new no-overwrite JSON file restricted to the
current operating-system user. Existing credentials can be exported or rotated
with:

```console
runonmine oauth registration-token export <connector-id> --output /absolute/private/oauth-registration.json
runonmine oauth registration-token rotate <connector-id> --output /absolute/private/new-oauth-registration.json
```

Rotation takes effect after the agent restarts. Emergency lock stops the service
and rotates every OAuth registration token before access can be restored.

Platforms that let the owner supply an OAuth Client ID and Client Secret do not need to use
DCR. Provision a confidential client locally with the exact HTTPS callback URL copied from
the client platform:

```console
runonmine oauth clients provision <connector-id> \
  --name ChatGPT \
  --redirect-uri 'https://chatgpt.com/connector/oauth/<exact-callback-id>' \
  --output /absolute/private/chatgpt-oauth-client.json
```

Do not invent or generalize the callback URL. The command refuses non-HTTPS redirects,
requires the explicit owner-full Cloudflare OAuth connector, and never prints the secret.
The export is create-new and owner-only. With no `--scope` arguments the confidential
client receives all RunOnMine OAuth scopes; repeat `--scope <scope>` to narrow it. The
server stores only a keyed, domain-separated client-secret hash. Token exchange accepts
`client_secret_basic` and `client_secret_post`, while a public DCR client rejects an
unexpected secret. Deleting the client cascades its secret hash and authorization state.

Registration payloads are fully validated before they can consume capacity. A
registration that omits `scope` receives only `machine:read`; clients must name
each additional capability explicitly and can never request a scope later that
was absent from their registered set. Platform-native automation uses the
separate `platform:exec` scope rather than inheriting `shell:exec`, and the local
consent page explains that it covers AppleScript, PowerShell, or D-Bus.
Authorized valid registrations are committed atomically with a SQLite-backed
limit of five registrations per
Cloudflare source per minute, twenty globally per minute, and 256 live clients.
These limits survive agent restarts. Unused
clients expire after 24 hours; the first and subsequent authorization use records
`last_used_at` and extends the client lifetime to at least 90 days. Expired
clients without active tokens are pruned before the capacity check so abandoned
registrations return quota automatically.

A dynamic client's `client_name` is self-asserted metadata, not a verified
publisher identity. The local consent page therefore labels it unverified and
also shows a stable SHA-256 client-ID fingerprint, the UTC registration time,
the redirect origin selected by the current request, and every distinct origin
registered for that client. Invisible, line-breaking, and bidirectional-control
characters are rejected from client names. Review the fingerprint and origins,
not the claimed name alone, before allowing access.

Access tokens last 15 minutes. Refresh tokens rotate and expire after 30 days;
reuse revokes the token family. Only keyed, domain-separated token, client-secret, and source
hashes are stored in SQLite. The GitHub client secret, hashing key, and
registration access token remain in the platform credential store.

The browser consent page is self-contained, uses the real packaged RunOnMine logo, and loads only same-origin CSS under a strict CSP. Approval uses a native HTML form with no client-side submit interception, while the authorization service keeps a bounded 30-second in-memory replay record keyed by consent ID, CSRF hash, and decision. An identical retry returns the same redirect without issuing a second authorization code; a mismatched decision or CSRF fails closed. Replay state is never persisted and expires automatically.

The public hostname, Cloudflare tunnel ID, credentials file, GitHub OAuth client
ID, GitHub owner display login, and immutable positive GitHub numeric owner ID are required. Only the numeric ID authorizes the owner; the login is display metadata and is atomically refreshed after a verified same-ID GitHub rename. The CLI prompts for secrets rather
than accepting them in command-line arguments. Incoming OAuth and MCP requests must use the configured public hostname with no explicit port or HTTPS port `443`; other Host authorities return 404.

## OpenAI Secure MCP Tunnel

```console
runonmine connect openai
```

RunOnMine manages the official external `tunnel-client`, creates a local profile
targeting `runonmine mcp stdio --connector <id>`, and stores the runtime API key
in the operating-system credential store. `runonmine doctor` checks binary,
profile, and health status without printing the key.

Creation follows a guarded prepare/validate/commit/activate transaction. The full
candidate connector is validated before downloading or creating connector
artifacts. A missing managed tunnel client is downloaded, digest-verified and
probed in an owner-private staging directory; profile `init`, runtime-key
`doctor`, and health-file preparation also use private staging paths. Only after
those checks succeed are configuration and the credential committed under the
configuration lock. The binary/receipt and connector data/state directories are
then activated from the same filesystems. A handled secret write, activation or
post-activation integrity failure restores the prior configuration and secret
values and removes only artifacts proven to belong to that transaction.

An existing managed binary is reused only when both its private receipt and
SHA-256 identity verify and its version probe succeeds. A symlink, incomplete
binary/receipt pair, or integrity-invalid existing installation is left untouched
and fails closed with a repair/removal error; setup never deletes or replaces it
before the connector commit. Repair, update, and rollback are explicit managed-
binary operations so forensic evidence and the last known state are preserved.
Explicit absolute user-supplied binaries are verified and probed but never
modified.

The current beta uses a singleton local tunnel-client profile and fixed loopback
health endpoint, so it supports only one **configured** OpenAI Secure MCP Tunnel
connector. This is an explicit configuration invariant rather than a best-effort
runtime assumption: a second connector is rejected before any download, staging,
credential mutation, profile initialization, or doctor process, even when the
existing connector is disabled or the candidate names a different health port.
Remove the existing OpenAI connector before creating another one.

Availability in ChatGPT depends on the user's current plan, workspace policy,
and Developer Mode access. RunOnMine does not claim or bypass those permissions.

## External binary policy

Managed `cloudflared` and `tunnel-client` downloads resolve from provenance
catalogs embedded in the RunOnMine build, not from mutable live `latest` metadata.
Each catalog is an Ed25519 envelope that must satisfy a 2-of-2 threshold: one
shared RunOnMine security root plus a distinct Cloudflare or OpenAI catalog root.
The signed payload binds the official source repository and 40-character commit,
release tag, exact platform asset URL, SHA-256 digest, byte size and archive
format. GitHub remains only the allowlisted HTTPS byte transport. New receipts
retain the signed envelope and startup re-verifies it before accepting the
managed version. Legacy digest-only receipts remain readable for migration and
are upgraded by the next managed update. Archive path traversal is rejected. New managed Cloudflare installs are stored in
immutable SHA-256-addressed version directories with a private receipt. Connector
startup accepts a managed version only when its exact path shape, receipt
provider/path, and executable digest all verify. `runonmine connect
update-managed-binaries` prepares, receipt-verifies and compatibility-probes new
Cloudflare and OpenAI versions before a config/active-manifest/service-restart
transaction. Only managed paths are rewritten; explicit external paths remain
untouched. Restart failure restores both the prior configuration and active
version. A valid legacy `data/bin/tunnel-client` plus receipt is copied into the
immutable version store on the next OpenAI setup, while the original pair is
preserved for recovery.

Compatibility is checked during setup, doctor, managed update and agent startup.
RunOnMine currently accepts stable OpenAI tunnel-client `0.0.10` and stable
cloudflared date versions from `2025.1.0` up to, but not including, `2027.0.0`.
Prereleases and versions outside those ranges fail before activation; the prior
known-good active version remains selected.

Explicit user-supplied absolute paths remain an advanced local trust decision;
PATH fallback is not used. `runonmine connect list` reports
`external_unpinned`, `external_pinned`, `managed_verified`, `missing`, or
`invalid`. `runonmine connect pin-external-binaries` stores an owner-only pin for
each configured external path, binding its canonical path, SHA-256 digest,
platform ownership, Unix mode where available, size, and modification time.
Agent startup verifies the pin before process creation. A mismatch degrades only
the affected connector; an unpinned external binary remains allowed but produces
an explicit warning.

The desktop application includes guided setup for Quick Tunnel, Cloudflare OAuth, and OpenAI Secure MCP Tunnel. Secrets are passed to the local CLI over bounded standard input and stored in the operating-system credential store. Multi-value credential replacement rolls back if any write or follow-up revocation fails. Child output is bounded and redacted, and background commands are canceled and joined when the desktop exits. Connector lifecycle commands remain available without editing configuration files:

```console
runonmine connect list
runonmine connect show <id>
runonmine connect enable <id>
runonmine connect disable <id>
runonmine connect update-managed-binaries
runonmine connect pin-external-binaries
runonmine connect remove <id> --confirm REMOVE
```

## OAuth callback retry and issuer deployment

OAuth issuers are intentionally root-only. A configured issuer such as `https://host.example/prefix` is rejected rather than partially supported; metadata and OAuth endpoints are derived from the root origin.

A GitHub callback first claims pending authorization state with a short lease bound to a domain-separated hash of the provider code. Only one callback can hold the claim. A different code can never replace the bound code. Temporary provider failures release the claim so the same state and code can be retried; terminal denial consumes it. The one-time code exchange itself is not blindly replayed, while the authenticated `/user` lookup has a bounded retry for transport, rate-limit, and server failures. On success, consent insertion and authorization-state deletion occur in one SQLite transaction.

## Orphan connector reconciliation

Before HTTP or stdio transport starts, RunOnMine completes pending removal
journals and compares connector artifact directories and Quick Tunnel runtime
records with committed config. Config-less real directories with valid connector
IDs are moved into an owner-only quarantine directory on the same filesystem;
they are not deleted. Orphan Quick runtime records are ephemeral and removed.
Invalid IDs, symlinks, non-directory entries, and corrupt runtime records are
reported as unsafe and left unchanged. The same inventory is visible through
`runonmine doctor`; explicit `doctor --repair` also removes managed-index
credentials whose connector owner no longer exists.

## Connector identity format

RunOnMine-generated connector IDs are UUIDs. Every connector ID used by config,
runtime artifacts, removal journals, OAuth namespaces, and secret names must be
8-64 lowercase ASCII letters, digits, `-`, or `_`, beginning and ending with an
alphanumeric character. Pre-release configurations with shorter, uppercase, or
otherwise ambiguous IDs are rejected fail-closed; recreate the connector so its
credentials and authorization state receive a new unambiguous namespace.

## OAuth connector isolation

OAuth state is connector-scoped. A client registered through one named-tunnel issuer cannot be looked up, authorized, refreshed, revoked, or reused through another connector that shares the same local state database. Administrative client and session listings show the owning connector, and revoke/delete operations require that connector identity. The schema-v4 migration intentionally removes namespace-free beta OAuth clients and sessions because they cannot be assigned safely to an issuer; affected clients must register and complete owner consent again.

## Immediate disable and removal

Disabling or removing a connector is a live revocation operation. The committed
configuration is the authorization source of truth: the MCP runtime reloads the
connector before exposing or authorizing tools, so a missing or disabled
connector is rejected immediately even before process reconciliation finishes.

After the configuration transaction succeeds, the CLI checks the owner-only
agent runtime marker. When an HTTP agent is running, RunOnMine performs the
platform-specific explicit restart and waits for the fresh protocol/package/PID
handshake. Restarting the owning agent closes its MCP sessions and drops every
managed Cloudflare/OpenAI child-process handle, whose shutdown path terminates
the corresponding process group. The command does not print a manual restart
instruction and does not report success if a detected running agent cannot be
restarted and verified.

If no runtime marker exists, no managed HTTP agent is active and no restart is
required. A malformed or symlinked marker fails closed. Connector mutation is
performed before reconciliation; if the service-manager restart itself fails,
the connector remains disabled/removed in configuration, so subsequent runtime
checks continue to deny access while the local error instructs the owner to
repair the service before reconnecting.

## Recoverable connector removal

Removal records an owner-only journal entry before deleting configuration or
credentials. The record binds the connector ID, kind and SHA-256 fingerprint of
the exact connector configuration, then advances monotonically through
configuration/secret deletion, approval and grant cleanup, connector-scoped
OAuth cleanup, and local artifact-directory removal. Every phase is idempotent;
a handled failure leaves the last completed phase on disk rather than reporting
a partially removed connector as complete.

Both loopback HTTP and stdio agent startup reconcile pending removals before
loading connector configuration. The CLI also reconciles pending records before
connector commands. A per-user inter-process lock serializes removal,
reconciliation and connector creation, and a connector ID cannot be reused while
a journal record remains. Repeating `connect remove` after successful cleanup is
a successful no-op. Corrupt, symlinked, mismatched or unexpectedly large journal
records fail closed.
