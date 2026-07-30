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
store. The agent listens on `127.0.0.1:47821`;
configuration rejects public bind addresses and reserves port `45799` for the
existing MacMCP installation.

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
invalidates the previous URL. Unknown or incorrect paths return 404. Cloudflare
describes Quick Tunnels as a testing and development facility; do not treat the
secret URL as a long-term identity system.

## Cloudflare Named Tunnel with OAuth 2.1

```console
runonmine connect cloudflare oauth \
  --registration-token-output /absolute/private/oauth-registration.json
```

The recommended Cloudflare mode uses Cloudflare only as the HTTPS carrier. The
Rust agent owns protected-resource metadata, authorization-server metadata,
dynamic client registration, authorization code flow, PKCE S256, consent, CSRF
protection, token rotation, and revocation. GitHub proves the configured machine
owner's identity.

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
reuse revokes the token family. Only keyed, domain-separated token and source
hashes are stored in SQLite. The GitHub client secret, hashing key, and
registration access token remain in the platform credential store.

The public hostname, Cloudflare tunnel ID, credentials file, GitHub OAuth client
ID, expected GitHub owner login, and immutable positive GitHub numeric owner ID are required. The CLI prompts for secrets rather
than accepting them in command-line arguments. Incoming OAuth and MCP requests must use the configured public hostname with no explicit port or HTTPS port `443`; other Host authorities return 404.

## OpenAI Secure MCP Tunnel

```console
runonmine connect openai
```

RunOnMine manages the official external `tunnel-client`, creates a local profile
targeting `runonmine mcp stdio --connector <id>`, and stores the runtime API key
in the operating-system credential store. `runonmine doctor` checks binary,
profile, and health status without printing the key.

Availability in ChatGPT depends on the user's current plan, workspace policy,
and Developer Mode access. RunOnMine does not claim or bypass those permissions.

## External binary policy

Managed `cloudflared` and `tunnel-client` downloads resolve through official
GitHub releases, require HTTPS URLs on allowlisted hosts, verify release digests,
reject archive path traversal, and install by atomic replacement. RunOnMine
persists a private installation receipt and re-verifies the executable path and
SHA-256 digest whenever the managed binary is loaded. Explicit user-supplied
absolute paths remain an advanced local trust decision; PATH fallback is not used.

The desktop application includes guided setup for Quick Tunnel, Cloudflare OAuth, and OpenAI Secure MCP Tunnel. Secrets are passed to the local CLI over bounded standard input and stored in the operating-system credential store. Multi-value credential replacement rolls back if any write or follow-up revocation fails. Child output is bounded and redacted, and background commands are canceled and joined when the desktop exits. Connector lifecycle commands remain available without editing configuration files:

```console
runonmine connect list
runonmine connect show <id>
runonmine connect enable <id>
runonmine connect disable <id>
runonmine connect remove <id> --confirm REMOVE
```
