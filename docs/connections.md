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

```console
runonmine agent run
```

The agent listens on `127.0.0.1:47821`. Configuration rejects public bind
addresses and reserves port `45799` for the existing MacMCP installation.

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
runonmine connect cloudflare oauth
```

The recommended Cloudflare mode uses Cloudflare only as the HTTPS carrier. The
Rust agent owns protected-resource metadata, authorization-server metadata,
dynamic client registration, authorization code flow, PKCE S256, consent, CSRF
protection, token rotation, and revocation. GitHub proves the configured machine
owner's identity.

Access tokens last 15 minutes. Refresh tokens rotate and expire after 30 days;
reuse revokes the token family. Only keyed, domain-separated token hashes are
stored in SQLite. The GitHub client secret and hashing key remain in the
platform credential store.

The public hostname, Cloudflare tunnel ID, credentials file, GitHub OAuth client
ID, and expected GitHub owner are required. The CLI prompts for secrets rather
than accepting them in command-line arguments.

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

`cloudflared` downloads resolve through the official GitHub release, require an
HTTPS URL on an allowed host, verify the release checksum, reject archive path
traversal, and install by atomic replacement. `tunnel-client` is discovered as
an external official dependency and is never reimplemented inside RunOnMine.
