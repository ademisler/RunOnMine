# Browser Profile Security

RunOnMine launches Chromium with a dedicated user-data directory below its own
data directory. It does not copy cookies, saved passwords, extensions, or other
state from the user's daily profile.

The default mode is ephemeral: browser objects and profile data are separated by
connector and MCP session, and the random session directory is removed when the
session closes. Create a persistent RunOnMine-only profile explicitly when login
state must survive:

```console
runonmine browser profile create --name work
```

Return to disposable profiles or remove an unused persistent profile with:

```console
runonmine browser profile ephemeral --name default
runonmine browser profile delete work
```

## Expert CDP attachment

RunOnMine never starts a daily Chrome profile with remote debugging enabled.
Advanced users may attach only to an already running browser endpoint supplied
explicitly with:

```console
runonmine browser attach http://127.0.0.1:<port>
```

HTTP and WebSocket CDP URLs must use `localhost`, `127.0.0.1`, or `::1`;
embedded credentials, query strings, and fragments are rejected. External CDP
is unavailable to remote connectors. RunOnMine cannot retrofit its
browser-process-wide network proxy into an already running external browser, so
protected mode rejects external CDP before connecting. External attachment is
available only after the local private-network exception is enabled explicitly.
The endpoint remains expert mode: every page, cookie, and account visible to
that browser may be reachable through browser actions. Start a dedicated
temporary browser profile whenever possible.

## Network boundary

When private-network access is disabled, every Chromium process owned by
RunOnMine is launched behind an ephemeral HTTP CONNECT proxy bound only to
`127.0.0.1`. Chrome is configured to remove its implicit loopback proxy bypass,
prevent direct hostname resolution, disable QUIC, and disallow non-proxied
WebRTC UDP. The proxy is therefore process-wide rather than page-specific:
normal pages, popups, dedicated and shared workers, service workers, WebSockets,
redirects, and background targets use the same network gate.

For every connection, the proxy canonicalizes the destination, resolves it
again, rejects empty, mixed public/private, loopback, private, carrier-grade NAT,
link-local, multicast, documentation, benchmark, reserved, and otherwise
non-routable address sets, and connects directly to one of the exact checked
socket addresses. This avoids a second DNS lookup between validation and
connection and closes the normal DNS-rebinding window. Request headers and
concurrency are bounded, malformed proxy requests fail closed, and stopping the
browser network guard aborts and joins active tunnels.

The active page still uses CDP Fetch interception and requested/final URL
validation as defense in depth. Only `about:blank`, HTTP(S), WebSocket, `data:`
and `blob:` subresources required by the isolated page are accepted by the
corresponding validation path.

Local development targets can be enabled explicitly:

```console
runonmine browser private-network allow
```

Disable the exception again with:

```console
runonmine browser private-network deny
```

Enabling this option intentionally removes the private-network proxy boundary
for local connectors. Remote Cloudflare and OpenAI connectors remain blocked
even when the local option is enabled. External CDP cannot be placed behind
RunOnMine's process-wide proxy, so it is rejected while protected mode is
active; a local user must explicitly enable private-network expert mode before
attaching to an external browser.

## Output and policy

Screenshots are encoded as complete JPEG images and rejected when they exceed
the configured MCP output budget; encoded image bytes are never truncated.
Page text, HTML snapshots, JavaScript input, and serialized evaluation results
also have explicit byte limits.

Navigation, click, type, key press, evaluation, open, and close operations use
the `browser_act` capability. URL, text, snapshot, screenshot, and profile
information use `browser_read`. Browser evaluation is marked destructive and
open-world because page JavaScript can create external side effects.

RunOnMine cannot make an already authenticated website harmless. A permitted
browser action can send messages, publish content, make purchases, or change
account settings. Keep sensitive profiles separate and use `ask` for browser
actions.
