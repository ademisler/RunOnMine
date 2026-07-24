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

HTTP and WebSocket CDP URLs must use `localhost`, `127.0.0.1`, or `::1`.
External CDP is unavailable to remote connectors. The endpoint is treated as expert mode: every page, cookie, and account visible
to that browser may be reachable through browser actions. Start a dedicated
temporary browser profile whenever possible.

## Network boundary

By default, navigation rejects loopback, private, carrier-grade NAT, link-local,
multicast, documentation, benchmark, reserved, and otherwise non-routable IP
ranges. Hostnames are resolved before navigation and rejected when any returned
address is non-public. Only `about:blank` is accepted from the `about:` scheme.

Local development targets can be enabled explicitly:

```console
runonmine browser private-network allow
```

Disable the exception again with:

```console
runonmine browser private-network deny
```

Enabling this option allows local connector browser actions to reach services on
the machine and local network. Remote Cloudflare and OpenAI connectors remain
blocked even when the local option is enabled. CDP Fetch interception validates
navigations, redirects, and subresources before they are continued. This reduces
SSRF exposure but does not make an authenticated browser session harmless.

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
