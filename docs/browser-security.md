# Browser Profile Security

RunOnMine launches Chromium with a dedicated user-data directory below its own
data directory. It does not copy cookies, saved passwords, extensions, or other
state from the user's daily profile.

Browser objects are separated by connector and MCP session. One AI conversation
cannot silently reuse another session's in-memory page object. Closing an MCP
session releases its browser session, while persistent profile data remains in
the explicitly named RunOnMine profile.

Create the default isolated profile with:

```console
runonmine browser profile create
```

## Expert CDP attachment

RunOnMine never starts a daily Chrome profile with remote debugging enabled.
Advanced users may attach only to an already running browser endpoint supplied
explicitly with:

```console
runonmine browser attach http://127.0.0.1:<port>
```

HTTP and WebSocket CDP URLs must resolve to `localhost`, `127.0.0.1`, or `::1`.
The endpoint is treated as expert mode: every page, cookie, and account visible
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

Enabling this option allows browser actions to reach services on the machine and
local network. It should not be enabled for an untrusted remote connector.
Redirect-chain enforcement remains part of the pre-release acceptance review;
do not treat the browser as a network sandbox.

## Output and policy

Screenshots are encoded as complete JPEG images. When they exceed the MCP output
budget, RunOnMine reduces quality and dimensions; it never truncates encoded
bytes into an invalid image.

Navigation, click, type, key press, evaluation, open, and close operations use
the `browser_act` capability. URL, text, snapshot, screenshot, and profile
information use `browser_read`. Browser evaluation is marked destructive and
open-world because page JavaScript can create external side effects.

RunOnMine cannot make an already authenticated website harmless. A permitted
browser action can send messages, publish content, make purchases, or change
account settings. Keep sensitive profiles separate and use `ask` for browser
actions.
