# Permissions

Every connector first resolves a tool in this order:

1. connector tool override;
2. connector capability override;
3. selected preset;
4. deny.

A final safety ceiling is then applied to internet-facing Cloudflare and OpenAI
connectors. File writes, user shell, browser actions, desktop control, and
platform-native scripting can never resolve above `ask`; administrator execution
always resolves to `deny`. Local stdio and loopback connectors retain the
configured result.

`deny` removes the tool from discovery and rejects direct calls. `ask` creates a
local approval request for up to 90 seconds. `allow` runs the tool without a
prompt. A missing capability always fails closed.

## Presets

| Capability | Safe | Developer | Full |
| --- | --- | --- | --- |
| Machine information | allow | allow | allow |
| Selected-root file read | allow | allow | allow |
| Selected-root file write | ask | allow | allow |
| User shell | ask | allow | allow |
| Browser read | allow | allow | allow |
| Browser action | ask | ask | allow |
| Desktop control | ask | ask | allow |
| Platform-native scripting | ask | ask | allow |
| Administrator helper | deny | deny | allow |

`full` is intentionally dangerous. It includes unrestricted user shell and,
when the separate helper is installed, allowlisted administrator execution.

## Local approvals

An approval may apply once, to the exact connector, tool, and argument hash for
ten minutes, or persistently to that same exact action. Persistent approval no
longer creates a broad tool-wide policy override. The approval screen displays a
bounded local preview of the concrete command, path, URL, selector, or script.
Common token, password, authorization-header, and API-key forms are redacted
before storage and display. Persistent exact-action grants can be listed and
revoked with `runonmine approvals grants ...`. MCP clients cannot list, grant,
or deny approvals.

For an internet-facing connector, a connector policy still cannot bypass the
remote safety ceiling. Exact grants authorize only the reviewed argument hash.

```console
runonmine approvals list
runonmine approvals approve <id> --once
runonmine approvals approve <id> --for 10m
runonmine approvals approve <id> --always
runonmine approvals deny <id>
runonmine approvals grants list
runonmine approvals grants revoke <connector> <tool> <argument-hash>
```

## OAuth scopes

Named Tunnel tokens may contain `machine:read`, `files:read`, `files:write`,
`shell:exec`, `browser:read`, `browser:act`, `desktop:control`, and
`admin:exec`. A tool runs only when both the token scope and local policy allow
it. Platform-native scripting maps to `shell:exec` for OAuth and retains its
separate local capability policy.

## Important boundaries

File tools canonicalize configured roots and requested paths and reject symlink
escapes. `fs_delete` uses the operating-system trash by default.

`shell_exec` is not a sandbox. When approved, it can run any command available
to the agent's user account. `admin_exec` is not a root shell: the helper accepts
only explicitly installed, hash-pinned absolute program paths. Program
arguments can still be security-sensitive and must be reviewed before approval.


## Emergency lock

Use `runonmine lock` or **Lock all access** in the desktop application to stop the
current user service, deny pending approvals, clear temporary grants, revoke
active OAuth tokens, delete incomplete OAuth authorization flows, rotate local
HTTP and Quick Tunnel secrets, and remove stored OpenAI runtime keys. On Linux,
`runonmine lock --system` also stops the system service.

The lock does not delete user configuration. Restoring access requires an
explicit service restart and, where credentials were invalidated, an explicit
connector reconnection.
