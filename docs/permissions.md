# Permissions

Every connector resolves a tool in this order:

1. the most specific matching principal/resource rule;
2. connector tool override;
3. connector capability override;
4. selected preset;
5. deny.

Principal matchers can target local requests, a specific OAuth client, or a
specific OAuth subject. Resource matchers can restrict a rule to a filesystem
prefix, browser origin, executable path, or command prefix. The desktop Permissions tab includes a visual rule builder for these combinations and validates the complete configuration before saving. At equal
specificity, `deny` wins over `ask`, which wins over `allow`. Rules are stored
in the connector's `policy_rules` configuration and are validated when the
configuration is loaded.

Browser-origin rules apply to both navigation targets and the actual current page.
Before URL/text/snapshot reads, click/type/key actions, screenshots, JavaScript
evaluation, close, and profile inspection, RunOnMine reads the active page URL
without launching a new browser and authorizes its normalized origin. The origin
is part of the exact-action grant hash and appears in the local approval preview.
If the page changes origin while approval is pending, the new origin is evaluated
again; repeated changes fail closed.

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

An approval may apply once, to the exact connector, requester principal, tool,
and argument hash for ten minutes, or persistently to that same exact action.
Local stdio, local HTTP, Quick Tunnel, and each OAuth client/subject pair have
distinct grant identities. A grant approved for one OAuth client or subject is
never reused by another. Persistent approval no longer creates a broad tool-wide
policy override. The approval screen displays the requester identity plus a
bounded local preview of the concrete command, path, URL, selector, or script.
Common token, password, authorization-header, and API-key forms are redacted
before storage and display. Persistent exact-action grants can be listed and
revoked with `runonmine approvals grants ...`. MCP clients cannot list, grant,
or deny approvals.

For an internet-facing connector, a connector policy still cannot bypass the
remote safety ceiling. Exact grants authorize only the reviewed requester and
argument hash. Explicit `deny` rules are checked before grants, so a grant created
earlier cannot override a later policy revocation. Tools with multiple
security-relevant resources authorize all of them; for example, `fs_move`
evaluates both its source and destination paths. Filesystem policy matching uses
the same selected-root path identity as execution, so relative paths cannot avoid
an absolute prefix rule. Upgrading from a pre-principal state schema expires old
pending approvals and removes old connector-wide temporary or persistent grants
rather than guessing who owned them.

```console
runonmine approvals list
runonmine approvals approve <id> --once
runonmine approvals approve <id> --for 10m
runonmine approvals approve <id> --always
runonmine approvals deny <id>
runonmine approvals grants list
runonmine approvals grants revoke <connector> --principal-fingerprint <fingerprint> <tool> <argument-hash>
```

## OAuth scopes

Named Tunnel tokens may contain `machine:read`, `files:read`, `files:write`,
`shell:exec`, `browser:read`, `browser:act`, `desktop:control`, and
`admin:exec`. A tool runs only when both the token scope and local policy allow
it. Platform-native scripting maps to `shell:exec` for OAuth and retains its
separate local capability policy.

## Important boundaries

File roots are opened once as directory capabilities. Reads, listings, searches,
writes, renames, and deletion staging are performed descriptor-relative to
those open handles. Parent traversal, symlink/reparse-point traversal, and
non-regular targets are rejected without a separate canonicalize-then-open
window. `fs_delete` moves entries into a private `.runonmine-trash` directory
inside the same selected root so the move remains descriptor-relative.

`shell_exec` is not a sandbox. When approved, it can run any command available
to the agent's user account. A `CommandPrefix` policy rule matches only a simple
single shell command. Shell composition, pipelines, redirection, command
substitution, backticks, and multiline input are rejected from prefix matching;
use `ask` for complex shell text. `admin_exec` is not a root shell: the helper accepts
only explicitly installed, hash-pinned absolute program paths. Before policy
evaluation, the requested program passes through the same root/SYSTEM ownership,
non-symlink, regular-file, and canonical path resolver used when installing the
helper allowlist. Alternate path spellings therefore cannot avoid an executable
resource rule. Program arguments can still be security-sensitive and must be
reviewed before approval.


## Emergency lock

Use `runonmine lock` or **Lock all access** in the desktop application to stop the
current user service, deny pending approvals, clear temporary grants, revoke
active OAuth tokens, delete incomplete OAuth authorization flows, rotate local
HTTP and Quick Tunnel secrets, and remove stored OpenAI runtime keys. On Linux,
`runonmine lock --system` also stops the system service.

The lock does not delete user configuration. Restoring access requires an
explicit service restart and, where credentials were invalidated, an explicit
connector reconnection.
