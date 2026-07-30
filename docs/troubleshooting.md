# Troubleshooting

Run `runonmine doctor` first. It checks configuration, the fixed loopback bind,
the audit chain, enabled connector secrets, external tunnel binaries, tunnel
health, the optional helper, and service status without printing credential
values.

## Missing tools

If file tools are absent, add at least one existing directory:

```console
runonmine setup --root <absolute-directory>
```

A denied tool is intentionally absent from `tools/list`. Inspect the connector's
effective policy with `runonmine policy show --connector <id>`.

Browser tools require a supported Chromium-based browser or an explicit
loopback CDP endpoint. Desktop tools require a desktop-enabled build plus the
operating system's capture/accessibility permissions. Linux headless builds do
not include desktop dependencies.

## Approval timeout

If an `ask` tool times out, keep `runonmine ui` open or approve the request from
a local terminal within 90 seconds:

```console
runonmine approvals list
runonmine approvals approve <id> --once
```

The remote MCP client cannot grant its own request.

## Audit verification failure

An audit-chain failure is treated as a local integrity problem and prevents a
new MCP runtime from starting. Do not delete the database immediately. Export a
copy of the RunOnMine state directory, inspect local filesystem or backup
activity, and report reproducible corruption privately if it is not explained.

Normal retention is not a verification failure: pruning advances the stored
chain anchor and the remaining rows continue to verify.

## Headless Linux secrets

If a connector reports that secret storage is unavailable, either start it in a
session with Secret Service or supply a valid 32-byte `RUNONMINE_MASTER_KEY`
through the host's secret manager. RunOnMine deliberately does not create a
fallback plaintext store.

## Typed doctor and JSON diagnostics

`runonmine doctor` renders human-readable checks. `runonmine doctor --json`,
`runonmine audit tail --json`, `runonmine service status --json`, and
`runonmine connect local-http status --json` emit the same versioned envelope:

```json
{"schema_version":1,"command":"doctor","data":{}}
```

Each doctor check has a stable ID, severity, status, bounded evidence, and an
optional remediation. `runonmine doctor --repair` performs only explicit safe
reconciliation: config-less connector directories are moved into owner-only
quarantine, orphan Quick Tunnel runtime records are removed, and indexed
connector credentials without a configured owner are deleted. Invalid names,
symlinks, and ambiguous filesystem entries are reported but never modified.

Platform credential stores generally cannot enumerate credentials created by
older versions or other tools. Doctor therefore reports keyring inventory
coverage as partial. The managed secret-name index contains names only; it never
contains credential values.

## Redacted support bundle

Run the doctor first, then create a private support ZIP when diagnostics need to
be shared:

```console
runonmine doctor
runonmine support-bundle --output runonmine-support.zip
```

The schema-v3 archive is written without overwriting an existing file and is
owner-only on Unix. It contains generated structural configuration and typed
service/input states, a bounded audit outcome sample without connector IDs,
argument hashes, or event summaries, a checksum manifest, and up to five recent
bounded log tails from `.log`, `.txt`, `.jsonl`, or `.ndjson` files. The manifest
records complete/partial/missing input state plus included, skipped, and truncated
counts without recording source paths or filenames. State values
separate missing, disabled, corrupt, temporarily unavailable, and
permission-denied conditions instead of representing all of them as false or
empty.

RunOnMine does not copy the raw config file, state database, credential store,
browser profiles, audit arguments, connector identifiers, hostnames, URLs, or
filesystem roots into the archive. Known local values plus generic credentials,
URLs, email addresses, absolute paths, IP addresses, hostnames, and high-entropy
tokens are redacted from included log fragments. Configured connector IDs are
matched at exact token boundaries, avoiding accidental substring replacement in
unrelated text. Redaction cannot prove that arbitrary application text contains
no personal data, so inspect the ZIP before sharing it.

## Service diagnostics

Service-manager stdout/stderr shown by status and installation failures is
bounded command output, not a secret-sanitized transcript. It is control-filtered
and limited to 1,000 characters; do not place credentials in service-manager
messages or attach the raw output without review.


```console
runonmine service status
runonmine service status --system
```

The `--system` form is Linux-only. The system unit runs as the account selected
at installation; initialize RunOnMine and inject headless secrets for that same
account.

## Existing MacMCP installation

RunOnMine never uses port `45799` and does not own `com.idemasler.macmcp.*`.
A problem with the separate MacMCP service must be diagnosed independently.
