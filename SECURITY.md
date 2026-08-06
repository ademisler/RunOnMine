# Security policy

RunOnMine controls real machines and must be treated as security-sensitive,
pre-release software. There is no supported production release yet.

## Supported versions

The current `main` branch is the reviewed source line, but it is not itself a
published production release. The exact private-beta candidate named in
`acceptance/release-candidate.toml` is eligible only for owner-authorized testing
when its artifact SHA-256 matches committed evidence. Older commits, locally
modified builds, and unrecorded artifacts are unsupported.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow for this repository. Do not
open a normal issue containing exploit details, live credentials, cookies,
private keys, secret MCP URLs, machine identifiers, filesystem paths,
screenshots, audit exports, or user data.

Replace sensitive values with synthetic data and include the affected commit,
operating system, connector type, required local policy, reproduction steps,
and the smallest proof needed to demonstrate the problem.

## Security boundaries

- The agent listens on loopback only.
- Remote transports authenticate independently from local tool policy.
- OAuth scope never expands local policy.
- Internet-facing connectors cannot bypass the remote safety ceiling.
- Local approval is not exposed as an MCP tool.
- Administrator execution is unavailable unless the separate helper is
  explicitly installed and enabled.
- Browser private-network access is denied by default, but the browser is not a
  complete network sandbox.
- The threat model does not claim to protect a user from malware already
  running as that same operating-system user.

## Security release gate

A beta candidate must pass formatting, Clippy, tests, dependency policy, full
Git-history secret scanning, the enforced coverage floor, scheduled fuzzing,
platform builds, clean-machine acceptance tests, and an owner risk review. The
tag workflow reads `acceptance/release-gates.toml` and fails while required
evidence is pending or blocked. The recorded frozen candidate completed the
private-beta platform gates, but its artifacts remain unsigned and limited to
owner-authorized testing. Public or production support remains blocked until
publisher signing and every public-beta gate are complete. Changes after a
freeze require a new candidate and may not reuse prior platform evidence.
