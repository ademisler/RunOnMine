# Security policy

RunOnMine controls real machines and must be treated as security-sensitive,
pre-release software. There is no supported production release yet.

## Supported versions

Only the current `main` branch is reviewed. Older commits, locally modified
builds, and pre-release artifacts are unsupported.

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
evidence is pending or blocked. Packages remain unsupported until signing and
platform acceptance are complete.
