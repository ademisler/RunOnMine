# Security Policy

RunOnMine controls real machines and must be treated as security-sensitive
software. Do not report vulnerabilities in a public issue.

## Supported versions

There is no supported public release yet. Security fixes will target the latest
pre-release branch until `0.1.0-beta.1` is published.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Do
not include live credentials, cookies, private keys, secret MCP URLs, or user
data in a report. Replace them with synthetic values and include the smallest
reproduction necessary.

## Security boundaries

- The agent listens on loopback only.
- Remote transports authenticate independently from local tool policy.
- OAuth scope never expands local policy.
- Local approval is not exposed as an MCP tool.
- Administrator execution is unavailable unless the separate helper is
  explicitly installed and enabled.
- The threat model does not claim to protect a user from malware already
  running as that same operating-system user.

