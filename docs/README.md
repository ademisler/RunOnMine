# Documentation

This index is the entry point for RunOnMine documentation. The live source code,
workflow definitions, package manifests, and machine-readable release gates are
the final authority when a document and implementation disagree.

## Product and platform operation

- [Secure onboarding](onboarding.md): roots, policy profiles, connectors,
  approvals, emergency lock, OS permissions, and permanent removal.
- [macOS](platforms/macos.md): universal application, LaunchAgent, permissions,
  packaging, and uninstall behavior.
- [Linux and VPS](platforms/linux.md): desktop DEB, per-user service, headless
  system service, secrets, and desktop-session acceptance.
- [Windows](platforms/windows.md): current-user NSIS installation, Scheduled
  Task, native tray behavior, package data retention, and helper boundaries.
- [Troubleshooting](troubleshooting.md): doctor, support bundles, service and
  desktop integration diagnostics.

## Architecture and connection modes

- [Architecture](architecture.md): process, persistence, desktop, service, and
  security-boundary design.
- [Connection modes](connections.md): local stdio/HTTP, Cloudflare, OAuth, and
  OpenAI Secure MCP Tunnel behavior.
- [MCP tools](tools.md): advertised tool families and platform availability.

## Security

- [Permissions](permissions.md): policy precedence, remote safety ceiling,
  approvals, scopes, and emergency lock.
- [Threat model](threat-model.md): assets, trust boundaries, controls, and
  explicit limitations.
- [Browser security](browser-security.md): isolated profiles, executable
  identity, network boundary, and crash recovery.
- [Audit integrity](audit-security.md): hash/MAC verification and same-user
  threat boundary.
- [Privileged helper](admin-helper.md): command profiles, transactional install,
  and executable identity.
- [Connector provenance](connector-provenance.md): threshold-signed catalogs,
  receipts, updates, and key rotation.

## Testing and release

- [Testing](testing.md): CI matrices, coverage, fuzzing, desktop parity, and
  native acceptance.
- [Release acceptance](acceptance.md): candidate-scoped machine-readable gates,
  clean-machine procedures, and evidence handling.
- [Release process](releasing.md): gates, artifacts, signing status, packaging,
  and branch protection.
- [Rollback runbook](release-rollback.md): application, connector, state, and
  helper recovery.
- [GitHub-hosted CI](ci-runner.md): ephemeral runner trust model, pinned tooling, and cleanup
  contract.

Repository-wide contribution and disclosure rules are in
[CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md), and
[AGENTS.md](../AGENTS.md).
