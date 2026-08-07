# Testing

## Documentation validation

Run the repository documentation contract after changing Markdown, workflows,
package manifests, acceptance commands, or release gates:

```console
python3 scripts/ci/check-docs.py
```

The checker validates relative links, Markdown anchors, and referenced repository
script/package/evidence paths; requires the complete document index to cover
every file below `docs/`; and rejects known stale claims
about coverage, hosted-platform guards, target-specific desktop paths, and hosted
runner failure causes. It also requires `docs/tools.md` to match every MCP tool
declaration in source. The Linux quality workflow runs the same check before the
Rust quality gates.

## CI platform and coverage contracts

Relevant pull requests run the macOS, Windows and ARM platform jobs directly;
there is no repository variable that silently skips them. Workflows install the
exact Rust toolchain through `scripts/ci/install-rust-toolchain.sh`, which pins
components and targets with `rustup` rather than relying on unsupported action
inputs.

Coverage is measured from LCOV and enforced by `scripts/ci/check-lcov.py` at
70% globally, 90% in policy/auth/storage/approval-critical modules, and 80% of
changed executable lines on pull requests. The main Linux quality job also runs
a real Streamable HTTP MCP lifecycle: initialize, initialized notification,
tools/list, a safe tool call, negative authentication and malformed-body checks,
and session deletion.

## Fuzzing and concurrency

The scheduled fuzz matrix builds every committed target from the independent
`fuzz/Cargo.lock` before running it. Targets cover TOML config, policy rules,
OAuth request models, restricted browser URL parsing, privileged-helper frames,
MCP session/header binding transitions, verified ZIP/TAR executable-entry
selection, and SQLite-backed approval transitions. Parser/state targets also
receive local libFuzzer smoke runs before changes are accepted.

Normal tests use reference models for approval resolution and MCP session
binding. The weekly mutation workflow narrows `cargo-mutants` to those critical
state machines instead of mutating the entire workspace: the current baseline
catches all 20 generated MCP session mutants and all 15 viable approval mutants.
OAuth dynamic client registration remains globally and per-source limited, and
a 64-concurrent-call test exercises atomic rate-limit admission on every normal
quality run.


## Acceptance and soak

`./scripts/acceptance/mcp-http-smoke.sh` starts a real isolated agent and covers
Streamable HTTP initialize, initialized notification, repeated `tools/list`,
`machine_info`, an approval-gated `fs_write` resolved once through the CLI,
invalid bearer and malformed-body rejection, and session deletion. Set
`RUNONMINE_MCP_SOAK_ITERATIONS` to increase the repeated discovery count.

`./scripts/acceptance/soak.sh` verifies 20,000 audit rows, appends and
incrementally verifies 2,000 more, and runs 5,000 MCP discovery calls in the
scheduled workflow. `helper-unix-identity.sh` is root-only and uses real owner
and attacker UIDs. `artifact-preflight.yml` runs fresh-host artifact checks but
explicitly does not claim OS reboot, code signing, notarization or release
clean-install acceptance.


## Real Unix helper identity acceptance

On macOS, run the helper identity acceptance as root with a real temporary second user:

```console
RUNONMINE_ACCEPTANCE_ATTACKER_USER=<second-user> sudo -E ./scripts/acceptance/helper-unix-identity.sh
```

The active console user is the helper owner. The test verifies UID ownership, socket mode `0600`, a successful owner health frame, and kernel denial for the second user. Remove the temporary account after the run.

## Physical macOS desktop acceptance

A physical Apple-silicon acceptance run builds both `aarch64-apple-darwin` and
`x86_64-apple-darwin`, merges the four application binaries with `lipo`,
validates the portable archive and CycloneDX SBOM, and packages the universal
DMG with cargo-packager 0.11.8. The installed application is exercised through
native and Rosetta launches, LaunchAgent install/stop/start, loopback health,
Streamable HTTP initialize and discovery, `machine_info`, a locally approved
`fs_write`, every desktop navigation view at the supported layout bounds,
non-purge uninstall, full purge, and restoration of the pre-existing user
state.

This acceptance does not substitute for Developer ID signing, Apple
notarization, or a real operating-system reboot. Unsigned local artifacts are
expected to fail Gatekeeper assessment until the release credentials are
provided.

## Cross-platform desktop parity acceptance

`desktop-launch-smoke.sh` uses a deliberately short `/tmp` sandbox on macOS because the native single-instance transport is a Unix-domain socket and Darwin enforces a small socket-path limit; Linux keeps the platform-default temporary directory.

`desktop-parity-smoke.sh` launches the actual desktop binary under an isolated
D-Bus/Xvfb session. The application renders Overview, Approvals, Connections,
Permissions, OAuth, Audit, and Diagnostics in order, keeps the final frame alive
long enough to expose a real window, and writes a no-overwrite JSON report with
platform, architecture, viewport bounds, application-icon state, native-shell
availability, close behavior, and the exact Open/Lock/Quit action contract. The
report deliberately excludes usernames, home paths, machine names, connector
identifiers, and credentials.

On a physical Ubuntu 24.04 Xfce/X11 session,
`linux-desktop-session-smoke.sh` additionally observes a real
StatusNotifierItem, sends the window manager's `_NET_CLOSE_WINDOW`, verifies the
window becomes hidden while the process remains alive, launches a second process
and verifies it activates the primary without creating another window, activates
the tray over D-Bus, verifies the window reappears, and confirms the tray name disappears on
exit.


The full Linux candidate path is `scripts/acceptance/linux-clean-install-vm.sh`.
It uses a disposable Ubuntu 24.04 QEMU overlay for actual boot cycles and package
manager behavior, while the exact extracted desktop DEB binary is tested on the
real Oty X11/StatusNotifier session. Nested containers are not accepted as
user-service credential or reboot evidence because their user mount namespace
can differ from a normal host. The ARM64 headless equivalent is
`scripts/acceptance/linux-headless-clean-install-vm.sh`, using an Ubuntu ARM64
cloud image, QEMU AArch64 UEFI boot, and a verified managed ARM64 connector
binary.


The Linux x86_64 artifact preflight builds all four binaries with desktop
control enabled, runs the seven-view parity smoke, creates a four-binary
portable archive plus CycloneDX SBOM, and builds the standalone
`runonmine-desktop` DEB. The job installs that DEB, validates its freedesktop
entry, launches `/usr/bin/runonmine-desktop`, removes the package, and verifies
that its executable and menu entry are gone. The headless Linux package remains
a separate artifact and is not replaced by this acceptance path.


Desktop screen, form, sidebar, and icon rendering is intentionally decomposed into focused helpers rather than suppressing `clippy::too_many_lines`. Warnings-denied desktop Clippy, the desktop unit suite, and this seven-view parity smoke are the regression guards for structure-only UI refactors.

## Windows desktop and NSIS acceptance

The Windows smoke test defaults to interactive acceptance: it starts the native
desktop executable, waits for a real `RunOnMine` window handle, validates the
same seven-view JSON contract, and sends `WM_CLOSE`; Win32 `IsWindowVisible`
must become false while the process continues in the notification area. The
NSIS smoke test then performs a silent current-user install, checks HKCU
uninstall metadata, all four binaries, Start Menu and desktop shortcuts, runs
the installed desktop acceptance, silently uninstalls, and verifies that the
registry record, package-owned binaries, uninstaller, and shortcuts are gone.
Per-user application data must remain by default, so the parent RunOnMine
directory is not required to disappear.

GitHub-hosted Windows jobs do not provide an authoritative interactive desktop
session. Artifact preflight therefore passes `-SkipInteractiveDesktop`: the real
binary must still launch, render all seven views, keep the final frame alive,
write the native-shell contract report, install, and uninstall, but the report
does not claim visible-HWND or `WM_CLOSE`-to-tray behavior. The default local
command omits that switch and remains the required interactive Windows VM or
physical-machine gate.

An interactive Windows VM or physical Windows machine is authoritative for the
native-window and tray lifecycle. The formal private-beta run also verifies a
real boot-identity change, Scheduled Task recovery, MCP approval/deny, the
LocalSystem helper owner/second-user boundary, purge, and zero unexpected
residue. A Wine x86_64 run remains useful supplemental evidence for PE launch,
tray creation, seven-view rendering, standard Windows data paths, and
GUI-subsystem compatibility, but it does not claim physical Windows
installation, Authenticode signing, reboot, or release clean-install acceptance.

When Windows is fully emulated under QEMU TCG, WGPU/Direct3D may fall back to a
software renderer. Use at least four virtual CPUs for authoritative interactive
acceptance on that path. A `wgpu-core` queue timeout from an otherwise clean
2-vCPU TCG run is infrastructure evidence, not a pass; preserve the failure and
rerun the same frozen artifact on a clean overlay with adequate CPU. Only the
complete clean retry may satisfy the gate.
