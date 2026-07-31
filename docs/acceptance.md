# Release acceptance

RunOnMine controls real machines. Unit tests and package creation are necessary,
but they are not sufficient evidence for a beta release. A release tag is
blocked until the machine-readable gates in `acceptance/release-gates.toml` are
marked `passed` with evidence.

Check the current state with:

```console
cargo run --locked -p xtask -- release-readiness --profile private-beta
cargo run --locked -p xtask -- release-readiness --profile public-beta
```

## Automated local smoke test

The debug-only smoke harness redirects the entire RunOnMine user environment to
a temporary directory and forces the encrypted file secret backend. Release
builds ignore `RUNONMINE_TEST_FILE_SECRETS`.

```console
./scripts/acceptance/cli-smoke.sh
```

It exercises setup, policy display, connector listing, approval and audit reads,
emergency lock, destructive confirmation, and purge without touching the real
user configuration or credential store.

Windows has the equivalent CLI/MCP harness:

```powershell
.\scripts\acceptance\windows-smoke.ps1 `
  -RunOnMine .\target\debug\runonmine.exe `
  -Agent .\target\debug\runonmine-agent.exe `
  -Desktop .\target\debug\runonmine-desktop.exe `
  -McpClient .\scripts\acceptance\mcp-http-smoke.py
```

Desktop binaries have a separate seven-view parity contract. On Linux, build to
an explicit target directory and run:

```console
cargo build --release --locked --target x86_64-unknown-linux-gnu \
  -p runonmine -p runonmine-agent -p runonmine-helper -p runonmine-desktop
./scripts/acceptance/desktop-parity-smoke.sh \
  "$PWD/target/x86_64-unknown-linux-gnu/release/runonmine-desktop"
```

The physical X11 tray lifecycle and Windows native-window/NSIS procedures are
specified in [testing](testing.md) and the platform documents. Wine is
supplemental Windows compatibility evidence, not physical Windows acceptance.

## Clean-machine acceptance

For each release artifact, record the exact artifact SHA-256, operating system,
architecture, install command, and tester. Use a disposable machine or VM. Start
from `acceptance/evidence/clean-install.template.json` for headless packages or
`acceptance/evidence/clean-install.desktop.template.json` for desktop packages,
then validate the completed file with
`scripts/release/validate-clean-install-evidence.py`. Desktop platforms require
explicit launch, seven-view, and native-shell evidence; universal macOS evidence
also requires native and Rosetta slice launches.

1. Verify the artifact and SBOM checksums.
2. Install the package and launch both CLI and desktop application where supported.
3. Run setup against a disposable project directory.
4. Start the service, restart the machine or service manager, and confirm recovery.
5. Connect a real MCP client and verify `tools/list` contains only supported tools.
6. Exercise an allowed read, an approval-gated write, a denied administrator call,
   and emergency lock.
7. Exercise one supported remote connector without recording its credentials.
8. Uninstall, then verify services, sockets, tasks, files, and credentials are
   removed or deliberately retained according to the documented mode.
9. Confirm the existing MacMCP port, services, files, and configuration were not changed.

Inspect a portable archive and SBOM with the matching package prefix. The
standalone Linux desktop files use `runonmine-desktop-...`; headless and
macOS/Windows portable archives use `runonmine-...`:

```console
./scripts/acceptance/package-inspect.sh \
  dist/runonmine-<version>-<target>-unsigned.tar.gz \
  dist/runonmine-<version>-<target>-unsigned.sbom.json
```

## Evidence

Evidence must not contain credentials, private paths, cookies, personal data, or
raw audit payloads. Prefer `runonmine support-bundle --output runonmine-support.zip`
over copying raw application directories, and inspect every generated ZIP before
attaching it. The schema-v3 support bundle intentionally omits raw config/state data, records
partial or truncated inputs without source paths, and applies bounded redaction,
but user review remains mandatory. Attach the reviewed
bundle, redacted command output, and screenshots to the release readiness issue,
then update only the corresponding gate in `acceptance/release-gates.toml`.

## Fuzz dependency maintenance

The fuzz harness has its own committed lockfile and is scanned by the security workflow. Workspace dependency upgrades are managed from the repository root because the harness consumes `runonmine-core` through a path dependency; a second Dependabot Cargo source would create duplicate PRs that can also alter production dependency constraints.

## Artifact preflight versus release acceptance

When GitHub assigns its hosted runners, the `Artifact preflight` workflow runs
on fresh Linux x86/ARM, Linux desktop, macOS, and Windows images and records
build, checksum/SBOM, setup, agent, MCP, owner-approved tool call, desktop launch
where applicable, uninstall, and residue checks. A job that ends before checkout
with no assigned runner and no executed steps is not acceptance evidence. Its
report type is `artifact_preflight_not_release_acceptance` and explicitly does
not claim an operating-system reboot, publisher signature or notarization.
Those items remain required evidence for the release clean-install gate.
