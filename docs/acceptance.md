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

Readiness also validates the frozen source fingerprint, rejects any non-evidence
path touched after the freeze, and requires every passed platform report to name
the exact candidate revision and a real artifact SHA-256.

## Candidate-scoped evidence

Do not infer current release readiness from a prose snapshot or an old commit.
The source of truth is the revision in `acceptance/release-candidate.toml` plus
the gate states in `acceptance/release-gates.toml`. A platform report counts only
when its `source_revision` exactly matches the frozen candidate and its artifact
SHA-256 identifies the artifact that was actually exercised.

Historical accepted candidates remain useful audit history, but their JSON must
never be copied forward or edited to name a newer revision. Any committed
production, dependency, workflow, packaging, or narrative-documentation change
outside release metadata changes the frozen source fingerprint and requires a
new candidate plus fresh applicable platform acceptance.

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

The default Windows invocation requires a visible native window and verifies
`WM_CLOSE` hides it to the tray. `-SkipInteractiveDesktop` is reserved for
non-interactive hosted preflight and must not be used as native-shell release
evidence. Formal Windows evidence additionally combines
`windows-installer-smoke.ps1`, `helper-windows-identity.ps1`, and the
Prepare/Verify/Cleanup stages of `windows-service-reboot-acceptance.ps1` across
a real reboot, followed by purge and zero-residue inspection.

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


### Linux QEMU and native desktop acceptance

After producing both x86_64 DEBs, run the QEMU harness from a clean committed
worktree. It generates validated headless and desktop evidence JSON for the exact
artifact hashes and combines VM reboot/service results with the physical X11
tray and single-instance report:

```console
sudo ./scripts/acceptance/linux-clean-install-vm.sh \
  /var/lib/runonmine-acceptance/cache/noble-server-cloudimg-amd64.img \
  "$PWD/dist/runonmine_0.1.0-beta.1_amd64.deb" \
  "$PWD/dist/runonmine-desktop_0.1.0-beta.1_amd64.deb" \
  /usr/local/bin/cloudflared \
  /var/lib/runonmine-acceptance/evidence/linux-x86_64
```

The VM starts from a qcow2 overlay, upgrades synthetic beta.0 packages, survives
two verified boot-ID changes, exercises both user and system services, runs the
real MCP approval flow and Quick Tunnel, locks and rejects the stale token, then
replaces and removes both package variants. The host portion never installs the
candidate DEB; it extracts only the packaged `runonmine` and
`runonmine-desktop` executables into a private temporary directory for
real-session validation.

ARM64 headless acceptance uses an Ubuntu ARM64 cloud image and the canonical
arm64 DEB. It validates the same headless service and MCP security lifecycle,
including RunOnMine's managed download and verification of the ARM64
`cloudflared` binary:

```console
sudo ./scripts/acceptance/linux-headless-clean-install-vm.sh \
  /var/lib/runonmine-acceptance/cache/noble-server-cloudimg-arm64.img \
  "$PWD/dist/runonmine_0.1.0-beta.1_arm64.deb" \
  /var/lib/runonmine-acceptance/evidence/linux-aarch64
```

## macOS physical acceptance

The repeatable macOS procedure is split around a real reboot:

```console
./scripts/acceptance/macos-clean-install.sh prepare \
  --dmg /absolute/path/to/RunOnMine.dmg \
  --sbom /absolute/path/to/runonmine-0.1.0-beta.1-universal-apple-darwin-unsigned.sbom.json \
  --cloudflared /absolute/canonical/path/to/cloudflared \
  --output /absolute/private/acceptance-directory
# Reboot, sign back into the same account, then:
./scripts/acceptance/macos-clean-install.sh verify \
  --output /absolute/private/acceptance-directory
```

The harness installs from a read-only DMG into `/Applications`, verifies all four
universal binaries, runs the seven-view desktop report in arm64 and Rosetta
x86_64, exercises close-to-menu-bar and single-instance restore, configures
authenticated Local HTTP plus a temporary Cloudflare Quick Tunnel, verifies the
LaunchAgent after reboot, performs an owner-approved MCP write while remote
administrator execution remains denied, tests Emergency Lock, retained-data
uninstall and full purge, and confirms MacMCP LaunchAgents and loopback port
45799 are unchanged. `--cloudflared` is optional: omit it to exercise the
signed-provenance managed download, or provide a canonical non-symlink executable
when a constrained network cannot complete that official asset download within
the bounded installer timeout. RunOnMine still checks compatibility and pins the
external file identity; its SHA-256 is recorded in local acceptance evidence. The
generated evidence is still reviewed before it is committed.

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
