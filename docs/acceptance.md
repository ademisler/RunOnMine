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

Windows has the equivalent harness:

```powershell
.\scripts\acceptance\windows-smoke.ps1 -RunOnMine .\target\debug\runonmine.exe
```

## Clean-machine acceptance

For each release artifact, record the exact artifact SHA-256, operating system,
architecture, install command, and tester. Use a disposable machine or VM.

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

Inspect a portable archive and SBOM with:

```console
./scripts/acceptance/package-inspect.sh \
  dist/runonmine-<version>-<target>-unsigned.tar.gz \
  dist/runonmine-<version>-<target>-unsigned.sbom.json
```

## Evidence

Evidence must not contain credentials, private paths, cookies, personal data, or
raw audit payloads. Attach redacted command output and screenshots to the release
readiness issue, then update only the corresponding gate in
`acceptance/release-gates.toml`.
