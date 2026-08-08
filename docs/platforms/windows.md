# Windows

RunOnMine supports the x86_64 MSVC target. The desktop application, CLI, agent,
and optional helper binary are distributed in one current-user NSIS installer.

## Desktop control center and installer

The Windows control center contains Overview, Approvals, Connections,
Permissions, OAuth, Audit, and Diagnostics. It uses the native Windows
notification area with **Open RunOnMine**, **Lock RunOnMine**, and **Quit**.
Closing the main window hides it while the tray remains active. The control
center renders through WGPU on the native Direct3D backend, so it does not
require an OpenGL driver. Release builds use the Windows GUI subsystem, so
launching `runonmine-desktop.exe` does not open a console window.

The executable carries the RunOnMine icon, version metadata, an `asInvoker`
manifest, Per-Monitor V2 DPI awareness, and long-path awareness. The NSIS package:

- installs for the current user without elevation;
- writes uninstall metadata only below HKCU;
- installs `runonmine.exe`, `runonmine-agent.exe`,
  `runonmine-desktop.exe`, and `runonmine-helper.exe` together;
- creates Start Menu and desktop shortcuts with the RunOnMine icon;
- offers English, French, and Turkish installer UI.

The helper binary being present does not install or activate the LocalSystem
helper. That requires a separate explicitly elevated `runonmine admin install`.

Selected filesystem roots keep one canonical execution identity. Windows may
report the same directory with a verbatim or expanded spelling that differs
from the absolute path originally selected by the owner; RunOnMine accepts that
exact selected-root spelling as an alias only to derive the relative path, then
performs the operation through the already-open canonical directory capability.
Changing an alias later cannot retarget the capability outside the selected
root.

## User service

The normal agent is copied into the immutable per-user versioned service-binary
directory and registered as a limited-logon Scheduled Task. The examples assume
the installation directory is the current directory or otherwise resolvable;
use the executable's full path when it is not on `PATH`:

```powershell
runonmine.exe setup --root C:\absolute\project
runonmine.exe service install
runonmine.exe service status
```

Task Scheduler restarts the task up to three times at one-minute intervals after
failure, ignores duplicate instances, and starts when the machine becomes
available. Service removal first ends a running task and waits for it to stop
before deleting the task and versioned agent binary. This recovery policy does
not elevate the task or change its interactive-user authority. Secrets use
Windows Credential Manager. Process timeouts assign descendants to a Job Object
so child processes do not survive the tool call.

## Building and packaging

Install Rust 1.95.0, Visual Studio 2022 Build Tools with the Windows SDK, NSIS,
and `cargo-packager` 0.11.8. From a PowerShell prompt:

The checked-in target configuration statically links the MSVC/UCRT runtime into
all Windows binaries. This is required for clean supported Windows images that
do not already provide `VCRUNTIME140.dll`; do not override the Windows target
rustflags when producing release artifacts.

```powershell
cargo build --release --locked --target x86_64-pc-windows-msvc `
  --workspace --exclude xtask
.\scripts\acceptance\windows-pe-resources.ps1 `
  -Desktop target\x86_64-pc-windows-msvc\release\runonmine-desktop.exe
cargo run --locked -p xtask -- package --target x86_64-pc-windows-msvc
cargo run --locked -p xtask -- validate-sbom `
  --path dist\runonmine-0.1.0-beta.1-x86_64-pc-windows-msvc-unsigned.sbom.json `
  --target x86_64-pc-windows-msvc
cargo run --locked -p xtask -- stage-packager `
  --target x86_64-pc-windows-msvc
cargo packager --release --config packaging\Packager.windows.toml
cargo run --locked -p xtask -- checksums
```

Use the generated filenames rather than assuming the example version after the
workspace version changes. Run the real installer contract on a disposable
Windows account or VM with:

```powershell
.\scripts\acceptance\windows-installer-smoke.ps1 `
  -Installer .\dist\runonmine-desktop_0.1.0-beta.1_x64-setup.exe
```

The acceptance performs a silent install, verifies the native main window and
all seven rendered views, delivers `WM_CLOSE`, confirms the process remains in
the notification area, checks HKCU metadata and both shortcuts, then silently
uninstalls and checks managed-file residue. A GNU/Wine run is supplemental
compatibility evidence only; it does not replace the real Windows runner,
rebooted clean-machine evidence, or publisher signing.

## Uninstall and retained data

`runonmine uninstall` and the NSIS uninstaller have different ownership:

- `runonmine uninstall` removes the per-user Scheduled Task and retains user data;
- `runonmine uninstall --purge --confirm PURGE` also removes RunOnMine user data
  and connector secrets;
- the NSIS uninstaller removes package-owned binaries, HKCU uninstall metadata,
  and shortcuts, while retaining user data by default.

Standard retained application-data roots are
`%LOCALAPPDATA%\RunOnMine\RunOnMine` and
`%APPDATA%\RunOnMine\RunOnMine`. Remove data through the explicit purge or the
interactive uninstaller data-removal choice; do not infer successful cleanup
from the installation directory disappearing, because retained data may keep a
RunOnMine directory present. The separately elevated LocalSystem helper must be
removed with an elevated `runonmine admin uninstall` before the NSIS package
is removed.

## Platform security boundaries

The optional LocalSystem helper's named pipe rejects remote clients, grants
access only to LocalSystem and the installing owner's SID, validates both client
and server tokens, and verifies the ACL, owner, and SHA-256 of every allowlisted
program. Its executable handle uses `FILE_FLAG_OPEN_REPARSE_POINT` and
`FILE_SHARE_READ` only; reparse attributes, volume serial, file index, size,
last-write identity, and digest are rechecked before process creation.

Desktop capture and input require an interactive session. The Windows-specific
PowerShell tool starts the fixed system PowerShell executable with no profile and
non-interactive flags, then passes the script over stdin. Privileged helper
upgrades stage executable and policy before stopping the Windows service, wait
for SCM to report `STOPPED`, and restore the previous files, registration, start
type, and running state after a failed start or health validation.

Unsigned beta installers do not carry a trusted publisher signature. Windows may show an unrecognized
publisher warning. Verify its SHA-256 file before running it. A candidate may
pass the Windows clean-install gate only after rebooted Windows Server 2025 or
equivalent owner-controlled acceptance proves the native desktop, Scheduled Task
recovery, MCP approval/deny, LocalSystem helper boundary, uninstall, and zero
unexpected residue for that exact source and artifact hash. Current status is
recorded in `acceptance/release-gates.toml`. An unsigned public beta is permitted
when the release notes state the unrecognized-publisher/SmartScreen limitation
and every required public-beta gate passes; Authenticode remains recommended
publisher-trust hardening.
