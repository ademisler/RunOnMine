# Windows

## Desktop control center and installer

The Windows desktop control center contains the same Overview, Approvals,
Connections, Permissions, OAuth, Audit, and Diagnostics screens as macOS and
Linux. It uses the native Windows notification area with **Open RunOnMine**,
**Lock RunOnMine**, and **Quit** actions. Closing the main window hides it while
the tray remains active. Release builds use the Windows GUI subsystem, so
launching the desktop application does not open a console window.

The NSIS package installs for the current user without elevation, writes only
HKCU uninstall metadata, installs the CLI, agent, desktop, and optional helper
binary together, and creates Start Menu and desktop shortcuts with the RunOnMine
icon. The helper binary being present does not install or activate the
LocalSystem helper; that still requires an explicit elevated admin command.
Installer UI is available in English, French, and Turkish.

The Windows artifact preflight performs a silent install, verifies the native
main window and all seven rendered views, delivers `WM_CLOSE` and confirms the
process remains available from the tray, then silently uninstalls, verifies that every managed binary, registry entry, and shortcut is gone, and confirms that user data is retained by default. A GNU/Wine run may be
used as supplemental compatibility evidence, but it does not replace the real
Windows runner or publisher-signing acceptance.

The normal agent is copied into the immutable per-user versioned service-binary
directory and registered as a limited logon Scheduled Task:

```console
runonmine.exe setup --root C:\absolute\project
runonmine.exe service install
runonmine.exe service status
```


Task Scheduler is configured to restart the task up to three times at one-minute
intervals after failure, ignore duplicate instances, and start when the machine
becomes available. This recovery policy does not elevate the task or change its
interactive-user authority.

Secrets use Windows Credential Manager. Process timeouts assign descendants to
a Job Object so child processes do not survive the tool call.

The optional LocalSystem helper is installed only through an elevated
`runonmine admin install`. Its named pipe rejects remote clients, grants access
only to LocalSystem and the installing owner's SID, validates both client and
server tokens, and verifies the ACL, owner, and SHA-256 hash of every allowlisted
program. Normal setup does not install it.

Desktop capture and input require an interactive session. The Windows-specific
PowerShell tool starts the fixed system PowerShell executable with no profile
and non-interactive flags, then passes the script over stdin.

The beta NSIS installer is unsigned. Windows may show an unrecognized publisher
warning. Verify the accompanying SHA-256 file before running it. Public release
remains blocked until Authenticode signing and rebooted clean-install evidence
are recorded.

Arguments are additionally restricted by the installed executable-specific command profile; an executable added with `--allow-program` alone accepts no arguments.

The privileged helper retains a handle opened with
`FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_SHARE_READ` only. Reparse attributes,
volume serial, file index, size, last-write identity and SHA-256 are rechecked
before process creation; write/delete/replace opens are blocked while the handle
is retained.

Helper upgrades stage the executable and policy before stopping the Windows service. The installer waits for SCM to report `STOPPED` so the executable handle is released; failed service configuration/start or health validation restores the previous files, registration, start type and running state.
