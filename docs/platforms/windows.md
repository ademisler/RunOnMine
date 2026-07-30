# Windows

The normal agent is registered as a limited logon Scheduled Task:

```console
runonmine.exe setup --root C:\absolute\project
runonmine.exe service install
runonmine.exe service status
```

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
warning. Verify the accompanying SHA-256 file before running it.

Arguments are additionally restricted by the installed executable-specific command profile; an executable added with `--allow-program` alone accepts no arguments.

The privileged helper retains a handle opened with
`FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_SHARE_READ` only. Reparse attributes,
volume serial, file index, size, last-write identity and SHA-256 are rechecked
before process creation; write/delete/replace opens are blocked while the handle
is retained.

Helper upgrades stage the executable and policy before stopping the Windows service. The stopped service releases its executable handle; failed service creation/start or health validation restores the previous files and prior installed/running service state.
