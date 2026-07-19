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
